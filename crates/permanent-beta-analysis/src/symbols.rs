//! Names and signatures from an MSVC PDB (design §4.1, M1 spike), read with the `pdb` crate.
//!
//! What it reads: procedure symbols (`S_GPROC32`/`S_LPROC32`) from every module, which gives each function's
//! entry, length, undecorated name and type; and from the type stream, the procedure's return and parameter
//! types. Parameter names (local symbols) are not read: a renamed parameter must not look like a changed
//! signature (repair compares signatures for equality).
//!
//! What it never does: decide a function's boundaries for the native analyzer, or name a function when more than
//! one procedure claims its entry (`/OPT:ICF` folds identical functions onto one address; their names are then
//! ambiguous and none is used).
//!
//! The corpus answer key comes from linker maps, and the corpus gate scores stripped analyses. A PDB reaches
//! matching only when a caller asks for it with `pbeta analyze --pdb`.

use crate::AnalysisError;
use pdb::{FallibleIterator, TypeData, TypeFinder, TypeIndex};
use permanent_beta_model::{
    ANALYSIS_SCHEMA_VERSION, AnalysisExport, BuildInfo, FunctionFeatures, FunctionSignature,
    NameSource, Param, Producer, Rva,
};
use std::collections::BTreeMap;
use std::path::Path;

pub const PRODUCER: &str = "permanent-beta-pdb";

/// How deep a type name is followed (pointer to pointer to ...). Deeper types are named `?`.
const MAX_TYPE_DEPTH: u32 = 8;

/// Everything read from one PDB.
#[derive(Debug, Clone)]
pub struct PdbSymbols {
    /// Uppercase, Windows style (`12345678-1234-...`), as the native analyzer records it from the debug
    /// directory.
    pub guid: String,
    /// The DBI age, which is what the executable's debug directory records.
    pub age: u32,
    /// Procedures by entry RVA. More than one at an entry means folded (ICF) code.
    pub procedures: BTreeMap<Rva, Vec<PdbProcedure>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdbProcedure {
    pub rva: Rva,
    pub len: u32,
    pub name: String,
    pub signature: Option<FunctionSignature>,
}

/// What [`apply`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApplyReport {
    /// Distinct entries with a procedure in the PDB.
    pub pdb_entries: usize,
    /// Functions given a PDB name (functions with an export name keep it).
    pub named: usize,
    /// Functions given a signature.
    pub signed: usize,
    /// Entries more than one procedure claims (folded code), left unnamed and unsigned.
    pub ambiguous: usize,
    /// PDB entries the analysis has no function at. `pbeta analysis-diff` against [`procedures_export`]
    /// lists them.
    pub not_in_analysis: usize,
}

/// Read a PDB file.
pub fn read(path: &Path) -> Result<PdbSymbols, AnalysisError> {
    let shown = path.display().to_string();
    let err = |e: pdb::Error| AnalysisError::InvalidPdb {
        path: shown.clone(),
        reason: e.to_string(),
    };
    let file = std::fs::File::open(path).map_err(|source| AnalysisError::Io {
        path: shown.clone(),
        source,
    })?;
    let mut pdb = pdb::PDB::open(file).map_err(err)?;

    let info = pdb.pdb_information().map_err(err)?;
    let dbi = pdb.debug_information().map_err(err)?;
    let guid = info.guid.hyphenated().to_string().to_uppercase();
    let age = dbi.age().unwrap_or(info.age);

    let address_map = pdb.address_map().map_err(err)?;
    let type_info = pdb.type_information().map_err(err)?;
    let mut finder = type_info.finder();
    let mut types = type_info.iter();
    while types.next().map_err(err)?.is_some() {
        finder.update(&types);
    }

    let mut procedures: BTreeMap<Rva, Vec<PdbProcedure>> = BTreeMap::new();
    let mut modules = dbi.modules().map_err(err)?;
    while let Some(module) = modules.next().map_err(err)? {
        let Some(module_info) = pdb.module_info(&module).map_err(err)? else {
            continue;
        };
        let mut symbols = module_info.symbols().map_err(err)?;
        while let Some(symbol) = symbols.next().map_err(err)? {
            // Symbol kinds the crate can't parse are skipped, not fatal: only procedures matter here.
            let Ok(pdb::SymbolData::Procedure(p)) = symbol.parse() else {
                continue;
            };
            let Some(rva) = p.offset.to_rva(&address_map) else {
                continue;
            };
            let rva = Rva(u64::from(rva.0));
            let procedure = PdbProcedure {
                rva,
                len: p.len,
                name: p.name.to_string().into_owned(),
                signature: signature(&finder, p.type_index),
            };
            let at = procedures.entry(rva).or_default();
            // The same procedure can appear in more than one module (an inline function's out-of-line copy
            // kept by COMDAT folding is listed once per module that emitted it). Same name and type: one entry.
            if !at.contains(&procedure) {
                at.push(procedure);
            }
        }
    }
    Ok(PdbSymbols {
        guid,
        age,
        procedures,
    })
}

/// Check that `symbols` belongs to the build `export` describes: the GUID and age in the executable's debug
/// directory must equal the PDB's. A mismatched PDB would name functions after another build's.
pub fn check_matches(export: &AnalysisExport, symbols: &PdbSymbols) -> Result<(), String> {
    let Some(expected) = &export.build.pdb else {
        return Err(format!(
            "{} has no CodeView debug record, so no PDB can be matched to it",
            export.build.file_name
        ));
    };
    if !expected.guid.eq_ignore_ascii_case(&symbols.guid) || expected.age != symbols.age {
        return Err(format!(
            "{} expects PDB {} age {}, but this PDB is {} age {}",
            export.build.file_name, expected.guid, expected.age, symbols.guid, symbols.age
        ));
    }
    Ok(())
}

/// Add PDB names and signatures to `export`'s functions, by entry RVA. Fails if the PDB isn't this build's.
/// Boundaries, hashes and every other feature stay the analyzer's.
pub fn apply(export: &mut AnalysisExport, symbols: &PdbSymbols) -> Result<ApplyReport, String> {
    check_matches(export, symbols)?;
    let mut report = ApplyReport {
        pdb_entries: symbols.procedures.len(),
        ..ApplyReport::default()
    };
    let mut seen = 0;
    for f in &mut export.functions {
        let Some(at) = symbols.procedures.get(&f.rva) else {
            continue;
        };
        seen += 1;
        let [procedure] = at.as_slice() else {
            report.ambiguous += 1;
            continue;
        };
        if f.name.is_none() {
            f.name = Some(procedure.name.clone());
            f.name_source = Some(NameSource::Pdb);
            report.named += 1;
        }
        if let Some(sig) = &procedure.signature {
            f.signature = Some(sig.clone());
            report.signed += 1;
        }
    }
    report.not_in_analysis = symbols.procedures.len() - seen;
    Ok(report)
}

/// The PDB's procedures as an analysis of `build`: entry, length, name and signature only, no hashes. For
/// comparing function boundaries with `pbeta analysis-diff` (M1's diff report). Folded entries are listed
/// once, unnamed.
pub fn procedures_export(build: &BuildInfo, symbols: &PdbSymbols) -> AnalysisExport {
    let functions = symbols
        .procedures
        .iter()
        .map(|(rva, at)| {
            let single = match at.as_slice() {
                [p] => Some(p),
                _ => None,
            };
            FunctionFeatures {
                rva: *rva,
                size: at.iter().map(|p| p.len).max().unwrap_or(0),
                name: single.map(|p| p.name.clone()),
                name_source: single.map(|_| NameSource::Pdb),
                normalized_hash: None,
                mnemonic_hash: None,
                basic_blocks: None,
                edges: None,
                callees: vec![],
                strings: vec![],
                constants: vec![],
                imports: vec![],
                signature: single.and_then(|p| p.signature.clone()),
                inferred_args: None,
                inferred_arg_classes: vec![],
                mnemonic_counts: Default::default(),
                pseudocode: None,
                entry: None,
            }
        })
        .collect();
    AnalysisExport {
        schema_version: ANALYSIS_SCHEMA_VERSION,
        build: build.clone(),
        producer: Producer {
            tool: PRODUCER.to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        },
        functions,
    }
}

/// A procedure's signature from its type, or `None` if the type isn't a function type the crate can read.
fn signature(finder: &TypeFinder<'_>, index: TypeIndex) -> Option<FunctionSignature> {
    let (convention, return_type, args, this) = match finder.find(index).ok()?.parse().ok()? {
        TypeData::Procedure(p) => (
            p.attributes.calling_convention(),
            p.return_type,
            p.argument_list,
            None,
        ),
        TypeData::MemberFunction(m) => (
            m.attributes.calling_convention(),
            Some(m.return_type),
            m.argument_list,
            m.this_pointer_type,
        ),
        _ => return None,
    };
    let TypeData::ArgumentList(list) = finder.find(args).ok()?.parse().ok()? else {
        return None;
    };
    let mut params: Vec<Param> = Vec::new();
    if let Some(this) = this {
        params.push(Param {
            name: Some("this".into()),
            ty: type_name(finder, this, 0),
        });
    }
    // `f(void)` is recorded as one `void` argument; it has no parameters.
    let void_only = list.arguments.len() == 1 && type_name(finder, list.arguments[0], 0) == "void";
    if !void_only {
        params.extend(list.arguments.iter().map(|&t| Param {
            name: None,
            ty: type_name(finder, t, 0),
        }));
    }
    Some(FunctionSignature {
        calling_convention: calling_convention(convention).map(str::to_owned),
        return_type: return_type.map(|t| type_name(finder, t, 0)),
        params,
    })
}

/// CodeView `CV_call_e`. On x64 every convention but `__vectorcall` is the same ABI; the name is recorded as
/// the compiler did.
fn calling_convention(cv: u8) -> Option<&'static str> {
    match cv {
        0x00 => Some("__cdecl"),
        0x04 => Some("__fastcall"),
        0x07 => Some("__stdcall"),
        0x0b => Some("__thiscall"),
        0x18 => Some("__vectorcall"),
        _ => None,
    }
}

/// A C-like name for a type: `int`, `const char*`, `struct z_stream_s*`. Not a full C++ declarator (function
/// pointers are `fnptr`, arrays `T[]`); it only needs to be stable within a PDB and readable in review.
fn type_name(finder: &TypeFinder<'_>, index: TypeIndex, depth: u32) -> String {
    if depth > MAX_TYPE_DEPTH {
        return "?".into();
    }
    let Some(data) = finder.find(index).ok().and_then(|t| t.parse().ok()) else {
        return format!("type#{:x}", index.0);
    };
    match data {
        TypeData::Primitive(p) => {
            let base = primitive_name(p.kind);
            match p.indirection {
                Some(_) => format!("{base}*"),
                None => base,
            }
        }
        TypeData::Pointer(p) => {
            let target = type_name(finder, p.underlying_type, depth + 1);
            let sigil = if p.attributes.is_reference() {
                "&"
            } else {
                "*"
            };
            format!("{target}{sigil}")
        }
        TypeData::Modifier(m) => {
            let target = type_name(finder, m.underlying_type, depth + 1);
            match (m.constant, m.volatile) {
                (true, true) => format!("const volatile {target}"),
                (true, false) => format!("const {target}"),
                (false, true) => format!("volatile {target}"),
                (false, false) => target,
            }
        }
        TypeData::Class(c) => format!("struct {}", c.name),
        TypeData::Union(u) => format!("union {}", u.name),
        TypeData::Enumeration(e) => format!("enum {}", e.name),
        TypeData::Array(a) => format!("{}[]", type_name(finder, a.element_type, depth + 1)),
        TypeData::Procedure(_) | TypeData::MemberFunction(_) => "fnptr".into(),
        TypeData::Bitfield(b) => type_name(finder, b.underlying_type, depth + 1),
        other => format!("{:?}", std::mem::discriminant(&other)),
    }
}

fn primitive_name(kind: pdb::PrimitiveKind) -> String {
    use pdb::PrimitiveKind as K;
    match kind {
        K::NoType => "?",
        K::Void => "void",
        K::Char | K::RChar => "char",
        K::UChar => "unsigned char",
        K::WChar => "wchar_t",
        K::RChar16 => "char16_t",
        K::RChar32 => "char32_t",
        K::I8 => "int8_t",
        K::U8 => "uint8_t",
        K::Short | K::I16 => "short",
        K::UShort | K::U16 => "unsigned short",
        K::Long => "long",
        K::ULong => "unsigned long",
        K::I32 => "int",
        K::U32 => "unsigned int",
        K::Quad | K::I64 => "__int64",
        K::UQuad | K::U64 => "unsigned __int64",
        K::F32 => "float",
        K::F64 => "double",
        K::Bool8 => "bool",
        K::HRESULT => "HRESULT",
        _ => return format!("{kind:?}"),
    }
    .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use permanent_beta_model::{BuildId, Machine, PdbInfo};

    fn export_with_pdb(pdb: Option<(&str, u32)>, rvas: &[(u64, Option<&str>)]) -> AnalysisExport {
        let mut e = procedures_export(
            &BuildInfo {
                id: BuildId("b".into()),
                file_name: "app.exe".into(),
                version: None,
                machine: Machine::X64,
                pdb: pdb.map(|(guid, age)| PdbInfo {
                    guid: guid.into(),
                    age,
                }),
            },
            &PdbSymbols {
                guid: String::new(),
                age: 0,
                procedures: BTreeMap::new(),
            },
        );
        e.functions = rvas
            .iter()
            .map(|&(rva, name)| {
                let mut f =
                    procedures_export(&e.build, &symbols(&[(rva, "x", 1)])).functions[0].clone();
                f.name = name.map(str::to_owned);
                f.name_source = name.map(|_| NameSource::Export);
                f.signature = None;
                f
            })
            .collect();
        e
    }

    fn symbols(procs: &[(u64, &str, u16)]) -> PdbSymbols {
        let mut procedures: BTreeMap<Rva, Vec<PdbProcedure>> = BTreeMap::new();
        for &(rva, name, params) in procs {
            procedures.entry(Rva(rva)).or_default().push(PdbProcedure {
                rva: Rva(rva),
                len: 0x10,
                name: name.into(),
                signature: Some(FunctionSignature {
                    calling_convention: Some("__cdecl".into()),
                    return_type: Some("int".into()),
                    params: (0..params)
                        .map(|_| Param {
                            name: None,
                            ty: "int".into(),
                        })
                        .collect(),
                }),
            });
        }
        PdbSymbols {
            guid: "AAAAAAAA-0000-0000-0000-000000000001".into(),
            age: 3,
            procedures,
        }
    }

    const GUID: &str = "aaaaaaaa-0000-0000-0000-000000000001";

    #[test]
    fn names_and_signs_by_entry_and_keeps_export_names() {
        let mut e = export_with_pdb(Some((GUID, 3)), &[(0x1000, None), (0x1100, Some("api_fn"))]);
        let s = symbols(&[
            (0x1000, "helper", 2),
            (0x1100, "api_fn_impl", 1),
            (0x1200, "dead", 0),
        ]);
        let r = apply(&mut e, &s).unwrap();
        assert_eq!(
            r,
            ApplyReport {
                pdb_entries: 3,
                named: 1,
                signed: 2,
                ambiguous: 0,
                not_in_analysis: 1
            }
        );
        assert_eq!(e.functions[0].name.as_deref(), Some("helper"));
        assert_eq!(e.functions[0].name_source, Some(NameSource::Pdb));
        assert_eq!(e.functions[0].signature.as_ref().unwrap().params.len(), 2);
        // The export name wins; the signature is still the PDB's.
        assert_eq!(e.functions[1].name.as_deref(), Some("api_fn"));
        assert_eq!(e.functions[1].name_source, Some(NameSource::Export));
        assert!(e.functions[1].signature.is_some());
    }

    #[test]
    fn folded_entries_get_no_name_or_signature() {
        // Negative case: two procedures folded onto one entry (/OPT:ICF). Picking either name would be a guess.
        let mut e = export_with_pdb(Some((GUID, 3)), &[(0x1000, None)]);
        let s = symbols(&[(0x1000, "crc_a", 1), (0x1000, "crc_b", 2)]);
        let r = apply(&mut e, &s).unwrap();
        assert_eq!(r.ambiguous, 1);
        assert_eq!(r.named, 0);
        assert!(e.functions[0].name.is_none());
        assert!(e.functions[0].signature.is_none());
        // The boundary export lists the entry once, unnamed.
        let p = procedures_export(&e.build, &s);
        assert_eq!(p.functions.len(), 1);
        assert!(p.functions[0].name.is_none());
    }

    #[test]
    fn refuses_another_builds_pdb() {
        // Negative case: a PDB from another build must not name this one's functions.
        let s = symbols(&[(0x1000, "helper", 0)]);
        let mut wrong_age = export_with_pdb(Some((GUID, 4)), &[(0x1000, None)]);
        assert!(apply(&mut wrong_age, &s).is_err());
        let mut wrong_guid = export_with_pdb(
            Some(("bbbbbbbb-0000-0000-0000-000000000001", 3)),
            &[(0x1000, None)],
        );
        assert!(apply(&mut wrong_guid, &s).is_err());
        let mut no_record = export_with_pdb(None, &[(0x1000, None)]);
        assert!(apply(&mut no_record, &s).is_err());
        assert!(wrong_age.functions[0].name.is_none());
    }
}
