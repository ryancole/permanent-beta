//! Names and signatures from an MSVC PDB (design §4.1, M1 spike), read with the `pdb` crate.
//!
//! What it reads: procedure symbols (`S_GPROC32`/`S_LPROC32`) from every module, which gives each function's
//! entry, length, undecorated name and type; and from the type stream, the procedure's return and parameter
//! types. Data symbols (`S_GDATA32`/`S_LDATA32`) give the global variables, for recording global state
//! (design §7.3). Parameter names (local symbols) are not read: a renamed parameter must not look like a changed
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
    ANALYSIS_SCHEMA_VERSION, AnalysisExport, BuildInfo, FieldLayout, FunctionFeatures,
    FunctionSignature, GlobalVar, NameSource, Param, Producer, Rva, TypeLayout,
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
    /// Layouts of the structs, classes and unions the procedures' signatures use (and of the structs inside
    /// them by value), sorted by name.
    pub types: Vec<TypeLayout>,
    /// Global variables with a unique name, sorted by name. A static local is named `procedure::name`; a name
    /// two variables at different addresses share is left out (it couldn't be found again by name).
    pub globals: Vec<GlobalVar>,
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
    /// Globals the code refers to, recorded in the analysis.
    pub globals: usize,
}

/// Read a PDB file.
pub fn read(path: &Path) -> Result<PdbSymbols, AnalysisError> {
    read_with_types(path, &[])
}

/// [`read`], also keeping the layouts of the structs named in `extra` (and the structs inside them by value),
/// which no procedure's signature may use: one code casts an opaque pointer to (zlib's `z_stream.state`, declared
/// `internal_state*`, holds a `struct inflate_state` in inflate). A name the PDB doesn't define is an error.
pub fn read_with_types(path: &Path, extra: &[String]) -> Result<PdbSymbols, AnalysisError> {
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
    let mut definitions = Definitions::new();
    while let Some(item) = types.next().map_err(err)? {
        finder.update(&types);
        let name = match item.parse() {
            Ok(TypeData::Class(c)) if !c.properties.forward_reference() => {
                c.name.to_string().into_owned()
            }
            Ok(TypeData::Union(u)) if !u.properties.forward_reference() => {
                u.name.to_string().into_owned()
            }
            _ => continue,
        };
        definitions.entry(name).or_insert(item.index());
    }
    let mut used_types: Vec<String> = Vec::new();

    let mut procedures: BTreeMap<Rva, Vec<PdbProcedure>> = BTreeMap::new();
    // Data symbols by qualified name: (RVA, size, type). More than one RVA under a name: ambiguous.
    let mut data: BTreeMap<String, Vec<(Rva, u64, String)>> = BTreeMap::new();
    let mut add_data = |name: String, d: &pdb::DataSymbol<'_>| {
        let Some(rva) = d.offset.to_rva(&address_map) else {
            return;
        };
        let entry = (
            Rva(u64::from(rva.0)),
            type_size(&finder, &definitions, d.type_index, 0),
            type_name(&finder, d.type_index, 0),
        );
        let at = data.entry(name).or_default();
        if !at.iter().any(|e| e.0 == entry.0) {
            at.push(entry);
        }
    };
    let mut modules = dbi.modules().map_err(err)?;
    while let Some(module) = modules.next().map_err(err)? {
        let Some(module_info) = pdb.module_info(&module).map_err(err)? else {
            continue;
        };
        let mut symbols = module_info.symbols().map_err(err)?;
        // Enclosing procedures, innermost last: (index of their S_END, name). A data symbol inside one is a
        // static local.
        let mut scopes: Vec<(pdb::SymbolIndex, String)> = Vec::new();
        while let Some(symbol) = symbols.next().map_err(err)? {
            while scopes.last().is_some_and(|(end, _)| *end <= symbol.index()) {
                scopes.pop();
            }
            // Symbol kinds the crate can't parse are skipped, not fatal: only procedures and data matter here.
            let p = match symbol.parse() {
                Ok(pdb::SymbolData::Procedure(p)) => p,
                Ok(pdb::SymbolData::Data(d)) => {
                    let name = d.name.to_string();
                    let name = match scopes.last() {
                        Some((_, proc_name)) => format!("{proc_name}::{name}"),
                        None => name.into_owned(),
                    };
                    add_data(name, &d);
                    continue;
                }
                _ => continue,
            };
            scopes.push((p.end, p.name.to_string().into_owned()));
            let Some(rva) = p.offset.to_rva(&address_map) else {
                continue;
            };
            let rva = Rva(u64::from(rva.0));
            used_types.extend(udts_of_procedure(&finder, p.type_index));
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
    // Globals (S_GDATA32) are in the global symbol stream; file statics can be in both.
    let global_symbols = pdb.global_symbols().map_err(err)?;
    let mut symbols = global_symbols.iter();
    while let Some(symbol) = symbols.next().map_err(err)? {
        if let Ok(pdb::SymbolData::Data(d)) = symbol.parse() {
            add_data(d.name.to_string().into_owned(), &d);
        }
    }
    let globals = data
        .into_iter()
        .filter_map(|(name, at)| match at.as_slice() {
            [(rva, size, ty)] => Some(GlobalVar {
                name,
                rva: *rva,
                size: *size,
                ty: ty.clone(),
            }),
            _ => None,
        })
        .collect();
    if let Some(missing) = extra.iter().find(|n| !definitions.contains_key(*n)) {
        return Err(AnalysisError::InvalidPdb {
            path: shown,
            reason: format!("no struct, class or union named {missing:?}"),
        });
    }
    used_types.extend(extra.iter().cloned());
    used_types.sort();
    used_types.dedup();
    let types = layouts(&finder, &definitions, used_types);
    Ok(PdbSymbols {
        guid,
        age,
        procedures,
        types,
        globals,
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
    export.types = symbols.types.clone();
    // Only the globals the code refers to: `data_refs` are the analyzer's references into writable sections.
    let refs: Vec<Rva> = export
        .functions
        .iter()
        .flat_map(|f| f.data_refs.iter().copied())
        .collect();
    export.globals = symbols
        .globals
        .iter()
        .filter(|g| {
            refs.iter()
                .any(|r| (g.rva.0..g.rva.0 + g.size.max(1)).contains(&r.0))
        })
        .cloned()
        .collect();
    report.globals = export.globals.len();
    export.data_symbols = symbols.globals.clone();
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
                data_refs: vec![],
                signature: single.and_then(|p| p.signature.clone()),
                inferred_args: None,
                inferred_arg_classes: vec![],
                mnemonic_counts: Default::default(),
                pseudocode: None,
                entry: None,
                arg_accesses: vec![],
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
        code_tables: Vec::new(),
        types: Vec::new(),
        globals: Vec::new(),
        data_symbols: Vec::new(),
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
    let args: Vec<(String, bool)> = list
        .arguments
        .iter()
        .map(|&t| (type_name(finder, t, 0), is_no_type(finder, t)))
        .collect();
    params.extend(parameter_list(args)?);
    Some(FunctionSignature {
        calling_convention: calling_convention(convention).map(str::to_owned),
        return_type: return_type.map(|t| type_name(finder, t, 0)),
        params,
    })
}

/// The parameters of an argument list, each type's name and whether it's CodeView's "no type". `None` when
/// the count isn't known: a list ending in "no type" is a variadic function (`f(const char*, ...)`) or one
/// defined without a prototype (K&R `f()` in C, as zlib 1.2.13 defines its functions), which the PDB can't tell
/// apart. Counting that as one parameter of unknown type made correct matches fail the parameter-count check
/// against the next release's prototypes. `f(void)` is recorded as one `void` argument: no parameters.
fn parameter_list(args: Vec<(String, bool)>) -> Option<Vec<Param>> {
    if args.last().is_some_and(|(_, no_type)| *no_type) {
        return None;
    }
    if matches!(args.as_slice(), [(ty, _)] if ty == "void") {
        return Some(Vec::new());
    }
    Some(
        args.into_iter()
            .map(|(ty, _)| Param { name: None, ty })
            .collect(),
    )
}

/// Whether `index` is CodeView's "no type" (not a pointer to it).
fn is_no_type(finder: &TypeFinder<'_>, index: TypeIndex) -> bool {
    matches!(
        finder.find(index).ok().and_then(|t| t.parse().ok()),
        Some(TypeData::Primitive(p)) if p.kind == pdb::PrimitiveKind::NoType && p.indirection.is_none()
    )
}

/// How many levels of by-value members are followed from a struct a signature uses (a struct inside a struct).
const MAX_NESTED_LAYOUTS: u32 = 3;

/// Full (non-forward) definitions of named structs, classes and unions, by name. The first definition of a
/// name wins; a forward reference has no fields and is resolved through this.
type Definitions = BTreeMap<String, TypeIndex>;

/// Struct, class and union names a procedure type uses, through pointers, references, modifiers and arrays.
fn udts_of_procedure(finder: &TypeFinder<'_>, index: TypeIndex) -> Vec<String> {
    let Some(data) = finder.find(index).ok().and_then(|t| t.parse().ok()) else {
        return Vec::new();
    };
    let (ret, args, this) = match data {
        TypeData::Procedure(p) => (p.return_type, p.argument_list, None),
        TypeData::MemberFunction(m) => (Some(m.return_type), m.argument_list, m.this_pointer_type),
        _ => return Vec::new(),
    };
    let mut out = Vec::new();
    let mut roots: Vec<TypeIndex> = ret.into_iter().chain(this).collect();
    if let Some(TypeData::ArgumentList(list)) = finder.find(args).ok().and_then(|t| t.parse().ok())
    {
        roots.extend(list.arguments);
    }
    for r in roots {
        if let Some(name) = udt_behind(finder, r, 0) {
            out.push(name);
        }
    }
    out
}

/// The struct, class or union a type is, or points to.
fn udt_behind(finder: &TypeFinder<'_>, index: TypeIndex, depth: u32) -> Option<String> {
    if depth > MAX_TYPE_DEPTH {
        return None;
    }
    match finder.find(index).ok()?.parse().ok()? {
        TypeData::Class(c) => Some(c.name.to_string().into_owned()),
        TypeData::Union(u) => Some(u.name.to_string().into_owned()),
        TypeData::Pointer(p) => udt_behind(finder, p.underlying_type, depth + 1),
        TypeData::Modifier(m) => udt_behind(finder, m.underlying_type, depth + 1),
        TypeData::Array(a) => udt_behind(finder, a.element_type, depth + 1),
        _ => None,
    }
}

/// A type's size in bytes, resolving forward references by name. 0 when unknown.
fn type_size(finder: &TypeFinder<'_>, defs: &Definitions, index: TypeIndex, depth: u32) -> u64 {
    if depth > MAX_TYPE_DEPTH {
        return 0;
    }
    let Some(data) = finder.find(index).ok().and_then(|t| t.parse().ok()) else {
        return 0;
    };
    let by_name = |name: &str| {
        defs.get(name)
            .filter(|&&d| d != index)
            .map_or(0, |&d| type_size(finder, defs, d, depth + 1))
    };
    match data {
        TypeData::Primitive(p) if p.indirection.is_some() => 8,
        TypeData::Primitive(p) => primitive_size(p.kind),
        TypeData::Pointer(p) => u64::from(p.attributes.size()),
        TypeData::Modifier(m) => type_size(finder, defs, m.underlying_type, depth + 1),
        TypeData::Class(c) if c.properties.forward_reference() => by_name(&c.name.to_string()),
        TypeData::Class(c) => c.size,
        TypeData::Union(u) if u.properties.forward_reference() => by_name(&u.name.to_string()),
        TypeData::Union(u) => u.size,
        TypeData::Enumeration(e) => type_size(finder, defs, e.underlying_type, depth + 1),
        // CodeView array dimensions are in bytes; the last is the whole array.
        TypeData::Array(a) => a.dimensions.last().copied().map_or(0, u64::from),
        TypeData::Bitfield(b) => type_size(finder, defs, b.underlying_type, depth + 1),
        _ => 0,
    }
}

fn primitive_size(kind: pdb::PrimitiveKind) -> u64 {
    use pdb::PrimitiveKind as K;
    match kind {
        K::Char | K::RChar | K::UChar | K::I8 | K::U8 | K::Bool8 => 1,
        K::WChar | K::RChar16 | K::Short | K::UShort | K::I16 | K::U16 | K::Bool16 => 2,
        K::RChar32 | K::Long | K::ULong | K::I32 | K::U32 | K::F32 | K::Bool32 | K::HRESULT => 4,
        K::Quad | K::UQuad | K::I64 | K::U64 | K::F64 | K::Bool64 => 8,
        K::F80 => 10,
        K::Octa | K::UOcta | K::I128 | K::U128 | K::F128 => 16,
        _ => 0,
    }
}

/// The layout of the full definition at `index`, and the struct types its by-value members use.
fn layout(
    finder: &TypeFinder<'_>,
    defs: &Definitions,
    index: TypeIndex,
) -> Option<(TypeLayout, Vec<String>)> {
    let (name, size, union, mut list) = match finder.find(index).ok()?.parse().ok()? {
        TypeData::Class(c) => (c.name.to_string().into_owned(), c.size, false, c.fields),
        TypeData::Union(u) => (
            u.name.to_string().into_owned(),
            u.size,
            true,
            Some(u.fields),
        ),
        _ => return None,
    };
    let mut fields = Vec::new();
    let mut nested = Vec::new();
    while let Some(at) = list.take() {
        let Some(TypeData::FieldList(fl)) = finder.find(at).ok().and_then(|t| t.parse().ok())
        else {
            break;
        };
        for f in fl.fields {
            match f {
                TypeData::Member(m) => {
                    let bits = match finder.find(m.field_type).ok().and_then(|t| t.parse().ok()) {
                        Some(TypeData::Bitfield(b)) => Some((b.position, b.length)),
                        _ => None,
                    };
                    if let Some(TypeData::Class(_) | TypeData::Union(_)) =
                        finder.find(m.field_type).ok().and_then(|t| t.parse().ok())
                    {
                        nested.extend(udt_behind(finder, m.field_type, 0));
                    }
                    fields.push(FieldLayout {
                        name: m.name.to_string().into_owned(),
                        offset: m.offset,
                        size: type_size(finder, defs, m.field_type, 0),
                        ty: type_name(finder, m.field_type, 0),
                        bits,
                    });
                }
                TypeData::BaseClass(b) => {
                    let base = type_name(finder, b.base_class, 0);
                    nested.extend(udt_behind(finder, b.base_class, 0));
                    fields.push(FieldLayout {
                        name: format!("<base {}>", base.trim_start_matches("struct ")),
                        offset: u64::from(b.offset),
                        size: type_size(finder, defs, b.base_class, 0),
                        ty: base,
                        bits: None,
                    });
                }
                TypeData::VirtualFunctionTablePointer(_) => fields.push(FieldLayout {
                    name: "<vfptr>".into(),
                    offset: 0,
                    size: 8,
                    ty: "void**".into(),
                    bits: None,
                }),
                _ => {}
            }
        }
        list = fl.continuation;
    }
    Some((
        TypeLayout {
            name,
            size,
            union,
            fields,
        },
        nested,
    ))
}

/// Layouts of the structs the procedures' signatures use, and of their by-value members' structs, sorted by
/// name. Names without a full definition in this PDB are left out.
fn layouts(finder: &TypeFinder<'_>, defs: &Definitions, roots: Vec<String>) -> Vec<TypeLayout> {
    let mut done: BTreeMap<String, TypeLayout> = BTreeMap::new();
    let mut level: Vec<String> = roots;
    for _ in 0..=MAX_NESTED_LAYOUTS {
        let mut next = Vec::new();
        for name in level {
            if done.contains_key(&name) {
                continue;
            }
            let Some(&index) = defs.get(&name) else {
                continue;
            };
            if let Some((l, nested)) = layout(finder, defs, index) {
                next.extend(nested);
                done.insert(name, l);
            }
        }
        level = next;
    }
    done.into_values().collect()
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
                types: Vec::new(),
                globals: Vec::new(),
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
            types: Vec::new(),
            globals: Vec::new(),
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
                not_in_analysis: 1,
                globals: 0,
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
    fn keeps_only_the_globals_the_code_refers_to() {
        let mut e = export_with_pdb(
            Some(("AAAAAAAA-0000-0000-0000-000000000001", 3)),
            &[(0x1000, None)],
        );
        // One reference into the middle of a struct, none to the other global.
        e.functions[0].data_refs = vec![Rva(0x4008)];
        let mut s = symbols(&[(0x1000, "reader", 0)]);
        let global = |name: &str, rva, size| GlobalVar {
            name: name.into(),
            rva: Rva(rva),
            size,
            ty: "int".into(),
        };
        s.globals = vec![
            global("g_config", 0x4000, 16),
            global("g_unused", 0x4010, 4),
        ];
        let r = apply(&mut e, &s).unwrap();
        assert_eq!(r.globals, 1);
        assert_eq!(e.globals, vec![global("g_config", 0x4000, 16)]);
        assert_eq!(
            e.global_at(Rva(0x400f)).map(|g| g.name.as_str()),
            Some("g_config")
        );
        // Negative: the unreferenced global isn't recorded, and nothing claims an address past the struct.
        assert!(e.global("g_unused").is_none());
        assert!(e.global_at(Rva(0x4010)).is_none());
        // Every data symbol is kept for mapping old-image addresses in replay, referenced or not.
        assert_eq!(e.data_symbols, s.globals);
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
    fn argument_lists_with_an_unknown_count_have_no_signature() {
        let arg = |ty: &str| (ty.to_owned(), false);
        let tys =
            |p: Option<Vec<Param>>| p.map(|p| p.into_iter().map(|p| p.ty).collect::<Vec<_>>());
        assert_eq!(
            tys(parameter_list(vec![arg("int"), arg("char*")])),
            Some(vec!["int".to_owned(), "char*".to_owned()])
        );
        assert_eq!(tys(parameter_list(vec![arg("void")])), Some(vec![]));
        assert_eq!(tys(parameter_list(vec![])), Some(vec![]));
        // Negative: K&R `f()` and variadic `f(const char*, ...)` end in "no type": the count isn't known, so no
        // signature, never one parameter of type `?`.
        let none = ("?".to_owned(), true);
        assert_eq!(parameter_list(vec![none.clone()]), None);
        assert_eq!(parameter_list(vec![arg("const char*"), none]), None);
        // A depth-limited name is `?` too, but it's a real parameter.
        assert_eq!(
            tys(parameter_list(vec![arg("?")])),
            Some(vec!["?".to_owned()])
        );
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
