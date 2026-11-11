//! Native PE x64 analyzer (design §4.2).
//!
//! Reads only what's in the binary: no PDB or map file. (The PDB GUID from the debug directory is recorded so
//! the matching PDB can be found later, but no symbols are read.) Names come from exports only.
//!
//! Known gaps: no PDB names or signatures (see `crate::symbols`), no version resource, dead code without
//! `.pdata` isn't found, and `edges` isn't computed. Address-taken functions (`lea` of code), code pointers in
//! data (base relocations) and chained `.pdata` fragments are handled (see `function`).

pub(crate) mod function;
pub(crate) mod ilt;
pub(crate) mod image;
pub mod pattern;
pub(crate) mod protection;

use crate::{AnalysisError, Analyzer};
use permanent_beta_model::{
    ANALYSIS_SCHEMA_VERSION, AnalysisExport, BuildId, BuildInfo, Machine, NameSource, PdbInfo,
    Producer, Rva,
};
use sha2::{Digest, Sha256};
use std::path::Path;

/// The native normalizer's [`AnalysisExport::features_version`]. Bump the number on any change to what a code
/// feature covers (the normalized or mnemonic hash, mnemonic counts, blocks and edges, inferred arguments, callee
/// order): analyses from before and after can't be matched against each other.
///
/// 2: calls and code pointers to an incremental linking thunk are the thunk's target's (`ilt`), and each thunk is
/// its own function.
pub const FEATURES_VERSION: &str = "native-2";

pub const PRODUCER: &str = "permanent-beta-native-pe";

pub struct NativePeAnalyzer;

impl Analyzer for NativePeAnalyzer {
    fn name(&self) -> &'static str {
        PRODUCER
    }

    fn analyze(&self, binary: &Path) -> Result<AnalysisExport, AnalysisError> {
        let path = binary.display().to_string();
        let bytes = std::fs::read(binary).map_err(|source| AnalysisError::Io {
            path: path.clone(),
            source,
        })?;
        let file_name = binary
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.clone());
        analyze_bytes(&bytes, &file_name).map_err(|e| match e {
            BytesError::Invalid(reason) => AnalysisError::InvalidPe { path, reason },
            BytesError::Protected(reason) => AnalysisError::Protected { path, reason },
        })
    }
}

#[derive(Debug)]
pub enum BytesError {
    Invalid(String),
    /// A protected or packed binary, refused (design §12).
    Protected(String),
}

/// Parse `bytes`, refusing a protected or packed binary.
fn parse_checked(bytes: &[u8]) -> Result<image::Image, BytesError> {
    let image = image::Image::parse_any(bytes).map_err(BytesError::Invalid)?;
    match protection::detect(&image) {
        Some(why) => Err(BytesError::Protected(protection::refusal(&why))),
        None => Ok(image),
    }
}

/// A build's id: the SHA-256 of the file, lowercase hex.
pub fn build_id(bytes: &[u8]) -> BuildId {
    BuildId(
        Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
    )
}

/// Analyze an in-memory PE x64 image.
pub fn analyze_bytes(bytes: &[u8], file_name: &str) -> Result<AnalysisExport, BytesError> {
    let image = parse_checked(bytes)?;
    let ranges = function::discover(&image);
    Ok(analyze_ranges(
        &image,
        bytes,
        file_name,
        ranges,
        Producer {
            tool: PRODUCER.to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        },
    ))
}

/// A function's entry and its code ranges `[start, end)`.
pub type FunctionBody = (Rva, Vec<(Rva, Rva)>);

/// Each function the native analyzer discovers, as its entry and code ranges `[start, end)`: the main range
/// first, then its chained `.pdata` fragments. The same shape as a Ghidra export's bodies.
pub fn function_bodies(bytes: &[u8]) -> Result<Vec<FunctionBody>, BytesError> {
    let image = parse_checked(bytes)?;
    Ok(function::discover(&image)
        .iter()
        .map(|r| {
            let rva = |x: u32| Rva(u64::from(x));
            (
                rva(r.start),
                std::iter::once((r.start, r.end))
                    .chain(r.fragments.iter().copied())
                    .map(|(s, e)| (rva(s), rva(e)))
                    .collect(),
            )
        })
        .collect())
}

/// Features for function boundaries found by any analyzer (native discovery, or a Ghidra export), named from
/// the image's exports. Every hash comes from here, so analyses from different sources stay comparable.
pub(crate) fn analyze_ranges(
    image: &image::Image,
    bytes: &[u8],
    file_name: &str,
    ranges: Vec<function::FunctionRange>,
    producer: Producer,
) -> AnalysisExport {
    let build_id = build_id(bytes).0;
    let mut code_tables = function::code_tables(image, &ranges);

    let mut functions: Vec<_> = ranges
        .into_iter()
        .map(|range| {
            let mut f = function::features(image, &range);
            if let Some((_, name)) = image.exports.iter().find(|e| e.0 == range.start) {
                f.name = Some(name.clone());
                f.name_source = Some(NameSource::Export);
            }
            f
        })
        .collect();
    through_ilt(&ilt::find(image), &mut functions, &mut code_tables);

    AnalysisExport {
        schema_version: ANALYSIS_SCHEMA_VERSION,
        build: BuildInfo {
            id: BuildId(build_id),
            file_name: file_name.to_owned(),
            version: None,
            machine: Machine::X64,
            pdb: image.pdb.clone().map(|(guid, age)| PdbInfo { guid, age }),
        },
        producer,
        features_version: Some(FEATURES_VERSION.to_owned()),
        functions,
        code_tables,
        types: Vec::new(),
        globals: Vec::new(),
        data_symbols: Vec::new(),
        pointer_aliases: Vec::new(),
    }
}

/// Mark each incremental linking thunk (`ilt`) found as a function with its target, and take every call, code
/// pointer and table slot to a thunk as one to its target: in an incremental image every call goes through one,
/// so otherwise a function's only caller would be its thunk.
fn through_ilt(
    ilt: &std::collections::BTreeMap<u32, u32>,
    functions: &mut [permanent_beta_model::FunctionFeatures],
    code_tables: &mut [permanent_beta_model::CodeTable],
) {
    if ilt.is_empty() {
        return;
    }
    let target = |r: Rva| {
        u32::try_from(r.0)
            .ok()
            .and_then(|r| ilt.get(&r))
            .map_or(r, |&t| Rva(u64::from(t)))
    };
    let starts: std::collections::BTreeSet<Rva> = functions.iter().map(|f| f.rva).collect();
    for f in functions.iter_mut() {
        let to = target(f.rva);
        if to != f.rva && starts.contains(&to) {
            f.thunk_to = Some(to);
            continue;
        }
        let mut seen = std::collections::BTreeSet::new();
        f.callees = f
            .callees
            .iter()
            .map(|&c| target(c))
            .filter(|c| seen.insert(*c))
            .collect();
        f.code_refs = f.code_refs.iter().map(|&c| target(c)).collect();
        f.code_refs.sort_unstable();
        f.code_refs.dedup();
    }
    for t in code_tables {
        for s in &mut t.slots {
            *s = target(*s);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calls_through_the_ilt_are_calls_to_its_targets() {
        // Four slots, each to a `ret` at 0x1100 + 0x10·i; then a caller at 0x1200 calling slots 0 and 1 and
        // slot 0 again, and taking slot 2's address.
        let mut code = ilt::tests::ilt_code(4);
        code.resize(0x200, 0xcc);
        let call = |at: u32, to: u32, op: &[u8], code: &mut Vec<u8>| {
            let len = op.len() as u32 + 4;
            code.extend_from_slice(op);
            code.extend_from_slice(&((to as i32) - (at as i32 + len as i32)).to_le_bytes());
        };
        call(0x1200, 0x1005, &[0xe8], &mut code);
        call(0x1205, 0x100a, &[0xe8], &mut code);
        call(0x120a, 0x1005, &[0xe8], &mut code);
        call(0x120f, 0x100f, &[0x48, 0x8d, 0x0d], &mut code); // lea rcx, [rip+…]
        code.push(0xc3);
        let mut img = image::tests::image(&code, &[]);
        img.entry = Some(0x1200);
        let ranges = function::discover(&img);
        let e = analyze_ranges(
            &img,
            &code,
            "t.exe",
            ranges,
            Producer {
                tool: PRODUCER.into(),
                version: "0".into(),
            },
        );
        let f = |rva: u64| e.function(Rva(rva)).unwrap();
        // Every slot is its own 5-byte thunk to its target, including the one nothing calls (0x1014).
        for i in 0..4u64 {
            let t = f(0x1005 + 5 * i);
            assert_eq!(t.size, 5);
            assert_eq!(t.thunk_to, Some(Rva(0x1100 + 0x10 * i)));
        }
        let caller = f(0x1200);
        assert_eq!(caller.thunk_to, None);
        assert_eq!(caller.callees, vec![Rva(0x1100), Rva(0x1110)]);
        assert_eq!(caller.code_refs, vec![Rva(0x1120)]);
        // Negative: the targets themselves aren't thunks.
        assert_eq!(f(0x1100).thunk_to, None);
    }

    #[test]
    fn without_an_ilt_calls_are_left_alone() {
        // Negative: a single `jmp` stub (a tail-calling function), not a table, is an ordinary function.
        let mut code = vec![0xe9];
        code.extend_from_slice(&(0x10i32 - 5).to_le_bytes());
        code.resize(0x10, 0xcc);
        code.push(0xc3);
        let mut img = image::tests::image(&code, &[]);
        img.entry = Some(0x1000);
        img.exports = vec![(0x1010, "g".into())];
        let ranges = function::discover(&img);
        let e = analyze_ranges(
            &img,
            &code,
            "t.exe",
            ranges,
            Producer {
                tool: PRODUCER.into(),
                version: "0".into(),
            },
        );
        let stub = e.function(Rva(0x1000)).unwrap();
        assert_eq!(stub.thunk_to, None);
        assert_eq!(stub.callees, vec![Rva(0x1010)]);
    }

    #[test]
    fn rejects_non_pe_input() {
        assert!(matches!(
            analyze_bytes(b"not a pe file", "x"),
            Err(BytesError::Invalid(_))
        ));
    }

    #[test]
    fn every_native_analysis_names_its_features_version() {
        // Whatever found the boundaries (native discovery or a Ghidra export), the features come from here.
        let image = image::tests::image(&[0xc3], &[]);
        let producer = Producer {
            tool: "ghidra".into(),
            version: "0".into(),
        };
        let e = analyze_ranges(&image, &[0xc3], "t.exe", Vec::new(), producer);
        assert_eq!(e.features_version.as_deref(), Some(FEATURES_VERSION));
        // Negative: an analysis without it doesn't match one with it.
        let mut old = e.clone();
        old.features_version = None;
        assert!(old.features_comparable(&e).is_err());
        assert!(e.features_comparable(&e).is_ok());
    }
}
