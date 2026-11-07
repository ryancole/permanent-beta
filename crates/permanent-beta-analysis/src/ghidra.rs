//! Function boundaries from a Ghidra headless export (design §4.3, M1).
//!
//! `integrations/ghidra/scripts/ExportFunctions.java` writes Ghidra's functions: entry, body (address ranges),
//! name and signature with where Ghidra got them, and optionally pseudocode. This turns that into an
//! [`AnalysisExport`] of the same binary: Ghidra decides the boundaries, and the native code computes every
//! hash and feature from them, so Ghidra-based and native analyses compare hash for hash.
//!
//! What's trusted from Ghidra:
//!
//! - **Boundaries**, always (that's what the export is for). A body outside executable code is dropped and
//!   reported. The part of the body containing the entry is the function's main range; other parts are
//!   fragments, as chained `.pdata` fragments are for the native analyzer.
//! - **Names, never.** `DEFAULT` names are placeholders (`FUN_1400010c0`), `ANALYSIS` names are guesses
//!   (Function ID matches library code by hash), and with the PDB analyzers off `IMPORTED` names are the
//!   exports, which the native code reads itself. The name-matching pass trusts any name, so a guess must not
//!   reach it.
//! - **Signatures** only when Ghidra didn't infer them (`IMPORTED` or `USER_DEFINED`). An inferred prototype
//!   (`undefined8 FUN_...(longlong param_1)`) would feed the parameter-count check and repair's "signature
//!   changed" rule with a guess.
//! - **Pseudocode**, as review and AI context only (it's never matched on).

use crate::AnalysisError;
use crate::native::{self, function::FunctionRange, image::Image};
use permanent_beta_model::{AnalysisExport, FunctionSignature, Param, Producer, Rva};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

pub const PRODUCER: &str = "ghidra-export";

/// The JSON `ExportFunctions.java` writes.
#[derive(Debug, Clone, Deserialize)]
pub struct GhidraExport {
    pub producer: String,
    pub ghidra_version: String,
    /// SHA-256 of the file Ghidra imported.
    pub sha256: String,
    pub image_base: Rva,
    pub functions: Vec<GhidraFunction>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GhidraFunction {
    pub entry: Rva,
    /// `[start, end)` RVA ranges.
    pub body: Vec<(Rva, Rva)>,
    pub name: Option<String>,
    /// Ghidra's `SourceType`: `DEFAULT`, `ANALYSIS`, `IMPORTED` or `USER_DEFINED`.
    pub name_source: String,
    #[serde(default)]
    pub thunk: bool,
    pub signature_source: String,
    pub calling_convention: Option<String>,
    pub return_type: Option<String>,
    #[serde(default)]
    pub params: Vec<String>,
    #[serde(default)]
    pub pseudocode: Option<String>,
}

/// What [`analyze`] used and dropped.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GhidraReport {
    /// Functions in the export.
    pub exported: usize,
    /// Functions in the analysis.
    pub analyzed: usize,
    /// Entries listed more than once (the first is used).
    pub duplicates: usize,
    /// Functions dropped because their entry or a body range isn't in executable code.
    pub outside_code: Vec<Rva>,
    /// Ghidra names not used (all of them; see the module docs), excluding `DEFAULT` placeholders.
    pub names_ignored: usize,
    pub signatures_used: usize,
    /// Signatures not used: inferred, or on a name Function ID guessed.
    pub signatures_inferred: usize,
    pub with_pseudocode: usize,
}

pub fn load(path: &Path) -> Result<GhidraExport, AnalysisError> {
    let shown = path.display().to_string();
    let text = std::fs::read_to_string(path).map_err(|source| AnalysisError::Io {
        path: shown.clone(),
        source,
    })?;
    let export: GhidraExport =
        serde_json::from_str(&text).map_err(|source| AnalysisError::Json {
            path: shown.clone(),
            source,
        })?;
    if export.producer != PRODUCER {
        return Err(AnalysisError::Unsupported {
            path: shown,
            reason: format!("producer `{}`, expected `{PRODUCER}`", export.producer),
        });
    }
    Ok(export)
}

/// Analyze `bytes` (the binary Ghidra exported) with Ghidra's function boundaries. Fails if the export is of
/// another file or another image base.
pub fn analyze(
    bytes: &[u8],
    file_name: &str,
    ghidra: &GhidraExport,
) -> Result<(AnalysisExport, GhidraReport), String> {
    let image = Image::parse(bytes)?;
    let id = native::build_id(bytes);
    if !ghidra.sha256.eq_ignore_ascii_case(&id.0) {
        return Err(format!(
            "the Ghidra export is of another file (SHA-256 {}, this file is {})",
            ghidra.sha256, id.0
        ));
    }
    if ghidra.image_base.0 != image.base {
        return Err(format!(
            "the Ghidra export uses image base {}, the file's is 0x{:x} (was the program rebased?)",
            ghidra.image_base, image.base
        ));
    }

    let mut report = GhidraReport {
        exported: ghidra.functions.len(),
        ..GhidraReport::default()
    };
    let mut by_entry: BTreeMap<u32, (FunctionRange, &GhidraFunction)> = BTreeMap::new();
    for f in &ghidra.functions {
        let Some(range) = range(&image, f) else {
            report.outside_code.push(f.entry);
            continue;
        };
        if by_entry.contains_key(&range.start) {
            report.duplicates += 1;
            continue;
        }
        by_entry.insert(range.start, (range, f));
    }

    let (ranges, sources): (Vec<FunctionRange>, Vec<&GhidraFunction>) =
        by_entry.into_values().unzip();
    let mut export = native::analyze_ranges(
        &image,
        bytes,
        file_name,
        ranges,
        Producer {
            tool: PRODUCER.to_owned(),
            version: format!(
                "ghidra {} + {}",
                ghidra.ghidra_version,
                env!("CARGO_PKG_VERSION")
            ),
        },
    );
    for (feature, source) in export.functions.iter_mut().zip(sources) {
        if source.name_source != "DEFAULT" {
            report.names_ignored += 1;
        }
        if trusted(source) {
            feature.signature = Some(signature(source));
            report.signatures_used += 1;
        } else {
            report.signatures_inferred += 1;
        }
        if let Some(c) = &source.pseudocode {
            feature.pseudocode = Some(c.clone());
            report.with_pseudocode += 1;
        }
    }
    report.analyzed = export.functions.len();
    Ok((export, report))
}

/// A signature Ghidra didn't infer, attached to a function it didn't identify by guesswork. Ghidra applies
/// library prototypes by name: for an import thunk (`memcpy`) the name is the import's, but a name from Function
/// ID (`ANALYSIS`, e.g. `__security_check_cookie`) is a guess, and so is the prototype it brings.
fn trusted(f: &GhidraFunction) -> bool {
    matches!(f.signature_source.as_str(), "IMPORTED" | "USER_DEFINED")
        && f.name_source != "ANALYSIS"
}

fn signature(f: &GhidraFunction) -> FunctionSignature {
    FunctionSignature {
        calling_convention: f.calling_convention.clone(),
        return_type: f.return_type.clone(),
        params: f
            .params
            .iter()
            .map(|ty| Param {
                name: None,
                ty: ty.clone(),
            })
            .collect(),
    }
}

/// The function's code as a native range: the body part holding the entry, from the entry on, is the main
/// range; every other part (including any part of that range before the entry) is a fragment. Parts are cut at
/// every `.pdata` boundary inside them: Ghidra merges touching ranges, while the native analyzer keeps a
/// chained fragment as its own segment, and the hash records segments. Cutting at the binary's own unwind
/// table makes equal bodies hash equally. `None` if the entry or any part is outside executable code, or no
/// part holds the entry.
fn range(image: &Image, f: &GhidraFunction) -> Option<FunctionRange> {
    let entry = u32::try_from(f.entry.0).ok()?;
    let mut parts: Vec<(u32, u32)> = Vec::new();
    for &(s, e) in &f.body {
        let (s, e) = (u32::try_from(s.0).ok()?, u32::try_from(e.0).ok()?);
        if e <= s || !image.is_executable(s) || !image.is_executable(e - 1) {
            return None;
        }
        image.bytes(s, (e - s) as usize)?;
        let mut cuts: Vec<u32> = image
            .pdata
            .iter()
            .flat_map(|r| [r.begin, r.end])
            .filter(|&c| s < c && c < e)
            .collect();
        cuts.sort_unstable();
        cuts.dedup();
        let mut from = s;
        for c in cuts {
            parts.push((from, c));
            from = c;
        }
        parts.push((from, e));
    }
    let main = parts.iter().position(|&(s, e)| s <= entry && entry < e)?;
    let (main_start, main_end) = parts.remove(main);
    if main_start < entry {
        parts.push((main_start, entry));
    }
    parts.sort_unstable();
    Some(FunctionRange {
        start: entry,
        end: main_end,
        from_pdata: false,
        fragments: parts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::image::tests::image;

    /// `xor eax, eax; ret` at 0x1000; `mov eax, 1; ret` at 0x1010; padding in between.
    fn code() -> Vec<u8> {
        let mut c = vec![0x33, 0xc0, 0xc3];
        c.resize(0x10, 0xcc);
        c.extend([0xb8, 1, 0, 0, 0, 0xc3]);
        c
    }

    fn func(entry: u64, body: &[(u64, u64)]) -> GhidraFunction {
        GhidraFunction {
            entry: Rva(entry),
            body: body.iter().map(|&(s, e)| (Rva(s), Rva(e))).collect(),
            name: Some(format!("FUN_{entry:x}")),
            name_source: "DEFAULT".into(),
            thunk: false,
            signature_source: "ANALYSIS".into(),
            calling_convention: Some("__fastcall".into()),
            return_type: Some("undefined8".into()),
            params: vec!["longlong".into()],
            pseudocode: None,
        }
    }

    #[test]
    fn main_range_starts_at_the_entry_and_other_parts_are_fragments() {
        let img = image(&code(), &[]);
        let r = range(&img, &func(0x1010, &[(0x1000, 0x1003), (0x1010, 0x1016)])).unwrap();
        assert_eq!((r.start, r.end), (0x1010, 0x1016));
        assert_eq!(r.fragments, vec![(0x1000, 0x1003)]);
        // An entry in the middle of its part: the part before it is a fragment.
        let r = range(&img, &func(0x1012, &[(0x1010, 0x1016)])).unwrap();
        assert_eq!(
            (r.start, r.end, r.fragments.clone()),
            (0x1012, 0x1016, vec![(0x1010, 0x1012)])
        );
    }

    #[test]
    fn touching_parts_are_cut_at_pdata_boundaries() {
        // Ghidra reports 0x1000..0x1016 as one range; .pdata says 0x1000..0x1010 is the function and
        // 0x1010..0x1016 a chained fragment of it. The native segments are the ones to hash.
        let mut img = image(&code(), &[]);
        img.pdata = vec![
            crate::native::image::RuntimeFunction {
                begin: 0x1000,
                end: 0x1010,
                chained: false,
                parent: None,
            },
            crate::native::image::RuntimeFunction {
                begin: 0x1010,
                end: 0x1016,
                chained: true,
                parent: Some(0x1000),
            },
        ];
        let r = range(&img, &func(0x1000, &[(0x1000, 0x1016)])).unwrap();
        assert_eq!((r.start, r.end), (0x1000, 0x1010));
        assert_eq!(r.fragments, vec![(0x1010, 0x1016)]);
    }

    #[test]
    fn a_body_outside_executable_code_is_rejected() {
        // Negative cases: a range in the data section, an empty range, and an entry outside its body.
        let img = image(&code(), &[0u8; 0x20]);
        assert!(range(&img, &func(0x1000, &[(0x1000, 0x1003), (0x2000, 0x2010)])).is_none());
        assert!(range(&img, &func(0x1000, &[(0x1000, 0x1000)])).is_none());
        assert!(range(&img, &func(0x1010, &[(0x1000, 0x1003)])).is_none());
    }

    #[test]
    fn only_signatures_ghidra_did_not_infer_are_trusted() {
        let with = |sig: &str, name: &str| {
            let mut f = func(0x1000, &[(0x1000, 0x1003)]);
            f.signature_source = sig.into();
            f.name_source = name.into();
            trusted(&f)
        };
        // An import thunk's library prototype (its name is the import's).
        assert!(with("IMPORTED", "DEFAULT"));
        assert!(with("USER_DEFINED", "USER_DEFINED"));
        // Negative cases: inferred prototypes, and a library prototype on a name Function ID guessed.
        assert!(!with("ANALYSIS", "DEFAULT"));
        assert!(!with("DEFAULT", "DEFAULT"));
        assert!(!with("IMPORTED", "ANALYSIS"));
    }
}
