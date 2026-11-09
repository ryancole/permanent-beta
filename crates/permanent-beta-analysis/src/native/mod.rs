//! Native PE x64 analyzer (design §4.2).
//!
//! Reads only what's in the binary: no PDB or map file. (The PDB GUID from the debug directory is recorded so
//! the matching PDB can be found later, but no symbols are read.) Names come from exports only.
//!
//! Known gaps: no PDB names or signatures (see `crate::symbols`), no version resource, dead code without
//! `.pdata` isn't found, and `edges` isn't computed. Address-taken functions (`lea` of code), code pointers in
//! data (base relocations) and chained `.pdata` fragments are handled (see `function`).

pub(crate) mod function;
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
    let code_tables = function::code_tables(image, &ranges);

    let functions = ranges
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
        functions,
        code_tables,
        types: Vec::new(),
        globals: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_pe_input() {
        assert!(matches!(
            analyze_bytes(b"not a pe file", "x"),
            Err(BytesError::Invalid(_))
        ));
    }
}
