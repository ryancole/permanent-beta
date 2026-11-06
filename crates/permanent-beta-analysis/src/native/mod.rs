//! Native PE x64 analyzer (design §4.2).
//!
//! Reads only what's in the binary: no PDB or map file. (The PDB GUID from the debug directory is recorded so
//! the matching PDB can be found later, but no symbols are read.) Names come from exports only.
//!
//! Known gaps, all deliberate for M1: no PDB names or signatures, no version resource, chained `.pdata`
//! fragments (split cold code) aren't merged into their parent, functions reached only indirectly (vtables,
//! callbacks) and without `.pdata` aren't found, and `edges` isn't computed.

mod function;
mod image;

use crate::{AnalysisError, Analyzer};
use permanent_beta_model::{
    ANALYSIS_SCHEMA_VERSION, AnalysisExport, BuildId, BuildInfo, Machine, NameSource, PdbInfo,
    Producer,
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
        })
    }
}

#[derive(Debug)]
pub enum BytesError {
    Invalid(String),
}

/// Analyze an in-memory PE x64 image.
pub fn analyze_bytes(bytes: &[u8], file_name: &str) -> Result<AnalysisExport, BytesError> {
    let image = image::Image::parse(bytes).map_err(BytesError::Invalid)?;
    let build_id: String = Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    let functions = function::discover(&image)
        .into_iter()
        .map(|range| {
            let mut f = function::features(&image, range);
            if let Some((_, name)) = image.exports.iter().find(|e| e.0 == range.start) {
                f.name = Some(name.clone());
                f.name_source = Some(NameSource::Export);
            }
            f
        })
        .collect();

    Ok(AnalysisExport {
        schema_version: ANALYSIS_SCHEMA_VERSION,
        build: BuildInfo {
            id: BuildId(build_id),
            file_name: file_name.to_owned(),
            version: None,
            machine: Machine::X64,
            pdb: image.pdb.map(|(guid, age)| PdbInfo { guid, age }),
        },
        producer: Producer {
            tool: PRODUCER.to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        },
        functions,
    })
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
