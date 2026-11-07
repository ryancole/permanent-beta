//! Analysis layer (design §4): produce or load an [`AnalysisExport`].
//!
//! - [`native`]: in-process PE x64 analyzer (`object` for parsing, `.pdata` + call targets for function
//!   discovery, `iced-x86` for features). Uses no symbols beyond exports.
//! - [`symbols`]: names and signatures from an MSVC PDB, added to an analysis only when asked for.
//! - [`diff`]: compare two analyses of the same build (native vs Ghidra, or vs a PDB's procedures).
//! - [`ghidra`]: native features for the function boundaries in a Ghidra headless export.
//! - [`export`]: load and save `AnalysisExport` JSON, e.g. as written by the Ghidra headless exporter.

use permanent_beta_model::AnalysisExport;
use std::path::Path;

pub mod diff;
pub mod export;
pub mod ghidra;
pub mod native;
pub mod symbols;

#[derive(Debug, thiserror::Error)]
pub enum AnalysisError {
    #[error("I/O error on {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid analysis export {path}: {source}")]
    Json {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("{path}: unsupported analysis schema version {found} (expected {expected})")]
    SchemaVersion {
        path: String,
        found: u32,
        expected: u32,
    },
    #[error("{0} is not implemented yet")]
    NotImplemented(&'static str),
    #[error("{path}: not a valid PE image: {reason}")]
    InvalidPe { path: String, reason: String },
    #[error("{path}: not a readable PDB: {reason}")]
    InvalidPdb { path: String, reason: String },
    #[error("{path}: unsupported binary: {reason}")]
    Unsupported { path: String, reason: String },
}

/// Anything that can turn a binary on disk into an [`AnalysisExport`].
pub trait Analyzer {
    fn name(&self) -> &'static str;
    fn analyze(&self, binary: &Path) -> Result<AnalysisExport, AnalysisError>;
}
