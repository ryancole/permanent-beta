//! Native PE x64 analyzer (design §4.2). Not implemented yet; this is the M1 spike.
//!
//! Plan:
//! 1. Parse the PE with `object` or `pelite`; hash the file for the `BuildId`.
//! 2. Function starts from `.pdata` RUNTIME_FUNCTION entries, plus exports, PDB symbols, and call targets.
//! 3. Decode with `iced-x86`; compute normalized + mnemonic hashes, callees, string/constant refs, imports.
//! 4. Read the PDB (`pdb` crate) when present for names and signatures.

use crate::{AnalysisError, Analyzer};
use rehook_model::AnalysisExport;
use std::path::Path;

pub struct NativePeAnalyzer;

impl Analyzer for NativePeAnalyzer {
    fn name(&self) -> &'static str {
        "rehook-native-pe"
    }

    fn analyze(&self, _binary: &Path) -> Result<AnalysisExport, AnalysisError> {
        Err(AnalysisError::NotImplemented(
            "the native PE x64 analyzer (use a Ghidra or hand-written AnalysisExport JSON for now)",
        ))
    }
}
