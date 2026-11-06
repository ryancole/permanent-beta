//! The normalized analysis schema (design §4.1). Every analyzer, native or Ghidra, produces this.

use crate::ids::{BuildId, Rva};
use serde::{Deserialize, Serialize};

/// Bump on any breaking change to [`AnalysisExport`].
pub const ANALYSIS_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisExport {
    pub schema_version: u32,
    pub build: BuildInfo,
    pub producer: Producer,
    pub functions: Vec<FunctionFeatures>,
}

impl AnalysisExport {
    pub fn function(&self, rva: Rva) -> Option<&FunctionFeatures> {
        self.functions.iter().find(|f| f.rva == rva)
    }

    pub fn function_by_name(&self, name: &str) -> Option<&FunctionFeatures> {
        self.functions
            .iter()
            .find(|f| f.name.as_deref() == Some(name))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildInfo {
    pub id: BuildId,
    pub file_name: String,
    pub version: Option<String>,
    pub machine: Machine,
    pub pdb: Option<PdbInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Machine {
    X64,
    X86,
    Arm64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdbInfo {
    pub guid: String,
    pub age: u32,
}

/// The tool that produced an export, e.g. `permanent-beta-native-pe` or `ghidra-export`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Producer {
    pub tool: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionFeatures {
    pub rva: Rva,
    pub size: u32,
    pub name: Option<String>,
    pub name_source: Option<NameSource>,
    /// Hash of instruction bytes with relocations, RIP-relative displacements and absolute addresses masked.
    pub normalized_hash: Option<String>,
    /// Hash of the mnemonic sequence only.
    pub mnemonic_hash: Option<String>,
    pub basic_blocks: Option<u32>,
    pub edges: Option<u32>,
    /// Direct callees (including tail-jump targets), in order of first call site.
    #[serde(default)]
    pub callees: Vec<Rva>,
    #[serde(default)]
    pub strings: Vec<String>,
    #[serde(default)]
    pub constants: Vec<u64>,
    #[serde(default)]
    pub imports: Vec<String>,
    pub signature: Option<FunctionSignature>,
}

/// Where a function name came from. Trust differs by source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NameSource {
    Export,
    Pdb,
    Rtti,
    Analyst,
    Inferred,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionSignature {
    pub calling_convention: Option<String>,
    pub return_type: Option<String>,
    #[serde(default)]
    pub params: Vec<Param>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Param {
    pub name: Option<String>,
    pub ty: String,
}
