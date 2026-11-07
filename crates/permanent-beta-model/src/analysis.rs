//! The normalized analysis schema (design §4.1). Every analyzer, native or Ghidra, produces this.

use crate::ids::{BuildId, Rva};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Bump on any breaking change to [`AnalysisExport`], including a change in what a hash covers: hashes from
/// different versions aren't comparable.
///
/// 2: the normalized hash covers the name of an import read through the IAT.
pub const ANALYSIS_SCHEMA_VERSION: u32 = 2;

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
    /// Register arguments the code reads before writing (Win64: rcx/xmm0, rdx/xmm1, r8/xmm2, r9/xmm3), up to
    /// the first call, as 1 + the highest slot used. A lower bound on the parameter count: unused trailing
    /// parameters and stack arguments are invisible. Capped at 4. Inferred from code; no symbols needed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inferred_args: Option<u8>,
    /// Register class of each inferred argument slot, `inferred_args` long: which of the slot's two registers
    /// (integer or vector) the code read. Empty if the analyzer didn't compute it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inferred_arg_classes: Vec<ArgClass>,
    /// How often each instruction mnemonic occurs (e.g. `"Mov" → 12`). Order-free, so it survives small
    /// edits and reordering; used by similarity matching. Empty if the analyzer didn't compute it.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub mnemonic_counts: BTreeMap<String, u32>,
    /// What a Detours-style entry patch would overwrite. `None` if the analyzer didn't compute it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<EntryInfo>,
}

/// Which register of a Win64 argument slot carries a value: rcx/rdx/r8/r9 or xmm0–3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArgClass {
    /// Integer or pointer (rcx, rdx, r8, r9).
    Integer,
    /// Floating point or vector (xmm0–3).
    Vector,
    /// The code didn't read this slot (a lower slot is unused while a higher one is read).
    Unused,
}

/// Facts about a function's entry that decide whether a 5-byte `jmp` patch (Detours) can be applied safely.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryInfo {
    /// Bytes the patch overwrites, rounded up to whole instructions. Below 5 means the function is too short.
    pub patch_len: u8,
    /// Some branch in the function targets the patched bytes. After patching it would land inside the `jmp`
    /// (or, for a branch back to the entry, re-enter the detour).
    pub branch_into_patch: bool,
    /// The function is only a jump elsewhere (a thunk). The hook probably belongs on the jump target.
    pub jump_thunk: bool,
}

impl EntryInfo {
    pub const PATCH_SIZE: u8 = 5;

    /// Problems that make the entry unsafe to patch, in plain words. Empty means hookable.
    pub fn hazards(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.patch_len < Self::PATCH_SIZE {
            out.push(format!(
                "function is only {} bytes, shorter than the {}-byte patch",
                self.patch_len,
                Self::PATCH_SIZE
            ));
        }
        if self.branch_into_patch {
            out.push("a branch inside the function targets the bytes the patch overwrites".into());
        }
        if self.jump_thunk {
            out.push("the function is only a jump (thunk); hook its target instead".into());
        }
        out
    }
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
