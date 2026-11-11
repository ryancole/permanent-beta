//! The normalized analysis schema (design §4.1). Every analyzer, native or Ghidra, produces this.

use crate::ids::{BuildId, Rva};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Bump on any breaking change to [`AnalysisExport`]'s shape. A change in what a hash or another code feature
/// covers bumps the analyzer's features version instead ([`AnalysisExport::features_version`]).
///
/// 2: the normalized hash covers the name of an import read through the IAT.
pub const ANALYSIS_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisExport {
    pub schema_version: u32,
    pub build: BuildInfo,
    pub producer: Producer,
    /// Which normalizer computed the code features (hashes, mnemonic counts, blocks and edges, inferred
    /// arguments): the analyzer's name and a version it bumps whenever what a feature covers changes, e.g.
    /// `native-1`. Two builds are matched only if their analyses agree on it (design §4.1): a hash from another
    /// normalizer, or another version of it, means nothing next to this one. `None` for an analysis without code
    /// features (PDB-only), and for analyses written before it existed. Optional, so adding it didn't change
    /// the schema version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub features_version: Option<String>,
    pub functions: Vec<FunctionFeatures>,
    /// Tables of code pointers stored in data: vtables and function tables. Optional, so adding it didn't
    /// change the schema version; an export without it just gives table-based matching nothing to use.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub code_tables: Vec<CodeTable>,
    /// Layouts of the structs, classes and unions that function signatures use (from a PDB: `pbeta analyze
    /// --pdb`), for adapting hooks when a layout changes (design §7.2). Optional, so adding it didn't change the
    /// schema version.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub types: Vec<TypeLayout>,
    /// Global variables in writable sections, from a PDB (`pbeta analyze --pdb`), for recording and replaying
    /// the global state a hooked function reads (design §7.3). Optional, so adding it didn't change the schema
    /// version.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub globals: Vec<GlobalVar>,
    /// Every data symbol with a name unique in the PDB, read-only data included (`static const` tables), from
    /// `pbeta analyze --pdb`: replay maps an address into the old image to the same symbol in the new one (design
    /// §7.3). Optional, like `globals`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub data_symbols: Vec<GlobalVar>,
    /// Pointer fields that code treats as pointing to another struct than declared, from `pbeta analyze --pdb`
    /// (design §7.3): zlib's `z_stream_s.state` is declared `internal_state*`, and inflate keeps it in a local
    /// `inflate_state* state`. For the record spec, which lists the field with both targets; the recorder picks by
    /// heap block size. Optional.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pointer_aliases: Vec<PointerAlias>,
}

/// A pointer field (`layout.field`) that may point to a `target` struct other than its declared type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PointerAlias {
    pub layout: String,
    pub field: String,
    pub target: String,
    /// Functions with a local of the same name pointing to `target`: the evidence (at most 64). The record spec
    /// uses the alias only if a hook reaches one of them.
    pub seen_in: Vec<String>,
}

/// Two analyses whose code features came from different normalizers (or versions of one): matching them would
/// compare hashes that mean different things.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncomparableFeatures {
    pub old_build: BuildId,
    pub new_build: BuildId,
    pub old: String,
    pub new: String,
}

impl std::fmt::Display for IncomparableFeatures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the analyses of {} and {} have different features versions ({} and {}): analyze both builds with              the same pbeta",
            self.old_build, self.new_build, self.old, self.new
        )
    }
}

impl std::error::Error for IncomparableFeatures {}

impl AnalysisExport {
    /// Whether this analysis's code features can be compared with `new`'s: the same features version, where an
    /// unknown one (`None`) only equals another unknown one.
    pub fn features_comparable(&self, new: &AnalysisExport) -> Result<(), IncomparableFeatures> {
        if self.features_version == new.features_version {
            return Ok(());
        }
        let shown = |v: &Option<String>| v.clone().unwrap_or_else(|| "none".to_owned());
        Err(IncomparableFeatures {
            old_build: self.build.id.clone(),
            new_build: new.build.id.clone(),
            old: shown(&self.features_version),
            new: shown(&new.features_version),
        })
    }

    pub fn type_layout(&self, name: &str) -> Option<&TypeLayout> {
        self.types.iter().find(|t| t.name == name)
    }

    pub fn global(&self, name: &str) -> Option<&GlobalVar> {
        self.globals.iter().find(|g| g.name == name)
    }

    /// The global whose bytes contain `rva`.
    pub fn global_at(&self, rva: Rva) -> Option<&GlobalVar> {
        self.globals
            .iter()
            .find(|g| (g.rva.0..g.rva.0 + g.size.max(1)).contains(&rva.0))
    }
}

/// A global variable from a PDB data symbol. Names are unique within one build: a static local is qualified by
/// its procedure (`__local_stdio_printf_options::_OptionsStorage`), and a name that's still ambiguous (two
/// files' `static int count`) is left out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GlobalVar {
    pub name: String,
    pub rva: Rva,
    pub size: u64,
    /// The type's name as the PDB spells it.
    #[serde(rename = "type")]
    pub ty: String,
}

/// A struct, class or union as laid out in one build.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeLayout {
    /// As the PDB names it, e.g. `Config` or `tinyxml2::XMLNode`.
    pub name: String,
    pub size: u64,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub union: bool,
    /// Data members and base classes, in declaration order.
    pub fields: Vec<FieldLayout>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldLayout {
    /// The member's name; a base class is `<base Name>`, the vtable pointer `<vfptr>`.
    pub name: String,
    pub offset: u64,
    pub size: u64,
    /// A C-like type name, e.g. `int`, `int[8]`, `struct Order*`.
    pub ty: String,
    /// Bit position and width, for a bitfield.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bits: Option<(u8, u8)>,
}

/// A run of at least two consecutive 64-bit pointers in a non-executable section, each a relocated pointer to a
/// function start: a vtable (MSVC puts the RTTI locator pointer, which points into data, right before each
/// vtable, so neighbouring vtables stay apart) or a C function table. Found from base relocations, no symbols.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeTable {
    /// Address of the first slot.
    pub rva: Rva,
    /// The function each slot points to, in slot order. The same function can fill several slots.
    pub slots: Vec<Rva>,
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
    /// Addresses in writable sections the function's code refers to RIP-relatively (globals it reads or
    /// writes), sorted. Not matched on and not hashed (the hash masks them); for recording global state
    /// (design §7.3). Optional, so adding it didn't change the schema version.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub data_refs: Vec<Rva>,
    /// Code addresses outside the function that it takes with a RIP-relative `lea` (a function pointer it passes,
    /// stores or calls), sorted. Not matched on and not hashed; for the call graph the wrong-target control walks
    /// (design §7.3). Optional, so adding it didn't change the schema version.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub code_refs: Vec<Rva>,
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
    /// Memory the function reads or writes through its pointer arguments, in address order: where a struct's
    /// fields are, as the code sees them (design §7.2, struct changes without a PDB). Empty if the analyzer
    /// didn't compute it. Optional, so adding it didn't change the schema version.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arg_accesses: Vec<ArgAccess>,
    /// How often each instruction mnemonic occurs (e.g. `"Mov" → 12`). Order-free, so it survives small
    /// edits and reordering; used by similarity matching. Empty if the analyzer didn't compute it.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub mnemonic_counts: BTreeMap<String, u32>,
    /// What a Detours-style entry patch would overwrite. `None` if the analyzer didn't compute it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<EntryInfo>,
    /// Decompiler output (Ghidra), for people reviewing a candidate and for AI prompts. Never matched on: it
    /// names other functions by address, which changes between builds. Optional, so adding it didn't change
    /// the schema version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pseudocode: Option<String>,
}

/// One access through a pointer argument: `[rcx+0x8]`, 4 bytes, read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArgAccess {
    /// The argument slot (0–3: rcx, rdx, r8, r9) whose pointer the address is based on.
    pub slot: u8,
    pub offset: u32,
    /// Bytes accessed.
    pub size: u8,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub write: bool,
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
