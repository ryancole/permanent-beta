//! Recorded per-call test cases (design §7.3): the record spec a recording hook DLL follows, and the test cases
//! it writes.
//!
//! A recording directory holds:
//! - `spec.toml`: the [`HarnessSpec`] the recorder ran with (`pbeta harness-spec`), copied in by the recorder;
//! - `cases/<hook>/<test_id>.json`: one [`TestCase`] per recorded call;
//! - `blobs/<sha256>`: the memory behind pointer arguments, the globals the hook reads and what imports touched,
//!   content-addressed ([`BlobRef`]).
//!
//! Recordings can contain customer data and stay local (design §7.3, privacy). What mustn't be recorded at all is
//! marked in the spec: `redact` on an argument or a global, `import_memory = false` for what import calls see.

use crate::analysis::TypeLayout;
use crate::ids::{BuildId, Rva};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

/// The recorder's ABI: Win64 (`rcx`, `rdx`, `r8`, `r9` / `xmm0`–`xmm3`, then the stack).
pub const ABI_WIN64: &str = "win64";
/// The recorder's ABI for x86 (32-bit) code: MSVC's conventions ([`Convention`]). Arguments are on the stack from
/// `esp+4` up, except `this` in ecx (`__thiscall`) and the first two small ones in ecx and edx (`__fastcall`).
/// Results are in eax (edx:eax for 8 bytes) and, for floating point, in st(0).
pub const ABI_WIN32: &str = "win32";

/// Which ABI a record spec's slots and a recording's registers follow.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Abi {
    #[default]
    Win64,
    Win32,
}

impl Abi {
    /// The name a [`TestCase`] records ([`ABI_WIN64`], [`ABI_WIN32`]).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Win64 => ABI_WIN64,
            Self::Win32 => ABI_WIN32,
        }
    }

    /// Bytes in a pointer.
    pub fn pointer_size(self) -> u64 {
        match self {
            Self::Win64 => 8,
            Self::Win32 => 4,
        }
    }

    pub fn is_win64(&self) -> bool {
        *self == Self::Win64
    }
}

/// An x86 calling convention (MSVC). Win64 has one convention, so it needs none.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Convention {
    /// Arguments on the stack; the caller removes them. MSVC's default for free functions.
    Cdecl,
    /// Arguments on the stack; the callee removes them (`ret n`). Most Win32 API functions.
    Stdcall,
    /// `this` in ecx, the rest on the stack; the callee removes them. MSVC's default for member functions.
    Thiscall,
    /// The first two arguments of 4 bytes or less in ecx and edx, the rest on the stack; the callee removes them.
    Fastcall,
}

impl Convention {
    /// The convention a keyword names (`__stdcall`, `__thiscall`, ...), if it names one.
    pub fn from_keyword(word: &str) -> Option<Self> {
        Some(match word.trim_start_matches('_') {
            "cdecl" => Self::Cdecl,
            "stdcall" => Self::Stdcall,
            "thiscall" => Self::Thiscall,
            "fastcall" => Self::Fastcall,
            _ => return None,
        })
    }

    /// The callee removes the stack arguments when it returns (`ret n`).
    pub fn callee_pops(self) -> bool {
        self != Self::Cdecl
    }
}

impl fmt::Display for Convention {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Cdecl => "__cdecl",
            Self::Stdcall => "__stdcall",
            Self::Thiscall => "__thiscall",
            Self::Fastcall => "__fastcall",
        })
    }
}

/// What the recording hook DLL captures for each hook of one build (`pbeta harness-spec`): the argument slots,
/// how each value travels, and what each pointer argument points to. Hand-editable: `capture` can be changed or
/// set to `none` for any argument.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarnessSpec {
    /// The build the RVAs are valid for. The recorder skips the spec in any other build.
    pub build: BuildId,
    /// The ABI the slots follow: the build's (`win32` for an x86 build). A spec without the key is Win64.
    #[serde(default, skip_serializing_if = "Abi::is_win64")]
    pub abi: Abi,
    /// At most this many distinct cases per hook. Identical calls (same registers, stack and memory) are
    /// recorded once.
    pub max_cases: u32,
    /// Capture the memory behind import calls' arguments. `false` records import calls without it (their
    /// arguments and results only): nothing derived from the hooks' data reaches the recording through an import
    /// (a formatted string passed to `printf`), and replay can't stand in for imports that read memory.
    #[serde(default = "default_true")]
    pub import_memory: bool,
    /// How many pointers deep the recorder follows from the arguments' memory: each pointer-sized word in captured memory
    /// that points to readable memory outside the image leads to a [`CaptureKind::Pointee`] region (a whole heap
    /// block, or a fixed block from the pointer), and so on, this many times. 0 captures the arguments' memory
    /// only (and is what a spec without the key means). Redacted memory is never captured.
    #[serde(default)]
    pub pointer_depth: u32,
    /// The pointer fields of the layouts below, which the recorder follows (`pointer_depth`): only these, so a
    /// buffer's stale bytes are never taken for pointers.
    #[serde(rename = "pointer", default, skip_serializing_if = "Vec::is_empty")]
    pub pointers: Vec<PointerField>,
    #[serde(rename = "hook", default)]
    pub hooks: Vec<HookRecordSpec>,
    /// Hooks that can't be recorded, with the reason (no prototype, one that can't be parsed, no RVA).
    #[serde(rename = "skipped", default, skip_serializing_if = "Vec::is_empty")]
    pub skipped: Vec<SkippedHook>,
    /// The old build's layouts of the structs captured by value ([`CaptureKind::Fixed`] with a `layout`), so a
    /// replay can translate them by field name when the new build's layout differs.
    #[serde(rename = "layout", default, skip_serializing_if = "Vec::is_empty")]
    pub layouts: Vec<TypeLayout>,
}

impl HarnessSpec {
    pub fn hook(&self, name: &str) -> Option<&HookRecordSpec> {
        self.hooks.iter().find(|h| h.name == name)
    }

    pub fn layout(&self, name: &str) -> Option<&TypeLayout> {
        self.layouts.iter().find(|l| l.name == name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedHook {
    pub name: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookRecordSpec {
    pub name: String,
    pub rva: Rva,
    pub prototype: String,
    /// The return value's register class and width. `unknown` (e.g. a struct by value) makes its cases
    /// inconclusive on replay: there's nothing sound to compare.
    pub ret: ValueType,
    /// The stack words to record. Win64: parameters past the fourth, 8-byte slots above the shadow space. Win32:
    /// every stack argument, 4-byte words from `esp+4` up (an 8-byte argument takes two).
    pub stack_args: u32,
    /// Win32: the calling convention, which says where the arguments are and whether the callee removes the
    /// `stack_args` words when it returns. None on Win64.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub convention: Option<Convention>,
    #[serde(rename = "arg", default)]
    pub args: Vec<ArgSpec>,
    /// Globals the function or anything it calls refers to (the analysis's `data_refs`, named by the PDB):
    /// captured before and after each call, so a replay can place them in the new build by name.
    #[serde(rename = "global", default, skip_serializing_if = "Vec::is_empty")]
    pub globals: Vec<GlobalSpec>,
}

/// A global variable to capture with each call: its bytes at `rva` in the recorded build.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GlobalSpec {
    /// The PDB name, which is how the new build's copy is found.
    pub name: String,
    pub rva: Rva,
    pub size: u64,
    /// Never record it. A replay that reads it is inconclusive.
    #[serde(default)]
    pub redact: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArgSpec {
    /// 0-based parameter position.
    pub index: u32,
    pub slot: ArgSlot,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "type")]
    pub ty: String,
    pub value: ValueType,
    /// What the pointer points to, if it's captured.
    pub capture: CaptureKind,
    /// `fixed`: bytes captured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// `fixed`: the struct's name in the build's PDB types ([`HarnessSpec::layouts`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layout: Option<String>,
    /// `sized`: the argument whose value is the byte count.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub len_slot: Option<ArgSlot>,
    /// `cstring` and `sized`: never capture more than this many bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<u64>,
    /// Never record what it points to: not as the argument's memory, and not in any import call's memory that
    /// overlaps it. A replay that reads it is inconclusive.
    #[serde(default)]
    pub redact: bool,
}

fn default_true() -> bool {
    true
}

/// What a pointer argument's memory is, for capturing it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureKind {
    /// Not a pointer, or nothing known about what it points to. A replay that reads it is inconclusive.
    None,
    /// `size` bytes: a struct (with its `layout`) or a scalar.
    Fixed,
    /// A NUL-terminated byte string, up to `max` bytes.
    Cstring,
    /// As many bytes as the argument in `len_slot` says, up to `max` (a buffer and its length).
    Sized,
    /// A scalar of `size` bytes (or a pointer, for `T**`) that may be one element of an array, or a field of a
    /// struct the prototype doesn't name: the whole heap block holding it, from the block's start (zlib's
    /// `inflate_table` gets pointers into the middle of inflate's state), up to the recorder's cap; otherwise
    /// (the stack, a block too large) `size` bytes at the pointer, as `fixed`.
    Array,
    /// Memory reached through a pointer inside captured memory (`HarnessSpec::pointer_depth`): untyped bytes, never
    /// overlapping an argument's region. Its `arg` is the argument it was reached from.
    Pointee,
}

/// A pointer field of a struct the recorder captures, and what it points to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PointerField {
    /// The struct (a layout of the spec) and the field's offset in it.
    pub layout: String,
    pub offset: u64,
    /// The struct it points to (a layout of the spec, captured with that layout and followed further), or none:
    /// bytes, captured but not followed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
}

/// How a value travels (integer register, vector register) and its width in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueType {
    Int(u8),
    Float(u8),
    Pointer,
    Void,
    /// Not a scalar this ABI passes in one register (a struct by value), or a type the parser doesn't know.
    Unknown,
}

impl ValueType {
    /// Win64: floating-point values travel in xmm registers, everything else that fits in rax/rcx/….
    pub fn in_vector_register(self) -> bool {
        matches!(self, Self::Float(_))
    }

    /// Bytes of the register that carry the value (`int` → the low 4 of rax).
    pub fn width(self) -> Option<u8> {
        match self {
            Self::Int(n) | Self::Float(n) => Some(n),
            Self::Pointer => Some(8),
            Self::Void | Self::Unknown => None,
        }
    }
}

impl fmt::Display for ValueType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Int(n) => write!(f, "int:{n}"),
            Self::Float(n) => write!(f, "float:{n}"),
            Self::Pointer => f.write_str("pointer:8"),
            Self::Void => f.write_str("void"),
            Self::Unknown => f.write_str("unknown"),
        }
    }
}

impl FromStr for ValueType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let width = |n: &str| -> Result<u8, String> {
            match n.parse::<u8>() {
                Ok(w @ (1 | 2 | 4 | 8)) => Ok(w),
                _ => Err(format!("bad value width in {s:?}")),
            }
        };
        match s.split_once(':') {
            Some(("int", n)) => Ok(Self::Int(width(n)?)),
            Some(("float", n)) => match width(n)? {
                w @ (4 | 8) => Ok(Self::Float(w)),
                _ => Err(format!("bad float width in {s:?}")),
            },
            Some(("pointer", "8")) => Ok(Self::Pointer),
            None if s == "void" => Ok(Self::Void),
            None if s == "unknown" => Ok(Self::Unknown),
            _ => Err(format!("unknown value type {s:?}")),
        }
    }
}

/// Where an argument is at the function's entry. Win64: `rcx`/`rdx`/`r8`/`r9`, `xmm0`–`xmm3`, or the stack slot at
/// `rsp + offset` (the fifth parameter is at `stack+0x28`, above the return address and the shadow space). Win32:
/// `ecx`/`edx`, or the stack at `esp + offset` (the first stack argument is at `esp+0x4`, above the return address).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ArgSlot {
    /// 0–3: rcx, rdx, r8, r9.
    Int(u8),
    /// 0–3: xmm0–xmm3.
    Vector(u8),
    /// Byte offset from rsp at entry.
    Stack(u32),
    /// Win32, 0–1: ecx, edx.
    Reg32(u8),
    /// Win32: byte offset from esp at entry.
    Stack32(u32),
}

pub const INT_ARG_REGS: [&str; 4] = ["rcx", "rdx", "r8", "r9"];
pub const REG32_ARG_REGS: [&str; 2] = ["ecx", "edx"];

/// Bytes a value takes on the x86 stack: 4, or 8 for a 64-bit integer or a double. `None` for a struct by value or
/// an unknown type, whose size the value type doesn't say.
pub fn stack32_size(value: ValueType) -> Option<u32> {
    match value {
        ValueType::Int(8) | ValueType::Float(8) => Some(8),
        ValueType::Int(_) | ValueType::Float(_) | ValueType::Pointer => Some(4),
        ValueType::Void | ValueType::Unknown => None,
    }
}

/// x86 argument slots for parameters of these value types under `convention`, and the bytes of stack arguments.
/// Once a parameter's stack size isn't known (a struct by value), it and every later stack parameter get `None`,
/// and so does the byte count: where they are isn't known.
pub fn slots32(
    convention: Convention,
    values: &[ValueType],
) -> (Vec<Option<ArgSlot>>, Option<u32>) {
    let mut next_reg = 0u8;
    let mut offset = Some(4u32);
    let mut out = Vec::with_capacity(values.len());
    for (i, &v) in values.iter().enumerate() {
        // `this` is in ecx; fastcall takes the first two arguments of 4 bytes or less, in order.
        let in_register = match convention {
            Convention::Thiscall => i == 0,
            Convention::Fastcall => {
                next_reg < 2 && matches!(v, ValueType::Int(1 | 2 | 4) | ValueType::Pointer)
            }
            Convention::Cdecl | Convention::Stdcall => false,
        };
        if in_register {
            out.push(Some(ArgSlot::Reg32(next_reg)));
            next_reg += 1;
            continue;
        }
        let size = stack32_size(v);
        out.push(offset.filter(|_| size.is_some()).map(ArgSlot::Stack32));
        offset = offset.zip(size).map(|(o, s)| o + s);
    }
    (out, offset.map(|o| o - 4))
}

impl ArgSlot {
    /// The slot of the parameter at `index` (0-based), passed in a vector register when `vector`.
    pub fn for_param(index: u32, vector: bool) -> Self {
        match (index, vector) {
            (0..=3, false) => Self::Int(index as u8),
            (0..=3, true) => Self::Vector(index as u8),
            _ => Self::Stack(8 * (index + 1)),
        }
    }
}

impl fmt::Display for ArgSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Int(i) => f.write_str(INT_ARG_REGS[usize::from(*i).min(3)]),
            Self::Vector(i) => write!(f, "xmm{i}"),
            Self::Stack(off) => write!(f, "stack+{off:#x}"),
            Self::Reg32(i) => f.write_str(REG32_ARG_REGS[usize::from(*i).min(1)]),
            Self::Stack32(off) => write!(f, "esp+{off:#x}"),
        }
    }
}

impl FromStr for ArgSlot {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(i) = INT_ARG_REGS.iter().position(|r| *r == s) {
            return Ok(Self::Int(i as u8));
        }
        if let Some(i) = s.strip_prefix("xmm").and_then(|n| n.parse::<u8>().ok())
            && i < 4
        {
            return Ok(Self::Vector(i));
        }
        if let Some(off) = s.strip_prefix("stack+0x")
            && let Ok(off) = u32::from_str_radix(off, 16)
            && off >= 0x28
            && off % 8 == 0
        {
            return Ok(Self::Stack(off));
        }
        if let Some(i) = REG32_ARG_REGS.iter().position(|r| *r == s) {
            return Ok(Self::Reg32(i as u8));
        }
        if let Some(off) = s.strip_prefix("esp+0x")
            && let Ok(off) = u32::from_str_radix(off, 16)
            && off >= 4
            && off % 4 == 0
        {
            return Ok(Self::Stack32(off));
        }
        Err(format!("unknown argument slot {s:?}"))
    }
}

macro_rules! string_serde {
    ($t:ty) => {
        impl Serialize for $t {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(self)
            }
        }
        impl<'de> Deserialize<'de> for $t {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                String::deserialize(deserializer)?
                    .parse()
                    .map_err(serde::de::Error::custom)
            }
        }
    };
}

string_serde!(ValueType);
string_serde!(ArgSlot);

/// A 64-bit register or memory word, serialized as hex (`"0x1f"`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Word(pub u64);

impl fmt::Display for Word {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl FromStr for Word {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hex = s
            .strip_prefix("0x")
            .ok_or_else(|| format!("expected 0x-prefixed hex, got {s:?}"))?;
        u64::from_str_radix(hex, 16)
            .map(Word)
            .map_err(|e| format!("{s:?}: {e}"))
    }
}

/// A 128-bit xmm register, serialized as 32 hex digits in memory (little-endian) byte order.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Xmm(pub [u8; 16]);

impl fmt::Display for Xmm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

impl FromStr for Xmm {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 32 || !s.is_ascii() {
            return Err(format!("expected 32 hex digits, got {s:?}"));
        }
        let mut out = [0u8; 16];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|e| format!("{s:?}: {e}"))?;
        }
        Ok(Self(out))
    }
}

/// A content-addressed blob in the recording's `blobs/` directory: `sha256:<hex>` of its bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BlobRef(pub String);

impl BlobRef {
    /// The hex digest, which is the blob's file name.
    pub fn digest(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BlobRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sha256:{}", self.0)
    }
}

impl FromStr for BlobRef {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.strip_prefix("sha256:") {
            Some(h) if h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()) => {
                Ok(Self(h.to_ascii_lowercase()))
            }
            _ => Err(format!("expected sha256:<64 hex digits>, got {s:?}")),
        }
    }
}

string_serde!(Word);
string_serde!(Xmm);
string_serde!(BlobRef);

/// One recorded call (design §7.3): the registers and stack at entry, the memory each pointer argument pointed
/// to before and after the call, and the return registers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestCase {
    pub test_id: String,
    pub hook: String,
    /// The build the call was recorded in, and the hooked function's RVA there.
    pub build: BuildId,
    pub rva: Rva,
    pub recorder: String,
    pub abi: String,
    /// Where the recorded process had the image loaded. Pointers into it (string literals, globals) mean nothing
    /// in another build.
    pub image_base: Word,
    /// The image's size in memory (`SizeOfImage`), so replay can tell a pointer into the image from other
    /// values. Older recordings don't have it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_size: Option<Word>,
    pub entry: EntryState,
    /// The memory behind pointer arguments, as the spec said to capture it.
    #[serde(default)]
    pub regions: Vec<Region>,
    /// The spec's globals before and after the call.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub globals: Vec<GlobalRegion>,
    /// True when the recorder intercepted every named import of the module, so `imports` is every import call
    /// the function (and what it called) made, in order. Otherwise a replay can't stand in for imports.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub imports_recorded: bool,
    /// The import calls made during the call, in order (nested hooked calls included).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub imports: Vec<ImportCall>,
    pub observed: Observed,
}

/// A global's bytes before and after the call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GlobalRegion {
    pub name: String,
    /// In the recorded build.
    pub rva: Rva,
    pub size: u64,
    pub before: BlobRef,
    pub after: BlobRef,
}

/// One call into an import (a DLL function) during a recorded call: its arguments, what it returned, and the
/// memory behind its pointer arguments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportCall {
    /// `dll!name`, the DLL lowercased.
    pub import: String,
    /// Argument registers and the first stack arguments (from `rsp+0x28` up) at the call.
    pub entry: EntryState,
    pub observed: Observed,
    /// Memory behind the arguments. Each argument that points to readable memory: up to a fixed number of
    /// bytes from it, before and after the call (`after` set). Inside those, each 8-byte word that points to
    /// readable memory: up to a smaller number of bytes from it, before the call only (strings a `va_list`
    /// points to). Truncated at the first unreadable page.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub memory: Vec<Snapshot>,
}

/// Memory at an address of the recorded process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub address: Word,
    pub before: BlobRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<BlobRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// Argument registers and stack at a call. Win32 uses the same fields: `rcx` and `rdx` hold ecx and edx, `r8`,
/// `r9` and `xmm` are zero, and `stack` holds 4-byte words.
pub struct EntryState {
    pub rcx: Word,
    pub rdx: Word,
    pub r8: Word,
    pub r9: Word,
    pub xmm: [Xmm; 4],
    /// Win64: the stack slots of parameters past the fourth, from `rsp+0x28` up. Win32: the stack arguments, 4-byte
    /// words from `esp+4` up.
    #[serde(default)]
    pub stack: Vec<Word>,
}

impl EntryState {
    pub fn int_reg(&self, i: u8) -> u64 {
        match i {
            0 => self.rcx.0,
            1 => self.rdx.0,
            2 => self.r8.0,
            _ => self.r9.0,
        }
    }

    /// The 64-bit value in an argument slot; for a vector register, its low 8 bytes. `None` for a stack slot
    /// that wasn't recorded.
    pub fn slot_value(&self, slot: ArgSlot) -> Option<u64> {
        match slot {
            ArgSlot::Int(i) => Some(self.int_reg(i)),
            ArgSlot::Vector(i) => {
                let x = self.xmm.get(usize::from(i))?;
                Some(u64::from_le_bytes(x.0[..8].try_into().ok()?))
            }
            ArgSlot::Stack(off) => {
                let i = (off.checked_sub(0x28)? / 8) as usize;
                self.stack.get(i).map(|w| w.0)
            }
            ArgSlot::Reg32(i) => Some(self.int_reg(i) & 0xffff_ffff),
            // An 8-byte value takes two words, the low one first.
            ArgSlot::Stack32(off) => {
                let i = (off.checked_sub(4)? / 4) as usize;
                let lo = self.stack.get(i)?.0 & 0xffff_ffff;
                let hi = self.stack.get(i + 1).map_or(0, |w| w.0 & 0xffff_ffff);
                Some(lo | hi << 32)
            }
        }
    }
}

/// Memory one pointer argument pointed to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Region {
    /// The argument (0-based parameter position) whose value is `address`: for an
    /// [`CaptureKind::Array`] region, inside `address..address + size` (the start of the heap block holding it);
    /// for a [`CaptureKind::Pointee`], the argument it was reached from.
    pub arg: u32,
    pub address: Word,
    pub size: u64,
    pub kind: CaptureKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layout: Option<String>,
    pub before: BlobRef,
    /// The same bytes after the call returned: what differs from `before` was written.
    pub after: BlobRef,
}

/// What the call returned. Win32: `rax` holds edx:eax (eax in the low half), and `xmm0` holds st(0) as the declared
/// return type (a `float` in 4 bytes, a `double` in 8), zero for anything else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observed {
    pub rax: Word,
    pub xmm0: Xmm,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slots_round_trip_and_follow_win64() {
        for s in ["rcx", "r9", "xmm0", "xmm3", "stack+0x28", "stack+0x38"] {
            assert_eq!(s.parse::<ArgSlot>().unwrap().to_string(), s);
        }
        assert_eq!(ArgSlot::for_param(0, false), ArgSlot::Int(0));
        assert_eq!(ArgSlot::for_param(1, true), ArgSlot::Vector(1));
        assert_eq!(ArgSlot::for_param(4, false), ArgSlot::Stack(0x28));
        assert_eq!(ArgSlot::for_param(5, true), ArgSlot::Stack(0x30));
    }

    #[test]
    fn win32_slots_round_trip_and_follow_each_convention() {
        for s in ["ecx", "edx", "esp+0x4", "esp+0xc"] {
            assert_eq!(s.parse::<ArgSlot>().unwrap().to_string(), s);
        }
        use ValueType::{Float, Int, Pointer, Unknown};
        let s = |c, v: &[ValueType]| {
            let (slots, bytes) = slots32(c, v);
            let slots: Vec<String> = slots
                .iter()
                .map(|s| s.map_or("?".into(), |s| s.to_string()))
                .collect();
            (slots.join(" "), bytes)
        };
        let args = [Pointer, Int(4), Float(8), Int(2)];
        assert_eq!(
            s(Convention::Cdecl, &args),
            ("esp+0x4 esp+0x8 esp+0xc esp+0x14".into(), Some(20))
        );
        assert_eq!(
            s(Convention::Thiscall, &args),
            ("ecx esp+0x4 esp+0x8 esp+0x10".into(), Some(16))
        );
        assert_eq!(
            s(Convention::Fastcall, &args),
            ("ecx edx esp+0x4 esp+0xc".into(), Some(12))
        );
        // fastcall: a double goes to the stack, and the next small arguments still get the registers.
        assert_eq!(
            s(Convention::Fastcall, &[Float(8), Int(4), Int(8), Int(1)]),
            ("esp+0x4 ecx esp+0xc edx".into(), Some(16))
        );
        // Negative: after a struct by value, where the rest are isn't known.
        assert_eq!(
            s(Convention::Stdcall, &[Int(4), Unknown, Int(4)]),
            ("esp+0x4 ? ?".into(), None)
        );
        assert!(Convention::Stdcall.callee_pops() && !Convention::Cdecl.callee_pops());
        assert_eq!(
            Convention::from_keyword("__thiscall"),
            Some(Convention::Thiscall)
        );
        assert_eq!(Convention::from_keyword("__vectorcall"), None);
    }

    #[test]
    fn win32_stack_values_take_one_or_two_words() {
        let entry = EntryState {
            rcx: Word(0xdead_beef_0000_0001),
            rdx: Word(2),
            r8: Word(0),
            r9: Word(0),
            xmm: [Xmm::default(); 4],
            stack: vec![Word(0x11), Word(0x22), Word(0x33)],
        };
        assert_eq!(
            entry.slot_value(ArgSlot::Reg32(0)),
            Some(1),
            "ecx is 32 bits"
        );
        assert_eq!(entry.slot_value(ArgSlot::Stack32(4)), Some(0x22_0000_0011));
        assert_eq!(entry.slot_value(ArgSlot::Stack32(0xc)), Some(0x33));
        // Negative: below the first argument (the return address), or past what was recorded.
        assert_eq!(entry.slot_value(ArgSlot::Stack32(0)), None);
        assert_eq!(entry.slot_value(ArgSlot::Stack32(0x10)), None);
    }

    #[test]
    fn bad_slots_and_types_are_refused() {
        // Negative: a fifth register, the shadow space, a misaligned slot, an unknown width.
        for s in [
            "r10",
            "xmm4",
            "stack+0x20",
            "stack+0x29",
            "rax",
            "esp+0x0",
            "esp+0x6",
            "eax",
        ] {
            assert!(s.parse::<ArgSlot>().is_err(), "{s}");
        }
        for s in ["int:3", "float:2", "pointer:4", "struct", ""] {
            assert!(s.parse::<ValueType>().is_err(), "{s}");
        }
        assert!("sha256:abc".parse::<BlobRef>().is_err());
        assert!("12".parse::<Word>().is_err());
    }

    #[test]
    fn value_types_round_trip() {
        for s in [
            "int:1",
            "int:4",
            "int:8",
            "float:4",
            "float:8",
            "pointer:8",
            "void",
            "unknown",
        ] {
            assert_eq!(s.parse::<ValueType>().unwrap().to_string(), s);
        }
        assert_eq!(ValueType::Int(4).width(), Some(4));
        assert_eq!(ValueType::Unknown.width(), None);
    }

    #[test]
    fn a_test_case_round_trips_through_json() {
        let blob = BlobRef(format!("{:064x}", 7));
        let case = TestCase {
            test_id: "price_lookup-0001".into(),
            hook: "price_lookup".into(),
            build: BuildId("ab".into()),
            rva: Rva(0x1010),
            recorder: "test".into(),
            abi: ABI_WIN64.into(),
            image_base: Word(0x7ff6_0000_0000),
            image_size: Some(Word(0x4000)),
            entry: EntryState {
                rcx: Word(10),
                rdx: Word(0),
                r8: Word(0),
                r9: Word(0),
                xmm: [Xmm([1; 16]), Xmm::default(), Xmm::default(), Xmm::default()],
                stack: vec![Word(5)],
            },
            regions: vec![Region {
                arg: 0,
                address: Word(0x1000),
                size: 4,
                kind: CaptureKind::Fixed,
                layout: None,
                before: blob.clone(),
                after: blob.clone(),
            }],
            globals: vec![GlobalRegion {
                name: "g_events".into(),
                rva: Rva(0x4088),
                size: 4,
                before: blob.clone(),
                after: blob.clone(),
            }],
            imports_recorded: true,
            imports: vec![ImportCall {
                import: "ucrtbase.dll!__acrt_iob_func".into(),
                entry: EntryState {
                    rcx: Word(1),
                    rdx: Word(0),
                    r8: Word(0),
                    r9: Word(0),
                    xmm: [Xmm::default(); 4],
                    stack: vec![],
                },
                observed: Observed {
                    rax: Word(0x7ff0_1234),
                    xmm0: Xmm::default(),
                },
                memory: vec![Snapshot {
                    address: Word(0x10),
                    before: blob,
                    after: None,
                }],
            }],
            observed: Observed {
                rax: Word(470),
                xmm0: Xmm::default(),
            },
        };
        let json = serde_json::to_string(&case).unwrap();
        assert!(json.contains("\"rcx\":\"0xa\""), "{json}");
        assert_eq!(serde_json::from_str::<TestCase>(&json).unwrap(), case);
        assert_eq!(case.entry.slot_value(ArgSlot::Stack(0x28)), Some(5));
        assert_eq!(case.entry.slot_value(ArgSlot::Stack(0x30)), None);
        assert_eq!(
            case.entry.slot_value(ArgSlot::Vector(0)),
            Some(0x0101_0101_0101_0101)
        );
    }
}
