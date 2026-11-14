//! Function discovery and per-function features.
//!
//! Discovery: x64 `.pdata` lists every function that needs unwind info, but MSVC emits none for leaf functions
//! that don't touch the stack, which is common at /O2. So starts are seeded from `.pdata`, the entry point,
//! exports and code pointers stored in data (base relocations: function tables, callbacks in initialized
//! structs), then extended to a fixpoint with direct call/jump targets and RIP-relative `lea` operands (an
//! address taken, e.g. a callback) that land in executable code outside any known function. A function without
//! `.pdata` ends at the next known start (trailing `int3` padding trimmed). Once nothing else is found, code
//! that starts on a 16-byte boundary after `int3` padding is a start too (dead code nothing references; see
//! `padding_starts`), so it isn't taken into the function before it.
//!
//! Chained `.pdata` entries are fragments of another function: at /O2 MSVC splits bodies into chained
//! fragments (shrink-wrapping), and these hold much of the code. Each fragment belongs to the function its chain
//! leads back to: it's decoded with it, and its calls, strings and constants are that function's.
//!
//! Features: the normalized hash covers each instruction's opcode and operands but masks anything that moves
//! when unrelated code moves: RIP-relative targets, branch targets outside the function, and immediates or
//! displacements that are addresses inside the image. Branch targets inside the function are kept as offsets
//! from the function start, so control-flow changes still change the hash. A RIP-relative operand that is an
//! import address table slot is hashed by the imported function's name instead.

use super::image::Image;
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess,
    OpKind, Register,
};
use permanent_beta_model::{ArgAccess, ArgClass, CodeTable, EntryInfo, FunctionFeatures, Rva};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FunctionRange {
    pub start: u32,
    pub end: u32,
    /// Boundaries come from `.pdata` (exact) rather than "until the next known start" (heuristic).
    pub from_pdata: bool,
    /// Chained `.pdata` fragments of this function, `[begin, end)`, in address order.
    pub fragments: Vec<(u32, u32)>,
}

impl FunctionRange {
    /// The function's code: its main range, then its fragments.
    fn segments(&self) -> impl Iterator<Item = (u32, u32)> + '_ {
        std::iter::once((self.start, self.end)).chain(self.fragments.iter().copied())
    }
}

/// Decode `[start, end)`. Stops early at the first invalid instruction.
fn decode(image: &Image, start: u32, end: u32) -> Vec<Instruction> {
    let Some(bytes) = image.bytes(start, end.saturating_sub(start) as usize) else {
        return Vec::new();
    };
    let mut decoder = Decoder::with_ip(64, bytes, image.base + start as u64, DecoderOptions::NONE);
    let mut out = Vec::new();
    let mut ins = Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut ins);
        if ins.is_invalid() {
            break;
        }
        out.push(ins);
    }
    out
}

fn is_near_branch(kind: OpKind) -> bool {
    matches!(
        kind,
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
    )
}

/// Find function starts and boundaries.
pub(crate) fn discover(image: &Image) -> Vec<FunctionRange> {
    let pdata: Vec<_> = image
        .pdata
        .iter()
        .filter(|r| image.is_executable(r.begin))
        .copied()
        .collect();
    let inside_pdata = |t: u32| pdata.iter().any(|r| r.begin <= t && t < r.end);

    let mut starts: BTreeSet<u32> = pdata
        .iter()
        .filter(|r| !r.chained)
        .map(|r| r.begin)
        .collect();
    starts.extend(image.entry.filter(|&e| image.is_executable(e)));
    starts.extend(
        image
            .exports
            .iter()
            .map(|e| e.0)
            .filter(|&e| image.is_executable(e)),
    );
    // A pointer in data into code outside any .pdata range: a function reached only through a table. Inside a
    // .pdata range it's a pointer into a known function (or a fragment), not a start.
    starts.extend(
        image
            .code_pointers
            .iter()
            .copied()
            .filter(|&t| !inside_pdata(t)),
    );
    // Every slot of an incremental linking table is a function of its own (`super::ilt`): one nothing calls
    // through would otherwise run into the slot before it.
    starts.extend(super::ilt::find(image).into_keys());

    loop {
        let mut found = Vec::new();
        let ranges = ranges(image, &starts);
        // Fragments whose chain couldn't be followed to a known start are still code worth scanning.
        let owned: BTreeSet<(u32, u32)> = ranges.iter().flat_map(|r| r.fragments.clone()).collect();
        let orphans = pdata
            .iter()
            .filter(|r| r.chained && !owned.contains(&(r.begin, r.end)))
            .map(|r| (r.begin, r.end));
        let segments: Vec<(u32, u32)> = ranges
            .iter()
            .flat_map(FunctionRange::segments)
            .chain(orphans)
            .collect();
        for (seg_start, seg_end) in segments {
            for ins in decode(image, seg_start, seg_end) {
                let (t, is_call) = if (0..ins.op_count()).any(|op| is_near_branch(ins.op_kind(op)))
                {
                    (
                        ins.near_branch_target(),
                        ins.flow_control() == FlowControl::Call,
                    )
                } else if ins.mnemonic() == Mnemonic::Lea && ins.is_ip_rel_memory_operand() {
                    // Address taken: treated like a jump (a new start only outside the current range).
                    (ins.ip_rel_memory_address(), false)
                } else {
                    continue;
                };
                let Some(t) = image.va_to_rva(t) else {
                    continue;
                };
                // A call target is a function start even inside the current range: a range without .pdata
                // runs to the next *known* start, so it can still swallow functions not yet discovered.
                // A jump inside the range is an ordinary branch.
                let internal = seg_start <= t && t < seg_end;
                if (is_call || !internal)
                    && image.is_executable(t)
                    && !starts.contains(&t)
                    && !inside_pdata(t)
                {
                    found.push(t);
                }
            }
        }
        if found.is_empty() {
            // Nothing reaches the rest: look for code that starts after padding (dead code, design §4.4).
            found = padding_starts(image, &ranges, &starts);
            if found.is_empty() {
                return ranges;
            }
        }
        starts.extend(found);
    }
}

/// Alignment MSVC gives function starts (`/ALIGN` default for x64 code is 16, padded with `int3`).
const FUNCTION_ALIGN: u32 = 16;

/// Function starts that nothing references, found by layout: MSVC pads between functions with `int3` up to a
/// 16-byte boundary. A start is the first byte after at least one `int3`, on a 16-byte boundary, that isn't
/// `int3` itself and decodes as an instruction, either
///
/// - in a gap no function or `.pdata` entry covers, or
/// - inside a function without `.pdata`, right after an instruction that doesn't fall through (`ret`, `jmp`,
///   `int3`), when no branch in that function targets it.
///
/// Inside a function, code after `int3` can be its own block (after a call that doesn't return), which is why
/// the padding, the alignment and the absence of an internal branch to it are all required. Functions with
/// `.pdata` are never split: their bounds are exact.
fn padding_starts(image: &Image, ranges: &[FunctionRange], starts: &BTreeSet<u32>) -> Vec<u32> {
    let mut covered: Vec<(u32, u32)> = ranges.iter().flat_map(|r| r.segments()).collect();
    covered.extend(image.pdata.iter().map(|r| (r.begin, r.end)));
    covered.sort_unstable();

    let mut found = Vec::new();
    let candidate = |at: u32, found: &mut Vec<u32>| {
        if at % FUNCTION_ALIGN == 0
            && image.is_executable(at)
            && !starts.contains(&at)
            && image.bytes(at, 1).is_some_and(|b| b[0] != 0xcc)
            && image
                .section_end(at)
                .is_some_and(|end| !decode(image, at, end.min(at + 16)).is_empty())
        {
            found.push(at);
        }
    };

    // Gaps between covered code, within each executable section.
    for section in image.sections.iter().filter(|s| s.executable) {
        let Some(section_end) = image.section_end(section.rva) else {
            continue;
        };
        let mut at = section.rva;
        for &(s, e) in covered
            .iter()
            .filter(|&&(s, _)| s >= section.rva && s < section_end)
        {
            if s > at {
                gap_start(image, at, s)
                    .into_iter()
                    .for_each(|c| candidate(c, &mut found));
            }
            at = at.max(e);
        }
        if section_end > at {
            gap_start(image, at, section_end)
                .into_iter()
                .for_each(|c| candidate(c, &mut found));
        }
    }

    // Inside functions without .pdata.
    for r in ranges.iter().filter(|r| !r.from_pdata) {
        let insns = decode(image, r.start, r.end);
        let targets: BTreeSet<u64> = insns
            .iter()
            .filter(|i| (0..i.op_count()).any(|op| is_near_branch(i.op_kind(op))))
            .map(Instruction::near_branch_target)
            .collect();
        let mut after_stop = false;
        let mut padding = 0;
        for ins in &insns {
            let rva = (ins.ip() - image.base) as u32;
            if ins.mnemonic() == Mnemonic::Int3 {
                padding += 1;
                continue;
            }
            if after_stop && padding > 0 && !targets.contains(&ins.ip()) {
                candidate(rva, &mut found);
            }
            after_stop = matches!(
                ins.flow_control(),
                FlowControl::Return
                    | FlowControl::UnconditionalBranch
                    | FlowControl::IndirectBranch
            );
            padding = 0;
        }
    }
    found.sort_unstable();
    found.dedup();
    found
}

/// In an uncovered gap `[from, to)`: the first byte after a run of at least one `int3`, if there is one.
fn gap_start(image: &Image, from: u32, to: u32) -> Option<u32> {
    let bytes = image.bytes(from, (to - from) as usize)?;
    let pad = bytes.iter().take_while(|&&b| b == 0xcc).count();
    (pad > 0 && pad < bytes.len()).then_some(from + pad as u32)
}

/// Boundaries for each start: exact from `.pdata`, otherwise up to the next start (or any `.pdata` begin,
/// including chained fragments), within the section, minus trailing `int3` padding.
fn ranges(image: &Image, starts: &BTreeSet<u32>) -> Vec<FunctionRange> {
    let mut boundaries: BTreeSet<u32> = starts.clone();
    boundaries.extend(image.pdata.iter().map(|r| r.begin));
    let fragments_of = |start: u32| -> Vec<(u32, u32)> {
        image
            .pdata
            .iter()
            .filter(|r| r.chained && r.parent == Some(start) && image.is_executable(r.begin))
            .map(|r| (r.begin, r.end))
            .collect()
    };

    starts
        .iter()
        .filter_map(|&start| {
            if let Some(r) = image.pdata.iter().find(|r| r.begin == start && !r.chained) {
                return Some(FunctionRange {
                    start,
                    end: r.end,
                    from_pdata: true,
                    fragments: fragments_of(start),
                });
            }
            let section_end = image.section_end(start)?;
            let next = boundaries
                .range(start + 1..)
                .next()
                .copied()
                .unwrap_or(section_end);
            let mut end = next.min(section_end);
            while end > start + 1 && image.bytes(end - 1, 1) == Some(&[0xcc]) {
                end -= 1;
            }
            Some(FunctionRange {
                start,
                end,
                from_pdata: false,
                fragments: fragments_of(start),
            })
        })
        .collect()
}

/// Constants worth keeping as matching evidence: not small integers and not small negatives.
/// Shortest run of consecutive code pointers kept as a table. One pointer alone is a callback, not a table, and
/// gives table-slot matching nothing to anchor on.
const MIN_TABLE_SLOTS: usize = 2;

/// Tables of code pointers in data (vtables, function tables): runs of consecutive 8-byte slots, each a
/// relocated pointer to the start of a function in `ranges`. A slot pointing anywhere else (RTTI locator, a
/// string, the middle of a function) ends the run.
pub(crate) fn code_tables(image: &Image, ranges: &[FunctionRange]) -> Vec<CodeTable> {
    let starts: BTreeSet<u32> = ranges.iter().map(|r| r.start).collect();
    let mut tables = Vec::new();
    let mut run: Vec<(u32, u32)> = Vec::new();
    let mut flush = |run: &mut Vec<(u32, u32)>| {
        if run.len() >= MIN_TABLE_SLOTS {
            tables.push(CodeTable {
                rva: Rva(u64::from(run[0].0)),
                slots: run.iter().map(|&(_, t)| Rva(u64::from(t))).collect(),
            });
        }
        run.clear();
    };
    for &(slot, target) in &image.code_pointer_slots {
        let follows = run.last().is_some_and(|&(prev, _)| prev + 8 == slot);
        if !follows {
            flush(&mut run);
        }
        if starts.contains(&target) {
            run.push((slot, target));
        } else {
            flush(&mut run);
        }
    }
    flush(&mut run);
    tables
}

fn is_interesting_constant(v: u64) -> bool {
    let s = v as i64;
    !(-0x100 < s && s < 0x100)
}

fn short_hash(h: Sha256, prefix: &str) -> String {
    let digest = h.finalize();
    let hex: String = digest[..8].iter().map(|b| format!("{b:02x}")).collect();
    format!("{prefix}:{hex}")
}

pub(crate) fn features(image: &Image, range: &FunctionRange) -> FunctionFeatures {
    let segments: Vec<(u64, u64)> = range
        .segments()
        .map(|(s, e)| (image.base + s as u64, image.base + e as u64))
        .collect();
    let insns: Vec<Instruction> = range
        .segments()
        .flat_map(|(s, e)| decode(image, s, e))
        .collect();
    let start_va = segments[0].0;
    // A branch into the function is hashed as (segment, offset within it): fragments can sit anywhere
    // relative to the main range, so an offset from the start alone would move with unrelated code.
    let internal = |t: u64| {
        segments
            .iter()
            .position(|&(s, e)| (s..e).contains(&t))
            .map(|i| (i as u8, (t - segments[i].0) as u32))
    };

    let mut nh = Sha256::new();
    let mut mh = Sha256::new();
    // Callees in order of first call site: the call-sequence matcher aligns on this order.
    let mut callees: Vec<Rva> = Vec::new();
    let mut strings = BTreeSet::new();
    let mut constants = BTreeSet::new();
    let mut imports = BTreeSet::new();
    let mut data_refs = BTreeSet::new();
    let mut code_refs = BTreeSet::new();
    let mut leaders: BTreeSet<u64> = segments.iter().map(|&(s, _)| s).collect();
    let mut internal_targets = BTreeSet::new();
    let mut mnemonic_counts: BTreeMap<String, u32> = BTreeMap::new();

    for (i, ins) in insns.iter().enumerate() {
        mh.update((ins.mnemonic() as u16).to_le_bytes());
        *mnemonic_counts
            .entry(format!("{:?}", ins.mnemonic()))
            .or_default() += 1;
        nh.update((ins.code() as u16).to_le_bytes());

        for op in 0..ins.op_count() {
            let kind = ins.op_kind(op);
            nh.update([kind as u8]);
            match kind {
                OpKind::Register => nh.update((ins.op_register(op) as u16).to_le_bytes()),
                k if is_near_branch(k) => {
                    let t = ins.near_branch_target();
                    if let Some((segment, offset)) = internal(t) {
                        nh.update(b"i");
                        nh.update([segment]);
                        nh.update(offset.to_le_bytes());
                        leaders.insert(t);
                        // A call to the function's own start (recursion) reaches the patch at its first byte and
                        // runs the hook, as a call from anywhere else does: not a hazard. A jump there (a loop back
                        // to the entry) or any branch into the rest of the patched bytes is.
                        if !(t == start_va && ins.flow_control() == FlowControl::Call) {
                            internal_targets.insert(t);
                        }
                    } else {
                        nh.update(b"x");
                        if let Some(rva) = image.va_to_rva(t).filter(|&r| image.is_executable(r)) {
                            let r = Rva(rva as u64);
                            if !callees.contains(&r) {
                                callees.push(r);
                            }
                        }
                    }
                }
                OpKind::Memory => {
                    nh.update((ins.memory_base() as u16).to_le_bytes());
                    nh.update((ins.memory_index() as u16).to_le_bytes());
                    nh.update(ins.memory_index_scale().to_le_bytes());
                    if ins.is_ip_rel_memory_operand() {
                        nh.update(b"r");
                        if let Some(rva) = image.va_to_rva(ins.ip_rel_memory_address()) {
                            if let Some(name) = image.iat.get(&rva) {
                                // The imported function's name is stable across builds, unlike the slot's
                                // address, so it's hashed: otherwise every import thunk (`jmp [slot]`) hashes
                                // the same, and so does code that differs only in which import it calls.
                                // Only the name after `!`: an API-set DLL version can change with the toolset.
                                nh.update(b"m");
                                nh.update(name.rsplit('!').next().unwrap_or(name).as_bytes());
                                nh.update([0]);
                                imports.insert(name.clone());
                            } else if let Some(s) = image.string_literal(rva) {
                                strings.insert(s);
                            } else if image.is_writable(rva) {
                                data_refs.insert(Rva(u64::from(rva)));
                            } else if ins.mnemonic() == Mnemonic::Lea
                                && image.is_executable(rva)
                                && internal(ins.ip_rel_memory_address()).is_none()
                            {
                                code_refs.insert(Rva(u64::from(rva)));
                            }
                        }
                    } else {
                        let d = ins.memory_displacement64();
                        if image.contains_va(d) {
                            nh.update(b"a");
                        } else {
                            nh.update(d.to_le_bytes());
                        }
                    }
                }
                OpKind::Immediate8
                | OpKind::Immediate8_2nd
                | OpKind::Immediate16
                | OpKind::Immediate32
                | OpKind::Immediate64
                | OpKind::Immediate8to16
                | OpKind::Immediate8to32
                | OpKind::Immediate8to64
                | OpKind::Immediate32to64 => {
                    let v = ins.immediate(op);
                    if image.contains_va(v) {
                        nh.update(b"a");
                    } else {
                        nh.update(v.to_le_bytes());
                        if is_interesting_constant(v) {
                            constants.insert(v);
                        }
                    }
                }
                _ => {}
            }
        }

        let ends_block = matches!(
            ins.flow_control(),
            FlowControl::ConditionalBranch
                | FlowControl::UnconditionalBranch
                | FlowControl::IndirectBranch
                | FlowControl::Return
        );
        if ends_block {
            if let Some(next) = insns.get(i + 1) {
                leaders.insert(next.ip());
            }
        }
    }

    // Only leaders that are actual instruction starts (a branch into the middle of an instruction is noise).
    let starts: BTreeSet<u64> = insns.iter().map(Instruction::ip).collect();
    let block_starts: BTreeSet<u64> = leaders.intersection(&starts).copied().collect();
    let basic_blocks = block_starts.len() as u32;

    // Control-flow edges between this function's blocks: taken branches to internal targets, plus
    // fall-through into the next block. Tail jumps, indirect jumps and returns leave the function.
    let mut edges = 0u32;
    for (i, ins) in insns.iter().enumerate() {
        let has_next = i + 1 < insns.len();
        let internal_branch = || {
            (0..ins.op_count()).any(|op| is_near_branch(ins.op_kind(op)))
                && internal(ins.near_branch_target()).is_some()
        };
        match ins.flow_control() {
            FlowControl::ConditionalBranch => {
                edges += u32::from(internal_branch()) + u32::from(has_next);
            }
            FlowControl::UnconditionalBranch => edges += u32::from(internal_branch()),
            FlowControl::IndirectBranch | FlowControl::Return => {}
            _ => {
                if insns
                    .get(i + 1)
                    .is_some_and(|n| block_starts.contains(&n.ip()))
                {
                    edges += 1;
                }
            }
        }
    }

    let args = if insns.is_empty() {
        (0, Vec::new())
    } else {
        inferred_args(&insns)
    };
    FunctionFeatures {
        rva: Rva(range.start as u64),
        size: range.segments().map(|(s, e)| e - s).sum(),
        name: None,
        name_source: None,
        normalized_hash: (!insns.is_empty()).then(|| short_hash(nh, "nh")),
        mnemonic_hash: (!insns.is_empty()).then(|| short_hash(mh, "mh")),
        basic_blocks: Some(basic_blocks),
        edges: Some(edges),
        callees,
        strings: strings.into_iter().collect(),
        constants: constants.into_iter().collect(),
        imports: imports.into_iter().collect(),
        data_refs: data_refs.into_iter().collect(),
        code_refs: code_refs.into_iter().collect(),
        thunk_to: None,
        signature: None,
        inferred_args: (!insns.is_empty()).then_some(args.0),
        inferred_arg_classes: args.1,
        arg_accesses: arg_accesses(&insns),
        entry: (!insns.is_empty()).then(|| entry_info(&insns, start_va, &internal_targets)),
        pseudocode: None,
        mnemonic_counts,
    }
}

/// What a 5-byte entry `jmp` would overwrite, and whether that's safe.
fn entry_info(insns: &[Instruction], start_va: u64, internal_targets: &BTreeSet<u64>) -> EntryInfo {
    let mut patch_len = 0usize;
    for ins in insns {
        if patch_len >= EntryInfo::PATCH_SIZE as usize {
            break;
        }
        patch_len += ins.len();
    }
    let patch_end = start_va + patch_len as u64;
    EntryInfo {
        patch_len: patch_len.min(u8::MAX as usize) as u8,
        branch_into_patch: internal_targets.range(start_va..patch_end).next().is_some(),
        jump_thunk: matches!(
            insns[0].flow_control(),
            FlowControl::UnconditionalBranch | FlowControl::IndirectBranch
        ),
    }
}

/// Most argument accesses recorded per function. **[Guess]**
const MAX_ARG_ACCESSES: usize = 64;
/// Offsets above this aren't taken for struct fields. **[Guess]**
const MAX_FIELD_OFFSET: i64 = 0x10000;

/// Memory accessed through the pointer arguments (design §7.2): a linear scan that follows each argument register
/// through register copies (`mov rbx, rcx`) and across calls in callee-saved registers, and drops it when the
/// register is written otherwise. Accesses with an index register, or a negative or very large offset, aren't
/// recorded. A heuristic: it ignores control flow, so a register reused on another path can be misread; struct
/// changes inferred from it are proposals for review, never applied.
fn arg_accesses(insns: &[Instruction]) -> Vec<ArgAccess> {
    const VOLATILE: [Register; 7] = [
        Register::RAX,
        Register::RCX,
        Register::RDX,
        Register::R8,
        Register::R9,
        Register::R10,
        Register::R11,
    ];
    let mut tracked: Vec<(Register, u8)> = ARG_SLOTS
        .iter()
        .enumerate()
        .map(|(i, &(g, _))| (g, i as u8))
        .collect();
    let slot_of = |tracked: &[(Register, u8)], r: Register| {
        tracked.iter().find(|(t, _)| *t == r).map(|(_, s)| *s)
    };
    let mut out = Vec::new();
    // Stack slots holding an argument: (offset from the entry rsp, slot).
    let mut spilled: Vec<(i64, u8)> = Vec::new();
    let mut rsp_delta: i64 = 0;
    let mut factory = InstructionInfoFactory::new();
    for ins in insns {
        if out.len() >= MAX_ARG_ACCESSES {
            break;
        }
        let info = factory.info(ins);
        for m in info.used_memory() {
            let base = m.base().full_register();
            let Some(slot) = slot_of(&tracked, base) else {
                continue;
            };
            let size = m.memory_size().size();
            let offset = m.displacement() as i64;
            if m.index() != Register::None
                || size == 0
                || size > 16
                || !(0..MAX_FIELD_OFFSET).contains(&offset)
            {
                continue;
            }
            let write = matches!(
                m.access(),
                OpAccess::Write
                    | OpAccess::CondWrite
                    | OpAccess::ReadWrite
                    | OpAccess::ReadCondWrite
            );
            out.push(ArgAccess {
                slot,
                offset: offset as u32,
                size: size as u8,
                write,
            });
        }
        // A 64-bit register copy carries the argument along, and so does a stack slot (/Od spills arguments to
        // their home slots and reloads them): slots are keyed by their offset from the entry rsp.
        let stack_key = |ins: &Instruction, rsp_delta: i64| {
            (ins.memory_base() == Register::RSP && ins.memory_index() == Register::None)
                .then(|| ins.memory_displacement64() as i64 - rsp_delta)
        };
        let is_mov64 = ins.mnemonic() == Mnemonic::Mov && ins.op_count() == 2;
        let mut copied = (is_mov64
            && ins.op0_kind() == OpKind::Register
            && ins.op1_kind() == OpKind::Register
            && ins.op0_register().size() == 8)
            .then(|| slot_of(&tracked, ins.op1_register()))
            .flatten();
        if is_mov64 && ins.op0_kind() == OpKind::Memory && ins.op1_kind() == OpKind::Register {
            if let Some(key) = stack_key(ins, rsp_delta) {
                spilled.retain(|(k, _)| *k != key);
                if ins.op1_register().size() == 8
                    && let Some(slot) = slot_of(&tracked, ins.op1_register())
                {
                    spilled.push((key, slot));
                }
            }
        }
        if is_mov64
            && ins.op0_kind() == OpKind::Register
            && ins.op0_register().size() == 8
            && ins.op1_kind() == OpKind::Memory
            && let Some(key) = stack_key(ins, rsp_delta)
        {
            copied = spilled.iter().find(|(k, _)| *k == key).map(|(_, s)| *s);
        }
        // Where rsp is relative to the entry, for the stack slots.
        match ins.mnemonic() {
            Mnemonic::Sub | Mnemonic::Add
                if ins.op0_kind() == OpKind::Register && ins.op0_register() == Register::RSP =>
            {
                if matches!(
                    ins.op1_kind(),
                    OpKind::Immediate8
                        | OpKind::Immediate8to64
                        | OpKind::Immediate32
                        | OpKind::Immediate32to64
                ) {
                    let imm = ins.immediate(1) as i64;
                    rsp_delta += if ins.mnemonic() == Mnemonic::Sub {
                        imm
                    } else {
                        -imm
                    };
                } else {
                    // `sub rsp, rax` (a __chkstk frame): rsp is no longer known, nor are the slots.
                    spilled.clear();
                }
            }
            Mnemonic::Push => rsp_delta += 8,
            Mnemonic::Pop => rsp_delta -= 8,
            _ => {}
        }
        for used in info.used_registers() {
            let writes = matches!(
                used.access(),
                OpAccess::Write
                    | OpAccess::CondWrite
                    | OpAccess::ReadWrite
                    | OpAccess::ReadCondWrite
            );
            if writes {
                let full = used.register().full_register();
                tracked.retain(|(t, _)| *t != full);
            }
        }
        if let Some(slot) = copied {
            tracked.push((ins.op0_register(), slot));
        }
        if ins.flow_control() == FlowControl::Call {
            tracked.retain(|(t, _)| !VOLATILE.contains(t));
        }
    }
    out
}

/// Win64 argument registers by slot: (integer register, vector register).
const ARG_SLOTS: [(Register, Register); 4] = [
    (Register::RCX, Register::ZMM0),
    (Register::RDX, Register::ZMM1),
    (Register::R8, Register::ZMM2),
    (Register::R9, Register::ZMM3),
];

/// Register-argument use: 1 + the highest argument slot whose register is read before it's written, scanning in
/// address order up to the first call or return, and each slot's register class up to that one. A heuristic
/// lower bound: it ignores control flow, unused trailing parameters and stack arguments.
fn inferred_args(insns: &[Instruction]) -> (u8, Vec<ArgClass>) {
    #[derive(Clone, Copy, PartialEq)]
    enum Slot {
        Unknown,
        Arg(ArgClass),
        Clobbered,
    }
    let mut slots = [Slot::Unknown; 4];
    let mut factory = InstructionInfoFactory::new();
    for ins in insns {
        if matches!(ins.flow_control(), FlowControl::Call | FlowControl::Return) {
            break;
        }
        let info = factory.info(ins);
        // Reads first: `add rcx, rdx` reads rcx before writing it.
        for pass_reads in [true, false] {
            for used in info.used_registers() {
                let full = used.register().full_register();
                let Some((slot, class)) = ARG_SLOTS.iter().enumerate().find_map(|(i, &(g, v))| {
                    if g == full {
                        Some((i, ArgClass::Integer))
                    } else if v == full {
                        Some((i, ArgClass::Vector))
                    } else {
                        None
                    }
                }) else {
                    continue;
                };
                if slots[slot] != Slot::Unknown {
                    continue;
                }
                let reads = matches!(
                    used.access(),
                    OpAccess::Read
                        | OpAccess::CondRead
                        | OpAccess::ReadWrite
                        | OpAccess::ReadCondWrite
                );
                let writes = used.access() == OpAccess::Write;
                if pass_reads && reads {
                    slots[slot] = Slot::Arg(class);
                } else if !pass_reads && writes {
                    slots[slot] = Slot::Clobbered;
                }
            }
        }
    }
    let count = slots
        .iter()
        .rposition(|s| matches!(s, Slot::Arg(_)))
        .map_or(0, |i| i + 1);
    let classes = slots[..count]
        .iter()
        .map(|s| match s {
            Slot::Arg(c) => *c,
            _ => ArgClass::Unused,
        })
        .collect();
    (count as u8, classes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::image::tests::image;

    fn range(start: u32, end: u32) -> FunctionRange {
        FunctionRange {
            start,
            end,
            from_pdata: false,
            fragments: vec![],
        }
    }

    #[test]
    fn rip_relative_targets_are_masked() {
        // lea rcx, [rip+0x0ff9]; ret   vs   lea rcx, [rip+0x1ff9]; ret  (same code, data moved)
        let a = [0x48, 0x8d, 0x0d, 0xf9, 0x0f, 0x00, 0x00, 0xc3];
        let b = [0x48, 0x8d, 0x0d, 0xf9, 0x1f, 0x00, 0x00, 0xc3];
        let fa = features(&image(&a, &[]), &range(0x1000, 0x1008));
        let fb = features(&image(&b, &[]), &range(0x1000, 0x1008));
        assert_eq!(fa.normalized_hash, fb.normalized_hash);
    }

    #[test]
    fn different_immediates_change_the_hash() {
        // add eax, 5; ret   vs   add eax, 6; ret
        let fa = features(
            &image(&[0x83, 0xc0, 0x05, 0xc3], &[]),
            &range(0x1000, 0x1004),
        );
        let fb = features(
            &image(&[0x83, 0xc0, 0x06, 0xc3], &[]),
            &range(0x1000, 0x1004),
        );
        assert_ne!(fa.normalized_hash, fb.normalized_hash);
        assert_eq!(fa.mnemonic_hash, fb.mnemonic_hash, "same mnemonics");
    }

    #[test]
    fn different_struct_offsets_change_the_hash() {
        // mov eax, [rcx+4]; ret   vs   mov eax, [rcx+8]; ret  (fixture scenario S5)
        let fa = features(
            &image(&[0x8b, 0x41, 0x04, 0xc3], &[]),
            &range(0x1000, 0x1004),
        );
        let fb = features(
            &image(&[0x8b, 0x41, 0x08, 0xc3], &[]),
            &range(0x1000, 0x1004),
        );
        assert_ne!(fa.normalized_hash, fb.normalized_hash);
    }

    /// `jmp qword ptr [rip+disp]` at 0x1000 reading the IAT slot at 0x2000 + `slot`.
    fn thunk(slot: u32) -> Vec<u8> {
        let mut code = vec![0xff, 0x25];
        code.extend((0x1000 + slot - 6).to_le_bytes());
        code
    }

    fn with_iat(code: &[u8], iat: &[(u32, &str)]) -> Image {
        let mut img = image(code, &[0; 0x40]);
        img.iat = iat.iter().map(|&(r, n)| (r, n.to_owned())).collect();
        img
    }

    #[test]
    fn import_thunks_hash_by_imported_name() {
        // The same import through a different slot (the IAT moved): same hash.
        let sin = features(
            &with_iat(&thunk(0x10), &[(0x2010, "math.dll!sin")]),
            &range(0x1000, 0x1006),
        );
        let sin_moved = features(
            &with_iat(&thunk(0x18), &[(0x2018, "math.dll!sin")]),
            &range(0x1000, 0x1006),
        );
        assert_eq!(sin.normalized_hash, sin_moved.normalized_hash);
        assert_eq!(sin.imports, vec!["math.dll!sin".to_string()]);
        // Only the name counts, not the API-set DLL it comes from.
        let sin_other_dll = features(
            &with_iat(&thunk(0x10), &[(0x2010, "math-l1-1-1.dll!sin")]),
            &range(0x1000, 0x1006),
        );
        assert_eq!(sin.normalized_hash, sin_other_dll.normalized_hash);
        // Negative: identical code reaching a different import must not hash the same (Lua's math_sin and
        // math_cos thunks did before).
        let cos = features(
            &with_iat(&thunk(0x10), &[(0x2010, "math.dll!cos")]),
            &range(0x1000, 0x1006),
        );
        assert_ne!(sin.normalized_hash, cos.normalized_hash);
        assert_eq!(sin.mnemonic_hash, cos.mnemonic_hash, "same mnemonics");
        // Negative: a RIP-relative read that isn't an IAT slot is still masked, not hashed by contents.
        let a = features(&with_iat(&thunk(0x10), &[]), &range(0x1000, 0x1006));
        let b = features(&with_iat(&thunk(0x18), &[]), &range(0x1000, 0x1006));
        assert_eq!(a.normalized_hash, b.normalized_hash);
        assert_ne!(a.normalized_hash, sin.normalized_hash);
    }

    #[test]
    fn collects_string_references() {
        // lea rcx, [rip+0x0ff9] → 0x1007 + 0x0ff9 = 0x2000; ret
        let code = [0x48, 0x8d, 0x0d, 0xf9, 0x0f, 0x00, 0x00, 0xc3];
        let f = features(&image(&code, b"pb-config.ini\0"), &range(0x1000, 0x1008));
        assert_eq!(f.strings, vec!["pb-config.ini".to_string()]);
    }

    #[test]
    fn collects_code_addresses_it_takes() {
        // 0x1000: lea rax, [rip+0x19] → 0x1020 (another function); lea rcx, [rip-0x0e] → 0x1000 (itself);
        // lea rdx, [rip+0x0feb] → 0x2000 (a string, not code); ret; 0x1020: ret
        let mut code = vec![0x48, 0x8d, 0x05, 0x19, 0x00, 0x00, 0x00];
        code.extend([0x48, 0x8d, 0x0d, 0xf2, 0xff, 0xff, 0xff]);
        code.extend([0x48, 0x8d, 0x15, 0xeb, 0x0f, 0x00, 0x00, 0xc3]);
        code.resize(0x20, 0xcc);
        code.push(0xc3);
        let f = features(&image(&code, b"pb-config.ini\0"), &range(0x1000, 0x1016));
        // Negative: its own address (a jump table's base, a recursion) and data aren't code refs.
        assert_eq!(f.code_refs, vec![Rva(0x1020)]);
        assert_eq!(f.strings, vec!["pb-config.ini".to_string()]);
        // Negative: a call is a callee, not an address taken.
        // 0x1000: call 0x1010; ret
        let mut code = vec![0xe8, 0x0b, 0x00, 0x00, 0x00, 0xc3];
        code.resize(0x10, 0xcc);
        code.push(0xc3);
        let f = features(&image(&code, &[]), &range(0x1000, 0x1006));
        assert_eq!(f.callees, vec![Rva(0x1010)]);
        assert!(f.code_refs.is_empty());
    }

    #[test]
    fn discovers_leaf_functions_from_call_targets() {
        // 0x1000: call 0x1010; ret; int3 padding; 0x1010: mov eax, 1; ret
        let mut code = vec![0xe8, 0x0b, 0x00, 0x00, 0x00, 0xc3];
        code.resize(0x10, 0xcc);
        code.extend([0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3]);
        let mut img = image(&code, &[]);
        img.entry = Some(0x1000);

        let found = discover(&img);
        let starts: Vec<u32> = found.iter().map(|r| r.start).collect();
        assert_eq!(starts, vec![0x1000, 0x1010]);
        assert_eq!(found[0].end, 0x1006, "trailing int3 padding trimmed");
        let caller = features(&img, &found[0]);
        assert_eq!(caller.callees, vec![Rva(0x1010)]);
    }

    #[test]
    fn jumps_into_a_pdata_function_body_are_not_new_starts() {
        use crate::native::image::RuntimeFunction;
        // 0x1000: jmp 0x1012 (into the middle of the pdata function at 0x1010..0x1020)
        let mut code = vec![0xe9, 0x0d, 0x00, 0x00, 0x00];
        code.resize(0x20, 0x90);
        let mut img = image(&code, &[]);
        img.entry = Some(0x1000);
        img.pdata = vec![RuntimeFunction {
            begin: 0x1010,
            end: 0x1020,
            chained: false,
            parent: None,
        }];

        let starts: Vec<u32> = discover(&img).iter().map(|r| r.start).collect();
        assert_eq!(starts, vec![0x1000, 0x1010]);
    }

    fn pdata(begin: u32, end: u32, parent: Option<u32>) -> crate::native::image::RuntimeFunction {
        crate::native::image::RuntimeFunction {
            begin,
            end,
            chained: parent.is_some(),
            parent,
        }
    }

    /// 0x1000: f, `jmp` to its chained fragment at `fragment`; 0x1010: a leaf without .pdata (`mov eax, 1; ret`);
    /// the fragment: `call 0x1010; ret`. The leaf is called only from the fragment.
    fn split_function(fragment: u32) -> Image {
        let mut code = vec![0xe9];
        code.extend((fragment as i32 - 0x1005).to_le_bytes());
        code.resize(0x10, 0xcc);
        code.extend([0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3]);
        code.resize((fragment - 0x1000) as usize, 0xcc);
        code.push(0xe8);
        code.extend((0x1010 - (fragment as i32 + 5)).to_le_bytes());
        code.push(0xc3);
        let mut img = image(&code, &[]);
        img.pdata = vec![
            pdata(0x1000, 0x1005, None),
            pdata(fragment, fragment + 6, Some(0x1000)),
        ];
        img
    }

    #[test]
    fn chained_fragments_are_part_of_their_function() {
        let img = split_function(0x1020);
        let found = discover(&img);
        let starts: Vec<u32> = found.iter().map(|r| r.start).collect();
        assert_eq!(
            starts,
            vec![0x1000, 0x1010],
            "leaf found through the fragment; the fragment itself is not a function"
        );
        assert_eq!(found[0].fragments, vec![(0x1020, 0x1026)]);
        let f = features(&img, &found[0]);
        assert_eq!(f.callees, vec![Rva(0x1010)], "the fragment's call is f's");
        assert_eq!(f.size, 5 + 6);
    }

    #[test]
    fn moving_a_fragment_does_not_change_the_hash() {
        // Same code; only the distance from f to its fragment differs.
        let (a, b) = (split_function(0x1020), split_function(0x1040));
        let fa = features(&a, &discover(&a)[0]);
        let fb = features(&b, &discover(&b)[0]);
        assert_eq!(fa.normalized_hash, fb.normalized_hash);
    }

    /// 0x1000..0x1008 (.pdata): `lea rcx, [rip+d]; ret` taking the address `target`. 0x1010: `xor eax, eax; ret`,
    /// then padding to 0x1020.
    fn takes_address(target: u32, pdata_at_0x1010: bool) -> Vec<u32> {
        let mut code = vec![0x48, 0x8d, 0x0d];
        code.extend((target as i32 - 0x1007).to_le_bytes());
        code.push(0xc3);
        // nop filler, not int3 padding: these cases are about address-taken code, not layout.
        code.resize(0x10, 0x90);
        code.extend([0x33, 0xc0, 0xc3]);
        code.resize(0x20, 0xcc);
        let mut img = image(&code, &[]);
        img.pdata = vec![pdata(0x1000, 0x1008, None)];
        if pdata_at_0x1010 {
            img.pdata.push(pdata(0x1010, 0x1020, None));
        }
        discover(&img).iter().map(|r| r.start).collect()
    }

    #[test]
    fn address_taken_code_is_a_function_start() {
        // A callback passed by address (zlib's zcalloc/zcfree): no .pdata, never called directly.
        assert_eq!(takes_address(0x1010, false), vec![0x1000, 0x1010]);
    }

    #[test]
    fn address_inside_a_known_function_is_not_a_start() {
        // lea into the middle of a .pdata function, or into the lea's own function: not new functions.
        assert_eq!(takes_address(0x1012, true), vec![0x1000, 0x1010]);
        assert_eq!(takes_address(0x1003, false), vec![0x1000]);
    }

    /// 0x1000 (.pdata 0x1000..0x1010): `xor eax, eax; ret`. 0x1010 and 0x1020: leaves without .pdata, each
    /// `mov eax, 1; ret`, never called; 0x1020 is in a function table in data (`table_has_0x1020`).
    fn table_image(code_pointers: Vec<u32>) -> Vec<(u32, u32)> {
        let mut code = vec![0x33, 0xc0, 0xc3];
        code.resize(0x10, 0xcc);
        code.extend([0xb8, 1, 0, 0, 0, 0xc3]);
        // nop filler before 0x1020, so only the table can make it a start (not int3 padding).
        code.resize(0x20, 0x90);
        code.extend([0xb8, 1, 0, 0, 0, 0xc3]);
        code.resize(0x30, 0xcc);
        let mut img = image(&code, &[]);
        img.pdata = vec![pdata(0x1000, 0x1010, None)];
        img.exports = vec![(0x1010, "f".into())];
        img.code_pointers = code_pointers;
        discover(&img).iter().map(|r| (r.start, r.end)).collect()
    }

    #[test]
    fn a_function_only_in_a_data_table_is_found_not_absorbed() {
        // Without the table entry, 0x1020 is absorbed: 0x1010 runs to the section's end (zstd's block
        // compressor table, design §4.4).
        assert_eq!(
            table_image(vec![]),
            vec![(0x1000, 0x1010), (0x1010, 0x1026)]
        );
        assert_eq!(
            table_image(vec![0x1020]),
            vec![(0x1000, 0x1010), (0x1010, 0x1020), (0x1020, 0x1026)]
        );
    }

    #[test]
    fn a_data_pointer_into_a_pdata_function_is_not_a_start() {
        // Negative case: a pointer into the middle of a function with exact .pdata bounds must not split it.
        assert_eq!(
            table_image(vec![0x1002]),
            vec![(0x1000, 0x1010), (0x1010, 0x1026)]
        );
    }

    /// Discover functions in `code` (at 0x1000), with an export at 0x1000 and the given .pdata entries.
    fn starts_in(code: &[u8], pdata_entries: &[(u32, u32)]) -> Vec<(u32, u32)> {
        let mut img = image(code, &[]);
        img.pdata = pdata_entries
            .iter()
            .map(|&(b, e)| pdata(b, e, None))
            .collect();
        img.exports = vec![(0x1000, "f".into())];
        discover(&img).iter().map(|r| (r.start, r.end)).collect()
    }

    /// `prefix` at 0x1000, `int3` padding up to `at`, then `mov eax, 1; ret`.
    fn padded(prefix: &[u8], at: usize) -> Vec<u8> {
        let mut c = prefix.to_vec();
        c.resize(at - 0x1000, 0xcc);
        c.extend([0xb8, 1, 0, 0, 0, 0xc3]);
        c
    }

    const XOR_RET: [u8; 3] = [0x33, 0xc0, 0xc3];

    #[test]
    fn unreferenced_code_after_padding_in_a_gap_is_a_function() {
        // A .pdata function, padding, then dead code nothing calls (zlib /Od's compressBound).
        let code = padded(&XOR_RET, 0x1010);
        assert_eq!(
            starts_in(&code, &[(0x1000, 0x1003)]),
            vec![(0x1000, 0x1003), (0x1010, 0x1016)]
        );
    }

    #[test]
    fn unreferenced_code_after_padding_is_not_absorbed() {
        // No .pdata: without the padding rule 0x1000 would run to the end (zstd /Od's FSE_compressBound).
        let code = padded(&XOR_RET, 0x1010);
        assert_eq!(
            starts_in(&code, &[]),
            vec![(0x1000, 0x1003), (0x1010, 0x1016)]
        );
    }

    #[test]
    fn a_block_its_function_branches_to_is_not_split_off() {
        // Negative case: `test ecx, ecx; je 0x1010; ret`, padding, then the je's target. One function.
        let code = padded(&[0x85, 0xc9, 0x74, 0x0c, 0xc3], 0x1010);
        assert_eq!(starts_in(&code, &[]), vec![(0x1000, 0x1016)]);
    }

    #[test]
    fn unaligned_code_after_padding_is_not_a_start() {
        // Negative case: padding that ends off a 16-byte boundary isn't function alignment.
        let code = padded(&XOR_RET, 0x100c);
        assert_eq!(starts_in(&code, &[]), vec![(0x1000, 0x1012)]);
    }

    #[test]
    fn a_pdata_function_is_never_split_by_padding() {
        // Negative case: .pdata says 0x1000..0x1016 is one function, padding inside or not.
        let code = padded(&XOR_RET, 0x1010);
        assert_eq!(
            starts_in(&code, &[(0x1000, 0x1016)]),
            vec![(0x1000, 0x1016)]
        );
    }

    fn analyze(code: &[u8]) -> FunctionFeatures {
        features(
            &image(code, &[]),
            &range(0x1000, 0x1000 + code.len() as u32),
        )
    }

    #[test]
    fn infers_integer_register_arguments() {
        // mov eax, ecx; add eax, edx; ret  → reads rcx and rdx
        assert_eq!(
            analyze(&[0x8b, 0xc1, 0x03, 0xc2, 0xc3]).inferred_args,
            Some(2)
        );
        // mov eax, r8d; ret  → third slot used, so at least 3 parameters; the first two aren't read
        let f = analyze(&[0x44, 0x89, 0xc0, 0xc3]);
        assert_eq!(f.inferred_args, Some(3));
        assert_eq!(
            f.inferred_arg_classes,
            vec![ArgClass::Unused, ArgClass::Unused, ArgClass::Integer]
        );
    }

    #[test]
    fn infers_vector_register_arguments() {
        // addss xmm0, xmm1; ret  → float parameters in slots 1 and 2
        let f = analyze(&[0xf3, 0x0f, 0x58, 0xc1, 0xc3]);
        assert_eq!(f.inferred_args, Some(2));
        assert_eq!(f.inferred_arg_classes, vec![ArgClass::Vector; 2]);
    }

    #[test]
    fn register_written_before_read_is_not_an_argument() {
        // mov ecx, 5; mov eax, ecx; ret
        let f = analyze(&[0xb9, 0x05, 0x00, 0x00, 0x00, 0x8b, 0xc1, 0xc3]);
        assert_eq!(f.inferred_args, Some(0));
    }

    #[test]
    fn reads_after_a_call_are_not_arguments() {
        // call +0; mov eax, ecx; ret  → rcx after a call is a clobbered value, not a parameter
        let f = analyze(&[0xe8, 0x00, 0x00, 0x00, 0x00, 0x8b, 0xc1, 0xc3]);
        assert_eq!(f.inferred_args, Some(0));
    }

    fn accesses(code: &[u8]) -> Vec<(u8, u32, u8, bool)> {
        analyze(code)
            .arg_accesses
            .iter()
            .map(|a| (a.slot, a.offset, a.size, a.write))
            .collect()
    }

    #[test]
    fn accesses_through_pointer_arguments_are_recorded() {
        // mov eax, [rcx+4]; add eax, eax; add eax, [rcx]; mov [rdx+0x10], eax; ret
        assert_eq!(
            accesses(&[
                0x8b, 0x41, 0x04, 0x01, 0xc0, 0x03, 0x01, 0x89, 0x42, 0x10, 0xc3
            ]),
            [(0, 4, 4, false), (0, 0, 4, false), (1, 0x10, 4, true)]
        );
    }

    #[test]
    fn an_argument_kept_in_a_callee_saved_register_survives_a_call() {
        // mov rbx, rcx; call $+5; mov eax, [rbx+8]; mov ecx, [rcx+8]; ret
        // rbx carries slot 0 across the call; rcx is volatile, so its access after the call isn't recorded.
        assert_eq!(
            accesses(&[
                0x48, 0x8b, 0xd9, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x8b, 0x43, 0x08, 0x8b, 0x49, 0x08,
                0xc3
            ]),
            [(0, 8, 4, false)]
        );
    }

    #[test]
    fn an_argument_spilled_to_its_home_slot_is_followed() {
        // /Od: mov [rsp+8], rcx; sub rsp, 28h; mov rax, [rsp+30h]; mov eax, [rax+4]; add rsp, 28h; ret
        assert_eq!(
            accesses(&[
                0x48, 0x89, 0x4c, 0x24, 0x08, 0x48, 0x83, 0xec, 0x28, 0x48, 0x8b, 0x44, 0x24, 0x30,
                0x8b, 0x40, 0x04, 0x48, 0x83, 0xc4, 0x28, 0xc3
            ]),
            [(0, 4, 4, false)]
        );
        // Negative: the reload is from another slot ([rsp+38h] is the second home slot, never written).
        assert_eq!(
            accesses(&[
                0x48, 0x89, 0x4c, 0x24, 0x08, 0x48, 0x83, 0xec, 0x28, 0x48, 0x8b, 0x44, 0x24, 0x38,
                0x8b, 0x40, 0x04, 0x48, 0x83, 0xc4, 0x28, 0xc3
            ]),
            []
        );
    }

    #[test]
    fn a_register_rsp_adjustment_doesnt_crash_the_scan() {
        // mov [rsp+8], rcx; sub rsp, rax (a __chkstk frame); mov rax, [rsp+8]; mov eax, [rax+4]; ret
        // Negative: after rsp moves by an unknown amount, the slot isn't trusted.
        assert_eq!(
            accesses(&[
                0x48, 0x89, 0x4c, 0x24, 0x08, 0x48, 0x2b, 0xe0, 0x48, 0x8b, 0x44, 0x24, 0x08, 0x8b,
                0x40, 0x04, 0xc3
            ]),
            []
        );
    }

    #[test]
    fn an_overwritten_argument_or_an_indexed_access_isnt_a_field() {
        // Negative: mov rcx, [rcx] (a read of field 0, then rcx is something else); mov eax, [rcx+8];
        // mov eax, [rdx+r8*4]; ret
        assert_eq!(
            accesses(&[
                0x48, 0x8b, 0x09, 0x8b, 0x41, 0x08, 0x42, 0x8b, 0x04, 0x82, 0xc3
            ]),
            [(0, 0, 8, false)]
        );
    }

    #[test]
    fn ordinary_function_entry_is_hookable() {
        // sub rsp, 0x28; mov eax, ecx; add rsp, 0x28; ret
        let f = analyze(&[
            0x48, 0x83, 0xec, 0x28, 0x8b, 0xc1, 0x48, 0x83, 0xc4, 0x28, 0xc3,
        ]);
        let e = f.entry.unwrap();
        assert_eq!(
            e.patch_len, 6,
            "two whole instructions cover the 5-byte patch"
        );
        assert!(e.hazards().is_empty(), "{:?}", e.hazards());
    }

    #[test]
    fn too_short_function_is_not_hookable() {
        // xor eax, eax; ret  (3 bytes)
        let e = analyze(&[0x33, 0xc0, 0xc3]).entry.unwrap();
        assert_eq!(e.patch_len, 3);
        assert_eq!(e.hazards().len(), 1);
    }

    #[test]
    fn loop_back_to_entry_is_not_hookable() {
        // 0x1000: dec ecx; jnz 0x1000; ret; nop; nop  → the loop jumps into the patched bytes
        let e = analyze(&[0xff, 0xc9, 0x75, 0xfc, 0xc3, 0x90, 0x90])
            .entry
            .unwrap();
        assert!(e.branch_into_patch);
        assert!(!e.hazards().is_empty());
    }

    #[test]
    fn a_function_that_calls_itself_is_hookable() {
        // 0x1000: sub rsp, 28h; call 0x1000; add rsp, 28h; ret  → the recursive call runs the hook, as it should
        let e = analyze(&[
            0x48, 0x83, 0xec, 0x28, 0xe8, 0xf7, 0xff, 0xff, 0xff, 0x48, 0x83, 0xc4, 0x28, 0xc3,
        ])
        .entry
        .unwrap();
        assert!(!e.branch_into_patch);
        assert!(e.hazards().is_empty(), "{:?}", e.hazards());
    }

    #[test]
    fn a_jump_to_the_entry_or_a_call_into_the_patch_is_not_hookable() {
        // Negative: 0x1000: sub rsp, 28h; add rsp, 28h; jmp 0x1000  → a loop back to the entry, not a call
        let e = analyze(&[0x48, 0x83, 0xec, 0x28, 0x48, 0x83, 0xc4, 0x28, 0xeb, 0xf6])
            .entry
            .unwrap();
        assert!(e.branch_into_patch);
        // Negative: 0x1000: nop; sub rsp, 28h; call 0x1001; add rsp, 28h; ret  → a call into the middle of the
        // patched bytes, which the hook's jmp overwrites
        let e = analyze(&[
            0x90, 0x48, 0x83, 0xec, 0x28, 0xe8, 0xf7, 0xff, 0xff, 0xff, 0x48, 0x83, 0xc4, 0x28,
            0xc3,
        ])
        .entry
        .unwrap();
        assert!(e.branch_into_patch);
        assert!(!e.hazards().is_empty());
    }

    #[test]
    fn counts_blocks_edges_and_mnemonics() {
        // 0x1000: test ecx, ecx; 0x1002: je 0x1006; 0x1004: mov eax, ecx; 0x1006: ret
        //   blocks {0x1000, 0x1004, 0x1006}: je taken + fall-through, mov falls into ret = 3 edges
        let f = analyze(&[0x85, 0xc9, 0x74, 0x02, 0x8b, 0xc1, 0xc3]);
        assert_eq!(f.basic_blocks, Some(3));
        assert_eq!(f.edges, Some(3));
        assert_eq!(f.mnemonic_counts.get("Mov"), Some(&1));
        assert_eq!(f.mnemonic_counts.values().sum::<u32>(), 4);
    }

    #[test]
    fn tail_jumps_and_returns_add_no_edges() {
        // jmp rel32 out of the function: one block, no edges.
        let f = analyze(&[0xe9, 0x10, 0x00, 0x00, 0x00]);
        assert_eq!((f.basic_blocks, f.edges), (Some(1), Some(0)));
    }

    #[test]
    fn jump_thunk_is_flagged() {
        // jmp rel32
        let e = analyze(&[0xe9, 0x10, 0x00, 0x00, 0x00]).entry.unwrap();
        assert!(e.jump_thunk);
    }

    #[test]
    fn consecutive_code_pointers_to_function_starts_are_tables() {
        let mut img = image(&[0xc3; 0x30], &[]);
        img.code_pointer_slots = vec![
            // A table of two.
            (0x2000, 0x1000),
            (0x2008, 0x1010),
            // A pointer into the middle of a function ends the run (and isn't part of any table).
            (0x2010, 0x1005),
            (0x2018, 0x1020),
            (0x2020, 0x1000),
            // A gap ends the run: a lone pointer is a callback, not a table.
            (0x2030, 0x1010),
            (0x2040, 0x1020),
        ];
        let ranges = vec![
            range(0x1000, 0x1010),
            range(0x1010, 0x1020),
            range(0x1020, 0x1030),
        ];
        let rva = |x: u64| Rva(x);
        assert_eq!(
            code_tables(&img, &ranges),
            vec![
                CodeTable {
                    rva: rva(0x2000),
                    slots: vec![rva(0x1000), rva(0x1010)]
                },
                CodeTable {
                    rva: rva(0x2018),
                    slots: vec![rva(0x1020), rva(0x1000)]
                },
            ]
        );
    }
}
