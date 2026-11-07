//! Function discovery and per-function features.
//!
//! Discovery: x64 `.pdata` lists every function that needs unwind info, but MSVC emits none for leaf functions
//! that don't touch the stack, which is common at /O2. So starts are seeded from `.pdata`, the entry point and
//! exports, then extended to a fixpoint with direct call/jump targets and RIP-relative `lea` operands (an
//! address taken, e.g. a callback) that land in executable code outside any known function. A function without
//! `.pdata` ends at the next known start (trailing `int3` padding trimmed).
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
use permanent_beta_model::{ArgClass, EntryInfo, FunctionFeatures, Rva};
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
            return ranges;
        }
        starts.extend(found);
    }
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
                        internal_targets.insert(t);
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
        signature: None,
        inferred_args: (!insns.is_empty()).then_some(args.0),
        inferred_arg_classes: args.1,
        entry: (!insns.is_empty()).then(|| entry_info(&insns, start_va, &internal_targets)),
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
        code.resize(0x10, 0xcc);
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
}
