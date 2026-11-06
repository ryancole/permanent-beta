//! Function discovery and per-function features.
//!
//! Discovery: x64 `.pdata` lists every function that needs unwind info, but MSVC emits none for leaf functions
//! that don't touch the stack, which is common at /O2. So starts are seeded from `.pdata`, the entry point and
//! exports, then extended to a fixpoint with direct call/jump targets that land in executable code outside any
//! known function. A function without `.pdata` ends at the next known start (trailing `int3` padding trimmed).
//!
//! Features: the normalized hash covers each instruction's opcode and operands but masks anything that moves
//! when unrelated code moves: RIP-relative targets, branch targets outside the function, and immediates or
//! displacements that are addresses inside the image. Branch targets inside the function are kept as offsets
//! from the function start, so control-flow changes still change the hash.

use super::image::Image;
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, OpKind};
use permanent_beta_model::{FunctionFeatures, Rva};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FunctionRange {
    pub start: u32,
    pub end: u32,
    /// Boundaries come from `.pdata` (exact) rather than "until the next known start" (heuristic).
    pub from_pdata: bool,
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
        for range in ranges(image, &starts) {
            for ins in decode(image, range.start, range.end) {
                if !(0..ins.op_count()).any(|op| is_near_branch(ins.op_kind(op))) {
                    continue;
                }
                let Some(t) = image.va_to_rva(ins.near_branch_target()) else {
                    continue;
                };
                // A call target is a function start even inside the current range: a range without .pdata
                // runs to the next *known* start, so it can still swallow functions not yet discovered.
                // A jump inside the range is an ordinary branch.
                let is_call = ins.flow_control() == FlowControl::Call;
                let internal = range.start <= t && t < range.end;
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
            return ranges(image, &starts);
        }
        starts.extend(found);
    }
}

/// Boundaries for each start: exact from `.pdata`, otherwise up to the next start (or any `.pdata` begin,
/// including chained fragments), within the section, minus trailing `int3` padding.
fn ranges(image: &Image, starts: &BTreeSet<u32>) -> Vec<FunctionRange> {
    let mut boundaries: BTreeSet<u32> = starts.clone();
    boundaries.extend(image.pdata.iter().map(|r| r.begin));

    starts
        .iter()
        .filter_map(|&start| {
            if let Some(r) = image.pdata.iter().find(|r| r.begin == start && !r.chained) {
                return Some(FunctionRange {
                    start,
                    end: r.end,
                    from_pdata: true,
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

pub(crate) fn features(image: &Image, range: FunctionRange) -> FunctionFeatures {
    let insns = decode(image, range.start, range.end);
    let (start_va, end_va) = (
        image.base + range.start as u64,
        image.base + range.end as u64,
    );

    let mut nh = Sha256::new();
    let mut mh = Sha256::new();
    // Callees in order of first call site: the call-sequence matcher aligns on this order.
    let mut callees: Vec<Rva> = Vec::new();
    let mut strings = BTreeSet::new();
    let mut constants = BTreeSet::new();
    let mut imports = BTreeSet::new();
    let mut leaders = BTreeSet::from([start_va]);

    for (i, ins) in insns.iter().enumerate() {
        mh.update((ins.mnemonic() as u16).to_le_bytes());
        nh.update((ins.code() as u16).to_le_bytes());

        for op in 0..ins.op_count() {
            let kind = ins.op_kind(op);
            nh.update([kind as u8]);
            match kind {
                OpKind::Register => nh.update((ins.op_register(op) as u16).to_le_bytes()),
                k if is_near_branch(k) => {
                    let t = ins.near_branch_target();
                    if (start_va..end_va).contains(&t) {
                        nh.update(b"i");
                        nh.update(((t - start_va) as u32).to_le_bytes());
                        leaders.insert(t);
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
    let basic_blocks = leaders.intersection(&starts).count() as u32;

    FunctionFeatures {
        rva: Rva(range.start as u64),
        size: range.end - range.start,
        name: None,
        name_source: None,
        normalized_hash: (!insns.is_empty()).then(|| short_hash(nh, "nh")),
        mnemonic_hash: (!insns.is_empty()).then(|| short_hash(mh, "mh")),
        basic_blocks: Some(basic_blocks),
        edges: None,
        callees,
        strings: strings.into_iter().collect(),
        constants: constants.into_iter().collect(),
        imports: imports.into_iter().collect(),
        signature: None,
    }
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
        }
    }

    #[test]
    fn rip_relative_targets_are_masked() {
        // lea rcx, [rip+0x0ff9]; ret   vs   lea rcx, [rip+0x1ff9]; ret  (same code, data moved)
        let a = [0x48, 0x8d, 0x0d, 0xf9, 0x0f, 0x00, 0x00, 0xc3];
        let b = [0x48, 0x8d, 0x0d, 0xf9, 0x1f, 0x00, 0x00, 0xc3];
        let fa = features(&image(&a, &[]), range(0x1000, 0x1008));
        let fb = features(&image(&b, &[]), range(0x1000, 0x1008));
        assert_eq!(fa.normalized_hash, fb.normalized_hash);
    }

    #[test]
    fn different_immediates_change_the_hash() {
        // add eax, 5; ret   vs   add eax, 6; ret
        let fa = features(
            &image(&[0x83, 0xc0, 0x05, 0xc3], &[]),
            range(0x1000, 0x1004),
        );
        let fb = features(
            &image(&[0x83, 0xc0, 0x06, 0xc3], &[]),
            range(0x1000, 0x1004),
        );
        assert_ne!(fa.normalized_hash, fb.normalized_hash);
        assert_eq!(fa.mnemonic_hash, fb.mnemonic_hash, "same mnemonics");
    }

    #[test]
    fn different_struct_offsets_change_the_hash() {
        // mov eax, [rcx+4]; ret   vs   mov eax, [rcx+8]; ret  (fixture scenario S5)
        let fa = features(
            &image(&[0x8b, 0x41, 0x04, 0xc3], &[]),
            range(0x1000, 0x1004),
        );
        let fb = features(
            &image(&[0x8b, 0x41, 0x08, 0xc3], &[]),
            range(0x1000, 0x1004),
        );
        assert_ne!(fa.normalized_hash, fb.normalized_hash);
    }

    #[test]
    fn collects_string_references() {
        // lea rcx, [rip+0x0ff9] → 0x1007 + 0x0ff9 = 0x2000; ret
        let code = [0x48, 0x8d, 0x0d, 0xf9, 0x0f, 0x00, 0x00, 0xc3];
        let f = features(&image(&code, b"pb-config.ini\0"), range(0x1000, 0x1008));
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
        let caller = features(&img, found[0]);
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
        }];

        let starts: Vec<u32> = discover(&img).iter().map(|r| r.start).collect();
        assert_eq!(starts, vec![0x1000, 0x1010]);
    }
}
