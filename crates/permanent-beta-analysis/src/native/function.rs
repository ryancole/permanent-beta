//! Function discovery and per-function features.
//!
//! Discovery: x64 `.pdata` lists every function that needs unwind info, but MSVC emits none for leaf functions
//! that don't touch the stack, which is common at /O2. So starts are seeded from `.pdata`, the entry point,
//! exports and code pointers stored in data (base relocations: function tables, callbacks in initialized
//! structs), then extended to a fixpoint with direct call/jump targets and RIP-relative `lea` operands (an
//! address taken, e.g. a callback) that land in executable code outside any known function, plus the destructor
//! and copy constructors a C++ throw site's ThrowInfo names (`thrown_type_functions`). A function without
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
//!
//! x86 (32-bit) differs in three ways, handled where they matter. There's no `.pdata`, so every function's
//! bounds come from discovery (the next known start, padding). Data and imports are reached through absolute
//! operands (`call [__imp_f]`, `push offset str`, `mov eax, [g]`), not RIP-relative ones: an absolute address
//! inside the image counts where x64 counts a RIP-relative one ([`absolute_address`]), and an immediate that is
//! a relocated address is a reference too. And arguments are on the stack (or in ecx/edx for `__thiscall` and
//! `__fastcall`): see `super::x86_args`.

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
    let mut decoder = Decoder::with_ip(
        image.bitness(),
        bytes,
        image.base + start as u64,
        DecoderOptions::NONE,
    );
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

/// The address in the image a memory operand names directly, if it does: RIP-relative on x64; on x86, the
/// displacement of an operand with no base or index register (`[g]`, `call [__imp_f]`) when it's an address in
/// the image. Indexed tables (`[table + ecx*4]`) aren't: x64 reaches the same tables through a `lea` first.
fn absolute_address(image: &Image, ins: &Instruction) -> Option<u64> {
    if ins.is_ip_rel_memory_operand() {
        return Some(ins.ip_rel_memory_address());
    }
    let memory = (0..ins.op_count()).any(|op| ins.op_kind(op) == OpKind::Memory);
    let address = u64::from(ins.memory_displacement32());
    (image.x86
        && memory
        && ins.memory_base() == Register::None
        && ins.memory_index() == Register::None
        && image.contains_va(address))
    .then_some(address)
}

/// x86: each immediate operand of `ins` that is a relocated address inside the image (`push offset f`, `mov
/// eax, offset s`). Constants that only look like addresses are left out when the image has relocations.
fn address_immediates(image: &Image, ins: &Instruction) -> Vec<u64> {
    if !image.x86 {
        return Vec::new();
    }
    let rva = (ins.ip() - image.base) as u32;
    (0..ins.op_count())
        .filter(|&op| is_immediate(ins.op_kind(op)))
        .map(|op| ins.immediate(op) & 0xffff_ffff)
        .filter(|&v| image.contains_va(v) && image.relocated(rva, ins.len() as u32))
        .collect()
}

pub(crate) fn is_immediate(kind: OpKind) -> bool {
    matches!(
        kind,
        OpKind::Immediate8
            | OpKind::Immediate8_2nd
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64
    )
}

/// A code address `ins` takes without calling it (a callback): `lea reg, [rip+f]` on x64; on x86 `push offset
/// f`, `mov reg, offset f` or `lea reg, [f]`.
fn taken_address(image: &Image, ins: &Instruction) -> Option<u64> {
    if ins.mnemonic() == Mnemonic::Lea {
        return if image.x86 {
            absolute_address(image, ins)
                .filter(|_| image.relocated((ins.ip() - image.base) as u32, ins.len() as u32))
        } else {
            ins.is_ip_rel_memory_operand()
                .then(|| ins.ip_rel_memory_address())
        };
    }
    address_immediates(image, ins)
        .into_iter()
        .find(|&v| image.va_to_rva(v).is_some_and(|r| image.is_executable(r)))
}

fn is_near_branch(kind: OpKind) -> bool {
    matches!(
        kind,
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
    )
}

/// Find function starts and boundaries.
///
/// On x86, discovery is redone once it has found SEH blocks (`seh_scope_blocks`) it didn't know of: a block taken
/// for a function start has already made its own jumps into starts, so they're found again without it. The set
/// only grows, so this ends.
pub(crate) fn discover(image: &Image) -> Vec<FunctionRange> {
    let mut data = rtc_frame_descriptors(image);
    data.extend(jump_tables_in_code(image));
    data.sort_unstable();
    let mut seh_blocks = BTreeSet::new();
    loop {
        let (ranges, found) = discover_except(image, &seh_blocks, &data);
        if found.is_subset(&seh_blocks) {
            return ranges;
        }
        seh_blocks.extend(found);
    }
}

/// Most variables an `_RTC_framedesc` is taken to describe. **[Guess]**
const MAX_RTC_VARS: u32 = 256;
/// Farthest past its variable records a descriptor's names are taken to be, and longest name. **[Guess]**
const MAX_RTC_NAMES: u32 = 0x1000;
const MAX_RTC_NAME: usize = 256;

/// x86 `/RTCs` (part of `/RTC1`, the Debug default) frame descriptors in code, `[start, end)`, sorted. MSVC puts
/// a function's `_RTC_framedesc` (for `_RTC_CheckStackVars`) in `.text` right after the function's code: a count
/// `n`, a pointer to the `n` variable records that follow it (`{ int offset; int size; char* name; }`), then the
/// names. Decoded as code it's garbage, and a garbage branch out of the function makes a bogus start in the next
/// one. Found from the relocated pointers in code (the function's `mov edx, offset desc`) and taken only in that
/// exact shape: the records pointer is the descriptor's own address + 8, each size is positive, and each name a
/// short printable string just past the records.
fn rtc_frame_descriptors(image: &Image) -> Vec<(u32, u32)> {
    if !image.x86 {
        return Vec::new();
    }
    let u32_at = |rva: u32| {
        image
            .bytes(rva, 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    let descriptor = |t: u32| -> Option<(u32, u32)> {
        let n = u32_at(t)?;
        if n == 0 || n > MAX_RTC_VARS || u64::from(u32_at(t + 4)?) != image.base + u64::from(t + 8)
        {
            return None;
        }
        let names = t + 8 + 12 * n;
        let mut end = names;
        for i in 0..n {
            let record = t + 8 + 12 * i;
            let size = u32_at(record + 4)? as i32;
            let name = image.va_to_rva(u64::from(u32_at(record + 8)?))?;
            if size <= 0 || !(names..names + MAX_RTC_NAMES).contains(&name) {
                return None;
            }
            let bytes = image.bytes_from(name)?;
            let len = bytes.iter().take(MAX_RTC_NAME).position(|&b| b == 0)?;
            if len == 0 || !bytes[..len].iter().all(|b| b.is_ascii_graphic()) {
                return None;
            }
            end = end.max(name + len as u32 + 1);
        }
        Some((t, end))
    };
    let mut found: Vec<(u32, u32)> = image
        .code_relocs
        .iter()
        .filter_map(|&slot| image.va_to_rva(u64::from(u32_at(slot)?)))
        .filter(|&t| image.is_executable(t))
        .collect::<BTreeSet<u32>>()
        .into_iter()
        .filter_map(descriptor)
        .collect();
    found.sort_unstable();
    found
}

/// Fewest consecutive relocated code pointers in code taken for a jump table. **[Guess]**: MSVC builds a table
/// for a switch of four cases or more; no instruction has two address operands 4 bytes apart that both point into
/// code.
const MIN_JUMP_TABLE_SLOTS: usize = 3;

/// x86 switch jump tables in code, `[start, end)`, sorted: MSVC puts a function's tables (`jmp [eax*4 + table]`)
/// in `.text` after its code, so without `.pdata` they'd be decoded as its code, and a garbage branch out of the
/// function makes a bogus start in the next one. A table is a run of at least [`MIN_JUMP_TABLE_SLOTS`] consecutive
/// relocated 4-byte slots in code, each pointing into code. A sparse switch's byte index table follows it; the
/// function ending at the table (`ranges`) keeps that out too.
fn jump_tables_in_code(image: &Image) -> Vec<(u32, u32)> {
    if !image.x86 {
        return Vec::new();
    }
    let points_into_code = |slot: u32| {
        image
            .bytes(slot, 4)
            .map(|b| u64::from(u32::from_le_bytes([b[0], b[1], b[2], b[3]])))
            .and_then(|va| image.va_to_rva(va))
            .is_some_and(|t| image.is_executable(t))
    };
    let mut tables = Vec::new();
    let mut run: Vec<u32> = Vec::new();
    for &slot in &image.code_relocs {
        let continues = run.last().is_some_and(|&last| slot == last + 4);
        if !continues {
            if run.len() >= MIN_JUMP_TABLE_SLOTS {
                tables.push((run[0], run[run.len() - 1] + 4));
            }
            run.clear();
        }
        if points_into_code(slot) {
            run.push(slot);
        } else {
            if run.len() >= MIN_JUMP_TABLE_SLOTS {
                tables.push((run[0], run[run.len() - 1] + 4));
            }
            run.clear();
        }
    }
    if run.len() >= MIN_JUMP_TABLE_SLOTS {
        tables.push((run[0], run[run.len() - 1] + 4));
    }
    tables
}

/// Discovery that never takes the addresses in `seh_blocks` for function starts, with `data` (RTC frame
/// descriptors, jump tables) never decoded as code. Also returns every SEH block found on the way.
fn discover_except(
    image: &Image,
    seh_blocks: &BTreeSet<u32>,
    data: &[(u32, u32)],
) -> (Vec<FunctionRange>, BTreeSet<u32>) {
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
    // x86: the `__except` filters and handlers an SEH scope table names are blocks of the function that pushes
    // the table, not functions, though the table's relocated pointers to them make them look like starts.
    starts.retain(|s| !seh_blocks.contains(s));
    let mut seh_found: BTreeSet<u32> = BTreeSet::new();
    // x86 has no unwind data to say which blocks are one function. Blocks a function reaches only by a
    // conditional jump out of its range (PGO moves cold blocks far from the hot ones) are boundaries here and
    // are given to their function at the end (`cold_block_owners`).
    let mut cold: BTreeSet<u32> = BTreeSet::new();

    loop {
        let mut found = Vec::new();
        let mut found_cold = Vec::new();
        let pieces: BTreeSet<u32> = starts.union(&cold).copied().collect();
        let ranges = ranges(image, &pieces, data, &BTreeMap::new());
        let fallen_into = if image.x86 {
            fallen_into(image, &ranges)
        } else {
            BTreeSet::new()
        };
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
            // A throw site's ThrowInfo: x64 passes it in rdx (the last `lea rdx, [rip+x]`); x86 pushes it (one of
            // the addresses pushed since the last call, each tried).
            let mut throw_info: Vec<u32> = Vec::new();
            for ins in decode(image, seg_start, seg_end) {
                if !image.x86
                    && ins.mnemonic() == Mnemonic::Lea
                    && ins.op0_register() == Register::RDX
                    && ins.is_ip_rel_memory_operand()
                {
                    throw_info = image
                        .va_to_rva(ins.ip_rel_memory_address())
                        .into_iter()
                        .collect();
                } else if image.x86 && ins.mnemonic() == Mnemonic::Push {
                    for pushed in address_immediates(image, &ins)
                        .into_iter()
                        .filter_map(|v| image.va_to_rva(v))
                    {
                        throw_info.push(pushed);
                        seh_found.extend(seh_scope_blocks(image, pushed, seg_start));
                    }
                } else if ins.flow_control() == FlowControl::Call
                    || ins.flow_control() == FlowControl::IndirectCall
                {
                    let throws = if let Some(slot) = absolute_address(image, &ins) {
                        is_throw_slot(image, slot)
                    } else {
                        // `call _CxxThrowException`: the import's `jmp [__imp__CxxThrowException]` stub.
                        (0..ins.op_count()).any(|op| is_near_branch(ins.op_kind(op)))
                            && image
                                .va_to_rva(ins.near_branch_target())
                                .and_then(|t| decode(image, t, t + 6).first().copied())
                                .is_some_and(|j| {
                                    j.flow_control() == FlowControl::IndirectBranch
                                        && absolute_address(image, &j)
                                            .is_some_and(|slot| is_throw_slot(image, slot))
                                })
                    };
                    if throws {
                        let named = throw_info
                            .iter()
                            .rev()
                            .find_map(|&ti| thrown_type_functions(image, ti));
                        for t in named.into_iter().flatten() {
                            if !starts.contains(&t) && !inside_pdata(t) {
                                found.push(t);
                            }
                        }
                    }
                    throw_info.clear();
                }
                let is_branch = (0..ins.op_count()).any(|op| is_near_branch(ins.op_kind(op)));
                let (t, is_call) = if is_branch {
                    (
                        ins.near_branch_target(),
                        ins.flow_control() == FlowControl::Call,
                    )
                } else if let Some(t) = taken_address(image, &ins) {
                    // Address taken: treated like a jump (a new start only outside the current range).
                    (t, false)
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
                    if !image.x86 || is_call || !is_branch {
                        found.push(t);
                    } else if cold.contains(&t) || fallen_into.contains(&t) {
                        // A jump into the middle of straight-line code (a cold block returning to its
                        // function's hot code) enters a function, it doesn't start one.
                    } else if ins.flow_control() == FlowControl::ConditionalBranch {
                        // MSVC doesn't tail-call conditionally: a block of the jumping function.
                        found_cold.push(t);
                    } else {
                        found.push(t);
                    }
                }
            }
        }
        let is_code = |f: &u32| {
            !seh_blocks.contains(f)
                // The descriptor's own address, taken by its function (`mov edx, offset desc`), isn't code.
                && !data.iter().any(|&(s, e)| s <= *f && *f < e)
        };
        found.retain(is_code);
        found_cold.retain(is_code);
        if found.is_empty() && found_cold.is_empty() {
            // Nothing reaches the rest: look for code that starts after padding (dead code, design §4.4).
            found = padding_starts(image, &ranges, &pieces, data);
            found.retain(|f| !seh_blocks.contains(f));
            if found.is_empty() {
                if cold.is_empty() {
                    return (ranges, seh_found);
                }
                let owners = cold_block_owners(image, &ranges, &starts);
                starts.extend(cold.iter().filter(|c| !owners.contains_key(c)));
                return (self::ranges(image, &starts, data, &owners), seh_found);
            }
        }
        starts.extend(found);
        cold.extend(found_cold);
        // A call wins: a block something calls is a function.
        cold.retain(|c| !starts.contains(c));
    }
}

/// x86: the addresses the instruction before them runs into. `ranges` are the pieces known so far, each decoded
/// from its start; an instruction after a return, a jump or `int3` isn't run into.
fn fallen_into(image: &Image, ranges: &[FunctionRange]) -> BTreeSet<u32> {
    let mut out = BTreeSet::new();
    for r in ranges.iter().filter(|r| !r.from_pdata) {
        let mut runs_on = false;
        for ins in decode(image, r.start, r.end) {
            if runs_on {
                out.insert((ins.ip() - image.base) as u32);
            }
            runs_on = ins.mnemonic() != Mnemonic::Int3
                && !matches!(
                    ins.flow_control(),
                    FlowControl::Return
                        | FlowControl::UnconditionalBranch
                        | FlowControl::IndirectBranch
                        | FlowControl::Interrupt
                        | FlowControl::Exception
                );
        }
    }
    out
}

/// x86: which function each cold block belongs to, from the direct jumps into it. `pieces` are the ranges of
/// functions (`starts`) and cold blocks alike. A block belongs to the one function whose code (its own range or
/// blocks already given to it) jumps there; a block two functions jump to, or none, gets no owner and is left a
/// function, as before.
fn cold_block_owners(
    image: &Image,
    pieces: &[FunctionRange],
    starts: &BTreeSet<u32>,
) -> BTreeMap<u32, u32> {
    let piece_starts: BTreeSet<u32> = pieces.iter().map(|r| r.start).collect();
    let piece_of = |t: u32| piece_starts.contains(&t).then_some(t);
    // Cold block -> the pieces that jump to it.
    let mut referrers: BTreeMap<u32, BTreeSet<u32>> = pieces
        .iter()
        .filter(|r| !starts.contains(&r.start))
        .map(|r| (r.start, BTreeSet::new()))
        .collect();
    for r in pieces {
        for ins in decode(image, r.start, r.end) {
            let jumps = matches!(
                ins.flow_control(),
                FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch
            ) && (0..ins.op_count()).any(|op| is_near_branch(ins.op_kind(op)));
            if !jumps {
                continue;
            }
            let Some(t) = image.va_to_rva(ins.near_branch_target()).and_then(piece_of) else {
                continue;
            };
            if t != r.start {
                if let Some(from) = referrers.get_mut(&t) {
                    from.insert(r.start);
                }
            }
        }
    }
    // Resolve through blocks that are reached from other cold blocks. `None`: no single owner.
    let mut owner: BTreeMap<u32, Option<u32>> = BTreeMap::new();
    loop {
        let mut changed = false;
        for (&block, from) in &referrers {
            if owner.contains_key(&block) {
                continue;
            }
            let mut roots = BTreeSet::new();
            let mut pending = false;
            for p in from {
                if starts.contains(p) {
                    roots.insert(Some(*p));
                } else {
                    match owner.get(p) {
                        Some(o) => {
                            roots.insert(*o);
                        }
                        None => pending = true,
                    }
                }
            }
            let decided = if roots.len() > 1 || roots.contains(&None) {
                Some(None)
            } else if pending {
                None
            } else {
                Some(roots.into_iter().next().flatten())
            };
            if let Some(d) = decided {
                owner.insert(block, d);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    // Blocks that only reach each other (pending forever) have no owner.
    owner
        .into_iter()
        .filter_map(|(block, o)| Some((block, o?)))
        .collect()
}

/// Farthest an SEH block is taken to be from the start of its function. **[Guess]**
const MAX_SEH_BLOCK_DISTANCE: u32 = 0x10000;

/// x86 structured exception handling: the filter and handler blocks of the scope table at `table`, if it is one,
/// pushed by the function starting at `owner`. MSVC's `__try`/`__except` prologue pushes the function's scope
/// table (`push offset table; ... call __SEH_prolog4`, or `push offset __except_handler3`), whose records point
/// at the filter expression and handler blocks laid out inside the function.
///
/// Two layouts: EH4 (Visual C++ 2005 on, `__except_handler4`) starts with four 32-bit cookie offsets, then the
/// records; EH3 (older) is the records alone. A record is `{ enclosing level, filter, handler }`: the outermost's
/// level is -2 (EH4) or -1 (EH3), an inner one's the index of a record before it; the filter is 0 for a
/// `__finally`. Read only while every record is plausible: in read-only data, its blocks in code after `owner`
/// and within [`MAX_SEH_BLOCK_DISTANCE`] of it. Empty unless at least one record is.
fn seh_scope_blocks(image: &Image, table: u32, owner: u32) -> Vec<u32> {
    if !image.x86 || image.is_executable(table) || image.is_writable(table) {
        return Vec::new();
    }
    let u32_at = |rva: u32| {
        image
            .bytes(rva, 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    let block = |va: u32| {
        image
            .va_to_rva(u64::from(va))
            .filter(|&r| image.is_executable(r) && r > owner && r - owner < MAX_SEH_BLOCK_DISTANCE)
    };
    let records = |first: u32, outermost: u32| -> Vec<u32> {
        let mut out = Vec::new();
        for i in 0..64u32 {
            let at = first + 12 * i;
            let (Some(level), Some(filter), Some(handler)) =
                (u32_at(at), u32_at(at + 4), u32_at(at + 8))
            else {
                break;
            };
            let level_ok = level == outermost || level < i;
            let filter_ok = filter == 0 || block(filter).is_some();
            let Some(handler) = block(handler).filter(|_| level_ok && filter_ok) else {
                break;
            };
            // Each record's pointers are relocated: a table in a /FIXED image has none to check.
            if image.has_relocs && !(image.code_pointer_slots.iter().any(|&(s, _)| s == at + 8)) {
                break;
            }
            out.push(handler);
            out.extend(block(filter));
        }
        out
    };
    // EH4: GSCookieOffset is -2 (no GS cookie) or a frame offset below ebp; EHCookieOffset is a frame offset.
    let frame_offset = |v: u32| (v as i32) < 0 && (v as i32) > -0x10000;
    if let (Some(gs), Some(eh)) = (u32_at(table), u32_at(table + 8))
        && (gs == 0xffff_fffe || frame_offset(gs))
        && frame_offset(eh)
    {
        let found = records(table + 16, 0xffff_fffe);
        if !found.is_empty() {
            return found;
        }
    }
    records(table, 0xffff_ffff)
}

/// An import address table slot for `_CxxThrowException` (VCRUNTIME140.dll and older runtimes).
fn is_throw_slot(image: &Image, va: u64) -> bool {
    image
        .va_to_rva(va)
        .and_then(|slot| image.iat.get(&slot))
        .is_some_and(|name| name.rsplit('!').next() == Some("_CxxThrowException"))
}

/// Most catchable types a ThrowInfo is taken to list (the thrown class and its bases). **[Guess]**
const MAX_CATCHABLE_TYPES: u32 = 64;

/// The functions a C++ throw site names (design §4.4): `_CxxThrowException(object, &ThrowInfo)` passes a
/// ThrowInfo whose image-relative RVAs name the thrown type's destructor and, through its CatchableTypeArray,
/// each catchable type's copy constructor. Nothing else may reference them (a small destructor inlined
/// everywhere else, laid out without `int3` padding before it), and image-relative RVAs aren't relocated
/// pointers, so without this they're missed and taken into the function before them.
///
/// Layout (`ehdata.h`): ThrowInfo `{ attributes, pmfnUnwind, pForwardCompat, pCatchableTypeArray }`;
/// CatchableTypeArray `{ nCatchableTypes, arrayOfCatchableTypes[] }`; CatchableType `{ properties, pType,
/// thisDisplacement (3 ints), sizeOrOffset, copyFunction }`, all 32-bit, so the offsets are the same on x64 and
/// x86. On x64 the references are image-relative RVAs; on x86 they're addresses (relocated pointers), read here
/// as RVAs. `None` unless every field is plausible: structures in read-only data, flags within their defined
/// bits, functions in code or 0.
fn thrown_type_functions(image: &Image, ti: u32) -> Option<Vec<u32>> {
    let raw = |rva: u32| {
        image
            .bytes(rva, 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    let u32_at = raw;
    // A reference field: an RVA (x64), or an address in the image (x86); 0 is none.
    let ref_at = |rva: u32| -> Option<u32> {
        let v = raw(rva)?;
        if !image.x86 || v == 0 {
            Some(v)
        } else {
            image.va_to_rva(u64::from(v))
        }
    };
    let read_only = |rva: u32| {
        rva != 0
            && image.bytes(rva, 4).is_some()
            && !image.is_executable(rva)
            && !image.is_writable(rva)
    };
    let code_or_none = |rva: u32| rva == 0 || image.is_executable(rva);
    if !read_only(ti) {
        return None;
    }
    let (attributes, unwind, compat, array) = (
        u32_at(ti)?,
        ref_at(ti + 4)?,
        ref_at(ti + 8)?,
        ref_at(ti + 12)?,
    );
    if attributes > 0x1f || !code_or_none(unwind) || !code_or_none(compat) || !read_only(array) {
        return None;
    }
    let count = u32_at(array)?;
    if count == 0 || count > MAX_CATCHABLE_TYPES {
        return None;
    }
    let mut out: Vec<u32> = [unwind, compat].into_iter().filter(|&r| r != 0).collect();
    for i in 0..count {
        let ct = ref_at(array + 4 + 4 * i)?;
        if !read_only(ct) {
            return None;
        }
        let (properties, type_descriptor, copy) = (u32_at(ct)?, ref_at(ct + 4)?, ref_at(ct + 24)?);
        let in_data =
            image.bytes(type_descriptor, 1).is_some() && !image.is_executable(type_descriptor);
        if properties > 0x1f || !in_data || !code_or_none(copy) {
            return None;
        }
        if copy != 0 {
            out.push(copy);
        }
    }
    out.sort_unstable();
    out.dedup();
    Some(out)
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
fn padding_starts(
    image: &Image,
    ranges: &[FunctionRange],
    starts: &BTreeSet<u32>,
    data: &[(u32, u32)],
) -> Vec<u32> {
    let mut covered: Vec<(u32, u32)> = ranges.iter().flat_map(|r| r.segments()).collect();
    covered.extend(image.pdata.iter().map(|r| (r.begin, r.end)));
    // Data in code (RTC frame descriptors) isn't a gap: the padding after it is.
    covered.extend(data.iter().copied());
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
fn ranges(
    image: &Image,
    starts: &BTreeSet<u32>,
    data: &[(u32, u32)],
    blocks: &BTreeMap<u32, u32>,
) -> Vec<FunctionRange> {
    let mut boundaries: BTreeSet<u32> = starts.clone();
    boundaries.extend(image.pdata.iter().map(|r| r.begin));
    boundaries.extend(blocks.keys());
    // Where the code starting at `start` ends, for code without `.pdata`.
    let end_of = |start: u32| -> Option<u32> {
        let section_end = image.section_end(start)?;
        let next = boundaries
            .range(start + 1..)
            .next()
            .copied()
            .unwrap_or(section_end);
        let mut end = next.min(section_end);
        // Data after the function's code (an RTC frame descriptor, a jump table) ends it.
        if let Some(&(d, _)) = data.iter().find(|&&(d, _)| start < d && d < end) {
            end = d;
        }
        while end > start + 1 && image.bytes(end - 1, 1) == Some(&[0xcc]) {
            end -= 1;
        }
        // MSVC follows a call that doesn't return with an `int3` of the function's own; on x86, where every
        // function ends this way, keep it. (On x64 a function that calls has `.pdata`, so exact bounds.)
        if image.x86
            && end < next.min(section_end)
            && decode(image, start, end).last().is_some_and(|i| {
                i.next_ip() == image.base + u64::from(end)
                    && matches!(
                        i.flow_control(),
                        FlowControl::Call | FlowControl::IndirectCall
                    )
            })
        {
            end += 1;
        }
        Some(end)
    };
    let fragments_of = |start: u32| -> Vec<(u32, u32)> {
        let mut f: Vec<(u32, u32)> = image
            .pdata
            .iter()
            .filter(|r| r.chained && r.parent == Some(start) && image.is_executable(r.begin))
            .map(|r| (r.begin, r.end))
            .collect();
        f.extend(
            blocks
                .iter()
                .filter(|&(_, &owner)| owner == start)
                .filter_map(|(&b, _)| Some((b, end_of(b)?))),
        );
        f.sort_unstable();
        f
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
            Some(FunctionRange {
                start,
                end: end_of(start)?,
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

/// Tables of code pointers in data (vtables, function tables): runs of consecutive pointer slots, each a
/// relocated pointer to the start of a function in `ranges`. A slot pointing anywhere else (RTTI locator, a
/// string, the middle of a function) ends the run.
pub(crate) fn code_tables(image: &Image, ranges: &[FunctionRange]) -> Vec<CodeTable> {
    let starts: BTreeSet<u32> = ranges.iter().map(|r| r.start).collect();
    let stride = image.pointer_size();
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
        let follows = run.last().is_some_and(|&(prev, _)| prev + stride == slot);
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
                    if let Some(address) = absolute_address(image, ins) {
                        nh.update(b"r");
                        if let Some(rva) = image.va_to_rva(address) {
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
                                && internal(address).is_none()
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
                    } else if image.x86 && image.contains_va(v & 0xffff_ffff) {
                        // `push offset s` on x86: an address (sign-extended by the decoder), masked the same way.
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

        // x86 passes addresses as immediates (`push offset s`): the same references a RIP-relative `lea` gives
        // on x64.
        for v in address_immediates(image, ins) {
            let Some(rva) = image.va_to_rva(v) else {
                continue;
            };
            if let Some(s) = image.string_literal(rva) {
                strings.insert(s);
            } else if image.is_writable(rva) {
                data_refs.insert(Rva(u64::from(rva)));
            } else if image.is_executable(rva) && internal(v).is_none() {
                code_refs.insert(Rva(u64::from(rva)));
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
    } else if image.x86 {
        // One class per register argument (ecx, edx): the slots before the stack words.
        let regs = super::x86_args::register_args(&insns);
        (
            super::x86_args::inferred_args(&insns),
            vec![ArgClass::Integer; usize::from(regs)],
        )
    } else {
        inferred_args(&insns)
    };
    let accesses = if image.x86 {
        super::x86_args::arg_accesses(&insns)
    } else {
        arg_accesses(&insns)
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
        arg_accesses: accesses,
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

    /// A throw site and the ThrowInfo it passes, for the throw-info tests. Code at 0x1000:
    ///   0x1000: lea rdx, [0x2010]; call 0x1020; ret; int3 padding
    ///   0x1020: jmp [0x2000] (the import stub; the slot is `import`)
    ///   0x1028: mov rax, rcx; ret   (the destructor: 4-byte aligned, no int3 before it)
    ///   0x102c: mov rax, rcx; ret   (the copy constructor, right after it)
    /// Read-only data at 0x2000: the IAT slot, ThrowInfo at 0x2010 (`attributes`, unwind 0x1028), its
    /// CatchableTypeArray at 0x2020 and one CatchableType at 0x2030 (copy constructor 0x102c). The type
    /// descriptor is in writable data at 0x3000.
    fn throw_image(import: &str, attributes: u32) -> Image {
        use crate::native::image::Section;
        let mut code = vec![0x48, 0x8d, 0x15, 0x09, 0x10, 0x00, 0x00]; // lea rdx, [rip+0x1009] = 0x2010
        code.extend([0xe8, 0x14, 0x00, 0x00, 0x00, 0xc3]); // call 0x1020; ret
        code.resize(0x20, 0xcc);
        code.extend([0xff, 0x25, 0xda, 0x0f, 0x00, 0x00]); // jmp [rip+0xfda] = [0x2000]
        code.extend([0xcc, 0xcc]);
        code.extend([0x48, 0x89, 0xc8, 0xc3, 0x48, 0x89, 0xc8, 0xc3]);
        let mut rdata = vec![0u8; 0x50];
        let mut put = |at: usize, v: u32| rdata[at..at + 4].copy_from_slice(&v.to_le_bytes());
        put(0x10, attributes);
        put(0x14, 0x1028); // pmfnUnwind
        put(0x1c, 0x2020); // pCatchableTypeArray
        put(0x20, 1); // nCatchableTypes
        put(0x24, 0x2030);
        put(0x34, 0x3000); // pType
        put(0x3c, 0xffff_ffff); // thisDisplacement.pdisp = -1
        put(0x44, 8); // sizeOrOffset
        put(0x48, 0x102c); // copyFunction
        let section = |name: &str, rva, data: Vec<u8>, executable, writable| Section {
            name: name.into(),
            rva,
            virtual_size: 0x1000,
            data,
            executable,
            writable,
        };
        let mut img = Image {
            base: 0x1_4000_0000,
            size_of_image: 0x4000,
            sections: vec![
                section(".text", 0x1000, code, true, false),
                section(".rdata", 0x2000, rdata, false, false),
                section(".data", 0x3000, vec![0u8; 0x20], false, true),
            ],
            entry: Some(0x1000),
            ..Default::default()
        };
        img.iat.insert(0x2000, import.into());
        img
    }

    #[test]
    fn a_throw_sites_destructor_and_copy_constructor_are_functions() {
        let img = throw_image("VCRUNTIME140.dll!_CxxThrowException", 0);
        let starts: Vec<u32> = discover(&img).iter().map(|r| r.start).collect();
        assert_eq!(starts, vec![0x1000, 0x1020, 0x1028, 0x102c]);
    }

    #[test]
    fn a_throw_info_is_read_only_when_everything_in_it_is_plausible() {
        // Negative: the same lea and call, but the import is another function: rdx isn't a ThrowInfo, and the
        // destructor and copy constructor stay inside the stub's range.
        let img = throw_image("KERNEL32.dll!RaiseException", 0);
        let starts: Vec<u32> = discover(&img).iter().map(|r| r.start).collect();
        assert_eq!(starts, vec![0x1000, 0x1020]);
        // Negative: attribute bits ThrowInfo doesn't define: not taken for one, nothing read from it.
        let img = throw_image("VCRUNTIME140.dll!_CxxThrowException", 0x100);
        let starts: Vec<u32> = discover(&img).iter().map(|r| r.start).collect();
        assert_eq!(starts, vec![0x1000, 0x1020]);
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

    // x86 (32-bit) images.

    const X86_BASE: u32 = 0x40_0000;

    fn va(rva: u32) -> [u8; 4] {
        (X86_BASE + rva).to_le_bytes()
    }

    /// An x86 image based at 0x400000: `.text` at 0x1000, read-only `.rdata` at 0x2000, writable `.data` at
    /// 0x3000. Without relocations, so every absolute operand counts as an address (`Image::relocated`).
    fn x86_image(code: &[u8], rdata: &[u8], data: &[u8]) -> Image {
        use crate::native::image::Section;
        let section = |name: &str, rva, data: &[u8], executable, writable| Section {
            name: name.into(),
            rva,
            virtual_size: 0x1000,
            data: data.to_vec(),
            executable,
            writable,
        };
        Image {
            x86: true,
            base: u64::from(X86_BASE),
            size_of_image: 0x4000,
            sections: vec![
                section(".text", 0x1000, code, true, false),
                section(".rdata", 0x2000, rdata, false, false),
                section(".data", 0x3000, data, false, true),
            ],
            entry: Some(0x1000),
            ..Default::default()
        }
    }

    /// x86: a function at 0x1000 that passes an RTC frame descriptor (at 0x1008) in edx, `records` as the
    /// descriptor's records pointer, then `int3` padding and a function at 0x1030.
    fn rtc_image(records: u32) -> Image {
        let mut code = vec![0xba];
        code.extend(va(0x1008)); // mov edx, offset desc
        code.extend([0xc3, 0x66, 0x90]); // ret; nop
        code.extend(1u32.to_le_bytes()); // desc: one variable
        code.extend(va(records));
        code.extend((-8i32).to_le_bytes()); // [ebp-8]
        code.extend(4u32.to_le_bytes()); // 4 bytes
        code.extend(va(0x101c)); // named
        code.extend(b"buf\0");
        code.resize(0x30, 0xcc);
        code.push(0xc3); // the next function: ret
        code.resize(0x1000, 0xcc); // the section's file data, padded
        let mut img = x86_image(&code, &[], &[]);
        img.has_relocs = true;
        img.code_relocs = [0x1001, 0x100c, 0x1018].into_iter().collect();
        img
    }

    #[test]
    fn an_rtc_frame_descriptor_after_x86_code_is_data() {
        let img = rtc_image(0x1010);
        assert_eq!(rtc_frame_descriptors(&img), vec![(0x1008, 0x1020)]);
        let ranges = discover(&img);
        let f = ranges
            .iter()
            .find(|r| r.start == 0x1000)
            .expect("the function");
        assert_eq!(f.end, 0x1008, "the descriptor isn't the function's code");
        assert!(ranges.iter().any(|r| r.start == 0x1030), "{ranges:x?}");
        assert_eq!(ranges.len(), 2, "{ranges:x?}");
        assert!(!ranges.iter().any(|r| (0x1008..0x1020).contains(&r.start)));
        // Negative: a records pointer that isn't the descriptor's own address + 8 isn't a descriptor, and the
        // bytes stay the function's.
        let img = rtc_image(0x1014);
        assert!(rtc_frame_descriptors(&img).is_empty());
        let ranges = discover(&img);
        assert!(
            ranges
                .iter()
                .find(|r| r.start == 0x1000)
                .expect("the function")
                .end
                > 0x1008
        );
    }

    #[test]
    fn an_x86_jump_table_after_the_code_is_data() {
        // 0x1000: cmp eax, 2; ja +7; jmp [eax*4 + 0x1018]; ret; (pad) 0x1018: table of 3 code pointers whose bytes
        // decode as a branch out of the function (0x1018 + .. ); 0x1030: the next function: ret.
        let mut code = vec![0x83, 0xf8, 0x02, 0x77, 0x07, 0xff, 0x24, 0x85];
        code.extend(va(0x1018));
        code.push(0xc3);
        code.resize(0x18, 0x90);
        for t in [0x100d, 0x100d, 0x1035] {
            code.extend(va(t));
        }
        code.resize(0x30, 0xcc);
        code.push(0xc3);
        code.resize(0x1000, 0xcc);
        let image = |code: &[u8], relocs: &[u32]| {
            let mut img = x86_image(code, &[], &[]);
            img.has_relocs = true;
            img.code_relocs = relocs.iter().copied().collect();
            img
        };
        let img = image(&code, &[0x1008, 0x1018, 0x101c, 0x1020]);
        assert_eq!(jump_tables_in_code(&img), vec![(0x1018, 0x1024)]);
        let ranges = discover(&img);
        assert_eq!(
            ranges.iter().find(|r| r.start == 0x1000).map(|r| r.end),
            Some(0x1018)
        );
        assert!(ranges.iter().any(|r| r.start == 0x1030), "{ranges:x?}");
        // Negative: two relocated slots aren't a table (an instruction can have two address operands).
        let img = image(&code, &[0x1008, 0x1018, 0x101c]);
        assert!(jump_tables_in_code(&img).is_empty());
        // Negative: nor are slots whose values don't all point into code.
        code[0x1c..0x20].copy_from_slice(&va(0x3000));
        let img = image(&code, &[0x1008, 0x1018, 0x101c, 0x1020]);
        assert!(jump_tables_in_code(&img).is_empty());
    }

    #[test]
    fn x86_import_calls_hash_by_imported_name() {
        // call dword ptr [slot]; ret
        let call = |slot: u32| {
            let mut c = vec![0xff, 0x15];
            c.extend(va(slot));
            c.push(0xc3);
            c
        };
        let f = |slot: u32, name: &str| {
            let mut img = x86_image(&call(slot), &[0; 0x10], &[]);
            img.iat.insert(slot, name.into());
            features(&img, &range(0x1000, 0x1007))
        };
        let sleep = f(0x2000, "k.dll!Sleep");
        assert_eq!(sleep.imports, vec!["k.dll!Sleep".to_string()]);
        // The IAT moved: same hash.
        assert_eq!(
            sleep.normalized_hash,
            f(0x2004, "k.dll!Sleep").normalized_hash
        );
        // Negative: the same code calling another import.
        assert_ne!(
            sleep.normalized_hash,
            f(0x2000, "k.dll!Beep").normalized_hash
        );
    }

    /// push offset 0x402010 (a string); push offset 0x403000 (a global); push offset 0x401020 (a function);
    /// add esp, 12; ret; ... 0x1020: ret. The string is at 0x2010 + `string_shift`.
    fn pushes_addresses(string_shift: u32) -> Image {
        let mut code = vec![0x68];
        code.extend(va(0x2010 + string_shift));
        code.push(0x68);
        code.extend(va(0x3000));
        code.push(0x68);
        code.extend(va(0x1020));
        code.extend([0x83, 0xc4, 0x0c, 0xc3]);
        code.resize(0x20, 0xcc);
        code.push(0xc3);
        let mut rdata = vec![0u8; 0x10 + string_shift as usize];
        rdata.extend(b"pb-config.ini\0");
        x86_image(&code, &rdata, &[0; 4])
    }

    #[test]
    fn x86_pushed_addresses_are_references() {
        let f = features(&pushes_addresses(0), &range(0x1000, 0x1013));
        assert_eq!(f.strings, vec!["pb-config.ini".to_string()]);
        assert_eq!(f.data_refs, vec![Rva(0x3000)]);
        assert_eq!(f.code_refs, vec![Rva(0x1020)]);
        assert!(f.constants.is_empty(), "addresses aren't constants");
        // The string moved: same hash.
        let moved = features(&pushes_addresses(0x20), &range(0x1000, 0x1013));
        assert_eq!(f.normalized_hash, moved.normalized_hash);
    }

    #[test]
    fn x86_unrelocated_immediates_are_not_references() {
        // Negative: in an image with relocations, an operand no relocation names is a constant that only looks
        // like an address. Still masked (it might be one), but no reference and no function start.
        let mut img = pushes_addresses(0);
        img.has_relocs = true;
        let f = features(&img, &range(0x1000, 0x1013));
        assert!(f.strings.is_empty() && f.data_refs.is_empty() && f.code_refs.is_empty());
        img.has_relocs = false;
        assert_eq!(
            f.normalized_hash,
            features(&img, &range(0x1000, 0x1013)).normalized_hash
        );
    }

    #[test]
    fn x86_callbacks_passed_by_address_are_functions() {
        let img = pushes_addresses(0);
        let starts: Vec<u32> = discover(&img).iter().map(|r| r.start).collect();
        assert!(starts.contains(&0x1020), "{starts:x?}");
        // Negative: the same push, unrelocated in an image with relocations, finds nothing.
        let mut img = img;
        img.has_relocs = true;
        let mut code = img.sections[0].data.clone();
        code[0x1f] = 0x90; // no padding before 0x1020: only the push could make it a start
        img.sections[0].data = code;
        let starts: Vec<u32> = discover(&img).iter().map(|r| r.start).collect();
        assert_eq!(starts, vec![0x1000]);
    }

    /// 0x1000: push offset scope_table (0x402000); xor eax, eax; ret; nop to 0x1010. 0x1010: the `__except`
    /// filter (mov eax, 1; ret); 0x1018: the handler (xor eax, eax; ret). The EH4 scope table's record has
    /// enclosing level `level`; its pointers are the image's code pointers in data.
    fn seh_image(level: u32) -> Image {
        let mut code = vec![0x68];
        code.extend(va(0x2000));
        code.extend([0x33, 0xc0, 0xc3]);
        code.resize(0x10, 0x90);
        code.extend([0xb8, 1, 0, 0, 0, 0xc3, 0x90, 0x90]);
        code.extend([0x33, 0xc0, 0xc3]);
        let mut rdata = Vec::new();
        for v in [0xffff_fffe_u32, 0, 0xffff_ffd8, 0, level] {
            rdata.extend(v.to_le_bytes());
        }
        rdata.extend(va(0x1010));
        rdata.extend(va(0x1018));
        let mut img = x86_image(&code, &rdata, &[]);
        img.code_pointer_slots = vec![(0x2014, 0x1010), (0x2018, 0x1018)];
        img.code_pointers = vec![0x1010, 0x1018];
        img
    }

    #[test]
    fn x86_seh_filters_and_handlers_belong_to_their_function() {
        let ranges = discover(&seh_image(0xffff_fffe));
        let bounds: Vec<(u32, u32)> = ranges.iter().map(|r| (r.start, r.end)).collect();
        assert_eq!(bounds, vec![(0x1000, 0x101b)]);
    }

    #[test]
    fn x86_an_implausible_scope_table_names_no_blocks() {
        // Negative: an outermost record whose enclosing level isn't -2 isn't a scope table, so the pointers stay
        // what they look like: functions reached through data.
        let starts: Vec<u32> = discover(&seh_image(5)).iter().map(|r| r.start).collect();
        assert_eq!(starts, vec![0x1000, 0x1010, 0x1018]);
    }

    /// 0x1000: call 0x1010, then `tail`, then int3 padding; 0x1010: ret.
    fn ends_after_call(tail: &[u8], x86: bool) -> Vec<(u32, u32)> {
        let mut code = vec![0xe8, 0x0b, 0x00, 0x00, 0x00];
        code.extend(tail);
        code.resize(0x10, 0xcc);
        code.push(0xc3);
        let img = if x86 {
            x86_image(&code, &[], &[])
        } else {
            let mut img = image(&code, &[]);
            img.entry = Some(0x1000);
            img
        };
        discover(&img).iter().map(|r| (r.start, r.end)).collect()
    }

    #[test]
    fn x86_an_int3_after_a_call_that_doesnt_return_is_the_functions() {
        assert_eq!(ends_after_call(&[0xcc], true)[0], (0x1000, 0x1006));
        // Negative: after a `ret`, the int3s are all padding; and x64's bounds are unchanged.
        assert_eq!(ends_after_call(&[0xc3, 0xcc], true)[0], (0x1000, 0x1006));
        assert_eq!(ends_after_call(&[0xcc], false)[0], (0x1000, 0x1005));
    }

    /// Code laid out at the given RVAs (from 0x1000), `int3` between, as an x86 or x64 image without `.pdata`;
    /// 0x1000 is the entry and `exported` are exports.
    fn laid_out(blocks: &[(u32, &[u8])], exported: &[u32], x86: bool) -> Vec<FunctionRange> {
        let mut code = Vec::new();
        for &(rva, bytes) in blocks {
            code.resize((rva - 0x1000) as usize, 0xcc);
            code.extend(bytes);
        }
        let mut img = if x86 {
            x86_image(&code, &[], &[])
        } else {
            image(&code, &[])
        };
        img.entry = Some(0x1000);
        img.exports = exported.iter().map(|&e| (e, "e".into())).collect();
        discover(&img)
    }

    const XOR_EAX_RET: &[u8] = &[0x33, 0xc0, 0xc3];

    #[test]
    fn x86_a_cold_block_is_a_fragment_of_the_function_that_jumps_to_it() {
        // PGO layout. f: `test ecx, ecx; je cold; xor eax, eax; inc eax; ret`. cold (0x1040): `xor eax, eax;
        // jmp` back to f's `inc eax` (0x100a). g (0x1020) lies between.
        let f: &[u8] = &[
            0x85, 0xc9, 0x0f, 0x84, 0x38, 0, 0, 0, 0x33, 0xc0, 0x40, 0xc3,
        ];
        let cold: &[u8] = &[0x33, 0xc0, 0xe9, 0xc3, 0xff, 0xff, 0xff];
        let blocks = [(0x1000, f), (0x1020, XOR_EAX_RET), (0x1040, cold)];
        assert_eq!(
            laid_out(&blocks, &[0x1020], true),
            vec![
                FunctionRange {
                    fragments: vec![(0x1040, 0x1047)],
                    ..range(0x1000, 0x100c)
                },
                range(0x1020, 0x1023)
            ]
        );
        // x64 is unchanged: without `.pdata` every jump out of a range starts a function.
        let x64: Vec<u32> = laid_out(&blocks, &[0x1020], false)
            .iter()
            .map(|r| r.start)
            .collect();
        assert_eq!(x64, vec![0x1000, 0x100a, 0x1020, 0x1040]);
    }

    #[test]
    fn x86_a_block_is_still_a_function_when_it_could_be_one() {
        let starts = |blocks: &[(u32, &[u8])], exported: &[u32]| -> Vec<u32> {
            let found = laid_out(blocks, exported, true);
            assert!(found.iter().all(|r| r.fragments.is_empty()), "{found:x?}");
            found.iter().map(|r| r.start).collect()
        };
        // Two functions jump conditionally to 0x1040: it belongs to neither.
        let f: &[u8] = &[0x85, 0xc9, 0x0f, 0x84, 0x38, 0, 0, 0, 0xc3];
        let g: &[u8] = &[0x85, 0xc9, 0x0f, 0x84, 0x18, 0, 0, 0, 0xc3];
        assert_eq!(
            starts(
                &[(0x1000, f), (0x1020, g), (0x1040, XOR_EAX_RET)],
                &[0x1020]
            ),
            vec![0x1000, 0x1020, 0x1040]
        );
        // An unconditional jump out of the function to code nothing runs into: a tail call.
        let tail: &[u8] = &[0xe9, 0x3b, 0, 0, 0];
        assert_eq!(
            starts(
                &[(0x1000, tail), (0x1020, XOR_EAX_RET), (0x1040, XOR_EAX_RET)],
                &[0x1020]
            ),
            vec![0x1000, 0x1020, 0x1040]
        );
        // A conditional jump to a block that is also called: a function.
        let calls: &[u8] = &[
            0x85, 0xc9, 0x0f, 0x84, 0x38, 0, 0, 0, 0xe8, 0x33, 0, 0, 0, 0xc3,
        ];
        assert_eq!(
            starts(&[(0x1000, calls), (0x1040, XOR_EAX_RET)], &[]),
            vec![0x1000, 0x1040]
        );
    }

    #[test]
    fn x86_code_tables_use_4_byte_slots() {
        let ranges = [range(0x1000, 0x1001), range(0x1010, 0x1011)];
        let mut img = x86_image(&[0xc3; 0x20], &[], &[]);
        img.code_pointer_slots = vec![(0x2000, 0x1000), (0x2004, 0x1010)];
        assert_eq!(code_tables(&img, &ranges).len(), 1);
        // Negative: x64-sized spacing on x86 is two lone pointers, not a table.
        img.code_pointer_slots = vec![(0x2000, 0x1000), (0x2008, 0x1010)];
        assert!(code_tables(&img, &ranges).is_empty());
    }

    /// 0x1000: push offset ThrowInfo (0x402010); push eax; call [__imp__CxxThrowException] (0x402000); ret.
    /// 0x1010: the destructor; 0x1018: the copy constructor (each `mov eax, ecx; ret`), laid out with no padding
    /// before them. The ThrowInfo's references are written by `reference` (an address on x86).
    fn x86_throw_image(reference: impl Fn(u32) -> u32) -> Image {
        let mut code = vec![0x68];
        code.extend(va(0x2010));
        code.extend([0x50, 0xff, 0x15]);
        code.extend(va(0x2000));
        code.push(0xc3);
        code.resize(0x10, 0x90);
        code.extend([
            0x8b, 0xc1, 0xc3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x8b, 0xc1, 0xc3,
        ]);
        let mut rdata = vec![0u8; 0x50];
        let mut put = |at: usize, v: u32| rdata[at..at + 4].copy_from_slice(&v.to_le_bytes());
        put(0x14, reference(0x1010)); // pmfnUnwind
        put(0x1c, reference(0x2020)); // pCatchableTypeArray
        put(0x20, 1);
        put(0x24, reference(0x2030));
        put(0x34, reference(0x3000)); // pType
        put(0x3c, 0xffff_ffff);
        put(0x44, 8);
        put(0x48, reference(0x1018)); // copyFunction
        let mut img = x86_image(&code, &rdata, &[0; 0x10]);
        img.iat
            .insert(0x2000, "vcruntime140.dll!_CxxThrowException".into());
        img
    }

    #[test]
    fn x86_a_throw_sites_destructor_and_copy_constructor_are_functions() {
        let img = x86_throw_image(|rva| X86_BASE + rva);
        let starts: Vec<u32> = discover(&img).iter().map(|r| r.start).collect();
        assert_eq!(starts, vec![0x1000, 0x1010, 0x1018]);
        // Negative: x64's image-relative references in an x86 ThrowInfo point nowhere, so it isn't one.
        let img = x86_throw_image(|rva| rva);
        let starts: Vec<u32> = discover(&img).iter().map(|r| r.start).collect();
        assert_eq!(starts, vec![0x1000]);
    }

    #[test]
    fn x86_functions_infer_stack_arguments() {
        // mov eax, [esp+8]; ret   (reads the second stack argument)
        let img = x86_image(&[0x8b, 0x44, 0x24, 0x08, 0xc3], &[], &[]);
        let f = features(&img, &range(0x1000, 0x1005));
        assert_eq!(f.inferred_args, Some(2));
        assert!(f.inferred_arg_classes.is_empty(), "no register arguments");
        // mov eax, [ecx]; add eax, [esp+4]; ret 4   (__thiscall: ecx, then a stack word)
        let img = x86_image(
            &[0x8b, 0x01, 0x03, 0x44, 0x24, 0x04, 0xc2, 0x04, 0x00],
            &[],
            &[],
        );
        let f = features(&img, &range(0x1000, 0x1009));
        assert_eq!(f.inferred_args, Some(2));
        assert_eq!(f.inferred_arg_classes, vec![ArgClass::Integer]);
        // Negative: the same bytes as x64 code read no argument register.
        let f = features(
            &image(&[0x8b, 0x44, 0x24, 0x08, 0xc3], &[]),
            &range(0x1000, 0x1005),
        );
        assert_eq!(f.inferred_args, Some(0));
    }
}
