//! Argument inference for x86 (32-bit) code, the counterpart of the Win64 register scan in `super::function`.
//!
//! x86 has no single calling convention. MSVC passes `__cdecl` and `__stdcall` arguments on the stack,
//! `__thiscall` passes `this` in ecx and the rest on the stack, and `__fastcall` passes the first two in ecx and
//! edx. The code says which: a function that reads ecx (or ecx and edx) before writing it takes it as its first
//! argument (or two); nothing else reads a register it hasn't set. So an argument *slot* here is the parameter's
//! index under that reading: ecx, then edx, then the stack arguments in order. For a `__thiscall` method, slot 0
//! is `this` and slot 1 the first stack argument, which is also the prototype's parameter order.
//!
//! Stack arguments are found relative to the entry `esp`: at the entry `[esp]` is the return address and stack
//! argument `k` is at `[esp + 4 + 4k]`. The scan follows `esp` through pushes, pops and constant adjustments, and
//! an `ebp` frame (`mov ebp, esp`). Like the x64 scan it's a heuristic over the instructions in address order,
//! ignoring control flow.

use iced_x86::{
    FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register,
};
use permanent_beta_model::ArgAccess;
use std::collections::BTreeMap;

/// Most argument slots counted. **[Guess]**: past this, the count is no better evidence.
const MAX_SLOTS: u8 = 8;
/// Most argument accesses recorded per function. **[Guess]**
const MAX_ARG_ACCESSES: usize = 64;
/// Offsets above this aren't taken for struct fields. **[Guess]**
const MAX_FIELD_OFFSET: i64 = 0x10000;

/// Where `esp` and `ebp` are relative to the entry `esp`, as far as the scan can tell.
#[derive(Default)]
struct Stack {
    /// Bytes pushed since the entry (the entry `esp` minus the current one), if known.
    esp: Option<i64>,
    /// The entry `esp` minus `ebp`, once `mov ebp, esp` has set up a frame.
    ebp: Option<i64>,
}

impl Stack {
    fn new() -> Self {
        Self {
            esp: Some(0),
            ebp: None,
        }
    }

    /// The offset from the entry `esp` that `[base + disp]` names, if it's a stack location the scan can place.
    fn key(&self, base: Register, index: Register, disp: u32) -> Option<i64> {
        if index != Register::None {
            return None;
        }
        let disp = i64::from(disp as i32);
        match base {
            Register::ESP => self.esp.map(|d| disp - d),
            Register::EBP => self.ebp.map(|d| disp - d),
            _ => None,
        }
    }

    /// Follow `ins`'s effect on `esp` and `ebp`.
    fn step(&mut self, ins: &Instruction) {
        let reg0 =
            (ins.op_count() > 0 && ins.op0_kind() == OpKind::Register).then(|| ins.op0_register());
        match ins.mnemonic() {
            Mnemonic::Push => self.esp = self.esp.map(|d| d + 4),
            Mnemonic::Pop => {
                self.esp = self.esp.map(|d| d - 4);
                if reg0 == Some(Register::EBP) {
                    self.ebp = None;
                }
            }
            Mnemonic::Sub | Mnemonic::Add if reg0 == Some(Register::ESP) => {
                let imm = (ins.op_count() == 2 && super::function::is_immediate(ins.op1_kind()))
                    .then(|| i64::from(ins.immediate(1) as u32 as i32));
                self.esp = match (self.esp, imm) {
                    (Some(d), Some(i)) if ins.mnemonic() == Mnemonic::Sub => Some(d + i),
                    (Some(d), Some(i)) => Some(d - i),
                    // `sub esp, eax` (a __chkstk frame): esp is no longer known.
                    _ => None,
                };
            }
            Mnemonic::Mov
                if reg0 == Some(Register::EBP)
                    && ins.op1_kind() == OpKind::Register
                    && ins.op1_register() == Register::ESP =>
            {
                self.ebp = self.esp;
            }
            Mnemonic::Mov
                if reg0 == Some(Register::ESP)
                    && ins.op1_kind() == OpKind::Register
                    && ins.op1_register() == Register::EBP =>
            {
                self.esp = self.ebp;
            }
            Mnemonic::Leave => {
                self.esp = self.ebp.map(|d| d - 4);
                self.ebp = None;
            }
            _ => {
                // Any other write to esp (`and esp, -16`, `lea esp, [ebp-x]`) loses it; to ebp, the frame.
                if reg0 == Some(Register::ESP) {
                    self.esp = None;
                }
                if reg0 == Some(Register::EBP) {
                    self.ebp = None;
                }
            }
        }
    }
}

/// The stack argument index at entry offset `key`: `[entry esp + 4 + 4k]`.
fn stack_arg(key: i64) -> Option<u8> {
    (key >= 4).then(|| ((key - 4) / 4).min(i64::from(u8::MAX)) as u8)
}

fn writes(access: OpAccess) -> bool {
    matches!(
        access,
        OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite
    )
}

fn reads(access: OpAccess) -> bool {
    matches!(
        access,
        OpAccess::Read | OpAccess::CondRead | OpAccess::ReadWrite | OpAccess::ReadCondWrite
    )
}

/// Whether `ins` is a prologue instruction: `push ebp`, `mov ebp, esp`, `push <register>`, `sub esp, imm`.
fn is_prologue(ins: &Instruction) -> bool {
    let reg0 =
        (ins.op_count() > 0 && ins.op0_kind() == OpKind::Register).then(|| ins.op0_register());
    match ins.mnemonic() {
        Mnemonic::Push => reg0.is_some(),
        Mnemonic::Mov => {
            reg0 == Some(Register::EBP)
                && ins.op1_kind() == OpKind::Register
                && ins.op1_register() == Register::ESP
        }
        Mnemonic::Sub => {
            reg0 == Some(Register::ESP) && super::function::is_immediate(ins.op1_kind())
        }
        _ => false,
    }
}

/// How many register arguments the code takes: 1 if it reads ecx before writing it (`__thiscall`, or a
/// one-argument `__fastcall`), 2 if it reads edx so (`__fastcall`), else 0. Scanned up to the first call or
/// return. A `push ecx` (or edx) in the prologue isn't a read: MSVC pushes ecx to make room for a 4-byte local
/// (`push ebp; mov ebp, esp; push ecx`), whatever ecx holds; a `__thiscall` function reads `this` from ecx after
/// that too (`mov [ebp-4], ecx`).
pub(crate) fn register_args(insns: &[Instruction]) -> u8 {
    let mut seen: BTreeMap<Register, bool> = BTreeMap::new();
    let mut factory = InstructionInfoFactory::new();
    let mut prologue = true;
    for ins in insns {
        if matches!(ins.flow_control(), FlowControl::Call | FlowControl::Return) {
            break;
        }
        prologue = prologue && is_prologue(ins);
        if prologue && ins.mnemonic() == Mnemonic::Push {
            continue;
        }
        let info = factory.info(ins);
        // Reads first: `add ecx, edx` reads ecx before writing it.
        for pass_reads in [true, false] {
            for used in info.used_registers() {
                let full = used.register().full_register32();
                if !matches!(full, Register::ECX | Register::EDX) || seen.contains_key(&full) {
                    continue;
                }
                if pass_reads && reads(used.access()) {
                    seen.insert(full, true);
                } else if !pass_reads && used.access() == OpAccess::Write {
                    seen.insert(full, false);
                }
            }
        }
    }
    let read = |r| seen.get(&r).copied().unwrap_or(false);
    if read(Register::EDX) {
        2
    } else {
        u8::from(read(Register::ECX))
    }
}

/// Whether `ins` is `add esp, imm`.
fn is_esp_cleanup(ins: &Instruction) -> bool {
    ins.mnemonic() == Mnemonic::Add
        && ins.op_count() == 2
        && ins.op0_kind() == OpKind::Register
        && ins.op0_register() == Register::ESP
        && super::function::is_immediate(ins.op1_kind())
}

/// Whether the call at `insns[i]` is followed by its caller's cleanup: the next instruction that changes `esp` is
/// `add esp, imm`, with no control flow before it (MSVC may put other instructions in between).
fn cleaned_up_after(insns: &[Instruction], i: usize, factory: &mut InstructionInfoFactory) -> bool {
    for next in &insns[i + 1..] {
        if is_esp_cleanup(next) {
            return true;
        }
        if next.flow_control() != FlowControl::Next {
            return false;
        }
        let writes_esp = factory
            .info(next)
            .used_registers()
            .iter()
            .any(|u| u.register().full_register32() == Register::ESP && writes(u.access()));
        if writes_esp {
            return false;
        }
    }
    false
}

/// 1 + the highest argument slot the code reads before writing, scanning in address order; capped at
/// [`MAX_SLOTS`]. Slots as in the module docs: ecx and edx when read as arguments, then the stack arguments. A
/// lower bound, like the x64 count: unused trailing parameters are invisible.
///
/// Unlike register arguments, stack arguments survive calls and are read on every path, so the whole function is
/// scanned (stopping at the first call or return made the count depend on code order: a guard reading the last
/// parameter first changed it). Where `esp` and `ebp` are is followed as in [`Stack`], and:
/// - a call whose caller's cleanup follows (`add esp, imm`, a `__cdecl` callee's arguments) leaves `esp` where it
///   was; after any other call `esp` is unknown (the callee may have removed its arguments itself);
/// - after a return both are unknown, and a branch's target gets them as they were at the branch, so the code after
///   an early return is placed again.
///
/// Reads that can't be placed are left out.
pub(crate) fn inferred_args(insns: &[Instruction]) -> u8 {
    let regs = register_args(insns);
    let mut stack = Stack::new();
    let mut written: Vec<u8> = Vec::new();
    let mut highest: Option<u8> = None;
    let mut factory = InstructionInfoFactory::new();
    let mut at_target: BTreeMap<u64, (Option<i64>, Option<i64>)> = BTreeMap::new();
    for (i, ins) in insns.iter().enumerate() {
        if let Some(&(esp, ebp)) = at_target.get(&ins.ip()) {
            stack.esp = stack.esp.or(esp);
            stack.ebp = stack.ebp.or(ebp);
        }
        if matches!(
            ins.flow_control(),
            FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch
        ) && matches!(ins.op0_kind(), OpKind::NearBranch32 | OpKind::NearBranch16)
        {
            at_target
                .entry(ins.near_branch_target())
                .or_insert((stack.esp, stack.ebp));
        }
        if ins.flow_control() == FlowControl::Return {
            stack.esp = None;
            stack.ebp = None;
            continue;
        }
        let info = factory.info(ins);
        for m in info.used_memory() {
            let Some(k) = stack
                .key(m.base(), m.index(), m.displacement() as u32)
                .and_then(stack_arg)
            else {
                continue;
            };
            if reads(m.access()) && !written.contains(&k) {
                highest = Some(highest.map_or(k, |h| h.max(k)));
            } else if writes(m.access()) {
                written.push(k);
            }
        }
        if ins.flow_control() == FlowControl::Call {
            if !cleaned_up_after(insns, i, &mut factory) {
                stack.esp = None;
            }
            continue;
        }
        stack.step(ins);
    }
    let stack_count = highest.map_or(0, |h| h.saturating_add(1));
    regs.saturating_add(stack_count).min(MAX_SLOTS)
}

/// Memory accessed through the pointer arguments (design §7.2), as the x64 scan records it: each argument is
/// followed from where it arrives (ecx, edx, or its stack slot) through loads into registers, register copies and
/// spills to the stack, and dropped when its register is written otherwise or a call clobbers it (eax, ecx, edx).
/// Accesses with an index register, or a negative or very large offset, aren't recorded.
pub(crate) fn arg_accesses(insns: &[Instruction]) -> Vec<ArgAccess> {
    let regs = register_args(insns);
    let mut tracked: Vec<(Register, u8)> = [Register::ECX, Register::EDX]
        .into_iter()
        .take(usize::from(regs))
        .zip(0..)
        .collect();
    let slot_of = |tracked: &[(Register, u8)], r: Register| {
        tracked
            .iter()
            .find(|(t, _)| *t == r.full_register32())
            .map(|(_, s)| *s)
    };
    // Stack locations by entry offset: what each holds now, once written (`None`: not an argument). A location
    // not in the map still holds what it held at the entry: a stack argument above the return address.
    let mut stack_values: BTreeMap<i64, Option<u8>> = BTreeMap::new();
    let holds = |values: &BTreeMap<i64, Option<u8>>, key: i64| -> Option<u8> {
        match values.get(&key) {
            Some(v) => *v,
            None => stack_arg(key)
                .filter(|_| (key - 4) % 4 == 0)
                .map(|k| k.saturating_add(regs)),
        }
    };
    let mut stack = Stack::new();
    let mut out = Vec::new();
    let mut factory = InstructionInfoFactory::new();
    for ins in insns {
        if out.len() >= MAX_ARG_ACCESSES {
            break;
        }
        let info = factory.info(ins);
        for m in info.used_memory() {
            let Some(slot) = slot_of(&tracked, m.base()) else {
                continue;
            };
            let size = m.memory_size().size();
            let offset = i64::from(m.displacement() as u32 as i32);
            if m.index() != Register::None
                || size == 0
                || size > 16
                || !(0..MAX_FIELD_OFFSET).contains(&offset)
            {
                continue;
            }
            out.push(ArgAccess {
                slot,
                offset: offset as u32,
                size: size as u8,
                write: writes(m.access()),
            });
        }

        // A 32-bit register copy, or a load from a stack location that holds an argument, carries it along; a
        // store to the stack records what the location holds now.
        let is_mov = ins.mnemonic() == Mnemonic::Mov && ins.op_count() == 2;
        let reg32 = |r: Register| r.size() == 4;
        let mut copied = None;
        if is_mov && ins.op0_kind() == OpKind::Register && reg32(ins.op0_register()) {
            if ins.op1_kind() == OpKind::Register {
                copied = slot_of(&tracked, ins.op1_register());
            } else if ins.op1_kind() == OpKind::Memory
                && let Some(key) = stack.key(
                    ins.memory_base(),
                    ins.memory_index(),
                    ins.memory_displacement32(),
                )
            {
                copied = holds(&stack_values, key);
            }
        }
        for m in info.used_memory() {
            if !writes(m.access()) {
                continue;
            }
            if let Some(key) = stack.key(m.base(), m.index(), m.displacement() as u32) {
                let value =
                    (is_mov && ins.op1_kind() == OpKind::Register && reg32(ins.op1_register()))
                        .then(|| slot_of(&tracked, ins.op1_register()))
                        .flatten();
                stack_values.insert(key, value);
            }
        }

        stack.step(ins);
        if ins.flow_control() == FlowControl::Call {
            // A `__stdcall` callee pops its own arguments, so without a frame the scan no longer knows esp.
            if stack.ebp.is_none() {
                stack.esp = None;
            }
        }
        for used in info.used_registers() {
            if writes(used.access()) {
                let full = used.register().full_register32();
                tracked.retain(|(t, _)| *t != full);
            }
        }
        if let Some(slot) = copied {
            tracked.push((ins.op0_register().full_register32(), slot));
        }
        if ins.flow_control() == FlowControl::Call {
            tracked.retain(|(t, _)| !matches!(t, Register::EAX | Register::ECX | Register::EDX));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::{Decoder, DecoderOptions};

    fn decode(code: &[u8]) -> Vec<Instruction> {
        let mut d = Decoder::with_ip(32, code, 0x401000, DecoderOptions::NONE);
        let mut out = Vec::new();
        while d.can_decode() {
            out.push(d.decode());
        }
        out
    }

    fn accesses(code: &[u8]) -> Vec<(u8, u32, u8, bool)> {
        arg_accesses(&decode(code))
            .into_iter()
            .map(|a| (a.slot, a.offset, a.size, a.write))
            .collect()
    }

    #[test]
    fn cdecl_stack_arguments_are_counted() {
        // mov eax, [esp+4]; add eax, [esp+0Ch]; ret   (reads arguments 0 and 2)
        let code = [0x8b, 0x44, 0x24, 0x04, 0x03, 0x44, 0x24, 0x0c, 0xc3];
        assert_eq!(inferred_args(&decode(&code)), 3);
        // Negative: the return address and locals below it aren't arguments.
        // mov eax, [esp]; ret
        assert_eq!(inferred_args(&decode(&[0x8b, 0x04, 0x24, 0xc3])), 0);
    }

    #[test]
    fn arguments_are_found_through_pushes_and_an_ebp_frame() {
        // push ebp; mov ebp, esp; push esi; mov eax, [ebp+0Ch]; pop esi; pop ebp; ret   (argument 1)
        let code = [0x55, 0x8b, 0xec, 0x56, 0x8b, 0x45, 0x0c, 0x5e, 0x5d, 0xc3];
        assert_eq!(inferred_args(&decode(&code)), 2);
        // push esi; mov eax, [esp+8]; pop esi; ret   (after one push, [esp+8] is argument 0)
        let code = [0x56, 0x8b, 0x44, 0x24, 0x08, 0x5e, 0xc3];
        assert_eq!(inferred_args(&decode(&code)), 1);
    }

    #[test]
    fn thiscall_and_fastcall_registers_come_first() {
        // mov eax, [ecx+8]; add eax, [esp+4]; ret 4   (this, then one stack argument)
        let code = [0x8b, 0x41, 0x08, 0x03, 0x44, 0x24, 0x04, 0xc2, 0x04, 0x00];
        assert_eq!(inferred_args(&decode(&code)), 2);
        // mov eax, ecx; add eax, edx; ret   (__fastcall, two register arguments)
        assert_eq!(inferred_args(&decode(&[0x8b, 0xc1, 0x03, 0xc2, 0xc3])), 2);
        // Negative: ecx written before it's read isn't an argument.
        // mov ecx, [esp+4]; mov eax, [ecx]; ret
        let code = [0x8b, 0x4c, 0x24, 0x04, 0x8b, 0x01, 0xc3];
        assert_eq!(inferred_args(&decode(&code)), 1);
    }

    #[test]
    fn a_push_ecx_making_room_for_a_local_isnt_a_this() {
        // MSVC /Od: push ebp; mov ebp, esp; push ecx (a local); mov eax, [ebp+8]; add eax, [ebp+0Ch];
        // mov esp, ebp; pop ebp; ret   (__cdecl, two stack arguments)
        let code = [
            0x55, 0x8b, 0xec, 0x51, 0x8b, 0x45, 0x08, 0x03, 0x45, 0x0c, 0x8b, 0xe5, 0x5d, 0xc3,
        ];
        assert_eq!(register_args(&decode(&code)), 0);
        assert_eq!(inferred_args(&decode(&code)), 2);
        // Negative: a __thiscall method that stores ecx into that local still takes `this` in ecx.
        // push ebp; mov ebp, esp; push ecx; mov [ebp-4], ecx; mov eax, [ebp+8]; mov esp, ebp; pop ebp; ret 4
        let code = [
            0x55, 0x8b, 0xec, 0x51, 0x89, 0x4d, 0xfc, 0x8b, 0x45, 0x08, 0x8b, 0xe5, 0x5d, 0xc2,
            0x04, 0x00,
        ];
        assert_eq!(register_args(&decode(&code)), 1);
        assert_eq!(inferred_args(&decode(&code)), 2);
        // Negative: a push of ecx past the prologue (an argument for a call) is a read.
        // mov eax, [esp+4]; push ecx; call $+5; ...
        let code = [
            0x8b, 0x44, 0x24, 0x04, 0x51, 0xe8, 0x00, 0x00, 0x00, 0x00, 0xc3,
        ];
        assert_eq!(register_args(&decode(&code)), 1);
    }

    #[test]
    fn stack_arguments_read_after_a_call_count_through_ebp() {
        // push ebp; mov ebp, esp; push [ebp+8]; call $+5; add esp, 4; mov eax, [ebp+10h]; pop ebp; ret
        // (argument 2 read only after the call)
        let code = [
            0x55, 0x8b, 0xec, 0xff, 0x75, 0x08, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x83, 0xc4, 0x04,
            0x8b, 0x45, 0x10, 0x5d, 0xc3,
        ];
        assert_eq!(inferred_args(&decode(&code)), 3);
        // Without a frame, through the caller's cleanup of a __cdecl call:
        // push [esp+4]; call $+5; add esp, 4; mov eax, [esp+0Ch]; ret   (argument 2 after the call)
        let code = [
            0xff, 0x74, 0x24, 0x04, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x83, 0xc4, 0x04, 0x8b, 0x44,
            0x24, 0x0c, 0xc3,
        ];
        assert_eq!(inferred_args(&decode(&code)), 3);
        // ... also with an instruction before the cleanup:
        // push [esp+4]; call $+5; mov edx, [esp+10h]; add esp, 4; ret   (argument 2: one word still pushed)
        let code = [
            0xff, 0x74, 0x24, 0x04, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x8b, 0x54, 0x24, 0x10, 0x83,
            0xc4, 0x04, 0xc3,
        ];
        assert_eq!(inferred_args(&decode(&code)), 3);
        // Negative: with no cleanup, esp after a call is unknown (the callee may have popped): an esp-relative read
        // there isn't placed. push [esp+4]; call $+5; mov eax, [esp+0Ch]; ret
        let code = [
            0xff, 0x74, 0x24, 0x04, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x8b, 0x44, 0x24, 0x0c, 0xc3,
        ];
        assert_eq!(inferred_args(&decode(&code)), 1);
    }

    #[test]
    fn stack_arguments_after_an_early_return_are_placed_from_the_branch() {
        // push ebx; mov eax, [esp+8]; test eax, eax; jz L; pop ebx; ret; L: mov eax, [esp+0Ch]; pop ebx; ret
        // (argument 0, then argument 1 on the path after the early return, esp as at the jz)
        let code = [
            0x53, 0x8b, 0x44, 0x24, 0x08, 0x85, 0xc0, 0x74, 0x02, 0x5b, 0xc3, 0x8b, 0x44, 0x24,
            0x0c, 0x5b, 0xc3,
        ];
        assert_eq!(inferred_args(&decode(&code)), 2);
        // Negative: code after a return that no branch reaches isn't placed.
        // mov eax, [esp+4]; ret; mov eax, [esp+0Ch]; ret
        let code = [0x8b, 0x44, 0x24, 0x04, 0xc3, 0x8b, 0x44, 0x24, 0x0c, 0xc3];
        assert_eq!(inferred_args(&decode(&code)), 1);
    }

    #[test]
    fn an_overwritten_stack_argument_read_back_isnt_one() {
        // mov dword [esp+4], 0; mov eax, [esp+4]; ret   (the argument's slot reused as a local)
        let code = [
            0xc7, 0x44, 0x24, 0x04, 0x00, 0x00, 0x00, 0x00, 0x8b, 0x44, 0x24, 0x04, 0xc3,
        ];
        assert_eq!(inferred_args(&decode(&code)), 0);
    }

    #[test]
    fn accesses_through_a_loaded_stack_argument_are_recorded() {
        // mov eax, [esp+4]; mov ecx, [eax+8]; mov [eax+0Ch], ecx; ret
        let code = [
            0x8b, 0x44, 0x24, 0x04, 0x8b, 0x48, 0x08, 0x89, 0x48, 0x0c, 0xc3,
        ];
        assert_eq!(accesses(&code), vec![(0, 8, 4, false), (0, 0xc, 4, true)]);
    }

    #[test]
    fn this_is_slot_zero_and_stack_arguments_follow() {
        // mov eax, [esp+4]; mov edx, [ecx+10h]; mov [eax+4], edx; ret 4
        let code = [
            0x8b, 0x44, 0x24, 0x04, 0x8b, 0x51, 0x10, 0x89, 0x50, 0x04, 0xc2, 0x04, 0x00,
        ];
        assert_eq!(accesses(&code), vec![(0, 0x10, 4, false), (1, 4, 4, true)]);
    }

    #[test]
    fn a_spilled_this_is_followed_at_od() {
        // push ebp; mov ebp, esp; push ecx; mov [ebp-4], ecx; mov eax, [ebp-4]; mov eax, [eax+8];
        // mov esp, ebp; pop ebp; ret
        let code = [
            0x55, 0x8b, 0xec, 0x51, 0x89, 0x4d, 0xfc, 0x8b, 0x45, 0xfc, 0x8b, 0x40, 0x08, 0x8b,
            0xe5, 0x5d, 0xc3,
        ];
        assert_eq!(accesses(&code), vec![(0, 8, 4, false)]);
    }

    #[test]
    fn a_clobbered_or_indexed_pointer_isnt_followed() {
        // Negative: mov eax, [esp+4]; mov eax, [eax]; mov ecx, [eax+4]; ret   (eax now holds what it pointed to;
        // its first read is recorded, the second isn't).
        let code = [0x8b, 0x44, 0x24, 0x04, 0x8b, 0x00, 0x8b, 0x48, 0x04, 0xc3];
        assert_eq!(accesses(&code), vec![(0, 0, 4, false)]);
        // Negative: mov eax, [esp+4]; mov ecx, [eax+esi*4]; ret   (indexed)
        let code = [0x8b, 0x44, 0x24, 0x04, 0x8b, 0x0c, 0xb0, 0xc3];
        assert!(accesses(&code).is_empty());
    }
}
