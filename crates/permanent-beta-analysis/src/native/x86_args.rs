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

/// How many register arguments the code takes: 1 if it reads ecx before writing it (`__thiscall`, or a
/// one-argument `__fastcall`), 2 if it reads edx so (`__fastcall`), else 0. Scanned up to the first call or
/// return.
pub(crate) fn register_args(insns: &[Instruction]) -> u8 {
    let mut seen: BTreeMap<Register, bool> = BTreeMap::new();
    let mut factory = InstructionInfoFactory::new();
    for ins in insns {
        if matches!(ins.flow_control(), FlowControl::Call | FlowControl::Return) {
            break;
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

/// 1 + the highest argument slot the code reads before writing, scanning in address order up to the first call
/// or return; capped at [`MAX_SLOTS`]. Slots as in the module docs: ecx and edx when read as arguments, then the
/// stack arguments. A lower bound, like the x64 count: unused trailing parameters are invisible.
pub(crate) fn inferred_args(insns: &[Instruction]) -> u8 {
    let regs = register_args(insns);
    let mut stack = Stack::new();
    let mut written: Vec<u8> = Vec::new();
    let mut highest: Option<u8> = None;
    let mut factory = InstructionInfoFactory::new();
    for ins in insns {
        if matches!(ins.flow_control(), FlowControl::Call | FlowControl::Return) {
            break;
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
