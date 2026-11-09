//! Running one function of the new build in icicle (design §7.3, replay by emulation). icicle executes Ghidra's
//! SLEIGH specification of x86-64 (`sleigh`), so replay and Ghidra share one definition of the instruction set.
//!
//! The address space holds only what the replay is entitled to:
//! - the new image at a base clear of the recorded memory (rebased if needed), its import address table pointing
//!   at trap addresses;
//! - the recorded memory at the addresses it had when recorded (pointer arguments keep their values);
//! - the recorded globals, at the new image's addresses for them;
//! - a fresh stack, whose return address is a trap: reaching it means the function returned.
//!
//! What the function may touch is enforced by icicle's per-byte permissions: code is executable, read-only
//! sections readable, writable sections readable and writable only at the recorded globals (and
//! `__security_cookie`, readable), the recorded memory and the stack readable and writable. Anything else stops the
//! run with the address.
//!
//! A call into an import reaches a trap (a breakpoint). With the case's recorded import calls ([`StandIns`]), a
//! modelled import is answered from the recording: its writes are made (only where the function itself may write),
//! rax set, and the run returns to the caller. Otherwise, and for anything else, the run stops and the case is
//! inconclusive, never a pass: an import with no stand-in, a read of a writable image section outside the recorded
//! globals (mutable global state the recording didn't capture), a write anywhere but the stack, the recorded memory
//! and the globals, a read of memory nobody recorded, an interrupt or `syscall`, an instruction the specification
//! doesn't cover, running out of instructions, and a stand-in that sees other inputs than recorded.
//!
//! Reads of uncaptured bytes in a 32-byte-aligned block that also holds captured bytes are allowed (they read
//! zeros): vectorized string and memory code reads whole aligned blocks past the end of its data, which can't
//! change a correct result. **[Guess]** at 32 (AVX2's width).

use crate::image::{Image, PAGE, page_up};
use crate::imports::{self, CallView, StandIns};
use icicle_vm::cpu::mem::{Mapping, perm};
use icicle_vm::cpu::{Config, ExceptionCode, VmExit};
use permanent_beta_model::EntryState;
use std::cell::RefCell;
use std::ops::Range;

/// Most instructions one case may run. **[Guess]**
pub const MAX_INSTRUCTIONS: u64 = 10_000_000;
const STACK_SIZE: u64 = 0x10_0000;
/// The value `__security_cookie` gets: MSVC's default (its top 16 bits must be zero for the cookie check).
const SECURITY_COOKIE: u64 = 0x0000_2B99_2DDF_A232;
const SLACK: u64 = 32;

/// Memory placed at a fixed address before the run.
#[derive(Debug, Clone)]
pub struct Placed {
    pub address: u64,
    pub bytes: Vec<u8>,
}

pub struct Setup<'a> {
    pub image: &'a Image,
    pub rva: u64,
    pub entry: &'a EntryState,
    pub regions: &'a [Placed],
    /// Globals: `address` is an RVA of the image.
    pub globals: &'a [Placed],
    /// The case's recorded import calls, if the recorder intercepted the module's imports.
    pub imports: Option<StandIns>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ran {
    pub rax: u64,
    pub xmm0: [u8; 16],
    /// Each placed region's bytes after the call, in `Setup::regions` order.
    pub regions: Vec<Vec<u8>>,
    /// Each global's bytes after the call, in `Setup::globals` order.
    pub globals: Vec<Vec<u8>>,
    /// Import calls answered from the recording.
    pub import_calls: usize,
    /// Where the new image was mapped: a pointer into it is the new build's address of something.
    pub image: Range<u64>,
    pub instructions: u64,
}

fn inside(ranges: &[Range<u64>], a: u64) -> bool {
    ranges.iter().any(|r| r.contains(&a))
}

/// Picks a free, page-aligned range of `size` bytes from `candidates`, clear of `taken`.
fn place(
    size: u64,
    taken: &mut Vec<Range<u64>>,
    candidates: impl IntoIterator<Item = u64>,
) -> Option<u64> {
    let size = page_up(size);
    let free = candidates.into_iter().find(|&base| {
        base % PAGE == 0
            && base.checked_add(size).is_some()
            && taken
                .iter()
                .all(|t| base + size <= t.start || base >= t.end)
    })?;
    taken.push(free..free + size);
    Some(free)
}

fn page_ranges(regions: &[Placed]) -> Vec<Range<u64>> {
    let mut pages: Vec<Range<u64>> = regions
        .iter()
        .filter(|r| !r.bytes.is_empty())
        .map(|r| (r.address & !(PAGE - 1))..page_up(r.address + r.bytes.len() as u64))
        .collect();
    pages.sort_by_key(|r| r.start);
    let mut merged: Vec<Range<u64>> = Vec::new();
    for p in pages {
        match merged.last_mut() {
            Some(last) if p.start <= last.end => last.end = last.end.max(p.end),
            _ => merged.push(p),
        }
    }
    merged
}

thread_local! {
    /// One VM per thread: building one compiles the SLEIGH specification. Reset before every case.
    static VM: RefCell<Option<icicle_vm::Vm>> = const { RefCell::new(None) };
}

fn new_vm() -> Result<icicle_vm::Vm, String> {
    let processors = crate::sleigh::processors()?;
    let config = Config {
        // Returns go to our traps, which no call pushed: icicle's shadow stack would flag them.
        enable_shadow_stack: false,
        ..Config::from_target_triple("x86_64-none")
    };
    icicle_vm::build_with_path(&config, &processors)
        .map_err(|e| format!("icicle couldn't build an x86-64 VM: {e}"))
}

/// Where the case may read and write, for the reasons it stopped.
struct Layout {
    image: Range<u64>,
    writable_sections: Vec<Range<u64>>,
    imports: Range<u64>,
    import_names: Vec<String>,
    import_first: u64,
    return_trap: u64,
}

impl Layout {
    fn describe(&self, a: u64) -> String {
        if self.image.contains(&a) {
            format!("RVA {:#x} of the image", a - self.image.start)
        } else {
            format!("{a:#x}")
        }
    }

    fn why(&self, code: ExceptionCode, a: u64) -> String {
        use ExceptionCode as E;
        match code {
            E::ReadUnmapped | E::ReadPerm | E::ReadUninitialized => {
                if inside(&self.writable_sections, a) {
                    format!(
                        "reads {} in a writable section: mutable global state the recording didn't capture",
                        self.describe(a)
                    )
                } else if self.imports.contains(&a) {
                    format!("reads the import trap at {a:#x}")
                } else {
                    format!("reads {a:#x}, memory the recording didn't capture")
                }
            }
            E::WriteUnmapped | E::WritePerm => {
                if self.image.contains(&a) {
                    format!("writes {}: global state", self.describe(a))
                } else {
                    format!("writes {a:#x}, outside the recorded memory and the stack")
                }
            }
            E::ExecViolation | E::ExternalAddr => {
                format!("executes {a:#x}, which the recording didn't capture")
            }
            E::Syscall => "makes a system call".into(),
            E::SoftwareBreakpoint | E::UnknownInterrupt | E::Halt => {
                format!("raises an interrupt at {a:#x} (int3, int 2e, ...)")
            }
            E::InvalidInstruction | E::UnimplementedOp | E::InvalidOpSize | E::InvalidFloatSize => {
                format!(
                    "runs an instruction the emulator doesn't support (at {})",
                    self.describe(a)
                )
            }
            other => format!("emulation stopped: {other:?} at {a:#x}"),
        }
    }
}

fn reg(vm: &icicle_vm::Vm, name: &str) -> Result<pcode::VarNode, String> {
    vm.cpu
        .arch
        .sleigh
        .get_varnode(name)
        .ok_or_else(|| format!("the x86-64 specification has no register {name}"))
}

fn read_mem(vm: &mut icicle_vm::Vm, address: u64, len: usize) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; len];
    vm.cpu.mem.read_bytes(address, &mut buf, perm::READ).ok()?;
    Some(buf)
}

/// The candidate's import call as the stand-ins see it: argument registers, stack arguments above the return
/// address, and memory it may read.
struct EmuView<'v> {
    vm: RefCell<&'v mut icicle_vm::Vm>,
}

impl CallView for EmuView<'_> {
    fn arg(&self, i: usize) -> Option<u64> {
        let mut vm = self.vm.borrow_mut();
        if let Some(name) = ["RCX", "RDX", "R8", "R9"].get(i) {
            let r = reg(&vm, name).ok()?;
            return Some(vm.cpu.read_reg(r));
        }
        // At the trap, [rsp] is the return address: the fifth argument is at rsp + 0x28.
        let rsp = reg(&vm, "RSP").ok()?;
        let rsp = vm.cpu.read_reg(rsp);
        let b = read_mem(&mut vm, rsp + 8 * (i as u64 + 1), 8)?;
        Some(u64::from_le_bytes(b.try_into().ok()?))
    }

    fn read(&self, address: u64, len: usize) -> Option<Vec<u8>> {
        read_mem(&mut self.vm.borrow_mut(), address, len)
    }
}

/// Runs the function at `setup.rva` with the recorded entry state. `Err` is why the case can't be judged.
pub fn run(setup: &Setup) -> Result<Ran, String> {
    VM.with(|cell| {
        let mut slot = cell.borrow_mut();
        if slot.is_none() {
            *slot = Some(new_vm()?);
        }
        let vm = slot.as_mut().expect("built above");
        // Reset first: it drops every translated block, so the last case's breakpoints can then be removed
        // (icicle decrements a count on blocks that hold one, and blocks translated after a breakpoint was set
        // never counted it).
        vm.reset();
        for b in vm.breakpoints() {
            vm.remove_breakpoint(b);
        }
        run_on(vm, setup)
    })
}

fn mem_err(e: impl std::fmt::Debug) -> String {
    format!("icicle: {e:?}")
}

fn map(vm: &mut icicle_vm::Vm, start: u64, len: u64, perm: u8, value: u8) -> Result<(), String> {
    if vm
        .cpu
        .mem
        .map_memory_len(start, len, Mapping { perm, value })
    {
        Ok(())
    } else {
        Err(format!("icicle couldn't map {len:#x} bytes at {start:#x}"))
    }
}

fn run_on(vm: &mut icicle_vm::Vm, setup: &Setup) -> Result<Ran, String> {
    let image = setup.image;
    let region_pages = page_ranges(setup.regions);
    let mut taken = region_pages.clone();
    let base = place(
        image.size(),
        &mut taken,
        std::iter::once(image.preferred_base)
            .chain((1..256u64).map(|i| 0x7000_0000_0000 + i * 0x1_0000_0000)),
    )
    .ok_or("no room for the image clear of the recorded memory")?;
    let stack_base = place(STACK_SIZE, &mut taken, (1..4096u64).map(|i| i * 0x100_0000))
        .ok_or("no room for a stack clear of the recorded memory")?;
    let import_count = image.imports.len() as u64;
    let traps_len = 16 * (import_count + 1);
    let traps = place(
        traps_len,
        &mut taken,
        (1..4096u64).map(|i| 0x6000_0000_0000 + i * 0x100_0000),
    )
    .ok_or("no room for import traps")?;
    let import_trap = |i: u64| traps + 16 * (i + 1);
    let layout = Layout {
        image: base..base + image.size(),
        writable_sections: image
            .sections
            .iter()
            .filter(|s| s.writable)
            .map(|s| base + u64::from(s.rva)..base + u64::from(s.rva) + u64::from(s.size))
            .collect(),
        imports: import_trap(0)..traps + page_up(traps_len),
        import_names: image.imports.iter().map(|(_, n)| n.clone()).collect(),
        import_first: import_trap(0),
        return_trap: traps,
    };

    // The image: mapped unreadable, then each part given what the function may do with it.
    let mut memory = image.loaded_at(base);
    for (i, (slot, _)) in image.imports.iter().enumerate() {
        let s = *slot as usize;
        if let Some(b) = memory.get_mut(s..s + 8) {
            b.copy_from_slice(&import_trap(i as u64).to_le_bytes());
        }
    }
    if let Some(r) = image.security_cookie {
        let r = r as usize;
        memory[r..r + 8].copy_from_slice(&SECURITY_COOKIE.to_le_bytes());
    }
    for g in setup.globals {
        let at = g.address as usize;
        memory
            .get_mut(at..at + g.bytes.len())
            .ok_or("a recorded global is outside the new image")?
            .copy_from_slice(&g.bytes);
    }
    map(vm, base, image.size(), perm::NONE, 0)?;
    let mem = &mut vm.cpu.mem;
    mem.write_bytes(base, &memory, perm::NONE)
        .map_err(mem_err)?;
    mem.update_perm(base, PAGE.min(image.size()), perm::READ)
        .map_err(mem_err)?;
    for s in image.sections.iter().filter(|s| s.size > 0) {
        let p = if s.executable {
            perm::READ | perm::EXEC
        } else if s.writable {
            perm::NONE
        } else {
            perm::READ
        };
        mem.update_perm(base + u64::from(s.rva), u64::from(s.size), p)
            .map_err(mem_err)?;
    }
    if let Some(r) = image.security_cookie {
        mem.update_perm(base + u64::from(r), 8, perm::READ)
            .map_err(mem_err)?;
    }
    for g in setup.globals.iter().filter(|g| !g.bytes.is_empty()) {
        mem.update_perm(
            base + g.address,
            g.bytes.len() as u64,
            perm::READ | perm::WRITE,
        )
        .map_err(mem_err)?;
    }

    // Traps (each one a breakpoint), the stack, and the recorded memory: its pages mapped unreadable and zeroed,
    // the 32-byte blocks around each region readable (vectorized over-reads read zeros), the region itself
    // readable and writable.
    map(vm, traps, page_up(traps_len), perm::READ | perm::EXEC, 0xcc)?;
    map(vm, stack_base, STACK_SIZE, perm::READ | perm::WRITE, 0)?;
    for p in &region_pages {
        map(vm, p.start, p.end - p.start, perm::NONE, 0)?;
    }
    let mem = &mut vm.cpu.mem;
    for r in setup.regions.iter().filter(|r| !r.bytes.is_empty()) {
        let start = r.address & !(SLACK - 1);
        let end = (r.address + r.bytes.len() as u64).div_ceil(SLACK) * SLACK;
        mem.update_perm(start, end - start, perm::READ)
            .map_err(mem_err)?;
    }
    for r in setup.regions.iter().filter(|r| !r.bytes.is_empty()) {
        mem.update_perm(r.address, r.bytes.len() as u64, perm::READ | perm::WRITE)
            .map_err(mem_err)?;
        mem.write_bytes(r.address, &r.bytes, perm::NONE)
            .map_err(mem_err)?;
    }

    // Entry state: [rsp] the return trap, then the shadow space, then the recorded stack arguments.
    let rsp0 = ((stack_base + STACK_SIZE - 0x1000) & !0xf) - 8; // as after a `call`
    mem.write_bytes(rsp0, &layout.return_trap.to_le_bytes(), perm::NONE)
        .map_err(mem_err)?;
    for (i, w) in setup.entry.stack.iter().enumerate() {
        mem.write_bytes(rsp0 + 0x28 + 8 * i as u64, &w.0.to_le_bytes(), perm::NONE)
            .map_err(mem_err)?;
    }
    for name in [
        "RAX", "RBX", "RBP", "RSI", "RDI", "R10", "R11", "R12", "R13", "R14", "R15",
    ] {
        let r = reg(vm, name)?;
        vm.cpu.write_reg(r, 0);
    }
    for (name, v) in [
        ("RSP", rsp0),
        ("RCX", setup.entry.rcx.0),
        ("RDX", setup.entry.rdx.0),
        ("R8", setup.entry.r8.0),
        ("R9", setup.entry.r9.0),
        ("MXCSR", 0x1f80),
    ] {
        let r = reg(vm, name)?;
        vm.cpu.write_reg(r, v);
    }
    for (i, x) in setup.entry.xmm.iter().enumerate() {
        let lo = u64::from_le_bytes(x.0[..8].try_into().expect("8 bytes"));
        let hi = u64::from_le_bytes(x.0[8..].try_into().expect("8 bytes"));
        let (a, b) = (
            reg(vm, &format!("XMM{i}_Qa"))?,
            reg(vm, &format!("XMM{i}_Qb"))?,
        );
        vm.cpu.write_reg(a, lo);
        vm.cpu.write_reg(b, hi);
    }

    vm.add_breakpoint(layout.return_trap);
    for i in 0..import_count {
        vm.add_breakpoint(import_trap(i));
    }
    let started_at = vm.cpu.icount;
    vm.icount_limit = started_at.saturating_add(MAX_INSTRUCTIONS);
    vm.cpu.write_pc(base + setup.rva);
    let mut stand_ins = setup.imports.clone();
    let mut import_calls = 0;
    loop {
        match vm.run() {
            VmExit::Breakpoint => {
                let pc = vm.cpu.read_pc();
                if pc == layout.return_trap {
                    break;
                }
                let name = layout
                    .import_names
                    .get(((pc - layout.import_first) / 16) as usize)
                    .cloned()
                    .unwrap_or_else(|| "?".into());
                let effect = {
                    let view = EmuView {
                        vm: RefCell::new(vm),
                    };
                    match imports::execute(&name, &view) {
                        Some(ran) => ran?,
                        None => {
                            let Some(s) = stand_ins.as_mut() else {
                                return Err(format!("calls the import {name}"));
                            };
                            s.call(&name, &view)?
                        }
                    }
                };
                // Make the import's writes (only where the function may write), set its result, return.
                for (at, bytes) in &effect.writes {
                    vm.cpu.mem.write_bytes(*at, bytes, perm::WRITE).map_err(|_| {
                        format!(
                            "the recorded {name} wrote at {at:#x}, outside the recorded memory, the globals and \
                             the stack"
                        )
                    })?;
                }
                let (rax, rsp) = (reg(vm, "RAX")?, reg(vm, "RSP")?);
                vm.cpu.write_reg(rax, effect.rax);
                let sp = vm.cpu.read_reg(rsp);
                let ret = read_mem(vm, sp, 8)
                    .ok_or_else(|| format!("returning from the stand-in for {name}: no stack"))?;
                vm.cpu.write_reg(rsp, sp + 8);
                vm.cpu
                    .write_pc(u64::from_le_bytes(ret.try_into().expect("8 bytes")));
                import_calls += 1;
            }
            VmExit::InstructionLimit => {
                return Err(format!(
                    "didn't return within {MAX_INSTRUCTIONS} instructions"
                ));
            }
            VmExit::UnhandledException((code, value)) => return Err(layout.why(code, value)),
            other => return Err(format!("emulation stopped: {other:?}")),
        }
    }
    let rsp = reg(vm, "RSP")?;
    if vm.cpu.read_reg(rsp) != rsp0 + 8 {
        return Err("returned with an unbalanced stack".into());
    }
    if let Some(s) = &mut stand_ins {
        s.finish()?;
    }
    let rax = reg(vm, "RAX")?;
    let rax = vm.cpu.read_reg(rax);
    let (lo, hi) = (reg(vm, "XMM0_Qa")?, reg(vm, "XMM0_Qb")?);
    let mut xmm0 = [0u8; 16];
    xmm0[..8].copy_from_slice(&vm.cpu.read_reg(lo).to_le_bytes());
    xmm0[8..].copy_from_slice(&vm.cpu.read_reg(hi).to_le_bytes());
    let read_back = |vm: &mut icicle_vm::Vm, at: u64, len: usize| -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; len];
        vm.cpu
            .mem
            .read_bytes(at, &mut buf, perm::NONE)
            .map_err(mem_err)?;
        Ok(buf)
    };
    let regions = setup
        .regions
        .iter()
        .map(|r| read_back(vm, r.address, r.bytes.len()))
        .collect::<Result<Vec<_>, _>>()?;
    let globals = setup
        .globals
        .iter()
        .map(|g| read_back(vm, base + g.address, g.bytes.len()))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Ran {
        rax,
        xmm0,
        regions,
        globals,
        import_calls,
        instructions: vm.cpu.icount - started_at,
        image: base..base + image.size(),
    })
}
