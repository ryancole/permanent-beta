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

use crate::address::{AddressMap, Rebase, Rewritten};
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
    /// Byte ranges (offsets into `bytes`) with no recorded value: a struct's fields the old build didn't have.
    /// Writable, unreadable until written.
    pub unknown: Vec<Range<usize>>,
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
    /// The recorded image's range and the address map: inputs holding a mapped old-image address get the new one.
    pub addresses: Option<(&'a Range<u64>, &'a AddressMap)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ran {
    pub rax: u64,
    pub xmm0: [u8; 16],
    /// Each placed region's bytes after the call, in `Setup::regions` order.
    pub regions: Vec<Vec<u8>>,
    /// Per region: the function freed it (`free`, or a `realloc` that moved it). What a freed block holds
    /// afterwards is the heap's business (the recorded bytes may be its bookkeeping), so it isn't compared.
    pub released: Vec<bool>,
    /// Each global's bytes after the call, in `Setup::globals` order.
    pub globals: Vec<Vec<u8>>,
    /// Import calls answered from the recording.
    pub import_calls: usize,
    /// Where the new image was mapped: a pointer into it is the new build's address of something.
    pub image: Range<u64>,
    /// Old-image addresses in the inputs rewritten to the new image.
    pub rewritten: Rewritten,
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
        // Memory is readable only where something was placed or written (INIT): a heap block replay hands out
        // becomes readable byte by byte as the function writes it, so reading what it never wrote is
        // inconclusive, not garbage. Everything else is granted INIT with its read permission.
        track_uninitialized: true,
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
    vm.cpu
        .mem
        .read_bytes(address, &mut buf, perm::READ | perm::INIT)
        .ok()?;
    Some(buf)
}

/// The candidate's import call as the stand-ins see it: argument registers, stack arguments above the return
/// address, and memory it may read: only memory something put there (`exact`: the recorded memory, the globals,
/// the image, the stack, handed-out heap blocks), never the zeros around recorded regions that let vectorized
/// code over-read: an executed `memcpy` would take them for data.
struct EmuView<'v> {
    vm: RefCell<&'v mut icicle_vm::Vm>,
    exact: &'v [Range<u64>],
}

/// Whether `ranges` cover every byte of `want`.
fn covered(ranges: &[Range<u64>], want: Range<u64>) -> bool {
    let mut at = want.start;
    while at < want.end {
        match ranges
            .iter()
            .filter(|r| r.contains(&at))
            .map(|r| r.end)
            .max()
        {
            Some(end) => at = end,
            None => return false,
        }
    }
    true
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
        if !covered(self.exact, address..address.checked_add(len as u64)?) {
            return None;
        }
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
    // The recorded heap blocks the stand-ins will hand out, reserved like the recorded memory.
    let allocations = setup
        .imports
        .as_ref()
        .map(StandIns::allocations)
        .unwrap_or_default();
    let reserved: Vec<Placed> = allocations
        .iter()
        .map(|r| Placed {
            address: r.start,
            bytes: vec![0; (r.end - r.start) as usize],
            unknown: Vec::new(),
        })
        .collect();
    let region_pages = page_ranges(&[setup.regions, &reserved].concat());
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

    // Old-image addresses in the inputs, rewritten to the new image where the map knows them.
    let rebase = setup.addresses.map(|(old_image, map)| Rebase {
        map,
        old_image,
        new_base: base,
    });
    let mut rewritten = Rewritten::default();
    let mut word = |v: u64| match rebase.and_then(|r| r.address(v)) {
        Some((new, kind)) => {
            rewritten.count(kind);
            new
        }
        None => v,
    };
    let entry_regs = [
        word(setup.entry.rcx.0),
        word(setup.entry.rdx.0),
        word(setup.entry.r8.0),
        word(setup.entry.r9.0),
    ];
    let stack_args: Vec<u64> = setup.entry.stack.iter().map(|w| word(w.0)).collect();
    let rebased = |address: u64, bytes: &[u8], n: &mut Rewritten| {
        let mut b = bytes.to_vec();
        if let Some(r) = rebase {
            n.add(r.rewrite(address, &mut b));
        }
        b
    };
    let global_bytes: Vec<Vec<u8>> = setup
        .globals
        .iter()
        .map(|g| rebased(base + g.address, &g.bytes, &mut rewritten))
        .collect();
    let region_bytes: Vec<Vec<u8>> = setup
        .regions
        .iter()
        .map(|r| rebased(r.address, &r.bytes, &mut rewritten))
        .collect();

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
    for (g, bytes) in setup.globals.iter().zip(&global_bytes) {
        let at = g.address as usize;
        memory
            .get_mut(at..at + bytes.len())
            .ok_or("a recorded global is outside the new image")?
            .copy_from_slice(bytes);
    }
    map(vm, base, image.size(), perm::NONE, 0)?;
    let mem = &mut vm.cpu.mem;
    mem.write_bytes(base, &memory, perm::NONE)
        .map_err(mem_err)?;
    mem.update_perm(base, PAGE.min(image.size()), perm::READ | perm::INIT)
        .map_err(mem_err)?;
    for s in image.sections.iter().filter(|s| s.size > 0) {
        let p = if s.executable {
            perm::READ | perm::EXEC | perm::INIT
        } else if s.writable {
            perm::NONE
        } else {
            perm::READ | perm::INIT
        };
        mem.update_perm(base + u64::from(s.rva), u64::from(s.size), p)
            .map_err(mem_err)?;
    }
    if let Some(r) = image.security_cookie {
        mem.update_perm(base + u64::from(r), 8, perm::READ | perm::INIT)
            .map_err(mem_err)?;
    }
    for g in setup.globals.iter().filter(|g| !g.bytes.is_empty()) {
        mem.update_perm(
            base + g.address,
            g.bytes.len() as u64,
            perm::READ | perm::WRITE | perm::INIT,
        )
        .map_err(mem_err)?;
    }

    // Traps (each one a breakpoint), the stack, and the recorded memory: its pages mapped unreadable and zeroed,
    // the 32-byte blocks around each region readable (vectorized over-reads read zeros), the region itself
    // readable and writable.
    map(
        vm,
        traps,
        page_up(traps_len),
        perm::READ | perm::EXEC | perm::INIT,
        0xcc,
    )?;
    map(
        vm,
        stack_base,
        STACK_SIZE,
        perm::READ | perm::WRITE | perm::INIT,
        0,
    )?;
    for p in &region_pages {
        map(vm, p.start, p.end - p.start, perm::NONE, 0)?;
    }
    let mem = &mut vm.cpu.mem;
    for r in setup.regions.iter().filter(|r| !r.bytes.is_empty()) {
        let start = r.address & !(SLACK - 1);
        let end = (r.address + r.bytes.len() as u64).div_ceil(SLACK) * SLACK;
        mem.update_perm(start, end - start, perm::READ | perm::INIT)
            .map_err(mem_err)?;
    }
    for (r, bytes) in setup.regions.iter().zip(&region_bytes) {
        if bytes.is_empty() {
            continue;
        }
        mem.update_perm(
            r.address,
            bytes.len() as u64,
            perm::READ | perm::WRITE | perm::INIT,
        )
        .map_err(mem_err)?;
        mem.write_bytes(r.address, bytes, perm::NONE)
            .map_err(mem_err)?;
        for u in &r.unknown {
            mem.update_perm(
                r.address + u.start as u64,
                (u.end - u.start) as u64,
                perm::READ | perm::WRITE,
            )
            .map_err(mem_err)?;
        }
    }

    // Entry state: [rsp] the return trap, then the shadow space, then the recorded stack arguments.
    let rsp0 = ((stack_base + STACK_SIZE - 0x1000) & !0xf) - 8; // as after a `call`
    mem.write_bytes(rsp0, &layout.return_trap.to_le_bytes(), perm::NONE)
        .map_err(mem_err)?;
    for (i, w) in stack_args.iter().enumerate() {
        mem.write_bytes(rsp0 + 0x28 + 8 * i as u64, &w.to_le_bytes(), perm::NONE)
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
        ("RCX", entry_regs[0]),
        ("RDX", entry_regs[1]),
        ("R8", entry_regs[2]),
        ("R9", entry_regs[3]),
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
    let mut heap_blocks: Vec<Range<u64>> = Vec::new();
    let mut released = vec![false; setup.regions.len()];
    // What an import may read: what something put there (see EmuView).
    let exact: Vec<Range<u64>> = setup
        .regions
        .iter()
        .map(|r| r.address..r.address + r.bytes.len() as u64)
        .chain(std::iter::once(base..base + image.size()))
        .chain(std::iter::once(stack_base..stack_base + STACK_SIZE))
        .collect();
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
                    let mut exact = exact.clone();
                    exact.extend(heap_blocks.iter().cloned());
                    let view = EmuView {
                        vm: RefCell::new(vm),
                        exact: &exact,
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
                match effect.heap {
                    Some(imports::Heap::Allocate {
                        address,
                        size,
                        zeroed,
                    }) => {
                        // Not yet written: unreadable until the function writes it (INIT), unless zeroed.
                        let p =
                            perm::READ | perm::WRITE | if zeroed { perm::INIT } else { perm::NONE };
                        vm.cpu.mem.update_perm(address, size, p).map_err(|_| {
                            format!("{name}: couldn't hand out {size:#x} bytes at {address:#x}")
                        })?;
                        if zeroed {
                            vm.cpu
                                .mem
                                .write_bytes(address, &vec![0; size as usize], perm::NONE)
                                .map_err(mem_err)?;
                        }
                        heap_blocks.push(address..address + size);
                    }
                    Some(imports::Heap::Free { address }) => {
                        // A block this run handed out, or recorded memory the function was given.
                        if let Some(b) =
                            take_block(&mut heap_blocks, setup.regions, &mut released, address)
                        {
                            vm.cpu
                                .mem
                                .update_perm(b.start, b.end - b.start, perm::NONE)
                                .map_err(mem_err)?;
                        }
                    }
                    Some(imports::Heap::Reallocate { from, to, size }) => {
                        let old = take_block(&mut heap_blocks, setup.regions, &mut released, from)
                            .ok_or_else(|| {
                                format!(
                                    "{name} of {from:#x}: not a block replay handed out or the recording holds                                      from its start"
                                )
                            })?;
                        reallocate(vm, old, to, size)?;
                        if to == from {
                            // In place: the recorded region (if it was one) is still the function's memory.
                            for (i, r) in setup.regions.iter().enumerate() {
                                if r.address == from {
                                    released[i] = false;
                                }
                            }
                        }
                        heap_blocks.push(to..to + size);
                    }
                    None => {}
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
        released,
        globals,
        import_calls,
        instructions: vm.cpu.icount - started_at,
        image: base..base + image.size(),
        rewritten,
    })
}

/// Takes the block starting at `address` out of what the function holds: a block this run handed out, or else a
/// recorded region starting there (marked released). `None` if it's neither.
fn take_block(
    heap_blocks: &mut Vec<Range<u64>>,
    regions: &[Placed],
    released: &mut [bool],
    address: u64,
) -> Option<Range<u64>> {
    if let Some(i) = heap_blocks.iter().position(|b| b.start == address) {
        // A recorded region grown or shrunk in place is one of these now: it goes too.
        for (r, gone) in regions.iter().zip(released.iter_mut()) {
            if r.address == address {
                *gone = true;
            }
        }
        return Some(heap_blocks.remove(i));
    }
    let i = regions
        .iter()
        .enumerate()
        .position(|(i, r)| r.address == address && !r.bytes.is_empty() && !released[i])?;
    released[i] = true;
    Some(address..address + regions[i].bytes.len() as u64)
}

/// `realloc` of `old` to `size` bytes at `to`: the bytes the function may read (written, or placed) in the first
/// `min(old, size)` move along, and the rest of the new block is writable but unreadable until written. Moved,
/// the old block is gone; in place, what's past the new size is.
fn reallocate(vm: &mut icicle_vm::Vm, old: Range<u64>, to: u64, size: u64) -> Result<(), String> {
    let keep = (old.end - old.start).min(size);
    let mem = &mut vm.cpu.mem;
    // Runs of readable bytes in what's kept, before any permission changes.
    let mut runs: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut at = 0;
    while at < keep {
        let readable = |a: u64| {
            let p = mem.get_perm(old.start + a);
            p & (perm::READ | perm::INIT) == perm::READ | perm::INIT
        };
        if !readable(at) {
            at += 1;
            continue;
        }
        let start = at;
        while at < keep && readable(at) {
            at += 1;
        }
        let mut bytes = vec![0u8; (at - start) as usize];
        mem.read_bytes(old.start + start, &mut bytes, perm::NONE)
            .map_err(mem_err)?;
        runs.push((start, bytes));
    }
    if to == old.start {
        if size > keep {
            mem.update_perm(to + keep, size - keep, perm::READ | perm::WRITE)
                .map_err(mem_err)?;
        } else if old.end > to + size {
            mem.update_perm(to + size, old.end - (to + size), perm::NONE)
                .map_err(mem_err)?;
        }
        return Ok(());
    }
    mem.update_perm(old.start, old.end - old.start, perm::NONE)
        .map_err(mem_err)?;
    mem.update_perm(to, size, perm::READ | perm::WRITE)
        .map_err(|_| format!("realloc: couldn't hand out {size:#x} bytes at {to:#x}"))?;
    // Writing marks the bytes initialized (readable).
    for (off, bytes) in runs {
        mem.write_bytes(to + off, &bytes, perm::NONE)
            .map_err(mem_err)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::covered;

    #[test]
    fn imports_read_only_memory_something_put_there() {
        let exact = [0x1000..0x1010, 0x1010..0x1020, 0x2000..0x2100];
        assert!(covered(&exact, 0x1008..0x1018), "across adjacent ranges");
        assert!(covered(&exact, 0x2000..0x2100));
        // Negative: one byte past a region (where the readable zeros for over-reads are), or a gap.
        assert!(!covered(&exact, 0x1018..0x1021));
        assert!(!covered(&exact, 0x1fff..0x2001));
    }
}
