//! Running one function of the new build in Unicorn (design §7.3, replay by emulation).
//!
//! The address space holds only what the replay is entitled to:
//! - the new image at a base clear of the recorded memory (rebased if needed), its import address table pointing
//!   at trap addresses;
//! - the recorded memory at the addresses it had when recorded (pointer arguments keep their values);
//! - a fresh stack, whose return address is a trap: reaching it means the function returned.
//!
//! Anything else stops the run, and the case is inconclusive, never a pass: a call into an import, a read of a
//! writable image section (mutable global state the recording didn't capture; `__security_cookie` excepted),
//! a write anywhere but the stack and the recorded memory, a read of memory nobody recorded, an interrupt or
//! `syscall`, an instruction Unicorn can't run, or running out of instructions.
//!
//! Reads of uncaptured bytes in a 32-byte-aligned block that also holds captured bytes are allowed (they read
//! zeros): vectorized string and memory code reads whole aligned blocks past the end of its data, which can't
//! change a correct result. **[Guess]** at 32 (AVX2's width).

use crate::image::{Image, PAGE, page_up};
use permanent_beta_model::EntryState;
use std::ops::Range;
use unicorn_engine::{
    Arch, HookType, MemType, Mode, Prot, RegisterX86, SECOND_SCALE, Unicorn, X86Insn,
};

/// Most instructions one case may run. **[Guess]**
pub const MAX_INSTRUCTIONS: usize = 10_000_000;
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ran {
    pub rax: u64,
    pub xmm0: [u8; 16],
    /// Each placed region's bytes after the call, in `Setup::regions` order.
    pub regions: Vec<Vec<u8>>,
    pub instructions: u64,
}

struct State {
    image: Range<u64>,
    stack: Range<u64>,
    regions: Vec<Range<u64>>,
    readonly: Vec<Range<u64>>,
    cookie: Option<Range<u64>>,
    imports: Range<u64>,
    import_names: Vec<String>,
    violation: Option<String>,
    instructions: u64,
}

fn inside(ranges: &[Range<u64>], a: u64) -> bool {
    ranges.iter().any(|r| r.contains(&a))
}

impl State {
    fn byte_readable(&self, a: u64) -> bool {
        if self.stack.contains(&a)
            || inside(&self.regions, a)
            || inside(&self.readonly, a)
            || self.cookie.as_ref().is_some_and(|c| c.contains(&a))
        {
            return true;
        }
        let block = a & !(SLACK - 1);
        self.regions
            .iter()
            .any(|r| block < r.end && block + SLACK > r.start)
    }

    fn byte_writable(&self, a: u64) -> bool {
        self.stack.contains(&a) || inside(&self.regions, a)
    }

    /// Where an address is, for a reason: an image RVA, or the address.
    fn describe(&self, a: u64) -> String {
        if self.image.contains(&a) {
            format!("RVA {:#x} of the image", a - self.image.start)
        } else {
            format!("{a:#x}")
        }
    }

    fn stop(&mut self, why: String) {
        self.violation.get_or_insert(why);
    }
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

fn err(e: impl std::fmt::Debug) -> String {
    format!("Unicorn: {e:?}")
}

/// Runs the function at `setup.rva` with the recorded entry state. `Err` is why the case can't be judged.
pub fn run(setup: &Setup) -> Result<Ran, String> {
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
    let return_trap = traps;
    let import_trap = |i: u64| traps + 16 * (i + 1);

    let mut readonly: Vec<Range<u64>> =
        std::iter::once(base..base + PAGE.min(image.size())).collect();
    for s in &image.sections {
        if !s.writable {
            let start = base + u64::from(s.rva);
            readonly.push(start..start + u64::from(s.size));
        }
    }
    let cookie = image
        .security_cookie
        .map(|r| base + u64::from(r)..base + u64::from(r) + 8);
    let stack_top = stack_base + STACK_SIZE;
    let state = State {
        image: base..base + image.size(),
        stack: stack_base..stack_top,
        regions: setup
            .regions
            .iter()
            .map(|r| r.address..r.address + r.bytes.len() as u64)
            .collect(),
        readonly,
        cookie,
        imports: import_trap(0)..traps + page_up(traps_len),
        import_names: image.imports.iter().map(|(_, n)| n.clone()).collect(),
        violation: None,
        instructions: 0,
    };

    let mut uc = Unicorn::new_with_data(Arch::X86, Mode::MODE_64, state).map_err(err)?;

    // The image: everything readable and writable to Unicorn, code executable; the hooks below decide what the
    // function may actually read and write.
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
    uc.mem_map(base, image.size(), Prot::READ | Prot::WRITE)
        .map_err(err)?;
    uc.mem_write(base, &memory).map_err(err)?;
    for s in image.sections.iter().filter(|s| s.executable) {
        uc.mem_protect(
            base + u64::from(s.rva),
            u64::from(s.size),
            Prot::READ | Prot::EXEC,
        )
        .map_err(err)?;
    }
    uc.mem_map(traps, page_up(traps_len), Prot::READ | Prot::EXEC)
        .map_err(err)?;
    uc.mem_write(traps, &vec![0xcc; page_up(traps_len) as usize])
        .map_err(err)?;
    uc.mem_map(stack_base, STACK_SIZE, Prot::READ | Prot::WRITE)
        .map_err(err)?;
    for p in &region_pages {
        uc.mem_map(p.start, p.end - p.start, Prot::READ | Prot::WRITE)
            .map_err(err)?;
    }
    for r in setup.regions {
        uc.mem_write(r.address, &r.bytes).map_err(err)?;
    }

    // Entry state: [rsp] the return trap, then the shadow space, then the recorded stack arguments.
    let rsp = (stack_top - 0x1000) & !0xf;
    let rsp = rsp - 8; // as after a `call`: rsp + 8 is 16-byte aligned
    uc.mem_write(rsp, &return_trap.to_le_bytes()).map_err(err)?;
    for (i, w) in setup.entry.stack.iter().enumerate() {
        uc.mem_write(rsp + 0x28 + 8 * i as u64, &w.0.to_le_bytes())
            .map_err(err)?;
    }
    for reg in [
        RegisterX86::RAX,
        RegisterX86::RBX,
        RegisterX86::RBP,
        RegisterX86::RSI,
        RegisterX86::RDI,
        RegisterX86::R10,
        RegisterX86::R11,
        RegisterX86::R12,
        RegisterX86::R13,
        RegisterX86::R14,
        RegisterX86::R15,
    ] {
        uc.reg_write(reg, 0).map_err(err)?;
    }
    uc.reg_write(RegisterX86::RSP, rsp).map_err(err)?;
    uc.reg_write(RegisterX86::RCX, setup.entry.rcx.0)
        .map_err(err)?;
    uc.reg_write(RegisterX86::RDX, setup.entry.rdx.0)
        .map_err(err)?;
    uc.reg_write(RegisterX86::R8, setup.entry.r8.0)
        .map_err(err)?;
    uc.reg_write(RegisterX86::R9, setup.entry.r9.0)
        .map_err(err)?;
    for (reg, x) in [
        RegisterX86::XMM0,
        RegisterX86::XMM1,
        RegisterX86::XMM2,
        RegisterX86::XMM3,
    ]
    .into_iter()
    .zip(&setup.entry.xmm)
    {
        uc.reg_write_long(reg, &x.0).map_err(err)?;
    }
    uc.reg_write(RegisterX86::MXCSR, 0x1f80).map_err(err)?;
    uc.reg_write(RegisterX86::RFLAGS, 0x202).map_err(err)?;

    uc.add_mem_hook(HookType::MEM_READ | HookType::MEM_WRITE, 1, 0, |uc, kind, a, size, _| {
        let s = uc.get_data_mut();
        let mut range = a..a.saturating_add(size as u64);
        let bad = if kind == MemType::WRITE {
            range.find(|&b| !s.byte_writable(b)).map(|b| {
                if s.image.contains(&b) {
                    format!("writes {}: global state", s.describe(b))
                } else {
                    format!("writes {b:#x}, outside the recorded memory and the stack")
                }
            })
        } else {
            range.find(|&b| !s.byte_readable(b)).map(|b| {
                if s.image.contains(&b) {
                    format!(
                        "reads {} in a writable section: mutable global state the recording didn't capture",
                        s.describe(b)
                    )
                } else if s.imports.contains(&b) {
                    format!("reads the import trap at {b:#x}")
                } else {
                    format!("reads {b:#x}, memory the recording didn't capture")
                }
            })
        };
        if let Some(why) = bad {
            s.stop(why);
            let _ = uc.emu_stop();
        }
        true
    })
    .map_err(err)?;
    uc.add_mem_hook(
        HookType::MEM_READ_UNMAPPED
            | HookType::MEM_WRITE_UNMAPPED
            | HookType::MEM_FETCH_UNMAPPED
            | HookType::MEM_FETCH_PROT,
        1,
        0,
        |uc, kind, a, _, _| {
            let what = match kind {
                MemType::FETCH_UNMAPPED | MemType::FETCH_PROT => "executes",
                MemType::WRITE_UNMAPPED => "writes",
                _ => "reads",
            };
            uc.get_data_mut()
                .stop(format!("{what} {a:#x}, which the recording didn't capture"));
            false
        },
    )
    .map_err(err)?;
    if import_count > 0 {
        // Code hook ranges are inclusive; begin > end would mean every address.
        let first = import_trap(0);
        uc.add_code_hook(first, import_trap(import_count) - 1, move |uc, a, _| {
            let s = uc.get_data_mut();
            let name = s
                .import_names
                .get(((a - first) / 16) as usize)
                .cloned()
                .unwrap_or_else(|| "?".into());
            s.stop(format!("calls the import {name}"));
            let _ = uc.emu_stop();
        })
        .map_err(err)?;
    }
    uc.add_code_hook(1, 0, |uc, _, _| {
        uc.get_data_mut().instructions += 1;
    })
    .map_err(err)?;
    uc.add_intr_hook(|uc, n| {
        uc.get_data_mut()
            .stop(format!("raises interrupt {n} (int3, int 2e, ...)"));
        let _ = uc.emu_stop();
    })
    .map_err(err)?;
    uc.add_insn_sys_hook(X86Insn::SYSCALL, 1, 0, |uc| {
        uc.get_data_mut().stop("makes a system call".into());
        let _ = uc.emu_stop();
    })
    .map_err(err)?;
    uc.add_insn_invalid_hook(|uc| {
        uc.get_data_mut()
            .stop("runs an instruction the emulator doesn't support".into());
        false
    })
    .map_err(err)?;

    let started = uc.emu_start(
        base + setup.rva,
        return_trap,
        10 * SECOND_SCALE,
        MAX_INSTRUCTIONS,
    );
    if let Some(why) = uc.get_data_mut().violation.take() {
        return Err(why);
    }
    started.map_err(|e| format!("emulation stopped: {e:?}"))?;
    let rip = uc.reg_read(RegisterX86::RIP).map_err(err)?;
    if rip != return_trap {
        return Err(format!(
            "didn't return within {MAX_INSTRUCTIONS} instructions (or 10 s)"
        ));
    }
    if uc.reg_read(RegisterX86::RSP).map_err(err)? != rsp + 8 {
        return Err("returned with an unbalanced stack".into());
    }
    let rax = uc.reg_read(RegisterX86::RAX).map_err(err)?;
    let x = uc.reg_read_long(RegisterX86::XMM0).map_err(err)?;
    let mut xmm0 = [0u8; 16];
    xmm0.copy_from_slice(&x[..16]);
    let regions = setup
        .regions
        .iter()
        .map(|r| uc.mem_read_as_vec(r.address, r.bytes.len()).map_err(err))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Ran {
        rax,
        xmm0,
        regions,
        instructions: uc.get_data().instructions,
    })
}
