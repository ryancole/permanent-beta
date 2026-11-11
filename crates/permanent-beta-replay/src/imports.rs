//! Standing in for import calls during a replay (design §7.3).
//!
//! An import (a function in a DLL) can't be emulated: its code isn't in the image. When the recorder intercepted
//! the module's imports (`TestCase::imports_recorded`), the case holds every import call the old function made,
//! in order, with its arguments, what it returned and the memory behind its arguments. The replay then answers
//! the candidate's import calls from the recording, one by one, but only for imports whose effects it models
//! here, and only after checking that the candidate passes the same inputs:
//!
//! - `__acrt_iob_func(index)`: returns the recorded `FILE*` for the same index.
//! - `__stdio_common_vfprintf(options, stream, format, locale, va_list)`: same options, stream and locale, the
//!   same format string, and the same value for every conversion; returns the recorded count. What it printed
//!   isn't in memory, so equal inputs are what make it the same call.
//! - `__stdio_common_vsprintf(options, buffer, count, format, locale, va_list)`: the same checks and count, then
//!   writes the bytes the recorded call wrote into its buffer (`min(result + 1, count)`) into the candidate's.
//! - `malloc`, `calloc`, `free`, `realloc`: the same request (block and size), answered with the recorded block
//!   at its recorded address ([`Heap`]). A `realloc` that moved the block carries over the bytes the function may
//!   read; what it added is unreadable until written.
//!
//! Conversions are compared by meaning, not by bits: integers at their width (the rest of an 8-byte `va_list` slot
//! can hold anything), doubles by their 8 bytes, `%s` by the string's content (a string literal's address
//! differs between builds). `%p`, `%n`, wide strings and anything else the parser doesn't know can't be
//! compared: inconclusive.
//!
//! A refusal is always **inconclusive**, never a fail: an import with no model, a call out of the recorded order,
//! more or fewer import calls than recorded, memory the recording doesn't hold, and also different inputs. The
//! import may be called by a callee whose behaviour changed while the hooked function didn't (the hook loop's v2
//! `log_event` prints a severity; `order_add` and `ship_order`, which call it, are the same functions). What the
//! function itself returns and writes is still compared, and a difference there fails the case.

use crate::recording::LoadedImport;

/// Most bytes of a format string or a `%s` argument read. **[Guess]**
pub const MAX_STRING: usize = 4096;

/// Why a stand-in can't answer: the case is inconclusive.
pub type Refusal = String;

/// What the stand-in does in place of the import: the value it returns, and the bytes it writes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Effect {
    pub rax: u64,
    pub writes: Vec<(u64, Vec<u8>)>,
    /// A heap block the call allocated or freed.
    pub heap: Option<Heap>,
}

/// What a heap call did, for the emulator to mirror.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Heap {
    /// A block at `address`: writable, and readable byte by byte once written (`zeroed`: readable at once, all
    /// zeros, as `calloc` gives it).
    Allocate {
        address: u64,
        size: u64,
        zeroed: bool,
    },
    /// The block at `address` is gone: touching it is inconclusive.
    Free { address: u64 },
    /// `realloc`: the block at `from` is now `size` bytes at `to` (the same address when it grew or shrank in
    /// place). What the function had written in its first `min(old size, size)` bytes moves with it; the rest is
    /// unreadable until written. Moved, the old block is gone.
    Reallocate { from: u64, to: u64, size: u64 },
}

/// An import call's arguments and the memory they point to.
pub trait CallView {
    /// Integer argument slot `i`: 0–3 are rcx, rdx, r8, r9; 4 and up are on the stack.
    fn arg(&self, i: usize) -> Option<u64>;
    /// `len` bytes at `address`, if all of them are readable (recorded, for a recorded call).
    fn read(&self, address: u64, len: usize) -> Option<Vec<u8>>;
}

/// The bytes of the string at `address` up to its NUL (left out) or `max` bytes; `None` if neither is reached in
/// readable memory.
fn read_str(view: &dyn CallView, address: u64, max: usize) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    while out.len() < max {
        let b = view.read(address + out.len() as u64, 1)?[0];
        if b == 0 {
            return Some(out);
        }
        out.push(b);
    }
    Some(out)
}

/// A recorded import call, as a [`CallView`] over its snapshots (their bytes before the call).
pub struct Recorded<'a>(pub &'a LoadedImport);

impl CallView for Recorded<'_> {
    fn arg(&self, i: usize) -> Option<u64> {
        let e = &self.0.call.entry;
        match i {
            0..=3 => Some(e.int_reg(i as u8)),
            _ => e.stack.get(i - 4).map(|w| w.0),
        }
    }

    fn read(&self, address: u64, len: usize) -> Option<Vec<u8>> {
        self.0.memory.iter().find_map(|(at, before, _)| {
            let off = address.checked_sub(*at)? as usize;
            before.get(off..off.checked_add(len)?).map(<[u8]>::to_vec)
        })
    }
}

/// The name after `dll!`.
pub fn base_name(import: &str) -> &str {
    import.rsplit('!').next().unwrap_or(import)
}

/// The imports [`StandIns`] can answer for.
pub const MODELLED: [&str; 7] = [
    "__acrt_iob_func",
    "__stdio_common_vfprintf",
    "__stdio_common_vsprintf",
    "malloc",
    "calloc",
    "free",
    "realloc",
];

/// Largest heap block replay hands out. **[Guess]**
pub const MAX_ALLOCATION: u64 = 1 << 26;

/// CRT functions replay runs itself instead of answering from the recording: their effect follows from their
/// arguments and the memory they read, which the emulator checks like any other access (unrecorded memory is
/// refused). A build may inline them, or call them a different number of times, without behaving differently, so
/// recorded calls to them are skipped when matching the recorded sequence. The rotates are the `_rotl` family an
/// /Od build calls instead of inlining (zstd's xxHash). `memcmp` and `strcmp` aren't here: only the sign of their
/// result is defined, and a caller may keep the value.
pub const EXECUTED: [&str; 8] = [
    "memcpy", "memmove", "memset", "strlen", "_rotl", "_rotr", "_rotl64", "_rotr64",
];

/// Most bytes an executed function copies, sets or scans. **[Guess]**
pub const MAX_EXECUTED: u64 = 1 << 24;

/// Runs `import` if it's one of [`EXECUTED`]: `None` for any other import.
pub fn execute(import: &str, now: &dyn CallView) -> Option<Result<Effect, Refusal>> {
    let name = base_name(import);
    if !EXECUTED.contains(&name) {
        return None;
    }
    Some(execute_named(name, now))
}

fn execute_named(name: &str, now: &dyn CallView) -> Result<Effect, Refusal> {
    let arg = |i| arg_of(now, i, name);
    let len = |n: u64| -> Result<usize, Refusal> {
        if n > MAX_EXECUTED {
            return Err(format!("{name} of {n} bytes: more than replay runs"));
        }
        Ok(n as usize)
    };
    match name {
        // memcpy runs as memmove: the source is read before anything is written.
        "memcpy" | "memmove" => {
            let (dst, src, n) = (arg(0)?, arg(1)?, len(arg(2)?)?);
            let bytes = if n == 0 {
                Vec::new()
            } else {
                now.read(src, n).ok_or_else(|| {
                    format!(
                        "{name} reads {n} bytes at {src:#x}, memory the recording didn't capture"
                    )
                })?
            };
            Ok(Effect {
                rax: dst,
                writes: if n == 0 {
                    Vec::new()
                } else {
                    vec![(dst, bytes)]
                },
                heap: None,
            })
        }
        "memset" => {
            let (dst, c, n) = (arg(0)?, arg(1)? as u8, len(arg(2)?)?);
            Ok(Effect {
                rax: dst,
                writes: if n == 0 {
                    Vec::new()
                } else {
                    vec![(dst, vec![c; n])]
                },
                heap: None,
            })
        }
        "strlen" => {
            let at = arg(0)?;
            let s = read_str(now, at, MAX_EXECUTED as usize).ok_or_else(|| {
                format!("strlen reads at {at:#x}, memory the recording didn't capture")
            })?;
            if s.len() == MAX_EXECUTED as usize {
                return Err(format!("strlen: no NUL within {MAX_EXECUTED} bytes"));
            }
            Ok(Effect {
                rax: s.len() as u64,
                writes: Vec::new(),
                heap: None,
            })
        }
        // `_rotl(unsigned value, int shift)`: the shift is taken modulo the width, a negative one too.
        "_rotl" | "_rotr" | "_rotl64" | "_rotr64" => {
            let (value, shift) = (arg(0)?, arg(1)? as u32);
            let rax = match name {
                "_rotl" => u64::from((value as u32).rotate_left(shift % 32)),
                "_rotr" => u64::from((value as u32).rotate_right(shift % 32)),
                "_rotl64" => value.rotate_left(shift % 64),
                _ => value.rotate_right(shift % 64),
            };
            Ok(Effect {
                rax,
                writes: Vec::new(),
                heap: None,
            })
        }
        _ => unreachable!("EXECUTED lists {name}"),
    }
}

/// The recorded import calls of one case, answered in order.
#[derive(Debug, Clone)]
pub struct StandIns {
    calls: Vec<LoadedImport>,
    next: usize,
}

impl StandIns {
    pub fn new(calls: Vec<LoadedImport>) -> Self {
        Self { calls, next: 0 }
    }

    /// Stands in for the candidate's call to `import` (`dll!name`), whose arguments `now` shows.
    pub fn call(&mut self, import: &str, now: &dyn CallView) -> Result<Effect, Refusal> {
        self.skip_executed();
        let name = base_name(import);
        if !MODELLED.contains(&name) {
            return Err(format!(
                "calls the import {import}, which replay has no model of"
            ));
        }
        let Some(rec) = self.calls.get(self.next) else {
            return Err(format!(
                "calls {import} after the {} import call(s) the recording has",
                self.calls.len()
            ));
        };
        if base_name(&rec.call.import) != name {
            return Err(format!(
                "calls {import} where the recording called {}",
                rec.call.import
            ));
        }
        self.next += 1;
        let r = Recorded(rec);
        let rax = rec.call.observed.rax.0;
        match name {
            "__acrt_iob_func" => {
                same_value(name, now, &r, 0, 4, "index")?;
                Ok(Effect {
                    rax,
                    writes: Vec::new(),
                    heap: None,
                })
            }
            "__stdio_common_vfprintf" => {
                same_value(name, now, &r, 0, 8, "options")?;
                same_value(name, now, &r, 1, 8, "stream")?;
                same_value(name, now, &r, 3, 8, "locale")?;
                same_printf(name, now, &r, 2, 4)?;
                Ok(Effect {
                    rax,
                    writes: Vec::new(),
                    heap: None,
                })
            }
            "__stdio_common_vsprintf" => {
                same_value(name, now, &r, 0, 8, "options")?;
                same_value(name, now, &r, 2, 8, "count")?;
                same_value(name, now, &r, 4, 8, "locale")?;
                same_printf(name, now, &r, 3, 5)?;
                let result = rax as u32 as i32;
                if result < 0 {
                    return Err(format!(
                        "the recorded {name} returned {result}: what it wrote isn't modelled"
                    ));
                }
                let count = now.arg(2).unwrap_or(0);
                let n = (result as u64 + 1).min(count) as usize;
                if n == 0 {
                    return Ok(Effect {
                        rax,
                        writes: Vec::new(),
                        heap: None,
                    });
                }
                let (Some(old_buf), Some(new_buf)) = (r.arg(1), now.arg(1)) else {
                    return Err(format!("{name}: no buffer argument"));
                };
                let written = rec
                    .memory
                    .iter()
                    .find(|(at, _, after)| *at == old_buf && after.is_some())
                    .and_then(|(_, _, after)| after.as_ref())
                    .filter(|after| after.len() >= n)
                    .ok_or_else(|| {
                        format!("the recording doesn't hold the {n} bytes {name} wrote")
                    })?;
                Ok(Effect {
                    rax,
                    writes: vec![(new_buf, written[..n].to_vec())],
                    heap: None,
                })
            }
            // Heap calls (design §7.3): the recorded block, at its recorded address, for the same request. Replay
            // reserves every recorded block's address before placing anything else, so it's free.
            "malloc" | "calloc" => {
                let size = if name == "malloc" {
                    same_value(name, now, &r, 0, 8, "size")?;
                    arg_of(&r, 0, name)?
                } else {
                    same_value(name, now, &r, 0, 8, "count")?;
                    same_value(name, now, &r, 1, 8, "size")?;
                    arg_of(&r, 0, name)?
                        .checked_mul(arg_of(&r, 1, name)?)
                        .ok_or_else(|| format!("{name}: the size overflows"))?
                };
                if size > MAX_ALLOCATION {
                    return Err(format!(
                        "{name} of {size} bytes: more than replay hands out"
                    ));
                }
                Ok(Effect {
                    rax,
                    writes: Vec::new(),
                    heap: (rax != 0 && size > 0).then_some(Heap::Allocate {
                        address: rax,
                        size,
                        zeroed: name == "calloc",
                    }),
                })
            }
            "free" => {
                same_value(name, now, &r, 0, 8, "pointer")?;
                let address = arg_of(&r, 0, name)?;
                Ok(Effect {
                    rax: 0,
                    writes: Vec::new(),
                    heap: (address != 0).then_some(Heap::Free { address }),
                })
            }
            // The same block and size as recorded, answered with the recorded result: the UCRT's `realloc(NULL,
            // n)` allocates, `realloc(p, 0)` frees `p` and returns NULL, and a NULL result for `n > 0` leaves `p`
            // as it was.
            "realloc" => {
                same_value(name, now, &r, 0, 8, "pointer")?;
                same_value(name, now, &r, 1, 8, "size")?;
                let (from, size) = (arg_of(&r, 0, name)?, arg_of(&r, 1, name)?);
                if size > MAX_ALLOCATION {
                    return Err(format!(
                        "{name} to {size} bytes: more than replay hands out"
                    ));
                }
                let heap = match (from, size, rax) {
                    (0, 0, _) | (0, _, 0) => None,
                    (0, _, to) => Some(Heap::Allocate {
                        address: to,
                        size,
                        zeroed: false,
                    }),
                    (_, 0, 0) => Some(Heap::Free { address: from }),
                    (_, 0, _) => {
                        return Err(format!(
                            "the recorded {name} to 0 bytes returned {rax:#x}: what it did isn't modelled"
                        ));
                    }
                    (_, _, 0) => None,
                    (_, _, to) => Some(Heap::Reallocate { from, to, size }),
                };
                Ok(Effect {
                    rax,
                    writes: Vec::new(),
                    heap,
                })
            }
            _ => unreachable!("checked against MODELLED"),
        }
    }

    /// The blocks the recorded `malloc`, `calloc` and `realloc` calls returned, so the emulator can keep their
    /// addresses free.
    pub fn allocations(&self) -> Vec<std::ops::Range<u64>> {
        self.calls
            .iter()
            .filter_map(|c| {
                let r = Recorded(c);
                let size = match base_name(&c.call.import) {
                    "malloc" => r.arg(0)?,
                    "calloc" => r.arg(0)?.checked_mul(r.arg(1)?)?,
                    "realloc" => r.arg(1)?,
                    _ => return None,
                };
                let at = c.call.observed.rax.0;
                (at != 0 && size > 0 && size <= MAX_ALLOCATION).then(|| at..at + size)
            })
            .collect()
    }

    /// After the candidate returned: it must have made every recorded import call.
    /// Recorded calls to [`EXECUTED`] functions: replay ran its own.
    fn skip_executed(&mut self) {
        while self
            .calls
            .get(self.next)
            .is_some_and(|c| EXECUTED.contains(&base_name(&c.call.import)))
        {
            self.next += 1;
        }
    }

    pub fn finish(&mut self) -> Result<(), Refusal> {
        self.skip_executed();
        if self.next < self.calls.len() {
            return Err(format!(
                "made {} of the {} recorded import call(s) (next: {})",
                self.next,
                self.calls.len(),
                self.calls[self.next].call.import
            ));
        }
        Ok(())
    }
}

fn arg_of(view: &dyn CallView, i: usize, name: &str) -> Result<u64, Refusal> {
    view.arg(i)
        .ok_or_else(|| format!("{name}: argument {i} wasn't recorded"))
}

/// The low `width` bytes of argument `i` must be equal.
fn same_value(
    name: &str,
    now: &dyn CallView,
    rec: &dyn CallView,
    i: usize,
    width: u32,
    what: &str,
) -> Result<(), Refusal> {
    let mask = if width >= 8 {
        u64::MAX
    } else {
        (1u64 << (8 * width)) - 1
    };
    let (a, b) = (arg_of(now, i, name)? & mask, arg_of(rec, i, name)? & mask);
    if a != b {
        return Err(format!("calls {name} with {what} {a:#x}, recorded {b:#x}"));
    }
    Ok(())
}

/// What one `va_list` slot holds for a conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Slot {
    /// An integer of this many bytes (the rest of the 8-byte slot is ignored).
    Int(u32),
    Double,
    /// A narrow string, compared up to its NUL or the precision.
    Str {
        precision: Option<Precision>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Precision {
    Fixed(usize),
    /// `.*`: the previous slot (an `int`) holds it.
    FromArg,
}

/// The `va_list` slots a format consumes, in order. `Err` names a conversion that can't be compared.
fn slots(format: &[u8]) -> Result<Vec<Slot>, String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < format.len() {
        if format[i] != b'%' {
            i += 1;
            continue;
        }
        let start = i;
        i += 1;
        if format.get(i) == Some(&b'%') {
            i += 1;
            continue;
        }
        while format.get(i).is_some_and(|c| b"-+ #0".contains(c)) {
            i += 1;
        }
        if format.get(i) == Some(&b'*') {
            out.push(Slot::Int(4));
            i += 1;
        } else {
            while format.get(i).is_some_and(u8::is_ascii_digit) {
                i += 1;
            }
        }
        let mut precision = None;
        if format.get(i) == Some(&b'.') {
            i += 1;
            if format.get(i) == Some(&b'*') {
                out.push(Slot::Int(4));
                precision = Some(Precision::FromArg);
                i += 1;
            } else {
                let digits_start = i;
                while format.get(i).is_some_and(u8::is_ascii_digit) {
                    i += 1;
                }
                let n = std::str::from_utf8(&format[digits_start..i])
                    .ok()
                    .and_then(|d| d.parse().ok())
                    .unwrap_or(0);
                precision = Some(Precision::Fixed(n));
            }
        }
        // Size: hh h l ll L w I I32 I64 z j t.
        let rest = &format[i..];
        let (size, len) = [
            ("I64", 3),
            ("I32", 3),
            ("hh", 2),
            ("ll", 2),
            ("h", 1),
            ("l", 1),
            ("L", 1),
            ("w", 1),
            ("I", 1),
            ("z", 1),
            ("j", 1),
            ("t", 1),
        ]
        .iter()
        .find(|(p, _)| rest.starts_with(p.as_bytes()))
        .map_or(("", 0), |&(p, n)| (p, n));
        i += len;
        let conv = *format
            .get(i)
            .ok_or_else(|| "an unfinished conversion".to_owned())?;
        i += 1;
        let spec = String::from_utf8_lossy(&format[start..i]).into_owned();
        let wide_int = matches!(size, "ll" | "I64" | "I" | "z" | "j" | "t");
        out.push(match conv {
            b'd' | b'i' | b'o' | b'u' | b'x' | b'X' => Slot::Int(if wide_int { 8 } else { 4 }),
            b'c' if !matches!(size, "l" | "w") => Slot::Int(4),
            b'e' | b'E' | b'f' | b'F' | b'g' | b'G' | b'a' | b'A' => Slot::Double,
            b's' if !matches!(size, "l" | "w") => Slot::Str { precision },
            _ => return Err(format!("the conversion {spec:?}")),
        });
    }
    Ok(out)
}

/// The same format string and the same value for every conversion.
fn same_printf(
    name: &str,
    now: &dyn CallView,
    rec: &dyn CallView,
    format_arg: usize,
    list_arg: usize,
) -> Result<(), Refusal> {
    let format_now = read_str(now, arg_of(now, format_arg, name)?, MAX_STRING)
        .ok_or_else(|| format!("{name}: the format string can't be read"))?;
    let format_rec = read_str(rec, arg_of(rec, format_arg, name)?, MAX_STRING)
        .ok_or_else(|| format!("{name}: the recording doesn't hold the whole format string"))?;
    if format_now != format_rec {
        return Err(format!(
            "calls {name} with the format {:?}, recorded {:?}",
            String::from_utf8_lossy(&format_now),
            String::from_utf8_lossy(&format_rec)
        ));
    }
    let slots = slots(&format_now).map_err(|what| format!("{name}: can't compare {what}"))?;
    let (list_now, list_rec) = (arg_of(now, list_arg, name)?, arg_of(rec, list_arg, name)?);
    let word = |view: &dyn CallView, list: u64, k: usize| -> Option<u64> {
        let b = view.read(list + 8 * k as u64, 8)?;
        Some(u64::from_le_bytes(b.try_into().ok()?))
    };
    let mut last_int = 0u64;
    for (k, slot) in slots.iter().enumerate() {
        let a =
            word(now, list_now, k).ok_or_else(|| format!("{name}: argument {k} can't be read"))?;
        let b = word(rec, list_rec, k)
            .ok_or_else(|| format!("{name}: the recording doesn't hold argument {k}"))?;
        let differs = |shown_a: String, shown_b: String| {
            format!("calls {name} with argument {k} {shown_a}, recorded {shown_b}")
        };
        match *slot {
            Slot::Int(w) => {
                let mask = if w >= 8 {
                    u64::MAX
                } else {
                    (1u64 << (8 * w)) - 1
                };
                if a & mask != b & mask {
                    return Err(differs(format!("{}", a & mask), format!("{}", b & mask)));
                }
                last_int = a & mask;
            }
            Slot::Double => {
                if a != b {
                    return Err(differs(
                        format!("{}", f64::from_bits(a)),
                        format!("{}", f64::from_bits(b)),
                    ));
                }
            }
            Slot::Str { precision } => {
                let max = match precision {
                    Some(Precision::Fixed(n)) => n,
                    Some(Precision::FromArg) if (last_int as u32 as i32) >= 0 => {
                        last_int as u32 as usize
                    }
                    _ => MAX_STRING,
                };
                match (a, b) {
                    (0, 0) => {}
                    (0, _) | (_, 0) => {
                        return Err(differs(format!("{a:#x}"), format!("{b:#x}")));
                    }
                    _ => {
                        let s_now = read_str(now, a, max).ok_or_else(|| {
                            format!("{name}: the string argument {k} can't be read")
                        })?;
                        let s_rec = read_str(rec, b, max).ok_or_else(|| {
                            format!("{name}: the recording doesn't hold the string argument {k}")
                        })?;
                        if s_now != s_rec {
                            return Err(differs(
                                format!("{:?}", String::from_utf8_lossy(&s_now)),
                                format!("{:?}", String::from_utf8_lossy(&s_rec)),
                            ));
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use permanent_beta_model::{EntryState, ImportCall, Observed, Word, Xmm};
    use std::collections::BTreeMap;

    /// A candidate's call: arguments and a flat memory.
    struct Now {
        args: Vec<u64>,
        memory: BTreeMap<u64, u8>,
    }

    impl Now {
        fn put(&mut self, at: u64, bytes: &[u8]) {
            for (i, b) in bytes.iter().enumerate() {
                self.memory.insert(at + i as u64, *b);
            }
        }
    }

    impl CallView for Now {
        fn arg(&self, i: usize) -> Option<u64> {
            self.args.get(i).copied()
        }
        fn read(&self, address: u64, len: usize) -> Option<Vec<u8>> {
            (0..len as u64)
                .map(|i| self.memory.get(&(address + i)).copied())
                .collect()
        }
    }

    fn words(ws: &[u64]) -> Vec<u8> {
        ws.iter().flat_map(|w| w.to_le_bytes()).collect()
    }

    fn cstr(s: &str) -> Vec<u8> {
        let mut v = s.as_bytes().to_vec();
        v.push(0);
        v
    }

    fn recorded(
        import: &str,
        args: &[u64],
        rax: u64,
        memory: Vec<(u64, Vec<u8>, Option<Vec<u8>>)>,
    ) -> LoadedImport {
        let a = |i: usize| Word(args.get(i).copied().unwrap_or(0));
        LoadedImport {
            call: ImportCall {
                import: import.into(),
                entry: EntryState {
                    rcx: a(0),
                    rdx: a(1),
                    r8: a(2),
                    r9: a(3),
                    xmm: [Xmm::default(); 4],
                    stack: args.iter().skip(4).map(|&v| Word(v)).collect(),
                },
                observed: Observed {
                    rax: Word(rax),
                    xmm0: Xmm::default(),
                },
                memory: Vec::new(),
            },
            memory,
        }
    }

    const FMT: &str = "Receipt #%d for %s: %d lines, total %d.%02d";

    /// The recorded `snprintf(buf, 64, FMT, 1, "Ada", 5, 12, 34)` from format_receipt: buffer, format and va_list
    /// at old addresses.
    fn recorded_sprintf() -> LoadedImport {
        let out = "Receipt #1 for Ada: 5 lines, total 12.34";
        let mut after = cstr(out);
        after.resize(64, 0xee);
        recorded(
            "api-ms-win-crt-stdio-l1-1-0.dll!__stdio_common_vsprintf",
            &[0x26, 0x7000, 64, 0x8000, 0, 0x9000],
            out.len() as u64,
            vec![
                (0x7000, vec![0xee; 64], Some(after)),
                (0x8000, cstr(FMT), Some(cstr(FMT))),
                (
                    0x9000,
                    words(&[0xffff_ffff_0000_0001, 0xa000, 5, 12, 34]),
                    None,
                ),
                (0xa000, cstr("Ada"), None),
            ],
        )
    }

    /// The candidate's call: the same values, at new addresses.
    fn candidate(values: &[u64], format: &str, customer: &str) -> Now {
        let mut now = Now {
            args: vec![0x26, 0x17000, 64, 0x18000, 0, 0x19000],
            memory: BTreeMap::new(),
        };
        now.put(0x18000, &cstr(format));
        let mut w = values.to_vec();
        w[1] = 0x1a000;
        now.put(0x19000, &words(&w));
        now.put(0x1a000, &cstr(customer));
        now
    }

    #[test]
    fn the_same_sprintf_writes_what_was_recorded() {
        let mut s = StandIns::new(vec![recorded_sprintf()]);
        let now = candidate(&[1, 0, 5, 12, 34], FMT, "Ada");
        let e = s
            .call("ucrtbase.dll!__stdio_common_vsprintf", &now)
            .unwrap();
        assert_eq!(e.rax, 40);
        // The output and its NUL, at the candidate's buffer; nothing past it.
        assert_eq!(e.writes.len(), 1);
        assert_eq!(e.writes[0].0, 0x17000);
        assert_eq!(
            e.writes[0].1,
            cstr("Receipt #1 for Ada: 5 lines, total 12.34")
        );
        assert_eq!(s.finish(), Ok(()));
    }

    #[test]
    fn different_inputs_are_refused() {
        // Negative: another value, another string with the same address layout, another format, another count.
        for (now, what) in [
            (candidate(&[2, 0, 5, 12, 34], FMT, "Ada"), "argument 0"),
            (candidate(&[1, 0, 5, 12, 34], FMT, "Bob"), "argument 1"),
            (candidate(&[1, 0, 5, 12, 34], "Receipt %d", "Ada"), "format"),
        ] {
            let mut s = StandIns::new(vec![recorded_sprintf()]);
            match s.call("x!__stdio_common_vsprintf", &now) {
                Err(why) => assert!(why.contains(what), "{why}"),
                other => panic!("{what}: {other:?}"),
            }
        }
        let mut now = candidate(&[1, 0, 5, 12, 34], FMT, "Ada");
        now.args[2] = 32;
        let mut s = StandIns::new(vec![recorded_sprintf()]);
        assert!(
            matches!(s.call("x!__stdio_common_vsprintf", &now), Err(why) if why.contains("count"))
        );
    }

    #[test]
    fn what_cant_be_compared_is_inconclusive() {
        // Negative: %p, an import with no model, a call out of order, a missing call, more calls than recorded.
        let mut s = StandIns::new(vec![recorded_sprintf()]);
        let now = candidate(&[1, 0, 5, 12, 34], "%p", "Ada");
        assert!(s.call("x!__stdio_common_vsprintf", &now).is_err());
        assert!(slots(b"at %p").is_err());
        assert!(slots(b"%ls").is_err());
        assert!(slots(b"%n").is_err());

        let mut s = StandIns::new(vec![recorded_sprintf()]);
        assert!(matches!(s.call("kernel32.dll!Sleep", &now), Err(why) if why.contains("no model")));
        assert!(matches!(
            s.call("x!__acrt_iob_func", &now),
            Err(why) if why.contains("where the recording called")
        ));
        assert!(matches!(s.finish(), Err(why) if why.contains("made 0 of the 1")));

        let mut s = StandIns::new(Vec::new());
        assert!(matches!(
            s.call("x!__stdio_common_vsprintf", &now),
            Err(why) if why.contains("after the 0")
        ));
    }

    #[test]
    fn printf_through_the_recorded_stream() {
        let iob = recorded("x!__acrt_iob_func", &[1], 0x7ff0_0010, Vec::new());
        let fmt = "%s\n";
        let printf = recorded(
            "x!__stdio_common_vfprintf",
            &[0x24, 0x7ff0_0010, 0x8000, 0, 0x9000],
            41,
            vec![
                (0x8000, cstr(fmt), Some(cstr(fmt))),
                (0x9000, words(&[0xa000]), None),
                (0xa000, cstr("Receipt #1"), None),
            ],
        );
        let mut s = StandIns::new(vec![iob, printf]);
        let mut now = Now {
            args: vec![1],
            memory: BTreeMap::new(),
        };
        let file = s.call("x!__acrt_iob_func", &now).unwrap().rax;
        assert_eq!(file, 0x7ff0_0010);
        now.args = vec![0x24, file, 0x28000, 0, 0x29000];
        now.put(0x28000, &cstr(fmt));
        now.put(0x29000, &words(&[0x2a000]));
        now.put(0x2a000, &cstr("Receipt #1"));
        let e = s.call("x!__stdio_common_vfprintf", &now).unwrap();
        assert_eq!((e.rax, e.writes.len()), (41, 0));
        assert_eq!(s.finish(), Ok(()));
    }

    #[test]
    fn conversions_take_their_slots() {
        assert_eq!(
            slots(b"%-5d|%*.*s|%lld|%.2f|%%|%c|%I64x|%zu").unwrap(),
            [
                Slot::Int(4),
                Slot::Int(4),
                Slot::Int(4),
                Slot::Str {
                    precision: Some(Precision::FromArg)
                },
                Slot::Int(8),
                Slot::Double,
                Slot::Int(4),
                Slot::Int(8),
                Slot::Int(8),
            ]
        );
    }

    #[test]
    fn memory_functions_run_on_the_candidates_arguments() {
        let mut now = Now {
            args: vec![0x2000, 0x1000, 4],
            memory: BTreeMap::new(),
        };
        now.put(0x1000, b"abcd");
        let e = execute("vcruntime140.dll!memcpy", &now).unwrap().unwrap();
        assert_eq!(e.rax, 0x2000);
        assert_eq!(e.writes, vec![(0x2000, b"abcd".to_vec())]);
        now.args = vec![0x2000, 0x7f, 3];
        let e = execute("x!memset", &now).unwrap().unwrap();
        assert_eq!(e.writes, vec![(0x2000, vec![0x7f; 3])]);
        now.put(0x3000, &cstr("hello"));
        now.args = vec![0x3000];
        assert_eq!(execute("x!strlen", &now).unwrap().unwrap().rax, 5);
        // Rotates: by the shift modulo the width; the 32-bit ones ignore the upper half and return 32 bits.
        now.args = vec![0x8000_0000_0000_0001, 4];
        assert_eq!(execute("x!_rotl64", &now).unwrap().unwrap().rax, 0x18);
        assert_eq!(
            execute("x!_rotr64", &now).unwrap().unwrap().rax,
            0x1800_0000_0000_0000
        );
        now.args = vec![0x8000_0000_0000_0001, 64 + 4];
        assert_eq!(execute("x!_rotl64", &now).unwrap().unwrap().rax, 0x18);
        now.args = vec![0xffff_ffff_8000_0001, 0xffff_ffff_0000_0001];
        assert_eq!(execute("x!_rotl", &now).unwrap().unwrap().rax, 3);
        assert_eq!(execute("x!_rotr", &now).unwrap().unwrap().rax, 0xc000_0000);
        // Negative: a 32-bit rotate isn't a 64-bit one.
        assert_ne!(
            execute("x!_rotl", &now).unwrap().unwrap().rax,
            execute("x!_rotl64", &now).unwrap().unwrap().rax
        );
        // Other imports aren't executed.
        assert!(execute("x!memcmp", &now).is_none());
        assert!(execute("x!_rotl8", &now).is_none());
        assert!(execute("x!__acrt_iob_func", &now).is_none());
    }

    #[test]
    fn memory_functions_refuse_memory_nobody_recorded() {
        // Negative: a source or string the recording doesn't hold is inconclusive, never bytes made up.
        let now = Now {
            args: vec![0x2000, 0x1000, 4],
            memory: BTreeMap::new(),
        };
        assert!(
            matches!(execute("x!memcpy", &now), Some(Err(why)) if why.contains("didn't capture"))
        );
        let now = Now {
            args: vec![0x1000],
            memory: BTreeMap::new(),
        };
        assert!(matches!(execute("x!strlen", &now), Some(Err(_))));
        // Negative: an absurd length.
        let now = Now {
            args: vec![0x2000, 0, MAX_EXECUTED + 1],
            memory: BTreeMap::new(),
        };
        assert!(matches!(execute("x!memset", &now), Some(Err(why)) if why.contains("more than")));
    }

    #[test]
    fn recorded_memory_calls_are_skipped_in_the_sequence() {
        // The old build called memcpy before __acrt_iob_func; the candidate (with memcpy inlined) doesn't.
        let copy = recorded("x!memcpy", &[0x2000, 0x1000, 4], 0x2000, Vec::new());
        let iob = recorded("x!__acrt_iob_func", &[1], 0x7ff0_0010, Vec::new());
        let tail = recorded("x!memset", &[0x2000, 0, 4], 0x2000, Vec::new());
        let mut s = StandIns::new(vec![copy, iob, tail]);
        let now = Now {
            args: vec![1],
            memory: BTreeMap::new(),
        };
        assert_eq!(s.call("x!__acrt_iob_func", &now).unwrap().rax, 0x7ff0_0010);
        assert_eq!(s.finish(), Ok(()));
        // Negative: skipping them doesn't excuse a missing modelled call.
        let iob = recorded("x!__acrt_iob_func", &[1], 0x7ff0_0010, Vec::new());
        let copy = recorded("x!memcpy", &[0x2000, 0x1000, 4], 0x2000, Vec::new());
        let mut s = StandIns::new(vec![copy, iob]);
        assert!(s.finish().is_err());
    }

    /// The candidate's `realloc(ptr, size)` against the recorded one that returned `rax`.
    fn realloc(ptr: u64, size: u64, rax: u64) -> Result<Effect, Refusal> {
        let rec = recorded("x!realloc", &[ptr, size], rax, Vec::new());
        let now = Now {
            args: vec![ptr, size],
            memory: BTreeMap::new(),
        };
        StandIns::new(vec![rec]).call("ucrtbase.dll!realloc", &now)
    }

    #[test]
    fn realloc_follows_the_recorded_result() {
        let heap = |ptr, size, rax| realloc(ptr, size, rax).unwrap().heap;
        assert_eq!(
            heap(0x1000, 64, 0x2000),
            Some(Heap::Reallocate {
                from: 0x1000,
                to: 0x2000,
                size: 64
            })
        );
        // NULL in: an allocation. Size 0: a free. NULL out for a real size: the block stays.
        assert_eq!(
            heap(0, 64, 0x2000),
            Some(Heap::Allocate {
                address: 0x2000,
                size: 64,
                zeroed: false
            })
        );
        assert_eq!(heap(0x1000, 0, 0), Some(Heap::Free { address: 0x1000 }));
        assert_eq!(heap(0x1000, 64, 0), None);
        // Its block is kept free like malloc's.
        let rec = recorded("x!realloc", &[0x1000, 64], 0x2000, Vec::new());
        assert_eq!(StandIns::new(vec![rec]).allocations(), vec![0x2000..0x2040]);
    }

    #[test]
    fn realloc_of_another_block_or_size_is_refused() {
        // Negative: another pointer, another size, an absurd size, and a size-0 call that returned a block.
        let rec = recorded("x!realloc", &[0x1000, 64], 0x2000, Vec::new());
        for (args, what) in [(vec![0x1100, 64], "pointer"), (vec![0x1000, 32], "size")] {
            let now = Now {
                args,
                memory: BTreeMap::new(),
            };
            let got = StandIns::new(vec![rec.clone()]).call("x!realloc", &now);
            assert!(matches!(&got, Err(why) if why.contains(what)), "{got:?}");
        }
        assert!(realloc(0x1000, MAX_ALLOCATION + 1, 0x2000).is_err());
        assert!(realloc(0x1000, 0, 0x2000).is_err());
    }
}
