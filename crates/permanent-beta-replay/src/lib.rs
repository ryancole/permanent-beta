//! Replay of recorded per-call test cases against a new build, by emulation (design §7.3).
//!
//! A case recorded in the old build (`permanent_beta_model::TestCase`) is replayed on the candidate function of
//! the new build: the new image is mapped in the emulator, the recorded memory placed at its recorded addresses (in the
//! new layout, when a struct's layout changed: [`translate`]), the recorded globals placed at the new build's
//! addresses for the same names, the entry registers and stack set, and the function run until it returns.
//! Import calls are answered from the recording when the recorder intercepted them and replay models the import
//! ([`imports`]). Then:
//! - **pass**: the return value (its declared width), every recorded region's bytes and every recorded global's
//!   bytes after the call are what the old build produced, and the modelled import calls had the same inputs;
//! - **fail**: the return value, a region or a global differs;
//! - **inconclusive**: the case couldn't be replayed faithfully (an import replay doesn't model or that was
//!   called with other inputs, uncaptured memory or global state, a global or struct layout that doesn't map by
//!   name, an unknown return type, nothing to compare, ...). Inconclusive is never a pass.
//!
//! Depends on `permanent-beta-model` only (design §3.1). Emulation needs the `emulator` feature (icicle, MIT or
//! Apache-2.0, running Ghidra's x86-64 SLEIGH specification, Apache-2.0); without it every case is inconclusive.

#[cfg(feature = "emulator")]
pub mod emulate;
pub mod image;
pub mod imports;
pub mod recording;
#[cfg(feature = "emulator")]
mod sleigh;
pub mod translate;

pub use image::Image;
pub use recording::{LoadedCase, LoadedGlobal, LoadedImport, LoadedRegion, Recording};

use permanent_beta_model::{GlobalVar, HarnessSpec, Rva, TypeLayout, ValueType};
use serde::Serialize;
use std::ops::Range;

/// Whether this build can emulate (the `emulator` feature).
pub const EMULATOR: bool = cfg!(feature = "emulator");

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum CaseOutcome {
    Pass { detail: String },
    Fail { detail: String },
    Inconclusive { reason: String },
}

impl CaseOutcome {
    fn inconclusive(reason: impl Into<String>) -> Self {
        Self::Inconclusive {
            reason: reason.into(),
        }
    }
}

/// What replay needs to know about the new build besides its image: from its analysis with `--pdb`.
#[derive(Debug, Clone, Copy, Default)]
pub struct NewBuild<'a> {
    /// Struct layouts, for translating recorded structs.
    pub layouts: &'a [TypeLayout],
    /// Globals, for placing recorded globals by name.
    pub globals: &'a [GlobalVar],
}

/// A recorded global as placed for the replay: at the new build's RVA for its name.
#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "emulator"), allow(dead_code))]
struct PreparedGlobal {
    name: String,
    rva: u64,
    before: Vec<u8>,
    expected_after: Vec<u8>,
}

fn prepare_globals(case: &LoadedCase, new: &NewBuild) -> Result<Vec<PreparedGlobal>, String> {
    case.globals
        .iter()
        .map(|g| {
            let name = &g.global.name;
            let n = new
                .globals
                .iter()
                .find(|n| &n.name == name)
                .ok_or_else(|| {
                    format!("the new build has no global {name} (analyze it with --pdb)")
                })?;
            if n.size != g.global.size {
                return Err(format!(
                    "global {name} is {} bytes in the new build, {} when recorded",
                    n.size, g.global.size
                ));
            }
            Ok(PreparedGlobal {
                name: name.clone(),
                rva: n.rva.0,
                before: g.before.clone(),
                expected_after: g.after.clone(),
            })
        })
        .collect()
}

/// One recorded region as placed for the replay: its bytes in the new layout and which of them to compare.
#[derive(Debug, Clone)]
struct Prepared {
    address: u64,
    before: Vec<u8>,
    expected_after: Vec<u8>,
    /// Byte ranges compared after the run: every byte, or a translated struct's fields.
    compare: Vec<Range<usize>>,
    label: String,
    translated: bool,
}

fn prepare(
    spec: &HarnessSpec,
    case: &LoadedCase,
    new_layouts: &[TypeLayout],
) -> Result<Vec<Prepared>, String> {
    let mut out = Vec::new();
    for r in &case.regions {
        let arg = r.region.arg;
        let mut p = Prepared {
            address: r.region.address.0,
            before: r.before.clone(),
            expected_after: r.after.clone(),
            compare: std::iter::once(0..r.before.len()).collect(),
            label: format!("arg{arg}"),
            translated: false,
        };
        if let Some(name) = &r.region.layout {
            p.label = format!("arg{arg} ({name})");
            let old = spec
                .layout(name)
                .ok_or_else(|| format!("the recording's spec has no layout of {name}"))?;
            let new = new_layouts
                .iter()
                .find(|l| &l.name == name)
                .ok_or_else(|| {
                    format!("no layout of {name} for the new build (analyze it with --pdb)")
                })?;
            if !translate::same_layout(old, new) {
                let before = translate::translate(old, new, &r.before)?;
                let after = translate::translate(old, new, &r.after)?;
                p.before = before.bytes;
                p.expected_after = after.bytes;
                p.compare = before.fields;
                p.translated = true;
            }
        }
        out.push(p);
    }
    // Overlapping regions must agree on their bytes (two arguments pointing into the same memory).
    for (i, a) in out.iter().enumerate() {
        for b in &out[i + 1..] {
            let lo = a.address.max(b.address);
            let hi = (a.address + a.before.len() as u64).min(b.address + b.before.len() as u64);
            if lo < hi {
                let (ia, ib) = ((lo - a.address) as usize, (lo - b.address) as usize);
                let n = (hi - lo) as usize;
                if a.translated || b.translated || a.before[ia..ia + n] != b.before[ib..ib + n] {
                    return Err(format!(
                        "{} and {} overlap and can't both be placed",
                        a.label, b.label
                    ));
                }
            }
        }
    }
    Ok(out)
}

#[cfg(feature = "emulator")]
fn low_bytes(v: u64, width: u8) -> u64 {
    if width >= 8 {
        v
    } else {
        v & ((1u64 << (8 * u32::from(width))) - 1)
    }
}

/// Replays one case on the function at `new_rva` of `image`. `spec` is the recording's spec (the hook's
/// prototype and the old layouts); `new` has the new build's PDB types and globals.
pub fn replay(
    image: &Image,
    new_rva: Rva,
    spec: &HarnessSpec,
    case: &LoadedCase,
    new: &NewBuild,
) -> CaseOutcome {
    let c = &case.case;
    if c.abi != permanent_beta_model::ABI_WIN64 {
        return CaseOutcome::inconclusive(format!("recorded with ABI {:?}", c.abi));
    }
    let Some(hook) = spec.hook(&c.hook) else {
        return CaseOutcome::inconclusive(format!("the spec has no hook {}", c.hook));
    };
    if hook.ret == ValueType::Unknown {
        return CaseOutcome::inconclusive(format!(
            "can't compare the return value of {:?}",
            hook.prototype
        ));
    }
    if hook.ret == ValueType::Void && case.regions.is_empty() && case.globals.is_empty() {
        return CaseOutcome::inconclusive(
            "returns nothing and has no recorded memory: nothing to compare",
        );
    }
    let prepared = match prepare(spec, case, new.layouts) {
        Ok(p) => p,
        Err(why) => return CaseOutcome::inconclusive(why),
    };
    let globals = match prepare_globals(case, new) {
        Ok(g) => g,
        Err(why) => return CaseOutcome::inconclusive(why),
    };
    // A returned pointer only means something inside the recorded memory, which keeps its addresses.
    if hook.ret == ValueType::Pointer {
        let v = c.observed.rax.0;
        let in_regions = prepared
            .iter()
            .any(|p| !p.translated && (p.address..=p.address + p.before.len() as u64).contains(&v));
        if v != 0 && !in_regions {
            return CaseOutcome::inconclusive(format!(
                "returns a pointer ({v:#x}) outside the recorded memory"
            ));
        }
    }
    run_and_compare(image, new_rva, hook.ret, case, &prepared, &globals)
}

#[cfg(not(feature = "emulator"))]
fn run_and_compare(
    _: &Image,
    _: Rva,
    _: ValueType,
    _: &LoadedCase,
    _: &[Prepared],
    _: &[PreparedGlobal],
) -> CaseOutcome {
    CaseOutcome::inconclusive(
        "built without the emulator (permanent-beta-replay's `emulator` feature)",
    )
}

#[cfg(feature = "emulator")]
fn run_and_compare(
    image: &Image,
    new_rva: Rva,
    ret: ValueType,
    case: &LoadedCase,
    prepared: &[Prepared],
    globals: &[PreparedGlobal],
) -> CaseOutcome {
    let placed: Vec<emulate::Placed> = prepared
        .iter()
        .map(|p| emulate::Placed {
            address: p.address,
            bytes: p.before.clone(),
        })
        .collect();
    let placed_globals: Vec<emulate::Placed> = globals
        .iter()
        .map(|g| emulate::Placed {
            address: g.rva,
            bytes: g.before.clone(),
        })
        .collect();
    let ran = match emulate::run(&emulate::Setup {
        image,
        rva: new_rva.0,
        entry: &case.case.entry,
        regions: &placed,
        globals: &placed_globals,
        imports: case
            .case
            .imports_recorded
            .then(|| imports::StandIns::new(case.imports.clone())),
    }) {
        Ok(r) => r,
        Err(why) => return CaseOutcome::inconclusive(why),
    };
    let old_image = case
        .case
        .image_size
        .map(|s| case.case.image_base.0..case.case.image_base.0.saturating_add(s.0));
    compare(ret, &case.case.observed, prepared, globals, &ran, old_image)
}

/// Where `expected` and `got` differ, except words that hold an address into each run's own image (see
/// [`ImagePointers`]). `base` is the bytes' address, for word alignment.
#[cfg(feature = "emulator")]
fn first_difference(
    base: u64,
    expected: &[u8],
    got: &[u8],
    range: Range<usize>,
    pointers: &mut ImagePointers,
) -> Option<usize> {
    let mut i = range.start;
    while i < range.end {
        if got[i] == expected[i] {
            i += 1;
            continue;
        }
        // The aligned 8-byte word holding byte i, if it lies inside the bytes.
        let aligned = (base + i as u64) & !7;
        let start = aligned
            .checked_sub(base)
            .and_then(|o| usize::try_from(o).ok());
        if let Some(start) = start
            && start + 8 <= expected.len()
            && pointers.both_in_image(&expected[start..start + 8], &got[start..start + 8])
        {
            i = start + 8;
            continue;
        }
        return Some(i);
    }
    None
}

/// Addresses into the image differ between builds: the old build's `&static_table` isn't the new build's. A word
/// that held an address into the recorded image and holds one into the new image after the replay is therefore
/// not a difference in behavior, but replay can't tell whether both point at the same thing (that would need
/// the old build's symbols), so the case is inconclusive, never a pass. Without the recorded image's size
/// (older recordings) no word is treated this way.
#[cfg(feature = "emulator")]
struct ImagePointers {
    old: Option<Range<u64>>,
    new: Range<u64>,
    /// The first such word: (expected, got).
    seen: Option<(u64, u64)>,
}

#[cfg(feature = "emulator")]
impl ImagePointers {
    fn both_in_image(&mut self, expected: &[u8], got: &[u8]) -> bool {
        let Some(old) = &self.old else {
            return false;
        };
        let word = |b: &[u8]| u64::from_le_bytes(b.try_into().expect("8 bytes"));
        let (e, g) = (word(expected), word(got));
        let yes = old.contains(&e) && self.new.contains(&g);
        if yes && self.seen.is_none() {
            self.seen = Some((e, g));
        }
        yes
    }
}

#[cfg(feature = "emulator")]
fn compare(
    ret: ValueType,
    observed: &permanent_beta_model::Observed,
    prepared: &[Prepared],
    globals: &[PreparedGlobal],
    ran: &emulate::Ran,
    old_image: Option<Range<u64>>,
) -> CaseOutcome {
    let mut pointers = ImagePointers {
        old: old_image,
        new: ran.image.clone(),
        seen: None,
    };
    let mut compared = Vec::new();
    match ret {
        ValueType::Int(w) => {
            let (want, got) = (low_bytes(observed.rax.0, w), low_bytes(ran.rax, w));
            if want != got {
                return CaseOutcome::Fail {
                    detail: format!("returned {got:#x}, expected {want:#x}"),
                };
            }
            compared.push(format!("return {want:#x}"));
        }
        ValueType::Pointer => {
            if observed.rax.0 != ran.rax {
                return CaseOutcome::Fail {
                    detail: format!("returned {:#x}, expected {:#x}", ran.rax, observed.rax.0),
                };
            }
            compared.push(format!("return {:#x}", ran.rax));
        }
        ValueType::Float(w) => {
            let w = usize::from(w);
            if observed.xmm0.0[..w] != ran.xmm0[..w] {
                return CaseOutcome::Fail {
                    detail: format!(
                        "returned xmm0 {}, expected {}",
                        image::hex(&ran.xmm0[..w]),
                        image::hex(&observed.xmm0.0[..w])
                    ),
                };
            }
            compared.push("return xmm0".into());
        }
        ValueType::Void => {}
        ValueType::Unknown => return CaseOutcome::inconclusive("unknown return type"),
    }
    for (p, got) in prepared.iter().zip(&ran.regions) {
        for r in &p.compare {
            if let Some(i) =
                first_difference(p.address, &p.expected_after, got, r.clone(), &mut pointers)
            {
                return CaseOutcome::Fail {
                    detail: format!(
                        "{} byte {i:#x} is {:#04x} after the call, expected {:#04x}",
                        p.label, got[i], p.expected_after[i]
                    ),
                };
            }
        }
        let written = p.before != p.expected_after;
        compared.push(format!(
            "{} {}",
            p.label,
            if written { "writes" } else { "unchanged" }
        ));
    }
    for (g, got) in globals.iter().zip(&ran.globals) {
        if let Some(i) = first_difference(
            ran.image.start + g.rva,
            &g.expected_after,
            got,
            0..got.len(),
            &mut pointers,
        ) {
            return CaseOutcome::Fail {
                detail: format!(
                    "global {} byte {i:#x} is {:#04x} after the call, expected {:#04x}",
                    g.name, got[i], g.expected_after[i]
                ),
            };
        }
        if g.before != g.expected_after {
            compared.push(format!("global {} writes", g.name));
        }
    }
    if let Some((expected, got)) = pointers.seen {
        return CaseOutcome::inconclusive(format!(
            "writes an address into the image ({got:#x}; recorded {expected:#x}): the builds' addresses differ, \
             and whether both point at the same thing isn't checked"
        ));
    }
    if ran.import_calls > 0 {
        compared.push(format!("{} import call(s) as recorded", ran.import_calls));
    }
    CaseOutcome::Pass {
        detail: format!(
            "{} ({} instructions)",
            compared.join(", "),
            ran.instructions
        ),
    }
}

#[cfg(test)]
mod tests;
