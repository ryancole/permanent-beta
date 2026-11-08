//! Replay of recorded per-call test cases against a new build, by emulation (design §7.3).
//!
//! A case recorded in the old build (`permanent_beta_model::TestCase`) is replayed on the candidate function of
//! the new build: the new image is mapped in Unicorn, the recorded memory placed at its recorded addresses (in the
//! new layout, when a struct's layout changed: [`translate`]), the entry registers and stack set, and the function
//! run until it returns. Then:
//! - **pass**: the return value (its declared width) and every recorded region's bytes after the call are what
//!   the old build produced;
//! - **fail**: either differs;
//! - **inconclusive**: the case couldn't be replayed faithfully (an import call, uncaptured memory or global
//!   state, a struct layout that doesn't map by name, an unknown return type, nothing to compare, ...).
//!   Inconclusive is never a pass.
//!
//! Depends on `permanent-beta-model` only (design §3.1). Emulation needs the `emulator` feature (Unicorn,
//! GPL-2.0); without it every case is inconclusive.

#[cfg(feature = "emulator")]
pub mod emulate;
pub mod image;
pub mod recording;
pub mod translate;

pub use image::Image;
pub use recording::{LoadedCase, LoadedRegion, Recording};

use permanent_beta_model::{HarnessSpec, Rva, TypeLayout, ValueType};
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
/// prototype and the old layouts); `new_layouts` are the new build's PDB types.
pub fn replay(
    image: &Image,
    new_rva: Rva,
    spec: &HarnessSpec,
    case: &LoadedCase,
    new_layouts: &[TypeLayout],
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
    if hook.ret == ValueType::Void && case.regions.is_empty() {
        return CaseOutcome::inconclusive(
            "returns nothing and has no recorded memory: nothing to compare",
        );
    }
    let prepared = match prepare(spec, case, new_layouts) {
        Ok(p) => p,
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
    run_and_compare(image, new_rva, hook.ret, case, &prepared)
}

#[cfg(not(feature = "emulator"))]
fn run_and_compare(_: &Image, _: Rva, _: ValueType, _: &LoadedCase, _: &[Prepared]) -> CaseOutcome {
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
) -> CaseOutcome {
    let placed: Vec<emulate::Placed> = prepared
        .iter()
        .map(|p| emulate::Placed {
            address: p.address,
            bytes: p.before.clone(),
        })
        .collect();
    let ran = match emulate::run(&emulate::Setup {
        image,
        rva: new_rva.0,
        entry: &case.case.entry,
        regions: &placed,
    }) {
        Ok(r) => r,
        Err(why) => return CaseOutcome::inconclusive(why),
    };
    compare(ret, &case.case.observed, prepared, &ran)
}

#[cfg(feature = "emulator")]
fn compare(
    ret: ValueType,
    observed: &permanent_beta_model::Observed,
    prepared: &[Prepared],
    ran: &emulate::Ran,
) -> CaseOutcome {
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
            if let Some(i) = r.clone().find(|&i| got[i] != p.expected_after[i]) {
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
