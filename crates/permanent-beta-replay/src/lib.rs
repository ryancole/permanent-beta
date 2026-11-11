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
//! When the caller knows which of the new build's functions changed since the old one ([`Changed`]), a
//! difference is attributed: one in a run that entered a changed function (other than the candidate) is
//! inconclusive, naming it, since the callee may be what differs; and an import called with other inputs, or
//! other import calls, in a run that entered none is a **fail**: every function it ran is the old code, so the
//! difference is the candidate's own.
//!
//! Depends on `permanent-beta-model` only (design §3.1). Emulation needs the `emulator` feature (icicle, MIT or
//! Apache-2.0, running Ghidra's x86-64 SLEIGH specification, Apache-2.0); without it every case is inconclusive.

pub mod address;
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

use permanent_beta_model::{CaptureKind, GlobalVar, HarnessSpec, Rva, TypeLayout, ValueType};
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
    /// Old-image addresses mapped to the new image ([`address`]); without it they stay as recorded.
    pub addresses: Option<&'a address::AddressMap>,
    /// The new build's functions whose code changed since the recording's build, for attributing a difference;
    /// without it, differences are judged as if nothing were known about the callees.
    pub changed: Option<&'a Changed>,
}

/// The new build's functions that aren't known to be the old code: those whose normalized code differs from
/// their old counterpart's, and those without one (no accepted match), by RVA, with a name to show.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Changed {
    pub functions: std::collections::BTreeMap<u64, String>,
}

impl Changed {
    /// The names of `rvas`, for a message.
    #[cfg_attr(not(feature = "emulator"), allow(dead_code))]
    fn names(&self, rvas: &[u64]) -> String {
        let mut shown: Vec<String> = rvas
            .iter()
            .take(3)
            .map(|r| {
                self.functions
                    .get(r)
                    .cloned()
                    .unwrap_or_else(|| format!("{r:#x}"))
            })
            .collect();
        if rvas.len() > 3 {
            shown.push(format!("{} more", rvas.len() - 3));
        }
        shown.join(", ")
    }
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
    /// Byte ranges with no recorded value (fields the old layout lacks): unreadable until written.
    unknown: Vec<Range<usize>>,
    /// Reached through a pointer ([`CaptureKind::Pointee`]): something replay doesn't model (an import's
    /// internals, another thread) may have written it during the recorded call, so a difference there makes the
    /// case inconclusive, not a fail.
    #[cfg_attr(not(feature = "emulator"), allow(dead_code))]
    pointee: bool,
}

fn prepare(
    spec: &HarnessSpec,
    case: &LoadedCase,
    new_layouts: &[TypeLayout],
) -> Result<Vec<Prepared>, String> {
    let types = translate::Types::new(&spec.layouts, new_layouts);
    let mut out = Vec::new();
    for r in &case.regions {
        let arg = r.region.arg;
        let mut p = Prepared {
            address: r.region.address.0,
            before: r.before.clone(),
            expected_after: r.after.clone(),
            compare: std::iter::once(0..r.before.len()).collect(),
            label: match r.region.kind {
                CaptureKind::Pointee => {
                    format!("memory at {:#x} (through arg{arg})", r.region.address.0)
                }
                // The heap block arg points into: what the function writes there is its output, compared like
                // the argument's own memory.
                CaptureKind::Array => {
                    format!("arg{arg}'s heap block at {:#x}", r.region.address.0)
                }
                _ => format!("arg{arg}"),
            },
            translated: false,
            unknown: Vec::new(),
            pointee: r.region.kind == CaptureKind::Pointee,
        };
        if let Some(name) = &r.region.layout {
            p.label = format!("arg{arg} ({name})");
            let old = spec
                .layout(name)
                .ok_or_else(|| format!("the recording's spec has no layout of {name}"))?;
            // The same name, or the struct it was renamed to (the same structure, translate::Types).
            let new = types.new_layout(name).ok_or_else(|| {
                format!("no layout of {name} for the new build (analyze it with --pdb)")
            })?;
            if !translate::same_layout(old, new) {
                let before = types.translate(old, new, &r.before)?;
                let after = types.translate(old, new, &r.after)?;
                p.before = before.bytes;
                p.expected_after = after.bytes;
                p.compare = before.fields;
                p.unknown = before.unknown;
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
    let old_image = c
        .image_size
        .map(|s| c.image_base.0..c.image_base.0.saturating_add(s.0));
    // A returned pointer only means something inside the recorded memory, which keeps its addresses, or at an
    // old-image address the map knows.
    if hook.ret == ValueType::Pointer {
        let v = c.observed.rax.0;
        let in_regions = prepared
            .iter()
            .any(|p| !p.translated && (p.address..=p.address + p.before.len() as u64).contains(&v));
        let mapped = old_image
            .as_ref()
            .zip(new.addresses)
            .is_some_and(|(img, m)| img.contains(&v) && m.rva(v - img.start).is_some());
        if v != 0 && !in_regions && !mapped {
            return CaseOutcome::inconclusive(format!(
                "returns a pointer ({v:#x}) outside the recorded memory"
            ));
        }
    }
    run_and_compare(
        image,
        new_rva,
        hook.ret,
        case,
        &prepared,
        &globals,
        old_image.as_ref().zip(new.addresses),
        new.changed,
    )
}

/// The recorded image's range and the address map, when both are known.
type Addresses<'a> = Option<(&'a Range<u64>, &'a address::AddressMap)>;

#[cfg(not(feature = "emulator"))]
#[allow(clippy::too_many_arguments)]
fn run_and_compare(
    _: &Image,
    _: Rva,
    _: ValueType,
    _: &LoadedCase,
    _: &[Prepared],
    _: &[PreparedGlobal],
    _: Addresses,
    _: Option<&Changed>,
) -> CaseOutcome {
    CaseOutcome::inconclusive(
        "built without the emulator (permanent-beta-replay's `emulator` feature)",
    )
}

#[cfg(feature = "emulator")]
#[allow(clippy::too_many_arguments)]
fn run_and_compare(
    image: &Image,
    new_rva: Rva,
    ret: ValueType,
    case: &LoadedCase,
    prepared: &[Prepared],
    globals: &[PreparedGlobal],
    addresses: Addresses,
    changed: Option<&Changed>,
) -> CaseOutcome {
    let watch: Vec<u64> = changed.map_or(Vec::new(), |c| c.functions.keys().copied().collect());
    let placed: Vec<emulate::Placed> = prepared
        .iter()
        .map(|p| emulate::Placed {
            address: p.address,
            bytes: p.before.clone(),
            unknown: p.unknown.clone(),
        })
        .collect();
    let placed_globals: Vec<emulate::Placed> = globals
        .iter()
        .map(|g| emulate::Placed {
            address: g.rva,
            bytes: g.before.clone(),
            unknown: Vec::new(),
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
        addresses,
        watch: &watch,
    }) {
        Ok(r) => r,
        Err(stop) => return attribute_stop(stop, changed),
    };
    let old_image = case
        .case
        .image_size
        .map(|s| case.case.image_base.0..case.case.image_base.0.saturating_add(s.0));
    let rebase = addresses.map(|(img, map)| address::Rebase {
        map,
        old_image: img,
        new_base: ran.image.start,
    });
    match compare(
        ret,
        &case.case.observed,
        prepared,
        globals,
        &ran,
        old_image,
        rebase,
    ) {
        // A function pointer mapped through another function's match: if that match is wrong, the difference is
        // its doing, so a correct candidate mustn't fail on it.
        CaseOutcome::Fail { detail } if ran.rewritten.functions > 0 => {
            CaseOutcome::inconclusive(format!(
                "{detail}; but the case ran through {} function pointer(s) mapped by other functions' matches, which \
             may be what differs",
                ran.rewritten.functions
            ))
        }
        // A callee whose code changed ran: the difference may be the callee's, so a correct candidate mustn't
        // fail on it.
        CaseOutcome::Fail { detail } if !ran.reached.is_empty() => {
            let names = changed.map_or_else(String::new, |c| c.names(&ran.reached));
            CaseOutcome::inconclusive(format!(
                "{detail}; but it ran {names}, whose code changed since the old build, which may be what differs"
            ))
        }
        CaseOutcome::Fail { detail } if changed.is_some() => CaseOutcome::Fail {
            detail: format!(
                "{detail} (it ran no function whose code changed: the difference is its own)"
            ),
        },
        other => other,
    }
}

/// A run that stopped early: inconclusive, unless it stopped on a difference from the recording (an import
/// called with other inputs, or other import calls) in a run that entered no changed function, with every
/// function pointer in its inputs its own: then the difference is the candidate's, a fail.
#[cfg(feature = "emulator")]
fn attribute_stop(stop: emulate::Stopped, changed: Option<&Changed>) -> CaseOutcome {
    let Some(changed) = changed else {
        return CaseOutcome::inconclusive(stop.why);
    };
    if !imports::is_difference(&stop.why) {
        return CaseOutcome::inconclusive(stop.why);
    }
    if !stop.reached.is_empty() {
        return CaseOutcome::inconclusive(format!(
            "{}; but it ran {}, whose code changed since the old build, which may be what differs",
            stop.why,
            changed.names(&stop.reached)
        ));
    }
    if stop.function_pointers > 0 {
        return CaseOutcome::inconclusive(format!(
            "{}; but the case ran through {} function pointer(s) mapped by other functions' matches, which may be \
             what differs",
            stop.why, stop.function_pointers
        ));
    }
    let what = stop.why.strip_prefix(imports::DIFFERS).unwrap_or(&stop.why);
    CaseOutcome::Fail {
        detail: format!(
            "{what} (it ran no function whose code changed: the difference is its own)"
        ),
    }
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
/// that held an address into the recorded image is compared through the address map ([`address`]) when it knows
/// the address: the same thing is the same, a different data address is a difference, a different function
/// address is inconclusive (it was mapped through another function's match). Otherwise, a word that holds an
/// address into the new image after the replay isn't a difference in behavior, but replay can't tell whether both
/// point at the same thing, so the case is inconclusive, never a pass. Without the recorded image's size (older
/// recordings) no word is treated this way.
#[cfg(feature = "emulator")]
struct ImagePointers<'a> {
    old: Option<Range<u64>>,
    new: Range<u64>,
    rebase: Option<address::Rebase<'a>>,
    /// The first unmapped such word: (expected, got).
    seen: Option<(u64, u64)>,
    /// The first mapped function address that differs: (expected, got).
    function_differs: Option<(u64, u64)>,
    /// Words the map showed to be the same thing.
    mapped: usize,
}

#[cfg(feature = "emulator")]
impl ImagePointers<'_> {
    /// Whether this differing word is not a difference in behavior (or not one replay may call a fail).
    fn both_in_image(&mut self, expected: &[u8], got: &[u8]) -> bool {
        let Some(old) = &self.old else {
            return false;
        };
        let word = |b: &[u8]| u64::from_le_bytes(b.try_into().expect("8 bytes"));
        let (e, g) = (word(expected), word(got));
        if let Some((new, kind)) = self.rebase.and_then(|r| r.address(e)) {
            if g == new {
                self.mapped += 1;
                return true;
            }
            return match kind {
                address::Kind::Data => false,
                address::Kind::Function => {
                    self.function_differs.get_or_insert((e, g));
                    true
                }
            };
        }
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
    rebase: Option<address::Rebase>,
) -> CaseOutcome {
    let mut pointers = ImagePointers {
        old: old_image,
        new: ran.image.clone(),
        rebase,
        seen: None,
        function_differs: None,
        mapped: 0,
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
            let (want, got) = (observed.rax.0.to_le_bytes(), ran.rax.to_le_bytes());
            if want != got && !pointers.both_in_image(&want, &got) {
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
    let mut pointee_difference = None;
    for ((p, got), &released) in prepared.iter().zip(&ran.regions).zip(&ran.released) {
        if released {
            compared.push(format!("{} freed", p.label));
            continue;
        }
        for r in &p.compare {
            if let Some(i) =
                first_difference(p.address, &p.expected_after, got, r.clone(), &mut pointers)
            {
                if p.pointee {
                    pointee_difference.get_or_insert_with(|| {
                        format!(
                            "{} byte {i:#x} is {:#04x} after the call, recorded {:#04x}: memory reached through a pointer, which an import or another thread may have written",
                            p.label, got[i], p.expected_after[i]
                        )
                    });
                    continue;
                }
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
    if let Some(why) = pointee_difference {
        return CaseOutcome::inconclusive(why);
    }
    if let Some((expected, got)) = pointers.function_differs {
        return CaseOutcome::inconclusive(format!(
            "holds the function address {got:#x} where the recording held {expected:#x}, which maps to another \
             function through the matches"
        ));
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
    let mapped = pointers.mapped + ran.rewritten.data + ran.rewritten.functions;
    if mapped > 0 {
        compared.push(format!("{mapped} old-image address(es) mapped"));
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
