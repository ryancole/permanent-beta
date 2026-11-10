//! Behavioral evidence from recorded per-call test cases (design §6.2, §7.3): every case recorded at the
//! candidate's old RVA in its old build is replayed on the candidate in the new build (`permanent-beta-replay`).
//!
//! Pass if every case that can be replayed matches and at least one can, and the passing cases are more than a
//! function that returns a constant and does nothing else would pass: one of them writes memory or a global or
//! calls a modelled import, or they return two different values. Otherwise one `return 0;` passes them
//! (zlib's `updatewindow`, on a call that had nothing to copy, passed on `_matherr`), so they're no evidence:
//! inconclusive. Fail if any case differs; inconclusive if none can be replayed (unmodelled imports, uncaptured memory or globals, unmappable layouts, no emulator), or there are no
//! cases for this function of this build. Cases are matched to builds like scenario traces: a case of another
//! build is no evidence, its RVA being another function there.

use permanent_beta_model::ValueType;
use permanent_beta_model::{
    AnalysisExport, BuildId, Candidate, CheckOutcome, CheckResult, FunctionFeatures, GlobalVar,
    Rva, TypeLayout,
};
use permanent_beta_replay::address::AddressMap;
use permanent_beta_replay::{CaseOutcome, Image, LoadedCase, NewBuild, Recording, imports, replay};
use permanent_beta_verify::{BehavioralRunner, VerifyContext};
use serde::Serialize;
use std::collections::BTreeMap;

pub struct RecordedCasesRunner {
    recordings: Vec<Recording>,
    image: Image,
    new_layouts: Vec<TypeLayout>,
    new_globals: Vec<GlobalVar>,
    /// Per old build, its image's addresses mapped to the new image (design §7.3).
    addresses: Vec<(BuildId, AddressMap)>,
}

/// Every case for one old function, replayed on one new function.
#[derive(Debug, Clone, Serialize)]
pub struct Judgement {
    pub outcome: CheckOutcome,
    pub detail: String,
    pub cases: Vec<CaseResult>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CaseResult {
    pub test_id: String,
    #[serde(flatten)]
    pub outcome: CaseOutcome,
    /// What the recorded call did that a constant function couldn't.
    #[serde(skip)]
    pub signal: Signal,
}

/// What a recorded call shows beyond its return value.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Signal {
    /// It wrote recorded memory or a global, or called an import replay answers (not one replay runs itself,
    /// like `memcpy`: its writes show in the memory).
    pub effect: bool,
    /// The return value at its declared width, if it has one.
    pub ret: Option<u64>,
}

impl Signal {
    fn of(case: &LoadedCase, ret: ValueType) -> Self {
        let effect = case.regions.iter().any(|r| r.before != r.after)
            || case.globals.iter().any(|g| g.before != g.after)
            || case
                .imports
                .iter()
                .any(|i| !imports::EXECUTED.contains(&imports::base_name(&i.call.import)));
        let rax = case.case.observed.rax.0;
        let ret = match ret {
            ValueType::Int(w) if w < 8 => Some(rax & ((1u64 << (8 * u32::from(w))) - 1)),
            ValueType::Int(_) | ValueType::Pointer => Some(rax),
            ValueType::Float(w) => Some(
                u64::from_le_bytes(case.case.observed.xmm0.0[..8].try_into().expect("8 bytes"))
                    & if w == 4 { 0xffff_ffff } else { u64::MAX },
            ),
            ValueType::Void | ValueType::Unknown => None,
        };
        Self { effect, ret }
    }
}

impl RecordedCasesRunner {
    /// `image` is the new build's binary; `new_layouts` and `new_globals` its PDB struct layouts and globals
    /// (the new analysis' `types` and `globals`).
    pub fn new(
        recordings: Vec<Recording>,
        image: Image,
        new_layouts: Vec<TypeLayout>,
        new_globals: Vec<GlobalVar>,
    ) -> Self {
        Self {
            recordings,
            image,
            new_layouts,
            new_globals,
            addresses: Vec::new(),
        }
    }

    /// Maps addresses into `old`'s image to the new image: its data symbols by name (both analyses with `--pdb`)
    /// and its functions through `functions` (old entry, new entry: the run's accepted matches).
    pub fn with_addresses(
        mut self,
        old: &AnalysisExport,
        new: &AnalysisExport,
        functions: &[(Rva, Rva)],
    ) -> Self {
        self.addresses.retain(|(b, _)| b != &old.build.id);
        self.addresses
            .push((old.build.id.clone(), AddressMap::new(old, new, functions)));
        self
    }

    pub fn image_build(&self) -> &BuildId {
        &self.image.build
    }

    /// Replays every case recorded at `old_rva` (in `old_build`, or in any build when `None`) on `new_rva`.
    pub fn judge(&self, old_build: Option<&BuildId>, old_rva: Rva, new_rva: Rva) -> Judgement {
        let mut cases = Vec::new();
        for rec in self
            .recordings
            .iter()
            .filter(|r| old_build.is_none_or(|b| &r.spec.build == b))
        {
            for c in rec.cases.iter().filter(|c| c.case.rva == old_rva) {
                let ret = rec
                    .spec
                    .hook(&c.case.hook)
                    .map_or(ValueType::Unknown, |h| h.ret);
                cases.push(CaseResult {
                    test_id: c.case.test_id.clone(),
                    signal: Signal::of(c, ret),
                    outcome: replay(
                        &self.image,
                        new_rva,
                        &rec.spec,
                        c,
                        &NewBuild {
                            layouts: &self.new_layouts,
                            globals: &self.new_globals,
                            addresses: self
                                .addresses
                                .iter()
                                .find(|(b, _)| b == &rec.spec.build)
                                .map(|(_, m)| m),
                        },
                    ),
                });
            }
        }
        let (outcome, detail) = summarize(&cases, old_rva);
        Judgement {
            outcome,
            detail,
            cases,
        }
    }
}

/// The same cases replayed on every other function of the new build: a control for replay itself. The cases of a
/// function should pass on no function but its counterpart, except two kinds listed apart: one with identical
/// code (the same normalized hash: a duplicate, an ICF twin), and one that calls the target (a wrapper that
/// forwards to it, as zlib's `crc32` to `crc32_z`), which behaves the same by construction. Replay can't tell
/// those from the target; matching has to.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Others {
    /// Functions with other code the cases pass on: replay can't tell them from the target. Should be empty.
    pub passed: Vec<Rva>,
    /// Functions with the target's code the cases pass on.
    pub same_code: Vec<Rva>,
    /// Functions calling the target that the cases pass on.
    pub calls_target: Vec<Rva>,
    pub failed: usize,
    pub inconclusive: usize,
}

impl Others {
    /// Sorts each function's outcome into the tally. `target_hash` is the target's normalized hash.
    fn add(
        &mut self,
        target_hash: Option<&str>,
        rva: Rva,
        hash: Option<&str>,
        calls_target: bool,
        outcome: CheckOutcome,
    ) {
        match outcome {
            CheckOutcome::Pass if target_hash.is_some() && hash == target_hash => {
                self.same_code.push(rva)
            }
            CheckOutcome::Pass if calls_target => self.calls_target.push(rva),
            CheckOutcome::Pass => self.passed.push(rva),
            CheckOutcome::Fail => self.failed += 1,
            CheckOutcome::Inconclusive => self.inconclusive += 1,
        }
    }
}

impl RecordedCasesRunner {
    /// [`Self::judge`] on every function of `new` but `new_rva`, spread over the machine's threads (each replays
    /// in its own emulator).
    pub fn judge_others(
        &self,
        old_build: Option<&BuildId>,
        old_rva: Rva,
        new_rva: Rva,
        new: &AnalysisExport,
    ) -> Others {
        let target_hash = new
            .function(new_rva)
            .and_then(|f| f.normalized_hash.as_deref());
        let targets: Vec<&FunctionFeatures> =
            new.functions.iter().filter(|f| f.rva != new_rva).collect();
        let threads = std::thread::available_parallelism()
            .map_or(1, |n| n.get())
            .min(targets.len().max(1));
        let chunk = targets.len().div_ceil(threads).max(1);
        let outcomes: Vec<CheckOutcome> = std::thread::scope(|s| {
            let handles: Vec<_> = targets
                .chunks(chunk)
                .map(|part| {
                    s.spawn(move || {
                        part.iter()
                            .map(|f| self.judge(old_build, old_rva, f.rva).outcome)
                            .collect::<Vec<_>>()
                    })
                })
                .collect();
            handles
                .into_iter()
                .flat_map(|h| h.join().expect("a replay thread panicked"))
                .collect()
        });
        let mut others = Others::default();
        for (f, outcome) in targets.iter().zip(outcomes) {
            others.add(
                target_hash,
                f.rva,
                f.normalized_hash.as_deref(),
                f.callees.contains(&new_rva),
                outcome,
            );
        }
        others
    }
}

fn summarize(cases: &[CaseResult], old_rva: Rva) -> (CheckOutcome, String) {
    if cases.is_empty() {
        return (
            CheckOutcome::Inconclusive,
            format!("no recorded cases at {old_rva} in the old build"),
        );
    }
    let mut reasons: BTreeMap<&str, usize> = BTreeMap::new();
    let mut passed = 0;
    for c in cases {
        match &c.outcome {
            CaseOutcome::Fail { detail } => {
                return (
                    CheckOutcome::Fail,
                    format!("recorded case {} differs: {detail}", c.test_id),
                );
            }
            CaseOutcome::Pass { .. } => passed += 1,
            CaseOutcome::Inconclusive { reason } => *reasons.entry(reason).or_default() += 1,
        }
    }
    let why = reasons
        .iter()
        .map(|(r, n)| {
            if *n > 1 {
                format!("{r} (x{n})")
            } else {
                (*r).to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("; ");
    let passing: Vec<Signal> = cases
        .iter()
        .filter(|c| matches!(c.outcome, CaseOutcome::Pass { .. }))
        .map(|c| c.signal)
        .collect();
    let returns: std::collections::BTreeSet<u64> = passing.iter().filter_map(|s| s.ret).collect();
    if passed > 0 && !passing.iter().any(|s| s.effect) && returns.len() < 2 {
        let what = match returns.first() {
            Some(v) => format!("return {v:#x}"),
            None => "return".into(),
        };
        return (
            CheckOutcome::Inconclusive,
            format!(
                "{passed} of {} recorded cases replay identically, but each only shows the same {what} with nothing                  written and no import called, which any function returning that constant would pass",
                cases.len()
            ),
        );
    }
    if passed > 0 {
        let rest = if reasons.is_empty() {
            String::new()
        } else {
            format!("; {} not replayable: {why}", cases.len() - passed)
        };
        (
            CheckOutcome::Pass,
            format!(
                "{passed} of {} recorded cases replay identically{rest}",
                cases.len()
            ),
        )
    } else {
        (
            CheckOutcome::Inconclusive,
            format!(
                "none of {} recorded cases could be replayed: {why}",
                cases.len()
            ),
        )
    }
}

impl BehavioralRunner for RecordedCasesRunner {
    fn run(
        &self,
        ctx: &VerifyContext,
        candidate: &Candidate,
        _old: &FunctionFeatures,
        _new: &FunctionFeatures,
    ) -> CheckResult {
        if self.image.build != ctx.new_build {
            return CheckResult::new(
                "behavioral",
                CheckOutcome::Inconclusive,
                format!(
                    "the binary given for replay is build {}, not the new build {}",
                    short(&self.image.build),
                    short(&ctx.new_build)
                ),
            );
        }
        let j = self.judge(Some(&ctx.old_build), candidate.old, candidate.new);
        CheckResult::new("behavioral", j.outcome, j.detail)
    }
}

fn short(id: &BuildId) -> &str {
    id.0.get(..12).unwrap_or(&id.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(id: &str, outcome: CaseOutcome) -> CaseResult {
        CaseResult {
            test_id: id.into(),
            outcome,
            signal: Signal {
                effect: true,
                ret: Some(0),
            },
        }
    }

    fn returning(id: &str, ret: u64) -> CaseResult {
        CaseResult {
            signal: Signal {
                effect: false,
                ret: Some(ret),
            },
            ..result(id, pass())
        }
    }

    #[test]
    fn other_functions_passing_are_listed_apart_from_identical_code() {
        let mut o = Others::default();
        o.add(Some("h1"), Rva(0x10), Some("h1"), false, CheckOutcome::Pass);
        o.add(Some("h1"), Rva(0x20), Some("h2"), false, CheckOutcome::Pass);
        o.add(Some("h1"), Rva(0x30), None, false, CheckOutcome::Pass);
        o.add(Some("h1"), Rva(0x40), Some("h1"), false, CheckOutcome::Fail);
        o.add(
            Some("h1"),
            Rva(0x50),
            Some("h3"),
            false,
            CheckOutcome::Inconclusive,
        );
        o.add(Some("h1"), Rva(0x60), Some("h4"), true, CheckOutcome::Pass);
        // Negative: only the same hash, or calling the target, excuses a pass; another hash or none is replay
        // failing to tell them apart.
        assert_eq!(o.same_code, [Rva(0x10)]);
        assert_eq!(o.calls_target, [Rva(0x60)]);
        assert_eq!(o.passed, [Rva(0x20), Rva(0x30)]);
        assert_eq!((o.failed, o.inconclusive), (1, 1));
        // Negative: a target without a hash excuses nothing, not even a function without one.
        let mut o = Others::default();
        o.add(None, Rva(0x10), None, false, CheckOutcome::Pass);
        assert_eq!(o.passed, [Rva(0x10)]);
    }

    #[test]
    fn what_a_constant_function_would_pass_is_no_evidence() {
        // Negative: one case (or several) returning 0 and doing nothing else; the rest not replayable.
        for passing in [
            vec![returning("f-1", 0)],
            vec![returning("f-1", 0), returning("f-2", 0)],
        ] {
            let mut cases = passing;
            cases.push(result("f-9", inconclusive("reads memory")));
            let (o, d) = summarize(&cases, Rva(0x10));
            assert_eq!(o, CheckOutcome::Inconclusive, "{d}");
            assert!(d.contains("returning that constant"), "{d}");
        }
        // Two different return values: a constant function fails one of them.
        let (o, _) = summarize(&[returning("f-1", 0), returning("f-2", 7)], Rva(0x10));
        assert_eq!(o, CheckOutcome::Pass);
        // A write or an import call in one passing case is enough.
        let (o, _) = summarize(&[returning("f-1", 0), result("f-2", pass())], Rva(0x10));
        assert_eq!(o, CheckOutcome::Pass);
        // Negative: a failing case still fails, trivial passes or not.
        let fail = CaseOutcome::Fail {
            detail: "returned 0x1, expected 0x0".into(),
        };
        let (o, _) = summarize(&[returning("f-1", 0), result("f-2", fail)], Rva(0x10));
        assert_eq!(o, CheckOutcome::Fail);
    }

    fn pass() -> CaseOutcome {
        CaseOutcome::Pass {
            detail: "same".into(),
        }
    }

    fn inconclusive(why: &str) -> CaseOutcome {
        CaseOutcome::Inconclusive { reason: why.into() }
    }

    #[test]
    fn every_replayable_case_must_match() {
        let (o, d) = summarize(
            &[
                result("f-1", pass()),
                result("f-2", inconclusive("calls the import x")),
            ],
            Rva(0x10),
        );
        assert_eq!(o, CheckOutcome::Pass);
        assert!(
            d.contains("1 of 2") && d.contains("calls the import x"),
            "{d}"
        );
        // Negative: one differing case fails the candidate, however many pass.
        let (o, d) = summarize(
            &[
                result("f-1", pass()),
                result(
                    "f-2",
                    CaseOutcome::Fail {
                        detail: "returned 0x1, expected 0x2".into(),
                    },
                ),
                result("f-3", pass()),
            ],
            Rva(0x10),
        );
        assert_eq!(o, CheckOutcome::Fail);
        assert!(d.contains("f-2"), "{d}");
    }

    #[test]
    fn no_replayable_case_is_no_evidence() {
        // Negative: inconclusive cases never add up to a pass.
        let (o, d) = summarize(
            &[
                result("f-1", inconclusive("a")),
                result("f-2", inconclusive("a")),
            ],
            Rva(0x10),
        );
        assert_eq!(o, CheckOutcome::Inconclusive);
        assert!(d.contains("a (x2)"), "{d}");
        // Negative: no cases at all.
        assert_eq!(summarize(&[], Rva(0x10)).0, CheckOutcome::Inconclusive);
    }
}
