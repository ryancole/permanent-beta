//! Behavioral checks from scenario call traces (design §7.3, option 3).
//!
//! The same scripted scenario runs against the old build (with the original hooks) and the new build (with the
//! repaired hooks), under a logging hook DLL. Each hook's calls, arguments and results by value, must be the same
//! in both traces. A hook that doesn't fire, fires with other values (e.g. it was relocated onto another
//! function), or whose run crashed fails.
//!
//! Two entry points:
//! - [`diff_traces`] judges every hook of a repaired manifest after the run (`pbeta trace-diff`), including that
//!   hooks repair sent to review were *not* applied and were reported.
//! - [`TraceDiffRunner`] is a [`BehavioralRunner`]: it judges one candidate (old RVA → new RVA) from traces whose
//!   hooks were placed at those addresses (`pbeta repair --old-trace --new-trace`).

use crate::BehavioralRunner;
use permanent_beta_model::{
    BuildId, Candidate, CheckOutcome, CheckResult, FunctionFeatures, HookManifest, Rva, Trace,
    TraceEvent,
};
use serde::Serialize;
use std::collections::BTreeMap;

/// One call as the detour logged it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call<'a> {
    pub args: &'a [String],
    pub ret: &'a str,
}

impl Call<'_> {
    fn render(&self) -> String {
        format!("({}) -> {}", self.args.join(", "), self.ret)
    }
}

fn calls<'a>(trace: &'a Trace, keep: impl Fn(&str, Rva) -> bool) -> Vec<Call<'a>> {
    trace
        .events
        .iter()
        .filter_map(|e| match e {
            TraceEvent::Call {
                hook,
                rva,
                args,
                ret,
            } if keep(hook, *rva) => Some(Call { args, ret }),
            _ => None,
        })
        .collect()
}

/// Calls logged by the hook named `hook`.
pub fn calls_of<'a>(trace: &'a Trace, hook: &str) -> Vec<Call<'a>> {
    calls(trace, |h, _| h == hook)
}

/// Calls logged by a detour placed at `rva`.
pub fn calls_at(trace: &Trace, rva: Rva) -> Vec<Call<'_>> {
    calls(trace, |_, r| r == rva)
}

/// How a hook was set up in a run: attached (with Detours' status), deliberately skipped, or not mentioned.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Placement<'a> {
    Attached { rva: Rva, status: &'a str },
    Skipped { reason: &'a str },
    Absent,
}

fn placement<'a>(trace: &'a Trace, hook: &str) -> Placement<'a> {
    trace
        .events
        .iter()
        .find_map(|e| match e {
            TraceEvent::Attach {
                hook: h,
                rva,
                status,
            } if h == hook => Some(Placement::Attached {
                rva: *rva,
                status: status.as_str(),
            }),
            TraceEvent::Skip {
                hook: h, reason, ..
            } if h == hook => Some(Placement::Skipped {
                reason: reason.as_str(),
            }),
            _ => None,
        })
        .unwrap_or(Placement::Absent)
}

const ATTACHED_OK: &str = "ok";

/// The result of comparing two call sequences.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallDiff {
    Same {
        calls: usize,
    },
    /// The first call that differs (0-based); `None` where one sequence ended early.
    Differs {
        call: usize,
        expected: Option<String>,
        got: Option<String>,
    },
}

pub fn compare_calls(expected: &[Call<'_>], got: &[Call<'_>]) -> CallDiff {
    let n = expected.len().max(got.len());
    for i in 0..n {
        let (e, g) = (expected.get(i), got.get(i));
        if e != g {
            return CallDiff::Differs {
                call: i,
                expected: e.map(Call::render),
                got: g.map(Call::render),
            };
        }
    }
    CallDiff::Same { calls: n }
}

/// What happened to one hook of the manifest in the new run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum HookOutcome {
    /// Baseline only: attached and fired this many times.
    Recorded { calls: usize },
    /// Same calls, arguments and results as the old run.
    Same { calls: usize },
    /// Fired, but call `call` (0-based) differs. `None` where one run had fewer calls.
    Differs {
        call: usize,
        expected: Option<String>,
        got: Option<String>,
    },
    /// Attached, but never called (the old run called it `expected` times).
    NotFired { expected: usize },
    /// Detours couldn't attach it.
    AttachFailed { status: String },
    /// Not applied, and repair reported it for review: the intended outcome for an unresolved hook.
    HeldForReview { reason: String },
    /// Not applied (e.g. its locator is bound to another build); no repair report was given to check it against.
    NotApplied { reason: String },
    /// Not applied, but repair didn't report it for review: a silently dropped hook.
    SkippedUnreported { reason: String },
    /// Repair sent it to review, yet it was attached anyway.
    AppliedDespiteReview { reason: String },
    /// The old run didn't attach this hook, so there's nothing to compare against.
    NoBaseline { calls: usize },
    /// The run never mentioned this hook (the harness didn't read it).
    Missing,
}

impl HookOutcome {
    pub fn passed(&self) -> bool {
        matches!(
            self,
            Self::Recorded { .. }
                | Self::Same { .. }
                | Self::HeldForReview { .. }
                | Self::NotApplied { .. }
                | Self::NoBaseline { .. }
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HookBehavior {
    pub hook: String,
    #[serde(flatten)]
    pub outcome: HookOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TraceDiff {
    pub build: Option<BuildId>,
    /// The new run exited normally. A crash fails the whole run, whatever the hooks show.
    pub completed: bool,
    pub hooks: Vec<HookBehavior>,
}

impl TraceDiff {
    pub fn passed(&self) -> bool {
        self.completed && self.hooks.iter().all(|h| h.outcome.passed())
    }
}

/// Check a baseline run: every hook in `manifest` must be attached and fire at least once, and the run must
/// complete. A baseline that misses a hook can't vouch for its repair later.
pub fn check_baseline(trace: &Trace, manifest: &HookManifest) -> TraceDiff {
    let hooks = manifest
        .hooks
        .iter()
        .map(|h| {
            let outcome = match placement(trace, &h.name) {
                Placement::Attached { status, .. } if status == ATTACHED_OK => {
                    match calls_of(trace, &h.name).len() {
                        0 => HookOutcome::NotFired { expected: 0 },
                        calls => HookOutcome::Recorded { calls },
                    }
                }
                Placement::Attached { status, .. } => HookOutcome::AttachFailed {
                    status: status.to_owned(),
                },
                Placement::Skipped { reason } => HookOutcome::SkippedUnreported {
                    reason: reason.to_owned(),
                },
                Placement::Absent => HookOutcome::Missing,
            };
            HookBehavior {
                hook: h.name.clone(),
                outcome,
            }
        })
        .collect();
    TraceDiff {
        build: trace.build().cloned(),
        completed: trace.completed(),
        hooks,
    }
}

/// Compare the new run of a repaired manifest against the old run, hook by hook (matched by hook name).
///
/// `held` lists the hooks repair sent to review, with the reason, when the repair report is known: those must
/// not be attached, and every hook that wasn't attached must be among them. With `None`, unattached hooks are
/// reported as not applied without that cross-check.
pub fn diff_traces(
    old: &Trace,
    new: &Trace,
    manifest: &HookManifest,
    held: Option<&BTreeMap<String, String>>,
) -> TraceDiff {
    let hooks = manifest
        .hooks
        .iter()
        .map(|h| {
            let review = held.and_then(|m| m.get(&h.name));
            let outcome = match (placement(new, &h.name), review) {
                (Placement::Attached { .. }, Some(reason)) => HookOutcome::AppliedDespiteReview {
                    reason: reason.clone(),
                },
                (Placement::Attached { status, .. }, None) if status != ATTACHED_OK => {
                    HookOutcome::AttachFailed {
                        status: status.to_owned(),
                    }
                }
                (Placement::Attached { .. }, None) => compare_hook(old, new, &h.name),
                (Placement::Skipped { .. }, Some(reason)) => HookOutcome::HeldForReview {
                    reason: reason.clone(),
                },
                (Placement::Skipped { reason }, None) if held.is_some() => {
                    HookOutcome::SkippedUnreported {
                        reason: reason.to_owned(),
                    }
                }
                (Placement::Skipped { reason }, None) => HookOutcome::NotApplied {
                    reason: reason.to_owned(),
                },
                (Placement::Absent, _) => HookOutcome::Missing,
            };
            HookBehavior {
                hook: h.name.clone(),
                outcome,
            }
        })
        .collect();
    TraceDiff {
        build: new.build().cloned(),
        completed: new.completed(),
        hooks,
    }
}

fn compare_hook(old: &Trace, new: &Trace, hook: &str) -> HookOutcome {
    let got = calls_of(new, hook);
    if !matches!(placement(old, hook), Placement::Attached { status, .. } if status == ATTACHED_OK)
    {
        return HookOutcome::NoBaseline { calls: got.len() };
    }
    let expected = calls_of(old, hook);
    if got.is_empty() && !expected.is_empty() {
        return HookOutcome::NotFired {
            expected: expected.len(),
        };
    }
    match compare_calls(&expected, &got) {
        CallDiff::Same { calls } => HookOutcome::Same { calls },
        CallDiff::Differs {
            call,
            expected,
            got,
        } => HookOutcome::Differs {
            call,
            expected,
            got,
        },
    }
}

/// Behavioral evidence for one candidate from two scenario traces: the calls a detour at `candidate.old` saw in
/// the old run must equal what a detour at `candidate.new` saw in the new run.
///
/// Inconclusive when the old run recorded nothing at the old address, or the new run had no working detour at
/// the new address (the candidate wasn't tried). Fails on any difference, and when the new run crashed.
pub struct TraceDiffRunner {
    old: Trace,
    new: Trace,
}

impl TraceDiffRunner {
    pub fn new(old: Trace, new: Trace) -> Self {
        Self { old, new }
    }

    fn attached_at(trace: &Trace, rva: Rva) -> bool {
        trace.events.iter().any(|e| {
            matches!(e, TraceEvent::Attach { rva: r, status, .. } if *r == rva && status == ATTACHED_OK)
        })
    }
}

impl BehavioralRunner for TraceDiffRunner {
    fn run(
        &self,
        candidate: &Candidate,
        _old: &FunctionFeatures,
        _new: &FunctionFeatures,
    ) -> CheckResult {
        let result = |outcome, detail: String| CheckResult::new("behavioral", outcome, detail);
        let expected = calls_at(&self.old, candidate.old);
        if !Self::attached_at(&self.old, candidate.old) || expected.is_empty() {
            return result(
                CheckOutcome::Inconclusive,
                format!("no recorded calls at {} in the old run", candidate.old),
            );
        }
        if !Self::attached_at(&self.new, candidate.new) {
            return result(
                CheckOutcome::Inconclusive,
                format!("the new run had no hook at {}", candidate.new),
            );
        }
        if !self.new.completed() {
            return result(
                CheckOutcome::Fail,
                "the new run didn't exit normally (crash?)".into(),
            );
        }
        match compare_calls(&expected, &calls_at(&self.new, candidate.new)) {
            CallDiff::Same { calls } => result(
                CheckOutcome::Pass,
                format!("{calls} calls identical in the scenario traces"),
            ),
            CallDiff::Differs {
                call,
                expected,
                got,
            } => result(
                CheckOutcome::Fail,
                format!(
                    "scenario call {call} differs: expected {}, got {}",
                    expected.as_deref().unwrap_or("no call"),
                    got.as_deref().unwrap_or("no call")
                ),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use permanent_beta_model::{Criticality, HookSpec, TargetLocator};

    fn attach(hook: &str, rva: u64) -> TraceEvent {
        TraceEvent::Attach {
            hook: hook.into(),
            rva: Rva(rva),
            status: "ok".into(),
        }
    }

    fn call(hook: &str, rva: u64, arg: &str, ret: &str) -> TraceEvent {
        TraceEvent::Call {
            hook: hook.into(),
            rva: Rva(rva),
            args: vec![arg.into()],
            ret: ret.into(),
        }
    }

    fn skip(hook: &str) -> TraceEvent {
        TraceEvent::Skip {
            hook: hook.into(),
            reason: "build_mismatch".into(),
            build: None,
        }
    }

    fn trace(events: Vec<TraceEvent>) -> Trace {
        let mut all = vec![TraceEvent::Start {
            build: BuildId("b".into()),
        }];
        all.extend(events);
        all.push(TraceEvent::End);
        Trace { events: all }
    }

    fn manifest(names: &[&str]) -> HookManifest {
        HookManifest {
            hooks: names
                .iter()
                .map(|n| HookSpec {
                    name: (*n).into(),
                    detour: None,
                    criticality: Criticality::Normal,
                    prototype: None,
                    target: TargetLocator {
                        build: BuildId("b".into()),
                        rva: None,
                        symbol: None,
                        pattern: None,
                    },
                })
                .collect(),
        }
    }

    /// Old run: `price` at 0x100 sees sku 10 -> 470 and sku 11 -> 507; `stock` at 0x200 sees sku 10 -> 30.
    fn old_run() -> Trace {
        trace(vec![
            attach("price", 0x100),
            attach("stock", 0x200),
            call("stock", 0x200, "10", "30"),
            call("price", 0x100, "10", "470"),
            call("price", 0x100, "11", "507"),
        ])
    }

    fn outcome(d: &TraceDiff, hook: &str) -> HookOutcome {
        d.hooks
            .iter()
            .find(|h| h.hook == hook)
            .unwrap()
            .outcome
            .clone()
    }

    #[test]
    fn correctly_relocated_hooks_see_the_same_calls() {
        let new = trace(vec![
            attach("price", 0x180),
            attach("stock", 0x280),
            call("stock", 0x280, "10", "30"),
            call("price", 0x180, "10", "470"),
            call("price", 0x180, "11", "507"),
        ]);
        let d = diff_traces(&old_run(), &new, &manifest(&["price", "stock"]), None);
        assert!(d.passed(), "{d:?}");
        assert_eq!(outcome(&d, "price"), HookOutcome::Same { calls: 2 });
    }

    #[test]
    fn a_hook_relocated_onto_the_wrong_function_is_caught() {
        // "price" was moved onto stock's function: it fires, but with stock's calls.
        let new = trace(vec![
            attach("price", 0x280),
            call("price", 0x280, "10", "30"),
        ]);
        let d = diff_traces(&old_run(), &new, &manifest(&["price"]), None);
        assert!(!d.passed());
        assert_eq!(
            outcome(&d, "price"),
            HookOutcome::Differs {
                call: 0,
                expected: Some("(10) -> 470".into()),
                got: Some("(10) -> 30".into()),
            }
        );
    }

    #[test]
    fn a_hook_that_no_longer_fires_fails() {
        let new = trace(vec![attach("price", 0x180), attach("stock", 0x280)]);
        let d = diff_traces(&old_run(), &new, &manifest(&["price"]), None);
        assert_eq!(outcome(&d, "price"), HookOutcome::NotFired { expected: 2 });
        assert!(!d.passed());
    }

    #[test]
    fn a_crashed_run_fails_even_if_every_hook_matched_so_far() {
        let mut new = trace(vec![
            attach("stock", 0x280),
            call("stock", 0x280, "10", "30"),
        ]);
        new.events.pop(); // no End
        let d = diff_traces(&old_run(), &new, &manifest(&["stock"]), None);
        assert_eq!(outcome(&d, "stock"), HookOutcome::Same { calls: 1 });
        assert!(!d.passed());
    }

    #[test]
    fn hooks_sent_to_review_must_be_held_and_reported() {
        let held: BTreeMap<String, String> = [("price".to_owned(), "ambiguous".to_owned())].into();
        let manifest = manifest(&["price", "stock"]);

        // Held and reported: passes.
        let new = trace(vec![
            skip("price"),
            attach("stock", 0x280),
            call("stock", 0x280, "10", "30"),
        ]);
        let d = diff_traces(&old_run(), &new, &manifest, Some(&held));
        assert!(d.passed(), "{d:?}");
        assert_eq!(
            outcome(&d, "price"),
            HookOutcome::HeldForReview {
                reason: "ambiguous".into()
            }
        );

        // Applied although repair sent it to review: fails.
        let new = trace(vec![
            attach("price", 0x180),
            call("price", 0x180, "10", "470"),
            call("price", 0x180, "11", "507"),
            attach("stock", 0x280),
            call("stock", 0x280, "10", "30"),
        ]);
        let d = diff_traces(&old_run(), &new, &manifest, Some(&held));
        assert!(!d.passed());
        assert!(matches!(
            outcome(&d, "price"),
            HookOutcome::AppliedDespiteReview { .. }
        ));

        // Skipped, but repair didn't report it: fails.
        let new = trace(vec![attach("price", 0x180), skip("stock")]);
        let d = diff_traces(&old_run(), &new, &manifest, Some(&BTreeMap::new()));
        assert!(matches!(
            outcome(&d, "stock"),
            HookOutcome::SkippedUnreported { .. }
        ));
        assert!(!d.passed());
    }

    #[test]
    fn a_failed_attach_or_missing_hook_fails() {
        let new = trace(vec![TraceEvent::Attach {
            hook: "price".into(),
            rva: Rva(0x180),
            status: "error 13".into(),
        }]);
        let d = diff_traces(&old_run(), &new, &manifest(&["price", "stock"]), None);
        assert!(matches!(
            outcome(&d, "price"),
            HookOutcome::AttachFailed { .. }
        ));
        assert_eq!(outcome(&d, "stock"), HookOutcome::Missing);
        assert!(!d.passed());
    }

    #[test]
    fn a_baseline_must_attach_and_fire_every_hook() {
        let m = manifest(&["price", "stock"]);
        assert!(check_baseline(&old_run(), &m).passed());

        let quiet = trace(vec![
            attach("price", 0x100),
            attach("stock", 0x200),
            call("stock", 0x200, "1", "2"),
        ]);
        let d = check_baseline(&quiet, &m);
        assert_eq!(outcome(&d, "price"), HookOutcome::NotFired { expected: 0 });
        assert!(!d.passed());
    }

    fn candidate(old: u64, new: u64) -> Candidate {
        Candidate {
            old: Rva(old),
            new: Rva(new),
            source: permanent_beta_model::CandidateSource::Deterministic {
                matcher: "test".into(),
            },
            score: 1.0,
            evidence: vec![],
        }
    }

    fn features(rva: u64) -> FunctionFeatures {
        serde_json::from_value(serde_json::json!({ "rva": rva, "size": 16 })).unwrap()
    }

    #[test]
    fn runner_passes_identical_calls_and_fails_a_wrong_candidate() {
        let new = trace(vec![
            attach("price", 0x180),
            attach("stock", 0x280),
            call("stock", 0x280, "10", "30"),
            call("price", 0x180, "10", "470"),
            call("price", 0x180, "11", "507"),
        ]);
        let runner = TraceDiffRunner::new(old_run(), new);
        let (o, n) = (features(0x100), features(0x180));
        assert_eq!(
            runner.run(&candidate(0x100, 0x180), &o, &n).outcome,
            CheckOutcome::Pass
        );
        // Old price function paired with new stock function: the calls differ.
        let r = runner.run(&candidate(0x100, 0x280), &o, &features(0x280));
        assert_eq!(r.outcome, CheckOutcome::Fail, "{}", r.detail);
        // A candidate the new run never hooked is not evidence either way.
        assert_eq!(
            runner
                .run(&candidate(0x100, 0x380), &o, &features(0x380))
                .outcome,
            CheckOutcome::Inconclusive
        );
    }
}
