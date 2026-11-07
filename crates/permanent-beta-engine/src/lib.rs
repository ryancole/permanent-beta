//! Engine: the only place where matching, verification and repair meet.
//!
//! The engine never decides acceptance itself; it routes candidates through `permanent-beta-verify`.

use permanent_beta_match::{MatchOutcome, Matcher, default_matchers, run_passes};
use permanent_beta_model::{
    Ambiguity, AnalysisExport, BuildId, Candidate, CandidateSource, Criticality, Decider, Evidence,
    FunctionFeatures, HookManifest, HookSpec, Mapping, MappingStatus, PriorDecisions, ReviewItem,
    Rva, VerificationReport,
};
use permanent_beta_repair::{
    HookRepair, RepairAction, decide, from_review, review_items, rewrite_manifest, stale_locator,
};
use permanent_beta_verify::{BehavioralRunner, Policy, Verifier, VerifyContext};
use serde::Serialize;

pub use permanent_beta_repair;
pub use permanent_beta_verify;

pub struct Engine {
    matchers: Vec<Box<dyn Matcher>>,
    verifier: Verifier,
}

#[derive(Debug, Serialize)]
pub struct MatchReport {
    pub from_build: BuildId,
    pub to_build: BuildId,
    pub reports: Vec<VerificationReport>,
    /// Key groups the passes refused to resolve. Their functions also appear in `unmatched_*`.
    pub ambiguities: Vec<Ambiguity>,
    pub unmatched_old: Vec<Rva>,
    pub unmatched_new: Vec<Rva>,
}

#[derive(Debug, Serialize)]
pub struct RepairReport {
    pub from_build: BuildId,
    pub to_build: BuildId,
    pub repairs: Vec<HookRepair>,
    pub mappings: Vec<Mapping>,
    pub review_items: Vec<ReviewItem>,
    #[serde(skip)]
    pub updated_manifest: HookManifest,
}

impl RepairReport {
    pub fn needs_review(&self) -> bool {
        !self.review_items.is_empty()
    }
}

impl Engine {
    pub fn new(matchers: Vec<Box<dyn Matcher>>, verifier: Verifier) -> Self {
        Self { matchers, verifier }
    }

    pub fn with_defaults() -> Self {
        Self::new(default_matchers(), Verifier::with_defaults())
    }

    /// The default passes and checks, with behavioral evidence from `runner` (design §6.2).
    pub fn with_behavioral(runner: Box<dyn BehavioralRunner>) -> Self {
        Self::new(default_matchers(), Verifier::with_behavioral(runner))
    }

    /// Match every function and verify each candidate with the `normal` policy.
    pub fn match_builds(&self, old: &AnalysisExport, new: &AnalysisExport) -> MatchReport {
        let outcome = run_passes(old, new, &self.matchers);
        let candidates = &outcome.candidates;
        let ctx = VerifyContext::new(old, new, candidates);
        let policy = Policy::for_criticality(Criticality::Normal);
        let reports: Vec<VerificationReport> = candidates
            .iter()
            .filter_map(|c| {
                let (o, n) = (old.function(c.old)?, new.function(c.new)?);
                Some(self.verifier.verify(&ctx, c, o, n, policy))
            })
            .collect();

        let unmatched = |funcs: &[FunctionFeatures], claimed: &dyn Fn(Rva) -> bool| {
            funcs
                .iter()
                .map(|f| f.rva)
                .filter(|r| !claimed(*r))
                .collect::<Vec<_>>()
        };
        MatchReport {
            from_build: old.build.id.clone(),
            to_build: new.build.id.clone(),
            unmatched_old: unmatched(&old.functions, &|r: Rva| {
                candidates.iter().any(|c| c.old == r)
            }),
            unmatched_new: unmatched(&new.functions, &|r: Rva| {
                candidates.iter().any(|c| c.new == r)
            }),
            reports,
            ambiguities: outcome.ambiguities.clone(),
        }
    }

    /// Repair every hook in `manifest`, moving it from `old` to `new`, with no earlier review decisions.
    pub fn repair(
        &self,
        manifest: &HookManifest,
        old: &AnalysisExport,
        new: &AnalysisExport,
    ) -> RepairReport {
        self.repair_with(manifest, old, new, &PriorDecisions::default())
    }

    /// Repair every hook, honoring earlier review decisions for this build pair:
    /// - a mapping a reviewer accepted resolves its hook (the reviewer decided on its verification report);
    /// - an (old, new) pair a reviewer rejected is never used, as the candidate or as an alternative.
    pub fn repair_with(
        &self,
        manifest: &HookManifest,
        old: &AnalysisExport,
        new: &AnalysisExport,
        prior: &PriorDecisions,
    ) -> RepairReport {
        let outcome = run_passes(old, new, &self.matchers);
        let candidates = &outcome.candidates;
        let ctx = VerifyContext::new(old, new, candidates);
        let (from, to) = (&old.build.id, &new.build.id);

        let repairs: Vec<HookRepair> = manifest
            .hooks
            .iter()
            .map(|hook| {
                if hook.target.build != old.build.id {
                    return stale_locator(hook, from);
                }
                let old_fn = resolve_old(hook, old);
                let reviewed = old_fn.and_then(|o| {
                    let m = prior.accepted.iter().find(|m| m.old == o.rva)?;
                    let Decider::Human { reviewer } = &m.decided_by else {
                        return None;
                    };
                    Some((o, new.function(m.new)?, reviewer))
                });
                if let Some((o, n, reviewer)) = reviewed {
                    return from_review(hook, o, n, reviewer);
                }
                let rejected = |c_old: Rva, c_new: Rva| prior.rejected.contains(&(c_old, c_new));
                let cand = old_fn
                    .and_then(|f| candidates.iter().find(|c| c.old == f.rva))
                    .filter(|c| !rejected(c.old, c.new));
                let new_fn = cand.and_then(|c| new.function(c.new));
                let policy = Policy::for_criticality(hook.criticality);
                let report = match (cand, old_fn, new_fn) {
                    (Some(c), Some(o), Some(n)) => {
                        Some(self.verifier.verify(&ctx, c, o, n, policy))
                    }
                    _ => None,
                };
                let mut alternatives = match (cand, old_fn) {
                    (None, Some(o)) => self.alternatives(&ctx, &outcome, o, new, policy),
                    _ => Vec::new(),
                };
                alternatives.retain(|a| !rejected(a.candidate.old, a.candidate.new));
                let mut repair = decide(hook, old_fn, report, new_fn, alternatives);
                let refused: Vec<String> = old_fn
                    .map(|o| {
                        prior
                            .rejected
                            .iter()
                            .filter(|(r_old, _)| *r_old == o.rva)
                            .map(|(_, r_new)| r_new.to_string())
                            .collect()
                    })
                    .unwrap_or_default();
                if let RepairAction::NeedsReview { detail, .. } = &mut repair.action {
                    if !refused.is_empty() {
                        detail.push_str(&format!(" (a reviewer rejected {})", refused.join(", ")));
                    }
                }
                repair
            })
            .collect();

        // Engine decisions only: a reviewer's mapping is already in the store (its `verification` is None).
        let mappings = repairs
            .iter()
            .filter(|r| r.is_resolved())
            .filter_map(|r| {
                let v = r.verification.as_ref()?;
                let new = match r.action {
                    RepairAction::Unchanged { rva } => rva,
                    RepairAction::Relocated { new, .. } => new,
                    RepairAction::NeedsReview { .. } => return None,
                };
                Some(Mapping {
                    from_build: from.clone(),
                    to_build: to.clone(),
                    old: v.candidate.old,
                    new,
                    decided_by: Decider::Engine,
                    source: v.candidate.source.clone(),
                    score: v.candidate.score,
                    evidence: v.candidate.evidence.clone(),
                    checks: v.checks.clone(),
                    status: MappingStatus::Accepted,
                })
            })
            .collect();

        RepairReport {
            from_build: from.clone(),
            to_build: to.clone(),
            review_items: review_items(&repairs, from, to),
            updated_manifest: rewrite_manifest(manifest, &repairs, to),
            mappings,
            repairs,
        }
    }

    /// Verify each competitor of an ambiguous old function, purely as evidence for the reviewer.
    /// `decide` routes these to review regardless of their verdicts.
    fn alternatives(
        &self,
        ctx: &VerifyContext,
        outcome: &MatchOutcome,
        old_fn: &FunctionFeatures,
        new: &AnalysisExport,
        policy: Policy,
    ) -> Vec<VerificationReport> {
        let groups: Vec<&Ambiguity> = outcome
            .ambiguities
            .iter()
            .filter(|a| a.old.contains(&old_fn.rva))
            .collect();
        outcome
            .competitors(old_fn.rva)
            .into_iter()
            .filter_map(|rva| {
                let new_fn = new.function(rva)?;
                let mine: Vec<&&Ambiguity> =
                    groups.iter().filter(|a| a.new.contains(&rva)).collect();
                let candidate = Candidate {
                    old: old_fn.rva,
                    new: rva,
                    source: CandidateSource::Deterministic {
                        matcher: mine.first().map(|a| a.matcher.clone()).unwrap_or_default(),
                    },
                    score: 0.0,
                    evidence: mine
                        .iter()
                        .map(|a| Evidence {
                            kind: "ambiguous".into(),
                            detail: a.detail.clone(),
                        })
                        .collect(),
                };
                Some(
                    self.verifier
                        .verify(ctx, &candidate, old_fn, new_fn, policy),
                )
            })
            .collect()
    }
}

fn resolve_old<'a>(hook: &HookSpec, old: &'a AnalysisExport) -> Option<&'a FunctionFeatures> {
    hook.target
        .rva
        .and_then(|rva| old.function(rva))
        .or_else(|| {
            hook.target
                .symbol
                .as_deref()
                .and_then(|s| old.function_by_name(s))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use permanent_beta_model::{
        ANALYSIS_SCHEMA_VERSION, BuildInfo, Machine, Producer, ReviewReason, TargetLocator,
    };

    fn func(rva: u64, hash: &str) -> FunctionFeatures {
        FunctionFeatures {
            rva: Rva(rva),
            size: 64,
            name: None,
            name_source: None,
            normalized_hash: Some(hash.to_owned()),
            mnemonic_hash: None,
            inferred_args: None,
            entry: None,
            basic_blocks: None,
            edges: None,
            callees: vec![],
            strings: vec![],
            constants: vec![],
            imports: vec![],
            signature: None,
            mnemonic_counts: Default::default(),
        }
    }

    fn export(id: &str, functions: Vec<FunctionFeatures>) -> AnalysisExport {
        AnalysisExport {
            schema_version: ANALYSIS_SCHEMA_VERSION,
            build: BuildInfo {
                id: BuildId(id.to_owned()),
                file_name: "t.exe".into(),
                version: None,
                machine: Machine::X64,
                pdb: None,
            },
            producer: Producer {
                tool: "test".into(),
                version: "0".into(),
            },
            functions,
        }
    }

    fn manifest() -> HookManifest {
        HookManifest {
            hooks: vec![HookSpec {
                name: "H".into(),
                detour: None,
                criticality: Criticality::Normal,
                prototype: None,
                target: TargetLocator {
                    build: BuildId("a".into()),
                    rva: Some(Rva(0x10)),
                    symbol: None,
                    pattern: None,
                },
            }],
        }
    }

    /// The hook target 0x10 has two identical copies in the new build: the engine refuses to pick.
    fn ambiguous_pair() -> (AnalysisExport, AnalysisExport) {
        (
            export("a", vec![func(0x10, "k")]),
            export("b", vec![func(0x110, "k"), func(0x120, "k")]),
        )
    }

    fn human(new: u64) -> Mapping {
        Mapping {
            from_build: BuildId("a".into()),
            to_build: BuildId("b".into()),
            old: Rva(0x10),
            new: Rva(new),
            decided_by: Decider::Human {
                reviewer: "ryan".into(),
            },
            source: CandidateSource::Deterministic {
                matcher: "normalized-hash".into(),
            },
            score: 0.0,
            evidence: vec![],
            checks: vec![],
            status: MappingStatus::Accepted,
        }
    }

    #[test]
    fn without_decisions_an_ambiguous_hook_needs_review() {
        let (old, new) = ambiguous_pair();
        let r = Engine::with_defaults().repair(&manifest(), &old, &new);
        assert!(r.needs_review());
        assert_eq!(r.review_items[0].reason, ReviewReason::Ambiguous);
    }

    #[test]
    fn a_reviewer_accepted_mapping_resolves_the_hook() {
        let (old, new) = ambiguous_pair();
        let prior = PriorDecisions {
            accepted: vec![human(0x120)],
            rejected: vec![],
        };
        let r = Engine::with_defaults().repair_with(&manifest(), &old, &new, &prior);
        assert!(!r.needs_review(), "{:?}", r.review_items);
        assert_eq!(
            r.repairs[0].action,
            RepairAction::Relocated {
                old: Rva(0x10),
                new: Rva(0x120)
            }
        );
        assert_eq!(r.repairs[0].reviewed_by.as_deref(), Some("ryan"));
        assert!(
            r.mappings.is_empty(),
            "the reviewer mapping is already stored"
        );
        assert_eq!(r.updated_manifest.hooks[0].target.rva, Some(Rva(0x120)));
    }

    #[test]
    fn an_engine_mapping_in_prior_decisions_does_not_resolve_a_hook() {
        // Only human decisions short-circuit repair; engine mappings are recomputed every run.
        let (old, new) = ambiguous_pair();
        let mut engine_made = human(0x120);
        engine_made.decided_by = Decider::Engine;
        let prior = PriorDecisions {
            accepted: vec![engine_made],
            rejected: vec![],
        };
        let r = Engine::with_defaults().repair_with(&manifest(), &old, &new, &prior);
        assert!(r.needs_review());
    }

    #[test]
    fn a_rejected_candidate_is_never_used_again() {
        // The engine matches 0x10 to 0x110 uniquely; the reviewer said that is wrong.
        let old = export("a", vec![func(0x10, "k")]);
        let new = export("b", vec![func(0x110, "k")]);
        let prior = PriorDecisions {
            accepted: vec![],
            rejected: vec![(Rva(0x10), Rva(0x110))],
        };
        let r = Engine::with_defaults().repair_with(&manifest(), &old, &new, &prior);
        assert!(r.needs_review());
        assert!(r.mappings.is_empty());
        let RepairAction::NeedsReview { detail, .. } = &r.repairs[0].action else {
            panic!("{:?}", r.repairs[0].action);
        };
        assert!(detail.contains("reviewer rejected 0x110"), "{detail}");
        assert!(r.review_items[0].candidates.is_empty());
    }

    #[test]
    fn a_locator_bound_to_another_build_is_not_trusted() {
        // The hook was written for build "z" (e.g. an earlier repair sent it to review). Its RVA happens to be a
        // function in "a" with a unique match in "b"; relocating it would hook whatever "a" has at that address.
        let old = export("a", vec![func(0x10, "k")]);
        let new = export("b", vec![func(0x110, "k")]);
        let mut stale = manifest();
        stale.hooks[0].target.build = BuildId("z".into());
        let r = Engine::with_defaults().repair(&stale, &old, &new);
        assert!(r.needs_review());
        assert_eq!(r.review_items[0].reason, ReviewReason::StaleLocator);
        assert!(r.mappings.is_empty());
        assert_eq!(
            r.updated_manifest.hooks[0].target.build,
            BuildId("z".into())
        );
        assert_eq!(r.updated_manifest.hooks[0].target.rva, Some(Rva(0x10)));

        // Control: bound to the old build, the same hook is looked up and matched (this bare test function then
        // lacks independent evidence, which is a different review reason).
        let r = Engine::with_defaults().repair(&manifest(), &old, &new);
        assert_eq!(r.repairs[0].old, Some(Rva(0x10)));
        assert_eq!(
            r.repairs[0].verification.as_ref().map(|v| v.candidate.new),
            Some(Rva(0x110))
        );
    }

    #[test]
    fn rejected_alternatives_are_dropped_from_review() {
        let (old, new) = ambiguous_pair();
        let prior = PriorDecisions {
            accepted: vec![],
            rejected: vec![(Rva(0x10), Rva(0x110))],
        };
        let r = Engine::with_defaults().repair_with(&manifest(), &old, &new, &prior);
        let news: Vec<Rva> = r.review_items[0]
            .candidates
            .iter()
            .map(|c| c.candidate.new)
            .collect();
        assert_eq!(news, vec![Rva(0x120)]);
    }
}
