//! Engine: the only place where matching, verification and repair meet.
//!
//! The engine never decides acceptance itself; it routes candidates through `permanent-beta-verify`.

use permanent_beta_match::{MatchOutcome, Matcher, default_matchers, run_passes};
use permanent_beta_model::{
    Ambiguity, AnalysisExport, BuildId, Candidate, CandidateSource, Criticality, Decider, Evidence,
    FunctionFeatures, HookManifest, HookSpec, Mapping, MappingStatus, ReviewItem, Rva,
    VerificationReport,
};
use permanent_beta_repair::{HookRepair, RepairAction, decide, review_items, rewrite_manifest};
use permanent_beta_verify::{Policy, Verifier, VerifyContext};
use serde::Serialize;

pub use permanent_beta_repair;

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

    /// Repair every hook in `manifest`, moving it from `old` to `new`.
    pub fn repair(
        &self,
        manifest: &HookManifest,
        old: &AnalysisExport,
        new: &AnalysisExport,
    ) -> RepairReport {
        let outcome = run_passes(old, new, &self.matchers);
        let candidates = &outcome.candidates;
        let ctx = VerifyContext::new(old, new, candidates);
        let (from, to) = (&old.build.id, &new.build.id);

        let repairs: Vec<HookRepair> = manifest
            .hooks
            .iter()
            .map(|hook| {
                // TODO: if hook.target.build != old.build.id, route to review instead of trusting the locator.
                let old_fn = resolve_old(hook, old);
                let cand = old_fn.and_then(|f| candidates.iter().find(|c| c.old == f.rva));
                let new_fn = cand.and_then(|c| new.function(c.new));
                let policy = Policy::for_criticality(hook.criticality);
                let report = match (cand, old_fn, new_fn) {
                    (Some(c), Some(o), Some(n)) => {
                        Some(self.verifier.verify(&ctx, c, o, n, policy))
                    }
                    _ => None,
                };
                let alternatives = match (cand, old_fn) {
                    (None, Some(o)) => self.alternatives(&ctx, &outcome, o, new, policy),
                    _ => Vec::new(),
                };
                decide(hook, old_fn, report, new_fn, alternatives)
            })
            .collect();

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
