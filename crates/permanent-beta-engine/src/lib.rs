//! Engine: the only place where matching, verification and repair meet.
//!
//! The engine never decides acceptance itself; it routes candidates through `permanent-beta-verify`.

use permanent_beta_match::{MatchOutcome, Matcher, default_matchers, run_passes};
use permanent_beta_model::{
    Ambiguity, AnalysisExport, BuildId, Candidate, CandidateSource, Criticality, Decider, Evidence,
    FunctionFeatures, HookManifest, HookSpec, Mapping, MappingStatus, PriorDecisions, ReviewItem,
    ReviewReason, Rva, VerificationReport,
};
use permanent_beta_repair::{
    HookRepair, RepairAction, decide, from_review, layout, prototype, review_items,
    rewrite_manifest, stale_locator,
};
use permanent_beta_verify::{BehavioralRunner, Policy, Verifier, VerifyContext};
use serde::Serialize;
use std::collections::BTreeMap;

pub mod recorded;

pub use permanent_beta_match;
pub use permanent_beta_repair;
pub use permanent_beta_replay;
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

    /// Attach verified outside proposals (the AI proposer, design §8) to a hook that matching left with no
    /// candidate at all (`unmatched`). They become alternatives in that hook's review item, for a reviewer to
    /// pick or reject: never the hook's target, never a mapping, and the hook stays in review. Proposals for
    /// another old function are dropped. Returns how many were attached; 0 if the hook isn't unmatched.
    pub fn attach_proposals(&mut self, hook: &str, proposals: Vec<VerificationReport>) -> usize {
        let Some(r) = self.repairs.iter_mut().find(|r| {
            r.hook == hook
                && matches!(
                    r.action,
                    RepairAction::NeedsReview {
                        reason: ReviewReason::Unmatched,
                        ..
                    }
                )
        }) else {
            return 0;
        };
        let before = r.alternatives.len();
        for p in proposals {
            let new = p.candidate.new;
            if Some(p.candidate.old) == r.old
                && !r.alternatives.iter().any(|a| a.candidate.new == new)
            {
                r.alternatives.push(p);
            }
        }
        let added = r.alternatives.len() - before;
        if added > 0 {
            if let RepairAction::NeedsReview { detail, .. } = &mut r.action {
                detail.push_str(&format!(
                    "; {added} outside proposal(s) attached for review, never applied"
                ));
            }
            self.review_items = review_items(&self.repairs, &self.from_build, &self.to_build);
        }
        added
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

    /// Verify one candidate proposed from outside the engine (an AI proposer, an MCP client) exactly like the
    /// engine's own: the same checks and policy, with this build pair's match run as the neighbour context.
    /// `None` if either function isn't in its analysis. Records and accepts nothing; the caller routes the
    /// report to review.
    pub fn verify_candidate(
        &self,
        old: &AnalysisExport,
        new: &AnalysisExport,
        candidate: &Candidate,
        criticality: Criticality,
    ) -> Option<VerificationReport> {
        let (o, n) = (old.function(candidate.old)?, new.function(candidate.new)?);
        let outcome = run_passes(old, new, &self.matchers);
        let ctx = VerifyContext::new(old, new, &outcome.candidates);
        Some(
            self.verifier
                .verify(&ctx, candidate, o, n, Policy::for_criticality(criticality)),
        )
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
        let priors = BTreeMap::from([(old.build.id.clone(), prior.clone())]);
        self.repair_across(manifest, old, &[], new, &priors)
    }

    /// Repair every hook to `new`, each from the build its locator is bound to: `old` (the previous build), or
    /// one of `earlier`, older builds that hooks an earlier repair sent to review are still bound to. Such a hook
    /// is matched from its own build straight to `new` (e.g. v1 → v3), never through `old`, where its RVA means
    /// nothing. A hook bound to a build that isn't given is a stale locator.
    ///
    /// `priors` holds review decisions per source build (for the pair source → `new`).
    pub fn repair_across(
        &self,
        manifest: &HookManifest,
        old: &AnalysisExport,
        earlier: &[AnalysisExport],
        new: &AnalysisExport,
        priors: &BTreeMap<BuildId, PriorDecisions>,
    ) -> RepairReport {
        let (from, to) = (&old.build.id, &new.build.id);
        // One match run per source build that some hook needs (always the old build: its mappings are recorded).
        let mut pairs: Vec<Pair> = vec![Pair::new(old, new, &self.matchers)];
        for hook in &manifest.hooks {
            let b = &hook.target.build;
            if pairs.iter().any(|p| &p.old.build.id == b) {
                continue;
            }
            if let Some(e) = earlier.iter().find(|e| &e.build.id == b) {
                pairs.push(Pair::new(e, new, &self.matchers));
            }
        }
        let none = PriorDecisions::default();

        let repairs: Vec<HookRepair> = manifest
            .hooks
            .iter()
            .map(|hook| {
                let Some(pair) = pairs.iter().find(|p| p.old.build.id == hook.target.build) else {
                    return stale_locator(hook, from);
                };
                let prior = priors.get(&pair.old.build.id).unwrap_or(&none);
                let mut repair = self.repair_hook(hook, pair, new, prior);
                if &pair.old.build.id != from {
                    repair.from_build = Some(pair.old.build.id.clone());
                }
                repair
            })
            .collect();

        // Engine decisions only: a reviewer's mapping is already in the store (its `verification` is None).
        let mappings = repairs
            .iter()
            .filter_map(|r| {
                let v = r.verification.as_ref()?;
                Some(Mapping {
                    from_build: r.from_build.clone().unwrap_or_else(|| from.clone()),
                    to_build: to.clone(),
                    old: v.candidate.old,
                    new: r.new_rva()?,
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

    /// Repair one hook within one build pair.
    fn repair_hook(
        &self,
        hook: &HookSpec,
        pair: &Pair,
        new: &AnalysisExport,
        prior: &PriorDecisions,
    ) -> HookRepair {
        let old = pair.old;
        let candidates = &pair.outcome.candidates;
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
            (Some(c), Some(o), Some(n)) => Some(self.verifier.verify(&pair.ctx, c, o, n, policy)),
            _ => None,
        };
        let mut alternatives = match (cand, old_fn) {
            (None, Some(o)) => self.alternatives(&pair.ctx, &pair.outcome, o, new, policy),
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
        // A hook in review whose candidates read more register arguments than its prototype declares gets a
        // proposed prototype and shim for each such candidate (design §7.2; suggestions only).
        if let (false, Some(o)) = (repair.is_resolved(), old_fn) {
            repair.proposals = repair
                .verification
                .iter()
                .chain(&repair.alternatives)
                .filter_map(|v| {
                    prototype::propose(hook, o, new.function(v.candidate.new)?, &new.build.id)
                })
                .collect();
        }
        // A struct the prototype uses changed layout (both builds' PDB types, design §7.2): even a verified match
        // goes to review, since the detour may read the wrong fields. The function match itself still stands
        // as the review item's candidate; no mapping is recorded until a reviewer accepts it.
        repair.struct_proposals = layout::propose(hook, pair.old, new);
        if !repair.struct_proposals.is_empty() {
            let what: Vec<String> = repair
                .struct_proposals
                .iter()
                .map(|p| format!("{} ({})", p.name, p.changes.join("; ")))
                .collect();
            let resolved_at = repair.new_rva();
            match (&mut repair.action, resolved_at) {
                (RepairAction::NeedsReview { detail, .. }, _) => {
                    detail.push_str(&format!("; struct layout changed: {}", what.join(", ")));
                }
                (_, Some(at)) => {
                    repair.action = RepairAction::NeedsReview {
                        reason: ReviewReason::StructLayoutChanged,
                        detail: format!(
                            "matched {at}, but a struct the hook uses changed layout: {}; the detour may read \
                             the wrong fields",
                            what.join(", ")
                        ),
                    };
                }
                _ => {}
            }
        }
        repair
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

/// One source build matched against the new build.
struct Pair<'a> {
    old: &'a AnalysisExport,
    outcome: MatchOutcome,
    ctx: VerifyContext,
}

impl<'a> Pair<'a> {
    fn new(old: &'a AnalysisExport, new: &AnalysisExport, matchers: &[Box<dyn Matcher>]) -> Self {
        let outcome = run_passes(old, new, matchers);
        let ctx = VerifyContext::new(old, new, &outcome.candidates);
        Self { old, outcome, ctx }
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
            inferred_arg_classes: vec![],
            entry: None,
            basic_blocks: None,
            edges: None,
            callees: vec![],
            strings: vec![],
            constants: vec![],
            imports: vec![],
            data_refs: vec![],
            signature: None,
            mnemonic_counts: Default::default(),
            pseudocode: None,
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
            code_tables: Vec::new(),
            types: Vec::new(),
            globals: Vec::new(),
            data_symbols: Vec::new(),
        }
    }

    fn manifest() -> HookManifest {
        HookManifest {
            hooks: vec![HookSpec {
                name: "H".into(),
                detour: None,
                criticality: Criticality::Normal,
                prototype: None,
                trial: false,
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
    fn a_stale_hook_is_repaired_from_its_own_build() {
        // The hook was written for "z" at 0x10. In "a" (the previous build) 0x10 is an unrelated function; given
        // z's analysis, the hook is matched z -> b directly.
        let z = export("z", vec![func(0x10, "hooked"), func(0x40, "other")]);
        let old = export("a", vec![func(0x10, "other"), func(0x30, "hooked")]);
        let new = export("b", vec![func(0x110, "other"), func(0x130, "hooked")]);
        let mut stale = manifest();
        stale.hooks[0].target.build = BuildId("z".into());

        let r = Engine::with_defaults().repair_across(
            &stale,
            &old,
            std::slice::from_ref(&z),
            &new,
            &BTreeMap::new(),
        );
        let repair = &r.repairs[0];
        assert_eq!(repair.from_build, Some(BuildId("z".into())));
        assert_eq!(repair.old, Some(Rva(0x10)));
        assert_eq!(
            repair.verification.as_ref().map(|v| v.candidate.new),
            Some(Rva(0x130)),
            "matched through z, not through a's 0x10"
        );
        // Its review item (bare test functions lack independent evidence) is for the pair z -> b.
        assert_eq!(r.review_items[0].from_build, BuildId("z".into()));
        assert!(
            r.review_items[0].id.starts_with("H:z:b"),
            "{}",
            r.review_items[0].id
        );

        // Without z's analysis it stays a stale locator.
        let r = Engine::with_defaults().repair_across(&stale, &old, &[], &new, &BTreeMap::new());
        assert_eq!(r.review_items[0].reason, ReviewReason::StaleLocator);
    }

    #[test]
    fn a_changed_register_signature_gets_a_prototype_proposal() {
        // Two identical candidates (ambiguous), each reading a third register argument.
        let mut old_fn = func(0x10, "k");
        old_fn.inferred_args = Some(2);
        let mut copies = vec![func(0x110, "k"), func(0x120, "k")];
        for c in &mut copies {
            c.inferred_args = Some(3);
        }
        let (old, new) = (export("a", vec![old_fn]), export("b", copies));
        let mut m = manifest();
        m.hooks[0].prototype = Some("void H(const char* msg, int code)".into());
        let r = Engine::with_defaults().repair(&m, &old, &new);
        assert!(!r.repairs[0].is_resolved());
        let proposed: Vec<Rva> = r.repairs[0].proposals.iter().map(|p| p.candidate).collect();
        assert_eq!(proposed, vec![Rva(0x110), Rva(0x120)]);
        for p in &r.repairs[0].proposals {
            assert_eq!(
                p.prototype,
                "void H(const char* msg, int code, intptr_t arg2)"
            );
        }

        // Negative: the same register use proposes nothing.
        let mut same = new.clone();
        for f in &mut same.functions {
            f.inferred_args = Some(2);
        }
        let r2 = Engine::with_defaults().repair(&m, &old, &same);
        assert!(r2.repairs[0].proposals.is_empty());
        assert_eq!(r.review_items[0].proposals, r.repairs[0].proposals);
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

    fn ai_candidate(old: u64, new: u64) -> Candidate {
        Candidate {
            old: Rva(old),
            new: Rva(new),
            source: CandidateSource::Ai {
                model: "claude-opus-5-5".into(),
            },
            score: 0.9,
            evidence: vec![Evidence {
                kind: permanent_beta_model::evidence_kind::AI.into(),
                detail: "same role".into(),
            }],
        }
    }

    /// The hook target 0x10 has no counterpart the passes can find.
    fn unmatched_pair() -> (AnalysisExport, AnalysisExport) {
        (
            export("a", vec![func(0x10, "k")]),
            export("b", vec![func(0x110, "z")]),
        )
    }

    #[test]
    fn an_ai_proposal_is_attached_to_an_unmatched_hooks_review_item_and_never_applied() {
        let (old, new) = unmatched_pair();
        let engine = Engine::with_defaults();
        let mut r = engine.repair(&manifest(), &old, &new);
        assert!(matches!(
            r.repairs[0].action,
            RepairAction::NeedsReview {
                reason: ReviewReason::Unmatched,
                ..
            }
        ));
        let v = engine
            .verify_candidate(&old, &new, &ai_candidate(0x10, 0x110), Criticality::Normal)
            .unwrap();
        assert_eq!(r.attach_proposals("H", vec![v]), 1);
        // Still in review, no mapping, the manifest unchanged; the proposal is a candidate in the review item.
        assert!(!r.repairs[0].is_resolved());
        assert!(r.mappings.is_empty());
        assert_eq!(r.updated_manifest.hooks[0].target.rva, Some(Rva(0x10)));
        assert_eq!(r.review_items.len(), 1);
        let item = &r.review_items[0];
        assert_eq!(item.reason, ReviewReason::Unmatched);
        assert_eq!(item.candidates.len(), 1);
        assert_eq!(item.candidates[0].candidate.new, Rva(0x110));
        assert!(item.detail.contains("never applied"), "{}", item.detail);
    }

    #[test]
    fn proposals_attach_only_to_unmatched_hooks_and_their_own_function() {
        // Negative: an ambiguous hook already has the engine's competitors; it takes no outside proposal.
        let (old, new) = ambiguous_pair();
        let engine = Engine::with_defaults();
        let mut r = engine.repair(&manifest(), &old, &new);
        let v = engine
            .verify_candidate(&old, &new, &ai_candidate(0x10, 0x110), Criticality::Normal)
            .unwrap();
        assert_eq!(r.attach_proposals("H", vec![v]), 0);
        // Negative: a proposal about another old function is dropped.
        let (old, new) = unmatched_pair();
        let mut r = engine.repair(&manifest(), &old, &new);
        let mut v = engine
            .verify_candidate(&old, &new, &ai_candidate(0x10, 0x110), Criticality::Normal)
            .unwrap();
        v.candidate.old = Rva(0x99);
        assert_eq!(r.attach_proposals("H", vec![v]), 0);
        assert!(r.review_items[0].candidates.is_empty());
        // Negative: an unknown hook.
        assert_eq!(r.attach_proposals("nope", vec![]), 0);
    }
}
