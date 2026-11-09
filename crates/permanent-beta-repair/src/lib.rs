//! Repair (design §7): decide what happens to each hook, rewrite the manifest, and emit review items.
//!
//! Generators: trial manifests for collecting behavioral evidence on review candidates ([`trial_manifest`]),
//! the offsets header ([`header`]) and prototype proposals ([`prototype`]). AOB patterns need the binary, so the
//! analyzer generates them (`permanent_beta_analysis::native::pattern`). Struct-layout proposals are not built.
//! The detour body is never rewritten automatically.

pub mod harness;
pub mod header;
pub mod layout;
pub mod prototype;

use permanent_beta_model::{
    AnalysisExport, BuildId, CheckOutcome, FunctionFeatures, HookManifest, HookSpec,
    PrototypeProposal, ReviewItem, ReviewReason, Rva, StructLayoutProposal, Verdict,
    VerificationReport,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum RepairAction {
    Unchanged {
        rva: Rva,
    },
    Relocated {
        old: Rva,
        new: Rva,
    },
    NeedsReview {
        reason: ReviewReason,
        detail: String,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HookRepair {
    pub hook: String,
    pub old: Option<Rva>,
    pub action: RepairAction,
    pub verification: Option<VerificationReport>,
    /// Competing new-build functions when the match was ambiguous. Verified only to give the reviewer
    /// evidence; never accepted automatically.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alternatives: Vec<VerificationReport>,
    /// Set when a reviewer decided this hook's target (an accepted human mapping) instead of the engine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewed_by: Option<String>,
    /// The build this hook was repaired from, when it isn't the report's old build: a hook whose locator is
    /// bound to an older build is repaired from that build directly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_build: Option<BuildId>,
    /// Prototype proposals for candidates whose parameters seem to have changed (review only).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proposals: Vec<PrototypeProposal>,
    /// Structs the hook's prototype uses whose layout changed between the builds (review only).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub struct_proposals: Vec<StructLayoutProposal>,
}

impl HookRepair {
    fn new(hook: &HookSpec, old: Option<Rva>, action: RepairAction) -> Self {
        Self {
            hook: hook.name.clone(),
            old,
            action,
            verification: None,
            alternatives: Vec::new(),
            reviewed_by: None,
            from_build: None,
            proposals: Vec::new(),
            struct_proposals: Vec::new(),
        }
    }

    pub fn is_resolved(&self) -> bool {
        !matches!(self.action, RepairAction::NeedsReview { .. })
    }

    /// The new-build RVA of a resolved hook.
    pub fn new_rva(&self) -> Option<Rva> {
        match self.action {
            RepairAction::Unchanged { rva } => Some(rva),
            RepairAction::Relocated { new, .. } => Some(new),
            RepairAction::NeedsReview { .. } => None,
        }
    }
}

/// Decide the outcome for one hook.
///
/// `old_fn` is the hook target in the old analysis, `report` the verification of its candidate (if any),
/// `new_fn` the candidate's function in the new analysis, and `alternatives` the verified competitors when
/// matching found the target ambiguous. Alternatives only matter when there is no candidate; they are never
/// accepted.
pub fn decide(
    hook: &HookSpec,
    old_fn: Option<&FunctionFeatures>,
    report: Option<VerificationReport>,
    new_fn: Option<&FunctionFeatures>,
    alternatives: Vec<VerificationReport>,
) -> HookRepair {
    let review = |reason, detail: String, report| HookRepair {
        verification: report,
        ..HookRepair::new(
            hook,
            old_fn.map(|f| f.rva),
            RepairAction::NeedsReview { reason, detail },
        )
    };

    let Some(old_fn) = old_fn else {
        return review(
            ReviewReason::Unmatched,
            "hook target not found in the old analysis".into(),
            None,
        );
    };
    let (Some(report), Some(new_fn)) = (report, new_fn) else {
        if alternatives.is_empty() {
            return review(
                ReviewReason::Unmatched,
                "no candidate in the new build".into(),
                None,
            );
        }
        let detail = match &alternatives[..] {
            // One competitor: a pass only suggested it (e.g. a call position under a matched caller) or another
            // old function claims it too. Not "equally plausible": there's nothing to be equal to.
            [only] => {
                let why: Vec<&str> = only
                    .candidate
                    .evidence
                    .iter()
                    .map(|e| e.detail.as_str())
                    .collect();
                format!(
                    "the only candidate, {}, is unconfirmed ({}); the engine will not pick it",
                    only.candidate.new,
                    if why.is_empty() {
                        "no unique evidence".to_owned()
                    } else {
                        why.join("; ")
                    }
                )
            }
            many => format!(
                "{} functions in the new build are equally plausible ({}); the engine will not pick one",
                many.len(),
                many.iter()
                    .map(|a| a.candidate.new.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        };
        let mut repair = review(ReviewReason::Ambiguous, detail, None);
        repair.alternatives = alternatives;
        return repair;
    };

    let sig_changed =
        matches!((&old_fn.signature, &new_fn.signature), (Some(a), Some(b)) if a != b);

    let verdict = report.verdict;
    match verdict {
        Verdict::Rejected => review(
            ReviewReason::VerificationFailed,
            format!(
                "candidate {} rejected: {}",
                new_fn.rva,
                failing_checks(&report)
            ),
            Some(report),
        ),
        _ if sig_changed => review(
            ReviewReason::SignatureChanged,
            format!(
                "matched {}, but the signature changed; the hook may need adapting",
                new_fn.rva
            ),
            Some(report),
        ),
        Verdict::NeedsReview => {
            let failing = failing_checks(&report);
            if failing.is_empty() {
                review(
                    ReviewReason::InsufficientEvidence,
                    format!(
                        "candidate {}: checks passed but policy needs more evidence",
                        new_fn.rva
                    ),
                    Some(report),
                )
            } else {
                review(
                    ReviewReason::VerificationFailed,
                    format!("candidate {}: {failing}", new_fn.rva),
                    Some(report),
                )
            }
        }
        Verdict::Accepted => {
            // Same function, but can the hook actually be placed there? Unknown entry info (e.g. a hand-written
            // or Ghidra export without it) is not treated as a hazard.
            let hazards = new_fn.entry.map(|e| e.hazards()).unwrap_or_default();
            if !hazards.is_empty() {
                return review(
                    ReviewReason::NotHookable,
                    format!(
                        "matched {}, but it can't be patched safely: {}",
                        new_fn.rva,
                        hazards.join("; ")
                    ),
                    Some(report),
                );
            }
            // And does the hook's prototype still fit how the new function takes its arguments?
            if let Some(why) = hook
                .prototype
                .as_deref()
                .and_then(|p| prototype_misfit(p, old_fn, new_fn))
            {
                return review(
                    ReviewReason::SignatureChanged,
                    format!(
                        "matched {}, but the hook's prototype doesn't fit it: {why}",
                        new_fn.rva
                    ),
                    Some(report),
                );
            }
            let action = if old_fn.rva == new_fn.rva {
                RepairAction::Unchanged { rva: new_fn.rva }
            } else {
                RepairAction::Relocated {
                    old: old_fn.rva,
                    new: new_fn.rva,
                }
            };
            HookRepair {
                verification: Some(report),
                ..HookRepair::new(hook, Some(old_fn.rva), action)
            }
        }
    }
}

/// Win64 argument registers by slot: (integer, vector).
const ARG_REGISTERS: [(&str, &str); 4] = [
    ("rcx", "xmm0"),
    ("rdx", "xmm1"),
    ("r8", "xmm2"),
    ("r9", "xmm3"),
];

/// How the new function takes its register arguments, against the hook's prototype (design §6.1, calling
/// convention): a register argument the function reads that the prototype doesn't declare (the detour would pass
/// whatever is in it), or a slot read in the other register class than the prototype passes it (an `int` in rdx
/// where the function reads xmm1). Only what the old function didn't already do counts: a prototype that was
/// already loose for the old build isn't the repair's news. The inferred arguments are a lower bound (the analyzer
/// scans to the first call), so fewer than declared is never a misfit. `None` when it fits, or when there's
/// nothing to judge by (no inferred arguments, a prototype that doesn't parse, a variadic one).
pub fn prototype_misfit(
    prototype: &str,
    old: &FunctionFeatures,
    new: &FunctionFeatures,
) -> Option<String> {
    use permanent_beta_model::{ArgClass, ValueType};
    let proto = prototype::Prototype::parse(prototype)?;
    let declared: Vec<Option<ArgClass>> = proto
        .params
        .iter()
        .take(4)
        .map(|p| match harness::value_type(&p.ty) {
            ValueType::Float(_) => Some(ArgClass::Vector),
            ValueType::Int(_) | ValueType::Pointer => Some(ArgClass::Integer),
            // A struct by value or an unknown type: no class to compare.
            _ => None,
        })
        .collect();
    let problems = |f: &FunctionFeatures| -> Option<Vec<String>> {
        let n = usize::from(f.inferred_args?);
        let mut out = Vec::new();
        for (slot, &(int, vec)) in ARG_REGISTERS.iter().enumerate().take(n) {
            let class = f.inferred_arg_classes.get(slot).copied();
            let reg = |c: Option<ArgClass>| match c {
                Some(ArgClass::Vector) => vec,
                _ => int,
            };
            match declared.get(slot) {
                None => out.push(format!(
                    "it reads {} (argument {}), which the prototype doesn't declare",
                    reg(class),
                    slot + 1
                )),
                Some(Some(want)) if class.is_some_and(|c| c != *want) => out.push(format!(
                    "it reads argument {} from {}, where the prototype passes it in {}",
                    slot + 1,
                    reg(class),
                    reg(Some(*want))
                )),
                _ => {}
            }
        }
        Some(out)
    };
    let before = problems(old).unwrap_or_default();
    let news: Vec<String> = problems(new)?
        .into_iter()
        .filter(|p| !before.contains(p))
        .collect();
    (!news.is_empty()).then(|| news.join("; "))
}

/// A hook whose locator is bound to another build than `old_build`. Its RVA is an address in that other build,
/// so looking it up in the old analysis could land on an unrelated function. Typically a hook an earlier repair
/// sent to review: it keeps its old binding until a reviewer decides it, or until it's repaired from its own build.
pub fn stale_locator(hook: &HookSpec, old_build: &BuildId) -> HookRepair {
    HookRepair::new(
        hook,
        None,
        RepairAction::NeedsReview {
            reason: ReviewReason::StaleLocator,
            detail: format!(
                "locator is bound to build {}, not the old build {}; repair it from its own build (give that \
                 build's analysis too), or decide its earlier review item",
                short(&hook.target.build),
                short(old_build)
            ),
        },
    )
}

/// A hook whose target a reviewer already decided (an accepted human mapping for this build pair). Not
/// re-verified here: the reviewer decided on a verification report, which is stored with the mapping.
pub fn from_review(
    hook: &HookSpec,
    old_fn: &FunctionFeatures,
    new_fn: &FunctionFeatures,
    reviewer: &str,
) -> HookRepair {
    let action = if old_fn.rva == new_fn.rva {
        RepairAction::Unchanged { rva: new_fn.rva }
    } else {
        RepairAction::Relocated {
            old: old_fn.rva,
            new: new_fn.rva,
        }
    };
    HookRepair {
        reviewed_by: Some(reviewer.to_owned()),
        ..HookRepair::new(hook, Some(old_fn.rva), action)
    }
}

fn failing_checks(report: &VerificationReport) -> String {
    report
        .checks
        .iter()
        .filter(|c| c.outcome == CheckOutcome::Fail)
        .map(|c| format!("{} failed ({})", c.check, c.detail))
        .collect::<Vec<_>>()
        .join("; ")
}

/// Re-bind resolved hooks to the new build. Unresolved hooks keep their old locator.
///
/// A re-bound locator drops its AOB pattern: the pattern was checked against the old build only, and a locator
/// claims validity for its build. Regenerate patterns from the new binary (`pbeta repair --new-binary`).
pub fn rewrite_manifest(
    manifest: &HookManifest,
    repairs: &[HookRepair],
    new_build: &BuildId,
) -> HookManifest {
    let mut out = manifest.clone();
    for hook in &mut out.hooks {
        let Some(new_rva) = repairs
            .iter()
            .find(|r| r.hook == hook.name)
            .and_then(HookRepair::new_rva)
        else {
            continue;
        };
        hook.target.build = new_build.clone();
        hook.target.rva = Some(new_rva);
        hook.target.pattern = None;
    }
    out
}

/// A manifest a repair may start from. Trial manifests are refused: their trial bindings point at unverified
/// candidates, and repairing from one would treat a guess as the old build's truth.
pub fn check_input(manifest: &HookManifest) -> Result<(), String> {
    let trial: Vec<&str> = manifest
        .hooks
        .iter()
        .filter(|h| h.trial)
        .map(|h| h.name.as_str())
        .collect();
    if trial.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "this is a trial manifest (trial bindings: {}); repair from the repaired manifest instead",
            trial.join(", ")
        ))
    }
}

/// The candidate a trial run can test for this hook: it went to review for insufficient evidence only (no
/// check failed, so behavioral evidence could settle it), its single candidate wasn't rejected, and the new
/// function's entry can be patched. Ambiguous hooks aren't trialed: one detour can only sit at one address.
pub fn trial_candidate(repair: &HookRepair, new: &AnalysisExport) -> Option<Rva> {
    let RepairAction::NeedsReview {
        reason: ReviewReason::InsufficientEvidence,
        ..
    } = repair.action
    else {
        return None;
    };
    let v = repair.verification.as_ref()?;
    if v.verdict != Verdict::NeedsReview || v.checks.iter().any(|c| c.outcome == CheckOutcome::Fail)
    {
        return None;
    }
    let f = new.function(v.candidate.new)?;
    if f.entry.is_some_and(|e| !e.hazards().is_empty()) {
        return None;
    }
    Some(v.candidate.new)
}

/// The repaired manifest plus trial bindings: every [`trial_candidate`] is bound to the new build at its
/// candidate and marked `trial`. Running the new build under it records what each candidate does, for
/// `pbeta repair --old-trace --new-trace` to judge. Returns the manifest and the hooks it trials.
pub fn trial_manifest(
    updated: &HookManifest,
    repairs: &[HookRepair],
    new: &AnalysisExport,
) -> (HookManifest, Vec<String>) {
    let mut out = updated.clone();
    let mut trialed = Vec::new();
    for hook in &mut out.hooks {
        let Some(rva) = repairs
            .iter()
            .find(|r| r.hook == hook.name)
            .and_then(|r| trial_candidate(r, new))
        else {
            continue;
        };
        hook.target.build = new.build.id.clone();
        hook.target.rva = Some(rva);
        hook.target.pattern = None;
        hook.trial = true;
        trialed.push(hook.name.clone());
    }
    (out, trialed)
}

/// Review items for every unresolved hook. Ids are stable per (hook, build pair).
pub fn review_items(repairs: &[HookRepair], from: &BuildId, to: &BuildId) -> Vec<ReviewItem> {
    repairs
        .iter()
        .filter_map(|r| match &r.action {
            RepairAction::NeedsReview { reason, detail } => Some(ReviewItem {
                id: format!(
                    "{}:{}:{}",
                    r.hook,
                    short(r.from_build.as_ref().unwrap_or(from)),
                    short(to)
                ),
                hook: Some(r.hook.clone()),
                from_build: r.from_build.clone().unwrap_or_else(|| from.clone()),
                to_build: to.clone(),
                old: r.old,
                reason: *reason,
                detail: detail.clone(),
                candidates: r
                    .verification
                    .iter()
                    .chain(&r.alternatives)
                    .cloned()
                    .collect(),
                proposals: r.proposals.clone(),
                struct_proposals: r.struct_proposals.clone(),
                status: Default::default(),
            }),
            _ => None,
        })
        .collect()
}

/// The review item for a candidate proposed from outside the engine (the AI proposer, an MCP client), after
/// verification. It waits for a human whatever the verdict: an AI never accepts (design §8). The id is stable
/// per (old, new, build pair), so proposing the same pair again refreshes the item.
pub fn proposal_review_item(
    report: &VerificationReport,
    from: &BuildId,
    to: &BuildId,
) -> ReviewItem {
    let (o, n) = (report.candidate.old, report.candidate.new);
    let by = match &report.candidate.source {
        permanent_beta_model::CandidateSource::Ai { model } => model.clone(),
        permanent_beta_model::CandidateSource::Human { reviewer } => reviewer.clone(),
        permanent_beta_model::CandidateSource::Deterministic { matcher } => matcher.clone(),
    };
    let verdict = match report.verdict {
        Verdict::Accepted => "it would pass the acceptance policy",
        Verdict::NeedsReview => "it needs review",
        Verdict::Rejected => "rejected",
    };
    ReviewItem {
        id: format!("ai:{o}:{n}:{}:{}", short(from), short(to)),
        hook: None,
        from_build: from.clone(),
        to_build: to.clone(),
        old: Some(o),
        reason: ReviewReason::AiProposal,
        detail: format!(
            "proposed by {by}: {o} -> {n}; verification says {verdict}; a human decides"
        ),
        candidates: vec![report.clone()],
        proposals: Vec::new(),
        struct_proposals: Vec::new(),
        status: Default::default(),
    }
}

fn short(id: &BuildId) -> &str {
    id.0.get(..12).unwrap_or(&id.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use permanent_beta_model::{
        Candidate, CandidateSource, Criticality, FunctionSignature, Param, TargetLocator,
    };

    fn hook() -> HookSpec {
        HookSpec {
            name: "H".into(),
            detour: None,
            criticality: Criticality::Normal,
            prototype: None,
            trial: false,
            target: TargetLocator {
                build: BuildId("old".into()),
                rva: Some(Rva(0x10)),
                symbol: None,
                pattern: None,
            },
        }
    }

    fn func(rva: u64, params: usize) -> FunctionFeatures {
        FunctionFeatures {
            rva: Rva(rva),
            size: 10,
            name: None,
            name_source: None,
            normalized_hash: None,
            mnemonic_hash: None,
            inferred_args: None,
            inferred_arg_classes: vec![],
            entry: None,
            basic_blocks: None,
            mnemonic_counts: Default::default(),
            pseudocode: None,
            edges: None,
            callees: vec![],
            strings: vec![],
            constants: vec![],
            imports: vec![],
            data_refs: vec![],
            signature: Some(FunctionSignature {
                calling_convention: None,
                return_type: None,
                params: (0..params)
                    .map(|_| Param {
                        name: None,
                        ty: "int".into(),
                    })
                    .collect(),
            }),
            arg_accesses: vec![],
        }
    }

    fn report(verdict: Verdict) -> VerificationReport {
        VerificationReport {
            candidate: Candidate {
                old: Rva(0x10),
                new: Rva(0x20),
                source: CandidateSource::Deterministic {
                    matcher: "t".into(),
                },
                score: 1.0,
                evidence: vec![],
            },
            checks: vec![],
            verdict,
        }
    }

    #[test]
    fn accepted_and_moved_is_relocated() {
        let r = decide(
            &hook(),
            Some(&func(0x10, 1)),
            Some(report(Verdict::Accepted)),
            Some(&func(0x20, 1)),
            vec![],
        );
        assert_eq!(
            r.action,
            RepairAction::Relocated {
                old: Rva(0x10),
                new: Rva(0x20)
            }
        );
    }

    #[test]
    fn accepted_with_changed_signature_still_needs_review() {
        let r = decide(
            &hook(),
            Some(&func(0x10, 1)),
            Some(report(Verdict::Accepted)),
            Some(&func(0x20, 2)),
            vec![],
        );
        assert!(matches!(
            r.action,
            RepairAction::NeedsReview {
                reason: ReviewReason::SignatureChanged,
                ..
            }
        ));
    }

    #[test]
    fn unresolved_hooks_keep_old_locator() {
        let manifest = HookManifest {
            hooks: vec![hook()],
        };
        let r = decide(&hook(), Some(&func(0x10, 1)), None, None, vec![]);
        let out = rewrite_manifest(&manifest, &[r], &BuildId("new".into()));
        assert_eq!(out.hooks[0].target.build, BuildId("old".into()));
    }

    #[test]
    fn no_candidate_and_no_alternatives_is_unmatched() {
        let r = decide(&hook(), Some(&func(0x10, 1)), None, None, vec![]);
        assert!(matches!(
            r.action,
            RepairAction::NeedsReview {
                reason: ReviewReason::Unmatched,
                ..
            }
        ));
    }

    #[test]
    fn a_single_unconfirmed_competitor_is_not_called_equally_plausible() {
        let mut a = report(Verdict::Rejected);
        a.candidate.evidence = vec![permanent_beta_model::Evidence {
            kind: "ambiguous".into(),
            detail: "suggestion from caller 0x11d0".into(),
        }];
        let r = decide(&hook(), Some(&func(0x10, 1)), None, None, vec![a]);
        let RepairAction::NeedsReview { reason, detail } = &r.action else {
            panic!("{:?}", r.action);
        };
        assert_eq!(*reason, ReviewReason::Ambiguous);
        assert!(!detail.contains("equally plausible"), "{detail}");
        assert!(
            detail.contains("only candidate, 0x20, is unconfirmed (suggestion from caller 0x11d0)"),
            "{detail}"
        );
    }

    #[test]
    fn ambiguity_goes_to_review_even_if_alternatives_verify() {
        // Both competitors would pass verification on their own; the hook must still not resolve.
        let mut a = report(Verdict::Accepted);
        let mut b = report(Verdict::Accepted);
        a.candidate.new = Rva(0x20);
        b.candidate.new = Rva(0x30);
        let r = decide(&hook(), Some(&func(0x10, 1)), None, None, vec![a, b]);

        assert!(!r.is_resolved());
        assert!(matches!(
            r.action,
            RepairAction::NeedsReview {
                reason: ReviewReason::Ambiguous,
                ..
            }
        ));
        let RepairAction::NeedsReview { detail, .. } = &r.action else {
            unreachable!()
        };
        assert!(
            detail.starts_with("2 functions in the new build are equally plausible (0x20, 0x30)"),
            "{detail}"
        );
        let items = review_items(&[r], &BuildId("old".into()), &BuildId("new".into()));
        assert_eq!(items[0].reason, ReviewReason::Ambiguous);
        assert_eq!(items[0].candidates.len(), 2);
    }

    #[test]
    fn a_rebound_locator_drops_its_unchecked_pattern() {
        let mut manifest = HookManifest {
            hooks: vec![hook()],
        };
        manifest.hooks[0].target.pattern = Some("48 89 5C 24 ??".into());
        let moved = decide(
            &hook(),
            Some(&func(0x10, 1)),
            Some(report(Verdict::Accepted)),
            Some(&func(0x20, 1)),
            vec![],
        );
        let out = rewrite_manifest(&manifest, &[moved], &BuildId("new".into()));
        assert_eq!(out.hooks[0].target.rva, Some(Rva(0x20)));
        assert_eq!(out.hooks[0].target.pattern, None);

        // A hook left in review keeps its old binding, pattern included: it's still valid for the old build.
        let held = decide(&hook(), Some(&func(0x10, 1)), None, None, vec![]);
        let out = rewrite_manifest(&manifest, &[held], &BuildId("new".into()));
        assert_eq!(
            out.hooks[0].target.pattern.as_deref(),
            Some("48 89 5C 24 ??")
        );
    }

    fn export(functions: Vec<FunctionFeatures>) -> AnalysisExport {
        serde_json::from_value(serde_json::json!({
            "schema_version": permanent_beta_model::ANALYSIS_SCHEMA_VERSION,
            "build": { "id": "new", "file_name": "t.exe", "version": null, "machine": "x64", "pdb": null },
            "producer": { "tool": "test", "version": "0" },
            "functions": functions,
        }))
        .unwrap()
    }

    #[test]
    fn only_insufficient_evidence_candidates_are_trialed() {
        use permanent_beta_model::{CheckResult, EntryInfo};
        let new = export(vec![func(0x20, 1)]);
        let manifest = HookManifest {
            hooks: vec![hook()],
        };
        let waiting = decide(
            &hook(),
            Some(&func(0x10, 1)),
            Some(report(Verdict::NeedsReview)),
            Some(&func(0x20, 1)),
            vec![],
        );
        let (trial, names) = trial_manifest(&manifest, std::slice::from_ref(&waiting), &new);
        assert_eq!(names, vec!["H".to_owned()]);
        assert!(trial.hooks[0].trial);
        assert_eq!(trial.hooks[0].target.rva, Some(Rva(0x20)));
        assert_eq!(trial.hooks[0].target.build, BuildId("new".into()));
        assert!(
            check_input(&trial).is_err(),
            "a trial manifest can't be repaired from"
        );
        assert!(check_input(&manifest).is_ok());

        // A failing check: behavioral evidence can't settle it, so no trial.
        let mut failing = report(Verdict::NeedsReview);
        failing.checks = vec![CheckResult::new("callers", CheckOutcome::Fail, "0/2")];
        let failed = decide(
            &hook(),
            Some(&func(0x10, 1)),
            Some(failing),
            Some(&func(0x20, 1)),
            vec![],
        );
        assert_eq!(trial_candidate(&failed, &new), None);
        // Ambiguous, unmatched or already resolved: nothing to trial.
        let mut a = report(Verdict::Accepted);
        a.candidate.new = Rva(0x30);
        let ambiguous = decide(
            &hook(),
            Some(&func(0x10, 1)),
            None,
            None,
            vec![a.clone(), a],
        );
        assert_eq!(trial_candidate(&ambiguous, &new), None);
        let resolved = decide(
            &hook(),
            Some(&func(0x10, 1)),
            Some(report(Verdict::Accepted)),
            Some(&func(0x20, 1)),
            vec![],
        );
        assert_eq!(trial_candidate(&resolved, &new), None);
        // An entry Detours can't patch.
        let mut short_fn = func(0x20, 1);
        short_fn.entry = Some(EntryInfo {
            patch_len: 3,
            branch_into_patch: false,
            jump_thunk: false,
        });
        assert_eq!(trial_candidate(&waiting, &export(vec![short_fn])), None);
    }

    #[test]
    fn verified_match_onto_an_unpatchable_function_needs_review() {
        use permanent_beta_model::EntryInfo;
        let mut new = func(0x20, 1);
        new.entry = Some(EntryInfo {
            patch_len: 3,
            branch_into_patch: false,
            jump_thunk: false,
        });
        let r = decide(
            &hook(),
            Some(&func(0x10, 1)),
            Some(report(Verdict::Accepted)),
            Some(&new),
            vec![],
        );
        assert!(!r.is_resolved());
        assert!(matches!(
            r.action,
            RepairAction::NeedsReview {
                reason: ReviewReason::NotHookable,
                ..
            }
        ));
    }

    #[test]
    fn patchable_function_is_relocated() {
        use permanent_beta_model::EntryInfo;
        let mut new = func(0x20, 1);
        new.entry = Some(EntryInfo {
            patch_len: 6,
            branch_into_patch: false,
            jump_thunk: false,
        });
        let r = decide(
            &hook(),
            Some(&func(0x10, 1)),
            Some(report(Verdict::Accepted)),
            Some(&new),
            vec![],
        );
        assert!(r.is_resolved());
    }

    /// `f` reading `classes` as its register arguments (the analyzer's inference).
    fn reads(
        mut f: FunctionFeatures,
        classes: &[permanent_beta_model::ArgClass],
    ) -> FunctionFeatures {
        f.inferred_args = Some(classes.len() as u8);
        f.inferred_arg_classes = classes.to_vec();
        f.signature = None;
        f
    }

    fn with_prototype(p: &str) -> HookSpec {
        HookSpec {
            prototype: Some(p.into()),
            ..hook()
        }
    }

    #[test]
    fn a_prototype_that_fits_is_relocated() {
        use permanent_beta_model::ArgClass::{Integer, Vector};
        let h = with_prototype("int f(int a, double b)");
        let r = decide(
            &h,
            Some(&reads(func(0x10, 0), &[Integer, Vector])),
            Some(report(Verdict::Accepted)),
            Some(&reads(func(0x20, 0), &[Integer, Vector])),
            vec![],
        );
        assert!(r.is_resolved(), "{:?}", r.action);
        // Fewer registers read than declared: the inference is a lower bound, never a misfit.
        let r = decide(
            &h,
            Some(&reads(func(0x10, 0), &[Integer, Vector])),
            Some(report(Verdict::Accepted)),
            Some(&reads(func(0x20, 0), &[Integer])),
            vec![],
        );
        assert!(r.is_resolved(), "{:?}", r.action);
    }

    #[test]
    fn a_new_argument_register_the_prototype_lacks_needs_review() {
        // Negative: the new function reads r8, which the two-parameter prototype doesn't pass.
        use permanent_beta_model::ArgClass::Integer;
        let r = decide(
            &with_prototype("int f(int a, int b)"),
            Some(&reads(func(0x10, 0), &[Integer, Integer])),
            Some(report(Verdict::Accepted)),
            Some(&reads(func(0x20, 0), &[Integer, Integer, Integer])),
            vec![],
        );
        match &r.action {
            RepairAction::NeedsReview {
                reason: ReviewReason::SignatureChanged,
                detail,
            } => assert!(detail.contains("r8"), "{detail}"),
            other => panic!("expected review, got {other:?}"),
        }
    }

    #[test]
    fn an_argument_in_the_other_register_class_needs_review() {
        // Negative: the prototype passes an int in rdx; the new function reads xmm1.
        use permanent_beta_model::ArgClass::{Integer, Vector};
        let r = decide(
            &with_prototype("int f(int a, int b)"),
            Some(&reads(func(0x10, 0), &[Integer, Integer])),
            Some(report(Verdict::Accepted)),
            Some(&reads(func(0x20, 0), &[Integer, Vector])),
            vec![],
        );
        match &r.action {
            RepairAction::NeedsReview {
                reason: ReviewReason::SignatureChanged,
                detail,
            } => assert!(
                detail.contains("xmm1") && detail.contains("rdx"),
                "{detail}"
            ),
            other => panic!("expected review, got {other:?}"),
        }
    }

    #[test]
    fn a_misfit_the_old_function_already_had_isnt_news() {
        // The prototype never declared the third argument; both builds read r8. Not the repair's business.
        use permanent_beta_model::ArgClass::Integer;
        let r = decide(
            &with_prototype("int f(int a, int b)"),
            Some(&reads(func(0x10, 0), &[Integer, Integer, Integer])),
            Some(report(Verdict::Accepted)),
            Some(&reads(func(0x20, 0), &[Integer, Integer, Integer])),
            vec![],
        );
        assert!(r.is_resolved(), "{:?}", r.action);
        // Nothing to judge by: no inference, or a variadic prototype.
        assert_eq!(
            prototype_misfit("int f(int a)", &func(0x10, 0), &func(0x20, 0)),
            None
        );
        assert_eq!(
            prototype_misfit(
                "int f(const char* fmt, ...)",
                &reads(func(0x10, 0), &[Integer]),
                &reads(func(0x20, 0), &[Integer, Integer])
            ),
            None
        );
    }
}
