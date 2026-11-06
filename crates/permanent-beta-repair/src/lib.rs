//! Repair (design §7): decide what happens to each hook, rewrite the manifest, and emit review items.
//!
//! Planned generators: AOB pattern regeneration, offsets header (`hooks.gen.h`), struct-layout and prototype
//! adaptation proposals. The detour body is never rewritten automatically.

use permanent_beta_model::{
    BuildId, CheckOutcome, FunctionFeatures, HookManifest, HookSpec, ReviewItem, ReviewReason, Rva,
    Verdict, VerificationReport,
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
}

impl HookRepair {
    pub fn is_resolved(&self) -> bool {
        !matches!(self.action, RepairAction::NeedsReview { .. })
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
        hook: hook.name.clone(),
        old: old_fn.map(|f| f.rva),
        action: RepairAction::NeedsReview { reason, detail },
        verification: report,
        alternatives: Vec::new(),
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
        let rvas: Vec<String> = alternatives
            .iter()
            .map(|a| a.candidate.new.to_string())
            .collect();
        let mut repair = review(
            ReviewReason::Ambiguous,
            format!(
                "{} functions in the new build are equally plausible ({}); the engine will not pick one",
                rvas.len(),
                rvas.join(", ")
            ),
            None,
        );
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
            let action = if old_fn.rva == new_fn.rva {
                RepairAction::Unchanged { rva: new_fn.rva }
            } else {
                RepairAction::Relocated {
                    old: old_fn.rva,
                    new: new_fn.rva,
                }
            };
            HookRepair {
                hook: hook.name.clone(),
                old: Some(old_fn.rva),
                action,
                verification: Some(report),
                alternatives: Vec::new(),
            }
        }
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
/// TODO(design §7.2): regenerate and uniqueness-check AOB patterns for relocated hooks. Until then an existing
/// pattern is kept as-is and must be re-validated.
pub fn rewrite_manifest(
    manifest: &HookManifest,
    repairs: &[HookRepair],
    new_build: &BuildId,
) -> HookManifest {
    let mut out = manifest.clone();
    for hook in &mut out.hooks {
        let Some(repair) = repairs.iter().find(|r| r.hook == hook.name) else {
            continue;
        };
        let new_rva = match repair.action {
            RepairAction::Unchanged { rva } => rva,
            RepairAction::Relocated { new, .. } => new,
            RepairAction::NeedsReview { .. } => continue,
        };
        hook.target.build = new_build.clone();
        hook.target.rva = Some(new_rva);
    }
    out
}

/// Review items for every unresolved hook. Ids are stable per (hook, build pair).
pub fn review_items(repairs: &[HookRepair], from: &BuildId, to: &BuildId) -> Vec<ReviewItem> {
    repairs
        .iter()
        .filter_map(|r| match &r.action {
            RepairAction::NeedsReview { reason, detail } => Some(ReviewItem {
                id: format!("{}:{}:{}", r.hook, short(from), short(to)),
                hook: Some(r.hook.clone()),
                from_build: from.clone(),
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
            }),
            _ => None,
        })
        .collect()
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
            basic_blocks: None,
            edges: None,
            callees: vec![],
            strings: vec![],
            constants: vec![],
            imports: vec![],
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
        let items = review_items(&[r], &BuildId("old".into()), &BuildId("new".into()));
        assert_eq!(items[0].reason, ReviewReason::Ambiguous);
        assert_eq!(items[0].candidates.len(), 2);
    }
}
