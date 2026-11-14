//! The accepted function mappings of one build pair, for tools that carry work across builds (the IDA plugin's
//! markup carry-forward, design §11.4). Reads only: it records nothing and decides nothing.
//!
//! A mapping is listed when the engine accepted it (verification's verdict, `normal` policy) or a reviewer did,
//! by the same rules repair honors: a reviewer's accepted mapping wins, a pair a reviewer rejected is never
//! listed, and a function with an open review item is pending, since a human is still deciding it. Everything
//! else in the old build is pending, with the reason.

use crate::MatchReport;
use permanent_beta_model::{
    BuildId, Decider, Mapping, MappingStatus, PriorDecisions, Rva, Verdict,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Serialize)]
pub struct MappingsReport {
    pub from_build: BuildId,
    pub to_build: BuildId,
    /// One per old function, sorted by old RVA.
    pub mappings: Vec<Mapping>,
    /// Old functions with no accepted mapping, sorted by old RVA.
    pub pending: Vec<Pending>,
    /// Mapped functions whose given prototype doesn't fit the new function's register arguments (repair's check,
    /// `prototype_misfit`): a tool carrying the prototype across must not apply it. Only for functions a
    /// prototype was given for.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub prototype_misfits: Vec<PrototypeMisfit>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PrototypeMisfit {
    pub old: Rva,
    pub new: Rva,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Pending {
    pub old: Rva,
    pub reason: PendingReason,
    /// The candidate, when there is exactly one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidate: Option<Rva>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingReason {
    /// An open review item is about this function.
    InReview,
    /// Verification needs more evidence than the candidate has.
    NeedsReview,
    /// Verification rejected the candidate.
    VerificationRejected,
    /// A reviewer said the candidate isn't the counterpart.
    ReviewerRejected,
    /// A reviewer mapped another old function onto the candidate.
    CandidateClaimed,
    /// Several plausible counterparts; matching refused to pick.
    Ambiguous,
    /// No candidate at all (deleted, or changed beyond matching).
    Unmatched,
}

/// Pick the accepted mappings out of a match run. `in_review` is the old functions with an open review item for
/// this build pair.
pub fn select(report: MatchReport, prior: &PriorDecisions, in_review: &[Rva]) -> MappingsReport {
    let (from, to) = (report.from_build, report.to_build);
    let in_review: BTreeSet<Rva> = in_review.iter().copied().collect();
    let mut mappings: BTreeMap<Rva, Mapping> = BTreeMap::new();
    let mut pending: BTreeMap<Rva, Pending> = BTreeMap::new();
    let pend = |old: Rva, reason, candidate| Pending {
        old,
        reason,
        candidate,
    };

    for m in &prior.accepted {
        let human = matches!(m.decided_by, Decider::Human { .. });
        if human && m.status == MappingStatus::Accepted && m.from_build == from && m.to_build == to
        {
            mappings.insert(m.old, m.clone());
        }
    }
    let claimed: BTreeSet<Rva> = mappings.values().map(|m| m.new).collect();
    for &old in &in_review {
        if !mappings.contains_key(&old) {
            pending.insert(old, pend(old, PendingReason::InReview, None));
        }
    }

    for r in report.reports {
        let (old, new) = (r.candidate.old, r.candidate.new);
        if mappings.contains_key(&old) || pending.contains_key(&old) {
            continue;
        }
        let reason = if prior.rejected.contains(&(old, new)) {
            Some(PendingReason::ReviewerRejected)
        } else if claimed.contains(&new) {
            Some(PendingReason::CandidateClaimed)
        } else {
            match r.verdict {
                Verdict::Accepted => None,
                Verdict::NeedsReview => Some(PendingReason::NeedsReview),
                Verdict::Rejected => Some(PendingReason::VerificationRejected),
            }
        };
        match reason {
            Some(reason) => {
                pending.insert(old, pend(old, reason, Some(new)));
            }
            None => {
                mappings.insert(
                    old,
                    Mapping {
                        from_build: from.clone(),
                        to_build: to.clone(),
                        old,
                        new,
                        decided_by: Decider::Engine,
                        source: r.candidate.source,
                        score: r.candidate.score,
                        evidence: r.candidate.evidence,
                        checks: r.checks,
                        status: MappingStatus::Accepted,
                    },
                );
            }
        }
    }

    let ambiguous: BTreeSet<Rva> = report
        .ambiguities
        .iter()
        .flat_map(|a| a.old.iter().copied())
        .collect();
    for old in report
        .unmatched_old
        .into_iter()
        .chain(ambiguous.iter().copied())
    {
        if mappings.contains_key(&old) || pending.contains_key(&old) {
            continue;
        }
        let reason = if ambiguous.contains(&old) {
            PendingReason::Ambiguous
        } else {
            PendingReason::Unmatched
        };
        pending.insert(old, pend(old, reason, None));
    }

    MappingsReport {
        from_build: from,
        to_build: to,
        mappings: mappings.into_values().collect(),
        pending: pending.into_values().collect(),
        prototype_misfits: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use permanent_beta_model::{
        Ambiguity, Candidate, CandidateSource, CheckOutcome, CheckResult, VerificationReport,
    };

    fn report(old: u64, new: u64, verdict: Verdict) -> VerificationReport {
        VerificationReport {
            candidate: Candidate {
                old: Rva(old),
                new: Rva(new),
                source: CandidateSource::Deterministic {
                    matcher: "normalized-hash".into(),
                },
                score: 1.0,
                evidence: vec![],
            },
            checks: vec![CheckResult::new("callers", CheckOutcome::Pass, "1/1")],
            verdict,
        }
    }

    fn run(reports: Vec<VerificationReport>) -> MatchReport {
        MatchReport {
            from_build: BuildId("a".into()),
            to_build: BuildId("b".into()),
            reports,
            ambiguities: vec![],
            unmatched_old: vec![],
            unmatched_new: vec![],
        }
    }

    fn human(old: u64, new: u64) -> Mapping {
        Mapping {
            from_build: BuildId("a".into()),
            to_build: BuildId("b".into()),
            old: Rva(old),
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

    fn pairs(r: &MappingsReport) -> Vec<(u64, u64)> {
        r.mappings.iter().map(|m| (m.old.0, m.new.0)).collect()
    }

    fn reason(r: &MappingsReport, old: u64) -> Option<PendingReason> {
        r.pending
            .iter()
            .find(|p| p.old == Rva(old))
            .map(|p| p.reason)
    }

    #[test]
    fn only_accepted_verdicts_are_listed() {
        let r = select(
            run(vec![
                report(0x10, 0x110, Verdict::Accepted),
                report(0x20, 0x120, Verdict::NeedsReview),
                report(0x30, 0x130, Verdict::Rejected),
            ]),
            &PriorDecisions::default(),
            &[],
        );
        assert_eq!(pairs(&r), vec![(0x10, 0x110)]);
        assert_eq!(r.mappings[0].decided_by, Decider::Engine);
        assert_eq!(r.mappings[0].checks.len(), 1, "keeps its checks");
        // Negative: a candidate in review or rejected by verification is pending, never listed.
        assert_eq!(reason(&r, 0x20), Some(PendingReason::NeedsReview));
        assert_eq!(reason(&r, 0x30), Some(PendingReason::VerificationRejected));
        assert_eq!(r.pending[0].candidate, Some(Rva(0x120)));
    }

    #[test]
    fn a_reviewer_rejected_pair_is_never_listed() {
        // Negative: the engine accepts 0x10 -> 0x110, but a reviewer said it's wrong.
        let prior = PriorDecisions {
            accepted: vec![],
            rejected: vec![(Rva(0x10), Rva(0x110))],
        };
        let r = select(
            run(vec![report(0x10, 0x110, Verdict::Accepted)]),
            &prior,
            &[],
        );
        assert!(r.mappings.is_empty());
        assert_eq!(reason(&r, 0x10), Some(PendingReason::ReviewerRejected));
    }

    #[test]
    fn a_reviewer_accepted_mapping_wins_over_the_engine() {
        let prior = PriorDecisions {
            accepted: vec![human(0x10, 0x120)],
            rejected: vec![],
        };
        let r = select(
            run(vec![
                report(0x10, 0x110, Verdict::NeedsReview),
                // Negative: the engine's accepted pair for another function onto the reviewer's choice is held.
                report(0x20, 0x120, Verdict::Accepted),
            ]),
            &prior,
            &[],
        );
        assert_eq!(pairs(&r), vec![(0x10, 0x120)]);
        assert!(matches!(r.mappings[0].decided_by, Decider::Human { .. }));
        assert_eq!(reason(&r, 0x20), Some(PendingReason::CandidateClaimed));
    }

    #[test]
    fn only_live_reviewer_mappings_for_this_pair_count() {
        // Negative: a revoked or superseded mapping, an engine mapping and another pair's mapping aren't used.
        let mut revoked = human(0x10, 0x110);
        revoked.status = MappingStatus::Revoked;
        let mut superseded = human(0x20, 0x120);
        superseded.status = MappingStatus::Superseded;
        let mut engine = human(0x30, 0x130);
        engine.decided_by = Decider::Engine;
        let mut other_pair = human(0x40, 0x140);
        other_pair.from_build = BuildId("z".into());
        let prior = PriorDecisions {
            accepted: vec![revoked, superseded, engine, other_pair],
            rejected: vec![],
        };
        let r = select(run(vec![]), &prior, &[]);
        assert!(r.mappings.is_empty(), "{:?}", r.mappings);
    }

    #[test]
    fn a_function_in_review_is_pending_even_if_the_engine_accepts_it() {
        // Negative: e.g. a high-criticality hook's item, or one a reviewer reopened by revoking.
        let r = select(
            run(vec![report(0x10, 0x110, Verdict::Accepted)]),
            &PriorDecisions::default(),
            &[Rva(0x10)],
        );
        assert!(r.mappings.is_empty());
        assert_eq!(reason(&r, 0x10), Some(PendingReason::InReview));
    }

    #[test]
    fn ambiguous_and_unmatched_functions_are_pending() {
        let mut m = run(vec![]);
        m.ambiguities = vec![Ambiguity {
            matcher: "normalized-hash".into(),
            old: vec![Rva(0x10)],
            new: vec![Rva(0x110), Rva(0x120)],
            detail: String::new(),
        }];
        m.unmatched_old = vec![Rva(0x10), Rva(0x20)];
        let r = select(m, &PriorDecisions::default(), &[]);
        assert!(r.mappings.is_empty());
        assert_eq!(reason(&r, 0x10), Some(PendingReason::Ambiguous));
        assert_eq!(reason(&r, 0x20), Some(PendingReason::Unmatched));
        assert_eq!(r.pending.len(), 2);
    }
}
