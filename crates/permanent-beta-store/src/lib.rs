//! Storage (design §9). [`MappingStore`] is the boundary; [`JsonFileStore`] is a stand-in for the planned
//! SQLite backend.
//!
//! Mappings are append-only: writing a mapping for an (from, to, old) key that already has an accepted
//! mapping marks the old one `superseded` rather than editing it. Review decisions are an append-only log too.

use permanent_beta_model::{
    BuildId, CheckOutcome, Decider, DecisionAction, Mapping, MappingStatus, PriorDecisions,
    ReviewDecision, ReviewItem, ReviewStatus, Rva, Verdict, VerificationReport,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

pub const STORE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("store I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("store data is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported store schema version {0}")]
    SchemaVersion(u32),
    /// A review decision the store refuses, with the reason.
    #[error("{0}")]
    Refused(String),
}

/// What a reviewer chose for a review item.
#[derive(Debug, Clone, PartialEq)]
pub enum Choice {
    /// Accept a candidate: the given one, or the only one. `force` allows a candidate that verification
    /// rejected.
    Accept { candidate: Option<Rva>, force: bool },
    /// Accept a function that isn't among the item's candidates, which the caller verified with the engine's
    /// checks and policy (`Engine::verify_candidate`): the report is recorded with the mapping like a
    /// candidate's. Refused for one of the candidates (use `Accept`), for another old function, and, unless
    /// `force`, for a function a reviewer rejected for this item; `force` also allows a report verification
    /// rejected, as for `Accept`.
    AcceptVerified {
        report: Box<VerificationReport>,
        force: bool,
    },
    /// None of the item's candidates is the counterpart.
    Reject,
    /// Withdraw the reviewer-accepted mapping that resolved the item: it's revoked and the item reopens.
    Revoke,
}

pub trait MappingStore {
    fn put_mappings(&mut self, mappings: &[Mapping]) -> Result<(), StoreError>;
    fn mappings(&self, from: &BuildId, to: &BuildId) -> Vec<Mapping>;
    /// Add or refresh review items. An item a reviewer resolved by rejecting stays resolved while it offers
    /// nothing new (every candidate already rejected); otherwise it reopens.
    fn enqueue_review(&mut self, items: &[ReviewItem]) -> Result<(), StoreError>;
    fn review_items(&self) -> Vec<ReviewItem>;
    /// Record a reviewer decision on an open item. An accepted candidate becomes a mapping decided by the
    /// reviewer, keeping its verification report.
    fn decide(
        &mut self,
        review_id: &str,
        reviewer: &str,
        choice: Choice,
        note: Option<String>,
        decided_at: u64,
    ) -> Result<ReviewDecision, StoreError>;
    fn decisions(&self) -> Vec<ReviewDecision>;
    /// Human decisions for one build pair, for repair to honor.
    fn prior_decisions(&self, from: &BuildId, to: &BuildId) -> PriorDecisions;
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct StoreData {
    schema_version: u32,
    mappings: Vec<Mapping>,
    review_queue: Vec<ReviewItem>,
    #[serde(default)]
    decisions: Vec<ReviewDecision>,
}

pub struct JsonFileStore {
    path: PathBuf,
    data: StoreData,
}

impl JsonFileStore {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let path = path.into();
        let data = if path.exists() {
            let data: StoreData = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
            if data.schema_version != STORE_SCHEMA_VERSION {
                return Err(StoreError::SchemaVersion(data.schema_version));
            }
            data
        } else {
            StoreData {
                schema_version: STORE_SCHEMA_VERSION,
                ..Default::default()
            }
        };
        Ok(Self { path, data })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn save(&self) -> Result<(), StoreError> {
        if let Some(dir) = self.path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(&self.path, serde_json::to_string_pretty(&self.data)?)?;
        Ok(())
    }

    fn supersede_and_push(&mut self, m: &Mapping) {
        for existing in self.data.mappings.iter_mut().filter(|e| {
            e.status == MappingStatus::Accepted
                && e.from_build == m.from_build
                && e.to_build == m.to_build
                && e.old == m.old
        }) {
            existing.status = MappingStatus::Superseded;
        }
        self.data.mappings.push(m.clone());
    }

    /// Everything a reviewer has rejected for this item.
    fn rejected_for(&self, review_id: &str) -> BTreeSet<Rva> {
        self.data
            .decisions
            .iter()
            .filter(|d| d.review_id == review_id)
            .filter_map(|d| match &d.action {
                DecisionAction::Reject { rejected } => Some(rejected.iter().copied()),
                DecisionAction::Accept { .. } | DecisionAction::Revoke { .. } => None,
            })
            .flatten()
            .collect()
    }

    /// Check a decision against the item and the live mappings. Returns the decision and, for an accept,
    /// the mapping to record. Changes nothing.
    fn plan(
        &self,
        item: &ReviewItem,
        reviewer: &str,
        choice: Choice,
        note: Option<String>,
        decided_at: u64,
    ) -> Result<(ReviewDecision, Option<Mapping>), StoreError> {
        let refuse = |msg: String| Err(StoreError::Refused(msg));
        if reviewer.trim().is_empty() {
            return refuse("a reviewer name is required".into());
        }
        let resolved = item.status == ReviewStatus::Resolved;
        if resolved && choice != Choice::Revoke {
            return refuse(format!(
                "review item {} is already resolved; decisions are append-only (revoke its accepted mapping \
                 to reopen it)",
                item.id
            ));
        }
        let Some(old) = item.old else {
            return refuse(format!(
                "review item {} has no old function (the hook target isn't in the old analysis); \
                 fix the hook manifest instead",
                item.id
            ));
        };
        let list = |rvas: &mut dyn Iterator<Item = Rva>| {
            rvas.map(|r| r.to_string()).collect::<Vec<_>>().join(", ")
        };
        let decision = |action| ReviewDecision {
            review_id: item.id.clone(),
            from_build: item.from_build.clone(),
            to_build: item.to_build.clone(),
            old,
            reviewer: reviewer.to_owned(),
            action,
            note: note.clone(),
            decided_at,
        };

        let (report, force) = match choice {
            Choice::Reject => {
                let rejected = item.candidates.iter().map(|r| r.candidate.new).collect();
                return Ok((decision(DecisionAction::Reject { rejected }), None));
            }
            Choice::Revoke => {
                if !resolved {
                    return refuse(format!(
                        "review item {} is open: there's no decision to revoke",
                        item.id
                    ));
                }
                let last = self
                    .data
                    .decisions
                    .iter()
                    .rev()
                    .find(|d| d.review_id == item.id);
                let Some(DecisionAction::Accept { new }) = last.map(|d| &d.action) else {
                    return refuse(format!(
                        "review item {} was resolved by rejecting; only an accepted mapping can be revoked",
                        item.id
                    ));
                };
                let live = self.data.mappings.iter().any(|m| {
                    m.status == MappingStatus::Accepted
                        && matches!(m.decided_by, Decider::Human { .. })
                        && m.from_build == item.from_build
                        && m.to_build == item.to_build
                        && m.old == old
                        && m.new == *new
                });
                if !live {
                    return refuse(format!(
                        "the mapping {old} -> {new} accepted for {} is no longer live (superseded or revoked)",
                        item.id
                    ));
                }
                return Ok((decision(DecisionAction::Revoke { new: *new }), None));
            }
            Choice::AcceptVerified { report, force } => {
                let new = report.candidate.new;
                if report.candidate.old != old {
                    return refuse(format!(
                        "the verified pair is for {}, but review item {} is about {old}",
                        report.candidate.old, item.id
                    ));
                }
                if item.candidates.iter().any(|r| r.candidate.new == new) {
                    return refuse(format!(
                        "{new} is one of the candidates of {}; accept it with --candidate",
                        item.id
                    ));
                }
                if self.rejected_for(&item.id).contains(&new) && !force {
                    return refuse(format!(
                        "{new} was rejected for {} by a reviewer; pass --force to accept it anyway",
                        item.id
                    ));
                }
                (*report, force)
            }
            Choice::Accept { candidate, force } => {
                let report = match (candidate, item.candidates.as_slice()) {
                    (Some(rva), cands) => match cands.iter().find(|r| r.candidate.new == rva) {
                        Some(r) => r,
                        None => {
                            return refuse(format!(
                                "{rva} is not one of the candidates of {} ({})",
                                item.id,
                                list(&mut cands.iter().map(|r| r.candidate.new))
                            ));
                        }
                    },
                    (None, [only]) => only,
                    (None, []) => {
                        return refuse(format!(
                            "review item {} has no candidates to accept; reject it, or fix the hook \
                             manifest by hand",
                            item.id
                        ));
                    }
                    (None, cands) => {
                        return refuse(format!(
                            "review item {} has {} candidates ({}); pick one with --candidate",
                            item.id,
                            cands.len(),
                            list(&mut cands.iter().map(|r| r.candidate.new))
                        ));
                    }
                };
                (report.clone(), force)
            }
        };

        let new = report.candidate.new;
        if report.verdict == Verdict::Rejected && !force {
            let failing: Vec<String> = report
                .checks
                .iter()
                .filter(|c| c.outcome == CheckOutcome::Fail)
                .map(|c| format!("{}: {}", c.check, c.detail))
                .collect();
            return refuse(format!(
                "verification rejected {new} ({}); pass --force to accept it anyway",
                failing.join("; ")
            ));
        }
        if let Some(other) = self.data.mappings.iter().find(|m| {
            m.status == MappingStatus::Accepted
                && m.from_build == item.from_build
                && m.to_build == item.to_build
                && m.new == new
                && m.old != old
        }) {
            return refuse(format!(
                "{new} is already the accepted counterpart of {}; a function maps one-to-one",
                other.old
            ));
        }
        let mapping = Mapping {
            from_build: item.from_build.clone(),
            to_build: item.to_build.clone(),
            old,
            new,
            decided_by: Decider::Human {
                reviewer: reviewer.to_owned(),
            },
            source: report.candidate.source.clone(),
            score: report.candidate.score,
            evidence: report.candidate.evidence.clone(),
            checks: report.checks.clone(),
            status: MappingStatus::Accepted,
        };
        Ok((decision(DecisionAction::Accept { new }), Some(mapping)))
    }
}

impl MappingStore for JsonFileStore {
    fn put_mappings(&mut self, mappings: &[Mapping]) -> Result<(), StoreError> {
        for m in mappings {
            self.supersede_and_push(m);
        }
        self.save()
    }

    fn mappings(&self, from: &BuildId, to: &BuildId) -> Vec<Mapping> {
        self.data
            .mappings
            .iter()
            .filter(|m| &m.from_build == from && &m.to_build == to)
            .cloned()
            .collect()
    }

    fn enqueue_review(&mut self, items: &[ReviewItem]) -> Result<(), StoreError> {
        for item in items {
            let settled = self.data.review_queue.iter().any(|e| {
                e.id == item.id && e.status == ReviewStatus::Resolved && {
                    let rejected = self.rejected_for(&item.id);
                    let last_was_reject = self
                        .data
                        .decisions
                        .iter()
                        .rev()
                        .find(|d| d.review_id == item.id)
                        .is_some_and(|d| matches!(d.action, DecisionAction::Reject { .. }));
                    last_was_reject
                        && item
                            .candidates
                            .iter()
                            .all(|c| rejected.contains(&c.candidate.new))
                }
            });
            if settled {
                continue;
            }
            self.data
                .review_queue
                .retain(|existing| existing.id != item.id);
            let mut fresh = item.clone();
            fresh.status = ReviewStatus::Open;
            self.data.review_queue.push(fresh);
        }
        self.save()
    }

    fn review_items(&self) -> Vec<ReviewItem> {
        self.data.review_queue.clone()
    }

    fn decide(
        &mut self,
        review_id: &str,
        reviewer: &str,
        choice: Choice,
        note: Option<String>,
        decided_at: u64,
    ) -> Result<ReviewDecision, StoreError> {
        let Some(item) = self.data.review_queue.iter().find(|i| i.id == review_id) else {
            return Err(StoreError::Refused(format!(
                "no review item with id {review_id}"
            )));
        };
        let (decision, mapping) = self.plan(item, reviewer, choice, note, decided_at)?;
        if let Some(m) = &mapping {
            self.supersede_and_push(m);
        }
        if let DecisionAction::Reject { rejected } = &decision.action {
            // A reviewer saying "not this one" also revokes any live mapping onto it.
            for m in self.data.mappings.iter_mut().filter(|m| {
                m.status == MappingStatus::Accepted
                    && m.from_build == decision.from_build
                    && m.to_build == decision.to_build
                    && m.old == decision.old
                    && rejected.contains(&m.new)
            }) {
                m.status = MappingStatus::Revoked;
            }
        }
        let reopen = if let DecisionAction::Revoke { new } = &decision.action {
            for m in self.data.mappings.iter_mut().filter(|m| {
                m.status == MappingStatus::Accepted
                    && matches!(m.decided_by, Decider::Human { .. })
                    && m.from_build == decision.from_build
                    && m.to_build == decision.to_build
                    && m.old == decision.old
                    && m.new == *new
            }) {
                m.status = MappingStatus::Revoked;
            }
            true
        } else {
            false
        };
        for i in self
            .data
            .review_queue
            .iter_mut()
            .filter(|i| i.id == review_id)
        {
            i.status = if reopen {
                ReviewStatus::Open
            } else {
                ReviewStatus::Resolved
            };
        }
        self.data.decisions.push(decision.clone());
        self.save()?;
        Ok(decision)
    }

    fn decisions(&self) -> Vec<ReviewDecision> {
        self.data.decisions.clone()
    }

    fn prior_decisions(&self, from: &BuildId, to: &BuildId) -> PriorDecisions {
        PriorDecisions {
            accepted: self
                .data
                .mappings
                .iter()
                .filter(|m| {
                    &m.from_build == from
                        && &m.to_build == to
                        && m.status == MappingStatus::Accepted
                        && matches!(m.decided_by, Decider::Human { .. })
                })
                .cloned()
                .collect(),
            rejected: self
                .data
                .decisions
                .iter()
                .filter(|d| &d.from_build == from && &d.to_build == to)
                .filter_map(|d| match &d.action {
                    DecisionAction::Reject { rejected } => {
                        Some(rejected.iter().map(move |&n| (d.old, n)))
                    }
                    DecisionAction::Accept { .. } | DecisionAction::Revoke { .. } => None,
                })
                .flatten()
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use permanent_beta_model::{
        Candidate, CandidateSource, CheckResult, ReviewReason, VerificationReport,
    };
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A fresh store file per test (tests run in parallel).
    fn temp_store() -> (JsonFileStore, PathBuf) {
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "permanent-beta-store-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("store.json");
        (JsonFileStore::open(&path).unwrap(), dir)
    }

    fn mapping(old: u64, new: u64) -> Mapping {
        Mapping {
            from_build: BuildId("a".into()),
            to_build: BuildId("b".into()),
            old: Rva(old),
            new: Rva(new),
            decided_by: Decider::Engine,
            source: CandidateSource::Deterministic {
                matcher: "t".into(),
            },
            score: 1.0,
            evidence: vec![],
            checks: vec![],
            status: MappingStatus::Accepted,
        }
    }

    fn report(new: u64, verdict: Verdict) -> VerificationReport {
        VerificationReport {
            candidate: Candidate {
                old: Rva(0x10),
                new: Rva(new),
                source: CandidateSource::Deterministic {
                    matcher: "similarity".into(),
                },
                score: 0.8,
                evidence: vec![],
            },
            checks: vec![CheckResult::new(
                "callers",
                if verdict == Verdict::Rejected {
                    CheckOutcome::Fail
                } else {
                    CheckOutcome::Pass
                },
                "1/1",
            )],
            verdict,
        }
    }

    fn item(candidates: Vec<VerificationReport>) -> ReviewItem {
        ReviewItem {
            id: "H:a:b".into(),
            hook: Some("H".into()),
            from_build: BuildId("a".into()),
            to_build: BuildId("b".into()),
            old: Some(Rva(0x10)),
            reason: ReviewReason::Ambiguous,
            detail: String::new(),
            candidates,
            proposals: vec![],
            struct_proposals: Vec::new(),
            status: ReviewStatus::Open,
        }
    }

    fn accept(candidate: Option<u64>) -> Choice {
        Choice::Accept {
            candidate: candidate.map(Rva),
            force: false,
        }
    }

    fn refused(r: Result<ReviewDecision, StoreError>) -> String {
        match r {
            Err(StoreError::Refused(msg)) => msg,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn rewriting_a_mapping_supersedes_instead_of_editing() {
        let (mut store, dir) = temp_store();
        store.put_mappings(&[mapping(0x10, 0x20)]).unwrap();
        store.put_mappings(&[mapping(0x10, 0x30)]).unwrap();

        let reopened = JsonFileStore::open(store.path()).unwrap();
        let all = reopened.mappings(&BuildId("a".into()), &BuildId("b".into()));
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].status, MappingStatus::Superseded);
        assert_eq!(all[1].status, MappingStatus::Accepted);
        assert_eq!(all[1].new, Rva(0x30));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn accepting_the_only_candidate_records_a_human_mapping() {
        let (mut store, dir) = temp_store();
        store
            .enqueue_review(&[item(vec![report(0x20, Verdict::NeedsReview)])])
            .unwrap();
        let d = store
            .decide("H:a:b", "ryan", accept(None), Some("checked".into()), 7)
            .unwrap();
        assert_eq!(d.action, DecisionAction::Accept { new: Rva(0x20) });

        let reopened = JsonFileStore::open(store.path()).unwrap();
        let prior = reopened.prior_decisions(&BuildId("a".into()), &BuildId("b".into()));
        assert_eq!(prior.accepted.len(), 1);
        let m = &prior.accepted[0];
        assert_eq!((m.old, m.new), (Rva(0x10), Rva(0x20)));
        assert_eq!(
            m.decided_by,
            Decider::Human {
                reviewer: "ryan".into()
            }
        );
        assert_eq!(
            m.checks.len(),
            1,
            "keeps the verification report it was decided on"
        );
        assert_eq!(reopened.review_items()[0].status, ReviewStatus::Resolved);
        assert_eq!(reopened.decisions(), vec![d]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_function_that_is_not_a_candidate_cannot_be_accepted() {
        let (mut store, dir) = temp_store();
        store
            .enqueue_review(&[item(vec![report(0x20, Verdict::NeedsReview)])])
            .unwrap();
        let msg = refused(store.decide("H:a:b", "ryan", accept(Some(0x99)), None, 7));
        assert!(msg.contains("not one of the candidates"), "{msg}");
        assert!(store.decisions().is_empty());
        assert_eq!(store.review_items()[0].status, ReviewStatus::Open);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn several_candidates_need_an_explicit_pick() {
        let (mut store, dir) = temp_store();
        store
            .enqueue_review(&[item(vec![
                report(0x20, Verdict::NeedsReview),
                report(0x30, Verdict::NeedsReview),
            ])])
            .unwrap();
        let msg = refused(store.decide("H:a:b", "ryan", accept(None), None, 7));
        assert!(msg.contains("--candidate"), "{msg}");
        let d = store
            .decide("H:a:b", "ryan", accept(Some(0x30)), None, 7)
            .unwrap();
        assert_eq!(d.action, DecisionAction::Accept { new: Rva(0x30) });
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_candidate_verification_rejected_needs_force() {
        let (mut store, dir) = temp_store();
        store
            .enqueue_review(&[item(vec![report(0x20, Verdict::Rejected)])])
            .unwrap();
        let msg = refused(store.decide("H:a:b", "ryan", accept(None), None, 7));
        assert!(msg.contains("--force") && msg.contains("callers"), "{msg}");
        let forced = Choice::Accept {
            candidate: None,
            force: true,
        };
        assert!(store.decide("H:a:b", "ryan", forced, None, 7).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn accepting_a_function_already_claimed_by_another_mapping_is_refused() {
        let (mut store, dir) = temp_store();
        store.put_mappings(&[mapping(0x40, 0x20)]).unwrap();
        store
            .enqueue_review(&[item(vec![report(0x20, Verdict::NeedsReview)])])
            .unwrap();
        let msg = refused(store.decide("H:a:b", "ryan", accept(None), None, 7));
        assert!(msg.contains("one-to-one"), "{msg}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_resolved_item_cannot_be_decided_again() {
        let (mut store, dir) = temp_store();
        store
            .enqueue_review(&[item(vec![report(0x20, Verdict::NeedsReview)])])
            .unwrap();
        store
            .decide("H:a:b", "ryan", accept(None), None, 7)
            .unwrap();
        let msg = refused(store.decide("H:a:b", "ryan", Choice::Reject, None, 8));
        assert!(msg.contains("already resolved"), "{msg}");
        assert!(
            refused(store.decide("nope", "ryan", Choice::Reject, None, 8))
                .contains("no review item")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_decision_needs_a_reviewer() {
        let (mut store, dir) = temp_store();
        store
            .enqueue_review(&[item(vec![report(0x20, Verdict::NeedsReview)])])
            .unwrap();
        assert!(refused(store.decide("H:a:b", " ", accept(None), None, 7)).contains("reviewer"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_rejected_item_stays_closed_until_something_new_shows_up() {
        let (mut store, dir) = temp_store();
        let first = item(vec![report(0x20, Verdict::NeedsReview)]);
        store.enqueue_review(std::slice::from_ref(&first)).unwrap();
        store
            .decide("H:a:b", "ryan", Choice::Reject, None, 7)
            .unwrap();
        let prior = store.prior_decisions(&BuildId("a".into()), &BuildId("b".into()));
        assert_eq!(prior.rejected, vec![(Rva(0x10), Rva(0x20))]);

        // The next repair run reports the same hook again: nothing new, so it stays resolved.
        store.enqueue_review(&[first]).unwrap();
        assert_eq!(store.review_items()[0].status, ReviewStatus::Resolved);
        store.enqueue_review(&[item(vec![])]).unwrap();
        assert_eq!(store.review_items()[0].status, ReviewStatus::Resolved);

        // A new candidate appears: the reviewer has something to look at again.
        store
            .enqueue_review(&[item(vec![report(0x30, Verdict::NeedsReview)])])
            .unwrap();
        assert_eq!(store.review_items()[0].status, ReviewStatus::Open);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejecting_revokes_a_live_mapping_onto_the_rejected_function() {
        let (mut store, dir) = temp_store();
        store.put_mappings(&[mapping(0x10, 0x20)]).unwrap();
        store
            .enqueue_review(&[item(vec![report(0x20, Verdict::NeedsReview)])])
            .unwrap();
        store
            .decide("H:a:b", "ryan", Choice::Reject, None, 7)
            .unwrap();
        let all = store.mappings(&BuildId("a".into()), &BuildId("b".into()));
        assert_eq!(all[0].status, MappingStatus::Revoked);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn revoking_an_accepted_mapping_reopens_the_item() {
        let (mut store, dir) = temp_store();
        store
            .enqueue_review(&[item(vec![report(0x20, Verdict::NeedsReview)])])
            .unwrap();
        // Negative: nothing to revoke on an open item.
        assert!(
            store
                .decide("H:a:b", "ryan", Choice::Revoke, None, 6)
                .is_err()
        );
        store
            .decide("H:a:b", "ryan", accept(None), None, 7)
            .unwrap();
        let d = store
            .decide("H:a:b", "ryan", Choice::Revoke, Some("wrong one".into()), 8)
            .unwrap();
        assert_eq!(d.action, DecisionAction::Revoke { new: Rva(0x20) });

        let reopened = JsonFileStore::open(store.path()).unwrap();
        let (a, b) = (BuildId("a".into()), BuildId("b".into()));
        assert_eq!(reopened.mappings(&a, &b)[0].status, MappingStatus::Revoked);
        let prior = reopened.prior_decisions(&a, &b);
        assert!(prior.accepted.is_empty(), "repair no longer uses it");
        // Negative: revoking isn't rejecting; the candidate can be proposed and accepted again.
        assert!(prior.rejected.is_empty());
        assert_eq!(reopened.review_items()[0].status, ReviewStatus::Open);
        let mut store = reopened;
        store
            .decide("H:a:b", "ryan", accept(None), None, 9)
            .unwrap();
        // Negative: the same mapping can't be revoked twice.
        store
            .decide("H:a:b", "ryan", Choice::Revoke, None, 10)
            .unwrap();
        assert!(
            store
                .decide("H:a:b", "ryan", Choice::Revoke, None, 11)
                .is_err()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_rejected_item_or_a_superseded_mapping_cant_be_revoked() {
        let (mut store, dir) = temp_store();
        store
            .enqueue_review(&[item(vec![report(0x20, Verdict::NeedsReview)])])
            .unwrap();
        store
            .decide("H:a:b", "ryan", Choice::Reject, None, 7)
            .unwrap();
        let why = store
            .decide("H:a:b", "ryan", Choice::Revoke, None, 8)
            .unwrap_err();
        assert!(why.to_string().contains("rejecting"), "{why}");

        let (mut store, dir2) = temp_store();
        store
            .enqueue_review(&[item(vec![report(0x20, Verdict::NeedsReview)])])
            .unwrap();
        store
            .decide("H:a:b", "ryan", accept(None), None, 7)
            .unwrap();
        // A later engine mapping for the same old function supersedes the reviewer's.
        store.put_mappings(&[mapping(0x10, 0x30)]).unwrap();
        let why = store
            .decide("H:a:b", "ryan", Choice::Revoke, None, 8)
            .unwrap_err();
        assert!(why.to_string().contains("no longer live"), "{why}");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&dir2);
    }

    fn verified(old: u64, new: u64, verdict: Verdict) -> Choice {
        let mut r = report(new, verdict);
        r.candidate.old = Rva(old);
        Choice::AcceptVerified {
            report: Box::new(r),
            force: false,
        }
    }

    #[test]
    fn accepting_a_verified_function_outside_the_candidates() {
        let (mut store, dir) = temp_store();
        store
            .enqueue_review(&[item(vec![report(0x20, Verdict::NeedsReview)])])
            .unwrap();
        // Negative: a candidate goes through Accept; a pair for another old function, or one verification
        // rejected, is refused.
        assert!(
            store
                .decide(
                    "H:a:b",
                    "ryan",
                    verified(0x10, 0x20, Verdict::NeedsReview),
                    None,
                    1
                )
                .is_err()
        );
        assert!(
            store
                .decide(
                    "H:a:b",
                    "ryan",
                    verified(0x11, 0x40, Verdict::NeedsReview),
                    None,
                    2
                )
                .is_err()
        );
        let why = store
            .decide(
                "H:a:b",
                "ryan",
                verified(0x10, 0x40, Verdict::Rejected),
                None,
                3,
            )
            .unwrap_err();
        assert!(why.to_string().contains("--force"), "{why}");
        let d = store
            .decide(
                "H:a:b",
                "ryan",
                verified(0x10, 0x40, Verdict::NeedsReview),
                None,
                4,
            )
            .unwrap();
        assert_eq!(d.action, DecisionAction::Accept { new: Rva(0x40) });
        let prior = store.prior_decisions(&BuildId("a".into()), &BuildId("b".into()));
        assert_eq!(
            (prior.accepted[0].old, prior.accepted[0].new),
            (Rva(0x10), Rva(0x40))
        );
        assert_eq!(
            prior.accepted[0].checks.len(),
            1,
            "keeps its verification report"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_function_rejected_for_the_item_needs_force() {
        let (mut store, dir) = temp_store();
        store
            .enqueue_review(&[item(vec![report(0x20, Verdict::NeedsReview)])])
            .unwrap();
        store
            .decide("H:a:b", "ryan", Choice::Reject, None, 1)
            .unwrap();
        // The rerun offers 0x40, which the reviewer then rejects too.
        store
            .enqueue_review(&[item(vec![report(0x40, Verdict::NeedsReview)])])
            .unwrap();
        store
            .decide("H:a:b", "ryan", Choice::Reject, None, 2)
            .unwrap();
        store
            .enqueue_review(&[item(vec![report(0x50, Verdict::NeedsReview)])])
            .unwrap();
        // Negative: 0x40 was rejected for this item.
        let why = store
            .decide(
                "H:a:b",
                "ryan",
                verified(0x10, 0x40, Verdict::NeedsReview),
                None,
                3,
            )
            .unwrap_err();
        assert!(why.to_string().contains("rejected"), "{why}");
        let mut forced = verified(0x10, 0x40, Verdict::NeedsReview);
        if let Choice::AcceptVerified { force, .. } = &mut forced {
            *force = true;
        }
        store.decide("H:a:b", "ryan", forced, None, 4).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
