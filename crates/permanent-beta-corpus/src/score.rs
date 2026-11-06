//! Score match results against an answer key (design §10).
//!
//! Every function in the answer key that exists in the old build gets one [`Outcome`]. The safety metric is
//! [`Totals::wrong`]: a candidate pointing at the wrong function, whatever its verdict, including candidates
//! for deleted functions and candidates that map an out-of-scope function onto a fixture function.

use crate::truth::GroundTruth;
use permanent_beta_model::{Ambiguity, Rva, Verdict, VerificationReport};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Correct candidate, accepted by verification.
    Accepted,
    /// Correct candidate, but verification sent it to review (or rejected it).
    Review,
    /// No candidate; the function is in an ambiguity group.
    Ambiguous,
    /// No candidate and no ambiguity.
    Unmatched,
    /// A candidate that points at the wrong function.
    Wrong,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionScore {
    pub names: Vec<String>,
    /// `None` for an out-of-scope old function that was matched onto a fixture function.
    pub old: Option<Rva>,
    /// Acceptable new addresses (more than one when folding differs between builds; empty if deleted).
    pub truth: Vec<Rva>,
    pub outcome: Outcome,
    /// The candidate's new address, if any.
    pub got: Option<Rva>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Totals {
    pub accepted: u32,
    pub review: u32,
    pub ambiguous: u32,
    pub unmatched: u32,
    pub wrong: u32,
}

impl Totals {
    /// Correct candidates, whatever the verdict.
    pub fn correct(&self) -> u32 {
        self.accepted + self.review
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scorecard {
    pub functions: Vec<FunctionScore>,
    pub totals: Totals,
}

impl Scorecard {
    pub fn outcome_of(&self, name: &str) -> Option<&FunctionScore> {
        self.functions
            .iter()
            .find(|f| f.names.iter().any(|n| n == name))
    }
}

pub fn score(
    truth: &GroundTruth,
    reports: &[VerificationReport],
    ambiguities: &[Ambiguity],
) -> Scorecard {
    // Old address → (names, acceptable new addresses). Several entries can share an old address when the
    // new build splits a folded function back apart.
    let mut by_old: BTreeMap<Rva, (BTreeSet<String>, BTreeSet<Rva>)> = BTreeMap::new();
    for e in &truth.functions {
        if let Some(old) = e.old {
            let slot = by_old.entry(old).or_default();
            slot.0.extend(e.names.iter().cloned());
            slot.1.extend(e.new);
        }
    }
    let in_scope_new: BTreeMap<Rva, Vec<String>> = truth
        .functions
        .iter()
        .filter_map(|e| Some((e.new?, e.names.clone())))
        .collect();

    let mut functions = Vec::new();
    for (&old, (names, acceptable)) in &by_old {
        let report = reports.iter().find(|r| r.candidate.old == old);
        let (outcome, got) = match report {
            Some(r) if acceptable.contains(&r.candidate.new) => {
                let o = if r.verdict == Verdict::Accepted {
                    Outcome::Accepted
                } else {
                    Outcome::Review
                };
                (o, Some(r.candidate.new))
            }
            Some(r) => (Outcome::Wrong, Some(r.candidate.new)),
            None if ambiguities.iter().any(|a| a.old.contains(&old)) => (Outcome::Ambiguous, None),
            None => (Outcome::Unmatched, None),
        };
        functions.push(FunctionScore {
            names: names.iter().cloned().collect(),
            old: Some(old),
            truth: acceptable.iter().copied().collect(),
            outcome,
            got,
        });
    }

    // A function outside the answer key's scope (e.g. CRT code) matched onto a fixture function is also wrong.
    for r in reports {
        if !by_old.contains_key(&r.candidate.old) {
            if let Some(names) = in_scope_new.get(&r.candidate.new) {
                functions.push(FunctionScore {
                    names: names.clone(),
                    old: None,
                    truth: vec![],
                    outcome: Outcome::Wrong,
                    got: Some(r.candidate.new),
                });
            }
        }
    }

    let mut totals = Totals::default();
    for f in &functions {
        match f.outcome {
            Outcome::Accepted => totals.accepted += 1,
            Outcome::Review => totals.review += 1,
            Outcome::Ambiguous => totals.ambiguous += 1,
            Outcome::Unmatched => totals.unmatched += 1,
            Outcome::Wrong => totals.wrong += 1,
        }
    }
    Scorecard { functions, totals }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::truth::{TRUTH_SCHEMA_VERSION, TruthEntry};
    use permanent_beta_model::{Candidate, CandidateSource};

    fn entry(name: &str, old: Option<u64>, new: Option<u64>) -> TruthEntry {
        TruthEntry {
            names: vec![name.into()],
            old: old.map(Rva),
            new: new.map(Rva),
            is_static: false,
        }
    }

    fn truth() -> GroundTruth {
        GroundTruth {
            schema_version: TRUTH_SCHEMA_VERSION,
            object: "t.obj".into(),
            functions: vec![
                entry("same", Some(0x10), Some(0x110)),
                entry("deleted", Some(0x20), None),
                entry("added", None, Some(0x130)),
                entry("dup", Some(0x40), Some(0x140)),
            ],
        }
    }

    fn report(old: u64, new: u64, verdict: Verdict) -> VerificationReport {
        VerificationReport {
            candidate: Candidate {
                old: Rva(old),
                new: Rva(new),
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
    fn classifies_correct_ambiguous_and_unmatched() {
        let amb = Ambiguity {
            matcher: "t".into(),
            old: vec![Rva(0x40)],
            new: vec![Rva(0x140), Rva(0x150)],
            detail: String::new(),
        };
        let card = score(
            &truth(),
            &[report(0x10, 0x110, Verdict::NeedsReview)],
            &[amb],
        );
        assert_eq!(card.outcome_of("same").unwrap().outcome, Outcome::Review);
        assert_eq!(card.outcome_of("dup").unwrap().outcome, Outcome::Ambiguous);
        assert_eq!(
            card.outcome_of("deleted").unwrap().outcome,
            Outcome::Unmatched
        );
        assert_eq!(card.totals.wrong, 0);
        assert_eq!(card.totals.correct(), 1);
    }

    #[test]
    fn wrong_target_is_wrong_even_if_only_sent_to_review() {
        let card = score(&truth(), &[report(0x10, 0x140, Verdict::NeedsReview)], &[]);
        assert_eq!(card.outcome_of("same").unwrap().outcome, Outcome::Wrong);
        assert_eq!(card.totals.wrong, 1);
    }

    #[test]
    fn matching_a_deleted_function_is_wrong() {
        let card = score(&truth(), &[report(0x20, 0x130, Verdict::Accepted)], &[]);
        assert_eq!(card.outcome_of("deleted").unwrap().outcome, Outcome::Wrong);
    }

    #[test]
    fn out_of_scope_function_matched_onto_a_fixture_function_is_wrong() {
        let card = score(&truth(), &[report(0x9999, 0x130, Verdict::Accepted)], &[]);
        assert_eq!(card.totals.wrong, 1);
        assert_eq!(card.outcome_of("added").unwrap().outcome, Outcome::Wrong);
    }

    #[test]
    fn out_of_scope_matches_onto_out_of_scope_functions_are_ignored() {
        let card = score(&truth(), &[report(0x9999, 0x8888, Verdict::Accepted)], &[]);
        assert_eq!(card.totals.wrong, 0);
    }
}
