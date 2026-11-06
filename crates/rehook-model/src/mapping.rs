//! Candidates, evidence, verification results and accepted mappings (design §5, §6, §9).

use crate::ids::{BuildId, Rva};
use serde::{Deserialize, Serialize};

/// Who proposed a candidate. Every source goes through the same verification.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CandidateSource {
    Deterministic { matcher: String },
    Ai { model: String },
    Human { reviewer: String },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    pub kind: String,
    pub detail: String,
}

/// A proposed old→new function correspondence. Not accepted until verified.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Candidate {
    pub old: Rva,
    pub new: Rva,
    pub source: CandidateSource,
    /// In [0, 1]. Not a probability until calibrated against the corpus (design §5.3).
    pub score: f32,
    pub evidence: Vec<Evidence>,
}

/// A key shared by several unmatched functions, so the pass refused to pick (design §5.2).
/// Not a candidate: it exists so review can show the competing functions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ambiguity {
    pub matcher: String,
    pub old: Vec<Rva>,
    pub new: Vec<Rva>,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckOutcome {
    Pass,
    Fail,
    Inconclusive,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CheckResult {
    pub check: String,
    pub outcome: CheckOutcome,
    pub detail: String,
}

impl CheckResult {
    pub fn new(check: &str, outcome: CheckOutcome, detail: impl Into<String>) -> Self {
        Self {
            check: check.to_owned(),
            outcome,
            detail: detail.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Accepted,
    NeedsReview,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerificationReport {
    pub candidate: Candidate,
    pub checks: Vec<CheckResult>,
    pub verdict: Verdict,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Decider {
    Engine,
    Human { reviewer: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MappingStatus {
    Accepted,
    Superseded,
    Revoked,
}

/// An accepted mapping. Append-only: corrections supersede, they never edit (design §9.1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Mapping {
    pub from_build: BuildId,
    pub to_build: BuildId,
    pub old: Rva,
    pub new: Rva,
    pub decided_by: Decider,
    pub source: CandidateSource,
    pub score: f32,
    pub evidence: Vec<Evidence>,
    pub checks: Vec<CheckResult>,
    pub status: MappingStatus,
}
