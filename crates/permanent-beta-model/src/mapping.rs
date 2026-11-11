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
    /// One of [`evidence_kind`] for deterministic matchers.
    pub kind: String,
    pub detail: String,
}

/// Evidence kinds written by matchers and read by verification to decide which checks are independent of the
/// evidence (design §6.1). Shared here so `match` and `verify` agree without depending on each other.
pub mod evidence_kind {
    /// Same unique export or PDB name.
    pub const NAME: &str = "name";
    /// Same unique normalized instruction hash.
    pub const NORMALIZED_HASH: &str = "normalized_hash";
    /// Same unique mnemonic sequence (operands may differ).
    pub const MNEMONIC_HASH: &str = "mnemonic_hash";
    /// Same unique set of referenced strings.
    pub const STRINGS: &str = "strings";
    /// Same position in the call sequence of an already-matched caller.
    pub const CALL_SEQUENCE: &str = "call_sequence";
    /// Calls the same already-matched functions, in the same order (paired with identical normalized code).
    pub const CALLEES: &str = "callees";
    /// Same slot in corresponding code-pointer tables (vtables), paired with identical normalized code. Implies no
    /// check: none measures table position.
    pub const TABLE_SLOT: &str = "table_slot";
    /// Similar code, shape and neighbourhood, clearly closer than any alternative (an edited function).
    pub const SIMILARITY: &str = "similarity";
    /// One of several equally plausible competitors (review evidence only, never accepted).
    pub const AMBIGUOUS: &str = "ambiguous";
    /// An AI proposer's rationale (design §8). Set by the server receiving the proposal, never by the model, so
    /// a model can't label its guess as a deterministic kind. Implies no check: every check counts.
    pub const AI: &str = "ai";
    /// A reviewer named the function by hand (`pbeta review accept --function`). Implies no check: every check
    /// counts.
    pub const REVIEWER: &str = "reviewer";
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
    /// Whether a pass counted towards the acceptance policy. False when the check only repeats the evidence
    /// that produced the candidate, or is a sanity check that can fail a candidate but never support it.
    #[serde(default = "default_true")]
    pub counted: bool,
}

fn default_true() -> bool {
    true
}

impl CheckResult {
    pub fn new(check: &str, outcome: CheckOutcome, detail: impl Into<String>) -> Self {
        Self {
            check: check.to_owned(),
            outcome,
            detail: detail.into(),
            counted: true,
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
