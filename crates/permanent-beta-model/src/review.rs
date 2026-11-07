//! Review queue items and the decisions reviewers make on them (design §9.1: ReviewItem, ReviewDecision).

use crate::ids::{BuildId, Rva};
use crate::mapping::{Mapping, VerificationReport};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewReason {
    /// No candidate at all (or the hook target isn't in the old analysis).
    Unmatched,
    /// Several plausible candidates; the engine refused to pick.
    Ambiguous,
    /// A candidate failed one or more checks.
    VerificationFailed,
    /// Checks passed but policy needs more (e.g. behavioral tests for high-criticality hooks).
    InsufficientEvidence,
    /// Matched, but the function signature changed; the hook may need adapting.
    SignatureChanged,
    /// Matched and verified, but a Detours-style entry patch can't be applied safely to the new function.
    NotHookable,
    /// Proposed by an AI proposer and awaiting a human.
    AiProposal,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewStatus {
    #[default]
    Open,
    /// A reviewer decided it (see the store's decision log).
    Resolved,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReviewItem {
    /// Stable id so re-running the same repair doesn't duplicate items.
    pub id: String,
    pub hook: Option<String>,
    pub from_build: BuildId,
    pub to_build: BuildId,
    pub old: Option<Rva>,
    pub reason: ReviewReason,
    pub detail: String,
    pub candidates: Vec<VerificationReport>,
    #[serde(default)]
    pub status: ReviewStatus,
}

/// What a reviewer decided about one review item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum DecisionAction {
    /// This candidate is the old function's counterpart.
    Accept { new: Rva },
    /// None of these new-build functions is the counterpart (empty: confirmed there's no candidate to pick).
    Reject { rejected: Vec<Rva> },
}

/// One reviewer decision. Append-only, like mappings: a correction is a new decision, never an edit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewDecision {
    pub review_id: String,
    pub from_build: BuildId,
    pub to_build: BuildId,
    pub old: Rva,
    pub reviewer: String,
    #[serde(flatten)]
    pub action: DecisionAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Unix time, seconds.
    pub decided_at: u64,
}

/// What earlier human decisions say about one build pair, for repair to honor.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PriorDecisions {
    /// Live mappings a reviewer accepted.
    pub accepted: Vec<Mapping>,
    /// (old, new) pairs a reviewer said are not counterparts.
    pub rejected: Vec<(Rva, Rva)>,
}
