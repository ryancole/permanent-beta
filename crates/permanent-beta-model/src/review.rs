//! Review queue items (design §9, review queue).

use crate::ids::{BuildId, Rva};
use crate::mapping::VerificationReport;
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
}
