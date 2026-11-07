//! Hook manifest (design §7.1): a library-neutral description of each hook and where its target lives.

use crate::ids::{BuildId, Rva};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HookManifest {
    #[serde(rename = "hook", default)]
    pub hooks: Vec<HookSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookSpec {
    pub name: String,
    /// Symbol of the detour function in the hook DLL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detour: Option<String>,
    #[serde(default)]
    pub criticality: Criticality,
    /// C prototype of the target, e.g. `int __fastcall F(Doc* doc)`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prototype: Option<String>,
    pub target: TargetLocator,
    /// A trial binding (`pbeta repair --trial-out`): the locator points at an unverified review candidate so a
    /// test run can collect behavioral evidence for it. Never a repair result: `pbeta repair` refuses a manifest
    /// with trial hooks, and nothing may ship one.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub trial: bool,
}

/// Where the hook target is, valid only for `build`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetLocator {
    pub build: BuildId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rva: Option<Rva>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    /// AOB pattern, space-separated hex bytes with `??` wildcards.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
}

/// Drives the acceptance policy (design §6.3).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Criticality {
    Low,
    #[default]
    Normal,
    High,
}

/// A proposed prototype for a hook target whose parameters changed (design §7.2, prototype adaptation). Text for
/// a reviewer to read and adapt: nothing applies it, and the detour body is never rewritten.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrototypeProposal {
    /// The new-build candidate this proposal is for.
    pub candidate: Rva,
    /// The proposed C prototype of the new function.
    pub prototype: String,
    /// What the proposal is based on, in plain words (e.g. which registers the new code reads).
    pub basis: String,
    /// A C++ shim that lets the existing detour run unchanged on the new function: a new detour with the new
    /// prototype that stashes the added arguments and calls the old detour, whose call to the original
    /// function forwards them.
    pub shim: String,
}
