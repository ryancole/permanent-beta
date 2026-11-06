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
