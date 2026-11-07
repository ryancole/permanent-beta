//! Scenario call traces (design §7.3, option 3): what a logging hook DLL saw while a build ran a fixed scenario.
//!
//! One JSON object per line (`{"event": "call", ...}`), written by the Detours harness in `corpus/hooks/hookdll`.
//! Comparing two builds' traces hook by hook shows whether a repaired hook still sees the same calls.

use crate::ids::{BuildId, Rva};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum TraceEvent {
    /// The harness loaded into the build with this id (SHA-256 of its .exe).
    Start { build: BuildId },
    /// A detour was placed at `rva`; `status` is `ok` or the Detours error.
    Attach {
        hook: String,
        rva: Rva,
        status: String,
    },
    /// The hook was deliberately not attached, e.g. `build_mismatch`: its locator is bound to another build.
    Skip {
        hook: String,
        reason: String,
        #[serde(default)]
        build: Option<BuildId>,
    },
    /// One call through the detour: arguments and result, by value, as the detour logged them.
    Call {
        hook: String,
        rva: Rva,
        args: Vec<String>,
        ret: String,
    },
    /// The harness couldn't do its job (e.g. no manifest).
    Error { detail: String },
    /// The process exited normally. Missing after a crash.
    End,
}

/// A whole trace, in order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Trace {
    pub events: Vec<TraceEvent>,
}

impl Trace {
    pub fn build(&self) -> Option<&BuildId> {
        self.events.iter().find_map(|e| match e {
            TraceEvent::Start { build } => Some(build),
            _ => None,
        })
    }

    /// The process reached a normal exit (an `end` event).
    pub fn completed(&self) -> bool {
        self.events.iter().any(|e| matches!(e, TraceEvent::End))
    }
}
