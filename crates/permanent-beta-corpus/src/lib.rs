//! Test-corpus tooling (design §10).
//!
//! - [`map`]: parse MSVC linker `/MAP` files.
//! - [`truth`]: join two map files by symbol name into the true old → new function mapping (the answer key).
//! - [`score`]: classify match results against the answer key; the safety metric is wrong matches.
//! - [`expected`]: per-fixture gate (zero wrong, no regression in correct matches) and per-scenario targets.
//! - [`fixture`]: run the real analyzer and engine on a built fixture and score it.
//! - [`ai_score`]: score the AI proposer's answers against the answer key, separately from the passes.
//! - [`hooks`]: the M4 hook-repair loop's answer key: v1 manifest from symbols, repaired manifests vs maps.
//!
//! The answer key is only ever used to *score* matching. Nothing in the pipeline may depend on this crate.

pub mod ai_score;
pub mod expected;
pub mod fixture;
pub mod hooks;
pub mod map;
pub mod score;
pub mod truth;
