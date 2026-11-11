# Guidance for AI agents working in this repo

This codebase is written by AI agents and reviewed by the owner. These rules exist to keep it reviewable and to
stop plausible-but-wrong matching logic from merging.

## Architecture rules

- Read `docs/design.md` §3 before changing crate structure.
- Allowed internal dependencies (enforced by Cargo.toml review):
  - `permanent-beta-model`: none
  - `permanent-beta-analysis`, `permanent-beta-match`, `permanent-beta-verify`, `permanent-beta-repair`, `permanent-beta-store`: `permanent-beta-model` only
  - `permanent-beta-engine`: model, match, verify, repair, replay
  - `permanent-beta-replay`: model only; only engine and CLI may depend on it. It replays recorded test cases by
    emulation and reports pass/fail/inconclusive; verification decides what that's worth. Its `emulator` feature
    links icicle (MIT or Apache-2.0) and embeds Ghidra's x86 SLEIGH specification (Apache-2.0, `sleigh/`): keep it
    optional and off by default, and add no GPL dependency.
  - `permanent-beta-ai`: model only. It proposes candidates; callers verify them and queue them for review.
  - `permanent-beta-cli`: engine, analysis, store, model, ai, replay. `pbeta propose` queues AI proposals for review and
    never writes a mapping.
  - `permanent-beta-mcp`: engine, store, model. It may only read the store and add review items to it
    (`tools::ReviewQueue`); no tool may decide a review item or write a mapping.
  - `permanent-beta-corpus` (test tooling): model now; may add engine, analysis and ai for scoring. No pipeline crate
    may depend on it: the answer key is for scoring only and must never reach analysis, matching or verification.
- `permanent-beta-match` and `permanent-beta-verify` must never depend on each other. Matchers propose; verification judges.
- No matcher, AI proposer or MCP tool may produce an accepted mapping without going through `permanent-beta-verify`.
- Ambiguity yields no candidate (review), never a best guess.

## Change rules

- Any change to analysis, matching or verification logic needs tests that include a *negative* case (something that
  must not match or must not be accepted).
- Never run the corpus unless the owner explicitly asks for it in the current conversation: it takes far too long.
  That covers `corpus/*.ps1` (`build-fixtures`, `build-projects`, `build-hooks -Run`, `replay-measure`,
  `ghidra-diff`), `pbeta-corpus score` and `cargo test -- --ignored`. Plain `cargo test` is fine (corpus tests are
  `#[ignore]`d). For an analysis, matching or verification change, say in the PR that the scorecards weren't run
  and offer to run `pwsh corpus/build-fixtures.ps1 -Score` before and after. When they are run: wrong matches must
  stay at zero, and when correct matches go up, raise `gate.min_correct` in the fixture's `expected.toml` in the
  same PR.
- Thresholds are tagged `[Guess]` in the design doc until calibrated. Don't present them as validated.
- Keep the analysis schema versioned. Bump `ANALYSIS_SCHEMA_VERSION` on breaking changes.
- Bump `FEATURES_VERSION` (`permanent-beta-analysis/src/native/mod.rs`) on any change to what a hash or code feature
  covers.
- No features for unpacking, defeating integrity checks, or evading anti-cheat or anti-tamper (design §12).

## Commands

- `cargo fmt --all`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
