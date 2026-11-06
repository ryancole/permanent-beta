# Guidance for AI agents working in this repo

This codebase is written by AI agents and reviewed by the owner. These rules exist to keep it reviewable and to
stop plausible-but-wrong matching logic from merging.

## Architecture rules

- Read `docs/design.md` §3 before changing crate structure.
- Allowed internal dependencies (enforced by Cargo.toml review):
  - `rehook-model`: none
  - `rehook-analysis`, `rehook-match`, `rehook-verify`, `rehook-repair`, `rehook-store`: `rehook-model` only
  - `rehook-engine`: model, match, verify, repair
  - `rehook-cli`: engine, analysis, store, model
- `rehook-match` and `rehook-verify` must never depend on each other. Matchers propose; verification judges.
- No matcher, AI proposer or MCP tool may produce an accepted mapping without going through `rehook-verify`.
- Ambiguity yields no candidate (review), never a best guess.

## Change rules

- Any change to analysis, matching or verification logic needs tests that include a *negative* case (something that
  must not match or must not be accepted).
- Once the corpus gate exists (design §10), report corpus precision and recall before and after in the PR.
- Thresholds are tagged `[Guess]` in the design doc until calibrated. Don't present them as validated.
- Keep the analysis schema versioned. Bump `ANALYSIS_SCHEMA_VERSION` on breaking changes.
- No features for unpacking, defeating integrity checks, or evading anti-cheat or anti-tamper (design §12).

## Commands

- `cargo fmt --all`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
