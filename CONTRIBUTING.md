# Contributing

Contributions are welcome. Permanent Beta is licensed under Apache-2.0 ([LICENSE](LICENSE)), and contributions are
accepted under the same license.

## What a change needs

- `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings` and `cargo test --workspace` pass.
  For changes to the hook host, `pwsh harness/host/test.ps1` too.
- A change to analysis, matching or verification has tests with a negative case (something that must not match or
  must not be accepted), and keeps wrong matches at zero on the corpus. Say in the pull request whether the
  corpus scorecards were run ([corpus/README.md](corpus/README.md)).
- Thresholds that haven't been calibrated are tagged `[Guess]` in [docs/design.md](docs/design.md).
- No features for unpacking, defeating integrity checks, or evading anti-cheat or anti-tamper (design §12).
- No GPL dependencies.
