# Contributing

Contributions are welcome. Permanent Beta is licensed under Apache-2.0 ([LICENSE](LICENSE)), and contributions are
accepted under the same license.

## Sign your commits (DCO)

Every commit in a pull request needs a `Signed-off-by` line, certifying the [Developer Certificate of
Origin](DCO): that you wrote the change, or otherwise have the right to submit it under the project's license.
Git adds the line for you with `-s`:

```
git commit -s -m "Matching: ..."
```

which appends

```
Signed-off-by: Your Name <you@example.com>
```

using your `user.name` and `user.email`. Use your real name or a name you're known by, and an email you can be
reached at. You keep the copyright to your contribution; there is no separate agreement to sign. A CI check fails a
pull request with a commit that has no sign-off. To add one to commits you've already made:
`git rebase --signoff origin/master`, then force-push the branch.

Code written with an AI assistant is welcome (most of this codebase is; see [CLAUDE.md](CLAUDE.md)). The sign-off is
yours: by signing off you certify the DCO for it, so review what you submit. An agent doesn't sign off on its own.

## What a change needs

- `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings` and `cargo test --workspace` pass.
  For changes to the hook host, `pwsh harness/host/test.ps1` too.
- A change to analysis, matching or verification has tests with a negative case (something that must not match or
  must not be accepted), and keeps wrong matches at zero on the corpus. Say in the pull request whether the
  corpus scorecards were run ([corpus/README.md](corpus/README.md)).
- Thresholds that haven't been calibrated are tagged `[Guess]` in [docs/design.md](docs/design.md).
- No features for unpacking, defeating integrity checks, or evading anti-cheat or anti-tamper (design §12).
- No GPL dependencies.
