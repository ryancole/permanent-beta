# Permanent Beta

Map functions across versions of a native binary and repair instrumentation hooks (for example Microsoft Detours)
when the target is rebuilt or patched.

> Status: **early (M1)**. `pbeta analyze` reads real PE x64 executables, and the matching, verification and repair
> pipeline runs end to end on its output. Purpose-built test executables and their answer keys are in `corpus/`.
> The Ghidra exporter, behavioral testing, MCP server and Ghidra UI are not built yet. See
> [docs/design.md](docs/design.md).

## Principles

- **Deterministic first.** Signature and diffing passes propose matches. AI is an optional proposer.
- **Verification is independent.** Every candidate, whatever its source, passes the same structural and
  behavioral checks and criticality policy.
- **Wrong is worse than unknown.** Anything ambiguous goes to a human review queue.
- **Evidence is stored.** Accepted mappings live in an append-only, versioned history with their evidence.
- **On-prem by default.** Nothing leaves the machine unless configured.

## Layout

```
crates/
  permanent-beta-model/     shared types: analysis schema, candidates, evidence, mappings, hooks, review items
  permanent-beta-analysis/  binary → AnalysisExport (native PE x64 analyzer; Ghidra export loader)
  permanent-beta-match/     matching passes → candidates (never decides acceptance)
  permanent-beta-verify/    structural checks, behavioral runner interface, acceptance policy
  permanent-beta-repair/    per-hook repair decisions, manifest rewrite
  permanent-beta-store/     mapping history + review queue (JSON file now, SQLite planned)
  permanent-beta-engine/    orchestration: match → verify → repair
  permanent-beta-cli/       the `pbeta` binary
  permanent-beta-corpus/    test tooling: map-file parser, answer keys (`pbeta-corpus`)
integrations/
  ghidra/           Ghidra extension + headless exporter (planned, Java)
  ida/              IDA Pro plugin (planned, after repair is validated)
harness/            C++ Detours harness for recording and replaying behavior (planned)
corpus/             test fixtures + real-world projects (zlib); MSVC build scripts, answer keys from map files
examples/demo/      hand-written analysis exports + hook manifest for the end-to-end demo
docs/design.md      architecture, data model, verification, review queue, open questions, risks
```

Dependency rule: `match` and `verify` never depend on each other. Both depend only on `permanent-beta-model`.

## Build and try the demo

Requires a stable Rust toolchain (https://rustup.rs).

```bash
cargo test --workspace
```

```bash
cargo run -p permanent-beta-cli -- match --old examples/demo/v1.json --new examples/demo/v2.json
```

```bash
cargo run -p permanent-beta-cli -- repair --old examples/demo/v1.json --new examples/demo/v2.json --hooks examples/demo/hooks.toml --out target/hooks.v2.toml --store target/demo-store.json
```

```bash
cargo run -p permanent-beta-cli -- review list --store target/demo-store.json
```

Expected `repair` outcome for the demo: `ParseConfig` relocated; `CreateDocument` needs review (high criticality,
no behavioral tests yet); `SaveDocument` needs review (parameter count changed); `ChecksumBlock` needs review as
ambiguous (two identical functions exist in v2, and both are listed in its review item). Exit code `1` = some hooks need review.

Decide a review item, then repair again: the decision is honored and `ChecksumBlock` is relocated, marked as
decided by the reviewer.

```bash
cargo run -p permanent-beta-cli -- review accept ChecksumBlock:111111111111:222222222222 --candidate 0x2700 --reviewer you --store target/demo-store.json
```

`review accept` takes one of the item's verified candidates (`--candidate` is required when there are several;
`--force` is required for one that verification rejected) and records a mapping decided by the reviewer.
`review reject` says none of the candidates is the counterpart: they're never proposed for that function again,
and the item stays closed until new candidates appear. The hook itself stays unresolved until its manifest entry
is fixed by hand. Decisions are append-only.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | All hooks resolved |
| 1 | Some hooks need human review |
| 2 | Error |

## Legal

Only analyze and instrument software you have the right to. This project does not support, and will not accept
contributions for, circumventing DRM, anti-tamper or anti-cheat protections. See the risks section of the design
document.

## License

Not yet chosen. See [LICENSE](LICENSE) and [licenses/README.md](licenses/README.md).
