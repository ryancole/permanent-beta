# rehook (working name)

Map functions across versions of a native binary and repair instrumentation hooks (for example Microsoft Detours)
when the target is rebuilt or patched.

> Status: **skeleton (M0)**. The matching, verification and repair pipeline runs end to end on hand-written analysis
> exports. The native PE analyzer, Ghidra exporter, behavioral testing, MCP server and Ghidra UI are not built yet.
> See [docs/design.md](docs/design.md).

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
  rehook-model/     shared types: analysis schema, candidates, evidence, mappings, hooks, review items
  rehook-analysis/  binary → AnalysisExport (native PE x64 analyzer: stub; Ghidra export loader)
  rehook-match/     matching passes → candidates (never decides acceptance)
  rehook-verify/    structural checks, behavioral runner interface, acceptance policy
  rehook-repair/    per-hook repair decisions, manifest rewrite
  rehook-store/     mapping history + review queue (JSON file now, SQLite planned)
  rehook-engine/    orchestration: match → verify → repair
  rehook-cli/       the `rehook` binary
integrations/
  ghidra/           Ghidra extension + headless exporter (planned, Java)
  ida/              IDA Pro plugin (planned, after repair is validated)
harness/            C++ Detours harness for recording and replaying behavior (planned)
corpus/             ground-truth corpus recipes and metrics (planned)
examples/demo/      hand-written analysis exports + hook manifest for the end-to-end demo
docs/design.md      architecture, data model, verification, review queue, open questions, risks
```

Dependency rule: `match` and `verify` never depend on each other. Both depend only on `rehook-model`.

## Build and try the demo

Requires a stable Rust toolchain (https://rustup.rs).

```bash
cargo test --workspace
```

```bash
cargo run -p rehook-cli -- match --old examples/demo/v1.json --new examples/demo/v2.json
```

```bash
cargo run -p rehook-cli -- repair --old examples/demo/v1.json --new examples/demo/v2.json --hooks examples/demo/hooks.toml --out target/hooks.v2.toml --store target/demo-store.json
```

```bash
cargo run -p rehook-cli -- review list --store target/demo-store.json
```

Expected `repair` outcome for the demo: `ParseConfig` relocated; `CreateDocument` needs review (high criticality,
no behavioral tests yet); `SaveDocument` needs review (parameter count changed); `ChecksumBlock` needs review as
ambiguous (two identical functions exist in v2, and both are listed in its review item). Exit code `1` = some hooks need review.

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
