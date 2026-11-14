# Permanent Beta

Keep function hooks working when the program they hook is rebuilt or updated.

A hook (Microsoft Detours, MinHook, …) patches a function at an address in one specific build. When the program is
rebuilt, every address moves and the hooks break; normally someone re-finds each function by hand in a
disassembler. `pbeta` does that part: it finds each hooked function in the new build, verifies it's the same
function, and rewrites your hook list with the new addresses. Anything it isn't sure about goes to a review queue
instead of being guessed. A generic hook DLL, the **hook host**, then attaches your hooks in whichever build is
running, so you don't write hook plumbing or hard-code addresses.

Windows x64 PE binaries, built with MSVC. Free and open source (Apache-2.0).

## Principles

- **Wrong is worse than unknown.** Ambiguity gives no answer, only a review item. A hook is never patched at a
  guessed address.
- **Matching proposes, verification judges.** Every candidate, from any source, passes the same independent checks
  and acceptance policy.
- **Deterministic first.** An AI model can propose candidates for leftovers; its proposals are verified and only
  ever queued for review.
- **Evidence is kept.** Accepted mappings and review decisions are stored with their evidence, append-only.
- **Local by default.** Nothing leaves the machine unless you opt in.

## Status

Working end to end, measured on real projects: zlib, Lua, zstd, TinyXML-2, yaml-cpp and JsonCpp across release
tags and optimization settings (`/O2`, `/Od`, identical-code folding, `/LTCG`, PGO), with **zero wrong matches**
(see [docs/STATUS.md](docs/STATUS.md)). Debug builds with incremental linking are supported.

| Part | State |
|---|---|
| Analysis of PE x64 binaries, with or without a PDB | Built |
| Matching (names, code hashes, strings, call graph, vtables, similarity) and verification | Built |
| Hook repair, review queue, AOB patterns, offsets header | Built |
| Prototype and struct-layout change proposals | Built (exact with PDBs; inferred without) |
| Behavioral checks: trace diff, and replay of recorded calls by emulation | Built (recording via the corpus harness) |
| Hook host: one DLL that runs your hooks in any build | Built ([harness/host](harness/host/README.md)) |
| AI proposer for unmatched functions (Claude, opt-in) | Built |
| MCP server for agents (read, explain, propose; never accept) | Built (`pbeta-mcp`) |
| Ghidra: headless exporter and review UI | Built ([integrations/ghidra](integrations/ghidra/README.md)) |
| IDA plugin, ELF, ARM64, x86 | Not started |

## Build

Needs the stable Rust toolchain ([rustup.rs](https://rustup.rs)). The hook host also needs Visual Studio's C++
x64 toolset and git (it fetches Microsoft Detours at a pinned commit).

```
cargo build --release
pwsh harness/host/build.ps1
```

That gives `target/release/pbeta.exe` and `target/host/` (`pbeta-host.dll`, `pbeta-launch.exe`,
`include/pbeta_handler.h`). Replay by emulation is optional: add `--features permanent-beta-replay/emulator`.

## Walkthrough

Two builds of a program you have the right to instrument: `old\app.exe` (the one your hooks were written for) and
`new\app.exe`. PDBs are optional; with them, matching and argument decoding are better.

**1. Analyze both builds.**

```
pbeta analyze old\app.exe --pdb old\app.pdb --out old.json
pbeta analyze new\app.exe --pdb new\app.pdb --out new.json
```

**2. Describe your hooks** in a manifest, `hooks.toml`, with their addresses (RVAs) in the old build:

```toml
[[hook]]
name = "SaveDocument"
detour = "log"                                   # what the hook host does (step 5)
prototype = "int SaveDocument(Doc* doc, const wchar_t* path)"   # optional; decodes arguments in the log

[hook.target]
build = "old"                                    # placeholder, set by `bind`
rva = 0x1600
```

**3. Bind it to the old build** (replaces the placeholder with the exe's SHA-256):

```
pbeta bind --hooks hooks.toml --binary old\app.exe
```

**4. Repair it for the new build:**

```
pbeta repair --old old.json --new new.json --hooks hooks.toml --new-binary new\app.exe --out hooks.new.toml --store store.json
```

Each hook is `unchanged`, `relocated` (with a fresh byte pattern) or `needs review`. Exit code 0 means every hook
was resolved, 1 that some need review, 2 an error. Review with `pbeta review list --store store.json`, then
`pbeta review accept` or `reject`, and repair again: decisions are honored.

**5. Run the program with your hooks** through the hook host:

```
pbeta host-config --hooks hooks.toml --hooks hooks.new.toml --analysis old.json --analysis new.json --out pbeta-host.toml
pbeta-launch pbeta-host.toml new\app.exe
```

The host hashes the running exe, attaches only the hooks verified for that build (after checking their bytes) and
nothing in a build it doesn't know. Each hook's `detour` is its action:

| `detour` | On each call |
|---|---|
| `log` | Log the decoded arguments and the result; the original runs. |
| `skip` / `return <n>` | Log the call; return 0 or `n` without running the original. |
| `mydll.dll!Name` | Run your handler instead (below). |

A handler is only the function body; the host attaches it and gives it the original:

```cpp
#include <pbeta_handler.h>

PBETA_HOOK(int, SaveDocument, (Doc* doc, const wchar_t* path)) {
    pbeta_log("saving %ls", path);
    return PBETA_ORIGINAL(SaveDocument)(doc, path);
}
```

`pbeta handler-stubs --hooks hooks.toml --out handlers.cpp` writes these declarations for you, from each hooked
function's prototype (or its PDB signature, with `--analysis`), so you only fill in the bodies.

On the next release: analyze it, repair from `hooks.new.toml`, run `host-config` with every manifest. Nothing gets
recompiled. More in [harness/host/README.md](harness/host/README.md).

Prefer your own hook DLL? `pbeta header --hooks <manifests>... --out hooks.gen.h` writes each build's RVAs and
patterns as a C header, looked up by the exe's SHA-256.

### Try it without a program of your own

`examples/demo` has two hand-written analyses and a manifest whose four hooks each show one outcome:

```
cargo run -p permanent-beta-cli -- repair --old examples/demo/v1.json --new examples/demo/v2.json --hooks examples/demo/hooks.toml --out target/hooks.v2.toml --store target/demo-store.json
cargo run -p permanent-beta-cli -- review list --store target/demo-store.json
```

`ParseConfig` is relocated; `CreateDocument` needs review (high criticality, no behavioral evidence);
`ChecksumBlock` is ambiguous (two identical functions in v2); `SaveDocument`'s signature changed. Accept one and
repair again:

```
cargo run -p permanent-beta-cli -- review accept ChecksumBlock:111111111111:222222222222 --candidate 0x2700 --reviewer you --store target/demo-store.json
```

`pwsh harness/host/test.ps1` runs the whole path, from analysis to hooks running under the host, on a test app built
twice, in about a minute.

## Commands

| Command | What it does |
|---|---|
| `analyze` | Binary (and optional PDB) → analysis JSON |
| `match` | Match and verify every function between two analyses |
| `bind` | Bind a manifest's placeholder builds to a binary |
| `repair` | Move a hook manifest to a new build; review items for the rest |
| `review list / accept / reject / revoke` | Decide the review queue |
| `host-config` | Manifests → the hook host's configuration |
| `handler-stubs` | Manifests → a handler DLL's source, declarations written from the prototypes |
| `header` | Manifests → `hooks.gen.h` for your own hook DLL |
| `pattern` | Unique byte pattern for a function |
| `propose` | Ask an AI model about unmatched functions (opt-in, queued for review) |
| `harness-spec`, `trace-diff`, `replay` | Behavioral evidence: record calls, compare traces, replay by emulation |
| `analysis-diff` | Compare two analyses of the same build |

`pbeta <command> --help` has the details. Design and rationale: [docs/design.md](docs/design.md).

## Layout

```
crates/
  permanent-beta-model/     shared types: analysis schema, candidates, evidence, mappings, hooks, review items
  permanent-beta-analysis/  binary → analysis (native PE x64 analyzer, PDB reader, Ghidra export loader)
  permanent-beta-match/     matching passes → candidates (never decides acceptance)
  permanent-beta-verify/    structural and behavioral checks, acceptance policy
  permanent-beta-repair/    per-hook repair decisions, patterns, header, host config, proposals
  permanent-beta-replay/    replay of recorded calls by emulation (optional `emulator` feature)
  permanent-beta-store/     mapping history and review queue (JSON file)
  permanent-beta-engine/    orchestration: match → verify → repair
  permanent-beta-cli/       `pbeta`
  permanent-beta-mcp/       `pbeta-mcp`, MCP server for agents
  permanent-beta-ai/        AI proposer (Claude via Claude Code); proposals go to review
  permanent-beta-corpus/    test tooling: answer keys and scoring (`pbeta-corpus`)
harness/host/               the hook host (C++, Detours) and its end-to-end test
integrations/ghidra/        headless exporter and review extension
corpus/                     ground-truth corpus: fixtures, real projects, the hook-repair loop
examples/demo/              hand-written analyses and manifest for the walkthrough above
docs/                       design.md (architecture), STATUS.md (where things stand)
```

`match` and `verify` never depend on each other; [CLAUDE.md](CLAUDE.md) lists every allowed dependency.

## Development

```
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
pwsh harness/host/test.ps1
```

CI runs the first three on Windows and Linux on every push. The corpus (building and scoring real projects across
versions) takes a long time and runs only on demand: Actions → ci → Run workflow with "corpus" ticked, or locally
`pwsh corpus/build-fixtures.ps1 -Score`, `pwsh corpus/build-projects.ps1 -Score` and
`pwsh corpus/build-hooks.ps1 -Run`. Any change to analysis, matching or verification needs tests with a negative
case, and must keep wrong matches at zero.

This codebase is written by AI agents and reviewed by the owner; [CLAUDE.md](CLAUDE.md) has the rules they follow.

## Legal

Only analyze and instrument software you have the right to. This project does not support, and will not accept
contributions for, circumventing DRM, anti-tamper or anti-cheat protections: the analyzer refuses binaries that
look packed or protected. See the risks section of the design document.

## License

Apache License 2.0: see [LICENSE](LICENSE) and [NOTICE](NOTICE). Third-party material keeps its own license
([licenses/README.md](licenses/README.md)).
