# Permanent Beta — design document

Status: draft v0.1 · 2026-11-05 · Owner: Ryan Cole

## How to read this document

Every claim that isn't settled carries a tag:

| Tag | Meaning |
|---|---|
| **[Decided]** | Chosen by the owner; change only deliberately. |
| **[Provisional]** | A recommended default the skeleton is built on; cheap to change now, expensive later. |
| **[Guess]** | An estimate or belief that has not been checked. |
| **[Validate]** | Needs market, legal or technical validation before relying on it. |

Untagged text describes the design intent, not established fact.

---

## 1. Problem

Hooks into native executables (for example Microsoft Detours detours) are tied to a specific build: an RVA, a byte
pattern, a symbol, a calling convention, struct offsets. When the target is rebuilt or patched, hooks break.

Detecting breakage is easy. **Repairing** it is the valuable part, and it requires:

1. Finding the function's new location in the new build.
2. Verifying the candidate is the *same* function, not a similar one.
3. Adapting the hook if the signature or struct layouts changed.
4. Checking the repaired hook against behavioral tests recorded from the old version.
5. Routing anything unresolved to a human review queue.

### Goals

- Headless, scriptable, deterministic engine usable in a build pipeline (exit codes, JSON output).
- Every accepted mapping is backed by recorded, inspectable evidence and stored in a versioned history.
- Wrong repairs are treated as worse than no repair. The engine prefers "needs review" over a guess.
- AI is an optional proposer whose output passes through exactly the same verification as everything else.
- Runs fully on-premises; nothing leaves the machine unless explicitly configured.

### Non-goals (v1)

- Defeating packers, obfuscators, DRM, or anti-tamper / anti-cheat protections (see §12, Risks).
- Managed (.NET / JVM) binaries.
- Being a general-purpose disassembler or decompiler. Deep analysis is delegated (§4).
- Fully automatic repair of hand-written detour *logic*. The engine updates locators and generated code; semantic
  changes to detour bodies are proposals for a human.

---

## 2. Decisions so far

| Topic | Choice | Status |
|---|---|---|
| Product name | Permanent Beta; crates `permanent-beta-*`, CLI `pbeta` | **[Decided]** |
| Core language | Rust | **[Decided]** |
| v1 targets | Windows PE, x64 only | **[Provisional]** |
| Analysis source | Hybrid: native analyzer in the core + import of a Ghidra headless export | **[Provisional]** |
| Hook libraries | Detours first, via a library-neutral hook manifest | **[Provisional]** |
| Hook manifest format | New TOML manifest (§7.1) | **[Provisional]**. Existing hooks' locator style is still unknown |
| Local storage | SQLite (the skeleton uses a JSON file as a stand-in) | **[Provisional]** |
| Open-source license | Apache-2.0 for core and Ghidra extension | **[Provisional]**. See §11 |
| Development model | Code is AI-written; the owner reviews | **[Decided]** |

### 2.1 Why Rust (summary)

- **Compiler as reviewer.** The code is AI-written. Rust rejects data races, use-after-free, unhandled `match`
  arms and null misuse at build time, which gives an agent a strict compile-fix loop.
- **Embeddability.** The core can be exposed as a C ABI and as Python bindings (PyO3). That matters for an
  IDAPython plugin, Binary Ninja, and scripting users.
- **Distribution.** Small static binaries and straightforward cross-compilation suit on-prem and CI.
- **Ecosystem.** `object`/`pelite`/`goblin` (PE parsing), `iced-x86` (x86/x64 decoding), `pdb` (PDB reading),
  `rmcp` (official MCP SDK). The maturity of `pdb` and `rmcp` for this use is **[Validate]**.
- **Cost.** The owner reads C# natively and Rust less fluently, so review is slower. Mitigation: strict crate
  boundaries, small modules, and the corpus metrics gate (§10) as the main correctness signal.

C# was the close second: owner fluency, Iced/AsmResolver, strong Azure tooling. The hosted service (§9.4) may still
be written in C# and share only the schema.

---

## 3. Architecture

```mermaid
flowchart LR
    subgraph Inputs
      B1[old build .exe/.dll + PDB?]
      B2[new build .exe/.dll + PDB?]
      GH[Ghidra headless export]
      HM[hook manifest .toml]
      TC[behavioral test corpus]
    end

    subgraph Core["Permanent Beta core (Rust, open source)"]
      AN[analysis\nnormalize to AnalysisExport]
      MA[match\npasses → candidates]
      VE[verify\nstructural + behavioral]
      RE[repair\nhook decisions, manifest rewrite, codegen]
      ST[store\nmappings, evidence, review queue]
      EN[engine\norchestration]
    end

    AI[ai-propose\noptional, local model] -.candidates.-> VE
    B1 & B2 --> AN
    GH --> AN
    AN --> MA --> VE --> RE
    HM --> RE
    TC --> VE
    EN --- MA & VE & RE & ST
    RE --> ST

    CLI[pbeta CLI] --> EN
    MCP[MCP server] --> EN
    GX[Ghidra extension (Java)] -->|JSON / RPC| CLI
```

### 3.1 Crate boundaries

| Crate | Responsibility | May depend on |
|---|---|---|
| `permanent-beta-model` | Shared data types: analysis schema, candidates, evidence, mappings, hooks, review items. No logic beyond helpers. | (nothing internal) |
| `permanent-beta-analysis` | Produce an `AnalysisExport` from a binary (native analyzer) or load one produced by Ghidra. | model |
| `permanent-beta-match` | Matching passes that emit `Candidate`s with evidence. Never decides acceptance. | model |
| `permanent-beta-verify` | Structural checks, behavioral test runner interface, acceptance policy → `Verdict`. | model |
| `permanent-beta-repair` | Per-hook decisions, manifest rewrite, generated code. | model |
| `permanent-beta-store` | Versioned mapping history, evidence, review queue persistence. | model |
| `permanent-beta-engine` | Orchestrates analysis output → match → verify → repair. | model, match, verify, repair |
| `permanent-beta-cli` | `pbeta` binary; argument parsing, I/O, exit codes. | engine, analysis, store, model |
| `permanent-beta-corpus` | Test tooling: linker map parser, ground-truth answer keys (`pbeta-corpus`). Nothing depends on it. | model |
| *(planned)* `permanent-beta-ai` | Proposers that call a local or remote model and emit `Candidate`s. | model |
| `permanent-beta-mcp` | MCP server over the engine (`pbeta-mcp`, §11.2). Reads the store and adds review items; never decides one. | engine, store, model |
| *(planned)* `permanent-beta-py` | PyO3 bindings for IDA / scripting. | engine, model |

**Rule that matters most:** `match` and `verify` do not depend on each other. Matchers propose, verification judges,
and the only shared language is `permanent-beta-model`. A matcher cannot mark its own output accepted, and that includes
AI proposers.

### 3.2 Process model

- **CLI** is the primary interface: one process per invocation, JSON in and out, deterministic exit codes.
- **Ghidra extension** (Java) runs out of process. It either invokes the CLI, or later talks to a long-running
  `pbeta serve` over local JSON-RPC. Nothing is linked into the JVM. **[Provisional]**
- **MCP server** wraps the same engine API. It exposes read and propose operations; acceptance still goes through
  verification and policy (§9.2).

---

## 4. Analysis layer

### 4.1 Normalized analysis schema (`AnalysisExport`)

Every analyzer produces the same versioned JSON document (`schema_version`, currently 1). Matching and verification
only ever see this schema, so analyzers are swappable and testable.

Per build: content hash (SHA-256, the `BuildId`), file name, version resource, machine, PDB GUID/age if present,
producer tool and version.

Per function (fields optional unless noted):

| Field | Purpose |
|---|---|
| `rva` (required), `size` | Identity within a build; size ratio check. |
| `name`, `name_source` | export / PDB / RTTI / analyst / inferred. Name trust differs by source. |
| `normalized_hash` | Hash of instruction bytes with relocations, RIP-relative displacements and absolute addresses masked. Survives relinking. |
| `mnemonic_hash` | Hash of the mnemonic sequence only. Survives register allocation changes. **[Guess]** at its usefulness for MSVC. |
| `basic_blocks`, `edges` | CFG shape (planned: a proper structural fingerprint, MD-index style). |
| `callees` | Call-graph edges (RVAs within the same build). |
| `strings`, `constants`, `imports` | Referenced string literals, non-trivial immediates, imported APIs called. |
| `signature` | Calling convention, return type, parameters, typically from PDB or decompiler. |

**Planned additions:** per-function pseudocode (from Ghidra, for review and AI), struct type definitions
referenced by signatures, and a `features_version` so that hashes from different normalizer versions are never
compared.

### 4.2 Native analyzer (fast path, in Rust)

Target: PE x64. Implemented in `permanent-beta-analysis/src/native` (M1, first version):

- Parse headers and sections with `object`; `.pdata` and the import table are parsed by hand from section bytes.
- Function starts: non-chained `.pdata` entries, the entry point and exports, then direct call/jump targets found
  by disassembly, iterated to a fixpoint. This matters more than expected: at `/O2`, MSVC emits no `.pdata` for
  leaf functions that don't touch the stack, which was most of the fixture's test functions. Functions without
  `.pdata` end at the next known start, minus `int3` padding. RIP-relative `lea` of code outside any known
  function also starts one (an address taken, e.g. zlib's `zcalloc`/`zcfree` callbacks).
- Chained `.pdata` fragments are followed back to their root function and decoded as part of it: at `/O2`, MSVC
  splits bodies into chained fragments, and their calls, strings and constants belong to the parent. Branches
  into a fragment are hashed as (fragment, offset), so the hash doesn't move with the fragment. Before this, 6 of
  zlib's 69 functions were invisible at /O2 (called only from fragments); after it, all 69 match.
- Decode with `iced-x86`. Normalized hash (opcode and operands, with RIP-relative targets, external branch
  targets and in-image addresses masked; internal branch offsets kept), mnemonic hash, basic-block count,
  callees, string literals (ASCII and UTF-16) and imports referenced through RIP-relative operands, and
  non-trivial constants.
- Build id = SHA-256 of the file. The PDB GUID and age are read from the debug directory; no symbols are read.
- Scored against the fixture answer keys (`permanent-beta-corpus/tests/native_fixtures.rs`): every answer-key
  function is found in all three flag sets.

Known gaps: no PDB names or types yet (`pdb` crate, planned), functions without `.pdata` reached only through
data (vtables, function-pointer tables) or not at all (dead code) are missed, and `edges` isn't computed. **[Validate]** the discovery approach on real targets with indirect calls and jump tables.

What it won't do: decompilation or type recovery. That comes from the Ghidra export.

### 4.3 Ghidra headless export (deep path)

A Ghidra script or extension, run through `analyzeHeadless`, writes `AnalysisExport` JSON including decompiler
pseudocode and recovered types. This makes the deep path free and scriptable in CI, at the cost of a JVM and a
Ghidra install on the build agent.

The two analyzers must agree on function identity (RVA) and on any hash they both emit. The cheapest rule: hashes
are always computed by the Rust normalizer, even for Ghidra exports (Ghidra provides boundaries and bytes; Rust
hashes). **[Provisional]**

---

## 5. Matching

Inspired by the multi-pass approach of BinDiff and Diaphora: run high-confidence, low-recall passes first, then
progressively weaker ones restricted to still-unmatched functions, and use matched pairs as anchors for
neighbourhood passes.

### 5.1 Passes (in order) **[Provisional]**

| # | Pass | Key | Notes |
|---|---|---|---|
| 1 | Symbol name | Export or PDB name unique on both sides | Implemented in the skeleton. |
| 2 | Normalized hash | `normalized_hash` unique on both sides | Implemented. |
| 3 | Unique string set | Sorted referenced strings, unique | Implemented. **Vetoed** when other evidence contradicts it: different inferred register-argument counts, or the old function has matched callers and none of their counterparts calls the new function. Vetoes are rechecked against the final matches (`Matcher::contradiction`): a contradicted pair is banned, all passes rerun without it, and it stays as a review suggestion. Found by Lua 5.4.8 (a literal moved into a new helper) and zstd 1.5.7 (a body moved behind a wrapper). |
| 4 | Mnemonic hash | `mnemonic_hash` unique on both sides, gated | Implemented 2026-11-07 (`MnemonicHashMatcher`): the same instruction sequence with changed operands (a constant, stack or field offset). On tiny functions two unrelated ones can each have a unique sequence, so uniqueness alone isn't enough: both functions must be ≥ 32 bytes **[Guess]**, and a matched neighbour must agree (they call the same matched function, or a matched caller's counterpart calls the new one; recorded as callee or call-sequence evidence, so that check doesn't count again). Without an anchor it's a review suggestion. Vetoed like the strings pass (argument registers, disagreeing callers). On the corpus: 0 wrong; zstd +3 to +23 correct per variant and ~60 more accepted per /O2 variant (taken over from similarity, which only reaches review); Lua a few moved from review to accepted. |
| 5a | Matched callees | `normalized_hash` + callee list mapped through earlier matches, unique on both sides | Implemented (`MatchedCalleesMatcher`). Normalization masks call targets, so code differing only in what it calls is hash-ambiguous (zlib's `adler32`/`crc32` `jmp` wrappers). Every callee must already be matched; no callees means no key. On zlib: /O2 61→63, /Od 150→154 and 152→156, 0 wrong. |
| 5 | Call-graph propagation | Callees of matched callers | Implemented (`CallSequenceMatcher`), iterated to fixpoint. **Candidate** only when a callee's code occurs exactly once among the caller's unmatched callees in both builds, which doesn't depend on call order. Pairing by call *position* (or repeated identical code by order) is a **review suggestion** (an ambiguity), never a candidate: MSVC reorders calls to side-effect-free functions, and in the `basic` fixture that paired a deleted function with an edited one. The corpus gate caught it. |
| 6 | Structural similarity | Weighted feature similarity among anchored pairs, best-vs-second-best margin on both sides | Implemented (`SimilarityMatcher`), a **weak** pass: it runs only once every stronger pass has stopped. Candidates share an anchor (matched callee or caller, string, constant, import). Score: weighted mean of code (mnemonic counts), shape (blocks, edges), size, matched callees and callers, strings, constants, imports. Candidate only if mutual best, score ≥ 0.75 and ≥ 0.05 ahead of the runner-up on both sides, size ≥ 16 bytes (**calibrated** 2026-11-07 with `pbeta-corpus sweep` over 21 corpus variants: wrong matches appear at score 0.70 and none at ≥ 0.75 for any margin 0.02–0.2 or size 8–32; margin 0.1 → 0.05 added 108 correct review candidates. Weights and the bucket limit are still **[Guess]**. Recheck with the sweep whenever the corpus grows). Vetoed by disagreeing matched callers; a new function that's the only callee of an unmatched new function gives an ambiguity (body moved behind a wrapper, zstd 1.5.6). Its evidence implies the neighbour, string, constant, import and size checks, so its matches go to review. On the corpus: 0 wrong; zstd /O2 433–511 → 623–669 correct, Lua /O2 642–667 → 706–714. |
| 7 | AI proposer | Pseudocode comparison for leftovers | Optional (§8). |

### 5.2 Invariants

- **One-to-one.** A function on either side is claimed at most once. The first (strongest) pass wins.
- **Uniqueness, not best score.** A key that maps to more than one function on either side produces *no* candidate.
  Ambiguity is a review item, not a coin toss.
- **Evidence is mandatory.** Every candidate records which pass produced it and why.
- **Many-to-one is real.** MSVC `/OPT:ICF` folds identical functions, inlining and function splitting change
  boundaries. The model must eventually express "old function folded into X" and "old function inlined into its
  callers" as outcomes, not just as failures to match. **[Validate]** how often hooked functions are affected.

### 5.3 Scores

Each candidate carries a score in [0, 1]. Scores are **not** probabilities until they've been calibrated against the
ground-truth corpus (§10). Until then, policy uses check outcomes rather than score thresholds.

---

## 6. Verification pipeline

Verification is independent of matching and is applied identically to deterministic, AI and human-proposed
candidates.

### 6.1 Structural checks

Implemented as small `StructuralCheck`s returning `pass | fail | inconclusive` with a reason:

| Check | Pass condition | Status |
|---|---|---|
| Parameter count | Equal when both signatures are known (PDB or Ghidra) | Implemented |
| Inferred register arguments | Same number of Win64 argument registers (rcx/rdx/r8/r9, xmm0–3) read before written, up to the first call. Works without symbols. A lower bound, so sanity-only: a mismatch sends to review (it caught fixture S4's added parameter), a match never counts | Implemented |
| String references | Jaccard similarity ≥ 0.5 **[Guess]** at the threshold | Implemented |
| Size ratio | New/old size within 0.5–2.0; fail outside 0.25–4.0 **[Guess]**. Sanity check only: can fail a candidate, never counts as support | Implemented |
| Callers / callees | Of the old function's neighbours that have a candidate, ≥ 50% land on the new function's neighbours; fail below that with ≥ 2 mapped neighbours **[Guess]**. Uses this run's candidates, so it measures consistency, not truth | Implemented |
| Constants, imports | Jaccard ≥ 0.5 passes; < 0.2 with ≥ 2 items on each side fails **[Guess]**. Constants are implied by a hash match, imports are not (IAT operands are masked). On zlib /Od this raised accepted matches from 130 to 133 | Implemented |
| Calling convention / prologue | Compatible with the hook's prototype and trampoline needs (e.g. enough bytes before a branch target for Detours) | Planned |
| Hookability | Moved to repair (§7.2): it's a property of the hook target, not evidence of identity, so it doesn't affect matching scores | Implemented in repair |

**Independence (implemented):** a check that measures what the candidate's evidence already established adds
nothing, so its pass doesn't count (`CheckResult.counted = false`, visible to reviewers). Implied checks per
evidence kind (`permanent_beta_verify::implied_checks`): normalized hash → string refs, size, constants and inferred
args; strings → string refs; call sequence → callers; matched callees → callees; similarity → string refs, size,
callers, callees, constants and imports. Failures always count, so evidence can't excuse a failing check.

### 6.2 Behavioral checks

A `BehavioralRunner` replays recorded tests (§7.3) against the new build and returns pass, fail or inconclusive.
The default is `NoBehavioralCorpus`, which always returns inconclusive. `TraceDiffRunner` (implemented, M4) judges a
candidate from two scenario traces: the calls a detour at the old RVA saw in the old run must equal the calls a
detour at the candidate's RVA saw in the new run. Traces are matched to builds by their `start` event, so the old
trace is always a run of the candidate's own old build (an RVA means nothing in another build). It's inconclusive
when there's no trace of either build or either side has no hook there, and fails on any difference or a crashed
run. `pbeta repair --old-trace ... --new-trace` uses it; the new trace is usually a trial run (§7.2), so review
candidates can be judged too. How a behavioral pass counts toward acceptance is part of the policy (§6.3).

### 6.3 Acceptance policy

Policy is a function of the hook's criticality (from the manifest):

| Criticality | Min. independent passes (beyond the candidate's own evidence) | Behavioral pass required |
|---|---|---|
| low | 1 | no |
| normal | 1 | no |
| high | 2 | **yes** |

All three numbers are **[Guess]**. Normal was 2 when every passing check counted. Once implied passes and the
size check stopped counting, 2 *independent* passes made a correctly matched leaf function with no strings
impossible to accept. Now a unique match plus one independent check (typically callers) is enough, and the corpus
gate guards it. Low may drop to 0 once calibrated.

A behavioral pass (decided 2026-11-07) is independent of every structural check and of the candidate's evidence,
so for low and normal it counts as one independent pass: a correctly matched function with no independent
structural evidence (a rewritten leaf, or a hash match with no strings) is accepted once its scenario trace
matches. For high it does not count: high still needs 2 independent *structural* passes, and the behavioral pass
on top. A scenario only exercises some inputs, so for the hooks that matter most it confirms the structure rather
than replacing it. **[Guess]**, like the numbers above. A behavioral failure always sends to review.

Verdict rules (implemented):

- 2 or more structural failures → **rejected** (still shown in review with its evidence)
- 1 structural failure, or a behavioral failure → **needs review**
- policy satisfied → **accepted**
- otherwise → **needs review**

Accepted candidates whose function **signature changed** are still routed to review by the repair stage.

---

## 7. Repair

### 7.1 Hook manifest **[Provisional]**

A library-neutral description of each hook. Detours is the first consumer; MinHook, PolyHook 2 and Frida could
consume the same manifest via generators.

```toml
[[hook]]
name        = "SaveDocument"
detour      = "Hook_SaveDocument"        # symbol in the hook DLL
criticality = "normal"                   # low | normal | high
prototype   = "int __fastcall SaveDocument(Doc* doc, const wchar_t* path)"

[hook.target]
build   = "<sha256 of the build this locator is valid for>"
rva     = 0x1600
symbol  = "SaveDocument"                 # optional
pattern = "48 89 5C 24 ?? 57 48 83 EC 20" # optional AOB signature
```

Each locator is bound to a specific `build`. A repaired manifest re-binds it to the new build.

### 7.2 Repair actions

| Outcome | Meaning | Output |
|---|---|---|
| `unchanged` | Verified, same RVA | Locator re-bound to the new build. |
| `relocated` | Verified, new RVA | New RVA, and with `--new-binary` a regenerated AOB pattern (below). |
| `needs_review` | Unmatched, ambiguous, verification failed, insufficient evidence, signature changed, not hookable (the new function is under 5 bytes, a branch targets the patched bytes, or it is only a jump thunk), or stale locator (bound to another build than the one repaired from, e.g. a hook an earlier repair sent to review: its RVA says nothing about the old build) | Review item; the locator stays bound to the old build. |

A hook whose locator is still bound to an older build (an earlier repair sent it to review) is repaired from that
build directly when its analysis is given (`pbeta repair --earlier`), e.g. v1 → v3. Without it, it's a stale
locator.

Generators (all output goes to review unless purely mechanical):

- **AOB patterns** (implemented): a re-bound locator drops its old pattern (it was checked against the old build
  only). `pbeta repair --new-binary` regenerates one per re-bound hook: the shortest run of whole instructions
  from the entry, at least 8 bytes **[Guess]**, never past the function, that matches exactly once in the image's
  executable code. RIP-relative displacements, branches leaving the function and in-image addresses are `??`;
  everything else stays concrete. Identical code elsewhere means no pattern, never a shorter one that could
  resolve to the copy. `pbeta pattern <binary> --rva` prints one.
- **Trial manifests** (implemented): `pbeta repair --trial-out` adds trial bindings (`trial = true`) for hooks in
  review whose only missing evidence is behavioral (insufficient evidence, no failing check, one patchable
  candidate) to the repaired manifest. A test run under it gives those candidates their behavioral evidence
  (§6.2). `repair` refuses a trial manifest as input, and `header` refuses to emit one.
- **Offsets header** (implemented): `pbeta header --hooks <manifest>... --out hooks.gen.h`: RVAs and patterns per
  build, for hook DLLs that use hardcoded tables, with a lookup by the executable's SHA-256. A hook without a
  verified locator for a build has RVA 0 there.
- **Prototype adaptation** (implemented for added register parameters): when a candidate reads more Win64
  argument registers than the hook's prototype declares (and the old function didn't), the review item gets a
  proposed prototype, with each added parameter typed from its register class (`intptr_t` or `double`), and a C++
  shim: a new detour that stashes the added arguments and calls the existing detour, whose call to the original
  forwards them. Removed or reordered parameters aren't proposed (inferred arguments are a lower bound). The
  detour body is never rewritten automatically.
- **Struct layout adaptation** (planned): when a struct used in the prototype changed, emit updated definitions or
  field offset constants derived from PDB or Ghidra types. Field correspondence (old field → new field) is itself
  a mapping with evidence. **[Validate]** feasibility without PDBs.

### 7.3 Behavioral test corpus **[Provisional]**

**Recording (old build).** A C++ harness DLL (built on Detours) installs logging detours at hook sites and
captures, per call:

- Argument registers and stack args (Win64 ABI).
- Memory reachable from pointer args, to a bounded depth, *typed* by the prototype and struct layouts.
- Return value, writes to the captured regions, and the sequence of callees or imports invoked.

**Representation.** One JSON test case per call, with content-addressed blobs for memory:

```json
{
  "test_id": "save-doc-0003",
  "hook": "SaveDocument",
  "build": "<sha256>",
  "recorder": "permanent-beta-harness 0.1",
  "abi": "win64",
  "args": [
    { "slot": "rcx", "type": "Doc*", "points_to": "blob:sha256:…", "layout": "Doc@<build>" },
    { "slot": "rdx", "type": "const wchar_t*", "points_to": "blob:sha256:…" }
  ],
  "observed": {
    "return": { "rax": "0x1" },
    "writes": [ { "region": "arg0", "field": "dirty", "value": "0x0" } ],
    "callees": ["kernel32!CreateFileW", "kernel32!WriteFile", "kernel32!CloseHandle"]
  },
  "compare": { "ignore": ["writes:arg0.lastSaved"], "callees": "multiset" }
}
```

Recording memory with its type layout is what makes replay possible when a struct changes: the replayer translates
old-layout blobs to the new layout through the field mapping. Without that, a layout change would fail every test.

**Replay (new build), options to choose between [open question §13]:**

1. **Emulation:** run the function in isolation (e.g. Unicorn or icicle-emu) with recorded memory, stubbing
   callees. Deterministic and safe to run on-prem in CI, but breaks on syscalls and heavy callees.
2. **Live in-process:** inject the harness into the new build and call the function with reconstructed args. Most
   faithful, but global state and side effects make it risky.
3. **Scenario trace diff:** run the same scripted scenario against both builds with logging detours and diff the
   call traces at the hook site. Easiest to build, and validates the repaired hook in place, but needs a
   reproducible scenario driver.

Recommendation: start with 3 (it exercises the actual repaired hook) and add 1 for leaf-ish functions.
**[Provisional]**

**Implemented (M4): scenario trace diff.** `corpus/hooks` has a Detours hook DLL and launcher
(`DetourCreateProcessWithDllExW`). The DLL reads the hook manifest and attaches a logging detour to each hook whose
locator is bound to the running build (by the .exe's SHA-256), so hooks sent to review are never applied. It
writes a JSON Lines trace (`TraceEvent` in the model): attach and skip records, then one `call` per call with
arguments and result by value (no pointers, which differ between runs), and `end` on a normal exit.
`pbeta trace-diff` compares two runs hook by hook. Given the repair report, it also checks that every hook repair
sent to review was held and every hook not applied was reported. Each hook is compared with the most recent run
that applied it (`--old` repeatable), so a hook repaired from an older build is checked against that build's run.
Not yet recorded: memory behind pointers, writes and callee sequences (the JSON test cases above), and comparison
rules (`compare.ignore`). Each detour logs what its prototype makes meaningful, written by hand.

**Privacy:** recorded memory can contain customer data. Recordings stay local by default, with redaction rules in
the harness config. **[Validate]** with target customers.

---

## 8. Where AI fits

AI is a **proposer**, never a judge.

| Use | Input | Output | Gate |
|---|---|---|---|
| Match leftovers | Pseudocode + features of unmatched old fn and top-k new candidates | `Candidate { source: ai, evidence: explanation }` | Same verification + policy as any candidate |
| Names, types, struct layouts | Pseudocode, usage sites | Proposed annotations | Human review; never feed matching without review |
| Behavioral diff summaries | Two traces, failing checks | Prose for the review queue | Informational only |
| Hook code and test inputs | Prototype diff, pseudocode | Proposed patch or test cases | Human review; tests must pass |

Design points:

- **Local first.** Talk to any OpenAI-compatible endpoint (llama.cpp server, Ollama, vLLM) configured on-prem.
  Remote providers are opt-in per project and logged. **[Provisional]**
- **Minimal context.** Send pseudocode and features, not the whole binary.
- **Untrusted output.** Binaries contain attacker-controllable strings, so prompt injection via a binary is
  plausible. Model output is parsed into strict schemas and never executed.
- **Measured.** AI proposals are tracked separately in corpus metrics (precision and acceptance rate). If they don't
  beat "send to review", they're switched off.

---

## 9. Data model and storage

### 9.1 Entities

```
Product ─┬─< Build (build_id = sha256, version, machine, pdb_guid/age, ingested_at)
         │      └─< AnalysisSnapshot (producer, producer_version, schema_version, features_version, blob)
         │             └─< Function (rva, size, name, name_source, hashes …)
         │
         ├─< MappingRun (from_build, to_build, engine_version, config_hash, started_at)
         │      ├─< Candidate (old_rva, new_rva, source, score)
         │      │     ├─< Evidence (kind, detail)
         │      │     └─< CheckResult (check, outcome, detail, check_version)
         │      └─< Mapping (old_rva, new_rva, decided_by, status, supersedes_id) ← accepted only
         │
         ├─< Hook (name) ─< HookRevision (build_id, locator, prototype, criticality, from_mapping_id)
         ├─< TestCase (hook, build_id, content hash) ─< TestRun (target_build, outcome, diff blob)
         ├─< ReviewItem (run, hook?, old_rva?, reason, status, assignee) ─< ReviewDecision (who, action, note)
         └─< AuditLog (actor, action, subject, at)
```

Principles:

- **Append-only.** Mappings are never edited. A correction creates a new mapping that supersedes the old one
  (`status = superseded | revoked`). The full history of any hook is reconstructible.
- **Reproducible.** Every run records engine version and config hash. Every check result records the check's
  version.
- **Transitive chains.** v1→v3 can be composed from v1→v2→v3, but a composed mapping is a *candidate*, not an
  accepted mapping. It still goes through verification against v3.
- **Human decisions are training data.** Review decisions become labeled ground truth for calibration (§10).
- **Review decisions (implemented in `JsonFileStore`).** An append-only decision log. *Accept* takes one of the
  item's verified candidates and records a mapping decided by the reviewer, keeping its verification report; a
  candidate that verification rejected needs an explicit `--force`, and a new function another live mapping
  already claims is refused (one-to-one). *Reject* records every listed candidate as "not the counterpart" and
  revokes any live mapping onto them. `repair --store` honors both: a reviewer's mapping resolves its hook, and a
  rejected pair is never used again, as the candidate or as an alternative. A rejected item stays resolved while
  a rerun offers nothing new and reopens when a new candidate appears. Not yet: revoking a reviewer's own
  mapping, and accepting a function that isn't among the candidates (it would need its own verification).

### 9.2 Storage backends **[Provisional]**

- Local and on-prem: **SQLite** file per project plus a content-addressed blob directory (analysis snapshots,
  traces, memory blobs). The skeleton uses a JSON file (`JsonFileStore`) behind the same `MappingStore` trait.
- Hosted: PostgreSQL + object storage, same schema.

### 9.3 SQL sketch

```sql
CREATE TABLE build (
  build_id TEXT PRIMARY KEY,            -- sha256
  product_id INTEGER NOT NULL,
  file_name TEXT, version TEXT, machine TEXT,
  pdb_guid TEXT, pdb_age INTEGER, ingested_at TEXT NOT NULL
);
CREATE TABLE mapping_run (
  run_id INTEGER PRIMARY KEY,
  from_build TEXT NOT NULL REFERENCES build, to_build TEXT NOT NULL REFERENCES build,
  engine_version TEXT NOT NULL, config_hash TEXT NOT NULL, started_at TEXT NOT NULL
);
CREATE TABLE candidate (
  candidate_id INTEGER PRIMARY KEY, run_id INTEGER NOT NULL REFERENCES mapping_run,
  old_rva INTEGER NOT NULL, new_rva INTEGER NOT NULL,
  source_kind TEXT NOT NULL, source_detail TEXT NOT NULL, score REAL NOT NULL,
  verdict TEXT NOT NULL                 -- accepted | needs_review | rejected
);
CREATE TABLE evidence (candidate_id INTEGER REFERENCES candidate, kind TEXT, detail TEXT);
CREATE TABLE check_result (candidate_id INTEGER REFERENCES candidate, check_name TEXT,
  check_version TEXT, outcome TEXT, detail TEXT);
CREATE TABLE mapping (
  mapping_id INTEGER PRIMARY KEY, candidate_id INTEGER NOT NULL REFERENCES candidate,
  from_build TEXT NOT NULL, to_build TEXT NOT NULL, old_rva INTEGER NOT NULL, new_rva INTEGER NOT NULL,
  decided_by TEXT NOT NULL,             -- engine | human:<id>
  status TEXT NOT NULL,                 -- accepted | superseded | revoked
  supersedes_id INTEGER REFERENCES mapping, created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX one_live_mapping ON mapping(from_build, to_build, old_rva) WHERE status = 'accepted';
CREATE TABLE review_item (
  review_id INTEGER PRIMARY KEY, run_id INTEGER REFERENCES mapping_run, hook TEXT, old_rva INTEGER,
  reason TEXT NOT NULL, status TEXT NOT NULL, assignee TEXT, created_at TEXT NOT NULL
);
CREATE TABLE review_decision (review_id INTEGER REFERENCES review_item, actor TEXT, action TEXT,
  chosen_candidate_id INTEGER, note TEXT, at TEXT);
```

### 9.4 Hosted service (later, proprietary)

Version history across teams, a shared signature database, and corpus hosting. It must also ship as an on-prem
deployable (container plus Postgres), since customers may require it. Shared signatures derived from third-party
binaries raise legal questions (§12). **[Validate]**

---

## 10. Validation: the ground-truth corpus

Because the code is AI-written, **this corpus and its metrics are the primary correctness gate**.

- **Ground truth:** pairs of builds with PDBs where the true mapping is known from symbol names. Candidates are
  open-source C/C++ projects built across real version tags with MSVC, with and without `/OPT:ICF`, `/LTCG`, PGO
  and different optimization levels (for example zlib, SQLite, libcurl, 7-Zip, Notepad++). Licenses and the
  build effort are **[Validate]**.
- **Matching runs on stripped copies**; PDB names are used only for scoring.
- **Metrics per pass and per verdict:** precision of *accepted* mappings, recall, review rate, and
  "silent wrong repair" count (an accepted wrong mapping on a hooked function).
- **Target:** zero silent wrong repairs on the corpus, with accepted-mapping precision ≥ 99.5% **[Guess]**, to be set
  from data.
- **CI gate:** any change to analysis, match or verify must not reduce accepted precision on the corpus.
  *Implemented for the purpose-built fixtures* (`pbeta-corpus score`, `corpus/fixtures/*/expected.toml`): zero
  wrong matches across every function in scope, and correct matches at or above a per-flag-set baseline that is
  raised as matching improves. Per-scenario targets are reported as met or not yet. *Real-world projects*
  (`corpus/projects/`), cloned and built in CI, 0 wrong in every variant (2026-11-06):

  | Project | Tags | /O2 correct | /Od correct |
  |---|---|---|---|
  | zlib | v1.2.13 → v1.3 → v1.3.1 | 69 of 69 | 159 of 163 |
  | Lua | v5.4.6 → v5.4.7 → v5.4.8 | 706–714 of ~735 | 1077–1085 of ~1095 |
  | zstd | v1.5.5 → v1.5.6 → v1.5.7 | 623–669 of ~729 | 1674–1731 of ~1879 |

  The scorecard reports precision and recall per pass. The second and third projects each found a real false
  positive in the strings pass that zlib couldn't: a literal moved into a new helper (Lua 5.4.8), and a body
  moved behind a wrapper (zstd 1.5.7). See §5.1 for the vetoes added. The similarity pass (§5.1 pass 6) then
  found a split zlib and Lua don't have (zstd 1.5.6's ZSTD_findFrameCompressedSize) and several undeclared
  renames.
- **Answer-key pitfalls:** joining by name must survive linkage changes (zlib 1.3.1 made minigzip's helpers
  `static`) and functions moving between object files (`truth.rs`, two-stage join). Renames can't be inferred
  safely, so they're declared per project in `recipe.psd1` after checking the sources (Lua 5.4.7 renamed six
  functions, zstd four so far). Otherwise correct matches get scored as wrong.
- **Hook corpus** (`corpus/hooks`, M4): a sample app in three versions, a Detours hook DLL, and eight hooks
  written against v1. `corpus/build-hooks.ps1 -Run` repairs them v1 → v2 → v3, checks every relocation against the
  linker maps, runs each version under its repaired hooks and diffs the traces; a deliberately swapped pair of
  hooks must be caught by both. CI gate: zero wrong relocations, identical traces, held hooks reported.

---

## 11. Interfaces, packaging, licensing

### 11.1 CLI (skeleton implements `match`, `repair`, `review list`)

```
pbeta analyze <binary> --out a.json                       # native PE x64 analyzer
pbeta match   --old a.json --new b.json [--json]
pbeta repair  --old a.json --new b.json --hooks hooks.toml [--earlier older.json]... [--out hooks.new.toml]
              [--new-binary b.exe] [--trial-out trial.toml] [--store path]
              [--old-trace a.jsonl... --new-trace b.jsonl] [--json]
pbeta trace-diff --old a.jsonl [--old older.jsonl]... --new b.jsonl --hooks hooks.new.toml [--repair report.json]
              [--json]
pbeta trace-diff --baseline a.jsonl --hooks hooks.toml   # every hook attached and fired
pbeta pattern <binary> --rva <rva>                        # shortest unique AOB pattern
pbeta header  --hooks a.toml [--hooks b.toml]... --out hooks.gen.h
pbeta review  list [--store path] [--all]
pbeta review  accept <id> --reviewer <name> [--candidate <rva>] [--force] [--note text] [--store path]
pbeta review  reject <id> --reviewer <name> [--note text] [--store path]
```

Exit codes: `0` everything resolved · `1` some hooks need review (`trace-diff`: a hook's behavior differs) ·
`2` error. That makes `pbeta repair` usable as a CI step that fails when a human is needed.

### 11.2 MCP server (step 2)

Tools: `list_builds`, `get_function`, `get_candidates`, `get_evidence`, `propose_mapping` (enters verification),
`run_verification`, `list_review_items`, `explain_review_item`. Agents **cannot** accept a mapping directly.
Accepting a review item requires a human decision through CLI or UI, or an explicit per-project setting that lets
policy-passing proposals through. **[Provisional]**

**Implemented (2026-11-07):** `pbeta-mcp --analysis <export>... [--store <path>]`, MCP over stdio (JSON-RPC 2.0,
one message per line; `initialize`, `ping`, `tools/list`, `tools/call`; protocol 2024-11-05 to 2025-06-18). Written
by hand rather than on an SDK: four methods, no async runtime.

- All tools above except `get_evidence`: `get_candidates` with an `rva` returns the candidate with its evidence
  and every check, which is what `get_evidence` would have.
- `propose_mapping` builds an AI candidate (`source: ai`, evidence kind `ai` set by the server, never by the
  model; it implies no check, so every check counts), verifies it with the engine's checks and policy
  (`Engine::verify_candidate`, this pair's match as neighbour context), and adds an `ai_proposal` review item.
  Whatever the verdict, it waits for a human. A pair a reviewer rejected is refused. Model name and rationale
  are length-bounded and stored as data.
- No tool decides an item or writes a mapping: the server's whole write surface is "add a review item"
  (`tools::ReviewQueue`). The per-project setting for letting policy-passing proposals through is not built.
- The store is reopened for every call, so decisions made with `pbeta review` meanwhile are seen and never
  overwritten.
- Results are JSON text. Strings from the binary are marked as data in tool descriptions and results (design
  §8: a binary can carry prompt injections).

REA (github.com/morluto/rea) is the reference for agent-facing tool ergonomics. Its interface has not been reviewed
yet. **[Validate]**

### 11.3 Ghidra extension (step 3)

Java extension (Ghidra's API is Java; the decompiler is a separate native process). Ghidra is Apache-2.0, which
fits an Apache-2.0 extension. Responsibilities:

- Export `AnalysisExport` JSON (also usable headless).
- Show mapping results, evidence and review items next to the listing and decompiler. Accept or reject from the UI.

Overlap: Ghidra already ships **Version Tracking** (function correlators across program versions) and **BSim**. The
extension should reuse or complement them, and the differentiation (hook repair, verification, CI, history) has to
be clear. **[Validate]**

### 11.4 IDA Pro plugin (step 5)

Via PyO3 bindings (`permanent-beta-py`) from IDAPython, or the same CLI/RPC route. Start after the repair pipeline is
validated on the corpus.

### 11.5 Licensing **[Provisional]**

| Component | License intent |
|---|---|
| Core crates, CLI, MCP server, Ghidra extension, harness | Open source. Apache-2.0 recommended for its patent grant and compatibility with Ghidra. |
| Signature database, test corpus (beyond the public ground-truth set), hosted history service | Proprietary, in **separate repositories**. |

The repo currently has a placeholder `LICENSE`. Until a license is chosen, nothing is licensed for reuse.
Still to decide: contributor terms (DCO vs CLA). A CLA keeps future relicensing options open but deters contributors.

---

## 12. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| **False-positive matches** (silent wrong repair) | Hook patches the wrong function: crashes, data corruption, and loss of trust. Worse than a broken hook. | Uniqueness rule, independent verification, criticality policy, behavioral gate for high-criticality hooks, corpus precision gate, default to review. |
| **Legal: reverse-engineering restrictions** | EULAs may prohibit reverse engineering. Statutory interoperability exceptions are narrow and vary by jurisdiction (e.g. US DMCA §1201(f), EU Software Directive Art. 6). | Not legal advice: get counsel before launch. Product terms require users to have the right to analyze and instrument the target. Position the product as interoperability and maintenance of software the customer owns or licenses. |
| **Legal: circumvention** | DRM, anti-tamper and anti-cheat circumvention is prohibited in many jurisdictions regardless of purpose. | Non-goal. No features for unpacking, defeating integrity checks or evading detection. Refuse to process known-protected targets (detect common protectors and stop). |
| **Dual use: cheat maintenance** | Keeping hooks working across game patches is exactly what cheat developers need. That's reputational, legal and platform risk (e.g. GitHub takedowns, anti-cheat vendor hostility). | Game segment = studios and anti-cheat teams analyzing their *own* builds. Authorization attestation, customer vetting for paid tiers, no public signature DB for third-party games. **[Validate]** whether the open-source core itself attracts this use and how to respond. |
| **Authorization** | Users analyzing third-party software without the right to. | Explicit authorization statement in docs and ToS. Hosted service records the claimed basis per product. On-prem can't be enforced technically. |
| **Shared signature database** | Distributing data derived from third-party copyrighted binaries. | Counsel review before building the paid DB. Prefer customer-private databases. **[Validate]** |
| **Compiler effects** | ICF folding, inlining, LTO, PGO and hot/cold splitting make "the same function" ill-defined. | Model fold, inline and split outcomes explicitly. Corpus builds cover these flags. Hookability check. |
| **Analysis gaps** | Leaf functions without `.pdata`, tail calls, jump tables. Ghidra and the native analyzer disagree on boundaries. | Hybrid analysis. Rust computes all hashes. Disagreement is reported, not silently resolved. |
| **Behavioral test flakiness** | Nondeterminism (time, threads, ASLR, global state) causes false failures. | Comparison rules per test (`compare.ignore`), multiple recordings, emulation for leaf functions, failures go to review. |
| **Recorded data is sensitive** | Traces capture customer data. | Local-only by default, redaction config, encrypted blob store option. |
| **AI-specific** | Hallucinated matches; prompt injection via binary strings; binaries leaving the premises. | Proposer-only role, same gates, strict output schemas, local models by default, remote opt-in with logging. |
| **AI-written codebase** | Plausible but wrong logic that compiles and passes weak tests. Slower owner review in Rust. | Corpus metrics gate in CI, small crates with enforced dependency rules, property tests for matchers, review checklist in `CLAUDE.md`. |
| **Market** | Ghidra Version Tracking, BinDiff and Diaphora are free. Willingness to pay for repair is unproven. | Validate with the target segments before the hosted service is built (§14). **[Validate]** |
| **Ecosystem maturity** | Rust PDB and MCP crates may have gaps. | Spike early (M1). Isolate behind the `analysis` and `mcp` crates. |

---

## 13. Open questions

**Scope**
1. Platforms: Windows PE only for v1, or ELF too? When? (Provisional: PE only.)
2. Architectures: x64 only, or x86 too (much of legacy software is 32-bit, with no `.pdata`)? ARM64?
3. Compilers: MSVC only, or also clang-cl and MinGW?
4. Hook libraries: Detours only, or MinHook, PolyHook 2, EasyHook, Frida, custom trampolines?
5. How do your *existing* hooks locate targets today: RVA tables, AOB patterns, symbols? This decides the first
   repair generator.
6. Will customer targets usually have PDBs? (Changes everything about type and struct repair.)

**Analysis and matching**
7. Hybrid analysis vs Ghidra-only for v1? Is a JVM on CI agents acceptable to target customers?
8. Reuse vs reimplement: BinDiff (open-sourced by Google in 2023; license **[Validate]**, believed Apache-2.0),
   Diaphora (believed AGPL-3.0 **[Validate]**, so its *code* can't be mixed into proprietary parts and maybe not
   into the Apache core), Ghidra Version Tracking and BSim (Apache-2.0). Options: reimplement the published ideas,
   import their outputs as candidate sources, or build on Ghidra VT.
9. Acceptance thresholds: set per customer, per hook, or globally from corpus calibration?

**Behavioral testing**
10. Test corpus representation: the JSON + content-addressed blobs proposed in §7.3, or a binary format
    (CBOR/protobuf) for large traces?
11. Recording mechanism: own Detours-based harness, Windows Time Travel Debugging (TTD) traces (redistribution and
    licensing **[Validate]**), or DynamoRIO / Frida instrumentation?
12. Replay mechanism: emulation, live in-process, scenario trace diff, or a combination (§7.3)?
13. Reuse existing behavioral-diffing research (e.g. blanket execution / BLEX-style approaches, differential
    tracing)? Needs a literature and tool survey. **[Validate]**

**Product and business**
14. Target-segment priority. Which segment do you interview first?
15. Hosted service: is it worth building if most paying customers require on-prem anyway?
16. Open-source license (Apache-2.0 vs MIT vs MPL-2.0) and contributor terms (DCO vs CLA).
17. Product name: decided as Permanent Beta (CLI `pbeta`). Trademark and crates.io availability not yet checked. **[Validate]**
18. Who reviews AI-written code besides you, and what review is required to merge (e.g. corpus gate + owner
    approval)?

---

## 14. Target users (to validate)

| Segment | Hypothesis | What would confirm it |
|---|---|---|
| Legacy-software teams | Pay for support. Long-lived instrumentation of vendor or legacy binaries with no source. **[Guess]** | 5+ interviews describing recurring hook breakage with a measurable cost. |
| Game studios and anti-cheat / security teams | Bigger budgets, on-prem required, analyze their own or customer builds. **[Guess]** | A design partner willing to share builds under NDA. |
| Mod communities | Large, low willingness to pay; free tier or donations. Highest dual-use and legal exposure. **[Guess]** | Mostly a reach channel. Validate that it doesn't dominate the project's reputation. |

---

## 15. Roadmap

| Milestone | Scope | Exit criteria |
|---|---|---|
| **M0 Skeleton** (this commit) | Crate boundaries, model types, 3 matching passes, 3 structural checks, policy, repair decisions, JSON store, CLI, demo fixtures | `cargo test` green; demo `repair` produces expected outcomes |
| **M1 Spikes** | Native PE x64 analyzer on one real binary; Ghidra headless exporter; `pdb` crate on MSVC PDBs | Both analyzers export the same functions for a sample binary (diff report) |
| **M2 Corpus** (done 2026-11-06) | Ground-truth corpus (3–5 projects × versions × flags), metrics harness, CI gate | Precision and recall reported per pass. Three projects (zlib, Lua, zstd) × 3 tags × 3 flag sets, plus the `basic` fixture |
| **M3 Matching depth** | Mnemonic hash, call-graph propagation, structural similarity, independence-aware policy, SQLite store | Measured improvement with no precision regression. Done 2026-11-07 apart from the SQLite store (deferred until history size or the hosted service needs it) |
| **M4 Repair loop** | Detours harness (record + scenario trace diff), AOB generator, offsets header, struct and prototype proposals | End-to-end repair of the sample app's hooks across 3 versions. Done 2026-11-07 (at /O2 7 of 8 hooks resolved v1 → v2 and 6 of 8 v2 → v3, at /Od 6 and 5, including a high-criticality hook and two hooks without structural evidence through their trial runs; 0 wrong; all applied hooks behave the same; review hooks repaired from their own build; patterns, offsets header and prototype proposals checked by the loop). Not built: the recording harness (per-call test cases) and struct-layout proposals |
| **M5 MCP + AI proposer** | `permanent-beta-mcp`, local-model proposer, review explanations | AI proposals measured separately on the corpus. MCP server and review explanations done 2026-11-07; the proposer and its corpus metrics not started |
| **M6 Ghidra extension** | Exporter + review UI | Usable by an external tester |
| Later | Hosted / on-prem history service, IDA plugin, ELF | Driven by §14 validation |
