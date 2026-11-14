# Permanent Beta — design document

Status: draft v0.1 · 2026-11-05 · Owner: Ryan Cole

## How to read this document

Every claim that isn't settled carries a tag:

| Tag | Meaning |
|---|---|
| **[Decided]** | Chosen by the owner; change only deliberately. |
| **[Provisional]** | A recommended default the skeleton is built on; cheap to change now, expensive later. |
| **[Guess]** | An estimate or belief that has not been checked. |
| **[Validate]** | Needs legal or technical validation before relying on it. |

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
| Open-source license | Apache-2.0 for everything in this repository | **[Decided]** 2026-11-08. See §11.5 |
| Development model | Code is AI-written; the owner reviews | **[Decided]** |

### 2.1 Why Rust (summary)

- **Compiler as reviewer.** The code is AI-written. Rust rejects data races, use-after-free, unhandled `match`
  arms and null misuse at build time, which gives an agent a strict compile-fix loop.
- **Embeddability.** The core can be exposed as a C ABI and as Python bindings (PyO3). That matters for an
  IDAPython plugin, Binary Ninja, and scripting users.
- **Distribution.** Small static binaries and straightforward cross-compilation suit on-prem and CI.
- **Ecosystem.** `object`/`pelite`/`goblin` (PE parsing), `iced-x86` (x86/x64 decoding), `pdb` (PDB reading),
  `rmcp` (official MCP SDK). `pdb` 0.8 reads every corpus PDB (procedures, types, address map; M1 spike,
  2026-11-07). `rmcp` wasn't needed: the MCP server is hand-written (§11.2).
- **Cost.** The owner reads C# natively and Rust less fluently, so review is slower. Mitigation: strict crate
  boundaries, small modules, and the corpus metrics gate (§10) as the main correctness signal.

C# was the close second: owner fluency, Iced/AsmResolver, strong Azure tooling.

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
| `permanent-beta-engine` | Orchestrates analysis output → match → verify → repair. | model, match, verify, repair, replay |
| `permanent-beta-replay` | Replays recorded per-call test cases (§7.3) on a new build by emulation: image mapping, memory placement, layout translation, comparison. Reports pass, fail or inconclusive per case; verification decides what that's worth. Emulation (icicle, MIT or Apache-2.0, executing Ghidra's x86-64 SLEIGH specification) is its optional `emulator` feature. Only engine and CLI may depend on it. | model |
| `permanent-beta-cli` | `pbeta` binary; argument parsing, I/O, exit codes. | engine, analysis, store, model, ai, replay |
| `permanent-beta-corpus` | Test tooling: linker map parser, ground-truth answer keys (`pbeta-corpus`). Nothing depends on it. | model |
| `permanent-beta-ai` | AI proposer (§8): shortlist, prompt, strict answer parsing, model backends, recordings. Emits `Candidate`s only. | model |
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
| `code_refs` | Code addresses outside the function taken by a RIP-relative `lea` (function pointers). Not hashed or matched on; the wrong-target control walks them with `callees` (§7.3). Optional; no schema bump. |
| `code_tables` (per build) | Runs of ≥ 2 consecutive relocated pointers to function starts in data: vtables and function tables. Optional; no schema bump. |
| `strings`, `constants`, `imports` | Referenced string literals, non-trivial immediates, imported APIs called. |
| `signature` | Calling convention, return type, parameters, typically from PDB or decompiler. |

Per build, **`features_version`** (2026-11-10) names the normalizer that computed the code features and its
version (`native-2`; `permanent_beta_analysis::native::FEATURES_VERSION`). Every native analysis has it, whatever
found the boundaries (native discovery or a Ghidra export: the features come from the same code). The engine
matches, repairs and verifies only between analyses that agree on it (`AnalysisExport::features_comparable`):
another version, or an analysis without one (written before it existed, or PDB-only), is refused with "analyze
both builds with the same pbeta", never matched on hashes that mean different things. An earlier build is checked
only if a hook is bound to it. The number is bumped on any change to what a feature covers; `schema_version` is
for the export's shape. Optional, so adding it didn't change the schema version.

Per-function pseudocode (from Ghidra, for review and AI) and the struct layouts signatures use (`types`, from a
PDB) are in the schema too.

### 4.2 Native analyzer (fast path, in Rust)

Target: PE x64. Implemented in `permanent-beta-analysis/src/native` (M1, first version):

- **Refuses protected and packed binaries** before reading any code (`native/protection.rs`, §12): a section
  with a common protector's or packer's default name (UPX, VMProtect, Themida/WinLicense, Enigma, ASPack, MPRESS,
  PECompact, Petite, NsPack), an entry point in a writable and executable section, or an executable section with
  no data in the file. One exception: the empty `.textbss` MSVC adds to incrementally linked images (the Debug
  default; Edit and Continue's room for recompiled code), accepted only as the first section, writable and
  executable, with no entry point, `.pdata` entry, export or code pointer in it. No override. Every path to an
  analysis, a pattern or a replay goes through it. None of the corpus's 106 binaries or 150 System32 executables
  is refused (2026-11-08). A protector that renames its sections and avoids both shapes isn't caught, and one
  that names an empty section `.textbss` avoids the third. Incremental images were checked on one program only
  (2026-11-10: two Debug builds of a 270-line app, 0 wrong matches without the PDB); the corpus has no
  incremental variant yet. **[Validate]**

- **Incremental linking tables** (`native/ilt.rs`, 2026-11-10). An `/INCREMENTAL` image starts its code with a
  table of 5-byte `jmp rel32` thunks, one per function, and every direct call goes through one. Recognized only
  at the start of an executable section's file data (after `int3` padding): at least 4 **[Guess]** consecutive
  slots, each jumping to code in the file outside the table. Each slot is its own function (`thunk_to` = its
  target; a slot nothing calls would otherwise run into the slot before), calls, `lea`s and table slots that
  name a thunk are recorded as its target's, thunks are never matched (`run_passes` drops them, so a thunk never
  competes with its own target as a "new wrapper", §5.1 pass 6), and a hook on a thunk is moved to its target
  and reported as relocated from the thunk. Release images have no table and analyze as before (`native-2` only
  bumps the version). Measured on CenterWindows Debug v1 → v2 without PDBs: 224 thunks; hooks resolved 6/8 → 7/8,
  the last an edited function with one correct similarity candidate, in review for evidence as designed;
  0 wrong matches. **[Validate]** on the corpus once it has an incremental variant.

- Parse headers and sections with `object`; `.pdata` and the import table are parsed by hand from section bytes.
- Function starts: non-chained `.pdata` entries, the entry point, exports and code pointers stored in data
  (`DIR64` base relocations in non-executable sections whose value points into code outside any `.pdata` range:
  function tables, callbacks in initialized structs; §4.4), then direct call/jump targets found by disassembly,
  iterated to a fixpoint. When nothing more is found, code on a 16-byte boundary right after `int3` padding is a
  start too (dead code; in a gap no function covers, or inside a function without `.pdata` after an instruction
  that doesn't fall through, and only if no branch in that function targets it), and the fixpoint resumes. This matters more than expected: at `/O2`, MSVC emits no `.pdata` for
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

Known gaps: PDB names and signatures only when asked for (§4.4), dead code is found only when it follows `int3`
padding on a 16-byte boundary (true for all of it on the corpus), and `edges` isn't computed. Vtables are found through base relocations
like any function table (checked on TinyXML-2, the corpus's C++ project), and recorded as `code_tables`: runs of ≥ 2
consecutive slots that each point at a function start. MSVC's RTTI locator pointer, which points into data, sits
right before each vtable, so neighbouring vtables stay apart. **[Validate]** the discovery approach on real targets with indirect calls and jump tables.

What it won't do: decompilation or type recovery. That comes from the Ghidra export.

### 4.3 Ghidra headless export (deep path)

A Ghidra script or extension, run through `analyzeHeadless`, writes `AnalysisExport` JSON including decompiler
pseudocode and recovered types. This makes the deep path free and scriptable in CI, at the cost of a JVM and a
Ghidra install on the build agent.

The two analyzers must agree on function identity (RVA) and on any hash they both emit. The cheapest rule: hashes
are always computed by the Rust normalizer, even for Ghidra exports (Ghidra provides boundaries and bytes; Rust
hashes). **[Provisional]**

**Implemented (M1, 2026-11-07), Ghidra 12.2:** `integrations/ghidra/scripts/` (README there). `DisablePdb.java`
turns the PDB analyzers off (Ghidra finds a PDB through the debug directory's path even for a copied .exe), and
`ExportFunctions.java` writes each function's entry, body ranges, name and signature with Ghidra's source for each,
and optionally pseudocode. `pbeta analyze --functions-from` (`permanent-beta-analysis::ghidra`) computes every
feature natively from those boundaries, after cutting Ghidra's ranges at the binary's `.pdata` boundaries (Ghidra
merges touching ranges, the native analyzer keeps chained fragments as segments, and the hash records segments).
A fixture test gives the Ghidra path the native bodies and requires identical hashes for every function. Ghidra's
names are never used: `DEFAULT` names are placeholders, `ANALYSIS` names are Function ID guesses, and the name pass
trusts any name. Its signatures are used only when not inferred and not on a guessed name (library prototypes on
import thunks qualify; `__security_check_cookie`, named by Function ID, doesn't). Pseudocode is stored
(`FunctionFeatures::pseudocode`, optional, so the schema version didn't change) and never matched on. Results: §4.4.

### 4.4 PDB names and signatures; the M1 diff report

`pbeta analyze --pdb` (`permanent-beta-analysis::symbols`, `pdb` crate 0.8) adds names (`name_source: pdb`) and
signatures to the native analysis by entry RVA: procedure symbols from every module, with return and parameter
types from the type stream. Parameter names aren't read, so a renamed parameter isn't a changed signature. The PDB
is refused unless its GUID and age match the executable's debug directory. Export names are kept. An entry more
than one procedure claims (ICF folding) gets no name and no signature. Boundaries and hashes stay the native
analyzer's. The corpus gate keeps scoring stripped analyses; the answer key comes from linker maps.

`pbeta analysis-diff a.json b.json` compares two analyses of one build: entries only one side has (with the other
side's function covering it, if any), and size, hash and name disagreements. It reports and never resolves.
`--pdb-functions` writes the PDB's procedures as an analysis to diff against.

**First diff report (2026-11-07, native vs PDB, newest tag of every corpus variant):**

| Variant | PDB entries | Agree | Native only | PDB only | Size differs |
|---|---|---|---|---|---|
| zlib /O2, /O2+ICF, /Od | 122, 112, 217 | 120, 112, 211 | 29, 29, 32 | 1, 0, 5 | 1, 0, 1 |
| Lua /O2, /O2+ICF, /Od | 788, 778, 1149 | 776, 768, 1146 | 55, 55, 50 | 11, 10, 2 | 1, 0, 1 |
| zstd /O2, /O2+ICF, /Od | 794, 751, 1992 | 786, 746, 1981 | 36, 36, 39 | 5, 4, 8 | 3, 1, 3 |

No name disagreement anywhere (the PDB side has no hashes, so hashes aren't compared here; that waits for the
Ghidra export). The fixture test `pdb_names_agree_with_the_answer_key` checks PDB names against the linker map at
every answer-key address, and that another build's PDB is refused. What differs:

- **Native only:** import thunks (6-byte `jmp [iat]`, linker-generated, no procedure symbol), one 12-byte CRT
  stub, and in Lua /O2 three 1-byte starts just past a function's end (false starts, not yet explained).
- **PDB only:** functions without `.pdata` reached only through data or not at all: function tables (Lua's
  `arith_*`, `str_find`, `str_match`; zstd's `ZSTD_compressBlock_fast*`/`doubleFast*` block-compressor table),
  dead code (zlib's `compressBound`, `get_crc_table`, `zlibVersion`; zstd /Od's `*_versionNumber`), and the CRT's
  `_guard_check_icall_nop`.
- **Absorbed functions (the worst case):** a missed function with no `.pdata` is taken into the previous one,
  which then runs to the next known start. zstd /O2's `ZSTD_writeLastEmptyBlock` is 147 bytes natively and 29 in
  the PDB; it swallows `ZSTD_compressBlock_doubleFast` and `_dictMatchState`. Its hashes and features then cover
  three functions. A 3-byte CRT stub (`__scrt_stub_for_acrt_uninitialize`) runs to 32 bytes the same way in most
variants.

**Fixed the same day: function starts from base relocations.** Every `DIR64` base relocation in a data section
whose value points into code outside a `.pdata` range is a function start (§4.2). Pointers stored in code
(immediates) and pointers into a `.pdata` function are not. Diff report after it:

| Variant | PDB only (before → after) | Agree (before → after) | Size differs (before → after) |
|---|---|---|---|
| zlib /O2, /O2+ICF, /Od | 1, 0, 5 → 0, 0, 4 | 120, 112, 211 → 121, 112, 212 | 1, 0, 1 → 1, 0, 1 |
| Lua /O2, /O2+ICF, /Od | 11, 10, 2 → 0, 0, 1 | 776, 768, 1146 → 787, 778, 1147 | 1, 0, 1 → 1, 0, 1 |
| zstd /O2, /O2+ICF, /Od | 5, 4, 8 → 0, 0, 7 | 786, 746, 1981 → 793, 751, 1982 | 3, 1, 3 → 1, 0, 3 |

Every /O2 build now finds every function the PDB lists, and no function is absorbed at /O2. What's left is dead
code at /Od (zlib's `compressBound`, `get_crc_table`, `gz_intmax`, `zlibVersion`; Lua's `lua_setallocf`; zstd's
`*_versionNumber`, `*_compressBound`, `ZSTD_defaultCLevel`, `ZSTD_getDictID_fromCDict`), two of which zstd /Od
still absorbs into the previous function, and the CRT stub. Nothing references those (found later from
layout; see "function starts after padding" below). Corpus: 0 wrong; Lua /O2 and /O2+ICF +10 correct per variant (all ten
previously unmatched), zstd /O2 +3 to +4; zlib and every /Od variant unchanged. The fixture scorecard and the
hook loop are unchanged.

**Native vs Ghidra (2026-11-07, `corpus/ghidra-diff.ps1`, Ghidra 12.2 with its PDB analyzers off), judged by the
PDB.** Same-size functions never differ in hash, so every disagreement is about boundaries:

| Build | Functions (native, Ghidra) | Agree | In the PDB, only native found | In the PDB, only Ghidra found | Size differs: native right / Ghidra right / no PDB entry | Ghidra time |
|---|---|---|---|---|---|---|
| zlib /O2 | 151, 149 | 135 | 1 | 0 | 12 / 1 / 1 | 15 s |
| zlib /O2+ICF | 141, 140 | 126 | 0 | 0 | 12 / 0 / 2 | 12 s |
| zlib /Od | 245, 243 | 223 | 1 | 0 | 18 / 1 / 1 | 16 s |
| Lua /O2 | 843, 820 | 656 | 19 | 0 | 162 / 1 / 1 | 18 s |
| Lua /O2+ICF | 833, 811 | 647 | 18 | 0 | 162 / 0 / 2 | 19 s |
| Lua /Od | 1198, 1194 | 991 | 3 | 0 | 201 / 1 / 1 | 30 s |
| zstd /O2 | 830, 822 | 714 | 7 | 0 | 106 / 1 / 1 | 36 s |
| zstd /O2+ICF | 787, 780 | 672 | 6 | 0 | 106 / 0 / 2 | 36 s |
| zstd /Od | 2024, 2025 | 1830 | 1 | 3 | 188 / 3 / 1 | 46 s |

- **Ghidra's bodies come up short.** Of 975 size disagreements with a PDB entry, the native size is the PDB's in 967
  and Ghidra's in 8. Some are a padding byte left out between two parts (`lua_error`: 48 vs 49), others whole tails
  (`lua_gc`: 644 vs 692, zstd's `ERR_getErrorString`: 446 vs 717). The cause isn't confirmed; likely code
  reached only through jump tables, or after a call Ghidra takes as non-returning.
- **Functions in data tables:** Ghidra misses the ones base relocations find (Lua's `arith_*`, `f_call`,
  `dothecall`, ...; zstd's block-compressor table), and the CRT's `_matherr`.
- **Dead code:** Ghidra finds three unreferenced zstd /Od functions native missed (`FSE_compressBound`,
  `HUF_compressBound`, `ZSTD_getDictID_fromCDict`), and gets the size right for two functions native absorbed
  code into (`BIT_getLowerBits`, `ZSTD_maxCLevel`) plus the CRT stub. It doesn't find zlib /Od's or Lua /Od's dead
  code either. (Since fixed natively; see below.)
- **Native only, not in the PDB:** the 6-byte import thunk Ghidra doesn't list as a function, and Lua /O2's three
  1-byte starts (unexplained, see above).

**Fixed the same day: function starts after padding.** All 12 unreferenced functions the PDB listed and native
missed sat on a 16-byte boundary right after `int3` padding: 10 in gaps between functions, 2 inside a function
without `.pdata` that had absorbed them. Once nothing else is found, such code is a start (§4.2), unless a branch
in the function it sits in targets it (code after a call that doesn't return), and functions with `.pdata` are
never split. Native vs PDB after it: every build finds every function the PDB lists, no native-only start was
added, and the only size disagreement left is the CRT's 3-byte `__scrt_stub_for_acrt_uninitialize` (32 bytes
natively). Corpus: 0 wrong; /Od +1 to +6 correct per variant (zlib 161 and 160, Lua 1087 and 1093, zstd 1705 and
1744; zstd accepts 2 fewer per variant, now in review); /O2, the fixture and the hook loop unchanged.

**Decision (answers §13 question 7 for v1): the native analyzer stays the source of boundaries.** On this
corpus it is right far more often than Ghidra, needs no JVM, and is seconds instead of up to 46 s per build.
Ghidra's value is what the native analyzer can't produce: pseudocode now, types later (struct layouts, §7.2). Its
boundaries are a cross-check through `pbeta analysis-diff`, not an input. **[Provisional]**: one compiler and
three C projects.

---

## 5. Matching

Inspired by the multi-pass approach of BinDiff and Diaphora: run high-confidence, low-recall passes first, then
progressively weaker ones restricted to still-unmatched functions, and use matched pairs as anchors for
neighbourhood passes.

### 5.1 Passes (in order) **[Provisional]**

| # | Pass | Key | Notes |
|---|---|---|---|
| 1 | Symbol name | Export or PDB name unique on both sides | Implemented in the skeleton. |
| 2 | Normalized hash | `normalized_hash` unique on both sides | Implemented. **Vetoed** like the strings pass when the old function's matched callers don't call the new one (yaml-cpp 0.9.0 replaced `std::string` iterator helpers with byte-identical `std::array` ones). When the code has several copies in either build, the last copies left are paired only with an agreeing matched neighbour, as in the mnemonic pass: uniqueness by elimination isn't identity (an 11-byte helper with 66 copies per build was paired wrongly). Costs 0–8 correct per corpus variant, now review suggestions. |
| 3 | Unique string set | Sorted referenced strings, unique | Implemented. **Vetoed** when other evidence contradicts it: different inferred register-argument counts, or the old function has matched callers and none of their counterparts calls the new function. Vetoes are rechecked against the final matches (`Matcher::contradiction`): a contradicted pair is banned, all passes rerun without it, and it stays as a review suggestion. Found by Lua 5.4.8 (a literal moved into a new helper) and zstd 1.5.7 (a body moved behind a wrapper). |
| 4 | Mnemonic hash | `mnemonic_hash` unique on both sides, gated | Implemented 2026-11-07 (`MnemonicHashMatcher`): the same instruction sequence with changed operands (a constant, stack or field offset). On tiny functions two unrelated ones can each have a unique sequence, so uniqueness alone isn't enough: both functions must be ≥ 32 bytes **[Guess]**, and a matched neighbour must agree (they call the same matched function, or a matched caller's counterpart calls the new one; recorded as callee or call-sequence evidence, so that check doesn't count again). Without an anchor it's a review suggestion. Vetoed like the strings pass (argument registers, disagreeing callers). On the corpus: 0 wrong; zstd +3 to +23 correct per variant and ~60 more accepted per /O2 variant (taken over from similarity, which only reaches review); Lua a few moved from review to accepted. |
| 5a | Matched callees | `normalized_hash` + callee list mapped through earlier matches, unique on both sides | Implemented (`MatchedCalleesMatcher`). Normalization masks call targets, so code differing only in what it calls is hash-ambiguous (zlib's `adler32`/`crc32` `jmp` wrappers). Every callee must already be matched; no callees means no key. On zlib: /O2 61→63, /Od 150→154 and 152→156, 0 wrong. |
| 5 | Call-graph propagation | Callees of matched callers | Implemented (`CallSequenceMatcher`), iterated to fixpoint. **Candidate** only when a callee's code occurs exactly once among the caller's unmatched callees in both builds, which doesn't depend on call order. Pairing by call *position* (or repeated identical code by order) is a **review suggestion** (an ambiguity), never a candidate: MSVC reorders calls to side-effect-free functions, and in the `basic` fixture that paired a deleted function with an edited one. The corpus gate caught it. |
| 5b | Table slot | Same slot in corresponding code-pointer tables (vtables), identical normalized code | Implemented 2026-11-07 (`TableSlotMatcher`) for C++ virtuals: tiny overrides are byte-identical across classes (TinyXML-2's `ToElement`, `ToText`, ... returning null), so the hash pass finds them ambiguous and nothing calls them. Two tables correspond when they're the same length, at least 1 slot holds functions already matched to each other (**calibrated** 2026-11-08 over three C++ projects: 0 and 1 give the same results, 2 costs 108 correct, 3 costs 198, 0 wrong throughout), no slot contradicts (an old function matched elsewhere, or a new one claimed while the old one isn't), and the correspondence is unique on both sides. Slot pairs are candidates only with identical normalized code; a slot whose code differs is a review suggestion (a virtual replaced at the same position). A function paired differently by two tables gets nothing; rechecked against the final matches. Table position implies no verification check, so most of its matches go to review. |
| 6 | Structural similarity | Weighted feature similarity among anchored pairs, best-vs-second-best margin on both sides | Implemented (`SimilarityMatcher`), a **weak** pass: it runs only once every stronger pass has stopped. Candidates share an anchor (matched callee or caller, string, constant, import). Score: weighted mean of code (mnemonic counts), shape (blocks, edges), size, matched callees and callers, strings, constants, imports. Candidate only if mutual best, score ≥ 0.75 and ≥ 0.05 ahead of the runner-up on both sides, size ≥ 16 bytes (**calibrated** 2026-11-07 with `pbeta-corpus sweep` over 21 corpus variants: wrong matches appear at score 0.70 and none at ≥ 0.75 for any margin 0.02–0.2 or size 8–32; margin 0.1 → 0.05 added 108 correct review candidates. Weights and the bucket limit are still **[Guess]**. Recheck with the sweep whenever the corpus grows). Vetoed by disagreeing matched callers; a new function called by a smaller unmatched new function whose other callees are all matched gives an ambiguity (body moved behind a wrapper: zstd 1.5.6; yaml-cpp 0.9.0 at /Od, where the wrapper also calls `data()` and `size()`), unless ≥ 2 of the old function's matched callers still call the new one directly and none calls the wrapper (**calibrated** 2026-11-08: 1 adds 27 correct but lets zstd 1.5.6's `BIT_reloadDStreamFast` through as a wrong match, 3 costs 12). An unmatched caller of the old function scoring within 0.1 **[Guess]** of the best also gives an ambiguity: the old code may have been inlined into it (TinyXML-2's `TestUtil::Push` under /LTCG). Its evidence implies the neighbour, string, constant, import and size checks, so its matches go to review. On the corpus: 0 wrong; zstd /O2 433–511 → 623–669 correct, Lua /O2 642–667 → 706–714. |
| 7 | AI proposer | Feature comparison for leftovers | Not a pass: run separately (`pbeta propose`, §8), and its candidates only go to review. |

### 5.2 Invariants

- **One-to-one.** A function on either side is claimed at most once. The first (strongest) pass wins.
- **Uniqueness, not best score.** A key that maps to more than one function on either side produces *no* candidate.
  Ambiguity is a review item, not a coin toss.
- **Evidence is mandatory.** Every candidate records which pass produced it and why.
- **Many-to-one is real.** MSVC `/OPT:ICF` folds identical functions, inlining and function splitting change
  boundaries. The model must eventually express "old function folded into X" and "old function inlined into its
  callers" as outcomes, not just as failures to match. **[Validate]** how often hooked functions are affected.
  Under /LTCG and PGO the two can swap: the compiler keeps a different one of two related functions out of line in
  each build, and the survivor can look exactly like the old function (zstd 1.5.7's `_wExtLitBuffer`: same callers
  and callee, different parameters). Without signatures matching can't tell; zstd's /LTCG and PGO variants are
  not scored for that reason (docs/STATUS.md).

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
| Parameter count | Equal when both signatures are known (PDB or Ghidra). A variadic or unprototyped (K&R) function has no known count, so no signature | Implemented; measured 2026-11-09 with PDB signatures only (`pbeta-corpus score --pdb-signatures`: no names, types or globals) on the 60 gated corpus variants and `basic`: correct and wrong counts unchanged (31,096 correct, 0 wrong); accepted 25,211 → 30,503 (it's an independent pass); 49 correct pairs fail it, each a real signature change sent to review (`basic` S4, Lua `funcargs`, yaml-cpp's `std::string&` → `const char*, size_t`, zstd's added or removed flags); never passes a wrong pair there. On zstd's skipped /LTCG and PGO variants it fails 2 of the 3 known wrong matches. The measurement caught K&R definitions (zlib 1.2.13) read as one parameter of unknown type, fixed |
| Inferred register arguments | Same number of Win64 argument registers (rcx/rdx/r8/r9, xmm0–3) read before written, up to the first call. Works without symbols. A lower bound, so sanity-only: a mismatch sends to review (it caught fixture S4's added parameter), a match never counts | Implemented |
| String references | Jaccard similarity ≥ 0.5 **[Guess]** at the threshold | Implemented |
| Size ratio | New/old size within 0.5–2.0; fail outside 0.25–4.0 **[Guess]**. Sanity check only: can fail a candidate, never counts as support | Implemented |
| Callers / callees | Of the old function's neighbours that have a candidate, ≥ 50% land on the new function's neighbours; fail below that with ≥ 2 mapped neighbours **[Guess]**. Uses this run's candidates, so it measures consistency, not truth | Implemented |
| Code tables | The old function's slot in a code-pointer table (vtable) holds the new function in the corresponding new table: same length, ≥ 1 other slot agreeing through this run's candidates, none disagreeing. Fails when a table corresponding with ≥ 2 agreeing slots holds another function there and no pair supports it **[Guess]**: it never fails on the corpus at 1, 2 or 3 (swept 2026-11-08), so the corpus can't calibrate it. Independent of the code hash, so it confirms hash-matched virtuals that have no callers: on the corpus +7 to +28 accepted per TinyXML-2 and zstd variant, 0 wrong. Implied by table-slot evidence. Never failed on the corpus | Implemented |
| Constants, imports | Jaccard ≥ 0.5 passes; < 0.2 with ≥ 2 items on each side fails **[Guess]**. Constants are implied by a hash match, imports are not (IAT operands are masked). On zlib /Od this raised accepted matches from 130 to 133 | Implemented |
| Calling convention / prologue | Compatible with the hook's prototype and trampoline needs (e.g. enough bytes before a branch target for Detours) | Implemented in repair (2026-11-08), like hookability: trampoline needs are the entry hazards (patch length, a branch into the patched bytes, a thunk); the prototype must fit the new function's inferred register arguments: no register argument read that the prototype doesn't declare, none read in the other register class (an `int` in rdx where the function reads xmm1). Only what the old function didn't already do counts, and fewer arguments read than declared never does (the inference is a lower bound). A misfit sends the hook to review as `signature_changed`. Hook loop unchanged |
| Hookability | Moved to repair (§7.2): it's a property of the hook target, not evidence of identity, so it doesn't affect matching scores | Implemented in repair |

**Independence (implemented):** a check that measures what the candidate's evidence already established adds
nothing, so its pass doesn't count (`CheckResult.counted = false`, visible to reviewers). Implied checks per
evidence kind (`permanent_beta_verify::implied_checks`): normalized hash → string refs, size, constants and inferred
args; strings → string refs; call sequence → callers; matched callees → callees; table slot → code tables; similarity → string refs, size,
callers, callees, constants and imports. Failures always count, so evidence can't excuse a failing check.

### 6.2 Behavioral checks

A `BehavioralRunner` replays recorded tests (§7.3) against the new build and returns pass, fail or inconclusive.
The default is `NoBehavioralCorpus`, which always returns inconclusive. `TraceDiffRunner` (implemented, M4) judges a
candidate from two scenario traces: the calls a detour at the old RVA saw in the old run must equal the calls a
detour at the candidate's RVA saw in the new run. Traces are matched to builds by their `start` event, so the old
trace is always a run of the candidate's own old build (an RVA means nothing in another build). It's inconclusive
when there's no trace of either build or either side has no hook there, and fails on any difference or a crashed
run. `pbeta repair --old-trace ... --new-trace` uses it; the new trace is usually a trial run (§7.2), so review
candidates can be judged too.

`RecordedCasesRunner` (implemented 2026-11-08, in the engine) replays the per-call test cases recorded at the
candidate's old RVA in its old build (§7.3) on the candidate in the new binary, by emulation: pass if every case that
can be replayed matches and at least one can, fail if any differs, inconclusive if none can (or there are none).
`pbeta repair --cases <recording> --new-binary` uses it; with traces as well, both run and a failure of either fails
(`AllOf`). How a behavioral pass counts toward acceptance is part of the policy (§6.3).

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
detour      = "Hook_SaveDocument"        # symbol in the hook DLL; for the hook host, its action (§7.2)
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
- **Hook host** (implemented 2026-11-13, `harness/host`): one Detours DLL for any x64 program, so a user writes no
  hook plumbing. `pbeta host-config --hooks <manifest>... [--analysis <a>...] --out pbeta-host.toml` lists every
  hook for the build its locator is bound to (a hook in review stays on its verified build), with its RVA, pattern,
  action and argument slots (from the manifest's prototype, or the build's PDB signature). The host hashes the
  executable, attaches only that build's hooks, each after its pattern matches, and does nothing in a build the
  config doesn't list. The action is the manifest's `detour`: `log`, `skip` and `return <n>` run through one
  generic thunk (no code per prototype; up to 12 parameters, not variadic), and `<file.dll>!<export>` attaches a
  handler the user writes (`PBETA_HOOK` in `pbeta_handler.h`: the body only, no Detours, no addresses). Checked on
  CenterWindows' two Debug builds: every action, a handler that calls through, a handler DLL without the export
  (refused), and an executable the config doesn't list (no hooks).
- **Prototype adaptation** (implemented for added register parameters): when a candidate reads more Win64
  argument registers than the hook's prototype declares (and the old function didn't), the review item gets a
  proposed prototype, with each added parameter typed from its register class (`intptr_t` or `double`), and a C++
  shim: a new detour that stashes the added arguments and calls the existing detour, whose call to the original
  forwards them. Removed or reordered parameters aren't proposed from registers (inferred arguments are a lower
  bound). **With both builds' PDB signatures** (2026-11-08) the change is known exactly and proposed first:
  parameters added (stack ones included), removed, reordered and retyped, and a changed return type. Parameters
  correspond by name; an unnamed or repeated name, or a hook prototype without the old signature's parameter
  count, gives no proposal. The shim's new detour takes the new parameters and calls the existing detour with the
  old ones by name (a removed one gets a value-initialized `{}`, a retyped one a cast, both flagged in the basis);
  the existing detour's call to the original forwards the new parameters in the new order. A changed return type
  gets the prototype but no shim. A generated shim with every kind of change compiles with `cl /W4 /WX`. The
  detour body is never rewritten automatically.
- **Struct layout adaptation** (implemented 2026-11-07, PDB types): `pbeta analyze --pdb` records the layouts
  (size; each field's name, offset, size, type and bitfield position) of the structs, classes and unions that
  function signatures use, and of the structs inside them by value, as the export's `types`. When a struct the
  hook's prototype names (`const Config* c` → `Config`) differs between the builds, the hook goes to review
  (`struct_layout_changed`; a verified match stays the item's candidate, no mapping is recorded) with what
  changed, the new C definition with offsets, and `offsetof` constants with `static_assert`s for the detour.
- **Struct changes without a PDB** (2026-11-08, inferred): the native analyzer records each function's accesses
  through its pointer arguments (`arg_accesses`: argument slot, offset, size, read or write; the argument followed
  through register copies, callee-saved registers across calls and its stack home slot, a heuristic linear scan).
  For each struct-pointer parameter of the hook's prototype that the PDBs don't lay out in both builds, the old
  function's and the candidate's (the verified one, or the only one in review: a moved field is why its code
  differs) accesses are aligned in order on size and read/write, and an offset whose aligned accesses all moved to
  one new offset is proposed: `offset 0x4 -> 0x8 (4 bytes, 1 access)`, with `basis` saying it's a guess. No
  proposal when an offset's accesses disagree, when offsets don't keep their order (an inserted or removed field
  shifts the ones after it; a crossing is reordered code), when under half of either side aligns **[Guess]**, or
  when nothing moved. Like the PDB proposal it sends the hook to review (`struct_layout_changed`). On the `basic`
  fixture's S5 without its PDB it proposes `0x4 -> 0x8` at /O2, /O2+ICF, /Od and /LTCG, the PDB's answer.
  Measured on zlib, Lua and zstd (o2, od) with the PDB types hidden and the PDBs judging
  (`crates/permanent-beta-corpus/tests/struct_inference.rs`): 3987 function pairs with a struct-pointer parameter;
  255 proposals, 249 on structs whose layout did change (6 false alarms, 0.15% of pairs); moves 1087 right, 11
  wrong (single accesses paired with another field), 16 on renamed fields that matching by name can't judge. The
  test is a baseline gate (at most 11 wrong).
  Fields correspond **by name**, the PDB being the evidence: a renamed field shows as removed plus added, never as
  a guess. A hook already in review gets the proposal attached. No layouts on both sides (no PDB) means no
  proposal. **[Validate]** feasibility without PDBs (Ghidra types).

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
Each detour logs what its prototype makes meaningful, written by hand.

**Implemented (2026-11-08): recorded test cases, replayed by emulation (option 1).**

- *Record spec* (`pbeta harness-spec --hooks --analysis`): per hook bound to the build, from its prototype and the
  build's PDB struct layouts (`pbeta analyze --pdb`): each parameter's Win64 slot (`rcx`…`r9`, `xmm0`–`xmm3`,
  `stack+0x28`…), its value class and width (`int:4`, `float:8`, `pointer:8`), and what a pointer points to: a
  struct with a layout (`fixed`, that many bytes), a scalar or a pointer (`int*`, `T**`: `array`, the heap block
  holding it, else its own bytes), `char*` (`cstring`), a byte pointer directly followed
  by an integer named like a length (`sized`, **[Guess]**), or nothing. Per hook also the globals to capture
  (`[[hook.global]]`): those the function or anything it calls, directly or indirectly, refers to. They come from
  the analysis: `data_refs` (each function's RIP-relative references into writable sections, native) inside a
  PDB data symbol (`globals`, with `--pdb`; a static local is named `procedure::name`, a name two variables share
  is left out). `__security_cookie` isn't captured. TOML, meant to be read and edited.
- *Recorder* (the hook DLL's record mode, `PBETA_RECORD` + `PBETA_SPEC`): a generic MASM thunk
  (`corpus/hooks/hookdll/record_thunk.asm`) saves the argument registers and up to 8 stack arguments, the DLL
  captures each pointer's memory (unreadable memory is left out, never a crash), calls the original, captures the
  same memory again and writes one JSON case per distinct call, at most `max_cases` (32, **[Guess]**) per hook.
  The format is `permanent_beta_model::TestCase`: entry registers and stack, `regions` (address, size, layout,
  `before` and `after` as `sha256:` blobs), `globals` (name, old RVA, before and after), the import calls made
  during the call (`imports`), and `observed` rax and xmm0. A recording directory holds the spec, `cases/<hook>/`
  and `blobs/`.
- *Import calls* (recorder): every named import of the app's own import address table points at an import thunk
  (64, **[Guess]**). A call made while a recorded call runs on the same thread (nested hooked calls included) is
  recorded into each of them: the argument registers and 8 stack arguments, what it returned, and for each
  argument that points to readable memory up to 512 bytes before and after, and inside those, for each word that
  points to readable memory, up to 256 bytes before (the strings a `va_list` points to; sizes **[Guess]**). The DLL's
  own CRT calls go through its own table. A case is marked `imports_recorded` only when every import was patched
  (none by ordinal, no more than the thunks).
- *Replay* (`permanent-beta-replay`, icicle): the new image mapped clear of the recorded memory (rebased if
  needed), its IAT pointing at traps, the recorded memory at its recorded addresses, a fresh stack whose return
  address is a trap. The candidate runs until it returns; the return value (its declared width: an `int` is eax)
  and every region's and global's bytes after the call must equal the recording. Recorded globals are placed at
  the new build's RVAs for their names (from its analysis with `--pdb`; a missing name or another size is
  inconclusive). With `imports_recorded`, an import call is answered from the recording, in order, for the imports
  replay models (`imports.rs`): `__acrt_iob_func`, `__stdio_common_vfprintf` and `__stdio_common_vsprintf` (the
  UCRT's `printf` and `snprintf`). The stand-in checks the candidate passes the same inputs (options, stream,
  count, the format string, and each conversion by type: integers at their width, doubles, `%s` by content), makes
  the recorded writes (`snprintf`'s buffer) and returns the recorded result. Different inputs are inconclusive, not
  a fail: the import may be called by a callee that changed while the hooked function didn't (the hook app's v2
  `log_event`). **Inconclusive, never a pass:** a call into an import with no stand-in (or a call out of the
  recorded order, or fewer or more calls than recorded), a read of a writable image section outside the recorded
  globals (mutable globals the recording didn't capture; `__security_cookie` excepted, it's given MSVC's default),
  a write outside the stack, the recorded memory and the globals, a read of memory nobody
  recorded (except the rest of a 32-byte block that holds recorded bytes, for vectorized over-reads,
  **[Guess]**), an interrupt or `syscall`, no return within 10M instructions, an unknown return type, nothing to
  compare, or a pointer returned outside the recorded memory.
- *Layout translation:* a recorded struct whose layout differs in the new build's PDB is rewritten into the new
  layout by field name, and only the fields both layouts have are compared. Since 2026-11-09 (zstd, below): a
  removed field is dropped; an added one has no recorded value, so its bytes are unreadable until the function
  writes them, and never compared; a struct held by value is translated field by field (the spec carries the
  nested layouts); a renamed struct is found by structure (the one new-only struct with the same fields), a renamed
  enum of the same size is the same type **[Guess]**, and a pointer is an address whatever its type's name. A
  resized or retyped field, or a moved bitfield, makes the case inconclusive; so does a struct with no layout for
  the new build (analyzed without `--pdb`).
- *Verification:* `RecordedCasesRunner` (§6.2), `pbeta repair --cases <dir> --new-binary`, and `pbeta replay`
  for one old/new RVA pair.

Measured on the hook loop (`corpus/build-hooks.ps1 -Run -Replay`): v1 and v2 recorded (77 cases of v1 at /O2 and
/Od, 70–73 of v2), the decision steps given the recordings, every resolved hook replayed on its new RVA. **22 of
24** resolved hook repairs replay, all passing (16 before globals and import calls, 2026-11-08): `price_lookup`,
`stock_level`, `apply_discount` (/O2; its body was rewritten in v2, same results), `checksum`, `format_receipt`
(through `snprintf`'s stand-in, its options global recorded), `order_add` (all 21 cases v2 → v3; v1 → v2 20 of
21) and `ship_order` v2 → v3. Inconclusive: `ship_order` v1 → v2 and `order_add`'s "order full" case v1 → v2, both
because they call `log_event`, which prints a severity in v2 (another format string). `log_event` stays in review.
Repair outcomes and traces are unchanged from the run without recordings. Negative control: `price_lookup`'s v1
cases replayed on `stock_level`'s v2 function fail, and the reverse (both flag sets). The hook app's `Order` never
changes layout, so translation is covered by unit tests only.

**Measured on real code (2026-11-08):** `corpus/replay-measure.ps1` hooks 16 zlib functions in minigzip
(`corpus/replay/zlib.template.toml`), records compressing and decompressing zlib's `deflate.c` in one release and
replays every case on the same function, by symbol, in the next. Every pair is correct, so a failure is replay's
error. The first run failed `_tr_init` (v1.3 → v1.3.1, /O2): it stores `&static_l_desc` in its state, and the new
build's address of the table isn't the old one's. Now fixed: the recorder saves the image's size
(`TestCase::image_size`), and a word that held an address into the recorded image and holds one into the new image
after the replay is not a difference in behavior. Whether both point at the same thing isn't checked (that needs
the old build's symbols), so the case is **inconclusive**, never a pass; any other difference still fails, and a
recording without the size compares as before. Result: 1 of 16 hooks replays (`crc32_z`, 18 of 18 cases), 0 fail,
on o2 v1.3 → v1.3.1 and od v1.2.13 → v1.3; 2 hooks are never called by the workload. Every other hook stops on
memory behind pointers inside its arguments (`z_stream.state`, `next_in`, the window, `pending_buf`): depth 1
isn't enough for real code. `build_tree` also reads old-image addresses recorded in its arguments
(`tree_desc_s.stat_desc`).

**Executed CRT functions (2026-11-08):** `memcpy`, `memmove`, `memset` and `strlen` are run by replay itself
(`imports::EXECUTED`) instead of answered from the recording: their effect follows from their arguments and the
memory they read, which the emulator checks like any other access, and a build may inline them or call them a
different number of times without behaving differently. Recorded calls to them are skipped when matching the
recorded sequence. Up to 16 MiB each **[Guess]**. `memcmp` and `strcmp` aren't: only their result's sign is
defined, and a caller may keep the value. Since 2026-11-10 also `_rotl`, `_rotr`, `_rotl64` and `_rotr64` (shift
modulo the width), which /Od builds call instead of inlining: zstd /Od's xxHash and decoder stopped at `_rotl64`.

**Pointers inside structs (2026-11-08).** The recorder follows pointers by type, `pointer_depth` levels from the
arguments (`pbeta harness-spec --pointer-depth`, default 2 **[Guess]**; 0 turns it off, and a spec without the key
means 0). The spec lists every pointer field of its layouts (`[[pointer]]`), adding the layouts of the structs they
point to (up to 64 **[Guess]**). A field pointing to a struct captures it with its layout (replay translates it by
field name like an argument's) and is followed further; one pointing to bytes or `void` captures the whole heap
block when the pointer is a process-heap block's start (up to 256 KiB **[Guess]**; also when the block is larger
than the struct: an array), otherwise 4 KiB **[Guess]**, and isn't followed. Function pointers, types without a
layout, pointers into the image and the recorder's own stack frames aren't followed. Regions never overlap (bytes
are cut short, an overlapping struct isn't captured), at most 4 MiB per case **[Guess]**. Redacted memory is never
captured; a pointee freed during the call is left out. These regions are `CaptureKind::Pointee`.

A first version scanned every word of captured memory for pointers, and the hook loop caught a false failure:
`format_receipt`'s output buffer starts out as stale bytes, which led to heap memory that `snprintf`'s internals
wrote during the recorded call. Hence types, not bytes. And for the same reason a **difference in pointee memory is
inconclusive, not a fail**: an import's internals or another thread may have written it during the recorded call.
A pass still needs every byte to match; arguments' memory, globals and the return value still fail on a
difference.

Measured with `corpus/replay-measure.ps1`: **7 of 16** zlib hooks replay (was 1), 0 fail, on o2 v1.3 → v1.3.1
and od v1.2.13 → v1.3: `crc32_z`, `deflate`, `longest_match` (32 of 32 cases), `fill_window`, `compress_block`,
`updatewindow`, `send_tree`. The rest stop on old-image addresses in recorded memory (`tree_desc_s.stat_desc`
pointing at static tables; `inflate` calling through a recorded function pointer), on a stack buffer larger than
the 4 KiB block (`next_in` into minigzip's 16 KiB buffer), and on memory `inflate`'s state reaches through fields
the layouts don't type. The hook loop is unchanged: 22 of 24, the negative control failing.

**Old-image addresses (2026-11-08).** Recorded memory holds addresses into the old image: a pointer to a static
table, a function pointer. Replay maps them to the new image (`permanent_beta_replay::address`): **data** by a
symbol name unique in both PDBs with the same size (`AnalysisExport::data_symbols`, every PDB data symbol,
read-only ones included; optional, no schema bump), any offset inside it; **functions** by entry, through the run's
accepted matches (`pbeta repair --cases` maps each old build it repairs from; `pbeta replay --old-analysis`).
Overlapping entries map neither. Inputs (registers, stack arguments, regions, globals) holding a mapped address
get the new one before the run; after it, an expected old-image address must equal the mapped new one: a
different data address fails, a different function address is inconclusive. And because a function pointer is
mapped through *another* function's match, which could be wrong, a case whose inputs had a function pointer mapped
can't fail, only be inconclusive. Unmapped old-image addresses are treated as before. zlib: **10 of 16** hooks
replay (was 7), 0 fail, both steps: `_tr_init`, `build_tree` and `_tr_flush_block` now pass; `inflate` now runs
through its mapped `zalloc` into `malloc`, which replay doesn't model. Hook loop and fixture scorecards unchanged.

**Heap allocation and buffers (2026-11-08).** `malloc`, `calloc` and `free` are answered from the recording, in
the recorded order, for the same request: the recorded block at its recorded address (replay reserves every
recorded block's address before placing anything), writable, and **readable only byte by byte as the function
writes it** (icicle's uninitialized-memory tracking, now on; everything else is granted readable as before), so
reading what the function never wrote is inconclusive, not a guess; `calloc` blocks are zeroed and readable; `free`
of a handed-out block unmaps it. Another size is inconclusive (a struct may have grown). Up to 64 MiB a block
**[Guess]**. `realloc` was added later (below).
The recorder now follows structs by type through every level first and captures byte buffers after (a 64 KiB block
behind a pointer into the middle of a heap buffer had swallowed zlib's state, which then wasn't followed). A byte
pointer that doesn't start a heap block captures up to 64 KiB **[Guess]** (was 4 KiB), and one into the caller's
stack also up to 64 KiB behind it (zlib's `updatewindow` copies from `next_out - copy`). And the CRT functions replay
runs itself (`memcpy`, ...) read only memory something put there: the recorded memory, the image, the stack, handed-out
blocks, never the zeros around recorded regions that exist for vectorized over-reads; 6 `deflate` cases had passed
by copying those zeros, and are inconclusive now. zlib: **13 of 16** hooks replay, 0 fail, both steps: everything
called but `inflate_table` (its `unsigned short*` arguments capture one element). zlib's structs have the same layout
in all three releases, so translation still isn't measured on real code. Hook loop and fixture scorecards unchanged.

**Array arguments and `realloc` (2026-11-09).** A pointer to a scalar or to a pointer (`unsigned short* lens`,
`code** table`) can't say from the prototype whether it's one value or an element of an array. The record spec
now gives it `array`: the recorder captures the whole process-heap block holding it (found with `HeapWalk`, its
start or anywhere inside, up to 256 KiB **[Guess]**), once when several arguments point into the same block, and
falls back to the element's own bytes on the stack, for a larger block, near redacted memory, or where the block
would partly overlap another argument's region. The block is compared like the argument's own memory: what the
function writes there is its output. zlib's `inflate_table` gets four pointers into inflate's state and now
replays (3 of 3 cases); its cases replayed on each of the other 157 functions of v1.3.1 never pass (46 fail, 111
inconclusive). `realloc` is answered like `malloc`: the same block and size, the recorded result. A moved block
carries the bytes the function may read (per-byte permissions) to the new address and the old one is gone; what
it grew by is unreadable until written; `realloc(NULL, n)` allocates, `realloc(p, 0)` frees, a NULL result leaves
the block. It may be a block this run handed out or recorded memory starting at the pointer. A recorded region the
function frees (`free`, or a moving `realloc`) is no longer compared after the call: the recorded bytes there may
be the heap's bookkeeping. zlib doesn't call `realloc`, so it's measured only by unit tests. zlib: **14 of 16**
hooks replay, 0 fail, both steps (`adler32_z` and `deflate_stored` aren't called). Hook loop and fixture
scorecards unchanged.

**Aliased pointer fields, whole heap blocks and constant-only cases (2026-11-09).** zlib's `inflate` and
`inflate_fast` replayed 1 of 8 and 1 of 9 cases: `z_stream.state` is declared `internal_state*` (deflate's state)
but holds a `struct inflate_state` in inflate, so the recorder took that larger heap block for bytes and never
followed its `window`. Two hand-given, reviewable hints fix it: `pbeta analyze --pdb --type inflate_state` keeps a
layout no signature uses (in both builds, for replay to translate), and `pbeta harness-spec --pointer-alias
z_stream_s.state=inflate_state` lists the field a second time with that target. The recorder takes a heap block as
a struct only when it's exactly that size (larger is bytes, smaller isn't that struct); elsewhere the declared
type, listed first, wins. A byte pointer into the middle of a heap block now captures that whole block (found with
`HeapWalk`) instead of 64 KiB from the pointer: what lies past the block is the heap's bookkeeping, which a
`malloc` during the call rewrites (8 `updatewindow` cases at /Od were inconclusive on it). And a hook's replay
passes only if its passing cases show more than a constant function would: a write, a modelled import call, or
two different return values. A wrong-target check (each hook's cases on every other function of the new build)
found `updatewindow` passing on 21 wrong functions through one case that returned 0 and wrote nothing (`_matherr`
returns 0); such cases alone are now inconclusive. zlib: **14 of 16** hooks replay, 0 fail, o2 and od, now with
`inflate` 8 of 8, `inflate_fast` 9 of 9 and `updatewindow` 7 of 8 cases (one `memcpy` reads a buffer not
captured); `inflate`, `inflate_fast`, `updatewindow` and `inflate_table` never pass on any of the 157 other
functions of v1.3.1. Hook loop and fixture scorecards unchanged. **[Guess]**: the rule's notion of "constant" is
the only trivial behaviour tested; a function returning its argument unchanged isn't ruled out.

**Wrong-target control (2026-11-09).** `pbeta replay --others` replays the cases on every other function of the
new build too, and `corpus/replay-measure.ps1` now fails if a hook's cases pass on one, like a correct pair
failing. Two kinds are listed apart, since replay can't tell them from the target by construction and matching
has to: identical code (the same normalized hash) and a function that calls the target (zlib's `crc32` forwards to
`crc32_z` and passes its 18 cases). zlib, o2 and od: no other hook's cases pass on any other function. The control
is most of the run time (about 10 and 20 minutes). A behavioral pass therefore says "behaves like the old function
on these calls", which a forwarding wrapper also does: the candidate's structural evidence has to separate them.

**The target's callees (2026-11-10).** A third kind is listed apart: a function the target calls, directly or
through other calls (`Others::called_by_target`), the code a dispatcher forwards these inputs to. A function whose
address the code takes counts as called: the analysis now records `code_refs`, code addresses outside the function
taken by a RIP-relative `lea` (not hashed, not matched on, optional in the schema). zstd /Od's
`HUF_decompress4X2_usingDTable_internal` calls `_default` through `fallbackFn`, and the control now passes there.
What it still can't excuse is an inlined copy: at /O2 `HUF_decompress4X_usingDTable` inlined `_internal`, which
also exists on its own, and `HIST_countFast_wksp` inlined `HIST_count_simple`. Both behave like the target on the
recorded inputs and nothing in the call graph links them; only matching can separate them.

**Changed callees (2026-11-10).** Given the old build's analysis (`--old-analysis`, and in the engine
`RecordedCasesRunner::with_addresses`), replay knows which of the new build's functions aren't the old code:
those without an accepted match, and those whose normalized hash differs from their counterpart's (the same
normalized code is taken to behave the same **[Guess]**: the hash masks addresses, so a function reading a data
table whose contents changed counts as unchanged). The emulator puts a breakpoint on each one's entry and notes
the ones a run enters (the candidate itself excepted). A difference is then attributed:

- a run that entered a changed function and differs (return value, memory, globals, or an import's inputs) is
  **inconclusive**, naming the function: the difference may be the callee's, and a correct candidate mustn't fail
  on it (before, a difference in memory or the return value failed the candidate);
- an import called with other inputs, or other import calls (`imports::DIFFERS`), in a run that entered no
  changed function and ran through no function pointer mapped by other matches is a **fail**: every function it
  ran is the old code, so the difference is the candidate's own (before, always inconclusive);
- without the old analysis, nothing changes.

On the corpus no case outcome changed (zlib and zstd: every correct pair still passes or stays inconclusive for
the reasons it did; no hook in them calls a modelled import with other inputs). The hook loop now passes
`--old-analysis`: `ship_order`'s cases at v1 → v2 stay inconclusive and say why, `log_event` (and
`apply_discount`), whose code changed, ran.

**Known confusions (2026-11-10).** Such pairs, once examined, are listed in
`corpus/replay/<project>.known-confusions.json` (hook, the function its cases also pass on, flags, new release and
the reason); `replay-measure.ps1` reports them as known and fails on any confusion not listed, and on a listed one
that no longer happens, so the list can't hide a new one or go stale. zstd /O2 lists the two inlined copies above
and passes. What separates them is matching and the structural checks, not replay: `HIST_countFast_wksp` takes 5
parameters to `HIST_count_simple`'s 4 (the parameter-count check, with PDB signatures). For these hooks a
behavioral pass doesn't distinguish the function from its inlined copy.

**Pointer aliases found in the PDB (2026-11-09).** The hand-given hints above are now found automatically:
`pbeta analyze --pdb` reads each procedure's locals, and a struct field `f` declared `X*` with a local `f` of type
`Y*` (`Y` ≠ `X`) somewhere is an alias (`pointer_aliases` in the analysis, with the functions it's seen in; the
layouts of the targets are kept). **[Guess]**: the shared name is the only evidence, and it's noisy (Lua: 53
aliases from fields like `next`; yaml-cpp and JsonCpp: STL internals), so the record spec applies one only when it's
seen in a function a hook reaches, and the recorder's exact-size rule still decides per block. On zlib that gives
exactly `z_stream_s.state → inflate_state` (seen in `inflate` and `inflate_fast`) and leaves out `→ gz_state` (the
`gz_*` functions, which no hook reaches). `--type` and `--pointer-alias` stay for what the PDB doesn't show.

**Replay measured on zstd (2026-11-09).** `corpus/replay-measure.ps1 -Project zstd` hooks 16 functions of the zstd
CLI (`corpus/replay/zstd.template.toml`: compression and decompression, most taking `ZSTD_CCtx_s*` or
`ZSTD_DCtx_s*`) and records compressing and decompressing `zstd_compress.c`, single-threaded. Unlike zlib, zstd's
structs change between releases (1.5.7 renamed dozens of types, `seqStore_t` → `SeqStore_t`, removed
`ZSTD_CCtx_s.blockSize` and added `blockSizeMax`, changed nested by-value structs), so this is layout translation's
first measurement on real code. The first run replayed 1 of 16 hooks; what it took, all general:
- translation by structure for renamed types, dropped removed fields, unreadable added fields, nested structs field
  by field, same-size integers and enums as the same bytes (§7.3 *Layout translation*);
- the spec carries the layouts of structs held by value; `…Capacity` is a length name and a sized buffer is
  captured up to 256 KiB **[Guess]** (a zstd block is 128 KiB);
- the recorder: 256 import thunks (zstd has 112 imports; with 64 no case had its imports recorded), at most 1024
  import calls kept per case **[Guess]** (past that the case keeps none and says `imports_recorded = false`: zstd /Od's
  compression wrote 1.9 million blobs over 6 hours of recording without it), whole heap
  blocks up to 1 MiB **[Guess]** (zstd's stream buffers are ~260 KiB), a 64 KiB window from an `array` pointer into
  a larger block, never past its end, and untyped regions an `array` capture overlaps merged into one (`count` and
  `normalizedCounter` in one workspace); and a pointer one past a heap block's end also captures that block
  (zlib's `updatewindow` copies from `next_out - copy`).
zstd /O2 1.5.6 → 1.5.7: **11 of 16** hooks replay, 0 fail. Two aren't called; `ZSTD_compressStream2`,
`ZSTD_compressBlock_internal` and `ZSTD_buildSeqStore` index hash tables across a workspace of megabytes, more
than a case records, and stay inconclusive. The wrong-target control runs on all threads (each its own emulator).

Not recorded: memory behind pointers inside structs beyond `pointer_depth` or without a typed field, the globals a callee reached only through a
pointer reads, and comparison rules (`compare.ignore`). Imports are modelled one by one; any other import is
inconclusive. Variadic functions and more than 8 stack arguments aren't supported by the thunks.

*Emulator* (2026-11-08): **icicle** (MIT or Apache-2.0), which executes Ghidra's SLEIGH specification of x86-64,
replaced Unicorn (GPL-2.0, §11.5), so replay and Ghidra share one definition of the instruction set. The x86
specification from Ghidra 12.2 (Apache-2.0) is embedded in `permanent-beta-replay/sleigh/` and compiled when the
first case runs (about 0.2 s, once per thread); no Ghidra install is needed. What a function may touch is
enforced by icicle's per-byte memory permissions, and the traps are breakpoints. icicle isn't on crates.io; it's
pinned to a git commit. Measured the same as with Unicorn: all 23 replay unit tests (negatives included) and the
hook loop's 22 of 24 replaying hook repairs, the negative control failing.

**Privacy:** recorded memory can contain whatever data the target was processing. Recordings stay local by default. **Redaction**
(implemented 2026-11-08): an argument or global marked `redact` in the spec (`pbeta harness-spec --redact
hook.param`) is never recorded, nor any import call's memory that overlaps a redacted argument seen so far in the
run. That part is best effort: an import can be handed text derived from a redacted value (a receipt formatted
from a name), or the value at an address no redacted argument pointed to. `import_memory = false`
(`--no-import-memory`) captures no import memory at all, which is the guarantee. The hook loop checks it: v1
recorded with the customer names' arguments redacted and import memory off contains no customer name in any
file, while the ordinary recording contains 83–97 (with import memory on, redaction alone leaves 36 blobs with a
name, down from 77). A replay that reads redacted memory is inconclusive. **[Validate]** on real targets.

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

**Implemented (2026-11-07):** `permanent-beta-ai`, used by `pbeta propose` and `pbeta-corpus score-ai`.

- **Shortlist:** for an old function matching left unmatched, the 5 **[Guess]** closest unmatched new functions
  by a cheap score (mnemonic counts, matched neighbours, strings, constants, imports, size). It only orders what
  the model sees.
- **Prompt:** features as JSON, not code: size, blocks, register arguments, top mnemonic counts, strings (at most
  16, each clipped to 120 characters), constants, imports, and neighbours labelled `N:<new rva>` when matched.
  Candidates are named `c1`..`c5`; the system prompt says strings are data and that `none` beats a guess.
- **Answer:** `{choice, confidence, rationale}`, with `choice` one of the offered names or `none`, enforced by the
  JSON Schema sent with the request and again on parsing; anything else is discarded. The rationale (at most 600
  characters) becomes the candidate's `ai` evidence.
- **Backend:** Claude through the Claude Code CLI in print mode (`claude -p --json-schema`), which runs on a Claude
  subscription; default model `claude-opus-5-5`. All tools, MCP servers and settings are off and it runs in an
  empty directory, so a reply can only be text. This is a remote provider: `pbeta propose` refuses to call it
  without `--allow-remote`, and every exchange, prompt and reply, is appended to a log (`--log`). `pbeta repair
  --propose` (same switches) asks it about every hook matching left with no candidate (`unmatched`), from the
  hook's own source build; each verified proposal is attached to that hook's review item as a candidate, the hook
  stays in review, and a pair a reviewer rejected isn't attached again. First live run (2026-11-07), the hook
  loop's only unmatched hook (`apply_discount` at /Od, rewritten in v2): the right function, both steps. The same log
  replays answers (`--replay`), which keeps corpus scores repeatable. A local OpenAI-compatible backend is not
  built yet (the `Model` trait is the seam).
- **Routing:** every proposal is verified with `Engine::verify_candidate` (same checks and policy) and queued as an
  `ai_proposal` review item (`proposal_review_item`, shared with the MCP server). Nothing writes a mapping; a
  human decides with `pbeta review`.
- **Scoring:** `pbeta-corpus score-ai` asks about the in-scope unmatched old functions of each variant (deleted
  ones included, where `none` is the right answer) and reports correct and wrong proposals, how many would pass
  the normal policy, right and missed `none`s, and counterparts the shortlist didn't include.

**First measurement (2026-11-07, `claude-opus-5-5`, Lua and zstd /O2, 20 questions per variant, 63 asked):**
32 proposals, 31 correct, 1 wrong (precision 96.9%). 30 of the correct ones would pass the normal policy, and the
wrong one wouldn't. The wrong one is a near miss: zstd 1.5.6 inlined one object file's `static` copy of
`BIT_initDStream`, and Claude picked another object file's copy of the same function, which the per-object answer
key counts as wrong. 31 answers were `none`, all for functions that do have a counterpart (none of the asked
functions was deleted), mostly families of near-identical functions: Lua's one-line `math_*` wrappers and zstd's
`ZSTD_compressBlock_fast_noDict_*` instantiations. The true counterpart wasn't on the shortlist twice. About 4
seconds per question. Recorded in `corpus/ai/claude-opus-5-5.jsonl`; replaying it needs byte-identical builds.
So far it beats sending these functions to review: half of them come with a correct suggestion, and verification
caught the one wrong suggestion. 

**Widened (2026-11-07):** /Od, deleted functions (`score-ai --select deleted`) and the near-identical families,
after the analyzer change below and with one more rename declared (zstd 1.5.7 `BMK_benchCLevel` →
`BMK_benchCLevels`, which Claude found three times while the answer key called it deleted).

| Set | Asked | Proposed | Correct | Wrong | Wrong passing policy | `none` |
|---|---|---|---|---|---|---|
| Lua /O2 | 11 | 7 | 7 | 0 | 0 | 4 |
| Lua /Od | 10 | 6 | 6 | 0 | 0 | 4 |
| zstd /O2 | 40 | 25 | 24 | 1 | 0 | 15 |
| zstd /Od | 40 | 18 | 17 | 1 | 0 | 22 (1 right) |
| Deleted (fixture + zstd, all flags) | 11 | 2 | 0 | 2 | 0 | 9 (all right) |

Lua asks fewer questions than before because matching now resolves the `math_*` wrappers (below). Every wrong
answer is a near miss, and none passes verification: `BIT_initDStream` (another object file's copy of
the same `static` function, three times) and zstd 1.5.7's `ZSTD_entropyCompressSeqStore`, whose body moved into a
new function behind a wrapper (Claude picked the body). On truly deleted functions Claude answered `none` every
time apart from those copies. Precision at /Od is the same as at /O2; fewer of its correct proposals pass the
policy alone (17 of 23 vs 30 of 31), because /Od code carries less independent evidence.

Instruction text was not added: neither family Claude declines differs in its own instructions. Lua's `math_*`
wrappers differed only in which import thunk they call (`sin`, `cos`, ...), and every thunk had the same
normalized hash, so none matched and the calls showed as `unmatched`. The normalized hash now covers the imported
name (analysis schema 2), the thunks match, and matching resolves the wrappers itself (+6 to +7 correct per Lua
variant, 0 wrong). zstd's `ZSTD_compressBlock_fast_noDict_*_0/_1` differ only in calling the new
`ZSTD_match4Found_cmov` or `_branch`, inlined in the old build; describing unmatched callees looked like the
lever there.

**Unmatched callees in the prompt: measured, not adopted (2026-11-07).** Each function's unmatched callees (at
most 4) were sketched in the prompt: size, top 8 mnemonics, a few strings, constants and imports, with a
sentence in the system prompt about inlined code. Same questions both arms, after tonight's matching changes
(Lua and zstd, /O2 and /Od, 40 per variant; deleted functions on the fixture and zstd):

| Set | Prompt | Asked | Correct | Wrong | Wrong passing policy | Precision |
|---|---|---|---|---|---|---|
| /O2 | current | 91 | 37 | 1 | 0 | 97.4% |
| /O2 | + unmatched callees | 91 | 38 | 4 | **2** | 90.5% |
| /Od | current | 91 | 38 | 1 | 0 | 97.4% |
| /Od | + unmatched callees | 91 | 42 | 2 | 0 | 95.5% |
| Deleted | current | 12 | 0 | 1 | 0 | 11 right `none`s |
| Deleted | + unmatched callees | 12 | 0 | 2 | 0 | 10 right `none`s |

The sketches made Claude choose inside the very family they were for, and choose wrong: `noDict_5_1` and
`noDict_7_1` got a sibling instantiation, and `ZSTD_cwksp_aligned_alloc_size` its neighbour. Two of the wrong
answers would pass verification. Five more correct answers don't pay for that, so the prompt is unchanged. The
current prompt's answers on these questions are recorded in `corpus/ai/claude-opus-5-5.jsonl` and replay offline
(the table's first rows); the sketch arm's answers are kept in the log too, as the experiment's raw data.

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
  a rerun offers nothing new and reopens when a new candidate appears. *Revoke* (2026-11-10) withdraws the
  mapping a reviewer accepted for an item: the mapping is revoked, repair stops using it and the item reopens; it
  isn't a rejection, so the function can be proposed again. Only the item's last decision can be revoked, and only
  while its mapping is live (not superseded). *Accept a function outside the candidates* (2026-11-10, `review
  accept --function` with both builds' analyses): the CLI verifies the pair with `Engine::verify_candidate`
  (source `human`, evidence kind `reviewer`, which implies no check), prints every check, and the store records
  it like a candidate's report, with the same `--force` rule for a rejected verdict and the same one-to-one check;
  a function a reviewer rejected for that item needs `--force` too.

### 9.2 Storage backends **[Provisional]**

- **SQLite** file per project plus a content-addressed blob directory (analysis snapshots, traces, memory blobs).
  The skeleton uses a JSON file (`JsonFileStore`) behind the same `MappingStore` trait.

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
- **CI gate:** any change to analysis, match or verify must not reduce accepted precision on the corpus. CI runs it
  only on request (`workflow_dispatch` with `corpus` ticked), not on every push: it takes too long.
  *Implemented for the purpose-built fixtures* (`pbeta-corpus score`, `corpus/fixtures/*/expected.toml`): zero
  wrong matches across every function in scope, and correct matches at or above a per-flag-set baseline that is
  raised as matching improves. Per-scenario targets are reported as met or not yet. *Real-world projects*
  (`corpus/projects/`), cloned and built in CI, 0 wrong in every variant (2026-11-06):

  | Project | Tags | /O2 correct | /Od correct |
  |---|---|---|---|
  | zlib | v1.2.13 → v1.3 → v1.3.1 | 69 of 69 | 160–161 of 163 |
  | Lua | v5.4.6 → v5.4.7 → v5.4.8 | 726–732 of ~735 | 1087–1093 of ~1095 |
  | zstd | v1.5.5 → v1.5.6 → v1.5.7 | 671–679 of ~729 | 1705–1744 of ~1879 |

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
pbeta analyze <binary> --out a.json [--pdb b.pdb [--pdb-functions p.json]] [--functions-from ghidra.json]
                                                          # native PE x64 analyzer (§4.3, §4.4)
pbeta analysis-diff a.json b.json [--json] [--limit n]    # two analyses of one build (§4.4)
pbeta match   --old a.json --new b.json [--json]
pbeta repair  --old a.json --new b.json --hooks hooks.toml [--earlier older.json]... [--out hooks.new.toml]
              [--new-binary b.exe] [--trial-out trial.toml] [--store path]
              [--old-trace a.jsonl... --new-trace b.jsonl] [--json]
pbeta trace-diff --old a.jsonl [--old older.jsonl]... --new b.jsonl --hooks hooks.new.toml [--repair report.json]
              [--json]
pbeta trace-diff --baseline a.jsonl --hooks hooks.toml   # every hook attached and fired
pbeta pattern <binary> --rva <rva>                        # shortest unique AOB pattern
pbeta header  --hooks a.toml [--hooks b.toml]... --out hooks.gen.h
pbeta repair  ... --propose (--allow-remote | --replay)  # also ask the AI proposer about unmatched hooks
pbeta propose --old a.json --new b.json [--store path] [--rva <rva>]... [--limit n] [--model id]
              (--allow-remote | --replay) [--log path] [--json]     # AI proposals into review (§8)
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

#### Overlap with Version Tracking and BSim (evaluated 2026-11-08, against Ghidra 12.2)

**Version Tracking** (`Features/VersionTracking`) is a session between a source and a destination program, stored
as a Ghidra domain object. Correlators fill match sets: exact bytes, instructions or mnemonics, symbol name
(exact, similar, duplicate), data and function references, combined, and a BSim correlator
(`Features/VersionTrackingBSim`). Its match table lets a user accept, reject and tag matches, and accepting is what
transfers **markup** (names, comments, signatures, labels, data types) from source to destination. That is its
purpose: porting reverse-engineering work forward. What it doesn't do, and we need:

- **No independent verification.** A match's score and confidence come from the correlator that found it; accepting
  is a click, with no checks between correlation and decision. Our rule is that matchers propose and verification
  judges (§6), counting only evidence independent of the match.
- **Ambiguity is shown, not withheld.** Correlators emit every plausible pair (duplicates included) and the user
  picks. Our invariant is that ambiguity gives no candidate (§5.2); a human decides, with the reason.
- **No hooks.** No manifest, criticality policy, AOB patterns, prototype or struct proposals, trial runs or replay
  (§7).
- **No CI or shared history.** A session is a Ghidra database in one project. Our decisions are the append-only
  store that `pbeta repair --store` honors in CI (§9.1); a decision taken in a VT session never reaches it.

**BSim** (`Features/BSim`) indexes decompiler-derived feature vectors into a database (H2, PostgreSQL or
Elasticsearch) and searches for similar functions across many binaries. It's a similarity search, close to our
weak similarity pass and to the AI proposer's job (finding leftovers), not identity evidence: it needs every
function decompiled, and a similar function is exactly what verification has to tell apart from the same one.

**Function Comparison** (`Features/CodeCompare`, `FunctionComparisonService.createComparison(left, right)`) shows
two functions from two programs side by side, listing and decompiler, with differences highlighted. That's the view
a reviewer needs for "is this the same function", and it exists.

**Decision (proposed):**

- **Add** what Ghidra lacks: the review queue (items, reasons, candidates, evidence, every check with whether it
  counted, the verdict and the policy that produced it), hook context (name, criticality, proposed prototype or
  struct), accept and reject through `pbeta review`, and the item's decision history.
- **Reuse, don't rebuild:** Function Comparison for old vs new, Ghidra's `GhidraTable` with its filter (as VT's
  match table does), and its Go To navigation. No correlators, no match table of our own for all pairs, no diff view.
- **Link, later:** pushing accepted mappings into a VT session as a match set (`VTSession.createMatchSet`), so a
  user can carry markup forward with VT's own UI. Not M6: VT's "accept" would look like a review decision while
  meaning only markup transfer, which needs its own design. BSim as an extra proposer for leftovers (its hits
  verified and queued, like the AI's, §8) is a separate step too.

#### M6 scope (confirmed 2026-11-08)

1. Module `integrations/ghidra/PermanentBeta/`, built headless with Ghidra's own `support/buildExtension.gradle`
   (`gradle -PGHIDRA_INSTALL_DIR=...`, Gradle ≥ 9.1, JDK 25) into an installable zip.
2. Reads through `pbeta-mcp` as a child process (its JSON-RPC protocol, `gson` from Ghidra's own libs): review
   items, explanations, candidates with evidence and checks. Decisions run `pbeta review accept|reject`, the only
   path that decides an item; the extension writes nothing itself, and its errors (a verification-rejected
   candidate without `--force`, a function another mapping claims) are pbeta's, shown as they are.
3. A Permanent Beta window: a review-item table (status, reason, hook, old function, candidates) and a detail pane
   (explanation, candidates with evidence and checks, verdict). Actions: go to the old or new function, compare
   them (Function Comparison), accept a chosen candidate, reject, each with reviewer and note. Programs are tied to
   builds by the executable's SHA-256 (Ghidra records it at import; a build ID is that hash), addresses as image
   base + RVA; a mismatched program is refused, not guessed.
4. Settings: paths to `pbeta`, `pbeta-mcp`, the store and the two analyses; reviewer name defaulting to Ghidra's
   user.
5. Tests: Java unit tests for the protocol client and parsing, against recorded `pbeta-mcp` output, including
   negative cases (a program whose hash isn't the build's; a refused accept surfaced, not swallowed).
6. Install and usage steps in `integrations/ghidra/README.md` an external tester can follow, verified end to end on
   the hook loop's `checksum` v2 → v3 item (ambiguous: an identical `checksum_backup` was added).

Not in M6: the VT link and BSim proposer above, running analysis or repair from the GUI (the headless exporter
stays as it is), and any tool that decides an item other than `pbeta review`.

**Built (2026-11-08)**, usage in `integrations/ghidra/README.md`. Where it differs from the scope above:

- Settings take no analyses: `pbeta-mcp --analysis` is now optional, since the review tools read only the store.
  The extension starts `pbeta-mcp --store <store>` and calls only its read tools (`McpClient.READ_TOOLS`; it
  refuses `propose_mapping` before sending anything).
- Tables are `GTable` with `GTableFilterPanel` (Ghidra's docking widgets); `GhidraTable` adds program navigation
  the item table doesn't need.
- Tests are a plain main (`SelfTest`, `gradle selfTest`): Ghidra ships no JUnit, and this keeps the build offline.
  12 tests against replies recorded from the real `pbeta-mcp` on the hook loop's v2 → v3 store, with negative
  cases: no `propose_mapping`, a program without a recorded hash, another build's hash or an id prefix is not the
  build, no decision without a reviewer, store or item, a refused `pbeta review` is an error carrying pbeta's
  message, malformed items are refused.
- **Verified in the GUI** (Ghidra 12.2, 2026-11-08) on the hook loop's `checksum` v2 → v3 item: accepted `0x1040`
  through the window, recorded by `pbeta review`, honored by the next `pbeta repair --store`; the forced-accept
  prompt and the refusal of a build that isn't open were checked too (docs/STATUS.md). An external tester is
  still to try it.

### 11.4 IDA Pro plugin (step 5)

Via PyO3 bindings (`permanent-beta-py`) from IDAPython, or the same CLI/RPC route. Start after the repair pipeline is
validated on the corpus.

### 11.5 Licensing

| Component | License |
|---|---|
| Everything in this repository: core crates, CLI, MCP server, Ghidra extension, harness, corpus tooling | **Apache-2.0** (decided 2026-11-08): its patent grant, and the same license as Ghidra and icicle. `LICENSE`, `NOTICE`, `license = "Apache-2.0"` on every crate. |

**No GPL code** (2026-11-08). Replay first emulated with Unicorn (GPL-2.0), which made any `pbeta` built with
replay GPL-2.0 as a whole; GPL-2.0 and Apache-2.0 are generally considered incompatible. It now uses icicle (MIT or
Apache-2.0) with Ghidra's x86 SLEIGH specification (Apache-2.0, embedded with Ghidra's license in
`permanent-beta-replay/sleigh/`), so every build can carry an Apache-2.0 license. Keep it that way: add no GPL
dependency. Not legal advice.
Still to decide: contributor terms (DCO vs CLA). A CLA keeps future relicensing options open but deters contributors.

---

## 12. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| **False-positive matches** (silent wrong repair) | Hook patches the wrong function: crashes, data corruption, and loss of trust. Worse than a broken hook. | Uniqueness rule, independent verification, criticality policy, behavioral gate for high-criticality hooks, corpus precision gate, default to review. |
| **Legal: reverse-engineering restrictions** | EULAs may prohibit reverse engineering. Statutory interoperability exceptions are narrow and vary by jurisdiction (e.g. US DMCA §1201(f), EU Software Directive Art. 6). | Not legal advice. The README says to analyze and instrument only software you have the right to. The project is for interoperability and maintenance of software the user owns or licenses. |
| **Legal: circumvention** | DRM, anti-tamper and anti-cheat circumvention is prohibited in many jurisdictions regardless of purpose. | Non-goal. No features for unpacking, defeating integrity checks or evading detection. Refuse to process known-protected targets (detect common protectors and stop): implemented in the analyzer (§4.2). |
| **Dual use: cheat maintenance** | Keeping hooks working across game patches is exactly what cheat developers need. That's reputational, legal and platform risk (e.g. GitHub takedowns, anti-cheat vendor hostility). | The README states the intended use (software you have the right to analyze), the analyzer refuses protected binaries, and there's no public signature DB for third-party games. **[Validate]** whether the tool attracts this use and how to respond. |
| **Authorization** | Users analyzing third-party software without the right to. | Explicit statement in the README (Legal). It can't be enforced technically. |
| **Shared signature database** | Distributing data derived from third-party copyrighted binaries. | Counsel review before building one. Prefer per-user databases. **[Validate]** |
| **Compiler effects** | ICF folding, inlining, LTO, PGO and hot/cold splitting make "the same function" ill-defined. | Model fold, inline and split outcomes explicitly. Corpus builds cover these flags. Hookability check. |
| **Analysis gaps** | Leaf functions without `.pdata`, tail calls, jump tables. Ghidra and the native analyzer disagree on boundaries. | Hybrid analysis. Rust computes all hashes. Disagreement is reported, not silently resolved. |
| **Behavioral test flakiness** | Nondeterminism (time, threads, ASLR, global state) causes false failures. | Comparison rules per test (`compare.ignore`), multiple recordings, emulation for leaf functions, failures go to review. |
| **Recorded data is sensitive** | Traces capture whatever data the target was processing. | Local-only by default, redaction in the record spec (§7.3, implemented), encrypted blob store option (not built). |
| **AI-specific** | Hallucinated matches; prompt injection via binary strings; binaries leaving the premises. | Proposer-only role, same gates, strict output schemas, local models by default, remote opt-in with logging. |
| **AI-written codebase** | Plausible but wrong logic that compiles and passes weak tests. Slower owner review in Rust. | Corpus metrics gate in CI, small crates with enforced dependency rules, property tests for matchers, review checklist in `CLAUDE.md`. |
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
6. Will targets usually have PDBs? (Changes everything about type and struct repair.)

**Analysis and matching**
7. Hybrid analysis vs Ghidra-only for v1? Is a JVM on CI agents acceptable to users? (Provisional,
   from M1: native boundaries, Ghidra for pseudocode and types only, §4.4. The JVM question stays open; the
   Ghidra diff runs locally only.)
8. Reuse vs reimplement: BinDiff (open-sourced by Google in 2023; license **[Validate]**, believed Apache-2.0),
   Diaphora (believed AGPL-3.0 **[Validate]**, so its *code* can't be mixed into the Apache-2.0
   core), Ghidra Version Tracking and BSim (Apache-2.0). Options: reimplement the published ideas,
   import their outputs as candidate sources, or build on Ghidra VT.
9. Acceptance thresholds: set per project, per hook, or globally from corpus calibration?

**Behavioral testing**
10. Test corpus representation: the JSON + content-addressed blobs proposed in §7.3, or a binary format
    (CBOR/protobuf) for large traces?
11. Recording mechanism: own Detours-based harness, Windows Time Travel Debugging (TTD) traces (redistribution and
    licensing **[Validate]**), or DynamoRIO / Frida instrumentation?
12. Replay mechanism: emulation, live in-process, scenario trace diff, or a combination (§7.3)? (Decided
    2026-11-08: scenario trace diff and emulation, both implemented, emulation with icicle and Ghidra's SLEIGH
    specification since it replaced Unicorn the same day; live in-process not built.
    Recording uses the own Detours harness, question 11.)
13. Reuse existing behavioral-diffing research (e.g. blanket execution / BLEX-style approaches, differential
    tracing)? Needs a literature and tool survey. **[Validate]**

**Project**
14. Open-source license: decided 2026-11-08, Apache-2.0. Still open: contributor terms (DCO vs CLA).
15. Project name: decided as Permanent Beta (CLI `pbeta`). Trademark and crates.io availability not yet checked. **[Validate]**
16. Who reviews AI-written code besides you, and what review is required to merge (e.g. corpus gate + owner
    approval)?

---

## 14. Who it's for

Permanent Beta is a free, open-source tool. Likely users, all **[Guess]**:

| Users | What they'd use it for |
|---|---|
| Teams maintaining legacy software | Long-lived instrumentation of vendor or legacy binaries with no source, where hooks break on every update. |
| Game studios, anti-cheat and security teams | Hooks into their own builds, kept working across releases. |
| Mod communities | Mods that hook a game, kept working across patches. The highest dual-use and legal exposure (§12). |

---

## 15. Roadmap

| Milestone | Scope | Exit criteria |
|---|---|---|
| **M0 Skeleton** (done 2026-11-05) | Crate boundaries, model types, 3 matching passes, 3 structural checks, policy, repair decisions, JSON store, CLI, demo fixtures | `cargo test` green; demo `repair` produces expected outcomes |
| **M1 Spikes** (done 2026-11-07) | Native PE x64 analyzer on one real binary; Ghidra headless exporter; `pdb` crate on MSVC PDBs | Both analyzers export the same functions for a sample binary (diff report). Native analyzer, `pdb` crate (names and signatures), Ghidra headless exporter (§4.3) and `pbeta analysis-diff`, with a three-way diff report (native, Ghidra, PDB) on the newest tag of every corpus project and flag set (§4.4). Native stays the source of boundaries |
| **M2 Corpus** (done 2026-11-06) | Ground-truth corpus (3–5 projects × versions × flags), metrics harness, CI gate | Precision and recall reported per pass. Three projects (zlib, Lua, zstd) × 3 tags × 3 flag sets, plus the `basic` fixture. Since grown (2026-11-07) to five projects (+ TinyXML-2 and yaml-cpp, C++) and five flag sets (+ /LTCG and PGO; zstd not under those two): 50 variants, 0 wrong |
| **M3 Matching depth** | Mnemonic hash, call-graph propagation, structural similarity, independence-aware policy, SQLite store | Measured improvement with no precision regression. Done 2026-11-07 apart from the SQLite store (deferred until history size needs it) |
| **M4 Repair loop** | Detours harness (record + scenario trace diff), AOB generator, offsets header, struct and prototype proposals | End-to-end repair of the sample app's hooks across 3 versions. Done 2026-11-07 (at /O2 7 of 8 hooks resolved v1 → v2 and 6 of 8 v2 → v3, at /Od 6 and 5, including a high-criticality hook and two hooks without structural evidence through their trial runs; 0 wrong; all applied hooks behave the same; review hooks repaired from their own build; patterns, offsets header and prototype proposals checked by the loop). Struct-layout proposals added 2026-11-07 (PDB types; checked on the `basic` fixture). Recording harness added 2026-11-08 (per-call test cases recorded by the hook DLL, replayed by emulation, with globals and import calls recorded: 22 of 24 resolved hook repairs replay, all passing; the swapped negative control fails replay; §7.3) |
| **M5 MCP + AI proposer** | `permanent-beta-mcp`, local-model proposer, review explanations | AI proposals measured separately on the corpus. MCP server, review explanations, the proposer (`pbeta propose`) and its corpus scoring (`pbeta-corpus score-ai`) built 2026-11-07, first measured on Lua and zstd /O2: 31 of 32 proposals correct, the wrong one not passing verification (§8). `pbeta repair --propose` added 2026-11-07; latest measurement 75 of 77 proposals correct (/O2 and /Od), no wrong one passing verification |
| **M6 Ghidra extension** | Exporter + review UI | Usable by an external tester. Exporter done (M1). Review UI built 2026-11-08 (`integrations/ghidra/PermanentBeta`, §11.3): review items with evidence and checks, Function Comparison, accept and reject through `pbeta review`; verified end to end in Ghidra 12.2 on the hook loop. Open: an external tester |
| Later | Shared history service, IDA plugin, ELF | As users ask for them |
