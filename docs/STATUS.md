# Status — where we left off (2026-11-07)

**M1 (spikes) is done**, M2 (corpus) is done, M3's matching depth is done apart from the SQLite store (deferred), and **M4
(repair loop) is done** apart from the recording harness and struct-layout proposals. 0 wrong matches on every
corpus variant, 0 wrong relocations in the hook loop.

Latest work: **table-slot matching** (design §5.1 pass 5b). The analyzer records code-pointer tables (runs of
≥ 2 relocated pointers to function starts in data: vtables and C function tables), and a new pass pairs the
functions at the same slot of corresponding tables when their code is identical. On TinyXML-2 that tells apart
the byte-identical tiny virtuals: /O2 +39 to +51 correct, /Od +38 to +44, /O2+ICF +5 to +9; zstd +9 at /O2 and
+34 at /Od from its function tables. 0 wrong everywhere; zlib, Lua, the fixtures and the hook loop unchanged.
Most of the new C++ matches go to review: table position implies no verification check, and a `return null`
body has nothing else to check.

Before that: **the first C++ project, TinyXML-2** (9.0.0 → 10.0.0 → 10.1.0, its `xmltest` driver with the
library compiled in). 0 wrong on all six variants: /O2 194–196 of ~267, /O2+ICF 199–203 of ~228, /Od 392–395 of
~474. Code reachable only through vtables is found (base relocations): only 5–15 functions per variant are
unmatched. Most misses are ambiguous and go to review: tiny virtual overrides that are byte-identical across
classes (`XMLNode`'s `ToElement`, `ToText`, … returning null). The first run's 5–18 "wrong" per variant were all
in the answer key: decorated names change with the signature (`int` → `size_t`) and with a function-local class's
scope number, and `main$dtor$N` funclets are renumbered. The answer key now joins C++ leftovers by undecorated name
(with, then without, the signature; unique on both sides; template arguments kept) and leaves funclets out. The
other projects' scores are unchanged.

Before that: **dead code found from layout** (design §4.2, §4.4). Code on a 16-byte boundary right after
`int3` padding is a function start once nothing else is found (not where its own function branches to it, never
inside a `.pdata` function). Every build now finds every function its PDB lists, with no new false start; /Od +1
to +6 correct per variant, 0 wrong, baselines raised; /O2 and the hook loop unchanged.

Before that: **Ghidra headless exporter, closing M1** (design §4.3, §4.4). `integrations/ghidra/scripts/` export
Ghidra 12.2's functions with its PDB analyzers off; `pbeta analyze --functions-from` hashes them natively (equal
bodies give equal hashes, fixture-tested); `corpus/ghidra-diff.ps1` writes the three-way report (native, Ghidra,
PDB) for the newest tag of every project and flag set. Judged by the PDB, native is right far more often: in 967
of 975 size disagreements, and Ghidra misses the table-referenced functions native finds through relocations.
Ghidra's one win is three unreferenced zstd /Od functions (two of which native absorbs). Decision: native stays
the source of boundaries; Ghidra is for pseudocode (stored now, optional) and types later. Ghidra's names and
inferred signatures are never used.

Before that: **M1 spikes, PDB and diff** (design §4.4). `pbeta analyze --pdb` adds PDB names and signatures
(refused for another build's PDB; folded entries stay unnamed), and `pbeta analysis-diff` compares two analyses of
one build. The first diff report, native vs PDB on every corpus variant: no hash or name disagreement; native
finds the import thunks the PDB has no symbol for; it misses functions reached only through data (function
tables, dead code), and where such a function has no `.pdata` the previous function **absorbs** it (zstd /O2's
`ZSTD_writeLastEmptyBlock`: 147 bytes natively, 29 in the PDB). **Fixed:** function starts now also come from
code pointers in data (base relocations). Every /O2 build finds every PDB function; only unreferenced dead code
at /Od is left. Lua /O2 +10 correct per variant, zstd /O2 +3 to +4, 0 wrong; baselines raised.

Before that: **widening the AI measurement** (design §8). /Od and deleted functions measured: 54 of 56 proposals
correct across Lua and zstd, /O2 and /Od; on deleted functions Claude answered `none` except for two near misses;
no wrong proposal passes verification. The analyzer now hashes import names (analysis schema 2): Lua's `math_*`
wrappers, which Claude couldn't tell apart, are now matched by the engine itself (+6 to +7 correct per Lua
variant, 0 wrong). `score-ai --select deleted|present` picks the questions. One more zstd rename declared
(`BMK_benchCLevel` → `BMK_benchCLevels`, found by Claude).

Before that: finishing M4 (`corpus/build-hooks.ps1 -Run`, `corpus/hooks/README.md`). Results, the same shape at
/O2 and /Od:

| Hook | v1 → v2 | v2 → v3 |
|---|---|---|
| `price_lookup`, `stock_level`, `format_receipt` | relocated, same trace | relocated (/Od: some unchanged), same trace |
| `order_add` (high criticality) | relocated after its trial run, same trace | same |
| `checksum` | relocated, same trace | review: ambiguous (identical `checksum_backup` added) |
| `ship_order` | relocated, same trace | relocated after its trial run (no independent structural evidence), same trace |
| `log_event` | review (parameter added), with a prototype proposal and a shim that compiles | repaired from v1: same review, same proposal |
| `apply_discount` | /O2: unchanged after its trial run (body rewritten, same results); /Od: review (unmatched) | /O2: unchanged after its trial; /Od: repaired from v1, still unmatched |

What's new:

- **Trial runs** (`pbeta repair --trial-out`): review candidates whose only missing evidence is behavioral are
  bound in a trial manifest, run, and judged from that run. This is how a high-criticality hook earns its
  behavioral pass.
- **Repair from the hook's own build** (`--earlier`): hooks still bound to v1 are matched v1 → v3, not reported
  as stale. Behavioral evidence is always taken from the trace of the candidate's own build.
- **AOB patterns** (`--new-binary`, `pbeta pattern`): regenerated for every re-bound hook, unique in the code,
  and checked against the new binary by the answer key. A re-bound hook no longer carries its old, unchecked
  pattern.
- **Offsets header** (`pbeta header`): `hooks.gen.h` from the manifests; compiles as C and C++.
- **Prototype proposals**: added register parameters (typed from the register class the analyzer now records,
  `inferred_arg_classes`) with a shim that keeps the existing detour unchanged.
- **Mnemonic-hash pass** (M3, design §5.1 pass 4): same instruction sequence with changed operands, gated on size
  (≥ 32 bytes) and an agreeing matched neighbour. 0 wrong; zstd up to +23 correct per variant and ~60 more
  accepted per /O2 variant.
- **Similarity thresholds calibrated** with the new `pbeta-corpus sweep` (a threshold grid scored over all 21
  corpus variants): score 0.75 is the lowest with 0 wrong (0.70 gives 2), margin lowered 0.1 → 0.05 (+108
  correct, 0 wrong), size kept at 16. Weights are still guesses. Baselines raised for Lua and zstd.
- **Policy:** a behavioral pass now counts as one independent pass for low and normal criticality (design §6.3);
  high still needs 2 structural passes plus the behavioral pass. That resolves `apply_discount` (/O2) and
  `ship_order` (v2 → v3) through their trial runs, both correct per the answer key; hook-loop baselines raised.
- The ambiguity message no longer calls a single, unconfirmed candidate "equally plausible".
- CI's hook-loop step failed on the previous commit although the loop passed: the negative control's last exit
  code (1, by design) leaked out of the script. It now exits 0 explicitly.

## What works

- **`pbeta analyze`** reads PE x64 executables with no symbols: functions from `.pdata`, code pointers in data
  (base relocations), call targets, address-taken code and code after `int3` padding, with chained `.pdata` fragments merged into their
  parent; with `--pdb`, names and signatures from the build's PDB; normalized and mnemonic hashes,
  callees in call order, strings, constants, imports, inferred register arguments, and entry hookability.
- **`pbeta trace-diff`** (design §7.3, scenario trace diff): compares two runs' traces hook by hook (missed,
  different or failed calls, crashes, review hooks applied or silently skipped). `pbeta repair --old-trace
  --new-trace` adds the same evidence to verification (`TraceDiffRunner`).
- **AI proposer** (M5, design §8): new `permanent-beta-ai` crate. For each function matching left unmatched it
  shows Claude (through the Claude Code CLI, on a Claude subscription) the function's features and its 5
  closest unmatched new functions, and takes a strict `{choice, confidence, rationale}` answer, `none` allowed.
  `pbeta propose` verifies each proposal and queues it for review; it needs `--allow-remote` and logs every
  exchange, which `--replay` reuses. `pbeta-corpus score-ai` scores answers against the answer keys. First
  measurement on Lua and zstd /O2 (63 questions): 32 proposals, 31 correct; the wrong one (another object
  file's copy of the same static function) doesn't pass verification; 31 cautious `none`s.
- **`pbeta-mcp`** (M5, design §11.2): MCP server over stdio. Agents list builds, read functions and candidates,
  run verification, list and explain review items, and propose mappings, which are verified and queued as
  `ai_proposal` items. Agents can't accept; `pbeta review accept` decides.
- **`pbeta repair --trial-out / --earlier / --new-binary`, `pbeta pattern`, `pbeta header`** (M4): trial
  manifests, repair from a hook's own build, AOB patterns, the offsets header, and prototype proposals in review
  items (see above, and design §7.2).
- **`pbeta match` / `repair` / `review list|accept|reject`**: eight matching passes (name, normalized hash, strings,
  mnemonic hash, matched callees, call graph, vtable/function-table slots, and a weak similarity pass for edited
  functions); string matches are vetoed when argument counts or matched callers contradict them,
  rechecked against the final matches. Verification on parameters, strings, size, callers, callees, constants,
  imports and inferred arguments, counting only evidence independent of the match; repair with review reasons
  (unmatched, ambiguous, verification failed, insufficient evidence, signature changed, not hookable, stale
  locator); exit codes
  0/1/2; updated manifest; append-only JSON store.
- **Corpus gate** (CI, Windows): zero wrong matches, plus correct-match baselines. Each scorecard lists every
  pass's precision and recall.
  - Purpose-built fixture `basic` (`corpus/fixtures`): 3 flag sets.
  - zlib v1.2.13 → v1.3 → v1.3.1: /O2 69 of 69, /Od 160–161 of 163.
  - Lua v5.4.6 → v5.4.7 → v5.4.8: /O2 726–732 of ~735, /Od 1087–1093 of ~1095.
  - zstd v1.5.5 → v1.5.6 → v1.5.7: /O2 680–688 of ~729 (/O2+ICF 666–674), /Od 1739–1778 of ~1879.
  - TinyXML-2 9.0.0 → 10.0.0 → 10.1.0 (C++): /O2 233–247 of ~267 (/O2+ICF 204–212 of ~228), /Od 433–436 of ~474.
  - Hook-repair loop (`corpus/hooks`): 8 Detours hooks across 3 versions, /O2 and /Od, 0 wrong relocations,
    with trial runs, patterns, the header and proposed shims checked.
  - Run locally: `pwsh corpus/build-fixtures.ps1 -Score`, `pwsh corpus/build-projects.ps1 -Score` and
    `pwsh corpus/build-hooks.ps1 -Run`. Add
    `--misses` to `pbeta-corpus score` to list misses.

## Progress against the original goals

| Goal | State |
|---|---|
| 1. Find the new location | Done; measured on zlib, Lua and zstd |
| 2. Verify it's the same function | Done for symbol-less binaries; with `--pdb`, signatures feed the parameter-count check (not yet measured on the corpus) |
| 3. Adapt hooks (signature/struct changes) | Proposals for added register parameters (prototype + shim); struct layouts not started |
| 4. Behavioral tests from the old version | Scenario trace diff and trial runs done (M4); recorded per-call test cases and replay not started |
| 5. Review queue | Listable with candidates; accept / reject / pick a candidate, honored by `repair --store` |
| MCP server | Done (M5): read tools, explanations, proposals into review |
| Ghidra | Headless exporter done (M1): boundaries cross-checked, pseudocode stored; UI extension (M6) not started |
| Hosted service, IDA plugin | Not started (designed) |
| AI fallback | Built and measured (M5): 54 of 56 proposals correct on Lua and zstd, /O2 and /Od; `none` on deleted functions apart from near misses; no wrong proposal passes verification (design §8) |
| License choice, market validation | Open |

## Suggested next steps

1. **Decide whether `pbeta propose` runs as part of `repair`** for unmatched hook targets (proposals into the
   hook's review item, never applied). Optionally describe unmatched callees in the prompt, the lever for zstd's
   `*_noDict_*` family; instruction text wouldn't separate it (design §8).
2. **Acceptance for table-slot matches:** they're correct on the corpus but mostly held for review. Decide
   whether a corresponding table counts as an independent structural check (it is independent of the code hash),
   measured on the corpus before changing policy.
3. **Corpus breadth:** a C++ project heavy on exceptions and the STL (yaml-cpp), `/LTCG` and PGO flag sets.
4. **Rest of M4's design:** the recording harness (per-call test cases with memory, §7.3) and struct-layout
   proposals; both lean on PDB or Ghidra types.
5. **Outside the code:** choose the license; talk to legacy-software teams (design §14).

## Known rough edges

- The hook manifest needs the build's SHA-256 typed in by hand (`pbeta analyze` prints it in its JSON);
  `pbeta-corpus hook-manifest` does it for the corpus only.
- The trace diff checks one scripted scenario: a wrong target that happens to see the same arguments and results
  for those calls would pass it. The detours log by-value arguments written per prototype by hand.
- AOB patterns are only regenerated with `--new-binary`; without it a re-bound hook has no pattern. The minimum
  length (8 bytes) is a guess, and patterns are only checked for uniqueness in the build they're made from.
- A trial run that crashes fails every candidate's behavioral check in that run, holding the whole step for
  review. One run per trialed hook would isolate it, at the cost of more runs.
- Prototype proposals only cover added register parameters (slots 1–4), with types guessed from the register
  class; stack parameters, removed or reordered ones aren't proposed.
- Call-sequence pairing by position is a review suggestion only. In the ICF build it suggests `pb_deleted` →
  `pb_body_edited`, which is misleading but not a wrong match.
- `.exe` hashes change on every rebuild even with `/Brepro` (PE timestamp, PDB signature), so a build ID is
  per build.
- Table correspondence needs same-length tables: a virtual added to a class changes its vtable's length, so that
  class's identical virtuals stay ambiguous (review). Tables are only split at pointers that aren't function
  starts; without RTTI, adjacent vtables would merge into one run.
- The matcher pairs exception-handling funclets (`main$dtor$N`) too; the answer key can't judge those pairs (they're
  out of its scope); on the first TinyXML-2 run some paired funclets of different numbers. A hook never targets
  one, but nothing stops it either.
- Renames in the answer key are declared by hand. zstd lists only the renames the engine matched; an
  undeclared rename shows up as a "wrong" match and must be checked against the sources before declaring it.
- Dead code is found only when it follows `int3` padding on a 16-byte boundary (all of it on the corpus, MSVC's
  default). Unpadded dead code would be absorbed into the function before it, as before.
- Lua /O2 has three 1-byte native-only starts just past a function's end (design §4.4), not yet explained.
- Once one copy in a group of identical code is resolved, the hash pass can pair the remaining copies by
  elimination, even if their callees differ. No wrong match from it on the corpus so far.
