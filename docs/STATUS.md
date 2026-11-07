# Status — where we left off (2026-11-07)

M2 (corpus) is done, M3's matching depth is done apart from the SQLite store (deferred), and **M4
(repair loop) is done** apart from the recording harness and struct-layout proposals. 0 wrong matches on every
corpus variant, 0 wrong relocations in the hook loop.

Latest work: **M1 spikes, PDB and diff** (design §4.4). `pbeta analyze --pdb` adds PDB names and signatures
(refused for another build's PDB; folded entries stay unnamed), and `pbeta analysis-diff` compares two analyses of
one build. The first diff report, native vs PDB on every corpus variant: no hash or name disagreement; native
finds the import thunks the PDB has no symbol for; it misses functions reached only through data (function
tables, dead code), and where such a function has no `.pdata` the previous function **absorbs** it (zstd /O2's
`ZSTD_writeLastEmptyBlock`: 147 bytes natively, 29 in the PDB). **Fixed:** function starts now also come from
code pointers in data (base relocations). Every /O2 build finds every PDB function; only unreferenced dead code
at /Od is left. Lua /O2 +10 correct per variant, zstd /O2 +3 to +4, 0 wrong; baselines raised. The Ghidra
exporter is still to do; Java and Ghidra aren't installed here.

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
  (base relocations), call targets and address-taken code, with chained `.pdata` fragments merged into their
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
- **`pbeta match` / `repair` / `review list|accept|reject`**: six matching passes (name, normalized hash, strings, matched
  callees, call graph, and a weak similarity pass for edited functions); string matches are vetoed when argument counts or matched callers contradict them,
  rechecked against the final matches. Verification on parameters, strings, size, callers, callees, constants,
  imports and inferred arguments, counting only evidence independent of the match; repair with review reasons
  (unmatched, ambiguous, verification failed, insufficient evidence, signature changed, not hookable, stale
  locator); exit codes
  0/1/2; updated manifest; append-only JSON store.
- **Corpus gate** (CI, Windows): zero wrong matches, plus correct-match baselines. Each scorecard lists every
  pass's precision and recall.
  - Purpose-built fixture `basic` (`corpus/fixtures`): 3 flag sets.
  - zlib v1.2.13 → v1.3 → v1.3.1: /O2 69 of 69, /Od 159 of 163.
  - Lua v5.4.6 → v5.4.7 → v5.4.8: /O2 726–732 of ~735, /Od 1086–1092 of ~1095.
  - zstd v1.5.5 → v1.5.6 → v1.5.7: /O2 671–679 of ~729 (/O2+ICF 657–665), /Od 1700–1738 of ~1879.
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
| Ghidra extension, hosted service, IDA plugin | Not started (designed) |
| AI fallback | Built and measured (M5): 54 of 56 proposals correct on Lua and zstd, /O2 and /Od; `none` on deleted functions apart from near misses; no wrong proposal passes verification (design §8) |
| License choice, market validation | Open |

## Suggested next steps

0. **Ghidra headless exporter** (needs a JDK 21 and Ghidra 11.x), diffed against the native analysis with
   `pbeta analysis-diff`, to close M1.
1. **Decide whether `pbeta propose` runs as part of `repair`** for unmatched hook targets (proposals into the
   hook's review item, never applied). Optionally describe unmatched callees in the prompt, the lever for zstd's
   `*_noDict_*` family; instruction text wouldn't separate it (design §8).
2. **Corpus breadth:** a C++ project (vtables, which discovery can't see yet), `/LTCG` and PGO flag sets.
3. **Rest of M4's design:** the recording harness (per-call test cases with memory, §7.3) and struct-layout
   proposals; both lean on PDB or Ghidra types.
4. **Outside the code:** choose the license; talk to legacy-software teams (design §14).

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
- Renames in the answer key are declared by hand. zstd lists only the renames the engine matched; an
  undeclared rename shows up as a "wrong" match and must be checked against the sources before declaring it.
- Dead code without `.pdata` is absorbed into the function before it when nothing marks its start (design §4.4):
  its code is hashed as part of that function. Seen only at /Od on the corpus.
- Dead code without `.pdata` (nothing references it) is never discovered: zlib /Od's `compressBound`,
  `get_crc_table`, `zlibVersion`, `zError`.
- Once one copy in a group of identical code is resolved, the hash pass can pair the remaining copies by
  elimination, even if their callees differ. No wrong match from it on the corpus so far.
