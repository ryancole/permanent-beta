# Status — where we left off (2026-11-07)

M2 (corpus) is done, M3's matching depth is done apart from the SQLite store (deferred), and **M4
(repair loop) is done** apart from the recording harness and struct-layout proposals. 0 wrong matches on every
corpus variant, 0 wrong relocations in the hook loop.

Latest work: finishing M4 (`corpus/build-hooks.ps1 -Run`, `corpus/hooks/README.md`). Results, the same shape at
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

- **`pbeta analyze`** reads PE x64 executables with no symbols: functions from `.pdata`, call targets and
  address-taken code, with chained `.pdata` fragments merged into their parent; normalized and mnemonic hashes,
  callees in call order, strings, constants, imports, inferred register arguments, and entry hookability.
- **`pbeta trace-diff`** (design §7.3, scenario trace diff): compares two runs' traces hook by hook (missed,
  different or failed calls, crashes, review hooks applied or silently skipped). `pbeta repair --old-trace
  --new-trace` adds the same evidence to verification (`TraceDiffRunner`).
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
  - Lua v5.4.6 → v5.4.7 → v5.4.8: /O2 710–716 of ~735, /Od 1079–1085 of ~1095.
  - zstd v1.5.5 → v1.5.6 → v1.5.7: /O2 667–676 of ~729 (/O2+ICF 653–662), /Od 1700–1738 of ~1879.
  - Hook-repair loop (`corpus/hooks`): 8 Detours hooks across 3 versions, /O2 and /Od, 0 wrong relocations,
    with trial runs, patterns, the header and proposed shims checked.
  - Run locally: `pwsh corpus/build-fixtures.ps1 -Score`, `pwsh corpus/build-projects.ps1 -Score` and
    `pwsh corpus/build-hooks.ps1 -Run`. Add
    `--misses` to `pbeta-corpus score` to list misses.

## Progress against the original goals

| Goal | State |
|---|---|
| 1. Find the new location | Done; measured on zlib, Lua and zstd |
| 2. Verify it's the same function | Done for symbol-less binaries; PDB signatures not read |
| 3. Adapt hooks (signature/struct changes) | Proposals for added register parameters (prototype + shim); struct layouts not started |
| 4. Behavioral tests from the old version | Scenario trace diff and trial runs done (M4); recorded per-call test cases and replay not started |
| 5. Review queue | Listable with candidates; accept / reject / pick a candidate, honored by `repair --store` |
| MCP server | Done (M5): read tools, explanations, proposals into review |
| Ghidra extension, hosted service, IDA plugin | Not started (designed) |
| AI fallback | Agents can propose through the MCP server; the built-in proposer and its corpus metrics not started (design §8) |
| License choice, market validation | Open |

## Suggested next steps

1. **AI proposer** (M5, design §8): a local-model proposer for unmatched functions, through the same
   verification, measured separately on the corpus (precision, acceptance rate). The MCP server already takes
   proposals; this adds one that runs without an agent and gets scored.
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
- Dead code without `.pdata` (nothing references it) is never discovered: zlib /Od's `compressBound`,
  `get_crc_table`, `zlibVersion`, `zError`.
- Once one copy in a group of identical code is resolved, the hash pass can pair the remaining copies by
  elimination, even if their callees differ. No wrong match from it on the corpus so far.
