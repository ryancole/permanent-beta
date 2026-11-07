# Status — where we left off (2026-11-06)

M2 (corpus) is done, and M3's matching depth is done apart from the mnemonic-hash pass and the SQLite store, with 0
wrong matches on every corpus variant. Review-queue decisions (`pbeta review accept` / `reject`) are honored by
`repair --store`.

Latest work: **M4's end-to-end loop** (not yet through CI). Real Detours hooks written against a sample app's v1
are repaired v1 → v2 → v3, checked against the answer key, run, and their call traces diffed
(`corpus/build-hooks.ps1 -Run`, `corpus/hooks/README.md`). Results, the same at /O2 and /Od:

| Hook | v1 → v2 | v2 → v3 |
|---|---|---|
| `price_lookup`, `stock_level`, `order_add`, `format_receipt` | relocated, same trace | relocated (/Od: unchanged), same trace |
| `checksum` | relocated, same trace | review: ambiguous (identical `checksum_backup` added) |
| `ship_order` | relocated, same trace | review: insufficient evidence (body edited) |
| `log_event` | review (parameter added): ambiguous at /O2, verification failed at /Od | review: stale locator |
| `apply_discount` | review (body rewritten): insufficient evidence at /O2, unmatched at /Od | review: stale locator |

0 wrong relocations. Every applied hook sees identical calls, review hooks are held and reported, and a
deliberately swapped pair is caught by both the answer key and the trace diff. The loop found a real bug: repair
trusted a locator bound to another build (v2 → v3 "relocated" `apply_discount` from its v1 RVA, correct only by
luck). Such hooks now go to review as `stale_locator`.

## What works

- **`pbeta analyze`** reads PE x64 executables with no symbols: functions from `.pdata`, call targets and
  address-taken code, with chained `.pdata` fragments merged into their parent; normalized and mnemonic hashes,
  callees in call order, strings, constants, imports, inferred register arguments, and entry hookability.
- **`pbeta trace-diff`** (design §7.3, scenario trace diff): compares two runs' traces hook by hook (missed,
  different or failed calls, crashes, review hooks applied or silently skipped). `pbeta repair --old-trace
  --new-trace` adds the same evidence to verification (`TraceDiffRunner`).
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
  - Lua v5.4.6 → v5.4.7 → v5.4.8: /O2 706–714 of ~735, /Od 1077–1085 of ~1095.
  - zstd v1.5.5 → v1.5.6 → v1.5.7: /O2 623–669 of ~729, /Od 1674–1731 of ~1879.
  - Hook-repair loop (`corpus/hooks`): 8 Detours hooks across 3 versions, /O2 and /Od, 0 wrong relocations.
  - Run locally: `pwsh corpus/build-fixtures.ps1 -Score`, `pwsh corpus/build-projects.ps1 -Score` and
    `pwsh corpus/build-hooks.ps1 -Run`. Add
    `--misses` to `pbeta-corpus score` to list misses.

## Progress against the original goals

| Goal | State |
|---|---|
| 1. Find the new location | Done; measured on zlib, Lua and zstd |
| 2. Verify it's the same function | Done for symbol-less binaries; PDB signatures not read |
| 3. Adapt hooks (signature/struct changes) | Detection only (inferred args, signatures if known); no adaptation |
| 4. Behavioral tests from the old version | Scenario trace diff done (M4); recorded per-call test cases and replay not started |
| 5. Review queue | Listable with candidates; accept / reject / pick a candidate, honored by `repair --store` |
| MCP server, Ghidra extension, hosted service, IDA plugin | Not started (designed) |
| AI fallback | Not started (designed, design §8) |
| License choice, market validation | Open |

## Suggested next steps

1. **Finish M4:** trial runs of review candidates (so high-criticality hooks can earn their behavioral pass),
   repairing a stale hook from its own build (v1 → v3), AOB regeneration, offsets header, and prototype proposals
   for `log_event`'s added parameter. The `log_event` review reads "1 functions ... equally plausible" at /O2: the
   ambiguity message should handle a single competitor.
2. **MCP server** (design §11.2): list and explain review items, propose mappings into verification. Agents
   can't accept; decisions stay with `pbeta review` (or the UI later).
3. **Calibrate the similarity thresholds** (score 0.75, margin 0.1, size 16, weights; all [Guess]) from the
   corpus: score distributions of correct vs ambiguous pairs. Fixture S3–S5 at /O2 are still unmatched.
4. **Corpus breadth:** a C++ project (vtables, which discovery can't see yet), `/LTCG` and PGO flag sets.
5. **Outside the code:** choose the license; talk to legacy-software teams (design §14).

## Known rough edges

- The hook manifest needs the build's SHA-256 typed in by hand (`pbeta analyze` prints it in its JSON);
  `pbeta-corpus hook-manifest` does it for the corpus only.
- The trace diff checks one scripted scenario: a wrong target that happens to see the same arguments and results
  for those calls would pass it. The detours log by-value arguments written per prototype by hand.
- AOB patterns are kept as they are, not regenerated or re-validated.
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
