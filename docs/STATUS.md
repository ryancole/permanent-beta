# Status — where we left off (2026-11-06)

M2 (corpus) is done and green in CI (`c104289`). Latest work: the similarity pass (design §5.1 pass 6), which
completes M3's matching depth apart from the mnemonic-hash pass and the SQLite store. 0 wrong matches on every
corpus variant; not yet through CI.

## What works

- **`pbeta analyze`** reads PE x64 executables with no symbols: functions from `.pdata`, call targets and
  address-taken code, with chained `.pdata` fragments merged into their parent; normalized and mnemonic hashes,
  callees in call order, strings, constants, imports, inferred register arguments, and entry hookability.
- **`pbeta match` / `repair` / `review list`**: six matching passes (name, normalized hash, strings, matched
  callees, call graph, and a weak similarity pass for edited functions); string matches are vetoed when argument counts or matched callers contradict them,
  rechecked against the final matches. Verification on parameters, strings, size, callers, callees, constants,
  imports and inferred arguments, counting only evidence independent of the match; repair with review reasons
  (unmatched, ambiguous, verification failed, insufficient evidence, signature changed, not hookable); exit codes
  0/1/2; updated manifest; append-only JSON store.
- **Corpus gate** (CI, Windows): zero wrong matches, plus correct-match baselines. Each scorecard lists every
  pass's precision and recall.
  - Purpose-built fixture `basic` (`corpus/fixtures`): 3 flag sets.
  - zlib v1.2.13 → v1.3 → v1.3.1: /O2 69 of 69, /Od 159 of 163.
  - Lua v5.4.6 → v5.4.7 → v5.4.8: /O2 706–714 of ~735, /Od 1077–1085 of ~1095.
  - zstd v1.5.5 → v1.5.6 → v1.5.7: /O2 623–669 of ~729, /Od 1674–1731 of ~1879.
  - Run locally: `pwsh corpus/build-fixtures.ps1 -Score` and `pwsh corpus/build-projects.ps1 -Score`. Add
    `--misses` to `pbeta-corpus score` to list misses.

## Progress against the original goals

| Goal | State |
|---|---|
| 1. Find the new location | Done; measured on zlib, Lua and zstd |
| 2. Verify it's the same function | Done for symbol-less binaries; PDB signatures not read |
| 3. Adapt hooks (signature/struct changes) | Detection only (inferred args, signatures if known); no adaptation |
| 4. Behavioral tests from the old version | Not started (designed, design §7.3) |
| 5. Review queue | Populated and listable; no accept/reject |
| MCP server, Ghidra extension, hosted service, IDA plugin | Not started (designed) |
| AI fallback | Not started (designed, design §8) |
| License choice, market validation | Open |

## Suggested next steps

1. **End-to-end Detours repair** (M4): a real hook DLL against the fixture's v1, repaired to v2 and run. That
   starts the behavioral harness (goal 4).
2. **Review-queue actions** (accept, reject, pick a candidate), then the MCP server. Similarity matches all
   land in review, so this is where they become usable.
3. **Calibrate the similarity thresholds** (score 0.75, margin 0.1, size 16, weights; all [Guess]) from the
   corpus: score distributions of correct vs ambiguous pairs. Fixture S3–S5 at /O2 are still unmatched.
4. **Corpus breadth:** a C++ project (vtables, which discovery can't see yet), `/LTCG` and PGO flag sets.
5. **Outside the code:** choose the license; talk to legacy-software teams (design §14).

## Known rough edges

- The hook manifest needs the build's SHA-256 typed in by hand (`pbeta analyze` prints it in its JSON). A hook
  whose `target.build` doesn't match the old binary isn't rejected yet.
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
