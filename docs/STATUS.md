# Status — where we left off (2026-11-05)

Last commit: `e8abb4e` on `master`, pushed. CI runs for the two latest pushes (`ee84771`, `e8abb4e`) were not
checked. They include the first GitHub run of the zlib corpus step. If it fails, the likely cause is the
runner's MSVC laying out code differently: adjust the baselines in `corpus/projects/zlib/expected.toml`, and keep
wrong matches at 0.

## What works

- **`pbeta analyze`** reads PE x64 executables with no symbols: functions from `.pdata` plus call targets,
  normalized and mnemonic hashes, callees in call order, strings, constants, imports, inferred register
  arguments, and entry hookability.
- **`pbeta match` / `repair` / `review list`**: four matching passes (name, normalized hash, strings, call
  graph); verification on parameters, strings, size, callers, callees, constants, imports and inferred
  arguments, counting only evidence independent of the match; repair with review reasons (unmatched,
  ambiguous, verification failed, insufficient evidence, signature changed, not hookable); exit codes 0/1/2;
  updated manifest; append-only JSON store.
- **Corpus gate** (CI, Windows): zero wrong matches, plus correct-match baselines.
  - Purpose-built fixture `basic` (`corpus/fixtures`): 3 flag sets.
  - zlib v1.2.13 → v1.3 → v1.3.1 (`corpus/projects/zlib`): /O2 61 of 69 correct, /Od 150–152 of 163, 0 wrong.
  - Run locally: `pwsh corpus/build-fixtures.ps1 -Score` and `pwsh corpus/build-projects.ps1 -Score`. Add
    `--misses` to `pbeta-corpus score` to list misses.

## Progress against the original goals

| Goal | State |
|---|---|
| 1. Find the new location | Done; measured on zlib |
| 2. Verify it's the same function | Done for symbol-less binaries; PDB signatures not read |
| 3. Adapt hooks (signature/struct changes) | Detection only (inferred args, signatures if known); no adaptation |
| 4. Behavioral tests from the old version | Not started (designed, design §7.3) |
| 5. Review queue | Populated and listable; no accept/reject |
| MCP server, Ghidra extension, hosted service, IDA plugin | Not started (designed) |
| AI fallback | Not started (designed, design §8) |
| License choice, market validation | Open |

## Suggested next steps

1. **Callee-based matching pass:** match a function by the set of already-matched functions it calls. It
   targets most of the remaining zlib /O2 misses (`adler32`/`crc32` tail-call wrappers, small helpers).
2. **Similarity matching for edited functions** (design §5.1 pass 6), with a best-vs-second-best margin.
   Fixture scenarios S3–S5 are still ambiguous or unmatched.
3. **A second real-world project with more churn between releases** (e.g. SQLite or libcurl), so tuning isn't
   only against zlib.
4. **End-to-end Detours repair:** a real hook DLL against the fixture's v1, repaired to v2 and run. That starts
   the behavioral harness (goal 4).
5. **Review-queue actions** (accept, reject, pick a candidate), then the MCP server.
6. **Outside the code:** choose the license; talk to legacy-software teams (design §14).

## Known rough edges

- The hook manifest needs the build's SHA-256 typed in by hand (`pbeta analyze` prints it in its JSON). A hook
  whose `target.build` doesn't match the old binary isn't rejected yet.
- AOB patterns are kept as they are, not regenerated or re-validated.
- Call-sequence pairing by position is a review suggestion only. In the ICF build it suggests `pb_deleted` →
  `pb_body_edited`, which is misleading but not a wrong match.
- `.exe` hashes change on every rebuild even with `/Brepro` (PE timestamp, PDB signature), so a build ID is
  per build.
