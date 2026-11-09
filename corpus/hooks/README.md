# Hook-repair loop (M4)

End-to-end proof that a hook written against v1 keeps working after `pbeta repair` moves it to v2 and v3, by
running it (design §7.3, option 3: scenario trace diff).

```bash
pwsh corpus/build-hooks.ps1 -Run              # o2 and od
pwsh corpus/build-hooks.ps1 -Flags o2 -Run
```

Requires Visual Studio or Build Tools with the x64 C++ toolset (`cl`, `link`, `nmake`), git and network access
the first time, and cargo. Output goes to `target/hooks/<flags>/v{1,2,3}/` and `target/hooks/bin/`.

## Pieces

| Path | What |
|---|---|
| `app/v{1,2,3}/app.cpp` | Sample app: a fixed order-processing script, so every run makes the same calls. Hook targets are `extern "C"` and `noinline`. |
| `hookdll/hookdll.cpp` | Hook DLL. Reads the manifest (`pbeta`'s TOML), attaches a logging Detours detour to every hook whose locator is bound to the running build, and writes a JSON Lines trace (`attach`, `skip`, `call` with arguments and result by value, `end`). |
| `launcher/launcher.cpp` | Starts the app with the DLL injected (`DetourCreateProcessWithDllExW`), passing the manifest, trace path and the .exe's SHA-256 (its build id) through the environment. |
| `hooks.template.toml` | The hooks, written against v1 by symbol. `pbeta-corpus hook-manifest` resolves the symbols through v1's linker map and drops them, so repair sees RVAs only. `order_add` is high criticality: it needs a behavioral pass, which only a trial run can give it. |
| `expected.toml` | Per step and flag set: hooks that must be resolved (at least), and hooks that must stay in review. |

Detours (MIT) is cloned at a pinned commit and built with its own makefile; it's never committed.

Why a launcher: `DetourCreateProcessWithDllExW` is how Detours users usually load a hook DLL. The DLL lands in the
import table, so its detours are in place before the app's own code runs, and no remote-thread injection is
needed.

The DLL never attaches a hook whose `target.build` isn't the running build. That's how repair leaves a hook it
sent to review (the locator keeps its old binding), and patching it would put the old RVA on whatever code is
at that address now.

## Churn between versions

| Function | v1 → v2 | v2 → v3 |
|---|---|---|
| `price_lookup`, `stock_level`, `order_add`, `format_receipt`, `checksum`, `ship_order` | moved (`loyalty_bonus` added; the linker orders functions by name) | some move again (`checksum_backup` added); `order_add` body edited (same results); `ship_order` body edited (calls `checksum_backup`) |
| `log_event` | gains a `severity` parameter | — |
| `apply_discount` | body rewritten, same results | — |
| `checksum` | — | `checksum_backup` added with the identical body: ambiguous |

## What `-Run` checks

1. **Baseline:** v1 runs under the v1 manifest; every hook must attach and fire, and the run must exit normally.
2. **Each step** (v1 → v2, v2 → v3), from the previous step's manifest. A hook still bound to an older build
   (an earlier step sent it to review) is repaired from that build directly (`--earlier`, e.g. v1 → v3):
   - **Trial run:** `pbeta repair --trial-out` writes the repaired manifest plus trial bindings: hooks in review
     whose only missing evidence is behavioral (`insufficient_evidence`, no failing check, one patchable
     candidate) are bound to their candidates and marked `trial = true`. The new version runs under it.
   - **Decision:** `pbeta repair --old-trace <each older run> --new-trace <trial run> --new-binary` decides with
     that behavioral evidence (`TraceDiffRunner`, design §6.2; each candidate is judged against its own old
     build's run), writes the repaired manifest with AOB patterns regenerated from the new binary, and
     `repair.json` keeps its report.
   - **Answer key** (`pbeta-corpus hook-check`): every re-bound hook must land on the function with the same symbol
     in the new map, judged from the build its locator was bound to. A wrong relocation fails, and so does a
     pattern that doesn't match exactly once, at the hook's RVA. So does resolving a hook whose locator wasn't
     bound to a build repair was given. The step must also meet `expected.toml`.
   - **Run:** the new version runs under the repaired manifest.
   - **Trace diff** (`pbeta trace-diff --repair repair.json`): every applied hook must see the same calls, arguments
     and results as in the last run that applied it (for a hook repaired from v1, v1's run). A hook that doesn't
     fire, fires differently, fails to attach, or crashes the app fails. So does a hook repair sent to review
     that was applied anyway, or one that was skipped without being reported.
   - **Evidence:** every hook repair resolved must have a passing behavioral check, and none may fail.
   - **Proposals:** `log_event` (a parameter added in v2) must come with a prototype proposal, and every proposed
     shim must compile (`cl /Zs`) against the hook's existing detour.
3. **Offsets header:** `pbeta header` builds `hooks.gen.h` from the three manifests; it must compile as C and C++.
4. **Negative control:** `price_lookup` and `stock_level` (both `int f(int)`) swap RVAs in the v2 manifest. Both
   the answer key and the trace diff must catch it.

The script prints a per-hook table (repair outcome and trace-diff outcome for each step) and exits 1 on any
failure.

## Recorded test cases (`-Replay`)

```bash
pwsh corpus/build-hooks.ps1 -Run -Replay
```

Design §7.3, replay by emulation. Needs pbeta built with the `emulator` feature (Unicorn): CMake, Ninja and
libclang, found by `corpus/lib/emulator.ps1` (see `third_party/README.md`). On top of the checks above:

1. **Record:** v1 (after its baseline) and v2 (after its step) run once more under the hook DLL's record mode:
   `PBETA_RECORD` (the recording directory, `target/hooks/<flags>/<version>/rec`) and `PBETA_SPEC` (from
   `pbeta harness-spec` on the version's manifest and its `--pdb` analysis). `hookdll/record_thunk.asm` is the
   generic thunk: it captures the argument registers and stack, the DLL the memory behind pointers and the
   globals the hook can reach before and after the call, and the app's import calls during it (its import table
   points at import thunks), one JSON case per distinct call.
2. **Decide with them:** the decision step also gets `--cases` for every older version's recording. A replay
   failure would send the hook to review (and fail the step's expectations).
3. **Replay every resolved hook:** `pbeta replay` with the older recordings on the hook's new RVA. All resolved hooks
   are correct (the answer key), so none may fail; inconclusive is allowed. The script prints how many replayed.
4. **Negative control:** v1's `price_lookup` cases replayed on the function the swapped manifest gives it
   (`stock_level`'s), and the reverse, must fail.

Which hooks replay: all resolved ones (22 of 24 per run). The printing ones (`format_receipt`, `ship_order`)
replay through the stand-ins for the UCRT's `printf` and `snprintf` imports, with the CRT's options global and
`g_events` recorded. `ship_order` v1 → v2 is inconclusive, as is `order_add`'s "order full" case: their callee
`log_event` prints a severity in v2, so the `printf` inputs differ from the recording.

Recordings can contain the app's data. They stay under `target/`.

## Limits

- One scripted scenario: a hook is only checked on the calls this run makes. A wrong target with identical
  arguments and results for those calls would pass the trace diff (the answer key would still catch it here).
- Detours are written against v1's prototypes and struct layout. A changed signature goes to review instead of
  being adapted (design §7.2).
- A hook sent to review stays bound to its old build. Later steps repair it from that build when its analysis is
  given (`--earlier`), and report it as `stale_locator` otherwise.
- A behavioral pass counts as one independent pass for normal hooks, but at high criticality it's required on
  top of 2 structural passes (design §6.3). So trials resolve `apply_discount` (/O2) and `ship_order` (v2 → v3),
  which have no independent structural evidence, and `order_add` (high, with 3 independent structural passes).
  A wrong candidate that happens to behave the same in the one scenario would also pass a normal hook's trial;
  the answer key would catch it here, but nothing does in production.
- A trial run binds unverified candidates. One that crashes the app fails the behavioral check of every
  candidate in that run (the run didn't complete), which holds the step's hooks for review: safe, but noisy.
