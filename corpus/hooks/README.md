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
| `hooks.template.toml` | The hooks, written against v1 by symbol. `pbeta-corpus hook-manifest` resolves the symbols through v1's linker map and drops them, so repair sees RVAs only. |
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
2. **Each step** (v1 → v2, v2 → v3), from the previous step's manifest:
   - `pbeta repair` writes the repaired manifest (`repair.json` keeps its report).
   - **Answer key** (`pbeta-corpus hook-check`): every re-bound hook must land on the function with the same symbol
     in the new map. A wrong relocation fails. So does resolving a hook whose locator wasn't valid for the old build.
     The step must also meet `expected.toml`.
   - **Run:** the new version runs under the repaired manifest.
   - **Trace diff** (`pbeta trace-diff --repair repair.json`): every applied hook must see the same calls, arguments
     and results as in the previous version's run. A hook that doesn't fire, fires differently, fails to attach,
     or crashes the app fails. So does a hook repair sent to review that was applied anyway, or one that was skipped
     without being reported.
   - **Behavioral evidence:** `pbeta repair --old-trace --new-trace` re-runs verification with the traces
     (`TraceDiffRunner`, design §6.2). Every hook it resolves must have a passing behavioral check, and none may fail.
3. **Negative control:** `price_lookup` and `stock_level` (both `int f(int)`) swap RVAs in the v2 manifest. Both
   the answer key and the trace diff must catch it.

The script prints a per-hook table (repair outcome and trace-diff outcome for each step) and exits 1 on any
failure.

## Limits

- One scripted scenario: a hook is only checked on the calls this run makes. A wrong target with identical
  arguments and results for those calls would pass the trace diff (the answer key would still catch it here).
- Detours are written against v1's prototypes and struct layout. A changed signature goes to review instead of
  being adapted (design §7.2).
- A hook sent to review stays bound to its old build, so later steps report it as `stale_locator` until a reviewer
  decides it, or it's repaired from its own build.
- High-criticality hooks need a behavioral pass before they're accepted, but the harness only runs accepted hooks.
  Trial runs of review candidates are not built yet, so every hook here is `normal`.
