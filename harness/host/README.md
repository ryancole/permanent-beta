# pbeta hook host

One Detours DLL that hooks any x64 program at the addresses pbeta found, with no address in your code and, for
logging or short-circuiting a function, no code at all.

```
pbeta repair ...          ->  repaired hook manifests (one per build)
pbeta host-config ...     ->  pbeta-host.toml (every build's hooks: RVA, pattern, action, argument decoding)
pbeta-launch pbeta-host.toml app.exe
```

On load, `pbeta-host.dll` hashes the executable it's in (SHA-256, the build id `pbeta analyze` records) and attaches
only the hooks listed for that build. A hook is attached only after the code at its RVA matches its pattern, when it
has one. A build missing from the config gets no hooks, so the program runs as it would without the host. A hook
that `repair` sent to review stays listed for the build where it was verified, so it's never attached in the new one.

## Actions

Set per hook with `detour` in the hook manifest (`repair` carries it forward), then run `pbeta host-config` again:

| `detour` | What happens on a call |
|---|---|
| `log` (or no `detour`) | Logs the arguments and the result; the original runs. |
| `skip` | Logs the call; the original doesn't run; returns 0. |
| `return <n>` | Logs the call; the original doesn't run; returns `n` (integer or pointer results only). |
| `<file.dll>!<export>` | Your handler runs instead (below). The DLL path is relative to the config's folder. |

The log decodes arguments by the hook's prototype: the manifest's `prototype`, or, with `--analysis`, the build's PDB
signature. Integers and floats print as values, pointers in hex, `char*`/`wchar_t*` (and `LPCSTR`, `LPCWSTR`, …) as
text too. Without a prototype it shows the four integer argument registers.

Built-in actions go through one generic thunk (`host_thunk.asm`), so they work for any prototype up to 12
parameters (4 in registers, 8 on the stack), except variadic functions. Up to 64 hooks per process use it; handlers
don't count.

## Handlers

A handler is your code for one function. It needs no Detours and knows no addresses:

```cpp
#include <pbeta_handler.h>

PBETA_HOOK(BOOL, CenterWindow, (HWND hWnd)) {
    pbeta_log("centering %p", hWnd);              // into the host's log
    return PBETA_ORIGINAL(CenterWindow)(hWnd);    // call through, or don't
}
```

Build it as a DLL with `target/host/include` on the include path (`cl /LD /I<...>\target\host\include
handlers.cpp`), and set `detour = "handlers.dll!CenterWindow"`. The host loads it, attaches `CenterWindow` in the
original's place and sets `pbeta_original_CenterWindow` to the original. The prototype must match the hooked
function's exactly, and nothing checks it when the DLL is loaded, so let pbeta write the declarations:

```
pbeta handler-stubs --hooks hooks.toml [--analysis app.json] --out handlers.cpp
```

For every hook whose `detour` is a handler, it writes the `PBETA_HOOK` declaration from the hooked function's
prototype (the manifest's, or with `--analysis` the build's PDB signature) and a body that calls the original, so
the DLL compiles and changes nothing until you edit a body. Pass every build's manifest: an export used in several
builds must have one prototype in all of them, or it's an error (give each its own export). It doesn't overwrite an
existing file without `--force`, and lists the hooks it can't write (no prototype; a variadic, function-pointer or
array parameter).

## Running

```
pbeta-launch [--log <file>] <pbeta-host.toml> <app.exe> [app args...]
```

The app starts suspended with the host added to its import table, so hooks are attached before its own code runs.
The log (default `pbeta-host.log` next to the config) is appended to and holds whatever the arguments contain.
`PBETA_HOST_CONFIG` and `PBETA_HOST_LOG` set the same paths when the host is loaded some other way.

## Building

```
pwsh harness/host/build.ps1
```

Writes `target/host`: `pbeta-host.dll`, `pbeta-launch.exe` (keep them together) and `include/pbeta_handler.h`.
Needs the MSVC x64 toolset; Microsoft Detours (MIT) is cloned at a pinned commit and built if
`target/hooks-src/Detours` doesn't have it.

## Testing

```
pwsh harness/host/test.ps1
```

About a minute (more the first time, when Detours is built). Builds a test app twice (`test/hosttest.cpp`; the
second build moves every function), lets pbeta locate its seven hooks in both, and runs both builds under the host
in each scenario: every hook logging (the app's output must be identical to an unhooked run), `return` and `skip`,
handlers that replace the original or call through (`test/hosttest_handlers.cpp`), every hook handled by stubs from
`pbeta handler-stubs` (two declared from PDB signatures; output unchanged), and three negatives (a build the config doesn't list, a pattern that
doesn't match, a handler DLL without the export). The functions cover what the thunk must get right: eight stack
arguments, float and double arguments and results, mixed slots, a void result, strings, direct recursion, four threads.
The app prints its own results, so a corrupted register or stack slot fails as a wrong number. Checked against
two deliberately broken thunks (stack arguments off by one slot, `xmm1` not restored): both fail.

## Limits

- x64 only. The launcher starts the program; attaching to a running process isn't built.
- A handler's prototype isn't checked against the function when the DLL loads; `pbeta handler-stubs` writes it
  from the function's prototype instead.
- The log is plain text, one line per call, unbuffered: very hot functions slow the program down.
