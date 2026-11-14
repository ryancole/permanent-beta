# Behavioral recording and replay harness (M4)

C++ (Detours). It runs inside the target process, so it is native code regardless of the core's language.

Built so far for the corpus hook app, in `corpus/hooks/hookdll/` (design §7.3):

- **Record (old build):** the hook DLL's record mode (`PBETA_RECORD`, `PBETA_SPEC`) attaches a generic
  register-capturing thunk (`record_thunk.asm`) per hook of a record spec (`pbeta harness-spec`): argument
  registers and stack, typed memory behind pointer arguments before and after the call, return registers. One JSON
  test case per distinct call, memory as content-addressed blobs.
- **Replay / compare (new build):** scenario trace diff (`pbeta trace-diff`, `repair --old-trace`) and emulation of
  the candidate on recorded cases (`permanent-beta-replay`, `pbeta replay`, `repair --cases`).

Not yet: callee sequences, memory reachable through pointers inside structs, redaction rules, and a harness DLL
for other targets (the corpus DLL's logging detours are written per prototype).

Recordings may contain whatever data the target was processing. Keep them local and support redaction rules.
