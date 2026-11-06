# Behavioral recording and replay harness (planned, M4)

C++ (Detours). It runs inside the target process, so it is native code regardless of the core's language.

- **Record (old build):** logging detours at hook sites capture args, typed memory, return value, writes and
  callees. Output is test cases in the format sketched in design §7.3.
- **Replay / compare (new build):** scenario trace diff first, then emulation for leaf-ish functions (design §7.3,
  open questions 11–12).

Recordings may contain customer data. Keep them local and support redaction rules.
