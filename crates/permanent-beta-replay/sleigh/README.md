# Ghidra's x86 SLEIGH specification (vendored)

`x86/` is `Ghidra/Processors/x86/` from **Ghidra 12.2** (the release built 2026-10-16), limited to what icicle
compiles: `data/languages/` without the compiled `.sla` files, the DWARF mappings, `x86.opinion`, `x86-16.gdis` and
`old/`. The files are unchanged. Ghidra is released under the Apache License 2.0 (`LICENSE-APACHE-2.0.txt`, Ghidra's
top-level `LICENSE`; `x86/LICENSE.txt` is the module's own notice, which lists no third-party files).

`permanent-beta-replay`'s `emulator` feature embeds these files (`src/sleigh.rs`) and unpacks them on first use to
a directory under the system temp directory named after their content hash. icicle compiles the x86-64 language
(`x86:LE:64:default`) from there (`src/emulate.rs`). Replay's instruction semantics are therefore pinned to this
version, and no Ghidra install is needed.

`.gitattributes` keeps them byte-for-byte (`-text`).

**Updating:** copy `data/languages/` (minus the files above) from a newer Ghidra install, regenerate the file list
in `src/sleigh.rs`, update the version here, and rerun the replay tests with `--features emulator` and
`corpus/build-hooks.ps1 -Run -Replay`.
