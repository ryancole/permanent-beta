# Ghidra integration

## Headless exporter (M1, built)

Two GhidraScripts in `scripts/`, run by `analyzeHeadless`:

- `DisablePdb.java` (pre-script): turns every PDB analyzer off, so the export measures Ghidra's own function
  discovery. Ghidra finds a PDB through the path in the executable's debug directory even when the .exe was copied
  away from it, so the analyzers are switched off instead of relying on the PDB being absent.
- `ExportFunctions.java` (post-script, arguments `<out.json> [pseudocode]`): writes every non-external function's
  entry, body (address ranges), name and signature with where Ghidra got them, and with `pseudocode` the
  decompiler's output (30 s limit per function). It computes no hashes.

`pbeta analyze <binary> --functions-from out.json` turns that into an `AnalysisExport`. Ghidra decides the
boundaries; every hash and feature is computed by the native code, so Ghidra-based and native analyses compare
hash for hash (design §4.3). Its names are never used (placeholders, Function ID guesses, or the exports the native
code reads anyway), and its signatures only when not inferred and not on a guessed name. The rules and their
reasons are in `crates/permanent-beta-analysis/src/ghidra.rs`.

Needs a JDK 25+ and Ghidra 12.x, with `GHIDRA_INSTALL_DIR` set to the Ghidra folder (the one holding `support/`).

```powershell
pwsh corpus/ghidra-diff.ps1                       # newest tag of every corpus project, every flag set
pwsh corpus/ghidra-diff.ps1 -Project zlib -Flags o2 -Pseudocode
```

`corpus/ghidra-diff.ps1` runs the export on copies of built corpus binaries and writes three `pbeta
analysis-diff` reports per build to `target/ghidra/<build>/`: native vs Ghidra, Ghidra vs PDB, native vs PDB.
Results are in design §4.4. Local only, not run in CI (design §13 question 7).

By hand:

```powershell
& "$env:GHIDRA_INSTALL_DIR\support\analyzeHeadless.bat" <project-dir> pb -import <copy-of>.exe `
    -scriptPath integrations/ghidra/scripts -preScript DisablePdb.java `
    -postScript ExportFunctions.java out.json -deleteProject
```

## UI extension (M6, planned)

Shows mappings, evidence and review items next to the listing and decompiler, and records review decisions through
the `pbeta` CLI or a local JSON-RPC server. Nothing is linked into the JVM. Evaluate overlap with Ghidra's built-in
Version Tracking and BSim before building matching UI (design §11.3).
