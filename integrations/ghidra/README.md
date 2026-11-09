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

## Review extension (M6)

`PermanentBeta/` is a Ghidra extension: a **Permanent Beta Review** window listing the review queue next to the
listing and decompiler. Per item: the reason, every candidate with its evidence and verification checks (and whether
each check counted as independent evidence), the verdict and past decisions. From there you go to the old function
or a candidate, compare the two side by side (Ghidra's Function Comparison), and accept or reject.

It decides nothing itself (design §11.3). It reads through `pbeta-mcp` (started as a child process with only the
store, and calling only its read tools), and a decision runs `pbeta review accept|reject`, the same command as on
the command line, so the same rules apply: a candidate verification rejected needs an explicit "accept anyway"
(`--force`), and pbeta's refusals are shown as they are. Nothing is linked into Ghidra's JVM.

### Install

Needs Ghidra 12.2, a JDK 25+ and Gradle 9.1+ to build; `pbeta.exe` and `pbeta-mcp.exe` to run
(`cargo build --release -p permanent-beta-cli -p permanent-beta-mcp`).

```powershell
cd integrations/ghidra/PermanentBeta
gradle -PGHIDRA_INSTALL_DIR="C:\path\to\ghidra_12.2"   # dist\ghidra_12.2_PUBLIC_<date>_PermanentBeta.zip
gradle -PGHIDRA_INSTALL_DIR="C:\path\to\ghidra_12.2" selfTest
```

In Ghidra: **File > Install Extensions**, **+**, pick the zip, restart Ghidra. When a CodeBrowser opens it offers the
new plugin; otherwise **File > Configure**, *Permanent Beta*, tick **PermanentBetaPlugin**.

Then **Edit > Tool Options > Permanent Beta**:

| Option | Value |
|---|---|
| pbeta executable | full path to `pbeta.exe` (or `pbeta` if it's on PATH) |
| pbeta-mcp executable | full path to `pbeta-mcp.exe` |
| Review store | the store `pbeta repair --store` wrote, e.g. `.pbeta\store.json` |
| Reviewer | your name; recorded with every decision |

### Use

1. Run a repair with a store, so there is something to review:
   `pbeta repair --old v1.json --new v2.json --hooks hooks.toml --store .pbeta\store.json`.
2. Import the old and the new executable into one Ghidra project and open both in the CodeBrowser (tabs). A program
   is tied to a build by its executable's SHA-256, which Ghidra records at import and which is pbeta's build id, so
   import the exact files that were analyzed. A program whose hash isn't the item's build is never used.
3. **Window > Permanent Beta Review**. The top table is the open items (the funnel toggle adds decided ones);
   select one to see its candidates, and a candidate to see its evidence and checks.
4. Toolbar or right-click: **Go To Old Function**, **Go To Candidate**, **Compare Functions** (needs a Ghidra
   function at both addresses), **Accept Candidate** (the selected one), **Reject Item** (none of the candidates is
   the counterpart). Each asks for an optional note, then runs `pbeta review` and refreshes.
5. Rerun `pbeta repair --store ...`: a hook whose item you accepted is resolved to your choice, a rejected pair is
   never used again.

Try it on the hook loop (`pwsh corpus/build-hooks.ps1 -Run`, then step 1 with
`target/hooks/o2/v2/analysis.json` → `v3`, hooks `v2/hooks.toml`, `--earlier v1/analysis.json`, the traces as in
`corpus/build-hooks.ps1`): `checksum` is ambiguous between `0x1040` and an identical `checksum_backup` at
`0x1070` added in v3 (the map file says `0x1040` is `checksum`), and `log_event`'s only candidate is rejected by
verification (a parameter was added).

Source: `src/main/java/permanentbeta/core` (protocol client, review model, the `pbeta review` command; no Ghidra
types, tested by `src/test/.../SelfTest.java` against recorded `pbeta-mcp` replies) and
`src/main/java/permanentbeta/ghidra` (the plugin and window).
