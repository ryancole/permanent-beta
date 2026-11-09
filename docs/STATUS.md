# Status — where we left off (2026-11-08)

**M1 (spikes) is done**, M2 (corpus) is done, M3's matching depth is done apart from the SQLite store (deferred), and **M4
(repair loop) is done**, recording harness included. 0 wrong matches on every corpus variant, 0 wrong relocations in
the hook loop.

Latest work: **replay measured on real code, and a false failure fixed** (design §7.3).
- `corpus/replay-measure.ps1` (local): 16 zlib functions hooked in minigzip, compress and decompress recorded in one
  release, every case replayed on the same function (by symbol, so every pair is correct) in the next.
- It found a **false failure**: `_tr_init` stores `&static_l_desc` in its state, and the new build's address isn't
  the old one's. The recorder now saves the image's size; an address into each run's own image is no longer a
  difference, and the case is inconclusive (never a pass) since what the addresses point at isn't compared. Any
  other difference still fails. Unit tests with negatives (a plain value where an address was recorded and the
  reverse fail; a real difference next to an address fails; recordings without the size compare as before).
- `memcpy`, `memmove`, `memset` and `strlen` are now executed by replay rather than answered from the recording,
  and recorded calls to them are skipped (a build may inline them).
- Result: 1 of 16 zlib hooks replays (`crc32_z`, 18/18), 0 fail, o2 v1.3 → v1.3.1 and od v1.2.13 → v1.3. The rest
  stop on memory behind pointers inside structs (depth > 1), which is the next step. Hook loop unchanged: 22 of 24
  replay, all passing, the negative control failing (o2 and od).

Before that: **M6, the Ghidra review extension: built and verified end to end in the GUI** (design §11.3).
- Evaluated first: Version Tracking ports markup between versions, with correlator scores and no independent
  verification, no hooks and no shared decision log; BSim is a similarity search. The extension adds the review
  queue and reuses Ghidra's Function Comparison and Go To; a VT link and a BSim proposer are deferred.
- `integrations/ghidra/PermanentBeta/`: a **Permanent Beta Review** window (items, candidates with evidence and
  every check, counted or not; go to old/candidate, compare, accept, reject). It reads through `pbeta-mcp` (now
  startable with only `--store`) using read tools only, and decides only by running `pbeta review accept|reject`.
  Programs are tied to builds by the executable's SHA-256. `gradle -PGHIDRA_INSTALL_DIR=...` builds the zip
  headless; `gradle selfTest` passes 12 tests (48 checks) against recorded `pbeta-mcp` replies, negative cases
  included.
- **Verified in Ghidra 12.2** on the hook loop's /O2 v2 → v3 store: both open items listed with their checks;
  Compare Functions opened v2 and v3 at `0x1040` side by side; accepting `log_event`'s rejected candidate asked
  first (Cancel by default); Go To Old Function on `log_event` (from v1, not open) was refused with the open
  builds named; accepting `checksum` → `0x1040` (the map file's `checksum`) was recorded by `pbeta review`, and the
  next `pbeta repair --store` resolved it ("decided by Ryan", 7 of 8 hooks). Two fixes from that run: a registered
  plugin package (Ghidra created a stub for ours) and a one-line note prompt.
- Not yet tried by an external tester (the exit criterion). The README's steps are what they'd follow.

Before that: **licensed Apache-2.0** (design §11.5): `LICENSE`, `NOTICE` (crediting Ghidra's vendored x86
specification), `license = "Apache-2.0"` on every crate. Contributor terms (DCO or CLA) are still open.

Before that: **replay emulates with icicle instead of Unicorn** (design §7.3, §11.5). icicle (MIT or
Apache-2.0) executes Ghidra's SLEIGH specification of x86-64, embedded from Ghidra 12.2 (Apache-2.0) in
`permanent-beta-replay/sleigh/`, so replay and Ghidra share the instruction semantics and no build contains GPL
code. Same results: all 23 replay unit tests, and the hook loop's 22 of 24 replaying hook repairs with the
negative control failing. Memory rules are icicle's per-byte permissions; traps are breakpoints. Building the
emulator no longer needs CMake, Ninja or libclang, and the patched Unicorn crate in `third_party/` is gone.

Before that: **protected binaries refused, recordings redactable** (design §4.2, §7.3, §12).
- The analyzer refuses protected and packed binaries before reading any code: a protector's or packer's default
  section name (UPX, VMProtect, Themida/WinLicense, Enigma, ASPack, MPRESS, PECompact, Petite, NsPack), an entry
  point in a writable and executable section, or executable space with no file data. No override; analysis,
  patterns and replay all go through it. 0 of the corpus's 106 binaries and 0 of 150 System32 executables are
  refused; a copy of the hook app with `.text` made writable is (exit 2). (A copy with a `.vmp0` section was
  quarantined by Windows Defender before `pbeta` could read it; unit tests cover the names.)
- `pbeta harness-spec --redact hook.param` (or `redact = true` in the spec) never records an argument or global,
  nor import memory overlapping a redacted argument seen so far (best effort); `--no-import-memory` records no
  import memory (the guarantee). The hook loop records v1 with the customer names redacted and import memory off
  and checks no file contains a name (0, against 83–97 in the ordinary recording). Replay is unchanged (22 of 24).

Before that: **a third C++ project (JsonCpp) and the C++ guesses calibrated** (design §5.1, §6.1). JsonCpp
1.9.6 → 1.9.7 → 1.9.8 scored 0 wrong on all 10 variants on its first run. With it, two of the three C++
guesses are calibrated over 64 variants: `TABLE_MIN_ANCHORS` (1) and `WRAPPER_MIN_DIRECT_CALLERS` (2) are the
lowest clean values. The code-tables fail threshold can't be: the check never fails on the corpus. No matching
behaviour changed; the other projects' scorecards are identical.

Before that: **replay through globals and import calls** (design §7.3, goal 4): **22 of 24** resolved hook
repairs replay now, all passing (16 before).
- The analysis records each function's RIP-relative references into writable sections (`data_refs`, native) and,
  with `--pdb`, the globals they fall in (`globals`; static locals named `procedure::name`, so the CRT's printf and
  scanf `_OptionsStorage` stay apart). Optional fields: no schema bump, and all 60 corpus scorecards are identical.
- The record spec lists per hook the globals it or anything it calls refers to (`[[hook.global]]`); the recorder
  captures them before and after each call, and replay places them at the new build's RVAs by name.
- The recorder points the app's import table at import thunks and records each import call made during a
  recorded call (arguments, result, the memory behind its pointer arguments). Replay answers modelled imports
  from the recording in order, after checking the inputs (`imports.rs`: `__acrt_iob_func`, the UCRT's
  `__stdio_common_vfprintf` and `__stdio_common_vsprintf`; conversions compared by type, `%s` by content).
  Different inputs are **inconclusive**, not a fail: the first run failed `order_add` and `ship_order` v1 → v2,
  correct relocations, because their callee `log_event` prints a severity in v2. Any other import is still
  inconclusive.
- Hook loop: `format_receipt` replays everywhere, `ship_order` and `order_add` (21 of 21) v2 → v3. Left
  inconclusive: `ship_order` v1 → v2 and `order_add`'s "order full" case v1 → v2 (the `log_event` change). The
  swapped negative control still fails replay. Repair outcomes and traces unchanged; corpus gates unchanged.

Before that: **the recording harness: per-call test cases, replayed by emulation** (design §7.3, goal 4).
- `pbeta harness-spec` writes a record spec from the hook manifest, the prototypes and the build's PDB struct
  layouts: per argument its Win64 slot, value class and width, and what a pointer points to (a struct of N bytes,
  a C string, a buffer sized by the next argument [Guess], or nothing).
- The hook DLL's record mode (`PBETA_RECORD`, `PBETA_SPEC`) attaches a generic MASM thunk per hook: argument
  registers and stack, the memory behind pointers before and after the call, rax/xmm0. One JSON case per distinct
  call (model `TestCase`), memory as `sha256:` blobs, 32 per hook at most.
- New crate `permanent-beta-replay` (model only; engine and CLI depend on it): maps the new build in Unicorn, places
  the recorded memory, runs the candidate until it returns, compares the return value and the writes. An import
  call, a read of a writable section (globals), uncaptured memory, an interrupt or no return is inconclusive, never
  a pass. Changed struct layouts are translated by field name; a field that doesn't map is inconclusive.
- `RecordedCasesRunner` (engine): pass if every replayable case matches, fail if any differs, inconclusive if none
  replays. `pbeta repair --cases <dir> --new-binary` (with traces too, a failure of either fails) and
  `pbeta replay`.
- **Measured** on the hook loop (`corpus/build-hooks.ps1 -Run -Replay`, now in CI): v1 and v2 recorded, the
  decisions given the recordings, every resolved hook replayed. **16 of 24** resolved hook repairs replay, all
  passing (`price_lookup`, `stock_level`, `apply_discount` at /O2, `checksum`, `order_add` with its `Order`
  struct, 20 of 21 cases). `format_receipt` and `ship_order` are inconclusive (the CRT's inline `snprintf` reads a
  global). Repair outcomes and traces are unchanged. The swapped negative control fails replay both ways, at /O2
  and /Od.
- **Unicorn is GPL-2.0**, so it's the optional `emulator` feature, off by default (a default build has no GPL
  code; a `pbeta` built with it is GPL-2.0; design §11.5). Building it needs CMake, Ninja and libclang
  (`corpus/lib/emulator.ps1`), and a patched copy of `unicorn-engine-sys` 2.1.5 in `third_party/` (a hard link
  instead of a symlink, so it builds without Windows Developer Mode).
- Gates before and after: identical scorecards, 0 wrong everywhere (fixtures, zlib, Lua, zstd, TinyXML-2, yaml-cpp, the
  hook loop).

Then (2026-11-08): **CI's red Lua PGO gate, fixed.** Every push since the /LTCG + PGO commit had failed on Lua
`o2-pgo` 5.4.7 → 5.4.8 (838 against a baseline of 839, 0 wrong). The cause was the checkout's path: training ran
`train.lua` by absolute path, and Lua puts the executable's directory into `package.path` (`setprogdir`), so a
different path length gave a different profile. Building locally from a CI-length path (a junction) reproduced
838. Training now runs from the recipe directory with `package.path`/`cpath` fixed (new `Env` per training step),
and every recipe's training program is started by name (`cmd /c`, build directory on PATH), so its `argv[0]` holds
no path: Lua keeps `argv[0]` in `arg[-1]`, and with only the first two fixes CI scored 841/838 (most likely
through the GC, which paces itself by bytes allocated; not traced further). The PGO code layout is now identical from three checkout paths, and both variants score 842
(baselines raised). zlib, TinyXML-2 and yaml-cpp PGO score their baselines with the new launcher. Their other
training arguments are still absolute paths. A first fix (199de64) claimed path independence from tests run in
Git Bash, which resolves the junction to the real path; the tests above ran from PowerShell, which keeps it. While
Lua's gate failed, CI never reached the projects after it, so this push is their first PGO score on CI.

Before that: **unmatched callees in the AI prompt, measured and not adopted** (design §8). Sketching
each function's unmatched callees (size, top mnemonics, strings, constants) gained 5 correct answers over 182
questions but went from 2 wrong to 6 wrong, 2 of which would pass verification: Claude started picking inside
zstd's near-identical `noDict_*` family, wrongly, where it used to say `none`. The prompt is unchanged. The
current prompt was remeasured after tonight's matching changes and its answers recorded: /O2 37 of 38 correct,
/Od 38 of 39, deleted functions 11 of 12 `none`, no wrong proposal passing the policy.

Before that: **struct layout proposals and the AI proposer in repair** (design §7.2, §8).
- `pbeta analyze --pdb` now records the layouts of the structs signatures use (`types`). When a struct a hook's
  prototype names changed layout, the hook goes to review (`struct_layout_changed`) with the field changes, the
  new definition and `offsetof` constants with `static_assert`s. Fields correspond by name. On the `basic`
  fixture's S5 (`Config` gains a field before `b`) the hook on `pb_struct_reader` gets `b: offset 0x4 -> 0x8` on
  every flag set; a hook whose struct didn't change is repaired as before (corpus tests, run in CI).
- `pbeta repair --propose` (`--allow-remote` or `--replay`, every exchange logged) asks the AI proposer about
  hooks matching left `unmatched` and attaches each verified proposal to the hook's review item. It never becomes
  the target or a mapping, and a pair a reviewer rejected isn't attached again. **Measured live** on the hook
  loop: its only unmatched hook, `apply_discount` at /Od (rewritten in v2, same results), v1 → v2 and v2 → v3
  (repaired from v1): Claude proposed `0x1140` both times (confidence 0.60), verification would accept it, and the
  map files confirm it is `apply_discount`. It stays in review. Answers recorded in
  `corpus/ai/claude-opus-5-5.jsonl` (replay with `--replay`).

Before that: **/LTCG and PGO flag sets** (`o2-ltcg`: /GL + /LTCG; `o2-pgo`: built instrumented, run on each
recipe's `Train` workload, relinked with the profile). 0 wrong on every new variant scored: zlib, Lua, TinyXML-2,
yaml-cpp and the `basic` fixture (/LTCG only; it has no training workload). /LTCG inlines across objects, so
fewer functions survive (zlib 51 vs 69 at /O2); PGO splits hot and cold code. New in similarity: a pair is held
for review when an unmatched caller of the old function scores within 0.1 [Guess] of it (inlined into its
caller: TinyXML-2's `TestUtil::Push` under /LTCG). **zstd is skipped for both** (`SkipFlags` in its recipe): in
3 cases the compiler kept a different one of two related functions out of line in each build (old
`ZSTD_entropyCompressSeqStore` inlined into the new `…_wExtLitBuffer`, which was itself inlined in the old
build), and similarity pairs the survivors. Structurally they look like real matches; only the names disagree.
PGO builds are reproducible: two builds give identical layouts for every project. Lua needed two things
fixed for it (`PgoCl` forces in `corpus/projects/lua/pgo_seed.h`): its string-hash seed (clock and ASLR'd
addresses) and `table.sort`'s pivot (clock and time), or each training run took different paths (838 correct on
one build, 834 on the next).

Before that: **winning back held-back matches**. Of the correct pairs the yaml-cpp rules sent to review, 71
were the wrapper rule firing on functions whose matched callers still call them directly (Lua's
`lua_tolstring`: 34 of 34). The rule is now overruled when ≥ 2 [Guess] matched callers call the function
directly and none calls the would-be wrapper; 1 wasn't enough (zstd's `BIT_reloadDStreamFast` came back as a
wrong match). Lua and zstd are back to or above their previous baselines (Lua /Od 5.4.7 → 5.4.8 still −1; zstd
/O2 +2 over), 0 wrong. Left in review on purpose: 15 identical copies with no matched neighbour at all, one
caller-veto case whose caller really changed, and TinyXML-2's 3–8 with a single matched caller.

Before that: **yaml-cpp, the second C++ project** (0.7.0 → 0.8.0 → 0.9.0, `util/read` with the library compiled
in: exceptions, STL, templates, lambdas). 0 wrong on all six variants: /O2 256–269 of ~325, /O2+ICF 236–246,
/Od 2913–2952 of ~3158. The first run had 12–14 "wrong" per /Od variant. Most were the answer key (lambdas'
per-build `<lambda_HASH>` names; now joined within their object file, and left out where ambiguous). Four were
real, all fixed in matching:
- similarity matched a body that moved behind a new wrapper; the wrapper rule now allows the wrapper's other
  callees when they're already matched (at /Od a wrapper calls `data()`, `size()`);
- the hash pass matched deleted `std::string` iterator helpers to new, byte-identical `std::array` ones; it's
  now vetoed when the old function's matched callers don't call the new one (as strings and mnemonic were);
- the hash pass paired the last two of 66 identical copies by elimination; such pairs now need an agreeing
  matched neighbour.
These cost 1–8 correct per variant on Lua, TinyXML-2 and zstd (now review suggestions, none was wrong), so those
baselines were lowered, each with a note in its `expected.toml`.

Before that: **a code-tables verification check** (design §6.1). A candidate passes it when the old and new
function fill the same slot of corresponding vtables or function tables. It's independent of the code hash, so
hash-matched virtuals with no callers are now accepted: +7 to +28 accepted per TinyXML-2 and zstd variant, the
same correct counts, 0 wrong; it never failed on the corpus. **Decided 2026-11-07:** table-slot candidates don't count it,
since it's the evidence that found them. Counting it anyway (measured, not adopted) would accept another 32–42
per TinyXML-2 variant with 0 wrong, but would mean accepting a `return null` body on one fact counted twice.

Before that: **table-slot matching** (design §5.1 pass 5b). The analyzer records code-pointer tables (runs of
≥ 2 relocated pointers to function starts in data: vtables and C function tables), and a new pass pairs the
functions at the same slot of corresponding tables when their code is identical. On TinyXML-2 that tells apart
the byte-identical tiny virtuals: /O2 +39 to +51 correct, /Od +38 to +44, /O2+ICF +5 to +9; zstd +9 at /O2 and
+34 at /Od from its function tables. 0 wrong everywhere; zlib, Lua, the fixtures and the hook loop unchanged.
Most of the new C++ matches go to review: table position implies no verification check, and a `return null`
body has nothing else to check.

Before that: **the first C++ project, TinyXML-2** (9.0.0 → 10.0.0 → 10.1.0, its `xmltest` driver with the
library compiled in). 0 wrong on all six variants: /O2 194–196 of ~267, /O2+ICF 199–203 of ~228, /Od 392–395 of
~474. Code reachable only through vtables is found (base relocations): only 5–15 functions per variant are
unmatched. Most misses are ambiguous and go to review: tiny virtual overrides that are byte-identical across
classes (`XMLNode`'s `ToElement`, `ToText`, … returning null). The first run's 5–18 "wrong" per variant were all
in the answer key: decorated names change with the signature (`int` → `size_t`) and with a function-local class's
scope number, and `main$dtor$N` funclets are renumbered. The answer key now joins C++ leftovers by undecorated name
(with, then without, the signature; unique on both sides; template arguments kept) and leaves funclets out. The
other projects' scores are unchanged.

Before that: **dead code found from layout** (design §4.2, §4.4). Code on a 16-byte boundary right after
`int3` padding is a function start once nothing else is found (not where its own function branches to it, never
inside a `.pdata` function). Every build now finds every function its PDB lists, with no new false start; /Od +1
to +6 correct per variant, 0 wrong, baselines raised; /O2 and the hook loop unchanged.

Before that: **Ghidra headless exporter, closing M1** (design §4.3, §4.4). `integrations/ghidra/scripts/` export
Ghidra 12.2's functions with its PDB analyzers off; `pbeta analyze --functions-from` hashes them natively (equal
bodies give equal hashes, fixture-tested); `corpus/ghidra-diff.ps1` writes the three-way report (native, Ghidra,
PDB) for the newest tag of every project and flag set. Judged by the PDB, native is right far more often: in 967
of 975 size disagreements, and Ghidra misses the table-referenced functions native finds through relocations.
Ghidra's one win is three unreferenced zstd /Od functions (two of which native absorbs). Decision: native stays
the source of boundaries; Ghidra is for pseudocode (stored now, optional) and types later. Ghidra's names and
inferred signatures are never used.

Before that: **M1 spikes, PDB and diff** (design §4.4). `pbeta analyze --pdb` adds PDB names and signatures
(refused for another build's PDB; folded entries stay unnamed), and `pbeta analysis-diff` compares two analyses of
one build. The first diff report, native vs PDB on every corpus variant: no hash or name disagreement; native
finds the import thunks the PDB has no symbol for; it misses functions reached only through data (function
tables, dead code), and where such a function has no `.pdata` the previous function **absorbs** it (zstd /O2's
`ZSTD_writeLastEmptyBlock`: 147 bytes natively, 29 in the PDB). **Fixed:** function starts now also come from
code pointers in data (base relocations). Every /O2 build finds every PDB function; only unreferenced dead code
at /Od is left. Lua /O2 +10 correct per variant, zstd /O2 +3 to +4, 0 wrong; baselines raised.

Before that: **widening the AI measurement** (design §8). /Od and deleted functions measured: 54 of 56 proposals
correct across Lua and zstd, /O2 and /Od; on deleted functions Claude answered `none` except for two near misses;
no wrong proposal passes verification. The analyzer now hashes import names (analysis schema 2): Lua's `math_*`
wrappers, which Claude couldn't tell apart, are now matched by the engine itself (+6 to +7 correct per Lua
variant, 0 wrong). `score-ai --select deleted|present` picks the questions. One more zstd rename declared
(`BMK_benchCLevel` → `BMK_benchCLevels`, found by Claude).

Before that: finishing M4 (`corpus/build-hooks.ps1 -Run`, `corpus/hooks/README.md`). Results, the same shape at
/O2 and /Od:

| Hook | v1 → v2 | v2 → v3 |
|---|---|---|
| `price_lookup`, `stock_level`, `format_receipt` | relocated, same trace | relocated (/Od: some unchanged), same trace |
| `order_add` (high criticality) | relocated after its trial run, same trace | same |
| `checksum` | relocated, same trace | review: ambiguous (identical `checksum_backup` added) |
| `ship_order` | relocated, same trace | relocated after its trial run (no independent structural evidence), same trace |
| `log_event` | review (parameter added), with a prototype proposal and a shim that compiles | repaired from v1: same review, same proposal |
| `apply_discount` | /O2: unchanged after its trial run (body rewritten, same results); /Od: review (unmatched) | /O2: unchanged after its trial; /Od: repaired from v1, still unmatched |

What's new:

- **Trial runs** (`pbeta repair --trial-out`): review candidates whose only missing evidence is behavioral are
  bound in a trial manifest, run, and judged from that run. This is how a high-criticality hook earns its
  behavioral pass.
- **Repair from the hook's own build** (`--earlier`): hooks still bound to v1 are matched v1 → v3, not reported
  as stale. Behavioral evidence is always taken from the trace of the candidate's own build.
- **AOB patterns** (`--new-binary`, `pbeta pattern`): regenerated for every re-bound hook, unique in the code,
  and checked against the new binary by the answer key. A re-bound hook no longer carries its old, unchecked
  pattern.
- **Offsets header** (`pbeta header`): `hooks.gen.h` from the manifests; compiles as C and C++.
- **Prototype proposals**: added register parameters (typed from the register class the analyzer now records,
  `inferred_arg_classes`) with a shim that keeps the existing detour unchanged.
- **Mnemonic-hash pass** (M3, design §5.1 pass 4): same instruction sequence with changed operands, gated on size
  (≥ 32 bytes) and an agreeing matched neighbour. 0 wrong; zstd up to +23 correct per variant and ~60 more
  accepted per /O2 variant.
- **Similarity thresholds calibrated** with the new `pbeta-corpus sweep` (a threshold grid scored over all 21
  corpus variants): score 0.75 is the lowest with 0 wrong (0.70 gives 2), margin lowered 0.1 → 0.05 (+108
  correct, 0 wrong), size kept at 16. Weights are still guesses. Baselines raised for Lua and zstd.
- **Policy:** a behavioral pass now counts as one independent pass for low and normal criticality (design §6.3);
  high still needs 2 structural passes plus the behavioral pass. That resolves `apply_discount` (/O2) and
  `ship_order` (v2 → v3) through their trial runs, both correct per the answer key; hook-loop baselines raised.
- The ambiguity message no longer calls a single, unconfirmed candidate "equally plausible".
- CI's hook-loop step failed on the previous commit although the loop passed: the negative control's last exit
  code (1, by design) leaked out of the script. It now exits 0 explicitly.

## What works

- **`pbeta analyze`** reads PE x64 executables with no symbols: functions from `.pdata`, code pointers in data
  (base relocations), call targets, address-taken code and code after `int3` padding, with chained `.pdata` fragments merged into their
  parent; with `--pdb`, names and signatures from the build's PDB; normalized and mnemonic hashes,
  callees in call order, strings, constants, imports, inferred register arguments, and entry hookability.
- **Recorded test cases** (design §7.3): `pbeta harness-spec` (record spec), the hook DLL's record mode
  (`corpus/hooks/hookdll`, MASM thunk), `pbeta replay` and `pbeta repair --cases` (replay by emulation,
  `permanent-beta-replay`, feature `emulator`).
- **`pbeta trace-diff`** (design §7.3, scenario trace diff): compares two runs' traces hook by hook (missed,
  different or failed calls, crashes, review hooks applied or silently skipped). `pbeta repair --old-trace
  --new-trace` adds the same evidence to verification (`TraceDiffRunner`).
- **AI proposer** (M5, design §8): new `permanent-beta-ai` crate. For each function matching left unmatched it
  shows Claude (through the Claude Code CLI, on a Claude subscription) the function's features and its 5
  closest unmatched new functions, and takes a strict `{choice, confidence, rationale}` answer, `none` allowed.
  `pbeta propose` verifies each proposal and queues it for review; it needs `--allow-remote` and logs every
  exchange, which `--replay` reuses. `pbeta-corpus score-ai` scores answers against the answer keys. First
  measurement on Lua and zstd /O2 (63 questions): 32 proposals, 31 correct; the wrong one (another object
  file's copy of the same static function) doesn't pass verification; 31 cautious `none`s.
- **`pbeta-mcp`** (M5, design §11.2): MCP server over stdio. Agents list builds, read functions and candidates,
  run verification, list and explain review items, and propose mappings, which are verified and queued as
  `ai_proposal` items. Agents can't accept; `pbeta review accept` decides.
- **`pbeta repair --trial-out / --earlier / --new-binary`, `pbeta pattern`, `pbeta header`** (M4): trial
  manifests, repair from a hook's own build, AOB patterns, the offsets header, and prototype proposals in review
  items (see above, and design §7.2).
- **`pbeta match` / `repair` / `review list|accept|reject`**: eight matching passes (name, normalized hash, strings,
  mnemonic hash, matched callees, call graph, vtable/function-table slots, and a weak similarity pass for edited
  functions); string matches are vetoed when argument counts or matched callers contradict them,
  rechecked against the final matches. Verification on parameters, strings, size, callers, callees, constants,
  imports and inferred arguments, counting only evidence independent of the match; repair with review reasons
  (unmatched, ambiguous, verification failed, insufficient evidence, signature changed, not hookable, stale
  locator); exit codes
  0/1/2; updated manifest; append-only JSON store.
- **Corpus gate** (CI, Windows): zero wrong matches, plus correct-match baselines. Each scorecard lists every
  pass's precision and recall.
  - Purpose-built fixture `basic` (`corpus/fixtures`): 3 flag sets.
  - zlib v1.2.13 → v1.3 → v1.3.1: /O2 69 of 69, /Od 160–161 of 163.
  - Every project also builds /LTCG and PGO except zstd (skipped, see above).
  - Lua v5.4.6 → v5.4.7 → v5.4.8: /O2 726–732 of ~735, /Od 1087–1092 of ~1095.
  - zstd v1.5.5 → v1.5.6 → v1.5.7: /O2 680–690 of ~729 (/O2+ICF 666–676), /Od 1737–1773 of ~1879.
  - TinyXML-2 9.0.0 → 10.0.0 → 10.1.0 (C++): /O2 231–247 of ~267 (/O2+ICF 201–212 of ~228), /Od 425–435 of ~474.
  - yaml-cpp 0.7.0 → 0.8.0 → 0.9.0 (C++): /O2 256–269 of ~325 (/O2+ICF 236–246), /Od 2913–2952 of ~3158.
  - JsonCpp 1.9.6 → 1.9.7 → 1.9.8 (C++): /O2 272–273 of 300 (/O2+ICF 260 of 271), /Od 1592–1626 of ~1670,
    /LTCG 215 of 243, PGO 327–329 of ~360.
  - Hook-repair loop (`corpus/hooks`): 8 Detours hooks across 3 versions, /O2 and /Od, 0 wrong relocations,
    with trial runs, patterns, the header and proposed shims checked.
  - Run locally: `pwsh corpus/build-fixtures.ps1 -Score`, `pwsh corpus/build-projects.ps1 -Score` and
    `pwsh corpus/build-hooks.ps1 -Run`. Add
    `--misses` to `pbeta-corpus score` to list misses.

## Progress against the original goals

| Goal | State |
|---|---|
| 1. Find the new location | Done; measured on zlib, Lua, zstd, TinyXML-2, yaml-cpp and JsonCpp, /O2, /O2+ICF, /Od, /LTCG and PGO (zstd: not /LTCG or PGO) |
| 2. Verify it's the same function | Done for symbol-less binaries, including C++ vtable slots (code-tables check); with `--pdb`, signatures feed the parameter-count check (not yet measured on the corpus) |
| 3. Adapt hooks (signature/struct changes) | Proposals for added register parameters (prototype + shim) and for changed struct layouts (PDB types: changes, new definition, offsets) |
| 4. Behavioral tests from the old version | Done: scenario trace diff and trial runs (M4), and recorded per-call test cases replayed by emulation, with struct layouts translated by field name, globals placed by name and the UCRT's printing imports answered from the recording; on the hook loop 22 of 24 resolved hook repairs replay, all passing |
| 5. Review queue | Listable with candidates; accept / reject / pick a candidate, honored by `repair --store` |
| MCP server | Done (M5): read tools, explanations, proposals into review |
| Ghidra | Headless exporter done (M1): boundaries cross-checked, pseudocode stored; review extension (M6) built and verified end to end in the GUI; external tester pending |
| Hosted service, IDA plugin | Not started (designed) |
| AI fallback | Built and measured (M5), in `propose` and `repair --propose`: 75 of 77 proposals correct on Lua and zstd, /O2 and /Od (remeasured 2026-11-07); `none` on 11 of 12 deleted functions; no wrong proposal passes verification (design §8) |
| License choice | Apache-2.0 (2026-11-08); contributor terms open |
| Market validation | Open |

## Suggested next steps

1. **zstd's `noDict_*` family stays with review (examined 2026-11-08, closed).** In each 1.5.6 → 1.5.7 variant
   the 8 `fast_noDict_*` and 4 `doubleFast_noDict_*` functions are ambiguous; match length (4–7) already
   separates, only `_0`/`_1` don't. The new `_0` and `_1` are identical but for calling `ZSTD_match4Found_branch`
   or `_cmov`. The old ones inlined that choice as `neg`/`sbb` code (no `cmov`), so the helpers have no old
   counterpart to match first, and the old pair differs by about 5 instructions of ~2000 bytes: a best guess.
   The only other evidence is call position (both dispatchers call the 8 in the same order in both builds), which
   the call-sequence pass already attaches as the right suggestion. Position isn't adopted: the dispatcher's own
   code changed, and a branch swap or block reorder would pair them backwards. The AI guessed wrongly inside this
   family too (design §8).
2. **Swapped inlining (zstd under /LTCG and PGO): examined 2026-11-08, left skipped.** The answer key is right
   in all three cases. (1) PGO 1.5.6 → 1.5.7: `ZSTD_entropyCompressSeqStore`'s body moved into a new
   `_wExtLitBuffer` (12 parameters, reordered) and the old function became an inlined wrapper. The survivor has
   the same callers and callee, so only a signature separates them; a hook moved there would read the wrong
   registers. (2) /LTCG 1.5.5 → 1.5.6: `ZSTD_compressSubBlock_sequences` was inlined into `ZSTD_compressSubBlock`,
   which in 1.5.5 was itself inlined into the caller (the survivor calls a new `_literal` whose code used to sit in
   that caller). (3) /LTCG: `ZSTDMT_expandBufferPool`/`createBufferPool` swapped which was inlined into which,
   and with the whole `ZSTDMT_*` neighbourhood unmatched, similarity paired old `expand` with new `create`.
   Measured over all 60 variants, not adopted: an inferred-argument-count veto in similarity (catches 1; −49
   correct and a new wrong match in yaml-cpp /Od), holding a pair another unmatched old function ranks first
   (−11, catches nothing), requiring a matched non-thunk neighbour in common (catches 3; −25). Case 1 needs
   signatures (a PDB, or better inferred ones), so PGO can't be unskipped by a matching rule; /LTCG could be, for
   −25 correct plus a rule for case 2 that would fit one case.
3. **Calibrate the C++ guesses: done 2026-11-08** with a third C++ project (JsonCpp, 0 wrong on its first run).
   Swept one at a time over all 64 corpus variants: `TABLE_MIN_ANCHORS` 1 is calibrated (0 and 1 identical, 2
   costs 108 correct, 3 costs 198, 0 wrong throughout); `WRAPPER_MIN_DIRECT_CALLERS` 2 is calibrated (1 adds 27
   correct and one wrong match in zstd, 3 costs 12). The code-tables fail threshold (now the named constant
   `CODE_TABLE_FAIL_AGREEING`) stays a guess: the check never fails on the corpus at 1, 2 or 3.
4. **Widen replay further** (§7.3): globals, the UCRT's printing imports and the CRT memory functions are done,
   and replay is measured on zlib (`corpus/replay-measure.ps1`: 1 of 16 hooks replays). Next: pointers inside
   structs (depth > 1), which stops all the others; then heap allocation, globals reached only through pointers,
   old-image addresses in recorded memory (mapping them needs the old build's symbols), a target whose callee
   changed telling "this function changed" from "a callee changed" (today both are inconclusive), and a real target with a changed struct to measure layout
   translation outside unit tests. Struct proposals without a PDB (Ghidra types) are open.
5. **License: Apache-2.0, decided 2026-11-08** (design §11.5; `LICENSE`, `NOTICE`, every crate's `license`).
   Still to choose: contributor terms (DCO or CLA).
6. **Outside the code:** talk to legacy-software teams (design §14).

## Known rough edges

- Replay needs the PDB of both builds for globals (named by it), and is inconclusive for a global without a
  unique PDB name, one only a callee reached through a pointer reads, and any import without a model (three are
  modelled). The recorder patches at most 64 imports, and its import memory sizes (512 bytes per argument, 256
  behind each pointer in that) are guesses. The record spec's `sized` buffers are guessed from parameter names.
  The thunks forward at most 8 stack arguments and don't support variadic functions. The emulator build needs
  CMake, Ninja and libclang; without the `emulator` feature every case is inconclusive (pbeta says so).

- The hook manifest needs the build's SHA-256 typed in by hand (`pbeta analyze` prints it in its JSON);
  `pbeta-corpus hook-manifest` does it for the corpus only.
- The trace diff checks one scripted scenario: a wrong target that happens to see the same arguments and results
  for those calls would pass it. The detours log by-value arguments written per prototype by hand.
- AOB patterns are only regenerated with `--new-binary`; without it a re-bound hook has no pattern. The minimum
  length (8 bytes) is a guess, and patterns are only checked for uniqueness in the build they're made from.
- A trial run that crashes fails every candidate's behavioral check in that run, holding the whole step for
  review. One run per trialed hook would isolate it, at the cost of more runs.
- Prototype proposals only cover added register parameters (slots 1–4), with types guessed from the register
  class; stack parameters, removed or reordered ones aren't proposed.
- Call-sequence pairing by position is a review suggestion only. In the ICF build it suggests `pb_deleted` →
  `pb_body_edited`, which is misleading but not a wrong match.
- `.exe` hashes change on every rebuild even with `/Brepro` (PE timestamp, PDB signature), so a build ID is
  per build.
- Table correspondence needs same-length tables: a virtual added to a class changes its vtable's length, so that
  class's identical virtuals stay ambiguous (review). Tables are only split at pointers that aren't function
  starts; without RTTI, adjacent vtables would merge into one run.
- The matcher pairs exception-handling funclets (`main$dtor$N`) too; the answer key can't judge those pairs (they're
  out of its scope); on the first TinyXML-2 run some paired funclets of different numbers. A hook never targets
  one, but nothing stops it either.
- Renames in the answer key are declared by hand. zstd lists only the renames the engine matched; an
  undeclared rename shows up as a "wrong" match and must be checked against the sources before declaring it.
- Dead code is found only when it follows `int3` padding on a 16-byte boundary (all of it on the corpus, MSVC's
  default). Unpadded dead code would be absorbed into the function before it, as before.
- Lua /O2 has three 1-byte native-only starts just past a function's end (design §4.4), not yet explained.
- Identical copies are no longer paired by elimination without an agreeing neighbour (yaml-cpp found the first
  wrong match from it). Pairs the gate can't judge: lambdas the answer key can't tell apart are out of scope,
  like funclets.
