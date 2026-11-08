# Ground-truth corpus

## Purpose-built fixtures

`fixtures/<name>/v1` and `v2` are small C++ programs where each function is one matching scenario. The script
`build-fixtures.ps1` compiles them with MSVC under several flag sets and writes an answer key (`truth.json`)
from the linker map files, using `pbeta-corpus truth`. See [fixtures/basic/README.md](fixtures/basic/README.md).

```bash
pwsh corpus/build-fixtures.ps1
```

Requires Visual Studio or Build Tools with the x64 C++ toolset. Output goes to `target/fixtures/` and isn't committed.

## Real-world projects

`projects/<name>/recipe.psd1` describes how to build an open-source project at several release tags.
`build-projects.ps1` shallow-clones each tag into `target/corpus-src/` (recording the exact commits in
`sources.json`), builds it under the same flag sets, and writes an answer key for each consecutive pair of tags
(functions from the project's own object files, joined by name from the map files). The analyzer never sees the
map files or PDBs; they're only used for scoring.

```bash
pwsh corpus/build-projects.ps1 -Score
```

| Project | Tags | Program | Gate (`expected.toml`) |
|---|---|---|---|
| zlib | v1.2.13, v1.3, v1.3.1 | `minigzip` with zlib compiled in | 0 wrong; /O2 69 of 69 correct, /Od 160–161 of 163 |
| lua | v5.4.6, v5.4.7, v5.4.8 | `lua` interpreter with the libraries compiled in | 0 wrong; /O2 726–732 of ~735, /Od 1087–1093 of ~1095 |
| zstd | v1.5.5, v1.5.6, v1.5.7 | `zstd` CLI with the library compiled in | 0 wrong; /O2 680–688 of ~729, /Od 1739–1778 of ~1879 |
| tinyxml2 | 9.0.0, 10.0.0, 10.1.0 | `xmltest` (C++) with the library compiled in | 0 wrong; /O2 233–247 of ~267, /Od 433–436 of ~474 |

The scorecard also reports each pass's precision (correct share of its own candidates) and recall (its correct
matches over the functions present in both builds).

**Recipes.** `Sources` may use wildcards (resolved per tag, since files come and go between releases), and
`Include` adds include directories. `Renames` declares functions renamed between releases, keyed by the newer
tag: the answer key joins by name, so without the declaration a correct match onto a renamed function is scored
as wrong. Check each rename against the sources before declaring it; a declaration whose old name still exists
in the new build is an error.

**C++ names.** The answer key joins functions by their decorated (mangled) name first. A decorated name changes
when the signature does (`int` → `size_t`) or when a class local to a function gets another scope number, so
leftovers are then joined by their undecorated name, with the signature and then without it, only where that name
is unique on both sides. Template arguments are part of the name: `MemPoolT<80>` and `MemPoolT<88>` never join.
Exception-handling funclets (`main$dtor$73`) are out of scope, because their numbers say nothing about which code
they are once the parent function changes.

Needs git and network access the first time. Only recipes and expected outcomes live here; sources and builds
stay in `target/` and keep their own licenses. Planned: `/LTCG` and PGO flag sets, and a C++ project that uses
exceptions and the STL heavily (yaml-cpp). The
extended proprietary corpus lives in a separate repository.

To see what wasn't matched:

```bash
cargo run -q -p permanent-beta-corpus -- score --built target/corpus/zlib --expected corpus/projects/zlib/expected.toml --misses
```

## Hook-repair loop (M4)

`hooks/` holds a sample app in three versions, a Detours hook DLL with its launcher, and the hooks written
against v1. `build-hooks.ps1 -Run` builds them (cloning Microsoft Detours at a pinned commit into
`target/hooks-src/`), repairs the hooks v1 → v2 → v3 with `pbeta repair`, runs each version under its repaired
hooks, and diffs the call traces. See [hooks/README.md](hooks/README.md).

```bash
pwsh corpus/build-hooks.ps1 -Run
```
