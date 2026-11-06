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
| zlib | v1.2.13, v1.3, v1.3.1 | `minigzip` with zlib compiled in | 0 wrong; /O2 61 of 69 correct, /Od 150–152 of 163 |

Needs git and network access the first time. Only recipes and expected outcomes live here; sources and builds
stay in `target/` and keep their own licenses. Planned: more projects, and `/LTCG` and PGO flag sets. The
extended proprietary corpus lives in a separate repository.

To see what wasn't matched:

```bash
cargo run -q -p permanent-beta-corpus -- score --built target/corpus/zlib --expected corpus/projects/zlib/expected.toml --misses
```
