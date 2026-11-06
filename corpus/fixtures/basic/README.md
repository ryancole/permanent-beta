# Fixture `basic`

A small C++ program in two versions (`v1/`, `v2/`). Each `pb_*` function is one matching scenario. All are
`extern "C"` (stable names across signature changes) and `__declspec(noinline)` (so they survive optimization).

| # | Function | v1 → v2 | What the engine should eventually do |
|---|---|---|---|
| S1 | `pb_unchanged` | identical source | match, relocate |
| S2 | `pb_moved` | identical source, other code shifts it | match, relocate |
| S3 | `pb_body_edited` | same signature, different arithmetic | match only with independent evidence, otherwise review |
| S4 | `pb_param_added` | gains a third parameter | match, then review (signature changed) |
| S5 | `pb_struct_reader` | same source, but the struct field it reads moves from offset 4 to 8 | match, then review (layout changed) |
| S6 | `pb_dup_a`, `pb_dup_b` | two identical bodies in both versions | `/OPT:ICF` folds them into one function; without ICF they're ambiguous → review |
| S7 | `pb_deleted` | v1 only | no match (must not be matched to anything) |
| S8 | `pb_static_strings` | static, unique string references, identical source | match by strings, relocate |
| S9 | `pb_added` | v2 only | no match |

Machine-checkable expected outcomes are the next step (design §10). Today `truth.json` records only the true
mapping.

Inline functions from headers (`printf`, `__local_stdio_printf_options`) are also compiled into `fixture.obj`, so
they appear in the answer key too. That's realistic, so they stay in scope.

## Build

```bash
pwsh corpus/build-fixtures.ps1
```

Output per flag set (`o2`, `o2-icf`, `od`) in `target/fixtures/basic/<flags>/`:
`v1/` and `v2/` with `fixture.exe`, `fixture.pdb`, `fixture.map`, and `truth.json` (the answer key).

If you change the sources, regenerate the parser test data:
`crates/permanent-beta-corpus/tests/data/basic-o2-icf-v{1,2}.map` ← `target/fixtures/basic/o2-icf/v{1,2}/fixture.map`.
