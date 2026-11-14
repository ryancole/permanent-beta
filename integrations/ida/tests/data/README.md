# Test data

Made from the hook loop's /O2 builds (`target/hooks/o2`, `corpus/build-hooks.ps1`) on 2026-11-14:

- `markup-o2-v2.json`: a `pbeta-markup` export of v2 written by hand from its data:
  - `build`: `app.exe`'s SHA-256;
  - the `app.obj` functions from `app.map`, with their names;
  - the prototypes from `corpus/hooks/hooks.template.toml`;
  - a comment on `price_lookup`, a repeatable comment on `stock_level` and an `Order` declaration.
- `mappings-o2-v2-v3.json`: the real reply of
  `pbeta mappings --old v2/analysis.json --new v3/analysis.json --markup markup-o2-v2.json --json`, with each
  mapping's `evidence` and `checks` removed (the plugin doesn't read them; the reply was 156 KB). All 67 listed
  mappings agree with the v2 and v3 map files. `checksum` (0x1040) is pending as ambiguous, and `ship_order`
  (0x1340) needs review with candidate 0x1380. No prototype misfits: no hooked function's arguments changed
  between v2 and v3.
