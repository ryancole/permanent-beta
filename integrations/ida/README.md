# IDA plugin: markup carry-forward

Carries your work from an old build's IDA database to a new build's: function names, prototypes, comments and
local types. It carries them only across the function mappings Permanent Beta accepted, either by verification or
by a reviewer. Functions that are ambiguous, in review or unmatched get nothing, and the plugin lists them.

The plugin decides nothing. Which functions correspond is the answer of `pbeta mappings`, and the plugin writes
only to the open database. Scope and rules: design §11.4.

Needs IDA Home or Pro 9.x with IDAPython (IDA Free has no IDAPython), and a `pbeta` build.

## Install

Copy `permanent_beta_ida.py` and the `permanent_beta` folder into IDA's plugins directory, either the install's
`plugins` folder or `%APPDATA%\Hex-Rays\IDA Pro\plugins`, then restart IDA. The plugin adds **Edit > Permanent Beta**.

## Use

1. Analyze both builds with pbeta (`pbeta analyze old.exe --out old.json`, the same for the new build). If you
   review with a store, keep its path to hand.
2. In the **old** build's database: **Edit > Permanent Beta > Export markup...** writes a `pbeta-markup` JSON
   file. It holds names you set (not IDA's `sub_` names, and not the library functions IDA recognised itself),
   prototypes you set, function comments and local types.
3. In the **new** build's database: **Edit > Permanent Beta > Apply markup from an older build...** asks for the
   pbeta executable, the markup export, both analyses and, optionally, the review store. It then runs
   `pbeta mappings --markup` and asks before writing anything.
   - Each database must be its analysis's build: IDA's input file SHA-256 is the build id. A mismatch is refused.
   - A name or prototype you already set in the new database is kept (listed as *kept*).
   - A prototype that `pbeta` finds doesn't fit the new function's register arguments isn't applied. This is the
     same check repair uses on hook prototypes. The name and comments still go across.
   - A name another function already has is skipped. IDA names are unique.
   - Each function that got markup gets a comment line starting with `pbeta:` that names the source build and
     who decided the mapping (the engine or a reviewer). Applying a second time changes nothing.
4. A results window lists each function: *carried*, *kept*, *skipped* or *pending*, with the reason. Press Enter
   on a row to jump to it.

## Tests

The IDA-free logic (export, the apply rules, the pbeta client) is tested without IDA, in CI too:

```bash
cd integrations/ida && python -m unittest discover -s tests -v
```

The data in `tests/data` comes from the hook loop's /O2 v2 → v3 builds (see the README there). The IDA side
(`ida_db.py`, `plugin.py`) can only be checked in IDA by hand. The check: export markup from v2, apply it to v3,
and compare against the map files.
