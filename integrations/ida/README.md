# IDA plugin: markup carry-forward

Carries your work from an old build's IDA database to a new build's: function names, prototypes, comments and
local types. It carries them only across the function mappings Permanent Beta accepted, either by verification or
by a reviewer. Functions that are ambiguous, in review or unmatched get nothing, and the plugin lists them.

The plugin decides nothing. Which functions correspond is the answer of `pbeta mappings`, and the plugin writes
only to the open database. Scope and rules: design §11.4.

Needs IDA Home or Pro 9.x with IDAPython (IDA Free has no IDAPython), and a `pbeta` build.

## Install

The plugin is a folder with an `ida-plugin.json` manifest, the format IDA 9 and Hex-Rays' plugin manager (HCLI) use.
Copy `ida-plugin.json`, `permanent_beta_ida.py` and the `permanent_beta` folder into a folder of their own, such as
`%APPDATA%\Hex-Rays\IDA Pro\plugins\permanent-beta`, then restart IDA. The `tests` folder isn't needed.

The plugin loads with each database (not on IDA's start screen) and adds **Edit > Plugins > Permanent Beta**. The
Output window shows `Permanent Beta: added Edit/Plugins/Permanent Beta`. It isn't in the Hex-Rays plugin repository,
and installing it with `hcli plugin install` hasn't been tried.

## Use

1. Analyze both builds with pbeta (`pbeta analyze old.exe --out old.json`, the same for the new build). If you
   review with a store, keep its path to hand.
2. In the **old** build's database: **Edit > Plugins > Permanent Beta > Export markup...** writes a `pbeta-markup` JSON
   file. It holds names you set (not IDA's `sub_` names, and not the library functions IDA recognised itself),
   prototypes you set, function comments and local types.
3. In the **new** build's database: **Edit > Plugins > Permanent Beta > Apply markup from an older build...** asks for the
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

## With an AI agent: IDA MCP and `pbeta-mcp`

Tried on 2026-11-14 with the hook loop's /O2 v2 → v3 `checksum` item, which is ambiguous: v3 adds a
byte-identical `checksum_backup`. `pbeta-mcp` showed both candidates passing the same checks, including the same
single matched caller. IDA MCP showed what tells them apart. In v2, `ship_order` calls `checksum` once, right
after printing the receipt. In v3 it calls `0x1040` at that same spot and then `0x1070` on the same data,
comparing the two results. So `0x1040` is the counterpart, which the map files confirm.

Two things to know:

- In Claude Code's auto mode, IDA MCP's calls are refused: its plugin adds a session field to each call after auto
  mode checks it. Use another permission mode.
- IDA MCP's headless workers load the build's PDB when they find it, so an agent sees the real names. Open copies
  of the binaries away from their PDBs to keep a review honest.

Hex-Rays ships its own MCP server, **IDA MCP** (IDA 9.4 or later, Home or Pro, with idalib). It lets an agent open
and read databases, and change them. Permanent Beta's server, `pbeta-mcp`, gives the same agent the build
analyses, candidates with their verification checks, and the review queue. With both, an agent can work through
the review queue: read an item's explanation from `pbeta-mcp`, look at the old function and each candidate in IDA,
and tell you what differs.

What each side may do stays as it is:

- `pbeta-mcp` only reads, and adds proposals to the review queue (`propose_mapping`, verified first). No agent can
  accept a mapping or decide a review item: you do that with `pbeta review` or the Ghidra review window.
- IDA MCP can change the database (names, types, comments). That's between you and the agent; it never becomes a
  mapping.

Setup, for Claude Code:

1. IDA MCP: follow Hex-Rays' instructions
   (https://docs.hex-rays.com/add-ons/mcp/getting-started). Their README gives these Claude Code commands:

   ```bash
   claude plugin marketplace add HexRaysSA/claude-marketplace
   claude plugin install ida-mcp@HexRaysSA
   ```

2. `pbeta-mcp`: add it to the project's `.mcp.json` with the analyses of the builds involved and your review store
   (paths are examples):

   ```json
   {
     "mcpServers": {
       "pbeta": {
         "command": "C:/path/to/pbeta-mcp.exe",
         "args": ["--analysis", "C:/work/v2/analysis.json", "--analysis", "C:/work/v3/analysis.json",
                  "--store", "C:/work/.pbeta/store.json"]
       }
     }
   }
   ```

A prompt to start with: *"List the open Permanent Beta review items. For each one, open the old and new builds in
IDA, compare the old function with each candidate, and tell me which you think is right and why. Don't change the
databases."*

## Tests

The IDA-free logic (export, the apply rules, the pbeta client) is tested without IDA, in CI too:

```bash
cd integrations/ida && python -m unittest discover -s tests -v
```

The data in `tests/data` comes from the hook loop's /O2 v2 → v3 builds (see the README there). The IDA side
(`ida_db.py`, `plugin.py`) can only be checked in IDA by hand. The check: export markup from v2, apply it to v3,
and compare against the map files.
