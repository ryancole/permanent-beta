# Licensing layout

This repository is licensed under the Apache License 2.0 ([../LICENSE](../LICENSE), [../NOTICE](../NOTICE)),
decided 2026-11-08 (design §11.5).

| Component | Location | License |
|---|---|---|
| Core crates (`crates/*`), CLI, MCP server | this repo | Apache-2.0 |
| Ghidra integration (`integrations/ghidra`) | this repo | Apache-2.0 |
| Recording harness (`corpus/hooks`) | this repo | Apache-2.0 |
| Public ground-truth corpus recipes (`corpus/`) | this repo | Apache-2.0; the projects they build are cloned at build time and keep their own licenses |
| Ghidra's x86 SLEIGH specification (`crates/permanent-beta-replay/sleigh/`) | this repo, vendored | Apache-2.0 (Ghidra's; its own license files) |
| Signature database | separate private repo | Proprietary |
| Extended test corpus | separate private repo | Proprietary |
| Hosted history service | separate private repo | Proprietary |

Dependencies must be compatible with Apache-2.0: no GPL (CLAUDE.md). Open decision: contributor terms (DCO vs CLA).
Proprietary code must never be added to this repository. Keeping it separate is what keeps the open-core split clean.
