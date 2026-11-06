# Licensing layout (placeholder)

Nothing in this repository is licensed for reuse yet. See [../LICENSE](../LICENSE).

| Component | Location | Intended license |
|---|---|---|
| Core crates (`crates/*`), CLI | this repo | Open source. Apache-2.0 recommended |
| Ghidra extension (`integrations/ghidra`) | this repo | Same as core |
| Recording/replay harness (`harness/`) | this repo | Same as core |
| Public ground-truth corpus recipes (`corpus/`) | this repo | Same as core; third-party sources keep their own licenses |
| Signature database | separate private repo | Proprietary |
| Extended test corpus | separate private repo | Proprietary |
| Hosted history service | separate private repo | Proprietary |

Open decisions: the license itself (Apache-2.0 vs MIT vs MPL-2.0) and contributor terms (DCO vs CLA).
Proprietary code must never be added to this repository. Keeping it separate is what keeps the open-core split clean.
