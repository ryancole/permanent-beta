# Ground-truth corpus (planned, M2)

Recipes to build open-source C/C++ projects across real version tags with MSVC under several flag sets
(`/O2`, `/OPT:ICF`, `/LTCG`, PGO), keeping PDBs. Matching runs on stripped copies; PDB names are used only for
scoring.

Metrics per pass and verdict: accepted precision, recall, review rate, silent wrong repairs. This is the CI gate
for analysis, match and verify changes (design §10).

Only recipes and metadata live here. Built binaries and third-party sources are fetched or built in CI and keep
their own licenses. The extended proprietary corpus lives in a separate repository.
