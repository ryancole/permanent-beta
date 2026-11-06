# Ghidra extension (planned, M6; exporter in M1)

Java. Ghidra's plugin API is Java; the decompiler is a separate native process.

1. **Headless exporter:** a script run via `analyzeHeadless` that writes `AnalysisExport` JSON
   (schema: `crates/permanent-beta-model/src/analysis.rs`), including function boundaries, bytes, decompiler pseudocode
   and recovered types. Hashes are computed by the Rust normalizer, not in Java (design §4.3).
2. **UI extension:** shows mappings, evidence and review items next to the listing and decompiler, and records
   review decisions through the `pbeta` CLI or a local JSON-RPC server. Nothing is linked into the JVM.

Evaluate overlap with Ghidra's built-in Version Tracking and BSim before building matching UI (design §11.3).
