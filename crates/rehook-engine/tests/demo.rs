//! End-to-end test over examples/demo. Keeps the README's expected outcomes honest.

use rehook_engine::Engine;
use rehook_engine::rehook_repair::RepairAction;
use rehook_model::{AnalysisExport, HookManifest, ReviewReason, Rva};
use std::path::PathBuf;

fn demo(file: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/demo")
        .join(file);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

#[test]
fn demo_repair_outcomes() {
    let old: AnalysisExport = serde_json::from_str(&demo("v1.json")).unwrap();
    let new: AnalysisExport = serde_json::from_str(&demo("v2.json")).unwrap();
    let manifest: HookManifest = toml::from_str(&demo("hooks.toml")).unwrap();

    let report = Engine::with_defaults().repair(&manifest, &old, &new);
    let action = |name: &str| {
        &report
            .repairs
            .iter()
            .find(|r| r.hook == name)
            .unwrap()
            .action
    };
    let reason = |name: &str| match action(name) {
        RepairAction::NeedsReview { reason, .. } => Some(*reason),
        _ => None,
    };

    assert_eq!(
        action("ParseConfig"),
        &RepairAction::Relocated {
            old: Rva(0x1200),
            new: Rva(0x2300)
        }
    );
    assert_eq!(
        reason("CreateDocument"),
        Some(ReviewReason::InsufficientEvidence)
    );
    assert_eq!(reason("ChecksumBlock"), Some(ReviewReason::Unmatched));
    assert_eq!(reason("SaveDocument"), Some(ReviewReason::SignatureChanged));

    assert_eq!(report.mappings.len(), 1);
    assert_eq!(report.review_items.len(), 3);
    assert!(report.needs_review());

    let parse = report
        .updated_manifest
        .hooks
        .iter()
        .find(|h| h.name == "ParseConfig")
        .unwrap();
    assert_eq!(parse.target.build, new.build.id);
    assert_eq!(parse.target.rva, Some(Rva(0x2300)));
    let checksum = report
        .updated_manifest
        .hooks
        .iter()
        .find(|h| h.name == "ChecksumBlock")
        .unwrap();
    assert_eq!(
        checksum.target.build, old.build.id,
        "unresolved hooks keep their old locator"
    );
}
