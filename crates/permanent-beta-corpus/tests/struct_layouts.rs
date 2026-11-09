//! Struct layout adaptation (design §7.2) on the real `basic` fixture builds, with their PDBs: scenario S5's
//! `Config` gains a field before `b` in v2.
//!
//! Needs `pwsh corpus/build-fixtures.ps1` first, so these are `#[ignore]`d in a plain `cargo test`. CI runs them
//! after building the fixtures: `cargo test -p permanent-beta-corpus -- --ignored`.

use permanent_beta_analysis::{Analyzer, native::NativePeAnalyzer, symbols};
use permanent_beta_engine::Engine;
use permanent_beta_engine::permanent_beta_repair::RepairAction;
use permanent_beta_model::{
    AnalysisExport, BuildId, Criticality, HookManifest, HookSpec, ReviewReason, TargetLocator,
};
use std::path::PathBuf;

const FLAG_SETS: [&str; 4] = ["o2", "o2-icf", "od", "o2-ltcg"];

fn analyze(flags: &str, version: &str) -> AnalysisExport {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/fixtures/basic")
        .join(flags)
        .join(version);
    let mut export = NativePeAnalyzer
        .analyze(&dir.join("fixture.exe"))
        .unwrap_or_else(|e| panic!("{e}. Run `pwsh corpus/build-fixtures.ps1` first."));
    let pdb = symbols::read(&dir.join("fixture.pdb")).unwrap();
    symbols::apply(&mut export, &pdb).unwrap();
    export
}

fn hook(name: &str, prototype: &str, export: &AnalysisExport) -> HookSpec {
    HookSpec {
        name: name.into(),
        detour: None,
        criticality: Criticality::Normal,
        prototype: Some(prototype.into()),
        trial: false,
        target: TargetLocator {
            build: BuildId(export.build.id.0.clone()),
            rva: Some(export.function_by_name(name).unwrap().rva),
            symbol: None,
            pattern: None,
        },
    }
}

#[test]
#[ignore = "needs the fixture builds (pwsh corpus/build-fixtures.ps1)"]
fn the_pdb_records_both_layouts_of_config() {
    for flags in FLAG_SETS {
        let (old, new) = (analyze(flags, "v1"), analyze(flags, "v2"));
        let fields = |e: &AnalysisExport| -> Vec<(String, u64)> {
            e.type_layout("Config")
                .unwrap_or_else(|| panic!("[{flags}] no Config layout"))
                .fields
                .iter()
                .map(|f| (f.name.clone(), f.offset))
                .collect()
        };
        assert_eq!(
            fields(&old),
            [("a".into(), 0), ("b".into(), 4)],
            "[{flags}]"
        );
        assert_eq!(
            fields(&new),
            [("a".into(), 0), ("inserted".into(), 4), ("b".into(), 8)],
            "[{flags}]"
        );
    }
}

#[test]
#[ignore = "needs the fixture builds (pwsh corpus/build-fixtures.ps1)"]
fn a_hook_on_a_function_whose_struct_changed_goes_to_review_with_the_new_offsets() {
    for flags in FLAG_SETS {
        let (old, new) = (analyze(flags, "v1"), analyze(flags, "v2"));
        let manifest = HookManifest {
            hooks: vec![
                hook(
                    "pb_struct_reader",
                    "int pb_struct_reader(const Config* c)",
                    &old,
                ),
                // Negative: a hook whose prototype uses no changed struct is repaired as before.
                hook("pb_unchanged", "int pb_unchanged(int x)", &old),
            ],
        };
        let r = Engine::with_defaults().repair(&manifest, &old, &new);
        let reader = &r.repairs[0];
        // Either the layout change is the reason, or the hook was already in review for another one and the
        // detail says the layout changed too.
        match &reader.action {
            RepairAction::NeedsReview { reason, detail } => assert!(
                *reason == ReviewReason::StructLayoutChanged
                    || detail.contains("struct layout changed"),
                "[{flags}] {reason:?}: {detail}"
            ),
            other => panic!("[{flags}] not in review: {other:?}"),
        }
        let [p] = reader.struct_proposals.as_slice() else {
            panic!("[{flags}] {:?}", reader.struct_proposals);
        };
        assert_eq!(
            (p.name.as_str(), p.old_size, p.new_size),
            ("Config", 8, 12),
            "[{flags}]"
        );
        assert!(
            p.changes.contains(&"b: offset 0x4 -> 0x8".to_owned()),
            "[{flags}] {:?}",
            p.changes
        );
        assert!(p.offsets.contains("Config_b = 0x8"), "[{flags}]");
        assert!(r.repairs[1].struct_proposals.is_empty(), "[{flags}]");
        assert!(
            r.repairs[1].is_resolved(),
            "[{flags}] {:?}",
            r.repairs[1].action
        );
        // The proposal reaches the hook's review item.
        let item = r
            .review_items
            .iter()
            .find(|i| i.hook.as_deref() == Some("pb_struct_reader"))
            .unwrap();
        assert_eq!(item.struct_proposals, reader.struct_proposals, "[{flags}]");
    }
}

/// The fixture analyzed without its PDB: no names, no types, only the native analyzer.
fn analyze_native(flags: &str, version: &str) -> AnalysisExport {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/fixtures/basic")
        .join(flags)
        .join(version);
    NativePeAnalyzer
        .analyze(&dir.join("fixture.exe"))
        .unwrap_or_else(|e| panic!("{e}. Run `pwsh corpus/build-fixtures.ps1` first."))
}

#[test]
#[ignore = "needs the fixture builds (pwsh corpus/build-fixtures.ps1)"]
fn without_a_pdb_the_moved_field_is_inferred_from_the_accesses() {
    for flags in FLAG_SETS {
        // The PDB only says where the hook is in v1, as the hook author would know it.
        let located = analyze(flags, "v1");
        let (old, new) = (analyze_native(flags, "v1"), analyze_native(flags, "v2"));
        assert!(old.types.is_empty() && new.types.is_empty());
        let mut h = hook(
            "pb_struct_reader",
            "int pb_struct_reader(const Config* c)",
            &located,
        );
        h.target.build = old.build.id.clone();
        let manifest = HookManifest { hooks: vec![h] };
        let r = Engine::with_defaults().repair(&manifest, &old, &new);
        let reader = &r.repairs[0];
        let [p] = reader.struct_proposals.as_slice() else {
            panic!(
                "[{flags}] {:?} {:?}",
                reader.action, reader.struct_proposals
            );
        };
        assert_eq!(p.name, "Config", "[{flags}]");
        assert_eq!(
            p.changes,
            ["offset 0x4 -> 0x8 (4 bytes, 1 access)"],
            "[{flags}]"
        );
        assert!(p.basis.is_some(), "[{flags}]");
        assert!(!reader.is_resolved(), "[{flags}] {:?}", reader.action);
    }
}
