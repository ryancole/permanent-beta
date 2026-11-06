//! The native analyzer, run on the real `basic` fixture builds and scored against their answer keys.
//!
//! Needs `pwsh corpus/build-fixtures.ps1` first, so these are `#[ignore]`d in a plain `cargo test`. CI runs them
//! after building the fixtures: `cargo test -p permanent-beta-corpus -- --ignored`.

use permanent_beta_analysis::{Analyzer, native::NativePeAnalyzer};
use permanent_beta_corpus::truth::GroundTruth;
use permanent_beta_model::{AnalysisExport, FunctionFeatures, Rva};
use std::path::PathBuf;

const FLAG_SETS: [&str; 3] = ["o2", "o2-icf", "od"];

struct Build {
    flags: &'static str,
    old: AnalysisExport,
    new: AnalysisExport,
    truth: GroundTruth,
}

fn load(flags: &'static str) -> Build {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/fixtures/basic")
        .join(flags);
    let truth_path = dir.join("truth.json");
    let truth_text = std::fs::read_to_string(&truth_path).unwrap_or_else(|e| {
        panic!(
            "{}: {e}. Run `pwsh corpus/build-fixtures.ps1` first.",
            truth_path.display()
        )
    });
    let analyze = |v: &str| {
        NativePeAnalyzer
            .analyze(&dir.join(v).join("fixture.exe"))
            .unwrap()
    };
    Build {
        flags,
        old: analyze("v1"),
        new: analyze("v2"),
        truth: serde_json::from_str(&truth_text).unwrap(),
    }
}

impl Build {
    /// The analyzed functions for `name` in (v1, v2), using the answer key's addresses.
    fn pair(&self, name: &str) -> (Option<&FunctionFeatures>, Option<&FunctionFeatures>) {
        let e = self
            .truth
            .entry(name)
            .unwrap_or_else(|| panic!("[{}] {name} not in truth", self.flags));
        (
            e.old.and_then(|r| self.old.function(r)),
            e.new.and_then(|r| self.new.function(r)),
        )
    }

    fn both(&self, name: &str) -> (&FunctionFeatures, &FunctionFeatures) {
        match self.pair(name) {
            (Some(o), Some(n)) => (o, n),
            other => panic!(
                "[{}] {name}: analyzer missed it: found (v1, v2) = {:?}",
                self.flags,
                (other.0.map(|f| f.rva), other.1.map(|f| f.rva))
            ),
        }
    }
}

#[test]
#[ignore = "needs corpus/build-fixtures.ps1"]
fn finds_every_fixture_function_at_its_true_address() {
    for flags in FLAG_SETS {
        let b = load(flags);
        let mut found = 0;
        let mut total = 0;
        for e in &b.truth.functions {
            for (rva, export) in [(e.old, &b.old), (e.new, &b.new)] {
                let Some(rva) = rva else { continue };
                total += 1;
                if export.function(rva).is_some() {
                    found += 1;
                } else if e.names.iter().any(|n| n.starts_with("pb_") || n == "main") {
                    panic!("[{flags}] {:?} at {rva} not found by the analyzer", e.names);
                }
            }
        }
        println!(
            "[{flags}] function starts found: {found}/{total} (answer-key functions from fixture.obj)"
        );
    }
}

#[test]
#[ignore = "needs corpus/build-fixtures.ps1"]
fn normalized_hash_is_stable_for_unchanged_code_and_changes_for_edited_code() {
    for flags in FLAG_SETS {
        let b = load(flags);
        // Same source in both versions: S1 unchanged, S2 moved, S8 static. Their addresses all moved because
        // pb_added was inserted, so this also checks that address masking works.
        for name in ["pb_unchanged", "pb_moved", "pb_static_strings"] {
            let (o, n) = b.both(name);
            assert_ne!(o.rva, n.rva, "[{flags}] {name} should have moved");
            assert_eq!(
                o.normalized_hash, n.normalized_hash,
                "[{flags}] {name}: same code, different hash"
            );
        }
        // Negative cases: S3 body edited, S4 parameter added, S5 struct offset moved.
        for name in ["pb_body_edited", "pb_param_added", "pb_struct_reader"] {
            let (o, n) = b.both(name);
            assert_ne!(
                o.normalized_hash, n.normalized_hash,
                "[{flags}] {name}: edited code, same hash"
            );
        }
    }
}

#[test]
#[ignore = "needs corpus/build-fixtures.ps1"]
fn identical_copies_hash_identically_when_not_folded() {
    for flags in ["o2", "od"] {
        let b = load(flags);
        let a = b.truth.entry("pb_dup_a").unwrap();
        let c = b.truth.entry("pb_dup_b").unwrap();
        assert_ne!(a.old, c.old, "[{flags}] not folded without /OPT:ICF");
        let ha = b
            .old
            .function(a.old.unwrap())
            .unwrap()
            .normalized_hash
            .clone();
        let hb = b
            .old
            .function(c.old.unwrap())
            .unwrap()
            .normalized_hash
            .clone();
        assert_eq!(ha, hb, "[{flags}] identical source should hash identically");
    }
}

#[test]
#[ignore = "needs corpus/build-fixtures.ps1"]
fn collects_string_references() {
    for flags in FLAG_SETS {
        let b = load(flags);
        let (o, n) = b.both("pb_static_strings");
        for f in [o, n] {
            assert_eq!(
                f.strings,
                vec!["[pb-settings]".to_string(), "pb-config.ini".to_string()],
                "[{flags}]"
            );
        }
    }
}

#[test]
#[ignore = "needs corpus/build-fixtures.ps1"]
fn main_calls_the_fixture_functions() {
    for flags in FLAG_SETS {
        let b = load(flags);
        let (main_old, _) = b.both("main");
        for name in ["pb_unchanged", "pb_body_edited", "pb_deleted"] {
            let rva: Rva = b.truth.entry(name).unwrap().old.unwrap();
            // With /O2 the last call may become a tail jump; either way it's recorded as a callee.
            assert!(
                main_old.callees.contains(&rva),
                "[{flags}] main → {name} ({rva}) missing"
            );
        }
    }
}
