//! The corpus gate for the `basic` fixture: analyze, match and score every flag set against the answer key
//! and corpus/fixtures/basic/expected.toml. Fails on any wrong match or a drop below the correct-match baseline.
//!
//! Needs `pwsh corpus/build-fixtures.ps1` first, so it's `#[ignore]`d in a plain `cargo test`. CI runs it after
//! building the fixtures: `cargo test -p permanent-beta-corpus -- --ignored`.

use permanent_beta_corpus::{expected::Expected, fixture};
use std::path::PathBuf;

#[test]
#[ignore = "needs corpus/build-fixtures.ps1"]
fn basic_fixture_passes_the_gate() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let expected = Expected::parse(
        &std::fs::read_to_string(root.join("corpus/fixtures/basic/expected.toml")).unwrap(),
    )
    .unwrap();

    let mut failures = Vec::new();
    for flags in expected.gate.min_correct.keys() {
        let dir = root.join("target/fixtures/basic").join(flags);
        let v = fixture::score_variant(&dir, flags, &expected).unwrap();
        print!("{}", fixture::render(&v));
        failures.extend(
            v.evaluation
                .gate_failures
                .iter()
                .map(|f| format!("[{flags}] {f}")),
        );
    }
    assert!(
        failures.is_empty(),
        "corpus gate failed:\n{}",
        failures.join("\n")
    );
}
