//! Run the real pipeline on one built fixture variant and score it.
//!
//! A variant directory is `target/fixtures/<name>/<flags>/` with `v1/fixture.exe`, `v2/fixture.exe` and
//! `truth.json`, as written by `corpus/build-fixtures.ps1`.

use crate::expected::{Evaluation, Expected};
use crate::score::{Scorecard, score};
use crate::truth::GroundTruth;
use anyhow::{Context, Result};
use permanent_beta_analysis::{Analyzer, native::NativePeAnalyzer};
use permanent_beta_engine::Engine;
use std::fmt::Write as _;
use std::path::Path;

pub struct VariantScore {
    pub flags: String,
    pub card: Scorecard,
    pub evaluation: Evaluation,
}

/// Analyze both builds natively, match them with the default engine, and score against the answer key.
pub fn score_variant(dir: &Path, flags: &str, expected: &Expected) -> Result<VariantScore> {
    let truth_path = dir.join("truth.json");
    let truth: GroundTruth =
        serde_json::from_str(&std::fs::read_to_string(&truth_path).with_context(|| {
            format!(
                "reading {}; run corpus/build-fixtures.ps1 first",
                truth_path.display()
            )
        })?)
        .with_context(|| format!("parsing {}", truth_path.display()))?;

    let analyze = |v: &str| {
        let exe = dir.join(v).join("fixture.exe");
        NativePeAnalyzer
            .analyze(&exe)
            .with_context(|| format!("analyzing {}", exe.display()))
    };
    let (old, new) = (analyze("v1")?, analyze("v2")?);
    let report = Engine::with_defaults().match_builds(&old, &new);
    let card = score(&truth, &report.reports, &report.ambiguities);
    let evaluation = expected.evaluate(flags, &card);
    Ok(VariantScore {
        flags: flags.to_owned(),
        card,
        evaluation,
    })
}

/// Human-readable scorecard for one variant.
pub fn render(v: &VariantScore) -> String {
    let t = &v.card.totals;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "[{}] correct {} (accepted {}, review {}), ambiguous {}, unmatched {}, WRONG {}",
        v.flags,
        t.correct(),
        t.accepted,
        t.review,
        t.ambiguous,
        t.unmatched,
        t.wrong
    );
    for s in &v.evaluation.scenarios {
        let actual = s
            .actual
            .map(|a| format!("{a:?}").to_lowercase())
            .unwrap_or_else(|| "-".into());
        let target = format!("{:?}", s.target).to_lowercase();
        let mark = if s.met { "met" } else { "not yet" };
        let _ = writeln!(
            out,
            "  {:<4} {:<20} target {:<10} actual {:<10} {mark}",
            s.id, s.function, target, actual
        );
    }
    if v.evaluation.gate_failures.is_empty() {
        let _ = writeln!(out, "  gate: pass");
    }
    for f in &v.evaluation.gate_failures {
        let _ = writeln!(out, "  gate: FAIL {f}");
    }
    out
}
