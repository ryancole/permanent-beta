//! Run the real pipeline on one built variant and score it.
//!
//! A variant directory holds `v1/` and `v2/`, each with exactly one `.exe`, plus `truth.json`. Written by
//! `corpus/build-fixtures.ps1` (`target/fixtures/<name>/<flags>/`) and `corpus/build-projects.ps1`
//! (`target/corpus/<project>/<flags>__<old>__<new>/`).

use crate::expected::{Evaluation, Expected};
use crate::score::{Scorecard, score};
use crate::truth::GroundTruth;
use anyhow::{Context, Result};
use permanent_beta_analysis::{Analyzer, native::NativePeAnalyzer};
use permanent_beta_engine::Engine;
use permanent_beta_engine::permanent_beta_match::{SimilarityParams, matchers_with_similarity};
use permanent_beta_engine::permanent_beta_verify::Verifier;
use permanent_beta_model::AnalysisExport;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

pub struct VariantScore {
    pub flags: String,
    pub card: Scorecard,
    pub evaluation: Evaluation,
}

/// Analyze both builds natively, match them with the default engine, and score against the answer key.
pub fn score_variant(dir: &Path, flags: &str, expected: &Expected) -> Result<VariantScore> {
    let (truth, old, new) = load_variant(dir)?;
    let report = Engine::with_defaults().match_builds(&old, &new);
    let card = score(&truth, &report.reports, &report.ambiguities);
    let evaluation = expected.evaluate(flags, &card);
    Ok(VariantScore {
        flags: flags.to_owned(),
        card,
        evaluation,
    })
}

/// A variant's answer key and both builds' native analyses.
pub fn load_variant(dir: &Path) -> Result<(GroundTruth, AnalysisExport, AnalysisExport)> {
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
        let exe = single_exe(&dir.join(v))?;
        NativePeAnalyzer
            .analyze(&exe)
            .with_context(|| format!("analyzing {}", exe.display()))
    };
    Ok((truth, analyze("v1")?, analyze("v2")?))
}

/// One point of a similarity-threshold sweep on one variant.
#[derive(Debug, Clone, Copy)]
pub struct SweepPoint {
    pub params: SimilarityParams,
    /// Correct candidates (any verdict), and those accepted by the normal policy.
    pub correct: u32,
    pub accepted: u32,
    pub wrong: u32,
    /// The similarity pass's own share.
    pub sim_correct: u32,
    pub sim_wrong: u32,
}

/// Score the variant with each set of similarity thresholds (matching and verification as in the engine).
pub fn sweep_variant(
    truth: &GroundTruth,
    old: &AnalysisExport,
    new: &AnalysisExport,
    grid: &[SimilarityParams],
) -> Vec<SweepPoint> {
    grid.iter()
        .map(|&params| {
            let engine = Engine::new(matchers_with_similarity(params), Verifier::with_defaults());
            let report = engine.match_builds(old, new);
            let card = score(truth, &report.reports, &report.ambiguities);
            let sim = card
                .by_pass()
                .get("similarity")
                .copied()
                .unwrap_or_default();
            SweepPoint {
                params,
                correct: card.totals.correct(),
                accepted: card.totals.accepted,
                wrong: card.totals.wrong,
                sim_correct: sim.correct(),
                sim_wrong: sim.wrong,
            }
        })
        .collect()
}

fn single_exe(dir: &Path) -> Result<PathBuf> {
    let exes: Vec<PathBuf> = std::fs::read_dir(dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x.eq_ignore_ascii_case("exe")))
        .collect();
    match exes.as_slice() {
        [one] => Ok(one.clone()),
        _ => anyhow::bail!(
            "expected exactly one .exe in {}, found {}",
            dir.display(),
            exes.len()
        ),
    }
}

/// Human-readable scorecard for one variant.
pub fn render(v: &VariantScore) -> String {
    let t = &v.card.totals;
    let in_both = v.card.in_both();
    let mut out = String::new();
    let _ = writeln!(
        out,
        "[{}] correct {}/{in_both} in both builds (accepted {}, review {}), ambiguous {}, unmatched {}, WRONG {}",
        v.flags,
        t.correct(),
        t.accepted,
        t.review,
        t.ambiguous,
        t.unmatched,
        t.wrong
    );
    // Per pass: precision over its own candidates, recall as its share of the functions present in both builds.
    for (pass, p) in v.card.by_pass() {
        let precision = p
            .precision()
            .map(|x| format!("{:.1}%", x * 100.0))
            .unwrap_or_else(|| "-".into());
        let recall = if in_both > 0 {
            f64::from(p.correct()) / f64::from(in_both) * 100.0
        } else {
            0.0
        };
        let _ = writeln!(
            out,
            "  pass {pass:<16} correct {:>4} (accepted {:>4}), wrong {:>2}, precision {precision:>6}, recall {recall:>5.1}%",
            p.correct(),
            p.accepted,
            p.wrong
        );
    }
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

/// Functions present in both builds that weren't matched correctly, one per line.
pub fn render_misses(v: &VariantScore) -> String {
    use crate::score::Outcome;
    let mut out = String::new();
    for f in &v.card.functions {
        let missed = !f.truth.is_empty()
            && matches!(
                f.outcome,
                Outcome::Ambiguous | Outcome::Unmatched | Outcome::Wrong
            );
        if missed {
            let old = f.old.map(|r| r.to_string()).unwrap_or_else(|| "-".into());
            let _ = writeln!(
                out,
                "    miss {:<10} {:<10} {}",
                format!("{:?}", f.outcome).to_lowercase(),
                old,
                f.names.join(",")
            );
        }
    }
    out
}
