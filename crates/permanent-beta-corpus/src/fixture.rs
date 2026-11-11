//! Run the real pipeline on one built variant and score it.
//!
//! A variant directory holds `v1/` and `v2/`, each with exactly one `.exe`, plus `truth.json`. Written by
//! `corpus/build-fixtures.ps1` (`target/fixtures/<name>/<flags>/`) and `corpus/build-projects.ps1`
//! (`target/corpus/<project>/<flags>__<old>__<new>/`).

use crate::expected::{Evaluation, Expected};
use crate::score::{Outcome, Scorecard, score};
use crate::truth::GroundTruth;
use anyhow::{Context, Result};
use permanent_beta_analysis::{Analyzer, native::NativePeAnalyzer, symbols};
use permanent_beta_engine::Engine;
use permanent_beta_engine::permanent_beta_match::{SimilarityParams, matchers_with_similarity};
use permanent_beta_engine::permanent_beta_verify::Verifier;
use permanent_beta_model::{AnalysisExport, CheckOutcome, VerificationReport};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

pub struct VariantScore {
    pub flags: String,
    pub card: Scorecard,
    pub evaluation: Evaluation,
    /// What the `param-count` check said about the candidates, by whether they were right.
    pub param_count: CheckTally,
}

/// One check's outcomes over a variant's candidates, split by the answer key.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CheckTally {
    pub correct: [u32; 3],
    pub wrong: [u32; 3],
}

impl CheckTally {
    const PASS: usize = 0;
    const FAIL: usize = 1;
    const INCONCLUSIVE: usize = 2;

    fn count(reports: &[VerificationReport], card: &Scorecard, check: &str) -> Self {
        let mut t = Self::default();
        for r in reports {
            let Some(c) = r.checks.iter().find(|c| c.check == check) else {
                continue;
            };
            // Only candidates the answer key judges: correct, or wrong (in scope).
            let Some(f) = card.functions.iter().find(|f| {
                f.got == Some(r.candidate.new) && f.old.is_none_or(|o| o == r.candidate.old)
            }) else {
                continue;
            };
            let slot = match c.outcome {
                CheckOutcome::Pass => Self::PASS,
                CheckOutcome::Fail => Self::FAIL,
                CheckOutcome::Inconclusive => Self::INCONCLUSIVE,
            };
            match f.outcome {
                Outcome::Accepted | Outcome::Review => t.correct[slot] += 1,
                Outcome::Wrong => t.wrong[slot] += 1,
                Outcome::Ambiguous | Outcome::Unmatched => {}
            }
        }
        t
    }

    /// Anything but inconclusive: the check had both signatures for some candidate.
    pub fn decided(&self) -> bool {
        self.correct[Self::PASS]
            + self.correct[Self::FAIL]
            + self.wrong[Self::PASS]
            + self.wrong[Self::FAIL]
            > 0
    }
}

/// What the analyses carry besides the native analyzer's features.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Symbols {
    /// Nothing: the default, what a customer without PDBs has.
    #[default]
    None,
    /// Each function's PDB signature (parameter types and names) and nothing else from the PDB: no function
    /// names (the name pass would match by them), no types, no globals. For measuring the `param-count` check.
    Signatures,
}

/// Analyze both builds natively, match them with the default engine, and score against the answer key.
pub fn score_variant(
    dir: &Path,
    flags: &str,
    expected: &Expected,
    symbols: Symbols,
) -> Result<VariantScore> {
    let (truth, old, new) = load_variant_with(dir, symbols)?;
    let report = Engine::with_defaults().match_builds(&old, &new)?;
    let card = score(&truth, &report.reports, &report.ambiguities);
    let evaluation = expected.evaluate(flags, &card);
    let param_count = CheckTally::count(&report.reports, &card, "param-count");
    Ok(VariantScore {
        flags: flags.to_owned(),
        card,
        evaluation,
        param_count,
    })
}

/// The PDB of `exe`: beside it, or (corpus projects, whose variants hold copies of the executables) in the
/// project's `builds/<flags>/<tag>/` for a variant directory named `<flags>__<old>__<new>`.
fn pdb_of(exe: &Path, variant: &Path, side: &str) -> Option<PathBuf> {
    let beside = exe.with_extension("pdb");
    if beside.exists() {
        return Some(beside);
    }
    let name = variant.file_name()?.to_str()?;
    let parts: Vec<&str> = name.split("__").collect();
    let [flags, old, new] = parts.as_slice() else {
        return None;
    };
    let tag = if side == "v1" { old } else { new };
    let p = variant
        .parent()?
        .join("builds")
        .join(flags)
        .join(tag)
        .join(beside.file_name()?);
    p.exists().then_some(p)
}

/// Adds only the PDB's signatures to `export`, by entry RVA (folded entries get none). Refused unless the PDB is
/// this build's.
fn add_signatures(export: &mut AnalysisExport, pdb: &Path) -> Result<()> {
    let symbols =
        symbols::read(pdb).with_context(|| format!("reading the PDB {}", pdb.display()))?;
    symbols::check_matches(export, &symbols).map_err(anyhow::Error::msg)?;
    for f in &mut export.functions {
        if let Some([p]) = symbols.procedures.get(&f.rva).map(Vec::as_slice) {
            f.signature = p.signature.clone();
        }
    }
    Ok(())
}

/// A variant's answer key and both builds' native analyses.
pub fn load_variant(dir: &Path) -> Result<(GroundTruth, AnalysisExport, AnalysisExport)> {
    load_variant_with(dir, Symbols::None)
}

/// [`load_variant`], with `symbols` added to both analyses.
pub fn load_variant_with(
    dir: &Path,
    symbols: Symbols,
) -> Result<(GroundTruth, AnalysisExport, AnalysisExport)> {
    let truth_path = dir.join("truth.json");
    let truth: GroundTruth =
        serde_json::from_str(&std::fs::read_to_string(&truth_path).with_context(|| {
            format!(
                "reading {}; run corpus/build-fixtures.ps1 first",
                truth_path.display()
            )
        })?)
        .with_context(|| format!("parsing {}", truth_path.display()))?;

    let analyze = |v: &str| -> Result<AnalysisExport> {
        let exe = single_exe(&dir.join(v))?;
        let mut export = NativePeAnalyzer
            .analyze(&exe)
            .with_context(|| format!("analyzing {}", exe.display()))?;
        if symbols == Symbols::Signatures {
            let pdb = pdb_of(&exe, dir, v)
                .with_context(|| format!("no PDB found for {}", exe.display()))?;
            add_signatures(&mut export, &pdb)?;
        }
        Ok(export)
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
) -> Result<Vec<SweepPoint>> {
    grid.iter()
        .map(|&params| {
            let engine = Engine::new(matchers_with_similarity(params), Verifier::with_defaults());
            let report = engine.match_builds(old, new)?;
            let card = score(truth, &report.reports, &report.ambiguities);
            let sim = card
                .by_pass()
                .get("similarity")
                .copied()
                .unwrap_or_default();
            Ok(SweepPoint {
                params,
                correct: card.totals.correct(),
                accepted: card.totals.accepted,
                wrong: card.totals.wrong,
                sim_correct: sim.correct(),
                sim_wrong: sim.wrong,
            })
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
    let pc = &v.param_count;
    if pc.decided() {
        let _ = writeln!(
            out,
            "  check param-count  correct: pass {}, fail {}, inconclusive {}; wrong: pass {}, fail {}, inconclusive {}",
            pc.correct[0], pc.correct[1], pc.correct[2], pc.wrong[0], pc.wrong[1], pc.wrong[2]
        );
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_projects_pdb_is_found_in_its_builds() {
        let root = std::env::temp_dir().join(format!("pbeta-pdb-of-{}", std::process::id()));
        let variant = root.join("zlib").join("o2__v1.3__v1.3.1");
        let build = |tag: &str| root.join("zlib").join("builds").join("o2").join(tag);
        for d in [variant.join("v1"), build("v1.3"), build("v1.3.1")] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::write(build("v1.3").join("minigzip.pdb"), b"").unwrap();
        std::fs::write(build("v1.3.1").join("minigzip.pdb"), b"").unwrap();
        let exe = variant.join("v1").join("minigzip.exe");
        assert_eq!(
            pdb_of(&exe, &variant, "v1"),
            Some(build("v1.3").join("minigzip.pdb"))
        );
        assert_eq!(
            pdb_of(&exe, &variant, "v2"),
            Some(build("v1.3.1").join("minigzip.pdb"))
        );
        // Beside the executable wins (the fixtures).
        std::fs::write(variant.join("v1").join("minigzip.pdb"), b"").unwrap();
        assert_eq!(
            pdb_of(&exe, &variant, "v1"),
            Some(variant.join("v1").join("minigzip.pdb"))
        );
        // Negative: a variant not named <flags>__<old>__<new>, or a build without a PDB, finds nothing.
        let odd = root.join("zlib").join("o2");
        assert_eq!(
            pdb_of(&odd.join("v1").join("minigzip.exe"), &odd, "v1"),
            None
        );
        std::fs::remove_file(build("v1.3.1").join("minigzip.pdb")).unwrap();
        let v2 = variant.join("v2").join("minigzip.exe");
        assert_eq!(pdb_of(&v2, &variant, "v2"), None);
        let _ = std::fs::remove_dir_all(&root);
    }
}
