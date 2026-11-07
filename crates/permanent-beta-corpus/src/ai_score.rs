//! Score the AI proposer against the answer key (design §8: AI proposals are measured separately from the passes).
//!
//! For each variant, the proposer is asked about the in-scope old functions that matching left unmatched,
//! including deleted ones, where the only right answer is `none`. Each proposal is verified like any candidate,
//! and judged against the answer key.

use crate::truth::GroundTruth;
use permanent_beta_ai::{Asked, Outcome, Proposer, backend::Model, shortlist::Matched};
use permanent_beta_engine::Engine;
use permanent_beta_model::{AnalysisExport, Criticality, Rva, Verdict};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct AiTotals {
    pub asked: u32,
    /// Proposals pointing at the true counterpart, and at anything else.
    pub correct: u32,
    pub wrong: u32,
    /// Of those, proposals verification would pass under the normal policy (still only queued for review).
    pub policy_correct: u32,
    pub policy_wrong: u32,
    /// `none` where the function was deleted (right), and where it has a counterpart (a miss).
    pub abstained_right: u32,
    pub abstained_missed: u32,
    /// The counterpart exists but wasn't on the shortlist: the model couldn't have picked it.
    pub not_shortlisted: u32,
    pub no_shortlist: u32,
    pub failed: u32,
}

impl AiTotals {
    pub fn add(&mut self, o: &AiTotals) {
        self.asked += o.asked;
        self.correct += o.correct;
        self.wrong += o.wrong;
        self.policy_correct += o.policy_correct;
        self.policy_wrong += o.policy_wrong;
        self.abstained_right += o.abstained_right;
        self.abstained_missed += o.abstained_missed;
        self.not_shortlisted += o.not_shortlisted;
        self.no_shortlist += o.no_shortlist;
        self.failed += o.failed;
    }

    /// Correct share of proposals, if any were made.
    pub fn precision(&self) -> Option<f64> {
        let all = self.correct + self.wrong;
        (all > 0).then(|| f64::from(self.correct) / f64::from(all))
    }
}

/// One asked function, judged.
#[derive(Debug, Clone, Serialize)]
pub struct AiRow {
    pub names: Vec<String>,
    pub old: Rva,
    pub truth: Vec<Rva>,
    pub asked: Asked,
    pub verdict: Option<Verdict>,
    pub judgement: &'static str,
}

/// Which unmatched in-scope old functions to ask about.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum Select {
    /// All of them.
    #[default]
    All,
    /// Only deleted ones (no counterpart in the new build): `none` is the only right answer.
    Deleted,
    /// Only ones with a counterpart.
    Present,
}

/// Ask about up to `limit` in-scope unmatched old functions chosen by `select` (lowest addresses first, so runs
/// are comparable).
pub fn score_variant(
    truth: &GroundTruth,
    old: &AnalysisExport,
    new: &AnalysisExport,
    model: &dyn Model,
    select: Select,
    limit: usize,
) -> (AiTotals, Vec<AiRow>) {
    let mut by_old: BTreeMap<Rva, (BTreeSet<String>, BTreeSet<Rva>)> = BTreeMap::new();
    for e in &truth.functions {
        if let Some(o) = e.old {
            let slot = by_old.entry(o).or_default();
            slot.0.extend(e.names.iter().cloned());
            slot.1.extend(e.new);
        }
    }
    let engine = Engine::with_defaults();
    let report = engine.match_builds(old, new);
    let pairs: Vec<_> = report.reports.iter().map(|r| r.candidate.clone()).collect();
    let m = Matched::new(old, new, &pairs);
    let proposer = Proposer::new(model);

    let mut totals = AiTotals::default();
    let mut rows = Vec::new();
    for &rva in report
        .unmatched_old
        .iter()
        .filter(|r| {
            by_old.get(r).is_some_and(|(_, t)| match select {
                Select::All => true,
                Select::Deleted => t.is_empty(),
                Select::Present => !t.is_empty(),
            })
        })
        .take(limit)
    {
        let (names, acceptable) = &by_old[&rva];
        let asked = proposer.ask_with(&m, old, new, rva);
        totals.asked += 1;
        let shortlisted = acceptable.iter().any(|t| asked.shortlist.contains(t));
        if !acceptable.is_empty()
            && !shortlisted
            && !matches!(asked.outcome, Outcome::Failed { .. })
        {
            totals.not_shortlisted += 1;
        }
        let mut verdict = None;
        let judgement = match &asked.outcome {
            Outcome::Proposed { candidate } => {
                verdict = engine
                    .verify_candidate(old, new, candidate, Criticality::Normal)
                    .map(|v| v.verdict);
                let right = acceptable.contains(&candidate.new);
                let passes = verdict == Some(Verdict::Accepted);
                match (right, passes) {
                    (true, true) => {
                        totals.correct += 1;
                        totals.policy_correct += 1;
                    }
                    (true, false) => totals.correct += 1,
                    (false, true) => {
                        totals.wrong += 1;
                        totals.policy_wrong += 1;
                    }
                    (false, false) => totals.wrong += 1,
                }
                if right { "correct" } else { "WRONG" }
            }
            Outcome::Abstained { .. } if acceptable.is_empty() => {
                totals.abstained_right += 1;
                "none (deleted: right)"
            }
            Outcome::Abstained { .. } => {
                totals.abstained_missed += 1;
                "none (missed)"
            }
            Outcome::NoShortlist => {
                totals.no_shortlist += 1;
                "no shortlist"
            }
            Outcome::Failed { .. } => {
                totals.failed += 1;
                "failed"
            }
        };
        rows.push(AiRow {
            names: names.iter().cloned().collect(),
            old: rva,
            truth: acceptable.iter().copied().collect(),
            asked,
            verdict,
            judgement,
        });
    }
    (totals, rows)
}

pub fn render_totals(label: &str, t: &AiTotals) -> String {
    format!(
        "[{label}] asked {}: proposed {} (correct {}, WRONG {}; passing the normal policy: {} correct, {} wrong), \
         none {} (right {}, missed {}), counterpart not shortlisted {}, no shortlist {}, failed {}{}",
        t.asked,
        t.correct + t.wrong,
        t.correct,
        t.wrong,
        t.policy_correct,
        t.policy_wrong,
        t.abstained_right + t.abstained_missed,
        t.abstained_right,
        t.abstained_missed,
        t.not_shortlisted,
        t.no_shortlist,
        t.failed,
        t.precision()
            .map(|p| format!("; precision {:.1}%", p * 100.0))
            .unwrap_or_default()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::truth::TruthEntry;
    use permanent_beta_ai::backend::Scripted;
    use permanent_beta_ai::prompt::Prompt;

    fn export(id: &str, functions: serde_json::Value) -> AnalysisExport {
        serde_json::from_value(serde_json::json!({
            "schema_version": permanent_beta_model::ANALYSIS_SCHEMA_VERSION,
            "build": { "id": id, "file_name": "t.exe", "version": null, "machine": "x64", "pdb": null },
            "producer": { "tool": "test", "version": "0" },
            "functions": functions,
        }))
        .unwrap()
    }

    fn f(rva: u64, hash: &str, strings: &[&str]) -> serde_json::Value {
        serde_json::json!({ "rva": rva, "size": 64, "name": null, "name_source": null, "normalized_hash": hash,
            "mnemonic_hash": null, "basic_blocks": null, "edges": null, "callees": [], "strings": strings,
            "constants": [], "imports": [], "signature": null })
    }

    fn entry(name: &str, old: Option<u64>, new: Option<u64>) -> TruthEntry {
        TruthEntry {
            names: vec![name.into()],
            old: old.map(Rva),
            new: new.map(Rva),
            is_static: false,
            renamed_to: None,
        }
    }

    #[test]
    fn proposals_are_judged_against_the_answer_key() {
        // `edited` (0x10 -> 0x110) and `gone` (0x20, deleted) are unmatched: different code, no unique strings.
        let old = export(
            "a",
            serde_json::json!([f(0x10, "e1", &["a", "b"]), f(0x20, "g1", &["z"])]),
        );
        let new = export(
            "b",
            serde_json::json!([f(0x110, "e2", &["a", "b", "c"]), f(0x130, "x", &["y"])]),
        );
        let truth = GroundTruth {
            schema_version: crate::truth::TRUTH_SCHEMA_VERSION,
            object: "t".into(),
            functions: vec![
                entry("edited", Some(0x10), Some(0x110)),
                entry("gone", Some(0x20), None),
            ],
        };
        // A model that always picks the first candidate: right for `edited`, wrong for `gone`.
        let first =
            Scripted(|_: &Prompt| Ok(r#"{"choice":"c1","confidence":0.9,"rationale":"x"}"#.into()));
        let (t, rows) = score_variant(&truth, &old, &new, &first, Select::All, 10);
        assert_eq!((t.asked, t.correct, t.wrong), (2, 1, 1), "{rows:#?}");
        // A model that always says none: right for the deleted one, a miss for the edited one.
        let none = Scripted(|_: &Prompt| {
            Ok(r#"{"choice":"none","confidence":0.5,"rationale":"x"}"#.into())
        });
        let (t, _) = score_variant(&truth, &old, &new, &none, Select::All, 10);
        assert_eq!(
            (t.abstained_right, t.abstained_missed, t.correct + t.wrong),
            (1, 1, 0)
        );
        assert_eq!(t.precision(), None);
        // The limit bounds the questions.
        assert_eq!(
            score_variant(&truth, &old, &new, &none, Select::All, 1)
                .0
                .asked,
            1
        );
        // Selecting deleted functions asks only about `gone`; a model that always picks c1 is then always wrong.
        let (t, rows) = score_variant(&truth, &old, &new, &first, Select::Deleted, 10);
        assert_eq!((t.asked, t.correct, t.wrong), (1, 0, 1), "{rows:#?}");
        assert_eq!(rows[0].names, vec!["gone".to_owned()]);
        let (t, _) = score_variant(&truth, &old, &new, &none, Select::Present, 10);
        assert_eq!((t.asked, t.abstained_missed), (1, 1));
    }
}
