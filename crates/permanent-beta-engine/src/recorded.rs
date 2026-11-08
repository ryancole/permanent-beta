//! Behavioral evidence from recorded per-call test cases (design §6.2, §7.3): every case recorded at the
//! candidate's old RVA in its old build is replayed on the candidate in the new build (`permanent-beta-replay`).
//!
//! Pass if every case that can be replayed matches and at least one can; fail if any differs; inconclusive if
//! none can be replayed (imports, uncaptured memory or globals, unmappable layouts, no emulator), or there are no
//! cases for this function of this build. Cases are matched to builds like scenario traces: a case of another
//! build is no evidence, its RVA being another function there.

use permanent_beta_model::{
    BuildId, Candidate, CheckOutcome, CheckResult, FunctionFeatures, Rva, TypeLayout,
};
use permanent_beta_replay::{CaseOutcome, Image, Recording, replay};
use permanent_beta_verify::{BehavioralRunner, VerifyContext};
use serde::Serialize;
use std::collections::BTreeMap;

pub struct RecordedCasesRunner {
    recordings: Vec<Recording>,
    image: Image,
    new_layouts: Vec<TypeLayout>,
}

/// Every case for one old function, replayed on one new function.
#[derive(Debug, Clone, Serialize)]
pub struct Judgement {
    pub outcome: CheckOutcome,
    pub detail: String,
    pub cases: Vec<CaseResult>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CaseResult {
    pub test_id: String,
    #[serde(flatten)]
    pub outcome: CaseOutcome,
}

impl RecordedCasesRunner {
    /// `image` is the new build's binary; `new_layouts` its PDB struct layouts (the new analysis' `types`).
    pub fn new(recordings: Vec<Recording>, image: Image, new_layouts: Vec<TypeLayout>) -> Self {
        Self {
            recordings,
            image,
            new_layouts,
        }
    }

    pub fn image_build(&self) -> &BuildId {
        &self.image.build
    }

    /// Replays every case recorded at `old_rva` (in `old_build`, or in any build when `None`) on `new_rva`.
    pub fn judge(&self, old_build: Option<&BuildId>, old_rva: Rva, new_rva: Rva) -> Judgement {
        let mut cases = Vec::new();
        for rec in self
            .recordings
            .iter()
            .filter(|r| old_build.is_none_or(|b| &r.spec.build == b))
        {
            for c in rec.cases.iter().filter(|c| c.case.rva == old_rva) {
                cases.push(CaseResult {
                    test_id: c.case.test_id.clone(),
                    outcome: replay(&self.image, new_rva, &rec.spec, c, &self.new_layouts),
                });
            }
        }
        let (outcome, detail) = summarize(&cases, old_rva);
        Judgement {
            outcome,
            detail,
            cases,
        }
    }
}

fn summarize(cases: &[CaseResult], old_rva: Rva) -> (CheckOutcome, String) {
    if cases.is_empty() {
        return (
            CheckOutcome::Inconclusive,
            format!("no recorded cases at {old_rva} in the old build"),
        );
    }
    let mut reasons: BTreeMap<&str, usize> = BTreeMap::new();
    let mut passed = 0;
    for c in cases {
        match &c.outcome {
            CaseOutcome::Fail { detail } => {
                return (
                    CheckOutcome::Fail,
                    format!("recorded case {} differs: {detail}", c.test_id),
                );
            }
            CaseOutcome::Pass { .. } => passed += 1,
            CaseOutcome::Inconclusive { reason } => *reasons.entry(reason).or_default() += 1,
        }
    }
    let why = reasons
        .iter()
        .map(|(r, n)| {
            if *n > 1 {
                format!("{r} (x{n})")
            } else {
                (*r).to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("; ");
    if passed > 0 {
        let rest = if reasons.is_empty() {
            String::new()
        } else {
            format!("; {} not replayable: {why}", cases.len() - passed)
        };
        (
            CheckOutcome::Pass,
            format!(
                "{passed} of {} recorded cases replay identically{rest}",
                cases.len()
            ),
        )
    } else {
        (
            CheckOutcome::Inconclusive,
            format!(
                "none of {} recorded cases could be replayed: {why}",
                cases.len()
            ),
        )
    }
}

impl BehavioralRunner for RecordedCasesRunner {
    fn run(
        &self,
        ctx: &VerifyContext,
        candidate: &Candidate,
        _old: &FunctionFeatures,
        _new: &FunctionFeatures,
    ) -> CheckResult {
        if self.image.build != ctx.new_build {
            return CheckResult::new(
                "behavioral",
                CheckOutcome::Inconclusive,
                format!(
                    "the binary given for replay is build {}, not the new build {}",
                    short(&self.image.build),
                    short(&ctx.new_build)
                ),
            );
        }
        let j = self.judge(Some(&ctx.old_build), candidate.old, candidate.new);
        CheckResult::new("behavioral", j.outcome, j.detail)
    }
}

fn short(id: &BuildId) -> &str {
    id.0.get(..12).unwrap_or(&id.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(id: &str, outcome: CaseOutcome) -> CaseResult {
        CaseResult {
            test_id: id.into(),
            outcome,
        }
    }

    fn pass() -> CaseOutcome {
        CaseOutcome::Pass {
            detail: "same".into(),
        }
    }

    fn inconclusive(why: &str) -> CaseOutcome {
        CaseOutcome::Inconclusive { reason: why.into() }
    }

    #[test]
    fn every_replayable_case_must_match() {
        let (o, d) = summarize(
            &[
                result("f-1", pass()),
                result("f-2", inconclusive("calls the import x")),
            ],
            Rva(0x10),
        );
        assert_eq!(o, CheckOutcome::Pass);
        assert!(
            d.contains("1 of 2") && d.contains("calls the import x"),
            "{d}"
        );
        // Negative: one differing case fails the candidate, however many pass.
        let (o, d) = summarize(
            &[
                result("f-1", pass()),
                result(
                    "f-2",
                    CaseOutcome::Fail {
                        detail: "returned 0x1, expected 0x2".into(),
                    },
                ),
                result("f-3", pass()),
            ],
            Rva(0x10),
        );
        assert_eq!(o, CheckOutcome::Fail);
        assert!(d.contains("f-2"), "{d}");
    }

    #[test]
    fn no_replayable_case_is_no_evidence() {
        // Negative: inconclusive cases never add up to a pass.
        let (o, d) = summarize(
            &[
                result("f-1", inconclusive("a")),
                result("f-2", inconclusive("a")),
            ],
            Rva(0x10),
        );
        assert_eq!(o, CheckOutcome::Inconclusive);
        assert!(d.contains("a (x2)"), "{d}");
        // Negative: no cases at all.
        assert_eq!(summarize(&[], Rva(0x10)).0, CheckOutcome::Inconclusive);
    }
}
