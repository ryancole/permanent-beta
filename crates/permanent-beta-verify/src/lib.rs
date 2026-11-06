//! Verification (design §6). Applied identically to deterministic, AI and human candidates.

use permanent_beta_model::{
    Candidate, CheckOutcome, CheckResult, Criticality, FunctionFeatures, Verdict,
    VerificationReport,
};
use std::collections::HashSet;

pub trait StructuralCheck {
    fn name(&self) -> &'static str;
    fn check(&self, old: &FunctionFeatures, new: &FunctionFeatures) -> CheckResult;
}

/// Replays recorded behavioral tests (design §7.3) against the new build.
pub trait BehavioralRunner {
    fn run(
        &self,
        candidate: &Candidate,
        old: &FunctionFeatures,
        new: &FunctionFeatures,
    ) -> CheckResult;
}

/// Placeholder until the harness exists: always inconclusive.
pub struct NoBehavioralCorpus;

impl BehavioralRunner for NoBehavioralCorpus {
    fn run(&self, _: &Candidate, _: &FunctionFeatures, _: &FunctionFeatures) -> CheckResult {
        CheckResult::new(
            "behavioral",
            CheckOutcome::Inconclusive,
            "no recorded behavioral tests for this function",
        )
    }
}

/// Acceptance policy per hook criticality (design §6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    pub min_structural_passes: usize,
    pub require_behavioral_pass: bool,
}

impl Policy {
    pub fn for_criticality(c: Criticality) -> Self {
        match c {
            Criticality::Low => Self {
                min_structural_passes: 1,
                require_behavioral_pass: false,
            },
            Criticality::Normal => Self {
                min_structural_passes: 2,
                require_behavioral_pass: false,
            },
            Criticality::High => Self {
                min_structural_passes: 2,
                require_behavioral_pass: true,
            },
        }
    }
}

pub struct Verifier {
    checks: Vec<Box<dyn StructuralCheck>>,
    behavioral: Box<dyn BehavioralRunner>,
}

impl Verifier {
    pub fn new(
        checks: Vec<Box<dyn StructuralCheck>>,
        behavioral: Box<dyn BehavioralRunner>,
    ) -> Self {
        Self { checks, behavioral }
    }

    pub fn with_defaults() -> Self {
        Self::new(
            vec![
                Box::new(ParamCountCheck),
                Box::new(StringRefCheck),
                Box::new(SizeRatioCheck),
            ],
            Box::new(NoBehavioralCorpus),
        )
    }

    // TODO(design §6.1): count only checks independent of the pass that produced the candidate.
    pub fn verify(
        &self,
        candidate: &Candidate,
        old: &FunctionFeatures,
        new: &FunctionFeatures,
        policy: Policy,
    ) -> VerificationReport {
        let mut checks: Vec<CheckResult> = self.checks.iter().map(|c| c.check(old, new)).collect();
        let fails = checks
            .iter()
            .filter(|c| c.outcome == CheckOutcome::Fail)
            .count();
        let passes = checks
            .iter()
            .filter(|c| c.outcome == CheckOutcome::Pass)
            .count();

        let behavioral = self.behavioral.run(candidate, old, new);
        let behavioral_outcome = behavioral.outcome;
        checks.push(behavioral);

        let verdict = decide(fails, passes, behavioral_outcome, policy);
        VerificationReport {
            candidate: candidate.clone(),
            checks,
            verdict,
        }
    }
}

fn decide(fails: usize, passes: usize, behavioral: CheckOutcome, policy: Policy) -> Verdict {
    if fails >= 2 {
        Verdict::Rejected
    } else if fails == 1 || behavioral == CheckOutcome::Fail {
        Verdict::NeedsReview
    } else if passes >= policy.min_structural_passes
        && (!policy.require_behavioral_pass || behavioral == CheckOutcome::Pass)
    {
        Verdict::Accepted
    } else {
        Verdict::NeedsReview
    }
}

/// Parameter count must match when both signatures are known.
pub struct ParamCountCheck;

impl StructuralCheck for ParamCountCheck {
    fn name(&self) -> &'static str {
        "param-count"
    }

    fn check(&self, old: &FunctionFeatures, new: &FunctionFeatures) -> CheckResult {
        match (&old.signature, &new.signature) {
            (Some(a), Some(b)) if a.params.len() == b.params.len() => CheckResult::new(
                self.name(),
                CheckOutcome::Pass,
                format!("{} params", a.params.len()),
            ),
            (Some(a), Some(b)) => CheckResult::new(
                self.name(),
                CheckOutcome::Fail,
                format!("{} params → {} params", a.params.len(), b.params.len()),
            ),
            _ => CheckResult::new(self.name(), CheckOutcome::Inconclusive, "signature unknown"),
        }
    }
}

/// Jaccard similarity of referenced strings. Threshold 0.5 is a guess until calibrated.
pub struct StringRefCheck;

impl StructuralCheck for StringRefCheck {
    fn name(&self) -> &'static str {
        "string-refs"
    }

    fn check(&self, old: &FunctionFeatures, new: &FunctionFeatures) -> CheckResult {
        let a: HashSet<&str> = old.strings.iter().map(String::as_str).collect();
        let b: HashSet<&str> = new.strings.iter().map(String::as_str).collect();
        if a.is_empty() && b.is_empty() {
            return CheckResult::new(
                self.name(),
                CheckOutcome::Inconclusive,
                "no string references",
            );
        }
        let jaccard = a.intersection(&b).count() as f32 / a.union(&b).count() as f32;
        let outcome = if jaccard >= 0.5 {
            CheckOutcome::Pass
        } else {
            CheckOutcome::Fail
        };
        CheckResult::new(self.name(), outcome, format!("Jaccard {jaccard:.2}"))
    }
}

/// Size ratio new/old: pass within 0.5–2.0, fail outside 0.25–4.0. Thresholds are guesses.
pub struct SizeRatioCheck;

impl StructuralCheck for SizeRatioCheck {
    fn name(&self) -> &'static str {
        "size-ratio"
    }

    fn check(&self, old: &FunctionFeatures, new: &FunctionFeatures) -> CheckResult {
        if old.size == 0 || new.size == 0 {
            return CheckResult::new(self.name(), CheckOutcome::Inconclusive, "size unknown");
        }
        let ratio = new.size as f32 / old.size as f32;
        let outcome = if (0.5..=2.0).contains(&ratio) {
            CheckOutcome::Pass
        } else if !(0.25..=4.0).contains(&ratio) {
            CheckOutcome::Fail
        } else {
            CheckOutcome::Inconclusive
        };
        CheckResult::new(
            self.name(),
            outcome,
            format!("{} → {} bytes ({ratio:.2}x)", old.size, new.size),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use permanent_beta_model::{CandidateSource, FunctionSignature, Param, Rva};

    fn func(size: u32, strings: &[&str], params: Option<usize>) -> FunctionFeatures {
        FunctionFeatures {
            rva: Rva(0),
            size,
            name: None,
            name_source: None,
            normalized_hash: None,
            mnemonic_hash: None,
            basic_blocks: None,
            edges: None,
            callees: vec![],
            strings: strings.iter().map(|s| s.to_string()).collect(),
            constants: vec![],
            imports: vec![],
            signature: params.map(|n| FunctionSignature {
                calling_convention: None,
                return_type: None,
                params: (0..n)
                    .map(|_| Param {
                        name: None,
                        ty: "int".into(),
                    })
                    .collect(),
            }),
        }
    }

    fn cand() -> Candidate {
        Candidate {
            old: Rva(0),
            new: Rva(0),
            source: CandidateSource::Deterministic {
                matcher: "test".into(),
            },
            score: 1.0,
            evidence: vec![],
        }
    }

    #[test]
    fn normal_hook_accepted_on_two_structural_passes() {
        let f = func(100, &["a"], Some(2));
        let r = Verifier::with_defaults().verify(
            &cand(),
            &f,
            &f,
            Policy::for_criticality(Criticality::Normal),
        );
        assert_eq!(r.verdict, Verdict::Accepted);
    }

    #[test]
    fn high_criticality_needs_behavioral_pass() {
        let f = func(100, &["a"], Some(2));
        let r = Verifier::with_defaults().verify(
            &cand(),
            &f,
            &f,
            Policy::for_criticality(Criticality::High),
        );
        assert_eq!(r.verdict, Verdict::NeedsReview);
    }

    #[test]
    fn param_count_change_needs_review() {
        let r = Verifier::with_defaults().verify(
            &cand(),
            &func(100, &["a"], Some(2)),
            &func(100, &["a"], Some(3)),
            Policy::for_criticality(Criticality::Low),
        );
        assert_eq!(r.verdict, Verdict::NeedsReview);
    }

    #[test]
    fn two_structural_failures_reject() {
        let r = Verifier::with_defaults().verify(
            &cand(),
            &func(100, &["a"], Some(2)),
            &func(1000, &["b"], Some(2)),
            Policy::for_criticality(Criticality::Low),
        );
        assert_eq!(r.verdict, Verdict::Rejected);
    }

    #[test]
    fn no_evidence_is_not_acceptance() {
        let f = func(0, &[], None);
        let r = Verifier::with_defaults().verify(
            &cand(),
            &f,
            &f,
            Policy::for_criticality(Criticality::Low),
        );
        assert_eq!(r.verdict, Verdict::NeedsReview);
    }
}
