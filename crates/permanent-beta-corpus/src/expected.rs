//! Expected outcomes for a fixture (`corpus/fixtures/<name>/expected.toml`).
//!
//! Two kinds of expectation:
//! - **Gate** (must hold now; CI fails otherwise): zero wrong matches, and at least `min_correct[flags]` correct
//!   matches. Raise `min_correct` when matching improves so it can't silently regress.
//! - **Targets** (what the engine should eventually do per scenario): reported as met or not yet, never failing.

use crate::score::{Outcome, Scorecard};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Expected {
    pub gate: Gate,
    #[serde(rename = "scenario", default)]
    pub scenarios: Vec<Scenario>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Gate {
    /// Correct matches (any verdict) required per flag set.
    pub min_correct: BTreeMap<String, u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scenario {
    pub id: String,
    /// Any one of the function's names (folded functions have several).
    pub function: String,
    pub target: Target,
    /// Per-flag-set target, e.g. identical copies are ambiguous unless `/OPT:ICF` folded them.
    #[serde(default)]
    pub overrides: BTreeMap<String, Target>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Target {
    Accepted,
    Review,
    Ambiguous,
    Unmatched,
    /// Exists only in the new build: nothing may be matched onto it.
    Added,
}

impl Scenario {
    pub fn target_for(&self, flags: &str) -> Target {
        self.overrides.get(flags).copied().unwrap_or(self.target)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScenarioResult {
    pub id: String,
    pub function: String,
    pub target: Target,
    /// `None` for `added` functions, which have no old address.
    pub actual: Option<Outcome>,
    pub met: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evaluation {
    pub scenarios: Vec<ScenarioResult>,
    /// Gate failures. Empty means the gate passed.
    pub gate_failures: Vec<String>,
}

impl Expected {
    pub fn parse(text: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(text)
    }

    pub fn evaluate(&self, flags: &str, card: &Scorecard) -> Evaluation {
        let mut gate_failures = Vec::new();
        if card.totals.wrong > 0 {
            let wrong: Vec<String> = card
                .functions
                .iter()
                .filter(|f| f.outcome == Outcome::Wrong)
                .map(|f| {
                    format!(
                        "{} (got {:?}, truth {:?})",
                        f.names.join(","),
                        f.got,
                        f.truth
                    )
                })
                .collect();
            gate_failures.push(format!(
                "{} wrong match(es): {}",
                card.totals.wrong,
                wrong.join("; ")
            ));
        }
        match self.gate.min_correct.get(flags) {
            Some(&min) if card.totals.correct() < min => gate_failures.push(format!(
                "{} correct matches, below the baseline of {min}",
                card.totals.correct()
            )),
            Some(_) => {}
            None => gate_failures.push(format!(
                "no gate.min_correct baseline for flag set `{flags}`"
            )),
        }

        let scenarios = self
            .scenarios
            .iter()
            .map(|s| {
                let target = s.target_for(flags);
                let actual = card.outcome_of(&s.function).map(|f| f.outcome);
                let met = match (target, actual) {
                    // Added functions have no old address; any wrong match onto them shows up as Wrong.
                    (Target::Added, None) => true,
                    (Target::Added, Some(_)) => false,
                    (Target::Accepted, Some(Outcome::Accepted))
                    | (Target::Review, Some(Outcome::Review))
                    | (Target::Ambiguous, Some(Outcome::Ambiguous))
                    | (Target::Unmatched, Some(Outcome::Unmatched)) => true,
                    _ => false,
                };
                ScenarioResult {
                    id: s.id.clone(),
                    function: s.function.clone(),
                    target,
                    actual,
                    met,
                }
            })
            .collect();

        Evaluation {
            scenarios,
            gate_failures,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::score::{FunctionScore, Totals};
    use permanent_beta_model::Rva;

    fn card(outcome: Outcome, wrong: u32, correct: u32) -> Scorecard {
        Scorecard {
            functions: vec![FunctionScore {
                names: vec!["f".into()],
                old: Some(Rva(1)),
                truth: vec![Rva(2)],
                outcome,
                got: None,
                matcher: None,
            }],
            totals: Totals {
                accepted: correct,
                wrong,
                ..Default::default()
            },
        }
    }

    const TOML: &str = r#"
        [gate.min_correct]
        o2 = 1

        [[scenario]]
        id = "S1"
        function = "f"
        target = "accepted"
        overrides = { od = "review" }
    "#;

    #[test]
    fn target_met_and_override_applied() {
        let e = Expected::parse(TOML).unwrap();
        let ev = e.evaluate("o2", &card(Outcome::Accepted, 0, 1));
        assert!(ev.gate_failures.is_empty());
        assert!(ev.scenarios[0].met);
        assert_eq!(e.scenarios[0].target_for("od"), Target::Review);
    }

    #[test]
    fn wrong_matches_fail_the_gate() {
        let ev = Expected::parse(TOML)
            .unwrap()
            .evaluate("o2", &card(Outcome::Wrong, 1, 1));
        assert_eq!(ev.gate_failures.len(), 1);
    }

    #[test]
    fn regression_below_baseline_fails_the_gate() {
        let ev = Expected::parse(TOML)
            .unwrap()
            .evaluate("o2", &card(Outcome::Accepted, 0, 0));
        assert_eq!(ev.gate_failures.len(), 1);
    }

    #[test]
    fn unmet_target_does_not_fail_the_gate() {
        let ev = Expected::parse(TOML)
            .unwrap()
            .evaluate("o2", &card(Outcome::Review, 0, 1));
        assert!(ev.gate_failures.is_empty());
        assert!(!ev.scenarios[0].met);
    }

    #[test]
    fn missing_baseline_fails_the_gate() {
        let ev = Expected::parse(TOML)
            .unwrap()
            .evaluate("o2-icf", &card(Outcome::Accepted, 0, 1));
        assert_eq!(ev.gate_failures.len(), 1);
    }
}
