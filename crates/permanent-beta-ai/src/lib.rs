//! AI proposer (design §8): for an old function matching left unmatched, show a model the function and a short
//! list of unmatched new-build functions, and turn its answer into a [`Candidate`] with `source: ai`.
//!
//! **A proposer, never a judge.** This crate depends on the model types only: it can't verify, record or
//! accept. Callers route every candidate through `permanent-beta-verify` (via the engine) and into the review
//! queue, like any other candidate (CLAUDE.md).
//!
//! - Minimal context: features of the old function and up to [`shortlist::SHORTLIST_LEN`] candidates, not code
//!   or the binary.
//! - Untrusted output: the reply must match a strict schema naming only offered candidates (or `none`);
//!   anything else is discarded. Nothing in a reply is executed.
//! - Measured: `pbeta-corpus score-ai` scores proposals against the answer keys, separately from the passes.

pub mod backend;
pub mod prompt;
pub mod shortlist;

use backend::Model;
use permanent_beta_model::{
    AnalysisExport, Candidate, CandidateSource, Evidence, Rva, evidence_kind,
};
use serde::Serialize;
use shortlist::Matched;

/// What happened when the proposer was asked about one old function.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum Outcome {
    /// The model picked a candidate. Unverified.
    Proposed { candidate: Candidate },
    /// The model said none of the candidates is the counterpart.
    Abstained { confidence: f32, rationale: String },
    /// No unmatched new function was close enough to ask about.
    NoShortlist,
    /// The model couldn't be asked, or its reply wasn't a valid answer (discarded).
    Failed { error: String },
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Asked {
    pub old: Rva,
    /// The new-build functions the model was shown, in prompt order.
    pub shortlist: Vec<Rva>,
    #[serde(flatten)]
    pub outcome: Outcome,
}

pub struct Proposer<'a> {
    model: &'a dyn Model,
    pub shortlist_len: usize,
}

impl<'a> Proposer<'a> {
    pub fn new(model: &'a dyn Model) -> Self {
        Self {
            model,
            shortlist_len: shortlist::SHORTLIST_LEN,
        }
    }

    /// Ask about one old function. `pairs` are the match so far (every engine candidate claims its functions).
    pub fn ask(
        &self,
        old: &AnalysisExport,
        new: &AnalysisExport,
        pairs: &[Candidate],
        rva: Rva,
    ) -> Asked {
        let m = Matched::new(old, new, pairs);
        self.ask_with(&m, old, new, rva)
    }

    /// [`Self::ask`] with the match context built once, for asking about many functions.
    pub fn ask_with(
        &self,
        m: &Matched,
        old: &AnalysisExport,
        new: &AnalysisExport,
        rva: Rva,
    ) -> Asked {
        let failed = |error: String| Asked {
            old: rva,
            shortlist: Vec::new(),
            outcome: Outcome::Failed { error },
        };
        let Some(old_fn) = old.function(rva) else {
            return failed(format!("no function at {rva} in the old build"));
        };
        if m.map.contains_key(&rva) {
            return failed(format!("{rva} is already matched"));
        }
        let list = shortlist::shortlist(m, new, old_fn, self.shortlist_len);
        let shown: Vec<Rva> = list.iter().map(|f| f.rva).collect();
        if list.is_empty() {
            return Asked {
                old: rva,
                shortlist: shown,
                outcome: Outcome::NoShortlist,
            };
        }
        let p = prompt::build(m, old_fn, &list);
        let outcome = match self
            .model
            .complete(&p)
            .and_then(|reply| prompt::parse(&p, &reply))
        {
            Err(error) => Outcome::Failed { error },
            Ok(a) => match a.choice {
                None => Outcome::Abstained {
                    confidence: a.confidence,
                    rationale: a.rationale,
                },
                Some(new_rva) => Outcome::Proposed {
                    candidate: Candidate {
                        old: rva,
                        new: new_rva,
                        source: CandidateSource::Ai {
                            model: self.model.name(),
                        },
                        score: a.confidence,
                        evidence: vec![Evidence {
                            kind: evidence_kind::AI.to_owned(),
                            detail: a.rationale,
                        }],
                    },
                },
            },
        };
        Asked {
            old: rva,
            shortlist: shown,
            outcome,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use backend::Scripted;
    use shortlist::tests::{export, func, pair};

    fn builds() -> (AnalysisExport, AnalysisExport) {
        (
            export(
                "a",
                vec![func(0x10, 64, &["save"], &[0x40]), func(0x40, 32, &[], &[])],
            ),
            export(
                "b",
                vec![
                    func(0x110, 64, &["save"], &[0x140]),
                    func(0x120, 64, &["save"], &[]),
                    func(0x140, 32, &[], &[]),
                ],
            ),
        )
    }

    #[test]
    fn a_pick_becomes_an_unverified_ai_candidate() {
        let (old, new) = builds();
        let model = Scripted(|_: &prompt::Prompt| {
            Ok(r#"{"choice":"c1","confidence":0.8,"rationale":"same string and callee"}"#.into())
        });
        let asked = Proposer::new(&model).ask(&old, &new, &[pair(0x40, 0x140)], Rva(0x10));
        let Outcome::Proposed { candidate } = &asked.outcome else {
            panic!("{asked:?}");
        };
        assert_eq!((candidate.old, candidate.new), (Rva(0x10), Rva(0x110)));
        assert_eq!(
            candidate.source,
            CandidateSource::Ai {
                model: "scripted".into()
            }
        );
        assert_eq!(candidate.evidence[0].kind, evidence_kind::AI);
        assert_eq!(asked.shortlist[0], Rva(0x110));
    }

    #[test]
    fn none_bad_replies_and_errors_never_become_candidates() {
        let (old, new) = builds();
        let pairs = [pair(0x40, 0x140)];
        let ask = |reply: &'static str| {
            let model = Scripted(move |_: &prompt::Prompt| Ok(reply.to_owned()));
            Proposer::new(&model)
                .ask(&old, &new, &pairs, Rva(0x10))
                .outcome
        };
        assert!(matches!(
            ask(r#"{"choice":"none","confidence":0.3,"rationale":"deleted?"}"#),
            Outcome::Abstained { .. }
        ));
        // A reply naming an address outright, or a matched function, isn't an offered choice.
        assert!(matches!(
            ask(r#"{"choice":"0x140","confidence":1,"rationale":"x"}"#),
            Outcome::Failed { .. }
        ));
        let down = Scripted(|_: &prompt::Prompt| Err("rate limited".into()));
        assert!(matches!(
            Proposer::new(&down)
                .ask(&old, &new, &pairs, Rva(0x10))
                .outcome,
            Outcome::Failed { .. }
        ));
        // Already matched functions aren't asked about.
        let any = Scripted(|_: &prompt::Prompt| Ok(String::new()));
        assert!(matches!(
            Proposer::new(&any)
                .ask(&old, &new, &pairs, Rva(0x40))
                .outcome,
            Outcome::Failed { .. }
        ));
    }
}
