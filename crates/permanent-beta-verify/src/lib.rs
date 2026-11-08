//! Verification (design §6). Applied identically to deterministic, AI and human candidates.
//!
//! Independence (design §6.1): a check that measures what the candidate's evidence already established adds
//! nothing. Identical normalized code trivially has the same strings and size, so for a hash match those passes
//! don't count. [`implied_checks`] encodes this per evidence kind. Size is also a sanity check only: its range
//! is wide enough that a pass says little, but a wildly different size is still a strong reason to fail.

use permanent_beta_model::{
    AnalysisExport, BuildId, Candidate, CheckOutcome, CheckResult, CodeTable, Criticality,
    FunctionFeatures, Rva, Verdict, VerificationReport, evidence_kind,
};
use std::collections::{HashMap, HashSet};

pub mod behavioral;
pub use behavioral::TraceDiffRunner;

/// What checks can see beyond the two functions: the other candidates of this run and call-graph indexes.
///
/// The mapping holds *candidates*, not accepted mappings, so neighbour checks measure consistency with the rest
/// of the match, not ground truth.
#[derive(Debug, Default)]
pub struct VerifyContext {
    /// The two builds being compared, so evidence recorded per build (e.g. traces) is only used for its own build.
    pub old_build: BuildId,
    pub new_build: BuildId,
    mapping: HashMap<Rva, Rva>,
    old_callers: HashMap<Rva, Vec<Rva>>,
    new_callers: HashMap<Rva, Vec<Rva>>,
    old_tables: Vec<CodeTable>,
    new_tables: Vec<CodeTable>,
}

impl VerifyContext {
    pub fn new(old: &AnalysisExport, new: &AnalysisExport, candidates: &[Candidate]) -> Self {
        Self {
            old_build: old.build.id.clone(),
            new_build: new.build.id.clone(),
            mapping: candidates.iter().map(|c| (c.old, c.new)).collect(),
            old_callers: callers_index(old),
            new_callers: callers_index(new),
            old_tables: old.code_tables.clone(),
            new_tables: new.code_tables.clone(),
        }
    }

    fn callers(index: &HashMap<Rva, Vec<Rva>>, f: Rva) -> &[Rva] {
        index.get(&f).map(Vec::as_slice).unwrap_or(&[])
    }
}

fn callers_index(export: &AnalysisExport) -> HashMap<Rva, Vec<Rva>> {
    let mut index: HashMap<Rva, Vec<Rva>> = HashMap::new();
    for f in &export.functions {
        for &callee in &f.callees {
            index.entry(callee).or_default().push(f.rva);
        }
    }
    index
}

pub trait StructuralCheck {
    fn name(&self) -> &'static str;
    fn check(
        &self,
        ctx: &VerifyContext,
        old: &FunctionFeatures,
        new: &FunctionFeatures,
    ) -> CheckResult;
}

/// Replays recorded behavioral tests (design §7.3) against the new build.
pub trait BehavioralRunner {
    fn run(
        &self,
        ctx: &VerifyContext,
        candidate: &Candidate,
        old: &FunctionFeatures,
        new: &FunctionFeatures,
    ) -> CheckResult;
}

/// Placeholder until the harness exists: always inconclusive.
pub struct NoBehavioralCorpus;

impl BehavioralRunner for NoBehavioralCorpus {
    fn run(
        &self,
        _: &VerifyContext,
        _: &Candidate,
        _: &FunctionFeatures,
        _: &FunctionFeatures,
    ) -> CheckResult {
        CheckResult::new(
            "behavioral",
            CheckOutcome::Inconclusive,
            "no recorded behavioral tests for this function",
        )
    }
}

/// Checks whose pass is already implied by a piece of evidence.
pub fn implied_checks(kind: &str) -> &'static [&'static str] {
    match kind {
        // Identical normalized code: same referenced strings, size, constants and register-argument use. (Imports
        // are reached through masked RIP-relative operands, so a hash match says nothing about them.)
        evidence_kind::NORMALIZED_HASH => {
            &["string-refs", "size-ratio", "constants", "inferred-args"]
        }
        evidence_kind::STRINGS => &["string-refs"],
        // Paired because they sit at the same position under the same matched caller.
        evidence_kind::CALL_SEQUENCE => &["callers"],
        // Paired because both call the same matched functions.
        evidence_kind::CALLEES => &["callees"],
        // Paired because they fill the same slot of corresponding code-pointer tables.
        evidence_kind::TABLE_SLOT => &["code-tables"],
        // The similarity score already weighed strings, size, neighbours, constants and imports.
        evidence_kind::SIMILARITY => &[
            "string-refs",
            "size-ratio",
            "callees",
            "callers",
            "constants",
            "imports",
        ],
        _ => &[],
    }
}

/// Checks that can fail a candidate but never count as supporting evidence.
pub const SANITY_ONLY: &[&str] = &["size-ratio", "inferred-args"];

/// Acceptance policy per hook criticality (design §6.3). Thresholds are guesses until calibrated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    /// Passes from checks independent of the candidate's own evidence.
    pub min_independent_passes: usize,
    pub require_behavioral_pass: bool,
}

impl Policy {
    pub fn for_criticality(c: Criticality) -> Self {
        let (min_independent_passes, require_behavioral_pass) = match c {
            Criticality::Low => (1, false),
            Criticality::Normal => (1, false),
            Criticality::High => (2, true),
        };
        Self {
            min_independent_passes,
            require_behavioral_pass,
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
        Self::with_behavioral(Box::new(NoBehavioralCorpus))
    }

    /// The default structural checks with this behavioral runner (e.g. a [`TraceDiffRunner`]).
    pub fn with_behavioral(behavioral: Box<dyn BehavioralRunner>) -> Self {
        Self::new(
            vec![
                Box::new(ParamCountCheck),
                Box::new(StringRefCheck),
                Box::new(SizeRatioCheck),
                Box::new(CalleeCheck),
                Box::new(CallerCheck),
                Box::new(CodeTableCheck),
                Box::new(ConstantsCheck),
                Box::new(ImportsCheck),
                Box::new(InferredArgsCheck),
            ],
            behavioral,
        )
    }

    pub fn verify(
        &self,
        ctx: &VerifyContext,
        candidate: &Candidate,
        old: &FunctionFeatures,
        new: &FunctionFeatures,
        policy: Policy,
    ) -> VerificationReport {
        let implied: HashSet<&str> = candidate
            .evidence
            .iter()
            .flat_map(|e| implied_checks(&e.kind).iter().copied())
            .chain(SANITY_ONLY.iter().copied())
            .collect();

        let mut checks: Vec<CheckResult> = self
            .checks
            .iter()
            .map(|c| {
                let mut r = c.check(ctx, old, new);
                r.counted = !implied.contains(c.name());
                r
            })
            .collect();
        // Failures always count: evidence that implies a pass can't excuse a fail.
        let fails = checks
            .iter()
            .filter(|c| c.outcome == CheckOutcome::Fail)
            .count();
        let passes = checks
            .iter()
            .filter(|c| c.outcome == CheckOutcome::Pass && c.counted)
            .count();

        // A behavioral pass is independent of every structural check and of the candidate's evidence, so it
        // counts as one independent pass, except where policy requires it on top of the structural passes
        // (high criticality): there it's a requirement, not a substitute for structural evidence.
        let mut behavioral = self.behavioral.run(ctx, candidate, old, new);
        behavioral.counted = !policy.require_behavioral_pass;
        let behavioral_outcome = behavioral.outcome;
        let passes =
            passes + usize::from(behavioral.counted && behavioral_outcome == CheckOutcome::Pass);
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
    } else if passes >= policy.min_independent_passes
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

    fn check(
        &self,
        _: &VerifyContext,
        old: &FunctionFeatures,
        new: &FunctionFeatures,
    ) -> CheckResult {
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

    fn check(
        &self,
        _: &VerifyContext,
        old: &FunctionFeatures,
        new: &FunctionFeatures,
    ) -> CheckResult {
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

/// Size ratio new/old: pass within 0.5–2.0, fail outside 0.25–4.0. Thresholds are guesses. Sanity-only.
pub struct SizeRatioCheck;

impl StructuralCheck for SizeRatioCheck {
    fn name(&self) -> &'static str {
        "size-ratio"
    }

    fn check(
        &self,
        _: &VerifyContext,
        old: &FunctionFeatures,
        new: &FunctionFeatures,
    ) -> CheckResult {
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

/// Jaccard overlap of two feature sets. Pass at ≥ 0.5; fail below 0.2 when each side has at least two items;
/// otherwise inconclusive. Edited functions legitimately change some constants and imports, so only a
/// near-total mismatch fails. Thresholds are guesses.
fn overlap_check<T: Eq + std::hash::Hash>(name: &str, noun: &str, a: &[T], b: &[T]) -> CheckResult {
    let (a, b): (HashSet<&T>, HashSet<&T>) = (a.iter().collect(), b.iter().collect());
    if a.is_empty() && b.is_empty() {
        return CheckResult::new(name, CheckOutcome::Inconclusive, format!("no {noun}"));
    }
    let jaccard = a.intersection(&b).count() as f32 / a.union(&b).count() as f32;
    let outcome = if jaccard >= 0.5 {
        CheckOutcome::Pass
    } else if jaccard < 0.2 && a.len() >= 2 && b.len() >= 2 {
        CheckOutcome::Fail
    } else {
        CheckOutcome::Inconclusive
    };
    CheckResult::new(
        name,
        outcome,
        format!("{noun} Jaccard {jaccard:.2} ({} vs {})", a.len(), b.len()),
    )
}

/// Non-trivial immediate constants (e.g. table sizes, magic numbers, masks) should mostly survive.
pub struct ConstantsCheck;

impl StructuralCheck for ConstantsCheck {
    fn name(&self) -> &'static str {
        "constants"
    }

    fn check(
        &self,
        _: &VerifyContext,
        old: &FunctionFeatures,
        new: &FunctionFeatures,
    ) -> CheckResult {
        overlap_check(self.name(), "constants", &old.constants, &new.constants)
    }
}

/// Imported APIs called (`dll!name`) should mostly survive.
pub struct ImportsCheck;

impl StructuralCheck for ImportsCheck {
    fn name(&self) -> &'static str {
        "imports"
    }

    fn check(
        &self,
        _: &VerifyContext,
        old: &FunctionFeatures,
        new: &FunctionFeatures,
    ) -> CheckResult {
        overlap_check(self.name(), "imports", &old.imports, &new.imports)
    }
}

/// Register arguments read before written, inferred from code (works without symbols). A difference is a
/// strong hint the signature changed, which matters for hooks. Sanity-only: the count is a lower bound, so
/// agreement says little.
pub struct InferredArgsCheck;

impl StructuralCheck for InferredArgsCheck {
    fn name(&self) -> &'static str {
        "inferred-args"
    }

    fn check(
        &self,
        _: &VerifyContext,
        old: &FunctionFeatures,
        new: &FunctionFeatures,
    ) -> CheckResult {
        match (old.inferred_args, new.inferred_args) {
            (Some(a), Some(b)) if a == b => CheckResult::new(
                self.name(),
                CheckOutcome::Pass,
                format!("{a} register args"),
            ),
            (Some(a), Some(b)) => CheckResult::new(
                self.name(),
                CheckOutcome::Fail,
                format!("reads {a} → {b} register args; the signature may have changed"),
            ),
            _ => CheckResult::new(self.name(), CheckOutcome::Inconclusive, "not inferred"),
        }
    }
}

/// Neighbour consistency: of the old function's neighbours that have a candidate, how many land on the new
/// function's neighbours. Pass at ≥ 50% agreement; fail below that only with at least two mapped neighbours
/// (one disagreeing neighbour could itself be the wrong candidate). Thresholds are guesses.
fn neighbour_check(
    name: &str,
    noun: &str,
    ctx: &VerifyContext,
    old_self: Rva,
    old_neighbours: &[Rva],
    new_neighbours: &[Rva],
) -> CheckResult {
    let new_set: HashSet<Rva> = new_neighbours.iter().copied().collect();
    let mapped: Vec<Rva> = old_neighbours
        .iter()
        .filter(|&&o| o != old_self)
        .filter_map(|o| ctx.mapping.get(o).copied())
        .collect();
    if mapped.is_empty() {
        return CheckResult::new(
            name,
            CheckOutcome::Inconclusive,
            format!("no matched {noun}"),
        );
    }
    let agree = mapped.iter().filter(|n| new_set.contains(n)).count();
    let ratio = agree as f32 / mapped.len() as f32;
    let outcome = if ratio >= 0.5 {
        CheckOutcome::Pass
    } else if mapped.len() >= 2 {
        CheckOutcome::Fail
    } else {
        CheckOutcome::Inconclusive
    };
    CheckResult::new(
        name,
        outcome,
        format!("{agree}/{} matched {noun} agree", mapped.len()),
    )
}

/// The old function's callees, mapped through the other candidates, should be callees of the new function.
pub struct CalleeCheck;

impl StructuralCheck for CalleeCheck {
    fn name(&self) -> &'static str {
        "callees"
    }

    fn check(
        &self,
        ctx: &VerifyContext,
        old: &FunctionFeatures,
        new: &FunctionFeatures,
    ) -> CheckResult {
        neighbour_check(
            self.name(),
            "callees",
            ctx,
            old.rva,
            &old.callees,
            &new.callees,
        )
    }
}

/// The old function's callers, mapped through the other candidates, should call the new function.
pub struct CallerCheck;

impl StructuralCheck for CallerCheck {
    fn name(&self) -> &'static str {
        "callers"
    }

    fn check(
        &self,
        ctx: &VerifyContext,
        old: &FunctionFeatures,
        new: &FunctionFeatures,
    ) -> CheckResult {
        neighbour_check(
            self.name(),
            "callers",
            ctx,
            old.rva,
            VerifyContext::callers(&ctx.old_callers, old.rva),
            VerifyContext::callers(&ctx.new_callers, new.rva),
        )
    }
}

/// Table consistency: the old function's slot in a code-pointer table (vtable, function table) should hold the
/// new function in the corresponding new table. Tables correspond here as in matching: same length, and every
/// other slot whose old function has a candidate lands on the new table's function at that slot.
///
/// - **Pass:** some old table and a new table correspond with at least one agreeing slot besides this one, and
///   hold the old and new function at the same slot.
/// - **Fail:** a new table corresponds to one of the old function's tables with at least two agreeing slots
///   (one could itself be a wrong candidate), but holds a different function at this slot, and no table pair
///   supports the candidate.
/// - Inconclusive otherwise (not in any table, or nothing matched around it).
pub struct CodeTableCheck;

/// Agreeing and disagreeing slots between `t` and `u`, ignoring the slots holding `old_self`.
fn table_agreement(ctx: &VerifyContext, t: &[Rva], u: &[Rva], old_self: Rva) -> (usize, usize) {
    let (mut agree, mut disagree) = (0, 0);
    for (o, n) in t.iter().zip(u) {
        if *o == old_self {
            continue;
        }
        match ctx.mapping.get(o) {
            Some(m) if m == n => agree += 1,
            Some(_) => disagree += 1,
            None => {}
        }
    }
    (agree, disagree)
}

impl StructuralCheck for CodeTableCheck {
    fn name(&self) -> &'static str {
        "code-tables"
    }

    fn check(
        &self,
        ctx: &VerifyContext,
        old: &FunctionFeatures,
        new: &FunctionFeatures,
    ) -> CheckResult {
        let (mut support, mut against) = (0usize, 0usize);
        for t in ctx.old_tables.iter().filter(|t| t.slots.contains(&old.rva)) {
            for u in ctx
                .new_tables
                .iter()
                .filter(|u| u.slots.len() == t.slots.len())
            {
                let (agree, disagree) = table_agreement(ctx, &t.slots, &u.slots, old.rva);
                if disagree > 0 || agree == 0 {
                    continue;
                }
                let same_slot = t
                    .slots
                    .iter()
                    .zip(&u.slots)
                    .any(|(o, n)| *o == old.rva && *n == new.rva);
                if same_slot {
                    support += 1;
                } else if agree >= 2 {
                    against += 1;
                }
            }
        }
        let (outcome, detail) = match (support, against) {
            (s, _) if s > 0 => (
                CheckOutcome::Pass,
                format!("same slot in {s} corresponding table pair(s)"),
            ),
            (0, a) if a > 0 => (
                CheckOutcome::Fail,
                format!("{a} corresponding table(s) hold another function at this slot"),
            ),
            _ => (
                CheckOutcome::Inconclusive,
                "no corresponding code-pointer tables".to_owned(),
            ),
        };
        CheckResult::new(self.name(), outcome, detail)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use permanent_beta_model::{
        ANALYSIS_SCHEMA_VERSION, BuildId, BuildInfo, CandidateSource, Evidence, FunctionSignature,
        Machine, Param, Producer,
    };

    fn func(rva: u64, size: u32, strings: &[&str], params: Option<usize>) -> FunctionFeatures {
        FunctionFeatures {
            rva: Rva(rva),
            size,
            name: None,
            name_source: None,
            normalized_hash: None,
            mnemonic_hash: None,
            inferred_args: None,
            inferred_arg_classes: vec![],
            entry: None,
            basic_blocks: None,
            mnemonic_counts: Default::default(),
            pseudocode: None,
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

    fn cand(old: u64, new: u64, kind: &str) -> Candidate {
        Candidate {
            old: Rva(old),
            new: Rva(new),
            source: CandidateSource::Deterministic {
                matcher: "test".into(),
            },
            score: 1.0,
            evidence: vec![Evidence {
                kind: kind.into(),
                detail: String::new(),
            }],
        }
    }

    fn export(functions: Vec<FunctionFeatures>) -> AnalysisExport {
        AnalysisExport {
            schema_version: ANALYSIS_SCHEMA_VERSION,
            build: BuildInfo {
                id: BuildId("x".into()),
                file_name: "x".into(),
                version: None,
                machine: Machine::X64,
                pdb: None,
            },
            producer: Producer {
                tool: "t".into(),
                version: "0".into(),
            },
            functions,
            code_tables: Vec::new(),
        }
    }

    fn verify(
        c: &Candidate,
        o: &FunctionFeatures,
        n: &FunctionFeatures,
        crit: Criticality,
    ) -> VerificationReport {
        Verifier::with_defaults().verify(
            &VerifyContext::default(),
            c,
            o,
            n,
            Policy::for_criticality(crit),
        )
    }

    #[test]
    fn name_match_with_matching_strings_is_accepted() {
        let f = func(0x10, 100, &["a"], Some(2));
        let r = verify(
            &cand(0x10, 0x10, evidence_kind::NAME),
            &f,
            &f,
            Criticality::Normal,
        );
        assert_eq!(r.verdict, Verdict::Accepted);
    }

    #[test]
    fn implied_passes_do_not_count() {
        // A hash match whose only passes are strings and size has no independent evidence.
        let f = func(0x10, 100, &["a"], None);
        let r = verify(
            &cand(0x10, 0x10, evidence_kind::NORMALIZED_HASH),
            &f,
            &f,
            Criticality::Normal,
        );
        assert_eq!(r.verdict, Verdict::NeedsReview);
        let strings = r.checks.iter().find(|c| c.check == "string-refs").unwrap();
        assert_eq!(
            (strings.outcome, strings.counted),
            (CheckOutcome::Pass, false)
        );
    }

    #[test]
    fn size_alone_is_never_enough() {
        let f = func(0x10, 100, &[], None);
        let r = verify(
            &cand(0x10, 0x10, evidence_kind::NAME),
            &f,
            &f,
            Criticality::Low,
        );
        assert_eq!(r.verdict, Verdict::NeedsReview);
    }

    #[test]
    fn high_criticality_needs_behavioral_pass() {
        let f = func(0x10, 100, &["a"], Some(2));
        let r = verify(
            &cand(0x10, 0x10, evidence_kind::NAME),
            &f,
            &f,
            Criticality::High,
        );
        assert_eq!(r.verdict, Verdict::NeedsReview);
    }

    /// A behavioral runner that always reports `outcome`.
    struct Fixed(CheckOutcome);

    impl BehavioralRunner for Fixed {
        fn run(
            &self,
            _: &VerifyContext,
            _: &Candidate,
            _: &FunctionFeatures,
            _: &FunctionFeatures,
        ) -> CheckResult {
            CheckResult::new("behavioral", self.0, "fixed")
        }
    }

    fn verify_with(
        behavioral: CheckOutcome,
        c: &Candidate,
        o: &FunctionFeatures,
        n: &FunctionFeatures,
        crit: Criticality,
    ) -> VerificationReport {
        Verifier::with_behavioral(Box::new(Fixed(behavioral))).verify(
            &VerifyContext::default(),
            c,
            o,
            n,
            Policy::for_criticality(crit),
        )
    }

    #[test]
    fn a_behavioral_pass_counts_as_one_independent_pass_below_high() {
        // A hash match of a leaf with no strings: no independent structural pass at all.
        let f = func(0x10, 100, &[], None);
        let c = cand(0x10, 0x10, evidence_kind::NORMALIZED_HASH);
        assert_eq!(
            verify(&c, &f, &f, Criticality::Normal).verdict,
            Verdict::NeedsReview
        );

        let r = verify_with(CheckOutcome::Pass, &c, &f, &f, Criticality::Normal);
        assert_eq!(r.verdict, Verdict::Accepted);
        let b = r.checks.iter().find(|c| c.check == "behavioral").unwrap();
        assert!(b.counted);
        assert_eq!(
            verify_with(CheckOutcome::Pass, &c, &f, &f, Criticality::Low).verdict,
            Verdict::Accepted
        );

        // Negative: inconclusive or failing behavior gives nothing (a failure still sends to review).
        assert_eq!(
            verify_with(CheckOutcome::Inconclusive, &c, &f, &f, Criticality::Normal).verdict,
            Verdict::NeedsReview
        );
        let mut strong = func(0x10, 100, &["a"], Some(2));
        strong.constants = vec![0x1234_5678];
        let named = cand(0x10, 0x10, evidence_kind::NAME);
        assert_eq!(
            verify(&named, &strong, &strong, Criticality::Normal).verdict,
            Verdict::Accepted
        );
        assert_eq!(
            verify_with(
                CheckOutcome::Fail,
                &named,
                &strong,
                &strong,
                Criticality::Normal
            )
            .verdict,
            Verdict::NeedsReview
        );
    }

    #[test]
    fn at_high_criticality_a_behavioral_pass_does_not_replace_structural_passes() {
        // One structural pass (strings) plus a behavioral pass: high needs two structural passes.
        let f = func(0x10, 100, &["a"], None);
        let c = cand(0x10, 0x10, evidence_kind::NAME);
        let r = verify_with(CheckOutcome::Pass, &c, &f, &f, Criticality::High);
        assert_eq!(r.verdict, Verdict::NeedsReview);
        let b = r.checks.iter().find(|c| c.check == "behavioral").unwrap();
        assert!(!b.counted, "at high it's a requirement, not a counted pass");

        // Two structural passes (strings, parameter count) plus the behavioral pass: accepted.
        let f = func(0x10, 100, &["a"], Some(2));
        assert_eq!(
            verify_with(CheckOutcome::Pass, &c, &f, &f, Criticality::High).verdict,
            Verdict::Accepted
        );
    }

    #[test]
    fn param_count_change_needs_review() {
        let r = verify(
            &cand(0x10, 0x10, evidence_kind::NAME),
            &func(0x10, 100, &["a"], Some(2)),
            &func(0x10, 100, &["a"], Some(3)),
            Criticality::Low,
        );
        assert_eq!(r.verdict, Verdict::NeedsReview);
    }

    #[test]
    fn two_structural_failures_reject() {
        let r = verify(
            &cand(0x10, 0x10, evidence_kind::NAME),
            &func(0x10, 100, &["a"], Some(2)),
            &func(0x10, 1000, &["b"], Some(2)),
            Criticality::Low,
        );
        assert_eq!(r.verdict, Verdict::Rejected);
    }

    #[test]
    fn implied_evidence_cannot_excuse_a_failure() {
        // Strings differ although the candidate claims a strings match: still a failure.
        let r = verify(
            &cand(0x10, 0x10, evidence_kind::STRINGS),
            &func(0x10, 100, &["a"], None),
            &func(0x10, 100, &["b"], None),
            Criticality::Low,
        );
        assert_eq!(r.verdict, Verdict::NeedsReview);
    }

    /// old: main(0x1) calls f(0x10) and g(0x20). new: main(0x101) calls f'(0x110) and g'(0x120).
    fn call_graph(new_main_callees: Vec<Rva>) -> (AnalysisExport, AnalysisExport) {
        let mut main_old = func(0x1, 50, &[], None);
        main_old.callees = vec![Rva(0x10), Rva(0x20)];
        let mut main_new = func(0x101, 50, &[], None);
        main_new.callees = new_main_callees;
        (
            export(vec![
                main_old,
                func(0x10, 10, &[], None),
                func(0x20, 10, &[], None),
            ]),
            export(vec![
                main_new,
                func(0x110, 10, &[], None),
                func(0x120, 10, &[], None),
            ]),
        )
    }

    #[test]
    fn consistent_callers_and_callees_pass() {
        let (old, new) = call_graph(vec![Rva(0x110), Rva(0x120)]);
        let candidates = [
            cand(0x1, 0x101, evidence_kind::NORMALIZED_HASH),
            cand(0x10, 0x110, evidence_kind::NORMALIZED_HASH),
            cand(0x20, 0x120, evidence_kind::NORMALIZED_HASH),
        ];
        let ctx = VerifyContext::new(&old, &new, &candidates);
        let v = Verifier::with_defaults();
        let policy = Policy::for_criticality(Criticality::Normal);

        let main = v.verify(
            &ctx,
            &candidates[0],
            &old.functions[0],
            &new.functions[0],
            policy,
        );
        assert_eq!(
            main.verdict,
            Verdict::Accepted,
            "callees agree: {:?}",
            main.checks
        );
        let f = v.verify(
            &ctx,
            &candidates[1],
            &old.functions[1],
            &new.functions[1],
            policy,
        );
        assert_eq!(
            f.verdict,
            Verdict::Accepted,
            "caller agrees: {:?}",
            f.checks
        );
    }

    #[test]
    fn inconsistent_callees_fail() {
        // The new main calls neither f' nor g': the candidate for main disagrees with its callees' candidates.
        let (old, new) = call_graph(vec![Rva(0x999), Rva(0x998)]);
        let candidates = [
            cand(0x1, 0x101, evidence_kind::NAME),
            cand(0x10, 0x110, evidence_kind::NAME),
            cand(0x20, 0x120, evidence_kind::NAME),
        ];
        let ctx = VerifyContext::new(&old, &new, &candidates);
        let r = Verifier::with_defaults().verify(
            &ctx,
            &candidates[0],
            &old.functions[0],
            &new.functions[0],
            Policy::for_criticality(Criticality::Normal),
        );
        let callees = r.checks.iter().find(|c| c.check == "callees").unwrap();
        assert_eq!(callees.outcome, CheckOutcome::Fail);
        assert_ne!(r.verdict, Verdict::Accepted);
    }

    #[test]
    fn call_sequence_candidates_cannot_use_the_caller_check() {
        let (old, new) = call_graph(vec![Rva(0x110), Rva(0x120)]);
        let candidates = [
            cand(0x1, 0x101, evidence_kind::NAME),
            cand(0x10, 0x110, evidence_kind::CALL_SEQUENCE),
        ];
        let ctx = VerifyContext::new(&old, &new, &candidates);
        let r = Verifier::with_defaults().verify(
            &ctx,
            &candidates[1],
            &old.functions[1],
            &new.functions[1],
            Policy::for_criticality(Criticality::Normal),
        );
        assert_eq!(r.verdict, Verdict::NeedsReview, "{:?}", r.checks);
    }

    #[test]
    fn matched_callee_candidates_cannot_use_the_callee_check() {
        // main was paired because it calls f' and g'; the callees check would only repeat that.
        let (old, new) = call_graph(vec![Rva(0x110), Rva(0x120)]);
        let candidates = [
            cand(0x1, 0x101, evidence_kind::CALLEES),
            cand(0x10, 0x110, evidence_kind::NAME),
            cand(0x20, 0x120, evidence_kind::NAME),
        ];
        let ctx = VerifyContext::new(&old, &new, &candidates);
        let r = Verifier::with_defaults().verify(
            &ctx,
            &candidates[0],
            &old.functions[0],
            &new.functions[0],
            Policy::for_criticality(Criticality::Normal),
        );
        let callees = r.checks.iter().find(|c| c.check == "callees").unwrap();
        assert_eq!(callees.outcome, CheckOutcome::Pass);
        assert!(!callees.counted);
        assert_eq!(r.verdict, Verdict::NeedsReview, "{:?}", r.checks);
    }

    #[test]
    fn similarity_candidates_go_to_review_even_with_agreeing_neighbours() {
        // The similarity score already used callers and callees, so their passes don't count.
        let (old, new) = call_graph(vec![Rva(0x110), Rva(0x120)]);
        let candidates = [
            cand(0x1, 0x101, evidence_kind::SIMILARITY),
            cand(0x10, 0x110, evidence_kind::NAME),
            cand(0x20, 0x120, evidence_kind::NAME),
        ];
        let ctx = VerifyContext::new(&old, &new, &candidates);
        let r = Verifier::with_defaults().verify(
            &ctx,
            &candidates[0],
            &old.functions[0],
            &new.functions[0],
            Policy::for_criticality(Criticality::Low),
        );
        assert!(
            r.checks
                .iter()
                .all(|c| !c.counted || c.outcome != CheckOutcome::Pass),
            "{:?}",
            r.checks
        );
        assert_eq!(r.verdict, Verdict::NeedsReview);
    }

    #[test]
    fn shared_constants_count_as_independent_evidence() {
        let mut o = func(0x10, 100, &[], None);
        let mut n = func(0x10, 100, &[], None);
        o.constants = vec![0xedb88320, 0x1000];
        n.constants = vec![0xedb88320, 0x1000];
        let r = verify(
            &cand(0x10, 0x10, evidence_kind::NAME),
            &o,
            &n,
            Criticality::Normal,
        );
        assert_eq!(r.verdict, Verdict::Accepted, "{:?}", r.checks);
    }

    #[test]
    fn constants_are_implied_by_a_hash_match_but_imports_are_not() {
        let mut f = func(0x10, 100, &[], None);
        f.constants = vec![0x1234];
        f.imports = vec!["kernel32.dll!CreateFileW".into()];
        let r = verify(
            &cand(0x10, 0x10, evidence_kind::NORMALIZED_HASH),
            &f,
            &f,
            Criticality::Normal,
        );
        let counted = |name: &str| r.checks.iter().find(|c| c.check == name).unwrap().counted;
        assert!(!counted("constants"));
        assert!(counted("imports"));
        assert_eq!(
            r.verdict,
            Verdict::Accepted,
            "imports are independent evidence"
        );
    }

    #[test]
    fn disjoint_imports_fail() {
        let mut o = func(0x10, 100, &["a"], None);
        let mut n = func(0x10, 100, &["a"], None);
        o.imports = vec![
            "kernel32.dll!ReadFile".into(),
            "kernel32.dll!CloseHandle".into(),
        ];
        n.imports = vec!["user32.dll!MessageBoxW".into(), "user32.dll!GetDC".into()];
        let r = verify(
            &cand(0x10, 0x10, evidence_kind::NAME),
            &o,
            &n,
            Criticality::Normal,
        );
        let imports = r.checks.iter().find(|c| c.check == "imports").unwrap();
        assert_eq!(imports.outcome, CheckOutcome::Fail);
        assert_ne!(r.verdict, Verdict::Accepted);
    }

    #[test]
    fn inferred_argument_change_sends_to_review() {
        // Scenario S4: the function now reads r8 as well.
        let mut o = func(0x10, 100, &["a"], None);
        let mut n = func(0x10, 100, &["a"], None);
        o.inferred_args = Some(2);
        n.inferred_args = Some(3);
        let r = verify(
            &cand(0x10, 0x10, evidence_kind::NAME),
            &o,
            &n,
            Criticality::Normal,
        );
        assert_eq!(r.verdict, Verdict::NeedsReview);
    }

    #[test]
    fn matching_inferred_arguments_are_not_evidence() {
        let mut f = func(0x10, 100, &[], None);
        f.inferred_args = Some(2);
        let r = verify(
            &cand(0x10, 0x10, evidence_kind::NAME),
            &f,
            &f,
            Criticality::Normal,
        );
        assert_eq!(
            r.verdict,
            Verdict::NeedsReview,
            "sanity-only: a pass doesn't count"
        );
    }

    /// Old vtable [0x10, 0x20, 0x30, 0x40], new [0x110, 0x120, 0x130, 0x140]; `candidates` is the run's mapping.
    fn table_report(candidate: &Candidate, candidates: &[Candidate]) -> VerificationReport {
        let with = |slots: &[u64], base: u64| {
            let mut e = export(slots.iter().map(|&r| func(r, 64, &[], None)).collect());
            e.code_tables = vec![CodeTable {
                rva: Rva(base),
                slots: slots.iter().map(|&r| Rva(r)).collect(),
            }];
            e
        };
        let old = with(&[0x10, 0x20, 0x30, 0x40], 0x5000);
        let new = with(&[0x110, 0x120, 0x130, 0x140], 0x6000);
        let ctx = VerifyContext::new(&old, &new, candidates);
        let (o, n) = (
            old.function(candidate.old).unwrap(),
            new.function(candidate.new).unwrap(),
        );
        Verifier::with_defaults().verify(
            &ctx,
            candidate,
            o,
            n,
            Policy::for_criticality(Criticality::Normal),
        )
    }

    fn table_check(r: &VerificationReport) -> &CheckResult {
        r.checks.iter().find(|c| c.check == "code-tables").unwrap()
    }

    #[test]
    fn a_hash_match_in_the_same_vtable_slot_is_accepted() {
        // A virtual with no callers and no strings: only its vtable confirms it, independently of the hash.
        let c = cand(0x20, 0x120, evidence_kind::NORMALIZED_HASH);
        let r = table_report(&c, &[cand(0x10, 0x110, evidence_kind::NAME), c.clone()]);
        assert_eq!(table_check(&r).outcome, CheckOutcome::Pass);
        assert!(table_check(&r).counted);
        assert_eq!(r.verdict, Verdict::Accepted);
    }

    #[test]
    fn a_candidate_at_another_slot_of_a_corresponding_table_fails() {
        // Negative: slots 0 and 3 agree, so the tables correspond, and slot 1's partner is 0x120, not 0x130.
        let c = cand(0x20, 0x130, evidence_kind::NORMALIZED_HASH);
        let others = [
            cand(0x10, 0x110, evidence_kind::NAME),
            cand(0x40, 0x140, evidence_kind::NAME),
        ];
        let r = table_report(&c, &[others[0].clone(), others[1].clone(), c.clone()]);
        assert_eq!(table_check(&r).outcome, CheckOutcome::Fail);
        assert_ne!(r.verdict, Verdict::Accepted);
        // With only one agreeing slot, that slot could itself be wrong: not enough to fail.
        let r = table_report(&c, &[others[0].clone(), c.clone()]);
        assert_eq!(table_check(&r).outcome, CheckOutcome::Inconclusive);
    }

    #[test]
    fn a_disagreeing_slot_means_the_tables_do_not_correspond() {
        // Negative: slot 2 is mapped elsewhere, so this table pair supports nothing.
        let c = cand(0x20, 0x120, evidence_kind::NORMALIZED_HASH);
        let r = table_report(
            &c,
            &[
                cand(0x10, 0x110, evidence_kind::NAME),
                cand(0x30, 0x140, evidence_kind::NAME),
                c.clone(),
            ],
        );
        assert_eq!(table_check(&r).outcome, CheckOutcome::Inconclusive);
    }

    #[test]
    fn a_table_slot_pair_does_not_count_its_own_table() {
        // Negative: table-slot evidence is exactly this check, so its pass is not independent.
        let c = cand(0x20, 0x120, evidence_kind::TABLE_SLOT);
        let r = table_report(&c, &[cand(0x10, 0x110, evidence_kind::NAME), c.clone()]);
        assert_eq!(table_check(&r).outcome, CheckOutcome::Pass);
        assert!(!table_check(&r).counted);
        assert_eq!(r.verdict, Verdict::NeedsReview);
    }

    #[test]
    fn nothing_matched_around_a_slot_is_inconclusive() {
        let c = cand(0x20, 0x120, evidence_kind::NORMALIZED_HASH);
        let r = table_report(&c, std::slice::from_ref(&c));
        assert_eq!(table_check(&r).outcome, CheckOutcome::Inconclusive);
    }
}
