//! Matching (design §5). Passes propose [`Candidate`]s; they never decide acceptance.
//!
//! Invariants:
//! - One-to-one: a function on either side is claimed at most once; earlier (stronger) passes win.
//! - Uniqueness: a key shared by more than one unmatched function on either side yields no candidate.
//!   It yields an [`Ambiguity`] instead, so review can show the competing functions.

use permanent_beta_model::{
    Ambiguity, AnalysisExport, Candidate, CandidateSource, Evidence, FunctionFeatures, Rva,
};
use std::collections::{HashMap, HashSet};
use std::hash::Hash;

/// What a matcher can see: both exports and which functions earlier passes already claimed.
pub struct MatchContext<'a> {
    pub old: &'a AnalysisExport,
    pub new: &'a AnalysisExport,
    pub matched_old: &'a HashSet<Rva>,
    pub matched_new: &'a HashSet<Rva>,
}

/// What one pass produced: unique candidates, plus key groups it refused to resolve.
#[derive(Debug, Default)]
pub struct Proposals {
    pub candidates: Vec<Candidate>,
    pub ambiguities: Vec<Ambiguity>,
}

pub trait Matcher {
    fn name(&self) -> &'static str;
    fn propose(&self, ctx: &MatchContext<'_>) -> Proposals;
}

/// Result of all passes.
#[derive(Debug, Default)]
pub struct MatchOutcome {
    pub candidates: Vec<Candidate>,
    /// Ambiguities still open after all passes: only functions that no pass matched, and only groups
    /// with at least one function left on each side. Sorted and deduplicated.
    pub ambiguities: Vec<Ambiguity>,
}

impl MatchOutcome {
    /// New-build functions that compete for `old` in an unresolved ambiguity. Sorted, deduplicated.
    pub fn competitors(&self, old: Rva) -> Vec<Rva> {
        let mut out: Vec<Rva> = self
            .ambiguities
            .iter()
            .filter(|a| a.old.contains(&old))
            .flat_map(|a| a.new.iter().copied())
            .collect();
        out.sort();
        out.dedup();
        out
    }
}

/// Default passes, strongest first.
pub fn default_matchers() -> Vec<Box<dyn Matcher>> {
    vec![
        Box::new(SymbolNameMatcher),
        Box::new(NormalizedHashMatcher),
        Box::new(UniqueStringsMatcher),
    ]
}

/// Run passes in order, repeating until no pass adds a candidate (so later passes can unlock earlier ones,
/// which matters once call-graph propagation exists).
pub fn run_passes(
    old: &AnalysisExport,
    new: &AnalysisExport,
    matchers: &[Box<dyn Matcher>],
) -> MatchOutcome {
    let mut matched_old = HashSet::new();
    let mut matched_new = HashSet::new();
    let mut accepted = Vec::new();
    let mut ambiguities = Vec::new();
    loop {
        let before = accepted.len();
        for matcher in matchers {
            let ctx = MatchContext {
                old,
                new,
                matched_old: &matched_old,
                matched_new: &matched_new,
            };
            let proposals = matcher.propose(&ctx);
            for c in proposals.candidates {
                if !matched_old.contains(&c.old) && !matched_new.contains(&c.new) {
                    matched_old.insert(c.old);
                    matched_new.insert(c.new);
                    accepted.push(c);
                }
            }
            ambiguities.extend(proposals.ambiguities);
        }
        if accepted.len() == before {
            break;
        }
    }

    // Drop functions a pass matched after the ambiguity was recorded, then groups left empty on a side.
    for a in &mut ambiguities {
        a.old.retain(|r| !matched_old.contains(r));
        a.new.retain(|r| !matched_new.contains(r));
    }
    ambiguities.retain(|a| !a.old.is_empty() && !a.new.is_empty());
    ambiguities.sort_by(|a, b| (&a.old, &a.new, &a.matcher).cmp(&(&b.old, &b.new, &b.matcher)));
    ambiguities.dedup();

    MatchOutcome {
        candidates: accepted,
        ambiguities,
    }
}

/// Functions grouped by key among unmatched functions on both sides.
#[derive(Debug, Default, PartialEq)]
pub struct KeyGroups {
    /// Key held by exactly one function on each side.
    pub unique: Vec<(Rva, Rva)>,
    /// Key present on both sides but held by more than one function on at least one side.
    pub ambiguous: Vec<(Vec<Rva>, Vec<Rva>)>,
}

/// Group unmatched functions by `key`. Sorted for determinism.
pub fn group_by_key<K: Hash + Eq>(
    ctx: &MatchContext<'_>,
    key: &dyn Fn(&FunctionFeatures) -> Option<K>,
) -> KeyGroups {
    let old_ix = index(&ctx.old.functions, ctx.matched_old, key);
    let new_ix = index(&ctx.new.functions, ctx.matched_new, key);
    let mut groups = KeyGroups::default();
    for (k, olds) in &old_ix {
        let Some(news) = new_ix.get(k) else { continue };
        if olds.len() == 1 && news.len() == 1 {
            groups.unique.push((olds[0], news[0]));
        } else {
            let (mut o, mut n) = (olds.clone(), news.clone());
            o.sort();
            n.sort();
            groups.ambiguous.push((o, n));
        }
    }
    groups.unique.sort();
    groups.ambiguous.sort();
    groups
}

/// Shared body of the key-based passes: unique groups become candidates, the rest become ambiguities.
/// `describe` explains the key using the (first) old function.
fn propose_by_key<K: Hash + Eq>(
    ctx: &MatchContext<'_>,
    matcher: &str,
    score: f32,
    kind: &str,
    key: &dyn Fn(&FunctionFeatures) -> Option<K>,
    describe: &dyn Fn(&FunctionFeatures) -> String,
) -> Proposals {
    let groups = group_by_key(ctx, key);
    let describe_rva = |rva: Rva| ctx.old.function(rva).map(describe).unwrap_or_default();
    Proposals {
        candidates: groups
            .unique
            .into_iter()
            .map(|(old, new)| {
                candidate(
                    matcher,
                    old,
                    new,
                    score,
                    kind,
                    format!("unique {}", describe_rva(old)),
                )
            })
            .collect(),
        ambiguities: groups
            .ambiguous
            .into_iter()
            .map(|(old, new)| Ambiguity {
                matcher: matcher.to_owned(),
                detail: format!(
                    "{} old and {} new functions share {}",
                    old.len(),
                    new.len(),
                    describe_rva(old[0])
                ),
                old,
                new,
            })
            .collect(),
    }
}

fn index<K: Hash + Eq>(
    funcs: &[FunctionFeatures],
    matched: &HashSet<Rva>,
    key: &dyn Fn(&FunctionFeatures) -> Option<K>,
) -> HashMap<K, Vec<Rva>> {
    let mut map: HashMap<K, Vec<Rva>> = HashMap::new();
    for f in funcs.iter().filter(|f| !matched.contains(&f.rva)) {
        if let Some(k) = key(f) {
            map.entry(k).or_default().push(f.rva);
        }
    }
    map
}

fn candidate(
    matcher: &str,
    old: Rva,
    new: Rva,
    score: f32,
    kind: &str,
    detail: String,
) -> Candidate {
    Candidate {
        old,
        new,
        source: CandidateSource::Deterministic {
            matcher: matcher.to_owned(),
        },
        score,
        evidence: vec![Evidence {
            kind: kind.to_owned(),
            detail,
        }],
    }
}

/// Pass 1: same export/PDB name, unique on both sides.
pub struct SymbolNameMatcher;

impl Matcher for SymbolNameMatcher {
    fn name(&self) -> &'static str {
        "symbol-name"
    }

    fn propose(&self, ctx: &MatchContext<'_>) -> Proposals {
        propose_by_key(
            ctx,
            self.name(),
            0.9,
            "name",
            &|f: &FunctionFeatures| f.name.clone(),
            &|f: &FunctionFeatures| format!("name `{}`", f.name.as_deref().unwrap_or("")),
        )
    }
}

/// Pass 2: identical normalized instruction hash, unique on both sides.
pub struct NormalizedHashMatcher;

impl Matcher for NormalizedHashMatcher {
    fn name(&self) -> &'static str {
        "normalized-hash"
    }

    fn propose(&self, ctx: &MatchContext<'_>) -> Proposals {
        propose_by_key(
            ctx,
            self.name(),
            0.95,
            "normalized_hash",
            &|f: &FunctionFeatures| f.normalized_hash.clone(),
            &|f: &FunctionFeatures| format!("hash {}", f.normalized_hash.as_deref().unwrap_or("")),
        )
    }
}

/// Pass 3: identical, non-empty set of referenced strings, unique on both sides.
pub struct UniqueStringsMatcher;

impl Matcher for UniqueStringsMatcher {
    fn name(&self) -> &'static str {
        "unique-strings"
    }

    fn propose(&self, ctx: &MatchContext<'_>) -> Proposals {
        propose_by_key(
            ctx,
            self.name(),
            0.7,
            "strings",
            &string_set_key,
            &|f: &FunctionFeatures| {
                let key = string_set_key(f).unwrap_or_default();
                format!("referenced-string set [{}]", key.replace('\u{1f}', ", "))
            },
        )
    }
}

fn string_set_key(f: &FunctionFeatures) -> Option<String> {
    if f.strings.is_empty() {
        return None;
    }
    let mut s = f.strings.clone();
    s.sort();
    s.dedup();
    Some(s.join("\u{1f}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use permanent_beta_model::{ANALYSIS_SCHEMA_VERSION, BuildId, BuildInfo, Machine, Producer};

    fn func(rva: u64, name: Option<&str>, hash: Option<&str>) -> FunctionFeatures {
        FunctionFeatures {
            rva: Rva(rva),
            size: 64,
            name: name.map(str::to_owned),
            name_source: None,
            normalized_hash: hash.map(str::to_owned),
            mnemonic_hash: None,
            basic_blocks: None,
            edges: None,
            callees: vec![],
            strings: vec![],
            constants: vec![],
            imports: vec![],
            signature: None,
        }
    }

    fn export(id: &str, functions: Vec<FunctionFeatures>) -> AnalysisExport {
        AnalysisExport {
            schema_version: ANALYSIS_SCHEMA_VERSION,
            build: BuildInfo {
                id: BuildId(id.to_owned()),
                file_name: "t.exe".into(),
                version: None,
                machine: Machine::X64,
                pdb: None,
            },
            producer: Producer {
                tool: "test".into(),
                version: "0".into(),
            },
            functions,
        }
    }

    #[test]
    fn matches_unique_name_then_unique_hash() {
        let old = export(
            "a",
            vec![func(0x10, Some("f"), None), func(0x20, None, Some("h1"))],
        );
        let new = export(
            "b",
            vec![func(0x110, Some("f"), None), func(0x220, None, Some("h1"))],
        );
        let got = run_passes(&old, &new, &default_matchers());
        let pairs: Vec<_> = got.candidates.iter().map(|c| (c.old.0, c.new.0)).collect();
        assert_eq!(pairs, vec![(0x10, 0x110), (0x20, 0x220)]);
        assert!(got.ambiguities.is_empty());
    }

    #[test]
    fn ambiguous_hash_yields_no_candidate_but_records_ambiguity() {
        let old = export("a", vec![func(0x10, None, Some("dup"))]);
        let new = export(
            "b",
            vec![
                func(0x100, None, Some("dup")),
                func(0x200, None, Some("dup")),
            ],
        );
        let got = run_passes(&old, &new, &default_matchers());
        assert!(got.candidates.is_empty());
        assert_eq!(
            got.ambiguities.len(),
            1,
            "recorded once despite the fixpoint loop"
        );
        assert_eq!(got.ambiguities[0].matcher, "normalized-hash");
        assert_eq!(got.ambiguities[0].old, vec![Rva(0x10)]);
        assert_eq!(got.ambiguities[0].new, vec![Rva(0x100), Rva(0x200)]);
        assert_eq!(got.competitors(Rva(0x10)), vec![Rva(0x100), Rva(0x200)]);
    }

    #[test]
    fn ambiguity_resolved_by_a_later_pass_is_dropped() {
        // The hash pass sees two copies; the string pass then pairs 0x10 with 0x100 uniquely.
        let mut f_old = func(0x10, None, Some("dup"));
        f_old.strings = vec!["s".into()];
        let mut f_new = func(0x100, None, Some("dup"));
        f_new.strings = vec!["s".into()];
        let old = export("a", vec![f_old]);
        let new = export("b", vec![f_new, func(0x200, None, Some("dup"))]);

        let got = run_passes(&old, &new, &default_matchers());
        assert_eq!(got.candidates.len(), 1);
        assert_eq!(got.candidates[0].new, Rva(0x100));
        assert!(got.ambiguities.is_empty());
        assert!(got.competitors(Rva(0x10)).is_empty());
    }

    #[test]
    fn a_function_is_claimed_at_most_once() {
        // Name says 0x10→0x100; hash would say 0x10→0x200. The stronger name pass wins and the hash pass
        // must not reuse 0x10.
        let old = export("a", vec![func(0x10, Some("f"), Some("h"))]);
        let new = export(
            "b",
            vec![func(0x100, Some("f"), None), func(0x200, None, Some("h"))],
        );
        let got = run_passes(&old, &new, &default_matchers()).candidates;
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].new, Rva(0x100));
    }
}
