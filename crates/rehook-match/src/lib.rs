//! Matching (design §5). Passes propose [`Candidate`]s; they never decide acceptance.
//!
//! Invariants:
//! - One-to-one: a function on either side is claimed at most once; earlier (stronger) passes win.
//! - Uniqueness: a key shared by more than one unmatched function on either side yields no candidate.

use rehook_model::{AnalysisExport, Candidate, CandidateSource, Evidence, FunctionFeatures, Rva};
use std::collections::{HashMap, HashSet};
use std::hash::Hash;

/// What a matcher can see: both exports and which functions earlier passes already claimed.
pub struct MatchContext<'a> {
    pub old: &'a AnalysisExport,
    pub new: &'a AnalysisExport,
    pub matched_old: &'a HashSet<Rva>,
    pub matched_new: &'a HashSet<Rva>,
}

pub trait Matcher {
    fn name(&self) -> &'static str;
    fn propose(&self, ctx: &MatchContext<'_>) -> Vec<Candidate>;
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
) -> Vec<Candidate> {
    let mut matched_old = HashSet::new();
    let mut matched_new = HashSet::new();
    let mut accepted = Vec::new();
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
            for c in proposals {
                if !matched_old.contains(&c.old) && !matched_new.contains(&c.new) {
                    matched_old.insert(c.old);
                    matched_new.insert(c.new);
                    accepted.push(c);
                }
            }
        }
        if accepted.len() == before {
            break;
        }
    }
    accepted
}

/// Pairs functions whose key is unique among unmatched functions on *both* sides. Sorted for determinism.
pub fn unique_pairs<K: Hash + Eq>(
    ctx: &MatchContext<'_>,
    key: &dyn Fn(&FunctionFeatures) -> Option<K>,
) -> Vec<(Rva, Rva)> {
    let old_ix = index(&ctx.old.functions, ctx.matched_old, key);
    let new_ix = index(&ctx.new.functions, ctx.matched_new, key);
    let mut pairs: Vec<(Rva, Rva)> = old_ix
        .iter()
        .filter_map(|(k, olds)| {
            let news = new_ix.get(k)?;
            (olds.len() == 1 && news.len() == 1).then(|| (olds[0], news[0]))
        })
        .collect();
    pairs.sort();
    pairs
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

    fn propose(&self, ctx: &MatchContext<'_>) -> Vec<Candidate> {
        unique_pairs(ctx, &|f: &FunctionFeatures| f.name.clone())
            .into_iter()
            .map(|(old, new)| {
                let name = ctx
                    .old
                    .function(old)
                    .and_then(|f| f.name.clone())
                    .unwrap_or_default();
                candidate(
                    self.name(),
                    old,
                    new,
                    0.9,
                    "name",
                    format!("unique name `{name}` on both sides"),
                )
            })
            .collect()
    }
}

/// Pass 2: identical normalized instruction hash, unique on both sides.
pub struct NormalizedHashMatcher;

impl Matcher for NormalizedHashMatcher {
    fn name(&self) -> &'static str {
        "normalized-hash"
    }

    fn propose(&self, ctx: &MatchContext<'_>) -> Vec<Candidate> {
        unique_pairs(ctx, &|f: &FunctionFeatures| f.normalized_hash.clone())
            .into_iter()
            .map(|(old, new)| {
                let hash = ctx
                    .old
                    .function(old)
                    .and_then(|f| f.normalized_hash.clone())
                    .unwrap_or_default();
                candidate(
                    self.name(),
                    old,
                    new,
                    0.95,
                    "normalized_hash",
                    format!("unique hash {hash}"),
                )
            })
            .collect()
    }
}

/// Pass 3: identical, non-empty set of referenced strings, unique on both sides.
pub struct UniqueStringsMatcher;

impl Matcher for UniqueStringsMatcher {
    fn name(&self) -> &'static str {
        "unique-strings"
    }

    fn propose(&self, ctx: &MatchContext<'_>) -> Vec<Candidate> {
        unique_pairs(ctx, &string_set_key)
            .into_iter()
            .map(|(old, new)| {
                let key = ctx
                    .old
                    .function(old)
                    .and_then(string_set_key)
                    .unwrap_or_default();
                candidate(
                    self.name(),
                    old,
                    new,
                    0.7,
                    "strings",
                    format!(
                        "unique referenced-string set [{}]",
                        key.replace('\u{1f}', ", ")
                    ),
                )
            })
            .collect()
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
    use rehook_model::{ANALYSIS_SCHEMA_VERSION, BuildId, BuildInfo, Machine, Producer};

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
        let pairs: Vec<_> = got.iter().map(|c| (c.old.0, c.new.0)).collect();
        assert_eq!(pairs, vec![(0x10, 0x110), (0x20, 0x220)]);
    }

    #[test]
    fn ambiguous_hash_yields_no_candidate() {
        let old = export("a", vec![func(0x10, None, Some("dup"))]);
        let new = export(
            "b",
            vec![
                func(0x100, None, Some("dup")),
                func(0x200, None, Some("dup")),
            ],
        );
        assert!(run_passes(&old, &new, &default_matchers()).is_empty());
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
        let got = run_passes(&old, &new, &default_matchers());
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].new, Rva(0x100));
    }
}
