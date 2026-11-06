//! Matching (design §5). Passes propose [`Candidate`]s; they never decide acceptance.
//!
//! Invariants:
//! - One-to-one: a function on either side is claimed at most once; earlier (stronger) passes win.
//! - Uniqueness: a key shared by more than one unmatched function on either side yields no candidate.
//!   It yields an [`Ambiguity`] instead, so review can show the competing functions.

use permanent_beta_model::{
    Ambiguity, AnalysisExport, Candidate, CandidateSource, Evidence, FunctionFeatures, Rva,
    evidence_kind,
};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::hash::Hash;

/// What a matcher can see: both exports and which functions earlier passes already claimed.
pub struct MatchContext<'a> {
    pub old: &'a AnalysisExport,
    pub new: &'a AnalysisExport,
    pub matched_old: &'a HashSet<Rva>,
    pub matched_new: &'a HashSet<Rva>,
    /// Candidates accepted by earlier passes, in order.
    pub pairs: &'a [Candidate],
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
        Box::new(CallSequenceMatcher),
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
                pairs: &accepted,
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
            evidence_kind::NAME,
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
            evidence_kind::NORMALIZED_HASH,
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
            evidence_kind::STRINGS,
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

/// Pass 4: call-graph propagation (design §5.1 pass 5).
///
/// For each already-matched caller, compare its unmatched callees in both builds.
///
/// - **Candidate** (order-independent): a callee whose normalized hash occurs exactly once among the caller's
///   unmatched callees on each side. "This caller calls this copy, not the other" holds whatever the call
///   order is, so it resolves copies the global hash pass found ambiguous.
/// - **Review suggestion only** (an [`Ambiguity`], never a candidate): pairs that rely on call *order*.
///   Callees are aligned in call order (longest common subsequence over matched pairs and identical code), and
///   a gap with the same number of unmatched callees on both sides is paired by position if sizes are within
///   2x ([Guess]); identical code occurring more than once is also paired by order. Compilers reorder calls
///   to side-effect-free functions (seen at /O2 in the `basic` fixture), so order alone can pair a deleted
///   function with an unrelated added one. It's useful to a reviewer, not proof.
///
/// A candidate is dropped if another caller proposes a different partner for either side.
pub struct CallSequenceMatcher;

/// Size ratio allowed for position-based suggestions. A guess until calibrated against the corpus.
const POSITIONAL_MAX_SIZE_RATIO: f32 = 2.0;

struct Aligner<'a> {
    ctx: &'a MatchContext<'a>,
    map: HashMap<Rva, Rva>,
    old_fns: HashMap<Rva, &'a FunctionFeatures>,
    new_fns: HashMap<Rva, &'a FunctionFeatures>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AlignKind {
    /// Identical code, occurring once among the caller's unmatched callees on each side.
    UniqueCode,
    /// Identical code occurring several times on each side, paired by call order.
    RepeatedCode,
    /// Different code at the same call position.
    Position,
}

/// One aligned pair from a caller's call sequence.
struct Aligned {
    old: Rva,
    new: Rva,
    kind: AlignKind,
}

impl Aligner<'_> {
    fn unmatched(&self, o: Rva, n: Rva) -> bool {
        !self.ctx.matched_old.contains(&o) && !self.ctx.matched_new.contains(&n)
    }

    fn hash_of<'b>(fns: &'b HashMap<Rva, &FunctionFeatures>, r: Rva) -> Option<&'b str> {
        fns.get(&r).and_then(|f| f.normalized_hash.as_deref())
    }

    /// Identical code anchors the alignment only if that code occurs equally often among the unmatched callees
    /// of both sequences. One old copy against two new copies would otherwise be a coin toss.
    fn same_code(&self, o: Rva, n: Rva, counts: &HashMap<String, (usize, usize)>) -> bool {
        match (
            Self::hash_of(&self.old_fns, o),
            Self::hash_of(&self.new_fns, n),
        ) {
            (Some(a), Some(b)) if a == b => counts.get(a).is_some_and(|&(x, y)| x == y),
            _ => false,
        }
    }

    fn aligns(&self, o: Rva, n: Rva, counts: &HashMap<String, (usize, usize)>) -> bool {
        match self.map.get(&o) {
            Some(&m) => m == n,
            None => self.unmatched(o, n) && self.same_code(o, n, counts),
        }
    }

    /// Per normalized hash: how many unmatched callees in (old_seq, new_seq) have it.
    fn hash_counts(&self, old_seq: &[Rva], new_seq: &[Rva]) -> HashMap<String, (usize, usize)> {
        let mut counts: HashMap<String, (usize, usize)> = HashMap::new();
        for &o in old_seq.iter().filter(|o| !self.ctx.matched_old.contains(o)) {
            if let Some(h) = Self::hash_of(&self.old_fns, o) {
                counts.entry(h.to_owned()).or_default().0 += 1;
            }
        }
        for &n in new_seq.iter().filter(|n| !self.ctx.matched_new.contains(n)) {
            if let Some(h) = Self::hash_of(&self.new_fns, n) {
                counts.entry(h.to_owned()).or_default().1 += 1;
            }
        }
        counts
    }

    fn sizes_compatible(&self, o: Rva, n: Rva) -> bool {
        let (Some(fo), Some(fnew)) = (self.old_fns.get(&o), self.new_fns.get(&n)) else {
            return false;
        };
        if fo.size == 0 || fnew.size == 0 {
            return false;
        }
        let ratio = fnew.size as f32 / fo.size as f32;
        (1.0 / POSITIONAL_MAX_SIZE_RATIO..=POSITIONAL_MAX_SIZE_RATIO).contains(&ratio)
    }

    fn align(&self, old_seq: &[Rva], new_seq: &[Rva]) -> Vec<Aligned> {
        // Longest common subsequence under `aligns`.
        let counts = self.hash_counts(old_seq, new_seq);
        let (n, m) = (old_seq.len(), new_seq.len());
        let mut lcs = vec![vec![0u32; m + 1]; n + 1];
        for i in (0..n).rev() {
            for j in (0..m).rev() {
                lcs[i][j] = if self.aligns(old_seq[i], new_seq[j], &counts) {
                    lcs[i + 1][j + 1] + 1
                } else {
                    lcs[i + 1][j].max(lcs[i][j + 1])
                };
            }
        }
        let mut anchors = Vec::new();
        let (mut i, mut j) = (0, 0);
        while i < n && j < m {
            if self.aligns(old_seq[i], new_seq[j], &counts) {
                anchors.push((i, j));
                i += 1;
                j += 1;
            } else if lcs[i + 1][j] >= lcs[i][j + 1] {
                i += 1;
            } else {
                j += 1;
            }
        }

        let mut out: Vec<Aligned> = anchors
            .iter()
            .filter(|&&(i, _)| !self.map.contains_key(&old_seq[i]))
            .map(|&(i, j)| {
                let unique = Self::hash_of(&self.old_fns, old_seq[i])
                    .and_then(|h| counts.get(h))
                    .is_some_and(|&c| c == (1, 1));
                Aligned {
                    old: old_seq[i],
                    new: new_seq[j],
                    kind: if unique {
                        AlignKind::UniqueCode
                    } else {
                        AlignKind::RepeatedCode
                    },
                }
            })
            .collect();

        // Gaps between anchors (with sentinels at both ends), paired by position when lengths agree.
        let mut prev = (0usize, 0usize);
        for &(ai, aj) in anchors.iter().chain([(n, m)].iter()) {
            let (old_gap, new_gap) = (&old_seq[prev.0..ai], &new_seq[prev.1..aj]);
            let clean = old_gap.iter().all(|o| !self.ctx.matched_old.contains(o))
                && new_gap.iter().all(|n| !self.ctx.matched_new.contains(n));
            if clean && !old_gap.is_empty() && old_gap.len() == new_gap.len() {
                for (&o, &nw) in old_gap.iter().zip(new_gap) {
                    if self.sizes_compatible(o, nw) {
                        out.push(Aligned {
                            old: o,
                            new: nw,
                            kind: AlignKind::Position,
                        });
                    }
                }
            }
            prev = (ai + 1, aj + 1);
        }
        out
    }
}

impl Matcher for CallSequenceMatcher {
    fn name(&self) -> &'static str {
        "call-sequence"
    }

    fn propose(&self, ctx: &MatchContext<'_>) -> Proposals {
        let aligner = Aligner {
            ctx,
            map: ctx.pairs.iter().map(|c| (c.old, c.new)).collect(),
            old_fns: ctx.old.functions.iter().map(|f| (f.rva, f)).collect(),
            new_fns: ctx.new.functions.iter().map(|f| (f.rva, f)).collect(),
        };

        // Unique-code pairs: old → proposed partners, new → proposing olds, and the first caller seen.
        let mut forward: BTreeMap<Rva, BTreeSet<Rva>> = BTreeMap::new();
        let mut backward: BTreeMap<Rva, BTreeSet<Rva>> = BTreeMap::new();
        let mut via: BTreeMap<(Rva, Rva), Rva> = BTreeMap::new();
        let mut ambiguities = Vec::new();
        for pair in ctx.pairs {
            let (Some(caller_old), Some(caller_new)) = (
                aligner.old_fns.get(&pair.old),
                aligner.new_fns.get(&pair.new),
            ) else {
                continue;
            };
            for a in aligner.align(&caller_old.callees, &caller_new.callees) {
                let suggestion = match a.kind {
                    AlignKind::UniqueCode => {
                        forward.entry(a.old).or_default().insert(a.new);
                        backward.entry(a.new).or_default().insert(a.old);
                        via.entry((a.old, a.new)).or_insert(pair.old);
                        continue;
                    }
                    AlignKind::RepeatedCode => {
                        "identical code that occurs more than once; paired by call order"
                    }
                    AlignKind::Position => {
                        "same call position, different code; order can change between builds"
                    }
                };
                ambiguities.push(Ambiguity {
                    matcher: self.name().to_owned(),
                    old: vec![a.old],
                    new: vec![a.new],
                    detail: format!("suggestion from caller {}: {suggestion}", pair.old),
                });
            }
        }

        let candidates = forward
            .iter()
            .filter(|(_, news)| news.len() == 1)
            .filter_map(|(&old, news)| {
                let new = *news.iter().next()?;
                if backward.get(&new).is_some_and(|olds| olds.len() != 1) {
                    return None;
                }
                let caller = via[&(old, new)];
                let mut c = candidate(
                    self.name(),
                    old,
                    new,
                    0.7,
                    evidence_kind::CALL_SEQUENCE,
                    format!(
                        "only callee of matched caller {caller} with this code, in both builds"
                    ),
                );
                c.evidence.push(Evidence {
                    kind: evidence_kind::NORMALIZED_HASH.to_owned(),
                    detail: "identical normalized code".into(),
                });
                Some(c)
            })
            .collect();
        Proposals {
            candidates,
            ambiguities,
        }
    }
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
            inferred_args: None,
            entry: None,
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

    // Call-sequence pass. `main` is matched by name; its callees are given in call order.

    fn sized(rva: u64, hash: &str, size: u32) -> FunctionFeatures {
        let mut f = func(rva, None, Some(hash));
        f.size = size;
        f
    }

    fn with_main(
        main_rva: u64,
        callees: &[u64],
        mut rest: Vec<FunctionFeatures>,
    ) -> Vec<FunctionFeatures> {
        let mut main = func(main_rva, Some("main"), None);
        main.callees = callees.iter().map(|&r| Rva(r)).collect();
        rest.insert(0, main);
        rest
    }

    fn pairs(old: &AnalysisExport, new: &AnalysisExport) -> Vec<(u64, u64)> {
        let mut p: Vec<_> = run_passes(old, new, &default_matchers())
            .candidates
            .iter()
            .map(|c| (c.old.0, c.new.0))
            .collect();
        p.sort();
        p
    }

    /// Call-sequence suggestions (review-only ambiguities) as (old, new) pairs.
    fn suggestions(old: &AnalysisExport, new: &AnalysisExport) -> Vec<(u64, u64)> {
        let mut s: Vec<_> = run_passes(old, new, &default_matchers())
            .ambiguities
            .iter()
            .filter(|a| a.matcher == "call-sequence")
            .flat_map(|a| {
                a.old
                    .iter()
                    .flat_map(|o| a.new.iter().map(move |n| (o.0, n.0)))
            })
            .collect();
        s.sort();
        s.dedup();
        s
    }

    #[test]
    fn same_position_is_a_suggestion_not_a_candidate() {
        // a is unchanged (hash match); x and y were edited (new hashes), same call order. Order alone isn't proof.
        let old = export(
            "a",
            with_main(
                1,
                &[0x10, 0x20, 0x30],
                vec![
                    sized(0x10, "a", 10),
                    sized(0x20, "x1", 10),
                    sized(0x30, "y1", 12),
                ],
            ),
        );
        let new = export(
            "b",
            with_main(
                2,
                &[0x110, 0x120, 0x130],
                vec![
                    sized(0x110, "a", 10),
                    sized(0x120, "x2", 11),
                    sized(0x130, "y2", 14),
                ],
            ),
        );
        assert_eq!(pairs(&old, &new), vec![(1, 2), (0x10, 0x110)]);
        assert_eq!(suggestions(&old, &new), vec![(0x20, 0x120), (0x30, 0x130)]);
    }

    #[test]
    fn unequal_gap_gives_no_suggestion() {
        // A callee was deleted somewhere after a: position no longer says which is which.
        let old = export(
            "a",
            with_main(
                1,
                &[0x10, 0x20, 0x30],
                vec![
                    sized(0x10, "a", 10),
                    sized(0x20, "x1", 10),
                    sized(0x30, "d", 10),
                ],
            ),
        );
        let new = export(
            "b",
            with_main(
                2,
                &[0x110, 0x120],
                vec![sized(0x110, "a", 10), sized(0x120, "x2", 10)],
            ),
        );
        assert_eq!(pairs(&old, &new), vec![(1, 2), (0x10, 0x110)]);
        assert!(suggestions(&old, &new).is_empty());
    }

    #[test]
    fn position_suggestions_need_compatible_sizes() {
        // Same slot, but a 10-byte function replaced by a 40-byte one: likely deleted + added, not edited.
        let old = export(
            "a",
            with_main(
                1,
                &[0x10, 0x20],
                vec![sized(0x10, "a", 10), sized(0x20, "d", 10)],
            ),
        );
        let new = export(
            "b",
            with_main(
                2,
                &[0x110, 0x120],
                vec![sized(0x110, "a", 10), sized(0x120, "z", 40)],
            ),
        );
        assert!(suggestions(&old, &new).is_empty());
    }

    #[test]
    fn repeated_copies_are_only_suggested_by_order() {
        // Two identical copies called in order: call order can change, so this is a suggestion, as is x after.
        let old = export(
            "a",
            with_main(
                1,
                &[0x10, 0x20, 0x30, 0x40],
                vec![
                    sized(0x10, "a", 10),
                    sized(0x20, "dup", 8),
                    sized(0x30, "dup", 8),
                    sized(0x40, "x1", 10),
                ],
            ),
        );
        let new = export(
            "b",
            with_main(
                2,
                &[0x110, 0x120, 0x130, 0x140],
                vec![
                    sized(0x110, "a", 10),
                    sized(0x120, "dup", 8),
                    sized(0x130, "dup", 8),
                    sized(0x140, "x2", 10),
                ],
            ),
        );
        assert_eq!(pairs(&old, &new), vec![(1, 2), (0x10, 0x110)]);
        assert_eq!(
            suggestions(&old, &new),
            vec![(0x20, 0x120), (0x30, 0x130), (0x40, 0x140)]
        );
    }

    #[test]
    fn caller_calling_only_one_copy_resolves_a_global_ambiguity() {
        // Globally the new build has two copies of `k` (ambiguous), but main calls exactly one of them in both
        // builds. That holds whatever the call order is, so it's a candidate.
        let old = export(
            "a",
            with_main(
                1,
                &[0x10, 0x20],
                vec![sized(0x10, "a", 10), sized(0x20, "k", 8)],
            ),
        );
        let new = export(
            "b",
            with_main(
                2,
                &[0x110, 0x120],
                vec![
                    sized(0x110, "a", 10),
                    sized(0x120, "k", 8),
                    sized(0x130, "k", 8),
                ],
            ),
        );
        assert_eq!(
            pairs(&old, &new),
            vec![(1, 2), (0x10, 0x110), (0x20, 0x120)]
        );
    }

    #[test]
    fn one_old_copy_against_two_new_copies_is_not_a_candidate() {
        // The caller calls one copy in v1 and both copies in v2: which new copy is the old one is a guess.
        let old = export(
            "a",
            with_main(
                1,
                &[0x10, 0x20, 0x40],
                vec![
                    sized(0x10, "a", 10),
                    sized(0x20, "dup", 8),
                    sized(0x40, "s", 10),
                ],
            ),
        );
        let new = export(
            "b",
            with_main(
                2,
                &[0x110, 0x120, 0x130, 0x140],
                vec![
                    sized(0x110, "a", 10),
                    sized(0x120, "dup", 8),
                    sized(0x130, "dup", 8),
                    sized(0x140, "s", 10),
                ],
            ),
        );
        let got = pairs(&old, &new);
        assert!(!got.iter().any(|&(o, _)| o == 0x20), "{got:?}");
    }

    #[test]
    fn conflicting_candidates_from_two_callers_are_dropped() {
        // main calls one copy of k (→ 0x120), helper calls the other (→ 0x130). Each caller alone would be
        // decisive; together they disagree, so neither is proposed.
        let mut helper_old = func(3, Some("helper"), None);
        helper_old.callees = vec![Rva(0x20)];
        let mut helper_new = func(4, Some("helper"), None);
        helper_new.callees = vec![Rva(0x130)];
        let mut old_fns = with_main(
            1,
            &[0x10, 0x20],
            vec![sized(0x10, "a", 10), sized(0x20, "k", 8)],
        );
        old_fns.push(helper_old);
        let mut new_fns = with_main(
            2,
            &[0x110, 0x120],
            vec![
                sized(0x110, "a", 10),
                sized(0x120, "k", 8),
                sized(0x130, "k", 8),
            ],
        );
        new_fns.push(helper_new);
        let got = pairs(&export("a", old_fns), &export("b", new_fns));
        assert!(!got.iter().any(|&(o, _)| o == 0x20), "{got:?}");
    }
}
