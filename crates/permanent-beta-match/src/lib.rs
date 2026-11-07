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

    /// Recheck one of this pass's candidates against the final matches (`ctx.pairs`, which includes it).
    /// `Some(reason)` means other evidence contradicts it: [`run_passes`] bans the pair, reruns every pass
    /// without it, and keeps it as a review suggestion. Default: never contradicted.
    fn contradiction(&self, _ctx: &MatchContext<'_>, _candidate: &Candidate) -> Option<String> {
        None
    }
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
        Box::new(MatchedCalleesMatcher),
        Box::new(CallSequenceMatcher),
    ]
}

/// Run passes in order, repeating until no pass adds a candidate (so later passes can unlock earlier ones,
/// which matters once call-graph propagation exists).
///
/// Then each candidate is rechecked by its pass against the final matches ([`Matcher::contradiction`]). If any
/// is contradicted, those pairs are banned and everything reruns from scratch, so nothing built on a vetoed
/// pair survives. Each round bans at least one new pair, so this terminates.
pub fn run_passes(
    old: &AnalysisExport,
    new: &AnalysisExport,
    matchers: &[Box<dyn Matcher>],
) -> MatchOutcome {
    let mut banned: BTreeMap<(Rva, Rva), Ambiguity> = BTreeMap::new();
    loop {
        let round = run_round(old, new, matchers, &banned);
        let ctx = MatchContext {
            old,
            new,
            matched_old: &round.matched_old,
            matched_new: &round.matched_new,
            pairs: &round.candidates,
        };
        let vetoed: Vec<Ambiguity> = round
            .candidates
            .iter()
            .filter_map(|c| {
                let CandidateSource::Deterministic { matcher } = &c.source else {
                    return None;
                };
                let m = matchers.iter().find(|m| m.name() == matcher)?;
                let reason = m.contradiction(&ctx, c)?;
                Some(Ambiguity {
                    matcher: matcher.clone(),
                    old: vec![c.old],
                    new: vec![c.new],
                    detail: format!("suggestion only: {reason}"),
                })
            })
            .collect();
        if vetoed.is_empty() {
            let mut ambiguities = round.ambiguities;
            ambiguities.extend(banned.into_values());
            return finish(
                round.candidates,
                &round.matched_old,
                &round.matched_new,
                ambiguities,
            );
        }
        for v in vetoed {
            banned.insert((v.old[0], v.new[0]), v);
        }
    }
}

struct Round {
    candidates: Vec<Candidate>,
    matched_old: HashSet<Rva>,
    matched_new: HashSet<Rva>,
    ambiguities: Vec<Ambiguity>,
}

/// One fixpoint of all passes, never accepting a banned pair.
fn run_round(
    old: &AnalysisExport,
    new: &AnalysisExport,
    matchers: &[Box<dyn Matcher>],
    banned: &BTreeMap<(Rva, Rva), Ambiguity>,
) -> Round {
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
                if !matched_old.contains(&c.old)
                    && !matched_new.contains(&c.new)
                    && !banned.contains_key(&(c.old, c.new))
                {
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
    Round {
        candidates: accepted,
        matched_old,
        matched_new,
        ambiguities,
    }
}

fn finish(
    accepted: Vec<Candidate>,
    matched_old: &HashSet<Rva>,
    matched_new: &HashSet<Rva>,
    mut ambiguities: Vec<Ambiguity>,
) -> MatchOutcome {
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
    group_by_keys(ctx, key, key)
}

/// Like [`group_by_key`], with a separate key function per build (for keys that refer to the other build).
pub fn group_by_keys<K: Hash + Eq>(
    ctx: &MatchContext<'_>,
    old_key: &dyn Fn(&FunctionFeatures) -> Option<K>,
    new_key: &dyn Fn(&FunctionFeatures) -> Option<K>,
) -> KeyGroups {
    let old_ix = index(&ctx.old.functions, ctx.matched_old, old_key);
    let new_ix = index(&ctx.new.functions, ctx.matched_new, new_key);
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
    propose_by_keys(ctx, matcher, score, kind, key, key, describe)
}

fn propose_by_keys<K: Hash + Eq>(
    ctx: &MatchContext<'_>,
    matcher: &str,
    score: f32,
    kind: &str,
    old_key: &dyn Fn(&FunctionFeatures) -> Option<K>,
    new_key: &dyn Fn(&FunctionFeatures) -> Option<K>,
    describe: &dyn Fn(&FunctionFeatures) -> String,
) -> Proposals {
    let groups = group_by_keys(ctx, old_key, new_key);
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
        let mut proposals = propose_by_key(
            ctx,
            self.name(),
            0.7,
            evidence_kind::STRINGS,
            &string_set_key,
            &|f: &FunctionFeatures| {
                let key = string_set_key(f).unwrap_or_default();
                format!("referenced-string set [{}]", key.replace('\u{1f}', ", "))
            },
        );
        // Contradicted pairs are dropped now, and rechecked against the final matches too, because the callers
        // may only be matched later.
        let mut kept = Vec::new();
        for c in proposals.candidates {
            match self.contradiction(ctx, &c) {
                None => kept.push(c),
                Some(reason) => proposals.ambiguities.push(Ambiguity {
                    matcher: self.name().to_owned(),
                    old: vec![c.old],
                    new: vec![c.new],
                    detail: format!("suggestion only: {reason}"),
                }),
            }
        }
        proposals.candidates = kept;
        proposals
    }

    /// Moving a literal, or a whole body, into a new function is a common refactor: Lua 5.4.8 moved
    /// "error in error handling" from luaD_seterrorobj into the new luaD_errerr, and zstd 1.5.7 moved
    /// ZSTD_entropyCompressSeqStore's body into a new ZSTD_entropyCompressSeqStore_wExtLitBuffer behind a
    /// wrapper. So strings alone don't decide when other evidence contradicts them:
    /// - a different register-argument count, or
    /// - callers: the old function has matched callers, and none of their counterparts calls the new function.
    ///   A veto only costs recall, so one disagreeing caller is enough.
    fn contradiction(&self, ctx: &MatchContext<'_>, c: &Candidate) -> Option<String> {
        let args = |e: &AnalysisExport, r| e.function(r).and_then(|f| f.inferred_args);
        if let (Some(a), Some(b)) = (args(ctx.old, c.old), args(ctx.new, c.new)) {
            if a != b {
                return Some(format!(
                    "same strings, but reads {a} -> {b} register arguments"
                ));
            }
        }
        let map: HashMap<Rva, Rva> = ctx.pairs.iter().map(|p| (p.old, p.new)).collect();
        let mapped: Vec<Rva> = ctx
            .old
            .functions
            .iter()
            .filter(|f| f.rva != c.old && f.callees.contains(&c.old))
            .filter_map(|f| map.get(&f.rva).copied())
            .collect();
        let agrees = mapped.iter().any(|&nc| {
            ctx.new
                .function(nc)
                .is_some_and(|f| f.callees.contains(&c.new))
        });
        (!mapped.is_empty() && !agrees).then(|| {
            format!(
                "same strings, but none of the {} matched caller(s) calls the new function",
                mapped.len()
            )
        })
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

/// Pass 4: identical code that calls the same already-matched functions (design §5.1 pass 5a).
///
/// Normalization masks call targets, so code that differs only in what it calls hashes the same, and the hash
/// pass finds it ambiguous: e.g. zlib's `jmp`-only wrappers `adler32` → `adler32_z` and `crc32` → `crc32_z`.
/// Key: normalized hash plus the callee list (in call order) mapped into the new build.
///
/// - Every callee must already be matched. A partly mapped list would treat unknown callees as equal.
/// - A function with no callees has no key: its key would be the hash alone, which the hash pass already tried.
/// - Several functions with the same code and the same mapped callees stay ambiguous.
pub struct MatchedCalleesMatcher;

type CalleeKey = (String, Vec<Rva>);

impl Matcher for MatchedCalleesMatcher {
    fn name(&self) -> &'static str {
        "matched-callees"
    }

    fn propose(&self, ctx: &MatchContext<'_>) -> Proposals {
        let map: HashMap<Rva, Rva> = ctx.pairs.iter().map(|c| (c.old, c.new)).collect();
        let old_key = |f: &FunctionFeatures| -> Option<CalleeKey> {
            if f.callees.is_empty() {
                return None;
            }
            let mapped: Option<Vec<Rva>> = f.callees.iter().map(|c| map.get(c).copied()).collect();
            Some((f.normalized_hash.clone()?, mapped?))
        };
        // New callees are taken as they are: an unmatched one can't equal a mapped old callee, so it never
        // produces a shared key.
        let new_key = |f: &FunctionFeatures| -> Option<CalleeKey> {
            if f.callees.is_empty() {
                return None;
            }
            Some((f.normalized_hash.clone()?, f.callees.clone()))
        };
        let describe = |f: &FunctionFeatures| {
            let callees: Vec<String> = f.callees.iter().map(|c| c.to_string()).collect();
            format!(
                "code {} calling matched [{}]",
                f.normalized_hash.as_deref().unwrap_or(""),
                callees.join(", ")
            )
        };
        let mut proposals = propose_by_keys(
            ctx,
            self.name(),
            0.9,
            evidence_kind::CALLEES,
            &old_key,
            &new_key,
            &describe,
        );
        for c in &mut proposals.candidates {
            c.evidence.push(Evidence {
                kind: evidence_kind::NORMALIZED_HASH.to_owned(),
                detail: "identical normalized code".into(),
            });
        }
        proposals
    }
}

/// Pass 5: call-graph propagation (design §5.1 pass 5).
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

    fn with_strings(rva: u64, hash: &str, strings: &[&str], args: Option<u8>) -> FunctionFeatures {
        let mut f = func(rva, None, Some(hash));
        f.strings = strings.iter().map(|s| s.to_string()).collect();
        f.inferred_args = args;
        f
    }

    #[test]
    fn a_moved_literal_with_a_different_argument_count_is_not_a_string_match() {
        // The only string moved from a 3-argument function into a new 1-argument helper.
        let old = export(
            "a",
            vec![with_strings(
                0x10,
                "h1",
                &["error in error handling"],
                Some(3),
            )],
        );
        let new = export(
            "b",
            vec![
                with_strings(0x100, "h2", &[], Some(3)),
                with_strings(0x200, "h3", &["error in error handling"], Some(1)),
            ],
        );
        assert!(pairs(&old, &new).is_empty());
    }

    #[test]
    fn string_match_survives_unknown_or_equal_argument_counts() {
        for (a, b) in [(Some(2), Some(2)), (None, Some(1)), (Some(1), None)] {
            let old = export("a", vec![with_strings(0x10, "h1", &["config.ini"], a)]);
            let new = export("b", vec![with_strings(0x100, "h2", &["config.ini"], b)]);
            assert_eq!(pairs(&old, &new), vec![(0x10, 0x100)], "{a:?} {b:?}");
        }
    }

    /// The old caller (matched by name) calls f, which holds the string. In the new build the caller calls
    /// `new_callee`; the string sits in 0x200.
    fn moved_body(new_callee: u64) -> (AnalysisExport, AnalysisExport) {
        let mut caller_old = func(1, Some("caller"), None);
        caller_old.callees = vec![Rva(0x10)];
        let mut caller_new = func(2, Some("caller"), None);
        caller_new.callees = vec![Rva(new_callee)];
        let mut wrapper = with_strings(0x100, "hw", &[], None);
        wrapper.callees = vec![Rva(0x200)];
        (
            export(
                "a",
                vec![
                    caller_old,
                    with_strings(0x10, "h1", &["compress failed"], None),
                ],
            ),
            export(
                "b",
                vec![
                    caller_new,
                    wrapper,
                    with_strings(0x200, "h2", &["compress failed"], None),
                ],
            ),
        )
    }

    #[test]
    fn a_body_moved_behind_a_wrapper_is_not_a_string_match() {
        // zstd 1.5.7: the matched caller now calls a wrapper, and the string moved into the wrapped function.
        let (old, new) = moved_body(0x100);
        let got = pairs(&old, &new);
        assert!(!got.iter().any(|&(o, _)| o == 0x10), "{got:?}");
    }

    #[test]
    fn a_contradiction_found_only_after_later_passes_still_vetoes() {
        // Strings run before the caller is matched (here by a name pass placed after it), so only the recheck
        // against the final matches sees the disagreement. The pair is banned, kept as a suggestion.
        let (old, new) = moved_body(0x100);
        let late: Vec<Box<dyn Matcher>> =
            vec![Box::new(UniqueStringsMatcher), Box::new(SymbolNameMatcher)];
        let got = run_passes(&old, &new, &late);
        assert!(
            !got.candidates.iter().any(|c| c.old == Rva(0x10)),
            "{:?}",
            got.candidates
        );
        assert!(
            got.candidates.iter().any(|c| c.old == Rva(1)),
            "caller still matched"
        );
        assert!(
            got.ambiguities
                .iter()
                .any(|a| a.old == vec![Rva(0x10)] && a.new == vec![Rva(0x200)]),
            "{:?}",
            got.ambiguities
        );
    }

    #[test]
    fn a_string_match_its_matched_caller_agrees_with_is_kept() {
        let (old, new) = moved_body(0x200);
        assert!(pairs(&old, &new).contains(&(0x10, 0x200)));
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

    // Matched-callees pass. Named functions are matched by name; `w` is a wrapper hash shared by every wrapper.

    fn calls(rva: u64, hash: &str, callees: &[u64]) -> FunctionFeatures {
        let mut f = func(rva, None, Some(hash));
        f.callees = callees.iter().map(|&r| Rva(r)).collect();
        f
    }

    fn matcher_of(old: &AnalysisExport, new: &AnalysisExport, old_rva: u64) -> Option<String> {
        run_passes(old, new, &default_matchers())
            .candidates
            .iter()
            .find(|c| c.old.0 == old_rva)
            .map(|c| match &c.source {
                CandidateSource::Deterministic { matcher } => matcher.clone(),
                other => format!("{other:?}"),
            })
    }

    #[test]
    fn identical_wrappers_are_told_apart_by_their_matched_callees() {
        // adler32 → adler32_z and crc32 → crc32_z: the same `jmp`, ambiguous by hash alone.
        let old = export(
            "a",
            vec![
                func(0x10, Some("adler32_z"), None),
                func(0x20, Some("crc32_z"), None),
                calls(0x30, "w", &[0x10]),
                calls(0x40, "w", &[0x20]),
            ],
        );
        let new = export(
            "b",
            vec![
                func(0x110, Some("adler32_z"), None),
                func(0x120, Some("crc32_z"), None),
                calls(0x140, "w", &[0x120]),
                calls(0x130, "w", &[0x110]),
            ],
        );
        let got = pairs(&old, &new);
        assert!(got.contains(&(0x30, 0x130)), "{got:?}");
        assert!(got.contains(&(0x40, 0x140)), "{got:?}");
        assert_eq!(
            matcher_of(&old, &new, 0x30).as_deref(),
            Some("matched-callees")
        );
    }

    #[test]
    fn wrappers_calling_the_same_function_stay_ambiguous() {
        // Two identical wrappers of the same function in both builds: callees don't say which is which.
        let old = export(
            "a",
            vec![
                func(0x10, Some("f"), None),
                calls(0x30, "w", &[0x10]),
                calls(0x40, "w", &[0x10]),
            ],
        );
        let new = export(
            "b",
            vec![
                func(0x110, Some("f"), None),
                calls(0x130, "w", &[0x110]),
                calls(0x140, "w", &[0x110]),
            ],
        );
        assert_eq!(pairs(&old, &new), vec![(0x10, 0x110)]);
    }

    #[test]
    fn a_partly_matched_callee_list_is_not_a_key() {
        // Old wrapper calls x and an unmatched u. New wrappers: one calls x and an unmatched v, one calls x and y.
        // Ignoring the unmatched callees would pair 0x30 with 0x130, but u and v are unknown, not equal.
        let old = export(
            "a",
            vec![
                func(0x10, Some("x"), None),
                func(0x20, Some("y"), None),
                func(0x50, None, Some("u1")),
                calls(0x30, "w", &[0x10, 0x50]),
            ],
        );
        let new = export(
            "b",
            vec![
                func(0x110, Some("x"), None),
                func(0x120, Some("y"), None),
                func(0x150, None, Some("v")),
                calls(0x130, "w", &[0x110, 0x150]),
                calls(0x140, "w", &[0x110, 0x120]),
            ],
        );
        let got = pairs(&old, &new);
        assert!(!got.iter().any(|&(o, _)| o == 0x30), "{got:?}");
    }

    #[test]
    fn a_wrapper_whose_matched_callee_differs_is_not_proposed() {
        // Old wrapper calls x; the only new wrapper with that code calls y. Same code, different target.
        let old = export(
            "a",
            vec![
                func(0x10, Some("x"), None),
                func(0x20, Some("y"), None),
                calls(0x30, "w", &[0x10]),
                calls(0x40, "w", &[0x10]),
            ],
        );
        let new = export(
            "b",
            vec![
                func(0x110, Some("x"), None),
                func(0x120, Some("y"), None),
                calls(0x140, "w", &[0x120]),
                calls(0x150, "w", &[0x120]),
            ],
        );
        let got = pairs(&old, &new);
        assert!(!got.iter().any(|&(o, _)| o == 0x30 || o == 0x40), "{got:?}");
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
