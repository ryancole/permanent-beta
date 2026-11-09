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

    /// A weak pass runs only once every other pass has stopped finding anything, so a weak guess never
    /// claims a function that stronger evidence would have matched. Default: not weak.
    fn weak(&self) -> bool {
        false
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
        Box::new(MnemonicHashMatcher),
        Box::new(MatchedCalleesMatcher),
        Box::new(CallSequenceMatcher),
        Box::new(TableSlotMatcher),
        Box::new(SimilarityMatcher::default()),
    ]
}

/// The default passes with other similarity thresholds, for calibrating them on the corpus.
pub fn matchers_with_similarity(params: SimilarityParams) -> Vec<Box<dyn Matcher>> {
    let mut m = default_matchers();
    m.pop();
    m.push(Box::new(SimilarityMatcher { params }));
    m
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

/// One fixpoint of all passes, never accepting a banned pair. The strong passes run to a fixpoint first; then
/// the weak passes run one at a time, and anything a weak pass adds goes back to the strong passes.
fn run_round(
    old: &AnalysisExport,
    new: &AnalysisExport,
    matchers: &[Box<dyn Matcher>],
    banned: &BTreeMap<(Rva, Rva), Ambiguity>,
) -> Round {
    let mut round = Round {
        candidates: Vec::new(),
        matched_old: HashSet::new(),
        matched_new: HashSet::new(),
        ambiguities: Vec::new(),
    };
    let (weak, strong): (Vec<&dyn Matcher>, Vec<&dyn Matcher>) =
        matchers.iter().map(|m| m.as_ref()).partition(|m| m.weak());
    loop {
        while strong
            .iter()
            .fold(false, |added, m| round.apply(*m, old, new, banned) | added)
        {}
        if !weak.iter().any(|m| round.apply(*m, old, new, banned)) {
            return round;
        }
    }
}

impl Round {
    /// Run one pass and accept its unclaimed, unbanned candidates. True if it added any.
    fn apply(
        &mut self,
        matcher: &dyn Matcher,
        old: &AnalysisExport,
        new: &AnalysisExport,
        banned: &BTreeMap<(Rva, Rva), Ambiguity>,
    ) -> bool {
        let ctx = MatchContext {
            old,
            new,
            matched_old: &self.matched_old,
            matched_new: &self.matched_new,
            pairs: &self.candidates,
        };
        let proposals = matcher.propose(&ctx);
        let before = self.candidates.len();
        for c in proposals.candidates {
            if !self.matched_old.contains(&c.old)
                && !self.matched_new.contains(&c.new)
                && !banned.contains_key(&(c.old, c.new))
            {
                self.matched_old.insert(c.old);
                self.matched_new.insert(c.new);
                self.candidates.push(c);
            }
        }
        self.ambiguities.extend(proposals.ambiguities);
        self.candidates.len() > before
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
///
/// **Vetoed** like the strings pass when the old function has matched callers and none of their counterparts
/// calls the new function (rechecked against the final matches). Unique code isn't unique identity: yaml-cpp
/// 0.9.0 dropped `std::string` iterator helpers and gained `std::array<char, 20>` ones with byte-identical
/// code, each the only copy in its build. The old helpers' matched caller no longer calls anything like them.
///
/// **Pairing by elimination needs an anchor.** When the code has several copies in either build, a group can
/// become unique only because other copies were matched first. Then the last copies left are paired only if a
/// matched neighbour agrees (as in the mnemonic pass); otherwise it's a review suggestion. In yaml-cpp 0.9.0 an
/// 11-byte helper with 66 copies per build was the last one left on each side, but a different function.
pub struct NormalizedHashMatcher;

impl Matcher for NormalizedHashMatcher {
    fn name(&self) -> &'static str {
        "normalized-hash"
    }

    fn propose(&self, ctx: &MatchContext<'_>) -> Proposals {
        let mut proposals = propose_by_key(
            ctx,
            self.name(),
            0.95,
            evidence_kind::NORMALIZED_HASH,
            &|f: &FunctionFeatures| f.normalized_hash.clone(),
            &|f: &FunctionFeatures| format!("hash {}", f.normalized_hash.as_deref().unwrap_or("")),
        );
        fn copies(e: &AnalysisExport) -> HashMap<&str, usize> {
            let mut c: HashMap<&str, usize> = HashMap::new();
            for h in e
                .functions
                .iter()
                .filter_map(|f| f.normalized_hash.as_deref())
            {
                *c.entry(h).or_default() += 1;
            }
            c
        }
        let (old_copies, new_copies) = (copies(ctx.old), copies(ctx.new));
        let hash = |e: &'_ AnalysisExport, r: Rva| {
            e.function(r)
                .and_then(|f| f.normalized_hash.clone())
                .unwrap_or_default()
        };
        let mut kept = Vec::new();
        for mut c in proposals.candidates {
            let h = hash(ctx.old, c.old);
            let (o, n) = (
                old_copies.get(h.as_str()).copied().unwrap_or(0),
                new_copies.get(h.as_str()).copied().unwrap_or(0),
            );
            if o <= 1 && n <= 1 {
                kept.push(c);
            } else if let Some(anchor) = MnemonicHashMatcher::anchor(ctx, c.old, c.new) {
                c.evidence.push(anchor);
                kept.push(c);
            } else {
                proposals.ambiguities.push(Ambiguity {
                    matcher: self.name().to_owned(),
                    old: vec![c.old],
                    new: vec![c.new],
                    detail: format!(
                        "suggestion only: identical code with {o} and {n} copies, the last unmatched                          on each side, but no matched neighbour agrees"
                    ),
                });
            }
        }
        proposals.candidates = kept;
        proposals
    }

    fn contradiction(&self, ctx: &MatchContext<'_>, c: &Candidate) -> Option<String> {
        callers_disagree(ctx, c).map(|r| format!("same code, but {r}"))
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
        callers_disagree(ctx, c).map(|r| format!("same strings, but {r}"))
    }
}

/// The old function has matched callers, and none of their counterparts calls the new function. A veto only
/// costs recall, so one disagreeing caller is enough.
fn callers_disagree(ctx: &MatchContext<'_>, c: &Candidate) -> Option<String> {
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
            "none of the {} matched caller(s) calls the new function",
            mapped.len()
        )
    })
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

/// Pass 4: the same instruction sequence (mnemonics only; operands may differ), unique on both sides, gated
/// (design §5.1 pass 4). Catches a function whose code is unchanged except for operands: a changed constant,
/// stack offset or struct field offset breaks the normalized hash but not the mnemonic sequence.
///
/// Uniqueness alone isn't safe: on short functions two unrelated ones can each have a unique sequence. So a
/// unique pair becomes a candidate only if
/// - both functions are at least [`MNEMONIC_MIN_SIZE`] bytes, and
/// - a matched neighbour agrees: the old function calls a matched function whose counterpart the new function
///   calls, or a matched caller's counterpart calls the new function. Without one it's a review suggestion.
///
/// Vetoed, like the strings pass, by a different register-argument count or by matched callers that disagree,
/// and rechecked against the final matches.
pub struct MnemonicHashMatcher;

/// Smallest function the mnemonic pass matches, in bytes. [Guess] until calibrated: the `basic` fixture's
/// smallest edited functions are around 20–40 bytes at /O2.
pub const MNEMONIC_MIN_SIZE: u32 = 32;

impl MnemonicHashMatcher {
    /// A matched neighbour that agrees with pairing `old` with `new`, as evidence.
    fn anchor(ctx: &MatchContext<'_>, old: Rva, new: Rva) -> Option<Evidence> {
        let (o, n) = (ctx.old.function(old)?, ctx.new.function(new)?);
        let map: HashMap<Rva, Rva> = ctx.pairs.iter().map(|p| (p.old, p.new)).collect();
        if let Some((oc, nc)) = o.callees.iter().filter(|c| **c != old).find_map(|c| {
            map.get(c)
                .filter(|m| n.callees.contains(m))
                .map(|m| (*c, *m))
        }) {
            return Some(Evidence {
                kind: evidence_kind::CALLEES.to_owned(),
                detail: format!("both call matched {oc} -> {nc}"),
            });
        }
        ctx.old
            .functions
            .iter()
            .filter(|f| f.rva != old && f.callees.contains(&old))
            .find_map(|caller| {
                let nc = map.get(&caller.rva)?;
                ctx.new
                    .function(*nc)
                    .filter(|f| f.callees.contains(&new))
                    .map(|_| Evidence {
                        kind: evidence_kind::CALL_SEQUENCE.to_owned(),
                        detail: format!("called by matched {} -> {nc}", caller.rva),
                    })
            })
    }
}

impl Matcher for MnemonicHashMatcher {
    fn name(&self) -> &'static str {
        "mnemonic-hash"
    }

    fn propose(&self, ctx: &MatchContext<'_>) -> Proposals {
        let key = |f: &FunctionFeatures| {
            (f.size >= MNEMONIC_MIN_SIZE)
                .then(|| f.mnemonic_hash.clone())
                .flatten()
        };
        let mut proposals = propose_by_key(
            ctx,
            self.name(),
            0.8,
            evidence_kind::MNEMONIC_HASH,
            &key,
            &|f: &FunctionFeatures| {
                format!(
                    "instruction sequence {}",
                    f.mnemonic_hash.as_deref().unwrap_or("")
                )
            },
        );
        let mut kept = Vec::new();
        for mut c in proposals.candidates {
            let suggestion = |detail: String| Ambiguity {
                matcher: self.name().to_owned(),
                old: vec![c.old],
                new: vec![c.new],
                detail: format!("suggestion only: {detail}"),
            };
            if let Some(reason) = self.contradiction(ctx, &c) {
                proposals.ambiguities.push(suggestion(reason));
            } else if let Some(anchor) = Self::anchor(ctx, c.old, c.new) {
                c.evidence.push(anchor);
                kept.push(c);
            } else {
                proposals.ambiguities.push(suggestion(
                    "same instruction sequence, but no matched neighbour agrees".into(),
                ));
            }
        }
        proposals.candidates = kept;
        proposals
    }

    fn contradiction(&self, ctx: &MatchContext<'_>, c: &Candidate) -> Option<String> {
        let args = |e: &AnalysisExport, r| e.function(r).and_then(|f| f.inferred_args);
        if let (Some(a), Some(b)) = (args(ctx.old, c.old), args(ctx.new, c.new)) {
            if a != b {
                return Some(format!(
                    "same instruction sequence, but reads {a} -> {b} register arguments"
                ));
            }
        }
        callers_disagree(ctx, c).map(|r| format!("same instruction sequence, but {r}"))
    }
}

/// Pass 5a: identical code that calls the same already-matched functions (design §5.1 pass 5a).
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

/// Pass 5b: same slot in corresponding code-pointer tables (design §5.1 pass 5b), for C++ virtual functions.
///
/// Small virtual overrides are often byte-identical across classes (TinyXML-2's `ToElement`, `ToText`, ...
/// returning null), so the hash pass finds them ambiguous, and nothing calls them directly. Their vtable says
/// which is which: slot `i` of a class's vtable is the same virtual in both builds.
///
/// - Two tables **correspond** when they have the same length, at least [`TABLE_MIN_ANCHORS`] slots hold
///   functions already matched to each other, no slot contradicts (an old function matched elsewhere, or a new
///   one already claimed while the old one isn't), and the correspondence is unique on both sides.
/// - The functions at the same unmatched slot of corresponding tables are a **candidate** only if their
///   normalized code is identical. A slot whose code differs is a review suggestion: a virtual replaced by a new
///   one at the same position (same table length) must not be matched.
/// - A function paired with different partners by different tables gets no candidate (an ambiguity).
/// - Rechecked against the final matches: if the tables no longer correspond, the pair is vetoed.
pub struct TableSlotMatcher;

/// Matched slots that must agree before two tables are taken to correspond. [Guess]: uniqueness and the
/// identical-code requirement carry most of the weight.
pub const TABLE_MIN_ANCHORS: usize = 1;

impl TableSlotMatcher {
    /// Corresponding (old table, new table) index pairs under the matches in `map`. Slots holding `ignore` (a
    /// candidate being rechecked) count as neither anchor nor conflict.
    fn correspondences(
        ctx: &MatchContext<'_>,
        map: &HashMap<Rva, Rva>,
        ignore: Option<Rva>,
    ) -> Vec<(usize, usize)> {
        let compatible = |t: &[Rva], u: &[Rva]| -> bool {
            if t.len() != u.len() {
                return false;
            }
            let mut anchors = 0;
            for (&o, &n) in t.iter().zip(u) {
                if Some(o) == ignore {
                    continue;
                }
                match map.get(&o) {
                    Some(&m) if m == n => anchors += 1,
                    Some(_) => return false,
                    None if ctx.matched_new.contains(&n) => return false,
                    None => {}
                }
            }
            anchors >= TABLE_MIN_ANCHORS
        };
        let (olds, news) = (&ctx.old.code_tables, &ctx.new.code_tables);
        let mut by_old: Vec<Vec<usize>> = vec![Vec::new(); olds.len()];
        let mut by_new: Vec<Vec<usize>> = vec![Vec::new(); news.len()];
        for (i, t) in olds.iter().enumerate() {
            for (j, u) in news.iter().enumerate() {
                if compatible(&t.slots, &u.slots) {
                    by_old[i].push(j);
                    by_new[j].push(i);
                }
            }
        }
        by_old
            .iter()
            .enumerate()
            .filter_map(|(i, js)| match js.as_slice() {
                [j] if by_new[*j].len() == 1 => Some((i, *j)),
                _ => None,
            })
            .collect()
    }
}

impl Matcher for TableSlotMatcher {
    fn name(&self) -> &'static str {
        "table-slot"
    }

    fn propose(&self, ctx: &MatchContext<'_>) -> Proposals {
        let map: HashMap<Rva, Rva> = ctx.pairs.iter().map(|c| (c.old, c.new)).collect();
        // Every pairing a corresponding table suggests, and the old slots that suggest it.
        let mut partners: BTreeMap<Rva, BTreeSet<Rva>> = BTreeMap::new();
        let mut rev: BTreeMap<Rva, BTreeSet<Rva>> = BTreeMap::new();
        let mut slots_of: BTreeMap<(Rva, Rva), BTreeSet<Rva>> = BTreeMap::new();
        for (i, j) in Self::correspondences(ctx, &map, None) {
            let (t, u) = (&ctx.old.code_tables[i], &ctx.new.code_tables[j]);
            for (k, (&o, &n)) in t.slots.iter().zip(&u.slots).enumerate() {
                if ctx.matched_old.contains(&o) || ctx.matched_new.contains(&n) {
                    continue;
                }
                partners.entry(o).or_default().insert(n);
                rev.entry(n).or_default().insert(o);
                slots_of
                    .entry((o, n))
                    .or_default()
                    .insert(Rva(t.rva.0 + 8 * k as u64));
            }
        }
        let hash =
            |e: &AnalysisExport, r: Rva| e.function(r).and_then(|f| f.normalized_hash.clone());
        let mut out = Proposals::default();
        for (&o, ns) in &partners {
            let single = ns.len() == 1 && ns.iter().all(|n| rev[n].len() == 1);
            if !single {
                let mut old: Vec<Rva> = ns.iter().flat_map(|n| rev[n].iter().copied()).collect();
                old.sort();
                old.dedup();
                out.ambiguities.push(Ambiguity {
                    matcher: self.name().to_owned(),
                    old,
                    new: ns.iter().copied().collect(),
                    detail: "corresponding code-pointer tables pair these functions differently"
                        .into(),
                });
                continue;
            }
            let n = *ns.iter().next().expect("one partner");
            let slots: Vec<String> = slots_of[&(o, n)].iter().map(|s| s.to_string()).collect();
            let at = format!("slot (old {})", slots.join(", "));
            match (hash(ctx.old, o), hash(ctx.new, n)) {
                (Some(a), Some(b)) if a == b => {
                    let mut c = candidate(
                        self.name(),
                        o,
                        n,
                        0.85,
                        evidence_kind::TABLE_SLOT,
                        format!("same {at} in corresponding code-pointer tables"),
                    );
                    c.evidence.push(Evidence {
                        kind: evidence_kind::NORMALIZED_HASH.to_owned(),
                        detail: "identical normalized code".into(),
                    });
                    out.candidates.push(c);
                }
                _ => out.ambiguities.push(Ambiguity {
                    matcher: self.name().to_owned(),
                    old: vec![o],
                    new: vec![n],
                    detail: format!(
                        "suggestion only: same {at} in corresponding code-pointer tables, but the code differs"
                    ),
                }),
            }
        }
        out
    }

    fn contradiction(&self, ctx: &MatchContext<'_>, c: &Candidate) -> Option<String> {
        let map: HashMap<Rva, Rva> = ctx.pairs.iter().map(|p| (p.old, p.new)).collect();
        let still = Self::correspondences(ctx, &map, Some(c.old))
            .into_iter()
            .any(|(i, j)| {
                let (t, u) = (&ctx.old.code_tables[i], &ctx.new.code_tables[j]);
                t.slots
                    .iter()
                    .zip(&u.slots)
                    .any(|(&o, &n)| o == c.old && n == c.new)
            });
        (!still)
            .then(|| "its code-pointer tables no longer correspond under the final matches".into())
    }
}

/// Pass 6: structural similarity, for edited functions (design §5.1 pass 6). Weak: it runs only once every
/// stronger pass has stopped.
///
/// - **Candidates** for an unmatched old function are the unmatched new functions that share an anchor with it:
///   a matched callee or caller, a string, a constant or an import. Anchors held by more than
///   [`SIM_MAX_BUCKET`] functions are too common to count.
/// - **Score:** the weighted mean of the components both functions have data for: code (mnemonic counts,
///   order-free), shape (blocks and edges), size, matched callees, matched callers, strings, constants and
///   imports.
/// - **Candidate** only if the pair is each function's best, scores at least [`SIM_MIN_SCORE`], and beats the
///   runner-up on *both* sides by [`SIM_MIN_MARGIN`]. Otherwise an old function with a qualifying best is an
///   ambiguity listing its closest competitors. Functions under [`SIM_MIN_SIZE`] bytes are skipped: small
///   functions look alike.
/// - **Vetoed** when the old function's matched callers don't call the new one (rechecked against the final
///   matches). A different inferred argument count is *not* a veto here: an added parameter is exactly the
///   kind of edit this pass is for, and verification sends it to review.
///
/// All thresholds and weights are [Guess] until calibrated against the corpus.
#[derive(Debug, Default, Clone, Copy)]
pub struct SimilarityMatcher {
    pub params: SimilarityParams,
}

/// The similarity pass's thresholds. `Default` is what the engine uses.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SimilarityParams {
    pub min_score: f32,
    pub min_margin: f32,
    pub min_size: u32,
}

impl Default for SimilarityParams {
    fn default() -> Self {
        Self {
            min_score: SIM_MIN_SCORE,
            min_margin: SIM_MIN_MARGIN,
            min_size: SIM_MIN_SIZE,
        }
    }
}

// Calibrated 2026-11-07 with `pbeta-corpus sweep` over the corpus (21 variants: basic, zlib, Lua, zstd):
// - score: wrong matches appear at 0.70 (2, zstd 1.5.6 -> 1.5.7 /O2) and none at 0.75 or above, at any margin
//   or size tried. So 0.75 is the lowest clean value, with no headroom below it.
// - margin: no wrong match at any margin from 0.02 to 0.2 once the score is >= 0.75; 0.1 -> 0.05 adds 108
//   correct (review) candidates. 0.05 sits halfway to the loosest clean value tried.
// - size: 8 adds 11 correct over 16, 32 loses 21; kept at 16.
// Calibrated on one small corpus: recheck with the sweep whenever the corpus grows.

/// Minimum similarity score for a candidate. [Calibrated]
pub const SIM_MIN_SCORE: f32 = 0.75;
/// Minimum lead over the runner-up, on both sides. [Calibrated]
pub const SIM_MIN_MARGIN: f32 = 0.05;
/// Functions smaller than this (bytes) are left alone. [Calibrated]
pub const SIM_MIN_SIZE: u32 = 16;
/// Anchors shared by more functions than this are ignored when picking candidates. [Guess]
pub const SIM_MAX_BUCKET: usize = 32;
/// Matched callers that must call a candidate directly (and none its would-be wrapper) before the wrapper rule
/// is overruled. [Guess]: 1 let zstd 1.5.6's BIT_reloadDStreamFast through as a wrong match.
pub const WRAPPER_MIN_DIRECT_CALLERS: usize = 2;
/// How close an unmatched caller's score must be to the best before the old function may have been inlined into
/// it. [Guess]: any score at all cost up to 31 correct per zstd variant; TinyXML-2's case is 0.07 behind.
pub const INLINED_CALLER_MARGIN: f32 = 0.1;

/// Component weights. [Guess]
const SIM_WEIGHTS: [(&str, f32); 8] = [
    ("code", 3.0),
    ("shape", 1.0),
    ("size", 1.0),
    ("callees", 2.0),
    ("callers", 2.0),
    ("strings", 2.0),
    ("constants", 1.0),
    ("imports", 1.0),
];

fn jaccard<T: Ord>(a: &BTreeSet<T>, b: &BTreeSet<T>) -> Option<f32> {
    let union = a.union(b).count();
    (union > 0).then(|| a.intersection(b).count() as f32 / union as f32)
}

fn ratio(a: u32, b: u32) -> f32 {
    match a.max(b) {
        0 => 1.0,
        hi => a.min(b) as f32 / hi as f32,
    }
}

/// Sum of minimum counts over sum of maximum counts.
fn weighted_jaccard(a: &BTreeMap<String, u32>, b: &BTreeMap<String, u32>) -> Option<f32> {
    let (mut lo, mut hi) = (0u32, 0u32);
    for k in a.keys().chain(b.keys().filter(|k| !a.contains_key(*k))) {
        let (x, y) = (
            a.get(k).copied().unwrap_or(0),
            b.get(k).copied().unwrap_or(0),
        );
        lo += x.min(y);
        hi += x.max(y);
    }
    (hi > 0).then(|| lo as f32 / hi as f32)
}

struct Similarity {
    score: f32,
    parts: Vec<(&'static str, f32)>,
}

/// One side's view of a function for scoring: its neighbours, expressed in new-build addresses.
struct Side<'a> {
    f: &'a FunctionFeatures,
    callees: BTreeSet<Rva>,
    callers: BTreeSet<Rva>,
}

fn similarity(o: &Side<'_>, n: &Side<'_>) -> Option<Similarity> {
    let code = weighted_jaccard(&o.f.mnemonic_counts, &n.f.mnemonic_counts)?;
    let set = |v: &[String]| v.iter().cloned().collect::<BTreeSet<String>>();
    let consts = |v: &[u64]| v.iter().copied().collect::<BTreeSet<u64>>();
    let shape = match (o.f.basic_blocks, n.f.basic_blocks, o.f.edges, n.f.edges) {
        (Some(a), Some(b), Some(c), Some(d)) => Some((ratio(a, b) + ratio(c, d)) / 2.0),
        (Some(a), Some(b), _, _) => Some(ratio(a, b)),
        _ => None,
    };
    let values = [
        Some(code),
        shape,
        Some(ratio(o.f.size, n.f.size)),
        jaccard(&o.callees, &n.callees),
        jaccard(&o.callers, &n.callers),
        jaccard(&set(&o.f.strings), &set(&n.f.strings)),
        jaccard(&consts(&o.f.constants), &consts(&n.f.constants)),
        jaccard(&set(&o.f.imports), &set(&n.f.imports)),
    ];
    let parts: Vec<(&'static str, f32)> = SIM_WEIGHTS
        .iter()
        .zip(values)
        .filter_map(|(&(name, _), v)| Some((name, v?)))
        .collect();
    let (sum, weight) = parts.iter().fold((0.0, 0.0), |(s, w), &(name, v)| {
        let wt = SIM_WEIGHTS
            .iter()
            .find(|x| x.0 == name)
            .map_or(0.0, |x| x.1);
        (s + wt * v, w + wt)
    });
    Some(Similarity {
        score: sum / weight,
        parts,
    })
}

impl Matcher for SimilarityMatcher {
    fn name(&self) -> &'static str {
        "similarity"
    }

    fn weak(&self) -> bool {
        true
    }

    fn contradiction(&self, ctx: &MatchContext<'_>, c: &Candidate) -> Option<String> {
        callers_disagree(ctx, c).map(|r| format!("similar code, but {r}"))
    }

    fn propose(&self, ctx: &MatchContext<'_>) -> Proposals {
        let map: HashMap<Rva, Rva> = ctx.pairs.iter().map(|c| (c.old, c.new)).collect();
        let eligible =
            |f: &FunctionFeatures| f.size >= self.params.min_size && !f.mnemonic_counts.is_empty();
        let olds: Vec<&FunctionFeatures> = ctx
            .old
            .functions
            .iter()
            .filter(|f| !ctx.matched_old.contains(&f.rva) && eligible(f))
            .collect();
        let news: Vec<&FunctionFeatures> = ctx
            .new
            .functions
            .iter()
            .filter(|f| !ctx.matched_new.contains(&f.rva) && eligible(f))
            .collect();
        if olds.is_empty() || news.is_empty() {
            return Proposals::default();
        }
        let callers_of = |e: &AnalysisExport| {
            let mut out: HashMap<Rva, Vec<Rva>> = HashMap::new();
            for f in &e.functions {
                for &c in &f.callees {
                    if c != f.rva {
                        out.entry(c).or_default().push(f.rva);
                    }
                }
            }
            out
        };
        let (old_callers, new_callers) = (callers_of(ctx.old), callers_of(ctx.new));
        // Neighbours in new-build addresses: (callees, callers).
        let old_neighbours = |f: &FunctionFeatures| -> (BTreeSet<Rva>, BTreeSet<Rva>) {
            let callees = f
                .callees
                .iter()
                .filter_map(|c| map.get(c).copied())
                .collect();
            let callers = old_callers
                .get(&f.rva)
                .into_iter()
                .flatten()
                .filter_map(|c| map.get(c).copied())
                .collect();
            (callees, callers)
        };
        let new_neighbours = |f: &FunctionFeatures| -> (BTreeSet<Rva>, BTreeSet<Rva>) {
            let callees = f
                .callees
                .iter()
                .copied()
                .filter(|c| ctx.matched_new.contains(c))
                .collect();
            let callers = new_callers
                .get(&f.rva)
                .into_iter()
                .flatten()
                .copied()
                .filter(|c| ctx.matched_new.contains(c))
                .collect();
            (callees, callers)
        };
        let new_sides: HashMap<Rva, Side<'_>> = news
            .iter()
            .map(|&f| {
                let (callees, callers) = new_neighbours(f);
                (
                    f.rva,
                    Side {
                        f,
                        callees,
                        callers,
                    },
                )
            })
            .collect();

        // Anchor buckets over the unmatched new functions.
        let mut by_anchor: HashMap<String, Vec<Rva>> = HashMap::new();
        for (rva, s) in &new_sides {
            let mut anchors: BTreeSet<String> = BTreeSet::new();
            anchors.extend(s.callees.iter().map(|c| format!("callee:{c}")));
            anchors.extend(s.callers.iter().map(|c| format!("caller:{c}")));
            anchors.extend(s.f.strings.iter().map(|x| format!("string:{x}")));
            anchors.extend(s.f.constants.iter().map(|x| format!("constant:{x}")));
            anchors.extend(s.f.imports.iter().map(|x| format!("import:{x}")));
            for a in anchors {
                by_anchor.entry(a).or_default().push(*rva);
            }
        }

        // Score every anchored pair.
        let mut scored: Vec<(Rva, Rva, Similarity)> = Vec::new();
        for &f in &olds {
            let (callees, callers) = old_neighbours(f);
            let o = Side {
                f,
                callees,
                callers,
            };
            let mut anchors: BTreeSet<String> = BTreeSet::new();
            anchors.extend(o.callees.iter().map(|c| format!("callee:{c}")));
            anchors.extend(o.callers.iter().map(|c| format!("caller:{c}")));
            anchors.extend(f.strings.iter().map(|x| format!("string:{x}")));
            anchors.extend(f.constants.iter().map(|x| format!("constant:{x}")));
            anchors.extend(f.imports.iter().map(|x| format!("import:{x}")));
            let candidates: BTreeSet<Rva> = anchors
                .iter()
                .filter_map(|a| by_anchor.get(a))
                .filter(|b| b.len() <= SIM_MAX_BUCKET)
                .flatten()
                .copied()
                .collect();
            for n in candidates {
                if let Some(s) = similarity(&o, &new_sides[&n]) {
                    scored.push((f.rva, n, s));
                }
            }
        }

        // Best and runner-up per function on each side (ties broken by address, so they stay ties in margin).
        let rank = |key: &dyn Fn(&(Rva, Rva, Similarity)) -> Rva| {
            let mut out: BTreeMap<Rva, Vec<(f32, Rva)>> = BTreeMap::new();
            for t in &scored {
                let other = if key(t) == t.0 { t.1 } else { t.0 };
                out.entry(key(t)).or_default().push((t.2.score, other));
            }
            for v in out.values_mut() {
                v.sort_by(|a, b| b.0.total_cmp(&a.0).then(a.1.cmp(&b.1)));
            }
            out
        };
        let by_old = rank(&|t| t.0);
        let by_new = rank(&|t| t.1);
        let runner_up = |v: &[(f32, Rva)]| v.get(1).map_or(0.0, |x| x.0);

        let mut proposals = Proposals::default();
        for (&o, ranked) in &by_old {
            let (best, n) = ranked[0];
            if best < self.params.min_score {
                continue;
            }
            let theirs = &by_new[&n];
            let mutual = theirs[0].1 == o;
            let old_margin = best - runner_up(ranked);
            let new_margin = best - runner_up(theirs);
            // Body moved behind a new wrapper (zstd 1.5.6's ZSTD_findFrameCompressedSize, now a wrapper around
            // a new _advanced): an unmatched new function, smaller than this one, that calls it and otherwise
            // only already-matched functions, so the old one may correspond to either. At /Od a wrapper also
            // calls accessors (yaml-cpp 0.9.0's `Write(const std::string&)` calls `data()` and `size()`, then
            // the new `Write(const char*, size_t)` that took over its body).
            let n_size = ctx.new.function(n).map_or(0, |f| f.size);
            let wrapper = new_callers
                .get(&n)
                .into_iter()
                .flatten()
                .copied()
                .find(|&w| {
                    !ctx.matched_new.contains(&w)
                        && ctx.new.function(w).is_some_and(|f| {
                            f.size < n_size
                                && f.callees.contains(&n)
                                && f.callees
                                    .iter()
                                    .all(|c| *c == n || ctx.matched_new.contains(c))
                        })
                });
            // The old function's matched callers decide: if at least WRAPPER_MIN_DIRECT_CALLERS of their
            // counterparts call this function directly and none calls the wrapper, nothing moved behind it
            // (Lua's lua_tolstring: 34 of 34 matched callers still call it, and some unrelated new helper calls
            // it too). One caller isn't enough: zstd 1.5.6's BIT_reloadDStream was retargeted from the old
            // BIT_reloadDStreamFast to the new body while other callers went through the new wrapper.
            let callers_calling = |target: Rva| {
                old_callers
                    .get(&o)
                    .into_iter()
                    .flatten()
                    .filter_map(|c| map.get(c))
                    .filter(|nc| {
                        ctx.new
                            .function(**nc)
                            .is_some_and(|f| f.callees.contains(&target))
                    })
                    .count()
            };
            let wrapper = wrapper.filter(|&w| {
                callers_calling(n) < WRAPPER_MIN_DIRECT_CALLERS || callers_calling(w) > 0
            });
            // Inlined into its caller (/LTCG: TinyXML-2's TestUtil::Push, now inside VisitEnter): an unmatched
            // caller of the old function scores nearly as well for the new one, so either may be its counterpart.
            let absorbers: Vec<Rva> = old_callers
                .get(&o)
                .into_iter()
                .flatten()
                .copied()
                .filter(|p| {
                    !ctx.matched_old.contains(p)
                        && theirs
                            .iter()
                            .any(|(s, c)| c == p && *s >= best - INLINED_CALLER_MARGIN)
                })
                .collect();
            if let Some(w) = wrapper {
                proposals.ambiguities.push(Ambiguity {
                    matcher: self.name().to_owned(),
                    old: vec![o],
                    new: vec![w, n],
                    detail: format!(
                        "similar code (best {best:.2}), but a smaller unmatched new function calls it: the old code \
                         may have moved behind a new wrapper"
                    ),
                });
            } else if !absorbers.is_empty() {
                let mut old = vec![o];
                old.extend(&absorbers);
                proposals.ambiguities.push(Ambiguity {
                    matcher: self.name().to_owned(),
                    old,
                    new: vec![n],
                    detail: format!(
                        "similar code (best {best:.2}), but an unmatched caller of the old function scores nearly as \
                         well: the old code may have been inlined into it"
                    ),
                });
            } else if mutual
                && old_margin >= self.params.min_margin
                && new_margin >= self.params.min_margin
            {
                let s = &scored
                    .iter()
                    .find(|t| t.0 == o && t.1 == n)
                    .expect("ranked pairs come from `scored`")
                    .2;
                let parts: Vec<String> =
                    s.parts.iter().map(|(k, v)| format!("{k} {v:.2}")).collect();
                proposals.candidates.push(candidate(
                    self.name(),
                    o,
                    n,
                    best,
                    evidence_kind::SIMILARITY,
                    format!(
                        "similarity {best:.2} (runner-up {:.2} / {:.2}): {}",
                        runner_up(ranked),
                        runner_up(theirs),
                        parts.join(", ")
                    ),
                ));
            } else {
                let close: Vec<Rva> = ranked
                    .iter()
                    .filter(|x| x.0 >= best - self.params.min_margin)
                    .take(3)
                    .map(|x| x.1)
                    .collect();
                proposals.ambiguities.push(Ambiguity {
                    matcher: self.name().to_owned(),
                    old: vec![o],
                    detail: format!(
                        "similar code, best {best:.2}, but {}",
                        if mutual {
                            "not clearly ahead of the runner-up"
                        } else {
                            "the new function is closer to another old one"
                        }
                    ),
                    new: if close.contains(&n) { close } else { vec![n] },
                });
            }
        }
        proposals
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use permanent_beta_model::{
        ANALYSIS_SCHEMA_VERSION, BuildId, BuildInfo, CodeTable, Machine, Producer,
    };

    fn func(rva: u64, name: Option<&str>, hash: Option<&str>) -> FunctionFeatures {
        FunctionFeatures {
            rva: Rva(rva),
            size: 64,
            name: name.map(str::to_owned),
            name_source: None,
            normalized_hash: hash.map(str::to_owned),
            mnemonic_hash: None,
            inferred_args: None,
            inferred_arg_classes: vec![],
            entry: None,
            basic_blocks: None,
            mnemonic_counts: Default::default(),
            pseudocode: None,
            edges: None,
            callees: vec![],
            strings: vec![],
            constants: vec![],
            imports: vec![],
            data_refs: vec![],
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
            code_tables: Vec::new(),
            types: Vec::new(),
            globals: Vec::new(),
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

    // Similarity pass. `main` and `x` are matched by name; f is edited (different hash, similar code).

    fn body(rva: u64, hash: &str, adds: u32, callees: &[u64], size: u32) -> FunctionFeatures {
        let mut f = func(rva, None, Some(hash));
        f.size = size;
        f.basic_blocks = Some(3);
        f.edges = Some(3);
        f.callees = callees.iter().map(|&r| Rva(r)).collect();
        f.mnemonic_counts = [("Mov", 10), ("Add", adds), ("Ret", 1)]
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect();
        f
    }

    /// A function with a mnemonic sequence `mh` and normalized hash `nh`, `size` bytes, calling `callees`.
    fn mnem(rva: u64, mh: &str, nh: &str, size: u32, callees: &[u64]) -> FunctionFeatures {
        let mut f = func(rva, None, Some(nh));
        f.mnemonic_hash = Some(mh.into());
        f.size = size;
        f.callees = callees.iter().map(|&r| Rva(r)).collect();
        f
    }

    fn mnemonic_only() -> Vec<Box<dyn Matcher>> {
        vec![
            Box::new(SymbolNameMatcher),
            Box::new(NormalizedHashMatcher),
            Box::new(MnemonicHashMatcher),
        ]
    }

    fn by(outcome: &MatchOutcome, matcher: &str) -> Vec<(u64, u64)> {
        let mut v: Vec<_> = outcome
            .candidates
            .iter()
            .filter(|c| matches!(&c.source, CandidateSource::Deterministic { matcher: m } if m == matcher))
            .map(|c| (c.old.0, c.new.0))
            .collect();
        v.sort();
        v
    }

    /// old: main -> f(0x10) -> leaf(0x40). new: main -> f'(0x110) -> leaf'(0x140). f and f' have the same
    /// instruction sequence but different operands (different normalized hashes); main matches by name and
    /// leaf by hash.
    fn edited_operands(size: u32) -> (AnalysisExport, AnalysisExport) {
        (
            export(
                "a",
                vec![
                    named_calling(0x1, "main", &[0x10]),
                    mnem(0x10, "m-f", "old-f", size, &[0x40]),
                    mnem(0x40, "m-leaf", "leaf", 48, &[]),
                ],
            ),
            export(
                "b",
                vec![
                    named_calling(0x101, "main", &[0x110]),
                    mnem(0x110, "m-f", "new-f", size, &[0x140]),
                    mnem(0x140, "m-leaf", "leaf", 48, &[]),
                ],
            ),
        )
    }

    #[test]
    fn an_operand_edit_is_matched_by_instruction_sequence_with_an_anchor() {
        let (old, new) = edited_operands(64);
        let out = run_passes(&old, &new, &mnemonic_only());
        assert_eq!(by(&out, "mnemonic-hash"), vec![(0x10, 0x110)]);
        let c = out.candidates.iter().find(|c| c.old == Rva(0x10)).unwrap();
        let kinds: Vec<&str> = c.evidence.iter().map(|e| e.kind.as_str()).collect();
        assert_eq!(
            kinds,
            vec![evidence_kind::MNEMONIC_HASH, evidence_kind::CALLEES]
        );
    }

    #[test]
    fn a_short_function_is_not_matched_by_instruction_sequence() {
        let (old, new) = edited_operands(MNEMONIC_MIN_SIZE - 1);
        let out = run_passes(&old, &new, &mnemonic_only());
        assert!(by(&out, "mnemonic-hash").is_empty());
    }

    #[test]
    fn without_an_agreeing_neighbour_it_is_only_a_suggestion() {
        // Same sequence, both big enough, but nothing around them is matched.
        let old = export("a", vec![mnem(0x10, "m-f", "old-f", 64, &[0x40])]);
        let new = export("b", vec![mnem(0x110, "m-f", "new-f", 64, &[0x140])]);
        let out = run_passes(&old, &new, &mnemonic_only());
        assert!(out.candidates.is_empty());
        assert!(
            out.ambiguities
                .iter()
                .any(|a| a.matcher == "mnemonic-hash" && a.detail.contains("no matched neighbour")),
            "{:?}",
            out.ambiguities
        );
    }

    #[test]
    fn a_shared_instruction_sequence_is_ambiguous() {
        let (old, mut new) = edited_operands(64);
        new.functions
            .push(mnem(0x180, "m-f", "other", 64, &[0x140]));
        let out = run_passes(&old, &new, &mnemonic_only());
        assert!(by(&out, "mnemonic-hash").is_empty());
        assert!(
            out.ambiguities
                .iter()
                .any(|a| a.matcher == "mnemonic-hash" && a.new == vec![Rva(0x110), Rva(0x180)])
        );
    }

    #[test]
    fn a_different_argument_count_or_disagreeing_caller_vetoes() {
        let (mut old, new) = edited_operands(64);
        let mut with_args = new.clone();
        old.functions[1].inferred_args = Some(2);
        with_args.functions[1].inferred_args = Some(3);
        let out = run_passes(&old, &with_args, &mnemonic_only());
        assert!(by(&out, "mnemonic-hash").is_empty());

        // The callee agrees, but new main no longer calls f': its matched caller disagrees.
        let (old, mut moved) = edited_operands(64);
        moved.functions[0].callees = vec![Rva(0x140)];
        let out = run_passes(&old, &moved, &mnemonic_only());
        assert!(by(&out, "mnemonic-hash").is_empty(), "{:?}", out.candidates);
    }

    fn named_calling(rva: u64, name: &str, callees: &[u64]) -> FunctionFeatures {
        let mut f = func(rva, Some(name), None);
        f.callees = callees.iter().map(|&r| Rva(r)).collect();
        f
    }

    /// old: main → f(0x10) → x. new: main → `main_callees`, plus `rest`.
    fn edited(
        main_callees: &[u64],
        rest: Vec<FunctionFeatures>,
    ) -> (AnalysisExport, AnalysisExport) {
        let old = export(
            "a",
            vec![
                named_calling(1, "main", &[0x10]),
                named_calling(0x50, "x", &[]),
                body(0x10, "h1", 5, &[0x50], 64),
            ],
        );
        let mut new_fns = vec![
            named_calling(2, "main", main_callees),
            named_calling(0x150, "x", &[]),
        ];
        new_fns.extend(rest);
        (old, export("b", new_fns))
    }

    #[test]
    fn an_edited_function_is_matched_by_similarity() {
        let (old, new) = edited(&[0x110], vec![body(0x110, "h2", 6, &[0x150], 66)]);
        assert!(pairs(&old, &new).contains(&(0x10, 0x110)));
        assert_eq!(matcher_of(&old, &new, 0x10).as_deref(), Some("similarity"));
    }

    #[test]
    fn two_equally_similar_candidates_give_no_candidate() {
        // Two near-identical edited copies, both called by main: no margin, so review gets both.
        let (old, new) = edited(
            &[0x110, 0x120],
            vec![
                body(0x110, "h2", 6, &[0x150], 66),
                body(0x120, "h3", 6, &[0x150], 66),
            ],
        );
        let got = run_passes(&old, &new, &default_matchers());
        assert!(!got.candidates.iter().any(|c| c.old == Rva(0x10)));
        assert!(
            got.competitors(Rva(0x10)).contains(&Rva(0x110))
                && got.competitors(Rva(0x10)).contains(&Rva(0x120)),
            "{:?}",
            got.ambiguities
        );
    }

    #[test]
    fn similar_code_with_nothing_in_common_is_not_a_candidate() {
        // Same shape, but no shared matched callee, caller, string, constant or import: no anchor.
        let old = export("a", vec![body(0x10, "h1", 5, &[], 64)]);
        let new = export("b", vec![body(0x110, "h2", 6, &[], 66)]);
        assert!(pairs(&old, &new).is_empty());
    }

    #[test]
    fn tiny_functions_are_left_alone() {
        let old = export(
            "a",
            vec![
                named_calling(1, "main", &[0x10]),
                named_calling(0x50, "x", &[]),
                body(0x10, "h1", 5, &[0x50], 8),
            ],
        );
        let new = export(
            "b",
            vec![
                named_calling(2, "main", &[0x110]),
                named_calling(0x150, "x", &[]),
                body(0x110, "h2", 6, &[0x150], 9),
            ],
        );
        assert!(!pairs(&old, &new).iter().any(|&(o, _)| o == 0x10));
    }

    #[test]
    fn a_body_behind_a_new_wrapper_is_an_ambiguity() {
        // zstd 1.5.6: main now calls a new wrapper w, and the edited body sits behind it.
        let (old, new) = edited(
            &[0x130],
            vec![
                body(0x130, "hw", 0, &[0x110], 8),
                body(0x110, "h2", 6, &[0x150], 66),
            ],
        );
        let got = run_passes(&old, &new, &default_matchers());
        assert!(
            !got.candidates.iter().any(|c| c.old == Rva(0x10)),
            "{:?}",
            got.candidates
        );
        assert!(
            got.ambiguities
                .iter()
                .any(|a| a.old == vec![Rva(0x10)] && a.new == vec![Rva(0x130), Rva(0x110)]),
            "{:?}",
            got.ambiguities
        );
    }

    /// Proposes fixed pairs; `after` makes it wait until that old function is matched.
    struct Fixed {
        name: &'static str,
        weak: bool,
        pair: (u64, u64),
        after: Option<u64>,
    }

    impl Matcher for Fixed {
        fn name(&self) -> &'static str {
            self.name
        }
        fn weak(&self) -> bool {
            self.weak
        }
        fn propose(&self, ctx: &MatchContext<'_>) -> Proposals {
            if self
                .after
                .is_some_and(|a| !ctx.matched_old.contains(&Rva(a)))
            {
                return Proposals::default();
            }
            Proposals {
                candidates: vec![candidate(
                    self.name,
                    Rva(self.pair.0),
                    Rva(self.pair.1),
                    0.5,
                    "test",
                    String::new(),
                )],
                ambiguities: vec![],
            }
        }
    }

    #[test]
    fn a_weak_pass_waits_for_the_strong_passes_to_finish() {
        // Listed first, the weak pass would claim 1 → 100 at once. Strong pass A only finds 1 → 200 after
        // strong pass B has matched 2, in the second iteration; it must still win.
        let matchers: Vec<Box<dyn Matcher>> = vec![
            Box::new(Fixed {
                name: "weak",
                weak: true,
                pair: (1, 100),
                after: None,
            }),
            Box::new(Fixed {
                name: "a",
                weak: false,
                pair: (1, 200),
                after: Some(2),
            }),
            Box::new(Fixed {
                name: "b",
                weak: false,
                pair: (2, 300),
                after: None,
            }),
        ];
        let empty = export("x", vec![]);
        let got: Vec<(u64, u64)> = run_passes(&empty, &empty, &matchers)
            .candidates
            .iter()
            .map(|c| (c.old.0, c.new.0))
            .collect();
        assert_eq!(got, vec![(2, 300), (1, 200)]);
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

    fn table(rva: u64, slots: &[u64]) -> CodeTable {
        CodeTable {
            rva: Rva(rva),
            slots: slots.iter().map(|&s| Rva(s)).collect(),
        }
    }

    fn with_tables(mut e: AnalysisExport, tables: Vec<CodeTable>) -> AnalysisExport {
        e.code_tables = tables;
        e
    }

    fn pairs_by(got: &MatchOutcome, matcher: &str) -> Vec<(u64, u64)> {
        got.candidates
            .iter()
            .filter(|c| matches!(&c.source, CandidateSource::Deterministic { matcher: m } if m == matcher))
            .map(|c| (c.old.0, c.new.0))
            .collect()
    }

    /// Two classes' vtables: [Accept, ToText]. Each Accept is unique code; both ToText are `return null`
    /// (hash `ret0`), so the hash pass can't tell them apart.
    fn two_vtables(new_second_to_text: &str) -> (AnalysisExport, AnalysisExport) {
        let old = with_tables(
            export(
                "a",
                vec![
                    func(0x10, None, Some("acceptA")),
                    func(0x20, None, Some("ret0")),
                    func(0x30, None, Some("acceptB")),
                    func(0x40, None, Some("ret0")),
                ],
            ),
            vec![table(0x5000, &[0x10, 0x20]), table(0x5100, &[0x30, 0x40])],
        );
        let new = with_tables(
            export(
                "b",
                vec![
                    func(0x110, None, Some("acceptA")),
                    func(0x120, None, Some("ret0")),
                    func(0x130, None, Some("acceptB")),
                    func(0x140, None, Some(new_second_to_text)),
                ],
            ),
            vec![
                table(0x6000, &[0x110, 0x120]),
                table(0x6100, &[0x130, 0x140]),
            ],
        );
        (old, new)
    }

    #[test]
    fn identical_virtuals_are_told_apart_by_their_vtable_slot() {
        let (old, new) = two_vtables("ret0");
        let got = run_passes(&old, &new, &default_matchers());
        assert_eq!(
            pairs_by(&got, "table-slot"),
            vec![(0x20, 0x120), (0x40, 0x140)]
        );
        let c = got.candidates.iter().find(|c| c.old == Rva(0x20)).unwrap();
        assert_eq!(c.evidence[0].kind, evidence_kind::TABLE_SLOT);
        assert_eq!(c.evidence[1].kind, evidence_kind::NORMALIZED_HASH);
    }

    #[test]
    fn a_virtual_replaced_in_the_same_slot_is_only_a_suggestion() {
        // Negative: the second class's ToText became other code. Same table length, same slot, but it must not
        // be matched. (The first ToText still has an identical copy in the old build, so its slot resolves it.)
        let (old, new) = two_vtables("other");
        let got = run_passes(&old, &new, &default_matchers());
        assert_eq!(pairs_by(&got, "table-slot"), vec![(0x20, 0x120)]);
        assert!(!got.candidates.iter().any(|c| c.old == Rva(0x40)));
        let a = got
            .ambiguities
            .iter()
            .find(|a| a.matcher == "table-slot")
            .expect("a review suggestion");
        assert_eq!(
            (a.old.clone(), a.new.clone()),
            (vec![Rva(0x40)], vec![Rva(0x140)])
        );
        assert!(a.detail.contains("code differs"), "{}", a.detail);
    }

    #[test]
    fn a_table_that_could_be_either_of_two_gives_no_candidate() {
        // Negative: two old tables share their only anchor (an inherited Accept) and could both be the one new
        // table, so neither corresponds.
        let old = with_tables(
            export(
                "a",
                vec![
                    func(0x10, None, Some("accept")),
                    func(0x20, None, Some("ret0")),
                    func(0x40, None, Some("ret0")),
                ],
            ),
            vec![table(0x5000, &[0x10, 0x20]), table(0x5100, &[0x10, 0x40])],
        );
        let new = with_tables(
            export(
                "b",
                vec![
                    func(0x110, None, Some("accept")),
                    func(0x120, None, Some("ret0")),
                    func(0x150, None, Some("ret0")),
                ],
            ),
            vec![table(0x6000, &[0x110, 0x120])],
        );
        let got = run_passes(&old, &new, &default_matchers());
        assert_eq!(pairs_by(&got, "normalized-hash"), vec![(0x10, 0x110)]);
        assert!(pairs_by(&got, "table-slot").is_empty());
    }

    #[test]
    fn a_contradicting_slot_means_the_tables_do_not_correspond() {
        // Negative: slot 1 holds functions matched to other partners (by name), so slot 2's pairing is not
        // trusted even though slot 0 agrees.
        let old = with_tables(
            export(
                "a",
                vec![
                    func(0x10, None, Some("accept")),
                    func(0x50, Some("g"), None),
                    func(0x20, None, Some("ret0")),
                    func(0x40, None, Some("ret0")),
                ],
            ),
            vec![table(0x5000, &[0x10, 0x50, 0x20])],
        );
        let new = with_tables(
            export(
                "b",
                vec![
                    func(0x110, None, Some("accept")),
                    func(0x160, Some("h"), None),
                    func(0x170, Some("g"), None),
                    func(0x120, None, Some("ret0")),
                    func(0x140, None, Some("ret0")),
                ],
            ),
            vec![table(0x6000, &[0x110, 0x160, 0x120])],
        );
        let got = run_passes(&old, &new, &default_matchers());
        assert!(
            got.candidates
                .iter()
                .any(|c| (c.old.0, c.new.0) == (0x50, 0x170))
        );
        assert!(pairs_by(&got, "table-slot").is_empty());
    }

    #[test]
    fn tables_of_different_lengths_do_not_correspond() {
        // Negative: a virtual added to the class shifts or extends its vtable.
        let (old, mut new) = two_vtables("ret0");
        new.code_tables[1].slots.push(Rva(0x130));
        let got = run_passes(&old, &new, &default_matchers());
        assert_eq!(pairs_by(&got, "table-slot"), vec![(0x20, 0x120)]);
    }

    #[test]
    fn a_table_slot_pair_is_vetoed_when_its_tables_stop_corresponding() {
        let old = with_tables(
            export("a", vec![]),
            vec![table(0x5000, &[0x10, 0x50, 0x20])],
        );
        let new = with_tables(
            export("b", vec![]),
            vec![table(0x6000, &[0x110, 0x160, 0x120])],
        );
        let pair = |o: u64, n: u64| candidate("test", Rva(o), Rva(n), 1.0, "test", String::new());
        let slot_pair = pair(0x20, 0x120);
        let recheck = |pairs: &[Candidate]| {
            let matched_old: HashSet<Rva> = pairs.iter().map(|c| c.old).collect();
            let matched_new: HashSet<Rva> = pairs.iter().map(|c| c.new).collect();
            let ctx = MatchContext {
                old: &old,
                new: &new,
                matched_old: &matched_old,
                matched_new: &matched_new,
                pairs,
            };
            TableSlotMatcher.contradiction(&ctx, &slot_pair)
        };
        // Slot 0 agrees, slot 1 unmatched: the tables still correspond.
        assert_eq!(recheck(&[pair(0x10, 0x110), slot_pair.clone()]), None);
        // A later match puts slot 1's old function elsewhere: no longer corresponding, so vetoed.
        assert!(recheck(&[pair(0x10, 0x110), pair(0x50, 0x170), slot_pair.clone()]).is_some());
        // The pair itself is no anchor: without slot 0 there is nothing left to support it.
        assert!(recheck(std::slice::from_ref(&slot_pair)).is_some());
    }

    #[test]
    fn a_wrapper_that_also_calls_matched_accessors_is_still_a_wrapper() {
        // yaml-cpp 0.9.0 at /Od: the new Write(const std::string&) calls data() and size() (matched) and then the
        // new Write(const char*, size_t) that took over the body. The old body must not be matched to either.
        let old = export(
            "a",
            vec![
                named_calling(1, "main", &[0x10]),
                named_calling(0x50, "x", &[]),
                named_calling(0x60, "data", &[]),
                body(0x10, "h1", 5, &[0x50], 64),
            ],
        );
        let new = export(
            "b",
            vec![
                named_calling(2, "main", &[0x130]),
                named_calling(0x150, "x", &[]),
                named_calling(0x160, "data", &[]),
                body(0x130, "hw", 0, &[0x160, 0x110], 12),
                body(0x110, "h2", 6, &[0x150], 66),
            ],
        );
        let got = run_passes(&old, &new, &default_matchers());
        assert!(
            !got.candidates.iter().any(|c| c.old == Rva(0x10)),
            "{:?}",
            got.candidates
        );
        assert!(
            got.ambiguities
                .iter()
                .any(|a| a.old == vec![Rva(0x10)] && a.new == vec![Rva(0x130), Rva(0x110)]),
            "{:?}",
            got.ambiguities
        );
    }

    /// old: c → helper 0x20 (code `it`). new: helper 0x120 with the same code, called by `d`; `c` calls the
    /// helper only if `still_called`.
    fn moved_helper(still_called: bool) -> (AnalysisExport, AnalysisExport) {
        let old = export(
            "a",
            vec![
                named_calling(0x10, "c", &[0x20]),
                func(0x20, None, Some("it")),
            ],
        );
        let c_callees: &[u64] = if still_called { &[0x120] } else { &[] };
        let new = export(
            "b",
            vec![
                named_calling(0x110, "c", c_callees),
                named_calling(0x130, "d", &[0x120]),
                func(0x120, None, Some("it")),
            ],
        );
        (old, new)
    }

    #[test]
    fn identical_code_its_matched_caller_no_longer_calls_is_not_matched() {
        // Negative (yaml-cpp 0.9.0): a std::string iterator helper is gone; a std::array one with the same code
        // appeared elsewhere. Each is the only copy in its build, but the old helper's matched caller doesn't
        // call the new one.
        let (old, new) = moved_helper(false);
        let got = run_passes(&old, &new, &default_matchers());
        assert!(
            !got.candidates.iter().any(|c| c.old == Rva(0x20)),
            "{:?}",
            got.candidates
        );
        assert!(
            got.ambiguities
                .iter()
                .any(|a| a.matcher == "normalized-hash" && a.detail.contains("matched caller")),
            "{:?}",
            got.ambiguities
        );
        // Control: still called by its matched caller, so matched.
        let (old, new) = moved_helper(true);
        assert!(pairs(&old, &new).contains(&(0x20, 0x120)));
    }

    /// Two copies of the same code on each side; the first pair is matched by name. The second copies call `x`
    /// only if `anchored`.
    fn copies(anchored: bool) -> (AnalysisExport, AnalysisExport) {
        let callees: &[u64] = if anchored { &[0x50] } else { &[] };
        let new_callees: &[u64] = if anchored { &[0x150] } else { &[] };
        let mut a = func(0x20, Some("a"), Some("dup"));
        a.callees = callees.iter().map(|&r| Rva(r)).collect();
        let mut b = func(0x30, None, Some("dup"));
        b.callees = callees.iter().map(|&r| Rva(r)).collect();
        let old = export("a", vec![named_calling(0x50, "x", &[]), a, b]);
        let mut a2 = func(0x120, Some("a"), Some("dup"));
        a2.callees = new_callees.iter().map(|&r| Rva(r)).collect();
        let mut b2 = func(0x130, None, Some("dup"));
        b2.callees = new_callees.iter().map(|&r| Rva(r)).collect();
        let new = export("b", vec![named_calling(0x150, "x", &[]), a2, b2]);
        (old, new)
    }

    #[test]
    fn the_last_copies_left_are_not_paired_by_elimination_alone() {
        // Negative (yaml-cpp 0.9.0, an 11-byte helper with 66 copies per build): once the other copies are
        // matched, the last two left are unique only among the unmatched. Without a matched neighbour that
        // agrees, that's a review suggestion.
        let (old, new) = copies(false);
        let got = run_passes(&old, &new, &default_matchers());
        assert!(
            !got.candidates.iter().any(|c| c.old == Rva(0x30)),
            "{:?}",
            got.candidates
        );
        assert!(
            got.ambiguities
                .iter()
                .any(|a| a.old == vec![Rva(0x30)] && a.detail.contains("copies")),
            "{:?}",
            got.ambiguities
        );
        // Control: both call matched x, so the pair is anchored.
        let (old, new) = copies(true);
        assert!(pairs(&old, &new).contains(&(0x30, 0x130)));
    }

    /// old: callers c1, c2 → f(0x10) → x. new: the edited f at 0x110, called by c1 and c2 if `direct` callers
    /// (else c1 only), plus a small new helper w(0x130) that also calls it.
    fn edited_with_helper(direct: usize) -> (AnalysisExport, AnalysisExport) {
        let old = export(
            "a",
            vec![
                named_calling(1, "c1", &[0x10]),
                named_calling(3, "c2", &[0x10]),
                named_calling(0x50, "x", &[]),
                body(0x10, "h1", 5, &[0x50], 64),
            ],
        );
        let c2_new: &[u64] = if direct >= 2 { &[0x110] } else { &[] };
        let new = export(
            "b",
            vec![
                named_calling(2, "c1", &[0x110]),
                named_calling(4, "c2", c2_new),
                named_calling(0x150, "x", &[]),
                body(0x130, "hw", 0, &[0x110], 12),
                body(0x110, "h2", 6, &[0x150], 66),
            ],
        );
        (old, new)
    }

    #[test]
    fn callers_still_calling_a_function_directly_overrule_the_wrapper_rule() {
        // Lua's lua_tolstring: matched callers still call the edited function, so the small new helper that
        // also calls it is not a wrapper it moved behind.
        let (old, new) = edited_with_helper(2);
        assert!(pairs(&old, &new).contains(&(0x10, 0x110)));
    }

    #[test]
    fn one_direct_caller_does_not_overrule_the_wrapper_rule() {
        // Negative (zstd 1.5.6's BIT_reloadDStreamFast): one matched caller was retargeted to the new body while
        // the rest went through the new wrapper. One caller isn't enough to rule the wrapper out.
        let (old, new) = edited_with_helper(1);
        let got = run_passes(&old, &new, &default_matchers());
        assert!(
            !got.candidates.iter().any(|c| c.old == Rva(0x10)),
            "{:?}",
            got.candidates
        );
        assert!(
            got.ambiguities
                .iter()
                .any(|a| a.old == vec![Rva(0x10)] && a.new == vec![Rva(0x130), Rva(0x110)]),
            "{:?}",
            got.ambiguities
        );
    }

    #[test]
    fn a_function_inlined_into_its_caller_is_an_ambiguity() {
        // Negative (TinyXML-2 /LTCG: TestUtil::Push inlined into VisitEnter): the old callee f and its old caller
        // g both look like the new g, which now holds f's code. Neither is a candidate.
        // g is a virtual (no direct callers). f is the closest to the new g; the old g is close behind.
        let old = export(
            "a",
            vec![
                named_calling(0x50, "x", &[]),
                body(0x20, "hg", 4, &[0x10, 0x50], 76),
                body(0x10, "h1", 6, &[0x50], 66),
            ],
        );
        let new = export(
            "b",
            vec![
                named_calling(0x150, "x", &[]),
                body(0x120, "h2", 6, &[0x150], 68),
            ],
        );
        let got = run_passes(&old, &new, &default_matchers());
        assert!(
            !got.candidates.iter().any(|c| c.new == Rva(0x120)),
            "{:?}",
            got.candidates
        );
        assert!(
            got.ambiguities
                .iter()
                .any(|a| a.new == vec![Rva(0x120)] && a.detail.contains("inlined")),
            "{:?}",
            got.ambiguities
        );
    }
}
