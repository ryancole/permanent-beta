//! Which new-build functions to show the model for one unmatched old function.
//!
//! A model can only pick among the candidates it's shown, and sending every unmatched function would be large
//! and expensive (design §8: minimal context). So each unmatched new function is scored cheaply against the old
//! one, and the best few go in the prompt. The score only orders the shortlist; it decides nothing.

use permanent_beta_model::{AnalysisExport, Candidate, FunctionFeatures, Rva};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

/// Default shortlist length. [Guess]
pub const SHORTLIST_LEN: usize = 5;

/// The match so far, seen from both builds: which functions are claimed, and the old → new mapping.
pub struct Matched {
    pub map: HashMap<Rva, Rva>,
    pub claimed_new: HashSet<Rva>,
    old_callers: HashMap<Rva, Vec<Rva>>,
    new_callers: HashMap<Rva, Vec<Rva>>,
}

impl Matched {
    pub fn new(old: &AnalysisExport, new: &AnalysisExport, pairs: &[Candidate]) -> Self {
        Self {
            map: pairs.iter().map(|c| (c.old, c.new)).collect(),
            claimed_new: pairs.iter().map(|c| c.new).collect(),
            old_callers: callers(old),
            new_callers: callers(new),
        }
    }

    /// The old function's neighbours in new-build addresses (matched ones only): (callees, callers).
    pub fn old_neighbours(&self, f: &FunctionFeatures) -> (BTreeSet<Rva>, BTreeSet<Rva>) {
        let callees = f
            .callees
            .iter()
            .filter_map(|c| self.map.get(c).copied())
            .collect();
        let callers = self
            .old_callers
            .get(&f.rva)
            .into_iter()
            .flatten()
            .filter_map(|c| self.map.get(c).copied())
            .collect();
        (callees, callers)
    }

    /// A new function's matched neighbours: (callees, callers).
    pub fn new_neighbours(&self, f: &FunctionFeatures) -> (BTreeSet<Rva>, BTreeSet<Rva>) {
        let matched = |r: &Rva| self.claimed_new.contains(r);
        let callees = f.callees.iter().copied().filter(matched).collect();
        let callers = self
            .new_callers
            .get(&f.rva)
            .into_iter()
            .flatten()
            .copied()
            .filter(matched)
            .collect();
        (callees, callers)
    }

    pub fn old_callers_of(&self, f: Rva) -> &[Rva] {
        self.old_callers.get(&f).map(Vec::as_slice).unwrap_or(&[])
    }

    pub fn new_callers_of(&self, f: Rva) -> &[Rva] {
        self.new_callers.get(&f).map(Vec::as_slice).unwrap_or(&[])
    }
}

fn callers(e: &AnalysisExport) -> HashMap<Rva, Vec<Rva>> {
    let mut out: HashMap<Rva, Vec<Rva>> = HashMap::new();
    for f in &e.functions {
        for &c in &f.callees {
            if c != f.rva {
                out.entry(c).or_default().push(f.rva);
            }
        }
    }
    out
}

fn jaccard<T: Ord + Clone>(a: &[T], b: &[T]) -> Option<f32> {
    let (a, b): (BTreeSet<T>, BTreeSet<T>) =
        (a.iter().cloned().collect(), b.iter().cloned().collect());
    let union = a.union(&b).count();
    (union > 0).then(|| a.intersection(&b).count() as f32 / union as f32)
}

fn set_jaccard(a: &BTreeSet<Rva>, b: &BTreeSet<Rva>) -> Option<f32> {
    let union = a.union(b).count();
    (union > 0).then(|| a.intersection(b).count() as f32 / union as f32)
}

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

/// Cheap closeness of an old and a new function, in [0, 1]. Missing features don't count either way.
pub fn closeness(m: &Matched, o: &FunctionFeatures, n: &FunctionFeatures) -> f32 {
    let (oc, ocl) = m.old_neighbours(o);
    let (nc, ncl) = m.new_neighbours(n);
    let size = match o.size.max(n.size) {
        0 => None,
        hi => Some(o.size.min(n.size) as f32 / hi as f32),
    };
    let parts = [
        (
            3.0,
            weighted_jaccard(&o.mnemonic_counts, &n.mnemonic_counts),
        ),
        (2.0, set_jaccard(&oc, &nc)),
        (2.0, set_jaccard(&ocl, &ncl)),
        (2.0, jaccard(&o.strings, &n.strings)),
        (1.0, jaccard(&o.constants, &n.constants)),
        (1.0, jaccard(&o.imports, &n.imports)),
        (1.0, size),
    ];
    let (sum, weight) = parts
        .iter()
        .filter_map(|(w, v)| Some((w * (*v)?, *w)))
        .fold((0.0, 0.0), |(s, t), (x, w)| (s + x, t + w));
    if weight == 0.0 { 0.0 } else { sum / weight }
}

/// The `len` unmatched new functions closest to `old_fn`, best first (ties by address).
pub fn shortlist<'a>(
    m: &Matched,
    new: &'a AnalysisExport,
    old_fn: &FunctionFeatures,
    len: usize,
) -> Vec<&'a FunctionFeatures> {
    let mut scored: Vec<(f32, &FunctionFeatures)> = new
        .functions
        .iter()
        .filter(|f| !m.claimed_new.contains(&f.rva))
        .map(|f| (closeness(m, old_fn, f), f))
        .filter(|(s, _)| *s > 0.0)
        .collect();
    scored.sort_by(|a, b| b.0.total_cmp(&a.0).then(a.1.rva.cmp(&b.1.rva)));
    scored.into_iter().take(len).map(|(_, f)| f).collect()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use permanent_beta_model::CandidateSource;

    pub(crate) fn export(id: &str, functions: Vec<FunctionFeatures>) -> AnalysisExport {
        serde_json::from_value(serde_json::json!({
            "schema_version": permanent_beta_model::ANALYSIS_SCHEMA_VERSION,
            "build": { "id": id, "file_name": "t.exe", "version": null, "machine": "x64", "pdb": null },
            "producer": { "tool": "test", "version": "0" },
            "functions": functions,
        }))
        .unwrap()
    }

    pub(crate) fn func(rva: u64, size: u32, strings: &[&str], callees: &[u64]) -> FunctionFeatures {
        serde_json::from_value(serde_json::json!({
            "rva": rva, "size": size, "name": null, "name_source": null,
            "normalized_hash": null, "mnemonic_hash": null, "basic_blocks": null, "edges": null,
            "callees": callees.iter().map(|c| format!("{c:#x}")).collect::<Vec<_>>(),
            "strings": strings, "constants": [], "imports": [], "signature": null,
        }))
        .unwrap()
    }

    pub(crate) fn pair(old: u64, new: u64) -> Candidate {
        Candidate {
            old: Rva(old),
            new: Rva(new),
            source: CandidateSource::Deterministic {
                matcher: "t".into(),
            },
            score: 1.0,
            evidence: vec![],
        }
    }

    #[test]
    fn closest_unmatched_functions_come_first_and_matched_ones_never() {
        // old 0x10 calls matched 0x40 (-> 0x140) and uses "save". New: 0x110 shares both, 0x120 only the
        // string, 0x130 nothing, 0x140 is already matched.
        let old = export(
            "a",
            vec![func(0x10, 64, &["save"], &[0x40]), func(0x40, 32, &[], &[])],
        );
        let new = export(
            "b",
            vec![
                func(0x110, 64, &["save"], &[0x140]),
                func(0x120, 64, &["save"], &[]),
                func(0x130, 2000, &["other"], &[]),
                func(0x140, 32, &[], &[]),
            ],
        );
        let m = Matched::new(&old, &new, &[pair(0x40, 0x140)]);
        let list: Vec<u64> = shortlist(&m, &new, &old.functions[0], 5)
            .iter()
            .map(|f| f.rva.0)
            .collect();
        assert_eq!(list[..2], [0x110, 0x120]);
        assert!(
            !list.contains(&0x140),
            "a matched function is never offered"
        );
        assert_eq!(shortlist(&m, &new, &old.functions[0], 1).len(), 1);
    }
}
