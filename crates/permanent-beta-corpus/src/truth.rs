//! Ground truth: the true old → new mapping for one build pair, joined by symbol name.
//!
//! Functions are grouped by address on each side, because `/OPT:ICF` can fold several names into one
//! function. One entry per distinct (old address, new address) pair:
//! - `old` and `new` set: the function exists in both builds.
//! - only `old`: deleted in the new build. Only `new`: added.
//! - several entries sharing an `old` or `new`: folding differs between builds (many-to-one).
//!
//! Join, in two stages:
//! 1. by (name, object file), since two objects may each have a static of the same name;
//! 2. leftovers by name alone, when the name is unique among the leftovers on both sides. This catches a
//!    function whose linkage changed (zlib 1.3.1 made minigzip's helpers `static`) or that moved to another
//!    object file. Without it, both look like deleted + added, and correct matches get scored as wrong.
//! 3. declared renames (old name → new name), checked by hand against the sources and listed in the project's
//!    recipe. Lua 5.4.7 renamed `luaK_exp2RK` to a static `exp2RK`: without the declaration, matching the two
//!    is scored as wrong. A declaration whose old name still exists in the new build is an error, so the list
//!    can't go stale.

use crate::map::{MapFile, MapSymbol};
use permanent_beta_model::Rva;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

pub const TRUTH_SCHEMA_VERSION: u32 = 1;

/// (old address, new address); either side is `None` when the function exists in only one build.
type AddressPair = (Option<Rva>, Option<Rva>);

/// Which functions are in scope for scoring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    /// Functions defined in one object file, e.g. `fixture.obj`.
    Object(String),
    /// Functions in every object file linked directly (the project's own code), excluding library members
    /// such as `MSVCRT:exe_main.obj` and import stubs.
    ProjectObjects,
}

impl Scope {
    fn includes(&self, s: &MapSymbol) -> bool {
        s.is_function
            && match self {
                Scope::Object(o) => &s.object == o,
                Scope::ProjectObjects => s.object.ends_with(".obj") && !s.object.contains(':'),
            }
    }

    fn describe(&self) -> String {
        match self {
            Scope::Object(o) => o.clone(),
            Scope::ProjectObjects => "*.obj (project objects)".into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroundTruth {
    pub schema_version: u32,
    /// Which object files' functions are in scope (CRT and library functions are excluded).
    pub object: String,
    pub functions: Vec<TruthEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TruthEntry {
    /// Every symbol name at this address pair, sorted. More than one means the linker folded them.
    pub names: Vec<String>,
    pub old: Option<Rva>,
    pub new: Option<Rva>,
    /// Internal linkage (listed under `Static symbols`) in either build.
    #[serde(rename = "static")]
    pub is_static: bool,
    /// The new build's name, when it differs from `names` because of a declared rename.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renamed_to: Option<String>,
}

impl GroundTruth {
    pub fn from_maps(old: &MapFile, new: &MapFile, scope: &Scope) -> Self {
        Self::from_maps_with_renames(old, new, scope, &[])
            .expect("no renames declared, so none can fail to apply")
    }

    /// Like [`Self::from_maps`], then joins declared renames `(old name, new name)` among the leftovers. Errors
    /// if a rename doesn't name exactly one unjoined function on each side.
    pub fn from_maps_with_renames(
        old: &MapFile,
        new: &MapFile,
        scope: &Scope,
        renames: &[(String, String)],
    ) -> Result<Self, String> {
        let in_scope = |map: &'_ MapFile| -> Vec<MapSymbol> {
            map.symbols
                .iter()
                .filter(|s| scope.includes(s))
                .cloned()
                .collect()
        };
        let (old_syms, new_syms) = (in_scope(old), in_scope(new));

        // Stage 1: by (name, object).
        let mut new_by_key: HashMap<(&str, &str), usize> = HashMap::new();
        for (i, s) in new_syms.iter().enumerate() {
            new_by_key.entry((&s.name, &s.object)).or_insert(i);
        }
        let mut new_used = vec![false; new_syms.len()];
        let mut joined: Vec<(Option<&MapSymbol>, Option<&MapSymbol>)> = Vec::new();
        let mut old_left: Vec<&MapSymbol> = Vec::new();
        for o in &old_syms {
            match new_by_key.get(&(o.name.as_str(), o.object.as_str())) {
                Some(&i) if !new_used[i] => {
                    new_used[i] = true;
                    joined.push((Some(o), Some(&new_syms[i])));
                }
                _ => old_left.push(o),
            }
        }
        let new_left: Vec<&MapSymbol> = new_syms
            .iter()
            .zip(&new_used)
            .filter(|(_, used)| !**used)
            .map(|(s, _)| s)
            .collect();

        // Stage 2: leftovers by name, only where the name is unique among the leftovers on both sides.
        fn count<'s>(syms: &[&'s MapSymbol]) -> HashMap<&'s str, usize> {
            let mut c: HashMap<&str, usize> = HashMap::new();
            for s in syms {
                *c.entry(s.name.as_str()).or_default() += 1;
            }
            c
        }
        let (old_count, new_count) = (count(&old_left), count(&new_left));
        let mut new_left_used = vec![false; new_left.len()];
        let mut old_unjoined: Vec<&MapSymbol> = Vec::new();
        for o in old_left {
            let unique =
                old_count[o.name.as_str()] == 1 && new_count.get(o.name.as_str()) == Some(&1);
            let partner = unique
                .then(|| new_left.iter().position(|n| n.name == o.name))
                .flatten();
            match partner {
                Some(i) => {
                    new_left_used[i] = true;
                    joined.push((Some(o), Some(new_left[i])));
                }
                None => old_unjoined.push(o),
            }
        }

        // Stage 3: declared renames. Skipped where either side has no such function (an optimized build can
        // inline a new static away). An error if the old name still exists in the new build (stale
        // declaration) or a name is held by more than one unjoined function (can't say which was renamed).
        let mut old_used = vec![false; old_unjoined.len()];
        for (from, to) in renames {
            if new_syms.iter().any(|s| s.name == *from) {
                return Err(format!(
                    "rename {from} -> {to} is stale: {from} still exists in the new build"
                ));
            }
            let olds: Vec<usize> = (0..old_unjoined.len())
                .filter(|&i| !old_used[i] && old_unjoined[i].name == *from)
                .collect();
            let news: Vec<usize> = (0..new_left.len())
                .filter(|&i| !new_left_used[i] && new_left[i].name == *to)
                .collect();
            match (olds.as_slice(), news.as_slice()) {
                ([o], [n]) => {
                    old_used[*o] = true;
                    new_left_used[*n] = true;
                    joined.push((Some(old_unjoined[*o]), Some(new_left[*n])));
                }
                ([], _) | (_, []) => {}
                _ => {
                    return Err(format!(
                        "rename {from} -> {to} is ambiguous: {} unjoined old function(s) named {from}, \
                         {} unjoined new function(s) named {to}",
                        olds.len(),
                        news.len()
                    ));
                }
            }
        }
        for (o, used) in old_unjoined.iter().zip(&old_used) {
            if !used {
                joined.push((Some(o), None));
            }
        }
        for (n, used) in new_left.iter().zip(&new_left_used) {
            if !used {
                joined.push((None, Some(n)));
            }
        }

        let mut groups: BTreeMap<AddressPair, (Vec<String>, bool, Option<String>)> =
            BTreeMap::new();
        for (o, n) in joined {
            let addresses = (o.map(|s| s.rva), n.map(|s| s.rva));
            let is_static = o.is_some_and(|s| s.is_static) || n.is_some_and(|s| s.is_static);
            let name = o.or(n).map(|s| s.name.clone()).unwrap_or_default();
            let entry = groups.entry(addresses).or_default();
            if let (Some(o), Some(n)) = (o, n) {
                if o.name != n.name {
                    entry.2 = Some(n.name.clone());
                }
            }
            entry.0.push(name);
            entry.1 |= is_static;
        }

        Ok(GroundTruth {
            schema_version: TRUTH_SCHEMA_VERSION,
            object: scope.describe(),
            functions: groups
                .into_iter()
                .map(|((old, new), (mut names, is_static, renamed_to))| {
                    names.sort();
                    TruthEntry {
                        names,
                        old,
                        new,
                        is_static,
                        renamed_to,
                    }
                })
                .collect(),
        })
    }

    pub fn entry(&self, name: &str) -> Option<&TruthEntry> {
        self.functions
            .iter()
            .find(|e| e.names.iter().any(|n| n == name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sym(name: &str, rva: u64, object: &str, is_static: bool) -> MapSymbol {
        MapSymbol {
            name: name.into(),
            rva: Rva(rva),
            is_function: true,
            is_static,
            object: object.into(),
        }
    }

    fn map(symbols: Vec<MapSymbol>) -> MapFile {
        MapFile {
            preferred_base: 0x1_4000_0000,
            symbols,
        }
    }

    #[test]
    fn project_scope_spans_objects_and_excludes_library_members() {
        let old = map(vec![
            sym("deflate", 0x10, "deflate.obj", false),
            sym("inflate", 0x20, "inflate.obj", false),
            sym("mainCRTStartup", 0x30, "MSVCRT:exe_main.obj", false),
        ]);
        let t = GroundTruth::from_maps(&old, &old, &Scope::ProjectObjects);
        assert!(t.entry("deflate").is_some() && t.entry("inflate").is_some());
        assert!(t.entry("mainCRTStartup").is_none());
    }

    #[test]
    fn linkage_change_still_joins() {
        // zlib 1.3 → 1.3.1: minigzip's `error` went from public to static, same object, same code.
        let old = map(vec![sym("error", 0x10, "minigzip.obj", false)]);
        let new = map(vec![sym("error", 0x10, "minigzip.obj", true)]);
        let t = GroundTruth::from_maps(&old, &new, &Scope::ProjectObjects);
        let e = t.entry("error").unwrap();
        assert_eq!((e.old, e.new), (Some(Rva(0x10)), Some(Rva(0x10))));
    }

    #[test]
    fn function_moved_to_another_object_still_joins() {
        let old = map(vec![sym("crc_fold", 0x10, "crc32.obj", true)]);
        let new = map(vec![sym("crc_fold", 0x90, "crc_simd.obj", true)]);
        let t = GroundTruth::from_maps(&old, &new, &Scope::ProjectObjects);
        assert_eq!(t.functions.len(), 1);
    }

    #[test]
    fn ambiguous_leftover_names_are_not_joined() {
        // Two old statics named `helper` disappear from their objects; one new `helper` appears elsewhere.
        // Which one moved is unknown, so none is joined.
        let old = map(vec![
            sym("helper", 0x10, "a.obj", true),
            sym("helper", 0x20, "b.obj", true),
        ]);
        let new = map(vec![sym("helper", 0x130, "c.obj", true)]);
        let t = GroundTruth::from_maps(&old, &new, &Scope::ProjectObjects);
        assert!(
            t.functions
                .iter()
                .all(|e| e.old.is_none() || e.new.is_none())
        );
    }

    #[test]
    fn statics_with_the_same_name_in_different_objects_stay_apart() {
        let old = map(vec![
            sym("helper", 0x10, "a.obj", true),
            sym("helper", 0x20, "b.obj", true),
        ]);
        let new = map(vec![
            sym("helper", 0x110, "a.obj", true),
            sym("helper", 0x120, "b.obj", true),
        ]);
        let t = GroundTruth::from_maps(&old, &new, &Scope::ProjectObjects);
        let pairs: Vec<_> = t.functions.iter().map(|e| (e.old, e.new)).collect();
        assert_eq!(
            pairs,
            vec![
                (Some(Rva(0x10)), Some(Rva(0x110))),
                (Some(Rva(0x20)), Some(Rva(0x120)))
            ]
        );
    }

    fn renames(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|&(a, b)| (a.to_owned(), b.to_owned()))
            .collect()
    }

    #[test]
    fn declared_rename_joins_old_and_new_names() {
        // Lua 5.4.7: luaK_exp2RK became static exp2RK.
        let old = map(vec![sym("luaK_exp2RK", 0x10, "lcode.obj", false)]);
        let new = map(vec![sym("exp2RK", 0x90, "lcode.obj", true)]);
        let t = GroundTruth::from_maps_with_renames(
            &old,
            &new,
            &Scope::ProjectObjects,
            &renames(&[("luaK_exp2RK", "exp2RK")]),
        )
        .unwrap();
        let e = t.entry("luaK_exp2RK").unwrap();
        assert_eq!((e.old, e.new), (Some(Rva(0x10)), Some(Rva(0x90))));
        assert_eq!(e.renamed_to.as_deref(), Some("exp2RK"));
        assert_eq!(t.functions.len(), 1);
    }

    #[test]
    fn without_a_declaration_a_rename_is_deleted_plus_added() {
        let old = map(vec![sym("luaK_exp2RK", 0x10, "lcode.obj", false)]);
        let new = map(vec![sym("exp2RK", 0x90, "lcode.obj", true)]);
        let t = GroundTruth::from_maps(&old, &new, &Scope::ProjectObjects);
        assert!(
            t.functions
                .iter()
                .all(|e| e.old.is_none() || e.new.is_none())
        );
    }

    #[test]
    fn a_stale_rename_is_an_error() {
        // The function kept its name: the declaration is out of date.
        let old = map(vec![sym("f", 0x10, "a.obj", false)]);
        let new = map(vec![
            sym("f", 0x90, "a.obj", false),
            sym("g", 0xa0, "a.obj", false),
        ]);
        let r = renames(&[("f", "g")]);
        assert!(
            GroundTruth::from_maps_with_renames(&old, &new, &Scope::ProjectObjects, &r).is_err()
        );
    }

    #[test]
    fn an_ambiguous_rename_is_an_error() {
        // Two unjoined new functions named g (different objects): which one f became is unknown.
        let old = map(vec![sym("f", 0x10, "a.obj", false)]);
        let new = map(vec![
            sym("g", 0x90, "a.obj", true),
            sym("g", 0xa0, "b.obj", true),
        ]);
        let r = renames(&[("f", "g")]);
        assert!(
            GroundTruth::from_maps_with_renames(&old, &new, &Scope::ProjectObjects, &r).is_err()
        );
    }

    #[test]
    fn a_rename_whose_new_function_was_inlined_away_is_skipped() {
        // /O2 inlined the new static freeCI, so it has no symbol: the old function stays deleted.
        let old = map(vec![sym("luaE_freeCI", 0x10, "lstate.obj", false)]);
        let new = map(vec![sym("other", 0x90, "lstate.obj", false)]);
        let r = renames(&[("luaE_freeCI", "freeCI")]);
        let t =
            GroundTruth::from_maps_with_renames(&old, &new, &Scope::ProjectObjects, &r).unwrap();
        let e = t.entry("luaE_freeCI").unwrap();
        assert_eq!((e.old, e.new), (Some(Rva(0x10)), None));
    }
}
