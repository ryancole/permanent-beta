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
//! 3. C++ leftovers by their undecorated name with local-scope numbers removed ([`cxx_identity`]), first with
//!    the signature (overloads stay apart), then without it, each when the name is unique among the leftovers
//!    on both sides. A decorated (mangled) name encodes the parameter and return types and, for a class local to a function, a scope number that moves when
//!    that function's body changes: TinyXML-2 10.0.0 → 10.1.0 changed `int` sizes to `size_t`, and its
//!    `xmltest` `main`'s local class went from scope 204 to 225. Template arguments stay in the name, so
//!    `MemPoolT<80>` and `MemPoolT<88>` never join.
//! 4. declared renames (old name → new name), checked by hand against the sources and listed in the project's
//!    recipe. Lua 5.4.7 renamed `luaK_exp2RK` to a static `exp2RK`: without the declaration, matching the two
//!    is scored as wrong. A declaration whose old name still exists in the new build is an error, so the list
//!    can't go stale.
//! 5. declared reused names, joined before everything else: zstd 1.5.7 renamed `ZSTD_cwksp_aligned_alloc_size`
//!    to `ZSTD_cwksp_aligned64_alloc_size` and gave the old name to a new function, so joining by name would pair
//!    the old function with an unrelated one. Skipped where either function was inlined away; an error when
//!    either name is ambiguous.
//!
//! Leftovers named after a lambda (`<lambda_HASH>`, a per-build hash) join only within their object file, and
//! those still unjoined are out of scope: two `(char)` lambdas in one file can't be told apart by name.
//!
//! Exception-handling funclets (`main$dtor$73`, `?dtor$0@?0??f@…`) are out of scope: the compiler numbers them
//! per parent function, so once the parent changes the same name says nothing about which code it is. Matching
//! an in-scope function onto a funclet is still scored as wrong.

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
            && !is_funclet(&s.name)
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
        Self::from_maps_with_declarations(old, new, scope, renames, &[])
    }

    /// Like [`Self::from_maps_with_renames`], and first joins each declared reused name `(old name, new name)`:
    /// the old build's function named `old name` with the new build's `new name`, while the new build's `old
    /// name` (another function) joins nothing by that name. Skipped when either is missing (inlined away); an
    /// error when the old build has more than one `old name` or the new build more than one `new name`.
    pub fn from_maps_with_declarations(
        old: &MapFile,
        new: &MapFile,
        scope: &Scope,
        renames: &[(String, String)],
        reused: &[(String, String)],
    ) -> Result<Self, String> {
        let in_scope = |map: &'_ MapFile| -> Vec<MapSymbol> {
            map.symbols
                .iter()
                .filter(|s| scope.includes(s))
                .cloned()
                .collect()
        };
        let (old_syms, new_syms) = (in_scope(old), in_scope(new));

        let mut new_used = vec![false; new_syms.len()];
        let mut joined: Vec<(Option<&MapSymbol>, Option<&MapSymbol>)> = Vec::new();

        // Stage 0: declared reused names. Where the renamed function was inlined away (an optimized build of
        // a header static), the old one is deleted; the namesake may be inlined away too, so it isn't required.
        let mut old_reused = vec![false; old_syms.len()];
        for (from, to) in reused {
            let find = |syms: &[MapSymbol], name: &str| -> Vec<usize> {
                (0..syms.len()).filter(|&i| syms[i].name == name).collect()
            };
            let (olds, new_to) = (find(&old_syms, from), find(&new_syms, to));
            match (olds.as_slice(), new_to.as_slice()) {
                ([o], [n]) => {
                    old_reused[*o] = true;
                    new_used[*n] = true;
                    joined.push((Some(&old_syms[*o]), Some(&new_syms[*n])));
                }
                // The renamed function was inlined away: the old one has no counterpart, and never its namesake.
                ([o], []) => {
                    old_reused[*o] = true;
                    joined.push((Some(&old_syms[*o]), None));
                }
                ([], _) => {}
                _ => {
                    return Err(format!(
                        "reused name {from} -> {to} is ambiguous: {} old function(s) named {from}, {} new named {to}",
                        olds.len(),
                        new_to.len()
                    ));
                }
            }
        }

        // Stage 1: by (name, object).
        let mut new_by_key: HashMap<(&str, &str), usize> = HashMap::new();
        for (i, s) in new_syms.iter().enumerate() {
            new_by_key.entry((&s.name, &s.object)).or_insert(i);
        }
        let mut old_left: Vec<&MapSymbol> = Vec::new();
        for (o, _) in old_syms.iter().zip(&old_reused).filter(|(_, r)| !**r) {
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

        // Stage 3: C++ leftovers by undecorated name, first with the signature, then without it, each only
        // where the key is unique among the remaining leftovers on both sides.
        for with_signature in [true, false] {
            // A lambda's type name holds a per-build hash, so its key is only meaningful within its object file.
            let key = |s: &MapSymbol| {
                cxx_identity(&s.name, with_signature).map(|k| {
                    if k.contains("<lambda>") {
                        format!("{}: {k}", s.object)
                    } else {
                        k
                    }
                })
            };
            let old_keys: Vec<Option<String>> = old_unjoined.iter().map(|s| key(s)).collect();
            let new_keys: Vec<Option<String>> = new_left
                .iter()
                .zip(&new_left_used)
                .map(|(s, used)| if *used { None } else { key(s) })
                .collect();
            let count = |keys: &[Option<String>]| -> HashMap<String, usize> {
                let mut c: HashMap<String, usize> = HashMap::new();
                for k in keys.iter().flatten() {
                    *c.entry(k.clone()).or_default() += 1;
                }
                c
            };
            let (old_count, new_count) = (count(&old_keys), count(&new_keys));
            let mut still_unjoined = Vec::new();
            for (o, k) in old_unjoined.into_iter().zip(&old_keys) {
                let partner = k
                    .as_ref()
                    .filter(|k| old_count[*k] == 1 && new_count.get(*k) == Some(&1))
                    .and_then(|k| (0..new_left.len()).find(|&i| new_keys[i].as_ref() == Some(k)));
                match partner {
                    Some(i) => {
                        new_left_used[i] = true;
                        joined.push((Some(o), Some(new_left[i])));
                    }
                    None => still_unjoined.push(o),
                }
            }
            old_unjoined = still_unjoined;
        }

        // Stage 4: declared renames, per unjoined old function. A partner in the same object file wins (header
        // statics exist once per object); otherwise the new name must be unique. Skipped where the new build has
        // no such function (an optimized build can inline a new static away). Errors: a stale declaration (the
        // old name still exists and every old copy was already joined by name), or more than one candidate.
        let mut old_used = vec![false; old_unjoined.len()];
        for (from, to) in renames {
            let olds: Vec<usize> = (0..old_unjoined.len())
                .filter(|&i| old_unjoined[i].name == *from)
                .collect();
            if olds.is_empty() && new_syms.iter().any(|s| s.name == *from) {
                return Err(format!(
                    "rename {from} -> {to} is stale: {from} still exists in the new build"
                ));
            }
            for &o in &olds {
                let free = |i: &usize| !new_left_used[*i] && new_left[*i].name == *to;
                let same_object: Vec<usize> = (0..new_left.len())
                    .filter(free)
                    .filter(|&i| new_left[i].object == old_unjoined[o].object)
                    .collect();
                let anywhere: Vec<usize> = (0..new_left.len()).filter(free).collect();
                let partner = match (same_object.as_slice(), anywhere.as_slice()) {
                    ([n], _) => Some(*n),
                    ([], []) => None,
                    ([], [n]) if olds.len() == 1 => Some(*n),
                    _ => {
                        return Err(format!(
                            "rename {from} -> {to} is ambiguous for {from} in {}: {} candidate(s) named {to}",
                            old_unjoined[o].object,
                            if same_object.is_empty() {
                                anywhere.len()
                            } else {
                                same_object.len()
                            }
                        ));
                    }
                };
                if let Some(n) = partner {
                    old_used[o] = true;
                    new_left_used[n] = true;
                    joined.push((Some(old_unjoined[o]), Some(new_left[n])));
                }
            }
        }
        // Left over and named after a lambda (its call operator, or a template instantiated on it): the answer key
        // can't tell which lambda it is, so it's neither deleted nor added but out of scope.
        for (o, used) in old_unjoined.iter().zip(&old_used) {
            if !used && !is_lambda_named(&o.name) {
                joined.push((Some(o), None));
            }
        }
        for (n, used) in new_left.iter().zip(&new_left_used) {
            if !used && !is_lambda_named(&n.name) {
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

/// A C++ function's identity across builds: its undecorated, scope-qualified name with local-scope numbers
/// (`` `204' ``) removed, e.g. `` `main'::`'::TestUtil::Visit ``, with or without its parameter and return types.
/// Template arguments are kept. `None` for an undecorated (C) name or one that doesn't demangle.
pub fn cxx_identity(name: &str, with_signature: bool) -> Option<String> {
    if !name.starts_with('?') {
        return None;
    }
    let flags = if with_signature {
        msvc_demangler::DemangleFlags::COMPLETE
    } else {
        msvc_demangler::DemangleFlags::NAME_ONLY
    };
    let undecorated = msvc_demangler::demangle(name, flags).ok()?;
    // Drop the digits of every `` `N' `` scope number.
    let mut out = String::with_capacity(undecorated.len());
    let mut rest = undecorated.as_str();
    while let Some(tick) = rest.find('`') {
        out.push_str(&rest[..=tick]);
        rest = &rest[tick + 1..];
        let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
        if digits > 0 && rest[digits..].starts_with('\'') {
            rest = &rest[digits..];
        }
    }
    out.push_str(rest);
    Some(normalize_lambdas(&out))
}

/// MSVC names a lambda's closure type `<lambda_` + 32 hex digits + `>`, a hash that changes between builds
/// (yaml-cpp 0.8.0 → 0.9.0: `<lambda_941fd7b9…>` → `<lambda_a8d71613…>` for the same lambda).
fn normalize_lambdas(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut rest = name;
    while let Some(i) = rest.find("<lambda_") {
        let after = &rest[i + "<lambda_".len()..];
        let hex = after.bytes().take_while(u8::is_ascii_hexdigit).count();
        out.push_str(&rest[..i]);
        if hex > 0 && after[hex..].starts_with('>') {
            out.push_str("<lambda>");
            rest = &after[hex + 1..];
        } else {
            out.push_str("<lambda_");
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

/// A symbol named after a lambda's closure type.
pub fn is_lambda_named(name: &str) -> bool {
    normalize_lambdas(name).contains("<lambda>")
}

/// An exception-handling funclet: `f$dtor$3`, `f$catch$0` (C names) or `?dtor$0@?0??f@…`, `?catch$1@…`
/// (C++ names); also `fin` and `filt`.
pub fn is_funclet(name: &str) -> bool {
    const KINDS: [&str; 4] = ["dtor$", "catch$", "fin$", "filt$"];
    let numbered = |rest: &str| rest.starts_with(|c: char| c.is_ascii_digit());
    KINDS.iter().any(|kind| {
        name.strip_prefix('?')
            .and_then(|n| n.strip_prefix(kind))
            .is_some_and(numbered)
            || name
                .match_indices(&format!("${kind}"))
                .any(|(i, m)| i > 0 && numbered(&name[i + m.len()..]))
    })
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
    fn a_reused_name_joins_the_renamed_function_not_the_namesake() {
        // zstd 1.5.7: aligned_alloc_size became aligned64_alloc_size, and the old name went to a new function.
        let old = map(vec![sym("aligned", 0x10, "a.obj", false)]);
        let new = map(vec![
            sym("aligned", 0x90, "a.obj", false),
            sym("aligned64", 0xa0, "a.obj", false),
        ]);
        let reused = renames(&[("aligned", "aligned64")]);
        let t = GroundTruth::from_maps_with_declarations(
            &old,
            &new,
            &Scope::ProjectObjects,
            &[],
            &reused,
        )
        .unwrap();
        let pairs: Vec<_> = t.functions.iter().map(|e| (e.old, e.new)).collect();
        assert!(
            pairs.contains(&(Some(Rva(0x10)), Some(Rva(0xa0)))),
            "{pairs:?}"
        );
        assert!(
            pairs.contains(&(None, Some(Rva(0x90)))),
            "the namesake is added: {pairs:?}"
        );
        // Without the declaration, the name joins: the namesake is the old function's answer.
        let t = GroundTruth::from_maps(&old, &new, &Scope::ProjectObjects);
        assert!(
            t.functions
                .iter()
                .any(|e| (e.old, e.new) == (Some(Rva(0x10)), Some(Rva(0x90))))
        );
    }

    #[test]
    fn a_reused_name_must_be_unambiguous() {
        let old = map(vec![sym("f", 0x10, "a.obj", false)]);
        let reused = renames(&[("f", "g")]);
        // The renamed function inlined away in the new build: nothing joined, f is deleted.
        let new = map(vec![sym("f", 0x90, "a.obj", false)]);
        let t = GroundTruth::from_maps_with_declarations(
            &old,
            &new,
            &Scope::ProjectObjects,
            &[],
            &reused,
        )
        .unwrap();
        assert!(
            t.functions
                .iter()
                .any(|e| (e.old, e.new) == (Some(Rva(0x10)), None))
        );
        // Negative: two functions with the new name.
        let new = map(vec![
            sym("f", 0x90, "a.obj", false),
            sym("g", 0xa0, "a.obj", false),
            sym("g", 0xb0, "b.obj", false),
        ]);
        assert!(
            GroundTruth::from_maps_with_declarations(
                &old,
                &new,
                &Scope::ProjectObjects,
                &[],
                &reused
            )
            .is_err()
        );
    }

    #[test]
    fn an_ambiguous_rename_is_an_error() {
        // Two unjoined new functions named g, neither in f's object: which one f became is unknown.
        let old = map(vec![sym("f", 0x10, "c.obj", false)]);
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
    fn a_rename_joins_per_object_when_the_old_name_lives_on_elsewhere() {
        // zstd 1.5.6: BIT_reloadDStreamFast's body became BIT_reloadDStream_internal, and a new Fast wrapper
        // appears only where something calls it. a.obj keeps a Fast (joined by name); in b.obj the old Fast's
        // counterpart is _internal.
        let old = map(vec![
            sym("Fast", 0x10, "a.obj", true),
            sym("Fast", 0x20, "b.obj", true),
        ]);
        let new = map(vec![
            sym("Fast", 0x110, "a.obj", true),
            sym("internal", 0x120, "a.obj", true),
            sym("internal", 0x220, "b.obj", true),
        ]);
        let r = renames(&[("Fast", "internal")]);
        let t =
            GroundTruth::from_maps_with_renames(&old, &new, &Scope::ProjectObjects, &r).unwrap();
        let pairs: Vec<_> = t.functions.iter().map(|e| (e.old, e.new)).collect();
        assert!(
            pairs.contains(&(Some(Rva(0x10)), Some(Rva(0x110)))),
            "{pairs:?}"
        );
        assert!(
            pairs.contains(&(Some(Rva(0x20)), Some(Rva(0x220)))),
            "{pairs:?}"
        );
        assert!(
            pairs.contains(&(None, Some(Rva(0x120)))),
            "a.obj's _internal is new: {pairs:?}"
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

    // TinyXML-2 10.0.0 → 10.1.0 and 9.0.0 → 10.0.0, decorated names from the MSVC map files.
    const ITEM_SIZE_INT: &str = "?ItemSize@?$MemPoolT@$0FA@@tinyxml2@@UEBAHXZ";
    const ITEM_SIZE_SIZE_T: &str = "?ItemSize@?$MemPoolT@$0FA@@tinyxml2@@UEBA_KXZ";

    fn pair_of(t: &GroundTruth, name: &str) -> (Option<Rva>, Option<Rva>) {
        let e = t.entry(name).unwrap();
        (e.old, e.new)
    }

    #[test]
    fn cxx_identity_drops_the_signature_and_local_scope_numbers() {
        assert_eq!(
            cxx_identity(ITEM_SIZE_INT, false).as_deref(),
            Some("tinyxml2::MemPoolT<80>::ItemSize")
        );
        assert_eq!(
            cxx_identity(ITEM_SIZE_INT, false),
            cxx_identity(ITEM_SIZE_SIZE_T, false)
        );
        assert_ne!(
            cxx_identity(ITEM_SIZE_INT, true),
            cxx_identity(ITEM_SIZE_SIZE_T, true)
        );
        assert_eq!(
            cxx_identity(
                "?Visit@TestUtil@?MM@??main@@YAHHPEAPEBD@Z@EEAA_NAEBVXMLText@tinyxml2@@@Z",
                false
            )
            .as_deref(),
            Some("`main'::`'::TestUtil::Visit")
        );
        assert_eq!(cxx_identity("deflate", true), None);
    }

    #[test]
    fn a_changed_cxx_signature_still_joins() {
        let old = map(vec![sym(ITEM_SIZE_INT, 0x10, "tinyxml2.obj", false)]);
        let new = map(vec![sym(ITEM_SIZE_SIZE_T, 0x90, "tinyxml2.obj", false)]);
        let t = GroundTruth::from_maps(&old, &new, &Scope::ProjectObjects);
        assert_eq!(
            pair_of(&t, ITEM_SIZE_INT),
            (Some(Rva(0x10)), Some(Rva(0x90)))
        );
        assert_eq!(
            t.entry(ITEM_SIZE_INT).unwrap().renamed_to.as_deref(),
            Some(ITEM_SIZE_SIZE_T)
        );
    }

    #[test]
    fn a_moved_local_class_scope_still_joins() {
        let old = map(vec![sym(
            "??1TestUtil@?MM@??main@@YAHHPEAPEBD@Z@UEAA@XZ",
            0x10,
            "xmltest.obj",
            false,
        )]);
        let new = map(vec![sym(
            "??1TestUtil@?OB@??main@@YAHHPEAPEBD@Z@UEAA@XZ",
            0x90,
            "xmltest.obj",
            false,
        )]);
        let t = GroundTruth::from_maps(&old, &new, &Scope::ProjectObjects);
        assert_eq!(
            pair_of(&t, "??1TestUtil@?MM@??main@@YAHHPEAPEBD@Z@UEAA@XZ"),
            (Some(Rva(0x10)), Some(Rva(0x90)))
        );
    }

    #[test]
    fn overloads_in_a_moved_local_class_join_by_signature() {
        // 9.0.0 → 10.0.0: TestUtil's Visit overloads, scope 204 → 225, signatures unchanged.
        let text = |scope: &str| {
            format!("?Visit@TestUtil@?{scope}@??main@@YAHHPEAPEBD@Z@EEAA_NAEBVXMLText@tinyxml2@@@Z")
        };
        let comment = |scope: &str| {
            format!(
                "?Visit@TestUtil@?{scope}@??main@@YAHHPEAPEBD@Z@EEAA_NAEBVXMLComment@tinyxml2@@@Z"
            )
        };
        let old = map(vec![
            sym(&text("MM"), 0x10, "xmltest.obj", false),
            sym(&comment("MM"), 0x20, "xmltest.obj", false),
        ]);
        let new = map(vec![
            sym(&comment("OB"), 0x90, "xmltest.obj", false),
            sym(&text("OB"), 0xa0, "xmltest.obj", false),
        ]);
        let t = GroundTruth::from_maps(&old, &new, &Scope::ProjectObjects);
        assert_eq!(pair_of(&t, &text("MM")), (Some(Rva(0x10)), Some(Rva(0xa0))));
        assert_eq!(
            pair_of(&t, &comment("MM")),
            (Some(Rva(0x20)), Some(Rva(0x90)))
        );
    }

    #[test]
    fn changed_template_arguments_do_not_join() {
        // MemPoolT<80> → MemPoolT<88>: another instantiation, deleted + added.
        let old = map(vec![sym(ITEM_SIZE_INT, 0x10, "tinyxml2.obj", false)]);
        let new = map(vec![sym(
            "?ItemSize@?$MemPoolT@$0FI@@tinyxml2@@UEBAHXZ",
            0x90,
            "tinyxml2.obj",
            false,
        )]);
        let t = GroundTruth::from_maps(&old, &new, &Scope::ProjectObjects);
        assert_eq!(pair_of(&t, ITEM_SIZE_INT), (Some(Rva(0x10)), None));
    }

    #[test]
    fn overloads_whose_signatures_both_changed_do_not_join() {
        // f(int) and f(char) become f(__int64) and f(short): the undecorated name `f` is not unique.
        let old = map(vec![
            sym("?f@@YAXH@Z", 0x10, "a.obj", false),
            sym("?f@@YAXD@Z", 0x20, "a.obj", false),
        ]);
        let new = map(vec![
            sym("?f@@YAX_J@Z", 0x90, "a.obj", false),
            sym("?f@@YAXF@Z", 0xa0, "a.obj", false),
        ]);
        let t = GroundTruth::from_maps(&old, &new, &Scope::ProjectObjects);
        assert_eq!(pair_of(&t, "?f@@YAXH@Z"), (Some(Rva(0x10)), None));
        assert_eq!(pair_of(&t, "?f@@YAXD@Z"), (Some(Rva(0x20)), None));
    }

    #[test]
    fn an_overload_left_over_alone_joins() {
        // f(char) unchanged (joined by name), f(int) → f(__int64): the only `f` left on each side.
        let old = map(vec![
            sym("?f@@YAXH@Z", 0x10, "a.obj", false),
            sym("?f@@YAXD@Z", 0x20, "a.obj", false),
        ]);
        let new = map(vec![
            sym("?f@@YAX_J@Z", 0x90, "a.obj", false),
            sym("?f@@YAXD@Z", 0xa0, "a.obj", false),
        ]);
        let t = GroundTruth::from_maps(&old, &new, &Scope::ProjectObjects);
        assert_eq!(
            pair_of(&t, "?f@@YAXH@Z"),
            (Some(Rva(0x10)), Some(Rva(0x90)))
        );
        assert_eq!(
            pair_of(&t, "?f@@YAXD@Z"),
            (Some(Rva(0x20)), Some(Rva(0xa0)))
        );
    }

    #[test]
    fn funclets_are_out_of_scope() {
        for name in [
            "main$dtor$73",
            "main$catch$0",
            "f$fin$1",
            "?dtor$0@?0??TestParseError@TestUtil@?MM@??main@@YAHHPEAPEBD@Z@QEAAXPEBD1W4XMLError@tinyxml2@@H@Z@4HA",
            "?catch$1@?0??f@@YAXXZ@4HA",
        ] {
            assert!(is_funclet(name), "{name}");
        }
        for name in [
            "catch_error",
            "dtor$",
            "?finish@@YAXXZ",
            "$dtor$1",
            "deflate",
        ] {
            assert!(!is_funclet(name), "{name}");
        }
        let old = map(vec![
            sym("main$dtor$73", 0x10, "xmltest.obj", false),
            sym("main", 0x20, "xmltest.obj", false),
        ]);
        let new = map(vec![
            sym("main$dtor$73", 0x90, "xmltest.obj", false),
            sym("main", 0xa0, "xmltest.obj", false),
        ]);
        let t = GroundTruth::from_maps(&old, &new, &Scope::ProjectObjects);
        assert!(t.entry("main$dtor$73").is_none());
        assert_eq!(pair_of(&t, "main"), (Some(Rva(0x20)), Some(Rva(0xa0))));
    }

    // yaml-cpp 0.8.0 → 0.9.0, from the map files: the same lambdas under new closure-type hashes.
    const LAMBDA_A_OLD: &str = "??R<lambda_941fd7b97b6be8c70b7927491b015f09>@@QEBA@D@Z";
    const LAMBDA_A_NEW: &str = "??R<lambda_a8d716137e123ff94adec8d3082cc9a1>@@QEBA@D@Z";
    const LAMBDA_B_OLD: &str = "??R<lambda_c86a95e158b1a7fca84f14a352913359>@@QEBA@D@Z";
    const LAMBDA_B_NEW: &str = "??R<lambda_e414d856a138ecba07b5a535ee517306>@@QEBA@D@Z";
    const LAMBDA_C_OLD: &str = "??R<lambda_8cf3b55acb51a04b3ee281edb105368a>@@QEBA@D@Z";
    const LAMBDA_C_NEW: &str = "??R<lambda_a4cd96d18033020525448eae0f50268e>@@QEBA@D@Z";

    #[test]
    fn lambda_hashes_are_normalized() {
        assert_eq!(
            cxx_identity(LAMBDA_A_OLD, true),
            cxx_identity(LAMBDA_A_NEW, true)
        );
        assert!(
            cxx_identity(LAMBDA_A_OLD, false)
                .unwrap()
                .contains("<lambda>")
        );
        assert!(is_lambda_named(LAMBDA_A_OLD));
        assert!(!is_lambda_named("?Write@Emitter@YAML@@QEAAAEAV12@PEBD_K@Z"));
        assert!(!is_lambda_named("<lambda_xyz>"), "not a closure-type hash");
    }

    #[test]
    fn a_renamed_lambda_joins_within_its_object_file() {
        // The same `(char)` lambda signature in two files: each joins with its own file's lambda.
        let old = map(vec![
            sym(LAMBDA_A_OLD, 0x10, "convert.obj", false),
            sym(LAMBDA_B_OLD, 0x20, "emitterutils.obj", false),
        ]);
        let new = map(vec![
            sym(LAMBDA_B_NEW, 0x90, "emitterutils.obj", false),
            sym(LAMBDA_A_NEW, 0xa0, "convert.obj", false),
        ]);
        let t = GroundTruth::from_maps(&old, &new, &Scope::ProjectObjects);
        assert_eq!(
            pair_of(&t, LAMBDA_A_OLD),
            (Some(Rva(0x10)), Some(Rva(0xa0)))
        );
        assert_eq!(
            pair_of(&t, LAMBDA_B_OLD),
            (Some(Rva(0x20)), Some(Rva(0x90)))
        );
    }

    #[test]
    fn lambdas_that_cannot_be_told_apart_are_out_of_scope() {
        // Negative: two `(char)` lambdas in one file, both renamed. Neither is joined, and neither counts as
        // deleted or added (the key would score a correct pairing as wrong half the time).
        let old = map(vec![
            sym(LAMBDA_B_OLD, 0x10, "emitterutils.obj", false),
            sym(LAMBDA_C_OLD, 0x20, "emitterutils.obj", false),
            sym("?gone@@YAXXZ", 0x30, "emitterutils.obj", false),
        ]);
        let new = map(vec![
            sym(LAMBDA_B_NEW, 0x90, "emitterutils.obj", false),
            sym(LAMBDA_C_NEW, 0xa0, "emitterutils.obj", false),
        ]);
        let t = GroundTruth::from_maps(&old, &new, &Scope::ProjectObjects);
        for name in [LAMBDA_B_OLD, LAMBDA_C_OLD, LAMBDA_B_NEW, LAMBDA_C_NEW] {
            assert!(t.entry(name).is_none(), "{name}");
        }
        // An ordinary function is still deleted.
        assert_eq!(pair_of(&t, "?gone@@YAXXZ"), (Some(Rva(0x30)), None));
    }
}
