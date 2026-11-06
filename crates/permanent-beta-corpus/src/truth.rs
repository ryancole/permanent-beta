//! Ground truth: the true old → new mapping for one fixture build pair, joined by symbol name.
//!
//! Functions are grouped by address on each side, because `/OPT:ICF` can fold several names into one
//! function. One entry per distinct (old address, new address) pair:
//! - `old` and `new` set: the function exists in both builds.
//! - only `old`: deleted in the new build. Only `new`: added.
//! - several entries sharing an `old` or `new`: folding differs between builds (many-to-one).

use crate::map::MapFile;
use permanent_beta_model::Rva;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const TRUTH_SCHEMA_VERSION: u32 = 1;

/// (old address, new address); either side is `None` when the function exists in only one build.
type AddressPair = (Option<Rva>, Option<Rva>);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroundTruth {
    pub schema_version: u32,
    /// The object file whose functions are in scope (CRT and library functions are excluded).
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
}

impl GroundTruth {
    pub fn from_maps(old: &MapFile, new: &MapFile, object: &str) -> Self {
        let index = |map: &MapFile| -> BTreeMap<String, (Rva, bool)> {
            map.functions_in(object)
                .map(|s| (s.name.clone(), (s.rva, s.is_static)))
                .collect()
        };
        let (old_ix, new_ix) = (index(old), index(new));
        let names: BTreeSet<&String> = old_ix.keys().chain(new_ix.keys()).collect();

        let mut groups: BTreeMap<AddressPair, (Vec<String>, bool)> = BTreeMap::new();
        for name in names {
            let o = old_ix.get(name);
            let n = new_ix.get(name);
            let key = (o.map(|x| x.0), n.map(|x| x.0));
            let is_static = o.is_some_and(|x| x.1) || n.is_some_and(|x| x.1);
            let entry = groups.entry(key).or_default();
            entry.0.push(name.clone());
            entry.1 |= is_static;
        }

        GroundTruth {
            schema_version: TRUTH_SCHEMA_VERSION,
            object: object.to_owned(),
            functions: groups
                .into_iter()
                .map(|((old, new), (names, is_static))| TruthEntry {
                    names,
                    old,
                    new,
                    is_static,
                })
                .collect(),
        }
    }

    pub fn entry(&self, name: &str) -> Option<&TruthEntry> {
        self.functions
            .iter()
            .find(|e| e.names.iter().any(|n| n == name))
    }
}
