//! Compare two analyses of the same build (design §4.3, §12 "analysis gaps").
//!
//! Two analyzers (native and Ghidra, or native with and without a PDB) must agree on function identity: the
//! same entry RVAs, the same extents, and the same hash for any hash both emit. This reports every
//! disagreement; it never resolves one. Which side is right is for a person (or the corpus answer key) to say.

use permanent_beta_model::{AnalysisExport, FunctionFeatures, Rva};
use serde::Serialize;
use std::collections::BTreeMap;

/// Every disagreement between analysis `a` and analysis `b`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct AnalysisDiff {
    pub a_producer: String,
    pub b_producer: String,
    /// The two exports are of different files. Every other finding is then meaningless: RVAs only mean
    /// something within one build.
    pub different_builds: bool,
    pub a_functions: usize,
    pub b_functions: usize,
    /// Same entry and size, and no hash or name disagreement.
    pub agreeing: usize,
    /// Entries only `a` found.
    pub only_a: Vec<Unpaired>,
    /// Entries only `b` found.
    pub only_b: Vec<Unpaired>,
    /// Same entry, different size.
    pub size_differs: Vec<SizeDiff>,
    /// Same entry and size, both emit a hash, and the hashes differ. (Different sizes nearly always mean
    /// different hashes, so those are only listed under `size_differs`.)
    pub hash_differs: Vec<HashDiff>,
    /// Same entry, both name it, and the names differ.
    pub name_differs: Vec<NameDiff>,
}

/// A function one side found and the other didn't, with the other side's function covering it, if any (for
/// example a fragment one analyzer split off and the other kept inside its parent).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Unpaired {
    pub rva: Rva,
    pub size: u32,
    pub name: Option<String>,
    /// The other side's function whose extent contains `rva`.
    pub inside: Option<Rva>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SizeDiff {
    pub rva: Rva,
    pub name: Option<String>,
    pub a_size: u32,
    pub b_size: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HashKind {
    Normalized,
    Mnemonic,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HashDiff {
    pub rva: Rva,
    pub name: Option<String>,
    pub kind: HashKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NameDiff {
    pub rva: Rva,
    pub a_name: String,
    pub b_name: String,
}

impl AnalysisDiff {
    /// No disagreement of any kind.
    pub fn is_clean(&self) -> bool {
        !self.different_builds
            && self.only_a.is_empty()
            && self.only_b.is_empty()
            && self.size_differs.is_empty()
            && self.hash_differs.is_empty()
            && self.name_differs.is_empty()
    }
}

/// Compare `a` with `b`. Functions are paired by entry RVA only: a function at another entry is a different
/// function, however much it overlaps.
pub fn diff(a: &AnalysisExport, b: &AnalysisExport) -> AnalysisDiff {
    let a_by_rva = by_rva(&a.functions);
    let b_by_rva = by_rva(&b.functions);

    let mut out = AnalysisDiff {
        a_producer: producer(a),
        b_producer: producer(b),
        different_builds: a.build.id != b.build.id,
        a_functions: a_by_rva.len(),
        b_functions: b_by_rva.len(),
        ..AnalysisDiff::default()
    };

    for (rva, fa) in &a_by_rva {
        let Some(fb) = b_by_rva.get(rva) else {
            out.only_a.push(unpaired(fa, &b_by_rva));
            continue;
        };
        let mut agrees = true;
        let same_size = fa.size == fb.size;
        if !same_size {
            agrees = false;
            out.size_differs.push(SizeDiff {
                rva: *rva,
                name: name_of(fa, fb),
                a_size: fa.size,
                b_size: fb.size,
            });
        }
        for (kind, ha, hb) in [
            (
                HashKind::Normalized,
                &fa.normalized_hash,
                &fb.normalized_hash,
            ),
            (HashKind::Mnemonic, &fa.mnemonic_hash, &fb.mnemonic_hash),
        ] {
            if let (Some(ha), Some(hb)) = (ha, hb)
                && same_size
                && ha != hb
            {
                agrees = false;
                out.hash_differs.push(HashDiff {
                    rva: *rva,
                    name: name_of(fa, fb),
                    kind,
                });
            }
        }
        if let (Some(na), Some(nb)) = (&fa.name, &fb.name)
            && na != nb
        {
            agrees = false;
            out.name_differs.push(NameDiff {
                rva: *rva,
                a_name: na.clone(),
                b_name: nb.clone(),
            });
        }
        if agrees {
            out.agreeing += 1;
        }
    }
    for (rva, fb) in &b_by_rva {
        if !a_by_rva.contains_key(rva) {
            out.only_b.push(unpaired(fb, &a_by_rva));
        }
    }
    out
}

fn producer(e: &AnalysisExport) -> String {
    format!("{} {}", e.producer.tool, e.producer.version)
}

/// Functions by entry. A duplicate entry keeps the first; an export shouldn't have one.
fn by_rva(functions: &[FunctionFeatures]) -> BTreeMap<Rva, &FunctionFeatures> {
    let mut map = BTreeMap::new();
    for f in functions {
        map.entry(f.rva).or_insert(f);
    }
    map
}

fn name_of(a: &FunctionFeatures, b: &FunctionFeatures) -> Option<String> {
    a.name.clone().or_else(|| b.name.clone())
}

fn unpaired(f: &FunctionFeatures, other: &BTreeMap<Rva, &FunctionFeatures>) -> Unpaired {
    // The other side's closest function starting before this entry, if its extent reaches it.
    let inside = other
        .range(..f.rva)
        .next_back()
        .filter(|(start, g)| f.rva.0 < start.0 + u64::from(g.size))
        .map(|(start, _)| *start);
    Unpaired {
        rva: f.rva,
        size: f.size,
        name: f.name.clone(),
        inside,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use permanent_beta_model::{BuildId, BuildInfo, Machine, Producer};

    fn func(rva: u64, size: u32, hash: Option<&str>, name: Option<&str>) -> FunctionFeatures {
        FunctionFeatures {
            rva: Rva(rva),
            size,
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
            data_refs: vec![],
            signature: None,
            inferred_args: None,
            inferred_arg_classes: vec![],
            mnemonic_counts: Default::default(),
            pseudocode: None,
            entry: None,
            arg_accesses: vec![],
        }
    }

    fn export(build: &str, tool: &str, functions: Vec<FunctionFeatures>) -> AnalysisExport {
        AnalysisExport {
            schema_version: permanent_beta_model::ANALYSIS_SCHEMA_VERSION,
            build: BuildInfo {
                id: BuildId(build.into()),
                file_name: "app.exe".into(),
                version: None,
                machine: Machine::X64,
                pdb: None,
            },
            producer: Producer {
                tool: tool.into(),
                version: "1".into(),
            },
            functions,
            code_tables: Vec::new(),
            types: Vec::new(),
            globals: Vec::new(),
            data_symbols: Vec::new(),
            pointer_aliases: Vec::new(),
        }
    }

    #[test]
    fn identical_analyses_are_clean() {
        let fs = vec![
            func(0x1000, 0x20, Some("h1"), Some("f")),
            func(0x1020, 0x10, Some("h2"), None),
        ];
        let d = diff(&export("b", "x", fs.clone()), &export("b", "y", fs));
        assert!(d.is_clean());
        assert_eq!(d.agreeing, 2);
    }

    #[test]
    fn reports_every_kind_of_disagreement() {
        let a = export(
            "b",
            "native",
            vec![
                func(0x1000, 0x40, Some("h1"), None),
                func(0x1100, 0x10, Some("h2"), Some("foo")),
                func(0x1200, 0x10, Some("h3"), None),
                func(0x1300, 0x08, None, None),
            ],
        );
        let b = export(
            "b",
            "ghidra",
            vec![
                // Same entry, shorter: a fragment split off at 0x1020.
                func(0x1000, 0x20, Some("h1"), None),
                func(0x1020, 0x20, None, None),
                func(0x1100, 0x10, Some("h2"), Some("bar")),
                func(0x1200, 0x10, Some("other"), None),
                // Dead code the native analyzer never reached.
                func(0x1400, 0x10, None, Some("dead")),
            ],
        );
        let d = diff(&a, &b);
        assert!(!d.is_clean());
        assert!(!d.different_builds);
        assert_eq!(d.agreeing, 0);
        assert_eq!(
            d.only_a,
            vec![Unpaired {
                rva: Rva(0x1300),
                size: 8,
                name: None,
                inside: None
            }]
        );
        assert_eq!(d.only_b.len(), 2);
        // The fragment sits inside a's function at 0x1000; the dead code inside nothing.
        assert_eq!(d.only_b[0].rva, Rva(0x1020));
        assert_eq!(d.only_b[0].inside, Some(Rva(0x1000)));
        assert_eq!(d.only_b[1].inside, None);
        assert_eq!(d.size_differs.len(), 1);
        assert_eq!(
            d.hash_differs,
            vec![HashDiff {
                rva: Rva(0x1200),
                name: None,
                kind: HashKind::Normalized
            }]
        );
        assert_eq!(d.name_differs.len(), 1);
    }

    #[test]
    fn a_size_difference_is_not_also_a_hash_difference() {
        let a = export("b", "x", vec![func(0x1000, 0x20, Some("h1"), None)]);
        let b = export("b", "y", vec![func(0x1000, 0x10, Some("h2"), None)]);
        let d = diff(&a, &b);
        assert_eq!(d.size_differs.len(), 1);
        assert!(d.hash_differs.is_empty());
        assert!(!d.is_clean());
    }

    #[test]
    fn a_hash_only_one_side_emits_is_not_a_disagreement() {
        let a = export("b", "x", vec![func(0x1000, 0x10, Some("h"), None)]);
        let b = export("b", "y", vec![func(0x1000, 0x10, None, Some("f"))]);
        let d = diff(&a, &b);
        assert!(d.is_clean());
    }

    #[test]
    fn different_builds_are_never_clean() {
        // Negative case: identical functions in two different files must not be reported as agreement.
        let fs = vec![func(0x1000, 0x10, Some("h"), None)];
        let d = diff(&export("b1", "x", fs.clone()), &export("b2", "x", fs));
        assert!(d.different_builds);
        assert!(!d.is_clean());
    }

    #[test]
    fn an_entry_past_the_end_of_the_previous_function_is_inside_nothing() {
        let a = export("b", "x", vec![func(0x1000, 0x10, None, None)]);
        let b = export("b", "y", vec![func(0x1010, 0x10, None, None)]);
        let d = diff(&a, &b);
        assert_eq!(d.only_b[0].inside, None);
    }
}
