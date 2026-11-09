//! Struct changes inferred from field accesses (design §7.2), measured on the corpus projects against their PDBs:
//! every function named uniquely in both builds whose parameter (one of the first four) points to a struct the
//! PDBs lay out in both builds. The inference runs with the PDB types hidden, as it would on a binary without a
//! PDB; each move it proposes is then judged by the PDBs: right when the field at the old offset is at the new
//! offset in the new build, a false alarm otherwise (including any move on a struct whose layout didn't change).
//!
//! Needs the corpus built (`pwsh corpus/build-projects.ps1`), so it's `#[ignore]`d. A measurement: it prints the
//! counts and fails only when an inferred move is wrong.

use permanent_beta_analysis::{Analyzer, native::NativePeAnalyzer, symbols};
use permanent_beta_engine::permanent_beta_repair::layout;
use permanent_beta_model::{AnalysisExport, BuildId, Criticality, HookSpec, TargetLocator};
use std::path::{Path, PathBuf};

fn analyze(dir: &Path, exe: &str) -> Option<AnalysisExport> {
    let mut export = NativePeAnalyzer
        .analyze(&dir.join(format!("{exe}.exe")))
        .ok()?;
    let pdb = symbols::read(&dir.join(format!("{exe}.pdb"))).ok()?;
    symbols::apply(&mut export, &pdb).ok()?;
    Some(export)
}

#[test]
#[ignore = "needs the corpus builds (pwsh corpus/build-projects.ps1)"]
fn inferred_struct_moves_against_the_pdbs() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/corpus");
    let projects = [
        ("zlib", "minigzip", ["v1.2.13", "v1.3", "v1.3.1"]),
        ("lua", "lua", ["v5.4.6", "v5.4.7", "v5.4.8"]),
        ("zstd", "zstd", ["v1.5.5", "v1.5.6", "v1.5.7"]),
    ];
    let (
        mut pairs,
        mut proposals,
        mut right,
        mut wrong,
        mut changed_structs,
        mut unjudged,
        mut renamed,
    ) = (0, 0, 0, 0, 0, 0, 0);
    for (project, exe, tags) in projects {
        for flags in ["o2", "od"] {
            for step in tags.windows(2) {
                let dir = |tag: &str| root.join(project).join("builds").join(flags).join(tag);
                let (Some(old), Some(new)) =
                    (analyze(&dir(step[0]), exe), analyze(&dir(step[1]), exe))
                else {
                    println!("{project} {flags} {}: not built", step[1]);
                    continue;
                };
                // The PDB types hidden from the inference, kept for judging it.
                let (mut o_blind, mut n_blind) = (old.clone(), new.clone());
                o_blind.types.clear();
                n_blind.types.clear();
                for of in &old.functions {
                    let Some(name) = of.name.as_deref() else {
                        continue;
                    };
                    let (Some(nf), Some(sig)) = (new.function_by_name(name), of.signature.as_ref())
                    else {
                        continue;
                    };
                    // A prototype from the old signature, as a hook author would write it.
                    let params: Vec<String> = sig
                        .params
                        .iter()
                        .enumerate()
                        .map(|(i, p)| format!("{} p{i}", p.ty))
                        .collect();
                    let prototype = format!("int {name}({})", params.join(", "));
                    let structs: Vec<(usize, String)> = sig
                        .params
                        .iter()
                        .take(4)
                        .enumerate()
                        .filter_map(|(i, p)| {
                            let base =
                                p.ty.replace('*', " ")
                                    .replace("const", " ")
                                    .replace("struct", " ");
                            let base = base.trim().to_owned();
                            (p.ty.matches('*').count() == 1
                                && old.type_layout(&base).is_some()
                                && new.type_layout(&base).is_some())
                            .then_some((i, base))
                        })
                        .collect();
                    if structs.is_empty() || of.arg_accesses.is_empty() {
                        continue;
                    }
                    pairs += 1;
                    let hook = HookSpec {
                        name: name.into(),
                        detour: None,
                        criticality: Criticality::Normal,
                        prototype: Some(prototype),
                        trial: false,
                        target: TargetLocator {
                            build: BuildId(old.build.id.0.clone()),
                            rva: Some(of.rva),
                            symbol: None,
                            pattern: None,
                        },
                    };
                    for p in layout::infer(&hook, &o_blind, &n_blind, of, nf) {
                        proposals += 1;
                        let (Some(ol), Some(nl)) =
                            (old.type_layout(&p.name), new.type_layout(&p.name))
                        else {
                            unjudged += 1; // a name the PDB has no layout under (a typedef)
                            continue;
                        };
                        if !layout::changes(ol, nl).is_empty() {
                            changed_structs += 1;
                        }
                        for change in &p.changes {
                            // "offset 0x4 -> 0x8 (...)"
                            let nums: Vec<u64> = change
                                .split_whitespace()
                                .filter_map(|w| w.strip_prefix("0x"))
                                .filter_map(|h| {
                                    u64::from_str_radix(
                                        h.trim_end_matches(|c: char| !c.is_ascii_hexdigit()),
                                        16,
                                    )
                                    .ok()
                                })
                                .collect();
                            let (from, to) = (nums[0], nums[1]);
                            let t = truth(&old, &new, &p.name, &p.name, from);
                            if t == Some(Truth::At(to)) {
                                right += 1;
                            } else if t == Some(Truth::Gone) {
                                renamed += 1;
                            } else {
                                wrong += 1;
                                println!(
                                    "WRONG {project} {flags} {}: {name} {}: {change}",
                                    step[1], p.name
                                );
                            }
                        }
                    }
                }
            }
        }
    }
    println!(
        "{pairs} function pairs with a struct-pointer parameter and accesses; {proposals} proposals \
         ({changed_structs} on structs whose layout changed, {unjudged} under a name without a layout); moves: \
         {right} right, {wrong} wrong, {renamed} of a renamed or removed field (not judged)"
    );
    // A baseline, like the corpus gate's: proposals are review suggestions (never applied), so a wrong move costs
    // a reviewer's look, not a wrong relocation. Measured 2026-11-08: 1087 right, 11 wrong (single accesses the
    // alignment paired with another field). Lower it when that improves; raise it only with a reason.
    assert!(
        wrong <= MAX_WRONG_MOVES,
        "{wrong} inferred moves the PDBs contradict (baseline {MAX_WRONG_MOVES})"
    );
}

/// Inferred moves the PDBs contradict, at most (the measured baseline).
const MAX_WRONG_MOVES: usize = 11;

/// What the PDBs say about a proposed move.
#[derive(Debug, PartialEq)]
enum Truth {
    /// The new offset of what the old layout has there.
    At(u64),
    /// The field holding it was renamed or removed: matching by name can't say.
    Gone,
}

/// Where the PDBs put, in the new layout `new_name`, what the old layout `old_name` has at `offset`: the field
/// holding it, matched by name, recursing into nested structs (each side by its own type name: zstd 1.5.7 renamed
/// `seqStore_t` to `SeqStore_t`); inside a scalar or an array the same position, if the field kept its size.
/// `None` when it can't be followed.
fn truth(
    old: &AnalysisExport,
    new: &AnalysisExport,
    old_name: &str,
    new_name: &str,
    offset: u64,
) -> Option<Truth> {
    let (ol, nl) = (old.type_layout(old_name)?, new.type_layout(new_name)?);
    let f = ol
        .fields
        .iter()
        .find(|f| f.bits.is_none() && f.offset <= offset && offset < f.offset + f.size.max(1))?;
    let Some(g) = nl.fields.iter().find(|g| g.name == f.name) else {
        return Some(Truth::Gone);
    };
    let inner = offset - f.offset;
    let nested = |ty: &str| {
        ty.trim_start_matches("struct ")
            .trim_start_matches("union ")
            .trim()
            .to_owned()
    };
    let (of, nf) = (nested(&f.ty), nested(&g.ty));
    if !of.contains(['*', '[']) && old.type_layout(&of).is_some() && new.type_layout(&nf).is_some()
    {
        return match truth(old, new, &of, &nf, inner)? {
            Truth::At(i) => Some(Truth::At(g.offset + i)),
            Truth::Gone => Some(Truth::Gone),
        };
    }
    (g.size == f.size).then_some(Truth::At(g.offset + inner))
}
