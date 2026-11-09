//! Struct layout adaptation (design §7.2): when a struct the hook's prototype uses changed layout between the
//! builds, the hook goes to review with what changed, the new definition and offset constants.
//!
//! Evidence is both builds' PDB types (`pbeta analyze --pdb` records the layouts signatures use). Fields
//! correspond **by name**: a renamed field shows as one removed and one added, never as a guess. Without a
//! layout on both sides there's no proposal: the native analyzer can't see struct layouts. Nothing here is
//! applied; the detour body is never rewritten.

use crate::prototype::Prototype;
use permanent_beta_model::{
    AnalysisExport, ArgAccess, FieldLayout, FunctionFeatures, HookSpec, StructLayoutProposal,
    TypeLayout,
};

/// The aligned accesses must cover at least this share of both functions' accesses through the argument, or the
/// code changed too much to tell a moved field from new code. **[Guess]**
pub const MIN_ALIGNED_SHARE: f64 = 0.5;

/// The struct names a prototype's parameters and return type use: `const Config* c` → `Config`, `struct
/// Order*` → `Order`. Built-in types come out too; callers keep only names a PDB defines.
pub fn type_names(prototype: &str) -> Vec<String> {
    let Some(proto) = Prototype::parse(prototype) else {
        return Vec::new();
    };
    let mut out: Vec<String> = std::iter::once(proto.head.as_str())
        .chain(proto.params.iter().map(|p| p.ty.as_str()))
        .filter_map(base_name)
        .collect();
    out.sort();
    out.dedup();
    out
}

/// The named type in a C type: qualifiers, `struct`/`class`/`union`, pointers, references and the calling
/// convention dropped. The last identifier wins (`int __fastcall` → `__fastcall` isn't a struct either way).
fn base_name(ty: &str) -> Option<String> {
    const SKIP: [&str; 9] = [
        "const",
        "volatile",
        "struct",
        "class",
        "union",
        "enum",
        "__cdecl",
        "__fastcall",
        "__stdcall",
    ];
    ty.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == ':'))
        .rfind(|w| !w.is_empty() && !SKIP.contains(w))
        .map(str::to_owned)
}

/// One line per difference between two layouts of a struct, fields matched by name. Empty if equal.
pub fn changes(old: &TypeLayout, new: &TypeLayout) -> Vec<String> {
    let mut out = Vec::new();
    if old.size != new.size {
        out.push(format!("size: {:#x} -> {:#x}", old.size, new.size));
    }
    let find = |l: &'_ TypeLayout, name: &str| -> Option<FieldLayout> {
        l.fields.iter().find(|f| f.name == name).cloned()
    };
    for o in &old.fields {
        match find(new, &o.name) {
            None => out.push(format!("{}: removed (was at {:#x})", o.name, o.offset)),
            Some(n) => {
                if o.offset != n.offset {
                    out.push(format!(
                        "{}: offset {:#x} -> {:#x}",
                        o.name, o.offset, n.offset
                    ));
                }
                if o.size != n.size {
                    out.push(format!("{}: size {} -> {}", o.name, o.size, n.size));
                }
                if o.ty != n.ty {
                    out.push(format!("{}: type {} -> {}", o.name, o.ty, n.ty));
                }
                if o.bits != n.bits {
                    out.push(format!("{}: bits {:?} -> {:?}", o.name, o.bits, n.bits));
                }
            }
        }
    }
    for n in &new.fields {
        if find(old, &n.name).is_none() {
            out.push(format!("{}: added at {:#x}", n.name, n.offset));
        }
    }
    out
}

/// A proposal for each struct the hook's prototype uses whose layout differs between `old` and `new`.
pub fn propose(
    hook: &HookSpec,
    old: &AnalysisExport,
    new: &AnalysisExport,
) -> Vec<StructLayoutProposal> {
    let Some(prototype) = hook.prototype.as_deref() else {
        return Vec::new();
    };
    type_names(prototype)
        .iter()
        .filter_map(|name| {
            let (o, n) = (old.type_layout(name)?, new.type_layout(name)?);
            let changes = changes(o, n);
            (!changes.is_empty()).then(|| StructLayoutProposal {
                name: name.clone(),
                old_size: o.size,
                new_size: n.size,
                changes,
                definition: definition(n),
                offsets: offsets(n),
                basis: None,
            })
        })
        .collect()
}

/// Struct changes inferred without PDB types (design §7.2): for each struct-pointer parameter of the hook's
/// prototype (the first four, passed in registers) whose struct isn't in both builds' PDB types, the old and new
/// function's accesses through it (`FunctionFeatures::arg_accesses`) are aligned in order on (size, read or
/// write), and every offset whose aligned accesses all moved to one new offset is a proposed move: `offset 0x4 ->
/// 0x8`. No proposal when an offset's accesses disagree, the offsets don't keep their order (a field inserted or
/// removed shifts the ones after it; a crossing is reordered code), the aligned accesses cover less than
/// [`MIN_ALIGNED_SHARE`] of either side, or nothing moved. Field names and sizes are
/// unknown, so it says offsets only; it's a guess for review (`basis`), never applied.
pub fn infer(
    hook: &HookSpec,
    old_build: &AnalysisExport,
    new_build: &AnalysisExport,
    old: &FunctionFeatures,
    new: &FunctionFeatures,
) -> Vec<StructLayoutProposal> {
    let Some(proto) = hook.prototype.as_deref().and_then(Prototype::parse) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (slot, p) in proto.params.iter().enumerate().take(4) {
        if p.ty.matches('*').count() != 1 {
            continue;
        }
        let Some(name) = base_name(&p.ty) else {
            continue;
        };
        let builtin = matches!(
            name.as_str(),
            "void"
                | "char"
                | "short"
                | "int"
                | "long"
                | "float"
                | "double"
                | "bool"
                | "unsigned"
                | "signed"
                | "wchar_t"
                | "size_t"
                | "uint8_t"
                | "int8_t"
                | "uint16_t"
                | "int16_t"
                | "uint32_t"
                | "int32_t"
                | "uint64_t"
                | "int64_t"
                | "BYTE"
                | "WORD"
                | "DWORD"
                | "__int64"
        );
        if builtin
            || (old_build.type_layout(&name).is_some() && new_build.type_layout(&name).is_some())
        {
            continue; // not a struct, or the PDB knows it exactly (`propose`)
        }
        let through = |f: &FunctionFeatures| -> Vec<ArgAccess> {
            f.arg_accesses
                .iter()
                .filter(|a| usize::from(a.slot) == slot)
                .copied()
                .collect()
        };
        let (a, b) = (through(old), through(new));
        if let Some(moves) = moved_offsets(&a, &b) {
            let changes: Vec<String> = moves
                .iter()
                .map(|(o, n, size, count)| {
                    format!(
                        "offset {o:#x} -> {n:#x} ({size} bytes, {count} access{})",
                        if *count == 1 { "" } else { "es" }
                    )
                })
                .collect();
            let constants: String = moves
                .iter()
                .map(|(o, n, ..)| {
                    format!(
                        "constexpr size_t {}_at_{o:#x} = {n:#x};  // was {o:#x}\n",
                        ident(&name)
                    )
                })
                .collect();
            out.push(StructLayoutProposal {
                name: name.clone(),
                old_size: 0,
                new_size: 0,
                definition: format!(
                    "// {name}: inferred from where the old and new function access it through argument {} (no PDB \
                     types): field names and sizes are unknown.\n{}",
                    slot + 1,
                    changes
                        .iter()
                        .map(|c| format!("// {c}\n"))
                        .collect::<String>()
                ),
                offsets: constants,
                changes,
                basis: Some(format!(
                    "inferred from the functions' accesses through argument {} (no PDB layout of {name} in both \
                     builds): a guess for review",
                    slot + 1
                )),
            });
        }
    }
    out
}

/// Aligns two access sequences (longest common subsequence on size and read/write) and returns the offsets that
/// moved: (old, new, size, aligned accesses). `None` when they disagree, cover too little, or nothing moved.
fn moved_offsets(a: &[ArgAccess], b: &[ArgAccess]) -> Option<Vec<(u32, u32, u8, usize)>> {
    if a.is_empty() || b.is_empty() {
        return None;
    }
    let same = |x: &ArgAccess, y: &ArgAccess| x.size == y.size && x.write == y.write;
    let (n, m) = (a.len(), b.len());
    let mut lcs = vec![vec![0usize; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[i][j] = if same(&a[i], &b[j]) {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }
    let mut pairs = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < n && j < m {
        if same(&a[i], &b[j]) && lcs[i][j] == lcs[i + 1][j + 1] + 1 {
            pairs.push((a[i], b[j]));
            i += 1;
            j += 1;
        } else if lcs[i + 1][j] >= lcs[i][j + 1] {
            i += 1;
        } else {
            j += 1;
        }
    }
    let share = |k: usize| pairs.len() as f64 / k as f64;
    if share(n) < MIN_ALIGNED_SHARE || share(m) < MIN_ALIGNED_SHARE {
        return None;
    }
    // Old offset -> (new offset, size, count); every aligned access of an old offset must agree.
    let mut map: std::collections::BTreeMap<u32, (u32, u8, usize)> = Default::default();
    for (x, y) in &pairs {
        let e = map.entry(x.offset).or_insert((y.offset, x.size, 0));
        if e.0 != y.offset {
            return None;
        }
        e.2 += 1;
    }
    // A field inserted or removed shifts the fields after it but keeps their order: across every aligned pair,
    // moved or not, a later old offset must have a later new offset. A crossing (two fields swapping, one moving
    // past another, two landing on one) is the compiler reordering accesses, not a layout change.
    let order: Vec<u32> = map.values().map(|v| v.0).collect();
    if order.windows(2).any(|w| w[0] >= w[1]) {
        return None;
    }
    let moves: Vec<(u32, u32, u8, usize)> = map
        .into_iter()
        .filter(|(o, (n, ..))| o != n)
        .map(|(o, (n, size, count))| (o, n, size, count))
        .collect();
    (!moves.is_empty()).then_some(moves)
}

/// A C identifier for a (possibly qualified) type name: `tinyxml2::XMLNode` → `tinyxml2_XMLNode`.
fn ident(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

/// The layout as a C definition with each field's offset, for reading next to the old one. Base classes and the
/// vtable pointer are comments: they can't be declared as members.
fn definition(l: &TypeLayout) -> String {
    let kind = if l.union { "union" } else { "struct" };
    let mut s = format!("{kind} {} {{  // {:#x} bytes\n", l.name, l.size);
    for f in &l.fields {
        let bits = f.bits.map(|(_, w)| format!(" : {w}")).unwrap_or_default();
        if f.name.starts_with('<') {
            s.push_str(&format!(
                "    // {:#06x}: {} ({} bytes)\n",
                f.offset, f.name, f.size
            ));
        } else {
            s.push_str(&format!(
                "    {} {}{bits};  // {:#06x}\n",
                declare(&f.ty),
                f.name,
                f.offset
            ));
        }
    }
    s.push_str("};\n");
    s
}

/// `int[]` (how PDB type names show arrays) can't be declared; show it as a comment-friendly `int /*[]*/`.
fn declare(ty: &str) -> String {
    ty.strip_suffix("[]")
        .map(|t| format!("{t} /*[]*/"))
        .unwrap_or_else(|| ty.to_owned())
}

/// `offsetof` constants for the new layout, checked against a header that declares it.
fn offsets(l: &TypeLayout) -> String {
    let id = ident(&l.name);
    let mut s = format!("// {} in the new build ({:#x} bytes)\n", l.name, l.size);
    s.push_str(&format!(
        "constexpr std::size_t {id}_size = {:#x};\n",
        l.size
    ));
    for f in l
        .fields
        .iter()
        .filter(|f| !f.name.starts_with('<') && f.bits.is_none())
    {
        s.push_str(&format!(
            "constexpr std::size_t {id}_{} = {:#x};\n",
            f.name, f.offset
        ));
    }
    s.push_str(&format!(
        "static_assert(sizeof({}) == {id}_size);\n",
        l.name
    ));
    for f in l
        .fields
        .iter()
        .filter(|f| !f.name.starts_with('<') && f.bits.is_none())
    {
        s.push_str(&format!(
            "static_assert(offsetof({}, {}) == {id}_{});\n",
            l.name, f.name, f.name
        ));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use permanent_beta_model::{BuildId, Criticality, TargetLocator};

    fn field(name: &str, offset: u64) -> FieldLayout {
        FieldLayout {
            name: name.into(),
            offset,
            size: 4,
            ty: "int".into(),
            bits: None,
        }
    }

    fn config(fields: Vec<FieldLayout>, size: u64) -> TypeLayout {
        TypeLayout {
            name: "Config".into(),
            size,
            union: false,
            fields,
        }
    }

    fn export(id: &str, types: Vec<TypeLayout>) -> AnalysisExport {
        let mut e: AnalysisExport = serde_json::from_value(serde_json::json!({
            "schema_version": permanent_beta_model::ANALYSIS_SCHEMA_VERSION,
            "build": { "id": id, "file_name": "t.exe", "version": null, "machine": "x64", "pdb": null },
            "producer": { "tool": "test", "version": "0" },
            "functions": [],
        }))
        .unwrap();
        e.types = types;
        e
    }

    fn hook(prototype: &str) -> HookSpec {
        HookSpec {
            name: "reader".into(),
            detour: None,
            criticality: Criticality::Normal,
            prototype: Some(prototype.into()),
            trial: false,
            target: TargetLocator {
                build: BuildId("a".into()),
                rva: None,
                symbol: None,
                pattern: None,
            },
        }
    }

    // The `basic` fixture's S5: v2 inserts `inserted` before `b`.
    fn v1() -> TypeLayout {
        config(vec![field("a", 0), field("b", 4)], 8)
    }
    fn v2() -> TypeLayout {
        config(vec![field("a", 0), field("inserted", 4), field("b", 8)], 12)
    }

    #[test]
    fn names_the_structs_a_prototype_uses() {
        assert_eq!(
            type_names("int pb_struct_reader(const Config* c)"),
            vec!["Config", "int"]
        );
        assert_eq!(
            type_names("unsigned ship_order(struct Order* o, const char* customer, int discount)"),
            vec!["Order", "char", "int", "unsigned"]
        );
        assert!(type_names("not a prototype").is_empty());
    }

    #[test]
    fn a_moved_field_and_an_added_one_are_reported() {
        assert_eq!(
            changes(&v1(), &v2()),
            vec![
                "size: 0x8 -> 0xc",
                "b: offset 0x4 -> 0x8",
                "inserted: added at 0x4"
            ]
        );
    }

    #[test]
    fn a_changed_struct_in_the_prototype_gets_a_proposal() {
        let p = propose(
            &hook("int pb_struct_reader(const Config* c)"),
            &export("a", vec![v1()]),
            &export("b", vec![v2()]),
        );
        assert_eq!(p.len(), 1);
        assert_eq!(
            (p[0].name.as_str(), p[0].old_size, p[0].new_size),
            ("Config", 8, 12)
        );
        assert!(
            p[0].definition.contains("int b;  // 0x0008"),
            "{}",
            p[0].definition
        );
        assert!(
            p[0].offsets
                .contains("constexpr std::size_t Config_b = 0x8;"),
            "{}",
            p[0].offsets
        );
        assert!(
            p[0].offsets
                .contains("static_assert(offsetof(Config, b) == Config_b);")
        );
    }

    #[test]
    fn an_unchanged_struct_gets_no_proposal() {
        // Negative: the hook app's Order is the same in every version.
        let p = propose(
            &hook("int pb_struct_reader(const Config* c)"),
            &export("a", vec![v1()]),
            &export("b", vec![v1()]),
        );
        assert!(p.is_empty());
    }

    #[test]
    fn no_proposal_without_a_layout_on_both_sides() {
        // Negative: one build analyzed without its PDB.
        let p = propose(
            &hook("int pb_struct_reader(const Config* c)"),
            &export("a", vec![v1()]),
            &export("b", vec![]),
        );
        assert!(p.is_empty());
        // Negative: a struct the prototype doesn't use.
        let p = propose(
            &hook("int other(int x)"),
            &export("a", vec![v1()]),
            &export("b", vec![v2()]),
        );
        assert!(p.is_empty());
    }

    #[test]
    fn a_renamed_field_is_removed_plus_added_never_guessed() {
        let renamed = config(vec![field("a", 0), field("bee", 4)], 8);
        assert_eq!(
            changes(&v1(), &renamed),
            vec!["b: removed (was at 0x4)", "bee: added at 0x4"]
        );
    }

    /// A function reading `accesses` (slot, offset, size, write).
    fn reads(accesses: &[(u8, u32, u8, bool)]) -> FunctionFeatures {
        let mut f: FunctionFeatures =
            serde_json::from_value(serde_json::json!({ "rva": 0x10, "size": 32 })).unwrap();
        f.arg_accesses = accesses
            .iter()
            .map(|&(slot, offset, size, write)| ArgAccess {
                slot,
                offset,
                size,
                write,
            })
            .collect();
        f
    }

    #[test]
    fn a_moved_field_is_inferred_from_the_accesses() {
        // S5: `return c->b * 2 + c->a`, with b moving from 0x4 to 0x8.
        let (o, n) = (export("a", vec![]), export("b", vec![]));
        let p = infer(
            &hook("int reader(const Config* c)"),
            &o,
            &n,
            &reads(&[(0, 4, 4, false), (0, 0, 4, false)]),
            &reads(&[(0, 8, 4, false), (0, 0, 4, false)]),
        );
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].name, "Config");
        assert_eq!(p[0].changes, ["offset 0x4 -> 0x8 (4 bytes, 1 access)"]);
        assert!(p[0].basis.as_deref().unwrap().contains("guess"));
        assert!(
            p[0].offsets.contains("Config_at_0x4 = 0x8"),
            "{}",
            p[0].offsets
        );
    }

    #[test]
    fn no_inference_when_the_accesses_disagree_or_say_nothing() {
        let (o, n) = (export("a", vec![]), export("b", vec![]));
        let h = hook("int reader(const Config* c)");
        let infer = |old: &[(u8, u32, u8, bool)], new: &[(u8, u32, u8, bool)]| {
            infer(&h, &o, &n, &reads(old), &reads(new))
        };
        // Negative: nothing moved.
        assert!(infer(&[(0, 4, 4, false)], &[(0, 4, 4, false)]).is_empty());
        // Negative: one old offset's accesses go to two new offsets.
        assert!(
            infer(
                &[(0, 4, 4, false), (0, 4, 4, false)],
                &[(0, 8, 4, false), (0, 12, 4, false)]
            )
            .is_empty()
        );
        // Negative: two old offsets land on one new offset.
        assert!(
            infer(
                &[(0, 0, 4, false), (0, 4, 4, false)],
                &[(0, 8, 4, false), (0, 8, 4, false)]
            )
            .is_empty()
        );
        // Negative: the code changed too much (one of four accesses aligns).
        assert!(
            infer(
                &[
                    (0, 4, 4, false),
                    (0, 8, 8, false),
                    (0, 16, 8, false),
                    (0, 24, 8, false)
                ],
                &[
                    (0, 8, 4, false),
                    (0, 8, 2, true),
                    (0, 16, 1, false),
                    (0, 24, 2, false)
                ]
            )
            .is_empty()
        );
        // Negative: accesses through another argument, or a pointer to a built-in type.
        assert!(infer(&[(1, 4, 4, false)], &[(1, 8, 4, false)]).is_empty());
        let int = hook("int reader(const int* c)");
        let o2 = export("a", vec![]);
        assert!(
            super::infer(
                &int,
                &o2,
                &n,
                &reads(&[(0, 4, 4, false)]),
                &reads(&[(0, 8, 4, false)])
            )
            .is_empty()
        );
    }

    #[test]
    fn no_inference_when_both_pdbs_know_the_struct() {
        let config = TypeLayout {
            name: "Config".into(),
            size: 8,
            union: false,
            fields: vec![field("a", 0), field("b", 4)],
        };
        let (o, n) = (export("a", vec![config.clone()]), export("b", vec![config]));
        assert!(
            infer(
                &hook("int reader(const Config* c)"),
                &o,
                &n,
                &reads(&[(0, 4, 4, false)]),
                &reads(&[(0, 8, 4, false)])
            )
            .is_empty()
        );
    }
}
