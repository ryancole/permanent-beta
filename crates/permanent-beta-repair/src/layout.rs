//! Struct layout adaptation (design §7.2): when a struct the hook's prototype uses changed layout between the
//! builds, the hook goes to review with what changed, the new definition and offset constants.
//!
//! Evidence is both builds' PDB types (`pbeta analyze --pdb` records the layouts signatures use). Fields
//! correspond **by name**: a renamed field shows as one removed and one added, never as a guess. Without a
//! layout on both sides there's no proposal: the native analyzer can't see struct layouts. Nothing here is
//! applied; the detour body is never rewritten.

use crate::prototype::Prototype;
use permanent_beta_model::{
    AnalysisExport, FieldLayout, HookSpec, StructLayoutProposal, TypeLayout,
};

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
            })
        })
        .collect()
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
}
