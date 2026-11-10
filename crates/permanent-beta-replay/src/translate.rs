//! Layout translation (design §7.3): recorded memory of a struct in the old build's layout, rewritten into the
//! new build's layout by field name, so a replay can feed it to the new code.
//!
//! Fields correspond **by name** (the PDB is the evidence, as for struct layout proposals), with:
//! - the same size and bit position, and an equivalent type: the same name; a renamed type ([`Types`]: an old
//!   struct the new build doesn't have, and the one new struct with the same structure, as zstd 1.5.7 renamed
//!   `seqStore_t` to `SeqStore_t`); a renamed enum of the same size **[Guess]**: enumerators aren't compared; or
//!   any pointer (the bytes are an address; what it points to is translated as its own region);
//! - a by-value struct whose layout changed is translated field by field, the same way.
//!
//! A field the new layout lacks (removed) is dropped: the new code has no name to read it by, and whatever now
//! sits at its offset gets its own field's value. A field only the new layout has (added) has no recorded value:
//! its bytes are [`Translated::unknown`], unreadable until the function writes them and never compared. A field
//! whose size, bits or type differ can't be rewritten soundly: the case is inconclusive. Bytes outside fields
//! (padding) are zero and never compared.

use permanent_beta_model::{FieldLayout, TypeLayout};
use std::collections::BTreeMap;
use std::ops::Range;

/// Old-layout bytes rewritten into the new layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Translated {
    pub bytes: Vec<u8>,
    /// The byte ranges of fields both layouts have: the only bytes a comparison may look at.
    pub fields: Vec<Range<usize>>,
    /// The byte ranges of fields only the new layout has: no recorded value, so unreadable until written.
    pub unknown: Vec<Range<usize>>,
}

/// Same size and every field at the same place: the bytes can be used as recorded.
pub fn same_layout(old: &TypeLayout, new: &TypeLayout) -> bool {
    old.size == new.size && old.fields == new.fields
}

/// The field ranges of a layout (for comparing an untranslated region field by field).
pub fn field_ranges(l: &TypeLayout) -> Vec<Range<usize>> {
    l.fields
        .iter()
        .map(|f| f.offset as usize..(f.offset + f.size) as usize)
        .collect()
}

/// Both builds' layouts, and the struct renames between them.
#[derive(Debug, Clone, Default)]
pub struct Types<'a> {
    old: BTreeMap<&'a str, &'a TypeLayout>,
    new: BTreeMap<&'a str, &'a TypeLayout>,
    /// Old struct name → new struct name, for structs only one side has a layout of.
    renames: BTreeMap<String, String>,
}

/// How many levels of by-value structs are translated. **[Guess]**
const MAX_DEPTH: u32 = 4;

impl<'a> Types<'a> {
    /// A struct the old build has and the new one doesn't is renamed to the new-only struct with the same size and
    /// fields (names, offsets, sizes, bits, and types equal ignoring case), if there's exactly one, and only one old
    /// struct claims it. Anything else stays unmapped.
    pub fn new(old: &'a [TypeLayout], new: &'a [TypeLayout]) -> Self {
        let old_map: BTreeMap<&str, &TypeLayout> =
            old.iter().map(|l| (l.name.as_str(), l)).collect();
        let new_map: BTreeMap<&str, &TypeLayout> =
            new.iter().map(|l| (l.name.as_str(), l)).collect();
        let shaped = |a: &TypeLayout, b: &TypeLayout| {
            a.size == b.size
                && a.union == b.union
                && a.fields.len() == b.fields.len()
                && a.fields.iter().zip(&b.fields).all(|(x, y)| {
                    x.name == y.name
                        && x.offset == y.offset
                        && x.size == y.size
                        && x.bits == y.bits
                        && similar_type(&x.ty, &y.ty)
                })
        };
        let only_old: Vec<&TypeLayout> = old
            .iter()
            .filter(|l| !new_map.contains_key(l.name.as_str()))
            .collect();
        let only_new: Vec<&TypeLayout> = new
            .iter()
            .filter(|l| !old_map.contains_key(l.name.as_str()))
            .collect();
        let mut renames = BTreeMap::new();
        for o in &only_old {
            let candidates: Vec<&&TypeLayout> = only_new.iter().filter(|n| shaped(o, n)).collect();
            let [n] = candidates.as_slice() else {
                continue;
            };
            if only_old.iter().filter(|x| shaped(x, n)).count() == 1 {
                renames.insert(o.name.clone(), n.name.clone());
            }
        }
        Self {
            old: old_map,
            new: new_map,
            renames,
        }
    }

    /// The new build's layout for the old build's struct `name`: the same name, or its rename.
    pub fn new_layout(&self, name: &str) -> Option<&'a TypeLayout> {
        self.new
            .get(name)
            .or_else(|| {
                self.renames
                    .get(name)
                    .and_then(|r| self.new.get(r.as_str()))
            })
            .copied()
    }

    /// Two field types that hold the same bytes.
    fn equivalent(&self, old: &FieldLayout, new: &FieldLayout) -> bool {
        let (a, b) = (old.ty.as_str(), new.ty.as_str());
        if a == b || (a.ends_with('*') && b.ends_with('*')) {
            return true;
        }
        if similar_type(a, b) && !(by_value_struct(a).is_some() && by_value_struct(b).is_some()) {
            return true; // same size checked by the caller
        }
        match (by_value_struct(a), by_value_struct(b)) {
            (Some(x), Some(y)) => self.renames.get(x).is_some_and(|r| r == y),
            _ => false,
        }
    }

    fn translate_into(
        &self,
        old: &TypeLayout,
        new: &TypeLayout,
        bytes: &[u8],
        out: &mut Translated,
        base: usize,
        depth: u32,
    ) -> Result<(), String> {
        for n in &new.fields {
            let (dst, len) = (base + n.offset as usize, n.size as usize);
            if out.bytes.get(dst..dst + len).is_none() {
                return Err(format!("{}.{} lies outside the struct", new.name, n.name));
            }
            let Some(o) = old.fields.iter().find(|o| o.name == n.name) else {
                out.unknown.push(dst..dst + len);
                continue;
            };
            if o.bits != n.bits {
                return Err(format!("{}.{} changed its bits", new.name, n.name));
            }
            if n.bits.is_some() && o.offset != n.offset {
                // A moved bitfield shares its unit with other fields: copying the unit would copy them too.
                return Err(format!("{}.{} is a bitfield that moved", new.name, n.name));
            }
            let src = o.offset as usize;
            let Some(from) = bytes.get(src..src + o.size as usize) else {
                return Err(format!("{}.{} lies outside the struct", old.name, o.name));
            };
            // A struct by value (the same one, or its rename) with both layouts known: field by field, whether or
            // not its layout changed.
            let nested = by_value_struct(&o.ty)
                .zip(by_value_struct(&n.ty))
                .filter(|(x, y)| x == y || self.renames.get(*x).is_some_and(|r| r == y))
                .and_then(|(x, y)| Some((*self.old.get(x)?, *self.new.get(y)?)))
                .filter(|(x, y)| x.size == o.size && y.size == n.size && depth < MAX_DEPTH);
            if let Some((x, y)) = nested {
                self.translate_into(x, y, from, out, dst, depth + 1)?;
                continue;
            }
            if o.size == n.size && self.equivalent(o, n) {
                out.bytes[dst..dst + len].copy_from_slice(from);
                out.fields.push(dst..dst + len);
                continue;
            }
            return Err(format!(
                "{}.{} changed ({} {} bytes -> {} {} bytes)",
                new.name, n.name, o.ty, o.size, n.ty, n.size
            ));
        }
        Ok(())
    }

    /// Rewrites `bytes` (`old.size` long) into the `new` layout. `Err` names the first field that doesn't map.
    pub fn translate(
        &self,
        old: &TypeLayout,
        new: &TypeLayout,
        bytes: &[u8],
    ) -> Result<Translated, String> {
        if bytes.len() as u64 != old.size {
            return Err(format!(
                "{} bytes recorded, but {} is {} bytes in the old build",
                bytes.len(),
                old.name,
                old.size
            ));
        }
        let mut out = Translated {
            bytes: vec![0u8; new.size as usize],
            fields: Vec::new(),
            unknown: Vec::new(),
        };
        self.translate_into(old, new, bytes, &mut out, 0, 0)?;
        Ok(out)
    }
}

/// Two type names that hold the same kind of bytes at the same size: equal ignoring case (zstd 1.5.7's
/// `seqStore_t` → `SeqStore_t`), both pointers, both enums **[Guess]**: enumerators aren't compared, or both
/// integers **[Guess]**: a signedness change (`unsigned int` → `int`) keeps the bytes. Sizes are compared by the
/// caller.
fn similar_type(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
        || (a.ends_with('*') && b.ends_with('*'))
        || (a.starts_with("enum ") && b.starts_with("enum "))
        || (is_integer(a) && is_integer(b))
}

/// A built-in integer type name (`int`, `unsigned __int64`, `char`, ...), not `bool`, a float or a pointer.
fn is_integer(ty: &str) -> bool {
    let t = ty.strip_prefix("const ").unwrap_or(ty);
    let t = t
        .strip_prefix("unsigned ")
        .or_else(|| t.strip_prefix("signed "))
        .unwrap_or(t);
    matches!(
        t,
        "char"
            | "short"
            | "int"
            | "long"
            | "long long"
            | "__int64"
            | "int8_t"
            | "int16_t"
            | "int32_t"
            | "int64_t"
    ) || matches!(
        ty,
        "unsigned" | "uint8_t" | "uint16_t" | "uint32_t" | "uint64_t" | "size_t"
    )
}

/// `struct X` or `union X` (not a pointer or an array) → `X`.
fn by_value_struct(ty: &str) -> Option<&str> {
    if ty.contains('*') || ty.contains('[') || ty.contains('&') {
        return None;
    }
    ty.strip_prefix("struct ")
        .or_else(|| ty.strip_prefix("union "))
}

/// [`Types::translate`] with only the two layouts known (no renames, no nested structs).
pub fn translate(old: &TypeLayout, new: &TypeLayout, bytes: &[u8]) -> Result<Translated, String> {
    Types::default().translate(old, new, bytes)
}

#[cfg(test)]
#[allow(clippy::single_range_in_vec_init)] // byte ranges, one of them
mod tests {
    use super::*;

    fn field(name: &str, offset: u64, size: u64, ty: &str) -> FieldLayout {
        FieldLayout {
            name: name.into(),
            offset,
            size,
            ty: ty.into(),
            bits: None,
        }
    }

    fn named(name: &str, fields: Vec<FieldLayout>, size: u64) -> TypeLayout {
        TypeLayout {
            name: name.into(),
            size,
            union: false,
            fields,
        }
    }

    fn layout(fields: Vec<FieldLayout>, size: u64) -> TypeLayout {
        named("Config", fields, size)
    }

    // The `basic` fixture's S5: v2 inserts a field before `b`.
    fn v1() -> TypeLayout {
        layout(vec![field("a", 0, 4, "int"), field("b", 4, 4, "int")], 8)
    }

    #[test]
    fn a_moved_field_is_copied_to_its_new_offset() {
        let v2 = layout(vec![field("b", 0, 4, "int"), field("a", 4, 4, "int")], 8);
        let t = translate(&v1(), &v2, &[1, 0, 0, 0, 2, 0, 0, 0]).unwrap();
        assert_eq!(t.bytes, [2, 0, 0, 0, 1, 0, 0, 0]);
        assert_eq!(t.fields, [0..4, 4..8]);
        assert!(t.unknown.is_empty());
        assert!(!same_layout(&v1(), &v2));
        assert!(same_layout(&v1(), &v1()));
    }

    #[test]
    fn padding_is_zero_and_not_a_field() {
        let v2 = layout(vec![field("a", 0, 4, "int"), field("b", 8, 4, "int")], 16);
        let t = translate(&v1(), &v2, &[1, 0, 0, 0, 2, 0, 0, 0]).unwrap();
        assert_eq!(t.bytes, [1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(t.fields, [0..4, 8..12]);
    }

    #[test]
    fn added_fields_are_unknown_and_removed_ones_dropped() {
        // An added field has no recorded value: unknown, not compared.
        let added = layout(
            vec![
                field("a", 0, 4, "int"),
                field("inserted", 4, 4, "int"),
                field("b", 8, 4, "int"),
            ],
            12,
        );
        let t = translate(&v1(), &added, &[1, 0, 0, 0, 2, 0, 0, 0]).unwrap();
        assert_eq!(t.bytes, [1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0]);
        assert_eq!((t.fields, t.unknown), (vec![0..4, 8..12], vec![4..8]));
        // A removed field is dropped: what's left is translated.
        let removed = layout(vec![field("a", 0, 4, "int")], 4);
        let t = translate(&v1(), &removed, &[1, 0, 0, 0, 2, 0, 0, 0]).unwrap();
        assert_eq!((t.bytes, t.fields), (vec![1, 0, 0, 0], vec![0..4]));
        // A renamed field is removed plus added: its value is never carried over by guess.
        let renamed = layout(vec![field("a", 0, 4, "int"), field("bee", 4, 4, "int")], 8);
        let t = translate(&v1(), &renamed, &[1, 0, 0, 0, 2, 0, 0, 0]).unwrap();
        assert_eq!(
            (t.bytes, t.unknown),
            (vec![1, 0, 0, 0, 0, 0, 0, 0], vec![4..8])
        );
    }

    #[test]
    fn fields_that_dont_map_are_refused() {
        // Negative: a widened field.
        let wider = layout(
            vec![field("a", 0, 4, "int"), field("b", 8, 8, "long long")],
            16,
        );
        assert!(
            translate(&v1(), &wider, &[0; 8])
                .unwrap_err()
                .contains("b changed")
        );
        // Negative: the same size, another type.
        let float = layout(vec![field("a", 0, 4, "int"), field("b", 4, 4, "float")], 8);
        assert!(
            translate(&v1(), &float, &[0; 8])
                .unwrap_err()
                .contains("b changed")
        );
        // Negative: the recording isn't the old layout's size.
        assert!(translate(&v1(), &v1(), &[0; 4]).is_err());
    }

    #[test]
    fn a_moved_bitfield_is_refused() {
        let mut old = v1();
        old.fields[1].bits = Some((0, 3));
        let mut new = old.clone();
        new.fields[1].offset = 0;
        new.fields[0].offset = 4;
        assert!(
            translate(&old, &new, &[0; 8])
                .unwrap_err()
                .contains("bitfield")
        );
    }

    /// zstd 1.5.6 → 1.5.7's shape: `seqStore_t` renamed `SeqStore_t` (same fields), held by value in a context
    /// that also gains a field, removes one, and renames an enum and a pointer's type.
    fn zstd_like() -> (Vec<TypeLayout>, Vec<TypeLayout>) {
        let seq = |name: &str| {
            named(
                name,
                vec![
                    field("lit", 0, 8, "unsigned char*"),
                    field("n", 8, 4, "int"),
                ],
                16,
            )
        };
        let old = vec![
            seq("seqStore_t"),
            named(
                "CCtx",
                vec![
                    field("stage", 0, 4, "enum ZSTD_cStage"),
                    field("blockSize", 4, 4, "unsigned int"),
                    field("seqStore", 8, 16, "struct seqStore_t"),
                    field("ext", 24, 8, "struct rawSeqStore_t*"),
                ],
                32,
            ),
        ];
        let new = vec![
            seq("SeqStore_t"),
            named(
                "CCtx",
                vec![
                    field("stage", 0, 4, "enum ZSTD_CStage"),
                    field("blockSizeMax", 4, 4, "unsigned long long"),
                    field("seqStore", 8, 16, "struct SeqStore_t"),
                    field("ext", 24, 8, "struct RawSeqStore_t*"),
                ],
                32,
            ),
        ];
        (old, new)
    }

    #[test]
    fn renamed_types_translate_by_structure() {
        let (old, new) = zstd_like();
        let types = Types::new(&old, &new);
        assert_eq!(
            types.new_layout("seqStore_t").map(|l| l.name.as_str()),
            Some("SeqStore_t")
        );
        let bytes: Vec<u8> = (0..32).collect();
        let t = types.translate(&old[1], &new[1], &bytes).unwrap();
        // stage, seqStore (field by field: its padding isn't compared) and ext carried over; blockSize dropped,
        // blockSizeMax unknown.
        assert_eq!(t.fields, [0..4, 8..16, 16..20, 24..32]);
        assert_eq!(t.unknown, [4..8]);
        assert_eq!(&t.bytes[8..20], &bytes[8..20]);
        assert_eq!(&t.bytes[20..24], &[0; 4], "padding is zero");
        assert_eq!(&t.bytes[24..32], &bytes[24..32]);
        // Negative: without the old layouts there's no rename, so the by-value field can't be mapped.
        let e = translate(&old[1], &new[1], &bytes).unwrap_err();
        assert!(e.contains("seqStore changed"), "{e}");
    }

    #[test]
    fn same_size_integers_and_enums_are_the_same_bytes() {
        let old = layout(
            vec![
                field("a", 0, 4, "unsigned int"),
                field("b", 4, 4, "enum Mode_e"),
            ],
            8,
        );
        let new = layout(
            vec![
                field("a", 0, 4, "int"),
                field("b", 4, 4, "enum ZSTD_Mode_e"),
            ],
            8,
        );
        let t = translate(&old, &new, &[1, 0, 0, 0, 2, 0, 0, 0]).unwrap();
        assert_eq!(t.fields, [0..4, 4..8]);
        // Negative: an integer that became a float, or a pointer that became an integer, of the same size.
        let float = layout(
            vec![field("a", 0, 4, "float"), field("b", 4, 4, "enum Mode_e")],
            8,
        );
        assert!(translate(&old, &float, &[0; 8]).is_err());
        let ptr_old = layout(vec![field("p", 0, 8, "char*")], 8);
        let ptr_new = layout(vec![field("p", 0, 8, "unsigned __int64")], 8);
        assert!(translate(&ptr_old, &ptr_new, &[0; 8]).is_err());
        assert!(!is_integer("bool") && !is_integer("double") && is_integer("unsigned __int64"));
    }

    #[test]
    fn a_rename_needs_one_structural_match() {
        // Negative: two new-only structs with the same structure: which one it became is a guess.
        let (old, mut new) = zstd_like();
        let mut twin = new[0].clone();
        twin.name = "SeqStoreTwin".into();
        new.push(twin);
        assert!(Types::new(&old, &new).new_layout("seqStore_t").is_none());
        // Negative: a new-only struct with another field.
        let (old, mut new) = zstd_like();
        new[0].fields[1].name = "count".into();
        assert!(Types::new(&old, &new).new_layout("seqStore_t").is_none());
    }

    #[test]
    fn a_changed_nested_struct_is_translated_field_by_field() {
        let inner_old = named(
            "Params",
            vec![field("level", 0, 4, "int"), field("split", 4, 4, "int")],
            8,
        );
        let inner_new = named(
            "Params",
            vec![field("pre", 0, 4, "int"), field("level", 4, 4, "int")],
            8,
        );
        let outer = |p: &TypeLayout| {
            named(
                "Ctx",
                vec![
                    field("id", 0, 4, "int"),
                    field("params", 4, p.size, "struct Params"),
                ],
                12,
            )
        };
        let (old, new) = (
            vec![inner_old.clone(), outer(&inner_old)],
            vec![inner_new.clone(), outer(&inner_new)],
        );
        let types = Types::new(&old, &new);
        let t = types
            .translate(&old[1], &new[1], &[1, 0, 0, 0, 7, 0, 0, 0, 9, 0, 0, 0])
            .unwrap();
        // id, then params.level moved to its new offset; params.pre unknown; params.split dropped.
        assert_eq!(t.bytes, [1, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0]);
        assert_eq!((t.fields, t.unknown), (vec![0..4, 8..12], vec![4..8]));
    }
}
