//! Layout translation (design §7.3): recorded memory of a struct in the old build's layout, rewritten into the
//! new build's layout by field name, so a replay can feed it to the new code.
//!
//! Fields correspond **by name** (the PDB is the evidence, as for struct layout proposals). Every field of either
//! layout must have its counterpart with the same size, type and bit position; otherwise there's no sound way to
//! build the new bytes (or to compare what the function wrote), and the case is inconclusive. Bytes outside
//! fields (padding) are zero in the result and never compared.

use permanent_beta_model::TypeLayout;
use std::ops::Range;

/// Old-layout bytes rewritten into the new layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Translated {
    pub bytes: Vec<u8>,
    /// The byte ranges of the new layout's fields: the only bytes a comparison may look at.
    pub fields: Vec<Range<usize>>,
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

/// Rewrites `bytes` (`old.size` long) into the `new` layout. `Err` names the first field that doesn't map.
pub fn translate(old: &TypeLayout, new: &TypeLayout, bytes: &[u8]) -> Result<Translated, String> {
    if bytes.len() as u64 != old.size {
        return Err(format!(
            "{} bytes recorded, but {} is {} bytes in the old build",
            bytes.len(),
            old.name,
            old.size
        ));
    }
    for o in &old.fields {
        if !new.fields.iter().any(|n| n.name == o.name) {
            return Err(format!(
                "{}.{} is gone from the new layout",
                old.name, o.name
            ));
        }
    }
    let mut out = vec![0u8; new.size as usize];
    let mut fields = Vec::new();
    for n in &new.fields {
        let Some(o) = old.fields.iter().find(|o| o.name == n.name) else {
            return Err(format!(
                "{}.{} is new: the recording has no value for it",
                new.name, n.name
            ));
        };
        if o.size != n.size || o.ty != n.ty || o.bits != n.bits {
            return Err(format!(
                "{}.{} changed ({} {} bytes -> {} {} bytes)",
                new.name, n.name, o.ty, o.size, n.ty, n.size
            ));
        }
        if n.bits.is_some() && o.offset != n.offset {
            // A moved bitfield shares its unit with other fields: copying the unit would copy them too.
            return Err(format!("{}.{} is a bitfield that moved", new.name, n.name));
        }
        let (src, dst) = (o.offset as usize, n.offset as usize);
        let len = n.size as usize;
        let (Some(from), Some(to)) = (bytes.get(src..src + len), out.get_mut(dst..dst + len))
        else {
            return Err(format!("{}.{} lies outside the struct", new.name, n.name));
        };
        to.copy_from_slice(from);
        fields.push(dst..dst + len);
    }
    Ok(Translated { bytes: out, fields })
}

#[cfg(test)]
mod tests {
    use super::*;
    use permanent_beta_model::FieldLayout;

    fn field(name: &str, offset: u64, size: u64, ty: &str) -> FieldLayout {
        FieldLayout {
            name: name.into(),
            offset,
            size,
            ty: ty.into(),
            bits: None,
        }
    }

    fn layout(fields: Vec<FieldLayout>, size: u64) -> TypeLayout {
        TypeLayout {
            name: "Config".into(),
            size,
            union: false,
            fields,
        }
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
    fn fields_that_dont_map_are_refused() {
        // Negative: an added field has no recorded value.
        let added = layout(
            vec![
                field("a", 0, 4, "int"),
                field("inserted", 4, 4, "int"),
                field("b", 8, 4, "int"),
            ],
            12,
        );
        let e = translate(&v1(), &added, &[0; 8]).unwrap_err();
        assert!(e.contains("inserted is new"), "{e}");
        // Negative: a removed field.
        let removed = layout(vec![field("a", 0, 4, "int")], 4);
        assert!(
            translate(&v1(), &removed, &[0; 8])
                .unwrap_err()
                .contains("b is gone")
        );
        // Negative: a renamed field is removed plus added, never guessed.
        let renamed = layout(vec![field("a", 0, 4, "int"), field("bee", 4, 4, "int")], 8);
        assert!(translate(&v1(), &renamed, &[0; 8]).is_err());
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
}
