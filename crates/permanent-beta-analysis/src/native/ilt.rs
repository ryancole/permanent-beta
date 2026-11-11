//! MSVC's incremental linking table (ILT).
//!
//! An image linked with `/INCREMENTAL` (the Debug default) starts its code with a table of 5-byte `jmp rel32`
//! thunks, one per function, and every direct call goes through a thunk, so the linker can move a function by
//! patching one `jmp`. To the analyzer each thunk looks like a tiny function that calls the real one: its callers
//! are the thunk's, and a changed function sits behind an unmatched "wrapper" in the new build. So the table is
//! found here, each slot becomes its own function (slots nothing calls would otherwise run into the slot before),
//! and `super::analyze_ranges` records calls and code pointers to a slot as calls to its target.
//!
//! Recognized only in its exact shape: at the start of an executable section's file data, after any `int3`
//! padding, at least [`MIN_ILT_SLOTS`] consecutive `E9 rel32` slots, each jumping to code that's in the file and
//! outside the table. A lone `jmp` stub, or jumps anywhere else, aren't ILT thunks.

use super::image::Image;
use std::collections::BTreeMap;

/// Fewest consecutive slots taken for a table. **[Guess]**: an incremental image has one slot per function
/// (dozens even for a small program, the C runtime's included); a few `jmp` stubs in a row by chance are rare.
pub(crate) const MIN_ILT_SLOTS: usize = 4;

const JMP_REL32: u8 = 0xe9;
const SLOT: u32 = 5;

/// The image's ILT, slot RVA → target RVA. Empty if it has none.
pub(crate) fn find(image: &Image) -> BTreeMap<u32, u32> {
    let mut table = BTreeMap::new();
    for s in image
        .sections
        .iter()
        .filter(|s| s.executable && !s.data.is_empty())
    {
        let pad = s.data.iter().take_while(|&&b| b == 0xcc).count() as u32;
        let first = s.rva + pad;
        let mut slots = Vec::new();
        let mut at = first;
        while let Some(b) = image.bytes(at, SLOT as usize)
            && b[0] == JMP_REL32
        {
            let rel = i32::from_le_bytes([b[1], b[2], b[3], b[4]]);
            let Some(target) = (at + SLOT).checked_add_signed(rel) else {
                break;
            };
            slots.push((at, target));
            at += SLOT;
        }
        // A slot that jumps into the table itself (or to nothing in the file) ends it there.
        let end = at;
        let good = slots
            .iter()
            .take_while(|&&(_, t)| {
                !(first..end).contains(&t) && image.is_executable(t) && image.bytes(t, 1).is_some()
            })
            .count();
        if good >= MIN_ILT_SLOTS {
            table.extend(slots.into_iter().take(good));
        }
    }
    table
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::native::image::tests::image;

    /// `n` ILT slots at 0x1005 (after 5 bytes of `int3`), slot i jumping to 0x1100 + 0x10·i, then `int3` up to
    /// 0x1100 and a `ret` at each target.
    pub(crate) fn ilt_code(n: usize) -> Vec<u8> {
        let mut code = vec![0xcc; 5];
        for i in 0..n {
            let at = 0x1005 + 5 * i as u32;
            let target = 0x1100 + 0x10 * i as u32;
            code.push(JMP_REL32);
            code.extend_from_slice(&((target as i32) - (at as i32 + 5)).to_le_bytes());
        }
        code.resize(0x100, 0xcc);
        for _ in 0..n {
            code.push(0xc3);
            code.extend_from_slice(&[0xcc; 15]);
        }
        code
    }

    #[test]
    fn an_incremental_linking_table_is_found() {
        let t = find(&image(&ilt_code(6), &[]));
        assert_eq!(t.len(), 6);
        assert_eq!(t[&0x1005], 0x1100);
        assert_eq!(t[&0x101e], 0x1150);
    }

    #[test]
    fn jumps_outside_the_table_shape_are_not_thunks() {
        // Negative: too few slots in a row.
        assert!(find(&image(&ilt_code(MIN_ILT_SLOTS - 1), &[])).is_empty());
        // Negative: the slots don't start the section (a function comes first).
        let mut code = ilt_code(6);
        code[0] = 0xc3;
        code.insert(0, 0x90);
        code.truncate(0x100);
        assert!(find(&image(&code, &[])).is_empty());
        // Negative: a jump into the table, or past the code in the file, ends it there.
        let mut code = ilt_code(6);
        code[5 + 5 * 2 + 1..5 + 5 * 2 + 5].copy_from_slice(&(-10i32).to_le_bytes());
        assert_eq!(find(&image(&code, &[])).len(), 0, "only 2 good slots");
        let mut code = ilt_code(6);
        code[5 + 5 * 5 + 1..5 + 5 * 5 + 5].copy_from_slice(&0x0010_0000i32.to_le_bytes());
        assert_eq!(find(&image(&code, &[])).len(), 5);
        // Negative: an ordinary image (code starts with a function, not a jump).
        assert!(find(&image(&[0x48, 0x89, 0xc8, 0xc3], &[])).is_empty());
    }
}
