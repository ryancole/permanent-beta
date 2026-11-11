//! Refusing protected and packed binaries (design §12, "Legal: circumvention"; CLAUDE.md non-goals).
//!
//! Permanent Beta doesn't analyze software that's packed, encrypted or virtualized by a protector: getting at its
//! code would mean unpacking it or defeating its protection, which is a non-goal, and in many jurisdictions
//! prohibited regardless of purpose. So the analyzer stops before reading any code when it sees one of:
//!
//! - a section named the way a common protector or packer names its sections by default (UPX, VMProtect,
//!   Themida/WinLicense, Enigma, ASPack, MPRESS, PECompact, Petite, NsPack);
//! - an entry point in a section that's both writable and executable (code that rewrites itself before running:
//!   the usual shape of an unpacking stub);
//! - an executable section with no data in the file (code that only exists once something fills it in at run
//!   time).
//!
//! None of these shapes occurs in what MSVC links, with one exception allowed for: the empty `.textbss` an
//! incrementally linked image starts with (`is_msvc_textbss`), accepted only in its exact shape. A protector that renames its sections and avoids both shapes isn't
//! caught: this is a refusal of the obvious cases, not a guarantee. There's no override.

use super::image::Image;

/// Default section names of common protectors and packers. **[Guess]** at completeness: these are the names the
/// tools use unless told otherwise.
const PROTECTOR_SECTIONS: &[(&str, &str)] = &[
    ("UPX0", "UPX"),
    ("UPX1", "UPX"),
    ("UPX2", "UPX"),
    (".vmp0", "VMProtect"),
    (".vmp1", "VMProtect"),
    (".vmp2", "VMProtect"),
    (".themida", "Themida"),
    (".winlice", "WinLicense"),
    (".enigma1", "Enigma Protector"),
    (".enigma2", "Enigma Protector"),
    (".aspack", "ASPack"),
    (".adata", "ASPack"),
    (".MPRESS1", "MPRESS"),
    (".MPRESS2", "MPRESS"),
    ("PEC2", "PECompact"),
    ("pec1", "PECompact"),
    ("pec2", "PECompact"),
    (".petite", "Petite"),
    (".nsp0", "NsPack"),
    (".nsp1", "NsPack"),
    (".nsp2", "NsPack"),
];

/// The error message for a refused binary.
pub(crate) fn refusal(why: &str) -> String {
    format!(
        "looks protected or packed ({why}); Permanent Beta doesn't analyze protected binaries (design §12)"
    )
}

/// Why `image` looks protected or packed, if it does.
pub(crate) fn detect(image: &Image) -> Option<String> {
    for s in &image.sections {
        if let Some((_, tool)) = PROTECTOR_SECTIONS.iter().find(|(n, _)| *n == s.name) {
            return Some(format!("section {:?} is {tool}'s", s.name));
        }
    }
    if let Some(entry) = image.entry
        && let Some(s) = image
            .sections
            .iter()
            .find(|s| entry >= s.rva && entry - s.rva < s.virtual_size.max(s.data.len() as u32))
        && s.writable
        && s.executable
    {
        return Some(format!(
            "the entry point is in {:?}, a writable and executable section",
            s.name
        ));
    }
    if let Some(s) = image.sections.iter().find(|s| {
        s.executable && s.data.is_empty() && s.virtual_size > 0 && !is_msvc_textbss(image, s)
    }) {
        return Some(format!(
            "executable section {:?} has no data in the file (filled in at run time)",
            s.name
        ));
    }
    None
}

/// The empty `.textbss` MSVC's linker adds to every incrementally linked image (`/INCREMENTAL`, the Debug
/// default): room for Edit and Continue to put recompiled functions while a debugger is attached. Only in its
/// exact shape: named `.textbss`, the first section, writable and executable, no data in the file, and nothing
/// the file holds (entry point, `.pdata`, exports, code pointers in data) inside it. Its code exists only under
/// a debugger, so there's nothing in it to analyze; the rest of the image is ordinary code.
fn is_msvc_textbss(image: &Image, s: &super::image::Section) -> bool {
    let inside = |rva: u32| rva >= s.rva && rva - s.rva < s.virtual_size;
    s.name == ".textbss"
        && image.sections.iter().all(|o| o.rva >= s.rva)
        && s.executable
        && s.writable
        && s.data.is_empty()
        && !image.entry.is_some_and(inside)
        && !image.pdata.iter().any(|f| inside(f.begin))
        && !image.exports.iter().any(|&(rva, _)| inside(rva))
        && !image.code_pointers.iter().any(|&rva| inside(rva))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::image::{RuntimeFunction, Section};

    fn section(name: &str, rva: u32, data: usize, executable: bool, writable: bool) -> Section {
        Section {
            name: name.into(),
            rva,
            virtual_size: 0x1000,
            data: vec![0xcc; data],
            executable,
            writable,
        }
    }

    fn msvc_like() -> Image {
        Image {
            base: 0x1_4000_0000,
            size_of_image: 0x5000,
            entry: Some(0x1010),
            sections: vec![
                section(".text", 0x1000, 0x200, true, false),
                section(".rdata", 0x2000, 0x200, false, false),
                section(".data", 0x3000, 0x200, false, true),
                section(".pdata", 0x4000, 0x200, false, false),
            ],
            ..Default::default()
        }
    }

    #[test]
    fn an_ordinary_msvc_layout_is_accepted() {
        assert_eq!(detect(&msvc_like()), None);
        // .bss-style data with no file bytes is fine: it isn't code.
        let mut i = msvc_like();
        i.sections[2].data.clear();
        assert_eq!(detect(&i), None);
    }

    #[test]
    fn protector_sections_are_refused() {
        // Negative: UPX's and VMProtect's default names.
        let mut i = msvc_like();
        i.sections.push(section("UPX1", 0x5000, 0x200, true, true));
        assert!(detect(&i).unwrap().contains("UPX"));
        let mut i = msvc_like();
        i.sections
            .push(section(".vmp0", 0x5000, 0x200, true, false));
        assert!(detect(&i).unwrap().contains("VMProtect"));
        // A name that only contains one isn't a match.
        let mut i = msvc_like();
        i.sections
            .push(section(".vmp0data", 0x5000, 0x200, false, false));
        assert_eq!(detect(&i), None);
    }

    #[test]
    fn unpacking_shapes_are_refused_under_any_name() {
        // Negative: the entry point in a writable, executable section (renamed sections).
        let mut i = msvc_like();
        i.sections[0].writable = true;
        assert!(detect(&i).unwrap().contains("writable and executable"));
        // Writable and executable code elsewhere, but not at the entry, isn't enough on its own.
        let mut i = msvc_like();
        i.sections.push(section(".stub", 0x5000, 0x200, true, true));
        assert_eq!(detect(&i), None);
        // Negative: executable space with nothing in the file.
        let mut i = msvc_like();
        i.sections.push(section(".code2", 0x5000, 0, true, false));
        assert!(detect(&i).unwrap().contains("no data in the file"));
    }

    /// An incrementally linked MSVC image: an empty, writable and executable `.textbss` first, then `.text`.
    fn incremental() -> Image {
        let mut i = msvc_like();
        for s in &mut i.sections {
            s.rva += 0x1000;
        }
        i.entry = Some(0x2010);
        i.sections
            .insert(0, section(".textbss", 0x1000, 0, true, true));
        i.pdata = vec![RuntimeFunction {
            begin: 0x2000,
            end: 0x2010,
            chained: false,
            parent: None,
        }];
        i.exports = vec![(0x2000, "f".into())];
        i.code_pointers = vec![0x2000];
        i
    }

    #[test]
    fn an_incrementally_linked_msvc_image_is_accepted() {
        assert_eq!(detect(&incremental()), None);
    }

    #[test]
    fn textbss_is_refused_outside_its_msvc_shape() {
        let refused = |i: &Image| detect(i).is_some_and(|w| w.contains("\".textbss\""));
        // Negative: something the file holds points into it (what an unpacking stub's target looks like).
        let mut i = incremental();
        i.entry = Some(0x1000);
        assert!(detect(&i).is_some());
        let mut i = incremental();
        i.pdata[0].begin = 0x1100;
        assert!(refused(&i));
        let mut i = incremental();
        i.exports.push((0x1200, "g".into()));
        assert!(refused(&i));
        let mut i = incremental();
        i.code_pointers.push(0x1300);
        assert!(refused(&i));
        // Negative: not the first section, or not writable.
        let mut i = incremental();
        let t = i.sections.remove(0);
        i.sections.push(Section { rva: 0x6000, ..t });
        assert!(refused(&i));
        let mut i = incremental();
        i.sections[0].writable = false;
        assert!(refused(&i));
        // Negative: the same shape under another name.
        let mut i = incremental();
        i.sections[0].name = ".text2".into();
        assert!(detect(&i).unwrap().contains("no data in the file"));
    }
}
