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
//! Neither shape occurs in what MSVC links. A protector that renames its sections and avoids both shapes isn't
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
    if let Some(s) = image
        .sections
        .iter()
        .find(|s| s.executable && s.data.is_empty() && s.virtual_size > 0)
    {
        return Some(format!(
            "executable section {:?} has no data in the file (filled in at run time)",
            s.name
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::image::Section;

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
}
