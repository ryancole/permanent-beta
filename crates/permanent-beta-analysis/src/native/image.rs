//! A loaded PE image, x64 (PE32+) or x86 (PE32): sections by RVA, exception table (`.pdata`, x64 only), import
//! address table, exports, and the code addresses stored in data (from base relocations).
//!
//! `object` parses the headers and sections. The exception, import and base relocation directories are parsed
//! by hand from section bytes: all are simple tables, and this keeps the parsing visible and testable.

use object::pe::{
    IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_EXCEPTION, IMAGE_DIRECTORY_ENTRY_IMPORT,
    IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_HIGHLOW, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE,
};
use object::read::pe::{ImageNtHeaders, PeFile, PeFile32, PeFile64};
use object::{Architecture, FileKind, LittleEndian as LE, Object, ObjectSection, SectionFlags};
use std::collections::{BTreeSet, HashMap};

/// `UNW_FLAG_CHAININFO`: this RUNTIME_FUNCTION is a fragment (e.g. split cold code) of another function.
const UNW_FLAG_CHAININFO: u8 = 0x4;

#[derive(Debug, Clone)]
pub(crate) struct Section {
    pub name: String,
    pub rva: u32,
    pub virtual_size: u32,
    pub data: Vec<u8>,
    pub executable: bool,
    pub writable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RuntimeFunction {
    pub begin: u32,
    pub end: u32,
    /// A fragment of another function, not a function start.
    pub chained: bool,
    /// For a chained fragment: the start of the function the chain leads back to, if it could be followed.
    pub parent: Option<u32>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct Image {
    /// A 32-bit x86 image (PE32); otherwise x64 (PE32+). x86 code has no `.pdata`, addresses data with absolute
    /// operands instead of RIP-relative ones, and stores 4-byte pointers.
    pub x86: bool,
    pub base: u64,
    pub size_of_image: u32,
    pub entry: Option<u32>,
    pub sections: Vec<Section>,
    pub pdata: Vec<RuntimeFunction>,
    /// IAT slot RVA → `dll!name` (dll lowercased).
    pub iat: HashMap<u32, String>,
    /// Export RVA → name.
    pub exports: Vec<(u32, String)>,
    /// CodeView GUID and age from the debug directory (identifies the matching PDB; no symbols are read).
    pub pdb: Option<(String, u32)>,
    /// Code addresses (RVAs, sorted, deduplicated) stored as pointers in non-executable sections: every `DIR64`
    /// (x64) or `HIGHLOW` (x86) base relocation whose slot is in data and whose value points into executable
    /// code. Function tables, vtables, callbacks in initialized structs. Pointers stored in code are left out.
    pub code_pointers: Vec<u32>,
    /// The same pointers by where they're stored: (slot RVA, target RVA), sorted by slot. Consecutive slots are
    /// tables (vtables, function tables).
    pub code_pointer_slots: Vec<(u32, u32)>,
    /// x86 only: the base relocation slots that are in executable code, i.e. absolute addresses in instruction
    /// operands (`push offset f`, `mov eax, [g]`). With them, an operand is known to be an address rather than a
    /// constant that happens to look like one. Empty for x64, and for an x86 image linked without relocations
    /// (`/FIXED`): see [`Self::relocated`].
    pub code_relocs: BTreeSet<u32>,
    /// The image has a base relocation directory.
    pub has_relocs: bool,
}

impl Image {
    /// Parse a PE x64 or x86 file, refusing a protected or packed one (`protection`).
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let image = Self::parse_any(bytes)?;
        match super::protection::detect(&image) {
            Some(why) => Err(super::protection::refusal(&why)),
            None => Ok(image),
        }
    }

    /// Parse a PE x64 or x86 file without the protection check: callers must make it themselves.
    pub fn parse_any(bytes: &[u8]) -> Result<Self, String> {
        match FileKind::parse(bytes).map_err(|e| e.to_string())? {
            FileKind::Pe64 => {
                Self::load(&PeFile64::parse(bytes).map_err(|e| e.to_string())?, false)
            }
            FileKind::Pe32 => Self::load(&PeFile32::parse(bytes).map_err(|e| e.to_string())?, true),
            kind => Err(format!("not a PE image ({kind:?})")),
        }
    }

    fn load<Pe: ImageNtHeaders>(pe: &PeFile<'_, Pe>, x86: bool) -> Result<Self, String> {
        let want = if x86 {
            Architecture::I386
        } else {
            Architecture::X86_64
        };
        if pe.architecture() != want {
            return Err(format!(
                "architecture {:?} (only x64 and x86 are supported)",
                pe.architecture()
            ));
        }
        let base = pe.relative_address_base();

        let mut sections = Vec::new();
        for s in pe.sections() {
            let header = s.pe_section();
            let flag = |bit| {
                matches!(s.flags(), SectionFlags::Coff { characteristics }
                    if characteristics & bit != 0)
            };
            sections.push(Section {
                name: String::from_utf8_lossy(s.name_bytes().unwrap_or_default()).into_owned(),
                rva: header.virtual_address.get(LE),
                virtual_size: header.virtual_size.get(LE),
                data: s.data().map(<[u8]>::to_vec).unwrap_or_default(),
                executable: flag(IMAGE_SCN_MEM_EXECUTE),
                writable: flag(IMAGE_SCN_MEM_WRITE),
            });
        }
        let size_of_image = sections
            .iter()
            .map(|s| s.rva.saturating_add(s.virtual_size))
            .max()
            .unwrap_or(0);

        let entry = pe
            .entry()
            .checked_sub(base)
            .filter(|&e| e != 0)
            .map(|e| e as u32);
        let exports = pe
            .exports()
            .map_err(|e| e.to_string())?
            .into_iter()
            .filter_map(|e| {
                let rva = e.address().checked_sub(base)? as u32;
                Some((rva, String::from_utf8_lossy(e.name()).into_owned()))
            })
            .collect();
        let pdb = pe
            .pdb_info()
            .ok()
            .flatten()
            .map(|cv| (format_guid(cv.guid()), cv.age()));
        let dir = |id: usize| {
            pe.data_directory(id)
                .map(|d| (d.virtual_address.get(LE), d.size.get(LE)))
                .filter(|&(rva, size)| rva != 0 && size != 0)
        };
        let (exception_dir, import_dir, reloc_dir) = (
            dir(IMAGE_DIRECTORY_ENTRY_EXCEPTION),
            dir(IMAGE_DIRECTORY_ENTRY_IMPORT),
            dir(IMAGE_DIRECTORY_ENTRY_BASERELOC),
        );

        let mut image = Image {
            x86,
            base,
            size_of_image,
            entry,
            sections,
            exports,
            pdb,
            ..Default::default()
        };
        // x86 keeps no RUNTIME_FUNCTION table; a stray exception directory isn't one.
        if let Some((rva, size)) = exception_dir.filter(|_| !x86) {
            image.pdata = image.parse_pdata(rva, size);
        }
        if let Some((rva, _)) = import_dir {
            image.iat = image.parse_imports(rva);
        }
        if let Some((rva, size)) = reloc_dir {
            image.has_relocs = true;
            let (slots, in_code) = image.parse_relocs(rva, size);
            image.code_pointer_slots = slots;
            if x86 {
                image.code_relocs = in_code;
            }
            let targets: BTreeSet<u32> = image.code_pointer_slots.iter().map(|&(_, t)| t).collect();
            image.code_pointers = targets.into_iter().collect();
        }
        Ok(image)
    }

    /// Instruction width in bits, for the decoder.
    pub fn bitness(&self) -> u32 {
        if self.x86 { 32 } else { 64 }
    }

    /// Bytes in a pointer stored in data.
    pub fn pointer_size(&self) -> u32 {
        if self.x86 { 4 } else { 8 }
    }

    /// Whether the instruction at `[rva, rva + len)` holds a relocated address (x86): an absolute operand the
    /// loader rebases, so an address and not a constant that happens to look like one. An image without
    /// relocations gives no such evidence, so there every operand counts.
    pub fn relocated(&self, rva: u32, len: u32) -> bool {
        !self.has_relocs || self.code_relocs.range(rva..rva + len).next().is_some()
    }

    fn section_at(&self, rva: u32) -> Option<&Section> {
        self.sections
            .iter()
            .find(|s| rva >= s.rva && rva - s.rva < s.virtual_size.max(s.data.len() as u32))
    }

    /// Raw bytes `[rva, rva + len)`, if they're backed by file data within one section.
    pub fn bytes(&self, rva: u32, len: usize) -> Option<&[u8]> {
        let s = self.section_at(rva)?;
        let off = (rva - s.rva) as usize;
        s.data.get(off..off.checked_add(len)?)
    }

    /// Bytes from `rva` to the end of its section's file data.
    pub fn bytes_from(&self, rva: u32) -> Option<&[u8]> {
        let s = self.section_at(rva)?;
        s.data.get((rva - s.rva) as usize..)
    }

    /// End RVA of the section containing `rva` (file-backed part).
    pub fn section_end(&self, rva: u32) -> Option<u32> {
        let s = self.section_at(rva)?;
        let file_len = s.data.len() as u32;
        // Raw data is padded to the file alignment; the virtual size is the real extent (0 for some linkers).
        let len = if s.virtual_size == 0 {
            file_len
        } else {
            file_len.min(s.virtual_size)
        };
        Some(s.rva + len)
    }

    pub fn is_executable(&self, rva: u32) -> bool {
        self.section_at(rva).is_some_and(|s| s.executable)
    }

    /// In a writable section (`.data`, `.bss`): global state.
    pub fn is_writable(&self, rva: u32) -> bool {
        self.section_at(rva).is_some_and(|s| s.writable)
    }

    pub fn va_to_rva(&self, va: u64) -> Option<u32> {
        let rva = va.checked_sub(self.base)?;
        (rva < self.size_of_image as u64).then_some(rva as u32)
    }

    /// True if `value` looks like an address inside this image (so it must be masked when hashing).
    pub fn contains_va(&self, value: u64) -> bool {
        self.va_to_rva(value).is_some()
    }

    fn u32_at(&self, rva: u32) -> Option<u32> {
        Some(u32::from_le_bytes(self.bytes(rva, 4)?.try_into().ok()?))
    }

    fn u64_at(&self, rva: u32) -> Option<u64> {
        Some(u64::from_le_bytes(self.bytes(rva, 8)?.try_into().ok()?))
    }

    /// A pointer-sized value: 4 bytes on x86, 8 on x64.
    pub fn ptr_at(&self, rva: u32) -> Option<u64> {
        if self.x86 {
            self.u32_at(rva).map(u64::from)
        } else {
            self.u64_at(rva)
        }
    }

    /// NUL-terminated byte string at `rva` (any bytes, for names in PE tables).
    fn c_name(&self, rva: u32) -> Option<String> {
        let tail = self.bytes_from(rva)?;
        let end = tail.iter().position(|&b| b == 0)?;
        Some(String::from_utf8_lossy(&tail[..end]).into_owned())
    }

    /// A printable string literal at `rva` in a non-executable section: ASCII or UTF-16LE, at least 4 chars.
    pub fn string_literal(&self, rva: u32) -> Option<String> {
        const MIN: usize = 4;
        const MAX: usize = 1024;
        if self.is_executable(rva) {
            return None;
        }
        let tail = self.bytes_from(rva)?;
        let tail = &tail[..tail.len().min(MAX * 2 + 2)];
        let printable = |c: u8| (0x20..0x7f).contains(&c) || matches!(c, b'\t' | b'\n' | b'\r');

        if let Some(end) = tail.iter().position(|&b| b == 0) {
            if (MIN..=MAX).contains(&end) && tail[..end].iter().all(|&c| printable(c)) {
                return Some(String::from_utf8_lossy(&tail[..end]).into_owned());
            }
        }
        // UTF-16LE (ASCII range only, which covers the cases worth matching on).
        let mut s = String::new();
        for pair in tail.chunks_exact(2) {
            match (pair[0], pair[1]) {
                (0, 0) => return (s.len() >= MIN).then_some(s),
                (c, 0) if printable(c) => s.push(c as char),
                _ => return None,
            }
        }
        None
    }

    fn parse_pdata(&self, rva: u32, size: u32) -> Vec<RuntimeFunction> {
        let mut out = Vec::new();
        for i in 0..size / 12 {
            let at = rva + i * 12;
            let (Some(begin), Some(end), Some(unwind)) =
                (self.u32_at(at), self.u32_at(at + 4), self.u32_at(at + 8))
            else {
                break;
            };
            if begin == 0 || end <= begin {
                continue;
            }
            let chained = self.chain_link(unwind).is_some();
            out.push(RuntimeFunction {
                begin,
                end,
                chained,
                parent: chained.then(|| self.chain_root(unwind)).flatten(),
            });
        }
        out.sort_by_key(|r| r.begin);
        out
    }

    /// If the unwind data at `unwind` is chained, the RVA of the RUNTIME_FUNCTION it chains to.
    ///
    /// Two encodings: low bit set means UnwindData itself points (minus 1) at a RUNTIME_FUNCTION; otherwise an
    /// UNWIND_INFO with `UNW_FLAG_CHAININFO` stores the RUNTIME_FUNCTION after its unwind codes (padded to an
    /// even count).
    fn chain_link(&self, unwind: u32) -> Option<u32> {
        if unwind & 1 != 0 {
            return Some(unwind & !1);
        }
        let header = self.bytes(unwind, 4)?;
        if (header[0] >> 3) & UNW_FLAG_CHAININFO == 0 {
            return None;
        }
        let codes = u32::from(header[2]).next_multiple_of(2);
        Some(unwind + 4 + codes * 2)
    }

    /// Follow a chain to the function that isn't itself chained, and return its start.
    fn chain_root(&self, unwind: u32) -> Option<u32> {
        let mut link = self.chain_link(unwind)?;
        // Real chains are one or two links long; the limit only guards against cycles in a malformed file.
        for _ in 0..32 {
            let begin = self.u32_at(link)?;
            let next_unwind = self.u32_at(link + 8)?;
            match self.chain_link(next_unwind) {
                Some(next) => link = next,
                None => return Some(begin),
            }
        }
        None
    }

    /// Walk the base relocation table (blocks of: page RVA, block size, then 16-bit entries of type << 12 |
    /// page offset). Returns the pointer slots in data that point into executable code, as (slot, target), and
    /// every slot that's in executable code. Only the image's own pointer type counts: `DIR64` on x64,
    /// `HIGHLOW` on x86.
    fn parse_relocs(&self, rva: u32, size: u32) -> (Vec<(u32, u32)>, BTreeSet<u32>) {
        let kind = if self.x86 {
            IMAGE_REL_BASED_HIGHLOW
        } else {
            IMAGE_REL_BASED_DIR64
        };
        let mut out = BTreeSet::new();
        let mut in_code = BTreeSet::new();
        let mut at = rva;
        let end = rva.saturating_add(size);
        while at + 8 <= end {
            let (Some(page), Some(block)) = (self.u32_at(at), self.u32_at(at + 4)) else {
                break;
            };
            if block < 8 {
                break;
            }
            for i in 0..(block - 8) / 2 {
                let Some(e) = self.bytes(at + 8 + i * 2, 2) else {
                    break;
                };
                let e = u16::from_le_bytes([e[0], e[1]]);
                if e >> 12 != kind {
                    continue;
                }
                let slot = page + u32::from(e & 0xfff);
                if self.is_executable(slot) {
                    in_code.insert(slot);
                    continue;
                }
                if let Some(target) = self.ptr_at(slot).and_then(|v| self.va_to_rva(v))
                    && self.is_executable(target)
                {
                    out.insert((slot, target));
                }
            }
            at += block;
        }
        (out.into_iter().collect(), in_code)
    }

    #[cfg(test)]
    fn parse_code_pointers(&self, rva: u32, size: u32) -> Vec<(u32, u32)> {
        self.parse_relocs(rva, size).0
    }

    fn parse_imports(&self, rva: u32) -> HashMap<u32, String> {
        let mut iat = HashMap::new();
        for d in 0.. {
            let at = rva + d * 20;
            let fields: Option<Vec<u32>> = (0..5).map(|f| self.u32_at(at + f * 4)).collect();
            let Some(f) = fields else { break };
            let (original_first_thunk, name, first_thunk) = (f[0], f[3], f[4]);
            if f.iter().all(|&x| x == 0) {
                break;
            }
            let dll = self.c_name(name).unwrap_or_default().to_lowercase();
            let lookup = if original_first_thunk != 0 {
                original_first_thunk
            } else {
                first_thunk
            };
            let (width, ordinal_flag) = if self.x86 {
                (4, 1u64 << 31)
            } else {
                (8, 1u64 << 63)
            };
            for i in 0.. {
                let Some(thunk) = self.ptr_at(lookup + i * width) else {
                    break;
                };
                if thunk == 0 {
                    break;
                }
                let func = if thunk & ordinal_flag != 0 {
                    format!("#{}", thunk & 0xffff)
                } else {
                    // IMAGE_IMPORT_BY_NAME: u16 hint, then the name.
                    self.c_name(thunk as u32 + 2).unwrap_or_default()
                };
                iat.insert(first_thunk + i * width, format!("{dll}!{func}"));
            }
        }
        iat
    }
}

fn format_guid(g: [u8; 16]) -> String {
    let d1 = u32::from_le_bytes([g[0], g[1], g[2], g[3]]);
    let d2 = u16::from_le_bytes([g[4], g[5]]);
    let d3 = u16::from_le_bytes([g[6], g[7]]);
    format!(
        "{d1:08X}-{d2:04X}-{d3:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15]
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A synthetic image with one executable section at RVA 0x1000 and one data section at 0x2000.
    pub fn image(code: &[u8], data: &[u8]) -> Image {
        Image {
            base: 0x1_4000_0000,
            size_of_image: 0x3000,
            sections: vec![
                Section {
                    name: ".text".into(),
                    rva: 0x1000,
                    virtual_size: 0x1000,
                    data: code.to_vec(),
                    executable: true,
                    writable: false,
                },
                Section {
                    name: ".data".into(),
                    rva: 0x2000,
                    virtual_size: 0x1000,
                    data: data.to_vec(),
                    executable: false,
                    writable: true,
                },
            ],
            ..Default::default()
        }
    }

    #[test]
    fn reads_ascii_and_utf16_literals() {
        let mut data = b"pb-config.ini\0".to_vec();
        data.extend("wide".encode_utf16().flat_map(u16::to_le_bytes));
        data.extend([0, 0]);
        let img = image(&[0xc3], &data);
        assert_eq!(img.string_literal(0x2000).as_deref(), Some("pb-config.ini"));
        assert_eq!(img.string_literal(0x2000 + 14).as_deref(), Some("wide"));
    }

    #[test]
    fn short_or_binary_data_is_not_a_string() {
        let img = image(&[0xc3], &[b'a', b'b', 0, 0x01, 0x02, 0x03, 0x04, 0x05, 0]);
        assert_eq!(img.string_literal(0x2000), None, "too short");
        assert_eq!(img.string_literal(0x2003), None, "not printable");
        assert_eq!(img.string_literal(0x1000), None, "executable section");
    }

    /// pdata table at 0x2000: f at 0x1000..0x1010 (plain unwind info at 0x2100) and a fragment at
    /// 0x1010..0x1020 whose unwind info at 0x2110 chains back to f.
    fn chained_image(fragment_unwind: u32) -> Image {
        let mut data = vec![0u8; 0x200];
        let entry = |d: &mut Vec<u8>, at: usize, b: u32, e: u32, u: u32| {
            d[at..at + 4].copy_from_slice(&b.to_le_bytes());
            d[at + 4..at + 8].copy_from_slice(&e.to_le_bytes());
            d[at + 8..at + 12].copy_from_slice(&u.to_le_bytes());
        };
        entry(&mut data, 0, 0x1000, 0x1010, 0x2100);
        entry(&mut data, 12, 0x1010, 0x1020, fragment_unwind);
        // Version 1, no flags, 1 unwind code (then padding to an even count).
        data[0x100..0x104].copy_from_slice(&[0x01, 0x04, 0x01, 0x00]);
        // Version 1 | UNW_FLAG_CHAININFO, no codes; the RUNTIME_FUNCTION of f follows.
        data[0x110..0x114].copy_from_slice(&[0x01 | (UNW_FLAG_CHAININFO << 3), 0, 0, 0]);
        entry(&mut data, 0x114, 0x1000, 0x1010, 0x2100);
        image(&[0xc3], &data)
    }

    #[test]
    fn chained_fragments_lead_back_to_their_function() {
        let img = chained_image(0x2110);
        let p = img.parse_pdata(0x2000, 24);
        assert_eq!((p[0].chained, p[0].parent), (false, None));
        assert_eq!((p[1].chained, p[1].parent), (true, Some(0x1000)));
    }

    #[test]
    fn indirect_chain_pointer_is_followed() {
        // Low bit set: UnwindData points straight at f's RUNTIME_FUNCTION (at 0x2000).
        let p = chained_image(0x2001).parse_pdata(0x2000, 24);
        assert_eq!((p[1].chained, p[1].parent), (true, Some(0x1000)));
    }

    #[test]
    fn unchained_entries_have_no_parent() {
        // Both entries use plain unwind info: two separate functions.
        let p = chained_image(0x2100).parse_pdata(0x2000, 24);
        assert!(p.iter().all(|r| !r.chained && r.parent.is_none()));
    }

    /// One relocation block for page 0x2000 holding `entries`, written at 0x2800 of the data section; the
    /// pointer slots it names are filled from `slots`.
    fn reloc_image(slots: &[(u32, u64)], entries: &[u16], code_slot: Option<(u32, u64)>) -> Image {
        let mut data = vec![0u8; 0x900];
        for &(slot, value) in slots {
            let at = (slot - 0x2000) as usize;
            data[at..at + 8].copy_from_slice(&value.to_le_bytes());
        }
        let block = 8 + 2 * entries.len() as u32;
        data[0x800..0x804].copy_from_slice(&0x2000u32.to_le_bytes());
        data[0x804..0x808].copy_from_slice(&block.to_le_bytes());
        for (i, e) in entries.iter().enumerate() {
            data[0x808 + i * 2..0x80a + i * 2].copy_from_slice(&e.to_le_bytes());
        }
        let mut code = vec![0xc3u8; 0x100];
        if let Some((slot, value)) = code_slot {
            let at = (slot - 0x1000) as usize;
            code[at..at + 8].copy_from_slice(&value.to_le_bytes());
        }
        image(&code, &data)
    }

    const BASE: u64 = 0x1_4000_0000;

    #[test]
    fn pointers_to_code_in_data_are_found() {
        let dir64 = |off: u16| (IMAGE_REL_BASED_DIR64 << 12) | off;
        let img = reloc_image(
            &[
                (0x2010, BASE + 0x1040),
                (0x2018, BASE + 0x1020),
                (0x2020, BASE + 0x1040),
            ],
            &[dir64(0x10), dir64(0x18), dir64(0x20), 0],
            None,
        );
        let block = 8 + 2 * 4;
        assert_eq!(
            img.parse_code_pointers(0x2800, block),
            vec![(0x2010, 0x1040), (0x2018, 0x1020), (0x2020, 0x1040)]
        );
    }

    #[test]
    fn pointers_to_data_or_stored_in_code_are_not_code_pointers() {
        // Negative case: a data pointer to data, a non-DIR64 entry, and a code pointer stored in code (an
        // immediate operand) must not become function starts.
        let dir64 = |off: u16| (IMAGE_REL_BASED_DIR64 << 12) | off;
        let highlow = (3u16 << 12) | 0x18;
        let img = reloc_image(
            &[(0x2010, BASE + 0x2400), (0x2018, BASE + 0x1040)],
            &[dir64(0x10), highlow],
            Some((0x1080, BASE + 0x1040)),
        );
        assert!(img.parse_code_pointers(0x2800, 12).is_empty());
        // The slot in code, named by a block for page 0x1000, is skipped too.
        let mut img = img;
        let d = &mut img.sections[1].data;
        d[0x800..0x804].copy_from_slice(&0x1000u32.to_le_bytes());
        d[0x804..0x808].copy_from_slice(&10u32.to_le_bytes());
        d[0x808..0x80a].copy_from_slice(&dir64(0x80).to_le_bytes());
        assert!(img.parse_code_pointers(0x2800, 10).is_empty());
    }

    /// A minimal PE32 (x86) file with base 0x400000: `.text` at 0x1000 (`push offset 0x401010` at its start, its
    /// operand relocated; `ret` at 0x1010), `.rdata` at 0x2000 (imports: `k.dll!Sleep` by name and ordinal 7;
    /// relocations) and `.data` at 0x3000 (a pointer to 0x401010, relocated). `machine` is the COFF machine.
    fn pe32(machine: u16) -> Vec<u8> {
        const BASE: u32 = 0x40_0000;
        let mut f = vec![0u8; 0xa00];
        let mut put = |off: usize, bytes: &[u8]| f[off..off + bytes.len()].copy_from_slice(bytes);
        put(0, b"MZ");
        put(0x3c, &0x80u32.to_le_bytes());
        put(0x80, b"PE  ");
        put(0x84, &machine.to_le_bytes());
        put(0x86, &3u16.to_le_bytes()); // sections
        put(0x94, &0xe0u16.to_le_bytes()); // optional header size
        put(0x96, &0x102u16.to_le_bytes()); // executable, 32-bit
        let o = 0x98;
        put(o, &0x10bu16.to_le_bytes()); // PE32
        put(o + 16, &0x1010u32.to_le_bytes()); // entry point
        put(o + 28, &BASE.to_le_bytes());
        put(o + 32, &0x1000u32.to_le_bytes()); // section alignment
        put(o + 36, &0x200u32.to_le_bytes()); // file alignment
        put(o + 40, &6u16.to_le_bytes());
        put(o + 48, &6u16.to_le_bytes());
        put(o + 56, &0x4000u32.to_le_bytes()); // size of image
        put(o + 60, &0x400u32.to_le_bytes()); // size of headers
        put(o + 68, &3u16.to_le_bytes()); // console
        put(o + 92, &16u32.to_le_bytes()); // data directories
        put(o + 96 + 8, &0x2000u32.to_le_bytes()); // import directory
        put(o + 96 + 12, &40u32.to_le_bytes());
        put(o + 96 + 5 * 8, &0x2100u32.to_le_bytes()); // base relocations
        put(o + 96 + 5 * 8 + 4, &32u32.to_le_bytes());
        let sections = [
            (b".text   ", 0x1000u32, 0x400u32, 0x6000_0020u32),
            (b".rdata  ", 0x2000, 0x600, 0x4000_0040),
            (b".data   ", 0x3000, 0x800, 0xc000_0040),
        ];
        for (i, (name, rva, raw, flags)) in sections.iter().enumerate() {
            let h = 0x178 + 40 * i;
            put(h, *name);
            put(h + 8, &0x200u32.to_le_bytes());
            put(h + 12, &rva.to_le_bytes());
            put(h + 16, &0x200u32.to_le_bytes());
            put(h + 20, &raw.to_le_bytes());
            put(h + 36, &flags.to_le_bytes());
        }
        // .text: push 0x401010; ret ... 0x1010: ret
        put(0x400, &[0x68, 0x10, 0x10, 0x40, 0x00, 0xc3]);
        put(0x410, &[0xc3]);
        // .rdata: one import descriptor (lookup 0x2040, name 0x2030, IAT 0x2050), then the null one.
        let r = 0x600;
        put(r, &0x2040u32.to_le_bytes());
        put(r + 12, &0x2030u32.to_le_bytes());
        put(r + 16, &0x2050u32.to_le_bytes());
        put(r + 0x30, b"K.dll ");
        for at in [r + 0x40, r + 0x50] {
            put(at, &0x2060u32.to_le_bytes()); // by name
            put(at + 4, &(0x8000_0000u32 | 7).to_le_bytes()); // by ordinal
        }
        put(r + 0x62, b"Sleep ");
        // Relocations: page 0x1000 (HIGHLOW at +1, the push operand), page 0x3000 (HIGHLOW at +0, and a DIR64
        // entry at +8 an x86 image doesn't use).
        put(r + 0x100, &0x1000u32.to_le_bytes());
        put(r + 0x104, &12u32.to_le_bytes());
        put(r + 0x108, &((3u16 << 12) | 1).to_le_bytes());
        put(r + 0x10c, &0x3000u32.to_le_bytes());
        put(r + 0x110, &12u32.to_le_bytes());
        put(r + 0x114, &(3u16 << 12).to_le_bytes());
        put(r + 0x116, &((10u16 << 12) | 8).to_le_bytes());
        // .data: a pointer to 0x401010, then (at +8) one to 0x401000 only a DIR64 entry names.
        put(0x800, &0x40_1010u32.to_le_bytes());
        put(0x808, &0x40_1000u32.to_le_bytes());
        f
    }

    #[test]
    fn a_pe32_image_is_read_as_x86() {
        let img = Image::parse(&pe32(0x14c)).expect("PE32 parses");
        assert!(img.x86);
        assert_eq!((img.base, img.entry), (0x40_0000, Some(0x1010)));
        // 4-byte IAT slots, the ordinal flag in bit 31.
        assert_eq!(
            img.iat.get(&0x2050).map(String::as_str),
            Some("k.dll!Sleep")
        );
        assert_eq!(img.iat.get(&0x2054).map(String::as_str), Some("k.dll!#7"));
        // The HIGHLOW pointer in data is a code pointer; the one in code is an operand's address.
        assert_eq!(img.code_pointer_slots, vec![(0x3000, 0x1010)]);
        assert_eq!(
            img.code_relocs.iter().copied().collect::<Vec<_>>(),
            vec![0x1001]
        );
        assert!(img.relocated(0x1000, 5));
        // Negative: a DIR64 entry in an x86 image isn't a pointer, and an instruction without a relocation holds
        // no address.
        assert!(!img.code_pointers.contains(&0x1000));
        assert!(!img.relocated(0x1005, 1));
    }

    #[test]
    fn a_pe32_with_another_machine_is_refused() {
        // Negative: a PE32 header claiming ARM (0x1c4) is neither x86 nor x64.
        let err = Image::parse(&pe32(0x1c4)).unwrap_err();
        assert!(err.contains("only x64 and x86"), "{err}");
    }

    #[test]
    fn guid_formats_like_windows() {
        let g = [
            0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0x78, 0x56, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08,
        ];
        assert_eq!(format_guid(g), "12345678-1234-5678-0102-030405060708");
    }
}
