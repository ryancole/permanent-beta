//! A loaded PE x64 image: sections by RVA, exception table (`.pdata`), import address table, exports, and the
//! code addresses stored in data (from base relocations).
//!
//! `object` parses the headers and sections. The exception, import and base relocation directories are parsed
//! by hand from section bytes: all are simple tables, and this keeps the parsing visible and testable.

use object::pe::{
    IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_EXCEPTION, IMAGE_DIRECTORY_ENTRY_IMPORT,
    IMAGE_REL_BASED_DIR64, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE,
};
use object::read::pe::PeFile64;
use object::{Architecture, LittleEndian as LE, Object, ObjectSection, SectionFlags};
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
    /// Code addresses (RVAs, sorted, deduplicated) stored as 64-bit pointers in non-executable sections: every
    /// `DIR64` base relocation whose slot is in data and whose value points into executable code. Function
    /// tables, vtables, callbacks in initialized structs. Pointers stored in code are left out.
    pub code_pointers: Vec<u32>,
    /// The same pointers by where they're stored: (slot RVA, target RVA), sorted by slot. Consecutive slots are
    /// tables (vtables, function tables).
    pub code_pointer_slots: Vec<(u32, u32)>,
}

impl Image {
    /// Parse a PE x64 file, refusing a protected or packed one (`protection`).
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let image = Self::parse_any(bytes)?;
        match super::protection::detect(&image) {
            Some(why) => Err(super::protection::refusal(&why)),
            None => Ok(image),
        }
    }

    /// Parse a PE x64 file without the protection check: callers must make it themselves.
    pub fn parse_any(bytes: &[u8]) -> Result<Self, String> {
        let pe = PeFile64::parse(bytes).map_err(|e| e.to_string())?;
        if pe.architecture() != Architecture::X86_64 {
            return Err(format!(
                "architecture {:?} (only x64 is supported)",
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
            base,
            size_of_image,
            entry,
            sections,
            exports,
            pdb,
            ..Default::default()
        };
        if let Some((rva, size)) = exception_dir {
            image.pdata = image.parse_pdata(rva, size);
        }
        if let Some((rva, _)) = import_dir {
            image.iat = image.parse_imports(rva);
        }
        if let Some((rva, size)) = reloc_dir {
            image.code_pointer_slots = image.parse_code_pointers(rva, size);
            let targets: BTreeSet<u32> = image.code_pointer_slots.iter().map(|&(_, t)| t).collect();
            image.code_pointers = targets.into_iter().collect();
        }
        Ok(image)
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
    /// page offset) and keep the `DIR64` slots in data that point into executable code, as (slot, target).
    fn parse_code_pointers(&self, rva: u32, size: u32) -> Vec<(u32, u32)> {
        let mut out = BTreeSet::new();
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
                if e >> 12 != IMAGE_REL_BASED_DIR64 {
                    continue;
                }
                let slot = page + u32::from(e & 0xfff);
                if self.is_executable(slot) {
                    continue;
                }
                if let Some(target) = self.u64_at(slot).and_then(|v| self.va_to_rva(v))
                    && self.is_executable(target)
                {
                    out.insert((slot, target));
                }
            }
            at += block;
        }
        out.into_iter().collect()
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
            for i in 0.. {
                let Some(thunk) = self.u64_at(lookup + i * 8) else {
                    break;
                };
                if thunk == 0 {
                    break;
                }
                let func = if thunk & (1 << 63) != 0 {
                    format!("#{}", thunk & 0xffff)
                } else {
                    // IMAGE_IMPORT_BY_NAME: u16 hint, then the name.
                    self.c_name(thunk as u32 + 2).unwrap_or_default()
                };
                iat.insert(first_thunk + i * 8, format!("{dll}!{func}"));
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

    #[test]
    fn guid_formats_like_windows() {
        let g = [
            0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0x78, 0x56, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08,
        ];
        assert_eq!(format_guid(g), "12345678-1234-5678-0102-030405060708");
    }
}
