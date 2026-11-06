//! A loaded PE x64 image: sections by RVA, exception table (`.pdata`), import address table, exports.
//!
//! `object` parses the headers and sections. The exception and import directories are parsed by hand from
//! section bytes: both are simple fixed-size tables, and this keeps the parsing visible and testable.

use object::pe::{
    IMAGE_DIRECTORY_ENTRY_EXCEPTION, IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_SCN_MEM_EXECUTE,
};
use object::read::pe::PeFile64;
use object::{Architecture, LittleEndian as LE, Object, ObjectSection, SectionFlags};
use std::collections::HashMap;

/// `UNW_FLAG_CHAININFO`: this RUNTIME_FUNCTION is a fragment (e.g. split cold code) of another function.
const UNW_FLAG_CHAININFO: u8 = 0x4;

#[derive(Debug, Clone)]
pub(crate) struct Section {
    pub rva: u32,
    pub virtual_size: u32,
    pub data: Vec<u8>,
    pub executable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RuntimeFunction {
    pub begin: u32,
    pub end: u32,
    /// A fragment of another function, not a function start.
    pub chained: bool,
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
}

impl Image {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
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
            let executable = matches!(s.flags(), SectionFlags::Coff { characteristics }
                if characteristics & IMAGE_SCN_MEM_EXECUTE != 0);
            sections.push(Section {
                rva: header.virtual_address.get(LE),
                virtual_size: header.virtual_size.get(LE),
                data: s.data().map(<[u8]>::to_vec).unwrap_or_default(),
                executable,
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
        let (exception_dir, import_dir) = (
            dir(IMAGE_DIRECTORY_ENTRY_EXCEPTION),
            dir(IMAGE_DIRECTORY_ENTRY_IMPORT),
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
            // Low bit set: UnwindData points at another RUNTIME_FUNCTION (an indirect chain).
            let chained = unwind & 1 != 0
                || self
                    .bytes(unwind, 1)
                    .is_some_and(|b| (b[0] >> 3) & UNW_FLAG_CHAININFO != 0);
            out.push(RuntimeFunction {
                begin,
                end,
                chained,
            });
        }
        out.sort_by_key(|r| r.begin);
        out
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
                    rva: 0x1000,
                    virtual_size: 0x1000,
                    data: code.to_vec(),
                    executable: true,
                },
                Section {
                    rva: 0x2000,
                    virtual_size: 0x1000,
                    data: data.to_vec(),
                    executable: false,
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

    #[test]
    fn guid_formats_like_windows() {
        let g = [
            0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0x78, 0x56, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08,
        ];
        assert_eq!(format_guid(g), "12345678-1234-5678-0102-030405060708");
    }
}
