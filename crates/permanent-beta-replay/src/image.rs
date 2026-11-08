//! The new build's image as the emulator maps it: the file's headers and sections laid out by RVA, which
//! sections are executable and writable, the import address table, base relocations and the security cookie.
//!
//! `object` parses the headers and sections; the import, relocation and load-config directories are simple
//! tables, read by hand.

use object::LittleEndian as LE;
use object::pe::{
    IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_IMPORT,
    IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, IMAGE_REL_BASED_DIR64, IMAGE_SCN_MEM_EXECUTE,
    IMAGE_SCN_MEM_WRITE,
};
use object::read::pe::PeFile64;
use object::{Architecture, Object, ObjectSection, SectionFlags};
use permanent_beta_model::BuildId;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub name: String,
    pub rva: u32,
    /// Bytes the section occupies in memory, page-aligned.
    pub size: u32,
    pub executable: bool,
    pub writable: bool,
}

#[derive(Debug, Clone)]
pub struct Image {
    pub build: BuildId,
    /// The base the image was linked for.
    pub preferred_base: u64,
    /// Headers and sections at their RVAs, `size_of_image` bytes (page-aligned).
    pub memory: Vec<u8>,
    pub sections: Vec<Section>,
    /// Import address table slots: (slot RVA, `dll!name`).
    pub imports: Vec<(u32, String)>,
    /// RVAs of the 64-bit absolute addresses the loader rebases (`DIR64` base relocations).
    pub relocations: Vec<u32>,
    /// RVA of `__security_cookie` (from the load config), which /GS code reads and that holds no state worth
    /// recording.
    pub security_cookie: Option<u32>,
}

pub const PAGE: u64 = 0x1000;

pub fn page_up(n: u64) -> u64 {
    n.div_ceil(PAGE) * PAGE
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
        let preferred_base = pe.relative_address_base();
        let headers_len = pe.nt_headers().optional_header.size_of_headers.get(LE) as usize;
        let mut sections = Vec::new();
        let mut layout: Vec<(u32, Vec<u8>)> = Vec::new();
        for s in pe.sections() {
            let header = s.pe_section();
            let characteristics = match s.flags() {
                SectionFlags::Coff { characteristics } => characteristics,
                _ => 0,
            };
            let rva = header.virtual_address.get(LE);
            let data = s.data().map(<[u8]>::to_vec).unwrap_or_default();
            let size =
                page_up(u64::from(header.virtual_size.get(LE)).max(data.len() as u64)) as u32;
            sections.push(Section {
                name: s.name().unwrap_or("?").to_owned(),
                rva,
                size,
                executable: characteristics & IMAGE_SCN_MEM_EXECUTE != 0,
                writable: characteristics & IMAGE_SCN_MEM_WRITE != 0,
            });
            layout.push((rva, data));
        }
        let size_of_image = sections
            .iter()
            .map(|s| u64::from(s.rva) + u64::from(s.size))
            .max()
            .unwrap_or(PAGE)
            .max(page_up(headers_len as u64));
        let mut memory = vec![0u8; page_up(size_of_image) as usize];
        let head = headers_len.min(bytes.len()).min(memory.len());
        memory[..head].copy_from_slice(&bytes[..head]);
        for (rva, data) in layout {
            let start = rva as usize;
            let end = (start + data.len()).min(memory.len());
            if start < end {
                memory[start..end].copy_from_slice(&data[..end - start]);
            }
        }

        let dir = |id: usize| {
            pe.data_directory(id)
                .map(|d| (d.virtual_address.get(LE), d.size.get(LE)))
                .filter(|&(rva, size)| rva != 0 && size != 0)
        };
        let mut image = Image {
            build: BuildId(hex(&Sha256::digest(bytes))),
            preferred_base,
            memory,
            sections,
            imports: Vec::new(),
            relocations: Vec::new(),
            security_cookie: None,
        };
        if let Some((rva, _)) = dir(IMAGE_DIRECTORY_ENTRY_IMPORT) {
            image.imports = image.parse_imports(rva);
        }
        if let Some((rva, size)) = dir(IMAGE_DIRECTORY_ENTRY_BASERELOC) {
            image.relocations = image.parse_relocations(rva, size);
        }
        if let Some((rva, size)) = dir(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG) {
            // IMAGE_LOAD_CONFIG_DIRECTORY64.SecurityCookie, a VA, at offset 0x58.
            image.security_cookie = (size >= 0x60)
                .then(|| image.u64_at(rva + 0x58))
                .flatten()
                .and_then(|va| va.checked_sub(preferred_base))
                .filter(|&r| r != 0 && r < image.memory.len() as u64)
                .map(|r| r as u32);
        }
        Ok(image)
    }

    pub fn size(&self) -> u64 {
        self.memory.len() as u64
    }

    pub fn section_at(&self, rva: u64) -> Option<&Section> {
        self.sections
            .iter()
            .find(|s| rva >= u64::from(s.rva) && rva < u64::from(s.rva) + u64::from(s.size))
    }

    fn u16_at(&self, rva: u32) -> Option<u16> {
        let b = self.memory.get(rva as usize..rva as usize + 2)?;
        Some(u16::from_le_bytes(b.try_into().ok()?))
    }

    fn u32_at(&self, rva: u32) -> Option<u32> {
        let b = self.memory.get(rva as usize..rva as usize + 4)?;
        Some(u32::from_le_bytes(b.try_into().ok()?))
    }

    fn u64_at(&self, rva: u32) -> Option<u64> {
        let b = self.memory.get(rva as usize..rva as usize + 8)?;
        Some(u64::from_le_bytes(b.try_into().ok()?))
    }

    fn c_name(&self, rva: u32) -> Option<String> {
        let tail = self.memory.get(rva as usize..)?;
        let end = tail.iter().position(|&b| b == 0)?;
        Some(String::from_utf8_lossy(&tail[..end]).into_owned())
    }

    /// Import descriptors (20 bytes each, zero-terminated): every IAT slot with the name it imports.
    fn parse_imports(&self, dir: u32) -> Vec<(u32, String)> {
        let mut out = Vec::new();
        for i in 0..4096u32 {
            let d = dir + 20 * i;
            let (Some(lookup), Some(name), Some(iat)) =
                (self.u32_at(d), self.u32_at(d + 12), self.u32_at(d + 16))
            else {
                break;
            };
            if name == 0 && iat == 0 {
                break;
            }
            let dll = self.c_name(name).unwrap_or_default().to_ascii_lowercase();
            let names = if lookup != 0 { lookup } else { iat };
            for j in 0..65536u32 {
                let Some(entry) = self.u64_at(names + 8 * j) else {
                    break;
                };
                if entry == 0 {
                    break;
                }
                let func = if entry & (1 << 63) != 0 {
                    format!("#{}", entry & 0xffff)
                } else {
                    self.c_name((entry & 0x7fff_ffff) as u32 + 2)
                        .unwrap_or_else(|| "?".into())
                };
                out.push((iat + 8 * j, format!("{dll}!{func}")));
            }
        }
        out
    }

    fn parse_relocations(&self, dir: u32, size: u32) -> Vec<u32> {
        let mut out = Vec::new();
        let mut at = dir;
        while at + 8 <= dir + size {
            let (Some(page), Some(block)) = (self.u32_at(at), self.u32_at(at + 4)) else {
                break;
            };
            if block < 8 {
                break;
            }
            for k in 0..(block - 8) / 2 {
                let Some(e) = self.u16_at(at + 8 + 2 * k) else {
                    break;
                };
                if e >> 12 == IMAGE_REL_BASED_DIR64 {
                    out.push(page + u32::from(e & 0xfff));
                }
            }
            at += block;
        }
        out
    }

    /// The image's bytes as loaded at `base`: absolute addresses rebased from the preferred base.
    pub fn loaded_at(&self, base: u64) -> Vec<u8> {
        let mut mem = self.memory.clone();
        let delta = base.wrapping_sub(self.preferred_base);
        if delta != 0 {
            for &r in &self.relocations {
                let r = r as usize;
                if let Some(slot) = mem.get_mut(r..r + 8) {
                    let v = u64::from_le_bytes(slot.try_into().expect("8 bytes"));
                    slot.copy_from_slice(&v.wrapping_add(delta).to_le_bytes());
                }
            }
        }
        mem
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
