//! The new build's image as the emulator maps it: the file's headers and sections laid out by RVA, which
//! sections are executable and writable, the import address table, base relocations and the security cookie.
//! x64 (PE32+) or x86 (PE32): an x86 image has 4-byte pointers (`HIGHLOW` relocations, 4-byte IAT slots).
//!
//! `object` parses the headers and sections; the import, relocation and load-config directories are simple
//! tables, read by hand.

use object::LittleEndian as LE;
use object::pe::{
    IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_IMPORT,
    IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_HIGHLOW,
    IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE,
};
use object::read::pe::{ImageNtHeaders, PeFile, PeFile32, PeFile64};
use object::{Architecture, FileKind, Object, ObjectSection, SectionFlags};
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
    /// A 32-bit x86 image (PE32); otherwise x64.
    pub x86: bool,
    /// The base the image was linked for.
    pub preferred_base: u64,
    /// Headers and sections at their RVAs, `size_of_image` bytes (page-aligned).
    pub memory: Vec<u8>,
    pub sections: Vec<Section>,
    /// Import address table slots: (slot RVA, `dll!name`).
    pub imports: Vec<(u32, String)>,
    /// RVAs of the absolute addresses the loader rebases: `DIR64` (8 bytes) on x64, `HIGHLOW` (4) on x86.
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
        match FileKind::parse(bytes).map_err(|e| e.to_string())? {
            FileKind::Pe64 => Self::load(
                &PeFile64::parse(bytes).map_err(|e| e.to_string())?,
                bytes,
                false,
            ),
            FileKind::Pe32 => Self::load(
                &PeFile32::parse(bytes).map_err(|e| e.to_string())?,
                bytes,
                true,
            ),
            kind => Err(format!("not a PE image ({kind:?})")),
        }
    }

    fn load<Pe: ImageNtHeaders>(
        pe: &PeFile<'_, Pe>,
        bytes: &[u8],
        x86: bool,
    ) -> Result<Self, String> {
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
        let preferred_base = pe.relative_address_base();
        let headers_len = {
            use object::read::pe::ImageOptionalHeader;
            pe.nt_headers().optional_header().size_of_headers() as usize
        };
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
            x86,
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
            // SecurityCookie, a VA: IMAGE_LOAD_CONFIG_DIRECTORY64's at offset 0x58, ...32's at 0x3c.
            let cookie = if x86 {
                (size >= 0x40)
                    .then(|| image.u32_at(rva + 0x3c).map(u64::from))
                    .flatten()
            } else {
                (size >= 0x60).then(|| image.u64_at(rva + 0x58)).flatten()
            };
            image.security_cookie = cookie
                .and_then(|va| va.checked_sub(preferred_base))
                .filter(|&r| r != 0 && r < image.memory.len() as u64)
                .map(|r| r as u32);
        }
        Ok(image)
    }

    pub fn size(&self) -> u64 {
        self.memory.len() as u64
    }

    /// Bytes in a pointer: 4 on x86, 8 on x64.
    pub fn pointer_size(&self) -> usize {
        if self.x86 { 4 } else { 8 }
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
            let (width, ordinal) = if self.x86 {
                (4, 1u64 << 31)
            } else {
                (8, 1u64 << 63)
            };
            for j in 0..65536u32 {
                let entry = if self.x86 {
                    self.u32_at(names + width * j).map(u64::from)
                } else {
                    self.u64_at(names + width * j)
                };
                let Some(entry) = entry else {
                    break;
                };
                if entry == 0 {
                    break;
                }
                let func = if entry & ordinal != 0 {
                    format!("#{}", entry & 0xffff)
                } else {
                    self.c_name((entry & 0x7fff_ffff) as u32 + 2)
                        .unwrap_or_else(|| "?".into())
                };
                out.push((iat + width * j, format!("{dll}!{func}")));
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
                let kind = if self.x86 {
                    IMAGE_REL_BASED_HIGHLOW
                } else {
                    IMAGE_REL_BASED_DIR64
                };
                if e >> 12 == kind {
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
                if self.x86 {
                    if let Some(slot) = mem.get_mut(r..r + 4) {
                        let v = u32::from_le_bytes(slot.try_into().expect("4 bytes"));
                        slot.copy_from_slice(&v.wrapping_add(delta as u32).to_le_bytes());
                    }
                } else if let Some(slot) = mem.get_mut(r..r + 8) {
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
