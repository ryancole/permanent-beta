//! Addresses into the old image, mapped to the new one (design §7.3).
//!
//! Recorded memory holds addresses into the image the old build was loaded as: a struct pointing at a static table
//! (zlib's `tree_desc_s.stat_desc` → `static_l_desc`), a function pointer (`z_stream.zalloc`). In another build
//! the same table or function is somewhere else. This map says where, by RVA:
//!
//! - **data**: a data symbol whose name is unique in both builds' PDBs (`AnalysisExport::data_symbols`) and has
//!   the same size. An address anywhere inside it maps to the same offset in the new one.
//! - **functions**: an old function's entry to its counterpart's entry, from pairs the caller gives (the run's
//!   accepted matches). Only the entry: a function pointer points there.
//!
//! What isn't mapped stays as recorded, and replay treats it as before (an old-image address is never run, read or
//! compared as if it meant something in the new build).

use permanent_beta_model::{AnalysisExport, Rva};
use std::ops::Range;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Data,
    /// From another function's match: if that match is wrong, behaviour through it is too, so it can make a case
    /// inconclusive but never fail it.
    Function,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    old: Range<u64>,
    new: u64,
    kind: Kind,
}

/// Old-image RVAs to new-image RVAs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AddressMap {
    entries: Vec<Entry>,
}

impl AddressMap {
    /// Data symbols by name from both analyses (`--pdb`), functions from `functions` (old entry, new entry).
    pub fn new(old: &AnalysisExport, new: &AnalysisExport, functions: &[(Rva, Rva)]) -> Self {
        let mut entries = Vec::new();
        for o in &old.data_symbols {
            let mut same = new.data_symbols.iter().filter(|n| n.name == o.name);
            if let (Some(n), None) = (same.next(), same.next())
                && n.size == o.size
                && o.size > 0
            {
                entries.push(Entry {
                    old: o.rva.0..o.rva.0 + o.size,
                    new: n.rva.0,
                    kind: Kind::Data,
                });
            }
        }
        for (o, n) in functions {
            entries.push(Entry {
                old: o.0..o.0 + 1,
                new: n.0,
                kind: Kind::Function,
            });
        }
        // An old RVA inside two entries (overlapping symbols) maps to neither: ambiguity is never resolved by guessing.
        let ambiguous: Vec<usize> = (0..entries.len())
            .filter(|&i| {
                entries.iter().enumerate().any(|(j, e)| {
                    j != i && e.old.start < entries[i].old.end && entries[i].old.start < e.old.end
                })
            })
            .collect();
        let mut keep = 0usize;
        entries.retain(|_| {
            let k = !ambiguous.contains(&keep);
            keep += 1;
            k
        });
        entries.sort_by_key(|e| e.old.start);
        Self { entries }
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The new RVA for an old one, and how it was mapped.
    pub fn rva(&self, old: u64) -> Option<(u64, Kind)> {
        let i = self.entries.partition_point(|e| e.old.start <= old);
        let e = self.entries[..i].last()?;
        e.old
            .contains(&old)
            .then(|| (e.new + (old - e.old.start), e.kind))
    }
}

/// An address map with where each image was loaded: the old one when recorded, the new one in this run.
#[derive(Debug, Clone, Copy)]
pub struct Rebase<'a> {
    pub map: &'a AddressMap,
    pub old_image: &'a Range<u64>,
    pub new_base: u64,
}

impl Rebase<'_> {
    /// The new address for `value`, when it's an address into the old image that the map knows.
    pub fn address(&self, value: u64) -> Option<(u64, Kind)> {
        if !self.old_image.contains(&value) {
            return None;
        }
        let (rva, kind) = self.map.rva(value - self.old_image.start)?;
        Some((self.new_base + rva, kind))
    }

    /// Rewrites every aligned 8-byte word of `bytes` (at `address`) that is a mapped old-image address. Returns
    /// how many of each kind it rewrote.
    pub fn rewrite(&self, address: u64, bytes: &mut [u8]) -> Rewritten {
        let mut n = Rewritten::default();
        let first = ((8 - (address & 7)) & 7) as usize;
        let mut off = first;
        while off + 8 <= bytes.len() {
            let w = u64::from_le_bytes(bytes[off..off + 8].try_into().expect("8 bytes"));
            if let Some((new, kind)) = self.address(w) {
                bytes[off..off + 8].copy_from_slice(&new.to_le_bytes());
                n.count(kind);
            }
            off += 8;
        }
        n
    }
}

/// How many old-image addresses a run's inputs had rewritten.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Rewritten {
    pub data: usize,
    pub functions: usize,
}

impl Rewritten {
    pub fn count(&mut self, kind: Kind) {
        match kind {
            Kind::Data => self.data += 1,
            Kind::Function => self.functions += 1,
        }
    }

    pub fn add(&mut self, other: Rewritten) {
        self.data += other.data;
        self.functions += other.functions;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use permanent_beta_model::GlobalVar;

    fn export(symbols: &[(&str, u64, u64)]) -> AnalysisExport {
        let mut e: AnalysisExport = serde_json::from_value(serde_json::json!({
            "schema_version": permanent_beta_model::ANALYSIS_SCHEMA_VERSION,
            "build": { "id": "b", "file_name": "t.exe", "version": null, "machine": "x64", "pdb": null },
            "producer": { "tool": "test", "version": "0" },
            "functions": [],
        }))
        .unwrap();
        e.data_symbols = symbols
            .iter()
            .map(|(name, rva, size)| GlobalVar {
                name: (*name).into(),
                rva: Rva(*rva),
                size: *size,
                ty: String::new(),
            })
            .collect();
        e
    }

    #[test]
    fn data_maps_by_name_and_offset_functions_by_pair() {
        let old = export(&[("static_l_desc", 0x9000, 24), ("table", 0x9100, 16)]);
        let new = export(&[("static_l_desc", 0xa000, 24), ("table", 0xa200, 16)]);
        let m = AddressMap::new(&old, &new, &[(Rva(0x1040), Rva(0x1070))]);
        assert_eq!(m.rva(0x9000), Some((0xa000, Kind::Data)));
        assert_eq!(m.rva(0x9010), Some((0xa010, Kind::Data)));
        assert_eq!(m.rva(0x9108), Some((0xa208, Kind::Data)));
        assert_eq!(m.rva(0x1040), Some((0x1070, Kind::Function)));
        // Negative: inside a function, past a symbol, nowhere.
        assert_eq!(m.rva(0x1041), None);
        assert_eq!(m.rva(0x9018), None);
        assert_eq!(m.rva(0x5000), None);
    }

    #[test]
    fn what_doesnt_match_exactly_isnt_mapped() {
        // Negative: another size, a name twice in the new build, a name missing from the new build.
        let old = export(&[
            ("grew", 0x9000, 16),
            ("twice", 0x9100, 8),
            ("gone", 0x9200, 8),
        ]);
        let new = export(&[
            ("grew", 0xa000, 32),
            ("twice", 0xa100, 8),
            ("twice", 0xa200, 8),
        ]);
        let m = AddressMap::new(&old, &new, &[]);
        assert!(m.is_empty(), "{m:?}");
    }

    #[test]
    fn overlapping_entries_map_neither() {
        // Negative: a function pair that falls inside a data symbol is ambiguous.
        let old = export(&[("blob", 0x1000, 0x100)]);
        let new = export(&[("blob", 0x2000, 0x100)]);
        let m = AddressMap::new(&old, &new, &[(Rva(0x1040), Rva(0x3000))]);
        assert_eq!(m.rva(0x1040), None);
        assert_eq!(m.rva(0x1000), None);
    }

    #[test]
    fn rewrites_aligned_words_inside_the_old_image() {
        let old = export(&[("t", 0x9000, 24)]);
        let new = export(&[("t", 0xa000, 24)]);
        let m = AddressMap::new(&old, &new, &[]);
        let image = 0x7ff6_0000_0000..0x7ff6_0001_0000;
        let r = Rebase {
            map: &m,
            old_image: &image,
            new_base: 0x1_4000_0000,
        };
        let mut bytes = Vec::new();
        bytes.extend((0x7ff6_0000_9008u64).to_le_bytes()); // mapped
        bytes.extend((0x7ff6_0000_5000u64).to_le_bytes()); // in the image, not mapped
        bytes.extend((0x9008u64).to_le_bytes()); // an RVA-like integer, not an address
        let n = r.rewrite(0x5_0000_0000, &mut bytes);
        assert_eq!(
            n,
            Rewritten {
                data: 1,
                functions: 0
            }
        );
        assert_eq!(&bytes[..8], &(0x1_4000_a008u64).to_le_bytes());
        assert_eq!(&bytes[8..16], &(0x7ff6_0000_5000u64).to_le_bytes());
        assert_eq!(&bytes[16..], &(0x9008u64).to_le_bytes());
    }
}
