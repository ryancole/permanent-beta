//! AOB (array-of-bytes) patterns for hook locators (design §7.2): the shortest run of a function's entry bytes
//! that occurs exactly once in the image's executable code, with every byte that moves when unrelated code moves
//! replaced by a `??` wildcard.
//!
//! Wildcarded, per instruction: RIP-relative displacements, branch displacements that leave the function (calls
//! and tail jumps), and displacements or immediates that are addresses inside the image. Everything else stays
//! concrete (opcodes, registers, stack offsets, struct offsets, constants and branches inside the function), so
//! the pattern still tells code apart by what it does.
//!
//! A pattern is grown one whole instruction at a time from the entry, never past the function's main range, and
//! is at least [`MIN_LEN`] bytes. If no prefix of the function is unique (identical code elsewhere, e.g. a copy
//! the linker didn't fold), there is no pattern: repair must not ship one that could resolve to the copy.

use super::function::{FunctionRange, discover};
use super::image::Image;
use iced_x86::{Decoder, DecoderOptions, Instruction, OpKind};
use std::fmt;
use std::str::FromStr;

/// At least the Detours patch size (a 5-byte `jmp`), plus a little: a pattern shorter than the bytes a hook
/// overwrites would also match the patched function's own `jmp`.
pub const MIN_LEN: usize = 8;

/// A byte pattern; `None` is a wildcard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern(pub Vec<Option<u8>>);

impl Pattern {
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn wildcards(&self) -> usize {
        self.0.iter().filter(|b| b.is_none()).count()
    }

    fn matches_at(&self, data: &[u8], at: usize) -> bool {
        data.get(at..at + self.0.len()).is_some_and(|window| {
            self.0
                .iter()
                .zip(window)
                .all(|(p, b)| p.is_none_or(|p| p == *b))
        })
    }
}

impl fmt::Display for Pattern {
    /// Space-separated hex bytes, `??` for wildcards (the manifest's `target.pattern` format).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let parts: Vec<String> = self
            .0
            .iter()
            .map(|b| b.map_or_else(|| "??".to_owned(), |b| format!("{b:02X}")))
            .collect();
        f.write_str(&parts.join(" "))
    }
}

impl FromStr for Pattern {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let bytes = s
            .split_whitespace()
            .map(|t| match t {
                "?" | "??" => Ok(None),
                hex => u8::from_str_radix(hex, 16)
                    .map(Some)
                    .map_err(|_| format!("bad pattern byte {hex:?}")),
            })
            .collect::<Result<Vec<_>, _>>()?;
        if bytes.iter().all(Option::is_none) {
            return Err("pattern has no concrete bytes".into());
        }
        Ok(Pattern(bytes))
    }
}

/// Why no pattern could be made for a function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatternError {
    /// No function starts at this RVA.
    NoFunction,
    /// Even the whole main range (this many bytes) occurs elsewhere in the executable code.
    NotUnique { len: usize, matches: usize },
}

impl fmt::Display for PatternError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoFunction => f.write_str("no function starts there"),
            Self::NotUnique { len, matches } => write!(
                f,
                "no unique pattern: all {len} bytes of the function match {matches} places in the code"
            ),
        }
    }
}

/// Generates and finds patterns in one image. Function boundaries come from the analyzer's own discovery.
pub struct PatternIndex {
    image: Image,
    functions: Vec<FunctionRange>,
}

impl PatternIndex {
    /// Parse a PE x64 file.
    pub fn new(pe_bytes: &[u8]) -> Result<Self, String> {
        let image = Image::parse(pe_bytes)?;
        Ok(Self::from_image(image))
    }

    pub(crate) fn from_image(image: Image) -> Self {
        let functions = discover(&image);
        Self { image, functions }
    }

    /// Every RVA in executable code where `pattern` matches.
    pub fn find(&self, pattern: &Pattern) -> Vec<u64> {
        let mut out = Vec::new();
        for s in self.image.sections.iter().filter(|s| s.executable) {
            let end = self.image.section_end(s.rva).unwrap_or(s.rva) - s.rva;
            let data = &s.data[..(end as usize).min(s.data.len())];
            for at in 0..data.len() {
                if pattern.matches_at(data, at) {
                    out.push(s.rva as u64 + at as u64);
                }
            }
        }
        out
    }

    /// The shortest unique pattern for the function starting at `rva`.
    pub fn generate(&self, rva: u64) -> Result<Pattern, PatternError> {
        let range = u32::try_from(rva)
            .ok()
            .and_then(|r| self.functions.iter().find(|f| f.start == r))
            .ok_or(PatternError::NoFunction)?;
        let (start, end) = (range.start, range.end);
        let bytes = self
            .image
            .bytes(start, (end - start) as usize)
            .ok_or(PatternError::NoFunction)?;
        let start_va = self.image.base + start as u64;
        let end_va = self.image.base + end as u64;

        let mut decoder = Decoder::with_ip(64, bytes, start_va, DecoderOptions::NONE);
        let mut ins = Instruction::default();
        let mut pattern: Vec<Option<u8>> = Vec::new();
        let mut matches = 0;
        while decoder.can_decode() {
            let offset = pattern.len();
            decoder.decode_out(&mut ins);
            if ins.is_invalid() {
                break;
            }
            let co = decoder.get_constant_offsets(&ins);
            let mut chunk: Vec<Option<u8>> = bytes[offset..offset + ins.len()]
                .iter()
                .copied()
                .map(Some)
                .collect();
            let mut wildcard = |at: usize, size: usize| {
                for b in chunk.iter_mut().skip(at).take(size) {
                    *b = None;
                }
            };
            if co.has_displacement() {
                let moves = ins.is_ip_rel_memory_operand()
                    || self.image.contains_va(ins.memory_displacement64());
                if moves {
                    wildcard(co.displacement_offset(), co.displacement_size());
                }
            }
            if co.has_immediate() {
                let is_branch = (0..ins.op_count()).any(|op| {
                    matches!(
                        ins.op_kind(op),
                        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
                    )
                });
                let moves = if is_branch {
                    let t = ins.near_branch_target();
                    !(start_va..end_va).contains(&t)
                } else {
                    (0..ins.op_count()).any(|op| {
                        is_immediate(ins.op_kind(op)) && self.image.contains_va(ins.immediate(op))
                    })
                };
                if moves {
                    wildcard(co.immediate_offset(), co.immediate_size());
                }
            }
            pattern.extend(chunk);

            if pattern.len() >= MIN_LEN && pattern.iter().any(Option::is_some) {
                let candidate = trimmed(&pattern);
                matches = self.find(&candidate).len();
                if matches == 1 {
                    return Ok(candidate);
                }
            }
        }
        Err(PatternError::NotUnique {
            len: pattern.len(),
            matches,
        })
    }
}

fn is_immediate(kind: OpKind) -> bool {
    matches!(
        kind,
        OpKind::Immediate8
            | OpKind::Immediate8_2nd
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64
    )
}

/// Drop trailing wildcards: they never narrow a match.
fn trimmed(bytes: &[Option<u8>]) -> Pattern {
    let end = bytes.iter().rposition(Option::is_some).map_or(0, |i| i + 1);
    Pattern(bytes[..end].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::image::tests::image;

    /// Two functions with distinct code, then a byte-identical copy of the first.
    ///   0x1000: sub rsp,28h; call 0x1040 (rel32, leaves the function); add rsp,28h; ret
    ///   0x1010: mov eax,[rip+0x1000]; add eax,1; ret
    ///   0x1020: same as 0x1000 but its call reaches 0x1040 from a different place
    fn code() -> Vec<u8> {
        let mut c = vec![0xCC; 0x50];
        let f1 = [
            0x48, 0x83, 0xEC, 0x28, // sub rsp, 28h
            0xE8, 0x37, 0x00, 0x00, 0x00, // call 0x1040
            0x48, 0x83, 0xC4, 0x28, // add rsp, 28h
            0xC3, // ret
        ];
        c[..f1.len()].copy_from_slice(&f1);
        let f2 = [
            0x8B, 0x05, 0xEA, 0x0F, 0x00, 0x00, // mov eax, [rip+0xfea] (-> 0x2000)
            0x83, 0xC0, 0x01, // add eax, 1
            0xC3, // ret
        ];
        c[0x10..0x10 + f2.len()].copy_from_slice(&f2);
        let mut f3 = f1;
        f3[5] = 0x17; // call 0x1040 from 0x1024: different displacement, same code
        c[0x20..0x20 + f3.len()].copy_from_slice(&f3);
        c[0x40] = 0xC3;
        c
    }

    fn index() -> PatternIndex {
        let mut image = image(&code(), &[0u8; 16]);
        image.exports = vec![
            (0x1000, "f1".into()),
            (0x1010, "f2".into()),
            (0x1020, "f3".into()),
        ];
        PatternIndex::from_image(image)
    }

    #[test]
    fn rip_relative_displacements_are_wildcarded_and_the_pattern_is_unique() {
        let ix = index();
        let p = ix.generate(0x1010).unwrap();
        assert_eq!(p.to_string(), "8B 05 ?? ?? ?? ?? 83 C0 01");
        assert_eq!(ix.find(&p), vec![0x1010]);
    }

    #[test]
    fn identical_code_has_no_pattern() {
        // f1 and f3 differ only in their call displacement, which is wildcarded: no prefix tells them apart, so
        // neither may get a pattern that could resolve to the other.
        let ix = index();
        let err = ix.generate(0x1000).unwrap_err();
        assert!(
            matches!(err, PatternError::NotUnique { matches: 2, .. }),
            "{err}"
        );
        assert!(ix.generate(0x1020).is_err());
    }

    #[test]
    fn no_function_no_pattern() {
        assert_eq!(index().generate(0x1004), Err(PatternError::NoFunction));
    }

    #[test]
    fn parses_and_prints_the_manifest_format() {
        let p: Pattern = "48 89 5C 24 ?? 57".parse().unwrap();
        assert_eq!(p.wildcards(), 1);
        assert_eq!(p.to_string(), "48 89 5C 24 ?? 57");
        assert!("?? ??".parse::<Pattern>().is_err());
        assert!("4G".parse::<Pattern>().is_err());
    }
}
