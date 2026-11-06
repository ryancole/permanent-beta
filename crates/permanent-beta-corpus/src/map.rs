//! MSVC linker map file (`link /MAP`) parser.
//!
//! Relevant layout:
//!
//! ```text
//!  Preferred load address is 0000000140000000
//!  ...
//!   Address         Publics by Value              Rva+Base               Lib:Object
//!  0001:000000c0       pb_body_edited             00000001400010c0 f   fixture.obj
//!  ...
//!  Static symbols
//!  0001:00000130       pb_static_strings          0000000140001130 f   fixture.obj
//! ```
//!
//! Symbol lines are `section:offset  name  va  [f] [i]  lib:object`. `f` marks a function.

use permanent_beta_model::Rva;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MapError {
    #[error("no `Preferred load address` line found")]
    MissingBase,
    #[error("no `Publics by Value` section found")]
    MissingPublics,
    #[error("line {line}: symbol address {va:#x} is below the preferred load address {base:#x}")]
    AddressBelowBase { line: usize, va: u64, base: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapSymbol {
    pub name: String,
    pub rva: Rva,
    pub is_function: bool,
    /// Listed under `Static symbols` (internal linkage).
    pub is_static: bool,
    /// `lib:object` or `object`, e.g. `fixture.obj` or `MSVCRT:exe_main.obj`.
    pub object: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapFile {
    pub preferred_base: u64,
    pub symbols: Vec<MapSymbol>,
}

impl MapFile {
    /// Functions defined in `object` itself (not in a library member such as `MSVCRT:exe_main.obj`).
    pub fn functions_in<'a>(&'a self, object: &'a str) -> impl Iterator<Item = &'a MapSymbol> {
        self.symbols
            .iter()
            .filter(move |s| s.is_function && s.object == object)
    }
}

pub fn parse(text: &str) -> Result<MapFile, MapError> {
    let mut base = None;
    let mut in_symbols = false;
    let mut is_static = false;
    let mut saw_publics = false;
    let mut symbols = Vec::new();

    for (i, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("Preferred load address is ") {
            base = u64::from_str_radix(rest.trim(), 16).ok();
            continue;
        }
        if trimmed.contains("Publics by Value") {
            in_symbols = true;
            saw_publics = true;
            continue;
        }
        if trimmed == "Static symbols" {
            in_symbols = true;
            is_static = true;
            continue;
        }
        if trimmed.starts_with("entry point at") {
            continue;
        }
        if !in_symbols {
            continue;
        }
        let Some(sym) = parse_symbol_line(trimmed) else {
            continue;
        };
        let base = base.ok_or(MapError::MissingBase)?;
        let rva = sym.va.checked_sub(base).ok_or(MapError::AddressBelowBase {
            line: i + 1,
            va: sym.va,
            base,
        })?;
        symbols.push(MapSymbol {
            name: sym.name.to_owned(),
            rva: Rva(rva),
            is_function: sym.is_function,
            is_static,
            object: sym.object.to_owned(),
        });
    }

    if !saw_publics {
        return Err(MapError::MissingPublics);
    }
    Ok(MapFile {
        preferred_base: base.ok_or(MapError::MissingBase)?,
        symbols,
    })
}

struct RawSymbol<'a> {
    name: &'a str,
    va: u64,
    is_function: bool,
    object: &'a str,
}

fn parse_symbol_line(line: &str) -> Option<RawSymbol<'_>> {
    let mut tokens = line.split_whitespace();
    let addr = tokens.next()?;
    let (sec, off) = addr.split_once(':')?;
    // Section 0000 holds absolute symbols (e.g. `__guard_flags`), which have no address in the image.
    if sec.len() != 4 || off.len() != 8 || !is_hex(sec) || !is_hex(off) || sec == "0000" {
        return None;
    }
    let name = tokens.next()?;
    let va_text = tokens.next()?;
    if va_text.len() != 16 || !is_hex(va_text) {
        return None;
    }
    let va = u64::from_str_radix(va_text, 16).ok()?;
    let rest: Vec<&str> = tokens.collect();
    let object = *rest.last()?;
    let flags = &rest[..rest.len() - 1];
    Some(RawSymbol {
        name,
        va,
        is_function: flags.contains(&"f"),
        object,
    })
}

fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
 fixture

 Preferred load address is 0000000140000000

 Start         Length     Name                   Class
 0001:00000000 00000da0H .text$mn                CODE

  Address         Publics by Value              Rva+Base               Lib:Object

 0000:00000000       __guard_flags              0000000000000000     <absolute>
 0001:000000c0       pb_body_edited             00000001400010c0 f   fixture.obj
 0001:00000490       mainCRTStartup             0000000140001490 f   MSVCRT:exe_main.obj
 0002:00000784       $unwind$main               0000000140002784     fixture.obj

 entry point at        0001:00000490

 Static symbols

 0001:00000130       pb_static_strings          0000000140001130 f   fixture.obj
";

    #[test]
    fn parses_publics_and_statics() {
        let map = parse(SAMPLE).unwrap();
        assert_eq!(map.preferred_base, 0x1_4000_0000);
        let f: Vec<_> = map.functions_in("fixture.obj").collect();
        assert_eq!(f.len(), 2);
        assert_eq!(
            (f[0].name.as_str(), f[0].rva, f[0].is_static),
            ("pb_body_edited", Rva(0x10c0), false)
        );
        assert_eq!(
            (f[1].name.as_str(), f[1].rva, f[1].is_static),
            ("pb_static_strings", Rva(0x1130), true)
        );
    }

    #[test]
    fn excludes_data_and_other_objects() {
        let map = parse(SAMPLE).unwrap();
        let names: Vec<_> = map
            .functions_in("fixture.obj")
            .map(|s| s.name.as_str())
            .collect();
        assert!(
            !names.contains(&"$unwind$main"),
            "data symbol (no `f` flag)"
        );
        assert!(!names.contains(&"mainCRTStartup"), "CRT object");
        assert!(
            !map.symbols.iter().any(|s| s.name == "__guard_flags"),
            "absolute symbols are skipped, not rejected as below the base"
        );
    }

    #[test]
    fn symbol_below_base_is_an_error() {
        let text = " Preferred load address is 0000000140000000\n  Address  Publics by Value\n \
                    0001:00000000       f                          0000000000001000 f   x.obj\n";
        assert!(matches!(
            parse(text),
            Err(MapError::AddressBelowBase { .. })
        ));
    }

    #[test]
    fn missing_publics_is_an_error() {
        assert_eq!(
            parse(" Preferred load address is 0000000140000000\n"),
            Err(MapError::MissingPublics)
        );
    }
}
