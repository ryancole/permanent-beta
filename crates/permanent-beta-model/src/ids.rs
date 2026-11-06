use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

/// Identifies a build: the SHA-256 (hex) of the binary file.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BuildId(pub String);

impl fmt::Display for BuildId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Relative virtual address of a function entry point within one build.
///
/// Serialized as a hex string (`"0x1400"`); deserializes from a hex string, decimal string, or integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Rva(pub u64);

impl fmt::Display for Rva {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:x}", self.0)
    }
}

impl FromStr for Rva {
    type Err = std::num::ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            Some(hex) => u64::from_str_radix(hex, 16).map(Rva),
            None => s.parse::<u64>().map(Rva),
        }
    }
}

impl Serialize for Rva {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Rva {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Num(u64),
            Str(String),
        }
        match Repr::deserialize(deserializer)? {
            Repr::Num(n) => Ok(Rva(n)),
            Repr::Str(s) => s.parse().map_err(serde::de::Error::custom),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rva_round_trips_as_hex() {
        let json = serde_json::to_string(&Rva(0x1400)).unwrap();
        assert_eq!(json, "\"0x1400\"");
        assert_eq!(serde_json::from_str::<Rva>(&json).unwrap(), Rva(0x1400));
    }

    #[test]
    fn rva_accepts_integers_and_decimal_strings() {
        assert_eq!(serde_json::from_str::<Rva>("5120").unwrap(), Rva(5120));
        assert_eq!(serde_json::from_str::<Rva>("\"5120\"").unwrap(), Rva(5120));
    }

    #[test]
    fn rva_rejects_garbage() {
        assert!(serde_json::from_str::<Rva>("\"0xZZ\"").is_err());
    }
}
