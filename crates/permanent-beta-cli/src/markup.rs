//! A reverser's markup exported from a disassembler database (the IDA plugin's export, design §11.4). `pbeta`
//! reads only what it checks: the build and each function's prototype. Names, comments and types are the
//! plugin's to carry; they never reach matching or verification.

use anyhow::{Result, ensure};
use permanent_beta_model::{BuildId, Rva};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

pub const FORMAT: &str = "pbeta-markup";
pub const VERSION: u32 = 1;

#[derive(Deserialize)]
struct MarkupExport {
    format: String,
    version: u32,
    /// The exported database's input file SHA-256: the build id.
    build: BuildId,
    functions: Vec<MarkupFunction>,
}

#[derive(Deserialize)]
struct MarkupFunction {
    rva: Rva,
    #[serde(default)]
    prototype: Option<String>,
}

/// The prototypes in a markup export of `build`, by RVA. Refused for another build's export (its RVAs mean
/// nothing in this one) and for another format or version.
pub fn prototypes(text: &str, build: &BuildId) -> Result<BTreeMap<Rva, String>> {
    let m: MarkupExport = serde_json::from_str(text)?;
    ensure!(
        m.format == FORMAT && m.version == VERSION,
        "not a {FORMAT} v{VERSION} export (format {:?}, version {})",
        m.format,
        m.version
    );
    ensure!(
        m.build.0.eq_ignore_ascii_case(&build.0),
        "the markup was exported from build {}, not the old build {build}",
        m.build
    );
    Ok(m.functions
        .into_iter()
        .filter_map(|f| Some((f.rva, f.prototype.filter(|p| !p.trim().is_empty())?)))
        .collect())
}

pub fn load_prototypes(path: &Path, build: &BuildId) -> Result<BTreeMap<Rva, String>> {
    let text = std::fs::read_to_string(path)?;
    prototypes(&text, build).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn export(build: &str, format: &str) -> String {
        format!(
            r#"{{"format":"{format}","version":1,"build":"{build}","functions":[
                {{"rva":"0x1010","name":"parse","prototype":"int __fastcall parse(Packet *p)"}},
                {{"rva":"0x1040","name":"helper"}},
                {{"rva":"0x1080","prototype":"  "}}
            ],"types":"struct Packet {{ int len; }};"}}"#
        )
    }

    #[test]
    fn reads_the_prototypes_of_its_own_build() {
        let p = prototypes(&export("ABCD", FORMAT), &BuildId("abcd".into())).unwrap();
        assert_eq!(
            p,
            BTreeMap::from([(Rva(0x1010), "int __fastcall parse(Packet *p)".to_owned())])
        );
    }

    #[test]
    fn another_builds_export_is_refused() {
        // Negative: its RVAs would land on unrelated functions.
        let e = prototypes(&export("abcd", FORMAT), &BuildId("ef01".into())).unwrap_err();
        assert!(e.to_string().contains("not the old build"), "{e}");
    }

    #[test]
    fn another_format_is_refused() {
        let e = prototypes(&export("abcd", "other"), &BuildId("abcd".into())).unwrap_err();
        assert!(e.to_string().contains("not a pbeta-markup"), "{e}");
    }
}
