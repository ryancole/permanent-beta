//! Load and save the normalized JSON export.
//!
//! Saved minified, and gzip-compressed when the path ends in `.gz`. Loading accepts either, whatever the
//! extension: gzip is recognized by its magic bytes, so pretty-printed exports from older versions and the Ghidra
//! headless exporter still load.

use crate::AnalysisError;
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use permanent_beta_model::{ANALYSIS_SCHEMA_VERSION, AnalysisExport};
use std::io::{Read, Write};
use std::path::Path;

/// The first two bytes of every gzip stream (RFC 1952).
const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];

/// `bytes` as JSON text: gunzipped when it's a gzip stream, without a leading UTF-8 BOM.
pub fn decode(bytes: Vec<u8>) -> std::io::Result<String> {
    let text = if bytes.starts_with(&GZIP_MAGIC) {
        let mut text = String::new();
        GzDecoder::new(bytes.as_slice()).read_to_string(&mut text)?;
        text
    } else {
        String::from_utf8(bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?
    };
    Ok(match text.strip_prefix('\u{feff}') {
        Some(rest) => rest.to_owned(),
        None => text,
    })
}

/// Whether `save` compresses to `path`: its extension is `.gz` (any case).
pub fn is_gzip_path(path: &Path) -> bool {
    path.extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("gz"))
}

pub fn load(path: &Path) -> Result<AnalysisExport, AnalysisError> {
    let shown = path.display().to_string();
    let io = |source| AnalysisError::Io {
        path: shown.clone(),
        source,
    };
    let text = decode(std::fs::read(path).map_err(io)?).map_err(io)?;
    let export: AnalysisExport =
        serde_json::from_str(&text).map_err(|source| AnalysisError::Json {
            path: shown.clone(),
            source,
        })?;
    if export.schema_version != ANALYSIS_SCHEMA_VERSION {
        return Err(AnalysisError::SchemaVersion {
            path: shown,
            found: export.schema_version,
            expected: ANALYSIS_SCHEMA_VERSION,
        });
    }
    Ok(export)
}

pub fn save(export: &AnalysisExport, path: &Path) -> Result<(), AnalysisError> {
    let shown = path.display().to_string();
    let text = serde_json::to_vec(export).map_err(|source| AnalysisError::Json {
        path: shown.clone(),
        source,
    })?;
    let io = |source| AnalysisError::Io {
        path: shown.clone(),
        source,
    };
    let bytes = if is_gzip_path(path) {
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(&text).map_err(io)?;
        gz.finish().map_err(io)?
    } else {
        text
    };
    std::fs::write(path, bytes).map_err(io)
}

#[cfg(test)]
mod tests {
    use super::*;
    use permanent_beta_model::{BuildId, BuildInfo, Machine, Producer};

    fn export() -> AnalysisExport {
        AnalysisExport {
            schema_version: ANALYSIS_SCHEMA_VERSION,
            build: BuildInfo {
                id: BuildId("ab".repeat(32)),
                file_name: "x.exe".into(),
                version: None,
                machine: Machine::X64,
                pdb: None,
            },
            producer: Producer {
                tool: "test".into(),
                version: "0".into(),
            },
            features_version: None,
            functions: Vec::new(),
            code_tables: Vec::new(),
            types: Vec::new(),
            globals: Vec::new(),
            data_symbols: Vec::new(),
            pointer_aliases: Vec::new(),
        }
    }

    fn dir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("pbeta-export-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn json_path_is_saved_minified_and_loads() {
        let p = dir("json").join("a.json");
        save(&export(), &p).unwrap();
        let bytes = std::fs::read(&p).unwrap();
        assert_eq!(bytes[0], b'{');
        assert!(!bytes.contains(&b'\n'), "minified output has no newlines");
        assert_eq!(load(&p).unwrap().build.id, export().build.id);
    }

    #[test]
    fn gz_path_is_saved_compressed_and_loads() {
        let p = dir("gz").join("a.json.gz");
        save(&export(), &p).unwrap();
        assert!(std::fs::read(&p).unwrap().starts_with(&GZIP_MAGIC));
        assert_eq!(load(&p).unwrap().build.id, export().build.id);
    }

    #[test]
    fn gzip_is_detected_by_content_not_extension() {
        let d = dir("detect");
        // Gzip under a .json name.
        let gz = d.join("a.json.gz");
        save(&export(), &gz).unwrap();
        let renamed = d.join("renamed.json");
        std::fs::copy(&gz, &renamed).unwrap();
        assert_eq!(load(&renamed).unwrap().build.id, export().build.id);
        // Pretty-printed with a BOM (an older pbeta, or a PowerShell rewrite) still loads.
        let pretty = d.join("pretty.json");
        let text = format!(
            "\u{feff}{}",
            serde_json::to_string_pretty(&export()).unwrap()
        );
        std::fs::write(&pretty, text).unwrap();
        assert_eq!(load(&pretty).unwrap().build.id, export().build.id);
    }

    #[test]
    fn truncated_gzip_is_an_error_not_a_partial_export() {
        let d = dir("trunc");
        let gz = d.join("a.json.gz");
        save(&export(), &gz).unwrap();
        let bytes = std::fs::read(&gz).unwrap();
        let cut = d.join("cut.json.gz");
        std::fs::write(&cut, &bytes[..bytes.len() / 2]).unwrap();
        assert!(matches!(load(&cut), Err(AnalysisError::Io { .. })));
    }

    #[test]
    fn non_gzip_binary_is_rejected() {
        let p = dir("bin").join("a.json");
        std::fs::write(&p, [0x4d, 0x5a, 0x90, 0x00, 0xff]).unwrap();
        assert!(load(&p).is_err());
    }
}
