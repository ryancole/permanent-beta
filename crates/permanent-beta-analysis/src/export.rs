//! Load and save the normalized JSON export.

use crate::AnalysisError;
use permanent_beta_model::{ANALYSIS_SCHEMA_VERSION, AnalysisExport};
use std::path::Path;

pub fn load(path: &Path) -> Result<AnalysisExport, AnalysisError> {
    let shown = path.display().to_string();
    let text = std::fs::read_to_string(path).map_err(|source| AnalysisError::Io {
        path: shown.clone(),
        source,
    })?;
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
    let text = serde_json::to_string_pretty(export).map_err(|source| AnalysisError::Json {
        path: shown.clone(),
        source,
    })?;
    std::fs::write(path, text).map_err(|source| AnalysisError::Io {
        path: shown,
        source,
    })
}
