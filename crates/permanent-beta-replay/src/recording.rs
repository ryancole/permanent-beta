//! Loading a recording directory (`spec.toml`, `cases/<hook>/*.json`, `blobs/<sha256>`; see
//! `permanent_beta_model::case`). Every blob is checked against its digest: a case whose memory doesn't hash
//! to what it names is refused, not replayed.

use crate::image::hex;
use permanent_beta_model::{BlobRef, GlobalRegion, HarnessSpec, ImportCall, Region, TestCase};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// One recorded call with its memory loaded.
#[derive(Debug, Clone)]
pub struct LoadedCase {
    pub case: TestCase,
    pub regions: Vec<LoadedRegion>,
    pub globals: Vec<LoadedGlobal>,
    pub imports: Vec<LoadedImport>,
}

#[derive(Debug, Clone)]
pub struct LoadedGlobal {
    pub global: GlobalRegion,
    pub before: Vec<u8>,
    pub after: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct LoadedImport {
    pub call: ImportCall,
    /// (address, before, after) per snapshot.
    pub memory: Vec<(u64, Vec<u8>, Option<Vec<u8>>)>,
}

#[derive(Debug, Clone)]
pub struct LoadedRegion {
    pub region: Region,
    pub before: Vec<u8>,
    pub after: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Recording {
    pub dir: PathBuf,
    pub spec: HarnessSpec,
    pub cases: Vec<LoadedCase>,
}

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("{path}: {detail}")]
    Invalid { path: PathBuf, detail: String },
}

fn read(path: &Path) -> Result<Vec<u8>, LoadError> {
    std::fs::read(path).map_err(|source| LoadError::Io {
        path: path.to_owned(),
        source,
    })
}

fn invalid(path: &Path, detail: impl Into<String>) -> LoadError {
    LoadError::Invalid {
        path: path.to_owned(),
        detail: detail.into(),
    }
}

/// A blob's bytes, checked against its digest.
pub fn load_blob(dir: &Path, blob: &BlobRef) -> Result<Vec<u8>, LoadError> {
    let path = dir.join("blobs").join(blob.digest());
    let bytes = read(&path)?;
    let digest = hex(&Sha256::digest(&bytes));
    if digest != blob.digest() {
        return Err(invalid(&path, format!("content hashes to {digest}")));
    }
    Ok(bytes)
}

impl Recording {
    /// Loads every case of the recording, sorted by hook and test id.
    pub fn load(dir: &Path) -> Result<Self, LoadError> {
        let spec_path = dir.join("spec.toml");
        let text =
            String::from_utf8(read(&spec_path)?).map_err(|_| invalid(&spec_path, "not UTF-8"))?;
        let spec: HarnessSpec =
            toml::from_str(&text).map_err(|e| invalid(&spec_path, e.to_string()))?;
        let mut files = Vec::new();
        let cases_dir = dir.join("cases");
        if cases_dir.is_dir() {
            for hook in std::fs::read_dir(&cases_dir).map_err(|source| LoadError::Io {
                path: cases_dir.clone(),
                source,
            })? {
                let hook = hook.map_err(|source| LoadError::Io {
                    path: cases_dir.clone(),
                    source,
                })?;
                if !hook.path().is_dir() {
                    continue;
                }
                for f in std::fs::read_dir(hook.path()).map_err(|source| LoadError::Io {
                    path: hook.path(),
                    source,
                })? {
                    let f = f.map_err(|source| LoadError::Io {
                        path: hook.path(),
                        source,
                    })?;
                    if f.path().extension().is_some_and(|e| e == "json") {
                        files.push(f.path());
                    }
                }
            }
        }
        files.sort();
        let mut cases = Vec::new();
        for path in files {
            let case: TestCase =
                serde_json::from_slice(&read(&path)?).map_err(|e| invalid(&path, e.to_string()))?;
            if case.build != spec.build {
                return Err(invalid(
                    &path,
                    format!(
                        "recorded in build {}, the spec is for {}",
                        case.build, spec.build
                    ),
                ));
            }
            let regions = case
                .regions
                .iter()
                .map(|r| {
                    let (before, after) = (load_blob(dir, &r.before)?, load_blob(dir, &r.after)?);
                    if before.len() as u64 != r.size || after.len() as u64 != r.size {
                        return Err(invalid(
                            &path,
                            format!("region at {} isn't {} bytes", r.address, r.size),
                        ));
                    }
                    Ok(LoadedRegion {
                        region: r.clone(),
                        before,
                        after,
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let globals = case
                .globals
                .iter()
                .map(|g| {
                    let (before, after) = (load_blob(dir, &g.before)?, load_blob(dir, &g.after)?);
                    if before.len() as u64 != g.size || after.len() as u64 != g.size {
                        return Err(invalid(
                            &path,
                            format!("global {} isn't {} bytes", g.name, g.size),
                        ));
                    }
                    Ok(LoadedGlobal {
                        global: g.clone(),
                        before,
                        after,
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let imports = case
                .imports
                .iter()
                .map(|call| {
                    let memory = call
                        .memory
                        .iter()
                        .map(|m| {
                            let before = load_blob(dir, &m.before)?;
                            let after = m.after.as_ref().map(|a| load_blob(dir, a)).transpose()?;
                            if after.as_ref().is_some_and(|a| a.len() != before.len()) {
                                return Err(invalid(
                                    &path,
                                    format!("{} memory at {} changed size", call.import, m.address),
                                ));
                            }
                            Ok((m.address.0, before, after))
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    Ok(LoadedImport {
                        call: call.clone(),
                        memory,
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            cases.push(LoadedCase {
                case,
                regions,
                globals,
                imports,
            });
        }
        Ok(Self {
            dir: dir.to_owned(),
            spec,
            cases,
        })
    }
}
