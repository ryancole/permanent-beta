//! Storage (design §9). [`MappingStore`] is the boundary; [`JsonFileStore`] is a stand-in for the planned
//! SQLite backend.
//!
//! Mappings are append-only: writing a mapping for an (from, to, old) key that already has an accepted
//! mapping marks the old one `superseded` rather than editing it.

use permanent_beta_model::{BuildId, Mapping, MappingStatus, ReviewItem};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const STORE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("store I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("store data is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported store schema version {0}")]
    SchemaVersion(u32),
}

pub trait MappingStore {
    fn put_mappings(&mut self, mappings: &[Mapping]) -> Result<(), StoreError>;
    fn mappings(&self, from: &BuildId, to: &BuildId) -> Vec<Mapping>;
    fn enqueue_review(&mut self, items: &[ReviewItem]) -> Result<(), StoreError>;
    fn review_items(&self) -> Vec<ReviewItem>;
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct StoreData {
    schema_version: u32,
    mappings: Vec<Mapping>,
    review_queue: Vec<ReviewItem>,
}

pub struct JsonFileStore {
    path: PathBuf,
    data: StoreData,
}

impl JsonFileStore {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let path = path.into();
        let data = if path.exists() {
            let data: StoreData = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
            if data.schema_version != STORE_SCHEMA_VERSION {
                return Err(StoreError::SchemaVersion(data.schema_version));
            }
            data
        } else {
            StoreData {
                schema_version: STORE_SCHEMA_VERSION,
                ..Default::default()
            }
        };
        Ok(Self { path, data })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn save(&self) -> Result<(), StoreError> {
        if let Some(dir) = self.path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(&self.path, serde_json::to_string_pretty(&self.data)?)?;
        Ok(())
    }
}

impl MappingStore for JsonFileStore {
    fn put_mappings(&mut self, mappings: &[Mapping]) -> Result<(), StoreError> {
        for m in mappings {
            for existing in self.data.mappings.iter_mut().filter(|e| {
                e.status == MappingStatus::Accepted
                    && e.from_build == m.from_build
                    && e.to_build == m.to_build
                    && e.old == m.old
            }) {
                existing.status = MappingStatus::Superseded;
            }
            self.data.mappings.push(m.clone());
        }
        self.save()
    }

    fn mappings(&self, from: &BuildId, to: &BuildId) -> Vec<Mapping> {
        self.data
            .mappings
            .iter()
            .filter(|m| &m.from_build == from && &m.to_build == to)
            .cloned()
            .collect()
    }

    fn enqueue_review(&mut self, items: &[ReviewItem]) -> Result<(), StoreError> {
        for item in items {
            self.data
                .review_queue
                .retain(|existing| existing.id != item.id);
            self.data.review_queue.push(item.clone());
        }
        self.save()
    }

    fn review_items(&self) -> Vec<ReviewItem> {
        self.data.review_queue.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use permanent_beta_model::{CandidateSource, Decider, Rva};

    fn mapping(new: u64) -> Mapping {
        Mapping {
            from_build: BuildId("a".into()),
            to_build: BuildId("b".into()),
            old: Rva(0x10),
            new: Rva(new),
            decided_by: Decider::Engine,
            source: CandidateSource::Deterministic {
                matcher: "t".into(),
            },
            score: 1.0,
            evidence: vec![],
            checks: vec![],
            status: MappingStatus::Accepted,
        }
    }

    #[test]
    fn rewriting_a_mapping_supersedes_instead_of_editing() {
        let dir =
            std::env::temp_dir().join(format!("permanent-beta-store-test-{}", std::process::id()));
        let path = dir.join("store.json");
        let _ = std::fs::remove_file(&path);

        let mut store = JsonFileStore::open(&path).unwrap();
        store.put_mappings(&[mapping(0x20)]).unwrap();
        store.put_mappings(&[mapping(0x30)]).unwrap();

        let reopened = JsonFileStore::open(&path).unwrap();
        let all = reopened.mappings(&BuildId("a".into()), &BuildId("b".into()));
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].status, MappingStatus::Superseded);
        assert_eq!(all[1].status, MappingStatus::Accepted);
        assert_eq!(all[1].new, Rva(0x30));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
