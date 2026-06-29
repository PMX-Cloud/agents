use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MANIFEST_SCHEMA: &str = "pmx-manifest-v1";

#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("schema mismatch: expected {expected}, got {got}")]
    SchemaMismatch { expected: String, got: String },
    #[error("json parse: {0}")]
    Json(#[from] serde_json::Error),
    #[error("missing agent entry for name={name} arch={arch}")]
    MissingEntry { name: String, arch: String },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Manifest {
    pub schema: String,
    pub version: String,
    #[serde(rename = "issuedAt")]
    pub issued_at: DateTime<Utc>,
    pub agents: Vec<AgentEntry>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AgentEntry {
    pub name: String,
    pub arch: String,
    pub url: String,
    pub sha256: String,
    pub sig: String,
    pub min_compat: String,
}

impl Manifest {
    pub fn parse(bytes: &[u8]) -> Result<Self, ManifestError> {
        let m: Self = serde_json::from_slice(bytes)?;
        if m.schema != MANIFEST_SCHEMA {
            return Err(ManifestError::SchemaMismatch {
                expected: MANIFEST_SCHEMA.to_string(),
                got: m.schema.clone(),
            });
        }
        Ok(m)
    }

    pub fn find_entry(&self, name: &str, arch: &str) -> Result<&AgentEntry, ManifestError> {
        self.agents
            .iter()
            .find(|e| e.name == name && e.arch == arch)
            .ok_or_else(|| ManifestError::MissingEntry {
                name: name.to_string(),
                arch: arch.to_string(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_manifest_bytes() -> Vec<u8> {
        serde_json::json!({
            "schema": "pmx-manifest-v1",
            "version": "1.4.2",
            "issuedAt": "2026-05-12T18:00:00Z",
            "agents": [
                {
                    "name": "pmx-network",
                    "arch": "amd64",
                    "url": "https://releases.pmxcloud.cloud/v1.4.2/pmx-network-1.4.2-linux-amd64",
                    "sha256": "deadbeef",
                    "sig": "cafebabe",
                    "min_compat": "1.4.0"
                }
            ]
        })
        .to_string()
        .into_bytes()
    }

    #[test]
    fn parse_valid_manifest() {
        let bytes = sample_manifest_bytes();
        let m = Manifest::parse(&bytes).expect("should parse");
        assert_eq!(m.schema, MANIFEST_SCHEMA);
        assert_eq!(m.version, "1.4.2");
        assert_eq!(m.agents.len(), 1);
        assert_eq!(m.agents[0].name, "pmx-network");
    }

    #[test]
    fn parse_rejects_schema_mismatch() {
        let bytes = serde_json::json!({
            "schema": "pmx-manifest-v99",
            "version": "1.4.2",
            "issuedAt": "2026-05-12T18:00:00Z",
            "agents": []
        })
        .to_string()
        .into_bytes();
        let err = Manifest::parse(&bytes).expect_err("should reject bad schema");
        assert!(matches!(err, ManifestError::SchemaMismatch { .. }));
        assert!(err.to_string().contains("pmx-manifest-v99"));
    }

    #[test]
    fn find_entry_returns_correct() {
        let bytes = sample_manifest_bytes();
        let m = Manifest::parse(&bytes).expect("parse");
        let entry = m.find_entry("pmx-network", "amd64").expect("should find");
        assert_eq!(entry.url, "https://releases.pmxcloud.cloud/v1.4.2/pmx-network-1.4.2-linux-amd64");
        assert_eq!(entry.sha256, "deadbeef");
    }

    #[test]
    fn find_entry_missing_returns_err() {
        let bytes = sample_manifest_bytes();
        let m = Manifest::parse(&bytes).expect("parse");
        let err = m.find_entry("pmx-nonexistent", "amd64").expect_err("should miss");
        assert!(matches!(err, ManifestError::MissingEntry { .. }));
        assert!(err.to_string().contains("pmx-nonexistent"));
    }
}
