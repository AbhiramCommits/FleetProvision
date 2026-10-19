//! Persistent node inventory. A JSON file keeps the system restart-safe
//! without requiring an external database.

use crate::tokens::{TokenError, TokenManager};
use fleet_proto::{NodeState, NodeSummary};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRecord {
    pub node_id: String,
    pub site: String,
    pub hostname: String,
    pub state: NodeState,
    pub serial_hex: Option<String>,
    pub cert_pem: Option<String>,
    pub not_after: Option<i64>,
    pub violations: Vec<String>,
    pub attestation_passed: bool,
    pub last_seen: i64,
    pub created_at: i64,
    pub updated_at: i64,
    pub vlan: Option<u16>,
    pub renewal_count: u32,
}

impl NodeRecord {
    pub fn pending(node_id: &str, site: &str, hostname: &str) -> Self {
        let now = crate::unix_now();
        Self {
            node_id: node_id.into(),
            site: site.into(),
            hostname: hostname.into(),
            state: NodeState::Pending,
            serial_hex: None,
            cert_pem: None,
            not_after: None,
            violations: Vec::new(),
            attestation_passed: false,
            last_seen: now,
            created_at: now,
            updated_at: now,
            vlan: Some(666),
            renewal_count: 0,
        }
    }

    pub fn summary(&self) -> NodeSummary {
        NodeSummary {
            node_id: self.node_id.clone(),
            site: self.site.clone(),
            hostname: self.hostname.clone(),
            state: self.state,
            serial_hex: self.serial_hex.clone(),
            not_after: self.not_after,
            violations: self.violations.clone(),
            attestation_passed: self.attestation_passed,
            last_seen: self.last_seen,
            created_at: self.created_at,
            vlan: self.vlan,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("illegal state transition from {from} to {to}")]
    IllegalTransition { from: NodeState, to: NodeState },
    #[error("node {0} not found")]
    NotFound(String),
    #[error("node {0} is revoked and cannot be enrolled again")]
    Revoked(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("token error: {0}")]
    Token(#[from] TokenError),
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct NodesFile {
    nodes: BTreeMap<String, NodeRecord>,
}

#[derive(Debug)]
pub struct Store {
    nodes_path: PathBuf,
    pub nodes: BTreeMap<String, NodeRecord>,
    pub tokens: TokenManager,
}

impl Store {
    pub fn load(state_dir: &Path, token_key: Option<&Path>) -> Result<Self, StoreError> {
        std::fs::create_dir_all(state_dir)?;
        let nodes_path = state_dir.join("nodes.json");
        let nodes = if nodes_path.exists() {
            serde_json::from_slice::<NodesFile>(&std::fs::read(&nodes_path)?)?.nodes
        } else {
            BTreeMap::new()
        };
        Ok(Self {
            nodes_path,
            nodes,
            tokens: TokenManager::load_or_create(state_dir, token_key)?,
        })
    }

    pub fn save(&self) -> Result<(), StoreError> {
        let file = NodesFile {
            nodes: self.nodes.clone(),
        };
        let tmp = self.nodes_path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(&file)?)?;
        std::fs::rename(&tmp, &self.nodes_path)?;
        self.tokens.save()?;
        Ok(())
    }

    pub fn get(&self, node_id: &str) -> Option<&NodeRecord> {
        self.nodes.get(node_id)
    }

    pub fn list(&self) -> Vec<NodeSummary> {
        let mut nodes: Vec<_> = self.nodes.values().map(NodeRecord::summary).collect();
        nodes.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        nodes
    }

    pub fn upsert(&mut self, record: NodeRecord) -> Result<(), StoreError> {
        let existing = self.nodes.get(&record.node_id);
        if let Some(existing) = existing {
            if existing.state == NodeState::Revoked && record.state != NodeState::Revoked {
                return Err(StoreError::Revoked(record.node_id.clone()));
            }
            if existing.state != record.state && !existing.state.can_transition_to(record.state) {
                return Err(StoreError::IllegalTransition {
                    from: existing.state,
                    to: record.state,
                });
            }
        }
        self.nodes.insert(record.node_id.clone(), record);
        self.save()
    }

    pub fn transition(&mut self, node_id: &str, next: NodeState) -> Result<NodeRecord, StoreError> {
        let record = self
            .nodes
            .get_mut(node_id)
            .ok_or_else(|| StoreError::NotFound(node_id.into()))?;
        if record.state != next && !record.state.can_transition_to(next) {
            return Err(StoreError::IllegalTransition {
                from: record.state,
                to: next,
            });
        }
        record.state = next;
        record.updated_at = crate::unix_now();
        let out = record.clone();
        self.save()?;
        Ok(out)
    }

    pub fn touch(&mut self, node_id: &str) -> Result<(), StoreError> {
        let record = self
            .nodes
            .get_mut(node_id)
            .ok_or_else(|| StoreError::NotFound(node_id.into()))?;
        record.last_seen = crate::unix_now();
        record.updated_at = record.last_seen;
        self.save()
    }

    pub fn expiries(&self) -> Vec<(String, i64)> {
        self.nodes
            .values()
            .filter_map(|n| n.not_after.map(|e| (n.node_id.clone(), e)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persistence_and_transitions() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::load(dir.path(), None).unwrap();
        store
            .upsert(NodeRecord::pending("n1", "dc1", "n1"))
            .unwrap();
        store.transition("n1", NodeState::Attested).unwrap();
        store.transition("n1", NodeState::Enrolled).unwrap();
        drop(store);
        let reloaded = Store::load(dir.path(), None).unwrap();
        assert_eq!(reloaded.get("n1").unwrap().state, NodeState::Enrolled);
        assert_eq!(reloaded.list().len(), 1);
    }

    #[test]
    fn illegal_and_terminal_transitions_fail() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::load(dir.path(), None).unwrap();
        store
            .upsert(NodeRecord::pending("n1", "dc1", "n1"))
            .unwrap();
        assert!(store.transition("n1", NodeState::Enrolled).is_err());
        store.transition("n1", NodeState::Revoked).unwrap();
        assert!(store.transition("n1", NodeState::Enrolled).is_err());
        let mut record = store.get("n1").unwrap().clone();
        record.state = NodeState::Enrolled;
        assert!(store.upsert(record).is_err());
    }

    #[test]
    fn summaries_are_sorted() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::load(dir.path(), None).unwrap();
        store
            .upsert(NodeRecord::pending("n2", "dc1", "n2"))
            .unwrap();
        store
            .upsert(NodeRecord::pending("n1", "dc1", "n1"))
            .unwrap();
        let ids: Vec<_> = store.list().into_iter().map(|n| n.node_id).collect();
        assert_eq!(ids, vec!["n1", "n2"]);
    }
}
