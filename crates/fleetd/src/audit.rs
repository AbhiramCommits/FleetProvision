//! Append-only, hash-chained audit log.
//!
//! Each record commits to the previous record's hash, so deleting, inserting,
//! or editing any record breaks verification at that sequence number.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditRecord {
    pub seq: u64,
    pub ts: i64,
    pub actor: String,
    pub action: String,
    pub subject: String,
    pub detail: String,
    pub prev_hash: String,
    pub record_hash: String,
}

impl AuditRecord {
    pub fn compute_hash(
        seq: u64,
        ts: i64,
        actor: &str,
        action: &str,
        subject: &str,
        detail: &str,
        prev_hash: &str,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(
            format!("{seq}|{ts}|{actor}|{action}|{subject}|{detail}|{prev_hash}").as_bytes(),
        );
        hex::encode(hasher.finalize())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("audit I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("audit JSON error at line {line}: {source}")]
    Json {
        line: usize,
        source: serde_json::Error,
    },
    #[error("audit chain broken at sequence {seq}: {reason}")]
    Broken { seq: u64, reason: String },
    #[error("audit serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    pub valid: bool,
    pub records: usize,
    pub first_bad_seq: Option<u64>,
    pub reason: Option<String>,
    pub last_hash: String,
}

#[derive(Debug)]
pub struct AuditLog {
    path: PathBuf,
    seq: u64,
    last_hash: String,
}

impl AuditLog {
    pub fn open(state_dir: &Path) -> Result<Self, AuditError> {
        std::fs::create_dir_all(state_dir)?;
        let path = state_dir.join("audit.jsonl");
        let (seq, last_hash) = if path.exists() {
            let mut seq = 0;
            let mut last_hash = GENESIS_HASH.to_string();
            for line in BufReader::new(std::fs::File::open(&path)?).lines() {
                let line = line?;
                if line.trim().is_empty() {
                    continue;
                }
                let record: AuditRecord =
                    serde_json::from_str(&line).map_err(|source| AuditError::Json {
                        line: seq as usize + 1,
                        source,
                    })?;
                seq = record.seq;
                last_hash = record.record_hash;
            }
            (seq, last_hash)
        } else {
            (0, GENESIS_HASH.to_string())
        };
        Ok(Self {
            path,
            seq,
            last_hash,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn append(
        &mut self,
        actor: &str,
        action: &str,
        subject: &str,
        detail: &str,
    ) -> Result<AuditRecord, AuditError> {
        let seq = self.seq + 1;
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let record_hash =
            AuditRecord::compute_hash(seq, ts, actor, action, subject, detail, &self.last_hash);
        let record = AuditRecord {
            seq,
            ts,
            actor: actor.into(),
            action: action.into(),
            subject: subject.into(),
            detail: detail.into(),
            prev_hash: self.last_hash.clone(),
            record_hash: record_hash.clone(),
        };
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(file, "{}", serde_json::to_string(&record)?)?;
        file.sync_data()?;
        self.seq = seq;
        self.last_hash = record_hash;
        Ok(record)
    }
}

pub fn verify(path: &Path) -> Result<AuditReport, AuditError> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(AuditReport {
                valid: false,
                records: 0,
                first_bad_seq: None,
                reason: Some("audit log does not exist".into()),
                last_hash: GENESIS_HASH.into(),
            })
        }
        Err(err) => return Err(AuditError::Io(err)),
    };
    let mut records = 0usize;
    let mut expected_seq = 1u64;
    let mut prev_hash = GENESIS_HASH.to_string();
    for (idx, line) in BufReader::new(file).lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let record: AuditRecord = match serde_json::from_str(&line) {
            Ok(record) => record,
            Err(source) => {
                return Ok(AuditReport {
                    valid: false,
                    records,
                    first_bad_seq: Some(expected_seq),
                    reason: Some(format!("invalid JSON at line {}: {source}", idx + 1)),
                    last_hash: prev_hash,
                });
            }
        };
        records += 1;
        let fail = |seq: u64, reason: String| AuditReport {
            valid: false,
            records,
            first_bad_seq: Some(seq),
            reason: Some(reason),
            last_hash: prev_hash.clone(),
        };
        if record.seq != expected_seq {
            return Ok(fail(
                record.seq,
                format!("expected sequence {expected_seq}, found {}", record.seq),
            ));
        }
        if record.prev_hash != prev_hash {
            return Ok(fail(record.seq, "prev_hash does not match".into()));
        }
        let recomputed = AuditRecord::compute_hash(
            record.seq,
            record.ts,
            &record.actor,
            &record.action,
            &record.subject,
            &record.detail,
            &record.prev_hash,
        );
        if recomputed != record.record_hash {
            return Ok(fail(record.seq, "record_hash does not match".into()));
        }
        prev_hash = record.record_hash.clone();
        expected_seq += 1;
    }
    Ok(AuditReport {
        valid: true,
        records,
        first_bad_seq: None,
        reason: None,
        last_hash: prev_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(dir: &Path) -> AuditLog {
        let mut log = AuditLog::open(dir).unwrap();
        log.append("n1", "enroll", "n1", "serial=01").unwrap();
        log.append("admin", "revoke", "n2", "reason=key_compromise")
            .unwrap();
        log.append("alice", "login", "alice", "groups=fleet-admin")
            .unwrap();
        log.append("n3", "policy_failure", "n3", "secure_boot_disabled")
            .unwrap();
        log.append("dot1x", "vlan_assignment", "n1", "vlan=100")
            .unwrap();
        log
    }

    #[test]
    fn chain_verifies_and_detects_byte_flip() {
        let dir = tempfile::tempdir().unwrap();
        let log = seed(dir.path());
        assert_eq!(log.seq, 5);
        let report = verify(log.path()).unwrap();
        assert!(report.valid);
        assert_eq!(report.records, 5);

        let path = log.path().to_path_buf();
        let mut contents = std::fs::read_to_string(&path).unwrap();
        let idx = contents.find("\"actor\":\"admin\"").unwrap() + "\"actor\":\"a".len();
        contents.replace_range(idx..idx + 1, "X");
        std::fs::write(&path, contents).unwrap();
        let report = verify(&path).unwrap();
        assert!(!report.valid);
        assert_eq!(report.first_bad_seq, Some(2));
    }

    #[test]
    fn deleting_a_record_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let log = seed(dir.path());
        let path = log.path().to_path_buf();
        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        let filtered = format!("{}\n{}\n", lines[0], lines[2]);
        std::fs::write(&path, filtered).unwrap();
        let report = verify(&path).unwrap();
        assert!(!report.valid);
        assert_eq!(report.first_bad_seq, Some(3));
    }

    #[test]
    fn reload_continues_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let log = seed(dir.path());
        let last = log.last_hash.clone();
        drop(log);
        let mut reopened = AuditLog::open(dir.path()).unwrap();
        let record = reopened
            .append("admin", "renew", "n1", "serial=02")
            .unwrap();
        assert_eq!(record.seq, 6);
        assert_eq!(record.prev_hash, last);
        assert!(verify(reopened.path()).unwrap().valid);
    }
}
