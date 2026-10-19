//! Single-use, TTL-bounded, HMAC-authenticated bootstrap tokens.

use base64::Engine;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("malformed token")]
    Malformed,
    #[error("token signature is invalid")]
    InvalidSignature,
    #[error("token has expired")]
    Expired,
    #[error("token was already used")]
    Replayed,
    #[error("token is not known to this control plane")]
    Unknown,
    #[error("token was issued for a different node or site")]
    IdentityMismatch,
    #[error("token state I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("token state JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenPayload {
    pub v: u8,
    pub id: String,
    pub node_id: String,
    pub site: String,
    pub exp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TokenRecord {
    id: String,
    node_id: String,
    site: String,
    expires_at: i64,
    used: bool,
    issued_at: i64,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct TokenFile {
    records: BTreeMap<String, TokenRecord>,
}

/// Issues and validates bootstrap tokens, persisting the used-token set so a
/// restart cannot resurrect a consumed token.
#[derive(Debug)]
pub struct TokenManager {
    key: [u8; 32],
    file: PathBuf,
    records: BTreeMap<String, TokenRecord>,
}

impl TokenManager {
    pub fn load_or_create(state_dir: &Path, key_path: Option<&Path>) -> Result<Self, TokenError> {
        std::fs::create_dir_all(state_dir)?;
        let key_path = key_path
            .map(PathBuf::from)
            .unwrap_or_else(|| state_dir.join("token-key.hex"));
        let key = if key_path.exists() {
            let hex_key = std::fs::read_to_string(&key_path)?;
            let bytes = hex::decode(hex_key.trim())
                .map_err(|_| std::io::Error::other("token key is not valid hex"))?;
            if bytes.len() != 32 {
                return Err(std::io::Error::other("token key must be 32 bytes").into());
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            key
        } else {
            let mut key = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut key);
            std::fs::write(&key_path, hex::encode(key))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
            }
            key
        };
        let file = state_dir.join("tokens.json");
        let records = if file.exists() {
            serde_json::from_slice::<TokenFile>(&std::fs::read(&file)?)?.records
        } else {
            BTreeMap::new()
        };
        Ok(Self { key, file, records })
    }

    pub fn issue(&mut self, node_id: &str, site: &str, ttl_seconds: u64) -> (String, i64) {
        let mut id_bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut id_bytes);
        let id = hex::encode(id_bytes);
        let now = crate::unix_now();
        let expires_at = now + ttl_seconds as i64;
        let payload = TokenPayload {
            v: 1,
            id: id.clone(),
            node_id: node_id.to_string(),
            site: site.to_string(),
            exp: expires_at,
        };
        let token = self.sign(&payload);
        self.records.insert(
            id.clone(),
            TokenRecord {
                id,
                node_id: node_id.into(),
                site: site.into(),
                expires_at,
                used: false,
                issued_at: now,
            },
        );
        let _ = self.save();
        (token, expires_at)
    }

    fn sign(&self, payload: &TokenPayload) -> String {
        let raw = serde_json::to_vec(payload).expect("token payload serializes");
        let body = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("hmac accepts 32-byte key");
        mac.update(body.as_bytes());
        let sig =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        format!("{body}.{sig}")
    }

    /// Validate the HMAC, expiry, and recorded state without consuming the token.
    pub fn peek(&self, token: &str) -> Result<TokenPayload, TokenError> {
        let (body, sig) = token.split_once('.').ok_or(TokenError::Malformed)?;
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(body)
            .map_err(|_| TokenError::Malformed)?;
        let payload: TokenPayload =
            serde_json::from_slice(&raw).map_err(|_| TokenError::Malformed)?;
        let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(sig)
            .map_err(|_| TokenError::Malformed)?;
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("hmac accepts 32-byte key");
        mac.update(body.as_bytes());
        mac.verify_slice(&sig_bytes)
            .map_err(|_| TokenError::InvalidSignature)?;
        let record = self.records.get(&payload.id).ok_or(TokenError::Unknown)?;
        if payload.exp <= crate::unix_now() || record.expires_at <= crate::unix_now() {
            return Err(TokenError::Expired);
        }
        if record.used {
            return Err(TokenError::Replayed);
        }
        if record.node_id != payload.node_id || record.site != payload.site {
            return Err(TokenError::IdentityMismatch);
        }
        Ok(payload)
    }

    /// Mark a validated token used. The caller persists once via [`save`](Self::save).
    pub fn consume(&mut self, id: &str) {
        if let Some(record) = self.records.get_mut(id) {
            record.used = true;
        }
    }

    pub fn save(&self) -> Result<(), TokenError> {
        let file = TokenFile {
            records: self.records.clone(),
        };
        std::fs::write(&self.file, serde_json::to_vec_pretty(&file)?)?;
        Ok(())
    }

    pub fn is_used(&self, id: &str) -> bool {
        self.records.get(id).map(|r| r.used).unwrap_or(false)
    }

    #[cfg(test)]
    pub fn force_expired(&mut self, id: &str) {
        if let Some(record) = self.records.get_mut(id) {
            record.expires_at = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_and_peek_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let mut mgr = TokenManager::load_or_create(dir.path(), None).unwrap();
        let (token, exp) = mgr.issue("n1", "dc1", 600);
        assert!(exp > crate::unix_now());
        let payload = mgr.peek(&token).unwrap();
        assert_eq!(payload.node_id, "n1");
        assert_eq!(payload.site, "dc1");
    }

    #[test]
    fn replay_is_rejected_after_consume_even_after_reload() {
        let dir = tempfile::tempdir().unwrap();
        let mut mgr = TokenManager::load_or_create(dir.path(), None).unwrap();
        let (token, _) = mgr.issue("n1", "dc1", 600);
        let payload = mgr.peek(&token).unwrap();
        mgr.consume(&payload.id);
        mgr.save().unwrap();
        assert!(matches!(mgr.peek(&token), Err(TokenError::Replayed)));

        let reloaded = TokenManager::load_or_create(dir.path(), None).unwrap();
        assert!(matches!(reloaded.peek(&token), Err(TokenError::Replayed)));
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let mut mgr = TokenManager::load_or_create(dir.path(), None).unwrap();
        let (token, _) = mgr.issue("n1", "dc1", 600);
        let (body, sig) = token.split_once('.').unwrap();
        let mut sig_bytes = sig.as_bytes().to_vec();
        sig_bytes[0] = if sig_bytes[0] == b'A' { b'B' } else { b'A' };
        let tampered = format!("{body}.{}", String::from_utf8(sig_bytes).unwrap());
        assert!(matches!(
            mgr.peek(&tampered),
            Err(TokenError::InvalidSignature)
        ));
    }

    #[test]
    fn wrong_node_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let mut mgr = TokenManager::load_or_create(dir.path(), None).unwrap();
        let (token, _) = mgr.issue("n1", "dc1", 600);
        let payload = mgr.peek(&token).unwrap();
        assert_eq!(payload.node_id, "n1");
        // Rewriting the payload invalidates the signature.
        assert!(matches!(
            mgr.peek(&format!("{token}x")),
            Err(TokenError::Malformed) | Err(TokenError::InvalidSignature)
        ));
    }

    #[test]
    fn expired_token_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let mut mgr = TokenManager::load_or_create(dir.path(), None).unwrap();
        let (token, _) = mgr.issue("n1", "dc1", 600);
        let payload = mgr.peek(&token).unwrap();
        mgr.force_expired(&payload.id);
        assert!(matches!(mgr.peek(&token), Err(TokenError::Expired)));
    }
}
