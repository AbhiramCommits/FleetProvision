//! Shared wire types for the FleetProvision control plane.

use serde::{Deserialize, Serialize};

/// Lifecycle of a node as tracked by `fleetd`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeState {
    /// Enrolled a bootstrap token, but no attestation has been evaluated yet.
    Pending,
    /// Attestation passed; eligible for certificate issuance.
    Attested,
    /// Holding a valid leaf certificate.
    Enrolled,
    /// Failed boot-integrity policy or was administratively isolated.
    Quarantined,
    /// Certificate revoked; all mTLS access is denied.
    Revoked,
}

impl NodeState {
    /// Returns true when a transition is legal. Revocation is terminal except
    /// for an explicit re-image flow that starts a brand new identity.
    pub fn can_transition_to(self, next: NodeState) -> bool {
        use NodeState::*;
        matches!(
            (self, next),
            (Pending, Attested)
                | (Pending, Quarantined)
                | (Pending, Revoked)
                | (Attested, Enrolled)
                | (Attested, Quarantined)
                | (Attested, Revoked)
                | (Enrolled, Quarantined)
                | (Enrolled, Revoked)
                | (Quarantined, Revoked)
                | (Quarantined, Attested)
                | (Quarantined, Enrolled)
        )
    }

    pub fn is_active(self) -> bool {
        matches!(self, NodeState::Enrolled | NodeState::Attested)
    }
}

impl std::fmt::Display for NodeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            NodeState::Pending => "pending",
            NodeState::Attested => "attested",
            NodeState::Enrolled => "enrolled",
            NodeState::Quarantined => "quarantined",
            NodeState::Revoked => "revoked",
        };
        f.write_str(s)
    }
}

/// Bootstrap token request from an operator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTokenRequest {
    pub node_id: String,
    pub site: String,
    #[serde(default = "default_token_ttl")]
    pub ttl_seconds: u64,
}

fn default_token_ttl() -> u64 {
    900
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTokenResponse {
    pub token: String,
    pub node_id: String,
    pub site: String,
    pub expires_at: i64,
}

/// Bootstrap request for a simulated TPM endorsement/AK certificate. The AK
/// is only used to sign quotes; it is not a TLS identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AkCertRequest {
    pub token: String,
    pub csr_pem: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AkCertResponse {
    pub node_id: String,
    pub cert_pem: String,
    pub serial_hex: String,
}

/// A node asks for a fresh nonce before producing a TPM quote.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeRequest {
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResponse {
    pub nonce: String,
    pub expires_at: i64,
}

/// Enrollment request from a node that does not yet have a certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollRequest {
    pub token: String,
    pub node_id: String,
    pub site: String,
    pub hostname: String,
    pub csr_pem: String,
    /// Opaque at this layer so the attestation crate owns the schema.
    #[serde(default)]
    pub attestation: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollResponse {
    pub node_id: String,
    pub state: NodeState,
    pub cert_pem: String,
    pub chain_pem: String,
    pub trust_bundle_pem: String,
    pub serial_hex: String,
    pub not_after: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenewRequest {
    pub csr_pem: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    pub node_id: String,
    pub sent_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatResponse {
    pub ok: bool,
    pub server_time: i64,
    pub crl_number: u64,
    pub state: NodeState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeRequest {
    #[serde(default = "default_revoke_reason")]
    pub reason: String,
}

fn default_revoke_reason() -> String {
    "key_compromise".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeSummary {
    pub node_id: String,
    pub site: String,
    pub hostname: String,
    pub state: NodeState,
    pub serial_hex: Option<String>,
    pub not_after: Option<i64>,
    pub violations: Vec<String>,
    pub attestation_passed: bool,
    pub last_seen: i64,
    pub created_at: i64,
    pub vlan: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodesResponse {
    pub nodes: Vec<NodeSummary>,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    pub error: String,
    pub code: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub violations: Vec<String>,
}

impl ApiError {
    pub fn new(code: &str, error: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            error: error.into(),
            violations: Vec::new(),
        }
    }
}

/// Certificate material returned by enrollment and renewal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuedMaterial {
    pub cert_pem: String,
    pub key_pem: Option<String>,
    pub chain_pem: String,
    pub trust_bundle_pem: String,
    pub serial_hex: String,
    pub not_after: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoAmI {
    pub node_id: String,
    pub site: String,
    pub hostname: String,
    pub serial_hex: String,
    pub role: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn happy_path_transitions_are_allowed() {
        assert!(NodeState::Pending.can_transition_to(NodeState::Attested));
        assert!(NodeState::Attested.can_transition_to(NodeState::Enrolled));
        assert!(NodeState::Enrolled.can_transition_to(NodeState::Revoked));
    }

    #[test]
    fn revoked_is_terminal() {
        for state in [
            NodeState::Pending,
            NodeState::Attested,
            NodeState::Enrolled,
            NodeState::Quarantined,
            NodeState::Revoked,
        ] {
            assert!(!NodeState::Revoked.can_transition_to(state));
        }
    }

    #[test]
    fn cannot_enroll_without_attestation() {
        assert!(!NodeState::Pending.can_transition_to(NodeState::Enrolled));
    }

    #[test]
    fn state_round_trips_through_json() {
        let encoded = serde_json::to_string(&NodeState::Quarantined).unwrap();
        assert_eq!(encoded, "\"quarantined\"");
        let decoded: NodeState = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, NodeState::Quarantined);
        assert!(!decoded.is_active());
    }

    #[test]
    fn enroll_request_round_trips_without_attestation() {
        let req = EnrollRequest {
            token: "t".into(),
            node_id: "n1".into(),
            site: "dc1".into(),
            hostname: "n1".into(),
            csr_pem: "-----BEGIN-----".into(),
            attestation: serde_json::Value::Null,
        };
        let raw = serde_json::to_string(&req).unwrap();
        let back: EnrollRequest = serde_json::from_str(&raw).unwrap();
        assert_eq!(back.node_id, "n1");
        assert!(back.attestation.is_null());
    }

    #[test]
    fn api_error_omits_empty_violations() {
        let err = ApiError::new("token_replayed", "token already used");
        let raw = serde_json::to_string(&err).unwrap();
        assert!(!raw.contains("violations"));
        assert!(raw.contains("token_replayed"));
    }
}
