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
}
