//! Boot-integrity attestation primitives.
//!
//! This crate replays TCG event logs into PCR values and evaluates the result
//! against the fleet boot-integrity policy. It is intentionally independent of
//! the network layer so the policy can be tested against committed fixtures.

use sha2::{Digest, Sha256};

/// Extend a PCR with a measurement: `PCR = H(PCR || digest)`.
pub fn pcr_extend(current: &[u8], digest: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(current);
    hasher.update(digest);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extend_matches_manual_sha256() {
        let pcr = [0u8; 32];
        let digest = Sha256::digest(b"fleet-boot-event");
        let extended = pcr_extend(&pcr, &digest);

        let mut manual = Sha256::new();
        manual.update(pcr);
        manual.update(digest);
        let expected: [u8; 32] = manual.finalize().into();
        assert_eq!(extended, expected);
    }

    #[test]
    fn extend_is_not_commutative() {
        let a = Sha256::digest(b"a");
        let b = Sha256::digest(b"b");
        assert_ne!(pcr_extend(&a, &b), pcr_extend(&b, &a));
    }
}
