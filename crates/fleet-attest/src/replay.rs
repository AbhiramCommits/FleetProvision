//! TCG event-log replay into PCR values.

use crate::types::TcgEvent;
use crate::AttestError;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// PCRs required by the fleet boot-integrity policy.
pub const POLICY_PCRS: [u8; 5] = [0, 2, 4, 7, 11];

/// Extend a PCR with a measurement: `PCR = H(PCR || digest)`.
pub fn pcr_extend(current: &[u8], digest: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(current);
    hasher.update(digest);
    hasher.finalize().into()
}

/// Replay an event log over the selected PCR set. PCRs not mentioned by any
/// event replay to 32 zero bytes, matching TPM reset semantics.
pub fn replay_event_log(
    events: &[TcgEvent],
    selection: &[u8],
) -> Result<BTreeMap<u8, [u8; 32]>, AttestError> {
    let selected: BTreeSet<u8> = selection.iter().copied().collect();
    let mut pcrs: BTreeMap<u8, [u8; 32]> = selected.iter().map(|idx| (*idx, [0u8; 32])).collect();
    for event in events {
        if !selected.contains(&event.pcr) {
            continue;
        }
        let digest = hex::decode(&event.digest)
            .map_err(|e| AttestError::BadDigest(event.digest.clone(), e.to_string()))?;
        if digest.len() != 32 {
            return Err(AttestError::BadDigest(
                event.digest.clone(),
                "expected 32 bytes".into(),
            ));
        }
        let current = pcrs.entry(event.pcr).or_insert([0u8; 32]);
        *current = pcr_extend(current, &digest);
    }
    Ok(pcrs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(pcr: u8, label: &str) -> TcgEvent {
        TcgEvent {
            pcr,
            digest: hex::encode(Sha256::digest(label.as_bytes())),
            event_type: "EV_ACTION".into(),
            description: label.into(),
        }
    }

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

    #[test]
    fn replay_applies_events_in_order() {
        let events = vec![event(4, "shim"), event(4, "grub")];
        let replayed = replay_event_log(&events, &[4]).unwrap();
        let first = pcr_extend(&[0u8; 32], &Sha256::digest(b"shim"));
        let expected = pcr_extend(&first, &Sha256::digest(b"grub"));
        assert_eq!(replayed[&4], expected);
    }

    #[test]
    fn replay_ignores_unselected_pcrs_and_zero_fills_absent_ones() {
        let events = vec![event(9, "not-policy")];
        let replayed = replay_event_log(&events, &[0, 4]).unwrap();
        assert_eq!(replayed[&0], [0u8; 32]);
        assert_eq!(replayed[&4], [0u8; 32]);
        assert!(!replayed.contains_key(&9));
    }

    #[test]
    fn bad_digest_length_is_rejected() {
        let events = vec![TcgEvent {
            pcr: 0,
            digest: "abcd".into(),
            event_type: "EV_POST_CODE".into(),
            description: "short".into(),
        }];
        assert!(replay_event_log(&events, &[0]).is_err());
    }
}
