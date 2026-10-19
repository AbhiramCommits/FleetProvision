//! Boot-integrity attestation primitives.
//!
//! This crate replays TCG event logs into PCR values, verifies TPM quote
//! signatures against a chained AK certificate, and evaluates the fleet
//! boot-integrity policy. It is independent of the network layer so policy
//! behaviour can be tested against committed fixtures.

pub mod fixtures;
pub mod policy;
pub mod quote;
pub mod replay;
pub mod types;

pub use policy::{Policy, Verdict, Violation};
pub use quote::{compute_quote_digest, sign_quote, verify_quote_signature};
pub use replay::{pcr_extend, replay_event_log, POLICY_PCRS};
pub use types::{AttestationBlob, Distro, SecureBootState, TcgEvent, TpmQuote};

#[derive(Debug, thiserror::Error)]
pub enum AttestError {
    #[error("bad PCR digest {0}: {1}")]
    BadDigest(String, String),
    #[error("bad nonce: {0}")]
    BadNonce(String),
    #[error("PCR {0} is missing from the quote")]
    MissingPcr(u8),
    #[error("quote signature error: {0}")]
    QuoteSignature(String),
    #[error("AK certificate error: {0}")]
    AkCertificate(String),
    #[error("key error: {0}")]
    Key(String),
    #[error("certificate error: {0}")]
    Pki(#[from] fleet_pki::PkiError),
    #[error("certificate generation error: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("YAML error: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("fixture error: {0}")]
    Fixture(String),
}
