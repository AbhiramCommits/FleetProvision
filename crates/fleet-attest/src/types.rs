//! Wire types for UEFI Secure Boot state, TPM 2.0 quotes, and TCG event logs.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Firmware family under test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Distro {
    Ubuntu,
    Fedora,
}

impl Distro {
    pub fn as_str(self) -> &'static str {
        match self {
            Distro::Ubuntu => "ubuntu",
            Distro::Fedora => "fedora",
        }
    }
}

impl std::fmt::Display for Distro {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// EFI variable digests. Each entry is the lowercase hex SHA-256 of the
/// variable value (for db/dbx: of one signature list entry).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecureBootState {
    pub secure_boot: bool,
    pub setup_mode: bool,
    pub pk: Vec<String>,
    pub kek: Vec<String>,
    pub db: Vec<String>,
    pub dbx: Vec<String>,
}

/// TPM 2.0 quote over selected PCRs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TpmQuote {
    pub pcr_selection: Vec<u8>,
    /// PCR index (as a string map key) to 32-byte SHA-256 value, hex encoded.
    pub pcr_values: BTreeMap<String, String>,
    /// SHA-256 over `index || value` for each selected PCR, in index order.
    pub digest: String,
    /// Base64 DER ECDSA P-256 signature over `nonce || digest` bytes.
    pub signature: String,
    /// Nonce that was signed. Must equal the enrollment challenge.
    pub nonce: String,
}

/// One TCG event-log entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TcgEvent {
    pub pcr: u8,
    pub digest: String,
    pub event_type: String,
    pub description: String,
}

/// Complete attestation evidence submitted with an enrollment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttestationBlob {
    pub version: u32,
    pub node_id: String,
    pub site: String,
    pub hostname: String,
    pub distro: Distro,
    pub firmware: String,
    pub captured_at: i64,
    /// Nonce fleetd issued for this enrollment.
    pub challenge: String,
    pub secure_boot: SecureBootState,
    pub quote: TpmQuote,
    pub event_log: Vec<TcgEvent>,
    /// Simulated TPM endorsement/AK certificate (PEM), chained to the fleet CA.
    pub ak_cert_pem: String,
}

impl AttestationBlob {
    pub fn from_json_value(value: &serde_json::Value) -> Result<Self, serde_json::Error> {
        serde_json::from_value(value.clone())
    }
}
