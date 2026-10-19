//! Boot-integrity policy loading and evaluation.

use crate::quote::{compute_quote_digest, verify_quote_signature};
use crate::replay::replay_event_log;
use crate::types::AttestationBlob;
use crate::AttestError;
use fleet_pki::LeafUsage;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

/// A single policy failure. The enum is stable enough for tests to match on
/// while remaining readable in operator output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Violation {
    SecureBootDisabled,
    SetupModeEnabled,
    SecureBootKeysMissing,
    DbxMissingKnownBad(String),
    MissingPcr(u8),
    PcrNotAllowed {
        pcr: u8,
        value: String,
    },
    LogQuoteMismatch {
        pcr: u8,
        replayed: String,
        quoted: String,
    },
    QuoteDigestMismatch,
    ReplayedNonce {
        challenge: String,
        signed: String,
    },
    ForgedQuote(String),
    AkChainUntrusted(String),
    BadEventLog(String),
}

impl Violation {
    pub fn code(&self) -> &'static str {
        match self {
            Violation::SecureBootDisabled => "secure_boot_disabled",
            Violation::SetupModeEnabled => "setup_mode_enabled",
            Violation::SecureBootKeysMissing => "secure_boot_keys_missing",
            Violation::DbxMissingKnownBad(_) => "dbx_missing_known_bad",
            Violation::MissingPcr(_) => "pcr_missing",
            Violation::PcrNotAllowed { .. } => "pcr_not_allowed",
            Violation::LogQuoteMismatch { .. } => "log_quote_mismatch",
            Violation::QuoteDigestMismatch => "quote_digest_mismatch",
            Violation::ReplayedNonce { .. } => "replayed_nonce",
            Violation::ForgedQuote(_) => "forged_quote",
            Violation::AkChainUntrusted(_) => "ak_chain_untrusted",
            Violation::BadEventLog(_) => "bad_event_log",
        }
    }
}

impl std::fmt::Display for Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Violation::SecureBootDisabled => write!(f, "SecureBoot is disabled"),
            Violation::SetupModeEnabled => write!(f, "SetupMode is enabled"),
            Violation::SecureBootKeysMissing => {
                write!(f, "PK or KEK is empty; secure boot is not provisioned")
            }
            Violation::DbxMissingKnownBad(hash) => {
                write!(f, "dbx does not contain known-bad shim {hash}")
            }
            Violation::MissingPcr(pcr) => write!(f, "PCR{pcr} was not quoted"),
            Violation::PcrNotAllowed { pcr, value } => {
                write!(f, "PCR{pcr} value {value} is not in the allowlist")
            }
            Violation::LogQuoteMismatch {
                pcr,
                replayed,
                quoted,
            } => write!(f, "PCR{pcr} replayed to {replayed} but quote says {quoted}"),
            Violation::QuoteDigestMismatch => {
                write!(f, "quote digest does not cover the quoted PCR values")
            }
            Violation::ReplayedNonce { challenge, signed } => write!(
                f,
                "quote nonce {signed} does not match enrollment challenge {challenge}"
            ),
            Violation::ForgedQuote(reason) => write!(f, "quote signature invalid: {reason}"),
            Violation::AkChainUntrusted(reason) => {
                write!(f, "AK certificate chain is not trusted: {reason}")
            }
            Violation::BadEventLog(reason) => write!(f, "event log replay failed: {reason}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    Fail(Vec<Violation>),
}

impl Verdict {
    pub fn is_pass(&self) -> bool {
        matches!(self, Verdict::Pass)
    }

    pub fn violations(&self) -> &[Violation] {
        match self {
            Verdict::Pass => &[],
            Verdict::Fail(v) => v,
        }
    }

    pub fn codes(&self) -> Vec<&'static str> {
        self.violations().iter().map(Violation::code).collect()
    }

    pub fn display_line(&self) -> String {
        match self {
            Verdict::Pass => "PASS".into(),
            Verdict::Fail(v) => v
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; "),
        }
    }
}

/// The persisted boot-integrity policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub version: u32,
    pub name: String,
    pub description: String,
    pub require_secure_boot: bool,
    pub require_setup_mode_off: bool,
    pub pcr_indices: Vec<u8>,
    pub allowed_pcr0: Vec<String>,
    /// Bootloader measurements per distro key (`ubuntu`, `fedora`).
    pub allowed_pcr4: BTreeMap<String, Vec<String>>,
    pub allowed_pcr7: Vec<String>,
    pub allowed_pcr11: Vec<String>,
    /// SHA-256 hashes that must be present in the UEFI dbx.
    pub known_bad_shim_dbx: Vec<String>,
    pub on_fail: String,
}

impl Policy {
    pub fn from_yaml(yaml: &str) -> Result<Self, AttestError> {
        Ok(serde_yaml::from_str(yaml)?)
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, AttestError> {
        let raw = std::fs::read_to_string(path)?;
        Self::from_yaml(&raw)
    }

    pub fn to_yaml(&self) -> Result<String, AttestError> {
        Ok(serde_yaml::to_string(self)?)
    }

    pub fn evaluate(&self, blob: &AttestationBlob) -> Verdict {
        self.evaluate_inner(blob, None)
    }

    /// Evaluate including the AK certificate chain against a PEM trust bundle.
    pub fn evaluate_with_ca(&self, blob: &AttestationBlob, ca_pem: &str) -> Verdict {
        self.evaluate_inner(blob, Some(ca_pem))
    }

    fn evaluate_inner(&self, blob: &AttestationBlob, ca_pem: Option<&str>) -> Verdict {
        let mut violations = Vec::new();

        if blob.challenge != blob.quote.nonce {
            violations.push(Violation::ReplayedNonce {
                challenge: blob.challenge.clone(),
                signed: blob.quote.nonce.clone(),
            });
        }
        if self.require_secure_boot && !blob.secure_boot.secure_boot {
            violations.push(Violation::SecureBootDisabled);
        }
        if self.require_setup_mode_off && blob.secure_boot.setup_mode {
            violations.push(Violation::SetupModeEnabled);
        }
        if blob.secure_boot.pk.is_empty() || blob.secure_boot.kek.is_empty() {
            violations.push(Violation::SecureBootKeysMissing);
        }
        for bad in &self.known_bad_shim_dbx {
            if !blob
                .secure_boot
                .dbx
                .iter()
                .any(|v| v.eq_ignore_ascii_case(bad))
            {
                violations.push(Violation::DbxMissingKnownBad(bad.clone()));
            }
        }

        for pcr in &self.pcr_indices {
            if !blob.quote.pcr_selection.contains(pcr) {
                violations.push(Violation::MissingPcr(*pcr));
            }
        }

        match replay_event_log(&blob.event_log, &self.pcr_indices) {
            Ok(replayed) => {
                for pcr in &self.pcr_indices {
                    let quoted = blob.quote.pcr_values.get(&pcr.to_string());
                    match (replayed.get(pcr), quoted) {
                        (Some(computed), Some(quoted_hex)) => {
                            let computed_hex = hex::encode(computed);
                            if !computed_hex.eq_ignore_ascii_case(quoted_hex) {
                                violations.push(Violation::LogQuoteMismatch {
                                    pcr: *pcr,
                                    replayed: computed_hex,
                                    quoted: quoted_hex.clone(),
                                });
                            }
                        }
                        (Some(computed), None) => violations.push(Violation::LogQuoteMismatch {
                            pcr: *pcr,
                            replayed: hex::encode(computed),
                            quoted: String::new(),
                        }),
                        _ => {}
                    }
                }
            }
            Err(err) => violations.push(Violation::BadEventLog(err.to_string())),
        }

        match compute_quote_digest(&blob.quote.pcr_selection, &blob.quote.pcr_values) {
            Ok(digest) if digest.eq_ignore_ascii_case(&blob.quote.digest) => {}
            Ok(_) => violations.push(Violation::QuoteDigestMismatch),
            Err(err) => violations.push(Violation::BadEventLog(err.to_string())),
        }

        if let Err(err) = verify_quote_signature(&blob.ak_cert_pem, &blob.quote) {
            violations.push(Violation::ForgedQuote(err.to_string()));
        }

        if let Some(ca_pem) = ca_pem {
            if let Err(err) =
                fleet_pki::verify_chain_with_bundle(&blob.ak_cert_pem, ca_pem, LeafUsage::Client)
            {
                violations.push(Violation::AkChainUntrusted(err.to_string()));
            }
        }

        self.check_allowlist(
            0,
            blob.quote.pcr_values.get("0"),
            &self.allowed_pcr0,
            &mut violations,
        );
        let pcr4_allowed = self
            .allowed_pcr4
            .get(blob.distro.as_str())
            .cloned()
            .unwrap_or_default();
        self.check_allowlist(
            4,
            blob.quote.pcr_values.get("4"),
            &pcr4_allowed,
            &mut violations,
        );
        self.check_allowlist(
            7,
            blob.quote.pcr_values.get("7"),
            &self.allowed_pcr7,
            &mut violations,
        );
        self.check_allowlist(
            11,
            blob.quote.pcr_values.get("11"),
            &self.allowed_pcr11,
            &mut violations,
        );

        if violations.is_empty() {
            Verdict::Pass
        } else {
            Verdict::Fail(violations)
        }
    }

    fn check_allowlist(
        &self,
        pcr: u8,
        value: Option<&String>,
        allowed: &[String],
        violations: &mut Vec<Violation>,
    ) {
        let Some(value) = value else {
            return;
        };
        if !allowed.iter().any(|v| v.eq_ignore_ascii_case(value)) {
            violations.push(Violation::PcrNotAllowed {
                pcr,
                value: value.clone(),
            });
        }
    }
}
