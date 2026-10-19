//! Certificate revocation lists and a small store that enforces freshness.

use crate::PkiError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use x509_parser::prelude::FromDer;

/// A parsed X.509 v2 CRL.
#[derive(Debug, Clone)]
pub struct Crl {
    der: Vec<u8>,
    this_update: i64,
    next_update: i64,
    revoked: BTreeSet<String>,
    crl_number: u64,
}

impl Crl {
    /// Parse a DER-encoded CRL and index its revoked serials.
    pub fn from_der(der: Vec<u8>) -> Result<Self, PkiError> {
        let (_, parsed) = x509_parser::revocation_list::CertificateRevocationList::from_der(&der)
            .map_err(|e| PkiError::X509(e.to_string()))?;
        let this_update = parsed.last_update().timestamp();
        let next_update = parsed
            .next_update()
            .ok_or_else(|| PkiError::X509("CRL has no nextUpdate".into()))?
            .timestamp();
        let revoked = parsed
            .iter_revoked_certificates()
            .map(|r| hex::encode(r.serial().to_bytes_be()))
            .collect();
        let crl_number = parsed
            .crl_number()
            .map(|n| n.to_u64_digits().first().copied().unwrap_or(0))
            .unwrap_or(0);
        drop(parsed);
        Ok(Self {
            der,
            this_update,
            next_update,
            revoked,
            crl_number,
        })
    }

    pub fn from_pem(pem: &str) -> Result<Self, PkiError> {
        let der = pem_to_der(pem, "X509 CRL")?;
        Self::from_der(der)
    }

    pub fn from_file(path: &Path) -> Result<Self, PkiError> {
        let pem = std::fs::read_to_string(path)?;
        Self::from_pem(&pem)
    }

    pub fn to_pem(&self) -> String {
        der_to_pem(&self.der, "X509 CRL")
    }

    pub fn der(&self) -> &[u8] {
        &self.der
    }

    pub fn next_update(&self) -> i64 {
        self.next_update
    }

    pub fn this_update(&self) -> i64 {
        self.this_update
    }

    pub fn crl_number(&self) -> u64 {
        self.crl_number
    }

    pub fn revoked_serials(&self) -> impl Iterator<Item = &String> {
        self.revoked.iter()
    }

    /// True when `serial` (lowercase hex, without separators) appears in the CRL.
    pub fn is_revoked(&self, serial: &str) -> bool {
        self.revoked.contains(&serial.to_ascii_lowercase())
    }

    /// True when the CRL's `nextUpdate` is in the past.
    pub fn is_stale_at(&self, now: i64) -> bool {
        now >= self.next_update
    }

    /// Verify the issuer's signature over the CRL.
    pub fn verify_signature(&self, issuer_cert_pem: &str) -> Result<(), PkiError> {
        let issuer_der = pem_to_der(issuer_cert_pem, "CERTIFICATE")?;
        let (_, cert) = x509_parser::parse_x509_certificate(&issuer_der)
            .map_err(|e| PkiError::X509(e.to_string()))?;
        let (_, parsed) =
            x509_parser::revocation_list::CertificateRevocationList::from_der(&self.der)
                .map_err(|e| PkiError::X509(e.to_string()))?;
        parsed
            .verify_signature(cert.public_key())
            .map_err(|e| PkiError::X509(format!("CRL signature invalid: {e}")))
    }
}

/// Thread-safe holder for the CRL currently served to nodes.
#[derive(Debug)]
pub struct CrlStore {
    crl: Crl,
}

impl CrlStore {
    pub fn new(crl: Crl) -> Self {
        Self { crl }
    }

    pub fn from_pem(pem: &str) -> Result<Self, PkiError> {
        Ok(Self::new(Crl::from_pem(pem)?))
    }

    pub fn from_file(path: &Path) -> Result<Self, PkiError> {
        Ok(Self::new(Crl::from_file(path)?))
    }

    pub fn crl(&self) -> &Crl {
        &self.crl
    }

    pub fn replace(&mut self, crl: Crl) {
        self.crl = crl;
    }

    /// Reject a stale CRL with a distinct error, then reject revoked serials.
    pub fn check(&self, serial: &str, now: i64) -> Result<(), PkiError> {
        if self.crl.is_stale_at(now) {
            return Err(PkiError::StaleCrl {
                next_update: self.crl.next_update,
            });
        }
        if self.crl.is_revoked(serial) {
            return Err(PkiError::Revoked(serial.to_string()));
        }
        Ok(())
    }

    pub fn check_now(&self, serial: &str) -> Result<(), PkiError> {
        self.check(serial, unix_now())
    }

    pub fn to_pem(&self) -> String {
        self.crl.to_pem()
    }
}

/// Serializable summary used by `fleetctl ca crl`.
#[derive(Debug, Serialize, Deserialize)]
pub struct CrlSummary {
    pub crl_number: u64,
    pub this_update: i64,
    pub next_update: i64,
    pub revoked_serials: Vec<String>,
    pub stale: bool,
}

impl Crl {
    pub fn summary(&self) -> CrlSummary {
        CrlSummary {
            crl_number: self.crl_number,
            this_update: self.this_update,
            next_update: self.next_update,
            revoked_serials: self.revoked.iter().cloned().collect(),
            stale: self.is_stale_at(unix_now()),
        }
    }
}

pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub(crate) fn pem_to_der(pem: &str, label: &str) -> Result<Vec<u8>, PkiError> {
    let block = pem::parse(pem).map_err(|e| PkiError::Pem(e.to_string()))?;
    if block.tag() != label {
        return Err(PkiError::Pem(format!(
            "expected {label} PEM block, found {}",
            block.tag()
        )));
    }
    Ok(block.into_contents())
}

pub(crate) fn der_to_pem(der: &[u8], label: &str) -> String {
    pem::encode(&pem::Pem::new(label, der.to_vec()))
}
