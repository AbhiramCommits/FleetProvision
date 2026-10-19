//! FleetProvision internal certificate authority.
//!
//! The hierarchy is intentionally small: a ten-year offline root, online
//! intermediates used for everyday issuance, and 90-day leaf certificates
//! bound to node identity through DNS and SPIFFE-like URI SANs. Private keys
//! generated on a node never leave it: the node sends a CSR and the CA signs
//! the public key.

mod crl;

pub use crl::{unix_now, Crl, CrlStore, CrlSummary};

use rand::RngCore;
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams,
    CertificateSigningRequestParams, CrlDistributionPoint, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyIdMethod, KeyPair, KeyUsagePurpose, RevocationReason, RevokedCertParams, SanType,
    SerialNumber, PKCS_ECDSA_P256_SHA256,
};
use rustls_pki_types::{CertificateDer, UnixTime};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;
use time::OffsetDateTime;
use x509_parser::extensions::{GeneralName, ParsedExtension};

/// Errors surfaced by the CA, CSR, chain, and CRL paths.
#[derive(Debug, thiserror::Error)]
pub enum PkiError {
    #[error("certificate generation failed: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("PEM error: {0}")]
    Pem(String),
    #[error("X.509 parse error: {0}")]
    X509(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("chain verification failed: {0}")]
    Chain(String),
    #[error("certificate has expired")]
    Expired,
    #[error("certificate is not yet valid")]
    NotYetValid,
    #[error("certificate EKU does not permit {0}")]
    Eku(&'static str),
    #[error("CRL is stale: nextUpdate {next_update} is in the past")]
    StaleCrl { next_update: i64 },
    #[error("serial {0} is revoked")]
    Revoked(String),
    #[error("certificate is missing a fleet identity SAN")]
    MissingIdentity,
    #[error("no CA material in {0}")]
    NotInitialized(String),
    #[error("unknown usage {0}; expected client or server")]
    UnknownUsage(String),
    #[error("unknown revocation reason {0}")]
    UnknownReason(String),
}

/// Tunables for the CA hierarchy. Persisted alongside the keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaConfig {
    pub organization: String,
    pub site: String,
    pub root_cn: String,
    pub intermediate_cn: String,
    pub root_validity_days: i64,
    pub intermediate_validity_days: i64,
    pub leaf_validity_days: i64,
    pub crl_validity_hours: i64,
    pub crl_url: String,
}

impl Default for CaConfig {
    fn default() -> Self {
        Self {
            organization: "FleetProvision".into(),
            site: "dc1".into(),
            root_cn: "FleetProvision Root CA".into(),
            intermediate_cn: "FleetProvision Issuing CA".into(),
            root_validity_days: 3650,
            intermediate_validity_days: 1825,
            leaf_validity_days: 90,
            crl_validity_hours: 168,
            crl_url: "https://127.0.0.1:8443/v1/crl".into(),
        }
    }
}

/// Whether a leaf is a server (`fleetd`) or client (node) identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LeafUsage {
    Client,
    Server,
}

impl LeafUsage {
    pub fn parse(value: &str) -> Result<Self, PkiError> {
        match value.to_ascii_lowercase().as_str() {
            "client" => Ok(Self::Client),
            "server" => Ok(Self::Server),
            other => Err(PkiError::UnknownUsage(other.into())),
        }
    }

    fn eku(self) -> ExtendedKeyUsagePurpose {
        match self {
            Self::Client => ExtendedKeyUsagePurpose::ClientAuth,
            Self::Server => ExtendedKeyUsagePurpose::ServerAuth,
        }
    }
}

impl std::fmt::Display for LeafUsage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Client => "client",
            Self::Server => "server",
        })
    }
}

/// Everything needed to issue one leaf certificate.
#[derive(Debug, Clone)]
pub struct LeafSpec {
    pub node_id: String,
    pub site: String,
    pub hostname: String,
    pub usage: LeafUsage,
    pub validity_days: i64,
    /// Extra DNS SANs (for example `localhost` for the control-plane listener).
    pub extra_dns: Vec<String>,
    /// Extra IP SANs (loopback addresses used by local clients and tests).
    pub extra_ips: Vec<String>,
    /// Optional PKCS#10 CSR from the node. When absent the CA generates a key
    /// pair and returns it once, which is convenient for operator tooling.
    pub csr_pem: Option<String>,
}

impl LeafSpec {
    pub fn for_node(site: impl Into<String>, node_id: impl Into<String>) -> Self {
        let site = site.into();
        let node_id = node_id.into();
        Self {
            hostname: node_id.clone(),
            node_id,
            site,
            usage: LeafUsage::Client,
            validity_days: 90,
            extra_dns: Vec::new(),
            extra_ips: Vec::new(),
            csr_pem: None,
        }
    }

    pub fn with_csr(mut self, csr_pem: impl Into<String>) -> Self {
        self.csr_pem = Some(csr_pem.into());
        self
    }

    pub fn with_usage(mut self, usage: LeafUsage) -> Self {
        self.usage = usage;
        self
    }

    pub fn with_validity_days(mut self, days: i64) -> Self {
        self.validity_days = days;
        self
    }

    pub fn with_hostname(mut self, hostname: impl Into<String>) -> Self {
        self.hostname = hostname.into();
        self
    }

    pub fn with_extra_dns(mut self, dns: impl Into<String>) -> Self {
        self.extra_dns.push(dns.into());
        self
    }

    pub fn with_extra_ip(mut self, ip: impl Into<String>) -> Self {
        self.extra_ips.push(ip.into());
        self
    }
}

/// A node-side key pair plus its CSR. The private key is never serialized by
/// the CA; callers keep it on the node.
#[derive(Debug, Clone)]
pub struct NodeKeypair {
    key_pem: String,
    csr_pem: String,
}

impl NodeKeypair {
    pub fn new(node_id: &str, site: &str) -> Result<Self, PkiError> {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.distinguished_name.push(
            DnType::CommonName,
            format!("{node_id}.{site}.fleet.internal"),
        );
        let csr = params.serialize_request(&key)?;
        Ok(Self {
            key_pem: key.serialize_pem(),
            csr_pem: csr.pem()?,
        })
    }

    pub fn key_pem(&self) -> &str {
        &self.key_pem
    }

    pub fn csr_pem(&self) -> &str {
        &self.csr_pem
    }
}

/// An issued leaf together with the node key when the CA generated it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuedCert {
    pub cert_pem: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_pem: Option<String>,
    pub chain_pem: String,
    pub serial_hex: String,
    pub identity: LeafIdentity,
}

/// Parsed, verified certificate identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LeafIdentity {
    pub node_id: String,
    pub site: String,
    pub hostname: String,
    pub dns_name: String,
    pub uri: String,
    pub serial_hex: String,
    pub not_before: i64,
    pub not_after: i64,
    pub usage: LeafUsage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RevocationRecord {
    serial_hex: String,
    reason: String,
    revoked_at: i64,
}

#[derive(Debug, Clone)]
struct Intermediate {
    cert_pem: String,
    key_pem: String,
    serial_hex: String,
    created_at: i64,
    not_after: i64,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedIntermediate {
    cert_pem: String,
    key_file: String,
    serial_hex: String,
    created_at: i64,
    not_after: i64,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedCa {
    config: CaConfig,
    root_pem: String,
    root_key_file: String,
    intermediates: Vec<PersistedIntermediate>,
    active: usize,
    revoked: Vec<RevocationRecord>,
    crl_pem: Option<String>,
    crl_number: u64,
}

/// Public description of one intermediate for `fleetctl ca show`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntermediateInfo {
    pub serial_hex: String,
    pub created_at: i64,
    pub not_after: i64,
    pub active: bool,
}

/// Public summary of the CA hierarchy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaSummary {
    pub config: CaConfig,
    pub root_subject: String,
    pub root_not_after: i64,
    pub intermediates: Vec<IntermediateInfo>,
    pub revoked_count: usize,
    pub crl_number: u64,
    pub trust_bundle_pem: String,
}

/// The in-memory CA plus optional on-disk state directory.
#[derive(Debug)]
pub struct Ca {
    config: CaConfig,
    root_pem: String,
    root_key_pem: String,
    intermediates: Vec<Intermediate>,
    active: usize,
    revoked: Vec<RevocationRecord>,
    crl_pem: Option<String>,
    crl_number: u64,
    dir: Option<PathBuf>,
}

impl Ca {
    /// Create a new root (10 years) and its first intermediate.
    pub fn init_root(config: CaConfig) -> Result<Self, PkiError> {
        let now = OffsetDateTime::now_utc();
        let root_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;

        let mut root_params = CertificateParams::new(Vec::<String>::new())?;
        root_params
            .distinguished_name
            .push(DnType::OrganizationName, config.organization.clone());
        root_params
            .distinguished_name
            .push(DnType::CommonName, config.root_cn.clone());
        root_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
        root_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        root_params.not_before = now - time::Duration::minutes(5);
        root_params.not_after = now + time::Duration::days(config.root_validity_days);
        root_params.serial_number = Some(random_serial());
        let root_cert = root_params.self_signed(&root_key)?;

        let mut ca = Self {
            config,
            root_pem: root_cert.pem(),
            root_key_pem: root_key.serialize_pem(),
            intermediates: Vec::new(),
            active: 0,
            revoked: Vec::new(),
            crl_pem: None,
            crl_number: 0,
            dir: None,
        };
        ca.issue_intermediate()?;
        ca.issue_crl()?;
        Ok(ca)
    }

    /// Load CA material from `dir`, or initialize and persist a new hierarchy.
    pub fn load_or_init(dir: impl AsRef<Path>, config: CaConfig) -> Result<Self, PkiError> {
        let dir = dir.as_ref();
        if dir.join("ca.json").exists() {
            Self::load(dir)
        } else {
            let mut ca = Self::init_root(config)?;
            ca.save(dir)?;
            Ok(ca)
        }
    }

    pub fn save(&mut self, dir: impl AsRef<Path>) -> Result<(), PkiError> {
        let dir = dir.as_ref();
        std::fs::create_dir_all(dir)?;
        std::fs::create_dir_all(dir.join("nodes"))?;
        self.dir = Some(dir.to_path_buf());

        write_private(dir.join("root-key.pem"), &self.root_key_pem)?;
        let persisted_intermediates = self
            .intermediates
            .iter()
            .map(|i| PersistedIntermediate {
                cert_pem: i.cert_pem.clone(),
                key_file: format!("intermediate-{}-key.pem", i.serial_hex),
                serial_hex: i.serial_hex.clone(),
                created_at: i.created_at,
                not_after: i.not_after,
            })
            .collect::<Vec<_>>();
        for (i, p) in self.intermediates.iter().zip(&persisted_intermediates) {
            write_private(dir.join(&p.key_file), &i.key_pem)?;
        }
        let state = PersistedCa {
            config: self.config.clone(),
            root_pem: self.root_pem.clone(),
            root_key_file: "root-key.pem".into(),
            intermediates: persisted_intermediates,
            active: self.active,
            revoked: self.revoked.clone(),
            crl_pem: self.crl_pem.clone(),
            crl_number: self.crl_number,
        };
        std::fs::write(dir.join("ca.json"), serde_json::to_vec_pretty(&state)?)?;
        std::fs::write(dir.join("root-cert.pem"), &self.root_pem)?;
        std::fs::write(dir.join("trust-bundle.pem"), self.trust_bundle_pem())?;
        if let Some(crl) = &self.crl_pem {
            std::fs::write(dir.join("crl.pem"), crl)?;
        }
        Ok(())
    }

    pub fn load(dir: impl AsRef<Path>) -> Result<Self, PkiError> {
        let dir = dir.as_ref();
        let raw = std::fs::read(dir.join("ca.json"))
            .map_err(|_| PkiError::NotInitialized(dir.display().to_string()))?;
        let state: PersistedCa = serde_json::from_slice(&raw)?;
        let root_key_pem = std::fs::read_to_string(dir.join(&state.root_key_file))?;
        let mut intermediates = Vec::with_capacity(state.intermediates.len());
        for p in &state.intermediates {
            intermediates.push(Intermediate {
                cert_pem: p.cert_pem.clone(),
                key_pem: std::fs::read_to_string(dir.join(&p.key_file))?,
                serial_hex: p.serial_hex.clone(),
                created_at: p.created_at,
                not_after: p.not_after,
            });
        }
        if intermediates.is_empty() {
            return Err(PkiError::NotInitialized(dir.display().to_string()));
        }
        Ok(Self {
            config: state.config,
            root_pem: state.root_pem,
            root_key_pem,
            intermediates,
            active: state.active.min(state.intermediates.len() - 1),
            revoked: state.revoked,
            crl_pem: state.crl_pem,
            crl_number: state.crl_number,
            dir: Some(dir.to_path_buf()),
        })
    }

    pub fn config(&self) -> &CaConfig {
        &self.config
    }

    pub fn root_pem(&self) -> &str {
        &self.root_pem
    }

    pub fn trust_bundle_pem(&self) -> String {
        let mut out = self.root_pem.clone();
        for i in &self.intermediates {
            out.push_str(&i.cert_pem);
        }
        out
    }

    pub fn crl_pem(&self) -> Option<&str> {
        self.crl_pem.as_deref()
    }

    pub fn crl_number(&self) -> u64 {
        self.crl_number
    }

    pub fn summary(&self) -> Result<CaSummary, PkiError> {
        let root_der = pem_to_der(&self.root_pem, "CERTIFICATE")?;
        let (_, root) = x509_parser::parse_x509_certificate(&root_der)
            .map_err(|e| PkiError::X509(e.to_string()))?;
        Ok(CaSummary {
            config: self.config.clone(),
            root_subject: root.subject().to_string(),
            root_not_after: root.validity().not_after.timestamp(),
            intermediates: self
                .intermediates
                .iter()
                .enumerate()
                .map(|(idx, i)| IntermediateInfo {
                    serial_hex: i.serial_hex.clone(),
                    created_at: i.created_at,
                    not_after: i.not_after,
                    active: idx == self.active,
                })
                .collect(),
            revoked_count: self.revoked.len(),
            crl_number: self.crl_number,
            trust_bundle_pem: self.trust_bundle_pem(),
        })
    }

    pub fn revoked_serials(&self) -> Vec<String> {
        self.revoked.iter().map(|r| r.serial_hex.clone()).collect()
    }

    fn issuer_at(&self, index: usize) -> Result<Issuer<'_, KeyPair>, PkiError> {
        let int = self
            .intermediates
            .get(index)
            .ok_or_else(|| PkiError::Chain("intermediate index out of range".into()))?;
        Ok(Issuer::from_ca_cert_pem(
            &int.cert_pem,
            KeyPair::from_pem(&int.key_pem)?,
        )?)
    }

    fn root_issuer(&self) -> Result<Issuer<'_, KeyPair>, PkiError> {
        Ok(Issuer::from_ca_cert_pem(
            &self.root_pem,
            KeyPair::from_pem(&self.root_key_pem)?,
        )?)
    }

    /// Sign a fresh intermediate with the root and make it active.
    pub fn issue_intermediate(&mut self) -> Result<IntermediateInfo, PkiError> {
        let now = OffsetDateTime::now_utc();
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let serial = random_serial();
        let serial_hex = serial_hex(&serial);

        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params
            .distinguished_name
            .push(DnType::OrganizationName, self.config.organization.clone());
        params.distinguished_name.push(
            DnType::CommonName,
            format!(
                "{} {} {}",
                self.config.intermediate_cn,
                self.config.site,
                &serial_hex[..8]
            ),
        );
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params.not_before = now - time::Duration::minutes(5);
        params.not_after = now + time::Duration::days(self.config.intermediate_validity_days);
        params.serial_number = Some(serial);
        params.use_authority_key_identifier_extension = true;

        let issuer = self.root_issuer()?;
        let cert = params.signed_by(&key, &issuer)?;
        let record = Intermediate {
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
            serial_hex: serial_hex.clone(),
            created_at: now.unix_timestamp(),
            not_after: params.not_after.unix_timestamp(),
        };
        self.intermediates.push(record);
        self.active = self.intermediates.len() - 1;
        self.issue_crl()?;
        Ok(IntermediateInfo {
            serial_hex,
            created_at: now.unix_timestamp(),
            not_after: params.not_after.unix_timestamp(),
            active: true,
        })
    }

    /// Rotate the intermediate. The retired intermediate remains in the trust
    /// bundle so certificates issued before rotation keep verifying.
    pub fn rotate_intermediate(&mut self) -> Result<IntermediateInfo, PkiError> {
        self.issue_intermediate()
    }

    /// Issue one leaf certificate from a spec (and optional CSR).
    pub fn issue_leaf(&mut self, spec: &LeafSpec) -> Result<IssuedCert, PkiError> {
        let now = OffsetDateTime::now_utc();
        let (not_before, not_after) = if spec.validity_days < 0 {
            (
                now + time::Duration::days(spec.validity_days) - time::Duration::minutes(5),
                now - time::Duration::days(1),
            )
        } else {
            (
                now - time::Duration::minutes(5),
                now + time::Duration::days(spec.validity_days),
            )
        };
        let serial = random_serial();
        let serial_hex = serial_hex(&serial);
        let dns_name = format!("{}.fleet.internal", spec.hostname);
        let uri = format!("fleet://{}/{}", spec.site, spec.node_id);

        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params
            .distinguished_name
            .push(DnType::CommonName, spec.node_id.clone());
        params.distinguished_name.push(
            DnType::OrganizationName,
            format!("{} {}", self.config.organization, spec.site),
        );
        let mut sans = vec![
            SanType::DnsName(rcgen::string::Ia5String::try_from(dns_name.clone())?),
            SanType::URI(rcgen::string::Ia5String::try_from(uri.clone())?),
        ];
        for dns in &spec.extra_dns {
            sans.push(SanType::DnsName(rcgen::string::Ia5String::try_from(
                dns.clone(),
            )?));
        }
        for ip in &spec.extra_ips {
            let addr = ip
                .parse()
                .map_err(|_| PkiError::X509(format!("invalid IP SAN {ip}")))?;
            sans.push(SanType::IpAddress(addr));
        }
        params.subject_alt_names = sans;
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![spec.usage.eku()];
        params.not_before = not_before;
        params.not_after = not_after;
        params.serial_number = Some(serial.clone());
        params.use_authority_key_identifier_extension = true;
        params.crl_distribution_points = vec![CrlDistributionPoint {
            uris: vec![self.config.crl_url.clone()],
        }];

        let issuer = self.issuer_at(self.active)?;
        let (cert, key_pem) = match &spec.csr_pem {
            Some(csr_pem) => {
                let csr = CertificateSigningRequestParams::from_pem(csr_pem)?;
                let cert = params.signed_by(&csr.public_key, &issuer)?;
                (cert, None)
            }
            None => {
                let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
                let cert = params.signed_by(&key, &issuer)?;
                (cert, Some(key.serialize_pem()))
            }
        };

        let identity = LeafIdentity {
            node_id: spec.node_id.clone(),
            site: spec.site.clone(),
            hostname: spec.hostname.clone(),
            dns_name,
            uri,
            serial_hex: serial_hex.clone(),
            not_before: not_before.unix_timestamp(),
            not_after: not_after.unix_timestamp(),
            usage: spec.usage,
        };
        let mut chain = cert.pem();
        chain.push_str(&self.intermediates[self.active].cert_pem);
        chain.push_str(&self.root_pem);
        Ok(IssuedCert {
            cert_pem: cert.pem(),
            key_pem,
            chain_pem: chain,
            serial_hex,
            identity,
        })
    }

    /// Renewal re-keys: a fresh key pair and CSR are generated, so a stolen old
    /// key cannot be used after renewal.
    pub fn renew_leaf(&mut self, spec: &LeafSpec) -> Result<IssuedCert, PkiError> {
        let keypair = NodeKeypair::new(&spec.node_id, &spec.site)?;
        let mut renewed = spec.clone();
        renewed.csr_pem = Some(keypair.csr_pem().to_string());
        let mut issued = self.issue_leaf(&renewed)?;
        issued.key_pem = Some(keypair.key_pem().to_string());
        Ok(issued)
    }

    /// Revoke a serial and immediately publish a new CRL.
    pub fn revoke(&mut self, serial_hex: &str, reason: &str) -> Result<(), PkiError> {
        let reason = parse_reason(reason)?;
        if !self.revoked.iter().any(|r| r.serial_hex == serial_hex) {
            self.revoked.push(RevocationRecord {
                serial_hex: serial_hex.to_ascii_lowercase(),
                reason: format!("{reason:?}").to_ascii_lowercase(),
                revoked_at: OffsetDateTime::now_utc().unix_timestamp(),
            });
        }
        self.issue_crl()?;
        self.flush()?;
        Ok(())
    }

    /// Build and sign a v2 CRL with reason codes.
    pub fn issue_crl(&mut self) -> Result<String, PkiError> {
        let now = OffsetDateTime::now_utc();
        let revoked_certs = self
            .revoked
            .iter()
            .map(|r| RevokedCertParams {
                serial_number: serial_from_hex(&r.serial_hex),
                revocation_time: OffsetDateTime::from_unix_timestamp(r.revoked_at).unwrap_or(now),
                reason_code: parse_reason(&r.reason).ok(),
                invalidity_date: None,
            })
            .collect();
        let next_update = now + time::Duration::hours(self.config.crl_validity_hours);
        let params = CertificateRevocationListParams {
            this_update: now - time::Duration::minutes(1),
            next_update,
            crl_number: SerialNumber::from_slice(&(self.crl_number + 1).to_be_bytes()),
            issuing_distribution_point: None,
            revoked_certs,
            key_identifier_method: KeyIdMethod::Sha256,
        };
        let issuer = self.issuer_at(self.active)?;
        let crl = params.signed_by(&issuer)?;
        let pem = crl.pem()?;
        self.crl_pem = Some(pem.clone());
        self.crl_number += 1;
        self.flush()?;
        Ok(pem)
    }

    pub fn crl_store(&self) -> Result<CrlStore, PkiError> {
        let pem = self
            .crl_pem
            .as_deref()
            .ok_or_else(|| PkiError::X509("no CRL issued".into()))?;
        CrlStore::from_pem(pem)
    }

    fn flush(&mut self) -> Result<(), PkiError> {
        if let Some(dir) = self.dir.clone() {
            self.save(dir)?;
        }
        Ok(())
    }

    /// Verify a leaf against the trust bundle for the requested EKU.
    pub fn verify_leaf(&self, leaf_pem: &str, usage: LeafUsage) -> Result<LeafIdentity, PkiError> {
        self.verify_leaf_at(leaf_pem, usage, OffsetDateTime::now_utc())
    }

    /// Time-injectable variant used by expiry tests.
    pub fn verify_leaf_at(
        &self,
        leaf_pem: &str,
        usage: LeafUsage,
        now: OffsetDateTime,
    ) -> Result<LeafIdentity, PkiError> {
        let leaf_der = pem_to_der(leaf_pem, "CERTIFICATE")?;
        let root_der = pem_to_der(&self.root_pem, "CERTIFICATE")?;
        let leaf_cert_der = CertificateDer::from(leaf_der.clone());
        let leaf = webpki::EndEntityCert::try_from(&leaf_cert_der)
            .map_err(|e| PkiError::Chain(e.to_string()))?;
        let root_cert = CertificateDer::from(root_der);
        let anchor = webpki::anchor_from_trusted_cert(&root_cert)
            .map_err(|e| PkiError::Chain(e.to_string()))?;
        let intermediate_ders: Vec<CertificateDer<'_>> = self
            .intermediates
            .iter()
            .map(|i| pem_to_der(&i.cert_pem, "CERTIFICATE").map(CertificateDer::from))
            .collect::<Result<_, _>>()?;
        let unix_time =
            UnixTime::since_unix_epoch(Duration::from_secs(now.unix_timestamp().max(0) as u64));
        let eku = match usage {
            LeafUsage::Client => webpki::KeyUsage::client_auth(),
            LeafUsage::Server => webpki::KeyUsage::server_auth(),
        };
        leaf.verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &[anchor],
            &intermediate_ders,
            unix_time,
            eku,
            None,
            None,
        )
        .map_err(|e| match e {
            webpki::Error::CertExpired { .. } => PkiError::Expired,
            webpki::Error::CertNotValidYet { .. } => PkiError::NotYetValid,
            webpki::Error::RequiredEkuNotFoundContext(_) => {
                PkiError::Eku(if usage == LeafUsage::Client {
                    "clientAuth"
                } else {
                    "serverAuth"
                })
            }
            other => PkiError::Chain(other.to_string()),
        })?;

        let (_, cert) = x509_parser::parse_x509_certificate(&leaf_der)
            .map_err(|e| PkiError::X509(e.to_string()))?;
        let mut dns_name = None;
        let mut uri = None;
        for ext in cert.extensions() {
            if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
                for name in &san.general_names {
                    match name {
                        GeneralName::DNSName(dns) => dns_name = Some((*dns).to_string()),
                        GeneralName::URI(u) => uri = Some((*u).to_string()),
                        _ => {}
                    }
                }
            }
        }
        let dns_name = dns_name.ok_or(PkiError::MissingIdentity)?;
        let uri = uri.ok_or(PkiError::MissingIdentity)?;
        let hostname = dns_name
            .strip_suffix(".fleet.internal")
            .ok_or(PkiError::MissingIdentity)?
            .to_string();
        let rest = uri
            .strip_prefix("fleet://")
            .ok_or(PkiError::MissingIdentity)?;
        let (site, node_id) = rest.split_once('/').ok_or(PkiError::MissingIdentity)?;
        Ok(LeafIdentity {
            node_id: node_id.to_string(),
            site: site.to_string(),
            hostname,
            dns_name,
            uri,
            serial_hex: hex::encode(cert.raw_serial()),
            not_before: cert.validity().not_before.timestamp(),
            not_after: cert.validity().not_after.timestamp(),
            usage,
        })
    }

    /// Verify the chain and enforce the current CRL's freshness and contents.
    pub fn verify_leaf_with_crl(
        &self,
        leaf_pem: &str,
        usage: LeafUsage,
        crl: &CrlStore,
    ) -> Result<LeafIdentity, PkiError> {
        let identity = self.verify_leaf(leaf_pem, usage)?;
        crl.check_now(&identity.serial_hex)?;
        Ok(identity)
    }
}

fn random_serial() -> SerialNumber {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes[0] &= 0x7f;
    if bytes[0] == 0 {
        bytes[0] = 1;
    }
    SerialNumber::from_slice(&bytes)
}

fn serial_hex(serial: &SerialNumber) -> String {
    hex::encode(serial.as_ref())
}

fn serial_from_hex(serial_hex: &str) -> SerialNumber {
    let bytes = hex::decode(serial_hex).unwrap_or_default();
    SerialNumber::from_slice(&bytes)
}

fn parse_reason(reason: &str) -> Result<RevocationReason, PkiError> {
    match reason.to_ascii_lowercase().replace('-', "_").as_str() {
        "unspecified" => Ok(RevocationReason::Unspecified),
        "key_compromise" => Ok(RevocationReason::KeyCompromise),
        "ca_compromise" => Ok(RevocationReason::CaCompromise),
        "affiliation_changed" => Ok(RevocationReason::AffiliationChanged),
        "superseded" => Ok(RevocationReason::Superseded),
        "cessation_of_operation" => Ok(RevocationReason::CessationOfOperation),
        "certificate_hold" => Ok(RevocationReason::CertificateHold),
        "remove_from_crl" => Ok(RevocationReason::RemoveFromCrl),
        "privilege_withdrawn" => Ok(RevocationReason::PrivilegeWithdrawn),
        "aa_compromise" => Ok(RevocationReason::AaCompromise),
        other => Err(PkiError::UnknownReason(other.into())),
    }
}

fn write_private(path: impl AsRef<Path>, contents: &str) -> Result<(), PkiError> {
    let path = path.as_ref();
    std::fs::write(path, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, perms)?;
    }
    Ok(())
}

pub(crate) fn pem_to_der(pem_str: &str, label: &str) -> Result<Vec<u8>, PkiError> {
    crl::pem_to_der(pem_str, label)
}

/// Generate a random 128-bit certificate serial number, encoded as lowercase
/// hex. RFC 5280 requires positive integers; the top bit is therefore cleared.
pub fn random_serial_hex() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes[0] &= 0x7f;
    if bytes[0] == 0 {
        bytes[0] = 1;
    }
    hex::encode(bytes)
}

/// Extract the set of SAN identities from an unverified certificate. Used by
/// the mTLS verifier after chain verification to locate the node identity.
pub fn san_identities(der: &[u8]) -> Result<BTreeSet<String>, PkiError> {
    let (_, cert) =
        x509_parser::parse_x509_certificate(der).map_err(|e| PkiError::X509(e.to_string()))?;
    let mut out = BTreeSet::new();
    for ext in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for name in &san.general_names {
                match name {
                    GeneralName::DNSName(d) => {
                        out.insert(format!("dns:{d}"));
                    }
                    GeneralName::URI(u) => {
                        out.insert(format!("uri:{u}"));
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(out)
}

/// Verify a leaf against a PEM trust bundle (root first, then any
/// intermediates) for the requested EKU. Used by the attestation crate to
/// validate the AK certificate, and available to external tooling.
pub fn verify_chain_with_bundle(
    leaf_pem: &str,
    bundle_pem: &str,
    usage: LeafUsage,
) -> Result<LeafIdentity, PkiError> {
    let leaf_der = pem_to_der(leaf_pem, "CERTIFICATE")?;
    let mut bundle = Vec::new();
    let mut rest = bundle_pem;
    while let Ok(block) = pem::parse(rest) {
        if block.tag() != "CERTIFICATE" {
            break;
        }
        bundle.push(block.into_contents());
        // Advance past this block by locating the end marker.
        match rest.find("-----END CERTIFICATE-----") {
            Some(pos) => {
                rest = &rest[pos + "-----END CERTIFICATE-----".len()..];
            }
            None => break,
        }
    }
    let mut iter = bundle.into_iter();
    let root_der = iter
        .next()
        .ok_or_else(|| PkiError::Pem("empty trust bundle".into()))?;
    let intermediates: Vec<CertificateDer<'static>> = iter.map(CertificateDer::from).collect();

    let leaf_cert_der = CertificateDer::from(leaf_der.clone());
    let leaf = webpki::EndEntityCert::try_from(&leaf_cert_der)
        .map_err(|e| PkiError::Chain(e.to_string()))?;
    let root_cert = CertificateDer::from(root_der);
    let anchor =
        webpki::anchor_from_trusted_cert(&root_cert).map_err(|e| PkiError::Chain(e.to_string()))?;
    let eku = match usage {
        LeafUsage::Client => webpki::KeyUsage::client_auth(),
        LeafUsage::Server => webpki::KeyUsage::server_auth(),
    };
    leaf.verify_for_usage(
        webpki::ALL_VERIFICATION_ALGS,
        &[anchor],
        &intermediates,
        UnixTime::now(),
        eku,
        None,
        None,
    )
    .map_err(|e| match e {
        webpki::Error::CertExpired { .. } => PkiError::Expired,
        webpki::Error::CertNotValidYet { .. } => PkiError::NotYetValid,
        webpki::Error::RequiredEkuNotFoundContext(_) => {
            PkiError::Eku(if usage == LeafUsage::Client {
                "clientAuth"
            } else {
                "serverAuth"
            })
        }
        other => PkiError::Chain(other.to_string()),
    })?;

    let mut identity = peer_identity(&leaf_der)?;
    identity.usage = usage;
    Ok(identity)
}

/// Identity extracted from a certificate SAN without performing chain
/// verification. Callers must verify the chain first (for example in the
/// rustls client-certificate verifier).
pub fn peer_identity(der: &[u8]) -> Result<LeafIdentity, PkiError> {
    let (_, cert) =
        x509_parser::parse_x509_certificate(der).map_err(|e| PkiError::X509(e.to_string()))?;
    let mut dns_name = None;
    let mut uri = None;
    for ext in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for name in &san.general_names {
                match name {
                    GeneralName::DNSName(dns) => dns_name = Some((*dns).to_string()),
                    GeneralName::URI(u) => uri = Some((*u).to_string()),
                    _ => {}
                }
            }
        }
    }
    let dns_name = dns_name.ok_or(PkiError::MissingIdentity)?;
    let uri = uri.ok_or(PkiError::MissingIdentity)?;
    let hostname = dns_name
        .strip_suffix(".fleet.internal")
        .ok_or(PkiError::MissingIdentity)?
        .to_string();
    let rest = uri
        .strip_prefix("fleet://")
        .ok_or(PkiError::MissingIdentity)?;
    let (site, node_id) = rest.split_once('/').ok_or(PkiError::MissingIdentity)?;
    Ok(LeafIdentity {
        node_id: node_id.to_string(),
        site: site.to_string(),
        hostname,
        dns_name,
        uri,
        serial_hex: hex::encode(cert.raw_serial()),
        not_before: cert.validity().not_before.timestamp(),
        not_after: cert.validity().not_after.timestamp(),
        // Usage is not encoded separately from the EKU; the caller knows the
        // context in which the certificate was presented.
        usage: LeafUsage::Client,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_parser::prelude::FromDer;

    fn test_ca() -> Ca {
        Ca::init_root(CaConfig {
            crl_validity_hours: 24,
            ..Default::default()
        })
        .unwrap()
    }

    fn client_leaf(ca: &mut Ca, node: &str) -> IssuedCert {
        ca.issue_leaf(&LeafSpec::for_node("dc1", node)).unwrap()
    }

    #[test]
    fn root_is_a_ten_year_ca_with_pathlen_one() {
        let ca = test_ca();
        let der = pem_to_der(&ca.root_pem, "CERTIFICATE").unwrap();
        let (_, cert) = x509_parser::parse_x509_certificate(&der).unwrap();
        assert!(cert.is_ca());
        assert_eq!(
            cert.basic_constraints()
                .unwrap()
                .unwrap()
                .value
                .path_len_constraint,
            Some(1)
        );
        let ku = cert.key_usage().unwrap().unwrap().value;
        assert!(ku.key_cert_sign());
        assert!(ku.crl_sign());
        let validity = cert.validity();
        let days = (validity.not_after.timestamp() - validity.not_before.timestamp()) / 86_400;
        assert!(
            (3648..=3651).contains(&days),
            "root validity was {days} days"
        );
    }

    #[test]
    fn leaf_has_client_eku_and_fleet_sans() {
        let mut ca = test_ca();
        let issued = client_leaf(&mut ca, "n1");
        let der = pem_to_der(&issued.cert_pem, "CERTIFICATE").unwrap();
        let (_, cert) = x509_parser::parse_x509_certificate(&der).unwrap();
        let eku = cert.extended_key_usage().unwrap().unwrap().value;
        assert!(eku.client_auth);
        assert!(!eku.server_auth);
        assert_eq!(issued.identity.dns_name, "n1.fleet.internal");
        assert_eq!(issued.identity.uri, "fleet://dc1/n1");
        assert_eq!(issued.identity.node_id, "n1");
        assert_eq!(issued.identity.site, "dc1");
        let days = (issued.identity.not_after - issued.identity.not_before) / 86_400;
        assert!((89..=90).contains(&days), "leaf validity was {days} days");
        assert_eq!(issued.serial_hex.len(), 32);
        assert_eq!(issued.serial_hex, hex::encode(cert.raw_serial()));
    }

    #[test]
    fn chain_verification_succeeds_and_parses_identity() {
        let mut ca = test_ca();
        let issued = client_leaf(&mut ca, "n2");
        let identity = ca.verify_leaf(&issued.cert_pem, LeafUsage::Client).unwrap();
        assert_eq!(identity, issued.identity);
        assert!(ca
            .verify_leaf_with_crl(
                &issued.cert_pem,
                LeafUsage::Client,
                &ca.crl_store().unwrap()
            )
            .is_ok());
    }

    #[test]
    fn leaf_signed_by_wrong_ca_fails() {
        let ca = test_ca();
        let mut other = test_ca();
        let issued = client_leaf(&mut other, "n3");
        let err = ca
            .verify_leaf(&issued.cert_pem, LeafUsage::Client)
            .unwrap_err();
        assert!(matches!(err, PkiError::Chain(_)), "got {err:?}");
    }

    #[test]
    fn expired_leaf_fails() {
        let mut ca = test_ca();
        let issued = ca
            .issue_leaf(&LeafSpec::for_node("dc1", "n4").with_validity_days(-1))
            .unwrap();
        let err = ca
            .verify_leaf(&issued.cert_pem, LeafUsage::Client)
            .unwrap_err();
        assert!(matches!(err, PkiError::Expired), "got {err:?}");
    }

    #[test]
    fn eku_mismatch_is_rejected_in_both_directions() {
        let mut ca = test_ca();
        let client = client_leaf(&mut ca, "n5");
        let server = ca
            .issue_leaf(&LeafSpec::for_node("dc1", "fleetd").with_usage(LeafUsage::Server))
            .unwrap();

        let err = ca
            .verify_leaf(&client.cert_pem, LeafUsage::Server)
            .unwrap_err();
        assert!(matches!(err, PkiError::Eku("serverAuth")), "got {err:?}");
        let err = ca
            .verify_leaf(&server.cert_pem, LeafUsage::Client)
            .unwrap_err();
        assert!(matches!(err, PkiError::Eku("clientAuth")), "got {err:?}");
        assert!(ca.verify_leaf(&server.cert_pem, LeafUsage::Server).is_ok());
    }

    #[test]
    fn revocation_is_enforced_by_the_crl() {
        let mut ca = test_ca();
        let issued = client_leaf(&mut ca, "n6");
        assert!(!ca.crl_store().unwrap().crl().is_revoked(&issued.serial_hex));
        ca.revoke(&issued.serial_hex, "key_compromise").unwrap();
        let store = ca.crl_store().unwrap();
        assert!(store.crl().is_revoked(&issued.serial_hex));
        let err = store.check_now(&issued.serial_hex).unwrap_err();
        assert!(matches!(err, PkiError::Revoked(_)), "got {err:?}");
        let err = ca
            .verify_leaf_with_crl(&issued.cert_pem, LeafUsage::Client, &store)
            .unwrap_err();
        assert!(matches!(err, PkiError::Revoked(_)));
        ca.revoke(&issued.serial_hex, "superseded").unwrap();
        assert_eq!(ca.revoked.len(), 1, "revocation must be idempotent");
    }

    #[test]
    fn stale_crl_reports_a_distinct_error() {
        let mut ca = test_ca();
        let issued = client_leaf(&mut ca, "n7");
        let store = ca.crl_store().unwrap();
        let future = store.crl().next_update() + 1;
        let err = store.check(&issued.serial_hex, future).unwrap_err();
        assert!(matches!(err, PkiError::StaleCrl { .. }), "got {err:?}");
    }

    #[test]
    fn crl_signature_and_version_are_valid() {
        let ca = test_ca();
        let store = ca.crl_store().unwrap();
        store.crl().verify_signature(ca.root_pem()).unwrap_err();
        let active_pem = ca.intermediates[ca.active].cert_pem.clone();
        store.crl().verify_signature(&active_pem).unwrap();
        let parsed =
            x509_parser::revocation_list::CertificateRevocationList::from_der(store.crl().der())
                .unwrap()
                .1;
        assert_eq!(parsed.version().unwrap().0, 1, "CRL must be v2");
        assert_eq!(
            parsed.issuer().to_string(),
            x509_parser::parse_x509_certificate(&pem_to_der(&active_pem, "CERTIFICATE").unwrap())
                .unwrap()
                .1
                .subject()
                .to_string()
        );
    }

    #[test]
    fn csr_from_node_is_signed_without_exporting_its_key() {
        let mut ca = test_ca();
        let node = NodeKeypair::new("n8", "dc1").unwrap();
        let issued = ca
            .issue_leaf(&LeafSpec::for_node("dc1", "n8").with_csr(node.csr_pem()))
            .unwrap();
        assert!(issued.key_pem.is_none());
        assert_eq!(
            ca.verify_leaf(&issued.cert_pem, LeafUsage::Client)
                .unwrap()
                .serial_hex,
            issued.serial_hex
        );
        assert!(node.key_pem().contains("PRIVATE KEY"));
    }

    #[test]
    fn renewal_rekeys_and_keeps_identity() {
        let mut ca = test_ca();
        let spec = LeafSpec::for_node("dc1", "n9");
        let first = ca.issue_leaf(&spec).unwrap();
        let renewed = ca.renew_leaf(&spec).unwrap();
        assert_ne!(first.serial_hex, renewed.serial_hex);
        assert_ne!(first.key_pem.unwrap(), renewed.key_pem.clone().unwrap());
        assert_eq!(first.identity.node_id, renewed.identity.node_id);
        assert!(ca.verify_leaf(&renewed.cert_pem, LeafUsage::Client).is_ok());
        assert!(ca.verify_leaf(&first.cert_pem, LeafUsage::Client).is_ok());
    }

    #[test]
    fn intermediate_rotation_keeps_old_leaves_trusted() {
        let mut ca = test_ca();
        let old = client_leaf(&mut ca, "n10");
        assert_eq!(ca.summary().unwrap().intermediates.len(), 1);
        let new_info = ca.rotate_intermediate().unwrap();
        assert!(new_info.active);
        let summary = ca.summary().unwrap();
        assert_eq!(summary.intermediates.len(), 2);
        assert!(!summary.intermediates[0].active);
        assert!(summary.intermediates[1].active);
        assert!(ca.verify_leaf(&old.cert_pem, LeafUsage::Client).is_ok());
        let new = client_leaf(&mut ca, "n11");
        assert!(ca.verify_leaf(&new.cert_pem, LeafUsage::Client).is_ok());
        assert_eq!(
            ca.trust_bundle_pem().matches("BEGIN CERTIFICATE").count(),
            3
        );
    }

    #[test]
    fn persistence_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let mut ca = test_ca();
        let leaf = client_leaf(&mut ca, "n12");
        ca.revoke(&leaf.serial_hex, "cessation_of_operation")
            .unwrap();
        ca.save(dir.path()).unwrap();
        let loaded = Ca::load(dir.path()).unwrap();
        assert_eq!(loaded.trust_bundle_pem(), ca.trust_bundle_pem());
        assert!(loaded
            .verify_leaf(&leaf.cert_pem, LeafUsage::Client)
            .is_ok());
        assert!(loaded
            .crl_store()
            .unwrap()
            .check_now(&leaf.serial_hex)
            .is_err());
        assert!(dir.path().join("trust-bundle.pem").exists());
        assert!(dir.path().join("crl.pem").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join("root-key.pem"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn loader_initializes_missing_state() {
        let dir = tempfile::tempdir().unwrap();
        let ca = Ca::load_or_init(dir.path(), CaConfig::default()).unwrap();
        assert!(dir.path().join("ca.json").exists());
        assert_eq!(ca.summary().unwrap().revoked_count, 0);
        let again = Ca::load_or_init(dir.path(), CaConfig::default()).unwrap();
        assert_eq!(
            again.summary().unwrap().root_subject,
            ca.summary().unwrap().root_subject
        );
    }

    #[test]
    fn san_identities_include_dns_and_uri() {
        let mut ca = test_ca();
        let leaf = client_leaf(&mut ca, "n13");
        let der = pem_to_der(&leaf.cert_pem, "CERTIFICATE").unwrap();
        let sans = san_identities(&der).unwrap();
        assert!(sans.contains("dns:n13.fleet.internal"));
        assert!(sans.contains("uri:fleet://dc1/n13"));
        assert_eq!(sans.len(), 2);
    }

    #[test]
    fn crl_distribution_point_is_present() {
        let mut ca = test_ca();
        let leaf = client_leaf(&mut ca, "n14");
        let der = pem_to_der(&leaf.cert_pem, "CERTIFICATE").unwrap();
        let (_, cert) = x509_parser::parse_x509_certificate(&der).unwrap();
        let crl_dp = cert
            .extensions()
            .iter()
            .find_map(|e| match e.parsed_extension() {
                ParsedExtension::CRLDistributionPoints(points) => Some(points),
                _ => None,
            })
            .expect("CRL distribution point");
        assert_eq!(points_len(crl_dp), 1);
    }

    fn points_len(points: &x509_parser::extensions::CRLDistributionPoints<'_>) -> usize {
        points.iter().count()
    }

    #[test]
    fn root_is_self_signed_and_intermediate_is_not() {
        let ca = test_ca();
        let root = pem_to_der(&ca.root_pem, "CERTIFICATE").unwrap();
        let int = pem_to_der(&ca.intermediates[0].cert_pem, "CERTIFICATE").unwrap();
        let (_, root_cert) = x509_parser::parse_x509_certificate(&root).unwrap();
        let (_, int_cert) = x509_parser::parse_x509_certificate(&int).unwrap();
        assert_eq!(root_cert.subject(), root_cert.issuer());
        assert_ne!(int_cert.subject(), int_cert.issuer());
        assert!(int_cert.is_ca());
    }

    #[test]
    fn serial_numbers_are_unique_across_issuance() {
        let mut ca = test_ca();
        let mut seen = BTreeSet::new();
        for i in 0..64 {
            let leaf = client_leaf(&mut ca, &format!("n{i}"));
            assert!(seen.insert(leaf.serial_hex), "duplicate serial");
        }
        assert_eq!(seen.len(), 64);
    }

    #[test]
    fn unknown_reason_is_rejected() {
        let mut ca = test_ca();
        let leaf = client_leaf(&mut ca, "n15");
        assert!(ca.revoke(&leaf.serial_hex, "because_i_said_so").is_err());
        assert!(ca.crl_store().unwrap().check_now(&leaf.serial_hex).is_ok());
    }
}
