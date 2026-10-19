//! TLS material and the custom client-certificate verifier.
//!
//! The verifier performs three checks on every handshake: chain validity
//! against the fleet root, EKU clientAuth, and CRL freshness plus revocation.

use crate::metrics::Metrics;
use fleet_pki::{CrlStore, LeafIdentity, PkiError};
use rustls::client::danger::HandshakeSignatureValid;
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, Error as TlsError, ServerConfig,
    SignatureScheme,
};
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone)]
pub struct TrustMaterial {
    pub root_der: CertificateDer<'static>,
    pub intermediate_ders: Vec<CertificateDer<'static>>,
    pub pem: String,
}

impl TrustMaterial {
    pub fn from_pem(pem: &str) -> Result<Self, PkiError> {
        let certs = pem_certs(pem)?;
        let mut iter = certs.into_iter();
        let root_der = iter
            .next()
            .ok_or_else(|| PkiError::Pem("trust bundle is empty".into()))?;
        Ok(Self {
            root_der,
            intermediate_ders: iter.collect(),
            pem: pem.to_string(),
        })
    }
}

pub fn pem_certs(pem: &str) -> Result<Vec<CertificateDer<'static>>, PkiError> {
    let mut reader = std::io::Cursor::new(pem.as_bytes());
    let certs: Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
    certs.map_err(|e| PkiError::Pem(e.to_string()))
}

pub fn pem_private_key(pem: &str) -> Result<rustls::pki_types::PrivateKeyDer<'static>, PkiError> {
    let mut reader = std::io::Cursor::new(pem.as_bytes());
    rustls_pemfile::private_key(&mut reader)
        .map_err(|e| PkiError::Pem(e.to_string()))?
        .ok_or_else(|| PkiError::Pem("no private key in PEM input".into()))
}

#[derive(Debug)]
pub struct FleetClientVerifier {
    trust: Arc<TrustMaterial>,
    crl: Arc<RwLock<CrlStore>>,
    metrics: Arc<Metrics>,
    hints: Vec<DistinguishedName>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl FleetClientVerifier {
    pub fn new(
        trust: Arc<TrustMaterial>,
        crl: Arc<RwLock<CrlStore>>,
        metrics: Arc<Metrics>,
        provider: Arc<rustls::crypto::CryptoProvider>,
    ) -> Self {
        Self {
            trust,
            crl,
            metrics,
            hints: Vec::new(),
            provider,
        }
    }
}

impl ClientCertVerifier for FleetClientVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &self.hints
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        let leaf = match webpki::EndEntityCert::try_from(end_entity) {
            Ok(cert) => cert,
            Err(_) => {
                self.metrics.handshake_failure("bad_encoding");
                return Err(TlsError::InvalidCertificate(CertificateError::BadEncoding));
            }
        };
        let anchor = match webpki::anchor_from_trusted_cert(&self.trust.root_der) {
            Ok(anchor) => anchor,
            Err(_) => {
                self.metrics.handshake_failure("bad_trust_anchor");
                return Err(TlsError::InvalidCertificate(CertificateError::BadEncoding));
            }
        };
        let mut chain_intermediates: Vec<CertificateDer<'_>> =
            self.trust.intermediate_ders.to_vec();
        chain_intermediates.extend(intermediates.iter().cloned());
        if let Err(err) = leaf.verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &[anchor],
            &chain_intermediates,
            now,
            webpki::KeyUsage::client_auth(),
            None,
            None,
        ) {
            let (reason, cert_error) = match err {
                webpki::Error::CertExpired { .. } => ("cert_expired", CertificateError::Expired),
                webpki::Error::CertNotValidYet { .. } => {
                    ("cert_not_yet_valid", CertificateError::NotValidYet)
                }
                webpki::Error::RequiredEkuNotFoundContext(_) => {
                    ("eku_mismatch", CertificateError::InvalidPurpose)
                }
                webpki::Error::UnknownIssuer => ("unknown_issuer", CertificateError::UnknownIssuer),
                _ => (
                    "chain_invalid",
                    CertificateError::Other(rustls::OtherError(Arc::new(std::io::Error::other(
                        err.to_string(),
                    )))),
                ),
            };
            self.metrics.handshake_failure(reason);
            return Err(TlsError::InvalidCertificate(cert_error));
        }

        let identity = match fleet_pki::peer_identity(end_entity.as_ref()) {
            Ok(identity) => identity,
            Err(_) => {
                self.metrics.handshake_failure("missing_identity");
                return Err(TlsError::InvalidCertificate(CertificateError::BadEncoding));
            }
        };
        let crl = self.crl.read().expect("crl lock poisoned");
        let now_secs = now.as_secs() as i64;
        match crl.check(&identity.serial_hex, now_secs) {
            Ok(()) => Ok(ClientCertVerified::assertion()),
            Err(PkiError::StaleCrl { .. }) => {
                self.metrics.handshake_failure("stale_crl");
                Err(TlsError::InvalidCertificate(
                    CertificateError::ExpiredRevocationList,
                ))
            }
            Err(PkiError::Revoked(_)) => {
                self.metrics.handshake_failure("revoked");
                Err(TlsError::InvalidCertificate(CertificateError::Revoked))
            }
            Err(_) => {
                self.metrics.handshake_failure("crl_error");
                Err(TlsError::InvalidCertificate(
                    CertificateError::UnknownRevocationStatus,
                ))
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub fn mtls_server_config(
    trust: Arc<TrustMaterial>,
    crl: Arc<RwLock<CrlStore>>,
    metrics: Arc<Metrics>,
    chain: Vec<CertificateDer<'static>>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
) -> Result<Arc<ServerConfig>, TlsError> {
    let provider = rustls::crypto::CryptoProvider::get_default()
        .expect("crypto provider installed")
        .clone();
    let verifier = Arc::new(FleetClientVerifier::new(trust, crl, metrics, provider));
    let config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)?;
    Ok(Arc::new(config))
}

pub fn server_auth_config(
    chain: Vec<CertificateDer<'static>>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
) -> Result<Arc<ServerConfig>, TlsError> {
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)?;
    Ok(Arc::new(config))
}

pub fn peer_from_certs(certs: Option<&[CertificateDer<'static>]>) -> Option<LeafIdentity> {
    certs
        .and_then(|certs| certs.first())
        .and_then(|der| fleet_pki::peer_identity(der.as_ref()).ok())
}
