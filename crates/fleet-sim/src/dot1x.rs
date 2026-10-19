//! Simulated 802.1X port authenticator with an EAP-TLS-shaped handshake.
//!
//! The transport is a JSON-line protocol over TCP rather than real EAPOL
//! frames, but the security decisions are real: the supplicant presents its
//! node certificate, proves possession of the key over a fresh challenge, and
//! the authenticator validates the chain, CRL freshness, revocation status, and
//! boot-attestation verdict before assigning a VLAN.

use crate::net::NetError;
use base64::Engine;
use fleet_pki::{CrlStore, LeafUsage};
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::pkcs8::{DecodePrivateKey, DecodePublicKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

pub const VLAN_PROD: u16 = 100;
pub const VLAN_QUARANTINE: u16 = 666;

#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMsg {
    EapolStart,
    EapResponseIdentity { node_id: String, cert_pem: String },
    EapResponseChallenge { signature: String },
}

#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMsg {
    EapRequestIdentity,
    EapRequestChallenge { challenge: String },
    EapSuccess { vlan: u16 },
    EapFailure { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum Dot1xOutcome {
    Authorized { vlan: u16 },
    Rejected { reason: String },
}

#[derive(Debug, Clone)]
pub struct Dot1xConfig {
    pub ca_pem: String,
    pub crl: Arc<RwLock<CrlStore>>,
    /// Boot-attestation verdict per node: true = pass, false = quarantine.
    /// Shared so the e2e harness can record verdicts as nodes enroll.
    pub attestations: Arc<RwLock<HashMap<String, bool>>>,
    /// Added to the wall clock when checking CRL freshness (test hook for
    /// simulating an expired CRL without waiting).
    pub clock_offset_seconds: i64,
}

pub struct RunningDot1x {
    pub addr: SocketAddr,
    shutdown: watch::Sender<bool>,
    handle: tokio::task::JoinHandle<()>,
}

impl RunningDot1x {
    pub async fn shutdown(self) {
        let _ = self.shutdown.send(true);
        let _ = self.handle.await;
    }
}

pub async fn start(config: Dot1xConfig) -> Result<RunningDot1x, NetError> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let (shutdown, mut rx) = watch::channel(false);
    let config = Arc::new(config);
    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                changed = rx.changed() => {
                    if changed.is_err() || *rx.borrow() { break; }
                }
                accepted = listener.accept() => {
                    let Ok((stream, _)) = accepted else { break };
                    let config = config.clone();
                    tokio::spawn(async move {
                        let _ = handle_supplicant(stream, config).await;
                    });
                }
            }
        }
    });
    Ok(RunningDot1x {
        addr,
        shutdown,
        handle,
    })
}

async fn read_msg(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
) -> Result<ClientMsg, NetError> {
    let mut line = String::new();
    let n = tokio::time::timeout(Duration::from_secs(10), reader.read_line(&mut line))
        .await
        .map_err(|_| NetError::Timeout)??;
    if n == 0 {
        return Err(NetError::Malformed(
            "supplicant closed the connection".into(),
        ));
    }
    serde_json::from_str(&line).map_err(|e| NetError::Malformed(e.to_string()))
}

async fn write_msg(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    msg: &ServerMsg,
) -> Result<(), NetError> {
    let mut line = serde_json::to_vec(msg).map_err(|e| NetError::Malformed(e.to_string()))?;
    line.push(b'\n');
    writer.write_all(&line).await?;
    writer.flush().await?;
    Ok(())
}

async fn reject(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    reason: &str,
) -> Result<Dot1xOutcome, NetError> {
    write_msg(
        writer,
        &ServerMsg::EapFailure {
            reason: reason.into(),
        },
    )
    .await?;
    Ok(Dot1xOutcome::Rejected {
        reason: reason.into(),
    })
}

async fn handle_supplicant(
    stream: TcpStream,
    config: Arc<Dot1xConfig>,
) -> Result<Dot1xOutcome, NetError> {
    let (read_half, mut writer) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    match read_msg(&mut reader).await? {
        ClientMsg::EapolStart => {}
        _ => return reject(&mut writer, "expected eapol_start").await,
    }
    write_msg(&mut writer, &ServerMsg::EapRequestIdentity).await?;

    let (node_id, cert_pem) = match read_msg(&mut reader).await? {
        ClientMsg::EapResponseIdentity { node_id, cert_pem } => (node_id, cert_pem),
        _ => return reject(&mut writer, "expected eap_response_identity").await,
    };

    let identity =
        match fleet_pki::verify_chain_with_bundle(&cert_pem, &config.ca_pem, LeafUsage::Client) {
            Ok(identity) => identity,
            Err(err) => {
                let reason = match err {
                    fleet_pki::PkiError::Expired => "cert_expired",
                    fleet_pki::PkiError::Eku(_) => "eku_mismatch",
                    _ => "unknown_identity",
                };
                return reject(&mut writer, reason).await;
            }
        };
    if identity.node_id != node_id {
        return reject(&mut writer, "identity_mismatch").await;
    }

    let crl_result = {
        let crl = config.crl.read().expect("crl lock poisoned");
        crl.check(
            &identity.serial_hex,
            crate::unix_now() + config.clock_offset_seconds,
        )
    };
    if let Err(err) = crl_result {
        let reason = match err {
            fleet_pki::PkiError::Revoked(_) => "revoked",
            fleet_pki::PkiError::StaleCrl { .. } => "stale_crl",
            _ => "crl_error",
        };
        return reject(&mut writer, reason).await;
    }

    let challenge = format!(
        "{:016x}{:016x}",
        rand::random::<u64>(),
        rand::random::<u64>()
    );
    write_msg(
        &mut writer,
        &ServerMsg::EapRequestChallenge {
            challenge: challenge.clone(),
        },
    )
    .await?;
    let signature = match read_msg(&mut reader).await? {
        ClientMsg::EapResponseChallenge { signature } => signature,
        _ => return reject(&mut writer, "expected eap_response_challenge").await,
    };
    if verify_possession(&cert_pem, challenge.as_bytes(), &signature).is_err() {
        return reject(&mut writer, "bad_possession_proof").await;
    }

    let verdict = config
        .attestations
        .read()
        .expect("attestation lock poisoned")
        .get(&node_id)
        .copied();
    match verdict {
        Some(true) => {
            write_msg(&mut writer, &ServerMsg::EapSuccess { vlan: VLAN_PROD }).await?;
            Ok(Dot1xOutcome::Authorized { vlan: VLAN_PROD })
        }
        Some(false) => {
            write_msg(
                &mut writer,
                &ServerMsg::EapSuccess {
                    vlan: VLAN_QUARANTINE,
                },
            )
            .await?;
            Ok(Dot1xOutcome::Authorized {
                vlan: VLAN_QUARANTINE,
            })
        }
        None => reject(&mut writer, "unknown_attestation").await,
    }
}

fn verify_possession(cert_pem: &str, message: &[u8], signature_b64: &str) -> Result<(), NetError> {
    use base64::Engine;
    let der = pem::parse(cert_pem)
        .map_err(|e| NetError::Malformed(format!("cert PEM: {e}")))?
        .into_contents();
    let (_, cert) = x509_parser::parse_x509_certificate(&der)
        .map_err(|e| NetError::Malformed(format!("cert X.509: {e}")))?;
    let verifying_key = VerifyingKey::from_public_key_der(cert.public_key().raw)
        .map_err(|e| NetError::Malformed(format!("public key: {e}")))?;
    let sig_der = base64::engine::general_purpose::STANDARD
        .decode(signature_b64)
        .map_err(|e| NetError::Malformed(format!("signature base64: {e}")))?;
    let signature = Signature::from_der(&sig_der)
        .map_err(|e| NetError::Malformed(format!("signature DER: {e}")))?;
    verifying_key
        .verify(message, &signature)
        .map_err(|_| NetError::Malformed("possession proof failed".into()))
}

/// Supplicant side: connect, present the node certificate, prove key
/// possession, and return the assigned VLAN.
pub async fn authenticate(
    server: SocketAddr,
    node_id: &str,
    cert_pem: &str,
    key_pem: &str,
) -> Result<Dot1xOutcome, NetError> {
    let key = SigningKey::from_pkcs8_pem(key_pem)
        .map_err(|e| NetError::Malformed(format!("key parse: {e}")))?;
    let stream = TcpStream::connect(server).await?;
    let (read_half, mut writer) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    send_client(&mut writer, &ClientMsg::EapolStart).await?;
    let msg = read_server(&mut reader).await?;
    if msg != ServerMsg::EapRequestIdentity {
        return Err(NetError::Malformed(format!(
            "expected identity request, got {msg:?}"
        )));
    }
    send_client(
        &mut writer,
        &ClientMsg::EapResponseIdentity {
            node_id: node_id.into(),
            cert_pem: cert_pem.into(),
        },
    )
    .await?;
    let challenge = match read_server(&mut reader).await? {
        ServerMsg::EapRequestChallenge { challenge } => challenge,
        ServerMsg::EapFailure { reason } => return Ok(Dot1xOutcome::Rejected { reason }),
        other => {
            return Err(NetError::Malformed(format!(
                "expected challenge, got {other:?}"
            )))
        }
    };
    let signature: Signature = key.sign(challenge.as_bytes());
    send_client(
        &mut writer,
        &ClientMsg::EapResponseChallenge {
            signature: base64::engine::general_purpose::STANDARD
                .encode(signature.to_der().as_bytes()),
        },
    )
    .await?;
    match read_server(&mut reader).await? {
        ServerMsg::EapSuccess { vlan } => Ok(Dot1xOutcome::Authorized { vlan }),
        ServerMsg::EapFailure { reason } => Ok(Dot1xOutcome::Rejected { reason }),
        other => Err(NetError::Malformed(format!("unexpected result {other:?}"))),
    }
}

async fn send_client(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    msg: &ClientMsg,
) -> Result<(), NetError> {
    let mut line = serde_json::to_vec(msg).map_err(|e| NetError::Malformed(e.to_string()))?;
    line.push(b'\n');
    writer.write_all(&line).await?;
    writer.flush().await?;
    Ok(())
}

async fn read_server(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
) -> Result<ServerMsg, NetError> {
    let mut line = String::new();
    let n = tokio::time::timeout(Duration::from_secs(10), reader.read_line(&mut line))
        .await
        .map_err(|_| NetError::Timeout)??;
    if n == 0 {
        return Err(NetError::Malformed(
            "authenticator closed the connection".into(),
        ));
    }
    serde_json::from_str(&line).map_err(|e| NetError::Malformed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fleet_pki::{Ca, CaConfig, IssuedCert, LeafSpec};

    struct Fixture {
        ca: Ca,
        server: RunningDot1x,
    }

    async fn fixture() -> Fixture {
        let mut ca = Ca::init_root(CaConfig::default()).unwrap();
        let leaf = ca.issue_leaf(&LeafSpec::for_node("dc1", "n1")).unwrap();
        let crl = Arc::new(RwLock::new(ca.crl_store().unwrap()));
        let mut attestations = HashMap::new();
        attestations.insert("n1".to_string(), true);
        let server = start(Dot1xConfig {
            ca_pem: ca.trust_bundle_pem(),
            crl,
            attestations: Arc::new(RwLock::new(attestations)),
            clock_offset_seconds: 0,
        })
        .await
        .unwrap();
        let _ = leaf;
        Fixture { ca, server }
    }

    fn leaf(ca: &mut Ca, node: &str) -> IssuedCert {
        ca.issue_leaf(&LeafSpec::for_node("dc1", node)).unwrap()
    }

    #[tokio::test]
    async fn attested_node_gets_production_vlan() {
        let mut f = fixture().await;
        let leaf = leaf(&mut f.ca, "n1");
        let outcome = authenticate(
            f.server.addr,
            "n1",
            &leaf.cert_pem,
            leaf.key_pem.as_deref().unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(outcome, Dot1xOutcome::Authorized { vlan: VLAN_PROD });
        f.server.shutdown().await;
    }

    #[tokio::test]
    async fn failed_attestation_gets_quarantine_vlan() {
        let mut ca = Ca::init_root(CaConfig::default()).unwrap();
        let leaf = ca.issue_leaf(&LeafSpec::for_node("dc1", "n2")).unwrap();
        let mut attestations = HashMap::new();
        attestations.insert("n2".to_string(), false);
        let server = start(Dot1xConfig {
            ca_pem: ca.trust_bundle_pem(),
            crl: Arc::new(RwLock::new(ca.crl_store().unwrap())),
            attestations: Arc::new(RwLock::new(attestations)),
            clock_offset_seconds: 0,
        })
        .await
        .unwrap();
        let outcome = authenticate(
            server.addr,
            "n2",
            &leaf.cert_pem,
            leaf.key_pem.as_deref().unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            outcome,
            Dot1xOutcome::Authorized {
                vlan: VLAN_QUARANTINE
            }
        );
        server.shutdown().await;
    }

    #[tokio::test]
    async fn revoked_certificate_is_refused() {
        let mut ca = Ca::init_root(CaConfig::default()).unwrap();
        let leaf = ca.issue_leaf(&LeafSpec::for_node("dc1", "n3")).unwrap();
        ca.revoke(&leaf.serial_hex, "key_compromise").unwrap();
        let mut attestations = HashMap::new();
        attestations.insert("n3".to_string(), true);
        let server = start(Dot1xConfig {
            ca_pem: ca.trust_bundle_pem(),
            crl: Arc::new(RwLock::new(ca.crl_store().unwrap())),
            attestations: Arc::new(RwLock::new(attestations)),
            clock_offset_seconds: 0,
        })
        .await
        .unwrap();
        let outcome = authenticate(
            server.addr,
            "n3",
            &leaf.cert_pem,
            leaf.key_pem.as_deref().unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            outcome,
            Dot1xOutcome::Rejected {
                reason: "revoked".into()
            }
        );
        server.shutdown().await;
    }

    #[tokio::test]
    async fn stale_crl_is_refused() {
        let mut ca = Ca::init_root(CaConfig::default()).unwrap();
        let leaf = ca.issue_leaf(&LeafSpec::for_node("dc1", "n4")).unwrap();
        ca.issue_crl_window(-2, -1).unwrap();
        let mut attestations = HashMap::new();
        attestations.insert("n4".to_string(), true);
        let server = start(Dot1xConfig {
            ca_pem: ca.trust_bundle_pem(),
            crl: Arc::new(RwLock::new(ca.crl_store().unwrap())),
            attestations: Arc::new(RwLock::new(attestations)),
            clock_offset_seconds: 0,
        })
        .await
        .unwrap();
        let outcome = authenticate(
            server.addr,
            "n4",
            &leaf.cert_pem,
            leaf.key_pem.as_deref().unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            outcome,
            Dot1xOutcome::Rejected {
                reason: "stale_crl".into()
            }
        );
        server.shutdown().await;
    }

    #[tokio::test]
    async fn foreign_certificate_is_unknown() {
        let ca = Ca::init_root(CaConfig::default()).unwrap();
        let mut foreign = Ca::init_root(CaConfig::default()).unwrap();
        let leaf = foreign
            .issue_leaf(&LeafSpec::for_node("dc1", "n5"))
            .unwrap();
        let mut attestations = HashMap::new();
        attestations.insert("n5".to_string(), true);
        let server = start(Dot1xConfig {
            ca_pem: ca.trust_bundle_pem(),
            crl: Arc::new(RwLock::new(ca.crl_store().unwrap())),
            attestations: Arc::new(RwLock::new(attestations)),
            clock_offset_seconds: 0,
        })
        .await
        .unwrap();
        let outcome = authenticate(
            server.addr,
            "n5",
            &leaf.cert_pem,
            leaf.key_pem.as_deref().unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            outcome,
            Dot1xOutcome::Rejected {
                reason: "unknown_identity".into()
            }
        );
        server.shutdown().await;
    }

    #[tokio::test]
    async fn node_without_attestation_is_refused() {
        let mut ca = Ca::init_root(CaConfig::default()).unwrap();
        let leaf = ca.issue_leaf(&LeafSpec::for_node("dc1", "n6")).unwrap();
        let server = start(Dot1xConfig {
            ca_pem: ca.trust_bundle_pem(),
            crl: Arc::new(RwLock::new(ca.crl_store().unwrap())),
            attestations: Arc::new(RwLock::new(HashMap::new())),
            clock_offset_seconds: 0,
        })
        .await
        .unwrap();
        let outcome = authenticate(
            server.addr,
            "n6",
            &leaf.cert_pem,
            leaf.key_pem.as_deref().unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            outcome,
            Dot1xOutcome::Rejected {
                reason: "unknown_attestation".into()
            }
        );
        server.shutdown().await;
    }
}
