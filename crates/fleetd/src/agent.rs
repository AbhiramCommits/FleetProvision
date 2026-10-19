//! On-node agent: enrollment, certificate installation, and renewal.

use crate::control::renewal_threshold;
use fleet_attest::fixtures::{build_blob, generate_ak_keypair, BlobOptions};
use fleet_attest::Distro;
use fleet_pki::NodeKeypair;
use fleet_proto::{
    AkCertRequest, AkCertResponse, ApiError, ChallengeRequest, ChallengeResponse, EnrollRequest,
    EnrollResponse, RenewRequest,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct EnrollConfig {
    pub control_plane: String,
    /// Base URL of the token-gated enrollment listener.
    pub enroll_url: String,
    pub state_dir: PathBuf,
    pub token: String,
    pub node_id: String,
    pub site: String,
    pub hostname: String,
    pub ca_bundle: PathBuf,
    pub distro: Distro,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentState {
    pub node_id: String,
    pub site: String,
    pub hostname: String,
    pub serial_hex: String,
    pub not_before: i64,
    pub not_after: i64,
}

fn client(trust_pem: &str, identity: Option<(&str, &str)>) -> anyhow::Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(trust_pem.as_bytes())?);
    if let Some((cert, key)) = identity {
        let pem = format!("{cert}{key}");
        builder = builder.identity(reqwest::Identity::from_pem(pem.as_bytes())?);
    }
    Ok(builder.build()?)
}

async fn send_error(response: reqwest::Response) -> anyhow::Error {
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    match serde_json::from_str::<ApiError>(&body) {
        Ok(err) => anyhow::anyhow!("{status} {}: {}", err.code, err.error),
        Err(_) => anyhow::anyhow!("{status}: {body}"),
    }
}

/// Enroll this node: generate a key pair locally, request a nonce, sign the
/// attestation with the simulated TPM key, and install the returned chain.
pub async fn enroll(config: &EnrollConfig) -> anyhow::Result<EnrollResponse> {
    let trust_pem = std::fs::read_to_string(&config.ca_bundle)?;
    let http = client(&trust_pem, None)?;
    let keypair = NodeKeypair::new(&config.node_id, &config.site)?;

    // Simulated TPM provisioning: the AK key pair is generated on the node and
    // its public key is certified by the fleet CA through the token-gated
    // enrollment listener.
    let (ak_key_pem, ak_csr_pem, ak_signing_key) = generate_ak_keypair()?;
    let ak_response = http
        .post(format!("{}/v1/ak", config.enroll_url))
        .json(&AkCertRequest {
            token: config.token.clone(),
            csr_pem: ak_csr_pem,
        })
        .send()
        .await?;
    if !ak_response.status().is_success() {
        return Err(send_error(ak_response).await);
    }
    let ak: AkCertResponse = ak_response.json().await?;

    let challenge_response = http
        .post(format!("{}/v1/attest/challenge", config.enroll_url))
        .json(&ChallengeRequest {
            token: config.token.clone(),
        })
        .send()
        .await?;
    if !challenge_response.status().is_success() {
        return Err(send_error(challenge_response).await);
    }
    let challenge: ChallengeResponse = challenge_response.json().await?;

    let blob = build_blob(
        &ak.cert_pem,
        &ak_signing_key,
        &BlobOptions::good(
            &config.node_id,
            &config.site,
            config.distro,
            &challenge.nonce,
        ),
    )?;

    let request = EnrollRequest {
        token: config.token.clone(),
        node_id: config.node_id.clone(),
        site: config.site.clone(),
        hostname: config.hostname.clone(),
        csr_pem: keypair.csr_pem().to_string(),
        attestation: serde_json::to_value(&blob)?,
    };
    let response = http
        .post(format!("{}/v1/enroll", config.enroll_url))
        .json(&request)
        .send()
        .await?;
    if !response.status().is_success() {
        return Err(send_error(response).await);
    }
    let enrolled: EnrollResponse = response.json().await?;

    let node_dir = config.state_dir.join("node");
    std::fs::create_dir_all(&node_dir)?;
    write_private(&node_dir.join("node.key.pem"), keypair.key_pem())?;
    write_private(&node_dir.join("ak.key.pem"), &ak_key_pem)?;
    std::fs::write(node_dir.join("ak.crt.pem"), &ak.cert_pem)?;
    std::fs::write(
        node_dir.join("attestation.json"),
        serde_json::to_vec_pretty(&blob)?,
    )?;
    std::fs::write(node_dir.join("node.crt.pem"), &enrolled.cert_pem)?;
    std::fs::write(node_dir.join("node-chain.pem"), &enrolled.chain_pem)?;
    std::fs::write(
        node_dir.join("trust-bundle.pem"),
        &enrolled.trust_bundle_pem,
    )?;
    let not_before = crate::unix_now();
    let state = AgentState {
        node_id: config.node_id.clone(),
        site: config.site.clone(),
        hostname: config.hostname.clone(),
        serial_hex: enrolled.serial_hex.clone(),
        not_before,
        not_after: enrolled.not_after,
    };
    std::fs::write(
        node_dir.join("agent-state.json"),
        serde_json::to_vec_pretty(&state)?,
    )?;
    Ok(enrolled)
}

fn write_private(path: &Path, contents: &str) -> std::io::Result<()> {
    std::fs::write(path, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenewOutcome {
    Renewed { serial_hex: String, not_after: i64 },
    NotDue { remaining_seconds: i64 },
}

/// Renew only after two thirds of the certificate lifetime has elapsed.
pub async fn renew_if_due(control_plane: &str, state_dir: &Path) -> anyhow::Result<RenewOutcome> {
    let node_dir = state_dir.join("node");
    let cert = std::fs::read_to_string(node_dir.join("node.crt.pem"))?;
    let key = std::fs::read_to_string(node_dir.join("node.key.pem"))?;
    let trust = std::fs::read_to_string(node_dir.join("trust-bundle.pem"))?;
    let state: AgentState =
        serde_json::from_slice(&std::fs::read(node_dir.join("agent-state.json"))?)?;

    let lifetime = Duration::from_secs((state.not_after - state.not_before).max(1) as u64);
    let threshold = renewal_threshold(lifetime);
    let now = crate::unix_now();
    let elapsed = Duration::from_secs((now - state.not_before).max(0) as u64);
    if elapsed < threshold {
        return Ok(RenewOutcome::NotDue {
            remaining_seconds: (state.not_after - now).max(0),
        });
    }

    let http = client(&trust, Some((&cert, &key)))?;
    let keypair = NodeKeypair::new(&state.node_id, &state.site)?;
    let response = http
        .post(format!("{control_plane}/v1/renew"))
        .json(&RenewRequest {
            csr_pem: keypair.csr_pem().to_string(),
        })
        .send()
        .await?;
    if !response.status().is_success() {
        return Err(send_error(response).await);
    }
    let renewed: EnrollResponse = response.json().await?;
    write_private(&node_dir.join("node.key.pem"), keypair.key_pem())?;
    std::fs::write(node_dir.join("node.crt.pem"), &renewed.cert_pem)?;
    std::fs::write(node_dir.join("node-chain.pem"), &renewed.chain_pem)?;
    let state = AgentState {
        serial_hex: renewed.serial_hex.clone(),
        not_before: now,
        not_after: renewed.not_after,
        ..state
    };
    std::fs::write(
        node_dir.join("agent-state.json"),
        serde_json::to_vec_pretty(&state)?,
    )?;
    Ok(RenewOutcome::Renewed {
        serial_hex: renewed.serial_hex,
        not_after: renewed.not_after,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_state_round_trips() {
        let state = AgentState {
            node_id: "n1".into(),
            site: "dc1".into(),
            hostname: "n1".into(),
            serial_hex: "01".into(),
            not_before: 10,
            not_after: 20,
        };
        let raw = serde_json::to_string(&state).unwrap();
        let back: AgentState = serde_json::from_str(&raw).unwrap();
        assert_eq!(back.node_id, "n1");
        assert_eq!(back.not_after - back.not_before, 10);
    }
}
