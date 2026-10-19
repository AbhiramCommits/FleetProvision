//! End-to-end tests over real TLS sockets and ephemeral ports.

use fleet_attest::fixtures::{build_blob, generate_ak_keypair, issue_ak_cert, BlobOptions};
use fleet_attest::{AttestationBlob, Distro};
use fleet_pki::{Ca, CaConfig, LeafUsage, NodeKeypair};
use fleet_proto::{
    ChallengeRequest, ChallengeResponse, CreateTokenRequest, CreateTokenResponse, EnrollRequest,
    EnrollResponse, HeartbeatRequest, NodesResponse, RenewRequest, RevokeRequest,
};
use fleetd::control::{start, ControlConfig, RunningControlPlane};
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::path::Path;
use tempfile::TempDir;

struct Harness {
    _dir: TempDir,
    running: RunningControlPlane,
    ca_pem: String,
    idp: fleetd::idp::RunningIdp,
}

fn free_port() -> SocketAddr {
    let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

fn policy_path() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../policy/boot-integrity.yaml")
}

fn init_ca(dir: &Path) -> Ca {
    let mut ca = Ca::init_root(CaConfig::default()).unwrap();
    ca.save(dir).unwrap();
    ca
}

async fn harness() -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let _ca = init_ca(dir.path());
    let idp = fleetd::idp::start().await.unwrap();
    let running = start(ControlConfig {
        state_dir: dir.path().to_path_buf(),
        listen: free_port(),
        enroll_listen: free_port(),
        operator_listen: free_port(),
        token_key: None,
        site: "dc1".into(),
        policy: policy_path(),
        oidc_issuer: idp.issuer.clone(),
        oidc_audience: "fleetd".into(),
        public_url: "https://127.0.0.1:8443".into(),
    })
    .await
    .unwrap();
    let ca_pem = running.ca_pem.clone();
    Harness {
        _dir: dir,
        running,
        ca_pem,
        idp,
    }
}

fn bearer_client(ca_pem: &str, token: &str) -> reqwest::Client {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::AUTHORIZATION,
        format!("Bearer {token}").parse().unwrap(),
    );
    reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
        .default_headers(headers)
        .build()
        .unwrap()
}

fn operator_client(h: &Harness, group: &str) -> reqwest::Client {
    let token = h.idp.sign_token(
        "operator@fleet.internal",
        vec![group.to_string()],
        "fleetd",
        600,
        &h.idp.kid,
        None,
    );
    bearer_client(&h.ca_pem, &token)
}

fn tls_client(ca_pem: &str, identity: Option<(&str, &str)>) -> reqwest::Client {
    let mut builder = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap());
    if let Some((cert, key)) = identity {
        builder = builder
            .identity(reqwest::Identity::from_pem(format!("{cert}{key}").as_bytes()).unwrap());
    }
    builder.build().unwrap()
}

async fn issue_token(h: &Harness, node_id: &str) -> String {
    let client = operator_client(h, "fleet-admin");
    let response: CreateTokenResponse = client
        .post(format!("https://{}/v1/tokens", h.running.operator_addr))
        .json(&CreateTokenRequest {
            node_id: node_id.into(),
            site: "dc1".into(),
            ttl_seconds: 600,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    response.token
}

#[derive(Debug)]
struct Enrolled {
    response: EnrollResponse,
    key_pem: String,
}

async fn enroll_node(h: &Harness, node_id: &str, token: &str) -> Result<Enrolled, String> {
    enroll_with(h, node_id, token, |_| {}).await
}

async fn enroll_with<F>(
    h: &Harness,
    node_id: &str,
    token: &str,
    mutate: F,
) -> Result<Enrolled, String>
where
    F: FnOnce(&mut AttestationBlob),
{
    let client = tls_client(&h.ca_pem, None);
    let keypair = NodeKeypair::new(node_id, "dc1").unwrap();
    let challenge_response = client
        .post(format!(
            "https://{}/v1/attest/challenge",
            h.running.enroll_addr
        ))
        .json(&ChallengeRequest {
            token: token.into(),
        })
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !challenge_response.status().is_success() {
        let status = challenge_response.status();
        let body = challenge_response.text().await.unwrap_or_default();
        return Err(format!("{status} {body}"));
    }
    let challenge: ChallengeResponse =
        challenge_response.json().await.map_err(|e| e.to_string())?;

    let mut ca = Ca::load(h._dir.path()).unwrap();
    let (_, ak_csr, ak_key) = generate_ak_keypair().unwrap();
    let ak_cert = issue_ak_cert(&mut ca, node_id, "dc1", &ak_csr).unwrap();
    let mut blob = build_blob(
        &ak_cert,
        &ak_key,
        &BlobOptions::good(node_id, "dc1", Distro::Ubuntu, &challenge.nonce),
    )
    .unwrap();
    mutate(&mut blob);

    let request = EnrollRequest {
        token: token.into(),
        node_id: node_id.into(),
        site: "dc1".into(),
        hostname: node_id.into(),
        csr_pem: keypair.csr_pem().to_string(),
        attestation: serde_json::to_value(&blob).unwrap(),
    };
    let response = client
        .post(format!("https://{}/v1/enroll", h.running.enroll_addr))
        .json(&request)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("{} {}", status, response.text().await.unwrap()));
    }
    Ok(Enrolled {
        response: response.json().await.unwrap(),
        key_pem: keypair.key_pem().to_string(),
    })
}

async fn enroll_or_panic(h: &Harness, node_id: &str) -> Enrolled {
    let token = issue_token(h, node_id).await;
    enroll_node(h, node_id, &token).await.unwrap()
}

async fn list_nodes(h: &Harness) -> NodesResponse {
    let client = operator_client(h, "fleet-admin");
    client
        .get(format!("https://{}/v1/nodes", h.running.operator_addr))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap()
}

#[tokio::test]
async fn happy_path_enrollment_issues_chained_certificate() {
    let h = harness().await;
    let enrolled = enroll_or_panic(&h, "n1").await;
    assert_eq!(enrolled.response.node_id, "n1");
    assert_eq!(enrolled.response.state, fleet_proto::NodeState::Enrolled);
    assert!(enrolled.response.cert_pem.contains("BEGIN CERTIFICATE"));
    assert!(
        enrolled
            .response
            .trust_bundle_pem
            .matches("BEGIN CERTIFICATE")
            .count()
            >= 2
    );
    assert_eq!(enrolled.response.serial_hex.len(), 32);

    let ca = Ca::load(h._dir.path()).unwrap();
    let identity = ca
        .verify_leaf(&enrolled.response.cert_pem, LeafUsage::Client)
        .unwrap();
    assert_eq!(identity.node_id, "n1");
    assert_eq!(identity.dns_name, "n1.fleet.internal");
    assert_eq!(identity.uri, "fleet://dc1/n1");

    let nodes = list_nodes(&h).await;
    assert_eq!(nodes.count, 1);
    assert_eq!(nodes.nodes[0].state, fleet_proto::NodeState::Enrolled);
}

#[tokio::test]
async fn reused_bootstrap_token_is_rejected_with_409() {
    let h = harness().await;
    let token = issue_token(&h, "n2").await;
    enroll_node(&h, "n2", &token).await.unwrap();
    let err = enroll_node(&h, "n2", &token).await.unwrap_err();
    assert!(err.contains("409"), "unexpected error: {err}");
    assert!(err.contains("token_replayed") || err.contains("already been used"));
}

#[tokio::test]
async fn tls_handshake_requires_a_client_certificate() {
    let h = harness().await;
    let client = tls_client(&h.ca_pem, None);
    let err = client
        .get(format!("https://{}/v1/whoami", h.running.mtls_addr))
        .send()
        .await
        .expect_err("handshake without a client cert must fail");
    let text = format!("{err:?}").to_lowercase();
    assert!(
        text.contains("certificate") || text.contains("tls") || text.contains("alert"),
        "unexpected handshake error: {text}"
    );
    assert!(h.running.state.metrics.handshake_failures_total() >= 1);
}

#[tokio::test]
async fn revoked_certificate_is_refused_at_handshake() {
    let h = harness().await;
    let enrolled = enroll_or_panic(&h, "n3").await;
    let node_client = tls_client(
        &h.ca_pem,
        Some((&enrolled.response.cert_pem, &enrolled.key_pem)),
    );
    node_client
        .get(format!("https://{}/v1/whoami", h.running.mtls_addr))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    let operator = operator_client(&h, "fleet-admin");
    operator
        .post(format!(
            "https://{}/v1/nodes/n3/revoke",
            h.running.operator_addr
        ))
        .json(&RevokeRequest {
            reason: "key_compromise".into(),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    let fresh = tls_client(
        &h.ca_pem,
        Some((&enrolled.response.cert_pem, &enrolled.key_pem)),
    );
    let err = fresh
        .get(format!("https://{}/v1/whoami", h.running.mtls_addr))
        .send()
        .await
        .expect_err("revoked certificate must be refused");
    let text = format!("{err:?}").to_lowercase();
    assert!(
        text.contains("revoked") || text.contains("alert"),
        "unexpected error: {text}"
    );

    let ca = Ca::load(h._dir.path()).unwrap();
    assert!(ca
        .crl_store()
        .unwrap()
        .crl()
        .is_revoked(&enrolled.response.serial_hex));
}

#[tokio::test]
async fn renewal_before_expiry_rekeys_and_revokes_the_old_serial() {
    let h = harness().await;
    let enrolled = enroll_or_panic(&h, "n4").await;
    let node_client = tls_client(
        &h.ca_pem,
        Some((&enrolled.response.cert_pem, &enrolled.key_pem)),
    );
    let new_key = NodeKeypair::new("n4", "dc1").unwrap();
    let renewed: EnrollResponse = node_client
        .post(format!("https://{}/v1/renew", h.running.mtls_addr))
        .json(&RenewRequest {
            csr_pem: new_key.csr_pem().to_string(),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_ne!(renewed.serial_hex, enrolled.response.serial_hex);

    let ca = Ca::load(h._dir.path()).unwrap();
    assert!(ca
        .crl_store()
        .unwrap()
        .crl()
        .is_revoked(&enrolled.response.serial_hex));
    ca.verify_leaf(&renewed.cert_pem, LeafUsage::Client)
        .unwrap();

    let new_client = tls_client(&h.ca_pem, Some((&renewed.cert_pem, new_key.key_pem())));
    new_client
        .get(format!("https://{}/v1/whoami", h.running.mtls_addr))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
}

#[tokio::test]
async fn server_restart_preserves_enrollment_state() {
    let h = harness().await;
    let enrolled = enroll_or_panic(&h, "n5").await;
    let dir = h._dir.path().to_path_buf();
    let ca_pem = h.ca_pem.clone();
    let issuer = h.idp.issuer.clone();
    h.running.shutdown().await;

    let running = start(ControlConfig {
        state_dir: dir.clone(),
        listen: free_port(),
        enroll_listen: free_port(),
        operator_listen: free_port(),
        token_key: None,
        site: "dc1".into(),
        policy: policy_path(),
        oidc_issuer: issuer,
        oidc_audience: "fleetd".into(),
        public_url: "https://127.0.0.1:8443".into(),
    })
    .await
    .unwrap();
    let token = h.idp.sign_token(
        "operator@fleet.internal",
        vec!["fleet-admin".into()],
        "fleetd",
        600,
        &h.idp.kid,
        None,
    );
    let client = bearer_client(&ca_pem, &token);
    let nodes: NodesResponse = client
        .get(format!("https://{}/v1/nodes", running.operator_addr))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(nodes.count, 1);
    assert_eq!(nodes.nodes[0].node_id, "n5");
    assert_eq!(nodes.nodes[0].state, fleet_proto::NodeState::Enrolled);
    assert_eq!(
        nodes.nodes[0].serial_hex.as_deref(),
        Some(enrolled.response.serial_hex.as_str())
    );
    running.shutdown().await;
}

#[tokio::test]
async fn heartbeat_is_accepted_only_from_the_matching_node_identity() {
    let h = harness().await;
    let enrolled = enroll_or_panic(&h, "n6").await;
    let node_client = tls_client(
        &h.ca_pem,
        Some((&enrolled.response.cert_pem, &enrolled.key_pem)),
    );
    let response = node_client
        .post(format!("https://{}/v1/heartbeat", h.running.mtls_addr))
        .json(&HeartbeatRequest {
            node_id: "n6".into(),
            sent_at: fleetd::unix_now(),
        })
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    let beat: fleet_proto::HeartbeatResponse = response.json().await.unwrap();
    assert!(beat.ok);

    let mismatch = node_client
        .post(format!("https://{}/v1/heartbeat", h.running.mtls_addr))
        .json(&HeartbeatRequest {
            node_id: "n7".into(),
            sent_at: fleetd::unix_now(),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(mismatch.status().as_u16(), 403);
}

#[tokio::test]
async fn node_certificate_cannot_call_operator_endpoints() {
    let h = harness().await;
    let enrolled = enroll_or_panic(&h, "n8").await;
    let node_client = tls_client(
        &h.ca_pem,
        Some((&enrolled.response.cert_pem, &enrolled.key_pem)),
    );
    let response = node_client
        .get(format!("https://{}/v1/nodes", h.running.operator_addr))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 401);
    let body = response.text().await.unwrap();
    assert!(body.contains("missing_token"), "body: {body}");
}

#[tokio::test]
async fn operator_token_cannot_call_node_endpoints() {
    let h = harness().await;
    let operator = operator_client(&h, "fleet-admin");
    let err = operator
        .get(format!("https://{}/v1/whoami", h.running.mtls_addr))
        .send()
        .await
        .expect_err("mTLS listener must require a client certificate");
    let text = format!("{err:?}").to_lowercase();
    assert!(
        text.contains("certificate") || text.contains("alert") || text.contains("tls"),
        "{text}"
    );
}

#[tokio::test]
async fn tampered_token_is_rejected_before_csr_processing() {
    let h = harness().await;
    let token = issue_token(&h, "n9").await;
    let mut bytes = token.into_bytes();
    let last = bytes.len() - 1;
    bytes[last] = if bytes[last] == b'A' { b'B' } else { b'A' };
    let err = enroll_node(&h, "n9", &String::from_utf8(bytes).unwrap())
        .await
        .unwrap_err();
    assert!(err.contains("401") || err.contains("signature"), "{err}");
}

#[tokio::test]
async fn revoked_node_cannot_re_enroll_with_a_new_token() {
    let h = harness().await;
    let enrolled = enroll_or_panic(&h, "n10").await;
    let operator = operator_client(&h, "fleet-admin");
    operator
        .post(format!(
            "https://{}/v1/nodes/n10/revoke",
            h.running.operator_addr
        ))
        .json(&RevokeRequest {
            reason: "cessation_of_operation".into(),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    let token = issue_token(&h, "n10").await;
    let err = enroll_node(&h, "n10", &token).await.unwrap_err();
    assert!(err.contains("node_revoked") || err.contains("403"), "{err}");
    assert!(!enrolled.response.cert_pem.is_empty());
}

#[tokio::test]
async fn describe_and_missing_node_handling() {
    let h = harness().await;
    enroll_or_panic(&h, "n11").await;
    let operator = operator_client(&h, "fleet-admin");
    let described: fleet_proto::NodeSummary = operator
        .get(format!("https://{}/v1/nodes/n11", h.running.operator_addr))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(described.node_id, "n11");
    assert!(described.attestation_passed);

    let missing = operator
        .get(format!(
            "https://{}/v1/nodes/does-not-exist",
            h.running.operator_addr
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status().as_u16(), 404);
}

#[tokio::test]
async fn metrics_and_crl_are_served() {
    let h = harness().await;
    enroll_or_panic(&h, "n12").await;
    let operator = operator_client(&h, "fleet-admin");
    let metrics = operator
        .get(format!("https://{}/metrics", h.running.operator_addr))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(metrics.contains("fleet_enrollments_total 1"), "{metrics}");
    assert!(metrics.contains("fleet_cert_expiry_seconds{node=\"n12\"}"));
    assert!(metrics.contains("fleet_handshake_failures_total"));

    let node = enroll_or_panic(&h, "n13").await;
    let client = tls_client(&h.ca_pem, Some((&node.response.cert_pem, &node.key_pem)));
    let crl = client
        .get(format!("https://{}/v1/crl", h.running.mtls_addr))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(crl.contains("BEGIN X509 CRL"));
}

#[tokio::test]
async fn re_enrollment_with_a_fresh_token_rotates_the_serial() {
    let h = harness().await;
    let first = enroll_or_panic(&h, "n14").await;
    let second = enroll_or_panic(&h, "n14").await;
    assert_ne!(first.response.serial_hex, second.response.serial_hex);
    let nodes = list_nodes(&h).await;
    assert_eq!(nodes.count, 1);
    assert_eq!(
        nodes.nodes[0].serial_hex.as_deref(),
        Some(second.response.serial_hex.as_str())
    );
}

#[tokio::test]
async fn secure_boot_off_is_quarantined_without_a_certificate() {
    let h = harness().await;
    let token = issue_token(&h, "q1").await;
    let err = enroll_with(&h, "q1", &token, |blob| {
        blob.secure_boot.secure_boot = false;
    })
    .await
    .unwrap_err();
    assert!(err.contains("attestation_failed"), "{err}");
    assert!(err.contains("SecureBoot is disabled"), "{err}");

    let nodes = list_nodes(&h).await;
    assert_eq!(nodes.count, 1);
    let node = &nodes.nodes[0];
    assert_eq!(node.state, fleet_proto::NodeState::Quarantined);
    assert!(node.serial_hex.is_none());
    assert!(!node.attestation_passed);
    assert!(node.violations.iter().any(|v| v.contains("SecureBoot")));
    assert_eq!(node.vlan, Some(666));
}

#[tokio::test]
async fn forged_quote_and_log_mismatch_are_rejected() {
    use base64::Engine;
    let h = harness().await;

    let token = issue_token(&h, "q2").await;
    let err = enroll_with(&h, "q2", &token, |blob| {
        blob.quote.signature = base64::engine::general_purpose::STANDARD.encode([0u8; 8]);
    })
    .await
    .unwrap_err();
    assert!(err.contains("forged_quote"), "{err}");

    let token = issue_token(&h, "q3").await;
    let err = enroll_with(&h, "q3", &token, |blob| {
        for event in &mut blob.event_log {
            if event.pcr == 4 {
                event.digest = "11".repeat(32);
            }
        }
    })
    .await
    .unwrap_err();
    assert!(err.contains("log_quote_mismatch"), "{err}");
}

#[tokio::test]
async fn ak_certificate_from_a_foreign_ca_is_rejected() {
    let h = harness().await;
    let token = issue_token(&h, "q4").await;
    let mut foreign = Ca::init_root(CaConfig::default()).unwrap();
    let (_, csr, _) = generate_ak_keypair().unwrap();
    let foreign_ak = issue_ak_cert(&mut foreign, "q4", "dc1", &csr).unwrap();
    let err = enroll_with(&h, "q4", &token, |blob| {
        blob.ak_cert_pem = foreign_ak.clone();
    })
    .await
    .unwrap_err();
    assert!(err.contains("ak_chain_untrusted"), "{err}");
}

#[tokio::test]
async fn replayed_nonce_and_missing_challenge_fail_closed() {
    let h = harness().await;
    let token = issue_token(&h, "q5").await;
    let err = enroll_with(&h, "q5", &token, |blob| {
        blob.challenge = fleet_attest::fixtures::REPLAYED_NONCE.into();
    })
    .await
    .unwrap_err();
    assert!(err.contains("replayed_nonce"), "{err}");

    // Direct enrollment without requesting a challenge is refused.
    let token = issue_token(&h, "q6").await;
    let client = tls_client(&h.ca_pem, None);
    let keypair = NodeKeypair::new("q6", "dc1").unwrap();
    let mut ca = Ca::load(h._dir.path()).unwrap();
    let (_, ak_csr, ak_key) = generate_ak_keypair().unwrap();
    let ak_cert = issue_ak_cert(&mut ca, "q6", "dc1", &ak_csr).unwrap();
    let blob = build_blob(
        &ak_cert,
        &ak_key,
        &BlobOptions::good("q6", "dc1", Distro::Ubuntu, "aa"),
    )
    .unwrap();
    let response = client
        .post(format!("https://{}/v1/enroll", h.running.enroll_addr))
        .json(&EnrollRequest {
            token,
            node_id: "q6".into(),
            site: "dc1".into(),
            hostname: "q6".into(),
            csr_pem: keypair.csr_pem().to_string(),
            attestation: serde_json::to_value(&blob).unwrap(),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 403);
    let body = response.text().await.unwrap();
    assert!(body.contains("missing_challenge"), "{body}");
}

#[tokio::test]
async fn oidc_negative_cases_are_rejected() {
    let h = harness().await;
    let cases = [
        h.idp.sign_token(
            "eve",
            vec!["fleet-admin".into()],
            "fleetd",
            -3600,
            &h.idp.kid,
            None,
        ),
        h.idp.sign_token(
            "eve",
            vec!["fleet-admin".into()],
            "another-service",
            600,
            &h.idp.kid,
            None,
        ),
        h.idp.sign_token(
            "eve",
            vec!["fleet-admin".into()],
            "fleetd",
            600,
            "unknown-kid",
            None,
        ),
    ];
    for token in cases {
        let client = bearer_client(&h.ca_pem, &token);
        let response = client
            .get(format!("https://{}/v1/nodes", h.running.operator_addr))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 401);
    }

    let valid = h.idp.sign_token(
        "eve",
        vec!["fleet-admin".into()],
        "fleetd",
        600,
        &h.idp.kid,
        None,
    );
    let mut parts: Vec<String> = valid.split('.').map(str::to_string).collect();
    let mut sig = parts[2].clone().into_bytes();
    sig[0] = if sig[0] == b'A' { b'B' } else { b'A' };
    parts[2] = String::from_utf8(sig).unwrap();
    let client = bearer_client(&h.ca_pem, &parts.join("."));
    let response = client
        .get(format!("https://{}/v1/nodes", h.running.operator_addr))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 401);
}

#[tokio::test]
async fn operator_group_can_read_but_not_revoke() {
    let h = harness().await;
    enroll_or_panic(&h, "rbac1").await;
    let reader = operator_client(&h, "fleet-operator");
    let list = reader
        .get(format!("https://{}/v1/nodes", h.running.operator_addr))
        .send()
        .await
        .unwrap();
    assert_eq!(list.status().as_u16(), 200);

    let revoke = reader
        .post(format!(
            "https://{}/v1/nodes/rbac1/revoke",
            h.running.operator_addr
        ))
        .json(&fleet_proto::RevokeRequest {
            reason: "key_compromise".into(),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(revoke.status().as_u16(), 403);
    let body = revoke.text().await.unwrap();
    assert!(body.contains("insufficient_group"), "{body}");
}

#[tokio::test]
async fn operator_bearer_cannot_call_enrollment() {
    let h = harness().await;
    let token = h.idp.sign_token(
        "eve",
        vec!["fleet-admin".into()],
        "fleetd",
        600,
        &h.idp.kid,
        None,
    );
    let client = bearer_client(&h.ca_pem, &token);
    let response = client
        .post(format!("https://{}/v1/enroll", h.running.enroll_addr))
        .json(&serde_json::json!({
            "token": "irrelevant",
            "node_id": "x",
            "site": "dc1",
            "hostname": "x",
            "csr_pem": "irrelevant",
            "attestation": {}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 403);
    let body = response.text().await.unwrap();
    assert!(body.contains("operator_credential"), "{body}");
}

#[tokio::test]
async fn session_endpoint_returns_operator_groups() {
    let h = harness().await;
    let client = operator_client(&h, "fleet-operator");
    let session: serde_json::Value = client
        .get(format!(
            "https://{}/v1/auth/session",
            h.running.operator_addr
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(session["subject"], "operator@fleet.internal");
    assert!(session["groups"]
        .as_array()
        .unwrap()
        .iter()
        .any(|g| g == "fleet-operator"));
}

#[tokio::test]
async fn audit_log_records_enrollment_and_detects_tampering() {
    let h = harness().await;
    enroll_or_panic(&h, "audit1").await;
    let path = h._dir.path().join("audit.jsonl");
    let report = fleetd::audit::verify(&path).unwrap();
    assert!(report.valid);
    assert!(report.records >= 2, "enroll + vlan assignment expected");
    let contents = std::fs::read_to_string(&path).unwrap();
    assert!(contents.contains("\"action\":\"enroll\""));
    assert!(contents.contains("\"action\":\"vlan_assignment\""));

    let mut bytes = std::fs::read(&path).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0x01;
    std::fs::write(&path, bytes).unwrap();
    let report = fleetd::audit::verify(&path).unwrap();
    assert!(!report.valid);
    assert!(report.first_bad_seq.is_some());
}
