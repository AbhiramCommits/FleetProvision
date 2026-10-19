//! Benchmark harness. Every number written to results/ comes from these
//! measurements; nothing is hard-coded.

use crate::dot1x::{self, Dot1xOutcome};
use crate::e2e;
use crate::net;
use anyhow::Context;
use fleet_attest::{Policy, Verdict};
use fleet_pki::{Ca, CaConfig, LeafSpec, NodeKeypair};
use fleetd::agent::{self, EnrollConfig};
use fleetd::control::{start, ControlConfig};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tempfile::TempDir;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Latencies {
    pub count: usize,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub max_ms: f64,
}

fn latencies(mut values: Vec<f64>) -> Latencies {
    if values.is_empty() {
        return Latencies {
            count: 0,
            p50_ms: 0.0,
            p95_ms: 0.0,
            p99_ms: 0.0,
            max_ms: 0.0,
        };
    }
    values.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let at = |p: f64| {
        let idx = ((p / 100.0) * (values.len() - 1) as f64).round() as usize;
        values[idx.min(values.len() - 1)]
    };
    Latencies {
        count: values.len(),
        p50_ms: round2(at(50.0)),
        p95_ms: round2(at(95.0)),
        p99_ms: round2(at(99.0)),
        max_ms: round2(*values.last().unwrap()),
    }
}

fn round2(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaMetrics {
    pub certificates: usize,
    pub total_ms: f64,
    pub throughput_per_sec: f64,
    pub latency: Latencies,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MtlsMetrics {
    pub handshakes: usize,
    pub latency: Latencies,
    pub revoked_attempts: usize,
    pub revoked_latency: Latencies,
    pub rejected_handshakes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentMetrics {
    pub nodes: usize,
    pub wall_ms: u64,
    pub nodes_per_sec: f64,
    pub per_node_ms: Latencies,
    pub success_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationMetrics {
    pub evaluations: usize,
    pub latency: Latencies,
    pub fixtures_passed: usize,
    pub fixtures_failed: usize,
    pub pass_fail: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dot1xMetrics {
    pub authorized_vlan_100: usize,
    pub quarantined_vlan_666: usize,
    pub rejected: usize,
    pub latency: Latencies,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailureCheck {
    pub scenario: String,
    pub expected: String,
    pub observed: String,
    pub failed_closed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailureMetrics {
    pub scenarios: usize,
    pub failed_closed: usize,
    pub details: Vec<FailureCheck>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Totals {
    pub tests: usize,
    pub terraform_resources_planned: u64,
    pub modules_validated: u64,
    pub fixtures: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Machine {
    pub os: String,
    pub arch: String,
    pub cpu: String,
    pub rustc: String,
    pub terraform: String,
    pub packer: String,
    pub ansible_lint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metrics {
    pub generated_at: String,
    pub machine: Machine,
    pub ca_issuance: CaMetrics,
    pub mtls: MtlsMetrics,
    pub enrollment_20: EnrollmentMetrics,
    pub enrollment_100: EnrollmentMetrics,
    pub attestation: AttestationMetrics,
    pub provisioning_20: e2e::E2eReport,
    pub provisioning_100: e2e::E2eReport,
    pub dot1x: Dot1xMetrics,
    pub failure_injection: FailureMetrics,
    pub totals: Totals,
}

fn strip_ansi(value: &str) -> String {
    let mut out = String::new();
    let mut escape = false;
    for ch in value.chars() {
        if ch == '\x1b' {
            escape = true;
            continue;
        }
        if escape {
            if ch == 'm' {
                escape = false;
            }
            continue;
        }
        out.push(ch);
    }
    out.trim().to_string()
}

fn command_output(cmd: &str, args: &[&str]) -> String {
    Command::new(cmd)
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| strip_ansi(&String::from_utf8_lossy(&o.stdout)))
        .unwrap_or_else(|| "not installed".into())
}

fn machine() -> Machine {
    let cpu = if cfg!(target_os = "macos") {
        command_output("sysctl", &["-n", "machdep.cpu.brand_string"])
    } else {
        std::fs::read_to_string("/proc/cpuinfo")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("model name"))
                    .and_then(|l| l.split_once(':'))
                    .map(|(_, v)| v.trim().to_string())
            })
            .unwrap_or_else(|| "unknown".into())
    };
    Machine {
        os: command_output("uname", &["-sr"]),
        arch: std::env::consts::ARCH.into(),
        cpu,
        rustc: command_output("rustc", &["--version"]),
        terraform: command_output("terraform", &["version"]),
        packer: command_output(".tools/packer", &["version"]),
        ansible_lint: command_output("ansible-lint", &["--version"]),
    }
}

async fn ca_issuance() -> anyhow::Result<CaMetrics> {
    let mut ca = Ca::init_root(CaConfig::default())?;
    let mut samples = Vec::with_capacity(1000);
    let started = Instant::now();
    for i in 0..1000 {
        let node = format!("bench-ca-{i}");
        let key = NodeKeypair::new(&node, "dc1")?;
        let spec = LeafSpec::for_node("dc1", node).with_csr(key.csr_pem().to_string());
        let t = Instant::now();
        ca.issue_leaf(&spec)?;
        samples.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    let total_ms = started.elapsed().as_secs_f64() * 1000.0;
    Ok(CaMetrics {
        certificates: samples.len(),
        total_ms: round2(total_ms),
        throughput_per_sec: round2(samples.len() as f64 / (total_ms / 1000.0)),
        latency: latencies(samples),
    })
}

async fn mtls_measurements() -> anyhow::Result<MtlsMetrics> {
    let dir = TempDir::new()?;
    let state = dir.path().join("state");
    std::fs::create_dir_all(&state)?;
    let mut ca = Ca::init_root(CaConfig::default())?;
    ca.save(&state)?;
    let trust = ca.trust_bundle_pem();
    let ca_path = dir.path().join("ca.pem");
    std::fs::write(&ca_path, &trust)?;
    let idp = fleetd::idp::start().await?;
    let running = start(ControlConfig {
        state_dir: state.clone(),
        listen: "127.0.0.1:0".parse()?,
        enroll_listen: "127.0.0.1:0".parse()?,
        operator_listen: "127.0.0.1:0".parse()?,
        token_key: None,
        site: "dc1".into(),
        policy: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../policy/boot-integrity.yaml"),
        oidc_issuer: idp.issuer.clone(),
        oidc_audience: "fleetd".into(),
        public_url: "https://127.0.0.1:8443".into(),
    })
    .await?;
    let token = {
        let mut store = running.state.store.lock().await;
        let (token, _) = store.tokens.issue("bench-node", "dc1", 900);
        store.tokens.save()?;
        token
    };
    let agent_dir = dir.path().join("agent");
    agent::enroll(&EnrollConfig {
        control_plane: format!("https://{}", running.mtls_addr),
        enroll_url: format!("https://{}", running.enroll_addr),
        state_dir: agent_dir.clone(),
        token,
        node_id: "bench-node".into(),
        site: "dc1".into(),
        hostname: "bench-node".into(),
        ca_bundle: ca_path.clone(),
        distro: fleet_attest::Distro::Ubuntu,
    })
    .await?;
    let cert = std::fs::read_to_string(agent_dir.join("node/node.crt.pem"))?;
    let key = std::fs::read_to_string(agent_dir.join("node/node.key.pem"))?;

    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(trust.as_bytes())?)
        .identity(reqwest::Identity::from_pem(
            format!("{cert}{key}").as_bytes(),
        )?)
        .pool_max_idle_per_host(0)
        .build()?;
    let url = format!("https://{}/healthz", running.mtls_addr);
    let mut samples = Vec::with_capacity(500);
    for _ in 0..500 {
        let t = Instant::now();
        let response = client.get(&url).send().await?;
        response.error_for_status()?;
        samples.push(t.elapsed().as_secs_f64() * 1000.0);
    }

    let admin = idp.sign_token(
        "bench-admin",
        vec!["fleet-admin".into()],
        "fleetd",
        600,
        &idp.kid,
        None,
    );
    let operator = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(trust.as_bytes())?)
        .build()?;
    operator
        .post(format!(
            "https://{}/v1/nodes/bench-node/revoke",
            running.operator_addr
        ))
        .bearer_auth(admin)
        .json(&serde_json::json!({"reason": "key_compromise"}))
        .send()
        .await?
        .error_for_status()?;

    let revoked_client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(trust.as_bytes())?)
        .identity(reqwest::Identity::from_pem(
            format!("{cert}{key}").as_bytes(),
        )?)
        .pool_max_idle_per_host(0)
        .build()?;
    let mut rejected = Vec::with_capacity(100);
    for _ in 0..100 {
        let t = Instant::now();
        let result = revoked_client.get(&url).send().await;
        rejected.push(t.elapsed().as_secs_f64() * 1000.0);
        if result.is_ok() {
            anyhow::bail!("revoked certificate was accepted during benchmark");
        }
    }
    let rejected_count = running.state.metrics.handshake_failures_total() as usize;
    running.shutdown().await;
    idp.shutdown().await;
    Ok(MtlsMetrics {
        handshakes: samples.len(),
        latency: latencies(samples),
        revoked_attempts: rejected.len(),
        revoked_latency: latencies(rejected),
        rejected_handshakes: rejected_count,
    })
}

async fn enrollment(nodes: usize) -> anyhow::Result<EnrollmentMetrics> {
    let report = e2e::run(nodes).await?;
    let per_node: Vec<f64> = report
        .per_node
        .iter()
        .map(|n| n.total_millis as f64)
        .collect();
    Ok(EnrollmentMetrics {
        nodes,
        wall_ms: report.wall_millis,
        nodes_per_sec: round2(nodes as f64 / (report.wall_millis as f64 / 1000.0)),
        per_node_ms: latencies(per_node),
        success_count: report.success_count,
    })
}

fn attestation() -> anyhow::Result<AttestationMetrics> {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let policy = Policy::load(repo.join("policy/boot-integrity.yaml"))?;
    let ca = std::fs::read_to_string(repo.join("fixtures/ca.pem"))?;
    let good: fleet_attest::AttestationBlob =
        serde_json::from_slice(&std::fs::read(repo.join("fixtures/ubuntu-good.json"))?)?;
    let mut samples = Vec::with_capacity(1000);
    for _ in 0..1000 {
        let t = Instant::now();
        let verdict = policy.evaluate_with_ca(&good, &ca);
        samples.push(t.elapsed().as_secs_f64() * 1000.0);
        if !verdict.is_pass() {
            anyhow::bail!("good fixture failed during benchmark");
        }
    }
    let mut pass_fail = BTreeMap::new();
    let mut passed = 0;
    let mut failed = 0;
    for entry in std::fs::read_dir(repo.join("fixtures"))? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let blob: fleet_attest::AttestationBlob = serde_json::from_slice(&std::fs::read(&path)?)?;
        let verdict = policy.evaluate_with_ca(&blob, &ca);
        let label = match &verdict {
            Verdict::Pass => {
                passed += 1;
                "PASS".to_string()
            }
            Verdict::Fail(violations) => {
                failed += 1;
                violations
                    .iter()
                    .map(|v| v.code())
                    .collect::<Vec<_>>()
                    .join(",")
            }
        };
        pass_fail.insert(
            path.file_name().unwrap().to_string_lossy().to_string(),
            label,
        );
    }
    Ok(AttestationMetrics {
        evaluations: samples.len(),
        latency: latencies(samples),
        fixtures_passed: passed,
        fixtures_failed: failed,
        pass_fail,
    })
}

async fn dot1x_metrics() -> anyhow::Result<Dot1xMetrics> {
    let mut ca = Ca::init_root(CaConfig::default())?;
    let pass = ca.issue_leaf(&LeafSpec::for_node("dc1", "pass"))?;
    let quarantine = ca.issue_leaf(&LeafSpec::for_node("dc1", "quarantine"))?;
    let revoked = ca.issue_leaf(&LeafSpec::for_node("dc1", "revoked"))?;
    ca.revoke(&revoked.serial_hex, "key_compromise")?;

    let mut attestations = std::collections::HashMap::new();
    attestations.insert("pass".to_string(), true);
    attestations.insert("quarantine".to_string(), false);
    attestations.insert("revoked".to_string(), true);
    let server = dot1x::start(dot1x::Dot1xConfig {
        ca_pem: ca.trust_bundle_pem(),
        crl: Arc::new(RwLock::new(ca.crl_store()?)),
        attestations: Arc::new(RwLock::new(attestations)),
        clock_offset_seconds: 0,
        audit: None,
    })
    .await?;

    let mut samples = Vec::new();
    let mut authorized = 0;
    let mut quarantined = 0;
    let mut rejected = 0;
    for (node, leaf) in [
        ("pass", &pass),
        ("quarantine", &quarantine),
        ("revoked", &revoked),
    ] {
        let t = Instant::now();
        let outcome = dot1x::authenticate(
            server.addr,
            node,
            &leaf.cert_pem,
            leaf.key_pem.as_deref().unwrap(),
        )
        .await?;
        samples.push(t.elapsed().as_secs_f64() * 1000.0);
        match outcome {
            Dot1xOutcome::Authorized { vlan } if vlan == dot1x::VLAN_PROD => authorized += 1,
            Dot1xOutcome::Authorized { .. } => quarantined += 1,
            Dot1xOutcome::Rejected { .. } => rejected += 1,
        }
    }
    server.shutdown().await;
    Ok(Dot1xMetrics {
        authorized_vlan_100: authorized,
        quarantined_vlan_666: quarantined,
        rejected,
        latency: latencies(samples),
    })
}

async fn failure_scenarios() -> anyhow::Result<FailureMetrics> {
    let mut details = Vec::new();

    let dhcp = net::start_dhcp(net::DhcpConfig::default()).await?;
    let result = net::dhcp_acquire(dhcp.addr, "52:54:00:00:00:99").await;
    dhcp.shutdown().await;
    let observed = match &result {
        Err(err) => err.to_string(),
        Ok(_) => "accepted unknown MAC".into(),
    };
    details.push(FailureCheck {
        scenario: "dhcp unknown MAC".into(),
        expected: "NAK".into(),
        failed_closed: matches!(result, Err(net::NetError::Nak(_))),
        observed,
    });

    let dir = TempDir::new()?;
    std::fs::write(dir.path().join("boot.ipxe"), "#!ipxe\n")?;
    let tftp = net::start_tftp(dir.path().to_path_buf()).await?;
    let result = net::tftp_get(tftp.addr, "missing.ipxe").await;
    tftp.shutdown().await;
    let observed = match &result {
        Err(err) => err.to_string(),
        Ok(_) => "served missing file".into(),
    };
    details.push(FailureCheck {
        scenario: "tftp file not found".into(),
        expected: "ERROR code 1".into(),
        failed_closed: matches!(result, Err(net::NetError::FileNotFound(_))),
        observed,
    });

    let http = net::start_http(dir.path().to_path_buf()).await?;
    let result = net::http_get(http.addr, "/kickstart/missing.ks").await;
    http.shutdown().await;
    let observed = match &result {
        Err(err) => err.to_string(),
        Ok(_) => "served missing kickstart".into(),
    };
    details.push(FailureCheck {
        scenario: "http 404 kickstart".into(),
        expected: "404".into(),
        failed_closed: matches!(result, Err(net::NetError::Http { status: 404, .. })),
        observed,
    });

    // Truncated TLS handshake: write a partial ClientHello and close.
    let state = dir.path().join("tls-state");
    std::fs::create_dir_all(&state)?;
    let mut ca = Ca::init_root(CaConfig::default())?;
    ca.save(&state)?;
    let idp = fleetd::idp::start().await?;
    let running = start(ControlConfig {
        state_dir: state,
        listen: "127.0.0.1:0".parse()?,
        enroll_listen: "127.0.0.1:0".parse()?,
        operator_listen: "127.0.0.1:0".parse()?,
        token_key: None,
        site: "dc1".into(),
        policy: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../policy/boot-integrity.yaml"),
        oidc_issuer: idp.issuer.clone(),
        oidc_audience: "fleetd".into(),
        public_url: "https://127.0.0.1:8443".into(),
    })
    .await?;
    use tokio::io::AsyncWriteExt;
    let mut socket = tokio::net::TcpStream::connect(running.mtls_addr).await?;
    socket
        .write_all(&[0x16, 0x03, 0x01, 0x00, 0x20, 0x01])
        .await?;
    socket.shutdown().await?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let health = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(running.ca_pem.as_bytes())?)
        .build()?
        .get(format!("https://{}/healthz", running.enroll_addr))
        .send()
        .await;
    let failures = running.state.metrics.handshake_failures_total();
    running.shutdown().await;
    idp.shutdown().await;
    details.push(FailureCheck {
        scenario: "truncated TLS handshake".into(),
        expected: "server stays up and counts a handshake failure".into(),
        observed: format!(
            "healthz_ok={} handshake_failures={failures}",
            health
                .as_ref()
                .map(|r| r.status().is_success())
                .unwrap_or(false)
        ),
        failed_closed: health.map(|r| r.status().is_success()).unwrap_or(false) && failures >= 1,
    });

    // Expired CRL.
    let mut ca = Ca::init_root(CaConfig::default())?;
    let leaf = ca.issue_leaf(&LeafSpec::for_node("dc1", "expired-crl"))?;
    ca.issue_crl_window(-2, -1)?;
    let mut attestations = std::collections::HashMap::new();
    attestations.insert("expired-crl".to_string(), true);
    let server = dot1x::start(dot1x::Dot1xConfig {
        ca_pem: ca.trust_bundle_pem(),
        crl: Arc::new(RwLock::new(ca.crl_store()?)),
        attestations: Arc::new(RwLock::new(attestations)),
        clock_offset_seconds: 0,
        audit: None,
    })
    .await?;
    let outcome = dot1x::authenticate(
        server.addr,
        "expired-crl",
        &leaf.cert_pem,
        leaf.key_pem.as_deref().unwrap(),
    )
    .await?;
    server.shutdown().await;
    details.push(FailureCheck {
        scenario: "expired CRL".into(),
        expected: "stale_crl rejection".into(),
        observed: format!("{outcome:?}"),
        failed_closed: outcome
            == Dot1xOutcome::Rejected {
                reason: "stale_crl".into(),
            },
    });

    // Revoked supplicant.
    let mut ca = Ca::init_root(CaConfig::default())?;
    let leaf = ca.issue_leaf(&LeafSpec::for_node("dc1", "revoked"))?;
    ca.revoke(&leaf.serial_hex, "key_compromise")?;
    let mut attestations = std::collections::HashMap::new();
    attestations.insert("revoked".to_string(), true);
    let server = dot1x::start(dot1x::Dot1xConfig {
        ca_pem: ca.trust_bundle_pem(),
        crl: Arc::new(RwLock::new(ca.crl_store()?)),
        attestations: Arc::new(RwLock::new(attestations)),
        clock_offset_seconds: 0,
        audit: None,
    })
    .await?;
    let outcome = dot1x::authenticate(
        server.addr,
        "revoked",
        &leaf.cert_pem,
        leaf.key_pem.as_deref().unwrap(),
    )
    .await?;
    server.shutdown().await;
    details.push(FailureCheck {
        scenario: "revoked supplicant".into(),
        expected: "revoked rejection".into(),
        observed: format!("{outcome:?}"),
        failed_closed: outcome
            == Dot1xOutcome::Rejected {
                reason: "revoked".into(),
            },
    });

    let failed_closed = details.iter().filter(|d| d.failed_closed).count();
    Ok(FailureMetrics {
        scenarios: details.len(),
        failed_closed,
        details,
    })
}

fn tests_count() -> usize {
    let output = Command::new("cargo")
        .args(["test", "--workspace", "--", "--list"])
        .output();
    match output {
        Ok(output) => String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter(|line| line.ends_with(": test"))
            .count(),
        Err(_) => 0,
    }
}

fn read_plan_counts() -> anyhow::Result<(u64, u64)> {
    let path = Path::new("results/iac-plan-counts.json");
    let raw = std::fs::read_to_string(path).with_context(|| {
        format!(
            "missing {}; run `make iac-validate` before `make bench`",
            path.display()
        )
    })?;
    #[derive(Deserialize)]
    struct Counts {
        resources_planned: u64,
        modules_validated: u64,
    }
    let counts: Counts = serde_json::from_str(&raw)?;
    Ok((counts.resources_planned, counts.modules_validated))
}

pub async fn run(out_dir: &Path) -> anyhow::Result<Metrics> {
    println!("bench: CA issuance");
    let ca_issuance = ca_issuance().await?;
    println!(
        "  {} certs at {:.1}/s, p50 {:.2} ms",
        ca_issuance.certificates, ca_issuance.throughput_per_sec, ca_issuance.latency.p50_ms
    );

    println!("bench: mTLS handshakes");
    let mtls = mtls_measurements().await?;
    println!(
        "  {} handshakes p50 {:.2} ms; {} revoked attempts",
        mtls.handshakes, mtls.latency.p50_ms, mtls.revoked_attempts
    );

    println!("bench: enrollment at 20 nodes");
    let enrollment_20 = enrollment(20).await?;
    println!("bench: enrollment at 100 nodes");
    let enrollment_100 = enrollment(100).await?;

    println!("bench: attestation evaluation");
    let attestation = attestation()?;

    println!("bench: 802.1X outcomes");
    let dot1x = dot1x_metrics().await?;

    println!("bench: failure injection");
    let failure_injection = failure_scenarios().await?;

    let (resources, modules) = read_plan_counts()?;
    let attestation_count = attestation.pass_fail.len();
    let metrics = Metrics {
        generated_at: time::OffsetDateTime::now_utc().to_string(),
        machine: machine(),
        ca_issuance,
        mtls,
        enrollment_20,
        enrollment_100,
        attestation,
        provisioning_20: e2e::run(20).await?,
        provisioning_100: e2e::run(100).await?,
        dot1x,
        failure_injection,
        totals: Totals {
            tests: tests_count(),
            terraform_resources_planned: resources,
            modules_validated: modules,
            fixtures: attestation_count,
        },
    };
    std::fs::create_dir_all(out_dir)?;
    std::fs::write(
        out_dir.join("metrics.json"),
        serde_json::to_vec_pretty(&metrics)?,
    )?;
    std::fs::write(out_dir.join("REPORT.md"), report(&metrics))?;
    Ok(metrics)
}

pub fn report(m: &Metrics) -> String {
    let mut out = String::new();
    out.push_str("# FleetProvision benchmark report\n\n");
    out.push_str(&format!("Generated: {}\n\n", m.generated_at));
    out.push_str("## Machine\n\n");
    out.push_str(&format!(
        "| OS | CPU | Rust | Terraform | Packer | ansible-lint |\n|---|---|---|---|---|---|\n| {} | {} | {} | {} | {} | {} |\n\n",
        m.machine.os,
        m.machine.cpu,
        m.machine.rustc,
        first_line(&m.machine.terraform),
        first_line(&m.machine.packer),
        first_line(&m.machine.ansible_lint)
    ));
    out.push_str("## CA issuance\n\n");
    out.push_str("| certs | throughput | p50 | p95 | p99 | max |\n|---|---|---|---|---|---|\n");
    out.push_str(&format!(
        "| {} | {:.1}/s | {:.2} ms | {:.2} ms | {:.2} ms | {:.2} ms |\n\n",
        m.ca_issuance.certificates,
        m.ca_issuance.throughput_per_sec,
        m.ca_issuance.latency.p50_ms,
        m.ca_issuance.latency.p95_ms,
        m.ca_issuance.latency.p99_ms,
        m.ca_issuance.latency.max_ms
    ));
    out.push_str("## mTLS\n\n");
    out.push_str("| handshakes | p50 | p95 | revoked attempts | rejection p50 | rejection p95 | handshake failures |\n|---|---|---|---|---|---|---|\n");
    out.push_str(&format!(
        "| {} | {:.2} ms | {:.2} ms | {} | {:.2} ms | {:.2} ms | {} |\n\n",
        m.mtls.handshakes,
        m.mtls.latency.p50_ms,
        m.mtls.latency.p95_ms,
        m.mtls.revoked_attempts,
        m.mtls.revoked_latency.p50_ms,
        m.mtls.revoked_latency.p95_ms,
        m.mtls.rejected_handshakes
    ));
    out.push_str("## Enrollment\n\n");
    out.push_str(
        "| nodes | success | wall | nodes/sec | per-node p50 | p95 |\n|---|---|---|---|---|---|\n",
    );
    for e in [&m.enrollment_20, &m.enrollment_100] {
        out.push_str(&format!(
            "| {} | {} | {} ms | {:.1} | {:.1} ms | {:.1} ms |\n",
            e.nodes,
            e.success_count,
            e.wall_ms,
            e.nodes_per_sec,
            e.per_node_ms.p50_ms,
            e.per_node_ms.p95_ms
        ));
    }
    out.push_str("\n## Attestation policy\n\n");
    out.push_str(&format!(
        "{} evaluations, p50 {:.3} ms, p95 {:.3} ms. Fixtures: {} pass, {} fail.\n\n",
        m.attestation.evaluations,
        m.attestation.latency.p50_ms,
        m.attestation.latency.p95_ms,
        m.attestation.fixtures_passed,
        m.attestation.fixtures_failed
    ));
    out.push_str("| fixture | verdict |\n|---|---|\n");
    for (fixture, verdict) in &m.attestation.pass_fail {
        out.push_str(&format!("| {fixture} | {verdict} |\n"));
    }
    out.push_str("\n## Provisioning simulation\n\n");
    out.push_str("| nodes | success | wall | VLAN100 | VLAN666 | rejected | boot-to-enrolled p50 | p95 |\n|---|---|---|---|---|---|---|---|\n");
    for e in [&m.provisioning_20, &m.provisioning_100] {
        let times: Vec<u64> = e.per_node.iter().map(|n| n.total_millis).collect();
        out.push_str(&format!(
            "| {} | {} | {} ms | {} | {} | {} | {} ms | {} ms |\n",
            e.nodes_requested,
            e.success_count,
            e.wall_millis,
            e.vlan_100,
            e.vlan_666,
            e.rejected,
            e2e::percentile(&times, 50.0),
            e2e::percentile(&times, 95.0)
        ));
    }
    out.push_str("\n## 802.1X outcomes\n\n");
    out.push_str(&format!(
        "VLAN 100: {}, VLAN 666: {}, rejected: {} (p50 {:.2} ms).\n\n",
        m.dot1x.authorized_vlan_100,
        m.dot1x.quarantined_vlan_666,
        m.dot1x.rejected,
        m.dot1x.latency.p50_ms
    ));
    out.push_str("## Failure injection\n\n");
    out.push_str(&format!(
        "{} of {} deliberate failures failed closed.\n\n",
        m.failure_injection.failed_closed, m.failure_injection.scenarios
    ));
    out.push_str("| scenario | expected | observed | failed closed |\n|---|---|---|---|\n");
    for d in &m.failure_injection.details {
        out.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            d.scenario, d.expected, d.observed, d.failed_closed
        ));
    }
    out.push_str("\n## Totals\n\n");
    out.push_str(&format!(
        "* Tests: {}\n* Terraform resources planned: {}\n* Modules/environments validated: {}\n* Attestation fixtures: {}\n",
        m.totals.tests, m.totals.terraform_resources_planned, m.totals.modules_validated, m.totals.fixtures
    ));
    out
}

fn first_line(value: &str) -> String {
    value.lines().next().unwrap_or(value).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latency_percentiles_are_ordered() {
        let values = (1..=100).map(|v| v as f64).collect();
        let l = latencies(values);
        assert_eq!(l.count, 100);
        assert!(l.p50_ms <= l.p95_ms);
        assert!(l.p95_ms <= l.p99_ms);
        assert_eq!(l.p99_ms, 99.0);
    }

    #[test]
    fn empty_latency_is_zero_not_nan() {
        let l = latencies(Vec::new());
        assert_eq!(l.count, 0);
        assert_eq!(l.p50_ms, 0.0);
    }
}
