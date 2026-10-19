//! End-to-end provisioning simulation over real sockets.
//!
//! For each node: DHCP -> TFTP iPXE -> HTTP Kickstart/cloud-init + token ->
//! HTTPS attestation and enrollment against an in-process fleetd -> 802.1X
//! authorization. All timing is measured with `Instant`.

use crate::dot1x::{self, Dot1xOutcome};
use crate::net;
use crate::render;
use anyhow::Context;
use fleet_attest::Distro;
use fleet_pki::{Ca, CaConfig};
use fleetd::control::{start, ControlConfig};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Instant;
use tempfile::TempDir;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageTiming {
    pub stage: String,
    pub millis: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRun {
    pub node_id: String,
    pub mac: String,
    pub distro: String,
    pub success: bool,
    pub total_millis: u64,
    pub vlan: Option<u16>,
    pub stages: Vec<StageTiming>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2eReport {
    pub nodes_requested: usize,
    pub success_count: usize,
    pub failure_count: usize,
    pub vlan_100: usize,
    pub vlan_666: usize,
    pub rejected: usize,
    pub wall_millis: u64,
    pub per_node: Vec<NodeRun>,
}

fn policy_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../policy/boot-integrity.yaml")
}

pub async fn run(nodes: usize) -> anyhow::Result<E2eReport> {
    if nodes == 0 || nodes > 200 {
        anyhow::bail!("nodes must be between 1 and 200");
    }
    let wall = Instant::now();
    let dir = TempDir::new()?;
    let state_dir = dir.path().join("state");
    std::fs::create_dir_all(&state_dir)?;
    let mut ca = Ca::init_root(CaConfig::default())?;
    ca.save(&state_dir)?;
    let ca_pem = ca.trust_bundle_pem();
    let ca_path = dir.path().join("ca.pem");
    std::fs::write(&ca_path, &ca_pem)?;

    let idp = fleetd::idp::start().await?;
    let running = start(ControlConfig {
        state_dir: state_dir.clone(),
        listen: "127.0.0.1:0".parse()?,
        enroll_listen: "127.0.0.1:0".parse()?,
        operator_listen: "127.0.0.1:0".parse()?,
        token_key: None,
        site: "dc1".into(),
        policy: policy_path(),
        oidc_issuer: idp.issuer.clone(),
        oidc_audience: "fleetd".into(),
    })
    .await
    .context("starting in-process fleetd")?;

    let inventory = build_inventory(nodes);
    let token_dir = dir.path().join("tokens");
    std::fs::create_dir_all(&token_dir)?;
    {
        let mut store = running.state.store.lock().await;
        for node in &inventory.nodes {
            let (token, _) = store.tokens.issue(&node.id, "dc1", 900);
            std::fs::write(token_dir.join(format!("{}.token", node.id)), token)?;
        }
        store.tokens.save()?;
    }

    let pxe_dir = dir.path().join("pxe");
    render::render(&inventory, &pxe_dir, &token_dir, &ca_path)?;
    std::fs::write(pxe_dir.join("ca.pem"), &ca_pem)?;
    let tftp_root = dir.path().join("tftp");
    std::fs::create_dir_all(&tftp_root)?;
    std::fs::copy(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../provisioning/ipxe/boot.ipxe"),
        tftp_root.join("boot.ipxe"),
    )?;

    let mut dhcp_config = net::DhcpConfig::default();
    let mut dns_records = HashMap::new();
    for (idx, node) in inventory.nodes.iter().enumerate() {
        let ip = Ipv4Addr::new(192, 168, 50, 10 + idx as u8);
        dhcp_config.leases.insert(
            node.mac.to_ascii_lowercase(),
            net::Lease {
                ip,
                filename: "boot.ipxe".into(),
                hostname: node.id.clone(),
            },
        );
        dns_records.insert(format!("{}.fleet.internal", node.id), ip);
    }

    let dhcp = net::start_dhcp(dhcp_config).await?;
    let tftp = net::start_tftp(tftp_root).await?;
    let http = net::start_http(pxe_dir).await?;
    let dns = net::start_dns(dns_records).await?;

    let attestations: Arc<RwLock<HashMap<String, bool>>> = Arc::new(RwLock::new(HashMap::new()));
    let dot1x = dot1x::start(dot1x::Dot1xConfig {
        ca_pem: ca_pem.clone(),
        crl: running.state.crl.clone(),
        attestations: attestations.clone(),
        clock_offset_seconds: 0,
        audit: Some(running.state.audit.clone()),
    })
    .await?;

    let mtls_url = format!("https://{}", running.mtls_addr);
    let enroll_url = format!("https://{}", running.enroll_addr);
    let mut set = tokio::task::JoinSet::new();
    for node in inventory.nodes.clone() {
        let enroll_url = enroll_url.clone();
        let mtls_url = mtls_url.clone();
        let ca_path = ca_path.clone();
        let token = std::fs::read_to_string(token_dir.join(format!("{}.token", node.id)))?;
        let agents_root = dir.path().join("agents");
        let dns_addr = dns.addr;
        let dhcp_addr = dhcp.addr;
        let tftp_addr = tftp.addr;
        let http_addr = http.addr;
        let dot1x_addr = dot1x.addr;
        let attestations = attestations.clone();
        set.spawn(async move {
            run_node(
                node,
                token.trim(),
                dhcp_addr,
                tftp_addr,
                http_addr,
                dns_addr,
                dot1x_addr,
                &mtls_url,
                &enroll_url,
                &ca_path,
                &agents_root,
                attestations,
            )
            .await
        });
    }

    let mut per_node = Vec::new();
    while let Some(joined) = set.join_next().await {
        match joined {
            Ok(node) => per_node.push(node),
            Err(err) => {
                per_node.push(NodeRun {
                    node_id: "unknown".into(),
                    mac: String::new(),
                    distro: String::new(),
                    success: false,
                    total_millis: 0,
                    vlan: None,
                    stages: Vec::new(),
                    error: Some(err.to_string()),
                });
            }
        }
    }
    per_node.sort_by(|a, b| a.node_id.cmp(&b.node_id));

    let success_count = per_node.iter().filter(|n| n.success).count();
    let vlan_100 = per_node
        .iter()
        .filter(|n| n.vlan == Some(dot1x::VLAN_PROD))
        .count();
    let vlan_666 = per_node
        .iter()
        .filter(|n| n.vlan == Some(dot1x::VLAN_QUARANTINE))
        .count();
    let rejected = per_node
        .iter()
        .filter(|n| n.error.as_deref().is_some_and(|e| e.contains("Rejected")))
        .count();

    dot1x.shutdown().await;
    dns.shutdown().await;
    http.shutdown().await;
    tftp.shutdown().await;
    dhcp.shutdown().await;
    running.shutdown().await;
    idp.shutdown().await;

    Ok(E2eReport {
        nodes_requested: nodes,
        success_count,
        failure_count: nodes - success_count,
        vlan_100,
        vlan_666,
        rejected,
        wall_millis: wall.elapsed().as_millis() as u64,
        per_node,
    })
}

#[allow(clippy::too_many_arguments)]
async fn run_node(
    node: render::InventoryNode,
    token: &str,
    dhcp_addr: std::net::SocketAddr,
    tftp_addr: std::net::SocketAddr,
    http_addr: std::net::SocketAddr,
    dns_addr: std::net::SocketAddr,
    dot1x_addr: std::net::SocketAddr,
    mtls_url: &str,
    enroll_url: &str,
    ca_path: &Path,
    agents_root: &Path,
    attestations: Arc<RwLock<HashMap<String, bool>>>,
) -> NodeRun {
    let started = Instant::now();
    let mut stages = Vec::new();

    let stage_start = Instant::now();
    let lease = match net::dhcp_acquire(dhcp_addr, &node.mac).await {
        Ok(lease) => lease,
        Err(err) => return failed(&node, started, stages, err.to_string()),
    };
    push_stage(&mut stages, "dhcp", stage_start);

    let stage_start = Instant::now();
    if let Err(err) = net::tftp_get(tftp_addr, "boot.ipxe").await {
        return failed(&node, started, stages, err.to_string());
    }
    push_stage(&mut stages, "tftp", stage_start);

    let stage_start = Instant::now();
    if let Err(err) = net::http_get(
        http_addr,
        &format!("/ipxe/{}.ipxe", render::mac_hyphen(&node.mac)),
    )
    .await
    {
        return failed(&node, started, stages, err.to_string());
    }
    if let Err(err) = net::http_get(http_addr, &format!("/boot/{}", node.id)).await {
        return failed(&node, started, stages, err.to_string());
    }
    if let Err(err) = net::http_get(http_addr, &format!("/tokens/{}.token", node.id)).await {
        return failed(&node, started, stages, err.to_string());
    }
    push_stage(&mut stages, "http", stage_start);

    let stage_start = Instant::now();
    if let Err(err) = net::dns_lookup(dns_addr, &format!("{}.fleet.internal", node.id)).await {
        return failed(&node, started, stages, err.to_string());
    }
    push_stage(&mut stages, "dns", stage_start);

    let distro = if node.distro == "fedora" {
        Distro::Fedora
    } else {
        Distro::Ubuntu
    };
    let agent_dir = agents_root.join(&node.id);
    let stage_start = Instant::now();
    let enrolled = match fleetd::agent::enroll(&fleetd::agent::EnrollConfig {
        control_plane: mtls_url.to_string(),
        enroll_url: enroll_url.to_string(),
        state_dir: agent_dir.clone(),
        token: token.to_string(),
        node_id: node.id.clone(),
        site: "dc1".into(),
        hostname: node.id.clone(),
        ca_bundle: ca_path.to_path_buf(),
        distro,
    })
    .await
    {
        Ok(enrolled) => enrolled,
        Err(err) => return failed(&node, started, stages, err.to_string()),
    };
    push_stage(&mut stages, "attest+enroll", stage_start);
    attestations
        .write()
        .expect("attestation lock poisoned")
        .insert(node.id.clone(), true);

    let cert = match std::fs::read_to_string(agent_dir.join("node/node.crt.pem")) {
        Ok(cert) => cert,
        Err(err) => return failed(&node, started, stages, err.to_string()),
    };
    let key = match std::fs::read_to_string(agent_dir.join("node/node.key.pem")) {
        Ok(key) => key,
        Err(err) => return failed(&node, started, stages, err.to_string()),
    };
    let stage_start = Instant::now();
    let outcome = match dot1x::authenticate(dot1x_addr, &node.id, &cert, &key).await {
        Ok(outcome) => outcome,
        Err(err) => return failed(&node, started, stages, err.to_string()),
    };
    push_stage(&mut stages, "802.1x", stage_start);

    let vlan = match outcome {
        Dot1xOutcome::Authorized { vlan } => Some(vlan),
        Dot1xOutcome::Rejected { reason } => {
            return failed(&node, started, stages, format!("802.1X Rejected: {reason}"))
        }
    };
    let _ = enrolled;
    let _ = lease;
    NodeRun {
        node_id: node.id,
        mac: node.mac,
        distro: node.distro,
        success: true,
        total_millis: started.elapsed().as_millis() as u64,
        vlan,
        stages,
        error: None,
    }
}

fn push_stage(stages: &mut Vec<StageTiming>, name: &str, at: Instant) {
    stages.push(StageTiming {
        stage: name.into(),
        millis: at.elapsed().as_millis() as u64,
    });
}

fn failed(
    node: &render::InventoryNode,
    started: Instant,
    stages: Vec<StageTiming>,
    error: String,
) -> NodeRun {
    NodeRun {
        node_id: node.id.clone(),
        mac: node.mac.clone(),
        distro: node.distro.clone(),
        success: false,
        total_millis: started.elapsed().as_millis() as u64,
        vlan: None,
        stages,
        error: Some(error),
    }
}

fn build_inventory(nodes: usize) -> render::Inventory {
    let nodes = (0..nodes)
        .map(|i| {
            let idx = i as u8 + 1;
            render::InventoryNode {
                id: format!("rack-a-node-{idx:03}"),
                mac: format!("52:54:00:aa:bb:{idx:02x}"),
                distro: if i % 2 == 0 { "ubuntu" } else { "fedora" }.into(),
                vlan: 100,
                role: "worker".into(),
            }
        })
        .collect();
    render::Inventory {
        site: "dc1".into(),
        api: "https://fleetd.fleet.internal:8443".into(),
        enroll_url: "https://fleetd.fleet.internal:8444".into(),
        tftp_server: "192.168.50.2".into(),
        http_server: "http://192.168.50.2:8080".into(),
        https_server: "https://192.168.50.2:8443".into(),
        token_url: "https://192.168.50.2:8443/tokens".into(),
        nodes,
    }
}

pub fn percentile(values: &[u64], p: f64) -> u64 {
    if values.is_empty() {
        return 0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let idx = ((p / 100.0) * (sorted.len() - 1) as f64).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

pub fn write_report(report: &E2eReport, out_dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(out_dir)?;
    std::fs::write(out_dir.join("e2e.json"), serde_json::to_vec_pretty(report)?)?;
    let mut text = String::new();
    text.push_str("# FleetProvision provisioning e2e\n\n");
    text.push_str(&format!(
        "Generated {} on {}. {} nodes requested, {} succeeded, {} failed, wall {} ms.\n\n",
        time::OffsetDateTime::now_utc(),
        std::env::consts::OS,
        report.nodes_requested,
        report.success_count,
        report.failure_count,
        report.wall_millis
    ));
    text.push_str("| node | mac | distro | total ms | vlan | stages | result |\n");
    text.push_str("| --- | --- | --- | --- | --- | --- | --- |\n");
    for node in &report.per_node {
        let stages = node
            .stages
            .iter()
            .map(|s| format!("{}={}ms", s.stage, s.millis))
            .collect::<Vec<_>>()
            .join(" ");
        text.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} |\n",
            node.node_id,
            node.mac,
            node.distro,
            node.total_millis,
            node.vlan
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".into()),
            stages,
            match (&node.error, node.success) {
                (Some(err), _) => format!("FAIL: {err}"),
                (None, true) => "OK".into(),
                _ => "FAIL".into(),
            }
        ));
    }
    text.push_str(&format!(
        "\n802.1X: {} nodes on VLAN 100, {} on VLAN 666, {} rejected.\n\n",
        report.vlan_100, report.vlan_666, report.rejected
    ));
    let totals: Vec<u64> = report.per_node.iter().map(|n| n.total_millis).collect();
    if !totals.is_empty() {
        text.push_str(&format!(
            "Per-node boot-to-enrolled: p50={} ms, p95={} ms, min={} ms, max={} ms.\n",
            percentile(&totals, 50.0),
            percentile(&totals, 95.0),
            totals.iter().min().unwrap(),
            totals.iter().max().unwrap()
        ));
    }
    std::fs::write(out_dir.join("e2e.txt"), text)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentiles_are_real() {
        let values = (1..=100).collect::<Vec<u64>>();
        assert_eq!(percentile(&values, 50.0), 51);
        assert_eq!(percentile(&values, 95.0), 95);
        assert_eq!(percentile(&values, 99.0), 99);
        assert_eq!(percentile(&[], 50.0), 0);
    }

    #[test]
    fn inventory_macs_are_unique() {
        let inv = build_inventory(20);
        assert_eq!(inv.nodes.len(), 20);
        let macs: std::collections::BTreeSet<_> = inv.nodes.iter().map(|n| n.mac.clone()).collect();
        assert_eq!(macs.len(), 20);
        assert!(inv.validate().is_ok());
    }
}
