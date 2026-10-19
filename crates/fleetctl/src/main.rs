mod cli;

use anyhow::{bail, Context};
use clap::Parser;
use cli::{
    AttestCommand, AuditCommand, CaCommand, CaInitArgs, CaIssueArgs, CaRevokeArgs, CaVerifyArgs,
    Cli, Command, NodeCommand, TokenCommand,
};
use fleet_pki::{Ca, CaConfig, IssuedCert, LeafSpec, LeafUsage, NodeKeypair};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Serialize, Deserialize)]
struct IssuedNodeRecord {
    node_id: String,
    site: String,
    hostname: String,
    usage: LeafUsage,
    serial_hex: String,
    not_after: i64,
    issued_at: i64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let state_dir = cli.state_dir.clone();
    let server = cli.server.clone();
    let insecure = cli.insecure;
    match cli.command {
        Command::Ca { command } => run_ca(&state_dir, command),
        Command::Node { command } => run_node(&state_dir, &server, insecure, command).await,
        Command::Token { command } => run_token(&state_dir, &server, insecure, command).await,
        Command::Attest { command } => run_attest(command),
        Command::Login(args) => run_login(&state_dir, &server, insecure, args).await,
        Command::Audit { command } => run_audit(&state_dir, command),
    }
}

fn run_ca(state_dir: &Path, command: CaCommand) -> anyhow::Result<()> {
    match command {
        CaCommand::Init(args) => ca_init(state_dir, args),
        CaCommand::Issue(args) => ca_issue(state_dir, args),
        CaCommand::Revoke(args) => ca_revoke(state_dir, args),
        CaCommand::Crl => ca_crl(state_dir),
        CaCommand::Show => ca_show(state_dir),
        CaCommand::Verify(args) => ca_verify(state_dir, args),
        CaCommand::Rotate => ca_rotate(state_dir),
    }
}

fn load_ca(state_dir: &Path) -> anyhow::Result<Ca> {
    Ca::load(state_dir).map_err(|e| {
        anyhow::anyhow!(
            "failed to load CA from {}: {e}. Run `fleetctl ca init` first.",
            state_dir.display()
        )
    })
}

fn ca_init(state_dir: &Path, args: CaInitArgs) -> anyhow::Result<()> {
    let existing = Ca::load(state_dir);
    if existing.is_ok() {
        bail!("CA already initialized in {}", state_dir.display());
    }
    let config = CaConfig {
        site: args.site.clone(),
        root_cn: args.root_cn,
        intermediate_cn: args.intermediate_cn,
        ..Default::default()
    };
    let mut ca = Ca::init_root(config)?;
    ca.save(state_dir)?;
    let summary = ca.summary()?;
    println!("initialized FleetProvision CA in {}", state_dir.display());
    println!("site:              {}", summary.config.site);
    println!("root subject:      {}", summary.root_subject);
    println!("root notAfter:     {}", summary.root_not_after);
    println!("intermediates:     {}", summary.intermediates.len());
    println!(
        "trust bundle:      {}",
        state_dir.join("trust-bundle.pem").display()
    );
    println!("crl:               {}", state_dir.join("crl.pem").display());
    println!("crl number:        {}", summary.crl_number);
    Ok(())
}

fn ca_issue(state_dir: &Path, args: CaIssueArgs) -> anyhow::Result<()> {
    let mut ca = load_ca(state_dir)?;
    let site = args
        .site
        .clone()
        .unwrap_or_else(|| ca.config().site.clone());
    let hostname = args
        .hostname
        .clone()
        .unwrap_or_else(|| args.node_id.clone());
    let usage = LeafUsage::parse(&args.usage)?;

    let node_dir = state_dir.join("nodes").join(&args.node_id);
    std::fs::create_dir_all(&node_dir)?;

    let (csr_pem, node_key) = match &args.csr {
        Some(csr_path) => (
            std::fs::read_to_string(csr_path)
                .with_context(|| format!("reading CSR {}", csr_path.display()))?,
            None,
        ),
        None => {
            let keypair = NodeKeypair::new(&args.node_id, &site)?;
            (
                keypair.csr_pem().to_string(),
                Some(keypair.key_pem().to_string()),
            )
        }
    };
    std::fs::write(node_dir.join("node.csr.pem"), &csr_pem)?;

    let spec = LeafSpec::for_node(site.clone(), args.node_id.clone())
        .with_usage(usage)
        .with_hostname(hostname.clone())
        .with_csr(csr_pem);
    let issued = ca.issue_leaf(&spec)?;
    persist_issued(&node_dir, &issued, node_key.as_deref())?;
    let record = IssuedNodeRecord {
        node_id: args.node_id.clone(),
        site,
        hostname,
        usage,
        serial_hex: issued.serial_hex.clone(),
        not_after: issued.identity.not_after,
        issued_at: fleet_pki::unix_now(),
    };
    std::fs::write(
        node_dir.join("node.json"),
        serde_json::to_vec_pretty(&record)?,
    )?;

    println!("issued leaf certificate");
    println!("node:        {}", record.node_id);
    println!("serial:      {}", record.serial_hex);
    println!("usage:       {}", record.usage);
    println!("dns:         {}", issued.identity.dns_name);
    println!("uri:         {}", issued.identity.uri);
    println!("notAfter:    {}", record.not_after);
    println!("cert:        {}", node_dir.join("node.crt.pem").display());
    if node_key.is_some() {
        println!("key:         {}", node_dir.join("node.key.pem").display());
    }
    println!("chain:       {}", node_dir.join("node-chain.pem").display());
    Ok(())
}

fn persist_issued(
    node_dir: &Path,
    issued: &IssuedCert,
    key_pem: Option<&str>,
) -> anyhow::Result<()> {
    std::fs::write(node_dir.join("node.crt.pem"), &issued.cert_pem)?;
    std::fs::write(node_dir.join("node-chain.pem"), &issued.chain_pem)?;
    if let Some(key) = key_pem.or(issued.key_pem.as_deref()) {
        let path = node_dir.join("node.key.pem");
        std::fs::write(&path, key)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
    }
    Ok(())
}

fn ca_revoke(state_dir: &Path, args: CaRevokeArgs) -> anyhow::Result<()> {
    let mut ca = load_ca(state_dir)?;
    ca.revoke(&args.serial, &args.reason)?;
    let store = ca.crl_store()?;
    println!("revoked serial {}", args.serial.to_ascii_lowercase());
    println!("reason:      {}", args.reason);
    println!("crl number:  {}", store.crl().crl_number());
    println!("nextUpdate:  {}", store.crl().next_update());
    Ok(())
}

fn ca_crl(state_dir: &Path) -> anyhow::Result<()> {
    let ca = load_ca(state_dir)?;
    let pem = ca
        .crl_pem()
        .context("CA has no CRL; run `fleetctl ca init`")?;
    let store = ca.crl_store()?;
    let summary = store.crl().summary();
    eprintln!(
        "CRL number {} thisUpdate {} nextUpdate {} revoked {} stale {}",
        summary.crl_number,
        summary.this_update,
        summary.next_update,
        summary.revoked_serials.len(),
        summary.stale
    );
    print!("{pem}");
    Ok(())
}

fn ca_show(state_dir: &Path) -> anyhow::Result<()> {
    let ca = load_ca(state_dir)?;
    let summary = ca.summary()?;
    println!("site:          {}", summary.config.site);
    println!("organization:  {}", summary.config.organization);
    println!("root:          {}", summary.root_subject);
    println!("root notAfter: {}", summary.root_not_after);
    println!("crl number:    {}", summary.crl_number);
    println!("revoked:       {}", summary.revoked_count);
    println!("intermediates:");
    for int in &summary.intermediates {
        println!(
            "  serial={} created={} notAfter={} active={}",
            int.serial_hex, int.created_at, int.not_after, int.active
        );
    }
    println!("trust bundle ({} bytes):", summary.trust_bundle_pem.len());
    print!("{}", summary.trust_bundle_pem);
    Ok(())
}

fn ca_verify(state_dir: &Path, args: CaVerifyArgs) -> anyhow::Result<()> {
    let ca = load_ca(state_dir)?;
    let node_dir = state_dir.join("nodes").join(&args.node_id);
    let cert = std::fs::read_to_string(node_dir.join("node.crt.pem"))
        .with_context(|| format!("reading {}", node_dir.join("node.crt.pem").display()))?;
    let record: IssuedNodeRecord = serde_json::from_slice(
        &std::fs::read(node_dir.join("node.json"))
            .with_context(|| format!("no issued record for {}", args.node_id))?,
    )?;
    let store = ca.crl_store()?;
    let identity = ca.verify_leaf_with_crl(&cert, record.usage, &store)?;
    println!("verified {}", args.node_id);
    println!("subject:    {}", identity.dns_name);
    println!("uri:        {}", identity.uri);
    println!("serial:     {}", identity.serial_hex);
    println!("usage:      {}", identity.usage);
    println!("notBefore:  {}", identity.not_before);
    println!("notAfter:   {}", identity.not_after);
    println!("crl number: {}", store.crl().crl_number());
    println!("result:     OK");
    Ok(())
}

fn ca_rotate(state_dir: &Path) -> anyhow::Result<()> {
    let mut ca = load_ca(state_dir)?;
    let info = ca.rotate_intermediate()?;
    ca.save(state_dir)?;
    println!("rotated intermediate");
    println!("serial:   {}", info.serial_hex);
    println!("notAfter: {}", info.not_after);
    println!(
        "trust bundle now contains {} intermediates",
        ca.summary()?.intermediates.len()
    );
    Ok(())
}

async fn run_node(
    state_dir: &Path,
    server: &str,
    insecure: bool,
    command: NodeCommand,
) -> anyhow::Result<()> {
    let client = operator_client(state_dir, insecure)?;
    match command {
        NodeCommand::List => {
            let response = client.get(format!("{server}/v1/nodes")).send().await?;
            print_json_response(response).await
        }
        NodeCommand::Describe { node_id } => {
            let response = client
                .get(format!("{server}/v1/nodes/{node_id}"))
                .send()
                .await?;
            print_json_response(response).await
        }
        NodeCommand::Revoke { node_id } => {
            let response = client
                .post(format!("{server}/v1/nodes/{node_id}/revoke"))
                .json(&serde_json::json!({"reason": "key_compromise"}))
                .send()
                .await?;
            print_json_response(response).await
        }
        NodeCommand::Renew { node_id, csr } => {
            let csr_pem = std::fs::read_to_string(&csr)
                .with_context(|| format!("reading CSR {}", csr.display()))?;
            let response = client
                .post(format!("{server}/v1/nodes/{node_id}/renew"))
                .json(&serde_json::json!({"csr_pem": csr_pem}))
                .send()
                .await?;
            print_json_response(response).await
        }
    }
}

async fn run_token(
    state_dir: &Path,
    server: &str,
    insecure: bool,
    command: TokenCommand,
) -> anyhow::Result<()> {
    match command {
        TokenCommand::Create {
            node_id,
            site,
            ttl,
            out,
        } => {
            let client = operator_client(state_dir, insecure)?;
            let response = client
                .post(format!("{server}/v1/tokens"))
                .json(&serde_json::json!({
                    "node_id": node_id,
                    "site": site,
                    "ttl_seconds": ttl,
                }))
                .send()
                .await?;
            let status = response.status();
            let body: serde_json::Value = response.json().await?;
            if !status.is_success() {
                bail!("token creation failed with {status}: {body}");
            }
            let token = body
                .get("token")
                .and_then(|v| v.as_str())
                .context("response did not include a token")?;
            if let Some(path) = out {
                std::fs::write(&path, token)?;
                println!("wrote bootstrap token to {}", path.display());
            } else {
                println!("{token}");
            }
            eprintln!("node_id: {}", body["node_id"]);
            eprintln!("expires_at: {}", body["expires_at"]);
            Ok(())
        }
    }
}

fn operator_client(state_dir: &Path, insecure: bool) -> anyhow::Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder().danger_accept_invalid_certs(insecure);
    let root = state_dir.join("root-cert.pem");
    if root.exists() {
        let pem = std::fs::read(&root)?;
        builder = builder.add_root_certificate(reqwest::Certificate::from_pem(&pem)?);
    }
    let node_dir = state_dir.join("nodes/operator-admin");
    let cert = node_dir.join("node.crt.pem");
    let key = node_dir.join("node.key.pem");
    if cert.exists() && key.exists() {
        let identity = format!(
            "{}{}",
            std::fs::read_to_string(cert)?,
            std::fs::read_to_string(key)?
        );
        builder = builder.identity(reqwest::Identity::from_pem(identity.as_bytes())?);
    }
    Ok(builder.build()?)
}

async fn print_json_response(response: reqwest::Response) -> anyhow::Result<()> {
    let status = response.status();
    let body = response.text().await?;
    if !status.is_success() {
        bail!("request failed with {status}: {body}");
    }
    let value: serde_json::Value =
        serde_json::from_str(&body).unwrap_or(serde_json::Value::String(body));
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

fn run_attest(command: AttestCommand) -> anyhow::Result<()> {
    match command {
        AttestCommand::Check { fixture, policy } => {
            let _ = (fixture, policy);
            bail!("attestation checks are not available in this build")
        }
    }
}

async fn run_login(
    _state_dir: &Path,
    _server: &str,
    _insecure: bool,
    _args: cli::LoginArgs,
) -> anyhow::Result<()> {
    bail!("login is not available in this build")
}

fn run_audit(_state_dir: &Path, _command: AuditCommand) -> anyhow::Result<()> {
    bail!("audit commands are not available in this build")
}
