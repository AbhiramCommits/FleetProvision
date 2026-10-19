mod cli;

use anyhow::{bail, Context};
use clap::Parser;
use cli::{
    AttestCommand, AuditCommand, CaCommand, CaInitArgs, CaIssueArgs, CaRevokeArgs, CaVerifyArgs,
    Cli, Command, NodeCommand, SamlCommand, SamlVerifyArgs, TokenCommand,
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
        Command::Saml { command } => run_saml(command),
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

fn load_operator_token(state_dir: &Path) -> anyhow::Result<String> {
    let path = state_dir.join("operator-token.json");
    let raw = std::fs::read(&path).with_context(|| {
        format!(
            "no operator token at {}; run `fleetctl login --group fleet-admin` first",
            path.display()
        )
    })?;
    #[derive(Deserialize)]
    struct TokenFile {
        access_token: String,
        expires_at: i64,
    }
    let token: TokenFile = serde_json::from_slice(&raw)?;
    if token.expires_at <= fleet_pki::unix_now() {
        bail!("operator token expired; run `fleetctl login` again");
    }
    Ok(token.access_token)
}

fn operator_client(state_dir: &Path, insecure: bool) -> anyhow::Result<reqwest::Client> {
    let token = load_operator_token(state_dir)?;
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::AUTHORIZATION,
        format!("Bearer {token}").parse()?,
    );
    let mut builder = reqwest::Client::builder()
        .danger_accept_invalid_certs(insecure)
        .default_headers(headers);
    let root = state_dir.join("root-cert.pem");
    if root.exists() {
        let pem = std::fs::read(&root)?;
        builder = builder.add_root_certificate(reqwest::Certificate::from_pem(&pem)?);
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
        AttestCommand::Check {
            fixture,
            policy,
            ca_bundle,
        } => {
            let policy = fleet_attest::Policy::load(&policy)
                .with_context(|| format!("loading policy {}", policy.display()))?;
            let blob: fleet_attest::AttestationBlob = serde_json::from_slice(
                &std::fs::read(&fixture)
                    .with_context(|| format!("reading fixture {}", fixture.display()))?,
            )?;
            let verdict = if ca_bundle.exists() {
                let ca = std::fs::read_to_string(&ca_bundle)?;
                policy.evaluate_with_ca(&blob, &ca)
            } else {
                policy.evaluate(&blob)
            };
            let name = fixture
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("<fixture>");
            println!("{:<26} {:<6} violations", "fixture", "result");
            println!("{}", "-".repeat(78));
            println!(
                "{:<26} {:<6} {}",
                name,
                if verdict.is_pass() { "PASS" } else { "FAIL" },
                if verdict.is_pass() {
                    "-".to_string()
                } else {
                    verdict
                        .violations()
                        .iter()
                        .map(|v| format!("{}: {}", v.code(), v))
                        .collect::<Vec<_>>()
                        .join("; ")
                }
            );
            if !verdict.is_pass() {
                std::process::exit(2);
            }
            Ok(())
        }
    }
}

#[derive(Debug, serde::Deserialize)]
struct DeviceAuthResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    expires_in: u64,
    interval: u64,
}

#[derive(Debug, serde::Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: i64,
}

async fn run_login(
    state_dir: &Path,
    server: &str,
    insecure: bool,
    args: cli::LoginArgs,
) -> anyhow::Result<()> {
    let http = reqwest::Client::builder()
        .danger_accept_invalid_certs(insecure)
        .build()?;
    let nonce = hex::encode({
        let mut bytes = [0u8; 16];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut bytes);
        bytes
    });
    let device: DeviceAuthResponse = http
        .post(format!(
            "{}/device_authorization",
            args.idp.trim_end_matches('/')
        ))
        .json(&serde_json::json!({
            "client_id": "fleetctl",
            "scope": "openid profile groups",
            "groups": [args.group],
            "nonce": nonce,
            "subject": "operator@fleet.internal"
        }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    println!(
        "Open {} and enter code {}",
        device.verification_uri, device.user_code
    );
    println!("(the mock IdP auto-approves device codes)");

    let mut token: Option<TokenResponse> = None;
    for _ in 0..=device.expires_in / device.interval.max(1) {
        let response = http
            .post(format!("{}/token", args.idp.trim_end_matches('/')))
            .json(&serde_json::json!({
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device.device_code,
                "client_id": "fleetctl"
            }))
            .send()
            .await?;
        if response.status().is_success() {
            token = Some(response.json().await?);
            break;
        }
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if body.contains("authorization_pending") {
            tokio::time::sleep(std::time::Duration::from_secs(device.interval.max(1))).await;
            continue;
        }
        bail!("token endpoint returned {status}: {body}");
    }
    let token = token.context("device authorization expired before approval")?;
    let expires_at = fleet_pki::unix_now() + token.expires_in;
    std::fs::create_dir_all(state_dir)?;
    let path = state_dir.join("operator-token.json");
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "access_token": token.access_token,
            "expires_at": expires_at,
            "issuer": args.idp,
            "groups": [args.group],
            "nonce": nonce,
        }))?,
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }

    let session = operator_client(state_dir, insecure)?
        .get(format!("{server}/v1/auth/session"))
        .send()
        .await?;
    let status = session.status();
    let body: serde_json::Value = session.json().await?;
    if !status.is_success() {
        bail!("operator session validation failed with {status}: {body}");
    }
    println!(
        "logged in as {} with groups {}",
        body["subject"], body["groups"]
    );
    println!("token saved to {}", path.display());
    Ok(())
}

fn run_saml(command: SamlCommand) -> anyhow::Result<()> {
    match command {
        SamlCommand::Verify(args) => saml_verify(args),
    }
}

fn saml_verify(args: SamlVerifyArgs) -> anyhow::Result<()> {
    let xml = std::fs::read_to_string(&args.response)
        .with_context(|| format!("reading SAML response {}", args.response.display()))?;
    let key = std::fs::read_to_string(&args.key)
        .with_context(|| format!("reading IdP public key {}", args.key.display()))?;
    let config = fleetd::saml::SamlConfig {
        public_key_pem: key,
        expected_issuer: args.issuer,
        audience: args.audience,
        destination: args.destination,
        clock_skew_seconds: 60,
    };
    let mut replay = fleetd::saml::ReplayCache::new();
    let assertion = config
        .verify(&xml, &args.in_response_to, &mut replay)
        .map_err(|e| anyhow::anyhow!("SAML verification failed: {e}"))?;
    println!("SAML assertion verified");
    println!("subject:        {}", assertion.subject);
    println!("groups:         {}", assertion.groups.join(","));
    println!("issuer:         {}", assertion.issuer);
    println!("audience:       {}", assertion.audience);
    println!("destination:    {}", assertion.destination);
    println!("inResponseTo:   {}", assertion.in_response_to);
    println!("assertion id:   {}", assertion.assertion_id);
    println!("notOnOrAfter:   {}", assertion.not_on_or_after);
    Ok(())
}

fn run_audit(state_dir: &Path, command: AuditCommand) -> anyhow::Result<()> {
    match command {
        AuditCommand::Verify => {
            let path = state_dir.join("audit.jsonl");
            let report = fleetd::audit::verify(&path)?;
            println!("audit log: {}", path.display());
            println!("records:   {}", report.records);
            println!("last hash: {}", report.last_hash);
            if report.valid {
                println!("result:    OK (hash chain intact)");
                Ok(())
            } else {
                println!(
                    "result:    TAMPERED at sequence {}: {}",
                    report
                        .first_bad_seq
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "-".into()),
                    report.reason.unwrap_or_default()
                );
                std::process::exit(1);
            }
        }
    }
}
