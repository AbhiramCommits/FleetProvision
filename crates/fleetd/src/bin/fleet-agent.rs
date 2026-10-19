use anyhow::Context;
use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "fleet-agent",
    about = "FleetProvision node agent: CSR enrollment, certificate install, and renewal",
    version
)]
struct AgentCli {
    #[command(subcommand)]
    command: AgentCommand,
}

#[derive(Debug, Subcommand)]
enum AgentCommand {
    /// Enroll this node using a single-use bootstrap token.
    Enroll(EnrollArgs),
    /// Renew the node certificate if two thirds of its lifetime have elapsed.
    Renew(RenewArgs),
    /// Print local certificate state without contacting the control plane.
    Status(StatusArgs),
}

#[derive(Debug, Args)]
struct EnrollArgs {
    /// Enrollment listener base URL.
    #[arg(long, default_value = "https://127.0.0.1:8444")]
    enroll_url: String,
    /// Node identity, e.g. rack-a-node-01.
    #[arg(long)]
    node_id: String,
    /// Fleet site.
    #[arg(long, default_value = "dc1")]
    site: String,
    /// DNS hostname (defaults to --node-id).
    #[arg(long)]
    hostname: Option<String>,
    /// Single-use bootstrap token issued by the control plane.
    #[arg(long)]
    token: String,
    /// Local state directory for keys and certificates.
    #[arg(long, default_value = "/var/lib/fleet-agent")]
    state_dir: PathBuf,
    /// Root CA bundle used to authenticate the enrollment listener.
    #[arg(long)]
    ca_bundle: PathBuf,
    /// Target distribution whose bootloader measurement should be simulated.
    #[arg(long, default_value = "ubuntu")]
    distro: String,
}

#[derive(Debug, Args)]
struct RenewArgs {
    /// mTLS listener base URL.
    #[arg(long, default_value = "https://127.0.0.1:8443")]
    control_plane: String,
    #[arg(long, default_value = "/var/lib/fleet-agent")]
    state_dir: PathBuf,
}

#[derive(Debug, Args)]
struct StatusArgs {
    #[arg(long, default_value = "/var/lib/fleet-agent")]
    state_dir: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "fleet_agent=info".into()),
        )
        .init();
    match AgentCli::parse().command {
        AgentCommand::Enroll(args) => {
            let hostname = args.hostname.unwrap_or_else(|| args.node_id.clone());
            let distro = match args.distro.to_ascii_lowercase().as_str() {
                "ubuntu" => fleet_attest::Distro::Ubuntu,
                "fedora" => fleet_attest::Distro::Fedora,
                other => anyhow::bail!("unknown distro {other}; expected ubuntu or fedora"),
            };
            let config = fleetd::agent::EnrollConfig {
                control_plane: args.enroll_url.clone(),
                enroll_url: args.enroll_url,
                state_dir: args.state_dir.clone(),
                token: args.token,
                node_id: args.node_id,
                site: args.site,
                hostname,
                ca_bundle: args.ca_bundle,
                distro,
            };
            let enrolled = fleetd::agent::enroll(&config)
                .await
                .context("enrollment failed")?;
            println!("enrolled node {}", enrolled.node_id);
            println!("state:     {}", enrolled.state);
            println!("serial:    {}", enrolled.serial_hex);
            println!("notAfter:  {}", enrolled.not_after);
            println!(
                "cert:      {}",
                args.state_dir.join("node/node.crt.pem").display()
            );
        }
        AgentCommand::Renew(args) => {
            match fleetd::agent::renew_if_due(&args.control_plane, &args.state_dir)
                .await
                .context("renewal failed")?
            {
                fleetd::agent::RenewOutcome::Renewed {
                    serial_hex,
                    not_after,
                } => {
                    println!("renewed serial {serial_hex}");
                    println!("notAfter: {not_after}");
                }
                fleetd::agent::RenewOutcome::NotDue { remaining_seconds } => {
                    println!("renewal not due; {remaining_seconds} seconds of validity remain");
                }
            }
        }
        AgentCommand::Status(args) => {
            let path = args.state_dir.join("node/agent-state.json");
            let raw = std::fs::read_to_string(&path)
                .with_context(|| format!("no agent state at {}", path.display()))?;
            println!("{raw}");
        }
    }
    Ok(())
}
