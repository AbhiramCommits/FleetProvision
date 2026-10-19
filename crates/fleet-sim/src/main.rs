mod dot1x;
mod e2e;
mod net;
mod render;

use clap::{Parser, Subcommand};

pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "fleet-sim",
    about = "FleetProvision provisioning, boot, identity-provider, and benchmark simulator",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the full DHCP -> TFTP -> HTTP -> attest -> enroll -> 802.1X pipeline.
    E2e {
        #[arg(long, default_value_t = 20)]
        nodes: usize,
        /// Directory for e2e.txt and e2e.json.
        #[arg(long, default_value = "results")]
        out: PathBuf,
    },
    /// Run the benchmark harness and write results/metrics.json.
    Bench {
        #[arg(long, default_value = "results")]
        out: PathBuf,
    },
    /// Generate deterministic attestation fixtures.
    GenFixtures {
        #[arg(long, default_value = "fixtures")]
        out: PathBuf,
    },
    /// Render per-MAC iPXE, Kickstart, and cloud-init from fleet.yaml.
    RenderIpxe {
        #[arg(long, default_value = "fleet.yaml")]
        inventory: PathBuf,
        #[arg(long, default_value = "out/pxe")]
        out: PathBuf,
        /// Directory containing `<node>.token` files issued by fleetctl.
        #[arg(long, default_value = "out/tokens")]
        token_dir: PathBuf,
        /// PEM trust bundle pinned by the rendered boot files.
        #[arg(long, default_value = "state/trust-bundle.pem")]
        ca_bundle: PathBuf,
    },
    /// Run a local OIDC mock identity provider with device authorization grant.
    Idp {
        #[arg(long, default_value = "127.0.0.1:8080")]
        listen: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "fleet_sim=info".into()),
        )
        .init();
    let cli = Cli::parse();
    match cli.command {
        Command::E2e { nodes, out } => {
            let report = e2e::run(nodes).await?;
            e2e::write_report(&report, &out)?;
            println!(
                "e2e: {} / {} nodes succeeded in {} ms (VLAN100={} VLAN666={} rejected={})",
                report.success_count,
                report.nodes_requested,
                report.wall_millis,
                report.vlan_100,
                report.vlan_666,
                report.rejected
            );
            for node in &report.per_node {
                println!(
                    "  {:<18} {:>6} ms  vlan={}  {}",
                    node.node_id,
                    node.total_millis,
                    node.vlan
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "-".into()),
                    node.error.clone().unwrap_or_else(|| "ok".into())
                );
            }
            if report.failure_count > 0 {
                anyhow::bail!("{} nodes failed", report.failure_count);
            }
            Ok(())
        }
        Command::Bench { out } => anyhow::bail!(
            "bench harness not available in this build (output {})",
            out.display()
        ),
        Command::GenFixtures { out } => {
            let policy = std::path::Path::new("policy/boot-integrity.yaml");
            let written = fleet_attest::fixtures::generate(&out, policy)?;
            for path in written {
                println!("wrote {path}");
            }
            Ok(())
        }
        Command::RenderIpxe {
            inventory,
            out,
            token_dir,
            ca_bundle,
        } => {
            let inventory = render::Inventory::load(&inventory)?;
            let manifest = render::render(&inventory, &out, &token_dir, &ca_bundle)?;
            println!(
                "rendered {} nodes for site {} into {}",
                manifest.nodes.len(),
                manifest.site,
                out.display()
            );
            for node in manifest.nodes {
                println!(
                    "  {} {} -> {} ({})",
                    node.id, node.mac, node.ipxe, node.boot
                );
            }
            Ok(())
        }
        Command::Idp { listen } => anyhow::bail!("mock IdP not available in this build ({listen})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn e2e_node_count_parses() {
        let cli = Cli::parse_from(["fleet-sim", "e2e", "--nodes", "7"]);
        match cli.command {
            Command::E2e { nodes, .. } => assert_eq!(nodes, 7),
            _ => panic!("wrong command"),
        }
    }

    #[test]
    fn every_subcommand_has_help_metadata() {
        use clap::CommandFactory;
        let cmd = Cli::command();
        let names: Vec<_> = cmd.get_subcommands().map(|c| c.get_name()).collect();
        assert_eq!(
            names,
            vec!["e2e", "bench", "gen-fixtures", "render-ipxe", "idp"]
        );
    }
}
