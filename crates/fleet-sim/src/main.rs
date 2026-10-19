use clap::{Parser, Subcommand};
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
    },
    /// Run a local OIDC mock identity provider with device authorization grant.
    Idp {
        #[arg(long, default_value = "127.0.0.1:8080")]
        listen: String,
    },
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "fleet_sim=info".into()),
        )
        .init();
    let cli = Cli::parse();
    match cli.command {
        Command::E2e { nodes } => {
            anyhow::bail!("e2e harness not available in this build ({nodes} nodes requested)")
        }
        Command::Bench { out } => anyhow::bail!(
            "bench harness not available in this build (output {})",
            out.display()
        ),
        Command::GenFixtures { out } => anyhow::bail!(
            "fixture generator not available in this build (output {})",
            out.display()
        ),
        Command::RenderIpxe { inventory, out } => anyhow::bail!(
            "iPXE renderer not available in this build ({} -> {})",
            inventory.display(),
            out.display()
        ),
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
            Command::E2e { nodes } => assert_eq!(nodes, 7),
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
