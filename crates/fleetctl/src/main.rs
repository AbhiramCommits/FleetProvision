mod cli;

use anyhow::bail;
use clap::Parser;
use cli::{CaCommand, Cli, Command};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Ca { command } => match command {
            CaCommand::Init(_) => bail!("ca init is not available in this build"),
            CaCommand::Issue(_) => bail!("ca issue is not available in this build"),
            CaCommand::Revoke(_) => bail!("ca revoke is not available in this build"),
            CaCommand::Crl => bail!("ca crl is not available in this build"),
            CaCommand::Show => bail!("ca show is not available in this build"),
            CaCommand::Verify(_) => bail!("ca verify is not available in this build"),
            CaCommand::Rotate => bail!("ca rotate is not available in this build"),
        },
        Command::Node { .. } => bail!("node commands require a running fleetd"),
        Command::Attest { .. } => bail!("attestation commands are not available in this build"),
        Command::Login(_) => bail!("login is not available in this build"),
        Command::Audit { .. } => bail!("audit commands are not available in this build"),
    }
}
