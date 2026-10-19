use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "fleetctl",
    about = "FleetProvision operator and PKI CLI",
    version
)]
pub struct Cli {
    /// Directory holding CA material and operator state.
    #[arg(long, global = true, default_value = "./state")]
    pub state_dir: PathBuf,

    /// Control-plane operator base URL.
    #[arg(long, global = true, default_value = "https://127.0.0.1:9443")]
    pub server: String,

    /// Machine mTLS base URL (node API).
    #[arg(long, global = true, default_value = "https://127.0.0.1:8443")]
    pub mtls_server: String,

    /// Skip TLS verification (development only; never use in production).
    #[arg(long, global = true)]
    pub insecure: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Internal certificate authority operations.
    Ca {
        #[command(subcommand)]
        command: CaCommand,
    },
    /// Node operations against a running control plane.
    Node {
        #[command(subcommand)]
        command: NodeCommand,
    },
    /// Bootstrap-token operations (requires an operator identity).
    Token {
        #[command(subcommand)]
        command: TokenCommand,
    },
    /// Boot-integrity attestation checks.
    Attest {
        #[command(subcommand)]
        command: AttestCommand,
    },
    /// Authenticate an operator through the OIDC device flow.
    Login(LoginArgs),
    /// Audit-log operations.
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum CaCommand {
    /// Create the root and intermediate CA in --state-dir.
    Init(CaInitArgs),
    /// Issue a leaf certificate for a node identity.
    Issue(CaIssueArgs),
    /// Revoke a serial and re-issue the CRL.
    Revoke(CaRevokeArgs),
    /// Print the current CRL.
    Crl,
    /// Show the CA hierarchy and trust bundle.
    Show,
    /// Verify a node certificate against the trust bundle and CRL.
    Verify(CaVerifyArgs),
    /// Rotate the intermediate, keeping the old one trusted until expiry.
    Rotate,
}

#[derive(Debug, Args)]
pub struct CaInitArgs {
    #[arg(long, default_value = "dc1")]
    pub site: String,
    #[arg(long, default_value = "FleetProvision Root CA")]
    pub root_cn: String,
    #[arg(long, default_value = "FleetProvision Issuing CA")]
    pub intermediate_cn: String,
}

#[derive(Debug, Args)]
pub struct CaIssueArgs {
    #[arg(long)]
    pub node_id: String,
    #[arg(long)]
    pub site: Option<String>,
    #[arg(long)]
    pub hostname: Option<String>,
    /// client (node) or server (fleetd).
    #[arg(long, default_value = "client")]
    pub usage: String,
    /// Issue from a CSR instead of generating a key locally.
    #[arg(long)]
    pub csr: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct CaRevokeArgs {
    #[arg(long)]
    pub serial: String,
    #[arg(long, default_value = "key_compromise")]
    pub reason: String,
}

#[derive(Debug, Args)]
pub struct CaVerifyArgs {
    #[arg(long)]
    pub node_id: String,
}

#[derive(Debug, Subcommand)]
pub enum NodeCommand {
    /// List all nodes known to fleetd.
    List,
    /// Describe one node including attestation violations.
    Describe { node_id: String },
    /// Revoke a node.
    Revoke { node_id: String },
    /// Renew a node certificate from a CSR.
    Renew {
        node_id: String,
        #[arg(long)]
        csr: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
pub enum TokenCommand {
    /// Issue a single-use bootstrap token for a node.
    Create {
        #[arg(long)]
        node_id: String,
        #[arg(long, default_value = "dc1")]
        site: String,
        #[arg(long, default_value_t = 900)]
        ttl: u64,
        /// Write the token to a file instead of stdout.
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
pub enum AttestCommand {
    /// Evaluate one fixture against a policy and print a verdict table.
    Check {
        #[arg(long)]
        fixture: PathBuf,
        #[arg(long, default_value = "policy/boot-integrity.yaml")]
        policy: PathBuf,
    },
}

#[derive(Debug, Args)]
pub struct LoginArgs {
    /// OIDC issuer (mock IdP by default).
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    pub idp: String,
}

#[derive(Debug, Subcommand)]
pub enum AuditCommand {
    /// Verify the hash chain and report the first broken record.
    Verify,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pki_commands_parse() {
        let cli = Cli::parse_from([
            "fleetctl",
            "--state-dir",
            "/tmp/x",
            "ca",
            "issue",
            "--node-id",
            "n1",
            "--usage",
            "client",
        ]);
        assert_eq!(cli.state_dir, PathBuf::from("/tmp/x"));
        assert!(matches!(
            cli.command,
            Command::Ca {
                command: CaCommand::Issue(_)
            }
        ));
    }

    #[test]
    fn node_and_attest_commands_parse() {
        let cli = Cli::parse_from(["fleetctl", "node", "revoke", "n17"]);
        assert!(matches!(
            cli.command,
            Command::Node {
                command: NodeCommand::Revoke { .. }
            }
        ));

        let cli = Cli::parse_from([
            "fleetctl",
            "attest",
            "check",
            "--fixture",
            "fixtures/ubuntu-good.json",
        ]);
        assert!(matches!(
            cli.command,
            Command::Attest {
                command: AttestCommand::Check { .. }
            }
        ));
    }

    #[test]
    fn token_create_parses() {
        let cli = Cli::parse_from([
            "fleetctl",
            "token",
            "create",
            "--node-id",
            "n1",
            "--ttl",
            "60",
        ]);
        assert!(matches!(
            cli.command,
            Command::Token {
                command: TokenCommand::Create { ttl: 60, .. }
            }
        ));
    }
}
