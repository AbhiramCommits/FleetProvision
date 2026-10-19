//! FleetProvision control plane.

use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;

/// Command-line configuration for the control plane.
#[derive(Debug, Clone, Parser)]
#[command(
    name = "fleetd",
    about = "FleetProvision control plane: mTLS enrollment, attestation, and revocation",
    version
)]
pub struct ServerArgs {
    /// Directory holding CA material, node state, CRL, and the audit log.
    #[arg(long, default_value = "./state")]
    pub state_dir: PathBuf,

    /// mTLS listener for enrolled nodes and operator machine-to-machine calls.
    #[arg(long, default_value = "127.0.0.1:8443")]
    pub listen: SocketAddr,

    /// Token-gated enrollment listener used before a node has a certificate.
    #[arg(long, default_value = "127.0.0.1:8444")]
    pub enroll_listen: SocketAddr,

    /// Operator listener: server TLS plus OIDC/SAML bearer tokens.
    #[arg(long, default_value = "127.0.0.1:9443")]
    pub operator_listen: SocketAddr,

    /// Public base URL advertised to agents (used for the CRL distribution point).
    #[arg(long, default_value = "https://127.0.0.1:8443")]
    pub public_url: String,

    /// OIDC issuer used to validate operator tokens.
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    pub oidc_issuer: String,

    /// Path to the boot-integrity policy.
    #[arg(long, default_value = "policy/boot-integrity.yaml")]
    pub policy: PathBuf,

    /// Path to a file containing the bootstrap-token HMAC key (hex).
    #[arg(long)]
    pub token_key: Option<PathBuf>,
}

impl ServerArgs {
    pub fn validate(&self) -> Result<(), String> {
        if self.listen == self.enroll_listen || self.listen == self.operator_listen {
            return Err("listeners must use distinct addresses".into());
        }
        if self.enroll_listen == self.operator_listen {
            return Err("listeners must use distinct addresses".into());
        }
        Ok(())
    }
}

/// Start the control plane. The full implementation arrives with the mTLS
/// layer; keeping the entry point here makes `fleetd --help` and argument
/// validation testable from the first commit.
pub async fn run(args: ServerArgs) -> anyhow::Result<()> {
    anyhow::bail!(
        "control plane state at {} is not initialized (run `fleetctl ca init` first)",
        args.state_dir.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_parseable_and_valid() {
        let args = ServerArgs::parse_from(["fleetd"]);
        assert_eq!(args.listen.port(), 8443);
        assert_eq!(args.enroll_listen.port(), 8444);
        assert_eq!(args.operator_listen.port(), 9443);
        assert!(args.validate().is_ok());
    }

    #[test]
    fn duplicate_listeners_are_rejected() {
        let args = ServerArgs::parse_from([
            "fleetd",
            "--listen",
            "127.0.0.1:9000",
            "--enroll-listen",
            "127.0.0.1:9000",
        ]);
        assert!(args.validate().is_err());
    }
}
