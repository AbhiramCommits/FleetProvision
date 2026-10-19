//! FleetProvision control plane.
//!
//! Three listeners separate machine enrollment from node mTLS and from human
//! operator access:
//!
//! * `--enroll-listen`  token-gated TLS, used before a node has an identity
//! * `--listen`         mandatory client-certificate mTLS for enrolled nodes
//! * `--operator-listen` human/operator API (OIDC in step 6)
//!
//! Node certificates are rejected on operator endpoints and operator identities
//! are rejected on node endpoints. Both checks are asserted in tests.

pub mod agent;
pub mod audit;
pub mod auth;
pub mod control;
pub mod idp;
pub mod metrics;
pub mod saml;
pub mod store;
pub mod tls;
pub mod tokens;

pub use control::{start, ControlConfig, RunningControlPlane};
pub use store::{NodeRecord, Store};
pub use tokens::{TokenError, TokenManager};

use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

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

    /// mTLS listener for enrolled nodes and machine-to-machine calls.
    #[arg(long, default_value = "127.0.0.1:8443")]
    pub listen: SocketAddr,

    /// Token-gated enrollment listener used before a node has a certificate.
    #[arg(long, default_value = "127.0.0.1:8444")]
    pub enroll_listen: SocketAddr,

    /// Operator listener (human identities, separate from machine mTLS).
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

pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Start the control plane and serve until Ctrl-C.
pub async fn run(args: ServerArgs) -> anyhow::Result<()> {
    let config = ControlConfig::from_args(&args);
    let running = control::start(config).await?;
    tracing::info!(
        mtls = %running.mtls_addr,
        enroll = %running.enroll_addr,
        operator = %running.operator_addr,
        "fleetd ready"
    );
    tokio::signal::ctrl_c().await?;
    running.shutdown().await;
    Ok(())
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
