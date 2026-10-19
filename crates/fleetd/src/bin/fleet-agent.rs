/// Entry point for the on-node agent. The full enrollment/renewal flow is
/// implemented in step 3; `--help` is stable from the first commit.
fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!(
            "fleet-agent {}\n\nUSAGE:\n    fleet-agent --state-dir <DIR> --control-plane <URL> --token-file <FILE>\n\nOPTIONS:\n    --state-dir <DIR>          Directory for node key, cert, and trust bundle\n    --control-plane <URL>      Enrollment listener base URL\n    --token-file <FILE>        Single-use bootstrap token\n    --attestation <FILE>       Attestation blob JSON (simulated TPM)\n    --help                     Print help",
            env!("CARGO_PKG_VERSION")
        );
        return Ok(());
    }
    anyhow::bail!("fleet-agent enrollment requires the control plane (see --help)");
}
