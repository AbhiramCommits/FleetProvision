use clap::Parser;
use fleetd::ServerArgs;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "fleetd=info,tower_http=warn".into()),
        )
        .init();

    let args = ServerArgs::parse();
    args.validate().map_err(anyhow::Error::msg)?;
    tracing::info!(
        state_dir = %args.state_dir.display(),
        listen = %args.listen,
        enroll_listen = %args.enroll_listen,
        operator_listen = %args.operator_listen,
        "fleetd starting"
    );
    fleetd::run(args).await
}
