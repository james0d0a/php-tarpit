use std::{net::IpAddr, path::PathBuf};

use anyhow::Context;
use clap::Parser;

/// Read-only web UI for reviewing one php_tarpit sensor's captured data.
/// Reach it through `ssh -L`; it only answers to localhost Host headers.
#[derive(Parser)]
#[command(version)]
struct Cli {
    /// The sensor's data directory (read only).
    #[arg(long, env = "PHP_TARPIT_VIEWER_DATA_DIR", default_value = "/data")]
    data_dir: PathBuf,
    /// Address to listen on. Keep it loopback unless inside a container
    /// whose port is published on the host's loopback only.
    #[arg(long, env = "PHP_TARPIT_VIEWER_BIND", default_value = "127.0.0.1")]
    bind: IpAddr,
    #[arg(long, env = "PHP_TARPIT_VIEWER_PORT", default_value_t = 8080)]
    port: u16,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let cli = Cli::parse();
    let listener = tokio::net::TcpListener::bind((cli.bind, cli.port))
        .await
        .with_context(|| format!("binding {}:{}", cli.bind, cli.port))?;
    tracing::info!(
        "viewer for {} on http://{}",
        cli.data_dir.display(),
        listener.local_addr()?
    );
    // SIGTERM too: as a container's PID 1 the default action is ignored.
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        r = php_tarpit_viewer::serve(listener, &cli.data_dir) => r,
        _ = tokio::signal::ctrl_c() => Ok(()),
        _ = term.recv() => Ok(()),
    }
}
