use std::{net::IpAddr, path::PathBuf};

use anyhow::Result;
use clap::Parser;
use php_tarpit::{Config, Sensor};
use tokio::signal::unix::{SignalKind, signal};

/// php2shell honeypot sensor.
#[derive(Parser)]
#[command(version)]
struct Cli {
    /// Persona TOML file.
    #[arg(long, env = "PHP_TARPIT_PERSONA")]
    persona: PathBuf,
    /// Directory for logs, raw streams and TLS material.
    #[arg(long, env = "PHP_TARPIT_DATA_DIR", default_value = "data")]
    data_dir: PathBuf,
    /// Listen address; `::` is dual-stack.
    #[arg(long, env = "PHP_TARPIT_BIND", default_value = "::")]
    bind: IpAddr,
    #[arg(long, env = "PHP_TARPIT_HTTP_PORT", default_value_t = 80)]
    http_port: u16,
    #[arg(long, env = "PHP_TARPIT_HTTPS_PORT", default_value_t = 443)]
    https_port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let cli = Cli::parse();
    let _sensor = Sensor::start(Config {
        persona: cli.persona,
        data_dir: cli.data_dir,
        bind: cli.bind,
        http_port: cli.http_port,
        https_port: cli.https_port,
    })
    .await?;

    let mut term = signal(SignalKind::terminate())?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
    tracing::info!("shutting down");
    Ok(())
}
