use std::{path::PathBuf, process::ExitCode};

use anyhow::{Context, Result};
use clap::Parser;
use php_tarpit::{Overrides, PersonaFile, Sensor, Settings, config::ENV_PERSONA};
use tokio::signal::unix::{SignalKind, signal};

/// php2shell honeypot sensor.
///
/// Each setting resolves as: CLI flag > PHP_TARPIT_* environment variable >
/// persona `[settings]` table > built-in default.
#[derive(Parser)]
#[command(version)]
struct Cli {
    /// Persona TOML file [env: PHP_TARPIT_PERSONA]
    #[arg(long)]
    persona: Option<PathBuf>,
    #[command(flatten)]
    overrides: Overrides,
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("php_tarpit: {e:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<()> {
    let env_var = |k: &str| std::env::var(k).ok();
    let persona_path = cli
        .persona
        .or_else(|| env_var(ENV_PERSONA).map(PathBuf::from))
        .with_context(|| format!("no persona: pass --persona or set {ENV_PERSONA}"))?;
    let persona = PersonaFile::load(&persona_path)?;
    let env = Overrides::from_env(env_var)?;
    let settings = Settings::resolve(&cli.overrides, &env, &persona.settings)?;
    let _sensor = Sensor::start(settings, persona).await?;

    let mut term = signal(SignalKind::terminate())?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
    tracing::info!("shutting down");
    Ok(())
}
