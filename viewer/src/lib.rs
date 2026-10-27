//! php_tarpit viewer: a read-only web UI over one sensor's `data/`
//! directory, browsed by attack session. See ADR 0001 and 0002.

mod data;
mod filter;
mod index;
mod records;
mod render;
mod web;

use std::path::Path;

pub use web::is_loopback_host;

/// Serves the viewer for `data_dir` on `listener` until the future is dropped.
pub async fn serve(listener: tokio::net::TcpListener, data_dir: &Path) -> anyhow::Result<()> {
    let app = web::router(data_dir)?;
    axum::serve(listener, app).await?;
    Ok(())
}
