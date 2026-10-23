//! JSONL output: `requests.jsonl` (one line per request) and
//! `connections.jsonl` (one line per connection, written at close, linking
//! the raw stream files to a source).

use std::{io, net::IpAddr, path::Path};

use serde::Serialize;
use tokio::{
    fs::OpenOptions,
    io::{AsyncWriteExt, BufWriter},
    sync::mpsc,
};
use uuid::Uuid;

use crate::capture::BodyRef;

#[derive(Clone)]
pub struct JsonlWriter {
    tx: mpsc::UnboundedSender<Vec<u8>>,
}

impl JsonlWriter {
    pub async fn open(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path).await?;
        let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let path_display = path.display().to_string();
        tokio::spawn(async move {
            let mut out = BufWriter::new(file);
            while let Some(line) = rx.recv().await {
                let mut res = out.write_all(&line).await;
                if res.is_ok() && rx.is_empty() {
                    res = out.flush().await;
                }
                if let Err(e) = res {
                    tracing::error!(path = path_display, error = %e, "JSONL write failed");
                }
            }
        });
        Ok(Self { tx })
    }

    pub fn write<T: Serialize>(&self, record: &T) {
        let mut line = serde_json::to_vec(record).expect("records serialize");
        line.push(b'\n');
        let _ = self.tx.send(line);
    }
}

pub fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}

#[derive(Serialize)]
pub struct RequestRecord {
    pub ts: String,
    pub conn_id: Uuid,
    pub attack_session_id: Uuid,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub tls: bool,
    /// `HTTP/1.0`, `HTTP/1.1` or `HTTP/2`.
    pub protocol: &'static str,
    /// HTTP/2 stream id; absent for HTTP/1.x.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<u32>,
    pub method: String,
    /// Request target as sent (path and query, or absolute form).
    pub target: String,
    /// HTTP/2 `:authority`; absent for HTTP/1.x (see the `Host` header).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority: Option<String>,
    /// Name/value pairs. HTTP/1.x: wire order and case. HTTP/2: lowercase,
    /// pseudo-headers excluded.
    pub headers: Vec<(String, String)>,
    /// Body bytes received (after chunk decoding). Partial if `status` is null.
    pub body_size: u64,
    /// Response status sent; null when the request was cut off before a response.
    pub status: Option<u16>,
    /// `[start, end)` byte offsets in `streams/<conn_id>.c2s` / `.s2c`. For
    /// HTTP/2, the span of this stream's frames, which may interleave with
    /// other streams. Body payloads are not in the stream files (see `body`).
    pub c2s_range: Option<[u64; 2]>,
    pub s2c_range: Option<[u64; 2]>,
    /// Request body in `bodies/`; absent when empty.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<BodyRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_body: Option<BodyRef>,
}

#[derive(Serialize)]
pub struct ConnectionRecord {
    pub ts_open: String,
    pub ts_close: String,
    pub conn_id: Uuid,
    pub attack_session_id: Uuid,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub tls: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alpn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_error: Option<String>,
    /// Plaintext bytes that crossed the wire in each direction.
    pub bytes_c2s: u64,
    pub bytes_s2c: u64,
    /// True when the per-connection capture cap was reached and later bytes
    /// were not stored.
    pub capture_truncated: bool,
    pub requests: u32,
}
