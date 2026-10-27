//! The viewer's own view of the sensor's JSONL records (ADR 0001).
//!
//! Only fields the viewer uses are declared; unknown fields are ignored and
//! fields added after the first sensor release default, so older and newer
//! `data/` directories both load.

use std::net::IpAddr;

use serde::Deserialize;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct RequestRecord {
    pub ts: String,
    pub conn_id: Uuid,
    pub attack_session_id: Uuid,
    pub src_ip: IpAddr,
    #[serde(default)]
    pub dst_port: u16,
    #[serde(default)]
    pub tls: bool,
    #[serde(default)]
    pub protocol: String,
    #[serde(default)]
    pub stream_id: Option<u32>,
    pub method: String,
    pub target: String,
    #[serde(default)]
    pub authority: Option<String>,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    #[serde(default)]
    pub body_size: u64,
    #[serde(default)]
    pub status: Option<u16>,
    #[serde(default)]
    pub c2s_range: Option<[u64; 2]>,
    #[serde(default)]
    pub s2c_range: Option<[u64; 2]>,
    #[serde(default)]
    pub body: Option<BodyRef>,
    #[serde(default)]
    pub response_body: Option<BodyRef>,
}

#[derive(Debug, Deserialize)]
pub struct BodyRef {
    pub sha256: String,
    pub size: u64,
    #[serde(default)]
    pub stored: u64,
    /// File name under `bodies/`; absent when nothing was stored.
    #[serde(default)]
    pub file: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ConnectionRecord {
    pub ts_open: String,
    #[serde(default)]
    pub ts_close: Option<String>,
    pub conn_id: Uuid,
    pub attack_session_id: Uuid,
    pub src_ip: IpAddr,
    #[serde(default)]
    pub dst_port: u16,
    #[serde(default)]
    pub tls: bool,
    #[serde(default)]
    pub sni: Option<String>,
    #[serde(default)]
    pub alpn: Option<String>,
    #[serde(default)]
    pub tls_error: Option<String>,
    #[serde(default)]
    pub bytes_c2s: u64,
    #[serde(default)]
    pub bytes_s2c: u64,
    #[serde(default)]
    pub capture_truncated: bool,
}
