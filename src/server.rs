//! Listeners and per-connection plumbing: capture, TLS, protocol dispatch, logging.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZeroUsize,
    path::PathBuf,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use anyhow::{Context, Result};
use tokio::{
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::timeout,
};
use tokio_rustls::TlsAcceptor;
use uuid::Uuid;

use crate::{
    capture::StreamCapture,
    http1, http2,
    log::{ConnectionRecord, JsonlWriter, RequestRecord, now},
    persona::Persona,
    session::AttackSessions,
    tls,
};

pub const REQUESTS_LOG: &str = "requests.jsonl";
pub const CONNECTIONS_LOG: &str = "connections.jsonl";
pub const STREAMS_DIR: &str = "streams";
pub const TLS_DIR: &str = "tls";

const ATTACK_SESSION_IDLE: Duration = Duration::from_secs(5 * 60);
const ATTACK_SESSION_CAPACITY: NonZeroUsize = NonZeroUsize::new(10_000).unwrap();
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug, Clone)]
pub struct Config {
    pub persona: PathBuf,
    pub data_dir: PathBuf,
    pub bind: IpAddr,
    /// 0 picks an ephemeral port.
    pub http_port: u16,
    pub https_port: u16,
}

pub struct Shared {
    pub persona: Persona,
    requests: JsonlWriter,
    connections: JsonlWriter,
    sessions: AttackSessions,
    streams_dir: PathBuf,
}

#[derive(Clone, Copy)]
pub struct ConnInfo {
    pub conn_id: Uuid,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub tls: bool,
}

/// Per-request fields gathered by a protocol front.
pub struct RequestMeta {
    pub protocol: &'static str,
    pub stream_id: Option<u32>,
    pub method: String,
    pub target: String,
    pub authority: Option<String>,
    pub headers: Vec<(String, String)>,
    pub body_size: u64,
    pub status: Option<u16>,
}

impl Shared {
    pub fn log_request(&self, conn: &ConnInfo, meta: RequestMeta) {
        self.requests.write(&RequestRecord {
            ts: now(),
            conn_id: conn.conn_id,
            attack_session_id: self.sessions.touch(conn.src_ip),
            src_ip: conn.src_ip,
            src_port: conn.src_port,
            dst_port: conn.dst_port,
            tls: conn.tls,
            protocol: meta.protocol,
            stream_id: meta.stream_id,
            method: meta.method,
            target: meta.target,
            authority: meta.authority,
            headers: meta.headers,
            body_size: meta.body_size,
            status: meta.status,
        });
    }
}

pub struct Sensor {
    pub http_addr: SocketAddr,
    pub https_addr: SocketAddr,
    tasks: Vec<JoinHandle<()>>,
}

impl Sensor {
    pub async fn start(config: Config) -> Result<Self> {
        let persona = Persona::load(&config.persona)?;
        let streams_dir = config.data_dir.join(STREAMS_DIR);
        let tls_dir = config.data_dir.join(TLS_DIR);
        for dir in [&streams_dir, &tls_dir] {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        let tls_config = tls::server_config(&tls_dir, persona.hostname.as_deref())?;
        let acceptor = TlsAcceptor::from(Arc::new(tls_config));

        let shared = Arc::new(Shared {
            persona,
            requests: JsonlWriter::open(&config.data_dir.join(REQUESTS_LOG)).await?,
            connections: JsonlWriter::open(&config.data_dir.join(CONNECTIONS_LOG)).await?,
            sessions: AttackSessions::new(ATTACK_SESSION_IDLE, ATTACK_SESSION_CAPACITY),
            streams_dir,
        });

        let http = bind(config.bind, config.http_port).await?;
        let https = bind(config.bind, config.https_port).await?;
        let http_addr = http.local_addr()?;
        let https_addr = https.local_addr()?;
        tracing::info!(persona = shared.persona.name, %http_addr, %https_addr, "sensor listening");
        Ok(Self {
            http_addr,
            https_addr,
            tasks: vec![
                tokio::spawn(accept_loop(http, shared.clone(), None)),
                tokio::spawn(accept_loop(https, shared, Some(acceptor))),
            ],
        })
    }
}

impl Drop for Sensor {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// Binds `addr:port`. An unspecified IPv6 address is dual-stack on Linux; if
/// the host has no IPv6, fall back to `0.0.0.0`.
async fn bind(addr: IpAddr, port: u16) -> Result<TcpListener> {
    match TcpListener::bind((addr, port)).await {
        Ok(l) => Ok(l),
        Err(e) if addr.is_unspecified() && addr.is_ipv6() => {
            tracing::warn!(error = %e, port, "IPv6 bind failed; falling back to IPv4");
            TcpListener::bind((Ipv4Addr::UNSPECIFIED, port))
                .await
                .with_context(|| format!("binding 0.0.0.0:{port}"))
        }
        Err(e) => Err(e).with_context(|| format!("binding {addr}:{port}")),
    }
}

async fn accept_loop(listener: TcpListener, shared: Arc<Shared>, tls: Option<TlsAcceptor>) {
    loop {
        match listener.accept().await {
            Ok((tcp, peer)) => {
                tokio::spawn(handle_connection(tcp, peer, shared.clone(), tls.clone()));
            }
            Err(e) => {
                // Typically EMFILE; back off rather than spin.
                tracing::warn!(error = %e, "accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

async fn handle_connection(tcp: TcpStream, peer: SocketAddr, shared: Arc<Shared>, tls: Option<TlsAcceptor>) {
    let ts_open = now();
    let _ = tcp.set_nodelay(true);
    let conn = ConnInfo {
        conn_id: Uuid::now_v7(),
        // Dual-stack sockets report IPv4 clients as ::ffff:a.b.c.d.
        src_ip: peer.ip().to_canonical(),
        src_port: peer.port(),
        dst_port: tcp.local_addr().map_or(0, |a| a.port()),
        tls: tls.is_some(),
    };
    let attack_session_id = shared.sessions.touch(conn.src_ip);
    let capture = match StreamCapture::create(&shared.streams_dir, conn.conn_id).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "cannot create stream files; dropping connection");
            return;
        }
    };

    let (mut sni, mut alpn, mut tls_error) = (None, None, None);
    let requests = match tls {
        None => http1::serve(capture.tee(tcp), &shared, &conn).await,
        Some(acceptor) => match timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
            Ok(Ok(stream)) => {
                let session = stream.get_ref().1;
                sni = session.server_name().map(str::to_owned);
                alpn = session.alpn_protocol().map(|p| String::from_utf8_lossy(p).into_owned());
                if alpn.as_deref() == Some("h2") {
                    http2::serve(capture.tee(stream), shared.clone(), conn).await
                } else {
                    http1::serve(capture.tee(stream), &shared, &conn).await
                }
            }
            Ok(Err(e)) => {
                tls_error = Some(e.to_string());
                0
            }
            Err(_) => {
                tls_error = Some("handshake timeout".to_owned());
                0
            }
        },
    };

    let bytes_c2s = capture.counters().c2s.load(Ordering::Relaxed);
    let bytes_s2c = capture.counters().s2c.load(Ordering::Relaxed);
    if let Err(e) = capture.finish().await {
        tracing::error!(conn_id = %conn.conn_id, error = %e, "stream capture write failed");
    }
    shared.connections.write(&ConnectionRecord {
        ts_open,
        ts_close: now(),
        conn_id: conn.conn_id,
        attack_session_id,
        src_ip: conn.src_ip,
        src_port: conn.src_port,
        dst_port: conn.dst_port,
        tls: conn.tls,
        sni,
        alpn,
        tls_error,
        bytes_c2s,
        bytes_s2c,
        requests,
    });
}
