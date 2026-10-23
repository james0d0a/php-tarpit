//! Listeners and per-connection plumbing: capture, TLS, protocol dispatch, logging.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZeroUsize,
    sync::{Arc, Mutex},
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
    capture::{ConnCapture, MessageCapture},
    config::Settings,
    h2capture::H2Capture,
    http1, http2,
    log::{ConnectionRecord, JsonlWriter, RequestRecord, now},
    persona::{Persona, PersonaFile, Vars},
    session::AttackSessions,
    storage::Storage,
    tls,
};

pub const REQUESTS_LOG: &str = "requests.jsonl";
pub const CONNECTIONS_LOG: &str = "connections.jsonl";
pub const TLS_DIR: &str = "tls";

const ATTACK_SESSION_IDLE: Duration = Duration::from_secs(5 * 60);
const ATTACK_SESSION_CAPACITY: NonZeroUsize = NonZeroUsize::new(10_000).unwrap();
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);

pub struct Shared {
    pub persona: Persona,
    requests: JsonlWriter,
    connections: JsonlWriter,
    sessions: AttackSessions,
    storage: Arc<Storage>,
    max_connection_bytes: u64,
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
    pub fn log_request(&self, conn: &ConnInfo, meta: RequestMeta, capture: MessageCapture) {
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
            c2s_range: capture.c2s_range,
            s2c_range: capture.s2c_range,
            body: capture.body,
            response_body: capture.response_body,
        });
    }
}

pub struct Sensor {
    pub http_addr: SocketAddr,
    pub https_addr: SocketAddr,
    tasks: Vec<JoinHandle<()>>,
}

impl Sensor {
    /// Starts a sensor presenting `persona` with resolved `settings`.
    pub async fn start(settings: Settings, persona: PersonaFile) -> Result<Self> {
        let tls_dir = settings.data_dir.join(TLS_DIR);
        std::fs::create_dir_all(&tls_dir).with_context(|| format!("creating {}", tls_dir.display()))?;
        let storage = Storage::open(&settings.data_dir, settings.max_total_bytes)?;
        let (tls_config, hostname) = tls::server_config(&tls_dir, settings.hostname.as_deref())?;
        let acceptor = TlsAcceptor::from(Arc::new(tls_config));
        let persona = Persona::build(
            persona,
            &Vars {
                hostname: &hostname,
                apache_version: &settings.apache_version,
                php_version: &settings.php_version,
            },
        )
        .context("building persona")?;

        let shared = Arc::new(Shared {
            persona,
            requests: JsonlWriter::open(&settings.data_dir.join(REQUESTS_LOG)).await?,
            connections: JsonlWriter::open(&settings.data_dir.join(CONNECTIONS_LOG)).await?,
            sessions: AttackSessions::new(ATTACK_SESSION_IDLE, ATTACK_SESSION_CAPACITY),
            storage: storage.clone(),
            max_connection_bytes: settings.max_connection_bytes,
        });

        let http = bind(settings.bind, settings.http_port).await?;
        let https = bind(settings.bind, settings.https_port).await?;
        let http_addr = http.local_addr()?;
        let https_addr = https.local_addr()?;
        tracing::info!(
            persona = shared.persona.name,
            hostname,
            apache_version = settings.apache_version,
            php_version = settings.php_version,
            data_dir = %settings.data_dir.display(),
            max_connection_bytes = settings.max_connection_bytes,
            max_total_bytes = settings.max_total_bytes,
            %http_addr,
            %https_addr,
            "sensor listening"
        );
        Ok(Self {
            http_addr,
            https_addr,
            tasks: vec![
                tokio::spawn(accept_loop(http, shared.clone(), None)),
                tokio::spawn(accept_loop(https, shared, Some(acceptor))),
                tokio::spawn(storage.rotation_task()),
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
    let mut capture =
        match ConnCapture::create(shared.storage.clone(), conn.conn_id, shared.max_connection_bytes).await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, "cannot create stream files; dropping connection");
                return;
            }
        };

    let (mut sni, mut alpn, mut tls_error) = (None, None, None);
    let (requests, stats) = match tls {
        None => (http1::serve(tcp, &shared, &conn, &mut capture).await, capture.finish().await),
        Some(acceptor) => match timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
            Ok(Ok(stream)) => {
                let session = stream.get_ref().1;
                sni = session.server_name().map(str::to_owned);
                alpn = session.alpn_protocol().map(|p| String::from_utf8_lossy(p).into_owned());
                if alpn.as_deref() == Some("h2") {
                    let h2 = Arc::new(Mutex::new(H2Capture::new(capture, shared.clone(), conn)));
                    let requests = http2::serve(stream, shared.clone(), h2.clone()).await;
                    // serve() joins every stream task and drops the tee.
                    let Some(h2) = Arc::into_inner(h2) else {
                        tracing::error!(conn_id = %conn.conn_id, "HTTP/2 capture still shared after close");
                        return;
                    };
                    (requests, h2.into_inner().expect("capture lock poisoned").finish().await)
                } else {
                    (http1::serve(stream, &shared, &conn, &mut capture).await, capture.finish().await)
                }
            }
            Ok(Err(e)) => {
                tls_error = Some(e.to_string());
                (0, capture.finish().await)
            }
            Err(_) => {
                tls_error = Some("handshake timeout".to_owned());
                (0, capture.finish().await)
            }
        },
    };
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
        bytes_c2s: stats.wire_c2s,
        bytes_s2c: stats.wire_s2c,
        capture_truncated: stats.truncated,
        requests,
    });
}
