//! Contract test (ADR 0001): the real sensor writes a data directory over real
//! HTTP/1.1, HTTP/1.1-over-TLS and HTTP/2-over-TLS traffic, and the viewer
//! renders it. A sensor change to a JSONL field the viewer reads fails here.

use std::{path::Path, sync::Arc, time::Duration};

use bytes::Bytes;
use php_tarpit::{Overrides, PersonaFile, Sensor, Settings};
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::{CertificateDer, ServerName, pem::PemObject};
use serde_json::Value;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::TlsConnector;

const PERSONA: &str = r#"
name = "contract"

[settings]
bind = "127.0.0.1"
http_port = 0
https_port = 0
apache_version = "2.4.62"
php_version = "8.3.30"

[[route]]
path = "/"
status = 200
headers = [
  ["Date", "{date}"],
  ["Server", "Apache/{apache_version} (Debian)"],
  ["Content-Length", "{content_length}"],
  ["Content-Type", "text/html; charset=UTF-8"],
]
body = "<html>wp</html>"

[not_found]
status = 404
headers = [["Date", "{date}"], ["Content-Length", "{content_length}"]]
body = "not found"

[bad_request]
status = 400
headers = [["Content-Length", "{content_length}"], ["Connection", "close"]]
body = "bad"
"#;

const HOSTNAME: &str = "sensor.test";
/// Distinctive, HTML-hostile request body for the plain HTTP/1.1 POST.
const POST_BODY: &[u8] = b"<?php echo \"contract-7f3a\" & 1; ?>";

/// Starts the sensor on ephemeral loopback ports with data in `dir/data`.
async fn start_sensor(dir: &Path) -> Sensor {
    let persona_path = dir.join("persona.toml");
    std::fs::write(&persona_path, PERSONA).unwrap();
    let persona = PersonaFile::load(&persona_path).unwrap();
    let cli = Overrides {
        data_dir: Some(dir.join("data")),
        hostname: Some(HOSTNAME.into()),
        // Wire capture needs CAP_NET_RAW; not part of the JSONL contract.
        pcap: Some(false),
        ..Default::default()
    };
    let settings = Settings::resolve(&cli, &Overrides::default(), &persona.settings).unwrap();
    Sensor::start(settings, persona).await.unwrap()
}

/// Polls a JSONL file until it has `n` lines (the sensor writes asynchronously,
/// connections only at close).
async fn lines(path: &Path, n: usize) -> Vec<Value> {
    for _ in 0..3000 {
        if let Ok(text) = std::fs::read_to_string(path) {
            let v: Vec<Value> = text
                .lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect();
            if v.len() >= n {
                return v;
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("{} never reached {n} lines", path.display());
}

fn tls_connector(data: &Path, alpn: &[u8]) -> TlsConnector {
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter(data.join("tls/cert.pem")).unwrap() {
        roots.add(cert.unwrap()).unwrap();
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut client = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.alpn_protocols = vec![alpn.to_vec()];
    TlsConnector::from(Arc::new(client))
}

/// The request head of the plain POST; the stream file holds exactly this
/// (body payloads are stored apart).
fn post_head() -> String {
    format!(
        "POST /contract.php?x=1 HTTP/1.1\r\nHost: {HOSTNAME}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        POST_BODY.len()
    )
}

async fn http1_post(sensor: &Sensor) {
    let mut tcp = TcpStream::connect(sensor.http_addr).await.unwrap();
    tcp.write_all(post_head().as_bytes()).await.unwrap();
    tcp.write_all(POST_BODY).await.unwrap();
    let mut response = Vec::new();
    tcp.read_to_end(&mut response).await.unwrap();
    assert!(
        response.starts_with(b"HTTP/1.1 "),
        "{}",
        String::from_utf8_lossy(&response)
    );
}

async fn http1_tls_get(sensor: &Sensor, data: &Path) {
    let tcp = TcpStream::connect(sensor.https_addr).await.unwrap();
    let name = ServerName::try_from(HOSTNAME).unwrap();
    let mut tls = tls_connector(data, b"http/1.1")
        .connect(name, tcp)
        .await
        .unwrap();
    let req = format!("GET /tls-get HTTP/1.1\r\nHost: {HOSTNAME}\r\nConnection: close\r\n\r\n");
    tls.write_all(req.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    // The peer may close without close_notify; what was read is enough.
    let _ = tls.read_to_end(&mut response).await;
    assert!(
        response.starts_with(b"HTTP/1.1 "),
        "{}",
        String::from_utf8_lossy(&response)
    );
}

async fn http2_tls_post(sensor: &Sensor, data: &Path) {
    let tcp = TcpStream::connect(sensor.https_addr).await.unwrap();
    let name = ServerName::try_from(HOSTNAME).unwrap();
    let tls = tls_connector(data, b"h2").connect(name, tcp).await.unwrap();
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
    let (h2, conn) = h2::client::handshake(tls).await.unwrap();
    let driver = tokio::spawn(conn);
    let mut h2 = h2.ready().await.unwrap();
    let req = http::Request::post(format!("https://{HOSTNAME}/h2-path"))
        .body(())
        .unwrap();
    let (resp, mut send) = h2.send_request(req, false).unwrap();
    send.send_data(Bytes::from_static(b"h2-body"), true)
        .unwrap();
    let resp = resp.await.unwrap();
    assert!(resp.status().as_u16() >= 200);
    let mut body = resp.into_body();
    while let Some(chunk) = body.data().await {
        chunk.unwrap();
    }
    // Close the TCP connection now instead of waiting out the sensor's idle
    // timeout; the connection record is written at close.
    drop(h2);
    driver.abort();
    let _ = driver.await;
}

struct Viewer {
    port: u16,
}

struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Reply {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

impl Viewer {
    async fn start(data: &Path) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let dir = data.to_owned();
        tokio::spawn(async move { php_tarpit_viewer::serve(listener, &dir).await.unwrap() });
        Self { port }
    }

    async fn get(&self, path: &str) -> Reply {
        let mut tcp = TcpStream::connect(("127.0.0.1", self.port)).await.unwrap();
        let head = format!(
            "GET {path} HTTP/1.1\r\nHost: localhost:{}\r\nConnection: close\r\n\r\n",
            self.port
        );
        tcp.write_all(head.as_bytes()).await.unwrap();
        let mut raw = Vec::new();
        tcp.read_to_end(&mut raw).await.unwrap();
        let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
        let head = String::from_utf8(raw[..split].to_vec()).unwrap();
        let mut lines = head.split("\r\n");
        let status = lines
            .next()
            .unwrap()
            .split(' ')
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        let headers = lines
            .filter_map(|l| {
                l.split_once(": ")
                    .map(|(n, v)| (n.to_owned(), v.to_owned()))
            })
            .collect();
        Reply {
            status,
            headers,
            body: raw[split + 4..].to_vec(),
        }
    }

    async fn page(&self, path: &str) -> String {
        let r = self.get(path).await;
        assert_eq!(r.status, 200, "{path}");
        r.text()
    }
}

/// Distinct `href="<prefix>…"` targets in page order.
fn links<'a>(page: &'a str, prefix: &str) -> Vec<&'a str> {
    let needle = format!("href=\"{prefix}");
    let mut out: Vec<&str> = Vec::new();
    for (i, _) in page.match_indices(&needle) {
        let start = i + 6;
        let end = start + page[start..].find('"').unwrap();
        let link = &page[start..end];
        if !out.contains(&link) {
            out.push(link);
        }
    }
    out
}

/// HTML text of `bytes` as the viewer must show it: `\r` made visible, then
/// HTML-escaped.
fn shown(bytes: &[u8]) -> String {
    std::str::from_utf8(bytes)
        .unwrap()
        .replace('\r', "\\r")
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[tokio::test]
async fn viewer_renders_what_the_real_sensor_logged() {
    let dir = tempfile::tempdir().unwrap();
    let sensor = start_sensor(dir.path()).await;
    let data = dir.path().join("data");

    http1_post(&sensor).await;
    http1_tls_get(&sensor, &data).await;
    http2_tls_post(&sensor, &data).await;

    let conns = lines(&data.join("connections.jsonl"), 3).await;
    let reqs = lines(&data.join("requests.jsonl"), 3).await;
    assert_eq!((conns.len(), reqs.len()), (3, 3));
    let post = reqs
        .iter()
        .find(|r| r["method"] == "POST" && r["protocol"] == "HTTP/1.1")
        .unwrap();

    let viewer = Viewer::start(&data).await;

    // Session list links every attack session the sensor logged.
    let index = viewer.page("/").await;
    let mut logged: Vec<String> = reqs
        .iter()
        .map(|r| format!("/session/{}", r["attack_session_id"].as_str().unwrap()))
        .collect();
    logged.sort();
    logged.dedup();
    let mut listed: Vec<String> = links(&index, "/session/")
        .into_iter()
        .map(str::to_owned)
        .collect();
    listed.sort();
    assert_eq!(listed, logged);

    // Session pages together list all three requests.
    let mut request_links = Vec::new();
    for session in &listed {
        let page = viewer.page(session).await;
        request_links.extend(links(&page, "/request/").into_iter().map(str::to_owned));
    }
    request_links.sort();
    let mut expected: Vec<String> = reqs
        .iter()
        .map(|r| format!("/request/{}/0", r["conn_id"].as_str().unwrap()))
        .collect();
    expected.sort();
    assert_eq!(request_links, expected, "one request per connection, seq 0");

    let mut details = Vec::new();
    for link in &request_links {
        details.push(viewer.page(link).await);
    }

    // POST detail: escaped body text and the exact client→server wire bytes.
    let post_page = &details[request_links
        .iter()
        .position(|l| *l == format!("/request/{}/0", post["conn_id"].as_str().unwrap()))
        .unwrap()];
    assert!(post_page.contains("/contract.php?x=1"));
    assert!(
        post_page.contains(&format!("<pre>{}</pre>", shown(POST_BODY))),
        "escaped body text"
    );
    assert!(!post_page.contains("<?php"), "body must not render raw");
    assert!(post_page.contains("HTTP/1.1"));
    let wire = shown(post_head().as_bytes());
    assert!(wire.starts_with("POST /contract.php?x=1 HTTP/1.1\\r\n"));
    assert!(
        post_page.contains(&format!("<pre>{wire}</pre>")),
        "exact c2s wire bytes"
    );
    assert!(post_page.contains(&format!(
        "Bytes 0–{} of the stream file.",
        post_head().len()
    )));

    // Body download returns the exact bytes.
    let body_links = links(post_page, "/body/");
    assert_eq!(
        body_links.len(),
        2,
        "request and response body: {body_links:?}"
    );
    let file = post["body"]["file"].as_str().unwrap();
    assert!(body_links.contains(&format!("/body/{file}").as_str()));
    let download = viewer.get(&format!("/body/{file}")).await;
    assert_eq!(download.status, 200);
    assert_eq!(
        download.header("content-type"),
        Some("application/octet-stream")
    );
    assert_eq!(download.body, POST_BODY);

    // TLS GET detail.
    let tls_get = details
        .iter()
        .find(|p| p.contains("/tls-get"))
        .expect("TLS GET detail");
    assert!(tls_get.contains("HTTP/1.1") && tls_get.contains("(TLS)"));
    assert!(
        tls_get.contains("GET /tls-get HTTP/1.1\\r\n"),
        "TLS GET plaintext wire bytes"
    );

    // HTTP/2 detail.
    let h2 = details
        .iter()
        .find(|p| p.contains("/h2-path"))
        .expect("HTTP/2 detail");
    assert!(h2.contains("<dd>HTTP/2 stream "), "protocol HTTP/2");
    assert!(h2.contains("(TLS)"));
    assert!(h2.contains("<pre>h2-body</pre>"));
}
