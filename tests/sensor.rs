//! In-process sensor on ephemeral ports: bytes on the wire and files on disk.

use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

use bytes::Bytes;
use php_tarpit::{Overrides, PersonaFile, Sensor, Settings};
use rustls::{ClientConfig, KeyLog, RootCertStore};
use rustls_pki_types::{CertificateDer, ServerName, pem::PemObject};
use serde_json::Value;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::TlsConnector;

const PERSONA: &str = r#"
name = "test"

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
  ["X-Powered-By", "PHP/{php_version}"],
  ["Content-Length", "{content_length}"],
  ["Keep-Alive", "timeout=5, max=100"],
  ["Connection", "Keep-Alive"],
  ["Content-Type", "text/html; charset=UTF-8"],
]
body = "<html>wp</html>"

[not_found]
status = 404
headers = [["Date", "{date}"], ["Content-Length", "{content_length}"]]
body = "<address>Apache/{apache_version} (Debian) Server at {hostname} Port 80</address> {unknown}"

[bad_request]
status = 400
headers = [["Content-Length", "{content_length}"], ["Connection", "close"]]
body = "bad"
"#;

/// Starts the sensor with `cli` and `env` layered over the test persona; the
/// data directory is always `dir/data`.
async fn start_with(dir: &Path, mut cli: Overrides, env: Overrides) -> Sensor {
    let persona_path = dir.join("persona.toml");
    std::fs::write(&persona_path, PERSONA).unwrap();
    let persona = PersonaFile::load(&persona_path).unwrap();
    cli.data_dir = Some(dir.join("data"));
    let settings = Settings::resolve(&cli, &env, &persona.settings).unwrap();
    Sensor::start(settings, persona).await.unwrap()
}

async fn start(dir: &Path) -> Sensor {
    start_with(dir, Overrides::default(), Overrides::default()).await
}

/// Sends one HTTP/1.1 request with `Connection: close`; returns the raw response.
async fn get(sensor: &Sensor, path: &str) -> String {
    let mut tcp = TcpStream::connect(sensor.http_addr).await.unwrap();
    let req = format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    tcp.write_all(req.as_bytes()).await.unwrap();
    let mut response = String::new();
    tcp.read_to_string(&mut response).await.unwrap();
    response
}

/// Polls a JSONL file until it has `n` lines (writes are asynchronous).
async fn lines(path: &Path, n: usize) -> Vec<Value> {
    for _ in 0..200 {
        if let Ok(text) = std::fs::read_to_string(path) {
            let v: Vec<Value> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
            if v.len() >= n {
                return v;
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("{} never reached {n} lines", path.display());
}

#[tokio::test]
async fn http1_chunked_request_is_answered_logged_and_captured_byte_for_byte() {
    let dir = tempfile::tempdir().unwrap();
    let sensor = start(dir.path()).await;
    let data = dir.path().join("data");

    let request: &[u8] = b"POST /?p=1 HTTP/1.1\r\nHost: sensor.test\r\nX-Mixed-CASE: a\r\n\
        Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n\
        5\r\nhello\r\n3;ext=1\r\nabc\r\n0\r\nX-Trailer: t\r\n\r\n";
    let mut tcp = TcpStream::connect(sensor.http_addr).await.unwrap();
    tcp.write_all(request).await.unwrap();
    let mut response = Vec::new();
    tcp.read_to_end(&mut response).await.unwrap();

    // Persona header order and case; closing drops Keep-Alive.
    let text = String::from_utf8(response.clone()).unwrap();
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    let names: Vec<&str> = head.lines().skip(1).map(|l| l.split_once(": ").unwrap().0).collect();
    assert!(head.starts_with("HTTP/1.1 200 OK\r\n"));
    assert_eq!(names, ["Date", "Server", "X-Powered-By", "Content-Length", "Connection", "Content-Type"]);
    assert!(head.contains("\r\nConnection: close\r\n"));
    assert!(head.contains("\r\nContent-Length: 15\r\n"));
    assert_eq!(body, "<html>wp</html>");

    let conns = lines(&data.join("connections.jsonl"), 1).await;
    let req = &lines(&data.join("requests.jsonl"), 1).await[0];
    assert_eq!(req["protocol"], "HTTP/1.1");
    assert_eq!(req["method"], "POST");
    assert_eq!(req["target"], "/?p=1");
    assert_eq!(req["body_size"], 8);
    assert_eq!(req["status"], 200);
    assert_eq!(req["src_ip"], "127.0.0.1");
    assert_eq!(req["headers"][1], serde_json::json!(["X-Mixed-CASE", "a"]));
    assert_eq!(req["attack_session_id"], conns[0]["attack_session_id"]);
    assert_eq!(req["conn_id"], conns[0]["conn_id"]);

    let id = req["conn_id"].as_str().unwrap();
    let streams = data.join("streams");
    assert_eq!(std::fs::read(streams.join(format!("{id}.c2s"))).unwrap(), request);
    assert_eq!(std::fs::read(streams.join(format!("{id}.s2c"))).unwrap(), response);
}

#[tokio::test]
async fn malformed_chunked_body_gets_persona_400_and_is_still_logged() {
    let dir = tempfile::tempdir().unwrap();
    let sensor = start(dir.path()).await;

    let mut tcp = TcpStream::connect(sensor.http_addr).await.unwrap();
    tcp.write_all(b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n").await.unwrap();
    let mut response = Vec::new();
    tcp.read_to_end(&mut response).await.unwrap();
    assert_eq!(response, b"HTTP/1.1 400 Bad Request\r\nContent-Length: 3\r\nConnection: close\r\n\r\nbad");

    let req = &lines(&dir.path().join("data/requests.jsonl"), 1).await[0];
    assert_eq!(req["status"], 400);
}

/// Records the secrets the client derives, to compare with the sensor's key log.
#[derive(Debug, Default)]
struct ClientKeys(Mutex<Vec<String>>);

impl KeyLog for ClientKeys {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        let line = format!("{label} {} {}", hex::encode(client_random), hex::encode(secret));
        self.0.lock().unwrap().push(line);
    }
}

#[tokio::test]
async fn http2_over_tls_lengthless_body_is_logged_and_key_log_matches_client_secrets() {
    let dir = tempfile::tempdir().unwrap();
    let cli = Overrides { hostname: Some("sensor.test".into()), ..Default::default() };
    let sensor = start_with(dir.path(), cli, Overrides::default()).await;
    let data = dir.path().join("data");

    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter(data.join("tls/cert.pem")).unwrap() {
        roots.add(cert.unwrap()).unwrap();
    }
    let keys = Arc::new(ClientKeys::default());
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut client = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.alpn_protocols = vec![b"h2".to_vec()];
    client.key_log = keys.clone();

    let tcp = TcpStream::connect(sensor.https_addr).await.unwrap();
    let name = ServerName::try_from("sensor.test").unwrap();
    let tls = TlsConnector::from(Arc::new(client)).connect(name, tcp).await.unwrap();
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));

    let (h2, conn) = h2::client::handshake(tls).await.unwrap();
    let driver = tokio::spawn(conn);
    let mut h2 = h2.ready().await.unwrap();
    // No content-length: the body is defined only by END_STREAM.
    let req = http::Request::post("https://sensor.test/").body(()).unwrap();
    let (resp, mut send) = h2.send_request(req, false).unwrap();
    send.send_data(Bytes::from(vec![b'x'; 70_000]), false).unwrap();
    send.send_data(Bytes::from_static(b"tail"), true).unwrap();
    let resp = resp.await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["x-powered-by"], "PHP/8.3.30");
    assert!(resp.headers().get("connection").is_none());
    let mut body = resp.into_body();
    let mut got = Vec::new();
    while let Some(chunk) = body.data().await {
        got.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(got, b"<html>wp</html>");
    drop(h2);
    driver.await.unwrap().unwrap();

    let req = &lines(&data.join("requests.jsonl"), 1).await[0];
    assert_eq!(req["protocol"], "HTTP/2");
    assert_eq!(req["tls"], true);
    assert_eq!(req["authority"], "sensor.test");
    assert_eq!(req["body_size"], 70_004);
    let conn = &lines(&data.join("connections.jsonl"), 1).await[0];
    assert_eq!(conn["alpn"], "h2");
    assert_eq!(conn["sni"], "sensor.test");

    let server_log = std::fs::read_to_string(data.join("tls/keylog.txt")).unwrap();
    let client_lines = keys.0.lock().unwrap().clone();
    assert!(client_lines.iter().any(|l| l.starts_with("CLIENT_TRAFFIC_SECRET_0 ")));
    for line in &client_lines {
        assert!(server_log.lines().any(|s| s == line), "sensor key log lacks {line}");
    }
}

#[tokio::test]
async fn cli_and_env_override_persona_settings_on_the_wire() {
    let dir = tempfile::tempdir().unwrap();
    let cli = Overrides { php_version: Some("8.3.7".into()), ..Default::default() };
    let env = Overrides::from_env(|k| match k {
        "PHP_TARPIT_APACHE_VERSION" => Some("2.4.99".into()),
        // Lower precedence than the CLI flag: must lose.
        "PHP_TARPIT_PHP_VERSION" => Some("8.3.1".into()),
        _ => None,
    })
    .unwrap();
    let sensor = start_with(dir.path(), cli, env).await;

    let home = get(&sensor, "/").await;
    assert!(home.contains("\r\nServer: Apache/2.4.99 (Debian)\r\n"), "{home}");
    assert!(home.contains("\r\nX-Powered-By: PHP/8.3.7\r\n"), "{home}");
    // Body substitution; unknown braces pass through untouched.
    let not_found = get(&sensor, "/missing").await;
    assert!(not_found.contains("<address>Apache/2.4.99 (Debian) Server at "), "{not_found}");
    assert!(not_found.ends_with(" {unknown}"), "{not_found}");
}

#[tokio::test]
async fn hostname_is_kept_across_restarts_and_regenerated_when_changed() {
    let dir = tempfile::tempdir().unwrap();
    let tls = dir.path().join("data/tls");

    // No hostname configured: a random one is generated, then kept.
    let sensor = start(dir.path()).await;
    let cert = std::fs::read(tls.join("cert.pem")).unwrap();
    let hostname = std::fs::read_to_string(tls.join("hostname")).unwrap().trim().to_owned();
    assert!(get(&sensor, "/x").await.contains(&format!("Server at {hostname} Port")));
    drop(sensor);
    let sensor = start(dir.path()).await;
    assert_eq!(std::fs::read(tls.join("cert.pem")).unwrap(), cert);
    assert!(get(&sensor, "/x").await.contains(&format!("Server at {hostname} Port")));
    drop(sensor);

    // An explicit, different hostname replaces the certificate.
    let cli = Overrides { hostname: Some("web01.example.com".into()), ..Default::default() };
    let sensor = start_with(dir.path(), cli, Overrides::default()).await;
    assert_ne!(std::fs::read(tls.join("cert.pem")).unwrap(), cert);
    assert!(get(&sensor, "/x").await.contains("Server at web01.example.com Port"));
}
