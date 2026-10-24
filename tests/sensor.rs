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
    // Wire capture needs CAP_NET_RAW; it is exercised by the harness.
    cli.pcap = Some(false);
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
async fn http1_chunked_request_is_answered_logged_and_captured_losslessly() {
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

    // Stream files hold everything but body payloads; bodies are stored apart.
    let c2s = stream(&data, req, "c2s");
    let s2c = stream(&data, req, "s2c");
    let elided: &[u8] = b"POST /?p=1 HTTP/1.1\r\nHost: sensor.test\r\nX-Mixed-CASE: a\r\n\
        Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n\
        5\r\n\r\n3;ext=1\r\n\r\n0\r\nX-Trailer: t\r\n\r\n";
    assert_eq!(c2s, elided);
    assert_eq!(body_file(&data, &req["body"]), b"helloabc");
    assert_eq!(req["body"]["sha256"], req["body"]["file"]);
    assert_eq!(req["c2s_range"], serde_json::json!([0, elided.len()]));
    assert_eq!(s2c, head.as_bytes().iter().chain(b"\r\n\r\n").copied().collect::<Vec<_>>());
    assert_eq!(req["s2c_range"], serde_json::json!([0, s2c.len()]));
    assert_eq!(body_file(&data, &req["response_body"]), b"<html>wp</html>");
    // Lossless: stored stream bytes + body bytes = what crossed the wire.
    assert_eq!(conns[0]["bytes_c2s"], request.len());
    assert_eq!(c2s.len() + 8, request.len());
}

fn stream(data: &Path, req: &Value, dir: &str) -> Vec<u8> {
    let id = req["conn_id"].as_str().unwrap();
    std::fs::read(data.join(format!("streams/{id}.{dir}"))).unwrap()
}

fn body_file(data: &Path, body: &Value) -> Vec<u8> {
    std::fs::read(data.join("bodies").join(body["file"].as_str().unwrap())).unwrap()
}

/// Writes `raw` on a fresh connection and reads until the sensor closes.
async fn exchange(sensor: &Sensor, raw: &[u8]) -> Vec<u8> {
    let mut tcp = TcpStream::connect(sensor.http_addr).await.unwrap();
    tcp.write_all(raw).await.unwrap();
    let mut response = Vec::new();
    tcp.read_to_end(&mut response).await.unwrap();
    response
}

#[tokio::test]
async fn keep_alive_requests_get_contiguous_offsets_into_the_stream_files() {
    let dir = tempfile::tempdir().unwrap();
    let sensor = start(dir.path()).await;
    let data = dir.path().join("data");

    let first: &[u8] = b"POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\nbody";
    let second: &[u8] = b"\r\nGET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    let response = exchange(&sensor, &[first, second].concat()).await;

    let reqs = lines(&data.join("requests.jsonl"), 2).await;
    lines(&data.join("connections.jsonl"), 1).await;
    let c2s = stream(&data, &reqs[0], "c2s");
    let s2c = stream(&data, &reqs[0], "s2c");
    let slice = |buf: &[u8], r: &Value| buf[r[0].as_u64().unwrap() as usize..r[1].as_u64().unwrap() as usize].to_vec();
    // Body payload "body" is elided from the first request's range.
    assert_eq!(slice(&c2s, &reqs[0]["c2s_range"]), b"POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\n");
    // The leading empty line belongs to the second request.
    assert_eq!(slice(&c2s, &reqs[1]["c2s_range"]), second);
    assert_eq!(reqs[0]["c2s_range"][1], reqs[1]["c2s_range"][0]);
    assert_eq!(reqs[1]["c2s_range"][1], c2s.len());

    // Response ranges + response bodies rebuild exactly what the client got.
    let mut rebuilt = Vec::new();
    for r in &reqs {
        rebuilt.extend(slice(&s2c, &r["s2c_range"]));
        rebuilt.extend(body_file(&data, &r["response_body"]));
    }
    assert_eq!(rebuilt, response);
    assert_eq!(reqs[0]["status"], 404);
    assert_eq!(reqs[1]["status"], 200);
}

#[tokio::test]
async fn identical_bodies_are_stored_once_across_connections() {
    let dir = tempfile::tempdir().unwrap();
    let sensor = start(dir.path()).await;
    let data = dir.path().join("data");

    // Larger than the in-memory threshold, so the temp-file path is used.
    let payload: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let mut request = format!("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", payload.len())
        .into_bytes();
    request.extend_from_slice(&payload);
    for _ in 0..3 {
        exchange(&sensor, &request).await;
    }

    let reqs = lines(&data.join("requests.jsonl"), 3).await;
    // Body files land when each connection's capture finishes.
    lines(&data.join("connections.jsonl"), 3).await;
    let file = reqs[0]["body"]["file"].clone();
    assert!(reqs.iter().all(|r| r["body"]["file"] == file && r["body"]["stored"] == payload.len()));
    assert_eq!(body_file(&data, &reqs[0]["body"]), payload);
    // One request body + one persona response body; no temp leftovers.
    let stored: Vec<_> = std::fs::read_dir(data.join("bodies")).unwrap().flatten().filter(|e| e.path().is_file()).collect();
    assert_eq!(stored.len(), 2);
    assert_eq!(std::fs::read_dir(data.join("bodies/tmp")).unwrap().count(), 0);
}

#[tokio::test]
async fn connection_cap_keeps_a_prefix_and_the_request_is_still_served() {
    let dir = tempfile::tempdir().unwrap();
    let cli = Overrides { max_connection_bytes: Some("1000".parse().unwrap()), ..Default::default() };
    let sensor = start_with(dir.path(), cli, Overrides::default()).await;
    let data = dir.path().join("data");

    let head = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5000\r\nConnection: close\r\n\r\n";
    let payload = vec![b'z'; 5000];
    let response = exchange(&sensor, &[&head[..], &payload].concat()).await;
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));

    let req = &lines(&data.join("requests.jsonl"), 1).await[0];
    let conn = &lines(&data.join("connections.jsonl"), 1).await[0];
    let kept = 1000 - head.len();
    assert_eq!(req["body_size"], 5000);
    assert_eq!(req["body"]["size"], 5000);
    assert_eq!(req["body"]["stored"], kept);
    assert_ne!(req["body"]["sha256"], req["body"]["file"]);
    assert_eq!(body_file(&data, &req["body"]), vec![b'z'; kept]);
    assert_eq!(conn["capture_truncated"], true);
    assert_eq!(conn["bytes_c2s"], head.len() + 5000);
    assert_eq!(stream(&data, req, "c2s"), head);
    assert!(stream(&data, req, "s2c").is_empty());
}

#[tokio::test]
async fn total_cap_rotates_out_the_oldest_connections() {
    let dir = tempfile::tempdir().unwrap();
    let cli = Overrides { max_total_bytes: Some("64KiB".parse().unwrap()), ..Default::default() };
    let sensor = start_with(dir.path(), cli, Overrides::default()).await;
    let data = dir.path().join("data");

    for i in 0..6u8 {
        let mut request = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 20000\r\nConnection: close\r\n\r\n".to_vec();
        request.extend(std::iter::repeat_n(i, 20_000));
        exchange(&sensor, &request).await;
        // Distinct mtimes so "oldest" is well defined.
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let reqs = lines(&data.join("requests.jsonl"), 6).await;
    lines(&data.join("connections.jsonl"), 6).await;

    let exists = |r: &Value| data.join("bodies").join(r["body"]["file"].as_str().unwrap()).exists();
    for _ in 0..200 {
        if !exists(&reqs[0]) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let id = |r: &Value| r["conn_id"].as_str().unwrap().to_owned();
    assert!(!exists(&reqs[0]), "oldest body survived rotation");
    assert!(!data.join(format!("streams/{}.c2s", id(&reqs[0]))).exists());
    assert!(exists(&reqs[5]), "newest body was rotated");
    assert!(data.join(format!("streams/{}.c2s", id(&reqs[5]))).exists());
    let used: u64 = walk_size(&data);
    assert!(used <= 64 * 1024, "data dir is {used} bytes");
}

fn walk_size(dir: &Path) -> u64 {
    std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| if e.path().is_dir() { walk_size(&e.path()) } else { e.metadata().unwrap().len() })
        .sum()
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
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
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
    // Apache's mod_http2 order: the response's own headers, then date, server.
    let names: Vec<&str> = resp.headers().keys().map(|k| k.as_str()).collect();
    assert_eq!(names, ["x-powered-by", "content-length", "content-type", "date", "server"]);
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

    // DATA payloads are stored as one body; frames stay in the stream file.
    let mut expected = vec![b'x'; 70_000];
    expected.extend_from_slice(b"tail");
    assert_eq!(body_file(&data, &req["body"]), expected);
    assert_eq!(body_file(&data, &req["response_body"]), b"<html>wp</html>");
    let c2s = stream(&data, req, "c2s");
    let s2c = stream(&data, req, "s2c");
    assert!(c2s.starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"));
    assert!(!c2s.windows(64).any(|w| w.iter().all(|&b| b == b'x')), "body bytes leaked into stream");
    assert_eq!(c2s.len() as u64 + 70_004, conn["bytes_c2s"].as_u64().unwrap());
    assert_eq!(s2c.len() as u64 + 15, conn["bytes_s2c"].as_u64().unwrap());
    let [cs, ce] = [req["c2s_range"][0].as_u64().unwrap(), req["c2s_range"][1].as_u64().unwrap()];
    let [ss, se] = [req["s2c_range"][0].as_u64().unwrap(), req["s2c_range"][1].as_u64().unwrap()];
    assert!(cs > 24 && cs < ce && ce <= c2s.len() as u64, "{cs}..{ce}");
    assert!(ss < se && se <= s2c.len() as u64, "{ss}..{se}");

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
