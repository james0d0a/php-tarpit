//! In-process viewer on an ephemeral loopback port over a fixture data
//! directory: HTTP in, rendered pages and headers out.

use std::{fs, io::Write, path::PathBuf};

use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

const SESSION_A: &str = "01a16b3f-0000-7000-8000-00000000000a";
const SESSION_B: &str = "01a16b3f-0000-7000-8000-00000000000b";
const SESSION_C: &str = "01a16b3f-0000-7000-8000-00000000000c";
const CONN_A1: &str = "01a16b3f-0000-7000-8000-0000000000a1";
const CONN_A2: &str = "01a16b3f-0000-7000-8000-0000000000a2";
const CONN_B1: &str = "01a16b3f-0000-7000-8000-0000000000b1";
const CONN_C1: &str = "01a16b3f-0000-7000-8000-0000000000c1";
const SHELL: &[u8] = b"<?php system($_GET['c']); ?>\x1b[2J";

fn sha(byte: char) -> String {
    byte.to_string().repeat(64)
}

struct Fixture {
    _tmp: tempfile::TempDir,
    dir: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("data");
        for sub in ["bodies", "streams", "tls"] {
            fs::create_dir_all(dir.join(sub)).unwrap();
        }
        fs::write(dir.join("tls/key.pem"), "PRIVATE KEY").unwrap();
        fs::write(dir.join("requests.jsonl"), "").unwrap();
        fs::write(dir.join("connections.jsonl"), "").unwrap();
        Self { _tmp: tmp, dir }
    }

    fn append(&self, log: &str, text: &str) {
        let mut f = fs::OpenOptions::new()
            .append(true)
            .open(self.dir.join(log))
            .unwrap();
        f.write_all(text.as_bytes()).unwrap();
    }

    fn request(&self, r: Value) {
        self.append("requests.jsonl", &format!("{r}\n"));
    }

    fn connection(&self, c: Value) {
        self.append("connections.jsonl", &format!("{c}\n"));
    }

    /// A typical data directory: a bodiless probe session (A, two
    /// connections), a POST session (B) whose body is a first sighting, and a
    /// later session (C) resending the same body.
    fn standard() -> Self {
        let f = Self::new();
        f.connection(conn(
            CONN_A1,
            SESSION_A,
            "2026-10-24T00:00:00.000001Z",
            false,
        ));
        f.connection(conn(
            CONN_A2,
            SESSION_A,
            "2026-10-24T00:05:00.000001Z",
            false,
        ));
        let mut conn_b = conn(CONN_B1, SESSION_B, "2026-10-25T10:00:00.000001Z", true);
        conn_b["src_ip"] = json!("45.135.1.2");
        f.connection(conn_b);
        f.connection(conn(
            CONN_C1,
            SESSION_C,
            "2026-10-26T12:00:00.000001Z",
            false,
        ));
        f.request(req(
            CONN_A1,
            SESSION_A,
            "2026-10-24T00:00:00.100000Z",
            "HEAD",
            "/",
        ));
        f.request(req(
            CONN_A2,
            SESSION_A,
            "2026-10-24T00:05:00.100000Z",
            "GET",
            "/<script>alert(1)</script>",
        ));
        let mut post = req(
            CONN_B1,
            SESSION_B,
            "2026-10-25T10:00:00.100000Z",
            "POST",
            "/index.php?-d+auto_prepend_file%3dphp://input",
        );
        post["src_ip"] = json!("45.135.1.2");
        post["status"] = json!(404);
        post["headers"] = json!([["Host", "x"], ["X-Evil", "\"><img src=x onerror=alert(1)>"]]);
        post["body_size"] = json!(SHELL.len());
        post["body"] = json!({"sha256": sha('b'), "size": SHELL.len(), "stored": SHELL.len(), "file": sha('b')});
        post["c2s_range"] = json!([0, 5]);
        post["s2c_range"] = json!([0, 4]);
        f.request(post);
        let mut again = req(
            CONN_C1,
            SESSION_C,
            "2026-10-26T12:00:00.100000Z",
            "POST",
            "/again",
        );
        again["body_size"] = json!(SHELL.len());
        again["body"] = json!({"sha256": sha('b'), "size": SHELL.len(), "stored": SHELL.len(), "file": sha('b')});
        f.request(again);
        fs::write(f.dir.join("bodies").join(sha('b')), SHELL).unwrap();
        fs::write(
            f.dir.join("streams").join(format!("{CONN_B1}.c2s")),
            b"POST /AAAAAAA",
        )
        .unwrap();
        fs::write(
            f.dir.join("streams").join(format!("{CONN_B1}.s2c")),
            b"HTTP/1.1 404",
        )
        .unwrap();
        f
    }

    async fn start(&self) -> Viewer {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let dir = self.dir.clone();
        tokio::spawn(async move { php_tarpit_viewer::serve(listener, &dir).await.unwrap() });
        Viewer { port }
    }
}

fn conn(conn_id: &str, session: &str, ts: &str, truncated: bool) -> Value {
    json!({
        "ts_open": ts, "ts_close": ts, "conn_id": conn_id, "attack_session_id": session,
        "src_ip": "198.51.100.7", "src_port": 40000, "dst_port": 80, "tls": false,
        "bytes_c2s": 1, "bytes_s2c": 1, "capture_truncated": truncated, "requests": 1,
    })
}

fn req(conn_id: &str, session: &str, ts: &str, method: &str, target: &str) -> Value {
    json!({
        "ts": ts, "conn_id": conn_id, "attack_session_id": session,
        "src_ip": "198.51.100.7", "src_port": 40000, "dst_port": 80, "tls": false,
        "protocol": "HTTP/1.1", "method": method, "target": target,
        "headers": [["Host", "203.0.113.1"]], "body_size": 0, "status": 200,
        "c2s_range": null, "s2c_range": null,
    })
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
    async fn get(&self, path: &str) -> Reply {
        self.get_as(path, &format!("localhost:{}", self.port)).await
    }

    async fn get_as(&self, path: &str, host: &str) -> Reply {
        let mut tcp = TcpStream::connect(("127.0.0.1", self.port)).await.unwrap();
        let head = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
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
}

fn session_links(page: &str) -> Vec<&str> {
    page.match_indices("href=\"/session/")
        .map(|(i, _)| &page[i + 15..i + 51])
        .collect()
}

// ---- #11: session list, session page, security baseline -------------------

#[tokio::test]
async fn lists_attack_sessions_newest_first_with_counts() {
    let f = Fixture::standard();
    let v = f.start().await;
    let page = v.get("/").await.text();
    assert_eq!(session_links(&page), [SESSION_C, SESSION_B, SESSION_A]);
    assert!(page.contains("3 of 3 attack sessions"));
    assert!(page.contains("4 requests"));
}

#[tokio::test]
async fn session_page_lists_requests_in_order_with_connections() {
    let f = Fixture::standard();
    let v = f.start().await;
    let page = v.get(&format!("/session/{SESSION_A}")).await.text();
    let head = page.find("HEAD").unwrap();
    let get = page.find("GET").unwrap();
    assert!(head < get, "requests in log order");
    assert!(page.contains(&format!("/request/{CONN_A1}/0")));
    assert!(page.contains(&format!("/request/{CONN_A2}/0")));
    assert_eq!(
        page.matches("title=\"01a16b3f-0000-7000-8000-0000000000a")
            .count(),
        4,
        "2 connection rows + 2 request rows"
    );
}

#[tokio::test]
async fn unknown_session_and_bad_ids_are_404() {
    let f = Fixture::standard();
    let v = f.start().await;
    assert_eq!(
        v.get("/session/01a16b3f-0000-7000-8000-000000000999")
            .await
            .status,
        404
    );
    assert_eq!(v.get("/session/../../tls/key.pem").await.status, 404);
    assert_eq!(v.get("/request/not-a-uuid/0").await.status, 404);
}

#[tokio::test]
async fn rejects_non_loopback_host() {
    let f = Fixture::standard();
    let v = f.start().await;
    for host in [
        "evil.example",
        "evil.example:8080",
        "localhost.evil.example",
        "127.0.0.1.nip.io",
        "[::2]",
        "localhost:x",
    ] {
        assert_eq!(v.get_as("/", host).await.status, 403, "{host}");
    }
    for host in [
        "localhost",
        "LOCALHOST:1",
        "127.0.0.1:8080",
        "[::1]:8080",
        "[::1]",
    ] {
        assert_eq!(v.get_as("/", host).await.status, 200, "{host}");
    }
}

#[tokio::test]
async fn attacker_values_render_inert_with_security_headers() {
    let f = Fixture::standard();
    let v = f.start().await;
    for path in [
        "/".to_owned(),
        format!("/session/{SESSION_A}"),
        format!("/request/{CONN_B1}/0"),
    ] {
        let r = v.get(&path).await;
        assert_eq!(r.status, 200, "{path}");
        let csp = r.header("content-security-policy").unwrap();
        assert!(
            csp.contains("default-src 'none'") && !csp.contains("unsafe"),
            "{csp}"
        );
        assert_eq!(r.header("x-content-type-options"), Some("nosniff"));
        assert_eq!(r.header("referrer-policy"), Some("no-referrer"));
        let page = r.text();
        assert!(!page.contains("<script"), "{path}");
        assert!(!page.contains("<img"), "{path}");
        assert!(!page.contains("<?php"), "{path}");
        assert!(!page.contains('\x1b'), "{path}");
    }
    let detail = v.get(&format!("/request/{CONN_B1}/0")).await.text();
    assert!(detail.contains("&lt;?php system"));
    assert!(detail.contains("\\x1b[2J"));
    assert!(detail.contains("&quot;&gt;&lt;img src=x onerror=alert(1)&gt;"));
}

#[tokio::test]
async fn tolerates_unknown_fields_and_bad_lines() {
    let f = Fixture::standard();
    f.append("requests.jsonl", "not json\n{\"ts\": 1}\n\n");
    let mut extra = req(
        CONN_A1,
        SESSION_A,
        "2026-10-24T00:00:01.000000Z",
        "OPTIONS",
        "/new",
    );
    extra["added_by_a_future_sensor"] = json!({"stage": "leak"});
    f.request(extra);
    let v = f.start().await;
    let page = v.get(&format!("/session/{SESSION_A}")).await.text();
    assert!(page.contains("OPTIONS"));
}

// ---- #12: request detail, bodies, download ---------------------------------

#[tokio::test]
async fn request_detail_shows_headers_in_wire_order_and_body_views() {
    let f = Fixture::standard();
    let v = f.start().await;
    let page = v.get(&format!("/request/{CONN_B1}/0")).await.text();
    assert!(page.find(">Host<").unwrap() < page.find(">X-Evil<").unwrap());
    assert!(page.contains("<summary>Text</summary>") && page.contains("<summary>Hex</summary>"));
    assert!(page.contains("3c 3f 70 68 70"), "hex dump of <?php");
    assert!(page.contains(&format!("href=\"/body/{}\"", sha('b'))));
}

#[tokio::test]
async fn body_download_is_an_octet_stream_attachment() {
    let f = Fixture::standard();
    let v = f.start().await;
    let r = v.get(&format!("/body/{}", sha('b'))).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.header("content-type"), Some("application/octet-stream"));
    assert!(
        r.header("content-disposition")
            .unwrap()
            .starts_with("attachment")
    );
    assert_eq!(r.body, SHELL);
}

#[tokio::test]
async fn download_only_serves_logged_body_files() {
    let f = Fixture::standard();
    fs::write(f.dir.join("bodies").join(sha('c')), "unlogged").unwrap();
    let v = f.start().await;
    for path in [
        format!("/body/{}", sha('c')),
        "/body/..%2Ftls%2Fkey.pem".to_owned(),
        "/body/../tls/key.pem".to_owned(),
        "/tls/key.pem".to_owned(),
        format!("/body/{}", sha('B')),
    ] {
        let r = v.get(&path).await;
        assert_eq!(r.status, 404, "{path}");
        assert!(!r.text().contains("PRIVATE KEY"));
    }
}

#[tokio::test]
async fn rotated_body_shows_rotated_and_download_is_gone() {
    let f = Fixture::standard();
    fs::remove_file(f.dir.join("bodies").join(sha('b'))).unwrap();
    let v = f.start().await;
    let page = v.get(&format!("/request/{CONN_B1}/0")).await.text();
    assert!(page.contains("Rotated"));
    assert!(page.contains(&sha('b')), "sha256 still shown");
    assert_eq!(v.get(&format!("/body/{}", sha('b'))).await.status, 410);
}

#[tokio::test]
async fn large_body_is_truncated_in_page() {
    let f = Fixture::new();
    f.connection(conn(
        CONN_A1,
        SESSION_A,
        "2026-10-24T00:00:00.000001Z",
        false,
    ));
    let mut r = req(
        CONN_A1,
        SESSION_A,
        "2026-10-24T00:00:00.100000Z",
        "POST",
        "/",
    );
    r["body"] = json!({"sha256": sha('d'), "size": 200_000, "stored": 200_000, "file": sha('d')});
    f.request(r);
    fs::write(f.dir.join("bodies").join(sha('d')), vec![b'A'; 200_000]).unwrap();
    let v = f.start().await;
    let page = v.get(&format!("/request/{CONN_A1}/0")).await.text();
    assert!(page.contains("Showing the first 65536 bytes only."));
    assert!(page.len() < 1_000_000);
}

// ---- #13: wire bytes ---------------------------------------------------------

#[tokio::test]
async fn wire_bytes_follow_logged_ranges() {
    let f = Fixture::standard();
    let v = f.start().await;
    let page = v.get(&format!("/request/{CONN_B1}/0")).await.text();
    assert!(page.contains("<pre>POST </pre>"), "c2s bytes 0..5 only");
    assert!(page.contains("<pre>HTTP</pre>"), "s2c bytes 0..4 only");
    assert!(page.contains("capture was truncated"));
}

#[tokio::test]
async fn wire_bytes_missing_or_unrecorded() {
    let f = Fixture::standard();
    fs::remove_file(f.dir.join("streams").join(format!("{CONN_B1}.c2s"))).unwrap();
    let v = f.start().await;
    let page = v.get(&format!("/request/{CONN_B1}/0")).await.text();
    assert!(page.contains("Rotated: the stream file"));
    let probe = v.get(&format!("/request/{CONN_A1}/0")).await.text();
    assert!(probe.contains("No wire bytes recorded."));
    assert!(!probe.contains("capture was truncated"));
}

#[tokio::test]
async fn http2_wire_bytes_are_labelled_as_a_span() {
    let f = Fixture::new();
    let mut r = req(
        CONN_A1,
        SESSION_A,
        "2026-10-24T00:00:00.100000Z",
        "GET",
        "/",
    );
    r["protocol"] = json!("HTTP/2");
    r["stream_id"] = json!(3);
    r["c2s_range"] = json!([0, 2]);
    f.request(r);
    fs::write(
        f.dir.join("streams").join(format!("{CONN_A1}.c2s")),
        b"\x00\x01",
    )
    .unwrap();
    let v = f.start().await;
    let page = v.get(&format!("/request/{CONN_A1}/0")).await.text();
    assert!(page.contains("may include other streams"));
    assert!(page.contains("stream 3"));
}

// ---- #14: refresh ------------------------------------------------------------

#[tokio::test]
async fn appended_lines_appear_on_next_load() {
    let f = Fixture::standard();
    let v = f.start().await;
    assert!(v.get("/").await.text().contains("3 of 3"));
    f.request(req(
        CONN_A1,
        "01a16b3f-0000-7000-8000-00000000000d",
        "2026-10-27T00:00:00.000000Z",
        "GET",
        "/fresh",
    ));
    let page = v.get("/").await.text();
    assert!(page.contains("4 of 4"));
    assert!(page.contains("/fresh"));
}

#[tokio::test]
async fn partial_trailing_line_waits_until_complete() {
    let f = Fixture::standard();
    let v = f.start().await;
    let line = req(
        CONN_A1,
        SESSION_A,
        "2026-10-24T00:00:02.000000Z",
        "PUT",
        "/half",
    )
    .to_string();
    let (first, rest) = line.split_at(line.len() / 2);
    f.append("requests.jsonl", first);
    let r = v.get(&format!("/session/{SESSION_A}")).await;
    assert_eq!(r.status, 200);
    assert!(!r.text().contains("/half"));
    f.append("requests.jsonl", &format!("{rest}\n"));
    assert!(
        v.get(&format!("/session/{SESSION_A}"))
            .await
            .text()
            .contains("/half")
    );
}

#[tokio::test]
async fn replaced_log_triggers_rebuild() {
    let f = Fixture::standard();
    let v = f.start().await;
    assert!(v.get("/").await.text().contains("4 requests"));
    let path = f.dir.join("requests.jsonl");
    let tmp = f.dir.join("requests.jsonl.new");
    fs::write(
        &tmp,
        format!(
            "{}\n",
            req(
                CONN_A1,
                SESSION_A,
                "2026-10-24T00:00:00.100000Z",
                "HEAD",
                "/"
            )
        ),
    )
    .unwrap();
    fs::rename(&tmp, &path).unwrap();
    assert!(v.get("/").await.text().contains("1 requests"));
    // Shrunk in place.
    fs::write(&path, "").unwrap();
    assert!(v.get("/").await.text().contains("0 requests"));
}

// ---- #15: filters --------------------------------------------------------------

async fn listed(v: &Viewer, query: &str) -> Vec<String> {
    session_links(&v.get(&format!("/?{query}")).await.text())
        .into_iter()
        .map(str::to_owned)
        .collect()
}

#[tokio::test]
async fn each_filter_narrows_the_list() {
    let f = Fixture::standard();
    let v = f.start().await;
    assert_eq!(listed(&v, "body=1").await, [SESSION_C, SESSION_B]);
    assert_eq!(listed(&v, "min_requests=2").await, [SESSION_A]);
    assert_eq!(listed(&v, "method=head").await, [SESSION_A]);
    assert_eq!(listed(&v, "status=404").await, [SESSION_B]);
    assert_eq!(listed(&v, "target=auto_prepend").await, [SESSION_B]);
    assert_eq!(listed(&v, "ip=45.135.").await, [SESSION_B]);
    assert_eq!(listed(&v, "from=2026-10-25").await, [SESSION_C, SESSION_B]);
    assert_eq!(listed(&v, "to=2026-10-25").await, [SESSION_B, SESSION_A]);
    assert_eq!(
        listed(&v, "from=2026-10-25T10%3A00&to=2026-10-25T10%3A00").await,
        [SESSION_B]
    );
    assert_eq!(
        listed(&v, "from=2026-10-24+00%3A05").await,
        [SESSION_C, SESSION_B, SESSION_A]
    );
}

#[tokio::test]
async fn filters_combine_and_round_trip() {
    let f = Fixture::standard();
    let v = f.start().await;
    assert_eq!(
        listed(&v, "body=1&method=POST&ip=198.51").await,
        [SESSION_C]
    );
    let page = v
        .get("/?body=1&target=%22%3E%3Cb%3E&method=POST")
        .await
        .text();
    assert!(page.contains("name=\"body\" value=\"1\" checked"));
    assert!(page.contains("value=\"POST\""));
    assert!(
        page.contains("value=\"&quot;&gt;&lt;b&gt;\""),
        "hostile filter text escaped"
    );
    assert!(!page.contains("\"><b>"));
}

#[tokio::test]
async fn invalid_filter_values_are_reported() {
    let f = Fixture::standard();
    let v = f.start().await;
    for q in ["min_requests=two", "status=OK", "from=yesterday"] {
        let r = v.get(&format!("/?{q}")).await;
        assert_eq!(r.status, 200, "{q}");
        assert!(r.text().contains("class=\"error\""), "{q}");
        assert!(session_links(&r.text()).is_empty(), "{q}");
    }
}

// ---- #16: first sighting ----------------------------------------------------------

#[tokio::test]
async fn first_sighting_flags_only_the_earliest_session() {
    let f = Fixture::standard();
    let v = f.start().await;
    assert_eq!(listed(&v, "first=1").await, [SESSION_B]);
    let first = v.get(&format!("/session/{SESSION_B}")).await.text();
    assert!(first.contains("first sighting"));
    let later = v.get(&format!("/session/{SESSION_C}")).await.text();
    assert!(later.contains(&format!("seen first in <a href=\"/session/{SESSION_B}\"")));
}

#[tokio::test]
async fn first_sighting_survives_body_rotation_and_refresh() {
    let f = Fixture::standard();
    fs::remove_dir_all(f.dir.join("bodies")).unwrap();
    let v = f.start().await;
    assert_eq!(listed(&v, "first=1").await, [SESSION_B]);
    let mut new = req(
        CONN_C1,
        SESSION_C,
        "2026-10-26T12:00:01.000000Z",
        "POST",
        "/new",
    );
    new["body"] = json!({"sha256": sha('e'), "size": 1, "stored": 1, "file": sha('e')});
    f.request(new);
    assert_eq!(listed(&v, "first=1").await, [SESSION_C, SESSION_B]);
}
