//! Real clients against the real sensor container. Run with `cargo harness`.

use harness::Lab;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn payload(tag: &str) -> String {
    format!("harness-{tag}-").repeat(2_000)
}

fn find<'a>(requests: &'a [Value], target: &str) -> Option<&'a Value> {
    requests.iter().find(|r| r["target"] == target)
}

fn has_header(request: &Value, name: &str, value: &str) -> bool {
    request["headers"].as_array().unwrap().iter().any(|h| h == &json!([name, value]))
}

#[test]
fn chunked_http1_request_is_captured_with_its_payload() {
    let lab = Lab::up();
    let body = payload("chunked");
    let out = lab.client(
        "curl",
        &[],
        &[
            "-sS", "--http1.1", "-D", "-", "-o", "/dev/null",
            "-H", "Transfer-Encoding: chunked", "-H", "X-Harness: chunked",
            "--data-binary", &body, "http://sensor/?harness=chunked",
        ],
    );
    assert_eq!(out.status, 0, "{}", out.stderr);
    assert!(out.stdout.starts_with("HTTP/1.1 200 OK\r\n"), "{}", out.stdout);
    assert!(out.stdout.contains("\r\nX-Powered-By: PHP/8.3.30\r\n"), "{}", out.stdout);

    let data = lab.data_when(|d| find(&d.requests, "/?harness=chunked").is_some() && !d.connections.is_empty());
    let req = find(&data.requests, "/?harness=chunked").unwrap();
    assert_eq!(req["protocol"], "HTTP/1.1");
    assert_eq!(req["method"], "POST");
    assert_eq!(req["dst_port"], 80);
    assert_eq!(req["status"], 200);
    assert!(has_header(req, "Transfer-Encoding", "chunked"), "{req}");
    assert!(has_header(req, "X-Harness", "chunked"), "{req}");
    assert_eq!(req["body"]["size"], body.len());
    assert_eq!(req["body"]["sha256"], hex::encode(Sha256::digest(&body)));
    assert_eq!(data.body(&req["body"]), body.as_bytes());

    // The request head (with chunk framing after it) is at its stream offset.
    let c2s = data.stream(req, "c2s");
    let start = req["c2s_range"][0].as_u64().unwrap() as usize;
    assert!(c2s[start..].starts_with(b"POST /?harness=chunked HTTP/1.1\r\n"));
}

#[test]
fn lengthless_http2_request_over_tls_is_captured_and_key_log_decrypts() {
    let lab = Lab::up();
    let body = payload("h2");
    // curl writes its TLS secrets to stderr; the sensor's key log must hold them.
    let out = lab.client(
        "curl",
        &[("SSLKEYLOGFILE", "/dev/stderr")],
        &[
            "-s", "-k", "--http2", "-o", "/dev/null", "-w", "%{http_code} %{http_version}",
            "-H", "Transfer-Encoding: chunked", "-H", "X-Harness: h2",
            "--data-binary", &body, "https://sensor/?harness=h2",
        ],
    );
    assert_eq!(out.status, 0, "{}", out.stderr);
    assert_eq!(out.stdout, "200 2");

    let data = lab.data_when(|d| {
        find(&d.requests, "/?harness=h2").is_some() && d.connections.iter().any(|c| c["alpn"] == "h2")
    });
    let req = find(&data.requests, "/?harness=h2").unwrap();
    assert_eq!(req["protocol"], "HTTP/2");
    assert_eq!(req["tls"], true);
    assert_eq!(req["dst_port"], 443);
    assert_eq!(req["authority"], "sensor");
    assert!(has_header(req, "x-harness", "h2"), "{req}");
    assert_eq!(req["body"]["sha256"], hex::encode(Sha256::digest(&body)));
    assert_eq!(data.body(&req["body"]), body.as_bytes());
    let conn = data.connections.iter().find(|c| c["conn_id"] == req["conn_id"]).unwrap();
    assert_eq!(conn["sni"], "sensor");

    let client_secrets: Vec<&str> = out.stderr.lines().filter(|l| l.contains("_SECRET")).collect();
    assert!(client_secrets.iter().any(|l| l.starts_with("CLIENT_TRAFFIC_SECRET_0 ")), "{}", out.stderr);
    let keylog = String::from_utf8(data.read("tls/keylog.txt")).unwrap();
    for line in client_secrets {
        assert!(keylog.lines().any(|l| l == line), "sensor key log lacks {line}");
    }
}

#[test]
fn official_nuclei_template_flags_the_sensor_vulnerable() {
    let lab = Lab::up();
    let out = lab.client(
        "nuclei",
        &[],
        &[
            "-t", "/templates/CVE-2026-109618.yaml", "-u", "http://sensor",
            "-jsonl", "-silent", "-duc", "-ni", "-no-color", "-timeout", "60",
        ],
    );
    let findings: Vec<Value> = out.stdout.lines().filter_map(|l| serde_json::from_str(l).ok()).collect();
    let hit = findings
        .iter()
        .find(|f| f["template-id"] == "CVE-2026-109618")
        .unwrap_or_else(|| panic!("no finding (exit {}):\n{}\n{}", out.status, out.stdout, out.stderr));
    assert_eq!(hit["matcher-name"], "version-vulnerable-no-crash", "{hit}");

    // The sensor captured the whole flow: control request, the 1/8/20 MiB
    // heap-pressure probes in full, and the final version check.
    let data = lab.data_when(|d| d.requests.iter().filter(|r| r["dst_port"] == 80).count() >= 5);
    let nuclei: Vec<&Value> = data.requests.iter().filter(|r| r["dst_port"] == 80).collect();
    let probe_sizes: Vec<u64> = nuclei
        .iter()
        .filter(|r| r["method"] == "POST")
        .map(|r| r["body_size"].as_u64().unwrap())
        .collect();
    for mib in [1, 8, 20] {
        // buildProbe() lands within a few bytes of the target size, either side.
        let size = mib * 1024 * 1024;
        assert!(probe_sizes.iter().any(|&s| s.abs_diff(size) <= 4096), "no ~{mib} MiB probe in {probe_sizes:?}");
    }
    for r in &nuclei {
        assert_eq!(r["status"], 200, "{r}");
        if let Some(body) = r.get("body") {
            assert_eq!(body["stored"], body["size"], "probe body not captured in full: {r}");
        }
    }
    assert!(nuclei.last().is_some_and(|r| r["method"] == "GET"), "no final version-check GET");
}

#[test]
fn wire_capture_holds_only_sensor_traffic_rotates_and_decrypts_with_the_key_log() {
    let lab = Lab::up();
    // Not a sensor port: refused, and must stay out of the capture.
    lab.client("curl", &[], &["-s", "-m", "3", "http://sensor:8080/"]);
    // Four ~100 KB HTTP/2 POSTs: enough to roll the 256 KiB pcap files.
    let body = "harness-pcap-".repeat(8_000);
    let out = lab.client(
        "curl",
        &[],
        &["-s", "-k", "--http2", "-o", "/dev/null", "--data-binary", &body, "https://sensor/?harness=pcap&n=[1-4]"],
    );
    assert_eq!(out.status, 0, "{}", out.stderr);

    // One TLS session spans several files, so merge before decrypting.
    let script = "set -e; mergecap -w /tmp/all.pcap /data/pcap/*.pcap; \
        stat -c 'size %s' /data/pcap/*.pcap; \
        tshark -r /tmp/all.pcap -Y 'tcp.flags.syn==1 && tcp.flags.ack==0' -T fields -e tcp.dstport | sed 's/^/syn /'; \
        tshark -r /tmp/all.pcap -o tls.keylog_file:/data/tls/keylog.txt -Y http2.headers.path \
            -T fields -e http2.headers.path | tr ',' '\\n' | sed 's/^/path /'";
    // The capture thread flushes after a second without packets.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let (sizes, syns) = loop {
        let out = lab.client("tshark", &[], &[script]);
        let field = |tag: &str| -> Vec<String> {
            out.stdout.lines().filter_map(|l| l.strip_prefix(tag).map(str::to_owned)).collect()
        };
        let paths = field("path ");
        if (1..=4).all(|n| paths.contains(&format!("/?harness=pcap&n={n}"))) {
            break (field("size "), field("syn "));
        }
        assert!(
            std::time::Instant::now() < deadline,
            "decrypted pcap never showed all requests:\n{}\n{}",
            out.stdout,
            out.stderr
        );
        std::thread::sleep(std::time::Duration::from_secs(1));
    };

    assert!(syns.iter().any(|p| p == "443"), "no connection to 443 captured: {syns:?}");
    assert!(!syns.iter().any(|p| p == "8080"), "non-sensor port captured: {syns:?}");
    assert!(sizes.len() >= 2, "pcap did not rotate: {sizes:?}");
    // A file closes once it reaches the limit, so it overshoots by at most one packet.
    let limit = 256 * 1024 + 65_536 + 16;
    for size in &sizes {
        assert!(size.parse::<u64>().unwrap() <= limit, "pcap file over limit: {sizes:?}");
    }
}
