//! HTTP surface: server-rendered, GET-only HTML over the index.
//!
//! Every attacker-derived value goes through maud's escaping and, for raw
//! bytes, through [`render::printable`]. Pages carry no script at all.

use std::{
    path::Path,
    sync::{Arc, Mutex, MutexGuard},
};

use axum::{
    Router,
    body::Body,
    extract::{Path as UrlPath, Query, Request, State},
    http::{HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::get,
};
use maud::{DOCTYPE, Markup, html};
use uuid::Uuid;

use crate::{
    data::{self, Fetch},
    filter::Filter,
    index::{Index, RequestKey, Session},
    records::BodyRef,
    render::{clip, hexdump, printable, printable_line, short_id, short_ts},
};

/// Sessions per list page.
const PAGE_SIZE: usize = 200;
/// Body bytes shown in a page; the rest is behind the download link.
const BODY_DISPLAY_LIMIT: usize = 64 * 1024;
/// Wire bytes shown per direction.
const WIRE_DISPLAY_LIMIT: usize = 256 * 1024;

const CSP: &str = "default-src 'none'; style-src 'self'; img-src 'none'; \
                   form-action 'self'; frame-ancestors 'none'; base-uri 'none'";
const STYLE: &str = include_str!("style.css");

type Shared = Arc<Mutex<Index>>;

pub fn router(data_dir: &Path) -> anyhow::Result<Router> {
    let index = Index::open(data_dir)?;
    let state: Shared = Arc::new(Mutex::new(index));
    Ok(Router::new()
        .route("/", get(session_list))
        .route("/session/{id}", get(session_page))
        .route("/request/{conn_id}/{seq}", get(request_page))
        .route("/body/{file}", get(body_download))
        .route("/static/style.css", get(style))
        .fallback(|| async { not_found() })
        .with_state(state)
        .layer(middleware::from_fn(security_headers))
        .layer(middleware::from_fn(loopback_host_only)))
}

/// The logs could not be read; logged, answered with a 500.
struct LogsUnreadable;

impl IntoResponse for LogsUnreadable {
    fn into_response(self) -> Response {
        (StatusCode::INTERNAL_SERVER_ERROR, "could not read the logs").into_response()
    }
}

/// Locks the index and picks up appended log lines.
fn fresh(state: &Shared) -> Result<MutexGuard<'_, Index>, LogsUnreadable> {
    let mut index = state.lock().unwrap_or_else(|e| e.into_inner());
    index.refresh().map_err(|e| {
        tracing::error!("refreshing index: {e}");
        LogsUnreadable
    })?;
    Ok(index)
}

// ---- middleware ---------------------------------------------------------

/// True for `localhost`, `127.0.0.1` and `[::1]`, with an optional port.
pub fn is_loopback_host(host: &str) -> bool {
    // `rest` is empty or `:port`.
    let (name, rest) = match host.strip_prefix('[') {
        Some(bracketed) => match bracketed.split_once(']') {
            Some(parts) => parts,
            None => return false,
        },
        None => host.find(':').map_or((host, ""), |i| host.split_at(i)),
    };
    let port_ok = rest.is_empty()
        || rest
            .strip_prefix(':')
            .is_some_and(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
    let name_ok = name.eq_ignore_ascii_case("localhost") || name == "127.0.0.1" || name == "::1";
    port_ok && name_ok
}

/// Blocks DNS rebinding: a page on another origin can make the operator's
/// browser connect here, but its Host header will name that origin.
async fn loopback_host_only(req: Request, next: Next) -> Response {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok());
    let authority = req.uri().authority().map(|a| a.as_str());
    let ok = host.is_some_and(is_loopback_host) && authority.is_none_or(is_loopback_host);
    if !ok {
        return (StatusCode::FORBIDDEN, "viewer only answers to localhost").into_response();
    }
    next.run(req).await
}

async fn security_headers(req: Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CSP),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

// ---- handlers -----------------------------------------------------------

fn not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        page("Not found", html! { p { "Not found." } }),
    )
        .into_response()
}

async fn style() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], STYLE)
}

async fn session_list(State(state): State<Shared>, Query(filter): Query<Filter>) -> Response {
    let index = match fresh(&state) {
        Ok(i) => i,
        Err(e) => return e.into_response(),
    };
    let (sessions, error) = match filter.apply(&index) {
        Ok(s) => (s, None),
        Err(e) => (Vec::new(), Some(e.0)),
    };
    let page_no = filter.page();
    let total = sessions.len();
    let shown = sessions.iter().skip(page_no * PAGE_SIZE).take(PAGE_SIZE);
    let pages = total.div_ceil(PAGE_SIZE).max(1);
    page(
        "Attack sessions",
        html! {
            h1 { "Attack sessions" }
            (filter_form(&filter))
            @if let Some(e) = error { p.error { (e) } }
            p.summary {
                (total) " of " (index.sessions.len()) " attack sessions"
                " · " (index.requests.len()) " requests · page " (page_no + 1) " of " (pages)
            }
            table {
                thead { tr {
                    th { "Last seen" } th { "First seen" } th { "Source" } th.num { "Req" }
                    th.num { "Conn" } th { "Body" } th { "First sighting" } th { "Targets" }
                } }
                tbody {
                    @for s in shown {
                        tr {
                            td.nowrap { a href={ "/session/" (s.id) } { (short_ts(&s.last_ts)) } }
                            td.nowrap { (short_ts(&s.first_ts)) }
                            td.mono.nowrap { (s.src_ip) }
                            td.num { (s.requests.len()) }
                            td.num { (s.connections.len()) }
                            td { @if s.has_body { "yes" } }
                            td { @if !s.first_sightings.is_empty() { span.badge { (s.first_sightings.len()) } } }
                            td.mono { (sample_targets(&index, s)) }
                        }
                    }
                }
            }
            nav.pager {
                @if page_no > 0 { a href={ "/?" (filter.with_page(page_no - 1).query()) } { "← newer" } " " }
                @if page_no + 1 < pages { a href={ "/?" (filter.with_page(page_no + 1).query()) } { "older →" } }
            }
        },
    )
    .into_response()
}

fn sample_targets(index: &Index, s: &Session) -> String {
    let mut seen: Vec<&str> = Vec::new();
    for &i in &s.requests {
        let t = index.requests[i].record.target.as_str();
        if !seen.contains(&t) {
            seen.push(t);
            if seen.len() == 3 {
                break;
            }
        }
    }
    let more = if s.requests.len() > seen.len() {
        " …"
    } else {
        ""
    };
    let list: Vec<String> = seen.iter().map(|t| clip(&printable_line(t), 60)).collect();
    format!("{}{more}", list.join("  "))
}

fn filter_form(f: &Filter) -> Markup {
    html! {
        form.filters method="get" action="/" {
            label { input type="checkbox" name="body" value="1" checked[f.body == "1"]; " has body" }
            label { input type="checkbox" name="first" value="1" checked[f.first == "1"]; " first sighting" }
            label { "min requests " input type="text" name="min_requests" size="3" value=(f.min_requests); }
            label { "method " input type="text" name="method" size="6" value=(f.method); }
            label { "status " input type="text" name="status" size="4" value=(f.status); }
            label { "target contains " input type="text" name="target" size="24" value=(f.target); }
            label { "src IP " input type="text" name="ip" size="16" value=(f.ip); }
            label { "from " input type="text" name="from" size="16" placeholder="2026-10-24" value=(f.from); }
            label { "to " input type="text" name="to" size="16" placeholder="2026-10-24T13:00" value=(f.to); }
            button type="submit" { "Filter" }
            " " a href="/" { "clear" }
        }
    }
}

async fn session_page(State(state): State<Shared>, UrlPath(id): UrlPath<String>) -> Response {
    let Ok(id) = Uuid::parse_str(&id) else {
        return not_found();
    };
    let index = match fresh(&state) {
        Ok(i) => i,
        Err(e) => return e.into_response(),
    };
    let Some(s) = index.sessions.get(&id) else {
        return not_found();
    };
    page(
        &format!("Attack session {}", short_id(&s.id)),
        html! {
            p { a href="/" { "← attack sessions" } }
            h1 { "Attack session " span.mono { (s.id) } }
            dl {
                dt { "Source" } dd.mono { (s.src_ip) }
                dt { "Active" } dd { (short_ts(&s.first_ts)) " → " (short_ts(&s.last_ts)) }
                dt { "Requests" } dd { (s.requests.len()) }
            }
            h2 { "Connections" }
            table {
                thead { tr {
                    th { "Conn" } th { "Opened" } th { "Port" } th { "TLS" } th { "SNI" } th { "ALPN" }
                    th.num { "C→S" } th.num { "S→C" } th { "Capture" }
                } }
                tbody {
                    @for conn_id in &s.connections {
                        @if let Some(c) = index.connections.get(conn_id) {
                            tr {
                                td.mono title=(c.conn_id) { (short_id(&c.conn_id)) }
                                td.nowrap { (short_ts(&c.ts_open)) }
                                td.num { (c.dst_port) }
                                td { @if c.tls { "yes" } @if let Some(e) = &c.tls_error { " " span.error { (printable_line(e)) } } }
                                td.mono { @if let Some(sni) = &c.sni { (printable_line(sni)) } }
                                td.mono { @if let Some(a) = &c.alpn { (printable_line(a)) } }
                                td.num { (c.bytes_c2s) }
                                td.num { (c.bytes_s2c) }
                                td { @if c.capture_truncated { span.error { "truncated" } } }
                            }
                        } @else {
                            tr { td.mono title=(conn_id) { (short_id(conn_id)) } td colspan="8" { "still open or not yet logged" } }
                        }
                    }
                }
            }
            h2 { "Requests" }
            table {
                thead { tr {
                    th { "Time" } th { "Conn" } th { "Proto" } th { "Method" } th { "Target" }
                    th.num { "Status" } th.num { "Body" } th { "Body sighting" }
                } }
                tbody {
                    @for &i in &s.requests {
                        @let req = &index.requests[i];
                        @let r = &req.record;
                        tr {
                            td.nowrap { a href=(request_href(req.key)) { (short_ts(&r.ts)) } }
                            td.mono.nowrap title=(r.conn_id) { (short_id(&r.conn_id)) }
                            td { (r.protocol) @if r.tls { " TLS" } }
                            td.mono { (clip(&printable_line(&r.method), 16)) }
                            td.mono { a href=(request_href(req.key)) { (clip(&printable_line(&r.target), 120)) } }
                            td.num { @match r.status { Some(st) => (st), None => "—" } }
                            td.num { (r.body_size) }
                            td { (sighting(&index, s.id, r.body.as_ref())) }
                        }
                    }
                }
            }
        },
    )
    .into_response()
}

fn request_href(key: RequestKey) -> String {
    format!("/request/{}/{}", key.conn_id, key.seq)
}

/// "first sighting", or a link to the session that first sent this body.
fn sighting(index: &Index, here: Uuid, body: Option<&BodyRef>) -> Markup {
    let Some(body) = body else { return html! {} };
    match index.first_sighting.get(&body.sha256) {
        Some(&first) if first == here => html! { span.badge { "first sighting" } },
        Some(first) => {
            html! { "seen first in " a href={ "/session/" (first) } { (short_id(first)) } }
        }
        None => html! {},
    }
}

async fn request_page(
    State(state): State<Shared>,
    UrlPath((conn_id, seq)): UrlPath<(String, String)>,
) -> Response {
    let (Ok(conn_id), Ok(seq)) = (Uuid::parse_str(&conn_id), seq.parse()) else {
        return not_found();
    };
    let index = match fresh(&state) {
        Ok(i) => i,
        Err(e) => return e.into_response(),
    };
    let Some(req) = index.request(RequestKey { conn_id, seq }) else {
        return not_found();
    };
    let r = &req.record;
    let conn = index.connections.get(&conn_id);
    let dir = index.dir();
    page(
        &format!("{} {}", clip(&printable_line(&r.method), 16), clip(&printable_line(&r.target), 60)),
        html! {
            p { a href={ "/session/" (r.attack_session_id) } { "← attack session " (short_id(&r.attack_session_id)) } }
            h1.mono { (printable_line(&r.method)) " " (printable_line(&r.target)) }
            dl {
                dt { "Time" } dd { (r.ts) }
                dt { "Source" } dd.mono { (r.src_ip) }
                dt { "Port" } dd { (r.dst_port) @if r.tls { " (TLS)" } }
                dt { "Protocol" } dd { (r.protocol) @if let Some(id) = r.stream_id { " stream " (id) } }
                @if let Some(a) = &r.authority { dt { ":authority" } dd.mono { (printable_line(a)) } }
                dt { "Status" } dd { @match r.status { Some(st) => (st), None => "none (cut off before a response)" } }
                dt { "Connection" } dd.mono { (r.conn_id) }
            }
            h2 { "Headers" }
            table.headers {
                tbody {
                    @for (name, value) in &r.headers {
                        tr { td.mono { (printable_line(name)) } td.mono { (printable_line(value)) } }
                    }
                }
            }
            h2 { "Request body" }
            (body_section(dir, r.body.as_ref(), r.body_size, Some(sighting(&index, r.attack_session_id, r.body.as_ref()))))
            h2 { "Response body" }
            (body_section(dir, r.response_body.as_ref(), 0, None))
            h2 { "Wire bytes" }
            @if conn.is_some_and(|c| c.capture_truncated) {
                p.error { "This connection's capture was truncated: bytes after the capture cap were not stored." }
            }
            @if r.protocol == "HTTP/2" {
                p.note { "HTTP/2: this is the span of this stream's frames and may include other streams' frames. Body payloads are not in the stream files." }
            }
            h3 { "Client → server" }
            (wire_section(dir, conn_id, false, r.c2s_range))
            h3 { "Server → client" }
            (wire_section(dir, conn_id, true, r.s2c_range))
        },
    )
    .into_response()
}

fn body_section(
    dir: &Path,
    body: Option<&BodyRef>,
    body_size: u64,
    sighting: Option<Markup>,
) -> Markup {
    let Some(b) = body else {
        return html! {
            p.note { "None." @if body_size > 0 { " " (body_size) " bytes were received but not recorded." } }
        };
    };
    let file = b.file.as_deref().filter(|f| data::is_body_file_name(f));
    let fetched = file
        .and_then(|f| data::body_path(dir, f))
        .map(|p| data::read_prefix(&p, BODY_DISPLAY_LIMIT));
    html! {
        dl {
            dt { "sha256" } dd.mono { (printable_line(&b.sha256)) }
            dt { "Size" } dd { (b.size) " bytes" @if b.stored < b.size { " " span.error { "(capture capped: " (b.stored) " stored)" } } }
            @if let Some(s) = sighting { dt { "Sighting" } dd { (s) } }
        }
        @match (file, fetched) {
            (None, _) | (_, None) => p.note { "Not stored." },
            (Some(_), Some(Ok(Fetch::Rotated))) => p.note { "Rotated: the body file has been deleted under the disk cap." },
            (Some(_), Some(Err(e))) => p.error { "Could not read the body file: " (e) },
            (Some(f), Some(Ok(Fetch::Found(ex)))) => {
                p { a href={ "/body/" (f) } download { "Download (" (b.stored) " bytes, application/octet-stream)" } }
                (bytes_view(&ex.bytes, ex.truncated))
            }
        }
    }
}

fn wire_section(dir: &Path, conn_id: Uuid, s2c: bool, range: Option<[u64; 2]>) -> Markup {
    let Some([start, end]) = range else {
        return html! { p.note { "No wire bytes recorded." } };
    };
    let path = data::stream_path(dir, conn_id, s2c);
    html! {
        p.note { "Bytes " (start) "–" (end) " of the stream file." }
        @match data::read_range(&path, start, end, WIRE_DISPLAY_LIMIT) {
            Ok(Fetch::Rotated) => p.note { "Rotated: the stream file has been deleted under the disk cap." },
            Err(e) => p.error { "Could not read the stream file: " (e) },
            Ok(Fetch::Found(ex)) => {
                @if (ex.bytes.len() as u64) < end - start && !ex.truncated {
                    p.error { "Only " (ex.bytes.len()) " of these bytes are in the file." }
                }
                (bytes_view(&ex.bytes, ex.truncated))
            }
        }
    }
}

/// Text view open, hex view one click away; no script needed.
fn bytes_view(bytes: &[u8], truncated: bool) -> Markup {
    html! {
        @if truncated { p.error { "Showing the first " (bytes.len()) " bytes only." } }
        details open { summary { "Text" } pre { (printable(bytes)) } }
        details { summary { "Hex" } pre { (hexdump(bytes)) } }
    }
}

async fn body_download(State(state): State<Shared>, UrlPath(file): UrlPath<String>) -> Response {
    let path = {
        let index = match fresh(&state) {
            Ok(i) => i,
            Err(e) => return e.into_response(),
        };
        // Only body files the logs reference, and only by validated name.
        if !index.body_files.contains(&file) {
            return not_found();
        }
        match data::body_path(index.dir(), &file) {
            Some(p) => p,
            None => return not_found(),
        }
    };
    match tokio::fs::read(&path).await {
        Ok(bytes) => Response::builder()
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .header(
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{file}.bin\""),
            )
            .body(Body::from(bytes))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (
            StatusCode::GONE,
            "rotated: the body file has been deleted under the disk cap",
        )
            .into_response(),
        Err(e) => {
            tracing::error!("reading {}: {e}", path.display());
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

fn page(title: &str, body: Markup) -> Html<String> {
    Html(
        html! {
            (DOCTYPE)
            html lang="en" {
                head {
                    meta charset="utf-8";
                    meta name="referrer" content="no-referrer";
                    title { (title) " · php_tarpit viewer" }
                    link rel="stylesheet" href="/static/style.css";
                }
                body { (body) }
            }
        }
        .into_string(),
    )
}
