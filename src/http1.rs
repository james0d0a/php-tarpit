//! HTTP/1.x front. Hand-rolled on `httparse` so that request headers are
//! recorded in wire order and case, response headers go out exactly as the
//! persona lists them, and request bodies are consumed in full (chunked or
//! Content-Length) without being buffered in memory.
//!
//! Capture happens here, not in a tee: the parser knows which consumed bytes
//! are framing and which are body payload. Every byte is captured as it is
//! consumed from the read buffer, so a timeout mid-read loses nothing, and
//! bytes read but never consumed are captured when the connection ends.

use std::time::Duration;

use anyhow::{Result, bail};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    time::timeout,
};

use crate::{
    capture::{BodyRef, ConnCapture, Dir, MessageCapture},
    persona::Response,
    server::{ConnInfo, RequestMeta, Shared},
};

/// Apache's default `LimitRequestFields`.
const MAX_HEADERS: usize = 100;
/// Upper bound on the request line plus headers.
const MAX_HEAD_BYTES: u64 = 64 * 1024;
/// Upper bound on one chunk-size or trailer line.
const MAX_LINE_BYTES: u64 = 8 * 1024;
const FIRST_REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
/// Apache's default `KeepAliveTimeout`.
const KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(5);
const BODY_TIMEOUT: Duration = Duration::from_secs(300);

/// Serves requests until the client closes, misbehaves or idles out.
/// Returns the number of requests logged.
pub async fn serve<S>(io: S, shared: &Shared, conn: &ConnInfo, cap: &mut ConnCapture) -> u32
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut io = BufReader::new(io);
    let mut requests = 0;
    loop {
        let wait = if requests == 0 { FIRST_REQUEST_TIMEOUT } else { KEEP_ALIVE_TIMEOUT };
        let c2s_start = cap.pos(Dir::C2s);
        let mut head = Vec::new();
        let skip = match timeout(wait, read_head(&mut io, cap, &mut head)).await {
            Ok(Ok(Some(skip))) => skip,
            Ok(Ok(None) | Err(HeadError::Io)) | Err(_) => break,
            Ok(Err(HeadError::TooLarge)) => {
                let _ = respond(&mut io, cap, &shared.persona.bad_request, false, true).await;
                break;
            }
        };
        requests += 1;
        let keep_going = handle(&mut io, &head[skip..], c2s_start, shared, conn, cap).await;
        if !keep_going {
            break;
        }
    }
    // Read from the socket but never consumed (e.g. a body after a 400).
    let rest = io.buffer();
    cap.wire(Dir::C2s, rest.len());
    cap.frame(Dir::C2s, rest);
    let _ = io.shutdown().await;
    requests
}

enum Line {
    Complete,
    Eof,
    TooLong,
}

/// Reads up to and including `\n`, at most `max` bytes, capturing as it goes.
async fn read_line<S: AsyncRead + Unpin>(
    io: &mut BufReader<S>,
    cap: &mut ConnCapture,
    max: u64,
    out: &mut Vec<u8>,
) -> std::io::Result<Line> {
    let mut budget = max;
    loop {
        let buf = io.fill_buf().await?;
        if buf.is_empty() {
            return Ok(Line::Eof);
        }
        let limit = (buf.len() as u64).min(budget) as usize;
        let (take, done) = match buf[..limit].iter().position(|&b| b == b'\n') {
            Some(i) => (i + 1, true),
            None => (limit, false),
        };
        cap.wire(Dir::C2s, take);
        cap.frame(Dir::C2s, &buf[..take]);
        out.extend_from_slice(&buf[..take]);
        io.consume(take);
        budget -= take as u64;
        if done {
            return Ok(Line::Complete);
        }
        if budget == 0 {
            return Ok(Line::TooLong);
        }
    }
}

enum HeadError {
    Io,
    TooLarge,
}

fn is_blank(line: &[u8]) -> bool {
    line == b"\r\n" || line == b"\n"
}

/// Reads one request head into `head`, ending at the first empty line. Empty
/// lines before the request line are allowed (RFC 9112 §2.2); returns how
/// many leading bytes they took. `None` on EOF before any request byte.
async fn read_head<S: AsyncRead + Unpin>(
    io: &mut BufReader<S>,
    cap: &mut ConnCapture,
    head: &mut Vec<u8>,
) -> Result<Option<usize>, HeadError> {
    let mut skip = 0;
    loop {
        let start = head.len();
        let budget = MAX_HEAD_BYTES.saturating_sub(start as u64);
        if budget == 0 {
            return Err(HeadError::TooLarge);
        }
        match read_line(io, cap, budget, head).await.map_err(|_| HeadError::Io)? {
            Line::Complete => {}
            Line::Eof if head[skip..].is_empty() => return Ok(None),
            Line::Eof => return Err(HeadError::Io),
            Line::TooLong => return Err(HeadError::TooLarge),
        }
        if is_blank(&head[start..]) {
            if start == skip {
                skip = head.len();
                continue;
            }
            return Ok(Some(skip));
        }
    }
}

enum Framing {
    None,
    Length(u64),
    Chunked,
}

/// Handles one parsed head: reads the body, responds, logs.
/// Returns whether the connection should stay open.
async fn handle<S>(
    io: &mut BufReader<S>,
    head: &[u8],
    c2s_start: u64,
    shared: &Shared,
    conn: &ConnInfo,
    cap: &mut ConnCapture,
) -> bool
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut slots = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut slots);
    let parsed = req.parse(head);

    let headers: Vec<(String, String)> = req
        .headers
        .iter()
        .take_while(|h| !h.name.is_empty())
        .map(|h| (h.name.to_owned(), String::from_utf8_lossy(h.value).into_owned()))
        .collect();
    let mut meta = RequestMeta {
        protocol: match req.version {
            Some(0) => "HTTP/1.0",
            _ => "HTTP/1.1",
        },
        stream_id: None,
        method: req.method.unwrap_or("").to_owned(),
        target: req.path.unwrap_or("").to_owned(),
        authority: None,
        headers,
        body_size: 0,
        status: None,
    };

    let framing = match parsed {
        Ok(httparse::Status::Complete(_)) => framing(&meta.headers),
        _ => Err(anyhow::anyhow!("unparseable head")),
    };
    let Ok(framing) = framing else {
        // The stream file has the raw bytes; log what parsed.
        reject(io, cap, shared, conn, meta, c2s_start, None).await;
        return false;
    };

    let mut body = match framing {
        Framing::Length(0) | Framing::None => None,
        Framing::Length(_) | Framing::Chunked => Some(cap.body_start()),
    };
    let read = match (&framing, body.as_mut()) {
        (Framing::Length(len), Some(b)) => timeout(BODY_TIMEOUT, read_exact(io, cap, b, *len)).await,
        (Framing::Chunked, Some(b)) => timeout(BODY_TIMEOUT, read_chunked(io, cap, b)).await,
        _ => Ok(Ok(())),
    };
    let body = body.and_then(|b| cap.body_end(b));
    meta.body_size = body.as_ref().map_or(0, |b| b.size);
    match read {
        Ok(Ok(())) => {}
        Ok(Err(BodyError::Malformed)) => {
            reject(io, cap, shared, conn, meta, c2s_start, body).await;
            return false;
        }
        // Cut off mid-body: log the partial request with no status.
        Ok(Err(BodyError::Io)) | Err(_) => {
            let msg = MessageCapture {
                c2s_range: Some([c2s_start, cap.pos(Dir::C2s)]),
                body,
                ..Default::default()
            };
            shared.log_request(conn, meta, msg);
            return false;
        }
    }
    let c2s_range = Some([c2s_start, cap.pos(Dir::C2s)]);

    let close = wants_close(meta.protocol, &meta.headers);
    let response = shared.persona.route(&meta.target);
    let head_only = meta.method == "HEAD";
    let s2c_start = cap.pos(Dir::S2c);
    let sent = respond(io, cap, response, head_only, close).await;
    meta.status = Some(response.status);
    let msg = MessageCapture {
        c2s_range,
        s2c_range: Some([s2c_start, cap.pos(Dir::S2c)]),
        body,
        response_body: sent.as_ref().ok().cloned().flatten(),
    };
    shared.log_request(conn, meta, msg);
    // A persona response that says `Connection: close` (e.g. 400) closes too.
    sent.is_ok() && !close && !response_closes(response)
}

/// Sends the persona's 400 and logs the request.
async fn reject<S: AsyncWrite + Unpin>(
    io: &mut S,
    cap: &mut ConnCapture,
    shared: &Shared,
    conn: &ConnInfo,
    mut meta: RequestMeta,
    c2s_start: u64,
    body: Option<BodyRef>,
) {
    let c2s_range = Some([c2s_start, cap.pos(Dir::C2s)]);
    let s2c_start = cap.pos(Dir::S2c);
    let sent = respond(io, cap, &shared.persona.bad_request, false, true).await;
    meta.status = Some(shared.persona.bad_request.status);
    let msg = MessageCapture {
        c2s_range,
        s2c_range: Some([s2c_start, cap.pos(Dir::S2c)]),
        body,
        response_body: sent.ok().flatten(),
    };
    shared.log_request(conn, meta, msg);
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> impl Iterator<Item = &'a str> {
    headers
        .iter()
        .filter(move |(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn has_token(headers: &[(String, String)], name: &str, token: &str) -> bool {
    header(headers, name)
        .flat_map(|v| v.split(','))
        .any(|t| t.trim().eq_ignore_ascii_case(token))
}

/// RFC 9112 §6.3 message body length rules for requests.
fn framing(headers: &[(String, String)]) -> Result<Framing> {
    let mut te = header(headers, "transfer-encoding").peekable();
    if te.peek().is_some() {
        let last = te
            .flat_map(|v| v.split(','))
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .last();
        return match last {
            Some(t) if t.eq_ignore_ascii_case("chunked") => Ok(Framing::Chunked),
            _ => bail!("transfer-encoding without final chunked"),
        };
    }
    let mut length = None;
    for value in header(headers, "content-length") {
        for part in value.split(',') {
            let n: u64 = part.trim().parse()?;
            if length.is_some_and(|l| l != n) {
                bail!("conflicting content-length");
            }
            length = Some(n);
        }
    }
    Ok(length.map_or(Framing::None, Framing::Length))
}

fn wants_close(protocol: &str, headers: &[(String, String)]) -> bool {
    if has_token(headers, "connection", "close") {
        return true;
    }
    protocol == "HTTP/1.0" && !has_token(headers, "connection", "keep-alive")
}

fn response_closes(response: &Response) -> bool {
    response
        .headers()
        .any(|(n, v)| n.eq_ignore_ascii_case("connection") && v.eq_ignore_ascii_case("close"))
}

enum BodyError {
    Io,
    Malformed,
}

/// Consumes exactly `len` body payload bytes into `body`.
async fn read_exact<S: AsyncRead + Unpin>(
    io: &mut BufReader<S>,
    cap: &mut ConnCapture,
    body: &mut crate::capture::BodyHandle,
    mut len: u64,
) -> Result<(), BodyError> {
    while len > 0 {
        let buf = io.fill_buf().await.map_err(|_| BodyError::Io)?;
        if buf.is_empty() {
            return Err(BodyError::Io);
        }
        let take = (buf.len() as u64).min(len) as usize;
        cap.wire(Dir::C2s, take);
        cap.body_bytes(body, &buf[..take]);
        io.consume(take);
        len -= take as u64;
    }
    Ok(())
}

async fn read_framing_line<S: AsyncRead + Unpin>(
    io: &mut BufReader<S>,
    cap: &mut ConnCapture,
    line: &mut Vec<u8>,
) -> Result<(), BodyError> {
    line.clear();
    match read_line(io, cap, MAX_LINE_BYTES, line).await {
        Ok(Line::Complete) => Ok(()),
        Ok(Line::TooLong) => Err(BodyError::Malformed),
        Ok(Line::Eof) | Err(_) => Err(BodyError::Io),
    }
}

async fn read_chunked<S: AsyncRead + Unpin>(
    io: &mut BufReader<S>,
    cap: &mut ConnCapture,
    body: &mut crate::capture::BodyHandle,
) -> Result<(), BodyError> {
    let mut line = Vec::with_capacity(64);
    loop {
        read_framing_line(io, cap, &mut line).await?;
        let size_text = std::str::from_utf8(&line).map_err(|_| BodyError::Malformed)?;
        let size_text = size_text.split(';').next().unwrap_or("").trim();
        let size = u64::from_str_radix(size_text, 16).map_err(|_| BodyError::Malformed)?;
        if size == 0 {
            break;
        }
        read_exact(io, cap, body, size).await?;
        read_framing_line(io, cap, &mut line).await?;
        if !is_blank(&line) {
            return Err(BodyError::Malformed);
        }
    }
    // Trailer section, ended by an empty line.
    loop {
        read_framing_line(io, cap, &mut line).await?;
        if is_blank(&line) {
            return Ok(());
        }
    }
}

/// Writes `response` with persona header order and case, then captures it.
/// When the connection is closing, Apache drops `Keep-Alive` and sends
/// `Connection: close`. Returns the response body reference.
async fn respond<S: AsyncWrite + Unpin>(
    io: &mut S,
    cap: &mut ConnCapture,
    response: &Response,
    head_only: bool,
    close: bool,
) -> std::io::Result<Option<BodyRef>> {
    let mut out = Vec::with_capacity(512 + response.body.len());
    out.extend_from_slice(format!("HTTP/1.1 {} {}\r\n", response.status, response.reason).as_bytes());
    for (name, value) in response.headers() {
        if close && name.eq_ignore_ascii_case("keep-alive") {
            continue;
        }
        let value = if close && name.eq_ignore_ascii_case("connection") { "close" } else { &value };
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    let head_len = out.len();
    if !head_only {
        out.extend_from_slice(&response.body);
    }
    io.write_all(&out).await?;
    io.flush().await?;
    cap.wire(Dir::S2c, out.len());
    cap.frame(Dir::S2c, &out[..head_len]);
    Ok(if head_only { None } else { cap.static_body(response.body_sha256, &response.body) })
}
