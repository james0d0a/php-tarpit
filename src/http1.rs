//! HTTP/1.x front. Hand-rolled on `httparse` so that request headers are
//! recorded in wire order and case, response headers go out exactly as the
//! persona lists them, and request bodies are consumed in full (chunked or
//! Content-Length) without being buffered in memory.

use std::time::Duration;

use anyhow::{Result, bail};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    time::timeout,
};

use crate::{
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
pub async fn serve<S>(io: S, shared: &Shared, conn: &ConnInfo) -> u32
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut io = BufReader::new(io);
    let mut requests = 0;
    loop {
        let wait = if requests == 0 { FIRST_REQUEST_TIMEOUT } else { KEEP_ALIVE_TIMEOUT };
        let head = match timeout(wait, read_head(&mut io)).await {
            Ok(Ok(Some(head))) => head,
            Ok(Ok(None)) | Err(_) => break,
            Ok(Err(HeadError::Io)) => break,
            Ok(Err(HeadError::TooLarge)) => {
                let _ = respond(&mut io, &shared.persona.bad_request, false, true).await;
                break;
            }
        };
        requests += 1;
        let keep_going = handle(&mut io, &head, shared, conn).await;
        if !keep_going {
            break;
        }
    }
    let _ = io.shutdown().await;
    requests
}

enum HeadError {
    Io,
    TooLarge,
}

/// Reads one request head, ending at the first empty line. Empty lines before
/// the request line are skipped (RFC 9112 §2.2). `None` on clean EOF.
async fn read_head<S: AsyncRead + Unpin>(
    io: &mut BufReader<S>,
) -> Result<Option<Vec<u8>>, HeadError> {
    let mut head = Vec::new();
    loop {
        let start = head.len();
        let budget = MAX_HEAD_BYTES.saturating_sub(start as u64);
        if budget == 0 {
            return Err(HeadError::TooLarge);
        }
        let n = (&mut *io)
            .take(budget)
            .read_until(b'\n', &mut head)
            .await
            .map_err(|_| HeadError::Io)?;
        if n == 0 {
            return if head.is_empty() { Ok(None) } else { Err(HeadError::Io) };
        }
        let line = &head[start..];
        if !line.ends_with(b"\n") {
            // Hit the budget mid-line.
            return Err(HeadError::TooLarge);
        }
        if line == b"\r\n" || line == b"\n" {
            if start == 0 {
                head.clear();
                continue;
            }
            return Ok(Some(head));
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
async fn handle<S>(io: &mut BufReader<S>, head: &[u8], shared: &Shared, conn: &ConnInfo) -> bool
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

    if !matches!(parsed, Ok(httparse::Status::Complete(_))) {
        // Unparseable head: the raw stream has the bytes; log what we got.
        let _ = respond(io, &shared.persona.bad_request, false, true).await;
        meta.status = Some(shared.persona.bad_request.status);
        shared.log_request(conn, meta);
        return false;
    }

    let framing = match framing(&meta.headers) {
        Ok(f) => f,
        Err(_) => {
            let _ = respond(io, &shared.persona.bad_request, false, true).await;
            meta.status = Some(shared.persona.bad_request.status);
            shared.log_request(conn, meta);
            return false;
        }
    };

    let body = match framing {
        Framing::None => Ok(Ok(())),
        Framing::Length(len) => timeout(BODY_TIMEOUT, read_length(io, len, &mut meta.body_size)).await,
        Framing::Chunked => timeout(BODY_TIMEOUT, read_chunked(io, &mut meta.body_size)).await,
    };
    match body {
        Ok(Ok(_)) => {}
        Ok(Err(BodyError::Malformed)) => {
            let _ = respond(io, &shared.persona.bad_request, false, true).await;
            meta.status = Some(shared.persona.bad_request.status);
            shared.log_request(conn, meta);
            return false;
        }
        // Cut off mid-body: log the partial request with no status.
        Ok(Err(BodyError::Io)) | Err(_) => {
            shared.log_request(conn, meta);
            return false;
        }
    }

    let close = wants_close(meta.protocol, &meta.headers);
    let response = shared.persona.route(&meta.target);
    let head_only = meta.method == "HEAD";
    let sent = respond(io, response, head_only, close).await;
    meta.status = Some(response.status);
    shared.log_request(conn, meta);
    // A persona response that says `Connection: close` (e.g. 400) closes too.
    sent.is_ok() && !close && !response_closes(response)
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

async fn read_length<S: AsyncRead + Unpin>(
    io: &mut BufReader<S>,
    len: u64,
    received: &mut u64,
) -> Result<(), BodyError> {
    let n = tokio::io::copy(&mut (&mut *io).take(len), &mut tokio::io::sink())
        .await
        .map_err(|_| BodyError::Io)?;
    *received += n;
    if n == len { Ok(()) } else { Err(BodyError::Io) }
}

async fn read_line<S: AsyncRead + Unpin>(
    io: &mut BufReader<S>,
    line: &mut Vec<u8>,
) -> Result<(), BodyError> {
    line.clear();
    let n = (&mut *io)
        .take(MAX_LINE_BYTES)
        .read_until(b'\n', line)
        .await
        .map_err(|_| BodyError::Io)?;
    if n == 0 {
        return Err(BodyError::Io);
    }
    if !line.ends_with(b"\n") {
        return Err(if n as u64 == MAX_LINE_BYTES { BodyError::Malformed } else { BodyError::Io });
    }
    Ok(())
}

async fn read_chunked<S: AsyncRead + Unpin>(
    io: &mut BufReader<S>,
    received: &mut u64,
) -> Result<(), BodyError> {
    let mut line = Vec::with_capacity(64);
    loop {
        read_line(io, &mut line).await?;
        let size_text = std::str::from_utf8(&line).map_err(|_| BodyError::Malformed)?;
        let size_text = size_text.split(';').next().unwrap_or("").trim();
        let size = u64::from_str_radix(size_text, 16).map_err(|_| BodyError::Malformed)?;
        if size == 0 {
            break;
        }
        read_length(io, size, received).await?;
        read_line(io, &mut line).await?;
        if line != b"\r\n" && line != b"\n" {
            return Err(BodyError::Malformed);
        }
    }
    // Trailer section, ended by an empty line.
    loop {
        read_line(io, &mut line).await?;
        if line == b"\r\n" || line == b"\n" {
            return Ok(());
        }
    }
}

/// Writes `response` with persona header order and case. When the connection
/// is closing, Apache drops `Keep-Alive` and sends `Connection: close`.
async fn respond<S: AsyncWrite + Unpin>(
    io: &mut S,
    response: &Response,
    head_only: bool,
    close: bool,
) -> std::io::Result<()> {
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
    if !head_only {
        out.extend_from_slice(&response.body);
    }
    io.write_all(&out).await?;
    io.flush().await
}
