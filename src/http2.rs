//! HTTP/2 front (TLS + ALPN only; no h2c). Request bodies are read to the
//! end of the stream whether or not a content-length was sent.

use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use h2::{RecvStream, server::SendResponse};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    task::JoinSet,
    time::{sleep, timeout},
};

use crate::server::{ConnInfo, RequestMeta, Shared};

const FIRST_REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
const KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(5);
const BODY_TIMEOUT: Duration = Duration::from_secs(300);
/// Apache mod_http2's default `H2MaxSessionStreams`.
const MAX_CONCURRENT_STREAMS: u32 = 100;

/// Connection-specific headers that are illegal in HTTP/2 (RFC 9113 §8.2.2).
const HOP_BY_HOP: [&str; 5] = ["connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade"];

pub async fn serve<S>(io: S, shared: Arc<Shared>, conn: ConnInfo) -> u32
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let handshake = h2::server::Builder::new()
        .max_concurrent_streams(MAX_CONCURRENT_STREAMS)
        .handshake::<_, Bytes>(io);
    let Ok(Ok(mut h2)) = timeout(FIRST_REQUEST_TIMEOUT, handshake).await else {
        return 0;
    };
    let mut requests = 0;
    let mut streams = JoinSet::new();
    loop {
        let idle = streams.is_empty();
        let wait = if requests == 0 { FIRST_REQUEST_TIMEOUT } else { KEEP_ALIVE_TIMEOUT };
        tokio::select! {
            next = h2.accept() => match next {
                Some(Ok((req, respond))) => {
                    requests += 1;
                    streams.spawn(handle_stream(req, respond, shared.clone(), conn));
                }
                Some(Err(_)) | None => break,
            },
            Some(_) = streams.join_next(), if !idle => {}
            () = sleep(wait), if idle => {
                h2.graceful_shutdown();
                while let Ok(Some(Ok(_))) = timeout(KEEP_ALIVE_TIMEOUT, h2.accept()).await {}
                break;
            }
        }
    }
    // Dropping the connection fails any stream still waiting on it.
    drop(h2);
    while streams.join_next().await.is_some() {}
    requests
}

async fn handle_stream(
    req: http::Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
    shared: Arc<Shared>,
    conn: ConnInfo,
) {
    let (parts, mut body) = req.into_parts();
    let mut meta = RequestMeta {
        protocol: "HTTP/2",
        stream_id: Some(respond.stream_id().as_u32()),
        method: parts.method.to_string(),
        target: parts.uri.path_and_query().map(|p| p.as_str().to_owned()).unwrap_or_default(),
        authority: parts.uri.authority().map(ToString::to_string),
        headers: parts
            .headers
            .iter()
            .map(|(n, v)| (n.as_str().to_owned(), String::from_utf8_lossy(v.as_bytes()).into_owned()))
            .collect(),
        body_size: 0,
        status: None,
    };

    let mut received = 0u64;
    let read = timeout(BODY_TIMEOUT, async {
        while let Some(chunk) = body.data().await {
            let chunk = chunk?;
            received += chunk.len() as u64;
            body.flow_control().release_capacity(chunk.len())?;
        }
        Ok::<_, h2::Error>(())
    })
    .await;
    meta.body_size = received;
    if !matches!(read, Ok(Ok(()))) {
        shared.log_request(&conn, meta);
        return;
    }

    let response = shared.persona.route(&meta.target);
    let mut builder = http::Response::builder().status(response.status);
    for (name, value) in response.headers() {
        if HOP_BY_HOP.iter().any(|h| name.eq_ignore_ascii_case(h)) {
            continue;
        }
        builder = builder.header(name, value.as_ref());
    }
    let head = builder.body(()).expect("persona headers are validated at load");
    let head_only = meta.method == "HEAD";
    let end_of_stream = head_only || response.body.is_empty();
    if let Ok(mut send) = respond.send_response(head, end_of_stream) {
        if !end_of_stream {
            let _ = send.send_data(response.body.clone(), true);
        }
        meta.status = Some(response.status);
    }
    shared.log_request(&conn, meta);
}
