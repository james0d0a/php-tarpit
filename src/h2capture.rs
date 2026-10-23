//! HTTP/2 capture: a tee below the `h2` codec that splits each direction into
//! frames, sends DATA payloads to per-stream bodies and everything else to
//! the stream files. A request's log line is written once its response
//! stream has ended, so both offset ranges are known.

use std::{
    collections::HashMap,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{
    capture::{BodyHandle, BodyRef, CaptureStats, ConnCapture, Dir, MessageCapture},
    server::{ConnInfo, RequestMeta, Shared},
};

const PREFACE_LEN: usize = 24;
const FRAME_HEADER_LEN: usize = 9;
const TYPE_DATA: u8 = 0x0;
const TYPE_HEADERS: u8 = 0x1;
const TYPE_RST_STREAM: u8 = 0x3;
const FLAG_END_STREAM: u8 = 0x1;
const FLAG_PADDED: u8 = 0x8;

enum Event<'a> {
    Framing { stream: u32, bytes: &'a [u8] },
    Data { stream: u32, bytes: &'a [u8] },
    FrameEnd { stream: u32, ty: u8, flags: u8 },
}

enum Phase {
    /// Non-DATA payload, or DATA padding.
    Framing,
    PadLength,
    Data { left: usize },
}

struct Frame {
    ty: u8,
    flags: u8,
    stream: u32,
    left: usize,
    phase: Phase,
}

/// Incremental HTTP/2 frame splitter; tolerates input split anywhere.
struct FrameParser {
    preface_left: usize,
    header: [u8; FRAME_HEADER_LEN],
    have: usize,
    frame: Option<Frame>,
}

impl FrameParser {
    fn new(preface_len: usize) -> Self {
        Self { preface_left: preface_len, header: [0; FRAME_HEADER_LEN], have: 0, frame: None }
    }

    fn feed(&mut self, mut data: &[u8], on: &mut impl FnMut(Event)) {
        while !data.is_empty() {
            if self.preface_left > 0 {
                let take = self.preface_left.min(data.len());
                on(Event::Framing { stream: 0, bytes: &data[..take] });
                self.preface_left -= take;
                data = &data[take..];
                continue;
            }
            let Some(frame) = &mut self.frame else {
                let take = (FRAME_HEADER_LEN - self.have).min(data.len());
                self.header[self.have..self.have + take].copy_from_slice(&data[..take]);
                self.have += take;
                data = &data[take..];
                if self.have == FRAME_HEADER_LEN {
                    self.have = 0;
                    self.start_frame(on);
                }
                continue;
            };
            let stream = frame.stream;
            let take = match &mut frame.phase {
                Phase::PadLength => {
                    let pad = data[0] as usize;
                    on(Event::Framing { stream, bytes: &data[..1] });
                    frame.left -= 1;
                    frame.phase = if pad <= frame.left {
                        Phase::Data { left: frame.left - pad }
                    } else {
                        // Invalid padding: keep the rest as framing.
                        Phase::Framing
                    };
                    1
                }
                Phase::Data { left } if *left > 0 => {
                    let take = (*left).min(data.len());
                    on(Event::Data { stream, bytes: &data[..take] });
                    *left -= take;
                    frame.left -= take;
                    take
                }
                Phase::Data { .. } | Phase::Framing => {
                    let take = frame.left.min(data.len());
                    on(Event::Framing { stream, bytes: &data[..take] });
                    frame.left -= take;
                    take
                }
            };
            data = &data[take..];
            self.end_frame_if_done(on);
        }
    }

    fn start_frame(&mut self, on: &mut impl FnMut(Event)) {
        let h = &self.header;
        let len = u32::from_be_bytes([0, h[0], h[1], h[2]]) as usize;
        let (ty, flags) = (h[3], h[4]);
        let stream = u32::from_be_bytes([h[5], h[6], h[7], h[8]]) & 0x7fff_ffff;
        on(Event::Framing { stream, bytes: &self.header });
        let phase = match ty {
            TYPE_DATA if flags & FLAG_PADDED != 0 && len > 0 => Phase::PadLength,
            TYPE_DATA => Phase::Data { left: len },
            _ => Phase::Framing,
        };
        self.frame = Some(Frame { ty, flags, stream, left: len, phase });
        self.end_frame_if_done(on);
    }

    fn end_frame_if_done(&mut self, on: &mut impl FnMut(Event)) {
        if let Some(f) = &self.frame
            && f.left == 0
        {
            on(Event::FrameEnd { stream: f.stream, ty: f.ty, flags: f.flags });
            self.frame = None;
        }
    }
}

#[derive(Default)]
struct StreamCapture {
    range: [Option<[u64; 2]>; 2],
    body: [Option<BodyHandle>; 2],
    result: [Option<BodyRef>; 2],
    ended: [bool; 2],
    meta: Option<RequestMeta>,
}

pub struct H2Capture {
    core: ConnCapture,
    parsers: [FrameParser; 2],
    streams: HashMap<u32, StreamCapture>,
    shared: Arc<Shared>,
    conn: ConnInfo,
}

impl H2Capture {
    pub fn new(core: ConnCapture, shared: Arc<Shared>, conn: ConnInfo) -> Self {
        Self {
            core,
            parsers: [FrameParser::new(PREFACE_LEN), FrameParser::new(0)],
            streams: HashMap::new(),
            shared,
            conn,
        }
    }

    fn feed(&mut self, dir: Dir, data: &[u8]) {
        self.core.wire(dir, data.len());
        let mut parser = std::mem::replace(&mut self.parsers[dir as usize], FrameParser::new(0));
        parser.feed(data, &mut |ev| self.on_event(dir, ev));
        self.parsers[dir as usize] = parser;
    }

    fn on_event(&mut self, dir: Dir, ev: Event) {
        let d = dir as usize;
        match ev {
            Event::Framing { stream, bytes } => {
                let start = self.core.pos(dir);
                self.core.frame(dir, bytes);
                let end = self.core.pos(dir);
                if stream != 0 {
                    let range = &mut self.streams.entry(stream).or_default().range[d];
                    *range = Some(match *range {
                        Some([s, _]) => [s, end],
                        None => [start, end],
                    });
                }
            }
            Event::Data { stream, bytes } => {
                let s = self.streams.entry(stream).or_default();
                let body = s.body[d].get_or_insert_with(|| self.core.body_start());
                self.core.body_bytes(body, bytes);
            }
            Event::FrameEnd { stream, ty, flags } => {
                if stream == 0 {
                    return;
                }
                let ends = matches!(ty, TYPE_DATA | TYPE_HEADERS) && flags & FLAG_END_STREAM != 0;
                if ends {
                    self.end_direction(stream, d);
                } else if ty == TYPE_RST_STREAM {
                    self.end_direction(stream, 0);
                    self.end_direction(stream, 1);
                }
                self.emit_if_done(stream);
            }
        }
    }

    fn end_direction(&mut self, stream: u32, d: usize) {
        let Some(s) = self.streams.get_mut(&stream) else { return };
        if let Some(body) = s.body[d].take() {
            s.result[d] = self.core.body_end(body);
        }
        s.ended[d] = true;
    }

    /// Hands over a request's protocol-level fields; logged once the
    /// response stream has ended.
    pub fn submit(&mut self, stream: u32, meta: RequestMeta) {
        self.streams.entry(stream).or_default().meta = Some(meta);
        self.emit_if_done(stream);
    }

    fn emit_if_done(&mut self, stream: u32) {
        let done = self.streams.get(&stream).is_some_and(|s| s.meta.is_some() && s.ended[Dir::S2c as usize]);
        if done {
            let s = self.streams.remove(&stream).expect("checked above");
            self.emit(s);
        }
    }

    fn emit(&self, mut s: StreamCapture) {
        let Some(meta) = s.meta.take() else { return };
        let [c2s_range, s2c_range] = s.range;
        let [body, response_body] = s.result;
        self.shared.log_request(&self.conn, meta, MessageCapture { c2s_range, s2c_range, body, response_body });
    }

    /// Logs requests whose streams never finished and flushes capture.
    pub async fn finish(mut self) -> CaptureStats {
        for (_, mut s) in std::mem::take(&mut self.streams) {
            for d in 0..2 {
                if let Some(body) = s.body[d].take() {
                    s.result[d] = self.core.body_end(body);
                }
            }
            self.emit(s);
        }
        self.core.finish().await
    }
}

/// Feeds every byte read and written through an [`H2Capture`].
pub struct H2Tee<S> {
    inner: S,
    capture: Arc<Mutex<H2Capture>>,
}

impl<S> H2Tee<S> {
    pub fn new(inner: S, capture: Arc<Mutex<H2Capture>>) -> Self {
        Self { inner, capture }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for H2Tee<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        let read = &buf.filled()[before..];
        if !read.is_empty() {
            self.capture.lock().expect("capture lock poisoned").feed(Dir::C2s, read);
        }
        poll
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for H2Tee<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = poll
            && n > 0
        {
            self.capture.lock().expect("capture lock poisoned").feed(Dir::S2c, &buf[..n]);
        }
        poll
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq)]
    enum Ev {
        Framing(u32, Vec<u8>),
        Data(u32, Vec<u8>),
        End(u32, u8, u8),
    }

    /// Feeds `input` split at every `step` bytes, merging adjacent events.
    fn parse(input: &[u8], preface: usize, step: usize) -> Vec<Ev> {
        let mut p = FrameParser::new(preface);
        let mut out: Vec<Ev> = Vec::new();
        for chunk in input.chunks(step) {
            p.feed(chunk, &mut |ev| match ev {
                Event::Framing { stream, bytes } => match out.last_mut() {
                    Some(Ev::Framing(s, b)) if *s == stream => b.extend_from_slice(bytes),
                    _ => out.push(Ev::Framing(stream, bytes.to_vec())),
                },
                Event::Data { stream, bytes } => match out.last_mut() {
                    Some(Ev::Data(s, b)) if *s == stream => b.extend_from_slice(bytes),
                    _ => out.push(Ev::Data(stream, bytes.to_vec())),
                },
                Event::FrameEnd { stream, ty, flags } => out.push(Ev::End(stream, ty, flags)),
            });
        }
        out
    }

    fn frame(ty: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let len = payload.len() as u32;
        let mut f = len.to_be_bytes()[1..].to_vec();
        f.extend_from_slice(&[ty, flags]);
        f.extend_from_slice(&stream.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    #[test]
    fn data_payload_is_separated_from_framing_and_padding_at_any_split() {
        let mut input = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        input.extend(frame(TYPE_HEADERS, 0x4, 1, b"hdrs"));
        // Padded DATA: pad length 2, data "abc", padding "\0\0".
        input.extend(frame(TYPE_DATA, FLAG_PADDED | FLAG_END_STREAM, 1, b"\x02abc\0\0"));
        let expected = vec![
            Ev::Framing(0, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec()),
            Ev::Framing(1, frame(TYPE_HEADERS, 0x4, 1, b"hdrs")),
            Ev::End(1, TYPE_HEADERS, 0x4),
            // Frame header (length 6) plus the pad-length byte.
            Ev::Framing(1, frame(TYPE_DATA, 0x9, 1, b"\x02abc\0\0")[..10].to_vec()),
            Ev::Data(1, b"abc".to_vec()),
            Ev::Framing(1, b"\0\0".to_vec()),
            Ev::End(1, TYPE_DATA, 0x9),
        ];
        for step in [1, 2, 5, 9, 10, input.len()] {
            assert_eq!(parse(&input, PREFACE_LEN, step), expected, "step {step}");
        }
    }

    #[test]
    fn empty_frames_end_immediately() {
        let input = [frame(TYPE_DATA, FLAG_END_STREAM, 3, b""), frame(0x4, 0, 0, b"")].concat();
        assert_eq!(
            parse(&input, 0, 4),
            vec![
                Ev::Framing(3, frame(TYPE_DATA, 1, 3, b"")),
                Ev::End(3, TYPE_DATA, 1),
                Ev::Framing(0, frame(0x4, 0, 0, b"")),
                Ev::End(0, 0x4, 0),
            ]
        );
    }
}
