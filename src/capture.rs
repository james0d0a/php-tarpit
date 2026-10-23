//! Per-connection capture with body deduplication.
//!
//! Each connection has two stream files, `streams/<conn_id>.c2s` and
//! `streams/<conn_id>.s2c`, holding every byte in that direction *except*
//! message body payloads, which are stored once per content in
//! `bodies/<sha256>`. The original bytes are recovered by re-inserting body
//! payloads where the stream's own framing says they go:
//!
//! - HTTP/1.x: after a head with `Content-Length: N`, the next N payload bytes;
//!   with chunked coding, each chunk's data (sizes, CRLFs and trailers stay in
//!   the stream). The body file is the concatenated payload.
//! - HTTP/2: the data portion of each DATA frame (frame header, pad length and
//!   padding stay in the stream). The body file is that stream's data, in order.
//!
//! Offsets reported in the request log are positions in the stream files.
//! Once a connection has stored `max_connection_bytes` (stream bytes plus body
//! bytes received), nothing more is stored for it; a body cut off this way is
//! stored under the hash of the part kept.

use std::{collections::HashMap, io, path::PathBuf, sync::Arc};

use bytes::Bytes;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::{
    fs::{self, File},
    io::{AsyncWriteExt, BufWriter},
    sync::mpsc,
    task::JoinHandle,
};
use uuid::Uuid;

use crate::storage::Storage;

/// Bodies up to this size are held in memory until their hash is known, so
/// duplicates never touch the disk.
const BODY_MEM_LIMIT: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    C2s = 0,
    S2c = 1,
}

/// A stored (or partially stored) message body.
#[derive(Debug, Clone, Serialize)]
pub struct BodyRef {
    /// sha256 of every body byte received.
    pub sha256: String,
    /// Body bytes received.
    pub size: u64,
    /// Bytes kept in the body file; less than `size` when capture was capped.
    pub stored: u64,
    /// File name under `bodies/`: sha256 of the stored bytes. Absent when
    /// nothing was stored.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
}

/// What capture recorded for one request/response exchange.
#[derive(Debug, Default)]
pub struct MessageCapture {
    /// `[start, end)` in the `.c2s` file; for HTTP/2, the span of the
    /// stream's frames (other streams' frames may be interleaved).
    pub c2s_range: Option<[u64; 2]>,
    pub s2c_range: Option<[u64; 2]>,
    pub body: Option<BodyRef>,
    pub response_body: Option<BodyRef>,
}

pub struct CaptureStats {
    pub wire_c2s: u64,
    pub wire_s2c: u64,
    pub truncated: bool,
}

enum Op {
    Stream(Dir, Bytes),
    BodyChunk(u64, Bytes),
    /// Body finished; `Some(hash)` names the stored bytes, `None` discards.
    BodyEnd(u64, Option<[u8; 32]>),
    /// A body whose bytes and hash are known up front (persona responses).
    StaticBody([u8; 32], Bytes),
}

/// An in-progress body.
pub struct BodyHandle {
    id: u64,
    full: Sha256,
    size: u64,
    stored: u64,
    /// Hash of the stored prefix, fixed when the connection cap cut it off.
    stored_hash: Option<[u8; 32]>,
}

pub struct ConnCapture {
    conn_id: Uuid,
    storage: Arc<Storage>,
    tx: mpsc::UnboundedSender<Op>,
    writer: JoinHandle<io::Result<()>>,
    pos: [u64; 2],
    wire: [u64; 2],
    stored: u64,
    cap: u64,
    truncated: bool,
    next_body: u64,
}

impl ConnCapture {
    pub async fn create(storage: Arc<Storage>, conn_id: Uuid, max_connection_bytes: u64) -> io::Result<Self> {
        let dir = storage.streams_dir();
        let c2s = BufWriter::new(File::create(dir.join(format!("{conn_id}.c2s"))).await?);
        let s2c = BufWriter::new(File::create(dir.join(format!("{conn_id}.s2c"))).await?);
        storage.set_live(conn_id, true);
        let (tx, rx) = mpsc::unbounded_channel();
        let writer = tokio::spawn(write_loop(rx, storage.clone(), conn_id, [c2s, s2c]));
        Ok(Self {
            conn_id,
            storage,
            tx,
            writer,
            pos: [0; 2],
            wire: [0; 2],
            stored: 0,
            cap: max_connection_bytes,
            truncated: false,
            next_body: 0,
        })
    }

    /// Counts bytes that crossed the wire (before elision or capping).
    pub fn wire(&mut self, dir: Dir, n: usize) {
        self.wire[dir as usize] += n as u64;
    }

    /// Current end of the stream file for `dir`.
    pub fn pos(&self, dir: Dir) -> u64 {
        self.pos[dir as usize]
    }

    /// Claims up to `n` bytes of the connection's storage budget.
    fn budget(&mut self, n: usize) -> usize {
        let left = self.cap.saturating_sub(self.stored);
        let take = (n as u64).min(left) as usize;
        if take < n {
            self.truncated = true;
        }
        self.stored += take as u64;
        take
    }

    /// Records non-body bytes (heads, framing) in the stream file.
    pub fn frame(&mut self, dir: Dir, bytes: &[u8]) {
        let take = self.budget(bytes.len());
        if take > 0 {
            let _ = self.tx.send(Op::Stream(dir, Bytes::copy_from_slice(&bytes[..take])));
            self.pos[dir as usize] += take as u64;
        }
    }

    pub fn body_start(&mut self) -> BodyHandle {
        self.next_body += 1;
        BodyHandle { id: self.next_body, full: Sha256::new(), size: 0, stored: 0, stored_hash: None }
    }

    pub fn body_bytes(&mut self, body: &mut BodyHandle, bytes: &[u8]) {
        let take = if body.stored_hash.is_some() { 0 } else { self.budget(bytes.len()) };
        if body.stored_hash.is_none() && take < bytes.len() {
            let mut prefix = body.full.clone();
            prefix.update(&bytes[..take]);
            body.stored_hash = Some(prefix.finalize().into());
        }
        if take > 0 {
            let _ = self.tx.send(Op::BodyChunk(body.id, Bytes::copy_from_slice(&bytes[..take])));
            body.stored += take as u64;
        }
        body.full.update(bytes);
        body.size += bytes.len() as u64;
    }

    /// Finishes a body. `None` for an empty body.
    pub fn body_end(&mut self, body: BodyHandle) -> Option<BodyRef> {
        let full: [u8; 32] = body.full.finalize().into();
        let file = (body.stored > 0).then(|| body.stored_hash.unwrap_or(full));
        let _ = self.tx.send(Op::BodyEnd(body.id, file));
        (body.size > 0).then(|| BodyRef {
            sha256: hex::encode(full),
            size: body.size,
            stored: body.stored,
            file: file.map(hex::encode),
        })
    }

    /// Records a body known in advance (a persona response). It is stored
    /// once per sensor and does not count against the connection cap.
    pub fn static_body(&mut self, sha256: [u8; 32], bytes: &Bytes) -> Option<BodyRef> {
        if bytes.is_empty() {
            return None;
        }
        let _ = self.tx.send(Op::StaticBody(sha256, bytes.clone()));
        let hex = hex::encode(sha256);
        Some(BodyRef { sha256: hex.clone(), size: bytes.len() as u64, stored: bytes.len() as u64, file: Some(hex) })
    }

    /// Waits until everything is on disk.
    pub async fn finish(self) -> CaptureStats {
        let Self { conn_id, storage, tx, writer, wire, truncated, .. } = self;
        drop(tx);
        match writer.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::error!(%conn_id, error = %e, "capture write failed"),
            Err(e) => tracing::error!(%conn_id, error = %e, "capture writer panicked"),
        }
        storage.set_live(conn_id, false);
        CaptureStats { wire_c2s: wire[0], wire_s2c: wire[1], truncated }
    }
}

/// A body being received: in memory until it outgrows [`BODY_MEM_LIMIT`],
/// then in a temp file.
#[derive(Default)]
struct PendingBody {
    mem: Vec<u8>,
    file: Option<(BufWriter<File>, PathBuf)>,
    on_disk: u64,
}

async fn write_loop(
    mut rx: mpsc::UnboundedReceiver<Op>,
    storage: Arc<Storage>,
    conn_id: Uuid,
    mut streams: [BufWriter<File>; 2],
) -> io::Result<()> {
    let mut bodies: HashMap<u64, PendingBody> = HashMap::new();
    let mut result = Ok(());
    while let Some(op) = rx.recv().await {
        let step = async {
            match op {
                Op::Stream(dir, b) => {
                    streams[dir as usize].write_all(&b).await?;
                    storage.add(b.len() as u64);
                }
                Op::BodyChunk(id, b) => {
                    let body = bodies.entry(id).or_default();
                    if body.file.is_none() && body.mem.len() + b.len() <= BODY_MEM_LIMIT {
                        body.mem.extend_from_slice(&b);
                    } else {
                        if body.file.is_none() {
                            let path = storage.tmp_body_path(conn_id, id);
                            let mut f = BufWriter::new(File::create(&path).await?);
                            f.write_all(&body.mem).await?;
                            body.on_disk = body.mem.len() as u64;
                            storage.add(body.on_disk);
                            body.mem = Vec::new();
                            body.file = Some((f, path));
                        }
                        let (f, _) = body.file.as_mut().expect("spilled above");
                        f.write_all(&b).await?;
                        body.on_disk += b.len() as u64;
                        storage.add(b.len() as u64);
                    }
                }
                Op::BodyEnd(id, hash) => {
                    let body = bodies.remove(&id).unwrap_or_default();
                    finish_body(&storage, conn_id, id, body, hash).await?;
                }
                Op::StaticBody(hash, bytes) => storage.ensure_body(&hash, &bytes).await?,
            }
            io::Result::Ok(())
        };
        if let Err(e) = step.await {
            // Keep draining so the connection never blocks; report once.
            if result.is_ok() {
                result = Err(e);
            }
        }
        if rx.is_empty() {
            for s in &mut streams {
                s.flush().await?;
            }
        }
    }
    for s in &mut streams {
        s.flush().await?;
    }
    // Bodies never ended (writer side bug or abort): discard temp files.
    for (_, body) in bodies {
        if let Some((_, path)) = body.file {
            let _ = fs::remove_file(path).await;
            storage.sub(body.on_disk);
        }
    }
    result
}

async fn finish_body(
    storage: &Storage,
    conn_id: Uuid,
    id: u64,
    body: PendingBody,
    hash: Option<[u8; 32]>,
) -> io::Result<()> {
    let discard = |path: PathBuf, n: u64| async move {
        let _ = fs::remove_file(path).await;
        storage.sub(n);
    };
    let Some(hash) = hash else {
        if let Some((_, path)) = body.file {
            discard(path, body.on_disk).await;
        }
        return Ok(());
    };
    if storage.touch_body(&hash).await {
        if let Some((_, path)) = body.file {
            discard(path, body.on_disk).await;
        }
        return Ok(());
    }
    let path = match body.file {
        Some((mut f, path)) => {
            f.flush().await?;
            path
        }
        None => {
            let path = storage.tmp_body_path(conn_id, id);
            let mut f = File::create(&path).await?;
            f.write_all(&body.mem).await?;
            f.flush().await?;
            storage.add(body.mem.len() as u64);
            path
        }
    };
    fs::rename(&path, storage.body_path(&hash)).await
}
