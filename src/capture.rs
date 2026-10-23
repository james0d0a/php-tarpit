//! Raw per-connection capture. [`Tee`] sits directly below the HTTP parsers
//! (above TLS), so the files hold the exact plaintext bytes in each direction,
//! including chunk framing and HTTP/2 frames.

use std::{
    io,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
};

use bytes::Bytes;
use tokio::{
    fs::File,
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufWriter, ReadBuf},
    sync::mpsc,
    task::JoinHandle,
};
use uuid::Uuid;

enum Chunk {
    ClientToSensor(Bytes),
    SensorToClient(Bytes),
}

/// Byte totals per direction, readable while the connection is live.
#[derive(Default)]
pub struct Counters {
    pub c2s: AtomicU64,
    pub s2c: AtomicU64,
}

/// Owns the writer task for one connection's two stream files.
pub struct StreamCapture {
    tx: mpsc::UnboundedSender<Chunk>,
    counters: Arc<Counters>,
    writer: JoinHandle<io::Result<()>>,
}

/// File names for a connection's streams: `<conn_id>.c2s` and `<conn_id>.s2c`.
pub fn stream_paths(streams_dir: &Path, conn_id: Uuid) -> (PathBuf, PathBuf) {
    (
        streams_dir.join(format!("{conn_id}.c2s")),
        streams_dir.join(format!("{conn_id}.s2c")),
    )
}

impl StreamCapture {
    pub async fn create(streams_dir: &Path, conn_id: Uuid) -> io::Result<Self> {
        let (c2s_path, s2c_path) = stream_paths(streams_dir, conn_id);
        let c2s = BufWriter::new(File::create(c2s_path).await?);
        let s2c = BufWriter::new(File::create(s2c_path).await?);
        let (tx, rx) = mpsc::unbounded_channel();
        Ok(Self {
            tx,
            counters: Arc::default(),
            writer: tokio::spawn(write_streams(rx, c2s, s2c)),
        })
    }

    pub fn tee<S>(&self, inner: S) -> Tee<S> {
        Tee {
            inner,
            tx: self.tx.clone(),
            counters: self.counters.clone(),
        }
    }

    pub fn counters(&self) -> &Counters {
        &self.counters
    }

    /// Waits until every captured byte is on disk. Call after the [`Tee`] is dropped.
    pub async fn finish(self) -> io::Result<()> {
        drop(self.tx);
        self.writer.await.map_err(io::Error::other)?
    }
}

async fn write_streams(
    mut rx: mpsc::UnboundedReceiver<Chunk>,
    mut c2s: BufWriter<File>,
    mut s2c: BufWriter<File>,
) -> io::Result<()> {
    while let Some(chunk) = rx.recv().await {
        match chunk {
            Chunk::ClientToSensor(b) => c2s.write_all(&b).await?,
            Chunk::SensorToClient(b) => s2c.write_all(&b).await?,
        }
        // Flush whenever we catch up so files are current during long connections.
        if rx.is_empty() {
            c2s.flush().await?;
            s2c.flush().await?;
        }
    }
    c2s.flush().await?;
    s2c.flush().await
}

pub struct Tee<S> {
    inner: S,
    tx: mpsc::UnboundedSender<Chunk>,
    counters: Arc<Counters>,
}

impl<S: AsyncRead + Unpin> AsyncRead for Tee<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        let read = &buf.filled()[before..];
        if !read.is_empty() {
            self.counters.c2s.fetch_add(read.len() as u64, Ordering::Relaxed);
            // A send error means the writer died; the connection keeps working.
            let _ = self.tx.send(Chunk::ClientToSensor(Bytes::copy_from_slice(read)));
        }
        poll
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Tee<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = poll
            && n > 0
        {
            self.counters.s2c.fetch_add(n as u64, Ordering::Relaxed);
            let _ = self.tx.send(Chunk::SensorToClient(Bytes::copy_from_slice(&buf[..n])));
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
