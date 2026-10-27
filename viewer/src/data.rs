//! Reads captured bytes from `bodies/` and `streams/`.
//!
//! Paths are built only from values the logs recorded and that pass strict
//! validation: body file names must be 64 lowercase hex digits and stream
//! files are named by a parsed UUID. No request path is ever joined onto the
//! data directory, and `tls/` is never touched.

use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

use uuid::Uuid;

pub const BODIES_DIR: &str = "bodies";
pub const STREAMS_DIR: &str = "streams";

/// Bytes read for display, and whether more existed beyond them.
pub struct Excerpt {
    pub bytes: Vec<u8>,
    pub truncated: bool,
}

pub enum Fetch {
    Found(Excerpt),
    /// The file is gone (rotated) or never existed.
    Rotated,
}

pub fn is_body_file_name(name: &str) -> bool {
    name.len() == 64 && name.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub fn body_path(dir: &Path, file: &str) -> Option<PathBuf> {
    is_body_file_name(file).then(|| dir.join(BODIES_DIR).join(file))
}

pub fn stream_path(dir: &Path, conn_id: Uuid, s2c: bool) -> PathBuf {
    let ext = if s2c { "s2c" } else { "c2s" };
    dir.join(STREAMS_DIR).join(format!("{conn_id}.{ext}"))
}

/// Reads `[start, end)` of `path`, at most `limit` bytes.
pub fn read_range(path: &Path, start: u64, end: u64, limit: usize) -> io::Result<Fetch> {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Fetch::Rotated),
        Err(e) => return Err(e),
    };
    let len = end.saturating_sub(start);
    let take = len.min(limit as u64);
    file.seek(SeekFrom::Start(start))?;
    let mut bytes = Vec::with_capacity(take as usize);
    file.take(take).read_to_end(&mut bytes)?;
    Ok(Fetch::Found(Excerpt {
        truncated: len > take,
        bytes,
    }))
}

/// Reads up to `limit` bytes from the start of `path`.
pub fn read_prefix(path: &Path, limit: usize) -> io::Result<Fetch> {
    let size = match std::fs::metadata(path) {
        Ok(m) => m.len(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Fetch::Rotated),
        Err(e) => return Err(e),
    };
    read_range(path, 0, size, limit)
}
