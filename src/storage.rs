//! Data directory management: the deduplicated body store, disk usage
//! accounting, and oldest-first rotation under the total disk cap.
//!
//! Rotation deletes whole connections (both stream files) by last write time,
//! bodies by last reference time (their mtime is bumped on every dedup hit)
//! and wire-capture files by last write time, oldest first, until usage is
//! back under 90% of the cap. Streams of live connections, in-progress bodies
//! and the pcap file being written are never rotated. JSONL logs and TLS
//! material count toward the cap but are not rotated.

use std::{
    collections::HashSet,
    io,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result};
use tokio::{
    fs::{self, File, OpenOptions},
    io::AsyncWriteExt,
    sync::Notify,
};
use uuid::Uuid;

pub const STREAMS_DIR: &str = "streams";
pub const BODIES_DIR: &str = "bodies";
pub const PCAP_DIR: &str = "pcap";
/// Inside `bodies/`: bodies still being received.
const TMP_DIR: &str = "tmp";
/// Rescan interval, so log growth (not tracked incrementally) is noticed.
const RESCAN_INTERVAL: Duration = Duration::from_secs(60);

pub struct Storage {
    data_dir: PathBuf,
    streams_dir: PathBuf,
    bodies_dir: PathBuf,
    tmp_dir: PathBuf,
    pcap_dir: PathBuf,
    max_total_bytes: u64,
    used: AtomicU64,
    over_cap: Notify,
    live: Mutex<HashSet<Uuid>>,
    live_files: Mutex<HashSet<PathBuf>>,
}

impl Storage {
    pub fn open(data_dir: &Path, max_total_bytes: u64) -> Result<Arc<Self>> {
        let streams_dir = data_dir.join(STREAMS_DIR);
        let bodies_dir = data_dir.join(BODIES_DIR);
        let tmp_dir = bodies_dir.join(TMP_DIR);
        let pcap_dir = data_dir.join(PCAP_DIR);
        // Bodies left in tmp by a crash are incomplete; drop them.
        let _ = std::fs::remove_dir_all(&tmp_dir);
        for dir in [&streams_dir, &bodies_dir, &tmp_dir, &pcap_dir] {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        let storage = Arc::new(Self {
            data_dir: data_dir.to_owned(),
            streams_dir,
            bodies_dir,
            tmp_dir,
            pcap_dir,
            max_total_bytes,
            used: AtomicU64::new(0),
            over_cap: Notify::new(),
            live: Mutex::default(),
            live_files: Mutex::default(),
        });
        storage.rotate_now();
        Ok(storage)
    }

    pub fn streams_dir(&self) -> &Path {
        &self.streams_dir
    }

    pub fn pcap_dir(&self) -> &Path {
        &self.pcap_dir
    }

    pub fn body_path(&self, sha256: &[u8; 32]) -> PathBuf {
        self.bodies_dir.join(hex::encode(sha256))
    }

    pub fn tmp_body_path(&self, conn_id: Uuid, body_id: u64) -> PathBuf {
        self.tmp_dir.join(format!("{conn_id}-{body_id}"))
    }

    /// Bytes currently attributed to the data directory.
    pub fn used(&self) -> u64 {
        self.used.load(Ordering::Relaxed)
    }

    pub fn add(&self, n: u64) {
        let used = self.used.fetch_add(n, Ordering::Relaxed) + n;
        if used > self.max_total_bytes {
            self.over_cap.notify_one();
        }
    }

    pub fn sub(&self, n: u64) {
        let _ = self.used.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |u| Some(u.saturating_sub(n)));
    }

    pub fn set_live(&self, conn_id: Uuid, live: bool) {
        let mut set = self.live.lock().expect("live set poisoned");
        if live {
            set.insert(conn_id);
        } else {
            set.remove(&conn_id);
        }
    }

    /// Marks a file as being written, so rotation leaves it alone.
    pub fn set_live_file(&self, path: &Path, live: bool) {
        let mut set = self.live_files.lock().expect("live file set poisoned");
        if live {
            set.insert(path.to_owned());
        } else {
            set.remove(path);
        }
    }

    /// Runs rotation whenever usage crosses the cap, and rescans periodically.
    pub async fn rotation_task(self: Arc<Self>) {
        loop {
            tokio::select! {
                () = self.over_cap.notified() => {}
                () = tokio::time::sleep(RESCAN_INTERVAL) => {}
            }
            let this = self.clone();
            let _ = tokio::task::spawn_blocking(move || this.rotate_now()).await;
        }
    }

    /// Rescans the data directory and, if over the cap, deletes the oldest
    /// connections, bodies and pcap files. Blocking.
    pub fn rotate_now(&self) {
        let mut files = Vec::new();
        let total = walk(&self.data_dir, &mut files);
        self.used.store(total, Ordering::Relaxed);
        if total <= self.max_total_bytes {
            return;
        }

        let live = self.live.lock().expect("live set poisoned").clone();
        let live_files = self.live_files.lock().expect("live file set poisoned").clone();
        // Candidates: (age, size, paths). Stream files group per connection.
        let mut candidates: Vec<(SystemTime, u64, Vec<PathBuf>)> = Vec::new();
        let mut by_conn: std::collections::HashMap<String, usize> = Default::default();
        for f in files {
            let parent = f.path.parent();
            if parent == Some(self.streams_dir.as_path()) {
                let Some(stem) = f.path.file_stem().and_then(|s| s.to_str()).map(str::to_owned) else {
                    continue;
                };
                if stem.parse::<Uuid>().is_ok_and(|id| live.contains(&id)) {
                    continue;
                }
                match by_conn.get(&stem) {
                    Some(&i) => {
                        let c = &mut candidates[i];
                        c.0 = c.0.max(f.mtime);
                        c.1 += f.size;
                        c.2.push(f.path);
                    }
                    None => {
                        by_conn.insert(stem, candidates.len());
                        candidates.push((f.mtime, f.size, vec![f.path]));
                    }
                }
            } else if parent == Some(self.bodies_dir.as_path())
                || (parent == Some(self.pcap_dir.as_path()) && !live_files.contains(&f.path))
            {
                candidates.push((f.mtime, f.size, vec![f.path]));
            }
        }
        candidates.sort_by_key(|c| c.0);

        let target = self.max_total_bytes / 10 * 9;
        let mut remaining = total;
        let mut deleted = 0usize;
        for (_, size, paths) in candidates {
            if remaining <= target {
                break;
            }
            for p in &paths {
                let _ = std::fs::remove_file(p);
            }
            remaining = remaining.saturating_sub(size);
            deleted += 1;
        }
        self.sub(total - remaining);
        if remaining > self.max_total_bytes {
            tracing::warn!(remaining, cap = self.max_total_bytes, "data directory still over cap; nothing left to rotate");
        } else {
            tracing::info!(deleted, freed = total - remaining, "rotated oldest captures");
        }
    }

    /// Marks an existing body as referenced now. False if it doesn't exist.
    pub async fn touch_body(&self, sha256: &[u8; 32]) -> bool {
        let Ok(file) = OpenOptions::new().write(true).open(self.body_path(sha256)).await else {
            return false;
        };
        let file = file.into_std().await;
        tokio::task::spawn_blocking(move || file.set_modified(SystemTime::now()))
            .await
            .is_ok_and(|r| r.is_ok())
    }

    /// Stores `bytes` under `sha256` unless already present.
    pub async fn ensure_body(&self, sha256: &[u8; 32], bytes: &[u8]) -> io::Result<()> {
        if self.touch_body(sha256).await {
            return Ok(());
        }
        let tmp = self.tmp_dir.join(format!("static-{}", Uuid::now_v7()));
        let mut f = File::create(&tmp).await?;
        f.write_all(bytes).await?;
        f.flush().await?;
        drop(f);
        fs::rename(&tmp, self.body_path(sha256)).await?;
        self.add(bytes.len() as u64);
        Ok(())
    }
}

struct FileInfo {
    path: PathBuf,
    size: u64,
    mtime: SystemTime,
}

/// Collects regular files under `dir`; returns their total size.
fn walk(dir: &Path, out: &mut Vec<FileInfo>) -> u64 {
    let Ok(entries) = std::fs::read_dir(dir) else { return 0 };
    let mut total = 0;
    for entry in entries.flatten() {
        let Ok(meta) = entry.metadata() else { continue };
        if meta.is_dir() {
            total += walk(&entry.path(), out);
        } else if meta.is_file() {
            total += meta.len();
            out.push(FileInfo {
                path: entry.path(),
                size: meta.len(),
                mtime: meta.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            });
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file_aged(path: &Path, secs_ago: u64) {
        std::fs::write(path, vec![0u8; 1000]).unwrap();
        let f = std::fs::File::options().write(true).open(path).unwrap();
        f.set_modified(SystemTime::now() - Duration::from_secs(secs_ago)).unwrap();
    }

    #[test]
    fn pcap_rotation_is_oldest_first_but_spares_the_file_being_written() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(dir.path(), 2500).unwrap();
        let pcap = storage.pcap_dir().to_owned();
        let (writing, older, newer) = (pcap.join("a.pcap"), pcap.join("b.pcap"), pcap.join("c.pcap"));
        file_aged(&writing, 300);
        file_aged(&older, 200);
        file_aged(&newer, 100);
        storage.set_live_file(&writing, true);

        storage.rotate_now();
        assert!(writing.exists(), "the live file was rotated");
        assert!(!older.exists(), "the oldest closed file survived");
        assert!(newer.exists(), "rotated more than needed");
        assert_eq!(storage.used(), 2000);
    }
}
