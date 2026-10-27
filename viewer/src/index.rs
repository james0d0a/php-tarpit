//! In-memory index of one sensor's JSONL logs, grouped by attack session.
//!
//! Both logs are append-only. Each file is followed by byte offset: a
//! refresh reads only bytes appended since the last one and consumes complete
//! lines, leaving a half-written trailing line for later. A file that shrank
//! or was replaced (new inode) triggers a full rebuild.

use std::{
    collections::{BTreeSet, HashMap},
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    net::IpAddr,
    path::{Path, PathBuf},
};

use uuid::Uuid;

use crate::records::{ConnectionRecord, RequestRecord};

pub const REQUESTS_LOG: &str = "requests.jsonl";
pub const CONNECTIONS_LOG: &str = "connections.jsonl";

/// A request's stable address: its connection and its position among that
/// connection's requests in log order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RequestKey {
    pub conn_id: Uuid,
    pub seq: usize,
}

pub struct Session {
    pub id: Uuid,
    pub src_ip: IpAddr,
    pub first_ts: String,
    pub last_ts: String,
    /// Indices into `Index::requests`, in log order.
    pub requests: Vec<usize>,
    pub connections: BTreeSet<Uuid>,
    pub has_body: bool,
    /// Request body sha256s whose first sighting is this session.
    pub first_sightings: BTreeSet<String>,
}

impl Session {
    fn new(id: Uuid, src_ip: IpAddr, ts: &str) -> Self {
        Self {
            id,
            src_ip,
            first_ts: ts.to_owned(),
            last_ts: ts.to_owned(),
            requests: Vec::new(),
            connections: BTreeSet::new(),
            has_body: false,
            first_sightings: BTreeSet::new(),
        }
    }

    fn touch(&mut self, ts: &str) {
        if ts < self.first_ts.as_str() {
            self.first_ts = ts.to_owned();
        }
        if ts > self.last_ts.as_str() {
            self.last_ts = ts.to_owned();
        }
    }
}

pub struct Request {
    pub key: RequestKey,
    pub record: RequestRecord,
}

#[derive(Default)]
struct Tail {
    offset: u64,
    #[cfg(unix)]
    inode: u64,
}

pub struct Index {
    dir: PathBuf,
    pub requests: Vec<Request>,
    pub sessions: HashMap<Uuid, Session>,
    pub connections: HashMap<Uuid, ConnectionRecord>,
    by_key: HashMap<RequestKey, usize>,
    conn_seq: HashMap<Uuid, usize>,
    /// Request body sha256 → attack session of its first sighting.
    pub first_sighting: HashMap<String, Uuid>,
    /// Body file names referenced by the logs; the only ones served.
    pub body_files: BTreeSet<String>,
    requests_tail: Tail,
    connections_tail: Tail,
}

impl Index {
    pub fn open(dir: &Path) -> io::Result<Self> {
        let mut index = Self::empty(dir.to_owned());
        index.refresh()?;
        Ok(index)
    }

    fn empty(dir: PathBuf) -> Self {
        Self {
            dir,
            requests: Vec::new(),
            sessions: HashMap::new(),
            connections: HashMap::new(),
            by_key: HashMap::new(),
            conn_seq: HashMap::new(),
            first_sighting: HashMap::new(),
            body_files: BTreeSet::new(),
            requests_tail: Tail::default(),
            connections_tail: Tail::default(),
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Indexes lines appended since the last refresh; rebuilds from scratch
    /// if either log shrank or was replaced.
    pub fn refresh(&mut self) -> io::Result<()> {
        let requests = read_appended(&self.dir.join(REQUESTS_LOG), &self.requests_tail)?;
        let connections = read_appended(&self.dir.join(CONNECTIONS_LOG), &self.connections_tail)?;
        let (Some(requests), Some(connections)) = (requests, connections) else {
            *self = Self::empty(std::mem::take(&mut self.dir));
            return self.refresh();
        };
        self.requests_tail = requests.tail;
        self.connections_tail = connections.tail;
        for line in complete_lines(&connections.bytes) {
            match serde_json::from_slice::<ConnectionRecord>(line) {
                Ok(record) => self.add_connection(record),
                Err(e) => tracing::debug!("skipping connection line: {e}"),
            }
        }
        for line in complete_lines(&requests.bytes) {
            match serde_json::from_slice::<RequestRecord>(line) {
                Ok(record) => self.add_request(record),
                Err(e) => tracing::debug!("skipping request line: {e}"),
            }
        }
        Ok(())
    }

    fn session(&mut self, id: Uuid, src_ip: IpAddr, ts: &str) -> &mut Session {
        let session = self
            .sessions
            .entry(id)
            .or_insert_with(|| Session::new(id, src_ip, ts));
        session.touch(ts);
        session
    }

    fn add_connection(&mut self, record: ConnectionRecord) {
        let session = self.session(record.attack_session_id, record.src_ip, &record.ts_open);
        session.connections.insert(record.conn_id);
        if let Some(close) = &record.ts_close {
            session.touch(close);
        }
        self.connections.insert(record.conn_id, record);
    }

    fn add_request(&mut self, record: RequestRecord) {
        let seq = self.conn_seq.entry(record.conn_id).or_default();
        let key = RequestKey {
            conn_id: record.conn_id,
            seq: *seq,
        };
        *seq += 1;
        let idx = self.requests.len();
        for body in [&record.body, &record.response_body].into_iter().flatten() {
            if let Some(file) = &body.file {
                self.body_files.insert(file.clone());
            }
        }
        let body_sha = record.body.as_ref().map(|b| b.sha256.clone());
        let first = body_sha
            .as_ref()
            .filter(|sha| !self.first_sighting.contains_key(*sha))
            .cloned();
        if let Some(sha) = &first {
            self.first_sighting
                .insert(sha.clone(), record.attack_session_id);
        }
        let session = self.session(record.attack_session_id, record.src_ip, &record.ts);
        session.requests.push(idx);
        session.connections.insert(record.conn_id);
        session.has_body |= body_sha.is_some();
        session.first_sightings.extend(first);
        self.by_key.insert(key, idx);
        self.requests.push(Request { key, record });
    }

    pub fn request(&self, key: RequestKey) -> Option<&Request> {
        self.by_key.get(&key).map(|&i| &self.requests[i])
    }
}

struct Appended {
    bytes: Vec<u8>,
    tail: Tail,
}

/// Reads complete lines appended after `tail`. `None` when the file shrank or
/// was replaced, so the caller must rebuild. A missing file reads as empty.
fn read_appended(path: &Path, tail: &Tail) -> io::Result<Option<Appended>> {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Ok((tail.offset == 0).then(|| Appended {
                bytes: Vec::new(),
                tail: Tail::default(),
            }));
        }
        Err(e) => return Err(e),
    };
    let meta = file.metadata()?;
    #[cfg(unix)]
    let inode = std::os::unix::fs::MetadataExt::ino(&meta);
    #[cfg(unix)]
    if tail.offset > 0 && inode != tail.inode {
        return Ok(None);
    }
    if meta.len() < tail.offset {
        return Ok(None);
    }
    file.seek(SeekFrom::Start(tail.offset))?;
    let mut bytes = Vec::with_capacity((meta.len() - tail.offset) as usize);
    file.read_to_end(&mut bytes)?;
    let complete = bytes.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1);
    bytes.truncate(complete);
    Ok(Some(Appended {
        tail: Tail {
            offset: tail.offset + complete as u64,
            #[cfg(unix)]
            inode,
        },
        bytes,
    }))
}

fn complete_lines(bytes: &[u8]) -> impl Iterator<Item = &[u8]> {
    bytes
        .split(|&b| b == b'\n')
        .filter(|l| !l.iter().all(u8::is_ascii_whitespace))
}
