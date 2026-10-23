//! Black-box lab driver: brings up `compose.yaml` under a unique project name,
//! runs client containers against the sensor, and fetches the sensor's data
//! directory for inspection. Uses the `docker` CLI (override with
//! `PT_HARNESS_DOCKER`, e.g. `podman`); `DOCKER_HOST` is honoured as usual.

use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicU32, Ordering},
    thread::sleep,
    time::{Duration, Instant},
};

use serde_json::Value;
use tempfile::TempDir;

pub struct Lab {
    project: String,
    compose_file: PathBuf,
}

/// Output of a client container.
pub struct ClientOutput {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

/// The sensor's `/data`, copied out of its volume.
pub struct Data {
    _dir: TempDir,
    pub root: PathBuf,
    pub requests: Vec<Value>,
    pub connections: Vec<Value>,
}

impl Data {
    pub fn read(&self, relative: impl AsRef<Path>) -> Vec<u8> {
        let path = self.root.join(relative);
        std::fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
    }

    pub fn body(&self, body_ref: &Value) -> Vec<u8> {
        self.read(Path::new("bodies").join(body_ref["file"].as_str().expect("body has a file")))
    }

    pub fn stream(&self, request: &Value, dir: &str) -> Vec<u8> {
        self.read(format!("streams/{}.{dir}", request["conn_id"].as_str().unwrap()))
    }
}

fn docker() -> Command {
    Command::new(std::env::var("PT_HARNESS_DOCKER").unwrap_or_else(|_| "docker".into()))
}

fn run(cmd: &mut Command) -> Output {
    let out = cmd.output().unwrap_or_else(|e| panic!("running {cmd:?}: {e}"));
    out
}

fn check(cmd: &mut Command) -> Output {
    let out = run(cmd);
    assert!(
        out.status.success(),
        "{cmd:?} failed:\n{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

impl Lab {
    /// Builds the images, starts the sensor and waits until it answers.
    pub fn up() -> Self {
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let lab = Self {
            project: format!("ptharness-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::Relaxed)),
            compose_file: Path::new(env!("CARGO_MANIFEST_DIR")).join("compose.yaml"),
        };
        check(lab.compose().args(["--profile", "clients", "build", "--quiet"]));
        check(lab.compose().args(["up", "--detach", "sensor"]));
        let ready = lab.client(
            "curl",
            &[],
            &["-sk", "-o", "/dev/null", "--retry", "30", "--retry-connrefused", "--retry-delay", "1", "https://sensor/"],
        );
        assert_eq!(ready.status, 0, "sensor never became ready: {}\n{}", ready.stderr, lab.logs());
        lab
    }

    fn compose(&self) -> Command {
        let mut cmd = docker();
        cmd.arg("compose").arg("-p").arg(&self.project).arg("-f").arg(&self.compose_file);
        cmd
    }

    /// Runs a one-off client container (a compose service) with `args`.
    pub fn client(&self, service: &str, env: &[(&str, &str)], args: &[&str]) -> ClientOutput {
        let mut cmd = self.compose();
        cmd.args(["run", "--rm", "-T"]);
        for (k, v) in env {
            cmd.arg("-e").arg(format!("{k}={v}"));
        }
        cmd.arg(service).args(args);
        let out = run(&mut cmd);
        ClientOutput {
            status: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    pub fn logs(&self) -> String {
        let out = run(self.compose().args(["logs", "--no-color", "sensor"]));
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr)
    }

    /// Copies the sensor's data directory until `ready` accepts it (logs and
    /// stream files are written asynchronously), or panics after 30 s.
    pub fn data_when(&self, ready: impl Fn(&Data) -> bool) -> Data {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let dir = tempfile::tempdir().unwrap();
            check(self.compose().arg("cp").arg("sensor:/data").arg(dir.path()));
            let root = dir.path().join("data");
            let data = Data {
                requests: jsonl(&root.join("requests.jsonl")),
                connections: jsonl(&root.join("connections.jsonl")),
                root,
                _dir: dir,
            };
            if ready(&data) {
                return data;
            }
            assert!(Instant::now() < deadline, "sensor data never reached the expected state\n{}", self.logs());
            sleep(Duration::from_millis(500));
        }
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        let _ = run(self.compose().args(["--profile", "clients", "down", "--volumes", "--remove-orphans"]));
    }
}

fn jsonl(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).expect("valid JSONL"))
        .collect()
}
