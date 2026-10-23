//! TLS: a self-signed, snakeoil-style certificate generated once per sensor
//! and kept on the data volume, ALPN h2 + http/1.1, and an NSS key log so
//! wire captures can be decrypted.

use std::{
    fs::{File, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::Path,
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result};
use chrono::Datelike;
use rcgen::{CertificateParams, DnType, KeyPair};
use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

pub const CERT_FILE: &str = "cert.pem";
pub const KEY_FILE: &str = "key.pem";
pub const KEYLOG_FILE: &str = "keylog.txt";
pub const HOSTNAME_FILE: &str = "hostname";

/// Snakeoil certificates are valid for ten years.
const VALIDITY_YEARS: i32 = 10;

/// Builds the TLS config. Returns it with the sensor's hostname, which is the
/// certificate's CN.
pub fn server_config(tls_dir: &Path, hostname: Option<&str>) -> Result<(ServerConfig, String)> {
    let (certs, key, hostname) = load_or_create_cert(tls_dir, hostname)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("loading certificate")?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    config.key_log = Arc::new(KeyLogFile::open(&tls_dir.join(KEYLOG_FILE))?);
    Ok((config, hostname))
}

/// Reuses the stored certificate unless a different hostname is configured.
/// With no hostname configured, the stored one is kept, so the persona stays
/// consistent with its certificate across restarts.
fn load_or_create_cert(
    dir: &Path,
    configured: Option<&str>,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>, String)> {
    let cert_path = dir.join(CERT_FILE);
    let key_path = dir.join(KEY_FILE);
    let hostname_path = dir.join(HOSTNAME_FILE);
    let stored = (cert_path.exists() && key_path.exists())
        .then(|| std::fs::read_to_string(&hostname_path).ok())
        .flatten()
        .map(|s| s.trim().to_owned());
    let hostname = match (configured, stored) {
        (Some(c), Some(s)) if c == s => s,
        (None, Some(s)) => s,
        (configured, _) => {
            let hostname = configured.map_or_else(random_hostname, str::to_owned);
            let (cert_pem, key_pem) = generate(&hostname)?;
            replace_file(&key_path, key_pem.as_bytes(), 0o600)?;
            replace_file(&cert_path, cert_pem.as_bytes(), 0o644)?;
            // Written last: marks the pair as complete.
            replace_file(&hostname_path, format!("{hostname}\n").as_bytes(), 0o644)?;
            tracing::info!(hostname, "generated TLS certificate");
            hostname
        }
    };
    let certs = CertificateDer::pem_file_iter(&cert_path)
        .with_context(|| format!("reading {}", cert_path.display()))?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("parsing {}", cert_path.display()))?;
    let key = PrivateKeyDer::from_pem_file(&key_path)
        .with_context(|| format!("reading {}", key_path.display()))?;
    Ok((certs, key, hostname))
}

fn generate(hostname: &str) -> Result<(String, String)> {
    let key = KeyPair::generate()?;
    let mut params = CertificateParams::new(vec![hostname.to_owned()])?;
    params.distinguished_name.push(DnType::CommonName, hostname);
    let today = chrono::Utc::now().date_naive();
    let (month, day) = (today.month() as u8, today.day() as u8);
    params.not_before = rcgen::date_time_ymd(today.year(), month, day);
    // Feb 29 has no counterpart ten years on in most cases; use Feb 28.
    let end_day = if month == 2 && day == 29 { 28 } else { day };
    params.not_after = rcgen::date_time_ymd(today.year() + VALIDITY_YEARS, month, end_day);
    let cert = params.self_signed(&key)?;
    Ok((cert.pem(), key.serialize_pem()))
}

/// A VPS-provider-style default hostname, e.g. `vps-3f9a2c1d`.
fn random_hostname() -> String {
    format!("vps-{:08x}", rand::random::<u32>())
}

/// Writes via a temporary file and rename, so a crash never leaves a torn file.
fn replace_file(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    let tmp = path.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&tmp)
        .with_context(|| format!("creating {}", tmp.display()))?;
    file.write_all(contents)?;
    file.sync_all()?;
    std::fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))?;
    Ok(())
}

/// NSS key log format (`SSLKEYLOGFILE`), appended and unbuffered so lines
/// are on disk before the connection carries application data.
#[derive(Debug)]
struct KeyLogFile(Mutex<File>);

impl KeyLogFile {
    fn open(path: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("opening {}", path.display()))?;
        Ok(Self(Mutex::new(file)))
    }
}

impl rustls::KeyLog for KeyLogFile {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        let line = format!("{label} {} {}\n", hex::encode(client_random), hex::encode(secret));
        let mut file = self.0.lock().expect("key log lock poisoned");
        if let Err(e) = file.write_all(line.as_bytes()) {
            tracing::error!(error = %e, "key log write failed");
        }
    }
}
