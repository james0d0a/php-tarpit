//! TLS: a self-signed certificate generated once per sensor and kept on the
//! data volume, ALPN http/1.1 (plus h2 when enabled), and an NSS key log so
//! wire captures can be decrypted.
//!
//! The certificate mirrors Debian's `ssl-cert-snakeoil.pem` as produced by
//! `make-ssl-cert` (ssl-cert 1.1.2 / OpenSSL 3.0 on bookworm): RSA 2048,
//! sha256WithRSAEncryption, 20-byte random serial, `CN=<hostname>` as both
//! subject and issuer, valid from the moment of generation for 3650 days, and
//! exactly these non-critical extensions in this order: basicConstraints
//! `CA:FALSE`, subjectAltName `DNS:<hostname>`, subjectKeyIdentifier (SHA-1
//! of the public key, RFC 5280 method 1).

use std::{
    fs::{File, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::Path,
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result};
use rcgen::{CertificateParams, CustomExtension, DistinguishedName, DnType, DnValue, IsCa, KeyPair, PublicKeyData};
use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use sha1::{Digest, Sha1};

pub const CERT_FILE: &str = "cert.pem";
pub const KEY_FILE: &str = "key.pem";
pub const KEYLOG_FILE: &str = "keylog.txt";
pub const HOSTNAME_FILE: &str = "hostname";

/// `make-ssl-cert` runs `openssl req -x509 -days 3650`.
const VALIDITY_DAYS: i64 = 3650;
const OID_BASIC_CONSTRAINTS: &[u64] = &[2, 5, 29, 19];
const OID_SUBJECT_ALT_NAME: &[u64] = &[2, 5, 29, 17];
const OID_SUBJECT_KEY_IDENTIFIER: &[u64] = &[2, 5, 29, 14];

/// Builds the TLS config, offering h2 before http/1.1 when `http2` is set.
/// Returns it with the sensor's hostname, which is the certificate's CN.
pub fn server_config(tls_dir: &Path, hostname: Option<&str>, http2: bool) -> Result<(ServerConfig, String)> {
    let (certs, key, hostname) = load_or_create_cert(tls_dir, hostname)?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("loading certificate")?;
    config.alpn_protocols = if http2 {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    } else {
        vec![b"http/1.1".to_vec()]
    };
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
    let key = KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256).context("generating RSA key")?;
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, DnValue::Utf8String(hostname.to_owned()));
    let now = time::OffsetDateTime::now_utc().replace_nanosecond(0)?;
    params.not_before = now;
    params.not_after = now + time::Duration::days(VALIDITY_DAYS);
    params.serial_number = Some(random_serial().to_vec().into());
    // rcgen's own basicConstraints is critical and follows the SKID; emit all
    // three extensions ourselves in OpenSSL's order instead.
    params.is_ca = IsCa::NoCa;
    params.custom_extensions = vec![
        // BasicConstraints ::= SEQUENCE {} (cA defaults to FALSE)
        CustomExtension::from_oid_content(OID_BASIC_CONSTRAINTS, vec![0x30, 0x00]),
        CustomExtension::from_oid_content(OID_SUBJECT_ALT_NAME, san_dns(hostname)),
        // subjectPublicKey BIT STRING contents: the PKCS#1 RSAPublicKey.
        CustomExtension::from_oid_content(
            OID_SUBJECT_KEY_IDENTIFIER,
            der_tlv(0x04, &Sha1::digest(PublicKeyData::der_bytes(&key))),
        ),
    ];
    let cert = params.self_signed(&key)?;
    Ok((cert.pem(), key.serialize_pem()))
}

/// 159 random bits, like OpenSSL: positive, and a nonzero first byte keeps
/// the DER INTEGER at 20 bytes.
fn random_serial() -> [u8; 20] {
    let mut serial: [u8; 20] = rand::random();
    serial[0] &= 0x7f;
    if serial[0] == 0 {
        serial[0] = 1;
    }
    serial
}

/// GeneralNames ::= SEQUENCE { dNSName [2] IA5String }
fn san_dns(hostname: &str) -> Vec<u8> {
    der_tlv(0x30, &der_tlv(0x82, hostname.as_bytes()))
}

fn der_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match value.len() {
        n @ 0..0x80 => out.push(n as u8),
        n @ 0x80..0x100 => out.extend([0x81, n as u8]),
        n => out.extend([0x82, (n >> 8) as u8, n as u8]),
    }
    out.extend_from_slice(value);
    out
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

#[cfg(test)]
mod tests {
    use x509_parser::{oid_registry as oids, prelude::*, public_key::PublicKey};

    use super::*;

    /// The fields a scanner can see match Debian's make-ssl-cert output.
    #[test]
    fn certificate_has_the_debian_snakeoil_shape() {
        let (cert_pem, _) = generate("web01").unwrap();
        let (_, pem) = parse_x509_pem(cert_pem.as_bytes()).unwrap();
        let cert = pem.parse_x509().unwrap();

        assert_eq!(cert.version(), X509Version::V3);
        assert_eq!(cert.signature_algorithm.algorithm, oids::OID_PKCS1_SHA256WITHRSA);
        assert_eq!(cert.subject().to_string(), "CN=web01");
        assert_eq!(cert.issuer().to_string(), "CN=web01");
        assert!(matches!(cert.public_key().parsed().unwrap(), PublicKey::RSA(k) if k.key_size() == 2048));
        let serial = cert.raw_serial();
        assert!(serial.len() == 20 && serial[0] != 0 && serial[0] < 0x80, "{serial:02x?}");
        let validity = cert.validity();
        assert_eq!((validity.not_after - validity.not_before).unwrap().whole_days(), VALIDITY_DAYS);

        let exts = cert.extensions();
        let order: Vec<_> = exts.iter().map(|e| e.oid.clone()).collect();
        assert_eq!(
            order,
            [oids::OID_X509_EXT_BASIC_CONSTRAINTS, oids::OID_X509_EXT_SUBJECT_ALT_NAME, oids::OID_X509_EXT_SUBJECT_KEY_IDENTIFIER]
        );
        assert!(exts.iter().all(|e| !e.critical));
        for e in exts {
            match e.parsed_extension() {
                ParsedExtension::BasicConstraints(bc) => assert!(!bc.ca && bc.path_len_constraint.is_none()),
                ParsedExtension::SubjectAlternativeName(san) => {
                    assert_eq!(san.general_names, [GeneralName::DNSName("web01")]);
                }
                ParsedExtension::SubjectKeyIdentifier(kid) => {
                    let spk = &cert.public_key().subject_public_key.data;
                    assert_eq!(kid.0, &Sha1::digest(spk)[..]);
                }
                other => panic!("unexpected extension {other:?}"),
            }
        }
    }
}
