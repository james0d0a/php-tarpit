//! Sensor settings, resolved per field in the order
//! CLI flag > environment variable > persona `[settings]` > built-in default.

use std::{fmt, net::IpAddr, path::PathBuf, str::FromStr};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

pub const ENV_PERSONA: &str = "PHP_TARPIT_PERSONA";

/// One layer of optional settings. Used for CLI flags, environment variables
/// and the persona file's `[settings]` table alike.
#[derive(Debug, Default, Clone, Deserialize, clap::Args)]
#[serde(deny_unknown_fields)]
pub struct Overrides {
    /// Directory for logs, raw streams and TLS material [env: PHP_TARPIT_DATA_DIR] [default: data]
    #[arg(long)]
    pub data_dir: Option<PathBuf>,
    /// Listen address; `::` is dual-stack [env: PHP_TARPIT_BIND] [default: ::]
    #[arg(long)]
    pub bind: Option<IpAddr>,
    /// Plain HTTP port; 0 picks an ephemeral port [env: PHP_TARPIT_HTTP_PORT] [default: 80]
    #[arg(long)]
    pub http_port: Option<u16>,
    /// TLS port [env: PHP_TARPIT_HTTPS_PORT] [default: 443]
    #[arg(long)]
    pub https_port: Option<u16>,
    /// Hostname for the certificate and `{hostname}` in the persona [env: PHP_TARPIT_HOSTNAME]
    /// [default: kept from the existing certificate, else random]
    #[arg(long)]
    pub hostname: Option<String>,
    /// `{apache_version}` in the persona [env: PHP_TARPIT_APACHE_VERSION] [default: 2.4.62]
    #[arg(long)]
    pub apache_version: Option<String>,
    /// `{php_version}` in the persona [env: PHP_TARPIT_PHP_VERSION] [default: 8.3.30]
    #[arg(long)]
    pub php_version: Option<String>,
    /// Raw capture cap per connection, e.g. `64MiB` [env: PHP_TARPIT_MAX_CONNECTION_BYTES] [default: 64MiB]
    #[arg(long)]
    pub max_connection_bytes: Option<ByteSize>,
    /// Total disk cap for the data directory, e.g. `5GiB` [env: PHP_TARPIT_MAX_TOTAL_BYTES] [default: 5GiB]
    #[arg(long)]
    pub max_total_bytes: Option<ByteSize>,
}

impl Overrides {
    /// Reads `PHP_TARPIT_*` variables through `get`, so tests need not touch
    /// the process environment.
    pub fn from_env(get: impl Fn(&str) -> Option<String>) -> Result<Self> {
        fn var<T: FromStr>(get: &impl Fn(&str) -> Option<String>, name: &str) -> Result<Option<T>>
        where
            T::Err: fmt::Display,
        {
            get(name)
                .map(|v| v.parse::<T>().map_err(|e| anyhow::anyhow!("invalid {name}={v:?}: {e}")))
                .transpose()
        }
        Ok(Self {
            data_dir: var(&get, "PHP_TARPIT_DATA_DIR")?,
            bind: var(&get, "PHP_TARPIT_BIND")?,
            http_port: var(&get, "PHP_TARPIT_HTTP_PORT")?,
            https_port: var(&get, "PHP_TARPIT_HTTPS_PORT")?,
            hostname: var(&get, "PHP_TARPIT_HOSTNAME")?,
            apache_version: var(&get, "PHP_TARPIT_APACHE_VERSION")?,
            php_version: var(&get, "PHP_TARPIT_PHP_VERSION")?,
            max_connection_bytes: var(&get, "PHP_TARPIT_MAX_CONNECTION_BYTES")?,
            max_total_bytes: var(&get, "PHP_TARPIT_MAX_TOTAL_BYTES")?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Settings {
    pub data_dir: PathBuf,
    pub bind: IpAddr,
    pub http_port: u16,
    pub https_port: u16,
    /// `None` keeps the hostname of the sensor's existing certificate, or
    /// picks a random one on first start.
    pub hostname: Option<String>,
    pub apache_version: String,
    pub php_version: String,
    pub max_connection_bytes: u64,
    pub max_total_bytes: u64,
}

impl Settings {
    /// Resolves each field from the first layer that sets it.
    pub fn resolve(cli: &Overrides, env: &Overrides, persona: &Overrides) -> Result<Self> {
        let layers = [cli, env, persona];
        macro_rules! pick {
            ($field:ident) => {
                layers.iter().find_map(|l| l.$field.clone())
            };
        }
        let settings = Self {
            data_dir: pick!(data_dir).unwrap_or_else(|| PathBuf::from("data")),
            bind: pick!(bind).unwrap_or(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)),
            http_port: pick!(http_port).unwrap_or(80),
            https_port: pick!(https_port).unwrap_or(443),
            hostname: pick!(hostname),
            apache_version: pick!(apache_version).unwrap_or_else(|| "2.4.62".to_owned()),
            php_version: pick!(php_version).unwrap_or_else(|| "8.3.30".to_owned()),
            max_connection_bytes: pick!(max_connection_bytes).map_or(64 << 20, |b| b.0),
            max_total_bytes: pick!(max_total_bytes).map_or(5 << 30, |b| b.0),
        };
        settings.validate()?;
        Ok(settings)
    }

    fn validate(&self) -> Result<()> {
        if let Some(h) = &self.hostname {
            validate_hostname(h).with_context(|| format!("invalid hostname {h:?}"))?;
        }
        for (name, v) in [("apache_version", &self.apache_version), ("php_version", &self.php_version)] {
            // Substituted into headers, so it must be a header-safe token.
            if v.is_empty() || !v.bytes().all(|b| b.is_ascii_graphic()) {
                bail!("invalid {name} {v:?}: must be non-empty printable ASCII without spaces");
            }
        }
        if self.http_port != 0 && self.http_port == self.https_port {
            bail!("http_port and https_port are both {}", self.http_port);
        }
        if self.max_connection_bytes == 0 || self.max_total_bytes == 0 {
            bail!("disk caps must be greater than zero");
        }
        Ok(())
    }
}

fn validate_hostname(h: &str) -> Result<()> {
    if h.is_empty() || h.len() > 253 {
        bail!("must be 1-253 characters");
    }
    for label in h.split('.') {
        let ok = (1..=63).contains(&label.len())
            && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-');
        if !ok {
            bail!("label {label:?} is not a valid DNS label");
        }
    }
    Ok(())
}

/// A byte count written as an integer or with a binary/decimal suffix:
/// `1048576`, `512KiB`, `64MiB`, `5GiB`, `10MB`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteSize(pub u64);

impl FromStr for ByteSize {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let s = s.trim();
        let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
        let (digits, unit) = s.split_at(split);
        let n: u64 = digits.parse().map_err(|_| format!("{s:?} is not a byte size"))?;
        let mult: u64 = match unit.trim() {
            "" | "B" => 1,
            "KB" => 1_000,
            "MB" => 1_000_000,
            "GB" => 1_000_000_000,
            "TB" => 1_000_000_000_000,
            "KiB" => 1 << 10,
            "MiB" => 1 << 20,
            "GiB" => 1 << 30,
            "TiB" => 1 << 40,
            other => return Err(format!("unknown size unit {other:?} (use B, KiB, MiB, GiB, TiB, KB, MB, GB, TB)")),
        };
        n.checked_mul(mult).map(ByteSize).ok_or_else(|| format!("{s:?} is too large"))
    }
}

impl<'de> Deserialize<'de> for ByteSize {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Int(u64),
            Text(String),
        }
        match Raw::deserialize(d)? {
            Raw::Int(n) => Ok(ByteSize(n)),
            Raw::Text(s) => s.parse().map_err(serde::de::Error::custom),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Overrides {
        let map: HashMap<String, String> =
            pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        Overrides::from_env(|k| map.get(k).cloned()).unwrap()
    }

    fn persona(toml_text: &str) -> Overrides {
        toml::from_str(toml_text).unwrap()
    }

    #[test]
    fn each_field_takes_the_highest_layer_that_sets_it() {
        let cli = Overrides { http_port: Some(1080), ..Default::default() };
        let env = env(&[("PHP_TARPIT_HTTP_PORT", "2080"), ("PHP_TARPIT_HTTPS_PORT", "2443")]);
        let persona = persona(
            r#"
            http_port = 3080
            https_port = 3443
            php_version = "8.3.1"
            max_total_bytes = "1GiB"
            "#,
        );
        let s = Settings::resolve(&cli, &env, &persona).unwrap();
        assert_eq!(s.http_port, 1080); // CLI over env and persona
        assert_eq!(s.https_port, 2443); // env over persona
        assert_eq!(s.php_version, "8.3.1"); // persona over default
        assert_eq!(s.max_total_bytes, 1 << 30);
        assert_eq!(s.apache_version, "2.4.62"); // default
        assert_eq!(s.max_connection_bytes, 64 << 20);
        assert_eq!(s.hostname, None);
    }

    #[test]
    fn invalid_environment_value_names_the_variable() {
        let err = Overrides::from_env(|k| (k == "PHP_TARPIT_HTTPS_PORT").then(|| "443x".to_owned()))
            .unwrap_err();
        assert!(err.to_string().contains("PHP_TARPIT_HTTPS_PORT"), "{err}");
    }

    #[test]
    fn byte_sizes_accept_integers_and_units() {
        assert_eq!("1048576".parse(), Ok(ByteSize(1 << 20)));
        assert_eq!("64MiB".parse(), Ok(ByteSize(64 << 20)));
        assert_eq!("10MB".parse(), Ok(ByteSize(10_000_000)));
        assert!("5 parsecs".parse::<ByteSize>().is_err());
        assert!("99999999999TiB".parse::<ByteSize>().is_err());
        assert_eq!(persona("max_connection_bytes = 4096").max_connection_bytes, Some(ByteSize(4096)));
    }

    #[test]
    fn unsafe_strings_are_rejected() {
        let bad_version = Overrides { php_version: Some("8.3.30\r\nX: y".into()), ..Default::default() };
        assert!(Settings::resolve(&bad_version, &Overrides::default(), &Overrides::default()).is_err());
        let bad_host = Overrides { hostname: Some("-evil.example".into()), ..Default::default() };
        assert!(Settings::resolve(&bad_host, &Overrides::default(), &Overrides::default()).is_err());
        let ok_host = Overrides { hostname: Some("web01.example.com".into()), ..Default::default() };
        assert!(Settings::resolve(&ok_host, &Overrides::default(), &Overrides::default()).is_ok());
    }
}
