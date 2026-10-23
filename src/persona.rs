//! Persona: the declarative static surface a sensor presents.
//!
//! Every response lists its headers in the exact order and capitalisation the
//! persona emits on HTTP/1.1. Two header values are filled in per response:
//! `{date}` (IMF-fixdate) and `{content_length}` (body length in bytes).
//! `{hostname}`, `{apache_version}` and `{php_version}` are replaced with the
//! resolved settings in any header value or body when the persona is built;
//! other braces are left alone.

use std::{collections::HashMap, path::Path, time::SystemTime};

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use serde::Deserialize;

use crate::config::Overrides;

const DATE_TOKEN: &str = "{date}";
const CONTENT_LENGTH_TOKEN: &str = "{content_length}";

/// A parsed persona file, before settings are substituted in.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersonaFile {
    name: String,
    /// The persona's settings layer, below CLI flags and environment variables.
    #[serde(default)]
    pub settings: Overrides,
    #[serde(default, rename = "route")]
    routes: Vec<RouteFile>,
    not_found: ResponseFile,
    bad_request: ResponseFile,
}

/// Values substituted into the persona's text.
pub struct Vars<'a> {
    pub hostname: &'a str,
    pub apache_version: &'a str,
    pub php_version: &'a str,
}

impl Vars<'_> {
    fn apply(&self, text: &str) -> String {
        text.replace("{hostname}", self.hostname)
            .replace("{apache_version}", self.apache_version)
            .replace("{php_version}", self.php_version)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteFile {
    path: String,
    #[serde(flatten)]
    response: ResponseFile,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseFile {
    status: u16,
    headers: Vec<(String, String)>,
    #[serde(default)]
    body: String,
}

#[derive(Debug)]
pub struct Persona {
    pub name: String,
    routes: HashMap<String, Response>,
    pub not_found: Response,
    pub bad_request: Response,
}

#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub reason: &'static str,
    headers: Vec<(String, HeaderValue)>,
    pub body: Bytes,
    /// sha256 of `body`, for the body store.
    pub body_sha256: [u8; 32],
}

#[derive(Debug)]
enum HeaderValue {
    Literal(String),
    Date,
    ContentLength,
}

impl PersonaFile {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read persona file {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("invalid persona file {}", path.display()))
    }

    pub fn parse(text: &str) -> Result<Self> {
        Ok(toml::from_str(text)?)
    }
}

impl Persona {
    pub fn build(file: PersonaFile, vars: &Vars) -> Result<Self> {
        let mut routes = HashMap::with_capacity(file.routes.len());
        for route in file.routes {
            if !route.path.starts_with('/') {
                bail!("route path {:?} must start with '/'", route.path);
            }
            let response = Response::prepare(route.response, vars)
                .with_context(|| format!("route {:?}", route.path))?;
            if routes.insert(route.path.clone(), response).is_some() {
                bail!("duplicate route path {:?}", route.path);
            }
        }
        Ok(Self {
            name: file.name,
            routes,
            not_found: Response::prepare(file.not_found, vars).context("not_found")?,
            bad_request: Response::prepare(file.bad_request, vars).context("bad_request")?,
        })
    }

    /// Picks the response for a request target. Matching is on the path only,
    /// so `/?p=1` and `/wp-login.php?ver=6` hit their routes.
    pub fn route(&self, target: &str) -> &Response {
        let path = target.split(['?', '#']).next().unwrap_or(target);
        self.routes.get(path).unwrap_or(&self.not_found)
    }
}

impl Response {
    fn prepare(file: ResponseFile, vars: &Vars) -> Result<Self> {
        let status = http::StatusCode::from_u16(file.status)
            .with_context(|| format!("invalid status {}", file.status))?;
        let mut headers = Vec::with_capacity(file.headers.len());
        for (name, value) in file.headers {
            http::HeaderName::from_bytes(name.as_bytes())
                .with_context(|| format!("invalid header name {name:?}"))?;
            let value = match value.as_str() {
                DATE_TOKEN => HeaderValue::Date,
                CONTENT_LENGTH_TOKEN => HeaderValue::ContentLength,
                _ => {
                    let value = vars.apply(&value);
                    http::HeaderValue::from_str(&value)
                        .with_context(|| format!("invalid value for header {name:?}"))?;
                    HeaderValue::Literal(value)
                }
            };
            headers.push((name, value));
        }
        let body = Bytes::from(vars.apply(&file.body));
        Ok(Self {
            status: file.status,
            reason: status.canonical_reason().unwrap_or(""),
            headers,
            body_sha256: <sha2::Sha256 as sha2::Digest>::digest(&body).into(),
            body,
        })
    }

    /// Headers in persona order with tokens filled in for this response.
    pub fn headers(&self) -> impl Iterator<Item = (&str, std::borrow::Cow<'_, str>)> {
        let date = httpdate::fmt_http_date(SystemTime::now());
        let length = self.body.len().to_string();
        self.headers.iter().map(move |(name, value)| {
            let value = match value {
                HeaderValue::Literal(v) => std::borrow::Cow::Borrowed(v.as_str()),
                HeaderValue::Date => std::borrow::Cow::Owned(date.clone()),
                HeaderValue::ContentLength => std::borrow::Cow::Owned(length.clone()),
            };
            (name.as_str(), value)
        })
    }
}
