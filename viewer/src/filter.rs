//! Attack session list filters over logged facts only (ADR 0002). Every field
//! is a raw query-string value so the form round-trips exactly; empty means
//! unset.

use serde::{Deserialize, Serialize};

use crate::index::{Index, Session};

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct Filter {
    /// `1`: only sessions that sent a request body.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub body: String,
    /// `1`: only sessions holding at least one first sighting.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub first: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub min_requests: String,
    /// Any request with this method (case-insensitive).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub method: String,
    /// Any request answered with this status.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub status: String,
    /// Any request target containing this text.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub target: String,
    /// Source IP prefix, e.g. `45.135.` or a full address.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub ip: String,
    /// Sessions active at or after this time (`2026-10-24` or `2026-10-24T13:00`, UTC).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub from: String,
    /// Sessions active at or before this time; a date or minute covers all of it.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub to: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub page: String,
}

/// A filter value that could not be used, reported back to the operator.
pub struct Invalid(pub &'static str);

struct Parsed<'a> {
    body: bool,
    first: bool,
    min_requests: usize,
    method: Option<&'a str>,
    status: Option<u16>,
    target: Option<&'a str>,
    ip: Option<&'a str>,
    from: Option<String>,
    to: Option<String>,
}

fn set(s: &str) -> Option<&str> {
    let s = s.trim();
    (!s.is_empty()).then_some(s)
}

/// Normalises `2026-10-24 13:00` to `2026-10-24T13:00`; rejects anything
/// that is not a prefix of an RFC 3339 UTC timestamp.
fn time_prefix(s: &str) -> Result<Option<String>, Invalid> {
    let Some(s) = set(s) else { return Ok(None) };
    let s = s.replacen(' ', "T", 1);
    let shape = "dddd-dd-ddTdd:dd:dd";
    let ok = s.len() >= 4
        && s.len() <= shape.len()
        && s.bytes().zip(shape.bytes()).all(|(c, p)| {
            if p == b'd' {
                c.is_ascii_digit()
            } else {
                c == p
            }
        });
    if ok {
        Ok(Some(s))
    } else {
        Err(Invalid(
            "times must look like 2026-10-24 or 2026-10-24T13:00",
        ))
    }
}

impl Filter {
    pub fn page(&self) -> usize {
        self.page.trim().parse().unwrap_or(0)
    }

    pub fn with_page(&self, page: usize) -> Self {
        Self {
            page: if page == 0 {
                String::new()
            } else {
                page.to_string()
            },
            ..self.clone()
        }
    }

    pub fn query(&self) -> String {
        serde_urlencoded::to_string(self).unwrap_or_default()
    }

    fn parse(&self) -> Result<Parsed<'_>, Invalid> {
        Ok(Parsed {
            body: self.body == "1",
            first: self.first == "1",
            min_requests: match set(&self.min_requests) {
                None => 0,
                Some(n) => n
                    .parse()
                    .map_err(|_| Invalid("minimum requests must be a whole number"))?,
            },
            method: set(&self.method),
            status: match set(&self.status) {
                None => None,
                Some(s) => Some(
                    s.parse()
                        .map_err(|_| Invalid("status must be a number such as 200"))?,
                ),
            },
            target: set(&self.target),
            ip: set(&self.ip),
            from: time_prefix(&self.from)?,
            to: time_prefix(&self.to)?,
        })
    }

    /// Matching sessions, most recently active first.
    pub fn apply<'a>(&self, index: &'a Index) -> Result<Vec<&'a Session>, Invalid> {
        let p = self.parse()?;
        let mut out: Vec<&Session> = index
            .sessions
            .values()
            .filter(|s| p.matches(index, s))
            .collect();
        out.sort_by(|a, b| b.last_ts.cmp(&a.last_ts).then(b.id.cmp(&a.id)));
        Ok(out)
    }
}

impl Parsed<'_> {
    fn matches(&self, index: &Index, s: &Session) -> bool {
        if self.body && !s.has_body
            || self.first && s.first_sightings.is_empty()
            || s.requests.len() < self.min_requests
        {
            return false;
        }
        if let Some(ip) = self.ip
            && !s.src_ip.to_string().starts_with(ip)
        {
            return false;
        }
        if let Some(from) = &self.from
            && s.last_ts.as_str() < from.as_str()
        {
            return false;
        }
        // A prefix bound covers its whole period: compare only that many chars.
        if let Some(to) = &self.to
            && s.first_ts.get(..to.len()).unwrap_or(&s.first_ts) > to.as_str()
        {
            return false;
        }
        if self.method.is_none() && self.status.is_none() && self.target.is_none() {
            return true;
        }
        s.requests.iter().any(|&i| {
            let r = &index.requests[i].record;
            self.method.is_none_or(|m| r.method.eq_ignore_ascii_case(m))
                && self.status.is_none_or(|st| r.status == Some(st))
                && self.target.is_none_or(|t| r.target.contains(t))
        })
    }
}
