//! Turns attacker-controlled bytes into inert display text. The output is
//! still HTML-escaped by the templates; this only makes control characters
//! (terminal escapes, NUL, bidi overrides) visible instead of acting on them.

use std::fmt::Write;

/// Lossy UTF-8 with control and bidi-control characters shown as `\xNN` /
/// `\u{NNNN}`. Newlines and tabs are kept; `\r` is shown and kept.
pub fn printable(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for chunk in bytes.utf8_chunks() {
        for c in chunk.valid().chars() {
            match c {
                '\n' | '\t' => out.push(c),
                '\r' => out.push_str("\\r"),
                c if (c as u32) < 0x20 || c == '\x7f' => {
                    let _ = write!(out, "\\x{:02x}", c as u32);
                }
                c if c.is_control() || is_bidi_control(c) => {
                    let _ = write!(out, "\\u{{{:04x}}}", c as u32);
                }
                c => out.push(c),
            }
        }
        for b in chunk.invalid() {
            let _ = write!(out, "\\x{b:02x}");
        }
    }
    out
}

/// [`printable`] on one line: newlines and tabs escaped too.
pub fn printable_line(s: &str) -> String {
    printable(s.as_bytes())
        .replace('\n', "\\n")
        .replace('\t', "\\t")
}

fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

/// Classic 16-bytes-per-row hex dump with an ASCII column.
pub fn hexdump(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 4 + 16);
    for (row, chunk) in bytes.chunks(16).enumerate() {
        let _ = write!(out, "{:08x}  ", row * 16);
        for i in 0..16 {
            match chunk.get(i) {
                Some(b) => {
                    let _ = write!(out, "{b:02x} ");
                }
                None => out.push_str("   "),
            }
            if i == 7 {
                out.push(' ');
            }
        }
        out.push(' ');
        out.extend(chunk.iter().map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                b as char
            } else {
                '.'
            }
        }));
        out.push('\n');
    }
    out
}

/// At most `max` chars, with an ellipsis when cut.
pub fn clip(s: &str, max: usize) -> String {
    match s.char_indices().nth(max) {
        Some((i, _)) => format!("{}…", &s[..i]),
        None => s.to_owned(),
    }
}

/// `2026-10-24T00:11:46.189948Z` → `2026-10-24 00:11:46Z`.
pub fn short_ts(ts: &str) -> String {
    let ts = ts.replacen('T', " ", 1);
    match ts.find('.') {
        Some(dot) if ts.ends_with('Z') => format!("{}Z", &ts[..dot]),
        _ => ts,
    }
}

pub fn short_id(id: &uuid::Uuid) -> String {
    id.simple().to_string()[24..].to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_and_invalid_bytes_are_visible() {
        assert_eq!(
            printable(b"a\x1b[31mb\r\n\xff\x00"),
            "a\\x1b[31mb\\r\n\\xff\\x00"
        );
        assert_eq!(printable("x\u{202e}y".as_bytes()), "x\\u{202e}y");
    }
}
