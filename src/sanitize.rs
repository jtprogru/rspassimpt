use std::io::Write;

use zeroize::{Zeroize, Zeroizing};

/// Convert a CSV record title into a safe relative pass path.
///
/// Mirrors the python reference logic and additionally drops `.` / `..`
/// segments — otherwise a malicious CSV could write a `.gpg` file above
/// the store directory.
pub fn sanitize_path(title: &str) -> String {
    title
        .split('/')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .filter_map(clean_segment)
        .collect::<Vec<_>>()
        .join("/")
}

fn clean_segment(part: &str) -> Option<String> {
    let cleaned: String = part
        .chars()
        .filter(|c| !c.is_control() && *c != '\0')
        .collect();
    let trimmed = cleaned
        .trim_matches(|c: char| c == '.' || c == ' ')
        .to_string();
    if trimmed.is_empty() || trimmed == "." || trimmed == ".." {
        None
    } else {
        Some(trimmed)
    }
}

/// Raw CSV row. Every field except `title`/`password` is optional.
#[derive(Debug, serde::Deserialize)]
pub struct RawRow {
    #[serde(rename = "Title", default)]
    pub title: String,
    #[serde(rename = "URL", default)]
    pub url: String,
    #[serde(rename = "Username", default)]
    pub username: String,
    #[serde(rename = "Password", default)]
    pub password: String,
    #[serde(rename = "Notes", default)]
    pub notes: String,
    #[serde(rename = "OTPAuth", default)]
    pub otpauth: String,
}

impl RawRow {
    /// Wipe the string buffers (best-effort — the csv parser may keep copies
    /// in its own internal buffers).
    pub fn zeroize_in_place(&mut self) {
        self.title.zeroize();
        self.url.zeroize();
        self.username.zeroize();
        self.password.zeroize();
        self.notes.zeroize();
        self.otpauth.zeroize();
    }
}

/// Build an entry payload in passwordstore.org format.
/// Returns `Zeroizing<Vec<u8>>` — the buffer is zeroed on drop.
pub fn build_entry(row: &RawRow) -> Zeroizing<Vec<u8>> {
    let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(
        row.password.len() + row.url.len() + row.username.len() + row.notes.len() + 64,
    ));
    // First line is the password.
    buf.extend_from_slice(row.password.trim().as_bytes());
    buf.push(b'\n');

    write_field(&mut buf, "user", &row.username);
    write_field(&mut buf, "url", &row.url);
    write_field(&mut buf, "otpauth", &row.otpauth);

    let notes = row.notes.trim();
    if !notes.is_empty() {
        buf.extend_from_slice(b"notes: |\n");
        for line in notes.lines() {
            buf.extend_from_slice(b"  ");
            buf.extend_from_slice(line.as_bytes());
            buf.push(b'\n');
        }
    }
    buf
}

fn write_field(buf: &mut Vec<u8>, key: &str, value: &str) {
    let v = value.trim();
    if v.is_empty() {
        return;
    }
    // write!/writeln! into a Vec<u8> never fails.
    let _ = writeln!(buf, "{key}: {v}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_basic() {
        assert_eq!(sanitize_path("a/b/c"), "a/b/c");
        assert_eq!(sanitize_path(" a / b "), "a/b");
    }

    #[test]
    fn sanitize_drops_traversal() {
        assert_eq!(sanitize_path("../../etc/passwd"), "etc/passwd");
        assert_eq!(sanitize_path("./a/../b"), "a/b");
    }

    #[test]
    fn sanitize_drops_control_chars() {
        assert_eq!(sanitize_path("a\x00b/c\x07d"), "ab/cd");
        assert_eq!(sanitize_path("a\nb/c\rd"), "ab/cd");
    }

    #[test]
    fn build_entry_format() {
        let row = RawRow {
            title: "t".into(),
            url: "https://e.com".into(),
            username: "u@e.com".into(),
            password: "secret".into(),
            notes: "line1\nline2".into(),
            otpauth: "otpauth://totp/x?secret=Y".into(),
        };
        let out = build_entry(&row);
        let s = std::str::from_utf8(&out).unwrap();
        assert_eq!(
            s,
            "secret\n\
             user: u@e.com\n\
             url: https://e.com\n\
             otpauth: otpauth://totp/x?secret=Y\n\
             notes: |\n  line1\n  line2\n"
        );
    }

    #[test]
    fn build_entry_minimal() {
        let row = RawRow {
            title: "t".into(),
            url: "".into(),
            username: "".into(),
            password: "p".into(),
            notes: "".into(),
            otpauth: "".into(),
        };
        let out = build_entry(&row);
        assert_eq!(std::str::from_utf8(&out).unwrap(), "p\n");
    }
}
