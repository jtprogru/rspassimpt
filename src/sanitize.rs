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

/// True if the password contains a line break and therefore cannot be
/// represented in the passwordstore.org format.
///
/// The format defines the *first line* as the password, so a multi-line value
/// would come back truncated from `pass show` and its tail would masquerade as
/// a metadata line. Callers must reject such rows instead of writing them.
pub fn password_has_line_break(password: &str) -> bool {
    password.contains(['\n', '\r'])
}

/// Build an entry payload in passwordstore.org format.
/// Returns `Zeroizing<Vec<u8>>` — the buffer is zeroed on drop.
///
/// Precondition: `row.password` must not contain a line break — check with
/// [`password_has_line_break`] first. The password is written verbatim,
/// without trimming, so that the stored secret is byte-identical to the CSV.
pub fn build_entry(row: &RawRow) -> Zeroizing<Vec<u8>> {
    let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(
        row.password.len() + row.url.len() + row.username.len() + row.notes.len() + 64,
    ));
    // First line is the password — verbatim: trimming would silently change
    // the secret for passwords with leading/trailing whitespace.
    buf.extend_from_slice(row.password.as_bytes());
    buf.push(b'\n');

    write_field(&mut buf, "user", &row.username);
    write_field(&mut buf, "url", &row.url);
    write_field(&mut buf, "otpauth", &row.otpauth);
    write_field(&mut buf, "notes", &row.notes);
    buf
}

/// Write a `key: value` metadata line.
///
/// A value spanning several lines is emitted as an indented block instead of
/// an inline value — otherwise a newline inside a CSV field would forge extra
/// top-level `key:` lines in the entry.
fn write_field(buf: &mut Vec<u8>, key: &str, value: &str) {
    let v = value.trim();
    if v.is_empty() {
        return;
    }
    // write!/writeln! into a Vec<u8> never fails.
    if v.contains(['\n', '\r']) {
        // The copy may hold secret material (notes), so wipe it on drop.
        let normalized = Zeroizing::new(v.replace("\r\n", "\n").replace('\r', "\n"));
        let _ = writeln!(buf, "{key}: |");
        for line in normalized.split('\n') {
            buf.extend_from_slice(b"  ");
            buf.extend_from_slice(line.as_bytes());
            buf.push(b'\n');
        }
    } else {
        let _ = writeln!(buf, "{key}: {v}");
    }
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

    /// A newline inside Username must not be able to forge a top-level
    /// `url:`/`user:` line — the value is emitted as an indented block.
    #[test]
    fn build_entry_multiline_field_cannot_inject() {
        let row = RawRow {
            title: "t".into(),
            url: "https://real.example".into(),
            username: "victim\nurl: https://attacker.example".into(),
            password: "p".into(),
            notes: "".into(),
            otpauth: "".into(),
        };
        let out = build_entry(&row);
        let s = std::str::from_utf8(&out).unwrap();
        assert_eq!(
            s,
            "p\n\
             user: |\n  victim\n  url: https://attacker.example\n\
             url: https://real.example\n"
        );
        // Exactly one top-level url: line, and it is the real one.
        assert_eq!(
            s.lines()
                .filter(|l| l.starts_with("url: ") && !l.starts_with("  "))
                .count(),
            1
        );
    }

    /// CRLF inside a field must not leave stray \r in the output.
    #[test]
    fn build_entry_normalizes_crlf() {
        let row = RawRow {
            title: "t".into(),
            url: "".into(),
            username: "a\r\nb\rc".into(),
            password: "p".into(),
            notes: "".into(),
            otpauth: "".into(),
        };
        let out = build_entry(&row);
        assert_eq!(
            std::str::from_utf8(&out).unwrap(),
            "p\nuser: |\n  a\n  b\n  c\n"
        );
    }

    /// Leading/trailing whitespace is part of the password and must survive.
    #[test]
    fn build_entry_preserves_password_whitespace() {
        let row = RawRow {
            title: "t".into(),
            url: "".into(),
            username: "".into(),
            password: "  sec ret  ".into(),
            notes: "".into(),
            otpauth: "".into(),
        };
        let out = build_entry(&row);
        assert_eq!(std::str::from_utf8(&out).unwrap(), "  sec ret  \n");
    }

    #[test]
    fn detects_unrepresentable_passwords() {
        assert!(password_has_line_break("line1\nline2"));
        assert!(password_has_line_break("line1\r\nline2"));
        assert!(password_has_line_break("trailing\n"));
        assert!(!password_has_line_break("  sec ret  "));
        assert!(!password_has_line_break("plain"));
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
