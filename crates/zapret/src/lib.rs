//! Utilities of the platform: the service, the processes and the release machinery.

pub mod discord_cache;
pub mod hosts;
pub mod procs;
pub mod release;
pub mod root;
pub mod service;
pub mod snapshot;
pub mod targets;

use std::path::Path;

/// A text file: UTF-8, where broken bytes become U+FFFD, or UTF-16LE when it starts with the BOM
/// `FF FE`, as PowerShell 5.1's `>` and Notepad's "Unicode" write it (decoded without the BOM).
/// A UTF-8 BOM stays in the text: the caller strips it where it matters.
pub fn read_text(path: &Path) -> std::io::Result<String> {
    let bytes = std::fs::read(path)?;
    Ok(match bytes.strip_prefix(&[0xFF, 0xFE]) {
        Some(utf16) => String::from_utf16_lossy(
            &utf16
                .chunks(2)
                .map(|pair| match *pair {
                    [low, high] => u16::from_le_bytes([low, high]),
                    // A byte left over after the last pair.
                    _ => char::REPLACEMENT_CHARACTER as u16,
                })
                .collect::<Vec<_>>(),
        ),
        None => String::from_utf8_lossy(&bytes).into_owned(),
    })
}

/// Lower-case hex SHA-256.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Every case-insensitive occurrence of an ASCII `needle` replaced, as cmd expands `%VAR%`.
pub fn replace_ci(hay: &str, needle: &str, with: &str) -> String {
    let lower = hay.to_ascii_lowercase();
    let needle_lower = needle.to_ascii_lowercase();
    let mut out = String::with_capacity(hay.len());
    let mut last = 0;
    for (start, _) in lower.match_indices(&needle_lower) {
        out.push_str(&hay[last..start]);
        out.push_str(with);
        last = start + needle.len();
    }
    out.push_str(&hay[last..]);
    out
}

/// Tokens of a quoted command line: split on whitespace outside quotes, quotes kept.
pub fn quoted_tokens(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    for c in text.chars() {
        if c == '"' {
            quoted = !quoted;
        }
        if c.is_whitespace() && !quoted {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
        } else {
            current.push(c);
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

/// Tokens of a spawn line: quotes dropped, empty tokens gone.
pub fn spawn_tokens(text: &str) -> Vec<String> {
    quoted_tokens(text)
        .into_iter()
        .map(|token| token.replace('"', ""))
        .filter(|token| !token.is_empty())
        .collect()
}

/// A strategy or list name: 1-40 chars, Latin alphanumerics, space, `-`, `_`, `.` — and, since the
/// name becomes a file on disk, not a Windows device name.
pub fn validate_name(name: &str) -> anyhow::Result<String> {
    let name = name.trim();
    let ok = (1..=40).contains(&name.len())
        && name.starts_with(|c: char| c.is_ascii_alphanumeric())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '-' | '_' | '.'));
    anyhow::ensure!(
        ok,
        "a name is 1-40 Latin letters, digits, spaces, '-', '_' or '.', starting with a letter or digit: {name}"
    );
    let stem = name
        .split('.')
        .next()
        .unwrap_or_default()
        .trim_end()
        .to_ascii_uppercase();
    let device = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.as_bytes()[3].is_ascii_digit());
    anyhow::ensure!(
        !device,
        "{name} is a Windows device name: choose another name"
    );
    Ok(name.to_owned())
}

/// File names sort the way a person orders them: `2` before `10` (`general (ALT2)` before
/// `general (ALT10)`).
pub fn natural_key(file_name: &str) -> String {
    let mut key = String::with_capacity(file_name.len() + 16);
    let mut digits = String::new();
    for c in file_name.chars() {
        if c.is_ascii_digit() {
            digits.push(c);
            continue;
        }
        flush_digits(&mut key, &mut digits);
        key.extend(c.to_lowercase());
    }
    flush_digits(&mut key, &mut digits);
    key
}

fn flush_digits(key: &mut String, digits: &mut String) {
    if digits.is_empty() {
        return;
    }
    for _ in digits.len()..8 {
        key.push('0');
    }
    key.push_str(digits);
    digits.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(bytes: &[u8]) -> String {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("text.txt");
        std::fs::write(&path, bytes).unwrap();
        read_text(&path).unwrap()
    }

    #[test]
    fn a_utf16_bom_file_decodes_while_a_utf8_one_is_kept_as_it_is() {
        assert_eq!(read(b"one"), "one");
        assert_eq!(read(&[0xFF, 0xFE, b'o', 0, b'n', 0, b'e', 0]), "one");
    }

    #[test]
    fn sha256_is_the_known_hex() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn replace_ci_mimics_how_cmd_expands_a_variable() {
        assert_eq!(replace_ci("%List%-%list%", "%List%", "x"), "x-x");
        assert_eq!(
            replace_ci("a%LIST%s %LIST2%", "%List%", "bc"),
            "abcs %LIST2%"
        );
    }

    #[test]
    fn quoted_and_spawn_tokens_split_a_command_line() {
        assert_eq!(
            quoted_tokens(r#"-a "one two" --b"#),
            vec!["-a", "\"one two\"", "--b"]
        );
        assert_eq!(
            spawn_tokens(r#""C:\A B\x.exe" arg"#),
            vec![r"C:\A B\x.exe", "arg"]
        );
    }

    #[test]
    fn validate_names_accept_a_plain_name_and_refuse_the_rest() {
        assert_eq!(validate_name(" ALT-2.bat ").unwrap(), "ALT-2.bat");
        assert!(validate_name("").is_err());
        assert!(validate_name("конский").is_err());
        assert!(validate_name("CON").is_err());
        assert!(validate_name("COM9").is_err());
        assert!(validate_name(&"x".repeat(41)).is_err());
    }

    #[test]
    fn a_run_of_digits_sorts_older_numbers_first() {
        assert!(natural_key("general (ALT2).bat") < natural_key("general (ALT10).bat"));
        assert_eq!(natural_key("General.txt"), "general.txt");
    }
}
