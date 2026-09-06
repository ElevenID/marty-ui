//! Shared response-text projection, separate from JSON byte decoding.
//! UTF-8/ASCII/Latin-1 are qualified here; additional Python codecs remain an
//! explicit adoption gate, not an assertion of blanket charset compatibility.

pub(crate) fn response_text(bytes: &[u8], content_type: Option<&str>) -> String {
    let charset = content_type.and_then(charset_parameter).unwrap_or_default();
    let normalized = normalize_encoding(&charset);
    let bytes = match normalized.as_str() {
        "ascii" | "646" | "ansi_x3.4_1968" | "ansi_x3.4_1986" | "ansi_x3_4_1968" | "cp367"
        | "csascii" | "ibm367" | "iso646_us" | "iso_646.irv_1991" | "iso_ir_6" | "us"
        | "us_ascii" => {
            return bytes
                .iter()
                .map(|byte| {
                    if byte.is_ascii() {
                        char::from(*byte)
                    } else {
                        char::REPLACEMENT_CHARACTER
                    }
                })
                .collect();
        }
        "latin_1" | "8859" | "cp819" | "csisolatin1" | "ibm819" | "iso8859" | "iso8859_1"
        | "iso_8859_1" | "iso_8859_1_1987" | "iso_ir_100" | "l1" | "latin" | "latin1" => {
            // Python Latin-1 is not the WHATWG Windows-1252 alias.
            return bytes.iter().map(|byte| char::from(*byte)).collect();
        }
        "utf_8_sig" => bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes),
        // Includes UTF-8 aliases and unknown/missing/empty declarations.
        // Other recognized Python codecs still require their own qualification.
        _ => bytes,
    };
    String::from_utf8_lossy(bytes).into_owned()
}

fn normalize_encoding(value: &str) -> String {
    let mut output = String::new();
    let mut separator = false;
    for character in value.chars() {
        if character.is_ascii_alphanumeric() || character == '.' {
            if separator && !output.is_empty() {
                output.push('_');
            }
            output.push(character.to_ascii_lowercase());
            separator = false;
        } else {
            separator = true;
        }
    }
    output
}

fn charset_parameter(content_type: &str) -> Option<String> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    for (index, character) in content_type.char_indices() {
        if escaped {
            escaped = false;
        } else if quoted && character == '\\' {
            escaped = true;
        } else if character == '"' {
            quoted = !quoted;
        } else if !quoted && character == ';' {
            parts.push(&content_type[start..index]);
            start = index + 1;
        }
    }
    parts.push(&content_type[start..]);
    // Python's email parameter reader accepts even an invalid media-type token
    // and uses the first charset, while respecting quoted parameter separators.
    parts.into_iter().skip(1).find_map(|part| {
        let (name, value) = part.split_once('=')?;
        if !name.trim().eq_ignore_ascii_case("charset") {
            return None;
        }
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .unwrap_or(value)
            .replace("\\\\", "\\")
            .replace("\\\"", "\"");
        Some(if value.is_ascii() {
            value
        } else {
            String::new()
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_and_latin1_keep_their_distinct_byte_mappings() {
        let bytes = (0..=255).collect::<Vec<u8>>();
        let ascii = response_text(&bytes, Some("text/plain; charset=ascii"));
        assert_eq!(
            ascii.chars().take(128).collect::<String>(),
            (0..128).map(char::from).collect::<String>()
        );
        assert!(ascii
            .chars()
            .skip(128)
            .all(|c| c == char::REPLACEMENT_CHARACTER));
        assert_eq!(
            response_text(&bytes, Some("text/plain; charset=latin1"))
                .chars()
                .map(u32::from)
                .collect::<Vec<_>>(),
            (0..=255).collect::<Vec<_>>()
        );
    }

    #[test]
    fn quoted_parameters_first_charset_and_bom_behavior_are_independent() {
        assert_eq!(
            response_text(
                &[0xe9],
                Some("synthetic; note=\"x; charset=ascii\"; CHARSET=\"ISO 8859-1\"; charset=ascii")
            ),
            "é"
        );
        let bom = b"\xef\xbb\xbfcaf\xc3\xa9";
        assert_eq!(
            response_text(bom, Some("text/plain; charset=utf-8-sig")),
            "café"
        );
        assert_eq!(
            response_text(bom, Some("text/plain; charset=utf-8")),
            "\u{feff}café"
        );
        assert_eq!(
            response_text(bom, Some("text/plain; charset=ascii")),
            "���caf��"
        );
    }
}
