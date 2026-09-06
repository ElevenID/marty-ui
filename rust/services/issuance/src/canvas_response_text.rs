//! Shared response-text projection, separate from JSON byte decoding.
//! Stateless single-byte mappings come from the frozen published response owner.
//! Multibyte/stateful codecs remain an explicit adoption gate.
use std::{collections::BTreeMap, sync::OnceLock};

struct SingleByteCodecs {
    tables: BTreeMap<String, [char; 256]>,
    aliases: BTreeMap<String, String>,
}

fn single_byte_codecs() -> &'static SingleByteCodecs {
    static REGISTRY: OnceLock<SingleByteCodecs> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        #[derive(serde::Deserialize)]
        struct Frozen {
            schema: String,
            codecs: BTreeMap<String, String>,
            aliases: BTreeMap<String, String>,
        }
        let frozen: Frozen = serde_json::from_str(include_str!(
            "../../../../contracts/canvas-single-byte-codecs.json"
        ))
        .expect("embedded published codec data must be valid");
        assert_eq!(frozen.schema, "marty.canvas-single-byte-codecs/v1");
        let tables = frozen
            .codecs
            .into_iter()
            .map(|(name, mapping)| {
                let table: [char; 256] = mapping
                    .chars()
                    .collect::<Vec<_>>()
                    .try_into()
                    .expect("embedded single-byte codec must map every byte");
                (name, table)
            })
            .collect::<BTreeMap<_, _>>();
        assert!(frozen
            .aliases
            .values()
            .all(|name| tables.contains_key(name)));
        SingleByteCodecs {
            tables,
            aliases: frozen.aliases,
        }
    })
}

pub(crate) fn response_text(bytes: &[u8], content_type: Option<&str>) -> String {
    let charset = content_type.and_then(charset_parameter).unwrap_or_default();
    let normalized = normalize_encoding(&charset);
    let registry = single_byte_codecs();
    if let Some(name) = registry.aliases.get(&normalized) {
        let table = &registry.tables[name];
        return bytes.iter().map(|byte| table[usize::from(*byte)]).collect();
    }
    let bytes = match normalized.as_str() {
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
    fn every_published_single_byte_alias_preserves_all_byte_values() {
        let frozen: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../contracts/canvas-single-byte-codecs.json"
        ))
        .unwrap();
        let bytes = (0..=255).collect::<Vec<u8>>();
        assert_eq!(frozen["codecs"].as_object().unwrap().len(), 73);
        assert_eq!(frozen["aliases"].as_object().unwrap().len(), 291);
        for (alias, name) in frozen["aliases"].as_object().unwrap() {
            let expected = frozen["codecs"][name.as_str().unwrap()].as_str().unwrap();
            for label in [alias.clone(), alias.to_ascii_uppercase().replace('_', "-")] {
                assert_eq!(
                    response_text(&bytes, Some(&format!("text/plain; charset={label}"))),
                    expected,
                    "{alias}"
                );
            }
        }
        for alias in frozen["unregistered_aliases"].as_array().unwrap() {
            assert_eq!(
                response_text(
                    &bytes,
                    Some(&format!("text/plain; charset={}", alias.as_str().unwrap()))
                ),
                String::from_utf8_lossy(&bytes),
                "unregistered alias must retain the published fallback"
            );
        }
    }

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
