//! Shared response-text projection, separate from JSON byte decoding.
//! Stateless single-byte mappings come from the frozen published response owner.
//! Other multibyte/stateful codecs remain an explicit adoption gate.
use std::{collections::BTreeMap, sync::OnceLock};

#[path = "canvas_response_charset.rs"]
mod charset;
use charset::charset_parameter;
#[path = "canvas_response_iso2022.rs"]
mod iso2022;
#[path = "canvas_response_multibyte.rs"]
mod multibyte;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CanvasResponseTextError {
    #[error("UTF-16 stream does not start with BOM")]
    Utf16MissingBom,
    #[error("UTF-32 stream does not start with BOM")]
    Utf32MissingBom,
    #[error("'<' not supported between instances of 'int' and 'NoneType'")]
    NumberedAfterBareContinuation,
    #[error("'<' not supported between instances of 'NoneType' and 'int'")]
    BareAfterNumberedContinuation,
    #[error("internal codec error")]
    InternalCodec,
    #[error("pending buffer overflow")]
    PendingBufferOverflow,
}

impl CanvasResponseTextError {
    pub const fn diagnostic_class(self) -> &'static str {
        match self {
            Self::InternalCodec => "RuntimeError",
            Self::Utf16MissingBom | Self::Utf32MissingBom | Self::PendingBufferOverflow => {
                "UnicodeError"
            }
            Self::NumberedAfterBareContinuation | Self::BareAfterNumberedContinuation => {
                "TypeError"
            }
        }
    }
}

#[derive(Clone, Copy, serde::Deserialize)]
enum UnicodeEncoding {
    #[serde(rename = "utf_16")]
    Utf16,
    #[serde(rename = "utf_16_le")]
    Utf16Le,
    #[serde(rename = "utf_16_be")]
    Utf16Be,
    #[serde(rename = "utf_32")]
    Utf32,
    #[serde(rename = "utf_32_le")]
    Utf32Le,
    #[serde(rename = "utf_32_be")]
    Utf32Be,
}

struct ResponseCodecs {
    tables: BTreeMap<String, [char; 256]>,
    aliases: BTreeMap<String, String>,
    unicode_aliases: BTreeMap<String, UnicodeEncoding>,
    registry_aliases: BTreeMap<String, String>,
}

fn response_codecs() -> &'static ResponseCodecs {
    static REGISTRY: OnceLock<ResponseCodecs> = OnceLock::new();
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
        #[derive(serde::Deserialize)]
        struct Unicode {
            schema: String,
            aliases: BTreeMap<String, UnicodeEncoding>,
        }
        let unicode: Unicode = serde_json::from_str(include_str!(
            "../../../../contracts/canvas-unicode-text-oracle.json"
        ))
        .expect("embedded published Unicode codec data must be valid");
        assert_eq!(unicode.schema, "marty.canvas-unicode-text/v1");
        #[derive(serde::Deserialize)]
        struct Headers {
            schema: String,
            registry_aliases: BTreeMap<String, String>,
        }
        let headers: Headers = serde_json::from_str(include_str!(
            "../../../../contracts/canvas-charset-headers-oracle.json"
        ))
        .expect("embedded published registry aliases must be valid");
        assert_eq!(headers.schema, "marty.canvas-charset-headers/v1");
        ResponseCodecs {
            tables,
            aliases: frozen.aliases,
            unicode_aliases: unicode.aliases,
            registry_aliases: headers.registry_aliases,
        }
    })
}

pub(crate) fn response_text(
    bytes: &[u8],
    content_type: Option<&str>,
) -> Result<String, CanvasResponseTextError> {
    // HTTPX does not select a text decoder for an empty response body.
    if bytes.is_empty() {
        return Ok(String::new());
    }
    let charset = content_type
        .map(charset_parameter)
        .transpose()?
        .flatten()
        .unwrap_or_default();
    let normalized = resolve_encoding(&charset);
    let registry = response_codecs();
    if let Some(name) = registry.aliases.get(&normalized) {
        let table = &registry.tables[name];
        return Ok(bytes.iter().map(|byte| table[usize::from(*byte)]).collect());
    }
    if let Some(encoding) = registry.unicode_aliases.get(&normalized) {
        return unicode_text(bytes, *encoding);
    }
    if let Some(machine) = multibyte::lookup(&normalized) {
        return Ok(machine
            .decode(bytes, false)
            .expect("replacement decoding cannot fail"));
    }
    if let Some(codec) = iso2022::lookup(&normalized) {
        return Ok(codec
            .decode(bytes, false)?
            .expect("replacement result or typed codec error"));
    }
    let bytes = match normalized.as_str() {
        "utf_8_sig" => bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes),
        // Includes UTF-8 aliases and unknown/missing/empty declarations.
        // Other recognized Python codecs still require their own qualification.
        _ => bytes,
    };
    Ok(String::from_utf8_lossy(bytes).into_owned())
}

fn unicode_text(
    mut bytes: &[u8],
    encoding: UnicodeEncoding,
) -> Result<String, CanvasResponseTextError> {
    use UnicodeEncoding::*;
    let (width, mut little, generic) = match encoding {
        Utf16 => (2, true, true),
        Utf16Le => (2, true, false),
        Utf16Be => (2, false, false),
        Utf32 => (4, true, true),
        Utf32Le => (4, true, false),
        Utf32Be => (4, false, false),
    };
    if generic && bytes.len() >= width {
        let (le, be): (&[u8], &[u8]) = if width == 2 {
            (&[0xff, 0xfe], &[0xfe, 0xff])
        } else {
            (&[0xff, 0xfe, 0, 0], &[0, 0, 0xfe, 0xff])
        };
        little = if bytes.starts_with(le) {
            true
        } else if bytes.starts_with(be) {
            false
        } else {
            return Err(if width == 2 {
                CanvasResponseTextError::Utf16MissingBom
            } else {
                CanvasResponseTextError::Utf32MissingBom
            });
        };
        bytes = &bytes[width..];
    }
    Ok(unicode_units(bytes, width, little, false).expect("replacement decoding cannot fail"))
}

pub(crate) fn unicode_units(
    bytes: &[u8],
    width: usize,
    little: bool,
    strict: bool,
) -> Option<String> {
    let mut text = String::new();
    let mut index = 0;
    while index < bytes.len() {
        let remaining = &bytes[index..];
        if remaining.len() < width {
            if strict {
                return None;
            }
            text.push(char::REPLACEMENT_CHARACTER);
            break;
        }
        let scalar = if width == 4 {
            let word = [remaining[0], remaining[1], remaining[2], remaining[3]];
            if little {
                u32::from_le_bytes(word)
            } else {
                u32::from_be_bytes(word)
            }
        } else {
            let unit = |pair: &[u8]| {
                if little {
                    u16::from_le_bytes([pair[0], pair[1]])
                } else {
                    u16::from_be_bytes([pair[0], pair[1]])
                }
            };
            let first = unit(remaining);
            if (0xd800..=0xdbff).contains(&first) {
                // A high surrogate plus an incomplete next unit is one error.
                if remaining.len() < 4 {
                    if strict {
                        return None;
                    }
                    text.push(char::REPLACEMENT_CHARACTER);
                    break;
                }
                let second = unit(&remaining[2..]);
                if (0xdc00..=0xdfff).contains(&second) {
                    index += 2;
                    0x10000 + ((u32::from(first) - 0xd800) << 10) + (u32::from(second) - 0xdc00)
                } else {
                    u32::from(first)
                }
            } else {
                u32::from(first)
            }
        };
        let character = char::from_u32(scalar);
        text.push(if strict {
            character?
        } else {
            character.unwrap_or(char::REPLACEMENT_CHARACTER)
        });
        index += width;
    }
    Some(text)
}

fn resolve_encoding(value: &str) -> String {
    let normalized = normalize_encoding(value);
    let aliases = &response_codecs().registry_aliases;
    aliases
        .get(&normalized)
        .or_else(|| aliases.get(&normalized.replace('.', "_")))
        .cloned()
        .unwrap_or(normalized)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn observation<T: serde::Serialize>(
        result: Result<T, CanvasResponseTextError>,
    ) -> serde_json::Value {
        match result {
            Ok(value) => serde_json::json!({"value":value}),
            Err(error) => {
                serde_json::json!({"error_class":error.diagnostic_class(),"error":error.to_string()})
            }
        }
    }

    #[test]
    fn unicode_text_and_excerpt_match_published_decoder_corpus() {
        let frozen: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../contracts/canvas-unicode-text-oracle.json"
        ))
        .unwrap();
        assert_eq!(frozen["cases"].as_array().unwrap().len(), 372);
        assert_eq!(frozen["aliases"].as_object().unwrap().len(), 16);
        for case in frozen["cases"].as_array().unwrap() {
            let bytes = hex::decode(case["body_hex"].as_str().unwrap()).unwrap();
            for (alias, target) in frozen["aliases"].as_object().unwrap() {
                if target != &case["charset"] {
                    continue;
                }
                for label in [alias.clone(), alias.to_ascii_uppercase().replace('_', "-")] {
                    let content_type = format!("text/plain; charset={label}");
                    assert_eq!(
                        observation(response_text(&bytes, Some(&content_type))),
                        case["text"],
                        "text {label} {}",
                        case["name"]
                    );
                    assert_eq!(
                        observation(crate::canvas_credentials_protocol::response_excerpt(
                            &bytes,
                            Some(&content_type)
                        )),
                        case["excerpt"],
                        "excerpt {label} {}",
                        case["name"]
                    );
                }
            }
        }
    }

    #[test]
    fn multibyte_response_cases_match_published_codecs() {
        for (_, source) in multibyte::SOURCES {
            let frozen: serde_json::Value = serde_json::from_str(source).unwrap();
            assert_published_codec_cases(&frozen);
        }
    }

    #[test]
    fn gb18030_response_cases_match_published_codec() {
        let frozen = serde_json::from_str(include_str!(
            "../../../../contracts/canvas-gb18030-codec.json"
        ))
        .unwrap();
        assert_published_codec_cases(&frozen);
    }

    fn assert_published_codec_cases(frozen: &serde_json::Value) {
        for case in frozen["cases"].as_array().unwrap() {
            let bytes = hex::decode(case["body_hex"].as_str().unwrap()).unwrap();
            for alias in frozen["aliases"].as_array().unwrap() {
                let header = format!("text/plain; charset={}", alias.as_str().unwrap());
                assert_eq!(
                    match response_text(&bytes, Some(&header)) {
                        Ok(text) => serde_json::Value::String(text),
                        Err(error) =>
                            serde_json::json!({"error_class": error.diagnostic_class(), "error": error.to_string()}),
                    },
                    case["text"],
                    "published codec {alias}"
                );
            }
        }
    }

    #[test]
    fn euc_kr_response_cases_match_published_codec() {
        let frozen = serde_json::from_str(include_str!(
            "../../../../contracts/canvas-euc-kr-codec.json"
        ))
        .unwrap();
        assert_published_codec_cases(&frozen);
    }

    #[test]
    fn iso2022_response_cases_match_published_codecs() {
        for (_, source) in iso2022::SOURCES {
            assert_published_codec_cases(&serde_json::from_str(source).unwrap());
        }
    }

    #[test]
    fn charset_headers_match_published_parameter_text_and_json_behavior() {
        let frozen: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../contracts/canvas-charset-headers-oracle.json"
        ))
        .unwrap();
        assert_eq!(frozen["cases"].as_array().unwrap().len(), 177);
        for case in frozen["cases"].as_array().unwrap() {
            let content_type = case["content_type"].as_str();
            let body = hex::decode(case["body_hex"].as_str().unwrap()).unwrap();
            assert_eq!(
                observation(
                    content_type
                        .map(charset_parameter)
                        .transpose()
                        .map(Option::flatten)
                ),
                case["charset"],
                "charset {}",
                case["name"]
            );
            assert_eq!(
                observation(response_text(&body, content_type)),
                case["text"],
                "text {}",
                case["name"]
            );
            assert_eq!(
                observation(crate::canvas_credentials_protocol::response_excerpt(
                    &body,
                    content_type
                )),
                case["excerpt"],
                "excerpt {}",
                case["name"]
            );
        }
    }

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
                    response_text(&bytes, Some(&format!("text/plain; charset={label}"))).unwrap(),
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
                )
                .unwrap(),
                String::from_utf8_lossy(&bytes),
                "unregistered alias must retain the published fallback"
            );
        }
    }

    #[test]
    fn ascii_and_latin1_keep_their_distinct_byte_mappings() {
        let bytes = (0..=255).collect::<Vec<u8>>();
        let ascii = response_text(&bytes, Some("text/plain; charset=ascii")).unwrap();
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
                .unwrap()
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
            )
            .unwrap(),
            "é"
        );
        let bom = b"\xef\xbb\xbfcaf\xc3\xa9";
        assert_eq!(
            response_text(bom, Some("text/plain; charset=utf-8-sig")).unwrap(),
            "café"
        );
        assert_eq!(
            response_text(bom, Some("text/plain; charset=utf-8")).unwrap(),
            "\u{feff}café"
        );
        assert_eq!(
            response_text(bom, Some("text/plain; charset=ascii")).unwrap(),
            "���caf��"
        );
    }
}
