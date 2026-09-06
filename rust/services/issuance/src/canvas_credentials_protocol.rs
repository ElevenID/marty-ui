//! Shared protocol primitives, without conflating validation and delivery policy.
use crate::canvas_response_text::{response_text, CanvasResponseTextError};
use crate::lossless_json::{LosslessJson, LosslessObject};
use serde_json::{Map, Value};
use url::Url;

pub(crate) const DEFAULT_API_BASE_URL: &str = "https://api.badgr.io";
pub(crate) const MAX_EXCERPT_CHARS: usize = 1_000;

/// Preserve the published ordered assignments without imposing a transport
/// range. Runtime Duration adoption remains a separate consumer constraint.
pub(crate) fn timeout_values(
    publish: Option<&str>,
    status: Option<&str>,
) -> Result<(f64, f64), &'static str> {
    let publish = mmf_config::numeric_config::parse_python_config_float(publish.unwrap_or("20"))
        .map_err(|_| "CANVAS_CREDENTIALS_PUBLISH_TIMEOUT_SECONDS")?;
    let status = match status {
        Some(value) => mmf_config::numeric_config::parse_python_config_float(value)
            .map_err(|_| "CANVAS_CREDENTIALS_STATUS_SYNC_TIMEOUT_SECONDS")?,
        None => publish,
    };
    Ok((publish, status))
}

pub(crate) fn provider_alias(configured: String) -> String {
    match configured.as_str() {
        "badgr" | "canvas_credentials" | "credentials_api" | "canvas" => "badgr_api".into(),
        "sandbox" | "proxy" | "bridge_api" => "bridge".into(),
        _ => configured,
    }
}

pub(crate) fn https_origin(value: &str) -> Option<String> {
    let parsed = Url::parse(value.trim()).ok()?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return None;
    }
    let host = parsed.host_str()?.to_ascii_lowercase();
    Some(match parsed.port() {
        Some(port) => format!("https://{host}:{port}"),
        None => format!("https://{host}"),
    })
}

/// Projection follows complete body consumption. Only text excerpts are bounded;
/// valid JSON objects/scalars must not silently lose fields at an I/O buffer size.
pub(crate) fn response_excerpt(
    bytes: &[u8],
    content_type: Option<&str>,
) -> Result<LosslessObject, CanvasResponseTextError> {
    if let Some(payload) = response_json(bytes) {
        return Ok(crate::lossless_json::object(match payload {
            Value::Object(object) => object,
            payload => Map::from_iter([("payload".into(), payload)]),
        }));
    }
    let text = response_text(bytes, content_type)?;
    Ok(LosslessObject::from_iter([(
        "body_excerpt".into(),
        LosslessJson::Text(truncate_text(&text)),
    )]))
}

/// Python's JSON byte reader detects UTF-8/16/32 independently of the response
/// text charset. Keep this separate from lossy text projection: stripping a BOM
/// or replacing invalid code units before JSON parsing can change its meaning.
fn response_json(bytes: &[u8]) -> Option<Value> {
    let (width, little, skip) = if bytes.starts_with(&[0xff, 0xfe, 0, 0]) {
        (4, true, 4)
    } else if bytes.starts_with(&[0, 0, 0xfe, 0xff]) {
        (4, false, 4)
    } else if bytes.starts_with(&[0xff, 0xfe]) {
        (2, true, 2)
    } else if bytes.starts_with(&[0xfe, 0xff]) {
        (2, false, 2)
    } else if bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
        (1, false, 3)
    } else if bytes.len() >= 4 && bytes[0] == 0 {
        (if bytes[1] == 0 { 4 } else { 2 }, false, 0)
    } else if bytes.len() >= 4 && bytes[1] == 0 {
        (if bytes[2] == 0 && bytes[3] == 0 { 4 } else { 2 }, true, 0)
    } else if bytes.len() == 2 && bytes[0] == 0 {
        (2, false, 0)
    } else if bytes.len() == 2 && bytes[1] == 0 {
        (2, true, 0)
    } else {
        (1, false, 0)
    };
    let bytes = &bytes[skip..];
    if width == 1 {
        return serde_json::from_slice(bytes).ok();
    }
    if !bytes.len().is_multiple_of(width) {
        return None;
    }
    let decoded = crate::canvas_response_text::unicode_units(bytes, width, little, true)?;
    serde_json::from_str(&decoded).ok()
}

pub(crate) fn truncate_text(
    text: &crate::python_text::PythonText,
) -> crate::python_text::PythonText {
    crate::python_text::PythonText::excerpt(text.codepoints(), MAX_EXCERPT_CHARS)
        .expect("decoded codepoints are valid")
}

pub(crate) fn quote_identifier(value: &str) -> String {
    use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
    // urllib.parse.quote(value, safe=""): URI-unreserved bytes only.
    const SET: &percent_encoding::AsciiSet = &NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'.')
        .remove(b'_')
        .remove(b'~');
    utf8_percent_encode(value, SET).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_byte_encodings_preserve_scalars_arrays_and_supplementary_characters() {
        for source in ["0", "[]", "true", "{\"message\":\"café 🙂\"}"] {
            let expected: Value = serde_json::from_str(source).unwrap();
            for little in [true, false] {
                let utf16 = source
                    .encode_utf16()
                    .flat_map(|unit| {
                        if little {
                            unit.to_le_bytes()
                        } else {
                            unit.to_be_bytes()
                        }
                    })
                    .collect::<Vec<_>>();
                let utf32 = source
                    .chars()
                    .flat_map(|value| {
                        if little {
                            (value as u32).to_le_bytes()
                        } else {
                            (value as u32).to_be_bytes()
                        }
                    })
                    .collect::<Vec<_>>();
                for (bytes, bom) in [
                    (
                        utf16,
                        if little {
                            vec![0xff, 0xfe]
                        } else {
                            vec![0xfe, 0xff]
                        },
                    ),
                    (
                        utf32,
                        if little {
                            vec![0xff, 0xfe, 0, 0]
                        } else {
                            vec![0, 0, 0xfe, 0xff]
                        },
                    ),
                ] {
                    assert_eq!(response_json(&bytes), Some(expected.clone()));
                    let with_bom = [bom, bytes].concat();
                    assert_eq!(response_json(&with_bom), Some(expected.clone()));
                }
            }
            let utf8_bom = [vec![0xef, 0xbb, 0xbf], source.as_bytes().to_vec()].concat();
            assert_eq!(response_json(&utf8_bom), Some(expected));
        }
    }

    #[test]
    fn json_detection_does_not_lossily_repair_invalid_units_or_change_text_bom() {
        for bytes in [
            vec![0xff, 0xfe, b'0'],                      // Incomplete UTF16 unit.
            vec![0xff, 0xfe, 0, 0, b'0'],                // Incomplete UTF32 unit.
            vec![0xff, 0xfe, b'"', 0, 0, 0xd8, b'"', 0], // Unpaired surrogate.
            vec![0xff, 0xfe, 0, 0, 0, 0, 0x11, 0],       // Outside Unicode scalar range.
        ] {
            assert!(response_json(&bytes).is_none());
        }
        let text = b"\xef\xbb\xbfnot JSON";
        assert_eq!(
            crate::lossless_json::scalar_object(&response_excerpt(text, None).unwrap()).unwrap(),
            serde_json::json!({"body_excerpt":"\u{feff}not JSON"})
                .as_object()
                .unwrap()
                .clone()
        );
    }

    fn hexadecimal(value: f64) -> String {
        if value.is_nan() {
            return "nan".into();
        }
        let sign = if value.is_sign_negative() { "-" } else { "" };
        if value.is_infinite() {
            return format!("{sign}inf");
        }
        if value == 0.0 {
            return format!("{sign}0x0.0p+0");
        }
        let bits = value.to_bits();
        let exponent = ((bits >> 52) & 0x7ff) as i32;
        let fraction = bits & 0x000f_ffff_ffff_ffff;
        let leading = if exponent == 0 { 0 } else { 1 };
        format!(
            "{sign}0x{leading}.{fraction:013x}p{:+}",
            if exponent == 0 {
                -1022
            } else {
                exponent - 1023
            }
        )
    }

    #[test]
    fn timeout_assignments_match_all_exact_source_observations() {
        let scenarios: Value = serde_json::from_str(include_str!(
            "../../../../contracts/canvas-provider-configuration-scenarios.json"
        ))
        .unwrap();
        let oracle: Value = serde_json::from_str(include_str!(
            "../../../../contracts/canvas-provider-configuration-oracle.json"
        ))
        .unwrap();
        let cases = scenarios["timeouts"].as_array().unwrap();
        let expected = oracle["timeouts"].as_array().unwrap();
        assert_eq!(cases.len(), expected.len());
        for (case, expected) in cases.iter().zip(expected) {
            assert_eq!(case["name"], expected["name"]);
            let actual = match timeout_values(case["publish"].as_str(), case["status"].as_str()) {
                Ok((publish, status)) => {
                    serde_json::json!({"name":case["name"],"publish":hexadecimal(publish),"status":hexadecimal(status)})
                }
                Err(_) => serde_json::json!({"name":case["name"],"error_class":"ValueError"}),
            };
            assert_eq!(&actual, expected);
        }
        assert_eq!(
            timeout_values(Some("invalid"), Some("also invalid")).unwrap_err(),
            "CANVAS_CREDENTIALS_PUBLISH_TIMEOUT_SECONDS"
        );
    }
}
