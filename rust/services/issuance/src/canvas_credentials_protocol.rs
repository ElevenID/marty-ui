//! Shared protocol primitives, without conflating validation and delivery policy.
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
pub(crate) fn response_excerpt(bytes: &[u8]) -> Map<String, Value> {
    if let Ok(payload) = serde_json::from_slice::<Value>(bytes) {
        return match payload {
            Value::Object(object) => object,
            payload => Map::from_iter([("payload".into(), payload)]),
        };
    }
    let text = String::from_utf8_lossy(bytes);
    Map::from_iter([("body_excerpt".into(), Value::String(truncate_text(&text)))])
}

pub(crate) fn truncate_text(text: &str) -> String {
    let mut chars = text.chars();
    let mut excerpt = chars.by_ref().take(MAX_EXCERPT_CHARS).collect::<String>();
    if chars.next().is_some() {
        excerpt.push('…');
    }
    excerpt
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
