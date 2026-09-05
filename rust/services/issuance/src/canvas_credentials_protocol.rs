//! Shared protocol primitives, without conflating validation and delivery policy.
use serde_json::{Map, Value};
use url::Url;

pub(crate) const DEFAULT_API_BASE_URL: &str = "https://api.badgr.io";
pub(crate) const MAX_EXCERPT_CHARS: usize = 1_000;

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

pub(crate) fn response_excerpt(bytes: &[u8], truncated: bool) -> Map<String, Value> {
    if !truncated {
        if let Ok(payload) = serde_json::from_slice::<Value>(bytes) {
            return match payload {
                Value::Object(object) => object,
                payload => Map::from_iter([("payload".into(), payload)]),
            };
        }
    }
    let text = String::from_utf8_lossy(bytes);
    let mut body = text.chars().take(MAX_EXCERPT_CHARS).collect::<String>();
    if truncated || text.chars().count() > MAX_EXCERPT_CHARS {
        body.push('…');
    }
    Map::from_iter([("body_excerpt".into(), Value::String(body))])
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
