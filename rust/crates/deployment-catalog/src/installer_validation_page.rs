//! Read-only local-listener checks of the shipped page, its entry assets and
//! explicit IP alias. This is not JavaScript execution or browser qualification.

use super::{bound_get, client, TrustInfo};
use reqwest::{header, Response, StatusCode};
use serde_json::Value;
use std::collections::BTreeSet;

const HTML_LIMIT: usize = 131072;
const ASSET_LIMIT: usize = 4 * 1024 * 1024;
const TOTAL_LIMIT: usize = 16 * 1024 * 1024;

#[derive(Debug, Eq, PartialEq)]
struct Asset {
    path: String,
    stylesheet: bool,
}

/// The build owns this HTML format. A generic 200 response, an unbuilt source
/// tree, an external script or a redirect is not a shipped entry document.
fn entry_assets(html: &[u8]) -> Option<Vec<Asset>> {
    if html.len() > HTML_LIMIT {
        return None;
    }
    let text = std::str::from_utf8(html).ok()?;
    if !text
        .trim_start()
        .to_ascii_lowercase()
        .starts_with("<!doctype html>")
        || !text.contains("<div id=\"root\"></div>")
        || !text.contains("<script src=\"/runtime-config.js\"></script>")
        || !text.contains("<script src=\"/startup.js\"></script>")
    {
        return None;
    }
    let script = regex::Regex::new(r#"<script\b[^>]*>"#).ok()?;
    let module = regex::Regex::new(r#"\stype=["']module["']"#).ok()?;
    let source = regex::Regex::new(r#"\ssrc=["'](/assets/[A-Za-z0-9_-]+\.js)["']"#).ok()?;
    let source_value = regex::Regex::new(r#"\ssrc=["']([^"']+)["']"#).ok()?;
    let mut assets = Vec::new();
    let mut bootstrap_scripts = BTreeSet::new();
    for tag in script.find_iter(text).map(|v| v.as_str()) {
        if module.is_match(tag) {
            let captures = source.captures(tag)?;
            assets.push(Asset {
                path: captures[1].into(),
                stylesheet: false,
            });
        } else {
            let source = source_value.captures(tag)?.get(1)?.as_str();
            if !["/runtime-config.js", "/startup.js"].contains(&source)
                || !bootstrap_scripts.insert(source)
            {
                return None;
            }
        }
    }
    if assets.len() != 1 || bootstrap_scripts.len() != 2 {
        return None;
    }
    let link = regex::Regex::new(r#"<link\b[^>]*>"#).ok()?;
    let stylesheet = regex::Regex::new(r#"\srel=["']stylesheet["']"#).ok()?;
    let preload = regex::Regex::new(r#"\srel=["']modulepreload["']"#).ok()?;
    let href = regex::Regex::new(r#"\shref=["']([^"']+)["']"#).ok()?;
    let local_css = regex::Regex::new(r#"\A/assets/[A-Za-z0-9_-]+\.css\z"#).ok()?;
    let local_js = regex::Regex::new(r#"\A/assets/[A-Za-z0-9_-]+\.js\z"#).ok()?;
    for tag in link.find_iter(text).map(|v| v.as_str()) {
        if preload.is_match(tag) {
            let path = href.captures(tag)?.get(1)?.as_str();
            if !local_js.is_match(path) {
                return None;
            }
            assets.push(Asset {
                path: path.into(),
                stylesheet: false,
            });
            continue;
        }
        if !stylesheet.is_match(tag) {
            continue;
        }
        let path = href.captures(tag)?.get(1)?.as_str();
        // Remote fonts are optional browser resources, not local readiness.
        if path.starts_with("https://fonts.googleapis.com/") {
            continue;
        }
        if !local_css.is_match(path) {
            return None;
        }
        assets.push(Asset {
            path: path.into(),
            stylesheet: true,
        });
    }
    if assets.len() > 48
        || assets
            .iter()
            .map(|asset| &asset.path)
            .collect::<BTreeSet<_>>()
            .len()
            != assets.len()
    {
        return None;
    }
    Some(assets)
}

fn runtime_configuration(bytes: &[u8], canonical: &str, alias: Option<&str>) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    // Parse the closed emitted data wrapper. Never evaluate downloaded JavaScript.
    let pattern = regex::Regex::new(concat!(
        r"\A\s*window\.__MARTY_RUNTIME_CONFIG__ = Object\.assign\(\{\}, window\.__MARTY_RUNTIME_CONFIG__, \{\s*",
        r"googleAnalyticsMeasurementId: '[A-Za-z0-9_-]*',\s*hosting: \{\s*",
        r"canonicalOrigin: '([^'\r\n]*)',\s*publicEntryOrigins: (\[[^\r\n]*\])\s*\}\s*\}\);\s*\z"
    )).expect("fixed runtime configuration pattern");
    let Some(captures) = pattern.captures(text) else {
        return false;
    };
    let Ok(value) = serde_json::from_str::<Value>(&captures[2]) else {
        return false;
    };
    let expected: Vec<&str> = alias.into_iter().collect();
    captures
        .get(1)
        .is_some_and(|value| value.as_str() == canonical)
        && value == serde_json::json!(expected)
}

fn content_type(response: &Response, types: &[&str]) -> bool {
    response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| {
            types
                .iter()
                .any(|expected| value.trim().eq_ignore_ascii_case(expected))
        })
}

async fn body(mut response: Response, limit: usize, anonymous_alias: bool) -> Option<Vec<u8>> {
    if response.status() != StatusCode::OK
        || anonymous_alias && response.headers().contains_key(header::SET_COOKIE)
        || response
            .content_length()
            .is_some_and(|length| length > limit as u64)
    {
        return None;
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.ok()? {
        if bytes.len().checked_add(chunk.len())? > limit {
            return None;
        }
        bytes.extend_from_slice(&chunk);
    }
    (!bytes.is_empty()).then_some(bytes)
}

async fn document(
    trust: &TrustInfo,
    canonical: &str,
    alias: Option<&str>,
    is_alias: bool,
) -> Option<()> {
    let client = client(trust).ok()?;
    let page = bound_get(&client, trust, "/").await?;
    if !content_type(&page, &["text/html"]) {
        return None;
    }
    let bytes = body(page, HTML_LIMIT, is_alias).await?;
    let assets = entry_assets(&bytes)?;
    let mut total = bytes.len();
    for path in ["/runtime-config.js", "/startup.js"] {
        let response = bound_get(&client, trust, path).await?;
        if !content_type(&response, &["text/javascript", "application/javascript"]) {
            return None;
        }
        let bytes = body(response, HTML_LIMIT, is_alias).await?;
        if path == "/runtime-config.js" && !runtime_configuration(&bytes, canonical, alias) {
            return None;
        }
        total += bytes.len();
    }
    for asset in assets {
        let response = bound_get(&client, trust, &asset.path).await?;
        let allowed = if asset.stylesheet {
            &["text/css"][..]
        } else {
            &["text/javascript", "application/javascript"][..]
        };
        if !content_type(&response, allowed) {
            return None;
        }
        let bytes = body(
            response,
            ASSET_LIMIT.min(TOTAL_LIMIT.checked_sub(total)?),
            is_alias,
        )
        .await?;
        // SPA fallback HTML under an asset URL cannot establish application readiness.
        let first = bytes
            .iter()
            .position(|byte| !byte.is_ascii_whitespace())
            .unwrap_or(bytes.len());
        if bytes[first..].starts_with(b"<!") || bytes[first..].starts_with(b"<html") {
            return None;
        }
        total += bytes.len();
    }
    if is_alias {
        // These requests are anonymous and must terminate at the alias policy.
        // No credentials, cookies, mutating HTTP methods or login request are sent.
        for path in [
            "/v1/auth/session",
            "/.well-known/openid-credential-issuer",
            "/console",
        ] {
            let response = bound_get(&client, trust, path).await?;
            if response.status() != StatusCode::NOT_FOUND
                || response.headers().contains_key(header::SET_COOKIE)
                || response.headers().contains_key(header::LOCATION)
            {
                return None;
            }
        }
    }
    Some(())
}

pub(super) async fn check(trust: &TrustInfo, alias: Option<&str>) -> [bool; 2] {
    let canonical = document(trust, &trust.origin, alias, false).await.is_some();
    let entry = if let Some(alias) = alias {
        let mut entry = trust.clone();
        entry.origin = alias.into();
        // Transport keeps the same admitted leaf and bound local listener, but
        // verifies the exact IP SAN and sends the configured alias authority.
        document(&entry, &trust.origin, Some(alias), true)
            .await
            .is_some()
    } else {
        true
    };
    [canonical, entry]
}

#[cfg(test)]
#[path = "installer_validation_page_tests.rs"]
mod tests;
