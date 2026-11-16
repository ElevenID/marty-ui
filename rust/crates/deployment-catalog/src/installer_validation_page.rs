//! Read-only local-listener checks of the shipped page, its entry assets and
//! explicit IP alias. This is not JavaScript execution or browser qualification.

use super::{bound_get, client, TrustInfo};
use reqwest::{header, Response, StatusCode};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const HTML_LIMIT: usize = 131072;
const ASSET_LIMIT: usize = 4 * 1024 * 1024;
const TOTAL_LIMIT: usize = 16 * 1024 * 1024;

/// Public response fingerprints, never response bodies or cookie values.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct PageAsset {
    pub path: String,
    pub media_type: String,
    pub size_bytes: usize,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct PageObservation {
    pub origin: String,
    pub assets: Vec<PageAsset>,
    pub app_name: Option<String>,
    pub alias_api_isolation_observed: bool,
}

fn fingerprint(path: &str, media_type: &str, bytes: &[u8]) -> PageAsset {
    PageAsset {
        path: path.into(),
        media_type: media_type.into(),
        size_bytes: bytes.len(),
        sha256: format!("{:x}", Sha256::digest(bytes)),
    }
}

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

fn runtime_configuration(
    bytes: &[u8],
    canonical: &str,
    alias: Option<&str>,
    enabled_sections: &str,
) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    // Parse the closed emitted data wrapper. Never evaluate downloaded JavaScript.
    let pattern = regex::Regex::new(concat!(
        r"\A\s*window\.__MARTY_RUNTIME_CONFIG__ = Object\.assign\(\{\}, window\.__MARTY_RUNTIME_CONFIG__, \{\s*",
        r"googleAnalyticsMeasurementId: '[A-Za-z0-9_-]*',\s*",
        r"(?:organizationCreationEnabled: (?:true|false),\s*)?",
        r"(?:web: \{\s*enabled_sections: (?P<sections>\[[^\r\n]*\])\s*\},\s*)?hosting: \{\s*",
        r"canonicalOrigin: '(?P<canonical>[^'\r\n]*)',\s*publicEntryOrigins: (?P<aliases>\[[^\r\n]*\])\s*\}\s*\}\);\s*\z"
    )).expect("fixed runtime configuration pattern");
    let Some(captures) = pattern.captures(text) else {
        return false;
    };
    let Ok(value) = serde_json::from_str::<Value>(&captures["aliases"]) else {
        return false;
    };
    let sections_match = if let Some(sections) = captures.name("sections") {
        let expected: Vec<&str> = if enabled_sections == "none" {
            Vec::new()
        } else {
            enabled_sections.split(',').collect()
        };
        serde_json::from_str::<Vec<String>>(sections.as_str())
            .is_ok_and(|actual| actual == expected)
    } else {
        // Authenticated historical images predate optional section selection.
        enabled_sections == "public,console"
    };
    let expected: Vec<&str> = alias.into_iter().collect();
    captures
        .name("canonical")
        .is_some_and(|value| value.as_str() == canonical)
        && value == serde_json::json!(expected)
        && sections_match
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
    entry_path: &str,
    enabled_sections: &str,
) -> Option<PageObservation> {
    let client = client(trust).ok()?;
    let page = bound_get(&client, trust, entry_path).await?;
    if !content_type(&page, &["text/html"]) {
        return None;
    }
    let bytes = body(page, HTML_LIMIT, is_alias).await?;
    let assets = entry_assets(&bytes)?;
    let mut observed = vec![fingerprint(entry_path, "text/html", &bytes)];
    let mut total = bytes.len();
    for path in ["/runtime-config.js", "/startup.js"] {
        let response = bound_get(&client, trust, path).await?;
        if !content_type(&response, &["text/javascript", "application/javascript"]) {
            return None;
        }
        let bytes = body(response, HTML_LIMIT, is_alias).await?;
        if path == "/runtime-config.js"
            && !runtime_configuration(&bytes, canonical, alias, enabled_sections)
        {
            return None;
        }
        total += bytes.len();
        observed.push(fingerprint(path, "application/javascript", &bytes));
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
        observed.push(fingerprint(
            &asset.path,
            if asset.stylesheet {
                "text/css"
            } else {
                "application/javascript"
            },
            &bytes,
        ));
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
    // Branding is a real runtime input. It is observed for the alias proof,
    // without adding a new requirement to legacy canonical-only validation.
    let app_name = if is_alias {
        let response = bound_get(&client, trust, "/config.json").await?;
        if !content_type(&response, &["application/json"]) {
            return None;
        }
        let bytes = body(
            response,
            HTML_LIMIT.min(TOTAL_LIMIT.checked_sub(total)?),
            true,
        )
        .await?;
        let config = crate::installer_json::decode(&bytes).ok()?;
        let name = config["appName"].as_str()?;
        if name.is_empty() || name.len() > 256 || name.chars().any(char::is_control) {
            return None;
        }
        observed.push(fingerprint("/config.json", "application/json", &bytes));
        Some(name.into())
    } else {
        None
    };
    observed.sort_by(|a, b| a.path.cmp(&b.path));
    Some(PageObservation {
        origin: trust.origin.clone(),
        assets: observed,
        app_name,
        alias_api_isolation_observed: is_alias,
    })
}

pub(super) async fn check(
    trust: &TrustInfo,
    alias: Option<&str>,
    enabled_sections: &str,
) -> ([bool; 2], Option<PageObservation>) {
    let public = matches!(enabled_sections, "public,console" | "public");
    let console = matches!(enabled_sections, "public,console" | "console");
    if !matches!(
        enabled_sections,
        "public,console" | "public" | "console" | "none"
    ) {
        return ([false, false], None);
    }
    let entry_path = if public { "/" } else { "/console" };
    let canonical = if public || console {
        document(
            trust,
            &trust.origin,
            alias,
            false,
            entry_path,
            enabled_sections,
        )
        .await
        .is_some()
    } else {
        true
    };
    let disabled_public =
        public || excluded(trust, &["/", "/index.html", "/login", "/apply"]).await;
    let disabled_console =
        console || excluded(trust, &["/console", "/console/", "/console/index.html"]).await;
    let disabled_assets = public
        || console
        || excluded(
            trust,
            &["/runtime-config.js", "/startup.js", "/config.json"],
        )
        .await;
    let entry = if let Some(alias) = alias {
        let mut entry = trust.clone();
        entry.origin = alias.into();
        // Transport keeps the same admitted leaf and bound local listener, but
        // verifies the exact IP SAN and sends the configured alias authority.
        if public {
            document(
                &entry,
                &trust.origin,
                Some(alias),
                true,
                "/",
                enabled_sections,
            )
            .await
        } else {
            None
        }
    } else {
        None
    };
    let alias_passed = if let Some(alias) = alias {
        if public {
            entry.is_some()
        } else {
            let mut alias_trust = trust.clone();
            alias_trust.origin = alias.into();
            excluded(&alias_trust, &["/", "/console", "/v1/auth/session"]).await
        }
    } else {
        true
    };
    (
        [
            canonical && disabled_public && disabled_console && disabled_assets,
            alias_passed,
        ],
        entry,
    )
}

async fn excluded(trust: &TrustInfo, paths: &[&str]) -> bool {
    let Ok(client) = client(trust) else {
        return false;
    };
    for path in paths {
        let Some(response) = bound_get(&client, trust, path).await else {
            return false;
        };
        if response.status() != StatusCode::NOT_FOUND
            || response.headers().contains_key(header::LOCATION)
            || response.headers().contains_key(header::SET_COOKIE)
        {
            return false;
        }
    }
    true
}

#[cfg(test)]
#[path = "installer_validation_page_tests.rs"]
mod tests;
