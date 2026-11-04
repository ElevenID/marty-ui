//! Public visitor-session routes, separate from Flow management authority.

use axum::{
    extract::Request,
    http::{header, HeaderMap, HeaderValue},
    middleware::Next,
    response::Response,
};
use mmf_platform::HttpMethod;
use std::collections::BTreeMap;

pub const ROUTES: &[(HttpMethod, &str)] = &[
    (HttpMethod::Get, "/v1/flows/public/verification/catalog"),
    (HttpMethod::Post, "/v1/flows/public/verification/sessions"),
    (
        HttpMethod::Get,
        "/v1/flows/public/verification/sessions/{session_id}",
    ),
    (
        HttpMethod::Post,
        "/v1/flows/public/verification/sessions/{session_id}/cancel",
    ),
    (
        HttpMethod::Post,
        "/v1/flows/public/verification/sessions/{session_id}/example",
    ),
];

#[must_use]
pub fn is_public_path(path: &str) -> bool {
    if matches!(
        path,
        "/v1/flows/public/verification/catalog" | "/v1/flows/public/verification/sessions"
    ) {
        return true;
    }
    let Some(tail) = path.strip_prefix("/v1/flows/public/verification/sessions/") else {
        return false;
    };
    let id = tail
        .strip_suffix("/cancel")
        .or_else(|| tail.strip_suffix("/example"))
        .unwrap_or(tail);
    id.len() == 36 && uuid::Uuid::parse_str(id).is_ok()
}

/// Reject ambiguity before the generic proxy collapses headers into a map.
/// Flow remains the owner of capability validity and configured Origin checks.
#[must_use]
pub fn unambiguous_headers(headers: &HeaderMap) -> bool {
    ["origin", "x-verification-session"].iter().all(|name| {
        let mut values = headers.get_all(*name).iter();
        let first = values.next();
        values.next().is_none() && first.is_none_or(|value| value.to_str().is_ok())
    })
}

pub fn restrict_headers(headers: &mut BTreeMap<String, String>) {
    headers.retain(|name, _| {
        matches!(
            name.to_ascii_lowercase().as_str(),
            "origin"
                | "x-verification-session"
                | "content-type"
                | "accept"
                | "host"
                | "x-forwarded-host"
                | "x-forwarded-proto"
                | "x-forwarded-port"
        )
    });
}

pub async fn no_store(request: Request, next: Next) -> Response {
    let public = request
        .uri()
        .path()
        .starts_with("/v1/flows/public/verification/");
    let mut response = next.run(request).await;
    if public {
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
            .headers_mut()
            .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn management_and_extra_suffixes_never_become_public() {
        for path in [
            "/v1/flows/instances/54cfd66e-b7ed-8926-9f8b-18e63fa83797/result",
            "/v1/flows/definitions", "/v1/flows/public/verification/definitions",
            "/v1/flows/public/verification/sessions/unknown",
            "/v1/flows/public/verification/sessions/54cfd66e-b7ed-8926-9f8b-18e63fa83797/result",
            "/v1/flows/public/verification/sessions/54cfd66e-b7ed-8926-9f8b-18e63fa83797/cancel/extra",
            "/v1/flows/public/verification/catalog/extra",
        ] { assert!(!is_public_path(path), "{path}"); }
    }
}
