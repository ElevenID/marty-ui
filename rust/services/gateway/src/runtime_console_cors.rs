//! Preflight for the static console's Auth and learner-consent transport.
//! Permission to send a request does not authorize its actual operation.
use super::*;
use axum::http::HeaderMap;

pub(super) fn is_namespace(path: &str) -> bool {
    path.starts_with("/v1/auth/") || crate::external_association::is_namespace(path)
}

fn single<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    values.next().is_none().then_some(value)
}

/// Response-only envelope: never skips authentication, tenant, body or rate
/// decisions. The innermost CORS stage cannot decorate their early rejections.
/// Strict preflight responses remain exclusively owned by their admission path.
pub(super) async fn error_headers(
    State(state): State<Arc<GatewayRuntimeState>>,
    request: Request,
    next: Next,
) -> Response {
    let scope = request.method() != axum::http::Method::OPTIONS
        && (request.uri().path().starts_with("/v1/auth/")
            || crate::external_association::requires_own_session(request.uri().path()));
    let origin = scope
        .then(|| single(request.headers(), "origin"))
        .flatten()
        .filter(|origin| state.cors_origins.contains(*origin))
        .map(str::to_owned);
    let mut response = next.run(request).await;
    if let Some(origin) = origin
        .filter(|_| response.status().is_client_error() || response.status().is_server_error())
    {
        insert_header(&mut response, "access-control-allow-origin", &origin);
        insert_header(&mut response, "access-control-allow-credentials", "true");
        insert_header(&mut response, "cache-control", "no-store");
        let varies_origin = response
            .headers()
            .get_all(header::VARY)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .any(|value| value.trim().eq_ignore_ascii_case("origin"));
        if !varies_origin {
            response
                .headers_mut()
                .append(header::VARY, HeaderValue::from_static("Origin"));
        }
    }
    response
}

pub(super) fn preflight(state: &GatewayRuntimeState, path: &str, headers: &HeaderMap) -> Response {
    let refused = || {
        let mut response = StatusCode::FORBIDDEN.into_response();
        insert_header(&mut response, "cache-control", "no-store");
        insert_header(
            &mut response,
            "vary",
            "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
        );
        response
    };
    let Some(origin) =
        single(headers, "origin").filter(|origin| state.cors_origins.contains(*origin))
    else {
        return refused();
    };
    let Some(method) = single(headers, "access-control-request-method") else {
        return refused();
    };
    let supported = match (path, method) {
        ("/v1/auth/me", "GET" | "PATCH")
        | ("/v1/auth/me/organizations" | "/v1/auth/provider", "GET")
        | ("/v1/auth/passkeys/enroll" | "/v1/auth/logout", "POST") => true,
        (_, "POST") => crate::external_association::requires_own_session(path),
        _ => false,
    };
    let Some(target) = http_method(method) else {
        return refused();
    };
    if !supported
        || state
            .routes
            .find(&GatewayRequest::new(target, path, now_ms()))
            .is_err()
    {
        return refused();
    }
    if headers.contains_key("access-control-request-headers")
        && !single(headers, "access-control-request-headers").is_some_and(|value| {
            // These clients send JSON and Accept only. Accept is safelisted;
            // attribution, bearer/API credentials and arbitrary headers are
            // not admitted by this browser transport.
            value.len() <= 128 && value.trim().eq_ignore_ascii_case("content-type")
        })
    {
        return refused();
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    for (name, value) in [
        ("access-control-allow-origin", origin),
        ("access-control-allow-credentials", "true"),
        ("access-control-allow-methods", method),
        ("access-control-allow-headers", "content-type"),
        ("cache-control", "no-store"),
        (
            "vary",
            "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
        ),
    ] {
        insert_header(&mut response, name, value);
    }
    response
}
