//! Browser transport for configured static console origins.
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
pub(super) async fn response_headers(
    State(state): State<Arc<GatewayRuntimeState>>,
    request: Request,
    next: Next,
) -> Response {
    let api = http_method(request.method().as_str())
        .is_some_and(|method| api_operation(&state, request.uri().path(), method));
    let scope = request.method() != axum::http::Method::OPTIONS
        && (api
            || request.uri().path().starts_with("/v1/auth/")
            || crate::external_association::requires_own_session(request.uri().path()));
    let origin = scope
        .then(|| single(request.headers(), "origin"))
        .flatten()
        .filter(|origin| state.cors_origins.contains(*origin))
        .map(str::to_owned);
    let mut response = next.run(request).await;
    if let Some(origin) = origin.filter(|_| {
        api || response.status().is_client_error() || response.status().is_server_error()
    }) {
        insert_header(&mut response, "access-control-allow-origin", &origin);
        insert_header(&mut response, "access-control-allow-credentials", "true");
        insert_header(&mut response, "cache-control", "no-store");
        if api {
            insert_header(
                &mut response,
                "access-control-expose-headers",
                "etag, location, retry-after, x-request-id, x-mip-version, content-disposition",
            );
        }
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

/// The installed route table remains the operation authority. Dedicated browser,
/// producer and native OAuth transports retain their own admission rules.
pub(super) fn api_operation(state: &GatewayRuntimeState, path: &str, method: HttpMethod) -> bool {
    if !matches!(
        method,
        HttpMethod::Get
            | HttpMethod::Post
            | HttpMethod::Put
            | HttpMethod::Patch
            | HttpMethod::Delete
    ) || is_namespace(path)
        || crate::agent_administration::is_namespace(path)
        || crate::delegation_commands::is_namespace(path)
        || crate::external_observation::is_admin_namespace(path)
        || path == crate::external_observation::PATH
        || path.starts_with("/v1/flows/public/verification/")
    {
        return false;
    }
    let public_read = method == HttpMethod::Get
        && matches!(
            path,
            "/health/ready" | "/openapi.json" | "/v1/protocol-support"
        );
    if !public_read && !path.starts_with("/v1/") {
        return false;
    }
    state
        .routes
        .find(&GatewayRequest::new(method, path, now_ms()))
        .is_ok_and(|found| found.route.auth_required || public_read)
}

/// Cross-origin session mutations must name the configured origin. Absence of
/// Origin retains the existing non-browser/same-origin transport contract.
pub(super) fn mutation_origin_allowed(
    state: &GatewayRuntimeState,
    method: HttpMethod,
    headers: &HeaderMap,
) -> bool {
    matches!(
        method,
        HttpMethod::Get | HttpMethod::Head | HttpMethod::Options
    ) || !headers.contains_key("origin")
        || single(headers, "origin")
            .is_some_and(|origin| origin != "null" && state.cors_origins.contains(origin))
}

pub(super) fn api_preflight(
    state: &GatewayRuntimeState,
    path: &str,
    headers: &HeaderMap,
) -> Option<Response> {
    let method = single(headers, "access-control-request-method")?;
    let target = http_method(method)?;
    if !api_operation(state, path, target) {
        return None;
    }
    let mut response = StatusCode::FORBIDDEN.into_response();
    insert_header(&mut response, "cache-control", "no-store");
    insert_header(
        &mut response,
        "vary",
        "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
    );
    let Some(origin) = single(headers, "origin")
        .filter(|origin| *origin != "null" && state.cors_origins.contains(*origin))
    else {
        return Some(response);
    };
    let requested = if headers.contains_key("access-control-request-headers") {
        let Some(value) =
            single(headers, "access-control-request-headers").filter(|value| value.len() <= 256)
        else {
            return Some(response);
        };
        let names = value
            .split(',')
            .map(|name| name.trim().to_ascii_lowercase())
            .collect::<Vec<_>>();
        let unique = names.iter().collect::<BTreeSet<_>>();
        if unique.len() != names.len()
            || names.iter().any(|name| {
                !matches!(
                    name.as_str(),
                    "content-type"
                        | "if-match"
                        | "idempotency-key"
                        | "x-mip-version"
                        | "x-request-id"
                )
            })
        {
            return Some(response);
        }
        names.join(", ")
    } else {
        String::new()
    };
    *response.status_mut() = StatusCode::NO_CONTENT;
    for (name, value) in [
        ("access-control-allow-origin", origin),
        ("access-control-allow-credentials", "true"),
        ("access-control-allow-methods", method),
    ] {
        insert_header(&mut response, name, value);
    }
    if !requested.is_empty() {
        insert_header(&mut response, "access-control-allow-headers", &requested);
    }
    Some(response)
}
