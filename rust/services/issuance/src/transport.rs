use std::{collections::BTreeSet, sync::Arc};

use axum::{
    extract::{Request, State},
    http::{header, HeaderValue, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use uuid::Uuid;

const ALLOWED_METHODS: &str = "DELETE, GET, HEAD, OPTIONS, PATCH, POST, PUT";

#[derive(Clone, Debug)]
pub struct TransportPolicy {
    allowed_origins: Arc<BTreeSet<String>>,
    allow_all_origins: bool,
}

impl TransportPolicy {
    #[must_use]
    pub fn new(origins: impl IntoIterator<Item = String>) -> Self {
        let allowed_origins = origins.into_iter().collect::<BTreeSet<_>>();
        let allow_all_origins = allowed_origins.contains("*");
        Self {
            allowed_origins: Arc::new(allowed_origins),
            allow_all_origins,
        }
    }

    fn allows(&self, origin: &HeaderValue) -> bool {
        self.allow_all_origins
            || origin
                .to_str()
                .is_ok_and(|origin| self.allowed_origins.contains(origin))
    }
}

pub async fn legacy_transport(
    State(policy): State<TransportPolicy>,
    request: Request,
    next: Next,
) -> Response {
    let request_id = request
        .headers()
        .get("x-request-id")
        .filter(|value| !value.as_bytes().is_empty())
        .cloned()
        .unwrap_or_else(generated_request_id);
    let origin = request.headers().get(header::ORIGIN).cloned();
    let is_preflight = request.method() == Method::OPTIONS
        && request
            .headers()
            .contains_key(header::ACCESS_CONTROL_REQUEST_METHOD);

    let mut response = match (is_preflight, origin.as_ref()) {
        (true, Some(origin)) => preflight_response(&policy, &request, origin),
        _ => {
            let mut response = next.run(request).await;
            if let Some(origin) = origin.as_ref().filter(|origin| policy.allows(origin)) {
                add_simple_cors_headers(response.headers_mut(), origin);
            }
            response
        }
    };
    response.headers_mut().insert("x-request-id", request_id);
    response
}

fn preflight_response(
    policy: &TransportPolicy,
    request: &Request,
    origin: &HeaderValue,
) -> Response {
    let origin_allowed = policy.allows(origin);
    let method_allowed = request
        .headers()
        .get(header::ACCESS_CONTROL_REQUEST_METHOD)
        .is_some_and(allowed_method);
    let mut failures = Vec::new();
    if !origin_allowed {
        failures.push("origin");
    }
    if !method_allowed {
        failures.push("method");
    }
    let mut response = if failures.is_empty() {
        (StatusCode::OK, "OK").into_response()
    } else {
        (
            StatusCode::BAD_REQUEST,
            format!("Disallowed CORS {}", failures.join(", ")),
        )
            .into_response()
    };
    let headers = response.headers_mut();
    headers.insert(header::VARY, HeaderValue::from_static("Origin"));
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static(ALLOWED_METHODS),
    );
    headers.insert(
        header::ACCESS_CONTROL_MAX_AGE,
        HeaderValue::from_static("600"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
        HeaderValue::from_static("true"),
    );
    if origin_allowed {
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin.clone());
    }
    if let Some(requested_headers) = request
        .headers()
        .get(header::ACCESS_CONTROL_REQUEST_HEADERS)
    {
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            requested_headers.clone(),
        );
    }
    response
}

fn add_simple_cors_headers(headers: &mut axum::http::HeaderMap, origin: &HeaderValue) {
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
        HeaderValue::from_static("true"),
    );
    headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin.clone());
    headers.insert(header::VARY, HeaderValue::from_static("Origin"));
}

fn allowed_method(value: &HeaderValue) -> bool {
    matches!(
        value.as_bytes(),
        b"DELETE" | b"GET" | b"HEAD" | b"OPTIONS" | b"PATCH" | b"POST" | b"PUT"
    )
}

fn generated_request_id() -> HeaderValue {
    let value = Uuid::new_v4().simple().to_string();
    HeaderValue::from_str(&value[..8]).expect("UUID prefix is a valid header value")
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::{generated_request_id, TransportPolicy};

    #[test]
    fn allowed_origins_are_exact_and_generated_ids_preserve_legacy_shape() {
        let policy = TransportPolicy::new(["https://wallet.example".to_owned()]);
        assert!(policy.allows(&HeaderValue::from_static("https://wallet.example")));
        assert!(!policy.allows(&HeaderValue::from_static("https://evil.example")));
        let wildcard = TransportPolicy::new(["*".to_owned()]);
        assert!(wildcard.allows(&HeaderValue::from_static("https://any.example")));

        let generated = generated_request_id();
        let request_id = generated.to_str().expect("request ID");
        assert_eq!(request_id.len(), 8);
        assert!(request_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
    }
}
