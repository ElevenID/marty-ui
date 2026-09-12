//! Actual limiter and transport middleware with a named stand-in endpoint,
//! matching the pinned Python reference's explicitly bounded ASGI projection.
use super::*;
use crate::token_rate_limit::{TokenRateClock, TokenRateLimitError};
use axum::{body::Body, http::Request as HttpRequest};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use tower::ServiceExt;

struct Clock(AtomicU64);
impl TokenRateClock for Clock {
    fn now(&self) -> Result<f64, TokenRateLimitError> {
        Ok(f64::from_bits(self.0.load(Ordering::SeqCst)))
    }
}

struct FailedClock;
impl TokenRateClock for FailedClock {
    fn now(&self) -> Result<f64, TokenRateLimitError> {
        Err(TokenRateLimitError::ClockUnavailable)
    }
}

#[tokio::test]
async fn clock_failure_is_closed_before_endpoint_and_transport_projection() {
    let limiter = TokenRateLimiter::legacy_defaults().with_clock(Arc::new(FailedClock));
    let calls = Arc::new(AtomicUsize::new(0));
    let response = request(&router(limiter, calls.clone()), true).await;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        response.headers()["content-type"],
        "text/plain; charset=utf-8"
    );
    for name in ["x-request-id", "retry-after", "access-control-allow-origin"] {
        assert!(!response.headers().contains_key(name));
    }
    assert_eq!(
        to_bytes(response.into_body(), 1024).await.unwrap().as_ref(),
        b"Internal Server Error"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

fn router(limiter: TokenRateLimiter, calls: Arc<AtomicUsize>) -> Router {
    Router::new()
        .route(
            "/synthetic-token-boundary",
            post(move || {
                calls.fetch_add(1, Ordering::SeqCst);
                async { Json(json!({"accepted":true})) }
            }),
        )
        .route_layer(middleware::from_fn_with_state(
            Some(limiter),
            token_rate_limit_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            TransportPolicy::new(["https://wallet.example".into()]),
            legacy_transport,
        ))
}

async fn request(router: &Router, origin: bool) -> Response {
    let mut request =
        HttpRequest::post("/synthetic-token-boundary").header("x-request-id", "synthetic-request");
    if origin {
        request = request.header("origin", "https://wallet.example");
    }
    router
        .clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

#[tokio::test]
async fn python_rate_configuration_runs_through_actual_http_middleware() {
    let reference: Value = serde_json::from_slice(include_bytes!(
        "../../../../contracts/token-rate-python-reference.json"
    ))
    .unwrap();
    let cases = reference["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 40);
    for case in cases {
        if case["phase"] == "configuration" {
            continue;
        }
        let values = [
            ("TOKEN_RATE_LIMIT", "limit"),
            ("TOKEN_RATE_WINDOW", "window"),
        ]
        .into_iter()
        .filter_map(|(name, field)| {
            case[field]
                .as_str()
                .map(|value| (name.to_owned(), value.to_owned()))
        });
        let config = crate::IssuanceServiceConfig::from_values(values).unwrap();
        let clock = Arc::new(Clock(AtomicU64::new(0)));
        let limiter =
            TokenRateLimiter::from_python_config(config.token_rate_limit, config.token_rate_window)
                .with_clock(clock.clone());
        let calls = Arc::new(AtomicUsize::new(0));
        let router = router(limiter, calls.clone());
        let step_count = case["time_bits"].as_array().unwrap().len();
        assert_eq!(step_count, case["times"].as_array().unwrap().len());
        assert_eq!(step_count, case["http"].as_array().unwrap().len());
        assert_eq!(step_count, case["direct"].as_array().unwrap().len());
        assert_eq!(step_count, case["stored_state"].as_array().unwrap().len());
        for (time, expected) in case["time_bits"]
            .as_array()
            .unwrap()
            .iter()
            .zip(case["http"].as_array().unwrap())
        {
            clock.0.store(
                u64::from_str_radix(time.as_str().unwrap(), 16).unwrap(),
                Ordering::SeqCst,
            );
            let response = request(&router, false).await;
            assert_eq!(
                u64::from(response.status().as_u16()),
                expected["status"].as_u64().unwrap(),
                "{}",
                case["case"]
            );
            let headers: Map<_, _> = ["content-type", "retry-after", "x-request-id"]
                .into_iter()
                .filter_map(|name| {
                    response
                        .headers()
                        .get(name)
                        .map(|value| (name.into(), json!(value.to_str().unwrap())))
                })
                .collect();
            assert_eq!(
                Value::Object(headers),
                expected["headers"],
                "{}",
                case["case"]
            );
            let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
            let body = serde_json::from_slice::<Value>(&body)
                .unwrap_or_else(|_| json!(std::str::from_utf8(&body).unwrap()));
            assert_eq!(body, expected["body"]);
            assert_eq!(
                calls.load(Ordering::SeqCst) as u64,
                expected["downstream_calls"].as_u64().unwrap()
            );
        }
    }
}

#[tokio::test]
async fn unhandled_rate_failure_bypasses_cors_but_normal_rejection_does_not() {
    for (window, status) in [
        ("60".to_owned(), StatusCode::TOO_MANY_REQUESTS),
        ("9".repeat(400), StatusCode::INTERNAL_SERVER_ERROR),
    ] {
        let limiter =
            TokenRateLimiter::from_python_config("0".parse().unwrap(), window.parse().unwrap());
        let calls = Arc::new(AtomicUsize::new(0));
        let response = request(&router(limiter, calls.clone()), true).await;
        assert_eq!(response.status(), status);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        for name in ["x-request-id", "access-control-allow-origin"] {
            assert_eq!(
                response.headers().contains_key(name),
                status == StatusCode::TOO_MANY_REQUESTS
            );
        }
    }
}
