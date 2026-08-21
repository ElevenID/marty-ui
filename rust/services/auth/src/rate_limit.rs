use std::{net::SocketAddr, sync::Arc};

use axum::{
    extract::{ConnectInfo, Request, State},
    http::{header, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use mmf_security::{
    DistributedRateLimiter, RateLimitQuota, RateLimitRule, RateLimitScope, RateLimitStrategy,
    SecurityError,
};
use serde_json::json;

const RATE_LIMIT_WINDOW_MS: u64 = 60_000;

pub struct AuthRateLimiter {
    provider: Arc<dyn DistributedRateLimiter>,
    rule: RateLimitRule,
}

impl AuthRateLimiter {
    pub fn new(
        provider: Arc<dyn DistributedRateLimiter>,
        requests_per_minute: u64,
    ) -> Result<Self, SecurityError> {
        let rule = RateLimitRule {
            name: "marty_auth_unauthenticated".into(),
            scope: RateLimitScope::PerIp,
            strategy: RateLimitStrategy::SlidingWindow,
            limit: requests_per_minute,
            window_ms: RATE_LIMIT_WINDOW_MS,
            burst_size: 0,
            enabled: true,
        };
        rule.validate()?;
        Ok(Self { provider, rule })
    }

    pub async fn check(
        &self,
        path: &str,
        client_ip: &str,
        now_ms: u64,
    ) -> Result<Option<mmf_security::RateLimitResult>, SecurityError> {
        if !is_rate_limited_auth_path(path) {
            return Ok(None);
        }
        self.provider
            .check(
                &self.rule,
                &RateLimitQuota {
                    ip_address: Some(client_ip.into()),
                    ..RateLimitQuota::default()
                },
                now_ms,
            )
            .await
            .map(Some)
    }
}

#[must_use]
pub fn is_rate_limited_auth_path(path: &str) -> bool {
    if path.starts_with("/v1/auth/credential-login/status")
        || path.starts_with("/v1/auth/credential-login/assets/")
    {
        return false;
    }
    [
        "/v1/auth/login",
        "/v1/auth/register",
        "/v1/auth/callback",
        "/v1/auth/credential-login",
    ]
    .iter()
    .any(|prefix| path.starts_with(prefix))
}

pub async fn auth_rate_limit_middleware(
    State(limiter): State<Arc<AuthRateLimiter>>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path().to_owned();
    let client_ip = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(address)| address.ip().to_string())
        .unwrap_or_else(|| "unknown".into());
    match limiter.check(&path, &client_ip, unix_time_ms()).await {
        Ok(Some(result)) if !result.allowed => {
            let retry_seconds = result.retry_after_ms.div_ceil(1_000).max(1);
            let mut response = (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({"detail": "Too many requests. Please try again later."})),
            )
                .into_response();
            if let Ok(value) = HeaderValue::from_str(&retry_seconds.to_string()) {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
            response
        }
        Ok(_) => next.run(request).await,
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"detail": "Authentication rate limiter is unavailable"})),
        )
            .into_response(),
    }
}

fn unix_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}
