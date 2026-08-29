use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const LEGACY_REQUEST_LIMIT: usize = 30;
const LEGACY_WINDOW_SECONDS: u64 = 60;

/// Per-client sliding-window guard retained from the Python OAuth endpoints.
///
/// The state is intentionally process-local: this preserves the deployed
/// behavior while keeping the implementation reusable by the remaining OAuth
/// routes as they move into this crate.
#[derive(Clone)]
pub struct TokenRateLimiter {
    limit: usize,
    window: Duration,
    hits: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
}

impl TokenRateLimiter {
    #[must_use]
    pub fn new(limit: usize, window: Duration) -> Self {
        Self {
            limit,
            window,
            hits: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    #[must_use]
    pub fn legacy_defaults() -> Self {
        Self::new(
            LEGACY_REQUEST_LIMIT,
            Duration::from_secs(LEGACY_WINDOW_SECONDS),
        )
    }

    #[must_use]
    pub fn retry_after_seconds(&self) -> u64 {
        self.window.as_secs()
    }

    pub fn check(&self, client: &str) -> bool {
        self.check_at(client, Instant::now())
    }

    fn check_at(&self, client: &str, now: Instant) -> bool {
        let mut hits = self
            .hits
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let timestamps = hits.entry(client.to_owned()).or_default();
        timestamps.retain(|timestamp| now.saturating_duration_since(*timestamp) < self.window);
        if timestamps.len() >= self.limit {
            return false;
        }
        timestamps.push(now);
        true
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::TokenRateLimiter;

    #[test]
    fn sliding_window_is_per_client_and_reopens_at_the_boundary() {
        let limiter = TokenRateLimiter::new(2, Duration::from_secs(60));
        let start = Instant::now();
        assert!(limiter.check_at("client-a", start));
        assert!(limiter.check_at("client-a", start + Duration::from_secs(1)));
        assert!(!limiter.check_at("client-a", start + Duration::from_secs(2)));
        assert!(limiter.check_at("client-b", start + Duration::from_secs(2)));
        assert!(limiter.check_at("client-a", start + Duration::from_secs(60)));
    }

    #[test]
    fn zero_limit_preserves_the_legacy_reject_all_configuration() {
        let limiter = TokenRateLimiter::new(0, Duration::from_secs(60));
        assert!(!limiter.check_at("client", Instant::now()));
    }
}
