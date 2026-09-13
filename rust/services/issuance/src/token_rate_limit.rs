use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex},
    time::Duration,
};

use mmf_config::numeric_config::{parse_python_config_float, PythonConfigInteger};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenRateLimitError {
    ClockUnavailable,
    WindowOverflow,
}

impl fmt::Display for TokenRateLimitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ClockUnavailable => "token rate clock unavailable",
            Self::WindowOverflow => "token rate window cannot be represented",
        })
    }
}
impl std::error::Error for TokenRateLimitError {}

pub trait TokenRateClock: Send + Sync {
    fn now(&self) -> Result<f64, TokenRateLimitError>;
}

struct PlatformClock;
impl TokenRateClock for PlatformClock {
    fn now(&self) -> Result<f64, TokenRateLimitError> {
        marty_platform_clock::monotonic_nanoseconds()
            .map(marty_platform_clock::nanoseconds_to_seconds)
            .map_err(|_| TokenRateLimitError::ClockUnavailable)
    }
}

/// Process-local per-IP Python sliding window, retaining exact configuration
/// integers and the original absolute-clock subtraction/comparison order.
#[derive(Clone)]
pub struct TokenRateLimiter {
    maximum_hits: Option<usize>,
    window: Result<f64, TokenRateLimitError>,
    retry_after: PythonConfigInteger,
    clock: Arc<dyn TokenRateClock>,
    hits: Arc<Mutex<HashMap<String, Vec<f64>>>>,
}

impl TokenRateLimiter {
    /// Preserve the existing constructor, including subsecond native durations.
    #[must_use]
    pub fn new(limit: usize, window: Duration) -> Self {
        Self {
            maximum_hits: Some(limit),
            window: Ok(window.as_secs_f64()),
            retry_after: window.as_secs().into(),
            clock: Arc::new(PlatformClock),
            hits: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    #[must_use]
    pub fn from_python_config(limit: PythonConfigInteger, window: PythonConfigInteger) -> Self {
        let maximum_hits = if limit <= 0_u64.into() {
            Some(0)
        } else {
            limit.to_usize()
        };
        // A positive threshold above usize cannot be reached by an addressable
        // Vec; preserve that distinction rather than clamping or rejecting it.
        let seconds = parse_python_config_float(window.as_decimal())
            .ok()
            .filter(|value| value.is_finite())
            .ok_or(TokenRateLimitError::WindowOverflow);
        Self {
            maximum_hits,
            window: seconds,
            retry_after: window,
            clock: Arc::new(PlatformClock),
            hits: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn TokenRateClock>) -> Self {
        self.clock = clock;
        self
    }

    #[must_use]
    pub fn legacy_defaults() -> Self {
        Self::new(30, Duration::from_secs(60))
    }

    /// Internal API now retains negative/large values, never a u64 sentinel.
    #[must_use]
    pub fn retry_after_seconds(&self) -> &PythonConfigInteger {
        &self.retry_after
    }

    #[must_use]
    pub fn retry_after_header(&self) -> &str {
        self.retry_after.as_decimal()
    }

    /// Compatibility bool API. HTTP owners use check_request to distinguish
    /// ordinary rejection from the original unhandled clock/arithmetic failure.
    pub fn check(&self, client: &str) -> bool {
        self.check_request(client).unwrap_or(false)
    }

    pub fn check_request(&self, client: &str) -> Result<bool, TokenRateLimitError> {
        self.check_at(client, self.clock.now()?)
    }

    fn check_at(&self, client: &str, now: f64) -> Result<bool, TokenRateLimitError> {
        if !now.is_finite() {
            return Err(TokenRateLimitError::ClockUnavailable);
        }
        let mut hits = self
            .hits
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Python converts the integer during subtraction before checking limit.
        let cutoff = now - self.window?;
        let mut timestamps: Vec<_> = hits
            .get(client)
            .into_iter()
            .flatten()
            .copied()
            .filter(|timestamp| *timestamp > cutoff)
            .collect();
        if self
            .maximum_hits
            .is_some_and(|limit| timestamps.len() >= limit)
        {
            return Ok(false);
        }
        timestamps.push(now);
        hits.insert(client.to_owned(), timestamps);
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_python_configuration_and_limiter_reference_is_preserved() {
        let reference: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../../contracts/token-rate-python-reference.json"
        ))
        .unwrap();
        let cases = reference["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 40);
        for case in cases {
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
            let config = crate::IssuanceServiceConfig::from_values(values);
            if case["phase"] == "configuration" {
                let error = config.unwrap_err();
                assert_eq!(error.code, mmf_core::ErrorCode::Configuration);
                let rendered = format!("{error:?}");
                assert!(!rendered.contains("private-canary"));
                assert!(error
                    .message
                    .ends_with("must be a Python-compatible integer"));
                continue;
            }
            let config = config.unwrap();
            assert_eq!(
                config.token_rate_limit.as_decimal(),
                case["parsed_limit"].as_str().unwrap()
            );
            assert_eq!(
                config.token_rate_window.as_decimal(),
                case["parsed_window"].as_str().unwrap()
            );
            let limiter = TokenRateLimiter::from_python_config(
                config.token_rate_limit,
                config.token_rate_window,
            );
            let step_count = case["time_bits"].as_array().unwrap().len();
            assert_eq!(step_count, case["times"].as_array().unwrap().len());
            assert_eq!(step_count, case["direct"].as_array().unwrap().len());
            assert_eq!(step_count, case["stored_state"].as_array().unwrap().len());
            assert_eq!(step_count, case["http"].as_array().unwrap().len());
            for (step, (time, expected)) in case["time_bits"]
                .as_array()
                .unwrap()
                .iter()
                .zip(case["direct"].as_array().unwrap())
                .enumerate()
            {
                let now = f64::from_bits(u64::from_str_radix(time.as_str().unwrap(), 16).unwrap());
                let observed = limiter.check_at("synthetic-client", now);
                if expected["allowed"] == true {
                    assert_eq!(observed, Ok(true));
                } else if expected["status"] == 429 {
                    assert_eq!(observed, Ok(false));
                    assert_eq!(
                        limiter.retry_after_header(),
                        expected["headers"]["Retry-After"].as_str().unwrap()
                    );
                } else {
                    assert_eq!(expected["error_type"], "OverflowError");
                    assert_eq!(observed, Err(TokenRateLimitError::WindowOverflow));
                }
                let hits = limiter.hits.lock().unwrap();
                let timestamp_bits: Vec<_> = hits
                    .get("synthetic-client")
                    .into_iter()
                    .flatten()
                    .map(|value| format!("{:016x}", value.to_bits()))
                    .collect();
                assert_eq!(
                    serde_json::json!({"clients":hits.len(),"timestamp_bits":timestamp_bits}),
                    case["stored_state"][step]
                );
            }
        }
    }

    #[test]
    fn sliding_window_is_per_client_and_reopens_at_the_boundary() {
        let limiter = TokenRateLimiter::new(2, Duration::from_secs(60));
        assert_eq!(limiter.check_at("client-a", 100.0), Ok(true));
        assert_eq!(limiter.check_at("client-a", 101.0), Ok(true));
        assert_eq!(limiter.check_at("client-a", 102.0), Ok(false));
        assert_eq!(limiter.check_at("client-b", 102.0), Ok(true));
        assert_eq!(limiter.check_at("client-a", 160.0), Ok(true));
    }

    #[test]
    fn zero_limit_preserves_the_legacy_reject_all_configuration() {
        let limiter = TokenRateLimiter::new(0, Duration::from_secs(60));
        assert_eq!(limiter.check_at("client", 100.0), Ok(false));
    }

    #[test]
    fn subsecond_duration_constructor_remains_supported() {
        let limiter = TokenRateLimiter::new(1, Duration::from_millis(500));
        assert_eq!(limiter.retry_after_header(), "0");
        assert_eq!(limiter.check_at("client", 100.0), Ok(true));
        assert_eq!(limiter.check_at("client", 100.25), Ok(false));
        assert_eq!(limiter.check_at("client", 100.5), Ok(true));
    }

    #[test]
    fn invalid_clock_is_explicit_and_does_not_mutate_budget() {
        let limiter = TokenRateLimiter::new(1, Duration::from_secs(60));
        for now in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert_eq!(
                limiter.check_at("client", now),
                Err(TokenRateLimitError::ClockUnavailable)
            );
        }
        assert!(limiter.hits.lock().unwrap().is_empty());
    }
}
