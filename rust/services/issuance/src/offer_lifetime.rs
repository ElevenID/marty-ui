//! Per-offer shortening only. This does not change process defaults or authorization.
use chrono::{DateTime, Datelike, Duration, Utc};

pub const MINIMUM_OFFER_TTL_SECONDS: u64 = 60;

pub fn shortened_expiry(
    now: DateTime<Utc>,
    configured_minutes: Option<i64>,
    seconds: u64,
) -> Result<DateTime<Utc>, &'static str> {
    let maximum = configured_minutes
        .and_then(|value| value.checked_mul(60))
        .and_then(|value| u64::try_from(value).ok())
        .ok_or("INVALID_OFFER_LIFETIME")?;
    if seconds < MINIMUM_OFFER_TTL_SECONDS || seconds > maximum {
        return Err("INVALID_OFFER_LIFETIME");
    }
    let duration = i64::try_from(seconds)
        .ok()
        .and_then(Duration::try_seconds)
        .ok_or("INVALID_OFFER_LIFETIME")?;
    now.checked_add_signed(duration)
        .filter(|value| (1..=9999).contains(&value.year()))
        .ok_or("INVALID_OFFER_LIFETIME")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn per_offer_lifetime_is_bounded_and_uses_server_time() {
        let now = DateTime::parse_from_rfc3339("2026-10-28T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        for seconds in [0, 1, 59, 121, u64::MAX] {
            assert!(shortened_expiry(now, Some(2), seconds).is_err());
        }
        for seconds in [60, 120] {
            assert_eq!(
                shortened_expiry(now, Some(2), seconds).unwrap(),
                now + Duration::seconds(seconds as i64)
            );
        }
        for configured in [None, Some(-1), Some(0), Some(i64::MAX)] {
            assert!(shortened_expiry(now, configured, 60).is_err());
        }
    }
}
