//! Absolute platform monotonic time matching the selected CPython 3.12 clocks.
//! No process-relative epoch, wall-clock fallback, request or configuration logic.
//! The safe API isolates the two pointer-free/owned-output platform FFI calls.

use std::fmt;

const NANOS_PER_SECOND: i64 = 1_000_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockError {
    Unavailable,
    OutOfRange,
    UnsupportedPlatform,
}

impl fmt::Display for ClockError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "monotonic clock unavailable",
            Self::OutOfRange => "monotonic clock out of range",
            Self::UnsupportedPlatform => "monotonic clock platform is not qualified",
        })
    }
}
impl std::error::Error for ClockError {}

/// Preserve CPython's integer-second fast path and cast-before-division order.
#[must_use]
pub fn nanoseconds_to_seconds(nanoseconds: i64) -> f64 {
    if nanoseconds % NANOS_PER_SECOND == 0 {
        (nanoseconds / NANOS_PER_SECOND) as f64
    } else {
        nanoseconds as f64 / 1_000_000_000.0
    }
}

#[cfg(any(windows, target_vendor = "apple", test))]
fn scaled_ticks(ticks: u64, numerator: u32, denominator: u32) -> Result<i64, ClockError> {
    if numerator == 0 || denominator == 0 {
        return Err(ClockError::Unavailable);
    }
    let nanoseconds = u128::from(ticks) * u128::from(numerator) / u128::from(denominator);
    i64::try_from(nanoseconds).map_err(|_| ClockError::OutOfRange)
}

/// Read the OS clock in its native absolute epoch, with checked nanoseconds.
#[cfg(windows)]
pub fn monotonic_nanoseconds() -> Result<i64, ClockError> {
    // SAFETY: GetTickCount64 takes no pointers or handles and has no preconditions.
    // It is the exact clock used by CPython 3.12 time.monotonic on Windows.
    let ticks = unsafe { windows_sys::Win32::System::SystemInformation::GetTickCount64() };
    scaled_ticks(ticks, 1_000_000, 1)
}

#[cfg(target_vendor = "apple")]
pub fn monotonic_nanoseconds() -> Result<i64, ClockError> {
    let mut ratio = libc::mach_timebase_info { numer: 0, denom: 0 };
    // SAFETY: ratio is an initialized, aligned, exclusively borrowed output
    // struct for the duration of the call. Its address is not retained.
    let status = unsafe { libc::mach_timebase_info(&mut ratio) };
    if status != 0 {
        return Err(ClockError::Unavailable);
    }
    // SAFETY: mach_absolute_time takes no pointers and has no preconditions.
    let ticks = unsafe { libc::mach_absolute_time() };
    scaled_ticks(ticks, ratio.numer, ratio.denom)
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
pub fn monotonic_nanoseconds() -> Result<i64, ClockError> {
    use rustix::time::{clock_gettime_dynamic, ClockId, DynamicClockId};
    let time = clock_gettime_dynamic(DynamicClockId::Known(ClockId::Monotonic))
        .map_err(|_| ClockError::Unavailable)?;
    combine_seconds(time.tv_sec, time.tv_nsec)
}

#[cfg(any(
    test,
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
fn combine_seconds(seconds: i64, fraction: impl Into<i64>) -> Result<i64, ClockError> {
    let fraction = fraction.into();
    if !(0..NANOS_PER_SECOND).contains(&fraction) {
        return Err(ClockError::OutOfRange);
    }
    seconds
        .checked_mul(NANOS_PER_SECOND)
        .and_then(|value| value.checked_add(fraction))
        .ok_or(ClockError::OutOfRange)
}

#[cfg(not(any(
    windows,
    target_vendor = "apple",
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
)))]
pub fn monotonic_nanoseconds() -> Result<i64, ClockError> {
    // Do not silently choose a different suspension/epoch policy on an unreviewed OS.
    Err(ClockError::UnsupportedPlatform)
}

#[must_use]
pub const fn implementation() -> &'static str {
    if cfg!(windows) {
        "GetTickCount64"
    } else if cfg!(target_vendor = "apple") {
        "mach_absolute_time"
    } else if cfg!(any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    )) {
        "clock_gettime(CLOCK_MONOTONIC)"
    } else {
        "unsupported"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scaling_checks_failure_and_preserves_integer_order() {
        assert_eq!(scaled_ticks(7, 125, 3), Ok(291));
        assert_eq!(scaled_ticks(1, 0, 1), Err(ClockError::Unavailable));
        assert_eq!(scaled_ticks(1, 1, 0), Err(ClockError::Unavailable));
        assert_eq!(
            scaled_ticks(u64::MAX, u32::MAX, 1),
            Err(ClockError::OutOfRange)
        );
        assert_eq!(scaled_ticks(1_000, 1_000_000, 1), Ok(NANOS_PER_SECOND));
        assert_eq!(combine_seconds(1, 7_i32), Ok(1_000_000_007));
        assert_eq!(combine_seconds(1, -1), Err(ClockError::OutOfRange));
        assert_eq!(
            combine_seconds(1, NANOS_PER_SECOND),
            Err(ClockError::OutOfRange)
        );
        assert_eq!(combine_seconds(i64::MAX, 0), Err(ClockError::OutOfRange));
    }

    #[test]
    fn platform_clock_retains_absolute_epoch_and_monotonicity() {
        assert_ne!(implementation(), "unsupported");
        let first = monotonic_nanoseconds().unwrap();
        let second = monotonic_nanoseconds().unwrap();
        assert!(first > 0);
        assert!(second >= first);
        #[cfg(windows)]
        assert_eq!(first % 1_000_000, 0);
    }

    #[test]
    fn seconds_match_actual_cpython_conversion_bits() {
        let reference: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../../contracts/token-rate-python-reference.json"
        ))
        .unwrap();
        let vectors = reference["clock_vectors"].as_array().unwrap();
        assert_eq!(vectors.len(), 15);
        for vector in vectors {
            let nanoseconds = vector["nanoseconds"].as_str().unwrap().parse().unwrap();
            let expected =
                u64::from_str_radix(vector["seconds_bits"].as_str().unwrap(), 16).unwrap();
            assert_eq!(nanoseconds_to_seconds(nanoseconds).to_bits(), expected);
        }
    }
}
