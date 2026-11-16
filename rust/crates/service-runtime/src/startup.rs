//! Bounded startup retries; dependency admission and retry classification stay at callers.

use std::{error::Error, fmt, future::Future, time::Duration};
use tokio::time::{sleep_until, timeout_at, Instant};

#[derive(Debug)]
pub enum StartupDependencyError<E> {
    Dependency(E),
    DeadlineExceeded,
    InvalidPolicy,
}

impl<E> fmt::Display for StartupDependencyError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dependency(_) => f.write_str("startup dependency failed"),
            Self::DeadlineExceeded => {
                f.write_str("startup dependency did not become available before its deadline")
            }
            Self::InvalidPolicy => {
                f.write_str("startup retry requires a finite positive budget and delay")
            }
        }
    }
}

impl<E: Error + 'static> Error for StartupDependencyError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Dependency(error) => Some(error),
            Self::DeadlineExceeded | Self::InvalidPolicy => None,
        }
    }
}

/// Retry only errors admitted by `is_retryable`, within one total deadline.
///
/// The budget includes both the dependency operation and retry delays. There is
/// no detached task: cancelling this future drops the current attempt or delay.
/// A successful operation is still required; expiry never supplies a fallback.
pub async fn retry_startup_dependency<T, E, F, Fut, P>(
    budget: Duration,
    retry_delay: Duration,
    mut attempt: F,
    mut is_retryable: P,
) -> Result<T, StartupDependencyError<E>>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    P: FnMut(&E) -> bool,
{
    if budget.is_zero() || retry_delay.is_zero() {
        return Err(StartupDependencyError::InvalidPolicy);
    }
    let deadline = Instant::now()
        .checked_add(budget)
        .ok_or(StartupDependencyError::InvalidPolicy)?;
    loop {
        if Instant::now() >= deadline {
            return Err(StartupDependencyError::DeadlineExceeded);
        }
        let outcome = timeout_at(deadline, attempt()).await;
        // Tokio polls the operation before its timer. A result made ready at
        // the deadline (or after a non-yielding section) is still too late.
        if Instant::now() >= deadline {
            return Err(StartupDependencyError::DeadlineExceeded);
        }
        match outcome {
            Ok(Ok(value)) => return Ok(value),
            Ok(Err(error)) if is_retryable(&error) => {}
            Ok(Err(error)) => return Err(StartupDependencyError::Dependency(error)),
            Err(_) => return Err(StartupDependencyError::DeadlineExceeded),
        }
        let retry_at = Instant::now()
            .checked_add(retry_delay)
            .map_or(deadline, |next| next.min(deadline));
        sleep_until(retry_at).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    };

    #[derive(Debug, PartialEq)]
    enum DependencyFailure {
        Unavailable,
        InvalidConfiguration,
    }

    fn retryable(error: &DependencyFailure) -> bool {
        matches!(error, DependencyFailure::Unavailable)
    }

    #[tokio::test(start_paused = true)]
    async fn a_delayed_dependency_must_actually_succeed_before_returning() {
        let calls = AtomicUsize::new(0);
        let started = Instant::now();
        let result = retry_startup_dependency(
            Duration::from_secs(30),
            Duration::from_secs(2),
            || {
                let call = calls.fetch_add(1, Ordering::SeqCst);
                async move {
                    if call < 2 {
                        Err(DependencyFailure::Unavailable)
                    } else {
                        Ok("verified connection")
                    }
                }
            },
            retryable,
        )
        .await
        .unwrap();
        assert_eq!(result, "verified connection");
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert_eq!(started.elapsed(), Duration::from_secs(4));
    }

    #[tokio::test(start_paused = true)]
    async fn invalid_configuration_fails_immediately_without_retrying() {
        let calls = AtomicUsize::new(0);
        let started = Instant::now();
        let result = retry_startup_dependency(
            Duration::from_secs(30),
            Duration::from_secs(2),
            || {
                calls.fetch_add(1, Ordering::SeqCst);
                async { Err::<(), _>(DependencyFailure::InvalidConfiguration) }
            },
            retryable,
        )
        .await;
        assert!(matches!(
            result,
            Err(StartupDependencyError::Dependency(
                DependencyFailure::InvalidConfiguration
            ))
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(started.elapsed(), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn persistent_unavailability_never_starts_an_attempt_after_the_deadline() {
        let calls = AtomicUsize::new(0);
        let started = Instant::now();
        let result = retry_startup_dependency(
            Duration::from_secs(5),
            Duration::from_secs(2),
            || {
                calls.fetch_add(1, Ordering::SeqCst);
                async { Err::<(), _>(DependencyFailure::Unavailable) }
            },
            retryable,
        )
        .await;
        assert!(matches!(
            result,
            Err(StartupDependencyError::DeadlineExceeded)
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert_eq!(started.elapsed(), Duration::from_secs(5));
    }

    #[tokio::test(start_paused = true)]
    async fn the_deadline_also_bounds_a_dependency_that_never_returns() {
        let calls = AtomicUsize::new(0);
        let started = Instant::now();
        let result = retry_startup_dependency(
            Duration::from_secs(5),
            Duration::from_secs(2),
            || {
                calls.fetch_add(1, Ordering::SeqCst);
                std::future::pending::<Result<(), DependencyFailure>>()
            },
            retryable,
        )
        .await;
        assert!(matches!(
            result,
            Err(StartupDependencyError::DeadlineExceeded)
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(started.elapsed(), Duration::from_secs(5));
    }

    #[tokio::test(start_paused = true)]
    async fn success_at_the_absolute_deadline_is_rejected() {
        let started = Instant::now();
        let result = retry_startup_dependency(
            Duration::from_secs(5),
            Duration::from_secs(2),
            || async {
                tokio::time::sleep(Duration::from_secs(5)).await;
                Ok::<_, DependencyFailure>("late connection")
            },
            retryable,
        )
        .await;
        assert!(matches!(
            result,
            Err(StartupDependencyError::DeadlineExceeded)
        ));
        assert_eq!(started.elapsed(), Duration::from_secs(5));
    }

    #[tokio::test(start_paused = true)]
    async fn cancelling_during_retry_delay_stops_further_attempts() {
        let calls = Arc::new(AtomicUsize::new(0));
        let task_calls = calls.clone();
        let task = tokio::spawn(retry_startup_dependency(
            Duration::from_secs(30),
            Duration::from_secs(2),
            move || {
                task_calls.fetch_add(1, Ordering::SeqCst);
                async { Err::<(), _>(DependencyFailure::Unavailable) }
            },
            retryable,
        ));
        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        tokio::time::advance(Duration::from_secs(60)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn cancelling_drops_the_in_flight_dependency_attempt() {
        struct Dropped(Arc<AtomicBool>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let dropped = Arc::new(AtomicBool::new(false));
        let attempt_dropped = dropped.clone();
        let task = tokio::spawn(retry_startup_dependency(
            Duration::from_secs(30),
            Duration::from_secs(2),
            move || {
                let guard = Dropped(attempt_dropped.clone());
                async move {
                    let _guard = guard;
                    std::future::pending::<Result<(), DependencyFailure>>().await
                }
            },
            retryable,
        ));
        tokio::task::yield_now().await;
        assert!(!dropped.load(Ordering::SeqCst));
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[tokio::test(start_paused = true)]
    async fn an_invalid_retry_policy_never_calls_the_dependency() {
        for (budget, delay) in [
            (Duration::ZERO, Duration::from_secs(1)),
            (Duration::from_secs(1), Duration::ZERO),
            (Duration::MAX, Duration::from_secs(1)),
        ] {
            let result: Result<(), StartupDependencyError<DependencyFailure>> =
                retry_startup_dependency(
                    budget,
                    delay,
                    || async { panic!("invalid policy must fail before activation") },
                    |_: &DependencyFailure| true,
                )
                .await;
            assert!(matches!(result, Err(StartupDependencyError::InvalidPolicy)));
        }
    }
}
