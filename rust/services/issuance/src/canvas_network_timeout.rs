//! Lossless Canvas timeout values and scoped per-operation deadlines.
//!
//! The published HTTPX owner accepts every Python float at configuration time.
//! Preserve that value separately from the clock's representable deadline. Each
//! connect, TLS, read, write or pool wait needs its own scope; this is not a total
//! request deadline. Existing HTTP consumers are adopted only after wire parity.

use std::{future::Future, time::Duration};

use tokio::time::Instant;

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CanvasNetworkTimeout(u64);

impl std::fmt::Debug for CanvasNetworkTimeout {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("CanvasNetworkTimeout")
            .field(&self.seconds())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanvasNetworkPhase {
    Connect,
    Tls,
    Read,
    Write,
    Pool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("Canvas network {phase:?} operation timed out")]
pub struct CanvasNetworkTimeoutError {
    pub phase: CanvasNetworkPhase,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Deadline {
    Immediate,
    At(Instant),
    Unbounded,
}

impl CanvasNetworkTimeout {
    /// Store IEEE bits so configuration equality is reflexive even for NaN and
    /// does not erase signed zero. No positivity or finite-range restriction.
    pub fn from_seconds(seconds: f64) -> Self {
        Self(seconds.to_bits())
    }

    pub fn seconds(self) -> f64 {
        f64::from_bits(self.0)
    }

    fn deadline(self, now: Instant) -> Deadline {
        let seconds = self.seconds();
        if seconds <= 0.0 {
            return Deadline::Immediate;
        }
        if seconds.is_nan() || seconds.is_infinite() {
            return Deadline::Unbounded;
        }
        let Ok(duration) = Duration::try_from_secs_f64(seconds) else {
            // A positive deadline outside the clock range cannot expire during
            // this process. Retain the original scalar, never clamp configuration.
            return Deadline::Unbounded;
        };
        if duration.is_zero() {
            return Deadline::Immediate;
        }
        now.checked_add(duration)
            .map(Deadline::At)
            .unwrap_or(Deadline::Unbounded)
    }

    /// Run one network operation. Dropping this future cancels its timer and
    /// operation together; no detached timeout task or operation is spawned.
    pub async fn run<F: Future>(
        self,
        phase: CanvasNetworkPhase,
        operation: F,
    ) -> Result<F::Output, CanvasNetworkTimeoutError> {
        let failure = CanvasNetworkTimeoutError { phase };
        match self.deadline(Instant::now()) {
            Deadline::Immediate => Err(failure),
            Deadline::Unbounded => Ok(operation.await),
            Deadline::At(deadline) => {
                if deadline <= Instant::now() {
                    return Err(failure);
                }
                tokio::time::timeout_at(deadline, operation)
                    .await
                    .map_err(|_| failure)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn preserves_all_frozen_timeout_scalars_without_startup_restrictions() {
        let cases: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../contracts/canvas-provider-configuration-scenarios.json"
        ))
        .unwrap();
        for case in cases["timeouts"].as_array().unwrap() {
            let Ok((_, seconds)) = crate::canvas_credentials_protocol::timeout_values(
                case["publish"].as_str(),
                case["status"].as_str(),
            ) else {
                continue;
            };
            let timeout = CanvasNetworkTimeout::from_seconds(seconds);
            assert_eq!(
                timeout, timeout,
                "NaN configuration equality must be reflexive"
            );
            assert_eq!(timeout.seconds().to_bits(), seconds.to_bits());
        }
        assert_ne!(
            CanvasNetworkTimeout::from_seconds(0.0),
            CanvasNetworkTimeout::from_seconds(-0.0)
        );
    }

    #[tokio::test]
    async fn frozen_nonpositive_and_tiny_timeouts_never_poll_connect() {
        for seconds in [0.0, -0.0, -1.0, f64::NEG_INFINITY, 1e-30] {
            let polls = AtomicUsize::new(0);
            let result = CanvasNetworkTimeout::from_seconds(seconds)
                .run(CanvasNetworkPhase::Connect, async {
                    polls.fetch_add(1, Ordering::SeqCst);
                })
                .await;
            assert_eq!(result.unwrap_err().phase, CanvasNetworkPhase::Connect);
            assert_eq!(polls.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn nan_infinite_and_huge_values_allow_delayed_operations() {
        for seconds in [f64::NAN, f64::INFINITY, 1e30, f64::MAX] {
            let result = CanvasNetworkTimeout::from_seconds(seconds)
                .run(CanvasNetworkPhase::Read, async {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    7
                })
                .await;
            assert_eq!(result.unwrap(), 7);
        }
    }

    #[tokio::test]
    async fn each_successful_operation_gets_a_fresh_budget() {
        let timeout = CanvasNetworkTimeout::from_seconds(0.1);
        let started = Instant::now();
        for _ in 0..5 {
            timeout
                .run(
                    CanvasNetworkPhase::Read,
                    tokio::time::sleep(Duration::from_millis(30)),
                )
                .await
                .unwrap();
        }
        assert!(started.elapsed() > Duration::from_millis(100));
        let failure = timeout
            .run(CanvasNetworkPhase::Read, std::future::pending::<()>())
            .await
            .unwrap_err();
        assert_eq!(failure.phase, CanvasNetworkPhase::Read);
    }

    #[tokio::test]
    async fn actual_io_read_and_write_waits_have_independent_deadlines() {
        let timeout = CanvasNetworkTimeout::from_seconds(0.03);
        let (mut writer, mut reader) = tokio::io::duplex(1);
        // One byte fills the owned stream; a second write must wait for a reader.
        timeout
            .run(CanvasNetworkPhase::Write, writer.write_all(b"a"))
            .await
            .unwrap()
            .unwrap();
        let failure = timeout
            .run(CanvasNetworkPhase::Write, writer.write_all(b"b"))
            .await
            .unwrap_err();
        assert_eq!(failure.phase, CanvasNetworkPhase::Write);
        let mut byte = [0];
        timeout
            .run(CanvasNetworkPhase::Read, reader.read_exact(&mut byte))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&byte, b"a");
        let failure = timeout
            .run(CanvasNetworkPhase::Read, reader.read_exact(&mut byte))
            .await
            .unwrap_err();
        assert_eq!(failure.phase, CanvasNetworkPhase::Read);
    }

    struct PendingOperation(Arc<AtomicUsize>);
    impl Future for PendingOperation {
        type Output = ();
        fn poll(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<()> {
            std::task::Poll::Pending
        }
    }
    impl Drop for PendingOperation {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn deadline_and_caller_cancellation_drop_the_owned_operation() {
        let drops = Arc::new(AtomicUsize::new(0));
        let timeout = CanvasNetworkTimeout::from_seconds(0.01);
        assert!(timeout
            .run(CanvasNetworkPhase::Tls, PendingOperation(drops.clone()))
            .await
            .is_err());
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        let task = tokio::spawn(
            CanvasNetworkTimeout::from_seconds(f64::INFINITY)
                .run(CanvasNetworkPhase::Pool, PendingOperation(drops.clone())),
        );
        tokio::task::yield_now().await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(drops.load(Ordering::SeqCst), 2);
    }
}
