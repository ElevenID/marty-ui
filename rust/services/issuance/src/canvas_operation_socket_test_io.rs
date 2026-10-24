//! In-memory I/O for the real operation socket; callers own the paused clock.
//! This does not model TLS, HTTP framing, a worker, or durable database effects.

use super::{failed, CanvasNetworkTimeout, CanvasOperationHttpError, OperationSocket};
use std::{
    sync::{atomic::AtomicU8, Arc},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::Instant,
};

pub(crate) struct ReadObservation {
    pub result: Result<Vec<u8>, CanvasOperationHttpError>,
    pub elapsed: Duration,
}

/// One byte represents each scheduled network-read completion. A successful
/// read must renew the inactivity budget; the total request duration may exceed
/// that budget. The writer is an inline owned future, never a detached task.
pub(crate) async fn read_schedule(
    timeout: CanvasNetworkTimeout,
    offsets: &[Duration],
) -> ReadObservation {
    assert!(!offsets.is_empty());
    assert!(offsets.windows(2).all(|pair| pair[0] <= pair[1]));
    let (io, mut peer) = tokio::io::duplex(64);
    let phase = Arc::new(AtomicU8::new(0));
    let mut socket = OperationSocket {
        inner: Box::new(io),
        timeout,
        read_budget: None,
        write_budget: None,
        phase: phase.clone(),
        header_tail: 0,
        headers_written: true,
        body_remaining: 0,
        request_flushed: true,
    };
    let started = Instant::now();
    let read = async {
        let mut bytes = vec![0; offsets.len()];
        let result = match socket.read_exact(&mut bytes).await {
            Ok(_) => Ok(bytes),
            Err(error) => {
                assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
                Err(failed(&phase, CanvasOperationHttpError::Response))
            }
        };
        ReadObservation {
            result,
            elapsed: started.elapsed(),
        }
    };
    let write = async {
        for (index, offset) in offsets.iter().enumerate() {
            tokio::time::sleep_until(started + *offset).await;
            peer.write_all(&[u8::try_from(index + 1).unwrap()])
                .await
                .unwrap();
        }
    };
    tokio::pin!(read);
    // Finishing or timing out the read drops the still-pending writer inline.
    // If all writes finish first, consume the remaining buffered bytes normally.
    tokio::select! {
        observation = &mut read => observation,
        () = write => read.await,
    }
}
