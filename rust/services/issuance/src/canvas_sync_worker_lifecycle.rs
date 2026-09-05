//! Initialized Canvas worker ownership, including awaited PostgreSQL disposal.

use std::{convert::Infallible, future::Future};

use mmf_runtime::managed_task::{ManagedTask, TaskCompletion, TaskJoinError};
use sqlx::PgPool;
use tokio::sync::watch;

/// Explicit graceful stop and task cancellation are separate control events.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerShutdown {
    Drain,
    Cancel,
}

/// Own the pool before invoking any fallible worker initialization. Cancellation
/// must be requested through the returned owner and acknowledged with `join`.
/// Dropping the owner requests cleanup but cannot await it; the runtime must
/// remain alive. Host failure and forced runtime shutdown cannot promise cleanup.
pub fn spawn_with_postgres_cleanup<T, E, F, W>(
    pool: PgPool,
    operation: F,
) -> ManagedTask<T, E, Infallible>
where
    T: Send + 'static,
    E: Send + 'static,
    F: FnOnce(PgPool) -> W + Send + 'static,
    W: Future<Output = Result<T, E>> + Send + 'static,
{
    let cleanup_pool = pool.clone();
    ManagedTask::spawn(async move { operation(pool).await }, move || async move {
        cleanup_pool.close().await;
        Ok(())
    })
}

/// Await cleanup after either control event. Cancellation is acknowledged by
/// the owner, not mapped to graceful success. The signal future is owned inline;
/// no detached signal helper survives operation completion or cancellation.
pub async fn finish_on_shutdown<T: Send + 'static, E: Send + 'static>(
    owner: ManagedTask<T, E>,
    stop: watch::Sender<bool>,
    shutdown: impl Future<Output = WorkerShutdown>,
) -> Result<TaskCompletion<T, E>, TaskJoinError> {
    let cancellation = owner.cancellation_handle();
    let join = owner.join();
    tokio::pin!(join);
    tokio::select! {
        result = &mut join => result,
        action = shutdown => {
            match action {
                WorkerShutdown::Drain => { let _ = stop.send(true); }
                WorkerShutdown::Cancel => { let _ = cancellation.cancel(); }
            }
            join.await
        }
    }
}
