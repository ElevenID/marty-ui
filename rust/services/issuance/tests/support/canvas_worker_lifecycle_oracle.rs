//! Actual worker-cycle cancellation against PostgreSQL, with controlled
//! processors as in the frozen legacy lifecycle oracle. No fake cycle/SQL.

use std::{
    collections::BTreeMap,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use async_trait::async_trait;
use marty_issuance_service::canvas_sync_worker::{
    CanvasSyncProcessingError, CanvasSyncProcessor, CanvasSyncResult, CanvasSyncTarget,
    CanvasSyncWorker, CanvasSyncWorkerConfig,
};
use marty_issuance_service::canvas_sync_worker_lifecycle::{
    finish_on_shutdown, spawn_with_postgres_cleanup, WorkerShutdown,
};
use mmf_runtime::managed_task::{CleanupOutcome, TaskOutcome};
use serde_json::Value;
use sqlx::{pool::PoolConnection, postgres::PgPoolOptions, PgPool, Postgres};
use tokio::sync::{oneshot, watch, Notify, Semaphore};

use super::canvas_worker_range_oracle::observed_worker;

#[derive(Default)]
pub(super) struct ProcessorState {
    entered: AtomicUsize,
    pub(super) active: AtomicUsize,
    pub(super) cleaned: AtomicUsize,
    entry: Notify,
}

struct ActiveProcessor(Arc<ProcessorState>);

struct SignalScope(Arc<AtomicUsize>);

impl Drop for SignalScope {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

impl Drop for ActiveProcessor {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
        self.0.cleaned.fetch_add(1, Ordering::SeqCst);
    }
}

struct ControlledProcessor {
    state: Arc<ProcessorState>,
    release: Arc<Semaphore>,
    panic_target: Option<&'static str>,
}

#[async_trait]
impl CanvasSyncProcessor for ControlledProcessor {
    fn configured(&self) -> bool {
        true
    }

    async fn process(
        &self,
        target: &CanvasSyncTarget,
    ) -> Result<CanvasSyncResult, CanvasSyncProcessingError> {
        self.state.active.fetch_add(1, Ordering::SeqCst);
        let _active = ActiveProcessor(self.state.clone());
        self.state.entered.fetch_add(1, Ordering::SeqCst);
        self.state.entry.notify_one();
        self.release
            .acquire()
            .await
            .expect("owned processor release")
            .forget();
        assert_ne!(
            self.panic_target,
            Some(target.id.as_str()),
            "synthetic processor panic"
        );
        Ok(CanvasSyncResult::default())
    }
}

pub(super) async fn await_both_processors<F: std::future::Future>(
    mut cycle: Pin<&mut F>,
    state: &ProcessorState,
) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while state.entered.load(Ordering::SeqCst) != 2 {
            tokio::select! {
                _ = &mut cycle => panic!("cycle completed before both processors were active"),
                () = state.entry.notified() => {},
            }
        }
    })
    .await
    .expect("both jobs must progress concurrently");
    assert_eq!(state.active.load(Ordering::SeqCst), 2);
}

pub(super) struct ControlledCycle {
    pub(super) worker: CanvasSyncWorker,
    pub(super) state: Arc<ProcessorState>,
    release: Arc<Semaphore>,
}

async fn controlled_cycle(pool: &PgPool, panic_target: Option<&'static str>) -> ControlledCycle {
    let config = CanvasSyncWorkerConfig::from_values(&BTreeMap::from([(
        "CANVAS_SYNC_WORKER_ID".to_owned(),
        "owned-cycle-worker".to_owned(),
    )]))
    .unwrap();
    controlled_cycle_with_config(pool, panic_target, config).await
}

pub(super) async fn controlled_cycle_with_config(
    pool: &PgPool,
    panic_target: Option<&'static str>,
    config: CanvasSyncWorkerConfig,
) -> ControlledCycle {
    sqlx::query("TRUNCATE issuance_service.canvas_evidence_sync_jobs, issuance_service.canvas_evidence_sync_targets, issuance_service.canvas_worker_heartbeats")
        .execute(pool).await.unwrap();
    super::seed_target(pool, "owned-cycle-a", 900).await;
    super::seed_target(pool, "owned-cycle-b", 900).await;
    let state = Arc::new(ProcessorState::default());
    let release = Arc::new(Semaphore::new(0));
    let (worker, _) = observed_worker(
        pool,
        config,
        Arc::new(ControlledProcessor {
            state: state.clone(),
            release: release.clone(),
            panic_target,
        }),
        None,
    );
    ControlledCycle {
        worker,
        state,
        release,
    }
}

async fn durable_jobs(pool: &PgPool) -> Vec<(String, bool)> {
    sqlx::query_as(
        "SELECT status, completed_at IS NOT NULL FROM issuance_service.canvas_evidence_sync_jobs ORDER BY target_id"
    ).fetch_all(pool).await.unwrap()
}

pub async fn assert_owned_cycle_lifecycle(pool: &PgPool) {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/issuance-canvas-sync-worker.json"
    ))
    .unwrap();
    assert_eq!(contract["shutdown"]["cancellation_propagates"], true);
    assert_eq!(
        contract["shutdown"]["lease_maintenance_task"],
        "cancel and await after every terminal or fenced outcome"
    );

    for panic_target in [None, Some("owned-cycle-a")] {
        let ControlledCycle {
            worker,
            state,
            release,
        } = controlled_cycle(pool, panic_target).await;
        let mut cycle = Box::pin(worker.run_cycle());
        await_both_processors(cycle.as_mut(), &state).await;
        if panic_target.is_none() {
            // Cancellation drops the actual parent future. Check BEFORE any
            // yield, SQL call or sleep could conceal a still-running child.
            drop(cycle);
            assert_eq!(
                state.active.load(Ordering::SeqCst),
                0,
                "cancelled cycle left live processor children"
            );
            assert_eq!(state.cleaned.load(Ordering::SeqCst), 2);
            assert_eq!(
                durable_jobs(pool).await,
                vec![("leased".to_owned(), false); 2],
                "cancellation must not falsely complete a leased job"
            );
        } else {
            release.add_permits(2);
            let result = tokio::time::timeout(Duration::from_secs(5), cycle)
                .await
                .expect("panic must not stall sibling completion")
                .unwrap();
            assert_eq!(result.leased, 2);
            assert_eq!(result.succeeded, 1);
            assert_eq!(result.retried, 0);
            assert_eq!(result.dead_lettered, 0);
            assert_eq!(state.active.load(Ordering::SeqCst), 0);
            assert_eq!(state.cleaned.load(Ordering::SeqCst), 2);
            assert_eq!(
                durable_jobs(pool).await,
                vec![("leased".to_owned(), false), ("succeeded".to_owned(), true)]
            );
        }
    }
    assert_eq!(
        contract["shutdown"]["stop_event_checked_before_each_cycle"],
        true
    );
    let ControlledCycle { worker, state, .. } = controlled_cycle(pool, None).await;
    let (_stop, receiver) = watch::channel(true);
    worker.run_loop(receiver).await.unwrap();
    assert_eq!(state.entered.load(Ordering::SeqCst), 0);
    assert!(durable_jobs(pool).await.is_empty());
    let (heartbeats,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM issuance_service.canvas_worker_heartbeats")
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(heartbeats, 0, "pre-stopped loop must start no work");

    assert_eq!(
        contract["shutdown"]["in_flight_cycle"],
        "allowed to finish unless task cancellation is requested"
    );
    let ControlledCycle {
        worker,
        state,
        release,
    } = controlled_cycle(pool, None).await;
    let (stop, receiver) = watch::channel(false);
    let mut run_loop = Box::pin(worker.run_loop(receiver));
    await_both_processors(run_loop.as_mut(), &state).await;
    stop.send(true).unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut run_loop)
            .await
            .is_err(),
        "graceful stop must allow in-flight work to finish"
    );
    assert_eq!(state.active.load(Ordering::SeqCst), 2);
    release.add_permits(2);
    tokio::time::timeout(Duration::from_secs(5), run_loop)
        .await
        .expect("graceful stop must finish after its active cycle")
        .unwrap();
    assert_eq!(state.active.load(Ordering::SeqCst), 0);
    assert_eq!(state.cleaned.load(Ordering::SeqCst), 2);
    assert_eq!(
        durable_jobs(pool).await,
        vec![("succeeded".to_owned(), true); 2]
    );
    eprintln!("native PostgreSQL lifecycle: owned cancellation, panic isolation, pre-stop and graceful drain passed");
}

async fn disposal_pool(observer: &PgPool) -> PgPool {
    // Same already-guarded synthetic *_test database, independent pool owner.
    // Keeping the observer open permits durable assertions AFTER owner disposal.
    PgPoolOptions::new()
        .max_connections(6)
        .connect_with((*observer.connect_options()).clone())
        .await
        .expect("dedicated disposal pool")
}

async fn join_after_connection_release<F: std::future::Future>(
    pool: &PgPool,
    mut join: Pin<&mut F>,
    held: PoolConnection<Postgres>,
) -> F::Output {
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::select! {
            _ = &mut join => panic!("join completed before pool disposal started"),
            () = pool.close_event() => {}
        }
    })
    .await
    .expect("cleanup must start even while a connection is checked out");
    assert!(
        pool.is_closed(),
        "closed flag means closing started, not finished"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut join)
            .await
            .is_err(),
        "join must await pool disposal, not merely request it"
    );
    assert!(
        pool.size() >= 1,
        "checked-out connection still belongs to pool"
    );
    drop(held);
    let result = tokio::time::timeout(Duration::from_secs(5), join)
        .await
        .expect("join must finish after the held connection is released");
    assert_eq!(
        pool.size(),
        0,
        "all owned connections disposed before acknowledgment"
    );
    assert!(matches!(pool.acquire().await, Err(sqlx::Error::PoolClosed)));
    result
}

pub async fn assert_initialized_pool_disposal(observer: &PgPool) {
    // Replays the initialized return/error floor against real PostgreSQL.
    // The extra initialization-factory panic case is a native strengthening.
    for exit in ["return", "error", "initialization-panic"] {
        let pool = disposal_pool(observer).await;
        let held = pool.acquire().await.unwrap();
        let owner = spawn_with_postgres_cleanup(pool.clone(), move |operation_pool| {
            assert_ne!(
                exit, "initialization-panic",
                "synthetic initialization panic"
            );
            async move {
                let (one,): (i32,) = sqlx::query_as("SELECT 1")
                    .fetch_one(&operation_pool)
                    .await
                    .unwrap();
                assert_eq!(one, 1);
                if exit == "error" {
                    Err("synthetic initialized operation failure")
                } else {
                    Ok(())
                }
            }
        });
        let cancellation = owner.cancellation_handle();
        let signal_drops = Arc::new(AtomicUsize::new(0));
        let signal_scope = SignalScope(signal_drops.clone());
        let (stop, _receiver) = watch::channel(false);
        let mut join = Box::pin(finish_on_shutdown(owner, stop, async move {
            let _scope = signal_scope;
            std::future::pending::<WorkerShutdown>().await
        }));
        // Waiting for the close event is not a substitute for awaiting join.
        tokio::time::timeout(Duration::from_secs(5), pool.close_event())
            .await
            .unwrap();
        assert!(
            !cancellation.cancel(),
            "late cancellation cannot abort disposal"
        );
        let completion = join_after_connection_release(&pool, join.as_mut(), held)
            .await
            .unwrap();
        assert_eq!(completion.cleanup, CleanupOutcome::Completed);
        assert_eq!(
            signal_drops.load(Ordering::SeqCst),
            1,
            "natural exit owns signal scope too"
        );
        match exit {
            "return" => assert_eq!(completion.outcome, TaskOutcome::Completed(())),
            "error" => assert_eq!(
                completion.outcome,
                TaskOutcome::Failed("synthetic initialized operation failure")
            ),
            _ => assert_eq!(completion.outcome, TaskOutcome::Panicked),
        }
    }

    // Real run_loop, real SQL and two active controlled processors. Graceful
    // shutdown and explicit cancellation must remain observably different.
    for cancel in [false, true] {
        let pool = disposal_pool(observer).await;
        let ControlledCycle {
            worker,
            state,
            release,
        } = controlled_cycle(&pool, None).await;
        let held = pool.acquire().await.unwrap();
        let (shutdown, signal) = oneshot::channel();
        let signal_drops = Arc::new(AtomicUsize::new(0));
        let signal_scope = SignalScope(signal_drops.clone());
        let (stop, receiver) = watch::channel(false);
        let owner = spawn_with_postgres_cleanup(pool.clone(), move |_pool| async move {
            worker.run_loop(receiver).await
        });
        let mut join = Box::pin(finish_on_shutdown(owner, stop, async move {
            let _scope = signal_scope;
            signal.await.expect("owned shutdown signal")
        }));
        await_both_processors(join.as_mut(), &state).await;
        if cancel {
            shutdown.send(WorkerShutdown::Cancel).unwrap();
        } else {
            shutdown.send(WorkerShutdown::Drain).unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(20), &mut join)
                    .await
                    .is_err(),
                "graceful shutdown must drain active processors"
            );
            assert_eq!(state.active.load(Ordering::SeqCst), 2);
            assert!(!pool.is_closed(), "pool must remain available during drain");
            release.add_permits(2);
        }
        let completion = join_after_connection_release(&pool, join.as_mut(), held)
            .await
            .unwrap();
        assert_eq!(completion.cleanup, CleanupOutcome::Completed);
        if cancel {
            assert_eq!(completion.outcome, TaskOutcome::Cancelled);
        } else {
            assert_eq!(completion.outcome, TaskOutcome::Completed(()));
        }
        assert_eq!(state.active.load(Ordering::SeqCst), 0);
        assert_eq!(state.cleaned.load(Ordering::SeqCst), 2);
        assert_eq!(
            signal_drops.load(Ordering::SeqCst),
            1,
            "no detached signal helper"
        );
        assert_eq!(
            durable_jobs(observer).await,
            vec![
                (
                    if cancel { "leased" } else { "succeeded" }.to_owned(),
                    !cancel
                );
                2
            ]
        );
    }
    eprintln!("native PostgreSQL disposal: return, error, initialization panic, active cancellation and graceful drain passed");
}
