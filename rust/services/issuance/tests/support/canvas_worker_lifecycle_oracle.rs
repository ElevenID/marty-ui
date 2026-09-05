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
use serde_json::Value;
use sqlx::PgPool;
use tokio::sync::{watch, Notify, Semaphore};

use super::canvas_worker_range_oracle::observed_worker;

#[derive(Default)]
struct ProcessorState {
    entered: AtomicUsize,
    active: AtomicUsize,
    cleaned: AtomicUsize,
    entry: Notify,
}

struct ActiveProcessor(Arc<ProcessorState>);

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

async fn await_both_processors<F: std::future::Future>(
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

struct ControlledCycle {
    worker: CanvasSyncWorker,
    state: Arc<ProcessorState>,
    release: Arc<Semaphore>,
}

async fn controlled_cycle(pool: &PgPool, panic_target: Option<&'static str>) -> ControlledCycle {
    sqlx::query("TRUNCATE issuance_service.canvas_evidence_sync_jobs, issuance_service.canvas_evidence_sync_targets, issuance_service.canvas_worker_heartbeats")
        .execute(pool).await.unwrap();
    super::seed_target(pool, "owned-cycle-a", 900).await;
    super::seed_target(pool, "owned-cycle-b", 900).await;
    let state = Arc::new(ProcessorState::default());
    let release = Arc::new(Semaphore::new(0));
    let config = CanvasSyncWorkerConfig::from_values(&BTreeMap::from([(
        "CANVAS_SYNC_WORKER_ID".to_owned(),
        "owned-cycle-worker".to_owned(),
    )]))
    .unwrap();
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
