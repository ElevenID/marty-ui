//! Frozen whole-job outcomes through the actual native worker and PostgreSQL.
//! Controlled processor outcomes; no replacement cycle, renewal method or clock.

use std::{
    collections::BTreeMap,
    sync::{atomic::Ordering, Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use futures_util::FutureExt;
use marty_issuance_service::{
    canvas_sync_lease::CanvasSyncLease,
    canvas_sync_worker::{
        canvas_sync_result, CanvasSyncProcessingError, CanvasSyncProcessor, CanvasSyncResult,
        CanvasSyncTarget, CanvasSyncWorkerConfig,
    },
};
use serde_json::{json, Value};
use sqlx::PgPool;
use tokio::sync::Semaphore;
use tracing::instrument::WithSubscriber;
use tracing_subscriber::layer::SubscriberExt;

#[derive(Default)]
struct JobErrorFields {
    job_id: Option<String>,
    class: Option<String>,
}

impl tracing::field::Visit for JobErrorFields {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        match field.name() {
            "job_id" => self.job_id = Some(value.to_owned()),
            "exception_class" => self.class = Some(value.to_owned()),
            _ => {}
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if matches!(field.name(), "job_id" | "exception_class") {
            self.record_str(field, &format!("{value:?}"));
        }
    }
}

struct JobErrors(Arc<Mutex<Vec<(String, String)>>>);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for JobErrors {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        if *event.metadata().level() != tracing::Level::ERROR {
            return;
        }
        let mut fields = JobErrorFields::default();
        event.record(&mut fields);
        if let (Some(job), Some(class)) = (fields.job_id, fields.class) {
            self.0.lock().unwrap().push((job, class));
        }
    }
}

use super::{
    canvas_worker_lifecycle_oracle::{await_processors, ProcessorState},
    canvas_worker_range_oracle::observed_worker,
    canvas_worker_renewal_oracle::{
        await_write_failure, install_write_failure, remove_write_probes,
    },
};

struct OutcomeProcessor {
    state: Arc<ProcessorState>,
    release: Arc<Semaphore>,
    outcomes: BTreeMap<String, String>,
}

#[async_trait]
impl CanvasSyncProcessor for OutcomeProcessor {
    fn configured(&self) -> bool {
        true
    }

    async fn process(
        &self,
        target: &CanvasSyncTarget,
        _: &CanvasSyncLease,
    ) -> Result<CanvasSyncResult, CanvasSyncProcessingError> {
        let _active = self.state.enter();
        let outcome = self.outcomes.get(&target.id).expect("seeded matrix target");
        if outcome == "deadline" || outcome == "cancel" {
            return std::future::pending().await;
        }
        self.release.acquire().await.unwrap().forget();
        match outcome.as_str() {
            "success" => {
                canvas_sync_result(json!({"facts_changed": 1}).as_object().unwrap().clone())
            }
            "retry" => Err(CanvasSyncProcessingError::retryable(
                "synthetic_processing_retry",
                "Synthetic processing failure",
            )),
            "terminal" => Err(CanvasSyncProcessingError::terminal(
                "synthetic_processing_terminal",
                "Synthetic processing failure",
            )),
            _ => panic!("unknown frozen outcome: {outcome}"),
        }
    }
}

async fn durable_jobs(pool: &PgPool) -> BTreeMap<String, Value> {
    sqlx::query_as::<_, (String, Value)>(
        "SELECT target_id, to_jsonb(j) FROM issuance_service.canvas_evidence_sync_jobs j ORDER BY target_id"
    ).fetch_all(pool).await.unwrap().into_iter().collect()
}

async fn durable_targets(pool: &PgPool) -> BTreeMap<String, Value> {
    sqlx::query_as::<_, (String, Value)>(
        "SELECT id, to_jsonb(t) FROM issuance_service.canvas_evidence_sync_targets t ORDER BY id",
    )
    .fetch_all(pool)
    .await
    .unwrap()
    .into_iter()
    .collect()
}

async fn change_fence(pool: &PgPool, target: &str, fence: &str) {
    let statement = match fence {
        "unchanged" => return,
        "owner" => "UPDATE issuance_service.canvas_evidence_sync_jobs SET lease_owner = 'another-worker' WHERE target_id = $1",
        "expiry" => "UPDATE issuance_service.canvas_evidence_sync_jobs SET lease_expires_at = clock_timestamp() - interval '1 second' WHERE target_id = $1",
        "attempt" => "UPDATE issuance_service.canvas_evidence_sync_jobs SET attempt_count = attempt_count + 1 WHERE target_id = $1",
        _ => panic!("unobserved fence: {fence}"),
    };
    assert_eq!(
        sqlx::query(statement)
            .bind(target)
            .execute(pool)
            .await
            .unwrap()
            .rows_affected(),
        1
    );
}

pub async fn assert_renewal_job_outcomes(pool: &PgPool) {
    // Preserve real 20s renewal / 30s deadline behavior. Each group owns a
    // separate database: its triggers, TRUNCATEs and heartbeat probes cannot
    // interfere with another group's observations.
    let (lease, target, process) = tokio::join!(
        isolated_group(pool, "lease"),
        isolated_group(pool, "target"),
        isolated_group(pool, "process"),
    );
    // All groups and their cleanup finish before propagating any failed case.
    let counts = [lease, target, process]
        .map(|result| result.unwrap_or_else(|panic| std::panic::resume_unwind(panic)));
    assert_eq!(
        counts.iter().sum::<usize>(),
        60,
        "every frozen renewal/outcome/fence combination must execute"
    );
}

async fn isolated_group(
    admin: &PgPool,
    failed_stage: &str,
) -> Result<usize, Box<dyn std::any::Any + Send>> {
    let database = format!("marty_renewal_{}_test", uuid::Uuid::new_v4().simple());
    assert!(database.starts_with("marty_renewal_") && database.ends_with("_test"));
    assert!(database
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'));
    // SQL identifiers cannot be bound parameters. This identifier consists only
    // of our fixed prefix/suffix and a generated UUID, validated above.
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE DATABASE {database}")))
        .execute(admin)
        .await
        .expect("create isolated renewal test database");
    let options = (*admin.connect_options()).clone().database(&database);
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(6)
        .connect_lazy_with(options);
    let result = std::panic::AssertUnwindSafe(async {
        super::setup_worker_schema(&pool).await;
        assert_group(&pool, failed_stage).await
    })
    .catch_unwind()
    .await;
    pool.close().await;
    // Drop only the uniquely named database created above, never the supplied DB.
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("DROP DATABASE {database}")))
        .execute(admin)
        .await
        .expect("clean up isolated renewal test database");
    result
}

async fn assert_group(pool: &PgPool, failed_stage: &str) -> usize {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/canvas-worker-renewal-job-outcomes.json"
    ))
    .unwrap();
    assert_eq!(
        fixture["schema"],
        "elevenid.canvas-worker-renewal-job-outcomes/v1"
    );
    assert_eq!(
        fixture["worker_blob"],
        "b516ed3d0855f16e9ec899a452a22df49d2cafe5"
    );
    assert_eq!(
        fixture["after_renewal_error"],
        json!({"processor_still_active": true, "job_handler_still_pending": true, "durable_job_status": "leased"})
    );
    assert_eq!(
        fixture["handler_exit_after_processor_termination"],
        "renewal_exception"
    );
    assert_eq!(fixture["processor_cleanup_acknowledged"], true);
    assert_eq!(fixture["cutover_authorized"], false);
    let mut observed_cases = 0;
    assert_eq!(
        fixture["renewal_failures"],
        json!(["lease", "target", "process"])
    );
    for failed_write in fixture["renewal_failures"].as_array().unwrap() {
        let failed_write = failed_write.as_str().unwrap();
        if failed_write != failed_stage {
            continue;
        }
        // Six actual cycles: each write failure with sixteen completing jobs,
        // then four externally cancelled jobs. Grouping only shares real elapsed
        // renewal time; every frozen combination has its own target/job/processor.
        for cancel in [false, true] {
            sqlx::query("TRUNCATE issuance_service.canvas_evidence_sync_jobs, issuance_service.canvas_evidence_sync_targets, issuance_service.canvas_worker_heartbeats").execute(pool).await.unwrap();
            let mut cases = BTreeMap::new();
            for outcome in fixture["processor_outcomes"].as_array().unwrap() {
                let name = outcome["name"].as_str().unwrap();
                if (name == "cancel") != cancel {
                    continue;
                }
                for fence in fixture["durable_fences_before_processor_exit"]
                    .as_array()
                    .unwrap()
                {
                    let fence = fence.as_str().unwrap();
                    let target = format!("outcome-{name}-{fence}");
                    super::seed_target(pool, &target, 900).await;
                    cases.insert(target, (outcome.clone(), fence.to_owned()));
                }
            }
            let count = cases.len();
            assert_eq!(count, if cancel { 4 } else { 16 });
            let config = CanvasSyncWorkerConfig::from_values(&BTreeMap::from([
                ("CANVAS_PORTABLE_INTEGRATION_ENABLED".into(), "true".into()),
                ("CANVAS_PILOT_ORGANIZATION_IDS".into(), "org-1".into()),
                (
                    "CANVAS_SYNC_WORKER_ID".into(),
                    "renewal-outcomes-worker".into(),
                ),
                ("CANVAS_SYNC_WORKER_BATCH_SIZE".into(), "20".into()),
                ("CANVAS_SYNC_WORKER_LEASE_SECONDS".into(), "60".into()),
                ("CANVAS_SYNC_WORKER_JOB_TIMEOUT_SECONDS".into(), "30".into()),
            ]))
            .unwrap();
            assert_eq!(config.lease_renewal_interval(), Duration::from_secs(20));
            assert_eq!(config.job_timeout, Duration::from_secs(30));
            assert!(
                config.enabled_for("org-1"),
                "match the frozen enabled pilot and execute real target validation"
            );
            let state = Arc::new(ProcessorState::default());
            let release = Arc::new(Semaphore::new(0));
            let (worker, _) = observed_worker(
                pool,
                config,
                Arc::new(OutcomeProcessor {
                    state: state.clone(),
                    release: release.clone(),
                    outcomes: cases
                        .iter()
                        .map(|(target, (outcome, _))| {
                            (target.clone(), outcome["name"].as_str().unwrap().to_owned())
                        })
                        .collect(),
                }),
                None,
            );
            let escaped = Arc::new(Mutex::new(Vec::new()));
            let subscriber = tracing_subscriber::registry().with(JobErrors(escaped.clone()));
            let mut cycle = Box::pin(worker.run_cycle().with_subscriber(subscriber));
            await_processors(cycle.as_mut(), &state, count).await;
            install_write_failure(pool, failed_write).await;
            let count_i64 = i64::try_from(count).unwrap();
            let attempts = match failed_write {
                "lease" => [count_i64, 0, 0],
                "target" => [count_i64, count_i64, 0],
                "process" => [count_i64, count_i64, count_i64],
                _ => panic!("unobserved failed write"),
            };
            await_write_failure(cycle.as_mut(), pool, attempts).await;
            assert_eq!(state.active.load(Ordering::SeqCst), count);
            assert_eq!(state.cleaned.load(Ordering::SeqCst), 0);
            for job in durable_jobs(pool).await.values() {
                assert_eq!(job["status"], "leased");
            }
            // Probes must not fail later legitimate outcome writes or the test's
            // durable fence changes. All real renewal operations have stopped.
            remove_write_probes(pool).await;
            for (target, (_, fence)) in &cases {
                change_fence(pool, target, fence).await;
            }
            let before = durable_jobs(pool).await;
            let targets_before = durable_targets(pool).await;
            if cancel {
                drop(cycle);
            } else {
                release.add_permits(count);
                let result = tokio::time::timeout(Duration::from_secs(15), &mut cycle)
                    .await
                    .expect("configured deadlines must finish the cycle")
                    .unwrap();
                assert_eq!((result.scheduled, result.leased), (count, count));
                // Original renewal errors still escape each job after fenced
                // persistence, preserving native exceptional-cycle accounting.
                assert_eq!(
                    (result.succeeded, result.retried, result.dead_lettered),
                    (0, 0, 0)
                );
                drop(cycle);
            }
            // No yield or database read may conceal delayed child cancellation.
            assert_eq!(state.active.load(Ordering::SeqCst), 0);
            assert_eq!(state.cleaned.load(Ordering::SeqCst), count);
            let errors = escaped.lock().unwrap().clone();
            if cancel {
                assert!(
                    errors.is_empty(),
                    "external cancellation must not be masked by renewal failure"
                );
            } else {
                assert_eq!(errors.len(), count);
                let expected_errors: BTreeMap<_, _> = before
                    .values()
                    .map(|job| {
                        (
                            job["id"].as_str().unwrap().to_owned(),
                            "CanvasSyncRepositoryUnavailable".to_owned(),
                        )
                    })
                    .collect();
                assert_eq!(errors.into_iter().collect::<BTreeMap<_, _>>(), expected_errors,
                    "every actual handler must surface its original renewal error after persistence");
            }
            let after = durable_jobs(pool).await;
            let targets_after = durable_targets(pool).await;
            assert_eq!(after.len(), count);
            for (target, (outcome, fence)) in &cases {
                let expected = if fence == "unchanged" {
                    outcome
                } else {
                    &fixture["fenced_outcome"]
                };
                let job = &after[target];
                assert_eq!(
                    job["status"], expected["durable_status"],
                    "{failed_write}/{target}"
                );
                assert_eq!(
                    !job["completed_at"].is_null(),
                    expected["completed"].as_bool().unwrap(),
                    "{failed_write}/{target}"
                );
                assert_eq!(
                    job["last_error_code"], expected["error_code"],
                    "{failed_write}/{target}"
                );
                if fence != "unchanged" || cancel {
                    assert_eq!(
                        job, &before[target],
                        "stale or cancelled job changed: {failed_write}/{target}"
                    );
                    assert_eq!(
                        targets_after[target], targets_before[target],
                        "stale or cancelled target changed: {failed_write}/{target}"
                    );
                } else if outcome["name"] == "success" {
                    assert_eq!(job["result"], json!({"facts_changed": 1}));
                }
                observed_cases += 1;
                eprintln!("native PostgreSQL renewal outcome PASS: {failed_write}/{target}");
            }
        }
    }
    assert_eq!(
        observed_cases, 20,
        "every frozen outcome/fence combination for this write must execute"
    );
    observed_cases
}
