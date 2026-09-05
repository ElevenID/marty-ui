//! Observe actual SQL and worker entry points; never replace the cycle or loop.
//! The frozen corpus covers empty queues, not active-job processing.

use std::{
    collections::BTreeMap,
    future::Future,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use marty_issuance_service::{
    canvas_oauth::{
        CanvasOAuthAuthorization, CanvasOAuthConnection, CanvasOAuthError, CanvasOAuthPlatform,
        CanvasOAuthPlatformPatch, CanvasOAuthRepository,
    },
    canvas_oauth_http::HttpCanvasOAuthProvider,
    canvas_oauth_postgres::{PostgresCanvasOAuthRepository, PostgresIntegrationSecretVault},
    canvas_sync_worker::{
        CanvasSyncJob, CanvasSyncJobStatus, CanvasSyncProcessingError, CanvasSyncProcessor,
        CanvasSyncRepositoryError, CanvasSyncResult, CanvasSyncTarget, CanvasSyncWorker,
        CanvasSyncWorkerConfig, CanvasSyncWorkerCycleResult, CanvasSyncWorkerRepository,
        JobFailure, WorkerHeartbeat,
    },
    canvas_sync_worker_postgres::PostgresCanvasSyncWorkerRepository,
    integration_secret::IntegrationSecretCipher,
};
use mmf_config::numeric_config::PythonConfigInteger;
use serde_json::{json, Value};
use sqlx::PgPool;
use tokio::sync::watch;

fn category(error: &CanvasSyncRepositoryError) -> &'static str {
    match error {
        CanvasSyncRepositoryError::IntegerSqlRange => "integer_sql_range",
        CanvasSyncRepositoryError::DurationRange => "duration_range",
        CanvasSyncRepositoryError::Unavailable => "unavailable",
        CanvasSyncRepositoryError::InvalidState => "invalid_state",
    }
}

pub(super) struct ObservedRepositories {
    worker: PostgresCanvasSyncWorkerRepository,
    oauth: PostgresCanvasOAuthRepository,
    events: Mutex<Vec<Value>>,
    cycles: AtomicUsize,
    stop: Option<(usize, watch::Sender<bool>)>,
}

impl ObservedRepositories {
    fn record(&self, event: Value) {
        self.events.lock().unwrap().push(event);
    }

    async fn observe<T>(
        &self,
        phase: &str,
        operation: impl Future<Output = Result<T, CanvasSyncRepositoryError>>,
        count: impl FnOnce(&T) -> usize,
    ) -> Result<T, CanvasSyncRepositoryError> {
        self.record(json!({"phase": phase, "event": "start"}));
        let result = operation.await;
        match &result {
            Ok(rows) => {
                self.record(json!({"phase": phase, "event": "complete", "row_count": count(rows)}))
            }
            Err(error) => {
                self.record(json!({"phase": phase, "event": "error", "category": category(error)}))
            }
        }
        result
    }
}

// Keep unobserved operations as direct forwarding calls. In particular, no
// default empty OAuth implementation may stand in for the actual queue query.
macro_rules! worker_repository {
    ($(fn $method:ident($($arg:ident: $ty:ty),*) -> $result:ty;)*) => {
        #[async_trait]
        impl CanvasSyncWorkerRepository for ObservedRepositories {
            async fn upsert_heartbeat(&self, heartbeat: &WorkerHeartbeat) -> Result<(), CanvasSyncRepositoryError> {
                self.record(json!({"phase": "heartbeat", "event": heartbeat.phase}));
                if heartbeat.phase == "scheduling" {
                    let cycle = self.cycles.fetch_add(1, Ordering::SeqCst) + 1;
                    if let Some((stop_after, sender)) = &self.stop {
                        if cycle == *stop_after {
                            sender.send(true).expect("owned loop stop receiver");
                        }
                    }
                }
                self.worker.upsert_heartbeat(heartbeat).await
            }

            async fn enqueue_due(&self, limit: &PythonConfigInteger) -> Result<usize, CanvasSyncRepositoryError> {
                self.observe("scheduling", self.worker.enqueue_due(limit), |count| *count).await
            }

            async fn lease_ready(&self, worker_id: &str, limit: &PythonConfigInteger, lease_seconds: &PythonConfigInteger) -> Result<Vec<CanvasSyncJob>, CanvasSyncRepositoryError> {
                self.observe("leasing", self.worker.lease_ready(worker_id, limit, lease_seconds), Vec::len).await
            }

            $(async fn $method(&self, $($arg: $ty),*) -> $result {
                self.worker.$method($($arg),*).await
            })*
        }
    };
}

worker_repository! {
    fn target(organization_id: &str, target_id: &str) -> Result<Option<CanvasSyncTarget>, CanvasSyncRepositoryError>;
    fn touch_target_heartbeat(target: &CanvasSyncTarget, worker_id: &str) -> Result<bool, CanvasSyncRepositoryError>;
    fn validate_target(target: &CanvasSyncTarget) -> Result<(), CanvasSyncProcessingError>;
    fn renew_lease(job: &CanvasSyncJob, worker_id: &str, lease_seconds: &PythonConfigInteger) -> Result<bool, CanvasSyncRepositoryError>;
    fn complete_job(job: &CanvasSyncJob, worker_id: &str, target_config_version: i32, result: &CanvasSyncResult) -> Result<bool, CanvasSyncRepositoryError>;
    fn fail_job(job: &CanvasSyncJob, worker_id: &str, failure: &JobFailure<'_>, target_config_version: i32) -> Result<Option<CanvasSyncJobStatus>, CanvasSyncRepositoryError>;
}

macro_rules! oauth_repository {
    ($(fn $method:ident($($arg:ident: $ty:ty),*) -> $result:ty;)*) => {
        #[async_trait]
        impl CanvasOAuthRepository for ObservedRepositories {
            async fn due_revocations(&self, limit: usize) -> Result<Vec<CanvasOAuthConnection>, CanvasOAuthError> {
                assert!((1..=500).contains(&limit), "bound before machine conversion");
                self.record(json!({"phase": "oauth_queue", "event": "start"}));
                let result = self.oauth.due_revocations(limit).await;
                match &result {
                    Ok(rows) => self.record(json!({"phase": "oauth_queue", "event": "complete", "row_count": rows.len()})),
                    Err(_) => self.record(json!({"phase": "oauth_queue", "event": "error"})),
                }
                result
            }
            $(async fn $method(&self, $($arg: $ty),*) -> $result {
                self.oauth.$method($($arg),*).await
            })*
        }
    };
}

oauth_repository! {
    fn acquire_due_revocation(organization_id: &str, platform_id: &str, lease_owner: &str, lease_seconds: i64) -> Result<Option<CanvasOAuthConnection>, CanvasOAuthError>;
    fn management_platform(organization_id: &str, platform_id: &str) -> Result<Option<CanvasOAuthPlatform>, CanvasOAuthError>;
    fn callback_platform(platform_id: &str) -> Result<Option<CanvasOAuthPlatform>, CanvasOAuthError>;
    fn connection(organization_id: &str, platform_id: &str) -> Result<Option<CanvasOAuthConnection>, CanvasOAuthError>;
    fn save_authorization(authorization: &CanvasOAuthAuthorization) -> Result<(), CanvasOAuthError>;
    fn consume_authorization(state_hash: &str, now: DateTime<Utc>) -> Result<Option<CanvasOAuthAuthorization>, CanvasOAuthError>;
    fn patch_platform(organization_id: &str, platform_id: &str, expected_config_version: i64, patch: CanvasOAuthPlatformPatch) -> Result<bool, CanvasOAuthError>;
    fn patch_validation(organization_id: &str, platform_id: &str, expected_config_version: i64, validated_at: Option<DateTime<Utc>>, error_code: Option<&str>) -> Result<bool, CanvasOAuthError>;
    fn publish_connection(connection: &CanvasOAuthConnection) -> Result<Option<DateTime<Utc>>, CanvasOAuthError>;
    fn mark_reauthorization_required(organization_id: &str, platform_id: &str, expected_updated_at: DateTime<Utc>) -> Result<bool, CanvasOAuthError>;
    fn acquire_refresh_lease(organization_id: &str, platform_id: &str, lease_owner: &str, lease_seconds: i64) -> Result<Option<CanvasOAuthConnection>, CanvasOAuthError>;
    fn complete_refresh(organization_id: &str, platform_id: &str, lease_owner: &str, access_token_secret_ref: &str, refresh_token_secret_ref: Option<&str>, token_expires_at: Option<DateTime<Utc>>) -> Result<Option<DateTime<Utc>>, CanvasOAuthError>;
    fn release_refresh_lease(organization_id: &str, platform_id: &str, lease_owner: &str, reauthorization_required: bool) -> Result<bool, CanvasOAuthError>;
    fn patch_validation_error(organization_id: &str, platform_id: &str, expected_config_version: i64, error_code: Option<&str>) -> Result<bool, CanvasOAuthError>;
    fn begin_revocation(organization_id: &str, platform_id: &str, expected_updated_at: DateTime<Utc>, lease_owner: &str, lease_seconds: i64) -> Result<Option<CanvasOAuthConnection>, CanvasOAuthError>;
    fn reschedule_revocation(organization_id: &str, platform_id: &str, lease_owner: &str, retry_at: DateTime<Utc>, error_code: &str) -> Result<bool, CanvasOAuthError>;
    fn complete_revocation(organization_id: &str, platform_id: &str, lease_owner: &str, secret_ids: &[String]) -> Result<bool, CanvasOAuthError>;
}

struct NoJobsExpected;

#[async_trait]
impl CanvasSyncProcessor for NoJobsExpected {
    fn configured(&self) -> bool {
        false
    }

    async fn process(
        &self,
        _: &CanvasSyncTarget,
        _: &marty_issuance_service::canvas_sync_lease::CanvasSyncLease,
    ) -> Result<CanvasSyncResult, CanvasSyncProcessingError> {
        panic!("empty-queue corpus must never invoke a job processor");
    }
}

fn expected_events(outcome: &Value) -> Vec<Value> {
    outcome["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|event| {
            if event["event"] != "error" {
                return event.clone();
            }
            let mut portable = event.as_object().unwrap().clone();
            let legacy = json!({
                "class": portable.remove("class").expect("observed exception class"),
                "driver_class": portable.remove("driver_class").expect("observed driver class"),
                "sqlstate": portable.remove("sqlstate").expect("observed SQL state"),
            });
            let category = match legacy["class"].as_str().unwrap() {
                "OverflowError" => {
                    assert_eq!(
                        legacy,
                        json!({"class": "OverflowError", "driver_class": null, "sqlstate": null})
                    );
                    "duration_range"
                }
                "DBAPIError" => {
                    assert_eq!(
                        legacy,
                        json!({"class": "DBAPIError", "driver_class": "Error", "sqlstate": "22000"})
                    );
                    "integer_sql_range"
                }
                unexpected => panic!("unmapped frozen error class: {unexpected}"),
            };
            assert_eq!(legacy, outcome["legacy_error"]);
            assert_eq!(category, outcome["category"].as_str().unwrap());
            portable.insert("category".into(), json!(category));
            Value::Object(portable)
        })
        .collect()
}

fn worker(
    pool: &PgPool,
    fixture: &Value,
    case: &Value,
    stop: Option<(usize, watch::Sender<bool>)>,
) -> (CanvasSyncWorker, Arc<ObservedRepositories>) {
    let field = case["field"].as_str().unwrap();
    let input = case["input"].as_str().unwrap();
    let config = CanvasSyncWorkerConfig::from_values(&BTreeMap::from([
        (
            "CANVAS_SYNC_WORKER_ID".to_owned(),
            "range-oracle-worker".to_owned(),
        ),
        (
            "CANVAS_SYNC_WORKER_POLL_SECONDS".to_owned(),
            "0.1".to_owned(),
        ),
        (
            fixture["fields"][field].as_str().unwrap().to_owned(),
            fixture["inputs"][input].as_str().unwrap().to_owned(),
        ),
    ]))
    .expect("frozen accepted configuration");
    observed_worker(pool, config, Arc::new(NoJobsExpected), stop)
}

pub(super) fn observed_worker(
    pool: &PgPool,
    config: CanvasSyncWorkerConfig,
    processor: Arc<dyn CanvasSyncProcessor>,
    stop: Option<(usize, watch::Sender<bool>)>,
) -> (CanvasSyncWorker, Arc<ObservedRepositories>) {
    let observed = Arc::new(ObservedRepositories {
        worker: PostgresCanvasSyncWorkerRepository::new(pool.clone()),
        oauth: PostgresCanvasOAuthRepository::new(pool.clone()),
        events: Mutex::new(Vec::new()),
        cycles: AtomicUsize::new(0),
        stop,
    });
    let cipher =
        IntegrationSecretCipher::from_base64("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=")
            .unwrap();
    (
        CanvasSyncWorker::new(
            observed.clone(),
            observed.clone(),
            Arc::new(PostgresIntegrationSecretVault::new(pool.clone(), cipher)),
            Arc::new(HttpCanvasOAuthProvider::new(
                Duration::from_secs(1),
                Vec::new(),
                false,
            )),
            processor,
            config,
        ),
        observed,
    )
}

pub async fn assert_consumer_ranges(pool: &PgPool) {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/canvas-worker-consumer-range-oracle.json"
    ))
    .unwrap();
    assert_eq!(
        fixture["schema"],
        "elevenid.canvas-worker-consumer-range-oracle/v1"
    );
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 36);
    for case in cases {
        let expected = &fixture["outcomes"][case["expected"].as_str().unwrap()];
        assert_eq!(expected["configuration"], "accepted");
        let (worker, observed) = worker(pool, &fixture, case, None);
        let result = worker.run_cycle().await;
        match expected["cycle"].as_str().unwrap() {
            "completed" => assert_eq!(result, Ok(CanvasSyncWorkerCycleResult::default()), "{case}"),
            "error" => assert_eq!(
                category(&result.expect_err("frozen range failure")),
                expected["category"].as_str().unwrap(),
                "{case}"
            ),
            unexpected => panic!("unknown frozen cycle outcome: {unexpected}"),
        }
        assert_eq!(
            *observed.events.lock().unwrap(),
            expected_events(expected),
            "{case}"
        );
        assert_eq!(observed.cycles.load(Ordering::SeqCst), 1);
    }

    let loops = fixture["loop_cases"].as_array().unwrap();
    assert_eq!(loops.len(), 3);
    for case in loops {
        let cycles = usize::try_from(case["cycles"].as_u64().unwrap()).unwrap();
        assert_eq!(cycles, 2);
        assert_eq!(case["stopped_normally"], true);
        let (sender, receiver) = watch::channel(false);
        let (worker, observed) = worker(pool, &fixture, case, Some((cycles, sender)));
        tokio::time::timeout(Duration::from_secs(10), worker.run_loop(receiver))
            .await
            .expect("actual loop must honor its owned stop signal")
            .expect("actual loop must survive both consumer failures");
        assert_eq!(observed.cycles.load(Ordering::SeqCst), cycles, "{case}");
        assert!(*observed.stop.as_ref().unwrap().1.borrow());
        let events =
            expected_events(&fixture["outcomes"][case["cycle_events_from"].as_str().unwrap()]);
        let expected: Vec<Value> = (0..cycles).flat_map(|_| events.iter().cloned()).collect();
        assert_eq!(*observed.events.lock().unwrap(), expected, "{case}");
    }
    eprintln!("native PostgreSQL range oracle: 36 cycles and 3 two-cycle loops passed");
}
