//! Hardened-reference log/state replay through actual native cycles and SQL.
//! Repository failures, processor outcomes and revocation responses are controlled;
//! worker scheduling, persistence, lease handling and encrypted cleanup are real.

use std::{
    collections::BTreeMap,
    future::Future,
    io::{self, Write},
    panic::AssertUnwindSafe,
    sync::{atomic::Ordering, Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use futures_util::FutureExt;
use marty_issuance_service::{
    canvas_oauth::{
        CanvasOAuthProvider, CanvasOAuthProviderError, CanvasOAuthSecretVault,
        CanvasOAuthTokenBundle,
    },
    canvas_sync_lease::CanvasSyncLease,
    canvas_sync_worker::{
        canvas_sync_result, CanvasSyncProcessingError, CanvasSyncProcessor, CanvasSyncResult,
        CanvasSyncTarget, CanvasSyncWorkerConfig, CanvasSyncWorkerCycleResult,
        UnexpectedCanvasSyncFailure,
    },
    integration_secret::NewIntegrationSecret,
};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tokio::sync::watch;
use tracing::{instrument::WithSubscriber, Instrument};
use tracing_subscriber::{layer::SubscriberExt, Layer};

use super::canvas_worker_range_oracle::{
    observed_vault, observed_worker_with_fault, RepositoryFault,
};

const TARGET: &str = "marty_issuance_service::canvas_sync_worker";
const REFERENCE: &str =
    include_str!("../../../../../contracts/canvas-worker-privacy-reference.json");

#[tokio::test]
async fn privacy_observer_does_not_discard_unexpected_fields_or_exception_metadata() {
    let reference: Value = serde_json::from_str(REFERENCE).unwrap();
    let expected = &reference["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["input"]["branch"] == "cycle_failure")
        .unwrap()["observed"]["log"];
    for ambient in [false, true] {
        let ((), logs) = observe(
            async {
                tracing::error!(
                    target: TARGET,
                    event = "canvas_sync_cycle_failed",
                    exception_class = "CanvasSyncRepositoryUnavailable",
                    unexpected_field = "synthetic-private-detail",
                    error = "synthetic-exception-object",
                    backtrace = "synthetic-stack",
                    "Canvas synchronization worker cycle failed"
                );
            },
            ambient,
        )
        .await;
        let actual = portable_log(logs, ambient, None, "CanvasSyncRepositoryUnavailable");
        assert_eq!(
            actual["fields"]["unexpected_field"],
            "synthetic-private-detail"
        );
        assert_eq!(actual["rendered"]["error"], "synthetic-exception-object");
        assert_eq!(actual["rendered"]["backtrace"], "synthetic-stack");
        assert_eq!(actual["exception_attached"], true);
        assert_eq!(actual["stack_attached"], true);
        assert_ne!(
            &actual, expected,
            "the real parity comparison must reject leaked metadata"
        );
    }
}

#[derive(Clone, Default)]
struct Logs {
    events: Arc<Mutex<Vec<Value>>>,
    rendered: Arc<Mutex<Vec<u8>>>,
}

#[derive(Default)]
struct Fields(Map<String, Value>);

impl tracing::field::Visit for Fields {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0.insert(field.name().to_owned(), json!(value));
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.record_str(field, &format!("{value:?}"));
    }
}

impl<S: tracing::Subscriber> Layer<S> for Logs {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        if event.metadata().target() == TARGET {
            let mut fields = Fields::default();
            event.record(&mut fields);
            self.events.lock().unwrap().push(json!({
                "level": event.metadata().level().as_str(), "fields": fields.0,
            }));
        }
    }
}

impl Write for Logs {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.rendered.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

async fn observe<F: Future>(future: F, ambient: bool) -> (F::Output, Logs) {
    let logs = Logs::default();
    let writer = logs.clone();
    let formatter = tracing_subscriber::fmt::layer()
        .json()
        .without_time()
        .with_writer(move || writer.clone())
        .with_filter(tracing_subscriber::filter::filter_fn(|metadata| {
            metadata.is_span() || metadata.target() == TARGET
        }));
    let subscriber = tracing_subscriber::registry()
        .with(logs.clone())
        .with(formatter);
    let result = async {
        if ambient {
            future
                .instrument(tracing::info_span!(
                    "privacy_context",
                    request_id = "synthetic-correlation"
                ))
                .await
        } else {
            future.await
        }
    }
    .with_subscriber(subscriber)
    .await;
    (result, logs)
}

fn portable_log(logs: Logs, ambient: bool, job_id: Option<&str>, native_class: &str) -> Value {
    let events = logs.events.lock().unwrap();
    assert_eq!(
        events.len(),
        1,
        "exactly one producer event, not selected fields/events"
    );
    let raw = String::from_utf8(logs.rendered.lock().unwrap().clone()).unwrap();
    let rendered: Vec<Value> = raw
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(rendered.len(), 1, "exactly one downstream rendered event");
    let mut envelope = rendered[0].as_object().unwrap().clone();
    assert_eq!(envelope.remove("level").unwrap(), events[0]["level"]);
    assert_eq!(envelope.remove("target").unwrap(), TARGET);
    assert_eq!(envelope.remove("fields").unwrap(), events[0]["fields"]);
    if ambient {
        let span = json!({"name": "privacy_context", "request_id": "synthetic-correlation"});
        assert_eq!(envelope.remove("span").unwrap(), span);
        assert_eq!(envelope.remove("spans").unwrap(), json!([span]));
    }
    assert!(
        envelope.is_empty(),
        "unexpected downstream metadata: {envelope:?}"
    );

    let mut fields = events[0]["fields"].as_object().unwrap().clone();
    let message = fields
        .remove("message")
        .expect("actual static worker message");
    // Explicit language mapping: each injected failure uses its exact native,
    // payload-free category, never an exception-object string.
    assert_eq!(fields["exception_class"], native_class);
    fields.insert(
        "exception_class".into(),
        json!(reference_class(native_class)),
    );
    if let Some(job_id) = job_id {
        assert_eq!(
            fields["job_id"], job_id,
            "normalize only the actual failed job ID"
        );
        fields.insert("job_id".into(), json!("<matching-job-id>"));
    }
    let exception_attached = fields.contains_key("error") || fields.contains_key("exception");
    let stack_attached = fields.contains_key("stack") || fields.contains_key("backtrace");
    let mut rendered = fields.clone();
    rendered.insert("message".into(), message);
    json!({
        "level": events[0]["level"], "fields": fields, "rendered": rendered,
        "exception_attached": exception_attached, "stack_attached": stack_attached,
    })
}

struct SuccessfulSibling;

fn reference_class(native_class: &str) -> &'static str {
    match native_class {
        "CanvasSyncRepositoryUnavailable"
        | "CanvasOAuthRepositoryUnavailable"
        | "CanvasSyncUnexpectedError" => "RuntimeError",
        "CanvasSyncHttpStatusError" => "HTTPStatusError",
        other => panic!("unmapped native privacy category {other}"),
    }
}

struct FailedProcessor(CanvasSyncProcessingError);

#[async_trait]
impl CanvasSyncProcessor for FailedProcessor {
    fn configured(&self) -> bool {
        true
    }

    async fn process(
        &self,
        _: &CanvasSyncTarget,
        _: &CanvasSyncLease,
    ) -> Result<CanvasSyncResult, CanvasSyncProcessingError> {
        Err(self.0.clone())
    }
}

fn cycle_observation(result: &CanvasSyncWorkerCycleResult) -> Value {
    json!({"scheduled": result.scheduled, "leased": result.leased,
        "succeeded": result.succeeded, "retried": result.retried,
        "dead_lettered": result.dead_lettered,
        "oauth_revocations_succeeded": result.oauth_revocations_succeeded,
        "oauth_revocations_retried": result.oauth_revocations_retried})
}

async fn processing_observation(
    pool: &PgPool,
    mut config: CanvasSyncWorkerConfig,
    ambient: bool,
    case: &Value,
) -> Value {
    config.portable_enabled = true;
    config.pilot_organizations.insert("org-1".into());
    let worker_id = config.worker_id.clone();
    let (kind, native_class) = if case["input"]["status"].is_null() {
        (
            UnexpectedCanvasSyncFailure::Runtime,
            "CanvasSyncUnexpectedError",
        )
    } else {
        (
            UnexpectedCanvasSyncFailure::HttpStatus(
                http::StatusCode::from_u16(
                    u16::try_from(case["input"]["status"].as_u64().unwrap()).unwrap(),
                )
                .unwrap(),
            ),
            "CanvasSyncHttpStatusError",
        )
    };
    super::seed_target(pool, "privacy-processing", 900).await;
    let mut failure = CanvasSyncProcessingError::unexpected(kind);
    // Existing public diagnostic fields cannot bypass the unexpected policy.
    // The category itself has no place to carry a body, credential or message.
    failure.code = "synthetic-unexpected-detail-must-not-persist";
    failure.summary = "synthetic-unexpected-detail-must-not-persist";
    failure.retryable = false;
    let (worker, _) = observed_worker_with_fault(
        pool,
        config,
        Arc::new(FailedProcessor(failure)),
        None,
        None,
        None,
    );
    let (result, logs) = observe(worker.run_cycle(), ambient).await;
    let result = result.unwrap();
    let (job, enabled): (Value, bool) = sqlx::query_as(
        "SELECT to_jsonb(j), t.enabled FROM issuance_service.canvas_evidence_sync_jobs j
         JOIN issuance_service.canvas_evidence_sync_targets t ON t.id = j.target_id",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    let mut projected = job_observation(&job, &worker_id, None);
    // Only the native type label is translated. Assert the entire native
    // static summary before mapping; never conceal arbitrary diagnostic text.
    assert_eq!(
        projected["error_summary"],
        format!("Canvas synchronization failed ({native_class})")
    );
    projected["error_summary"] = json!(format!(
        "Canvas synchronization failed ({})",
        reference_class(native_class)
    ));
    json!({
        "cycle": cycle_observation(&result), "job": projected, "target_enabled": enabled,
        "log": portable_log(logs, ambient, Some(job["id"].as_str().unwrap()), native_class),
    })
}

#[derive(Default)]
struct ObservedRevoker(Mutex<Vec<String>>);

#[async_trait]
impl CanvasOAuthProvider for ObservedRevoker {
    async fn exchange(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: &str,
        _: &str,
    ) -> Result<CanvasOAuthTokenBundle, CanvasOAuthProviderError> {
        panic!("disconnect reference must not exchange a token")
    }

    async fn refresh(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: &str,
    ) -> Result<CanvasOAuthTokenBundle, CanvasOAuthProviderError> {
        panic!("disconnect reference must not refresh a token")
    }

    async fn revoke(
        &self,
        canvas_base_url: &str,
        access_token: &str,
    ) -> Result<(), CanvasOAuthProviderError> {
        assert_eq!(canvas_base_url, "https://canvas.example.invalid");
        self.0.lock().unwrap().push(access_token.to_owned());
        Ok(())
    }
}

async fn disconnect_observation(
    pool: &PgPool,
    config: CanvasSyncWorkerConfig,
    ambient: bool,
) -> Value {
    let vault = observed_vault(pool);
    for (id, organization, value) in [
        ("access-secret-1", "org-1", "access-token-value"),
        ("refresh-secret-1", "org-1", "refresh-token-value"),
        (
            "retained-control-secret",
            "org-2",
            "synthetic-retained-control",
        ),
    ] {
        vault
            .save(NewIntegrationSecret {
                id: id.to_owned(),
                organization_id: organization.to_owned(),
                name: id.to_owned(),
                provider: "canvas".into(),
                purpose: "privacy-test".into(),
                value: value.to_owned(),
                metadata: json!({}),
            })
            .await
            .unwrap();
        assert_eq!(
            vault.value(organization, id).await.unwrap().as_deref(),
            Some(value)
        );
    }
    sqlx::query(
        "INSERT INTO issuance_service.canvas_platforms VALUES ('oauth-platform-1', 'org-1', true, NULL, 1)"
    ).execute(pool).await.unwrap();
    sqlx::query(
        "INSERT INTO issuance_service.canvas_oauth_connections
        (id, organization_id, platform_id, canvas_base_url, platform_config_version, client_id,
         client_secret_ref, capabilities, scopes, access_token_secret_ref, refresh_token_secret_ref,
         status, revoke_retry_count, updated_at)
        VALUES ('privacy-oauth', 'org-1', 'oauth-platform-1', 'https://canvas.example.invalid', 1,
         'synthetic-client', 'org_secret://org-1/client-secret', '[]', '[]',
         'org_secret://org-1/access-secret-1', 'org_secret://org-1/refresh-secret-1',
         'revocation_pending', 0, clock_timestamp())",
    )
    .execute(pool)
    .await
    .unwrap();
    let revoker = Arc::new(ObservedRevoker::default());
    let (worker, observed) = observed_worker_with_fault(
        pool,
        config,
        Arc::new(SuccessfulSibling),
        None,
        Some(RepositoryFault::DisconnectMarker),
        Some(revoker.clone()),
    );
    let (result, logs) = observe(worker.run_cycle(), ambient).await;
    let result = result.unwrap();
    assert_eq!(
        (
            result.scheduled,
            result.leased,
            result.succeeded,
            result.retried,
            result.dead_lettered
        ),
        (0, 0, 0, 0, 0),
        "revocation must not create or alter background jobs"
    );
    assert_eq!(observed.phase_events("disconnect_marker"), ["failure"]);
    assert_eq!(*revoker.0.lock().unwrap(), ["access-token-value"]);
    assert_eq!(
        vault
            .value("org-2", "retained-control-secret")
            .await
            .unwrap()
            .as_deref(),
        Some("synthetic-retained-control"),
        "cleanup must retain the other tenant's secret"
    );
    let remaining: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM issuance_service.canvas_oauth_connections WHERE organization_id = 'org-1' AND platform_id = 'oauth-platform-1'"
    ).fetch_one(pool).await.unwrap();
    let raw_logs = String::from_utf8(logs.rendered.lock().unwrap().clone()).unwrap();
    for secret in [
        "access-token-value",
        "refresh-token-value",
        "synthetic-retained-control",
    ] {
        assert!(
            !raw_logs.contains(secret),
            "rendered worker log leaked a synthetic secret"
        );
    }
    json!({
        "succeeded": result.oauth_revocations_succeeded, "retried": result.oauth_revocations_retried,
        "remote_revoke_count": revoker.0.lock().unwrap().len(), "connection_absent": remaining == 0,
        "secrets_absent": {
            "access-secret-1": vault.value("org-1", "access-secret-1").await.unwrap().is_none(),
            "refresh-secret-1": vault.value("org-1", "refresh-secret-1").await.unwrap().is_none(),
        },
        "log": portable_log(logs, ambient, None, "CanvasOAuthRepositoryUnavailable"),
    })
}

#[async_trait]
impl CanvasSyncProcessor for SuccessfulSibling {
    fn configured(&self) -> bool {
        true
    }

    async fn process(
        &self,
        _: &CanvasSyncTarget,
        _: &CanvasSyncLease,
    ) -> Result<CanvasSyncResult, CanvasSyncProcessingError> {
        canvas_sync_result(json!({"facts_changed": 1}).as_object().unwrap().clone())
    }
}

fn job_observation(job: &Value, worker: &str, internal_generation: Option<i32>) -> Value {
    let mut result = job["result"].clone();
    if let Some(generation) = internal_generation {
        // PostgreSQL retains a private lease-generation fence that the
        // reference's in-memory repository does not store. Prove its exact
        // value before projecting business result; never remove the SQL fence.
        assert_eq!(result, json!({"target_config_version": generation}));
        result
            .as_object_mut()
            .unwrap()
            .remove("target_config_version");
    }
    json!({
        "status": job["status"], "attempt_count": job["attempt_count"],
        "max_attempts": job["max_attempts"], "error_code": job["last_error_code"],
        "error_summary": job["last_error_summary"], "result": result,
        "completed": !job["completed_at"].is_null(), "lease_owned": job["lease_owner"] == worker,
        "lease_released": job["lease_owner"].is_null() && job["lease_expires_at"].is_null(),
    })
}

async fn assert_case(pool: &PgPool, case: &Value) {
    super::setup_worker_schema(pool).await;
    let mode = case["id"].as_str().unwrap().rsplit_once('[').unwrap().1;
    let ambient = if mode.starts_with("ambient-correlation") {
        true
    } else {
        assert!(
            mode.starts_with("standalone"),
            "unmapped reference correlation mode"
        );
        false
    };
    let worker_id = "canvas-worker-1";
    let config = CanvasSyncWorkerConfig::from_values(&BTreeMap::from([
        ("CANVAS_SYNC_WORKER_ID".to_owned(), worker_id.to_owned()),
        (
            "CANVAS_SYNC_WORKER_POLL_SECONDS".to_owned(),
            "0.1".to_owned(),
        ),
    ]))
    .unwrap();
    let actual = match case["input"]["branch"].as_str().unwrap() {
        "escaped_job" => {
            super::seed_target(pool, "privacy-failed", 900).await;
            super::seed_target(pool, "privacy-sibling", 900).await;
            let (worker, _) = observed_worker_with_fault(
                pool,
                config,
                Arc::new(SuccessfulSibling),
                None,
                Some(RepositoryFault::Target("privacy-failed".into())),
                None,
            );
            let (result, logs) = observe(worker.run_cycle(), ambient).await;
            let result = result.unwrap();
            let jobs: BTreeMap<String, Value> = sqlx::query_as::<_, (String, Value)>(
                "SELECT target_id, to_jsonb(j) FROM issuance_service.canvas_evidence_sync_jobs j",
            )
            .fetch_all(pool)
            .await
            .unwrap()
            .into_iter()
            .collect();
            assert_eq!(jobs.len(), 2);
            let failed = &jobs["privacy-failed"];
            let generation: i32 = sqlx::query_scalar(
                "SELECT config_version FROM issuance_service.canvas_evidence_sync_targets WHERE id = 'privacy-failed'"
            ).fetch_one(pool).await.unwrap();
            json!({
            "cycle": cycle_observation(&result),
            "failed_job": job_observation(failed, worker_id, Some(generation)),
            "sibling_job": job_observation(&jobs["privacy-sibling"], worker_id, None),
                "log": portable_log(logs, ambient, Some(failed["id"].as_str().unwrap()), "CanvasSyncRepositoryUnavailable"),
            })
        }
        "cycle_failure" => {
            let (sender, stop) = watch::channel(false);
            let (worker, observed) = observed_worker_with_fault(
                pool,
                config,
                Arc::new(SuccessfulSibling),
                Some((2, sender)),
                Some(RepositoryFault::FirstOAuthQueueRead),
                None,
            );
            let (result, logs) = observe(worker.run_loop(stop), ambient).await;
            result.unwrap();
            assert_eq!(
                observed.phase_events("scheduling"),
                ["start", "complete"],
                "the failed OAuth queue read must not continue into scheduling"
            );
            assert_eq!(
                observed.phase_events("heartbeat"),
                ["scheduling", "scheduling", "idle", "idle"],
                "only the recovered empty cycle writes its post-lease and final idle heartbeats"
            );
            let (identity, metadata): (String, Value) = sqlx::query_as(
                "SELECT worker_id, metadata FROM issuance_service.canvas_worker_heartbeats",
            )
            .fetch_one(pool)
            .await
            .unwrap();
            json!({
                "cycle_attempts": observed.oauth_reads.load(Ordering::SeqCst),
                "heartbeat_phase": metadata["phase"], "worker_id": identity,
                "log": portable_log(logs, ambient, None, "CanvasSyncRepositoryUnavailable"),
            })
        }
        "disconnect_marker" => disconnect_observation(pool, config, ambient).await,
        "processing" => processing_observation(pool, config, ambient, case).await,
        other => panic!("unmapped privacy branch {other}"),
    };
    assert_eq!(actual, case["observed"], "{}", case["id"]);
    eprintln!("native hardened privacy replay PASS: {}", case["id"]);
}

async fn assert_classified_errors_unchanged(pool: &PgPool) {
    for failure in [
        CanvasSyncProcessingError::retryable(
            "canvas_rate_limited",
            "Canvas background evidence could not be read",
        ),
        CanvasSyncProcessingError::terminal(
            "canvas_requirements_invalid",
            "Canvas evidence requirements are invalid",
        ),
    ] {
        super::setup_worker_schema(pool).await;
        super::seed_target(pool, "classified-control", 900).await;
        assert!(failure.unexpected.is_none());
        let mut config = CanvasSyncWorkerConfig::from_values(&BTreeMap::new()).unwrap();
        config.portable_enabled = true;
        config.pilot_organizations.insert("org-1".into());
        let (worker, _) = observed_worker_with_fault(
            pool,
            config,
            Arc::new(FailedProcessor(failure.clone())),
            None,
            None,
            None,
        );
        let (result, logs) = observe(worker.run_cycle(), true).await;
        let result = result.unwrap();
        assert_eq!(
            (result.scheduled, result.leased, result.succeeded),
            (1, 1, 0)
        );
        assert_eq!(
            (result.retried, result.dead_lettered),
            if failure.retryable { (1, 0) } else { (0, 1) }
        );
        let (job, enabled): (Value, bool) = sqlx::query_as(
            "SELECT to_jsonb(j), t.enabled FROM issuance_service.canvas_evidence_sync_jobs j
             JOIN issuance_service.canvas_evidence_sync_targets t ON t.id = j.target_id",
        )
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(job["last_error_code"], failure.code);
        assert_eq!(job["last_error_summary"], failure.summary);
        assert_eq!(job["result"], json!({}));
        assert_eq!(enabled, failure.retryable);
        assert!(
            logs.events.lock().unwrap().is_empty(),
            "classified failures do not become unexpected log events"
        );
        assert!(logs.rendered.lock().unwrap().is_empty());
    }
    eprintln!("native classified error controls PASS: retry and terminal semantics unchanged");
}

pub async fn assert_worker_failure_privacy(pool: &PgPool) {
    assert_eq!(
        format!(
            "{:x}",
            Sha256::digest(REFERENCE.replace("\r\n", "\n").as_bytes())
        ),
        "2bcffee4bfd78152e1a6eb611442391a228fa034cce1266818ded532f8f35c05"
    );
    let reference: Value = serde_json::from_str(REFERENCE).unwrap();
    assert_eq!(
        reference["source_commit"],
        "d418ac0df283625f43b0c011fb1c72fd7d3013a9"
    );
    assert_eq!(reference["cases"].as_array().unwrap().len(), 63);
    let cases: Vec<_> = reference["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| {
            matches!(
                case["input"]["branch"].as_str(),
                Some("escaped_job" | "cycle_failure" | "disconnect_marker" | "processing")
            )
        })
        .collect();
    assert_eq!(
        cases.len(),
        12,
        "all four reference worker branches, including three processing categories and both correlation modes"
    );
    let mut failed = Vec::new();
    for case in cases {
        let result = AssertUnwindSafe(tokio::time::timeout(
            Duration::from_secs(10),
            assert_case(pool, case),
        ))
        .catch_unwind()
        .await;
        if !matches!(result, Ok(Ok(()))) {
            failed.push(case["id"].clone());
        }
    }
    assert!(
        failed.is_empty(),
        "native privacy replay failed: {failed:?}"
    );
    assert_classified_errors_unchanged(pool).await;
}
