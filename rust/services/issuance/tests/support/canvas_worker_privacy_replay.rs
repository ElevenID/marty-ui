//! Hardened-reference log/state replay through actual native cycles and SQL.
//! Only the reference's repository failure and successful processor are controlled.

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
    canvas_sync_lease::CanvasSyncLease,
    canvas_sync_worker::{
        canvas_sync_result, CanvasSyncProcessingError, CanvasSyncProcessor, CanvasSyncResult,
        CanvasSyncTarget, CanvasSyncWorkerConfig,
    },
};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tokio::sync::watch;
use tracing::{instrument::WithSubscriber, Instrument};
use tracing_subscriber::{layer::SubscriberExt, Layer};

use super::canvas_worker_range_oracle::{observed_worker_with_fault, ReadFault};

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
        let actual = portable_log(logs, ambient, None);
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

fn portable_log(logs: Logs, ambient: bool, job_id: Option<&str>) -> Value {
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
    // Explicit language mapping: the injected repository RuntimeError is a
    // payload-free native persistence error, never an exception-object string.
    assert_eq!(fields["exception_class"], "CanvasSyncRepositoryUnavailable");
    fields.insert("exception_class".into(), json!("RuntimeError"));
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
    let ambient = case["id"]
        .as_str()
        .unwrap()
        .ends_with("[ambient-correlation]");
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
                Some(ReadFault::Target("privacy-failed".into())),
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
                "cycle": {"scheduled": result.scheduled, "leased": result.leased,
                    "succeeded": result.succeeded, "retried": result.retried,
                    "dead_lettered": result.dead_lettered,
                    "oauth_revocations_succeeded": result.oauth_revocations_succeeded,
                    "oauth_revocations_retried": result.oauth_revocations_retried},
            "failed_job": job_observation(failed, worker_id, Some(generation)),
            "sibling_job": job_observation(&jobs["privacy-sibling"], worker_id, None),
                "log": portable_log(logs, ambient, Some(failed["id"].as_str().unwrap())),
            })
        }
        "cycle_failure" => {
            let (sender, stop) = watch::channel(false);
            let (worker, observed) = observed_worker_with_fault(
                pool,
                config,
                Arc::new(SuccessfulSibling),
                Some((2, sender)),
                Some(ReadFault::FirstOAuthQueueRead),
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
                "log": portable_log(logs, ambient, None),
            })
        }
        other => panic!("unmapped privacy branch {other}"),
    };
    assert_eq!(actual, case["observed"], "{}", case["id"]);
    eprintln!("native hardened privacy replay PASS: {}", case["id"]);
}

pub async fn assert_repository_failure_privacy(pool: &PgPool) {
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
                Some("escaped_job" | "cycle_failure")
            )
        })
        .collect();
    assert_eq!(
        cases.len(),
        4,
        "two branches, each with/without ambient correlation"
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
}
