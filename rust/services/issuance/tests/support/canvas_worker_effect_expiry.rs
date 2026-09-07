//! Native transaction/time regression with a controlled provider, not actual
//! HTTP, whole-worker lifecycle, or published-process parity qualification.
use super::{
    canvas_worker_final_completion_race::assert_job_locked,
    canvas_worker_rest_replay::{prepare, validation_scenarios},
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use marty_issuance_service::{
    canvas_sync_lease::CanvasSyncLease,
    canvas_sync_processor::{
        CanvasAuthoritativeObservation, CanvasAuthoritativeProvider, CanvasProviderReadError,
        CanvasRosterSnapshot, CanvasSyncProcessorRepository, CanvasSyncResources,
        NativeCanvasSyncProcessor,
    },
    canvas_sync_processor_postgres::PostgresCanvasSyncProcessorRepository,
    canvas_sync_worker::{
        CanvasSyncProcessingError, CanvasSyncProcessor, CanvasSyncTarget, CanvasSyncWorkerConfig,
        CanvasSyncWorkerRepository,
    },
    canvas_sync_worker_lifecycle::worker_pool_options,
    canvas_sync_worker_postgres::PostgresCanvasSyncWorkerRepository,
};
use serde_json::{json, Value};
use sqlx::{postgres::PgConnectOptions, PgPool};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

const JOB: &str = "worker-validation-job";
const OWNER: &str = "effect-expiry-owner";
const OPERATION: &str = "canvas-effect-expiry-operation";
const BUSINESS_ROWS: &str = "SELECT jsonb_build_object(
    'facts',COALESCE((SELECT jsonb_agg(to_jsonb(f) ORDER BY id) FROM issuance_service.evidence_facts f),'[]'),
    'heads',COALESCE((SELECT jsonb_agg(to_jsonb(h) ORDER BY application_id,logical_key) FROM issuance_service.evidence_fact_heads h),'[]'),
    'reviews',COALESCE((SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM issuance_service.evidence_policy_reviews r),'[]'),
    'events',COALESCE((SELECT jsonb_agg(to_jsonb(e) ORDER BY id) FROM issuance_service.issuance_events e),'[]'),
    'applications',(SELECT jsonb_agg(to_jsonb(a) ORDER BY id) FROM issuance_service.applications a),
    'platforms',(SELECT jsonb_agg(to_jsonb(p) ORDER BY id) FROM issuance_service.canvas_platforms p),
    'bindings',(SELECT jsonb_agg(to_jsonb(b) ORDER BY id) FROM issuance_service.canvas_program_bindings b),
    'targets',(SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM issuance_service.canvas_evidence_sync_targets t),
    'credentials',(SELECT jsonb_agg(to_jsonb(c) ORDER BY id) FROM issuance_service.issued_credentials c),
    'transactions',(SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM issuance_service.issuance_transactions t),
    'secrets',(SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM issuance_service.organization_integration_secrets s),
    'oauth',(SELECT jsonb_agg(to_jsonb(c) ORDER BY id) FROM issuance_service.canvas_oauth_connections c))";

struct Provider {
    calls: AtomicUsize,
}

#[async_trait]
impl CanvasAuthoritativeProvider for Provider {
    fn for_run(self: Arc<Self>) -> Arc<dyn CanvasAuthoritativeProvider> {
        self
    }

    async fn read_requirement(
        &self,
        resources: &CanvasSyncResources,
        requirement: &Value,
        user: Option<&str>,
        subject: Option<&str>,
    ) -> Result<CanvasAuthoritativeObservation, CanvasProviderReadError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        assert!(
            call < 2,
            "exactly one initial and one contested read are allowed"
        );
        assert_eq!(requirement["requirement_id"], "assignment");
        assert_eq!(user, Some("7"));
        assert_eq!(subject, Some("subject-7"));
        if call == 1 {
            // The second process invocation must reread the successful first
            // invocation's context, not reuse a stale application snapshot.
            assert_eq!(
                resources
                    .application
                    .as_ref()
                    .unwrap()
                    .application
                    .integration_context["canvas"]["last_evidence_policy_allowed"],
                true
            );
        }
        let score = if call == 0 { 90 } else { 10 };
        let effective = if call == 0 {
            "2026-09-01T00:01:00Z"
        } else {
            "2026-09-01T00:02:00Z"
        };
        Ok(CanvasAuthoritativeObservation {
            assertion: json!({"score_percent":score}).as_object().unwrap().clone(),
            source_payload: json!({"synthetic_effect_revision":call,"score":score})
                .as_object()
                .unwrap()
                .clone(),
            verification_method: "canvas_rest",
            effective_at: Some(
                DateTime::parse_from_rfc3339(effective)
                    .unwrap()
                    .with_timezone(&Utc),
            ),
        })
    }

    async fn roster(
        &self,
        _: &CanvasSyncTarget,
        _: &CanvasSyncResources,
        _: &[Value],
        _: usize,
    ) -> Result<CanvasRosterSnapshot, CanvasProviderReadError> {
        panic!("issued-drift effect test must not read a roster")
    }
}

async fn business_rows(pool: &PgPool) -> Value {
    sqlx::query_scalar(BUSINESS_ROWS)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn job_row(pool: &PgPool) -> Value {
    sqlx::query_scalar(
        "SELECT to_jsonb(j) FROM issuance_service.canvas_evidence_sync_jobs j WHERE id=$1",
    )
    .bind(JOB)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn lease_is_current(pool: &PgPool) -> bool {
    sqlx::query_scalar("SELECT status='leased' AND lease_owner=$2 AND attempt_count=1 AND lease_expires_at > clock_timestamp() FROM issuance_service.canvas_evidence_sync_jobs WHERE id=$1")
        .bind(JOB).bind(OWNER).fetch_one(pool).await.unwrap()
}

async fn assert_waiting_at_event_insert(pool: &PgPool, blocker: i32) {
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let waiting: i64 = sqlx::query_scalar(
                "SELECT count(DISTINCT a.pid) FROM pg_stat_activity a
                 JOIN pg_locks l ON l.pid=a.pid
                 WHERE a.datname=current_database() AND a.application_name=$1
                   AND a.state='active' AND a.wait_event_type='Lock'
                   AND $2=ANY(pg_blocking_pids(a.pid))
                   AND l.locktype='relation' AND NOT l.granted
                   AND l.mode='RowExclusiveLock'
                   AND l.relation='issuance_service.issuance_events'::regclass
                   AND a.query LIKE '%INSERT INTO issuance_service.issuance_events%'",
            )
            .bind(OPERATION)
            .bind(blocker)
            .fetch_one(pool)
            .await
            .unwrap();
            if waiting == 1 {
                break;
            }
            assert_eq!(
                waiting, 0,
                "more than one effect writer reached the barrier"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("native evidence transaction must reach the exact owned event barrier");
    // Independent proof that the writer passed its initial lease authorization
    // and retained job-before-resource transaction ordering.
    assert_job_locked(pool, JOB).await;
}

fn assert_projection(state: &Value, denied: bool) {
    assert_eq!(state["facts"], if denied { 2 } else { 1 });
    assert_eq!(state["head_scores"], json!([if denied { 10 } else { 90 }]));
    assert_eq!(state["application"]["policy_allowed"], !denied);
    assert_eq!(state["credential"], json!({"count":1,"active":true}));
    if denied {
        assert_eq!(
            state["events"],
            json!({"evidence_fact_created":2,"evidence_policy_review_created":1})
        );
        let reviews = state["reviews"].as_array().unwrap();
        assert_eq!(reviews.len(), 1);
        assert_eq!(reviews[0]["status"], "open");
        assert_eq!(reviews[0]["prior_allowed"], true);
        assert_eq!(reviews[0]["current_allowed"], false);
        assert_eq!(reviews[0]["triggering_score"], 10);
    } else {
        assert_eq!(state["events"], json!({"evidence_fact_created":1}));
        assert_eq!(state["reviews"], json!([]));
    }
}

fn assert_positive_preserves_unrelated_rows(before: &Value, after: &Value) {
    for key in [
        "bindings",
        "targets",
        "credentials",
        "transactions",
        "secrets",
        "oauth",
    ] {
        assert_eq!(
            after[key], before[key],
            "valid effect changed unrelated {key}"
        );
    }
    for key in ["facts", "events"] {
        for original in before[key].as_array().unwrap() {
            assert!(
                after[key].as_array().unwrap().contains(original),
                "valid effect modified prior immutable {key}"
            );
        }
    }
    let mut expected_platforms = before["platforms"].clone();
    assert_eq!(expected_platforms.as_array().unwrap().len(), 1);
    for field in ["last_validated_at", "updated_at"] {
        assert!(after["platforms"][0][field].as_str().is_some());
        expected_platforms[0][field] = after["platforms"][0][field].clone();
    }
    assert_eq!(after["platforms"], expected_platforms);
    let mut expected_applications = before["applications"].clone();
    assert_eq!(expected_applications.as_array().unwrap().len(), 1);
    assert!(after["applications"][0]["updated_at"].as_str().is_some());
    expected_applications[0]["updated_at"] = after["applications"][0]["updated_at"].clone();
    let canvas = &after["applications"][0]["integration_context"]["canvas"];
    assert!(canvas["last_evidence_sync_at"].as_str().is_some());
    expected_applications[0]["integration_context"]["canvas"]["last_evidence_sync_at"] =
        canvas["last_evidence_sync_at"].clone();
    expected_applications[0]["integration_context"]["canvas"]["last_evidence_policy_allowed"] =
        json!(false);
    assert_eq!(after["applications"], expected_applications);
}

/// Requires a separate fresh published-schema database per call, a caller pool
/// with at least three connections, and at least 90 seconds of owned DB lifetime.
/// The positive control and expiry case execute identical native processor code.
pub async fn run(pool: &PgPool, database_url: &str, expire_before_commit: bool) {
    let fixture = prepare(pool, "https://127.0.0.1:1", "rest").await;
    sqlx::raw_sql(validation_scenarios()["initial_job_seed"].as_str().unwrap())
        .execute(pool)
        .await
        .unwrap();
    let repository = PostgresCanvasSyncWorkerRepository::new(pool.clone());
    let jobs = repository
        .lease_ready(OWNER, &1_u64.into(), &30_u64.into())
        .await
        .unwrap();
    assert_eq!(jobs.len(), 1);
    let job = &jobs[0];
    assert_eq!(job.id, JOB);
    assert_eq!(job.attempt_count, 1);
    let target = repository
        .target("org-review", "target-review")
        .await
        .unwrap()
        .unwrap();
    repository.validate_target(&target).await.unwrap();
    let lease = CanvasSyncLease::from_job(job, OWNER).unwrap();
    let original_job = job_row(pool).await;
    let options: PgConnectOptions = database_url.parse().unwrap();
    let operation_pool = worker_pool_options()
        .max_connections(1)
        .connect_with(options.application_name(OPERATION))
        .await
        .unwrap();
    let provider = Arc::new(Provider {
        calls: AtomicUsize::new(0),
    });
    let processor_repository = Arc::new(PostgresCanvasSyncProcessorRepository::new(
        operation_pool.clone(),
    ));
    let config = CanvasSyncWorkerConfig::from_values(&BTreeMap::from([
        ("CANVAS_SYNC_WORKER_ID".into(), OWNER.into()),
        ("CANVAS_PORTABLE_INTEGRATION_ENABLED".into(), "true".into()),
        ("CANVAS_PILOT_ORGANIZATION_IDS".into(), "org-review".into()),
    ]))
    .unwrap();
    let processor = NativeCanvasSyncProcessor::new(
        processor_repository.clone(),
        provider.clone(),
        config,
        1,
        10,
    );
    let initial = serde_json::to_value(processor.process(&target, &lease).await.unwrap()).unwrap();
    assert_eq!(initial["facts_created"], 1);
    assert_eq!(initial["policy_allowed"], true);
    let current_resources = processor_repository
        .resources(&target)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        current_resources
            .application
            .unwrap()
            .application
            .integration_context["canvas"]["last_evidence_policy_allowed"],
        true
    );
    let before = business_rows(pool).await;
    let projection_sql = fixture.shared["snapshot_sql"].as_str().unwrap();
    let projection: Value = sqlx::query_scalar(projection_sql)
        .fetch_one(pool)
        .await
        .unwrap();
    assert_projection(&projection, false);
    fixture.assert_preserved(pool).await;
    assert!(lease_is_current(pool).await);

    // SHARE permits observation SELECTs but delays the normal event INSERT.
    // No trigger, production statement, lease, timestamp, or clock is changed.
    let mut barrier = pool.begin().await.unwrap();
    let blocker: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *barrier)
        .await
        .unwrap();
    sqlx::query("LOCK TABLE issuance_service.issuance_events IN SHARE MODE NOWAIT")
        .execute(&mut *barrier)
        .await
        .unwrap();
    let mut operations = tokio::task::JoinSet::new();
    operations.spawn(async move { processor.process(&target, &lease).await });
    assert_waiting_at_event_insert(pool, blocker).await;
    assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        business_rows(pool).await,
        before,
        "pending effects must not be visible"
    );
    assert_eq!(job_row(pool).await, original_job);
    assert!(
        lease_is_current(pool).await,
        "writer must reach the effect barrier before expiry"
    );
    if expire_before_commit {
        tokio::time::timeout(Duration::from_secs(35), async {
            while lease_is_current(pool).await {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("real database lease expiry must occur without mutation");
        assert_eq!(
            job_row(pool).await,
            original_job,
            "expiry is elapsed time, not a row edit"
        );
        assert_job_locked(pool, JOB).await;
        assert_eq!(business_rows(pool).await, before);
        assert_waiting_at_event_insert(pool, blocker).await;
    }
    barrier.rollback().await.unwrap();
    let result = tokio::time::timeout(Duration::from_secs(8), operations.join_next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(operations.is_empty());
    if expire_before_commit {
        // record_fact maps its atomic owner's final lease rejection to the
        // existing repository-unavailable classification, not lease_lost.
        // Keep that exact public error shape; do not invent a runtime change.
        assert_eq!(
            result.unwrap_err(),
            CanvasSyncProcessingError::retryable(
                "canvas_sync_repository_unavailable",
                "Canvas synchronization persistence is unavailable",
            )
        );
        assert_eq!(
            business_rows(pool).await,
            before,
            "all effect rows must roll back"
        );
        assert!(!lease_is_current(pool).await);
    } else {
        let committed = serde_json::to_value(result.unwrap()).unwrap();
        assert_eq!(committed["facts_created"], 1);
        assert_eq!(committed["policy_allowed"], false);
        assert!(
            lease_is_current(pool).await,
            "positive control must commit while current"
        );
        assert_positive_preserves_unrelated_rows(&before, &business_rows(pool).await);
    }
    let after: Value = sqlx::query_scalar(projection_sql)
        .fetch_one(pool)
        .await
        .unwrap();
    assert_projection(&after, !expire_before_commit);
    fixture.assert_preserved(pool).await;
    assert_eq!(
        job_row(pool).await,
        original_job,
        "processor-only check must not invent an outcome"
    );
    let settled = business_rows(pool).await;
    tokio::time::timeout(Duration::from_secs(5), operation_pool.close())
        .await
        .expect("owned operation pool must acknowledge cleanup");
    assert!(operation_pool.is_closed());
    assert_eq!(
        business_rows(pool).await,
        settled,
        "owned operation pool cleanup changed effects"
    );
    assert_eq!(job_row(pool).await, original_job);
    println!("Controlled-provider native transaction real-time {} passed (not HTTP or whole-worker qualification)",
        if expire_before_commit { "expiry rollback" } else { "valid-lease positive control" });
}
