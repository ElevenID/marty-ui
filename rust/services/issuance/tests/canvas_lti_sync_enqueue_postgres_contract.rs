use std::{collections::BTreeSet, sync::Arc};

use marty_issuance_service::{
    canvas_lti_bootstrap::CanvasLtiBootstrapSyncEnqueuer,
    canvas_lti_evidence::CanvasLtiEvidenceSyncEnqueueError,
    canvas_lti_sync_enqueue::{
        CanvasSyncEnqueueIdGenerator, CanvasSyncEnqueueIds, PostgresCanvasLtiBootstrapSyncEnqueuer,
    },
};
use serde_json::Value;
use sqlx::{postgres::PgPoolOptions, Row};

fn database_url() -> Option<String> {
    std::env::var("MARTY_ISSUANCE_POSTGRES_CONTRACT_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
}

struct FixedIds;

impl CanvasSyncEnqueueIdGenerator for FixedIds {
    fn generate(&self) -> CanvasSyncEnqueueIds {
        CanvasSyncEnqueueIds {
            target_id: "target-1".to_owned(),
            job_id: "job-1".to_owned(),
        }
    }
}

#[tokio::test]
async fn sync_enqueue_is_tenant_bound_durable_and_idempotent() {
    let Some(database_url) = database_url() else {
        eprintln!("skipping Canvas sync enqueue PostgreSQL contract without database URL");
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&database_url)
        .await
        .expect("issuance PostgreSQL contract database must connect");
    setup_schema(&pool).await;
    seed_application(&pool).await;
    let enqueuer = PostgresCanvasLtiBootstrapSyncEnqueuer::new(
        pool.clone(),
        true,
        BTreeSet::from(["org-1".to_owned()]),
        Arc::new(FixedIds),
    );

    enqueuer.enqueue("org-1", "application-1").await.unwrap();
    let target = sqlx::query(
        "SELECT id, target_type, schedule_seconds, config_version, metadata,
                last_enqueued_at IS NOT NULL AS enqueued
         FROM issuance_service.canvas_evidence_sync_targets",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(target.get::<String, _>("id"), "target-1");
    assert_eq!(
        target.get::<String, _>("target_type"),
        "learner_application"
    );
    assert_eq!(target.get::<i32, _>("schedule_seconds"), 900);
    assert_eq!(target.get::<i32, _>("config_version"), 3);
    assert_eq!(
        target.get::<Value, _>("metadata")["created_from"],
        "application_sync_api"
    );
    assert!(target.get::<bool, _>("enqueued"));
    assert_eq!(table_count(&pool, "canvas_evidence_sync_jobs").await, 1);

    // Replays converge on the canonical target and one active job.
    enqueuer.enqueue("org-1", "application-1").await.unwrap();
    assert_eq!(table_count(&pool, "canvas_evidence_sync_targets").await, 1);
    assert_eq!(table_count(&pool, "canvas_evidence_sync_jobs").await, 1);
    let metadata: Value = sqlx::query_scalar(
        "SELECT metadata FROM issuance_service.canvas_evidence_sync_targets
         WHERE id = 'target-1'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(metadata["created_from"], "application_sync_api");
    assert_eq!(metadata["last_requested_from"], "application_sync_api");

    // Once issued, the same durable target switches to six-hour drift checks.
    sqlx::query(
        "UPDATE issuance_service.applications SET credential_id = 'credential-1'
         WHERE id = 'application-1'",
    )
    .execute(&pool)
    .await
    .unwrap();
    enqueuer.enqueue("org-1", "application-1").await.unwrap();
    let target = sqlx::query(
        "SELECT target_type, schedule_seconds
         FROM issuance_service.canvas_evidence_sync_targets WHERE id = 'target-1'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(target.get::<String, _>("target_type"), "issued_drift");
    assert_eq!(target.get::<i32, _>("schedule_seconds"), 21_600);
    assert_eq!(table_count(&pool, "canvas_evidence_sync_jobs").await, 1);

    // An active job from another tenant must never satisfy the idempotent
    // fallback, even if corrupted legacy data reuses this target identifier.
    sqlx::query("DELETE FROM issuance_service.canvas_evidence_sync_jobs")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO issuance_service.canvas_evidence_sync_jobs (
            id, organization_id, target_id, status, attempt_count, max_attempts,
            available_at, result, created_at, updated_at
         ) VALUES ('foreign-job', 'org-other', 'target-1', 'queued', 0, 8,
                   clock_timestamp(), '{}'::json, clock_timestamp(), clock_timestamp())",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        marty_issuance_service::canvas_lti_evidence::CanvasLtiEvidenceSyncEnqueuer::enqueue(
            &enqueuer,
            "org-1",
            "application-1",
        )
        .await
        .unwrap_err(),
        CanvasLtiEvidenceSyncEnqueueError::RepositoryUnavailable
    );
    sqlx::query("DELETE FROM issuance_service.canvas_evidence_sync_jobs")
        .execute(&pool)
        .await
        .unwrap();

    assert!(enqueuer
        .enqueue("org-other", "application-1")
        .await
        .is_err());
    sqlx::query(
        "UPDATE issuance_service.canvas_program_bindings SET enabled = false
         WHERE id = 'binding-1'",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert!(enqueuer.enqueue("org-1", "application-1").await.is_err());
    assert_eq!(
        marty_issuance_service::canvas_lti_evidence::CanvasLtiEvidenceSyncEnqueuer::enqueue(
            &enqueuer,
            "org-1",
            "application-1",
        )
        .await
        .unwrap_err(),
        CanvasLtiEvidenceSyncEnqueueError::Conflict {
            code: "canvas_binding_inactive"
        }
    );
    assert_eq!(
        marty_issuance_service::canvas_lti_evidence::CanvasLtiEvidenceSyncEnqueuer::enqueue(
            &enqueuer,
            "org-1",
            "missing-application",
        )
        .await
        .unwrap_err(),
        CanvasLtiEvidenceSyncEnqueueError::NotFound
    );
}

async fn table_count(pool: &sqlx::PgPool, table: &str) -> i64 {
    let query = match table {
        "canvas_evidence_sync_targets" => {
            "SELECT count(*) FROM issuance_service.canvas_evidence_sync_targets"
        }
        "canvas_evidence_sync_jobs" => {
            "SELECT count(*) FROM issuance_service.canvas_evidence_sync_jobs"
        }
        _ => panic!("unaudited contract table {table}"),
    };
    sqlx::query_scalar(query).fetch_one(pool).await.unwrap()
}

async fn setup_schema(pool: &sqlx::PgPool) {
    sqlx::query("DROP SCHEMA IF EXISTS issuance_service CASCADE")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("CREATE SCHEMA issuance_service")
        .execute(pool)
        .await
        .unwrap();
    for statement in [
        "CREATE TABLE issuance_service.applications (
            id text PRIMARY KEY, organization_id text NOT NULL,
            integration_context json NOT NULL, credential_id text)",
        "CREATE TABLE issuance_service.canvas_platforms (
            id text PRIMARY KEY, organization_id text NOT NULL, enabled boolean NOT NULL)",
        "CREATE TABLE issuance_service.canvas_program_bindings (
            id text PRIMARY KEY, organization_id text NOT NULL, platform_id text NOT NULL,
            enabled boolean NOT NULL, config_version integer NOT NULL)",
        "CREATE TABLE issuance_service.canvas_evidence_sync_targets (
            id text PRIMARY KEY, organization_id text NOT NULL, platform_id text NOT NULL,
            binding_id text NOT NULL, target_type text NOT NULL, logical_key text NOT NULL,
            application_id text, candidate_id text, enabled boolean NOT NULL,
            schedule_seconds integer NOT NULL, next_run_at timestamptz NOT NULL,
            last_enqueued_at timestamptz, last_succeeded_at timestamptz,
            config_version integer NOT NULL, metadata json NOT NULL,
            created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL,
            UNIQUE (organization_id, logical_key))",
        "CREATE TABLE issuance_service.canvas_evidence_sync_jobs (
            id text PRIMARY KEY, organization_id text NOT NULL, target_id text NOT NULL,
            status text NOT NULL, attempt_count integer NOT NULL, max_attempts integer NOT NULL,
            available_at timestamptz NOT NULL, lease_owner text, lease_expires_at timestamptz,
            last_error_code text, last_error_summary text, result json NOT NULL,
            created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL,
            started_at timestamptz, completed_at timestamptz)",
        "CREATE UNIQUE INDEX one_active_canvas_job
         ON issuance_service.canvas_evidence_sync_jobs (target_id)
         WHERE status IN ('queued', 'leased', 'retry')",
    ] {
        sqlx::query(statement).execute(pool).await.unwrap();
    }
}

async fn seed_application(pool: &sqlx::PgPool) {
    for statement in [
        "INSERT INTO issuance_service.applications
         VALUES ('application-1', 'org-1',
                 '{\"canvas\":{\"canvas_platform_id\":\"platform-1\",\"canvas_program_binding_id\":\"binding-1\"}}'::json,
                 NULL)",
        "INSERT INTO issuance_service.canvas_platforms VALUES ('platform-1', 'org-1', true)",
        "INSERT INTO issuance_service.canvas_program_bindings
         VALUES ('binding-1', 'org-1', 'platform-1', true, 3)",
    ] {
        sqlx::query(statement).execute(pool).await.unwrap();
    }
}
