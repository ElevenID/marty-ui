use chrono::{Duration, Utc};
use marty_issuance_service::{
    canvas_sync_worker::{CanvasSyncJobStatus, CanvasSyncWorkerRepository, WorkerHeartbeat},
    canvas_sync_worker_postgres::PostgresCanvasSyncWorkerRepository,
};
use sqlx::postgres::PgPoolOptions;

fn database_url() -> Option<String> {
    std::env::var("MARTY_ISSUANCE_POSTGRES_CONTRACT_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
}

#[tokio::test]
async fn scheduler_recovery_renewal_and_heartbeat_match_frozen_postgres_vectors() {
    let Some(database_url) = database_url() else {
        eprintln!("skipping Canvas worker PostgreSQL contract without database URL");
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(6)
        .connect(&database_url)
        .await
        .expect("Canvas worker contract database must connect");
    setup_schema(&pool).await;
    let repository = PostgresCanvasSyncWorkerRepository::new(pool.clone());

    seed_target(&pool, "target-new", 15).await;
    seed_target(&pool, "target-conflict", 900).await;
    sqlx::query(
        "INSERT INTO issuance_service.canvas_evidence_sync_jobs
            (id, organization_id, target_id, status, attempt_count, max_attempts,
             available_at, result, created_at, updated_at)
         VALUES ('active-conflict', 'org-1', 'target-conflict', 'queued', 0, 8,
                 clock_timestamp(), '{}'::json, clock_timestamp(), clock_timestamp())",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(repository.enqueue_due(100).await.unwrap(), 1);
    for (target_id, expected_schedule) in [("target-new", 60_i64), ("target-conflict", 900)] {
        let row: (bool, i64) = sqlx::query_as(
            "SELECT last_enqueued_at IS NOT NULL,
                    EXTRACT(EPOCH FROM (next_run_at - last_enqueued_at))::bigint
             FROM issuance_service.canvas_evidence_sync_targets WHERE id = $1",
        )
        .bind(target_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(row.0);
        assert!((row.1 - expected_schedule).abs() <= 1);
    }

    seed_target(&pool, "target-expired-retry", 900).await;
    seed_target(&pool, "target-expired-final", 900).await;
    for (id, target, attempt) in [
        ("expired-retry", "target-expired-retry", 7),
        ("expired-final", "target-expired-final", 8),
    ] {
        sqlx::query(
            "INSERT INTO issuance_service.canvas_evidence_sync_jobs
                (id, organization_id, target_id, status, attempt_count, max_attempts,
                 available_at, lease_owner, lease_expires_at, result, created_at,
                 updated_at, started_at)
             VALUES ($1, 'org-1', $2, 'leased', $3, 8, clock_timestamp(),
                     'crashed-worker', clock_timestamp() - interval '1 second',
                     '{}'::json, clock_timestamp(), clock_timestamp(), clock_timestamp())",
        )
        .bind(id)
        .bind(target)
        .bind(attempt)
        .execute(&pool)
        .await
        .unwrap();
    }
    let recovery_leased = repository.lease_ready("worker-1", 10, 120).await.unwrap();
    let retry: (String, String) = sqlx::query_as(
        "SELECT status, last_error_code FROM issuance_service.canvas_evidence_sync_jobs
         WHERE id = 'expired-retry'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        retry,
        ("retry".to_owned(), "canvas_worker_lease_expired".to_owned())
    );
    let final_state: (String, String, bool) = sqlx::query_as(
        "SELECT j.status, j.last_error_code, t.enabled
         FROM issuance_service.canvas_evidence_sync_jobs j
         JOIN issuance_service.canvas_evidence_sync_targets t ON t.id = j.target_id
         WHERE j.id = 'expired-final'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        final_state,
        (
            "dead_letter".to_owned(),
            "canvas_worker_lease_expired".to_owned(),
            false
        )
    );

    let leased = recovery_leased
        .into_iter()
        .find(|job| job.target_id == "target-new")
        .expect("newly scheduled job is leased");
    assert_eq!(leased.status, CanvasSyncJobStatus::Leased);
    assert!(!repository
        .renew_lease(&leased, "wrong-worker", 120)
        .await
        .unwrap());
    let mut wrong_generation = leased.clone();
    wrong_generation.attempt_count += 1;
    assert!(!repository
        .renew_lease(&wrong_generation, "worker-1", 120)
        .await
        .unwrap());
    assert!(repository
        .renew_lease(&leased, "worker-1", 120)
        .await
        .unwrap());

    let heartbeat = WorkerHeartbeat {
        worker_id: "worker-1".to_owned(),
        started_at: Utc::now() - Duration::minutes(1),
        phase: "processing",
        leased_jobs: 1,
        processor_configured: false,
    };
    repository.upsert_heartbeat(&heartbeat).await.unwrap();
    let metadata: serde_json::Value = sqlx::query_scalar(
        "SELECT metadata FROM issuance_service.canvas_worker_heartbeats
         WHERE worker_id = 'worker-1'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(metadata["phase"], "processing");
    assert_eq!(metadata["leased_jobs"], 1);
    assert_eq!(metadata["process"], "standalone");
    assert_eq!(metadata["processor_configured"], false);
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
        "CREATE TABLE issuance_service.canvas_platforms (
            id text PRIMARY KEY, organization_id text NOT NULL, enabled boolean NOT NULL,
            archived_at timestamptz, config_version integer NOT NULL)",
        "CREATE TABLE issuance_service.canvas_program_bindings (
            id text PRIMARY KEY, organization_id text NOT NULL, platform_id text NOT NULL,
            enabled boolean NOT NULL, archived_at timestamptz, config_version integer NOT NULL)",
        "CREATE TABLE issuance_service.applications (
            id text PRIMARY KEY, organization_id text NOT NULL)",
        "CREATE TABLE issuance_service.canvas_award_candidates (
            id text PRIMARY KEY, organization_id text NOT NULL)",
        "CREATE TABLE issuance_service.canvas_evidence_sync_targets (
            id text PRIMARY KEY, organization_id text NOT NULL, platform_id text NOT NULL,
            binding_id text NOT NULL, target_type text NOT NULL, logical_key text NOT NULL,
            application_id text, candidate_id text, enabled boolean NOT NULL,
            schedule_seconds integer NOT NULL, next_run_at timestamptz NOT NULL,
            last_enqueued_at timestamptz, last_succeeded_at timestamptz,
            config_version integer NOT NULL, metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
            created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL)",
        "CREATE TABLE issuance_service.canvas_evidence_sync_jobs (
            id text PRIMARY KEY, organization_id text NOT NULL, target_id text NOT NULL,
            status text NOT NULL, attempt_count integer NOT NULL, max_attempts integer NOT NULL,
            available_at timestamptz NOT NULL, lease_owner text, lease_expires_at timestamptz,
            last_error_code text, last_error_summary text, result jsonb NOT NULL,
            created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL,
            started_at timestamptz, completed_at timestamptz)",
        "CREATE UNIQUE INDEX ux_canvas_sync_jobs_one_active_target
            ON issuance_service.canvas_evidence_sync_jobs(target_id)
            WHERE status IN ('queued', 'leased', 'retry')",
        "CREATE TABLE issuance_service.canvas_worker_heartbeats (
            worker_id text PRIMARY KEY, role text NOT NULL, started_at timestamptz NOT NULL,
            last_heartbeat_at timestamptz NOT NULL, metadata jsonb NOT NULL)",
    ] {
        sqlx::query(statement).execute(pool).await.unwrap();
    }
    sqlx::query(
        "INSERT INTO issuance_service.canvas_platforms
            VALUES ('platform-1', 'org-1', true, NULL, 3);
         INSERT INTO issuance_service.canvas_program_bindings
            VALUES ('binding-1', 'org-1', 'platform-1', true, NULL, 3);",
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn seed_target(pool: &sqlx::PgPool, id: &str, schedule_seconds: i32) {
    sqlx::query(
        "INSERT INTO issuance_service.canvas_evidence_sync_targets
            (id, organization_id, platform_id, binding_id, target_type, logical_key,
             enabled, schedule_seconds, next_run_at, config_version, metadata,
             created_at, updated_at)
         VALUES ($1, 'org-1', 'platform-1', 'binding-1', 'background_roster', $1,
                 true, $2, clock_timestamp() - interval '1 minute', 3, '{}'::jsonb,
                 clock_timestamp(), clock_timestamp())",
    )
    .bind(id)
    .bind(schedule_seconds)
    .execute(pool)
    .await
    .unwrap();
}
