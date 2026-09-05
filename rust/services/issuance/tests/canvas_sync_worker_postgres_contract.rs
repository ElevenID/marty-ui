use chrono::{Duration, Utc};
use marty_issuance_service::{
    canvas_sync_worker::{
        safe_result, CanvasSyncJobStatus, CanvasSyncResult, CanvasSyncWorkerRepository, JobFailure,
        WorkerHeartbeat,
    },
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
    assert_eq!(repository.enqueue_due(&100_u64.into()).await.unwrap(), 1);
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
    seed_target(&pool, "target-expired-reconfigured", 900).await;
    for (id, target, attempt) in [
        ("expired-retry", "target-expired-retry", 7),
        ("expired-final", "target-expired-final", 8),
        ("expired-reconfigured", "target-expired-reconfigured", 8),
    ] {
        sqlx::query(
            "INSERT INTO issuance_service.canvas_evidence_sync_jobs
                (id, organization_id, target_id, status, attempt_count, max_attempts,
                 available_at, lease_owner, lease_expires_at, result, created_at,
                 updated_at, started_at)
             VALUES ($1, 'org-1', $2, 'leased', $3, 8, clock_timestamp(),
                     'crashed-worker', clock_timestamp() - interval '1 second',
                     jsonb_build_object('target_config_version', 3),
                     clock_timestamp(), clock_timestamp(), clock_timestamp())",
        )
        .bind(id)
        .bind(target)
        .bind(attempt)
        .execute(&pool)
        .await
        .unwrap();
    }
    sqlx::query(
        "UPDATE issuance_service.canvas_evidence_sync_targets
         SET config_version = 4, enabled = true WHERE id = 'target-expired-reconfigured'",
    )
    .execute(&pool)
    .await
    .unwrap();
    let recovery_leased = repository
        .lease_ready("worker-1", &10_u64.into(), &120_u64.into())
        .await
        .unwrap();
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
        .renew_lease(&leased, "wrong-worker", &120_u64.into())
        .await
        .unwrap());
    let mut wrong_generation = leased.clone();
    wrong_generation.attempt_count += 1;
    assert!(!repository
        .renew_lease(&wrong_generation, "worker-1", &120_u64.into())
        .await
        .unwrap());
    assert!(repository
        .renew_lease(&leased, "worker-1", &120_u64.into())
        .await
        .unwrap());

    sqlx::query(
        "UPDATE issuance_service.canvas_evidence_sync_targets
         SET config_version = 4, enabled = true WHERE id = 'target-new'",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        repository
            .fail_job(
                &leased,
                "worker-1",
                &JobFailure {
                    error_code: "terminal_test",
                    error_summary: None,
                    retry_after_seconds: None,
                    force_dead_letter: true,
                },
                leased.target_config_version,
            )
            .await
            .unwrap(),
        Some(CanvasSyncJobStatus::DeadLetter)
    );
    let reconfigured_enabled: bool = sqlx::query_scalar(
        "SELECT enabled FROM issuance_service.canvas_evidence_sync_targets
         WHERE id = 'target-expired-reconfigured'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(reconfigured_enabled);
    assert!(sqlx::query_scalar::<_, bool>(
        "SELECT enabled FROM issuance_service.canvas_evidence_sync_targets
         WHERE id = 'target-new'",
    )
    .fetch_one(&pool)
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

    seed_target(&pool, "target-complete-current", 900).await;
    seed_target(&pool, "target-complete-stale", 900).await;
    seed_target(&pool, "target-complete-during", 900).await;
    sqlx::query(
        "INSERT INTO issuance_service.canvas_evidence_sync_jobs
            (id, organization_id, target_id, status, attempt_count, max_attempts,
             available_at, result, created_at, updated_at)
         VALUES
            ('complete-current', 'org-1', 'target-complete-current', 'queued', 0, 8,
             clock_timestamp(), '{}'::json, clock_timestamp(), clock_timestamp()),
            ('complete-stale', 'org-1', 'target-complete-stale', 'queued', 0, 8,
             clock_timestamp(), '{}'::json, clock_timestamp(), clock_timestamp()),
            ('complete-during', 'org-1', 'target-complete-during', 'queued', 0, 8,
             clock_timestamp(), '{}'::json, clock_timestamp(), clock_timestamp()),
            ('orphan', 'org-1', 'missing-target', 'queued', 0, 8,
             clock_timestamp(), '{}'::json, clock_timestamp(), clock_timestamp())",
    )
    .execute(&pool)
    .await
    .unwrap();
    let race_jobs = repository
        .lease_ready("race-worker", &10_u64.into(), &120_u64.into())
        .await
        .unwrap();
    let current = race_jobs
        .iter()
        .find(|job| job.id == "complete-current")
        .unwrap();
    let stale = race_jobs
        .iter()
        .find(|job| job.id == "complete-stale")
        .unwrap();
    let during = race_jobs
        .iter()
        .find(|job| job.id == "complete-during")
        .unwrap()
        .clone();
    let orphan = race_jobs.iter().find(|job| job.id == "orphan").unwrap();
    assert_eq!(orphan.target_config_version, 0);
    let processor_result: CanvasSyncResult = serde_json::from_str(
        r#"{"facts_observed":18446744073709551617,"facts_changed":-18446744073709551617,"policy_allowed":true,"candidate_state":"ready","provider_payload":{"synthetic":"discard"}}"#,
    ).unwrap();
    assert!(repository
        .complete_job(
            current,
            "race-worker",
            current.target_config_version,
            &safe_result(&processor_result),
        )
        .await
        .unwrap());
    let persisted: String = sqlx::query_scalar(
        "SELECT result::text FROM issuance_service.canvas_evidence_sync_jobs WHERE id = 'complete-current'",
    ).fetch_one(&pool).await.unwrap();
    let persisted: CanvasSyncResult = serde_json::from_str(&persisted).unwrap();
    assert_eq!(persisted.len(), 4);
    assert_eq!(persisted["facts_observed"].get(), "18446744073709551617");
    assert_eq!(persisted["facts_changed"].get(), "0");
    assert_eq!(persisted["policy_allowed"].get(), "true");
    assert_eq!(persisted["candidate_state"].get(), r#""ready""#);
    sqlx::query(
        "UPDATE issuance_service.canvas_evidence_sync_targets
         SET config_version = 4 WHERE id = 'target-complete-current'",
    )
    .execute(&pool)
    .await
    .unwrap();
    let completed_status: String = sqlx::query_scalar(
        "SELECT status FROM issuance_service.canvas_evidence_sync_jobs WHERE id = 'complete-current'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(completed_status, "succeeded");
    sqlx::query(
        "UPDATE issuance_service.canvas_evidence_sync_targets
         SET config_version = 4 WHERE id = 'target-complete-stale'",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert!(repository
        .complete_job(
            stale,
            "race-worker",
            stale.target_config_version,
            &Default::default(),
        )
        .await
        .unwrap());
    let (stale_status, stale_target_succeeded): (String, Option<chrono::DateTime<Utc>>) =
        sqlx::query_as(
            "SELECT j.status, t.last_succeeded_at
             FROM issuance_service.canvas_evidence_sync_jobs j
             JOIN issuance_service.canvas_evidence_sync_targets t ON t.id = j.target_id
             WHERE j.id = 'complete-stale'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(stale_status, "succeeded");
    assert_eq!(stale_target_succeeded, None);

    let mut reconfiguration = pool.begin().await.unwrap();
    sqlx::query(
        "UPDATE issuance_service.canvas_evidence_sync_targets
         SET config_version = 4 WHERE id = 'target-complete-during'",
    )
    .execute(&mut *reconfiguration)
    .await
    .unwrap();
    let during_repository = repository.clone();
    let completion = tokio::spawn(async move {
        during_repository
            .complete_job(
                &during,
                "race-worker",
                during.target_config_version,
                &Default::default(),
            )
            .await
            .unwrap()
    });
    tokio::task::yield_now().await;
    reconfiguration.commit().await.unwrap();
    assert!(completion.await.unwrap());
    let (during_status, during_target_succeeded): (String, Option<chrono::DateTime<Utc>>) =
        sqlx::query_as(
            "SELECT j.status, t.last_succeeded_at
             FROM issuance_service.canvas_evidence_sync_jobs j
             JOIN issuance_service.canvas_evidence_sync_targets t ON t.id = j.target_id
             WHERE j.id = 'complete-during'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(during_status, "succeeded");
    assert_eq!(during_target_succeeded, None);
    assert_eq!(
        repository
            .fail_job(
                orphan,
                "race-worker",
                &JobFailure {
                    error_code: "canvas_sync_target_not_found",
                    error_summary: None,
                    retry_after_seconds: None,
                    force_dead_letter: true,
                },
                orphan.target_config_version,
            )
            .await
            .unwrap(),
        Some(CanvasSyncJobStatus::DeadLetter),
    );
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
    for statement in [
        "INSERT INTO issuance_service.canvas_platforms
            VALUES ('platform-1', 'org-1', true, NULL, 3)",
        "INSERT INTO issuance_service.canvas_program_bindings
            VALUES ('binding-1', 'org-1', 'platform-1', true, NULL, 3)",
    ] {
        sqlx::query(statement).execute(pool).await.unwrap();
    }
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
