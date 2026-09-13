//! Focused repository regression; actual whole-worker parity remains a separate gate.
use super::{
    canvas_worker_final_completion_race::assert_job_locked, canvas_worker_rest_replay::prepare,
};
use chrono::{DateTime, Utc};
use marty_issuance_service::{
    canvas_sync_lease::CanvasSyncLease,
    canvas_sync_processor::CanvasSyncProcessorRepository,
    canvas_sync_processor_postgres::PostgresCanvasSyncProcessorRepository,
    canvas_sync_worker::{CanvasSyncProcessingError, CanvasSyncWorkerRepository},
    canvas_sync_worker_postgres::PostgresCanvasSyncWorkerRepository,
};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::{sync::Arc, time::Duration};

const JOB: &str = "roster-metadata-job";
const OWNER: &str = "roster-metadata-worker";
const ROWS: &str = "SELECT jsonb_build_object(
    'target',(SELECT to_jsonb(t) FROM issuance_service.canvas_evidence_sync_targets t WHERE id='target-review'),
    'jobs',(SELECT jsonb_agg(to_jsonb(j) ORDER BY id) FROM issuance_service.canvas_evidence_sync_jobs j),
    'platforms',(SELECT jsonb_agg(to_jsonb(p) ORDER BY id) FROM issuance_service.canvas_platforms p),
    'bindings',(SELECT jsonb_agg(to_jsonb(b) ORDER BY id) FROM issuance_service.canvas_program_bindings b),
    'applications',(SELECT jsonb_agg(to_jsonb(a) ORDER BY id) FROM issuance_service.applications a),
    'candidates',(SELECT jsonb_agg(to_jsonb(c) ORDER BY id) FROM issuance_service.canvas_award_candidates c),
    'observations',(SELECT jsonb_agg(to_jsonb(o) ORDER BY id) FROM issuance_service.canvas_candidate_observations o),
    'facts',(SELECT jsonb_agg(to_jsonb(f) ORDER BY id) FROM issuance_service.evidence_facts f),
    'events',(SELECT jsonb_agg(to_jsonb(e) ORDER BY id) FROM issuance_service.issuance_events e))";

async fn rows(pool: &PgPool) -> Value {
    sqlx::query_scalar(ROWS).fetch_one(pool).await.unwrap()
}

async fn lease_current(pool: &PgPool) -> bool {
    sqlx::query_scalar("SELECT lease_expires_at > clock_timestamp() FROM issuance_service.canvas_evidence_sync_jobs WHERE id=$1")
        .bind(JOB).fetch_one(pool).await.unwrap()
}

async fn await_expiry(pool: &PgPool) {
    tokio::time::timeout(Duration::from_secs(35), async {
        while lease_current(pool).await {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the normal 30-second repository lease must expire without row/clock edits");
}

async fn await_update_barrier(pool: &PgPool) {
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='relation'
                 AND database=(SELECT oid FROM pg_database WHERE datname=current_database())
                 AND relation='issuance_service.canvas_evidence_sync_targets'::regclass
                 AND mode='RowExclusiveLock' AND NOT granted)",
            )
            .fetch_one(pool)
            .await
            .unwrap();
            if waiting {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the real roster UPDATE must wait after the lease/resource guards");
    assert_job_locked(pool, JOB).await;
}

/// Each case needs a fresh official-schema database and at least four pool slots.
pub async fn assert_reconciliation(pool: &PgPool, name: &str) {
    assert!(matches!(
        name,
        "absent"
            | "preexisting"
            | "explicit_null"
            | "worker_only"
            | "heartbeat_only"
            | "stale_target_generation"
            | "wrong_owner"
            | "wrong_attempt"
            | "expired_before_write"
            | "expired_during_lock"
    ));
    let fixture = prepare(pool, "https://127.0.0.1:1", "retry").await;
    let mut initial = json!({
        "roster_cursor": 0,
        "roster_cycle_completed_at": "2026-09-01T00:00:00Z",
        "unrelated": {"version": "snapshot"},
        "removed_after_snapshot": true,
    });
    if matches!(name, "preexisting" | "worker_only") {
        initial["worker_id"] = json!("prior-worker");
    }
    if matches!(name, "preexisting" | "heartbeat_only") {
        initial["worker_heartbeat_at"] = json!("2026-09-01T00:00:01Z");
    }
    if name == "explicit_null" {
        initial["worker_id"] = Value::Null;
        initial["worker_heartbeat_at"] = Value::Null;
    }
    assert_eq!(sqlx::query("UPDATE issuance_service.canvas_evidence_sync_targets SET target_type='background_roster',application_id=NULL,metadata=$1 WHERE id='target-review' AND organization_id='org-review'")
        .bind(&initial).execute(pool).await.unwrap().rows_affected(), 1);
    sqlx::query("INSERT INTO issuance_service.canvas_evidence_sync_jobs (id,organization_id,target_id) VALUES ($1,'org-review','target-review')")
        .bind(JOB).execute(pool).await.unwrap();
    let queue = PostgresCanvasSyncWorkerRepository::new(pool.clone());
    let lease_seconds = if name.starts_with("expired_") {
        30_u64
    } else {
        120_u64
    };
    let jobs = queue
        .lease_ready(OWNER, &1_u64.into(), &lease_seconds.into())
        .await
        .unwrap();
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].id, JOB);
    // This is the real worker order: snapshot first, heartbeat second.
    let target = queue
        .target("org-review", "target-review")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(Value::Object(target.metadata.clone()), initial);
    assert!(queue.touch_target_heartbeat(&target, OWNER).await.unwrap());
    let touched = rows(pool).await;
    assert_eq!(touched["target"]["metadata"]["worker_id"], OWNER);
    assert!(touched["target"]["metadata"]["worker_heartbeat_at"].is_string());

    let mut captured_job = jobs[0].clone();
    if name == "wrong_owner" {
        captured_job.lease_owner = Some("another-worker".into());
    }
    if name == "wrong_attempt" {
        captured_job.attempt_count += 1;
    }
    let lease =
        CanvasSyncLease::from_job(&captured_job, captured_job.lease_owner.as_deref().unwrap())
            .unwrap();
    let repository =
        Arc::new(PostgresCanvasSyncProcessorRepository::new(pool.clone())).for_lease(lease);
    let resources = repository.resources(&target).await.unwrap().unwrap();
    // A different committed writer may replace, add, or remove unrelated keys.
    // Whole-snapshot replacement would regress each of these observations.
    assert_eq!(sqlx::query("UPDATE issuance_service.canvas_evidence_sync_targets SET metadata=(metadata::jsonb-'removed_after_snapshot')||'{\"unrelated\":{\"version\":\"current\"},\"added_after_snapshot\":[1,2]}'::jsonb WHERE id='target-review' AND organization_id='org-review'")
        .execute(pool).await.unwrap().rows_affected(), 1);
    if name == "stale_target_generation" {
        assert_eq!(sqlx::query("UPDATE issuance_service.canvas_evidence_sync_targets SET config_version=config_version+1 WHERE id='target-review' AND organization_id='org-review'")
            .execute(pool).await.unwrap().rows_affected(), 1);
    }
    let before = rows(pool).await;
    assert_eq!(
        before["jobs"], touched["jobs"],
        "fixtures may not mutate the durable lease"
    );
    let started: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(pool)
        .await
        .unwrap();
    if name == "expired_before_write" {
        await_expiry(pool).await;
    }
    let result = if name == "expired_during_lock" {
        // SHARE admits SELECT FOR UPDATE (including the resource guard), then
        // blocks the real UPDATE's RowExclusiveLock. Final lease validation must
        // roll the resumed UPDATE back after natural expiry.
        let mut barrier = pool.begin().await.unwrap();
        sqlx::query(
            "LOCK TABLE issuance_service.canvas_evidence_sync_targets IN SHARE MODE NOWAIT",
        )
        .execute(&mut *barrier)
        .await
        .unwrap();
        let operation_repository = repository.clone();
        let operation_target = target.clone();
        let operation_resources = resources.clone();
        let mut operations = tokio::task::JoinSet::new();
        operations.spawn(async move {
            operation_repository
                .update_roster_cursor(&operation_target, &operation_resources, 1, 7)
                .await
        });
        await_update_barrier(pool).await;
        assert!(
            lease_current(pool).await,
            "writer must reach barrier before expiry"
        );
        assert_eq!(rows(pool).await, before);
        await_expiry(pool).await;
        assert_eq!(
            rows(pool).await,
            before,
            "expiry must be time, not a durable edit"
        );
        await_update_barrier(pool).await;
        barrier.rollback().await.unwrap();
        tokio::time::timeout(Duration::from_secs(8), operations.join_next())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
    } else {
        repository
            .update_roster_cursor(&target, &resources, 1, 7)
            .await
    };
    let after = rows(pool).await;
    if matches!(
        name,
        "stale_target_generation"
            | "wrong_owner"
            | "wrong_attempt"
            | "expired_before_write"
            | "expired_during_lock"
    ) {
        let expected = if name == "stale_target_generation" {
            CanvasSyncProcessingError::retryable(
                "canvas_platform_reconfigured",
                "Canvas target, platform, binding, or application changed during synchronization",
            )
        } else {
            CanvasSyncProcessingError::retryable(
                "canvas_sync_lease_lost",
                "Canvas synchronization no longer owns its job lease",
            )
        };
        assert_eq!(result.unwrap_err(), expected, "{name}");
        assert_eq!(
            after, before,
            "a rejected cursor write changed durable rows: {name}"
        );
    } else {
        result.unwrap();
        let mut expected = before.clone();
        let metadata = expected["target"]["metadata"].as_object_mut().unwrap();
        for key in ["worker_id", "worker_heartbeat_at"] {
            metadata.remove(key);
            if let Some(value) = initial.get(key) {
                metadata.insert(key.into(), value.clone());
            }
        }
        metadata.insert("roster_cursor".into(), json!(1));
        metadata.insert("roster_size".into(), json!(7));
        metadata.insert("roster_cycle_completed_at".into(), Value::Null);
        let timestamps_valid: bool = sqlx::query_scalar("SELECT updated_at >= $1 AND updated_at <= clock_timestamp() AND next_run_at >= $1 + interval '60 seconds' AND next_run_at <= clock_timestamp() + interval '60 seconds' FROM issuance_service.canvas_evidence_sync_targets WHERE id='target-review'")
            .bind(started).fetch_one(pool).await.unwrap();
        assert!(
            timestamps_valid,
            "real cursor scheduling timestamps outside write window"
        );
        expected["target"]["updated_at"] = after["target"]["updated_at"].clone();
        expected["target"]["next_run_at"] = after["target"]["next_run_at"].clone();
        assert_eq!(
            after, expected,
            "only roster progress and snapshot heartbeat keys may reconcile: {name}"
        );
    }
    fixture.assert_preserved(pool).await;
}
