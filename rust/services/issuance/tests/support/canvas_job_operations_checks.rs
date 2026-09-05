//! Native invariants on the official disposable schema, supplementary to the
//! frozen HTTP replay. These are not additional published differential cases.
use super::canvas_operations_read_replay::{fixtures, job_router, request_case, seed};
use serde_json::{json, Value};
use sqlx::PgPool;

async fn job(pool: &PgPool) -> Value {
    sqlx::query_scalar("SELECT to_jsonb(job) FROM issuance_service.canvas_evidence_sync_jobs job WHERE id='job-dead'")
        .fetch_one(pool).await.unwrap()
}

async fn target(pool: &PgPool) -> Value {
    sqlx::query_scalar("SELECT to_jsonb(target) FROM issuance_service.canvas_evidence_sync_targets target WHERE id='target-review'")
        .fetch_one(pool).await.unwrap()
}

fn post(path: &str) -> Value {
    json!({"method":"POST","path":format!("/v1/integrations/canvas/{path}")})
}

async fn compete(router: &axum::Router, case: &Value, expected: [u16; 2]) -> [Value; 2] {
    let (first, second) = tokio::join!(request_case(router, case), request_case(router, case));
    let mut statuses = [first.0, second.0];
    statuses.sort_unstable();
    assert_eq!(
        statuses, expected,
        "competing requests: {first:?}, {second:?}"
    );
    [first.2, second.2]
}

pub async fn exercise(pool: &PgPool) {
    seed(pool).await;
    let [shared, _, _] = fixtures();
    let preserved: Value = sqlx::query_scalar(shared["preserved_rows_sql"].as_str().unwrap())
        .fetch_one(pool)
        .await
        .unwrap();
    let review: Value = sqlx::query_scalar("SELECT to_jsonb(review) FROM issuance_service.evidence_policy_reviews review WHERE id='review-dismiss'")
        .fetch_one(pool).await.unwrap();
    let router = job_router(pool, true);
    let retry = post("canvas-sync-jobs/job-dead/retry");
    let resolve = post("canvas-sync-jobs/job-dead/resolve");
    // Seed fields omitted by the compact frozen snapshot, then verify the full
    // retry reset and preservation of started_at (legacy does not clear it).
    // The official lease constraint requires null lease fields for dead_letter.
    sqlx::query("UPDATE issuance_service.canvas_evidence_sync_jobs SET max_attempts=12, started_at='2026-01-01T00:00:00Z', completed_at=now() WHERE id='job-dead'")
        .execute(pool).await.unwrap();
    let before = job(pool).await;
    compete(&router, &retry, [202, 409]).await;
    let after = job(pool).await;
    assert_eq!(after["status"], "queued");
    assert_eq!(after["attempt_count"], 0);
    assert_eq!(after["max_attempts"], 8);
    assert_eq!(after["result"], json!({}));
    for key in [
        "lease_owner",
        "lease_expires_at",
        "last_error_code",
        "last_error_summary",
        "completed_at",
    ] {
        assert_eq!(after[key], Value::Null, "retry must clear {key}");
    }
    for key in [
        "id",
        "organization_id",
        "target_id",
        "started_at",
        "created_at",
    ] {
        assert_eq!(after[key], before[key], "retry must preserve {key}");
    }
    assert_eq!(target(pool).await["enabled"], true);

    sqlx::query("UPDATE issuance_service.canvas_evidence_sync_jobs SET status='dead_letter',attempt_count=8,last_error_code='synthetic',result='{\"facts_changed\":1}' WHERE id='job-dead'")
        .execute(pool).await.unwrap();
    sqlx::query("UPDATE issuance_service.canvas_evidence_sync_targets SET enabled=false WHERE id='target-review'")
        .execute(pool).await.unwrap();
    let before = job(pool).await;
    let stopped = target(pool).await;
    // A target failure must roll back the already-executed job UPDATE.
    sqlx::query("ALTER TABLE issuance_service.canvas_evidence_sync_targets ADD CONSTRAINT synthetic_reject_enable CHECK (id <> 'target-review' OR enabled=false)")
        .execute(pool).await.unwrap();
    assert_eq!(
        request_case(&router, &retry).await,
        (
            500,
            "text/plain; charset=utf-8".into(),
            json!("Internal Server Error")
        )
    );
    assert_eq!(
        job(pool).await,
        before,
        "failed target update partially reset job"
    );
    assert_eq!(target(pool).await, stopped);
    sqlx::query("ALTER TABLE issuance_service.canvas_evidence_sync_targets DROP CONSTRAINT synthetic_reject_enable")
        .execute(pool).await.unwrap();

    // Resolution deliberately works with rollout disabled and never restarts target.
    compete(&job_router(pool, false), &resolve, [200, 409]).await;
    let mut after = job(pool).await;
    assert_eq!(after["status"], "cancelled");
    assert!(after["completed_at"].is_string());
    for key in ["status", "completed_at", "updated_at"] {
        after[key] = before[key].clone();
    }
    assert_eq!(after, before, "resolution changed unrelated job fields");
    assert_eq!(target(pool).await, stopped);

    let enqueue = post("applications/application-review/canvas-sync");
    let bodies = compete(&router, &enqueue, [202, 202]).await;
    assert_eq!(
        bodies[0]["id"], bodies[1]["id"],
        "canonical job must be reused"
    );
    assert_eq!(bodies[0]["target_id"], bodies[1]["target_id"]);
    let canonical: Value = sqlx::query_scalar("SELECT to_jsonb(target) FROM issuance_service.canvas_evidence_sync_targets target WHERE logical_key='application:application-review' AND organization_id='org-review'")
        .fetch_one(pool).await.unwrap();
    assert_eq!(canonical["target_type"], "issued_drift");
    assert_eq!(canonical["schedule_seconds"], 21600);
    assert_eq!(
        canonical["metadata"]["created_from"],
        "application_sync_api"
    );
    assert_eq!(
        canonical["metadata"]["last_requested_from"],
        "application_sync_api"
    );
    let active: i64 = sqlx::query_scalar("SELECT count(*) FROM issuance_service.canvas_evidence_sync_jobs WHERE target_id=$1 AND status IN ('queued','leased','retry')")
        .bind(canonical["id"].as_str().unwrap()).fetch_one(pool).await.unwrap();
    assert_eq!(active, 1);

    // All callers still use the same enqueue owner and canonical active job.
    use marty_issuance_service::{
        canvas_lti_bootstrap::CanvasLtiBootstrapSyncEnqueuer,
        canvas_lti_evidence::{CanvasLtiEvidenceSyncEnqueueError, CanvasLtiEvidenceSyncEnqueuer},
        canvas_lti_sync_enqueue::{
            PostgresCanvasLtiBootstrapSyncEnqueuer, UuidCanvasSyncEnqueueIdGenerator,
        },
    };
    let legacy = PostgresCanvasLtiBootstrapSyncEnqueuer::new(
        pool.clone(),
        true,
        ["org-review".to_owned()].into(),
        std::sync::Arc::new(UuidCanvasSyncEnqueueIdGenerator),
    );
    CanvasLtiBootstrapSyncEnqueuer::enqueue(&legacy, "org-review", "application-review")
        .await
        .unwrap();
    CanvasLtiEvidenceSyncEnqueuer::enqueue(&legacy, "org-review", "application-review")
        .await
        .unwrap();
    assert_eq!(
        request_case(&router, &enqueue).await.2["id"],
        bodies[0]["id"]
    );
    let disabled = PostgresCanvasLtiBootstrapSyncEnqueuer::new(
        pool.clone(),
        false,
        ["org-review".to_owned()].into(),
        std::sync::Arc::new(UuidCanvasSyncEnqueueIdGenerator),
    );
    assert_eq!(
        CanvasLtiEvidenceSyncEnqueuer::enqueue(&disabled, "org-review", "missing")
            .await
            .unwrap_err(),
        CanvasLtiEvidenceSyncEnqueueError::Conflict {
            code: "canvas_rollout_disabled"
        },
        "existing LTI rollout validation still precedes application lookup"
    );

    // Python replaces non-object metadata before merging its request marker.
    sqlx::query("UPDATE issuance_service.canvas_evidence_sync_targets SET metadata='[1,2]',enabled=false WHERE id=$1")
        .bind(canonical["id"].as_str().unwrap()).execute(pool).await.unwrap();
    assert_eq!(request_case(&router, &enqueue).await.0, 202);
    let metadata: Value = sqlx::query_scalar(
        "SELECT metadata FROM issuance_service.canvas_evidence_sync_targets WHERE id=$1",
    )
    .bind(canonical["id"].as_str().unwrap())
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(
        metadata,
        json!({"last_requested_from":"application_sync_api"})
    );

    learner_and_enqueue_rollback(pool, &router).await;

    // Rollout and tenant checks cannot modify existing durable state.
    let closed = job_router(pool, false);
    assert_eq!(request_case(&closed, &enqueue).await.0, 409);
    assert_eq!(
        request_case(&closed, &post("applications/missing/canvas-sync"))
            .await
            .0,
        404,
        "operations application lookup precedes rollout"
    );
    let mut foreign = resolve.clone();
    foreign["headers"] = json!({"X-Organization-ID":"foreign"});
    assert_eq!(request_case(&router, &foreign).await.0, 404);
    assert_eq!(
        request_case(&router, &post("canvas-sync-jobs/missing/resolve"))
            .await
            .0,
        404
    );
    assert_eq!(target(pool).await, stopped);
    let current: Value = sqlx::query_scalar(shared["preserved_rows_sql"].as_str().unwrap())
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(current, preserved);
    let current: Value = sqlx::query_scalar("SELECT to_jsonb(review) FROM issuance_service.evidence_policy_reviews review WHERE id='review-dismiss'")
        .fetch_one(pool).await.unwrap();
    assert_eq!(
        current, review,
        "job operations must not change correction review"
    );
}

async fn learner_and_enqueue_rollback(pool: &PgPool, router: &axum::Router) {
    sqlx::query("INSERT INTO issuance_service.applications (id,organization_id,application_template_id,applicant_identifier,form_data,submitted_evidence,status,derived_claims,integration_context,created_at,updated_at)
        SELECT 'application-learner',organization_id,application_template_id,'synthetic-learner','{}','[]','approved','{}',integration_context,now(),now()
        FROM issuance_service.applications WHERE id='application-review'")
        .execute(pool).await.unwrap();
    let case = post("applications/application-learner/canvas-sync");
    sqlx::query("UPDATE issuance_service.canvas_evidence_sync_jobs SET status='cancelled' WHERE status='queued'")
        .execute(pool).await.unwrap();
    sqlx::query("ALTER TABLE issuance_service.canvas_evidence_sync_jobs ADD CONSTRAINT synthetic_reject_enqueue CHECK (status <> 'queued')")
        .execute(pool).await.unwrap();
    assert_eq!(request_case(router, &case).await.0, 500);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM issuance_service.canvas_evidence_sync_targets WHERE application_id='application-learner'")
        .fetch_one(pool).await.unwrap();
    assert_eq!(count, 0, "failed job INSERT must roll back the new target");
    sqlx::query("ALTER TABLE issuance_service.canvas_evidence_sync_jobs DROP CONSTRAINT synthetic_reject_enqueue")
        .execute(pool).await.unwrap();
    let bodies = compete(router, &case, [202, 202]).await;
    assert_eq!(bodies[0]["id"], bodies[1]["id"]);
    assert_eq!(bodies[0]["target_id"], bodies[1]["target_id"]);
    let target: Value = sqlx::query_scalar("SELECT to_jsonb(target) FROM issuance_service.canvas_evidence_sync_targets target WHERE application_id='application-learner'")
        .fetch_one(pool).await.unwrap();
    assert_eq!(target["target_type"], "learner_application");
    assert_eq!(target["schedule_seconds"], 900);
}
