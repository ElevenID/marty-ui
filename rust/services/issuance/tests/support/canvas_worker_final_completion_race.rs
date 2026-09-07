//! Normative repository overlap on the published schema; not process parity.
use super::canvas_worker_rest_replay::prepare;
use marty_issuance_service::{
    canvas_sync_worker::{CanvasSyncResult, CanvasSyncWorkerRepository, JobFailure},
    canvas_sync_worker_postgres::PostgresCanvasSyncWorkerRepository,
};
use serde_json::{json, Value};
use sqlx::{postgres::PgConnectOptions, postgres::PgPoolOptions, PgPool};
use std::{sync::OnceLock, time::Duration};

const JOB: &str = "worker-final-job";
const OWNER: &str = "final-race-owner";

async fn rows(pool: &PgPool) -> Value {
    sqlx::query_scalar("SELECT jsonb_build_object('jobs',(SELECT jsonb_agg(to_jsonb(j) ORDER BY id) FROM issuance_service.canvas_evidence_sync_jobs j),'targets',(SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM issuance_service.canvas_evidence_sync_targets t))")
        .fetch_one(pool).await.unwrap()
}

async fn real_expiry(pool: &PgPool) {
    tokio::time::timeout(Duration::from_secs(35), async {
        loop {
            let expired: bool = sqlx::query_scalar("SELECT lease_expires_at <= clock_timestamp() FROM issuance_service.canvas_evidence_sync_jobs WHERE id=$1")
                .bind(JOB).fetch_one(pool).await.unwrap();
            if expired { break; }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }).await.expect("real lease must expire without timestamp mutation");
}

async fn target_wait(pool: &PgPool, barrier_pid: i32, completion: bool) {
    let query_fragment = if completion {
        "%SET last_succeeded_at%"
    } else {
        "%SET enabled = false%"
    };
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND application_name='canvas-final-race-operation' AND state='active' AND wait_event_type='Lock' AND $1=ANY(pg_blocking_pids(pid)) AND query LIKE $2)")
                .bind(barrier_pid).bind(query_fragment).fetch_one(pool).await.unwrap();
            if waiting { break; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("actual winner must block on the owned target barrier");
    // Confirm job-before-target locking independently of the query text.
    let mut probe = pool.begin().await.unwrap();
    let error = sqlx::query(
        "SELECT id FROM issuance_service.canvas_evidence_sync_jobs WHERE id=$1 FOR UPDATE NOWAIT",
    )
    .bind(JOB)
    .execute(&mut *probe)
    .await
    .unwrap_err();
    assert_eq!(
        error.as_database_error().unwrap().code().as_deref(),
        Some("55P03")
    );
    probe.rollback().await.unwrap();
}

pub async fn run(pool: &PgPool, database_url: &str, case: &Value) {
    let completion_wins = match case["winner"].as_str().unwrap() {
        "completion" => true,
        "recovery" => false,
        _ => panic!("unknown final completion race case"),
    };
    let fixture = prepare(pool, "https://127.0.0.1:1", "rest").await;
    static HISTORY: OnceLock<Value> = OnceLock::new();
    let history = HISTORY.get_or_init(|| {
        serde_json::from_str(include_str!(
            "../../../../../contracts/canvas-worker-provider-final-scenarios.json"
        ))
        .unwrap()
    });
    sqlx::raw_sql(history["initial_job_seed"].as_str().unwrap())
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
    assert_eq!(
        (
            job.attempt_count,
            job.max_attempts,
            job.target_config_version
        ),
        (8, 8, 1)
    );
    let leased = rows(pool).await;
    assert_eq!(
        leased["jobs"][0]["result"],
        json!({"target_config_version":1})
    );

    let mut barrier = pool.begin().await.unwrap();
    let barrier_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *barrier)
        .await
        .unwrap();
    sqlx::query("SELECT id FROM issuance_service.canvas_evidence_sync_targets WHERE id='target-review' FOR UPDATE")
        .execute(&mut *barrier).await.unwrap();
    let options: PgConnectOptions = database_url.parse().unwrap();
    let operation_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options.application_name("canvas-final-race-operation"))
        .await
        .unwrap();
    let operation_repository = PostgresCanvasSyncWorkerRepository::new(operation_pool.clone());
    let mut operations = tokio::task::JoinSet::new();
    if completion_wins {
        let owned_job = job.clone();
        operations.spawn(async move {
            operation_repository
                .complete_job(&owned_job, OWNER, 1, &CanvasSyncResult::new())
                .await
                .unwrap()
        });
        target_wait(pool, barrier_pid, true).await;
        real_expiry(pool).await;
        // Recovery actually executes while completion owns the job. SKIP LOCKED
        // must return promptly, with no new lease or committed state change.
        let recovered = tokio::time::timeout(
            Duration::from_secs(5),
            repository.lease_ready("final-reclaimer", &1_u64.into(), &30_u64.into()),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(recovered.is_empty());
        assert_eq!(rows(pool).await, leased);
    } else {
        real_expiry(pool).await;
        operations.spawn(async move {
            operation_repository
                .lease_ready("final-reclaimer", &1_u64.into(), &30_u64.into())
                .await
                .unwrap()
                .is_empty()
        });
        target_wait(pool, barrier_pid, false).await;
        let completed = tokio::time::timeout(
            Duration::from_secs(5),
            repository.complete_job(job, OWNER, 1, &CanvasSyncResult::new()),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(completed, case["completion_return"].as_bool().unwrap());
        assert!(!completed);
        assert_eq!(rows(pool).await, leased);
    }
    barrier.rollback().await.unwrap();
    let winner_return = tokio::time::timeout(Duration::from_secs(5), operations.join_next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(winner_return);
    if completion_wins {
        assert_eq!(winner_return, case["completion_return"].as_bool().unwrap());
    }
    assert!(operations.is_empty());
    let committed = rows(pool).await;
    assert_eq!(committed["jobs"].as_array().unwrap().len(), 1);
    assert_eq!(committed["targets"].as_array().unwrap().len(), 1);
    let terminal = &committed["jobs"][0];
    assert_eq!(terminal["status"], case["status"]);
    for key in [
        "id",
        "organization_id",
        "target_id",
        "attempt_count",
        "max_attempts",
        "started_at",
        "created_at",
        "available_at",
    ] {
        assert_eq!(terminal[key], leased["jobs"][0][key], "changed {key}");
    }
    assert!(terminal["lease_owner"].is_null() && terminal["lease_expires_at"].is_null());
    assert!(!terminal["completed_at"].is_null());
    assert_eq!(committed["targets"][0]["enabled"], case["target_enabled"]);
    assert_eq!(
        !committed["targets"][0]["last_succeeded_at"].is_null(),
        completion_wins
    );
    assert_eq!(
        terminal["result"],
        if completion_wins {
            json!({})
        } else {
            json!({"target_config_version":1})
        }
    );
    assert_eq!(
        terminal["last_error_code"],
        if completion_wins {
            Value::Null
        } else {
            json!("canvas_worker_lease_expired")
        }
    );
    assert_eq!(
        terminal["last_error_summary"],
        if completion_wins {
            Value::Null
        } else {
            json!("Canvas worker lease expired on final attempt")
        }
    );
    // Compare every field outside each operation's explicit write set, including
    // schema fields not individually named in the terminal projection above.
    for (table, changed_fields) in [
        (
            "jobs",
            &[
                "status",
                "result",
                "last_error_code",
                "last_error_summary",
                "lease_owner",
                "lease_expires_at",
                "completed_at",
                "updated_at",
            ][..],
        ),
        (
            "targets",
            &["enabled", "last_succeeded_at", "updated_at"][..],
        ),
    ] {
        let mut expected = leased[table][0].clone();
        for field in changed_fields {
            expected[*field] = committed[table][0][*field].clone();
        }
        assert_eq!(committed[table][0], expected, "unexpected {table} mutation");
    }

    // Every stale persistence entrypoint must leave the full committed state
    // identical, not merely keep its status string or row count unchanged.
    assert!(!repository
        .complete_job(job, OWNER, 1, &CanvasSyncResult::new())
        .await
        .unwrap());
    assert_eq!(rows(pool).await, committed);
    let failure = JobFailure {
        error_code: "synthetic_stale_failure",
        error_summary: Some("Synthetic stale outcome"),
        retry_after_seconds: None,
        force_dead_letter: true,
    };
    assert!(repository
        .fail_job(job, OWNER, &failure, 1)
        .await
        .unwrap()
        .is_none());
    assert_eq!(rows(pool).await, committed);
    assert!(repository
        .lease_ready("final-reclaimer", &1_u64.into(), &30_u64.into())
        .await
        .unwrap()
        .is_empty());
    assert_eq!(rows(pool).await, committed);
    assert_eq!(case["terminal_winners"], 1);
    assert_eq!(case["stale_writes"], 0);
    fixture.assert_preserved(pool).await;
    operation_pool.close().await;
    println!("Native final-attempt repository {} PASS (real expiry, one terminal winner, zero stale writes)", case["winner"].as_str().unwrap());
}
