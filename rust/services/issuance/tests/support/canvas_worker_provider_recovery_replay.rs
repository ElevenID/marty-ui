//! Actual native renewal/expiry/retry, using the independent published corpus.
use super::{
    canvas_worker_concurrent_replay::{heartbeats, start_blocked_workers, WORKER_IDS},
    canvas_worker_process_signals::OwnedWorker,
    canvas_worker_provider_signals_replay::{
        assert_generation_fenced_state, assert_leased_state, await_marker, control_directory, mark,
        snapshot,
    },
    canvas_worker_rest_replay::{prepare, worker_environment, WorkerFixture},
};
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{PgPool, Row};
use std::{collections::BTreeMap, sync::OnceLock, time::Duration};

struct Generation {
    id: String,
    attempt: i32,
    owner: Option<String>,
    expires: Option<DateTime<Utc>>,
    started: DateTime<Utc>,
    worker_heartbeat: DateTime<Utc>,
    target_heartbeat: DateTime<Utc>,
}

async fn generation(pool: &PgPool) -> Generation {
    let rows = sqlx::query(
        "SELECT j.id,j.attempt_count,j.lease_owner,j.lease_expires_at,j.started_at,
        h.last_heartbeat_at AS worker_heartbeat,
        (t.metadata->>'worker_heartbeat_at')::timestamptz AS target_heartbeat
        FROM issuance_service.canvas_evidence_sync_jobs j
        JOIN issuance_service.canvas_evidence_sync_targets t ON t.id=j.target_id
        JOIN issuance_service.canvas_worker_heartbeats h ON h.worker_id='worker-rest'",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    assert_eq!(
        rows.len(),
        1,
        "recovery must retain exactly one durable job"
    );
    let row = &rows[0];
    Generation {
        id: row.get("id"),
        attempt: row.get("attempt_count"),
        owner: row.get("lease_owner"),
        expires: row.get("lease_expires_at"),
        started: row.get("started_at"),
        worker_heartbeat: row.get("worker_heartbeat"),
        target_heartbeat: row.get("target_heartbeat"),
    }
}

async fn start(
    pool: &PgPool,
    database_url: &str,
    environment: &BTreeMap<String, String>,
) -> (OwnedWorker, DateTime<Utc>) {
    let since = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(pool)
        .await
        .unwrap();
    (
        OwnedWorker::start_with_environment(database_url, "worker-rest", environment),
        since,
    )
}

async fn idle_outcome(
    pool: &PgPool,
    fixture: &WorkerFixture,
    worker: &mut OwnedWorker,
    status: &str,
    attempt: i64,
    since: DateTime<Utc>,
) -> Value {
    tokio::time::timeout(Duration::from_secs(25), async {
        loop {
            assert!(worker.0.try_wait().unwrap().is_none(), "native process exited before idle outcome");
            let state = snapshot(pool, fixture).await;
            let fresh: bool = sqlx::query_scalar("SELECT last_heartbeat_at >= $1 FROM issuance_service.canvas_worker_heartbeats WHERE worker_id='worker-rest'")
                .bind(since).fetch_one(pool).await.unwrap();
            let jobs = state["jobs"].as_array().unwrap();
            if fresh && state["heartbeat"]["metadata"]["phase"] == "idle"
                && jobs.len() == 1 && jobs[0]["status"] == status && jobs[0]["attempt_count"] == attempt {
                break state;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }).await.expect("actual native worker must reach fresh durable idle outcome")
}

async fn await_database_condition(pool: &PgPool, query: &'static str, id: &str, seconds: u64) {
    tokio::time::timeout(Duration::from_secs(seconds), async {
        loop {
            let ready: bool = sqlx::query_scalar(query)
                .bind(id)
                .fetch_one(pool)
                .await
                .unwrap();
            if ready {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("actual persisted expiry/eligibility must occur without timestamp mutation");
}

async fn observe_reclaimers(
    pool: &PgPool,
    fixture: &WorkerFixture,
    worker: &mut OwnedWorker,
    contender: &mut Option<OwnedWorker>,
    started: DateTime<Utc>,
    expected: &Value,
    boundary: &str,
) {
    let Some(mut other) = contender.take() else {
        return;
    };
    let alive_key = match boundary {
        "reclaimed" => "both_reclaimers_alive_after_recovery",
        "completed" => "both_reclaimers_alive_after_completion",
        _ => panic!("unknown reclaimer observation boundary"),
    };
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            assert!(worker.0.try_wait().unwrap().is_none());
            assert!(other.0.try_wait().unwrap().is_none());
            let fresh: bool = sqlx::query_scalar("SELECT count(*)=2 AND bool_and(last_heartbeat_at >= $1 AND metadata->>'phase'='idle') FROM issuance_service.canvas_worker_heartbeats")
                .bind(started).fetch_one(pool).await.unwrap();
            if fresh { break; }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }).await.expect("both reclaimer heartbeats must be fresh and idle after restart");
    assert_eq!(heartbeats(pool).await, expected["reclaimer_heartbeats"]);
    assert_generation_fenced_state(snapshot(pool, fixture).await, &expected[boundary], 1);
    assert_eq!(expected[alive_key], true);
    other.signal("SIGINT");
    assert_eq!(other.wait().await.code(), Some(130));
    assert_eq!(expected["contender_exit_code_after_interrupt"], -2);
}

pub async fn replay(pool: &PgPool, database_url: &str, origin: &str, case: &str) {
    assert!(matches!(
        case,
        "renewal" | "recovery" | "final" | "reclaimers" | "reclaimers_retry"
    ));
    let final_attempt = matches!(case, "final" | "reclaimers");
    let retry_recovery = matches!(case, "recovery" | "reclaimers_retry");
    let dual_reclaimers = matches!(case, "reclaimers" | "reclaimers_retry");
    let (reference_json, scenarios_json) = match case {
        "reclaimers_retry" => (
            include_str!("../../../../../contracts/canvas-worker-reclaimers-retry-oracle.json"),
            include_str!("../../../../../contracts/canvas-worker-reclaimers-retry-scenarios.json"),
        ),
        "reclaimers" => (
            include_str!("../../../../../contracts/canvas-worker-reclaimers-oracle.json"),
            include_str!("../../../../../contracts/canvas-worker-reclaimers-scenarios.json"),
        ),
        "final" => (
            include_str!("../../../../../contracts/canvas-worker-provider-final-oracle.json"),
            include_str!("../../../../../contracts/canvas-worker-provider-final-scenarios.json"),
        ),
        _ => (
            include_str!("../../../../../contracts/canvas-worker-provider-recovery-oracle.json"),
            include_str!("../../../../../contracts/canvas-worker-provider-recovery-scenarios.json"),
        ),
    };
    let reference: Value = serde_json::from_str(reference_json).unwrap();
    static FINAL_SCENARIO: OnceLock<Value> = OnceLock::new();
    static RECOVERY_SCENARIO: OnceLock<Value> = OnceLock::new();
    static RECLAIMERS_SCENARIO: OnceLock<Value> = OnceLock::new();
    static RECLAIMERS_RETRY_SCENARIO: OnceLock<Value> = OnceLock::new();
    let cases = match case {
        "final" => &FINAL_SCENARIO,
        "reclaimers" => &RECLAIMERS_SCENARIO,
        "reclaimers_retry" => &RECLAIMERS_RETRY_SCENARIO,
        _ => &RECOVERY_SCENARIO,
    }
    .get_or_init(|| {
        let parsed: Value = serde_json::from_str(scenarios_json).unwrap();
        if case == "reclaimers_retry" {
            assert_eq!(
                parsed["extends"],
                "canvas-worker-provider-recovery-scenarios.json"
            );
            assert_eq!(
                parsed["reclaimer_settings"],
                "canvas-worker-reclaimers-scenarios.json"
            );
            let mut base: Value = serde_json::from_str(include_str!(
                "../../../../../contracts/canvas-worker-provider-recovery-scenarios.json"
            ))
            .unwrap();
            base.as_object_mut()
                .unwrap()
                .extend(parsed.as_object().unwrap().clone());
            let settings: Value = serde_json::from_str(include_str!(
                "../../../../../contracts/canvas-worker-reclaimers-scenarios.json"
            ))
            .unwrap();
            // Share contention settings, never final-attempt history.
            for key in [
                "reclaimer_ids",
                "barrier_sql",
                "blocked_reclaimers_sql",
                "concurrency_scenario",
            ] {
                base[key] = settings[key].clone();
            }
            assert!(base.get("initial_job_seed").is_none());
            base
        } else if case == "reclaimers" {
            assert_eq!(
                parsed["extends"],
                "canvas-worker-provider-final-scenarios.json"
            );
            let mut base: Value = serde_json::from_str(include_str!(
                "../../../../../contracts/canvas-worker-provider-final-scenarios.json"
            ))
            .unwrap();
            base.as_object_mut()
                .unwrap()
                .extend(parsed.as_object().unwrap().clone());
            base
        } else {
            parsed
        }
    });
    let expected = if final_attempt || dual_reclaimers {
        &reference
    } else {
        &reference[case]
    };
    let fixture = prepare(pool, origin, "rest").await;
    if final_attempt {
        // Historical attempts are fixture input before any worker starts.
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM issuance_service.canvas_evidence_sync_jobs")
                .fetch_one(pool)
                .await
                .unwrap();
        assert_eq!(count, 0);
        sqlx::raw_sql(cases["initial_job_seed"].as_str().unwrap())
            .execute(pool)
            .await
            .unwrap();
    }
    let mut environment = worker_environment(origin);
    assert_eq!(cases["lease_seconds"], 30);
    environment.insert("CANVAS_SYNC_WORKER_LEASE_SECONDS".into(), "30".into());
    let control = control_directory();
    let (mut worker, mut started) = start(pool, database_url, &environment).await;
    let mut contender: Option<OwnedWorker> = None;
    await_marker(&control, "request-received", &mut worker).await;
    assert_leased_state(snapshot(pool, &fixture).await, &expected["before"], 1);
    let first = generation(pool).await;
    let advanced = tokio::time::timeout(Duration::from_secs(13), async {
        loop {
            assert!(
                worker.0.try_wait().unwrap().is_none(),
                "native process exited during renewal"
            );
            let current = generation(pool).await;
            if current.expires > first.expires
                && current.worker_heartbeat > first.worker_heartbeat
                && current.target_heartbeat > first.target_heartbeat
            {
                break current;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("lease and both actual heartbeats must advance during provider I/O");
    assert_eq!(
        (
            &advanced.id,
            advanced.attempt,
            &advanced.owner,
            advanced.started
        ),
        (&first.id, first.attempt, &first.owner, first.started)
    );
    assert_eq!(expected["lease_and_both_heartbeats_advanced"], true);
    assert_eq!(expected["generation_preserved_during_renewal"], true);
    assert_leased_state(snapshot(pool, &fixture).await, &expected["renewed"], 1);
    if retry_recovery || final_attempt {
        worker.signal("SIGKILL");
        let status = worker.wait().await;
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(status.signal(), Some(9));
        }
        assert_eq!(status.code(), None);
        assert_eq!(expected["crash_exit_code"], -9);
        assert_leased_state(snapshot(pool, &fixture).await, &expected["after_crash"], 1);
        mark(&control, "release-response");
        await_database_condition(pool, "SELECT lease_expires_at<=clock_timestamp() FROM issuance_service.canvas_evidence_sync_jobs WHERE id=$1", &first.id, 35).await;
        if dual_reclaimers {
            assert_eq!(cases["reclaimer_ids"], serde_json::json!(WORKER_IDS));
            assert_eq!(
                cases["concurrency_scenario"],
                "canvas-worker-concurrent-scenarios.json"
            );
            started = sqlx::query_scalar("SELECT clock_timestamp()")
                .fetch_one(pool)
                .await
                .unwrap();
            let mut reclaimers = start_blocked_workers(
                pool,
                database_url,
                &environment,
                cases["barrier_sql"].as_str().unwrap(),
                cases["blocked_reclaimers_sql"].as_str().unwrap(),
                1,
                || assert_eq!(expected["both_reclaimers_blocked"], true),
            )
            .await;
            contender = reclaimers.pop();
            worker = reclaimers.pop().unwrap();
            assert!(reclaimers.is_empty());
        } else {
            let (reclaimer, since) = start(pool, database_url, &environment).await;
            worker = reclaimer;
            started = since;
        }
    }
    if retry_recovery {
        let reclaimed = idle_outcome(pool, &fixture, &mut worker, "retry", 1, started).await;
        assert_generation_fenced_state(reclaimed, &expected["reclaimed"], 1);
        let delay_in_range: bool = sqlx::query_scalar("SELECT extract(epoch FROM available_at-updated_at) BETWEEN 14.9 AND 20.1 FROM issuance_service.canvas_evidence_sync_jobs WHERE id=$1")
            .bind(&first.id).fetch_one(pool).await.unwrap();
        assert!(delay_in_range);
        assert_eq!(expected["recovery_backoff_in_range"], true);
        observe_reclaimers(
            pool,
            &fixture,
            &mut worker,
            &mut contender,
            started,
            expected,
            "reclaimed",
        )
        .await;
        mark(&control, "reclaimer-idle");
        await_marker(&control, "reclaimer-observed", &mut worker).await;
        worker.signal("SIGINT");
        assert_eq!(worker.wait().await.code(), Some(130));
        assert_eq!(expected["reclaimer_exit_code"], -2);
        await_database_condition(pool, "SELECT status='retry' AND available_at<=clock_timestamp() FROM issuance_service.canvas_evidence_sync_jobs WHERE id=$1", &first.id, 25).await;
        (worker, started) = start(pool, database_url, &environment).await;
    } else if case == "renewal" {
        mark(&control, "release-response");
    }
    let completed = idle_outcome(
        pool,
        &fixture,
        &mut worker,
        if final_attempt {
            "dead_letter"
        } else {
            "succeeded"
        },
        match case {
            "final" | "reclaimers" => 8,
            "recovery" | "reclaimers_retry" => 2,
            _ => 1,
        },
        started,
    )
    .await;
    if final_attempt {
        assert_generation_fenced_state(completed, &expected["completed"], 1);
    } else {
        assert_eq!(completed, expected["completed"]);
    }
    observe_reclaimers(
        pool,
        &fixture,
        &mut worker,
        &mut contender,
        started,
        expected,
        "completed",
    )
    .await;
    if final_attempt || dual_reclaimers {
        let target_enabled: bool = sqlx::query_scalar("SELECT enabled FROM issuance_service.canvas_evidence_sync_targets WHERE id='target-review'")
            .fetch_one(pool).await.unwrap();
        assert_eq!(target_enabled, !final_attempt);
        assert_eq!(expected["target_enabled"], !final_attempt);
    }
    worker.signal("SIGINT");
    assert_eq!(worker.wait().await.code(), Some(130));
    assert_eq!(expected["exit_code_after_interrupt"], -2);
    let final_state = generation(pool).await;
    assert_eq!(
        (&final_state.id, final_state.started),
        (&first.id, first.started)
    );
    assert_eq!(expected["same_job_and_original_start"], true);
    fixture.assert_preserved(pool).await;
}
