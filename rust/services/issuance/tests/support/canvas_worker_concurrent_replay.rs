//! Actual competing native schedulers against independently frozen behavior.
use super::{
    canvas_worker_process_signals::OwnedWorker,
    canvas_worker_provider_signals_replay::{
        assert_leased_state, await_marker, control_directory, mark, snapshot,
    },
    canvas_worker_rest_replay::{prepare, worker_environment, WorkerFixture},
};
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{PgPool, Row};
use std::{sync::OnceLock, time::Duration};

fn assert_alive(workers: &mut [OwnedWorker]) {
    assert_eq!(workers.len(), 2);
    for worker in workers {
        assert!(
            worker.0.try_wait().unwrap().is_none(),
            "concurrent worker exited before observation"
        );
    }
}

async fn phase_state(
    pool: &PgPool,
    fixture: &WorkerFixture,
    cases: &'static Value,
    workers: &mut [OwnedWorker],
    phases: &[&str],
    status: &str,
) -> Value {
    tokio::time::timeout(Duration::from_secs(25), async {
        loop {
            assert_alive(workers);
            let mut state = snapshot(pool, fixture).await;
            state["heartbeat"] = sqlx::query_scalar(cases["heartbeats_sql"].as_str().unwrap())
                .fetch_one(pool)
                .await
                .unwrap();
            let observed: Vec<_> = state["heartbeat"]
                .as_array()
                .unwrap()
                .iter()
                .map(|entry| entry["metadata"]["phase"].as_str().unwrap())
                .collect();
            if observed == phases
                && state["jobs"].as_array().unwrap().len() == 1
                && state["jobs"][0]["status"] == status
            {
                break state;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("both actual worker phases and one durable outcome must be observed")
}

pub async fn replay(pool: &PgPool, database_url: &str, origin: &str) {
    static CASES: OnceLock<Value> = OnceLock::new();
    let cases = CASES.get_or_init(|| {
        serde_json::from_str(include_str!(
            "../../../../../contracts/canvas-worker-concurrent-scenarios.json"
        ))
        .unwrap()
    });
    let expected: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/canvas-worker-concurrent-oracle.json"
    ))
    .unwrap();
    let worker_ids = ["worker-rest", "worker-contender"];
    assert_eq!(cases["worker_ids"], serde_json::json!(worker_ids));
    let fixture = prepare(pool, origin, "rest").await;
    let environment = worker_environment(origin);
    let control = control_directory();
    // This transaction holds only the isolated fixture's target table. Its
    // RAII rollback releases the barrier on failure as well as success.
    let mut barrier = pool.begin().await.unwrap();
    sqlx::raw_sql(cases["barrier_sql"].as_str().unwrap())
        .execute(&mut *barrier)
        .await
        .unwrap();
    let mut workers: Vec<_> = worker_ids
        .iter()
        .map(|id| OwnedWorker::start_with_environment(database_url, id, &environment))
        .collect();
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            assert_alive(&mut workers);
            let blocked: i64 =
                sqlx::query_scalar(cases["blocked_schedulers_sql"].as_str().unwrap())
                    .fetch_one(pool)
                    .await
                    .unwrap();
            if blocked == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("both actual schedulers must wait at the fixture barrier");
    assert_eq!(expected["both_schedulers_blocked"], true);
    let jobs: i64 =
        sqlx::query_scalar("SELECT count(*) FROM issuance_service.canvas_evidence_sync_jobs")
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(jobs, 0);
    assert!(!control.join("request-received").exists());
    barrier.commit().await.unwrap();
    await_marker(&control, "request-received", &mut workers[0]).await;
    let before = phase_state(
        pool,
        &fixture,
        cases,
        &mut workers,
        &["idle", "processing"],
        "leased",
    )
    .await;
    assert_leased_state(before, &expected["before"], 1);
    let original = sqlx::query(
        "SELECT id,lease_owner,started_at FROM issuance_service.canvas_evidence_sync_jobs",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    let id: String = original.get("id");
    let started: DateTime<Utc> = original.get("started_at");
    let owner: String = original.get("lease_owner");
    assert!(worker_ids.contains(&owner.as_str()));
    mark(&control, "release-response");
    let completed = phase_state(
        pool,
        &fixture,
        cases,
        &mut workers,
        &["idle", "idle"],
        "succeeded",
    )
    .await;
    assert_eq!(completed, expected["completed"]);
    assert_alive(&mut workers);
    assert_eq!(expected["both_workers_alive_after_completion"], true);
    let final_state =
        sqlx::query("SELECT id,started_at FROM issuance_service.canvas_evidence_sync_jobs")
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(final_state.get::<String, _>("id"), id);
    assert_eq!(final_state.get::<DateTime<Utc>, _>("started_at"), started);
    assert_eq!(expected["same_job_and_original_start"], true);
    assert_eq!(
        expected["exit_codes_after_interrupt"],
        serde_json::json!([-2, -2])
    );
    for worker in &mut workers {
        worker.signal("SIGINT");
        assert_eq!(worker.wait().await.code(), Some(130));
    }
    fixture.assert_preserved(pool).await;
}
