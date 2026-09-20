//! Actual post-validation resource disappearance, with native query ordering.

use super::{
    canvas_worker_process_signals::OwnedWorker,
    canvas_worker_provider_signals_replay::{assert_leased_state, snapshot},
    canvas_worker_rest_replay::{prepare, validation_scenarios, worker_environment},
};
use serde_json::Value;
use sqlx::{PgPool, Postgres, Transaction};
use std::{collections::BTreeSet, sync::OnceLock, time::Duration};

fn scenarios() -> &'static Value {
    static SCENARIOS: OnceLock<Value> = OnceLock::new();
    SCENARIOS.get_or_init(|| {
        serde_json::from_str(include_str!(
            "../../../../../contracts/canvas-worker-resources-unavailable-scenarios.json"
        ))
        .unwrap()
    })
}

async fn scalar(pool: &PgPool, query: &'static str) -> Value {
    sqlx::query_scalar(query).fetch_one(pool).await.unwrap()
}

async fn hold<'a>(pool: &'a PgPool, table: &str) -> (Transaction<'a, Postgres>, i32) {
    let query = match table {
        "applications" => "LOCK TABLE issuance_service.applications IN ACCESS EXCLUSIVE MODE",
        "canvas_platforms" => {
            "LOCK TABLE issuance_service.canvas_platforms IN ACCESS EXCLUSIVE MODE"
        }
        _ => panic!("unknown native resource barrier"),
    };
    let mut barrier = pool.begin().await.unwrap();
    // This timeout belongs only to the fixture connection, never the worker.
    sqlx::raw_sql("SET LOCAL lock_timeout='5s'")
        .execute(&mut *barrier)
        .await
        .unwrap();
    sqlx::raw_sql(query).execute(&mut *barrier).await.unwrap();
    let pid = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *barrier)
        .await
        .unwrap();
    (barrier, pid)
}

async fn await_lookup(pool: &PgPool, worker: &mut OwnedWorker, table: &str, blocker: i32) {
    assert!(matches!(table, "applications" | "canvas_platforms"));
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            assert!(
                worker.0.try_wait().unwrap().is_none(),
                "worker exited at {table}"
            );
            // Match the requested relation lock, not a possibly truncated ORM
            // query tail. Worker pool connections may differ between phases.
            let blocked: i64 = sqlx::query_scalar(
                "SELECT count(DISTINCT a.pid)
                 FROM pg_stat_activity a JOIN pg_locks l ON l.pid=a.pid
                 WHERE a.datname=current_database() AND a.application_name='worker-rest'
                   AND a.wait_event_type='Lock' AND a.query ILIKE 'SELECT%'
                   AND l.locktype='relation' AND l.mode='AccessShareLock' AND NOT l.granted
                   AND l.relation=$1::regclass AND $2=ANY(pg_blocking_pids(a.pid))",
            )
            .bind(format!("issuance_service.{table}"))
            .bind(blocker)
            .fetch_one(pool)
            .await
            .unwrap();
            if blocked == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("native worker must reach the owned resource lookup barrier");
}

pub async fn replay(pool: &PgPool, database_url: &str, origin: &str, name: &str) {
    let matrix = scenarios();
    let references: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/canvas-worker-resources-unavailable-oracle.json"
    ))
    .unwrap();
    let cases = matrix["cases"].as_array().unwrap();
    assert!(!cases.is_empty(), "resource matrix must not be empty");
    let names = cases
        .iter()
        .map(|case| case["name"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(names.len(), cases.len(), "duplicate resource case");
    assert_eq!(
        names,
        references
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
    );
    let case = cases.iter().find(|case| case["name"] == name).unwrap();
    let expected = &references[name];
    assert_eq!(expected["case"], name);
    assert_eq!(expected["requests"], serde_json::json!([]));
    // Python's repeated validations need five barriers. Native validates once
    // and then reloads platform/binding jointly, so two real barriers reach
    // the same external boundary. Never invent matching internal read traces.
    assert_eq!(
        expected["observed_barriers"],
        serde_json::json!([
            "wrapper_application",
            "hook_platform",
            "hook_binding",
            "hook_application",
            "resource_platform"
        ])
    );
    assert_eq!(
        matrix["queued_job_scenario"],
        "canvas-worker-validation-scenarios.json"
    );
    assert_eq!(
        matrix["reference_scenario"],
        "canvas-worker-rest-scenarios.json"
    );
    let fixture = prepare(pool, origin, "rest").await;
    let mut seed = pool.begin().await.unwrap();
    for statement in case["seed"]
        .as_array()
        .unwrap()
        .iter()
        .map(|sql| sql.as_str().unwrap())
        .chain(std::iter::once(
            validation_scenarios()["initial_job_seed"].as_str().unwrap(),
        ))
    {
        assert_eq!(
            sqlx::raw_sql(statement)
                .execute(&mut *seed)
                .await
                .unwrap()
                .rows_affected(),
            1
        );
    }
    seed.commit().await.unwrap();

    let (application_barrier, application_blocker) = hold(pool, "applications").await;
    let mut worker = OwnedWorker::start_with_environment(
        database_url,
        "worker-rest",
        &worker_environment(origin),
    );
    await_lookup(pool, &mut worker, "applications", application_blocker).await;
    let (mut resource_barrier, resource_blocker) = hold(pool, "canvas_platforms").await;
    application_barrier.commit().await.unwrap();
    await_lookup(pool, &mut worker, "canvas_platforms", resource_blocker).await;
    assert_leased_state(snapshot(pool, &fixture).await, &expected["before"], 1);
    let original_job = scalar(pool, matrix["job_row_sql"].as_str().unwrap()).await;
    // The platform is locked: inspect it through its owning connection.
    let protected: Value = sqlx::query_scalar(matrix["protected_rows_sql"].as_str().unwrap())
        .fetch_one(&mut *resource_barrier)
        .await
        .unwrap();
    for statement in case["mutation"].as_array().unwrap() {
        assert_eq!(
            sqlx::raw_sql(statement.as_str().unwrap())
                .execute(&mut *resource_barrier)
                .await
                .unwrap()
                .rows_affected(),
            1
        );
    }
    let changed: Value = sqlx::query_scalar(matrix["resources_sql"].as_str().unwrap())
        .fetch_one(&mut *resource_barrier)
        .await
        .unwrap();
    assert_eq!(changed, expected["changed_resources"]);
    let unchanged_job: Value = sqlx::query_scalar(matrix["job_row_sql"].as_str().unwrap())
        .fetch_one(&mut *resource_barrier)
        .await
        .unwrap();
    assert_eq!(unchanged_job, original_job, "fixture changed a running job");
    resource_barrier.commit().await.unwrap();

    let after = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            assert!(
                worker.0.try_wait().unwrap().is_none(),
                "worker exited before its outcome"
            );
            let state = snapshot(pool, &fixture).await;
            if state["heartbeat"]["metadata"]["phase"] == "idle"
                && state["jobs"].as_array().unwrap().len() == 1
                && state["jobs"][0]["status"] == "dead_letter"
            {
                break state;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("resource disappearance must reach its durable outcome");
    assert_eq!(
        after, expected["after"],
        "complete unavailable-resource state"
    );
    let resources = scalar(pool, matrix["resources_sql"].as_str().unwrap()).await;
    assert_eq!(resources, expected["final_resources"]);
    assert_eq!(
        scalar(pool, matrix["protected_rows_sql"].as_str().unwrap()).await,
        protected
    );
    let terminal = scalar(pool, matrix["job_row_sql"].as_str().unwrap()).await;
    assert_eq!(terminal["id"], original_job["id"]);
    assert_eq!(terminal["id"], "worker-validation-job");
    assert_eq!(expected["same_job"], true);
    worker.signal("SIGINT");
    assert_eq!(worker.wait().await.code(), Some(130));
    assert_eq!(expected["exit_code_after_interrupt"], -2);
    assert_eq!(snapshot(pool, &fixture).await, after);
    assert_eq!(
        scalar(pool, matrix["job_row_sql"].as_str().unwrap()).await,
        terminal
    );
    assert_eq!(
        scalar(pool, matrix["resources_sql"].as_str().unwrap()).await,
        resources
    );
    assert_eq!(
        scalar(pool, matrix["protected_rows_sql"].as_str().unwrap()).await,
        protected
    );
    assert_eq!(expected["protected_rows_unchanged"], true);
    assert_eq!(expected["unchanged_after_exit"], true);
    fixture.assert_preserved(pool).await;
}
