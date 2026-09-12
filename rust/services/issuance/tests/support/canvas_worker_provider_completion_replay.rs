//! Actual worker/provider completion race; retain stronger native atomicity.
use super::{
    canvas_worker_final_completion_race::assert_job_locked,
    canvas_worker_process_signals::OwnedWorker,
    canvas_worker_provider_signals_replay::{
        assert_generation_fenced_state, assert_leased_state, await_marker, control_directory, mark,
        snapshot,
    },
    canvas_worker_rest_replay::{prepare, worker_environment},
};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::{sync::OnceLock, time::Duration};

async fn wait(pool: &PgPool, query: &'static str, seconds: u64, workers: &mut [&mut OwnedWorker]) {
    tokio::time::timeout(Duration::from_secs(seconds), async {
        loop {
            for worker in workers.iter_mut() {
                assert!(
                    worker.0.try_wait().unwrap().is_none(),
                    "actual worker exited before observation"
                );
            }
            let ready: bool = sqlx::query_scalar(query).fetch_one(pool).await.unwrap();
            if ready {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("actual process must reach the required database boundary");
}

async fn row(pool: &PgPool, query: &'static str) -> Value {
    sqlx::query_scalar(query).fetch_one(pool).await.unwrap()
}

fn assert_atomic_target(reference: &Value, before: &Value, after: &Value) {
    // Three explicit normative differences, never a generic parity filter.
    assert_eq!(reference["reclaimer_blocked_by_completion"], true);
    assert_eq!(reference["target_enabled"], false);
    assert_eq!(reference["target_success_timestamp_present"], false);
    assert_eq!(before["enabled"], true);
    assert!(before["last_succeeded_at"].is_null());
    assert_eq!(after["enabled"], true);
    assert!(!after["last_succeeded_at"].is_null());
    let mut expected = before.clone();
    for field in ["last_succeeded_at", "updated_at"] {
        expected[field] = after[field].clone();
    }
    assert_eq!(
        after, &expected,
        "completion/recovery changed unrelated target state"
    );
}

fn assert_rejected_owner_state(observed: Value, reference: &Value) {
    assert_eq!(reference["stale_owner_path"], "blocked");
    assert_eq!(reference["contending"], reference["terminal_pending"]);
    assert_eq!(
        reference["contending"]["heartbeat"]["metadata"]["phase"],
        "processing"
    );
    assert_eq!(
        reference["contending"]["heartbeat"]["metadata"]["leased_jobs"],
        1
    );
    let mut expected = reference["contending"].clone();
    // Native checks the current DB clock after the statement wait. It rejects
    // expiry before waiting on the row, unlike Python's captured timestamp.
    expected["heartbeat"]["metadata"]["phase"] = json!("idle");
    expected["heartbeat"]["metadata"]["leased_jobs"] = json!(0);
    assert_leased_state(observed, &expected, 1);
}

pub async fn replay(pool: &PgPool, database_url: &str, origin: &str, name: &str) {
    assert!(matches!(name, "completion" | "recovery_first"));
    let recovery_first = name == "recovery_first";
    static CASE: OnceLock<Value> = OnceLock::new();
    static RECOVERY_CASE: OnceLock<Value> = OnceLock::new();
    static HISTORY: OnceLock<Value> = OnceLock::new();
    let case = CASE.get_or_init(|| {
        serde_json::from_str(include_str!(
            "../../../../../contracts/canvas-worker-provider-completion-scenarios.json"
        ))
        .unwrap()
    });
    let case = if recovery_first {
        RECOVERY_CASE.get_or_init(|| {
            let mut combined = case.clone();
            let extension: Value = serde_json::from_str(include_str!(
                "../../../../../contracts/canvas-worker-provider-recovery-first-scenarios.json"
            ))
            .unwrap();
            assert_eq!(
                extension["extends"],
                "canvas-worker-provider-completion-scenarios.json"
            );
            combined
                .as_object_mut()
                .unwrap()
                .extend(extension.as_object().unwrap().clone());
            combined
        })
    } else {
        case
    };
    let history = HISTORY.get_or_init(|| {
        serde_json::from_str(include_str!(
            "../../../../../contracts/canvas-worker-provider-final-scenarios.json"
        ))
        .unwrap()
    });
    let reference: Value = serde_json::from_str(if recovery_first {
        include_str!("../../../../../contracts/canvas-worker-provider-recovery-first-oracle.json")
    } else {
        include_str!("../../../../../contracts/canvas-worker-provider-completion-oracle.json")
    })
    .unwrap();
    assert_eq!(case["case"], name);
    assert_eq!(case["lease_seconds"], 30);
    let fixture = prepare(pool, origin, "rest").await;
    sqlx::raw_sql(history["initial_job_seed"].as_str().unwrap())
        .execute(pool)
        .await
        .unwrap();
    for statement in case["setup"].as_array().unwrap() {
        sqlx::raw_sql(statement.as_str().unwrap())
            .execute(pool)
            .await
            .unwrap();
    }
    let mut environment = worker_environment(origin);
    environment.insert("CANVAS_SYNC_WORKER_LEASE_SECONDS".into(), "30".into());
    let control = control_directory();
    let mut barrier = pool.begin().await.unwrap();
    sqlx::raw_sql(case["barrier_sql"].as_str().unwrap())
        .execute(&mut *barrier)
        .await
        .unwrap();
    let mut worker = OwnedWorker::start_with_environment(database_url, "worker-rest", &environment);
    await_marker(&control, "request-received", &mut worker).await;
    assert_leased_state(snapshot(pool, &fixture).await, &reference["before"], 1);
    let original = row(pool, case["job_row_sql"].as_str().unwrap()).await;
    assert_eq!(original["attempt_count"], 8);
    let mut owner_barrier = if recovery_first {
        let mut owned = pool.begin().await.unwrap();
        sqlx::raw_sql(case["owner_barrier_sql"].as_str().unwrap())
            .execute(&mut *owned)
            .await
            .unwrap();
        for statement in case["owner_barrier_setup"].as_array().unwrap() {
            sqlx::raw_sql(statement.as_str().unwrap())
                .execute(pool)
                .await
                .unwrap();
        }
        Some(owned)
    } else {
        None
    };
    mark(&control, "release-response");
    wait(
        pool,
        case[if recovery_first {
            "owner_statement_wait_sql"
        } else {
            "terminal_wait_sql"
        }]
        .as_str()
        .unwrap(),
        15,
        &mut [&mut worker],
    )
    .await;
    if recovery_first {
        let mut probe = pool.begin().await.unwrap();
        let id: String = sqlx::query_scalar("SELECT id FROM issuance_service.canvas_evidence_sync_jobs WHERE id='worker-final-job' FOR UPDATE NOWAIT").fetch_one(&mut *probe).await.unwrap();
        assert_eq!(id, "worker-final-job");
        probe.rollback().await.unwrap();
    } else {
        assert_job_locked(pool, "worker-final-job").await;
    }
    assert_leased_state(
        snapshot(pool, &fixture).await,
        &reference["terminal_pending"],
        1,
    );
    let target_before = row(pool, case["target_row_sql"].as_str().unwrap()).await;
    assert_eq!(target_before["enabled"], true);
    assert!(target_before["last_succeeded_at"].is_null());
    assert_eq!(
        row(pool, case["journal_sql"].as_str().unwrap()).await,
        json!([])
    );
    wait(pool, "SELECT lease_expires_at<=clock_timestamp() FROM issuance_service.canvas_evidence_sync_jobs WHERE id='worker-final-job'", 35, &mut [&mut worker]).await;
    let mut reclaimer_url = url::Url::parse(database_url).unwrap();
    reclaimer_url.set_username("synthetic_reclaimer").unwrap();
    reclaimer_url
        .set_password(Some("synthetic-reclaimer-local-only"))
        .unwrap();
    let mut contender = OwnedWorker::start_with_environment(
        reclaimer_url.as_str(),
        "worker-contender",
        &environment,
    );
    if recovery_first {
        wait(
            pool,
            case["terminal_wait_sql"].as_str().unwrap(),
            15,
            &mut [&mut worker, &mut contender],
        )
        .await;
        assert_job_locked(pool, "worker-final-job").await;
        assert_leased_state(
            snapshot(pool, &fixture).await,
            &reference["terminal_pending"],
            1,
        );
        owner_barrier.take().unwrap().rollback().await.unwrap();
        wait(pool, "SELECT metadata->>'phase'='idle' FROM issuance_service.canvas_worker_heartbeats WHERE worker_id='worker-rest'", 15, &mut [&mut worker, &mut contender]).await;
        assert_rejected_owner_state(snapshot(pool, &fixture).await, &reference);
        assert_eq!(reference["owner_statement_blocked_before_row_lock"], true);
        assert_eq!(reference["reclaimer_blocked_by_completion"], false);
    } else {
        // Native recovery must skip the locked job and finish its actual cycle
        // before the completion barrier is released, unlike the published worker.
        wait(pool, "SELECT EXISTS(SELECT 1 FROM issuance_service.canvas_worker_heartbeats WHERE worker_id='worker-contender' AND metadata->>'phase'='idle')", 15, &mut [&mut worker, &mut contender]).await;
        let blocked: bool = sqlx::query_scalar(case["reclaimer_wait_sql"].as_str().unwrap())
            .fetch_one(pool)
            .await
            .unwrap();
        assert!(!blocked);
        assert_leased_state(
            snapshot(pool, &fixture).await,
            &reference["terminal_pending"],
            1,
        );
    }
    assert_eq!(
        row(pool, case["target_row_sql"].as_str().unwrap()).await,
        target_before
    );
    assert_eq!(
        row(pool, case["journal_sql"].as_str().unwrap()).await,
        json!([])
    );
    barrier.rollback().await.unwrap();
    wait(pool, "SELECT count(*)=2 AND bool_and(metadata->>'phase'='idle') FROM issuance_service.canvas_worker_heartbeats", 20, &mut [&mut worker, &mut contender]).await;
    if recovery_first {
        assert_generation_fenced_state(snapshot(pool, &fixture).await, &reference["completed"], 1);
    } else {
        assert_eq!(snapshot(pool, &fixture).await, reference["completed"]);
    }
    let terminal = row(pool, case["job_row_sql"].as_str().unwrap()).await;
    let target = row(pool, case["target_row_sql"].as_str().unwrap()).await;
    if recovery_first {
        assert_eq!(reference["target_enabled"], false);
        assert_eq!(reference["target_success_timestamp_present"], false);
        assert_eq!(target["enabled"], false);
        assert!(target["last_succeeded_at"].is_null());
        let mut expected = target_before.clone();
        expected["enabled"] = json!(false);
        expected["updated_at"] = target["updated_at"].clone();
        assert_eq!(target, expected, "stale completion changed target state");
    } else {
        assert_atomic_target(&reference, &target_before, &target);
    }
    assert_eq!(
        row(pool, case["journal_sql"].as_str().unwrap()).await,
        reference["terminal_journal"]
    );
    assert_eq!(
        reference["terminal_journal"],
        json!([if recovery_first {
            "dead_letter"
        } else {
            "succeeded"
        }])
    );
    for key in [
        "id",
        "started_at",
        "created_at",
        "attempt_count",
        "max_attempts",
    ] {
        assert_eq!(terminal[key], original[key]);
    }
    assert_eq!(reference["same_job_and_original_start"], true);
    assert_eq!(reference["both_workers_alive_after_completion"], true);
    for child in [&mut worker, &mut contender] {
        child.signal("SIGINT");
        assert_eq!(child.wait().await.code(), Some(130));
    }
    assert_eq!(reference["exit_codes_after_interrupt"], json!([-2, -2]));
    assert_eq!(
        row(pool, case["job_row_sql"].as_str().unwrap()).await,
        terminal
    );
    assert_eq!(
        row(pool, case["target_row_sql"].as_str().unwrap()).await,
        target
    );
    assert_eq!(reference["rows_unchanged_after_exit"], true);
    assert_eq!(
        row(pool, case["journal_sql"].as_str().unwrap()).await,
        reference["terminal_journal"]
    );
    fixture.assert_preserved(pool).await;
}

#[test]
fn rejected_owner_check_rejects_unrelated_or_reference_drift() {
    let reference: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/canvas-worker-provider-recovery-first-oracle.json"
    ))
    .unwrap();
    let mut native = reference["contending"].clone();
    native["heartbeat"]["metadata"]["phase"] = json!("idle");
    native["heartbeat"]["metadata"]["leased_jobs"] = json!(0);
    native["jobs"][0]["result"] = json!({"target_config_version": 1});
    assert_rejected_owner_state(native.clone(), &reference);
    for (field, value) in [("phase", json!("idle")), ("leased_jobs", json!(0))] {
        let mut changed = reference.clone();
        for state in ["contending", "terminal_pending"] {
            changed[state]["heartbeat"]["metadata"][field] = value.clone();
        }
        assert!(std::panic::catch_unwind(|| {
            assert_rejected_owner_state(native.clone(), &changed)
        })
        .is_err());
    }
    for (pointer, value) in [
        ("/heartbeat/metadata/phase", json!("processing")),
        ("/heartbeat/metadata/leased_jobs", json!(1)),
        ("/heartbeat/metadata/processor_configured", json!(false)),
        ("/jobs/0/result", json!({"target_config_version": 2})),
        (
            "/jobs/0/result",
            json!({"target_config_version": 1, "unexpected": true}),
        ),
        ("/jobs/0/status", json!("succeeded")),
        ("/facts", json!([])),
        ("/snapshot/events", json!({})),
        ("/snapshot/application/policy_allowed", json!(false)),
        ("/oauth/secret_enabled", json!(false)),
    ] {
        let mut changed = native.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(
            std::panic::catch_unwind(|| assert_rejected_owner_state(changed, &reference)).is_err()
        );
    }
    for (pointer, value) in [
        ("/stale_owner_path", json!("idle")),
        ("/contending/heartbeat/metadata/phase", json!("idle")),
        ("/contending/heartbeat/metadata/leased_jobs", json!(0)),
        ("/terminal_pending/facts", json!([])),
    ] {
        let mut changed = reference.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(
            std::panic::catch_unwind(|| assert_rejected_owner_state(native.clone(), &changed))
                .is_err()
        );
    }
}

#[test]
fn completion_atomicity_check_rejects_reference_or_target_drift() {
    let reference: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/canvas-worker-provider-completion-oracle.json"
    ))
    .unwrap();
    let before = json!({"enabled":true,"last_succeeded_at":null,"updated_at":"before","config_version":1,"metadata":{"synthetic":true}});
    let mut after = before.clone();
    after["last_succeeded_at"] = json!("after");
    after["updated_at"] = json!("after");
    assert_atomic_target(&reference, &before, &after);
    for (key, value) in [
        ("enabled", json!(false)),
        ("last_succeeded_at", Value::Null),
        ("config_version", json!(2)),
        ("metadata", json!({})),
        ("extra", json!(true)),
    ] {
        let mut changed = after.clone();
        changed[key] = value;
        assert!(
            std::panic::catch_unwind(|| assert_atomic_target(&reference, &before, &changed))
                .is_err()
        );
    }
    for (key, value) in [
        ("reclaimer_blocked_by_completion", json!(false)),
        ("target_enabled", json!(true)),
        ("target_success_timestamp_present", json!(true)),
    ] {
        let mut changed = reference.clone();
        changed[key] = value;
        assert!(
            std::panic::catch_unwind(|| assert_atomic_target(&changed, &before, &after)).is_err()
        );
    }
}
