//! Actual provider interruption using independently frozen published state.
use super::{
    canvas_worker_process_signals::OwnedWorker,
    canvas_worker_rest_replay::{prepare, worker_environment, WorkerFixture},
};
use serde_json::Value;
use sqlx::PgPool;
use std::{path::PathBuf, time::Duration};

pub(super) fn assert_leased_state(observed: Value, published: &Value, target_generation: i32) {
    for job in published["jobs"].as_array().unwrap() {
        assert_eq!(job["status"], "leased");
    }
    assert_generation_fenced_state(observed, published, target_generation);
}

pub(super) fn assert_generation_fenced_state(
    observed: Value,
    published: &Value,
    target_generation: i32,
) {
    // The native repository retains this internal fence for safe final-attempt
    // recovery. Public job views omit it. Assert its exact expected value and
    // every other field; never strip arbitrary native result metadata to pass.
    let mut expected = published.clone();
    for job in expected["jobs"].as_array_mut().unwrap() {
        assert!(
            job["status"] == "leased"
                || (job["status"] == "retry"
                    && job["last_error_code"] == "canvas_worker_lease_expired")
                || (job["status"] == "dead_letter"
                    && job["last_error_code"] == "canvas_worker_lease_expired"
                    && job["attempt_count"].as_i64().unwrap()
                        >= job["max_attempts"].as_i64().unwrap()
                    && job["completed"] == true
                    && job["lease_owner_present"] == false
                    && job["lease_expires_present"] == false)
        );
        assert_eq!(job["result"], serde_json::json!({}));
        job["result"] = serde_json::json!({"target_config_version": target_generation});
    }
    assert_eq!(observed, expected);
}

#[test]
fn expired_final_requires_exact_generation_and_exhausted_terminal_state() {
    let reference: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/canvas-worker-provider-final-oracle.json"
    ))
    .unwrap();
    let published = &reference["completed"];
    let mut native = published.clone();
    native["jobs"][0]["result"] = serde_json::json!({"target_config_version": 1});
    assert_generation_fenced_state(native.clone(), published, 1);
    for result in [
        serde_json::json!({}),
        serde_json::json!({"target_config_version": 2}),
        serde_json::json!({"target_config_version": "1"}),
        serde_json::json!({"target_config_version": 1, "unexpected": true}),
    ] {
        let mut invalid = native.clone();
        invalid["jobs"][0]["result"] = result;
        assert!(
            std::panic::catch_unwind(|| assert_generation_fenced_state(invalid, published, 1))
                .is_err()
        );
    }
    for (field, value) in [
        ("status", serde_json::json!("succeeded")),
        (
            "last_error_code",
            serde_json::json!("canvas_provider_failure"),
        ),
        ("attempt_count", serde_json::json!(7)),
        ("completed", serde_json::json!(false)),
        ("lease_owner_present", serde_json::json!(true)),
        ("lease_expires_present", serde_json::json!(true)),
    ] {
        // Even if both projections agree, this exception cannot accept an
        // unrelated failure or a nonfinal/incomplete recovery outcome.
        let mut invalid_reference = published.clone();
        let mut invalid_native = native.clone();
        invalid_reference["jobs"][0][field] = value.clone();
        invalid_native["jobs"][0][field] = value;
        assert!(std::panic::catch_unwind(|| assert_generation_fenced_state(
            invalid_native,
            &invalid_reference,
            1
        ))
        .is_err());
    }
    let mut invalid = native.clone();
    invalid["oauth"]["secret_enabled"] = serde_json::json!(false);
    assert!(
        std::panic::catch_unwind(|| assert_generation_fenced_state(invalid, published, 1)).is_err()
    );
    assert!(std::panic::catch_unwind(|| assert_leased_state(native, published, 1)).is_err());
}

#[test]
fn leased_state_requires_exact_native_generation_and_all_other_fields() {
    let reference: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/canvas-worker-provider-signals-oracle.json"
    ))
    .unwrap();
    let published = &reference["SIGINT"]["before"];
    let mut native = published.clone();
    native["jobs"][0]["result"] = serde_json::json!({"target_config_version": 1});
    assert_leased_state(native.clone(), published, 1);
    for result in [
        serde_json::json!({}),
        serde_json::json!({"target_config_version": 2}),
        serde_json::json!({"target_config_version": "1"}),
        serde_json::json!({"target_config_version": 1, "unexpected": true}),
    ] {
        let mut invalid = native.clone();
        invalid["jobs"][0]["result"] = result;
        assert!(std::panic::catch_unwind(|| assert_leased_state(invalid, published, 1)).is_err());
    }
    let mut invalid = native;
    invalid["oauth"]["secret_enabled"] = Value::Bool(false);
    assert!(std::panic::catch_unwind(|| assert_leased_state(invalid, published, 1)).is_err());
    assert_eq!(published["jobs"][0]["result"], serde_json::json!({}));
}

pub(super) async fn snapshot(pool: &PgPool, fixture: &WorkerFixture) -> Value {
    let mut state = serde_json::Map::new();
    for (key, query) in [
        ("jobs", fixture.spec["jobs_sql"].as_str().unwrap()),
        ("facts", fixture.spec["facts_sql"].as_str().unwrap()),
        ("oauth", fixture.spec["oauth_sql"].as_str().unwrap()),
        ("snapshot", fixture.shared["snapshot_sql"].as_str().unwrap()),
        ("heartbeat", "SELECT jsonb_build_object('role',role,'metadata',metadata) FROM issuance_service.canvas_worker_heartbeats WHERE worker_id='worker-rest'"),
    ] {
        let value: Value = sqlx::query_scalar(query).fetch_one(pool).await.unwrap();
        state.insert(key.into(), value);
    }
    fixture.assert_preserved(pool).await;
    Value::Object(state)
}

#[test]
fn expired_retry_requires_exact_generation_without_relaxing_terminal_results() {
    let reference: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/canvas-worker-provider-recovery-oracle.json"
    ))
    .unwrap();
    let published = &reference["recovery"]["reclaimed"];
    let mut native = published.clone();
    native["jobs"][0]["result"] = serde_json::json!({"target_config_version": 1});
    assert_generation_fenced_state(native.clone(), published, 1);
    for field in ["last_error_code", "status"] {
        let mut invalid = native.clone();
        invalid["jobs"][0][field] = Value::String("unexpected".into());
        assert!(
            std::panic::catch_unwind(|| assert_generation_fenced_state(invalid, published, 1))
                .is_err()
        );
    }
    assert!(std::panic::catch_unwind(|| assert_leased_state(native, published, 1)).is_err());
    let completed = &reference["recovery"]["completed"];
    assert!(std::panic::catch_unwind(|| assert_generation_fenced_state(
        completed.clone(),
        completed,
        1
    ))
    .is_err());
}

pub(super) fn control_directory() -> PathBuf {
    let control = PathBuf::from(std::env::var("MARTY_CANVAS_WORKER_SIGNAL_CONTROL").unwrap())
        .canonicalize()
        .unwrap();
    let certificate = PathBuf::from(std::env::var("SSL_CERT_FILE").unwrap())
        .canonicalize()
        .unwrap();
    assert_eq!(
        control,
        certificate.parent().unwrap().join("native-control")
    );
    assert!(control.is_dir());
    control
}

pub(super) async fn await_marker(
    control: &std::path::Path,
    marker: &str,
    worker: &mut OwnedWorker,
) {
    assert!(matches!(marker, "request-received" | "reclaimer-observed"));
    tokio::time::timeout(Duration::from_secs(20), async {
        while !control.join(marker).is_file() {
            assert!(
                worker.0.try_wait().unwrap().is_none(),
                "worker exited before parent observation"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("parent must acknowledge actual provider observation");
}

pub(super) fn mark(control: &std::path::Path, marker: &str) {
    assert!(matches!(marker, "release-response" | "reclaimer-idle"));
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(control.join(marker))
        .unwrap();
}

pub async fn replay(pool: &PgPool, database_url: &str, origin: &str, signal: &str) {
    assert!(matches!(signal, "SIGINT" | "SIGTERM" | "SIGKILL"));
    let fixture = prepare(pool, origin, "rest").await;
    let reference: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/canvas-worker-provider-signals-oracle.json"
    ))
    .unwrap();
    let expected = &reference[signal];
    let control = control_directory();
    let mut worker = OwnedWorker::start_with_environment(
        database_url,
        "worker-rest",
        &worker_environment(origin),
    );
    await_marker(&control, "request-received", &mut worker).await;
    assert_leased_state(snapshot(pool, &fixture).await, &expected["before"], 1);
    worker.signal(signal);
    if signal == "SIGTERM" {
        // Deliberate native improvement: TERM requests a drain, not Python's
        // default abrupt exit. The parent keeps the response held until this
        // liveness/state check finishes; no database timestamp is advanced.
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert!(
            worker.0.try_wait().unwrap().is_none(),
            "TERM exited before provider drain"
        );
        assert_leased_state(snapshot(pool, &fixture).await, &expected["before"], 1);
        mark(&control, "release-response");
    }
    let status = worker.wait().await;
    match signal {
        "SIGTERM" => {
            assert_eq!(expected["exit_code"], -15);
            assert_eq!(status.code(), Some(0));
            let rest: Value = serde_json::from_str(include_str!(
                "../../../../../contracts/canvas-worker-rest-oracle.json"
            ))
            .unwrap();
            let state = snapshot(pool, &fixture).await;
            for (key, value) in state.as_object().unwrap() {
                assert_eq!(value, &rest["observations"][0][key], "drained {key}");
            }
        }
        "SIGINT" => {
            assert_eq!(expected["exit_code"], -2);
            assert_eq!(status.code(), Some(130));
            assert_leased_state(snapshot(pool, &fixture).await, &expected["after"], 1);
        }
        "SIGKILL" => {
            assert_eq!(expected["exit_code"], -9);
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                assert_eq!(status.signal(), Some(9));
            }
            assert_eq!(status.code(), None);
            assert_leased_state(snapshot(pool, &fixture).await, &expected["after"], 1);
        }
        _ => unreachable!(),
    }
}
