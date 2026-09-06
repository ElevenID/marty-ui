//! Actual provider interruption using independently frozen published state.
use super::{
    canvas_worker_process_signals::OwnedWorker,
    canvas_worker_rest_replay::{prepare, worker_environment, WorkerFixture},
};
use serde_json::Value;
use sqlx::PgPool;
use std::{path::PathBuf, time::Duration};

async fn snapshot(pool: &PgPool, fixture: &WorkerFixture) -> Value {
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

pub async fn replay(pool: &PgPool, database_url: &str, origin: &str, signal: &str) {
    assert!(matches!(signal, "SIGINT" | "SIGTERM" | "SIGKILL"));
    let fixture = prepare(pool, origin, "rest").await;
    let reference: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/canvas-worker-provider-signals-oracle.json"
    ))
    .unwrap();
    let expected = &reference[signal];
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
    let mut worker = OwnedWorker::start_with_environment(
        database_url,
        "worker-rest",
        &worker_environment(origin),
    );
    tokio::time::timeout(Duration::from_secs(20), async {
        while !control.join("request-received").is_file() {
            assert!(
                worker.0.try_wait().unwrap().is_none(),
                "worker exited before actual HTTPS request"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("parent must observe actual provider I/O");
    assert_eq!(snapshot(pool, &fixture).await, expected["before"]);
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
        assert_eq!(snapshot(pool, &fixture).await, expected["before"]);
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(control.join("release-response"))
            .unwrap();
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
            assert_eq!(snapshot(pool, &fixture).await, expected["after"]);
        }
        "SIGKILL" => {
            assert_eq!(expected["exit_code"], -9);
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                assert_eq!(status.signal(), Some(9));
            }
            assert_eq!(status.code(), None);
            assert_eq!(snapshot(pool, &fixture).await, expected["after"]);
        }
        _ => unreachable!(),
    }
}
