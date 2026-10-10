//! Actual native process startup on published migrations. No provider is called
//! by these empty queues; deferred signing validation has separate use-site tests.
use super::canvas_worker_process_signals::OwnedWorker;
use serde_json::{json, Value};
use sqlx::PgPool;
use std::{collections::BTreeMap, time::Duration};

pub async fn replay(pool: &PgPool, database_url: &str) {
    let scenarios: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/canvas-worker-startup-scenarios.json"
    ))
    .unwrap();
    let cases = scenarios["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 8);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        eprintln!("Actual native startup case: {name}");
        let worker_id = format!("native-startup-{name}");
        let environment: BTreeMap<String, String> =
            serde_json::from_value(case["environment"].clone()).unwrap();
        let url = database_url.replacen(
            "postgresql:",
            &format!("{}:", case["database_scheme"].as_str().unwrap()),
            1,
        );
        let mut worker = OwnedWorker::start_with_environment(&url, &worker_id, &environment);
        let heartbeat = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                assert!(
                    worker.0.try_wait().unwrap().is_none(),
                    "actual worker exited before idle heartbeat: {name}"
                );
                let row: Option<(String, Value)> = sqlx::query_as(
                    "SELECT role, metadata FROM issuance_service.canvas_worker_heartbeats
                     WHERE worker_id = $1 AND metadata->>'phase' = 'idle'",
                )
                .bind(&worker_id)
                .fetch_optional(pool)
                .await
                .unwrap();
                if let Some((role, metadata)) = row {
                    break json!({"role":role,"metadata":metadata});
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await;
        let heartbeat = match heartbeat {
            Ok(heartbeat) => heartbeat,
            Err(_) => {
                let phase: Option<String> = sqlx::query_scalar(
                    "SELECT metadata->>'phase' FROM issuance_service.canvas_worker_heartbeats WHERE worker_id=$1",
                ).bind(&worker_id).fetch_optional(pool).await.unwrap();
                panic!("actual worker must reach idle: case={name}, last phase={phase:?}");
            }
        };
        assert_eq!(
            heartbeat,
            json!({"role":"canvas_sync","metadata":{"leased_jobs":0,"phase":"idle","process":"standalone","processor_configured":true}}),
            "startup case {name}"
        );
        assert!(
            worker.0.try_wait().unwrap().is_none(),
            "startup case {name}"
        );
        let jobs: i64 =
            sqlx::query_scalar("SELECT count(*) FROM issuance_service.canvas_evidence_sync_jobs")
                .fetch_one(pool)
                .await
                .unwrap();
        assert_eq!(jobs, 0, "startup case {name}");
        if cfg!(unix) {
            worker.signal("SIGINT");
            let status = worker.wait().await;
            assert_eq!(status.code(), Some(130), "startup case {name}");
        } else {
            // Windows proves actual boot/heartbeat only. POSIX exit evidence is
            // mandatory in the configured Linux CI run, never fabricated here.
            worker.0.kill().unwrap();
            worker.wait().await;
        }
    }
}
