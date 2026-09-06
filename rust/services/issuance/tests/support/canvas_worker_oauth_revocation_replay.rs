//! Real native worker, published schema, remote DELETE and durable token cleanup.
use super::{
    canvas_worker_process_signals::OwnedWorker,
    canvas_worker_provider_signals_replay::{await_marker, control_directory, mark},
    canvas_worker_rest_replay,
};
use marty_issuance_service::{
    canvas_oauth::CanvasOAuthSecretVault, integration_secret::NewIntegrationSecret,
};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::{sync::OnceLock, time::Duration};

pub async fn replay(pool: &PgPool, database_url: &str, origin: &str, name: &str, kind: &str) {
    assert!(matches!(
        kind,
        "oauth-revocation" | "oauth-revocation-fence"
    ));
    static MATRIX: OnceLock<Value> = OnceLock::new();
    static FENCE_MATRIX: OnceLock<Value> = OnceLock::new();
    let base = MATRIX.get_or_init(|| {
        serde_json::from_str(include_str!(
            "../../../../../contracts/canvas-worker-oauth-revocation-scenarios.json"
        ))
        .unwrap()
    });
    let matrix = if kind == "oauth-revocation-fence" {
        FENCE_MATRIX.get_or_init(|| {
            let extension: Value = serde_json::from_str(include_str!(
                "../../../../../contracts/canvas-worker-oauth-revocation-fence-scenarios.json"
            ))
            .unwrap();
            let mut merged = base.as_object().unwrap().clone();
            merged.extend(extension.as_object().unwrap().clone());
            Value::Object(merged)
        })
    } else {
        base
    };
    let reference: Value = serde_json::from_str(if kind == "oauth-revocation-fence" {
        include_str!("../../../../../contracts/canvas-worker-oauth-revocation-fence-oracle.json")
    } else {
        include_str!("../../../../../contracts/canvas-worker-oauth-revocation-oracle.json")
    })
    .unwrap();
    let matching = matrix["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| case["name"] == name)
        .collect::<Vec<_>>();
    assert_eq!(matching.len(), 1);
    let case = matching[0];
    let fixture = canvas_worker_rest_replay::prepare(pool, origin, "rest").await;
    for statement in matrix["seed"].as_array().unwrap() {
        sqlx::raw_sql(statement.as_str().unwrap())
            .execute(pool)
            .await
            .unwrap();
    }
    for secret in matrix["additional_secrets"].as_array().unwrap() {
        fixture
            .vault
            .save(NewIntegrationSecret {
                id: secret[0].as_str().unwrap().into(),
                organization_id: secret[1].as_str().unwrap().into(),
                name: "Synthetic worker control".into(),
                provider: "canvas".into(),
                purpose: "api_token".into(),
                value: secret[2].as_str().unwrap().into(),
                metadata: json!({}),
            })
            .await
            .unwrap();
    }
    let before: Value = sqlx::query_scalar(matrix["secret_sql"].as_str().unwrap())
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(before.as_object().unwrap().len(), 3);
    for secret in matrix["additional_secrets"].as_array().unwrap() {
        assert_ne!(before[secret[0].as_str().unwrap()], secret[2]);
    }
    let environment = canvas_worker_rest_replay::worker_environment(origin);
    let mut worker =
        OwnedWorker::start_with_environment(database_url, "worker-revocation", &environment);
    let fence = if kind == "oauth-revocation-fence" {
        let control = control_directory();
        await_marker(&control, "request-received", &mut worker).await;
        let mut transaction = pool.begin().await.unwrap();
        let before_fence: Value = sqlx::query_scalar(matrix["fence_sql"].as_str().unwrap())
            .fetch_one(&mut *transaction)
            .await
            .unwrap();
        assert_eq!(before_fence["owner"], "worker-revocation");
        assert_eq!(before_fence["lease_unexpired"], true);
        let changed = sqlx::raw_sql(matrix["takeover_sql"].as_str().unwrap())
            .execute(&mut *transaction)
            .await
            .unwrap();
        assert_eq!(changed.rows_affected(), 1);
        let replacement: Value = sqlx::query_scalar(matrix["row_sql"].as_str().unwrap())
            .fetch_one(&mut *transaction)
            .await
            .unwrap();
        let replacement_fence: Value = sqlx::query_scalar(matrix["fence_sql"].as_str().unwrap())
            .fetch_one(&mut *transaction)
            .await
            .unwrap();
        transaction.commit().await.unwrap();
        mark(&control, "release-response");
        Some((
            replacement,
            json!({"before": before_fence, "replacement": replacement_fence}),
        ))
    } else {
        None
    };
    let heartbeat = tokio::time::timeout(Duration::from_secs(25), async {
        loop {
            assert!(
                worker.0.try_wait().unwrap().is_none(),
                "native revocation worker exited before idle"
            );
            let heartbeat: Option<Value> =
                sqlx::query_scalar(matrix["heartbeat_sql"].as_str().unwrap())
                    .fetch_optional(pool)
                    .await
                    .unwrap();
            if let Some(heartbeat) = heartbeat {
                if heartbeat["metadata"]["phase"] == "idle" {
                    break heartbeat;
                }
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("actual native revocation must reach durable idle");
    // SIGINT behavior has a separate qualified process gate. Here stop only
    // this owned child after the observed cycle, before reading durable state.
    worker.signal("SIGINT");
    assert_eq!(worker.wait().await.code(), Some(130));
    let connection: Option<Value> = sqlx::query_scalar(matrix["connection_sql"].as_str().unwrap())
        .fetch_optional(pool)
        .await
        .unwrap();
    let secrets: Value = sqlx::query_scalar(matrix["secret_sql"].as_str().unwrap())
        .fetch_one(pool)
        .await
        .unwrap();
    let platform: Value = sqlx::query_scalar(matrix["platform_sql"].as_str().unwrap())
        .fetch_one(pool)
        .await
        .unwrap();
    let delay: Option<f64> = sqlx::query_scalar(matrix["retry_delay_sql"].as_str().unwrap())
        .fetch_optional(pool)
        .await
        .unwrap();
    let jobs: i64 =
        sqlx::query_scalar("SELECT count(*) FROM issuance_service.canvas_evidence_sync_jobs")
            .fetch_one(pool)
            .await
            .unwrap();
    fixture.assert_issued_rows_preserved(pool).await;
    assert_eq!(
        secrets["worker-unrelated-token"],
        before["worker-unrelated-token"]
    );
    for (id, ciphertext) in secrets.as_object().unwrap() {
        assert_eq!(ciphertext, &before[id]);
    }
    let timing = if fence.is_some() {
        assert_eq!(secrets, before);
        json!({"kind": "preserved", "matches": true})
    } else if let Some(bounds) = case.get("delay_bounds") {
        let delay = delay.expect("retry has an actual stored deadline");
        assert!(
            delay >= bounds[0].as_f64().unwrap() - 0.1
                && delay <= bounds[1].as_f64().unwrap() + 0.1,
            "actual retry timing differs: {delay}"
        );
        json!({"kind": "bounds", "matches": true})
    } else {
        assert!(delay.is_none());
        Value::Null
    };
    let mut retained = secrets
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    retained.sort();
    let mut actual = json!({
        "schema": format!("marty.canvas-worker-{kind}-oracle/v1"), "name": name,
        "connection": connection, "platform": platform, "heartbeat": heartbeat,
        "retained_secret_ids": retained, "retained_ciphertexts_unchanged": true,
        "issued_rows_unchanged": true, "job_count": jobs, "retry_timing": timing,
    });
    if let Some((replacement, mut observation)) = fence {
        let after: Value = sqlx::query_scalar(matrix["row_sql"].as_str().unwrap())
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(
            after, replacement,
            "stale worker changed replacement owner's row"
        );
        observation["replacement_row_unchanged"] = json!(true);
        actual["fence"] = observation;
    }
    let mut expected = reference[name].as_object().unwrap().clone();
    // HTTP observations are compared in full by the actual HTTPS owner.
    // Published source hashes are verified by independent reference regeneration.
    assert!(expected.remove("requests").is_some());
    assert!(expected.remove("source_sha256").is_some());
    assert_eq!(
        actual,
        Value::Object(expected),
        "actual native revocation {name}"
    );
}
