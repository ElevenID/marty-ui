//! Real native worker, published schema, remote DELETE and durable token cleanup.
use super::{
    canvas_worker_concurrent_replay::{start_workers_at_barrier, WorkerBarrier},
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
    let matrix = matrix_for(kind);
    let reference: Value = serde_json::from_str(match kind {
        "oauth-revocation-lease" => include_str!(
            "../../../../../contracts/canvas-worker-oauth-revocation-lease-oracle.json"
        ),
        "oauth-revocation-queue" => include_str!(
            "../../../../../contracts/canvas-worker-oauth-revocation-queue-oracle.json"
        ),
        "oauth-revocation-backoff" => include_str!(
            "../../../../../contracts/canvas-worker-oauth-revocation-backoff-oracle.json"
        ),
        "oauth-revocation-retry-after" => include_str!(
            "../../../../../contracts/canvas-worker-oauth-revocation-retry-after-oracle.json"
        ),
        "oauth-revocation-fence" => include_str!(
            "../../../../../contracts/canvas-worker-oauth-revocation-fence-oracle.json"
        ),
        "oauth-revocation-patch" => include_str!(
            "../../../../../contracts/canvas-worker-oauth-revocation-patch-oracle.json"
        ),
        _ => include_str!("../../../../../contracts/canvas-worker-oauth-revocation-oracle.json"),
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
    let (fixture, before) = prepare_fixture(pool, origin, matrix, case).await;
    let before_queue: Option<Value> = if let Some(statement) = matrix.get("queue_rows_sql") {
        Some(
            sqlx::query_scalar(statement.as_str().unwrap())
                .fetch_one(pool)
                .await
                .unwrap(),
        )
    } else {
        None
    };
    let mut environment = canvas_worker_rest_replay::worker_environment(origin);
    if let Some(overrides) = case.get("environment") {
        for (key, value) in overrides.as_object().unwrap() {
            assert!(matches!(
                key.as_str(),
                "CANVAS_OAUTH_REVOCATION_BATCH_SIZE" | "CANVAS_SYNC_WORKER_LEASE_SECONDS"
            ));
            environment.insert(key.clone(), value.as_str().unwrap().into());
        }
    }
    let mut patch_attempt_observed = false;
    let mut worker = if kind == "oauth-revocation-patch" {
        start_workers_at_barrier(
            pool,
            database_url,
            &environment,
            WorkerBarrier {
                worker_ids: &["worker-revocation"],
                barrier_sql: matrix["barrier_sql"].as_str().unwrap(),
                blocked_sql: matrix["blocked_sql"].as_str().unwrap(),
                expected_jobs: 0,
                release_sql: &[],
            },
            || {
                patch_attempt_observed = true;
            },
        )
        .await
        .pop()
        .unwrap()
    } else {
        OwnedWorker::start_with_environment(database_url, "worker-revocation", &environment)
    };
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
                "native revocation worker exited before durable completion"
            );
            let heartbeat: Option<Value> =
                sqlx::query_scalar(matrix["heartbeat_sql"].as_str().unwrap())
                    .fetch_optional(pool)
                    .await
                    .unwrap();
            if let Some(heartbeat) = heartbeat {
                let completed = if let Some(statement) = case.get("completion_sql") {
                    sqlx::query_scalar::<_, bool>(statement.as_str().unwrap())
                        .fetch_one(pool)
                        .await
                        .unwrap()
                } else {
                    true
                };
                if heartbeat["metadata"]["phase"]
                    == case
                        .get("completion_phase")
                        .and_then(Value::as_str)
                        .unwrap_or("idle")
                    && completed
                {
                    break heartbeat;
                }
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("actual native revocation must reach the expected durable phase");
    // SIGINT behavior has a separate qualified process gate. Here stop only
    // this owned child after the observed cycle, before reading durable state.
    worker.signal("SIGINT");
    assert_eq!(worker.wait().await.code(), Some(130));
    let queue = if let Some(before_queue) = before_queue {
        let order: Vec<String> =
            sqlx::query_scalar::<_, Value>(matrix["queue_order_sql"].as_str().unwrap())
                .fetch_one(pool)
                .await
                .map(|value| serde_json::from_value(value).unwrap())
                .unwrap();
        let after_queue: Value = sqlx::query_scalar(matrix["queue_rows_sql"].as_str().unwrap())
            .fetch_one(pool)
            .await
            .unwrap();
        let before_queue = before_queue.as_object().unwrap();
        let after_queue = after_queue.as_object().unwrap();
        assert_eq!(
            before_queue
                .keys()
                .collect::<std::collections::BTreeSet<_>>(),
            after_queue.keys().collect()
        );
        assert_eq!(
            order.len(),
            case["request_count"].as_u64().unwrap() as usize
        );
        assert_eq!(
            order.len(),
            order
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
        );
        for (id, row) in before_queue {
            if !order.contains(id) {
                assert_eq!(&after_queue[id], row, "unselected connection changed: {id}");
            }
        }
        let connections: Value = sqlx::query_scalar(matrix["queue_state_sql"].as_str().unwrap())
            .fetch_one(pool)
            .await
            .unwrap();
        assert!(
            sqlx::query_scalar::<_, bool>(matrix["queue_delay_sql"].as_str().unwrap())
                .fetch_one(pool)
                .await
                .unwrap()
        );
        let mut observation = json!({"lease_order": order, "connections": connections, "unselected_rows_unchanged": true});
        if let Some(seconds) = case.get("lease_seconds") {
            let durations: Value =
                sqlx::query_scalar(matrix["lease_journal_sql"].as_str().unwrap())
                    .fetch_one(pool)
                    .await
                    .unwrap();
            let durations = durations.as_array().unwrap();
            assert_eq!(
                durations.len(),
                case["request_count"].as_u64().unwrap() as usize
            );
            assert!(durations
                .iter()
                .all(|value| (value.as_f64().unwrap() - seconds.as_f64().unwrap()).abs() <= 0.1));
            observation["acquired_leases"] =
                json!({"count": durations.len(), "seconds": seconds, "all_within_tolerance": true});
        }
        Some(observation)
    } else {
        None
    };
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
    let timing = if queue.is_some() {
        json!({"kind": "selected_bounds", "matches": true})
    } else if kind == "oauth-revocation-retry-after" {
        assert_eq!(secrets, before);
        // Explicit storage mapping: OAuth revoke_retry_at is the shared
        // comparator's available_at. The parent owns the emitted HTTP date
        // and verifies all actual timing evidence, including bounded cases.
        canvas_worker_rest_replay::print_retry_timing(pool,
            "SELECT revoke_retry_at,updated_at FROM issuance_service.canvas_oauth_connections WHERE id='worker-rest-connection'"
        ).await;
        Value::Null
    } else if fence.is_some() {
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
    if kind == "oauth-revocation-patch" {
        assert!(patch_attempt_observed);
        actual["disconnect_marker_update_observed"] = json!(true);
    }
    if let Some(queue) = queue {
        actual["queue"] = queue;
    }
    let mut expected = reference[name].as_object().unwrap().clone();
    // HTTP observations are compared in full by the actual HTTPS owner.
    // Published source hashes are verified by independent reference regeneration.
    assert!(expected.remove("requests").is_some());
    assert!(expected.remove("source_sha256").is_some());
    if kind == "oauth-revocation-retry-after" {
        // No invented success flag: the HTTPS parent compares the actual
        // durable timestamps to this frozen timing expectation in full.
        assert!(expected.remove("retry_timing").is_some());
        assert!(actual
            .as_object_mut()
            .unwrap()
            .remove("retry_timing")
            .is_some());
    }
    assert_eq!(
        actual,
        Value::Object(expected),
        "actual native revocation {name}"
    );
}

fn matrix_for(kind: &str) -> &'static Value {
    assert!(matches!(
        kind,
        "oauth-revocation"
            | "oauth-revocation-fence"
            | "oauth-revocation-patch"
            | "oauth-revocation-retry-after"
            | "oauth-revocation-backoff"
            | "oauth-revocation-queue"
            | "oauth-revocation-lease"
    ));
    static MATRIX: OnceLock<Value> = OnceLock::new();
    static FENCE_MATRIX: OnceLock<Value> = OnceLock::new();
    static PATCH_MATRIX: OnceLock<Value> = OnceLock::new();
    static RETRY_MATRIX: OnceLock<Value> = OnceLock::new();
    static BACKOFF_MATRIX: OnceLock<Value> = OnceLock::new();
    static QUEUE_MATRIX: OnceLock<Value> = OnceLock::new();
    static LEASE_MATRIX: OnceLock<Value> = OnceLock::new();
    let base = MATRIX.get_or_init(|| {
        serde_json::from_str(include_str!(
            "../../../../../contracts/canvas-worker-oauth-revocation-scenarios.json"
        ))
        .unwrap()
    });
    let base = if kind == "oauth-revocation-lease" {
        matrix_for("oauth-revocation-queue")
    } else {
        base
    };
    let extension = match kind {
        "oauth-revocation-lease" => Some((
            &LEASE_MATRIX,
            include_str!("../../../../../contracts/canvas-worker-oauth-revocation-lease-scenarios.json"),
        )),
        "oauth-revocation-queue" => Some((
            &QUEUE_MATRIX,
            include_str!("../../../../../contracts/canvas-worker-oauth-revocation-queue-scenarios.json"),
        )),
        "oauth-revocation-backoff" => Some((
            &BACKOFF_MATRIX,
            include_str!("../../../../../contracts/canvas-worker-oauth-revocation-backoff-scenarios.json"),
        )),
        "oauth-revocation-retry-after" => Some((
            &RETRY_MATRIX,
            include_str!("../../../../../contracts/canvas-worker-oauth-revocation-retry-after-scenarios.json"),
        )),
        "oauth-revocation-fence" => Some((
            &FENCE_MATRIX,
            include_str!(
                "../../../../../contracts/canvas-worker-oauth-revocation-fence-scenarios.json"
            ),
        )),
        "oauth-revocation-patch" => Some((
            &PATCH_MATRIX,
            include_str!(
                "../../../../../contracts/canvas-worker-oauth-revocation-patch-scenarios.json"
            ),
        )),
        _ => None,
    };
    if let Some((storage, source)) = extension {
        storage.get_or_init(|| {
            let extension: Value = serde_json::from_str(source).unwrap();
            let mut merged = base.as_object().unwrap().clone();
            merged.extend(extension.as_object().unwrap().clone());
            Value::Object(merged)
        })
    } else {
        base
    }
}

async fn prepare_fixture(
    pool: &PgPool,
    origin: &str,
    matrix: &'static Value,
    case: &'static Value,
) -> (canvas_worker_rest_replay::WorkerFixture, Value) {
    let fixture = canvas_worker_rest_replay::prepare(pool, origin, "rest").await;
    for statement in matrix["seed"].as_array().unwrap() {
        sqlx::raw_sql(statement.as_str().unwrap())
            .execute(pool)
            .await
            .unwrap();
    }
    if let Some(statements) = case.get("seed") {
        for statement in statements.as_array().unwrap() {
            sqlx::raw_sql(statement.as_str().unwrap())
                .execute(pool)
                .await
                .unwrap();
        }
    }
    if let Some(count) = case.get("retry_count") {
        let seeded: Value = sqlx::query_scalar(matrix["connection_sql"].as_str().unwrap())
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(&seeded["retry_count"], count);
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
    for key in ["before_start_sql", "case_before_start_sql"] {
        if let Some(statements) = matrix.get(key) {
            for statement in statements.as_array().unwrap() {
                sqlx::raw_sql(statement.as_str().unwrap())
                    .execute(pool)
                    .await
                    .unwrap();
            }
        }
    }
    (fixture, before)
}

pub async fn assert_queue_repository_selection(pool: &PgPool) {
    use marty_issuance_service::{
        canvas_oauth::CanvasOAuthRepository, canvas_oauth_postgres::PostgresCanvasOAuthRepository,
    };
    let matrix = matrix_for("oauth-revocation-queue");
    let reference: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/canvas-worker-oauth-revocation-queue-oracle.json"
    ))
    .unwrap();
    let (fixture, _) =
        prepare_fixture(pool, "https://127.0.0.1:1", matrix, &matrix["cases"][0]).await;
    let repository = PostgresCanvasOAuthRepository::new(pool.clone());
    for case in matrix["cases"].as_array().unwrap() {
        let limit = case["environment"]["CANVAS_OAUTH_REVOCATION_BATCH_SIZE"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let ids = repository
            .due_revocations(limit)
            .await
            .unwrap()
            .into_iter()
            .map(|connection| connection.id)
            .collect::<Vec<_>>();
        assert_eq!(
            json!(ids),
            reference[case["name"].as_str().unwrap()]["queue"]["lease_order"],
            "real repository selection must match actual published acquisition order"
        );
    }
    fixture.assert_issued_rows_preserved(pool).await;
}
