//! Published heartbeat observations through the existing SQL/runtime/policy owners.
use async_trait::async_trait;
use chrono::{DateTime, TimeDelta, Utc};
use marty_issuance_service::{
    canvas_binding_domain::{CanvasApplicationTemplateProjection, CanvasProgramBindingRecord},
    canvas_management_domain::{CanvasOriginPolicy, CanvasPlatformRecord},
    canvas_management_service::CanvasReadinessInputProvider,
    canvas_readiness::evaluate_canvas_binding_readiness,
    canvas_readiness_runtime::{
        CanvasReadinessChallengeProvider, CanvasReadinessDocumentProvider,
        CanvasReadinessDocuments, CanvasReadinessRuntime, CanvasReadinessStateProvider,
        PostgresCanvasReadinessStateProvider,
    },
    canvas_sync_worker::{CanvasSyncWorkerRepository, WorkerHeartbeat},
    canvas_sync_worker_postgres::PostgresCanvasSyncWorkerRepository,
};
use serde_json::{json, Map, Value};
use sqlx::PgPool;
use std::{sync::Arc, time::Duration};

// Unrelated document/signing ports are deliberately inert. Database state and
// heartbeat readiness policy are real; no claim of complete activation parity.
struct UnconfiguredDependencies;

#[async_trait]
impl CanvasReadinessDocumentProvider for UnconfiguredDependencies {
    async fn documents(&self, _: &str) -> CanvasReadinessDocuments {
        CanvasReadinessDocuments::default()
    }
}

#[async_trait]
impl CanvasReadinessChallengeProvider for UnconfiguredDependencies {
    async fn lti_tool_signing_ready(&self, _: DateTime<Utc>) -> bool {
        false
    }
    async fn kms_did_signing_ready(
        &self,
        _: &str,
        _: &Map<String, Value>,
        _: DateTime<Utc>,
    ) -> bool {
        false
    }
}

fn records(now: DateTime<Utc>) -> (CanvasPlatformRecord, CanvasProgramBindingRecord) {
    let mut platform = CanvasPlatformRecord::new_draft(
        "org-heartbeat".into(),
        serde_json::from_value(json!({"canvas_base_url":"https://canvas.example.edu"})).unwrap(),
        CanvasOriginPolicy::default()
            .resolve("https://canvas.example.edu")
            .unwrap(),
        now,
    )
    .unwrap();
    platform.id = "platform-heartbeat".into();
    let template = CanvasApplicationTemplateProjection {
        id: "template-heartbeat".into(),
        organization_id: "org-heartbeat".into(),
        credential_template_id: Some("credential-heartbeat".into()),
        approval_policy_set_id: None,
        active: true,
    };
    let mut binding = CanvasProgramBindingRecord::configure(
        &platform,
        serde_json::from_value(json!({"application_template_id":"template-heartbeat",
            "evidence_requirements":[{"requirement_id":"course", "source":"canvas_rest",
                "fact_type":"canvas.course_completion", "scope":{"course_id":"42"},
                "pass_rule":{"completed":true}, "required":true}]}))
        .unwrap(),
        &template,
        Map::new(),
        None,
        now,
    )
    .unwrap();
    binding.id = "binding-heartbeat".into();
    (platform, binding)
}

async fn check(pool: &PgPool, max_age: u64, now: DateTime<Utc>) -> Value {
    let state = Arc::new(PostgresCanvasReadinessStateProvider::new(
        pool.clone(),
        Duration::from_secs(max_age),
    ));
    let runtime = CanvasReadinessRuntime::new(
        state,
        Arc::new(UnconfiguredDependencies),
        Arc::new(UnconfiguredDependencies),
        false,
        Default::default(),
        Vec::new(),
        Duration::from_secs(900),
    );
    let (platform, binding) = records(now);
    let inputs = runtime.inputs(&platform, &binding, now).await;
    let result = evaluate_canvas_binding_readiness(&platform, &binding, &inputs, now);
    let checks: Vec<_> = result
        .checks
        .iter()
        .filter(|check| check.code == "worker_heartbeat")
        .collect();
    assert_eq!(checks.len(), 1);
    serde_json::to_value(checks[0]).unwrap()
}

pub async fn replay(pool: &PgPool, expected: &Value) {
    let scenarios: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/canvas-heartbeat-readiness-scenarios.json"
    ))
    .unwrap();
    let now: DateTime<Utc> = scenarios["evaluated_at"].as_str().unwrap().parse().unwrap();
    let cases = scenarios["cases"].as_array().unwrap();
    let observations = expected["observations"].as_array().unwrap();
    assert_eq!(observations.len(), cases.len() + 1);
    for (case, observation) in cases.iter().zip(observations) {
        assert_eq!(case["name"], observation["name"]);
        sqlx::query("TRUNCATE issuance_service.canvas_worker_heartbeats")
            .execute(pool)
            .await
            .unwrap();
        for row in case["rows"].as_array().unwrap() {
            sqlx::query(
                "INSERT INTO issuance_service.canvas_worker_heartbeats
                (worker_id, role, started_at, last_heartbeat_at, metadata)
                VALUES ($1, $2, $3, $4, $5)",
            )
            .bind(row["id"].as_str().unwrap())
            .bind(row["role"].as_str().unwrap_or("canvas_sync"))
            .bind(now - TimeDelta::days(1))
            .bind(now - TimeDelta::microseconds(row["age_us"].as_i64().unwrap()))
            .bind(&row["metadata"])
            .execute(pool)
            .await
            .unwrap();
        }
        assert_eq!(
            check(pool, case["max_age_seconds"].as_u64().unwrap(), now).await,
            observation["check"],
            "heartbeat case {}",
            case["name"],
        );
    }
    sqlx::query("ALTER TABLE issuance_service.canvas_worker_heartbeats RENAME TO canvas_worker_heartbeats_unavailable")
        .execute(pool).await.unwrap();
    let state = PostgresCanvasReadinessStateProvider::new(pool.clone(), Duration::from_secs(120));
    assert!(state.worker_heartbeat_configured(now).await.is_err());
    // Exercise the actual runtime's error-to-failed-readiness projection.
    let failed_check = check(pool, 120, now).await;
    sqlx::query("ALTER TABLE issuance_service.canvas_worker_heartbeats_unavailable RENAME TO canvas_worker_heartbeats")
        .execute(pool).await.unwrap();
    assert_eq!(observations.last().unwrap()["name"], "database_failure");
    assert_eq!(failed_check, observations.last().unwrap()["check"]);

    worker_writes_feed_shared_readiness(pool, now).await;
}

async fn worker_writes_feed_shared_readiness(pool: &PgPool, started: DateTime<Utc>) {
    sqlx::query("TRUNCATE issuance_service.canvas_worker_heartbeats")
        .execute(pool)
        .await
        .unwrap();
    let repository = PostgresCanvasSyncWorkerRepository::new(pool.clone());
    for (index, phase) in ["scheduling", "oauth_revocation", "processing", "idle"]
        .iter()
        .enumerate()
    {
        let configured = index % 2 == 0;
        let before: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(pool)
            .await
            .unwrap();
        repository
            .upsert_heartbeat(&WorkerHeartbeat {
                worker_id: "native-worker".into(),
                // A restarted producer must not overwrite the original start time.
                started_at: started + TimeDelta::seconds(i64::try_from(index).unwrap()),
                phase,
                leased_jobs: index,
                processor_configured: configured,
            })
            .await
            .unwrap();
        let (stored_start, heartbeat, role, metadata): (DateTime<Utc>, DateTime<Utc>, String, Value) =
            sqlx::query_as("SELECT started_at, last_heartbeat_at, role, metadata FROM issuance_service.canvas_worker_heartbeats WHERE worker_id = 'native-worker'")
                .fetch_one(pool).await.unwrap();
        let after: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(stored_start, started);
        assert!(heartbeat >= before && heartbeat <= after);
        assert_eq!(role, "canvas_sync");
        assert_eq!(
            metadata,
            json!({"phase":phase,"leased_jobs":index,"process":"standalone","processor_configured":configured})
        );
        assert_eq!(
            check(pool, 120, after).await["status"],
            if configured { "ready" } else { "failed" }
        );
    }
}
