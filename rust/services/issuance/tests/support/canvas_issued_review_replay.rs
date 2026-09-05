//! Replay observed published Python lifecycle behavior through the actual native
//! processor and PostgreSQL owners. The transport is deliberately controlled.
use super::canvas_published_processor::{run_for_organization, WORKER};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use marty_issuance_service::{
    canvas_sync_processor::{
        CanvasAuthoritativeObservation, CanvasAuthoritativeProvider, CanvasProviderReadError,
        CanvasRosterSnapshot, CanvasSyncResources, NativeCanvasSyncProcessor,
    },
    canvas_sync_processor_postgres::PostgresCanvasSyncProcessorRepository,
    canvas_sync_worker::{CanvasSyncTarget, CanvasSyncWorkerConfig},
};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, OnceLock,
    },
};

fn scenarios() -> &'static Value {
    static SCENARIOS: OnceLock<Value> = OnceLock::new();
    SCENARIOS.get_or_init(|| {
        serde_json::from_str(include_str!(
            "../../../../../contracts/canvas-issued-review-scenarios.json"
        ))
        .unwrap()
    })
}

struct Provider {
    stage: AtomicUsize,
}

#[async_trait]
impl CanvasAuthoritativeProvider for Provider {
    async fn read_requirement(
        &self,
        _: &CanvasSyncResources,
        requirement: &Value,
        user: Option<&str>,
        subject: Option<&str>,
    ) -> Result<CanvasAuthoritativeObservation, CanvasProviderReadError> {
        assert_eq!(requirement["requirement_id"], "assignment");
        assert_eq!(user, Some("7"));
        assert_eq!(subject, Some("subject-7"));
        let stage = &scenarios()["stages"][self.stage.load(Ordering::SeqCst)];
        if stage.get("error").is_some() {
            return Err(CanvasProviderReadError::Unavailable);
        }
        let score = stage["score"].as_f64().unwrap();
        let timestamp = format!(
            "2026-09-01T00:{:02}:00Z",
            stage["revision"].as_u64().unwrap()
        );
        Ok(CanvasAuthoritativeObservation {
            assertion:json!({"completed":true,"score":score,"score_maximum":100.0,"score_percent":score,
                "provider_state":"graded","requirement_count":null,"requirement_completed_count":null}).as_object().unwrap().clone(),
            source_payload:json!({"id":11,"assignment_id":9,"score":stage["score"],"workflow_state":"graded",
                "points_possible":100,"updated_at":timestamp}).as_object().unwrap().clone(),
            verification_method:"CANVAS_OAUTH_API_READ",
            effective_at:Some(DateTime::parse_from_rfc3339(&timestamp).unwrap().with_timezone(&Utc)),
        })
    }
    async fn roster(
        &self,
        _: &CanvasSyncTarget,
        _: &CanvasSyncResources,
        _: &[Value],
        _: usize,
    ) -> Result<CanvasRosterSnapshot, CanvasProviderReadError> {
        panic!("Issued drift must not read a roster")
    }
}

pub async fn replay(pool: &PgPool, expected: &Value) {
    for statement in scenarios()["seed"].as_array().unwrap() {
        sqlx::raw_sql(statement.as_str().unwrap())
            .execute(pool)
            .await
            .unwrap();
    }
    let credential_query = scenarios()["preserved_rows_sql"].as_str().unwrap();
    let original: Value = sqlx::query_scalar(credential_query)
        .fetch_one(pool)
        .await
        .unwrap();
    let provider = Arc::new(Provider {
        stage: AtomicUsize::new(0),
    });
    let config = CanvasSyncWorkerConfig::from_values(&BTreeMap::from([
        ("CANVAS_SYNC_WORKER_ID".into(), WORKER.into()),
        ("CANVAS_PORTABLE_INTEGRATION_ENABLED".into(), "true".into()),
        ("CANVAS_PILOT_ORGANIZATION_IDS".into(), "org-review".into()),
    ]))
    .unwrap();
    let processor = NativeCanvasSyncProcessor::new(
        Arc::new(PostgresCanvasSyncProcessorRepository::new(pool.clone())),
        provider.clone(),
        config,
        1,
        10,
    );
    let stages = scenarios()["stages"].as_array().unwrap();
    assert_eq!(
        stages.len(),
        expected["observations"].as_array().unwrap().len()
    );
    for (index, stage) in stages.iter().enumerate() {
        provider.stage.store(index, Ordering::SeqCst);
        if let Some(action) = stage.get("action").and_then(Value::as_str) {
            let affected = sqlx::raw_sql(scenarios()["actions"][action].as_str().unwrap())
                .execute(pool)
                .await
                .unwrap();
            assert_eq!(affected.rows_affected(), 1);
        }
        let result = run_for_organization(pool, &processor, "target-review", "org-review").await;
        let mut observed = match result {
            Ok(result) => json!({"result":result}),
            Err(error) => json!({"error":{"code":error.code,"retryable":error.retryable}}),
        };
        observed["name"] = stage["name"].clone();
        observed["snapshot"] =
            sqlx::query_scalar::<_, Value>(scenarios()["snapshot_sql"].as_str().unwrap())
                .fetch_one(pool)
                .await
                .unwrap();
        let current: Value = sqlx::query_scalar(credential_query)
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(
            current, original,
            "issued credential changed at {}",
            stage["name"]
        );
        assert_eq!(
            observed, expected["observations"][index],
            "published Python/native mismatch at {}",
            stage["name"]
        );
        eprintln!("Issued-review Python/native parity: {}", stage["name"]);
    }
}
