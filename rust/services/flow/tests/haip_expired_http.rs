use std::{env, error::Error, str::FromStr, sync::Arc};

use axum::{body::Body, http::Request};
use chrono::{Duration, Utc};
use marty_flow::{
    flow_read_router, FlowHttpApplicationApprovalOptions, FlowHttpState,
    FlowHttpVerificationOptions, FlowProviderRegistry, PostgresFlowRepository,
};
use serde_json::json;
use sqlx::{postgres::PgConnectOptions, PgPool};
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn Error + Send + Sync>>;

#[tokio::test]
async fn expired_and_cancelled_legacy_haip_http_submissions_need_no_private_key() -> TestResult {
    let Ok(database_url) = env::var("HAIP_FLOW_POSTGRES_TEST_URL") else {
        eprintln!("skipped: requires an isolated HAIP Flow PostgreSQL test database");
        return Ok(());
    };
    let options = PgConnectOptions::from_str(&database_url)?;
    assert!(
        matches!(options.get_host(), "127.0.0.1" | "localhost"),
        "HAIP Flow PostgreSQL test requires loopback"
    );
    assert_eq!(options.get_database(), Some("marty_haip_expiry_test"));
    let pool = PgPool::connect_with(options).await?;
    sqlx::raw_sql(include_str!("../migrations/0001_flow_schema.sql"))
        .execute(&pool)
        .await?;

    let now = Utc::now();
    for (id, status, expires_at) in [
        (
            "90000000-0000-0000-0000-000000000901",
            "awaiting_wallet",
            now - Duration::minutes(1),
        ),
        (
            "90000000-0000-0000-0000-000000000902",
            "awaiting_wallet",
            now - Duration::minutes(1),
        ),
        (
            "90000000-0000-0000-0000-000000000903",
            "cancelled",
            now + Duration::minutes(5),
        ),
        (
            "90000000-0000-0000-0000-000000000904",
            "cancelled",
            now + Duration::minutes(5),
        ),
    ] {
        sqlx::query(
            "INSERT INTO flow_service.flow_instances \
             (id, flow_definition_id, organization_id, status, context, \
              expires_at, created_at, updated_at) \
             VALUES ($1, '__verification__', 'org-1', $2, $3, $4, $5, $5)",
        )
        .bind(id)
        .bind(status)
        .bind(json!({"haip_response_encryption_key_envelope": "vault:synthetic"}))
        .bind(expires_at)
        .bind(now - Duration::minutes(5))
        .execute(&pool)
        .await?;
    }
    let state = FlowHttpState {
        repository: PostgresFlowRepository::new(pool.clone()),
        providers: Arc::new(FlowProviderRegistry::default()),
        public_base_url: "https://verifier.example".into(),
        verification: FlowHttpVerificationOptions::default(),
        application_approval: FlowHttpApplicationApprovalOptions::default(),
    };
    let direct = flow_read_router(state.clone())
        .oneshot(
            Request::post("/v1/flows/instances/90000000-0000-0000-0000-000000000901/submit")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("response=not-a-jwe"))?,
        )
        .await?;
    assert_eq!(direct.status(), 410);
    let dc_api = flow_read_router(state.clone())
        .oneshot(
            Request::post("/v1/flows/instances/90000000-0000-0000-0000-000000000902/submit/dc-api")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"protocol":"openid4vp-v1-signed","data":{"response":"not-a-jwe"}})
                        .to_string(),
                ))?,
        )
        .await?;
    assert_eq!(dc_api.status(), 410);
    let cancelled_direct = flow_read_router(state.clone())
        .oneshot(
            Request::post("/v1/flows/instances/90000000-0000-0000-0000-000000000903/submit")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("response=not-a-jwe"))?,
        )
        .await?;
    assert_eq!(cancelled_direct.status(), 400);
    let body = axum::body::to_bytes(cancelled_direct.into_body(), 16_384).await?;
    let error: serde_json::Value = serde_json::from_slice(&body)?;
    assert_eq!(error["error"], "verification_submission_invalid");
    let cancelled_dc_api = flow_read_router(state)
        .oneshot(
            Request::post("/v1/flows/instances/90000000-0000-0000-0000-000000000904/submit/dc-api")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"protocol":"openid4vp-v1-signed","data":{"response":"not-a-jwe"}})
                        .to_string(),
                ))?,
        )
        .await?;
    assert_eq!(cancelled_dc_api.status(), 400);
    let body = axum::body::to_bytes(cancelled_dc_api.into_body(), 16_384).await?;
    let error: serde_json::Value = serde_json::from_slice(&body)?;
    assert_eq!(error["error"], "verification_submission_invalid");
    let statuses: Vec<String> =
        sqlx::query_scalar("SELECT status FROM flow_service.flow_instances ORDER BY id")
            .fetch_all(&pool)
            .await?;
    assert_eq!(statuses, ["expired", "expired", "cancelled", "cancelled"]);
    pool.close().await;
    Ok(())
}
