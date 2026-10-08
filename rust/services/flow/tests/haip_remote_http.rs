use std::{env, error::Error, fs, str::FromStr, sync::Arc};

use axum::{body::Body, http::Request};
use chrono::{Duration, Utc};
use marty_flow::{
    flow_read_router, FlowHttpApplicationApprovalOptions, FlowHttpState,
    FlowHttpVerificationOptions, FlowProviderRegistry, HttpSigningProvider, PostgresFlowRepository,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::{postgres::PgConnectOptions, PgPool};
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn Error + Send + Sync>>;

#[derive(Deserialize)]
struct HolderInput {
    organization_id: String,
    flow_instance_id: String,
    key_reference: String,
    public_jwk: Value,
    jwe: String,
    plaintext: String,
}

async fn test_pool(database_url: &str) -> Result<PgPool, Box<dyn Error + Send + Sync>> {
    let options = PgConnectOptions::from_str(database_url)?;
    assert!(matches!(options.get_host(), "127.0.0.1" | "localhost"));
    assert_eq!(options.get_database(), Some("marty_haip_http_test"));
    let pool = PgPool::connect_with(options).await?;
    sqlx::raw_sql(include_str!("../migrations/0001_flow_schema.sql"))
        .execute(&pool)
        .await?;
    Ok(pool)
}

#[tokio::test]
async fn terminal_haip_http_replays_decrypt_with_remote_custody() -> TestResult {
    let settings = (
        env::var("HAIP_FLOW_POSTGRES_TEST_URL"),
        env::var("MARTY_TEST_HAIP_FLOW_INPUT"),
        env::var("MARTY_TEST_SIGNING_KEYS_URL"),
        env::var("MARTY_TEST_SIGNING_KEYS_API_KEY"),
    );
    if settings.0.is_err() && settings.1.is_err() && settings.2.is_err() && settings.3.is_err() {
        eprintln!(
            "skipped: requires isolated HAIP PostgreSQL, a live holder JWE, and Rust signing-keys"
        );
        return Ok(());
    }
    let (database_url, input_path, signing_url, api_key) =
        (settings.0?, settings.1?, settings.2?, settings.3?);
    let pool = test_pool(&database_url).await?;

    let input: HolderInput = serde_json::from_slice(&fs::read(input_path)?)?;
    let plaintext: Value = serde_json::from_str(&input.plaintext)?;
    let vp_token = plaintext["vp_token"]
        .as_str()
        .ok_or("holder vp_token missing")?;
    let state = plaintext["state"].as_str().ok_or("holder state missing")?;
    let now = Utc::now();
    sqlx::query("DELETE FROM flow_service.flow_instances WHERE id = $1")
        .bind(&input.flow_instance_id)
        .execute(&pool)
        .await?;
    sqlx::query(
        "INSERT INTO flow_service.flow_instances \
             (id, flow_definition_id, organization_id, status, context, result, \
              expires_at, completed_at, created_at, updated_at) \
             VALUES ($1, '__verification__', $2, 'completed', $3, $4, $5, $6, $6, $6)",
    )
    .bind(&input.flow_instance_id)
    .bind(&input.organization_id)
    .bind(json!({
        "oid4vp_profile": "haip",
        "haip_response_encryption_key_reference": input.key_reference,
        "haip_response_encryption_public_jwk": input.public_jwk,
        "dc_api_expected_origins": ["https://verifier.example"],
    }))
    .bind(json!({}))
    .bind(now + Duration::minutes(5))
    .bind(now)
    .execute(&pool)
    .await?;
    let provider = HttpSigningProvider::new(&format!("{signing_url}/internal/"), &api_key)?;
    let http_state = FlowHttpState {
        repository: PostgresFlowRepository::new(pool.clone()),
        providers: Arc::new(FlowProviderRegistry {
            flow_key_envelope: Some(Arc::new(provider)),
            ..FlowProviderRegistry::default()
        }),
        public_base_url: "https://verifier.example".into(),
        verification: FlowHttpVerificationOptions::default(),
        application_approval: FlowHttpApplicationApprovalOptions::default(),
    };
    let route = format!("/v1/flows/instances/{}/submit", input.flow_instance_id);

    for status in ["completed", "failed"] {
        let direct_digest = mmf_push::payload_digest(&json!({
            "vp_token": vp_token,
            "presentation_submission": null,
            "state": state,
        }))?;
        set_terminal_result(&pool, &input.flow_instance_id, status, &direct_digest).await?;
        let same = flow_read_router(http_state.clone())
            .oneshot(
                Request::post(&route)
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(format!("response={}", input.jwe)))?,
            )
            .await?;
        assert_eq!(same.status(), 400);
        assert_eq!(error_code(same).await?, "verification_already_processed");

        set_terminal_result(&pool, &input.flow_instance_id, status, &"0".repeat(64)).await?;
        let conflict = flow_read_router(http_state.clone())
            .oneshot(
                Request::post(&route)
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(format!("response={}", input.jwe)))?,
            )
            .await?;
        assert_eq!(conflict.status(), 409);
        assert_eq!(error_code(conflict).await?, "verification_replay_conflict");

        let dc_digest = mmf_push::payload_digest(&json!({
            "vp_token": vp_token,
            "presentation_submission": null,
            "state": null,
        }))?;
        set_terminal_result(&pool, &input.flow_instance_id, status, &dc_digest).await?;
        let dc_route = format!("{route}/dc-api");
        let dc_body = json!({
            "protocol": "openid4vp-v1-signed",
            "origin": "https://verifier.example",
            "data": {"response": input.jwe},
        })
        .to_string();
        let same = flow_read_router(http_state.clone())
            .oneshot(
                Request::post(&dc_route)
                    .header("content-type", "application/json")
                    .body(Body::from(dc_body.clone()))?,
            )
            .await?;
        assert_eq!(same.status(), 200);
        let body = axum::body::to_bytes(same.into_body(), 16_384).await?;
        let result: Value = serde_json::from_slice(&body)?;
        assert_eq!(result["status"], status.to_ascii_uppercase());
        assert_eq!(result["instance_id"], input.flow_instance_id);

        set_terminal_result(&pool, &input.flow_instance_id, status, &"0".repeat(64)).await?;
        let conflict = flow_read_router(http_state.clone())
            .oneshot(
                Request::post(&dc_route)
                    .header("content-type", "application/json")
                    .body(Body::from(dc_body))?,
            )
            .await?;
        assert_eq!(conflict.status(), 409);
        assert_eq!(error_code(conflict).await?, "verification_replay_conflict");
    }
    pool.close().await;
    Ok(())
}

async fn set_terminal_result(pool: &PgPool, id: &str, status: &str, digest: &str) -> TestResult {
    sqlx::query("UPDATE flow_service.flow_instances SET status = $2, result = $3 WHERE id = $1")
        .bind(id)
        .bind(status)
        .bind(json!({
            "submission_digest": digest,
            "evaluation_result": if status == "completed" { "passed" } else { "failed" },
            "decision": if status == "completed" { "allow" } else { "deny" },
        }))
        .execute(pool)
        .await?;
    Ok(())
}

async fn error_code(
    response: axum::response::Response,
) -> Result<String, Box<dyn Error + Send + Sync>> {
    let body = axum::body::to_bytes(response.into_body(), 16_384).await?;
    let error: Value = serde_json::from_slice(&body)?;
    Ok(error["error"]
        .as_str()
        .ok_or("error code missing")?
        .to_owned())
}
