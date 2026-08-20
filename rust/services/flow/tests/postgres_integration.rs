use std::{env, error::Error, str::FromStr};

use chrono::{Duration, Utc};
use marty_flow::{CallbackEvent, FlowInstance, PostgresFlowRepository};
use marty_verification::flow::FlowInstanceStatus;
use mmf_push::WebhookDestinationRegistry;
use serde_json::{json, Value};
use sqlx::{postgres::PgConnectOptions, PgPool};

const TEST_DATABASE_NAME: &str = "marty_atomic_test";
const FIRST_INSTANCE_ID: &str = "90000000-0000-0000-0000-000000000001";
const EXPIRED_INSTANCE_ID: &str = "90000000-0000-0000-0000-000000000002";

type TestResult = Result<(), Box<dyn Error + Send + Sync>>;

#[tokio::test]
async fn postgres_finalization_and_callback_leases_are_atomic() -> TestResult {
    let Ok(database_url) = env::var("FLOW_POSTGRES_TEST_URL") else {
        eprintln!("FLOW_POSTGRES_TEST_URL is not configured; PostgreSQL contract skipped");
        return Ok(());
    };
    let database_url = database_url.replace("postgresql+asyncpg://", "postgresql://");
    let options = PgConnectOptions::from_str(&database_url)?;
    assert!(
        matches!(options.get_host(), "127.0.0.1" | "localhost"),
        "Flow PostgreSQL tests require an isolated loopback database"
    );
    assert_eq!(
        options.get_database(),
        Some(TEST_DATABASE_NAME),
        "Flow PostgreSQL tests require the isolated test database"
    );
    let pool = PgPool::connect_with(options).await?;

    reset_schema(&pool).await?;
    let contract = run_contract(&pool).await;
    let cleanup = sqlx::query("DROP SCHEMA IF EXISTS flow_service CASCADE")
        .execute(&pool)
        .await;
    pool.close().await;
    cleanup?;
    contract
}

async fn run_contract(pool: &PgPool) -> TestResult {
    let repository = PostgresFlowRepository::new(pool.clone());
    let now = Utc::now();
    let now_ms = u64::try_from(now.timestamp_millis())?;
    insert_live_instance(pool, FIRST_INSTANCE_ID, now, None).await?;

    let candidate_a = terminal_instance(FIRST_INSTANCE_ID, now_ms, "allow-a");
    let candidate_b = terminal_instance(FIRST_INSTANCE_ID, now_ms, "allow-b");
    let callback_a = callback(FIRST_INSTANCE_ID, now_ms, "a")?;
    let callback_b = callback(FIRST_INSTANCE_ID, now_ms, "b")?;
    let digest_a = "a".repeat(64);
    let digest_b = "b".repeat(64);
    let replay_expiry = u64::try_from((now + Duration::minutes(5)).timestamp_millis())?;
    let (outcome_a, outcome_b) = tokio::join!(
        repository.finalize_verification(
            &candidate_a,
            &digest_a,
            replay_expiry,
            FlowInstanceStatus::AwaitingWallet,
            Some(&callback_a),
        ),
        repository.finalize_verification(
            &candidate_b,
            &digest_b,
            replay_expiry,
            FlowInstanceStatus::AwaitingWallet,
            Some(&callback_b),
        )
    );
    let outcomes = [outcome_a?, outcome_b?];
    assert_eq!(outcomes.into_iter().filter(|accepted| *accepted).count(), 1);
    let winning_marker = if outcomes[0] { "a" } else { "b" };
    let expected_result = if outcomes[0] {
        candidate_a.result
    } else {
        candidate_b.result
    };

    let (status, stored_result): (String, Option<Value>) =
        sqlx::query_as("SELECT status, result FROM flow_service.flow_instances WHERE id=$1")
            .bind(FIRST_INSTANCE_ID)
            .fetch_one(pool)
            .await?;
    assert_eq!(status, "completed");
    assert_eq!(stored_result, expected_result);
    let replay: (String, String) = sqlx::query_as(
        "SELECT nonce_digest, flow_instance_id FROM flow_service.flow_nonce_consumptions",
    )
    .fetch_one(pool)
    .await?;
    assert_eq!(
        replay,
        (winning_marker.repeat(64), FIRST_INSTANCE_ID.into())
    );
    let (callback_status, callback_payload): (String, Value) =
        sqlx::query_as("SELECT status, payload FROM flow_service.flow_callback_outbox")
            .fetch_one(pool)
            .await?;
    assert_eq!(callback_status, "pending");
    assert_eq!(callback_payload["decision"], winning_marker);

    let claimed = repository
        .claim_due_callbacks(now + Duration::seconds(1), now + Duration::seconds(31), 10)
        .await?;
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].attempt_count, 1);
    assert!(
        !repository
            .mark_callback_delivered(
                &claimed[0].event_id,
                "stale-worker-lease",
                now + Duration::seconds(2),
            )
            .await?
    );
    assert!(
        repository
            .mark_callback_failed(
                &claimed[0].event_id,
                &claimed[0].lease_token,
                now + Duration::seconds(2),
                false,
                "network.failure",
            )
            .await?
    );
    let reclaimed = repository
        .claim_due_callbacks(now + Duration::seconds(3), now + Duration::seconds(33), 10)
        .await?;
    assert_eq!(reclaimed.len(), 1);
    assert_eq!(reclaimed[0].attempt_count, 2);
    assert_ne!(reclaimed[0].lease_token, claimed[0].lease_token);
    assert!(
        !repository
            .mark_callback_delivered(
                &reclaimed[0].event_id,
                &claimed[0].lease_token,
                now + Duration::seconds(4),
            )
            .await?
    );
    assert!(
        repository
            .mark_callback_delivered(
                &reclaimed[0].event_id,
                &reclaimed[0].lease_token,
                now + Duration::seconds(4),
            )
            .await?
    );
    let delivered: (String, String, Value, i32) = sqlx::query_as(
        "SELECT status, destination_url, payload, attempt_count \
         FROM flow_service.flow_callback_outbox",
    )
    .fetch_one(pool)
    .await?;
    assert_eq!(delivered, ("delivered".into(), String::new(), json!({}), 2));

    insert_live_instance(
        pool,
        EXPIRED_INSTANCE_ID,
        now,
        Some(now - Duration::seconds(1)),
    )
    .await?;
    let expired = terminal_instance(EXPIRED_INSTANCE_ID, now_ms, "allow");
    assert!(
        !repository
            .finalize_verification(
                &expired,
                &"f".repeat(64),
                replay_expiry,
                FlowInstanceStatus::AwaitingWallet,
                None,
            )
            .await?
    );
    let expired_status: String =
        sqlx::query_scalar("SELECT status FROM flow_service.flow_instances WHERE id=$1")
            .bind(EXPIRED_INSTANCE_ID)
            .fetch_one(pool)
            .await?;
    assert_eq!(expired_status, "awaiting_wallet");
    let expired_replays: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM flow_service.flow_nonce_consumptions WHERE flow_instance_id=$1",
    )
    .bind(EXPIRED_INSTANCE_ID)
    .fetch_one(pool)
    .await?;
    assert_eq!(expired_replays, 0);
    Ok(())
}

fn terminal_instance(id: &str, now_ms: u64, decision: &str) -> FlowInstance {
    FlowInstance {
        id: id.into(),
        flow_definition_id: "__verification__".into(),
        organization_id: "org-1".into(),
        status: FlowInstanceStatus::Completed,
        current_step_id: None,
        application_flow_key_hash: None,
        context: json!({"request_digest": "c".repeat(64)}),
        step_history: Vec::new(),
        state_history: Vec::new(),
        expires_at_ms: None,
        completed_at_ms: Some(now_ms),
        result: Some(json!({"evaluation_result": "passed", "decision": decision})),
        error: None,
    }
}

fn callback(
    id: &str,
    now_ms: u64,
    decision: &str,
) -> Result<mmf_messaging::Message, mmf_push::PushError> {
    let destinations =
        WebhookDestinationRegistry::parse("org-1|https://callbacks.example/flows/__MARTY_TOKEN__")?;
    Ok(CallbackEvent::new(
        id,
        "org-1",
        format!("https://callbacks.example/flows/{id}"),
        json!({"flow_instance_id": id, "decision": decision}),
        now_ms,
        &destinations,
    )?
    .into_outbox_message())
}

async fn insert_live_instance(
    pool: &PgPool,
    id: &str,
    now: chrono::DateTime<Utc>,
    expires_at: Option<chrono::DateTime<Utc>>,
) -> TestResult {
    sqlx::query(
        "INSERT INTO flow_service.flow_instances \
         (id, flow_definition_id, organization_id, status, context, step_history, \
          subject_type, expires_at, created_at, updated_at) \
         VALUES ($1,'__verification__','org-1','awaiting_wallet',$2,$3, \
                 'applicant',$4,$5,$5)",
    )
    .bind(id)
    .bind(json!({"request_digest": "c".repeat(64)}))
    .bind(json!([]))
    .bind(expires_at)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

async fn reset_schema(pool: &PgPool) -> TestResult {
    sqlx::query("DROP SCHEMA IF EXISTS flow_service CASCADE")
        .execute(pool)
        .await?;
    sqlx::query("CREATE SCHEMA flow_service")
        .execute(pool)
        .await?;
    sqlx::query(
        "CREATE TABLE flow_service.flow_instances ( \
           id VARCHAR(36) PRIMARY KEY, flow_definition_id VARCHAR(36) NOT NULL, \
           organization_id VARCHAR(255) NOT NULL, status VARCHAR(50) NOT NULL, \
           current_step_id VARCHAR(36), context JSON NOT NULL, step_history JSON NOT NULL, \
           subject_type VARCHAR(50) NOT NULL, application_flow_key_hash VARCHAR(64), \
           completed_at TIMESTAMPTZ, expires_at TIMESTAMPTZ, result JSON, error TEXT, \
           created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL)",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE TABLE flow_service.flow_nonce_consumptions ( \
           nonce_digest VARCHAR(64) PRIMARY KEY, flow_instance_id VARCHAR(36) NOT NULL UNIQUE, \
           consumed_at TIMESTAMPTZ NOT NULL, expires_at TIMESTAMPTZ NOT NULL)",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE TABLE flow_service.flow_callback_outbox ( \
           event_id VARCHAR(36) PRIMARY KEY, flow_instance_id VARCHAR(36) NOT NULL UNIQUE \
             REFERENCES flow_service.flow_instances(id) ON DELETE CASCADE, \
           organization_id VARCHAR(255) NOT NULL, destination_url TEXT NOT NULL, \
           audience VARCHAR(255) NOT NULL, event_type VARCHAR(128) NOT NULL, payload JSON NOT NULL, \
           status VARCHAR(32) NOT NULL DEFAULT 'pending', attempt_count INTEGER NOT NULL DEFAULT 0, \
           next_attempt_at TIMESTAMPTZ NOT NULL, lease_token VARCHAR(36), \
           lease_expires_at TIMESTAMPTZ, last_error_code VARCHAR(128), \
           created_at TIMESTAMPTZ NOT NULL, delivered_at TIMESTAMPTZ, expires_at TIMESTAMPTZ NOT NULL)",
    )
    .execute(pool)
    .await?;
    Ok(())
}
