use std::{env, error::Error, str::FromStr};

use chrono::{Duration, Utc};
use marty_flow::{
    migrate_flow_schema, ApprovalStrategy, ArtifactStatus, CallbackEvent, DefinitionStatus,
    FlowArtifactRecord, FlowDefinitionRecord, FlowInstance, FlowInstanceRecord,
    PostgresFlowRepository,
};
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
    let now = chrono::DateTime::from_timestamp_micros(Utc::now().timestamp_micros())
        .expect("current timestamp");
    let now_ms = u64::try_from(now.timestamp_millis())?;
    run_crud_contract(&repository, now).await?;
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

async fn run_crud_contract(
    repository: &PostgresFlowRepository,
    now: chrono::DateTime<Utc>,
) -> TestResult {
    for id in [
        "71000000-0000-0000-0000-000000000001",
        "72000000-0000-0000-0000-000000000010",
        "72000000-0000-0000-0000-000000000040",
    ] {
        let seeded = repository.definition(id).await?.expect("seeded definition");
        seeded.kernel()?;
        seeded.projection()?;
    }
    let definition = FlowDefinitionRecord {
        id: "90000000-0000-0000-0000-000000000010".into(),
        organization_id: "org-1".into(),
        name: "Contract flow".into(),
        description: Some("lossless".into()),
        status: DefinitionStatus::Active,
        flow_type: marty_flow::FlowType::Oid4vciPreAuthorized,
        steps: vec![
            json!({"id":"step-1","name":"create_offer","config":{"protocol_step":"create_offer"}}),
            json!({"id":"step-2","name":"token_exchange","config":{"protocol_step":"token_exchange"}}),
        ],
        transitions: vec![
            json!({"id":"transition-1","from_step_id":"step-1","to_step_id":"step-2","condition":"success"}),
        ],
        start_step_id: Some("step-1".into()),
        credential_template_id: Some("template-1".into()),
        application_template_id: None,
        presentation_policy_id: None,
        delivery_destination_profile_id: None,
        deployment_profile_id: Some("deployment-1".into()),
        deployment_profile_ids: vec!["deployment-1".into()],
        trust_profile_id: Some("trust-1".into()),
        approval_strategy: ApprovalStrategy::Auto,
        hooks: Default::default(),
        trigger: None,
        extension: None,
        preconditions: vec!["approved".into()],
        default_timeout_seconds: 600,
        max_retries: 3,
        retry_cooldown_minutes: 7,
        enable_resume: true,
        version: 2,
        created_at: now,
        updated_at: now,
    };
    repository.save_definition(&definition).await?;
    let stored = repository
        .definition(&definition.id)
        .await?
        .expect("stored definition");
    assert_eq!(stored, definition);
    let definitions = repository.definitions_for_tenant("org-1").await?;
    assert!(definitions
        .iter()
        .any(|candidate| candidate.id == definition.id));

    let instance = FlowInstanceRecord {
        id: "90000000-0000-0000-0000-000000000011".into(),
        flow_definition_id: definition.id.clone(),
        organization_id: "org-1".into(),
        status: FlowInstanceStatus::InProgress,
        current_step_id: Some("step-1".into()),
        context: json!({"current_step_name":"create_offer"}),
        step_history: vec![json!({"step_id":"step-0"})],
        state_history: vec![
            json!({"prior_state":"pending","new_state":"in_progress","timestamp":now.to_rfc3339(),"actor":"user-1","event":"advance"}),
        ],
        subject_id: Some("subject-1".into()),
        subject_type: "applicant".into(),
        external_reference: Some("external-1".into()),
        application_flow_key_hash: Some("c".repeat(64)),
        started_at: Some(now),
        completed_at: None,
        expires_at: Some(now + Duration::minutes(10)),
        result: None,
        error: None,
        created_at: now,
        updated_at: now,
    };
    assert!(repository.save_instance(&instance).await?);
    assert_eq!(
        repository.instance(&instance.id).await?.expect("instance"),
        instance
    );
    assert_eq!(
        repository
            .instances_for_tenant(
                "org-1",
                Some(&definition.id),
                Some(FlowInstanceStatus::InProgress)
            )
            .await?
            .len(),
        1
    );

    let artifact = FlowArtifactRecord {
        id: "90000000-0000-0000-0000-000000000012".into(),
        flow_instance_id: instance.id.clone(),
        issuance_transaction_id: Some("90000000-0000-0000-0000-000000000013".into()),
        credential_offer_uri: Some("openid-credential-offer://first".into()),
        credential_offer_uris: Default::default(),
        credential_offer_labels: Default::default(),
        pre_authorized_code: Some("code-1".into()),
        issuance_status: Some("offer_created".into()),
        qr_payload: Some("qr".into()),
        expires_at: Some(now + Duration::minutes(10)),
        scanned_at: None,
        status: ArtifactStatus::Active,
        state: Some("state-1".into()),
        wallet_metadata: json!({"wallet":"example"}),
        attempt_number: 1,
        created_at: now,
        updated_at: now,
    };
    let saved = repository
        .save_artifact_record(&artifact)
        .await?
        .expect("artifact insert");
    assert_eq!(saved, artifact);
    let mut replay = artifact.clone();
    replay.id = "90000000-0000-0000-0000-000000000014".into();
    replay.issuance_status = Some("issued".into());
    let replayed = repository
        .save_artifact_record(&replay)
        .await?
        .expect("artifact replay");
    assert_eq!(replayed.id, artifact.id);
    assert_eq!(replayed.issuance_status.as_deref(), Some("issued"));
    assert_eq!(
        repository.artifacts_for_instance(&instance.id).await?.len(),
        1
    );
    assert_eq!(
        repository
            .artifact_by_pre_authorized_code("code-1")
            .await?
            .expect("artifact by code")
            .id,
        artifact.id
    );

    let mut atomic_instance = instance.clone();
    atomic_instance.id = "90000000-0000-0000-0000-000000000021".into();
    atomic_instance.application_flow_key_hash = Some("d".repeat(64));
    let mut atomic_artifact = artifact.clone();
    atomic_artifact.id = "90000000-0000-0000-0000-000000000022".into();
    atomic_artifact
        .flow_instance_id
        .clone_from(&atomic_instance.id);
    atomic_artifact.issuance_transaction_id = Some("90000000-0000-0000-0000-000000000023".into());
    atomic_artifact.pre_authorized_code = Some("code-atomic".into());
    assert!(
        repository
            .save_started_instance(&atomic_instance, Some(&atomic_artifact))
            .await?
    );
    assert!(repository.instance(&atomic_instance.id).await?.is_some());
    assert_eq!(
        repository
            .artifacts_for_instance(&atomic_instance.id)
            .await?
            .len(),
        1
    );

    let mut conflicting_instance = atomic_instance.clone();
    conflicting_instance.id = "90000000-0000-0000-0000-000000000024".into();
    let mut conflicting_artifact = atomic_artifact.clone();
    conflicting_artifact.id = "90000000-0000-0000-0000-000000000025".into();
    conflicting_artifact
        .flow_instance_id
        .clone_from(&conflicting_instance.id);
    assert!(
        !repository
            .save_started_instance(&conflicting_instance, Some(&conflicting_artifact))
            .await?
    );
    assert!(repository
        .instance(&conflicting_instance.id)
        .await?
        .is_none());

    let expected_updated_at = atomic_instance.updated_at;
    atomic_instance.context["advance"] = json!("winner");
    atomic_instance.updated_at = expected_updated_at + Duration::seconds(1);
    assert!(
        repository
            .compare_and_swap_instance(
                &atomic_instance,
                FlowInstanceStatus::InProgress,
                expected_updated_at
            )
            .await?
    );
    let mut stale = atomic_instance.clone();
    stale.context["advance"] = json!("stale");
    stale.updated_at += Duration::seconds(1);
    assert!(
        !repository
            .compare_and_swap_instance(&stale, FlowInstanceStatus::InProgress, expected_updated_at)
            .await?
    );
    assert_eq!(
        repository
            .instance(&atomic_instance.id)
            .await?
            .unwrap()
            .context["advance"],
        "winner"
    );

    let cancelled = repository
        .cancel_instance(&instance.id, "user-1", now + Duration::seconds(1))
        .await?
        .expect("cancelled instance");
    assert_eq!(cancelled.status, FlowInstanceStatus::Cancelled);
    assert_eq!(cancelled.state_history.len(), 2);
    assert_eq!(cancelled.state_history[1]["event"], "flow_cancelled");
    cancelled.kernel()?;
    assert!(repository
        .cancel_instance(&instance.id, "user-1", now + Duration::seconds(2))
        .await?
        .is_none());
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
    migrate_flow_schema(pool).await?;
    Ok(())
}
