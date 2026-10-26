use std::{
    env,
    error::Error,
    str::FromStr,
    sync::{Arc, Mutex},
};

use axum::{extract::State, http::HeaderMap, routing::post, Json, Router};
use chrono::{Duration, Utc};
use marty_flow::{
    create_definition_record, deliver_due_callbacks, migrate_flow_schema, parse_request,
    validate_flow_schema, ApplicationEventReceipt, ApprovalStrategy, ArtifactStatus,
    CallbackDeliveryConfig, CallbackEvent, CreateFlowDefinitionRequest, DefinitionStatus,
    FlowArtifactRecord, FlowDefinitionRecord, FlowInstanceRecord, FlowType,
    PhysicalStartReservation, PhysicalStartReservationInput, PhysicalStartSnapshot,
    PlannedApplicationFlowRecord, PostgresFlowRepository, RepositoryError,
};
use marty_verification::flow::FlowInstanceStatus;
use mmf_push::WebhookDestinationRegistry;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgConnectOptions, PgPool};

#[path = "support/flow_schema.rs"]
mod flow_schema;

const TEST_DATABASE_NAME: &str = "marty_atomic_test";
const FIRST_INSTANCE_ID: &str = "90000000-0000-0000-0000-000000000001";
const EXPIRED_INSTANCE_ID: &str = "90000000-0000-0000-0000-000000000002";
const DELIVERED_CALLBACK_INSTANCE_ID: &str = "90000000-0000-0000-0000-000000000003";
const REJECTED_CALLBACK_INSTANCE_ID: &str = "90000000-0000-0000-0000-000000000004";

type TestResult = Result<(), Box<dyn Error + Send + Sync>>;
type CallbackReceiver = Arc<Mutex<Option<tokio::sync::oneshot::Sender<(HeaderMap, Value)>>>>;

#[tokio::test]
async fn physical_start_intent_claim_replay_and_atomic_finalization() -> TestResult {
    let Ok(database_url) = env::var("FLOW_POSTGRES_TEST_URL") else {
        eprintln!("FLOW_POSTGRES_TEST_URL is not configured; PostgreSQL contract skipped");
        return Ok(());
    };
    let options = PgConnectOptions::from_str(
        &database_url.replace("postgresql+asyncpg://", "postgresql://"),
    )?;
    assert!(matches!(options.get_host(), "127.0.0.1" | "localhost"));
    assert_eq!(options.get_database(), Some(TEST_DATABASE_NAME));
    let _schema_lock = flow_schema::lock_shared_test_schemas(&options).await?;
    let pool = PgPool::connect_with(options).await?;
    reset_schema(&pool).await?;
    validate_flow_schema(&pool).await?;
    let repository = PostgresFlowRepository::new(pool.clone());
    let now = chrono::DateTime::from_timestamp_micros(Utc::now().timestamp_micros())
        .expect("current timestamp");
    let key = hex::encode(Sha256::digest(
        b"marty:physical-flow-start-key:v1:client-owned-1",
    ));
    let digest = "b".repeat(64);
    let definition_request: CreateFlowDefinitionRequest = parse_request(json!({
        "organization_id":"org-1", "name":"Physical issuance",
        "flow_type":"physical_document_issuance",
        "credential_template_id":"template-1",
        "application_template_id":"application-template-1",
        "delivery_destination_profile_id":"delivery-1"
    }))?;
    let mut definition = create_definition_record(definition_request, now)?;
    definition.id = "physical-1".into();
    definition.status = DefinitionStatus::Active;
    let snapshot = PhysicalStartSnapshot {
        definition,
        issuer_did: "did:example:test".into(),
    };
    let snapshot_value = serde_json::to_value(&snapshot)?;
    for extra in ["initial_context", "holder"] {
        let mut unsafe_shape = snapshot_value.clone();
        unsafe_shape[extra] = json!({});
        assert!(serde_json::from_value::<PhysicalStartSnapshot>(unsafe_shape.clone()).is_err());
        let rejected = sqlx::query(
            "INSERT INTO flow_service.physical_start_intents
             (organization_id,key_hash,request_hash,definition_snapshot,initial_actor,
              original_deadline_at,key_source,flow_definition_id,instance_id,created_at,updated_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$10)",
        )
        .bind("org-1")
        .bind(if extra == "holder" {
            "a".repeat(64)
        } else {
            "c".repeat(64)
        })
        .bind(&digest)
        .bind(unsafe_shape)
        .bind("actor-1")
        .bind(now + Duration::seconds(3600))
        .bind("client")
        .bind("physical-1")
        .bind("90000000-0000-0000-0000-000000000049")
        .bind(now)
        .execute(&pool)
        .await;
        assert!(rejected.is_err());
    }
    let mut foreign_snapshot = snapshot.clone();
    foreign_snapshot.definition.organization_id = "org-2".into();
    let mut wrong_type_snapshot = snapshot.clone();
    wrong_type_snapshot.definition.flow_type = FlowType::Custom;
    for invalid in [&foreign_snapshot, &wrong_type_snapshot] {
        assert!(matches!(
            repository
                .reserve_physical_start(PhysicalStartReservationInput {
                    organization_id: "org-1",
                    definition_id: "physical-1",
                    operation_key: "invalid-snapshot",
                    key_hash: &"d".repeat(64),
                    request_hash: &digest,
                    definition_snapshot: invalid,
                    initial_actor: "actor-1",
                    original_deadline_at: now + Duration::seconds(3600),
                    generated_key: false,
                    proposed_instance_id: "90000000-0000-0000-0000-000000000048",
                    now,
                })
                .await,
            Err(RepositoryError::InvalidPhysicalStartSnapshot)
        ));
    }
    let instance_id = "90000000-0000-0000-0000-000000000041";
    let (first, concurrent) = tokio::join!(
        repository.reserve_physical_start(PhysicalStartReservationInput {
            organization_id: "org-1",
            definition_id: "physical-1",
            operation_key: "client-owned-1",
            key_hash: &key,
            request_hash: &digest,
            definition_snapshot: &snapshot,
            initial_actor: "actor-1",
            original_deadline_at: now + Duration::seconds(3600),
            generated_key: false,
            proposed_instance_id: instance_id,
            now,
        }),
        repository.reserve_physical_start(PhysicalStartReservationInput {
            organization_id: "org-1",
            definition_id: "physical-1",
            operation_key: "client-owned-1",
            key_hash: &key,
            request_hash: &digest,
            definition_snapshot: &snapshot,
            initial_actor: "actor-1",
            original_deadline_at: now + Duration::seconds(3600),
            generated_key: false,
            proposed_instance_id: "90000000-0000-0000-0000-000000000042",
            now,
        }),
    );
    let results = [first?, concurrent?];
    let token = results
        .iter()
        .find_map(|result| match result {
            PhysicalStartReservation::Acquired { claim_token, .. } => Some(*claim_token),
            _ => None,
        })
        .expect("one claimant");
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, PhysicalStartReservation::Acquired { .. }))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, PhysicalStartReservation::InProgress { .. }))
            .count(),
        1
    );
    let owned_id = results
        .iter()
        .find_map(|result| match result {
            PhysicalStartReservation::Acquired { instance_id, .. } => Some(instance_id.clone()),
            _ => None,
        })
        .expect("owned instance");
    let pending = repository.pending_physical_starts("org-1", 10, 0).await?;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].key_source, "client");
    assert_eq!(pending[0].instance_id, owned_id);
    assert_eq!(
        pending[0].original_deadline_at,
        now + Duration::seconds(3600)
    );
    let origin = repository
        .physical_start_origin("org-1", &key)
        .await?
        .unwrap();
    assert_eq!(origin.created_at, now);
    assert_eq!(origin.initial_actor, "actor-1");
    assert_eq!(origin.original_deadline_at, now + Duration::seconds(3600));
    assert_eq!(
        repository.physical_start_snapshot("org-1", &key).await?,
        Some(snapshot_value.clone())
    );
    assert_eq!(
        repository
            .physical_start_snapshot_by_instance("org-1", &owned_id)
            .await?,
        Some(snapshot_value.clone())
    );
    assert!(repository
        .physical_start_snapshot("org-2", &key)
        .await?
        .is_none());
    assert!(repository
        .pending_physical_starts("org-2", 10, 0)
        .await?
        .is_empty());
    assert!(repository
        .reserve_physical_start(PhysicalStartReservationInput {
            organization_id: "org-1",
            definition_id: "physical-1",
            operation_key: "client-owned-1",
            key_hash: &key,
            request_hash: &"c".repeat(64),
            definition_snapshot: &snapshot,
            initial_actor: "actor-1",
            original_deadline_at: now + Duration::seconds(3600),
            generated_key: false,
            proposed_instance_id: &owned_id,
            now,
        })
        .await
        .is_err());
    // A readback UUID cannot replace an explicit client key. The old intent
    // remains the sole owned start and no alias intent can dispatch native.
    let wrong_alias_hash = hex::encode(Sha256::digest(
        format!("marty:physical-flow-start-key:v1:{owned_id}").as_bytes(),
    ));
    assert!(repository
        .reserve_physical_start(PhysicalStartReservationInput {
            organization_id: "org-1",
            definition_id: "physical-1",
            operation_key: &owned_id,
            key_hash: &wrong_alias_hash,
            request_hash: &digest,
            definition_snapshot: &snapshot,
            initial_actor: "actor-1",
            original_deadline_at: now + Duration::seconds(3600),
            generated_key: false,
            proposed_instance_id: "90000000-0000-0000-0000-000000000044",
            now,
        })
        .await
        .is_err());
    assert_eq!(
        repository
            .pending_physical_starts("org-1", 10, 0)
            .await?
            .len(),
        1
    );

    let mut wrong = terminal_instance("90000000-0000-0000-0000-000000000043", now, "wrong");
    wrong.flow_definition_id = "physical-1".into();
    assert!(
        !repository
            .save_started_physical_instance(&wrong, &key, token)
            .await?
    );
    assert!(repository.instance(&wrong.id).await?.is_none());

    let retry = repository
        .reserve_physical_start(PhysicalStartReservationInput {
            organization_id: "org-1",
            definition_id: "physical-1",
            operation_key: "client-owned-1",
            key_hash: &key,
            request_hash: &digest,
            definition_snapshot: &snapshot,
            initial_actor: "actor-1",
            original_deadline_at: now + Duration::seconds(3600),
            generated_key: false,
            proposed_instance_id: &owned_id,
            now: now + Duration::seconds(61),
        })
        .await?;
    let retry_token = match retry {
        PhysicalStartReservation::Acquired {
            instance_id,
            claim_token,
        } => {
            assert_eq!(instance_id, owned_id);
            claim_token
        }
        _ => panic!("expired claim must be recoverable with original input"),
    };
    let mut stored = terminal_instance(&owned_id, now, "stored");
    stored.flow_definition_id = "physical-1".into();
    assert!(
        !repository
            .save_started_physical_instance(&stored, &key, token)
            .await?
    );
    assert!(
        repository
            .save_started_physical_instance(&stored, &key, retry_token)
            .await?
    );
    assert!(
        matches!(repository.reserve_physical_start(PhysicalStartReservationInput {
            organization_id: "org-1", definition_id: "physical-1", operation_key: "client-owned-1",
            key_hash: &key, request_hash: &digest, definition_snapshot: &snapshot,
            initial_actor: "actor-1",
            original_deadline_at: now + Duration::seconds(3600),
            generated_key: false, proposed_instance_id: &owned_id, now: now + Duration::seconds(62),
        }).await?,
        PhysicalStartReservation::Completed { instance_id } if instance_id == owned_id)
    );
    assert!(repository
        .pending_physical_starts("org-1", 10, 0)
        .await?
        .is_empty());
    assert_eq!(repository.instance(&owned_id).await?, Some(stored));
    let generated_id = "90000000-0000-0000-0000-000000000045";
    let generated_key_hash = hex::encode(Sha256::digest(
        format!("marty:physical-flow-start-key:v1:{generated_id}").as_bytes(),
    ));
    assert!(matches!(
        repository
            .reserve_physical_start(PhysicalStartReservationInput {
                organization_id: "org-1",
                definition_id: "physical-1",
                operation_key: generated_id,
                key_hash: &generated_key_hash,
                request_hash: &digest,
                definition_snapshot: &snapshot,
                initial_actor: "actor-1",
                original_deadline_at: now + Duration::seconds(3600),
                generated_key: true,
                proposed_instance_id: generated_id,
                now,
            })
            .await?,
        PhysicalStartReservation::Acquired { .. }
    ));
    let pending = repository.pending_physical_starts("org-1", 10, 0).await?;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].key_source, "generated");
    assert!(
        matches!(repository.reserve_physical_start(PhysicalStartReservationInput {
            organization_id: "org-1", definition_id: "physical-1", operation_key: generated_id,
            key_hash: &generated_key_hash, request_hash: &digest, definition_snapshot: &snapshot,
            initial_actor: "actor-1",
            original_deadline_at: now + Duration::seconds(3600),
            generated_key: false, proposed_instance_id: "90000000-0000-0000-0000-000000000046",
            now: now + Duration::seconds(61),
        }).await?,
        PhysicalStartReservation::Acquired { instance_id, .. } if instance_id == generated_id)
    );
    assert!(
        matches!(repository.reserve_physical_start(PhysicalStartReservationInput {
        organization_id: "org-1", definition_id: "physical-1", operation_key: generated_id,
        key_hash: &generated_key_hash, request_hash: &digest, definition_snapshot: &snapshot,
        initial_actor: "actor-later", original_deadline_at: now + Duration::seconds(7200),
        generated_key: false, proposed_instance_id: "90000000-0000-0000-0000-000000000047",
        now: now + Duration::seconds(3601),
    }).await?, PhysicalStartReservation::Expired { instance_id } if instance_id == generated_id)
    );
    assert_eq!(
        repository
            .pending_physical_starts("org-1", 10, 0)
            .await?
            .len(),
        1
    );
    sqlx::raw_sql(
        "DROP SCHEMA IF EXISTS flow_service CASCADE;
        DROP SCHEMA IF EXISTS deployment_profile_service CASCADE;",
    )
    .execute(&pool)
    .await?;
    pool.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires an isolated fenced marty role and explicit FLOW_FENCED_APP_TEST_URL"]
async fn fenced_physical_start_role_can_claim_finalize_but_not_rewrite_identity() -> TestResult {
    let database_url = env::var("FLOW_FENCED_APP_TEST_URL")
        .expect("an explicit disposable fenced app database URL is required");
    let options = PgConnectOptions::from_str(
        &database_url.replace("postgresql+asyncpg://", "postgresql://"),
    )?;
    assert!(matches!(options.get_host(), "127.0.0.1" | "localhost"));
    assert_eq!(options.get_database(), Some("marty"));
    let pool = PgPool::connect_with(options).await?;
    let identity: (String, bool) = sqlx::query_as(
        "SELECT current_user, EXISTS (
           SELECT 1 FROM pg_namespace WHERE nspname='passport_cutover')",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(identity.0, "marty");
    assert!(identity.1);
    validate_flow_schema(&pool).await?;
    let acl_ready: bool = sqlx::query_scalar("SELECT flow_service.physical_start_acl_ready()")
        .fetch_one(&pool)
        .await?;
    assert!(acl_ready);

    let now = chrono::DateTime::from_timestamp_micros(Utc::now().timestamp_micros())
        .expect("current timestamp");
    let definition_request: CreateFlowDefinitionRequest = parse_request(json!({
        "organization_id":"org-1", "name":"Scoped physical role test",
        "flow_type":"physical_document_issuance",
        "credential_template_id":"template-1",
        "application_template_id":"application-template-1",
        "delivery_destination_profile_id":"delivery-1"
    }))?;
    let mut definition = create_definition_record(definition_request, now)?;
    definition.id = uuid::Uuid::new_v4().to_string();
    definition.status = DefinitionStatus::Active;
    let snapshot = PhysicalStartSnapshot {
        definition: definition.clone(),
        issuer_did: "did:example:scoped-test".into(),
    };
    let instance_id = uuid::Uuid::new_v4().to_string();
    let operation_key = format!("fenced-test:{instance_id}");
    let key_hash = hex::encode(Sha256::digest(
        format!("marty:physical-flow-start-key:v1:{operation_key}").as_bytes(),
    ));
    let request_hash = "b".repeat(64);
    let deadline = now + Duration::seconds(3600);
    let repository = PostgresFlowRepository::new(pool.clone());
    let input = PhysicalStartReservationInput {
        organization_id: "org-1",
        definition_id: &definition.id,
        operation_key: &operation_key,
        key_hash: &key_hash,
        request_hash: &request_hash,
        definition_snapshot: &snapshot,
        initial_actor: "original-actor",
        original_deadline_at: deadline,
        generated_key: false,
        proposed_instance_id: &instance_id,
        now,
    };
    let first = repository.reserve_physical_start(input).await?;
    assert!(matches!(first, PhysicalStartReservation::Acquired { .. }));
    let retry_proposed_id = uuid::Uuid::new_v4().to_string();
    let retry = repository
        .reserve_physical_start(PhysicalStartReservationInput {
            organization_id: "org-1",
            definition_id: &definition.id,
            operation_key: &operation_key,
            key_hash: &key_hash,
            request_hash: &request_hash,
            definition_snapshot: &snapshot,
            initial_actor: "retry-actor",
            original_deadline_at: deadline + Duration::seconds(3600),
            generated_key: false,
            proposed_instance_id: &retry_proposed_id,
            now: now + Duration::seconds(61),
        })
        .await?;
    let claim_token = match retry {
        PhysicalStartReservation::Acquired {
            instance_id: owned,
            claim_token,
        } => {
            assert_eq!(owned, instance_id);
            claim_token
        }
        other => panic!("expected fenced claim renewal, got {other:?}"),
    };
    let origin = repository
        .physical_start_origin("org-1", &key_hash)
        .await?
        .unwrap();
    assert_eq!(origin.initial_actor, "original-actor");
    assert_eq!(origin.created_at, now);
    assert_eq!(origin.original_deadline_at, deadline);
    let mut started = terminal_instance(&instance_id, now, "fenced");
    started.flow_definition_id = definition.id.clone();
    assert!(
        repository
            .save_started_physical_instance(&started, &key_hash, claim_token)
            .await?
    );
    assert_eq!(repository.instance(&instance_id).await?, Some(started));
    assert!(
        matches!(repository.reserve_physical_start(PhysicalStartReservationInput {
        organization_id: "org-1", definition_id: &definition.id,
        operation_key: &operation_key, key_hash: &key_hash, request_hash: &request_hash,
        definition_snapshot: &snapshot, initial_actor: "another-actor",
        original_deadline_at: deadline, generated_key: false,
        proposed_instance_id: &instance_id, now: now + Duration::seconds(62),
    }).await?, PhysicalStartReservation::Completed { instance_id: owned } if owned == instance_id)
    );

    for statement in [
        "UPDATE flow_service.physical_start_intents SET definition_snapshot=definition_snapshot WHERE organization_id=$1 AND key_hash=$2",
        "UPDATE flow_service.physical_start_intents SET initial_actor=initial_actor WHERE organization_id=$1 AND key_hash=$2",
        "UPDATE flow_service.physical_start_intents SET original_deadline_at=original_deadline_at WHERE organization_id=$1 AND key_hash=$2",
        "UPDATE flow_service.physical_start_intents SET instance_id=instance_id WHERE organization_id=$1 AND key_hash=$2",
        "UPDATE flow_service.physical_start_intents SET organization_id=organization_id WHERE organization_id=$1 AND key_hash=$2",
    ] {
        assert!(sqlx::query(statement)
            .bind("org-1")
            .bind(&key_hash)
            .execute(&pool)
            .await
            .is_err());
    }
    assert_eq!(
        repository
            .physical_start_origin("org-1", &key_hash)
            .await?
            .unwrap()
            .initial_actor,
        "original-actor"
    );
    pool.close().await;
    Ok(())
}

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
    let _schema_lock = flow_schema::lock_shared_test_schemas(&options).await?;
    let pool = PgPool::connect_with(options).await?;

    reset_schema(&pool).await?;
    let contract = run_contract(&pool).await;
    let cleanup = sqlx::raw_sql(
        "DROP SCHEMA IF EXISTS flow_service CASCADE;
         DROP SCHEMA IF EXISTS deployment_profile_service CASCADE;",
    )
    .execute(&pool)
    .await;
    pool.close().await;
    cleanup?;
    contract
}

async fn run_contract(pool: &PgPool) -> TestResult {
    validate_flow_schema(pool).await?;
    sqlx::query(
        "DELETE FROM flow_service.flow_definitions
         WHERE id='71000000-0000-0000-0000-000000000001'",
    )
    .execute(pool)
    .await?;
    assert!(validate_flow_schema(pool).await.is_err());
    migrate_flow_schema(pool).await?;
    validate_flow_schema(pool).await?;
    sqlx::raw_sql(
        "DROP INDEX flow_service.ux_flow_instances_org_application_flow_key;
         CREATE UNIQUE INDEX ux_flow_instances_org_application_flow_key
         ON flow_service.flow_instances (id);",
    )
    .execute(pool)
    .await?;
    assert!(validate_flow_schema(pool).await.is_err());
    sqlx::query("DROP INDEX flow_service.ux_flow_instances_org_application_flow_key")
        .execute(pool)
        .await?;
    migrate_flow_schema(pool).await?;
    sqlx::query(
        "ALTER TABLE flow_service.flow_nonce_consumptions
         DROP CONSTRAINT flow_nonce_consumptions_pkey",
    )
    .execute(pool)
    .await?;
    assert!(validate_flow_schema(pool).await.is_err());
    sqlx::query(
        "ALTER TABLE flow_service.flow_nonce_consumptions
         ADD PRIMARY KEY (nonce_digest)",
    )
    .execute(pool)
    .await?;
    assert_builtin_flow_link_is_idempotent(pool).await?;
    let repository = PostgresFlowRepository::new(pool.clone());
    let now = chrono::DateTime::from_timestamp_micros(Utc::now().timestamp_micros())
        .expect("current timestamp");
    let now_ms = u64::try_from(now.timestamp_millis())?;
    run_crud_contract(&repository, now).await?;
    insert_live_instance(pool, FIRST_INSTANCE_ID, now, None).await?;

    let candidate_a = terminal_instance(FIRST_INSTANCE_ID, now, "allow-a");
    let candidate_b = terminal_instance(FIRST_INSTANCE_ID, now, "allow-b");
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
    let expected_subject = if outcomes[0] {
        candidate_a.subject_id.clone()
    } else {
        candidate_b.subject_id.clone()
    };
    let expected_external_reference = if outcomes[0] {
        candidate_a.external_reference.clone()
    } else {
        candidate_b.external_reference.clone()
    };
    let expected_result = if outcomes[0] {
        candidate_a.result
    } else {
        candidate_b.result
    };

    let (status, stored_result, subject_id, external_reference): (
        String,
        Option<Value>,
        Option<String>,
        Option<String>,
    ) =
        sqlx::query_as("SELECT status, result, subject_id, external_reference FROM flow_service.flow_instances WHERE id=$1")
            .bind(FIRST_INSTANCE_ID)
            .fetch_one(pool)
            .await?;
    assert_eq!(status, "completed");
    assert_eq!(stored_result, expected_result);
    assert_eq!(subject_id, expected_subject);
    assert_eq!(external_reference, expected_external_reference);
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

    run_callback_delivery_contract(pool, &repository, now, replay_expiry).await?;

    insert_live_instance(
        pool,
        EXPIRED_INSTANCE_ID,
        now,
        Some(now - Duration::seconds(1)),
    )
    .await?;
    let expired = terminal_instance(EXPIRED_INSTANCE_ID, now, "allow");
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

async fn run_callback_delivery_contract(
    pool: &PgPool,
    repository: &PostgresFlowRepository,
    now: chrono::DateTime<Utc>,
    replay_expiry: u64,
) -> TestResult {
    let (received_tx, received_rx) = tokio::sync::oneshot::channel();
    let state = Arc::new(Mutex::new(Some(received_tx)));
    let router = Router::new()
        .route("/callback", post(receive_callback))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(async move { axum::serve(listener, router).await });
    let destination = format!("http://{address}/callback");
    let registration = format!("org-1|{destination}");
    let destinations = WebhookDestinationRegistry::parse(&registration)?;

    insert_live_instance(pool, DELIVERED_CALLBACK_INSTANCE_ID, now, None).await?;
    let callback = CallbackEvent::new(
        DELIVERED_CALLBACK_INSTANCE_ID,
        "org-1",
        &destination,
        json!({"flow_instance_id": DELIVERED_CALLBACK_INSTANCE_ID, "decision": "allow"}),
        u64::try_from(now.timestamp_millis())?,
        &destinations,
    )?
    .into_outbox_message();
    assert!(
        repository
            .finalize_verification(
                &terminal_instance(DELIVERED_CALLBACK_INSTANCE_ID, now, "allow"),
                &"d".repeat(64),
                replay_expiry,
                FlowInstanceStatus::AwaitingWallet,
                Some(&callback),
            )
            .await?
    );
    let report = deliver_due_callbacks(
        repository,
        &destinations,
        "0123456789abcdef0123456789abcdef",
        &CallbackDeliveryConfig::default(),
    )
    .await?;
    assert_eq!(report.claimed, 1);
    assert_eq!(report.delivered, 1);
    let (headers, payload) = received_rx.await?;
    assert_eq!(headers["x-mip-audience"], "marty-auth-service");
    assert_eq!(headers["x-mip-event"], "flow.verification_completed");
    assert_eq!(headers["x-mip-delivery-attempt"], "1");
    let signature = headers["x-mip-signature"].to_str()?;
    assert!(signature.starts_with("sha256="));
    assert_eq!(signature.len(), "sha256=".len() + 64);
    assert_eq!(payload["flow_instance_id"], DELIVERED_CALLBACK_INSTANCE_ID);
    let delivered: (String, String, Value) = sqlx::query_as(
        "SELECT status, destination_url, payload FROM flow_service.flow_callback_outbox \
         WHERE event_id=$1",
    )
    .bind(DELIVERED_CALLBACK_INSTANCE_ID)
    .fetch_one(pool)
    .await?;
    assert_eq!(delivered, ("delivered".into(), String::new(), json!({})));

    insert_live_instance(pool, REJECTED_CALLBACK_INSTANCE_ID, now, None).await?;
    let rejected = CallbackEvent::new(
        REJECTED_CALLBACK_INSTANCE_ID,
        "org-1",
        &destination,
        json!({"flow_instance_id": REJECTED_CALLBACK_INSTANCE_ID, "decision": "allow"}),
        u64::try_from(now.timestamp_millis())?,
        &destinations,
    )?
    .into_outbox_message();
    assert!(
        repository
            .finalize_verification(
                &terminal_instance(REJECTED_CALLBACK_INSTANCE_ID, now, "allow"),
                &"e".repeat(64),
                replay_expiry,
                FlowInstanceStatus::AwaitingWallet,
                Some(&rejected),
            )
            .await?
    );
    let report = deliver_due_callbacks(
        repository,
        &WebhookDestinationRegistry::default(),
        "0123456789abcdef0123456789abcdef",
        &CallbackDeliveryConfig::default(),
    )
    .await?;
    assert_eq!(report.dead_lettered, 1);
    let rejected_status: (String, Option<String>) = sqlx::query_as(
        "SELECT status, last_error_code FROM flow_service.flow_callback_outbox WHERE event_id=$1",
    )
    .bind(REJECTED_CALLBACK_INSTANCE_ID)
    .fetch_one(pool)
    .await?;
    assert_eq!(
        rejected_status,
        ("dead_letter".into(), Some("destination_rejected".into()))
    );
    server.abort();
    Ok(())
}

async fn receive_callback(
    State(sender): State<CallbackReceiver>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> axum::http::StatusCode {
    if let Some(sender) = sender.lock().expect("callback receiver lock").take() {
        let _ = sender.send((headers, payload));
    }
    axum::http::StatusCode::NO_CONTENT
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

    let mut application_instance = instance.clone();
    application_instance.id = "90000000-0000-0000-0000-000000000031".into();
    application_instance.application_flow_key_hash = Some("e".repeat(64));
    application_instance.context = json!({
        "_marty_application_offer_semantics_hash_v1": "f".repeat(64)
    });
    let planned = PlannedApplicationFlowRecord {
        instance: application_instance.clone(),
        plan_entry: std::collections::BTreeMap::from([
            ("flow_definition_id".into(), definition.id.clone()),
            ("application_flow_key_hash".into(), "e".repeat(64)),
            ("offer_semantics_hash".into(), "f".repeat(64)),
            (
                "offer_semantics_context_key".into(),
                "_marty_application_offer_semantics_hash_v1".into(),
            ),
        ]),
    };
    let receipt = ApplicationEventReceipt {
        event_id_sha256: "1".repeat(64),
        payload_sha256: "2".repeat(64),
        organization_id: "org-1".into(),
        application_id: "application-1".into(),
        flow_plan: Vec::new(),
        created_at_ms: u64::try_from(now.timestamp_millis())?,
        updated_at_ms: u64::try_from(now.timestamp_millis())?,
    };
    let (reserved, created) = repository
        .reserve_application_event_plan(receipt.clone(), std::slice::from_ref(&planned))
        .await?;
    assert!(created);
    assert_eq!(
        reserved.flow_plan[0]["instance_id"],
        application_instance.id
    );
    let (replayed, created) = repository
        .reserve_application_event_plan(receipt.clone(), std::slice::from_ref(&planned))
        .await?;
    assert!(!created);
    assert_eq!(replayed.flow_plan, reserved.flow_plan);

    let mut changed_payload = receipt.clone();
    changed_payload.payload_sha256 = "3".repeat(64);
    assert!(repository
        .reserve_application_event_plan(changed_payload, std::slice::from_ref(&planned))
        .await
        .is_err());
    let mut changed_semantics = planned;
    changed_semantics.instance.id = "90000000-0000-0000-0000-000000000032".into();
    changed_semantics.instance.context = json!({
        "_marty_application_offer_semantics_hash_v1": "4".repeat(64)
    });
    changed_semantics
        .plan_entry
        .insert("offer_semantics_hash".into(), "4".repeat(64));
    let mut new_event = receipt;
    new_event.event_id_sha256 = "5".repeat(64);
    new_event.payload_sha256 = "6".repeat(64);
    assert!(repository
        .reserve_application_event_plan(new_event, &[changed_semantics])
        .await
        .is_err());
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

    let replacement_expected_at = atomic_instance.updated_at;
    atomic_instance.updated_at += Duration::seconds(1);
    atomic_instance.context["oid4vci_artifact_id"] = json!("90000000-0000-0000-0000-000000000026");
    let mut replacement = atomic_artifact.clone();
    replacement.id = "90000000-0000-0000-0000-000000000026".into();
    replacement.issuance_transaction_id = Some("90000000-0000-0000-0000-000000000027".into());
    replacement.pre_authorized_code = Some("code-replacement".into());
    replacement.attempt_number = 2;
    replacement.created_at = atomic_instance.updated_at;
    replacement.updated_at = atomic_instance.updated_at;
    assert!(
        repository
            .replace_active_artifacts(
                &atomic_instance,
                &replacement,
                replacement_expected_at,
                atomic_instance.updated_at
            )
            .await?
    );
    let offers = repository
        .artifacts_for_instance(&atomic_instance.id)
        .await?;
    assert_eq!(offers.len(), 2);
    assert_eq!(offers[0].status, ArtifactStatus::Expired);
    assert_eq!(offers[1].status, ArtifactStatus::Active);

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

fn terminal_instance(id: &str, now: chrono::DateTime<Utc>, decision: &str) -> FlowInstanceRecord {
    FlowInstanceRecord {
        id: id.into(),
        flow_definition_id: "__verification__".into(),
        organization_id: "org-1".into(),
        status: FlowInstanceStatus::Completed,
        current_step_id: None,
        context: json!({"request_digest": "c".repeat(64)}),
        step_history: Vec::new(),
        state_history: Vec::new(),
        subject_id: Some(format!("subject-{decision}")),
        subject_type: "holder".into(),
        external_reference: Some(format!("external-{decision}")),
        application_flow_key_hash: None,
        started_at: Some(now - Duration::minutes(1)),
        completed_at: Some(now),
        expires_at: None,
        result: Some(json!({"evaluation_result": "passed", "decision": decision})),
        error: None,
        created_at: now - Duration::minutes(1),
        updated_at: now,
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
    sqlx::raw_sql(
        "DROP SCHEMA IF EXISTS flow_service CASCADE;
         DROP SCHEMA IF EXISTS deployment_profile_service CASCADE;
         CREATE SCHEMA deployment_profile_service;
         CREATE TABLE deployment_profile_service.deployment_profiles (
             id text PRIMARY KEY,
             enabled_flow_ids jsonb NOT NULL DEFAULT '[]'::jsonb
         );
         INSERT INTO deployment_profile_service.deployment_profiles(id)
         VALUES ('70000000-0000-0000-0000-000000000001');",
    )
    .execute(pool)
    .await?;
    migrate_flow_schema(pool).await?;
    Ok(())
}

async fn assert_builtin_flow_link_is_idempotent(pool: &PgPool) -> TestResult {
    const BUILTIN_FLOW_ID: &str = "71000000-0000-0000-0000-000000000001";
    const DEPLOYMENT_PROFILE_ID: &str = "70000000-0000-0000-0000-000000000001";

    migrate_flow_schema(pool).await?;
    let enabled: Value = sqlx::query_scalar(
        "SELECT enabled_flow_ids
         FROM deployment_profile_service.deployment_profiles
         WHERE id = $1",
    )
    .bind(DEPLOYMENT_PROFILE_ID)
    .fetch_one(pool)
    .await?;
    assert_eq!(enabled, json!([BUILTIN_FLOW_ID]));
    Ok(())
}
