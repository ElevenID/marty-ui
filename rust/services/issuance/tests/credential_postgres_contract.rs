use axum::{routing::post, Json, Router};
use chrono::{Duration, TimeZone, Utc};
use hmac::{Hmac, Mac};
use marty_issuance_service::canvas_issuance_guard::{
    CanvasGuardConfig, PostgresCanvasIssuanceGuard,
};
use marty_issuance_service::credential::{
    CredentialIssuanceError, CredentialLifecycle, CredentialRepository, CredentialTransaction,
    CredentialTransactionStatus, IssuedCredential, IssuerContext,
};
use marty_issuance_service::credential_lifecycle::PostgresCredentialLifecycle;
use marty_issuance_service::credential_management::{
    CredentialLifecycleAction, CredentialManagementRepository, ManagedCredentialStatus,
};
use marty_issuance_service::credential_management_postgres::PostgresCredentialManagementRepository;
use marty_issuance_service::credential_postgres::PostgresCredentialRepository;
use marty_issuance_service::initiation::{
    IdempotencyBinding, InitiationApplicationClaimsResolver, InitiationClientRepository,
    InitiationRepository, InitiationRepositoryError,
};
use marty_issuance_service::initiation_dependencies::PostgresInitiationApplicationClaimsResolver;
use marty_issuance_service::initiation_didcomm::{
    InitiationDidcommDeliveryState, InitiationDidcommRepository,
    InitiationDidcommTransportClaimOutcome, StagedInitiationDidcommDelivery,
    DIDCOMM_TRANSPORT_READY_STATUS, DIDCOMM_TRANSPORT_RETRYABLE_STATUS,
};
use marty_issuance_service::token_postgres::PostgresTokenExchangeRepository;
use serde_json::json;
use sha2::Sha256;
use sqlx::{postgres::PgPoolOptions, Row};
use std::{collections::BTreeSet, time::Duration as StdDuration};
use url::Url;
use uuid::Uuid;

fn token_digest(key: &[u8], token: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(token.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

#[tokio::test]
async fn credential_management_repository_is_concurrency_safe_and_canvas_durable() {
    let Ok(database_url) = std::env::var("ISSUANCE_POSTGRES_TEST_URL") else {
        return;
    };
    let database_name = url::Url::parse(&database_url)
        .expect("credential PostgreSQL contract URL must parse")
        .path()
        .trim_start_matches('/')
        .to_owned();
    assert!(
        database_name.ends_with("_test"),
        "ISSUANCE_POSTGRES_TEST_URL must name a dedicated *_test database"
    );
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&database_url)
        .await
        .expect("credential PostgreSQL contract database must connect");
    create_contract_schema(&pool).await;
    sqlx::query(
        "INSERT INTO issuance_service.issued_credentials
             (id, transaction_id, organization_id, credential_template_id,
              issuer_did, revocation_profile_id, status_list_entries,
              credential_jwt, credential_hash, status, status_updated_at,
              revoked, issued_at)
         VALUES ('credential-managed', 'transaction-managed', 'org-managed', 'template-managed',
                 NULL, 'profile-managed',
                 '[{\"status_list_id\":\"profile-managed\",\"index\":11}]'::jsonb,
                 'credential', 'hash', 'active', clock_timestamp(), false, clock_timestamp())",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO issuance_service.credential_delivery_records
             (id, credential_id, transaction_id, organization_id, delivery_target,
              delivery_mode, status, metadata, created_at, updated_at)
         VALUES ('delivery-managed', 'credential-managed', 'transaction-managed',
                 'org-managed', 'canvas_credentials', 'wallet_plus_canvas_mirror',
                 'delivered', '{}'::jsonb, clock_timestamp(), clock_timestamp())",
    )
    .execute(&pool)
    .await
    .unwrap();

    let repository = PostgresCredentialManagementRepository::new(pool.clone());
    let mut credential = repository
        .get("credential-managed")
        .await
        .unwrap()
        .expect("managed credential");
    assert_eq!(credential.status, ManagedCredentialStatus::Active);
    assert_eq!(
        credential.issuer_did, None,
        "nullable issuer DID is preserved"
    );
    credential.status = ManagedCredentialStatus::Suspended;
    credential.status_updated_at = Utc::now();
    let credential = repository
        .persist(&credential, ManagedCredentialStatus::Active)
        .await
        .expect("conditional status persistence");
    assert_eq!(credential.status, ManagedCredentialStatus::Suspended);
    assert!(
        repository
            .persist(&credential, ManagedCredentialStatus::Active)
            .await
            .is_err(),
        "a stale lifecycle writer must not overwrite the canonical status"
    );
    repository
        .synchronize_canvas(
            &credential,
            CredentialLifecycleAction::Suspend,
            Some("manual review"),
        )
        .await
        .expect("durable Canvas lifecycle request");
    let metadata: serde_json::Value = sqlx::query_scalar(
        "SELECT metadata FROM issuance_service.credential_delivery_records
         WHERE id = 'delivery-managed'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(metadata["status_sync_state"], "pending");
    assert_eq!(metadata["last_status_sync_action"], "suspend");
    assert_eq!(metadata["requested_credential_status"], "suspended");
    assert_eq!(metadata["requested_status_sync_reason"], "manual review");

    let mut credential = credential;
    credential.status = ManagedCredentialStatus::Active;
    credential.status_updated_at = Utc::now();
    let credential = repository
        .persist(&credential, ManagedCredentialStatus::Suspended)
        .await
        .expect("reinstate projection persistence");
    repository
        .synchronize_canvas(&credential, CredentialLifecycleAction::Reinstate, None)
        .await
        .expect("nullable Canvas lifecycle reason");
    let metadata: serde_json::Value = sqlx::query_scalar(
        "SELECT metadata FROM issuance_service.credential_delivery_records
         WHERE id = 'delivery-managed'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(metadata["requested_credential_status"], "active");
    assert!(metadata["requested_status_sync_reason"].is_null());

    drop_contract_schema(&pool).await;
}

#[tokio::test]
async fn credential_repository_is_hmac_compatible_atomic_and_canvas_safe() {
    let Ok(database_url) = std::env::var("ISSUANCE_POSTGRES_TEST_URL") else {
        return;
    };
    let database_name = url::Url::parse(&database_url)
        .expect("credential PostgreSQL contract URL must parse")
        .path()
        .trim_start_matches('/')
        .to_owned();
    assert!(
        database_name.ends_with("_test"),
        "ISSUANCE_POSTGRES_TEST_URL must name a dedicated *_test database"
    );
    let pool = PgPoolOptions::new()
        .max_connections(12)
        .connect(&database_url)
        .await
        .expect("credential PostgreSQL contract database must connect");
    create_contract_schema(&pool).await;

    let key = format!("credential-postgres-contract-key-{}", Uuid::new_v4());
    let access_token = format!("credential-access-token-{}", Uuid::new_v4());
    let nonce = format!("credential-proof-nonce-{}", Uuid::new_v4());
    sqlx::query(
        "INSERT INTO issuance_service.issuance_transactions
             (id, organization_id, credential_template_id, revocation_profile_id,
              renewal_of_credential_id, application_id, status, pre_auth_code,
              access_token, c_nonce, claims,
              credential_type, issuer_profile_id, issuer_did_override,
              issuer_algorithm, signing_service_id, delivery_mode)
         VALUES ('tx-contract', 'org-a', 'template-a', 'status-profile-a',
                 'credential-source', 'application-a', 'authorized',
                 'pre-auth-contract', $1, $2,
                 '{}'::jsonb, 'OpenBadgeCredential', 'issuer-profile-a',
                 'did:web:issuer.example', 'ES256', 'kms-service-a',
                 'wallet_plus_canvas_mirror')",
    )
    .bind(token_digest(key.as_bytes(), &access_token))
    .bind(&nonce)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO issuance_service.applications
             (id, organization_id, application_template_id, status,
              issuance_transaction_id, credential_id, integration_context)
         VALUES ('application-a', 'org-a', 'application-template-a', 'approved',
                 'tx-contract', NULL,
                 '{\"canvas\":{\"source\":\"canvas-lti\",\"canvas_award_candidate_id\":\"candidate-a\",\"canvas_account_id\":\"account-a\",\"canvas_program_binding_id\":\"binding-a\",\"canvas_platform_id\":\"platform-a\",\"application_template_id\":\"application-template-a\",\"credential_template_id\":\"template-a\",\"lti_subject\":\"opaque-subject-a\"}}')",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO issuance_service.canvas_award_candidates
             (id, organization_id, application_id, binding_id, platform_id, state)
         VALUES ('candidate-a', 'org-a', 'application-a', 'binding-a', 'platform-a', 'pending_claim')",
    )
    .execute(&pool)
    .await
    .unwrap();

    seed_canvas_guard_contract(&pool).await;
    sqlx::query(
        "INSERT INTO issuance_service.issued_credentials
             (id, transaction_id, organization_id, credential_template_id,
              issuer_did, revocation_profile_id, status_list_entries,
              credential_jwt, credential_hash, status, status_updated_at,
              revoked, issued_at)
         VALUES ('credential-source', 'source-transaction', 'org-a', 'template-a',
                 'did:web:issuer.example', 'status-profile-a',
                 '[{\"status_list_id\":\"status-profile-a\",\"index\":8,\"type\":\"BitstringStatusListEntry\",\"status_purpose\":\"revocation\"}]'::jsonb,
                 'source-credential', 'source-hash', 'active', clock_timestamp(),
                 false, clock_timestamp())",
    )
    .execute(&pool)
    .await
    .unwrap();

    let repository = PostgresCredentialRepository::new(pool.clone(), key.as_bytes());
    let transaction = repository
        .transaction_by_access_token(&access_token)
        .await
        .unwrap()
        .expect("Python-compatible HMAC token lookup");
    assert_eq!(transaction.nonce.as_deref(), Some(nonce.as_str()));
    let guard = PostgresCanvasIssuanceGuard::new(
        pool.clone(),
        CanvasGuardConfig {
            enabled: true,
            pilot_organizations: BTreeSet::from(["org-a".to_owned()]),
            evidence_max_age: StdDuration::from_secs(900),
            readiness_max_age: StdDuration::from_secs(900),
        },
    );
    let issuer_did = "did:web:issuer.example";
    let issuer = IssuerContext {
        issuer_profile_id: "issuer-profile-a".to_owned(),
        issuer_did: issuer_did.to_owned(),
        signing_service_id: "kms-service-a".to_owned(),
        algorithm: "ES256".to_owned(),
        verification_method_id: Some(format!("{issuer_did}#key-a")),
        public_jwk: Some(json!({"kty":"EC","crv":"P-256","x":"x","y":"y"})),
        certificate_chain: Vec::new(),
        raw_context: json!({
            "organization_id":"org-a", "issuer_did":issuer_did,
            "verification_method_id":format!("{issuer_did}#key-a"),
            "key_purpose":"vc_jwt_issuer", "algorithm":"ES256",
            "public_jwk":{"kty":"EC","crv":"P-256","x":"x","y":"y"},
            "issuer_profile":{
                "id":"issuer-profile-a", "status":"active", "organization_id":"org-a",
                "issuer_did":issuer_did, "verification_method_id":format!("{issuer_did}#key-a"),
                "key_purpose":"vc_jwt_issuer"
            },
            "service":{"id":"kms-service-a","algorithm":"ES256"}
        }),
    };
    assert!(guard.ensure_ready(&transaction, &issuer).await.unwrap());
    sqlx::query(
        "UPDATE issuance_service.evidence_facts
         SET verification = '{\"status\":\"UNVERIFIED\"}'::jsonb WHERE id = 'fact-a'",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert!(matches!(
        guard.ensure_ready(&transaction, &issuer).await,
        Err(CredentialIssuanceError::CanvasEligibilityDenied)
    ));
    sqlx::query(
        "UPDATE issuance_service.evidence_facts
         SET verification = '{\"status\":\"VERIFIED\"}'::jsonb WHERE id = 'fact-a'",
    )
    .execute(&pool)
    .await
    .unwrap();
    let credential_id = "urn:uuid:credential-postgres-contract";
    let (first, second) = tokio::join!(
        repository.claim_for_signing(&transaction, credential_id),
        repository.claim_for_signing(&transaction, credential_id)
    );
    let first = first.unwrap();
    let second = second.unwrap();
    assert_ne!(first.is_some(), second.is_some());
    let claimed = first.or(second).unwrap();
    assert_eq!(claimed.status, CredentialTransactionStatus::Signing);

    let now = Utc::now();
    let issued = IssuedCredential {
        id: credential_id.to_owned(),
        transaction_id: claimed.id.clone(),
        organization_id: claimed.organization_id.clone(),
        credential_template_id: claimed.credential_template_id.clone(),
        applicant_id: None,
        subject_did: Some("did:key:holder".to_owned()),
        issuer_did: "did:web:issuer.example".to_owned(),
        revocation_profile_id: None,
        renewed_from_credential_id: claimed.renewal_of_credential_id.clone(),
        status_list_entries: vec![json!({"index": 7})],
        credential: "signed-credential".to_owned(),
        credential_hash: "credential-hash".to_owned(),
        issued_at: now,
        expires_at: now + Duration::days(365),
    };
    repository.finalize(&claimed, &issued).await.unwrap();
    let (revocation_url, revocation_server) = revocation_server().await;
    let lifecycle = PostgresCredentialLifecycle::new(
        pool.clone(),
        revocation_url,
        Some("contract-service-token"),
        StdDuration::from_secs(1),
        CanvasGuardConfig {
            enabled: true,
            pilot_organizations: BTreeSet::from(["org-a".to_owned()]),
            evidence_max_age: StdDuration::from_secs(900),
            readiness_max_age: StdDuration::from_secs(900),
        },
    )
    .unwrap();
    lifecycle
        .after_issued(&claimed, &issued, "dc+sd-jwt")
        .await
        .unwrap();
    assert!(repository.finalize(&claimed, &issued).await.is_err());
    let persisted = repository
        .credential_by_transaction(&claimed.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(persisted.id, credential_id);
    assert_eq!(persisted.credential, "signed-credential");
    let finalized = sqlx::query(
        "SELECT status, c_nonce FROM issuance_service.issuance_transactions
         WHERE id = 'tx-contract'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(finalized.try_get::<String, _>("status").unwrap(), "issued");
    assert!(finalized
        .try_get::<Option<String>, _>("c_nonce")
        .unwrap()
        .is_none());
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT credential_id FROM issuance_service.applications WHERE id = 'application-a'",
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        credential_id
    );
    let candidate = sqlx::query(
        "SELECT state, claimed_credential_id
         FROM issuance_service.canvas_award_candidates WHERE id = 'candidate-a'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(candidate.try_get::<String, _>("state").unwrap(), "claimed");
    assert_eq!(
        candidate
            .try_get::<Option<String>, _>("claimed_credential_id")
            .unwrap()
            .as_deref(),
        Some(credential_id)
    );
    let drift = sqlx::query(
        "SELECT target_type, schedule_seconds, metadata
         FROM issuance_service.canvas_evidence_sync_targets
         WHERE organization_id = 'org-a' AND logical_key = 'application:application-a'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        drift.try_get::<String, _>("target_type").unwrap(),
        "issued_drift"
    );
    assert_eq!(drift.try_get::<i32, _>("schedule_seconds").unwrap(), 21_600);
    assert_eq!(
        drift.try_get::<serde_json::Value, _>("metadata").unwrap()["claimed_credential_id"],
        credential_id
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM issuance_service.issuance_events
             WHERE transaction_id = 'tx-contract' AND event_type = 'credential_issued'",
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );
    let deliveries = sqlx::query(
        "SELECT delivery_target, status FROM issuance_service.credential_delivery_records
         WHERE credential_id = $1 ORDER BY delivery_target",
    )
    .bind(credential_id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(deliveries.len(), 2);
    assert_eq!(
        deliveries[0]
            .try_get::<String, _>("delivery_target")
            .unwrap(),
        "canvas_credentials"
    );
    assert_eq!(
        deliveries[0].try_get::<String, _>("status").unwrap(),
        "pending"
    );
    assert_eq!(
        deliveries[1]
            .try_get::<String, _>("delivery_target")
            .unwrap(),
        "wallet"
    );
    assert_eq!(
        deliveries[1].try_get::<String, _>("status").unwrap(),
        "delivered"
    );
    let source = sqlx::query(
        "SELECT status, revoked, revocation_reason, renewed_to_credential_id
         FROM issuance_service.issued_credentials WHERE id = 'credential-source'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(source.try_get::<String, _>("status").unwrap(), "revoked");
    assert!(source.try_get::<bool, _>("revoked").unwrap());
    assert_eq!(
        source
            .try_get::<Option<String>, _>("revocation_reason")
            .unwrap()
            .as_deref(),
        Some("Superseded by renewed credential")
    );
    assert_eq!(
        source
            .try_get::<Option<String>, _>("renewed_to_credential_id")
            .unwrap()
            .as_deref(),
        Some(credential_id)
    );

    assert_authorization_only_race(&pool, &repository, key.as_bytes()).await;
    assert_initiation_idempotency_race(&repository).await;
    assert_initiation_dependency_reads(&pool, key.as_bytes()).await;
    assert_didcomm_retry_and_lifecycle_contract(&pool, &repository, &lifecycle).await;
    revocation_server.abort();
    drop_contract_schema(&pool).await;
}

async fn assert_didcomm_retry_and_lifecycle_contract(
    pool: &sqlx::PgPool,
    repository: &PostgresCredentialRepository,
    lifecycle: &PostgresCredentialLifecycle,
) {
    sqlx::query(
        "INSERT INTO issuance_service.issuance_transactions
             (id, organization_id, credential_template_id, status, pre_auth_code,
              claims, credential_type, credential_payload_format, delivery_mode,
              issuer_profile_id, issuer_did_override, issuer_algorithm,
              signing_service_id, subject_did)
         VALUES ('tx-didcomm-contract', 'org-a', 'template-didcomm', 'pending',
                 'pre-auth-didcomm-contract', '{\"role\":\"engineer\"}'::jsonb,
                 'OpenBadgeCredential', 'w3c_vcdm_v2_sd_jwt', 'wallet_only',
                 'issuer-profile-a', 'did:web:issuer.example', 'ES256',
                 'kms-service-a', 'did:key:holder')",
    )
    .execute(pool)
    .await
    .unwrap();

    let pending = repository
        .transaction_by_id("tx-didcomm-contract")
        .await
        .unwrap()
        .expect("pending DIDComm transaction");
    assert_eq!(pending.status, CredentialTransactionStatus::Pending);
    let credential_id = "urn:uuid:credential-didcomm-contract";
    let claim = repository
        .claim_retryably(&pending, credential_id)
        .await
        .unwrap()
        .expect("first DIDComm worker claims the transaction");
    assert_eq!(claim.previous_status, CredentialTransactionStatus::Pending);
    assert_eq!(
        claim.transaction.status,
        CredentialTransactionStatus::Signing
    );
    assert_eq!(
        claim.transaction.reserved_credential_id.as_deref(),
        Some(credential_id)
    );
    assert!(repository
        .claim_retryably(&pending, credential_id)
        .await
        .unwrap()
        .is_none());

    repository.release_retryably(&claim).await.unwrap();
    let released = sqlx::query(
        "SELECT status, reserved_credential_id
         FROM issuance_service.issuance_transactions WHERE id = 'tx-didcomm-contract'",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(released.try_get::<String, _>("status").unwrap(), "pending");
    assert!(released
        .try_get::<Option<String>, _>("reserved_credential_id")
        .unwrap()
        .is_none());

    let pending = repository
        .transaction_by_id("tx-didcomm-contract")
        .await
        .unwrap()
        .expect("released DIDComm transaction");
    let claim = repository
        .claim_retryably(&pending, credential_id)
        .await
        .unwrap()
        .expect("retry reclaims the same stable credential identifier");
    // PostgreSQL `timestamptz` is microsecond-precise. Use a non-zero,
    // microsecond-aligned value so this round-trip contract verifies the
    // precision the production repository can actually preserve instead of
    // comparing an unrepresentable nanosecond remainder.
    let now = Utc
        .timestamp_opt(1_700_000_000, 123_456_000)
        .single()
        .unwrap();
    let issued = IssuedCredential {
        id: credential_id.to_owned(),
        transaction_id: claim.transaction.id.clone(),
        organization_id: claim.transaction.organization_id.clone(),
        credential_template_id: claim.transaction.credential_template_id.clone(),
        applicant_id: claim.transaction.applicant_id.clone(),
        subject_did: claim.transaction.subject_did.clone(),
        issuer_did: "did:web:issuer.example".to_owned(),
        revocation_profile_id: None,
        renewed_from_credential_id: None,
        status_list_entries: Vec::new(),
        credential: "didcomm-signed-credential".to_owned(),
        credential_hash: "didcomm-credential-hash".to_owned(),
        issued_at: now,
        expires_at: now + Duration::days(365),
    };
    let staged = StagedInitiationDidcommDelivery {
        holder_did: "did:key:holder".to_owned(),
        service_endpoint: "https://holder.example/didcomm".to_owned(),
        message_id: "didcomm-message-contract".to_owned(),
        encrypted_message: "encrypted-didcomm-contract".to_owned(),
    };
    repository
        .stage_delivery(&claim.transaction, &issued, &staged)
        .await
        .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT status FROM issuance_service.credential_delivery_records
             WHERE credential_id = $1 AND delivery_target = 'didcomm_v2'",
        )
        .bind(credential_id)
        .fetch_one(pool)
        .await
        .unwrap(),
        DIDCOMM_TRANSPORT_READY_STATUS
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM issuance_service.credential_delivery_records
             WHERE credential_id = $1 AND delivery_target = 'didcomm_v2'
               AND status IN ('pending', 'failed', 'transported')",
        )
        .bind(credential_id)
        .fetch_one(pool)
        .await
        .unwrap(),
        0,
        "a writer-owned ready row must be invisible to an old reader's retry query"
    );
    let pending_state = repository
        .delivery_state("org-a", "tx-didcomm-contract")
        .await
        .unwrap()
        .expect("finalization atomically stages DIDComm delivery");
    let InitiationDidcommDeliveryState::Pending(pending_delivery) = pending_state else {
        panic!("a staged delivery must remain pending");
    };
    assert_eq!(pending_delivery.credential, issued);
    assert_eq!(pending_delivery.delivery, staged);
    assert!(!pending_delivery.transported);
    let compatibility_pending = repository
        .pending_delivery("org-a", "tx-didcomm-contract")
        .await
        .unwrap()
        .expect("the public pending-delivery compatibility method must remain available");
    assert_eq!(compatibility_pending.credential, issued);
    assert_eq!(compatibility_pending.delivery, staged);

    assert!(
        lifecycle
            .after_didcomm_issued(
                &claim.transaction,
                &issued,
                "https://holder.example/didcomm",
                "didcomm-message-contract",
            )
            .await
            .is_err(),
        "projection may only transition a durably transported delivery"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM issuance_service.issuance_events
             WHERE transaction_id = 'tx-didcomm-contract'"
        )
        .fetch_one(pool)
        .await
        .unwrap(),
        0
    );
    assert!(matches!(
        repository
            .claim_transport("org-other", "tx-didcomm-contract", "did:key:holder")
            .await
            .unwrap(),
        InitiationDidcommTransportClaimOutcome::Absent
    ));
    assert!(matches!(
        repository
            .claim_transport("org-a", "tx-didcomm-contract", "did:key:other-holder")
            .await
            .unwrap(),
        InitiationDidcommTransportClaimOutcome::BindingMismatch
    ));

    sqlx::query(
        "INSERT INTO issuance_service.credential_delivery_records
             (id, credential_id, transaction_id, organization_id, delivery_target,
              delivery_mode, status, metadata, created_at, updated_at)
         SELECT 'duplicate-didcomm-claim-sentinel', credential_id, transaction_id,
                organization_id, delivery_target, delivery_mode, status, metadata,
                clock_timestamp(), clock_timestamp()
         FROM issuance_service.credential_delivery_records
         WHERE credential_id = $1 AND delivery_target = 'didcomm_v2'",
    )
    .bind(credential_id)
    .execute(pool)
    .await
    .unwrap();
    assert!(matches!(
        repository
            .claim_transport("org-a", "tx-didcomm-contract", "did:key:holder")
            .await,
        Err(CredentialIssuanceError::RepositoryUnavailable)
    ));
    sqlx::query(
        "DELETE FROM issuance_service.credential_delivery_records
         WHERE id = 'duplicate-didcomm-claim-sentinel'",
    )
    .execute(pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO issuance_service.credential_delivery_records
             (id, credential_id, transaction_id, organization_id, delivery_target,
              delivery_mode, status, metadata, created_at, updated_at)
         VALUES ('canvas-didcomm-claim-sentinel', $1, 'tx-didcomm-contract', 'org-a',
                 'canvas_credentials', 'wallet_plus_canvas_mirror', 'pending',
                 '{\"canvas_sentinel\":true}'::jsonb,
                 clock_timestamp(), clock_timestamp())",
    )
    .bind(credential_id)
    .execute(pool)
    .await
    .unwrap();

    let canonical_delivery_id = sqlx::query_scalar::<_, String>(
        "SELECT id FROM issuance_service.credential_delivery_records
         WHERE credential_id = $1 AND delivery_target = 'didcomm_v2'",
    )
    .bind(credential_id)
    .fetch_one(pool)
    .await
    .unwrap();
    let wrong_binding_delivery_id = "wrong-binding-didcomm-sentinel";
    sqlx::query("UPDATE issuance_service.credential_delivery_records SET id = $2 WHERE id = $1")
        .bind(&canonical_delivery_id)
        .bind(wrong_binding_delivery_id)
        .execute(pool)
        .await
        .unwrap();
    assert!(matches!(
        repository
            .claim_transport("org-a", "tx-didcomm-contract", "did:key:holder")
            .await
            .unwrap(),
        InitiationDidcommTransportClaimOutcome::BindingMismatch
    ));
    sqlx::query("UPDATE issuance_service.credential_delivery_records SET id = $2 WHERE id = $1")
        .bind(wrong_binding_delivery_id)
        .bind(&canonical_delivery_id)
        .execute(pool)
        .await
        .unwrap();

    let second_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(pool.connect_options().as_ref().clone())
        .await
        .unwrap();
    let second_instance =
        PostgresCredentialRepository::new(second_pool.clone(), b"contract-token-key");
    let (pending_claim_a, pending_claim_b) = tokio::join!(
        repository.claim_transport("org-a", "tx-didcomm-contract", "did:key:holder"),
        second_instance.claim_transport("org-a", "tx-didcomm-contract", "did:key:holder")
    );
    let pending_claim = match (pending_claim_a.unwrap(), pending_claim_b.unwrap()) {
        (
            InitiationDidcommTransportClaimOutcome::Claimed(claim),
            InitiationDidcommTransportClaimOutcome::Busy,
        )
        | (
            InitiationDidcommTransportClaimOutcome::Busy,
            InitiationDidcommTransportClaimOutcome::Claimed(claim),
        ) => claim,
        states => panic!("one pending worker must claim and one must observe busy: {states:?}"),
    };
    let claimed_row = sqlx::query(
        "SELECT id, status, metadata
         FROM issuance_service.credential_delivery_records
         WHERE credential_id = $1 AND delivery_target = 'didcomm_v2'",
    )
    .bind(credential_id)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(
        claimed_row.try_get::<String, _>("status").unwrap(),
        "transporting"
    );
    let claimed_metadata = claimed_row
        .try_get::<serde_json::Value, _>("metadata")
        .unwrap();
    let original_attempt_id = claimed_metadata["didcomm_transport_attempt_id"]
        .as_str()
        .expect("claim attempt token")
        .to_owned();
    assert!(Uuid::parse_str(&original_attempt_id).is_ok());
    assert!(claimed_metadata["didcomm_transport_lease_expires_at"]
        .as_str()
        .is_some_and(|deadline| !deadline.is_empty()));
    assert_eq!(claimed_metadata["didcomm_message_id"], staged.message_id);
    assert_eq!(
        claimed_metadata["encrypted_message"],
        staged.encrypted_message
    );
    let original_delivery_id = claimed_row.try_get::<String, _>("id").unwrap();

    for binding in [
        "credential_id",
        "transaction_id",
        "organization_id",
        "delivery_target",
        "holder_did",
        "service_endpoint",
        "didcomm_message_id",
        "encrypted_message",
    ] {
        let tampered = sqlx::query(
            "UPDATE issuance_service.credential_delivery_records
             SET credential_id = CASE WHEN $2 = 'credential_id'
                                      THEN 'tampered-credential' ELSE credential_id END,
                 transaction_id = CASE WHEN $2 = 'transaction_id'
                                       THEN 'tampered-transaction' ELSE transaction_id END,
                 organization_id = CASE WHEN $2 = 'organization_id'
                                        THEN 'tampered-organization' ELSE organization_id END,
                 delivery_target = CASE WHEN $2 = 'delivery_target'
                                        THEN 'tampered-target' ELSE delivery_target END,
                 metadata = metadata || jsonb_build_object(
                     'holder_did', CASE WHEN $2 = 'holder_did'
                                        THEN 'did:example:tampered' ELSE metadata ->> 'holder_did' END,
                     'service_endpoint', CASE WHEN $2 = 'service_endpoint'
                                        THEN 'https://tampered.example/didcomm'
                                        ELSE metadata ->> 'service_endpoint' END,
                     'didcomm_message_id', CASE WHEN $2 = 'didcomm_message_id'
                                        THEN 'tampered-message'
                                        ELSE metadata ->> 'didcomm_message_id' END,
                     'encrypted_message', CASE WHEN $2 = 'encrypted_message'
                                        THEN 'tampered-ciphertext'
                                        ELSE metadata ->> 'encrypted_message' END)
             WHERE id = $1",
        )
        .bind(&original_delivery_id)
        .bind(binding)
        .execute(pool)
        .await
        .unwrap();
        assert_eq!(tampered.rows_affected(), 1);
        assert!(
            repository
                .mark_transport_succeeded(&pending_claim)
                .await
                .is_err(),
            "completion must reject a tampered {binding} binding"
        );
        let restored = sqlx::query(
            "UPDATE issuance_service.credential_delivery_records
             SET credential_id = $2, transaction_id = 'tx-didcomm-contract',
                 organization_id = 'org-a', delivery_target = 'didcomm_v2',
                 metadata = metadata || jsonb_build_object(
                     'holder_did', $3::text,
                     'service_endpoint', $4::text,
                     'didcomm_message_id', $5::text,
                     'encrypted_message', $6::text)
             WHERE id = $1",
        )
        .bind(&original_delivery_id)
        .bind(credential_id)
        .bind(&staged.holder_did)
        .bind(&staged.service_endpoint)
        .bind(&staged.message_id)
        .bind(&staged.encrypted_message)
        .execute(pool)
        .await
        .unwrap();
        assert_eq!(restored.rows_affected(), 1);
    }

    let wrong_attempt_id = Uuid::new_v4().to_string();
    sqlx::query(
        "UPDATE issuance_service.credential_delivery_records
         SET metadata = jsonb_set(metadata, '{didcomm_transport_attempt_id}', to_jsonb($2::text))
         WHERE credential_id = $1 AND delivery_target = 'didcomm_v2'",
    )
    .bind(credential_id)
    .bind(&wrong_attempt_id)
    .execute(pool)
    .await
    .unwrap();
    assert!(repository
        .mark_transport_succeeded(&pending_claim)
        .await
        .is_err());
    sqlx::query(
        "UPDATE issuance_service.credential_delivery_records
         SET metadata = jsonb_set(metadata, '{didcomm_transport_attempt_id}', to_jsonb($2::text))
         WHERE credential_id = $1 AND delivery_target = 'didcomm_v2'",
    )
    .bind(credential_id)
    .bind(&original_attempt_id)
    .execute(pool)
    .await
    .unwrap();
    let moved_delivery_id = "moved-didcomm-claim-sentinel";
    sqlx::query(
        "UPDATE issuance_service.credential_delivery_records
         SET id = $2
         WHERE id = $1 AND delivery_target = 'didcomm_v2'",
    )
    .bind(&original_delivery_id)
    .bind(moved_delivery_id)
    .execute(pool)
    .await
    .unwrap();
    assert!(repository
        .mark_transport_succeeded(&pending_claim)
        .await
        .is_err());
    sqlx::query(
        "UPDATE issuance_service.credential_delivery_records
         SET id = $2
         WHERE id = $1 AND delivery_target = 'didcomm_v2'",
    )
    .bind(moved_delivery_id)
    .bind(&original_delivery_id)
    .execute(pool)
    .await
    .unwrap();
    repository
        .mark_transport_unattempted(&pending_claim)
        .await
        .unwrap();
    let failed_row = sqlx::query(
        "SELECT status, metadata
         FROM issuance_service.credential_delivery_records
         WHERE credential_id = $1 AND delivery_target = 'didcomm_v2'",
    )
    .bind(credential_id)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(
        failed_row.try_get::<String, _>("status").unwrap(),
        DIDCOMM_TRANSPORT_RETRYABLE_STATUS
    );
    let failed_metadata = failed_row
        .try_get::<serde_json::Value, _>("metadata")
        .unwrap();
    assert!(failed_metadata
        .get("didcomm_transport_attempt_id")
        .is_none());
    assert!(failed_metadata
        .get("didcomm_transport_lease_expires_at")
        .is_none());
    let retryable_state = repository
        .delivery_state("org-a", "tx-didcomm-contract")
        .await
        .unwrap()
        .expect("a definitely-unattempted failure remains claim-aware retryable work");
    let InitiationDidcommDeliveryState::Pending(retryable_delivery) = retryable_state else {
        panic!("a retryable transport must remain a pending delivery")
    };
    assert!(!retryable_delivery.transported);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM issuance_service.credential_delivery_records
             WHERE credential_id = $1 AND delivery_target = 'didcomm_v2'
               AND status IN ('pending', 'failed', 'transported')",
        )
        .bind(credential_id)
        .fetch_one(pool)
        .await
        .unwrap(),
        0,
        "a claim-aware retryable row must remain invisible to old retry readers"
    );

    let (failed_claim_a, failed_claim_b) = tokio::join!(
        repository.claim_transport("org-a", "tx-didcomm-contract", "did:key:holder"),
        second_instance.claim_transport("org-a", "tx-didcomm-contract", "did:key:holder")
    );
    let failed_claim = match (failed_claim_a.unwrap(), failed_claim_b.unwrap()) {
        (
            InitiationDidcommTransportClaimOutcome::Claimed(claim),
            InitiationDidcommTransportClaimOutcome::Busy,
        )
        | (
            InitiationDidcommTransportClaimOutcome::Busy,
            InitiationDidcommTransportClaimOutcome::Claimed(claim),
        ) => claim,
        states => {
            panic!("one failed-retry worker must claim and one must observe busy: {states:?}")
        }
    };
    repository
        .mark_transport_outcome_unknown(&failed_claim)
        .await
        .unwrap();
    assert!(matches!(
        repository
            .claim_transport("org-a", "tx-didcomm-contract", "did:key:holder")
            .await
            .unwrap(),
        InitiationDidcommTransportClaimOutcome::OutcomeUnknown
    ));

    sqlx::query(
        "UPDATE issuance_service.credential_delivery_records
         SET status = $2, last_error = 'didcomm_delivery_failed',
             metadata = metadata
                 - 'didcomm_transport_attempt_id'
                 - 'didcomm_transport_lease_expires_at'
         WHERE credential_id = $1 AND delivery_target = 'didcomm_v2'",
    )
    .bind(credential_id)
    .bind(DIDCOMM_TRANSPORT_RETRYABLE_STATUS)
    .execute(pool)
    .await
    .unwrap();
    let expiry_claim = repository
        .claim_transport("org-a", "tx-didcomm-contract", "did:key:holder")
        .await
        .unwrap();
    assert!(matches!(
        expiry_claim,
        InitiationDidcommTransportClaimOutcome::Claimed(_)
    ));
    sqlx::query(
        "UPDATE issuance_service.credential_delivery_records
         SET metadata = jsonb_set(
             metadata,
             '{didcomm_transport_lease_expires_at}',
             to_jsonb(clock_timestamp() - INTERVAL '1 second'))
         WHERE credential_id = $1 AND delivery_target = 'didcomm_v2'",
    )
    .bind(credential_id)
    .execute(pool)
    .await
    .unwrap();
    assert!(matches!(
        repository
            .claim_transport("org-a", "tx-didcomm-contract", "did:key:holder")
            .await
            .unwrap(),
        InitiationDidcommTransportClaimOutcome::OutcomeUnknown
    ));
    let expired_row = sqlx::query(
        "SELECT status, metadata
         FROM issuance_service.credential_delivery_records
         WHERE credential_id = $1 AND delivery_target = 'didcomm_v2'",
    )
    .bind(credential_id)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(
        expired_row.try_get::<String, _>("status").unwrap(),
        "delivery_unknown"
    );
    let expired_metadata = expired_row
        .try_get::<serde_json::Value, _>("metadata")
        .unwrap();
    assert!(expired_metadata
        .get("didcomm_transport_attempt_id")
        .is_none());
    assert!(expired_metadata
        .get("didcomm_transport_lease_expires_at")
        .is_none());

    sqlx::query(
        "UPDATE issuance_service.credential_delivery_records
         SET status = 'transporting', last_error = NULL,
             metadata = (metadata || jsonb_build_object(
                 'didcomm_transport_attempt_id', $2::text,
                 'didcomm_transport_lease_expires_at', 'malformed-deadline'))
         WHERE credential_id = $1 AND delivery_target = 'didcomm_v2'",
    )
    .bind(credential_id)
    .bind(Uuid::new_v4().to_string())
    .execute(pool)
    .await
    .unwrap();
    assert!(matches!(
        repository
            .claim_transport("org-a", "tx-didcomm-contract", "did:key:holder")
            .await
            .unwrap(),
        InitiationDidcommTransportClaimOutcome::OutcomeUnknown
    ));

    sqlx::query(
        "UPDATE issuance_service.credential_delivery_records
         SET status = $2, last_error = 'didcomm_delivery_failed',
             metadata = metadata
                 - 'didcomm_transport_attempt_id'
                 - 'didcomm_transport_lease_expires_at'
         WHERE credential_id = $1 AND delivery_target = 'didcomm_v2'",
    )
    .bind(credential_id)
    .bind(DIDCOMM_TRANSPORT_RETRYABLE_STATUS)
    .execute(pool)
    .await
    .unwrap();
    let success_claim = repository
        .claim_transport("org-a", "tx-didcomm-contract", "did:key:holder")
        .await
        .unwrap();
    let InitiationDidcommTransportClaimOutcome::Claimed(success_claim) = success_claim else {
        panic!("the reconciled failed state must be claimable")
    };
    repository
        .mark_transport_succeeded(&success_claim)
        .await
        .unwrap();
    let transported_state = repository
        .delivery_state("org-a", "tx-didcomm-contract")
        .await
        .unwrap()
        .expect("transport completion remains pending until lifecycle projection");
    let InitiationDidcommDeliveryState::Pending(transported_delivery) = transported_state else {
        panic!("a transported delivery must remain pending until projection");
    };
    assert_eq!(transported_delivery.delivery, staged);
    assert!(transported_delivery.transported);
    lifecycle
        .after_didcomm_issued(
            &claim.transaction,
            &issued,
            "https://holder.example/didcomm",
            "didcomm-message-contract",
        )
        .await
        .unwrap();
    let delivered_state = repository
        .delivery_state("org-a", "tx-didcomm-contract")
        .await
        .unwrap()
        .expect("a completed delivery remains available for receipt-only retries");
    let InitiationDidcommDeliveryState::Delivered(delivered) = delivered_state else {
        panic!("a completed delivery must expose only its terminal receipt state");
    };
    assert_eq!(delivered.transaction_id, "tx-didcomm-contract");
    assert_eq!(delivered.organization_id, "org-a");
    assert_eq!(delivered.credential_id, issued.id);
    assert_eq!(delivered.holder_did, staged.holder_did);
    assert_eq!(delivered.service_endpoint, staged.service_endpoint);
    assert_eq!(delivered.message_id, staged.message_id);
    let terminal_claim = repository
        .claim_transport("org-a", "tx-didcomm-contract", "did:key:holder")
        .await
        .unwrap();
    let InitiationDidcommTransportClaimOutcome::Delivered(terminal) = terminal_claim else {
        panic!("a completed delivery must replay its terminal receipt")
    };
    assert_eq!(terminal, delivered);
    assert!(repository
        .pending_delivery("org-a", "tx-didcomm-contract")
        .await
        .unwrap()
        .is_none());
    assert!(repository
        .delivery_state("org-other", "tx-didcomm-contract")
        .await
        .unwrap()
        .is_none());

    let finalized = sqlx::query(
        "SELECT status, reserved_credential_id
         FROM issuance_service.issuance_transactions WHERE id = 'tx-didcomm-contract'",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(finalized.try_get::<String, _>("status").unwrap(), "issued");
    assert_eq!(
        finalized
            .try_get::<Option<String>, _>("reserved_credential_id")
            .unwrap()
            .as_deref(),
        Some(credential_id)
    );
    assert!(repository.release_retryably(&claim).await.is_err());
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT status FROM issuance_service.issuance_transactions
             WHERE id = 'tx-didcomm-contract'",
        )
        .fetch_one(pool)
        .await
        .unwrap(),
        "issued"
    );

    let event_metadata: serde_json::Value = sqlx::query_scalar(
        "SELECT metadata FROM issuance_service.issuance_events
         WHERE transaction_id = 'tx-didcomm-contract'
           AND event_type = 'credential_issued'",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(event_metadata["credential_id"], credential_id);
    assert_eq!(event_metadata["delivery_protocol"], "didcomm_v2");
    assert_eq!(
        event_metadata["service_endpoint"],
        "https://holder.example/didcomm"
    );

    let delivery = sqlx::query(
        "SELECT delivery_target, status, metadata
         FROM issuance_service.credential_delivery_records
         WHERE credential_id = $1 AND delivery_target = 'didcomm_v2'",
    )
    .bind(credential_id)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(
        delivery.try_get::<String, _>("delivery_target").unwrap(),
        "didcomm_v2"
    );
    assert_eq!(
        delivery.try_get::<String, _>("status").unwrap(),
        "delivered"
    );
    let metadata = delivery
        .try_get::<serde_json::Value, _>("metadata")
        .unwrap();
    assert_eq!(metadata["protocol"], "didcomm_v2");
    assert_eq!(metadata["didcomm_message_id"], "didcomm-message-contract");
    assert_eq!(metadata["holder_did"], "did:key:holder");
    assert!(metadata.get("encrypted_message").is_none());
    assert_eq!(
        metadata["service_endpoint"],
        "https://holder.example/didcomm"
    );

    for required_key in ["holder_did", "service_endpoint", "didcomm_message_id"] {
        sqlx::query(
            "UPDATE issuance_service.credential_delivery_records
             SET metadata = $2 - $3
             WHERE credential_id = $1 AND delivery_target = 'didcomm_v2'",
        )
        .bind(credential_id)
        .bind(metadata.clone())
        .bind(required_key)
        .execute(pool)
        .await
        .unwrap();
        assert!(repository
            .pending_delivery("org-a", "tx-didcomm-contract")
            .await
            .unwrap()
            .is_none());
        assert!(matches!(
            repository
                .delivery_state("org-a", "tx-didcomm-contract")
                .await,
            Err(CredentialIssuanceError::RepositoryUnavailable)
        ));
    }
    sqlx::query(
        "UPDATE issuance_service.credential_delivery_records
         SET metadata = $2
         WHERE credential_id = $1 AND delivery_target = 'didcomm_v2'",
    )
    .bind(credential_id)
    .bind(metadata)
    .execute(pool)
    .await
    .unwrap();
    let canvas_sentinel = sqlx::query(
        "SELECT status, metadata
         FROM issuance_service.credential_delivery_records
         WHERE id = 'canvas-didcomm-claim-sentinel'
           AND delivery_target = 'canvas_credentials'",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(
        canvas_sentinel.try_get::<String, _>("status").unwrap(),
        "pending"
    );
    assert_eq!(
        canvas_sentinel
            .try_get::<serde_json::Value, _>("metadata")
            .unwrap(),
        json!({"canvas_sentinel": true})
    );
    assert_legacy_didcomm_status_fails_closed(pool, repository, "pending").await;
    assert_legacy_didcomm_status_fails_closed(pool, repository, "failed").await;
    second_pool.close().await;
}

async fn assert_legacy_didcomm_status_fails_closed(
    pool: &sqlx::PgPool,
    repository: &PostgresCredentialRepository,
    legacy_status: &str,
) {
    let transaction_id = format!("tx-didcomm-legacy-{legacy_status}");
    let credential_id = format!("urn:uuid:credential-didcomm-legacy-{legacy_status}");
    let pre_auth_code = format!("pre-auth-didcomm-legacy-{legacy_status}");
    let delivery_id = Uuid::new_v5(
        &Uuid::NAMESPACE_URL,
        format!("{credential_id}:didcomm_v2:-").as_bytes(),
    )
    .to_string();
    sqlx::query(
        "INSERT INTO issuance_service.issuance_transactions
             (id, organization_id, credential_template_id, status, pre_auth_code,
              claims, credential_type, credential_payload_format, delivery_mode,
              issuer_profile_id, issuer_did_override, issuer_algorithm,
              signing_service_id, subject_did, reserved_credential_id, issued_at)
         VALUES ($1, 'org-legacy', 'template-legacy', 'issued', $2,
                 '{}'::jsonb, 'OpenBadgeCredential', 'w3c_vcdm_v2_sd_jwt', 'wallet_only',
                 'issuer-profile-legacy', 'did:web:issuer.example', 'ES256',
                 'kms-service-legacy', 'did:key:legacy-holder', $3, clock_timestamp())",
    )
    .bind(&transaction_id)
    .bind(&pre_auth_code)
    .bind(&credential_id)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO issuance_service.issued_credentials
             (id, transaction_id, organization_id, credential_template_id,
              subject_did, issuer_did, status_list_entries, credential_jwt,
              credential_hash, status, status_updated_at, revoked, issued_at, expires_at)
         VALUES ($1, $2, 'org-legacy', 'template-legacy', 'did:key:legacy-holder',
                 'did:web:issuer.example', '[]'::jsonb, 'legacy-signed-credential',
                 'legacy-credential-hash', 'active', clock_timestamp(), false,
                 clock_timestamp(), clock_timestamp() + INTERVAL '365 days')",
    )
    .bind(&credential_id)
    .bind(&transaction_id)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO issuance_service.credential_delivery_records
             (id, credential_id, transaction_id, organization_id, delivery_target,
              delivery_mode, status, metadata, created_at, updated_at)
         VALUES ($1, $2, $3, 'org-legacy', 'didcomm_v2', 'wallet_only', $4,
                 jsonb_build_object(
                     'protocol', 'didcomm_v2',
                     'holder_did', 'did:key:legacy-holder',
                     'service_endpoint', 'https://legacy-holder.example/didcomm',
                     'didcomm_message_id', $5::text,
                     'encrypted_message', 'legacy-encrypted-message',
                     'didcomm_transport_attempt_id', $6::text,
                     'didcomm_transport_lease_expires_at',
                         clock_timestamp() + INTERVAL '1 hour'),
                 clock_timestamp(), clock_timestamp())",
    )
    .bind(&delivery_id)
    .bind(&credential_id)
    .bind(&transaction_id)
    .bind(legacy_status)
    .bind(format!("legacy-message-{legacy_status}"))
    .bind(Uuid::new_v4().to_string())
    .execute(pool)
    .await
    .unwrap();

    assert!(matches!(
        repository
            .claim_transport("org-legacy", &transaction_id, "did:key:wrong-holder")
            .await
            .unwrap(),
        InitiationDidcommTransportClaimOutcome::BindingMismatch
    ));
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT status FROM issuance_service.credential_delivery_records WHERE id = $1",
        )
        .bind(&delivery_id)
        .fetch_one(pool)
        .await
        .unwrap(),
        legacy_status,
        "a mismatched holder must not mutate a legacy delivery"
    );
    assert!(repository
        .delivery_state("org-legacy", &transaction_id)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM issuance_service.credential_delivery_records
             WHERE id = $1 AND status IN ('pending', 'failed', 'transported')",
        )
        .bind(&delivery_id)
        .fetch_one(pool)
        .await
        .unwrap(),
        1,
        "an old reader would consider the unmarked legacy row retryable"
    );
    assert!(matches!(
        repository
            .claim_transport("org-legacy", &transaction_id, "did:key:legacy-holder")
            .await
            .unwrap(),
        InitiationDidcommTransportClaimOutcome::OutcomeUnknown
    ));
    let reconciled = sqlx::query(
        "SELECT status, metadata FROM issuance_service.credential_delivery_records WHERE id = $1",
    )
    .bind(&delivery_id)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(
        reconciled.try_get::<String, _>("status").unwrap(),
        "delivery_unknown"
    );
    let metadata = reconciled
        .try_get::<serde_json::Value, _>("metadata")
        .unwrap();
    assert!(metadata.get("didcomm_transport_attempt_id").is_none());
    assert!(metadata.get("didcomm_transport_lease_expires_at").is_none());
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM issuance_service.credential_delivery_records
             WHERE id = $1 AND status IN ('pending', 'failed', 'transported')",
        )
        .bind(&delivery_id)
        .fetch_one(pool)
        .await
        .unwrap(),
        0
    );
}

async fn assert_initiation_dependency_reads(pool: &sqlx::PgPool, key: &[u8]) {
    sqlx::query(
        "UPDATE issuance_service.applications
         SET form_data = '{\"employee_id\":\"employee-1\",\"role\":\"engineer\"}'::jsonb
         WHERE id = 'application-a'",
    )
    .execute(pool)
    .await
    .unwrap();
    let applications = PostgresInitiationApplicationClaimsResolver::new(pool.clone());
    let claims = applications
        .resolve("application-a")
        .await
        .unwrap()
        .expect("application claims");
    assert_eq!(claims["employee_id"], "employee-1");
    assert_eq!(claims["role"], "engineer");
    assert!(applications
        .resolve("application-missing")
        .await
        .unwrap()
        .is_none());

    sqlx::query(
        "INSERT INTO issuance_service.oid4vci_registered_clients
             (organization_id, client_id, jwks, token_endpoint_auth_method, active)
         VALUES ('org-a', 'wallet-client-a', '{}'::jsonb, 'private_key_jwt', true)",
    )
    .execute(pool)
    .await
    .unwrap();
    let clients = PostgresTokenExchangeRepository::new(pool.clone(), key);
    let client = InitiationClientRepository::get(&clients, "org-a", "wallet-client-a")
        .await
        .unwrap()
        .expect("registered initiation client");
    assert_eq!(client.client_id, "wallet-client-a");
    assert!(client.active);
    assert_eq!(client.token_endpoint_auth_method, "private_key_jwt");
    assert!(
        InitiationClientRepository::get(&clients, "org-b", "wallet-client-a")
            .await
            .unwrap()
            .is_none()
    );
}

async fn revocation_server() -> (Url, tokio::task::JoinHandle<()>) {
    async fn process(Json(body): Json<serde_json::Value>) -> Json<serde_json::Value> {
        Json(json!({
            "success":true,
            "organization_id":body["organization_id"],
            "index":body["index"],
            "status_list_url":"https://status.example/lists/active"
        }))
    }
    let app = Router::new().route(
        "/revocation/internal/revocation-profiles/{profile_id}/process-revocation",
        post(process),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (
        Url::parse(&format!("http://{address}/revocation")).unwrap(),
        server,
    )
}

async fn seed_canvas_guard_contract(pool: &sqlx::PgPool) {
    for statement in [
        "INSERT INTO issuance_service.application_templates
             (id, organization_id, credential_template_id, status)
         VALUES ('application-template-a', 'org-a', 'template-a', 'active')",
        "INSERT INTO issuance_service.canvas_platforms
             (id, organization_id, canvas_account_id, registration_status, enabled)
         VALUES ('platform-a', 'org-a', 'account-a', 'installed', true)",
        "INSERT INTO issuance_service.canvas_program_bindings
             (id, organization_id, platform_id, application_template_id,
              credential_template_id, evidence_requirements, config_version,
              validated_config_version, readiness_checks, readiness_validated_at,
              activated_at, credential_template_snapshot, enabled)
         VALUES ('binding-a', 'org-a', 'platform-a', 'application-template-a',
                 'template-a',
                 '[{\"requirement_id\":\"score-a\",\"source\":\"canvas_rest\",\"fact_type\":\"canvas.assignment_score\",\"scope\":{\"course_id\":\"course-a\",\"activity_id\":\"activity-a\"},\"pass_rule\":{\"min_score_percent\":80},\"required\":true}]'::jsonb,
                 1, 1, '[{\"status\":\"ready\",\"blocking\":true}]'::jsonb,
                 clock_timestamp(), clock_timestamp(),
                 '{\"id\":\"template-a\",\"organization_id\":\"org-a\",\"status\":\"active\",\"credential_type\":\"OpenBadgeCredential\",\"credential_payload_format\":\"w3c_vcdm_v2_sd_jwt\",\"revocation_profile_id\":\"status-profile-a\",\"issuer_did\":\"did:web:issuer.example\",\"issuer_algorithm\":\"ES256\"}'::jsonb,
                 true)",
        "INSERT INTO issuance_service.evidence_facts
             (id, organization_id, application_id, subject_id, provider, fact_type,
              scope, assertion, verification, source, requirement_id, logical_key,
              source_revision, payload_hash, effective_at, observed_at, created_at)
         VALUES ('fact-a', 'org-a', 'application-a', 'opaque-subject-a', 'canvas',
                 'canvas.assignment_score',
                 '{\"course_id\":\"course-a\",\"activity_id\":\"activity-a\"}'::jsonb,
                 '{\"score_percent\":92}'::jsonb, '{\"status\":\"VERIFIED\"}'::jsonb,
                 '{\"source\":\"canvas_rest\"}'::jsonb, 'score-a', 'logical-a',
                 'revision-a', 'payload-a', clock_timestamp(), clock_timestamp(),
                 clock_timestamp())",
        "INSERT INTO issuance_service.evidence_fact_heads
             (organization_id, application_id, logical_key, fact_id)
         VALUES ('org-a', 'application-a', 'logical-a', 'fact-a')",
    ] {
        sqlx::query(statement).execute(pool).await.unwrap();
    }
}

async fn assert_authorization_only_race(
    pool: &sqlx::PgPool,
    repository: &PostgresCredentialRepository,
    key: &[u8],
) {
    let token = format!("authorization-only-token-{}", Uuid::new_v4());
    sqlx::query(
        "INSERT INTO issuance_service.authorization_sessions
             (id, organization_id, issuer_state, credential_configuration_ids,
              access_token, dpop_jkt)
         VALUES ('authorization-session-race', 'org-a', NULL,
                 '[\"OpenBadgeCredential#sd-jwt\"]'::jsonb, $1, 'dpop-contract')",
    )
    .bind(token_digest(key, &token))
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO credential_template_service.credential_templates
             (organization_id, credential_type, status, issuer_did, issuer_algorithm, updated_at)
         VALUES ('org-a', 'OpenBadgeCredential', 'active',
                 'did:web:issuer.example', 'ES256', clock_timestamp())",
    )
    .execute(pool)
    .await
    .unwrap();
    let session = repository
        .authorization_by_access_token(&token)
        .await
        .unwrap()
        .unwrap();
    let (first, second) = tokio::join!(
        repository.ensure_authorization_transaction(&session, &token),
        repository.ensure_authorization_transaction(&session, &token)
    );
    let first = first.unwrap();
    let second = second.unwrap();
    assert_eq!(first.id, "dca62a6b-abc0-590d-906b-2582303615e5");
    assert_eq!(first.id, second.id);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM issuance_service.issuance_transactions WHERE id = $1",
        )
        .bind(&first.id)
        .fetch_one(pool)
        .await
        .unwrap(),
        1
    );
    let (first_claim, second_claim) = tokio::join!(
        repository.claim_for_signing(&first, "urn:uuid:auth-only-contract"),
        repository.claim_for_signing(&second, "urn:uuid:auth-only-contract")
    );
    assert_ne!(
        first_claim.unwrap().is_some(),
        second_claim.unwrap().is_some()
    );
}

async fn assert_initiation_idempotency_race(repository: &PostgresCredentialRepository) {
    let now = Utc::now();
    let key_hash = "a".repeat(64);
    let request_hash = "b".repeat(64);
    let transaction = CredentialTransaction {
        id: Uuid::new_v4().to_string(),
        organization_id: "org-initiation-race".to_owned(),
        credential_template_id: "template-initiation".to_owned(),
        revocation_profile_id: Some("profile-initiation".to_owned()),
        renewal_of_credential_id: None,
        applicant_id: Some("applicant-initiation".to_owned()),
        application_id: Some("application-initiation".to_owned()),
        subject_did: Some("did:key:initiation-holder".to_owned()),
        idempotency_key_hash: Some(key_hash.clone()),
        idempotency_request_hash: Some(request_hash.clone()),
        status: CredentialTransactionStatus::Pending,
        pre_authorized_code: format!("pre-auth-{}", Uuid::new_v4()),
        nonce: None,
        claims: serde_json::from_value(json!({"degree": "BSc"})).unwrap(),
        credential_type: Some("OpenBadgeCredential".to_owned()),
        selective_disclosure_claims: vec!["degree".to_owned()],
        zk_predicate_claims: Vec::new(),
        credential_payload_format: "w3c_vcdm_v2_sd_jwt".to_owned(),
        wallet_configs: vec![json!({"wallet_id": "default"})],
        validity_days: 365,
        renewable: true,
        renewal_window_days: 30,
        delivery_mode: "wallet_only".to_owned(),
        issuer_profile_id: Some("issuer-profile-initiation".to_owned()),
        issuer_mode: "org_managed".to_owned(),
        issuer_did: Some("did:web:issuer.example".to_owned()),
        issuer_algorithm: Some("ES256".to_owned()),
        signing_service_id: Some("kms-initiation".to_owned()),
        reserved_credential_id: None,
        oid4vci_client_id: Some("wallet-client-initiation".to_owned()),
        created_at: now,
        expires_at: now + Duration::days(7),
    };
    let mut retry = transaction.clone();
    retry.id = Uuid::new_v4().to_string();
    retry.pre_authorized_code = format!("pre-auth-{}", Uuid::new_v4());
    let (first, second) = tokio::join!(
        repository.reserve_idempotently(&transaction),
        repository.reserve_idempotently(&retry)
    );
    let first = first.unwrap();
    let second = second.unwrap();
    assert_ne!(first.created, second.created);
    assert_eq!(first.transaction.id, second.transaction.id);
    assert_eq!(first.transaction.created_at, second.transaction.created_at);
    assert_eq!(first.transaction.expires_at, second.transaction.expires_at);
    assert_eq!(
        repository
            .recover_idempotently(
                &transaction.organization_id,
                &IdempotencyBinding {
                    key_hash: key_hash.clone(),
                    request_hash: request_hash.clone(),
                },
            )
            .await
            .unwrap()
            .unwrap()
            .id,
        first.transaction.id
    );
    assert_eq!(
        repository
            .recover_idempotently(
                &transaction.organization_id,
                &IdempotencyBinding {
                    key_hash,
                    request_hash: "c".repeat(64),
                },
            )
            .await,
        Err(InitiationRepositoryError::IdempotencyConflict)
    );
}

async fn create_contract_schema(pool: &sqlx::PgPool) {
    sqlx::query("CREATE SCHEMA IF NOT EXISTS issuance_service")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("CREATE SCHEMA IF NOT EXISTS credential_template_service")
        .execute(pool)
        .await
        .unwrap();
    drop_contract_schema(pool).await;
    for statement in [
        "CREATE TABLE issuance_service.issuance_transactions (
            id TEXT PRIMARY KEY, organization_id TEXT NOT NULL,
            credential_template_id TEXT NOT NULL DEFAULT '', revocation_profile_id TEXT,
            renewal_of_credential_id TEXT, applicant_id TEXT, application_id TEXT,
            subject_did TEXT, idempotency_key_hash TEXT, idempotency_request_hash TEXT,
            status TEXT NOT NULL, pre_auth_code TEXT NOT NULL UNIQUE,
            access_token TEXT, c_nonce TEXT, claims JSONB NOT NULL DEFAULT '{}'::jsonb,
            credential_type TEXT, selective_disclosure_claims JSONB DEFAULT '[]'::jsonb,
            zk_predicate_claims JSONB DEFAULT '[]'::jsonb,
            credential_payload_format TEXT NOT NULL DEFAULT 'w3c_vcdm_v2_sd_jwt',
            wallet_configs JSONB DEFAULT '[]'::jsonb, validity_days INTEGER NOT NULL DEFAULT 365,
            renewable BOOLEAN NOT NULL DEFAULT false,
            renewal_window_days INTEGER NOT NULL DEFAULT 30,
            delivery_mode TEXT NOT NULL DEFAULT 'wallet_only',
            issuer_profile_id TEXT, issuer_mode TEXT NOT NULL DEFAULT 'org_managed',
            issuer_did_override TEXT, issuer_algorithm TEXT, signing_service_id TEXT,
            reserved_credential_id TEXT, oid4vci_client_id TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
            expires_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp() + interval '15 minutes',
            issued_at TIMESTAMPTZ,
            UNIQUE (organization_id, idempotency_key_hash))",
        "CREATE TABLE issuance_service.issued_credentials (
            id TEXT PRIMARY KEY, transaction_id TEXT NOT NULL UNIQUE,
            organization_id TEXT NOT NULL, credential_template_id TEXT NOT NULL,
            applicant_id TEXT, subject_did TEXT, issuer_did TEXT,
            revocation_profile_id TEXT, renewed_from_credential_id TEXT,
            renewed_to_credential_id TEXT,
            status_list_entries JSONB NOT NULL, credential_jwt TEXT NOT NULL,
            credential_hash TEXT NOT NULL, status TEXT NOT NULL,
            status_updated_at TIMESTAMPTZ NOT NULL, revoked BOOLEAN NOT NULL,
            revoked_at TIMESTAMPTZ, revocation_reason TEXT,
            issued_at TIMESTAMPTZ NOT NULL, expires_at TIMESTAMPTZ)",
        "CREATE TABLE issuance_service.applications (
            id TEXT PRIMARY KEY, organization_id TEXT NOT NULL,
            application_template_id TEXT, status TEXT, issuance_transaction_id TEXT,
            credential_id TEXT, form_data JSONB NOT NULL DEFAULT '{}'::jsonb,
            integration_context JSONB NOT NULL DEFAULT '{}'::jsonb,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp())",
        "CREATE TABLE issuance_service.oid4vci_registered_clients (
            organization_id TEXT NOT NULL, client_id TEXT NOT NULL,
            jwks JSONB NOT NULL, token_endpoint_auth_method TEXT NOT NULL,
            active BOOLEAN NOT NULL,
            PRIMARY KEY (organization_id, client_id))",
        "CREATE TABLE issuance_service.application_templates (
            id TEXT PRIMARY KEY, organization_id TEXT NOT NULL,
            credential_template_id TEXT NOT NULL, approval_policy_set_id TEXT,
            status TEXT NOT NULL)",
        "CREATE TABLE issuance_service.canvas_platforms (
            id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, canvas_account_id TEXT,
            registration_status TEXT, enabled BOOLEAN NOT NULL, archived_at TIMESTAMPTZ)",
        "CREATE TABLE issuance_service.canvas_program_bindings (
            id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, platform_id TEXT,
            application_template_id TEXT, credential_template_id TEXT,
            auto_approve_on_evidence BOOLEAN NOT NULL DEFAULT false,
            evidence_requirements JSONB NOT NULL, approval_policy_set_id TEXT,
            config_version INTEGER, validated_config_version INTEGER,
            readiness_checks JSONB, readiness_validated_at TIMESTAMPTZ,
            activated_at TIMESTAMPTZ, archived_at TIMESTAMPTZ,
            credential_template_snapshot JSONB, canvas_credentials JSONB NOT NULL DEFAULT '{}'::jsonb,
            enabled BOOLEAN NOT NULL)",
        "CREATE TABLE issuance_service.evidence_facts (
            id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, application_id TEXT NOT NULL,
            subject_id TEXT, provider TEXT, fact_type TEXT, scope JSONB, assertion JSONB,
            verification JSONB, source JSONB, requirement_id TEXT, logical_key TEXT,
            source_revision TEXT, payload_hash TEXT, effective_at TIMESTAMPTZ,
            observed_at TIMESTAMPTZ, created_at TIMESTAMPTZ)",
        "CREATE TABLE issuance_service.evidence_fact_heads (
            organization_id TEXT NOT NULL, application_id TEXT NOT NULL,
            logical_key TEXT NOT NULL, fact_id TEXT NOT NULL)",
        "CREATE TABLE issuance_service.canvas_evidence_sync_targets (
            id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, platform_id TEXT NOT NULL,
            binding_id TEXT NOT NULL, target_type TEXT NOT NULL, logical_key TEXT NOT NULL,
            application_id TEXT, enabled BOOLEAN NOT NULL, schedule_seconds INTEGER NOT NULL,
            next_run_at TIMESTAMPTZ NOT NULL, config_version INTEGER NOT NULL,
            metadata JSON NOT NULL, created_at TIMESTAMPTZ NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL, UNIQUE (organization_id, logical_key))",
        "CREATE TABLE issuance_service.issuance_events (
            id TEXT PRIMARY KEY, transaction_id TEXT, application_id TEXT,
            event_type TEXT NOT NULL, metadata JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL)",
        "CREATE TABLE issuance_service.credential_delivery_records (
            id TEXT PRIMARY KEY, credential_id TEXT NOT NULL, transaction_id TEXT NOT NULL,
            organization_id TEXT NOT NULL, delivery_target TEXT NOT NULL,
            delivery_mode TEXT NOT NULL, status TEXT NOT NULL, canvas_account_id TEXT,
            external_credential_id TEXT, external_issuer_id TEXT, last_error TEXT,
            metadata JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL)",
        "CREATE TABLE issuance_service.canvas_award_candidates (
            id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, application_id TEXT,
            binding_id TEXT NOT NULL, platform_id TEXT NOT NULL, state TEXT NOT NULL,
            claimed_credential_id TEXT, updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp())",
        "CREATE TABLE issuance_service.authorization_sessions (
            id TEXT PRIMARY KEY, organization_id TEXT, issuer_state TEXT,
            credential_configuration_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
            access_token TEXT, dpop_jkt TEXT)",
        "CREATE TABLE credential_template_service.credential_templates (
            id BIGSERIAL PRIMARY KEY, organization_id TEXT NOT NULL, credential_type TEXT,
            status TEXT NOT NULL, issuer_did TEXT, issuer_algorithm TEXT,
            updated_at TIMESTAMPTZ NOT NULL)",
    ] {
        sqlx::query(statement).execute(pool).await.unwrap();
    }
}

async fn drop_contract_schema(pool: &sqlx::PgPool) {
    for statement in [
        "DROP TABLE IF EXISTS issuance_service.credential_delivery_records",
        "DROP TABLE IF EXISTS issuance_service.oid4vci_registered_clients",
        "DROP TABLE IF EXISTS issuance_service.issuance_events",
        "DROP TABLE IF EXISTS issuance_service.canvas_evidence_sync_targets",
        "DROP TABLE IF EXISTS issuance_service.evidence_fact_heads",
        "DROP TABLE IF EXISTS issuance_service.evidence_facts",
        "DROP TABLE IF EXISTS issuance_service.canvas_program_bindings",
        "DROP TABLE IF EXISTS issuance_service.canvas_platforms",
        "DROP TABLE IF EXISTS issuance_service.application_templates",
        "DROP TABLE IF EXISTS issuance_service.canvas_award_candidates",
        "DROP TABLE IF EXISTS issuance_service.issued_credentials",
        "DROP TABLE IF EXISTS issuance_service.applications",
        "DROP TABLE IF EXISTS issuance_service.authorization_sessions",
        "DROP TABLE IF EXISTS issuance_service.issuance_transactions",
        "DROP TABLE IF EXISTS credential_template_service.credential_templates",
    ] {
        sqlx::query(statement).execute(pool).await.unwrap();
    }
}
