use axum::{routing::post, Json, Router};
use chrono::{Duration, Utc};
use hmac::{Hmac, Mac};
use marty_issuance_service::canvas_issuance_guard::{
    CanvasGuardConfig, PostgresCanvasIssuanceGuard,
};
use marty_issuance_service::credential::{
    CredentialIssuanceError, CredentialLifecycle, CredentialRepository,
    CredentialTransactionStatus, IssuedCredential, IssuerContext,
};
use marty_issuance_service::credential_lifecycle::PostgresCredentialLifecycle;
use marty_issuance_service::credential_management::{
    CredentialLifecycleAction, CredentialManagementRepository, ManagedCredentialStatus,
};
use marty_issuance_service::credential_management_postgres::PostgresCredentialManagementRepository;
use marty_issuance_service::credential_postgres::PostgresCredentialRepository;
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
    revocation_server.abort();
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
    drop_contract_schema(&pool).await;
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
            subject_did TEXT, status TEXT NOT NULL, pre_auth_code TEXT NOT NULL UNIQUE,
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
            reserved_credential_id TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
            expires_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp() + interval '15 minutes',
            issued_at TIMESTAMPTZ)",
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
            credential_id TEXT,
            integration_context JSONB NOT NULL DEFAULT '{}'::jsonb,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp())",
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
