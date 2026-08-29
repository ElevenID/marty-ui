use chrono::{Duration, Utc};
use hmac::{Hmac, Mac};
use marty_issuance_service::credential::{
    CredentialRepository, CredentialTransactionStatus, IssuedCredential,
};
use marty_issuance_service::credential_postgres::PostgresCredentialRepository;
use serde_json::json;
use sha2::Sha256;
use sqlx::{postgres::PgPoolOptions, Row};
use uuid::Uuid;

fn token_digest(key: &[u8], token: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(token.as_bytes());
    hex::encode(mac.finalize().into_bytes())
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
             (id, organization_id, credential_template_id, application_id, status,
              pre_auth_code, access_token, c_nonce, claims, credential_type)
         VALUES ('tx-contract', 'org-a', 'template-a', 'application-a', 'authorized',
                 'pre-auth-contract', $1, $2, '{}'::jsonb, 'OpenBadgeCredential')",
    )
    .bind(token_digest(key.as_bytes(), &access_token))
    .bind(&nonce)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO issuance_service.applications
             (id, organization_id, credential_id, integration_context)
         VALUES ('application-a', 'org-a', NULL,
                 '{\"canvas\":{\"source\":\"canvas-lti\",\"canvas_award_candidate_id\":\"candidate-a\",\"canvas_program_binding_id\":\"binding-a\",\"canvas_platform_id\":\"platform-a\"}}')",
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

    let repository = PostgresCredentialRepository::new(pool.clone(), key.as_bytes());
    let transaction = repository
        .transaction_by_access_token(&access_token)
        .await
        .unwrap()
        .expect("Python-compatible HMAC token lookup");
    assert_eq!(transaction.nonce.as_deref(), Some(nonce.as_str()));
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
        renewed_from_credential_id: None,
        status_list_entries: vec![json!({"index": 7})],
        credential: "signed-credential".to_owned(),
        credential_hash: "credential-hash".to_owned(),
        issued_at: now,
        expires_at: now + Duration::days(365),
    };
    repository.finalize(&claimed, &issued).await.unwrap();
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

    assert_authorization_only_race(&pool, &repository, key.as_bytes()).await;
    drop_contract_schema(&pool).await;
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
            credential_payload_format TEXT NOT NULL DEFAULT 'w3c_vcdm_v2_sd_jwt',
            wallet_configs JSONB DEFAULT '[]'::jsonb, validity_days INTEGER NOT NULL DEFAULT 365,
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
            status_list_entries JSONB NOT NULL, credential_jwt TEXT NOT NULL,
            credential_hash TEXT NOT NULL, status TEXT NOT NULL,
            status_updated_at TIMESTAMPTZ NOT NULL, revoked BOOLEAN NOT NULL,
            issued_at TIMESTAMPTZ NOT NULL, expires_at TIMESTAMPTZ)",
        "CREATE TABLE issuance_service.applications (
            id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, credential_id TEXT,
            integration_context JSONB NOT NULL DEFAULT '{}'::jsonb,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp())",
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
