use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use marty_issuance_service::{
    client_auth::RegisteredClientRepository,
    token_exchange::TokenExchangeRepository,
    token_postgres::PostgresTokenExchangeRepository,
    transaction_postgres::PostgresTransactionReadRepository,
    transaction_reads::{TransactionReadError, TransactionReadRepository, TransactionStatus},
};
use sha2::Sha256;
use sqlx::postgres::PgPoolOptions;
use sqlx::Row;

#[tokio::test]
async fn transaction_projection_round_trips_and_enforces_tenant_lists_when_configured() {
    // The deployed Python-owned schema uses json. Also retain compatibility
    // with installations/tests using jsonb; neither requires a schema rewrite.
    for claims_type in ["json", "jsonb"] {
        transaction_contract(claims_type).await;
    }
}

async fn transaction_contract(claims_type: &str) {
    let Ok(database_url) = std::env::var("ISSUANCE_POSTGRES_TEST_URL") else {
        return;
    };
    let database_name = url::Url::parse(&database_url)
        .expect("issuance PostgreSQL contract URL must parse")
        .path()
        .trim_start_matches('/')
        .to_owned();
    assert!(
        database_name.ends_with("_test"),
        "ISSUANCE_POSTGRES_TEST_URL must name a dedicated *_test database"
    );
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .expect("issuance PostgreSQL contract database must connect");

    sqlx::query("CREATE SCHEMA IF NOT EXISTS issuance_service")
        .execute(&pool)
        .await
        .expect("issuance schema must be available");
    sqlx::query("DROP TABLE IF EXISTS issuance_service.issuance_transactions")
        .execute(&pool)
        .await
        .expect("stale issuance contract table must be removable");
    sqlx::query(
        "CREATE TABLE issuance_service.issuance_transactions (
            id TEXT PRIMARY KEY,
            organization_id TEXT NOT NULL,
            credential_template_id TEXT NOT NULL,
            applicant_id TEXT,
            application_id TEXT,
            subject_did TEXT,
            status TEXT NOT NULL,
            pre_auth_code TEXT NOT NULL UNIQUE,
            credential_type TEXT,
            created_at TIMESTAMPTZ NOT NULL,
            expires_at TIMESTAMPTZ NOT NULL,
            issued_at TIMESTAMPTZ,
            revoked_at TIMESTAMPTZ,
            revocation_reason TEXT,
            access_token TEXT,
            c_nonce TEXT,
            claims JSON NOT NULL DEFAULT '{}'::json,
            oid4vci_client_id TEXT
        )",
    )
    .execute(&pool)
    .await
    .expect("issuance contract table must be created");
    if claims_type == "jsonb" {
        // Only this newly created, empty test table is changed. Literal SQL
        // keeps the storage matrix independent of dynamic query construction.
        sqlx::query(
            "ALTER TABLE issuance_service.issuance_transactions
             ALTER COLUMN claims TYPE JSONB USING claims::jsonb,
             ALTER COLUMN claims SET DEFAULT '{}'::jsonb",
        )
        .execute(&pool)
        .await
        .unwrap();
    }
    let actual_claims_type: String = sqlx::query_scalar(
        "SELECT data_type FROM information_schema.columns
         WHERE table_schema = 'issuance_service' AND table_name = 'issuance_transactions'
           AND column_name = 'claims'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(actual_claims_type, claims_type);

    let created_at = timestamp("2026-08-20T12:34:56.123000+00:00");
    let expires_at = timestamp("2099-08-20T12:49:56+00:00");
    for (id, organization_id, status, revoked_at) in [
        ("tx-a", "org-a", "pending", None),
        (
            "tx-revoked",
            "org-a",
            "revoked",
            Some(timestamp("2026-08-21T09:30:00+00:00")),
        ),
        ("tx-foreign", "org-b", "authorized", None),
    ] {
        sqlx::query(
            "INSERT INTO issuance_service.issuance_transactions (
                id, organization_id, credential_template_id, applicant_id, application_id,
                subject_did, status, pre_auth_code, credential_type, created_at, expires_at,
                issued_at, revoked_at, revocation_reason
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
        )
        .bind(id)
        .bind(organization_id)
        .bind(format!("template-{id}"))
        .bind(Some(format!("applicant-{id}")))
        .bind(Some(format!("application-{id}")))
        .bind(Some(format!("did:key:{id}")))
        .bind(status)
        .bind(format!("pre-auth-{id}"))
        .bind(Some(format!("Credential{id}")))
        .bind(created_at)
        .bind(expires_at)
        .bind(None::<DateTime<Utc>>)
        .bind(revoked_at)
        .bind(revoked_at.map(|_| "superseded"))
        .execute(&pool)
        .await
        .expect("issuance transaction fixture must insert");
    }

    let repository = PostgresTransactionReadRepository::new(pool.clone());
    let transaction = repository
        .get("tx-revoked")
        .await
        .expect("transaction lookup must succeed")
        .expect("transaction must exist");
    assert_eq!(transaction.organization_id, "org-a");
    assert_eq!(transaction.status, TransactionStatus::Revoked);
    assert_eq!(transaction.created_at, created_at);
    assert_eq!(
        transaction.revoked_at,
        Some(timestamp("2026-08-21T09:30:00+00:00"))
    );
    assert_eq!(transaction.revocation_reason.as_deref(), Some("superseded"));
    assert!(repository
        .get("missing")
        .await
        .expect("missing lookup must succeed")
        .is_none());

    let tenant_transactions = repository
        .list("org-a")
        .await
        .expect("tenant list must succeed");
    assert_eq!(tenant_transactions.len(), 2);
    assert!(tenant_transactions
        .iter()
        .all(|transaction| transaction.organization_id == "org-a"));

    sqlx::query(
        "UPDATE issuance_service.issuance_transactions SET status = 'unknown' WHERE id = 'tx-a'",
    )
    .execute(&pool)
    .await
    .expect("invalid status fixture must update");
    assert_eq!(
        repository.get("tx-a").await,
        Err(TransactionReadError::RepositoryUnavailable)
    );

    sqlx::query(
        "UPDATE issuance_service.issuance_transactions SET status = 'pending' WHERE id = 'tx-a'",
    )
    .execute(&pool)
    .await
    .expect("token fixture status must reset");
    let token_repository =
        PostgresTokenExchangeRepository::new(pool.clone(), "postgres-contract-token-hmac-key");
    // Exercise both branches deterministically before the concurrent claim
    // test. A race alone may never exercise a successful DPoP-bound update.
    for dpop_jkt in [None, Some("deterministic-dpop-thumbprint")] {
        let original_claims = serde_json::json!({
            "subject": {"name": "Synthetic \u{00e9}vidence", "verified": true},
            "counter": 9007199254740991_u64,
            "roles": ["learner", "reviewer"],
            "optional": null
        });
        sqlx::query(
            "UPDATE issuance_service.issuance_transactions
             SET status = 'pending', access_token = NULL, c_nonce = 'old-nonce', claims = $1::json
             WHERE id = 'tx-a'",
        )
        .bind(serde_json::to_string(&original_claims).unwrap())
        .execute(&pool)
        .await
        .unwrap();
        let original_storage: String = sqlx::query_scalar(
            "SELECT claims::text FROM issuance_service.issuance_transactions WHERE id = 'tx-a'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let pending = token_repository
            .transaction_by_pre_authorized_code("pre-auth-tx-a")
            .await
            .unwrap()
            .unwrap();
        assert!(token_repository
            .claim_transaction(&pending, "deterministic-clear-token", dpop_jkt)
            .await
            .expect("token claim must support the actual claims storage type"));
        assert!(!token_repository
            .claim_transaction(&pending, "replayed-token", Some("different-thumbprint"))
            .await
            .unwrap());
        let persisted = sqlx::query(
            "SELECT claims, access_token, c_nonce, status
             FROM issuance_service.issuance_transactions WHERE id = 'tx-a'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let mut expected_claims = original_claims;
        if let Some(thumbprint) = dpop_jkt {
            expected_claims["_dpop_jkt"] = thumbprint.into();
        }
        assert_eq!(
            persisted.get::<serde_json::Value, _>("claims"),
            expected_claims
        );
        if dpop_jkt.is_none() {
            let after_storage: String = sqlx::query_scalar(
                "SELECT claims::text FROM issuance_service.issuance_transactions WHERE id = 'tx-a'",
            )
            .fetch_one(&pool)
            .await
            .unwrap();
            assert_eq!(
                after_storage, original_storage,
                "unbound token exchange must not rewrite claims"
            );
        }
        assert_eq!(
            persisted.get::<String, _>("access_token"),
            expected_token_hash("deterministic-clear-token")
        );
        assert_eq!(persisted.get::<String, _>("status"), "authorized");
        assert!(persisted.get::<Option<String>, _>("c_nonce").is_none());
    }
    sqlx::query(
        "UPDATE issuance_service.issuance_transactions
         SET status = 'pending', access_token = NULL, claims = '{}' WHERE id = 'tx-a'",
    )
    .execute(&pool)
    .await
    .unwrap();
    let token_transaction = token_repository
        .transaction_by_pre_authorized_code("pre-auth-tx-a")
        .await
        .expect("pre-authorized lookup must succeed")
        .expect("pre-authorized transaction must exist");
    let (first_claim, second_claim) = tokio::join!(
        token_repository.claim_transaction(
            &token_transaction,
            "clear-token-first",
            Some("dpop-thumbprint")
        ),
        token_repository.claim_transaction(&token_transaction, "clear-token-second", None)
    );
    let first_claim = first_claim.expect("first transaction claim");
    let second_claim = second_claim.expect("second transaction claim");
    assert_ne!(first_claim, second_claim);
    let stored = sqlx::query(
        "SELECT access_token, claims, c_nonce, status
         FROM issuance_service.issuance_transactions WHERE id = 'tx-a'",
    )
    .fetch_one(&pool)
    .await
    .expect("claimed transaction must load");
    let stored_hash: String = stored.try_get("access_token").unwrap();
    assert_ne!(stored_hash, "clear-token-first");
    assert_ne!(stored_hash, "clear-token-second");
    let claimed_token = if first_claim {
        "clear-token-first"
    } else {
        "clear-token-second"
    };
    assert_eq!(stored_hash, expected_token_hash(claimed_token));
    assert_eq!(stored.try_get::<String, _>("status").unwrap(), "authorized");
    assert!(stored
        .try_get::<Option<String>, _>("c_nonce")
        .unwrap()
        .is_none());
    let claims: serde_json::Value = stored.try_get("claims").unwrap();
    if first_claim {
        assert_eq!(claims["_dpop_jkt"], "dpop-thumbprint");
    } else {
        assert!(claims.get("_dpop_jkt").is_none());
    }

    sqlx::query("DROP TABLE IF EXISTS issuance_service.authorization_sessions")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "CREATE TABLE issuance_service.authorization_sessions (
            id TEXT PRIMARY KEY, code TEXT NOT NULL UNIQUE, client_id TEXT NOT NULL,
            organization_id TEXT, redirect_uri TEXT, issuer_state TEXT,
            credential_configuration_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
            code_challenge TEXT, code_challenge_method TEXT, status TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL, expires_at TIMESTAMPTZ NOT NULL,
            access_token TEXT, c_nonce TEXT, dpop_jkt TEXT
        )",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO issuance_service.authorization_sessions
         (id, code, client_id, organization_id, status, created_at, expires_at)
         VALUES ('auth-a', 'code-a', 'wallet-a', 'org-a', 'pending', clock_timestamp(),
                 clock_timestamp() + interval '10 minutes')",
    )
    .execute(&pool)
    .await
    .unwrap();
    let authorization = token_repository
        .authorization_by_code("code-a")
        .await
        .unwrap()
        .unwrap();
    let (first_auth, second_auth) = tokio::join!(
        token_repository.claim_authorization(&authorization, "auth-token-first", Some("auth-jkt")),
        token_repository.claim_authorization(&authorization, "auth-token-second", None)
    );
    assert_ne!(first_auth.unwrap(), second_auth.unwrap());

    sqlx::query("DROP TABLE IF EXISTS issuance_service.oid4vci_client_assertions")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DROP TABLE IF EXISTS issuance_service.oid4vci_registered_clients")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "CREATE TABLE issuance_service.oid4vci_registered_clients (
            organization_id TEXT NOT NULL, client_id TEXT NOT NULL, jwks JSONB NOT NULL,
            token_endpoint_auth_method TEXT NOT NULL, active BOOLEAN NOT NULL,
            PRIMARY KEY (organization_id, client_id)
        )",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TABLE issuance_service.oid4vci_client_assertions (
            organization_id TEXT NOT NULL, client_id TEXT NOT NULL, jti TEXT NOT NULL,
            expires_at TIMESTAMPTZ NOT NULL, created_at TIMESTAMPTZ NOT NULL,
            PRIMARY KEY (organization_id, client_id, jti)
        )",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO issuance_service.oid4vci_registered_clients
         VALUES ('org-a', 'wallet-a', '{\"keys\": []}'::jsonb, 'private_key_jwt', true)",
    )
    .execute(&pool)
    .await
    .unwrap();
    let client = token_repository
        .client("org-a", "wallet-a")
        .await
        .unwrap()
        .unwrap();
    assert!(client.active);
    let expires_at = Utc::now() + chrono::Duration::minutes(5);
    let (first_assertion, second_assertion) = tokio::join!(
        token_repository.claim_assertion("org-a", "wallet-a", "jti-a", expires_at),
        token_repository.claim_assertion("org-a", "wallet-a", "jti-a", expires_at)
    );
    assert_ne!(first_assertion.unwrap(), second_assertion.unwrap());

    sqlx::query("DROP TABLE issuance_service.oid4vci_client_assertions")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DROP TABLE issuance_service.oid4vci_registered_clients")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DROP TABLE issuance_service.authorization_sessions")
        .execute(&pool)
        .await
        .unwrap();

    sqlx::query("DROP TABLE issuance_service.issuance_transactions")
        .execute(&pool)
        .await
        .expect("issuance contract table must be removed");
}

fn timestamp(value: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(value)
        .expect("contract timestamp")
        .to_utc()
}

fn expected_token_hash(value: &str) -> String {
    let mut expected = Hmac::<Sha256>::new_from_slice(b"postgres-contract-token-hmac-key").unwrap();
    expected.update(value.as_bytes());
    hex::encode(expected.finalize().into_bytes())
}
