use hmac::{Hmac, Mac};
use sha2::Sha256;
use sqlx::{postgres::PgPoolOptions, Row};

use marty_issuance_service::{
    migration,
    oid4vci_authorization::Oid4vciAuthorizationRepository,
    oid4vci_authorization_postgres::PostgresOid4vciAuthorizationRepository,
    oid4vci_management::{Oid4vciManagementRepository, RegisteredClientWrite},
    oid4vci_management_postgres::PostgresOid4vciManagementRepository,
};

#[tokio::test]
async fn migration_bounds_legacy_tokens_and_backfills_notification_audit_identity() {
    let Ok(database_url) = std::env::var("ISSUANCE_POSTGRES_TEST_URL") else {
        return;
    };
    let database_name = url::Url::parse(&database_url)
        .unwrap()
        .path()
        .trim_start_matches('/')
        .to_owned();
    assert!(database_name.ends_with("_test"));
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .unwrap();
    sqlx::raw_sql(include_str!("fixtures/oid4vci_migration_base.sql"))
        .execute(&pool)
        .await
        .unwrap();

    let legacy_token = "legacy-linked-token";
    let legacy_key = b"migration-token-key";
    let legacy_digest = token_digest(legacy_key, legacy_token);
    sqlx::query(
        "INSERT INTO issuance_service.issuance_transactions
             (id, organization_id, application_id, pre_auth_code,
              oid4vci_client_id, access_token, claims)
         VALUES ('dca62a6b-abc0-590d-906b-2582303615e5', 'org-a', NULL,
                 'legacy-random-capability', NULL, $1,
                 '{\"_dpop_jkt\":\"legacy-jkt\"}'::jsonb)",
    )
    .bind(&legacy_digest)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO issuance_service.authorization_sessions
             (id, client_id, organization_id, issuer_state, access_token, dpop_jkt)
         VALUES ('authorization-session-race', 'wallet-a', 'org-a', NULL, $1,
                 'legacy-jkt')",
    )
    .bind(&legacy_digest)
    .execute(&pool)
    .await
    .unwrap();

    migration::migrate(&pool).await.unwrap();
    migration::migrate(&pool).await.unwrap();
    let transaction_remaining: f64 = sqlx::query_scalar(
        "SELECT extract(epoch FROM access_token_expires_at - clock_timestamp())::double precision
         FROM issuance_service.issuance_transactions
         WHERE id = 'tx-legacy'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let session_remaining: f64 = sqlx::query_scalar(
        "SELECT extract(epoch FROM access_token_expires_at - clock_timestamp())::double precision
         FROM issuance_service.authorization_sessions
         WHERE id = 'session-legacy'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    for remaining in [transaction_remaining, session_remaining] {
        assert!((1798.0..=1800.0).contains(&remaining));
    }
    let linked_expiry_count: i64 = sqlx::query_scalar(
        "SELECT count(DISTINCT access_token_expires_at)
         FROM (
             SELECT access_token_expires_at
             FROM issuance_service.issuance_transactions
             WHERE id = 'dca62a6b-abc0-590d-906b-2582303615e5'
             UNION ALL
             SELECT access_token_expires_at
             FROM issuance_service.authorization_sessions
             WHERE id = 'authorization-session-race'
         ) AS linked",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(linked_expiry_count, 1);
    assert!(
        PostgresOid4vciAuthorizationRepository::new(pool.clone(), legacy_key)
            .access_token_grant(legacy_token)
            .await
            .unwrap()
            .is_some()
    );
    let binding = sqlx::query(
        "SELECT application_id, metadata FROM issuance_service.issuance_events
         WHERE id = 'binding-a'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(binding.get::<String, _>("application_id"), "application-a");
    assert_eq!(
        binding.get::<serde_json::Value, _>("metadata")["organization_id"],
        "org-a"
    );
    let duplicate = sqlx::query(
        r#"INSERT INTO issuance_service.issuance_events
             VALUES ('binding-b', 'tx-legacy', 'application-a',
                     'oid4vci_notification_binding',
                     '{"notification_id":"notification-a","credential_id":"credential-a","organization_id":"org-a"}'::json,
                     clock_timestamp())"#,
    )
    .execute(&pool)
    .await;
    assert!(
        duplicate.is_err(),
        "notification IDs must be globally unique"
    );

    sqlx::raw_sql(
        r#"DROP TABLE issuance_service.issuance_events;
         DROP TABLE issuance_service.issued_credentials;
         DROP TABLE issuance_service.authorization_sessions;
         DROP TABLE issuance_service.issuance_transactions;
         CREATE TABLE issuance_service.issuance_transactions (
             id text PRIMARY KEY, organization_id text NOT NULL, application_id text,
             access_token text, claims jsonb NOT NULL DEFAULT '{}'::jsonb);
         CREATE TABLE issuance_service.authorization_sessions (
             id text PRIMARY KEY, client_id text NOT NULL, organization_id text,
             issuer_state text, access_token text, dpop_jkt text);
         CREATE TABLE issuance_service.issued_credentials (
             id text PRIMARY KEY, transaction_id text NOT NULL,
             organization_id text NOT NULL);
         CREATE TABLE issuance_service.issuance_events (
             id text PRIMARY KEY, transaction_id text, application_id text,
             event_type text NOT NULL, metadata json NOT NULL,
             created_at timestamptz NOT NULL);
         INSERT INTO issuance_service.issuance_transactions
             VALUES ('tx-corrupt', 'org-a', 'application-a', 'digest-corrupt', '{}'::jsonb);
         INSERT INTO issuance_service.issued_credentials
             VALUES ('credential-a', 'tx-corrupt', 'org-a');
         INSERT INTO issuance_service.issuance_events
             VALUES ('binding-orphan', 'missing-transaction', NULL,
                     'oid4vci_notification_binding',
                     '{"notification_id":"notification-orphan","credential_id":"missing-credential"}'::json,
                     clock_timestamp());"#,
    )
    .execute(&pool)
    .await
    .unwrap();

    let error = migration::migrate(&pool)
        .await
        .expect_err("orphaned legacy notification bindings must fail closed");
    assert!(error
        .to_string()
        .contains("inconsistent legacy OID4VCI notification binding"));
    let expiry_column_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (
             SELECT 1 FROM information_schema.columns
             WHERE table_schema = 'issuance_service'
               AND table_name = 'issuance_transactions'
               AND column_name = 'access_token_expires_at')",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!expiry_column_exists, "failed migration must roll back DDL");
    let orphan = sqlx::query(
        "SELECT application_id, metadata FROM issuance_service.issuance_events
         WHERE id = 'binding-orphan'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(orphan.get::<Option<String>, _>("application_id").is_none());
    assert!(orphan.get::<serde_json::Value, _>("metadata")["organization_id"].is_null());
    let binding_index: Option<String> = sqlx::query_scalar(
        "SELECT to_regclass('issuance_service.ux_issuance_events_oid4vci_notification_id')::text",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        binding_index.is_none(),
        "failed migration must not create index"
    );

    sqlx::raw_sql(
        r#"DROP TABLE issuance_service.issuance_events;
         DROP TABLE issuance_service.issued_credentials;
         DROP TABLE issuance_service.authorization_sessions;
         DROP TABLE issuance_service.issuance_transactions;
         CREATE TABLE issuance_service.issuance_transactions (
             id text PRIMARY KEY, organization_id text NOT NULL, application_id text,
             access_token text, access_token_expires_at text,
             claims jsonb NOT NULL DEFAULT '{}'::jsonb);
         CREATE TABLE issuance_service.authorization_sessions (
             id text PRIMARY KEY, access_token text,
             access_token_expires_at timestamptz);
         CREATE TABLE issuance_service.issued_credentials (
             id text PRIMARY KEY, transaction_id text NOT NULL,
             organization_id text NOT NULL);
         CREATE TABLE issuance_service.issuance_events (
             id text PRIMARY KEY, transaction_id text, application_id text,
             event_type text NOT NULL, metadata json NOT NULL,
             created_at timestamptz NOT NULL);"#,
    )
    .execute(&pool)
    .await
    .unwrap();
    let error = migration::migrate(&pool)
        .await
        .expect_err("wrong-typed preexisting expiry columns must fail closed");
    assert!(error
        .to_string()
        .contains("compatible timestamptz issuance_transactions.access_token_expires_at"));

    sqlx::raw_sql(
        r#"DROP TABLE issuance_service.issuance_events;
         DROP TABLE issuance_service.issued_credentials;
         DROP TABLE issuance_service.authorization_sessions;
         DROP TABLE issuance_service.issuance_transactions;
         CREATE TABLE issuance_service.issuance_transactions (
             id text PRIMARY KEY, organization_id text NOT NULL, application_id text,
             access_token text, access_token_expires_at timestamptz,
             claims jsonb NOT NULL DEFAULT '{}'::jsonb);
         CREATE TABLE issuance_service.authorization_sessions (
             id text PRIMARY KEY, access_token text,
             access_token_expires_at timestamptz);
         CREATE TABLE issuance_service.issued_credentials (
             id text PRIMARY KEY, transaction_id text NOT NULL,
             organization_id text NOT NULL);
         CREATE TABLE issuance_service.issuance_events (
             id text PRIMARY KEY, transaction_id text, application_id text,
             event_type text NOT NULL, metadata json NOT NULL,
             created_at timestamptz NOT NULL);
         CREATE UNIQUE INDEX ux_issuance_events_oid4vci_notification_id
             ON issuance_service.issuance_events ((metadata ->> 'not_notification_id'))
             WHERE event_type <> 'oid4vci_notification_binding';"#,
    )
    .execute(&pool)
    .await
    .unwrap();
    let error = migration::migrate(&pool)
        .await
        .expect_err("same-named incompatible notification indexes must fail closed");
    assert!(error
        .to_string()
        .contains("notification binding index is incompatible"));
}

#[test]
fn migration_documents_one_bounded_legacy_grace_and_required_uniqueness() {
    let sql = include_str!("../migrations/0001_oid4vci_public_protocol.sql");
    assert_eq!(sql.matches("interval '1800 seconds'").count(), 2);
    assert_eq!(sql.matches("transaction_timestamp()").count(), 2);
    assert!(!sql.contains("clock_timestamp() + interval '1800 seconds'"));
    assert!(sql.contains("ux_issuance_events_oid4vci_notification_id"));
    assert!(sql.contains("inconsistent legacy OID4VCI notification binding"));
}

#[tokio::test]
async fn management_repository_preserves_registration_and_idempotent_revocation_contracts() {
    let Ok(database_url) = std::env::var("ISSUANCE_POSTGRES_TEST_URL") else {
        return;
    };
    let database_name = url::Url::parse(&database_url)
        .unwrap()
        .path()
        .trim_start_matches('/')
        .to_owned();
    assert!(database_name.ends_with("_test"));
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .unwrap();
    sqlx::raw_sql(
        r#"CREATE SCHEMA IF NOT EXISTS issuance_service;
         DROP TABLE IF EXISTS issuance_service.issued_credentials;
         DROP TABLE IF EXISTS issuance_service.issuance_transactions;
         DROP TABLE IF EXISTS issuance_service.oid4vci_registered_clients;
         CREATE TABLE issuance_service.oid4vci_registered_clients (
             organization_id text NOT NULL, client_id text NOT NULL,
             jwks jsonb NOT NULL, redirect_uris jsonb NOT NULL,
             token_endpoint_auth_method text NOT NULL, active boolean NOT NULL,
             created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL,
             PRIMARY KEY (organization_id, client_id));
         CREATE TABLE issuance_service.issuance_transactions (
             id text PRIMARY KEY, organization_id text NOT NULL,
             status text NOT NULL, revoked_at timestamptz, revocation_reason text);
         CREATE TABLE issuance_service.issued_credentials (
             id text PRIMARY KEY, transaction_id text NOT NULL UNIQUE,
             organization_id text NOT NULL);
         INSERT INTO issuance_service.issuance_transactions
             VALUES ('tx-a', 'org-a', 'issued', NULL, NULL),
                    ('tx-concurrent', 'org-a', 'issued', NULL, NULL);
         INSERT INTO issuance_service.issued_credentials
             VALUES ('credential-a', 'tx-a', 'org-a');"#,
    )
    .execute(&pool)
    .await
    .unwrap();

    let repository = PostgresOid4vciManagementRepository::new(pool.clone());
    let mut write = RegisteredClientWrite {
        organization_id: "org-a".to_owned(),
        client_id: "wallet-a".to_owned(),
        jwks: serde_json::json!({"keys":[{"kid":"key-a"}]}),
        redirect_uris: vec!["https://wallet.example/callback".to_owned()],
        active: true,
    };
    repository.save_registered_client(&write).await.unwrap();
    let created = repository
        .registered_client("org-a", "wallet-a")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(created.token_endpoint_auth_method, "private_key_jwt");
    assert_eq!(created.redirect_uris, write.redirect_uris);

    write.active = false;
    write.redirect_uris = vec![];
    repository.save_registered_client(&write).await.unwrap();
    let rotated = repository
        .registered_client("org-a", "wallet-a")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rotated.created_at, created.created_at);
    assert!(rotated.updated_at >= created.updated_at);
    assert!(!rotated.active);
    assert!(rotated.redirect_uris.is_empty());

    assert_eq!(
        repository
            .transaction("tx-a")
            .await
            .unwrap()
            .unwrap()
            .status,
        "issued"
    );
    let binding = repository
        .credential_for_transaction("tx-a")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(binding.id, "credential-a");
    assert_eq!(binding.organization_id, "org-a");

    let revoked = repository
        .revoke_transaction("tx-a", Some("holder request"))
        .await
        .unwrap();
    assert_eq!(revoked.status, "revoked");
    assert_eq!(revoked.revocation_reason.as_deref(), Some("holder request"));
    let original_timestamp = revoked.revoked_at.unwrap();
    let retried = repository
        .revoke_transaction("tx-a", Some("replacement reason"))
        .await
        .unwrap();
    assert_eq!(retried.revoked_at, Some(original_timestamp));
    assert_eq!(
        retried.revocation_reason.as_deref(),
        Some("holder request"),
        "idempotent retries preserve the first committed reason"
    );

    let first_repository = repository.clone();
    let second_repository = repository.clone();
    let (first, second) = tokio::join!(
        first_repository.revoke_transaction("tx-concurrent", Some("first retry")),
        second_repository.revoke_transaction("tx-concurrent", Some("second retry"))
    );
    let first = first.unwrap();
    let second = second.unwrap();
    assert_eq!(first.revoked_at, second.revoked_at);
    assert_eq!(first.revocation_reason, second.revocation_reason);
    assert!(matches!(
        first.revocation_reason.as_deref(),
        Some("first retry" | "second retry")
    ));

    sqlx::raw_sql(
        r#"DROP TABLE issuance_service.issued_credentials;
         DROP TABLE issuance_service.issuance_transactions;
         DROP TABLE issuance_service.oid4vci_registered_clients;"#,
    )
    .execute(&pool)
    .await
    .unwrap();
}

fn token_digest(key: &[u8], token: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(token.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}
