use hmac::{Hmac, Mac};
use sha2::Sha256;
use sqlx::{postgres::PgPoolOptions, Row};

use marty_issuance_service::{
    migration, oid4vci_authorization::Oid4vciAuthorizationRepository,
    oid4vci_authorization_postgres::PostgresOid4vciAuthorizationRepository,
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
    sqlx::raw_sql(
        r#"CREATE SCHEMA IF NOT EXISTS issuance_service;
         DROP TABLE IF EXISTS issuance_service.issuance_events;
         DROP TABLE IF EXISTS issuance_service.issued_credentials;
         DROP TABLE IF EXISTS issuance_service.authorization_sessions;
         DROP TABLE IF EXISTS issuance_service.issuance_transactions;
         CREATE TABLE issuance_service.issuance_transactions (
             id text PRIMARY KEY, organization_id text NOT NULL, application_id text,
             pre_auth_code text, oid4vci_client_id text,
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
             (id, organization_id, application_id, access_token, claims)
             VALUES ('tx-legacy', 'org-a', 'application-a', 'digest-a', '{}'::jsonb);
         INSERT INTO issuance_service.authorization_sessions
             VALUES ('session-legacy', 'wallet-a', 'org-a', NULL, 'digest-b', NULL);
         INSERT INTO issuance_service.issued_credentials
             VALUES ('credential-a', 'tx-legacy', 'org-a');
         INSERT INTO issuance_service.issuance_events
             VALUES ('binding-a', 'tx-legacy', NULL, 'oid4vci_notification_binding',
                     '{"notification_id":"notification-a","credential_id":"credential-a"}'::json,
                     clock_timestamp());"#,
    )
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

fn token_digest(key: &[u8], token: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(token.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}
