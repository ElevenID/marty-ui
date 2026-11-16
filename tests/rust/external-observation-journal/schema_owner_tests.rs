// SPDX-License-Identifier: AGPL-3.0-only
//! Actual registered schema and catalog validator against the disposable database.
//! These tests do not qualify the entire owner CLI or production runtime roles.
use super::*;
use crate::external_observation_schema::{validate, LOCK_MIGRATION_SQL, MIGRATION_SQL, VERSION};

#[tokio::test]
async fn registered_schema_verifies_in_read_only_transaction() {
    let f = Fixture::new().await;
    let mut tx = f.pool.begin().await.unwrap();
    sqlx::query("SET TRANSACTION READ ONLY")
        .execute(&mut *tx)
        .await
        .unwrap();
    validate(&mut tx).await.unwrap();
    tx.rollback().await.unwrap();
    assert_eq!(f.counts().await, (0, 0, 0));
    f.pool.close().await;
}

#[tokio::test]
async fn missing_owner_ledger_or_registered_version_fails_closed() {
    let f = Fixture::new().await;
    let mut tx = f.pool.begin().await.unwrap();
    sqlx::query("DELETE FROM issuance_service.rust_schema_migrations WHERE version=$1")
        .bind(VERSION)
        .execute(&mut *tx)
        .await
        .unwrap();
    assert!(validate(&mut tx).await.is_err());
    tx.rollback().await.unwrap();
    let mut tx = f.pool.begin().await.unwrap();
    sqlx::query("DROP TABLE issuance_service.rust_schema_migrations")
        .execute(&mut *tx)
        .await
        .unwrap();
    assert!(validate(&mut tx).await.is_err());
    tx.rollback().await.unwrap();
    let mut tx = f.pool.begin().await.unwrap();
    validate(&mut tx).await.unwrap();
    tx.rollback().await.unwrap();
    f.pool.close().await;
}

#[tokio::test]
async fn catalog_rejects_weakened_or_unexpected_schema_and_function_bodies() {
    let f = Fixture::new().await;
    for drift in [
        "ALTER TABLE issuance_service.external_observation_receipts ALTER COLUMN envelope DROP NOT NULL",
        "ALTER TABLE issuance_service.external_observation_producer_grants DISABLE TRIGGER external_observation_grants_revision",
        "ALTER TABLE issuance_service.external_observation_receipts DISABLE TRIGGER ALL",
        "CREATE RULE external_observation_suppress_update AS ON UPDATE TO issuance_service.external_observation_producer_grants DO INSTEAD NOTHING",
        "GRANT SELECT ON issuance_service.external_observation_receipts TO PUBLIC",
        "GRANT SELECT(envelope) ON issuance_service.external_observation_receipts TO PUBLIC",
        "GRANT EXECUTE ON FUNCTION issuance_service.bump_external_observation_revision() TO PUBLIC",
        "ALTER TABLE issuance_service.external_observation_receipts DROP CONSTRAINT external_observation_requires_audit",
        "DROP INDEX issuance_service.external_observation_grants_key_lookup",
        "CREATE TABLE issuance_service.external_observation_unregistered (id text)",
        "ALTER TABLE issuance_service.external_observation_bindings ENABLE ROW LEVEL SECURITY",
        "CREATE OR REPLACE FUNCTION issuance_service.bump_external_observation_revision() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RETURN NEW; END;$$",
    ] {
        let mut tx = f.pool.begin().await.unwrap();
        sqlx::raw_sql(drift).execute(&mut *tx).await.unwrap();
        assert!(validate(&mut tx).await.is_err(), "accepted schema drift: {drift}");
        tx.rollback().await.unwrap();
    }
    let mut tx = f.pool.begin().await.unwrap();
    validate(&mut tx).await.unwrap();
    tx.rollback().await.unwrap();
    f.pool.close().await;
}

#[tokio::test]
async fn catalog_verification_needs_no_authority_table_privileges() {
    let f = Fixture::new().await;
    let mut tx = f.pool.begin().await.unwrap();
    // Transactional role creation is rolled back; no database-global role remains.
    sqlx::raw_sql("CREATE ROLE observation_catalog_reader NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
        GRANT USAGE ON SCHEMA issuance_service TO observation_catalog_reader;
        GRANT SELECT ON issuance_service.rust_schema_migrations TO observation_catalog_reader;
        SET LOCAL ROLE observation_catalog_reader;")
        .execute(&mut *tx).await.unwrap();
    validate(&mut tx).await.unwrap();
    let can_read: bool = sqlx::query_scalar("SELECT has_table_privilege(current_user,'issuance_service.external_observation_receipts','SELECT')")
        .fetch_one(&mut *tx).await.unwrap();
    let can_write: bool = sqlx::query_scalar("SELECT has_table_privilege(current_user,'issuance_service.external_observation_producer_grants','UPDATE')")
        .fetch_one(&mut *tx).await.unwrap();
    assert!(!can_read && !can_write);
    tx.rollback().await.unwrap();
    f.pool.close().await;
}

#[tokio::test]
async fn registered_migration_revokes_public_even_with_permissive_owner_defaults() {
    let f = Fixture::new().await;
    let mut tx = f.pool.begin().await.unwrap();
    sqlx::raw_sql("ALTER DEFAULT PRIVILEGES IN SCHEMA issuance_service GRANT ALL ON TABLES TO PUBLIC;
        ALTER DEFAULT PRIVILEGES IN SCHEMA issuance_service GRANT EXECUTE ON FUNCTIONS TO PUBLIC;
        DROP TABLE issuance_service.external_observation_producer_grants, issuance_service.external_observation_bindings,
            issuance_service.external_observation_grant_bindings, issuance_service.external_observation_receipts,
            issuance_service.external_observation_heads, issuance_service.external_observation_audit CASCADE;
        DROP FUNCTION issuance_service.bump_external_observation_revision(),
            issuance_service.bump_external_observation_grant_membership(), issuance_service.reject_external_observation_membership_update(),
            issuance_service.external_observation_lock_organization(uuid),
            issuance_service.external_observation_lock_api_keys(uuid,uuid[]),
            issuance_service.external_observation_lock_application(text,text),
            issuance_service.external_observation_lock_administrator(uuid,text),
            issuance_service.external_observation_lock_receipt(text,text,text);")
        .execute(&mut *tx).await.unwrap();
    sqlx::raw_sql(MIGRATION_SQL)
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::raw_sql(LOCK_MIGRATION_SQL)
        .execute(&mut *tx)
        .await
        .unwrap();
    validate(&mut tx).await.unwrap();
    let public_tables: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace,
        LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) acl
        WHERE n.nspname='issuance_service' AND c.relname LIKE 'external_observation_%' AND c.relkind='r' AND acl.grantee=0")
        .fetch_one(&mut *tx).await.unwrap();
    let public_functions: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace,
        LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) acl
        WHERE n.nspname='issuance_service' AND p.proname LIKE '%external_observation%' AND acl.grantee=0")
        .fetch_one(&mut *tx).await.unwrap();
    assert_eq!((public_tables, public_functions), (0, 0));
    tx.rollback().await.unwrap();
    f.pool.close().await;
}
