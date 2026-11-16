// SPDX-License-Identifier: AGPL-3.0-only
use super::Fixture;
use crate::external_observation_authority_postgres::PostgresObservationAuthority;
use crate::external_observation_postgres::{PostgresObservationJournal, ProducerIdentity};
use crate::external_observation_startup::{
    prepare_isolated_observation_router, verify_runtime_role,
};
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::sync::Arc;
use uuid::Uuid;

// Fixture-only DDL interpolates identifiers built exclusively from fixed prefixes
// and locally generated UUID hex. No caller or environment value reaches SQL.
fn fixture_sql(sql: String) -> sqlx::AssertSqlSafe<String> {
    sqlx::AssertSqlSafe(sql)
}

struct Roles {
    fixture: Fixture,
    runtime: PgPool,
    owner: String,
    name: String,
    url: String,
}
impl Roles {
    async fn new() -> Self {
        let fixture = super::admin_tests::setup().await;
        let suffix = Uuid::new_v4().simple().to_string();
        let owner = format!("observation_owner_{suffix}");
        let name = format!("observation_runtime_{suffix}");
        let install = format!(
            "CREATE ROLE {owner} NOLOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS;
             CREATE ROLE {name} LOGIN PASSWORD 'synthetic-observation-runtime' NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS;
             ALTER SCHEMA organization_service OWNER TO {owner}; ALTER SCHEMA issuance_service OWNER TO {owner};
             DO $$ DECLARE item record; BEGIN
               FOR item IN SELECT n.nspname,c.relname FROM pg_catalog.pg_class c
                 JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
                 WHERE n.nspname IN ('organization_service','issuance_service') AND c.relkind='r' LOOP
                 EXECUTE format('ALTER TABLE %I.%I OWNER TO %I',item.nspname,item.relname,'{owner}');
               END LOOP;
               FOR item IN SELECT p.oid::regprocedure::text AS signature FROM pg_catalog.pg_proc p
                 JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='issuance_service' LOOP
                 EXECUTE format('ALTER FUNCTION %s OWNER TO %I',item.signature,'{owner}');
               END LOOP;
             END $$;
             GRANT USAGE ON SCHEMA organization_service,issuance_service TO {name};
             GRANT SELECT ON issuance_service.rust_schema_migrations,
               issuance_service.external_observation_producer_grants,issuance_service.external_observation_bindings,
               issuance_service.external_observation_grant_bindings,issuance_service.external_observation_receipts,
               issuance_service.external_observation_heads,issuance_service.external_observation_audit TO {name};
             GRANT SELECT(id,organization_id,applicant_identifier,status,updated_at,expires_at)
               ON issuance_service.applications TO {name};
             GRANT SELECT,INSERT ON organization_service.audit_events TO {name};
             GRANT INSERT ON issuance_service.external_observation_producer_grants,issuance_service.external_observation_bindings,
               issuance_service.external_observation_grant_bindings,issuance_service.external_observation_receipts,
               issuance_service.external_observation_heads,issuance_service.external_observation_audit TO {name};
             GRANT DELETE ON issuance_service.external_observation_grant_bindings TO {name};
             GRANT UPDATE(grant_id) ON issuance_service.external_observation_grant_bindings TO {name};
             GRANT UPDATE(active,api_key_id,expires_at,approved_by,approved_at,revision)
               ON issuance_service.external_observation_producer_grants TO {name};
             GRANT UPDATE(resource_scope,claim_rules,max_age_ms,max_clock_skew_ms,active,updated_by,revision)
               ON issuance_service.external_observation_bindings TO {name};
             GRANT UPDATE(sequence,receipt_id) ON issuance_service.external_observation_heads TO {name};
             GRANT EXECUTE ON FUNCTION issuance_service.external_observation_lock_organization(uuid),
               issuance_service.external_observation_lock_api_keys(uuid,uuid[]),
               issuance_service.external_observation_lock_application(text,text),
               issuance_service.external_observation_lock_administrator(uuid,text),
               issuance_service.external_observation_lock_receipt(text,text,text) TO {name};"
        );
        sqlx::raw_sql(fixture_sql(install))
            .execute(&fixture.pool)
            .await
            .unwrap();
        let port = std::env::var("EXTERNAL_OBSERVATION_TEST_PORT").unwrap();
        let url=format!("postgresql://{name}:synthetic-observation-runtime@127.0.0.1:{port}/external_observation_contract_test");
        let runtime = PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        Self {
            fixture,
            runtime,
            owner,
            name,
            url,
        }
    }
    async fn close(self) {
        self.runtime.close().await;
        sqlx::raw_sql(fixture_sql(format!(
            "DROP OWNED BY {}; DROP ROLE {}; DROP OWNED BY {} CASCADE; DROP ROLE {};",
            self.name, self.name, self.owner, self.owner
        )))
        .execute(&self.fixture.pool)
        .await
        .unwrap();
        self.fixture.pool.close().await;
    }
}

#[tokio::test]
async fn restricted_core_role_admits_and_revokes_without_canonical_mutation_rights() {
    let roles = Roles::new().await;
    verify_runtime_role(&roles.runtime).await.unwrap();
    assert!(verify_runtime_role(&roles.fixture.pool).await.is_err());
    for statement in [
        "UPDATE organization_service.api_keys SET enabled=false",
        "UPDATE organization_service.organizations SET status='suspended'",
        "UPDATE organization_service.members SET status='inactive'",
        "DELETE FROM organization_service.role_permissions",
        "UPDATE issuance_service.applications SET status='approved'",
        "UPDATE issuance_service.external_observation_receipts SET subject_id='forged'",
        "DELETE FROM issuance_service.external_observation_audit",
        "DELETE FROM organization_service.audit_events",
        "UPDATE issuance_service.external_observation_grant_bindings SET grant_id=grant_id",
        "CREATE TABLE issuance_service.forbidden(value text)",
    ] {
        assert!(
            sqlx::query(statement)
                .execute(&roles.runtime)
                .await
                .is_err(),
            "{statement}"
        );
    }
    assert!(
        sqlx::query(fixture_sql(format!("SET ROLE {}", roles.owner)))
            .execute(&roles.runtime)
            .await
            .is_err()
    );
    let journal = PostgresObservationJournal::new(
        roles.runtime.clone(),
        Arc::new(PostgresObservationAuthority),
    );
    let identity = ProducerIdentity {
        api_key_id: "10000000-0000-4000-8000-000000000001".into(),
        organization_id: "20000000-0000-4000-8000-000000000001".into(),
    };
    let input = roles.fixture.input();
    let first = journal
        .submit(&identity, &input, &input.observation_id)
        .await
        .unwrap();
    assert!(!first.replayed);
    let replay = journal
        .submit(&identity, &input, &input.observation_id)
        .await
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(first.receipt_id, replay.receipt_id);
    assert_eq!(roles.fixture.counts().await, (1, 1, 1));
    let router = prepare_isolated_observation_router(
        &roles.fixture.pool,
        Some(&roles.url),
        true,
        Some("synthetic-isolated-gateway-service-key"),
    )
    .await
    .unwrap();
    assert!(router.is_some());
    drop(router);
    let organization = Uuid::parse_str(&identity.organization_id).unwrap();
    let grant = Uuid::parse_str("30000000-0000-4000-8000-000000000001").unwrap();
    let replacement = Uuid::parse_str("10000000-0000-4000-8000-000000000002").unwrap();
    sqlx::query("INSERT INTO organization_service.api_keys(id,organization_id,scopes,scope_type,status,enabled,expires_at,updated_at) VALUES ($1,$2,ARRAY['evidence:submit'],'ORGANIZATION','active',true,clock_timestamp()+interval '2 minutes',clock_timestamp())")
        .bind(replacement).bind(organization).execute(&roles.fixture.pool).await.unwrap();
    let rotated = crate::external_observation_grant_lifecycle::rotate_grant_api_key(
        &roles.runtime,
        organization,
        "admin-one",
        grant,
        2,
        replacement,
    )
    .await
    .unwrap();
    assert_eq!(rotated.revision, 3);
    let approved = crate::external_observation_grant_lifecycle::approve_grant(
        &roles.runtime,
        organization,
        "admin-one",
        grant,
        3,
    )
    .await
    .unwrap();
    assert_eq!(approved.revision, 4);
    let rotated_identity = ProducerIdentity {
        api_key_id: replacement.to_string(),
        organization_id: identity.organization_id.clone(),
    };
    assert!(journal
        .submit(&rotated_identity, &input, &input.observation_id)
        .await
        .is_err());
    let mut next_input = input.clone();
    next_input.observation_id = "role-rotation-observation-two".into();
    next_input.sequence = 2;
    assert!(
        !journal
            .submit(&rotated_identity, &next_input, &next_input.observation_id)
            .await
            .unwrap()
            .replayed
    );
    crate::external_observation_admin::revoke_grant(
        &roles.runtime,
        Uuid::parse_str(&identity.organization_id).unwrap(),
        "admin-one",
        Uuid::parse_str("30000000-0000-4000-8000-000000000001").unwrap(),
        4,
    )
    .await
    .unwrap();
    assert!(journal
        .submit(&identity, &input, &input.observation_id)
        .await
        .is_err());
    drop(journal);
    roles.close().await;
}

#[tokio::test]
async fn isolated_mount_rejects_missing_credentials_same_role_and_owner_escalation() {
    let roles = Roles::new().await;
    let key = Some("synthetic-isolated-gateway-service-key");
    assert!(
        prepare_isolated_observation_router(&roles.fixture.pool, None, false, None)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        prepare_isolated_observation_router(&roles.fixture.pool, None, true, key)
            .await
            .is_err()
    );
    assert!(
        prepare_isolated_observation_router(&roles.runtime, Some(&roles.url), true, key)
            .await
            .is_err()
    );
    sqlx::query(fixture_sql(format!(
        "GRANT {} TO {}",
        roles.owner, roles.name
    )))
    .execute(&roles.fixture.pool)
    .await
    .unwrap();
    assert!(verify_runtime_role(&roles.runtime).await.is_err());
    sqlx::query(fixture_sql(format!(
        "REVOKE {} FROM {}",
        roles.owner, roles.name
    )))
    .execute(&roles.fixture.pool)
    .await
    .unwrap();
    verify_runtime_role(&roles.runtime).await.unwrap();
    roles.close().await;
}

#[tokio::test]
async fn noninherited_authority_membership_and_extra_column_rights_fail_role_profile() {
    let roles = Roles::new().await;
    sqlx::query(fixture_sql(format!(
        "GRANT SET ON PARAMETER session_replication_role TO {}",
        roles.name
    )))
    .execute(&roles.fixture.pool)
    .await
    .unwrap();
    assert!(verify_runtime_role(&roles.runtime).await.is_err());
    sqlx::query(fixture_sql(format!(
        "REVOKE SET ON PARAMETER session_replication_role FROM {}",
        roles.name
    )))
    .execute(&roles.fixture.pool)
    .await
    .unwrap();
    verify_runtime_role(&roles.runtime).await.unwrap();
    sqlx::query(fixture_sql(format!(
        "ALTER ROLE {} SET session_replication_role='replica'",
        roles.name
    )))
    .execute(&roles.fixture.pool)
    .await
    .unwrap();
    let replica = PgPoolOptions::new()
        .max_connections(1)
        .connect(&roles.url)
        .await
        .unwrap();
    assert!(verify_runtime_role(&replica).await.is_err());
    replica.close().await;
    sqlx::query(fixture_sql(format!(
        "ALTER ROLE {} RESET session_replication_role",
        roles.name
    )))
    .execute(&roles.fixture.pool)
    .await
    .unwrap();
    sqlx::query(fixture_sql(format!(
        "GRANT pg_execute_server_program TO {}",
        roles.name
    )))
    .execute(&roles.fixture.pool)
    .await
    .unwrap();
    assert!(verify_runtime_role(&roles.runtime).await.is_err());
    sqlx::query(fixture_sql(format!(
        "REVOKE pg_execute_server_program FROM {}",
        roles.name
    )))
    .execute(&roles.fixture.pool)
    .await
    .unwrap();
    verify_runtime_role(&roles.runtime).await.unwrap();
    let dangerous = format!("observation_unsafe_{}", Uuid::new_v4().simple());
    sqlx::raw_sql(fixture_sql(format!("CREATE ROLE {dangerous} NOLOGIN; GRANT UPDATE(enabled) ON organization_service.api_keys TO {dangerous};
        ALTER ROLE {} NOINHERIT; GRANT {dangerous} TO {};",roles.name,roles.name))).execute(&roles.fixture.pool).await.unwrap();
    assert!(verify_runtime_role(&roles.runtime).await.is_err());
    sqlx::raw_sql(fixture_sql(format!(
        "REVOKE {dangerous} FROM {}; DROP OWNED BY {dangerous}; DROP ROLE {dangerous};
        GRANT UPDATE(enabled) ON organization_service.api_keys TO {};",
        roles.name, roles.name
    )))
    .execute(&roles.fixture.pool)
    .await
    .unwrap();
    assert!(verify_runtime_role(&roles.runtime).await.is_err());
    sqlx::query(fixture_sql(format!(
        "REVOKE UPDATE(enabled) ON organization_service.api_keys FROM {}",
        roles.name
    )))
    .execute(&roles.fixture.pool)
    .await
    .unwrap();
    verify_runtime_role(&roles.runtime).await.unwrap();
    roles.close().await;
}
