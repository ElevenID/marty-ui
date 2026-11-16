// SPDX-License-Identifier: AGPL-3.0-only
use crate::{
    external_observation_admin_http::admin_router,
    external_observation_authority_postgres::PostgresObservationAuthority,
    external_observation_http::observation_router,
    external_observation_postgres::PostgresObservationJournal,
};
use axum::Router;
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::sync::Arc;
use std::time::Duration;

/// Only production mounting entry point. Credentials must authenticate a
/// different, restricted Core role against the same canonical database backend.
/// The connector never receives this URL or any Core database access.
pub async fn prepare_isolated_observation_router(
    canonical_pool: &PgPool,
    observation_database_url: Option<&str>,
    enabled: bool,
    service_key: Option<&str>,
) -> Result<Option<Router>, &'static str> {
    const FAILURE: &str = "Isolated observation runtime preflight failed";
    if !enabled {
        return Ok(None);
    }
    if service_key.is_none() {
        return Err("Observation Gateway service credential is required");
    }
    let url = observation_database_url
        .filter(|value| !value.trim().is_empty())
        .ok_or("Separate Core observation database credentials are required")?;
    let pool = tokio::time::timeout(
        Duration::from_secs(5),
        PgPoolOptions::new()
            .max_connections(8)
            .acquire_timeout(Duration::from_secs(5))
            .connect(url),
    )
    .await
    .map_err(|_| FAILURE)?
    .map_err(|_| FAILURE)?;
    let result = async {
        type Identity = (String, String, Option<String>, Option<i32>);
        const IDENTITY: &str = "SELECT current_user::text,current_database()::text,inet_server_addr()::text,inet_server_port()::int";
        let canonical: Identity = sqlx::query_as(IDENTITY)
            .fetch_one(canonical_pool)
            .await
            .map_err(|_| FAILURE)?;
        let restricted: Identity = sqlx::query_as(IDENTITY)
            .fetch_one(&pool)
            .await
            .map_err(|_| FAILURE)?;
        if canonical.0 == restricted.0
            || canonical.1 != restricted.1
            || canonical.2.is_none()
            || canonical.2 != restricted.2
            || canonical.3 != restricted.3
        {
            return Err(FAILURE);
        }
        verify_runtime_role(&pool).await?;
        prepare_observation_router(&pool, true, service_key).await
    }
    .await;
    if result.is_err() {
        pool.close().await;
    }
    result
}

/// Metadata-only role qualification. Runtime cannot become an owner role,
/// mutate canonical authority, replace pinned helpers, or rewrite the journal.
pub async fn verify_runtime_role(pool: &PgPool) -> Result<(), &'static str> {
    const FAILURE: &str = "Restricted observation role preflight failed";
    let mut tx = pool.begin().await.map_err(|_| FAILURE)?;
    sqlx::query("SET LOCAL statement_timeout='5s'")
        .execute(&mut *tx)
        .await
        .map_err(|_| FAILURE)?;
    let safe: bool = sqlx::query_scalar(
        "WITH reachable AS (
          SELECT r.* FROM pg_catalog.pg_roles r
          WHERE pg_catalog.pg_has_role(current_user::regrole::oid,r.oid,'MEMBER')
        ), canonical(name) AS (VALUES
          ('organization_service.organizations'),('organization_service.api_keys'),
          ('organization_service.members'),('organization_service.member_roles'),
          ('organization_service.roles'),('organization_service.role_permissions'),
          ('organization_service.permissions'),('issuance_service.applications')
        ), helpers(name,relation) AS (VALUES
          ('external_observation_lock_organization','organization_service.organizations'),
          ('external_observation_lock_api_keys','organization_service.api_keys'),
          ('external_observation_lock_application','issuance_service.applications'),
          ('external_observation_lock_receipt','issuance_service.external_observation_receipts'),
          ('external_observation_lock_administrator','organization_service.organizations'),
          ('external_observation_lock_administrator','organization_service.members'),
          ('external_observation_lock_administrator','organization_service.member_roles'),
          ('external_observation_lock_administrator','organization_service.roles'),
          ('external_observation_lock_administrator','organization_service.role_permissions'),
          ('external_observation_lock_administrator','organization_service.permissions')
        ), pinned AS (
          SELECT p.*,h.relation FROM helpers h JOIN pg_catalog.pg_proc p ON p.proname=h.name
          JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace AND n.nspname='issuance_service'
        ) SELECT current_user=session_user
          AND pg_catalog.current_setting('session_replication_role')='origin'
          AND NOT EXISTS(SELECT 1 FROM reachable r CROSS JOIN pg_catalog.pg_parameter_acl p WHERE
            pg_catalog.has_parameter_privilege(r.oid,p.parname,'SET')
            OR pg_catalog.has_parameter_privilege(r.oid,p.parname,'ALTER SYSTEM'))
          AND NOT EXISTS(SELECT 1 FROM reachable r WHERE left(r.rolname,3)='pg_'
            OR r.rolsuper OR r.rolcreaterole OR r.rolcreatedb
            OR r.rolreplication OR r.rolbypassrls
            OR pg_catalog.has_database_privilege(r.oid,current_database(),'CREATE')
            OR pg_catalog.has_schema_privilege(r.oid,'issuance_service','CREATE')
            OR pg_catalog.has_schema_privilege(r.oid,'organization_service','CREATE'))
          AND NOT EXISTS(SELECT 1 FROM reachable r CROSS JOIN canonical c WHERE
            pg_catalog.has_any_column_privilege(r.oid,c.name,'INSERT')
            OR pg_catalog.has_any_column_privilege(r.oid,c.name,'UPDATE')
            OR pg_catalog.has_table_privilege(r.oid,c.name,'DELETE')
            OR pg_catalog.has_table_privilege(r.oid,c.name,'TRUNCATE')
            OR pg_catalog.has_table_privilege(r.oid,c.name,'TRIGGER'))
          AND (SELECT count(DISTINCT oid)=5 AND bool_and(prosecdef
            AND proconfig=ARRAY['search_path=pg_catalog']::text[]
            AND NOT pg_catalog.pg_has_role(current_user::regrole::oid,proowner,'MEMBER')
            AND pg_catalog.has_function_privilege(current_user,oid,'EXECUTE')
            AND pg_catalog.has_table_privilege(proowner,relation,'SELECT')
            AND pg_catalog.has_any_column_privilege(proowner,relation,'UPDATE')) FROM pinned)
          AND NOT EXISTS(SELECT 1 FROM reachable r CROSS JOIN pg_catalog.pg_class c
            JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
            WHERE ((n.nspname='issuance_service' AND c.relname ~ '^external_observation_')
              OR (n.nspname='organization_service' AND c.relname='audit_events')) AND c.relowner=r.oid)
          AND NOT EXISTS(SELECT 1 FROM reachable r CROSS JOIN (VALUES
            ('issuance_service.external_observation_receipts'),('issuance_service.external_observation_audit'),
            ('organization_service.audit_events')) immutable(name) WHERE
            pg_catalog.has_any_column_privilege(r.oid,immutable.name,'UPDATE')
            OR pg_catalog.has_table_privilege(r.oid,immutable.name,'DELETE')
            OR pg_catalog.has_table_privilege(r.oid,immutable.name,'TRUNCATE')
            OR pg_catalog.has_table_privilege(r.oid,immutable.name,'TRIGGER'))",
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| FAILURE)?;
    tx.rollback().await.map_err(|_| FAILURE)?;
    if safe {
        Ok(())
    } else {
        Err(FAILURE)
    }
}

/// This is a preflight, not migration registration or deployment approval.
/// It never creates tables/grants or manufactures canonical authority.
pub(crate) async fn prepare_observation_router(
    pool: &PgPool,
    enabled: bool,
    service_key: Option<&str>,
) -> Result<Option<Router>, &'static str> {
    if !enabled {
        return Ok(None);
    }
    let key = service_key.ok_or("Observation Gateway service credential is required")?;
    let router = observation_router(
        Arc::new(PostgresObservationJournal::new(
            pool.clone(),
            Arc::new(PostgresObservationAuthority),
        )),
        key.as_bytes(),
    )?;
    verify_storage(pool).await?;
    Ok(Some(
        router.merge(admin_router(pool.clone(), key.as_bytes())?),
    ))
}

pub async fn verify_storage(pool: &PgPool) -> Result<(), &'static str> {
    const FAILURE: &str = "Canonical observation storage preflight failed";
    let mut tx = pool.begin().await.map_err(|_| FAILURE)?;
    sqlx::query("SET LOCAL statement_timeout='5s'")
        .execute(&mut *tx)
        .await
        .map_err(|_| FAILURE)?;
    crate::external_observation_schema::validate(&mut tx)
        .await
        .map_err(|_| FAILURE)?;
    // LIMIT 0 checks pinned helper outputs and observation-owned privileges
    // without reading records or modifying canonical authority.
    for statement in [
        "SELECT status FROM issuance_service.external_observation_lock_organization(NULL::uuid) LIMIT 0",
        "SELECT id,organization_id,scopes,scope_type,deployment_profile_id,status,enabled,expires_at,updated_at FROM issuance_service.external_observation_lock_api_keys(NULL::uuid,ARRAY[]::uuid[]) LIMIT 0",
        "SELECT id,organization_id,source_id,api_key_id,active,revision,expires_at,created_by,approved_by,approved_at,created_at,updated_at FROM issuance_service.external_observation_producer_grants LIMIT 0 FOR UPDATE",
        "SELECT grant_id,binding_id,organization_id,source_id FROM issuance_service.external_observation_grant_bindings LIMIT 0 FOR SHARE",
        "SELECT id,organization_id,source_id,application_id,subject_id,provider,fact_type,resource_scope,claim_rules,max_age_ms,max_clock_skew_ms,active,revision,created_by,updated_by,created_at,updated_at FROM issuance_service.external_observation_bindings LIMIT 0 FOR UPDATE",
        "SELECT id,organization_id,applicant_identifier,status,updated_at,expires_at FROM issuance_service.external_observation_lock_application(NULL::text,NULL::text) LIMIT 0",
        "SELECT id FROM issuance_service.external_observation_lock_administrator(NULL::uuid,NULL::text) LIMIT 0",
        "SELECT id,organization_id,event_type,action,category,resource_type,resource_id,actor_id,actor_type,severity,message,changes,metadata,created_at FROM organization_service.audit_events LIMIT 0",
        "SELECT receipt_id,organization_id,source_id,api_key_id,binding_id,binding_revision,observation_id,sequence,received_at_ms,application_id,subject_id,provider,fact_type,resource_scope,envelope FROM issuance_service.external_observation_receipts LIMIT 0",
        "SELECT organization_id,source_id,binding_id,sequence,receipt_id FROM issuance_service.external_observation_heads LIMIT 0 FOR UPDATE",
        "SELECT receipt_id,event_type,received_at_ms FROM issuance_service.external_observation_audit LIMIT 0",
    ] {
        sqlx::query(statement).execute(&mut *tx).await.map_err(|_| FAILURE)?;
    }
    let writes: bool=sqlx::query_scalar("SELECT
      has_table_privilege(current_user,'issuance_service.external_observation_bindings','INSERT') AND
      has_column_privilege(current_user,'issuance_service.external_observation_bindings','resource_scope','UPDATE') AND
      has_column_privilege(current_user,'issuance_service.external_observation_bindings','claim_rules','UPDATE') AND
      has_column_privilege(current_user,'issuance_service.external_observation_bindings','max_age_ms','UPDATE') AND
      has_column_privilege(current_user,'issuance_service.external_observation_bindings','max_clock_skew_ms','UPDATE') AND
      has_column_privilege(current_user,'issuance_service.external_observation_bindings','active','UPDATE') AND
      has_column_privilege(current_user,'issuance_service.external_observation_bindings','updated_by','UPDATE') AND
      has_column_privilege(current_user,'issuance_service.external_observation_bindings','revision','UPDATE') AND
      has_table_privilege(current_user,'issuance_service.external_observation_grant_bindings','INSERT') AND
      has_table_privilege(current_user,'issuance_service.external_observation_grant_bindings','DELETE') AND
      has_table_privilege(current_user,'issuance_service.external_observation_producer_grants','INSERT') AND
      has_column_privilege(current_user,'issuance_service.external_observation_producer_grants','expires_at','UPDATE') AND
      has_column_privilege(current_user,'issuance_service.external_observation_producer_grants','api_key_id','UPDATE') AND
      has_column_privilege(current_user,'issuance_service.external_observation_producer_grants','approved_by','UPDATE') AND
      has_column_privilege(current_user,'issuance_service.external_observation_producer_grants','approved_at','UPDATE') AND
      has_table_privilege(current_user,'organization_service.audit_events','INSERT') AND
      has_column_privilege(current_user,'issuance_service.external_observation_producer_grants','active','UPDATE') AND
      has_column_privilege(current_user,'issuance_service.external_observation_producer_grants','revision','UPDATE') AND
      has_table_privilege(current_user,'issuance_service.external_observation_receipts','INSERT') AND
      has_table_privilege(current_user,'issuance_service.external_observation_audit','INSERT') AND
      has_table_privilege(current_user,'issuance_service.external_observation_heads','INSERT') AND
      has_column_privilege(current_user,'issuance_service.external_observation_heads','sequence','UPDATE') AND
      has_column_privilege(current_user,'issuance_service.external_observation_heads','receipt_id','UPDATE')")
      .fetch_one(&mut *tx).await.map_err(|_| FAILURE)?;
    if !writes {
        return Err(FAILURE);
    }
    let approval_nullable: bool = sqlx::query_scalar(
        "SELECT count(*)=2 FROM pg_catalog.pg_attribute
      WHERE attrelid='issuance_service.external_observation_producer_grants'::regclass
      AND attname IN ('approved_by','approved_at') AND NOT attisdropped AND NOT attnotnull",
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| FAILURE)?;
    if !approval_nullable {
        return Err(FAILURE);
    }
    let audit_column: bool = sqlx::query_scalar(
        "SELECT count(*)=3 FROM pg_catalog.pg_attribute
      WHERE attrelid='issuance_service.external_observation_audit'::regclass
        AND attname IN ('receipt_id','event_type','received_at_ms') AND NOT attisdropped",
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| FAILURE)?;
    if !audit_column {
        return Err(FAILURE);
    }
    let triggers: i64=sqlx::query_scalar("SELECT count(*) FROM pg_catalog.pg_trigger t
      JOIN pg_catalog.pg_class c ON c.oid=t.tgrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='issuance_service' AND NOT t.tgisinternal AND t.tgenabled IN ('O','A') AND
      (c.relname,t.tgname) IN (
        ('external_observation_producer_grants','external_observation_grants_revision'),
        ('external_observation_bindings','external_observation_bindings_revision'),
        ('external_observation_grant_bindings','external_observation_grant_binding_insert'),
        ('external_observation_grant_bindings','external_observation_grant_binding_delete'),
        ('external_observation_grant_bindings','external_observation_grant_binding_immutable'))")
      .fetch_one(&mut *tx).await.map_err(|_| FAILURE)?;
    if triggers != 5 {
        return Err(FAILURE);
    }
    tx.rollback().await.map_err(|_| FAILURE)?;
    Ok(())
}
