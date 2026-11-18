// SPDX-License-Identifier: AGPL-3.0-only
//! Read-only opt-in qualification; Core owner installs schema/grants separately.
use axum::Router;
use sqlx::PgPool;

pub async fn prepare_router(
    pool: &PgPool,
    enabled: bool,
    service_key: Option<&str>,
) -> Result<Option<Router>, &'static str> {
    if !enabled {
        return Ok(None);
    }
    let key = service_key.ok_or("Ownership Gateway service credential is required")?;
    verify_storage(pool).await?;
    Ok(Some(crate::application_ownership_http::ownership_router(
        pool.clone(),
        key.as_bytes(),
    )?))
}
pub async fn verify_storage(pool: &PgPool) -> Result<(), &'static str> {
    const FAILURE: &str = "Application ownership storage preflight failed";
    let mut tx = pool.begin().await.map_err(|_| FAILURE)?;
    sqlx::query("SET TRANSACTION READ ONLY")
        .execute(&mut *tx)
        .await
        .map_err(|_| FAILURE)?;
    sqlx::query("SET LOCAL statement_timeout='5s'")
        .execute(&mut *tx)
        .await
        .map_err(|_| FAILURE)?;
    crate::application_ownership_schema::validate(&mut tx)
        .await
        .map_err(|_| FAILURE)?;
    let safe:bool=sqlx::query_scalar(
        "WITH reachable AS (SELECT r.* FROM pg_catalog.pg_roles r WHERE pg_catalog.pg_has_role(current_user::regrole::oid,r.oid,'MEMBER')),
        required(name) AS (VALUES
          ('issuance_service.mutate_application_ownership(uuid,text,text,uuid,text,bigint,bigint,text)'),
          ('issuance_service.read_application_ownership(uuid,text,text,uuid)'),
          ('issuance_service.application_ownership_lock_administrator(uuid,text)'),
          ('issuance_service.external_observation_lock_organization(uuid)'),
          ('issuance_service.external_observation_lock_application(text,text)'))
        SELECT current_user=session_user AND pg_catalog.current_setting('session_replication_role')='origin'
        AND NOT EXISTS(SELECT 1 FROM reachable r CROSS JOIN pg_catalog.pg_parameter_acl p WHERE
          pg_catalog.has_parameter_privilege(r.oid,p.parname,'SET') OR pg_catalog.has_parameter_privilege(r.oid,p.parname,'ALTER SYSTEM'))
        AND NOT EXISTS(SELECT 1 FROM reachable WHERE left(rolname,3)='pg_' OR rolsuper OR rolcreaterole OR rolcreatedb OR rolbypassrls OR rolreplication)
        AND NOT EXISTS(SELECT 1 FROM reachable r WHERE pg_catalog.has_schema_privilege(r.oid,'issuance_service','CREATE')
          OR pg_catalog.has_schema_privilege(r.oid,'organization_service','CREATE') OR pg_catalog.has_database_privilege(r.oid,current_database(),'CREATE'))
        AND NOT EXISTS(SELECT 1 FROM reachable r CROSS JOIN (VALUES
          ('issuance_service.application_ownerships'),('issuance_service.application_ownership_operations')) t(name)
          JOIN pg_catalog.pg_class c ON c.oid=pg_catalog.to_regclass(t.name)
          WHERE c.relowner=r.oid OR pg_catalog.has_table_privilege(r.oid,c.oid,'DELETE')
           OR pg_catalog.has_table_privilege(r.oid,c.oid,'TRUNCATE') OR pg_catalog.has_table_privilege(r.oid,c.oid,'TRIGGER'))
        AND NOT EXISTS(SELECT 1 FROM reachable r WHERE
          pg_catalog.has_any_column_privilege(r.oid,'issuance_service.application_ownership_operations','UPDATE')
          OR pg_catalog.has_column_privilege(r.oid,'issuance_service.application_ownerships','organization_id','UPDATE')
          OR pg_catalog.has_column_privilege(r.oid,'issuance_service.application_ownerships','application_id','UPDATE'))
        AND (SELECT bool_and(pg_catalog.has_table_privilege(current_user,t.name,'SELECT')
          AND pg_catalog.has_table_privilege(current_user,t.name,'INSERT')) FROM (VALUES
          ('issuance_service.application_ownerships'),('issuance_service.application_ownership_operations')) t(name))
        AND (SELECT bool_and(pg_catalog.has_column_privilege(current_user,'issuance_service.application_ownerships',c.name,'UPDATE'))
          FROM (VALUES('user_id'),('subject_id'),('application_revision'),('status'),('revision'),('proposed_by'),('confirmed_at'),('updated_at')) c(name))
        AND (SELECT count(*)=5 AND bool_and(p.oid IS NOT NULL AND pg_catalog.has_function_privilege(current_user,p.oid,'EXECUTE')
          AND NOT pg_catalog.pg_has_role(current_user::regrole::oid,p.proowner,'MEMBER'))
          FROM required LEFT JOIN pg_catalog.pg_proc p ON p.oid=pg_catalog.to_regprocedure(required.name))"
    ).fetch_one(&mut *tx).await.map_err(|_|FAILURE)?;
    tx.rollback().await.map_err(|_| FAILURE)?;
    if !safe {
        return Err(FAILURE);
    }
    Ok(())
}
