// SPDX-License-Identifier: AGPL-3.0-only
use crate::{
    external_observation_admin_http::admin_router,
    external_observation_authority_postgres::PostgresObservationAuthority,
    external_observation_http::observation_router,
    external_observation_postgres::PostgresObservationJournal,
};
use axum::Router;
use sqlx::PgPool;
use std::sync::Arc;

/// This is a preflight, not migration registration or deployment approval.
/// It never creates tables/grants or manufactures canonical authority.
pub async fn prepare_observation_router(
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
    // LIMIT 0 checks column availability and row-lock privileges without reading
    // records or modifying any authority. Keep this aligned with the adapter.
    for statement in [
        "SELECT id,organization_id,scopes,scope_type,deployment_profile_id,status,enabled,expires_at,updated_at FROM organization_service.api_keys LIMIT 0 FOR UPDATE",
        "SELECT id,organization_id,source_id,api_key_id,active,revision,expires_at FROM issuance_service.external_observation_producer_grants LIMIT 0 FOR UPDATE",
        "SELECT grant_id,binding_id,organization_id,source_id FROM issuance_service.external_observation_grant_bindings LIMIT 0 FOR SHARE",
        "SELECT id,organization_id,source_id,application_id,subject_id,provider,fact_type,resource_scope,claim_rules,max_age_ms,max_clock_skew_ms,active,revision FROM issuance_service.external_observation_bindings LIMIT 0 FOR UPDATE",
        "SELECT id,organization_id,applicant_identifier,status,updated_at,expires_at FROM issuance_service.applications LIMIT 0 FOR UPDATE",
        "SELECT o.status,m.id,m.user_id,m.status,r.id,p.resource,p.action FROM organization_service.organizations o JOIN organization_service.members m ON m.organization_id=o.id JOIN organization_service.member_roles mr ON mr.member_id=m.id JOIN organization_service.roles r ON r.id=mr.role_id AND r.organization_id=o.id JOIN organization_service.role_permissions rp ON rp.role_id=r.id JOIN organization_service.permissions p ON p.id=rp.permission_id LIMIT 0 FOR SHARE OF o,m,mr,r,rp,p",
        "SELECT id,organization_id,event_type,action,category,resource_type,resource_id,actor_id,actor_type,severity,message,changes,metadata,created_at FROM organization_service.audit_events LIMIT 0",
        "SELECT receipt_id,organization_id,source_id,api_key_id,binding_id,binding_revision,observation_id,sequence,received_at_ms,application_id,subject_id,provider,fact_type,resource_scope,envelope FROM issuance_service.external_observation_receipts LIMIT 0",
        "SELECT organization_id,source_id,binding_id,sequence,receipt_id FROM issuance_service.external_observation_heads LIMIT 0 FOR UPDATE",
    ] {
        sqlx::query(statement).execute(&mut *tx).await.map_err(|_| FAILURE)?;
    }
    let writes: bool=sqlx::query_scalar("SELECT
      has_table_privilege(current_user,'issuance_service.external_observation_bindings','INSERT') AND
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
