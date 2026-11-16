// SPDX-License-Identifier: AGPL-3.0-only
//! Canonical administrative mutations. Caller identity must be authenticated by
//! the public Gateway and its trusted service transport; no connector authority.
use sqlx::{PgConnection, PgPool, Row};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdminError {
    NotAuthorized,
    Conflict,
    Unavailable,
    CommitUnknown,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantRevocation {
    pub revision: i64,
    pub audit_id: Uuid,
}

pub(crate) fn database_error(error: sqlx::Error) -> AdminError {
    match error
        .as_database_error()
        .and_then(|error| error.code())
        .as_deref()
    {
        Some("40001" | "40P01" | "55P03" | "23505") => AdminError::Conflict,
        _ => AdminError::Unavailable,
    }
}

pub(crate) async fn lock_admin(
    connection: &mut PgConnection,
    organization_id: Uuid,
    actor_id: &str,
) -> Result<(), AdminError> {
    if actor_id.is_empty() || actor_id.len() > 255 || actor_id.chars().any(char::is_control) {
        return Err(AdminError::NotAuthorized);
    }
    // These are the existing organization tables, not an authority mirror. Row
    // locks serialize revocation with membership/role/permission removal.
    let rows = sqlx::query(
        "SELECT id FROM issuance_service.external_observation_lock_administrator($1,$2)",
    )
    .bind(organization_id)
    .bind(actor_id)
    .fetch_all(connection)
    .await
    .map_err(database_error)?;
    if rows.is_empty() {
        return Err(AdminError::NotAuthorized);
    }
    Ok(())
}

/// Explicit revision precondition; no automatic write retry. Audit insertion
/// and grant mutation commit together. A failed COMMIT must be reconciled.
pub async fn revoke_grant(
    pool: &PgPool,
    organization_id: Uuid,
    actor_id: &str,
    grant_id: Uuid,
    expected_revision: i64,
) -> Result<GrantRevocation, AdminError> {
    if expected_revision < 1 {
        return Err(AdminError::Conflict);
    }
    let mut tx = pool.begin().await.map_err(database_error)?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        .execute(&mut *tx)
        .await
        .map_err(database_error)?;
    sqlx::query("SET LOCAL lock_timeout='5s'")
        .execute(&mut *tx)
        .await
        .map_err(database_error)?;
    sqlx::query("SET LOCAL statement_timeout='10s'")
        .execute(&mut *tx)
        .await
        .map_err(database_error)?;
    lock_admin(&mut tx, organization_id, actor_id).await?;
    // Discover the key without locking the grant out of order, then lock the
    // canonical key before the grant, matching observation admission.
    let key: Option<Uuid> = sqlx::query_scalar(
        "SELECT api_key_id FROM issuance_service.external_observation_producer_grants
      WHERE id=$1 AND organization_id=$2",
    )
    .bind(grant_id)
    .bind(organization_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(database_error)?;
    let key = key.ok_or(AdminError::NotAuthorized)?;
    let found: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM issuance_service.external_observation_lock_api_keys($2,ARRAY[$1]::uuid[])",
    )
    .bind(key)
    .bind(organization_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(database_error)?;
    if found.is_none() {
        return Err(AdminError::NotAuthorized);
    }
    let grant=sqlx::query("SELECT revision,active,api_key_id FROM issuance_service.external_observation_producer_grants
      WHERE id=$1 AND organization_id=$2 FOR UPDATE").bind(grant_id).bind(organization_id)
      .fetch_optional(&mut *tx).await.map_err(database_error)?.ok_or(AdminError::NotAuthorized)?;
    let revision: i64 = grant.try_get("revision").map_err(database_error)?;
    let actual_key: Uuid = grant.try_get("api_key_id").map_err(database_error)?;
    if revision != expected_revision || actual_key != key {
        return Err(AdminError::Conflict);
    }
    let audit_id = Uuid::new_v4();
    let next: i64 = sqlx::query_scalar(
        "UPDATE issuance_service.external_observation_producer_grants
      SET active=false WHERE id=$1 RETURNING revision",
    )
    .bind(grant_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(database_error)?;
    // Fixed structured identifiers only: no credentials, observations or raw
    // request bodies enter administrative audit changes/metadata.
    sqlx::query("INSERT INTO organization_service.audit_events
      (id,organization_id,event_type,action,category,resource_type,resource_id,actor_id,actor_type,severity,message,changes,metadata,created_at)
      VALUES ($1,$2,'external_observation_grant_revoked','revoke','evidence','external-observation-producer',$3,$4,
        'user','info','External observation producer grant revoked',$5,'{}'::jsonb,clock_timestamp())")
      .bind(audit_id).bind(organization_id).bind(grant_id.to_string()).bind(actor_id)
      .bind(serde_json::json!({"active":false,"previous_revision":revision,"revision":next}))
      .execute(&mut *tx).await.map_err(database_error)?;
    tx.commit().await.map_err(|_| AdminError::CommitUnknown)?;
    Ok(GrantRevocation {
        revision: next,
        audit_id,
    })
}
