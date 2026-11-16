// SPDX-License-Identifier: AGPL-3.0-only
//! Core administrator grant creation and expiry changes. Neither operation
//! creates active delegation, copies a secret or changes binding membership.
use crate::external_observation_admin::{database_error, lock_admin, AdminError};
use crate::external_observation_grant_lifecycle::GrantMutation;
use sqlx::{PgConnection, PgPool, Row};
use uuid::Uuid;

async fn eligible_key(
    connection: &mut PgConnection,
    organization: Uuid,
    key: Uuid,
) -> Result<(), AdminError> {
    let eligible: Option<bool> = sqlx::query_scalar(
        "SELECT status='active' AND enabled AND scope_type='ORGANIZATION'
         AND deployment_profile_id IS NULL AND COALESCE('evidence:submit'=ANY(scopes),false)
         AND (expires_at IS NULL OR expires_at>clock_timestamp())
         FROM organization_service.api_keys WHERE id=$1 AND organization_id=$2 FOR UPDATE",
    )
    .bind(key)
    .bind(organization)
    .fetch_optional(connection)
    .await
    .map_err(database_error)?;
    if eligible != Some(true) {
        return Err(AdminError::NotAuthorized);
    }
    Ok(())
}

/// The caller supplies a stable UUID so an uncertain commit can be reconciled.
/// Reusing it is a conflict, never an automatic retry or an implicit approval.
pub async fn create_grant(
    pool: &PgPool,
    organization: Uuid,
    actor: &str,
    grant: Uuid,
    key: Uuid,
    source: &str,
    expires_at_ms: i64,
) -> Result<GrantMutation, AdminError> {
    if grant.is_nil()
        || key.is_nil()
        || source.is_empty()
        || source.len() > 128
        || !source
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        || !(1..=9007199254740991).contains(&expires_at_ms)
    {
        return Err(AdminError::Conflict);
    }
    edit(
        pool,
        organization,
        actor,
        grant,
        Some((key, source)),
        None,
        expires_at_ms,
    )
    .await
}

/// Changes only expiry, with an exact revision precondition. It deactivates the
/// grant and clears approval; the same key/source/memberships remain unchanged.
pub async fn change_grant_expiry(
    pool: &PgPool,
    organization: Uuid,
    actor: &str,
    grant: Uuid,
    expected_revision: i64,
    expires_at_ms: i64,
) -> Result<GrantMutation, AdminError> {
    if grant.is_nil()
        || !(1..=9007199254740991).contains(&expected_revision)
        || !(1..=9007199254740991).contains(&expires_at_ms)
    {
        return Err(AdminError::Conflict);
    }
    edit(
        pool,
        organization,
        actor,
        grant,
        None,
        Some(expected_revision),
        expires_at_ms,
    )
    .await
}

async fn edit(
    pool: &PgPool,
    organization: Uuid,
    actor: &str,
    grant: Uuid,
    creation: Option<(Uuid, &str)>,
    expected_revision: Option<i64>,
    expires_at_ms: i64,
) -> Result<GrantMutation, AdminError> {
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
    lock_admin(&mut tx, organization, actor).await?;
    let key = if let Some((key, _)) = creation {
        key
    } else {
        sqlx::query_scalar("SELECT api_key_id FROM issuance_service.external_observation_producer_grants WHERE id=$1 AND organization_id=$2")
        .bind(grant).bind(organization).fetch_optional(&mut *tx).await.map_err(database_error)?.ok_or(AdminError::NotAuthorized)?
    };
    // Canonical key before grant, matching admission/revoke/approve/rotation.
    eligible_key(&mut tx, organization, key).await?;
    let (revision, event, action) = if let Some((_, source)) = creation {
        let revision:i64=sqlx::query_scalar("INSERT INTO issuance_service.external_observation_producer_grants
          (id,organization_id,source_id,api_key_id,active,expires_at,created_by,approved_by,approved_at)
          SELECT $1,$2,$3,$4,false,to_timestamp($5::bigint::double precision/1000.0),$6,NULL,NULL
          WHERE to_timestamp($5::bigint::double precision/1000.0)>clock_timestamp() RETURNING revision")
          .bind(grant).bind(organization).bind(source).bind(key).bind(expires_at_ms).bind(actor)
          .fetch_optional(&mut *tx).await.map_err(database_error)?.ok_or(AdminError::Conflict)?;
        (revision, "external_observation_grant_created", "create")
    } else {
        let row=sqlx::query("SELECT api_key_id,revision FROM issuance_service.external_observation_producer_grants WHERE id=$1 AND organization_id=$2 FOR UPDATE")
          .bind(grant).bind(organization).fetch_optional(&mut *tx).await.map_err(database_error)?.ok_or(AdminError::NotAuthorized)?;
        if row
            .try_get::<Uuid, _>("api_key_id")
            .map_err(database_error)?
            != key
            || Some(row.try_get::<i64, _>("revision").map_err(database_error)?) != expected_revision
        {
            return Err(AdminError::Conflict);
        }
        let revision:i64=sqlx::query_scalar("UPDATE issuance_service.external_observation_producer_grants
          SET expires_at=to_timestamp($3::bigint::double precision/1000.0),active=false,approved_by=NULL,approved_at=NULL
          WHERE id=$1 AND organization_id=$2 AND to_timestamp($3::bigint::double precision/1000.0)>clock_timestamp() RETURNING revision")
          .bind(grant).bind(organization).bind(expires_at_ms).fetch_optional(&mut *tx).await.map_err(database_error)?.ok_or(AdminError::Conflict)?;
        (
            revision,
            "external_observation_grant_expiry_changed",
            "change-expiry",
        )
    };
    let audit_id = Uuid::new_v4();
    sqlx::query("INSERT INTO organization_service.audit_events
      (id,organization_id,event_type,action,category,resource_type,resource_id,actor_id,actor_type,severity,message,changes,metadata,created_at)
      VALUES ($1,$2,$3,$4,'evidence','external-observation-producer',$5,$6,'user','info',
        'External observation producer grant changed',$7,'{}'::jsonb,clock_timestamp())")
      .bind(audit_id).bind(organization).bind(event).bind(action).bind(grant.to_string()).bind(actor)
      .bind(serde_json::json!({"revision":revision,"previous_revision":expected_revision,"expires_at_ms":expires_at_ms,"active":false}))
      .execute(&mut *tx).await.map_err(database_error)?;
    // Expiry can cross while row locks, triggers or audit insertion wait. These
    // same-transaction locks and the final wall clock check fence all writes.
    eligible_key(&mut tx, organization, key).await?;
    let unexpired:bool=sqlx::query_scalar("SELECT expires_at>clock_timestamp() FROM issuance_service.external_observation_producer_grants WHERE id=$1 AND organization_id=$2")
      .bind(grant).bind(organization).fetch_one(&mut *tx).await.map_err(database_error)?;
    if !unexpired {
        return Err(AdminError::Conflict);
    }
    tx.commit().await.map_err(|_| AdminError::CommitUnknown)?;
    Ok(GrantMutation { revision, audit_id })
}
