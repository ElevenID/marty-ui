// SPDX-License-Identifier: AGPL-3.0-only
//! Replace a canonical producer grant's binding membership. Selected binding
//! revisions are an administrator precondition, never connector authority.
use crate::external_observation_admin::{database_error, lock_admin, AdminError};
use crate::external_observation_grant_edit::eligible_key;
use crate::external_observation_grant_lifecycle::GrantMutation;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use std::collections::BTreeMap;
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BindingSelection {
    pub binding_id: String,
    pub expected_revision: i64,
}

pub fn valid_selection(bindings: &[BindingSelection]) -> bool {
    let mut ids = std::collections::BTreeSet::new();
    bindings.len() <= 32
        && bindings.iter().all(|b| {
            !b.binding_id.is_empty()
                && b.binding_id.len() <= 128
                && b.binding_id
                    .bytes()
                    .all(|v| v.is_ascii_alphanumeric() || v == b'_' || v == b'-')
                && (1..=9007199254740991).contains(&b.expected_revision)
                && ids.insert(&b.binding_id)
        })
}

/// Replaces membership only, including an explicit empty set. Every successful
/// operation deactivates the grant and clears its approval. No binding,
/// application, source, subject, key or observation is modified.
pub async fn replace_grant_bindings(
    pool: &PgPool,
    organization: Uuid,
    actor: &str,
    grant: Uuid,
    expected_revision: i64,
    bindings: &[BindingSelection],
) -> Result<GrantMutation, AdminError> {
    if grant.is_nil()
        || !(1..=9007199254740991).contains(&expected_revision)
        || !valid_selection(bindings)
    {
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
    lock_admin(&mut tx, organization, actor).await?;
    let key:Uuid=sqlx::query_scalar("SELECT api_key_id FROM issuance_service.external_observation_producer_grants WHERE id=$1 AND organization_id=$2")
      .bind(grant).bind(organization).fetch_optional(&mut *tx).await.map_err(database_error)?.ok_or(AdminError::NotAuthorized)?;
    eligible_key(&mut tx, organization, key).await?;
    let current=sqlx::query("SELECT api_key_id,source_id,revision,expires_at>clock_timestamp() AS unexpired FROM issuance_service.external_observation_producer_grants WHERE id=$1 AND organization_id=$2 FOR UPDATE")
      .bind(grant).bind(organization).fetch_optional(&mut *tx).await.map_err(database_error)?.ok_or(AdminError::NotAuthorized)?;
    if current
        .try_get::<Uuid, _>("api_key_id")
        .map_err(database_error)?
        != key
        || current
            .try_get::<i64, _>("revision")
            .map_err(database_error)?
            != expected_revision
        || !current
            .try_get::<bool, _>("unexpired")
            .map_err(database_error)?
    {
        return Err(AdminError::Conflict);
    }
    let source: String = current.try_get("source_id").map_err(database_error)?;
    let previous:Vec<String>=sqlx::query_scalar("SELECT binding_id FROM issuance_service.external_observation_grant_bindings WHERE grant_id=$1 ORDER BY binding_id FOR UPDATE")
      .bind(grant).fetch_all(&mut *tx).await.map_err(database_error)?;
    let wanted: BTreeMap<String, i64> = bindings
        .iter()
        .map(|b| (b.binding_id.clone(), b.expected_revision))
        .collect();
    let ids: Vec<String> = wanted.keys().cloned().collect();
    let rows=sqlx::query("SELECT id,revision FROM issuance_service.external_observation_bindings WHERE organization_id=$1 AND source_id=$2 AND id=ANY($3) ORDER BY id FOR UPDATE")
      .bind(organization).bind(&source).bind(&ids).fetch_all(&mut *tx).await.map_err(database_error)?;
    if rows.len() != wanted.len() {
        return Err(AdminError::NotAuthorized);
    }
    for row in rows {
        let id: String = row.try_get("id").map_err(database_error)?;
        if wanted.get(&id) != Some(&row.try_get::<i64, _>("revision").map_err(database_error)?) {
            return Err(AdminError::Conflict);
        }
    }
    for id in &previous {
        if !wanted.contains_key(id) {
            sqlx::query("DELETE FROM issuance_service.external_observation_grant_bindings WHERE grant_id=$1 AND binding_id=$2")
              .bind(grant).bind(id).execute(&mut *tx).await.map_err(database_error)?;
        }
    }
    for id in &ids {
        if !previous.contains(id) {
            sqlx::query("INSERT INTO issuance_service.external_observation_grant_bindings(grant_id,binding_id,organization_id,source_id) VALUES ($1,$2,$3,$4)")
              .bind(grant).bind(id).bind(organization).bind(&source).execute(&mut *tx).await.map_err(database_error)?;
        }
    }
    // Membership revision triggers fence each insertion/deletion; this final
    // mutation always invalidates approval, even for an identical selected set.
    let revision:i64=sqlx::query_scalar("UPDATE issuance_service.external_observation_producer_grants SET active=false,approved_by=NULL,approved_at=NULL WHERE id=$1 AND organization_id=$2 RETURNING revision")
      .bind(grant).bind(organization).fetch_one(&mut *tx).await.map_err(database_error)?;
    let audit_id = Uuid::new_v4();
    sqlx::query("INSERT INTO organization_service.audit_events (id,organization_id,event_type,action,category,resource_type,resource_id,actor_id,actor_type,severity,message,changes,metadata,created_at)
      VALUES ($1,$2,'external_observation_grant_bindings_replaced','replace-bindings','evidence','external-observation-producer',$3,$4,'user','info','External observation producer bindings changed',$5,'{}'::jsonb,clock_timestamp())")
      .bind(audit_id).bind(organization).bind(grant.to_string()).bind(actor)
      .bind(serde_json::json!({"previous_revision":expected_revision,"revision":revision,"bindings":bindings,"active":false}))
      .execute(&mut *tx).await.map_err(database_error)?;
    eligible_key(&mut tx, organization, key).await?;
    let current:bool=sqlx::query_scalar("SELECT count(*)=1 FROM issuance_service.external_observation_producer_grants WHERE id=$1 AND organization_id=$2 AND api_key_id=$3 AND source_id=$4 AND revision=$5 AND NOT active AND approved_by IS NULL AND approved_at IS NULL AND expires_at>clock_timestamp()")
      .bind(grant).bind(organization).bind(key).bind(&source).bind(revision).fetch_one(&mut *tx).await.map_err(database_error)?;
    if !current {
        return Err(AdminError::Conflict);
    }
    let final_bindings:Vec<String>=sqlx::query_scalar("SELECT binding_id FROM issuance_service.external_observation_grant_bindings WHERE grant_id=$1 ORDER BY binding_id")
      .bind(grant).fetch_all(&mut *tx).await.map_err(database_error)?;
    if final_bindings
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>()
        != ids.iter().cloned().collect()
    {
        return Err(AdminError::Conflict);
    }
    let final_rows=sqlx::query("SELECT id,revision FROM issuance_service.external_observation_bindings WHERE organization_id=$1 AND source_id=$2 AND id=ANY($3) ORDER BY id")
      .bind(organization).bind(&source).bind(&ids).fetch_all(&mut *tx).await.map_err(database_error)?;
    if final_rows.len() != wanted.len() {
        return Err(AdminError::Conflict);
    }
    for row in final_rows {
        let id: String = row.try_get("id").map_err(database_error)?;
        if wanted.get(&id) != Some(&row.try_get::<i64, _>("revision").map_err(database_error)?) {
            return Err(AdminError::Conflict);
        }
    }
    tx.commit().await.map_err(|_| AdminError::CommitUnknown)?;
    Ok(GrantMutation { revision, audit_id })
}
