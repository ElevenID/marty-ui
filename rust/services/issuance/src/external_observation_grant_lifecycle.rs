// SPDX-License-Identifier: AGPL-3.0-only
//! Explicit core-owned key delegation. Rotation never silently transfers active
//! authority: it deactivates the grant until a fresh canonical approval.
use crate::external_observation_admin::{database_error, lock_admin, AdminError};
use sqlx::{PgPool, Row};
use uuid::Uuid;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantMutation {
    pub revision: i64,
    pub audit_id: Uuid,
}
#[derive(Clone, Copy)]
enum Mutation {
    Approve,
    Rotate(Uuid),
}

/// Reapprove the exact current revision and current canonical key. This never
/// extends expiry, changes binding membership, or verifies an observation.
pub async fn approve_grant(
    pool: &PgPool,
    organization_id: Uuid,
    actor_id: &str,
    grant_id: Uuid,
    expected_revision: i64,
) -> Result<GrantMutation, AdminError> {
    change_grant(
        pool,
        organization_id,
        actor_id,
        grant_id,
        expected_revision,
        Mutation::Approve,
    )
    .await
}
/// The replacement key must already exist in canonical organization storage.
/// Its secret is never accepted, copied or returned by this operation.
pub async fn rotate_grant_api_key(
    pool: &PgPool,
    organization_id: Uuid,
    actor_id: &str,
    grant_id: Uuid,
    expected_revision: i64,
    replacement_key_id: Uuid,
) -> Result<GrantMutation, AdminError> {
    change_grant(
        pool,
        organization_id,
        actor_id,
        grant_id,
        expected_revision,
        Mutation::Rotate(replacement_key_id),
    )
    .await
}
async fn change_grant(
    pool: &PgPool,
    organization_id: Uuid,
    actor_id: &str,
    grant_id: Uuid,
    expected_revision: i64,
    mutation: Mutation,
) -> Result<GrantMutation, AdminError> {
    if !(1..=9007199254740991).contains(&expected_revision) {
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
    // Discovery is not authority. Lock canonical keys before locking the grant,
    // then recheck its key/revision. Multiple keys use stable UUID order.
    let previous_key:Uuid=sqlx::query_scalar("SELECT api_key_id FROM issuance_service.external_observation_producer_grants WHERE id=$1 AND organization_id=$2")
        .bind(grant_id).bind(organization_id).fetch_optional(&mut *tx).await.map_err(database_error)?.ok_or(AdminError::NotAuthorized)?;
    let next_key = match mutation {
        Mutation::Approve => previous_key,
        Mutation::Rotate(id) => id,
    };
    if next_key.is_nil() || matches!(mutation, Mutation::Rotate(_)) && next_key == previous_key {
        return Err(AdminError::Conflict);
    }
    let mut key_ids = vec![previous_key, next_key];
    key_ids.sort();
    key_ids.dedup();
    let keys=sqlx::query("SELECT id,(status='active' AND enabled AND scope_type='ORGANIZATION' AND deployment_profile_id IS NULL AND COALESCE('evidence:submit'=ANY(scopes),false) AND (expires_at IS NULL OR expires_at>clock_timestamp())) AS eligible FROM issuance_service.external_observation_lock_api_keys($1,$2) ORDER BY id")
        .bind(organization_id).bind(&key_ids).fetch_all(&mut *tx).await.map_err(database_error)?;
    if keys.len() != key_ids.len() {
        return Err(AdminError::NotAuthorized);
    }
    let mut eligible = false;
    for key in keys {
        let id: Uuid = key.try_get("id").map_err(database_error)?;
        if id == next_key {
            eligible = key.try_get("eligible").map_err(database_error)?;
        }
    }
    if !eligible {
        return Err(AdminError::NotAuthorized);
    }
    let grant=sqlx::query("SELECT api_key_id,revision,active,expires_at>clock_timestamp() AS unexpired FROM issuance_service.external_observation_producer_grants WHERE id=$1 AND organization_id=$2 FOR UPDATE")
        .bind(grant_id).bind(organization_id).fetch_optional(&mut *tx).await.map_err(database_error)?.ok_or(AdminError::NotAuthorized)?;
    let actual_key: Uuid = grant.try_get("api_key_id").map_err(database_error)?;
    let revision: i64 = grant.try_get("revision").map_err(database_error)?;
    let active: bool = grant.try_get("active").map_err(database_error)?;
    let unexpired: bool = grant.try_get("unexpired").map_err(database_error)?;
    if actual_key != previous_key || revision != expected_revision || !unexpired {
        return Err(AdminError::Conflict);
    }
    if matches!(mutation, Mutation::Approve) && active {
        return Err(AdminError::Conflict);
    }
    let (event, action, next) = match mutation {
        Mutation::Approve => {
            let next:i64=sqlx::query_scalar("UPDATE issuance_service.external_observation_producer_grants SET active=true,approved_by=$2,approved_at=clock_timestamp() WHERE id=$1 RETURNING revision")
                .bind(grant_id).bind(actor_id).fetch_one(&mut *tx).await.map_err(database_error)?;
            ("external_observation_grant_approved", "approve", next)
        }
        Mutation::Rotate(_) => {
            // Keep the last approval as historical metadata. It is ineffective
            // while inactive; fresh approval replaces it for the new key.
            let next:i64=sqlx::query_scalar("UPDATE issuance_service.external_observation_producer_grants SET api_key_id=$2,active=false WHERE id=$1 RETURNING revision")
                .bind(grant_id).bind(next_key).fetch_one(&mut *tx).await.map_err(database_error)?;
            (
                "external_observation_grant_key_rotated",
                "rotate-api-key",
                next,
            )
        }
    };
    let audit_id = Uuid::new_v4();
    sqlx::query("INSERT INTO organization_service.audit_events (id,organization_id,event_type,action,category,resource_type,resource_id,actor_id,actor_type,severity,message,changes,metadata,created_at) VALUES ($1,$2,$3,$4,'evidence','external-observation-producer',$5,$6,'user','info','External observation producer grant changed',$7,'{}'::jsonb,clock_timestamp())")
        .bind(audit_id).bind(organization_id).bind(event).bind(action).bind(grant_id.to_string()).bind(actor_id)
        .bind(serde_json::json!({"previous_revision":revision,"revision":next,"previous_api_key_id":previous_key.to_string(),"api_key_id":next_key.to_string(),"active":matches!(mutation,Mutation::Approve)}))
        .execute(&mut *tx).await.map_err(database_error)?;
    // Clock time can advance while locks/audit writes wait. Revalidate time
    // after all staged writes; a newly expired key/grant rolls everything back.
    let still_eligible:bool=sqlx::query_scalar("SELECT count(*)=1 FROM issuance_service.external_observation_producer_grants g JOIN LATERAL issuance_service.external_observation_lock_api_keys(g.organization_id,ARRAY[g.api_key_id]::uuid[]) k ON k.id=g.api_key_id AND k.organization_id=g.organization_id WHERE g.id=$1 AND g.organization_id=$2 AND g.expires_at>clock_timestamp() AND k.status='active' AND k.enabled AND k.scope_type='ORGANIZATION' AND k.deployment_profile_id IS NULL AND COALESCE('evidence:submit'=ANY(k.scopes),false) AND (k.expires_at IS NULL OR k.expires_at>clock_timestamp())")
        .bind(grant_id).bind(organization_id).fetch_one(&mut *tx).await.map_err(database_error)?;
    if !still_eligible {
        return Err(AdminError::NotAuthorized);
    }
    tx.commit().await.map_err(|_| AdminError::CommitUnknown)?;
    Ok(GrantMutation {
        revision: next,
        audit_id,
    })
}
