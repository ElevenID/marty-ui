use chrono::{DateTime, Utc};
use marty_verification::flow::FlowInstanceStatus;
use mmf_messaging::Message;
use serde_json::Value;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::{FlowInstance, RepositoryError};

#[derive(Clone, Debug, PartialEq)]
pub struct ClaimedCallback {
    pub event_id: String,
    pub flow_instance_id: String,
    pub organization_id: String,
    pub destination_url: String,
    pub audience: String,
    pub event_type: String,
    pub payload: Value,
    pub attempt_count: u32,
    pub lease_token: String,
    pub lease_expires_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct PostgresFlowRepository {
    pool: PgPool,
}

impl PostgresFlowRepository {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    #[must_use]
    pub const fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Atomically consumes the nonce, compare-and-swaps the live instance,
    /// and enqueues its callback. Any failed step rolls the entire unit back.
    pub async fn finalize_verification(
        &self,
        instance: &FlowInstance,
        nonce_digest: &str,
        replay_expires_at_ms: u64,
        expected_status: FlowInstanceStatus,
        callback: Option<&Message>,
    ) -> Result<bool, RepositoryError> {
        if !valid_sha256(nonce_digest) {
            return Err(RepositoryError::InvalidReplayDigest);
        }
        if !matches!(
            expected_status,
            FlowInstanceStatus::AwaitingWallet | FlowInstanceStatus::InProgress
        ) {
            return Ok(false);
        }
        validate_callback(instance, callback)?;
        let replay_expires_at = timestamp(replay_expires_at_ms)?;
        let mut transaction = self.pool.begin().await.map_err(storage)?;

        sqlx::query(
            "DELETE FROM flow_service.flow_nonce_consumptions \
             WHERE expires_at <= clock_timestamp()",
        )
        .execute(&mut *transaction)
        .await
        .map_err(storage)?;
        let replay = sqlx::query(
            "INSERT INTO flow_service.flow_nonce_consumptions \
             (nonce_digest, flow_instance_id, consumed_at, expires_at) \
             VALUES ($1, $2, clock_timestamp(), $3) \
             ON CONFLICT DO NOTHING RETURNING nonce_digest",
        )
        .bind(nonce_digest)
        .bind(&instance.id)
        .bind(replay_expires_at)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(storage)?;
        if replay.is_none() {
            transaction.rollback().await.map_err(storage)?;
            return Ok(false);
        }

        let completed_at = instance.completed_at_ms.map(timestamp).transpose()?;
        let expires_at = instance.expires_at_ms.map(timestamp).transpose()?;
        let update = sqlx::query(
            "UPDATE flow_service.flow_instances SET \
             flow_definition_id=$1, organization_id=$2, status=$3, \
             current_step_id=$4, context=$5, step_history=$6, \
             application_flow_key_hash=$7, completed_at=$8, expires_at=$9, \
             result=$10, error=$11, updated_at=clock_timestamp() \
             WHERE id=$12 AND status=$13 \
             AND (expires_at IS NULL OR expires_at >= clock_timestamp())",
        )
        .bind(&instance.flow_definition_id)
        .bind(&instance.organization_id)
        .bind(instance.status.to_string())
        .bind(&instance.current_step_id)
        .bind(&instance.context)
        .bind(serde_json::to_value(&instance.step_history).map_err(json_storage)?)
        .bind(&instance.application_flow_key_hash)
        .bind(completed_at)
        .bind(expires_at)
        .bind(&instance.result)
        .bind(&instance.error)
        .bind(&instance.id)
        .bind(expected_status.to_string())
        .execute(&mut *transaction)
        .await
        .map_err(storage)?;
        if update.rows_affected() != 1 {
            transaction.rollback().await.map_err(storage)?;
            return Ok(false);
        }

        if let Some(callback) = callback {
            insert_callback(&mut transaction, callback).await?;
        }
        transaction.commit().await.map_err(storage)?;
        Ok(true)
    }

    pub async fn claim_due_callbacks(
        &self,
        now: DateTime<Utc>,
        lease_expires_at: DateTime<Utc>,
        limit: u32,
    ) -> Result<Vec<ClaimedCallback>, RepositoryError> {
        if limit == 0 || limit > 100 || lease_expires_at <= now {
            return Err(RepositoryError::Storage(
                "callback claim requires a bounded limit and future lease".into(),
            ));
        }
        let mut transaction = self.pool.begin().await.map_err(storage)?;
        sqlx::query(
            "UPDATE flow_service.flow_callback_outbox SET \
             status='expired', destination_url='', payload='{}'::json, \
             lease_token=NULL, lease_expires_at=NULL, \
             last_error_code='retention_expired' \
             WHERE expires_at <= $1 \
             AND status IN ('pending','retry','delivering','dead_letter')",
        )
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(storage)?;
        let rows = sqlx::query(
            "SELECT event_id, flow_instance_id, organization_id, \
             destination_url, audience, event_type, payload, attempt_count \
             FROM flow_service.flow_callback_outbox \
             WHERE expires_at > $1 AND ( \
               (status IN ('pending','retry') AND next_attempt_at <= $1) OR \
               (status='delivering' AND lease_expires_at <= $1)) \
             ORDER BY created_at LIMIT $2 FOR UPDATE SKIP LOCKED",
        )
        .bind(now)
        .bind(i64::from(limit))
        .fetch_all(&mut *transaction)
        .await
        .map_err(storage)?;
        let mut claimed = Vec::with_capacity(rows.len());
        for row in rows {
            let event_id: String = row.try_get("event_id").map_err(storage)?;
            let lease_token = Uuid::new_v4().to_string();
            let prior_attempts: i32 = row.try_get("attempt_count").map_err(storage)?;
            let attempt_count = prior_attempts.saturating_add(1);
            let updated = sqlx::query(
                "UPDATE flow_service.flow_callback_outbox SET \
                 status='delivering', attempt_count=$1, lease_token=$2, \
                 lease_expires_at=$3 WHERE event_id=$4",
            )
            .bind(attempt_count)
            .bind(&lease_token)
            .bind(lease_expires_at)
            .bind(&event_id)
            .execute(&mut *transaction)
            .await
            .map_err(storage)?;
            if updated.rows_affected() != 1 {
                return Err(RepositoryError::Storage(
                    "claimed callback disappeared".into(),
                ));
            }
            claimed.push(ClaimedCallback {
                event_id,
                flow_instance_id: row.try_get("flow_instance_id").map_err(storage)?,
                organization_id: row.try_get("organization_id").map_err(storage)?,
                destination_url: row.try_get("destination_url").map_err(storage)?,
                audience: row.try_get("audience").map_err(storage)?,
                event_type: row.try_get("event_type").map_err(storage)?,
                payload: row.try_get("payload").map_err(storage)?,
                attempt_count: u32::try_from(attempt_count)
                    .map_err(|error| RepositoryError::Storage(error.to_string()))?,
                lease_token,
                lease_expires_at,
            });
        }
        transaction.commit().await.map_err(storage)?;
        Ok(claimed)
    }

    pub async fn mark_callback_delivered(
        &self,
        event_id: &str,
        lease_token: &str,
        delivered_at: DateTime<Utc>,
    ) -> Result<bool, RepositoryError> {
        let result = sqlx::query(
            "UPDATE flow_service.flow_callback_outbox SET \
             status='delivered', destination_url='', payload='{}'::json, \
             delivered_at=$1, lease_token=NULL, lease_expires_at=NULL, \
             last_error_code=NULL WHERE event_id=$2 AND status='delivering' \
             AND lease_token=$3",
        )
        .bind(delivered_at)
        .bind(event_id)
        .bind(lease_token)
        .execute(&self.pool)
        .await
        .map_err(storage)?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn mark_callback_failed(
        &self,
        event_id: &str,
        lease_token: &str,
        next_attempt_at: DateTime<Utc>,
        terminal: bool,
        error_code: &str,
    ) -> Result<bool, RepositoryError> {
        let status = if terminal { "dead_letter" } else { "retry" };
        let result = sqlx::query(
            "UPDATE flow_service.flow_callback_outbox SET status=$1, \
             next_attempt_at=$2, lease_token=NULL, lease_expires_at=NULL, \
             last_error_code=$3 WHERE event_id=$4 AND status='delivering' \
             AND lease_token=$5",
        )
        .bind(status)
        .bind(next_attempt_at)
        .bind(error_code.chars().take(128).collect::<String>())
        .bind(event_id)
        .bind(lease_token)
        .execute(&self.pool)
        .await
        .map_err(storage)?;
        Ok(result.rows_affected() == 1)
    }
}

async fn insert_callback(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    callback: &Message,
) -> Result<(), RepositoryError> {
    let destination = callback
        .reply_to
        .as_deref()
        .ok_or_else(|| RepositoryError::Storage("callback destination is missing".into()))?;
    let organization = callback
        .metadata
        .tenant_id
        .as_deref()
        .ok_or_else(|| RepositoryError::Storage("callback organization is missing".into()))?;
    let flow_instance = callback
        .metadata
        .correlation_id
        .as_deref()
        .ok_or_else(|| RepositoryError::Storage("callback flow identity is missing".into()))?;
    let audience = callback
        .metadata
        .headers
        .get("X-MIP-Audience")
        .ok_or_else(|| RepositoryError::Storage("callback audience is missing".into()))?;
    let created = timestamp(callback.metadata.created_at_ms)?;
    let next_attempt = timestamp(
        callback
            .metadata
            .scheduled_at_ms
            .unwrap_or(callback.metadata.created_at_ms),
    )?;
    let expires = timestamp(
        callback
            .metadata
            .expires_at_ms
            .ok_or_else(|| RepositoryError::Storage("callback expiry is missing".into()))?,
    )?;
    sqlx::query(
        "INSERT INTO flow_service.flow_callback_outbox \
         (event_id, flow_instance_id, organization_id, destination_url, \
          audience, event_type, payload, status, attempt_count, \
          next_attempt_at, created_at, expires_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,'pending',0,$8,$9,$10)",
    )
    .bind(&callback.metadata.message_id)
    .bind(flow_instance)
    .bind(organization)
    .bind(destination)
    .bind(audience)
    .bind(&callback.message_type)
    .bind(&callback.payload)
    .bind(next_attempt)
    .bind(created)
    .bind(expires)
    .execute(&mut **transaction)
    .await
    .map_err(storage)?;
    Ok(())
}

fn validate_callback(
    instance: &FlowInstance,
    callback: Option<&Message>,
) -> Result<(), RepositoryError> {
    if callback.is_some_and(|message| {
        message.metadata.message_id != instance.id
            || message.metadata.correlation_id.as_deref() != Some(instance.id.as_str())
            || message.metadata.tenant_id.as_deref() != Some(instance.organization_id.as_str())
    }) {
        return Err(RepositoryError::Storage(
            "callback identity does not match terminal flow".into(),
        ));
    }
    Ok(())
}

fn timestamp(value: u64) -> Result<DateTime<Utc>, RepositoryError> {
    i64::try_from(value)
        .ok()
        .and_then(DateTime::from_timestamp_millis)
        .ok_or_else(|| RepositoryError::Storage("timestamp is out of range".into()))
}

fn storage(error: sqlx::Error) -> RepositoryError {
    RepositoryError::Storage(error.to_string())
}

fn json_storage(error: serde_json::Error) -> RepositoryError {
    RepositoryError::Storage(error.to_string())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
