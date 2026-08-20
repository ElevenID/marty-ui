use chrono::{DateTime, Utc};
use marty_verification::flow::FlowInstanceStatus;
use mmf_messaging::Message;
use serde::de::DeserializeOwned;
use serde_json::Value;
use sqlx::{postgres::PgRow, PgPool, Postgres, QueryBuilder, Row};
use uuid::Uuid;

use crate::{
    FlowArtifactRecord, FlowDefinitionRecord, FlowInstance, FlowInstanceRecord, FlowRecordError,
    RepositoryError,
};

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

    pub async fn save_definition(
        &self,
        definition: &FlowDefinitionRecord,
    ) -> Result<(), RepositoryError> {
        validate_definition_numbers(definition)?;
        sqlx::query(
            "INSERT INTO flow_service.flow_definitions (id, organization_id, name, description, \
             status, flow_type, steps, transitions, start_step_id, credential_template_id, \
             application_template_id, presentation_policy_id, delivery_destination_profile_id, \
             deployment_profile_id, deployment_profile_ids, trust_profile_id, approval_strategy, \
             hooks, trigger, extension, preconditions, default_timeout_seconds, max_retries, \
             retry_cooldown_minutes, enable_resume, version, created_at, updated_at) VALUES \
             ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21, \
              $22,$23,$24,$25,$26,$27,$28) ON CONFLICT (id) DO UPDATE SET \
             organization_id=EXCLUDED.organization_id, name=EXCLUDED.name, \
             description=EXCLUDED.description, status=EXCLUDED.status, flow_type=EXCLUDED.flow_type, \
             steps=EXCLUDED.steps, transitions=EXCLUDED.transitions, \
             start_step_id=EXCLUDED.start_step_id, credential_template_id=EXCLUDED.credential_template_id, \
             application_template_id=EXCLUDED.application_template_id, \
             presentation_policy_id=EXCLUDED.presentation_policy_id, \
             delivery_destination_profile_id=EXCLUDED.delivery_destination_profile_id, \
             deployment_profile_id=EXCLUDED.deployment_profile_id, \
             deployment_profile_ids=EXCLUDED.deployment_profile_ids, \
             trust_profile_id=EXCLUDED.trust_profile_id, approval_strategy=EXCLUDED.approval_strategy, \
             hooks=EXCLUDED.hooks, trigger=EXCLUDED.trigger, extension=EXCLUDED.extension, \
             preconditions=EXCLUDED.preconditions, \
             default_timeout_seconds=EXCLUDED.default_timeout_seconds, max_retries=EXCLUDED.max_retries, \
             retry_cooldown_minutes=EXCLUDED.retry_cooldown_minutes, \
             enable_resume=EXCLUDED.enable_resume, version=EXCLUDED.version, \
             updated_at=EXCLUDED.updated_at",
        )
        .bind(&definition.id)
        .bind(&definition.organization_id)
        .bind(&definition.name)
        .bind(&definition.description)
        .bind(enum_string(definition.status)?)
        .bind(enum_string(definition.flow_type)?)
        .bind(json(&definition.steps)?)
        .bind(json(&definition.transitions)?)
        .bind(&definition.start_step_id)
        .bind(&definition.credential_template_id)
        .bind(&definition.application_template_id)
        .bind(&definition.presentation_policy_id)
        .bind(&definition.delivery_destination_profile_id)
        .bind(&definition.deployment_profile_id)
        .bind(json(&definition.deployment_profile_ids)?)
        .bind(&definition.trust_profile_id)
        .bind(enum_string(definition.approval_strategy)?)
        .bind(json(&definition.hooks)?)
        .bind(&definition.trigger)
        .bind(&definition.extension)
        .bind(json(&definition.preconditions)?)
        .bind(i32::try_from(definition.default_timeout_seconds).map_err(number_storage)?)
        .bind(i32::try_from(definition.max_retries).map_err(number_storage)?)
        .bind(i32::try_from(definition.retry_cooldown_minutes).map_err(number_storage)?)
        .bind(definition.enable_resume)
        .bind(i32::try_from(definition.version).map_err(number_storage)?)
        .bind(definition.created_at)
        .bind(definition.updated_at)
        .execute(&self.pool)
        .await
        .map_err(storage)?;
        Ok(())
    }

    pub async fn definition(
        &self,
        id: &str,
    ) -> Result<Option<FlowDefinitionRecord>, RepositoryError> {
        sqlx::query(DEFINITION_SELECT)
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage)?
            .map(|row| definition_from_row(&row))
            .transpose()
    }

    pub async fn definitions_for_tenant(
        &self,
        organization_id: &str,
    ) -> Result<Vec<FlowDefinitionRecord>, RepositoryError> {
        let rows = sqlx::query(DEFINITIONS_FOR_TENANT_SELECT)
            .bind(organization_id)
            .fetch_all(&self.pool)
            .await
            .map_err(storage)?;
        rows.iter().map(definition_from_row).collect()
    }

    pub async fn delete_definition(&self, id: &str) -> Result<bool, RepositoryError> {
        let result = sqlx::query("DELETE FROM flow_service.flow_definitions WHERE id=$1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage)?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn save_instance(
        &self,
        instance: &FlowInstanceRecord,
    ) -> Result<bool, RepositoryError> {
        validate_instance_record(instance)?;
        let result = sqlx::query(
            "INSERT INTO flow_service.flow_instances (id, flow_definition_id, organization_id, \
             status, current_step_id, context, step_history, state_history, subject_id, subject_type, \
             external_reference, application_flow_key_hash, started_at, completed_at, expires_at, \
             result, error, created_at, updated_at) VALUES \
             ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19) \
             ON CONFLICT (id) DO UPDATE SET flow_definition_id=EXCLUDED.flow_definition_id, \
             organization_id=EXCLUDED.organization_id, status=EXCLUDED.status, \
             current_step_id=EXCLUDED.current_step_id, context=EXCLUDED.context, \
             step_history=EXCLUDED.step_history, state_history=EXCLUDED.state_history, \
             subject_id=EXCLUDED.subject_id, subject_type=EXCLUDED.subject_type, \
             external_reference=EXCLUDED.external_reference, started_at=EXCLUDED.started_at, \
             completed_at=EXCLUDED.completed_at, expires_at=EXCLUDED.expires_at, \
             result=EXCLUDED.result, error=EXCLUDED.error, updated_at=EXCLUDED.updated_at \
             WHERE flow_instances.status NOT IN ('completed','failed','cancelled','expired')",
        )
        .bind(&instance.id)
        .bind(&instance.flow_definition_id)
        .bind(&instance.organization_id)
        .bind(instance.status.to_string())
        .bind(&instance.current_step_id)
        .bind(&instance.context)
        .bind(json(&instance.step_history)?)
        .bind(json(&instance.state_history)?)
        .bind(&instance.subject_id)
        .bind(&instance.subject_type)
        .bind(&instance.external_reference)
        .bind(&instance.application_flow_key_hash)
        .bind(instance.started_at)
        .bind(instance.completed_at)
        .bind(instance.expires_at)
        .bind(&instance.result)
        .bind(&instance.error)
        .bind(instance.created_at)
        .bind(instance.updated_at)
        .execute(&self.pool)
        .await
        .map_err(storage)?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn instance(&self, id: &str) -> Result<Option<FlowInstanceRecord>, RepositoryError> {
        sqlx::query(INSTANCE_SELECT)
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage)?
            .map(|row| instance_from_row(&row))
            .transpose()
    }

    pub async fn cancel_instance(
        &self,
        id: &str,
        actor: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<FlowInstanceRecord>, RepositoryError> {
        let row = sqlx::query(
            "UPDATE flow_service.flow_instances SET status='cancelled', completed_at=$2, \
             updated_at=$2, state_history=COALESCE(state_history, '[]'::jsonb) || \
             jsonb_build_array(jsonb_build_object('prior_state', status, \
             'new_state', 'cancelled', 'timestamp', $4, 'actor', $3, \
             'event', 'flow_cancelled')) WHERE id=$1 AND status NOT IN \
             ('completed','failed','cancelled','expired') RETURNING *",
        )
        .bind(id)
        .bind(now)
        .bind(actor)
        .bind(now.to_rfc3339())
        .fetch_optional(&self.pool)
        .await
        .map_err(storage)?;
        row.map(|row| instance_from_row(&row)).transpose()
    }

    pub async fn instances_for_tenant(
        &self,
        organization_id: &str,
        flow_definition_id: Option<&str>,
        status: Option<FlowInstanceStatus>,
    ) -> Result<Vec<FlowInstanceRecord>, RepositoryError> {
        let mut query = QueryBuilder::<Postgres>::new(INSTANCE_SELECT_PREFIX);
        query
            .push(" WHERE organization_id=")
            .push_bind(organization_id);
        if let Some(flow_definition_id) = flow_definition_id {
            query
                .push(" AND flow_definition_id=")
                .push_bind(flow_definition_id);
        }
        if let Some(status) = status {
            query.push(" AND status=").push_bind(status.to_string());
        }
        query.push(" ORDER BY created_at DESC");
        let rows = query.build().fetch_all(&self.pool).await.map_err(storage)?;
        rows.iter().map(instance_from_row).collect()
    }

    pub async fn save_artifact_record(
        &self,
        artifact: &FlowArtifactRecord,
    ) -> Result<Option<FlowArtifactRecord>, RepositoryError> {
        validate_artifact_record(artifact)?;
        let statement = if artifact.issuance_transaction_id.is_some() {
            ARTIFACT_UPSERT_BY_TRANSACTION
        } else {
            ARTIFACT_UPSERT_BY_ID
        };
        let row = sqlx::query(statement)
            .bind(&artifact.id)
            .bind(&artifact.flow_instance_id)
            .bind(&artifact.issuance_transaction_id)
            .bind(&artifact.credential_offer_uri)
            .bind(json(&artifact.credential_offer_uris)?)
            .bind(json(&artifact.credential_offer_labels)?)
            .bind(&artifact.pre_authorized_code)
            .bind(&artifact.issuance_status)
            .bind(&artifact.qr_payload)
            .bind(artifact.expires_at)
            .bind(artifact.scanned_at)
            .bind(enum_string(artifact.status)?)
            .bind(&artifact.state)
            .bind(&artifact.wallet_metadata)
            .bind(i32::try_from(artifact.attempt_number).map_err(number_storage)?)
            .bind(artifact.created_at)
            .bind(artifact.updated_at)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage)?;
        row.map(|row| artifact_from_row(&row)).transpose()
    }

    pub async fn artifact_record(
        &self,
        id: &str,
    ) -> Result<Option<FlowArtifactRecord>, RepositoryError> {
        sqlx::query("SELECT * FROM flow_service.flow_instance_artifacts WHERE id=$1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage)?
            .map(|row| artifact_from_row(&row))
            .transpose()
    }

    pub async fn artifacts_for_instance(
        &self,
        flow_instance_id: &str,
    ) -> Result<Vec<FlowArtifactRecord>, RepositoryError> {
        let rows = sqlx::query(
            "SELECT * FROM flow_service.flow_instance_artifacts \
             WHERE flow_instance_id=$1 ORDER BY attempt_number, created_at",
        )
        .bind(flow_instance_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage)?;
        rows.iter().map(artifact_from_row).collect()
    }

    pub async fn artifact_by_pre_authorized_code(
        &self,
        code: &str,
    ) -> Result<Option<FlowArtifactRecord>, RepositoryError> {
        sqlx::query(
            "SELECT * FROM flow_service.flow_instance_artifacts \
             WHERE pre_authorized_code=$1 ORDER BY created_at DESC LIMIT 1",
        )
        .bind(code)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage)?
        .map(|row| artifact_from_row(&row))
        .transpose()
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
             state_history=$7, application_flow_key_hash=$8, completed_at=$9, expires_at=$10, \
             result=$11, error=$12, updated_at=clock_timestamp() \
             WHERE id=$13 AND status=$14 \
             AND (expires_at IS NULL OR expires_at >= clock_timestamp())",
        )
        .bind(&instance.flow_definition_id)
        .bind(&instance.organization_id)
        .bind(instance.status.to_string())
        .bind(&instance.current_step_id)
        .bind(&instance.context)
        .bind(serde_json::to_value(&instance.step_history).map_err(json_storage)?)
        .bind(serde_json::to_value(&instance.state_history).map_err(json_storage)?)
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

const DEFINITION_SELECT: &str =
    "SELECT id, organization_id, name, description, status, flow_type, \
    steps, transitions, start_step_id, credential_template_id, application_template_id, \
    presentation_policy_id, delivery_destination_profile_id, deployment_profile_id, \
    deployment_profile_ids, trust_profile_id, approval_strategy, hooks, trigger, extension, \
    preconditions, default_timeout_seconds, max_retries, retry_cooldown_minutes, enable_resume, \
    version, created_at, updated_at \
    FROM flow_service.flow_definitions WHERE id=$1";
const DEFINITIONS_FOR_TENANT_SELECT: &str =
    "SELECT id, organization_id, name, description, status, flow_type, \
    steps, transitions, start_step_id, credential_template_id, application_template_id, \
    presentation_policy_id, delivery_destination_profile_id, deployment_profile_id, \
    deployment_profile_ids, trust_profile_id, approval_strategy, hooks, trigger, extension, \
    preconditions, default_timeout_seconds, max_retries, retry_cooldown_minutes, enable_resume, \
    version, created_at, updated_at \
    FROM flow_service.flow_definitions WHERE organization_id=$1 ORDER BY created_at DESC";
const INSTANCE_SELECT_PREFIX: &str = "SELECT id, flow_definition_id, organization_id, status, \
    current_step_id, context, step_history, state_history, subject_id, subject_type, \
    external_reference, application_flow_key_hash, started_at, completed_at, expires_at, \
    result, error, created_at, updated_at FROM flow_service.flow_instances";
const INSTANCE_SELECT: &str = "SELECT id, flow_definition_id, organization_id, status, \
    current_step_id, context, step_history, state_history, subject_id, subject_type, \
    external_reference, application_flow_key_hash, started_at, completed_at, expires_at, \
    result, error, created_at, updated_at FROM flow_service.flow_instances WHERE id=$1";
const ARTIFACT_UPSERT_BY_ID: &str = "INSERT INTO flow_service.flow_instance_artifacts \
    (id, flow_instance_id, issuance_transaction_id, credential_offer_uri, credential_offer_uris, \
     credential_offer_labels, pre_authorized_code, issuance_status, qr_payload, expires_at, \
     scanned_at, status, state, wallet_metadata, attempt_number, created_at, updated_at) VALUES \
    ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17) \
    ON CONFLICT (id) DO UPDATE SET issuance_transaction_id=EXCLUDED.issuance_transaction_id, \
    credential_offer_uri=EXCLUDED.credential_offer_uri, \
    credential_offer_uris=EXCLUDED.credential_offer_uris, \
    credential_offer_labels=EXCLUDED.credential_offer_labels, \
    pre_authorized_code=EXCLUDED.pre_authorized_code, issuance_status=EXCLUDED.issuance_status, \
    qr_payload=EXCLUDED.qr_payload, expires_at=EXCLUDED.expires_at, \
    scanned_at=EXCLUDED.scanned_at, status=EXCLUDED.status, state=EXCLUDED.state, \
    wallet_metadata=EXCLUDED.wallet_metadata, attempt_number=EXCLUDED.attempt_number, \
    updated_at=EXCLUDED.updated_at \
    WHERE flow_instance_artifacts.flow_instance_id=EXCLUDED.flow_instance_id RETURNING *";
const ARTIFACT_UPSERT_BY_TRANSACTION: &str = "INSERT INTO flow_service.flow_instance_artifacts \
    (id, flow_instance_id, issuance_transaction_id, credential_offer_uri, credential_offer_uris, \
     credential_offer_labels, pre_authorized_code, issuance_status, qr_payload, expires_at, \
     scanned_at, status, state, wallet_metadata, attempt_number, created_at, updated_at) VALUES \
    ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17) \
    ON CONFLICT (issuance_transaction_id) DO UPDATE SET \
    credential_offer_uri=EXCLUDED.credential_offer_uri, \
    credential_offer_uris=EXCLUDED.credential_offer_uris, \
    credential_offer_labels=EXCLUDED.credential_offer_labels, \
    pre_authorized_code=EXCLUDED.pre_authorized_code, issuance_status=EXCLUDED.issuance_status, \
    qr_payload=EXCLUDED.qr_payload, expires_at=EXCLUDED.expires_at, \
    scanned_at=EXCLUDED.scanned_at, status=EXCLUDED.status, state=EXCLUDED.state, \
    wallet_metadata=EXCLUDED.wallet_metadata, attempt_number=EXCLUDED.attempt_number, \
    updated_at=EXCLUDED.updated_at \
    WHERE flow_instance_artifacts.flow_instance_id=EXCLUDED.flow_instance_id RETURNING *";

fn definition_from_row(row: &PgRow) -> Result<FlowDefinitionRecord, RepositoryError> {
    let preconditions_value: Value = row.try_get("preconditions").map_err(storage)?;
    let preconditions = preconditions_value
        .as_array()
        .ok_or_else(|| record("definition.preconditions"))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| record("definition.preconditions[]"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(FlowDefinitionRecord {
        id: row.try_get("id").map_err(storage)?,
        organization_id: row.try_get("organization_id").map_err(storage)?,
        name: row.try_get("name").map_err(storage)?,
        description: row.try_get("description").map_err(storage)?,
        status: row_enum(row, "status")?,
        flow_type: row_enum(row, "flow_type")?,
        steps: json_array(row, "steps")?,
        transitions: json_array(row, "transitions")?,
        start_step_id: row.try_get("start_step_id").map_err(storage)?,
        credential_template_id: row.try_get("credential_template_id").map_err(storage)?,
        application_template_id: row.try_get("application_template_id").map_err(storage)?,
        presentation_policy_id: row.try_get("presentation_policy_id").map_err(storage)?,
        delivery_destination_profile_id: row
            .try_get("delivery_destination_profile_id")
            .map_err(storage)?,
        deployment_profile_id: row.try_get("deployment_profile_id").map_err(storage)?,
        deployment_profile_ids: json_typed(row, "deployment_profile_ids")?,
        trust_profile_id: row.try_get("trust_profile_id").map_err(storage)?,
        approval_strategy: row_enum(row, "approval_strategy")?,
        hooks: json_typed(row, "hooks")?,
        trigger: row.try_get("trigger").map_err(storage)?,
        extension: row.try_get("extension").map_err(storage)?,
        preconditions,
        default_timeout_seconds: positive_u32(row, "default_timeout_seconds")?,
        max_retries: nonnegative_u32(row, "max_retries")?,
        retry_cooldown_minutes: nonnegative_u32(row, "retry_cooldown_minutes")?,
        enable_resume: row.try_get("enable_resume").map_err(storage)?,
        version: positive_u32(row, "version")?,
        created_at: row.try_get("created_at").map_err(storage)?,
        updated_at: row.try_get("updated_at").map_err(storage)?,
    })
}

fn instance_from_row(row: &PgRow) -> Result<FlowInstanceRecord, RepositoryError> {
    Ok(FlowInstanceRecord {
        id: row.try_get("id").map_err(storage)?,
        flow_definition_id: row.try_get("flow_definition_id").map_err(storage)?,
        organization_id: row.try_get("organization_id").map_err(storage)?,
        status: row_enum(row, "status")?,
        current_step_id: row.try_get("current_step_id").map_err(storage)?,
        context: row.try_get("context").map_err(storage)?,
        step_history: json_array(row, "step_history")?,
        state_history: json_array(row, "state_history")?,
        subject_id: row.try_get("subject_id").map_err(storage)?,
        subject_type: row.try_get("subject_type").map_err(storage)?,
        external_reference: row.try_get("external_reference").map_err(storage)?,
        application_flow_key_hash: row.try_get("application_flow_key_hash").map_err(storage)?,
        started_at: row.try_get("started_at").map_err(storage)?,
        completed_at: row.try_get("completed_at").map_err(storage)?,
        expires_at: row.try_get("expires_at").map_err(storage)?,
        result: row.try_get("result").map_err(storage)?,
        error: row.try_get("error").map_err(storage)?,
        created_at: row.try_get("created_at").map_err(storage)?,
        updated_at: row.try_get("updated_at").map_err(storage)?,
    })
}

fn artifact_from_row(row: &PgRow) -> Result<FlowArtifactRecord, RepositoryError> {
    Ok(FlowArtifactRecord {
        id: row.try_get("id").map_err(storage)?,
        flow_instance_id: row.try_get("flow_instance_id").map_err(storage)?,
        issuance_transaction_id: row.try_get("issuance_transaction_id").map_err(storage)?,
        credential_offer_uri: row.try_get("credential_offer_uri").map_err(storage)?,
        credential_offer_uris: json_typed(row, "credential_offer_uris")?,
        credential_offer_labels: json_typed(row, "credential_offer_labels")?,
        pre_authorized_code: row.try_get("pre_authorized_code").map_err(storage)?,
        issuance_status: row.try_get("issuance_status").map_err(storage)?,
        qr_payload: row.try_get("qr_payload").map_err(storage)?,
        expires_at: row.try_get("expires_at").map_err(storage)?,
        scanned_at: row.try_get("scanned_at").map_err(storage)?,
        status: row_enum(row, "status")?,
        state: row.try_get("state").map_err(storage)?,
        wallet_metadata: row.try_get("wallet_metadata").map_err(storage)?,
        attempt_number: positive_u32(row, "attempt_number")?,
        created_at: row.try_get("created_at").map_err(storage)?,
        updated_at: row.try_get("updated_at").map_err(storage)?,
    })
}

fn row_enum<T: DeserializeOwned>(row: &PgRow, field: &str) -> Result<T, RepositoryError> {
    let value: String = row.try_get(field).map_err(storage)?;
    serde_json::from_value(Value::String(value)).map_err(|_| record(field))
}

fn enum_string<T: serde::Serialize>(value: T) -> Result<String, RepositoryError> {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or_else(|| record("enum"))
}

fn json<T: serde::Serialize>(value: &T) -> Result<Value, RepositoryError> {
    serde_json::to_value(value).map_err(|_| record("json"))
}

fn json_array(row: &PgRow, field: &str) -> Result<Vec<Value>, RepositoryError> {
    let value: Value = row.try_get(field).map_err(storage)?;
    value.as_array().cloned().ok_or_else(|| record(field))
}

fn json_typed<T: DeserializeOwned>(row: &PgRow, field: &str) -> Result<T, RepositoryError> {
    let value: Value = row.try_get(field).map_err(storage)?;
    serde_json::from_value(value).map_err(|_| record(field))
}

fn positive_u32(row: &PgRow, field: &str) -> Result<u32, RepositoryError> {
    let value: i32 = row.try_get(field).map_err(storage)?;
    u32::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| record(field))
}

fn nonnegative_u32(row: &PgRow, field: &str) -> Result<u32, RepositoryError> {
    let value: i32 = row.try_get(field).map_err(storage)?;
    u32::try_from(value).map_err(|_| record(field))
}

fn validate_definition_numbers(definition: &FlowDefinitionRecord) -> Result<(), RepositoryError> {
    definition.kernel()?;
    if definition.default_timeout_seconds == 0 || definition.version == 0 {
        return Err(record("definition numeric bounds"));
    }
    Ok(())
}

fn validate_instance_record(instance: &FlowInstanceRecord) -> Result<(), RepositoryError> {
    instance.kernel()?;
    if instance
        .application_flow_key_hash
        .as_ref()
        .is_some_and(|value| !valid_sha256(value))
    {
        return Err(record("instance.application_flow_key_hash"));
    }
    Ok(())
}

fn validate_artifact_record(artifact: &FlowArtifactRecord) -> Result<(), RepositoryError> {
    if artifact.attempt_number == 0 || !artifact.wallet_metadata.is_object() {
        return Err(record("artifact state"));
    }
    Ok(())
}

fn record(field: &str) -> RepositoryError {
    FlowRecordError::InvalidStoredState(field.into()).into()
}

fn number_storage(error: std::num::TryFromIntError) -> RepositoryError {
    RepositoryError::Storage(error.to_string())
}
