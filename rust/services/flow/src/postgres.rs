use chrono::{DateTime, Duration, Utc};
use marty_verification::flow::FlowInstanceStatus;
use mmf_messaging::Message;
use serde::de::DeserializeOwned;
use serde_json::Value;
use sqlx::{postgres::PgRow, PgPool, Postgres, QueryBuilder, Row};
use uuid::Uuid;

use crate::{
    checked_public_record, ApplicationEventReceipt, FlowArtifactRecord, FlowDefinitionRecord,
    FlowInstanceRecord, FlowRecordError, PhysicalStartSnapshot, PlannedApplicationFlowRecord,
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

pub struct PhysicalStartReservationInput<'a> {
    pub organization_id: &'a str,
    pub definition_id: &'a str,
    pub operation_key: &'a str,
    pub key_hash: &'a str,
    pub request_hash: &'a str,
    pub definition_snapshot: &'a PhysicalStartSnapshot,
    pub initial_actor: &'a str,
    pub original_deadline_at: DateTime<Utc>,
    pub generated_key: bool,
    pub proposed_instance_id: &'a str,
    pub now: DateTime<Utc>,
}

pub struct PhysicalStartOrigin {
    pub definition_snapshot: Value,
    pub created_at: DateTime<Utc>,
    pub initial_actor: String,
    pub original_deadline_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PhysicalStartReservation {
    Acquired {
        instance_id: String,
        claim_token: Uuid,
    },
    InProgress {
        instance_id: String,
    },
    Expired {
        instance_id: String,
    },
    Completed {
        instance_id: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingPhysicalStart {
    pub instance_id: String,
    pub flow_definition_id: String,
    pub key_source: String,
    pub created_at: DateTime<Utc>,
    pub original_deadline_at: DateTime<Utc>,
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

    pub async fn physical_start_snapshot(
        &self,
        organization_id: &str,
        key_hash: &str,
    ) -> Result<Option<Value>, RepositoryError> {
        Ok(self
            .physical_start_origin(organization_id, key_hash)
            .await?
            .map(|origin| origin.definition_snapshot))
    }

    pub async fn physical_start_origin(
        &self,
        organization_id: &str,
        key_hash: &str,
    ) -> Result<Option<PhysicalStartOrigin>, RepositoryError> {
        if !valid_sha256(key_hash) {
            return Err(RepositoryError::InvalidReplayDigest);
        }
        sqlx::query(
            "SELECT definition_snapshot,created_at,initial_actor,original_deadline_at
             FROM flow_service.physical_start_intents
             WHERE organization_id=$1 AND key_hash=$2",
        )
        .bind(organization_id)
        .bind(key_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage)?
        .map(|row| {
            Ok(PhysicalStartOrigin {
                definition_snapshot: row.try_get("definition_snapshot").map_err(storage)?,
                created_at: row.try_get("created_at").map_err(storage)?,
                initial_actor: row.try_get("initial_actor").map_err(storage)?,
                original_deadline_at: row.try_get("original_deadline_at").map_err(storage)?,
            })
        })
        .transpose()
    }

    pub async fn physical_start_snapshot_by_instance(
        &self,
        organization_id: &str,
        instance_id: &str,
    ) -> Result<Option<Value>, RepositoryError> {
        sqlx::query_scalar(
            "SELECT definition_snapshot FROM flow_service.physical_start_intents
             WHERE organization_id=$1 AND instance_id=$2",
        )
        .bind(organization_id)
        .bind(instance_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage)
    }

    pub async fn physical_start_snapshot_by_definition_key(
        &self,
        definition_id: &str,
        key_hash: &str,
    ) -> Result<Option<(String, Value)>, RepositoryError> {
        if !valid_sha256(key_hash) {
            return Err(RepositoryError::InvalidReplayDigest);
        }
        let rows = sqlx::query(
            "SELECT organization_id,definition_snapshot
             FROM flow_service.physical_start_intents
             WHERE flow_definition_id=$1 AND key_hash=$2 LIMIT 2",
        )
        .bind(definition_id)
        .bind(key_hash)
        .fetch_all(&self.pool)
        .await
        .map_err(storage)?;
        if rows.len() > 1 {
            return Err(RepositoryError::PhysicalStartKeyConflict);
        }
        rows.into_iter()
            .next()
            .map(|row| {
                Ok((
                    row.try_get("organization_id").map_err(storage)?,
                    row.try_get("definition_snapshot").map_err(storage)?,
                ))
            })
            .transpose()
    }

    pub async fn reserve_physical_start(
        &self,
        input: PhysicalStartReservationInput<'_>,
    ) -> Result<PhysicalStartReservation, RepositoryError> {
        let PhysicalStartReservationInput {
            organization_id,
            definition_id,
            operation_key,
            key_hash,
            request_hash,
            definition_snapshot,
            initial_actor,
            original_deadline_at,
            generated_key,
            proposed_instance_id,
            now,
        } = input;
        if !valid_sha256(key_hash) || !valid_sha256(request_hash) {
            return Err(RepositoryError::InvalidReplayDigest);
        }
        if !definition_snapshot.matches(organization_id, definition_id) {
            return Err(RepositoryError::InvalidPhysicalStartSnapshot);
        }
        let snapshot_json = serde_json::to_value(definition_snapshot)
            .map_err(|_| RepositoryError::InvalidPhysicalStartSnapshot)?;
        let token = Uuid::new_v4();
        let expires = now + Duration::seconds(60);
        let mut transaction = self.pool.begin().await.map_err(storage)?;
        // A pending client-key start exposes its instance UUID for readback,
        // but that UUID is not a substitute for the original client key.
        if Uuid::parse_str(operation_key)
            .ok()
            .is_some_and(|id| id.to_string() == operation_key)
        {
            let reserved_by_other_key: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM flow_service.physical_start_intents
                 WHERE organization_id=$1 AND instance_id=$2 AND key_hash<>$3)",
            )
            .bind(organization_id)
            .bind(operation_key)
            .bind(key_hash)
            .fetch_one(&mut *transaction)
            .await
            .map_err(storage)?;
            if reserved_by_other_key {
                return Err(RepositoryError::PhysicalStartKeyConflict);
            }
        }
        let inserted = sqlx::query(
            "INSERT INTO flow_service.physical_start_intents
             (organization_id,key_hash,request_hash,definition_snapshot,initial_actor,original_deadline_at,key_source,flow_definition_id,instance_id,
              status,claim_token,claim_expires_at,created_at,updated_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'pending',$10,$11,$12,$12)
             ON CONFLICT (organization_id,key_hash) DO NOTHING RETURNING instance_id",
        )
        .bind(organization_id)
        .bind(key_hash)
        .bind(request_hash)
        .bind(snapshot_json)
        .bind(initial_actor)
        .bind(original_deadline_at)
        .bind(if generated_key { "generated" } else { "client" })
        .bind(definition_id)
        .bind(proposed_instance_id)
        .bind(token)
        .bind(expires)
        .bind(now)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(storage)?;
        if inserted.is_some() {
            transaction.commit().await.map_err(storage)?;
            return Ok(PhysicalStartReservation::Acquired {
                instance_id: proposed_instance_id.to_owned(),
                claim_token: token,
            });
        }
        let row = sqlx::query(
            "SELECT request_hash,flow_definition_id,instance_id,status,claim_expires_at,original_deadline_at
             FROM flow_service.physical_start_intents
             WHERE organization_id=$1 AND key_hash=$2 FOR UPDATE",
        )
        .bind(organization_id)
        .bind(key_hash)
        .fetch_one(&mut *transaction)
        .await
        .map_err(storage)?;
        let prior_hash: String = row.try_get("request_hash").map_err(storage)?;
        let prior_definition: String = row.try_get("flow_definition_id").map_err(storage)?;
        let instance_id: String = row.try_get("instance_id").map_err(storage)?;
        if prior_hash != request_hash || prior_definition != definition_id {
            return Err(RepositoryError::PhysicalStartKeyConflict);
        }
        let status: String = row.try_get("status").map_err(storage)?;
        if status == "completed" {
            transaction.commit().await.map_err(storage)?;
            return Ok(PhysicalStartReservation::Completed { instance_id });
        }
        let original_deadline_at: DateTime<Utc> =
            row.try_get("original_deadline_at").map_err(storage)?;
        if now >= original_deadline_at {
            transaction.commit().await.map_err(storage)?;
            return Ok(PhysicalStartReservation::Expired { instance_id });
        }
        let prior_expiry: Option<DateTime<Utc>> =
            row.try_get("claim_expires_at").map_err(storage)?;
        if prior_expiry.is_some_and(|expiry| expiry > now) {
            transaction.commit().await.map_err(storage)?;
            return Ok(PhysicalStartReservation::InProgress { instance_id });
        }
        sqlx::query(
            "UPDATE flow_service.physical_start_intents
             SET claim_token=$3,claim_expires_at=$4,updated_at=$5
             WHERE organization_id=$1 AND key_hash=$2 AND status='pending'",
        )
        .bind(organization_id)
        .bind(key_hash)
        .bind(token)
        .bind(expires)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(storage)?;
        transaction.commit().await.map_err(storage)?;
        Ok(PhysicalStartReservation::Acquired {
            instance_id,
            claim_token: token,
        })
    }

    pub async fn pending_physical_starts(
        &self,
        organization_id: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<PendingPhysicalStart>, RepositoryError> {
        let rows = sqlx::query(
            "SELECT instance_id,flow_definition_id,key_source,created_at,original_deadline_at
             FROM flow_service.physical_start_intents
             WHERE organization_id=$1 AND status='pending'
             ORDER BY created_at,instance_id LIMIT $2 OFFSET $3",
        )
        .bind(organization_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await
        .map_err(storage)?;
        rows.into_iter()
            .map(|row| {
                Ok(PendingPhysicalStart {
                    instance_id: row.try_get("instance_id").map_err(storage)?,
                    flow_definition_id: row.try_get("flow_definition_id").map_err(storage)?,
                    key_source: row.try_get("key_source").map_err(storage)?,
                    created_at: row.try_get("created_at").map_err(storage)?,
                    original_deadline_at: row.try_get("original_deadline_at").map_err(storage)?,
                })
            })
            .collect()
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

    /// Inserts a newly started instance and its optional protocol artifact as
    /// one database unit. Conflicts fail without leaving either partial row.
    pub async fn save_started_instance(
        &self,
        instance: &FlowInstanceRecord,
        artifact: Option<&FlowArtifactRecord>,
    ) -> Result<bool, RepositoryError> {
        self.save_started_instance_with_intent(instance, artifact, None)
            .await
    }

    pub async fn save_started_physical_instance(
        &self,
        instance: &FlowInstanceRecord,
        key_hash: &str,
        claim_token: Uuid,
    ) -> Result<bool, RepositoryError> {
        if !valid_sha256(key_hash) {
            return Err(RepositoryError::InvalidReplayDigest);
        }
        self.save_started_instance_with_intent(instance, None, Some((key_hash, claim_token)))
            .await
    }

    async fn save_started_instance_with_intent(
        &self,
        instance: &FlowInstanceRecord,
        artifact: Option<&FlowArtifactRecord>,
        physical_intent: Option<(&str, Uuid)>,
    ) -> Result<bool, RepositoryError> {
        validate_instance_record(instance)?;
        if let Some(artifact) = artifact {
            validate_artifact_record(artifact)?;
            if artifact.flow_instance_id != instance.id {
                return Err(record("artifact.flow_instance_id"));
            }
        }
        let mut transaction = self.pool.begin().await.map_err(storage)?;
        let inserted = sqlx::query(
            "INSERT INTO flow_service.flow_instances (id, flow_definition_id, organization_id, \
             status, current_step_id, context, step_history, state_history, subject_id, subject_type, \
             external_reference, application_flow_key_hash, started_at, completed_at, expires_at, \
             result, error, created_at, updated_at) VALUES \
             ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19) \
             ON CONFLICT DO NOTHING",
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
        .execute(&mut *transaction)
        .await
        .map_err(storage)?;
        if inserted.rows_affected() != 1 {
            transaction.rollback().await.map_err(storage)?;
            return Ok(false);
        }
        if let Some(artifact) = artifact {
            let inserted = sqlx::query(
                "INSERT INTO flow_service.flow_instance_artifacts \
                 (id, flow_instance_id, issuance_transaction_id, credential_offer_uri, \
                  credential_offer_uris, credential_offer_labels, pre_authorized_code, \
                  issuance_status, qr_payload, expires_at, scanned_at, status, state, \
                  wallet_metadata, attempt_number, created_at, updated_at) VALUES \
                 ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17) \
                 ON CONFLICT DO NOTHING",
            )
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
            .execute(&mut *transaction)
            .await
            .map_err(storage)?;
            if inserted.rows_affected() != 1 {
                transaction.rollback().await.map_err(storage)?;
                return Ok(false);
            }
        }
        if let Some((key_hash, claim_token)) = physical_intent {
            let updated = sqlx::query(
                "UPDATE flow_service.physical_start_intents
                 SET status='completed',claim_token=NULL,claim_expires_at=NULL,updated_at=$5
                 WHERE organization_id=$1 AND key_hash=$2 AND instance_id=$3
                   AND claim_token=$4 AND status='pending'",
            )
            .bind(&instance.organization_id)
            .bind(key_hash)
            .bind(&instance.id)
            .bind(claim_token)
            .bind(instance.updated_at)
            .execute(&mut *transaction)
            .await
            .map_err(storage)?;
            if updated.rows_affected() != 1 {
                transaction.rollback().await.map_err(storage)?;
                return Ok(false);
            }
        }
        transaction.commit().await.map_err(storage)?;
        Ok(true)
    }

    /// Reserves an authenticated application event and every selected flow in
    /// one transaction. Event identity and logical application-flow identity
    /// are immutable; replays recover the original plan, while changed payload
    /// or offer semantics fail closed.
    pub async fn reserve_application_event_plan(
        &self,
        mut receipt: ApplicationEventReceipt,
        planned: &[PlannedApplicationFlowRecord],
    ) -> Result<(ApplicationEventReceipt, bool), RepositoryError> {
        if !valid_sha256(&receipt.event_id_sha256) || !valid_sha256(&receipt.payload_sha256) {
            return Err(RepositoryError::InvalidReplayDigest);
        }
        for candidate in planned {
            validate_instance_record(&candidate.instance)?;
            if candidate
                .instance
                .application_flow_key_hash
                .as_deref()
                .is_none_or(|digest| !valid_sha256(digest))
            {
                return Err(record("instance.application_flow_key_hash"));
            }
        }

        let created_at = timestamp(receipt.created_at_ms)?;
        let updated_at = timestamp(receipt.updated_at_ms)?;
        let mut transaction = self.pool.begin().await.map_err(storage)?;
        let inserted = sqlx::query(
            "INSERT INTO flow_service.flow_application_event_receipts \
             (event_id_sha256, payload_sha256, organization_id, application_id, flow_plan, \
              created_at, updated_at) VALUES ($1,$2,$3,$4,'[]'::json,$5,$6) \
             ON CONFLICT (event_id_sha256) DO NOTHING",
        )
        .bind(&receipt.event_id_sha256)
        .bind(&receipt.payload_sha256)
        .bind(&receipt.organization_id)
        .bind(&receipt.application_id)
        .bind(created_at)
        .bind(updated_at)
        .execute(&mut *transaction)
        .await
        .map_err(storage)?;
        if inserted.rows_affected() == 0 {
            let row = sqlx::query(
                "SELECT event_id_sha256, payload_sha256, organization_id, application_id, \
                 flow_plan, created_at, updated_at \
                 FROM flow_service.flow_application_event_receipts WHERE event_id_sha256=$1",
            )
            .bind(&receipt.event_id_sha256)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(storage)?
            .ok_or_else(|| RepositoryError::Storage("application event plan is missing".into()))?;
            let existing = application_receipt_from_row(&row)?;
            if existing.payload_sha256 != receipt.payload_sha256
                || existing.organization_id != receipt.organization_id
                || existing.application_id != receipt.application_id
            {
                transaction.rollback().await.map_err(storage)?;
                return Err(RepositoryError::ApplicationOfferConflict(
                    "event identity is bound to another payload".into(),
                ));
            }
            transaction.commit().await.map_err(storage)?;
            return Ok((existing, false));
        }

        let mut final_plan = Vec::with_capacity(planned.len());
        for candidate in planned {
            let instance = &candidate.instance;
            sqlx::query(
                "INSERT INTO flow_service.flow_instances \
                 (id, flow_definition_id, organization_id, status, current_step_id, context, \
                  step_history, state_history, subject_id, subject_type, external_reference, \
                  application_flow_key_hash, started_at, completed_at, expires_at, result, error, \
                  created_at, updated_at) VALUES \
                 ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19) \
                 ON CONFLICT (organization_id, application_flow_key_hash) DO NOTHING",
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
            .execute(&mut *transaction)
            .await
            .map_err(storage)?;

            let row = sqlx::query(
                "SELECT id, flow_definition_id, organization_id, status, current_step_id, \
                 context, step_history, state_history, subject_id, subject_type, \
                 external_reference, application_flow_key_hash, started_at, completed_at, \
                 expires_at, result, error, created_at, updated_at \
                 FROM flow_service.flow_instances \
                 WHERE organization_id=$1 AND application_flow_key_hash=$2",
            )
            .bind(&instance.organization_id)
            .bind(&instance.application_flow_key_hash)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(storage)?
            .ok_or_else(|| {
                RepositoryError::Storage("application flow reservation is missing".into())
            })?;
            let selected = instance_from_row(&row)?;
            let semantics_key = candidate
                .plan_entry
                .get("offer_semantics_context_key")
                .map(String::as_str)
                .unwrap_or("_marty_application_offer_semantics_hash_v1");
            if selected.context.get(semantics_key).and_then(Value::as_str)
                != candidate
                    .plan_entry
                    .get("offer_semantics_hash")
                    .map(String::as_str)
            {
                transaction.rollback().await.map_err(storage)?;
                return Err(RepositoryError::ApplicationOfferConflict(
                    "application and flow are bound to different issuance claims".into(),
                ));
            }
            let mut entry = candidate.plan_entry.clone();
            entry.insert("instance_id".into(), selected.id);
            final_plan.push(entry);
        }

        checked_public_record(&final_plan)?;
        sqlx::query(
            "UPDATE flow_service.flow_application_event_receipts SET flow_plan=$1, updated_at=$2 \
             WHERE event_id_sha256=$3",
        )
        .bind(json(&final_plan)?)
        .bind(updated_at)
        .bind(&receipt.event_id_sha256)
        .execute(&mut *transaction)
        .await
        .map_err(storage)?;
        receipt.flow_plan = final_plan;
        transaction.commit().await.map_err(storage)?;
        Ok((receipt, true))
    }

    /// Persists one advancement only when the caller's source snapshot still
    /// matches the live status and timestamp.
    pub async fn compare_and_swap_instance(
        &self,
        instance: &FlowInstanceRecord,
        expected_status: FlowInstanceStatus,
        expected_updated_at: DateTime<Utc>,
    ) -> Result<bool, RepositoryError> {
        validate_instance_record(instance)?;
        if !matches!(
            expected_status,
            FlowInstanceStatus::InProgress | FlowInstanceStatus::AwaitingWallet
        ) || instance.updated_at <= expected_updated_at
        {
            return Ok(false);
        }
        let result = sqlx::query(
            "UPDATE flow_service.flow_instances SET flow_definition_id=$1, \
             organization_id=$2, status=$3, current_step_id=$4, context=$5, \
             step_history=$6, state_history=$7, subject_id=$8, subject_type=$9, \
             external_reference=$10, application_flow_key_hash=$11, started_at=$12, \
             completed_at=$13, expires_at=$14, result=$15, error=$16, updated_at=$17 \
             WHERE id=$18 AND status=$19 AND updated_at=$20 \
             AND status NOT IN ('completed','failed','cancelled','expired')",
        )
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
        .bind(instance.updated_at)
        .bind(&instance.id)
        .bind(expected_status.to_string())
        .bind(expected_updated_at)
        .execute(&self.pool)
        .await
        .map_err(storage)?;
        Ok(result.rows_affected() == 1)
    }

    /// Expires active offer artifacts, inserts a replacement, and updates the
    /// instance's offer context using one snapshot-bound transaction.
    pub async fn replace_active_artifacts(
        &self,
        instance: &FlowInstanceRecord,
        artifact: &FlowArtifactRecord,
        expected_updated_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<bool, RepositoryError> {
        validate_instance_record(instance)?;
        validate_artifact_record(artifact)?;
        if artifact.flow_instance_id != instance.id || instance.updated_at <= expected_updated_at {
            return Err(record("artifact replacement binding"));
        }
        let mut transaction = self.pool.begin().await.map_err(storage)?;
        let updated = sqlx::query(
            "UPDATE flow_service.flow_instances SET context=$1, updated_at=$2 \
             WHERE id=$3 AND updated_at=$4",
        )
        .bind(&instance.context)
        .bind(instance.updated_at)
        .bind(&instance.id)
        .bind(expected_updated_at)
        .execute(&mut *transaction)
        .await
        .map_err(storage)?;
        if updated.rows_affected() != 1 {
            transaction.rollback().await.map_err(storage)?;
            return Ok(false);
        }
        sqlx::query(
            "UPDATE flow_service.flow_instance_artifacts SET status='expired', updated_at=$2 \
             WHERE flow_instance_id=$1 AND status='active'",
        )
        .bind(&instance.id)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(storage)?;
        let inserted = sqlx::query(
            "INSERT INTO flow_service.flow_instance_artifacts \
             (id, flow_instance_id, issuance_transaction_id, credential_offer_uri, \
              credential_offer_uris, credential_offer_labels, pre_authorized_code, \
              issuance_status, qr_payload, expires_at, scanned_at, status, state, \
              wallet_metadata, attempt_number, created_at, updated_at) VALUES \
             ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17) \
             ON CONFLICT DO NOTHING",
        )
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
        .execute(&mut *transaction)
        .await
        .map_err(storage)?;
        if inserted.rows_affected() != 1 {
            transaction.rollback().await.map_err(storage)?;
            return Ok(false);
        }
        transaction.commit().await.map_err(storage)?;
        Ok(true)
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
             updated_at=$2, state_history=(COALESCE(state_history, '[]'::json)::jsonb || \
             jsonb_build_array(jsonb_build_object('prior_state', status, \
             'new_state', 'cancelled', 'timestamp', $4, 'actor', $3, \
             'event', 'flow_cancelled')))::json WHERE id=$1 AND status NOT IN \
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
        instance: &FlowInstanceRecord,
        nonce_digest: &str,
        replay_expires_at_ms: u64,
        expected_status: FlowInstanceStatus,
        callback: Option<&Message>,
    ) -> Result<bool, RepositoryError> {
        validate_instance_record(instance)?;
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

        let update = sqlx::query(
            "UPDATE flow_service.flow_instances SET \
             status=$1, current_step_id=$2, context=$3, step_history=$4, \
             state_history=$5, subject_id=$6, subject_type=$7, external_reference=$8, \
             application_flow_key_hash=$9, started_at=$10, completed_at=$11, expires_at=$12, \
             result=$13, error=$14, updated_at=$15 \
             WHERE id=$16 AND status=$17 AND organization_id=$18 AND flow_definition_id=$19 \
             AND (expires_at IS NULL OR expires_at >= clock_timestamp())",
        )
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
        .bind(instance.updated_at)
        .bind(&instance.id)
        .bind(expected_status.to_string())
        .bind(&instance.organization_id)
        .bind(&instance.flow_definition_id)
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
                payload: checked_public_record(row.try_get("payload").map_err(storage)?)?,
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
    instance: &FlowInstanceRecord,
    callback: Option<&Message>,
) -> Result<(), RepositoryError> {
    if let Some(message) = callback {
        checked_public_record(&message.payload)?;
    }
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
    checked_public_record(FlowDefinitionRecord {
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

fn application_receipt_from_row(row: &PgRow) -> Result<ApplicationEventReceipt, RepositoryError> {
    let flow_plan: Value = row.try_get("flow_plan").map_err(storage)?;
    checked_public_record(&flow_plan)?;
    let flow_plan = serde_json::from_value(flow_plan).map_err(|_| record("receipt.flow_plan"))?;
    let created_at: DateTime<Utc> = row.try_get("created_at").map_err(storage)?;
    let updated_at: DateTime<Utc> = row.try_get("updated_at").map_err(storage)?;
    Ok(ApplicationEventReceipt {
        event_id_sha256: row.try_get("event_id_sha256").map_err(storage)?,
        payload_sha256: row.try_get("payload_sha256").map_err(storage)?,
        organization_id: row.try_get("organization_id").map_err(storage)?,
        application_id: row.try_get("application_id").map_err(storage)?,
        flow_plan,
        created_at_ms: u64::try_from(created_at.timestamp_millis()).map_err(number_storage)?,
        updated_at_ms: u64::try_from(updated_at.timestamp_millis()).map_err(number_storage)?,
    })
}

fn instance_from_row(row: &PgRow) -> Result<FlowInstanceRecord, RepositoryError> {
    checked_public_record(FlowInstanceRecord {
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
    checked_public_record(FlowArtifactRecord {
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
    checked_public_record(definition)?;
    definition.kernel()?;
    if definition.default_timeout_seconds == 0 || definition.version == 0 {
        return Err(record("definition numeric bounds"));
    }
    Ok(())
}

fn validate_instance_record(instance: &FlowInstanceRecord) -> Result<(), RepositoryError> {
    checked_public_record(instance)?;
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
    checked_public_record(artifact)?;
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

#[cfg(test)]
mod private_material_tests {
    use super::*;
    use sqlx::postgres::PgPoolOptions;

    #[tokio::test]
    async fn direct_instance_write_rejects_private_jwk_before_database_access() {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://localhost:1/flow_test")
            .unwrap();
        let repository = PostgresFlowRepository::new(pool);
        let instance = FlowInstanceRecord {
            id: "instance-1".into(),
            flow_definition_id: "flow-1".into(),
            organization_id: "org-1".into(),
            status: FlowInstanceStatus::Created,
            current_step_id: None,
            context: serde_json::json!({"public_jwk":{"kty":"EC","d":"secret"}}),
            step_history: vec![],
            state_history: vec![],
            subject_id: None,
            subject_type: "applicant".into(),
            external_reference: None,
            application_flow_key_hash: None,
            started_at: None,
            completed_at: None,
            expires_at: None,
            result: None,
            error: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert!(matches!(
            repository.save_instance(&instance).await,
            Err(RepositoryError::InvalidStoredState(_))
        ));
    }
}
