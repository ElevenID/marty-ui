// SPDX-License-Identifier: AGPL-3.0-only
//! Core-owned receipt journal. No HTTP route, authority cache, or provider I/O.
//!
//! A real authority adapter is mandatory. It must serialize canonical key/grant/
//! binding/application changes with this transaction. No production adapter is
//! installed by this module; a stale replica or an unlocked RPC is insufficient.

use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{PgConnection, PgPool, Row};
use uuid::Uuid;

use crate::external_observation_admission::{
    plan_admission, Admission, ApplicationSnapshot, AuthenticatedApiKey, Denial, EvidenceBinding,
    InsertPlan, Observation, ProducerGrant, ReplaySnapshot, Scalar, StoredReceipt,
};

/// Single SQL source registered by the protected issuance schema-owner command.
pub const OBSERVATION_SCHEMA: &str = crate::external_observation_schema::MIGRATION_SQL;

/// Identity from successful Common Gateway authentication, not body/header claims.
/// No raw API key is stored here or in the journal.
pub struct ProducerIdentity {
    pub api_key_id: String,
    pub organization_id: String,
}

pub struct LockedAuthority {
    pub principal: AuthenticatedApiKey,
    pub grant: ProducerGrant,
    pub binding: EvidenceBinding,
    pub application: ApplicationSnapshot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalError {
    Denied(Denial),
    Conflict,
    Unavailable,
    InvalidStoredState,
    /// COMMIT may have reached PostgreSQL. Reconcile by the SAME observation ID;
    /// never manufacture a replacement ID or perform an automatic write retry.
    CommitUnknown,
}

impl std::fmt::Display for JournalError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "External observation journal: {self:?}")
    }
}
impl std::error::Error for JournalError {}

/// Locks must survive until transaction end and be acquired in a stable order.
/// Return an error on missing/unavailable authority; never fabricate a snapshot.
/// Revisions must change on every permission, identity, lifecycle or schema edit.
/// Implementations may read core owners only; connector packages cannot implement
/// this boundary remotely. The second call is a final locked revalidation.
#[async_trait]
pub trait ObservationAuthority: Send + Sync {
    async fn lock_current(
        &self,
        connection: &mut PgConnection,
        identity: &ProducerIdentity,
        binding_id: &str,
    ) -> Result<LockedAuthority, JournalError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptAcknowledgment {
    pub receipt_id: String,
    pub replayed: bool,
}

pub struct PostgresObservationJournal {
    pool: PgPool,
    authority: Arc<dyn ObservationAuthority>,
}

impl PostgresObservationJournal {
    pub fn new(pool: PgPool, authority: Arc<dyn ObservationAuthority>) -> Self {
        Self { pool, authority }
    }

    /// No plan supplied by a caller is accepted. Recompute admission from locked
    /// core authority, and return an acknowledgment only after COMMIT succeeds.
    pub async fn submit(
        &self,
        identity: &ProducerIdentity,
        input: &Observation,
        idempotency_key: &str,
    ) -> Result<ReceiptAcknowledgment, JournalError> {
        let mut transaction = self.pool.begin().await.map_err(database_error)?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
            .execute(&mut *transaction)
            .await
            .map_err(database_error)?;
        sqlx::query("SET LOCAL lock_timeout = '5s'")
            .execute(&mut *transaction)
            .await
            .map_err(database_error)?;
        sqlx::query("SET LOCAL statement_timeout = '10s'")
            .execute(&mut *transaction)
            .await
            .map_err(database_error)?;
        let authority = self
            .authority
            .lock_current(&mut transaction, identity, &input.binding_id)
            .await?;
        check_identity(identity, &authority)?;

        let receipt = lookup_receipt(
            &mut transaction,
            &authority.principal.organization_id,
            &authority.grant.source_id,
            &input.observation_id,
        )
        .await?;
        let sequence = sqlx::query_scalar::<_, i64>(
            "SELECT sequence FROM issuance_service.external_observation_heads \
             WHERE organization_id = $1 AND source_id = $2 AND binding_id = $3 FOR UPDATE",
        )
        .bind(&authority.principal.organization_id)
        .bind(&authority.grant.source_id)
        .bind(&authority.binding.id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(database_error)?;
        let sequence = match sequence {
            Some(value) => u64::try_from(value).map_err(|_| JournalError::InvalidStoredState)?,
            None => 0,
        };
        let decision = evaluate(
            &authority,
            input,
            idempotency_key,
            receipt.as_ref(),
            sequence,
            database_clock(&mut transaction).await?,
        )?;
        let acknowledgment = match &decision {
            Admission::Insert(plan) => insert(&mut transaction, plan).await?,
            Admission::Replay { receipt_id } => ReceiptAcknowledgment {
                receipt_id: receipt_id.clone(),
                replayed: true,
            },
        };

        // Keep all locks, including the canonical authority locks, until COMMIT.
        // Re-check clock expiry AFTER writes/lock waits, not only at transaction start.
        let final_authority = self
            .authority
            .lock_current(&mut transaction, identity, &input.binding_id)
            .await?;
        check_identity(identity, &final_authority)?;
        let final_decision = evaluate(
            &final_authority,
            input,
            idempotency_key,
            receipt.as_ref(),
            sequence,
            database_clock(&mut transaction).await?,
        )?;
        if !same_decision(&decision, &final_decision) {
            return Err(JournalError::Conflict);
        }
        // On every earlier error, SQLx drops the transaction and rolls it back.
        transaction.commit().await.map_err(|error| {
            if database_error(error) == JournalError::Conflict {
                JournalError::Conflict
            } else {
                JournalError::CommitUnknown
            }
        })?;
        Ok(acknowledgment)
    }
}

fn check_identity(
    identity: &ProducerIdentity,
    authority: &LockedAuthority,
) -> Result<(), JournalError> {
    if identity.api_key_id != authority.principal.id
        || identity.organization_id != authority.principal.organization_id
    {
        return Err(JournalError::Denied(Denial::NotAuthorized));
    }
    Ok(())
}

fn evaluate(
    authority: &LockedAuthority,
    input: &Observation,
    idempotency_key: &str,
    receipt: Option<&StoredReceipt>,
    current_sequence: u64,
    now: u64,
) -> Result<Admission, JournalError> {
    plan_admission(
        &authority.principal,
        &authority.grant,
        &authority.binding,
        &authority.application,
        input,
        idempotency_key,
        receipt.map_or(
            ReplaySnapshot::Missing { current_sequence },
            ReplaySnapshot::Existing,
        ),
        now,
    )
    .map_err(JournalError::Denied)
}

fn same_decision(before: &Admission, after: &Admission) -> bool {
    match (before, after) {
        (Admission::Replay { receipt_id: a }, Admission::Replay { receipt_id: b }) => a == b,
        (Admission::Insert(a), Admission::Insert(b)) => {
            a.fence == b.fence
                && a.observation == b.observation
                && a.organization_id == b.organization_id
                && a.api_key_id == b.api_key_id
                && a.source_id == b.source_id
                && a.provider == b.provider
                && a.application_id == b.application_id
                && a.subject_id == b.subject_id
                && a.fact_type == b.fact_type
                && a.resource_scope == b.resource_scope
        }
        _ => false,
    }
}

async fn database_clock(connection: &mut PgConnection) -> Result<u64, JournalError> {
    let value = sqlx::query_scalar::<_, i64>(
        "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint",
    )
    .fetch_one(connection)
    .await
    .map_err(database_error)?;
    u64::try_from(value).map_err(|_| JournalError::InvalidStoredState)
}

fn database_error(error: sqlx::Error) -> JournalError {
    match error
        .as_database_error()
        .and_then(|value| value.code())
        .as_deref()
    {
        Some("23505" | "40001" | "40P01" | "55P03") => JournalError::Conflict,
        _ => JournalError::Unavailable,
    }
}

// Internal persistence encoding only. This is NOT the public HTTP decoder.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedObservation {
    binding_id: String,
    binding_revision: u64,
    observation_id: String,
    sequence: u64,
    observed_at_ms: u64,
    effective_at_ms: u64,
    claims: BTreeMap<String, Value>,
}

fn encode(input: &Observation) -> Result<Value, JournalError> {
    let claims = input
        .claims
        .iter()
        .map(|(key, value)| {
            let value = match value {
                Scalar::Null => Value::Null,
                Scalar::Boolean(value) => Value::Bool(*value),
                Scalar::Number(value) => Value::Number(
                    serde_json::Number::from_f64(*value).ok_or(JournalError::InvalidStoredState)?,
                ),
                Scalar::Text(value) => Value::String(value.clone()),
            };
            Ok((key.clone(), value))
        })
        .collect::<Result<_, JournalError>>()?;
    serde_json::to_value(PersistedObservation {
        binding_id: input.binding_id.clone(),
        binding_revision: input.binding_revision,
        observation_id: input.observation_id.clone(),
        sequence: input.sequence,
        observed_at_ms: input.observed_at_ms,
        effective_at_ms: input.effective_at_ms,
        claims,
    })
    .map_err(|_| JournalError::InvalidStoredState)
}

fn decode(value: Value) -> Result<Observation, JournalError> {
    let stored: PersistedObservation =
        serde_json::from_value(value).map_err(|_| JournalError::InvalidStoredState)?;
    let claims = stored
        .claims
        .into_iter()
        .map(|(key, value)| {
            let value = match value {
                Value::Null => Scalar::Null,
                Value::Bool(value) => Scalar::Boolean(value),
                Value::Number(value) => Scalar::Number(
                    value
                        .as_f64()
                        .filter(|v| v.is_finite())
                        .ok_or(JournalError::InvalidStoredState)?,
                ),
                Value::String(value) => Scalar::Text(value),
                _ => return Err(JournalError::InvalidStoredState),
            };
            Ok((key, value))
        })
        .collect::<Result<_, JournalError>>()?;
    Ok(Observation {
        binding_id: stored.binding_id,
        binding_revision: stored.binding_revision,
        observation_id: stored.observation_id,
        sequence: stored.sequence,
        observed_at_ms: stored.observed_at_ms,
        effective_at_ms: stored.effective_at_ms,
        claims,
    })
}

async fn lookup_receipt(
    connection: &mut PgConnection,
    organization: &str,
    source: &str,
    observation: &str,
) -> Result<Option<StoredReceipt>, JournalError> {
    let row = sqlx::query(
        "SELECT receipt_id, organization_id, source_id, api_key_id, envelope \
         FROM issuance_service.external_observation_lock_receipt($1,$2,$3)",
    )
    .bind(organization)
    .bind(source)
    .bind(observation)
    .fetch_optional(connection)
    .await
    .map_err(database_error)?;
    row.map(|row| {
        Ok(StoredReceipt {
            id: row
                .try_get::<Uuid, _>("receipt_id")
                .map_err(database_error)?
                .to_string(),
            organization_id: row.try_get("organization_id").map_err(database_error)?,
            source_id: row.try_get("source_id").map_err(database_error)?,
            api_key_id: row.try_get("api_key_id").map_err(database_error)?,
            observation: decode(row.try_get("envelope").map_err(database_error)?)?,
        })
    })
    .transpose()
}

async fn insert(
    connection: &mut PgConnection,
    plan: &InsertPlan,
) -> Result<ReceiptAcknowledgment, JournalError> {
    let receipt_id = Uuid::new_v4();
    let input = &plan.observation;
    sqlx::query(
        "INSERT INTO issuance_service.external_observation_receipts \
         (receipt_id, organization_id, source_id, api_key_id, binding_id, binding_revision, \
          observation_id, sequence, received_at_ms, application_id, subject_id, provider, fact_type, \
          resource_scope, envelope) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)",
    ).bind(receipt_id).bind(&plan.organization_id).bind(&plan.source_id).bind(&plan.api_key_id)
        .bind(&input.binding_id).bind(input.binding_revision as i64).bind(&input.observation_id)
        .bind(input.sequence as i64).bind(plan.received_at_ms as i64)
        .bind(&plan.application_id).bind(&plan.subject_id).bind(&plan.provider).bind(&plan.fact_type)
        .bind(serde_json::to_value(&plan.resource_scope).map_err(|_| JournalError::InvalidStoredState)?)
        .bind(encode(input)?)
        .execute(&mut *connection).await.map_err(database_error)?;
    let changed = if plan.fence.previous_sequence == 0 {
        sqlx::query(
            "INSERT INTO issuance_service.external_observation_heads \
             (organization_id, source_id, binding_id, sequence, receipt_id) VALUES ($1,$2,$3,$4,$5) \
             ON CONFLICT (organization_id, source_id, binding_id) DO NOTHING",
        ).bind(&plan.organization_id).bind(&plan.source_id).bind(&input.binding_id)
            .bind(input.sequence as i64).bind(receipt_id)
            .execute(&mut *connection).await.map_err(database_error)?.rows_affected()
    } else {
        sqlx::query(
            "UPDATE issuance_service.external_observation_heads SET sequence = $4, receipt_id = $5 \
             WHERE organization_id = $1 AND source_id = $2 AND binding_id = $3 AND sequence = $6",
        ).bind(&plan.organization_id).bind(&plan.source_id).bind(&input.binding_id)
            .bind(input.sequence as i64).bind(receipt_id).bind(plan.fence.previous_sequence as i64)
            .execute(&mut *connection).await.map_err(database_error)?.rows_affected()
    };
    if changed != 1 {
        return Err(JournalError::Conflict);
    }
    sqlx::query(
        "INSERT INTO issuance_service.external_observation_audit (receipt_id, event_type, received_at_ms) \
         VALUES ($1, 'external_observation_admitted', $2)",
    ).bind(receipt_id).bind(plan.received_at_ms as i64)
        .execute(connection).await.map_err(database_error)?;
    Ok(ReceiptAcknowledgment {
        receipt_id: receipt_id.to_string(),
        replayed: false,
    })
}
