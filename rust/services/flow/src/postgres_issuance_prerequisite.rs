//! Owner-only persistence for the issuance intent bound before verification.

use chrono::{DateTime, Utc};
use marty_oid4vp_contract::issuance_prerequisite::{
    IssuanceIntentBindingV1, IssuancePrerequisiteEvidenceResponseV1,
    ISSUANCE_PREREQUISITE_EVIDENCE_RESPONSE_V1,
};
use sqlx::{Postgres, Transaction};

use super::{instance_from_row, storage, PostgresFlowRepository};
use crate::{
    issuance_prerequisite::{conflict, validate_bound_instance},
    FlowInstanceRecord, RepositoryError,
};

impl PostgresFlowRepository {
    pub(crate) async fn issuance_prerequisite_clock(
        &self,
    ) -> Result<DateTime<Utc>, RepositoryError> {
        sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&self.pool)
            .await
            .map_err(storage)
    }

    pub(crate) async fn issuance_prerequisite_instance(
        &self,
        intent: &IssuanceIntentBindingV1,
    ) -> Result<Option<FlowInstanceRecord>, RepositoryError> {
        intent.validate().map_err(|_| conflict())?;
        let instance = self.instance(&intent.flow_instance_id).await?;
        if let Some(instance) = &instance {
            validate_bound_instance(instance, intent)?;
        }
        Ok(instance)
    }

    /// Only the authenticated owner-start adapter can create the private
    /// binding. Generic instance inserts cannot use this path.
    pub(crate) async fn save_issuance_prerequisite_start(
        &self,
        instance: &FlowInstanceRecord,
        intent: &IssuanceIntentBindingV1,
    ) -> Result<bool, RepositoryError> {
        self.save_started_instance_with_intent(instance, None, None, None, Some(intent))
            .await
    }

    pub(crate) async fn issuance_prerequisite_evidence(
        &self,
        intent: &IssuanceIntentBindingV1,
    ) -> Result<Option<IssuancePrerequisiteEvidenceResponseV1>, RepositoryError> {
        intent
            .validate()
            .map_err(|error| contract_rejected("intent_structure", &error))?;
        // Acquire the repository's sealed evidence capability. A deserialized
        // projection, public result digest, or a caller receipt cannot enter.
        let acquired = self
            .managed_evidence(&intent.organization_id, &intent.flow_instance_id)
            .await
            .map_err(|error| evidence_rejected("historical_recovery", error))?;
        let mut transaction = self.pool.begin().await.map_err(storage)?;
        let row = sqlx::query(
            "SELECT * FROM flow_service.flow_instances \
             WHERE id=$1 AND organization_id=$2 FOR SHARE",
        )
        .bind(&intent.flow_instance_id)
        .bind(&intent.organization_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(storage)?;
        let Some(row) = row else {
            transaction.rollback().await.map_err(storage)?;
            return Ok(None);
        };
        let stored =
            instance_from_row(&row).map_err(|error| evidence_rejected("stored_instance", error))?;
        validate_bound_instance(&stored, intent)
            .map_err(|error| evidence_rejected("bound_instance", error))?;
        // Observe a fresh clock after obtaining the row lock. Transaction-start
        // time is not a freshness check when another writer held that lock.
        let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *transaction)
            .await
            .map_err(storage)?;
        intent
            .validate_at(now.timestamp_micros())
            .map_err(|error| contract_rejected("intent_freshness", &error))?;
        if stored.expires_at.is_none_or(|expiry| now >= expiry) {
            return Err(evidence_rejected("flow_deadline", conflict()));
        }
        let Some(acquired) = acquired else {
            transaction.rollback().await.map_err(storage)?;
            return Ok(None);
        };
        let current = crate::canonical_evidence::validate_owner_record(&stored)
            .map_err(|error| evidence_rejected("current_record", error))?
            .ok_or_else(|| evidence_rejected("current_record_missing", conflict()))?
            .after_owner_persistence();
        if current.projection() != acquired.projection() {
            return Err(evidence_rejected(
                "recovered_projection_changed",
                conflict(),
            ));
        }
        let response = IssuancePrerequisiteEvidenceResponseV1 {
            contract: ISSUANCE_PREREQUISITE_EVIDENCE_RESPONSE_V1.into(),
            intent: intent.clone(),
            evidence: acquired.projection().clone(),
            observed_at_epoch_micros: now.timestamp_micros(),
        };
        response
            .validate_for_intent(intent, now.timestamp_micros())
            .map_err(|error| contract_rejected("response_correspondence", &error))?;
        transaction.commit().await.map_err(storage)?;
        Ok(Some(response))
    }
}

// Report only fixed stages and contract enum variants. Never emit stored
// context, evidence, identifiers, credentials, owner headers or request values.
fn evidence_rejected(stage: &'static str, error: RepositoryError) -> RepositoryError {
    tracing::debug!(
        target: "marty_flow::postgres_issuance_prerequisite",
        stage,
        "issuance prerequisite owner evidence rejected"
    );
    error
}

fn contract_rejected(
    stage: &'static str,
    error: &marty_oid4vp_contract::Oid4vpContractError,
) -> RepositoryError {
    tracing::debug!(
        target: "marty_flow::postgres_issuance_prerequisite",
        stage,
        contract_error = ?error,
        "issuance prerequisite owner evidence rejected"
    );
    conflict()
}

pub(super) async fn admit_start(
    transaction: &mut Transaction<'_, Postgres>,
    instance: &FlowInstanceRecord,
    intent: &IssuanceIntentBindingV1,
) -> Result<bool, RepositoryError> {
    validate_bound_instance(instance, intent)?;
    if instance.status != marty_verification::flow::FlowInstanceStatus::AwaitingWallet
        || instance.result.is_some()
        || instance.completed_at.is_some()
    {
        return Err(conflict());
    }
    // Serialize the transaction identity, not just the proposed Flow ID. A
    // retry with a changed intent/Flow ID must never create a second request.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(
            serde_json::to_string(&(
                "marty:issuance-prerequisite:v1",
                &intent.organization_id,
                &intent.transaction_id,
            ))
            .map_err(|_| conflict())?,
        )
        .execute(&mut **transaction)
        .await
        .map_err(storage)?;
    let rows = sqlx::query(
        "SELECT * FROM flow_service.flow_instances WHERE id=$1 OR \
         (organization_id=$2 AND \
          context::jsonb->'_marty_issuance_prerequisite_v1'->>'transaction_id'=$3) FOR UPDATE",
    )
    .bind(&intent.flow_instance_id)
    .bind(&intent.organization_id)
    .bind(&intent.transaction_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(storage)?;
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **transaction)
        .await
        .map_err(storage)?;
    intent
        .validate_at(now.timestamp_micros())
        .map_err(|_| conflict())?;
    if instance.expires_at.is_none_or(|expiry| now >= expiry) {
        return Err(conflict());
    }
    match rows.as_slice() {
        [] => Ok(true),
        [row] => {
            validate_bound_instance(&instance_from_row(row)?, intent)?;
            Ok(false)
        }
        _ => Err(conflict()),
    }
}
