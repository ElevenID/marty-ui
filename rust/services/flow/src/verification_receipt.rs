//! Flow-owned evidence of atomic finalization, separate from policy authority.
//!
//! Preparation retains correspondence only. The repository exposes the sealed
//! result after its transaction succeeds; deserializing a receipt never proves
//! persistence, authenticates an owner channel, or grants issuance authority.

use chrono::{DateTime, SecondsFormat, Utc};
use marty_oid4vp_contract::{
    build_verification_callback_payload, digest_domain_json, flow_callback_payload_digest,
    flow_result_digest, FlowVerificationReceiptContractVersion, FlowVerificationReceiptV1,
    FLOW_REQUEST_BINDING_DIGEST_DOMAIN, VERIFICATION_RECEIPT,
};
use marty_verification::flow::FlowInstanceStatus;
use mmf_messaging::Message;
use mmf_push::payload_digest;
use serde_json::Value;

use crate::{
    presentation_request::load_frozen_flow_presentation_request,
    verification_submission::sha256_hex, FlowInstanceRecord, PreparedVerificationFinalization,
    RepositoryError,
};

const PREPARED_INSTANCE_DOMAIN: &str = "marty.flow/prepared-verification-instance/v1";
const PREPARED_CALLBACK_DOMAIN: &str = "marty.flow/prepared-verification-callback/v1";

#[derive(Clone, Debug)]
pub(crate) struct PreparedVerificationReceipt {
    request_binding_digest: String,
    prepared_instance_digest: String,
    prepared_callback_digest: Option<String>,
    nonce_digest: String,
    submission_digest: String,
    replay_expires_at_ms: u64,
    policy_evaluated_at_epoch_micros: i64,
}

/// A terminal result returned only after repository finalization succeeds.
/// It is a Flow persistence fact, not canonical OID4VP or issuance authority.
///
/// ```compile_fail
/// let _: marty_flow::CommittedVerificationFinalization =
///     serde_json::from_str("{}").unwrap();
/// ```
#[derive(Clone, Debug)]
pub struct CommittedVerificationFinalization {
    instance: FlowInstanceRecord,
    receipt: FlowVerificationReceiptV1,
}

impl CommittedVerificationFinalization {
    #[must_use]
    pub fn instance(&self) -> &FlowInstanceRecord {
        &self.instance
    }

    #[must_use]
    pub fn receipt(&self) -> &FlowVerificationReceiptV1 {
        &self.receipt
    }

    pub(crate) fn after_commit(
        instance: FlowInstanceRecord,
        receipt: FlowVerificationReceiptV1,
    ) -> Self {
        Self { instance, receipt }
    }
}

pub(crate) fn canonical_policy_timestamp(value: &str) -> Result<String, RepositoryError> {
    let timestamp = DateTime::parse_from_rfc3339(value).map_err(|_| invalid())?;
    if timestamp.timestamp_micros() <= 0 || timestamp.timestamp_subsec_nanos() % 1_000 != 0 {
        return Err(invalid());
    }
    Ok(timestamp
        .with_timezone(&Utc)
        .to_rfc3339_opts(SecondsFormat::Micros, true))
}

impl PreparedVerificationReceipt {
    pub(crate) fn prepare(
        finalization: &PreparedVerificationFinalization,
    ) -> Result<Self, RepositoryError> {
        let expected = &finalization.expected_instance;
        let instance = &finalization.instance;
        let frozen = load_frozen_flow_presentation_request(expected).map_err(|_| invalid())?;
        let result = instance
            .result
            .as_ref()
            .and_then(Value::as_object)
            .ok_or_else(invalid)?;
        let policy = serde_json::from_value::<marty_oid4vp_contract::FrozenPolicyIdentity>(
            result.get("policy_revision").cloned().ok_or_else(invalid)?,
        )
        .map_err(|_| invalid())?;
        let evaluated_at = result
            .get("evaluation_timestamp")
            .and_then(Value::as_str)
            .ok_or_else(invalid)?;
        let normalized = canonical_policy_timestamp(evaluated_at)?;
        if normalized != evaluated_at
            || !matches!(
                instance.status,
                FlowInstanceStatus::Completed | FlowInstanceStatus::Failed
            )
            || instance.id != expected.id
            || instance.organization_id != expected.organization_id
            || instance.flow_definition_id != expected.flow_definition_id
            || policy != frozen.policy_revision
            || result.contains_key(VERIFICATION_RECEIPT)
            || result.get("submission_digest").and_then(Value::as_str)
                != Some(finalization.submission_digest.as_str())
            || sha256_hex(frozen.nonce.as_bytes()) != finalization.nonce_digest
        {
            return Err(invalid());
        }
        let payload = callback_payload(instance)?;
        if finalization.callback.as_ref().is_some_and(|callback| {
            callback.payload != payload
                || callback.metadata.message_id != instance.id
                || callback.metadata.tenant_id.as_deref() != Some(instance.organization_id.as_str())
        }) {
            return Err(invalid());
        }
        Ok(Self {
            request_binding_digest: digest_domain_json(
                FLOW_REQUEST_BINDING_DIGEST_DOMAIN,
                expected,
            )
            .map_err(|_| invalid())?,
            prepared_instance_digest: digest_domain_json(PREPARED_INSTANCE_DOMAIN, instance)
                .map_err(|_| invalid())?,
            prepared_callback_digest: finalization
                .callback
                .as_ref()
                .map(|callback| digest_domain_json(PREPARED_CALLBACK_DOMAIN, callback))
                .transpose()
                .map_err(|_| invalid())?,
            nonce_digest: finalization.nonce_digest.clone(),
            submission_digest: finalization.submission_digest.clone(),
            replay_expires_at_ms: finalization.replay_expires_at_ms,
            policy_evaluated_at_epoch_micros: DateTime::parse_from_rfc3339(&normalized)
                .map_err(|_| invalid())?
                .timestamp_micros(),
        })
    }

    pub(crate) fn validate_prepared(
        &self,
        finalization: &PreparedVerificationFinalization,
    ) -> Result<(), RepositoryError> {
        let observed = Self::prepare(finalization)?;
        if self.request_binding_digest != observed.request_binding_digest
            || self.prepared_instance_digest != observed.prepared_instance_digest
            || self.prepared_callback_digest != observed.prepared_callback_digest
            || self.nonce_digest != observed.nonce_digest
            || self.submission_digest != observed.submission_digest
            || self.replay_expires_at_ms != observed.replay_expires_at_ms
            || self.policy_evaluated_at_epoch_micros != observed.policy_evaluated_at_epoch_micros
        {
            return Err(invalid());
        }
        Ok(())
    }

    /// The timestamp is the database nonce-consumption observation inside the
    /// transaction. It is deliberately not described as PostgreSQL's COMMIT time.
    pub(crate) fn attach(
        &self,
        finalization: &PreparedVerificationFinalization,
        consumed_at: DateTime<Utc>,
    ) -> Result<
        (
            FlowInstanceRecord,
            Option<Message>,
            FlowVerificationReceiptV1,
        ),
        RepositoryError,
    > {
        self.validate_prepared(finalization)?;
        let mut instance = finalization.instance.clone();
        let result = instance.result.as_ref().ok_or_else(invalid)?;
        let policy =
            serde_json::from_value(result["policy_revision"].clone()).map_err(|_| invalid())?;
        let mut receipt = FlowVerificationReceiptV1 {
            contract: FlowVerificationReceiptContractVersion::V1,
            organization_id: instance.organization_id.clone(),
            flow_instance_id: instance.id.clone(),
            policy,
            request_binding_digest: self.request_binding_digest.clone(),
            submission_digest: self.submission_digest.clone(),
            nonce_digest: self.nonce_digest.clone(),
            result_digest: flow_result_digest(result).map_err(|_| invalid())?,
            callback_payload_digest: flow_callback_payload_digest(&callback_payload(&instance)?)
                .map_err(|_| invalid())?,
            policy_evaluated_at_epoch_micros: self.policy_evaluated_at_epoch_micros,
            nonce_consumed_at_epoch_micros: consumed_at.timestamp_micros(),
            nonce_retention_expires_at_epoch_micros: i64::try_from(self.replay_expires_at_ms)
                .ok()
                .and_then(|millis| millis.checked_mul(1_000))
                .ok_or_else(invalid)?,
            receipt_digest: String::new(),
        };
        receipt.receipt_digest = receipt.recompute_digest().map_err(|_| invalid())?;
        receipt.validate().map_err(|_| invalid())?;
        instance
            .result
            .as_mut()
            .and_then(Value::as_object_mut)
            .ok_or_else(invalid)?
            .insert(
                VERIFICATION_RECEIPT.into(),
                serde_json::to_value(&receipt).map_err(|_| invalid())?,
            );
        let callback = finalization
            .callback
            .clone()
            .map(|mut callback| -> Result<Message, RepositoryError> {
                callback.payload = callback_payload(&instance)?;
                Ok(callback)
            })
            .transpose()?;
        Ok((instance, callback, receipt))
    }
}

pub(crate) fn callback_payload(instance: &FlowInstanceRecord) -> Result<Value, RepositoryError> {
    let policy_id = instance.context["presentation_policy_id"]
        .as_str()
        .ok_or_else(invalid)?;
    build_verification_callback_payload(
        &instance.id,
        policy_id,
        instance.completed_at.map(|value| value.to_rfc3339()),
        instance
            .result
            .as_ref()
            .and_then(Value::as_object)
            .ok_or_else(invalid)?,
        payload_digest,
    )
    .map_err(|_| invalid())
}

pub(crate) fn invalid() -> RepositoryError {
    RepositoryError::InvalidVerificationReceipt
}

/// Generic writers cannot introduce owner-produced receipt fields. Genuine
/// terminal receipts are read back unchanged or written by finalization only.
pub(crate) fn reject_supplied_receipt(
    context: &Value,
    result: Option<&Value>,
) -> Result<(), RepositoryError> {
    if context.get(VERIFICATION_RECEIPT).is_some()
        || result.is_some_and(|value| value.get(VERIFICATION_RECEIPT).is_some())
    {
        return Err(invalid());
    }
    Ok(())
}
