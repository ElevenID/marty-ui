//! Bounded projections of Flow's durable verification finalization.
//!
//! A valid digest proves correspondence only. This deserializable value is not
//! authenticated OID4VP evidence, proof of a database commit, or issuance
//! authority. Only Flow's repository can establish that the referenced nonce,
//! result and callback were committed together.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::{
    digest_domain_json, FrozenPolicyIdentity, Oid4vpContractError, MAX_EVIDENCE_PROJECTION_BYTES,
    MAX_IDENTIFIER_BYTES,
};

pub const VERIFICATION_RECEIPT: &str = "verification_receipt";
pub const MAX_FLOW_VERIFICATION_RECEIPT_BYTES: usize = 4_096;
pub const FLOW_REQUEST_BINDING_DIGEST_DOMAIN: &str = "marty.flow/verification-request-binding/v1";
pub const FLOW_RESULT_DIGEST_DOMAIN: &str = "marty.flow/verification-result/v1";
pub const FLOW_CALLBACK_PAYLOAD_DIGEST_DOMAIN: &str = "marty.flow/verification-callback-payload/v1";
pub const FLOW_VERIFICATION_RECEIPT_DIGEST_DOMAIN: &str = "marty.flow/verification-receipt/v1";

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub enum FlowVerificationReceiptContractVersion {
    #[default]
    #[serde(rename = "marty.flow-verification-receipt/v1")]
    V1,
}

/// Untrusted wire projection of an owner-persisted finalization receipt.
///
/// Policy observation and nonce consumption retain separate clocks. The latter
/// is the database timestamp recorded inside the successful transaction, not
/// the exact instant that COMMIT completed. Historical readback remains valid
/// after nonce-retention expiry; a receipt is a persistence fact, not a live
/// authorization lease.
///
/// Deserialization and digest validation never promote this value:
///
/// ```compile_fail
/// let receipt: marty_oid4vp_contract::FlowVerificationReceiptV1 =
///     serde_json::from_str("{}").unwrap();
/// let _: marty_oid4vp_contract::AuthenticatedOid4vpEvidenceV1 = receipt.into();
/// ```
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FlowVerificationReceiptV1 {
    pub contract: FlowVerificationReceiptContractVersion,
    pub organization_id: String,
    pub flow_instance_id: String,
    pub policy: FrozenPolicyIdentity,
    pub request_binding_digest: String,
    /// Existing Flow submission digest, as 64 lower-case hexadecimal bytes.
    pub submission_digest: String,
    /// Exact key used in Flow's nonce-consumption table, in the same format.
    pub nonce_digest: String,
    pub result_digest: String,
    pub callback_payload_digest: String,
    pub policy_evaluated_at_epoch_micros: i64,
    pub nonce_consumed_at_epoch_micros: i64,
    pub nonce_retention_expires_at_epoch_micros: i64,
    pub receipt_digest: String,
}

#[derive(Serialize)]
struct ReceiptDigestBasis<'a> {
    contract: FlowVerificationReceiptContractVersion,
    organization_id: &'a str,
    flow_instance_id: &'a str,
    policy: &'a FrozenPolicyIdentity,
    request_binding_digest: &'a str,
    submission_digest: &'a str,
    nonce_digest: &'a str,
    result_digest: &'a str,
    callback_payload_digest: &'a str,
    policy_evaluated_at_epoch_micros: i64,
    nonce_consumed_at_epoch_micros: i64,
    nonce_retention_expires_at_epoch_micros: i64,
}

impl FlowVerificationReceiptV1 {
    /// Hash the complete bounded body, excluding only `receipt_digest`.
    /// Recomputing this public correspondence hash authenticates no authority.
    pub fn recompute_digest(&self) -> Result<String, Oid4vpContractError> {
        self.validate_body()?;
        digest_domain_json(
            FLOW_VERIFICATION_RECEIPT_DIGEST_DOMAIN,
            &ReceiptDigestBasis {
                contract: self.contract,
                organization_id: &self.organization_id,
                flow_instance_id: &self.flow_instance_id,
                policy: &self.policy,
                request_binding_digest: &self.request_binding_digest,
                submission_digest: &self.submission_digest,
                nonce_digest: &self.nonce_digest,
                result_digest: &self.result_digest,
                callback_payload_digest: &self.callback_payload_digest,
                policy_evaluated_at_epoch_micros: self.policy_evaluated_at_epoch_micros,
                nonce_consumed_at_epoch_micros: self.nonce_consumed_at_epoch_micros,
                nonce_retention_expires_at_epoch_micros: self
                    .nonce_retention_expires_at_epoch_micros,
            },
        )
    }

    pub fn validate(&self) -> Result<(), Oid4vpContractError> {
        self.validate_body()?;
        require_digest(&self.receipt_digest, "flow_receipt.receipt_digest")?;
        let encoded = serde_json::to_vec(self).map_err(|_| Oid4vpContractError::Serialization)?;
        if encoded.len() > MAX_FLOW_VERIFICATION_RECEIPT_BYTES {
            return Err(Oid4vpContractError::SizeLimit(VERIFICATION_RECEIPT));
        }
        if self.receipt_digest != self.recompute_digest()? {
            return Err(Oid4vpContractError::BindingMismatch);
        }
        Ok(())
    }

    /// Correspondence with the full stored result before adding its receipt.
    /// Callback consumers do not possess this private basis and must not claim
    /// to have performed this check merely from the callback projection.
    pub fn validate_result(&self, result: &Value) -> Result<(), Oid4vpContractError> {
        self.validate()?;
        let object = result.as_object().ok_or(Oid4vpContractError::InvalidField(
            "flow_verification_result",
        ))?;
        if object.get("submission_digest").and_then(Value::as_str)
            != Some(self.submission_digest.as_str())
            || object.get("policy_revision")
                != Some(
                    &serde_json::to_value(&self.policy)
                        .map_err(|_| Oid4vpContractError::Serialization)?,
                )
            || self.result_digest != flow_result_digest(result)?
        {
            return Err(Oid4vpContractError::DecisionMismatch);
        }
        Ok(())
    }

    /// Bind the receipt to the exact minimized callback and policy identity.
    /// Its tenant must additionally match the callback consumer's owner scope.
    /// The existing signed callback authenticates delivery; this hash does not.
    pub fn validate_callback(&self, payload: &Value) -> Result<(), Oid4vpContractError> {
        self.validate()?;
        if payload
            .get(VERIFICATION_RECEIPT)
            .is_some_and(|receipt| serde_json::to_value(self).as_ref().ok() != Some(receipt))
        {
            return Err(Oid4vpContractError::BindingMismatch);
        }
        let basis = callback_basis(payload)?;
        if basis.get("flow_instance_id").and_then(Value::as_str)
            != Some(self.flow_instance_id.as_str())
            || basis.get("presentation_policy_id").and_then(Value::as_str)
                != Some(self.policy.id.as_str())
            || basis.get("policy_revision")
                != Some(
                    &serde_json::to_value(&self.policy)
                        .map_err(|_| Oid4vpContractError::Serialization)?,
                )
            || self.callback_payload_digest
                != digest_domain_json(FLOW_CALLBACK_PAYLOAD_DIGEST_DOMAIN, &basis)?
        {
            return Err(Oid4vpContractError::DecisionMismatch);
        }
        Ok(())
    }

    fn validate_body(&self) -> Result<(), Oid4vpContractError> {
        require_identifier(&self.organization_id, "flow_receipt.organization_id")?;
        require_identifier(&self.flow_instance_id, "flow_receipt.flow_instance_id")?;
        self.policy.validate()?;
        require_digest(
            &self.request_binding_digest,
            "flow_receipt.request_binding_digest",
        )?;
        require_raw_digest(&self.submission_digest, "flow_receipt.submission_digest")?;
        require_raw_digest(&self.nonce_digest, "flow_receipt.nonce_digest")?;
        require_digest(&self.result_digest, "flow_receipt.result_digest")?;
        require_digest(
            &self.callback_payload_digest,
            "flow_receipt.callback_payload_digest",
        )?;
        if self.policy_evaluated_at_epoch_micros <= 0
            || self.policy_evaluated_at_epoch_micros > self.nonce_consumed_at_epoch_micros
            || self.nonce_consumed_at_epoch_micros >= self.nonce_retention_expires_at_epoch_micros
        {
            return Err(Oid4vpContractError::InvalidLifetime);
        }
        Ok(())
    }
}

/// Digest the entire terminal result before adding its receipt. Refusing the
/// receipt-bearing object makes the non-recursive digest boundary explicit.
pub fn flow_result_digest(result: &Value) -> Result<String, Oid4vpContractError> {
    let object = bounded_object(result, "flow_verification_result")?;
    if object.contains_key(VERIFICATION_RECEIPT) {
        return Err(Oid4vpContractError::InvalidField(
            "flow_verification_result",
        ));
    }
    digest_domain_json(FLOW_RESULT_DIGEST_DOMAIN, object)
}

/// Digest the legacy callback basis. Receipt and decision hashes are excluded
/// so Flow can add the receipt before calculating the final decision digest.
pub fn flow_callback_payload_digest(payload: &Value) -> Result<String, Oid4vpContractError> {
    digest_domain_json(
        FLOW_CALLBACK_PAYLOAD_DIGEST_DOMAIN,
        &callback_basis(payload)?,
    )
}

fn callback_basis(payload: &Value) -> Result<Map<String, Value>, Oid4vpContractError> {
    let object = payload
        .as_object()
        .ok_or(Oid4vpContractError::InvalidField(
            "flow_verification_callback",
        ))?;
    const KEYS: [&str; 9] = [
        "flow_instance_id",
        "result",
        "decision",
        "decision_reason",
        "verified_claims",
        "presentation_policy_id",
        "policy_revision",
        "completed_at",
        "evidence_digest",
    ];
    if object.keys().any(|key| {
        !KEYS.contains(&key.as_str()) && key != VERIFICATION_RECEIPT && key != "decision_digest"
    }) {
        return Err(Oid4vpContractError::InvalidField(
            "flow_verification_callback",
        ));
    }
    // Bound the same basis before and after adding a receipt. The envelope's
    // optional receipt must not push an otherwise valid basis over its limit.
    // Clone only included fields, never a caller-supplied excluded extension.
    let basis = KEYS
        .into_iter()
        .map(|key| {
            object
                .get(key)
                .cloned()
                .map(|value| (key.into(), value))
                .ok_or(Oid4vpContractError::InvalidField(
                    "flow_verification_callback",
                ))
        })
        .collect::<Result<Map<String, Value>, _>>()?;
    if serde_json::to_vec(&basis)
        .map_err(|_| Oid4vpContractError::Serialization)?
        .len()
        > MAX_EVIDENCE_PROJECTION_BYTES
    {
        return Err(Oid4vpContractError::SizeLimit("flow_verification_callback"));
    }
    if !basis["verified_claims"].is_object()
        || !(basis["decision_reason"].is_null() || basis["decision_reason"].is_string())
        || !(basis["completed_at"].is_null() || basis["completed_at"].is_string())
    {
        return Err(Oid4vpContractError::InvalidField(
            "flow_verification_callback",
        ));
    }
    for field in [
        "flow_instance_id",
        "result",
        "decision",
        "presentation_policy_id",
    ] {
        require_identifier(
            basis[field]
                .as_str()
                .ok_or(Oid4vpContractError::InvalidField(
                    "flow_verification_callback",
                ))?,
            "flow_verification_callback",
        )?;
    }
    let policy: FrozenPolicyIdentity = serde_json::from_value(basis["policy_revision"].clone())
        .map_err(|_| Oid4vpContractError::InvalidField("flow_verification_callback.policy"))?;
    policy.validate()?;
    if basis["presentation_policy_id"].as_str() != Some(policy.id.as_str()) {
        return Err(Oid4vpContractError::DecisionMismatch);
    }
    require_raw_digest(
        basis["evidence_digest"]
            .as_str()
            .ok_or(Oid4vpContractError::InvalidDigest(
                "flow_callback.evidence_digest",
            ))?,
        "flow_callback.evidence_digest",
    )?;
    Ok(basis)
}

fn bounded_object<'a>(
    value: &'a Value,
    field: &'static str,
) -> Result<&'a Map<String, Value>, Oid4vpContractError> {
    let object = value
        .as_object()
        .ok_or(Oid4vpContractError::InvalidField(field))?;
    if serde_json::to_vec(value)
        .map_err(|_| Oid4vpContractError::Serialization)?
        .len()
        > MAX_EVIDENCE_PROJECTION_BYTES
    {
        return Err(Oid4vpContractError::SizeLimit(field));
    }
    Ok(object)
}

fn require_identifier(value: &str, field: &'static str) -> Result<(), Oid4vpContractError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(Oid4vpContractError::InvalidField(field));
    }
    Ok(())
}

fn require_digest(value: &str, field: &'static str) -> Result<(), Oid4vpContractError> {
    let digest = value
        .strip_prefix("sha256:")
        .ok_or(Oid4vpContractError::InvalidDigest(field))?;
    require_raw_digest(digest, field)
}

fn require_raw_digest(value: &str, field: &'static str) -> Result<(), Oid4vpContractError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Oid4vpContractError::InvalidDigest(field));
    }
    Ok(())
}
