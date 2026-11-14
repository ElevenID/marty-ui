//! Bounded correspondence for a Policy-owned finalization deadline.
//!
//! This wire projection is not canonical authenticated evidence or issuance
//! authority. Only an authenticated Policy channel can establish its producer.
//! Its deadline bounds previously observed facts; it does not lock the owners.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    digest_domain_json, FrozenPolicyIdentity, Oid4vpContractError, Oid4vpEvaluationTransportV1,
    MAX_EVIDENCE_PROJECTION_BYTES, MAX_FROZEN_REQUEST_BYTES, MAX_IDENTIFIER_BYTES, MAX_TOKEN_BYTES,
    MAX_TRANSPORT_CLIENT_ID_BYTES, MIN_NONCE_BYTES,
};

pub const POLICY_EVALUATION_VALIDITY: &str = "evaluation_validity";
pub const MAX_POLICY_EVALUATION_VALIDITY_BYTES: usize = 4_096;
pub const MAX_POLICY_EVALUATION_VALIDITY_MICROS: i64 = 60_000_000;

/// Exact inputs shared by Policy's producer and Flow's authenticated adapter.
/// Raw credential material is used only to compute the correspondence digest.
#[derive(Serialize)]
pub struct PolicyEvaluationValidityRequest<'a> {
    pub organization_id: &'a str,
    pub policy: &'a FrozenPolicyIdentity,
    pub nonce: &'a str,
    pub audience: &'a str,
    pub vp_token: &'a str,
    pub trust_profile_id: Option<&'a str>,
    pub context: &'a Value,
    pub oid4vp_transport: &'a Oid4vpEvaluationTransportV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum PolicyEvaluationValidityContractVersion {
    #[serde(rename = "marty.policy-evaluation-validity/v1")]
    V1,
}

/// Untrusted wire projection. Parsing, binding and checking its clock never
/// authenticate a caller or promote it to canonical OID4VP evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyEvaluationValidityV1 {
    pub contract: PolicyEvaluationValidityContractVersion,
    pub organization_id: String,
    pub policy: FrozenPolicyIdentity,
    pub request_binding_digest: String,
    pub result_binding_digest: String,
    pub evaluated_at_epoch_micros: i64,
    /// Exclusive, conservative deadline for the managed positive result.
    pub valid_until_epoch_micros: i64,
}

impl PolicyEvaluationValidityV1 {
    pub fn bind(
        request: &PolicyEvaluationValidityRequest<'_>,
        result: &Value,
        evaluated_at_epoch_micros: i64,
        valid_until_epoch_micros: i64,
    ) -> Result<Self, Oid4vpContractError> {
        let value = Self {
            contract: PolicyEvaluationValidityContractVersion::V1,
            organization_id: request.organization_id.into(),
            policy: request.policy.clone(),
            request_binding_digest: request_digest(request)?,
            result_binding_digest: result_digest(result)?,
            evaluated_at_epoch_micros,
            valid_until_epoch_micros,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn from_json(value: &str) -> Result<Self, Oid4vpContractError> {
        if value.len() > MAX_POLICY_EVALUATION_VALIDITY_BYTES {
            return Err(Oid4vpContractError::SizeLimit(POLICY_EVALUATION_VALIDITY));
        }
        let parsed: Self =
            serde_json::from_str(value).map_err(|_| Oid4vpContractError::Deserialization)?;
        parsed.validate()?;
        Ok(parsed)
    }

    pub fn validate(&self) -> Result<(), Oid4vpContractError> {
        require_text(&self.organization_id, MAX_IDENTIFIER_BYTES)?;
        self.policy.validate()?;
        require_digest(&self.request_binding_digest)?;
        require_digest(&self.result_binding_digest)?;
        let lifetime = self
            .valid_until_epoch_micros
            .checked_sub(self.evaluated_at_epoch_micros)
            .ok_or(Oid4vpContractError::InvalidLifetime)?;
        if self.evaluated_at_epoch_micros <= 0
            || !(1..=MAX_POLICY_EVALUATION_VALIDITY_MICROS).contains(&lifetime)
        {
            return Err(Oid4vpContractError::InvalidLifetime);
        }
        require_size(self, MAX_POLICY_EVALUATION_VALIDITY_BYTES)
    }

    pub fn validate_at(&self, now_epoch_micros: i64) -> Result<(), Oid4vpContractError> {
        self.validate()?;
        if now_epoch_micros < self.evaluated_at_epoch_micros
            || now_epoch_micros >= self.valid_until_epoch_micros
        {
            return Err(Oid4vpContractError::InvalidLifetime);
        }
        Ok(())
    }

    pub fn validate_for_request(
        &self,
        request: &PolicyEvaluationValidityRequest<'_>,
        result: &Value,
    ) -> Result<(), Oid4vpContractError> {
        self.validate()?;
        if self.organization_id != request.organization_id
            || self.policy != *request.policy
            || self.request_binding_digest != request_digest(request)?
            || self.result_binding_digest != result_digest(result)?
        {
            return Err(Oid4vpContractError::BindingMismatch);
        }
        Ok(())
    }
}

fn request_digest(
    request: &PolicyEvaluationValidityRequest<'_>,
) -> Result<String, Oid4vpContractError> {
    require_text(request.organization_id, MAX_IDENTIFIER_BYTES)?;
    request.policy.validate()?;
    require_text(request.nonce, MAX_TOKEN_BYTES)?;
    require_text(request.audience, MAX_TRANSPORT_CLIENT_ID_BYTES)?;
    require_text(request.vp_token, MAX_TOKEN_BYTES)?;
    if let Some(profile) = request.trust_profile_id {
        require_text(profile, MAX_IDENTIFIER_BYTES)?;
    }
    request.oid4vp_transport.validate_transport()?;
    require_size(request.context, MAX_FROZEN_REQUEST_BYTES)?;
    if request.nonce.len() < MIN_NONCE_BYTES
        || request.nonce != request.oid4vp_transport.request_nonce
        || request.audience != request.oid4vp_transport.verifier_client_id
        || !request.context.is_object()
        || request
            .oid4vp_transport
            .credential_authority
            .as_ref()
            .is_some_and(|authority| authority.organization_id != request.organization_id)
    {
        return Err(Oid4vpContractError::BindingMismatch);
    }
    digest_domain_json("marty.policy/evaluation-validity-request/v1", request)
}

fn result_digest(result: &Value) -> Result<String, Oid4vpContractError> {
    require_size(result, MAX_EVIDENCE_PROJECTION_BYTES)?;
    if result["result"] != "passed"
        || result["decision"] != "allow"
        || !result["verified_claims"].is_object()
        || !result["credential_results"].is_array()
        || !result["evaluation_timestamp"].is_string()
    {
        return Err(Oid4vpContractError::DecisionMismatch);
    }
    let reason = match result.get("decision_reason") {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) if value.trim().is_empty() => None,
        Some(Value::String(value)) => Some(value.as_str()),
        _ => return Err(Oid4vpContractError::DecisionMismatch),
    };
    // These are the complete decision fields transported by the existing gRPC
    // response and retained by Flow. Top-level warnings/error codes are not
    // transported; per-credential diagnostics remain bound in the full rows.
    digest_domain_json(
        "marty.policy/evaluation-validity-result/v1",
        &json!({
            "result": result["result"],
            "decision": result["decision"],
            "decision_reason": reason,
            "verified_claims": result["verified_claims"],
            "credential_results": result["credential_results"],
            "evaluation_timestamp": result["evaluation_timestamp"],
        }),
    )
}

fn require_text(value: &str, maximum: usize) -> Result<(), Oid4vpContractError> {
    if value.is_empty()
        || value.len() > maximum
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(Oid4vpContractError::InvalidField(
            POLICY_EVALUATION_VALIDITY,
        ));
    }
    Ok(())
}

fn require_digest(value: &str) -> Result<(), Oid4vpContractError> {
    if value.strip_prefix("sha256:").is_none_or(|digest| {
        digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }) {
        return Err(Oid4vpContractError::InvalidDigest(
            POLICY_EVALUATION_VALIDITY,
        ));
    }
    Ok(())
}

fn require_size<T: Serialize>(value: &T, maximum: usize) -> Result<(), Oid4vpContractError> {
    if serde_json::to_vec(value)
        .map_err(|_| Oid4vpContractError::Serialization)?
        .len()
        > maximum
    {
        return Err(Oid4vpContractError::SizeLimit(POLICY_EVALUATION_VALIDITY));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{digest_query_document, QueryKind};

    #[test]
    fn validity_binds_request_context_result_and_exact_exclusive_clock() {
        let policy = FrozenPolicyIdentity {
            id: "policy-1".into(),
            version: 1,
            content_digest: format!("sha256:{}", "1".repeat(64)),
        };
        let nonce = "validity-test-request-nonce-at-least-32-bytes";
        let query = json!({"credentials":[{"id":"member", "format":"dc+sd-jwt"}]});
        let transport = Oid4vpEvaluationTransportV1 {
            credential_authority: None,
            query_kind: QueryKind::Dcql,
            query_digest: digest_query_document(&query).unwrap(),
            query_document: query,
            presentation_submission: None,
            vp_token_raw: json!({"member":["header.payload.signature"]}).to_string(),
            verifier_client_id: "https://verifier.example".into(),
            request_nonce: nonce.into(),
        };
        let context = json!({"oid4vp_verifier_context":true, "replay_check_verified":true});
        let mut request = PolicyEvaluationValidityRequest {
            organization_id: "org-1",
            policy: &policy,
            nonce,
            audience: "https://verifier.example",
            vp_token: "header.payload.signature",
            trust_profile_id: Some("trust-1"),
            context: &context,
            oid4vp_transport: &transport,
        };
        let result = json!({
            "result":"passed", "decision":"allow", "decision_reason":"accepted",
            "verified_claims":{"member":true}, "credential_results":[{"signature_valid":true}],
            "evaluation_timestamp":"2026-11-14T00:00:00Z"
        });
        let validity =
            PolicyEvaluationValidityV1::bind(&request, &result, 1_000_000, 1_250_001).unwrap();
        validity.validate_for_request(&request, &result).unwrap();
        validity.validate_at(1_250_000).unwrap();
        assert!(validity.validate_at(999_999).is_err());
        assert!(validity.validate_at(1_250_001).is_err());
        request.organization_id = "org-2";
        assert!(validity.validate_for_request(&request, &result).is_err());
        request.organization_id = "org-1";
        request.trust_profile_id = Some("trust-2");
        assert!(validity.validate_for_request(&request, &result).is_err());
        request.trust_profile_id = Some("trust-1");
        let changed_context =
            json!({"oid4vp_verifier_context":true, "replay_check_verified":false});
        request.context = &changed_context;
        assert!(validity.validate_for_request(&request, &result).is_err());
        request.context = &context;
        for (key, value) in [
            ("verified_claims", json!({"member":false})),
            ("credential_results", json!([{"signature_valid":false}])),
            ("decision_reason", json!("different")),
            ("evaluation_timestamp", json!("2026-11-14T00:00:01Z")),
        ] {
            let mut changed = result.clone();
            changed[key] = value;
            assert!(
                validity.validate_for_request(&request, &changed).is_err(),
                "{key}"
            );
        }
        let encoded = serde_json::to_string(&validity).unwrap();
        assert_eq!(
            PolicyEvaluationValidityV1::from_json(&encoded).unwrap(),
            validity
        );
        let mut malformed = serde_json::to_value(&validity).unwrap();
        malformed["unexpected"] = json!(true);
        assert!(PolicyEvaluationValidityV1::from_json(&malformed.to_string()).is_err());
        let duplicate = encoded.replacen("{", "{\"organization_id\":\"org-1\",", 1);
        assert!(PolicyEvaluationValidityV1::from_json(&duplicate).is_err());
        assert!(PolicyEvaluationValidityV1::bind(&request, &result, 1, 60_000_002).is_err());
    }
}
