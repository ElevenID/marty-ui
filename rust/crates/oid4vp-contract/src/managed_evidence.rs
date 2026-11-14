//! Managed-only historical evidence projections. These DTOs never authenticate
//! their producer, prove a commit, or authorize issuance. The Policy and Flow
//! owners retain those capabilities outside this dependency-light contract.
//!
//! V1 contracts and digests remain unchanged. In particular this module does
//! not reinterpret a Flow request binding as a FrozenOid4vpRequestV1 digest.

use std::collections::{BTreeMap, BTreeSet};

use serde::{de, Deserialize, Deserializer, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::{
    digest_audience, digest_domain_json, digest_nonce, digest_response_item,
    managed_status::{
        digest_sd_jwt_issuer_jws, ManagedCredentialStatusState, MANAGED_STATUS_AUTHORITY,
        MAX_MANAGED_STATUS_AGE_SECONDS,
    },
    trust_authority::CredentialTrustEvaluationResponseV1,
    EvidenceCheckOutcome, FlowVerificationReceiptV1, FrozenPolicyIdentity, Oid4vpContractError,
    PolicyEvaluationValidityRequest, PolicyEvaluationValidityV1, QueryKind,
    MAX_CLAIMS_PER_CREDENTIAL, MAX_CLAIM_VALUE_BYTES, MAX_EVIDENCE_PROJECTION_BYTES,
    MAX_IDENTIFIER_BYTES, MAX_JSON_DEPTH, MAX_TOKEN_BYTES, MAX_TRANSPORT_CLIENT_ID_BYTES,
};

pub const MANAGED_POLICY_EVIDENCE_V2: &str = "managed_policy_evidence";
pub const MANAGED_POLICY_EVIDENCE_DIGEST_V2: &str = "managed_policy_evidence_digest";
pub const MANAGED_POLICY_EVIDENCE_CONTRACT_V2: &str = "marty.managed-policy-evidence/v2";
pub const MANAGED_OID4VP_EVIDENCE_CONTRACT_V2: &str = "marty.managed-oid4vp-evidence/v2";
pub const MANAGED_POLICY_EVIDENCE_DIGEST_DOMAIN_V2: &str =
    "marty.oid4vp/managed-policy-evidence/v2";
pub const MANAGED_OID4VP_EVIDENCE_DIGEST_DOMAIN_V2: &str = "marty.oid4vp/managed-evidence/v2";
pub const MANAGED_STATE_DIGEST_DOMAIN_V2: &str = "marty.oid4vp/managed-state/v2";

/// The minimized projection of the actual Issuance-owned observation. Its
/// public digest is correspondence data, not an owner signature. Policy must
/// validate the complete authenticated owner response before producing this.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedStatusEvidenceProjectionV2 {
    pub authority: String,
    pub state: ManagedCredentialStatusState,
    pub request_binding_digest: String,
    pub issuer_jwt_digest: String,
    pub checked_at_epoch_seconds: i64,
    pub valid_until_epoch_seconds: i64,
    pub evidence_digest: String,
}

/// A positive native Policy observation, without any assertion of durable
/// replay. The full envelope is internal owner data; public callbacks must not
/// expose it. The native result retains real claim-constraint outcomes/counts.
#[derive(Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedPolicyEvidenceProjectionV2 {
    pub contract: String,
    pub organization_id: String,
    pub policy: FrozenPolicyIdentity,
    pub query_id: String,
    pub query_digest: String,
    pub response_token_digest: String,
    pub nonce_digest: String,
    pub audience_digest: String,
    pub credential_template_id: String,
    pub issuer_id: String,
    pub vct: String,
    pub issuer_algorithm: String,
    pub issuer_scoped_subject_digest: String,
    pub holder_key_thumbprint: String,
    pub issuer_key_thumbprint: String,
    pub issuer_jwt_digest: String,
    pub issued_at_epoch_seconds: i64,
    pub valid_from_epoch_seconds: i64,
    pub expires_at_epoch_seconds: i64,
    pub selected_claims: BTreeMap<String, Value>,
    /// Exact Core result, before the legacy service projection. This remains a
    /// bounded, strictly validated DTO, never a substitute for native provenance.
    pub policy_result: Value,
    pub trust: CredentialTrustEvaluationResponseV1,
    pub status: ManagedStatusEvidenceProjectionV2,
    pub validity: PolicyEvaluationValidityV1,
    pub evidence_digest: String,
}

impl std::fmt::Debug for ManagedPolicyEvidenceProjectionV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagedPolicyEvidenceProjectionV2")
            .field("contract", &self.contract)
            .field("evidence_digest", &self.evidence_digest)
            .finish_non_exhaustive()
    }
}

/// Exact bindings obtained by Flow from its admitted row and emitted request.
/// The request_binding_digest is the existing Flow full-record digest. It is
/// deliberately distinct from the canonical nonce and Policy request digests.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedFlowRequestBindingV2 {
    pub organization_id: String,
    pub flow_instance_id: String,
    pub initiating_principal_id: String,
    pub policy: FrozenPolicyIdentity,
    pub query_id: String,
    pub query_digest: String,
    pub verifier_client_id: String,
    pub response_uri: String,
    pub nonce_digest: String,
    pub flow_nonce_digest: String,
    pub expected_state_digest: String,
    pub request_binding_digest: String,
    pub submission_digest: String,
    pub policy_request_binding_digest: String,
}

impl std::fmt::Debug for ManagedFlowRequestBindingV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagedFlowRequestBindingV2")
            .field("request_binding_digest", &self.request_binding_digest)
            .finish_non_exhaustive()
    }
}

/// Historical composition of a Policy observation and a Flow receipt. Only
/// the Flow owner can establish that these were actually committed together.
/// This public type is intentionally deserializable and carries no authority.
#[derive(Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedOid4vpEvidenceProjectionV2 {
    pub contract: String,
    pub request: ManagedFlowRequestBindingV2,
    pub policy_evidence: ManagedPolicyEvidenceProjectionV2,
    pub receipt: FlowVerificationReceiptV1,
    pub evidence_digest: String,
}

impl std::fmt::Debug for ManagedOid4vpEvidenceProjectionV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagedOid4vpEvidenceProjectionV2")
            .field("contract", &self.contract)
            .field("evidence_digest", &self.evidence_digest)
            .finish_non_exhaustive()
    }
}

impl ManagedPolicyEvidenceProjectionV2 {
    pub fn from_json(value: &str) -> Result<Self, Oid4vpContractError> {
        let parsed: Self = parse_strict(value)?;
        parsed.validate_historical()?;
        Ok(parsed)
    }

    /// Correspondence only: this does not mint an authenticated capability.
    pub fn recompute_digest(&self) -> Result<String, Oid4vpContractError> {
        self.validate_body()?;
        digest_without_field(MANAGED_POLICY_EVIDENCE_DIGEST_DOMAIN_V2, self)
    }

    /// Check the observation at its original Policy time, never at wall clock
    /// now. A historical pass is not a fresh authorization lease.
    pub fn validate_historical(&self) -> Result<(), Oid4vpContractError> {
        self.validate_body()?;
        require_digest(&self.evidence_digest)?;
        if self.evidence_digest != self.recompute_digest()? {
            return Err(Oid4vpContractError::BindingMismatch);
        }
        Ok(())
    }

    /// The caller supplies the genuine request and complete transported result
    /// before any privacy projection. Authentication is the caller's duty.
    pub fn validate_for_request(
        &self,
        request: &PolicyEvaluationValidityRequest<'_>,
        result: &Value,
    ) -> Result<(), Oid4vpContractError> {
        self.validate_historical()?;
        self.validity.validate_for_request(request, result)?;
        let transport = request.oid4vp_transport;
        transport.validate_transport()?;
        let authority = transport
            .credential_authority
            .as_ref()
            .ok_or(Oid4vpContractError::TrustEvidenceMismatch)?;
        if request.organization_id != self.organization_id
            || *request.policy != self.policy
            || transport.query_kind != QueryKind::Dcql
            || transport.presentation_submission.is_some()
            || transport.query_digest != self.query_digest
            || authority.organization_id != self.organization_id
            || authority.profile != self.trust.profile
            || request.nonce != transport.request_nonce
            || request.audience != transport.verifier_client_id
            || request.audience.starts_with("origin:")
            || digest_nonce(request.nonce)? != self.nonce_digest
            || digest_audience(request.audience)? != self.audience_digest
            || digest_response_item(request.vp_token, &self.query_id, "0")?
                != self.response_token_digest
            || digest_sd_jwt_issuer_jws(request.vp_token)? != self.issuer_jwt_digest
        {
            return Err(Oid4vpContractError::BindingMismatch);
        }
        let associated = transport.associate_response()?;
        if associated.presentation_count != 1
            || associated.tokens.len() != 1
            || associated.tokens[0].token != request.vp_token
        {
            return Err(Oid4vpContractError::ResponseDigestMismatch);
        }
        let query: ManagedDcqlQuery = serde_json::from_value(transport.query_document.clone())
            .map_err(|_| Oid4vpContractError::InvalidQueryDocument)?;
        let [credential] = query.credentials.as_slice() else {
            return Err(Oid4vpContractError::QueryCoverageMismatch);
        };
        let mut names = BTreeSet::new();
        let mut ids = BTreeSet::new();
        for claim in &credential.claims {
            let [name] = claim.path.as_slice() else {
                return Err(Oid4vpContractError::InvalidQueryDocument);
            };
            require_text(name, MAX_IDENTIFIER_BYTES)?;
            if !names.insert(name.as_str()) {
                return Err(Oid4vpContractError::InvalidQueryDocument);
            }
            if let Some(id) = &claim.id {
                require_text(id, MAX_IDENTIFIER_BYTES)?;
                if !ids.insert(id) {
                    return Err(Oid4vpContractError::InvalidQueryDocument);
                }
            }
        }
        if credential.id != self.query_id
            || credential.format != "dc+sd-jwt"
            || credential.meta.vct_values != [self.vct.as_str()]
            || names != self.selected_claims.keys().map(String::as_str).collect()
        {
            return Err(Oid4vpContractError::InvalidQueryDocument);
        }
        let native = self.native_result()?;
        if result["result"] != native.result
            || result["decision"] != native.decision
            || result["decision_reason"] != native.decision_reason
            || result["verified_claims"]
                != serde_json::to_value(&native.verified_claims)
                    .map_err(|_| Oid4vpContractError::Serialization)?
        {
            return Err(Oid4vpContractError::DecisionMismatch);
        }
        // Flow's legacy DTO omits counts; when present (the Policy producer's
        // actual result), compare rather than manufacturing replacements.
        for (name, count) in [
            ("total_requirements", native.total_requirements),
            ("satisfied_requirements", native.satisfied_requirements),
            ("required_total", native.required_total),
            ("required_satisfied", native.required_satisfied),
        ] {
            if result
                .get(name)
                .is_some_and(|value| value.as_u64() != Some(count))
            {
                return Err(Oid4vpContractError::DecisionMismatch);
            }
        }
        let rows = result["credential_results"]
            .as_array()
            .ok_or(Oid4vpContractError::DecisionMismatch)?;
        let [row] = rows.as_slice() else {
            return Err(Oid4vpContractError::DecisionMismatch);
        };
        let credential_result = &native.credential_results[0];
        let transported_claims: Vec<NativeClaimResult> =
            serde_json::from_value(row["claim_results"].clone())
                .map_err(|_| Oid4vpContractError::DecisionMismatch)?;
        if row["credential_template_id"] != self.credential_template_id
            || row["issuer_did"] != self.issuer_id
            || row["signature_valid"] != true
            || row["satisfied"] != true
            || transported_claims != credential_result.claim_results
            || row
                .get("credential_id")
                .is_some_and(|value| value.as_str() != credential_result.credential_id.as_deref())
        {
            return Err(Oid4vpContractError::DecisionMismatch);
        }
        self.validate_original_tokens(&[request.vp_token])
    }

    /// Validate the complete internal projection while original credential
    /// bytes are still available. Recovery must not claim to repeat this check.
    pub fn validate_original_tokens(&self, tokens: &[&str]) -> Result<(), Oid4vpContractError> {
        validate_privacy(self, tokens)
    }

    fn validate_body(&self) -> Result<(), Oid4vpContractError> {
        require_size(self)?;
        if self.contract != MANAGED_POLICY_EVIDENCE_CONTRACT_V2 {
            return Err(invalid());
        }
        self.policy.validate()?;
        self.validity.validate()?;
        self.trust.validate()?;
        for value in [
            &self.organization_id,
            &self.query_id,
            &self.credential_template_id,
            &self.issuer_algorithm,
        ] {
            require_text(value, MAX_IDENTIFIER_BYTES)?;
        }
        require_text(&self.issuer_id, 2_048)?;
        require_text(&self.vct, 2_048)?;
        for value in [
            &self.query_digest,
            &self.response_token_digest,
            &self.nonce_digest,
            &self.audience_digest,
            &self.issuer_scoped_subject_digest,
            &self.issuer_jwt_digest,
            &self.status.request_binding_digest,
            &self.status.issuer_jwt_digest,
            &self.status.evidence_digest,
        ] {
            require_digest(value)?;
        }
        require_thumbprint(&self.holder_key_thumbprint)?;
        require_thumbprint(&self.issuer_key_thumbprint)?;
        let evaluated = self.validity.evaluated_at_epoch_micros;
        if evaluated % 1_000_000 != 0 {
            return Err(Oid4vpContractError::InvalidLifetime);
        }
        let evaluated_seconds = evaluated / 1_000_000;
        if self.validity.organization_id != self.organization_id
            || self.validity.policy != self.policy
            || self.issued_at_epoch_seconds <= 0
            || self.valid_from_epoch_seconds < self.issued_at_epoch_seconds
            || self.valid_from_epoch_seconds > evaluated_seconds
            || self.expires_at_epoch_seconds <= evaluated_seconds
            || self.validity.valid_until_epoch_micros > micros(self.expires_at_epoch_seconds)?
        {
            return Err(Oid4vpContractError::InvalidLifetime);
        }
        let owner_binding = self.authority_binding_digest()?;
        if self.trust.organization_id != self.organization_id
            || self.trust.issuer_id != self.issuer_id
            || self.trust.format != "SD_JWT_VC"
            || self.trust.vct != self.vct
            || self.trust.issuer_algorithm != self.issuer_algorithm
            || self.trust.issuer_key_thumbprint != self.issuer_key_thumbprint
            || self.trust.request_binding_digest != owner_binding
            || self.trust.outcome != EvidenceCheckOutcome::Passed
            || self.trust.checked_at_epoch_seconds > evaluated_seconds
            || self.trust.valid_until_epoch_seconds <= evaluated_seconds
            || self.validity.valid_until_epoch_micros
                > micros(self.trust.valid_until_epoch_seconds)?
        {
            return Err(Oid4vpContractError::TrustEvidenceMismatch);
        }
        let status_lifetime = self
            .status
            .valid_until_epoch_seconds
            .checked_sub(self.status.checked_at_epoch_seconds)
            .ok_or(Oid4vpContractError::InvalidLifetime)?;
        if self.status.authority != MANAGED_STATUS_AUTHORITY
            || self.status.state != ManagedCredentialStatusState::Active
            || self.status.request_binding_digest != owner_binding
            || self.status.issuer_jwt_digest != self.issuer_jwt_digest
            || self.status.checked_at_epoch_seconds <= 0
            || self.status.checked_at_epoch_seconds > evaluated_seconds
            || self.status.valid_until_epoch_seconds <= evaluated_seconds
            || !(1..=i64::from(MAX_MANAGED_STATUS_AGE_SECONDS)).contains(&status_lifetime)
            || self.validity.valid_until_epoch_micros
                > micros(self.status.valid_until_epoch_seconds)?
        {
            return Err(Oid4vpContractError::StatusEvidenceMismatch);
        }
        validate_claims(&self.selected_claims)?;
        self.validate_native_result()?;
        validate_privacy(self, &[])
    }

    fn authority_binding_digest(&self) -> Result<String, Oid4vpContractError> {
        digest_domain_json(
            "marty.oid4vp/managed-credential-authority-request/v1",
            &json!({
                "organization_id": self.organization_id,
                "policy": self.policy,
                "trust_profile": self.trust.profile,
                "credential_template_id": self.credential_template_id,
                "query_id": self.query_id,
                "query_digest": self.query_digest,
                "response_token_digest": self.response_token_digest,
                "nonce_digest": self.nonce_digest,
                "audience_digest": self.audience_digest,
                "issuer_id": self.issuer_id,
                "issuer_scoped_subject_digest": self.issuer_scoped_subject_digest,
                "holder_key_thumbprint": self.holder_key_thumbprint,
                "issuer_key_thumbprint": self.issuer_key_thumbprint,
                "issuer_jwt_digest": self.issuer_jwt_digest,
                "vct": self.vct,
                "issuer_algorithm": self.issuer_algorithm,
            }),
        )
    }

    fn native_result(&self) -> Result<NativePolicyResult, Oid4vpContractError> {
        serde_json::from_value(self.policy_result.clone())
            .map_err(|_| Oid4vpContractError::DecisionMismatch)
    }

    fn validate_native_result(&self) -> Result<(), Oid4vpContractError> {
        let native = self.native_result()?;
        require_text(&native.policy_name, 255)?;
        require_text(&native.decision_reason, 1_024)?;
        validate_messages(&native.warnings)?;
        let [credential] = native.credential_results.as_slice() else {
            return Err(Oid4vpContractError::DecisionMismatch);
        };
        if native.result != "passed"
            || native.decision != "allow"
            || native.policy_id != self.policy.id
            || native.evaluation_time_epoch_seconds
                != self.validity.evaluated_at_epoch_micros / 1_000_000
            || !native.alternative_results.is_empty()
            || !native.errors.is_empty()
            || !(1..=2).contains(&native.total_requirements)
            || native.total_requirements != native.required_total
            || native.total_requirements != native.satisfied_requirements
            || native.required_total != native.required_satisfied
            || credential.requirement_id != self.query_id
            || credential.credential_template_id != self.credential_template_id
            || credential.issuer_id.as_deref() != Some(self.issuer_id.as_str())
            || !credential.satisfied
            || !credential.errors.is_empty()
            || credential.claim_results.len() > MAX_CLAIMS_PER_CREDENTIAL
        {
            return Err(Oid4vpContractError::DecisionMismatch);
        }
        require_text(
            credential.credential_id.as_deref().ok_or_else(invalid)?,
            2_048,
        )?;
        validate_messages(&credential.warnings)?;
        validate_claims(&native.verified_claims)?;
        let mut names = BTreeSet::new();
        let mut verified = BTreeMap::new();
        for claim in &credential.claim_results {
            require_text(&claim.claim_name, MAX_IDENTIFIER_BYTES)?;
            if !names.insert(claim.claim_name.as_str()) || claim.constraint_results.len() > 128 {
                return Err(Oid4vpContractError::DecisionMismatch);
            }
            if let Some(value) = &claim.presented_value {
                validate_scalar(value)?;
                if self.selected_claims.get(&claim.claim_name) != Some(value) {
                    return Err(Oid4vpContractError::DecisionMismatch);
                }
            } else if self.selected_claims.contains_key(&claim.claim_name) {
                return Err(Oid4vpContractError::DecisionMismatch);
            }
            if claim.satisfied {
                if claim
                    .constraint_results
                    .iter()
                    .any(|constraint| !constraint.passed)
                {
                    return Err(Oid4vpContractError::DecisionMismatch);
                }
                if let Some(value) = &claim.presented_value {
                    verified.insert(claim.claim_name.clone(), value.clone());
                }
            }
        }
        if self
            .selected_claims
            .keys()
            .any(|name| !names.contains(name.as_str()))
            || native.verified_claims != verified
        {
            return Err(Oid4vpContractError::DecisionMismatch);
        }
        Ok(())
    }
}

impl ManagedFlowRequestBindingV2 {
    /// Scan the complete owner request binding while original wallet bytes are
    /// available. This is a privacy check, not request-owner authentication.
    pub fn validate_original_tokens(&self, tokens: &[&str]) -> Result<(), Oid4vpContractError> {
        validate_privacy(self, tokens)
    }

    pub fn validate(&self) -> Result<(), Oid4vpContractError> {
        self.policy.validate()?;
        for value in [
            &self.organization_id,
            &self.flow_instance_id,
            &self.initiating_principal_id,
            &self.query_id,
        ] {
            require_text(value, MAX_IDENTIFIER_BYTES)?;
        }
        require_text(&self.verifier_client_id, MAX_TRANSPORT_CLIENT_ID_BYTES)?;
        require_text(&self.response_uri, MAX_TRANSPORT_CLIENT_ID_BYTES)?;
        let uri = url::Url::parse(&self.response_uri).map_err(|_| invalid())?;
        if !matches!(uri.scheme(), "https" | "http")
            || uri.host_str().is_none()
            || !uri.username().is_empty()
            || uri.password().is_some()
            || uri.fragment().is_some()
            || self.verifier_client_id.starts_with("origin:")
        {
            return Err(invalid());
        }
        for value in [
            &self.query_digest,
            &self.nonce_digest,
            &self.expected_state_digest,
            &self.request_binding_digest,
            &self.policy_request_binding_digest,
        ] {
            require_digest(value)?;
        }
        require_hex(&self.flow_nonce_digest)?;
        require_hex(&self.submission_digest)?;
        Ok(())
    }

    /// The Flow owner separately validates state and the original stored row.
    pub fn validate_for_request(
        &self,
        request: &PolicyEvaluationValidityRequest<'_>,
    ) -> Result<(), Oid4vpContractError> {
        self.validate()?;
        if self.organization_id != request.organization_id
            || self.policy != *request.policy
            || self.query_digest != request.oid4vp_transport.query_digest
            || self.verifier_client_id != request.audience
            || self.nonce_digest != digest_nonce(request.nonce)?
            || self.flow_nonce_digest != format!("{:x}", Sha256::digest(request.nonce.as_bytes()))
        {
            return Err(Oid4vpContractError::RequestDigestMismatch);
        }
        Ok(())
    }
}

impl ManagedOid4vpEvidenceProjectionV2 {
    pub fn from_json(value: &str) -> Result<Self, Oid4vpContractError> {
        let parsed: Self = parse_strict(value)?;
        parsed.validate_historical()?;
        Ok(parsed)
    }

    /// Construct correspondence data only. Flow must supply authenticated
    /// acquisition and actual commit capabilities before exposing authority.
    pub fn bind(
        request: ManagedFlowRequestBindingV2,
        policy_evidence: ManagedPolicyEvidenceProjectionV2,
        receipt: FlowVerificationReceiptV1,
    ) -> Result<Self, Oid4vpContractError> {
        let mut value = Self {
            contract: MANAGED_OID4VP_EVIDENCE_CONTRACT_V2.into(),
            request,
            policy_evidence,
            receipt,
            evidence_digest: String::new(),
        };
        value.evidence_digest = value.recompute_digest()?;
        value.validate_historical()?;
        Ok(value)
    }

    pub fn recompute_digest(&self) -> Result<String, Oid4vpContractError> {
        self.validate_body()?;
        digest_without_field(MANAGED_OID4VP_EVIDENCE_DIGEST_DOMAIN_V2, self)
    }

    pub fn validate_historical(&self) -> Result<(), Oid4vpContractError> {
        self.validate_body()?;
        require_digest(&self.evidence_digest)?;
        if self.evidence_digest != self.recompute_digest()? {
            return Err(Oid4vpContractError::BindingMismatch);
        }
        Ok(())
    }

    /// Recheck the complete private result, not the minimized callback. The
    /// result binds the Policy candidate digest; the receipt does not hash this
    /// final envelope and therefore no receipt/evidence digest cycle exists.
    pub fn validate_for_stored_result(&self, result: &Value) -> Result<(), Oid4vpContractError> {
        self.validate_historical()?;
        self.receipt.validate_result(result)?;
        if result
            .get(MANAGED_POLICY_EVIDENCE_DIGEST_V2)
            .and_then(Value::as_str)
            != Some(self.policy_evidence.evidence_digest.as_str())
            || result.get("evaluation_result").and_then(Value::as_str) != Some("passed")
            || result.get("decision").and_then(Value::as_str) != Some("allow")
        {
            return Err(Oid4vpContractError::DecisionMismatch);
        }
        Ok(())
    }

    pub fn validate_original_tokens(&self, tokens: &[&str]) -> Result<(), Oid4vpContractError> {
        validate_privacy(self, tokens)
    }

    fn validate_body(&self) -> Result<(), Oid4vpContractError> {
        require_size(self)?;
        self.request.validate()?;
        self.policy_evidence.validate_historical()?;
        self.receipt.validate()?;
        let request = &self.request;
        let policy = &self.policy_evidence;
        let receipt = &self.receipt;
        if self.contract != MANAGED_OID4VP_EVIDENCE_CONTRACT_V2
            || request.organization_id != policy.organization_id
            || request.organization_id != receipt.organization_id
            || request.flow_instance_id != receipt.flow_instance_id
            || request.policy != policy.policy
            || request.policy != receipt.policy
            || request.query_id != policy.query_id
            || request.query_digest != policy.query_digest
            || request.nonce_digest != policy.nonce_digest
            || request.flow_nonce_digest != receipt.nonce_digest
            || digest_audience(&request.verifier_client_id)? != policy.audience_digest
            || request.request_binding_digest != receipt.request_binding_digest
            || request.submission_digest != receipt.submission_digest
            || request.policy_request_binding_digest != policy.validity.request_binding_digest
            || receipt.policy_evaluated_at_epoch_micros != policy.validity.evaluated_at_epoch_micros
            || receipt.policy_valid_until_epoch_micros
                != Some(policy.validity.valid_until_epoch_micros)
        {
            return Err(Oid4vpContractError::BindingMismatch);
        }
        // These are real different clocks. No COMMIT timestamp is invented.
        policy
            .validity
            .validate_at(receipt.nonce_consumed_at_epoch_micros)?;
        validate_privacy(self, &[])
    }
}

pub fn digest_managed_state_v2(state: &str) -> Result<String, Oid4vpContractError> {
    require_text(state, MAX_TOKEN_BYTES)?;
    digest_domain_json(MANAGED_STATE_DIGEST_DOMAIN_V2, state)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagedDcqlQuery {
    credentials: Vec<ManagedDcqlCredential>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagedDcqlCredential {
    id: String,
    format: String,
    meta: ManagedDcqlMeta,
    #[serde(default)]
    claims: Vec<ManagedDcqlClaim>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagedDcqlMeta {
    vct_values: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagedDcqlClaim {
    id: Option<String>,
    path: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativePolicyResult {
    result: String,
    decision: String,
    decision_reason: String,
    policy_id: String,
    policy_name: String,
    credential_results: Vec<NativeCredentialResult>,
    alternative_results: Vec<Value>,
    total_requirements: u64,
    satisfied_requirements: u64,
    required_satisfied: u64,
    required_total: u64,
    verified_claims: BTreeMap<String, Value>,
    errors: Vec<Value>,
    warnings: Vec<String>,
    evaluation_time_epoch_seconds: i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeCredentialResult {
    requirement_id: String,
    credential_template_id: String,
    credential_id: Option<String>,
    issuer_id: Option<String>,
    satisfied: bool,
    claim_results: Vec<NativeClaimResult>,
    errors: Vec<Value>,
    warnings: Vec<String>,
}
#[derive(Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct NativeClaimResult {
    claim_name: String,
    satisfied: bool,
    presented_value: Option<Value>,
    constraint_results: Vec<NativeConstraintResult>,
}
#[derive(Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct NativeConstraintResult {
    constraint_type: NativeConstraintType,
    passed: bool,
}
#[derive(Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum NativeConstraintType {
    Equals,
    NotEquals,
    GreaterThan,
    LessThan,
    GreaterOrEqual,
    LessOrEqual,
    InSet,
    NotInSet,
    Presence,
    Regex,
    AgeOver,
}

fn validate_claims(claims: &BTreeMap<String, Value>) -> Result<(), Oid4vpContractError> {
    if claims.len() > MAX_CLAIMS_PER_CREDENTIAL {
        return Err(invalid());
    }
    for (name, value) in claims {
        require_text(name, MAX_IDENTIFIER_BYTES)?;
        validate_scalar(value)?;
    }
    Ok(())
}
fn validate_scalar(value: &Value) -> Result<(), Oid4vpContractError> {
    if !(value.is_string() || value.is_number() || value.is_boolean())
        || serde_json::to_vec(value)
            .map_err(|_| Oid4vpContractError::Serialization)?
            .len()
            > MAX_CLAIM_VALUE_BYTES
    {
        return Err(invalid());
    }
    Ok(())
}
fn validate_messages(values: &[String]) -> Result<(), Oid4vpContractError> {
    if values.len() > 128 {
        return Err(invalid());
    }
    for value in values {
        require_text(value, 1_024)?;
    }
    Ok(())
}
fn require_text(value: &str, limit: usize) -> Result<(), Oid4vpContractError> {
    if value.is_empty()
        || value.len() > limit
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(invalid());
    }
    Ok(())
}
fn require_hex(value: &str) -> Result<(), Oid4vpContractError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Oid4vpContractError::InvalidDigest(
            MANAGED_POLICY_EVIDENCE_V2,
        ));
    }
    Ok(())
}
fn require_digest(value: &str) -> Result<(), Oid4vpContractError> {
    require_hex(
        value
            .strip_prefix("sha256:")
            .ok_or(Oid4vpContractError::InvalidDigest(
                MANAGED_POLICY_EVIDENCE_V2,
            ))?,
    )
}
fn require_thumbprint(value: &str) -> Result<(), Oid4vpContractError> {
    if value.len() != 43
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(invalid());
    }
    Ok(())
}
fn micros(seconds: i64) -> Result<i64, Oid4vpContractError> {
    seconds
        .checked_mul(1_000_000)
        .filter(|value| *value > 0)
        .ok_or(Oid4vpContractError::InvalidLifetime)
}
fn require_size<T: Serialize>(value: &T) -> Result<(), Oid4vpContractError> {
    let value = serde_json::to_value(value).map_err(|_| Oid4vpContractError::Serialization)?;
    if serde_json::to_vec(&value)
        .map_err(|_| Oid4vpContractError::Serialization)?
        .len()
        > MAX_EVIDENCE_PROJECTION_BYTES
        || json_depth(&value) > MAX_JSON_DEPTH
    {
        return Err(Oid4vpContractError::SizeLimit(MANAGED_POLICY_EVIDENCE_V2));
    }
    Ok(())
}
fn json_depth(value: &Value) -> usize {
    1 + match value {
        Value::Array(items) => items.iter().map(json_depth).max().unwrap_or(0),
        Value::Object(items) => items.values().map(json_depth).max().unwrap_or(0),
        _ => 0,
    }
}
fn digest_without_field<T: Serialize>(
    domain: &'static str,
    value: &T,
) -> Result<String, Oid4vpContractError> {
    let mut value = serde_json::to_value(value).map_err(|_| Oid4vpContractError::Serialization)?;
    value
        .as_object_mut()
        .ok_or_else(invalid)?
        .remove("evidence_digest");
    digest_domain_json(domain, &value)
}
fn validate_privacy<T: Serialize>(value: &T, tokens: &[&str]) -> Result<(), Oid4vpContractError> {
    require_size(value)?;
    if tokens.len() > crate::MAX_TOKENS
        || tokens
            .iter()
            .any(|token| token.len() > crate::MAX_TRANSPORT_RAW_TOKEN_BYTES)
    {
        return Err(Oid4vpContractError::SizeLimit(MANAGED_POLICY_EVIDENCE_V2));
    }
    let value = serde_json::to_value(value).map_err(|_| Oid4vpContractError::Serialization)?;
    crate::validation::validate_managed_projection_privacy(&value, tokens)
}
fn invalid() -> Oid4vpContractError {
    Oid4vpContractError::InvalidField(MANAGED_POLICY_EVIDENCE_V2)
}

/// Reject duplicate keys throughout native-result Value fields as well as the
/// typed outer record. Parsing still establishes no owner provenance.
fn parse_strict<T: serde::de::DeserializeOwned>(input: &str) -> Result<T, Oid4vpContractError> {
    if input.len() > MAX_EVIDENCE_PROJECTION_BYTES {
        return Err(Oid4vpContractError::SizeLimit(MANAGED_POLICY_EVIDENCE_V2));
    }
    let value: UniqueValue =
        serde_json::from_str(input).map_err(|_| Oid4vpContractError::Deserialization)?;
    if json_depth(&value.0) > MAX_JSON_DEPTH {
        return Err(invalid());
    }
    serde_json::from_value(value.0).map_err(|_| Oid4vpContractError::Deserialization)
}
struct UniqueValue(Value);
impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = UniqueValue;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("bounded JSON without duplicate keys")
            }
            fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Bool(value)))
            }
            fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(value)
                    .map(Value::Number)
                    .map(UniqueValue)
                    .ok_or_else(|| E::custom("nonfinite JSON"))
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Null))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Null))
            }
            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut result = Vec::new();
                while let Some(value) = seq.next_element::<UniqueValue>()? {
                    result.push(value.0);
                }
                Ok(UniqueValue(Value::Array(result)))
            }
            fn visit_map<A: de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut result = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if result.contains_key(&key) {
                        return Err(de::Error::custom("duplicate JSON key"));
                    }
                    result.insert(key, map.next_value::<UniqueValue>()?.0);
                }
                Ok(UniqueValue(Value::Object(result)))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

#[cfg(test)]
#[path = "managed_evidence_tests.rs"]
mod tests;
