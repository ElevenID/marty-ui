//! Managed evidence is acquired through Policy's inspected workload channel,
//! bound to Flow's original request, and exposed only after owner persistence.
//! A wire projection or a receipt alone cannot construct this capability.

use marty_oid4vp_contract::{
    digest_domain_json, digest_managed_state_v2, digest_nonce, FlowVerificationReceiptV1,
    ManagedFlowRequestBindingV2, ManagedOid4vpEvidenceProjectionV2,
    ManagedPolicyEvidenceProjectionV2, PolicyEvaluationValidityRequest, QueryKind,
    FLOW_REQUEST_BINDING_DIGEST_DOMAIN, MANAGED_POLICY_EVIDENCE_DIGEST_V2,
    POLICY_EVALUATION_VALIDITY, VERIFICATION_RECEIPT,
};
use marty_verification::flow::FlowInstanceStatus;
use serde_json::Value;

use crate::{
    presentation_request::load_frozen_flow_presentation_request,
    verification_submission::sha256_hex, FlowInstanceRecord, PreparedVerificationFinalization,
    PresentationEvaluationRequest, PresentationEvaluationResult, RepositoryError,
};

pub(crate) const MANAGED_EVIDENCE_CONTEXT_KEY: &str = "_marty_managed_oid4vp_evidence_v2";

/// An owner-retained historical verification fact. Future issuance admission
/// must independently bind its intent and enforce its own freshness deadline.
///
/// ```compile_fail
/// let _: marty_flow::AuthenticatedOid4vpEvidenceV2 = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Clone, Debug)]
pub struct AuthenticatedOid4vpEvidenceV2 {
    projection: ManagedOid4vpEvidenceProjectionV2,
}

impl AuthenticatedOid4vpEvidenceV2 {
    /// Internal owner projection; HTTP and gRPC expose only its digest.
    #[must_use]
    pub fn projection(&self) -> &ManagedOid4vpEvidenceProjectionV2 {
        &self.projection
    }
}

/// Correspondence checked before COMMIT. This is deliberately a distinct,
/// crate-private type and cannot be passed as authenticated evidence.
pub(crate) struct ValidatedManagedEvidence(ManagedOid4vpEvidenceProjectionV2);

impl ValidatedManagedEvidence {
    pub(crate) fn after_owner_persistence(self) -> AuthenticatedOid4vpEvidenceV2 {
        AuthenticatedOid4vpEvidenceV2 { projection: self.0 }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct PreparedManagedEvidence {
    request: ManagedFlowRequestBindingV2,
    candidate: ManagedPolicyEvidenceProjectionV2,
}

impl PreparedManagedEvidence {
    pub(crate) fn acquire(
        expected: &FlowInstanceRecord,
        request: &PresentationEvaluationRequest,
        evaluation: &PresentationEvaluationResult,
        state: Option<&str>,
        submission_digest: &str,
    ) -> Result<Option<Self>, RepositoryError> {
        let Some(acquired) = &evaluation.managed_evidence else {
            return Ok(None);
        };
        let candidate = acquired
            .candidate_for(request, evaluation)
            .map_err(|_| invalid())?;
        let transport = request.oid4vp_transport.as_ref().ok_or_else(invalid)?;
        let expected_state = text(&expected.context, "oid4vp_expected_state")?;
        if state != Some(expected_state)
            || expected_state != expected.id
            || transport.query_kind != QueryKind::Dcql
            || transport.presentation_submission.is_some()
        {
            return Err(invalid());
        }
        let binding = ManagedFlowRequestBindingV2 {
            organization_id: expected.organization_id.clone(),
            flow_instance_id: expected.id.clone(),
            initiating_principal_id: request.principal_id.clone(),
            policy: request.expected_policy_revision.clone(),
            query_id: candidate.query_id.clone(),
            query_digest: transport.query_digest.clone(),
            verifier_client_id: request.audience.clone(),
            response_uri: text(&expected.context, "oid4vp_response_uri")?.into(),
            nonce_digest: digest_nonce(&request.nonce).map_err(|_| invalid())?,
            flow_nonce_digest: sha256_hex(request.nonce.as_bytes()),
            expected_state_digest: digest_managed_state_v2(expected_state)
                .map_err(|_| invalid())?,
            request_binding_digest: digest_domain_json(
                FLOW_REQUEST_BINDING_DIGEST_DOMAIN,
                expected,
            )
            .map_err(|_| invalid())?,
            submission_digest: submission_digest.into(),
            policy_request_binding_digest: candidate.validity.request_binding_digest.clone(),
        };
        let context = serde_json::to_value(&request.context).map_err(|_| invalid())?;
        binding
            .validate_for_request(&PolicyEvaluationValidityRequest {
                organization_id: &request.organization_id,
                policy: &request.expected_policy_revision,
                nonce: &request.nonce,
                audience: &request.audience,
                vp_token: &request.presentation,
                trust_profile_id: request
                    .context
                    .get("trust_profile_id")
                    .and_then(Value::as_str),
                context: &context,
                oid4vp_transport: transport,
            })
            .map_err(|_| invalid())?;
        validate_stable_request(expected, &binding, candidate)?;
        candidate
            .validate_original_tokens(&[&request.presentation, &transport.vp_token_raw])
            .map_err(|_| invalid())?;
        binding
            .validate_original_tokens(&[&request.presentation, &transport.vp_token_raw])
            .map_err(|_| invalid())?;
        Ok(Some(Self {
            request: binding,
            candidate: candidate.clone(),
        }))
    }

    pub(crate) fn candidate_digest(&self) -> &str {
        &self.candidate.evidence_digest
    }

    pub(crate) fn validate_prepared(
        &self,
        prepared: &PreparedVerificationFinalization,
    ) -> Result<(), RepositoryError> {
        if digest_domain_json(
            FLOW_REQUEST_BINDING_DIGEST_DOMAIN,
            &prepared.expected_instance,
        )
        .map_err(|_| invalid())?
            != self.request.request_binding_digest
            || prepared.nonce_digest != self.request.flow_nonce_digest
            || prepared.submission_digest != self.request.submission_digest
            || prepared
                .instance
                .context
                .get(MANAGED_EVIDENCE_CONTEXT_KEY)
                .is_some()
        {
            return Err(invalid());
        }
        validate_stable_request(&prepared.expected_instance, &self.request, &self.candidate)?;
        validate_stable_request(&prepared.instance, &self.request, &self.candidate)?;
        validate_result(&prepared.instance, &self.candidate)
    }

    pub(crate) fn attach(
        &self,
        prepared: &PreparedVerificationFinalization,
        instance: &mut FlowInstanceRecord,
        receipt: &FlowVerificationReceiptV1,
    ) -> Result<ValidatedManagedEvidence, RepositoryError> {
        self.validate_prepared(prepared)?;
        let envelope = ManagedOid4vpEvidenceProjectionV2::bind(
            self.request.clone(),
            self.candidate.clone(),
            receipt.clone(),
        )
        .map_err(|_| invalid())?;
        instance
            .context
            .as_object_mut()
            .ok_or_else(invalid)?
            .insert(
                MANAGED_EVIDENCE_CONTEXT_KEY.into(),
                serde_json::to_value(envelope).map_err(|_| invalid())?,
            );
        validate_owner_record(instance)?.ok_or_else(invalid)
    }
}

/// Called only on records read by the owner repository, or immediately before
/// its atomic write. It checks historical bounds, not the current wall clock.
pub(crate) fn validate_owner_record(
    instance: &FlowInstanceRecord,
) -> Result<Option<ValidatedManagedEvidence>, RepositoryError> {
    let envelope = instance.context.get(MANAGED_EVIDENCE_CONTEXT_KEY);
    let digest = instance
        .result
        .as_ref()
        .and_then(|result| result.get(MANAGED_POLICY_EVIDENCE_DIGEST_V2));
    let Some(envelope) = envelope else {
        return if digest.is_none() {
            Ok(None)
        } else {
            Err(invalid())
        };
    };
    if digest.is_none() {
        return Err(invalid());
    }
    let envelope = ManagedOid4vpEvidenceProjectionV2::from_json(
        &serde_json::to_string(envelope).map_err(|_| invalid())?,
    )
    .map_err(|_| invalid())?;
    validate_stable_request(instance, &envelope.request, &envelope.policy_evidence)?;
    validate_result(instance, &envelope.policy_evidence)?;
    let mut result = instance.result.clone().ok_or_else(invalid)?;
    let receipt = result
        .as_object_mut()
        .ok_or_else(invalid)?
        .remove(VERIFICATION_RECEIPT)
        .ok_or_else(invalid)?;
    if receipt != serde_json::to_value(&envelope.receipt).map_err(|_| invalid())?
        || instance.expires_at.is_none_or(|deadline| {
            envelope.receipt.nonce_consumed_at_epoch_micros >= deadline.timestamp_micros()
        })
    {
        return Err(invalid());
    }
    envelope
        .validate_for_stored_result(&result)
        .map_err(|_| invalid())?;
    Ok(Some(ValidatedManagedEvidence(envelope)))
}

fn validate_result(
    instance: &FlowInstanceRecord,
    candidate: &ManagedPolicyEvidenceProjectionV2,
) -> Result<(), RepositoryError> {
    let result = instance.result.as_ref().ok_or_else(invalid)?;
    if instance.status != FlowInstanceStatus::Completed
        || result["evaluation_result"] != "passed"
        || result["decision"] != "allow"
        || result[MANAGED_POLICY_EVIDENCE_DIGEST_V2].as_str()
            != Some(candidate.evidence_digest.as_str())
        || result[POLICY_EVALUATION_VALIDITY]
            != serde_json::to_value(&candidate.validity).map_err(|_| invalid())?
    {
        return Err(invalid());
    }
    Ok(())
}

fn validate_stable_request(
    instance: &FlowInstanceRecord,
    binding: &ManagedFlowRequestBindingV2,
    candidate: &ManagedPolicyEvidenceProjectionV2,
) -> Result<(), RepositoryError> {
    binding.validate().map_err(|_| invalid())?;
    let frozen = load_frozen_flow_presentation_request(instance).map_err(|_| invalid())?;
    let authority = frozen.credential_authority.as_ref().ok_or_else(invalid)?;
    let context = &instance.context;
    let message = &context["mip_messages"]["presentation_request"];
    let payload = &message["payload"];
    let nonce = text(context, "nonce")?;
    let state = text(context, "oid4vp_expected_state")?;
    if instance.id != binding.flow_instance_id
        || instance.organization_id != binding.organization_id
        || frozen.policy_revision != binding.policy
        || frozen.dcql_query_digest != binding.query_digest
        || authority.profile != candidate.trust.profile
        || authority.organization_id != candidate.organization_id
        || text(context, "_marty_verification_principal_id")? != binding.initiating_principal_id
        || text(context, "presentation_policy_id")? != binding.policy.id
        || text(context, "trust_profile_id")? != authority.profile.id
        || text(context, "oid4vp_client_id")? != binding.verifier_client_id
        || text(context, "verification_audience")? != binding.verifier_client_id
        || text(context, "oid4vp_response_uri")? != binding.response_uri
        || context["oid4vp_verifier_context"] != true
        || state != instance.id
        || digest_managed_state_v2(state).map_err(|_| invalid())? != binding.expected_state_digest
        || digest_nonce(nonce).map_err(|_| invalid())? != binding.nonce_digest
        || sha256_hex(nonce.as_bytes()) != binding.flow_nonce_digest
        || message["correlation_id"].as_str() != Some(instance.id.as_str())
        || payload["mip_flow_instance_id"].as_str() != Some(instance.id.as_str())
        || payload["response_type"] != "vp_token"
        || !matches!(
            payload["response_mode"].as_str(),
            Some("direct_post" | "direct_post.jwt")
        )
        || payload["client_id"].as_str() != Some(binding.verifier_client_id.as_str())
        || payload["response_uri"].as_str() != Some(binding.response_uri.as_str())
        || payload["nonce"].as_str() != Some(nonce)
        || payload["dcql_query"] != frozen.dcql_query
        || payload
            .get("presentation_definition")
            .is_some_and(|value| !value.is_null())
    {
        return Err(invalid());
    }
    Ok(())
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, RepositoryError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(invalid)
}

fn invalid() -> RepositoryError {
    RepositoryError::InvalidVerificationReceipt
}
