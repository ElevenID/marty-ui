//! Canonical Core policy projection shared by creation, activation and evaluation.
use crate::{CredentialRequirement, PolicyDomainError, PresentationPolicy};
use serde_json::{json, Value};

pub(crate) fn validate_policy(policy: &PresentationPolicy) -> Result<(), PolicyDomainError> {
    if policy.compliance_profile_id.is_some() {
        return Err(PolicyDomainError::Native(
            "Resolved ComplianceProfile verification is unavailable".into(),
        ));
    }
    let canonical: marty_verification::policy::service::ServicePresentationPolicy =
        serde_json::from_value(service_policy(policy))
            .map_err(|error| PolicyDomainError::Native(error.to_string()))?;
    marty_verification::policy::validate_service_policy(&canonical)
        .map_err(|error| PolicyDomainError::Native(error.to_string()))
}

pub(crate) fn service_policy(policy: &PresentationPolicy) -> Value {
    let freshness = policy.holder_binding.proof_freshness.clone();
    json!({
        "id": policy.id.to_string(),
        "name": policy.name,
        "organization_id": policy.organization_id.to_string(),
        "accepted_credential_types": policy.accepted_credential_types,
        "fallback_policy": policy.fallback_policy.as_deref().unwrap_or("ACCEPT_RAW"),
        "supported_circuits": policy.supported_circuits,
        "credential_requirements": policy.credential_requirements.iter().map(|requirement| service_requirement(policy, requirement)).collect::<Vec<_>>(),
        "alternative_requirements": policy.alternative_requirements.iter().map(|alternative| json!({
            "id": alternative.id.to_string(),
            "name": alternative.name,
            "credential_requirements": alternative.credential_requirements.iter().map(|requirement| service_requirement(policy, requirement)).collect::<Vec<_>>(),
            "min_satisfied": alternative.min_satisfied
        })).collect::<Vec<_>>(),
        "trust_profile_id": policy.trust_profile_id.map(|id| id.to_string()),
        "presentation_proof_required": policy.presentation_proof_required,
        "holder_binding": {
            "required": policy.holder_binding.required,
            "binding_methods": policy.holder_binding.binding_methods,
            "proof_profiles": policy.holder_binding.proof_profiles,
            "challenge_required": freshness.get("challenge_required").copied().unwrap_or(false),
            "audience_binding_required": freshness.get("audience_binding_required").copied().unwrap_or(false),
            "replay_detection_required": freshness.get("replay_detection_required").copied().unwrap_or(false),
            "max_proof_age_seconds": Value::Null
        },
        "freshness": policy.freshness,
        "issuer_constraints": policy.issuer_constraints,
        "allowed_issuers": [],
        "single_presentation": true
    })
}

fn service_requirement(policy: &PresentationPolicy, requirement: &CredentialRequirement) -> Value {
    json!({
        "id": requirement.id.to_string(),
        "credential_template_id": if is_inline_requirement(policy, requirement) { "" } else { &requirement.credential_template_id },
        "required": requirement.required,
        "credential_payload_format": requirement.credential_payload_format,
        "requested_claims": requirement.requested_claims.iter().map(|claim| json!({
            "claim_name": claim.claim_name,
            "credential_type": claim.description.as_deref().and_then(|value| value.strip_prefix("credential_type:")),
            "required": claim.required,
            "selective_disclosure": claim.selective_disclosure,
            "accept_derived": claim.accept_derived,
            "predicate_spec": claim.predicate_spec,
            "constraints": claim.constraints.iter().map(|constraint| json!({
                "claim_name": constraint.claim_name,
                "constraint_type": constraint.constraint_type,
                "value": constraint.value
            })).collect::<Vec<_>>()
        })).collect::<Vec<_>>(),
        "trust_profile_id": requirement.trust_profile_id.map(|id| id.to_string()),
        "max_age_seconds": requirement.max_age_seconds,
        "require_fresh_issuance": requirement.require_fresh_issuance
    })
}

pub(crate) fn is_inline_requirement(
    policy: &PresentationPolicy,
    requirement: &CredentialRequirement,
) -> bool {
    // Also recognize the released inline representation so existing policies
    // retain their accepted-type alternatives without inventing catalog IDs.
    !policy.required_claims.is_empty()
        && requirement.requested_claims == policy.required_claims
        && (requirement.credential_template_id == "protocol-inline"
            || policy.accepted_credential_types.first()
                == Some(&requirement.credential_template_id))
}
