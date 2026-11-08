use marty_oid4vci::presentation_request::{
    build_presentation_request, MdocClaimInput, PresentationRequestArtifacts,
    PresentationRequestBuildInput, PresentationRequirementInput, RequestedClaimInput,
};
use marty_oid4vp_contract::{digest_query_document, FrozenPolicyIdentity};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

use crate::{
    CredentialTemplateReference, FlowInstanceRecord, FlowProviderError, FlowProviderRegistry,
    PresentationPolicyReference,
};

#[derive(Debug, Error)]
pub enum FlowPresentationRequestError {
    #[error(transparent)]
    Provider(#[from] FlowProviderError),
    #[error("FLOW.PRESENTATION_REQUEST_INVALID_POLICY: {0}")]
    InvalidPolicy(String),
    #[error("FLOW.PRESENTATION_REQUEST_POLICY_NOT_VISIBLE")]
    PolicyNotVisible,
    #[error("FLOW.PRESENTATION_REQUEST_POLICY_INACTIVE")]
    PolicyInactive,
    #[error("FLOW.PRESENTATION_REQUEST_INVALID_TEMPLATE: {0}")]
    InvalidTemplate(String),
    #[error("FLOW.PRESENTATION_REQUEST_TEMPLATE_NOT_VISIBLE")]
    TemplateNotVisible,
    #[error("FLOW.PRESENTATION_REQUEST_TEMPLATE_INACTIVE")]
    TemplateInactive,
    #[error("FLOW.PRESENTATION_REQUEST_NATIVE: {0}")]
    Native(String),
    #[error("FLOW.VERIFICATION_RESTART_REQUIRED: frozen presentation request is missing")]
    FrozenRequestMissing,
    #[error("FLOW.PRESENTATION_REQUEST_INVALID_SNAPSHOT")]
    InvalidFrozenRequest,
}

pub(crate) const FROZEN_PRESENTATION_REQUEST_KEY: &str = "_marty_presentation_request_v1";

/// Flow-owned policy and exact Core artifacts retained at session creation.
/// This is stored behind the reserved private context boundary; it is not
/// authenticated presentation evidence or an OpenID wire extension.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FrozenFlowPresentationRequest {
    pub instance_id: String,
    pub organization_id: String,
    pub nonce: String,
    pub policy_revision: FrozenPolicyIdentity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_authority:
        Option<marty_oid4vp_contract::trust_authority::CredentialAuthoritySnapshotV1>,
    pub presentation_definition: Value,
    pub presentation_definition_digest: String,
    pub dcql_query: Value,
    pub dcql_query_digest: String,
}

impl FrozenFlowPresentationRequest {
    pub fn artifacts(&self) -> PresentationRequestArtifacts {
        PresentationRequestArtifacts {
            presentation_definition: self.presentation_definition.clone(),
            dcql_query: self.dcql_query.clone(),
        }
    }

    pub fn matches_query(&self, kind: marty_oid4vp_contract::QueryKind, query: &Value) -> bool {
        match kind {
            marty_oid4vp_contract::QueryKind::Dcql => query == &self.dcql_query,
            marty_oid4vp_contract::QueryKind::PresentationExchange => {
                query == &self.presentation_definition
            }
        }
    }
}

pub(crate) fn freeze_flow_presentation_request(
    instance: &mut FlowInstanceRecord,
    policy_revision: FrozenPolicyIdentity,
    credential_authority: Option<
        marty_oid4vp_contract::trust_authority::CredentialAuthoritySnapshotV1,
    >,
    artifacts: &PresentationRequestArtifacts,
) -> Result<(), FlowPresentationRequestError> {
    let snapshot = FrozenFlowPresentationRequest {
        instance_id: instance.id.clone(),
        organization_id: instance.organization_id.clone(),
        nonce: instance.context["nonce"]
            .as_str()
            .ok_or(FlowPresentationRequestError::InvalidFrozenRequest)?
            .into(),
        policy_revision,
        credential_authority,
        presentation_definition: artifacts.presentation_definition.clone(),
        presentation_definition_digest: digest_query_document(&artifacts.presentation_definition)
            .map_err(|_| {
            FlowPresentationRequestError::InvalidFrozenRequest
        })?,
        dcql_query: artifacts.dcql_query.clone(),
        dcql_query_digest: digest_query_document(&artifacts.dcql_query)
            .map_err(|_| FlowPresentationRequestError::InvalidFrozenRequest)?,
    };
    validate_frozen_request(&snapshot, instance)?;
    instance.context[FROZEN_PRESENTATION_REQUEST_KEY] = serde_json::to_value(snapshot)
        .map_err(|_| FlowPresentationRequestError::InvalidFrozenRequest)?;
    Ok(())
}

pub(crate) fn load_frozen_flow_presentation_request(
    instance: &FlowInstanceRecord,
) -> Result<FrozenFlowPresentationRequest, FlowPresentationRequestError> {
    let value = instance
        .context
        .get(FROZEN_PRESENTATION_REQUEST_KEY)
        .ok_or(FlowPresentationRequestError::FrozenRequestMissing)?;
    let snapshot = serde_json::from_value(value.clone())
        .map_err(|_| FlowPresentationRequestError::InvalidFrozenRequest)?;
    validate_frozen_request(&snapshot, instance)?;
    Ok(snapshot)
}

fn validate_frozen_request(
    snapshot: &FrozenFlowPresentationRequest,
    instance: &FlowInstanceRecord,
) -> Result<(), FlowPresentationRequestError> {
    if snapshot.policy_revision.validate().is_err()
        || snapshot
            .credential_authority
            .as_ref()
            .is_some_and(|authority| {
                authority.validate().is_err()
                    || authority.organization_id != instance.organization_id
                    || instance.context["trust_profile_id"]
                        .as_str()
                        .is_some_and(|profile_id| profile_id != authority.profile.id)
            })
        || snapshot.instance_id != instance.id
        || snapshot.organization_id != instance.organization_id
        || snapshot.nonce.is_empty()
        || Some(snapshot.nonce.as_str()) != instance.context["nonce"].as_str()
        || Some(snapshot.policy_revision.id.as_str())
            != instance.context["presentation_policy_id"].as_str()
        || !snapshot.presentation_definition.is_object()
        || !snapshot.dcql_query.is_object()
        || digest_query_document(&snapshot.presentation_definition)
            .ok()
            .as_deref()
            != Some(snapshot.presentation_definition_digest.as_str())
        || digest_query_document(&snapshot.dcql_query).ok().as_deref()
            != Some(snapshot.dcql_query_digest.as_str())
    {
        return Err(FlowPresentationRequestError::InvalidFrozenRequest);
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq)]
pub struct ResolvedPresentationPolicy {
    pub policy: PresentationPolicyReference,
    pub requirements: Vec<(Value, CredentialTemplateReference)>,
}

pub async fn resolve_flow_presentation_policy(
    providers: &FlowProviderRegistry,
    presentation_policy_id: &str,
    organization_id: &str,
) -> Result<ResolvedPresentationPolicy, FlowPresentationRequestError> {
    if presentation_policy_id.trim().is_empty() || organization_id.trim().is_empty() {
        return Err(FlowPresentationRequestError::InvalidPolicy(
            "policy and organization are required".into(),
        ));
    }
    let policy_provider =
        providers
            .presentation_policy
            .as_ref()
            .ok_or(FlowProviderError::Unavailable {
                provider: "presentation_policy",
            })?;
    let template_provider =
        providers
            .credential_template
            .as_ref()
            .ok_or(FlowProviderError::Unavailable {
                provider: "credential_template",
            })?;
    let policy = policy_provider.get_policy(presentation_policy_id).await?;
    if policy.id != presentation_policy_id || policy.organization_id != organization_id {
        return Err(FlowPresentationRequestError::PolicyNotVisible);
    }
    if !policy.status.eq_ignore_ascii_case("active") {
        return Err(FlowPresentationRequestError::PolicyInactive);
    }
    if policy.policy_revision.id != policy.id || policy.policy_revision.validate().is_err() {
        return Err(FlowPresentationRequestError::InvalidPolicy(
            "policy revision is missing or invalid".into(),
        ));
    }
    match (
        &policy.prerequisite_evidence_profile,
        &policy.credential_authority,
    ) {
        (None, None) => {}
        (Some(profile), Some(authority))
            if profile == "managed_sd_jwt_dcql_v1"
                && authority.organization_id == organization_id
                && authority.validate().is_ok() => {}
        _ => {
            return Err(FlowPresentationRequestError::InvalidPolicy(
                "managed prerequisite authority is missing or invalid".into(),
            ))
        }
    }
    if policy.credential_requirements.is_empty() {
        return Err(FlowPresentationRequestError::InvalidPolicy(
            "policy has no credential requirements".into(),
        ));
    }
    let mut requirements = Vec::with_capacity(policy.credential_requirements.len());
    for (index, requirement) in policy.credential_requirements.iter().enumerate() {
        let object = requirement.as_object().ok_or_else(|| {
            FlowPresentationRequestError::InvalidPolicy(format!(
                "requirement {index} must be an object"
            ))
        })?;
        let template_id = object
            .get("credential_template_id")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                FlowPresentationRequestError::InvalidPolicy(format!(
                    "requirement {index} has no credential template"
                ))
            })?;
        let template = template_provider.get_template(template_id).await?;
        validate_template(&template, template_id, organization_id)?;
        requirements.push((requirement.clone(), template));
    }
    Ok(ResolvedPresentationPolicy {
        policy,
        requirements,
    })
}

pub async fn build_flow_presentation_request(
    providers: &FlowProviderRegistry,
    presentation_policy_id: &str,
    organization_id: &str,
) -> Result<PresentationRequestArtifacts, FlowPresentationRequestError> {
    let resolved =
        resolve_flow_presentation_policy(providers, presentation_policy_id, organization_id)
            .await?;
    build_resolved_flow_presentation_request(providers, &resolved).await
}

pub(crate) async fn build_resolved_flow_presentation_request(
    providers: &FlowProviderRegistry,
    resolved: &ResolvedPresentationPolicy,
) -> Result<PresentationRequestArtifacts, FlowPresentationRequestError> {
    let template_provider =
        providers
            .credential_template
            .as_ref()
            .ok_or(FlowProviderError::Unavailable {
                provider: "credential_template",
            })?;
    let mut requirements = Vec::with_capacity(resolved.requirements.len());
    for (index, (requirement, template)) in resolved.requirements.iter().enumerate() {
        let object = requirement.as_object().ok_or_else(|| {
            FlowPresentationRequestError::InvalidPolicy(format!(
                "requirement {index} must be an object"
            ))
        })?;
        requirements.push(PresentationRequirementInput {
            id: optional_string(object.get("id")),
            display_name: optional_string(object.get("display_name")),
            description: optional_string(object.get("description")),
            credential_type: nonempty(&template.credential_type),
            credential_vct: nonempty(&template.vct),
            credential_doctype: nonempty(&template.doctype),
            supported_formats: template.supported_formats.clone(),
            requested_claims: requested_claims(object.get("requested_claims"), index)?,
            mdoc_claims: template
                .claims
                .iter()
                .filter(|claim| !claim.mdoc_namespace.trim().is_empty())
                .map(|claim| MdocClaimInput {
                    claim_name: claim.name.clone(),
                    namespace: claim.mdoc_namespace.clone(),
                    element_identifier: if claim.mdoc_element_identifier.trim().is_empty() {
                        claim.name.clone()
                    } else {
                        claim.mdoc_element_identifier.clone()
                    },
                })
                .collect(),
        });
    }
    let wallet_formats = template_provider
        .wallet_formats(&resolved.policy.organization_id)
        .await?;
    build_presentation_request(PresentationRequestBuildInput {
        id: Uuid::new_v4().to_string(),
        requirements,
        wallet_formats,
    })
    .map_err(|error| FlowPresentationRequestError::Native(error.to_string()))
}

fn validate_template(
    template: &CredentialTemplateReference,
    template_id: &str,
    organization_id: &str,
) -> Result<(), FlowPresentationRequestError> {
    if template.id != template_id || template.organization_id != organization_id {
        return Err(FlowPresentationRequestError::TemplateNotVisible);
    }
    if !template.status.eq_ignore_ascii_case("active") {
        return Err(FlowPresentationRequestError::TemplateInactive);
    }
    if template.supported_formats.is_empty() {
        return Err(FlowPresentationRequestError::InvalidTemplate(
            template_id.into(),
        ));
    }
    Ok(())
}

fn requested_claims(
    value: Option<&Value>,
    requirement_index: usize,
) -> Result<Vec<RequestedClaimInput>, FlowPresentationRequestError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let values = value.as_array().ok_or_else(|| {
        FlowPresentationRequestError::InvalidPolicy(format!(
            "requirement {requirement_index} requested_claims must be an array"
        ))
    })?;
    values
        .iter()
        .enumerate()
        .map(|(claim_index, value)| {
            let object = value.as_object().ok_or_else(|| {
                FlowPresentationRequestError::InvalidPolicy(format!(
                    "requirement {requirement_index} claim {claim_index} must be an object"
                ))
            })?;
            let claim_name = object
                .get("claim_name")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| {
                    FlowPresentationRequestError::InvalidPolicy(format!(
                        "requirement {requirement_index} claim {claim_index} has no name"
                    ))
                })?;
            Ok(RequestedClaimInput {
                claim_name: claim_name.into(),
                display_name: optional_string(object.get("display_name")),
                purpose: optional_string(object.get("purpose")),
                required: object
                    .get("required")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                intent_to_retain: object
                    .get("intent_to_retain")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            })
        })
        .collect()
}

fn optional_string(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn nonempty(value: &str) -> Option<String> {
    (!value.trim().is_empty()).then(|| value.to_owned())
}
