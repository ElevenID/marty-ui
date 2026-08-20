use marty_oid4vci::presentation_request::{
    build_presentation_request, MdocClaimInput, PresentationRequestArtifacts,
    PresentationRequestBuildInput, PresentationRequirementInput, RequestedClaimInput,
};
use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

use crate::{CredentialTemplateReference, FlowProviderError, FlowProviderRegistry};

#[derive(Debug, Error)]
pub enum FlowPresentationRequestError {
    #[error(transparent)]
    Provider(#[from] FlowProviderError),
    #[error("FLOW.PRESENTATION_REQUEST_INVALID_POLICY: {0}")]
    InvalidPolicy(String),
    #[error("FLOW.PRESENTATION_REQUEST_INVALID_TEMPLATE: {0}")]
    InvalidTemplate(String),
    #[error("FLOW.PRESENTATION_REQUEST_NATIVE: {0}")]
    Native(String),
}

pub async fn build_flow_presentation_request(
    providers: &FlowProviderRegistry,
    presentation_policy_id: &str,
    organization_id: &str,
) -> Result<PresentationRequestArtifacts, FlowPresentationRequestError> {
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
    if policy.id != presentation_policy_id
        || policy.organization_id != organization_id
        || !policy.status.eq_ignore_ascii_case("active")
        || policy.credential_requirements.is_empty()
    {
        return Err(FlowPresentationRequestError::InvalidPolicy(
            "policy identity, tenant, status, or requirements are invalid".into(),
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
    let wallet_formats = template_provider.wallet_formats().await?;
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
    if template.id != template_id
        || template.organization_id != organization_id
        || !template.status.eq_ignore_ascii_case("active")
        || template.supported_formats.is_empty()
    {
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
