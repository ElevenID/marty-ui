use std::collections::{BTreeMap, BTreeSet};

use crate::{
    CredentialTemplateReference, FlowProviderError, FlowProviderRegistry, FlowReference,
    FlowReferenceKind,
};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FlowDefinitionReferenceSet {
    pub credential_template_id: Option<String>,
    pub application_template_id: Option<String>,
    pub presentation_policy_id: Option<String>,
    pub delivery_destination_profile_id: Option<String>,
    pub deployment_profile_ids: Vec<String>,
    pub trust_profile_id: Option<String>,
}

pub async fn validate_definition_references(
    providers: &FlowProviderRegistry,
    principal_id: &str,
    organization_id: &str,
    references: &FlowDefinitionReferenceSet,
    require_active: bool,
) -> Result<(), FlowProviderError> {
    if principal_id.trim().is_empty() || organization_id.trim().is_empty() {
        return Err(rejected("principal and organization must be bound"));
    }

    let templates =
        providers
            .credential_template
            .as_ref()
            .ok_or(FlowProviderError::Unavailable {
                provider: "credential_template",
            })?;
    let policies =
        providers
            .presentation_policy
            .as_ref()
            .ok_or(FlowProviderError::Unavailable {
                provider: "presentation_policy",
            })?;
    let signing = providers
        .signing_identity
        .as_ref()
        .ok_or(FlowProviderError::Unavailable {
            provider: "signing_identity",
        })?;
    let catalog = providers
        .reference_catalog
        .as_ref()
        .ok_or(FlowProviderError::Unavailable {
            provider: "reference_catalog",
        })?;

    let mut template_cache = BTreeMap::new();
    if let Some(template_id) = references.credential_template_id.as_deref() {
        validate_template(
            templates.as_ref(),
            signing.as_ref(),
            organization_id,
            template_id,
            require_active,
            &mut template_cache,
        )
        .await?;
    }

    if let Some(policy_id) = references.presentation_policy_id.as_deref() {
        let policy = policies.get_policy(policy_id).await?;
        if policy.id != policy_id || policy.organization_id != organization_id {
            return Err(rejected("presentation policy is not bound to the tenant"));
        }
        require_active_status("presentation policy", &policy.status, require_active)?;
        for requirement in policy.credential_requirements {
            if let Some(template_id) = requirement
                .as_object()
                .and_then(|value| value.get("credential_template_id"))
                .and_then(serde_json::Value::as_str)
                .filter(|value| !value.trim().is_empty())
            {
                validate_template(
                    templates.as_ref(),
                    signing.as_ref(),
                    organization_id,
                    template_id,
                    require_active,
                    &mut template_cache,
                )
                .await?;
            }
        }
    }

    for (kind, reference_id) in catalog_references(references) {
        let reference = catalog.resolve(kind, reference_id, principal_id).await?;
        validate_catalog_reference(
            kind,
            reference_id,
            organization_id,
            &reference,
            require_active,
        )?;
    }
    Ok(())
}

async fn validate_template(
    templates: &dyn crate::CredentialTemplateProvider,
    signing: &dyn crate::SigningIdentityProvider,
    organization_id: &str,
    template_id: &str,
    require_active: bool,
    cache: &mut BTreeMap<String, CredentialTemplateReference>,
) -> Result<(), FlowProviderError> {
    let template = if let Some(template) = cache.get(template_id) {
        template.clone()
    } else {
        let template = templates.get_template(template_id).await?;
        cache.insert(template_id.to_owned(), template.clone());
        template
    };
    if template.id != template_id || template.organization_id != organization_id {
        return Err(rejected("credential template is not bound to the tenant"));
    }
    require_active_status("credential template", &template.status, require_active)?;
    if !template.issuer_did.starts_with("did:") {
        return Err(rejected("credential template has no issuer DID"));
    }
    let credential_format = canonical_signing_format(&template.credential_format);
    if credential_format.is_empty() {
        return Err(rejected("credential template has no credential format"));
    }
    let key_purpose = key_purpose(credential_format);
    let identity = signing
        .resolve(
            organization_id,
            &template.issuer_did,
            key_purpose,
            credential_format,
            template.issuer_algorithm.as_deref(),
        )
        .await?;
    identity.validate_binding(
        organization_id,
        &template.issuer_did,
        key_purpose,
        credential_format,
        template.issuer_algorithm.as_deref(),
    )
}

fn catalog_references(references: &FlowDefinitionReferenceSet) -> Vec<(FlowReferenceKind, &str)> {
    let mut values = Vec::new();
    for (kind, value) in [
        (
            FlowReferenceKind::ApplicationTemplate,
            references.application_template_id.as_deref(),
        ),
        (
            FlowReferenceKind::DeliveryDestination,
            references.delivery_destination_profile_id.as_deref(),
        ),
        (
            FlowReferenceKind::TrustProfile,
            references.trust_profile_id.as_deref(),
        ),
    ] {
        if let Some(value) = value {
            values.push((kind, value));
        }
    }
    let mut seen = BTreeSet::new();
    for profile_id in &references.deployment_profile_ids {
        if seen.insert(profile_id.as_str()) {
            values.push((FlowReferenceKind::DeploymentProfile, profile_id));
        }
    }
    values
}

fn validate_catalog_reference(
    expected_kind: FlowReferenceKind,
    expected_id: &str,
    organization_id: &str,
    reference: &FlowReference,
    require_active: bool,
) -> Result<(), FlowProviderError> {
    if reference.kind != expected_kind || reference.id != expected_id {
        return Err(rejected("reference owner returned a mismatched identity"));
    }
    let tenant_matches = reference.organization_id.as_deref() == Some(organization_id);
    let system_delivery =
        expected_kind == FlowReferenceKind::DeliveryDestination && reference.system_owned;
    if !(tenant_matches || system_delivery) {
        return Err(rejected("reference is not bound to the tenant"));
    }
    if require_active && !reference.is_active() {
        return Err(rejected("reference must be active before activation"));
    }
    Ok(())
}

fn require_active_status(
    kind: &str,
    status: &str,
    require_active: bool,
) -> Result<(), FlowProviderError> {
    if require_active && !status.eq_ignore_ascii_case("active") {
        Err(rejected(&format!(
            "{kind} must be active before activation"
        )))
    } else {
        Ok(())
    }
}

fn canonical_signing_format(value: &str) -> &str {
    match value.trim().to_ascii_lowercase().as_str() {
        "sd_jwt_vc" | "ietf_sd_jwt" | "w3c_vcdm_v2_sd_jwt" | "vc+sd-jwt" => "dc+sd-jwt",
        "jwt_vc" | "vc_jwt" | "w3c_vcdm_v2_jwt_vc" => "jwt_vc_json",
        "json_ld" | "json-ld" => "ldp_vc",
        "mdoc" => "mso_mdoc",
        _ => value.trim(),
    }
}

fn key_purpose(credential_format: &str) -> &'static str {
    match credential_format {
        "mso_mdoc" | "zk_mdoc" => "mdoc_dsc",
        "vds_nc" | "vdsnc" => "vdsnc_signing",
        _ => "vc_jwt_issuer",
    }
}

fn rejected(message: &str) -> FlowProviderError {
    FlowProviderError::Rejected {
        provider: "reference_validation",
        message: message.to_owned(),
    }
}
