use std::collections::BTreeMap;

use marty_oid4vci::lti::{verify_lti_launch_jwt, VerifiedLtiLaunch};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

use crate::canvas_lti_login::CanvasLtiPlatform;

const CUSTOM_CLAIM: &str = "https://purl.imsglobal.org/spec/lti/claim/custom";
const RESOURCE_LINK_CLAIM: &str = "https://purl.imsglobal.org/spec/lti/claim/resource_link";
const MESSAGE_TYPE_CLAIM: &str = "https://purl.imsglobal.org/spec/lti/claim/message_type";
const DEEP_LINKING_CLAIM: &str =
    "https://purl.imsglobal.org/spec/lti-dl/claim/deep_linking_settings";
const AGS_ENDPOINT_CLAIM: &str = "https://purl.imsglobal.org/spec/lti-ags/claim/endpoint";
const NRPS_CLAIM: &str = "https://purl.imsglobal.org/spec/lti-nrps/claim/namesroleservice";

const FEATURE_FLAGS: [&str; 8] = [
    "enable_background_awards",
    "enable_canvas_ags",
    "enable_canvas_deep_linking",
    "enable_canvas_evidence",
    "enable_canvas_lti",
    "enable_canvas_mirror_ops",
    "enable_canvas_mirror_publish",
    "enable_canvas_nrps",
];

#[derive(Clone, Debug, PartialEq)]
pub struct CanvasLtiProgramBinding {
    pub id: String,
    pub organization_id: String,
    pub platform_id: String,
    pub application_template_id: String,
    pub credential_template_id: String,
    pub delivery_mode: String,
    pub deployment_profile_id: Option<String>,
    pub feature_flags: Value,
    pub evidence_requirements: Vec<Value>,
    pub canvas_scope: Value,
    pub enabled: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct CanvasLtiVerifiedLaunchResponse {
    pub organization_id: String,
    pub canvas_account_id: String,
    pub canvas_platform_id: String,
    pub canvas_program_binding_id: String,
    pub application_template_id: String,
    pub credential_template_id: String,
    pub delivery_mode: String,
    pub deployment_profile_id: Option<String>,
    pub feature_flags: BTreeMap<String, bool>,
    pub evidence_requirements: Vec<Value>,
    pub state: String,
    pub verified: bool,
    pub issuer: String,
    pub subject: String,
    pub audience: Vec<String>,
    pub deployment_id: String,
    pub nonce: Option<String>,
    pub issued_at: Option<u64>,
    pub expires_at: Option<u64>,
    pub message_type: Option<String>,
    pub lti_version: Option<String>,
    pub target_link_uri: Option<String>,
    pub context: Option<Value>,
    pub roles: Vec<String>,
    pub learner_identity: Value,
    pub raw_claims: Value,
    pub lti_capabilities: Value,
    pub identity_mapping_status: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CanvasLtiPublicLaunchResponse {
    pub verified: bool,
    pub organization_id: String,
    pub canvas_account_id: String,
    pub canvas_platform_id: String,
    pub canvas_program_binding_id: String,
    pub application_template_id: Option<String>,
    pub credential_template_id: Option<String>,
    pub message_type: Option<String>,
    pub context: BTreeMap<String, Value>,
    pub roles: Vec<String>,
    pub identity_mapping_status: Option<String>,
}

#[derive(Debug, Error)]
pub enum CanvasLtiLaunchPlanError {
    #[error("Canvas LTI launch verification failed: {0}")]
    Verification(String),
    #[error("Canvas LTI launch did not match an enabled Canvas program binding")]
    BindingNotFound,
    #[error("Canvas LTI is disabled for this deployment profile")]
    FeatureDisabled,
}

pub fn verify_launch(
    platform: &CanvasLtiPlatform,
    id_token: &str,
    expected_nonce: &str,
) -> Result<VerifiedLtiLaunch, CanvasLtiLaunchPlanError> {
    let issuer = platform.lti_issuer.as_deref().unwrap_or_default();
    let client_id = platform.lti_client_id.as_deref().unwrap_or_default();
    let deployment_id = platform.lti_deployment_id.as_deref().unwrap_or_default();
    let jwks = serde_json::to_string(platform.lti_jwks_json.as_ref().unwrap_or(&Value::Null))
        .map_err(|error| CanvasLtiLaunchPlanError::Verification(error.to_string()))?;
    verify_lti_launch_jwt(
        id_token,
        issuer,
        client_id,
        deployment_id,
        &jwks,
        Some(expected_nonce),
        120,
    )
    .map_err(|error| CanvasLtiLaunchPlanError::Verification(error.to_string()))
}

pub fn select_binding<'a>(
    platform: &CanvasLtiPlatform,
    verified: &VerifiedLtiLaunch,
    bindings: &'a [CanvasLtiProgramBinding],
) -> Result<&'a CanvasLtiProgramBinding, CanvasLtiLaunchPlanError> {
    let actual_scope = launch_scope(verified, &platform.canvas_account_id);
    let binding = bindings
        .iter()
        .find(|binding| {
            binding.enabled
                && binding.organization_id == platform.organization_id
                && binding.platform_id == platform.id
                && scope_matches(&binding.canvas_scope, &actual_scope)
        })
        .ok_or(CanvasLtiLaunchPlanError::BindingNotFound)?;
    if !feature_enabled(&binding.feature_flags, "enable_canvas_lti") {
        return Err(CanvasLtiLaunchPlanError::FeatureDisabled);
    }
    Ok(binding)
}

#[must_use]
pub fn private_launch_response(
    platform: &CanvasLtiPlatform,
    binding: &CanvasLtiProgramBinding,
    state: &str,
    verified: VerifiedLtiLaunch,
    identity_mapping_status: Option<String>,
) -> CanvasLtiVerifiedLaunchResponse {
    let lti_capabilities = lti_capabilities(platform, binding, &verified);
    CanvasLtiVerifiedLaunchResponse {
        organization_id: platform.organization_id.clone(),
        canvas_account_id: platform.canvas_account_id.clone(),
        canvas_platform_id: platform.id.clone(),
        canvas_program_binding_id: binding.id.clone(),
        application_template_id: binding.application_template_id.clone(),
        credential_template_id: binding.credential_template_id.clone(),
        delivery_mode: if binding.delivery_mode.is_empty() {
            "wallet_only".to_owned()
        } else {
            binding.delivery_mode.clone()
        },
        deployment_profile_id: binding.deployment_profile_id.clone(),
        feature_flags: normalized_feature_flags(&binding.feature_flags),
        evidence_requirements: binding.evidence_requirements.clone(),
        state: state.to_owned(),
        verified: true,
        issuer: verified.issuer,
        subject: verified.subject,
        audience: verified.audience,
        deployment_id: verified.deployment_id,
        nonce: verified.nonce,
        issued_at: verified.issued_at,
        expires_at: verified.expires_at,
        message_type: verified.message_type,
        lti_version: verified.lti_version,
        target_link_uri: verified.target_link_uri,
        context: verified.context,
        roles: verified.roles,
        learner_identity: verified.learner_identity,
        raw_claims: verified.raw_claims,
        lti_capabilities,
        identity_mapping_status,
    }
}

#[must_use]
pub fn public_launch_response(
    response: &CanvasLtiVerifiedLaunchResponse,
) -> CanvasLtiPublicLaunchResponse {
    CanvasLtiPublicLaunchResponse {
        verified: response.verified,
        organization_id: response.organization_id.clone(),
        canvas_account_id: response.canvas_account_id.clone(),
        canvas_platform_id: response.canvas_platform_id.clone(),
        canvas_program_binding_id: response.canvas_program_binding_id.clone(),
        application_template_id: Some(response.application_template_id.clone()),
        credential_template_id: Some(response.credential_template_id.clone()),
        message_type: response.message_type.clone(),
        context: browser_safe_context(response),
        roles: response
            .roles
            .iter()
            .map(|role| role.rsplit('/').next().unwrap_or(role).to_owned())
            .collect(),
        identity_mapping_status: response.identity_mapping_status.clone(),
    }
}

#[must_use]
pub fn launch_scope(verified: &VerifiedLtiLaunch, canvas_account_id: &str) -> Map<String, Value> {
    let custom = claim_object(&verified.raw_claims, CUSTOM_CLAIM, "custom");
    let resource_link = claim_object(&verified.raw_claims, RESOURCE_LINK_CLAIM, "resource_link");
    let context = verified.context.as_ref().and_then(Value::as_object);
    let course_id = custom
        .and_then(|values| values.get("canvas_course_id"))
        .or_else(|| context.and_then(|values| values.get("id")))
        .or_else(|| context.and_then(|values| values.get("context_id")))
        .or_else(|| verified.raw_claims.get("context_id"));
    let mut scope = Map::new();
    insert_value(
        &mut scope,
        "canvas_account_id",
        custom
            .and_then(|values| values.get("canvas_account_id"))
            .cloned()
            .unwrap_or_else(|| Value::String(canvas_account_id.to_owned())),
    );
    for key in [
        "course_id",
        "canvas_course_id",
        "canvas_context_id",
        "context_id",
    ] {
        if let Some(value) = course_id.cloned() {
            insert_value(&mut scope, key, value);
        }
    }
    if let Some(value) = resource_link.and_then(|values| values.get("id")).cloned() {
        insert_value(&mut scope, "resource_link_id", value);
    }
    for key in ["subject_id", "lti_subject"] {
        insert_value(&mut scope, key, Value::String(verified.subject.clone()));
    }
    if let Some(value) = custom
        .and_then(|values| values.get("canvas_user_id"))
        .cloned()
    {
        insert_value(&mut scope, "user_id", value.clone());
        insert_value(&mut scope, "canvas_user_id", value);
    }
    scope
}

#[must_use]
pub fn scope_matches(expected: &Value, actual: &Map<String, Value>) -> bool {
    if expected.is_null() {
        return true;
    }
    let Some(expected) = expected.as_object() else {
        return false;
    };
    expected.iter().all(|(key, expected_value)| {
        if is_empty(expected_value) {
            return true;
        }
        std::iter::once(key.as_str())
            .chain(aliases(key).iter().copied())
            .find_map(|alias| actual.get(alias).filter(|value| !is_empty(value)))
            .is_some_and(|actual_value| {
                scalar_string(actual_value) == scalar_string(expected_value)
            })
    })
}

#[must_use]
pub fn feature_enabled(flags: &Value, flag: &str) -> bool {
    let normalized = normalized_feature_flags(flags);
    normalized.is_empty() || normalized.get(flag).copied().unwrap_or(false)
}

fn normalized_feature_flags(flags: &Value) -> BTreeMap<String, bool> {
    let Some(flags) = flags.as_object() else {
        return BTreeMap::new();
    };
    FEATURE_FLAGS
        .iter()
        .filter_map(|key| {
            flags
                .get(*key)
                .map(|value| ((*key).to_owned(), truthy(value)))
        })
        .collect()
}

fn lti_capabilities(
    platform: &CanvasLtiPlatform,
    binding: &CanvasLtiProgramBinding,
    verified: &VerifiedLtiLaunch,
) -> Value {
    let message_type = verified
        .message_type
        .as_deref()
        .or_else(|| {
            verified
                .raw_claims
                .get(MESSAGE_TYPE_CLAIM)
                .and_then(Value::as_str)
        })
        .or_else(|| {
            verified
                .raw_claims
                .get("message_type")
                .and_then(Value::as_str)
        })
        .unwrap_or_default();
    let deep_linking = claim_object(
        &verified.raw_claims,
        DEEP_LINKING_CLAIM,
        "deep_linking_settings",
    );
    let ags = claim_object(&verified.raw_claims, AGS_ENDPOINT_CLAIM, "ags_endpoint");
    let nrps = claim_object(&verified.raw_claims, NRPS_CLAIM, "names_roles_service");
    let requirements = if binding.evidence_requirements.is_empty() {
        vec![Value::String("canvas.course_completion".to_owned())]
    } else {
        binding.evidence_requirements.clone()
    };
    serde_json::json!({
        "message_type": (!message_type.is_empty()).then_some(message_type),
        "resource_link": message_type == "LtiResourceLinkRequest",
        "deep_linking": deep_linking.is_some_and(|claim| !claim.is_empty()) || message_type == "LtiDeepLinkingRequest",
        "assignment_grade_services": ags.is_some_and(|claim| !claim.is_empty()),
        "names_roles": nrps.is_some_and(|claim| !claim.is_empty()),
        "deep_link_return_url": object_value(deep_linking, "deep_link_return_url"),
        "deep_link_accept_types": string_list(object_value(deep_linking, "accept_types")),
        "deep_link_accept_presentation_document_targets": string_list(object_value(deep_linking, "accept_presentation_document_targets")),
        "ags_lineitems_url": object_value(ags, "lineitems"),
        "ags_lineitem_url": object_value(ags, "lineitem"),
        "ags_scopes": string_list(object_value(ags, "scope")),
        "nrps_context_memberships_url": object_value(nrps, "context_memberships_url"),
        "supported_scopes": openid_string_list(platform, "scopes_supported"),
        "supported_claims": openid_string_list(platform, "claims_supported"),
        "binding_evidence_fact_types": evidence_fact_types(&requirements),
    })
}

fn object_value<'a>(object: Option<&'a Map<String, Value>>, key: &str) -> Option<&'a Value> {
    object.and_then(|object| object.get(key))
}

fn string_list(value: Option<&Value>) -> Vec<String> {
    match value {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::String(value)) => (!value.is_empty())
            .then(|| value.clone())
            .into_iter()
            .collect(),
        Some(Value::Array(values)) => values
            .iter()
            .filter(|value| !value.is_null())
            .map(scalar_string)
            .filter(|value| !value.is_empty())
            .collect(),
        Some(value) => {
            let value = scalar_string(value);
            (!value.is_empty()).then_some(value).into_iter().collect()
        }
    }
}

fn openid_string_list(platform: &CanvasLtiPlatform, key: &str) -> Vec<String> {
    unique_strings(string_list(
        platform
            .lti_openid_configuration
            .as_ref()
            .and_then(|configuration| configuration.get(key)),
    ))
}

fn evidence_fact_types(requirements: &[Value]) -> Vec<String> {
    unique_strings(
        requirements
            .iter()
            .filter_map(|requirement| match requirement {
                Value::String(value) => Some(value.clone()),
                Value::Object(value) => ["fact_type", "evidence_type", "type"]
                    .iter()
                    .find_map(|key| value.get(*key).filter(|value| !is_empty(value)))
                    .map(scalar_string),
                _ => None,
            })
            .collect(),
    )
}

fn unique_strings(values: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    values
        .into_iter()
        .filter(|value| !value.is_empty() && seen.insert(value.clone()))
        .collect()
}

fn browser_safe_context(response: &CanvasLtiVerifiedLaunchResponse) -> BTreeMap<String, Value> {
    let context = response.context.as_ref().and_then(Value::as_object);
    let custom = claim_object(&response.raw_claims, CUSTOM_CLAIM, "custom");
    let mut result = BTreeMap::new();
    let course_id = custom
        .and_then(|values| values.get("canvas_course_id"))
        .or_else(|| context.and_then(|values| values.get("id")))
        .or_else(|| context.and_then(|values| values.get("context_id")));
    for (name, value) in [
        ("course_id", course_id),
        ("title", context.and_then(|values| values.get("title"))),
        ("label", context.and_then(|values| values.get("label"))),
    ] {
        if let Some(value) = value.filter(|value| !is_empty(value)) {
            result.insert(name.to_owned(), value.clone());
        }
    }
    result
}

fn claim_object<'a>(
    raw: &'a Value,
    canonical: &str,
    legacy: &str,
) -> Option<&'a Map<String, Value>> {
    raw.get(canonical)
        .and_then(Value::as_object)
        .or_else(|| raw.get(legacy).and_then(Value::as_object))
}

fn aliases(key: &str) -> &'static [&'static str] {
    match key {
        "canvas_account_id" | "account_id" => &["canvas_account_id", "account_id"],
        "course_id" | "canvas_course_id" | "canvas_context_id" | "context_id" => &[
            "course_id",
            "canvas_course_id",
            "canvas_context_id",
            "context_id",
        ],
        "assignment_id" | "canvas_assignment_id" => {
            &["assignment_id", "canvas_assignment_id", "resource_link_id"]
        }
        "module_id" | "canvas_module_id" => &["module_id", "canvas_module_id"],
        "quiz_id" | "canvas_quiz_id" => &["quiz_id", "canvas_quiz_id"],
        "user_id" | "canvas_user_id" => &["user_id", "canvas_user_id"],
        "subject_id" | "lti_subject" => &["subject_id", "lti_subject"],
        "enrollment_id" | "canvas_enrollment_id" => &["enrollment_id", "canvas_enrollment_id"],
        _ => &[],
    }
}

fn insert_value(target: &mut Map<String, Value>, key: &str, value: Value) {
    if !is_empty(&value) {
        target.insert(key.to_owned(), value);
    }
}

fn is_empty(value: &Value) -> bool {
    value.is_null() || value.as_str().is_some_and(str::is_empty)
}

fn scalar_string(value: &Value) -> String {
    match value {
        Value::Null => "None".to_owned(),
        Value::Bool(true) => "True".to_owned(),
        Value::Bool(false) => "False".to_owned(),
        Value::String(value) => value.clone(),
        _ => value.to_string(),
    }
}

fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64().is_some_and(|value| value != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
    }
}
