use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug)]
pub struct DeploymentContractError;

#[derive(Clone, Copy)]
pub enum DeploymentResponseKind {
    Profile,
    Profiles,
    Lane,
    Lanes,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Callbacks {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    issuance_complete_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    verification_complete_url: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FeatureFlags {
    #[serde(default = "yes")]
    enable_selective_disclosure: bool,
    #[serde(default = "yes")]
    enable_derived_attributes: bool,
    #[serde(default)]
    enable_batch_issuance: bool,
    #[serde(default = "yes")]
    enable_deferred_issuance: bool,
    #[serde(default = "yes")]
    enable_credential_refresh: bool,
    #[serde(default = "yes")]
    enable_qr_code_generation: bool,
    #[serde(default)]
    enable_push_notifications: bool,
    #[serde(default)]
    enable_biometric_binding: bool,
    #[serde(default)]
    enable_canvas_evidence: bool,
    #[serde(default)]
    enable_canvas_lti: bool,
    #[serde(default)]
    enable_canvas_mirror_publish: bool,
    #[serde(default)]
    enable_canvas_mirror_ops: bool,
    #[serde(default)]
    enable_canvas_deep_linking: bool,
    #[serde(default)]
    enable_canvas_ags: bool,
    #[serde(default)]
    enable_canvas_nrps: bool,
    #[serde(default)]
    custom_flags: std::collections::BTreeMap<String, bool>,
}

const fn yes() -> bool {
    true
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProfileCreate {
    organization_id: String,
    name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    activate_immediately: Option<bool>,
    #[serde(default = "development")]
    environment: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    callbacks: Option<Callbacks>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    feature_flags: Option<FeatureFlags>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    trust_profile_id: Option<String>,
    #[serde(default)]
    presentation_policy_ids: Vec<String>,
    #[serde(default)]
    credential_template_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    default_policy_id: Option<String>,
    #[serde(default)]
    enabled_flow_ids: Vec<String>,
    #[serde(default = "online")]
    network_mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    environment_config: Option<serde_json::Map<String, Value>>,
    #[serde(default = "stable")]
    update_channel: String,
}

fn development() -> String {
    "development".into()
}

fn online() -> String {
    "ONLINE".into()
}

fn stable() -> String {
    "stable".into()
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProfileUpdate {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    trust_profile_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    presentation_policy_ids: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    credential_template_ids: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    default_policy_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    network_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key_access_mode: Option<String>,
    #[serde(
        default,
        alias = "biometric_required",
        skip_serializing_if = "Option::is_none"
    )]
    operator_biometric_authentication_required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    environment_config: Option<serde_json::Map<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    feature_flags: Option<FeatureFlags>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LaneCreate {
    name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    location: Option<String>,
    #[serde(default = "kiosk")]
    device_type: String,
}

fn kiosk() -> String {
    "kiosk".into()
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DeviceAssignment {
    device_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    device_name: Option<String>,
}

pub fn canonicalize_request(
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<Option<Vec<u8>>, DeploymentContractError> {
    let canonical = if method == "POST" && path == "/v1/deployment-profiles" {
        let value: ProfileCreate = parse(body)?;
        validate_profile_create(&value)?;
        Some(serde_json::to_vec(&value).map_err(|_| DeploymentContractError)?)
    } else if method == "PATCH" && profile_id(path).is_some() {
        let value: ProfileUpdate = parse(body)?;
        validate_profile_update(&value)?;
        Some(serde_json::to_vec(&value).map_err(|_| DeploymentContractError)?)
    } else if matches!(method, "POST" | "PUT") && lane_collection_or_item(path, method) {
        let value: LaneCreate = parse(body)?;
        validate_string(&value.name, 1, usize::MAX)?;
        validate_string(&value.device_type, 1, usize::MAX)?;
        Some(serde_json::to_vec(&value).map_err(|_| DeploymentContractError)?)
    } else if method == "POST" && device_assignment_path(path) {
        let value: DeviceAssignment = parse(body)?;
        validate_string(&value.device_id, 1, usize::MAX)?;
        Some(serde_json::to_vec(&value).map_err(|_| DeploymentContractError)?)
    } else {
        None
    };
    Ok(canonical)
}

fn validate_profile_create(value: &ProfileCreate) -> Result<(), DeploymentContractError> {
    validate_string(&value.organization_id, 1, 255)?;
    validate_string(&value.name, 1, 255)?;
    validate_optional(&value.description, 2000)?;
    validate_optional(&value.status, 50)?;
    validate_string(&value.environment, 0, 50)?;
    validate_optional(&value.trust_profile_id, 255)?;
    validate_optional(&value.default_policy_id, 255)?;
    validate_string(&value.network_mode, 0, 50)?;
    validate_string(&value.update_channel, 0, 50)?;
    validate_ids(&value.presentation_policy_ids)?;
    validate_ids(&value.credential_template_ids)?;
    validate_ids(&value.enabled_flow_ids)
}

fn validate_profile_update(value: &ProfileUpdate) -> Result<(), DeploymentContractError> {
    validate_optional(&value.name, usize::MAX)?;
    validate_optional(&value.description, usize::MAX)?;
    validate_optional(&value.status, usize::MAX)?;
    validate_optional(&value.trust_profile_id, usize::MAX)?;
    validate_optional(&value.default_policy_id, usize::MAX)?;
    validate_optional(&value.network_mode, usize::MAX)?;
    validate_optional(&value.key_access_mode, usize::MAX)?;
    if let Some(ids) = &value.presentation_policy_ids {
        validate_ids(ids)?;
    }
    if let Some(ids) = &value.credential_template_ids {
        validate_ids(ids)?;
    }
    Ok(())
}

fn validate_ids(values: &[String]) -> Result<(), DeploymentContractError> {
    values
        .iter()
        .try_for_each(|value| validate_string(value, 0, usize::MAX))
}

fn validate_optional(value: &Option<String>, max: usize) -> Result<(), DeploymentContractError> {
    value
        .as_ref()
        .map_or(Ok(()), |value| validate_string(value, 0, max))
}

fn validate_string(value: &str, min: usize, max: usize) -> Result<(), DeploymentContractError> {
    (value.len() >= min && value.len() <= max)
        .then_some(())
        .ok_or(DeploymentContractError)
}

fn parse<T: for<'de> Deserialize<'de>>(body: &[u8]) -> Result<T, DeploymentContractError> {
    serde_json::from_slice(body).map_err(|_| DeploymentContractError)
}

pub fn create_dependencies(
    value: &Value,
) -> Result<DeploymentDependencies, DeploymentContractError> {
    let profile: ProfileCreate =
        serde_json::from_value(value.clone()).map_err(|_| DeploymentContractError)?;
    Ok(DeploymentDependencies {
        organization_id: profile.organization_id,
        trust_profile_id: profile.trust_profile_id,
        presentation_policy_ids: profile.presentation_policy_ids,
        credential_template_ids: profile.credential_template_ids,
        default_policy_id: profile.default_policy_id,
    })
}

pub struct DeploymentDependencies {
    pub organization_id: String,
    pub trust_profile_id: Option<String>,
    pub presentation_policy_ids: Vec<String>,
    pub credential_template_ids: Vec<String>,
    pub default_policy_id: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProfileResponse {
    id: String,
    organization_id: String,
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    environment: Option<String>,
    #[serde(default)]
    callbacks: Option<Value>,
    #[serde(default)]
    feature_flags: Option<Value>,
    #[serde(default)]
    trust_profile_id: Option<String>,
    #[serde(default)]
    presentation_policy_ids: Vec<String>,
    #[serde(default)]
    credential_template_ids: Vec<String>,
    #[serde(default)]
    enabled_flow_ids: Vec<String>,
    default_policy_id: Option<String>,
    #[serde(default)]
    network_mode: Option<String>,
    #[serde(default)]
    key_access_mode: Option<String>,
    #[serde(default)]
    environment_config: Option<Value>,
    #[serde(default)]
    update_channel: Option<String>,
    #[serde(default)]
    update_policy: Option<Value>,
    #[serde(default)]
    offline_cache_ttl_hours: Option<i64>,
    #[serde(default)]
    operator_biometric_authentication_required: Option<bool>,
    #[serde(default)]
    audit_all_events: Option<bool>,
    #[serde(default)]
    canvas_feature_flags: std::collections::BTreeMap<String, bool>,
    #[serde(default)]
    lanes: Vec<Value>,
    #[serde(default)]
    api_key_prefix: Option<String>,
    created_at: String,
    updated_at: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LaneResponse {
    id: String,
    deployment_profile_id: String,
    name: String,
    description: Option<String>,
    location: Option<String>,
    device_type: String,
    device_count: i64,
    status: String,
    created_at: String,
    updated_at: String,
}

pub fn project_response(
    value: Value,
    kind: DeploymentResponseKind,
) -> Result<Value, DeploymentContractError> {
    match kind {
        DeploymentResponseKind::Profile => project_one::<ProfileResponse>(value, profile_fields()),
        DeploymentResponseKind::Profiles => {
            project_many::<ProfileResponse>(value, profile_fields())
        }
        DeploymentResponseKind::Lane => project_one::<LaneResponse>(value, lane_fields()),
        DeploymentResponseKind::Lanes => project_many::<LaneResponse>(value, lane_fields()),
    }
}

fn project_one<T: for<'de> Deserialize<'de> + Serialize>(
    value: Value,
    fields: &[&str],
) -> Result<Value, DeploymentContractError> {
    let object = value.as_object().ok_or(DeploymentContractError)?;
    let mut projected = object.clone();
    projected.retain(|key, _| fields.contains(&key.as_str()));
    let public = serde_json::from_value::<T>(Value::Object(projected))
        .map_err(|_| DeploymentContractError)?;
    let allowed = serde_json::to_value(public).map_err(|_| DeploymentContractError)?;
    Ok(allowed)
}

fn project_many<T: for<'de> Deserialize<'de> + Serialize>(
    value: Value,
    fields: &[&str],
) -> Result<Value, DeploymentContractError> {
    value
        .as_array()
        .ok_or(DeploymentContractError)?
        .iter()
        .cloned()
        .map(|value| project_one::<T>(value, fields))
        .collect::<Result<Vec<_>, _>>()
        .map(Value::Array)
}

const fn profile_fields() -> &'static [&'static str] {
    &[
        "id",
        "organization_id",
        "name",
        "description",
        "status",
        "environment",
        "callbacks",
        "feature_flags",
        "trust_profile_id",
        "presentation_policy_ids",
        "credential_template_ids",
        "enabled_flow_ids",
        "default_policy_id",
        "network_mode",
        "key_access_mode",
        "environment_config",
        "update_channel",
        "update_policy",
        "offline_cache_ttl_hours",
        "operator_biometric_authentication_required",
        "audit_all_events",
        "canvas_feature_flags",
        "lanes",
        "api_key_prefix",
        "created_at",
        "updated_at",
    ]
}

const fn lane_fields() -> &'static [&'static str] {
    &[
        "id",
        "deployment_profile_id",
        "name",
        "description",
        "location",
        "device_type",
        "device_count",
        "status",
        "created_at",
        "updated_at",
    ]
}

pub fn response_shape(method: &str, path: &str) -> Option<DeploymentResponseKind> {
    if path == "/v1/deployment-profiles" {
        return match method {
            "GET" => Some(DeploymentResponseKind::Profiles),
            "POST" => Some(DeploymentResponseKind::Profile),
            _ => None,
        };
    }
    let segments = path.trim_matches('/').split('/').collect::<Vec<_>>();
    match (method, segments.as_slice()) {
        ("GET" | "PATCH", ["v1", "deployment-profiles", _])
        | ("POST", ["v1", "deployment-profiles", _, "activate"]) => {
            Some(DeploymentResponseKind::Profile)
        }
        ("GET", ["v1", "deployment-profiles", _, "lanes"]) => Some(DeploymentResponseKind::Lanes),
        ("POST", ["v1", "deployment-profiles", _, "lanes"])
        | ("GET" | "PUT", ["v1", "deployment-profiles", _, "lanes", _]) => {
            Some(DeploymentResponseKind::Lane)
        }
        _ => None,
    }
}

fn profile_id(path: &str) -> Option<&str> {
    let segments = path.trim_matches('/').split('/').collect::<Vec<_>>();
    match segments.as_slice() {
        ["v1", "deployment-profiles", id] if !id.is_empty() => Some(id),
        _ => None,
    }
}

fn lane_collection_or_item(path: &str, method: &str) -> bool {
    let segments = path.trim_matches('/').split('/').collect::<Vec<_>>();
    matches!(
        (method, segments.as_slice()),
        ("POST", ["v1", "deployment-profiles", _, "lanes"])
            | ("PUT", ["v1", "deployment-profiles", _, "lanes", _])
    )
}

fn device_assignment_path(path: &str) -> bool {
    matches!(
        path.trim_matches('/')
            .split('/')
            .collect::<Vec<_>>()
            .as_slice(),
        ["v1", "deployment-profiles", _, "lanes", _, "devices"]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize)]
    struct Contract {
        schema_version: u32,
        create_input: Value,
        expected_create: Value,
        update_alias_input: Value,
        expected_update: Value,
        internal_profile: Value,
        expected_profile: Value,
        internal_lane: Value,
        expected_lane: Value,
    }

    #[test]
    fn language_neutral_deployment_contract() {
        let contract: Contract = serde_json::from_str(include_str!(
            "../../../../contracts/gateway-deployment-behavior.json"
        ))
        .expect("deployment contract");
        assert_eq!(contract.schema_version, 1);
        let create = canonicalize_request(
            "POST",
            "/v1/deployment-profiles",
            &serde_json::to_vec(&contract.create_input).unwrap(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&create).unwrap(),
            contract.expected_create
        );
        let update = canonicalize_request(
            "PATCH",
            "/v1/deployment-profiles/profile-1",
            &serde_json::to_vec(&contract.update_alias_input).unwrap(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&update).unwrap(),
            contract.expected_update
        );
        assert_eq!(
            project_response(contract.internal_profile, DeploymentResponseKind::Profile).unwrap(),
            contract.expected_profile
        );
        assert_eq!(
            project_response(contract.internal_lane, DeploymentResponseKind::Lane).unwrap(),
            contract.expected_lane
        );
    }

    #[test]
    fn rejects_removed_and_ambiguous_fields() {
        for body in [
            serde_json::json!({"organization_id":"org-1","name":"Runtime","ux_config":{}}),
            serde_json::json!({"operator_biometric_authentication_required":true,"biometric_required":true}),
        ] {
            let method = if body.get("organization_id").is_some() {
                "POST"
            } else {
                "PATCH"
            };
            let path = if method == "POST" {
                "/v1/deployment-profiles"
            } else {
                "/v1/deployment-profiles/profile-1"
            };
            assert!(
                canonicalize_request(method, path, &serde_json::to_vec(&body).unwrap()).is_err()
            );
        }
    }
}
