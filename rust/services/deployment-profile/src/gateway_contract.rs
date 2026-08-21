//! Shared Gateway request and response boundary for Deployment Profiles.

use chrono::Utc;
use serde_json::{Map, Value};

use crate::{
    AssignDeviceRequest, CreateDeploymentProfileRequest, CreateLaneRequest, DeploymentProfile,
    UpdateDeploymentProfileRequest, UpdateLaneRequest,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeploymentResponseKind {
    Profile,
    Profiles,
    Lane,
    Lanes,
}

#[derive(Clone, Copy, Debug)]
pub struct DeploymentContractError;

pub fn canonicalize_request(
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<Option<Vec<u8>>, DeploymentContractError> {
    let canonical = if method == "POST" && path == "/v1/deployment-profiles" {
        let request: CreateDeploymentProfileRequest = parse(body)?;
        DeploymentProfile::new(request.clone(), Utc::now()).map_err(|_| DeploymentContractError)?;
        Some(canonical_json(request)?)
    } else if method == "PATCH" && profile_id(path).is_some() {
        Some(canonical_json(parse::<UpdateDeploymentProfileRequest>(
            body,
        )?)?)
    } else if method == "POST" && lane_collection(path) {
        let request: CreateLaneRequest = parse(body)?;
        crate::Lane::new("profile", request.clone(), Utc::now())
            .map_err(|_| DeploymentContractError)?;
        Some(canonical_json(request)?)
    } else if method == "PUT" && lane_item(path) {
        Some(canonical_json(parse::<UpdateLaneRequest>(body)?)?)
    } else if method == "POST" && device_assignment_path(path) {
        let request: AssignDeviceRequest = parse(body)?;
        if request.device_id.trim().is_empty() {
            return Err(DeploymentContractError);
        }
        Some(canonical_json(request)?)
    } else {
        None
    };
    Ok(canonical)
}

pub fn create_dependencies(
    value: &Value,
) -> Result<DeploymentDependencies, DeploymentContractError> {
    let request: CreateDeploymentProfileRequest =
        serde_json::from_value(value.clone()).map_err(|_| DeploymentContractError)?;
    Ok(DeploymentDependencies {
        organization_id: request.organization_id,
        trust_profile_id: request.trust_profile_id,
        presentation_policy_ids: request.presentation_policy_ids,
        credential_template_ids: request.credential_template_ids,
        default_policy_id: request.default_policy_id,
    })
}

pub struct DeploymentDependencies {
    pub organization_id: String,
    pub trust_profile_id: Option<String>,
    pub presentation_policy_ids: Vec<String>,
    pub credential_template_ids: Vec<String>,
    pub default_policy_id: Option<String>,
}

pub fn project_response(
    value: Value,
    kind: DeploymentResponseKind,
) -> Result<Value, DeploymentContractError> {
    match kind {
        DeploymentResponseKind::Profile => project_profile(value),
        DeploymentResponseKind::Profiles => project_many(value, project_profile),
        DeploymentResponseKind::Lane => project_lane(value),
        DeploymentResponseKind::Lanes => project_many(value, project_lane),
    }
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
        | ("POST", ["v1", "deployment-profiles", _, "activate" | "suspend"]) => {
            Some(DeploymentResponseKind::Profile)
        }
        ("GET", ["v1", "deployment-profiles", _, "lanes"]) => Some(DeploymentResponseKind::Lanes),
        ("POST", ["v1", "deployment-profiles", _, "lanes"])
        | ("GET" | "PUT", ["v1", "deployment-profiles", _, "lanes", _])
        | ("POST", ["v1", "deployment-profiles", _, "lanes", _, "devices"]) => {
            Some(DeploymentResponseKind::Lane)
        }
        _ => None,
    }
}

fn project_profile(value: Value) -> Result<Value, DeploymentContractError> {
    let mut object = value.as_object().cloned().ok_or(DeploymentContractError)?;
    for required in ["id", "organization_id", "name", "created_at", "updated_at"] {
        if object.get(required).and_then(Value::as_str).is_none() {
            return Err(DeploymentContractError);
        }
    }
    object.retain(|key, _| PROFILE_FIELDS.contains(&key.as_str()));
    for name in PROFILE_NULL_DEFAULTS {
        object.entry(*name).or_insert(Value::Null);
    }
    for (name, value) in [
        ("presentation_policy_ids", Value::Array(Vec::new())),
        ("credential_template_ids", Value::Array(Vec::new())),
        ("enabled_flow_ids", Value::Array(Vec::new())),
        ("canvas_feature_flags", Value::Object(Map::new())),
        ("lanes", Value::Array(Vec::new())),
    ] {
        object.entry(name).or_insert(value);
    }
    Ok(Value::Object(object))
}

fn project_lane(value: Value) -> Result<Value, DeploymentContractError> {
    let mut object = value.as_object().cloned().ok_or(DeploymentContractError)?;
    for required in ["id", "deployment_profile_id", "name"] {
        if object.get(required).and_then(Value::as_str).is_none() {
            return Err(DeploymentContractError);
        }
    }
    object.retain(|key, _| LANE_FIELDS.contains(&key.as_str()));
    Ok(Value::Object(object))
}

fn project_many(
    value: Value,
    project: fn(Value) -> Result<Value, DeploymentContractError>,
) -> Result<Value, DeploymentContractError> {
    value
        .as_array()
        .ok_or(DeploymentContractError)?
        .iter()
        .cloned()
        .map(project)
        .collect::<Result<Vec<_>, _>>()
        .map(Value::Array)
}

fn canonical_json(value: impl serde::Serialize) -> Result<Vec<u8>, DeploymentContractError> {
    let mut value = serde_json::to_value(value).map_err(|_| DeploymentContractError)?;
    strip_nulls(&mut value);
    serde_json::to_vec(&value).map_err(|_| DeploymentContractError)
}

fn strip_nulls(value: &mut Value) {
    match value {
        Value::Object(object) => {
            object.retain(|_, value| !value.is_null());
            object.values_mut().for_each(strip_nulls);
        }
        Value::Array(values) => values.iter_mut().for_each(strip_nulls),
        _ => {}
    }
}

fn parse<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, DeploymentContractError> {
    serde_json::from_slice(body).map_err(|_| DeploymentContractError)
}

fn profile_id(path: &str) -> Option<&str> {
    let segments = path.trim_matches('/').split('/').collect::<Vec<_>>();
    match segments.as_slice() {
        ["v1", "deployment-profiles", id] if !id.is_empty() => Some(id),
        _ => None,
    }
}

fn lane_collection(path: &str) -> bool {
    matches!(
        path.trim_matches('/')
            .split('/')
            .collect::<Vec<_>>()
            .as_slice(),
        ["v1", "deployment-profiles", _, "lanes"]
    )
}

fn lane_item(path: &str) -> bool {
    matches!(
        path.trim_matches('/')
            .split('/')
            .collect::<Vec<_>>()
            .as_slice(),
        ["v1", "deployment-profiles", _, "lanes", _]
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

const PROFILE_NULL_DEFAULTS: &[&str] = &[
    "description",
    "status",
    "environment",
    "callbacks",
    "feature_flags",
    "trust_profile_id",
    "default_policy_id",
    "network_mode",
    "key_access_mode",
    "environment_config",
    "update_channel",
    "update_policy",
    "offline_cache_ttl_hours",
    "operator_biometric_authentication_required",
    "audit_all_events",
    "api_key_prefix",
];

const PROFILE_FIELDS: &[&str] = &[
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
];

const LANE_FIELDS: &[&str] = &[
    "id",
    "deployment_profile_id",
    "name",
    "description",
    "location",
    "device_type",
    "default_policy_id",
    "device_ids",
    "device_count",
    "metadata",
    "status",
    "created_at",
    "updated_at",
];

#[cfg(test)]
mod tests {
    use serde::Deserialize;

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
            let (method, path) = if body.get("organization_id").is_some() {
                ("POST", "/v1/deployment-profiles")
            } else {
                ("PATCH", "/v1/deployment-profiles/profile-1")
            };
            assert!(
                canonicalize_request(method, path, &serde_json::to_vec(&body).unwrap()).is_err()
            );
        }
    }
}
