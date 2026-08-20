use std::collections::BTreeMap;

use chrono::DateTime;
use marty_verification::flow::FlowInstanceStatus;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

use crate::{
    public_context, public_status, ApprovalStrategy, DefinitionStatus, FlowCategory, FlowType,
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum FlowProjectionError {
    #[error("FLOW.INVALID_STORED_STATE: {0}")]
    InvalidStoredState(String),
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DefinitionProjectionInput {
    pub id: String,
    pub organization_id: String,
    pub name: String,
    pub description: Option<String>,
    pub status: DefinitionStatus,
    pub flow_type: FlowType,
    pub extension: Option<Value>,
    #[serde(default)]
    pub references: BTreeMap<String, String>,
    pub approval_strategy: ApprovalStrategy,
    #[serde(default)]
    pub hooks: BTreeMap<String, Vec<Value>>,
    pub trigger: Option<Value>,
    pub version: u32,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FlowDefinitionResponse {
    pub id: String,
    pub organization_id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub flow_type: FlowType,
    pub flow_category: FlowCategory,
    pub resolved_steps: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extension: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_profile_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_template_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_template_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub presentation_policy_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivery_destination_profile_id: Option<String>,
    pub deployment_profile_ids: Vec<String>,
    pub approval_strategy: ApprovalStrategy,
    pub hooks: BTreeMap<String, Vec<Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trigger: Option<Value>,
    pub version: u32,
    pub status: DefinitionStatus,
    pub created_at: String,
    pub updated_at: String,
}

pub fn project_definition(
    input: DefinitionProjectionInput,
) -> Result<FlowDefinitionResponse, FlowProjectionError> {
    validate_timestamp(&input.created_at, "definition.created_at")?;
    validate_timestamp(&input.updated_at, "definition.updated_at")?;
    let effective_type = effective_flow_type(input.flow_type, input.extension.as_ref())?;
    let resolved_steps = if input.flow_type == FlowType::Custom {
        extension_steps(input.extension.as_ref())?
    } else {
        input
            .flow_type
            .sequence()
            .iter()
            .map(|step| (*step).to_owned())
            .collect()
    };
    Ok(FlowDefinitionResponse {
        id: input.id,
        organization_id: input.organization_id,
        name: input.name,
        description: input.description,
        flow_type: input.flow_type,
        flow_category: effective_type
            .category()
            .ok_or_else(|| invalid("custom flow category"))?,
        resolved_steps,
        extension: input.extension,
        trust_profile_id: reference(&input.references, "trust_profile_id"),
        credential_template_id: reference(&input.references, "credential_template_id"),
        application_template_id: reference(&input.references, "application_template_id"),
        presentation_policy_id: reference(&input.references, "presentation_policy_id"),
        delivery_destination_profile_id: reference(
            &input.references,
            "delivery_destination_profile_id",
        ),
        deployment_profile_ids: input
            .references
            .get("deployment_profile_ids")
            .map(|value| {
                serde_json::from_str::<Vec<String>>(value)
                    .map_err(|_| invalid("definition.deployment_profile_ids"))
            })
            .transpose()?
            .unwrap_or_default(),
        approval_strategy: input.approval_strategy,
        hooks: input.hooks,
        trigger: input.trigger,
        version: input.version,
        status: input.status,
        created_at: input.created_at,
        updated_at: input.updated_at,
    })
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstanceProjectionInput {
    pub id: String,
    pub flow_definition_id: String,
    pub organization_id: String,
    pub status: FlowInstanceStatus,
    #[serde(default)]
    pub context: Value,
    pub subject_id: Option<String>,
    pub subject_type: String,
    pub external_reference: Option<String>,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub expires_at: Option<String>,
    pub result: Option<Value>,
    pub error: Option<String>,
    #[serde(default)]
    pub state_history: Vec<Value>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FlowInstanceResponse {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow_type: Option<FlowType>,
    pub organization_id: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_step: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_step_index: Option<u64>,
    pub context_data: Value,
    pub step_results: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issued_credential_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    pub metadata: Value,
    pub state_history: Vec<Value>,
    pub created_at: String,
    pub updated_at: String,
}

pub fn project_instance(
    input: &InstanceProjectionInput,
) -> Result<FlowInstanceResponse, FlowProjectionError> {
    validate_optional_timestamp(input.started_at.as_deref(), "instance.started_at")?;
    validate_optional_timestamp(input.completed_at.as_deref(), "instance.completed_at")?;
    validate_optional_timestamp(input.expires_at.as_deref(), "instance.expires_at")?;
    validate_timestamp(&input.created_at, "instance.created_at")?;
    validate_timestamp(&input.updated_at, "instance.updated_at")?;
    let context_data = public_context(&input.context);
    let context = context_data
        .as_object()
        .ok_or_else(|| invalid("instance.context"))?;
    let flow_type = response_flow_type(context)?;
    let step_results = context
        .get("step_results")
        .filter(|value| value.is_object())
        .cloned()
        .unwrap_or_else(|| Value::Object(Map::new()));
    let definition_reference = context
        .get("flow_definition_reference")
        .and_then(Value::as_str)
        .unwrap_or(&input.flow_definition_id);
    let mut metadata = Map::from_iter([
        (
            "runtime_status".into(),
            Value::String(input.status.to_string()),
        ),
        (
            "flow_definition_reference".into(),
            Value::String(definition_reference.to_owned()),
        ),
        (
            "subject_type".into(),
            Value::String(input.subject_type.clone()),
        ),
    ]);
    if let Some(subject_id) = &input.subject_id {
        metadata.insert("subject_id".into(), Value::String(subject_id.clone()));
    }
    if let Some(external_reference) = &input.external_reference {
        metadata.insert(
            "external_reference".into(),
            Value::String(external_reference.clone()),
        );
    }
    Ok(FlowInstanceResponse {
        id: input.id.clone(),
        flow_id: (!input.flow_definition_id.starts_with("__"))
            .then(|| input.flow_definition_id.clone()),
        flow_type,
        organization_id: input.organization_id.clone(),
        status: public_status(input.status).into(),
        current_step: optional_string(context, "current_step_name")?,
        current_step_index: optional_u64(context, "current_step_index")?,
        issued_credential_id: optional_string(context, "issued_credential_id")?,
        error_code: optional_string(context, "error_code")?,
        context_data,
        step_results,
        started_at: input.started_at.clone(),
        completed_at: input.completed_at.clone(),
        expires_at: input.expires_at.clone(),
        metadata: public_context(&Value::Object(metadata)),
        state_history: input.state_history.iter().map(public_context).collect(),
        created_at: input.created_at.clone(),
        updated_at: input.updated_at.clone(),
    })
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationResultResponse {
    pub instance_id: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision_reason: Option<String>,
    pub verified_claims: Value,
    pub credential_results: Vec<Value>,
    pub error_codes: Vec<String>,
    pub warnings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evaluation_timestamp: Option<String>,
}

pub fn project_verification_result(
    input: &InstanceProjectionInput,
) -> Result<VerificationResultResponse, FlowProjectionError> {
    let result = input.result.as_ref().and_then(Value::as_object);
    let verified_claims = result
        .and_then(|value| value.get("verified_claims"))
        .map(public_context)
        .filter(Value::is_object)
        .unwrap_or_else(|| Value::Object(Map::new()));
    Ok(VerificationResultResponse {
        instance_id: input.id.clone(),
        status: public_status(input.status).into(),
        result: optional_result_string(result, "evaluation_result")?,
        decision: optional_result_string(result, "decision")?,
        decision_reason: optional_result_string(result, "decision_reason")?
            .or_else(|| input.error.clone()),
        verified_claims,
        credential_results: public_object_array(result, "credential_results"),
        error_codes: public_string_array(result, "error_codes"),
        warnings: public_string_array(result, "warnings"),
        evaluation_timestamp: input.completed_at.clone(),
    })
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactProjectionInput {
    pub id: String,
    pub flow_instance_id: String,
    pub credential_offer_uri: Option<String>,
    pub qr_payload: Option<String>,
    pub pre_authorized_code: Option<String>,
    pub expires_at: Option<String>,
    pub scanned_at: Option<String>,
    pub status: String,
    pub state: Option<String>,
    #[serde(default)]
    pub wallet_metadata: Value,
    pub attempt_number: u32,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FlowArtifactResponse {
    pub id: String,
    pub flow_instance_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_offer_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qr_payload: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pre_authorized_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanned_at: Option<String>,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    pub wallet_metadata: Value,
    pub attempt_number: u32,
    pub created_at: String,
    pub updated_at: String,
}

pub fn project_artifact(
    input: ArtifactProjectionInput,
) -> Result<FlowArtifactResponse, FlowProjectionError> {
    validate_optional_timestamp(input.expires_at.as_deref(), "artifact.expires_at")?;
    validate_optional_timestamp(input.scanned_at.as_deref(), "artifact.scanned_at")?;
    validate_timestamp(&input.created_at, "artifact.created_at")?;
    validate_timestamp(&input.updated_at, "artifact.updated_at")?;
    if input.status.trim().is_empty() || !input.wallet_metadata.is_object() {
        return Err(invalid("artifact state"));
    }
    Ok(FlowArtifactResponse {
        id: input.id,
        flow_instance_id: input.flow_instance_id,
        credential_offer_uri: input.credential_offer_uri,
        qr_payload: input.qr_payload,
        pre_authorized_code: input.pre_authorized_code,
        expires_at: input.expires_at,
        scanned_at: input.scanned_at,
        status: input.status,
        state: input.state,
        wallet_metadata: public_context(&input.wallet_metadata),
        attempt_number: input.attempt_number,
        created_at: input.created_at,
        updated_at: input.updated_at,
    })
}

fn effective_flow_type(
    flow_type: FlowType,
    extension: Option<&Value>,
) -> Result<FlowType, FlowProjectionError> {
    if flow_type != FlowType::Custom {
        return Ok(flow_type);
    }
    extension
        .and_then(|value| value.get("extends_flow_type"))
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok())
        .filter(|value| *value != FlowType::Custom)
        .ok_or_else(|| invalid("definition.extension.extends_flow_type"))
}

fn extension_steps(extension: Option<&Value>) -> Result<Vec<String>, FlowProjectionError> {
    extension
        .and_then(|value| value.get("steps"))
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("definition.extension.steps"))?
        .iter()
        .map(|step| {
            step.get("step_id")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| invalid("definition.extension.steps[].step_id"))
        })
        .collect()
}

fn response_flow_type(
    context: &Map<String, Value>,
) -> Result<Option<FlowType>, FlowProjectionError> {
    if let Some(value) = context.get("protocol_flow_type") {
        return serde_json::from_value(value.clone())
            .map(Some)
            .map_err(|_| invalid("instance.context.protocol_flow_type"));
    }
    let runtime = context
        .get("flow_type")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    Ok(match runtime.as_str() {
        "verification" => Some(FlowType::Oid4vpPresentation),
        "siop_v2" | "siopv2" => Some(FlowType::Siopv2),
        "" => None,
        _ => None,
    })
}

fn reference(references: &BTreeMap<String, String>, name: &str) -> Option<String> {
    references
        .get(name)
        .filter(|value| !value.is_empty())
        .cloned()
}

fn optional_string(
    object: &Map<String, Value>,
    name: &str,
) -> Result<Option<String>, FlowProjectionError> {
    match object.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(invalid(&format!("instance.context.{name}"))),
    }
}

fn optional_u64(
    object: &Map<String, Value>,
    name: &str,
) -> Result<Option<u64>, FlowProjectionError> {
    match object.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(value)) => value
            .as_u64()
            .map(Some)
            .ok_or_else(|| invalid(&format!("instance.context.{name}"))),
        Some(_) => Err(invalid(&format!("instance.context.{name}"))),
    }
}

fn optional_result_string(
    object: Option<&Map<String, Value>>,
    name: &str,
) -> Result<Option<String>, FlowProjectionError> {
    match object.and_then(|value| value.get(name)) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(invalid(&format!("instance.result.{name}"))),
    }
}

fn public_object_array(object: Option<&Map<String, Value>>, name: &str) -> Vec<Value> {
    object
        .and_then(|value| value.get(name))
        .map(public_context)
        .and_then(|value| value.as_array().cloned())
        .filter(|values| values.iter().all(Value::is_object))
        .unwrap_or_default()
}

fn public_string_array(object: Option<&Map<String, Value>>, name: &str) -> Vec<String> {
    object
        .and_then(|value| value.get(name))
        .map(public_context)
        .and_then(|value| value.as_array().cloned())
        .filter(|values| values.iter().all(Value::is_string))
        .unwrap_or_default()
        .into_iter()
        .filter_map(|value| value.as_str().map(str::to_owned))
        .collect()
}

fn validate_optional_timestamp(
    value: Option<&str>,
    field: &str,
) -> Result<(), FlowProjectionError> {
    value.map_or(Ok(()), |value| validate_timestamp(value, field))
}

fn validate_timestamp(value: &str, field: &str) -> Result<(), FlowProjectionError> {
    DateTime::parse_from_rfc3339(value)
        .map(|_| ())
        .map_err(|_| invalid(field))
}

fn invalid(field: &str) -> FlowProjectionError {
    FlowProjectionError::InvalidStoredState(field.into())
}
