use std::collections::BTreeMap;

use chrono::{DateTime, SecondsFormat, Utc};
use marty_verification::flow::FlowInstanceStatus;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{
    project_artifact, project_definition, project_instance, project_verification_result,
    ApprovalStrategy, ArtifactProjectionInput, DefinitionProjectionInput, DefinitionStatus,
    FlowArtifactResponse, FlowDefinition, FlowDefinitionResponse, FlowInstance,
    FlowInstanceResponse, FlowProjectionError, FlowStep, FlowTransition, FlowType,
    InstanceProjectionInput, StateHistoryEntry, VerificationResultResponse,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactStatus {
    Active,
    Scanned,
    Expired,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FlowDefinitionRecord {
    pub id: String,
    pub organization_id: String,
    pub name: String,
    pub description: Option<String>,
    pub status: DefinitionStatus,
    pub flow_type: FlowType,
    pub steps: Vec<Value>,
    pub transitions: Vec<Value>,
    pub start_step_id: Option<String>,
    pub credential_template_id: Option<String>,
    pub application_template_id: Option<String>,
    pub presentation_policy_id: Option<String>,
    pub delivery_destination_profile_id: Option<String>,
    pub deployment_profile_id: Option<String>,
    #[serde(default)]
    pub deployment_profile_ids: Vec<String>,
    pub trust_profile_id: Option<String>,
    pub approval_strategy: ApprovalStrategy,
    #[serde(default)]
    pub hooks: BTreeMap<String, Vec<Value>>,
    pub trigger: Option<Value>,
    pub extension: Option<Value>,
    #[serde(default)]
    pub preconditions: Vec<String>,
    pub default_timeout_seconds: u32,
    pub max_retries: u32,
    pub retry_cooldown_minutes: u32,
    pub enable_resume: bool,
    pub version: u32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FlowInstanceRecord {
    pub id: String,
    pub flow_definition_id: String,
    pub organization_id: String,
    pub status: FlowInstanceStatus,
    pub current_step_id: Option<String>,
    #[serde(default)]
    pub context: Value,
    #[serde(default)]
    pub step_history: Vec<Value>,
    #[serde(default)]
    pub state_history: Vec<Value>,
    pub subject_id: Option<String>,
    pub subject_type: String,
    pub external_reference: Option<String>,
    pub application_flow_key_hash: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub result: Option<Value>,
    pub error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FlowArtifactRecord {
    pub id: String,
    pub flow_instance_id: String,
    pub issuance_transaction_id: Option<String>,
    pub credential_offer_uri: Option<String>,
    #[serde(default)]
    pub credential_offer_uris: BTreeMap<String, String>,
    #[serde(default)]
    pub credential_offer_labels: BTreeMap<String, String>,
    pub pre_authorized_code: Option<String>,
    pub issuance_status: Option<String>,
    pub qr_payload: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub scanned_at: Option<DateTime<Utc>>,
    pub status: ArtifactStatus,
    pub state: Option<String>,
    #[serde(default)]
    pub wallet_metadata: Value,
    pub attempt_number: u32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum FlowRecordError {
    #[error("FLOW.INVALID_STORED_STATE: {0}")]
    InvalidStoredState(String),
    #[error(transparent)]
    Projection(#[from] FlowProjectionError),
}

impl FlowDefinitionRecord {
    pub fn kernel(&self) -> Result<FlowDefinition, FlowRecordError> {
        let steps = self
            .steps
            .iter()
            .enumerate()
            .map(|(index, value)| {
                let object = object(value, &format!("definition.steps[{index}]"))?;
                Ok(FlowStep {
                    id: required_string(
                        object.get("id"),
                        &format!("definition.steps[{index}].id"),
                    )?,
                    protocol_step: protocol_step(object, index)?,
                })
            })
            .collect::<Result<Vec<_>, FlowRecordError>>()?;
        let transitions = self
            .transitions
            .iter()
            .enumerate()
            .map(|(index, value)| {
                let object = object(value, &format!("definition.transitions[{index}]"))?;
                Ok(FlowTransition {
                    from_step_id: required_string(
                        object.get("from_step_id"),
                        &format!("definition.transitions[{index}].from_step_id"),
                    )?,
                    to_step_id: required_string(
                        object.get("to_step_id"),
                        &format!("definition.transitions[{index}].to_step_id"),
                    )?,
                    outcome: parse_enum(
                        object.get("condition"),
                        &format!("definition.transitions[{index}].condition"),
                    )?,
                })
            })
            .collect::<Result<Vec<_>, FlowRecordError>>()?;
        let start_step_id = self
            .start_step_id
            .clone()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| invalid("definition.start_step_id"))?;
        let definition = FlowDefinition {
            id: self.id.clone(),
            organization_id: self.organization_id.clone(),
            name: self.name.clone(),
            flow_type: self.flow_type,
            status: self.status,
            steps,
            transitions,
            start_step_id,
            references: self.references()?,
            extension: self.extension.clone(),
            version: self.version,
        };
        definition
            .validate_graph()
            .map_err(|error| invalid(&error.to_string()))?;
        Ok(definition)
    }

    pub fn projection(&self) -> Result<FlowDefinitionResponse, FlowRecordError> {
        Ok(project_definition(DefinitionProjectionInput {
            id: self.id.clone(),
            organization_id: self.organization_id.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
            status: self.status,
            flow_type: self.flow_type,
            extension: self.extension.clone(),
            references: self.references()?,
            approval_strategy: self.approval_strategy,
            hooks: self.hooks.clone(),
            trigger: self.trigger.clone(),
            version: self.version,
            created_at: timestamp(self.created_at),
            updated_at: timestamp(self.updated_at),
        })?)
    }

    fn references(&self) -> Result<BTreeMap<String, String>, FlowRecordError> {
        let mut references = BTreeMap::new();
        for (name, value) in [
            ("credential_template_id", &self.credential_template_id),
            ("application_template_id", &self.application_template_id),
            ("presentation_policy_id", &self.presentation_policy_id),
            (
                "delivery_destination_profile_id",
                &self.delivery_destination_profile_id,
            ),
            ("deployment_profile_id", &self.deployment_profile_id),
            ("trust_profile_id", &self.trust_profile_id),
        ] {
            if let Some(value) = value.as_ref().filter(|value| !value.is_empty()) {
                references.insert(name.into(), value.clone());
            }
        }
        references.insert(
            "deployment_profile_ids".into(),
            serde_json::to_string(&self.deployment_profile_ids)
                .map_err(|_| invalid("definition.deployment_profile_ids"))?,
        );
        Ok(references)
    }
}

impl FlowInstanceRecord {
    pub fn kernel(&self) -> Result<FlowInstance, FlowRecordError> {
        if !self.context.is_object() {
            return Err(invalid("instance.context"));
        }
        Ok(FlowInstance {
            id: self.id.clone(),
            flow_definition_id: self.flow_definition_id.clone(),
            organization_id: self.organization_id.clone(),
            status: self.status,
            current_step_id: self.current_step_id.clone(),
            application_flow_key_hash: self.application_flow_key_hash.clone(),
            context: self.context.clone(),
            step_history: self.step_history.clone(),
            state_history: self
                .state_history
                .iter()
                .enumerate()
                .map(|(index, entry)| parse_state_history(entry, index))
                .collect::<Result<Vec<_>, _>>()?,
            expires_at_ms: optional_millis(self.expires_at)?,
            completed_at_ms: optional_millis(self.completed_at)?,
            result: self.result.clone(),
            error: self.error.clone(),
        })
    }

    pub fn projection(&self) -> Result<FlowInstanceResponse, FlowRecordError> {
        Ok(project_instance(&self.projection_input()?)?)
    }

    pub fn verification_projection(&self) -> Result<VerificationResultResponse, FlowRecordError> {
        Ok(project_verification_result(&self.projection_input()?)?)
    }

    fn projection_input(&self) -> Result<InstanceProjectionInput, FlowRecordError> {
        Ok(InstanceProjectionInput {
            id: self.id.clone(),
            flow_definition_id: self.flow_definition_id.clone(),
            organization_id: self.organization_id.clone(),
            status: self.status,
            context: self.context.clone(),
            subject_id: self.subject_id.clone(),
            subject_type: self.subject_type.clone(),
            external_reference: self.external_reference.clone(),
            started_at: self.started_at.map(timestamp),
            completed_at: self.completed_at.map(timestamp),
            expires_at: self.expires_at.map(timestamp),
            result: self.result.clone(),
            error: self.error.clone(),
            state_history: self.state_history.clone(),
            created_at: timestamp(self.created_at),
            updated_at: timestamp(self.updated_at),
        })
    }
}

impl FlowArtifactRecord {
    pub fn projection(&self) -> Result<FlowArtifactResponse, FlowRecordError> {
        Ok(project_artifact(ArtifactProjectionInput {
            id: self.id.clone(),
            flow_instance_id: self.flow_instance_id.clone(),
            credential_offer_uri: self.credential_offer_uri.clone(),
            qr_payload: self.qr_payload.clone(),
            pre_authorized_code: self.pre_authorized_code.clone(),
            expires_at: self.expires_at.map(timestamp),
            scanned_at: self.scanned_at.map(timestamp),
            status: enum_string(self.status)?,
            state: self.state.clone(),
            wallet_metadata: self.wallet_metadata.clone(),
            attempt_number: self.attempt_number,
            created_at: timestamp(self.created_at),
            updated_at: timestamp(self.updated_at),
        })?)
    }
}

fn object<'a>(
    value: &'a Value,
    field: &str,
) -> Result<&'a serde_json::Map<String, Value>, FlowRecordError> {
    value.as_object().ok_or_else(|| invalid(field))
}

fn required_string(value: Option<&Value>, field: &str) -> Result<String, FlowRecordError> {
    value
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .ok_or_else(|| invalid(field))
}

fn protocol_step(
    object: &serde_json::Map<String, Value>,
    index: usize,
) -> Result<String, FlowRecordError> {
    object
        .get("config")
        .and_then(Value::as_object)
        .and_then(|config| config.get("protocol_step"))
        .or_else(|| object.get("name"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .ok_or_else(|| invalid(&format!("definition.steps[{index}].protocol_step")))
}

fn parse_state_history(value: &Value, index: usize) -> Result<StateHistoryEntry, FlowRecordError> {
    let field = format!("instance.state_history[{index}]");
    let object = object(value, &field)?;
    let prior_state = object
        .get("prior_state")
        .filter(|value| !value.is_null())
        .map(|value| parse_enum(Some(value), &format!("{field}.prior_state")))
        .transpose()?;
    let new_state = parse_enum(object.get("new_state"), &format!("{field}.new_state"))?;
    let timestamp_ms = if let Some(value) = object.get("timestamp_ms").and_then(Value::as_u64) {
        value
    } else {
        let timestamp = required_string(object.get("timestamp"), &format!("{field}.timestamp"))?;
        u64::try_from(
            DateTime::parse_from_rfc3339(&timestamp)
                .map_err(|_| invalid(&format!("{field}.timestamp")))?
                .timestamp_millis(),
        )
        .map_err(|_| invalid(&format!("{field}.timestamp")))?
    };
    Ok(StateHistoryEntry {
        prior_state,
        new_state,
        timestamp_ms,
        actor: object
            .get("actor")
            .and_then(Value::as_str)
            .map(str::to_owned),
        event: required_string(object.get("event"), &format!("{field}.event"))?,
    })
}

fn parse_enum<T: DeserializeOwned>(
    value: Option<&Value>,
    field: &str,
) -> Result<T, FlowRecordError> {
    serde_json::from_value(value.cloned().ok_or_else(|| invalid(field))?)
        .map_err(|_| invalid(field))
}

fn enum_string<T: Serialize>(value: T) -> Result<String, FlowRecordError> {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or_else(|| invalid("enum"))
}

fn timestamp(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Micros, true)
}

fn optional_millis(value: Option<DateTime<Utc>>) -> Result<Option<u64>, FlowRecordError> {
    value
        .map(|value| u64::try_from(value.timestamp_millis()).map_err(|_| invalid("timestamp")))
        .transpose()
}

fn invalid(field: &str) -> FlowRecordError {
    FlowRecordError::InvalidStoredState(field.into())
}
