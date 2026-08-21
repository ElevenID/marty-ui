use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use marty_verification::flow::TransitionOutcome;
use serde::Serialize;
use serde_json::{json, Value};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    validate_definition_references, CreateFlowDefinitionRequest, DefinitionStatus, FlowApiError,
    FlowDefinition, FlowDefinitionRecord, FlowDefinitionReferenceSet, FlowDomainError,
    FlowHookRequest, Patch, UpdateFlowDefinitionRequest, ValidateRequest,
};

#[derive(Debug, Error)]
pub enum FlowDefinitionMutationError {
    #[error(transparent)]
    Api(#[from] FlowApiError),
    #[error(transparent)]
    Domain(#[from] FlowDomainError),
    #[error("FLOW.INVALID_STORED_STATE: {0}")]
    Stored(&'static str),
    #[error("FLOW.SERIALIZATION: {0}")]
    Serialization(&'static str),
}

#[derive(Clone, Debug, Serialize)]
pub struct FlowDefinitionValidationResult {
    pub valid: bool,
    pub errors: Vec<FlowDefinitionValidationIssue>,
    pub warnings: Vec<FlowDefinitionValidationIssue>,
    pub resolved_dependencies: Vec<ResolvedFlowDependency>,
    pub resolved_steps: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct FlowDefinitionValidationIssue {
    pub code: &'static str,
    pub field: &'static str,
    pub message: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ResolvedFlowDependency {
    #[serde(rename = "type")]
    pub kind: String,
    pub id: String,
}

pub fn create_definition_record(
    request: CreateFlowDefinitionRequest,
    now: DateTime<Utc>,
) -> Result<FlowDefinitionRecord, FlowDefinitionMutationError> {
    request.validate()?;
    build_record(request, Uuid::new_v4().to_string(), 1, now, now)
}

pub fn update_definition_record(
    existing: &FlowDefinitionRecord,
    request: UpdateFlowDefinitionRequest,
    now: DateTime<Utc>,
) -> Result<FlowDefinitionRecord, FlowDefinitionMutationError> {
    request.validate()?;
    if request.organization_id != existing.organization_id {
        return Err(FlowDefinitionMutationError::Api(FlowApiError {
            code: "FLOW.INVALID_REQUEST",
            field: "organization_id".into(),
            message: "cannot be changed for an existing flow definition".into(),
        }));
    }
    let mut merged = request_from_record(existing)?;
    apply_patch(&mut merged, request);
    merged.validate()?;
    build_record(
        merged,
        existing.id.clone(),
        existing.version.saturating_add(1),
        existing.created_at,
        now,
    )
}

pub fn definition_references(record: &FlowDefinitionRecord) -> FlowDefinitionReferenceSet {
    FlowDefinitionReferenceSet {
        credential_template_id: record.credential_template_id.clone(),
        application_template_id: record.application_template_id.clone(),
        presentation_policy_id: record.presentation_policy_id.clone(),
        delivery_destination_profile_id: record.delivery_destination_profile_id.clone(),
        deployment_profile_ids: record.deployment_profile_ids.clone(),
        trust_profile_id: record.trust_profile_id.clone(),
    }
}

pub async fn validate_definition_record(
    providers: &crate::FlowProviderRegistry,
    principal_id: &str,
    record: &FlowDefinitionRecord,
) -> FlowDefinitionValidationResult {
    let mut errors = Vec::new();
    if let Err(error) = record.kernel() {
        errors.push(FlowDefinitionValidationIssue {
            code: "INVALID_FLOW",
            field: "flow_type",
            message: error.to_string(),
        });
    }
    if let Err(error) = validate_definition_references(
        providers,
        principal_id,
        &record.organization_id,
        &definition_references(record),
        true,
    )
    .await
    {
        errors.push(FlowDefinitionValidationIssue {
            code: "DEPENDENCY_INVALID",
            field: "dependencies",
            message: error.to_string(),
        });
    }
    let warnings = if record.deployment_profile_ids.is_empty() {
        vec![FlowDefinitionValidationIssue {
            code: "NO_DEPLOYMENT_TARGET",
            field: "deployment_profile_ids",
            message: "No deployment target is selected; activation is allowed, but the flow cannot be deployed.".into(),
        }]
    } else {
        Vec::new()
    };
    FlowDefinitionValidationResult {
        valid: errors.is_empty(),
        errors,
        warnings,
        resolved_dependencies: required_dependencies(record),
        resolved_steps: resolved_steps(record),
    }
}

fn build_record(
    request: CreateFlowDefinitionRequest,
    id: String,
    version: u32,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
) -> Result<FlowDefinitionRecord, FlowDefinitionMutationError> {
    let references = reference_map(&request)?;
    let deployment_profile_ids = deduplicate(request.deployment_profile_ids.clone());
    let (kernel, steps, transitions, start_step_id) =
        if request.flow_type == crate::FlowType::Custom {
            custom_graph(&request, &id, version, &references)?
        } else {
            let mut kernel = FlowDefinition::built_in(
                request.organization_id.clone(),
                request.name.clone(),
                request.flow_type,
                references.clone(),
            )?;
            kernel.id.clone_from(&id);
            kernel.version = version;
            let steps = kernel
                .steps
                .iter()
                .map(|step| standard_step(&step.id, &step.protocol_step))
                .collect();
            let transitions = kernel
                .transitions
                .iter()
                .map(serialize_transition)
                .collect::<Result<Vec<_>, _>>()?;
            let start_step_id = kernel.start_step_id.clone();
            (kernel, steps, transitions, start_step_id)
        };
    kernel.validate_graph()?;
    Ok(FlowDefinitionRecord {
        id,
        organization_id: request.organization_id,
        name: request.name,
        description: request.description,
        status: DefinitionStatus::Draft,
        flow_type: request.flow_type,
        steps,
        transitions,
        start_step_id: Some(start_step_id),
        credential_template_id: request.credential_template_id,
        application_template_id: request.application_template_id,
        presentation_policy_id: request.presentation_policy_id,
        delivery_destination_profile_id: request.delivery_destination_profile_id,
        deployment_profile_id: deployment_profile_ids.first().cloned(),
        deployment_profile_ids,
        trust_profile_id: request.trust_profile_id,
        approval_strategy: request.approval_strategy,
        hooks: serialize_hooks(request.hooks)?,
        trigger: request
            .trigger
            .map(|value| serde_json::to_value(value).map_err(|_| serialization("trigger")))
            .transpose()?,
        extension: request
            .extension
            .map(|value| serde_json::to_value(value).map_err(|_| serialization("extension")))
            .transpose()?,
        preconditions: Vec::new(),
        default_timeout_seconds: 600,
        max_retries: 3,
        retry_cooldown_minutes: 5,
        enable_resume: true,
        version,
        created_at,
        updated_at,
    })
}

fn custom_graph(
    request: &CreateFlowDefinitionRequest,
    id: &str,
    version: u32,
    references: &BTreeMap<String, String>,
) -> Result<(FlowDefinition, Vec<Value>, Vec<Value>, String), FlowDefinitionMutationError> {
    let extension = request
        .extension
        .as_ref()
        .ok_or(FlowDefinitionMutationError::Stored("extension"))?;
    let ids = extension
        .steps
        .iter()
        .map(|step| (step.step_id.clone(), Uuid::new_v4().to_string()))
        .collect::<BTreeMap<_, _>>();
    let kernel_steps = extension
        .steps
        .iter()
        .map(|step| crate::FlowStep {
            id: ids[&step.step_id].clone(),
            protocol_step: extension_action(&step.action).to_owned(),
        })
        .collect::<Vec<_>>();
    let kernel_transitions = extension
        .transitions
        .iter()
        .map(|transition| crate::FlowTransition {
            from_step_id: ids[&transition.from_step_id].clone(),
            to_step_id: ids[&transition.to_step_id].clone(),
            outcome: transition.outcome.into(),
        })
        .collect::<Vec<_>>();
    let start_step_id = ids[&extension.entry_step_id].clone();
    let extension_value =
        serde_json::to_value(extension).map_err(|_| serialization("extension"))?;
    let kernel = FlowDefinition {
        id: id.into(),
        organization_id: request.organization_id.clone(),
        name: request.name.clone(),
        flow_type: request.flow_type,
        status: DefinitionStatus::Draft,
        steps: kernel_steps.clone(),
        transitions: kernel_transitions.clone(),
        start_step_id: start_step_id.clone(),
        references: references.clone(),
        extension: Some(extension_value),
        version,
    };
    let steps = extension
        .steps
        .iter()
        .map(|step| {
            let protocol_step = extension_action(&step.action);
            let mut config = step.config.clone();
            config.insert("extension_step_id".into(), json!(step.step_id));
            config.insert("extension_action".into(), json!(step.action));
            config.insert("protocol_step".into(), json!(protocol_step));
            json!({
                "id": ids[&step.step_id],
                "name": titleize(&step.step_id),
                "description": step.description,
                "step_type": step_type(protocol_step),
                "config": config,
                "timeout_seconds": step.timeout_seconds
            })
        })
        .collect();
    let transitions = extension
        .transitions
        .iter()
        .map(|transition| {
            let outcome: TransitionOutcome = transition.outcome.into();
            Ok(json!({
                "id": Uuid::new_v4().to_string(),
                "from_step_id": ids[&transition.from_step_id],
                "to_step_id": ids[&transition.to_step_id],
                "condition": serde_json::to_value(outcome).map_err(|_| serialization("transition.outcome"))?,
                "condition_expression": transition.condition.as_ref().map(serde_json::to_string).transpose().map_err(|_| serialization("transition.condition"))?
            }))
        })
        .collect::<Result<Vec<_>, FlowDefinitionMutationError>>()?;
    Ok((kernel, steps, transitions, start_step_id))
}

fn request_from_record(
    record: &FlowDefinitionRecord,
) -> Result<CreateFlowDefinitionRequest, FlowDefinitionMutationError> {
    Ok(CreateFlowDefinitionRequest {
        organization_id: record.organization_id.clone(),
        name: record.name.clone(),
        description: record.description.clone(),
        flow_type: record.flow_type,
        approval_strategy: record.approval_strategy,
        hooks: record
            .hooks
            .iter()
            .map(|(name, values)| {
                let hooks = values
                    .iter()
                    .cloned()
                    .map(serde_json::from_value::<FlowHookRequest>)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| FlowDefinitionMutationError::Stored("hooks"))?;
                Ok((name.clone(), hooks))
            })
            .collect::<Result<_, FlowDefinitionMutationError>>()?,
        trigger: record
            .trigger
            .clone()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|_| FlowDefinitionMutationError::Stored("trigger"))?,
        extension: record
            .extension
            .clone()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|_| FlowDefinitionMutationError::Stored("extension"))?,
        credential_template_id: record.credential_template_id.clone(),
        application_template_id: record.application_template_id.clone(),
        presentation_policy_id: record.presentation_policy_id.clone(),
        delivery_destination_profile_id: record.delivery_destination_profile_id.clone(),
        deployment_profile_ids: record.deployment_profile_ids.clone(),
        trust_profile_id: record.trust_profile_id.clone(),
    })
}

fn apply_patch(target: &mut CreateFlowDefinitionRequest, request: UpdateFlowDefinitionRequest) {
    patch_required(&mut target.name, request.name);
    patch_optional(&mut target.description, request.description);
    patch_required(&mut target.flow_type, request.flow_type);
    patch_required(&mut target.approval_strategy, request.approval_strategy);
    patch_required(&mut target.hooks, request.hooks);
    patch_optional(&mut target.trigger, request.trigger);
    patch_optional(&mut target.extension, request.extension);
    patch_optional(
        &mut target.credential_template_id,
        request.credential_template_id,
    );
    patch_optional(
        &mut target.application_template_id,
        request.application_template_id,
    );
    patch_optional(
        &mut target.presentation_policy_id,
        request.presentation_policy_id,
    );
    patch_optional(
        &mut target.delivery_destination_profile_id,
        request.delivery_destination_profile_id,
    );
    patch_required(
        &mut target.deployment_profile_ids,
        request.deployment_profile_ids,
    );
    patch_optional(&mut target.trust_profile_id, request.trust_profile_id);
}

fn patch_required<T>(target: &mut T, patch: Patch<T>) {
    if let Patch::Value(value) = patch {
        *target = value;
    }
}

fn patch_optional<T>(target: &mut Option<T>, patch: Patch<T>) {
    match patch {
        Patch::Unset => {}
        Patch::Null => *target = None,
        Patch::Value(value) => *target = Some(value),
    }
}

fn reference_map(
    request: &CreateFlowDefinitionRequest,
) -> Result<BTreeMap<String, String>, FlowDefinitionMutationError> {
    let mut values = BTreeMap::new();
    for (name, value) in [
        (
            "credential_template_id",
            request.credential_template_id.as_ref(),
        ),
        (
            "application_template_id",
            request.application_template_id.as_ref(),
        ),
        (
            "presentation_policy_id",
            request.presentation_policy_id.as_ref(),
        ),
        (
            "delivery_destination_profile_id",
            request.delivery_destination_profile_id.as_ref(),
        ),
        ("trust_profile_id", request.trust_profile_id.as_ref()),
    ] {
        if let Some(value) = value {
            values.insert(name.into(), value.clone());
        }
    }
    if let Some(extension) = &request.extension {
        values.insert(
            "extension".into(),
            serde_json::to_string(extension).map_err(|_| serialization("extension"))?,
        );
    }
    Ok(values)
}

fn standard_step(id: &str, protocol_step: &str) -> Value {
    json!({
        "id": id,
        "name": titleize(protocol_step),
        "description": format!("Protocol-defined step: {protocol_step}"),
        "step_type": step_type(protocol_step),
        "config": {"protocol_step": protocol_step},
        "timeout_seconds": null
    })
}

fn serialize_transition(
    transition: &crate::FlowTransition,
) -> Result<Value, FlowDefinitionMutationError> {
    Ok(json!({
        "id": Uuid::new_v4().to_string(),
        "from_step_id": transition.from_step_id,
        "to_step_id": transition.to_step_id,
        "condition": serde_json::to_value(transition.outcome).map_err(|_| serialization("transition.outcome"))?,
        "condition_expression": null
    }))
}

fn serialize_hooks(
    hooks: BTreeMap<String, Vec<FlowHookRequest>>,
) -> Result<BTreeMap<String, Vec<Value>>, FlowDefinitionMutationError> {
    hooks
        .into_iter()
        .map(|(name, hooks)| {
            let values = hooks
                .into_iter()
                .map(|hook| serde_json::to_value(hook).map_err(|_| serialization("hooks")))
                .collect::<Result<Vec<_>, _>>()?;
            Ok((name, values))
        })
        .collect()
}

fn deduplicate(values: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    values
        .into_iter()
        .filter(|value| seen.insert(value.clone()))
        .collect()
}

fn required_dependencies(record: &FlowDefinitionRecord) -> Vec<ResolvedFlowDependency> {
    let references = definition_references(record);
    record
        .flow_type
        .required_references()
        .iter()
        .filter_map(|name| {
            let id = match *name {
                "credential_template_id" => references.credential_template_id.as_ref(),
                "application_template_id" => references.application_template_id.as_ref(),
                "presentation_policy_id" => references.presentation_policy_id.as_ref(),
                "delivery_destination_profile_id" => {
                    references.delivery_destination_profile_id.as_ref()
                }
                _ => None,
            }?;
            Some(ResolvedFlowDependency {
                kind: name.trim_end_matches("_id").into(),
                id: id.clone(),
            })
        })
        .collect()
}

fn resolved_steps(record: &FlowDefinitionRecord) -> Vec<String> {
    if record.flow_type == crate::FlowType::Custom {
        record
            .extension
            .as_ref()
            .and_then(|value| value.get("steps"))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|step| {
                step.get("step_id")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .collect()
    } else {
        record
            .flow_type
            .sequence()
            .iter()
            .map(|value| (*value).to_owned())
            .collect()
    }
}

fn extension_action(value: &str) -> &str {
    value.rsplit([':', '.']).next().unwrap_or(value)
}

fn titleize(value: &str) -> String {
    value
        .split('_')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut characters = part.chars();
            characters.next().map_or_else(String::new, |first| {
                first.to_uppercase().collect::<String>() + characters.as_str()
            })
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn step_type(value: &str) -> &'static str {
    if matches!(value, "approval_decision" | "accept_application") {
        "approval"
    } else if value.starts_with("validate") {
        "validation"
    } else if value.starts_with("verify") {
        "verification"
    } else if value.starts_with("issue") || matches!(value, "create_offer" | "deliver_credential") {
        "issuance"
    } else if matches!(
        value,
        "token_exchange"
            | "presentation_submission"
            | "authentication_submission"
            | "session_establishment"
            | "response_items"
    ) {
        "callback"
    } else if matches!(
        value,
        "wallet_selection"
            | "device_engagement"
            | "request_items"
            | "authorization"
            | "create_request"
    ) {
        "user_input"
    } else if matches!(
        value,
        "notify_holder" | "revoke_old_credential" | "update_status_list" | "session_termination"
    ) {
        "end"
    } else {
        "wait"
    }
}

fn serialization(field: &'static str) -> FlowDefinitionMutationError {
    FlowDefinitionMutationError::Serialization(field)
}
