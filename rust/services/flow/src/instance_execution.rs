use chrono::{DateTime, Duration, Utc};
use marty_verification::flow::{select_next_step, FlowInstanceStatus, TransitionOutcome};
use serde_json::{json, Map, Value};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    AdvanceFlowRequest, DefinitionStatus, FlowApiError, FlowDefinitionRecord, FlowDomainError,
    FlowInstanceRecord, FlowRecordError, FlowType, StartFlowRequest, ValidateRequest,
};

const PRECONDITION_EVIDENCE_KEY: &str = "_marty_precondition_evidence_v1";

#[derive(Debug, Error)]
pub enum FlowInstanceExecutionError {
    #[error(transparent)]
    Api(#[from] FlowApiError),
    #[error(transparent)]
    Domain(#[from] FlowDomainError),
    #[error(transparent)]
    Record(#[from] FlowRecordError),
    #[error("FLOW.DEFINITION_NOT_ACTIVE")]
    DefinitionNotActive,
    #[error("FLOW.DEFINITION_TENANT_MISMATCH")]
    DefinitionTenantMismatch,
    #[error("FLOW.INSTANCE_DEFINITION_MISMATCH")]
    InstanceDefinitionMismatch,
    #[error("FLOW.INSTANCE_NOT_ADVANCEABLE: {0}")]
    NotAdvanceable(FlowInstanceStatus),
    #[error("FLOW.INSTANCE_NO_CURRENT_STEP")]
    NoCurrentStep,
    #[error("FLOW.INVALID_STEP_RESULT: {0}")]
    InvalidStepResult(String),
    #[error("FLOW.PRECONDITIONS_NOT_MET: {0}")]
    PreconditionsNotMet(String),
    #[error("FLOW.INVALID_SYSTEM_CLOCK")]
    InvalidClock,
    #[error("FLOW.INVALID_CONTEXT")]
    InvalidContext,
}

pub fn start_instance_record(
    definition: &FlowDefinitionRecord,
    request: StartFlowRequest,
    actor: &str,
    now: DateTime<Utc>,
) -> Result<FlowInstanceRecord, FlowInstanceExecutionError> {
    start_instance_record_with_trusted_context(definition, request, actor, now, Map::new())
}

pub fn start_instance_record_with_trusted_context(
    definition: &FlowDefinitionRecord,
    request: StartFlowRequest,
    actor: &str,
    now: DateTime<Utc>,
    trusted_context: Map<String, Value>,
) -> Result<FlowInstanceRecord, FlowInstanceExecutionError> {
    request.validate()?;
    if request.organization_id != definition.organization_id {
        return Err(FlowInstanceExecutionError::DefinitionTenantMismatch);
    }
    if definition.status != DefinitionStatus::Active {
        return Err(FlowInstanceExecutionError::DefinitionNotActive);
    }
    definition.kernel()?;
    let mut context = request
        .initial_context
        .as_object()
        .cloned()
        .ok_or(FlowInstanceExecutionError::InvalidContext)?;
    context.extend(trusted_context);
    require_preconditions(definition, &context)?;
    let status = if definition.start_step_id.is_some() {
        FlowInstanceStatus::InProgress
    } else {
        FlowInstanceStatus::Pending
    };
    sync_protocol_context(
        &mut context,
        definition,
        definition.start_step_id.as_deref(),
    );
    let state_history = vec![json!({
        "prior_state": null,
        "new_state": serde_json::to_value(status).map_err(|_| FlowInstanceExecutionError::InvalidContext)?,
        "timestamp": now.to_rfc3339(),
        "actor": actor,
        "event": "flow_instance_created"
    })];
    let step_history = definition
        .start_step_id
        .as_ref()
        .map_or_else(Vec::new, |step_id| {
            vec![json!({
                "step_id": step_id,
                "entered_at": now.to_rfc3339(),
                "status": "entered"
            })]
        });
    let expires_at = now
        .checked_add_signed(Duration::seconds(i64::from(
            definition.default_timeout_seconds,
        )))
        .ok_or(FlowInstanceExecutionError::InvalidClock)?;
    let record = FlowInstanceRecord {
        id: Uuid::new_v4().to_string(),
        flow_definition_id: definition.id.clone(),
        organization_id: definition.organization_id.clone(),
        status,
        current_step_id: definition.start_step_id.clone(),
        context: Value::Object(context),
        step_history,
        state_history,
        subject_id: request.subject_id,
        subject_type: request.subject_type,
        external_reference: request.external_reference,
        application_flow_key_hash: None,
        started_at: Some(now),
        completed_at: None,
        expires_at: Some(expires_at),
        result: None,
        error: None,
        created_at: now,
        updated_at: now,
    };
    record.kernel()?;
    Ok(record)
}

pub fn advance_instance_record(
    definition: &FlowDefinitionRecord,
    instance: &FlowInstanceRecord,
    request: AdvanceFlowRequest,
    actor: &str,
    now: DateTime<Utc>,
) -> Result<FlowInstanceRecord, FlowInstanceExecutionError> {
    request.validate()?;
    if instance.flow_definition_id != definition.id
        || instance.organization_id != definition.organization_id
    {
        return Err(FlowInstanceExecutionError::InstanceDefinitionMismatch);
    }
    if !matches!(
        instance.status,
        FlowInstanceStatus::InProgress | FlowInstanceStatus::AwaitingWallet
    ) {
        return Err(FlowInstanceExecutionError::NotAdvanceable(instance.status));
    }
    let definition_kernel = definition.kernel()?;
    let current_step_id = instance
        .current_step_id
        .as_deref()
        .ok_or(FlowInstanceExecutionError::NoCurrentStep)?;
    let outcome = parse_outcome(&request.step_result)?;
    let mut updated = instance.clone();
    let mut kernel = updated.kernel()?;
    let mut context = updated
        .context
        .as_object()
        .cloned()
        .ok_or(FlowInstanceExecutionError::InvalidContext)?;
    require_current_step_preconditions(definition, current_step_id, &context)?;

    let now_ms = u64::try_from(now.timestamp_millis())
        .map_err(|_| FlowInstanceExecutionError::InvalidClock)?;
    if kernel.status == FlowInstanceStatus::AwaitingWallet {
        kernel.transition_to(
            FlowInstanceStatus::InProgress,
            Some(actor.into()),
            Some("wallet_step_response_received".into()),
            now_ms,
        )?;
    }
    let next_step_id =
        select_next_step(&definition_kernel.graph_request(), current_step_id, outcome)
            .map_err(|error| FlowDomainError::InvalidDefinition(error.to_string()))?;
    merge_context(&mut context, request.data)?;
    complete_current_step(
        &mut updated.step_history,
        &mut context,
        definition,
        current_step_id,
        &request.step_result,
        now,
    );

    if let Some(next_step_id) = next_step_id {
        kernel.current_step_id = Some(next_step_id.clone());
        sync_protocol_context(&mut context, definition, Some(&next_step_id));
        updated.step_history.push(json!({
            "step_id": next_step_id,
            "entered_at": now.to_rfc3339(),
            "status": "entered"
        }));
        if step_type(definition, &next_step_id) == Some("end") {
            kernel.transition_to(
                FlowInstanceStatus::Completed,
                Some(actor.into()),
                Some("flow_completed".into()),
                now_ms,
            )?;
            kernel.result = Some(Value::Object(context.clone()));
        }
    } else if outcome == TransitionOutcome::Failure {
        kernel.transition_to(
            FlowInstanceStatus::Failed,
            Some(actor.into()),
            Some("flow_failed".into()),
            now_ms,
        )?;
        kernel.error = Some("Step failed with no recovery transition".into());
    } else {
        kernel.transition_to(
            FlowInstanceStatus::Completed,
            Some(actor.into()),
            Some("flow_completed".into()),
            now_ms,
        )?;
    }

    updated.status = kernel.status;
    updated.current_step_id = kernel.current_step_id;
    updated.context = Value::Object(context);
    updated.state_history = kernel
        .state_history
        .into_iter()
        .map(|entry| {
            serde_json::to_value(entry).map_err(|_| FlowInstanceExecutionError::InvalidContext)
        })
        .collect::<Result<_, _>>()?;
    updated.completed_at = kernel
        .completed_at_ms
        .map(millis_to_timestamp)
        .transpose()?;
    updated.result = kernel.result;
    updated.error = kernel.error;
    updated.updated_at = now;
    updated.kernel()?;
    Ok(updated)
}

fn require_preconditions(
    definition: &FlowDefinitionRecord,
    context: &Map<String, Value>,
) -> Result<(), FlowInstanceExecutionError> {
    let mut required = definition.preconditions.clone();
    if application_approved_trigger(definition) {
        required.push("application_approved".into());
    }
    for step in &definition.steps {
        if step.get("step_type").and_then(Value::as_str) != Some("approval") {
            continue;
        }
        append_configured_preconditions(&mut required, step);
    }
    verify_preconditions(&required, context)
}

fn require_current_step_preconditions(
    definition: &FlowDefinitionRecord,
    current_step_id: &str,
    context: &Map<String, Value>,
) -> Result<(), FlowInstanceExecutionError> {
    let Some(step) = definition
        .steps
        .iter()
        .find(|step| step["id"] == current_step_id)
    else {
        return Err(FlowInstanceExecutionError::NoCurrentStep);
    };
    if step.get("step_type").and_then(Value::as_str) != Some("approval") {
        return Ok(());
    }
    let mut required = definition.preconditions.clone();
    if required.is_empty() {
        append_configured_preconditions(&mut required, step);
    }
    verify_preconditions(&required, context)
}

fn append_configured_preconditions(required: &mut Vec<String>, step: &Value) {
    match step
        .get("config")
        .and_then(|config| config.get("required_preconditions"))
    {
        Some(Value::Array(values)) => required.extend(
            values
                .iter()
                .filter_map(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .map(str::to_owned),
        ),
        Some(value) if !value.is_null() => {
            required.push("invalid_required_preconditions_configuration".into());
        }
        _ => {}
    }
}

fn verify_preconditions(
    required: &[String],
    context: &Map<String, Value>,
) -> Result<(), FlowInstanceExecutionError> {
    let mut unique = required
        .iter()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    let evidence = context
        .get(PRECONDITION_EVIDENCE_KEY)
        .and_then(Value::as_object);
    unique.retain(|name| !precondition_met(name, evidence));
    if unique.is_empty() {
        Ok(())
    } else {
        Err(FlowInstanceExecutionError::PreconditionsNotMet(
            unique.into_iter().collect::<Vec<_>>().join(","),
        ))
    }
}

fn precondition_met(name: &str, evidence: Option<&Map<String, Value>>) -> bool {
    if name != "application_approved" {
        return false;
    }
    let Some(approval) = evidence
        .and_then(|value| value.get("application_approved"))
        .and_then(Value::as_object)
    else {
        return false;
    };
    approval.get("producer").and_then(Value::as_str) == Some("marty-applicant-service")
        && approval.get("audience").and_then(Value::as_str) == Some("marty-flow-service")
        && approval
            .get("event_id_sha256")
            .and_then(Value::as_str)
            .is_some_and(lower_hex_digest)
        && approval
            .get("payload_sha256")
            .and_then(Value::as_str)
            .is_some_and(lower_hex_digest)
        && approval
            .get("authenticated_at")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.trim().is_empty())
}

fn lower_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn application_approved_trigger(definition: &FlowDefinitionRecord) -> bool {
    effective_flow_type(definition) == FlowType::Oid4vciPreAuthorized
        && definition
            .trigger
            .as_ref()
            .and_then(Value::as_object)
            .is_some_and(|trigger| {
                trigger
                    .get("trigger_type")
                    .and_then(Value::as_str)
                    .is_some_and(|value| value.eq_ignore_ascii_case("WEBHOOK"))
                    && trigger
                        .get("config")
                        .and_then(Value::as_object)
                        .and_then(|config| config.get("event_type"))
                        .and_then(Value::as_str)
                        .is_some_and(|value| value.eq_ignore_ascii_case("APPLICATION_APPROVED"))
            })
}

#[must_use]
pub fn effective_flow_type(definition: &FlowDefinitionRecord) -> FlowType {
    if definition.flow_type != FlowType::Custom {
        return definition.flow_type;
    }
    definition
        .extension
        .as_ref()
        .and_then(|extension| extension.get("extends_flow_type"))
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok())
        .unwrap_or(FlowType::Custom)
}

fn sync_protocol_context(
    context: &mut Map<String, Value>,
    definition: &FlowDefinitionRecord,
    step_id: Option<&str>,
) {
    if !context.get("step_results").is_some_and(Value::is_object) {
        context.insert("step_results".into(), json!({}));
    }
    context.insert(
        "protocol_flow_type".into(),
        json!(effective_flow_type(definition)),
    );
    if let Some(step_id) = step_id {
        if let Some((index, step)) = definition
            .steps
            .iter()
            .enumerate()
            .find(|(_, step)| step["id"] == step_id)
        {
            if let Some(name) = protocol_step(step) {
                context.insert("current_step_name".into(), json!(name));
            }
            context.insert("current_step_index".into(), json!(index));
        }
    }
}

fn complete_current_step(
    history: &mut [Value],
    context: &mut Map<String, Value>,
    definition: &FlowDefinitionRecord,
    current_step_id: &str,
    result: &str,
    now: DateTime<Utc>,
) {
    if let Some(entry) = history.last_mut().and_then(Value::as_object_mut) {
        entry.insert("completed_at".into(), json!(now.to_rfc3339()));
        entry.insert("result".into(), json!(result));
    }
    let Some(name) = definition
        .steps
        .iter()
        .find(|step| step["id"] == current_step_id)
        .and_then(protocol_step)
    else {
        return;
    };
    let results = context.entry("step_results").or_insert_with(|| json!({}));
    if let Some(results) = results.as_object_mut() {
        results.insert(
            name.into(),
            json!({"result": result, "completed_at": now.to_rfc3339()}),
        );
    }
}

fn protocol_step(step: &Value) -> Option<&str> {
    step.get("config")
        .and_then(Value::as_object)
        .and_then(|config| config.get("protocol_step"))
        .or_else(|| step.get("name"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
}

fn step_type<'a>(definition: &'a FlowDefinitionRecord, step_id: &str) -> Option<&'a str> {
    definition
        .steps
        .iter()
        .find(|step| step["id"] == step_id)
        .and_then(|step| step.get("step_type"))
        .and_then(Value::as_str)
}

#[must_use]
pub fn definition_protocol_step<'a>(
    definition: &'a FlowDefinitionRecord,
    step_id: &str,
) -> Option<&'a str> {
    definition
        .steps
        .iter()
        .find(|step| step["id"] == step_id)
        .and_then(protocol_step)
}

fn merge_context(
    context: &mut Map<String, Value>,
    data: Value,
) -> Result<(), FlowInstanceExecutionError> {
    let data = data
        .as_object()
        .ok_or(FlowInstanceExecutionError::InvalidContext)?;
    context.extend(data.clone());
    Ok(())
}

fn parse_outcome(value: &str) -> Result<TransitionOutcome, FlowInstanceExecutionError> {
    serde_json::from_value(Value::String(value.trim().to_ascii_lowercase()))
        .map_err(|_| FlowInstanceExecutionError::InvalidStepResult(value.into()))
}

fn millis_to_timestamp(value: u64) -> Result<DateTime<Utc>, FlowInstanceExecutionError> {
    DateTime::from_timestamp_millis(
        i64::try_from(value).map_err(|_| FlowInstanceExecutionError::InvalidClock)?,
    )
    .ok_or(FlowInstanceExecutionError::InvalidClock)
}
