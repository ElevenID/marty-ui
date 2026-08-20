use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use mmf_security::{canonical_event_payload, ApplicationEventEvidence};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    application_approved_trigger, effective_flow_type, start_instance_record_with_trusted_context,
    ApplicationApprovedWebhook, ApplicationEventReceipt, FlowApiError, FlowDefinitionRecord,
    FlowInstanceExecutionError, FlowInstanceRecord, FlowRecordError, FlowType, StartFlowRequest,
    ValidateRequest,
};

const PRECONDITION_EVIDENCE_KEY: &str = "_marty_precondition_evidence_v1";
const SEMANTICS_V1_KEY: &str = "_marty_application_offer_semantics_hash_v1";
const SEMANTICS_V2_KEY: &str = "_marty_application_offer_semantics_hash_v2";

#[derive(Clone, Debug, PartialEq)]
pub struct PlannedApplicationFlowRecord {
    pub instance: FlowInstanceRecord,
    pub plan_entry: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PreparedApplicationEventPlan {
    pub receipt: ApplicationEventReceipt,
    pub planned_flows: Vec<PlannedApplicationFlowRecord>,
    pub manual_issue: bool,
}

#[derive(Debug, Error)]
pub enum ApplicationApprovalError {
    #[error(transparent)]
    Api(#[from] FlowApiError),
    #[error(transparent)]
    Execution(#[from] FlowInstanceExecutionError),
    #[error(transparent)]
    Record(#[from] FlowRecordError),
    #[error("FLOW.APPLICATION_OFFER_CONFLICT: {0}")]
    Conflict(&'static str),
    #[error("FLOW.APPLICATION_EVENT_INVALID_CLOCK")]
    InvalidClock,
    #[error("FLOW.APPLICATION_EVENT_CANONICALIZATION")]
    Canonicalization,
}

pub fn prepare_application_event_plan(
    event: &ApplicationApprovedWebhook,
    evidence: &ApplicationEventEvidence,
    definitions: &[FlowDefinitionRecord],
    now: DateTime<Utc>,
) -> Result<PreparedApplicationEventPlan, ApplicationApprovalError> {
    event.validate()?;
    let applicant_id = required_data_string(event, "applicant_id")?;
    let requested_template_id = optional_data_string(event, "credential_template_id")?;
    let triggered_by_event = optional_data_string(event, "triggered_by_event")?
        .unwrap_or_else(|| "application.approved".into());
    let manual_issue = triggered_by_event == "application.manual_issue";
    let issuance_attempt_id = optional_canonical_uuid(event, "issuance_attempt_id")?;
    if manual_issue && issuance_attempt_id.is_none() {
        return Err(ApplicationApprovalError::Conflict(
            "manual application issuance requires issuance_attempt_id",
        ));
    }
    let claims = match event.data.get("claims") {
        Some(Value::Object(claims)) => Value::Object(claims.clone()),
        Some(Value::Null) | None => json!({}),
        Some(_) => {
            return Err(ApplicationApprovalError::Conflict(
                "application claims must be a JSON object",
            ))
        }
    };

    let mut matching = definitions
        .iter()
        .filter(|definition| {
            application_approved_trigger(definition)
                && requested_template_id.as_deref().is_none_or(|expected| {
                    definition.credential_template_id.as_deref() == Some(expected)
                })
        })
        .collect::<Vec<_>>();
    matching.sort_unstable_by(|left, right| left.id.cmp(&right.id));

    let mut planned_flows = Vec::with_capacity(matching.len());
    for definition in matching {
        if effective_flow_type(definition) != FlowType::Oid4vciPreAuthorized {
            continue;
        }
        let logical_key = application_flow_logical_key(
            &event.organization_id,
            &event.aggregate_id,
            issuance_attempt_id.as_deref(),
            &definition.id,
        )?;
        let (semantics_hash, semantics_key) = application_offer_semantics(
            event,
            definition,
            &applicant_id,
            &claims,
            issuance_attempt_id.as_deref(),
        )?;
        let initial_context = json!({
            "applicant_id": applicant_id,
            "application_id": event.aggregate_id,
            "application_status": "approved",
            "application_approved_at": event.timestamp,
            "applicant_email": event.data.get("email").cloned().unwrap_or(Value::Null),
            "applicant_given_name": event.data.get("given_name").cloned().unwrap_or(Value::Null),
            "applicant_family_name": event.data.get("family_name").cloned().unwrap_or(Value::Null),
            "vetting_level": event.data.get("vetting_level").cloned().unwrap_or(Value::Null),
            "triggered_by_event": triggered_by_event,
            "claims": claims
        });
        let mut trusted = Map::new();
        trusted.insert(
            PRECONDITION_EVIDENCE_KEY.into(),
            json!({"application_approved": evidence}),
        );
        trusted.insert(semantics_key.into(), Value::String(semantics_hash.clone()));
        if let Some(attempt_id) = &issuance_attempt_id {
            trusted.insert(
                "issuance_attempt_id".into(),
                Value::String(attempt_id.clone()),
            );
        }
        let mut instance = start_instance_record_with_trusted_context(
            definition,
            StartFlowRequest {
                organization_id: event.organization_id.clone(),
                flow_definition_id: definition.id.clone(),
                subject_id: Some(applicant_id.clone()),
                subject_type: "applicant".into(),
                external_reference: Some(format!("application-flow:{logical_key}")),
                initial_context,
            },
            "application-approved-event",
            now,
            trusted,
        )?;
        instance.application_flow_key_hash = Some(logical_key.clone());
        instance.kernel()?;
        planned_flows.push(PlannedApplicationFlowRecord {
            instance,
            plan_entry: BTreeMap::from([
                ("flow_definition_id".into(), definition.id.clone()),
                ("application_flow_key_hash".into(), logical_key),
                ("offer_semantics_hash".into(), semantics_hash),
                ("offer_semantics_context_key".into(), semantics_key.into()),
                (
                    "flow_definition_version".into(),
                    definition.version.to_string(),
                ),
            ]),
        });
    }

    let now_ms = u64::try_from(now.timestamp_millis())
        .map_err(|_| ApplicationApprovalError::InvalidClock)?;
    Ok(PreparedApplicationEventPlan {
        receipt: ApplicationEventReceipt {
            event_id_sha256: evidence.event_id_sha256.clone(),
            payload_sha256: evidence.payload_sha256.clone(),
            organization_id: event.organization_id.clone(),
            application_id: event.aggregate_id.clone(),
            flow_plan: Vec::new(),
            created_at_ms: now_ms,
            updated_at_ms: now_ms,
        },
        planned_flows,
        manual_issue,
    })
}

pub fn application_flow_logical_key(
    organization_id: &str,
    application_id: &str,
    issuance_attempt_id: Option<&str>,
    flow_definition_id: &str,
) -> Result<String, ApplicationApprovalError> {
    let (version, material) = issuance_attempt_id.map_or_else(
        || {
            (
                "v1",
                json!([organization_id, application_id, flow_definition_id]),
            )
        },
        |attempt_id| {
            (
                "v2",
                json!([
                    organization_id,
                    application_id,
                    attempt_id,
                    flow_definition_id
                ]),
            )
        },
    );
    let material =
        serde_json::to_string(&material).map_err(|_| ApplicationApprovalError::Canonicalization)?;
    Ok(sha256_hex(
        format!("marty:application-flow-offer:{version}:{material}").as_bytes(),
    ))
}

fn application_offer_semantics(
    event: &ApplicationApprovedWebhook,
    definition: &FlowDefinitionRecord,
    applicant_id: &str,
    claims: &Value,
    issuance_attempt_id: Option<&str>,
) -> Result<(String, &'static str), ApplicationApprovalError> {
    let mut payload = json!({
        "application_id": event.aggregate_id,
        "organization_id": definition.organization_id,
        "flow_definition_id": definition.id,
        "flow_definition_name": definition.name,
        "flow_definition_description": definition.description,
        "flow_definition_version": definition.version,
        "flow_status": definition.status,
        "flow_type": definition.flow_type,
        "flow_extension": definition.extension.clone().unwrap_or_else(|| json!({})),
        "steps": definition.steps,
        "transitions": definition.transitions,
        "start_step_id": definition.start_step_id,
        "preconditions": definition.preconditions,
        "credential_template_id": definition.credential_template_id,
        "application_template_id": definition.application_template_id,
        "presentation_policy_id": definition.presentation_policy_id,
        "delivery_destination_profile_id": definition.delivery_destination_profile_id,
        "deployment_profile_id": definition.deployment_profile_id,
        "deployment_profile_ids": definition.deployment_profile_ids,
        "trust_profile_id": definition.trust_profile_id,
        "approval_strategy": definition.approval_strategy,
        "hooks": definition.hooks,
        "trigger": definition.trigger,
        "default_timeout_seconds": definition.default_timeout_seconds,
        "max_retries": definition.max_retries,
        "retry_cooldown_minutes": definition.retry_cooldown_minutes,
        "enable_resume": definition.enable_resume,
        "applicant_id": applicant_id,
        "claims": claims
    });
    let (version, context_key) =
        issuance_attempt_id.map_or(("v1", SEMANTICS_V1_KEY), |attempt_id| {
            payload["issuance_attempt_id"] = Value::String(attempt_id.into());
            ("v2", SEMANTICS_V2_KEY)
        });
    let canonical = canonical_event_payload(&payload)
        .map_err(|_| ApplicationApprovalError::Canonicalization)?;
    let mut material = format!("marty:application-offer-semantics:{version}:").into_bytes();
    material.extend(canonical);
    Ok((sha256_hex(&material), context_key))
}

fn required_data_string(
    event: &ApplicationApprovedWebhook,
    name: &'static str,
) -> Result<String, ApplicationApprovalError> {
    optional_data_string(event, name)?.ok_or(ApplicationApprovalError::Conflict(
        "application event is missing applicant_id",
    ))
}

fn optional_data_string(
    event: &ApplicationApprovedWebhook,
    name: &'static str,
) -> Result<Option<String>, ApplicationApprovalError> {
    match event.data.get(name) {
        Some(Value::String(value)) if !value.trim().is_empty() => Ok(Some(value.trim().into())),
        Some(Value::Null) | None | Some(Value::String(_)) => Ok(None),
        Some(_) => Err(ApplicationApprovalError::Conflict(
            "application event string field has an invalid type",
        )),
    }
}

fn optional_canonical_uuid(
    event: &ApplicationApprovedWebhook,
    name: &'static str,
) -> Result<Option<String>, ApplicationApprovalError> {
    let Some(value) = optional_data_string(event, name)? else {
        return Ok(None);
    };
    let canonical = Uuid::parse_str(&value)
        .map_err(|_| {
            ApplicationApprovalError::Conflict(
                "issuance_attempt_id must be a canonical UUID string",
            )
        })?
        .to_string();
    if canonical != value.to_ascii_lowercase() {
        return Err(ApplicationApprovalError::Conflict(
            "issuance_attempt_id must be a canonical UUID string",
        ));
    }
    Ok(Some(canonical))
}

fn sha256_hex(input: &[u8]) -> String {
    Sha256::digest(input)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
