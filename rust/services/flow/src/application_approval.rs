use std::collections::BTreeMap;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mmf_security::{
    canonical_event_payload, ApplicationEventAuthError, ApplicationEventAuthenticator,
    ApplicationEventEvidence, ApplicationEventReplayStore, ApplicationEventReplayStoreError,
};
use serde::Serialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    application_approved_trigger, effective_flow_type, prepare_instance_start,
    start_instance_record_with_trusted_context, ApplicationApprovedWebhook,
    ApplicationEventReceipt, FlowApiError, FlowDefinitionRecord, FlowInstanceExecutionError,
    FlowInstanceRecord, FlowRecordError, FlowType, PostgresFlowRepository, RepositoryError,
    StartFlowRequest, ValidateRequest,
};

const PRECONDITION_EVIDENCE_KEY: &str = "_marty_precondition_evidence_v1";
const SEMANTICS_V1_KEY: &str = "_marty_application_offer_semantics_hash_v1";
const SEMANTICS_V2_KEY: &str = "_marty_application_offer_semantics_hash_v2";

#[derive(Clone)]
pub struct RedisApplicationEventReplayStore {
    connection: redis::aio::ConnectionManager,
}

impl RedisApplicationEventReplayStore {
    #[must_use]
    pub fn new(connection: redis::aio::ConnectionManager) -> Self {
        Self { connection }
    }
}

#[async_trait]
impl ApplicationEventReplayStore for RedisApplicationEventReplayStore {
    async fn consume(
        &self,
        key: &str,
        payload_sha256: &str,
        ttl_seconds: u64,
    ) -> Result<bool, ApplicationEventReplayStoreError> {
        let mut connection = self.connection.clone();
        let result: Option<String> = redis::cmd("SET")
            .arg(key)
            .arg(payload_sha256)
            .arg("NX")
            .arg("EX")
            .arg(ttl_seconds)
            .query_async(&mut connection)
            .await
            .map_err(|_| ApplicationEventReplayStoreError)?;
        Ok(result.as_deref() == Some("OK"))
    }
}

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

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ApplicationApprovalResponse {
    pub success: bool,
    pub flows_triggered: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub instance_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub offers: Vec<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failed_flow_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Copy)]
pub struct ApplicationEventExecutionContext<'a> {
    pub authenticator: &'a ApplicationEventAuthenticator,
    pub replay_store: &'a dyn ApplicationEventReplayStore,
    pub repository: &'a PostgresFlowRepository,
    pub providers: &'a crate::FlowProviderRegistry,
    pub public_base_url: &'a str,
}

#[derive(Debug, Error)]
pub enum ApplicationApprovalError {
    #[error(transparent)]
    Api(#[from] FlowApiError),
    #[error(transparent)]
    Execution(#[from] FlowInstanceExecutionError),
    #[error(transparent)]
    Record(#[from] FlowRecordError),
    #[error(transparent)]
    Repository(#[from] RepositoryError),
    #[error(transparent)]
    Authentication(#[from] ApplicationEventAuthError),
    #[error("FLOW.APPLICATION_OFFER_CONFLICT: {0}")]
    Conflict(&'static str),
    #[error("FLOW.APPLICATION_EVENT_INVALID_CLOCK")]
    InvalidClock,
    #[error("FLOW.APPLICATION_EVENT_CANONICALIZATION")]
    Canonicalization,
}

pub async fn execute_application_event_plan(
    event: &ApplicationApprovedWebhook,
    evidence: &ApplicationEventEvidence,
    context: ApplicationEventExecutionContext<'_>,
    now: DateTime<Utc>,
) -> Result<ApplicationApprovalResponse, ApplicationApprovalError> {
    let definitions = context
        .repository
        .definitions_for_tenant(&event.organization_id)
        .await?;
    let prepared = prepare_application_event_plan(event, evidence, &definitions, now)?;
    let (receipt, _created) = context
        .repository
        .reserve_application_event_plan(prepared.receipt, &prepared.planned_flows)
        .await?;
    match context
        .authenticator
        .consume(evidence, context.replay_store)
        .await
    {
        Ok(()) => {}
        Err(ApplicationEventAuthError::ReplayedEvent) if !receipt.flow_plan.is_empty() => {}
        Err(error) => return Err(error.into()),
    }

    if receipt.flow_plan.is_empty() {
        let template = optional_data_string(event, "credential_template_id")?;
        let mut reason = format!(
            "No active custom OID4VCI extension handling APPLICATION_APPROVED matched org {}",
            event.organization_id
        );
        if let Some(template) = template {
            reason.push_str(&format!(" and credential template {template}"));
        }
        return Ok(ApplicationApprovalResponse {
            success: !prepared.manual_issue,
            flows_triggered: 0,
            instance_ids: Vec::new(),
            offers: Vec::new(),
            failed_flow_ids: Vec::new(),
            reason: Some(reason),
        });
    }

    let definitions_by_id = definitions
        .iter()
        .map(|definition| (definition.id.as_str(), definition))
        .collect::<BTreeMap<_, _>>();
    let planned_by_id = prepared
        .planned_flows
        .iter()
        .map(|planned| (planned.plan_entry["flow_definition_id"].as_str(), planned))
        .collect::<BTreeMap<_, _>>();
    let mut instance_ids = Vec::new();
    let mut offers = Vec::new();
    let mut failed_flow_ids = Vec::new();
    for entry in &receipt.flow_plan {
        let flow_id = entry
            .get("flow_definition_id")
            .ok_or(ApplicationApprovalError::Conflict(
                "durable application event plan is invalid",
            ))?;
        let definition = definitions_by_id.get(flow_id.as_str()).copied().ok_or(
            ApplicationApprovalError::Conflict(
                "durably selected application flow is unavailable or has changed",
            ),
        )?;
        let current = planned_by_id
            .get(flow_id.as_str())
            .copied()
            .filter(|planned| {
                planned.plan_entry.get("offer_semantics_hash") == entry.get("offer_semantics_hash")
            })
            .ok_or(ApplicationApprovalError::Conflict(
                "durably selected application flow is unavailable or has changed",
            ))?;
        let instance_id = entry
            .get("instance_id")
            .ok_or(ApplicationApprovalError::Conflict(
                "durable application event plan is invalid",
            ))?;
        let Some(instance) = context.repository.instance(instance_id).await? else {
            return Err(ApplicationApprovalError::Conflict(
                "durable application event plan references a missing instance",
            ));
        };
        if instance.application_flow_key_hash != current.instance.application_flow_key_hash {
            return Err(ApplicationApprovalError::Conflict(
                "durable application event plan identity changed",
            ));
        }

        match complete_application_offer(
            context.repository,
            context.providers,
            definition,
            instance,
            context.public_base_url,
            now,
        )
        .await
        {
            Ok((instance, artifact)) => {
                instance_ids.push(instance.id.clone());
                offers.push(application_offer_projection(
                    definition, &instance, &artifact,
                ));
            }
            Err(_) => failed_flow_ids.push(flow_id.clone()),
        }
    }
    Ok(ApplicationApprovalResponse {
        success: failed_flow_ids.is_empty(),
        flows_triggered: instance_ids.len(),
        instance_ids,
        offers,
        failed_flow_ids,
        reason: None,
    })
}

async fn complete_application_offer(
    repository: &PostgresFlowRepository,
    providers: &crate::FlowProviderRegistry,
    definition: &FlowDefinitionRecord,
    instance: FlowInstanceRecord,
    public_base_url: &str,
    now: DateTime<Utc>,
) -> Result<(FlowInstanceRecord, crate::FlowArtifactRecord), ApplicationApprovalError> {
    if let Some(artifact) = repository
        .artifacts_for_instance(&instance.id)
        .await?
        .into_iter()
        .find(|artifact| artifact.status == crate::ArtifactStatus::Active)
    {
        return Ok((instance, artifact));
    }
    let expected_updated_at = instance.updated_at;
    let mut prepared =
        prepare_instance_start(providers, definition, instance, public_base_url, now)
            .await
            .map_err(|_| {
                ApplicationApprovalError::Conflict("application offer initiation failed")
            })?;
    let artifact = prepared
        .artifact
        .take()
        .ok_or(ApplicationApprovalError::Conflict(
            "application offer initiation returned no artifact",
        ))?;
    prepared.instance.updated_at =
        std::cmp::max(now, expected_updated_at + chrono::Duration::microseconds(1));
    if repository
        .replace_active_artifacts(
            &prepared.instance,
            &artifact,
            expected_updated_at,
            prepared.instance.updated_at,
        )
        .await?
    {
        return Ok((prepared.instance, artifact));
    }
    let current = repository.instance(&prepared.instance.id).await?.ok_or(
        ApplicationApprovalError::Conflict("application flow disappeared during offer completion"),
    )?;
    let artifact = repository
        .artifacts_for_instance(&current.id)
        .await?
        .into_iter()
        .find(|candidate| candidate.status == crate::ArtifactStatus::Active)
        .ok_or(ApplicationApprovalError::Conflict(
            "concurrent application offer completion did not persist an artifact",
        ))?;
    Ok((current, artifact))
}

fn application_offer_projection(
    definition: &FlowDefinitionRecord,
    instance: &FlowInstanceRecord,
    artifact: &crate::FlowArtifactRecord,
) -> Value {
    json!({
        "flow_definition_id": definition.id,
        "flow_definition_name": definition.name,
        "flow_instance_id": instance.id,
        "artifact_id": artifact.id,
        "credential_offer_transaction_id": instance.context.get("credential_offer_transaction_id"),
        "credential_offer_uri": artifact.credential_offer_uri,
        "credential_offer_uris": instance.context.get("credential_offer_uris").cloned().unwrap_or_else(|| json!({})),
        "credential_offer_labels": instance.context.get("credential_offer_labels").cloned().unwrap_or_else(|| json!({})),
        "pre_authorized_code": artifact.pre_authorized_code,
        "expires_at": artifact.expires_at.map(|value| value.to_rfc3339()),
        "issuance_status": instance.context.get("issuance_status").cloned().unwrap_or_else(|| json!("pending"))
    })
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
