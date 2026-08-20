use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
use marty_verification::flow::TransitionOutcome;
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use serde_json::{json, Map, Value};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    definition_protocol_step, effective_flow_type, ArtifactStatus, CredentialTemplateReference,
    FlowArtifactRecord, FlowDefinitionRecord, FlowInstanceRecord, FlowProviderError,
    FlowProviderRegistry, FlowType, IssuanceInitiationRequest, PhysicalDocumentOperation,
    PhysicalDocumentRequest, PhysicalDocumentResult,
};

const MIP_MESSAGE_VERSION: &str = "0.3.1";
const PYTHON_QUOTE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'/')
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

#[derive(Clone, Debug, PartialEq)]
pub struct PreparedInstanceStart {
    pub instance: FlowInstanceRecord,
    pub artifact: Option<FlowArtifactRecord>,
}

#[derive(Debug, Error)]
pub enum FlowInstanceSideEffectError {
    #[error(transparent)]
    Provider(#[from] FlowProviderError),
    #[error("FLOW.INSTANCE_SIDE_EFFECT_INVALID_CONTEXT: {0}")]
    InvalidContext(&'static str),
    #[error("FLOW.INSTANCE_SIDE_EFFECT_INVALID_RESPONSE: {0}")]
    InvalidResponse(&'static str),
    #[error("FLOW.INSTANCE_SIDE_EFFECT_PROTOCOL: {0}")]
    Protocol(String),
    #[error("FLOW.INSTANCE_SIDE_EFFECT_INVALID_CLOCK")]
    InvalidClock,
}

pub async fn prepare_instance_start(
    providers: &FlowProviderRegistry,
    definition: &FlowDefinitionRecord,
    mut instance: FlowInstanceRecord,
    public_base_url: &str,
    now: DateTime<Utc>,
) -> Result<PreparedInstanceStart, FlowInstanceSideEffectError> {
    match effective_flow_type(definition) {
        FlowType::PhysicalDocumentIssuance => {
            initialize_physical_document(providers, definition, &mut instance).await?;
            Ok(PreparedInstanceStart {
                instance,
                artifact: None,
            })
        }
        FlowType::Oid4vciPreAuthorized => {
            let artifact =
                initialize_oid4vci(providers, definition, &mut instance, public_base_url, now)
                    .await?;
            Ok(PreparedInstanceStart {
                instance,
                artifact: Some(artifact),
            })
        }
        _ => Ok(PreparedInstanceStart {
            instance,
            artifact: None,
        }),
    }
}

pub async fn apply_physical_advance_side_effect(
    providers: &FlowProviderRegistry,
    definition: &FlowDefinitionRecord,
    mut instance: FlowInstanceRecord,
    outcome: TransitionOutcome,
    data: &Value,
) -> Result<FlowInstanceRecord, FlowInstanceSideEffectError> {
    if effective_flow_type(definition) != FlowType::PhysicalDocumentIssuance
        || outcome != TransitionOutcome::Success
    {
        return Ok(instance);
    }
    let step_id =
        instance
            .current_step_id
            .as_deref()
            .ok_or(FlowInstanceSideEffectError::InvalidContext(
                "current_step_id is required",
            ))?;
    let Some(operation) =
        definition_protocol_step(definition, step_id).and_then(physical_operation_for_step)
    else {
        return Ok(instance);
    };
    let context = context_mut(&mut instance)?;
    let application_id = context
        .get("physical_document_job")
        .and_then(Value::as_object)
        .and_then(|job| job.get("application_id"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or(FlowInstanceSideEffectError::InvalidContext(
            "physical document job is not initialized",
        ))?;
    let mut request_data = BTreeMap::from([(
        "application_id".into(),
        Value::String(application_id.into()),
    )]);
    if operation == PhysicalDocumentOperation::QualityVerify {
        request_data.insert(
            "passed".into(),
            Value::Bool(data.get("passed").and_then(Value::as_bool).unwrap_or(false)),
        );
        request_data.insert(
            "failure_codes".into(),
            data.get("failure_codes")
                .cloned()
                .unwrap_or_else(|| json!([])),
        );
    }
    let provider = providers
        .physical_document
        .as_ref()
        .ok_or(FlowProviderError::Unavailable {
            provider: "physical_document",
        })?;
    let result = provider
        .execute(&PhysicalDocumentRequest {
            organization_id: instance.organization_id.clone(),
            flow_instance_id: instance.id.clone(),
            operation,
            data: request_data,
        })
        .await?;
    validate_physical_result(operation, &result, None)?;
    context_mut(&mut instance)?.insert(
        "physical_document_job".into(),
        serde_json::to_value(result.data)
            .map_err(|_| FlowInstanceSideEffectError::InvalidResponse("physical document job"))?,
    );
    Ok(instance)
}

async fn initialize_physical_document(
    providers: &FlowProviderRegistry,
    definition: &FlowDefinitionRecord,
    instance: &mut FlowInstanceRecord,
) -> Result<(), FlowInstanceSideEffectError> {
    let physical = context_mut(instance)?
        .remove("physical_document")
        .and_then(|value| value.as_object().cloned())
        .ok_or(FlowInstanceSideEffectError::InvalidContext(
            "initial_context.physical_document is required",
        ))?;
    for field in ["country_code", "applicant", "mrz", "data_groups"] {
        if physical.get(field).is_none_or(empty_json_value) {
            return Err(FlowInstanceSideEffectError::InvalidContext(
                "physical_document is missing required fields",
            ));
        }
    }
    let required_reference = |value: &Option<String>| {
        value
            .clone()
            .filter(|value| !value.trim().is_empty())
            .ok_or(FlowInstanceSideEffectError::InvalidContext(
                "physical document definition references are required",
            ))
    };
    let data = BTreeMap::from([
        (
            "application_template_id".into(),
            json!(required_reference(&definition.application_template_id)?),
        ),
        (
            "credential_template_id".into(),
            json!(required_reference(&definition.credential_template_id)?),
        ),
        (
            "delivery_destination_profile_id".into(),
            json!(required_reference(
                &definition.delivery_destination_profile_id
            )?),
        ),
        (
            "document_type".into(),
            physical
                .get("document_type")
                .cloned()
                .unwrap_or_else(|| json!("TD3")),
        ),
        ("country_code".into(), physical["country_code"].clone()),
        ("applicant".into(), physical["applicant"].clone()),
        ("mrz".into(), physical["mrz"].clone()),
        ("data_groups".into(), physical["data_groups"].clone()),
    ]);
    let provider = providers
        .physical_document
        .as_ref()
        .ok_or(FlowProviderError::Unavailable {
            provider: "physical_document",
        })?;
    let result = provider
        .execute(&PhysicalDocumentRequest {
            organization_id: instance.organization_id.clone(),
            flow_instance_id: instance.id.clone(),
            operation: PhysicalDocumentOperation::Initialize,
            data,
        })
        .await?;
    let application_id = validate_physical_result(
        PhysicalDocumentOperation::Initialize,
        &result,
        Some(&instance.id),
    )?;
    let context = context_mut(instance)?;
    context.insert("physical_document_job".into(), json!(result.data));
    context.insert("application_id".into(), json!(application_id));
    Ok(())
}

async fn initialize_oid4vci(
    providers: &FlowProviderRegistry,
    definition: &FlowDefinitionRecord,
    instance: &mut FlowInstanceRecord,
    public_base_url: &str,
    now: DateTime<Utc>,
) -> Result<FlowArtifactRecord, FlowInstanceSideEffectError> {
    let template_id = definition
        .credential_template_id
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or(FlowInstanceSideEffectError::InvalidContext(
            "credential template is required",
        ))?;
    let template_provider =
        providers
            .credential_template
            .as_ref()
            .ok_or(FlowProviderError::Unavailable {
                provider: "credential_template",
            })?;
    let template = template_provider.get_template(template_id).await?;
    validate_template(&template, template_id, &instance.organization_id)?;
    let context =
        instance
            .context
            .as_object()
            .ok_or(FlowInstanceSideEffectError::InvalidContext(
                "instance context must be an object",
            ))?;
    let claims = context
        .get("claims")
        .and_then(Value::as_object)
        .map(|claims| claims.clone().into_iter().collect())
        .unwrap_or_default();
    let application_id = nonempty_context_string(context, "application_id");
    let idempotency_key = instance
        .application_flow_key_hash
        .as_ref()
        .filter(|_| application_id.is_some())
        .map_or_else(
            || format!("flow-instance-offer-v1:{}", instance.id),
            |digest| format!("application-flow-offer-v1:{digest}"),
        );
    let issuance = providers
        .issuance
        .as_ref()
        .ok_or(FlowProviderError::Unavailable {
            provider: "issuance",
        })?
        .initiate(&IssuanceInitiationRequest {
            organization_id: instance.organization_id.clone(),
            flow_instance_id: instance.id.clone(),
            credential_template_id: template_id.into(),
            applicant_id: instance.subject_id.clone(),
            subject_did: nonempty_context_string(context, "subject_did"),
            holder_did: nonempty_context_string(context, "holder_did"),
            authorized_client_id: None,
            application_id,
            issuer_did: template.issuer_did.clone(),
            delivery_mode: Some("wallet_only".into()),
            idempotency_key: Some(idempotency_key),
            claims,
        })
        .await?;
    let mut offer_uris = issuance.credential_offer_uris;
    let mut offer_labels = issuance.credential_offer_labels;
    if offer_uris.is_empty() {
        if let Some(code) = issuance.pre_authorized_code.as_deref() {
            (offer_uris, offer_labels) =
                build_wallet_offers(&template, &instance.organization_id, code, public_base_url);
        }
    }
    let offer_uri = issuance
        .credential_offer_uri
        .or_else(|| offer_uris.values().find(|value| !value.is_empty()).cloned())
        .ok_or(FlowInstanceSideEffectError::InvalidResponse(
            "issuance did not return a credential offer URI",
        ))?;
    let expires_at = issuance
        .expires_at_ms
        .map(|value| {
            DateTime::from_timestamp_millis(
                i64::try_from(value).map_err(|_| FlowInstanceSideEffectError::InvalidClock)?,
            )
            .ok_or(FlowInstanceSideEffectError::InvalidClock)
        })
        .transpose()?
        .or_else(|| now.checked_add_signed(Duration::minutes(15)))
        .ok_or(FlowInstanceSideEffectError::InvalidClock)?;
    let artifact_id = Uuid::new_v4().to_string();
    let artifact = FlowArtifactRecord {
        id: artifact_id.clone(),
        flow_instance_id: instance.id.clone(),
        issuance_transaction_id: Some(issuance.transaction_id.clone()),
        credential_offer_uri: Some(offer_uri.clone()),
        credential_offer_uris: offer_uris.clone(),
        credential_offer_labels: offer_labels.clone(),
        pre_authorized_code: issuance.pre_authorized_code.clone(),
        issuance_status: Some(issuance.status.clone()),
        qr_payload: None,
        expires_at: Some(expires_at),
        scanned_at: None,
        status: ArtifactStatus::Active,
        state: Some(issuance.transaction_id.clone()),
        wallet_metadata: json!({}),
        attempt_number: 1,
        created_at: now,
        updated_at: now,
    };
    let instance_id = instance.id.clone();
    let context = context_mut(instance)?;
    context.insert("oid4vci_artifact_id".into(), json!(artifact_id));
    context.insert(
        "credential_offer_transaction_id".into(),
        json!(issuance.transaction_id),
    );
    context.insert("offer_id".into(), json!(artifact.issuance_transaction_id));
    context.insert("credential_offer_uri".into(), json!(offer_uri));
    context.insert("credential_offer_uris".into(), json!(offer_uris));
    context.insert("credential_offer_labels".into(), json!(offer_labels));
    context.insert("issuance_status".into(), json!(issuance.status));
    if let Some(code) = issuance.pre_authorized_code {
        context.insert("pre_auth_code".into(), json!(code));
    }
    let message = json!({
        "mip_version": MIP_MESSAGE_VERSION,
        "message_type": "CredentialOffer",
        "message_id": Uuid::new_v4().to_string(),
        "correlation_id": instance_id,
        "timestamp": now.to_rfc3339(),
        "sender_id": public_base_url,
        "nonce": null,
        "payload": {
            "credential_issuer": public_base_url,
            "credential_configuration_ids": [template_id],
            "grants": {
                "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                    "pre-authorized_code": artifact.pre_authorized_code
                }
            },
            "mip_flow_instance_id": instance_id
        },
        "signature": null
    });
    context
        .entry("mip_messages")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or(FlowInstanceSideEffectError::InvalidContext(
            "mip_messages must be an object",
        ))?
        .insert("credential_offer".into(), message);
    Ok(artifact)
}

fn build_wallet_offers(
    template: &CredentialTemplateReference,
    organization_id: &str,
    pre_authorized_code: &str,
    public_base_url: &str,
) -> (BTreeMap<String, String>, BTreeMap<String, String>) {
    let mut uris = BTreeMap::new();
    let mut labels = BTreeMap::new();
    let issuer_url = format!(
        "{}/org/{organization_id}",
        public_base_url.trim_end_matches('/')
    );
    for wallet in &template.wallet_configurations {
        if wallet.wallet_id.trim().is_empty() {
            continue;
        }
        let suffix = if wallet.format_variant.as_deref() == Some("mso_mdoc") {
            "mdoc"
        } else {
            "sd-jwt"
        };
        let configuration = format!("{}#{suffix}", template.credential_type);
        let Ok(offer) = marty_oid4vci::issuer::create_credential_offer(
            &issuer_url,
            &[configuration],
            Some(pre_authorized_code),
            false,
        ) else {
            continue;
        };
        let separator = if wallet.deep_link_scheme.contains('?') {
            '&'
        } else {
            '?'
        };
        uris.insert(
            wallet.wallet_id.clone(),
            format!(
                "{}{separator}credential_offer={}",
                wallet.deep_link_scheme,
                utf8_percent_encode(&offer, PYTHON_QUOTE_SET)
            ),
        );
        if let Some(label) = wallet
            .display_name
            .as_ref()
            .filter(|value| !value.is_empty())
        {
            labels.insert(wallet.wallet_id.clone(), label.clone());
        }
    }
    (uris, labels)
}

fn validate_template(
    template: &CredentialTemplateReference,
    expected_id: &str,
    organization_id: &str,
) -> Result<(), FlowInstanceSideEffectError> {
    if template.id != expected_id
        || template.organization_id != organization_id
        || !template.status.eq_ignore_ascii_case("active")
        || !template.issuer_did.starts_with("did:")
        || template.credential_type.trim().is_empty()
    {
        return Err(FlowInstanceSideEffectError::InvalidResponse(
            "credential template binding",
        ));
    }
    Ok(())
}

fn physical_operation_for_step(value: &str) -> Option<PhysicalDocumentOperation> {
    match value {
        "generate_data_groups" => Some(PhysicalDocumentOperation::GenerateDataGroups),
        "sign_sod" => Some(PhysicalDocumentOperation::SignSod),
        "submit_to_personalization" => Some(PhysicalDocumentOperation::SubmitToPersonalization),
        "track_production" => Some(PhysicalDocumentOperation::TrackProduction),
        "quality_verify" => Some(PhysicalDocumentOperation::QualityVerify),
        "activate_credential" => Some(PhysicalDocumentOperation::ActivateCredential),
        _ => None,
    }
}

fn validate_physical_result(
    operation: PhysicalDocumentOperation,
    result: &PhysicalDocumentResult,
    expected_flow_execution_id: Option<&str>,
) -> Result<String, FlowInstanceSideEffectError> {
    if result.operation != operation || result.status.trim().is_empty() {
        return Err(FlowInstanceSideEffectError::InvalidResponse(
            "physical document operation binding",
        ));
    }
    let application_id = result
        .data
        .get("application_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or(FlowInstanceSideEffectError::InvalidResponse(
            "physical document application_id",
        ))?;
    if expected_flow_execution_id.is_some_and(|expected| {
        result.data.get("flow_execution_id").and_then(Value::as_str) != Some(expected)
    }) {
        return Err(FlowInstanceSideEffectError::InvalidResponse(
            "physical document flow_execution_id",
        ));
    }
    Ok(application_id.into())
}

fn context_mut(
    instance: &mut FlowInstanceRecord,
) -> Result<&mut Map<String, Value>, FlowInstanceSideEffectError> {
    instance
        .context
        .as_object_mut()
        .ok_or(FlowInstanceSideEffectError::InvalidContext(
            "instance context must be an object",
        ))
}

fn nonempty_context_string(context: &Map<String, Value>, name: &str) -> Option<String> {
    context
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
}

fn empty_json_value(value: &Value) -> bool {
    value.is_null()
        || value.as_str().is_some_and(str::is_empty)
        || value.as_array().is_some_and(Vec::is_empty)
        || value.as_object().is_some_and(Map::is_empty)
}
