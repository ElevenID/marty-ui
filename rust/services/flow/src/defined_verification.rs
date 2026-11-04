//! Bind the canonical OID4VP lifecycle to an approved, versioned definition.
//!
//! Only the built-in verification graph is supported here. In particular, this
//! adapter must never skip a custom approval, hook, or issuance step.

use chrono::{DateTime, Utc};
use marty_oid4vci::presentation_request::PresentationRequestArtifacts;
use marty_verification::flow::{FlowInstanceStatus, TransitionOutcome};
use mmf_push::WebhookDestinationRegistry;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    prepare_profiled_verification_start, ApprovalStrategy, DefinitionStatus, FlowDefinitionRecord,
    FlowInstanceRecord, FlowProviderRegistry, FlowType, FlowVerificationStartError, Oid4vpProfile,
    PreparedVerificationStart, RequestTransport, RequestUriMethod, StartVerificationFlowRequest,
    VerificationResponseType, VerificationStartContext, VerificationStartOptions,
};

const SNAPSHOT: &str = "_marty_verification_definition";
pub(crate) const REQUEST_DIGEST: &str = "_marty_verification_request_digest";
const STEPS: [&str; 4] = [
    "create_request",
    "wallet_selection",
    "presentation_submission",
    "verify_presentation",
];

/// Server-selected binding. Public request fields cannot select these values.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationDefinitionBinding {
    pub organization_id: String,
    pub definition_id: String,
    pub version: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DefinitionSnapshot {
    binding: VerificationDefinitionBinding,
    step_ids: Vec<String>,
}

#[derive(Debug, Error)]
pub enum DefinedVerificationError {
    #[error("FLOW.VERIFICATION_DEFINITION_UNAVAILABLE")]
    DefinitionUnavailable,
    #[error("FLOW.VERIFICATION_DEFINITION_UNSUPPORTED")]
    UnsupportedDefinition,
    #[error("FLOW.VERIFICATION_DEFINITION_SNAPSHOT_INVALID")]
    InvalidSnapshot,
    #[error(transparent)]
    Start(#[from] FlowVerificationStartError),
}

pub(crate) fn verification_request_digest(
    artifacts: &PresentationRequestArtifacts,
) -> Result<String, DefinedVerificationError> {
    let mut value =
        serde_json::to_value(artifacts).map_err(|_| DefinedVerificationError::InvalidSnapshot)?;
    // The builder assigns a fresh presentation-definition ID on every read.
    // Query formats, requirements, claims and constraints must remain identical.
    value["presentation_definition"]
        .as_object_mut()
        .ok_or(DefinedVerificationError::InvalidSnapshot)?
        .remove("id");
    let bytes =
        serde_json::to_vec(&value).map_err(|_| DefinedVerificationError::InvalidSnapshot)?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

pub(crate) fn validate_defined_request(
    instance: &FlowInstanceRecord,
    artifacts: &PresentationRequestArtifacts,
) -> Result<(), DefinedVerificationError> {
    if instance.context.get(SNAPSHOT).is_some()
        && instance
            .context
            .get(REQUEST_DIGEST)
            .and_then(serde_json::Value::as_str)
            != Some(verification_request_digest(artifacts)?.as_str())
    {
        return Err(DefinedVerificationError::InvalidSnapshot);
    }
    Ok(())
}

pub(crate) async fn validate_defined_submission(
    providers: &FlowProviderRegistry,
    instance: &FlowInstanceRecord,
) -> Result<(), DefinedVerificationError> {
    if instance.context.get(SNAPSHOT).is_some() {
        let policy = instance
            .context
            .get("presentation_policy_id")
            .and_then(serde_json::Value::as_str)
            .ok_or(DefinedVerificationError::InvalidSnapshot)?;
        let artifacts =
            crate::build_flow_presentation_request(providers, policy, &instance.organization_id)
                .await
                .map_err(FlowVerificationStartError::Presentation)?;
        validate_defined_request(instance, &artifacts)?;
    }
    Ok(())
}

impl VerificationDefinitionBinding {
    /// Validate before resolving signing providers or advertising a wallet URI.
    pub fn validate(
        &self,
        definition: &FlowDefinitionRecord,
    ) -> Result<(), DefinedVerificationError> {
        if self.organization_id.is_empty()
            || self.definition_id.is_empty()
            || self.version == 0
            || definition.organization_id != self.organization_id
            || definition.id != self.definition_id
            || definition.version != self.version
            || definition.status != DefinitionStatus::Active
        {
            return Err(DefinedVerificationError::DefinitionUnavailable);
        }
        let graph = definition
            .kernel()
            .map_err(|_| DefinedVerificationError::UnsupportedDefinition)?;
        if definition.flow_type != FlowType::Oid4vpPresentation
            || definition.approval_strategy != ApprovalStrategy::Auto
            || definition.extension.is_some()
            || !definition.hooks.is_empty()
            || !definition.preconditions.is_empty()
            || definition.credential_template_id.is_some()
            || definition.application_template_id.is_some()
            || definition.delivery_destination_profile_id.is_some()
            || definition
                .presentation_policy_id
                .as_deref()
                .is_none_or(str::is_empty)
            || !(30..=3_600).contains(&definition.default_timeout_seconds)
            || !definition.default_timeout_seconds.is_multiple_of(60)
            || graph.steps.len() != STEPS.len()
            || graph.transitions.len() != STEPS.len() - 1
            || graph.start_step_id != graph.steps[0].id
            || graph
                .steps
                .iter()
                .zip(STEPS)
                .any(|(step, name)| step.protocol_step != name)
            || graph.steps.windows(2).any(|pair| {
                !graph.transitions.iter().any(|transition| {
                    transition.from_step_id == pair[0].id
                        && transition.to_step_id == pair[1].id
                        && transition.outcome == TransitionOutcome::Success
                })
            })
        {
            return Err(DefinedVerificationError::UnsupportedDefinition);
        }
        Ok(())
    }
}

/// Resolve all definition references through the existing validation owner at
/// the admission boundary before calling this function. This function then
/// reuses the canonical policy/template and signing-identity admission at start.
#[allow(clippy::too_many_arguments)]
pub async fn prepare_defined_verification_start(
    providers: &FlowProviderRegistry,
    callbacks: &WebhookDestinationRegistry,
    definition: &FlowDefinitionRecord,
    binding: &VerificationDefinitionBinding,
    issuer_did: &str,
    options: &VerificationStartOptions,
    context: VerificationStartContext<'_>,
) -> Result<PreparedVerificationStart, DefinedVerificationError> {
    binding.validate(definition)?;
    let mut prepared = prepare_profiled_verification_start(
        providers,
        callbacks,
        StartVerificationFlowRequest {
            organization_id: binding.organization_id.clone(),
            presentation_policy_id: definition.presentation_policy_id.clone(),
            issuer_did: issuer_did.to_owned(),
            response_type: VerificationResponseType::VpToken,
            trust_profile_id: definition.trust_profile_id.clone(),
            deployment_profile_id: definition.deployment_profile_id.clone(),
            external_reference: None,
            callback_url: None,
            expiry_minutes: u16::try_from(definition.default_timeout_seconds / 60)
                .map_err(|_| DefinedVerificationError::UnsupportedDefinition)?,
            oid4vp_profile: Oid4vpProfile::Standard,
            request_transport: RequestTransport::RequestUri,
            request_uri_method: RequestUriMethod::Get,
        },
        options,
        context,
    )
    .await?;
    prepared
        .instance
        .flow_definition_id
        .clone_from(&definition.id);
    prepared
        .response
        .flow_definition_id
        .clone_from(&definition.id);
    let graph = definition
        .kernel()
        .map_err(|_| DefinedVerificationError::UnsupportedDefinition)?;
    let snapshot = DefinitionSnapshot {
        binding: binding.clone(),
        step_ids: graph.steps.iter().map(|step| step.id.clone()).collect(),
    };
    prepared.instance.context[SNAPSHOT] =
        serde_json::to_value(&snapshot).map_err(|_| DefinedVerificationError::InvalidSnapshot)?;
    prepared.instance.context["flow_definition_reference"] = json!(definition.id);
    prepared.instance.current_step_id = Some(snapshot.step_ids[1].clone());
    prepared.instance.step_history = vec![
        json!({"step_id": snapshot.step_ids[0], "entered_at": context.now, "completed_at": context.now, "status": "completed"}),
        json!({"step_id": snapshot.step_ids[1], "entered_at": context.now, "status": "entered"}),
    ];
    Ok(prepared)
}

/// Called only after a signed request has been built, or after canonical
/// evaluation. Standalone verification transactions keep their existing behavior.
pub fn record_defined_verification_progress(
    instance: &mut FlowInstanceRecord,
    terminal: bool,
    now: DateTime<Utc>,
) -> Result<(), DefinedVerificationError> {
    let Some(raw) = instance.context.get(SNAPSHOT) else {
        return Ok(());
    };
    let snapshot: DefinitionSnapshot = serde_json::from_value(raw.clone())
        .map_err(|_| DefinedVerificationError::InvalidSnapshot)?;
    if snapshot.binding.organization_id != instance.organization_id
        || snapshot.binding.definition_id != instance.flow_definition_id
        || snapshot.binding.version == 0
        || snapshot.step_ids.len() != STEPS.len()
        || (terminal
            && !matches!(
                instance.status,
                FlowInstanceStatus::Completed | FlowInstanceStatus::Failed
            ))
    {
        return Err(DefinedVerificationError::InvalidSnapshot);
    }
    let target = if terminal { 3 } else { 2 };
    for index in 1..=target {
        let id = &snapshot.step_ids[index];
        let position = instance
            .step_history
            .iter()
            .position(|entry| entry["step_id"] == *id);
        let position = position.unwrap_or_else(|| {
            instance
                .step_history
                .push(json!({"step_id": id, "entered_at": now, "status": "entered"}));
            instance.step_history.len() - 1
        });
        if index < target || terminal {
            let entry = &mut instance.step_history[position];
            if entry.get("completed_at").is_none() {
                entry["completed_at"] = json!(now);
                entry["status"] = json!(if index == 3
                    && instance.status == FlowInstanceStatus::Failed
                {
                    "failed"
                } else {
                    "completed"
                });
            }
        }
    }
    instance.current_step_id = if terminal {
        None
    } else {
        Some(snapshot.step_ids[target].clone())
    };
    Ok(())
}
