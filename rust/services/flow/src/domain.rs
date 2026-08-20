use std::collections::{BTreeMap, BTreeSet};

use marty_verification::flow::{
    evaluate_transition, validate_graph, FlowGraphRequest, FlowGraphStep, FlowGraphTransition,
    FlowInstanceStatus, FlowTransitionRequest, TransitionOutcome,
};
use mmf_workflow::WorkflowRetryPolicy;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

pub const CALLBACK_EVENT_TYPE: &str = "flow.verification_completed";
pub const CALLBACK_RETENTION_SECONDS: u64 = 900;
pub const CALLBACK_MAX_ATTEMPTS: u32 = 10;
pub const CALLBACK_LEASE_SECONDS: u64 = 30;
pub const CALLBACK_POLL_MILLISECONDS: u64 = 1_000;
pub const CALLBACK_RETRY_BASE_SECONDS: u64 = 1;
pub const CALLBACK_RETRY_CAP_SECONDS: u64 = 60;

const PRIVATE_CONTEXT_PREFIX: &str = "_marty_";
const PRIVATE_CONTEXT_KEYS: &[&str] = &[
    "issuer_profile_id",
    "issuer_key_id",
    "issuer_algorithm",
    "key_access_mode",
    "verification_method_id",
    "signing_service_id",
    "signing_key_reference",
    "key_reference",
    "kms_provider",
    "provider",
    "key_name",
    "key_version",
    "transit_mount",
    "pre_auth_code",
    "pre_authorized_code",
    "pre-authorized-code",
    "access_token",
    "refresh_token",
    "client_secret",
    "private_key",
    "private_key_jwk",
    "session_token",
    "api_key",
];

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowType {
    Oid4vciPreAuthorized,
    Oid4vciAuthorizationCode,
    MdlIssuance,
    Oid4vpPresentation,
    MdlPresentation,
    Siopv2,
    ApplicationApprovalIssuance,
    CredentialRenewal,
    CredentialRevocation,
    PhysicalDocumentIssuance,
    Combined,
    Custom,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FlowCategory {
    Issuance,
    Verification,
    Renewal,
    Revocation,
    Combined,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DefinitionStatus {
    Draft,
    Active,
    Paused,
    Archived,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct FlowStep {
    pub id: String,
    pub protocol_step: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct FlowTransition {
    pub from_step_id: String,
    pub to_step_id: String,
    pub outcome: TransitionOutcome,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct FlowDefinition {
    pub id: String,
    pub organization_id: String,
    pub name: String,
    pub flow_type: FlowType,
    pub status: DefinitionStatus,
    pub steps: Vec<FlowStep>,
    pub transitions: Vec<FlowTransition>,
    pub start_step_id: String,
    #[serde(default)]
    pub references: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension: Option<Value>,
    pub version: u32,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct StateHistoryEntry {
    pub prior_state: FlowInstanceStatus,
    pub new_state: FlowInstanceStatus,
    pub timestamp_ms: u64,
    pub actor: Option<String>,
    pub event: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct FlowInstance {
    pub id: String,
    pub flow_definition_id: String,
    pub organization_id: String,
    pub status: FlowInstanceStatus,
    pub current_step_id: Option<String>,
    pub application_flow_key_hash: Option<String>,
    #[serde(default)]
    pub context: Value,
    #[serde(default)]
    pub state_history: Vec<StateHistoryEntry>,
    pub expires_at_ms: Option<u64>,
    pub completed_at_ms: Option<u64>,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum FlowDomainError {
    #[error("FLOW.INVALID_DEFINITION: {0}")]
    InvalidDefinition(String),
    #[error("FLOW.PRIVATE_CONTEXT: {0}")]
    PrivateContext(String),
    #[error("FLOW.INVALID_TRANSITION: {0}")]
    InvalidTransition(String),
}

impl FlowType {
    #[must_use]
    pub const fn category(self) -> Option<FlowCategory> {
        match self {
            Self::Oid4vciPreAuthorized
            | Self::Oid4vciAuthorizationCode
            | Self::MdlIssuance
            | Self::ApplicationApprovalIssuance
            | Self::PhysicalDocumentIssuance => Some(FlowCategory::Issuance),
            Self::Oid4vpPresentation | Self::MdlPresentation | Self::Siopv2 => {
                Some(FlowCategory::Verification)
            }
            Self::CredentialRenewal => Some(FlowCategory::Renewal),
            Self::CredentialRevocation => Some(FlowCategory::Revocation),
            Self::Combined => Some(FlowCategory::Combined),
            Self::Custom => None,
        }
    }

    #[must_use]
    pub const fn required_references(self) -> &'static [&'static str] {
        match self {
            Self::Oid4vciPreAuthorized
            | Self::Oid4vciAuthorizationCode
            | Self::MdlIssuance
            | Self::CredentialRenewal
            | Self::CredentialRevocation => &["credential_template_id"],
            Self::Oid4vpPresentation | Self::MdlPresentation | Self::Siopv2 => {
                &["presentation_policy_id"]
            }
            Self::ApplicationApprovalIssuance => &["application_template_id"],
            Self::PhysicalDocumentIssuance => &[
                "credential_template_id",
                "application_template_id",
                "delivery_destination_profile_id",
            ],
            Self::Combined => &["credential_template_id", "presentation_policy_id"],
            Self::Custom => &["extension"],
        }
    }

    #[must_use]
    pub const fn sequence(self) -> &'static [&'static str] {
        match self {
            Self::Oid4vciPreAuthorized => &[
                "create_offer",
                "token_exchange",
                "credential_request",
                "issue_credential",
            ],
            Self::Oid4vciAuthorizationCode => &[
                "create_offer",
                "authorization",
                "token_exchange",
                "credential_request",
                "issue_credential",
            ],
            Self::MdlIssuance => &[
                "application_submit",
                "validate_evidence",
                "approval_decision",
                "issue_mdl",
                "deliver_credential",
            ],
            Self::Oid4vpPresentation => &[
                "create_request",
                "wallet_selection",
                "presentation_submission",
                "verify_presentation",
            ],
            Self::MdlPresentation => &[
                "device_engagement",
                "session_establishment",
                "request_items",
                "response_items",
                "session_termination",
            ],
            Self::Siopv2 => &[
                "create_request",
                "authentication_submission",
                "verify_id_token",
            ],
            Self::ApplicationApprovalIssuance => &[
                "accept_application",
                "validate_evidence",
                "approval_decision",
                "issue_credential",
                "deliver_credential",
            ],
            Self::CredentialRenewal => &[
                "validate_existing",
                "create_offer",
                "token_exchange",
                "credential_request",
                "issue_renewed_credential",
                "revoke_old_credential",
            ],
            Self::CredentialRevocation => &[
                "validate_revocation_request",
                "update_status_list",
                "notify_holder",
            ],
            Self::PhysicalDocumentIssuance => &[
                "accept_application",
                "validate_evidence",
                "approval_decision",
                "generate_data_groups",
                "sign_sod",
                "submit_to_personalization",
                "track_production",
                "quality_verify",
                "activate_credential",
            ],
            Self::Combined => &[
                "accept_application",
                "approval_decision",
                "issue_credential",
                "create_request",
                "presentation_submission",
                "verify_presentation",
            ],
            Self::Custom => &[],
        }
    }

    pub fn all() -> impl Iterator<Item = Self> {
        [
            Self::Oid4vciPreAuthorized,
            Self::Oid4vciAuthorizationCode,
            Self::MdlIssuance,
            Self::Oid4vpPresentation,
            Self::MdlPresentation,
            Self::Siopv2,
            Self::ApplicationApprovalIssuance,
            Self::CredentialRenewal,
            Self::CredentialRevocation,
            Self::PhysicalDocumentIssuance,
            Self::Combined,
            Self::Custom,
        ]
        .into_iter()
    }
}

impl FlowDefinition {
    pub fn built_in(
        organization_id: impl Into<String>,
        name: impl Into<String>,
        flow_type: FlowType,
        references: BTreeMap<String, String>,
    ) -> Result<Self, FlowDomainError> {
        if flow_type == FlowType::Custom {
            return Err(FlowDomainError::InvalidDefinition(
                "custom flows require an extension graph".into(),
            ));
        }
        let organization_id = organization_id.into();
        let name = name.into();
        validate_identity(&organization_id, &name)?;
        validate_references(flow_type, &references, None)?;
        let steps = flow_type
            .sequence()
            .iter()
            .map(|protocol_step| FlowStep {
                id: Uuid::new_v4().to_string(),
                protocol_step: (*protocol_step).to_owned(),
            })
            .collect::<Vec<_>>();
        let transitions = steps
            .windows(2)
            .map(|pair| FlowTransition {
                from_step_id: pair[0].id.clone(),
                to_step_id: pair[1].id.clone(),
                outcome: TransitionOutcome::Success,
            })
            .collect::<Vec<_>>();
        let start_step_id = steps
            .first()
            .map(|step| step.id.clone())
            .ok_or_else(|| FlowDomainError::InvalidDefinition("flow has no steps".into()))?;
        let definition = Self {
            id: Uuid::new_v4().to_string(),
            organization_id,
            name,
            flow_type,
            status: DefinitionStatus::Draft,
            steps,
            transitions,
            start_step_id,
            references,
            extension: None,
            version: 1,
        };
        definition.validate_graph()?;
        Ok(definition)
    }

    pub fn validate_graph(&self) -> Result<(), FlowDomainError> {
        validate_graph(&self.graph_request())
            .map(|_| ())
            .map_err(|error| FlowDomainError::InvalidDefinition(error.to_string()))
    }

    #[must_use]
    pub fn graph_request(&self) -> FlowGraphRequest {
        FlowGraphRequest {
            entry_step_id: self.start_step_id.clone(),
            steps: self
                .steps
                .iter()
                .map(|step| FlowGraphStep {
                    step_id: step.id.clone(),
                })
                .collect(),
            transitions: self
                .transitions
                .iter()
                .map(|transition| FlowGraphTransition {
                    from_step_id: transition.from_step_id.clone(),
                    to_step_id: transition.to_step_id.clone(),
                    outcome: transition.outcome,
                })
                .collect(),
        }
    }
}

impl FlowInstance {
    pub fn transition_to(
        &mut self,
        target: FlowInstanceStatus,
        actor: Option<String>,
        event: Option<String>,
        now_ms: u64,
    ) -> Result<(), FlowDomainError> {
        let decision = evaluate_transition(FlowTransitionRequest {
            current: self.status,
            target,
            actor,
            event,
        })
        .map_err(|error| FlowDomainError::InvalidTransition(error.to_string()))?;
        if decision.no_op {
            return Ok(());
        }
        self.status = decision.new_state;
        self.state_history.push(StateHistoryEntry {
            prior_state: decision.prior_state,
            new_state: decision.new_state,
            timestamp_ms: now_ms,
            actor: decision.actor,
            event: decision.event,
        });
        if decision.terminal {
            self.completed_at_ms = Some(now_ms);
        }
        Ok(())
    }
}

#[must_use]
pub fn public_status(status: FlowInstanceStatus) -> &'static str {
    match status {
        FlowInstanceStatus::Created | FlowInstanceStatus::Pending => "PENDING",
        FlowInstanceStatus::InProgress => "IN_PROGRESS",
        FlowInstanceStatus::AwaitingWallet => "AWAITING_WALLET",
        FlowInstanceStatus::AwaitingApproval => "AWAITING_APPROVAL",
        FlowInstanceStatus::AwaitingEvidence => "AWAITING_EVIDENCE",
        FlowInstanceStatus::Completed => "COMPLETED",
        FlowInstanceStatus::Failed => "FAILED",
        FlowInstanceStatus::Cancelled => "CANCELLED",
        FlowInstanceStatus::Expired => "EXPIRED",
    }
}

pub fn reject_private_context(value: &Value) -> Result<(), FlowDomainError> {
    private_context_path(value, "")
        .map_or(Ok(()), |path| Err(FlowDomainError::PrivateContext(path)))
}

#[must_use]
pub fn public_context(value: &Value) -> Value {
    match value {
        Value::Object(object) => Value::Object(
            object
                .iter()
                .filter(|(key, _)| !is_private_key(key))
                .map(|(key, value)| (key.clone(), public_context(value)))
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.iter().map(public_context).collect()),
        _ => value.clone(),
    }
}

#[must_use]
pub fn callback_retry_delay_seconds(attempt_count: u32) -> u64 {
    WorkflowRetryPolicy {
        max_attempts: CALLBACK_MAX_ATTEMPTS,
        initial_delay_ms: CALLBACK_RETRY_BASE_SECONDS * 1_000,
        maximum_delay_ms: CALLBACK_RETRY_CAP_SECONDS * 1_000,
        exponential_base: 2,
    }
    .delay_ms(attempt_count)
        / 1_000
}

fn validate_identity(organization_id: &str, name: &str) -> Result<(), FlowDomainError> {
    if organization_id.trim().is_empty() || name.trim().is_empty() {
        return Err(FlowDomainError::InvalidDefinition(
            "organization_id and name are required".into(),
        ));
    }
    Ok(())
}

fn validate_references(
    flow_type: FlowType,
    references: &BTreeMap<String, String>,
    extension: Option<&Value>,
) -> Result<(), FlowDomainError> {
    let missing = flow_type
        .required_references()
        .iter()
        .copied()
        .filter(|name| {
            if *name == "extension" {
                return extension.is_none();
            }
            references
                .get(*name)
                .is_none_or(|value| value.trim().is_empty())
        })
        .collect::<BTreeSet<_>>();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(FlowDomainError::InvalidDefinition(format!(
            "missing required references: {}",
            missing.into_iter().collect::<Vec<_>>().join(", ")
        )))
    }
}

fn private_context_path(value: &Value, prefix: &str) -> Option<String> {
    match value {
        Value::Object(object) => object.iter().find_map(|(key, value)| {
            let path = if prefix.is_empty() {
                key.clone()
            } else {
                format!("{prefix}.{key}")
            };
            is_private_key(key)
                .then_some(path.clone())
                .or_else(|| private_context_path(value, &path))
        }),
        Value::Array(values) => values.iter().enumerate().find_map(|(index, value)| {
            let path = if prefix.is_empty() {
                format!("[{index}]")
            } else {
                format!("{prefix}[{index}]")
            };
            private_context_path(value, &path)
        }),
        _ => None,
    }
}

fn is_private_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase();
    normalized.starts_with(PRIVATE_CONTEXT_PREFIX)
        || PRIVATE_CONTEXT_KEYS.contains(&normalized.as_str())
}
