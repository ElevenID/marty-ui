//! Deprecated signed Canvas webhook ingestion retained during portable cutover.
//!
//! The three public routes deliberately share one verification, replay and
//! evidence-transition kernel. Provider-shaped AGS and NRPS bodies are only
//! adapters into the frozen completion-event contract.

use std::{collections::BTreeMap, fmt, path::PathBuf, sync::Arc};

use async_trait::async_trait;
use chrono::{DateTime, SecondsFormat, Timelike, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    canvas_award_candidate::python_canonical_json,
    canvas_award_candidate_approval::{
        plan_canvas_approval_transaction, plan_legacy_canvas_approval_transaction,
        resolve_and_attach_canvas_issuer, resolve_and_attach_required_issuer,
        reuse_canvas_approval_transaction, CanvasAwardApprovalSeedGenerator,
    },
    canvas_award_candidate_service::CanvasAwardCandidateApprovalError,
    canvas_issuance_guard::evaluate_canvas_evidence_policy,
    canvas_lti_launch::CanvasLtiClock,
    credential::{CredentialTransaction, IssuerContextResolver},
};

pub const SIGNATURE_HEADER: &str = "x-canvas-signature-256";
pub const TIMESTAMP_HEADER: &str = "x-canvas-timestamp";
pub const SUNSET: &str = "Wed, 14 Oct 2026 00:00:00 GMT";
pub const EVIDENCE_LINK: &str = "</docs/canvas-portable-integration>; rel=\"deprecation\"";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanvasLegacyEventKind {
    Evidence,
    AgsScore,
    NrpsMembership,
}

impl CanvasLegacyEventKind {
    #[must_use]
    pub const fn disabled_detail(self) -> &'static str {
        match self {
            Self::Evidence => {
                "Legacy Canvas event ingestion is disabled; use portable synchronization"
            }
            Self::AgsScore => "Legacy Canvas AGS event ingestion is disabled",
            Self::NrpsMembership => "Legacy Canvas NRPS event ingestion is disabled",
        }
    }

    pub(crate) const fn audit_source(self) -> &'static str {
        match self {
            Self::Evidence => "canvas_evidence_event",
            Self::AgsScore => "canvas_ags_score_event",
            Self::NrpsMembership => "canvas_nrps_membership_event",
        }
    }

    pub(crate) const fn verification_method(self) -> &'static str {
        match self {
            Self::Evidence => "SIGNED_WEBHOOK",
            Self::AgsScore => "SIGNED_AGS_SCORE",
            Self::NrpsMembership => "SIGNED_NRPS_MEMBERSHIP",
        }
    }

    const fn feature_flag(self) -> &'static str {
        match self {
            Self::Evidence => "enable_canvas_evidence",
            Self::AgsScore => "enable_canvas_ags",
            Self::NrpsMembership => "enable_canvas_nrps",
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct CanvasLegacyIngestConfig {
    pub enabled: bool,
    pub shared_secret: Option<String>,
    pub shared_secret_file: Option<String>,
    pub signature_tolerance_seconds: i64,
}

impl fmt::Debug for CanvasLegacyIngestConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanvasLegacyIngestConfig")
            .field("enabled", &self.enabled)
            .field("shared_secret_configured", &self.shared_secret.is_some())
            .field(
                "shared_secret_file_configured",
                &self.shared_secret_file.is_some(),
            )
            .field(
                "signature_tolerance_seconds",
                &self.signature_tolerance_seconds,
            )
            .finish()
    }
}

impl CanvasLegacyIngestConfig {
    fn resolve_shared_secret(&self) -> Option<String> {
        if let Some(secret) = self
            .shared_secret
            .as_ref()
            .filter(|value| !value.is_empty())
        {
            return Some(secret.clone());
        }
        let configured_path = self
            .shared_secret_file
            .as_ref()
            .filter(|path| !path.is_empty())?;
        let trusted_root = canvas_secret_root().canonicalize().ok()?;
        let configured_path = PathBuf::from(configured_path);
        let candidate = if configured_path.is_absolute() {
            configured_path
        } else {
            trusted_root.join(configured_path)
        };
        let candidate = candidate.canonicalize().ok()?;
        if !candidate.starts_with(&trusted_root) {
            return None;
        }
        let metadata = std::fs::metadata(&candidate).ok()?;
        if !metadata.is_file() || metadata.len() > 64 * 1024 {
            return None;
        }
        std::fs::read_to_string(candidate)
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
    }
}

#[cfg(not(test))]
fn canvas_secret_root() -> PathBuf {
    PathBuf::from("/run/secrets")
}

#[cfg(test)]
fn canvas_secret_root() -> PathBuf {
    std::env::temp_dir()
}

#[derive(Clone, Debug, PartialEq)]
pub struct CanvasLegacyApplicationSnapshot {
    pub application: Map<String, Value>,
    pub application_template: Option<Map<String, Value>>,
    pub platform: Map<String, Value>,
    pub binding: Map<String, Value>,
    pub evidence_facts: Vec<Value>,
    pub policy_set: Option<Value>,
    pub existing_transaction: Option<CredentialTransaction>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum CanvasLegacyIngestSnapshot {
    Replay(CanvasLegacyStoredReceipt),
    New(Box<CanvasLegacyApplicationSnapshot>),
}

#[derive(Clone, Debug, PartialEq)]
pub struct CanvasLegacyStoredReceipt {
    pub payload_hash: String,
    pub status: String,
    pub response: Value,
}

#[derive(Clone, Debug)]
pub struct CanvasLegacyCommit {
    pub event: CanvasEvidenceEvent,
    pub application: Map<String, Value>,
    pub requirements: Vec<Value>,
    pub evaluate_policy: bool,
    pub payload_hash: String,
    pub receipt_id: String,
    pub audit_source: &'static str,
    pub verification_method: &'static str,
    pub fact: Value,
    pub safe_fact: Value,
    pub mip_primitives: Value,
    pub evidence: Value,
    pub evidence_submission: Value,
    pub evaluated_policy_decision: Option<Value>,
    pub policy_decision: Option<Value>,
    pub transaction: Option<CredentialTransaction>,
    pub approval_failure: Option<String>,
    pub now: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum CanvasLegacyCommitOutcome {
    Created(Box<CanvasEvidenceEventResponse>),
    Replay(CanvasLegacyStoredReceipt),
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum CanvasLegacyRepositoryError {
    #[error("Canvas legacy ingest repository is unavailable")]
    Unavailable,
    #[error("Canvas legacy ingest snapshot changed")]
    SnapshotChanged,
}

#[async_trait]
pub trait CanvasLegacyIngestRepository: Send + Sync {
    async fn load(
        &self,
        event: &CanvasEvidenceEvent,
        payload_hash: &str,
    ) -> Result<Option<CanvasLegacyIngestSnapshot>, CanvasLegacyRepositoryError>;

    async fn replay(
        &self,
        event: &CanvasEvidenceEvent,
        payload_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<CanvasLegacyStoredReceipt, CanvasLegacyIngestError>;

    async fn commit(
        &self,
        snapshot: &CanvasLegacyApplicationSnapshot,
        commit: &CanvasLegacyCommit,
    ) -> Result<CanvasLegacyCommitOutcome, CanvasLegacyIngestError>;
}

pub trait CanvasLegacyIdGenerator: Send + Sync {
    fn receipt_id(&self) -> String;
    fn fact_id(&self) -> String;
}

#[derive(Clone, Debug, Default)]
pub struct UuidCanvasLegacyIdGenerator;

impl CanvasLegacyIdGenerator for UuidCanvasLegacyIdGenerator {
    fn receipt_id(&self) -> String {
        uuid::Uuid::new_v4().to_string()
    }

    fn fact_id(&self) -> String {
        uuid::Uuid::new_v4().to_string()
    }
}

#[derive(Clone)]
pub struct CanvasLegacyIngestService {
    repository: Arc<dyn CanvasLegacyIngestRepository>,
    issuer_resolver: Arc<dyn IssuerContextResolver>,
    approval_seeds: Arc<dyn CanvasAwardApprovalSeedGenerator>,
    ids: Arc<dyn CanvasLegacyIdGenerator>,
    clock: Arc<dyn CanvasLtiClock>,
    config: CanvasLegacyIngestConfig,
}

impl fmt::Debug for CanvasLegacyIngestService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanvasLegacyIngestService")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl CanvasLegacyIngestService {
    #[must_use]
    pub fn new(
        repository: Arc<dyn CanvasLegacyIngestRepository>,
        issuer_resolver: Arc<dyn IssuerContextResolver>,
        approval_seeds: Arc<dyn CanvasAwardApprovalSeedGenerator>,
        ids: Arc<dyn CanvasLegacyIdGenerator>,
        clock: Arc<dyn CanvasLtiClock>,
        config: CanvasLegacyIngestConfig,
    ) -> Self {
        Self {
            repository,
            issuer_resolver,
            approval_seeds,
            ids,
            clock,
            config,
        }
    }

    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.config.enabled
    }

    pub async fn process(
        &self,
        kind: CanvasLegacyEventKind,
        raw_body: &[u8],
        headers: &BTreeMap<String, String>,
    ) -> Result<CanvasEvidenceEventResponse, CanvasLegacyIngestError> {
        if !self.config.enabled {
            return Err(CanvasLegacyIngestError::Gone(kind.disabled_detail()));
        }
        let now = self.clock.now();
        let shared_secret = self.config.resolve_shared_secret();
        verify_signature(
            raw_body,
            headers,
            shared_secret.as_deref(),
            now.timestamp(),
            self.config.signature_tolerance_seconds,
        )?;
        let payload: Value = serde_json::from_slice(raw_body)
            .map_err(|_| CanvasLegacyIngestError::MalformedPayload)?;
        if kind != CanvasLegacyEventKind::Evidence && !payload.is_object() {
            return Err(CanvasLegacyIngestError::ObjectRequired);
        }
        let event = parse_and_normalize(kind, &payload, now)?;
        let payload_hash = hex::encode(Sha256::digest(python_canonical_json(&payload).as_bytes()));

        for _attempt in 0..2 {
            let loaded = self
                .repository
                .load(&event, &payload_hash)
                .await
                .map_err(map_repository_error)?
                .ok_or(CanvasLegacyIngestError::ApplicationNotFound)?;
            let snapshot = match loaded {
                CanvasLegacyIngestSnapshot::Replay(receipt) => {
                    validate_replay(&receipt, &payload_hash)?;
                    let receipt = self.repository.replay(&event, &payload_hash, now).await?;
                    return response_from_stored(receipt.response, &event.canvas_event_id, true);
                }
                CanvasLegacyIngestSnapshot::New(snapshot) => snapshot,
            };
            let mut event = event.clone();
            event.organization_id = Some(text(snapshot.binding.get("organization_id")));
            if event
                .credential_template_id
                .as_deref()
                .is_none_or(str::is_empty)
            {
                event.credential_template_id =
                    Some(text(snapshot.binding.get("credential_template_id")));
            }
            validate_runtime(kind, &event, &snapshot)?;
            let requirements = effective_requirements(&snapshot);
            matching_requirement(&event, &requirements)
                .ok_or(CanvasLegacyIngestError::EvidenceNotRequired)?;
            event.evidence_type = match event.evidence_type.trim() {
                "" => "canvas.course_completion".to_owned(),
                normalized => normalized.to_owned(),
            };
            let mip_primitives = mip_receipt(&event, &payload_hash);
            let fact_id = self.ids.fact_id();
            let receipt_id = self.ids.receipt_id();
            let fact = evidence_fact(
                &event,
                &mip_primitives,
                &fact_id,
                &receipt_id,
                &payload_hash,
                kind.verification_method(),
                now,
            );
            let safe_fact = safe_fact(&fact, &event);
            let mut application = snapshot.application.clone();
            apply_application_context(
                &mut application,
                &event,
                &snapshot.binding,
                kind,
                &fact_id,
                None,
            );
            let evaluate_policy = snapshot
                .binding
                .get("auto_approve_on_evidence")
                .and_then(Value::as_bool)
                == Some(true);
            let mut policy_decision = if evaluate_policy {
                let facts = projected_evidence_heads(&snapshot.evidence_facts, &fact);
                Some(
                    evaluate_canvas_evidence_policy(
                        &application,
                        snapshot.application_template.as_ref(),
                        Some(&snapshot.binding),
                        &requirements,
                        &facts,
                        snapshot.policy_set.as_ref(),
                    )
                    .map_err(|_| CanvasLegacyIngestError::RepositoryUnavailable)?,
                )
            } else {
                None
            };
            let evaluated_policy_decision = policy_decision.clone();
            let (transaction, approval_failure) = if policy_decision
                .as_ref()
                .and_then(|decision| decision.get("allowed"))
                .and_then(Value::as_bool)
                == Some(true)
            {
                let strict_snapshot = snapshot
                    .binding
                    .get("credential_template_snapshot")
                    .is_some_and(|value| !value.is_null());
                let seed = self.approval_seeds.generate();
                let planned = if strict_snapshot {
                    plan_canvas_approval_transaction(&application, &snapshot.binding, &seed, now)
                } else {
                    let credential_template_id = snapshot
                        .application_template
                        .as_ref()
                        .map(|template| text(template.get("credential_template_id")))
                        .unwrap_or_default();
                    plan_legacy_canvas_approval_transaction(
                        &application,
                        &credential_template_id,
                        &seed,
                        now,
                    )
                };
                let planned = planned.map(|planned| {
                    snapshot
                        .existing_transaction
                        .as_ref()
                        .map_or(planned.clone(), |existing| {
                            reuse_canvas_approval_transaction(existing, &planned, strict_snapshot)
                        })
                });
                match planned {
                    Some(mut transaction) => match if strict_snapshot {
                        resolve_and_attach_canvas_issuer(
                            self.issuer_resolver.as_ref(),
                            &snapshot.binding,
                            &mut transaction,
                        )
                        .await
                    } else {
                        resolve_and_attach_required_issuer(
                            self.issuer_resolver.as_ref(),
                            &mut transaction,
                        )
                        .await
                    } {
                        Ok(()) => (Some(transaction), None),
                        Err(error) => return Err(map_issuer_error(error)),
                    },
                    None => {
                        let message = canvas_approval_plan_failure(
                            &application,
                            &snapshot.binding,
                            snapshot.application_template.as_ref(),
                            strict_snapshot,
                        );
                        deny_policy_after_approval_failure(&mut policy_decision, &message);
                        (None, Some(message))
                    }
                }
            } else {
                (None, None)
            };
            apply_application_context(
                &mut application,
                &event,
                &snapshot.binding,
                kind,
                &fact_id,
                policy_decision.as_ref(),
            );
            let evidence = mip_primitives
                .get("evidence_data")
                .cloned()
                .unwrap_or_else(|| json!({}));
            let evidence_submission = evidence_submission(
                &event,
                &mip_primitives,
                &fact_id,
                &requirements,
                kind,
                evaluate_policy,
                now,
            );
            let commit = CanvasLegacyCommit {
                event: event.clone(),
                application,
                requirements,
                evaluate_policy,
                payload_hash: payload_hash.clone(),
                receipt_id,
                audit_source: kind.audit_source(),
                verification_method: kind.verification_method(),
                fact,
                safe_fact,
                mip_primitives,
                evidence,
                evidence_submission,
                evaluated_policy_decision,
                policy_decision,
                transaction,
                approval_failure,
                now,
            };
            match self.repository.commit(&snapshot, &commit).await {
                Ok(CanvasLegacyCommitOutcome::Created(response)) => return Ok(*response),
                Ok(CanvasLegacyCommitOutcome::Replay(receipt)) => {
                    validate_replay(&receipt, &payload_hash)?;
                    return response_from_stored(receipt.response, &event.canvas_event_id, true);
                }
                Err(CanvasLegacyIngestError::SnapshotChanged) => continue,
                Err(error) => return Err(error),
            }
        }
        Err(CanvasLegacyIngestError::RepositoryUnavailable)
    }
}

fn map_repository_error(error: CanvasLegacyRepositoryError) -> CanvasLegacyIngestError {
    match error {
        CanvasLegacyRepositoryError::Unavailable => CanvasLegacyIngestError::RepositoryUnavailable,
        CanvasLegacyRepositoryError::SnapshotChanged => CanvasLegacyIngestError::SnapshotChanged,
    }
}

fn map_issuer_error(_error: CanvasAwardCandidateApprovalError) -> CanvasLegacyIngestError {
    CanvasLegacyIngestError::AutoApprovalUnavailable
}

fn deny_policy_after_approval_failure(decision: &mut Option<Value>, message: &str) {
    let Some(decision) = decision.as_mut().and_then(Value::as_object_mut) else {
        return;
    };
    decision.insert("allowed".to_owned(), Value::Bool(false));
    let errors = decision
        .entry("errors".to_owned())
        .or_insert_with(|| Value::Array(Vec::new()));
    if let Some(errors) = errors.as_array_mut() {
        errors.push(Value::String(message.to_owned()));
    }
}

fn canvas_approval_plan_failure(
    application: &Map<String, Value>,
    binding: &Map<String, Value>,
    template: Option<&Map<String, Value>>,
    strict_snapshot: bool,
) -> String {
    if !strict_snapshot {
        if has_non_scalar_credential_identifier(application) {
            return "Canvas credential identifiers must be scalar values".to_owned();
        }
        return if template
            .map(|template| text(template.get("credential_template_id")))
            .is_none_or(|value| value.is_empty())
        {
            "Application template missing credential template ID".to_owned()
        } else {
            "Cannot approve application in its current status".to_owned()
        };
    }
    let Some(snapshot) = binding
        .get("credential_template_snapshot")
        .and_then(Value::as_object)
    else {
        return "Credential template snapshot is required".to_owned();
    };
    let credential_type = text(snapshot.get("credential_type"));
    if credential_type.is_empty() {
        return "Credential template snapshot is missing credential_type".to_owned();
    }
    let normalized = credential_type
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect::<String>();
    if !matches!(
        normalized.as_str(),
        "openbadge" | "openbadgev2" | "openbadgev3" | "openbadgecredential"
    ) {
        return "Canvas issuance requires an Open Badge credential template".to_owned();
    }
    for (field, message) in [
        (
            "credential_payload_format",
            "Credential template snapshot is missing credential_payload_format",
        ),
        (
            "revocation_profile_id",
            "Credential template snapshot is missing revocation_profile_id",
        ),
        (
            "issuer_did",
            "Credential template snapshot is missing issuer_did",
        ),
        (
            "issuer_algorithm",
            "Credential template snapshot is missing issuer_algorithm",
        ),
    ] {
        if text(snapshot.get(field)).is_empty() {
            return message.to_owned();
        }
    }
    "Credential template snapshot uses an unsupported issuer_algorithm".to_owned()
}

fn has_non_scalar_credential_identifier(application: &Map<String, Value>) -> bool {
    let form = application.get("form_data").and_then(Value::as_object);
    let integration = application
        .get("integration_context")
        .and_then(Value::as_object);
    [
        form.and_then(|value| value.get("_credential_type")),
        form.and_then(|value| value.get("_vct")),
        integration.and_then(|value| value.get("credential_type")),
        integration.and_then(|value| value.get("credential_vct")),
    ]
    .into_iter()
    .flatten()
    .any(|value| match value {
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
        _ => false,
    })
}

#[derive(Clone, Debug, Error, PartialEq)]
pub enum CanvasLegacyIngestError {
    #[error("{0}")]
    Gone(&'static str),
    #[error("Invalid Canvas event signature")]
    InvalidSignature,
    #[error("Malformed Canvas event payload")]
    MalformedPayload,
    #[error("Canvas event payload must be a JSON object")]
    ObjectRequired,
    #[error("Canvas event payload validation failed")]
    Validation(Vec<Value>),
    #[error("Application not found")]
    ApplicationNotFound,
    #[error(
        "No Canvas program binding found for canvas_account_id, application template, and scope"
    )]
    ProgramBindingNotFound,
    #[error("Canvas feature gate is disabled: {0}")]
    FeatureDisabled(&'static str),
    #[error("Canvas evidence organization does not match application")]
    OrganizationMismatch,
    #[error("Cannot submit evidence for application in {0} status")]
    InvalidApplicationStatus(String),
    #[error("Canvas runtime binding application template does not match application")]
    ApplicationTemplateMismatch,
    #[error("Canvas evidence credential template does not match program binding")]
    BindingCredentialTemplateMismatch,
    #[error("Canvas evidence credential template does not match application")]
    ApplicationCredentialTemplateMismatch,
    #[error("Canvas evidence type is not required for this application")]
    EvidenceNotRequired,
    #[error("canvas_event_id already exists with different payload")]
    ReplayPayloadConflict,
    #[error("canvas_event_id already exists for a different Canvas flow")]
    ReplayFlowConflict,
    #[error("Canvas automatic approval is unavailable")]
    AutoApprovalUnavailable,
    #[error("Canvas legacy ingest snapshot changed")]
    SnapshotChanged,
    #[error("Canvas legacy ingest repository is unavailable")]
    RepositoryUnavailable,
    #[error("Stored Canvas evidence response is malformed")]
    MalformedStoredResponse,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CanvasEvidenceEvent {
    pub canvas_event_id: String,
    pub organization_id: Option<String>,
    pub credential_template_id: Option<String>,
    pub canvas_account_id: String,
    pub canvas_course_id: String,
    pub canvas_course_name: String,
    pub canvas_enrollment_id: String,
    pub canvas_user_id: String,
    pub learner_email: String,
    pub learner_name: Option<String>,
    pub learner_given_name: Option<String>,
    pub learner_family_name: Option<String>,
    pub achievement_name: String,
    pub achievement_description: Option<String>,
    pub completion_at: String,
    pub application_id: String,
    pub evidence_type: String,
    pub canvas_assignment_id: Option<String>,
    pub canvas_module_id: Option<String>,
    pub canvas_quiz_id: Option<String>,
    pub submitted: Option<bool>,
    pub completed: Option<bool>,
    pub passed: Option<bool>,
    pub score: Option<f64>,
    pub score_percent: Option<f64>,
    pub roles: Option<Vec<String>>,
    pub membership_status: Option<String>,
    pub eligible: Option<bool>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CanvasEvidenceEventResponse {
    pub id: String,
    pub application_id: String,
    pub organization_id: String,
    pub canvas_account_id: String,
    pub evidence_type: String,
    pub status: String,
    pub application_status: Option<String>,
    pub source_event_id: String,
    pub replayed: bool,
    pub evidence: Value,
    pub mip_primitives: Value,
    #[serde(default)]
    pub evidence_facts: Vec<Value>,
    pub policy_decision: Option<Value>,
}

fn verify_signature(
    raw_body: &[u8],
    headers: &BTreeMap<String, String>,
    secret: Option<&str>,
    now: i64,
    tolerance_seconds: i64,
) -> Result<(), CanvasLegacyIngestError> {
    let secret = secret.filter(|secret| !secret.is_empty());
    let timestamp = headers.get(TIMESTAMP_HEADER).map(String::as_str);
    let signature = headers.get(SIGNATURE_HEADER).map(String::as_str);
    let (Some(secret), Some(timestamp), Some(signature)) = (secret, timestamp, signature) else {
        return Err(CanvasLegacyIngestError::InvalidSignature);
    };
    let timestamp_lexical = timestamp.trim();
    let unsigned_timestamp = timestamp_lexical
        .strip_prefix('+')
        .or_else(|| timestamp_lexical.strip_prefix('-'))
        .unwrap_or(timestamp_lexical);
    if timestamp_lexical.starts_with('_')
        || timestamp_lexical.ends_with('_')
        || timestamp_lexical.contains("__")
        || unsigned_timestamp.starts_with('_')
    {
        return Err(CanvasLegacyIngestError::InvalidSignature);
    }
    let timestamp_value = timestamp_lexical
        .replace('_', "")
        .parse::<i64>()
        .map_err(|_| CanvasLegacyIngestError::InvalidSignature)?;
    if tolerance_seconds < 0 || now.abs_diff(timestamp_value) > tolerance_seconds as u64 {
        return Err(CanvasLegacyIngestError::InvalidSignature);
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|_| CanvasLegacyIngestError::InvalidSignature)?;
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(raw_body);
    let expected = mac.finalize().into_bytes();
    let normalized = signature
        .trim()
        .strip_prefix("sha256=")
        .unwrap_or(signature.trim());
    if normalized.len() != 64
        || !normalized
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CanvasLegacyIngestError::InvalidSignature);
    }
    let actual = hex::decode(normalized).map_err(|_| CanvasLegacyIngestError::InvalidSignature)?;
    if actual.len() != expected.len()
        || !mmf_security::constant_time_secret_eq(actual.as_slice(), expected.as_slice())
    {
        return Err(CanvasLegacyIngestError::InvalidSignature);
    }
    Ok(())
}

fn validate_replay(
    receipt: &CanvasLegacyStoredReceipt,
    payload_hash: &str,
) -> Result<(), CanvasLegacyIngestError> {
    if receipt.payload_hash != payload_hash {
        return Err(CanvasLegacyIngestError::ReplayPayloadConflict);
    }
    if receipt.status != "evidence_received" {
        return Err(CanvasLegacyIngestError::ReplayFlowConflict);
    }
    Ok(())
}

fn parse_and_normalize(
    kind: CanvasLegacyEventKind,
    payload: &Value,
    now: DateTime<Utc>,
) -> Result<CanvasEvidenceEvent, CanvasLegacyIngestError> {
    match kind {
        CanvasLegacyEventKind::Evidence => parse_evidence(payload),
        CanvasLegacyEventKind::AgsScore => parse_ags(payload, now),
        CanvasLegacyEventKind::NrpsMembership => parse_nrps(payload, now),
    }
}

fn parse_evidence(payload: &Value) -> Result<CanvasEvidenceEvent, CanvasLegacyIngestError> {
    let object = payload.as_object().ok_or_else(|| {
        CanvasLegacyIngestError::Validation(vec![json!({
            "type": "model_type",
            "loc": [],
            "msg": "Input should be a valid dictionary or instance of CanvasEvidenceEvent",
            "input": payload,
            "ctx": {"class_name": "CanvasEvidenceEvent"},
            "url": "https://errors.pydantic.dev/2.13/v/model_type"
        })])
    })?;
    let mut errors = Vec::new();
    let event = CanvasEvidenceEvent {
        canvas_event_id: required_string(object, "canvas_event_id", &mut errors),
        organization_id: optional_string(object, "organization_id", &mut errors),
        credential_template_id: optional_string(object, "credential_template_id", &mut errors),
        canvas_account_id: required_string(object, "canvas_account_id", &mut errors),
        canvas_course_id: required_string(object, "canvas_course_id", &mut errors),
        canvas_course_name: required_string(object, "canvas_course_name", &mut errors),
        canvas_enrollment_id: required_string(object, "canvas_enrollment_id", &mut errors),
        canvas_user_id: required_string(object, "canvas_user_id", &mut errors),
        learner_email: required_string(object, "learner_email", &mut errors),
        learner_name: optional_string(object, "learner_name", &mut errors),
        learner_given_name: optional_string(object, "learner_given_name", &mut errors),
        learner_family_name: optional_string(object, "learner_family_name", &mut errors),
        achievement_name: required_string(object, "achievement_name", &mut errors),
        achievement_description: optional_string(object, "achievement_description", &mut errors),
        completion_at: required_string(object, "completion_at", &mut errors),
        application_id: required_string(object, "application_id", &mut errors),
        evidence_type: defaulted_string(
            object,
            "evidence_type",
            "canvas.course_completion",
            &mut errors,
        ),
        canvas_assignment_id: optional_string(object, "canvas_assignment_id", &mut errors),
        canvas_module_id: optional_string(object, "canvas_module_id", &mut errors),
        canvas_quiz_id: optional_string(object, "canvas_quiz_id", &mut errors),
        submitted: optional_bool(object, "submitted", &mut errors),
        completed: optional_bool(object, "completed", &mut errors),
        passed: optional_bool(object, "passed", &mut errors),
        score: optional_number(object, "score", &mut errors),
        score_percent: optional_number(object, "score_percent", &mut errors),
        roles: optional_string_list(object, "roles", &mut errors),
        membership_status: optional_string(object, "membership_status", &mut errors),
        eligible: optional_bool(object, "eligible", &mut errors),
    };
    finish_validation(event, errors)
}

fn parse_ags(
    payload: &Value,
    now: DateTime<Utc>,
) -> Result<CanvasEvidenceEvent, CanvasLegacyIngestError> {
    let object = payload
        .as_object()
        .ok_or(CanvasLegacyIngestError::ObjectRequired)?;
    let mut errors = Vec::new();
    let canvas_event_id = required_string(object, "canvas_event_id", &mut errors);
    let application_id = required_string(object, "application_id", &mut errors);
    let organization_id = optional_string(object, "organization_id", &mut errors);
    let credential_template_id = optional_string(object, "credential_template_id", &mut errors);
    let canvas_account_id = required_string(object, "canvas_account_id", &mut errors);
    let canvas_course_id = required_string(object, "canvas_course_id", &mut errors);
    let canvas_course_name = optional_string(object, "canvas_course_name", &mut errors);
    let canvas_user_id = required_string(object, "canvas_user_id", &mut errors);
    let canvas_enrollment_id = optional_string(object, "canvas_enrollment_id", &mut errors);
    let learner_email = optional_string(object, "learner_email", &mut errors);
    let learner_name = optional_string(object, "learner_name", &mut errors);
    let learner_given_name = optional_string(object, "learner_given_name", &mut errors);
    let learner_family_name = optional_string(object, "learner_family_name", &mut errors);
    let evidence_type = optional_string(object, "evidence_type", &mut errors);
    let assignment_id = optional_string(object, "canvas_assignment_id", &mut errors);
    let module_id = optional_string(object, "canvas_module_id", &mut errors);
    let quiz_id = optional_string(object, "canvas_quiz_id", &mut errors);
    let line_item_id = optional_string(object, "line_item_id", &mut errors);
    let _line_item_url = optional_string(object, "line_item_url", &mut errors);
    let line_item_label = optional_string(object, "line_item_label", &mut errors);
    let activity_progress = optional_string(object, "activity_progress", &mut errors);
    let grading_progress = optional_string(object, "grading_progress", &mut errors);
    let submitted = optional_bool(object, "submitted", &mut errors);
    let completed = optional_bool(object, "completed", &mut errors);
    let passed = optional_bool(object, "passed", &mut errors);
    let score = optional_number(object, "score", &mut errors);
    let score_given = optional_number(object, "score_given", &mut errors);
    let score_maximum = optional_number(object, "score_maximum", &mut errors);
    let score_percent = optional_number(object, "score_percent", &mut errors);
    let submitted_at = optional_string(object, "submitted_at", &mut errors);
    let graded_at = optional_string(object, "graded_at", &mut errors);
    let timestamp = optional_string(object, "timestamp", &mut errors);
    if !errors.is_empty() {
        return Err(CanvasLegacyIngestError::Validation(errors));
    }
    let progress = activity_progress
        .as_deref()
        .unwrap_or("")
        .to_ascii_lowercase();
    let grading = grading_progress
        .as_deref()
        .unwrap_or("")
        .to_ascii_lowercase();
    let line_item = nonempty_owned(line_item_id.clone())
        .or_else(|| nonempty_owned(assignment_id.clone()))
        .or_else(|| nonempty_owned(quiz_id.clone()));
    let achievement_name = nonempty_owned(line_item_label)
        .or_else(|| line_item.clone())
        .unwrap_or_else(|| "Canvas AGS score".to_owned());
    let score_percent = score_percent.or_else(|| {
        score_given.zip(score_maximum).and_then(|(given, maximum)| {
            (maximum != 0.0).then(|| python_round_6(given / maximum * 100.0))
        })
    });
    Ok(CanvasEvidenceEvent {
        canvas_event_id,
        application_id,
        organization_id,
        credential_template_id,
        canvas_account_id: canvas_account_id.clone(),
        canvas_course_id,
        canvas_course_name: nonempty_owned(canvas_course_name)
            .unwrap_or_else(|| "Canvas course".to_owned()),
        canvas_enrollment_id: nonempty_owned(canvas_enrollment_id)
            .unwrap_or_else(|| format!("canvas-user:{canvas_user_id}")),
        canvas_user_id: canvas_user_id.clone(),
        learner_email: nonempty_owned(learner_email)
            .unwrap_or_else(|| format!("canvas:{canvas_account_id}:user:{canvas_user_id}")),
        learner_name,
        learner_given_name,
        learner_family_name,
        achievement_name: achievement_name.clone(),
        achievement_description: Some(format!("Canvas AGS score for {achievement_name}")),
        completion_at: nonempty_owned(graded_at)
            .or_else(|| nonempty_owned(submitted_at))
            .or_else(|| nonempty_owned(timestamp))
            .unwrap_or_else(|| timestamp_string(now)),
        evidence_type: nonempty_owned(evidence_type).unwrap_or_else(|| {
            if quiz_id.as_deref().is_some_and(|value| !value.is_empty()) {
                "canvas.quiz_score".to_owned()
            } else {
                "canvas.assignment_score".to_owned()
            }
        }),
        canvas_assignment_id: nonempty_owned(assignment_id)
            .or_else(|| nonempty_owned(line_item_id)),
        canvas_module_id: module_id,
        canvas_quiz_id: quiz_id,
        submitted: submitted
            .or_else(|| matches!(progress.as_str(), "submitted" | "completed").then_some(true)),
        completed: Some(completed.unwrap_or({
            matches!(progress.as_str(), "completed" | "submitted")
                || matches!(grading.as_str(), "fullygraded" | "fully_graded" | "graded")
        })),
        passed,
        score: score.or(score_given),
        score_percent,
        roles: None,
        membership_status: None,
        eligible: None,
    })
}

fn parse_nrps(
    payload: &Value,
    now: DateTime<Utc>,
) -> Result<CanvasEvidenceEvent, CanvasLegacyIngestError> {
    let object = payload
        .as_object()
        .ok_or(CanvasLegacyIngestError::ObjectRequired)?;
    let mut errors = Vec::new();
    let canvas_event_id = required_string(object, "canvas_event_id", &mut errors);
    let application_id = required_string(object, "application_id", &mut errors);
    let organization_id = optional_string(object, "organization_id", &mut errors);
    let credential_template_id = optional_string(object, "credential_template_id", &mut errors);
    let canvas_account_id = required_string(object, "canvas_account_id", &mut errors);
    let canvas_course_id = required_string(object, "canvas_course_id", &mut errors);
    let canvas_course_name = optional_string(object, "canvas_course_name", &mut errors);
    let canvas_user_id = required_string(object, "canvas_user_id", &mut errors);
    let canvas_enrollment_id = optional_string(object, "canvas_enrollment_id", &mut errors);
    let membership_id = optional_string(object, "membership_id", &mut errors);
    let _context_memberships_url = optional_string(object, "context_memberships_url", &mut errors);
    let learner_email = optional_string(object, "learner_email", &mut errors);
    let learner_name = optional_string(object, "learner_name", &mut errors);
    let learner_given_name = optional_string(object, "learner_given_name", &mut errors);
    let learner_family_name = optional_string(object, "learner_family_name", &mut errors);
    let roles = defaulted_string_list(object, "roles", &mut errors);
    let membership_status = optional_string(object, "membership_status", &mut errors);
    let eligible = optional_bool(object, "eligible", &mut errors);
    let evidence_type = defaulted_string(
        object,
        "evidence_type",
        "canvas.nrps_membership",
        &mut errors,
    );
    let timestamp = optional_string(object, "timestamp", &mut errors);
    if !errors.is_empty() {
        return Err(CanvasLegacyIngestError::Validation(errors));
    }
    let active = eligible.unwrap_or_else(|| {
        matches!(
            membership_status
                .as_deref()
                .unwrap_or("")
                .to_ascii_lowercase()
                .as_str(),
            "active" | "enrolled" | "current" | "eligible" | ""
        )
    });
    let status = nonempty_owned(membership_status).unwrap_or_else(|| {
        if active {
            "eligible".to_owned()
        } else {
            "ineligible".to_owned()
        }
    });
    Ok(CanvasEvidenceEvent {
        canvas_event_id,
        application_id,
        organization_id,
        credential_template_id,
        canvas_account_id: canvas_account_id.clone(),
        canvas_course_id,
        canvas_course_name: nonempty_owned(canvas_course_name)
            .unwrap_or_else(|| "Canvas course".to_owned()),
        canvas_enrollment_id: nonempty_owned(canvas_enrollment_id)
            .or_else(|| nonempty_owned(membership_id))
            .unwrap_or_else(|| format!("canvas-user:{canvas_user_id}")),
        canvas_user_id: canvas_user_id.clone(),
        learner_email: nonempty_owned(learner_email)
            .unwrap_or_else(|| format!("canvas:{canvas_account_id}:user:{canvas_user_id}")),
        learner_name,
        learner_given_name,
        learner_family_name,
        achievement_name: "Canvas roster membership".to_owned(),
        achievement_description: Some(format!("Canvas NRPS membership status: {status}")),
        completion_at: nonempty_owned(timestamp).unwrap_or_else(|| timestamp_string(now)),
        evidence_type,
        canvas_assignment_id: None,
        canvas_module_id: None,
        canvas_quiz_id: None,
        submitted: None,
        completed: Some(active),
        passed: Some(active),
        score: None,
        score_percent: None,
        roles: Some(roles),
        membership_status: Some(status),
        eligible: Some(active),
    })
}

fn finish_validation<T>(value: T, errors: Vec<Value>) -> Result<T, CanvasLegacyIngestError> {
    if errors.is_empty() {
        Ok(value)
    } else {
        Err(CanvasLegacyIngestError::Validation(errors))
    }
}

fn required_string(object: &Map<String, Value>, name: &str, errors: &mut Vec<Value>) -> String {
    match object.get(name) {
        None => {
            errors.push(validation_error(
                name,
                "missing",
                "Field required",
                object,
                None,
            ));
            String::new()
        }
        Some(Value::String(value)) if !value.is_empty() => value.clone(),
        Some(Value::String(value)) => {
            errors.push(validation_error(
                name,
                "string_too_short",
                "String should have at least 1 character",
                Value::String(value.clone()),
                Some(json!({"min_length": 1})),
            ));
            String::new()
        }
        Some(value) => {
            errors.push(validation_error(
                name,
                "string_type",
                "Input should be a valid string",
                value,
                None,
            ));
            String::new()
        }
    }
}

fn optional_string(
    object: &Map<String, Value>,
    name: &str,
    errors: &mut Vec<Value>,
) -> Option<String> {
    match object.get(name) {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) => Some(value.clone()),
        Some(value) => {
            errors.push(validation_error(
                name,
                "string_type",
                "Input should be a valid string",
                value,
                None,
            ));
            None
        }
    }
}

fn defaulted_string(
    object: &Map<String, Value>,
    name: &str,
    default: &str,
    errors: &mut Vec<Value>,
) -> String {
    match object.get(name) {
        None => default.to_owned(),
        Some(Value::String(value)) => value.clone(),
        Some(value) => {
            errors.push(validation_error(
                name,
                "string_type",
                "Input should be a valid string",
                value,
                None,
            ));
            String::new()
        }
    }
}

fn optional_number(
    object: &Map<String, Value>,
    name: &str,
    errors: &mut Vec<Value>,
) -> Option<f64> {
    match object.get(name) {
        None | Some(Value::Null) => None,
        Some(Value::Bool(value)) => Some(if *value { 1.0 } else { 0.0 }),
        Some(Value::Number(value)) => value.as_f64(),
        Some(Value::String(value)) => match pydantic_float(value) {
            Ok(value) => Some(value),
            Err(_) => {
                errors.push(validation_error(
                    name,
                    "float_parsing",
                    "Input should be a valid number, unable to parse string as a number",
                    Value::String(value.clone()),
                    None,
                ));
                None
            }
        },
        Some(value) => {
            errors.push(validation_error(
                name,
                "float_type",
                "Input should be a valid number",
                value,
                None,
            ));
            None
        }
    }
}

fn optional_bool(object: &Map<String, Value>, name: &str, errors: &mut Vec<Value>) -> Option<bool> {
    match object.get(name) {
        None | Some(Value::Null) => None,
        Some(Value::Bool(value)) => Some(*value),
        Some(Value::Number(value)) if value.as_f64() == Some(0.0) => Some(false),
        Some(Value::Number(value)) if value.as_f64() == Some(1.0) => Some(true),
        Some(Value::String(value)) => match value.to_ascii_lowercase().as_str() {
            "0" | "off" | "f" | "false" | "n" | "no" => Some(false),
            "1" | "on" | "t" | "true" | "y" | "yes" => Some(true),
            _ => {
                errors.push(validation_error(
                    name,
                    "bool_parsing",
                    "Input should be a valid boolean, unable to interpret input",
                    Value::String(value.clone()),
                    None,
                ));
                None
            }
        },
        Some(value) => {
            errors.push(validation_error(
                name,
                "bool_type",
                "Input should be a valid boolean",
                value,
                None,
            ));
            None
        }
    }
}

fn pydantic_float(value: &str) -> Result<f64, std::num::ParseFloatError> {
    let parsed = value.parse::<f64>()?;
    // Pydantic accepts non-finite spellings, but the frozen FastAPI response
    // cannot serialize their normalized score fields. Reject them at the
    // validation boundary instead of allowing a post-persistence 500.
    if !parsed.is_finite() {
        return "not-a-finite-number".parse::<f64>();
    }
    Ok(parsed)
}

fn optional_string_list(
    object: &Map<String, Value>,
    name: &str,
    errors: &mut Vec<Value>,
) -> Option<Vec<String>> {
    match object.get(name) {
        None | Some(Value::Null) => None,
        Some(Value::Array(values)) => {
            let mut output = Vec::with_capacity(values.len());
            for (index, value) in values.iter().enumerate() {
                if let Some(value) = value.as_str() {
                    output.push(value.to_owned());
                } else {
                    errors.push(json!({
                        "type": "string_type",
                        "loc": [name, index],
                        "msg": "Input should be a valid string",
                        "input": value,
                        "url": "https://errors.pydantic.dev/2.13/v/string_type"
                    }));
                }
            }
            Some(output)
        }
        Some(value) => {
            errors.push(validation_error(
                name,
                "list_type",
                "Input should be a valid list",
                value,
                None,
            ));
            None
        }
    }
}

fn defaulted_string_list(
    object: &Map<String, Value>,
    name: &str,
    errors: &mut Vec<Value>,
) -> Vec<String> {
    match object.get(name) {
        None => Vec::new(),
        Some(Value::Array(values)) => {
            let mut output = Vec::with_capacity(values.len());
            for (index, value) in values.iter().enumerate() {
                if let Some(value) = value.as_str() {
                    output.push(value.to_owned());
                } else {
                    errors.push(json!({
                        "type": "string_type",
                        "loc": [name, index],
                        "msg": "Input should be a valid string",
                        "input": value,
                        "url": "https://errors.pydantic.dev/2.13/v/string_type"
                    }));
                }
            }
            output
        }
        Some(value) => {
            errors.push(validation_error(
                name,
                "list_type",
                "Input should be a valid list",
                value,
                None,
            ));
            Vec::new()
        }
    }
}

fn validation_error(
    name: &str,
    error_type: &str,
    message: &str,
    input: impl Serialize,
    context: Option<Value>,
) -> Value {
    let mut error = json!({
        "type": error_type,
        "loc": [name],
        "msg": message,
        "input": input,
        "url": format!("https://errors.pydantic.dev/2.13/v/{error_type}")
    });
    if let Some(context) = context {
        error["ctx"] = context;
    }
    error
}

fn python_round_6(value: f64) -> f64 {
    format!("{value:.6}").parse().unwrap_or(value)
}

fn validate_runtime(
    kind: CanvasLegacyEventKind,
    event: &CanvasEvidenceEvent,
    snapshot: &CanvasLegacyApplicationSnapshot,
) -> Result<(), CanvasLegacyIngestError> {
    if text(snapshot.platform.get("id")).is_empty() || text(snapshot.binding.get("id")).is_empty() {
        return Err(CanvasLegacyIngestError::ProgramBindingNotFound);
    }
    if event
        .credential_template_id
        .as_deref()
        .is_some_and(|value| value != text(snapshot.binding.get("credential_template_id")))
    {
        return Err(CanvasLegacyIngestError::BindingCredentialTemplateMismatch);
    }
    if !feature_enabled(&snapshot.binding, kind.feature_flag()) {
        return Err(CanvasLegacyIngestError::FeatureDisabled(
            kind.feature_flag(),
        ));
    }
    let application_org = text(snapshot.application.get("organization_id"));
    if event.organization_id.as_deref().unwrap_or(&application_org) != application_org {
        return Err(CanvasLegacyIngestError::OrganizationMismatch);
    }
    let status = text(snapshot.application.get("status"));
    if status != "pending" {
        return Err(CanvasLegacyIngestError::InvalidApplicationStatus(
            python_application_status(&status),
        ));
    }
    if text(snapshot.binding.get("application_template_id"))
        != text(snapshot.application.get("application_template_id"))
    {
        return Err(CanvasLegacyIngestError::ApplicationTemplateMismatch);
    }
    if snapshot
        .application_template
        .as_ref()
        .is_some_and(|template| {
            let credential = text(template.get("credential_template_id"));
            !credential.is_empty()
                && event
                    .credential_template_id
                    .as_deref()
                    .is_some_and(|event| event != credential)
        })
    {
        return Err(CanvasLegacyIngestError::ApplicationCredentialTemplateMismatch);
    }
    Ok(())
}

fn effective_requirements(snapshot: &CanvasLegacyApplicationSnapshot) -> Vec<Value> {
    snapshot
        .binding
        .get("evidence_requirements")
        .and_then(Value::as_array)
        .filter(|requirements| !requirements.is_empty())
        .cloned()
        .or_else(|| {
            snapshot
                .application_template
                .as_ref()
                .and_then(|template| template.get("evidence_requirements"))
                .and_then(Value::as_array)
                .filter(|requirements| !requirements.is_empty())
                .cloned()
        })
        .unwrap_or_else(|| vec![Value::String("canvas.course_completion".to_owned())])
}

fn matching_requirement<'a>(
    event: &CanvasEvidenceEvent,
    requirements: &'a [Value],
) -> Option<&'a Value> {
    requirements.iter().find(|requirement| {
        let (provider, fact_type) = match requirement {
            Value::String(value) => ("", value.as_str()),
            Value::Object(requirement) => {
                let provider = requirement
                    .get("provider")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let fact_type = ["fact_type", "evidence_type", "type"]
                    .iter()
                    .find_map(|key| {
                        requirement
                            .get(*key)
                            .and_then(Value::as_str)
                            .filter(|value| !value.is_empty())
                    })
                    .unwrap_or("");
                (provider, fact_type)
            }
            _ => return false,
        };
        (provider.is_empty() || provider == "canvas")
            && (fact_type.is_empty()
                || fact_type == "EXTERNAL_FACT"
                || fact_type == event.evidence_type)
    })
}

fn feature_enabled(binding: &Map<String, Value>, flag: &str) -> bool {
    let Some(flags) = binding.get("feature_flags").and_then(Value::as_object) else {
        return true;
    };
    const CANVAS_FLAGS: [&str; 8] = [
        "enable_canvas_evidence",
        "enable_canvas_lti",
        "enable_canvas_mirror_publish",
        "enable_canvas_mirror_ops",
        "enable_canvas_deep_linking",
        "enable_canvas_ags",
        "enable_canvas_nrps",
        "enable_background_awards",
    ];
    if !flags.keys().any(|key| CANVAS_FLAGS.contains(&key.as_str())) {
        return true;
    }
    flags.get(flag).is_some_and(python_json_truthy)
}

fn python_json_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64().is_some_and(|value| value != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
    }
}

fn projected_evidence_heads(current: &[Value], revision: &Value) -> Vec<Value> {
    let revision_key = revision.get("logical_key").and_then(Value::as_str);
    current
        .iter()
        .filter(|fact| {
            revision_key.is_none()
                || fact.get("logical_key").and_then(Value::as_str) != revision_key
        })
        .cloned()
        .chain(std::iter::once(revision.clone()))
        .collect()
}

fn mip_receipt(event: &CanvasEvidenceEvent, payload_hash: &str) -> Value {
    let (given_name, family_name) = split_name(event);
    json!({
        "organization_id": event.organization_id.as_deref().unwrap_or(""),
        "application_id": event.application_id,
        "evidence_type": event.evidence_type,
        "subject_id": event.learner_email,
        "evidence_data": {
            "email": event.learner_email,
            "given_name": given_name,
            "family_name": family_name,
            "achievement_name": event.achievement_name,
            "achievement_description": event.achievement_description.as_deref().unwrap_or(""),
            "canvas_account_id": event.canvas_account_id,
            "canvas_course_id": event.canvas_course_id,
            "canvas_course_name": event.canvas_course_name,
            "canvas_enrollment_id": event.canvas_enrollment_id,
            "canvas_user_id": event.canvas_user_id,
            "completion_at": event.completion_at,
            "source_event_id": event.canvas_event_id,
        },
        "source": {
            "provider": "canvas",
            "provider_account_id": event.canvas_account_id,
            "provider_event_id": event.canvas_event_id,
            "event_type": event.evidence_type,
            "subject_id": event.learner_email,
            "signature_scheme": "HMAC_SHA256_TIMESTAMPED",
            "payload_hash": payload_hash,
            "attributes": {
                "canvas_course_id": event.canvas_course_id,
                "canvas_enrollment_id": event.canvas_enrollment_id,
                "canvas_user_id": event.canvas_user_id,
            }
        },
        "action": "applications:write",
        "resource_type": "Application",
        "protocol": "SIGNED_EVIDENCE_RECEIPT",
    })
}

fn split_name(event: &CanvasEvidenceEvent) -> (String, String) {
    let given = event
        .learner_given_name
        .as_deref()
        .unwrap_or("")
        .trim()
        .to_owned();
    let family = event
        .learner_family_name
        .as_deref()
        .unwrap_or("")
        .trim()
        .to_owned();
    if !given.is_empty() || !family.is_empty() {
        return (given, family);
    }
    let full = event.learner_name.as_deref().unwrap_or("").trim();
    let (given, family) = full.split_once(' ').unwrap_or((full, ""));
    (given.trim().to_owned(), family.trim().to_owned())
}

fn evidence_fact(
    event: &CanvasEvidenceEvent,
    mip_primitives: &Value,
    fact_id: &str,
    receipt_id: &str,
    event_payload_hash: &str,
    verification_method: &str,
    now: DateTime<Utc>,
) -> Value {
    // The legacy Python adapter admitted against the matched requirement but
    // intentionally persisted an unbound fact. Preserve that logical-head key
    // so cutover revisions supersede Python-created facts instead of forking.
    let scope = event_scope(event);
    let assertion = event_assertion(event);
    let verification = json!({
        "method": verification_method,
        "status": "VERIFIED",
        "verified_at": timestamp_string(now),
    });
    let source = json!({
        "receipt_id": receipt_id,
        "provider_event_id": event.canvas_event_id,
        "payload_hash": event_payload_hash,
        "mip_receipt": mip_primitives,
    });
    let canonical_scope = python_canonical_json(&scope);
    let logical_key = hex::encode(Sha256::digest(
        format!(
            "{}|canvas|{}|{}|{}",
            "", event.evidence_type, canonical_scope, event.learner_email
        )
        .as_bytes(),
    ));
    let fact_payload = json!({
        "provider": "canvas",
        "fact_type": event.evidence_type,
        "scope": scope,
        "assertion": assertion,
        "verification": verification,
    });
    let payload_hash = hex::encode(Sha256::digest(
        python_canonical_json(&fact_payload).as_bytes(),
    ));
    json!({
        "id": fact_id,
        "organization_id": event.organization_id.as_deref().unwrap_or(""),
        "application_id": event.application_id,
        "subject_id": event.learner_email,
        "provider": "canvas",
        "fact_type": event.evidence_type,
        "scope": scope,
        "assertion": assertion,
        "verification": verification,
        "source": source,
        "requirement_id": Value::Null,
        "logical_key": logical_key,
        "source_revision": payload_hash,
        "payload_hash": payload_hash,
        "observed_at": timestamp_string(now),
        "effective_at": timestamp_string(now),
        "created_at": timestamp_string(now),
    })
}

fn event_scope(event: &CanvasEvidenceEvent) -> Value {
    let mut scope = Map::from_iter([
        (
            "canvas_account_id".to_owned(),
            Value::String(event.canvas_account_id.clone()),
        ),
        (
            "course_id".to_owned(),
            Value::String(event.canvas_course_id.clone()),
        ),
        (
            "enrollment_id".to_owned(),
            Value::String(event.canvas_enrollment_id.clone()),
        ),
        (
            "user_id".to_owned(),
            Value::String(event.canvas_user_id.clone()),
        ),
    ]);
    for (key, value) in [
        ("assignment_id", event.canvas_assignment_id.as_ref()),
        ("module_id", event.canvas_module_id.as_ref()),
        ("quiz_id", event.canvas_quiz_id.as_ref()),
    ] {
        if let Some(value) = value {
            scope.insert(key.to_owned(), Value::String(value.clone()));
        }
    }
    Value::Object(scope)
}

fn event_assertion(event: &CanvasEvidenceEvent) -> Value {
    let mut assertion = Map::from_iter([
        (
            "completed".to_owned(),
            Value::Bool(event.completed.unwrap_or(true)),
        ),
        (
            "completion_at".to_owned(),
            Value::String(event.completion_at.clone()),
        ),
    ]);
    for (key, value) in [
        ("submitted", event.submitted.map(Value::Bool)),
        ("passed", event.passed.map(Value::Bool)),
        (
            "score",
            event
                .score
                .and_then(serde_json::Number::from_f64)
                .map(Value::Number),
        ),
        (
            "score_percent",
            event
                .score_percent
                .and_then(serde_json::Number::from_f64)
                .map(Value::Number),
        ),
        (
            "course_name",
            Some(Value::String(event.canvas_course_name.clone())),
        ),
        (
            "achievement_name",
            Some(Value::String(event.achievement_name.clone())),
        ),
        ("roles", event.roles.clone().map(|roles| json!(roles))),
        (
            "membership_status",
            event.membership_status.clone().map(Value::String),
        ),
        ("eligible", event.eligible.map(Value::Bool)),
    ] {
        if let Some(value) = value {
            assertion.insert(key.to_owned(), value);
        }
    }
    Value::Object(assertion)
}

fn safe_fact(fact: &Value, event: &CanvasEvidenceEvent) -> Value {
    let names = [
        "id",
        "organization_id",
        "application_id",
        "subject_id",
        "provider",
        "fact_type",
        "scope",
        "assertion",
        "verification",
        "source",
        "created_at",
    ];
    let mut safe = Map::from_iter(names.into_iter().filter_map(|name| {
        fact.get(name)
            .cloned()
            .map(|value| (name.to_owned(), value))
    }));
    safe.insert("scope".to_owned(), event_scope(event));
    if let Some(source) = safe.get_mut("source").and_then(Value::as_object_mut) {
        source.remove("source");
    }
    Value::Object(safe)
}

fn evidence_submission(
    event: &CanvasEvidenceEvent,
    mip: &Value,
    fact_id: &str,
    requirements: &[Value],
    kind: CanvasLegacyEventKind,
    auto_approve: bool,
    now: DateTime<Utc>,
) -> Value {
    json!({
        "evidence_type": event.evidence_type,
        "evidence_data": mip.get("evidence_data").cloned().unwrap_or_else(|| json!({})),
        "submitted_at": timestamp_string(now),
        "source": mip.get("source").cloned().unwrap_or_else(|| json!({})),
        "mip_primitives": mip,
        "evidence_fact_ids": [fact_id],
        "verification": {
            "status": "verified",
            "method": kind.verification_method(),
            "requirements": requirements,
            "auto_approve_on_evidence": auto_approve,
        }
    })
}

fn apply_application_context(
    application: &mut Map<String, Value>,
    event: &CanvasEvidenceEvent,
    binding: &Map<String, Value>,
    kind: CanvasLegacyEventKind,
    fact_id: &str,
    policy_decision: Option<&Value>,
) {
    let mut integration = application
        .get("integration_context")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let delivery_mode = match text(binding.get("delivery_mode")) {
        value if value.is_empty() => "wallet_only".to_owned(),
        value => value,
    };
    let mut delivery = integration
        .get("delivery")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    delivery.insert("mode".to_owned(), Value::String(delivery_mode.clone()));
    let mut canvas = integration
        .get("canvas")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    canvas.extend(Map::from_iter([
        (
            "runtime_source".to_owned(),
            Value::String("program_binding".to_owned()),
        ),
        (
            "canvas_platform_id".to_owned(),
            binding.get("platform_id").cloned().unwrap_or(Value::Null),
        ),
        (
            "canvas_program_binding_id".to_owned(),
            binding.get("id").cloned().unwrap_or(Value::Null),
        ),
        (
            "deployment_profile_id".to_owned(),
            binding
                .get("deployment_profile_id")
                .cloned()
                .unwrap_or(Value::Null),
        ),
        (
            "feature_flags".to_owned(),
            binding
                .get("feature_flags")
                .cloned()
                .unwrap_or_else(|| json!({})),
        ),
        (
            "delivery_mode".to_owned(),
            Value::String(delivery_mode.clone()),
        ),
        (
            "canvas_account_id".to_owned(),
            Value::String(event.canvas_account_id.clone()),
        ),
        (
            "canvas_course_id".to_owned(),
            Value::String(event.canvas_course_id.clone()),
        ),
        (
            "canvas_user_id".to_owned(),
            Value::String(event.canvas_user_id.clone()),
        ),
        (
            "canvas_enrollment_id".to_owned(),
            Value::String(event.canvas_enrollment_id.clone()),
        ),
        (
            "source_event_id".to_owned(),
            Value::String(event.canvas_event_id.clone()),
        ),
        (
            "evidence_fact_id".to_owned(),
            Value::String(fact_id.to_owned()),
        ),
        (
            "standard_source".to_owned(),
            Value::String(kind.audit_source().to_owned()),
        ),
    ]));
    integration.insert("canvas".to_owned(), Value::Object(canvas));
    integration.insert("delivery_mode".to_owned(), Value::String(delivery_mode));
    integration.insert("delivery".to_owned(), Value::Object(delivery));
    if let Some(policy) = policy_decision {
        integration.insert("policy".to_owned(), policy.clone());
    }
    application.insert("integration_context".to_owned(), Value::Object(integration));
}

fn response_from_stored(
    stored: Value,
    source_event_id: &str,
    replayed: bool,
) -> Result<CanvasEvidenceEventResponse, CanvasLegacyIngestError> {
    let mut object = stored
        .as_object()
        .cloned()
        .ok_or(CanvasLegacyIngestError::MalformedStoredResponse)?;
    object.insert(
        "source_event_id".to_owned(),
        Value::String(source_event_id.to_owned()),
    );
    object.insert("replayed".to_owned(), Value::Bool(replayed));
    serde_json::from_value(Value::Object(object))
        .map_err(|_| CanvasLegacyIngestError::MalformedStoredResponse)
}

pub(crate) fn timestamp_string(now: DateTime<Utc>) -> String {
    let micros = now.nanosecond() / 1_000;
    let truncated = now.with_nanosecond(micros * 1_000).unwrap_or(now);
    truncated.to_rfc3339_opts(
        if micros == 0 {
            SecondsFormat::Secs
        } else {
            SecondsFormat::Micros
        },
        false,
    )
}

fn python_application_status(status: &str) -> String {
    format!("ApplicationStatus.{}", status.to_ascii_uppercase())
}

fn nonempty_owned(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.is_empty())
}

fn text(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(value)) => value.clone(),
        Some(Value::Null) | None => String::new(),
        Some(value) => value.to_string().trim_matches('"').to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    #[test]
    fn config_debug_redacts_the_webhook_secret() {
        let debug = format!(
            "{:?}",
            CanvasLegacyIngestConfig {
                enabled: true,
                shared_secret: Some("private-webhook-secret".to_owned()),
                shared_secret_file: None,
                signature_tolerance_seconds: 300,
            }
        );
        assert!(!debug.contains("private-webhook-secret"));
        assert!(debug.contains("shared_secret_configured: true"));
    }

    #[test]
    fn file_secret_is_reloaded_for_rotation_and_direct_secret_wins() {
        let path =
            std::env::temp_dir().join(format!("marty-canvas-secret-{}", uuid::Uuid::new_v4()));
        std::fs::write(&path, "first\n").expect("write first secret");
        let mut config = CanvasLegacyIngestConfig {
            enabled: true,
            shared_secret: None,
            shared_secret_file: Some(path.to_string_lossy().into_owned()),
            signature_tolerance_seconds: 300,
        };
        assert_eq!(config.resolve_shared_secret().as_deref(), Some("first"));
        std::fs::write(&path, "second\n").expect("rotate secret");
        assert_eq!(config.resolve_shared_secret().as_deref(), Some("second"));
        config.shared_secret = Some("direct".to_owned());
        assert_eq!(config.resolve_shared_secret().as_deref(), Some("direct"));
        std::fs::remove_file(path).expect("remove test secret");
    }

    #[test]
    fn file_secret_rejects_paths_outside_the_trusted_secret_root() {
        let config = CanvasLegacyIngestConfig {
            enabled: true,
            shared_secret: None,
            shared_secret_file: Some(
                std::env::current_exe()
                    .expect("current test executable")
                    .to_string_lossy()
                    .into_owned(),
            ),
            signature_tolerance_seconds: 300,
        };
        assert_eq!(config.resolve_shared_secret(), None);
    }

    #[test]
    fn python_rounding_is_ties_to_even_at_six_places() {
        for (input, expected) in [
            (1.234_566_5, 1.234_566),
            (1.234_567_5, 1.234_568),
            (0.000_000_5, 0.0),
            (0.000_001_5, 0.000_002),
            (66.666_666_5, 66.666_667),
            (66.666_667_5, 66.666_668),
        ] {
            assert_eq!(python_round_6(input), expected, "input={input:?}");
        }
    }

    #[test]
    fn signature_accepts_python_prefix_whitespace_and_inclusive_window() {
        let body = br#"{"emoji":"\ud83d\ude00","score":0.00001}"#;
        let timestamp = " 1788152400 ";
        let mut mac = Hmac::<Sha256>::new_from_slice(b"shared-secret").expect("HMAC key");
        mac.update(timestamp.as_bytes());
        mac.update(b".");
        mac.update(body);
        let digest = hex::encode(mac.finalize().into_bytes());
        for signature in [digest.clone(), format!(" sha256={digest} ")] {
            let headers = BTreeMap::from([
                (TIMESTAMP_HEADER.to_owned(), timestamp.to_owned()),
                (SIGNATURE_HEADER.to_owned(), signature),
            ]);
            assert_eq!(
                verify_signature(body, &headers, Some("shared-secret"), 1_788_152_700, 300),
                Ok(())
            );
            assert_eq!(
                verify_signature(body, &headers, Some("shared-secret"), 1_788_152_701, 300),
                Err(CanvasLegacyIngestError::InvalidSignature)
            );
        }
        for timestamp in ["+_1788152400", "-_1788152400"] {
            let mut mac = Hmac::<Sha256>::new_from_slice(b"shared-secret").expect("HMAC key");
            mac.update(timestamp.as_bytes());
            mac.update(b".");
            mac.update(body);
            let headers = BTreeMap::from([
                (TIMESTAMP_HEADER.to_owned(), timestamp.to_owned()),
                (
                    SIGNATURE_HEADER.to_owned(),
                    hex::encode(mac.finalize().into_bytes()),
                ),
            ]);
            assert_eq!(
                verify_signature(body, &headers, Some("shared-secret"), 1_788_152_400, 300),
                Err(CanvasLegacyIngestError::InvalidSignature)
            );
        }
    }

    #[test]
    fn ags_coercion_matches_pydantic_numeric_and_boolean_inputs() {
        let now = Utc::now();
        let event = parse_ags(
            &json!({
                "canvas_event_id":"event-1",
                "application_id":"application-1",
                "canvas_account_id":"account-1",
                "canvas_course_id":"course-1",
                "canvas_user_id":"user-1",
                "score_given":"1000",
                "score_maximum":"1500",
                "completed":1.0,
                "ignored_extension":{"large":true}
            }),
            now,
        )
        .expect("Pydantic-compatible AGS input");
        assert_eq!(event.score, Some(1_000.0));
        assert_eq!(event.score_percent, Some(66.666_667));
        assert_eq!(event.completed, Some(true));
        assert!(matches!(
            parse_ags(
                &json!({
                    "canvas_event_id":"event-1",
                    "application_id":"application-1",
                    "canvas_account_id":"account-1",
                    "canvas_course_id":"course-1",
                    "canvas_user_id":"user-1",
                    "score_given":" 1_0.5 "
                }),
                now,
            ),
            Err(CanvasLegacyIngestError::Validation(_))
        ));
        for value in ["_1", "1_", "1__0", "NaN", "Infinity", "-Infinity"] {
            assert!(matches!(
                parse_ags(
                    &json!({
                        "canvas_event_id":"event-1",
                        "application_id":"application-1",
                        "canvas_account_id":"account-1",
                        "canvas_course_id":"course-1",
                        "canvas_user_id":"user-1",
                        "score_given": value
                    }),
                    now,
                ),
                Err(CanvasLegacyIngestError::Validation(_))
            ));
        }
    }

    #[test]
    fn evidence_and_provider_non_object_errors_remain_distinct() {
        assert!(matches!(
            parse_evidence(&json!([])),
            Err(CanvasLegacyIngestError::Validation(errors))
                if errors[0]["type"] == "model_type"
        ));
        assert_eq!(
            parse_ags(&json!([]), Utc::now()),
            Err(CanvasLegacyIngestError::ObjectRequired)
        );
        assert_eq!(
            parse_nrps(&json!([]), Utc::now()),
            Err(CanvasLegacyIngestError::ObjectRequired)
        );
    }

    #[test]
    fn replay_restores_transport_fields_without_requiring_them_at_rest() {
        let response = response_from_stored(
            json!({
                "id":"event-1","application_id":"application-1",
                "organization_id":"org-1","canvas_account_id":"account-1",
                "evidence_type":"canvas.course_completion","status":"evidence_received",
                "evidence":{},"mip_primitives":{},"older_extra_field":"ignored"
            }),
            "event-1",
            true,
        )
        .expect("stored response");
        assert_eq!(response.source_event_id, "event-1");
        assert!(response.replayed);
        assert!(response.evidence_facts.is_empty());
        assert_eq!(response.application_status, None);
        assert_eq!(response.policy_decision, None);
    }

    #[test]
    fn feature_flags_use_python_json_truthiness_and_ignore_unknown_only_snapshots() {
        for (value, expected) in [
            (json!(1), true),
            (json!("false"), true),
            (json!([0]), true),
            (json!({"legacy": false}), true),
            (json!(0), false),
            (json!(""), false),
            (json!([]), false),
            (json!({}), false),
            (json!(null), false),
        ] {
            let binding = Map::from_iter([(
                "feature_flags".to_owned(),
                json!({"enable_canvas_evidence": value}),
            )]);
            assert_eq!(
                feature_enabled(&binding, "enable_canvas_evidence"),
                expected
            );
        }
        let binding = Map::from_iter([(
            "feature_flags".to_owned(),
            json!({"unknown_future_flag": false}),
        )]);
        assert!(feature_enabled(&binding, "enable_canvas_evidence"));
    }

    #[test]
    fn projected_policy_heads_replace_the_previous_revision() {
        let current = vec![
            json!({"id":"old-same-head","logical_key":"same","passed":true}),
            json!({"id":"other-head","logical_key":"other","passed":true}),
        ];
        let revision = json!({"id":"new-same-head","logical_key":"same","passed":false});
        assert_eq!(
            projected_evidence_heads(&current, &revision),
            vec![current[1].clone(), revision]
        );
    }

    #[test]
    fn legacy_fact_persists_actual_event_scope_not_requirement_scope() {
        let event = CanvasEvidenceEvent {
            canvas_event_id: "event-1".to_owned(),
            organization_id: Some("org-1".to_owned()),
            credential_template_id: None,
            canvas_account_id: "account-1".to_owned(),
            canvas_course_id: "course-actual".to_owned(),
            canvas_course_name: "Course".to_owned(),
            canvas_enrollment_id: "enrollment-actual".to_owned(),
            canvas_user_id: "user-actual".to_owned(),
            learner_email: "learner@example.test".to_owned(),
            learner_name: None,
            learner_given_name: None,
            learner_family_name: None,
            achievement_name: "Achievement".to_owned(),
            achievement_description: None,
            completion_at: "2026-08-31T00:00:00Z".to_owned(),
            application_id: "application-1".to_owned(),
            evidence_type: "canvas.course_completion".to_owned(),
            canvas_assignment_id: Some("assignment-actual".to_owned()),
            canvas_module_id: None,
            canvas_quiz_id: None,
            submitted: None,
            completed: Some(true),
            passed: Some(true),
            score: None,
            score_percent: None,
            roles: None,
            membership_status: None,
            eligible: None,
        };
        let fact = evidence_fact(
            &event,
            &json!({}),
            "fact-1",
            "receipt-1",
            "event-hash",
            "SIGNED_WEBHOOK",
            Utc::now(),
        );
        assert_eq!(fact["scope"], event_scope(&event));
        assert_eq!(fact["scope"]["course_id"], "course-actual");
        assert_eq!(fact["scope"]["assignment_id"], "assignment-actual");
        assert!(fact["requirement_id"].is_null());
        assert!(fact["source"].get("source").is_none());
        let expected_key = hex::encode(Sha256::digest(
            format!(
                "|canvas|canvas.course_completion|{}|learner@example.test",
                python_canonical_json(&event_scope(&event))
            )
            .as_bytes(),
        ));
        assert_eq!(fact["logical_key"], expected_key);
    }

    #[test]
    fn timestamps_match_python_isoformat_microsecond_precision() {
        let base = Utc
            .with_ymd_and_hms(2026, 8, 31, 12, 0, 0)
            .single()
            .expect("time");
        assert_eq!(timestamp_string(base), "2026-08-31T12:00:00+00:00");
        assert_eq!(
            timestamp_string(base.with_nanosecond(120_000_000).expect("nanos")),
            "2026-08-31T12:00:00.120000+00:00"
        );
        assert_eq!(
            timestamp_string(base.with_nanosecond(999).expect("nanos")),
            "2026-08-31T12:00:00+00:00"
        );
        assert_eq!(
            timestamp_string(base.with_nanosecond(120_000_999).expect("nanos")),
            "2026-08-31T12:00:00.120000+00:00"
        );
    }
}
