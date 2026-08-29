use std::{collections::BTreeSet, sync::Arc};

use async_trait::async_trait;
use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;
use serde_json::{Map, Value};
use thiserror::Error;

use crate::{
    canvas_issuance_guard::validated_requirements,
    canvas_lti_experience::{
        portable_canvas_pilot_enabled, python_string, CanvasLtiExperienceSessionContext,
        CanvasLtiExperienceSessionError, CanvasLtiExperienceSessionService,
    },
};

#[derive(Clone, Debug, PartialEq)]
pub struct CanvasLtiEvidenceApplication {
    pub id: String,
    pub organization_id: String,
    pub application_template_id: String,
    pub status: String,
    pub credential_id: Option<String>,
    pub integration_context: Value,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CanvasLtiEvidenceBinding {
    pub id: String,
    pub organization_id: String,
    pub platform_id: String,
    pub application_template_id: String,
    pub evidence_requirements: Vec<Value>,
    pub config_version: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanvasLtiEvidencePlatform {
    pub id: String,
    pub organization_id: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CanvasLtiEvidenceScope {
    pub application: CanvasLtiEvidenceApplication,
    pub binding: CanvasLtiEvidenceBinding,
    pub platform: CanvasLtiEvidencePlatform,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CanvasLtiEvidenceFact {
    pub provider: String,
    pub requirement_id: Option<String>,
    pub source: Value,
    pub verification: Value,
    pub observed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanvasLtiEvidenceSyncTarget {
    pub id: String,
    pub application_id: Option<String>,
    pub binding_id: String,
    pub platform_id: String,
    pub config_version: i64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CanvasLtiEvidenceSyncJob {
    pub id: String,
    pub status: String,
    pub result: Value,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanvasLtiEvidenceCandidate {
    pub id: String,
    pub application_id: Option<String>,
    pub binding_id: String,
    pub platform_id: String,
    pub state: String,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct CanvasLtiEvidenceProjectionData {
    pub facts: Vec<CanvasLtiEvidenceFact>,
    pub target: Option<CanvasLtiEvidenceSyncTarget>,
    pub jobs: Vec<CanvasLtiEvidenceSyncJob>,
    pub candidate: Option<CanvasLtiEvidenceCandidate>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CanvasLtiEvidenceJobStatus {
    pub job_id: String,
    pub status: String,
    pub requested_at: String,
    pub completed_at: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CanvasLtiEvidenceSummary {
    pub required_count: usize,
    pub current_authoritative_count: usize,
    pub verified_authoritative_count: usize,
    pub verified_required_count: usize,
    pub status: String,
    pub last_observed_at: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CanvasLtiEvidencePolicyStatus {
    pub status: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CanvasLtiClaimStatus {
    pub status: String,
    pub unsigned: bool,
    pub available: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CanvasLtiApplicationEvidenceStatusResponse {
    pub application_status: String,
    pub sync: Option<CanvasLtiEvidenceJobStatus>,
    pub evidence: CanvasLtiEvidenceSummary,
    pub policy: CanvasLtiEvidencePolicyStatus,
    pub claim: CanvasLtiClaimStatus,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CanvasLtiEvidenceError {
    #[error("Canvas LTI experience session not found")]
    SessionNotFound,
    #[error("Bootstrap the Canvas application before synchronizing evidence")]
    BootstrapRequired,
    #[error("Canvas application context was not found")]
    ContextNotFound,
    #[error("Portable Canvas integration is not enabled for this organization")]
    PilotDisabled,
    #[error("Canvas evidence configuration is unavailable")]
    EvidenceConfigurationUnavailable,
    #[error("Canvas evidence status is temporarily unavailable")]
    RepositoryUnavailable,
}

#[async_trait]
pub trait CanvasLtiEvidenceRepository: Send + Sync {
    async fn load_scope(
        &self,
        context: &CanvasLtiExperienceSessionContext,
    ) -> Result<Option<CanvasLtiEvidenceScope>, CanvasLtiEvidenceError>;

    async fn load_projection_data(
        &self,
        scope: &CanvasLtiEvidenceScope,
    ) -> Result<CanvasLtiEvidenceProjectionData, CanvasLtiEvidenceError>;
}

#[derive(Clone)]
pub struct CanvasLtiEvidenceService {
    sessions: CanvasLtiExperienceSessionService,
    repository: Arc<dyn CanvasLtiEvidenceRepository>,
    portable_enabled: bool,
    pilot_organizations: BTreeSet<String>,
}

impl std::fmt::Debug for CanvasLtiEvidenceService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CanvasLtiEvidenceService")
            .field("portable_enabled", &self.portable_enabled)
            .field("pilot_organizations", &self.pilot_organizations)
            .finish_non_exhaustive()
    }
}

impl CanvasLtiEvidenceService {
    #[must_use]
    pub fn new(
        sessions: CanvasLtiExperienceSessionService,
        repository: Arc<dyn CanvasLtiEvidenceRepository>,
        portable_enabled: bool,
        pilot_organizations: BTreeSet<String>,
    ) -> Self {
        Self {
            sessions,
            repository,
            portable_enabled,
            pilot_organizations,
        }
    }

    pub async fn status(
        &self,
        session_token: &str,
    ) -> Result<CanvasLtiApplicationEvidenceStatusResponse, CanvasLtiEvidenceError> {
        let context = self
            .sessions
            .load(session_token)
            .await
            .map_err(session_error)?;
        if context
            .application_id
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
        {
            return Err(CanvasLtiEvidenceError::BootstrapRequired);
        }
        if context
            .canvas_program_binding_id
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
            || context.canvas_platform_id.trim().is_empty()
        {
            return Err(CanvasLtiEvidenceError::ContextNotFound);
        }
        let scope = self
            .repository
            .load_scope(&context)
            .await?
            .filter(|scope| scope_matches_session(&context, scope))
            .ok_or(CanvasLtiEvidenceError::ContextNotFound)?;
        if !portable_canvas_pilot_enabled(
            self.portable_enabled,
            &self.pilot_organizations,
            &scope.application.organization_id,
        ) {
            return Err(CanvasLtiEvidenceError::PilotDisabled);
        }
        let data = self.repository.load_projection_data(&scope).await?;
        project_canvas_lti_evidence_status(&scope, &data)
    }
}

pub fn project_canvas_lti_evidence_status(
    scope: &CanvasLtiEvidenceScope,
    data: &CanvasLtiEvidenceProjectionData,
) -> Result<CanvasLtiApplicationEvidenceStatusResponse, CanvasLtiEvidenceError> {
    let binding = Map::from_iter([(
        "evidence_requirements".to_owned(),
        Value::Array(scope.binding.evidence_requirements.clone()),
    )]);
    let requirements = validated_requirements(&binding)
        .map_err(|_| CanvasLtiEvidenceError::EvidenceConfigurationUnavailable)?;
    let configured_ids = requirements
        .iter()
        .filter_map(|requirement| text(requirement.get("requirement_id")))
        .collect::<BTreeSet<_>>();
    let required_ids = requirements
        .iter()
        .filter(|requirement| {
            requirement
                .get("required")
                .and_then(Value::as_bool)
                .unwrap_or(true)
        })
        .filter_map(|requirement| text(requirement.get("requirement_id")))
        .collect::<BTreeSet<_>>();
    let authoritative_facts = data
        .facts
        .iter()
        .filter(|fact| {
            fact.provider == "canvas"
                && fact
                    .requirement_id
                    .as_ref()
                    .is_some_and(|id| configured_ids.contains(id))
                && fact
                    .source
                    .get("source")
                    .and_then(Value::as_str)
                    .is_some_and(|source| matches!(source, "ags_result" | "canvas_rest"))
        })
        .collect::<Vec<_>>();
    let authoritative_ids = authoritative_facts
        .iter()
        .filter_map(|fact| fact.requirement_id.clone())
        .collect::<BTreeSet<_>>();
    let verified_ids = authoritative_facts
        .iter()
        .filter(|fact| {
            fact.verification
                .get("status")
                .and_then(python_string)
                .is_some_and(|status| status.eq_ignore_ascii_case("VERIFIED"))
        })
        .filter_map(|fact| fact.requirement_id.clone())
        .collect::<BTreeSet<_>>();
    let target = data.target.as_ref().filter(|target| {
        target.application_id.as_deref() == Some(scope.application.id.as_str())
            && target.binding_id == scope.binding.id
            && target.platform_id == scope.platform.id
            && target.config_version == scope.binding.config_version
    });
    let jobs = if target.is_some() {
        data.jobs.as_slice()
    } else {
        &[]
    };
    let latest_job = jobs.first();
    let latest_success = jobs.iter().find(|job| {
        job.status == "succeeded"
            && job.result.get("config_version").and_then(Value::as_i64)
                == Some(scope.binding.config_version)
    });
    let current_verified_ids = if latest_success.is_some() {
        verified_ids
    } else {
        BTreeSet::new()
    };
    let sync = latest_job
        .map(|job| {
            Ok(CanvasLtiEvidenceJobStatus {
                job_id: job.id.clone(),
                status: public_job_status(&job.status)
                    .ok_or(CanvasLtiEvidenceError::RepositoryUnavailable)?
                    .to_owned(),
                requested_at: python_isoformat(job.created_at),
                completed_at: job.completed_at.map(python_isoformat),
            })
        })
        .transpose()?;
    let active_job =
        latest_job.is_some_and(|job| matches!(job.status.as_str(), "queued" | "leased" | "retry"));
    let evidence_status = if required_ids.is_empty() {
        "not_required"
    } else if required_ids.is_subset(&current_verified_ids) {
        "verified"
    } else if active_job && authoritative_ids.is_empty() {
        "syncing"
    } else if !authoritative_ids.is_empty() {
        "partial"
    } else {
        "not_observed"
    };
    let last_observed_at = authoritative_facts
        .iter()
        .map(|fact| fact.observed_at)
        .max()
        .map(python_isoformat);
    let policy_status = latest_success
        .and_then(|job| job.result.get("policy_allowed"))
        .and_then(Value::as_bool)
        .map_or("not_evaluated", |allowed| {
            if allowed {
                "permitted"
            } else {
                "not_permitted"
            }
        });
    let canvas = scope
        .application
        .integration_context
        .get("canvas")
        .and_then(Value::as_object);
    let candidate_id = canvas
        .and_then(|canvas| canvas.get("canvas_award_candidate_id"))
        .and_then(python_string)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    let candidate = data.candidate.as_ref().filter(|candidate| {
        candidate_id.as_deref() == Some(candidate.id.as_str())
            && candidate.application_id.as_deref() == Some(scope.application.id.as_str())
            && candidate.binding_id == scope.binding.id
            && candidate.platform_id == scope.platform.id
    });
    let (claim_status, unsigned, available) = if scope
        .application
        .credential_id
        .as_deref()
        .is_some_and(|value| !value.is_empty())
        || candidate.is_some_and(|candidate| candidate.state == "claimed")
    {
        ("claimed", false, false)
    } else if scope.application.status == "approved" {
        ("ready_to_claim", true, true)
    } else if candidate.is_some_and(|candidate| candidate.state == "pending_claim") {
        ("pending_claim", true, false)
    } else {
        ("not_available", false, false)
    };
    Ok(CanvasLtiApplicationEvidenceStatusResponse {
        application_status: scope.application.status.clone(),
        sync,
        evidence: CanvasLtiEvidenceSummary {
            required_count: required_ids.len(),
            current_authoritative_count: authoritative_ids.len(),
            verified_authoritative_count: current_verified_ids.len(),
            verified_required_count: required_ids.intersection(&current_verified_ids).count(),
            status: evidence_status.to_owned(),
            last_observed_at,
        },
        policy: CanvasLtiEvidencePolicyStatus {
            status: policy_status.to_owned(),
        },
        claim: CanvasLtiClaimStatus {
            status: claim_status.to_owned(),
            unsigned,
            available,
        },
    })
}

fn scope_matches_session(
    context: &CanvasLtiExperienceSessionContext,
    scope: &CanvasLtiEvidenceScope,
) -> bool {
    let application = &scope.application;
    let binding = &scope.binding;
    let platform = &scope.platform;
    if context.application_id.as_deref() != Some(application.id.as_str())
        || application.organization_id != context.launch_state.organization_id
        || context.canvas_program_binding_id.as_deref() != Some(binding.id.as_str())
        || context.canvas_platform_id != platform.id
        || binding.organization_id != application.organization_id
        || platform.organization_id != application.organization_id
        || binding.platform_id != platform.id
        || binding.application_template_id != application.application_template_id
    {
        return false;
    }
    let Some(canvas) = application
        .integration_context
        .get("canvas")
        .and_then(Value::as_object)
    else {
        return false;
    };
    if text(canvas.get("canvas_platform_id")).as_deref() != Some(platform.id.as_str())
        || text(canvas.get("canvas_program_binding_id")).as_deref() != Some(binding.id.as_str())
    {
        return false;
    }
    let mut states = [canvas.get("lti_state"), canvas.get("last_lti_state")]
        .into_iter()
        .flatten()
        .filter_map(python_string)
        .filter(|value| !value.is_empty())
        .collect::<BTreeSet<_>>();
    states.extend(
        canvas
            .get("lti_states")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(python_string)
            .filter(|value| !value.is_empty()),
    );
    states.contains(&context.state)
}

fn public_job_status(status: &str) -> Option<&str> {
    match status {
        "queued" => Some("queued"),
        "leased" => Some("running"),
        "retry" => Some("retrying"),
        "succeeded" => Some("succeeded"),
        "dead_letter" => Some("failed"),
        "cancelled" => Some("cancelled"),
        _ => None,
    }
}

fn python_isoformat(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::AutoSi, false)
}

fn text(value: Option<&Value>) -> Option<String> {
    value
        .and_then(python_string)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn session_error(error: CanvasLtiExperienceSessionError) -> CanvasLtiEvidenceError {
    match error {
        CanvasLtiExperienceSessionError::NotFound => CanvasLtiEvidenceError::SessionNotFound,
        CanvasLtiExperienceSessionError::RepositoryUnavailable => {
            CanvasLtiEvidenceError::RepositoryUnavailable
        }
    }
}
