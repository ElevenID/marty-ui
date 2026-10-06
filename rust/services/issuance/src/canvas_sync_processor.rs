//! Authoritative, unsigned Canvas evidence reconciliation.
//!
//! Provider I/O and persistence are ports so the same processor is exercised
//! by bounded simulators and the standalone worker. Signing/approval remain
//! outside this module by design.

use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use chrono::{DateTime, SecondsFormat, Utc};
use mmf_config::numeric_config::PythonConfigInteger;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    canvas_award_candidate::python_canonical_json,
    canvas_issuance_guard::validated_requirements,
    canvas_lti_bootstrap::CanvasLtiBootstrapApplication,
    canvas_sync_lease::{lease_lost, CanvasSyncLease},
    canvas_sync_worker::{
        canvas_sync_result, CanvasSyncProcessingError, CanvasSyncProcessor, CanvasSyncResult,
        CanvasSyncTarget, CanvasSyncTargetType, CanvasSyncWorkerConfig,
        UnexpectedCanvasSyncFailure,
    },
};

#[derive(Clone, Debug, PartialEq)]
pub struct CanvasSyncPlatformSnapshot {
    pub id: String,
    pub organization_id: String,
    pub canvas_base_url: String,
    pub lti_trust_profile: String,
    pub lti_issuer: String,
    pub lti_client_id: String,
    pub lti_deployment_id: String,
    pub lti_auth_token_url: String,
    pub config_version: i32,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CanvasSyncApplicationSnapshot {
    pub application: CanvasLtiBootstrapApplication,
    pub credential_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CanvasSyncResources {
    pub platform: CanvasSyncPlatformSnapshot,
    pub binding: Map<String, Value>,
    pub application: Option<CanvasSyncApplicationSnapshot>,
    pub application_template: Option<Map<String, Value>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanvasLinkedIdentitySnapshot {
    pub id: String,
    pub lti_subject: String,
    pub canvas_user_id: Option<String>,
    pub status: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CanvasAuthoritativeObservation {
    pub assertion: Map<String, Value>,
    pub source_payload: Map<String, Value>,
    pub verification_method: &'static str,
    pub effective_at: Option<DateTime<Utc>>,
}

impl CanvasAuthoritativeObservation {
    fn into_candidate(mut self, source: &str) -> Self {
        // Published background AGS hashes exclude the learner-only result ID
        // and status assertion. Keep the full shared provider observation for
        // learner/issued-drift facts; project only at the candidate boundary.
        if source == "ags_result" {
            self.assertion.remove("result_status");
            self.source_payload.remove("id");
        }
        self
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct CanvasRosterSnapshot {
    pub canvas_user_ids: Vec<String>,
    pub lti_subjects: Vec<String>,
    pub preloaded_observations: BTreeMap<(String, String), CanvasAuthoritativeObservation>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CanvasRosterCandidate {
    pub id: String,
    pub candidate_key: String,
    pub canvas_user_id: Option<String>,
    pub lti_subject: Option<String>,
    pub learner_identity_id: Option<String>,
    pub state: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CanvasCandidateObservationSnapshot {
    pub requirement_id: String,
    pub assertion: Map<String, Value>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanvasFactCommit {
    pub fact_id: String,
    pub inserted: bool,
    pub policy_allowed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CanvasProviderReadError {
    Unavailable,
    ReauthorizationRequired,
    RateLimited { retry_after_seconds: u64 },
    InvalidConfiguration,
    RosterConfigurationInvalid,
    RosterOAuthUnavailable,
    NrpsRosterUnavailable,
    RosterCollectionTooLarge,
    RosterHttpStatusFailure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanvasProviderRunScope {
    Application,
    BackgroundRoster,
}

impl CanvasProviderRunScope {
    pub fn from_target_type(target_type: CanvasSyncTargetType) -> Option<Self> {
        match target_type {
            CanvasSyncTargetType::LearnerApplication | CanvasSyncTargetType::IssuedDrift => {
                Some(Self::Application)
            }
            CanvasSyncTargetType::BackgroundRoster => Some(Self::BackgroundRoster),
            CanvasSyncTargetType::AwardCandidate => None,
        }
    }
}

#[async_trait]
pub trait CanvasAuthoritativeProvider: Send + Sync {
    /// Start one processor invocation. Stateful providers must return fresh
    /// run-local state; a shared provider must never retain another job's tokens.
    fn for_run(
        self: Arc<Self>,
        scope: CanvasProviderRunScope,
    ) -> Arc<dyn CanvasAuthoritativeProvider>;

    async fn read_requirement(
        &self,
        resources: &CanvasSyncResources,
        requirement: &Value,
        canvas_user_id: Option<&str>,
        lti_subject: Option<&str>,
    ) -> Result<CanvasAuthoritativeObservation, CanvasProviderReadError>;

    async fn roster(
        &self,
        target: &CanvasSyncTarget,
        resources: &CanvasSyncResources,
        requirements: &[Value],
        limit: usize,
    ) -> Result<CanvasRosterSnapshot, CanvasProviderReadError>;
}

#[async_trait]
pub trait CanvasSyncProcessorRepository: Send + Sync {
    /// Bind a distinct repository instance to this job; never mutate a shared
    /// current-job slot while concurrently processing another lease.
    fn for_lease(self: Arc<Self>, lease: CanvasSyncLease)
        -> Arc<dyn CanvasSyncProcessorRepository>;
    async fn resources(
        &self,
        target: &CanvasSyncTarget,
    ) -> Result<Option<CanvasSyncResources>, CanvasSyncProcessingError>;
    async fn linked_identity_by_subject(
        &self,
        organization_id: &str,
        platform_id: &str,
        deployment_id: &str,
        subject: &str,
    ) -> Result<Option<CanvasLinkedIdentitySnapshot>, CanvasSyncProcessingError>;
    async fn linked_identity_by_canvas_user(
        &self,
        organization_id: &str,
        platform_id: &str,
        deployment_id: &str,
        canvas_user_id: &str,
    ) -> Result<Option<CanvasLinkedIdentitySnapshot>, CanvasSyncProcessingError>;
    async fn record_fact(
        &self,
        target: &CanvasSyncTarget,
        resources: &CanvasSyncResources,
        fact: &Value,
    ) -> Result<CanvasFactCommit, CanvasSyncProcessingError>;
    async fn patch_application_sync(
        &self,
        target: &CanvasSyncTarget,
        resources: &CanvasSyncResources,
        checked: &[String],
        policy_allowed: bool,
    ) -> Result<bool, CanvasSyncProcessingError>;
    async fn patch_platform_validation(
        &self,
        target: &CanvasSyncTarget,
        resources: &CanvasSyncResources,
        error_code: Option<&str>,
    ) -> Result<bool, CanvasSyncProcessingError>;
    async fn disable_target(
        &self,
        target: &CanvasSyncTarget,
    ) -> Result<(), CanvasSyncProcessingError>;
    async fn existing_candidates(
        &self,
        organization_id: &str,
        binding_id: &str,
        limit: usize,
    ) -> Result<Vec<CanvasRosterCandidate>, CanvasSyncProcessingError>;
    async fn save_candidate(
        &self,
        target: &CanvasSyncTarget,
        resources: &CanvasSyncResources,
        candidate: &CanvasRosterCandidate,
    ) -> Result<String, CanvasSyncProcessingError>;
    async fn save_candidate_observation(
        &self,
        target: &CanvasSyncTarget,
        resources: &CanvasSyncResources,
        candidate_id: &str,
        requirement_id: &str,
        observation: &CanvasAuthoritativeObservation,
    ) -> Result<bool, CanvasSyncProcessingError>;
    async fn current_candidate_observations(
        &self,
        organization_id: &str,
        candidate_id: &str,
    ) -> Result<Vec<CanvasCandidateObservationSnapshot>, CanvasSyncProcessingError>;
    async fn update_roster_cursor(
        &self,
        target: &CanvasSyncTarget,
        resources: &CanvasSyncResources,
        next_cursor: usize,
        roster_size: usize,
    ) -> Result<(), CanvasSyncProcessingError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanvasRosterBounds {
    batch_size: usize,
    limit: usize,
}

impl CanvasRosterBounds {
    const MAX_BATCH_SIZE: usize = 2_000;
    const MAX_ROSTER_SIZE: usize = 10_000;

    fn new(batch_size: usize, limit: usize) -> Self {
        let batch_size = batch_size.clamp(1, Self::MAX_BATCH_SIZE);
        Self {
            batch_size,
            limit: limit.clamp(batch_size, Self::MAX_ROSTER_SIZE),
        }
    }

    /// Parse without requiring a roster job to exist. Callers retain an error
    /// until roster processing; unrelated application work must remain available.
    pub fn from_values(
        batch: Option<&str>,
        limit: Option<&str>,
    ) -> Result<Self, CanvasSyncProcessingError> {
        fn bounded(
            value: Option<&str>,
            default: u64,
            minimum: usize,
            maximum: u64,
        ) -> Result<usize, CanvasSyncProcessingError> {
            let value = match value {
                None => PythonConfigInteger::from(default),
                Some(value) => value.parse::<PythonConfigInteger>().map_err(|_| {
                    CanvasSyncProcessingError::terminal(
                        "canvas_roster_configuration_invalid",
                        "Canvas roster bounds are invalid",
                    )
                })?,
            };
            let value = value.max((minimum as u64).into()).min(maximum.into());
            Ok(
                usize::try_from(value.to_u64().expect("bounded roster integer fits u64"))
                    .expect("roster bound at most 10000 fits usize"),
            )
        }
        let batch_size = bounded(batch, 500, 1, Self::MAX_BATCH_SIZE as u64)?;
        let limit = bounded(limit, 5_000, batch_size, Self::MAX_ROSTER_SIZE as u64)?;
        Ok(Self { batch_size, limit })
    }
}

#[derive(Clone)]
pub struct NativeCanvasSyncProcessor {
    repository: Arc<dyn CanvasSyncProcessorRepository>,
    provider: Arc<dyn CanvasAuthoritativeProvider>,
    config: CanvasSyncWorkerConfig,
    roster_configuration: Result<CanvasRosterBounds, CanvasSyncProcessingError>,
}

impl std::fmt::Debug for NativeCanvasSyncProcessor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = formatter.debug_struct("NativeCanvasSyncProcessor");
        match &self.roster_configuration {
            Ok(bounds) => {
                debug
                    .field("roster_batch_size", &bounds.batch_size)
                    .field("roster_limit", &bounds.limit);
            }
            Err(error) => {
                debug.field("roster_configuration_error", &error.code);
            }
        }
        debug.finish_non_exhaustive()
    }
}

impl NativeCanvasSyncProcessor {
    #[must_use]
    pub fn new(
        repository: Arc<dyn CanvasSyncProcessorRepository>,
        provider: Arc<dyn CanvasAuthoritativeProvider>,
        config: CanvasSyncWorkerConfig,
        roster_batch_size: usize,
        roster_limit: usize,
    ) -> Self {
        Self::new_with_roster_configuration(
            repository,
            provider,
            config,
            Ok(CanvasRosterBounds::new(roster_batch_size, roster_limit)),
        )
    }

    #[must_use]
    pub fn new_with_roster_configuration(
        repository: Arc<dyn CanvasSyncProcessorRepository>,
        provider: Arc<dyn CanvasAuthoritativeProvider>,
        config: CanvasSyncWorkerConfig,
        roster_configuration: Result<CanvasRosterBounds, CanvasSyncProcessingError>,
    ) -> Self {
        Self {
            repository,
            provider,
            config,
            roster_configuration,
        }
    }

    async fn process_application(
        &self,
        target: &CanvasSyncTarget,
        resources: &CanvasSyncResources,
    ) -> Result<Map<String, Value>, CanvasSyncProcessingError> {
        let requirements = requirements(resources)?;
        let application = resources
            .application
            .as_ref()
            .ok_or_else(resources_unavailable)?;
        let template = resources
            .application_template
            .as_ref()
            .filter(|template| text(template.get("organization_id")) == target.organization_id)
            .ok_or_else(|| {
                CanvasSyncProcessingError::terminal(
                    "canvas_application_template_unavailable",
                    "Canvas application template is unavailable",
                )
            })?;
        let canvas_context = application
            .application
            .integration_context
            .get("canvas")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let subject = text(canvas_context.get("lti_subject"));
        if subject.is_empty() {
            return Err(CanvasSyncProcessingError::terminal(
                "canvas_lti_identity_missing",
                "Canvas application has no verified LTI subject",
            ));
        }
        let identity = self
            .repository
            .linked_identity_by_subject(
                &target.organization_id,
                &resources.platform.id,
                &resources.platform.lti_deployment_id,
                &subject,
            )
            .await?;
        let numeric_user_id = identity
            .as_ref()
            .filter(|identity| identity.status == "linked")
            .and_then(|identity| identity.canvas_user_id.as_deref());
        let mut checked = Vec::new();
        let mut created = 0usize;
        let mut reused = 0usize;
        let mut policy_allowed = canvas_context
            .get("last_evidence_policy_allowed")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let mut retry_after = None;
        let mut reauthorization = false;
        for requirement in &requirements {
            let source = text(requirement.get("source"));
            if source == "canvas_rest" && numeric_user_id.is_none() {
                continue;
            }
            let read = self
                .provider
                .read_requirement(resources, requirement, numeric_user_id, Some(&subject))
                .await;
            let observation = match read {
                Ok(observation) => observation,
                Err(CanvasProviderReadError::RateLimited {
                    retry_after_seconds,
                }) => {
                    retry_after = Some(retry_after.unwrap_or(0).max(retry_after_seconds));
                    continue;
                }
                Err(CanvasProviderReadError::ReauthorizationRequired) => {
                    reauthorization = true;
                    continue;
                }
                Err(CanvasProviderReadError::Unavailable) => continue,
                Err(error @ CanvasProviderReadError::RosterHttpStatusFailure) => {
                    return Err(provider_processing_error(error));
                }
                Err(CanvasProviderReadError::InvalidConfiguration) => {
                    return Err(CanvasSyncProcessingError::terminal(
                        "canvas_requirements_invalid",
                        "Canvas evidence requirements are invalid",
                    ));
                }
                Err(CanvasProviderReadError::RosterConfigurationInvalid) => {
                    return Err(CanvasSyncProcessingError::terminal(
                        "canvas_roster_configuration_invalid",
                        "Canvas roster configuration is invalid",
                    ));
                }
                Err(CanvasProviderReadError::RosterCollectionTooLarge) => {
                    return Err(CanvasSyncProcessingError::terminal(
                        "canvas_roster_collection_too_large",
                        "Canvas roster collection exceeds the configured bound",
                    ));
                }
                Err(
                    CanvasProviderReadError::RosterOAuthUnavailable
                    | CanvasProviderReadError::NrpsRosterUnavailable,
                ) => continue,
            };
            let fact = authoritative_fact(
                application,
                &resources.platform,
                &resources.binding,
                requirement,
                &subject,
                &observation,
            );
            // The reused atomic owner locks the application, advances the fact
            // head, evaluates policy, and creates/resolves correction reviews.
            let commit = self
                .repository
                .record_fact(target, resources, &fact)
                .await?;
            checked.push(text(requirement.get("requirement_id")));
            if commit.inserted {
                created += 1;
            } else {
                reused += 1;
            }
            policy_allowed = commit.policy_allowed;
        }
        let validation_error = if reauthorization {
            Some("oauth_reauthorization_required")
        } else if checked.is_empty() {
            Some("canvas_authoritative_reads_failed")
        } else {
            None
        };
        if !self
            .repository
            .patch_platform_validation(target, resources, validation_error)
            .await?
        {
            return Err(platform_reconfigured());
        }
        if !self
            .repository
            .patch_application_sync(target, resources, &checked, policy_allowed)
            .await?
        {
            return Err(application_unavailable());
        }
        if let Some(retry_after_seconds) = retry_after {
            return Err(CanvasSyncProcessingError::retryable(
                "canvas_rate_limited",
                "Canvas rate limited one or more authoritative evidence reads",
            )
            .with_retry_after(retry_after_seconds));
        }
        if checked.is_empty() {
            return Err(CanvasSyncProcessingError::retryable(
                "canvas_authoritative_reads_failed",
                "No authoritative Canvas evidence requirement could be read",
            ));
        }
        let _ = template; // Template presence is part of the frozen gate.
        Ok(Map::from_iter([
            (
                "application_id".to_owned(),
                Value::String(application.application.id.clone()),
            ),
            (
                "config_version".to_owned(),
                Value::from(target.config_version),
            ),
            (
                "requirements_checked".to_owned(),
                Value::from(checked.len()),
            ),
            ("facts_created".to_owned(), Value::from(created)),
            ("facts_reused".to_owned(), Value::from(reused)),
            ("policy_allowed".to_owned(), Value::Bool(policy_allowed)),
        ]))
    }

    async fn process_roster(
        &self,
        target: &CanvasSyncTarget,
        resources: &CanvasSyncResources,
    ) -> Result<Map<String, Value>, CanvasSyncProcessingError> {
        let requirements = requirements(resources)?;
        let bounds = self.roster_configuration.as_ref().map_err(Clone::clone)?;
        let has_rest = requirements
            .iter()
            .any(|item| text(item.get("source")) == "canvas_rest");
        let has_ags = requirements
            .iter()
            .any(|item| text(item.get("source")) == "ags_result");
        let mixed = has_rest && has_ags;
        let roster = self
            .provider
            .roster(target, resources, &requirements, bounds.limit)
            .await
            .map_err(provider_processing_error)?;
        let preloaded_observations = roster.preloaded_observations.clone();
        let opaque = roster
            .lti_subjects
            .iter()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        let mut inputs = Vec::new();
        if has_rest {
            let mut users = roster.canvas_user_ids;
            users.sort();
            users.dedup();
            for user in users {
                let identity = self
                    .repository
                    .linked_identity_by_canvas_user(
                        &target.organization_id,
                        &resources.platform.id,
                        &resources.platform.lti_deployment_id,
                        &user,
                    )
                    .await?;
                let subject = identity
                    .as_ref()
                    .filter(|identity| identity.status == "linked")
                    .map(|identity| identity.lti_subject.clone());
                inputs.push((Some(user), subject, identity));
            }
        } else {
            let mut subjects = roster.lti_subjects;
            subjects.sort();
            subjects.dedup();
            inputs.extend(
                subjects
                    .into_iter()
                    .map(|subject| (None, Some(subject), None)),
            );
        }
        let mut cursor = roster_cursor(target);
        if cursor >= inputs.len() {
            cursor = 0;
        }
        let batch = inputs
            .iter()
            .skip(cursor)
            .take(bounds.batch_size)
            .cloned()
            .collect::<Vec<_>>();
        let existing = self
            .repository
            .existing_candidates(
                &target.organization_id,
                &resources.binding_id(),
                bounds.limit,
            )
            .await?
            .into_iter()
            .map(|candidate| (candidate.candidate_key.clone(), candidate))
            .collect::<BTreeMap<_, _>>();
        let mut seen = 0usize;
        let mut pending = 0usize;
        let mut identity_required = 0usize;
        let mut written = 0usize;
        for (canvas_user_id, lti_subject, identity) in batch.iter() {
            let key = candidate_key(
                &resources.platform.id,
                &resources.binding_id(),
                canvas_user_id.as_deref(),
                lti_subject.as_deref(),
            );
            let mut candidate = existing
                .get(&key)
                .cloned()
                .unwrap_or(CanvasRosterCandidate {
                    id: Uuid::new_v4().to_string(),
                    candidate_key: key,
                    canvas_user_id: None,
                    lti_subject: None,
                    learner_identity_id: None,
                    state: "observed".to_owned(),
                });
            candidate.canvas_user_id.clone_from(canvas_user_id);
            candidate.lti_subject.clone_from(lti_subject);
            candidate.learner_identity_id = identity.as_ref().map(|value| value.id.clone());
            if !matches!(candidate.state.as_str(), "claimed" | "dismissed") {
                let linked = identity
                    .as_ref()
                    .is_some_and(|identity| identity.status == "linked");
                candidate.state = if mixed
                    && (!linked
                        || lti_subject
                            .as_deref()
                            .is_none_or(|subject| !opaque.contains(subject)))
                {
                    "identity_link_required"
                } else {
                    "observed"
                }
                .to_owned();
            }
            candidate.id = self
                .repository
                .save_candidate(target, resources, &candidate)
                .await?;
            seen += 1;
            if candidate.state == "identity_link_required" {
                identity_required += 1;
                continue;
            }
            for requirement in &requirements {
                let requirement_id = text(requirement.get("requirement_id"));
                let preloaded = canvas_user_id
                    .as_ref()
                    .and_then(|user| {
                        preloaded_observations.get(&(requirement_id.clone(), user.clone()))
                    })
                    .cloned();
                let observation = if let Some(observation) = preloaded {
                    Ok(observation)
                } else {
                    self.provider
                        .read_requirement(
                            resources,
                            requirement,
                            canvas_user_id.as_deref(),
                            lti_subject.as_deref(),
                        )
                        .await
                };
                match observation {
                    Ok(observation) => {
                        let observation =
                            observation.into_candidate(&text(requirement.get("source")));
                        written += usize::from(
                            self.repository
                                .save_candidate_observation(
                                    target,
                                    resources,
                                    &candidate.id,
                                    &requirement_id,
                                    &observation,
                                )
                                .await?,
                        );
                    }
                    Err(CanvasProviderReadError::RateLimited {
                        retry_after_seconds,
                    }) => {
                        return Err(CanvasSyncProcessingError::retryable(
                            "canvas_rate_limited",
                            "Canvas background evidence could not be read",
                        )
                        .with_retry_after(retry_after_seconds));
                    }
                    Err(_) => {} // Preserve the current observation head.
                }
            }
            let current = self
                .repository
                .current_candidate_observations(&target.organization_id, &candidate.id)
                .await?
                .into_iter()
                .map(|observation| (observation.requirement_id.clone(), observation))
                .collect::<BTreeMap<_, _>>();
            let allowed = requirements.iter().all(|requirement| {
                requirement.get("required").and_then(Value::as_bool) == Some(false)
                    || current
                        .get(&text(requirement.get("requirement_id")))
                        .is_some_and(|observation| observation_satisfies(requirement, observation))
            });
            if allowed && !matches!(candidate.state.as_str(), "claimed" | "dismissed") {
                candidate.state = "pending_claim".to_owned();
                candidate.id = self
                    .repository
                    .save_candidate(target, resources, &candidate)
                    .await?;
                pending += 1;
            }
        }
        let mut next_cursor = cursor + batch.len();
        if next_cursor >= inputs.len() {
            next_cursor = 0;
        }
        self.repository
            .update_roster_cursor(target, resources, next_cursor, inputs.len())
            .await?;
        Ok(Map::from_iter([
            ("candidates_seen".to_owned(), Value::from(seen)),
            ("pending_claim".to_owned(), Value::from(pending)),
            (
                "identity_link_required".to_owned(),
                Value::from(identity_required),
            ),
            ("observations_written".to_owned(), Value::from(written)),
            (
                "roster_remaining".to_owned(),
                Value::from(if next_cursor == 0 {
                    0
                } else {
                    inputs.len().saturating_sub(next_cursor)
                }),
            ),
        ]))
    }
}

#[async_trait]
impl CanvasSyncProcessor for NativeCanvasSyncProcessor {
    fn configured(&self) -> bool {
        true
    }

    async fn process(
        &self,
        target: &CanvasSyncTarget,
        lease: &CanvasSyncLease,
    ) -> Result<CanvasSyncResult, CanvasSyncProcessingError> {
        if lease.organization_id != target.organization_id
            || lease.target_id != target.id
            || lease.worker_id != self.config.worker_id
        {
            return Err(lease_lost());
        }
        let scoped = Self {
            repository: self.repository.clone().for_lease(lease.clone()),
            provider: match CanvasProviderRunScope::from_target_type(target.target_type) {
                Some(scope) => self.provider.clone().for_run(scope),
                // Preserve process_fields' rollout-before-unsupported ordering.
                // Unsupported targets never execute provider reads or create a run.
                None => self.provider.clone(),
            },
            ..self.clone()
        };
        canvas_sync_result(scoped.process_fields(target).await?)
    }
}

impl NativeCanvasSyncProcessor {
    async fn process_fields(
        &self,
        target: &CanvasSyncTarget,
    ) -> Result<Map<String, Value>, CanvasSyncProcessingError> {
        if !self.config.enabled_for(&target.organization_id) {
            return Ok(Map::from_iter([(
                "no_change".to_owned(),
                Value::Bool(true),
            )]));
        }
        if target.target_type == CanvasSyncTargetType::AwardCandidate {
            return Err(CanvasSyncProcessingError::terminal(
                "canvas_sync_target_type_unsupported",
                "Canvas target type has no authoritative processor",
            ));
        }
        if target.target_type == CanvasSyncTargetType::IssuedDrift
            && target
                .metadata
                .get("drift_until")
                .and_then(Value::as_str)
                .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
                .is_some_and(|value| value.with_timezone(&Utc) <= Utc::now())
        {
            self.repository.disable_target(target).await?;
            return Ok(Map::from_iter([
                (
                    "application_id".to_owned(),
                    target
                        .application_id
                        .clone()
                        .map_or(Value::Null, Value::String),
                ),
                ("no_change".to_owned(), Value::Bool(true)),
            ]));
        }
        let resources = self
            .repository
            .resources(target)
            .await?
            .ok_or_else(resources_unavailable)?;
        match target.target_type {
            CanvasSyncTargetType::BackgroundRoster => self.process_roster(target, &resources).await,
            CanvasSyncTargetType::LearnerApplication | CanvasSyncTargetType::IssuedDrift => {
                self.process_application(target, &resources).await
            }
            CanvasSyncTargetType::AwardCandidate => unreachable!(),
        }
    }
}

impl CanvasSyncResources {
    fn binding_id(&self) -> String {
        text(self.binding.get("id"))
    }
}

fn requirements(resources: &CanvasSyncResources) -> Result<Vec<Value>, CanvasSyncProcessingError> {
    validated_requirements(&resources.binding).map_err(|_| {
        CanvasSyncProcessingError::terminal(
            "canvas_requirements_invalid",
            "Canvas evidence requirements are invalid",
        )
    })
}

pub(crate) fn platform_reconfigured() -> CanvasSyncProcessingError {
    CanvasSyncProcessingError::retryable(
        "canvas_platform_reconfigured",
        "Canvas platform configuration changed during synchronization",
    )
}

pub(crate) fn application_unavailable() -> CanvasSyncProcessingError {
    CanvasSyncProcessingError::terminal(
        "canvas_application_unavailable",
        "Canvas application became unavailable during synchronization",
    )
}

fn resources_unavailable() -> CanvasSyncProcessingError {
    CanvasSyncProcessingError::terminal(
        "canvas_sync_resources_unavailable",
        "Canvas synchronization resources are unavailable",
    )
}

fn provider_processing_error(error: CanvasProviderReadError) -> CanvasSyncProcessingError {
    match error {
        CanvasProviderReadError::RateLimited {
            retry_after_seconds,
        } => CanvasSyncProcessingError::retryable(
            "canvas_rate_limited",
            "Canvas background evidence could not be read",
        )
        .with_retry_after(retry_after_seconds),
        CanvasProviderReadError::InvalidConfiguration => CanvasSyncProcessingError::terminal(
            "canvas_requirements_invalid",
            "Canvas evidence requirements are invalid",
        ),
        CanvasProviderReadError::RosterConfigurationInvalid => CanvasSyncProcessingError::terminal(
            "canvas_roster_configuration_invalid",
            "Canvas roster configuration is invalid",
        ),
        CanvasProviderReadError::RosterOAuthUnavailable => CanvasSyncProcessingError::retryable(
            "canvas_roster_oauth_unavailable",
            "Canvas background roster OAuth requires reauthorization",
        ),
        CanvasProviderReadError::NrpsRosterUnavailable => CanvasSyncProcessingError::retryable(
            "canvas_nrps_roster_unavailable",
            "Canvas NRPS roster URL is unavailable",
        ),
        CanvasProviderReadError::RosterCollectionTooLarge => CanvasSyncProcessingError::terminal(
            "canvas_roster_collection_too_large",
            "Canvas roster exceeds the configured complete-read limit",
        ),
        CanvasProviderReadError::RosterHttpStatusFailure => CanvasSyncProcessingError::unexpected(
            UnexpectedCanvasSyncFailure::ProviderHttpException,
        ),
        CanvasProviderReadError::Unavailable | CanvasProviderReadError::ReauthorizationRequired => {
            CanvasSyncProcessingError::retryable(
                "canvas_authoritative_read_failed",
                "Canvas background evidence could not be read",
            )
        }
    }
}

fn authoritative_fact(
    application: &CanvasSyncApplicationSnapshot,
    platform: &CanvasSyncPlatformSnapshot,
    binding: &Map<String, Value>,
    requirement: &Value,
    subject: &str,
    observation: &CanvasAuthoritativeObservation,
) -> Value {
    let requirement_id = text(requirement.get("requirement_id"));
    let source = requirement.get("source").cloned().unwrap_or(Value::Null);
    let fact_type = requirement.get("fact_type").cloned().unwrap_or(Value::Null);
    let scope = requirement
        .get("scope")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let normalized = json!({
        "requirement_id": requirement_id,
        "source": source,
        "fact_type": fact_type,
        "scope": scope,
        "assertion": observation.assertion,
        "payload": observation.source_payload,
    });
    let canonical = python_canonical_json(&normalized);
    let payload_hash = sha256_hex(canonical.as_bytes());
    let provider_event_id = Uuid::new_v5(
        &Uuid::NAMESPACE_URL,
        format!("canvas:{}:{canonical}", text(requirement.get("source"))).as_bytes(),
    )
    .to_string();
    let logical = format!(
        "{}:{}:{}:{}:{}",
        platform.id,
        text(binding.get("id")),
        application.application.id,
        requirement_id,
        subject
    );
    let observed_at = Utc::now();
    let effective_at = observation.effective_at.unwrap_or(observed_at);
    let now = observed_at.to_rfc3339_opts(SecondsFormat::AutoSi, false);
    json!({
        "id": Uuid::new_v4().to_string(),
        "organization_id": application.application.organization_id,
        "application_id": application.application.id,
        "subject_id": subject,
        "provider": "canvas",
        "fact_type": fact_type,
        "scope": scope,
        "assertion": observation.assertion,
        "verification": {"status": "VERIFIED", "method": observation.verification_method},
        "source": {"source": source, "provider_event_id": provider_event_id},
        "requirement_id": requirement_id,
        "logical_key": sha256_hex(logical.as_bytes()),
        "source_revision": payload_hash,
        "payload_hash": payload_hash,
        "observed_at": now,
        "effective_at": effective_at.to_rfc3339_opts(SecondsFormat::AutoSi, false),
        "created_at": now,
    })
}

fn candidate_key(
    platform_id: &str,
    binding_id: &str,
    canvas_user_id: Option<&str>,
    lti_subject: Option<&str>,
) -> String {
    let (namespace, identifier) = canvas_user_id
        .filter(|value| !value.trim().is_empty())
        .map_or(("lti_subject", lti_subject.unwrap_or_default()), |value| {
            ("canvas_user", value)
        });
    sha256_hex(
        format!(
            "{platform_id}:{binding_id}:{namespace}:{}",
            identifier.trim()
        )
        .as_bytes(),
    )
}

fn roster_cursor(target: &CanvasSyncTarget) -> usize {
    target
        .metadata
        .get("roster_cursor")
        .and_then(|value| match value {
            Value::Number(value) => value.as_u64(),
            Value::String(value) => value.parse().ok(),
            _ => None,
        })
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(0)
}

fn observation_satisfies(
    requirement: &Value,
    observation: &CanvasCandidateObservationSnapshot,
) -> bool {
    let rule = requirement.get("pass_rule").and_then(Value::as_object);
    if let Some(minimum) = rule
        .and_then(|rule| rule.get("min_score_percent"))
        .and_then(Value::as_f64)
    {
        return observation
            .assertion
            .get("score_percent")
            .and_then(Value::as_f64)
            .is_some_and(|score| score >= minimum);
    }
    rule.and_then(|rule| rule.get("completed"))
        .and_then(Value::as_bool)
        == Some(true)
        && observation
            .assertion
            .get("completed")
            .and_then(Value::as_bool)
            == Some(true)
}

fn sha256_hex(value: &[u8]) -> String {
    hex::encode(Sha256::digest(value))
}

fn text(value: Option<&Value>) -> String {
    value
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_owned()
}

#[allow(clippy::items_after_test_module)]
#[cfg(test)]
#[path = "canvas_sync_processor_tests.rs"]
mod tests;

pub(crate) fn rest_assertion(fact_type: &str, record: &Value) -> Map<String, Value> {
    let record = record.as_object().cloned().unwrap_or_default();
    let assignment = record.get("assignment").and_then(Value::as_object);
    let score = canvas_number(record.get("score"));
    let maximum = assignment.and_then(|value| canvas_number(value.get("points_possible")));
    let percent = score
        .zip(maximum)
        .and_then(|(score, maximum)| (maximum != 0.0).then_some(score / maximum * 100.0));
    let state = text(record.get("workflow_state").or_else(|| record.get("state"))).to_lowercase();
    let completed = match fact_type {
        "canvas.course_completion" => {
            let required = canvas_number(record.get("requirement_count")).unwrap_or(0.0) as i64;
            let completed =
                canvas_number(record.get("requirement_completed_count")).unwrap_or(0.0) as i64;
            required > 0 && completed >= required
        }
        "canvas.module_completion" => {
            state == "completed" || record.get("completed_at").is_some_and(python_truthy)
        }
        _ => {
            !record.is_empty()
                && !matches!(
                    state.as_str(),
                    "unsubmitted" | "available" | "invited" | "creation_pending"
                )
        }
    };
    Map::from_iter([
        ("completed".to_owned(), Value::Bool(completed)),
        ("score".to_owned(), score.map_or(Value::Null, Value::from)),
        (
            "score_maximum".to_owned(),
            maximum.map_or(Value::Null, Value::from),
        ),
        (
            "score_percent".to_owned(),
            percent.map_or(Value::Null, Value::from),
        ),
        (
            "provider_state".to_owned(),
            if state.is_empty() {
                Value::Null
            } else {
                Value::String(state)
            },
        ),
        (
            "requirement_count".to_owned(),
            record
                .get("requirement_count")
                .cloned()
                .unwrap_or(Value::Null),
        ),
        (
            "requirement_completed_count".to_owned(),
            record
                .get("requirement_completed_count")
                .cloned()
                .unwrap_or(Value::Null),
        ),
    ])
}

pub(crate) fn ags_assertion(record: &Value) -> Map<String, Value> {
    let record = record.as_object().cloned().unwrap_or_default();
    let score = canvas_number(record.get("resultScore"));
    let maximum = canvas_number(record.get("resultMaximum"));
    let percent = score
        .zip(maximum)
        .and_then(|(score, maximum)| (maximum != 0.0).then_some(score / maximum * 100.0));
    let status = text(record.get("resultStatus"));
    Map::from_iter([
        (
            "completed".to_owned(),
            Value::Bool(
                !record.is_empty()
                    && !matches!(status.to_lowercase().as_str(), "notready" | "failed"),
            ),
        ),
        ("score".to_owned(), score.map_or(Value::Null, Value::from)),
        (
            "score_maximum".to_owned(),
            maximum.map_or(Value::Null, Value::from),
        ),
        (
            "score_percent".to_owned(),
            percent.map_or(Value::Null, Value::from),
        ),
        (
            "result_status".to_owned(),
            if status.is_empty() {
                Value::Null
            } else {
                Value::String(status)
            },
        ),
    ])
}

pub(crate) fn normalized_rest_payload(record: &Value) -> Map<String, Value> {
    let record = record.as_object().cloned().unwrap_or_default();
    let assignment = record.get("assignment").and_then(Value::as_object);
    let mut output = Map::new();
    for key in [
        "id",
        "assignment_id",
        "score",
        "grade",
        "workflow_state",
        "state",
        "submitted_at",
        "graded_at",
        "updated_at",
        "completed_at",
        "requirement_count",
        "requirement_completed_count",
    ] {
        if let Some(value) = record.get(key).filter(|value| !value.is_null()) {
            output.insert(key.to_owned(), value.clone());
        }
    }
    if let Some(value) = assignment
        .and_then(|value| value.get("points_possible"))
        .filter(|value| !value.is_null())
    {
        output.insert("points_possible".to_owned(), value.clone());
    }
    output
}

fn canvas_number(value: Option<&Value>) -> Option<f64> {
    match value {
        Some(Value::Number(value)) => value.as_f64(),
        Some(Value::String(value)) => value.trim().parse().ok(),
        _ => None,
    }
}

fn python_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64() != Some(0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
    }
}
