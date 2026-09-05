//! Authoritative, unsigned Canvas evidence reconciliation.
//!
//! Provider I/O and persistence are ports so the same processor is exercised
//! by bounded simulators and the standalone worker. Signing/approval remain
//! outside this module by design.

use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use chrono::{DateTime, SecondsFormat, Utc};
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
}

#[async_trait]
pub trait CanvasAuthoritativeProvider: Send + Sync {
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

#[derive(Clone)]
pub struct NativeCanvasSyncProcessor {
    repository: Arc<dyn CanvasSyncProcessorRepository>,
    provider: Arc<dyn CanvasAuthoritativeProvider>,
    config: CanvasSyncWorkerConfig,
    roster_batch_size: usize,
    roster_limit: usize,
}

impl std::fmt::Debug for NativeCanvasSyncProcessor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeCanvasSyncProcessor")
            .field("roster_batch_size", &self.roster_batch_size)
            .field("roster_limit", &self.roster_limit)
            .finish_non_exhaustive()
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
        let roster_batch_size = roster_batch_size.clamp(1, 2_000);
        Self {
            repository,
            provider,
            config,
            roster_batch_size,
            roster_limit: roster_limit.clamp(roster_batch_size, 10_000),
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
            return Err(CanvasSyncProcessingError::retryable(
                "canvas_platform_reconfigured",
                "Canvas platform configuration changed during synchronization",
            ));
        }
        if !self
            .repository
            .patch_application_sync(target, resources, &checked, policy_allowed)
            .await?
        {
            return Err(CanvasSyncProcessingError::terminal(
                "canvas_application_unavailable",
                "Canvas application became unavailable during synchronization",
            ));
        }
        if let Some(retry_after_seconds) = retry_after {
            return Err(CanvasSyncProcessingError {
                code: "canvas_rate_limited",
                summary: "Canvas rate limited one or more authoritative evidence reads",
                retryable: true,
                retry_after_seconds: Some(retry_after_seconds),
            });
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
        let has_rest = requirements
            .iter()
            .any(|item| text(item.get("source")) == "canvas_rest");
        let has_ags = requirements
            .iter()
            .any(|item| text(item.get("source")) == "ags_result");
        let mixed = has_rest && has_ags;
        let roster = self
            .provider
            .roster(target, resources, &requirements, self.roster_limit)
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
            .take(self.roster_batch_size)
            .cloned()
            .collect::<Vec<_>>();
        let existing = self
            .repository
            .existing_candidates(
                &target.organization_id,
                &resources.binding_id(),
                self.roster_limit,
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
                        return Err(CanvasSyncProcessingError {
                            code: "canvas_rate_limited",
                            summary: "Canvas background evidence could not be read",
                            retryable: true,
                            retry_after_seconds: Some(retry_after_seconds),
                        });
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
        } => CanvasSyncProcessingError {
            code: "canvas_rate_limited",
            summary: "Canvas background evidence could not be read",
            retryable: true,
            retry_after_seconds: Some(retry_after_seconds),
        },
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
            "Canvas roster collection exceeds the configured bound",
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

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[test]
    fn all_four_provider_fact_projections_have_exact_assertion_semantics() {
        let assignment = rest_assertion(
            "canvas.assignment_score",
            &json!({
                "score": 8, "workflow_state": "graded", "assignment": {"points_possible": 10}
            }),
        );
        assert_eq!(assignment.get("completed"), Some(&Value::Bool(true)));
        assert_eq!(
            assignment.get("score_percent").and_then(Value::as_f64),
            Some(80.0)
        );
        let quiz = rest_assertion(
            "canvas.quiz_score",
            &json!({
                "score": 9, "workflow_state": "unsubmitted", "assignment": {"points_possible": 10}
            }),
        );
        assert_eq!(quiz.get("completed"), Some(&Value::Bool(false)));
        let module = rest_assertion("canvas.module_completion", &json!({"state": "completed"}));
        assert_eq!(module.get("completed"), Some(&Value::Bool(true)));
        let course = rest_assertion(
            "canvas.course_completion",
            &json!({
                "requirement_count": 3, "requirement_completed_count": 3
            }),
        );
        assert_eq!(course.get("completed"), Some(&Value::Bool(true)));
    }

    #[derive(Debug)]
    struct SimulatorRepository {
        resources: CanvasSyncResources,
        facts: Mutex<Vec<Value>>,
        candidates: Mutex<BTreeMap<String, CanvasRosterCandidate>>,
        observations: Mutex<BTreeMap<String, Vec<CanvasCandidateObservationSnapshot>>>,
        cursor: Mutex<Option<(usize, usize)>>,
        disabled: Mutex<bool>,
    }

    #[async_trait]
    impl CanvasSyncProcessorRepository for SimulatorRepository {
        fn for_lease(
            self: Arc<Self>,
            lease: CanvasSyncLease,
        ) -> Arc<dyn CanvasSyncProcessorRepository> {
            assert_eq!(
                lease.organization_id,
                self.resources.platform.organization_id
            );
            self
        }
        async fn resources(
            &self,
            _: &CanvasSyncTarget,
        ) -> Result<Option<CanvasSyncResources>, CanvasSyncProcessingError> {
            Ok(Some(self.resources.clone()))
        }
        async fn linked_identity_by_subject(
            &self,
            _: &str,
            _: &str,
            _: &str,
            subject: &str,
        ) -> Result<Option<CanvasLinkedIdentitySnapshot>, CanvasSyncProcessingError> {
            Ok(Some(CanvasLinkedIdentitySnapshot {
                id: "identity-1".into(),
                lti_subject: subject.into(),
                canvas_user_id: Some("42".into()),
                status: "linked".into(),
            }))
        }
        async fn linked_identity_by_canvas_user(
            &self,
            _: &str,
            _: &str,
            _: &str,
            user: &str,
        ) -> Result<Option<CanvasLinkedIdentitySnapshot>, CanvasSyncProcessingError> {
            Ok(Some(CanvasLinkedIdentitySnapshot {
                id: format!("identity-{user}"),
                lti_subject: format!("subject-{user}"),
                canvas_user_id: Some(user.into()),
                status: "linked".into(),
            }))
        }
        async fn record_fact(
            &self,
            _: &CanvasSyncTarget,
            _: &CanvasSyncResources,
            fact: &Value,
        ) -> Result<CanvasFactCommit, CanvasSyncProcessingError> {
            self.facts.lock().unwrap().push(fact.clone());
            Ok(CanvasFactCommit {
                fact_id: text(fact.get("id")),
                inserted: true,
                policy_allowed: true,
            })
        }
        async fn patch_application_sync(
            &self,
            _: &CanvasSyncTarget,
            _: &CanvasSyncResources,
            _: &[String],
            _: bool,
        ) -> Result<bool, CanvasSyncProcessingError> {
            Ok(true)
        }
        async fn patch_platform_validation(
            &self,
            _: &CanvasSyncTarget,
            _: &CanvasSyncResources,
            _: Option<&str>,
        ) -> Result<bool, CanvasSyncProcessingError> {
            Ok(true)
        }
        async fn disable_target(
            &self,
            _: &CanvasSyncTarget,
        ) -> Result<(), CanvasSyncProcessingError> {
            *self.disabled.lock().unwrap() = true;
            Ok(())
        }
        async fn existing_candidates(
            &self,
            _: &str,
            _: &str,
            _: usize,
        ) -> Result<Vec<CanvasRosterCandidate>, CanvasSyncProcessingError> {
            Ok(self.candidates.lock().unwrap().values().cloned().collect())
        }
        async fn save_candidate(
            &self,
            _: &CanvasSyncTarget,
            _: &CanvasSyncResources,
            candidate: &CanvasRosterCandidate,
        ) -> Result<String, CanvasSyncProcessingError> {
            self.candidates
                .lock()
                .unwrap()
                .insert(candidate.candidate_key.clone(), candidate.clone());
            Ok(candidate.id.clone())
        }
        async fn save_candidate_observation(
            &self,
            _: &CanvasSyncTarget,
            _: &CanvasSyncResources,
            candidate: &str,
            requirement: &str,
            observation: &CanvasAuthoritativeObservation,
        ) -> Result<bool, CanvasSyncProcessingError> {
            let mut all = self.observations.lock().unwrap();
            let current = all.entry(candidate.into()).or_default();
            current.retain(|item| item.requirement_id != requirement);
            current.push(CanvasCandidateObservationSnapshot {
                requirement_id: requirement.into(),
                assertion: observation.assertion.clone(),
            });
            Ok(true)
        }
        async fn current_candidate_observations(
            &self,
            _: &str,
            candidate: &str,
        ) -> Result<Vec<CanvasCandidateObservationSnapshot>, CanvasSyncProcessingError> {
            Ok(self
                .observations
                .lock()
                .unwrap()
                .get(candidate)
                .cloned()
                .unwrap_or_default())
        }
        async fn update_roster_cursor(
            &self,
            _: &CanvasSyncTarget,
            _: &CanvasSyncResources,
            cursor: usize,
            size: usize,
        ) -> Result<(), CanvasSyncProcessingError> {
            *self.cursor.lock().unwrap() = Some((cursor, size));
            Ok(())
        }
    }

    #[derive(Debug)]
    struct SimulatorProvider;

    #[async_trait]
    impl CanvasAuthoritativeProvider for SimulatorProvider {
        async fn read_requirement(
            &self,
            _: &CanvasSyncResources,
            requirement: &Value,
            _: Option<&str>,
            _: Option<&str>,
        ) -> Result<CanvasAuthoritativeObservation, CanvasProviderReadError> {
            let fact_type = text(requirement.get("fact_type"));
            let assertion = match fact_type.as_str() {
                "canvas.assignment_score" => rest_assertion(
                    &fact_type,
                    &json!({"score":8,"workflow_state":"graded","assignment":{"points_possible":10}}),
                ),
                "canvas.quiz_score" => ags_assertion(
                    &json!({"resultScore":9,"resultMaximum":10,"resultStatus":"FullyGraded"}),
                ),
                "canvas.module_completion" => {
                    rest_assertion(&fact_type, &json!({"state":"completed"}))
                }
                "canvas.course_completion" => rest_assertion(
                    &fact_type,
                    &json!({"requirement_count":1,"requirement_completed_count":1}),
                ),
                _ => return Err(CanvasProviderReadError::InvalidConfiguration),
            };
            Ok(CanvasAuthoritativeObservation {
                assertion,
                source_payload: Map::new(),
                verification_method: if text(requirement.get("source")) == "ags_result" {
                    "LTI_AGS_RESULT_READ"
                } else {
                    "CANVAS_OAUTH_API_READ"
                },
                effective_at: None,
            })
        }
        async fn roster(
            &self,
            _: &CanvasSyncTarget,
            _: &CanvasSyncResources,
            _: &[Value],
            _: usize,
        ) -> Result<CanvasRosterSnapshot, CanvasProviderReadError> {
            Ok(CanvasRosterSnapshot {
                canvas_user_ids: vec!["42".into(), "84".into()],
                lti_subjects: Vec::new(),
                preloaded_observations: BTreeMap::new(),
            })
        }
    }

    fn simulator_resources(requirements: Vec<Value>) -> CanvasSyncResources {
        let now = Utc::now();
        CanvasSyncResources {
            platform: CanvasSyncPlatformSnapshot {
                id: "platform-1".into(),
                organization_id: "org-1".into(),
                canvas_base_url: "https://canvas.test".into(),
                lti_trust_profile: "self_managed_same_origin".into(),
                lti_issuer: "https://canvas.test".into(),
                lti_client_id: "client".into(),
                lti_deployment_id: "deployment".into(),
                lti_auth_token_url: "https://canvas.test/login/oauth2/token".into(),
                config_version: 1,
            },
            binding: Map::from_iter([
                ("id".into(), Value::String("binding-1".into())),
                ("organization_id".into(), Value::String("org-1".into())),
                (
                    "application_template_id".into(),
                    Value::String("template-1".into()),
                ),
                ("evidence_requirements".into(), Value::Array(requirements)),
            ]),
            application: Some(CanvasSyncApplicationSnapshot {
                application: CanvasLtiBootstrapApplication {
                    id: "application-1".into(),
                    organization_id: "org-1".into(),
                    application_template_id: "template-1".into(),
                    applicant_identifier: "opaque".into(),
                    form_data: json!({}),
                    integration_context: json!({"canvas":{"lti_subject":"subject-42"}}),
                    status: "approved".into(),
                    created_at: now,
                    updated_at: now,
                },
                credential_id: Some("credential-1".into()),
            }),
            application_template: Some(Map::from_iter([
                ("id".into(), Value::String("template-1".into())),
                ("organization_id".into(), Value::String("org-1".into())),
            ])),
        }
    }

    fn requirement(
        id: &str,
        source: &str,
        fact_type: &str,
        scope: Value,
        pass_rule: Value,
    ) -> Value {
        json!({"requirement_id":id,"source":source,"fact_type":fact_type,"scope":scope,"pass_rule":pass_rule,"required":true})
    }

    fn target(kind: CanvasSyncTargetType) -> CanvasSyncTarget {
        CanvasSyncTarget {
            id: "target-1".into(),
            organization_id: "org-1".into(),
            platform_id: "platform-1".into(),
            binding_id: "binding-1".into(),
            target_type: kind,
            logical_key: "logical".into(),
            application_id: Some("application-1".into()),
            candidate_id: None,
            enabled: true,
            schedule_seconds: 900,
            config_version: 1,
            metadata: Map::new(),
            created_at: Utc::now(),
        }
    }

    async fn run_simulated(
        processor: &NativeCanvasSyncProcessor,
        target: CanvasSyncTarget,
    ) -> Result<CanvasSyncResult, CanvasSyncProcessingError> {
        let lease = CanvasSyncLease {
            job_id: "simulator-job".into(),
            organization_id: target.organization_id.clone(),
            target_id: target.id.clone(),
            worker_id: processor.config.worker_id.clone(),
            attempt_count: 1,
        };
        processor.process(&target, &lease).await
    }

    fn enabled_config() -> CanvasSyncWorkerConfig {
        CanvasSyncWorkerConfig {
            worker_id: "sim".into(),
            batch_size: 10_u64.into(),
            lease_seconds: 120_u64.into(),
            job_timeout: std::time::Duration::from_secs(600),
            schedule_limit: 100_u64.into(),
            oauth_revocation_limit: 25_u64.into(),
            poll_interval: std::time::Duration::from_secs(5),
            portable_enabled: true,
            pilot_organizations: ["org-1".to_owned()].into_iter().collect(),
        }
    }

    #[tokio::test]
    async fn executable_simulator_reconciles_all_four_facts_without_signing() {
        let requirements = vec![
            requirement(
                "assignment",
                "canvas_rest",
                "canvas.assignment_score",
                json!({"course_id":"1","activity_id":"2"}),
                json!({"min_score_percent":70}),
            ),
            requirement(
                "quiz",
                "ags_result",
                "canvas.quiz_score",
                json!({"course_id":"1","line_item_url":"https://canvas.test/lineitems/2"}),
                json!({"min_score_percent":70}),
            ),
            requirement(
                "module",
                "canvas_rest",
                "canvas.module_completion",
                json!({"course_id":"1","module_id":"3"}),
                json!({"completed":true}),
            ),
            requirement(
                "course",
                "canvas_rest",
                "canvas.course_completion",
                json!({"course_id":"1"}),
                json!({"completed":true}),
            ),
        ];
        let repository = Arc::new(SimulatorRepository {
            resources: simulator_resources(requirements),
            facts: Mutex::new(Vec::new()),
            candidates: Mutex::new(BTreeMap::new()),
            observations: Mutex::new(BTreeMap::new()),
            cursor: Mutex::new(None),
            disabled: Mutex::new(false),
        });
        let processor = NativeCanvasSyncProcessor::new(
            repository.clone(),
            Arc::new(SimulatorProvider),
            enabled_config(),
            500,
            5000,
        );
        let result = run_simulated(&processor, target(CanvasSyncTargetType::LearnerApplication))
            .await
            .unwrap();
        assert_eq!(
            result.get("requirements_checked").map(|value| value.get()),
            Some("4")
        );
        let facts = repository.facts.lock().unwrap();
        assert_eq!(facts.len(), 4);
        assert!(facts.iter().all(|fact| fact
            .get("verification")
            .and_then(|value| value.get("status"))
            .and_then(Value::as_str)
            == Some("VERIFIED")));
        assert!(facts.iter().all(|fact| fact.get("credential_id").is_none()));
    }

    #[tokio::test]
    async fn executable_simulator_bounds_roster_cursor_and_preserves_claimed_state() {
        let requirements = vec![requirement(
            "assignment",
            "canvas_rest",
            "canvas.assignment_score",
            json!({"course_id":"1","activity_id":"2"}),
            json!({"min_score_percent":70}),
        )];
        let repository = Arc::new(SimulatorRepository {
            resources: simulator_resources(requirements),
            facts: Mutex::new(Vec::new()),
            candidates: Mutex::new(BTreeMap::new()),
            observations: Mutex::new(BTreeMap::new()),
            cursor: Mutex::new(None),
            disabled: Mutex::new(false),
        });
        let claimed_key = candidate_key("platform-1", "binding-1", Some("42"), Some("subject-42"));
        repository.candidates.lock().unwrap().insert(
            claimed_key.clone(),
            CanvasRosterCandidate {
                id: "claimed".into(),
                candidate_key: claimed_key,
                canvas_user_id: Some("42".into()),
                lti_subject: Some("subject-42".into()),
                learner_identity_id: Some("identity-42".into()),
                state: "claimed".into(),
            },
        );
        let processor = NativeCanvasSyncProcessor::new(
            repository.clone(),
            Arc::new(SimulatorProvider),
            enabled_config(),
            1,
            2,
        );
        let result = run_simulated(&processor, target(CanvasSyncTargetType::BackgroundRoster))
            .await
            .unwrap();
        assert_eq!(
            result.get("candidates_seen").map(|value| value.get()),
            Some("1")
        );
        assert_eq!(*repository.cursor.lock().unwrap(), Some((1, 2)));
        assert_eq!(
            result.get("roster_remaining").map(|value| value.get()),
            Some("1")
        );
        assert!(repository
            .candidates
            .lock()
            .unwrap()
            .values()
            .any(|candidate| candidate.state == "claimed"));
        let mut next = target(CanvasSyncTargetType::BackgroundRoster);
        next.metadata.insert("roster_cursor".into(), Value::from(1));
        let result = run_simulated(&processor, next).await.unwrap();
        assert_eq!(
            result.get("roster_remaining").map(|value| value.get()),
            Some("0")
        );
        assert_eq!(*repository.cursor.lock().unwrap(), Some((0, 2)));
    }

    #[tokio::test]
    async fn expired_issued_drift_disables_without_provider_or_fact_mutation() {
        let repository = Arc::new(SimulatorRepository {
            resources: simulator_resources(vec![requirement(
                "course",
                "canvas_rest",
                "canvas.course_completion",
                json!({"course_id":"1"}),
                json!({"completed":true}),
            )]),
            facts: Mutex::new(Vec::new()),
            candidates: Mutex::new(BTreeMap::new()),
            observations: Mutex::new(BTreeMap::new()),
            cursor: Mutex::new(None),
            disabled: Mutex::new(false),
        });
        let processor = NativeCanvasSyncProcessor::new(
            repository.clone(),
            Arc::new(SimulatorProvider),
            enabled_config(),
            500,
            5000,
        );
        let mut drift = target(CanvasSyncTargetType::IssuedDrift);
        drift.metadata.insert(
            "drift_until".into(),
            Value::String("2020-01-01T00:00:00Z".into()),
        );
        let result = run_simulated(&processor, drift).await.unwrap();
        assert_eq!(
            result.get("no_change").map(|value| value.get()),
            Some("true")
        );
        assert!(*repository.disabled.lock().unwrap());
        assert!(repository.facts.lock().unwrap().is_empty());
    }

    #[test]
    fn roster_provider_failures_keep_the_frozen_retry_categories() {
        for (provider, code, retryable) in [
            (
                CanvasProviderReadError::RosterConfigurationInvalid,
                "canvas_roster_configuration_invalid",
                false,
            ),
            (
                CanvasProviderReadError::RosterOAuthUnavailable,
                "canvas_roster_oauth_unavailable",
                true,
            ),
            (
                CanvasProviderReadError::NrpsRosterUnavailable,
                "canvas_nrps_roster_unavailable",
                true,
            ),
            (
                CanvasProviderReadError::RosterCollectionTooLarge,
                "canvas_roster_collection_too_large",
                false,
            ),
        ] {
            let actual = provider_processing_error(provider);
            assert_eq!(actual.code, code);
            assert_eq!(actual.retryable, retryable, "{code}");
            assert_eq!(actual.retry_after_seconds, None, "{code}");
        }
    }
}

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
