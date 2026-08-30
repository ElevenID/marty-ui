use std::{collections::BTreeSet, sync::Arc, time::Duration};

use async_trait::async_trait;
use serde_json::{Map, Value};
use thiserror::Error;

use crate::{
    canvas_award_candidate::{
        plan_selected_canvas_award_candidate_materialization, select_canvas_award_candidate,
        CanvasAwardCandidate, CanvasAwardCandidateMaterializationPlan, CanvasCandidateObservation,
        CanvasIdentityJoin, CanvasLinkedIdentity,
    },
    canvas_lti_bootstrap::{
        CanvasLtiAwardCandidateMaterializer, CanvasLtiBootstrapApplication,
        CanvasLtiBootstrapRepositoryError,
    },
    canvas_lti_experience::CanvasLtiExperienceSessionContext,
    canvas_lti_launch::CanvasLtiClock,
};

#[derive(Clone, Debug)]
pub struct CanvasAwardCandidateMaterializerConfig {
    pub enabled: bool,
    pub pilot_organizations: BTreeSet<String>,
    pub evidence_max_age: Duration,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CanvasAwardCandidateSnapshot {
    pub binding: Map<String, Value>,
    pub application_template: Map<String, Value>,
    pub candidates: Vec<CanvasAwardCandidate>,
    pub identity_by_subject: Option<CanvasLinkedIdentity>,
    pub identity_by_canvas_user: Option<CanvasLinkedIdentity>,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CanvasAwardCandidateRepositoryError {
    #[error("Canvas award candidate repository is temporarily unavailable")]
    Unavailable,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CanvasAwardCandidateApprovalError {
    #[error("Canvas award approval readiness changed")]
    ReadinessDrift,
    #[error("Canvas award approval is temporarily unavailable")]
    Unavailable,
}

#[async_trait]
pub trait CanvasAwardCandidateRepository: Send + Sync {
    async fn load_snapshot(
        &self,
        context: &CanvasLtiExperienceSessionContext,
        application: &CanvasLtiBootstrapApplication,
    ) -> Result<Option<CanvasAwardCandidateSnapshot>, CanvasAwardCandidateRepositoryError>;

    async fn current_observations(
        &self,
        organization_id: &str,
        candidate_id: &str,
    ) -> Result<Vec<CanvasCandidateObservation>, CanvasAwardCandidateRepositoryError>;

    async fn record_fact_and_evaluate_policy(
        &self,
        application: &CanvasLtiBootstrapApplication,
        binding: &Map<String, Value>,
        application_template: &Map<String, Value>,
        fact: &Value,
    ) -> Result<bool, CanvasAwardCandidateRepositoryError>;

    async fn link_candidate(
        &self,
        application: &CanvasLtiBootstrapApplication,
        plan: &CanvasAwardCandidateMaterializationPlan,
    ) -> Result<(), CanvasAwardCandidateRepositoryError>;
}

#[async_trait]
pub trait CanvasAwardCandidateApprover: Send + Sync {
    async fn approve_if_ready(
        &self,
        context: &CanvasLtiExperienceSessionContext,
        application: &CanvasLtiBootstrapApplication,
        plan: &CanvasAwardCandidateMaterializationPlan,
        policy_allowed: bool,
    ) -> Result<(), CanvasAwardCandidateApprovalError>;
}

pub trait CanvasEvidenceFactIdGenerator: Send + Sync {
    fn generate(&self) -> String;
}

#[derive(Clone, Debug, Default)]
pub struct UuidCanvasEvidenceFactIdGenerator;

impl CanvasEvidenceFactIdGenerator for UuidCanvasEvidenceFactIdGenerator {
    fn generate(&self) -> String {
        uuid::Uuid::new_v4().to_string()
    }
}

#[derive(Clone)]
pub struct CanvasAwardCandidateMaterializerService {
    repository: Arc<dyn CanvasAwardCandidateRepository>,
    approver: Arc<dyn CanvasAwardCandidateApprover>,
    fact_ids: Arc<dyn CanvasEvidenceFactIdGenerator>,
    clock: Arc<dyn CanvasLtiClock>,
    config: CanvasAwardCandidateMaterializerConfig,
}

impl std::fmt::Debug for CanvasAwardCandidateMaterializerService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CanvasAwardCandidateMaterializerService")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl CanvasAwardCandidateMaterializerService {
    #[must_use]
    pub fn new(
        repository: Arc<dyn CanvasAwardCandidateRepository>,
        approver: Arc<dyn CanvasAwardCandidateApprover>,
        fact_ids: Arc<dyn CanvasEvidenceFactIdGenerator>,
        clock: Arc<dyn CanvasLtiClock>,
        config: CanvasAwardCandidateMaterializerConfig,
    ) -> Self {
        Self {
            repository,
            approver,
            fact_ids,
            clock,
            config,
        }
    }

    pub async fn materialize_candidate(
        &self,
        context: &CanvasLtiExperienceSessionContext,
        application: &CanvasLtiBootstrapApplication,
    ) -> Result<(), CanvasAwardCandidateRepositoryError> {
        if !self.config.enabled
            || !self
                .config
                .pilot_organizations
                .contains(&application.organization_id)
        {
            return Ok(());
        }
        let Some(snapshot) = self.repository.load_snapshot(context, application).await? else {
            return Ok(());
        };
        let Some(selection) = select_canvas_award_candidate(
            context,
            application,
            &snapshot.candidates,
            CanvasIdentityJoin {
                by_subject: snapshot.identity_by_subject.as_ref(),
                by_canvas_user: snapshot.identity_by_canvas_user.as_ref(),
            },
        ) else {
            return Ok(());
        };
        let observations = self
            .repository
            .current_observations(&application.organization_id, &selection.candidate.id)
            .await?;
        let now = self.clock.now();
        let Some(plan) = plan_selected_canvas_award_candidate_materialization(
            context,
            application,
            &snapshot.binding,
            &selection,
            &observations,
            now,
            self.config.evidence_max_age,
            || self.fact_ids.generate(),
        ) else {
            return Ok(());
        };
        let mut policy_allowed = false;
        for fact in &plan.facts {
            policy_allowed = self
                .repository
                .record_fact_and_evaluate_policy(
                    application,
                    &snapshot.binding,
                    &snapshot.application_template,
                    fact,
                )
                .await?;
        }
        self.repository.link_candidate(application, &plan).await?;
        match self
            .approver
            .approve_if_ready(context, application, &plan, policy_allowed)
            .await
        {
            Ok(()) | Err(CanvasAwardCandidateApprovalError::ReadinessDrift) => Ok(()),
            Err(CanvasAwardCandidateApprovalError::Unavailable) => {
                Err(CanvasAwardCandidateRepositoryError::Unavailable)
            }
        }
    }
}

#[async_trait]
impl CanvasLtiAwardCandidateMaterializer for CanvasAwardCandidateMaterializerService {
    async fn materialize(
        &self,
        context: &CanvasLtiExperienceSessionContext,
        application: &CanvasLtiBootstrapApplication,
    ) -> Result<(), CanvasLtiBootstrapRepositoryError> {
        self.materialize_candidate(context, application)
            .await
            .map_err(|_| CanvasLtiBootstrapRepositoryError::Unavailable)
    }
}
