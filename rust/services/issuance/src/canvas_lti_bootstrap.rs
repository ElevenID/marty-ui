use std::{collections::BTreeSet, fmt, sync::Arc};

use async_trait::async_trait;
use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;
use serde_json::{Map, Value};
use thiserror::Error;

use crate::canvas_lti_experience::{
    browser_safe_canvas_context, first_text, lti_subject, signed_canvas_identifier,
    CanvasLtiExperienceSessionContext, CanvasLtiExperienceSessionError,
    CanvasLtiExperienceSessionService,
};
use crate::canvas_lti_launch::CanvasLtiClock;

const PROTECTED_CALLER_FIELDS: [&str; 3] = ["canvas_subject", "canvas_course_id", "canvas_user_id"];
const REDACTED: &str = "[REDACTED]";

#[derive(Clone, Default, PartialEq)]
pub struct CanvasLtiBootstrapRequest {
    pub applicant_identifier: Option<String>,
    pub applicant_data: Map<String, Value>,
}

impl fmt::Debug for CanvasLtiBootstrapRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanvasLtiBootstrapRequest")
            .field("applicant_identifier", &REDACTED)
            .field("applicant_data", &REDACTED)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanvasLtiBootstrapApplicationSeed {
    pub id: String,
    pub anonymous_identifier_suffix: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanvasLtiBootstrapTemplate {
    pub id: String,
    pub organization_id: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanvasLtiBootstrapApplicationAction {
    Create,
    Resume,
    Replay,
}

#[derive(Clone, PartialEq)]
pub struct CanvasLtiBootstrapApplication {
    pub id: String,
    pub organization_id: String,
    pub application_template_id: String,
    pub applicant_identifier: String,
    pub form_data: Value,
    pub integration_context: Value,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl fmt::Debug for CanvasLtiBootstrapApplication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanvasLtiBootstrapApplication")
            .field("id", &self.id)
            .field("organization_id", &self.organization_id)
            .field("application_template_id", &self.application_template_id)
            .field("applicant_identifier", &REDACTED)
            .field("form_data", &REDACTED)
            .field("integration_context", &REDACTED)
            .field("status", &self.status)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CanvasLtiBootstrapResponse {
    pub application_id: String,
    pub application_status: String,
    pub created: bool,
    pub organization_id: String,
    pub application_template_id: String,
    pub credential_template_id: Option<String>,
    pub canvas_account_id: String,
    pub canvas_platform_id: Option<String>,
    pub canvas_program_binding_id: Option<String>,
    pub canvas_context: Value,
}

#[derive(Clone, PartialEq)]
pub struct CanvasLtiBootstrapPlan {
    pub application: CanvasLtiBootstrapApplication,
    pub application_action: CanvasLtiBootstrapApplicationAction,
    pub created: bool,
    pub session_metadata: Value,
    pub bootstrap_event_metadata: Option<Value>,
    pub materialize_award_candidate: bool,
    pub enqueue_canvas_sync: bool,
    pub response: CanvasLtiBootstrapResponse,
}

impl fmt::Debug for CanvasLtiBootstrapPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanvasLtiBootstrapPlan")
            .field("application", &self.application)
            .field("application_action", &self.application_action)
            .field("created", &self.created)
            .field("session_metadata", &REDACTED)
            .field("bootstrap_event_metadata", &REDACTED)
            .field(
                "materialize_award_candidate",
                &self.materialize_award_candidate,
            )
            .field("enqueue_canvas_sync", &self.enqueue_canvas_sync)
            .field("response", &REDACTED)
            .finish()
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CanvasLtiBootstrapPlanError {
    #[error("Canvas LTI is disabled for this deployment profile")]
    FeatureDisabled,
    #[error("Portable Canvas integration is not enabled for this organization")]
    PilotDisabled,
    #[error("Canvas LTI session is not bound to an application template")]
    MissingApplicationTemplate,
    #[error("Bound application template not found")]
    ApplicationTemplateNotFound,
    #[error("Canvas LTI application template belongs to a different organization")]
    CrossOrganizationTemplate,
    #[error("Canvas LTI experience session not found")]
    InvalidSession,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CanvasLtiBootstrapRepositoryError {
    #[error("Canvas LTI bootstrap repository is unavailable")]
    Unavailable,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("Canvas LTI sync enqueue is unavailable")]
pub struct CanvasLtiBootstrapSyncError;

#[async_trait]
pub trait CanvasLtiBootstrapRepository: Send + Sync {
    async fn bound_feature_enabled(
        &self,
        organization_id: &str,
        binding_id: &str,
        flag: &str,
    ) -> Result<Option<bool>, CanvasLtiBootstrapRepositoryError>;

    async fn get_template(
        &self,
        template_id: &str,
    ) -> Result<Option<CanvasLtiBootstrapTemplate>, CanvasLtiBootstrapRepositoryError>;

    async fn list_applications(
        &self,
        organization_id: &str,
        template_id: &str,
    ) -> Result<Vec<CanvasLtiBootstrapApplication>, CanvasLtiBootstrapRepositoryError>;

    async fn persist_plan(
        &self,
        context: &CanvasLtiExperienceSessionContext,
        plan: &CanvasLtiBootstrapPlan,
    ) -> Result<(), CanvasLtiBootstrapRepositoryError>;

    async fn get_application(
        &self,
        application_id: &str,
    ) -> Result<Option<CanvasLtiBootstrapApplication>, CanvasLtiBootstrapRepositoryError>;
}

#[async_trait]
pub trait CanvasLtiAwardCandidateMaterializer: Send + Sync {
    async fn materialize(
        &self,
        context: &CanvasLtiExperienceSessionContext,
        application: &CanvasLtiBootstrapApplication,
    ) -> Result<(), CanvasLtiBootstrapRepositoryError>;
}

#[async_trait]
pub trait CanvasLtiBootstrapSyncEnqueuer: Send + Sync {
    async fn enqueue(
        &self,
        organization_id: &str,
        application_id: &str,
    ) -> Result<(), CanvasLtiBootstrapSyncError>;
}

pub trait CanvasLtiBootstrapApplicationGenerator: Send + Sync {
    fn generate(&self, anonymous_identifier_required: bool) -> CanvasLtiBootstrapApplicationSeed;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SecureCanvasLtiBootstrapApplicationGenerator;

impl CanvasLtiBootstrapApplicationGenerator for SecureCanvasLtiBootstrapApplicationGenerator {
    fn generate(&self, anonymous_identifier_required: bool) -> CanvasLtiBootstrapApplicationSeed {
        CanvasLtiBootstrapApplicationSeed {
            id: uuid::Uuid::new_v4().to_string(),
            anonymous_identifier_suffix: if anonymous_identifier_required {
                uuid::Uuid::new_v4()
                    .simple()
                    .to_string()
                    .chars()
                    .take(8)
                    .collect()
            } else {
                String::new()
            },
        }
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CanvasLtiBootstrapServiceError {
    #[error("Canvas LTI experience session not found")]
    SessionNotFound,
    #[error(transparent)]
    Plan(#[from] CanvasLtiBootstrapPlanError),
    #[error("Canvas LTI bootstrap is temporarily unavailable")]
    RepositoryUnavailable,
}

#[derive(Clone)]
pub struct CanvasLtiBootstrapService {
    session_service: CanvasLtiExperienceSessionService,
    repository: Arc<dyn CanvasLtiBootstrapRepository>,
    candidate_materializer: Arc<dyn CanvasLtiAwardCandidateMaterializer>,
    sync_enqueuer: Arc<dyn CanvasLtiBootstrapSyncEnqueuer>,
    application_generator: Arc<dyn CanvasLtiBootstrapApplicationGenerator>,
    clock: Arc<dyn CanvasLtiClock>,
    portable_enabled: bool,
    pilot_organizations: BTreeSet<String>,
}

impl std::fmt::Debug for CanvasLtiBootstrapService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CanvasLtiBootstrapService")
            .field("portable_enabled", &self.portable_enabled)
            .field("pilot_organizations", &self.pilot_organizations)
            .finish_non_exhaustive()
    }
}

impl CanvasLtiBootstrapService {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        session_service: CanvasLtiExperienceSessionService,
        repository: Arc<dyn CanvasLtiBootstrapRepository>,
        candidate_materializer: Arc<dyn CanvasLtiAwardCandidateMaterializer>,
        sync_enqueuer: Arc<dyn CanvasLtiBootstrapSyncEnqueuer>,
        application_generator: Arc<dyn CanvasLtiBootstrapApplicationGenerator>,
        clock: Arc<dyn CanvasLtiClock>,
        portable_enabled: bool,
        pilot_organizations: BTreeSet<String>,
    ) -> Self {
        Self {
            session_service,
            repository,
            candidate_materializer,
            sync_enqueuer,
            application_generator,
            clock,
            portable_enabled,
            pilot_organizations,
        }
    }

    pub async fn bootstrap(
        &self,
        session_token: &str,
        request: &CanvasLtiBootstrapRequest,
    ) -> Result<CanvasLtiBootstrapResponse, CanvasLtiBootstrapServiceError> {
        let context = self
            .session_service
            .load(session_token)
            .await
            .map_err(session_error)?;
        let bound_feature_enabled =
            if let Some(binding_id) = context.canvas_program_binding_id.as_deref() {
                self.repository
                    .bound_feature_enabled(
                        &context.launch_state.organization_id,
                        binding_id,
                        "enable_canvas_lti",
                    )
                    .await
                    .map_err(repository_error)?
            } else {
                None
            };
        if bound_feature_enabled == Some(false) {
            return Err(CanvasLtiBootstrapPlanError::FeatureDisabled.into());
        }
        let pilot_enabled = self.portable_enabled
            && !context.launch_state.organization_id.trim().is_empty()
            && self
                .pilot_organizations
                .contains(context.launch_state.organization_id.trim());
        if !pilot_enabled {
            return Err(CanvasLtiBootstrapPlanError::PilotDisabled.into());
        }
        let template_id = context
            .application_template_id
            .as_deref()
            .filter(|value| !value.is_empty())
            .ok_or(CanvasLtiBootstrapPlanError::MissingApplicationTemplate)?;
        let template = self
            .repository
            .get_template(template_id)
            .await
            .map_err(repository_error)?;
        let existing = self
            .repository
            .list_applications(&context.launch_state.organization_id, template_id)
            .await
            .map_err(repository_error)?;
        let plan = plan_canvas_lti_experience_bootstrap(
            &context,
            request,
            true,
            bound_feature_enabled,
            template.as_ref(),
            &existing,
            |anonymous_identifier_required| {
                self.application_generator
                    .generate(anonymous_identifier_required)
            },
            self.clock.now(),
        )?;
        self.repository
            .persist_plan(&context, &plan)
            .await
            .map_err(repository_error)?;
        if plan.materialize_award_candidate {
            self.candidate_materializer
                .materialize(&context, &plan.application)
                .await
                .map_err(repository_error)?;
        }
        let application = self
            .repository
            .get_application(&plan.application.id)
            .await
            .map_err(repository_error)?
            .unwrap_or(plan.application);
        if plan.enqueue_canvas_sync {
            if let Err(cause) = self
                .sync_enqueuer
                .enqueue(&application.organization_id, &application.id)
                .await
            {
                tracing::warn!(%cause, application_id = %application.id, "Canvas bootstrap sync enqueue deferred");
            }
        }
        Ok(canvas_lti_bootstrap_response(
            &context,
            &application,
            plan.created,
        ))
    }
}

fn session_error(cause: CanvasLtiExperienceSessionError) -> CanvasLtiBootstrapServiceError {
    match cause {
        CanvasLtiExperienceSessionError::NotFound => {
            CanvasLtiBootstrapServiceError::SessionNotFound
        }
        CanvasLtiExperienceSessionError::RepositoryUnavailable => {
            CanvasLtiBootstrapServiceError::RepositoryUnavailable
        }
    }
}

fn repository_error(_cause: CanvasLtiBootstrapRepositoryError) -> CanvasLtiBootstrapServiceError {
    CanvasLtiBootstrapServiceError::RepositoryUnavailable
}

#[allow(clippy::too_many_arguments)]
pub fn plan_canvas_lti_experience_bootstrap<F>(
    context: &CanvasLtiExperienceSessionContext,
    request: &CanvasLtiBootstrapRequest,
    portable_pilot_enabled: bool,
    bound_feature_enabled: Option<bool>,
    template: Option<&CanvasLtiBootstrapTemplate>,
    existing_applications: &[CanvasLtiBootstrapApplication],
    new_application: F,
    now: DateTime<Utc>,
) -> Result<CanvasLtiBootstrapPlan, CanvasLtiBootstrapPlanError>
where
    F: FnOnce(bool) -> CanvasLtiBootstrapApplicationSeed,
{
    if context.canvas_program_binding_id.is_some() && bound_feature_enabled == Some(false) {
        return Err(CanvasLtiBootstrapPlanError::FeatureDisabled);
    }
    if !portable_pilot_enabled {
        return Err(CanvasLtiBootstrapPlanError::PilotDisabled);
    }
    let application_template_id = context
        .application_template_id
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or(CanvasLtiBootstrapPlanError::MissingApplicationTemplate)?;
    let template = template.ok_or(CanvasLtiBootstrapPlanError::ApplicationTemplateNotFound)?;
    if template.id != application_template_id {
        return Err(CanvasLtiBootstrapPlanError::ApplicationTemplateNotFound);
    }
    if template.organization_id != context.launch_state.organization_id {
        return Err(CanvasLtiBootstrapPlanError::CrossOrganizationTemplate);
    }

    let mut applications = existing_applications.to_vec();
    applications.sort_by_key(|application| std::cmp::Reverse(application.created_at));
    let subject = lti_subject(&context.verified_launch);
    let mut application_action = CanvasLtiBootstrapApplicationAction::Replay;
    let mut event_metadata = None;
    let application = if let Some(application) = applications.iter().find(|application| {
        canvas_application_context(application)
            .get("lti_state")
            .and_then(Value::as_str)
            == Some(context.state.as_str())
    }) {
        application.clone()
    } else if let Some(application) = applications.iter().find(|application| {
        !matches!(application.status.as_str(), "rejected" | "withdrawn")
            && application_matches_subject(application, context, subject.as_deref())
    }) {
        application_action = CanvasLtiBootstrapApplicationAction::Resume;
        resume_subject_application(application, context, now)
    } else {
        application_action = CanvasLtiBootstrapApplicationAction::Create;
        let seed = new_application(subject.is_none());
        let application = create_application(context, request, template, &seed, now);
        event_metadata = Some(bootstrap_event_metadata(context, &application, subject));
        application
    };
    let created = application_action == CanvasLtiBootstrapApplicationAction::Create;
    let session_metadata = attach_application_to_session(context, &application.id, created, now)?;
    let response = canvas_lti_bootstrap_response(context, &application, created);
    Ok(CanvasLtiBootstrapPlan {
        application,
        application_action,
        created,
        session_metadata,
        bootstrap_event_metadata: event_metadata,
        materialize_award_candidate: true,
        enqueue_canvas_sync: true,
        response,
    })
}

fn create_application(
    context: &CanvasLtiExperienceSessionContext,
    request: &CanvasLtiBootstrapRequest,
    template: &CanvasLtiBootstrapTemplate,
    seed: &CanvasLtiBootstrapApplicationSeed,
    now: DateTime<Utc>,
) -> CanvasLtiBootstrapApplication {
    let subject = lti_subject(&context.verified_launch);
    let applicant_identifier = subject.as_ref().map_or_else(
        || format!("canvas_lti_{}", seed.anonymous_identifier_suffix),
        |subject| format!("canvas_lti:{subject}"),
    );
    CanvasLtiBootstrapApplication {
        id: seed.id.clone(),
        organization_id: template.organization_id.clone(),
        application_template_id: template.id.clone(),
        applicant_identifier,
        form_data: Value::Object(application_form_data(context, request)),
        integration_context: Value::Object(Map::from_iter([
            (
                "canvas".to_owned(),
                Value::Object(application_canvas_context(context)),
            ),
            (
                "delivery_mode".to_owned(),
                Value::String(context.delivery_mode.clone()),
            ),
            (
                "delivery".to_owned(),
                Value::Object(Map::from_iter([(
                    "mode".to_owned(),
                    Value::String(context.delivery_mode.clone()),
                )])),
            ),
        ])),
        status: "pending".to_owned(),
        created_at: now,
        updated_at: now,
    }
}

fn application_form_data(
    context: &CanvasLtiExperienceSessionContext,
    request: &CanvasLtiBootstrapRequest,
) -> Map<String, Value> {
    let verified = &context.verified_launch;
    let empty = Map::new();
    let learner = verified
        .get("learner_identity")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let raw_claims = verified
        .get("raw_claims")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let canvas_context = verified
        .get("context")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let mut form_data = request
        .applicant_data
        .iter()
        .filter(|(name, _)| !PROTECTED_CALLER_FIELDS.contains(&name.as_str()))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect::<Map<_, _>>();
    let trusted = [
        (
            "email",
            first_truthy_value([learner.get("email"), raw_claims.get("email")]),
        ),
        (
            "given_name",
            first_truthy_value([learner.get("given_name"), raw_claims.get("given_name")]),
        ),
        (
            "family_name",
            first_truthy_value([learner.get("family_name"), raw_claims.get("family_name")]),
        ),
        (
            "name",
            first_truthy_value([learner.get("name"), raw_claims.get("name")]),
        ),
        ("canvas_subject", lti_subject(verified).map(Value::String)),
        (
            "canvas_course_id",
            signed_canvas_identifier(verified, "canvas_course_id")
                .or_else(|| {
                    first_text([canvas_context.get("id"), canvas_context.get("context_id")])
                })
                .map(Value::String),
        ),
        (
            "canvas_course_name",
            first_truthy_value([canvas_context.get("title"), canvas_context.get("label")]),
        ),
    ];
    for (name, value) in trusted {
        if let Some(value) = value {
            form_data.insert(name.to_owned(), value);
        } else {
            form_data.remove(name);
        }
    }
    form_data
}

fn application_canvas_context(context: &CanvasLtiExperienceSessionContext) -> Map<String, Value> {
    let verified = &context.verified_launch;
    let empty = Map::new();
    let canvas_context = verified
        .get("context")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let learner = verified
        .get("learner_identity")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let roles = verified
        .get("roles")
        .cloned()
        .filter(crate::canvas_lti_experience::python_truthy)
        .unwrap_or_else(|| Value::Array(Vec::new()));
    let course_id = signed_canvas_identifier(verified, "canvas_course_id")
        .or_else(|| first_text([canvas_context.get("id"), canvas_context.get("context_id")]));
    Map::from_iter([
        (
            "source".to_owned(),
            Value::String("canvas_lti_bootstrap".to_owned()),
        ),
        ("lti_state".to_owned(), Value::String(context.state.clone())),
        (
            "last_lti_state".to_owned(),
            Value::String(context.state.clone()),
        ),
        (
            "lti_states".to_owned(),
            Value::Array(vec![Value::String(context.state.clone())]),
        ),
        (
            "canvas_account_id".to_owned(),
            Value::String(context.launch_state.canvas_account_id.clone()),
        ),
        (
            "canvas_platform_id".to_owned(),
            Value::String(context.canvas_platform_id.clone()),
        ),
        (
            "canvas_program_binding_id".to_owned(),
            optional_string(&context.canvas_program_binding_id),
        ),
        (
            "deployment_profile_id".to_owned(),
            optional_string(&context.deployment_profile_id),
        ),
        ("feature_flags".to_owned(), context.feature_flags.clone()),
        (
            "application_template_id".to_owned(),
            optional_string(&context.application_template_id),
        ),
        (
            "credential_template_id".to_owned(),
            optional_string(&context.credential_template_id),
        ),
        (
            "delivery_mode".to_owned(),
            Value::String(context.delivery_mode.clone()),
        ),
        (
            "canvas_course_id".to_owned(),
            course_id.map_or(Value::Null, Value::String),
        ),
        (
            "canvas_context".to_owned(),
            Value::Object(canvas_context.clone()),
        ),
        (
            "lti_subject".to_owned(),
            lti_subject(verified).map_or(Value::Null, Value::String),
        ),
        (
            "canvas_user_id".to_owned(),
            signed_canvas_identifier(verified, "canvas_user_id").map_or(Value::Null, Value::String),
        ),
        ("learner_identity".to_owned(), Value::Object(learner)),
        ("roles".to_owned(), roles),
        (
            "launch_url".to_owned(),
            optional_string(&context.launch_url),
        ),
        (
            "lti_capabilities".to_owned(),
            context.lti_capabilities.clone(),
        ),
    ])
}

fn resume_subject_application(
    application: &CanvasLtiBootstrapApplication,
    context: &CanvasLtiExperienceSessionContext,
    now: DateTime<Utc>,
) -> CanvasLtiBootstrapApplication {
    let mut application = application.clone();
    let mut integration = application
        .integration_context
        .as_object()
        .cloned()
        .unwrap_or_default();
    let mut canvas = integration
        .get("canvas")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let mut states = canvas
        .get("lti_states")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let state = Value::String(context.state.clone());
    if !states.contains(&state) {
        states.push(state.clone());
    }
    if states.len() > 10 {
        states = states.split_off(states.len() - 10);
    }
    canvas.insert("last_lti_state".to_owned(), state);
    canvas.insert("lti_states".to_owned(), Value::Array(states));
    canvas.insert(
        "deployment_profile_id".to_owned(),
        optional_string(&context.deployment_profile_id),
    );
    let feature_flags = if crate::canvas_lti_experience::python_truthy(&context.feature_flags) {
        context.feature_flags.clone()
    } else {
        canvas
            .get("feature_flags")
            .cloned()
            .filter(crate::canvas_lti_experience::python_truthy)
            .unwrap_or_else(|| Value::Object(Map::new()))
    };
    canvas.insert("feature_flags".to_owned(), feature_flags);
    canvas.insert(
        "delivery_mode".to_owned(),
        Value::String(context.delivery_mode.clone()),
    );
    integration.insert("canvas".to_owned(), Value::Object(canvas));
    integration.insert(
        "delivery_mode".to_owned(),
        Value::String(context.delivery_mode.clone()),
    );
    let mut delivery = integration
        .get("delivery")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    delivery.insert(
        "mode".to_owned(),
        Value::String(context.delivery_mode.clone()),
    );
    integration.insert("delivery".to_owned(), Value::Object(delivery));
    application.integration_context = Value::Object(integration);
    application.updated_at = now;
    application
}

fn application_matches_subject(
    application: &CanvasLtiBootstrapApplication,
    context: &CanvasLtiExperienceSessionContext,
    subject: Option<&str>,
) -> bool {
    let Some(subject) = subject else { return false };
    let canvas = canvas_application_context(application);
    let binding_matches = match context.canvas_program_binding_id.as_deref() {
        Some(binding_id) => {
            canvas
                .get("canvas_program_binding_id")
                .and_then(Value::as_str)
                == Some(binding_id)
        }
        None => canvas
            .get("canvas_program_binding_id")
            .is_none_or(Value::is_null),
    };
    binding_matches
        && canvas
            .get("lti_subject")
            .and_then(crate::canvas_lti_experience::python_string)
            .unwrap_or_default()
            == subject
}

fn canvas_application_context(application: &CanvasLtiBootstrapApplication) -> Map<String, Value> {
    application
        .integration_context
        .get("canvas")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default()
}

fn attach_application_to_session(
    context: &CanvasLtiExperienceSessionContext,
    application_id: &str,
    created: bool,
    now: DateTime<Utc>,
) -> Result<Value, CanvasLtiBootstrapPlanError> {
    let mut metadata = context
        .launch_state
        .metadata
        .as_object()
        .cloned()
        .ok_or(CanvasLtiBootstrapPlanError::InvalidSession)?;
    let mut verified = context.verified_launch.clone();
    verified.insert(
        "application_id".to_owned(),
        Value::String(application_id.to_owned()),
    );
    let mut mip = context.mip_primitives.clone();
    let mut mip_context = mip
        .get("context")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    mip_context.insert(
        "application_id".to_owned(),
        Value::String(application_id.to_owned()),
    );
    mip.insert("context".to_owned(), Value::Object(mip_context));
    metadata.insert("verified_launch".to_owned(), Value::Object(verified));
    metadata.insert("mip_primitives".to_owned(), Value::Object(mip));
    metadata.insert(
        "application_bootstrap".to_owned(),
        Value::Object(Map::from_iter([
            (
                "application_id".to_owned(),
                Value::String(application_id.to_owned()),
            ),
            ("created".to_owned(), Value::Bool(created)),
            (
                "bootstrapped_at".to_owned(),
                Value::String(now.to_rfc3339_opts(SecondsFormat::AutoSi, false)),
            ),
        ])),
    );
    Ok(Value::Object(metadata))
}

fn bootstrap_event_metadata(
    context: &CanvasLtiExperienceSessionContext,
    application: &CanvasLtiBootstrapApplication,
    subject: Option<String>,
) -> Value {
    Value::Object(Map::from_iter([
        (
            "organization_id".to_owned(),
            Value::String(application.organization_id.clone()),
        ),
        (
            "source".to_owned(),
            Value::String("canvas_lti_experience".to_owned()),
        ),
        ("state".to_owned(), Value::String(context.state.clone())),
        (
            "canvas_account_id".to_owned(),
            Value::String(context.launch_state.canvas_account_id.clone()),
        ),
        (
            "canvas_platform_id".to_owned(),
            Value::String(context.canvas_platform_id.clone()),
        ),
        (
            "canvas_program_binding_id".to_owned(),
            optional_string(&context.canvas_program_binding_id),
        ),
        (
            "application_template_id".to_owned(),
            Value::String(application.application_template_id.clone()),
        ),
        (
            "credential_template_id".to_owned(),
            optional_string(&context.credential_template_id),
        ),
        (
            "subject".to_owned(),
            subject.map_or(Value::Null, Value::String),
        ),
    ]))
}

pub fn canvas_lti_bootstrap_response(
    context: &CanvasLtiExperienceSessionContext,
    application: &CanvasLtiBootstrapApplication,
    created: bool,
) -> CanvasLtiBootstrapResponse {
    let mut canvas_context = browser_safe_canvas_context(&context.verified_launch)
        .as_object()
        .cloned()
        .unwrap_or_default();
    canvas_context.insert(
        "identity_mapping_status".to_owned(),
        context
            .verified_launch
            .get("identity_mapping_status")
            .cloned()
            .unwrap_or(Value::Null),
    );
    CanvasLtiBootstrapResponse {
        application_id: application.id.clone(),
        application_status: application.status.clone(),
        created,
        organization_id: application.organization_id.clone(),
        application_template_id: application.application_template_id.clone(),
        credential_template_id: context.credential_template_id.clone(),
        canvas_account_id: context.launch_state.canvas_account_id.clone(),
        canvas_platform_id: Some(context.canvas_platform_id.clone()),
        canvas_program_binding_id: context.canvas_program_binding_id.clone(),
        canvas_context: Value::Object(canvas_context),
    }
}

fn first_truthy_value<const N: usize>(values: [Option<&Value>; N]) -> Option<Value> {
    values
        .into_iter()
        .flatten()
        .find(|value| crate::canvas_lti_experience::python_truthy(value))
        .cloned()
}

fn optional_string(value: &Option<String>) -> Value {
    value.clone().map_or(Value::Null, Value::String)
}
