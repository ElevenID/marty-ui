use std::{collections::BTreeSet, sync::Arc, time::Duration};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    canvas_lti_launch::{
        CanvasLtiClock, CanvasLtiLaunchPlanError, CanvasLtiLaunchStateRepository,
        CanvasLtiStoredLaunchState,
    },
    canvas_lti_login::random_token,
};

#[derive(Clone, Eq, PartialEq)]
pub struct CanvasLtiExperienceSessionSeed {
    pub id: String,
    pub token: String,
    pub state_digest: String,
    pub nonce: String,
}

impl std::fmt::Debug for CanvasLtiExperienceSessionSeed {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CanvasLtiExperienceSessionSeed")
            .field("id", &self.id)
            .field("token", &"[REDACTED]")
            .field("state_digest", &self.state_digest)
            .field("nonce", &"[REDACTED]")
            .finish()
    }
}

pub trait CanvasLtiExperienceSessionGenerator: Send + Sync {
    fn generate(&self) -> CanvasLtiExperienceSessionSeed;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SecureCanvasLtiExperienceSessionGenerator;

impl CanvasLtiExperienceSessionGenerator for SecureCanvasLtiExperienceSessionGenerator {
    fn generate(&self) -> CanvasLtiExperienceSessionSeed {
        let token = random_token();
        CanvasLtiExperienceSessionSeed {
            id: uuid::Uuid::new_v4().to_string(),
            state_digest: sha256_hex(&token),
            token,
            nonce: random_token(),
        }
    }
}

#[derive(Clone, PartialEq)]
pub struct CanvasLtiExperienceExchangePersistence {
    pub code: String,
    pub session_ttl: Duration,
}

impl std::fmt::Debug for CanvasLtiExperienceExchangePersistence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CanvasLtiExperienceExchangePersistence")
            .field("code", &"[REDACTED]")
            .field("session_ttl", &self.session_ttl)
            .finish()
    }
}

#[derive(Clone, PartialEq)]
pub struct CanvasLtiExperienceExchangeRecord {
    pub experience_code_id: String,
    pub session: CanvasLtiExperienceSessionSeed,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub session_metadata: Value,
    pub spent_code_metadata: Value,
}

impl std::fmt::Debug for CanvasLtiExperienceExchangeRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CanvasLtiExperienceExchangeRecord")
            .field("experience_code_id", &self.experience_code_id)
            .field("session", &self.session)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

#[async_trait]
pub trait CanvasLtiExperienceExchangeRepository: Send + Sync {
    async fn exchange_experience_code(
        &self,
        request: &CanvasLtiExperienceExchangePersistence,
        generator: &dyn CanvasLtiExperienceSessionGenerator,
        clock: &dyn CanvasLtiClock,
    ) -> Result<CanvasLtiExperienceExchangeRecord, CanvasLtiExperienceExchangeError>;
}

#[derive(Clone, Eq, PartialEq)]
pub struct CanvasLtiExperienceExchangeResult {
    pub session_token: String,
    pub expires_at: DateTime<Utc>,
}

impl std::fmt::Debug for CanvasLtiExperienceExchangeResult {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CanvasLtiExperienceExchangeResult")
            .field("session_token", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CanvasLtiExperienceExchangeError {
    #[error("Canvas LTI experience code has expired, is invalid, or was already used")]
    InvalidCode,
    #[error("Canvas LTI experience exchange is temporarily unavailable")]
    RepositoryUnavailable,
    #[error("Canvas LTI experience exchange configuration is invalid")]
    InvalidConfiguration,
}

#[derive(Clone)]
pub struct CanvasLtiExperienceExchangeService {
    repository: Arc<dyn CanvasLtiExperienceExchangeRepository>,
    generator: Arc<dyn CanvasLtiExperienceSessionGenerator>,
    clock: Arc<dyn CanvasLtiClock>,
    session_ttl: Duration,
}

impl std::fmt::Debug for CanvasLtiExperienceExchangeService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CanvasLtiExperienceExchangeService")
            .field("session_ttl", &self.session_ttl)
            .finish_non_exhaustive()
    }
}

impl CanvasLtiExperienceExchangeService {
    pub fn new(
        repository: Arc<dyn CanvasLtiExperienceExchangeRepository>,
        generator: Arc<dyn CanvasLtiExperienceSessionGenerator>,
        clock: Arc<dyn CanvasLtiClock>,
        session_ttl: Duration,
    ) -> Result<Self, CanvasLtiExperienceExchangeError> {
        if session_ttl.is_zero() || chrono::Duration::from_std(session_ttl).is_err() {
            return Err(CanvasLtiExperienceExchangeError::InvalidConfiguration);
        }
        Ok(Self {
            repository,
            generator,
            clock,
            session_ttl,
        })
    }

    pub async fn exchange(
        &self,
        code: &str,
    ) -> Result<CanvasLtiExperienceExchangeResult, CanvasLtiExperienceExchangeError> {
        let code = code.trim();
        if !(32..=256).contains(&code.chars().count()) {
            return Err(CanvasLtiExperienceExchangeError::InvalidCode);
        }
        let record = self
            .repository
            .exchange_experience_code(
                &CanvasLtiExperienceExchangePersistence {
                    code: code.to_owned(),
                    session_ttl: self.session_ttl,
                },
                self.generator.as_ref(),
                self.clock.as_ref(),
            )
            .await?;
        validate_session(&record.session)?;
        Ok(CanvasLtiExperienceExchangeResult {
            session_token: record.session.token,
            expires_at: record.expires_at,
        })
    }
}

pub(crate) fn generate_valid_session(
    generator: &dyn CanvasLtiExperienceSessionGenerator,
) -> Result<CanvasLtiExperienceSessionSeed, CanvasLtiExperienceExchangeError> {
    let session = generator.generate();
    validate_session(&session)?;
    Ok(session)
}

fn validate_session(
    session: &CanvasLtiExperienceSessionSeed,
) -> Result<(), CanvasLtiExperienceExchangeError> {
    if session.id.trim().is_empty()
        || session.token.trim().is_empty()
        || session.nonce.trim().is_empty()
        || session.state_digest != sha256_hex(&session.token)
    {
        return Err(CanvasLtiExperienceExchangeError::InvalidConfiguration);
    }
    Ok(())
}

#[must_use]
pub fn canvas_lti_experience_exchange_metadata(
    code_metadata: &Value,
    experience_code_id: &str,
    session_id: &str,
    session_created_at: DateTime<Utc>,
) -> (Value, Value) {
    let mut session_metadata = code_metadata.as_object().cloned().unwrap_or_default();
    session_metadata.insert(
        "kind".to_owned(),
        Value::String("canvas_lti_experience_session".to_owned()),
    );
    session_metadata.insert(
        "experience_code_id".to_owned(),
        Value::String(experience_code_id.to_owned()),
    );
    session_metadata.insert(
        "session_created_at".to_owned(),
        Value::String(session_created_at.to_rfc3339()),
    );
    let spent_code_metadata = Map::from_iter([
        (
            "kind".to_owned(),
            Value::String("canvas_lti_experience_code_consumed".to_owned()),
        ),
        (
            "launch_state".to_owned(),
            code_metadata
                .get("launch_state")
                .cloned()
                .unwrap_or(Value::Null),
        ),
        (
            "session_id".to_owned(),
            Value::String(session_id.to_owned()),
        ),
        (
            "exchanged_at".to_owned(),
            Value::String(session_created_at.to_rfc3339()),
        ),
    ]);
    (
        Value::Object(session_metadata),
        Value::Object(spent_code_metadata),
    )
}

#[must_use]
pub fn sha256_hex(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CanvasLtiExperienceSessionResponse {
    pub organization_id: String,
    pub canvas_account_id: String,
    pub canvas_platform_id: String,
    pub canvas_program_binding_id: Option<String>,
    pub application_template_id: Option<String>,
    pub credential_template_id: Option<String>,
    pub status: String,
    pub application_id: Option<String>,
    pub lti_capabilities: Value,
    pub canvas_context: Value,
    pub roles: Vec<String>,
    pub learner_display_name: Option<String>,
    pub learner_key: String,
    pub identity_mapping_status: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CanvasLtiExperienceSessionContext {
    pub launch_state: CanvasLtiStoredLaunchState,
    pub verified_launch: Map<String, Value>,
    pub mip_primitives: Map<String, Value>,
    pub state: String,
    pub canvas_platform_id: String,
    pub canvas_program_binding_id: Option<String>,
    pub application_template_id: Option<String>,
    pub credential_template_id: Option<String>,
    pub delivery_mode: String,
    pub deployment_profile_id: Option<String>,
    pub feature_flags: Value,
    pub launch_url: Option<String>,
    pub application_id: Option<String>,
    pub lti_capabilities: Value,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CanvasLtiExperienceSessionError {
    #[error("Canvas LTI experience session not found")]
    NotFound,
    #[error("Canvas LTI experience session is temporarily unavailable")]
    RepositoryUnavailable,
}

#[derive(Clone)]
pub struct CanvasLtiExperienceSessionService {
    repository: Arc<dyn CanvasLtiLaunchStateRepository>,
}

impl std::fmt::Debug for CanvasLtiExperienceSessionService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CanvasLtiExperienceSessionService")
            .finish_non_exhaustive()
    }
}

impl CanvasLtiExperienceSessionService {
    #[must_use]
    pub fn new(repository: Arc<dyn CanvasLtiLaunchStateRepository>) -> Self {
        Self { repository }
    }

    pub async fn current(
        &self,
        session_token: &str,
    ) -> Result<CanvasLtiExperienceSessionResponse, CanvasLtiExperienceSessionError> {
        let context = self.load(session_token).await?;
        Ok(canvas_lti_experience_session_response(&context))
    }

    pub async fn load(
        &self,
        session_token: &str,
    ) -> Result<CanvasLtiExperienceSessionContext, CanvasLtiExperienceSessionError> {
        let session_token = session_token.trim();
        if session_token.is_empty() {
            return Err(CanvasLtiExperienceSessionError::NotFound);
        }
        let session = self
            .repository
            .get_launch_state(&sha256_hex(session_token))
            .await
            .map_err(session_repository_error)?
            .ok_or(CanvasLtiExperienceSessionError::NotFound)?;
        canvas_lti_experience_session_context(session)
    }
}

pub fn canvas_lti_experience_session_projection(
    session: &CanvasLtiStoredLaunchState,
) -> Result<CanvasLtiExperienceSessionResponse, CanvasLtiExperienceSessionError> {
    let context = canvas_lti_experience_session_context(session.clone())?;
    Ok(canvas_lti_experience_session_response(&context))
}

pub fn canvas_lti_experience_session_context(
    session: CanvasLtiStoredLaunchState,
) -> Result<CanvasLtiExperienceSessionContext, CanvasLtiExperienceSessionError> {
    let metadata = session
        .metadata
        .as_object()
        .ok_or(CanvasLtiExperienceSessionError::NotFound)?;
    let verified = metadata
        .get("verified_launch")
        .and_then(Value::as_object)
        .ok_or(CanvasLtiExperienceSessionError::NotFound)?;
    let mip = metadata
        .get("mip_primitives")
        .and_then(Value::as_object)
        .ok_or(CanvasLtiExperienceSessionError::NotFound)?;
    if session.status != "session"
        || session.expired
        || metadata.get("kind").and_then(Value::as_str) != Some("canvas_lti_experience_session")
    {
        return Err(CanvasLtiExperienceSessionError::NotFound);
    }
    let empty = Map::new();
    let mip_context = mip
        .get("context")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let canvas_platform_id = first_text([
        mip_context.get("canvas_platform_id"),
        verified.get("canvas_platform_id"),
        Some(&Value::String(session.platform_id.clone())),
    ])
    .unwrap_or_default();
    let state = first_text([metadata.get("launch_state")]).unwrap_or_else(|| session.id.clone());
    let canvas_program_binding_id = first_text([
        mip_context.get("canvas_program_binding_id"),
        verified.get("canvas_program_binding_id"),
    ]);
    let application_template_id = first_text([
        mip_context.get("application_template_id"),
        verified.get("application_template_id"),
    ]);
    let credential_template_id = first_text([
        mip_context.get("credential_template_id"),
        verified.get("credential_template_id"),
    ]);
    let delivery_mode = first_text([
        mip_context.get("delivery_mode"),
        verified.get("delivery_mode"),
    ])
    .unwrap_or_else(|| "wallet_only".to_owned());
    let deployment_profile_id = first_text([
        mip_context.get("deployment_profile_id"),
        verified.get("deployment_profile_id"),
    ]);
    let feature_flags = first_truthy([
        mip_context.get("feature_flags"),
        verified.get("feature_flags"),
    ])
    .cloned()
    .unwrap_or_else(|| Value::Object(Map::new()));
    let launch_url = first_text([metadata.get("launch_url")]);
    let application_id = first_text([
        mip_context.get("application_id"),
        verified.get("application_id"),
    ]);
    let lti_capabilities = first_truthy([
        mip_context.get("lti_capabilities"),
        verified.get("lti_capabilities"),
    ])
    .cloned()
    .unwrap_or_else(|| Value::Object(Map::new()));
    Ok(CanvasLtiExperienceSessionContext {
        verified_launch: verified.clone(),
        mip_primitives: mip.clone(),
        launch_state: session,
        state,
        canvas_platform_id,
        canvas_program_binding_id,
        application_template_id,
        credential_template_id,
        delivery_mode,
        deployment_profile_id,
        feature_flags,
        launch_url,
        application_id,
        lti_capabilities,
    })
}

fn canvas_lti_experience_session_response(
    context: &CanvasLtiExperienceSessionContext,
) -> CanvasLtiExperienceSessionResponse {
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
    let learner_subject = first_python_text([
        verified.get("subject"),
        learner.get("subject"),
        raw_claims.get("sub"),
    ])
    .unwrap_or_default();
    let deployment_id = first_python_text([verified.get("deployment_id")]).unwrap_or_default();
    let learner_key = sha256_hex(&format!(
        "{}:{deployment_id}:{learner_subject}",
        context.canvas_platform_id
    ));
    let capabilities = context.lti_capabilities.as_object().unwrap_or(&empty);
    let lti_capabilities = Value::Object(Map::from_iter(
        [
            "resource_link",
            "deep_linking",
            "assignment_grade_services",
            "names_roles",
        ]
        .into_iter()
        .map(|name| {
            (
                name.to_owned(),
                Value::Bool(capabilities.get(name).is_some_and(python_truthy)),
            )
        }),
    ));
    let canvas_context = browser_safe_canvas_context(verified);
    let roles = verified
        .get("roles")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(python_string)
        .map(|role| {
            role.trim_end_matches('/').rsplit_once('/').map_or_else(
                || role.trim_end_matches('/').to_owned(),
                |(_, value)| value.to_owned(),
            )
        })
        .collect();
    let learner_display_name = learner
        .get("name")
        .filter(|value| python_truthy(value))
        .and_then(python_string)
        .map(|name| name.trim().to_owned())
        .filter(|name| !name.is_empty());
    CanvasLtiExperienceSessionResponse {
        organization_id: context.launch_state.organization_id.clone(),
        canvas_account_id: context.launch_state.canvas_account_id.clone(),
        canvas_platform_id: context.canvas_platform_id.clone(),
        canvas_program_binding_id: context.canvas_program_binding_id.clone(),
        application_template_id: context.application_template_id.clone(),
        credential_template_id: context.credential_template_id.clone(),
        status: context.launch_state.status.clone(),
        application_id: context.application_id.clone(),
        lti_capabilities,
        canvas_context,
        roles,
        learner_display_name,
        learner_key,
        identity_mapping_status: first_text([verified.get("identity_mapping_status")]),
    }
}

pub(crate) fn browser_safe_canvas_context(verified: &Map<String, Value>) -> Value {
    let empty = Map::new();
    let context = verified
        .get("context")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let mut result = Map::new();
    if let Some(course_id) = signed_canvas_identifier(verified, "canvas_course_id")
        .or_else(|| first_text([context.get("id"), context.get("context_id")]))
    {
        result.insert("course_id".to_owned(), Value::String(course_id));
    }
    for name in ["title", "label"] {
        if let Some(value) = context.get(name).filter(|value| {
            !value.is_null() && python_string(value).is_some_and(|value| !value.trim().is_empty())
        }) {
            result.insert(name.to_owned(), value.clone());
        }
    }
    Value::Object(result)
}

pub(crate) fn first_text<const N: usize>(values: [Option<&Value>; N]) -> Option<String> {
    values
        .into_iter()
        .flatten()
        .filter(|value| python_truthy(value))
        .find_map(Value::as_str)
        .map(str::to_owned)
}

pub(crate) fn first_python_text<const N: usize>(values: [Option<&Value>; N]) -> Option<String> {
    values
        .into_iter()
        .flatten()
        .filter(|value| python_truthy(value))
        .find_map(python_string)
        .filter(|value| !value.trim().is_empty())
}

pub(crate) fn first_truthy<const N: usize>(values: [Option<&Value>; N]) -> Option<&Value> {
    values
        .into_iter()
        .flatten()
        .find(|value| python_truthy(value))
}

pub(crate) use crate::python_value::{python_string, python_truthy};

pub(crate) fn portable_canvas_pilot_enabled(
    enabled: bool,
    pilot_organizations: &BTreeSet<String>,
    organization_id: &str,
) -> bool {
    enabled
        && !organization_id.trim().is_empty()
        && pilot_organizations.contains(organization_id.trim())
}

pub(crate) fn lti_subject(verified: &Map<String, Value>) -> Option<String> {
    let empty = Map::new();
    let learner = verified
        .get("learner_identity")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let raw_claims = verified
        .get("raw_claims")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    first_python_text([
        verified.get("subject"),
        learner.get("subject"),
        raw_claims.get("sub"),
    ])
}

pub(crate) fn signed_canvas_identifier(
    verified: &Map<String, Value>,
    name: &str,
) -> Option<String> {
    let raw_claims = verified.get("raw_claims")?.as_object()?;
    let custom = raw_claims
        .get("https://purl.imsglobal.org/spec/lti/claim/custom")
        .and_then(Value::as_object)
        .or_else(|| raw_claims.get("custom").and_then(Value::as_object))?;
    custom
        .get(name)
        .and_then(python_string)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn session_repository_error(_cause: CanvasLtiLaunchPlanError) -> CanvasLtiExperienceSessionError {
    CanvasLtiExperienceSessionError::RepositoryUnavailable
}
