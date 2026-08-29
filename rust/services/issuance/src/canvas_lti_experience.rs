use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{canvas_lti_launch::CanvasLtiClock, canvas_lti_login::random_token};

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
