use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Duration, TimeZone, Utc};
use rand::RngCore;
use redis::{aio::ConnectionManager, AsyncCommands, Script};
use thiserror::Error;
use tokio::sync::Mutex;

use crate::{
    SessionStatus, SubmissionOutcome, SubmissionTransition, VerificationSession,
    SESSION_TTL_SECONDS, SUBMISSION_CAS_RETRIES, SUBMISSION_LEASE_SECONDS,
};

const SESSION_PREFIX: &str = "verification:session:";
const SAVE: &str = r#"
redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
redis.call('SADD', KEYS[2], ARGV[3])
redis.call('EXPIRE', KEYS[2], ARGV[2])
return 1
"#;
const CAS_KEEP_TTL: &str = r#"
local current = redis.call('GET', KEYS[1])
if not current or current ~= ARGV[1] then return 0 end
local ttl = redis.call('PTTL', KEYS[1])
if ttl >= 0 then
  redis.call('SET', KEYS[1], ARGV[2], 'PX', ttl)
else
  redis.call('SET', KEYS[1], ARGV[2], 'EX', ARGV[3])
end
return 1
"#;
const CAS_RESET_TTL: &str = r#"
local current = redis.call('GET', KEYS[1])
if not current or current ~= ARGV[1] then return 0 end
redis.call('SET', KEYS[1], ARGV[2], 'EX', ARGV[3])
return 1
"#;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum StoreError {
    #[error("verification session persistence unavailable")]
    Unavailable,
    #[error("verification session record is invalid")]
    InvalidRecord,
    #[error("terminal session changed immutable verification state")]
    ImmutableState,
    #[error("terminal session must contain a completed outcome")]
    InvalidTerminalState,
}

#[async_trait]
pub trait SessionStore: Send + Sync {
    async fn save(&self, session: VerificationSession) -> Result<(), StoreError>;
    async fn get(&self, session_id: &str) -> Result<Option<VerificationSession>, StoreError>;
    async fn list_by_org(
        &self,
        organization_id: &str,
        status: Option<&str>,
    ) -> Result<Vec<VerificationSession>, StoreError>;
    async fn claim_submission(
        &self,
        session_id: &str,
        digest: &str,
    ) -> Result<SubmissionTransition, StoreError>;
    async fn finalize_submission(
        &self,
        session_id: &str,
        digest: &str,
        token: &str,
        candidate: VerificationSession,
    ) -> Result<SubmissionTransition, StoreError>;
}

#[derive(Clone, Debug, Default)]
pub struct MemorySessionStore {
    sessions: Arc<Mutex<BTreeMap<String, VerificationSession>>>,
}

impl MemorySessionStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn get_at(
        &self,
        session_id: &str,
        now: DateTime<Utc>,
    ) -> Option<VerificationSession> {
        self.sessions
            .lock()
            .await
            .get(session_id)
            .cloned()
            .map(|session| project_expiry(session, now))
    }

    pub async fn claim_at(
        &self,
        session_id: &str,
        digest: &str,
        now: DateTime<Utc>,
    ) -> SubmissionTransition {
        let mut sessions = self.sessions.lock().await;
        let Some(stored) = sessions.get(session_id).cloned() else {
            return SubmissionTransition::new(SubmissionOutcome::Missing);
        };
        let mut session = stored;
        if let Some(outcome) = submission_state(&session, digest, now) {
            if outcome == SubmissionOutcome::Expired {
                expire_session(&mut session, now);
                sessions.insert(session_id.into(), session.clone());
            }
            return transition(outcome, session, None);
        }
        let token = random_token(32);
        session.vp_token_sha256 = Some(digest.into());
        session.processing_token = Some(token.clone());
        session.processing_expires_at = Some(now + Duration::seconds(SUBMISSION_LEASE_SECONDS));
        session.updated_at = now;
        sessions.insert(session_id.into(), session.clone());
        transition(SubmissionOutcome::Claimed, session, Some(token))
    }

    pub async fn finalize_at(
        &self,
        session_id: &str,
        digest: &str,
        token: &str,
        candidate: VerificationSession,
    ) -> Result<SubmissionTransition, StoreError> {
        let mut sessions = self.sessions.lock().await;
        let Some(current) = sessions.get(session_id).cloned() else {
            return Ok(SubmissionTransition::new(SubmissionOutcome::Missing));
        };
        if current.status != SessionStatus::Pending {
            return Ok(transition(
                if current.vp_token_sha256.as_deref() == Some(digest) {
                    SubmissionOutcome::Duplicate
                } else {
                    SubmissionOutcome::Conflict
                },
                current,
                None,
            ));
        }
        if current.vp_token_sha256.as_deref() != Some(digest) {
            return Ok(transition(SubmissionOutcome::Conflict, current, None));
        }
        if current.processing_token.as_deref() != Some(token) {
            return Ok(transition(SubmissionOutcome::Busy, current, None));
        }
        validate_terminal_candidate(&current, &candidate)?;
        let mut terminal = candidate;
        terminal.vp_token_sha256 = Some(digest.into());
        terminal.processing_token = None;
        terminal.processing_expires_at = None;
        terminal.minimize_terminal();
        sessions.insert(session_id.into(), terminal.clone());
        Ok(transition(SubmissionOutcome::Committed, terminal, None))
    }
}

#[async_trait]
impl SessionStore for MemorySessionStore {
    async fn save(&self, mut session: VerificationSession) -> Result<(), StoreError> {
        session.minimize_terminal();
        self.sessions
            .lock()
            .await
            .insert(session.session_id.clone(), session);
        Ok(())
    }

    async fn get(&self, session_id: &str) -> Result<Option<VerificationSession>, StoreError> {
        Ok(self.get_at(session_id, Utc::now()).await)
    }

    async fn list_by_org(
        &self,
        organization_id: &str,
        status: Option<&str>,
    ) -> Result<Vec<VerificationSession>, StoreError> {
        let mut sessions = self
            .sessions
            .lock()
            .await
            .values()
            .filter(|session| session.organization_id == organization_id)
            .filter(|session| status.is_none_or(|status| status_name(session.status) == status))
            .cloned()
            .collect::<Vec<_>>();
        sessions.sort_by_key(|session| std::cmp::Reverse(session.created_at));
        Ok(sessions)
    }

    async fn claim_submission(
        &self,
        session_id: &str,
        digest: &str,
    ) -> Result<SubmissionTransition, StoreError> {
        Ok(self.claim_at(session_id, digest, Utc::now()).await)
    }

    async fn finalize_submission(
        &self,
        session_id: &str,
        digest: &str,
        token: &str,
        candidate: VerificationSession,
    ) -> Result<SubmissionTransition, StoreError> {
        self.finalize_at(session_id, digest, token, candidate).await
    }
}

#[derive(Clone)]
pub struct RedisSessionStore {
    connection: ConnectionManager,
}

impl std::fmt::Debug for RedisSessionStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RedisSessionStore")
            .finish_non_exhaustive()
    }
}

impl RedisSessionStore {
    pub async fn connect(url: &str) -> Result<Self, StoreError> {
        if url.trim().is_empty() {
            return Err(StoreError::Unavailable);
        }
        let client = redis::Client::open(url).map_err(|_| StoreError::Unavailable)?;
        let mut connection = ConnectionManager::new(client)
            .await
            .map_err(|_| StoreError::Unavailable)?;
        let pong: String = redis::cmd("PING")
            .query_async(&mut connection)
            .await
            .map_err(|_| StoreError::Unavailable)?;
        if pong != "PONG" {
            return Err(StoreError::Unavailable);
        }
        Ok(Self { connection })
    }

    async fn raw(&self, session_id: &str) -> Result<Option<String>, StoreError> {
        let mut connection = self.connection.clone();
        connection
            .get(session_key(session_id))
            .await
            .map_err(|_| StoreError::Unavailable)
    }

    async fn server_time(&self) -> Result<DateTime<Utc>, StoreError> {
        let mut connection = self.connection.clone();
        let (seconds, microseconds): (i64, i64) = redis::cmd("TIME")
            .query_async(&mut connection)
            .await
            .map_err(|_| StoreError::Unavailable)?;
        Utc.timestamp_opt(
            seconds,
            u32::try_from(microseconds).map_err(|_| StoreError::InvalidRecord)? * 1_000,
        )
        .single()
        .ok_or(StoreError::InvalidRecord)
    }

    async fn cas(
        &self,
        session_id: &str,
        expected: &str,
        replacement: &str,
        reset_ttl: bool,
    ) -> Result<bool, StoreError> {
        let mut connection = self.connection.clone();
        let script = if reset_ttl {
            CAS_RESET_TTL
        } else {
            CAS_KEEP_TTL
        };
        let changed: i64 = Script::new(script)
            .key(session_key(session_id))
            .arg(expected)
            .arg(replacement)
            .arg(SESSION_TTL_SECONDS)
            .invoke_async(&mut connection)
            .await
            .map_err(|_| StoreError::Unavailable)?;
        Ok(changed == 1)
    }
}

#[async_trait]
impl SessionStore for RedisSessionStore {
    async fn save(&self, mut session: VerificationSession) -> Result<(), StoreError> {
        session.minimize_terminal();
        let encoded = encode(&session)?;
        let mut connection = self.connection.clone();
        Script::new(SAVE)
            .key(session_key(&session.session_id))
            .key(organization_key(&session.organization_id))
            .arg(encoded)
            .arg(SESSION_TTL_SECONDS)
            .arg(&session.session_id)
            .invoke_async::<i64>(&mut connection)
            .await
            .map_err(|_| StoreError::Unavailable)?;
        Ok(())
    }

    async fn get(&self, session_id: &str) -> Result<Option<VerificationSession>, StoreError> {
        let Some(raw) = self.raw(session_id).await? else {
            return Ok(None);
        };
        let mut session = decode(&raw)?;
        let canonical = encode(&session)?;
        if canonical != raw && self.cas(session_id, &raw, &canonical, false).await? {
            session = decode(&canonical)?;
        }
        if session.status == SessionStatus::Pending && session.vp_token_sha256.is_none() {
            session = project_expiry(session, self.server_time().await?);
        }
        Ok(Some(session))
    }

    async fn list_by_org(
        &self,
        organization_id: &str,
        status: Option<&str>,
    ) -> Result<Vec<VerificationSession>, StoreError> {
        let mut connection = self.connection.clone();
        let ids: Vec<String> = connection
            .smembers(organization_key(organization_id))
            .await
            .map_err(|_| StoreError::Unavailable)?;
        let mut sessions = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(session) = self.get(&id).await? {
                if status.is_none_or(|status| status_name(session.status) == status) {
                    sessions.push(session);
                }
            }
        }
        sessions.sort_by_key(|session| std::cmp::Reverse(session.created_at));
        Ok(sessions)
    }

    async fn claim_submission(
        &self,
        session_id: &str,
        digest: &str,
    ) -> Result<SubmissionTransition, StoreError> {
        for _ in 0..SUBMISSION_CAS_RETRIES {
            let Some(raw) = self.raw(session_id).await? else {
                return Ok(SubmissionTransition::new(SubmissionOutcome::Missing));
            };
            let mut session = decode(&raw)?;
            let now = self.server_time().await?;
            if let Some(outcome) = submission_state(&session, digest, now) {
                if outcome == SubmissionOutcome::Expired {
                    expire_session(&mut session, now);
                    if !self
                        .cas(session_id, &raw, &encode(&session)?, false)
                        .await?
                    {
                        continue;
                    }
                }
                return Ok(transition(outcome, session, None));
            }
            let token = random_token(32);
            session.vp_token_sha256 = Some(digest.into());
            session.processing_token = Some(token.clone());
            session.processing_expires_at = Some(now + Duration::seconds(SUBMISSION_LEASE_SECONDS));
            session.updated_at = now;
            if self
                .cas(session_id, &raw, &encode(&session)?, false)
                .await?
            {
                return Ok(transition(SubmissionOutcome::Claimed, session, Some(token)));
            }
        }
        Err(StoreError::Unavailable)
    }

    async fn finalize_submission(
        &self,
        session_id: &str,
        digest: &str,
        token: &str,
        candidate: VerificationSession,
    ) -> Result<SubmissionTransition, StoreError> {
        for _ in 0..SUBMISSION_CAS_RETRIES {
            let Some(raw) = self.raw(session_id).await? else {
                return Ok(SubmissionTransition::new(SubmissionOutcome::Missing));
            };
            let current = decode(&raw)?;
            if current.status != SessionStatus::Pending {
                return Ok(transition(
                    if current.vp_token_sha256.as_deref() == Some(digest) {
                        SubmissionOutcome::Duplicate
                    } else {
                        SubmissionOutcome::Conflict
                    },
                    current,
                    None,
                ));
            }
            if current.vp_token_sha256.as_deref() != Some(digest) {
                return Ok(transition(SubmissionOutcome::Conflict, current, None));
            }
            if current.processing_token.as_deref() != Some(token) {
                return Ok(transition(SubmissionOutcome::Busy, current, None));
            }
            validate_terminal_candidate(&current, &candidate)?;
            let mut terminal = candidate.clone();
            terminal.vp_token_sha256 = Some(digest.into());
            terminal.processing_token = None;
            terminal.processing_expires_at = None;
            terminal.minimize_terminal();
            if self
                .cas(session_id, &raw, &encode(&terminal)?, true)
                .await?
            {
                return Ok(transition(SubmissionOutcome::Committed, terminal, None));
            }
        }
        Err(StoreError::Unavailable)
    }
}

fn session_key(session_id: &str) -> String {
    format!("{SESSION_PREFIX}{session_id}")
}

fn organization_key(organization_id: &str) -> String {
    format!("{SESSION_PREFIX}org:{organization_id}")
}

fn encode(session: &VerificationSession) -> Result<String, StoreError> {
    serde_json::to_string(session).map_err(|_| StoreError::InvalidRecord)
}

fn decode(raw: &str) -> Result<VerificationSession, StoreError> {
    let mut session: VerificationSession =
        serde_json::from_str(raw).map_err(|_| StoreError::InvalidRecord)?;
    session.callback_url = None;
    session.minimize_terminal();
    Ok(session)
}

fn project_expiry(mut session: VerificationSession, now: DateTime<Utc>) -> VerificationSession {
    if session.status == SessionStatus::Pending
        && session.vp_token_sha256.is_none()
        && session.is_expired_at(now)
    {
        expire_session(&mut session, now);
    }
    session
}

fn submission_state(
    session: &VerificationSession,
    digest: &str,
    now: DateTime<Utc>,
) -> Option<SubmissionOutcome> {
    if session.status == SessionStatus::Expired {
        return Some(SubmissionOutcome::Expired);
    }
    if session.status != SessionStatus::Pending {
        return Some(if session.vp_token_sha256.as_deref() == Some(digest) {
            SubmissionOutcome::Duplicate
        } else {
            SubmissionOutcome::Conflict
        });
    }
    if session
        .vp_token_sha256
        .as_deref()
        .is_some_and(|existing| existing != digest)
    {
        return Some(SubmissionOutcome::Conflict);
    }
    if session.processing_token.is_some()
        && session
            .processing_expires_at
            .is_some_and(|expires_at| expires_at > now)
    {
        return Some(SubmissionOutcome::Busy);
    }
    if session.vp_token_sha256.as_deref() == Some(digest) {
        return None;
    }
    session
        .is_expired_at(now)
        .then_some(SubmissionOutcome::Expired)
}

fn expire_session(session: &mut VerificationSession, now: DateTime<Utc>) {
    session.status = SessionStatus::Expired;
    session.error = Some("Session expired before presentation was submitted".into());
    session.updated_at = now;
    session.processing_token = None;
    session.processing_expires_at = None;
}

fn validate_terminal_candidate(
    current: &VerificationSession,
    candidate: &VerificationSession,
) -> Result<(), StoreError> {
    let immutable = current.session_id == candidate.session_id
        && current.flow_id == candidate.flow_id
        && current.flow_instance_id == candidate.flow_instance_id
        && current.organization_id == candidate.organization_id
        && current.presentation_policy_id == candidate.presentation_policy_id
        && current.response_type == candidate.response_type
        && current.nonce == candidate.nonce
        && current.created_at == candidate.created_at
        && current.expires_at == candidate.expires_at;
    if !immutable {
        return Err(StoreError::ImmutableState);
    }
    if candidate.status == SessionStatus::Pending || candidate.completed_at.is_none() {
        return Err(StoreError::InvalidTerminalState);
    }
    Ok(())
}

fn transition(
    outcome: SubmissionOutcome,
    session: VerificationSession,
    token: Option<String>,
) -> SubmissionTransition {
    SubmissionTransition {
        outcome,
        session: Some(session),
        token,
    }
}

fn random_token(bytes: usize) -> String {
    let mut value = vec![0_u8; bytes];
    rand::rng().fill_bytes(&mut value);
    URL_SAFE_NO_PAD.encode(value)
}

const fn status_name(status: SessionStatus) -> &'static str {
    match status {
        SessionStatus::Pending => "pending",
        SessionStatus::Completed => "completed",
        SessionStatus::Expired => "expired",
        SessionStatus::Failed => "failed",
    }
}
