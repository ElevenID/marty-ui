use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use mmf_data::CacheStore;

use crate::{PkceState, PkceStateRepository, PortError, Session, SessionRepository};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthCacheKeySpace {
    pub session_prefix: String,
    pub user_sessions_prefix: String,
    pub pkce_prefix: String,
    pub pkce_ttl_seconds: u64,
    pub user_session_ttl_buffer_seconds: u64,
}

impl Default for AuthCacheKeySpace {
    fn default() -> Self {
        Self {
            session_prefix: "session:".to_owned(),
            user_sessions_prefix: "user_sessions:".to_owned(),
            pkce_prefix: "pkce:".to_owned(),
            pkce_ttl_seconds: 600,
            user_session_ttl_buffer_seconds: 3_600,
        }
    }
}

#[derive(Clone)]
pub struct AuthCacheRepository {
    cache: Arc<dyn CacheStore>,
    keys: AuthCacheKeySpace,
}

impl AuthCacheRepository {
    #[must_use]
    pub fn new(cache: Arc<dyn CacheStore>, keys: AuthCacheKeySpace) -> Self {
        Self { cache, keys }
    }

    fn session_key(&self, session_id: &str) -> String {
        format!("{}{session_id}", self.keys.session_prefix)
    }

    fn user_sessions_key(&self, user_id: &str) -> String {
        format!("{}{user_id}", self.keys.user_sessions_prefix)
    }

    fn pkce_key(&self, state: &str) -> String {
        format!("{}{state}", self.keys.pkce_prefix)
    }

    fn now_ms() -> u64 {
        u64::try_from(Utc::now().timestamp_millis()).unwrap_or_default()
    }

    fn data_error(operation: &str, error: impl std::fmt::Display) -> PortError {
        PortError::new(
            "auth_cache_operation_failed",
            format!("{operation}: {error}"),
        )
    }

    fn decode_session(bytes: &[u8]) -> Result<Session, PortError> {
        serde_json::from_slice(bytes).map_err(|error| {
            PortError::new(
                "invalid_cached_session",
                format!("cached session is malformed: {error}"),
            )
        })
    }

    async fn remove_user_session_reference(
        &self,
        user_id: &str,
        session_id: &str,
        now_ms: u64,
    ) -> Result<(), PortError> {
        self.cache
            .srem(
                &self.user_sessions_key(user_id),
                vec![session_id.as_bytes().to_vec()],
                now_ms,
            )
            .await
            .map_err(|error| Self::data_error("remove user-session reference", error))?;
        Ok(())
    }

    pub async fn get_by_user_at(
        &self,
        user_id: &str,
        now_ms: u64,
    ) -> Result<Vec<Session>, PortError> {
        let user_key = self.user_sessions_key(user_id);
        let session_ids = self
            .cache
            .smembers(&user_key, now_ms)
            .await
            .map_err(|error| Self::data_error("list user sessions", error))?;
        let mut sessions = Vec::new();
        let mut invalid = Vec::new();
        let now =
            chrono::DateTime::from_timestamp_millis(i64::try_from(now_ms).unwrap_or(i64::MAX))
                .unwrap_or_else(Utc::now);
        for session_id in session_ids {
            let session_id = String::from_utf8(session_id).map_err(|error| {
                PortError::new(
                    "invalid_user_session_reference",
                    format!("user-session reference is not UTF-8: {error}"),
                )
            })?;
            match self.get(&session_id).await? {
                Some(session) if session.is_valid_at(now) => sessions.push(session),
                _ => invalid.push(session_id.into_bytes()),
            }
        }
        if !invalid.is_empty() {
            self.cache
                .srem(&user_key, invalid, now_ms)
                .await
                .map_err(|error| Self::data_error("prune user-session references", error))?;
        }
        Ok(sessions)
    }
}

#[async_trait]
impl SessionRepository for AuthCacheRepository {
    async fn save(&self, session: &Session) -> Result<(), PortError> {
        let now = Utc::now();
        let ttl = session.remaining_ttl_seconds_at(now);
        let Ok(ttl) = u64::try_from(ttl) else {
            return Ok(());
        };
        if ttl == 0 {
            return Ok(());
        }
        let now_ms = Self::now_ms();
        let bytes = serde_json::to_vec(session).map_err(|error| {
            PortError::new(
                "session_serialization_failed",
                format!("session cannot be serialized: {error}"),
            )
        })?;
        self.cache
            .set(
                &self.session_key(&session.session_id),
                bytes,
                Some(ttl),
                now_ms,
            )
            .await
            .map_err(|error| Self::data_error("save session", error))?;
        let user_key = self.user_sessions_key(&session.user.user_id);
        self.cache
            .sadd(
                &user_key,
                vec![session.session_id.as_bytes().to_vec()],
                now_ms,
            )
            .await
            .map_err(|error| Self::data_error("track user session", error))?;
        self.cache
            .expire(
                &user_key,
                ttl.saturating_add(self.keys.user_session_ttl_buffer_seconds),
                now_ms,
            )
            .await
            .map_err(|error| Self::data_error("expire user-session index", error))?;
        Ok(())
    }

    async fn get(&self, session_id: &str) -> Result<Option<Session>, PortError> {
        self.cache
            .get(&self.session_key(session_id), Self::now_ms())
            .await
            .map_err(|error| Self::data_error("load session", error))?
            .map(|bytes| Self::decode_session(&bytes))
            .transpose()
    }

    async fn delete(&self, session_id: &str) -> Result<(), PortError> {
        let now_ms = Self::now_ms();
        if let Some(session) = self.get(session_id).await? {
            self.remove_user_session_reference(&session.user.user_id, session_id, now_ms)
                .await?;
        }
        self.cache
            .delete(&self.session_key(session_id))
            .await
            .map_err(|error| Self::data_error("delete session", error))?;
        Ok(())
    }

    async fn get_by_user(&self, user_id: &str) -> Result<Vec<Session>, PortError> {
        self.get_by_user_at(user_id, Self::now_ms()).await
    }

    async fn delete_all_for_user(&self, user_id: &str) -> Result<usize, PortError> {
        let sessions = self.get_by_user(user_id).await?;
        for session in &sessions {
            self.delete(&session.session_id).await?;
        }
        self.cache
            .delete(&self.user_sessions_key(user_id))
            .await
            .map_err(|error| Self::data_error("delete user-session index", error))?;
        Ok(sessions.len())
    }
}

#[async_trait]
impl PkceStateRepository for AuthCacheRepository {
    async fn save(&self, state: &PkceState) -> Result<(), PortError> {
        let bytes = serde_json::to_vec(state).map_err(|error| {
            PortError::new(
                "pkce_state_serialization_failed",
                format!("PKCE state cannot be serialized: {error}"),
            )
        })?;
        self.cache
            .set(
                &self.pkce_key(&state.state),
                bytes,
                Some(self.keys.pkce_ttl_seconds),
                Self::now_ms(),
            )
            .await
            .map_err(|error| Self::data_error("save PKCE state", error))?;
        Ok(())
    }

    async fn take(&self, state: &str) -> Result<Option<PkceState>, PortError> {
        self.cache
            .take(&self.pkce_key(state), Self::now_ms())
            .await
            .map_err(|error| Self::data_error("consume PKCE state", error))?
            .map(|bytes| {
                serde_json::from_slice(&bytes).map_err(|error| {
                    PortError::new(
                        "invalid_cached_pkce_state",
                        format!("cached PKCE state is malformed: {error}"),
                    )
                })
            })
            .transpose()
    }
}
