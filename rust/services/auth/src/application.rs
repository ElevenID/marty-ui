use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::domain::{
    generate_pkce_pair, random_urlsafe_token, AuthenticatedUser, OidcValidatedIdentity, PkceState,
    Session, SessionSpec,
};

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{code}: {message}")]
pub struct PortError {
    pub code: String,
    pub message: String,
}

impl PortError {
    #[must_use]
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

#[derive(Debug, Error)]
pub enum AuthApplicationError {
    #[error("invalid or expired OIDC state")]
    InvalidState,
    #[error("OIDC state has expired")]
    ExpiredState,
    #[error("OIDC nonce is missing from login state")]
    MissingNonce,
    #[error("OIDC provider did not return an access token")]
    MissingAccessToken,
    #[error("OIDC provider did not return an ID token")]
    MissingIdToken,
    #[error("{operation} failed: {source}")]
    Port {
        operation: &'static str,
        #[source]
        source: PortError,
    },
}

fn port(operation: &'static str, source: PortError) -> AuthApplicationError {
    AuthApplicationError::Port { operation, source }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitiateLoginCommand {
    pub redirect_uri: Option<String>,
    pub oidc_redirect_uri: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitiateLoginResult {
    pub authorization_url: String,
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandleCallbackCommand {
    pub code: String,
    pub state: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HandleCallbackResult {
    pub session: Session,
    pub redirect_uri: String,
    pub audit_warning: Option<PortError>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogoutResult {
    pub success: bool,
    pub sso_logout_url: Option<String>,
    pub audit_warning: Option<PortError>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcAuthorizationRequest {
    pub state: String,
    pub code_challenge: String,
    pub nonce: String,
    pub redirect_uri: Option<String>,
    pub registration: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcTokenSet {
    pub access_token: String,
    pub id_token: Option<String>,
    pub refresh_token: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcCodeExchange {
    pub code: String,
    pub code_verifier: String,
    pub redirect_uri: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcLogoutRequest {
    pub id_token: Option<String>,
    pub post_logout_redirect_uri: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthEvent {
    UserAuthenticated {
        user_id: String,
        email: String,
        organization_id: Option<String>,
        ip_address: Option<String>,
    },
    SessionCreated {
        session_id: String,
        user_id: String,
        expires_at: DateTime<Utc>,
    },
    UserLoggedOut {
        user_id: String,
        session_id: String,
        logout_type: String,
    },
    SessionRevoked {
        session_id: String,
        user_id: String,
        revoked_by: String,
        reason: String,
    },
}

#[async_trait]
pub trait SessionRepository: Send + Sync {
    async fn save(&self, session: &Session) -> Result<(), PortError>;
    async fn get(&self, session_id: &str) -> Result<Option<Session>, PortError>;
    async fn delete(&self, session_id: &str) -> Result<(), PortError>;
    async fn get_by_user(&self, user_id: &str) -> Result<Vec<Session>, PortError>;
    async fn delete_all_for_user(&self, user_id: &str) -> Result<usize, PortError>;
}

#[async_trait]
pub trait PkceStateRepository: Send + Sync {
    async fn save(&self, state: &PkceState) -> Result<(), PortError>;
    async fn take(&self, state: &str) -> Result<Option<PkceState>, PortError>;
}

#[async_trait]
pub trait OidcProvider: Send + Sync {
    fn authorization_url(&self, request: &OidcAuthorizationRequest) -> Result<String, PortError>;
    async fn exchange_code(&self, request: &OidcCodeExchange) -> Result<OidcTokenSet, PortError>;
    async fn validate_tokens(
        &self,
        id_token: &str,
        access_token: &str,
        expected_nonce: &str,
    ) -> Result<OidcValidatedIdentity, PortError>;
    fn logout_url(&self, request: &OidcLogoutRequest) -> Result<Option<String>, PortError>;
}

#[async_trait]
pub trait UserProvisioner: Send + Sync {
    async fn provision(
        &self,
        identity: &OidcValidatedIdentity,
    ) -> Result<AuthenticatedUser, PortError>;
}

#[async_trait]
pub trait AuthEventPublisher: Send + Sync {
    async fn publish(&self, event: &AuthEvent) -> Result<(), PortError>;
}

#[async_trait]
pub trait AuthAuditSink: Send + Sync {
    async fn record_authentication(
        &self,
        session: &Session,
        authentication_method: &str,
    ) -> Result<(), PortError>;
    async fn record_logout(&self, session: &Session) -> Result<(), PortError>;
}

#[derive(Clone)]
pub struct AuthApplication {
    sessions: Arc<dyn SessionRepository>,
    pkce_states: Arc<dyn PkceStateRepository>,
    oidc: Arc<dyn OidcProvider>,
    provisioner: Arc<dyn UserProvisioner>,
    events: Arc<dyn AuthEventPublisher>,
    audit: Option<Arc<dyn AuthAuditSink>>,
    session_ttl_seconds: i64,
    post_logout_redirect_uri: String,
}

#[derive(Clone)]
pub struct AuthApplicationPorts {
    pub sessions: Arc<dyn SessionRepository>,
    pub pkce_states: Arc<dyn PkceStateRepository>,
    pub oidc: Arc<dyn OidcProvider>,
    pub provisioner: Arc<dyn UserProvisioner>,
    pub events: Arc<dyn AuthEventPublisher>,
    pub audit: Option<Arc<dyn AuthAuditSink>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthApplicationConfig {
    pub session_ttl_seconds: i64,
    pub post_logout_redirect_uri: String,
}

impl AuthApplication {
    #[must_use]
    pub fn new(ports: AuthApplicationPorts, config: AuthApplicationConfig) -> Self {
        Self {
            sessions: ports.sessions,
            pkce_states: ports.pkce_states,
            oidc: ports.oidc,
            provisioner: ports.provisioner,
            events: ports.events,
            audit: ports.audit,
            session_ttl_seconds: config.session_ttl_seconds,
            post_logout_redirect_uri: config.post_logout_redirect_uri,
        }
    }

    pub async fn initiate_login(
        &self,
        command: InitiateLoginCommand,
        now: DateTime<Utc>,
    ) -> Result<InitiateLoginResult, AuthApplicationError> {
        self.initiate(command, false, now).await
    }

    pub async fn initiate_registration(
        &self,
        command: InitiateLoginCommand,
        now: DateTime<Utc>,
    ) -> Result<InitiateLoginResult, AuthApplicationError> {
        self.initiate(command, true, now).await
    }

    async fn initiate(
        &self,
        command: InitiateLoginCommand,
        registration: bool,
        now: DateTime<Utc>,
    ) -> Result<InitiateLoginResult, AuthApplicationError> {
        let pkce = generate_pkce_pair();
        let state = random_urlsafe_token(32);
        let nonce = random_urlsafe_token(32);
        let stored = PkceState {
            state: state.clone(),
            code_verifier: pkce.verifier,
            redirect_uri: command.redirect_uri.unwrap_or_else(|| "/".to_owned()),
            oidc_redirect_uri: command.oidc_redirect_uri.clone(),
            nonce: Some(nonce.clone()),
            created_at: now,
            expires_at: now + Duration::minutes(10),
        };
        self.pkce_states
            .save(&stored)
            .await
            .map_err(|error| port("save OIDC state", error))?;
        let authorization_url = self
            .oidc
            .authorization_url(&OidcAuthorizationRequest {
                state: state.clone(),
                code_challenge: pkce.challenge,
                nonce,
                redirect_uri: command.oidc_redirect_uri,
                registration,
            })
            .map_err(|error| port("build OIDC authorization URL", error))?;
        Ok(InitiateLoginResult {
            authorization_url,
            state,
        })
    }

    pub async fn handle_callback(
        &self,
        command: HandleCallbackCommand,
        now: DateTime<Utc>,
    ) -> Result<HandleCallbackResult, AuthApplicationError> {
        let state = self
            .pkce_states
            .take(&command.state)
            .await
            .map_err(|error| port("consume OIDC state", error))?
            .ok_or(AuthApplicationError::InvalidState)?;
        if !state.is_valid_at(now) {
            return Err(AuthApplicationError::ExpiredState);
        }
        let nonce = state
            .nonce
            .as_deref()
            .ok_or(AuthApplicationError::MissingNonce)?;
        let tokens = self
            .oidc
            .exchange_code(&OidcCodeExchange {
                code: command.code,
                code_verifier: state.code_verifier,
                redirect_uri: state.oidc_redirect_uri,
            })
            .await
            .map_err(|error| port("exchange OIDC code", error))?;
        if tokens.access_token.is_empty() {
            return Err(AuthApplicationError::MissingAccessToken);
        }
        let id_token = tokens
            .id_token
            .ok_or(AuthApplicationError::MissingIdToken)?;
        let identity = self
            .oidc
            .validate_tokens(&id_token, &tokens.access_token, nonce)
            .await
            .map_err(|error| port("validate OIDC tokens", error))?;
        let user = self
            .provisioner
            .provision(&identity)
            .await
            .map_err(|error| port("provision authenticated user", error))?;
        let session = Session::create(SessionSpec {
            user,
            ttl_seconds: self.session_ttl_seconds,
            now,
            ip_address: command.ip_address,
            user_agent: command.user_agent,
            id_token: Some(id_token),
            refresh_token: tokens.refresh_token,
            oidc_claims: Some(identity.id_token_claims),
        });
        self.sessions
            .save(&session)
            .await
            .map_err(|error| port("save authenticated session", error))?;
        self.publish_login_events(&session).await?;
        let audit_warning = if let Some(audit) = &self.audit {
            audit.record_authentication(&session, "oidc").await.err()
        } else {
            None
        };
        Ok(HandleCallbackResult {
            session,
            redirect_uri: state.redirect_uri,
            audit_warning,
        })
    }

    async fn publish_login_events(&self, session: &Session) -> Result<(), AuthApplicationError> {
        self.events
            .publish(&AuthEvent::UserAuthenticated {
                user_id: session.user.user_id.clone(),
                email: session.user.email.clone(),
                organization_id: session.user.organization_id.clone(),
                ip_address: session.ip_address.clone(),
            })
            .await
            .map_err(|error| port("publish authentication event", error))?;
        self.events
            .publish(&AuthEvent::SessionCreated {
                session_id: session.session_id.clone(),
                user_id: session.user.user_id.clone(),
                expires_at: session.expires_at,
            })
            .await
            .map_err(|error| port("publish session-created event", error))
    }

    pub async fn validate_session(
        &self,
        session_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<Session>, AuthApplicationError> {
        let Some(mut session) = self
            .sessions
            .get(session_id)
            .await
            .map_err(|error| port("load session", error))?
        else {
            return Ok(None);
        };
        if !session.is_valid_at(now) {
            self.sessions
                .delete(session_id)
                .await
                .map_err(|error| port("delete invalid session", error))?;
            return Ok(None);
        }
        session.touch_at(now);
        self.sessions
            .save(&session)
            .await
            .map_err(|error| port("refresh session activity", error))?;
        Ok(Some(session))
    }

    pub async fn invalidate_session(&self, session_id: &str) -> Result<bool, AuthApplicationError> {
        let exists = self
            .sessions
            .get(session_id)
            .await
            .map_err(|error| port("load session", error))?
            .is_some();
        if exists {
            self.sessions
                .delete(session_id)
                .await
                .map_err(|error| port("delete session", error))?;
        }
        Ok(exists)
    }

    pub async fn logout(&self, session_id: &str) -> Result<LogoutResult, AuthApplicationError> {
        let Some(mut session) = self
            .sessions
            .get(session_id)
            .await
            .map_err(|error| port("load logout session", error))?
        else {
            return Ok(LogoutResult {
                success: true,
                sso_logout_url: None,
                audit_warning: None,
            });
        };
        session.revoke();
        self.sessions
            .delete(session_id)
            .await
            .map_err(|error| port("delete logout session", error))?;
        let sso_logout_url = self
            .oidc
            .logout_url(&OidcLogoutRequest {
                id_token: session.id_token.clone(),
                post_logout_redirect_uri: self.post_logout_redirect_uri.clone(),
            })
            .map_err(|error| port("build OIDC logout URL", error))?;
        self.publish_logout_events(&session).await?;
        let audit_warning = if let Some(audit) = &self.audit {
            audit.record_logout(&session).await.err()
        } else {
            None
        };
        Ok(LogoutResult {
            success: true,
            sso_logout_url,
            audit_warning,
        })
    }

    async fn publish_logout_events(&self, session: &Session) -> Result<(), AuthApplicationError> {
        self.events
            .publish(&AuthEvent::UserLoggedOut {
                user_id: session.user.user_id.clone(),
                session_id: session.session_id.clone(),
                logout_type: "user_initiated".to_owned(),
            })
            .await
            .map_err(|error| port("publish logout event", error))?;
        self.events
            .publish(&AuthEvent::SessionRevoked {
                session_id: session.session_id.clone(),
                user_id: session.user.user_id.clone(),
                revoked_by: session.user.user_id.clone(),
                reason: "User initiated logout".to_owned(),
            })
            .await
            .map_err(|error| port("publish session-revoked event", error))
    }
}
