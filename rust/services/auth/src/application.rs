use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::domain::{
    generate_pkce_pair, random_urlsafe_token, AuthenticatedUser, OidcValidatedIdentity,
    PasskeyEnrollmentBinding, PkceState, Session, SessionSpec,
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
    #[error("passkey enrollment is unavailable for this session")]
    PasskeyEnrollmentUnavailable,
    #[error("passkey enrollment account or session changed")]
    PasskeyEnrollmentMismatch,
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
pub enum PasskeyEnrollmentStart {
    Authorization(InitiateLoginResult),
    EmailSent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyEnrollmentEmail {
    pub subject: String,
    pub expected_email: String,
    pub client_id: String,
    pub redirect_uri: String,
}

#[async_trait]
pub trait PasskeyEmailEnrollment: Send + Sync {
    async fn send_enrollment_email(
        &self,
        request: &PasskeyEnrollmentEmail,
    ) -> Result<(), PortError>;
}

/// Never treat an application/provisioned user ID as a Keycloak subject. Reject
/// contradictory bindings rather than silently switching the account source.
fn keycloak_subject(session: &Session) -> Option<&str> {
    let resolved = session
        .keycloak_subject
        .as_deref()
        .filter(|sub| !sub.is_empty());
    let oidc = session
        .oidc_claims
        .as_ref()
        .and_then(|claims| claims["sub"].as_str())
        .filter(|sub| !sub.is_empty());
    match (resolved, oidc) {
        (Some(left), Some(right)) if left != right => None,
        (Some(subject), _) | (_, Some(subject)) => Some(subject),
        _ => None,
    }
}

fn has_oidc_enrollment_hint(session: &Session) -> bool {
    // Credential-account resolution does not establish browser SSO, even if
    // token exchange was available. Use the same native email path for badges.
    session.keycloak_subject.is_none()
        && session
            .id_token
            .as_ref()
            .is_some_and(|token| !token.is_empty())
        && session
            .oidc_claims
            .as_ref()
            .and_then(|claims| claims["sub"].as_str())
            .is_some_and(|subject| {
                !subject.is_empty() && keycloak_subject(session) == Some(subject)
            })
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
        organization_id: Option<String>,
        expires_at: DateTime<Utc>,
    },
    UserLoggedOut {
        user_id: String,
        session_id: String,
        logout_type: String,
        organization_id: Option<String>,
    },
    SessionRevoked {
        session_id: String,
        user_id: String,
        revoked_by: String,
        reason: String,
        organization_id: Option<String>,
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
    fn supports_passkey_enrollment(&self) -> bool {
        false
    }
    fn passkey_enrollment_url(
        &self,
        _request: &OidcAuthorizationRequest,
        _id_token_hint: &str,
    ) -> Result<String, PortError> {
        Err(PortError::new(
            "passkey_enrollment_unsupported",
            "Provider does not support native passkey enrollment",
        ))
    }
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
    passkeys_enabled: bool,
    passkey_email: Option<Arc<dyn PasskeyEmailEnrollment>>,
    passkey_client_id: String,
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
    pub passkey_email: Option<Arc<dyn PasskeyEmailEnrollment>>,
    pub sessions: Arc<dyn SessionRepository>,
    pub pkce_states: Arc<dyn PkceStateRepository>,
    pub oidc: Arc<dyn OidcProvider>,
    pub provisioner: Arc<dyn UserProvisioner>,
    pub events: Arc<dyn AuthEventPublisher>,
    pub audit: Option<Arc<dyn AuthAuditSink>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthApplicationConfig {
    pub passkeys_enabled: bool,
    pub passkey_client_id: String,
    pub session_ttl_seconds: i64,
    pub post_logout_redirect_uri: String,
}

impl AuthApplication {
    #[must_use]
    pub fn new(ports: AuthApplicationPorts, config: AuthApplicationConfig) -> Self {
        Self {
            passkeys_enabled: config.passkeys_enabled,
            passkey_email: ports.passkey_email,
            passkey_client_id: config.passkey_client_id,
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
        self.initiate(command, false, None, now).await
    }

    pub async fn initiate_registration(
        &self,
        command: InitiateLoginCommand,
        now: DateTime<Utc>,
    ) -> Result<InitiateLoginResult, AuthApplicationError> {
        self.initiate(command, true, None, now).await
    }

    #[must_use]
    pub fn passkey_enrollment_available(&self, session: &Session) -> bool {
        self.passkeys_enabled
            && self.oidc.supports_passkey_enrollment()
            && session
                .user
                .impersonation
                .as_ref()
                .is_none_or(|context| !context.active)
            && keycloak_subject(session).is_some()
            && (has_oidc_enrollment_hint(session)
                || (session.keycloak_subject.is_some()
                    && self.passkey_email.is_some()
                    && !session.user.email.is_empty()))
    }

    pub async fn initiate_passkey_enrollment(
        &self,
        session_id: &str,
        command: InitiateLoginCommand,
        now: DateTime<Utc>,
    ) -> Result<PasskeyEnrollmentStart, AuthApplicationError> {
        let session = self
            .validate_session(session_id, now)
            .await?
            .filter(|session| self.passkey_enrollment_available(session))
            .ok_or(AuthApplicationError::PasskeyEnrollmentUnavailable)?;
        if has_oidc_enrollment_hint(&session) {
            return self
                .initiate(command, false, Some(&session), now)
                .await
                .map(PasskeyEnrollmentStart::Authorization);
        }
        // Badge sessions do not imply a browser SSO session or invent an OIDC
        // authentication time. Require a recent server-created verified session
        // and let Keycloak confirm the same account through its signed email.
        if !(0..=300).contains(&now.signed_duration_since(session.created_at).num_seconds()) {
            return Err(AuthApplicationError::PasskeyEnrollmentUnavailable);
        }
        let callback = command
            .oidc_redirect_uri
            .as_deref()
            .and_then(|uri| url::Url::parse(uri).ok())
            .filter(|url| {
                matches!(url.scheme(), "https" | "http")
                    && url.username().is_empty()
                    && url.password().is_none()
            })
            .ok_or(AuthApplicationError::PasskeyEnrollmentUnavailable)?;
        let redirect = callback
            .join(command.redirect_uri.as_deref().unwrap_or("/"))
            .map_err(|_| AuthApplicationError::PasskeyEnrollmentUnavailable)?;
        if redirect.origin() != callback.origin() || self.passkey_client_id.is_empty() {
            return Err(AuthApplicationError::PasskeyEnrollmentUnavailable);
        }
        self.passkey_email
            .as_ref()
            .ok_or(AuthApplicationError::PasskeyEnrollmentUnavailable)?
            .send_enrollment_email(&PasskeyEnrollmentEmail {
                subject: keycloak_subject(&session)
                    .ok_or(AuthApplicationError::PasskeyEnrollmentUnavailable)?
                    .into(),
                expected_email: session.user.email.clone(),
                client_id: self.passkey_client_id.clone(),
                redirect_uri: redirect.into(),
            })
            .await
            .map_err(|error| port("send passkey enrollment email", error))?;
        Ok(PasskeyEnrollmentStart::EmailSent)
    }

    async fn initiate(
        &self,
        command: InitiateLoginCommand,
        registration: bool,
        enrollment: Option<&Session>,
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
            passkey_enrollment: enrollment.map(|session| PasskeyEnrollmentBinding {
                session_id: session.session_id.clone(),
                subject: keycloak_subject(session).unwrap_or_default().to_owned(),
            }),
            created_at: now,
            expires_at: now + Duration::minutes(10),
        };
        let request = OidcAuthorizationRequest {
            state: state.clone(),
            code_challenge: pkce.challenge,
            nonce,
            redirect_uri: command.oidc_redirect_uri,
            registration,
        };
        let authorization_url = if let Some(session) = enrollment {
            self.oidc
                .passkey_enrollment_url(&request, session.id_token.as_deref().unwrap_or_default())
        } else {
            self.oidc.authorization_url(&request)
        }
        .map_err(|error| port("build OIDC authorization URL", error))?;
        self.pkce_states
            .save(&stored)
            .await
            .map_err(|error| port("save OIDC state", error))?;
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
        if let Some(binding) = state.passkey_enrollment {
            // The ID-token hint constrains Keycloak before the required action.
            // Independently bind the callback before provisioning or issuing any
            // application session. Account settings must not switch accounts or
            // replace the original session's roles/organization context.
            if identity.user_info.sub != binding.subject {
                return Err(AuthApplicationError::PasskeyEnrollmentMismatch);
            }
            let session = self
                .sessions
                .get(&binding.session_id)
                .await
                .map_err(|error| port("read enrollment session", error))?
                .filter(|session| {
                    session.is_valid_at(now)
                        && self.passkey_enrollment_available(session)
                        && keycloak_subject(session) == Some(binding.subject.as_str())
                })
                .ok_or(AuthApplicationError::PasskeyEnrollmentMismatch)?;
            return Ok(HandleCallbackResult {
                session,
                redirect_uri: state.redirect_uri,
                audit_warning: None,
            });
        }
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
                organization_id: session.user.organization_id.clone(),
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
                organization_id: session.user.organization_id.clone(),
            })
            .await
            .map_err(|error| port("publish logout event", error))?;
        self.events
            .publish(&AuthEvent::SessionRevoked {
                session_id: session.session_id.clone(),
                user_id: session.user.user_id.clone(),
                revoked_by: session.user.user_id.clone(),
                reason: "User initiated logout".to_owned(),
                organization_id: session.user.organization_id.clone(),
            })
            .await
            .map_err(|error| port("publish session-revoked event", error))
    }
}
