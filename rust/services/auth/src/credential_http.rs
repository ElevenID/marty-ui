use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use thiserror::Error;
use url::Url;

use crate::{
    domain::random_urlsafe_token, CredentialCallbackApplication, CredentialCallbackContext,
    CredentialCallbackError, CredentialCallbackHeaders, CredentialCallbackResult,
    CredentialLoginCompletion, CredentialLoginPoll, CredentialLoginStateStore,
    CredentialStateError, CredentialVerifiedPayload, PendingCredentialLogin, PortError,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartCredentialVerification {
    pub presentation_policy_id: String,
    pub organization_id: String,
    pub issuer_did: String,
    pub callback_url: String,
    pub user_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialVerificationFlow {
    pub instance_id: String,
    pub request_uri: String,
    pub qr_code_data: String,
}

#[async_trait]
pub trait CredentialVerificationStarter: Send + Sync {
    async fn start(
        &self,
        request: &StartCredentialVerification,
    ) -> Result<CredentialVerificationFlow, PortError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialLoginPageInput {
    pub nonce: String,
    pub flow_instance_id: String,
    pub oid4vp_uri: String,
    pub request_uri: String,
}

pub trait CredentialLoginPageRenderer: Send + Sync {
    fn render(&self, input: &CredentialLoginPageInput) -> Result<String, PortError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialLoginStartConfig {
    pub presentation_policy_id: String,
    pub organization_id: String,
    pub issuer_did: String,
    pub auth_service_internal_url: String,
}

impl CredentialLoginStartConfig {
    pub fn validate(&self) -> Result<(), CredentialHttpError> {
        if self.presentation_policy_id.trim().is_empty()
            || self.organization_id.trim().is_empty()
            || self.issuer_did.trim().is_empty()
        {
            return Err(CredentialHttpError::Unavailable(
                "credential-login policy, organization and issuer DID are required".into(),
            ));
        }
        let url = Url::parse(&self.auth_service_internal_url)
            .map_err(|_| CredentialHttpError::Unavailable("auth internal URL is invalid".into()))?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(CredentialHttpError::Unavailable(
                "auth internal URL must be an uncredentialed HTTP(S) base URL".into(),
            ));
        }
        Ok(())
    }

    fn callback_url(&self, nonce: &str) -> String {
        format!(
            "{}/internal/v1/auth/credential-verified?nonce={nonce}",
            self.auth_service_internal_url.trim_end_matches('/')
        )
    }
}

#[derive(Debug, Error)]
pub enum CredentialHttpError {
    #[error("AUTH.CREDENTIAL_LOGIN_UNAVAILABLE: {0}")]
    Unavailable(String),
    #[error(transparent)]
    State(#[from] CredentialStateError),
    #[error(transparent)]
    Callback(#[from] CredentialCallbackError),
    #[error(transparent)]
    Port(#[from] PortError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialLoginStartResult {
    pub nonce: String,
    pub html: String,
}

pub struct CredentialLoginHttpApplication {
    state: Arc<CredentialLoginStateStore>,
    callback: Arc<CredentialCallbackApplication>,
    flow: Arc<dyn CredentialVerificationStarter>,
    renderer: Arc<dyn CredentialLoginPageRenderer>,
    config: CredentialLoginStartConfig,
}

#[async_trait]
pub trait CredentialLoginHttpService: Send + Sync {
    async fn start_login(&self) -> Result<CredentialLoginStartResult, CredentialHttpError>;
    async fn poll_login(&self, nonce: &str) -> Result<CredentialLoginPoll, CredentialHttpError>;
    async fn finalize_login(
        &self,
        nonce: &str,
    ) -> Result<Option<CredentialLoginCompletion>, CredentialHttpError>;
    async fn verified_callback(
        &self,
        payload: &CredentialVerifiedPayload,
        headers: &CredentialCallbackHeaders,
        context: &CredentialCallbackContext,
    ) -> Result<CredentialCallbackResult, CredentialHttpError>;
}

#[async_trait]
impl CredentialLoginHttpService for CredentialLoginHttpApplication {
    async fn start_login(&self) -> Result<CredentialLoginStartResult, CredentialHttpError> {
        self.start(Utc::now()).await
    }

    async fn poll_login(&self, nonce: &str) -> Result<CredentialLoginPoll, CredentialHttpError> {
        self.poll(nonce, Utc::now()).await
    }

    async fn finalize_login(
        &self,
        nonce: &str,
    ) -> Result<Option<CredentialLoginCompletion>, CredentialHttpError> {
        self.finalize(nonce, Utc::now()).await
    }

    async fn verified_callback(
        &self,
        payload: &CredentialVerifiedPayload,
        headers: &CredentialCallbackHeaders,
        context: &CredentialCallbackContext,
    ) -> Result<CredentialCallbackResult, CredentialHttpError> {
        self.credential_verified(payload, headers, context, Utc::now())
            .await
    }
}

impl CredentialLoginHttpApplication {
    pub fn new(
        state: Arc<CredentialLoginStateStore>,
        callback: Arc<CredentialCallbackApplication>,
        flow: Arc<dyn CredentialVerificationStarter>,
        renderer: Arc<dyn CredentialLoginPageRenderer>,
        config: CredentialLoginStartConfig,
    ) -> Result<Self, CredentialHttpError> {
        config.validate()?;
        Ok(Self {
            state,
            callback,
            flow,
            renderer,
            config,
        })
    }

    pub async fn start(
        &self,
        now: DateTime<Utc>,
    ) -> Result<CredentialLoginStartResult, CredentialHttpError> {
        let nonce = random_urlsafe_token(32);
        let flow = self
            .flow
            .start(&StartCredentialVerification {
                presentation_policy_id: self.config.presentation_policy_id.clone(),
                organization_id: self.config.organization_id.clone(),
                issuer_did: self.config.issuer_did.clone(),
                callback_url: self.config.callback_url(&nonce),
                user_id: "auth-service".into(),
            })
            .await?;
        if flow.instance_id.trim().is_empty() {
            return Err(CredentialHttpError::Unavailable(
                "flow service returned no verification instance ID".into(),
            ));
        }
        let oid4vp_uri = nonempty(&flow.request_uri)
            .or_else(|| nonempty(&flow.qr_code_data))
            .ok_or_else(|| {
                CredentialHttpError::Unavailable(
                    "flow service returned no OID4VP request URI".into(),
                )
            })?
            .to_owned();
        let now_ms = u64::try_from(now.timestamp_millis()).unwrap_or_default();
        self.state
            .save_pending(
                &PendingCredentialLogin {
                    nonce: nonce.clone(),
                    flow_instance_id: flow.instance_id.clone(),
                    presentation_policy_id: self.config.presentation_policy_id.clone(),
                    organization_id: self.config.organization_id.clone(),
                    status: "pending".into(),
                    revocation_checked: false,
                },
                now_ms,
            )
            .await?;
        let html = self.renderer.render(&CredentialLoginPageInput {
            nonce: nonce.clone(),
            flow_instance_id: flow.instance_id,
            oid4vp_uri,
            request_uri: flow.request_uri,
        })?;
        Ok(CredentialLoginStartResult { nonce, html })
    }

    pub async fn poll(
        &self,
        nonce: &str,
        now: DateTime<Utc>,
    ) -> Result<CredentialLoginPoll, CredentialHttpError> {
        self.state
            .poll(
                nonce,
                u64::try_from(now.timestamp_millis()).unwrap_or_default(),
            )
            .await
            .map_err(Into::into)
    }

    pub async fn finalize(
        &self,
        nonce: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<CredentialLoginCompletion>, CredentialHttpError> {
        self.state
            .finalize(
                nonce,
                u64::try_from(now.timestamp_millis()).unwrap_or_default(),
            )
            .await
            .map_err(Into::into)
    }

    pub async fn credential_verified(
        &self,
        payload: &CredentialVerifiedPayload,
        headers: &CredentialCallbackHeaders,
        context: &CredentialCallbackContext,
        now: DateTime<Utc>,
    ) -> Result<CredentialCallbackResult, CredentialHttpError> {
        self.callback
            .handle(payload, headers, context, now)
            .await
            .map_err(Into::into)
    }
}

fn nonempty(value: &str) -> Option<&str> {
    let value = value.trim();
    (!value.is_empty()).then_some(value)
}
