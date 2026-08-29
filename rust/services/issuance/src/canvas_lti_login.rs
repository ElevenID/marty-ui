use std::{collections::BTreeSet, sync::Arc, time::Duration};

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use marty_oid4vci::lti::canvas_lti_trust_profile;
use rand::RngCore;
use serde_json::{json, Value};
use thiserror::Error;
use url::Url;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq)]
pub struct CanvasLtiPlatform {
    pub id: String,
    pub organization_id: String,
    pub canvas_account_id: String,
    pub canvas_base_url: Option<String>,
    pub lti_client_id: Option<String>,
    pub lti_deployment_id: Option<String>,
    pub lti_trust_profile: String,
    pub lti_issuer: Option<String>,
    pub lti_jwks_url: Option<String>,
    pub lti_jwks_json: Option<Value>,
    pub lti_openid_configuration: Option<Value>,
    pub config_version: i64,
    pub enabled: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CanvasLtiLaunchState {
    pub id: String,
    pub platform_id: String,
    pub organization_id: String,
    pub canvas_account_id: String,
    pub state: String,
    pub nonce: String,
    pub login_hint: String,
    pub target_link_uri: Option<String>,
    pub lti_message_hint: Option<String>,
    pub redirect_uri: String,
    pub metadata: Value,
    pub ttl: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanvasLtiLoginMode {
    Launch,
    Experience,
}

pub(crate) struct PreparedCanvasLtiLogin {
    platform: CanvasLtiPlatform,
    trust: marty_oid4vci::lti::CanvasLtiTrustProfile,
    mode: CanvasLtiLoginMode,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CanvasLtiLoginSubmission {
    pub iss: Option<String>,
    pub login_hint: Option<String>,
    pub target_link_uri: Option<String>,
    pub lti_message_hint: Option<String>,
    pub client_id: Option<String>,
}

impl CanvasLtiLoginSubmission {
    #[must_use]
    pub fn from_json_object(object: &serde_json::Map<String, Value>) -> Self {
        Self {
            iss: json_string(object, "iss"),
            login_hint: json_string(object, "login_hint"),
            target_link_uri: json_string(object, "target_link_uri"),
            lti_message_hint: json_string(object, "lti_message_hint"),
            client_id: json_string(object, "client_id"),
        }
    }

    #[must_use]
    pub fn normalized(self) -> Self {
        Self {
            iss: non_empty(self.iss),
            login_hint: non_empty(self.login_hint),
            target_link_uri: non_empty(self.target_link_uri),
            lti_message_hint: non_empty(self.lti_message_hint),
            client_id: non_empty(self.client_id),
        }
    }
}

#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum CanvasLtiLoginError {
    #[error("Canvas platform not found")]
    PlatformNotFound,
    #[error("Portable Canvas integration is not enabled for this organization")]
    PilotDisabled,
    #[error("{0}")]
    Invalid(&'static str),
    #[error("{0}")]
    Conflict(&'static str),
    #[error("{0}")]
    TrustConflict(String),
    #[error("Canvas LTI repository is unavailable")]
    RepositoryUnavailable,
}

#[async_trait]
pub trait CanvasLtiLoginRepository: Send + Sync {
    async fn get_platform(
        &self,
        platform_id: &str,
    ) -> Result<Option<CanvasLtiPlatform>, CanvasLtiLoginError>;

    async fn save_launch_state(
        &self,
        launch_state: &CanvasLtiLaunchState,
    ) -> Result<(), CanvasLtiLoginError>;
}

#[derive(Clone)]
pub struct CanvasLtiLoginService {
    repository: Arc<dyn CanvasLtiLoginRepository>,
    issuer_base_url: String,
    portable_enabled: bool,
    pilot_organizations: BTreeSet<String>,
    state_ttl: Duration,
    self_managed_origins: Vec<String>,
}

impl std::fmt::Debug for CanvasLtiLoginService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CanvasLtiLoginService")
            .field("issuer_base_url", &self.issuer_base_url)
            .field("portable_enabled", &self.portable_enabled)
            .field("pilot_organizations", &self.pilot_organizations)
            .field("state_ttl", &self.state_ttl)
            .field(
                "self_managed_origin_count",
                &self.self_managed_origins.len(),
            )
            .finish_non_exhaustive()
    }
}

impl CanvasLtiLoginService {
    pub fn new(
        repository: Arc<dyn CanvasLtiLoginRepository>,
        issuer_base_url: &str,
        portable_enabled: bool,
        pilot_organizations: BTreeSet<String>,
        state_ttl: Duration,
        self_managed_origins: Vec<String>,
    ) -> Result<Self, CanvasLtiLoginError> {
        if state_ttl.is_zero() {
            return Err(CanvasLtiLoginError::RepositoryUnavailable);
        }
        let issuer_base_url = issuer_base_url.trim_end_matches('/').to_owned();
        Url::parse(&issuer_base_url).map_err(|_| CanvasLtiLoginError::RepositoryUnavailable)?;
        Ok(Self {
            repository,
            issuer_base_url,
            portable_enabled,
            pilot_organizations,
            state_ttl,
            self_managed_origins,
        })
    }

    pub async fn initiate(
        &self,
        platform_id: &str,
        submission: CanvasLtiLoginSubmission,
        mode: CanvasLtiLoginMode,
    ) -> Result<String, CanvasLtiLoginError> {
        let prepared = self.prepare(platform_id, mode).await?;
        self.initiate_prepared(prepared, submission).await
    }

    pub(crate) async fn ready_platform(
        &self,
        platform_id: &str,
    ) -> Result<CanvasLtiPlatform, CanvasLtiLoginError> {
        Ok(self
            .prepare(platform_id, CanvasLtiLoginMode::Launch)
            .await?
            .platform)
    }

    pub(crate) async fn prepare(
        &self,
        platform_id: &str,
        mode: CanvasLtiLoginMode,
    ) -> Result<PreparedCanvasLtiLogin, CanvasLtiLoginError> {
        let platform = self
            .repository
            .get_platform(platform_id)
            .await?
            .ok_or(CanvasLtiLoginError::PlatformNotFound)?;
        if !self.portable_enabled
            || platform.organization_id.trim().is_empty()
            || !self
                .pilot_organizations
                .contains(platform.organization_id.trim())
        {
            return Err(CanvasLtiLoginError::PilotDisabled);
        }
        let trust = self.validate_ready_platform(&platform)?;
        Ok(PreparedCanvasLtiLogin {
            platform,
            trust,
            mode,
        })
    }

    pub(crate) async fn initiate_prepared(
        &self,
        prepared: PreparedCanvasLtiLogin,
        submission: CanvasLtiLoginSubmission,
    ) -> Result<String, CanvasLtiLoginError> {
        let PreparedCanvasLtiLogin {
            platform,
            trust,
            mode,
        } = prepared;
        let submission = submission.normalized();
        let login_hint = submission.login_hint.ok_or(CanvasLtiLoginError::Invalid(
            "Canvas LTI login requires login_hint",
        ))?;
        if submission
            .iss
            .as_deref()
            .is_some_and(|issuer| Some(issuer) != platform.lti_issuer.as_deref())
        {
            return Err(CanvasLtiLoginError::Invalid(
                "Canvas LTI issuer does not match platform",
            ));
        }
        if submission
            .client_id
            .as_deref()
            .is_some_and(|client_id| Some(client_id) != platform.lti_client_id.as_deref())
        {
            return Err(CanvasLtiLoginError::Invalid(
                "Canvas LTI client_id does not match platform",
            ));
        }

        let redirect_suffix = match mode {
            CanvasLtiLoginMode::Launch => "launch",
            CanvasLtiLoginMode::Experience => "experience",
        };
        let redirect_uri = format!(
            "{}/v1/integrations/canvas/lti/platforms/{}/{}",
            self.issuer_base_url, platform.id, redirect_suffix
        );
        let launch_state = CanvasLtiLaunchState {
            id: Uuid::new_v4().to_string(),
            platform_id: platform.id.clone(),
            organization_id: platform.organization_id.clone(),
            canvas_account_id: platform.canvas_account_id.clone(),
            state: random_token(),
            nonce: random_token(),
            login_hint,
            target_link_uri: submission.target_link_uri,
            lti_message_hint: submission.lti_message_hint,
            redirect_uri,
            metadata: json!({
                "issuer": submission.iss,
                "client_id": submission.client_id,
                "canvas_platform_id": platform.id,
                "experience_mode": mode == CanvasLtiLoginMode::Experience,
            }),
            ttl: self.state_ttl,
        };
        self.repository.save_launch_state(&launch_state).await?;

        let mut authorization_endpoint =
            Url::parse(&trust.authorization_endpoint).map_err(|_| {
                CanvasLtiLoginError::Conflict(
                    "Canvas platform is missing LTI authorization_endpoint metadata",
                )
            })?;
        {
            let client_id = platform
                .lti_client_id
                .as_deref()
                .expect("readiness validation requires a client id");
            let mut query = authorization_endpoint.query_pairs_mut();
            query
                .append_pair("scope", "openid")
                .append_pair("response_type", "id_token")
                .append_pair("response_mode", "form_post")
                .append_pair("prompt", "none")
                .append_pair("client_id", client_id)
                .append_pair("redirect_uri", &launch_state.redirect_uri)
                .append_pair("login_hint", &launch_state.login_hint)
                .append_pair("state", &launch_state.state)
                .append_pair("nonce", &launch_state.nonce);
            if let Some(message_hint) = launch_state.lti_message_hint.as_deref() {
                query.append_pair("lti_message_hint", message_hint);
            }
        }
        Ok(authorization_endpoint.into())
    }

    fn validate_ready_platform(
        &self,
        platform: &CanvasLtiPlatform,
    ) -> Result<marty_oid4vci::lti::CanvasLtiTrustProfile, CanvasLtiLoginError> {
        if !platform.enabled {
            return Err(CanvasLtiLoginError::Conflict("Canvas platform is disabled"));
        }
        if non_empty(platform.lti_client_id.clone()).is_none()
            || non_empty(platform.lti_deployment_id.clone()).is_none()
        {
            return Err(CanvasLtiLoginError::Conflict(
                "Canvas platform is missing LTI client or deployment configuration",
            ));
        }
        if non_empty(platform.lti_issuer.clone()).is_none()
            || platform
                .lti_jwks_json
                .as_ref()
                .and_then(Value::as_object)
                .is_none_or(serde_json::Map::is_empty)
        {
            return Err(CanvasLtiLoginError::Conflict(
                "Canvas platform has not been sandbox-probed or is missing LTI trust metadata",
            ));
        }
        let canvas_origin = non_empty(platform.canvas_base_url.clone()).ok_or(
            CanvasLtiLoginError::Conflict("Canvas platform is missing its HTTPS origin"),
        )?;
        let trust = canvas_lti_trust_profile(
            &canvas_origin,
            &platform.lti_trust_profile,
            &self.self_managed_origins,
        )
        .map_err(|error| {
            CanvasLtiLoginError::TrustConflict(format!(
                "Canvas LTI trust configuration is not permitted: {error}"
            ))
        })?;
        let metadata = platform
            .lti_openid_configuration
            .as_ref()
            .and_then(Value::as_object);
        let authorization_endpoint = metadata
            .and_then(|metadata| metadata.get("authorization_endpoint"))
            .and_then(Value::as_str)
            .and_then(|value| non_empty(Some(value.to_owned())))
            .ok_or(CanvasLtiLoginError::Conflict(
                "Canvas platform is missing LTI authorization_endpoint metadata",
            ))?;
        let observed = [
            platform.lti_issuer.as_deref().map(str::trim),
            Some(authorization_endpoint.as_str()),
            metadata
                .and_then(|value| value.get("token_endpoint"))
                .and_then(Value::as_str)
                .map(str::trim),
            metadata
                .and_then(|value| value.get("jwks_uri"))
                .and_then(Value::as_str)
                .map(str::trim)
                .or_else(|| platform.lti_jwks_url.as_deref().map(str::trim)),
        ];
        let expected = [
            trust.issuer.as_str(),
            trust.authorization_endpoint.as_str(),
            trust.token_endpoint.as_str(),
            trust.jwks_uri.as_str(),
        ];
        if observed
            .into_iter()
            .zip(expected)
            .any(|(observed, expected)| {
                observed.is_some_and(|value| !value.is_empty() && value != expected)
            })
        {
            return Err(CanvasLtiLoginError::Conflict(
                "Canvas LTI metadata does not match the persisted trust profile",
            ));
        }
        if authorization_endpoint != trust.authorization_endpoint {
            return Err(CanvasLtiLoginError::Conflict(
                "Canvas LTI authorization_endpoint does not match probed metadata",
            ));
        }
        Ok(trust)
    }
}

fn non_empty(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let value = value.trim();
        (!value.is_empty()).then(|| value.to_owned())
    })
}

fn json_string(object: &serde_json::Map<String, Value>, name: &str) -> Option<String> {
    object.get(name).and_then(Value::as_str).map(str::to_owned)
}

pub(crate) fn random_token() -> String {
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
