use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mmf_platform::{OutboundHttpClient, OutboundHttpMethod, OutboundHttpRequest};
use serde_json::{json, Map, Value};
use url::Url;

use crate::{
    build_canvas_lti_user, AuthenticatedUser, PortError, Session, SessionRepository, SessionSpec,
};

pub const CANVAS_SESSION_RESPONSE_MAX_BYTES: usize = 1024 * 1024;

#[async_trait]
pub trait CanvasExperienceSessionProvider: Send + Sync {
    async fn by_state(&self, state: &str) -> Result<Value, PortError>;
    async fn current(&self, bearer_token: &str) -> Result<Value, PortError>;
}

#[derive(Clone)]
pub struct HttpCanvasExperienceSessionProvider {
    http: Arc<dyn OutboundHttpClient>,
    issuance_base_url: Url,
}

impl HttpCanvasExperienceSessionProvider {
    pub fn new(
        http: Arc<dyn OutboundHttpClient>,
        issuance_base_url: &str,
    ) -> Result<Self, PortError> {
        let mut url = Url::parse(issuance_base_url).map_err(|_| invalid_configuration())?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(invalid_configuration());
        }
        let base_path = url.path().trim_end_matches('/').to_owned();
        url.set_path(&base_path);
        Ok(Self {
            http,
            issuance_base_url: url,
        })
    }

    async fn get(&self, path: &str, bearer_token: Option<&str>) -> Result<Value, PortError> {
        let mut url = self.issuance_base_url.clone();
        url.set_path(&format!("{}{path}", self.issuance_base_url.path()));
        let mut headers = BTreeMap::from([("accept".into(), "application/json".into())]);
        if let Some(token) = bearer_token {
            headers.insert("authorization".into(), format!("Bearer {token}"));
        }
        let response = self
            .http
            .execute(OutboundHttpRequest {
                method: OutboundHttpMethod::Get,
                url: url.into(),
                headers,
                body: None,
                maximum_response_bytes: CANVAS_SESSION_RESPONSE_MAX_BYTES,
            })
            .await
            .map_err(|error| PortError::new("canvas_lti_session_unavailable", error.to_string()))?;
        match response.status {
            200..=299 => response
                .json_object("Canvas LTI session")
                .map_err(|error| PortError::new("canvas_lti_session_invalid", error.to_string())),
            401 | 404 if bearer_token.is_some() => Err(PortError::new(
                "canvas_lti_session_expired",
                "Canvas LTI session is invalid or expired",
            )),
            404 => Err(PortError::new(
                "canvas_lti_session_not_found",
                "Canvas LTI session was not found",
            )),
            status if status >= 500 => Err(PortError::new(
                "canvas_lti_session_unavailable",
                "Canvas LTI session service failed",
            )),
            status => Err(PortError::new(
                "canvas_lti_session_invalid",
                format!("Canvas LTI session service returned HTTP {status}"),
            )),
        }
    }
}

#[async_trait]
impl CanvasExperienceSessionProvider for HttpCanvasExperienceSessionProvider {
    async fn by_state(&self, state: &str) -> Result<Value, PortError> {
        let state = state.trim();
        if state.is_empty() {
            return Err(PortError::new(
                "canvas_lti_state_required",
                "Canvas LTI state is required",
            ));
        }
        let encoded: String = url::form_urlencoded::byte_serialize(state.as_bytes()).collect();
        self.get(
            &format!("/v1/integrations/canvas/lti/experience-sessions/{encoded}"),
            None,
        )
        .await
    }

    async fn current(&self, bearer_token: &str) -> Result<Value, PortError> {
        let bearer_token = bearer_token.trim();
        if bearer_token.is_empty() {
            return Err(PortError::new(
                "canvas_lti_token_required",
                "Canvas LTI session token is required",
            ));
        }
        self.get(
            "/v1/integrations/canvas/lti/experience-sessions/current",
            Some(bearer_token),
        )
        .await
    }
}

#[async_trait]
pub trait CanvasApplicantProfileProvisioner: Send + Sync {
    async fn ensure_profile(&self, user: &AuthenticatedUser) -> Result<Option<String>, PortError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanvasFinalizeContext {
    pub bearer_token: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

pub struct CanvasLtiApplication {
    provider: Arc<dyn CanvasExperienceSessionProvider>,
    sessions: Arc<dyn SessionRepository>,
    applicant_profiles: Option<Arc<dyn CanvasApplicantProfileProvisioner>>,
    session_ttl_seconds: i64,
}

impl CanvasLtiApplication {
    pub fn new(
        provider: Arc<dyn CanvasExperienceSessionProvider>,
        sessions: Arc<dyn SessionRepository>,
        applicant_profiles: Option<Arc<dyn CanvasApplicantProfileProvisioner>>,
        session_ttl_seconds: i64,
    ) -> Result<Self, PortError> {
        if session_ttl_seconds <= 0 {
            return Err(PortError::new(
                "canvas_lti_configuration_invalid",
                "Canvas LTI session TTL must be positive",
            ));
        }
        Ok(Self {
            provider,
            sessions,
            applicant_profiles,
            session_ttl_seconds,
        })
    }

    pub async fn finalize(
        &self,
        context: &CanvasFinalizeContext,
        now: DateTime<Utc>,
    ) -> Result<Session, PortError> {
        let payload = self.provider.current(&context.bearer_token).await?;
        let mut user = build_canvas_lti_user(&payload)?;
        if let Some(organization_id) = user.organization_id.clone() {
            let mut organizations = Map::new();
            organizations.insert(
                organization_id,
                json!({
                    "name": user.organization_name.as_deref().unwrap_or("ElevenID LLC"),
                    "source": "canvas_lti"
                }),
            );
            user.organization = Some(Value::Object(organizations));
        }
        if let Some(provisioner) = &self.applicant_profiles {
            if let Ok(Some(applicant_id)) = provisioner.ensure_profile(&user).await {
                user.applicant_id = Some(applicant_id);
            }
        }
        let session = Session::create(SessionSpec {
            user,
            ttl_seconds: self.session_ttl_seconds,
            now,
            ip_address: context.ip_address.clone(),
            user_agent: context.user_agent.clone(),
            id_token: None,
            refresh_token: None,
            oidc_claims: None,
        });
        self.sessions.save(&session).await?;
        Ok(session)
    }
}

fn invalid_configuration() -> PortError {
    PortError::new(
        "canvas_lti_configuration_invalid",
        "Canvas LTI issuance service URL must be an uncredentialed HTTP(S) base URL",
    )
}
