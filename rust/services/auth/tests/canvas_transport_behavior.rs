use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{TimeZone as _, Utc};
use marty_auth::{
    CanvasExperienceSessionProvider, CanvasFinalizeContext, CanvasLtiApplication,
    HttpCanvasExperienceSessionProvider, PortError, Session, SessionRepository,
};
use mmf_platform::{OutboundHttpClient, OutboundHttpRequest, OutboundHttpResponse, PlatformError};
use serde_json::{json, Value};

struct HttpStub {
    response: Mutex<Option<OutboundHttpResponse>>,
    request: Mutex<Option<OutboundHttpRequest>>,
}

#[async_trait]
impl OutboundHttpClient for HttpStub {
    async fn execute(
        &self,
        request: OutboundHttpRequest,
    ) -> Result<OutboundHttpResponse, PlatformError> {
        *self.request.lock().unwrap() = Some(request);
        Ok(self.response.lock().unwrap().take().unwrap())
    }
}

struct Provider(Value);

#[async_trait]
impl CanvasExperienceSessionProvider for Provider {
    async fn by_state(&self, _state: &str) -> Result<Value, PortError> {
        Ok(self.0.clone())
    }

    async fn current(&self, token: &str) -> Result<Value, PortError> {
        assert_eq!(token, "experience-token");
        Ok(self.0.clone())
    }
}

#[derive(Default)]
struct Sessions(Mutex<Vec<Session>>);

#[async_trait]
impl SessionRepository for Sessions {
    async fn save(&self, session: &Session) -> Result<(), PortError> {
        self.0.lock().unwrap().push(session.clone());
        Ok(())
    }
    async fn get(&self, _: &str) -> Result<Option<Session>, PortError> {
        Ok(None)
    }
    async fn delete(&self, _: &str) -> Result<(), PortError> {
        Ok(())
    }
    async fn get_by_user(&self, _: &str) -> Result<Vec<Session>, PortError> {
        Ok(Vec::new())
    }
    async fn delete_all_for_user(&self, _: &str) -> Result<usize, PortError> {
        Ok(0)
    }
}

#[tokio::test]
async fn canvas_http_transport_is_bounded_bearer_bound_and_status_aware() {
    let http = Arc::new(HttpStub {
        response: Mutex::new(Some(OutboundHttpResponse {
            status: 200,
            headers: Default::default(),
            body: serde_json::to_vec(&json!({"learner_key": "learner-1"})).unwrap(),
        })),
        request: Mutex::new(None),
    });
    let provider =
        HttpCanvasExperienceSessionProvider::new(http.clone(), "http://issuance:8005/base/")
            .unwrap();
    assert_eq!(
        provider.current("experience-token").await.unwrap()["learner_key"],
        "learner-1"
    );
    let request = http.request.lock().unwrap().clone().unwrap();
    assert_eq!(
        request.url,
        "http://issuance:8005/base/v1/integrations/canvas/lti/experience-sessions/current"
    );
    assert_eq!(request.headers["authorization"], "Bearer experience-token");
    assert_eq!(request.maximum_response_bytes, 1024 * 1024);

    let unauthorized = Arc::new(HttpStub {
        response: Mutex::new(Some(OutboundHttpResponse {
            status: 401,
            headers: Default::default(),
            body: Vec::new(),
        })),
        request: Mutex::new(None),
    });
    let provider =
        HttpCanvasExperienceSessionProvider::new(unauthorized, "https://issuer.test").unwrap();
    assert_eq!(
        provider.current("expired").await.unwrap_err().code,
        "canvas_lti_session_expired"
    );
}

#[tokio::test]
async fn canvas_finalize_creates_the_constrained_session_and_org_shape() {
    let sessions = Arc::new(Sessions::default());
    let app = CanvasLtiApplication::new(
        Arc::new(Provider(json!({
            "organization_id": "org-1",
            "canvas_account_id": "canvas",
            "learner_key": "learner-key-1",
            "learner_display_name": "Canvas Learner"
        }))),
        sessions.clone(),
        None,
        3_600,
    )
    .unwrap();
    let now = Utc.with_ymd_and_hms(2026, 8, 21, 12, 0, 0).unwrap();
    let session = app
        .finalize(
            &CanvasFinalizeContext {
                bearer_token: "experience-token".into(),
                ip_address: Some("127.0.0.1".into()),
                user_agent: Some("canvas-test".into()),
            },
            now,
        )
        .await
        .unwrap();
    assert_eq!(session.user.roles, ["applicant", "canvas_lti_learner"]);
    assert_eq!(session.user.organization_id.as_deref(), Some("org-1"));
    assert_eq!(
        session.user.organization.as_ref().unwrap()["org-1"]["source"],
        "canvas_lti"
    );
    assert_eq!(session.expires_at.timestamp() - now.timestamp(), 3_600);
    assert_eq!(sessions.0.lock().unwrap().len(), 1);
}

#[test]
fn canvas_transport_rejects_credentialed_or_non_http_origins() {
    let http = Arc::new(HttpStub {
        response: Mutex::new(None),
        request: Mutex::new(None),
    });
    for url in ["file:///tmp/issuer", "https://user:pass@issuer.test"] {
        assert!(HttpCanvasExperienceSessionProvider::new(http.clone(), url).is_err());
    }
}

#[test]
fn canvas_application_rejects_non_positive_session_ttl() {
    let provider: Arc<dyn CanvasExperienceSessionProvider> = Arc::new(Provider(json!({})));
    let sessions: Arc<dyn SessionRepository> = Arc::new(Sessions::default());

    let error = CanvasLtiApplication::new(provider, sessions, None, 0)
        .err()
        .expect("zero TTL must fail closed");

    assert_eq!(error.code, "canvas_lti_configuration_invalid");
}
