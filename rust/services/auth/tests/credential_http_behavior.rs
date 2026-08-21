use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{TimeZone as _, Utc};
use marty_auth::{
    CredentialCallbackApplication, CredentialCallbackConfig, CredentialCallbackPolicy,
    CredentialHttpError, CredentialLoginHttpApplication, CredentialLoginPageInput,
    CredentialLoginPageRenderer, CredentialLoginPoll, CredentialLoginStartConfig,
    CredentialLoginStateStore, CredentialVerificationFlow, CredentialVerificationStarter,
    PortError, Session, SessionRepository, StartCredentialVerification,
};
use mmf_data::MemoryCache;

#[derive(Default)]
struct Sessions;

#[async_trait]
impl SessionRepository for Sessions {
    async fn save(&self, _: &Session) -> Result<(), PortError> {
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

struct FlowStub {
    request: Mutex<Option<StartCredentialVerification>>,
    response: CredentialVerificationFlow,
}

#[async_trait]
impl CredentialVerificationStarter for FlowStub {
    async fn start(
        &self,
        request: &StartCredentialVerification,
    ) -> Result<CredentialVerificationFlow, PortError> {
        *self.request.lock().unwrap() = Some(request.clone());
        Ok(self.response.clone())
    }
}

struct Renderer;

impl CredentialLoginPageRenderer for Renderer {
    fn render(&self, input: &CredentialLoginPageInput) -> Result<String, PortError> {
        Ok(format!(
            "<html data-nonce=\"{}\" data-flow=\"{}\">{}</html>",
            input.nonce, input.flow_instance_id, input.oid4vp_uri
        ))
    }
}

fn application(
    flow: Arc<FlowStub>,
) -> (
    CredentialLoginHttpApplication,
    Arc<CredentialLoginStateStore>,
) {
    let policy = CredentialCallbackPolicy {
        secret: "test-flow-webhook-secret-at-least-32-bytes".into(),
        expected_policy_id: "policy-1".into(),
        expected_organization_id: "org-1".into(),
        maximum_timestamp_skew_seconds: 300,
        pending_ttl_seconds: 900,
        completion_ttl_seconds: 300,
        claim_lease_seconds: 30,
    };
    let state =
        Arc::new(CredentialLoginStateStore::new(Arc::new(MemoryCache::default()), policy).unwrap());
    let callback = Arc::new(CredentialCallbackApplication::new(
        state.clone(),
        Arc::new(Sessions),
        None,
        None,
        CredentialCallbackConfig {
            default_organization_id: "org-1".into(),
            session_ttl_seconds: 86_400,
            require_existing_keycloak_user: false,
            create_keycloak_users: false,
        },
    ));
    let application = CredentialLoginHttpApplication::new(
        state.clone(),
        callback,
        flow,
        Arc::new(Renderer),
        CredentialLoginStartConfig {
            presentation_policy_id: "policy-1".into(),
            organization_id: "org-1".into(),
            issuer_did: "did:web:issuer.example".into(),
            auth_service_internal_url: "http://auth:8001/base/".into(),
        },
    )
    .unwrap();
    (application, state)
}

#[tokio::test]
async fn start_binds_flow_callback_persists_pending_state_and_renders_page() {
    let flow = Arc::new(FlowStub {
        request: Mutex::new(None),
        response: CredentialVerificationFlow {
            instance_id: "flow-1".into(),
            request_uri: "openid4vp://authorize?request_uri=https%3A%2F%2Fflow%2Frequest".into(),
            qr_code_data: String::new(),
        },
    });
    let (application, _) = application(flow.clone());
    let now = Utc.with_ymd_and_hms(2026, 8, 21, 12, 0, 0).unwrap();
    let result = application.start(now).await.unwrap();
    assert!(result.html.contains(&result.nonce));
    assert!(result.html.contains("flow-1"));
    let request = flow.request.lock().unwrap().clone().unwrap();
    assert_eq!(request.presentation_policy_id, "policy-1");
    assert_eq!(request.organization_id, "org-1");
    assert_eq!(request.issuer_did, "did:web:issuer.example");
    assert_eq!(request.user_id, "auth-service");
    assert_eq!(
        request.callback_url,
        format!(
            "http://auth:8001/base/internal/v1/auth/credential-verified?nonce={}",
            result.nonce
        )
    );
    assert!(matches!(
        application.poll(&result.nonce, now).await.unwrap(),
        CredentialLoginPoll::Pending
    ));
}

#[tokio::test]
async fn malformed_flow_success_fails_closed_without_rendering_completion() {
    let flow = Arc::new(FlowStub {
        request: Mutex::new(None),
        response: CredentialVerificationFlow {
            instance_id: "flow-1".into(),
            request_uri: String::new(),
            qr_code_data: String::new(),
        },
    });
    let (application, _) = application(flow);
    assert!(matches!(
        application.start(Utc::now()).await,
        Err(CredentialHttpError::Unavailable(_))
    ));
}

#[test]
fn unsafe_or_incomplete_start_configuration_is_rejected() {
    for url in ["file:///tmp/auth", "https://user:pass@auth.example"] {
        let config = CredentialLoginStartConfig {
            presentation_policy_id: "policy-1".into(),
            organization_id: "org-1".into(),
            issuer_did: "did:web:issuer.example".into(),
            auth_service_internal_url: url.into(),
        };
        assert!(config.validate().is_err());
    }
}
