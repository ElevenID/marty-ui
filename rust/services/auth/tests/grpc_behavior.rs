use std::{collections::BTreeSet, sync::Arc};

use async_trait::async_trait;
use chrono::{Duration, Utc};
use marty_auth::{
    auth_proto::{
        auth_service_server::AuthService, CreateSessionRequest, CredentialVerifiedRequest,
        GetAuthStatusRequest, HealthCheckRequest, InvalidateSessionRequest, ValidateSessionRequest,
    },
    AuthGrpcService, AuthSessionService, AuthenticatedUser, Session, SessionSpec, UserType,
    AUTH_GRPC_METHODS,
};
use serde_json::Value;
use tonic::{Code, Request, Status};

struct SessionStub {
    session: Option<Session>,
}

#[async_trait]
impl AuthSessionService for SessionStub {
    async fn validate_session(&self, session_id: &str) -> Result<Option<Session>, Status> {
        Ok(self
            .session
            .as_ref()
            .filter(|session| session.session_id == session_id)
            .cloned())
    }

    async fn invalidate_session(&self, session_id: &str) -> Result<bool, Status> {
        Ok(self
            .session
            .as_ref()
            .is_some_and(|session| session.session_id == session_id))
    }
}

fn session() -> Session {
    let now = Utc::now();
    let mut session = Session::create(SessionSpec {
        user: AuthenticatedUser {
            user_id: "user-1".into(),
            email: "alice@example.com".into(),
            username: Some("alice".into()),
            given_name: Some("Alice".into()),
            family_name: Some("Smith".into()),
            user_type: UserType::Administrator,
            applicant_id: Some("applicant-1".into()),
            roles: vec!["admin".into()],
            organization_id: Some("org-1".into()),
            organization_name: Some("Acme".into()),
            organization: None,
            default_organization_id: None,
            default_organization_name: None,
            organizations: Vec::new(),
            organization_context_unavailable: false,
            organization_context_error: None,
            onboarding_completed: Some(now - Duration::minutes(1)),
            picture: Some("https://example.test/alice.png".into()),
            impersonation: None,
            did_subject: None,
        },
        ttl_seconds: 3_600,
        now,
        ip_address: None,
        user_agent: None,
        id_token: None,
        refresh_token: None,
        oidc_claims: None,
    });
    session.session_id = "session-1".into();
    session
}

fn service(session: Option<Session>) -> AuthGrpcService {
    AuthGrpcService::new(Arc::new(SessionStub { session }))
}

#[test]
fn grpc_surface_matches_the_language_neutral_contract() {
    let contract: Value =
        serde_json::from_str(include_str!("../../../../contracts/auth-behavior.json"))
            .expect("valid auth contract");
    let expected = contract["grpc_methods"]
        .as_array()
        .unwrap()
        .iter()
        .map(|method| method["name"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        AUTH_GRPC_METHODS.iter().copied().collect::<BTreeSet<_>>(),
        expected
    );
}

#[tokio::test]
async fn validation_status_and_invalidation_preserve_the_session_contract() {
    let service = service(Some(session()));
    let validated = service
        .validate_session(Request::new(ValidateSessionRequest {
            session_id: "session-1".into(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(validated.valid);
    assert!(!validated.expires_at.is_empty());
    let user = validated.user.unwrap();
    assert_eq!(user.user_id, "user-1");
    assert_eq!(user.user_type, "administrator");
    assert_eq!(user.roles, ["admin"]);
    assert_eq!(user.organization_id, "org-1");
    assert!(user.onboarding_completed);

    let status = service
        .get_auth_status(Request::new(GetAuthStatusRequest {
            session_id: "session-1".into(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(status.authenticated);
    assert_eq!(status.user.unwrap().email, "alice@example.com");

    let invalidated = service
        .invalidate_session(Request::new(InvalidateSessionRequest {
            session_id: "session-1".into(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(invalidated.success);

    let missing = service
        .validate_session(Request::new(ValidateSessionRequest {
            session_id: "missing".into(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(!missing.valid);
    assert!(missing.user.is_none());
}

#[tokio::test]
async fn retired_mutation_rpcs_fail_with_unimplemented_and_health_is_serving() {
    let service = service(None);
    let create = service
        .create_session(Request::new(CreateSessionRequest::default()))
        .await
        .unwrap_err();
    assert_eq!(create.code(), Code::Unimplemented);
    assert!(create.message().contains("authoritative login flow"));

    let callback = service
        .credential_verified(Request::new(CredentialVerifiedRequest::default()))
        .await
        .unwrap_err();
    assert_eq!(callback.code(), Code::Unimplemented);
    assert!(callback
        .message()
        .contains("authenticated internal HTTP callback"));

    let health = service
        .health_check(Request::new(HealthCheckRequest {}))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(health.status, "serving");
}
