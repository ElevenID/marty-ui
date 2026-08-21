use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use marty_auth::{
    AuthApplication, AuthApplicationConfig, AuthApplicationError, AuthApplicationPorts,
    AuthAuditSink, AuthEvent, AuthEventPublisher, AuthenticatedUser, HandleCallbackCommand,
    InitiateLoginCommand, OidcAuthorizationRequest, OidcCodeExchange, OidcLogoutRequest,
    OidcProvider, OidcTokenSet, OidcUserInfo, OidcValidatedIdentity, PkceState,
    PkceStateRepository, PortError, Session, SessionRepository, SessionSpec, UserProvisioner,
    UserType,
};
use serde_json::json;

fn now() -> DateTime<Utc> {
    "2026-08-20T12:00:00Z".parse().expect("timestamp")
}

fn user() -> AuthenticatedUser {
    AuthenticatedUser {
        user_id: "user-1".to_owned(),
        email: "alice@example.com".to_owned(),
        username: Some("alice".to_owned()),
        given_name: Some("Alice".to_owned()),
        family_name: Some("Smith".to_owned()),
        user_type: UserType::Applicant,
        applicant_id: Some("applicant-1".to_owned()),
        roles: vec!["applicant".to_owned()],
        organization_id: Some("org-1".to_owned()),
        organization_name: Some("Acme".to_owned()),
        organization: None,
        default_organization_id: Some("org-1".to_owned()),
        default_organization_name: Some("Acme".to_owned()),
        organizations: Vec::new(),
        organization_context_unavailable: false,
        organization_context_error: None,
        onboarding_completed: None,
        picture: None,
        impersonation: None,
        did_subject: None,
    }
}

#[derive(Default)]
struct MemorySessions(Mutex<HashMap<String, Session>>);

#[async_trait]
impl SessionRepository for MemorySessions {
    async fn save(&self, session: &Session) -> Result<(), PortError> {
        self.0
            .lock()
            .expect("sessions lock")
            .insert(session.session_id.clone(), session.clone());
        Ok(())
    }

    async fn get(&self, session_id: &str) -> Result<Option<Session>, PortError> {
        Ok(self
            .0
            .lock()
            .expect("sessions lock")
            .get(session_id)
            .cloned())
    }

    async fn delete(&self, session_id: &str) -> Result<(), PortError> {
        self.0.lock().expect("sessions lock").remove(session_id);
        Ok(())
    }

    async fn get_by_user(&self, user_id: &str) -> Result<Vec<Session>, PortError> {
        Ok(self
            .0
            .lock()
            .expect("sessions lock")
            .values()
            .filter(|session| session.user.user_id == user_id)
            .cloned()
            .collect())
    }

    async fn delete_all_for_user(&self, user_id: &str) -> Result<usize, PortError> {
        let mut sessions = self.0.lock().expect("sessions lock");
        let before = sessions.len();
        sessions.retain(|_, session| session.user.user_id != user_id);
        Ok(before - sessions.len())
    }
}

#[derive(Default)]
struct MemoryStates(Mutex<HashMap<String, PkceState>>);

#[async_trait]
impl PkceStateRepository for MemoryStates {
    async fn save(&self, state: &PkceState) -> Result<(), PortError> {
        self.0
            .lock()
            .expect("states lock")
            .insert(state.state.clone(), state.clone());
        Ok(())
    }

    async fn take(&self, state: &str) -> Result<Option<PkceState>, PortError> {
        Ok(self.0.lock().expect("states lock").remove(state))
    }
}

#[derive(Default)]
struct FakeOidc {
    authorization: Mutex<Option<OidcAuthorizationRequest>>,
    validated_nonce: Mutex<Option<String>>,
}

#[async_trait]
impl OidcProvider for FakeOidc {
    fn authorization_url(&self, request: &OidcAuthorizationRequest) -> Result<String, PortError> {
        *self.authorization.lock().expect("authorization lock") = Some(request.clone());
        Ok(format!(
            "https://login.example/auth?state={}",
            request.state
        ))
    }

    async fn exchange_code(&self, _request: &OidcCodeExchange) -> Result<OidcTokenSet, PortError> {
        Ok(OidcTokenSet {
            access_token: "access-token".to_owned(),
            id_token: Some("id-token".to_owned()),
            refresh_token: Some("refresh-token".to_owned()),
        })
    }

    async fn validate_tokens(
        &self,
        _id_token: &str,
        _access_token: &str,
        expected_nonce: &str,
    ) -> Result<OidcValidatedIdentity, PortError> {
        *self.validated_nonce.lock().expect("nonce lock") = Some(expected_nonce.to_owned());
        let claims = json!({"sub": "user-1", "email": "alice@example.com", "trusted": true});
        Ok(OidcValidatedIdentity {
            user_info: OidcUserInfo::from_claims(&claims, None),
            id_token_claims: claims,
            access_token_claims: json!({"sub": "user-1"}),
        })
    }

    fn logout_url(&self, request: &OidcLogoutRequest) -> Result<Option<String>, PortError> {
        Ok(request
            .id_token
            .as_ref()
            .map(|_| "https://login.example/logout".to_owned()))
    }
}

struct FakeProvisioner;

#[async_trait]
impl UserProvisioner for FakeProvisioner {
    async fn provision(
        &self,
        _identity: &OidcValidatedIdentity,
    ) -> Result<AuthenticatedUser, PortError> {
        Ok(user())
    }
}

#[derive(Default)]
struct MemoryEvents(Mutex<Vec<AuthEvent>>);

#[async_trait]
impl AuthEventPublisher for MemoryEvents {
    async fn publish(&self, event: &AuthEvent) -> Result<(), PortError> {
        self.0.lock().expect("events lock").push(event.clone());
        Ok(())
    }
}

struct FailingAudit;

#[async_trait]
impl AuthAuditSink for FailingAudit {
    async fn record_authentication(
        &self,
        _session: &Session,
        _method: &str,
    ) -> Result<(), PortError> {
        Err(PortError::new("audit_unavailable", "audit offline"))
    }

    async fn record_logout(&self, _session: &Session) -> Result<(), PortError> {
        Err(PortError::new("audit_unavailable", "audit offline"))
    }
}

struct Harness {
    app: AuthApplication,
    sessions: Arc<MemorySessions>,
    states: Arc<MemoryStates>,
    oidc: Arc<FakeOidc>,
    events: Arc<MemoryEvents>,
}

fn harness() -> Harness {
    let sessions = Arc::new(MemorySessions::default());
    let states = Arc::new(MemoryStates::default());
    let oidc = Arc::new(FakeOidc::default());
    let events = Arc::new(MemoryEvents::default());
    let app = AuthApplication::new(
        AuthApplicationPorts {
            sessions: sessions.clone(),
            pkce_states: states.clone(),
            oidc: oidc.clone(),
            provisioner: Arc::new(FakeProvisioner),
            events: events.clone(),
            audit: Some(Arc::new(FailingAudit)),
        },
        AuthApplicationConfig {
            session_ttl_seconds: 86_400,
            post_logout_redirect_uri: "https://ui.example/".to_owned(),
        },
    );
    Harness {
        app,
        sessions,
        states,
        oidc,
        events,
    }
}

#[tokio::test]
async fn login_and_callback_bind_nonce_consume_state_and_persist_only_validated_claims() {
    let harness = harness();
    let initiated = harness
        .app
        .initiate_login(
            InitiateLoginCommand {
                redirect_uri: Some("/console".to_owned()),
                oidc_redirect_uri: Some("https://ui.example/v1/auth/callback".to_owned()),
            },
            now(),
        )
        .await
        .expect("initiate login");
    let request = harness
        .oidc
        .authorization
        .lock()
        .expect("authorization lock")
        .clone()
        .expect("request");
    assert!(!request.registration);
    assert!(!request.nonce.is_empty());
    assert!(!request.code_challenge.is_empty());

    let result = harness
        .app
        .handle_callback(
            HandleCallbackCommand {
                code: "code-1".to_owned(),
                state: initiated.state.clone(),
                ip_address: Some("127.0.0.1".to_owned()),
                user_agent: Some("browser".to_owned()),
            },
            now(),
        )
        .await
        .expect("callback");
    assert_eq!(result.redirect_uri, "/console");
    assert_eq!(
        result.session.oidc_claims,
        Some(json!({"sub": "user-1", "email": "alice@example.com", "trusted": true}))
    );
    assert_eq!(
        *harness.oidc.validated_nonce.lock().expect("nonce lock"),
        Some(request.nonce)
    );
    assert!(
        result.audit_warning.is_some(),
        "audit failures remain observable but do not discard a valid login"
    );
    assert_eq!(harness.events.0.lock().expect("events lock").len(), 2);
    assert!(harness
        .sessions
        .0
        .lock()
        .expect("sessions lock")
        .contains_key(&result.session.session_id));

    let replay = harness
        .app
        .handle_callback(
            HandleCallbackCommand {
                code: "code-2".to_owned(),
                state: initiated.state,
                ip_address: None,
                user_agent: None,
            },
            now(),
        )
        .await
        .expect_err("state replay must fail");
    assert!(matches!(replay, AuthApplicationError::InvalidState));
}

#[tokio::test]
async fn pre_cutover_state_without_nonce_fails_closed_after_single_use_consumption() {
    let harness = harness();
    harness
        .states
        .save(&PkceState {
            state: "legacy".to_owned(),
            code_verifier: "verifier".to_owned(),
            redirect_uri: "/".to_owned(),
            oidc_redirect_uri: None,
            nonce: None,
            created_at: now(),
            expires_at: now() + Duration::minutes(5),
        })
        .await
        .expect("seed state");
    let error = harness
        .app
        .handle_callback(
            HandleCallbackCommand {
                code: "code".to_owned(),
                state: "legacy".to_owned(),
                ip_address: None,
                user_agent: None,
            },
            now(),
        )
        .await
        .expect_err("missing nonce must fail");
    assert!(matches!(error, AuthApplicationError::MissingNonce));
    assert!(!harness
        .states
        .0
        .lock()
        .expect("states lock")
        .contains_key("legacy"));
}

#[tokio::test]
async fn validation_touches_active_sessions_and_deletes_invalid_sessions() {
    let harness = harness();
    let session = Session::create(SessionSpec {
        user: user(),
        ttl_seconds: 60,
        now: now(),
        ip_address: None,
        user_agent: None,
        id_token: None,
        refresh_token: None,
        oidc_claims: None,
    });
    harness
        .sessions
        .save(&session)
        .await
        .expect("seed active session");
    let touched_at = now() + Duration::seconds(10);
    let valid = harness
        .app
        .validate_session(&session.session_id, touched_at)
        .await
        .expect("validate")
        .expect("active");
    assert_eq!(valid.last_activity, touched_at);

    let mut revoked = session.clone();
    revoked.session_id = "revoked".to_owned();
    revoked.revoke();
    harness
        .sessions
        .save(&revoked)
        .await
        .expect("seed revoked session");
    assert!(harness
        .app
        .validate_session("revoked", now())
        .await
        .expect("validate revoked")
        .is_none());
    assert!(!harness
        .sessions
        .0
        .lock()
        .expect("sessions lock")
        .contains_key("revoked"));
}

#[tokio::test]
async fn logout_is_idempotent_and_emits_both_domain_events() {
    let harness = harness();
    let session = Session::create(SessionSpec {
        user: user(),
        ttl_seconds: 60,
        now: now(),
        ip_address: None,
        user_agent: None,
        id_token: Some("id-token".to_owned()),
        refresh_token: None,
        oidc_claims: None,
    });
    harness.sessions.save(&session).await.expect("seed session");
    let result = harness
        .app
        .logout(&session.session_id)
        .await
        .expect("logout");
    assert_eq!(
        result.sso_logout_url.as_deref(),
        Some("https://login.example/logout")
    );
    assert!(result.audit_warning.is_some());
    assert_eq!(harness.events.0.lock().expect("events lock").len(), 2);
    assert!(!harness
        .sessions
        .0
        .lock()
        .expect("sessions lock")
        .contains_key(&session.session_id));

    let repeated = harness
        .app
        .logout(&session.session_id)
        .await
        .expect("repeated logout");
    assert!(repeated.success);
    assert!(repeated.sso_logout_url.is_none());
    assert_eq!(harness.events.0.lock().expect("events lock").len(), 2);
}
