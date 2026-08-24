use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
};
use chrono::Utc;
use marty_auth::{
    auth_core_router, AuthHttpApplication, AuthHttpState, AuthenticatedUser, CanvasFinalizeContext,
    CanvasHttpApplication, CredentialCallbackContext, CredentialCallbackHeaders,
    CredentialCallbackResult, CredentialHttpError, CredentialLoginCompletion,
    CredentialLoginHttpService, CredentialLoginPoll, CredentialLoginStartResult,
    CredentialVerifiedPayload, HandleCallbackCommand, HandleCallbackResult, PortError, Session,
    SessionCookieConfig, SessionRepository, SessionSpec, UiOriginPolicy, UserType,
    AUTH_CORE_HTTP_ROUTES, AUTH_CREDENTIAL_HTTP_ROUTES,
};
use serde_json::Value;
use tower::ServiceExt as _;

#[derive(Default)]
struct AppStub {
    initiated: Mutex<Vec<(bool, String, String)>>,
    session: Mutex<Option<Session>>,
    callback_error: Mutex<Option<PortError>>,
}

#[async_trait]
impl AuthHttpApplication for AppStub {
    async fn initiate(
        &self,
        registration: bool,
        redirect_uri: String,
        oidc_redirect_uri: String,
    ) -> Result<String, PortError> {
        self.initiated
            .lock()
            .unwrap()
            .push((registration, redirect_uri, oidc_redirect_uri));
        Ok("https://identity.example/authorize".into())
    }

    async fn callback(&self, _: HandleCallbackCommand) -> Result<HandleCallbackResult, PortError> {
        if let Some(error) = self.callback_error.lock().unwrap().take() {
            return Err(error);
        }
        Ok(HandleCallbackResult {
            session: self.session.lock().unwrap().clone().unwrap(),
            redirect_uri: "/".into(),
            audit_warning: None,
        })
    }

    async fn logout(&self, _: &str) -> Result<Option<String>, PortError> {
        Ok(Some("https://identity.example/logout".into()))
    }

    async fn validate_session(&self, session_id: &str) -> Result<Option<Session>, PortError> {
        Ok(self
            .session
            .lock()
            .unwrap()
            .as_ref()
            .filter(|session| session.session_id == session_id)
            .cloned())
    }
}

struct CanvasStub(Session);

#[async_trait]
impl CanvasHttpApplication for CanvasStub {
    async fn finalize(&self, context: &CanvasFinalizeContext) -> Result<Session, PortError> {
        assert_eq!(context.bearer_token, "canvas-token");
        Ok(self.0.clone())
    }
}

struct CredentialStub;

#[async_trait]
impl CredentialLoginHttpService for CredentialStub {
    async fn start_login(&self) -> Result<CredentialLoginStartResult, CredentialHttpError> {
        Ok(CredentialLoginStartResult {
            nonce: "nonce-1".into(),
            html: "<!doctype html><title>Credential login</title>".into(),
        })
    }

    async fn poll_login(&self, nonce: &str) -> Result<CredentialLoginPoll, CredentialHttpError> {
        Ok(match nonce {
            "completed" => CredentialLoginPoll::Completed {
                redirect_to: "/v1/auth/credential-login/finalize?nonce=completed".into(),
                revocation_checked: true,
                revocation_status: "valid".into(),
            },
            "expired" => CredentialLoginPoll::Expired,
            _ => CredentialLoginPoll::Pending,
        })
    }

    async fn finalize_login(
        &self,
        nonce: &str,
    ) -> Result<Option<CredentialLoginCompletion>, CredentialHttpError> {
        Ok(match nonce {
            "completed" => Some(completion("completed", Some("session-1"))),
            "failed" => Some(CredentialLoginCompletion {
                status: "failed".into(),
                session_id: None,
                reason_code: Some("issuer_not_trusted".into()),
                message: Some("Issuer is not trusted".into()),
                reason: None,
                detail: Some("trust profile mismatch".into()),
                revocation_checked: false,
                revocation_status: "unknown".into(),
            }),
            _ => None,
        })
    }

    async fn verified_callback(
        &self,
        payload: &CredentialVerifiedPayload,
        _: &CredentialCallbackHeaders,
        context: &CredentialCallbackContext,
    ) -> Result<CredentialCallbackResult, CredentialHttpError> {
        assert_eq!(payload.flow_instance_id, "flow-1");
        assert_eq!(context.nonce, "nonce-1");
        Ok(CredentialCallbackResult::Completed {
            session_id: "session-1".into(),
        })
    }
}

fn completion(status: &str, session_id: Option<&str>) -> CredentialLoginCompletion {
    CredentialLoginCompletion {
        status: status.into(),
        session_id: session_id.map(str::to_owned),
        reason_code: None,
        message: None,
        reason: None,
        detail: None,
        revocation_checked: true,
        revocation_status: "valid".into(),
    }
}

#[derive(Default)]
struct Sessions(Mutex<Option<Session>>);

#[async_trait]
impl SessionRepository for Sessions {
    async fn save(&self, session: &Session) -> Result<(), PortError> {
        *self.0.lock().unwrap() = Some(session.clone());
        Ok(())
    }
    async fn get(&self, session_id: &str) -> Result<Option<Session>, PortError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .as_ref()
            .filter(|session| session.session_id == session_id)
            .cloned())
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

fn session() -> Session {
    let mut session = Session::create(SessionSpec {
        user: AuthenticatedUser {
            user_id: "user-1".into(),
            email: "alice@example.com".into(),
            username: Some("alice".into()),
            given_name: Some("Alice".into()),
            family_name: None,
            user_type: UserType::Applicant,
            applicant_id: None,
            roles: vec!["applicant".into()],
            organization_id: Some("org-1".into()),
            organization_name: Some("Acme".into()),
            organization: None,
            default_organization_id: None,
            default_organization_name: None,
            organizations: Vec::new(),
            organization_context_unavailable: false,
            organization_context_error: None,
            onboarding_completed: None,
            picture: None,
            impersonation: None,
            did_subject: None,
        },
        ttl_seconds: 3_600,
        now: Utc::now(),
        ip_address: None,
        user_agent: None,
        id_token: None,
        refresh_token: None,
        oidc_claims: None,
    });
    session.session_id = "session-1".into();
    session
}

fn harness() -> (axum::Router, Arc<AppStub>, Arc<Sessions>) {
    let app = Arc::new(AppStub::default());
    *app.session.lock().unwrap() = Some(session());
    let sessions = Arc::new(Sessions::default());
    *sessions.0.lock().unwrap() = Some(session());
    let router = auth_core_router(AuthHttpState {
        application: app.clone(),
        canvas: Arc::new(CanvasStub(session())),
        credential_login: Arc::new(CredentialStub),
        sessions: sessions.clone(),
        origins: UiOriginPolicy::new("https://elevenidllc.com", ["https://beta.elevenidllc.com"])
            .unwrap(),
        cookie: SessionCookieConfig {
            name: "sessionId".into(),
            secure: true,
            same_site: "lax".into(),
            maximum_age_seconds: 86_400,
            path: "/".into(),
        },
        canvas_session_ttl_seconds: 3_600,
        impersonation_handoff_cookie_name: "marty_impersonation_handoff".into(),
    })
    .unwrap();
    (router, app, sessions)
}

async fn request(
    router: &axum::Router,
    method: Method,
    uri: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> axum::response::Response {
    let mut request = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    router
        .clone()
        .oneshot(request.body(Body::from(body.to_owned())).unwrap())
        .await
        .unwrap()
}

#[test]
fn core_surface_is_the_exact_non_credential_route_subset() {
    let contract: Value =
        serde_json::from_str(include_str!("../../../../contracts/auth-behavior.json")).unwrap();
    let expected = contract["http_routes"].as_array().unwrap()[..8]
        .iter()
        .map(|route| {
            (
                route["method"].as_str().unwrap(),
                route["path"].as_str().unwrap(),
            )
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        AUTH_CORE_HTTP_ROUTES
            .iter()
            .copied()
            .collect::<BTreeSet<_>>(),
        expected
    );
}

#[test]
fn combined_surface_matches_all_fourteen_frozen_routes() {
    let contract: Value =
        serde_json::from_str(include_str!("../../../../contracts/auth-behavior.json")).unwrap();
    let expected = contract["http_routes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|route| {
            (
                route["method"].as_str().unwrap(),
                route["path"].as_str().unwrap(),
            )
        })
        .collect::<BTreeSet<_>>();
    let actual = AUTH_CORE_HTTP_ROUTES
        .iter()
        .chain(AUTH_CREDENTIAL_HTTP_ROUTES)
        .copied()
        .collect::<BTreeSet<_>>();
    assert_eq!(actual, expected);
}

#[tokio::test]
async fn credential_routes_preserve_assets_poll_finalize_and_callback_behavior() {
    let (router, _, _) = harness();
    for (path, content_type) in [
        ("/v1/auth/credential-login/assets/styles.css", "text/css"),
        (
            "/v1/auth/credential-login/assets/app.js",
            "application/javascript",
        ),
    ] {
        let response = request(&router, Method::GET, path, &[], "").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers()[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with(content_type));
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "no-store, max-age=0"
        );
    }

    let page = request(&router, Method::GET, "/v1/auth/credential-login", &[], "").await;
    assert_eq!(page.status(), StatusCode::OK);
    assert!(page.headers()[header::CONTENT_TYPE]
        .to_str()
        .unwrap()
        .starts_with("text/html"));

    let poll = request(
        &router,
        Method::GET,
        "/v1/auth/credential-login/status?nonce=completed",
        &[],
        "",
    )
    .await;
    let poll: Value =
        serde_json::from_slice(&to_bytes(poll.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(poll["status"], "completed");
    assert_eq!(poll["revocation_status"], "valid");

    let finalized = request(
        &router,
        Method::GET,
        "/v1/auth/credential-login/finalize?nonce=completed",
        &[],
        "",
    )
    .await;
    assert_eq!(finalized.status(), StatusCode::FOUND);
    assert_eq!(
        finalized.headers()[header::LOCATION],
        "https://elevenidllc.com/console"
    );
    assert!(finalized.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .contains("sessionId=session-1"));

    let failed = request(
        &router,
        Method::GET,
        "/v1/auth/credential-login/finalize?nonce=failed",
        &[],
        "",
    )
    .await;
    let location = failed.headers()[header::LOCATION].to_str().unwrap();
    assert!(location.contains("auth_error=Issuer+is+not+trusted"));
    assert!(location.contains("auth_error_code=issuer_not_trusted"));

    let payload = serde_json::json!({
        "flow_instance_id": "flow-1",
        "result": "passed",
        "decision": "allow",
        "verified_claims": {"email": "alice@example.com"},
        "evidence_digest": "a".repeat(64),
        "decision_digest": "b".repeat(64)
    });
    let callback = request(
        &router,
        Method::POST,
        "/internal/v1/auth/credential-verified?nonce=nonce-1",
        &[("content-type", "application/json")],
        &payload.to_string(),
    )
    .await;
    assert_eq!(callback.status(), StatusCode::OK);
    let callback: Value =
        serde_json::from_slice(&to_bytes(callback.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(callback["status"], "completed");
    assert_eq!(callback["session_id"], "session-1");
}

#[tokio::test]
async fn login_registration_and_canvas_preserve_redirect_auth_and_cookie_behavior() {
    let (router, app, _) = harness();
    let login = request(
        &router,
        Method::GET,
        "/v1/auth/login?redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fconsole%2Fapps%3Fsecret%3D1",
        &[
            ("x-forwarded-host", "beta.elevenidllc.com"),
            ("x-forwarded-proto", "https"),
        ],
        "",
    )
    .await;
    assert_eq!(login.status(), StatusCode::FOUND);
    assert_eq!(
        login.headers()[header::LOCATION],
        "https://identity.example/authorize"
    );
    assert_eq!(
        app.initiated.lock().unwrap()[0],
        (
            false,
            "/console/apps".into(),
            "https://beta.elevenidllc.com/v1/auth/callback".into(),
        )
    );

    let register = request(&router, Method::GET, "/v1/auth/register", &[], "").await;
    assert_eq!(register.status(), StatusCode::FOUND);
    assert!(app.initiated.lock().unwrap()[1].0);

    let legacy = request(
        &router,
        Method::GET,
        "/v1/auth/canvas-lti/finalize",
        &[],
        "",
    )
    .await;
    assert_eq!(legacy.status(), StatusCode::GONE);
    let unauthorized = request(
        &router,
        Method::POST,
        "/v1/auth/canvas-lti/finalize",
        &[],
        "",
    )
    .await;
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
    let canvas = request(
        &router,
        Method::POST,
        "/v1/auth/canvas-lti/finalize",
        &[("authorization", "Bearer canvas-token")],
        "",
    )
    .await;
    assert_eq!(canvas.status(), StatusCode::OK);
    assert!(canvas
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .any(|value| value.to_str().unwrap().contains("sessionId=session-1")));
}

#[tokio::test]
async fn callback_me_update_and_logout_preserve_browser_boundary_behavior() {
    let (router, app, sessions) = harness();
    let missing = request(&router, Method::GET, "/v1/auth/callback", &[], "").await;
    assert!(missing.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .contains("Missing+authentication+parameters"));

    *app.callback_error.lock().unwrap() = Some(PortError::new(
        "auth_user_provisioning_failed",
        "private downstream detail",
    ));
    let failed_callback = request(
        &router,
        Method::GET,
        "/v1/auth/callback?code=code&state=state",
        &[],
        "",
    )
    .await;
    let failed_location = failed_callback.headers()[header::LOCATION]
        .to_str()
        .unwrap();
    assert!(failed_location.contains("Session+expired.+Please+try+again"));
    assert!(!failed_location.contains("private"));

    let callback = request(
        &router,
        Method::GET,
        "/v1/auth/callback?code=code&state=state",
        &[],
        "",
    )
    .await;
    assert_eq!(
        callback.headers()[header::LOCATION],
        "https://elevenidllc.com/console"
    );
    assert!(callback
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .any(|value| value.to_str().unwrap().contains("HttpOnly")));

    let anonymous = request(&router, Method::GET, "/v1/auth/me", &[], "").await;
    let anonymous_body: Value =
        serde_json::from_slice(&to_bytes(anonymous.into_body(), usize::MAX).await.unwrap())
            .unwrap();
    assert_eq!(anonymous_body, serde_json::json!({"authenticated": false}));

    let authenticated = request(
        &router,
        Method::GET,
        "/v1/auth/me",
        &[("cookie", "sessionId=session-1")],
        "",
    )
    .await;
    assert_eq!(
        authenticated.headers()[header::CACHE_CONTROL],
        "no-store, max-age=0"
    );
    let authenticated_body: Value = serde_json::from_slice(
        &to_bytes(authenticated.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(authenticated_body["user"]["email"], "alice@example.com");
    assert!(authenticated_body["user"].get("picture").is_none());

    let invalid_picture = request(
        &router,
        Method::PATCH,
        "/v1/auth/me",
        &[
            ("cookie", "sessionId=session-1"),
            ("content-type", "application/json"),
        ],
        r#"{"picture":"http://insecure.example/picture"}"#,
    )
    .await;
    assert_eq!(invalid_picture.status(), StatusCode::BAD_REQUEST);
    let updated = request(
        &router,
        Method::PATCH,
        "/v1/auth/me",
        &[
            ("cookie", "sessionId=session-1"),
            ("content-type", "application/json"),
        ],
        r#"{"picture":"https://images.example/alice.png"}"#,
    )
    .await;
    assert_eq!(updated.status(), StatusCode::OK);
    assert_eq!(
        sessions
            .0
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .user
            .picture
            .as_deref(),
        Some("https://images.example/alice.png")
    );

    let logout = request(
        &router,
        Method::POST,
        "/v1/auth/logout",
        &[("cookie", "sessionId=session-1")],
        "",
    )
    .await;
    assert_eq!(
        logout.headers()[header::LOCATION],
        "https://identity.example/logout"
    );
    assert_eq!(
        logout.headers().get_all(header::SET_COOKIE).iter().count(),
        2
    );
}
