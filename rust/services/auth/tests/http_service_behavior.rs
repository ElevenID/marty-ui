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
    CanvasHttpApplication, HandleCallbackCommand, HandleCallbackResult, PortError, Session,
    SessionCookieConfig, SessionRepository, SessionSpec, UiOriginPolicy, UserType,
    AUTH_CORE_HTTP_ROUTES,
};
use serde_json::Value;
use tower::ServiceExt as _;

#[derive(Default)]
struct AppStub {
    initiated: Mutex<Vec<(bool, String, String)>>,
    session: Mutex<Option<Session>>,
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
    let (router, _, sessions) = harness();
    let missing = request(&router, Method::GET, "/v1/auth/callback", &[], "").await;
    assert!(missing.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .contains("Missing+authentication+parameters"));

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
