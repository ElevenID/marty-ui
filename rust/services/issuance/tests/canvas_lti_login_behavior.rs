use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use axum::{
    body::Body,
    http::{header, Request, StatusCode},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use marty_issuance_service::{
    canvas_lti_login::{
        CanvasLtiLaunchState, CanvasLtiLoginError, CanvasLtiLoginRepository, CanvasLtiLoginService,
        CanvasLtiPlatform,
    },
    http::router_with_canvas_lti_login,
    transport::TransportPolicy,
    IssuanceRuntime, IssuanceServiceConfig,
};
use marty_oid4vci::discovery::StaticDiscoveryDocuments;
use serde_json::{json, Value};
use tower::ServiceExt;
use url::Url;

#[derive(Clone)]
struct ContractRepository {
    platform: Arc<Mutex<Option<CanvasLtiPlatform>>>,
    launch_states: Arc<Mutex<Vec<CanvasLtiLaunchState>>>,
}

#[async_trait]
impl CanvasLtiLoginRepository for ContractRepository {
    async fn get_platform(
        &self,
        platform_id: &str,
    ) -> Result<Option<CanvasLtiPlatform>, CanvasLtiLoginError> {
        Ok(self
            .platform
            .lock()
            .expect("platform")
            .clone()
            .filter(|platform| platform.id == platform_id))
    }

    async fn save_launch_state(
        &self,
        launch_state: &CanvasLtiLaunchState,
    ) -> Result<(), CanvasLtiLoginError> {
        self.launch_states
            .lock()
            .expect("launch states")
            .push(launch_state.clone());
        Ok(())
    }
}

fn ready_platform() -> CanvasLtiPlatform {
    CanvasLtiPlatform {
        id: "platform-123".to_owned(),
        organization_id: "org-123".to_owned(),
        canvas_account_id: "account-123".to_owned(),
        canvas_base_url: Some("https://school.canvas.example".to_owned()),
        lti_client_id: Some("client-123".to_owned()),
        lti_deployment_id: Some("deployment-123".to_owned()),
        lti_trust_profile: "hosted_global".to_owned(),
        lti_issuer: Some("https://canvas.instructure.com".to_owned()),
        lti_jwks_url: Some("https://sso.canvaslms.com/api/lti/security/jwks".to_owned()),
        lti_jwks_json: Some(json!({"keys": [{"kid": "canvas-key"}]})),
        lti_openid_configuration: Some(json!({
            "issuer": "https://canvas.instructure.com",
            "authorization_endpoint": "https://sso.canvaslms.com/api/lti/authorize_redirect",
            "token_endpoint": "https://school.canvas.example/login/oauth2/token",
            "jwks_uri": "https://sso.canvaslms.com/api/lti/security/jwks"
        })),
        config_version: 1,
        enabled: true,
    }
}

fn app(
    platform: Option<CanvasLtiPlatform>,
    portable_enabled: bool,
    pilots: BTreeSet<String>,
) -> (axum::Router, Arc<Mutex<Vec<CanvasLtiLaunchState>>>) {
    app_with_self_managed_origins(platform, portable_enabled, pilots, Vec::new())
}

fn app_with_self_managed_origins(
    platform: Option<CanvasLtiPlatform>,
    portable_enabled: bool,
    pilots: BTreeSet<String>,
    self_managed_origins: Vec<String>,
) -> (axum::Router, Arc<Mutex<Vec<CanvasLtiLaunchState>>>) {
    let config =
        IssuanceServiceConfig::from_values(std::iter::empty::<(String, String)>()).expect("config");
    let runtime = IssuanceRuntime::new(&config).expect("runtime");
    let states = Arc::new(Mutex::new(Vec::new()));
    let repository = ContractRepository {
        platform: Arc::new(Mutex::new(platform)),
        launch_states: states.clone(),
    };
    let service = CanvasLtiLoginService::new(
        Arc::new(repository),
        "https://issuer.example",
        portable_enabled,
        pilots,
        Duration::from_secs(600),
        self_managed_origins,
    )
    .expect("Canvas LTI login service");
    let documents =
        StaticDiscoveryDocuments::new(&config.issuer_base_url, &config.issuer_display_name);
    (
        router_with_canvas_lti_login(
            runtime.state(),
            documents,
            TransportPolicy::new(config.cors_allowed_origins),
            service,
        ),
        states,
    )
}

#[tokio::test]
async fn self_managed_canvas_requires_and_uses_the_exact_allowlisted_origin() {
    let mut platform = ready_platform();
    platform.canvas_base_url = Some("https://canvas.example.edu".to_owned());
    platform.lti_trust_profile = "self_managed_same_origin".to_owned();
    platform.lti_issuer = Some("https://canvas.example.edu".to_owned());
    platform.lti_jwks_url = Some("https://canvas.example.edu/api/lti/security/jwks".to_owned());
    platform.lti_openid_configuration = Some(json!({
        "issuer": "https://canvas.example.edu",
        "authorization_endpoint": "https://canvas.example.edu/api/lti/authorize_redirect",
        "token_endpoint": "https://canvas.example.edu/login/oauth2/token",
        "jwks_uri": "https://canvas.example.edu/api/lti/security/jwks"
    }));

    let (allowed_app, states) = app_with_self_managed_origins(
        Some(platform.clone()),
        true,
        pilot(),
        vec!["https://CANVAS.EXAMPLE.EDU:443/".to_owned()],
    );
    let allowed = allowed_app
        .oneshot(
            Request::post("/v1/integrations/canvas/lti/platforms/platform-123/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "iss": "https://canvas.example.edu",
                        "login_hint": "hint",
                        "client_id": "client-123"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(allowed.status(), StatusCode::SEE_OTHER);
    let location = Url::parse(allowed.headers()[header::LOCATION].to_str().unwrap()).unwrap();
    assert_eq!(
        location.as_str().split('?').next().unwrap(),
        "https://canvas.example.edu/api/lti/authorize_redirect"
    );
    assert_eq!(states.lock().expect("states").len(), 1);

    let (denied_app, denied_states) = app(Some(platform), true, pilot());
    let denied = denied_app
        .oneshot(
            Request::post("/v1/integrations/canvas/lti/platforms/platform-123/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({"login_hint": "hint"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::CONFLICT);
    assert_eq!(
        json_body(denied).await,
        json!({
            "detail": "Canvas LTI trust configuration is not permitted: Invalid request: Self-managed Canvas LTI trust requires an exact origin allow-list entry"
        })
    );
    assert!(denied_states.lock().expect("states").is_empty());
}

fn pilot() -> BTreeSet<String> {
    BTreeSet::from(["org-123".to_owned()])
}

async fn json_body(response: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("JSON body")
}

#[tokio::test]
async fn json_login_matches_the_frozen_redirect_and_persistence_contract() {
    let (app, states) = app(Some(ready_platform()), true, pilot());
    let response = app
        .oneshot(
            Request::post("/v1/integrations/canvas/lti/platforms/platform-123/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "iss": "https://canvas.instructure.com",
                        "login_hint": " login-hint-123 ",
                        "target_link_uri": "https://issuer.example/launch",
                        "lti_message_hint": "message-hint-123",
                        "client_id": "client-123",
                        "ignored": "compatible-extra-input"
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = Url::parse(
        response
            .headers()
            .get(header::LOCATION)
            .expect("location")
            .to_str()
            .expect("location value"),
    )
    .expect("location URL");
    assert_eq!(
        location.origin().ascii_serialization(),
        "https://sso.canvaslms.com"
    );
    assert_eq!(location.path(), "/api/lti/authorize_redirect");
    let query = location
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(query["scope"], "openid");
    assert_eq!(query["response_type"], "id_token");
    assert_eq!(query["response_mode"], "form_post");
    assert_eq!(query["prompt"], "none");
    assert_eq!(query["client_id"], "client-123");
    assert_eq!(query["login_hint"], "login-hint-123");
    assert_eq!(query["lti_message_hint"], "message-hint-123");
    assert_eq!(
        query["redirect_uri"],
        "https://issuer.example/v1/integrations/canvas/lti/platforms/platform-123/launch"
    );
    for generated in [&query["state"], &query["nonce"]] {
        assert_eq!(URL_SAFE_NO_PAD.decode(generated).expect("token").len(), 32);
    }

    let stored = states.lock().expect("states");
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].state, query["state"]);
    assert_eq!(stored[0].nonce, query["nonce"]);
    assert_eq!(stored[0].ttl, Duration::from_secs(600));
    assert_eq!(stored[0].metadata["experience_mode"], false);
    assert_eq!(stored[0].metadata["canvas_platform_id"], "platform-123");
}

#[tokio::test]
async fn form_experience_login_uses_the_experience_callback_and_last_duplicate_value() {
    let (app, states) = app(Some(ready_platform()), true, pilot());
    let response = app
        .oneshot(
            Request::post("/v1/integrations/canvas/lti/platforms/platform-123/experience-login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(
                    "login_hint=stale&login_hint=current&client_id=client-123",
                ))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = Url::parse(response.headers()[header::LOCATION].to_str().unwrap()).unwrap();
    let query = location
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(query["login_hint"], "current");
    assert!(query["redirect_uri"].ends_with("/platform-123/experience"));
    let stored = states.lock().expect("states");
    assert_eq!(stored[0].metadata["experience_mode"], true);
}

#[tokio::test]
async fn frozen_login_failures_preserve_status_and_detail() {
    struct Case {
        name: &'static str,
        platform: Option<CanvasLtiPlatform>,
        enabled: bool,
        pilots: BTreeSet<String>,
        body: Value,
        status: StatusCode,
        detail: &'static str,
    }
    let cases = [
        Case {
            name: "platform_missing",
            platform: None,
            enabled: true,
            pilots: pilot(),
            body: json!({"login_hint": "hint"}),
            status: StatusCode::NOT_FOUND,
            detail: "Canvas platform not found",
        },
        Case {
            name: "pilot_disabled",
            platform: Some(ready_platform()),
            enabled: false,
            pilots: pilot(),
            body: json!({"login_hint": "hint"}),
            status: StatusCode::NOT_FOUND,
            detail: "Portable Canvas integration is not enabled for this organization",
        },
        Case {
            name: "login_hint_missing",
            platform: Some(ready_platform()),
            enabled: true,
            pilots: pilot(),
            body: json!({}),
            status: StatusCode::BAD_REQUEST,
            detail: "Canvas LTI login requires login_hint",
        },
        Case {
            name: "issuer_mismatch",
            platform: Some(ready_platform()),
            enabled: true,
            pilots: pilot(),
            body: json!({"login_hint": "hint", "iss": "https://evil.example"}),
            status: StatusCode::BAD_REQUEST,
            detail: "Canvas LTI issuer does not match platform",
        },
        Case {
            name: "client_id_mismatch",
            platform: Some(ready_platform()),
            enabled: true,
            pilots: pilot(),
            body: json!({"login_hint": "hint", "client_id": "other-client"}),
            status: StatusCode::BAD_REQUEST,
            detail: "Canvas LTI client_id does not match platform",
        },
    ];
    for case in cases {
        let (app, states) = app(case.platform, case.enabled, case.pilots);
        let response = app
            .oneshot(
                Request::post("/v1/integrations/canvas/lti/platforms/platform-123/login")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(case.body.to_string()))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), case.status, "{}", case.name);
        assert_eq!(json_body(response).await, json!({"detail": case.detail}));
        assert!(states.lock().expect("states").is_empty(), "{}", case.name);
    }
}

#[tokio::test]
async fn malformed_json_and_persisted_metadata_drift_fail_closed() {
    let (missing_app, _) = app(None, true, pilot());
    let missing = missing_app
        .oneshot(
            Request::post("/v1/integrations/canvas/lti/platforms/platform-123/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        json_body(missing).await,
        json!({"detail": "Canvas platform not found"})
    );

    let (malformed_app, states) = app(Some(ready_platform()), true, pilot());
    for (body, detail) in [
        ("{".to_owned(), "Invalid JSON body"),
        (
            json!([{"login_hint": "hint"}]).to_string(),
            "Canvas LTI JSON body must be an object",
        ),
    ] {
        let response = malformed_app
            .clone()
            .oneshot(
                Request::post("/v1/integrations/canvas/lti/platforms/platform-123/login")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await, json!({"detail": detail}));
    }
    assert!(states.lock().expect("states").is_empty());

    let (unsupported_app, unsupported_states) = app(Some(ready_platform()), true, pilot());
    let response = unsupported_app
        .oneshot(
            Request::post("/v1/integrations/canvas/lti/platforms/platform-123/login")
                .header(header::CONTENT_TYPE, "text/plain")
                .body(Body::from("login_hint=must-not-be-parsed"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(response).await,
        json!({"detail": "Canvas LTI login requires login_hint"})
    );
    assert!(unsupported_states.lock().expect("states").is_empty());

    let response = malformed_app
        .oneshot(
            Request::post("/v1/integrations/canvas/lti/platforms/platform-123/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "login_hint": "hint",
                        "iss": 42,
                        "client_id": false,
                        "target_link_uri": ["not", "a", "string"]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    {
        let stored = states.lock().expect("states");
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].metadata["issuer"], Value::Null);
        assert_eq!(stored[0].metadata["client_id"], Value::Null);
        assert!(stored[0].target_link_uri.is_none());
    }

    let mut drifted = ready_platform();
    drifted.lti_openid_configuration = Some(json!({
        "authorization_endpoint": "https://lookalike.example/api/lti/authorize_redirect"
    }));
    let (app, states) = app(Some(drifted), true, pilot());
    let response = app
        .oneshot(
            Request::post("/v1/integrations/canvas/lti/platforms/platform-123/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({"login_hint": "hint"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        json_body(response).await,
        json!({"detail": "Canvas LTI metadata does not match the persisted trust profile"})
    );
    assert!(states.lock().expect("states").is_empty());
}
