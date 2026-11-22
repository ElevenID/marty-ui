const ADMIN_ORG: &str = "11111111-1111-4111-8111-111111111111";
const ADMIN_USER: &str = "22222222-2222-4222-8222-222222222222";
const ADMIN_SESSION: &str = "33333333-3333-4333-8333-333333333333";
const ADMIN_AGENT: &str = "44444444-4444-4444-8444-444444444444";
const ADMIN_REVIEW: &str = "55555555-5555-4555-8555-555555555555";

struct AgentAdminProvider {
    mode: std::sync::atomic::AtomicU8,
    membership_calls: std::sync::atomic::AtomicUsize,
}
impl Default for AgentAdminProvider {
    fn default() -> Self {
        Self {
            mode: 0.into(),
            membership_calls: 0.into(),
        }
    }
}
#[async_trait]
impl GatewayIdentityProvider for AgentAdminProvider {
    async fn validate_session(
        &self,
        session: &str,
    ) -> Result<Option<SessionIdentity>, SecurityError> {
        if session != ADMIN_SESSION {
            return Ok(None);
        }
        let mode = self.mode.load(Ordering::SeqCst);
        Ok(Some(SessionIdentity {
            user_id: ADMIN_USER.into(),
            organization_id: Some(if mode == 7 { ADMIN_AGENT } else { ADMIN_ORG }.into()),
            non_impersonated_session: if mode == 2 { Some(false) } else { Some(true) },
            expires_at_unix: if mode == 3 {
                None
            } else {
                Some(Utc::now().timestamp() + if mode == 4 { -1 } else { 3600 })
            },
            ..Default::default()
        }))
    }
    async fn validate_api_key(&self, _: &str) -> Result<Option<ApiKeyIdentity>, SecurityError> {
        Ok(Some(ApiKeyIdentity {
            api_key_id: "machine".into(),
            organization_id: Some(ADMIN_ORG.into()),
            key_prefix: None,
            scopes: vec!["*".into(), "admin".into(), "agent-identity:create".into()],
        }))
    }
}
#[async_trait]
impl OrganizationMembershipProvider for AgentAdminProvider {
    async fn get_membership(
        &self,
        user: &str,
        organization: &str,
    ) -> Result<Option<OrganizationMembership>, SecurityError> {
        self.membership_calls.fetch_add(1, Ordering::SeqCst);
        let mode = self.mode.load(Ordering::SeqCst);
        if mode == 5 {
            return Err(SecurityError::ProviderUnavailable(
                "private database endpoint".into(),
            ));
        }
        if organization != ADMIN_ORG || mode == 8 {
            return Ok(None);
        }
        Ok(Some(OrganizationMembership {
            user_id: if mode == 10 { ADMIN_AGENT } else { user }.into(),
            organization_id: if mode == 9 { ADMIN_AGENT } else { organization }.into(),
            status: if mode == 1 { "inactive" } else { "active" }.into(),
            permissions: if mode == 6 {
                BTreeSet::new()
            } else {
                BTreeSet::from([
                    "agent-identity:view".into(),
                    "agent-identity:create".into(),
                    "agent-identity:update".into(),
                    "agent-identity:suspend".into(),
                    "agent-identity:revoke".into(),
                    "agent-identity:retire".into(),
                    "agent-identity:rotate-key".into(),
                    "agent-identity:enroll".into(),
                    "delegation-grant:create".into(),
                    "delegation-grant:suspend".into(),
                    "delegation-grant:reinstate".into(),
                    "delegation-grant:revoke".into(),
                    "delegation-grant:view".into(),
                    "delegation-grant:approve".into(),
                ])
            },
            role_names: BTreeSet::from(["administrator".into()]),
            is_owner: true,
        }))
    }
}

#[derive(Default)]
struct AgentAdminUpstream {
    calls: std::sync::Mutex<Vec<(String, GatewayRequest)>>,
    response: std::sync::Mutex<Option<(u16, Value)>>,
}
// GatewayRequest stores header names as strings; HTTP names remain case
// insensitive even when the canonical proxy chooses its own capitalization.
fn admin_header<'a>(request: &'a GatewayRequest, name: &str) -> &'a str {
    let values: Vec<_> = request
        .headers
        .iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
        .collect();
    assert_eq!(
        values.len(),
        1,
        "one trusted {name} header must cross the proxy"
    );
    values[0]
}

fn synthetic_agent() -> Value {
    json!({"id":ADMIN_AGENT,"organization_id":ADMIN_ORG,"owner_user_id":ADMIN_USER,"created_by":ADMIN_USER,
        "kind":"EXTERNAL","status":"ACTIVE","revision":1,
        "metadata":{"display_name":"Synthetic agent","description":null,"logical_application_ref":"urn:test:application"},
        "principal":{"type":"SERVICE_ACCOUNT","id":"urn:test:agent"},"issuer":"https://issuer.example.invalid",
        "subject":"synthetic-agent","runtime_instance_ref":"urn:test:runtime","keys":[],
        "provenance":{"kind":"OPERATOR_DECLARATION","registered_by":ADMIN_USER,"registration_ref":"urn:test:registration",
            "managed_enrollment":"NOT_ASSESSED","external_authentication":"NOT_ASSESSED"},
        "authority_status":"NOT_ASSESSED","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"})
}
fn synthetic_approval_review(reference: Value) -> Value {
    json!({"review_id":ADMIN_REVIEW,"grant":reference,
        "terms":{
            "grantor":{"type":"USER","id":format!("urn:marty:user:{ADMIN_USER}")},
            "subject":{"type":"ORGANIZATION","id":format!("urn:marty:organization:{ADMIN_ORG}")},
            "delegate":{"type":"SERVICE_ACCOUNT","id":"urn:test:synthetic-agent"},
            "binding":{"method":"KEY","key_thumbprint":format!("sha256:{}","b".repeat(64))},
            "actions":["urn:test:review"],"audiences":["urn:test:verifier"],"resources":["urn:test:resource"],
            "valid_from":"2026-01-01T00:00:00Z","valid_until":"2026-01-01T01:00:00Z","subdelegation_allowed":false,
            "constraints":{"mode":"EXACT_OPERATION","request_profile":"urn:test:request","request_digest":format!("sha256:{}","c".repeat(64))}},
        "issuer":{"type":"ORGANIZATION","id":format!("urn:marty:organization:{ADMIN_ORG}")},
        "created_at":"2026-01-01T00:00:00Z","expires_at":"2026-01-01T00:05:00Z","confirmation_max_age_seconds":300})
}

#[async_trait]
impl UpstreamClient for AgentAdminUpstream {
    async fn send(
        &self,
        instance: &ServiceInstance,
        request: GatewayRequest,
    ) -> Result<GatewayResponse, PlatformError> {
        self.calls
            .lock()
            .unwrap()
            .push((instance.service_name.clone(), request.clone()));
        let (status,value)=self.response.lock().unwrap().clone().unwrap_or_else(|| {
            let input=request.body.as_ref().and_then(|body|serde_json::from_slice::<Value>(body).ok()).unwrap_or(Value::Null);
            let value=if request.path.ends_with("/approval-reviews") {
                synthetic_approval_review(input["grant"].clone())
            } else if request.path.ends_with("/confirm") {
                json!({"confirmation_id":input["confirmation_id"],"review_id":ADMIN_REVIEW,"grant_id":ADMIN_AGENT,
                    "terms_digest":input["terms_digest"],"confirmed_at":"2026-01-01T00:00:00Z","valid_until":"2026-01-01T00:05:00Z","recovered":true})
            } else if request.path.ends_with("/withdraw") {
                json!({"confirmation_id":ADMIN_REVIEW,"grant_id":ADMIN_AGENT,"withdrawn_at":"2026-01-01T00:00:01Z","recovered":true})
            } else if request.method==HttpMethod::Get && request.path.ends_with("/agents") {
                json!({"items":[synthetic_agent()],"total":1,"limit":50,"offset":0})
            } else { synthetic_agent() };
            (200,value)
        });
        Ok(GatewayResponse {
            status_code: status,
            body: Some(serde_json::to_vec(&value).unwrap()),
            headers: BTreeMap::from([("x-private-upstream".into(), "do-not-forward".into())]),
            set_cookies: vec!["private=secret".into()],
            response_time_ms: None,
            upstream_service: Some(instance.service_name.clone()),
        })
    }
}

fn candidate_admin_test_state(
    enabled: bool,
    commands: bool,
    enrollment: bool,
) -> (
    Arc<GatewayRuntimeState>,
    Arc<AgentAdminProvider>,
    Arc<AgentAdminUpstream>,
) {
    let provider = Arc::new(AgentAdminProvider::default());
    let upstream = Arc::new(AgentAdminUpstream::default());
    let contract = GatewayContract::load().unwrap();
    let mut routes = contract.runtime_route_table().unwrap();
    let mut proxy_routes = contract.proxy_route_table().unwrap();
    crate::agent_administration::add_routes(&mut routes, enabled, enabled).unwrap();
    crate::agent_administration::add_routes(&mut proxy_routes, enabled, enabled).unwrap();
    crate::agent_administration::add_enrollment_routes(&mut routes, enrollment).unwrap();
    crate::agent_administration::add_enrollment_routes(&mut proxy_routes, enrollment).unwrap();
    crate::delegation_commands::add_routes(&mut routes, commands).unwrap();
    crate::delegation_commands::add_routes(&mut proxy_routes, commands).unwrap();
    let registry = StaticServiceRegistry::from_urls(&BTreeMap::from([
        ("organizations".into(), "http://organizations:8002".into()),
        (
            "delegated-commands".into(),
            "http://delegated-commands:8020".into(),
        ),
        (
            "delegated-authority".into(),
            "http://delegated-authority:8088".into(),
        ),
    ]))
    .unwrap();
    let proxy = GatewayProxy::new(
        proxy_routes,
        Arc::new(registry),
        upstream.clone(),
        ProxyConfig::default(),
    )
    .unwrap();
    let state = GatewayRuntimeState::new(
        routes,
        proxy,
        provider.clone(),
        provider.clone(),
        Arc::new(NoOwner),
        Arc::new(NoOwner),
        Arc::new(NoOwner),
        vec![],
        GatewayRateLimiter::new(Arc::new(InMemoryRateLimiter::default()), 1000).unwrap(),
        Arc::new(InMemoryIdempotencyStore::new(60_000, 5_000).unwrap()),
        ["https://console.example".into()],
        "https://issuer.example",
        "https://api.example",
        "api.example",
        None,
        "signing-test-key",
        "issuance-test-key",
        ReleaseIdentity::default(),
    )
    .unwrap()
    .with_service_token(Some("s".repeat(32)))
    .unwrap()
    .with_agent_administration(enabled, enabled)
    .unwrap()
    .with_delegation_commands(commands)
    .unwrap()
    .with_agent_enrollment(enrollment)
    .unwrap();
    (Arc::new(state), provider, upstream)
}
fn agent_admin_test_state(
    enabled: bool,
) -> (
    Arc<GatewayRuntimeState>,
    Arc<AgentAdminProvider>,
    Arc<AgentAdminUpstream>,
) {
    candidate_admin_test_state(enabled, false, false)
}
fn admin_request(method: &str, path: &str, body: &str) -> Request {
    Request::builder()
        .method(method)
        .uri(path)
        .header("cookie", format!("sessionId={ADMIN_SESSION}"))
        .header("origin", "https://console.example")
        .header("content-type", "application/json")
        .body(Body::from(body.to_owned()))
        .unwrap()
}

#[tokio::test]
async fn agent_administration_is_default_off_and_does_not_change_support_catalog() {
    let (state, _, upstream) = agent_admin_test_state(false);
    let response = gateway_router(state.clone())
        .oneshot(admin_request(
            "GET",
            &format!("/v1/organizations/{ADMIN_ORG}/agents"),
            "",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(upstream.calls.lock().unwrap().is_empty());
    let mut document = GatewayContract::load().unwrap().openapi_document("test");
    let original = document.clone();
    crate::agent_administration::extend_openapi(&mut document, false, false);
    assert_eq!(document, original);
    assert_eq!(
        state.policies.negotiate_version(Some("0.5.0")),
        mmf_platform::ProtocolVersionDecision::Accepted
    );
}

#[tokio::test]
async fn agent_admin_real_middleware_requires_current_session_and_membership_before_every_call() {
    let (state, provider, upstream) = agent_admin_test_state(true);
    let app = gateway_router(state);
    let path = format!("/v1/organizations/{ADMIN_ORG}/agents");
    let success = app
        .clone()
        .oneshot(admin_request("GET", &path, ""))
        .await
        .unwrap();
    assert_eq!(success.status(), StatusCode::OK);
    assert_eq!(success.headers()["cache-control"], "no-store");
    assert!(!success.headers().contains_key("etag"));
    assert!(!success.headers().contains_key("set-cookie"));
    for (mode, status) in [(1, 403), (2, 403), (3, 403), (4, 403), (5, 503), (6, 403)] {
        provider.mode.store(mode, Ordering::SeqCst);
        let response = app
            .clone()
            .oneshot(admin_request("GET", &path, ""))
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), status, "mode {mode}");
        let request_id = response.headers()["x-request-id"]
            .to_str()
            .unwrap()
            .to_owned();
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["message_id"], request_id);
        assert!(!String::from_utf8_lossy(&body).contains("private database"));
    }
    assert_eq!(upstream.calls.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn agent_admin_api_keys_foreign_tenants_and_duplicate_cookies_cannot_become_humans() {
    let (state, _, upstream) = agent_admin_test_state(true);
    let app = gateway_router(state);
    let path = format!("/v1/organizations/{ADMIN_ORG}/agents");
    let mut key = admin_request("GET", &path, "");
    key.headers_mut()
        .insert("x-api-key", "mk_live_machine".parse().unwrap());
    assert_eq!(
        app.clone().oneshot(key).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let mut duplicate = admin_request("GET", &path, "");
    duplicate.headers_mut().append(
        "cookie",
        format!("sessionId={ADMIN_SESSION}").parse().unwrap(),
    );
    assert_eq!(
        app.clone().oneshot(duplicate).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        app.oneshot(admin_request(
            "GET",
            &format!("/v1/organizations/{ADMIN_AGENT}/agents"),
            ""
        ))
        .await
        .unwrap()
        .status(),
        StatusCode::FORBIDDEN
    );
    assert!(upstream.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn agent_admin_non_default_organization_requires_its_exact_current_membership() {
    let (state, provider, upstream) = agent_admin_test_state(true);
    let app = gateway_router(state);
    let path = format!("/v1/organizations/{ADMIN_ORG}/agents");
    // The Auth login organization differs from the selected Console tenant.
    provider.mode.store(7, Ordering::SeqCst);
    assert_eq!(
        app.clone()
            .oneshot(admin_request("GET", &path, ""))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    for mode in [1, 8, 9, 10] {
        provider.mode.store(mode, Ordering::SeqCst);
        assert_eq!(
            app.clone()
                .oneshot(admin_request("GET", &path, ""))
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN,
            "inactive, missing or mismatched path membership mode {mode}"
        );
    }
    let calls = upstream.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(admin_header(&calls[0].1, "x-organization-id"), ADMIN_ORG);
    assert_eq!(provider.membership_calls.load(Ordering::SeqCst), 5);
}

#[tokio::test]
async fn agent_admin_origin_strict_json_and_revision_checks_precede_upstream() {
    let (state, _, upstream) = agent_admin_test_state(true);
    let app = gateway_router(state);
    let path = format!("/v1/organizations/{ADMIN_ORG}/agents/{ADMIN_AGENT}/revoke");
    for body in [
        "{\"expected_revision\":1,\"expected_revision\":2}",
        "{\"expected_revision\":1,\"owner_id\":\"attacker\"}",
        "{\"expected_revision\":null}",
        "{\"expected_revision\":true}",
        "{\"expected_revision\":1.0}",
        "{\"expected_revision\":0}",
    ] {
        assert_eq!(
            app.clone()
                .oneshot(admin_request("POST", &path, body))
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    for origin in [None, Some("https://attacker.example"), Some("null")] {
        let mut request = admin_request("POST", &path, "{\"expected_revision\":1}");
        request.headers_mut().remove("origin");
        if let Some(origin) = origin {
            request
                .headers_mut()
                .insert("origin", origin.parse().unwrap());
        }
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
    }
    let mut duplicate = admin_request("POST", &path, "{\"expected_revision\":1}");
    duplicate
        .headers_mut()
        .append("origin", "https://console.example".parse().unwrap());
    assert_eq!(
        app.oneshot(duplicate).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    assert!(upstream.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn agent_admin_reconstructs_actor_and_correlation_and_never_replays_generic_cache() {
    let (state, provider, upstream) = agent_admin_test_state(true);
    let app = gateway_router(state);
    let path = format!("/v1/organizations/{ADMIN_ORG}/agents/{ADMIN_AGENT}/revoke");
    let request = || {
        let mut request = admin_request("POST", &path, "{\"expected_revision\":1}");
        for (name, value) in [
            ("x-user-id", "forged"),
            ("x-organization-id", "forged"),
            ("x-required-permission", "*"),
            ("x-service-token", "forged"),
            ("x-request-id", "caller-chosen"),
            ("x-marty-approval-user-id", "forged"),
            ("idempotency-key", "reused-client-key"),
        ] {
            request.headers_mut().insert(
                axum::http::HeaderName::from_static(name),
                value.parse().unwrap(),
            );
        }
        request
    };
    let first = app.clone().oneshot(request()).await.unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let first_id = first.headers()["x-request-id"].to_str().unwrap().to_owned();
    assert_ne!(first_id, "caller-chosen");
    {
        let calls = upstream.calls.lock().unwrap();
        let forwarded = &calls[0].1;
        assert_eq!(calls[0].0, "organizations");
        assert_eq!(admin_header(forwarded, "x-user-id"), ADMIN_USER);
        assert_eq!(admin_header(forwarded, "x-organization-id"), ADMIN_ORG);
        assert_eq!(
            admin_header(forwarded, "x-required-permission"),
            "agent-identity:revoke"
        );
        assert_eq!(admin_header(forwarded, "x-request-id"), first_id);
        assert_eq!(admin_header(forwarded, "x-service-token"), "s".repeat(32));
        for forbidden in [
            "cookie",
            "authorization",
            "x-api-key",
            "x-marty-approval-user-id",
            "idempotency-key",
        ] {
            assert!(!forwarded
                .headers
                .keys()
                .any(|name| name.eq_ignore_ascii_case(forbidden)));
        }
    }
    provider.mode.store(1, Ordering::SeqCst);
    assert_eq!(
        app.oneshot(request()).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(upstream.calls.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn agent_admin_approval_binds_review_confirmation_withdrawal_and_real_session_observation() {
    let (state, _, upstream) = agent_admin_test_state(true);
    let app = gateway_router(state);
    let base = format!("/v1/organizations/{ADMIN_ORG}/delegation-grants/{ADMIN_AGENT}");
    let digest = format!("sha256:{}", "a".repeat(64));
    let body = json!({"grant":{"id":ADMIN_AGENT,"revision":1,"terms_digest":digest}}).to_string();
    assert_eq!(
        app.clone()
            .oneshot(admin_request(
                "POST",
                &format!("{base}/approval-reviews"),
                &body
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    let body = json!({"confirmation_id":ADMIN_REVIEW,"terms_digest":digest,"decision":"CONFIRM"})
        .to_string();
    assert_eq!(
        app.clone()
            .oneshot(admin_request(
                "POST",
                &format!("{base}/approval-reviews/{ADMIN_REVIEW}/confirm"),
                &body
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        app.oneshot(admin_request(
            "POST",
            &format!("{base}/approval-confirmations/{ADMIN_REVIEW}/withdraw"),
            "{}"
        ))
        .await
        .unwrap()
        .status(),
        StatusCode::OK
    );
    let calls = upstream.calls.lock().unwrap();
    assert_eq!(calls.len(), 3);
    for (index, (service, request)) in calls.iter().enumerate() {
        assert_eq!(service, "delegated-authority");
        assert_eq!(
            admin_header(request, "x-marty-approval-user-id"),
            ADMIN_USER
        );
        assert_eq!(
            admin_header(request, "x-marty-approval-organization-id"),
            ADMIN_ORG
        );
        assert!(admin_header(request, "x-marty-approval-session-ref")
            .starts_with("urn:marty:session:sha256:"));
        assert!(!request.headers.values().any(|value| value == ADMIN_SESSION));
        let observed = chrono::DateTime::parse_from_rfc3339(admin_header(
            request,
            "x-marty-approval-observed-at",
        ))
        .unwrap();
        let deadline = chrono::DateTime::parse_from_rfc3339(admin_header(
            request,
            "x-marty-approval-valid-until",
        ))
        .unwrap();
        assert!(deadline > observed && (deadline - observed).num_seconds() <= 30);
        assert_eq!(
            admin_header(request, "x-required-permission"),
            if index == 0 {
                "delegation-grant:approve"
            } else {
                "delegation-grant:view"
            }
        );
    }
}

#[tokio::test]
async fn agent_admin_rejects_cross_tenant_and_false_qualification_responses_and_sanitizes_errors() {
    let (state, _, upstream) = agent_admin_test_state(true);
    let app = gateway_router(state);
    let path = format!("/v1/organizations/{ADMIN_ORG}/agents/{ADMIN_AGENT}");
    for (field, value) in [
        ("organization_id", ADMIN_AGENT),
        ("authority_status", "QUALIFIED"),
    ] {
        let mut value_body = synthetic_agent();
        value_body[field] = json!(value);
        *upstream.response.lock().unwrap() = Some((200, value_body));
        assert_eq!(
            app.clone()
                .oneshot(admin_request("GET", &path, ""))
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_GATEWAY
        );
    }
    *upstream.response.lock().unwrap() = Some((500, json!({"error":"secret-source-details"})));
    let response = app.oneshot(admin_request("GET", &path, "")).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    assert!(!String::from_utf8_lossy(&body).contains("secret-source"));
}

#[tokio::test]
async fn agent_admin_rejects_incomplete_or_retargeted_terms_before_public_consent() {
    let (state, _, upstream) = agent_admin_test_state(true);
    let app = gateway_router(state);
    let path =
        format!("/v1/organizations/{ADMIN_ORG}/delegation-grants/{ADMIN_AGENT}/approval-reviews");
    let reference =
        json!({"id":ADMIN_AGENT,"revision":1,"terms_digest":format!("sha256:{}","a".repeat(64))});
    let body = json!({"grant":reference}).to_string();
    let review = synthetic_approval_review(reference);
    for (pointer, value) in [
        ("/terms", json!({})),
        ("/issuer", json!({})),
        (
            "/terms/grantor/id",
            json!(format!("urn:marty:user:{ADMIN_AGENT}")),
        ),
        (
            "/terms/subject/id",
            json!(format!("urn:marty:organization:{ADMIN_AGENT}")),
        ),
        (
            "/issuer/id",
            json!(format!("urn:marty:organization:{ADMIN_AGENT}")),
        ),
        (
            "/terms/delegate",
            json!({"type":"EXTERNAL","id":"urn:test:agent","trusted":true}),
        ),
        ("/terms/actions", json!([])),
        ("/terms/actions", json!([{}])),
        ("/terms/resources", json!(["urn:test:*"])),
        (
            "/terms/audiences",
            json!(["urn:test:verifier", "urn:test:verifier"]),
        ),
        (
            "/terms/binding",
            json!({"method":"SESSION","session_ref":"urn:test:session"}),
        ),
        ("/terms/binding/key_thumbprint", json!("unbound")),
        ("/terms/constraints", json!({"mode":"EXACT_OPERATION"})),
        ("/terms/subdelegation_allowed", json!(true)),
        ("/terms/valid_until", json!("2025-01-01T00:00:00Z")),
        ("/expires_at", json!("2026-01-01T00:05:01Z")),
        ("/expires_at", json!("not-a-time")),
        ("/confirmation_max_age_seconds", json!(0)),
        ("/confirmation_max_age_seconds", json!(301)),
    ] {
        let mut changed = review.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        *upstream.response.lock().unwrap() = Some((200, changed));
        assert_eq!(
            app.clone()
                .oneshot(admin_request("POST", &path, &body))
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_GATEWAY,
            "{pointer}"
        );
    }
    // The other supported constraint mode stays reviewable without inventing
    // authority or interpreting its domain-specific policy document.
    let mut external = review;
    external["terms"]["constraints"] = json!({"mode":"EXTERNAL_PROFILE","profile":"urn:test:constraint",
        "document_ref":"urn:test:document","document_digest":format!("sha256:{}","d".repeat(64)),
        "evaluator":{"type":"SERVICE_ACCOUNT","id":"urn:test:evaluator"}});
    *upstream.response.lock().unwrap() = Some((200, external));
    assert_eq!(
        app.oneshot(admin_request("POST", &path, &body))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn agent_admin_original_confirmation_rejects_wrong_bindings_and_invalid_time_bounds() {
    let (state, _, upstream) = agent_admin_test_state(true);
    let app = gateway_router(state);
    let path = format!("/v1/organizations/{ADMIN_ORG}/delegation-grants/{ADMIN_AGENT}/approval-reviews/{ADMIN_REVIEW}/confirm");
    let digest = format!("sha256:{}", "a".repeat(64));
    let body = json!({"confirmation_id":ADMIN_REVIEW,"terms_digest":digest,"decision":"CONFIRM"})
        .to_string();
    let confirmation = json!({"confirmation_id":ADMIN_REVIEW,"review_id":ADMIN_REVIEW,"grant_id":ADMIN_AGENT,
        "terms_digest":digest,"confirmed_at":"2026-01-01T00:00:00Z","valid_until":"2026-01-01T00:05:00Z","recovered":true});
    for (field, value) in [
        ("confirmation_id", json!(ADMIN_AGENT)),
        ("review_id", json!(ADMIN_AGENT)),
        ("grant_id", json!(ADMIN_REVIEW)),
        ("terms_digest", json!(format!("sha256:{}", "b".repeat(64)))),
        ("confirmed_at", json!("invalid")),
        ("valid_until", json!("2026-01-01T00:00:00Z")),
        ("valid_until", json!("2026-01-01T00:05:01Z")),
        ("recovered", json!("true")),
    ] {
        let mut changed = confirmation.clone();
        changed[field] = value;
        *upstream.response.lock().unwrap() = Some((200, changed));
        assert_eq!(
            app.clone()
                .oneshot(admin_request("POST", &path, &body))
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_GATEWAY,
            "{field}"
        );
    }
    // Historical results remain inspectable: validation must not manufacture
    // a new confirmation lifetime by requiring the old result to be current.
    *upstream.response.lock().unwrap() = Some((200, confirmation));
    assert_eq!(
        app.oneshot(admin_request("POST", &path, &body))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn agent_admin_cors_preflight_is_scoped_to_opt_in_route_origin_and_headers() {
    let (state, _, upstream) = agent_admin_test_state(true);
    let app = gateway_router(state);
    let path = format!("/v1/organizations/{ADMIN_ORG}/agents");
    let preflight = |origin: &str, headers: &str| {
        Request::builder()
            .method("OPTIONS")
            .uri(&path)
            .header("origin", origin)
            .header("access-control-request-method", "POST")
            .header("access-control-request-headers", headers)
            .body(Body::empty())
            .unwrap()
    };
    assert_eq!(
        app.clone()
            .oneshot(preflight(
                "https://console.example",
                "content-type,x-mip-version"
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        app.clone()
            .oneshot(preflight("https://evil.example", "content-type"))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        app.oneshot(preflight("https://console.example", "x-api-key"))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert!(upstream.calls.lock().unwrap().is_empty());
}
