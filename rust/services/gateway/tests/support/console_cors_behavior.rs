const CONSOLE_ASSOCIATION: &str = "/v1/organizations/20000000-0000-4000-8000-000000000001/external-association-challenges/30000000-0000-4000-8000-000000000001/confirm";
const CONSOLE_ORIGIN: &str = "https://beta.elevenidllc.com";

fn console_preflight_request(path: &str, method: &str, origin: &str, headers: &str) -> Request {
    Request::builder()
        .method("OPTIONS")
        .uri(path)
        .header("origin", origin)
        .header("access-control-request-method", method)
        .header("access-control-request-headers", headers)
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn console_preflight_admits_only_declared_auth_and_learner_operations_without_upstream_calls()
{
    let recorder = Arc::new(ActorRecordingUpstream::default());
    let router = gateway_router(runtime_state_with_upstream(
        Arc::new(NoOwner),
        recorder.clone(),
    ));
    for (path, method) in [
        ("/v1/auth/me", "GET"),
        ("/v1/auth/me", "PATCH"),
        ("/v1/auth/me/organizations", "GET"),
        ("/v1/auth/provider", "GET"),
        ("/v1/auth/passkeys/enroll", "POST"),
        ("/v1/auth/logout", "POST"),
        (CONSOLE_ASSOCIATION, "POST"),
    ] {
        let response = router
            .clone()
            .oneshot(console_preflight_request(
                path,
                method,
                CONSOLE_ORIGIN,
                "content-type",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT, "{method} {path}");
        let headers = response.headers();
        assert_eq!(headers["access-control-allow-origin"], CONSOLE_ORIGIN);
        assert_eq!(headers["access-control-allow-credentials"], "true");
        assert_eq!(headers["access-control-allow-methods"], method);
        assert_eq!(headers["access-control-allow-headers"], "content-type");
        assert_eq!(headers["cache-control"], "no-store");
        assert!(!headers.contains_key("set-cookie"));
    }
    assert!(recorder.0.lock().unwrap().is_empty());
}

#[tokio::test]
async fn console_preflight_rejects_unallowed_origins_methods_headers_paths_and_ambiguity() {
    let recorder = Arc::new(ActorRecordingUpstream::default());
    let router = gateway_router(runtime_state_with_upstream(
        Arc::new(NoOwner),
        recorder.clone(),
    ));
    let mut requests = vec![
        console_preflight_request(
            CONSOLE_ASSOCIATION,
            "POST",
            "https://untrusted.example",
            "content-type",
        ),
        console_preflight_request(CONSOLE_ASSOCIATION, "POST", "null", "content-type"),
        console_preflight_request(
            CONSOLE_ASSOCIATION,
            "DELETE",
            CONSOLE_ORIGIN,
            "content-type",
        ),
        console_preflight_request("/v1/auth/me", "DELETE", CONSOLE_ORIGIN, "content-type"),
        console_preflight_request("/v1/auth/callback", "POST", CONSOLE_ORIGIN, "content-type"),
        console_preflight_request("/v1/auth/unknown", "POST", CONSOLE_ORIGIN, "content-type"),
        console_preflight_request(
            &CONSOLE_ASSOCIATION.replace("/confirm", "/unknown"),
            "POST",
            CONSOLE_ORIGIN,
            "content-type",
        ),
        console_preflight_request(
            &CONSOLE_ASSOCIATION.replace("30000000-0000-4000-8000-000000000001", "bad-id"),
            "POST",
            CONSOLE_ORIGIN,
            "content-type",
        ),
        console_preflight_request(
            "/v1/identity/association-challenges/30000000-0000-4000-8000-000000000001/create",
            "POST",
            CONSOLE_ORIGIN,
            "content-type",
        ),
        console_preflight_request(
            &CONSOLE_ASSOCIATION.replace(
                "external-association-challenges",
                "external-association-sources",
            ),
            "POST",
            CONSOLE_ORIGIN,
            "content-type",
        ),
    ];
    for headers in [
        "authorization",
        "x-api-key",
        "x-user-id",
        "content-type,x-organization-id",
        "",
        "content-type,content-type",
    ] {
        requests.push(console_preflight_request(
            CONSOLE_ASSOCIATION,
            "POST",
            CONSOLE_ORIGIN,
            headers,
        ));
    }
    for name in [
        "origin",
        "access-control-request-method",
        "access-control-request-headers",
    ] {
        let mut request =
            console_preflight_request(CONSOLE_ASSOCIATION, "POST", CONSOLE_ORIGIN, "content-type");
        let value = request.headers()[name].clone();
        request
            .headers_mut()
            .append(HeaderName::from_bytes(name.as_bytes()).unwrap(), value);
        requests.push(request);
    }
    let mut missing =
        console_preflight_request(CONSOLE_ASSOCIATION, "POST", CONSOLE_ORIGIN, "content-type");
    missing.headers_mut().remove("origin");
    requests.push(missing);
    for request in requests {
        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(!response
            .headers()
            .contains_key("access-control-allow-origin"));
        assert!(!response.headers().contains_key("set-cookie"));
    }
    assert!(recorder.0.lock().unwrap().is_empty());
}

#[tokio::test]
async fn console_preflight_does_not_authorize_a_real_learner_operation() {
    let recorder = Arc::new(ActorRecordingUpstream::default());
    let router = gateway_router(runtime_state_with_upstream(
        Arc::new(NoOwner),
        recorder.clone(),
    ));
    assert_eq!(
        router
            .clone()
            .oneshot(console_preflight_request(
                CONSOLE_ASSOCIATION,
                "POST",
                CONSOLE_ORIGIN,
                "content-type"
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::NO_CONTENT
    );
    for (session, expected) in [
        (None, StatusCode::UNAUTHORIZED),
        (Some("observation-impersonated"), StatusCode::FORBIDDEN),
        (Some("valid"), StatusCode::UNAUTHORIZED),
        (Some("valid-uuid"), StatusCode::FORBIDDEN),
    ] {
        let mut request = Request::builder()
            .method("POST")
            .uri(CONSOLE_ASSOCIATION)
            .header("origin", CONSOLE_ORIGIN)
            .header("content-type", "application/json");
        if let Some(session) = session {
            request = request.header("cookie", format!("sessionId={session}"));
        }
        let response = router
            .clone()
            .oneshot(request.body(Body::from("{}")).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        assert_eq!(
            response.headers()["access-control-allow-origin"],
            CONSOLE_ORIGIN
        );
        assert_eq!(
            response.headers()["access-control-allow-credentials"],
            "true"
        );
        assert_eq!(response.headers()["cache-control"], "no-store");
    }
    let duplicate = Request::builder()
        .method("POST")
        .uri(CONSOLE_ASSOCIATION)
        .header("origin", CONSOLE_ORIGIN)
        .header("origin", CONSOLE_ORIGIN)
        .header("cookie", "sessionId=observation-session")
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();
    // HTTP permits multiple field lines; the real operation must retain its
    // exact-one-Origin check even after a successful preflight.
    assert_eq!(duplicate.headers().get_all("origin").iter().count(), 2);
    let response = router.oneshot(duplicate).await.unwrap();
    assert!(!response.status().is_success());
    assert!(!response
        .headers()
        .contains_key("access-control-allow-origin"));
    assert!(recorder.0.lock().unwrap().is_empty());
}

#[tokio::test]
async fn console_error_headers_exclude_unallowed_origins_and_nonlearner_operations() {
    let recorder = Arc::new(ActorRecordingUpstream::default());
    let router = gateway_router(runtime_state_with_upstream(
        Arc::new(NoOwner),
        recorder.clone(),
    ));
    for (path, origin) in [
        (CONSOLE_ASSOCIATION, None),
        (CONSOLE_ASSOCIATION, Some("https://untrusted.example")),
        ("/v1/identity/association-challenges/30000000-0000-4000-8000-000000000001/create", Some(CONSOLE_ORIGIN)),
        ("/v1/organizations/20000000-0000-4000-8000-000000000001/external-association-sources/30000000-0000-4000-8000-000000000001/create", Some(CONSOLE_ORIGIN)),
    ] {
        let mut request = Request::builder().method("POST").uri(path).header("content-type", "application/json");
        if path == CONSOLE_ASSOCIATION { request = request.header("cookie", "sessionId=observation-session"); }
        if let Some(origin) = origin { request = request.header("origin", origin); }
        let response = router.clone().oneshot(request.body(Body::from("{}")).unwrap()).await.unwrap();
        assert!(!response.status().is_success(), "{path}");
        assert!(!response.headers().contains_key("access-control-allow-origin"), "{path}");
    }
    assert!(recorder.0.lock().unwrap().is_empty());
}

/// Exercise the production router over HTTP. The opt-in hold only serves a
/// separately run local browser fixture; identities and upstreams remain test
/// doubles, so this cannot attest live Auth, provider or installed acceptance.
#[tokio::test]
async fn console_preflight_http_boundary() {
    let browser = std::env::var("MARTY_TEST_GATEWAY_BROWSER").as_deref() == Ok("1");
    let recorder = Arc::new(ActorRecordingUpstream::default());
    let mut state = runtime_state_with_upstream(Arc::new(NoOwner), recorder.clone());
    if browser {
        Arc::get_mut(&mut state)
            .unwrap()
            .cors_origins
            .insert("https://console.elevenid.test:38443".into());
    }
    let listener = tokio::net::TcpListener::bind(if browser {
        "0.0.0.0:38143"
    } else {
        "127.0.0.1:0"
    })
    .await
    .unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        axum::serve(listener, gateway_router(state)).await.unwrap();
    });
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let base = format!("http://127.0.0.1:{port}");
    for (path, method) in [(CONSOLE_ASSOCIATION, "POST"), ("/v1/auth/me", "PATCH")] {
        let response = client
            .request(reqwest::Method::OPTIONS, format!("{base}{path}"))
            .header("origin", CONSOLE_ORIGIN)
            .header("access-control-request-method", method)
            .header("access-control-request-headers", "content-type")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(response.headers()["access-control-allow-methods"], method);
    }
    let response = client
        .post(format!("{base}{CONSOLE_ASSOCIATION}"))
        .header("origin", CONSOLE_ORIGIN)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers()["access-control-allow-origin"],
        CONSOLE_ORIGIN
    );
    assert_eq!(
        response.headers()["access-control-allow-credentials"],
        "true"
    );
    assert!(recorder.0.lock().unwrap().is_empty());
    if browser {
        let directory = std::path::Path::new("/browser-evidence");
        let nonce = uuid::Uuid::new_v4().to_string();
        std::fs::write(
            directory.join("ready.json"),
            serde_json::to_vec(&json!({
                "fixture": true, "nonce": nonce, "port": port,
                "scope": "Actual Gateway router with controlled identity/upstream ports",
            }))
            .unwrap(),
        )
        .unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(180);
        loop {
            if let Ok(bytes) = std::fs::read(directory.join("browser-complete.json")) {
                let complete: Value = serde_json::from_slice(&bytes).unwrap();
                assert_eq!(complete["nonce"], nonce);
                assert_eq!(complete["passed"], true);
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "browser fixture timed out"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let records = recorder
            .0
            .lock()
            .unwrap()
            .iter()
            .map(|(service, request)| {
                json!({
                    "service": service, "path": request.path,
                    "method": format!("{:?}", request.method),
                    "authenticated_actor_present": request.header("x-user-id").is_some(),
                })
            })
            .collect::<Vec<_>>();
        std::fs::write(
            directory.join("gateway-observations.json"),
            serde_json::to_vec(&json!({"fixture":true,"upstream_operations":records})).unwrap(),
        )
        .unwrap();
    }
    server.abort();
}

#[tokio::test]
async fn console_catalog_preflight_supports_dashboard_preferences_and_conditional_json_writes() {
    let recorder = Arc::new(ActorRecordingUpstream::default());
    let router = gateway_router(runtime_state_with_upstream(
        Arc::new(NoOwner),
        recorder.clone(),
    ));
    for (path, method, requested) in [
        (
            "/v1/organizations/org-1/members/me/permissions",
            "GET",
            "content-type, x-mip-version, x-request-id",
        ),
        ("/v1/me/preferences", "GET", "content-type"),
        ("/v1/me/preferences", "PUT", "Content-Type, Idempotency-Key"),
        ("/v1/signing-keys/config", "PATCH", "content-type, if-match"),
        (
            "/v1/trust-profiles",
            "POST",
            "content-type, idempotency-key",
        ),
    ] {
        let response = router
            .clone()
            .oneshot(console_preflight_request(
                path,
                method,
                CONSOLE_ORIGIN,
                requested,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT, "{method} {path}");
        assert_eq!(
            response.headers()["access-control-allow-origin"],
            CONSOLE_ORIGIN
        );
        assert_eq!(
            response.headers()["access-control-allow-credentials"],
            "true"
        );
        assert_eq!(response.headers()["access-control-allow-methods"], method);
        assert_eq!(
            response.headers()["access-control-allow-headers"],
            requested.to_ascii_lowercase()
        );
        assert!(!response.headers().contains_key("set-cookie"));
    }
    assert!(recorder.0.lock().unwrap().is_empty());
}

#[tokio::test]
async fn console_catalog_transport_rejects_attribution_authority_and_ambiguous_preflights() {
    let recorder = Arc::new(ActorRecordingUpstream::default());
    let router = gateway_router(runtime_state_with_upstream(
        Arc::new(NoOwner),
        recorder.clone(),
    ));
    for (origin, requested) in [
        ("https://untrusted.example", "content-type"),
        ("null", "content-type"),
        (CONSOLE_ORIGIN, "authorization"),
        (CONSOLE_ORIGIN, "x-api-key"),
        (CONSOLE_ORIGIN, "x-user-id"),
        (CONSOLE_ORIGIN, "content-type, content-type"),
        (CONSOLE_ORIGIN, "content-type, x-organization-id"),
        (CONSOLE_ORIGIN, ""),
    ] {
        let response = router
            .clone()
            .oneshot(console_preflight_request(
                "/v1/me/preferences",
                "PUT",
                origin,
                requested,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(!response
            .headers()
            .contains_key("access-control-allow-origin"));
    }
    for name in [
        "origin",
        "access-control-request-method",
        "access-control-request-headers",
    ] {
        let mut request =
            console_preflight_request("/v1/me/preferences", "PUT", CONSOLE_ORIGIN, "content-type");
        let value = request.headers()[name].clone();
        request
            .headers_mut()
            .append(HeaderName::from_bytes(name.as_bytes()).unwrap(), value);
        let response = router.clone().oneshot(request).await.unwrap();
        assert!(response.status().is_client_error());
        assert!(!response
            .headers()
            .contains_key("access-control-allow-origin"));
    }
    for (path, method) in [
        ("/v1/me/preferences", "DELETE"),
        ("/v1/unknown", "POST"),
        ("/internal/metrics", "GET"),
        ("/v1/evidence/observations", "POST"),
    ] {
        let response = router
            .clone()
            .oneshot(console_preflight_request(
                path,
                method,
                CONSOLE_ORIGIN,
                "content-type",
            ))
            .await
            .unwrap();
        assert!(response.status().is_client_error(), "{method} {path}");
        assert!(!response
            .headers()
            .contains_key("access-control-allow-origin"));
    }
    assert!(recorder.0.lock().unwrap().is_empty());
}

#[tokio::test]
async fn console_catalog_errors_are_readable_without_authorizing_operations() {
    let recorder = Arc::new(ActorRecordingUpstream::default());
    let router = gateway_router(runtime_state_with_upstream(
        Arc::new(NoOwner),
        recorder.clone(),
    ));
    for (path, method) in [
        ("/v1/me/preferences", "GET"),
        ("/v1/me/preferences", "PUT"),
        ("/v1/organizations/org-1/members/me/permissions", "GET"),
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("origin", CONSOLE_ORIGIN)
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{method} {path}"
        );
        assert_eq!(
            response.headers()["access-control-allow-origin"],
            CONSOLE_ORIGIN
        );
        assert_eq!(
            response.headers()["access-control-allow-credentials"],
            "true"
        );
        assert_eq!(
            response.headers()["access-control-expose-headers"],
            "etag, location, retry-after, x-request-id, x-mip-version, content-disposition"
        );
        assert!(!response.headers().contains_key("set-cookie"));
    }
    for origin in ["https://untrusted.example", "null"] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/v1/me/preferences")
                    .header("cookie", "sessionId=valid")
                    .header("origin", origin)
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(!response
            .headers()
            .contains_key("access-control-allow-origin"));
    }
    assert!(recorder.0.lock().unwrap().is_empty());
}

#[tokio::test]
async fn console_catalog_transport_preserves_tenant_and_body_rejections() {
    let recorder = Arc::new(ActorRecordingUpstream::default());
    let mut state = runtime_state_with_upstream(Arc::new(NoOwner), recorder.clone());
    Arc::get_mut(&mut state).unwrap().memberships = Arc::new(ScriptedMembership("missing"));
    let router = gateway_router(state);
    for (method, path, content_type, expected) in [
        (
            "GET",
            "/v1/signing-keys/config?organization_id=org-other",
            "application/json",
            StatusCode::FORBIDDEN,
        ),
        (
            "POST",
            "/v1/trust-profiles",
            "text/plain",
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("cookie", "sessionId=valid")
                    .header("origin", CONSOLE_ORIGIN)
                    .header("content-type", content_type)
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected, "{method} {path}");
        assert_eq!(
            response.headers()["access-control-allow-origin"],
            CONSOLE_ORIGIN
        );
        assert_eq!(
            response.headers()["access-control-allow-credentials"],
            "true"
        );
    }
    assert!(recorder.0.lock().unwrap().is_empty());
}
