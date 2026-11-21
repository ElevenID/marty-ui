fn lifecycle_fixture() -> Value {
    serde_json::from_str(include_str!("../fixtures/delegation-lifecycle.json")).unwrap()
}
fn lifecycle_request() -> Value {
    lifecycle_fixture()["command"].clone()
}
fn lifecycle_result(command: &Value) -> Value {
    let fixture = lifecycle_fixture();
    assert_eq!(command, &fixture["command"]);
    fixture["result"].clone()
}

#[tokio::test(start_paused = true)]
async fn candidate_human_mutations_bound_body_stream_time_before_dispatch() {
    let (state, _, upstream) = candidate_admin_test_state(true, true, true);
    let app = gateway_router(state);
    for path in [
        format!("/v1/organizations/{ADMIN_ORG}/delegation-commands"),
        format!("/v1/organizations/{ADMIN_ORG}/agents/{ADMIN_AGENT}/enrollment-challenges"),
    ] {
        let (parts, _) = admin_request("POST", &path, "").into_parts();
        let body = Body::from_stream(tokio_stream::pending::<
            Result<axum::body::Bytes, std::io::Error>,
        >());
        let response = app
            .clone()
            .oneshot(Request::from_parts(parts, body))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
        assert_eq!(response.headers()["cache-control"], "no-store");
    }
    assert!(upstream.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn lifecycle_commands_default_off_and_unsupported_use_do_not_reach_upstream() {
    let path = format!("/v1/organizations/{ADMIN_ORG}/delegation-commands");
    let (state, _, upstream) = candidate_admin_test_state(false, false, false);
    let response = gateway_router(state)
        .oneshot(admin_request(
            "POST",
            &path,
            &lifecycle_request().to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(upstream.calls.lock().unwrap().is_empty());
    let mut doc = json!({"paths":{}});
    let original = doc.clone();
    crate::delegation_commands::extend_openapi(&mut doc, false);
    assert_eq!(doc, original);
    let (state, _, upstream) = candidate_admin_test_state(false, true, false);
    let app = gateway_router(state);
    for command in ["START_USE", "FINALIZE_USE", "ACTIVATE_GRANT", "UNKNOWN"] {
        let mut body = lifecycle_request();
        body["command"] = json!(command);
        let response = app
            .clone()
            .oneshot(admin_request("POST", &path, &body.to_string()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{command}");
    }
    assert!(upstream.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn lifecycle_commands_bind_original_intent_and_recheck_current_access_on_every_request() {
    let path = format!("/v1/organizations/{ADMIN_ORG}/delegation-commands");
    let (state, provider, upstream) = candidate_admin_test_state(false, true, false);
    let command = lifecycle_request();
    *upstream.response.lock().unwrap() = Some((200, lifecycle_result(&command)));
    let app = gateway_router(state);
    for _ in 0..2 {
        let mut request = admin_request("POST", &path, &command.to_string());
        for (name, value) in [
            ("x-marty-command-user-id", ADMIN_AGENT),
            ("x-marty-command-session-ref", "attacker"),
            ("x-user-id", "attacker"),
            ("idempotency-key", "same-key"),
            ("x-service-token", "attacker"),
        ] {
            request.headers_mut().insert(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert!(!response.headers().contains_key("etag"));
        assert!(!response.headers().contains_key("set-cookie"));
    }
    assert_eq!(
        upstream.calls.lock().unwrap().len(),
        2,
        "generic idempotency must not replay a response"
    );
    assert_eq!(provider.membership_calls.load(Ordering::SeqCst), 2);
    {
        let calls = upstream.calls.lock().unwrap();
        let (service, request) = &calls[0];
        assert_eq!(service, "delegated-commands");
        assert_eq!(admin_header(request, "x-marty-command-user-id"), ADMIN_USER);
        assert_eq!(
            admin_header(request, "x-marty-command-organization-id"),
            ADMIN_ORG
        );
        assert_eq!(
            admin_header(request, "x-required-permission"),
            "delegation-grant:create"
        );
        assert_eq!(admin_header(request, "x-service-token"), "s".repeat(32));
        assert!(admin_header(request, "x-marty-command-session-ref")
            .starts_with("urn:marty:session:sha256:"));
        assert!(!request
            .headers
            .keys()
            .any(|key| key.eq_ignore_ascii_case("cookie")
                || key.eq_ignore_ascii_case("idempotency-key")));
        assert_eq!(
            request.body.as_deref(),
            Some(command.to_string().as_bytes())
        );
    }
    for (mode, status) in [
        (1, 403),
        (2, 403),
        (3, 403),
        (4, 403),
        (5, 503),
        (6, 403),
        (8, 403),
        (9, 403),
        (10, 403),
    ] {
        provider.mode.store(mode, Ordering::SeqCst);
        let response = app
            .clone()
            .oneshot(admin_request("POST", &path, &command.to_string()))
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), status, "mode {mode}");
    }
    assert_eq!(upstream.calls.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn lifecycle_commands_reject_actor_claims_nulls_duplicate_fields_and_cross_tenant_terms() {
    let path = format!("/v1/organizations/{ADMIN_ORG}/delegation-commands");
    let (state, _, upstream) = candidate_admin_test_state(false, true, false);
    let app = gateway_router(state);
    let mut invalid = Vec::new();
    for key in ["actor", "organization_id", "approval", "verified", "status"] {
        let mut body = lifecycle_request();
        body[key] = json!("untrusted");
        invalid.push(body.to_string());
    }
    for pointer in ["/terms/grantor/id", "/terms/subject/id"] {
        let mut body = lifecycle_request();
        *body.pointer_mut(pointer).unwrap() = json!("urn:attacker");
        invalid.push(body.to_string());
    }
    let mut body = lifecycle_request();
    body["terms"]["binding"]["key_thumbprint"] = Value::Null;
    invalid.push(body.to_string());
    let raw = lifecycle_request().to_string();
    invalid.push(raw.replacen(
        "\"CREATE_GRANT\"",
        "\"CREATE_GRANT\",\"command\":\"REVOKE_GRANT\"",
        1,
    ));
    invalid.push(raw.replacen(
        "\"method\":\"KEY\"",
        "\"method\":\"KEY\",\"method\":\"KEY\"",
        1,
    ));
    for raw in invalid {
        let response = app
            .clone()
            .oneshot(admin_request("POST", &path, &raw))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    let mut no_origin = admin_request("POST", &path, &raw);
    no_origin.headers_mut().remove("origin");
    assert_eq!(
        app.clone().oneshot(no_origin).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let api_key = Request::builder()
        .method("POST")
        .uri(&path)
        .header("x-api-key", "any-key")
        .header("origin", "https://console.example")
        .header("content-type", "application/json")
        .body(Body::from(raw.clone()))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(api_key).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        app.clone()
            .oneshot(admin_request("POST", &format!("{path}?ignored=1"), &raw))
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert!(upstream.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn lifecycle_commands_validate_returned_original_result_and_preserve_historical_recovery() {
    let path = format!("/v1/organizations/{ADMIN_ORG}/delegation-commands");
    let (state, _, upstream) = candidate_admin_test_state(false, true, false);
    let app = gateway_router(state);
    let command = lifecycle_request();
    let result = lifecycle_result(&command);
    for (pointer, value) in [
        ("/original_command_id", json!(ADMIN_AGENT)),
        (
            "/command_digest",
            json!(format!("sha256:{}", "f".repeat(64))),
        ),
        ("/recovered", json!("true")),
        ("/result/grant/organization_id", json!(ADMIN_AGENT)),
        ("/result/grant/terms/delegate/id", json!("urn:attacker")),
        ("/result/grant/status", json!("ACTIVE")),
        ("/result/grant/revision", json!(2)),
        (
            "/result/grant/terms_digest",
            json!(format!("sha256:{}", "e".repeat(64))),
        ),
    ] {
        let mut changed = result.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        *upstream.response.lock().unwrap() = Some((200, changed));
        assert_eq!(
            app.clone()
                .oneshot(admin_request("POST", &path, &command.to_string()))
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_GATEWAY,
            "{pointer}"
        );
    }
    let recover = json!({"profile":"urn:marty:delegation-command:v1","command":"RECOVER_RESULT","original_command_id":ADMIN_REVIEW,"expected_command_digest":result["command_digest"]});
    let mut historic = result.clone();
    historic["recovered"] = json!(true);
    // Original snapshot expired months ago. Recovery must preserve that snapshot
    // without turning it into a current authorization or refreshing its dates.
    *upstream.response.lock().unwrap() = Some((200, historic.clone()));
    let response = app
        .clone()
        .oneshot(admin_request("POST", &path, &recover.to_string()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        serde_json::from_slice::<Value>(&to_bytes(response.into_body(), 131072).await.unwrap())
            .unwrap(),
        historic
    );
    let calls = upstream.calls.lock().unwrap();
    assert_eq!(
        admin_header(&calls.last().unwrap().1, "x-required-permission"),
        "delegation-grant:view"
    );
}

#[tokio::test]
async fn lifecycle_commands_preflight_requires_selected_route_and_exact_origin() {
    let path = format!("/v1/organizations/{ADMIN_ORG}/delegation-commands");
    let (state, _, upstream) = candidate_admin_test_state(false, true, false);
    let app = gateway_router(state);
    for (origin, headers, status) in [
        ("https://console.example", "content-type,x-mip-version", 204),
        ("https://other.example", "content-type", 403),
        ("https://console.example", "x-marty-command-user-id", 403),
    ] {
        let request = Request::builder()
            .method("OPTIONS")
            .uri(&path)
            .header("origin", origin)
            .header("access-control-request-method", "POST")
            .header("access-control-request-headers", headers)
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.clone()
                .oneshot(request)
                .await
                .unwrap()
                .status()
                .as_u16(),
            status
        );
    }
    assert!(upstream.calls.lock().unwrap().is_empty());
}
