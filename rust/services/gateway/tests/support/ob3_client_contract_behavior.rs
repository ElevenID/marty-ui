// Public client boundary regressions: real middleware, adaptation and proxy routing.
#[derive(Default)]
struct ClientContractUpstream(std::sync::Mutex<Vec<(String, GatewayRequest)>>);

#[async_trait]
impl UpstreamClient for ClientContractUpstream {
    async fn send(
        &self,
        instance: &ServiceInstance,
        request: GatewayRequest,
    ) -> Result<GatewayResponse, PlatformError> {
        self.0
            .lock()
            .unwrap()
            .push((instance.service_name.clone(), request.clone()));
        SuccessfulUpstream.send(instance, request).await
    }
}

fn client_issuance_request(key: Option<&str>, employee_id: &str) -> Request {
    let mut request = Request::builder()
        .method("POST")
        .uri("/v1/issuance")
        .header("cookie", "sessionId=valid")
        .header("content-type", "application/json");
    if let Some(key) = key {
        request = request.header("idempotency-key", key);
    }
    request
        .body(Body::from(
            serde_json::to_vec(&json!({
                "organization_id":"org-1", "credential_template_id":"template-1",
                "authorized_client": {
                    "client_id":"official-wallet",
                    "jwks":{"keys":[{
                        "kty":"EC", "crv":"P-256", "kid":"wallet-key",
                        "x":"f83OJ3D2xF4A9O2jZ8M7VJQYxqvR8K0K8qZ8K0K8qZ8",
                        "y":"x_FEzRu9G8K0K8qZ8K0K8qZ8K0K8qZ8K0K8qZ8K0K8q"
                    }]}
                },
                "claims":{"employee_id":employee_id}
            }))
            .unwrap(),
        ))
        .unwrap()
}

#[tokio::test]
async fn issuance_client_key_reaches_durable_owner_and_cache_replay_stays_exact() {
    let upstream = Arc::new(ClientContractUpstream::default());
    let router = gateway_router(runtime_state_with_upstream(
        Arc::new(NoOwner),
        upstream.clone(),
    ));
    let first = router
        .clone()
        .oneshot(client_issuance_request(Some("course:event-1"), "123"))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(first.headers()["idempotency-replayed"], "false");
    let count = upstream.0.lock().unwrap().len();
    {
        let calls = upstream.0.lock().unwrap();
        let issuance = calls
            .iter()
            .filter(|(_, request)| request.path == "/v1/issuance/initiate")
            .collect::<Vec<_>>();
        assert_eq!(issuance.len(), 1);
        assert_eq!(issuance[0].0, issuance_native::NATIVE_SERVICE);
        assert_eq!(
            issuance[0].1.header("idempotency-key"),
            Some("course:event-1")
        );
        assert!(calls
            .iter()
            .filter(|(_, request)| request.path != "/v1/issuance/initiate")
            .all(|(_, request)| request.header("idempotency-key").is_none()));
        assert!(calls
            .iter()
            .any(|(_, request)| request.path == "/v1/issuance/oid4vci-clients"));
    }
    let replay = router
        .clone()
        .oneshot(client_issuance_request(Some("course:event-1"), "123"))
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::OK);
    assert_eq!(replay.headers()["idempotency-replayed"], "true");
    assert_eq!(upstream.0.lock().unwrap().len(), count);
    let conflict = router
        .clone()
        .oneshot(client_issuance_request(Some("course:event-1"), "456"))
        .await
        .unwrap();
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    assert_eq!(upstream.0.lock().unwrap().len(), count);

    // Invalid headers must not alias a populated cache entry or reach any dependency.
    for invalid in [
        " course:event-1",
        "course:event-1 ",
        "",
        "a,b",
        "a/b",
        "a b",
        "a\tb",
    ] {
        let response = router
            .clone()
            .oneshot(client_issuance_request(Some(invalid), "123"))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "{invalid:?}"
        );
    }
    let mut duplicate = client_issuance_request(Some("course:event-1"), "123");
    duplicate
        .headers_mut()
        .append("idempotency-key", "course:event-2".parse().unwrap());
    assert_eq!(
        router.clone().oneshot(duplicate).await.unwrap().status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let mut non_ascii = client_issuance_request(Some("course:event-1"), "123");
    non_ascii.headers_mut().insert(
        "idempotency-key",
        axum::http::HeaderValue::from_bytes(&[0x80]).unwrap(),
    );
    assert_eq!(
        router.clone().oneshot(non_ascii).await.unwrap().status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(upstream.0.lock().unwrap().len(), count);

    // A fresh gateway cache still forwards the durable key unchanged.
    let restarted = gateway_router(runtime_state_with_upstream(
        Arc::new(NoOwner),
        upstream.clone(),
    ));
    assert_eq!(
        restarted
            .oneshot(client_issuance_request(Some("course:event-1"), "123"))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        upstream
            .0
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .1
            .header("idempotency-key"),
        Some("course:event-1")
    );
    assert_eq!(
        router
            .oneshot(client_issuance_request(None, "789"))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert!(upstream
        .0
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .1
        .header("idempotency-key")
        .is_none());
}

#[test]
fn issuance_key_admission_matches_documented_durable_bounds() {
    let document = GatewayContract::load().unwrap().openapi_document("test");
    let parameters = document["paths"]["/v1/issuance"]["post"]["parameters"]
        .as_array()
        .unwrap();
    let key = parameters
        .iter()
        .find(|parameter| parameter["name"] == "Idempotency-Key")
        .unwrap();
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/issuance-initiation.json"
    ))
    .unwrap();
    assert_eq!(
        key["schema"]["pattern"],
        contract["idempotency"]["key_pattern"]
    );
    let mut headers = axum::http::HeaderMap::new();
    assert_eq!(issuance_idempotency_key(&headers).unwrap(), None);
    for valid in ["a".to_owned(), "Abc012._:-".to_owned(), "a".repeat(128)] {
        headers.insert("idempotency-key", valid.parse().unwrap());
        assert_eq!(
            issuance_idempotency_key(&headers).unwrap().as_deref(),
            Some(valid.as_str())
        );
    }
    headers.insert("idempotency-key", "a".repeat(129).parse().unwrap());
    assert!(issuance_idempotency_key(&headers).is_err());
}

#[tokio::test]
async fn vc_api_verification_checks_combined_machine_scopes_before_replay() {
    for (path, field) in [
        ("/v1/vc-api/credentials/verify", "verifiableCredential"),
        ("/v1/vc-api/presentations/verify", "verifiablePresentation"),
    ] {
        let upstream = Arc::new(ClientContractUpstream::default());
        let router = gateway_router(runtime_state_with_upstream(
            Arc::new(NoOwner),
            upstream.clone(),
        ));
        let request = |key: &str| {
            Request::builder()
                .method("POST")
                .uri(format!(
                    "{path}?organization_id=org-1&presentation_policy_id=policy-1"
                ))
                .header("x-api-key", key)
                .header("content-type", "application/json")
                .header("idempotency-key", "verify:event-1")
                .body(Body::from(
                    serde_json::to_vec(&json!({(field):"header.payload.signature"})).unwrap(),
                ))
                .unwrap()
        };
        let complete = router
            .clone()
            .oneshot(request("verification-complete"))
            .await
            .unwrap();
        assert_eq!(complete.status(), StatusCode::OK, "{path}");
        let count = upstream.0.lock().unwrap().len();
        assert_eq!(count, 1);
        for accepted in ["verification-alternative", "verification-admin"] {
            let response = router.clone().oneshot(request(accepted)).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()["idempotency-replayed"], "true");
        }
        for rejected in [
            "verification-credentials-only",
            "verification-trust-only",
            "verification-other",
        ] {
            let response = router.clone().oneshot(request(rejected)).await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::FORBIDDEN,
                "{path} {rejected}"
            );
            assert!(!response.headers().contains_key("idempotency-replayed"));
            if rejected == "verification-credentials-only" {
                let body = to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
                    .await
                    .unwrap();
                let body: Value = serde_json::from_slice(&body).unwrap();
                assert!(body["detail"].as_str().unwrap().contains("trust:read"));
            }
        }
        assert_eq!(upstream.0.lock().unwrap().len(), count);
        let document = GatewayContract::load().unwrap().openapi_document("test");
        let description = document["paths"][path]["post"]["description"]
            .as_str()
            .unwrap();
        assert!(description.contains("credentials:read plus trust:read"));
        assert!(description.contains("presentation-policy:view"));
    }
}
