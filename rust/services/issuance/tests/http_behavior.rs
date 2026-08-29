use axum::{
    body::Body,
    http::{Method, Request},
};
use marty_issuance_service::{
    http::router, transport::TransportPolicy, IssuanceRuntime, IssuanceServiceConfig,
};
use marty_oid4vci::discovery::StaticDiscoveryDocuments;
use serde_json::Value;
use tower::ServiceExt;

async fn json_body(response: axum::response::Response) -> Value {
    let body = response_body(response).await;
    serde_json::from_slice(&body).expect("json")
}

async fn response_body(response: axum::response::Response) -> Vec<u8> {
    axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body")
        .to_vec()
}

#[tokio::test]
async fn native_health_preserves_the_legacy_body_and_mmf_readiness() {
    let coverage: Value = serde_json::from_str(include_str!(
        "../../../../contracts/issuance-native-coverage.json"
    ))
    .expect("coverage");
    let expected = &coverage["native_http"][0]["response"];
    let config =
        IssuanceServiceConfig::from_values(std::iter::empty::<(String, String)>()).expect("config");
    let runtime = IssuanceRuntime::new(&config).expect("runtime");
    let discovery =
        StaticDiscoveryDocuments::new(&config.issuer_base_url, &config.issuer_display_name);
    let transport = TransportPolicy::new(config.cors_allowed_origins.clone());
    let app = router(runtime.state(), discovery, transport);

    let health = app
        .clone()
        .oneshot(
            Request::get("/health")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(health.status().as_u16(), expected["status_code"]);
    assert_eq!(json_body(health).await, expected["body"]);

    let not_ready = app
        .clone()
        .oneshot(Request::get("/ready").body(Body::empty()).expect("request"))
        .await
        .expect("response");
    assert_eq!(not_ready.status(), 503);

    runtime.mark_listener_healthy().expect("listener");
    runtime.activate().expect("active");
    let ready = app
        .oneshot(Request::get("/ready").body(Body::empty()).expect("request"))
        .await
        .expect("response");
    assert_eq!(ready.status(), 200);
    assert_eq!(json_body(ready).await["ready"], true);
}

#[tokio::test]
async fn native_static_discovery_matches_the_python_oracle_contract() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/issuance-static-discovery.json"
    ))
    .expect("discovery contract");
    let inputs = &contract["inputs"];
    let transport_contract = &contract["transport"];
    let request_id_contract = &transport_contract["request_id"];
    let cors_contract = &transport_contract["cors"];
    let config = IssuanceServiceConfig::from_values([
        (
            "ISSUER_BASE_URL".to_owned(),
            inputs["issuer_base_url"]
                .as_str()
                .expect("base URL")
                .to_owned(),
        ),
        (
            "ISSUER_DISPLAY_NAME".to_owned(),
            inputs["issuer_display_name"]
                .as_str()
                .expect("display name")
                .to_owned(),
        ),
        (
            "CORS_ALLOWED_ORIGINS".to_owned(),
            cors_contract["allowed_origin"]
                .as_str()
                .expect("allowed origin")
                .to_owned(),
        ),
    ])
    .expect("config");
    let runtime = IssuanceRuntime::new(&config).expect("runtime");
    let documents =
        StaticDiscoveryDocuments::new(&config.issuer_base_url, &config.issuer_display_name);
    let transport = TransportPolicy::new(config.cors_allowed_origins.clone());
    let app = router(runtime.state(), documents, transport);

    for case in contract["cases"].as_array().expect("cases") {
        let method = Method::from_bytes(case["method"].as_str().expect("method").as_bytes())
            .expect("valid method");
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(case["path"].as_str().expect("path"))
                    .header(
                        request_id_contract["request_header"]
                            .as_str()
                            .expect("request ID header"),
                        request_id_contract["propagated_value"]
                            .as_str()
                            .expect("request ID"),
                    )
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(
            response.status().as_u16(),
            case["status_code"].as_u64().expect("status") as u16,
            "{}",
            case["operation"]
        );
        assert_eq!(
            response
                .headers()
                .get(
                    request_id_contract["response_header"]
                        .as_str()
                        .expect("response ID header"),
                )
                .expect("response request ID"),
            request_id_contract["propagated_value"]
                .as_str()
                .expect("request ID"),
            "{}",
            case["operation"]
        );
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .expect("content type"),
            case["content_type"]
                .as_str()
                .expect("expected content type"),
            "{}",
            case["operation"]
        );
        assert_eq!(
            json_body(response).await,
            case["body"],
            "{}",
            case["operation"]
        );
    }

    let generated = app
        .clone()
        .oneshot(
            Request::get(contract["cases"][0]["path"].as_str().expect("path"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let generated_request_id = generated
        .headers()
        .get(
            request_id_contract["response_header"]
                .as_str()
                .expect("response ID header"),
        )
        .expect("generated request ID")
        .to_str()
        .expect("request ID string");
    assert_eq!(generated_request_id.len(), 8);
    assert!(generated_request_id
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
    let empty_request_id = app
        .clone()
        .oneshot(
            Request::get(contract["cases"][0]["path"].as_str().expect("path"))
                .header("x-request-id", "")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let empty_request_id = empty_request_id
        .headers()
        .get("x-request-id")
        .expect("generated request ID")
        .to_str()
        .expect("request ID string");
    assert_eq!(empty_request_id.len(), 8);
    assert!(empty_request_id
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));

    let simple_cors = app
        .clone()
        .oneshot(
            Request::get(contract["cases"][0]["path"].as_str().expect("path"))
                .header(
                    "origin",
                    cors_contract["allowed_origin"]
                        .as_str()
                        .expect("allowed origin"),
                )
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    for (name, value) in cors_contract["simple_response_headers"]
        .as_object()
        .expect("simple CORS headers")
    {
        assert_eq!(
            simple_cors.headers().get(name).expect("CORS header"),
            value.as_str().expect("CORS header value")
        );
    }

    let wildcard = &cors_contract["wildcard_simple_request"];
    let wildcard_app = router(
        runtime.state(),
        StaticDiscoveryDocuments::new(&config.issuer_base_url, &config.issuer_display_name),
        TransportPolicy::new([wildcard["configured_origin"]
            .as_str()
            .expect("configured wildcard")
            .to_owned()]),
    );
    let wildcard_response = wildcard_app
        .oneshot(
            Request::get(contract["cases"][0]["path"].as_str().expect("path"))
                .header(
                    "origin",
                    wildcard["request_origin"]
                        .as_str()
                        .expect("wildcard request origin"),
                )
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    for (name, value) in wildcard["response_headers"]
        .as_object()
        .expect("wildcard response headers")
    {
        assert_eq!(
            wildcard_response
                .headers()
                .get(name)
                .expect("wildcard CORS header"),
            value.as_str().expect("wildcard CORS value")
        );
    }

    for contract_key in ["preflight", "denied_preflight", "denied_method_preflight"] {
        let case = &cors_contract[contract_key];
        let mut request = Request::builder()
            .method(case["method"].as_str().expect("method"))
            .uri(case["path"].as_str().expect("path"));
        for (name, value) in case["request_headers"]
            .as_object()
            .expect("request headers")
        {
            request = request.header(name, value.as_str().expect("request header value"));
        }
        let response = app
            .clone()
            .oneshot(request.body(Body::empty()).expect("request"))
            .await
            .expect("response");
        assert_eq!(
            response.status().as_u16(),
            case["status_code"].as_u64().expect("status") as u16
        );
        for (name, value) in case["response_headers"]
            .as_object()
            .expect("response headers")
        {
            assert_eq!(
                response.headers().get(name).expect("response header"),
                value.as_str().expect("response header value"),
                "{contract_key}: {name}"
            );
        }
        assert_eq!(
            response_body(response).await,
            case["body"].as_str().expect("body").as_bytes(),
            "{contract_key}"
        );
    }

    for path in contract["rejected_paths"]
        .as_array()
        .expect("rejected paths")
    {
        let response = app
            .clone()
            .oneshot(
                Request::get(path.as_str().expect("rejected path"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), 404, "{path}");
    }
}
