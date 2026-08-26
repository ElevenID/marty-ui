use axum::body::{to_bytes, Body};
use http::{Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt;

async fn get_json(path: &str) -> Value {
    let response = marty_signing_keys::http::router()
        .oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "{path}");
    serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap()
}

#[tokio::test]
async fn public_catalog_matches_language_neutral_contract() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/catalog.json")).unwrap();
    assert_eq!(
        get_json("/v1/signing-keys/config/purposes").await,
        fixture["purposes"]
    );
    assert_eq!(
        get_json("/v1/signing-keys/config/service-capabilities").await,
        fixture["service_capabilities"]
    );
}

#[tokio::test]
async fn csca_signing_surface_matches_the_language_neutral_contract() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/csca-capability-behavior.json"
    ))
    .unwrap();
    let catalog = get_json("/v1/signing-keys/config/purposes").await;
    let csca = catalog["purposes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|purpose| purpose["id"] == "csca")
        .unwrap();
    assert_eq!(
        csca,
        &contract["supported_rust_surface"]["signing_keys"]["key_purpose"]
    );

    for route in contract["supported_rust_surface"]["signing_keys"]["internal_routes"]
        .as_array()
        .unwrap()
    {
        let contract_path = route["path"].as_str().unwrap();
        let path = contract_path
            .replace("{organization_id}", "org-a")
            .replace("{certificate_id}", "csca-a")
            .replace("{event_id}", "event-a");
        let body = match contract_path {
            "/internal/kms/sign" => {
                serde_json::json!({"service_config": {}, "payload_b64": ""})
            }
            "/internal/kms/public-key" | "/internal/kms/verify" => {
                serde_json::json!({"service_config": {}})
            }
            "/internal/documents/certificate/inspect" => {
                serde_json::json!({"cert_pem": "not-a-certificate"})
            }
            path if path.ends_with("/renew") => serde_json::json!({
                "replacement_certificate_id": "csca-b",
                "cert_pem": "not-a-certificate",
                "key_reference": "hsm://csca/b",
                "expected_public_jwk": {}
            }),
            path if path.ends_with("/revoke") => {
                serde_json::json!({"reason": "test"})
            }
            path if path.ends_with("/expiring") => {
                serde_json::json!({"days_threshold": 30})
            }
            _ if route["method"] == "PUT" => serde_json::json!({
                "cert_pem": "not-a-certificate",
                "key_reference": "hsm://csca/a",
                "expected_public_jwk": {}
            }),
            _ => serde_json::json!({}),
        };
        let method = route["method"].as_str().unwrap();
        let response = marty_signing_keys::http::router()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(&path)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{method} {path}"
        );
    }
}

#[tokio::test]
async fn public_openapi_does_not_publish_internal_custody_routes() {
    let spec = get_json("/openapi.json").await;
    assert!(spec["paths"]
        .as_object()
        .unwrap()
        .keys()
        .all(|path| !path.starts_with("/internal/")));
}

#[tokio::test]
async fn health_and_extraction_status_preserve_the_service_contract() {
    assert_eq!(
        get_json("/health").await,
        serde_json::json!({"status": "healthy", "service": "signing-keys-service"})
    );
    let status = get_json("/v1/signing-keys/service-status").await;
    assert_eq!(status["phase"], "provider-validation");
    assert_eq!(status["service_name"], "signing-keys-service");
    assert!(status["migrated_capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .any(|capability| capability == "kms-adapter-integration"));
    assert!(status["migrated_capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .any(|capability| capability == "service-registration-validation"));
}

#[tokio::test]
async fn internal_kms_routes_require_the_service_api_key() {
    let body = serde_json::json!({
        "service_config": {"service_type": "unknown"}
    })
    .to_string();
    let unauthorized = marty_signing_keys::http::router()
        .oneshot(
            Request::post("/internal/kms/verify")
                .header("content-type", "application/json")
                .body(Body::from(body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let authorized = marty_signing_keys::http::router()
        .oneshot(
            Request::post("/internal/kms/verify")
                .header("content-type", "application/json")
                .header("x-api-key", "dev-signing-keys-internal-api-key")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(authorized.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn internal_validation_requires_the_service_api_key() {
    let body = serde_json::json!({
        "service_type": "aws-kms",
        "live_probe": false
    })
    .to_string();
    let unauthorized = marty_signing_keys::http::router()
        .oneshot(
            Request::post("/internal/config/validate")
                .header("content-type", "application/json")
                .body(Body::from(body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let authorized = marty_signing_keys::http::router()
        .oneshot(
            Request::post("/internal/config/validate")
                .header("content-type", "application/json")
                .header("x-api-key", "dev-signing-keys-internal-api-key")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(authorized.status(), StatusCode::OK);
    let result: Value =
        serde_json::from_slice(&to_bytes(authorized.into_body(), usize::MAX).await.unwrap())
            .unwrap();
    assert_eq!(result["ok"], false);
}

#[tokio::test]
async fn internal_registry_routes_fail_closed_without_auth_or_storage() {
    let unauthorized = marty_signing_keys::http::router()
        .oneshot(
            Request::get("/internal/registry/org-a")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let unavailable = marty_signing_keys::http::router()
        .oneshot(
            Request::get("/internal/registry/org-a")
                .header("x-api-key", "dev-signing-keys-internal-api-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);

    let malformed = marty_signing_keys::http::router()
        .oneshot(
            Request::post("/internal/registry/normalize")
                .header("content-type", "application/json")
                .header("x-api-key", "dev-signing-keys-internal-api-key")
                .body(Body::from(
                    serde_json::json!({
                        "mode": "requested",
                        "registry": {
                            "services": [],
                            "key_reference_purposes": {
                                "svc": {"key": ["lti_tool_signing", "vc_jwt_issuer"]}
                            }
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(malformed.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn internal_document_routes_require_auth_and_fail_closed_without_storage() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/document_vectors.json")).unwrap();
    let inspect_body = serde_json::json!({
        "cert_pem": fixture["certificate"]["cert_pem"]
    })
    .to_string();
    let unauthorized = marty_signing_keys::http::router()
        .oneshot(
            Request::post("/internal/documents/certificate/inspect")
                .header("content-type", "application/json")
                .body(Body::from(inspect_body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let inspected = marty_signing_keys::http::router()
        .oneshot(
            Request::post("/internal/documents/certificate/inspect")
                .header("content-type", "application/json")
                .header("x-api-key", "dev-signing-keys-internal-api-key")
                .body(Body::from(inspect_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(inspected.status(), StatusCode::OK);
    let result: Value =
        serde_json::from_slice(&to_bytes(inspected.into_body(), usize::MAX).await.unwrap())
            .unwrap();
    assert_eq!(
        result["expires_at"],
        fixture["certificate"]["expected_expiry"]
    );

    let unavailable = marty_signing_keys::http::router()
        .oneshot(
            Request::get("/internal/documents/org-a/jwks")
                .header("x-api-key", "dev-signing-keys-internal-api-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);

    let csca_unavailable = marty_signing_keys::http::router()
        .oneshot(
            Request::get("/internal/documents/org-a/csca-certificates")
                .header("x-api-key", "dev-signing-keys-internal-api-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(csca_unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);

    let compatibility_unavailable = marty_signing_keys::http::router()
        .oneshot(
            Request::post("/internal/compat/issuer-profiles")
                .header("content-type", "application/json")
                .header("x-api-key", "dev-signing-keys-internal-api-key")
                .body(Body::from(
                    serde_json::json!({
                        "organization_id": "org-a",
                        "body": {
                            "issuer_did": "did:web:issuer.example:orgs:acme",
                            "signing_service_id": "service-a"
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        compatibility_unavailable.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[tokio::test]
async fn internal_profile_routes_require_auth_use_vectors_and_fail_closed_without_storage() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/issuer_profile_vectors.json")).unwrap();
    let normalize_body = serde_json::json!({
        "body": fixture["normalize"]["body"],
        "profile_id": fixture["normalize"]["profile_id"],
        "now": fixture["normalize"]["now"],
    })
    .to_string();
    let unauthorized = marty_signing_keys::http::router()
        .oneshot(
            Request::post("/internal/profiles/org-a/normalize")
                .header("content-type", "application/json")
                .body(Body::from(normalize_body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let normalized = marty_signing_keys::http::router()
        .oneshot(
            Request::post("/internal/profiles/org-a/normalize")
                .header("content-type", "application/json")
                .header("x-api-key", "dev-signing-keys-internal-api-key")
                .body(Body::from(normalize_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(normalized.status(), StatusCode::OK);
    let result: Value =
        serde_json::from_slice(&to_bytes(normalized.into_body(), usize::MAX).await.unwrap())
            .unwrap();
    assert_eq!(result["profile"], fixture["normalize"]["expected"]);

    let custody = marty_signing_keys::http::router()
        .oneshot(
            Request::post("/internal/profiles/org-a/custody-format")
                .header("content-type", "application/json")
                .header("x-api-key", "dev-signing-keys-internal-api-key")
                .body(Body::from(
                    serde_json::json!({
                        "credential_format": "SD_JWT_VC",
                        "key_purpose": "lti_tool_signing"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(custody.status(), StatusCode::OK);
    let result: Value =
        serde_json::from_slice(&to_bytes(custody.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(result, serde_json::json!({"wire_format": "lti_tool_jwt"}));

    let unavailable = marty_signing_keys::http::router()
        .oneshot(
            Request::get("/internal/profiles/org-a")
                .header("x-api-key", "dev-signing-keys-internal-api-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
}
