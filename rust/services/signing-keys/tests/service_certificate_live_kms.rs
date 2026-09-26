//! Opt-in route contract against disposable Redis and OpenBao instances.
//! The private signing key is created and retained only inside Transit.

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use der::DecodePem;
use marty_signing_keys::{
    documents::DocumentStore, http::router_with_dependencies, registry::RegistryStore,
};
use serde_json::{json, Value};
use tower::ServiceExt;
use x509_cert::request::CertReq;

#[tokio::test]
#[ignore = "requires disposable MARTY_TEST_REDIS_URL, MARTY_TEST_OPENBAO_URL, and MARTY_TEST_OPENBAO_TOKEN"]
async fn registered_service_csr_is_signed_by_kms_through_public_rust_route() {
    let redis_url = std::env::var("MARTY_TEST_REDIS_URL").expect("disposable Redis URL");
    let bao_url = std::env::var("MARTY_TEST_OPENBAO_URL").expect("disposable OpenBao URL");
    let bao_token = std::env::var("MARTY_TEST_OPENBAO_TOKEN").expect("disposable OpenBao token");
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let key_name = format!("marty-service-csr-{suffix}");
    let organization_id = format!("test-service-csr-{suffix}");

    let kms_client = reqwest::Client::new();
    let mount = kms_client
        .get(format!("{bao_url}/v1/sys/mounts/transit"))
        .header("X-Vault-Token", &bao_token)
        .send()
        .await
        .expect("inspect disposable Transit mount");
    if !mount.status().is_success() {
        let enabled = kms_client
            .post(format!("{bao_url}/v1/sys/mounts/transit"))
            .header("X-Vault-Token", &bao_token)
            .json(&json!({"type": "transit"}))
            .send()
            .await
            .expect("enable disposable Transit mount");
        assert!(
            enabled.status().is_success(),
            "disposable Transit mount unavailable"
        );
    }
    let created = kms_client
        .post(format!("{bao_url}/v1/transit/keys/{key_name}"))
        .header("X-Vault-Token", &bao_token)
        .json(&json!({"type": "ecdsa-p256"}))
        .send()
        .await
        .expect("create only inside disposable Transit");
    assert!(
        created.status().is_success(),
        "disposable KMS key creation failed"
    );

    let registry = RegistryStore::connect(&redis_url)
        .await
        .expect("Redis registry");
    registry
        .save(
            &organization_id,
            &json!({
                "services": [{
                    "id": "service-a", "name": "Test Passport Signer",
                    "service_type": "openbao-transit", "endpoint": bao_url,
                    "mount": "transit", "auth_mode": "token", "auth_reference": bao_token,
                    "key_reference": key_name, "algorithms": ["ES256"],
                    "key_purposes": ["csca"]
                }],
                "default_service_id": "service-a"
            }),
        )
        .await
        .expect("register disposable KMS service");
    let client = redis::Client::open(redis_url).expect("Redis client");
    let documents = DocumentStore::from_connection(
        client
            .get_connection_manager()
            .await
            .expect("Redis document connection"),
    );
    let app = router_with_dependencies(
        "test-internal-only".into(),
        Some(registry),
        Some(documents),
        None,
        None,
        None,
        None,
    );

    let request = Request::builder()
        .method("POST")
        .uri(format!(
            "/v1/signing-keys/services/service-a/certificate-csr?organization_id={organization_id}"
        ))
        .header("content-type", "application/json")
        .body(Body::from(json!({
            "country": "US", "organization": "ElevenID Beta", "common_name": "Test Passport Signer"
        }).to_string()))
        .expect("CSR request");
    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("CSR route response");
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(
        &to_bytes(response.into_body(), 1_048_576)
            .await
            .expect("CSR response body"),
    )
    .expect("CSR JSON");
    let csr = CertReq::from_pem(body["csr_pem"].as_str().expect("public CSR PEM"))
        .expect("valid PKCS#10 request");
    assert!(!csr
        .info
        .public_key
        .subject_public_key
        .raw_bytes()
        .is_empty());
    let serialized = body.to_string();
    assert!(!serialized.contains("auth_reference"));
    assert!(!serialized.contains("key_reference"));
    assert!(!serialized.contains("private_key"));

    let jwks_request = Request::builder()
        .uri(format!(
            "/v1/signing-keys/jwks?organization_id={organization_id}"
        ))
        .body(Body::empty())
        .expect("JWKS request");
    let jwks_response = app
        .clone()
        .oneshot(jwks_request)
        .await
        .expect("JWKS response");
    assert_eq!(jwks_response.status(), StatusCode::OK);
    let jwks: Value = serde_json::from_slice(
        &to_bytes(jwks_response.into_body(), 1_048_576)
            .await
            .expect("JWKS body"),
    )
    .expect("JWKS JSON");
    assert_eq!(jwks["organization_id"], organization_id);
    assert_eq!(jwks["keys"], json!([]));

    let missing = Request::builder()
        .uri(format!(
            "/v1/signing-keys/services/service-a/certificate?organization_id={organization_id}"
        ))
        .body(Body::empty())
        .expect("read missing certificate");
    assert_eq!(
        app.clone()
            .oneshot(missing)
            .await
            .expect("read response")
            .status(),
        StatusCode::NOT_FOUND
    );
    let invalid = Request::builder()
        .method("PUT")
        .uri(format!(
            "/v1/signing-keys/services/service-a/certificate?organization_id={organization_id}"
        ))
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"cert_pem": "not an X.509 certificate"}).to_string(),
        ))
        .expect("invalid certificate request");
    assert_eq!(
        app.clone()
            .oneshot(invalid)
            .await
            .expect("invalid response")
            .status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let cross_tenant = Request::builder()
        .uri("/v1/signing-keys/services/service-a/certificate?organization_id=another-test-org")
        .body(Body::empty())
        .expect("cross-tenant read");
    assert_eq!(
        app.oneshot(cross_tenant)
            .await
            .expect("cross-tenant response")
            .status(),
        StatusCode::NOT_FOUND
    );
}
