//! Opt-in route contract against disposable Redis and OpenBao instances.
//! The private signing key is created and retained only inside Transit.

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    routing::any,
    Json, Router,
};
use der::DecodePem;
use marty_signing_keys::{
    documents::DocumentStore, http::router_with_dependencies, profiles::ProfileStore,
    registry::RegistryStore,
};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tower::ServiceExt;
use x509_cert::request::CertReq;

async fn write_disposable_pki(
    client: &reqwest::Client,
    base_url: &str,
    token: &str,
    path: &str,
    payload: Value,
) -> Value {
    let response = client
        .post(format!("{base_url}/v1/{path}"))
        .header("X-Vault-Token", token)
        .json(&payload)
        .send()
        .await
        .expect("disposable PKI request");
    let status = response.status();
    let body: Value = response.json().await.expect("disposable PKI JSON");
    assert!(
        status.is_success(),
        "disposable PKI {path}: {status}: {body}"
    );
    body
}

#[tokio::test]
#[ignore = "requires guarded disposable MARTY_TEST_REDIS_URL and nonce sentinel"]
async fn public_config_rejects_private_material_without_changing_registry() {
    let redis_url = std::env::var("MARTY_TEST_REDIS_URL").expect("disposable Redis URL");
    let parsed = reqwest::Url::parse(&redis_url).expect("disposable Redis URL syntax");
    assert!(matches!(
        parsed.host_str(),
        Some("127.0.0.1" | "localhost" | "::1")
    ));
    assert!(parsed
        .path()
        .trim_start_matches('/')
        .parse::<u8>()
        .is_ok_and(|db| db >= 13));
    let nonce = std::env::var("MARTY_TEST_REDIS_DISPOSABLE_NONCE")
        .expect("disposable Redis sentinel value");
    assert!(nonce.len() >= 16);
    let registry = RegistryStore::connect(&redis_url)
        .await
        .expect("disposable Redis registry");
    let mut connection = registry.connection();
    let observed: Option<String> = redis::cmd("GET")
        .arg("marty:tests:disposable-guard")
        .query_async(&mut connection)
        .await
        .expect("disposable Redis sentinel read");
    assert_eq!(observed.as_deref(), Some(nonce.as_str()));

    let organization_id = format!("test-private-input-{}", uuid::Uuid::new_v4().simple());
    let baseline = json!({"services": [], "default_service_id": null});
    registry
        .save(&organization_id, &baseline)
        .await
        .expect("save baseline config");
    let stored_before = registry
        .load(&organization_id)
        .await
        .expect("baseline read");
    let app = router_with_dependencies(
        "test-internal-only".into(),
        Some(registry.clone()),
        None,
        None,
        None,
        None,
        None,
    );
    for body in [
        json!({"services": [], "private_key_pem": "synthetic-secret"}),
        json!({"services": [{"managed": true, "privateKey": "synthetic-secret"}]}),
        json!({"services": [{"key_reference": "-----BEGIN PRIVATE KEY-----"}]}),
    ] {
        let request = Request::builder()
            .method("PATCH")
            .uri(format!(
                "/v1/signing-keys/config?organization_id={organization_id}"
            ))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("public configuration request");
        let response = app
            .clone()
            .oneshot(request)
            .await
            .expect("public configuration response");
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let stored_after = registry
            .load(&organization_id)
            .await
            .expect("registry read");
        assert_eq!(stored_after, stored_before);
    }
}

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
    let registration = json!({
        "services": [{
            "id": "service-a", "name": "Test Passport Signer",
            "service_type": "openbao-transit", "endpoint": bao_url,
            "mount": "transit", "auth_mode": "token", "auth_reference": bao_token,
            "key_reference": key_name, "algorithms": ["ES256"],
            "key_purposes": ["vc_jwt_issuer"],
            "credential_formats": ["dc+sd-jwt"]
        }],
        "default_service_id": "service-a"
    });
    let client = redis::Client::open(redis_url).expect("Redis client");
    let documents = DocumentStore::from_connection(
        client
            .get_connection_manager()
            .await
            .expect("Redis document connection"),
    );
    let profiles = ProfileStore::from_connection(registry.connection());
    let app = router_with_dependencies(
        "test-internal-only".into(),
        Some(registry.clone()),
        Some(documents),
        None,
        Some(profiles.clone()),
        None,
        Some("beta.example".into()),
    );
    let register = Request::builder()
        .method("PATCH")
        .uri(format!(
            "/v1/signing-keys/config?organization_id={organization_id}"
        ))
        .header("content-type", "application/json")
        .body(Body::from(registration.to_string()))
        .expect("public service registration");
    let registered = app
        .clone()
        .oneshot(register)
        .await
        .expect("public service registration response");
    let registration_status = registered.status();
    let registered: Value = serde_json::from_slice(
        &to_bytes(registered.into_body(), 1_048_576)
            .await
            .expect("public service registration body"),
    )
    .expect("public service registration JSON");
    assert_eq!(registration_status, StatusCode::OK, "{registered}");
    assert!(!registered.to_string().contains(&bao_token));
    let persisted = registry
        .load(&organization_id)
        .await
        .expect("saved service");
    assert_eq!(persisted["services"][0]["key_reference"], key_name);

    let request = Request::builder()
        .method("POST")
        .uri(format!(
            "/v1/signing-keys/services/service-a/certificate-csr?organization_id={organization_id}"
        ))
        .header("content-type", "application/json")
        .body(Body::from(json!({
            "country": "US", "organization": "ElevenID Beta", "common_name": "signer.example.test"
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

    // The CA and signer keys both stay inside disposable OpenBao. PKI signs
    // the public CSR; no test process creates or handles a private key.
    let pki_mount = format!("pki-byok-{suffix}");
    let mounted = kms_client
        .post(format!("{bao_url}/v1/sys/mounts/{pki_mount}"))
        .header("X-Vault-Token", &bao_token)
        .json(&json!({"type": "pki", "config": {"max_lease_ttl": "8760h"}}))
        .send()
        .await
        .expect("mount disposable PKI");
    assert!(mounted.status().is_success(), "disposable PKI mount failed");
    let root = write_disposable_pki(
        &kms_client,
        &bao_url,
        &bao_token,
        &format!("{pki_mount}/root/generate/internal"),
        json!({"common_name": "Disposable BYOK CA", "ttl": "8760h"}),
    )
    .await;
    let root_pem = root["data"]["certificate"]
        .as_str()
        .expect("public root certificate");
    write_disposable_pki(
        &kms_client,
        &bao_url,
        &bao_token,
        &format!("{pki_mount}/roles/service-signer"),
        json!({"allow_any_name": true, "max_ttl": "24h", "key_type": "ec", "key_bits": 256}),
    )
    .await;
    let signed = write_disposable_pki(
        &kms_client,
        &bao_url,
        &bao_token,
        &format!("{pki_mount}/sign/service-signer"),
        json!({
            "csr": body["csr_pem"],
            "common_name": "signer.example.test",
            "ttl": "1h"
        }),
    )
    .await;
    assert!(signed["data"].get("private_key").is_none());
    let leaf_pem = signed["data"]["certificate"]
        .as_str()
        .expect("public signer certificate");
    let certificate_path = format!(
        "/v1/signing-keys/services/service-a/certificate?organization_id={organization_id}"
    );
    let attach = Request::builder()
        .method("PUT")
        .uri(&certificate_path)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"cert_pem": leaf_pem, "cert_chain_pem": root_pem}).to_string(),
        ))
        .expect("public certificate attachment");
    let attached = app
        .clone()
        .oneshot(attach)
        .await
        .expect("attachment response");
    assert_eq!(attached.status(), StatusCode::OK);
    let attached: Value = serde_json::from_slice(
        &to_bytes(attached.into_body(), 1_048_576)
            .await
            .expect("attachment body"),
    )
    .expect("attachment JSON");
    assert_eq!(attached["ok"], true);
    assert!(!attached.to_string().contains("private_key"));

    let issuer_did = format!("did:web:beta.example:orgs:{organization_id}");
    let identity = json!({
        "organization_id": organization_id,
        "issuer_did": issuer_did,
        "key_purpose": "vc_jwt_issuer",
        "credential_format": "SD_JWT_VC",
        "algorithm": "ES256"
    });
    let identity_create = Request::builder()
        .method("POST")
        .uri(format!(
            "/v1/signing-keys/issuer-identities?organization_id={organization_id}"
        ))
        .header("content-type", "application/json")
        .body(Body::from(identity.to_string()))
        .expect("issuer identity creation");
    let created = app
        .clone()
        .oneshot(identity_create)
        .await
        .expect("issuer identity response");
    let created_status = created.status();
    let created: Value = serde_json::from_slice(
        &to_bytes(created.into_body(), 1_048_576)
            .await
            .expect("issuer identity body"),
    )
    .expect("issuer identity JSON");
    assert_eq!(created_status, StatusCode::OK, "{created}");
    assert_eq!(created["identity"]["issuer_did"], issuer_did);
    let stored_profiles = profiles
        .list(&organization_id)
        .await
        .expect("issuer profiles");
    assert_eq!(
        stored_profiles["profiles"][0]["signing_key_reference"],
        key_name
    );
    let identity_certificate = Request::builder()
        .method("PUT")
        .uri(format!(
            "/v1/signing-keys/issuer-identities/certificate?organization_id={organization_id}"
        ))
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "organization_id": organization_id,
                "issuer_did": issuer_did,
                "key_purpose": "vc_jwt_issuer",
                "credential_format": "SD_JWT_VC",
                "algorithm": "ES256",
                "cert_pem": leaf_pem,
                "cert_chain_pem": root_pem
            })
            .to_string(),
        ))
        .expect("issuer certificate attachment");
    let identity_attached = app
        .clone()
        .oneshot(identity_certificate)
        .await
        .expect("issuer certificate response");
    let identity_status = identity_attached.status();
    let identity_attached: Value = serde_json::from_slice(
        &to_bytes(identity_attached.into_body(), 1_048_576)
            .await
            .expect("issuer certificate body"),
    )
    .expect("issuer certificate JSON");
    assert_eq!(identity_status, StatusCode::OK, "{identity_attached}");
    assert!(identity_attached.get("signing_key_reference").is_none());
    let wrong_identity_certificate = Request::builder()
        .method("PUT")
        .uri(format!(
            "/v1/signing-keys/issuer-identities/certificate?organization_id={organization_id}"
        ))
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "organization_id": organization_id,
                "issuer_did": issuer_did,
                "key_purpose": "vc_jwt_issuer",
                "credential_format": "SD_JWT_VC",
                "algorithm": "ES256",
                "cert_pem": root_pem
            })
            .to_string(),
        ))
        .expect("wrong-key issuer certificate");
    assert_eq!(
        app.clone()
            .oneshot(wrong_identity_certificate)
            .await
            .expect("wrong-key issuer response")
            .status(),
        StatusCode::CONFLICT
    );
    let cross_tenant_identity = Request::builder()
        .method("PUT")
        .uri("/v1/signing-keys/issuer-identities/certificate?organization_id=other-organization")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "organization_id": organization_id,
                "issuer_did": issuer_did,
                "key_purpose": "vc_jwt_issuer",
                "credential_format": "SD_JWT_VC",
                "algorithm": "ES256",
                "cert_pem": leaf_pem
            })
            .to_string(),
        ))
        .expect("cross-tenant issuer certificate");
    assert_eq!(
        app.clone()
            .oneshot(cross_tenant_identity)
            .await
            .expect("cross-tenant issuer response")
            .status(),
        StatusCode::FORBIDDEN
    );

    let wrong_key = Request::builder()
        .method("PUT")
        .uri(&certificate_path)
        .header("content-type", "application/json")
        .body(Body::from(json!({"cert_pem": root_pem}).to_string()))
        .expect("wrong-key certificate attachment");
    assert_eq!(
        app.clone()
            .oneshot(wrong_key)
            .await
            .expect("wrong-key response")
            .status(),
        StatusCode::CONFLICT
    );
    let forbidden = Request::builder()
        .method("PUT")
        .uri(&certificate_path)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"cert_pem": leaf_pem, "private_key_pem": "forbidden"}).to_string(),
        ))
        .expect("private-field certificate attachment");
    assert_eq!(
        app.clone()
            .oneshot(forbidden)
            .await
            .expect("private-field response")
            .status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );

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

    let did_request = Request::builder()
        .uri(format!(
            "/v1/signing-keys/did-document?organization_id={organization_id}"
        ))
        .body(Body::empty())
        .expect("DID request");
    let did_response = app
        .clone()
        .oneshot(did_request)
        .await
        .expect("DID response");
    assert_eq!(did_response.status(), StatusCode::OK);
    let did: Value = serde_json::from_slice(
        &to_bytes(did_response.into_body(), 1_048_576)
            .await
            .expect("DID body"),
    )
    .expect("DID JSON");
    assert_eq!(
        did["id"],
        format!("did:web:beta.example:orgs:{organization_id}")
    );
    assert_eq!(did["verificationMethod"].as_array().map(Vec::len), Some(1));
    assert_eq!(did["verificationMethod"][0]["controller"], issuer_did);
    assert!(did["verificationMethod"][0]["publicKeyJwk"]
        .get("d")
        .is_none());

    let stored = Request::builder()
        .uri(format!(
            "/v1/signing-keys/services/service-a/certificate?organization_id={organization_id}"
        ))
        .body(Body::empty())
        .expect("read stored certificate");
    assert_eq!(
        app.clone()
            .oneshot(stored)
            .await
            .expect("read response")
            .status(),
        StatusCode::OK
    );
    let stored_chain = Request::builder()
        .uri(format!(
            "/v1/signing-keys/services/service-a/mdoc-x5c?organization_id={organization_id}"
        ))
        .body(Body::empty())
        .expect("read stored mDoc certificate chain");
    assert_eq!(
        app.clone()
            .oneshot(stored_chain)
            .await
            .expect("mDoc chain response")
            .status(),
        StatusCode::OK
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

#[tokio::test]
#[ignore = "requires disposable MARTY_TEST_REDIS_URL; KMS public-key endpoint is mocked"]
async fn registered_service_public_material_routes_use_current_kms_key_and_tenant_scope() {
    let redis_url = std::env::var("MARTY_TEST_REDIS_URL").expect("disposable Redis URL");
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let organization_id = format!("test-mdoc-x5c-{suffix}");
    let fixture: Value = serde_json::from_str(include_str!("fixtures/document_vectors.json"))
        .expect("certificate vector");
    let provider_vectors: Value =
        serde_json::from_str(include_str!("fixtures/kms_provider_vectors.json"))
            .expect("provider vector");
    let provider_response = provider_vectors["public_key_cases"]
        .as_array()
        .expect("public key cases")
        .iter()
        .find(|case| case["name"] == "gcp_pem_public_key")
        .expect("matching GCP public key vector")["provider_response"]
        .clone();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("mock KMS listener");
    let endpoint = format!(
        "http://{}",
        listener.local_addr().expect("mock KMS address")
    );
    tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().fallback(any(move || {
                let response = provider_response.clone();
                async move { Json(response) }
            })),
        )
        .await
        .expect("mock KMS server");
    });

    let registry = RegistryStore::connect(&redis_url)
        .await
        .expect("Redis registry");
    registry
        .save(
            &organization_id,
            &json!({
                "services": [{
                    "id": "service-a", "name": "Test mDoc Signer",
                    "service_type": "gcp-cloud-kms", "endpoint": endpoint,
                    "auth_mode": "workload_identity", "auth_reference": "test-only-token",
                    "key_reference": "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1", "algorithms": ["ES256"],
                    "key_purposes": ["mdoc_dsc"],
                    "cert_pem": fixture["certificate"]["cert_pem"]
                }],
                "default_service_id": "service-a"
            }),
        )
        .await
        .expect("register test signing service");
    let documents = DocumentStore::from_connection(registry.connection());
    let inspect_registry = registry.clone();
    let app = router_with_dependencies(
        "test-internal-only".into(),
        Some(registry),
        Some(documents),
        None,
        None,
        None,
        Some("beta.example".into()),
    );
    let request = Request::builder()
        .uri(format!(
            "/v1/signing-keys/services/service-a/mdoc-x5c?organization_id={organization_id}"
        ))
        .body(Body::empty())
        .expect("mDoc chain request");
    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("mDoc chain response");
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(
        &to_bytes(response.into_body(), 1_048_576)
            .await
            .expect("mDoc chain body"),
    )
    .expect("mDoc chain JSON");
    assert_eq!(body["x5c"][0], fixture["certificate"]["expected_x5c"]);
    assert_eq!(body["mdoc_cose_header_hints"]["x5c_length"], 1);
    assert!(body.get("key_reference").is_none());
    let verify = Request::builder()
        .uri(format!(
            "/v1/signing-keys/services/service-a/verify-current?organization_id={organization_id}"
        ))
        .body(Body::empty())
        .expect("verify current KMS key request");
    let verified = app.clone().oneshot(verify).await.expect("KMS key response");
    assert_eq!(verified.status(), StatusCode::OK);
    let verified: Value = serde_json::from_slice(
        &to_bytes(verified.into_body(), 1_048_576)
            .await
            .expect("KMS key response body"),
    )
    .expect("KMS key verification JSON");
    assert_eq!(verified["key_valid"], true);
    assert_eq!(verified["checks"]["algorithm_supported"], true);
    assert!(verified.get("public_jwk").is_none());
    assert!(verified.get("key_reference").is_none());
    let publish = Request::builder()
        .method("POST")
        .uri(format!(
            "/v1/signing-keys/services/service-a/publish-jwks?organization_id={organization_id}"
        ))
        .body(Body::empty())
        .expect("publish current KMS public key");
    let published = app
        .clone()
        .oneshot(publish)
        .await
        .expect("JWKS publication");
    assert_eq!(published.status(), StatusCode::OK);
    let published: Value = serde_json::from_slice(
        &to_bytes(published.into_body(), 1_048_576)
            .await
            .expect("JWKS publication body"),
    )
    .expect("JWKS publication JSON");
    assert_eq!(published["jwks_document"]["key_count"], 1);
    assert_eq!(
        published["jwk"]["x5c"][0],
        fixture["certificate"]["expected_x5c"]
    );
    assert!(published["jwk"].get("key_reference").is_none());
    let public_jwks = Request::builder()
        .uri(format!(
            "/v1/signing-keys/jwks?organization_id={organization_id}"
        ))
        .body(Body::empty())
        .expect("public JWKS read");
    let jwks = app
        .clone()
        .oneshot(public_jwks)
        .await
        .expect("public JWKS response");
    assert_eq!(jwks.status(), StatusCode::OK);
    let jwks: Value = serde_json::from_slice(
        &to_bytes(jwks.into_body(), 1_048_576)
            .await
            .expect("public JWKS body"),
    )
    .expect("public JWKS JSON");
    assert_eq!(jwks["keys"].as_array().expect("published keys").len(), 1);
    assert!(jwks["keys"][0].get("key_reference").is_none());
    let saved_registry = inspect_registry
        .load(&organization_id)
        .await
        .expect("saved discovery state");
    assert_eq!(
        saved_registry["services"][0]["discovered_capabilities"]["last_jwk_fetch_ok"],
        true
    );
    let publish_did = Request::builder()
        .method("POST")
        .uri(format!(
            "/v1/signing-keys/services/service-a/publish-did-vm?organization_id={organization_id}"
        ))
        .header("content-type", "application/json")
        .body(Body::from(r#"{"fragment":"service-a-vm"}"#))
        .expect("publish current KMS verification method");
    let published_did = app
        .clone()
        .oneshot(publish_did)
        .await
        .expect("DID publication");
    assert_eq!(published_did.status(), StatusCode::OK);
    let published_did: Value = serde_json::from_slice(
        &to_bytes(published_did.into_body(), 1_048_576)
            .await
            .expect("DID publication body"),
    )
    .expect("DID publication JSON");
    let expected_did = format!("did:web:beta.example:orgs:{organization_id}");
    let expected_method = format!("{expected_did}#service-a-vm");
    assert_eq!(published_did["did_document"]["id"], expected_did);
    assert_eq!(published_did["verification_method"]["id"], expected_method);
    assert_eq!(
        published_did["verification_method"]["x5c"][0],
        fixture["certificate"]["expected_x5c"]
    );
    assert!(published_did["verification_method"]
        .get("key_reference")
        .is_none());
    let did_read = Request::builder()
        .uri(format!(
            "/v1/signing-keys/did-document?organization_id={organization_id}"
        ))
        .body(Body::empty())
        .expect("public DID document read");
    let did = app
        .clone()
        .oneshot(did_read)
        .await
        .expect("public DID response");
    assert_eq!(did.status(), StatusCode::OK);
    let did: Value = serde_json::from_slice(
        &to_bytes(did.into_body(), 1_048_576)
            .await
            .expect("public DID document body"),
    )
    .expect("public DID document JSON");
    assert_eq!(did["verificationMethod"][0]["id"], expected_method);
    assert_eq!(did["assertionMethod"][0], expected_method);
    let saved_registry = inspect_registry
        .load(&organization_id)
        .await
        .expect("saved DID discovery state");
    assert_eq!(
        saved_registry["services"][0]["discovered_capabilities"]["last_did_publish_ok"],
        true
    );
    assert_eq!(
        saved_registry["services"][0]["discovered_capabilities"]["has_x5c"],
        true
    );
    let cross_tenant = Request::builder()
        .uri("/v1/signing-keys/services/service-a/mdoc-x5c?organization_id=another-tenant")
        .body(Body::empty())
        .expect("cross-tenant mDoc chain request");
    assert_eq!(
        app.oneshot(cross_tenant)
            .await
            .expect("cross-tenant mDoc chain response")
            .status(),
        StatusCode::NOT_FOUND
    );
}
