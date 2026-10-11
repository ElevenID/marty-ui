//! Opt-in public-route contract against disposable Redis and OpenBao.
//! Transit creates and retains the private signing key; this test sees only a signature.

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use marty_signing_grant::{
    mint_bound, replay::RedisGrantReplayStore, transit::TransitGrantClient,
    verifier::GrantVerifier, GrantBinding, SigningOrigin, HEADER_NAME,
};
use marty_signing_keys::{
    documents::DocumentStore,
    kms::{create_managed_openbao, ProviderRequest, SignRequest},
    profiles::{storage_key as profile_storage_key, ProfileStore},
    registry::{storage_key, RegistryStore},
};
use redis::AsyncCommands;
use serde_json::{json, Value};
use std::io::Write;
use tower::ServiceExt;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires marked disposable OpenBao and managed signing token"]
async fn managed_openbao_rs256_signature_matches_jose_pkcs1_profile() {
    let (endpoint, _) = disposable_openbao().await;
    let namespace = Uuid::new_v5(&Uuid::NAMESPACE_URL, Uuid::new_v4().as_bytes())
        .simple()
        .to_string();
    let reference = format!("cred-issuer-{namespace}-rsa-rs256");
    let config = json!({
        "id": "managed-openbao-transit", "service_type": "openbao-transit",
        "auth_mode": "service_token", "endpoint": endpoint,
        "mount": "transit", "key_reference": reference, "algorithm": "RS256"
    });
    let metadata = create_managed_openbao(ProviderRequest {
        service_config: config.clone(),
    })
    .await
    .expect("managed non-exportable RSA key");
    assert_eq!(metadata["status"], "active");
    assert_eq!(metadata["exportable"], false);
    assert_eq!(metadata["allow_plaintext_backup"], false);

    let payload = b"managed RSA issuer signing contract";
    let signed = marty_signing_keys::kms::sign(SignRequest {
        service_config: config.clone(),
        payload_b64: URL_SAFE_NO_PAD.encode(payload),
    })
    .await
    .expect("remote RS256 signing");
    assert_eq!(signed.signature_encoding, "raw");
    let signature = URL_SAFE_NO_PAD.decode(signed.signature_b64).unwrap();
    assert_eq!(signature.len(), 256);
    assert!(
        marty_oid4vci::jose::verify_detached_signature_with_public_jwk(
            payload,
            &signature,
            &metadata["public_jwk"].to_string(),
            "RS256",
        )
        .unwrap()
    );

    // Canvas client assertions use this same remote RS256 boundary. The
    // public JWK verifies the exact compact-JWT signing input; no private
    // material enters this process or fixture.
    let header = json!({"alg": "RS256", "typ": "JWT", "kid": "lti-tool-rs256"});
    let claims = json!({
        "iss": "canvas-client", "sub": "canvas-client",
        "aud": "https://canvas.example.edu/login/oauth2/token",
        "iat": 1, "exp": 301, "jti": "remote-test-assertion",
    });
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let assertion_signature = marty_signing_keys::kms::sign(SignRequest {
        service_config: config,
        payload_b64: URL_SAFE_NO_PAD.encode(signing_input.as_bytes()),
    })
    .await
    .expect("remote Canvas assertion signing");
    let assertion = format!("{signing_input}.{}", assertion_signature.signature_b64);
    let segments = assertion.split('.').collect::<Vec<_>>();
    assert_eq!(segments.len(), 3);
    let signature = URL_SAFE_NO_PAD.decode(segments[2]).unwrap();
    assert!(
        marty_oid4vci::jose::verify_detached_signature_with_public_jwk(
            format!("{}.{}", segments[0], segments[1]).as_bytes(),
            &signature,
            &metadata["public_jwk"].to_string(),
            "RS256",
        )
        .unwrap()
    );
    assert!(
        !marty_oid4vci::jose::verify_detached_signature_with_public_jwk(
            b"tampered.assertion",
            &signature,
            &metadata["public_jwk"].to_string(),
            "RS256",
        )
        .unwrap()
    );
}

async fn disposable_redis_url() -> String {
    let url = std::env::var("MARTY_TEST_REDIS_URL").expect("disposable Redis URL");
    let parsed = reqwest::Url::parse(&url).expect("disposable Redis URL syntax");
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
    assert!(nonce.len() >= 16, "disposable Redis sentinel is too short");
    let client = redis::Client::open(url.as_str()).expect("disposable Redis client");
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("disposable Redis connection");
    let observed: Option<String> = connection
        .get("marty:tests:disposable-guard")
        .await
        .expect("disposable Redis sentinel read");
    assert_eq!(observed.as_deref(), Some(nonce.as_str()));
    url
}

async fn disposable_openbao() -> (String, String) {
    let url = std::env::var("MARTY_TEST_OPENBAO_URL").expect("disposable OpenBao URL");
    let parsed = reqwest::Url::parse(&url).expect("disposable OpenBao URL syntax");
    assert!(parsed.scheme() == "http" && parsed.host_str() == Some("127.0.0.1"));
    assert_eq!(
        std::env::var("BAO_ADDR").ok().as_deref(),
        Some(url.as_str()),
        "managed token must be bound to the configured OpenBao endpoint"
    );
    let token = std::env::var("MARTY_TEST_OPENBAO_TOKEN").expect("disposable OpenBao token");
    let guard_token = std::env::var("MARTY_TEST_OPENBAO_ROOT_TOKEN")
        .expect("disposable OpenBao marker guard token");
    assert_ne!(guard_token, token);
    assert_eq!(
        std::env::var("BAO_TOKEN").ok().as_deref(),
        Some(token.as_str())
    );
    let nonce = std::env::var("MARTY_TEST_OPENBAO_DISPOSABLE_NONCE")
        .expect("pre-provisioned disposable OpenBao sentinel value");
    assert!(
        nonce.len() >= 16,
        "disposable OpenBao sentinel is too short"
    );
    let client = reqwest::Client::new();
    let marker = client
        .get(
            parsed
                .join("/v1/secret/data/marty-test-disposable-guard")
                .unwrap(),
        )
        .header("X-Vault-Token", &guard_token)
        .send()
        .await
        .expect("disposable OpenBao sentinel read");
    assert!(
        marker.status().is_success(),
        "disposable OpenBao sentinel is absent"
    );
    let marker: Value = marker
        .json()
        .await
        .expect("disposable OpenBao sentinel JSON");
    assert_eq!(
        marker["data"]["data"]["nonce"].as_str(),
        Some(nonce.as_str())
    );
    (url.trim_end_matches('/').to_owned(), token)
}

async fn sign(app: &Router, organization_id: &str, payload: Value) -> (StatusCode, Value) {
    sign_service(app, organization_id, "service-a", payload).await
}

async fn sign_service(
    app: &Router,
    organization_id: &str,
    service_id: &str,
    payload: Value,
) -> (StatusCode, Value) {
    let route = format!("/v1/signing-keys/services/{service_id}/sign");
    let grant = if let (Some(encoded), Some(reference), Some(purpose), Some(algorithm)) = (
        payload.get("payload_b64").and_then(Value::as_str),
        payload.get("key_reference").and_then(Value::as_str),
        payload.get("key_purpose").and_then(Value::as_str),
        payload.get("algorithm").and_then(Value::as_str),
    ) {
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .expect("test signing payload");
        let endpoint = std::env::var("MARTY_TEST_OPENBAO_URL").expect("disposable OpenBao URL");
        let token =
            std::env::var("MARTY_TEST_GRANT_MINT_TOKEN").expect("scoped Gateway grant mint token");
        let client = TransitGrantClient::for_origin(&endpoint, SigningOrigin::GatewayService)
            .expect("Gateway grant key");
        let operation_id = Uuid::new_v4().to_string();
        let binding = GrantBinding {
            origin: SigningOrigin::GatewayService,
            operation_id: &operation_id,
            organization_id,
            route: &route,
            service_id: Some(service_id),
            issuer_did: None,
            key_reference: Some(reference),
            key_purpose: purpose,
            algorithm,
            payload: &bytes,
        };
        Some(
            mint_bound(&client, &token, &binding)
                .await
                .expect("scoped signing grant")
                .to_header_value()
                .expect("signing grant header"),
        )
    } else {
        None
    };
    let mut request = Request::post(format!("{route}?organization_id={organization_id}"))
        .header("content-type", "application/json")
        .header("x-api-key", "test-service-sign-gateway-key-000000");
    if let Some(grant) = grant.as_deref() {
        request = request.header(HEADER_NAME, grant);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(payload.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| panic!("sign route returned non-JSON status={status}"));
    (status, body)
}

async fn scoped_grant_verifier(
    endpoint: &str,
    connection: redis::aio::ConnectionManager,
) -> (GrantVerifier, tempfile::NamedTempFile) {
    let token = std::env::var("MARTY_TEST_GRANT_VERIFY_TOKEN").expect("scoped grant verify token");
    let mut file = tempfile::NamedTempFile::new().expect("grant token file");
    file.write_all(token.as_bytes()).expect("write grant token");
    let verifier = GrantVerifier::for_managed_openbao(
        endpoint,
        file.path().to_path_buf(),
        RedisGrantReplayStore::new(connection),
    )
    .expect("scoped signing verifier");
    (verifier, file)
}

async fn signing_router(
    registry: RegistryStore,
    documents: DocumentStore,
    profiles: ProfileStore,
    grant_endpoint: &str,
) -> (Router, tempfile::NamedTempFile) {
    let (verifier, file) = scoped_grant_verifier(grant_endpoint, registry.connection()).await;
    let router = marty_signing_keys::http::router_with_all_keys_and_grants(
        "test-internal-key".into(),
        Some("test-service-sign-gateway-key-000000".into()),
        None,
        None,
        None,
        None,
        false,
        Some(registry),
        Some(documents),
        None,
        Some(profiles),
        None,
        None,
        Some(verifier),
    );
    (router, file)
}

#[tokio::test]
#[ignore = "requires independently marked disposable loopback Redis and OpenBao grants"]
async fn stale_managed_profile_binding_cannot_select_a_kms_key() {
    let redis_url = disposable_redis_url().await;
    let (endpoint, _) = disposable_openbao().await;
    let organization_id = format!("test-managed-stale-{}", Uuid::new_v4().simple());
    let stale_reference = "cred-issuer-0123456789abcdefabcd-es256";
    let foreign_namespace = Uuid::new_v5(&Uuid::NAMESPACE_URL, b"other-tenant")
        .simple()
        .to_string();
    let foreign_reference = format!("cred-issuer-{foreign_namespace}-foreign-es256");
    let registry = RegistryStore::connect(&redis_url).await.unwrap();
    registry
        .save(
            &organization_id,
            &json!({
                "services": [],
                "key_reference_purposes": {
                    "managed-openbao-transit": {
                        (stale_reference): ["vc_jwt_issuer", "jwks_signing"],
                        (foreign_reference.clone()): ["vc_jwt_issuer"]
                    }
                }
            }),
        )
        .await
        .unwrap();
    let managed = registry
        .clone()
        .with_managed_openbao(Some(endpoint.clone()));
    let profiles = ProfileStore::from_connection(registry.connection());
    let (app, _grant_file) = signing_router(
        managed,
        DocumentStore::from_connection(registry.connection()),
        profiles.clone(),
        &endpoint,
    )
    .await;
    let (status, body) = sign_service(
        &app,
        &organization_id,
        "managed-openbao-transit",
        json!({
            "payload_b64": "cGF5bG9hZA",
            "algorithm": "ES256",
            "key_purpose": "vc_jwt_issuer",
            "key_reference": stale_reference
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    let (status, foreign) = sign_service(
        &app,
        &organization_id,
        "managed-openbao-transit",
        json!({
            "payload_b64": "cGF5bG9hZA",
            "algorithm": "ES256",
            "key_purpose": "vc_jwt_issuer",
            "key_reference": foreign_reference
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{foreign}");
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/issuer_profile_vectors.json")).unwrap();
    let mut profile = fixture["normalize"]["expected"].clone();
    profile["organization_id"] = json!(organization_id);
    profile["signing_service_id"] = json!("managed-openbao-transit");
    profile["signing_key_reference"] = json!(stale_reference);
    profile["key_purpose"] = json!("vc_jwt_issuer");
    profile["algorithm"] = json!("ES256");
    profile["status"] = json!("active");
    profiles
        .put(&organization_id, "ip-vector", profile)
        .await
        .unwrap();
    let (status, mismatched) = sign_service(
        &app,
        &organization_id,
        "managed-openbao-transit",
        json!({
            "payload_b64": "cGF5bG9hZA",
            "algorithm": "ES256",
            "key_purpose": "jwks_signing",
            "key_reference": stale_reference
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{mismatched}");
    let mut connection = registry.connection();
    let _: () = connection.del(storage_key(&organization_id)).await.unwrap();
    let _: () = connection
        .del(profile_storage_key(&organization_id))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires independently marked disposable loopback Redis"]
async fn public_config_cannot_replace_managed_kms_purpose_bindings() {
    let redis_url = disposable_redis_url().await;
    let organization_id = format!("test-managed-config-{}", Uuid::new_v4().simple());
    let registry = RegistryStore::connect(&redis_url).await.unwrap();
    registry
        .save(
            &organization_id,
            &json!({
                "services": [],
                "key_reference_purposes": {
                    "managed-openbao-transit": {"approved-key": ["vc_jwt_issuer"]}
                }
            }),
        )
        .await
        .unwrap();
    let app = marty_signing_keys::http::router_with_dependencies_and_sign_key(
        "test-internal-key".to_string(),
        Some("test-service-sign-gateway-key-000000".into()),
        Some(registry.clone()),
        None,
        None,
        None,
        None,
        None,
    );
    for body in [
        json!({
            "services": [],
            "key_reference_purposes": {
                "managed-openbao-transit": {"foreign-key": ["vc_jwt_issuer"]}
            }
        }),
        json!({}),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::patch(format!(
                    "/v1/signing-keys/config?organization_id={organization_id}"
                ))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let stored = registry.load(&organization_id).await.unwrap();
        let managed = &stored["key_reference_purposes"]["managed-openbao-transit"];
        assert_eq!(managed["approved-key"], json!(["vc_jwt_issuer"]));
        assert!(managed.get("foreign-key").is_none());
    }
    for body in [
        json!([]),
        Value::Null,
        json!("invalid"),
        json!(1),
        json!({"hsm_enabled": false}),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::patch(format!(
                    "/v1/signing-keys/config?organization_id={organization_id}"
                ))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let stored = registry.load(&organization_id).await.unwrap();
        assert_eq!(
            stored["key_reference_purposes"]["managed-openbao-transit"]["approved-key"],
            json!(["vc_jwt_issuer"])
        );
    }
    let mut connection = registry.connection();
    let _: () = connection.del(storage_key(&organization_id)).await.unwrap();
}

#[tokio::test]
#[ignore = "requires independently marked disposable loopback Redis and scoped OpenBao grants"]
async fn live_managed_alias_requires_tenant_purpose_and_algorithm_before_kms_sign() {
    let redis_url = disposable_redis_url().await;
    let (endpoint, _) = disposable_openbao().await;
    let organization_id = format!("test-managed-alias-{}", Uuid::new_v4().simple());
    let other_organization_id = format!("test-managed-other-{}", Uuid::new_v4().simple());
    let namespace = Uuid::new_v5(&Uuid::NAMESPACE_URL, organization_id.as_bytes())
        .simple()
        .to_string();
    let reference = format!("cred-issuer-{namespace}-issuer-es256");
    let metadata = create_managed_openbao(ProviderRequest {
        service_config: json!({
            "id": "managed-openbao-transit", "service_type": "openbao-transit",
            "auth_mode": "service_token", "endpoint": endpoint,
            "mount": "transit", "key_reference": reference, "algorithm": "ES256"
        }),
    })
    .await
    .expect("non-exportable tenant signing key");
    assert_eq!(metadata["exportable"], false);
    assert_eq!(metadata["allow_plaintext_backup"], false);
    let stored = RegistryStore::connect(&redis_url).await.unwrap();
    let managed = stored.clone().with_managed_openbao(Some(endpoint.clone()));
    for tenant in [&organization_id, &other_organization_id] {
        managed
            .save(
                tenant,
                &json!({
                    "services": [],
                    "key_reference_purposes": {
                        "managed-openbao-transit": {(reference.clone()): ["vc_jwt_issuer"]}
                    }
                }),
            )
            .await
            .unwrap();
    }
    let profiles = ProfileStore::from_connection(stored.connection());
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/issuer_profile_vectors.json")).unwrap();
    let mut foreign_profile = fixture["normalize"]["expected"].clone();
    foreign_profile["id"] = json!("foreign-profile");
    foreign_profile["organization_id"] = json!(other_organization_id);
    foreign_profile["signing_service_id"] = json!("managed-openbao-transit");
    foreign_profile["signing_key_reference"] = json!(reference);
    foreign_profile["key_purpose"] = json!("vc_jwt_issuer");
    foreign_profile["algorithm"] = json!("ES256");
    foreign_profile["status"] = json!("active");
    profiles
        .put(&other_organization_id, "foreign-profile", foreign_profile)
        .await
        .unwrap();
    let (app, _grant_file) = signing_router(
        managed,
        DocumentStore::from_connection(stored.connection()),
        profiles.clone(),
        &endpoint,
    )
    .await;
    let request = json!({
        "payload_b64": "cGF5bG9hZA",
        "algorithm": "ES256",
        "key_purpose": "vc_jwt_issuer",
        "key_reference": reference
    });
    let (status, signed) = sign_service(
        &app,
        &organization_id,
        "managed-openbao-transit",
        request.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{signed}");
    assert!(signed["signature_b64"]
        .as_str()
        .is_some_and(|value| !value.is_empty()));
    for (tenant, purpose, algorithm) in [
        (&organization_id, "mdoc_dsc", "ES256"),
        (&organization_id, "vc_jwt_issuer", "RS256"),
        (&other_organization_id, "vc_jwt_issuer", "ES256"),
    ] {
        let mut denied = request.clone();
        denied["key_purpose"] = json!(purpose);
        denied["algorithm"] = json!(algorithm);
        let (status, body) = sign_service(&app, tenant, "managed-openbao-transit", denied).await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
    }
    let mut implicit_reference = request.clone();
    implicit_reference
        .as_object_mut()
        .unwrap()
        .remove("key_reference");
    let (status, body) = sign_service(
        &app,
        &other_organization_id,
        "managed-openbao-transit",
        implicit_reference,
    )
    .await;
    assert_ne!(status, StatusCode::OK, "{body}");
    let mut connection = stored.connection();
    for tenant in [&organization_id, &other_organization_id] {
        let _: () = connection.del(storage_key(tenant)).await.unwrap();
    }
    let _: () = connection
        .del(profile_storage_key(&other_organization_id))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires independently marked disposable loopback Redis and scoped OpenBao"]
async fn live_managed_provider_rejects_foreign_profile_for_explicit_and_default_signing() {
    let redis_url = disposable_redis_url().await;
    let endpoint = std::env::var("MARTY_TEST_OPENBAO_URL").expect("disposable OpenBao URL");
    let parsed = reqwest::Url::parse(&endpoint).expect("disposable OpenBao URL syntax");
    assert!(parsed.scheme() == "http" && parsed.host_str() == Some("127.0.0.1"));
    let scoped_token = std::env::var("MARTY_TEST_OPENBAO_TOKEN").expect("scoped OpenBao token");
    assert_eq!(
        std::env::var("BAO_TOKEN").ok().as_deref(),
        Some(scoped_token.as_str())
    );
    let root_token = std::env::var("MARTY_TEST_OPENBAO_ROOT_TOKEN").expect("root guard token");
    assert_ne!(root_token, scoped_token);
    let nonce = std::env::var("MARTY_TEST_OPENBAO_DISPOSABLE_NONCE").expect("guard nonce");
    let marker: Value = reqwest::Client::new()
        .get(format!(
            "{endpoint}/v1/secret/data/marty-test-disposable-guard"
        ))
        .header("X-Vault-Token", &root_token)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        marker["data"]["data"]["nonce"].as_str(),
        Some(nonce.as_str())
    );

    let suffix = Uuid::new_v4().simple().to_string();
    let own_tenant = format!("test-live-own-{suffix}");
    let foreign_tenant = format!("test-live-foreign-{suffix}");
    let namespace = Uuid::new_v5(&Uuid::NAMESPACE_URL, own_tenant.as_bytes())
        .simple()
        .to_string();
    let reference = format!("cred-issuer-{namespace}-issuer-es256");
    create_managed_openbao(ProviderRequest {
        service_config: json!({
            "id": "managed-openbao-transit", "service_type": "openbao-transit",
            "auth_mode": "service_token", "endpoint": endpoint,
            "mount": "transit", "key_reference": reference, "algorithm": "ES256"
        }),
    })
    .await
    .expect("scoped managed key creation");
    let stored = RegistryStore::connect(&redis_url).await.unwrap();
    let managed = stored.clone().with_managed_openbao(Some(endpoint.clone()));
    for tenant in [&own_tenant, &foreign_tenant] {
        managed
            .save(
                tenant,
                &json!({
                    "services": [], "key_reference_purposes": {
                        "managed-openbao-transit": {(reference.clone()): ["vc_jwt_issuer"]}
                    }
                }),
            )
            .await
            .unwrap();
    }
    let profiles = ProfileStore::from_connection(stored.connection());
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/issuer_profile_vectors.json")).unwrap();
    let mut forged = fixture["normalize"]["expected"].clone();
    forged["id"] = json!("foreign-profile");
    forged["organization_id"] = json!(foreign_tenant);
    forged["signing_service_id"] = json!("managed-openbao-transit");
    forged["signing_key_reference"] = json!(reference);
    forged["key_purpose"] = json!("vc_jwt_issuer");
    forged["algorithm"] = json!("ES256");
    forged["status"] = json!("active");
    profiles
        .put(&foreign_tenant, "foreign-profile", forged)
        .await
        .unwrap();
    let (app, _grant_file) = signing_router(
        managed,
        DocumentStore::from_connection(stored.connection()),
        profiles,
        &endpoint,
    )
    .await;
    let request = json!({
        "payload_b64": "cGF5bG9hZA", "algorithm": "ES256",
        "key_purpose": "vc_jwt_issuer", "key_reference": reference
    });
    let (status, signed) = sign_service(
        &app,
        &own_tenant,
        "managed-openbao-transit",
        request.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{signed}");
    assert!(signed["signature_b64"]
        .as_str()
        .is_some_and(|value| !value.is_empty()));
    let (status, body) = sign_service(
        &app,
        &foreign_tenant,
        "managed-openbao-transit",
        request.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    let mut implicit = request;
    implicit.as_object_mut().unwrap().remove("key_reference");
    let (status, body) =
        sign_service(&app, &foreign_tenant, "managed-openbao-transit", implicit).await;
    assert_ne!(status, StatusCode::OK, "{body}");
    let mut connection = stored.connection();
    for tenant in [&own_tenant, &foreign_tenant] {
        let _: () = connection.del(storage_key(tenant)).await.unwrap();
    }
    let _: () = connection
        .del(profile_storage_key(&foreign_tenant))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires independently marked disposable loopback Redis and OpenBao"]
async fn public_service_sign_uses_registered_kms_key_and_rejects_unbound_selection() {
    let redis_url = disposable_redis_url().await;
    let (bao_url, bao_token) = disposable_openbao().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let key_name = format!("marty-public-sign-{suffix}");
    let profile_key_name = format!("marty-public-sign-profile-{suffix}");
    let organization_id = format!("test-public-sign-{suffix}");
    let client = reqwest::Client::new();
    let mount = client
        .get(format!("{bao_url}/v1/sys/mounts/transit"))
        .header("X-Vault-Token", &bao_token)
        .send()
        .await
        .unwrap();
    assert!(
        mount.status().is_success(),
        "disposable Transit mount is unavailable"
    );
    let created = client
        .post(format!("{bao_url}/v1/transit/keys/{key_name}"))
        .header("X-Vault-Token", &bao_token)
        .json(&json!({"type":"ecdsa-p256"}))
        .send()
        .await
        .unwrap();
    assert!(created.status().is_success());
    let profile_key_created = client
        .post(format!("{bao_url}/v1/transit/keys/{profile_key_name}"))
        .header("X-Vault-Token", &bao_token)
        .json(&json!({"type":"ecdsa-p256"}))
        .send()
        .await
        .unwrap();
    assert!(profile_key_created.status().is_success());
    let registry = RegistryStore::connect(&redis_url).await.unwrap();
    registry
        .save(
            &organization_id,
            &json!({
                "services": [{
                    "id": "service-a", "name": "Test KMS signer",
                    "service_type": "openbao-transit", "endpoint": bao_url,
                    "mount": "transit", "auth_mode": "token", "auth_reference": bao_token,
                    "key_reference": key_name, "algorithms": ["ES256"],
                    "key_purposes": ["vc_jwt_issuer"]
                }],
                "default_service_id": "service-a"
            }),
        )
        .await
        .unwrap();
    let documents = DocumentStore::from_connection(registry.connection());
    let profiles = ProfileStore::from_connection(registry.connection());
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/issuer_profile_vectors.json")).unwrap();
    let mut profile = fixture["normalize"]["expected"].clone();
    profile["organization_id"] = json!(organization_id);
    profile["signing_service_id"] = json!("service-a");
    profile["signing_key_reference"] = json!(profile_key_name);
    profiles
        .put(&organization_id, "ip-vector", profile)
        .await
        .unwrap();
    let (app, _grant_file) =
        signing_router(registry.clone(), documents, profiles.clone(), &bao_url).await;
    let request = json!({
        "payload_b64": "cGF5bG9hZA",
        "algorithm": "ES256",
        "key_purpose": "vc_jwt_issuer",
        "key_reference": key_name,
    });
    let (status, signed) = sign(&app, &organization_id, request.clone()).await;
    assert_eq!(status, StatusCode::OK, "{signed}");
    assert_eq!(signed["ok"], true);
    assert_eq!(signed["service_id"], "service-a");
    assert_eq!(signed["algorithm"], "ES256");
    assert_eq!(signed["payload_length"], 7);
    assert!(!signed["signature_b64"].as_str().unwrap().is_empty());
    assert!(!signed["signature_hex"].as_str().unwrap().is_empty());
    assert!(!signed.to_string().contains(&bao_token));
    assert!(!signed.to_string().contains(&key_name));

    let mut legacy_profile_selection = request.clone();
    legacy_profile_selection["key_reference"] = json!(profile_key_name);
    let (status, profile_signed) = sign(&app, &organization_id, legacy_profile_selection).await;
    assert_eq!(status, StatusCode::OK, "{profile_signed}");
    assert!(!profile_signed["signature_b64"].as_str().unwrap().is_empty());

    let mut unbound = request.clone();
    unbound["key_reference"] = json!("other-tenant-key");
    assert_eq!(
        sign(&app, &organization_id, unbound).await.0,
        StatusCode::CONFLICT
    );
    let mut mismatch = request.clone();
    mismatch["organization_id"] = json!("other-tenant");
    assert_eq!(
        sign(&app, &organization_id, mismatch).await.0,
        StatusCode::FORBIDDEN
    );
    let mut private = request.clone();
    private["private_key"] = json!("not-allowed");
    assert_eq!(
        sign(&app, &organization_id, private).await.0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        sign(&app, &organization_id, json!({})).await.0,
        StatusCode::BAD_REQUEST
    );
    let missing = app
        .oneshot(
            Request::post(format!(
                "/v1/signing-keys/services/missing/sign?organization_id={organization_id}"
            ))
            .header("content-type", "application/json")
            .body(Body::from(request.to_string()))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);

    let mut connection = registry.connection();
    let _: () = connection.del(storage_key(&organization_id)).await.unwrap();
    let _: () = connection
        .del(profile_storage_key(&organization_id))
        .await
        .unwrap();
}
