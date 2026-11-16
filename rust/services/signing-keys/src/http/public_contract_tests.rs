use super::*;
use axum::{
    body::Body,
    http::Request,
    middleware::{self, Next},
};
use tower::ServiceExt;

#[tokio::test]
async fn absent_extensions_return_typed_capability_only_after_authorization() {
    let app = router_with_internal_api_key("test-only-internal-authority".into());
    let requests = [
        (
            "/internal/haip-response-keys/create",
            json!({"organization_id":"org-a", "flow_instance_id":"flow-a"}),
            "haip_response_encryption",
        ),
        (
            "/internal/haip-response-keys/resolve",
            json!({"organization_id":"org-a", "flow_instance_id":"flow-a", "version":"1"}),
            "haip_response_encryption",
        ),
        (
            "/internal/haip-response-keys/decrypt",
            json!({"organization_id":"org-a", "flow_instance_id":"flow-a", "version":"1", "jwe":"encrypted-response"}),
            "haip_response_encryption",
        ),
        (
            "/internal/documents/org-a/passport-artifacts/encrypt",
            json!({"artifact_id":"artifact-a", "chunk_index":0, "chunk_count":1, "plaintext_b64":"YQ=="}),
            "passport_artifact_encryption",
        ),
        (
            "/internal/documents/org-a/passport-artifacts/decrypt",
            json!({"artifact_id":"artifact-a", "chunk_index":0, "chunk_count":1, "ciphertext":"vault:v1:opaque"}),
            "passport_artifact_encryption",
        ),
        (
            "/internal/documents/org-a/passport-callbacks/verify",
            json!({"body_b64":"YQ==", "signature":"vault:v1:opaque"}),
            "passport_callback_verification",
        ),
    ];
    for (path, body, capability) in requests {
        for authorized in [false, true] {
            let mut request = Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json");
            if authorized {
                request = request.header("x-api-key", "test-only-internal-authority");
            }
            let response = app
                .clone()
                .oneshot(request.body(Body::from(body.to_string())).unwrap())
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                if authorized {
                    StatusCode::UNPROCESSABLE_ENTITY
                } else {
                    StatusCode::UNAUTHORIZED
                },
                "{path}"
            );
            if authorized {
                let bytes = axum::body::to_bytes(response.into_body(), 2048)
                    .await
                    .unwrap();
                let value: Value = serde_json::from_slice(&bytes).unwrap();
                assert_eq!(value["code"], "capability_unavailable", "{path}");
                assert_eq!(value["capability"], capability, "{path}");
            }
        }
    }
}

#[test]
fn config_cas_response_protects_strong_etag_from_intermediary_transforms() {
    let revision = format!("\"r-{}\"", uuid::Uuid::new_v4());
    let response = (
        public_config_revision_headers(revision.clone()),
        Json(json!({"services": []})),
    )
        .into_response();
    assert_eq!(response.headers()[ETAG], revision.as_str());
    assert_eq!(response.headers()[CACHE_CONTROL], "no-store, no-transform");
    let mut headers = HeaderMap::new();
    headers.insert(IF_MATCH, response.headers()[ETAG].clone());
    assert_eq!(strong_config_if_match(&headers), Ok(Some(revision.clone())));
    headers.insert(IF_MATCH, format!("W/{revision}").parse().unwrap());
    assert!(strong_config_if_match(&headers).is_err());
}

#[test]
fn registry_secret_capability_failure_is_typed_for_config_writes() {
    let (status, Json(body)) = registry_error(registry::RegistryError::SecretCapabilityUnavailable);
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["code"], "capability_unavailable");
    assert_eq!(body["capability"], "integration_secret_encryption");
    assert_eq!(
        body["detail"],
        "The configured KMS cannot encrypt this service credential."
    );
    let (status, Json(body)) = registry_error(registry::RegistryError::Storage("fixture".into()));
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(body.get("code").is_none());
}

#[test]
fn config_if_match_requires_one_strong_opaque_revision() {
    let mut headers = HeaderMap::new();
    assert_eq!(strong_config_if_match(&headers), Ok(None));
    for invalid in [
        "*",
        "W/\"r-legacy\"",
        "\"r-not-a-uuid\"",
        "\"r-legacy\", \"r-legacy\"",
    ] {
        headers.insert(IF_MATCH, invalid.parse().unwrap());
        assert!(strong_config_if_match(&headers).is_err());
    }
    headers.insert(IF_MATCH, "\"r-legacy\"".parse().unwrap());
    assert!(strong_config_if_match(&headers).is_err());
    let revision = format!("\"r-{}\"", uuid::Uuid::new_v4());
    headers.insert(IF_MATCH, revision.parse().unwrap());
    assert_eq!(strong_config_if_match(&headers), Ok(Some(revision)));
    headers.append(IF_MATCH, "\"r-legacy\"".parse().unwrap());
    assert!(strong_config_if_match(&headers).is_err());
}

#[tokio::test]
async fn public_identity_mutations_reject_invalid_revision_before_binding() {
    let app = router_with_dependencies("test-key".into(), None, None, None, None, None, None);
    let body = json!({"organization_id": "org-a", "issuer_did": "did:web:issuer.example:orgs:org-a",
            "key_purpose": "vc_jwt_issuer", "credential_format": "SD_JWT_VC", "algorithm": "ES256"});
    for method in [axum::http::Method::POST, axum::http::Method::PATCH] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri("/v1/signing-keys/issuer-identities?organization_id=org-a")
                    .header("content-type", "application/json")
                    .header(IF_MATCH, "W/\"r-not-strong\"")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
#[ignore = "requires guarded disposable MARTY_TEST_REDIS_URL"]
async fn conditional_config_restore_rejects_intervening_edit() {
    let redis_url = std::env::var("MARTY_TEST_REDIS_URL").expect("disposable Redis URL");
    let parsed = reqwest::Url::parse(&redis_url).unwrap();
    assert!(matches!(
        parsed.host_str(),
        Some("127.0.0.1" | "localhost" | "::1")
    ));
    assert!(parsed
        .path()
        .trim_start_matches('/')
        .parse::<u8>()
        .is_ok_and(|db| db >= 13));
    let nonce = std::env::var("MARTY_TEST_REDIS_DISPOSABLE_NONCE").expect("disposable sentinel");
    assert!(nonce.len() >= 16);
    let store = RegistryStore::connect(&redis_url).await.unwrap();
    let mut connection = store.connection();
    let observed: Option<String> = redis::cmd("GET")
        .arg("marty:tests:disposable-guard")
        .query_async(&mut connection)
        .await
        .unwrap();
    assert_eq!(observed.as_deref(), Some(nonce.as_str()));

    let organization_id = format!("conditional-config-{}", uuid::Uuid::new_v4().simple());
    let base = json!({"services": [{
        "id": "service-a", "name": "Original", "service_type": "aws-kms",
        "region": "us-east-1", "auth_mode": "iam_role",
        "algorithms": ["ES256"], "key_purposes": ["vc_jwt_issuer"]
    }]});
    store.save(&organization_id, &base).await.unwrap();
    let binding_org = format!("conditional-binding-{}", uuid::Uuid::new_v4().simple());
    store.save(&binding_org, &base).await.unwrap();
    let binding_first = store.load_with_revision(&binding_org).await.unwrap().1;
    let binding = json!({"signing_service_id": "service-a", "signing_key_reference": "owned-key",
            "key_purpose": "vc_jwt_issuer"});
    let (_, binding_second) = store
        .bind_profile_if_revision(&binding_org, &binding, Some(&binding_first))
        .await
        .unwrap();
    assert_ne!(binding_first, binding_second);
    assert_eq!(
        store.load(&binding_org).await.unwrap()["key_reference_purposes"]["service-a"]["owned-key"],
        json!(["vc_jwt_issuer"])
    );
    let mut foreign = store.load(&binding_org).await.unwrap();
    foreign["services"][0]["name"] = json!("Foreign edit");
    store.save(&binding_org, &foreign).await.unwrap();
    assert!(matches!(
        store
            .bind_profile_if_revision(&binding_org, &binding, Some(&binding_second))
            .await,
        Err(registry::RegistryError::PreconditionFailed)
    ));
    assert_eq!(
        store.load(&binding_org).await.unwrap()["services"][0]["name"],
        "Foreign edit"
    );
    let app = router_with_dependencies(
        "test-key".into(),
        Some(store.clone()),
        None,
        None,
        None,
        None,
        None,
    );
    let uri = format!("/v1/signing-keys/config?organization_id={organization_id}");
    let first = app
        .clone()
        .oneshot(Request::get(uri.as_str()).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let first_revision = first.headers()[ETAG].to_str().unwrap().to_owned();
    let first_body: Value = serde_json::from_slice(
        &axum::body::to_bytes(first.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(first_body["services"][0]["auth_reference"], "");

    // Actor B edits after actor A has captured the original revision.
    let mut second_body = first_body.clone();
    second_body["services"][0]["name"] = json!("Intervening");
    let second = app
        .clone()
        .oneshot(
            Request::patch(uri.as_str())
                .header("content-type", "application/json")
                .header(IF_MATCH, first_revision.as_str())
                .body(Body::from(second_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::OK);
    let second_revision = second.headers()[ETAG].to_str().unwrap().to_owned();
    assert_ne!(first_revision, second_revision);

    // Actor A's stale full-document restoration must not erase B's edit.
    let stale = app
        .clone()
        .oneshot(
            Request::patch(uri.as_str())
                .header("content-type", "application/json")
                .header(IF_MATCH, first_revision.as_str())
                .body(Body::from(first_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(stale.status(), StatusCode::PRECONDITION_FAILED);
    assert_eq!(
        store.load(&organization_id).await.unwrap()["services"][0]["name"],
        "Intervening"
    );
    assert_eq!(
        store.load_with_revision(&organization_id).await.unwrap().1,
        second_revision
    );

    // A fresh revision permits the intended restoration.
    let restored = app
        .clone()
        .oneshot(
            Request::patch(uri.as_str())
                .header("content-type", "application/json")
                .header(IF_MATCH, second_revision.as_str())
                .body(Body::from(first_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(restored.status(), StatusCode::OK);
    let restored_revision = restored.headers()[ETAG].to_str().unwrap().to_owned();
    assert_eq!(
        store.load(&organization_id).await.unwrap()["services"][0]["name"],
        "Original"
    );
    // Simulate an older writer changing the raw document without touching
    // the revision sidecar. The next conditional write must still fail.
    let raw: String = redis::cmd("GET")
        .arg(registry::storage_key(&organization_id))
        .query_async(&mut connection)
        .await
        .unwrap();
    let mut legacy: Value = serde_json::from_str(&raw).unwrap();
    legacy["services"][0]["name"] = json!("Legacy writer edit");
    let _: () = redis::cmd("SET")
        .arg(registry::storage_key(&organization_id))
        .arg(legacy.to_string())
        .query_async(&mut connection)
        .await
        .unwrap();
    let stale_legacy = app
        .clone()
        .oneshot(
            Request::patch(uri.as_str())
                .header("content-type", "application/json")
                .header(IF_MATCH, restored_revision.as_str())
                .body(Body::from(first_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(stale_legacy.status(), StatusCode::PRECONDITION_FAILED);
    assert_eq!(
        store.load(&organization_id).await.unwrap()["services"][0]["name"],
        "Legacy writer edit"
    );
    // Force the second race window: an old/out-of-band writer changes the
    // raw document after the precondition read but before the fenced SET.
    let snapshot = store
        .load_with_revision_snapshot(&organization_id)
        .await
        .unwrap();
    let lease = store
        .acquire_rotation_lease(&organization_id)
        .await
        .unwrap()
        .unwrap();
    let raw: String = redis::cmd("GET")
        .arg(registry::storage_key(&organization_id))
        .query_async(&mut connection)
        .await
        .unwrap();
    let mut raced: Value = serde_json::from_str(&raw).unwrap();
    raced["services"][0]["name"] = json!("Between-read-and-save edit");
    let _: () = redis::cmd("SET")
        .arg(registry::storage_key(&organization_id))
        .arg(raced.to_string())
        .query_async(&mut connection)
        .await
        .unwrap();
    let refused = store
        .save_requested_if_unchanged_with_rotation_lease(
            &organization_id,
            &first_body,
            &snapshot,
            &lease,
        )
        .await;
    assert!(matches!(
        refused,
        Err(registry::RegistryError::PreconditionFailed)
    ));
    lease.release().await.unwrap();
    assert_eq!(
        store.load(&organization_id).await.unwrap()["services"][0]["name"],
        "Between-read-and-save edit"
    );
    let _: i32 = redis::cmd("DEL")
        .arg(registry::storage_key(&organization_id))
        .arg(registry::revision_key(&organization_id))
        .query_async(&mut connection)
        .await
        .unwrap();
}

#[tokio::test]
async fn service_signing_denies_api_key_without_a_bound_grant() {
    let app = router_with_all_keys(
        "shared-internal-signing-key-32-chars".into(),
        Some("dedicated-service-sign-key-32-chars".into()),
        Some("dedicated-issuer-sign-key-32-chars".into()),
        None,
        None,
        None,
        false,
        None,
        None,
        None,
        None,
        None,
        None,
    );
    let payload = json!({
        "organization_id": "org-a",
        "payload_b64": "cGF5bG9hZA",
        "algorithm": "ES256",
        "key_reference": "issuer-key-1",
        "key_purpose": "vc_jwt_issuer"
    });
    for grant in [None, Some("invalid-grant")] {
        let mut request =
            Request::post("/v1/signing-keys/services/service-1/sign?organization_id=org-a")
                .header("content-type", "application/json")
                .header("x-api-key", "dedicated-service-sign-key-32-chars");
        if let Some(grant) = grant {
            request = request.header(HEADER_NAME, grant);
        }
        let response = app
            .clone()
            .oneshot(request.body(Body::from(payload.to_string())).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}

#[tokio::test]
async fn issuer_signing_rejects_shared_internal_key_before_reaching_provider() {
    let app = router_with_all_keys(
        "shared-internal-signing-key-32-chars".into(),
        Some("dedicated-service-sign-key-32-chars".into()),
        Some("dedicated-issuer-sign-key-32-chars".into()),
        None,
        None,
        None,
        false,
        None,
        None,
        None,
        None,
        None,
        None,
    );
    let payload = json!({
        "organization_id": "org-a",
        "issuer_did": "did:web:issuer.example:orgs:org-a",
        "key_purpose": "vc_jwt_issuer",
        "credential_format": "SD_JWT_VC",
        "algorithm": "EdDSA",
        "payload_b64": "cGF5bG9hZA"
    });
    for (key, expected) in [
        (
            "shared-internal-signing-key-32-chars",
            StatusCode::UNAUTHORIZED,
        ),
        (
            "dedicated-issuer-sign-key-32-chars",
            StatusCode::UNAUTHORIZED,
        ),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::post("/internal/compat/issuer-dids/sign")
                    .header("content-type", "application/json")
                    .header("x-api-key", key)
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
}

#[tokio::test]
async fn integration_secret_routes_require_their_dedicated_key() {
    let app = router_with_all_keys(
        "shared-internal-signing-key-32-chars".into(),
        Some("dedicated-service-sign-key-32-chars".into()),
        Some("dedicated-issuer-sign-key-32-chars".into()),
        Some("dedicated-integration-secret-key-32-chars".into()),
        None,
        None,
        false,
        None,
        None,
        None,
        None,
        None,
        None,
    );
    for (operation, payload) in [
        (
            "encrypt",
            json!({"organization_id":"org-a","secret_id":"secret-a","provider":"canvas","purpose":"oauth_client_secret","plaintext_b64":"c2VjcmV0"}),
        ),
        (
            "decrypt",
            json!({"organization_id":"org-a","secret_id":"secret-a","provider":"canvas","purpose":"oauth_client_secret","envelope":{"schema":"marty.integration-secret-envelope/v1","ciphertext":"vault:v1:synthetic"}}),
        ),
    ] {
        for (key, expected) in [
            (
                "shared-internal-signing-key-32-chars",
                StatusCode::UNAUTHORIZED,
            ),
            (
                "dedicated-integration-secret-key-32-chars",
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::post(format!("/internal/integration-secrets/{operation}"))
                        .header("content-type", "application/json")
                        .header("x-api-key", key)
                        .body(Body::from(payload.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), expected);
            let body = axum::body::to_bytes(response.into_body(), 2048)
                .await
                .unwrap();
            let body: Value = serde_json::from_slice(&body).unwrap();
            if expected == StatusCode::UNPROCESSABLE_ENTITY {
                assert_eq!(body["code"], "capability_unavailable");
                assert_eq!(body["capability"], "integration_secret_encryption");
            } else {
                assert!(body.get("code").is_none());
                assert!(body.get("capability").is_none());
            }
        }
    }
}

#[tokio::test]
async fn dsc_issuance_rejects_shared_internal_key_and_requires_distinct_gateway_key() {
    let app = router_with_dependencies_and_dsc_key(
        "shared-internal-signing-key-32-chars".into(),
        Some("dedicated-dsc-operator-gateway-key-32-chars".into()),
        None,
        None,
        None,
        None,
        None,
        None,
    );
    let payload = json!({
        "dsc_issuer_did": "did:web:beta.example:orgs:org-a",
        "csca_issuer_did": "did:web:beta.example:orgs:org-a",
        "csca_certificate_id": "csca-1",
        "credential_format": "ICAO_EMRTD",
        "country": "US", "organization": "ElevenID Beta", "common_name": "Pilot DSC",
        "validity_days": 30, "idempotency_key": "request-1"
    });
    let request = |key: &str| {
        Request::post("/v1/signing-keys/issuer-identities/dsc-certificate?organization_id=org-a")
            .header("content-type", "application/json")
            .header("x-api-key", key)
            .header("x-user-id", "operator-1")
            .body(Body::from(payload.to_string()))
            .unwrap()
    };
    assert_eq!(
        app.clone()
            .oneshot(request("shared-internal-signing-key-32-chars"))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.oneshot(request("dedicated-dsc-operator-gateway-key-32-chars"))
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[tokio::test]
async fn csca_ceremony_requires_beta_and_its_own_gateway_authority() {
    let key = "dedicated-csca-operator-gateway-key-32-chars";
    let payload = json!({
        "issuer_did": "did:web:beta.example:orgs:org-a",
        "certificate_id": "csca-pilot-1",
        "credential_format": "ICAO_EMRTD",
        "country": "US", "organization": "ElevenID Beta", "common_name": "Pilot CSCA",
        "validity_days": 365
    });
    let request =
        |key: &str, body: Value| {
            Request::post(
            "/v1/signing-keys/issuer-identities/csca-self-signed-certificate?organization_id=org-a"
        ).header("content-type", "application/json")
            .header("x-api-key", key)
            .header("x-user-id", "operator-1")
            .body(Body::from(body.to_string())).unwrap()
        };
    let disabled = router_with_dependencies_and_ceremony_keys(
        "internal-signing-key-32-characters-long".into(),
        None,
        Some(key.into()),
        false,
        None,
        None,
        None,
        None,
        None,
        None,
    );
    assert_eq!(
        disabled
            .oneshot(request(key, payload.clone()))
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let enabled = router_with_dependencies_and_ceremony_keys(
        "internal-signing-key-32-characters-long".into(),
        Some("dedicated-dsc-operator-gateway-key-32-chars".into()),
        Some(key.into()),
        true,
        None,
        None,
        None,
        None,
        None,
        None,
    );
    for wrong in [
        "internal-signing-key-32-characters-long",
        "dedicated-dsc-operator-gateway-key-32-chars",
        "forged",
    ] {
        assert_eq!(
            enabled
                .clone()
                .oneshot(request(wrong, payload.clone()))
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        enabled
            .clone()
            .oneshot(request(key, payload.clone()))
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let mut forged = payload;
    forged["key_reference"] = json!("attacker-selected-kms-key");
    assert_eq!(
        enabled
            .oneshot(request(key, forged))
            .await
            .unwrap()
            .status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert!(openapi().await.0["paths"]
        ["/v1/signing-keys/issuer-identities/csca-self-signed-certificate"]["post"]
        .is_object());
}

#[test]
fn dsc_issuance_public_errors_do_not_disclose_managed_key_references() {
    let reference = "kms-secret-key-locator";
    let compatibility = dsc_compat_failure(CompatibilityError::Conflict(reference.into()));
    let storage = dsc_store_failure(DscIssuanceStoreError::Storage(reference.into()));
    assert_eq!(compatibility.status, StatusCode::CONFLICT);
    assert_eq!(storage.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(!compatibility.detail.contains(reference));
    assert!(!storage.detail.contains(reference));
}

#[test]
fn config_discovery_accepts_public_jwks_inside_provider_envelopes() {
    let vectors: Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/kms_provider_vectors.json"
    ))
    .unwrap();
    let fixture = |name: &str| {
        vectors["public_key_cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["name"] == name)
            .unwrap()["expected_response"]
            .clone()
    };
    for (name, algorithm) in [
        ("aws_kms_spki_public_key", "ES256"),
        ("azure_embedded_public_jwk", "ES256"),
        ("gcp_pem_public_key", "ES256"),
        ("openbao_raw_ed25519", "EdDSA"),
    ] {
        let response = fixture(name);
        assert_eq!(
            discovered_key_matches_algorithm(&response, algorithm),
            Ok(true),
            "{name}"
        );
        assert_eq!(
            discovered_key_matches_algorithm(&response, "ES512"),
            Ok(false),
            "{name}"
        );
    }
    let mut aws = fixture("aws_kms_spki_public_key");
    aws["key_usage"] = json!("ENCRYPT_DECRYPT");
    assert_eq!(discovered_key_matches_algorithm(&aws, "ES256"), Ok(false));
    aws["key_usage"] = json!("SIGN_VERIFY");
    aws["signing_algorithms"] = json!(["ECDSA_SHA_384"]);
    assert_eq!(discovered_key_matches_algorithm(&aws, "ES256"), Ok(false));
    aws.as_object_mut().unwrap().remove("signing_algorithms");
    assert!(discovered_key_matches_algorithm(&aws, "ES256").is_err());
    let mut gcp = fixture("gcp_pem_public_key");
    gcp["algorithm"] = json!("RSA_DECRYPT_OAEP_2048_SHA256");
    assert_eq!(discovered_key_matches_algorithm(&gcp, "ES256"), Ok(false));
    gcp.as_object_mut().unwrap().remove("algorithm");
    assert!(discovered_key_matches_algorithm(&gcp, "ES256").is_err());
    let mut azure = fixture("azure_embedded_public_jwk");
    azure["key_ops"] = json!(["verify"]);
    assert_eq!(discovered_key_matches_algorithm(&azure, "ES256"), Ok(false));
    azure["key_ops"] = json!(["sign"]);
    azure["use"] = json!("enc");
    assert_eq!(discovered_key_matches_algorithm(&azure, "ES256"), Ok(false));
    let public_verifier = json!({
        "kty": "EC", "crv": "P-256", "x": "public-x", "y": "public-y",
        "use": "sig", "key_ops": ["verify"]
    });
    assert_eq!(
        discovered_key_matches_algorithm(&public_verifier, "ES256"),
        Ok(true)
    );
    assert!(discovered_key_matches_algorithm(&json!({"provider":"gcp"}), "ES256").is_err());
}

#[tokio::test]
async fn every_gateway_declared_signing_pair_matches_a_rust_public_route() {
    async fn mark_matched_route(request: Request<Body>, next: Next) -> Response {
        let mut response = next.run(request).await;
        response.headers_mut().insert(
            "x-rust-signing-route-match",
            axum::http::HeaderValue::from_static("true"),
        );
        response
    }

    let gateway: Value =
        serde_json::from_str(include_str!("../../../../../contracts/gateway-routes.json")).unwrap();
    let declared = gateway["routes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|route| {
            route["path"]
                .as_str()
                .is_some_and(|path| path.starts_with("/v1/signing-keys"))
        })
        .collect::<Vec<_>>();
    assert_eq!(declared.len(), 42, "review route additions explicitly");
    let app = router_with_internal_api_key("test-only".into())
        .route_layer(middleware::from_fn(mark_matched_route));
    let unknown = app
        .clone()
        .oneshot(
            Request::get("/v1/signing-keys/not/a/declared/path")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(unknown
        .headers()
        .get("x-rust-signing-route-match")
        .is_none());
    for route in declared {
        let method = route["method"].as_str().unwrap();
        let path = route["path"]
            .as_str()
            .unwrap()
            .replace("{service_id}", "service-1")
            .replace("{key_id}", "key-1");
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(format!("{path}?organization_id=org-a"))
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response
                .headers()
                .get("x-rust-signing-route-match")
                .unwrap(),
            "true",
            "{method} {path} did not reach a Rust route"
        );
        assert_ne!(
            response.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "{method} {path} lacks its declared method"
        );
    }
}

#[test]
fn managed_key_creation_behavior_is_frozen_before_public_port() {
    let behavior: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/signing-managed-key-create-behavior.json"
    ))
    .unwrap();
    assert_eq!(behavior["method"], "POST");
    assert_eq!(behavior["path"], "/v1/signing-keys");
    assert_eq!(
        behavior["request_fields"]["algorithm"],
        "ES256 by default; released support ES256, ES384, RS256, EdDSA"
    );
    assert_eq!(
        behavior["released_reference_prefixes"]["lti_tool_signing"],
        "lti-tool-"
    );
    assert!(behavior["long_name_collision_policy"]
        .as_str()
        .is_some_and(|policy| policy.contains("stable SHA-256 suffix")));
}

#[test]
fn managed_inventory_enrichment_uses_verified_aliases_not_stale_bindings() {
    let service = json!({
        "id": "managed-openbao-transit",
        "key_reference": "cred-issuer-own-live",
        "key_aliases": ["cred-issuer-own-live", "oid4vp-verifier-own-live"]
    });
    let bindings = json!({
        "cred-issuer-own-live": ["vc_jwt_issuer"],
        "cred-issuer-0123456789abcdef0123-es256": ["vc_jwt_issuer"],
        "cred-issuer-foreign-tenant-key": ["vc_jwt_issuer"]
    });
    let references = verified_managed_references(&service);
    assert_eq!(references.len(), 2);
    assert!(references.contains("cred-issuer-own-live"));
    assert!(references.contains("oid4vp-verifier-own-live"));
    for bound in bindings.as_object().unwrap().keys() {
        if bound != "cred-issuer-own-live" {
            assert!(!references.contains(bound));
        }
    }
}

#[tokio::test]
async fn managed_key_creation_names_are_tenant_scoped_and_inputs_fail_closed() {
    assert!(openapi().await.0["paths"]["/v1/signing-keys"]["post"].is_object());
    let first = managed_key_name("org-a", "cred-dsc-My Key", "vc_jwt_issuer", "ES256").unwrap();
    let same = managed_key_name("org-a", "cred-dsc-My Key", "vc_jwt_issuer", "ES256").unwrap();
    let other = managed_key_name("org-b", "cred-dsc-My Key", "vc_jwt_issuer", "ES256").unwrap();
    assert_eq!(first, same);
    assert_ne!(first, other);
    assert!(first.starts_with("cred-issuer-"));
    assert!(first.ends_with("-my-key-es256"));
    assert!(first.len() <= 96);
    let long_prefix = "a".repeat(80);
    let first_long = managed_key_name(
        "org-a",
        &format!("{long_prefix}-first"),
        "vc_jwt_issuer",
        "ES256",
    )
    .unwrap();
    let second_long = managed_key_name(
        "org-a",
        &format!("{long_prefix}-second"),
        "vc_jwt_issuer",
        "ES256",
    )
    .unwrap();
    assert_ne!(first_long, second_long);
    assert_eq!(
        first_long,
        managed_key_name(
            "org-a",
            &format!("{long_prefix}-first"),
            "vc_jwt_issuer",
            "ES256"
        )
        .unwrap()
    );
    assert!(first_long.len() <= 96 && second_long.len() <= 96);
    assert!(first_long.ends_with("-es256") && second_long.ends_with("-es256"));
    for (purpose, prefix) in [
        ("vc_jwt_issuer", "cred-issuer-"),
        ("jwks_signing", "cred-issuer-"),
        ("mdoc_dsc", "cred-dsc-"),
        ("x509_doc_signer", "cred-dsc-"),
        ("vdsnc_signing", "cred-dsc-"),
        ("csca", "cred-dsc-"),
        ("holder_binding", "cred-holder-"),
        ("presentation_signing", "cred-presenter-"),
        ("oid4vp_request_signing", "oid4vp-verifier-"),
        ("lti_tool_signing", "lti-tool-"),
    ] {
        let reference = managed_key_name("org-a", "shared", purpose, "ES256").unwrap();
        assert!(reference.starts_with(prefix), "{purpose}: {reference}");
        assert!(crate::domain::managed_key_purposes(&reference).contains(&purpose));
    }
    assert!(
        managed_key_name("org-a", &"a".repeat(250), "lti_tool_signing", "RS256")
            .unwrap()
            .ends_with("-rs256")
    );
    assert!(managed_key_name("org-a", " ", "vc_jwt_issuer", "ES256").is_err());
    let router = router_with_internal_api_key("test-only".into());
    let request = |body: Value| {
        Request::post("/v1/signing-keys?organization_id=org-a")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    let valid = router
        .clone()
        .oneshot(request(json!({"name": "Key"})))
        .await
        .unwrap();
    assert_eq!(valid.status(), StatusCode::SERVICE_UNAVAILABLE);
    for invalid in [
        json!({"name": ""}),
        json!({"name": "bad\nname"}),
        json!({"name": "Key", "algorithm": "ES512"}),
        json!({"name": "Key", "key_purpose": "lti_tool_signing", "algorithm": "ES256"}),
        json!({"name": "Key", "key_purpose": "mdoc_dsc", "algorithm": "RS256"}),
        json!({"name": "Key", "key_purpose": "vdsnc_signing", "algorithm": "RS256"}),
        json!({"name": "Key", "key_purpose": "holder_binding", "algorithm": "RS256"}),
        json!({"name": "Key", "key_purpose": "presentation_signing", "algorithm": "ES384"}),
        json!({"name": "Key", "key_purpose": "oid4vp_request_signing", "algorithm": "EdDSA"}),
        json!({"name": "Key", "private_key": "forged"}),
        json!({"name": "Key", "public_key": "not-an-import-route"}),
        json!({"name": "Key", "key_type": "local"}),
        json!({"name": "Key", "hsm_config": {"endpoint": "https://attacker.invalid"}}),
        json!({"name": "Key", "endpoint": "https://attacker.invalid"}),
    ] {
        let status = router
            .clone()
            .oneshot(request(invalid))
            .await
            .unwrap()
            .status();
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }
    let mismatch = router
        .oneshot(request(json!({"name": "Key", "organization_id": "org-b"})))
        .await
        .unwrap();
    assert_eq!(mismatch.status(), StatusCode::FORBIDDEN);
}

#[test]
fn public_key_metadata_behavior_is_frozen_before_public_port() {
    let behavior: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/signing-public-key-metadata-behavior.json"
    ))
    .unwrap();
    assert_eq!(behavior["routes"].as_array().unwrap().len(), 3);
    assert_eq!(behavior["routes"][0]["method"], "GET");
    assert_eq!(
        behavior["routes"][1]["mutable_fields"],
        json!(["name", "status", "aliases", "key_aliases"])
    );
    assert_eq!(behavior["routes"][2]["method"], "DELETE");
    assert!(behavior["concurrent_mutation_rule"]
        .as_str()
        .is_some_and(|rule| rule.contains("atomic read-modify-write")));
}

#[tokio::test]
async fn public_key_metadata_routes_reject_custody_fields_before_storage() {
    for method in ["get", "patch", "delete"] {
        assert!(openapi().await.0["paths"]["/v1/signing-keys/{key_id}"][method].is_object());
    }
    let router = router_with_internal_api_key("test-only".into());
    let request = |body: Value| {
        Request::patch("/v1/signing-keys/key-a?organization_id=org-a")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    let valid = router
        .clone()
        .oneshot(request(json!({"name": "New name"})))
        .await
        .unwrap();
    assert_eq!(valid.status(), StatusCode::SERVICE_UNAVAILABLE);
    for body in [
        json!({"d": "private-scalar"}),
        json!({"auth_reference": "provider-secret"}),
        json!({"aliases": [{"private_key": "forged"}]}),
        json!({"name": {"private_key": "forged"}}),
        json!({"status": "active\nforged"}),
    ] {
        assert_eq!(
            router
                .clone()
                .oneshot(request(body))
                .await
                .unwrap()
                .status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }
}

#[test]
fn vdsnc_registration_behavior_is_frozen_before_public_port() {
    let behavior: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/signing-vdsnc-registration-behavior.json"
    ))
    .unwrap();
    assert_eq!(behavior["method"], "POST");
    assert_eq!(behavior["path"], "/v1/signing-keys/services/vdsnc/register");
    assert_eq!(
        behavior["defaults"]["key_purposes"],
        json!(["vdsnc_signing"])
    );
    assert_eq!(
        behavior["defaults"]["released_credential_formats"],
        json!(["mso_mdoc"])
    );
    assert_eq!(
        behavior["discovered_capabilities"],
        json!([
            "vdsnc_namespaced_key_reference",
            "vdsnc_role",
            "vdsnc_generation"
        ])
    );
}

#[tokio::test]
async fn vdsnc_registration_validates_reference_fields_before_storage() {
    assert!(
        openapi().await.0["paths"]["/v1/signing-keys/services/vdsnc/register"]["post"].is_object()
    );
    let request = |body: Value| {
        Request::post("/v1/signing-keys/services/vdsnc/register?organization_id=org-a")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    let router = router_with_internal_api_key("test-only".into());
    let valid = router
        .clone()
        .oneshot(request(
            json!({"country_code": "USA", "authority_name": "Bureau"}),
        ))
        .await
        .unwrap();
    assert_eq!(valid.status(), StatusCode::SERVICE_UNAVAILABLE);
    for body in [
        json!({"country_code": "U$", "authority_name": "Bureau"}),
        json!({"country_code": "USA", "authority_name": "Bureau", "role": "../dsc"}),
        json!({"country_code": "USA", "authority_name": "Bureau", "generation": -1}),
        json!({"country_code": "USA", "authority_name": "Bureau", "key_reference": "bad\nkey"}),
        json!({"country_code": "USA", "authority_name": "Bureau", "private_key": "forged"}),
    ] {
        let response = router.clone().oneshot(request(body)).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }
}

#[test]
fn resolver_projects_aws_and_gcp_public_key_envelopes() {
    for provider in ["aws", "gcp"] {
        let mut response = json!({
            "provider": provider,
            "public_jwk": {"kty": "EC", "crv": "P-256", "x": "AQ", "y": "AQ"}
        });
        if provider == "aws" {
            response["key_usage"] = json!("SIGN_VERIFY");
            response["signing_algorithms"] = json!(["ECDSA_SHA_256"]);
        } else {
            response["algorithm"] = json!("EC_SIGN_P256_SHA256");
        }
        assert!(discovered_key_matches_algorithm(&response, "ES256").unwrap());
        assert!(!discovered_key_matches_algorithm(&response, "ES384").unwrap());
        assert!(discovered_key_matches_algorithm(
            &json!({
                "public_jwk": {"kty": "EC", "crv": "P-256", "alg": "ES384"}
            }),
            "ES256"
        )
        .is_ok_and(|compatible| !compatible));
    }
    assert!(discovered_key_matches_algorithm(&json!({"provider": "aws"}), "ES256").is_err());
}

#[tokio::test]
#[ignore = "requires disposable MARTY_TEST_REDIS_URL"]
async fn publication_discovery_preserves_intervening_config_edit() {
    let redis_url = std::env::var("MARTY_TEST_REDIS_URL").expect("disposable Redis URL");
    let store = RegistryStore::connect(&redis_url).await.unwrap();
    let organization_id = format!("test-publication-{}", uuid::Uuid::new_v4().simple());
    store
        .save(
            &organization_id,
            &json!({"services": [{
                "id": "service-a", "name": "Before", "service_type": "openbao-transit",
                "endpoint": "https://kms.example.test", "key_reference": "signing-key",
                "algorithms": ["ES256"], "key_purposes": ["vc_jwt_issuer"]
            }]}),
        )
        .await
        .unwrap();
    let state = AppState {
        internal_api_key: Arc::from("test-key"),
        service_sign_gateway_key: None,
        issuer_sign_key: None,
        integration_secret_key: None,
        dsc_issue_gateway_key: None,
        csca_issue_gateway_key: None,
        mdoc_certificates: Arc::new(Default::default()),
        beta_csca_issuance_enabled: false,
        registry_store: Some(store.clone()),
        document_store: None,
        csca_lifecycle_store: None,
        profile_store: None,
        dsc_issuance_store: None,
        flow_envelopes: None,
        integration_secret_envelopes: None,
        compatibility: None,
        grant_verifier: None,
        public_domain: None,
    };
    let lease = store
        .acquire_rotation_lease(&organization_id)
        .await
        .unwrap()
        .unwrap();
    let app = router_with_dependencies(
        "test-key".into(),
        Some(store.clone()),
        None,
        None,
        None,
        None,
        None,
    );
    let busy = app
            .oneshot(
                Request::post(format!(
                    "/v1/signing-keys/services/service-a/publish-jwks?organization_id={organization_id}"
                ))
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
    assert_eq!(busy.status(), StatusCode::CONFLICT);
    lease.release().await.unwrap();
    let mut config = store.load(&organization_id).await.unwrap();
    config["services"][0]["name"] = json!("After");
    store.save(&organization_id, &config).await.unwrap();
    let lease = store
        .acquire_rotation_lease(&organization_id)
        .await
        .unwrap()
        .unwrap();
    mark_service_publication_discovered(
        &state,
        &organization_id,
        "service-a",
        &[("jwks", json!(true))],
        &lease,
    )
    .await
    .unwrap();
    lease.release().await.unwrap();
    let final_registry = store.load(&organization_id).await.unwrap();
    assert_eq!(final_registry["services"][0]["name"], "After");
    assert_eq!(
        final_registry["services"][0]["discovered_capabilities"]["jwks"],
        true
    );
    let mut connection = store.connection();
    let _: () = redis::cmd("DEL")
        .arg(registry::storage_key(&organization_id))
        .query_async(&mut connection)
        .await
        .unwrap();
}

#[tokio::test]
async fn service_rotation_behavior_is_frozen_before_public_port() {
    let behavior: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/signing-service-rotation-behavior.json"
    ))
    .unwrap();
    assert_eq!(behavior["method"], "POST");
    assert_eq!(
        behavior["path"],
        "/v1/signing-keys/services/{service_id}/rotate"
    );
    assert_eq!(behavior["request_fields"]["overlap_days"]["default"], 7);
    assert_eq!(
        behavior["request_fields"]["publish_updates"]["default"],
        true
    );
    assert_eq!(
        behavior["provider_rotation"]["success_statuses"],
        json!([200, 204])
    );
    assert_eq!(behavior["concurrent_same_tenant_status"], 409);
    assert_eq!(behavior["ambiguous_provider_failure"]["status"], 503);
    assert_eq!(
        behavior["ambiguous_provider_failure"]["reconcile_required"],
        true
    );
    assert_eq!(
        behavior["ambiguous_provider_failure"]["marker_survives_service_rebind"],
        true
    );
    assert_eq!(
        behavior["internal_reconciliation"]["automated_resolution"],
        "stable_baseline_plus_one_only"
    );
    assert_eq!(behavior["publication_fields"], json!(["jwks", "did"]));
    assert_eq!(behavior["managed_or_read_only_service_status"], 403);
    assert!(
        openapi().await.0["paths"]["/v1/signing-keys/services/{service_id}/rotate"]["post"]
            .is_object()
    );
}

#[tokio::test]
async fn public_config_resolver_discovers_only_existing_algorithm_compatible_keys() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    assert!(openapi().await.0["paths"]["/v1/signing-keys/config/resolve"]["post"].is_object());

    let writes = Arc::new(AtomicUsize::new(0));
    let app = Router::new().route(
            "/v1/transit/keys/{reference}",
            get(|Path(reference): Path<String>| async move {
                if reference != "dsc-ed" {
                    return (StatusCode::NOT_FOUND, Json(json!({}))).into_response();
                }
                (StatusCode::OK, Json(json!({
                    "data": {
                        "latest_version": 1,
                        "type": "ed25519",
                        "keys": {"1": {"name": "ed25519", "public_key": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="}}
                    }
                }))).into_response()
            })
            .post({
                let writes = Arc::clone(&writes);
                move || {
                    let writes = Arc::clone(&writes);
                    async move {
                        writes.fetch_add(1, Ordering::SeqCst);
                        StatusCode::INTERNAL_SERVER_ERROR
                    }
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("local KMS fixture");
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let service = json!({
        "id": "service-a", "service_type": "openbao-transit",
        "endpoint": endpoint, "mount": "transit", "key_reference": "vc-key",
        "key_aliases": ["dsc-ed"], "auth_mode": "token", "auth_reference": "never-echo-this"
    });
    let registry = json!({
        "services": [service], "default_service_id": "service-a",
        "key_reference_purposes": {
            "service-a": {"dsc-ed": ["mdoc_dsc"]}
        }
    });
    let service = &registry["services"][0];
    let (keys, unavailable) =
        resolution_keys(&registry, service, &[], Some("mdoc_dsc"), Some("EdDSA")).await;
    assert!(!unavailable);
    assert_eq!(keys, vec![json!({"id": "dsc-ed", "algorithm": "EdDSA"})]);
    let selected = registry::resolve(ResolveRequest {
        registry: registry.clone(),
        service: Some(service.clone()),
        keys,
        credential_format: None,
        key_purpose: Some("mdoc_dsc".into()),
        algorithm: Some("EdDSA".into()),
    })
    .unwrap();
    assert_eq!(selected.key_reference.as_deref(), Some("dsc-ed"));
    assert!(!public_service_config(service)
        .to_string()
        .contains("never-echo-this"));
    let (wrong_algorithm, unavailable) =
        resolution_keys(&registry, service, &[], Some("mdoc_dsc"), Some("ES256")).await;
    assert!(!unavailable);
    assert!(wrong_algorithm.is_empty());
    let (algorithm_only, unavailable) =
        resolution_keys(&registry, service, &[], None, Some("EdDSA")).await;
    assert!(!unavailable);
    assert_eq!(
        algorithm_only,
        vec![json!({"id": "dsc-ed", "algorithm": "EdDSA"})]
    );
    let selected = registry::resolve(ResolveRequest {
        registry: registry.clone(),
        service: Some(service.clone()),
        keys: algorithm_only,
        credential_format: None,
        key_purpose: None,
        algorithm: Some("EdDSA".into()),
    })
    .unwrap();
    assert_eq!(selected.key_reference.as_deref(), Some("dsc-ed"));
    let (wrong_algorithm_only, unavailable) =
        resolution_keys(&registry, service, &[], None, Some("ES256")).await;
    assert!(!unavailable);
    assert!(wrong_algorithm_only.is_empty());
    assert_eq!(writes.load(Ordering::SeqCst), 0);
    server.abort();
}

#[test]
fn public_config_resolver_hints_only_for_mdoc_formats_and_purposes() {
    let behavior: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/signing-public-config-resolve-behavior.json"
    ))
    .unwrap();
    assert_eq!(behavior["path"], "/v1/signing-keys/config/resolve");
    for purpose in behavior["mdoc_hint_triggers"]["key_purposes"]
        .as_array()
        .unwrap()
    {
        assert!(needs_mdoc_hints(None, purpose.as_str()));
    }
    for format in behavior["mdoc_hint_triggers"]["credential_formats"]
        .as_array()
        .unwrap()
    {
        assert!(needs_mdoc_hints(format.as_str(), None));
    }
    assert!(!needs_mdoc_hints(Some("dc+sd-jwt"), Some("vc_jwt_issuer")));
}

fn identity(purpose: &str, algorithm: &str) -> IssuerIdentityRequest {
    IssuerIdentityRequest {
        organization_id: Some("org-a".into()),
        issuer_did: "did:web:beta.example:orgs:acme".into(),
        key_purpose: purpose.into(),
        credential_format: "SD_JWT_VC".into(),
        algorithm: algorithm.into(),
        key_attestation_policy: None,
        cert_pem: None,
        cert_chain_pem: None,
    }
}

#[test]
fn public_csca_enrollment_derives_custody_from_matching_managed_identity() {
    let input: CscaCertificateEnrollment = serde_json::from_value(json!({
        "organization_id": "org-a",
        "issuer_did": "did:web:beta.example:orgs:acme",
        "credential_format": "MDOC",
        "algorithm": "ES256",
        "certificate_id": "csca-a",
        "cert_pem": "public-certificate",
        "cert_chain_pem": ""
    }))
    .unwrap();
    assert_eq!(input.identity().key_purpose, "csca");
    let profile = json!({
        "id": "profile-a", "key_purpose": "csca",
        "signing_service_id": "managed-openbao-transit",
        "signing_key_reference": "managed-kms-csca-a"
    });
    let resolved = json!({
        "issuer_profile": {"id": "profile-a", "signing_service_id": "managed-openbao-transit", "signing_key_reference": "managed-kms-csca-a"},
        "public_jwk": {"kty": "EC", "crv": "P-256", "x": "public-x", "y": "public-y"}
    });
    let request =
        managed_csca_import(&input, &profile, &resolved, &resolved["public_jwk"]).unwrap();
    assert_eq!(request.key_reference, "managed-kms-csca-a");
    assert_eq!(request.expected_public_jwk, resolved["public_jwk"]);
    assert_eq!(request.metadata, json!({"issuer_did": input.issuer_did}));
    assert!(serde_json::from_value::<CscaCertificateEnrollment>(json!({
        "issuer_did": input.issuer_did, "credential_format": "MDOC",
        "algorithm": "ES256", "certificate_id": "csca-a",
        "cert_pem": "public-certificate", "key_reference": "attacker-key"
    }))
    .is_err());
    assert!(managed_csca_import(
        &input,
        &profile,
        &json!({"issuer_profile": {"id": "profile-b"}, "public_jwk": resolved["public_jwk"]}),
        &resolved["public_jwk"]
    )
    .is_err());
    assert!(managed_csca_import(
            &input,
            &profile,
            &json!({
                "issuer_profile": {"id": "profile-a", "signing_service_id": "managed-openbao-transit", "signing_key_reference": "stale-kms-csca"},
                "public_jwk": resolved["public_jwk"]
            }),
            &resolved["public_jwk"]
        )
        .is_err());
    assert!(managed_csca_import(
        &input,
        &profile,
        &resolved,
        &json!({"kty": "EC", "crv": "P-256", "x": "rotated-x", "y": "rotated-y"})
    )
    .is_err());
}

#[test]
fn passport_csr_request_accepts_only_public_issuer_identity_fields() {
    let behavior: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/passport-certificate-csr-behavior.json"
    ))
    .unwrap();
    let route = behavior["public_route"]["path"].as_str().unwrap();
    assert_eq!(route, "/v1/signing-keys/issuer-identities/certificate-csr");
    let request = json!({
        "organization_id": "org-a", "issuer_did": "did:web:beta.example:orgs:acme",
        "key_purpose": "csca", "credential_format": "MDOC", "algorithm": "ES256",
        "country": "US", "organization": "ElevenID Beta", "common_name": "Pilot CSCA"
    });
    let parsed: IssuerCsrIntent = serde_json::from_value(request.clone()).unwrap();
    assert_eq!(passport_csr_identity(&parsed).key_purpose, "csca");
    let mut with_key = request;
    with_key["key_reference"] = json!("attacker-key");
    assert!(serde_json::from_value::<IssuerCsrIntent>(with_key).is_err());
}

#[tokio::test]
async fn public_csr_route_rejects_caller_custody_before_managed_lookup() {
    let valid = json!({
        "organization_id": "org-a", "issuer_did": "did:web:beta.example:orgs:acme",
        "key_purpose": "csca", "credential_format": "MDOC", "algorithm": "ES256",
        "country": "US", "organization": "ElevenID Beta", "common_name": "Pilot CSCA"
    });
    let request = |body: Value| {
        Request::builder()
            .method("PUT")
            .uri("/v1/signing-keys/issuer-identities/certificate-csr?organization_id=org-a")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    let response = router_with_internal_api_key("test-only".into())
        .oneshot(request(valid.clone()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let mut forbidden = valid;
    forbidden["key_reference"] = json!("caller-selected-key");
    let response = router_with_internal_api_key("test-only".into())
        .oneshot(request(forbidden))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[test]
fn service_certificate_contract_rejects_caller_custody_coordinates() {
    let behavior: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/signing-service-certificate-behavior.json"
    ))
    .unwrap();
    assert_eq!(behavior["routes"].as_array().unwrap().len(), 3);
    let upload = json!({"cert_pem": "public certificate", "cert_chain_pem": "public chain"});
    assert!(serde_json::from_value::<ServiceCertificateRequest>(upload.clone()).is_ok());
    for field in ["key_reference", "private_key", "expected_public_jwk"] {
        let mut forged = upload.clone();
        forged[field] = json!("attacker-selected-key");
        assert!(serde_json::from_value::<ServiceCertificateRequest>(forged).is_err());
    }
    let csr = json!({
        "country": "US", "organization": "ElevenID Beta", "common_name": "Signing Service",
        "key_reference": "registered-service-key", "algorithm": "ES256"
    });
    assert!(serde_json::from_value::<ServiceCsrIntent>(csr.clone()).is_ok());
    let mut forged = csr;
    forged["private_key"] = json!("attacker-key");
    assert!(serde_json::from_value::<ServiceCsrIntent>(forged).is_err());
    assert!(validate_service_scope("org-a", Some("org-b")).is_err());
}

#[test]
fn service_certificate_projection_never_leaks_kms_coordinates() {
    let service = json!({
        "id": "service-a", "name": "Signer", "service_type": "openbao-transit",
        "key_reference": "secret-key-name", "auth_reference": "secret-token",
        "endpoint": "https://private-kms.example", "private_key": "forbidden"
    });
    let certificate = json!({
        "cert_pem": "public certificate", "cert_chain_pem": "public chain",
        "cert_expires_at": "2030-01-01T00:00:00Z"
    });
    let projection = service_certificate_projection(&service, &certificate);
    let serialized = projection.to_string();
    for forbidden in [
        "secret-key-name",
        "secret-token",
        "private-kms",
        "forbidden",
    ] {
        assert!(!serialized.contains(forbidden));
    }
    assert_eq!(projection["cert_pem"], "public certificate");
}

#[test]
fn service_certificate_uses_one_registered_key_without_caller_selection() {
    let fixed = json!({"key_reference": "service-primary", "key_aliases": ["service-secondary"]});
    assert_eq!(
        service_certificate_key_config(&fixed).unwrap()["key_reference"],
        "service-primary"
    );
    let one_alias = json!({"key_reference": "", "key_aliases": ["service-only"]});
    assert_eq!(
        service_certificate_key_config(&one_alias).unwrap()["key_reference"],
        "service-only"
    );
    let ambiguous = json!({"key_reference": "", "key_aliases": ["service-a", "service-b"]});
    assert!(service_certificate_key_config(&ambiguous).is_err());
}

#[test]
fn mdoc_x5c_prefers_override_and_requires_current_kms_public_key() {
    let behavior: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/signing-mdoc-x5c-behavior.json"
    ))
    .unwrap();
    assert_eq!(
        behavior["path"],
        "/v1/signing-keys/services/{service_id}/mdoc-x5c"
    );
    let fixture: Value =
        serde_json::from_str(include_str!("../../tests/fixtures/document_vectors.json")).unwrap();
    let cert = &fixture["certificate"];
    let service = json!({"id": "service-a", "cert_pem": "stale-inline-cert"});
    let overrides = json!({"services": {"service-a": {"cert_pem": cert["cert_pem"]}}});
    let selected = selected_service_certificate(&service, &overrides, "service-a").unwrap();
    assert_eq!(selected["cert_pem"], cert["cert_pem"]);
    let result = checked_service_x5c(selected, &cert["expected_jwk"], "service-a").unwrap();
    assert_eq!(result["x5c"][0], cert["expected_x5c"]);
    assert_eq!(
        result["mdoc_cose_header_hints"],
        json!({"x5chain": true, "x5c_length": 1})
    );
    assert!(result.get("key_reference").is_none());
    let mut wrong_key = cert["expected_jwk"].clone();
    wrong_key["x"] = json!("different-public-key");
    assert_eq!(
        checked_service_x5c(selected, &wrong_key, "service-a")
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    assert_eq!(
        checked_service_x5c(
            &json!({"cert_pem": "not-a-cert"}),
            &cert["expected_jwk"],
            "service-a"
        )
        .unwrap_err()
        .status,
        StatusCode::BAD_GATEWAY
    );
    assert!(selected_service_certificate(
        &json!({"id": "service-a"}),
        &json!({"services": {}}),
        "service-a"
    )
    .is_none());
}

#[test]
fn verify_current_preserves_checks_and_accepts_supported_kms_key_types() {
    let behavior: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/signing-service-verify-current-behavior.json"
    ))
    .unwrap();
    assert_eq!(
        behavior["path"],
        "/v1/signing-keys/services/{service_id}/verify-current"
    );
    let fixture: Value =
        serde_json::from_str(include_str!("../../tests/fixtures/document_vectors.json")).unwrap();
    let p256 = &fixture["certificate"]["expected_jwk"];
    let result = verify_service_key_result(
        "service-a",
        &json!({"algorithms": ["ES256"]}),
        p256,
        "2026-09-26T00:00:00Z".into(),
    );
    assert_eq!(result["key_valid"], true);
    assert_eq!(
        result["checks"],
        json!({
            "key_present": true,
            "required_fields_present": true,
            "algorithm_supported": true,
        })
    );
    assert_eq!(result["verified_at"], "2026-09-26T00:00:00Z");
    assert!(result.get("key_reference").is_none());
    assert!(result.get("public_jwk").is_none());
    let wrong_policy = verify_service_key_result(
        "service-a",
        &json!({"algorithms": ["ES384"]}),
        p256,
        String::new(),
    );
    assert_eq!(wrong_policy["checks"]["algorithm_supported"], false);
    assert_eq!(wrong_policy["key_valid"], false);
    let missing_coordinate = verify_service_key_result(
        "service-a",
        &json!({"algorithms": ["ES256"]}),
        &json!({"kty": "EC", "crv": "P-256", "x": p256["x"]}),
        String::new(),
    );
    assert_eq!(
        missing_coordinate["checks"]["required_fields_present"],
        false
    );
    assert_eq!(missing_coordinate["key_valid"], false);
    for (key, algorithm) in [
        (
            json!({"kty": "EC", "crv": "P-384", "x": "x", "y": "y"}),
            "ES384",
        ),
        (
            json!({"kty": "EC", "crv": "P-521", "x": "x", "y": "y"}),
            "ES512",
        ),
        (
            json!({"kty": "RSA", "n": "n", "e": "AQAB", "alg": "PS256"}),
            "PS256",
        ),
        (json!({"kty": "OKP", "crv": "Ed25519", "x": "x"}), "EdDSA"),
    ] {
        assert_eq!(
            verify_service_key_result(
                "service-a",
                &json!({"algorithms": [algorithm]}),
                &key,
                String::new(),
            )["key_valid"],
            true
        );
    }
}

#[tokio::test]
async fn public_jwks_publication_rejects_caller_key_selection_before_kms_use() {
    let behavior: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/signing-service-publish-jwks-behavior.json"
    ))
    .unwrap();
    assert_eq!(
        behavior["path"],
        "/v1/signing-keys/services/{service_id}/publish-jwks"
    );
    assert!(serde_json::from_value::<PublicServiceJwksPublicationRequest>(json!({})).is_ok());
    assert!(
        serde_json::from_value::<PublicServiceJwksPublicationRequest>(
            json!({"key_reference": "caller-selected"})
        )
        .is_err()
    );
    let forbidden = Request::builder()
        .method("POST")
        .uri("/v1/signing-keys/services/service-a/publish-jwks?organization_id=org-a")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"key_reference":"caller-selected"}"#))
        .unwrap();
    let response = router_with_internal_api_key("test-only".into())
        .oneshot(forbidden)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let empty = Request::builder()
        .method("POST")
        .uri("/v1/signing-keys/services/service-a/publish-jwks?organization_id=org-a")
        .body(Body::empty())
        .unwrap();
    let response = router_with_internal_api_key("test-only".into())
        .oneshot(empty)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn public_did_publication_accepts_only_identity_fields_before_kms_use() {
    let behavior: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/signing-service-publish-did-vm-behavior.json"
    ))
    .unwrap();
    assert_eq!(
        behavior["path"],
        "/v1/signing-keys/services/{service_id}/publish-did-vm"
    );
    let accepted: PublicServiceDidPublicationRequest = serde_json::from_value(json!({
        "did_id": "did:web:issuer.example:orgs:acme",
        "org_slug": "acme",
        "fragment": "service-a-vm"
    }))
    .unwrap();
    assert_eq!(accepted.org_slug.as_deref(), Some("acme"));
    assert!(
        serde_json::from_value::<PublicServiceDidPublicationRequest>(
            json!({"key_reference": "caller-selected"})
        )
        .is_err()
    );
    let forbidden = Request::builder()
        .method("POST")
        .uri("/v1/signing-keys/services/service-a/publish-did-vm?organization_id=org-a")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"key_reference":"caller-selected"}"#))
        .unwrap();
    let response = router_with_internal_api_key("test-only".into())
        .oneshot(forbidden)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[test]
fn certificate_alerts_overlay_service_certificates_without_profile_leakage() {
    let behavior: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/signing-certificate-alerts-behavior.json"
    ))
    .unwrap();
    assert_eq!(
        behavior["path"],
        "/v1/signing-keys/config/certificate-expiry-alerts"
    );
    assert_eq!(behavior["query"]["days_until_expiry_default"], 30);
    let registry = json!({"services": [
        {"id": "service-a", "name": "Signer", "cert_expires_at": "2035-01-01T00:00:00Z"},
        {"id": "service-b", "name": "Other", "cert_expires_at": "2034-01-01T00:00:00Z"}
    ]});
    let overrides = json!({
        "services": {"service-a": {"cert_pem": "public-a", "cert_expires_at": "2026-10-01T00:00:00Z", "key_reference": "must-not-leak"}},
        "profiles": {"profile-a": {"cert_expires_at": "2026-09-27T00:00:00Z"}}
    });
    let services = services_with_certificate_overrides(&registry, &overrides);
    assert_eq!(services.len(), 2);
    assert_eq!(services[0]["cert_expires_at"], "2026-10-01T00:00:00Z");
    assert_eq!(services[1]["cert_expires_at"], "2034-01-01T00:00:00Z");
    assert!(services[0].get("key_reference").is_none());
    let alerts = documents::certificate_alerts(CertificateAlertsRequest {
        services,
        days_until_expiry: 30,
        now: Some("2026-09-26T00:00:00Z".into()),
    })
    .unwrap();
    assert_eq!(alerts.alerts.len(), 1);
    assert_eq!(alerts.alerts[0].service_id.as_deref(), Some("service-a"));
}

#[test]
fn public_jwks_preserves_verification_fields_but_never_returns_custody_fields() {
    let behavior: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/signing-public-jwks-behavior.json"
    ))
    .unwrap();
    assert_eq!(behavior["path"], "/v1/signing-keys/jwks");
    let document = json!({
        "organization_id": "untrusted-stored-org", "updated_at": "2026-09-26T00:00:00Z",
        "auth_reference": "secret-top-level-token",
        "keys": [{
            "kty": "EC", "crv": "P-256", "x": "public-x", "y": "public-y", "kid": "public-id",
            "x5c": ["public-cert"], "service_id": "service-a", "status": "active",
            "key_reference": "internal-key-name", "auth_reference": "secret-token"
        }]
    });
    let projected = public_jwks_document(document.clone(), "org-a").unwrap();
    assert_eq!(projected["keys"][0]["kid"], "public-id");
    assert_eq!(projected["organization_id"], "org-a");
    assert_eq!(projected["keys"][0]["x5c"][0], "public-cert");
    assert!(projected.get("auth_reference").is_none());
    for field in behavior["forbidden_fields"].as_array().unwrap() {
        assert!(projected["keys"][0].get(field.as_str().unwrap()).is_none());
    }
    let mut private = document;
    private["keys"][0]["d"] = json!("private-scalar");
    assert!(public_jwks_document(private, "org-a").is_err());
    assert!(public_jwks_document(json!({"keys": [{}]}), "org-a").is_err());
}

#[test]
fn public_issuer_resolution_contract_rejects_selectors_and_scrubs_public_jwk() {
    let behavior: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/signing-public-issuer-resolution-behavior.json"
    ))
    .unwrap();
    assert_eq!(
        behavior["path"],
        "/v1/signing-keys/issuer-identities/resolve"
    );
    let request = json!({
        "organization_id": "org-a", "issuer_did": "did:web:beta.example:orgs:org-a",
        "key_purpose": "csca", "credential_format": "ICAO_EMRTD", "algorithm": "ES256"
    });
    assert!(serde_json::from_value::<IssuerIdentityRequest>(request.clone()).is_ok());
    for field in behavior["forbidden_request_fields"].as_array().unwrap() {
        let mut forbidden = request.clone();
        forbidden[field.as_str().unwrap()] = json!("caller-selected");
        assert!(serde_json::from_value::<IssuerIdentityRequest>(forbidden).is_err());
    }
    let jwk = json!({
        "kty": "EC", "crv": "P-256", "x": "public-x", "y": "public-y",
        "kid": "internal-key-name", "key_reference": "internal-key-name",
        "auth_reference": "secret-token"
    });
    let public = public_issuer_jwk(&jwk).unwrap();
    assert_eq!(public["x"], "public-x");
    for field in behavior["forbidden_public_jwk_fields"].as_array().unwrap() {
        assert!(public.get(field.as_str().unwrap()).is_none());
    }
    let mut private = jwk;
    private["d"] = json!("private-scalar");
    assert!(public_issuer_jwk(&private).is_err());
    assert!(public_issuer_jwk(&json!({"d": "private-only"})).is_err());
    let profile = json!({
        "signing_service_id": "managed-openbao-transit",
        "signing_key_reference": "cred-issuer-key-a"
    });
    assert_eq!(
        managed_key_binding_sha256("org-a", &profile).as_deref(),
        Some("795e3bc59e96474ffd1791289dd82098a7dfb2655799b7075b45d4359cf45b5c")
    );
    assert_ne!(
        managed_key_binding_sha256("org-b", &profile),
        managed_key_binding_sha256("org-a", &profile)
    );
    assert!(managed_key_binding_sha256("org-a", &json!({})).is_none());
}

#[tokio::test]
async fn public_issuer_resolve_route_rejects_caller_custody_before_lookup() {
    let request = |body: Value| {
        Request::builder()
            .method("POST")
            .uri("/v1/signing-keys/issuer-identities/resolve?organization_id=org-a")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    let valid = json!({
        "organization_id": "org-a", "issuer_did": "did:web:beta.example:orgs:org-a",
        "key_purpose": "csca", "credential_format": "ICAO_EMRTD", "algorithm": "ES256"
    });
    let router = router_with_internal_api_key("test-only".into());
    let unavailable = router
        .clone()
        .oneshot(request(valid.clone()))
        .await
        .unwrap();
    assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
    let mut forged = valid;
    forged["key_reference"] = json!("attacker-selected");
    let rejected = router.oneshot(request(forged)).await.unwrap();
    assert_eq!(rejected.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[test]
fn public_did_preserves_relationships_and_services_without_custody_fields() {
    let behavior: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/signing-public-did-document-behavior.json"
    ))
    .unwrap();
    assert_eq!(behavior["path"], "/v1/signing-keys/did-document");
    let document = json!({
        "id": "did:web:beta.example:orgs:org-a", "controller": "did:web:beta.example:orgs:org-a",
        "verificationMethod": [{
            "id": "did:web:beta.example:orgs:org-a#key-1", "type": "JsonWebKey2020",
            "publicKeyJwk": {"kty": "EC", "crv": "P-256", "x": "public-x", "y": "public-y", "key_reference": "secret-key-name"}
        }],
        "assertionMethod": ["did:web:beta.example:orgs:org-a#key-1"],
        "service": [{"id": "#endpoint", "serviceEndpoint": "https://example.org", "auth_reference": "secret-token"}],
        "key_reference": "secret-key-name"
    });
    let projected = public_did_document(document.clone()).unwrap();
    assert_eq!(
        projected["verificationMethod"][0]["publicKeyJwk"]["x"],
        "public-x"
    );
    assert_eq!(
        projected["assertionMethod"][0],
        "did:web:beta.example:orgs:org-a#key-1"
    );
    assert_eq!(
        projected["service"][0]["serviceEndpoint"],
        "https://example.org"
    );
    for forbidden in ["private-scalar", "secret-key-name", "secret-token"] {
        assert!(!projected.to_string().contains(forbidden));
    }
    let mut private = document;
    private["verificationMethod"][0]["publicKeyJwk"]["d"] = json!("private-scalar");
    assert!(public_did_document(private).is_err());
    assert!(public_did_document(json!({"id": "did:web:beta.example", "verificationMethod": [{"publicKeyJwk": {"d": "private"}}]})).is_err());
}

#[tokio::test]
async fn service_certificate_routes_reject_custody_fields_before_storage() {
    let request = |method: &str, path: &str, body: Value| {
        Request::builder()
            .method(method)
            .uri(format!(
                "/v1/signing-keys/services/service-a/{path}?organization_id=org-a"
            ))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    let router = router_with_internal_api_key("test-only".into());
    let response = router
        .clone()
        .oneshot(request("PUT", "certificate", json!({"cert_pem": "public"})))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let response = router
        .clone()
        .oneshot(request("PUT", "certificate", json!({})))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let response = router
        .clone()
        .oneshot(request(
            "PUT",
            "certificate",
            json!({"cert_pem": "public", "key_reference": "forged"}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let response = router
        .clone()
        .oneshot(request(
            "POST",
            "certificate-csr",
            json!({
                "country": "US", "organization": "Test", "common_name": "Test",
                "key_reference": "service-key", "algorithm": "ES256"
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = router
        .oneshot(request(
            "POST",
            "certificate-csr",
            json!({
                "country": "US", "organization": "Test", "common_name": "Test",
                "key_reference": "service-key", "algorithm": "ES256", "private_key": "forged"
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn public_certificate_alert_route_validates_threshold_before_storage() {
    let router = router_with_internal_api_key("test-only".into());
    let request = |threshold: &str| {
        Request::builder()
                .uri(format!(
                    "/v1/signing-keys/config/certificate-expiry-alerts?organization_id=org-a&days_until_expiry={threshold}"
                ))
                .body(Body::empty())
                .unwrap()
    };
    let response = router.clone().oneshot(request("-1")).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let response = router.oneshot(request("30")).await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[test]
fn public_projection_never_exposes_private_profile_or_kms_coordinates() {
    let projection = identity_projection(&json!({
        "id": "private-profile-id",
        "issuer_did": "did:web:beta.example:orgs:acme",
        "signing_service_id": "private-service-id",
        "signing_key_reference": "private-key-reference",
        "key_purpose": "vc_jwt_issuer",
        "credential_format": "SD_JWT_VC",
        "algorithm": "ES256",
    }));
    assert_eq!(projection["status"], "active");
    for private in ["id", "signing_service_id", "signing_key_reference"] {
        assert!(projection.get(private).is_none());
    }
}

#[test]
fn managed_identity_requires_the_current_provider_public_key() {
    let published = json!({
        "issuer_profile": {},
        "public_jwk": {"kty": "EC", "crv": "P-256", "x": "x-a", "y": "y-a"}
    });
    let current = json!({
        "kty": "EC", "crv": "P-256", "x": "x-a", "y": "y-a", "kid": "private-ref"
    });
    assert!(same_current_managed_key(&published, &current));
    assert!(!same_current_managed_key(
        &published,
        &json!({"kty": "EC", "crv": "P-256", "x": "x-b", "y": "y-a"})
    ));
    assert!(!same_current_managed_key(&json!({}), &current));
}

#[test]
fn managed_key_names_preserve_purpose_isolation_and_algorithm_canonicalization() {
    let issuer = managed_key_reference("org-a", &identity("vc_jwt_issuer", "ES256"));
    let verifier = managed_key_reference("org-a", &identity("oid4vp_request_signing", "ES256"));
    let csca = managed_key_reference("org-a", &identity("csca", "ES256"));
    let dsc = managed_key_reference("org-a", &identity("mdoc_dsc", "ES256"));
    let csca_contract: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/csca-capability-behavior.json"
    ))
    .unwrap();
    assert!(issuer.starts_with("cred-issuer-"));
    assert!(issuer.ends_with("-es256"));
    assert!(verifier.starts_with("oid4vp-verifier-"));
    assert!(csca.starts_with(
        csca_contract["supported_rust_surface"]["signing_keys"]["managed_key_reference_prefix"]
            .as_str()
            .unwrap()
    ));
    assert_ne!(csca, dsc);
    assert_ne!(issuer, verifier);
    assert_eq!(canonical_algorithm("eddsa"), "EdDSA");
}

#[test]
fn managed_profile_reference_must_derive_from_its_tenant_and_purpose() {
    let input = identity("vc_jwt_issuer", "ES256");
    let tuple_reference = managed_key_reference("org-a", &input);
    let mut profile = json!({
        "organization_id": "org-a",
        "issuer_did": input.issuer_did,
        "key_purpose": input.key_purpose,
        "credential_format": input.credential_format,
        "algorithm": input.algorithm
    });
    assert!(registry::managed_profile_key_belongs_to_tenant(
        "org-a",
        &profile,
        &tuple_reference
    ));
    assert!(!registry::managed_profile_key_belongs_to_tenant(
        "org-b",
        &profile,
        &tuple_reference
    ));
    profile["organization_id"] = json!("org-b");
    assert!(!registry::managed_profile_key_belongs_to_tenant(
        "org-b",
        &profile,
        &tuple_reference
    ));

    let tenant_reference =
        managed_key_name("org-a", "issuer", "vc_jwt_issuer", "ES256").expect("tenant-scoped key");
    profile["organization_id"] = json!("org-a");
    assert!(registry::managed_profile_key_belongs_to_tenant(
        "org-a",
        &profile,
        &tenant_reference
    ));
    profile["key_purpose"] = json!("mdoc_dsc");
    assert!(!registry::managed_profile_key_belongs_to_tenant(
        "org-a",
        &profile,
        &tenant_reference
    ));
}

#[test]
fn disposable_passport_key_references_match_root_only_bootstrap() {
    let organization_id = "00000000-0000-0000-0000-000000000001";
    let mut request = identity("csca", "ES256");
    request.organization_id = Some(organization_id.into());
    request.issuer_did = "did:web:localhost:orgs:marty".into();
    request.credential_format = "ICAO_EMRTD".into();
    assert_eq!(
        managed_key_reference(organization_id, &request),
        "cred-dsc-5fc5bffec62456e58552-es256"
    );
    request.key_purpose = "x509_doc_signer".into();
    assert_eq!(
        managed_key_reference(organization_id, &request),
        "cred-dsc-86997e8fa454582d8bb5-es256"
    );
    request.issuer_did = "did:web:localhost%3A29876:orgs:marty".into();
    request.key_purpose = "csca".into();
    assert_eq!(
        managed_key_reference(organization_id, &request),
        "cred-dsc-12003bce3b8a5d59814b-es256"
    );
    request.key_purpose = "x509_doc_signer".into();
    assert_eq!(
        managed_key_reference(organization_id, &request),
        "cred-dsc-22f8cf60394c5f1f88a0-es256"
    );
}

#[test]
fn managed_identity_scope_requires_the_local_path_scoped_did() {
    assert!(local_managed_did(
        Some("localhost:29876"),
        "did:web:localhost%3A29876:orgs:marty"
    ));
    assert!(!local_managed_did(
        Some("localhost:29876"),
        "did:web:localhost%3A29877:orgs:marty"
    ));
    assert!(!local_managed_did(
        Some("localhost:29876"),
        "did:web:localhost:29876:orgs:marty"
    ));
    assert!(local_managed_did(
        Some("beta.example"),
        "did:web:beta.example:orgs:acme"
    ));
    assert!(!local_managed_did(
        Some("beta.example"),
        "did:web:attacker.example:orgs:acme"
    ));
    assert!(validate_identity_scope("org-a", &identity("vc_jwt_issuer", "ES256")).is_ok());
    assert!(validate_identity_scope("org-b", &identity("vc_jwt_issuer", "ES256")).is_err());
}

#[test]
fn public_identity_requests_reject_private_custody_selectors() {
    for private in [
        "issuer_profile_id",
        "signing_service_id",
        "signing_key_reference",
        "private_key_pem",
    ] {
        let mut request = json!({
            "organization_id": "org-a",
            "issuer_did": "did:web:beta.example:orgs:acme",
            "key_purpose": "vc_jwt_issuer",
            "credential_format": "SD_JWT_VC",
            "algorithm": "ES256"
        });
        request[private] = json!("must-not-cross");
        assert!(serde_json::from_value::<IssuerIdentityRequest>(request).is_err());
    }
}

#[test]
fn public_config_preserves_provider_routing_defaults_for_lossless_updates() {
    let state = AppState {
        internal_api_key: Arc::from("test-key"),
        service_sign_gateway_key: None,
        issuer_sign_key: None,
        integration_secret_key: None,
        dsc_issue_gateway_key: None,
        csca_issue_gateway_key: None,
        mdoc_certificates: Arc::new(Default::default()),
        beta_csca_issuance_enabled: false,
        registry_store: None,
        document_store: None,
        csca_lifecycle_store: None,
        profile_store: None,
        dsc_issuance_store: None,
        flow_envelopes: None,
        integration_secret_envelopes: None,
        compatibility: None,
        grant_verifier: None,
        public_domain: Some("beta.example".into()),
    };
    let projected = public_config_document(
        &state,
        json!({
            "services": [],
            "default_service_id": "provider-a",
            "format_defaults": {"dc+sd-jwt": "provider-b"},
            "type_defaults": {"vc_jwt_issuer": "provider-c"},
            "key_reference_purposes": {}
        }),
    );
    assert_eq!(projected["format_defaults"]["dc+sd-jwt"], "provider-b");
    assert_eq!(projected["type_defaults"]["vc_jwt_issuer"], "provider-c");
    assert!(projected["provider_metadata"]["provider"].is_null());
    assert_eq!(projected["provider_metadata"]["status"], "unconfigured");
    assert_eq!(projected["supports_native_key_management"], false);
    let services = json!([{"id":"extension-a","provider":"openbao","service_type":"openbao-transit",
            "discovered_capabilities":{"didcomm_authcrypt":true}}]);
    let unbound = public_config_document(&state, json!({"services":services}));
    assert_eq!(
        unbound["services"][0]["extensions"]["didcomm_authcrypt"]["enabled"],
        false
    );
    let bound = public_config_document(
        &state,
        json!({"services":services,
            "did_operation_bindings":{"did:example:issuer":{"didcomm_authcrypt":{"service_id":"extension-a","key_reference":"private-reference"}}}}),
    );
    assert_eq!(
        bound["services"][0]["extensions"]["didcomm_authcrypt"]["enabled"],
        true
    );
    assert!(bound.get("did_operation_bindings").is_none());
    assert!(!bound.to_string().contains("private-reference"));
    for legacy in [
        "hsm_enabled",
        "hsm_settings",
        "vault_enabled",
        "vault_settings",
    ] {
        assert!(
            projected.get(legacy).is_none(),
            "legacy field {legacy} in public config"
        );
    }
}

#[tokio::test]
async fn public_config_redacts_credentials_without_hiding_service_metadata() {
    let state = AppState {
        internal_api_key: Arc::from("test-key"),
        service_sign_gateway_key: None,
        issuer_sign_key: None,
        integration_secret_key: None,
        dsc_issue_gateway_key: None,
        csca_issue_gateway_key: None,
        mdoc_certificates: Arc::new(Default::default()),
        beta_csca_issuance_enabled: false,
        registry_store: None,
        document_store: None,
        csca_lifecycle_store: None,
        profile_store: None,
        dsc_issuance_store: None,
        flow_envelopes: None,
        integration_secret_envelopes: None,
        compatibility: None,
        grant_verifier: None,
        public_domain: None,
    };
    let revision = format!("\"r-{}\"", uuid::Uuid::new_v4());
    let response = public_config_revision_response(
        &state,
        json!({"services": [{
            "id": "provider-a",
            "provider": "aws",
            "endpoint": "https://kms.example.test",
            "key_reference": "issuer-key",
            "auth_reference": "sensitive-test-token"
        }]}),
        revision.clone(),
    );
    assert_eq!(response.headers()[ETAG], revision.as_str());
    let projected: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(projected["config_revision"], revision);
    assert_eq!(projected["services"][0]["id"], "provider-a");
    assert_eq!(projected["services"][0]["key_reference"], "issuer-key");
    assert_eq!(projected["services"][0]["auth_reference"], "");
    assert_eq!(projected["services"][0]["auth_configured"], true);
    assert!(!projected.to_string().contains("sensitive-test-token"));
    assert_eq!(projected["provider_metadata"]["provider"], "aws");
    assert_eq!(projected["provider_metadata"]["providers"], json!(["aws"]));
    assert_eq!(projected["provider_metadata"]["basis"], "registration");
    assert_eq!(projected["supports_native_key_management"], false);
    assert_eq!(projected["registration_mode"], "external-only");

    let hybrid = public_config_document(
        &state,
        json!({"services": [
            {"id": "provider-a", "provider": "aws"},
            {"id": "managed-openbao-transit", "provider": "openbao", "managed": true}
        ]}),
    );
    assert_eq!(hybrid["provider_metadata"]["provider"], "multiple");
    assert_eq!(
        hybrid["provider_metadata"]["providers"],
        json!(["aws", "openbao"])
    );
    assert_eq!(hybrid["supports_native_key_management"], true);
    assert_eq!(hybrid["registration_mode"], "managed-or-external");
}

#[test]
fn redacted_config_round_trip_preserves_only_unchanged_credential_binding() {
    let existing = json!({"services": [{
        "id": "provider-a",
        "provider": "openbao",
        "service_type": "openbao-transit",
        "endpoint": "https://kms.example.test",
        "region": "",
        "auth_mode": "token",
        "mount": "transit",
        "namespace": "",
        "auth_reference": "sensitive-test-token"
    }]});
    let mut unchanged = json!({"services": [{
        "id": "provider-a",
        "provider": "openbao",
        "service_type": "openbao-transit",
        "endpoint": "https://kms.example.test",
        "region": "",
        "auth_mode": "token",
        "mount": "transit",
        "namespace": "",
        "auth_reference": ""
    }]});
    preserve_unchanged_auth_references(&mut unchanged, &existing);
    assert_eq!(
        unchanged["services"][0]["auth_reference"],
        "sensitive-test-token"
    );

    let mut rebound = unchanged.clone();
    rebound["services"][0]["endpoint"] = json!("https://other.example.test");
    rebound["services"][0]["auth_reference"] = json!("");
    preserve_unchanged_auth_references(&mut rebound, &existing);
    assert_eq!(rebound["services"][0]["auth_reference"], "");

    let mut cleared = unchanged;
    cleared["services"][0]["auth_reference"] = Value::Null;
    preserve_unchanged_auth_references(&mut cleared, &existing);
    assert!(cleared["services"][0]["auth_reference"].is_null());
}

#[test]
fn public_inventory_combines_profile_and_service_key_references_without_custody_data() {
    let registry = json!({
        "services": [{
            "id": "svc-openbao",
            "provider": "openbao",
            "algorithms": ["ES256"],
            "key_reference": "configured-key",
            "auth_reference": "private-token-reference"
        }]
    });
    let profiles = vec![json!({
        "id": "private-profile-id",
        "name": "Issuer identity",
        "signing_service_id": "svc-openbao",
        "signing_key_reference": "issuer-key",
        "key_purpose": "vc_jwt_issuer",
        "algorithm": "ES256",
        "status": "active"
    })];
    let inventory = public_signing_key_inventory(&registry, &profiles);
    assert_eq!(inventory.len(), 2);
    assert!(inventory.iter().any(|key| key["id"] == "issuer-key"));
    assert!(inventory.iter().any(|key| key["id"] == "configured-key"));
    let serialized = serde_json::to_string(&inventory).expect("inventory JSON");
    assert!(!serialized.contains("private-profile-id"));
    assert!(!serialized.contains("private-token-reference"));
}

#[test]
fn public_inventory_uses_verified_algorithm_for_unprofiled_managed_key() {
    let registry = json!({"services": [{
        "id": "managed-openbao-transit", "provider": "openbao",
        "algorithms": ["ES256", "RS256", "EdDSA"],
        "key_reference": "cred-issuer-rsa", "key_aliases": ["cred-issuer-ed"],
        "key_algorithms": {"cred-issuer-rsa": "RS256", "cred-issuer-ed": "EdDSA"}
    }]});
    let inventory = public_signing_key_inventory(&registry, &[]);
    assert_eq!(inventory.len(), 2);
    assert_eq!(
        inventory
            .iter()
            .find(|key| key["id"] == "cred-issuer-rsa")
            .unwrap()["algorithm"],
        "RS256"
    );
    assert_eq!(
        inventory
            .iter()
            .find(|key| key["id"] == "cred-issuer-ed")
            .unwrap()["algorithm"],
        "EdDSA"
    );
}

#[tokio::test]
async fn unavailable_observability_retains_the_released_mip_error_envelope() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/signing-observability-unavailable-behavior.json"
    ))
    .unwrap();
    assert_eq!(
        contract["routes"]["audit_log"]["registered_service_status"],
        501
    );
    assert_eq!(contract["routes"]["compliance_summary"]["status"], 501);
    let response = unavailable_observability_response(
        "key_audit_log_unavailable",
        "Key audit log storage is not available for service 'svc-a'.",
        json!({"organization_id": "org-a", "service_id": "svc-a"}),
    );
    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    assert_eq!(response.headers()["x-mip-version"], "0.5.0");
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["error"], contract["routes"]["audit_log"]["error"]);
    assert_eq!(body["organization_id"], "org-a");
    assert_eq!(body["service_id"], "svc-a");
    assert!(uuid::Uuid::parse_str(body["message_id"].as_str().unwrap()).is_ok());
}

#[test]
fn public_didcomm_key_agreement_contract_keeps_custody_out_of_publication() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/signing-issuer-didcomm-key-agreement-behavior.json"
    ))
    .unwrap();
    assert_eq!(contract["method"], "PUT");
    assert_eq!(contract["published_relationship"], "keyAgreement");
    assert_eq!(contract["published_fragment"], "didcomm-authcrypt-x25519");
    assert_eq!(contract["private_key_material_allowed"], false);
    assert_eq!(
        contract["requires_compatible_registered_signing_service"],
        true
    );
    assert_eq!(contract["kms_key_agreement_follow_up"], "DIDCOMM-KMS-001");
    let public_jwk = json!({
        "kty": "OKP", "crv": "X25519",
        "x": URL_SAFE_NO_PAD.encode([7_u8; 32]),
    });
    assert!(documents::validate_x25519_public_jwk(&public_jwk).is_ok());
    let mut private_jwk = public_jwk;
    private_jwk["d"] = json!(URL_SAFE_NO_PAD.encode([8_u8; 32]));
    assert!(documents::validate_x25519_public_jwk(&private_jwk).is_err());
}

#[test]
fn public_service_sign_contract_reuses_the_kms_only_authorized_kernel() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/signing-public-service-sign-behavior.json"
    ))
    .unwrap();
    assert_eq!(contract["method"], "POST");
    assert_eq!(contract["signing_private_key_location"], "KMS only");
    assert_eq!(contract["public_request_private_key_fields_allowed"], false);
    assert_eq!(contract["empty_or_missing_payload_status"], 422);
    assert_eq!(contract["missing_service_status"], 404);
    assert!(contract["managed_reference_rule"].is_string());
    let tenant = uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL, b"org-a")
        .simple()
        .to_string();
    let tenant_key = format!("cred-issuer-{tenant}-issuer-es256");
    assert!(is_tenant_managed_create_reference("org-a", &tenant_key));
    assert!(!is_tenant_managed_create_reference("org-b", &tenant_key));
    assert!(!is_tenant_managed_create_reference(
        "org-a",
        "cred-issuer-0123456789abcdefabcd-es256"
    ));
    assert!(contract["managed_binding_update_rule"].is_string());
    let service = json!({
        "key_aliases": [tenant_key.clone()],
        "key_algorithms": {(tenant_key.clone()): "ES256"}
    });
    let binding = json!(["vc_jwt_issuer"]);
    let purposes = binding.as_array();
    assert!(managed_alias_allowed(
        &service,
        "org-a",
        &tenant_key,
        purposes,
        Some("vc_jwt_issuer"),
        Some("ES256")
    ));
    assert!(!managed_alias_allowed(
        &service,
        "org-a",
        &tenant_key,
        purposes,
        Some("mdoc_dsc"),
        Some("ES256")
    ));
    assert!(!managed_alias_allowed(
        &service,
        "org-a",
        &tenant_key,
        purposes,
        Some("vc_jwt_issuer"),
        Some("RS256")
    ));
    assert!(!managed_alias_allowed(
        &service,
        "org-b",
        &tenant_key,
        purposes,
        Some("vc_jwt_issuer"),
        Some("ES256")
    ));
    assert!(!managed_alias_allowed(
        &service,
        "org-a",
        &tenant_key,
        None,
        Some("vc_jwt_issuer"),
        Some("ES256")
    ));
}
#[test]
fn explicit_jwt_vc_http_custody_rejects_missing_empty_or_historical_format_capability() {
    for service in [
        json!({}),
        json!({"credential_formats":[]}),
        json!({"credential_formats":["jwt_vc_json"]}),
    ] {
        assert!(!service_supports_issuer_value(
            &service,
            "credential_formats",
            "application/vc+jwt"
        ));
    }
    assert!(service_supports_issuer_value(
        &json!({"credential_formats":["application/vc+jwt"]}),
        "credential_formats",
        "application/vc+jwt"
    ));
    assert!(service_supports_issuer_value(
        &json!({}),
        "credential_formats",
        "jwt_vc_json"
    ));
    assert!(service_supports_issuer_value(
        &json!({"credential_formats":[]}),
        "credential_formats",
        "jwt_vc_json"
    ));
}
