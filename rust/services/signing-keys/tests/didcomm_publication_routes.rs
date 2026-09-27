use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use marty_signing_keys::{
    documents::{did_storage_key, slug_storage_key, DocumentStore, LoadDidRequest},
    profiles::{storage_key as profile_storage_key, ProfileStore},
    registry::{storage_key as registry_storage_key, RegistryStore},
};
use redis::AsyncCommands;
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

async fn publish(app: &Router, organization_id: &str, payload: Value) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::put(format!(
                "/v1/signing-keys/issuer-identities/didcomm-key-agreement?organization_id={organization_id}"
            ))
            .header("content-type", "application/json")
            .body(Body::from(payload.to_string()))
            .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body =
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap();
    (status, body)
}

#[tokio::test]
#[ignore = "requires disposable loopback MARTY_TEST_REDIS_URL and nonce sentinel"]
async fn public_didcomm_publication_is_tenant_scoped_and_public_only() {
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
    assert!(nonce.len() >= 16, "disposable Redis sentinel is too short");
    let client = redis::Client::open(redis_url.as_str()).expect("disposable Redis client");
    let mut sentinel_connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("disposable Redis connection");
    let observed: Option<String> = sentinel_connection
        .get("marty:tests:disposable-guard")
        .await
        .expect("disposable Redis sentinel read");
    assert_eq!(observed.as_deref(), Some(nonce.as_str()));
    let organization_id = format!("rust-didcomm-publication-{}", Uuid::new_v4().simple());
    let other_organization_id = format!("rust-didcomm-other-{}", Uuid::new_v4().simple());
    let slug = format!("didcomm-{}", Uuid::new_v4().simple());
    let issuer_did = format!("did:web:issuer.example:orgs:{slug}");
    let registry = RegistryStore::connect(&redis_url).await.unwrap();
    let profiles = ProfileStore::from_connection(registry.connection());
    let documents = DocumentStore::from_connection(registry.connection());
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/issuer_profile_vectors.json")).unwrap();
    let mut profile = fixture["normalize"]["expected"].clone();
    profile["organization_id"] = json!(organization_id);
    profile["issuer_did"] = json!(issuer_did);
    profiles
        .put(&organization_id, "ip-vector", profile.clone())
        .await
        .unwrap();
    let app = marty_signing_keys::http::router_with_dependencies(
        "test-internal-key".to_string(),
        Some(registry.clone()),
        Some(documents.clone()),
        None,
        Some(profiles.clone()),
        None,
        Some("issuer.example".to_string()),
    );
    let public_jwk = json!({"kty":"OKP", "crv":"X25519", "x":URL_SAFE_NO_PAD.encode([7_u8; 32])});
    let request = json!({
        "organization_id":organization_id,
        "issuer_did":issuer_did,
        "key_purpose":"vc_jwt_issuer",
        "credential_format":"SD_JWT_VC",
        "algorithm":"ES256",
        "public_jwk":public_jwk,
    });

    let (missing_service, missing_detail) = publish(&app, &organization_id, request.clone()).await;
    assert_eq!(missing_service, StatusCode::NOT_FOUND);
    assert!(!missing_detail.to_string().contains("svc-a"));
    assert!(!missing_detail.to_string().contains("key-a"));
    assert!(
        !documents
            .load_did(
                &organization_id,
                LoadDidRequest {
                    did_id: Some(issuer_did.clone()),
                    fallback_did: None,
                },
            )
            .await
            .unwrap()
            .found
    );
    let service = json!({
        "id": "svc-a", "name": "Test issuer service", "service_type": "aws-kms",
        "provider": "aws", "auth_mode": "iam_role", "key_reference": "key-a",
        "credential_formats": ["dc+sd-jwt"], "key_purposes": ["vc_jwt_issuer"],
        "algorithms": ["ES256"]
    });
    registry
        .save(&organization_id, &json!({"services": [service.clone()]}))
        .await
        .unwrap();

    let (status, response) = publish(&app, &organization_id, request.clone()).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["issuer_did"], issuer_did);
    let method_id = format!("{issuer_did}#didcomm-authcrypt-x25519");
    assert_eq!(response["key_agreement_method_id"], method_id);
    assert_eq!(response.as_object().unwrap().len(), 2);
    let stored = documents
        .load_did(
            &organization_id,
            LoadDidRequest {
                did_id: Some(issuer_did.clone()),
                fallback_did: None,
            },
        )
        .await
        .unwrap();
    assert!(stored.found);
    assert_eq!(stored.document["keyAgreement"], json!([method_id]));
    assert_eq!(
        stored.document["verificationMethod"][0]["publicKeyJwk"],
        public_jwk
    );
    assert!(!stored.document.to_string().contains("\"d\""));

    let mut incompatible_service = service.clone();
    incompatible_service["algorithms"] = json!(["ES384"]);
    registry
        .save(
            &organization_id,
            &json!({"services": [incompatible_service]}),
        )
        .await
        .unwrap();
    assert_eq!(
        publish(&app, &organization_id, request.clone()).await.0,
        StatusCode::NOT_FOUND
    );
    incompatible_service = service.clone();
    incompatible_service["credential_formats"] = json!(["mso_mdoc"]);
    registry
        .save(
            &organization_id,
            &json!({"services": [incompatible_service]}),
        )
        .await
        .unwrap();
    assert_eq!(
        publish(&app, &organization_id, request.clone()).await.0,
        StatusCode::NOT_FOUND
    );
    registry
        .save(
            &organization_id,
            &json!({
                "services": [service.clone()],
                "key_reference_purposes": {"svc-a": {"key-a": ["lti_tool_signing"]}}
            }),
        )
        .await
        .unwrap();
    let (reserved_status, reserved_detail) = publish(&app, &organization_id, request.clone()).await;
    assert_eq!(reserved_status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(!reserved_detail.to_string().contains("svc-a"));
    assert!(!reserved_detail.to_string().contains("key-a"));
    registry
        .save(&organization_id, &json!({"services": [service]}))
        .await
        .unwrap();

    let mut private_jwk = request.clone();
    private_jwk["public_jwk"]["d"] = json!(URL_SAFE_NO_PAD.encode([8_u8; 32]));
    assert_eq!(
        publish(&app, &organization_id, private_jwk).await.0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let mut noncanonical_jwk = request.clone();
    noncanonical_jwk["public_jwk"]["x"] = json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
    assert_eq!(
        publish(&app, &organization_id, noncanonical_jwk).await.0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let mut mismatched_scope = request.clone();
    mismatched_scope["organization_id"] = json!(other_organization_id);
    assert_eq!(
        publish(&app, &organization_id, mismatched_scope).await.0,
        StatusCode::FORBIDDEN
    );
    let mut absent = request.clone();
    absent["organization_id"] = json!(other_organization_id);
    assert_eq!(
        publish(&app, &other_organization_id, absent).await.0,
        StatusCode::NOT_FOUND
    );
    let foreign_did = format!("did:web:other.example:orgs:{slug}");
    let mut foreign_profile = profile.clone();
    foreign_profile["id"] = json!("ip-foreign");
    foreign_profile["issuer_did"] = json!(foreign_did);
    profiles
        .put(&organization_id, "ip-foreign", foreign_profile)
        .await
        .unwrap();
    let mut nonlocal = request.clone();
    nonlocal["issuer_did"] = json!(foreign_did);
    assert_eq!(
        publish(&app, &organization_id, nonlocal).await.0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let mut duplicate = profile;
    duplicate["id"] = json!("ip-duplicate");
    profiles
        .put(&organization_id, "ip-duplicate", duplicate)
        .await
        .unwrap();
    assert_eq!(
        publish(&app, &organization_id, request).await.0,
        StatusCode::CONFLICT
    );

    let mut connection = registry.connection();
    for key in [
        profile_storage_key(&organization_id),
        registry_storage_key(&organization_id),
        did_storage_key(&organization_id, Some(&issuer_did)),
        did_storage_key(&organization_id, None),
        slug_storage_key(&slug),
    ] {
        let _: () = connection.del(key).await.unwrap();
    }
}
