//! Managed issuer profile route against disposable HTTPS OpenBao and Redis.
//! Only a public CA and scoped tokens enter this test process.

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use marty_signing_keys::{
    documents::{DocumentStore, LoadDidRequest},
    http::router_with_all_keys,
    kms::{read_managed_openbao, ProviderRequest},
    profiles::ProfileStore,
    registry::RegistryStore,
};
use redis::AsyncCommands;
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

struct MountedTokenGuard(String);

impl MountedTokenGuard {
    fn replace(token: &str) -> Self {
        let previous = std::env::var("BAO_TOKEN").expect("mounted OpenBao token");
        std::env::set_var("BAO_TOKEN", token);
        Self(previous)
    }
}

impl Drop for MountedTokenGuard {
    fn drop(&mut self) {
        std::env::set_var("BAO_TOKEN", &self.0);
    }
}

async fn route(app: &Router, path: &str, payload: Value) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::post(path)
                .header("content-type", "application/json")
                .header("x-api-key", "test-internal-key")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
        .unwrap_or(Value::Null);
    (status, body)
}

#[tokio::test]
#[ignore = "requires guarded disposable HTTPS OpenBao and Redis"]
async fn issuer_profile_uses_non_exportable_remote_key_and_public_only_routes() {
    let endpoint = std::env::var("MARTY_TEST_OPENBAO_URL").expect("OpenBao URL");
    let parsed = reqwest::Url::parse(&endpoint).expect("OpenBao origin");
    assert_eq!(parsed.scheme(), "https");
    assert_eq!(parsed.host_str(), Some("127.0.0.1"));
    assert_eq!(std::env::var("BAO_ADDR").as_deref(), Ok(endpoint.as_str()));
    let ca_file = std::env::var("BAO_CACERT").expect("public OpenBao CA");
    let ca = reqwest::Certificate::from_pem(&std::fs::read(ca_file).unwrap()).unwrap();
    let root = std::env::var("MARTY_TEST_OPENBAO_ROOT_TOKEN").expect("guard token");
    let token = std::env::var("BAO_TOKEN").expect("scoped token");
    assert_ne!(root, token);
    let nonce = std::env::var("MARTY_TEST_OPENBAO_DISPOSABLE_NONCE").expect("guard nonce");
    let root_client = reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .tls_certs_only([ca])
        .build()
        .unwrap();
    let guard = root_client
        .get(format!(
            "{endpoint}/v1/secret/data/marty-test-disposable-guard"
        ))
        .header("X-Vault-Token", &root)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(guard["data"]["data"]["nonce"], nonce);

    let redis_url = std::env::var("MARTY_TEST_REDIS_URL").expect("disposable Redis");
    let redis_parsed = reqwest::Url::parse(&redis_url).unwrap();
    assert_eq!(redis_parsed.host_str(), Some("127.0.0.1"));
    let mut redis = redis::Client::open(redis_url.as_str())
        .unwrap()
        .get_multiplexed_async_connection()
        .await
        .unwrap();
    let observed: Option<String> = redis.get("marty:tests:disposable-guard").await.unwrap();
    assert_eq!(
        observed.as_deref(),
        std::env::var("MARTY_TEST_REDIS_DISPOSABLE_NONCE")
            .ok()
            .as_deref()
    );

    let organization_id = format!("real-issuer-{}", Uuid::new_v4().simple());
    let did = format!("did:web:issuer.example:orgs:{organization_id}");
    let registry = RegistryStore::connect(&redis_url)
        .await
        .unwrap()
        .with_managed_openbao(Some(endpoint.clone()));
    let profiles = ProfileStore::from_connection(registry.connection());
    let documents = DocumentStore::from_connection(registry.connection());
    let app = router_with_all_keys(
        "test-internal-key".into(),
        Some("test-service-sign-gateway-key-000000".into()),
        Some("test-issuer-sign-key-000000000000000".into()),
        None,
        None,
        None,
        false,
        Some(registry.clone()),
        Some(documents.clone()),
        None,
        Some(profiles.clone()),
        None,
        Some("issuer.example".into()),
    );
    let request = json!({
        "organization_id": organization_id, "issuer_did": did,
        "key_purpose": "vc_jwt_issuer", "credential_format": "SD_JWT_VC",
        "algorithm": "EdDSA",
    });
    let path = format!("/v1/signing-keys/issuer-identities?organization_id={organization_id}");
    let (status, created) = route(&app, &path, request.clone()).await;
    assert_eq!(status, StatusCode::OK, "{created}");
    assert_eq!(created["created"], true);
    let stored = profiles.list(&organization_id).await.unwrap();
    let reference = stored["profiles"][0]["signing_key_reference"]
        .as_str()
        .unwrap();
    assert!(reference.starts_with("cred-issuer-"));
    let metadata = read_managed_openbao(ProviderRequest {
        service_config: json!({
            "id":"managed-openbao-transit", "service_type":"openbao-transit",
            "auth_mode":"service_token", "endpoint":endpoint,
            "mount":"transit", "key_reference":reference, "algorithm":"EdDSA",
        }),
    })
    .await
    .unwrap();
    assert_eq!(metadata["exportable"], false);
    assert_eq!(metadata["allow_plaintext_backup"], false);
    assert!(metadata["public_jwk"].get("d").is_none());

    let (status, resolved) = route(
        &app,
        &format!("/v1/signing-keys/issuer-identities/resolve?organization_id={organization_id}"),
        request,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resolved}");
    assert_eq!(resolved["public_jwk"]["crv"], metadata["public_jwk"]["crv"]);
    assert_eq!(resolved["public_jwk"]["x"], metadata["public_jwk"]["x"]);
    assert!(resolved["public_jwk"].get("d").is_none());
    assert!(
        documents
            .load_did(
                &organization_id,
                LoadDidRequest {
                    did_id: Some(did),
                    fallback_did: None,
                }
            )
            .await
            .unwrap()
            .found
    );
    for public in [&created, &resolved] {
        let serialized = public.to_string();
        for secret in [&endpoint, &token, &root, reference] {
            assert!(
                !serialized.contains(secret),
                "public route leaked KMS custody metadata"
            );
        }
    }

    // A token with an explicit Transit deny must not create a profile.
    let deny_policy = format!("deny-issuer-{}", Uuid::new_v4().simple());
    root_client
        .put(format!("{endpoint}/v1/sys/policies/acl/{deny_policy}"))
        .header("X-Vault-Token", &root)
        .json(&json!({"policy": "path \"transit/*\" { capabilities = [\"deny\"] }"}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let denied_token: Value = root_client
        .post(format!("{endpoint}/v1/auth/token/create"))
        .header("X-Vault-Token", &root)
        .json(&json!({"policies": [deny_policy], "no_default_policy": true, "ttl": "5m"}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let denied_token = denied_token["auth"]["client_token"].as_str().unwrap();
    let denied_org = format!("denied-issuer-{}", Uuid::new_v4().simple());
    let denied_request = json!({
        "organization_id": denied_org,
        "issuer_did": format!("did:web:issuer.example:orgs:{denied_org}"),
        "key_purpose": "vc_jwt_issuer", "credential_format": "SD_JWT_VC",
        "algorithm": "EdDSA",
    });
    {
        let _mounted = MountedTokenGuard::replace(denied_token);
        let (status, response) = route(
            &app,
            &format!("/v1/signing-keys/issuer-identities?organization_id={denied_org}"),
            denied_request,
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{response}");
    }
    assert!(profiles.list(&denied_org).await.unwrap()["profiles"]
        .as_array()
        .unwrap()
        .is_empty());

    // A pre-existing non-exportable key remains usable with read-only Transit access.
    let read_org = format!("readonly-issuer-{}", Uuid::new_v4().simple());
    let read_did = format!("did:web:issuer.example:orgs:{read_org}");
    let selector = format!("{read_org}|{read_did}|vc_jwt_issuer|SD_JWT_VC|EdDSA");
    let id = Uuid::new_v5(&Uuid::NAMESPACE_URL, selector.as_bytes())
        .simple()
        .to_string();
    let read_reference = format!("cred-issuer-{}-eddsa", &id[..20]);
    root_client
        .post(format!("{endpoint}/v1/transit/keys/{read_reference}"))
        .header("X-Vault-Token", &root)
        .json(&json!({"type":"ed25519", "exportable":false, "allow_plaintext_backup":false}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let read_token: Value = root_client
        .post(format!("{endpoint}/v1/auth/token/create"))
        .header("X-Vault-Token", &root)
        .json(&json!({"policies": ["credential-service"], "no_default_policy": true, "ttl": "5m"}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let read_token = read_token["auth"]["client_token"].as_str().unwrap();
    let forbidden_create = root_client
        .post(format!(
            "{endpoint}/v1/transit/keys/cred-issuer-readonly-foreign"
        ))
        .header("X-Vault-Token", read_token)
        .json(&json!({"type":"ed25519"}))
        .send()
        .await
        .unwrap();
    assert_eq!(forbidden_create.status(), reqwest::StatusCode::FORBIDDEN);
    let read_request = json!({
        "organization_id": read_org, "issuer_did": read_did,
        "key_purpose": "vc_jwt_issuer", "credential_format": "SD_JWT_VC",
        "algorithm": "EdDSA",
    });
    let unprovisioned_org = format!("unprovisioned-issuer-{}", Uuid::new_v4().simple());
    let unprovisioned_request = json!({
        "organization_id": unprovisioned_org,
        "issuer_did": format!("did:web:issuer.example:orgs:{unprovisioned_org}"),
        "key_purpose": "vc_jwt_issuer", "credential_format": "SD_JWT_VC",
        "algorithm": "EdDSA",
    });
    {
        let _mounted = MountedTokenGuard::replace(read_token);
        let (status, response) = route(
            &app,
            &format!("/v1/signing-keys/issuer-identities?organization_id={read_org}"),
            read_request.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{response}");
        let (status, resolved) = route(
            &app,
            &format!("/v1/signing-keys/issuer-identities/resolve?organization_id={read_org}"),
            read_request,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{resolved}");
        assert_eq!(resolved["public_jwk"]["crv"], "Ed25519");
        let (status, failed) = route(
            &app,
            &format!("/v1/signing-keys/issuer-identities?organization_id={unprovisioned_org}"),
            unprovisioned_request,
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{failed}");
    }
    assert!(profiles.list(&unprovisioned_org).await.unwrap()["profiles"]
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(
        profiles.list(&read_org).await.unwrap()["profiles"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}
