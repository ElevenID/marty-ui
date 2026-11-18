use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use marty_signing_keys::{http::router_with_dependencies, registry::RegistryStore};
use serde_json::{json, Value};
use tower::ServiceExt;

use super::disposable_backends;

fn app(registry: Option<RegistryStore>) -> Router {
    router_with_dependencies(
        "test-internal-key".into(),
        registry,
        None,
        None,
        None,
        None,
        Some("issuer.example:8443".into()),
    )
}

async fn get(app: Router, org: &str) -> (StatusCode, Value) {
    let response = app
        .oneshot(
            Request::get(format!(
                "/v1/signing-keys/issuer-identities/capabilities?organization_id={org}"
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    if status == StatusCode::OK {
        assert_eq!(response.headers()["cache-control"], "no-store");
    }
    let body =
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap();
    (status, body)
}

#[tokio::test]
async fn issuer_capabilities_fail_closed_when_registry_is_unavailable() {
    let (status, body) = get(app(None), "org-a").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(body.get("creation_options").is_none());
    assert_eq!(get(app(None), "").await.0, StatusCode::UNPROCESSABLE_ENTITY);
    let response = app(None).oneshot(Request::get("/v1/signing-keys/issuer-identities/capabilities?organization_id=org-a&signing_service_id=forbidden")
        .body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn issuer_creation_rejects_incompatible_catalog_tuples_before_any_side_effect() {
    for (purpose, format, algorithm) in [
        ("vc_jwt_issuer", "MDOC", "ES256"),
        ("mdoc_dsc", "MDOC", "RS256"),
        ("unknown", "SD_JWT_VC", "ES256"),
    ] {
        let response = app(None).oneshot(Request::post("/v1/signing-keys/issuer-identities?organization_id=org-a")
            .header("content-type", "application/json")
            .body(Body::from(json!({"issuer_did":"did:web:issuer.example%3A8443:orgs:a", "key_purpose":purpose,
                "credential_format":format, "algorithm":algorithm}).to_string())).unwrap()).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let value: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert!(value["detail"].as_str().unwrap().contains("incompatible"));
    }
}

#[tokio::test]
#[ignore = "requires a sentinel-guarded disposable MARTY_TEST_REDIS_URL"]
async fn issuer_capabilities_follow_live_tenant_registry_updates() {
    let redis_url = disposable_backends::disposable_redis_url().await;
    let store = RegistryStore::connect(&redis_url).await.unwrap();
    let org = format!("capabilities-{}", uuid::Uuid::new_v4().simple());
    let other_org = format!("capabilities-other-{}", uuid::Uuid::new_v4().simple());
    let mut registry = json!({"default_service_id":"private-service", "services":[{
        "id":"private-service", "service_type":"aws-kms", "auth_mode":"iam_role", "region":"us-east-1",
        "auth_reference":"", "key_reference":"arn:aws:kms:us-east-1:000000000000:key/private-reference", "algorithms":["ES256"],
        "credential_formats":["dc+sd-jwt"], "key_purposes":["vc_jwt_issuer"]
    }]});
    // Use the private persistence key to seed configuration, like the other
    // native storage tests. This disposable fixture has no real credentials.
    let mut connection = store.connection();
    let _: () = redis::cmd("SET")
        .arg(marty_signing_keys::registry::storage_key(&org))
        .arg(registry.to_string())
        .query_async(&mut connection)
        .await
        .unwrap();
    let router = app(Some(store.clone()));
    assert_eq!(
        store.load(&org).await.expect("valid fixture registry")["services"][0]["id"],
        "private-service"
    );
    let (status, body) = get(router.clone(), &org).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        json!({"organization_id":org, "managed_issuer_did_prefix":"did:web:issuer.example%3A8443:orgs:", "basis":"configuration", "creation_options":[{"key_purpose":"vc_jwt_issuer", "credential_format":"SD_JWT_VC", "algorithm":"ES256"}]})
    );
    assert!(!body.to_string().contains("private-"));
    let (_, other) = get(router.clone(), &other_org).await;
    assert_eq!(other["organization_id"], other_org);
    assert_eq!(other["creation_options"], json!([]));
    registry["services"][0]["algorithms"] = json!(["RS256"]);
    let _: () = redis::cmd("SET")
        .arg(marty_signing_keys::registry::storage_key(&org))
        .arg(registry.to_string())
        .query_async(&mut connection)
        .await
        .unwrap();
    let (_, changed) = get(router.clone(), &org).await;
    assert_eq!(
        changed["creation_options"],
        json!([{"key_purpose":"vc_jwt_issuer", "credential_format":"SD_JWT_VC", "algorithm":"RS256"}])
    );
    registry["services"][0]["auth_reference"] = json!("private-invalid-plaintext");
    let _: () = redis::cmd("SET")
        .arg(marty_signing_keys::registry::storage_key(&org))
        .arg(registry.to_string())
        .query_async(&mut connection)
        .await
        .unwrap();
    let (status, rejected) = get(router, &org).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(!rejected.to_string().contains("private-invalid-plaintext"));
    let _: () = redis::cmd("DEL")
        .arg(marty_signing_keys::registry::storage_key(&org))
        .query_async(&mut connection)
        .await
        .unwrap();
}
