use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use marty_signing_keys::registry::{storage_key, RegistryStore};
use redis::AsyncCommands;
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

async fn body(response: axum::response::Response) -> Value {
    serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap()
}

#[tokio::test]
#[ignore = "requires MARTY_TEST_REDIS_URL"]
async fn public_observability_errors_preserve_status_scope_and_mip_fields() {
    let redis_url = std::env::var("MARTY_TEST_REDIS_URL").expect("disposable Redis URL");
    let organization_id = format!("rust-signing-observability-{}", Uuid::new_v4().simple());
    let other_organization_id = format!("rust-signing-other-{}", Uuid::new_v4().simple());
    let registry = RegistryStore::connect(&redis_url).await.unwrap();
    registry
        .save(
            &organization_id,
            &json!({
                "services": [{
                    "id": "svc-mdoc", "name": "Test DSC", "service_type": "aws-kms",
                    "provider": "aws", "auth_mode": "iam_role",
                    "key_reference": "arn:aws:kms:us-east-1:000000000000:key/test-only",
                    "algorithms": ["ES512"], "key_purposes": ["mdoc_dsc"]
                }],
                "default_service_id": "svc-mdoc"
            }),
        )
        .await
        .unwrap();
    let app = marty_signing_keys::http::router_with_dependencies(
        "test-internal-key".to_string(),
        Some(registry.clone()),
        None,
        None,
        None,
        None,
        None,
    );
    let audit = format!(
        "/v1/signing-keys/services/svc-mdoc/audit-log?organization_id={organization_id}&limit=1&offset=0"
    );
    let response = app
        .clone()
        .oneshot(Request::get(&audit).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    assert_eq!(response.headers()["x-mip-version"], "0.5.0");
    let unavailable = body(response).await;
    assert_eq!(unavailable["error"], "key_audit_log_unavailable");
    assert_eq!(unavailable["organization_id"], organization_id);
    assert_eq!(unavailable["service_id"], "svc-mdoc");
    assert!(Uuid::parse_str(unavailable["message_id"].as_str().unwrap()).is_ok());

    let missing = app
        .clone()
        .oneshot(
            Request::get(format!(
                "/v1/signing-keys/services/missing/audit-log?organization_id={organization_id}"
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        body(missing).await["detail"],
        "Service 'missing' not found."
    );

    let other = app
        .clone()
        .oneshot(
            Request::get(format!(
                "/v1/signing-keys/services/svc-mdoc/audit-log?organization_id={other_organization_id}"
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(other.status(), StatusCode::NOT_FOUND);

    let bad_limit = app
        .clone()
        .oneshot(
            Request::get(format!(
                "/v1/signing-keys/services/svc-mdoc/audit-log?organization_id={organization_id}&limit=0"
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad_limit.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let summary = app
        .oneshot(
            Request::get(format!(
                "/v1/signing-keys/compliance/keys-summary?organization_id={organization_id}"
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(summary.status(), StatusCode::NOT_IMPLEMENTED);
    let summary = body(summary).await;
    assert_eq!(summary["error"], "key_compliance_summary_unavailable");
    assert_eq!(summary["organization_id"], organization_id);

    let mut connection = registry.connection();
    let _: () = connection.del(storage_key(&organization_id)).await.unwrap();
}
