use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use marty_device_registration::{
    challenge::{ChallengeRepository, MemoryChallengeRepository},
    control_plane::AllowMembership,
    http::{router, HttpState},
    CreateRegistration, DeviceError, DeviceService, MemoryDeviceRepository, Platform,
    UpdateRegistration,
};
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;

fn service() -> DeviceService {
    let repository = Arc::new(MemoryDeviceRepository::default());
    let challenges: Arc<dyn ChallengeRepository> = Arc::new(MemoryChallengeRepository::new(300));
    DeviceService::new(repository, challenges, 300).unwrap()
}

fn registration() -> CreateRegistration {
    CreateRegistration {
        user_id: None,
        organization_id: Some("org-1".into()),
        device_id: "device-1".into(),
        platform: Platform::Web,
        fcm_token: "push-token".into(),
        app_version: Some("1.0".into()),
        os_version: None,
        device_model: None,
        preferences: Default::default(),
        public_key_der: None,
        public_key_kid: None,
        key_valid_from: None,
        key_valid_until: None,
        is_active: true,
    }
}

#[test]
fn contract_retires_device_private_key_challenge() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/device-registration-service-behavior.json"
    ))
    .unwrap();
    assert_eq!(contract["routes"].as_array().unwrap().len(), 5);
    assert!(contract["challenge"].is_null());
    assert!(contract["invariants"]
        .as_array()
        .unwrap()
        .iter()
        .any(|value| { value.as_str().unwrap_or_default().contains("remote KMS") }));
}

#[tokio::test]
async fn keyless_registration_metadata_and_deactivation_preserve_identity() {
    let service = service();
    let first = service
        .register("user-1", registration(), Default::default())
        .await
        .unwrap();
    assert!(first.is_active);
    assert!(first.public_key_der.is_none());
    let changed = service
        .update(
            "user-1",
            &first.id,
            UpdateRegistration {
                fcm_token: Some("next-push-token".into()),
                ..Default::default()
            },
            Default::default(),
        )
        .await
        .unwrap();
    assert_eq!(changed.id, first.id);
    assert_eq!(changed.fcm_token, "next-push-token");
    service.delete("user-1", &first.id).await.unwrap();
    service.delete("user-1", &first.id).await.unwrap();
    assert!(!service.get("user-1", &first.id).await.unwrap().is_active);
    assert!(matches!(
        service
            .update(
                "user-1",
                &first.id,
                UpdateRegistration {
                    is_active: Some(true),
                    ..Default::default()
                },
                Default::default()
            )
            .await,
        Err(DeviceError::Conflict(_))
    ));
    let second = service
        .register("user-1", registration(), Default::default())
        .await
        .unwrap();
    assert_ne!(first.id, second.id);
    assert!(matches!(
        service.get("other-user", &second.id).await,
        Err(DeviceError::NotFound(_))
    ));
}

#[tokio::test]
async fn device_held_key_inputs_are_rejected_without_generating_private_keys() {
    let service = service();
    let mut input = registration();
    input.public_key_der = Some("retired-public-projection".into());
    input.public_key_kid = Some("retired-kid".into());
    assert!(
        matches!(service.register("user-1", input, Default::default()).await,
        Err(DeviceError::BadRequest(message)) if message.contains("retired"))
    );
    let registered = service
        .register("user-1", registration(), Default::default())
        .await
        .unwrap();
    let old_update: UpdateRegistration = serde_json::from_value(json!({
        "public_key_der": "retired-public-projection", "public_key_kid": "retired-kid"
    }))
    .unwrap();
    assert!(
        matches!(service.update("user-1", &registered.id, old_update, Default::default()).await,
        Err(DeviceError::BadRequest(message)) if message.contains("retired"))
    );
}

#[tokio::test]
async fn http_requires_gateway_and_has_no_device_key_challenge_route() {
    let gateway_key = "g".repeat(32);
    let app = router(HttpState {
        service: Arc::new(service()),
        memberships: Arc::new(AllowMembership),
        release_version: "test".into(),
        build_revision: "fixture".into(),
        gateway_key: gateway_key.clone(),
    });
    for supplied in [None, Some("forged-service-token")] {
        let mut request = Request::builder().uri("/v1/devices");
        if let Some(token) = supplied {
            request = request.header("x-service-token", token);
        }
        let response = app
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    let retired = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/devices/challenge")
                .header("x-user-id", "user-1")
                .header("x-service-token", &gateway_key)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(retired.status(), StatusCode::METHOD_NOT_ALLOWED);
    let native = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health/native-backend")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let native: Value =
        serde_json::from_slice(&to_bytes(native.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(native["required_capability"], "keyless_registration");
    assert_ne!(native["backend"], "marty-verification");
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/devices")
                .header("content-type", "application/json")
                .header("x-user-id", "user-1")
                .header("x-service-token", &gateway_key)
                .body(Body::from(
                    r#"{"device_id":"device-1","platform":"web","fcm_token":"push-token"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}
