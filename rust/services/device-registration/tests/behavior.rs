use async_trait::async_trait;
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use marty_device_registration::{
    control_plane::{AllowMembership, MembershipAuthorizer},
    http::{router, HttpState},
    pairing_ticket::MemoryPairingTickets,
    CreateRegistration, DeviceError, DeviceService, MemoryDeviceRepository, Platform,
    UpdateRegistration,
};
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;

fn service() -> DeviceService {
    DeviceService::new(Arc::new(MemoryDeviceRepository::default()))
}

fn registration() -> CreateRegistration {
    CreateRegistration {
        user_id: None,
        organization_id: Some("org-1".into()),
        device_id: "device-1".into(),
        platform: Platform::Web,
        fcm_token: Some("push-token".into()),
        app_version: Some("1.0".into()),
        os_version: None,
        device_model: None,
        preferences: Default::default(),
        is_active: true,
    }
}

struct RejectMembership;

#[async_trait]
impl MembershipAuthorizer for RejectMembership {
    async fn require_active(&self, _: &str, _: &str) -> Result<(), DeviceError> {
        Err(DeviceError::Forbidden(
            "Not a member of this organization".into(),
        ))
    }
}

#[test]
fn contract_retires_device_private_key_challenge() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/device-registration-service-behavior.json"
    ))
    .unwrap();
    assert_eq!(contract["routes"].as_array().unwrap().len(), 11);
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
    let first = service.register("user-1", registration()).await.unwrap();
    assert!(first.is_active);
    assert!(serde_json::to_value(&first)
        .unwrap()
        .get("public_key_der")
        .is_none());
    let changed = service
        .update(
            "user-1",
            &first.id,
            UpdateRegistration {
                fcm_token: Some("next-push-token".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(changed.id, first.id);
    assert_eq!(changed.fcm_token.as_deref(), Some("next-push-token"));
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
            )
            .await,
        Err(DeviceError::Conflict(_))
    ));
    let second = service.register("user-1", registration()).await.unwrap();
    assert_ne!(first.id, second.id);
    assert!(matches!(
        service.get("other-user", &second.id).await,
        Err(DeviceError::NotFound(_))
    ));
}

#[tokio::test]
async fn keyless_mobile_registration_does_not_require_push_delivery() {
    let service = service();
    let mut input = registration();
    input.platform = Platform::Android;
    input.fcm_token = None;
    let registered = service.register("user-1", input).await.unwrap();
    assert_eq!(registered.fcm_token, None);
}

#[tokio::test]
async fn device_held_key_inputs_are_rejected_without_generating_private_keys() {
    let create = json!({
        "device_id": "device-1", "platform": "web", "fcm_token": "push-token",
        "public_key_der": "retired-public-projection"
    });
    assert!(serde_json::from_value::<CreateRegistration>(create).is_err());
    assert!(serde_json::from_value::<UpdateRegistration>(json!({
        "public_key_der": "retired-public-projection", "public_key_kid": "retired-kid"
    }))
    .is_err());
    assert!(serde_json::from_value::<CreateRegistration>(json!({
        "device_id": "device-1", "platform": "web", "fcm_token": "push-token",
        "preferences": {"private_key": "retired"}
    }))
    .is_err());
    let service = service();
    let mut input = registration();
    input.preferences.quiet_hours_start = Some("-----BEGIN PRIVATE KEY-----synthetic".into());
    assert!(matches!(
        service.register("user-1", input).await,
        Err(DeviceError::BadRequest(_))
    ));
}

#[tokio::test]
async fn http_requires_gateway_and_has_no_device_key_challenge_route() {
    let gateway_key = "g".repeat(32);
    let app = router(HttpState {
        service: Arc::new(service()),
        memberships: Arc::new(AllowMembership),
        pairing_tickets: Arc::new(MemoryPairingTickets::new(300)),
        pairing_confirmations: None,
        pairing_enrollment: None,
        holder_signer: None,
        holder_credential_rotator: None,
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

#[tokio::test]
async fn pairing_ticket_issuance_requires_gateway_and_active_membership() {
    let gateway_key = "g".repeat(32);
    let tickets = Arc::new(MemoryPairingTickets::new(300));
    let app = router(HttpState {
        service: Arc::new(service()),
        memberships: Arc::new(AllowMembership),
        pairing_tickets: tickets.clone(),
        pairing_confirmations: None,
        pairing_enrollment: None,
        holder_signer: None,
        holder_credential_rotator: None,
        release_version: "test".into(),
        build_revision: "fixture".into(),
        gateway_key: gateway_key.clone(),
    });
    let request = |token: Option<&str>, organization_id: &str| {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/v1/devices/pairing-tickets")
            .header("content-type", "application/json")
            .header("x-user-id", "user-1");
        if let Some(token) = token {
            builder = builder.header("x-service-token", token);
        }
        builder
            .body(Body::from(
                json!({"organization_id": organization_id}).to_string(),
            ))
            .unwrap()
    };
    let unauthenticated = app.clone().oneshot(request(None, "org-1")).await.unwrap();
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
    let response = app
        .oneshot(request(Some(&gateway_key), "org-1"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

    let denied = router(HttpState {
        service: Arc::new(service()),
        memberships: Arc::new(RejectMembership),
        pairing_tickets: tickets,
        pairing_confirmations: None,
        pairing_enrollment: None,
        holder_signer: None,
        holder_credential_rotator: None,
        release_version: "test".into(),
        build_revision: "fixture".into(),
        gateway_key: gateway_key.clone(),
    })
    .oneshot(request(Some(&gateway_key), "org-1"))
    .await
    .unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn mobile_redemption_cannot_use_a_missing_remote_kms_authority() {
    let gateway_key = "g".repeat(32);
    let app = router(HttpState {
        service: Arc::new(service()),
        memberships: Arc::new(AllowMembership),
        pairing_tickets: Arc::new(MemoryPairingTickets::new(300)),
        pairing_confirmations: None,
        pairing_enrollment: None,
        holder_signer: None,
        holder_credential_rotator: None,
        release_version: "test".into(),
        build_revision: "fixture".into(),
        gateway_key: gateway_key.clone(),
    });
    let request = |token: Option<&str>| {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/v1/devices/pair")
            .header("content-type", "application/json");
        if let Some(token) = token {
            builder = builder.header("x-service-token", token);
        }
        builder
            .body(Body::from(
                r#"{"pairing_code":"synthetic","platform":"android","fcm_token":"push-token"}"#,
            ))
            .unwrap()
    };
    assert_eq!(
        app.clone().oneshot(request(None)).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.oneshot(request(Some(&gateway_key)))
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[tokio::test]
async fn mobile_signing_requires_gateway_and_remote_kms_authority() {
    let gateway_key = "g".repeat(32);
    let app = router(HttpState {
        service: Arc::new(service()),
        memberships: Arc::new(AllowMembership),
        pairing_tickets: Arc::new(MemoryPairingTickets::new(300)),
        pairing_confirmations: None,
        pairing_enrollment: None,
        holder_signer: None,
        holder_credential_rotator: None,
        release_version: "test".into(),
        build_revision: "fixture".into(),
        gateway_key: gateway_key.clone(),
    });
    let request = |token: Option<&str>| {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/v1/devices/holder-signatures")
            .header("authorization", "Bearer synthetic-device-credential")
            .header("content-type", "application/json");
        if let Some(token) = token {
            builder = builder.header("x-service-token", token);
        }
        builder
            .body(Body::from(
                r#"{"purpose":"holder_binding","payload_b64":"cHJvb2Y"}"#,
            ))
            .unwrap()
    };
    assert_eq!(
        app.clone().oneshot(request(None)).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.oneshot(request(Some(&gateway_key)))
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}
