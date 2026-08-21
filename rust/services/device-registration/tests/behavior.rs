use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use marty_device_registration::{
    challenge::{ChallengeRepository, MemoryChallengeRepository},
    control_plane::AllowMembership,
    http::{router, HttpState},
    CreateRegistration, DeviceError, DeviceRepository, DeviceService, MemoryDeviceRepository,
    Platform, ProofHeaders, UpdateRegistration,
};
use marty_verification::device_auth::inspect_device_public_key;
use marty_verification::device_auth::DeviceChallengeRecord;
use rand08::rngs::OsRng;
use rsa::{
    pkcs1::EncodeRsaPublicKey,
    pss::BlindedSigningKey,
    signature::{RandomizedSigner, SignatureEncoding},
    RsaPrivateKey,
};
use serde_json::Value;
use sha2::Sha256;
use std::sync::Arc;
use tower::ServiceExt;

fn service() -> (DeviceService, Arc<MemoryDeviceRepository>) {
    let repository = Arc::new(MemoryDeviceRepository::default());
    let challenges: Arc<dyn ChallengeRepository> = Arc::new(MemoryChallengeRepository::new(300));
    (
        DeviceService::new(repository.clone(), challenges, 300).unwrap(),
        repository,
    )
}

fn key() -> (RsaPrivateKey, String, String) {
    let private = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
    let der = private.to_public_key().to_pkcs1_der().unwrap();
    let encoded = URL_SAFE_NO_PAD.encode(der.as_bytes());
    let kid = inspect_device_public_key(&encoded).unwrap().public_key_kid;
    (private, encoded, kid)
}

fn registration(der: Option<String>, kid: Option<String>) -> CreateRegistration {
    CreateRegistration {
        user_id: None,
        organization_id: None,
        device_id: "device-1".into(),
        platform: Platform::Web,
        fcm_token: "push-token".into(),
        app_version: Some("1.0".into()),
        os_version: None,
        device_model: None,
        preferences: Default::default(),
        public_key_der: der,
        public_key_kid: kid,
        key_valid_from: None,
        key_valid_until: None,
        is_active: true,
    }
}

async fn proof(
    service: &DeviceService,
    private: &RsaPrivateKey,
    der: &str,
    kid: &str,
    registration_id: Option<String>,
    expected_key_version: Option<u64>,
) -> ProofHeaders {
    let response = service
        .request_challenge(
            "user-1",
            marty_device_registration::ChallengeRequest {
                device_id: "device-1".into(),
                public_key_der: der.into(),
                public_key_kid: kid.into(),
                registration_id,
                expected_key_version,
            },
        )
        .await
        .unwrap();
    let message = URL_SAFE_NO_PAD.decode(response.challenge).unwrap();
    let signature =
        BlindedSigningKey::<Sha256>::new(private.clone()).sign_with_rng(&mut OsRng, &message);
    ProofHeaders {
        challenge_id: Some(response.challenge_id),
        signature: Some(URL_SAFE_NO_PAD.encode(signature.to_bytes())),
    }
}

#[test]
fn language_neutral_contract_covers_the_whole_surface() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/device-registration-service-behavior.json"
    ))
    .unwrap();
    assert_eq!(contract["routes"].as_array().unwrap().len(), 6);
    assert_eq!(contract["key_lifecycle"].as_array().unwrap().len(), 3);
    assert_eq!(contract["challenge"]["algorithm"], "PS256");
    assert!(contract["invariants"].as_array().unwrap().len() >= 7);
}

#[test]
fn shared_challenge_golden_vectors_are_preserved() {
    let vectors: Value =
        serde_json::from_str(include_str!("../../../../tests/vectors/device_auth.json")).unwrap();
    for case in vectors["challenge_cases"].as_array().unwrap() {
        let challenge: DeviceChallengeRecord =
            serde_json::from_value(case["challenge"].clone()).unwrap();
        assert_eq!(
            challenge.encoded_message().unwrap(),
            case["expected_message_base64url"]
        );
    }
}

#[tokio::test]
async fn key_registration_rotation_replay_and_soft_delete_match_the_contract() {
    let (service, repository) = service();
    let (old_private, old_der, old_kid) = key();
    let initial_proof = proof(&service, &old_private, &old_der, &old_kid, None, None).await;
    let replay = initial_proof.clone();
    let registered = service
        .register(
            "user-1",
            registration(Some(old_der), Some(old_kid)),
            initial_proof,
        )
        .await
        .unwrap();
    assert_eq!(registered.key_version, Some(1));
    assert!(
        matches!(service.register("user-1", registration(registered.public_key_der.clone(), registered.public_key_kid.clone()), replay).await, Err(DeviceError::BadRequest(message)) if message == "Device challenge is invalid or expired")
    );

    let (next_private, next_der, next_kid) = key();
    let rotation_proof = proof(
        &service,
        &next_private,
        &next_der,
        &next_kid,
        Some(registered.id.clone()),
        Some(1),
    )
    .await;
    let rotated = service
        .update(
            "user-1",
            &registered.id,
            UpdateRegistration {
                public_key_der: Some(next_der),
                public_key_kid: Some(next_kid),
                expected_key_version: Some(1),
                ..Default::default()
            },
            rotation_proof,
        )
        .await
        .unwrap();
    assert_eq!(rotated.key_version, Some(2));

    let stale = repository
        .rotate_key(&registered.id, 1, "unused", "unused", 0)
        .await;
    assert!(
        matches!(stale, Err(DeviceError::Conflict(message)) if message == "current device key version changed")
    );
    service.delete("user-1", &registered.id).await.unwrap();
    service.delete("user-1", &registered.id).await.unwrap();
    let inactive = service.get("user-1", &registered.id).await.unwrap();
    assert!(!inactive.is_active);
    assert!(inactive.key_version.is_none());
    assert!(
        matches!(service.update("user-1", &registered.id, UpdateRegistration { is_active: Some(true), ..Default::default() }, Default::default()).await, Err(DeviceError::Conflict(message)) if message == "a deactivated device must be registered with a new key")
    );
}

#[tokio::test]
async fn concurrent_rotation_has_one_compare_and_swap_winner() {
    let (service, repository) = service();
    let registered = service
        .register("user-1", registration(None, None), Default::default())
        .await
        .unwrap();
    let (private, der, kid) = key();
    let initial = proof(
        &service,
        &private,
        &der,
        &kid,
        Some(registered.id.clone()),
        None,
    )
    .await;
    let keyed = service
        .update(
            "user-1",
            &registered.id,
            UpdateRegistration {
                public_key_der: Some(der),
                public_key_kid: Some(kid),
                ..Default::default()
            },
            initial,
        )
        .await
        .unwrap();
    assert_eq!(keyed.key_version, Some(1));
    let first = repository.rotate_key(&keyed.id, 1, "first", "first", 0);
    let second = repository.rotate_key(&keyed.id, 1, "second", "second", 0);
    let (first, second) = tokio::join!(first, second);
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
}

#[test]
fn explicit_null_metadata_cannot_be_combined_with_key_rotation() {
    let body: UpdateRegistration = serde_json::from_value(serde_json::json!({
        "public_key_der": "replacement-key",
        "public_key_kid": "replacement-kid",
        "expected_key_version": 1,
        "fcm_token": null
    }))
    .unwrap();
    assert!(body.has_metadata_with_key_rotation());

    let rotation_only: UpdateRegistration = serde_json::from_value(serde_json::json!({
        "public_key_der": "replacement-key",
        "public_key_kid": "replacement-kid",
        "expected_key_version": 1
    }))
    .unwrap();
    assert!(!rotation_only.has_metadata_with_key_rotation());
}

#[tokio::test]
async fn invalid_signature_does_not_consume_the_challenge() {
    let (service, _) = service();
    let (private, der, kid) = key();
    let valid = proof(&service, &private, &der, &kid, None, None).await;
    let invalid = ProofHeaders {
        challenge_id: valid.challenge_id.clone(),
        signature: Some("invalid".into()),
    };
    assert!(
        matches!(service.register("user-1", registration(Some(der.clone()), Some(kid.clone())), invalid).await, Err(DeviceError::BadRequest(message)) if message.contains("INVALID"))
    );
    let registered = service
        .register("user-1", registration(Some(der), Some(kid)), valid)
        .await
        .unwrap();
    assert_eq!(registered.key_version, Some(1));
}

#[tokio::test]
async fn deactivated_reregistration_gets_a_new_identity_and_key_history() {
    let (service, _) = service();
    let first = service
        .register("user-1", registration(None, None), Default::default())
        .await
        .unwrap();
    service.delete("user-1", &first.id).await.unwrap();
    let second = service
        .register("user-1", registration(None, None), Default::default())
        .await
        .unwrap();
    assert_ne!(first.id, second.id);
    assert!(second.is_active);
}

#[tokio::test]
async fn http_surface_preserves_routes_identity_and_response_shapes() {
    let (service, _) = service();
    let app = router(HttpState {
        service: Arc::new(service),
        memberships: Arc::new(AllowMembership),
        release_version: "test".into(),
        build_revision: "fixture".into(),
    });
    let request = Request::builder()
        .method("POST")
        .uri("/v1/devices")
        .header("content-type", "application/json")
        .header("x-user-id", "user-1")
        .body(Body::from(
            r#"{"device_id":"device-1","platform":"web","fcm_token":"push-token"}"#,
        ))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap();
    let id = body["id"].as_str().unwrap();
    assert_eq!(body["user_id"], "user-1");
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/v1/devices/{id}"))
                .header("x-user-id", "another-user")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(body["detail"], "Device registration not found");
}

#[test]
fn migration_is_irreversible_and_preserves_legacy_projection_history() {
    let sql = include_str!("../migrations/0001_device_registration.sql");
    for required in [
        "device_registrations",
        "device_registration_keys",
        "device_key_transitions",
        "KEY_REGISTERED",
        "KEY_ROTATED",
        "KEYS_REVOKED",
        "cannot migrate incomplete legacy device key projection",
        "ux_device_key_one_current",
    ] {
        assert!(sql.contains(required), "migration omitted {required}");
    }
    assert!(!sql.to_ascii_uppercase().contains("DROP TABLE"));
}
