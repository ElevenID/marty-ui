//! Guarded combined Rust services proof with disposable OpenBao and PostgreSQL.

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey};
use marty_device_registration::{
    control_plane::MembershipAuthorizer,
    holder_credential_repository::PostgresHolderCredentialRepository,
    holder_key_cleanup::HolderKeyCleanup,
    holder_key_client::HolderKeyClient,
    holder_key_provisioner::HolderKeyProvisioner,
    holder_key_repository::PostgresHolderKeyRepository,
    holder_signer::HolderSigner,
    http::{router, HttpState},
    migration::migrate,
    pairing_enrollment::{PairingEnrollment, PairingRedeemResult},
    pairing_ticket::{MemoryPairingTickets, PairingTicketRepository},
    postgres::PostgresDeviceRepository,
    DeviceError, DeviceRepository, DeviceService,
};
use marty_holder_key_reference::HolderSignature;
use marty_signing_keys::{
    kms::{read_managed_openbao, ProviderRequest},
    managed_holder_http,
    managed_holder_key::OpenBaoManagedHolderKeys,
};
use p256::ecdsa::{
    signature::Verifier as _, Signature as P256Signature, VerifyingKey as P256VerifyingKey,
};
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use uuid::Uuid;

#[derive(Default)]
struct SwitchMembership(AtomicBool);

#[async_trait]
impl MembershipAuthorizer for SwitchMembership {
    async fn require_active(
        &self,
        _user_id: &str,
        _organization_id: &str,
    ) -> Result<(), DeviceError> {
        if self.0.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(DeviceError::Forbidden("membership inactive".into()))
        }
    }
}

#[tokio::test]
#[ignore = "requires guarded disposable OpenBao and fresh PostgreSQL"]
async fn registration_provision_sign_and_deactivate_delete_remote_key() {
    let endpoint = std::env::var("MARTY_TEST_OPENBAO_URL").expect("disposable OpenBao URL");
    let parsed = reqwest::Url::parse(&endpoint).expect("OpenBao URL syntax");
    assert_eq!(parsed.scheme(), "http");
    assert_eq!(parsed.host_str(), Some("127.0.0.1"));
    let token = std::env::var("MARTY_TEST_OPENBAO_TOKEN").expect("scoped OpenBao token");
    let root_token = std::env::var("MARTY_TEST_OPENBAO_ROOT_TOKEN").expect("root guard token");
    assert_ne!(token, root_token);
    let nonce = std::env::var("MARTY_TEST_OPENBAO_DISPOSABLE_NONCE").expect("guard nonce");
    let marker = reqwest::Client::new()
        .get(format!(
            "{endpoint}/v1/secret/data/marty-test-disposable-guard"
        ))
        .header("X-Vault-Token", root_token)
        .send()
        .await
        .expect("read disposable sentinel");
    assert!(marker.status().is_success());
    let marker: serde_json::Value = marker.json().await.expect("sentinel JSON");
    assert_eq!(marker["data"]["data"]["nonce"], nonce);

    let database_url =
        std::env::var("DEVICE_REGISTRATION_POSTGRES_TEST_URL").expect("disposable PostgreSQL URL");
    let database = reqwest::Url::parse(&database_url).expect("PostgreSQL URL syntax");
    assert_eq!(database.host_str(), Some("127.0.0.1"));
    let pool = PgPoolOptions::new()
        .max_connections(3)
        .connect(&database_url)
        .await
        .expect("disposable PostgreSQL");
    migrate(&pool).await.expect("fresh Rust schema");

    let devices: Arc<dyn DeviceRepository> = Arc::new(PostgresDeviceRepository::new(pool.clone()));
    let user_id = format!("user-{}", Uuid::new_v4());
    let organization_id = Uuid::new_v4().to_string();
    let tickets = Arc::new(MemoryPairingTickets::new(300));
    let ticket = tickets.issue(&user_id, &organization_id).await.unwrap();

    let service_key = "disposable-device-registration-signing-key-32-chars";
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Signing Keys listener");
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let provider = OpenBaoManagedHolderKeys::new(endpoint.clone(), token.clone())
        .expect("managed OpenBao provider");
    let app = managed_holder_http::router(service_key.into(), provider);
    let server = tokio::spawn(async move { axum::serve(listener, app).await });
    let client = HolderKeyClient::new(&origin, service_key.into()).expect("dedicated client");
    let keys = PostgresHolderKeyRepository::new(pool.clone());
    let provisioner = HolderKeyProvisioner::new(devices.clone(), keys.clone(), client.clone());
    let credentials = PostgresHolderCredentialRepository::new(pool.clone());
    let device_service = Arc::new(DeviceService::new(devices.clone()));
    let memberships = Arc::new(SwitchMembership(AtomicBool::new(true)));
    let signer = Arc::new(HolderSigner::new(
        pool.clone(),
        client.clone(),
        memberships.clone(),
    ));
    let enrollment = Arc::new(PairingEnrollment::new(
        tickets.clone(),
        memberships.clone(),
        device_service.clone(),
        provisioner,
        credentials.clone(),
    ));
    let gateway_key = "disposable-gateway-device-registration-key-32-chars";
    let device_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Device Registration listener");
    let device_origin = format!("http://{}", device_listener.local_addr().unwrap());
    let app = router(HttpState {
        service: device_service,
        memberships: memberships.clone(),
        pairing_tickets: tickets,
        pairing_enrollment: Some(enrollment),
        holder_signer: Some(signer.clone()),
        release_version: "test".into(),
        build_revision: "disposable".into(),
        gateway_key: gateway_key.into(),
    });
    let device_server = tokio::spawn(async move { axum::serve(device_listener, app).await });
    let pairing_body = json!({
        "pairing_code": ticket.token,
        "platform": "android",
        "fcm_token": "synthetic-push-token",
    });
    let http = reqwest::Client::new();
    let paired = http
        .post(format!("{device_origin}/v1/devices/pair"))
        .header("x-service-token", gateway_key)
        .json(&pairing_body)
        .send()
        .await
        .expect("wallet pairing HTTP response");
    assert!(paired.status().is_success());
    assert_eq!(paired.headers()["cache-control"], "no-store");
    let enrolled: PairingRedeemResult = paired.json().await.expect("wallet pairing JSON");
    let replay = http
        .post(format!("{device_origin}/v1/devices/pair"))
        .header("x-service-token", gateway_key)
        .json(&pairing_body)
        .send()
        .await
        .expect("ticket replay response");
    assert_eq!(replay.status(), reqwest::StatusCode::FORBIDDEN);
    let registration = devices
        .get(&enrolled.registration_id)
        .await
        .unwrap()
        .unwrap();
    let key = keys
        .current(&registration.id, "holder_binding")
        .await
        .unwrap()
        .unwrap();
    let presentation = keys
        .current(&registration.id, "presentation_signing")
        .await
        .unwrap()
        .unwrap();
    assert!(key.valid_for(&registration));
    assert!(presentation.valid_for(&registration));
    assert_eq!(enrolled.holder_binding_public_jwk, key.public_jwk());
    assert_eq!(
        enrolled.presentation_signing_public_jwk,
        presentation.public_jwk()
    );
    assert!(credentials
        .issue_for_registration(
            &registration.id,
            "wrong-user",
            key.organization_id.as_str(),
            chrono::Duration::hours(1),
        )
        .await
        .is_err());
    let payload = b"exact managed holder proof";
    assert!(signer
        .sign(
            "invalid",
            &registration.user_id,
            key.organization_id.as_str(),
            "holder_binding",
            payload
        )
        .await
        .is_err());
    let signed = http
        .post(format!("{device_origin}/v1/devices/holder-signatures"))
        .header("x-service-token", gateway_key)
        .bearer_auth(&enrolled.device_credential)
        .json(&json!({"purpose":"holder_binding","payload_b64":URL_SAFE_NO_PAD.encode(payload)}))
        .send()
        .await
        .expect("holder signing HTTP response");
    assert!(signed.status().is_success());
    assert_eq!(signed.headers()["cache-control"], "no-store");
    let signature: HolderSignature = signed.json().await.unwrap();
    assert_eq!(signature.signature_encoding, "raw");
    let coordinate: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&key.public_x)
        .unwrap()
        .try_into()
        .unwrap();
    let verifying = VerifyingKey::from_bytes(&coordinate).unwrap();
    let signature =
        Signature::from_slice(&URL_SAFE_NO_PAD.decode(signature.signature_b64).unwrap()).unwrap();
    verifying.verify_strict(payload, &signature).unwrap();

    let signed = http
        .post(format!("{device_origin}/v1/devices/holder-signatures"))
        .header("x-service-token", gateway_key)
        .bearer_auth(&enrolled.device_credential)
        .json(&json!({"purpose":"presentation_signing","payload_b64":URL_SAFE_NO_PAD.encode(payload)}))
        .send()
        .await
        .expect("presentation signing HTTP response");
    assert!(signed.status().is_success());
    let presentation_signature: HolderSignature = signed.json().await.unwrap();
    assert_eq!(presentation_signature.signature_encoding, "der");
    let mut public_point = vec![4_u8];
    public_point.extend(URL_SAFE_NO_PAD.decode(&presentation.public_x).unwrap());
    public_point.extend(
        URL_SAFE_NO_PAD
            .decode(presentation.public_y.as_deref().unwrap())
            .unwrap(),
    );
    let verifier = P256VerifyingKey::from_sec1_bytes(&public_point).unwrap();
    let signature = P256Signature::from_der(
        &URL_SAFE_NO_PAD
            .decode(presentation_signature.signature_b64)
            .unwrap(),
    )
    .unwrap();
    verifier.verify(payload, &signature).unwrap();

    memberships.0.store(false, Ordering::SeqCst);
    let revoked_membership = http
        .post(format!("{device_origin}/v1/devices/holder-signatures"))
        .header("x-service-token", gateway_key)
        .bearer_auth(&enrolled.device_credential)
        .json(&json!({"purpose":"holder_binding","payload_b64":URL_SAFE_NO_PAD.encode(payload)}))
        .send()
        .await
        .expect("revoked membership signing response");
    assert_eq!(revoked_membership.status(), reqwest::StatusCode::FORBIDDEN);
    memberships.0.store(true, Ordering::SeqCst);

    let replacement = credentials
        .issue_for_registration(
            &registration.id,
            &registration.user_id,
            key.organization_id.as_str(),
            chrono::Duration::hours(1),
        )
        .await
        .expect("atomically rotate bearer using database clock");
    assert!(signer
        .sign(
            &enrolled.device_credential,
            &registration.user_id,
            key.organization_id.as_str(),
            "holder_binding",
            payload,
        )
        .await
        .is_err());
    signer
        .sign(
            &replacement.bearer,
            &registration.user_id,
            key.organization_id.as_str(),
            "holder_binding",
            payload,
        )
        .await
        .expect("rotated bearer signs through KMS");

    devices
        .deactivate(&registration.id)
        .await
        .expect("device deactivation")
        .expect("registered device");
    assert!(signer
        .sign(
            &replacement.bearer,
            &registration.user_id,
            key.organization_id.as_str(),
            "holder_binding",
            payload
        )
        .await
        .is_err());
    let cleanup = HolderKeyCleanup::new(keys.clone(), client);
    assert_eq!(cleanup.run_once().await.expect("remote cleanup"), (2, 0));
    let read = read_managed_openbao(ProviderRequest {
        service_config: json!({
            "id":"managed-openbao-transit", "service_type":"openbao-transit",
            "endpoint":endpoint, "mount":"transit",
            "key_reference":key.provider_reference, "algorithm":"EdDSA",
            "auth_reference":token
        }),
    })
    .await;
    let error = read.expect_err("remote key must be absent after deactivation");
    assert!(matches!(
        error,
        marty_signing_keys::kms::KmsError::ProviderStatus {
            status: reqwest::StatusCode::NOT_FOUND,
            ..
        }
    ));
    let remaining = marty_signing_keys::kms::list_managed_openbao_key_names(&endpoint)
        .await
        .expect("scoped inventory after deletion");
    assert!(!remaining.contains(&key.provider_reference));
    assert!(!remaining.contains(&presentation.provider_reference));
    device_server.abort();
    server.abort();
}
