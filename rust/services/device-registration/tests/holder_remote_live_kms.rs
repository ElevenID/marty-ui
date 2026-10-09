//! Guarded combined Rust services proof with disposable OpenBao and PostgreSQL.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use ed25519_dalek::{Signature, VerifyingKey};
use marty_device_registration::{
    holder_credential_repository::PostgresHolderCredentialRepository,
    holder_key_cleanup::HolderKeyCleanup, holder_key_client::HolderKeyClient,
    holder_key_provisioner::HolderKeyProvisioner,
    holder_key_repository::PostgresHolderKeyRepository, holder_signer::HolderSigner,
    migration::migrate, postgres::PostgresDeviceRepository, CreateRegistration, DeviceRegistration,
    DeviceRepository, Platform,
};
use marty_signing_keys::{
    kms::{read_managed_openbao, ProviderRequest},
    managed_holder_http,
    managed_holder_key::OpenBaoManagedHolderKeys,
};
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use uuid::Uuid;

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
    let registration = devices
        .save(DeviceRegistration::new(
            format!("user-{}", Uuid::new_v4()),
            CreateRegistration {
                user_id: None,
                organization_id: Some(Uuid::new_v4().to_string()),
                device_id: Uuid::new_v4().to_string(),
                platform: Platform::Web,
                fcm_token: "synthetic-push-token".into(),
                app_version: None,
                os_version: None,
                device_model: None,
                preferences: Default::default(),
                is_active: true,
            },
            Utc::now(),
        ))
        .await
        .expect("keyless device registration");

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
    let key = provisioner
        .provision(
            &registration.user_id,
            registration.organization_id.as_deref().unwrap(),
            &registration.id,
            "holder_binding",
            "EdDSA",
        )
        .await
        .expect("real non-exportable OpenBao key binding");
    assert!(key.valid_for(&registration));
    let credentials = PostgresHolderCredentialRepository::new(pool.clone());
    assert!(credentials
        .issue_for_registration(
            &registration.id,
            "wrong-user",
            key.organization_id.as_str(),
            chrono::Duration::hours(1),
        )
        .await
        .is_err());
    let credential = credentials
        .issue_for_registration(
            &registration.id,
            &registration.user_id,
            key.organization_id.as_str(),
            chrono::Duration::hours(1),
        )
        .await
        .expect("issue bearer from database clock and store only its digest");
    let signer = HolderSigner::new(pool.clone(), client.clone());
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
    let signature = signer
        .sign(
            &credential.bearer,
            &registration.user_id,
            key.organization_id.as_str(),
            "holder_binding",
            payload,
        )
        .await
        .expect("authorized version-pinned remote signature");
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
            &credential.bearer,
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
    assert_eq!(cleanup.run_once().await.expect("remote cleanup"), (1, 0));
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
    server.abort();
}
