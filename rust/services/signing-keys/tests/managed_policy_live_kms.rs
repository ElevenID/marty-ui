//! Opt-in Rust adapter proof against disposable OpenBao and its scoped token.
//! OpenBao retains the private signing key; only public metadata enters Rust.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use marty_holder_key_reference::new_reference;
use marty_signing_keys::kms::{
    create_managed_openbao, read_managed_openbao, rotate_openbao, sign, ProviderRequest,
    SignRequest,
};
use marty_signing_keys::managed_holder_key::{
    CreateHolderKeyRequest, HolderKeyScope, OpenBaoManagedHolderKeys, SignHolderKeyRequest,
};
use serde_json::{json, Value};
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires guarded disposable OpenBao with signing-keys-managed policy"]
async fn managed_key_create_rotate_and_read_use_scoped_provider_only() {
    let endpoint = std::env::var("MARTY_TEST_OPENBAO_URL").expect("disposable OpenBao URL");
    let parsed = reqwest::Url::parse(&endpoint).expect("disposable OpenBao URL syntax");
    assert!(parsed.scheme() == "http" && parsed.host_str() == Some("127.0.0.1"));
    assert_eq!(
        std::env::var("BAO_ADDR").ok().as_deref(),
        Some(endpoint.as_str()),
        "managed token must be bound to the configured OpenBao endpoint"
    );
    let scoped_token =
        std::env::var("MARTY_TEST_OPENBAO_TOKEN").expect("disposable scoped OpenBao token");
    assert_eq!(
        std::env::var("BAO_TOKEN").ok().as_deref(),
        Some(scoped_token.as_str())
    );
    let root_token =
        std::env::var("MARTY_TEST_OPENBAO_ROOT_TOKEN").expect("disposable root guard token");
    assert_ne!(scoped_token, root_token);
    let nonce = std::env::var("MARTY_TEST_OPENBAO_DISPOSABLE_NONCE")
        .expect("pre-provisioned disposable OpenBao sentinel");
    assert!(nonce.len() >= 16);
    let marker = reqwest::Client::new()
        .get(format!(
            "{}/v1/secret/data/marty-test-disposable-guard",
            endpoint.trim_end_matches('/')
        ))
        .header("X-Vault-Token", root_token)
        .send()
        .await
        .expect("disposable marker read");
    assert!(marker.status().is_success());
    let marker: Value = marker.json().await.expect("disposable marker JSON");
    assert_eq!(
        marker["data"]["data"]["nonce"].as_str(),
        Some(nonce.as_str())
    );

    let reference = format!("cred-issuer-probe-{}", Uuid::new_v4().simple());
    let config = json!({
        "id": "managed-openbao-transit",
        "service_type": "openbao-transit",
        "auth_mode": "service_token",
        "endpoint": endpoint,
        "mount": "transit",
        "key_reference": reference,
        "algorithm": "ES256"
    });
    let first = create_managed_openbao(ProviderRequest {
        service_config: config.clone(),
    })
    .await
    .expect("scoped key creation");
    assert_eq!(first["status"], "active");
    assert_eq!(first["latest_version"], 1);
    assert_eq!(first["exportable"], false);
    assert_eq!(first["allow_plaintext_backup"], false);

    rotate_openbao(ProviderRequest {
        service_config: config.clone(),
    })
    .await
    .expect("scoped key rotation");
    let second = read_managed_openbao(ProviderRequest {
        service_config: config,
    })
    .await
    .expect("scoped public key read");
    assert_eq!(second["status"], "active");
    assert_eq!(second["latest_version"], 2);
    assert_ne!(first["public_jwk"], second["public_jwk"]);
    assert!(second["public_jwk"].get("d").is_none());

    let mut pinned_config = json!({
        "id": "managed-openbao-transit", "service_type": "openbao-transit",
        "auth_mode": "service_token", "endpoint": endpoint, "mount": "transit",
        "key_reference": reference, "algorithm": "ES256", "key_version": 1
    });
    let pinned = read_managed_openbao(ProviderRequest {
        service_config: pinned_config.clone(),
    })
    .await
    .expect("version-one public key read after rotation");
    assert_eq!(pinned["public_jwk"], first["public_jwk"]);
    assert_eq!(pinned["selected_version"], "1");
    let signed = sign(SignRequest {
        service_config: pinned_config.clone(),
        payload_b64: URL_SAFE_NO_PAD.encode(b"versioned-holder-proof"),
    })
    .await
    .expect("version-one non-exportable signature after rotation");
    assert_eq!(signed.signature_encoding, "der");
    assert!(!signed.signature_b64.is_empty());
    pinned_config["key_version"] = json!(2);
    let current = read_managed_openbao(ProviderRequest {
        service_config: pinned_config,
    })
    .await
    .expect("version-two public key read");
    assert_eq!(current["public_jwk"], second["public_jwk"]);

    let holder = OpenBaoManagedHolderKeys::new(endpoint.clone(), scoped_token.clone())
        .expect("scoped holder provider");
    let holder_reference = new_reference("org-holder", "registration-holder", "holder_binding")
        .expect("scoped holder reference");
    let scope = || HolderKeyScope {
        organization_id: "org-holder".into(),
        registration_id: "registration-holder".into(),
        purpose: "holder_binding".into(),
        provider_reference: holder_reference.clone(),
    };
    let holder_metadata = holder
        .create(CreateHolderKeyRequest {
            scope: scope(),
            algorithm: "EdDSA".into(),
        })
        .await
        .expect("non-exportable holder key creation");
    assert_eq!(holder_metadata["status"], "active");
    assert_eq!(holder_metadata["exportable"], false);
    let signature = holder
        .sign(SignHolderKeyRequest {
            scope: scope(),
            algorithm: "EdDSA".into(),
            key_version: holder_metadata["latest_version"].as_u64().unwrap(),
            public_jwk: holder_metadata["public_jwk"].clone(),
            payload_b64: URL_SAFE_NO_PAD.encode(b"exact-holder-proof"),
        })
        .await
        .expect("version-pinned managed holder signature");
    assert_eq!(signature.signature_encoding, "raw");
    assert!(!signature.signature_b64.is_empty());
    holder
        .revoke(scope())
        .await
        .expect("remote holder revocation");
    holder
        .revoke(scope())
        .await
        .expect("idempotent remote revocation");
    assert!(read_managed_openbao(ProviderRequest {
        service_config: json!({
            "id":"managed-openbao-transit", "service_type":"openbao-transit",
            "endpoint":endpoint, "mount":"transit", "key_reference":holder_reference,
            "algorithm":"EdDSA", "auth_reference":scoped_token
        }),
    })
    .await
    .is_err());
}
