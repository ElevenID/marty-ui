//! Opt-in contract against a disposable OpenBao Transit key. No key material
//! enters this test process; all plaintext is synthetic.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use marty_signing_keys::{
    flow_envelope::OpenBaoEnvelopeProvider,
    integration_secret_envelope::{
        self, DecryptRequest, EncryptRequest, IntegrationSecretEnvelopeError,
    },
};
use serde_json::Value;

const KEY_ID: &str = "integration-secret-envelope-marty-aes256";

#[tokio::test]
#[ignore = "requires disposable MARTY_TEST_OPENBAO_URL and MARTY_TEST_OPENBAO_TOKEN with a non-exportable integration-secret Transit key"]
async fn integration_secret_envelope_survives_rotation_and_rejects_wrong_binding() {
    let endpoint = std::env::var("MARTY_TEST_OPENBAO_URL").expect("disposable OpenBao URL");
    let token = std::env::var("MARTY_TEST_OPENBAO_TOKEN").expect("disposable OpenBao token");
    let provider = OpenBaoEnvelopeProvider::new(&endpoint, &token).expect("KMS client");
    let secret_id = format!("secret-{}", uuid::Uuid::new_v4());
    let envelope = integration_secret_envelope::encrypt(
        &provider,
        EncryptRequest {
            organization_id: "org-1".into(),
            secret_id: secret_id.clone(),
            provider: "canvas".into(),
            purpose: "oauth_client_secret".into(),
            plaintext_b64: STANDARD.encode("synthetic-secret"),
        },
    )
    .await
    .expect("remote encrypt");
    assert_eq!(envelope["schema"], "marty.integration-secret-envelope/v1");
    assert!(envelope["ciphertext"]
        .as_str()
        .unwrap()
        .starts_with("vault:v"));
    let request = |envelope: Value, organization_id: &str, purpose: &str| DecryptRequest {
        organization_id: organization_id.into(),
        secret_id: secret_id.clone(),
        provider: "canvas".into(),
        purpose: purpose.into(),
        envelope,
    };
    let decrypted = integration_secret_envelope::decrypt(
        &provider,
        request(envelope.clone(), "org-1", "oauth_client_secret"),
    )
    .await
    .expect("remote decrypt");
    assert_eq!(
        STANDARD
            .decode(decrypted["plaintext_b64"].as_str().unwrap())
            .unwrap(),
        b"synthetic-secret"
    );
    for (organization_id, purpose) in [("org-2", "oauth_client_secret"), ("org-1", "other-purpose")]
    {
        assert!(matches!(
            integration_secret_envelope::decrypt(
                &provider,
                request(envelope.clone(), organization_id, purpose),
            )
            .await,
            Err(IntegrationSecretEnvelopeError::BindingMismatch)
        ));
    }

    let rotate = reqwest::Client::new()
        .post(format!("{endpoint}/v1/transit/keys/{KEY_ID}/rotate"))
        .header("X-Vault-Token", &token)
        .send()
        .await
        .expect("rotate request");
    assert!(
        rotate.status().is_success(),
        "disposable key rotation failed"
    );
    assert!(integration_secret_envelope::decrypt(
        &provider,
        request(envelope.clone(), "org-1", "oauth_client_secret"),
    )
    .await
    .is_ok());

    let mut tampered = envelope;
    tampered["ciphertext"] = Value::String("vault:v1:invalid".into());
    assert!(integration_secret_envelope::decrypt(
        &provider,
        request(tampered, "org-1", "oauth_client_secret"),
    )
    .await
    .is_err());
}
