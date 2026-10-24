//! Opt-in Notification envelope proof against disposable HTTPS OpenBao.

use std::{env, path::PathBuf};

use marty_notification::webhook::WebhookSecretEnvelope;

#[tokio::test]
#[ignore = "requires the disposable Notification HTTPS OpenBao profile"]
async fn scoped_notification_envelope_rejects_wrong_binding_ca_and_shared_token() {
    let endpoint = env::var("BAO_ADDR").expect("disposable OpenBao endpoint");
    assert!(endpoint.starts_with("https://"));
    let ca = env::var("NOTIFICATION_OPENBAO_CA_CERT_FILE").expect("public OpenBao CA");
    let token_file = env::var("NOTIFICATION_OPENBAO_TOKEN_FILE").expect("scoped token file");
    let envelope = WebhookSecretEnvelope::from_environment().expect("scoped HTTPS envelope");
    envelope
        .check_ready()
        .await
        .expect("non-exportable Transit key");
    let secret = "disposable-notification-secret-00000001";
    let ciphertext = envelope
        .wrap("organization-a", "webhook-a", secret)
        .await
        .expect("remote encrypt");
    assert!(ciphertext.starts_with("vault:"));
    assert_eq!(
        envelope
            .unwrap("organization-a", "webhook-a", &ciphertext)
            .await
            .expect("bound remote decrypt"),
        secret
    );
    assert!(envelope
        .unwrap("organization-b", "webhook-a", &ciphertext)
        .await
        .is_err());
    assert!(envelope
        .unwrap("organization-a", "webhook-b", &ciphertext)
        .await
        .is_err());

    let wrong_ca = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../signing-keys/tests/fixtures/public_certificates/root-ca.pem");
    env::set_var("NOTIFICATION_OPENBAO_CA_CERT_FILE", &wrong_ca);
    let untrusted = WebhookSecretEnvelope::from_environment().expect("valid unrelated CA");
    assert!(
        untrusted.check_ready().await.is_err(),
        "wrong CA must fail closed"
    );
    env::set_var("NOTIFICATION_OPENBAO_CA_CERT_FILE", ca);

    env::remove_var("NOTIFICATION_OPENBAO_TOKEN_FILE");
    env::set_var("OPENBAO_SERVICE_TOKEN", "shared-token-must-not-be-accepted");
    assert!(
        WebhookSecretEnvelope::from_environment().is_err(),
        "a shared OpenBao token must not replace the scoped identity"
    );
    env::set_var("NOTIFICATION_OPENBAO_TOKEN_FILE", token_file);
    env::remove_var("OPENBAO_SERVICE_TOKEN");
}
