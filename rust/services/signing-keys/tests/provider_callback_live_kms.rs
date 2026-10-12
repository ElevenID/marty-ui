//! Opt-in exact-body provider HMAC verification with a disposable scoped OpenBao token.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use marty_signing_keys::{
    flow_envelope::OpenBaoEnvelopeProvider,
    passport_callback_hmac::{verify_provider, ProviderVerifyRequest},
};

#[tokio::test]
#[ignore = "requires disposable OpenBao and a verify-only provider callback token"]
async fn scoped_provider_callback_verifies_exact_body_without_key_material() {
    let endpoint = std::env::var("MARTY_TEST_OPENBAO_URL").unwrap();
    let parsed = reqwest::Url::parse(&endpoint).unwrap();
    assert_eq!(parsed.scheme(), "http");
    assert_eq!(parsed.host_str(), Some("127.0.0.1"));
    let token = std::env::var("MARTY_TEST_PROVIDER_CALLBACK_TOKEN").unwrap();
    let root = std::env::var("MARTY_TEST_OPENBAO_ROOT_TOKEN").unwrap();
    assert_ne!(token, root);
    let profile_id = std::env::var("MARTY_TEST_PROVIDER_PROFILE_ID").unwrap();
    let body_b64 = std::env::var("MARTY_TEST_PROVIDER_CALLBACK_BODY_B64").unwrap();
    let signature_hex = std::env::var("MARTY_TEST_PROVIDER_CALLBACK_HMAC_HEX").unwrap();
    let provider = OpenBaoEnvelopeProvider::new(endpoint, token).unwrap();
    let accepted = verify_provider(
        &provider,
        &profile_id,
        ProviderVerifyRequest {
            body_b64: body_b64.clone(),
            signature_hex: signature_hex.clone(),
            key_version: 1,
        },
    )
    .await
    .unwrap();
    assert_eq!(accepted["valid"], true);
    let mut altered = STANDARD.decode(body_b64).unwrap();
    altered[0] ^= 1;
    let rejected = verify_provider(
        &provider,
        &profile_id,
        ProviderVerifyRequest {
            body_b64: STANDARD.encode(altered),
            signature_hex,
            key_version: 1,
        },
    )
    .await
    .unwrap();
    assert_eq!(rejected["valid"], false);
}
