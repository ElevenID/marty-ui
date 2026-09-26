//! Explicit opt-in contract against a disposable OpenBao instance. Test keys
//! are generated and held by Transit; this test never sees private material.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use der::{DecodePem, Encode};
use marty_signing_keys::{
    certificate_csr::{self, CsrSubject},
    kms::{self, ProviderRequest, SignRequest},
};
use serde_json::{json, Value};
use x509_cert::request::CertReq;

#[tokio::test]
#[ignore = "requires MARTY_TEST_OPENBAO_URL and disposable MARTY_TEST_OPENBAO_TOKEN"]
async fn csr_is_signed_and_verified_for_every_passport_ecdsa_curve_in_kms() {
    let endpoint = std::env::var("MARTY_TEST_OPENBAO_URL").expect("disposable OpenBao URL");
    let token = std::env::var("MARTY_TEST_OPENBAO_TOKEN").expect("disposable OpenBao token");
    for algorithm in ["ES256", "ES384", "ES512"] {
        let config = json!({
            "id": "managed-openbao-transit",
            "service_type": "openbao-transit",
            "endpoint": endpoint,
            "mount": "transit",
            "key_reference": format!("marty-csr-contract-{}", algorithm.to_ascii_lowercase()),
            "algorithm": algorithm,
            "auth_reference": token,
        });
        let provider = kms::public_key(ProviderRequest {
            service_config: config.clone(),
        })
        .await
        .expect("public key remains in OpenBao");
        let public_jwk = provider.get("public_jwk").unwrap_or(&provider);
        let csr = certificate_csr::prepare(
            public_jwk,
            algorithm,
            &CsrSubject {
                country: "US",
                organization: "ElevenID Beta",
                common_name: "Pilot CSCA",
            },
        )
        .expect("public CSR body");
        let signature = kms::sign(SignRequest {
            service_config: config,
            payload_b64: URL_SAFE_NO_PAD.encode(csr.signing_bytes()),
        })
        .await
        .expect("sign only inside OpenBao");
        assert_eq!(signature.signature_encoding, "der");
        let bytes = URL_SAFE_NO_PAD
            .decode(&signature.signature_b64)
            .expect("provider signature encoding");
        let pem = csr
            .finish(&bytes)
            .expect("signature matches current public key");
        let parsed = CertReq::from_pem(&pem).expect("valid PKCS#10 PEM");
        let parsed_jwk: Value = serde_json::to_value(
            marty_crypto::jwk::public_key_der_to_jwk(
                &parsed.info.public_key.to_der().expect("SPKI DER"),
            )
            .expect("public JWK from CSR"),
        )
        .expect("JWK JSON");
        for field in ["kty", "crv", "x", "y"] {
            assert_eq!(parsed_jwk[field], public_jwk[field], "{algorithm} {field}");
        }
    }
}
