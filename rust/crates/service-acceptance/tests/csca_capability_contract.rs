use chrono::Utc;
use marty_crypto::certificate::{get_certificate_info, load_certificate_pem};
use marty_crypto::jwk::certificate_pem_to_jwk;
use marty_signing_keys::csca_lifecycle::{CscaLifecycleDocument, ImportCscaCertificateRequest};
use marty_verification::issuance::CscaAuthority;
use marty_verification::issuance::CscaKeyAlgorithm;
use serde_json::{json, Value};

#[test]
fn creation_algorithms_match_the_language_neutral_contract() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/csca-capability-behavior.json"
    ))
    .unwrap();
    let supported = CscaKeyAlgorithm::ALL.map(CscaKeyAlgorithm::as_str);
    assert_eq!(
        json!(supported),
        contract["supported_rust_surface"]["emrtd_issuance"]["creation_algorithms"]
    );
}

#[test]
fn verification_authority_certificate_is_accepted_by_signing_lifecycle() {
    let authority = CscaAuthority::new("DEU", "German CSCA", 30).unwrap();
    let cert_pem = authority.cert_pem().unwrap();
    let cert_der = load_certificate_pem(&cert_pem).unwrap();
    let now =
        chrono::DateTime::parse_from_rfc3339(&get_certificate_info(&cert_der).unwrap().not_before)
            .unwrap()
            .with_timezone(&Utc);
    let mut document = CscaLifecycleDocument::empty("org-a", now);
    document
        .import(
            "csca-deu-1",
            ImportCscaCertificateRequest {
                expected_public_jwk: serde_json::to_value(
                    certificate_pem_to_jwk(&cert_pem).unwrap(),
                )
                .unwrap(),
                cert_pem: cert_pem.clone(),
                cert_chain_pem: String::new(),
                key_reference: "hsm://csca/deu".to_string(),
                metadata: json!({"country": "DEU"}),
            },
            now,
        )
        .unwrap();
    assert_eq!(
        document.certificate_data("csca-deu-1", now).unwrap(),
        cert_pem
    );
}
