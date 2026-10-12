use chrono::Utc;
use marty_crypto::certificate::{get_certificate_info, load_certificate_pem};
use marty_crypto::jwk::certificate_pem_to_jwk;
use marty_signing_keys::csca_lifecycle::{CscaLifecycleDocument, ImportCscaCertificateRequest};
use serde_json::json;

#[test]
fn public_csca_certificate_is_accepted_by_signing_lifecycle() {
    let cert_pem =
        include_str!("../../../services/signing-keys/tests/fixtures/csca_public/deu-original.pem")
            .to_string();
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
