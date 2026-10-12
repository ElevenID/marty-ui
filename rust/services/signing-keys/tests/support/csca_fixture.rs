use marty_crypto::cert_builder::{CertProfile, CertificateBuilderConfig, DistinguishedName};
use marty_crypto::certificate::der_to_pem;
use marty_crypto::jwk::certificate_pem_to_jwk;
use marty_crypto::keygen::KeyType;
use marty_signing_keys::csca_lifecycle::ImportCscaCertificateRequest;
use serde_json::json;

pub fn request(country: &str, label: &str, key_reference: &str) -> ImportCscaCertificateRequest {
    let (cert_der, _) = CertificateBuilderConfig::new()
        .subject(
            DistinguishedName::new()
                .cn(&format!("{country} Country Signing CA"))
                .country(country)
                .organization(label),
        )
        .validity_days(30)
        .profile(CertProfile::Csca {
            country_code: country.to_string(),
        })
        .key_type(KeyType::EcdsaP256)
        .build_self_signed()
        .unwrap();
    request_from_der(cert_der, key_reference, country)
}

pub fn request_from_der(
    cert_der: Vec<u8>,
    key_reference: &str,
    country: &str,
) -> ImportCscaCertificateRequest {
    let cert_pem = der_to_pem(&cert_der).unwrap();
    ImportCscaCertificateRequest {
        expected_public_jwk: serde_json::to_value(certificate_pem_to_jwk(&cert_pem).unwrap())
            .unwrap(),
        cert_pem,
        cert_chain_pem: String::new(),
        key_reference: key_reference.to_string(),
        metadata: json!({"country": country}),
    }
}
