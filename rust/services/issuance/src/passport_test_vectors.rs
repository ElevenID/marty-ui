//! Public-only passport certificates and signed SOD vectors for service tests.

use serde::Deserialize;

#[derive(Clone, Deserialize)]
pub(crate) struct PublicPassportVector {
    pub dsc_der_b64: String,
    pub csca_der_b64: String,
    pub signing_input_sha256: String,
    pub signature_der_b64: String,
    pub sod_der_b64: String,
}

pub(crate) fn public_passport_vectors() -> [PublicPassportVector; 2] {
    serde_json::from_str(include_str!(
        "../tests/fixtures/passport_public_signatures.json"
    ))
    .expect("public passport vectors")
}

pub(crate) fn certificate_pem(der_b64: &str) -> String {
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in der_b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).expect("base64 certificate"));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}
