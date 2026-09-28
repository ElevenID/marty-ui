//! Shared simulator receipt commitments for first acceptance and reconciliation.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use marty_crypto::certificate::load_certificate_pem;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

#[derive(Clone, Deserialize, Serialize)]
pub struct PassportBetaMaterialDigests {
    pub content_sha256: Vec<u8>,
    pub legacy_request_sha256: Vec<u8>,
    pub sod_der_sha256: Option<Vec<u8>>,
    pub dsc_der_sha256: Option<Vec<u8>>,
    pub dsc_pem_wire_sha256: Vec<u8>,
}

/// Compute the same tenant/source and exact-wire commitments at both ends of
/// the simulator exchange. A malformed SOD or DSC has no accepted receipt.
pub fn material_digests(
    value: &Value,
    organization_id: &str,
    job_id: &str,
    country_code: &str,
    document_type: Option<&str>,
) -> Result<PassportBetaMaterialDigests, serde_json::Error> {
    let content_identity = json!({
        "organization_id": organization_id,
        "job_id": job_id,
        "application_id": value["application_id"],
        "country_code": country_code,
        "data_groups": value["data_groups"],
        "mrz": value["mrz"],
    });
    let content_sha256 = Sha256::digest(serde_json::to_vec(&content_identity)?).to_vec();
    let mut legacy_identity = content_identity;
    legacy_identity["document_type"] = json!(document_type);
    let legacy_request_sha256 = Sha256::digest(serde_json::to_vec(&legacy_identity)?).to_vec();
    let sod_der_sha256 = value["sod_der_base64"]
        .as_str()
        .and_then(|encoded| STANDARD.decode(encoded).ok())
        .map(|der| Sha256::digest(der).to_vec());
    let dsc_pem = value["dsc_cert_pem"].as_str().unwrap_or_default();
    let dsc_der_sha256 = load_certificate_pem(dsc_pem)
        .ok()
        .map(|der| Sha256::digest(der).to_vec());
    let dsc_pem_wire_sha256 = Sha256::digest(dsc_pem.as_bytes()).to_vec();
    Ok(PassportBetaMaterialDigests {
        content_sha256,
        legacy_request_sha256,
        sod_der_sha256,
        dsc_der_sha256,
        dsc_pem_wire_sha256,
    })
}
