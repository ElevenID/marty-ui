// Frozen strict issuer admission from UI a1fc4c93d3e974c9abe682bba128ad509d23fc89.
// The only local scaffold is its error type; admission functions and format lists
// are exact released source. Keep this old-reader control historical.
#[derive(Debug, Eq, PartialEq)]
pub enum CredentialIssuanceError { UnsupportedFormat(String) }

const SD_JWT_PAYLOAD_FORMATS: &[&str] = &[
    "w3c_vcdm_v2_sd_jwt",
    "ietf_sd_jwt",
    "sd_jwt_vc",
    "vc+sd_jwt",
    "dc+sd_jwt",
];

const JWT_VC_PAYLOAD_FORMATS: &[&str] = &[
    "jwt_vc",
    "jwt_vc_json",
    "w3c_vcdm_v2_jwt",
    "w3c_vcdm_v2_jwt_vc",
];

const MDOC_PAYLOAD_FORMATS: &[&str] = &["mso_mdoc", "mdoc"];

const DATA_INTEGRITY_PAYLOAD_FORMATS: &[&str] = &["json_ld", "ldp_vc", "w3c_vcdm_v2_di"];

pub(crate) fn remote_credential_format(
    payload_format: &str,
) -> Result<String, CredentialIssuanceError> {
    let normalized = normalize_format(payload_format);
    if MDOC_PAYLOAD_FORMATS.contains(&normalized.as_str()) {
        Ok("mso_mdoc".to_owned())
    } else if DATA_INTEGRITY_PAYLOAD_FORMATS.contains(&normalized.as_str()) {
        Ok("ldp_vc".to_owned())
    } else if SD_JWT_PAYLOAD_FORMATS.contains(&normalized.as_str()) {
        Ok("dc+sd-jwt".to_owned())
    } else if JWT_VC_PAYLOAD_FORMATS.contains(&normalized.as_str()) {
        Ok("jwt_vc_json".to_owned())
    } else {
        Err(CredentialIssuanceError::UnsupportedFormat(normalized))
    }
}

fn normalize_format(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace('-', "_")
}
