//! Nonsecret issuer metadata from the signing-key registry. Key material stays
//! in the managed signing service.

use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuerProfileContext {
    pub issuer_profile_id: String,
    pub issuer_did: String,
    pub signing_service_id: String,
    pub signing_key_reference: String,
    pub verification_method_id: String,
}

impl TryFrom<&Value> for IssuerProfileContext {
    type Error = String;

    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        fn required(value: &Value, field: &str) -> Result<String, String> {
            value[field]
                .as_str()
                .map(str::trim)
                .filter(|text| !text.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| format!("Signing registry issuer context missing {field}"))
        }
        Ok(Self {
            issuer_profile_id: required(value, "issuer_profile_id")?,
            issuer_did: required(value, "issuer_did")?,
            signing_service_id: required(value, "signing_service_id")?,
            signing_key_reference: required(value, "signing_key_reference")?,
            verification_method_id: required(value, "verification_method_id")?,
        })
    }
}
