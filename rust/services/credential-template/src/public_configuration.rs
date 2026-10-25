//! Public derivation configuration must remain readable after persistence.
use crate::CredentialTemplateError;
use serde_json::Value;

pub fn validate_derivation_parameters(
    value: &Value,
    depth: usize,
) -> Result<(), CredentialTemplateError> {
    let invalid = || {
        CredentialTemplateError::InvalidConfiguration(
            "Derivation parameters contain private custody fields or excessive nesting".into(),
        )
    };
    if depth > 48 {
        return Err(invalid());
    }
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                if [
                    "key_reference",
                    "signing_service_id",
                    "signing_key_reference",
                    "issuer_profile_id",
                    "private_key",
                    "privatekeyjwk",
                    "access_token",
                    "auth_token",
                    "api_key",
                    "client_secret",
                ]
                .contains(&key.to_ascii_lowercase().as_str())
                {
                    return Err(invalid());
                }
                validate_derivation_parameters(value, depth + 1)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                validate_derivation_parameters(value, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}
