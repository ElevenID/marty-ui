//! Fail-closed admission checks for public metadata and document stores.

use serde_json::{Map, Value};

/// Detect private key material in JSON values, including JSON-encoded strings.
#[must_use]
pub fn contains_private_key(value: &Value) -> bool {
    contains_private_key_inner(value, 0)
}

/// Check a JSON object without cloning it into a `Value`.
#[must_use]
pub fn contains_private_key_map(values: &Map<String, Value>) -> bool {
    contains_private_key_map_inner(values, 0)
}

fn contains_private_key_inner(value: &Value, depth: usize) -> bool {
    // Bound repeated decoding so nested strings cannot consume unbounded stack/CPU.
    if depth > 16 {
        return true;
    }
    match value {
        Value::String(value) => {
            if has_private_key_marker(value) {
                return true;
            }
            let trimmed = value.trim_start();
            if !(trimmed.starts_with('{') || trimmed.starts_with('[')) {
                return false;
            }
            serde_json::from_str::<Value>(trimmed)
                .is_ok_and(|decoded| contains_private_key_inner(&decoded, depth + 1))
        }
        Value::Array(values) => values
            .iter()
            .any(|value| contains_private_key_inner(value, depth + 1)),
        Value::Object(values) => contains_private_key_map_inner(values, depth),
        _ => false,
    }
}

fn contains_private_key_map_inner(values: &Map<String, Value>, depth: usize) -> bool {
    if depth > 16 {
        return true;
    }
    let private_named_field = values.iter().any(|(name, value)| {
        let normalized = name
            .chars()
            .filter(|character| character.is_ascii_alphanumeric())
            .flat_map(char::to_lowercase)
            .collect::<String>();
        !value.is_null()
            && (normalized.contains("privatekey")
                || normalized.contains("privatejwk")
                || normalized.contains("privatepem")
                || normalized.contains("secretkey")
                || normalized.contains("pkcs8"))
    });
    let private_jwk = values.contains_key("kty")
        && ["d", "p", "q", "dp", "dq", "qi", "oth", "k", "rsa_d"]
            .iter()
            .any(|name| values.get(*name).is_some_and(|value| !value.is_null()));
    private_named_field
        || private_jwk
        || values
            .values()
            .any(|value| contains_private_key_inner(value, depth + 1))
}

/// Detect PEM-encoded private keys in otherwise public text fields.
#[must_use]
pub fn has_private_key_marker(value: &str) -> bool {
    value.contains("-----BEGIN") && value.contains("PRIVATE KEY-----")
}

#[cfg(test)]
mod tests {
    use super::contains_private_key;
    use serde_json::json;

    #[test]
    fn rejects_nested_or_encoded_private_material() {
        for value in [
            json!({"privateKeyJwk": "opaque-secret-bytes"}),
            json!({"privateKeyMultibase": "opaque-secret-bytes"}),
            json!({"private_jwk": "opaque-secret-bytes"}),
            json!({"sender_x25519_private_key": "opaque-secret-bytes"}),
            json!({"issuerPrivateKeyPem": "opaque-secret-bytes"}),
            json!({"private_pem": "opaque-secret-bytes"}),
            json!({"secret_key_der": "opaque-secret-bytes"}),
            json!({"metadata": "{\"kty\":\"EC\",\"d\":\"opaque-secret-bytes\"}"}),
            json!({"metadata": {"kty": "RSA", "rsa_d": "opaque-secret-bytes"}}),
            json!({"metadata": "[\"{\\\"kty\\\":\\\"oct\\\",\\\"k\\\":\\\"opaque-secret-bytes\\\"}\"]"}),
            json!({"note": "-----BEGIN PRIVATE KEY-----\\nopaque\\n-----END PRIVATE KEY-----"}),
        ] {
            assert!(contains_private_key(&value), "accepted {value}");
        }
    }

    #[test]
    fn preserves_public_keys_and_remote_references() {
        assert!(!contains_private_key(&json!({
            "public_jwk": {"kty": "OKP", "crv": "Ed25519", "x": "public-only"},
            "key_reference": "transit/keys/issuer-v4",
            "metadata": "{\"note\":\"public certificate\"}"
        })));
    }
}
