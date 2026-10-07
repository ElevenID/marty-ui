use serde_json::Value;

pub(crate) fn contains_private_key(value: &Value) -> bool {
    contains_private_key_inner(value, 0)
}

fn contains_private_key_inner(value: &Value, depth: usize) -> bool {
    // A field may carry a JSON-encoded JWK string. Bound repeated decoding so
    // an attacker cannot use nested strings to consume unbounded stack/CPU.
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
        Value::Object(values) => {
            let private_named_field = values.iter().any(|(name, value)| {
                let normalized = name
                    .chars()
                    .filter(|character| character.is_ascii_alphanumeric())
                    .flat_map(char::to_lowercase)
                    .collect::<String>();
                !value.is_null()
                    && (normalized.starts_with("privatekey")
                        || normalized.starts_with("secretkey")
                        || normalized.starts_with("pkcs8"))
            });
            let private_jwk = values.contains_key("kty")
                && ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]
                    .iter()
                    .any(|name| values.get(*name).is_some_and(|value| !value.is_null()));
            private_named_field
                || private_jwk
                || values
                    .values()
                    .any(|value| contains_private_key_inner(value, depth + 1))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::contains_private_key;
    use serde_json::json;

    #[test]
    fn rejects_private_jwk_in_named_or_encoded_metadata() {
        for value in [
            json!({"privateKeyJwk": "opaque-secret-bytes"}),
            json!({"privateKeyMultibase": "opaque-secret-bytes"}),
            json!({"secret_key_der": "opaque-secret-bytes"}),
            json!({"metadata": "{\"kty\":\"EC\",\"d\":\"opaque-secret-bytes\"}"}),
            json!({"metadata": "[\"{\\\"kty\\\":\\\"oct\\\",\\\"k\\\":\\\"opaque-secret-bytes\\\"}\"]"}),
        ] {
            assert!(contains_private_key(&value), "accepted {value}");
        }
    }

    #[test]
    fn preserves_public_keys_and_remote_references() {
        assert!(!contains_private_key(&json!({
            "public_jwk": {"kty": "OKP", "crv": "Ed25519", "x": "public-only"},
            "key_reference": "transit/keys/issuer-v4",
            "auth_reference": "vault-token-reference",
            "metadata": "{\"note\":\"public certificate\"}"
        })));
    }
}

pub(crate) fn has_private_key_marker(value: &str) -> bool {
    value.contains("-----BEGIN") && value.contains("PRIVATE KEY-----")
}
