//! Fail-closed admission checks for public metadata and document stores.

use marty_response_compat::lossless_json_tree::{JsonNode, JsonTree};
use serde_json::{Map, Value};

const PRIVATE_JWK_MEMBERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// Enumerate prohibited members of an object being admitted as a public JWK.
///
/// Presence is enough: null or empty private members are rejected too. Unlike
/// the recursive metadata scanner, this is a strict top-level JWK shape check
/// and does not require `kty` to be present. Callers retain algorithm, public
/// coordinate, and metadata validation.
pub fn private_jwk_members(jwk: &Map<String, Value>) -> impl Iterator<Item = &'static str> + '_ {
    PRIVATE_JWK_MEMBERS
        .iter()
        .copied()
        .filter(|member| jwk.contains_key(*member))
}

fn is_private_jwk_field(name: &str) -> bool {
    PRIVATE_JWK_MEMBERS.contains(&name) || name == "rsa_d"
}

/// Detect populated private JWK fields, including the legacy `rsa_d` alias.
///
/// Null values are permitted and `kty` is not required. Use this for metadata
/// updates; public JWK shape admission must use `private_jwk_members` instead.
#[must_use]
pub fn contains_populated_private_jwk_fields(values: &Map<String, Value>) -> bool {
    values
        .iter()
        .any(|(name, value)| !value.is_null() && is_private_jwk_field(name))
}

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

fn contains_private_key_inner(value: &Value, decoded_depth: usize) -> bool {
    // Walk parsed JSON iteratively: Canvas credentials can legitimately have
    // thousands of array levels. Only repeated string decoding needs a cap.
    if decoded_depth > 16 {
        return true;
    }
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        match value {
            Value::String(value) => {
                if has_private_key_marker(value) {
                    return true;
                }
                let trimmed = value.trim_start();
                if trimmed.starts_with('{') || trimmed.starts_with('[') {
                    let decoded = contains_private_key_json_inner(trimmed, decoded_depth + 1)
                        .unwrap_or(false);
                    if decoded {
                        return true;
                    }
                }
            }
            Value::Array(values) => pending.extend(values),
            Value::Object(values) => {
                if has_private_key_fields(values) {
                    return true;
                }
                pending.extend(values.values());
            }
            _ => {}
        }
    }
    false
}

fn contains_private_key_map_inner(values: &Map<String, Value>, decoded_depth: usize) -> bool {
    has_private_key_fields(values)
        || values
            .values()
            .any(|value| contains_private_key_inner(value, decoded_depth))
}

fn has_private_key_fields(values: &Map<String, Value>) -> bool {
    let private_named_field = values
        .iter()
        .any(|(name, value)| !value.is_null() && is_private_field_name(name));
    let private_jwk = values.contains_key("kty") && contains_populated_private_jwk_fields(values);
    private_named_field || private_jwk
}

fn is_private_field_name(name: &str) -> bool {
    let normalized = name
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect::<String>();
    [
        "privatekey",
        "privatejwk",
        "privatepem",
        "secretkey",
        "pkcs8",
    ]
    .iter()
    .any(|part| normalized.contains(part))
}

/// Scan JSON text with the depth-safe parser used by Canvas response handling.
/// `None` means the text is not valid JSON.
#[must_use]
pub fn contains_private_key_json(raw: &str) -> Option<bool> {
    contains_private_key_json_inner(raw, 0)
}

fn contains_private_key_json_inner(raw: &str, decoded_depth: usize) -> Option<bool> {
    if decoded_depth > 16 {
        return Some(true);
    }
    let tree = JsonTree::from_json_bytes_preserving_duplicates(raw.as_bytes())?;
    let mut pending = vec![tree.root()];
    while let Some(id) = pending.pop() {
        let text = match tree.node(id) {
            JsonNode::Text(value) => value.as_scalar(),
            JsonNode::Scalar(Value::String(value)) => Some(value.as_str()),
            _ => None,
        };
        if let Some(value) = text {
            if has_private_key_marker(value) {
                return Some(true);
            }
            let trimmed = value.trim_start();
            if (trimmed.starts_with('{') || trimmed.starts_with('['))
                && contains_private_key_json_inner(trimmed, decoded_depth + 1).unwrap_or(false)
            {
                return Some(true);
            }
        }
        match tree.node(id) {
            JsonNode::Array(children) => pending.extend(children.iter().copied()),
            JsonNode::Object(entries) => {
                let has_kty = entries
                    .iter()
                    .any(|(name, _)| name.as_scalar() == Some("kty"));
                for (name, child) in entries {
                    if let Some(name) = name.as_scalar() {
                        let populated = !matches!(tree.node(*child), JsonNode::Scalar(Value::Null));
                        if populated
                            && (is_private_field_name(name)
                                || (has_kty && is_private_jwk_field(name)))
                        {
                            return Some(true);
                        }
                    }
                    pending.push(*child);
                }
            }
            _ => {}
        }
    }
    Some(false)
}

/// Detect PEM-encoded private keys in otherwise public text fields.
#[must_use]
pub fn has_private_key_marker(value: &str) -> bool {
    value.contains("-----BEGIN") && value.contains("PRIVATE KEY-----")
}

#[cfg(test)]
mod tests {
    use super::{
        contains_populated_private_jwk_fields, contains_private_key, contains_private_key_json,
        private_jwk_members,
    };
    use serde_json::json;

    #[test]
    fn populated_policy_preserves_null_and_kty_boundaries_in_both_scanners() {
        for member in ["d", "p", "q", "dp", "dq", "qi", "oth", "k", "rsa_d"] {
            for value in [
                json!(null),
                json!(""),
                json!(false),
                json!(0),
                json!([]),
                json!({}),
                json!("secret"),
            ] {
                let populated = !value.is_null();
                for has_kty in [false, true] {
                    let mut object = serde_json::Map::new();
                    object.insert(member.into(), value.clone());
                    if has_kty {
                        // Existing metadata policy tests presence, not the value of kty.
                        object.insert("kty".into(), json!(null));
                    }
                    assert_eq!(contains_populated_private_jwk_fields(&object), populated);
                    assert_eq!(
                        private_jwk_members(&object).next().is_some(),
                        member != "rsa_d"
                    );
                    let nested = json!({"metadata": [object]});
                    let expected = populated && has_kty;
                    assert_eq!(contains_private_key(&nested), expected, "{nested}");
                    let raw = nested.to_string();
                    assert_eq!(contains_private_key_json(&raw), Some(expected), "{raw}");
                    assert_eq!(contains_private_key(&json!(raw)), expected);
                }
            }
        }
    }

    #[test]
    fn lossless_policy_checks_populated_duplicate_members_in_either_order() {
        for member in ["d", "p", "q", "dp", "dq", "qi", "oth", "k", "rsa_d"] {
            for values in ["null,\"secret\"", "\"secret\",null"] {
                let (first, second) = values.split_once(',').unwrap();
                let raw = format!(r#"{{"kty":"RSA","{member}":{first},"{member}":{second}}}"#);
                assert_eq!(contains_private_key_json(&raw), Some(true), "{raw}");
                assert!(contains_private_key(&json!({"metadata": raw})), "{raw}");
            }
        }
    }

    #[test]
    fn encoded_admission_checks_overwritten_objects_and_allows_public_duplicates() {
        for raw in [
            r#"{"publicKeyJwk":{"kty":"RSA","d":"secret"},"publicKeyJwk":null}"#,
            r#"{"kty":"RSA","d":"secret","\u0064":null}"#,
            r#"{"private_key":"secret","private_key":null}"#,
        ] {
            assert_eq!(contains_private_key_json(raw), Some(true));
            assert!(contains_private_key(&json!({"metadata": raw})));
        }
        for raw in [
            r#"{"kty":"RSA","d":null,"d":null}"#,
            r#"{"note":"public","note":"also public"}"#,
            r#"{"key_reference":"transit/keys/a","key_reference":"transit/keys/b"}"#,
        ] {
            assert_eq!(contains_private_key_json(raw), Some(false));
            assert!(!contains_private_key(&json!({"metadata": raw})));
        }
    }

    #[test]
    fn public_jwk_admission_rejects_private_members_even_when_empty_or_null() {
        let invalid = json!({
            "d": null, "p": "", "q": false, "dp": 0,
            "dq": [], "qi": {}, "oth": null, "k": "symmetric-secret"
        });
        let mut rejected = private_jwk_members(invalid.as_object().unwrap()).collect::<Vec<_>>();
        rejected.sort_unstable();
        assert_eq!(rejected, ["d", "dp", "dq", "k", "oth", "p", "q", "qi"]);

        // Metadata admission intentionally permits an unused null field, but
        // public JWK admission must reject the private member's presence.
        let null_private = json!({"kty": "EC", "d": null});
        assert!(!contains_private_key(&null_private));
        assert_eq!(
            private_jwk_members(null_private.as_object().unwrap()).next(),
            Some("d")
        );
    }

    #[test]
    fn public_jwk_admission_keeps_public_coordinates_and_remote_key_references() {
        for public in [
            json!({"kty":"EC", "crv":"P-256", "x":"public-x", "y":"public-y"}),
            json!({"kty":"OKP", "crv":"Ed25519", "x":"public-x"}),
            json!({"kty":"RSA", "n":"public-n", "e":"AQAB", "kid":"did:web:issuer#key"}),
            json!({"key_reference":"transit/keys/issuer", "x5c":["public-certificate"]}),
        ] {
            assert!(private_jwk_members(public.as_object().unwrap())
                .next()
                .is_none());
        }
    }

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

    #[test]
    fn deep_public_json_is_allowed_but_deep_private_material_is_rejected() {
        let mut public = json!({"key_reference": "transit/keys/issuer-v4"});
        let mut private = json!({"kty": "OKP", "d": "private-material"});
        for _ in 0..126 {
            public = json!([public]);
            private = json!([private]);
        }
        assert!(!contains_private_key(&public));
        assert!(contains_private_key(&private));
        let deep_public = format!(
            "{}{{\"key_reference\":\"transit/keys/issuer-v4\"}}{}",
            "[".repeat(1600),
            "]".repeat(1600)
        );
        let deep_private = format!(
            "{}{{\"kty\":\"OKP\",\"d\":\"private-material\"}}{}",
            "[".repeat(1600),
            "]".repeat(1600)
        );
        assert_eq!(contains_private_key_json(&deep_public), Some(false));
        assert_eq!(contains_private_key_json(&deep_private), Some(true));
        assert!(!contains_private_key(&json!(deep_public)));
        assert!(contains_private_key(&json!(deep_private)));
    }
}
