//! Shared HAIP public-key and scoped KMS-reference validation.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::Value;

pub fn valid_version(version: &str) -> bool {
    version.len() == 32
        && version
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn version_for<'a>(
    reference: &'a str,
    organization_id: &str,
    flow_id: &str,
) -> Option<&'a str> {
    let parts: Vec<_> = reference.split('/').collect();
    match parts.as_slice() {
        ["didcomm", "haip", "keys", tenant, flow, "versions", version]
            if *tenant == organization_id && *flow == flow_id && valid_version(version) =>
        {
            Some(version)
        }
        _ => None,
    }
}

fn kid_matches_version(kid: &str, version: &str) -> bool {
    valid_version(version) && kid == format!("oid4vp-haip-{version}")
}

pub fn matches_public_jwk(public: &Value, version: &str) -> bool {
    let Some(object) = public.as_object() else {
        return false;
    };
    if object.len() != 7
        || public["kty"] != "EC"
        || public["crv"] != "P-256"
        || public["alg"] != "ECDH-ES"
        || public["use"] != "enc"
        || !public["kid"]
            .as_str()
            .is_some_and(|kid| kid_matches_version(kid, version))
    {
        return false;
    }
    let (Some(x), Some(y)) = (public["x"].as_str(), public["y"].as_str()) else {
        return false;
    };
    let (Ok(x), Ok(y)) = (URL_SAFE_NO_PAD.decode(x), URL_SAFE_NO_PAD.decode(y)) else {
        return false;
    };
    if x.len() != 32 || y.len() != 32 {
        return false;
    }
    let mut point = Vec::with_capacity(65);
    point.push(4);
    point.extend_from_slice(&x);
    point.extend_from_slice(&y);
    p256::PublicKey::from_sec1_bytes(&point).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn reference_requires_exact_scope_and_version() {
        let version = "0123456789abcdef0123456789abcdef";
        let key_ref = format!("didcomm/haip/keys/org-1/flow-1/versions/{version}");
        assert_eq!(version_for(&key_ref, "org-1", "flow-1"), Some(version));
        assert!(version_for(&key_ref, "org-2", "flow-1").is_none());
        assert!(version_for(&key_ref, "org-1", "flow-2").is_none());
        assert!(version_for(&key_ref, "org/other", "flow-1").is_none());
        assert!(version_for(
            "didcomm/haip/keys/org-1/flow-1/versions/ABC",
            "org-1",
            "flow-1"
        )
        .is_none());
    }

    #[test]
    fn remote_kid_must_bind_to_exact_version_and_public_point() {
        let x = hex::decode("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
            .unwrap();
        let y = hex::decode("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
            .unwrap();
        let version = "12345678123442348234123456789abc";
        let mut public = json!({
            "kty":"EC", "crv":"P-256", "alg":"ECDH-ES", "use":"enc",
            "kid":format!("oid4vp-haip-{version}"),
            "x":URL_SAFE_NO_PAD.encode(x), "y":URL_SAFE_NO_PAD.encode(y)
        });
        assert!(matches_public_jwk(&public, version));
        assert!(!matches_public_jwk(
            &public,
            "12345678123442348234123456789abd"
        ));
        public["kid"] = json!("oid4vp-haip-12345678-1234-4234-8234-123456789abc");
        assert!(!matches_public_jwk(&public, version));
        public["kid"] = json!(format!("oid4vp-haip-{version}"));
        public["d"] = json!("private");
        assert!(!matches_public_jwk(&public, version));
    }
}
