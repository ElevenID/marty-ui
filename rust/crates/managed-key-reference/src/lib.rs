//! Stable tenant namespace for standard remote bootstrap keys, not registered holder keys.

pub const MANAGED_KEY_PREFIXES: &[&str] = &[
    "cred-issuer-",
    "cred-dsc-",
    "lti-tool-",
    "oid4vp-verifier-",
    "cred-holder-",
    "cred-presenter-",
];

/// Preserve raw organization bytes and the standard key suffix exactly.
pub fn tenant_standard_key_reference(org: &str, id: &str) -> Option<String> {
    let prefix = MANAGED_KEY_PREFIXES
        .iter()
        .find(|prefix| id.starts_with(**prefix))?;
    let tenant = uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL, org.as_bytes())
        .simple()
        .to_string();
    Some(format!("{prefix}{tenant}-{}", &id[prefix.len()..]))
}

/// Only the two managed profiles consumed by the installed self-host journey.
pub fn selfhost_reference(org: &str, purpose: &str) -> Option<String> {
    let id = match purpose {
        "vc_jwt_issuer" => "cred-issuer-marty-es256",
        "oid4vp_request_signing" => "oid4vp-verifier-marty-es256",
        _ => return None,
    };
    tenant_standard_key_reference(org, id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_names_and_raw_organization_bytes_remain_stable() {
        for (org, namespace) in [
            (
                "00000000-0000-0000-0000-000000000001",
                "52224a0cec8a56149d0967de03fadd5c",
            ),
            ("Acme", "fc98e4867bf95735b25748954893b06b"),
            ("acme", "7efecc64b5ed5dbfb37990a0ffcfe6df"),
        ] {
            for prefix in MANAGED_KEY_PREFIXES {
                assert_eq!(
                    tenant_standard_key_reference(org, &format!("{prefix}marty-es256")),
                    Some(format!("{prefix}{namespace}-marty-es256"))
                );
            }
            assert_eq!(
                selfhost_reference(org, "vc_jwt_issuer"),
                Some(format!("cred-issuer-{namespace}-marty-es256"))
            );
            assert_eq!(
                selfhost_reference(org, "oid4vp_request_signing"),
                Some(format!("oid4vp-verifier-{namespace}-marty-es256"))
            );
        }
        assert!(tenant_standard_key_reference("org", "unknown-key").is_none());
        assert!(selfhost_reference("org", "holder_binding").is_none());
    }
}
