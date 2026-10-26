//! Canonical tenant and public-identity namespaces for remote keys.

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

pub fn managed_key_prefix_for_purpose(purpose: &str) -> Option<&'static str> {
    match purpose {
        "vc_jwt_issuer" | "jwks_signing" => Some("cred-issuer-"),
        "mdoc_dsc" | "x509_doc_signer" | "vdsnc_signing" | "csca" => Some("cred-dsc-"),
        "lti_tool_signing" => Some("lti-tool-"),
        "oid4vp_request_signing" => Some("oid4vp-verifier-"),
        "holder_binding" => Some("cred-holder-"),
        "presentation_signing" => Some("cred-presenter-"),
        _ => None,
    }
}

/// Preserve the existing public API's exact tuple encoding and key names.
pub fn issuer_identity_reference(
    org: &str,
    issuer_did: &str,
    purpose: &str,
    credential_format: &str,
    algorithm: &str,
) -> String {
    let tuple = format!("{org}|{issuer_did}|{purpose}|{credential_format}|{algorithm}");
    let token = uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL, tuple.as_bytes())
        .simple()
        .to_string();
    let prefix = managed_key_prefix_for_purpose(purpose).unwrap_or("cred-issuer-");
    format!(
        "{prefix}{}-{}",
        &token[..20],
        algorithm.to_ascii_lowercase()
    )
}

/// The installed journey creates these two identities through the public API.
pub fn selfhost_reference(org: &str, issuer_did: &str, purpose: &str) -> Option<String> {
    if !matches!(purpose, "vc_jwt_issuer" | "oid4vp_request_signing") {
        return None;
    }
    Some(issuer_identity_reference(
        org,
        issuer_did,
        purpose,
        "SD_JWT_VC",
        "ES256",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_identity_names_preserve_bytes_and_bind_the_full_tuple() {
        let org = "00000000-0000-0000-0000-000000000001";
        let did = "did:web:marty.test:orgs:marty";
        let reference = issuer_identity_reference(org, did, "vc_jwt_issuer", "SD_JWT_VC", "ES256");
        assert_eq!(reference, "cred-issuer-dcd4d4b4b9575a019d8a-es256");
        assert_eq!(
            selfhost_reference(org, did, "vc_jwt_issuer"),
            Some(reference.clone())
        );
        assert_eq!(
            selfhost_reference(org, did, "oid4vp_request_signing").as_deref(),
            Some("oid4vp-verifier-f9483881590356239d44-es256")
        );
        for tuple in [
            ("another-org", did, "vc_jwt_issuer", "SD_JWT_VC", "ES256"),
            (
                org,
                "did:web:another",
                "vc_jwt_issuer",
                "SD_JWT_VC",
                "ES256",
            ),
            (org, did, "oid4vp_request_signing", "SD_JWT_VC", "ES256"),
            (org, did, "vc_jwt_issuer", "VC_JWT", "ES256"),
            (org, did, "vc_jwt_issuer", "SD_JWT_VC", "ES384"),
        ] {
            assert_ne!(
                reference,
                issuer_identity_reference(tuple.0, tuple.1, tuple.2, tuple.3, tuple.4)
            );
        }
    }

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
        }
        assert!(tenant_standard_key_reference("org", "unknown-key").is_none());
        assert!(selfhost_reference("org", "did:example:issuer", "holder_binding").is_none());
    }
}
