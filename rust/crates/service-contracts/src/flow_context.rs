//! Names reserved for trusted Flow state or private caller material.

const PRIVATE_CONTEXT_PREFIX: &str = "_marty_";
const PRIVATE_CONTEXT_KEYS: &[&str] = &[
    "issuer_profile_id",
    "issuer_key_id",
    "issuer_algorithm",
    "key_access_mode",
    "verification_method_id",
    "signing_service_id",
    "signing_key_reference",
    "key_reference",
    "kms_provider",
    "provider",
    "key_name",
    "key_version",
    "transit_mount",
    "pre_auth_code",
    "pre_authorized_code",
    "pre-authorized-code",
    "access_token",
    "refresh_token",
    "client_secret",
    "private_key",
    "private_key_jwk",
    "session_token",
    "api_key",
];

/// Preserve the Flow domain's ASCII-case key policy without allocating a
/// lowercase copy. Non-ASCII values after the reserved prefix remain private.
#[must_use]
pub fn is_private_context_key(key: &str) -> bool {
    key.get(..PRIVATE_CONTEXT_PREFIX.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(PRIVATE_CONTEXT_PREFIX))
        || PRIVATE_CONTEXT_KEYS
            .iter()
            .any(|reserved| key.eq_ignore_ascii_case(reserved))
}

#[cfg(test)]
mod tests {
    use super::is_private_context_key;

    #[test]
    fn trusted_state_and_credentials_are_reserved_in_ascii_case_variants() {
        for key in [
            "_marty_",
            "_MARTY_precondition_evidence_v1",
            "_marty_非公開",
            "access_TOKEN",
            "Pre-Authorized-Code",
            "ISSUER_KEY_ID",
            "api_key",
        ] {
            assert!(is_private_context_key(key), "{key}");
        }
    }

    #[test]
    fn public_names_and_unicode_folding_keep_the_domain_contract() {
        for key in [
            "",
            "_marty",
            "marty_key",
            "visible",
            "key_id",
            "api_Key",
            "pré_auth_code",
        ] {
            assert!(!is_private_context_key(key), "{key}");
        }
    }
}
