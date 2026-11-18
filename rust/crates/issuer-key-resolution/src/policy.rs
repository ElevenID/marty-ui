//! Protocol DID trust controls shared by configuration and verification adapters.
//! A fallback decision never turns an invalid registry binding into public trust.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{canonical_method_id, valid_public_jwk, IssuerKeyResolutionError};

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResolverType {
    #[default]
    OrganizationRegistry,
    PublicDid,
    OrganizationRegistryWithPublicFallback,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct DidResolutionPolicy {
    pub resolver_type: ResolverType,
    pub allow_public_fallback: bool,
    pub cache_ttl_seconds: u64,
}

impl Default for DidResolutionPolicy {
    fn default() -> Self {
        Self {
            resolver_type: ResolverType::OrganizationRegistry,
            allow_public_fallback: false,
            cache_ttl_seconds: 300,
        }
    }
}

impl DidResolutionPolicy {
    /// An explicit source organization always requires the registry first,
    /// including when the source permits subsequent public resolution.
    #[must_use]
    pub fn registry_first(&self, organization_id: Option<&str>) -> bool {
        organization_id.is_some() || self.resolver_type != ResolverType::PublicDid
    }

    /// Only a missing/unavailable lookup can use configured fallback. A
    /// wrong-tenant, inactive, incompatible or ambiguous binding is Invalid.
    #[must_use]
    pub fn permits_fallback(&self, failure: &IssuerKeyResolutionError) -> bool {
        matches!(failure, IssuerKeyResolutionError::Unavailable)
            && (self.allow_public_fallback
                || matches!(
                    self.resolver_type,
                    ResolverType::PublicDid | ResolverType::OrganizationRegistryWithPublicFallback
                ))
    }

    /// Zero disables reuse; future timestamps never extend a cache lifetime.
    #[must_use]
    pub fn permits_cached(&self, retrieved_at: u64, now: u64) -> bool {
        self.cache_ttl_seconds > 0
            && now
                .checked_sub(retrieved_at)
                .is_some_and(|age| age <= self.cache_ttl_seconds)
    }
}

pub fn validate_source_controls(
    issuer_did: &str,
    organization_id: Option<&str>,
    verification_method_ids: &[String],
) -> Result<(), IssuerKeyResolutionError> {
    if !issuer_did.starts_with("did:")
        || issuer_did.len() <= 4
        || issuer_did.contains(['#', '?'])
        || issuer_did.chars().any(char::is_whitespace)
        || organization_id.is_some_and(|id| id.trim().is_empty() || id != id.trim())
    {
        return Err(IssuerKeyResolutionError::Invalid);
    }
    let mut seen = BTreeSet::new();
    for method in verification_method_ids {
        if !method.starts_with("did:")
            || canonical_method_id(issuer_did, method).is_none()
            || method.chars().any(char::is_whitespace)
            || !seen.insert(method)
        {
            return Err(IssuerKeyResolutionError::Invalid);
        }
    }
    Ok(())
}

/// Restrict already assertion-authorized keys to this source's DID and pins.
/// Callers must first validate the registry binding / DID document; this helper
/// cannot turn arbitrary client-supplied JWKs into trusted keys.
pub fn pin_assertion_keys(
    issuer_did: &str,
    verification_method_ids: &[String],
    keys: &[Value],
) -> Result<Vec<Value>, IssuerKeyResolutionError> {
    validate_source_controls(issuer_did, None, verification_method_ids)?;
    let mut selected = Vec::new();
    let mut seen = BTreeSet::new();
    for key in keys {
        let object = key.as_object().ok_or(IssuerKeyResolutionError::Invalid)?;
        valid_public_jwk(object)?;
        let id = object
            .get("kid")
            .and_then(Value::as_str)
            .filter(|id| id.starts_with("did:"))
            .and_then(|id| canonical_method_id(issuer_did, id))
            .ok_or(IssuerKeyResolutionError::Invalid)?;
        if !seen.insert(id.clone()) {
            return Err(IssuerKeyResolutionError::Invalid);
        }
        if verification_method_ids.is_empty() || verification_method_ids.contains(&id) {
            selected.push(key.clone());
        }
    }
    if selected.is_empty() {
        return Err(IssuerKeyResolutionError::Invalid);
    }
    Ok(selected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn scoped_resolution_never_skips_registry_and_invalid_bindings_never_fallback() {
        let policy = DidResolutionPolicy::default();
        assert!(policy.registry_first(Some("org-1")));
        assert!(!policy.permits_fallback(&IssuerKeyResolutionError::Unavailable));
        for resolver_type in [
            ResolverType::PublicDid,
            ResolverType::OrganizationRegistryWithPublicFallback,
        ] {
            let policy = DidResolutionPolicy {
                resolver_type,
                ..Default::default()
            };
            assert!(policy.registry_first(Some("org-1")));
            assert!(policy.permits_fallback(&IssuerKeyResolutionError::Unavailable));
            assert!(!policy.permits_fallback(&IssuerKeyResolutionError::Invalid));
        }
        let policy = DidResolutionPolicy {
            allow_public_fallback: true,
            ..Default::default()
        };
        assert!(policy.permits_fallback(&IssuerKeyResolutionError::Unavailable));
        assert!(!policy.permits_fallback(&IssuerKeyResolutionError::Invalid));
    }

    #[test]
    fn cache_expiry_is_bounded_and_zero_disables_reuse() {
        let mut policy = DidResolutionPolicy::default();
        assert!(policy.permits_cached(100, 400));
        assert!(!policy.permits_cached(100, 401));
        assert!(!policy.permits_cached(101, 100));
        policy.cache_ttl_seconds = 0;
        assert!(!policy.permits_cached(100, 100));
    }

    #[test]
    fn configuration_rejects_unknown_selectors_negative_ttl_and_invalid_pins() {
        for invalid in [
            json!({"resolver_url":"https://attacker.example"}),
            json!({"cache_ttl_seconds":-1}),
            json!({"resolver_type":"KMS"}),
        ] {
            assert!(serde_json::from_value::<DidResolutionPolicy>(invalid).is_err());
        }
        for pins in [
            vec!["did:web:other.example#key".into()],
            vec!["#key".into()],
            vec!["did:web:issuer.example#key".into(); 2],
        ] {
            assert!(
                validate_source_controls("did:web:issuer.example", Some("org-1"), &pins).is_err()
            );
        }
        assert!(validate_source_controls("did:web:issuer.example", Some(" "), &[]).is_err());
    }

    #[test]
    fn pins_select_only_matching_public_methods_and_reject_ambiguous_keys() {
        let did = "did:web:issuer.example";
        let key = json!({"kty":"EC","crv":"P-256","x":"x","y":"y","kid":format!("{did}#one")});
        let mut second = key.clone();
        second["kid"] = json!(format!("{did}#two"));
        assert_eq!(
            pin_assertion_keys(did, &[format!("{did}#two")], &[key.clone(), second.clone()])
                .unwrap(),
            vec![second]
        );
        assert!(
            pin_assertion_keys(did, &[format!("{did}#missing")], std::slice::from_ref(&key))
                .is_err()
        );
        assert!(pin_assertion_keys(did, &[], &[key.clone(), key.clone()]).is_err());
        let mut private = key.clone();
        private["d"] = json!("secret");
        assert!(pin_assertion_keys(did, &[], &[private]).is_err());
        assert!(pin_assertion_keys("did:web:other.example", &[], &[key]).is_err());
    }
}
