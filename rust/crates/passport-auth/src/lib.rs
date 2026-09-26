//! One credential per organization for the physical-document HTTP boundary.
//! This keyring does not authorize job ownership by itself: repository reads
//! and writes must still be scoped to the authenticated organization.

use std::{collections::BTreeMap, fmt};

use mmf_security::constant_time_secret_eq;
use serde::de::{MapAccess, Visitor};

#[derive(Clone, Eq, PartialEq)]
pub struct PassportTenantKeyring {
    keys: BTreeMap<String, Box<str>>,
}

/// Selects either the frozen per-tenant credential boundary or an existing
/// internal workload credential. The latter is opt-in for trusted gateway and
/// Flow handoffs; public tenant authorization must happen before forwarding.
#[derive(Clone, Eq, PartialEq)]
pub enum PassportTenantCredentialSource {
    PerTenant(PassportTenantKeyring),
    InternalServiceToken(Box<str>),
}

pub trait PassportCredentialLookup {
    fn key_for(&self, organization_id: &str) -> Option<&str>;
}

impl PassportCredentialLookup for PassportTenantKeyring {
    fn key_for(&self, organization_id: &str) -> Option<&str> {
        PassportTenantKeyring::key_for(self, organization_id)
    }
}

impl PassportCredentialLookup for PassportTenantCredentialSource {
    fn key_for(&self, organization_id: &str) -> Option<&str> {
        PassportTenantCredentialSource::key_for(self, organization_id)
    }
}

impl fmt::Debug for PassportTenantCredentialSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PerTenant(keys) => formatter.debug_tuple("PerTenant").field(keys).finish(),
            Self::InternalServiceToken(_) => {
                formatter.write_str("InternalServiceToken([REDACTED])")
            }
        }
    }
}

impl From<PassportTenantKeyring> for PassportTenantCredentialSource {
    fn from(value: PassportTenantKeyring) -> Self {
        Self::PerTenant(value)
    }
}

impl fmt::Debug for PassportTenantKeyring {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PassportTenantKeyring")
            .field("tenant_count", &self.keys.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum KeyringError {
    #[error("passport tenant key configuration is invalid")]
    InvalidJson,
    #[error("passport tenant key configuration has no tenants")]
    Empty,
    #[error("passport tenant key configuration has a duplicate organization")]
    DuplicateOrganization,
    #[error("passport tenant key configuration has a duplicate API key")]
    DuplicateKey,
    #[error("passport tenant key configuration has an invalid organization")]
    InvalidOrganization,
    #[error("passport tenant key configuration has a weak or invalid API key")]
    InvalidKey,
    #[error("passport internal service credential is weak or invalid")]
    InvalidInternalServiceToken,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PassportTenantAuthError {
    #[error("X-Organization-ID header is missing")]
    MissingOrganization,
    #[error("X-API-Key header is missing")]
    MissingKey,
    #[error("Invalid API Key")]
    InvalidKey,
}

/// An organization identity that was proven with its own passport API key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PassportTenantPrincipal {
    organization_id: String,
}

impl PassportTenantPrincipal {
    #[must_use]
    pub fn organization_id(&self) -> &str {
        &self.organization_id
    }
}

impl PassportTenantKeyring {
    pub fn from_json(value: &str) -> Result<Self, KeyringError> {
        let pairs = parse_pairs(value)?;
        if pairs.is_empty() {
            return Err(KeyringError::Empty);
        }
        let mut keys: BTreeMap<String, Box<str>> = BTreeMap::new();
        for (organization, key) in pairs {
            if !valid_organization(&organization) {
                return Err(KeyringError::InvalidOrganization);
            }
            if !valid_key(&key) {
                return Err(KeyringError::InvalidKey);
            }
            if keys
                .values()
                .any(|existing| constant_time_secret_eq(existing.as_bytes(), key.as_bytes()))
            {
                return Err(KeyringError::DuplicateKey);
            }
            keys.insert(organization, key.into_boxed_str());
        }
        Ok(Self { keys })
    }

    #[must_use]
    pub fn key_for(&self, organization_id: &str) -> Option<&str> {
        self.keys.get(organization_id).map(Box::as_ref)
    }

    pub fn authorize(
        &self,
        organization_id: &str,
        presented: Option<&str>,
    ) -> Result<(), PassportTenantAuthError> {
        self.authenticate(Some(organization_id), presented)
            .map(|_| ())
    }

    pub fn authenticate(
        &self,
        organization_id: Option<&str>,
        presented: Option<&str>,
    ) -> Result<PassportTenantPrincipal, PassportTenantAuthError> {
        let organization_id = organization_id
            .filter(|value| !value.is_empty())
            .ok_or(PassportTenantAuthError::MissingOrganization)?;
        let presented = presented
            .filter(|value| !value.is_empty())
            .ok_or(PassportTenantAuthError::MissingKey)?;
        // Unknown tenants and wrong keys share the same public result. The
        // comparison still executes for unknown tenants to avoid a trivial
        // presence oracle at this boundary.
        let expected = self
            .key_for(organization_id)
            .unwrap_or("00000000000000000000000000000000");
        let matches = constant_time_secret_eq(expected.as_bytes(), presented.as_bytes());
        if self.key_for(organization_id).is_some() && matches {
            Ok(PassportTenantPrincipal {
                organization_id: organization_id.to_owned(),
            })
        } else {
            Err(PassportTenantAuthError::InvalidKey)
        }
    }
}

impl PassportTenantCredentialSource {
    pub fn internal_service_token(value: &str) -> Result<Self, KeyringError> {
        if !valid_key(value) || value.starts_with("dev-") {
            return Err(KeyringError::InvalidInternalServiceToken);
        }
        Ok(Self::InternalServiceToken(value.into()))
    }

    #[must_use]
    pub fn key_for(&self, organization_id: &str) -> Option<&str> {
        match self {
            Self::PerTenant(keys) => keys.key_for(organization_id),
            Self::InternalServiceToken(token) if valid_organization(organization_id) => Some(token),
            Self::InternalServiceToken(_) => None,
        }
    }

    pub fn authenticate(
        &self,
        organization_id: Option<&str>,
        presented: Option<&str>,
    ) -> Result<PassportTenantPrincipal, PassportTenantAuthError> {
        match self {
            Self::PerTenant(keys) => keys.authenticate(organization_id, presented),
            Self::InternalServiceToken(expected) => {
                let organization_id = organization_id
                    .filter(|value| !value.is_empty())
                    .ok_or(PassportTenantAuthError::MissingOrganization)?;
                let presented = presented
                    .filter(|value| !value.is_empty())
                    .ok_or(PassportTenantAuthError::MissingKey)?;
                if !valid_organization(organization_id)
                    || !constant_time_secret_eq(expected.as_bytes(), presented.as_bytes())
                {
                    return Err(PassportTenantAuthError::InvalidKey);
                }
                Ok(PassportTenantPrincipal {
                    organization_id: organization_id.to_owned(),
                })
            }
        }
    }
}

fn valid_organization(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
}

fn valid_key(value: &str) -> bool {
    value.len() >= 32 && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn parse_pairs(value: &str) -> Result<Vec<(String, String)>, KeyringError> {
    struct UniquePairs;
    impl<'de> Visitor<'de> for UniquePairs {
        type Value = Vec<(String, String)>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a JSON object of organization IDs to API keys")
        }

        fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
            let mut result = Vec::new();
            while let Some((organization, key)) = map.next_entry::<String, String>()? {
                if result
                    .iter()
                    .any(|(existing, _): &(String, String)| existing == &organization)
                {
                    return Err(serde::de::Error::custom("duplicate organization"));
                }
                result.push((organization, key));
            }
            Ok(result)
        }
    }

    struct UniqueMap(Vec<(String, String)>);
    impl<'de> serde::Deserialize<'de> for UniqueMap {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            deserializer.deserialize_map(UniquePairs).map(Self)
        }
    }

    let parsed = serde_json::from_str::<UniqueMap>(value).map_err(|error| {
        if error.to_string().contains("duplicate organization") {
            KeyringError::DuplicateOrganization
        } else {
            KeyringError::InvalidJson
        }
    })?;
    Ok(parsed.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[test]
    fn internal_service_credential_is_opt_in_tenant_bound_and_redacted() {
        let source = PassportTenantCredentialSource::internal_service_token(A).unwrap();
        assert_eq!(source.key_for("org-a"), Some(A));
        assert_eq!(source.key_for("bad org"), None);
        assert_eq!(
            source
                .authenticate(Some("org-a"), Some(A))
                .unwrap()
                .organization_id(),
            "org-a"
        );
        assert_eq!(
            source.authenticate(Some("org-a"), Some(B)),
            Err(PassportTenantAuthError::InvalidKey)
        );
        assert_eq!(
            source.authenticate(Some("bad org"), Some(A)),
            Err(PassportTenantAuthError::InvalidKey)
        );
        assert!(!format!("{source:?}").contains(A));
        assert!(PassportTenantCredentialSource::internal_service_token("dev-token").is_err());
    }

    #[test]
    fn tenant_key_can_authorize_only_its_own_organization() {
        let ring =
            PassportTenantKeyring::from_json(&format!("{{\"org-a\":\"{A}\",\"org-b\":\"{B}\"}}"))
                .unwrap();
        assert_eq!(ring.key_for("org-a"), Some(A));
        assert_eq!(ring.authorize("org-a", Some(A)), Ok(()));
        assert_eq!(ring.authorize("org-b", Some(B)), Ok(()));
        assert_eq!(
            ring.authenticate(Some("org-b"), Some(B))
                .unwrap()
                .organization_id(),
            "org-b"
        );
        assert_eq!(
            ring.authorize("org-b", Some(A)),
            Err(PassportTenantAuthError::InvalidKey)
        );
        assert_eq!(
            ring.authorize("unknown", Some(A)),
            Err(PassportTenantAuthError::InvalidKey)
        );
        assert_eq!(
            ring.authorize("org-a", None),
            Err(PassportTenantAuthError::MissingKey)
        );
        assert_eq!(
            ring.authenticate(None, Some(A)),
            Err(PassportTenantAuthError::MissingOrganization)
        );
        assert!(!format!("{ring:?}").contains(A));
    }

    #[test]
    fn keyring_rejects_ambiguous_or_weak_secrets() {
        for (value, expected) in [
            ("{}".to_owned(), KeyringError::Empty),
            (
                format!("{{\"org-a\":\"{A}\",\"org-a\":\"{B}\"}}"),
                KeyringError::DuplicateOrganization,
            ),
            (
                format!("{{\"org-a\":\"{A}\",\"org-b\":\"{A}\"}}"),
                KeyringError::DuplicateKey,
            ),
            ("{\"org-a\":\"short\"}".to_owned(), KeyringError::InvalidKey),
            (
                format!("{{\"org a\":\"{A}\"}}"),
                KeyringError::InvalidOrganization,
            ),
        ] {
            assert_eq!(
                PassportTenantKeyring::from_json(&value).unwrap_err(),
                expected
            );
        }
    }
}
