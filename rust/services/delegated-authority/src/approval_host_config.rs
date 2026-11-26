//! Explicit configuration for the optional organization approval producer.
//! Secrets and connection strings are deliberately absent from diagnostics.

use std::{collections::BTreeMap, fmt, fs, net::SocketAddr};

use url::Url;
use uuid::Uuid;

use crate::{ApprovalAdapterPin, Principal, PrincipalType};

const DATABASE_FIELDS: [&str; 4] = [
    "DELEGATION_APPROVAL_RUNTIME_DATABASE_URL",
    "DELEGATION_APPROVAL_CONSENT_DATABASE_URL",
    "DELEGATION_APPROVAL_AUTHORITY_DATABASE_URL",
    "DELEGATION_APPROVAL_ORGANIZATION_DATABASE_URL",
];

#[derive(Clone)]
pub struct ApprovalHostConfig {
    pub http_addr: SocketAddr,
    pub runtime_database_url: String,
    pub consent_database_url: String,
    pub authority_database_url: String,
    pub organization_database_url: String,
    pub runtime_pool_max_connections: u32,
    pub consent_pool_max_connections: u32,
    pub authority_pool_max_connections: u32,
    pub organization_pool_max_connections: u32,
    pub service_token: String,
    pub organization_id: Uuid,
    pub issuer: Principal,
    pub pin: ApprovalAdapterPin,
    pub review_ttl_seconds: u32,
    pub confirmation_max_age_seconds: u32,
    pub authority_validity_seconds: u32,
    pub authority_refresh_seconds: u32,
}

impl fmt::Debug for ApprovalHostConfig {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.debug_struct("ApprovalHostConfig")
            .field("http_addr", &self.http_addr)
            .field("organization_id", &self.organization_id)
            .field("review_ttl_seconds", &self.review_ttl_seconds)
            .field(
                "confirmation_max_age_seconds",
                &self.confirmation_max_age_seconds,
            )
            .field(
                "authority_validity_seconds",
                &self.authority_validity_seconds,
            )
            .field("authority_refresh_seconds", &self.authority_refresh_seconds)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ApprovalHostConfigError {
    #[error(
        "delegation approval hosting requires explicit MARTY_DELEGATION_APPROVAL_ENABLED=true"
    )]
    Disabled,
    #[error("delegation approval configuration is missing or invalid: {0}")]
    Invalid(&'static str),
    #[error(
        "delegation approval secret file is unreadable or conflicts with an inline value: {0}"
    )]
    SecretFile(&'static str),
}

impl ApprovalHostConfig {
    pub fn from_env() -> Result<Self, ApprovalHostConfigError> {
        let mut values = std::env::vars().collect::<BTreeMap<_, _>>();
        for name in DATABASE_FIELDS.into_iter().chain(["GRPC_SERVICE_TOKEN"]) {
            load_secret(&mut values, name)?;
        }
        Self::from_values(values)
    }

    pub fn from_values(
        values: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, ApprovalHostConfigError> {
        let values = values.into_iter().collect::<BTreeMap<_, _>>();
        match values
            .get("MARTY_DELEGATION_APPROVAL_ENABLED")
            .map(String::as_str)
        {
            Some("true") => {}
            None | Some("false") => return Err(ApprovalHostConfigError::Disabled),
            _ => {
                return Err(ApprovalHostConfigError::Invalid(
                    "MARTY_DELEGATION_APPROVAL_ENABLED",
                ))
            }
        }
        let http_addr = values
            .get("DELEGATION_APPROVAL_HTTP_ADDR")
            .map(String::as_str)
            .unwrap_or("127.0.0.1:8019")
            .parse()
            .map_err(|_| ApprovalHostConfigError::Invalid("DELEGATION_APPROVAL_HTTP_ADDR"))?;
        let organization_id = required(&values, "DELEGATION_APPROVAL_ORGANIZATION_ID")?;
        let id = Uuid::parse_str(organization_id)
            .map_err(|_| ApprovalHostConfigError::Invalid("DELEGATION_APPROVAL_ORGANIZATION_ID"))?;
        if id.is_nil() || id.to_string() != organization_id {
            return Err(ApprovalHostConfigError::Invalid(
                "DELEGATION_APPROVAL_ORGANIZATION_ID",
            ));
        }
        let service_token = required(&values, "GRPC_SERVICE_TOKEN")?;
        if service_token.len() < 32
            || service_token.len() > 1024
            || !service_token.bytes().all(|c| (0x21..=0x7e).contains(&c))
        {
            return Err(ApprovalHostConfigError::Invalid("GRPC_SERVICE_TOKEN"));
        }
        let profile = required(&values, "DELEGATION_APPROVAL_PROFILE")?;
        if profile.len() > 512 || !crate::domain::valid_uri(Some(profile)) {
            return Err(ApprovalHostConfigError::Invalid(
                "DELEGATION_APPROVAL_PROFILE",
            ));
        }
        let version = required(&values, "DELEGATION_APPROVAL_VERSION")?;
        if !crate::consent::valid_version(version) {
            return Err(ApprovalHostConfigError::Invalid(
                "DELEGATION_APPROVAL_VERSION",
            ));
        }
        let artifact_digest = required(&values, "DELEGATION_APPROVAL_ARTIFACT_DIGEST")?;
        if !crate::consent::valid_digest(artifact_digest) {
            return Err(ApprovalHostConfigError::Invalid(
                "DELEGATION_APPROVAL_ARTIFACT_DIGEST",
            ));
        }
        let authority_validity_seconds = seconds(
            &values,
            "DELEGATION_APPROVAL_AUTHORITY_VALIDITY_SECONDS",
            15,
            15,
        )?;
        let authority_refresh_seconds = seconds(
            &values,
            "DELEGATION_APPROVAL_AUTHORITY_REFRESH_SECONDS",
            5,
            14,
        )?;
        if authority_refresh_seconds.saturating_mul(2) >= authority_validity_seconds {
            return Err(ApprovalHostConfigError::Invalid(
                "DELEGATION_APPROVAL_AUTHORITY_REFRESH_SECONDS",
            ));
        }
        Ok(Self {
            http_addr,
            runtime_database_url: database_url(&values, DATABASE_FIELDS[0])?,
            consent_database_url: database_url(&values, DATABASE_FIELDS[1])?,
            authority_database_url: database_url(&values, DATABASE_FIELDS[2])?,
            organization_database_url: database_url(&values, DATABASE_FIELDS[3])?,
            runtime_pool_max_connections: pool_limit(
                &values,
                "DELEGATION_APPROVAL_RUNTIME_POOL_MAX_CONNECTIONS",
                1,
            )?,
            consent_pool_max_connections: pool_limit(
                &values,
                "DELEGATION_APPROVAL_CONSENT_POOL_MAX_CONNECTIONS",
                1,
            )?,
            // Authority refresh holds its write transaction while reading the
            // original binding through the authority pool. It needs two leases.
            authority_pool_max_connections: pool_limit(
                &values,
                "DELEGATION_APPROVAL_AUTHORITY_POOL_MAX_CONNECTIONS",
                2,
            )?,
            organization_pool_max_connections: pool_limit(
                &values,
                "DELEGATION_APPROVAL_ORGANIZATION_POOL_MAX_CONNECTIONS",
                1,
            )?,
            service_token: service_token.to_owned(),
            organization_id: id,
            issuer: Principal {
                principal_type: PrincipalType::Organization,
                id: format!("urn:marty:organization:{id}"),
            },
            pin: ApprovalAdapterPin {
                profile: profile.to_owned(),
                version: version.to_owned(),
                artifact_digest: artifact_digest.to_owned(),
            },
            review_ttl_seconds: seconds(
                &values,
                "DELEGATION_APPROVAL_REVIEW_TTL_SECONDS",
                120,
                300,
            )?,
            confirmation_max_age_seconds: seconds(
                &values,
                "DELEGATION_APPROVAL_CONFIRMATION_MAX_AGE_SECONDS",
                300,
                300,
            )?,
            authority_validity_seconds,
            authority_refresh_seconds,
        })
    }
}

fn required<'a>(
    values: &'a BTreeMap<String, String>,
    name: &'static str,
) -> Result<&'a str, ApprovalHostConfigError> {
    values
        .get(name)
        .map(String::as_str)
        .filter(|v| !v.is_empty() && v.trim() == *v)
        .ok_or(ApprovalHostConfigError::Invalid(name))
}

fn seconds(
    values: &BTreeMap<String, String>,
    name: &'static str,
    default: u32,
    max: u32,
) -> Result<u32, ApprovalHostConfigError> {
    let result = values
        .get(name)
        .map(|v| v.parse::<u32>())
        .transpose()
        .map_err(|_| ApprovalHostConfigError::Invalid(name))?
        .unwrap_or(default);
    if !(1..=max).contains(&result) {
        return Err(ApprovalHostConfigError::Invalid(name));
    }
    Ok(result)
}

fn pool_limit(
    values: &BTreeMap<String, String>,
    name: &'static str,
    minimum: u32,
) -> Result<u32, ApprovalHostConfigError> {
    let value = seconds(values, name, 8, 8)?;
    if value < minimum {
        return Err(ApprovalHostConfigError::Invalid(name));
    }
    Ok(value)
}

fn database_url(
    values: &BTreeMap<String, String>,
    name: &'static str,
) -> Result<String, ApprovalHostConfigError> {
    let raw = required(values, name)?;
    let parsed = Url::parse(raw).map_err(|_| ApprovalHostConfigError::Invalid(name))?;
    if !matches!(parsed.scheme(), "postgres" | "postgresql")
        || parsed.host_str().is_none()
        || parsed.username().is_empty()
        || parsed.path().trim_matches('/').is_empty()
        || parsed.fragment().is_some()
    {
        return Err(ApprovalHostConfigError::Invalid(name));
    }
    Ok(raw.to_owned())
}

fn load_secret(
    values: &mut BTreeMap<String, String>,
    name: &'static str,
) -> Result<(), ApprovalHostConfigError> {
    let Some(path) = values.get(&format!("{name}_FILE")) else {
        return Ok(());
    };
    if values.contains_key(name) {
        return Err(ApprovalHostConfigError::SecretFile(name));
    }
    let secret = fs::read_to_string(path).map_err(|_| ApprovalHostConfigError::SecretFile(name))?;
    values.insert(name.into(), secret.trim_end_matches(['\r', '\n']).into());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values() -> BTreeMap<String, String> {
        let mut values = BTreeMap::from([
            ("MARTY_DELEGATION_APPROVAL_ENABLED".into(), "true".into()),
            (
                "DELEGATION_APPROVAL_ORGANIZATION_ID".into(),
                "25a96b94-637d-4ebe-8db7-d454a7130518".into(),
            ),
            (
                "GRPC_SERVICE_TOKEN".into(),
                "a-test-only-service-token-with-32-bytes".into(),
            ),
            (
                "DELEGATION_APPROVAL_PROFILE".into(),
                "urn:example:organization-approval:v1".into(),
            ),
            ("DELEGATION_APPROVAL_VERSION".into(), "1.0.0".into()),
            (
                "DELEGATION_APPROVAL_ARTIFACT_DIGEST".into(),
                format!("sha256:{}", "a".repeat(64)),
            ),
        ]);
        for (index, name) in DATABASE_FIELDS.iter().enumerate() {
            values.insert(
                (*name).into(),
                format!("postgresql://approval_role_{index}:example-secret@localhost/marty"),
            );
        }
        values
    }

    #[test]
    fn explicit_configuration_caps_authority_and_redacts_secrets() {
        let config = ApprovalHostConfig::from_values(values()).unwrap();
        assert_eq!(config.http_addr.to_string(), "127.0.0.1:8019");
        assert_eq!(config.authority_validity_seconds, 15);
        assert_eq!(config.runtime_pool_max_connections, 8);
        assert_eq!(config.consent_pool_max_connections, 8);
        assert_eq!(config.authority_pool_max_connections, 8);
        assert_eq!(config.organization_pool_max_connections, 8);
        let debug = format!("{config:?}");
        assert!(!debug.contains("example-secret"));
        assert!(!debug.contains("service-token"));
        assert!(!debug.contains("postgresql"));
    }

    #[test]
    fn native_container_http_address_is_explicit_and_invalid_values_do_not_fall_back() {
        let mut input = values();
        input.insert(
            "DELEGATION_APPROVAL_HTTP_ADDR".into(),
            "0.0.0.0:8019".into(),
        );
        let config = ApprovalHostConfig::from_values(input).unwrap();
        assert!(config.http_addr.ip().is_unspecified());
        assert_eq!(config.http_addr.port(), 8019);
        for address in ["", "http://0.0.0.0:8019", "0.0.0.0:8019\n"] {
            let mut input = values();
            input.insert("DELEGATION_APPROVAL_HTTP_ADDR".into(), address.into());
            assert_eq!(
                ApprovalHostConfig::from_values(input).unwrap_err(),
                ApprovalHostConfigError::Invalid("DELEGATION_APPROVAL_HTTP_ADDR")
            );
        }
    }

    #[test]
    fn missing_feature_or_any_credential_fails_closed() {
        let mut input = values();
        input.remove("MARTY_DELEGATION_APPROVAL_ENABLED");
        assert_eq!(
            ApprovalHostConfig::from_values(input).unwrap_err(),
            ApprovalHostConfigError::Disabled
        );
        for name in DATABASE_FIELDS.into_iter().chain(["GRPC_SERVICE_TOKEN"]) {
            let mut input = values();
            input.remove(name);
            assert_eq!(
                ApprovalHostConfig::from_values(input).unwrap_err(),
                ApprovalHostConfigError::Invalid(name)
            );
        }
    }

    #[test]
    fn rejects_weak_tokens_noncanonical_tenants_and_unbounded_freshness() {
        for (name, value) in [
            ("GRPC_SERVICE_TOKEN", "weak"),
            (
                "DELEGATION_APPROVAL_ORGANIZATION_ID",
                "25A96B94-637D-4EBE-8DB7-D454A7130518",
            ),
            (
                "DELEGATION_APPROVAL_ORGANIZATION_ID",
                "00000000-0000-0000-0000-000000000000",
            ),
            ("DELEGATION_APPROVAL_AUTHORITY_VALIDITY_SECONDS", "16"),
            ("DELEGATION_APPROVAL_AUTHORITY_REFRESH_SECONDS", "15"),
            ("DELEGATION_APPROVAL_REVIEW_TTL_SECONDS", "301"),
            ("DELEGATION_APPROVAL_CONFIRMATION_MAX_AGE_SECONDS", "0"),
            (
                "DELEGATION_APPROVAL_RUNTIME_DATABASE_URL",
                "sqlite:///tmp/approval",
            ),
        ] {
            let mut input = values();
            input.insert(name.into(), value.into());
            assert_eq!(
                ApprovalHostConfig::from_values(input).unwrap_err(),
                ApprovalHostConfigError::Invalid(name)
            );
        }
        for (name, minimum) in [
            ("DELEGATION_APPROVAL_RUNTIME_POOL_MAX_CONNECTIONS", 1),
            ("DELEGATION_APPROVAL_CONSENT_POOL_MAX_CONNECTIONS", 1),
            ("DELEGATION_APPROVAL_AUTHORITY_POOL_MAX_CONNECTIONS", 2),
            ("DELEGATION_APPROVAL_ORGANIZATION_POOL_MAX_CONNECTIONS", 1),
        ] {
            for invalid in ["0", "9", "-1", "", " 2", "4294967296"] {
                let mut input = values();
                input.insert(name.into(), invalid.into());
                assert_eq!(
                    ApprovalHostConfig::from_values(input).unwrap_err(),
                    ApprovalHostConfigError::Invalid(name)
                );
            }
            let mut input = values();
            input.insert(name.into(), minimum.to_string());
            let config = ApprovalHostConfig::from_values(input).unwrap();
            let actual = match name {
                "DELEGATION_APPROVAL_RUNTIME_POOL_MAX_CONNECTIONS" => {
                    config.runtime_pool_max_connections
                }
                "DELEGATION_APPROVAL_CONSENT_POOL_MAX_CONNECTIONS" => {
                    config.consent_pool_max_connections
                }
                "DELEGATION_APPROVAL_AUTHORITY_POOL_MAX_CONNECTIONS" => {
                    config.authority_pool_max_connections
                }
                _ => config.organization_pool_max_connections,
            };
            assert_eq!(actual, minimum);
        }
        let mut input = values();
        input.insert(
            "DELEGATION_APPROVAL_AUTHORITY_POOL_MAX_CONNECTIONS".into(),
            "1".into(),
        );
        assert_eq!(
            ApprovalHostConfig::from_values(input).unwrap_err(),
            ApprovalHostConfigError::Invalid("DELEGATION_APPROVAL_AUTHORITY_POOL_MAX_CONNECTIONS")
        );
    }
}
