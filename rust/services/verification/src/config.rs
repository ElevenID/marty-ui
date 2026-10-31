use std::{collections::BTreeMap, fmt, net::SocketAddr, time::Duration};

use thiserror::Error;
use url::Url;

use crate::{
    credentials_compat::{GovernanceEngine, ProcessingLease},
    GrpcProviderConfig, WorkloadClientTlsFiles,
};

const DEFAULT_HTTP_ADDR: &str = "0.0.0.0:8012";
const DEFAULT_GRPC_ADDR: &str = "0.0.0.0:9017";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Environment {
    Development,
    Test,
    Beta,
    Production,
}

impl Environment {
    #[must_use]
    pub const fn is_deployed(self) -> bool {
        matches!(self, Self::Beta | Self::Production)
    }
}

#[derive(Clone)]
pub struct VerificationServiceConfig {
    pub environment: Environment,
    pub http_addr: SocketAddr,
    pub grpc_addr: SocketAddr,
    pub grpc_enabled: bool,
    pub public_base_url: String,
    pub redis_url: Option<String>,
    pub credentials_compat_enabled: bool,
    pub credentials_governance: Option<GovernanceEngine>,
    pub credentials_database_url: Option<String>,
    pub credentials_processing_lease: ProcessingLease,
    pub credentials_resolver: Option<IssuerResolverConfig>,
    pub providers: GrpcProviderConfig,
    pub release_version: String,
    pub build_revision: String,
}

#[derive(Clone)]
pub struct IssuerResolverConfig {
    pub base_url: String,
    api_key: String,
    pub did_web_allowed_hosts: Vec<String>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct VerificationMigrationConfig {
    database_url: String,
}

impl VerificationMigrationConfig {
    pub fn from_env() -> Result<Self, VerificationConfigError> {
        Self::from_values(std::env::vars())
    }

    pub fn from_values(
        values: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, VerificationConfigError> {
        let values = values.into_iter().collect::<BTreeMap<_, _>>();
        let database_url = value(&values, "DATABASE_URL")
            .ok_or(VerificationConfigError::Missing {
                name: "DATABASE_URL",
            })
            .and_then(normalize_postgres_url)?;
        Ok(Self { database_url })
    }

    #[must_use]
    pub fn database_url(&self) -> &str {
        &self.database_url
    }
}

impl fmt::Debug for VerificationMigrationConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerificationMigrationConfig")
            .field("database_url", &"[CONFIGURED]")
            .finish()
    }
}

impl IssuerResolverConfig {
    #[must_use]
    pub fn api_key(&self) -> &str {
        &self.api_key
    }
}

impl fmt::Debug for IssuerResolverConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuerResolverConfig")
            .field("base_url", &self.base_url)
            .field("api_key", &"[REDACTED]")
            .field("did_web_allowed_hosts", &self.did_web_allowed_hosts)
            .finish()
    }
}

impl fmt::Debug for VerificationServiceConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerificationServiceConfig")
            .field("environment", &self.environment)
            .field("http_addr", &self.http_addr)
            .field("grpc_addr", &self.grpc_addr)
            .field("grpc_enabled", &self.grpc_enabled)
            .field("public_base_url", &self.public_base_url)
            .field(
                "credentials_compat_enabled",
                &self.credentials_compat_enabled,
            )
            .field(
                "redis_url",
                &self.redis_url.as_ref().map(|_| "[CONFIGURED]"),
            )
            .field(
                "credentials_governance",
                &self
                    .credentials_governance
                    .as_ref()
                    .map(|_| "[VALIDATED AND REDACTED]"),
            )
            .field(
                "credentials_database_url",
                &self
                    .credentials_database_url
                    .as_ref()
                    .map(|_| "[CONFIGURED]"),
            )
            .field(
                "credentials_processing_lease",
                &self.credentials_processing_lease,
            )
            .field("credentials_resolver", &self.credentials_resolver)
            .field("providers", &"[CONFIGURED]")
            .field("release_version", &self.release_version)
            .field("build_revision", &self.build_revision)
            .finish()
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum VerificationConfigError {
    #[error("VERIFICATION.CONFIGURATION: {name} is required")]
    Missing { name: &'static str },
    #[error("VERIFICATION.CONFIGURATION: {name} is invalid")]
    Invalid { name: &'static str },
}

impl VerificationServiceConfig {
    pub fn from_env() -> Result<Self, VerificationConfigError> {
        Self::from_values(std::env::vars())
    }

    pub fn from_values(
        values: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, VerificationConfigError> {
        let values = values.into_iter().collect::<BTreeMap<_, _>>();
        let environment = match value(&values, "ENVIRONMENT").unwrap_or("production") {
            "development" | "dev" | "local" => Environment::Development,
            "test" => Environment::Test,
            "beta" | "staging" => Environment::Beta,
            "production" | "prod" => Environment::Production,
            _ => return Err(invalid("ENVIRONMENT")),
        };
        let http_addr = address(
            &values,
            "VERIFICATION_HTTP_ADDR",
            "VERIFICATION_SERVICE_PORT",
            DEFAULT_HTTP_ADDR,
        )?;
        let grpc_addr = address(
            &values,
            "VERIFICATION_GRPC_ADDR",
            "VERIF_GRPC_PORT",
            DEFAULT_GRPC_ADDR,
        )?;
        if http_addr == grpc_addr {
            return Err(invalid("VERIFICATION_GRPC_ADDR"));
        }
        let grpc_enabled = boolean(
            value(&values, "VERIF_GRPC_ENABLED").unwrap_or("false"),
            "VERIF_GRPC_ENABLED",
        )?;
        if environment.is_deployed() && grpc_enabled {
            return Err(invalid("VERIF_GRPC_ENABLED"));
        }
        let public_base_url = value(&values, "PUBLIC_BASE_URL")
            .unwrap_or("http://localhost:8012")
            .trim_end_matches('/')
            .to_owned();
        if !valid_http_url(&public_base_url)
            || (environment.is_deployed() && !public_base_url.starts_with("https://"))
        {
            return Err(invalid("PUBLIC_BASE_URL"));
        }
        let redis_url = value(&values, "REDIS_URL").map(str::to_owned);
        if environment.is_deployed() && redis_url.is_none() {
            return Err(VerificationConfigError::Missing { name: "REDIS_URL" });
        }
        if redis_url.as_deref().is_some_and(|url| {
            !Url::parse(url).is_ok_and(|parsed| match parsed.scheme() {
                "redis" | "rediss" => parsed.host_str().is_some() && parsed.fragment().is_none(),
                "unix" => {
                    parsed.host_str().is_none()
                        && parsed.path().starts_with('/')
                        && parsed.fragment().is_none()
                }
                _ => false,
            })
        }) {
            return Err(invalid("REDIS_URL"));
        }
        let workload_tls = workload_tls(&values, environment)?;
        let credentials_compat_enabled = boolean(
            value(&values, "VERIFICATION_CREDENTIALS_COMPAT_ENABLED").unwrap_or("false"),
            "VERIFICATION_CREDENTIALS_COMPAT_ENABLED",
        )?;
        let credentials_governance = match value(&values, "VERIFICATION_GOVERNANCE_JSON") {
            Some(raw) => Some(
                GovernanceEngine::new(raw).map_err(|_| invalid("VERIFICATION_GOVERNANCE_JSON"))?,
            ),
            None if credentials_compat_enabled => {
                return Err(VerificationConfigError::Missing {
                    name: "VERIFICATION_GOVERNANCE_JSON",
                });
            }
            None => None,
        };
        let credentials_database_url = value(&values, "DATABASE_URL")
            .map(normalize_postgres_url)
            .transpose()?;
        if credentials_compat_enabled && credentials_database_url.is_none() {
            return Err(VerificationConfigError::Missing {
                name: "DATABASE_URL",
            });
        }
        let credentials_processing_lease = ProcessingLease::from_seconds(number(
            value(&values, "VERIFICATION_PROCESSING_LEASE_SECONDS").unwrap_or("60"),
            "VERIFICATION_PROCESSING_LEASE_SECONDS",
            5,
            300,
        )?)
        .map_err(|_| invalid("VERIFICATION_PROCESSING_LEASE_SECONDS"))?;
        let resolver_api_key = value(&values, "SIGNING_KEYS_INTERNAL_API_KEY");
        let resolver_api_key_file = value(&values, "SIGNING_KEYS_INTERNAL_API_KEY_FILE");
        let credentials_resolver = if credentials_compat_enabled {
            let api_key = match (resolver_api_key, resolver_api_key_file) {
                (Some(secret), _) => secret.to_owned(),
                (None, Some(path)) => std::fs::read_to_string(path)
                    .map_err(|_| invalid("SIGNING_KEYS_INTERNAL_API_KEY_FILE"))?
                    .trim()
                    .to_owned(),
                (None, None) => {
                    return Err(VerificationConfigError::Missing {
                        name: "SIGNING_KEYS_INTERNAL_API_KEY",
                    });
                }
            };
            if api_key.is_empty() {
                return Err(invalid("SIGNING_KEYS_INTERNAL_API_KEY"));
            }
            let base_url = value(&values, "SIGNING_KEYS_INTERNAL_URL")
                .unwrap_or("http://gateway:8000/internal/signing-keys")
                .trim_end_matches('/')
                .to_owned();
            if !valid_http_url_with_path(&base_url) {
                return Err(invalid("SIGNING_KEYS_INTERNAL_URL"));
            }
            let did_web_allowed_hosts = value(&values, "DID_WEB_ALLOWED_HOSTS")
                .unwrap_or_default()
                .split(',')
                .map(str::trim)
                .filter(|host| !host.is_empty())
                .map(str::to_ascii_lowercase)
                .collect::<Vec<_>>();
            if environment == Environment::Production && did_web_allowed_hosts.is_empty() {
                return Err(VerificationConfigError::Missing {
                    name: "DID_WEB_ALLOWED_HOSTS",
                });
            }
            Some(IssuerResolverConfig {
                base_url,
                api_key,
                did_web_allowed_hosts,
            })
        } else {
            None
        };
        let service_token = value(&values, "GRPC_SERVICE_TOKEN").map(str::to_owned);
        if environment.is_deployed() && service_token.as_ref().is_none_or(|v| v.len() < 32) {
            return Err(VerificationConfigError::Missing {
                name: "GRPC_SERVICE_TOKEN",
            });
        }
        let inspection_target = value(&values, "INSPECTION_SYSTEM_TARGET").map(str::to_owned);
        let inspection_method = value(&values, "INSPECTION_SYSTEM_GRPC_METHOD")
            .unwrap_or_default()
            .to_owned();
        if inspection_target.is_some() && inspection_method.is_empty() {
            return Err(VerificationConfigError::Missing {
                name: "INSPECTION_SYSTEM_GRPC_METHOD",
            });
        }
        let timeout_seconds = number(
            value(&values, "VERIFICATION_DEPENDENCY_TIMEOUT_SECONDS").unwrap_or("10"),
            "VERIFICATION_DEPENDENCY_TIMEOUT_SECONDS",
            1,
            120,
        )?;
        let organization_target = value(&values, "ORG_GRPC_TARGET")
            .or_else(|| value(&values, "ORGANIZATION_GRPC_TARGET"))
            .unwrap_or("organization:9002");
        let credential_template_target =
            value(&values, "CT_GRPC_TARGET").unwrap_or("credential-template:9003");
        let presentation_policy_target =
            value(&values, "PP_GRPC_TARGET").unwrap_or("presentation-policy:9009");
        if workload_tls.is_some() {
            for (name, target) in [
                ("ORG_GRPC_TARGET", organization_target),
                ("CT_GRPC_TARGET", credential_template_target),
                ("PP_GRPC_TARGET", presentation_policy_target),
            ] {
                if !target.starts_with("https://") {
                    return Err(invalid(name));
                }
            }
            if inspection_target
                .as_deref()
                .is_some_and(|target| !target.starts_with("https://"))
            {
                return Err(invalid("INSPECTION_SYSTEM_TARGET"));
            }
        }
        Ok(Self {
            environment,
            http_addr,
            grpc_addr,
            grpc_enabled,
            public_base_url,
            redis_url,
            credentials_compat_enabled,
            credentials_governance,
            credentials_database_url,
            credentials_processing_lease,
            credentials_resolver,
            providers: GrpcProviderConfig {
                organization_target: organization_target.into(),
                credential_template_target: credential_template_target.into(),
                presentation_policy_target: presentation_policy_target.into(),
                inspection_target,
                inspection_method,
                service_token,
                workload_tls,
                timeout: Duration::from_secs(timeout_seconds),
            },
            release_version: value(&values, "MARTY_RELEASE_VERSION")
                .unwrap_or(env!("CARGO_PKG_VERSION"))
                .into(),
            build_revision: value(&values, "MARTY_UI_SHA").unwrap_or("unknown").into(),
        })
    }
}

fn workload_tls(
    values: &BTreeMap<String, String>,
    environment: Environment,
) -> Result<Option<WorkloadClientTlsFiles>, VerificationConfigError> {
    const CERT: &str = "GRPC_WORKLOAD_TLS_CLIENT_CERT";
    if values.contains_key("GRPC_WORKLOAD_TLS_CLIENT_KEY") {
        return Err(invalid("GRPC_WORKLOAD_TLS_CLIENT_KEY"));
    }
    let mut names = marty_service_runtime::TlsIdentityNames::new("GRPC_WORKLOAD_TLS");
    names.certificate = CERT.into();
    names.private_key = "GRPC_WORKLOAD_TLS_CLIENT_KEY".into();
    let files = WorkloadClientTlsFiles::from_values(
        |name| values.get(name).map(String::as_str),
        names,
        "GRPC_WORKLOAD_TLS_CA_CERT",
        value(values, "GRPC_WORKLOAD_TLS_CA_CERT").is_some(),
        std::time::Duration::from_secs(10),
        64,
    )
    .map_err(|_| invalid(CERT))?;
    if files.is_none() && environment.is_deployed() {
        return Err(VerificationConfigError::Missing { name: CERT });
    }
    Ok(files)
}

fn address(
    values: &BTreeMap<String, String>,
    address_name: &'static str,
    port_name: &'static str,
    default: &str,
) -> Result<SocketAddr, VerificationConfigError> {
    let raw = value(values, address_name)
        .map(str::to_owned)
        .unwrap_or_else(|| {
            value(values, port_name)
                .map_or_else(|| default.into(), |port| format!("0.0.0.0:{port}"))
        });
    raw.parse().map_err(|_| invalid(address_name))
}

fn boolean(value: &str, name: &'static str) -> Result<bool, VerificationConfigError> {
    match value.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        _ => Err(invalid(name)),
    }
}

fn number(
    value: &str,
    name: &'static str,
    minimum: u64,
    maximum: u64,
) -> Result<u64, VerificationConfigError> {
    let value = value.parse().map_err(|_| invalid(name))?;
    (minimum..=maximum)
        .contains(&value)
        .then_some(value)
        .ok_or_else(|| invalid(name))
}

fn valid_http_url(value: &str) -> bool {
    Url::parse(value).is_ok_and(|url| {
        matches!(url.scheme(), "http" | "https")
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && matches!(url.path(), "" | "/")
            && url.query().is_none()
            && url.fragment().is_none()
    })
}

fn valid_http_url_with_path(value: &str) -> bool {
    Url::parse(value).is_ok_and(|url| {
        matches!(url.scheme(), "http" | "https")
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
    })
}

fn normalize_postgres_url(value: &str) -> Result<String, VerificationConfigError> {
    let normalized = [
        "postgresql+psycopg://",
        "postgresql+psycopg2://",
        "postgresql+asyncpg://",
    ]
    .into_iter()
    .find_map(|prefix| value.strip_prefix(prefix))
    .map_or_else(
        || value.to_owned(),
        |suffix| format!("postgresql://{suffix}"),
    );
    let parsed = Url::parse(&normalized).map_err(|_| invalid("DATABASE_URL"))?;
    if !matches!(parsed.scheme(), "postgres" | "postgresql")
        || parsed.host_str().is_none()
        || parsed.username().is_empty()
        || parsed.fragment().is_some()
    {
        return Err(invalid("DATABASE_URL"));
    }
    Ok(normalized)
}

fn value<'a>(values: &'a BTreeMap<String, String>, name: &str) -> Option<&'a str> {
    values
        .get(name)
        .map(String::as_str)
        .filter(|v| !v.trim().is_empty())
}

const fn invalid(name: &'static str) -> VerificationConfigError {
    VerificationConfigError::Invalid { name }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aws_workload_identity_uses_existing_client_certificate_spelling() {
        let mut values = BTreeMap::from([
            ("GRPC_WORKLOAD_TLS_CLIENT_CERT".into(), "client.pem".into()),
            ("GRPC_WORKLOAD_TLS_CA_CERT".into(), "peer-ca.pem".into()),
            ("GRPC_WORKLOAD_TLS_KMS_PROVIDER".into(), "aws-kms".into()),
            ("GRPC_WORKLOAD_TLS_KMS_REGION".into(), "us-east-1".into()),
            (
                "GRPC_WORKLOAD_TLS_KMS_KEY_ARN".into(),
                "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
                    .into(),
            ),
        ]);
        let tls = workload_tls(&values, Environment::Beta).unwrap().unwrap();
        let marty_service_runtime::RemoteTlsIdentityFiles::AwsKms(identity) = tls.identity else {
            panic!("configured AWS identity must reach verification providers");
        };
        assert_eq!(identity.certificate_chain_file.to_str(), Some("client.pem"));
        values.insert("GRPC_WORKLOAD_TLS_KMS_KEY_VERSION".into(), "1".into());
        assert!(workload_tls(&values, Environment::Beta).is_err());
    }

    #[test]
    fn deployed_configuration_fails_closed() {
        let error = VerificationServiceConfig::from_values([
            ("ENVIRONMENT".into(), "beta".into()),
            ("PUBLIC_BASE_URL".into(), "https://beta.example".into()),
            ("REDIS_URL".into(), "redis://redis/3".into()),
        ])
        .unwrap_err();
        assert_eq!(
            error,
            VerificationConfigError::Missing {
                name: "GRPC_WORKLOAD_TLS_CLIENT_CERT"
            }
        );
    }

    #[test]
    fn local_configuration_allows_memory_and_optional_grpc() {
        let config = VerificationServiceConfig::from_values([
            ("ENVIRONMENT".into(), "test".into()),
            ("VERIF_GRPC_ENABLED".into(), "true".into()),
        ])
        .unwrap();
        assert!(config.grpc_enabled);
        assert!(config.redis_url.is_none());
        assert!(config.providers.workload_tls.is_none());
    }

    #[test]
    fn inspection_target_requires_an_explicit_method_contract() {
        let error = VerificationServiceConfig::from_values([
            ("ENVIRONMENT".into(), "test".into()),
            ("INSPECTION_SYSTEM_TARGET".into(), "inspection:9020".into()),
        ])
        .unwrap_err();
        assert_eq!(
            error,
            VerificationConfigError::Missing {
                name: "INSPECTION_SYSTEM_GRPC_METHOD"
            }
        );
    }

    #[test]
    fn complete_beta_configuration_is_accepted_and_inbound_grpc_is_closed() {
        let configured = vec![
            ("ENVIRONMENT".into(), "beta".into()),
            ("PUBLIC_BASE_URL".into(), "https://beta.example".into()),
            ("REDIS_URL".into(), "rediss://redis/3".into()),
            ("GRPC_SERVICE_TOKEN".into(), "x".repeat(32)),
            ("ORG_GRPC_TARGET".into(), "https://organization:9002".into()),
            (
                "CT_GRPC_TARGET".into(),
                "https://credential-template:9003".into(),
            ),
            (
                "PP_GRPC_TARGET".into(),
                "https://presentation-policy:9009".into(),
            ),
            ("GRPC_WORKLOAD_TLS_CLIENT_CERT".into(), "client.crt".into()),
            ("GRPC_WORKLOAD_TLS_CA_CERT".into(), "ca.crt".into()),
            (
                "GRPC_WORKLOAD_TLS_KMS_ADDR".into(),
                "https://bao:8200".into(),
            ),
            ("GRPC_WORKLOAD_TLS_KMS_CA_CERT".into(), "bao-ca.crt".into()),
            ("GRPC_WORKLOAD_TLS_KMS_TOKEN_FILE".into(), "token".into()),
            (
                "GRPC_WORKLOAD_TLS_KMS_KEY_NAME".into(),
                "verification-client".into(),
            ),
            ("GRPC_WORKLOAD_TLS_KMS_KEY_VERSION".into(), "1".into()),
            ("VERIF_GRPC_ENABLED".into(), "false".into()),
        ];
        let config = VerificationServiceConfig::from_values(configured.clone()).unwrap();
        assert_eq!(config.environment, Environment::Beta);
        assert!(!config.grpc_enabled);
        let mut socket_config = configured.clone();
        socket_config.retain(|(name, _)| name != "REDIS_URL");
        socket_config.push((
            "REDIS_URL".into(),
            "unix:///run/marty-redis/redis.sock?db=3".into(),
        ));
        assert!(VerificationServiceConfig::from_values(socket_config.clone()).is_ok());
        socket_config.last_mut().unwrap().1 = "unix://remote/run/redis.sock".into();
        assert!(matches!(
            VerificationServiceConfig::from_values(socket_config),
            Err(VerificationConfigError::Invalid { name: "REDIS_URL" })
        ));
        assert!(config.providers.workload_tls.is_some());
        assert!(config.credentials_governance.is_none());
        assert!(!config.credentials_compat_enabled);

        for (name, target) in [
            ("ORG_GRPC_TARGET", "organization:9002"),
            ("CT_GRPC_TARGET", "http://credential-template:9003"),
            ("PP_GRPC_TARGET", "presentation-policy:9009"),
        ] {
            let mut changed = configured.clone();
            changed
                .iter_mut()
                .find(|(setting, _)| setting == name)
                .unwrap()
                .1 = target.into();
            assert_eq!(
                VerificationServiceConfig::from_values(changed).unwrap_err(),
                VerificationConfigError::Invalid { name }
            );
        }

        let error = VerificationServiceConfig::from_values([
            ("ENVIRONMENT".into(), "beta".into()),
            ("VERIF_GRPC_ENABLED".into(), "true".into()),
        ])
        .unwrap_err();
        assert_eq!(
            error,
            VerificationConfigError::Invalid {
                name: "VERIF_GRPC_ENABLED"
            }
        );
    }

    #[test]
    fn retired_workload_private_key_file_is_rejected() {
        let error = VerificationServiceConfig::from_values([
            ("ENVIRONMENT".into(), "test".into()),
            ("GRPC_WORKLOAD_TLS_CLIENT_KEY".into(), "client.key".into()),
        ])
        .unwrap_err();
        assert_eq!(
            error,
            VerificationConfigError::Invalid {
                name: "GRPC_WORKLOAD_TLS_CLIENT_KEY"
            }
        );
    }

    #[test]
    fn governance_is_validated_and_redacted_at_the_configuration_boundary() {
        let error = VerificationServiceConfig::from_values([
            ("ENVIRONMENT".into(), "test".into()),
            ("VERIFICATION_GOVERNANCE_JSON".into(), "{}".into()),
        ])
        .unwrap_err();
        assert_eq!(
            error,
            VerificationConfigError::Invalid {
                name: "VERIFICATION_GOVERNANCE_JSON"
            }
        );

        let fixture: serde_json::Value =
            serde_json::from_str(marty_verification::governance::behavior_fixture_json()).unwrap();
        let digest = fixture["governance"]["clients"][0]["api_key_sha256"]
            .as_str()
            .unwrap();
        let config = VerificationServiceConfig::from_values([
            ("ENVIRONMENT".into(), "test".into()),
            (
                "VERIFICATION_GOVERNANCE_JSON".into(),
                fixture["governance"].to_string(),
            ),
        ])
        .unwrap();
        let debug = format!("{config:?}");
        assert!(debug.contains("VALIDATED AND REDACTED"));
        assert!(!debug.contains(digest));
    }

    #[test]
    fn compatibility_activation_requires_governance_in_every_environment() {
        let error = VerificationServiceConfig::from_values([
            ("ENVIRONMENT".into(), "test".into()),
            (
                "VERIFICATION_CREDENTIALS_COMPAT_ENABLED".into(),
                "true".into(),
            ),
        ])
        .unwrap_err();
        assert_eq!(
            error,
            VerificationConfigError::Missing {
                name: "VERIFICATION_GOVERNANCE_JSON"
            }
        );

        let fixture: serde_json::Value =
            serde_json::from_str(marty_verification::governance::behavior_fixture_json()).unwrap();
        let config = VerificationServiceConfig::from_values([
            ("ENVIRONMENT".into(), "test".into()),
            (
                "VERIFICATION_CREDENTIALS_COMPAT_ENABLED".into(),
                "true".into(),
            ),
            (
                "VERIFICATION_GOVERNANCE_JSON".into(),
                fixture["governance"].to_string(),
            ),
            (
                "DATABASE_URL".into(),
                "postgresql+psycopg://verification:secret@postgres/verification".into(),
            ),
            (
                "SIGNING_KEYS_INTERNAL_API_KEY".into(),
                "resolver-secret".into(),
            ),
        ])
        .unwrap();
        assert!(config.credentials_compat_enabled);
        assert!(config.credentials_governance.is_some());
        assert_eq!(
            config.credentials_database_url.as_deref(),
            Some("postgresql://verification:secret@postgres/verification")
        );
        assert_eq!(config.credentials_processing_lease.seconds(), 60);
        assert_eq!(
            config.credentials_resolver.as_ref().unwrap().api_key(),
            "resolver-secret"
        );
        let debug = format!("{config:?}");
        assert!(!debug.contains("resolver-secret"));
        assert!(!debug.contains("postgresql://"));
    }

    #[test]
    fn compatibility_runtime_configuration_is_bounded_and_fail_closed() {
        let fixture: serde_json::Value =
            serde_json::from_str(marty_verification::governance::behavior_fixture_json()).unwrap();
        let base = [
            (
                "VERIFICATION_CREDENTIALS_COMPAT_ENABLED".into(),
                "true".into(),
            ),
            (
                "VERIFICATION_GOVERNANCE_JSON".into(),
                fixture["governance"].to_string(),
            ),
            (
                "SIGNING_KEYS_INTERNAL_API_KEY".into(),
                "resolver-secret".into(),
            ),
        ];
        for (name, value) in [
            ("DATABASE_URL", "sqlite://local"),
            ("VERIFICATION_PROCESSING_LEASE_SECONDS", "4"),
            ("VERIFICATION_PROCESSING_LEASE_SECONDS", "301"),
            (
                "SIGNING_KEYS_INTERNAL_URL",
                "http://user:password@gateway/internal",
            ),
        ] {
            let mut values = base.to_vec();
            values.push((
                "DATABASE_URL".into(),
                "postgres://verification:secret@postgres/verification".into(),
            ));
            values.push((name.into(), value.into()));
            assert!(VerificationServiceConfig::from_values(values).is_err());
        }
    }

    #[test]
    fn migration_configuration_exposes_the_url_only_through_an_explicit_accessor() {
        let config = VerificationMigrationConfig::from_values([(
            "DATABASE_URL".into(),
            "postgres://verification:secret@postgres/verification".into(),
        )])
        .unwrap();
        assert_eq!(
            config.database_url(),
            "postgres://verification:secret@postgres/verification"
        );
        let debug = format!("{config:?}");
        assert!(debug.contains("[CONFIGURED]"));
        assert!(!debug.contains("verification:secret"));
    }

    #[test]
    fn deployment_governance_fixture_stays_identical_to_the_canonical_core_vector() {
        let deployment: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../contracts/verification-governance-behavior.json"
        ))
        .unwrap();
        let canonical: serde_json::Value =
            serde_json::from_str(marty_verification::governance::behavior_fixture_json()).unwrap();
        assert_eq!(deployment, canonical);
        GovernanceEngine::new(&deployment["governance"].to_string()).unwrap();
    }
}
