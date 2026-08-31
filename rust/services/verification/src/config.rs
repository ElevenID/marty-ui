use std::{collections::BTreeMap, fmt, net::SocketAddr, path::PathBuf, time::Duration};

use thiserror::Error;
use url::Url;

use crate::{credentials_compat::GovernanceEngine, GrpcProviderConfig, WorkloadClientTlsFiles};

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
    pub providers: GrpcProviderConfig,
    pub release_version: String,
    pub build_revision: String,
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
        if redis_url
            .as_deref()
            .is_some_and(|url| !(url.starts_with("redis://") || url.starts_with("rediss://")))
        {
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
        Ok(Self {
            environment,
            http_addr,
            grpc_addr,
            grpc_enabled,
            public_base_url,
            redis_url,
            credentials_compat_enabled,
            credentials_governance,
            providers: GrpcProviderConfig {
                organization_target: value(&values, "ORG_GRPC_TARGET")
                    .or_else(|| value(&values, "ORGANIZATION_GRPC_TARGET"))
                    .unwrap_or("organization:9002")
                    .into(),
                credential_template_target: value(&values, "CT_GRPC_TARGET")
                    .unwrap_or("credential-template:9003")
                    .into(),
                presentation_policy_target: value(&values, "PP_GRPC_TARGET")
                    .unwrap_or("presentation-policy:9009")
                    .into(),
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
    let names = [
        "GRPC_WORKLOAD_TLS_CLIENT_CERT",
        "GRPC_WORKLOAD_TLS_CLIENT_KEY",
        "GRPC_WORKLOAD_TLS_CA_CERT",
    ];
    let configured = names
        .iter()
        .filter(|name| value(values, name).is_some())
        .count();
    if configured == 0 && !environment.is_deployed() {
        return Ok(None);
    }
    if configured != names.len() {
        return Err(if configured == 0 {
            VerificationConfigError::Missing { name: names[0] }
        } else {
            invalid(names[0])
        });
    }
    Ok(Some(WorkloadClientTlsFiles {
        certificate: PathBuf::from(value(values, names[0]).unwrap_or_default()),
        private_key: PathBuf::from(value(values, names[1]).unwrap_or_default()),
        ca_certificate: PathBuf::from(value(values, names[2]).unwrap_or_default()),
    }))
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
        let config = VerificationServiceConfig::from_values([
            ("ENVIRONMENT".into(), "beta".into()),
            ("PUBLIC_BASE_URL".into(), "https://beta.example".into()),
            ("REDIS_URL".into(), "rediss://redis/3".into()),
            ("GRPC_SERVICE_TOKEN".into(), "x".repeat(32)),
            ("GRPC_WORKLOAD_TLS_CLIENT_CERT".into(), "client.crt".into()),
            ("GRPC_WORKLOAD_TLS_CLIENT_KEY".into(), "client.key".into()),
            ("GRPC_WORKLOAD_TLS_CA_CERT".into(), "ca.crt".into()),
            ("VERIF_GRPC_ENABLED".into(), "false".into()),
        ])
        .unwrap();
        assert_eq!(config.environment, Environment::Beta);
        assert!(!config.grpc_enabled);
        assert!(config.providers.workload_tls.is_some());
        assert!(config.credentials_governance.is_none());
        assert!(!config.credentials_compat_enabled);

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
        ])
        .unwrap();
        assert!(config.credentials_compat_enabled);
        assert!(config.credentials_governance.is_some());
    }
}
