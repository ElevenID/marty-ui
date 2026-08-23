use std::{collections::BTreeMap, net::SocketAddr, path::PathBuf, time::Duration};

use thiserror::Error;
use url::Url;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeEnvironment {
    Development,
    Test,
    Beta,
    Production,
}

impl RuntimeEnvironment {
    #[must_use]
    pub const fn is_deployed(self) -> bool {
        matches!(self, Self::Beta | Self::Production)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkloadTlsFiles {
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    pub ca_certificate: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeploymentServiceConfig {
    pub environment: RuntimeEnvironment,
    pub http_addr: SocketAddr,
    pub database_url: String,
    pub database_max_connections: u32,
    pub organization_grpc_target: String,
    pub service_token: Option<String>,
    pub workload_tls: Option<WorkloadTlsFiles>,
    pub dependency_timeout: Duration,
    pub release_version: String,
    pub build_revision: String,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum DeploymentConfigError {
    #[error("DEPLOYMENT_PROFILE.CONFIGURATION: {name} is required")]
    Missing { name: &'static str },
    #[error("DEPLOYMENT_PROFILE.CONFIGURATION: {name} is invalid")]
    Invalid { name: &'static str },
}

impl DeploymentServiceConfig {
    pub fn from_env() -> Result<Self, DeploymentConfigError> {
        Self::from_values(std::env::vars())
    }

    pub fn from_values(
        values: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, DeploymentConfigError> {
        let values = values.into_iter().collect::<BTreeMap<_, _>>();
        let environment = match value(&values, "ENVIRONMENT").unwrap_or("development") {
            "development" | "dev" | "local" => RuntimeEnvironment::Development,
            "test" => RuntimeEnvironment::Test,
            "beta" | "staging" => RuntimeEnvironment::Beta,
            "production" | "prod" => RuntimeEnvironment::Production,
            _ => return Err(invalid("ENVIRONMENT")),
        };
        let database_url = required(&values, "DATABASE_URL")?.replacen(
            "postgresql+asyncpg://",
            "postgresql://",
            1,
        );
        let parsed = Url::parse(&database_url).map_err(|_| invalid("DATABASE_URL"))?;
        if !matches!(parsed.scheme(), "postgres" | "postgresql") || parsed.host_str().is_none() {
            return Err(invalid("DATABASE_URL"));
        }
        let http_addr = value(&values, "DEPLOYMENT_PROFILE_HTTP_ADDR")
            .map(str::to_owned)
            .unwrap_or_else(|| {
                format!(
                    "0.0.0.0:{}",
                    value(&values, "DEPLOYMENT_PROFILE_SERVICE_PORT").unwrap_or("8010")
                )
            })
            .parse()
            .map_err(|_| invalid("DEPLOYMENT_PROFILE_HTTP_ADDR"))?;
        let database_max_connections = number(
            value(&values, "DEPLOYMENT_PROFILE_DATABASE_MAX_CONNECTIONS").unwrap_or("20"),
            "DEPLOYMENT_PROFILE_DATABASE_MAX_CONNECTIONS",
            1,
            100,
        )? as u32;
        let organization_grpc_target = normalize_target(
            value(&values, "ORG_GRPC_TARGET")
                .or_else(|| value(&values, "ORGANIZATION_GRPC_TARGET"))
                .unwrap_or("organization:9002"),
        )?;
        let service_token = value(&values, "GRPC_SERVICE_TOKEN").map(str::to_owned);
        if environment.is_deployed() && service_token.as_ref().is_none_or(|v| v.len() < 32) {
            return Err(DeploymentConfigError::Missing {
                name: "GRPC_SERVICE_TOKEN",
            });
        }
        let insecure_allowed = boolean(&values, "GRPC_INSECURE_ALLOWED", false)?;
        if environment == RuntimeEnvironment::Production && insecure_allowed {
            return Err(invalid("GRPC_INSECURE_ALLOWED"));
        }
        let workload_tls = workload_tls(&values, environment, insecure_allowed)?;
        let timeout = number(
            value(&values, "DEPLOYMENT_PROFILE_DEPENDENCY_TIMEOUT_SECONDS").unwrap_or("10"),
            "DEPLOYMENT_PROFILE_DEPENDENCY_TIMEOUT_SECONDS",
            1,
            120,
        )?;
        Ok(Self {
            environment,
            http_addr,
            database_url,
            database_max_connections,
            organization_grpc_target,
            service_token,
            workload_tls,
            dependency_timeout: Duration::from_secs(timeout),
            release_version: value(&values, "MARTY_RELEASE_VERSION")
                .unwrap_or(env!("CARGO_PKG_VERSION"))
                .into(),
            build_revision: value(&values, "MARTY_UI_SHA").unwrap_or("unknown").into(),
        })
    }
}

fn workload_tls(
    values: &BTreeMap<String, String>,
    environment: RuntimeEnvironment,
    insecure_allowed: bool,
) -> Result<Option<WorkloadTlsFiles>, DeploymentConfigError> {
    let names = [
        "GRPC_WORKLOAD_TLS_CLIENT_CERT",
        "GRPC_WORKLOAD_TLS_CLIENT_KEY",
        "GRPC_WORKLOAD_TLS_CA_CERT",
    ];
    let configured = names
        .iter()
        .filter(|name| value(values, name).is_some())
        .count();
    if configured == 0 && (!environment.is_deployed() || insecure_allowed) {
        return Ok(None);
    }
    if configured != names.len() {
        return Err(if configured == 0 {
            DeploymentConfigError::Missing { name: names[0] }
        } else {
            invalid(names[0])
        });
    }
    Ok(Some(WorkloadTlsFiles {
        certificate: value(values, names[0]).unwrap_or_default().into(),
        private_key: value(values, names[1]).unwrap_or_default().into(),
        ca_certificate: value(values, names[2]).unwrap_or_default().into(),
    }))
}

fn boolean(
    values: &BTreeMap<String, String>,
    name: &'static str,
    default: bool,
) -> Result<bool, DeploymentConfigError> {
    value(values, name).map_or(Ok(default), |raw| match raw.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        _ => Err(invalid(name)),
    })
}

fn normalize_target(raw: &str) -> Result<String, DeploymentConfigError> {
    if raw.chars().any(char::is_whitespace) {
        return Err(invalid("ORG_GRPC_TARGET"));
    }
    Ok(if raw.contains("://") {
        raw.into()
    } else {
        format!("http://{raw}")
    })
}

fn required(
    values: &BTreeMap<String, String>,
    name: &'static str,
) -> Result<String, DeploymentConfigError> {
    value(values, name)
        .map(str::to_owned)
        .ok_or(DeploymentConfigError::Missing { name })
}

fn number(raw: &str, name: &'static str, min: u64, max: u64) -> Result<u64, DeploymentConfigError> {
    let parsed = raw.parse().map_err(|_| invalid(name))?;
    (min..=max)
        .contains(&parsed)
        .then_some(parsed)
        .ok_or_else(|| invalid(name))
}

fn value<'a>(values: &'a BTreeMap<String, String>, name: &str) -> Option<&'a str> {
    values
        .get(name)
        .map(String::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())
}

const fn invalid(name: &'static str) -> DeploymentConfigError {
    DeploymentConfigError::Invalid { name }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base(environment: &str) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("ENVIRONMENT".into(), environment.into()),
            (
                "DATABASE_URL".into(),
                "postgresql+asyncpg://marty:secret@localhost/marty".into(),
            ),
        ])
    }

    #[test]
    fn normalizes_legacy_database_and_compose_grpc_urls() {
        let config = DeploymentServiceConfig::from_values(base("development")).unwrap();
        assert_eq!(config.http_addr.port(), 8010);
        assert_eq!(config.organization_grpc_target, "http://organization:9002");
        assert!(config.database_url.starts_with("postgresql://"));
    }

    #[test]
    fn deployed_configuration_requires_service_identity_and_mutual_tls() {
        assert_eq!(
            DeploymentServiceConfig::from_values(base("beta")),
            Err(DeploymentConfigError::Missing {
                name: "GRPC_SERVICE_TOKEN"
            })
        );
        let mut values = base("beta");
        values.insert("GRPC_SERVICE_TOKEN".into(), "s".repeat(32));
        assert_eq!(
            DeploymentServiceConfig::from_values(values),
            Err(DeploymentConfigError::Missing {
                name: "GRPC_WORKLOAD_TLS_CLIENT_CERT"
            })
        );
    }

    #[test]
    fn beta_can_explicitly_match_a_plaintext_organization_server_but_production_cannot() {
        let mut beta = base("beta");
        beta.insert("GRPC_SERVICE_TOKEN".into(), "s".repeat(32));
        beta.insert("GRPC_INSECURE_ALLOWED".into(), "true".into());
        assert!(DeploymentServiceConfig::from_values(beta)
            .unwrap()
            .workload_tls
            .is_none());

        let mut production = base("production");
        production.insert("GRPC_SERVICE_TOKEN".into(), "s".repeat(32));
        production.insert("GRPC_INSECURE_ALLOWED".into(), "true".into());
        assert_eq!(
            DeploymentServiceConfig::from_values(production),
            Err(DeploymentConfigError::Invalid {
                name: "GRPC_INSECURE_ALLOWED"
            })
        );
    }
}
