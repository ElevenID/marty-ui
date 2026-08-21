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
pub struct ComplianceServiceConfig {
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
pub enum ComplianceConfigError {
    #[error("COMPLIANCE_PROFILE.CONFIGURATION: {name} is required")]
    Missing { name: &'static str },
    #[error("COMPLIANCE_PROFILE.CONFIGURATION: {name} is invalid")]
    Invalid { name: &'static str },
}
impl ComplianceServiceConfig {
    pub fn from_env() -> Result<Self, ComplianceConfigError> {
        Self::from_values(std::env::vars())
    }
    pub fn from_values(
        values: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, ComplianceConfigError> {
        let v = values.into_iter().collect::<BTreeMap<_, _>>();
        let environment = match value(&v, "ENVIRONMENT").unwrap_or("development") {
            "development" | "dev" | "local" => RuntimeEnvironment::Development,
            "test" => RuntimeEnvironment::Test,
            "beta" | "staging" => RuntimeEnvironment::Beta,
            "production" | "prod" => RuntimeEnvironment::Production,
            _ => return Err(invalid("ENVIRONMENT")),
        };
        let database_url =
            required(&v, "DATABASE_URL")?.replacen("postgresql+asyncpg://", "postgresql://", 1);
        let parsed = Url::parse(&database_url).map_err(|_| invalid("DATABASE_URL"))?;
        if !matches!(parsed.scheme(), "postgres" | "postgresql") || parsed.host_str().is_none() {
            return Err(invalid("DATABASE_URL"));
        }
        let http_addr = value(&v, "COMPLIANCE_PROFILE_HTTP_ADDR")
            .map(str::to_owned)
            .unwrap_or_else(|| {
                format!(
                    "0.0.0.0:{}",
                    value(&v, "COMPLIANCE_PROFILE_SERVICE_PORT").unwrap_or("8008")
                )
            })
            .parse()
            .map_err(|_| invalid("COMPLIANCE_PROFILE_HTTP_ADDR"))?;
        let service_token = value(&v, "GRPC_SERVICE_TOKEN").map(str::to_owned);
        if environment.is_deployed() && service_token.as_ref().is_none_or(|s| s.len() < 32) {
            return Err(ComplianceConfigError::Missing {
                name: "GRPC_SERVICE_TOKEN",
            });
        }
        let workload_tls = tls(&v, environment)?;
        let target = value(&v, "ORG_GRPC_TARGET").unwrap_or("organization:9002");
        if target.chars().any(char::is_whitespace) {
            return Err(invalid("ORG_GRPC_TARGET"));
        }
        Ok(Self {
            environment,
            http_addr,
            database_url,
            database_max_connections: number(
                value(&v, "COMPLIANCE_PROFILE_DATABASE_MAX_CONNECTIONS").unwrap_or("20"),
                "COMPLIANCE_PROFILE_DATABASE_MAX_CONNECTIONS",
                1,
                100,
            )? as u32,
            organization_grpc_target: if target.contains("://") {
                target.into()
            } else {
                format!("http://{target}")
            },
            service_token,
            workload_tls,
            dependency_timeout: Duration::from_secs(number(
                value(&v, "COMPLIANCE_PROFILE_DEPENDENCY_TIMEOUT_SECONDS").unwrap_or("10"),
                "COMPLIANCE_PROFILE_DEPENDENCY_TIMEOUT_SECONDS",
                1,
                120,
            )?),
            release_version: value(&v, "MARTY_RELEASE_VERSION")
                .unwrap_or(env!("CARGO_PKG_VERSION"))
                .into(),
            build_revision: value(&v, "MARTY_UI_SHA").unwrap_or("unknown").into(),
        })
    }
}
fn tls(
    v: &BTreeMap<String, String>,
    e: RuntimeEnvironment,
) -> Result<Option<WorkloadTlsFiles>, ComplianceConfigError> {
    let n = [
        "GRPC_WORKLOAD_TLS_CLIENT_CERT",
        "GRPC_WORKLOAD_TLS_CLIENT_KEY",
        "GRPC_WORKLOAD_TLS_CA_CERT",
    ];
    let count = n.iter().filter(|x| value(v, x).is_some()).count();
    if count == 0 && !e.is_deployed() {
        return Ok(None);
    }
    if count != 3 {
        return Err(if count == 0 {
            ComplianceConfigError::Missing { name: n[0] }
        } else {
            invalid(n[0])
        });
    }
    Ok(Some(WorkloadTlsFiles {
        certificate: value(v, n[0]).unwrap_or_default().into(),
        private_key: value(v, n[1]).unwrap_or_default().into(),
        ca_certificate: value(v, n[2]).unwrap_or_default().into(),
    }))
}
fn value<'a>(v: &'a BTreeMap<String, String>, n: &str) -> Option<&'a str> {
    v.get(n)
        .map(String::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())
}
fn required(
    v: &BTreeMap<String, String>,
    n: &'static str,
) -> Result<String, ComplianceConfigError> {
    value(v, n)
        .map(str::to_owned)
        .ok_or(ComplianceConfigError::Missing { name: n })
}
fn number(v: &str, n: &'static str, min: u64, max: u64) -> Result<u64, ComplianceConfigError> {
    let x = v.parse().map_err(|_| invalid(n))?;
    (min..=max)
        .contains(&x)
        .then_some(x)
        .ok_or_else(|| invalid(n))
}
const fn invalid(name: &'static str) -> ComplianceConfigError {
    ComplianceConfigError::Invalid { name }
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
    fn development_normalizes_legacy_database_and_compose_grpc_urls() {
        let config = ComplianceServiceConfig::from_values(base("development")).unwrap();
        assert_eq!(config.http_addr.port(), 8008);
        assert_eq!(config.organization_grpc_target, "http://organization:9002");
        assert!(config.database_url.starts_with("postgresql://"));
        assert!(config.workload_tls.is_none());
    }

    #[test]
    fn deployed_configuration_requires_service_identity_and_mutual_tls() {
        assert_eq!(
            ComplianceServiceConfig::from_values(base("beta")),
            Err(ComplianceConfigError::Missing {
                name: "GRPC_SERVICE_TOKEN"
            })
        );
        let mut values = base("beta");
        values.insert("GRPC_SERVICE_TOKEN".into(), "s".repeat(32));
        assert_eq!(
            ComplianceServiceConfig::from_values(values),
            Err(ComplianceConfigError::Missing {
                name: "GRPC_WORKLOAD_TLS_CLIENT_CERT"
            })
        );
    }
}
