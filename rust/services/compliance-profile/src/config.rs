use std::{collections::BTreeMap, net::SocketAddr, time::Duration};
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
pub use marty_service_runtime::WorkloadTlsFiles;
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
        let insecure_allowed = boolean(&v, "GRPC_INSECURE_ALLOWED", false)?;
        if environment.is_deployed() && insecure_allowed {
            return Err(invalid("GRPC_INSECURE_ALLOWED"));
        }
        let workload_tls = tls(&v, environment)?;
        let target = value(&v, "ORG_GRPC_TARGET").unwrap_or("organization:9002");
        if target.chars().any(char::is_whitespace) {
            return Err(invalid("ORG_GRPC_TARGET"));
        }
        let organization_grpc_target = if target.contains("://") {
            target.to_owned()
        } else {
            format!("http://{target}")
        };
        if workload_tls.is_some() && !organization_grpc_target.starts_with("https://") {
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
            organization_grpc_target,
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
    values: &BTreeMap<String, String>,
    environment: RuntimeEnvironment,
) -> Result<Option<WorkloadTlsFiles>, ComplianceConfigError> {
    if values.contains_key("GRPC_WORKLOAD_TLS_CLIENT_KEY") {
        return Err(invalid("GRPC_WORKLOAD_TLS_CLIENT_KEY"));
    }
    let mut names = marty_service_runtime::TlsIdentityNames::new("GRPC_WORKLOAD_TLS");
    names.certificate = "GRPC_WORKLOAD_TLS_CLIENT_CERT".into();
    names.private_key = "GRPC_WORKLOAD_TLS_CLIENT_KEY".into();
    let tls = WorkloadTlsFiles::from_values(
        |name| values.get(name).map(String::as_str),
        names,
        "GRPC_WORKLOAD_TLS_CA_CERT",
        value(values, "GRPC_WORKLOAD_TLS_CA_CERT").is_some(),
        Duration::from_secs(10),
        64,
    )
    .map_err(|error| {
        if error.starts_with("GRPC_WORKLOAD_TLS_KMS_KEY_VERSION") && !error.ends_with("is required")
        {
            invalid("GRPC_WORKLOAD_TLS_KMS_KEY_VERSION")
        } else {
            invalid("GRPC_WORKLOAD_TLS_CLIENT_CERT")
        }
    })?;
    if tls.is_none() && environment.is_deployed() {
        return Err(ComplianceConfigError::Missing {
            name: "GRPC_WORKLOAD_TLS_CLIENT_CERT",
        });
    }
    Ok(tls)
}
fn boolean(
    v: &BTreeMap<String, String>,
    n: &'static str,
    default: bool,
) -> Result<bool, ComplianceConfigError> {
    value(v, n).map_or(Ok(default), |raw| match raw.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        _ => Err(invalid(n)),
    })
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

    #[test]
    fn workload_tls_requires_remote_key_and_rejects_private_key_file() {
        let mut values = base("production");
        values.insert("GRPC_SERVICE_TOKEN".into(), "s".repeat(32));
        values.insert("GRPC_WORKLOAD_TLS_CLIENT_CERT".into(), "client.pem".into());
        values.insert("GRPC_WORKLOAD_TLS_CA_CERT".into(), "server-ca.pem".into());
        assert_eq!(
            ComplianceServiceConfig::from_values(values.clone()),
            Err(ComplianceConfigError::Invalid {
                name: "GRPC_WORKLOAD_TLS_CLIENT_CERT"
            })
        );
        for (name, value) in [
            ("GRPC_WORKLOAD_TLS_KMS_ADDR", "https://bao:8200"),
            ("GRPC_WORKLOAD_TLS_KMS_CA_CERT", "bao-ca.pem"),
            ("GRPC_WORKLOAD_TLS_KMS_TOKEN_FILE", "token"),
            ("GRPC_WORKLOAD_TLS_KMS_KEY_NAME", "compliance-client"),
            ("GRPC_WORKLOAD_TLS_KMS_KEY_VERSION", "1"),
        ] {
            values.insert(name.into(), value.into());
        }
        assert_eq!(
            ComplianceServiceConfig::from_values(values.clone()),
            Err(ComplianceConfigError::Invalid {
                name: "ORG_GRPC_TARGET"
            })
        );
        values.insert("ORG_GRPC_TARGET".into(), "https://organization:9002".into());
        let tls = ComplianceServiceConfig::from_values(values.clone())
            .unwrap()
            .workload_tls
            .unwrap();
        let marty_service_runtime::RemoteTlsIdentityFiles::OpenBao(identity) = tls.identity else {
            panic!("omitted provider must preserve OpenBao");
        };
        assert_eq!(identity.kms_key_version, 1);
        values.insert("GRPC_WORKLOAD_TLS_CLIENT_KEY".into(), "legacy.pem".into());
        assert_eq!(
            ComplianceServiceConfig::from_values(values),
            Err(ComplianceConfigError::Invalid {
                name: "GRPC_WORKLOAD_TLS_CLIENT_KEY"
            })
        );
    }

    #[test]
    fn deployed_environments_reject_plaintext_override() {
        for environment in ["beta", "production"] {
            let mut values = base(environment);
            values.insert("GRPC_SERVICE_TOKEN".into(), "s".repeat(32));
            values.insert("GRPC_INSECURE_ALLOWED".into(), "true".into());
            assert_eq!(
                ComplianceServiceConfig::from_values(values),
                Err(ComplianceConfigError::Invalid {
                    name: "GRPC_INSECURE_ALLOWED"
                })
            );
        }
    }
}
