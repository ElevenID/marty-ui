use std::{collections::BTreeMap, fs, net::SocketAddr, path::PathBuf};

use mmf_messaging::OutboxDispatcherConfig;
use thiserror::Error;
use url::Url;
use uuid::Uuid;

const DEFAULT_MARTY_ORGANIZATION_ID: &str = "00000000-0000-0000-0000-000000000001";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrganizationEnvironment {
    Development,
    Test,
    Beta,
    Production,
}

impl OrganizationEnvironment {
    #[must_use]
    pub const fn is_deployed(self) -> bool {
        matches!(self, Self::Beta | Self::Production)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrganizationServiceConfig {
    pub environment: OrganizationEnvironment,
    pub http_addr: SocketAddr,
    pub grpc_addr: SocketAddr,
    pub grpc_server_tls: Option<OrganizationGrpcServerTls>,
    pub database_url: String,
    pub database_max_connections: u32,
    pub redis_url: String,
    pub redis_database: u32,
    pub service_token: Option<String>,
    pub event_stream_target: String,
    pub event_stream_ca_certificate: Option<PathBuf>,
    pub event_stream_timeout_seconds: u64,
    pub organization_creation_enabled: bool,
    pub marty_organization_id: Uuid,
    pub marty_admin_email: Option<String>,
    pub marty_reviewer_email: Option<String>,
    pub outbox: OutboxDispatcherConfig,
    pub release_version: String,
    pub build_revision: String,
}

pub use marty_service_runtime::GrpcServerTls as OrganizationGrpcServerTls;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum OrganizationConfigError {
    #[error("ORGANIZATION.CONFIGURATION: {name} is required")]
    Missing { name: &'static str },
    #[error("ORGANIZATION.CONFIGURATION: {name} is invalid")]
    Invalid { name: &'static str },
    #[error("ORGANIZATION.CONFIGURATION: {name}_FILE could not be read")]
    SecretFile { name: &'static str },
}

impl OrganizationServiceConfig {
    pub fn from_env() -> Result<Self, OrganizationConfigError> {
        let mut values = std::env::vars().collect::<BTreeMap<_, _>>();
        load_secret(&mut values, "GRPC_SERVICE_TOKEN")?;
        Self::from_values(values)
    }

    pub fn from_values(
        values: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, OrganizationConfigError> {
        let values = values.into_iter().collect::<BTreeMap<_, _>>();
        let environment = environment(value(&values, "ENVIRONMENT").unwrap_or("development"))?;
        let http_addr = listener(
            &values,
            "ORGANIZATION_HTTP_ADDR",
            "ORGANIZATION_SERVICE_PORT",
            8002,
        )?;
        let grpc_addr = listener(&values, "ORGANIZATION_GRPC_ADDR", "ORG_GRPC_PORT", 9002)?;
        if http_addr == grpc_addr {
            return Err(invalid("ORGANIZATION_GRPC_ADDR"));
        }
        let grpc_server_tls = grpc_server_tls(&values)?;
        let database_url = value(&values, "DATABASE_URL")
            .ok_or(OrganizationConfigError::Missing {
                name: "DATABASE_URL",
            })?
            .replace("postgresql+asyncpg://", "postgresql://");
        let database_url = Url::parse(&database_url).map_err(|_| invalid("DATABASE_URL"))?;
        if !matches!(database_url.scheme(), "postgres" | "postgresql") {
            return Err(invalid("DATABASE_URL"));
        }
        let database_url = database_url.to_string();
        let database_max_connections =
            number(&values, "ORGANIZATION_DATABASE_MAX_CONNECTIONS", 30)?;
        if database_max_connections == 0 {
            return Err(invalid("ORGANIZATION_DATABASE_MAX_CONNECTIONS"));
        }
        let redis_database = number(&values, "REDIS_DB_GATEWAY", 2)?;
        let redis_url = redis_url(
            value(&values, "REDIS_URL").unwrap_or("redis://localhost:6379"),
            redis_database,
        )?;
        let service_token = value(&values, "GRPC_SERVICE_TOKEN").map(str::to_owned);
        if environment.is_deployed() && service_token.is_none() {
            return Err(OrganizationConfigError::Missing {
                name: "GRPC_SERVICE_TOKEN",
            });
        }
        if service_token.as_ref().is_some_and(|token| token.len() < 32) {
            return Err(invalid("GRPC_SERVICE_TOKEN"));
        }
        if environment.is_deployed() && grpc_server_tls.is_none() {
            return Err(OrganizationConfigError::Missing {
                name: "GRPC_WORKLOAD_TLS_SERVER_CERT",
            });
        }
        let event_stream_target = value(&values, "ES_GRPC_TARGET")
            .unwrap_or("event-stream:9015")
            .trim()
            .to_owned();
        if event_stream_target.is_empty() {
            return Err(invalid("ES_GRPC_TARGET"));
        }
        let event_stream_ca_certificate = value(&values, "ES_GRPC_CA_CERT").map(PathBuf::from);
        if environment.is_deployed() && event_stream_ca_certificate.is_none() {
            return Err(OrganizationConfigError::Missing {
                name: "ES_GRPC_CA_CERT",
            });
        }
        if event_stream_ca_certificate.is_some() && !event_stream_target.starts_with("https://") {
            return Err(invalid("ES_GRPC_TARGET"));
        }
        let marty_organization_id = value(&values, "MARTY_ORG_ID")
            .unwrap_or(DEFAULT_MARTY_ORGANIZATION_ID)
            .parse()
            .map_err(|_| invalid("MARTY_ORG_ID"))?;
        let outbox = OutboxDispatcherConfig {
            batch_size: number(&values, "ORGANIZATION_OUTBOX_BATCH_SIZE", 100)?,
            lease_duration_ms: number(&values, "ORGANIZATION_OUTBOX_LEASE_MS", 30_000)?,
            poll_interval_ms: number(&values, "ORGANIZATION_OUTBOX_POLL_MS", 250)?,
            retry_base_ms: number(&values, "ORGANIZATION_OUTBOX_RETRY_BASE_MS", 1_000)?,
            retry_max_ms: number(&values, "ORGANIZATION_OUTBOX_RETRY_MAX_MS", 60_000)?,
            partition: optional_number(&values, "ORGANIZATION_OUTBOX_PARTITION")?,
        };
        outbox
            .validate()
            .map_err(|_| invalid("ORGANIZATION_OUTBOX_CONFIGURATION"))?;
        Ok(Self {
            environment,
            http_addr,
            grpc_addr,
            grpc_server_tls,
            database_url,
            database_max_connections,
            redis_url,
            redis_database,
            service_token,
            event_stream_target,
            event_stream_ca_certificate,
            event_stream_timeout_seconds: number(&values, "ES_GRPC_TIMEOUT_SECONDS", 5)?,
            organization_creation_enabled: boolean(&values, "ORGANIZATION_CREATION_ENABLED", true)?,
            marty_organization_id,
            marty_admin_email: email(&values, "MARTY_ORG_ADMIN_EMAIL")?,
            marty_reviewer_email: email(&values, "MARTY_ORG_REVIEWER_EMAIL")?,
            outbox,
            release_version: value(&values, "MARTY_RELEASE_VERSION")
                .unwrap_or(env!("CARGO_PKG_VERSION"))
                .to_owned(),
            build_revision: value(&values, "MARTY_UI_SHA")
                .unwrap_or("unknown")
                .to_owned(),
        })
    }
}

fn value<'a>(values: &'a BTreeMap<String, String>, name: &str) -> Option<&'a str> {
    values
        .get(name)
        .map(String::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())
}

fn invalid(name: &'static str) -> OrganizationConfigError {
    OrganizationConfigError::Invalid { name }
}

fn grpc_server_tls(
    values: &BTreeMap<String, String>,
) -> Result<Option<OrganizationGrpcServerTls>, OrganizationConfigError> {
    if values.contains_key("GRPC_WORKLOAD_TLS_SERVER_KEY") {
        return Err(invalid("GRPC_WORKLOAD_TLS_SERVER_KEY"));
    }
    const NAMES: [&str; 6] = [
        "GRPC_WORKLOAD_TLS_SERVER_CERT",
        "GRPC_WORKLOAD_TLS_SERVER_KMS_ADDR",
        "GRPC_WORKLOAD_TLS_SERVER_KMS_CA_CERT",
        "GRPC_WORKLOAD_TLS_SERVER_KMS_TOKEN_FILE",
        "GRPC_WORKLOAD_TLS_SERVER_KMS_KEY_NAME",
        "GRPC_WORKLOAD_TLS_SERVER_KMS_KEY_VERSION",
    ];
    OrganizationGrpcServerTls::from_values(
        |name| values.get(name).map(String::as_str),
        marty_service_runtime::TlsIdentityNames::new("GRPC_WORKLOAD_TLS_SERVER"),
        std::time::Duration::from_secs(10),
        64,
    )
    .map_err(|error| {
        let name = if error.ends_with("is required") {
            NAMES[0]
        } else {
            NAMES
                .iter()
                .copied()
                .find(|name| error.starts_with(name))
                .unwrap_or(NAMES[0])
        };
        invalid(name)
    })
}

fn environment(value: &str) -> Result<OrganizationEnvironment, OrganizationConfigError> {
    match value.to_ascii_lowercase().as_str() {
        "development" | "dev" | "local" => Ok(OrganizationEnvironment::Development),
        "test" => Ok(OrganizationEnvironment::Test),
        "beta" => Ok(OrganizationEnvironment::Beta),
        "production" | "prod" => Ok(OrganizationEnvironment::Production),
        _ => Err(invalid("ENVIRONMENT")),
    }
}

fn listener(
    values: &BTreeMap<String, String>,
    address_name: &'static str,
    port_name: &'static str,
    default_port: u16,
) -> Result<SocketAddr, OrganizationConfigError> {
    if let Some(address) = value(values, address_name) {
        return address.parse().map_err(|_| invalid(address_name));
    }
    let port = optional_number::<u16>(values, port_name)?.unwrap_or(default_port);
    Ok(SocketAddr::from(([0, 0, 0, 0], port)))
}

fn number<T>(
    values: &BTreeMap<String, String>,
    name: &'static str,
    default: T,
) -> Result<T, OrganizationConfigError>
where
    T: std::str::FromStr,
{
    optional_number(values, name).map(|value| value.unwrap_or(default))
}

fn optional_number<T>(
    values: &BTreeMap<String, String>,
    name: &'static str,
) -> Result<Option<T>, OrganizationConfigError>
where
    T: std::str::FromStr,
{
    value(values, name)
        .map(|value| value.parse().map_err(|_| invalid(name)))
        .transpose()
}

fn boolean(
    values: &BTreeMap<String, String>,
    name: &'static str,
    default: bool,
) -> Result<bool, OrganizationConfigError> {
    value(values, name).map_or(Ok(default), |value| {
        match value.to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" => Ok(true),
            "false" | "0" | "no" => Ok(false),
            _ => Err(invalid(name)),
        }
    })
}

fn email(
    values: &BTreeMap<String, String>,
    name: &'static str,
) -> Result<Option<String>, OrganizationConfigError> {
    let email = value(values, name).map(str::to_ascii_lowercase);
    if email.as_ref().is_some_and(|email| !email.contains('@')) {
        return Err(invalid(name));
    }
    Ok(email)
}

fn redis_url(value: &str, database: u32) -> Result<String, OrganizationConfigError> {
    let mut url = Url::parse(value).map_err(|_| invalid("REDIS_URL"))?;
    if !matches!(url.scheme(), "redis" | "rediss" | "unix")
        || (url.scheme() == "unix" && (url.host_str().is_some() || !url.path().starts_with('/')))
    {
        return Err(invalid("REDIS_URL"));
    }
    if url.scheme() == "unix" {
        url.query_pairs_mut()
            .clear()
            .append_pair("db", &database.to_string());
    } else {
        url.set_path(&format!("/{database}"));
    }
    Ok(url.to_string())
}

fn load_secret(
    values: &mut BTreeMap<String, String>,
    name: &'static str,
) -> Result<(), OrganizationConfigError> {
    let file_name = format!("{name}_FILE");
    let direct = value(values, name).map(str::to_owned);
    let file = value(values, &file_name).map(str::to_owned);
    if direct.is_some() && file.is_some() {
        return Err(invalid(name));
    }
    if let Some(file) = file {
        let secret = fs::read_to_string(file)
            .map_err(|_| OrganizationConfigError::SecretFile { name })?
            .trim()
            .to_owned();
        if secret.is_empty() {
            return Err(invalid(name));
        }
        values.insert(name.into(), secret);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> BTreeMap<String, String> {
        BTreeMap::from([(
            "DATABASE_URL".into(),
            "postgresql+asyncpg://marty:secret@postgres:5432/marty".into(),
        )])
    }

    #[test]
    fn development_defaults_preserve_legacy_ports_and_redis_database() {
        let config = OrganizationServiceConfig::from_values(base()).expect("config");
        assert_eq!(config.http_addr.port(), 8002);
        assert_eq!(config.grpc_addr.port(), 9002);
        assert_eq!(config.redis_url, "redis://localhost:6379/2");
        assert!(config.database_url.starts_with("postgresql://"));
        assert!(config.organization_creation_enabled);
    }

    #[test]
    fn local_redis_socket_preserves_its_path_and_selects_database() {
        assert_eq!(
            redis_url("unix:///run/marty-redis/redis.sock", 2).unwrap(),
            "unix:///run/marty-redis/redis.sock?db=2"
        );
        assert!(redis_url("unix://remote/run/redis.sock", 2).is_err());
    }

    #[test]
    fn deployed_configuration_requires_a_strong_service_token() {
        let mut values = base();
        values.insert("ENVIRONMENT".into(), "beta".into());
        assert!(matches!(
            OrganizationServiceConfig::from_values(values.clone()),
            Err(OrganizationConfigError::Missing {
                name: "GRPC_SERVICE_TOKEN"
            })
        ));
        values.insert("GRPC_SERVICE_TOKEN".into(), "too-short".into());
        assert!(matches!(
            OrganizationServiceConfig::from_values(values),
            Err(OrganizationConfigError::Invalid {
                name: "GRPC_SERVICE_TOKEN"
            })
        ));
    }

    #[test]
    fn deployed_configuration_requires_remote_grpc_server_identity() {
        for environment in ["beta", "production"] {
            let mut values = base();
            values.insert("ENVIRONMENT".into(), environment.into());
            values.insert("GRPC_SERVICE_TOKEN".into(), "s".repeat(32));
            assert_eq!(
                OrganizationServiceConfig::from_values(values.clone()),
                Err(OrganizationConfigError::Missing {
                    name: "GRPC_WORKLOAD_TLS_SERVER_CERT"
                })
            );
            for (name, value) in [
                ("GRPC_WORKLOAD_TLS_SERVER_CERT", "server.pem"),
                ("GRPC_WORKLOAD_TLS_SERVER_KMS_ADDR", "https://bao:8200"),
                ("GRPC_WORKLOAD_TLS_SERVER_KMS_CA_CERT", "bao-ca.pem"),
                ("GRPC_WORKLOAD_TLS_SERVER_KMS_TOKEN_FILE", "token"),
                (
                    "GRPC_WORKLOAD_TLS_SERVER_KMS_KEY_NAME",
                    "organization-server",
                ),
                ("GRPC_WORKLOAD_TLS_SERVER_KMS_KEY_VERSION", "1"),
            ] {
                values.insert(name.into(), value.into());
            }
            assert_eq!(
                OrganizationServiceConfig::from_values(values.clone()),
                Err(OrganizationConfigError::Missing {
                    name: "ES_GRPC_CA_CERT"
                })
            );
            values.insert("ES_GRPC_CA_CERT".into(), "public-ca.pem".into());
            assert_eq!(
                OrganizationServiceConfig::from_values(values.clone()),
                Err(invalid("ES_GRPC_TARGET"))
            );
            values.insert("ES_GRPC_TARGET".into(), "https://event-stream:9015".into());
            assert!(OrganizationServiceConfig::from_values(values)
                .unwrap()
                .grpc_server_tls
                .is_some());
        }
    }

    #[test]
    fn invalid_listener_cache_and_outbox_values_fail_closed() {
        for (name, value) in [
            ("ORGANIZATION_SERVICE_PORT", "not-a-port"),
            ("REDIS_URL", "http://redis:6379"),
            ("ORGANIZATION_OUTBOX_BATCH_SIZE", "0"),
        ] {
            let mut values = base();
            values.insert(name.into(), value.into());
            assert!(OrganizationServiceConfig::from_values(values).is_err());
        }
    }

    #[test]
    fn remote_grpc_server_identity_is_complete_and_rejects_private_key_files() {
        let mut values = base();
        values.insert("GRPC_WORKLOAD_TLS_SERVER_CERT".into(), "server.pem".into());
        assert_eq!(
            OrganizationServiceConfig::from_values(values.clone()),
            Err(invalid("GRPC_WORKLOAD_TLS_SERVER_CERT"))
        );
        for (name, value) in [
            ("GRPC_WORKLOAD_TLS_SERVER_KMS_ADDR", "https://bao:8200"),
            ("GRPC_WORKLOAD_TLS_SERVER_KMS_CA_CERT", "bao-ca.pem"),
            ("GRPC_WORKLOAD_TLS_SERVER_KMS_TOKEN_FILE", "token"),
            (
                "GRPC_WORKLOAD_TLS_SERVER_KMS_KEY_NAME",
                "organization-server",
            ),
            ("GRPC_WORKLOAD_TLS_SERVER_KMS_KEY_VERSION", "1"),
        ] {
            values.insert(name.into(), value.into());
        }
        let tls = OrganizationServiceConfig::from_values(values.clone())
            .unwrap()
            .grpc_server_tls
            .unwrap();
        let OrganizationGrpcServerTls::OpenBao(identity) = tls else {
            panic!("omitted provider must preserve OpenBao");
        };
        assert_eq!(identity.kms_key_version, 1);
        values.insert(
            "GRPC_WORKLOAD_TLS_SERVER_KMS_ADDR".into(),
            "http://bao:8200".into(),
        );
        assert_eq!(
            OrganizationServiceConfig::from_values(values.clone()),
            Err(invalid("GRPC_WORKLOAD_TLS_SERVER_KMS_ADDR"))
        );
        values.insert(
            "GRPC_WORKLOAD_TLS_SERVER_KMS_ADDR".into(),
            "https://bao:8200".into(),
        );
        values.insert("GRPC_WORKLOAD_TLS_SERVER_KEY".into(), "legacy.pem".into());
        assert_eq!(
            OrganizationServiceConfig::from_values(values),
            Err(invalid("GRPC_WORKLOAD_TLS_SERVER_KEY"))
        );
    }
}
