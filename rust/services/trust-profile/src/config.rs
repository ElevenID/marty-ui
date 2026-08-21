use std::{collections::BTreeMap, fs, net::SocketAddr, time::Duration};

use thiserror::Error;
use url::Url;
use uuid::Uuid;

const MINIMUM_SERVICE_SECRET_BYTES: usize = 32;
const MINIMUM_INTERNAL_API_KEY_BYTES: usize = 16;

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
pub struct TrustProfileServiceConfig {
    pub environment: RuntimeEnvironment,
    pub http_addr: SocketAddr,
    pub database_url: String,
    pub database_max_connections: u32,
    pub organization_grpc_target: String,
    pub service_token: Option<String>,
    pub internal_api_key: Option<String>,
    pub dependency_timeout: Duration,
    pub marty_organization_id: Uuid,
    pub marty_issuer_did: String,
    pub marty_issuer_url: String,
    pub release_version: String,
    pub build_revision: String,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TrustProfileConfigError {
    #[error("TRUST_PROFILE.CONFIGURATION: {name} is required")]
    Missing { name: &'static str },
    #[error("TRUST_PROFILE.CONFIGURATION: {name} is invalid")]
    Invalid { name: &'static str },
    #[error("TRUST_PROFILE.CONFIGURATION: {name} must contain at least {minimum} bytes")]
    SecretTooShort { name: &'static str, minimum: usize },
    #[error("TRUST_PROFILE.CONFIGURATION: {name}_FILE could not be read")]
    SecretFile { name: &'static str },
}

impl TrustProfileServiceConfig {
    pub fn from_env() -> Result<Self, TrustProfileConfigError> {
        let mut values = std::env::vars().collect::<BTreeMap<_, _>>();
        for name in ["GRPC_SERVICE_TOKEN", "SIGNING_KEYS_INTERNAL_API_KEY"] {
            load_secret(&mut values, name)?;
        }
        Self::from_values(values)
    }

    pub fn from_values(
        values: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, TrustProfileConfigError> {
        let values = values.into_iter().collect::<BTreeMap<_, _>>();
        let environment = environment(value(&values, "ENVIRONMENT").unwrap_or("development"))?;
        let http_addr = listener(&values)?;
        let database_url = required(&values, "DATABASE_URL")?.replacen(
            "postgresql+asyncpg://",
            "postgresql://",
            1,
        );
        validate_url(&database_url, "DATABASE_URL", &["postgres", "postgresql"])?;
        let database_max_connections =
            number(&values, "TRUST_PROFILE_DATABASE_MAX_CONNECTIONS", 20_u32)?;
        if database_max_connections == 0 || database_max_connections > 100 {
            return Err(invalid("TRUST_PROFILE_DATABASE_MAX_CONNECTIONS"));
        }
        let organization_grpc_target =
            grpc_target(value(&values, "ORG_GRPC_TARGET").unwrap_or("organization:9002"))?;
        let service_token = secret(
            &values,
            "GRPC_SERVICE_TOKEN",
            MINIMUM_SERVICE_SECRET_BYTES,
            environment,
        )?;
        let internal_api_key = secret(
            &values,
            "SIGNING_KEYS_INTERNAL_API_KEY",
            MINIMUM_INTERNAL_API_KEY_BYTES,
            environment,
        )?;
        let marty_organization_id = value(&values, "MARTY_ORG_ID")
            .unwrap_or("00000000-0000-0000-0000-000000000001")
            .parse()
            .map_err(|_| invalid("MARTY_ORG_ID"))?;
        let organization_slug = value(&values, "MARTY_ORG_SLUG").unwrap_or("marty");
        let public_domain = value(&values, "PUBLIC_DOMAIN").unwrap_or("localhost");
        let marty_issuer_did = value(&values, "MARTY_ISSUER_DID")
            .map(str::to_owned)
            .unwrap_or_else(|| format!("did:web:{public_domain}:orgs:{organization_slug}"));
        if !marty_issuer_did.starts_with("did:") {
            return Err(invalid("MARTY_ISSUER_DID"));
        }
        let marty_issuer_url = ["MARTY_ISSUER_BASE_URL", "ISSUER_BASE_URL", "PUBLIC_API_URL"]
            .into_iter()
            .find_map(|name| value(&values, name))
            .unwrap_or("http://localhost:8000")
            .to_owned();
        validate_url(
            &marty_issuer_url,
            "MARTY_ISSUER_BASE_URL",
            &["http", "https"],
        )?;
        if environment.is_deployed()
            && Url::parse(&marty_issuer_url)
                .map_err(|_| invalid("MARTY_ISSUER_BASE_URL"))?
                .scheme()
                != "https"
        {
            return Err(invalid("MARTY_ISSUER_BASE_URL"));
        }
        let dependency_timeout = Duration::from_secs(number(
            &values,
            "TRUST_PROFILE_DEPENDENCY_TIMEOUT_SECONDS",
            5_u64,
        )?);
        if dependency_timeout.is_zero() {
            return Err(invalid("TRUST_PROFILE_DEPENDENCY_TIMEOUT_SECONDS"));
        }
        Ok(Self {
            environment,
            http_addr,
            database_url,
            database_max_connections,
            organization_grpc_target,
            service_token,
            internal_api_key,
            dependency_timeout,
            marty_organization_id,
            marty_issuer_did,
            marty_issuer_url: marty_issuer_url.trim_end_matches('/').to_owned(),
            release_version: value(&values, "MARTY_RELEASE_VERSION")
                .unwrap_or(env!("CARGO_PKG_VERSION"))
                .to_owned(),
            build_revision: value(&values, "MARTY_UI_SHA")
                .unwrap_or("unknown")
                .to_owned(),
        })
    }

    #[must_use]
    pub const fn service_authentication_required(&self) -> bool {
        self.environment.is_deployed()
    }
}

fn environment(value: &str) -> Result<RuntimeEnvironment, TrustProfileConfigError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "development" | "dev" | "local" => Ok(RuntimeEnvironment::Development),
        "test" => Ok(RuntimeEnvironment::Test),
        "beta" => Ok(RuntimeEnvironment::Beta),
        "production" | "prod" => Ok(RuntimeEnvironment::Production),
        _ => Err(invalid("ENVIRONMENT")),
    }
}

fn listener(values: &BTreeMap<String, String>) -> Result<SocketAddr, TrustProfileConfigError> {
    if let Some(address) = value(values, "TRUST_PROFILE_HTTP_ADDR") {
        return address
            .parse()
            .map_err(|_| invalid("TRUST_PROFILE_HTTP_ADDR"));
    }
    Ok(SocketAddr::from((
        [0, 0, 0, 0],
        number(values, "TRUST_PROFILE_SERVICE_PORT", 8004_u16)?,
    )))
}

fn grpc_target(value: &str) -> Result<String, TrustProfileConfigError> {
    if value.chars().any(char::is_whitespace) {
        return Err(invalid("ORG_GRPC_TARGET"));
    }
    Ok(if value.contains("://") {
        value.to_owned()
    } else {
        format!("http://{value}")
    })
}

fn validate_url(
    value: &str,
    name: &'static str,
    schemes: &[&str],
) -> Result<(), TrustProfileConfigError> {
    let parsed = Url::parse(value).map_err(|_| invalid(name))?;
    if !schemes.contains(&parsed.scheme()) || parsed.host_str().is_none() {
        return Err(invalid(name));
    }
    Ok(())
}

fn secret(
    values: &BTreeMap<String, String>,
    name: &'static str,
    minimum: usize,
    environment: RuntimeEnvironment,
) -> Result<Option<String>, TrustProfileConfigError> {
    match value(values, name) {
        Some(value) if value.len() >= minimum => Ok(Some(value.to_owned())),
        Some(_) => Err(TrustProfileConfigError::SecretTooShort { name, minimum }),
        None if environment.is_deployed() => Err(TrustProfileConfigError::Missing { name }),
        None => Ok(None),
    }
}

fn load_secret(
    values: &mut BTreeMap<String, String>,
    name: &'static str,
) -> Result<(), TrustProfileConfigError> {
    if value(values, name).is_some() {
        return Ok(());
    }
    let file_name = format!("{name}_FILE");
    let Some(path) = value(values, &file_name).map(str::to_owned) else {
        return Ok(());
    };
    let secret =
        fs::read_to_string(path).map_err(|_| TrustProfileConfigError::SecretFile { name })?;
    values.insert(name.to_owned(), secret.trim().to_owned());
    Ok(())
}

fn number<T>(
    values: &BTreeMap<String, String>,
    name: &'static str,
    default: T,
) -> Result<T, TrustProfileConfigError>
where
    T: std::str::FromStr,
{
    value(values, name).map_or(Ok(default), |raw| raw.parse().map_err(|_| invalid(name)))
}

fn required(
    values: &BTreeMap<String, String>,
    name: &'static str,
) -> Result<String, TrustProfileConfigError> {
    value(values, name)
        .map(str::to_owned)
        .ok_or(TrustProfileConfigError::Missing { name })
}

fn value<'a>(values: &'a BTreeMap<String, String>, name: &str) -> Option<&'a str> {
    values
        .get(name)
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn invalid(name: &'static str) -> TrustProfileConfigError {
    TrustProfileConfigError::Invalid { name }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(environment: &str) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("ENVIRONMENT".into(), environment.into()),
            (
                "DATABASE_URL".into(),
                "postgresql+asyncpg://marty:secret@localhost/marty".into(),
            ),
            (
                "MARTY_ISSUER_BASE_URL".into(),
                "https://issuer.example/".into(),
            ),
        ])
    }

    #[test]
    fn normalizes_the_python_database_url_and_compose_target() {
        let config = TrustProfileServiceConfig::from_values(values("development")).unwrap();
        assert!(config.database_url.starts_with("postgresql://"));
        assert_eq!(config.organization_grpc_target, "http://organization:9002");
        assert_eq!(config.http_addr.port(), 8004);
        assert_eq!(config.marty_issuer_url, "https://issuer.example");
    }

    #[test]
    fn deployed_runtime_fails_closed_without_internal_secrets() {
        let beta = values("beta");
        assert_eq!(
            TrustProfileServiceConfig::from_values(beta),
            Err(TrustProfileConfigError::Missing {
                name: "GRPC_SERVICE_TOKEN"
            })
        );
        let mut beta = values("beta");
        beta.insert("GRPC_SERVICE_TOKEN".into(), "s".repeat(32));
        assert_eq!(
            TrustProfileServiceConfig::from_values(beta),
            Err(TrustProfileConfigError::Missing {
                name: "SIGNING_KEYS_INTERNAL_API_KEY"
            })
        );
    }

    #[test]
    fn deployed_runtime_rejects_insecure_issuer_origin() {
        let mut beta = values("beta");
        beta.insert("GRPC_SERVICE_TOKEN".into(), "s".repeat(32));
        beta.insert("SIGNING_KEYS_INTERNAL_API_KEY".into(), "k".repeat(16));
        beta.insert(
            "MARTY_ISSUER_BASE_URL".into(),
            "http://issuer.example".into(),
        );
        assert_eq!(
            TrustProfileServiceConfig::from_values(beta),
            Err(TrustProfileConfigError::Invalid {
                name: "MARTY_ISSUER_BASE_URL"
            })
        );
    }
}
