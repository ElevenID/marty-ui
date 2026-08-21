use std::{collections::BTreeMap, fs, net::SocketAddr, time::Duration};

use thiserror::Error;
use url::Url;
use uuid::Uuid;

use crate::RuntimeEnvironment;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialTemplateServiceConfig {
    pub environment: RuntimeEnvironment,
    pub http_addr: SocketAddr,
    pub grpc_addr: SocketAddr,
    pub database_url: String,
    pub database_max_connections: u32,
    pub service_token: Option<String>,
    pub organization_grpc_target: String,
    pub revocation_grpc_target: String,
    pub signing_keys_internal_url: String,
    pub signing_keys_internal_api_key: Option<String>,
    pub trust_profile_service_url: String,
    pub public_api_origin: Url,
    pub marty_organization_id: Uuid,
    pub migration_profile: String,
    pub dependency_timeout: Duration,
    pub release_version: String,
    pub build_revision: String,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CredentialTemplateConfigError {
    #[error("CREDENTIAL_TEMPLATE.CONFIGURATION: {name} is required")]
    Missing { name: &'static str },
    #[error("CREDENTIAL_TEMPLATE.CONFIGURATION: {name} is invalid")]
    Invalid { name: &'static str },
    #[error("CREDENTIAL_TEMPLATE.CONFIGURATION: {name}_FILE could not be read")]
    SecretFile { name: &'static str },
}

impl CredentialTemplateServiceConfig {
    pub fn from_env() -> Result<Self, CredentialTemplateConfigError> {
        let mut values = std::env::vars().collect::<BTreeMap<_, _>>();
        for name in ["GRPC_SERVICE_TOKEN", "SIGNING_KEYS_INTERNAL_API_KEY"] {
            load_secret(&mut values, name)?;
        }
        Self::from_values(values)
    }

    pub fn from_values(
        values: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, CredentialTemplateConfigError> {
        let values = values.into_iter().collect::<BTreeMap<_, _>>();
        let environment =
            parse_environment(value(&values, "ENVIRONMENT").unwrap_or("development"))?;
        let http_addr = listener(
            &values,
            "CREDENTIAL_TEMPLATE_HTTP_ADDR",
            "CREDENTIAL_TEMPLATE_SERVICE_PORT",
            8003,
        )?;
        let grpc_addr = listener(
            &values,
            "CREDENTIAL_TEMPLATE_GRPC_ADDR",
            "CT_GRPC_PORT",
            9003,
        )?;
        if http_addr == grpc_addr {
            return Err(invalid("CREDENTIAL_TEMPLATE_GRPC_ADDR"));
        }

        let database_url = value(&values, "DATABASE_URL")
            .ok_or(CredentialTemplateConfigError::Missing {
                name: "DATABASE_URL",
            })?
            .replace("postgresql+asyncpg://", "postgresql://");
        let parsed_database = Url::parse(&database_url).map_err(|_| invalid("DATABASE_URL"))?;
        if !matches!(parsed_database.scheme(), "postgres" | "postgresql") {
            return Err(invalid("DATABASE_URL"));
        }
        let database_max_connections = number(
            &values,
            "CREDENTIAL_TEMPLATE_DATABASE_MAX_CONNECTIONS",
            30_u32,
        )?;
        if database_max_connections == 0 {
            return Err(invalid("CREDENTIAL_TEMPLATE_DATABASE_MAX_CONNECTIONS"));
        }

        let service_token = value(&values, "GRPC_SERVICE_TOKEN").map(str::to_owned);
        let signing_keys_internal_api_key =
            value(&values, "SIGNING_KEYS_INTERNAL_API_KEY").map(str::to_owned);
        if environment_is_deployed(environment) {
            require_secret(&service_token, "GRPC_SERVICE_TOKEN", 32)?;
            require_secret(
                &signing_keys_internal_api_key,
                "SIGNING_KEYS_INTERNAL_API_KEY",
                16,
            )?;
        }
        let public_api_origin = public_origin(&values, environment)?;
        let marty_organization_id = value(&values, "MARTY_ORG_ID")
            .unwrap_or("00000000-0000-0000-0000-000000000001")
            .parse()
            .map_err(|_| invalid("MARTY_ORG_ID"))?;
        let migration_profile = value(&values, "MARTY_MIGRATION_PROFILE")
            .unwrap_or("dev")
            .to_ascii_lowercase();
        if !matches!(
            migration_profile.as_str(),
            "dev" | "beta" | "prod" | "production" | "selfhost-production" | "test"
        ) {
            return Err(invalid("MARTY_MIGRATION_PROFILE"));
        }

        Ok(Self {
            environment,
            http_addr,
            grpc_addr,
            database_url: parsed_database.to_string(),
            database_max_connections,
            service_token,
            organization_grpc_target: target(&values, "ORG_GRPC_TARGET", "organization:9002")?,
            revocation_grpc_target: target(&values, "RP_GRPC_TARGET", "revocation-profile:9013")?,
            signing_keys_internal_url: http_url(
                &values,
                "SIGNING_KEYS_INTERNAL_URL",
                "http://gateway:8000/internal/signing-keys",
            )?,
            signing_keys_internal_api_key,
            trust_profile_service_url: http_url(
                &values,
                "TRUST_PROFILE_SERVICE_URL",
                "http://trust-profile:8004",
            )?,
            public_api_origin,
            marty_organization_id,
            migration_profile,
            dependency_timeout: Duration::from_secs(number(
                &values,
                "CREDENTIAL_TEMPLATE_DEPENDENCY_TIMEOUT_SECONDS",
                3_u64,
            )?),
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
        environment_is_deployed(self.environment)
    }
}

const fn environment_is_deployed(environment: RuntimeEnvironment) -> bool {
    matches!(
        environment,
        RuntimeEnvironment::Beta | RuntimeEnvironment::Production
    )
}

fn require_secret(
    secret: &Option<String>,
    name: &'static str,
    minimum_length: usize,
) -> Result<(), CredentialTemplateConfigError> {
    let Some(secret) = secret else {
        return Err(CredentialTemplateConfigError::Missing { name });
    };
    if secret.len() < minimum_length {
        return Err(invalid(name));
    }
    Ok(())
}

fn parse_environment(value: &str) -> Result<RuntimeEnvironment, CredentialTemplateConfigError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "development" | "dev" | "local" => Ok(RuntimeEnvironment::Development),
        "test" => Ok(RuntimeEnvironment::Test),
        "beta" => Ok(RuntimeEnvironment::Beta),
        "production" | "prod" => Ok(RuntimeEnvironment::Production),
        _ => Err(invalid("ENVIRONMENT")),
    }
}

fn value<'a>(values: &'a BTreeMap<String, String>, name: &str) -> Option<&'a str> {
    values
        .get(name)
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn listener(
    values: &BTreeMap<String, String>,
    address_name: &'static str,
    port_name: &'static str,
    default_port: u16,
) -> Result<SocketAddr, CredentialTemplateConfigError> {
    if let Some(address) = value(values, address_name) {
        return address.parse().map_err(|_| invalid(address_name));
    }
    let port = number(values, port_name, default_port)?;
    Ok(SocketAddr::from(([0, 0, 0, 0], port)))
}

fn target(
    values: &BTreeMap<String, String>,
    name: &'static str,
    default: &str,
) -> Result<String, CredentialTemplateConfigError> {
    let target = value(values, name).unwrap_or(default);
    if target.chars().any(char::is_whitespace) {
        return Err(invalid(name));
    }
    Ok(if target.contains("://") {
        target.to_owned()
    } else {
        format!("http://{target}")
    })
}

fn http_url(
    values: &BTreeMap<String, String>,
    name: &'static str,
    default: &str,
) -> Result<String, CredentialTemplateConfigError> {
    let parsed = Url::parse(value(values, name).unwrap_or(default)).map_err(|_| invalid(name))?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return Err(invalid(name));
    }
    Ok(parsed.as_str().trim_end_matches('/').to_owned())
}

fn public_origin(
    values: &BTreeMap<String, String>,
    environment: RuntimeEnvironment,
) -> Result<Url, CredentialTemplateConfigError> {
    let configured = ["PUBLIC_API_URL", "ISSUER_BASE_URL", "PUBLIC_BASE_URL"]
        .into_iter()
        .find_map(|name| value(values, name));
    let raw = match configured {
        Some(value) => value,
        None if environment_is_deployed(environment) => {
            return Err(CredentialTemplateConfigError::Missing {
                name: "PUBLIC_API_URL",
            })
        }
        None => "http://localhost:8000",
    };
    let parsed = Url::parse(raw).map_err(|_| invalid("PUBLIC_API_URL"))?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || matches!(parsed.host_str(), Some("gateway" | "marty.example"))
        || (environment_is_deployed(environment) && parsed.scheme() != "https")
    {
        return Err(invalid("PUBLIC_API_URL"));
    }
    Ok(parsed)
}

fn number<T>(
    values: &BTreeMap<String, String>,
    name: &'static str,
    default: T,
) -> Result<T, CredentialTemplateConfigError>
where
    T: std::str::FromStr,
{
    value(values, name).map_or(Ok(default), |raw| raw.parse().map_err(|_| invalid(name)))
}

fn load_secret(
    values: &mut BTreeMap<String, String>,
    name: &'static str,
) -> Result<(), CredentialTemplateConfigError> {
    if value(values, name).is_some() {
        return Ok(());
    }
    let file_name = format!("{name}_FILE");
    let Some(path) = value(values, &file_name).map(str::to_owned) else {
        return Ok(());
    };
    let secret =
        fs::read_to_string(path).map_err(|_| CredentialTemplateConfigError::SecretFile { name })?;
    values.insert(name.to_owned(), secret.trim().to_owned());
    Ok(())
}

fn invalid(name: &'static str) -> CredentialTemplateConfigError {
    CredentialTemplateConfigError::Invalid { name }
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
        ])
    }

    #[test]
    fn python_database_url_and_compose_grpc_targets_are_normalized() {
        let config = CredentialTemplateServiceConfig::from_values(values("development")).unwrap();
        assert!(config.database_url.starts_with("postgresql://"));
        assert_eq!(config.organization_grpc_target, "http://organization:9002");
        assert_eq!(
            config.revocation_grpc_target,
            "http://revocation-profile:9013"
        );
        assert_eq!(config.http_addr.port(), 8003);
        assert_eq!(config.grpc_addr.port(), 9003);
    }

    #[test]
    fn deployed_configuration_fails_closed_without_both_native_secrets() {
        let beta = values("beta");
        assert_eq!(
            CredentialTemplateServiceConfig::from_values(beta.clone()).unwrap_err(),
            CredentialTemplateConfigError::Missing {
                name: "GRPC_SERVICE_TOKEN"
            }
        );
        let mut token_only = beta;
        token_only.insert("GRPC_SERVICE_TOKEN".into(), "s".repeat(32));
        assert_eq!(
            CredentialTemplateServiceConfig::from_values(token_only.clone()).unwrap_err(),
            CredentialTemplateConfigError::Missing {
                name: "SIGNING_KEYS_INTERNAL_API_KEY"
            }
        );
        token_only.insert("SIGNING_KEYS_INTERNAL_API_KEY".into(), "k".repeat(16));
        assert_eq!(
            CredentialTemplateServiceConfig::from_values(token_only).unwrap_err(),
            CredentialTemplateConfigError::Missing {
                name: "PUBLIC_API_URL"
            }
        );
    }

    #[test]
    fn invalid_urls_ports_and_shared_listeners_are_rejected() {
        let mut invalid_url = values("development");
        invalid_url.insert(
            "TRUST_PROFILE_SERVICE_URL".into(),
            "file:///tmp/trust".into(),
        );
        assert!(CredentialTemplateServiceConfig::from_values(invalid_url).is_err());

        let mut shared = values("development");
        shared.insert("CREDENTIAL_TEMPLATE_SERVICE_PORT".into(), "9003".into());
        assert!(CredentialTemplateServiceConfig::from_values(shared).is_err());

        let mut insecure_beta = values("beta");
        insecure_beta.insert("GRPC_SERVICE_TOKEN".into(), "s".repeat(32));
        insecure_beta.insert("SIGNING_KEYS_INTERNAL_API_KEY".into(), "k".repeat(16));
        insecure_beta.insert("PUBLIC_API_URL".into(), "http://beta.example".into());
        assert!(CredentialTemplateServiceConfig::from_values(insecure_beta).is_err());
    }
}
