use std::{collections::BTreeMap, net::SocketAddr};

use thiserror::Error;
use url::Url;

const DEFAULT_HTTP_ADDR: &str = "0.0.0.0:8011";
const DEFAULT_GRPC_ADDR: &str = "0.0.0.0:9011";
const MINIMUM_SECRET_BYTES: usize = 32;

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlowServiceConfig {
    pub environment: Environment,
    pub http_addr: SocketAddr,
    pub grpc_addr: SocketAddr,
    pub database_url: String,
    pub database_max_connections: u32,
    pub redis_url: String,
    pub redis_database: u8,
    pub organization_grpc_target: String,
    pub credential_template_grpc_target: String,
    pub presentation_policy_grpc_target: String,
    pub issuance_grpc_target: String,
    pub signing_keys_url: String,
    pub signing_keys_api_key: Option<String>,
    pub issuance_url: String,
    pub issuance_api_key: Option<String>,
    pub service_token: Option<String>,
    pub webhook_secret: Option<String>,
    pub release_version: String,
    pub build_revision: String,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum FlowConfigError {
    #[error("FLOW.CONFIGURATION: {name} is required")]
    Missing { name: &'static str },
    #[error("FLOW.CONFIGURATION: {name} is invalid")]
    Invalid { name: &'static str },
    #[error("FLOW.CONFIGURATION: {name} must contain at least {minimum} bytes")]
    SecretTooShort { name: &'static str, minimum: usize },
}

impl FlowServiceConfig {
    pub fn from_env() -> Result<Self, FlowConfigError> {
        Self::from_values(std::env::vars())
    }

    pub fn from_values(
        values: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, FlowConfigError> {
        let values = values.into_iter().collect::<BTreeMap<_, _>>();
        let environment = parse_environment(value(&values, "ENVIRONMENT").unwrap_or("production"))?;
        let http_addr = parse_address(
            value(&values, "FLOW_HTTP_ADDR").unwrap_or(DEFAULT_HTTP_ADDR),
            "FLOW_HTTP_ADDR",
        )?;
        let grpc_addr = parse_address(
            value(&values, "FLOW_GRPC_ADDR").unwrap_or(DEFAULT_GRPC_ADDR),
            "FLOW_GRPC_ADDR",
        )?;
        if http_addr == grpc_addr {
            return Err(invalid("FLOW_GRPC_ADDR"));
        }

        let database_url = required(&values, "DATABASE_URL")?;
        validate_url(&database_url, "DATABASE_URL", &["postgres", "postgresql"])?;
        let database_max_connections = parse_bounded(
            value(&values, "FLOW_DATABASE_MAX_CONNECTIONS").unwrap_or("15"),
            "FLOW_DATABASE_MAX_CONNECTIONS",
            1,
            100,
        )?;
        let redis_url = required(&values, "REDIS_URL")?;
        validate_url(&redis_url, "REDIS_URL", &["redis", "rediss"])?;
        let redis_database = u8::try_from(parse_bounded(
            value(&values, "REDIS_DB_FLOW").unwrap_or("3"),
            "REDIS_DB_FLOW",
            0,
            255,
        )?)
        .map_err(|_| invalid("REDIS_DB_FLOW"))?;

        let organization_grpc_target = grpc_target(
            &values,
            "ORGANIZATION_GRPC_TARGET",
            Some("organization:9002"),
            environment,
        )?;
        let credential_template_grpc_target = grpc_target(
            &values,
            "CT_GRPC_TARGET",
            Some("credential-template:9003"),
            environment,
        )?;
        let presentation_policy_grpc_target = grpc_target(
            &values,
            "PP_GRPC_TARGET",
            Some("presentation-policy:9009"),
            environment,
        )?;
        let issuance_grpc_target = grpc_target(
            &values,
            "ISSUANCE_GRPC_TARGET",
            Some("issuance:9006"),
            environment,
        )?;
        let signing_keys_url = service_url(
            &values,
            "SIGNING_KEYS_INTERNAL_URL",
            Some("http://signing-keys:8017"),
            environment,
        )?;
        let issuance_url = service_url(
            &values,
            "ISSUANCE_SERVICE_URL",
            Some("http://issuance:8006"),
            environment,
        )?;

        let service_token = optional_secret(&values, "GRPC_SERVICE_TOKEN", environment)?;
        let webhook_secret = optional_secret(&values, "FLOW_WEBHOOK_SECRET", environment)?;
        let signing_keys_api_key =
            optional_secret(&values, "SIGNING_KEYS_INTERNAL_API_KEY", environment)?;
        let issuance_api_key = optional_secret(&values, "ISSUANCE_INTERNAL_API_KEY", environment)?;

        Ok(Self {
            environment,
            http_addr,
            grpc_addr,
            database_url,
            database_max_connections,
            redis_url,
            redis_database,
            organization_grpc_target,
            credential_template_grpc_target,
            presentation_policy_grpc_target,
            issuance_grpc_target,
            signing_keys_url,
            signing_keys_api_key,
            issuance_url,
            issuance_api_key,
            service_token,
            webhook_secret,
            release_version: value(&values, "RELEASE_VERSION")
                .unwrap_or(env!("CARGO_PKG_VERSION"))
                .to_owned(),
            build_revision: value(&values, "BUILD_REVISION")
                .unwrap_or("unknown")
                .to_owned(),
        })
    }
}

fn parse_environment(value: &str) -> Result<Environment, FlowConfigError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "development" | "dev" | "local" => Ok(Environment::Development),
        "test" => Ok(Environment::Test),
        "beta" | "staging" => Ok(Environment::Beta),
        "production" | "prod" => Ok(Environment::Production),
        _ => Err(invalid("ENVIRONMENT")),
    }
}

fn value<'a>(values: &'a BTreeMap<String, String>, name: &str) -> Option<&'a str> {
    values
        .get(name)
        .map(String::as_str)
        .filter(|value| !value.trim().is_empty())
}

fn required(
    values: &BTreeMap<String, String>,
    name: &'static str,
) -> Result<String, FlowConfigError> {
    value(values, name)
        .map(str::to_owned)
        .ok_or(FlowConfigError::Missing { name })
}

fn parse_address(value: &str, name: &'static str) -> Result<SocketAddr, FlowConfigError> {
    value.parse().map_err(|_| invalid(name))
}

fn parse_bounded(
    value: &str,
    name: &'static str,
    minimum: u32,
    maximum: u32,
) -> Result<u32, FlowConfigError> {
    value
        .parse::<u32>()
        .ok()
        .filter(|value| (minimum..=maximum).contains(value))
        .ok_or_else(|| invalid(name))
}

fn validate_url(value: &str, name: &'static str, schemes: &[&str]) -> Result<(), FlowConfigError> {
    let url = Url::parse(value).map_err(|_| invalid(name))?;
    if !schemes.contains(&url.scheme()) || url.host_str().is_none() || url.fragment().is_some() {
        return Err(invalid(name));
    }
    Ok(())
}

fn grpc_target(
    values: &BTreeMap<String, String>,
    name: &'static str,
    default: Option<&str>,
    environment: Environment,
) -> Result<String, FlowConfigError> {
    let raw = value(values, name)
        .or_else(|| (!environment.is_deployed()).then_some(default).flatten())
        .ok_or(FlowConfigError::Missing { name })?;
    let target = if raw.contains("://") {
        raw.to_owned()
    } else {
        format!("http://{raw}")
    };
    validate_origin(&target, name)?;
    Ok(target)
}

fn service_url(
    values: &BTreeMap<String, String>,
    name: &'static str,
    default: Option<&str>,
    environment: Environment,
) -> Result<String, FlowConfigError> {
    let url = value(values, name)
        .or_else(|| (!environment.is_deployed()).then_some(default).flatten())
        .ok_or(FlowConfigError::Missing { name })?
        .to_owned();
    validate_origin(&url, name)?;
    Ok(url)
}

fn validate_origin(value: &str, name: &'static str) -> Result<(), FlowConfigError> {
    validate_url(value, name, &["http", "https"])?;
    let url = Url::parse(value).map_err(|_| invalid(name))?;
    if !url.username().is_empty()
        || url.password().is_some()
        || !matches!(url.path(), "" | "/")
        || url.query().is_some()
    {
        return Err(invalid(name));
    }
    Ok(())
}

fn optional_secret(
    values: &BTreeMap<String, String>,
    name: &'static str,
    environment: Environment,
) -> Result<Option<String>, FlowConfigError> {
    match value(values, name) {
        Some(secret) if secret.len() >= MINIMUM_SECRET_BYTES => Ok(Some(secret.to_owned())),
        Some(_) => Err(FlowConfigError::SecretTooShort {
            name,
            minimum: MINIMUM_SECRET_BYTES,
        }),
        None if environment.is_deployed() => Err(FlowConfigError::Missing { name }),
        None => Ok(None),
    }
}

const fn invalid(name: &'static str) -> FlowConfigError {
    FlowConfigError::Invalid { name }
}
