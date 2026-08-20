use std::{collections::BTreeMap, fmt, fs, net::SocketAddr, path::PathBuf};

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

#[derive(Clone, Eq, PartialEq)]
pub struct FlowServiceConfig {
    pub environment: Environment,
    pub http_addr: SocketAddr,
    pub grpc_addr: SocketAddr,
    pub public_base_url: String,
    pub database_url: String,
    pub database_max_connections: u32,
    pub redis_url: String,
    pub redis_database: u8,
    pub organization_grpc_target: String,
    pub credential_template_grpc_target: String,
    pub presentation_policy_grpc_target: String,
    pub issuance_grpc_target: String,
    pub signing_keys_url: String,
    pub credential_template_url: String,
    pub trust_profile_url: String,
    pub deployment_profile_url: String,
    pub signing_keys_api_key: Option<String>,
    pub issuance_url: String,
    pub issuance_api_key: Option<String>,
    pub service_token: Option<String>,
    pub webhook_secret: Option<String>,
    pub allow_plaintext_grpc: bool,
    pub workload_client_tls: Option<WorkloadClientTlsFiles>,
    pub workload_server_tls: Option<WorkloadServerTlsFiles>,
    pub release_version: String,
    pub build_revision: String,
}

#[derive(Clone, Eq, PartialEq)]
pub struct WorkloadClientTlsFiles {
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    pub ca_certificate: PathBuf,
}

#[derive(Clone, Eq, PartialEq)]
pub struct WorkloadServerTlsFiles {
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    pub ca_certificate: PathBuf,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum FlowConfigError {
    #[error("FLOW.CONFIGURATION: {name} is required")]
    Missing { name: &'static str },
    #[error("FLOW.CONFIGURATION: {name} is invalid")]
    Invalid { name: &'static str },
    #[error("FLOW.CONFIGURATION: {name} must contain at least {minimum} bytes")]
    SecretTooShort { name: &'static str, minimum: usize },
    #[error("FLOW.CONFIGURATION: {name}_FILE could not be read")]
    SecretFile { name: &'static str },
}

impl fmt::Debug for FlowServiceConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FlowServiceConfig")
            .field("environment", &self.environment)
            .field("http_addr", &self.http_addr)
            .field("grpc_addr", &self.grpc_addr)
            .field("public_base_url", &self.public_base_url)
            .field("database_url", &"[REDACTED]")
            .field("database_max_connections", &self.database_max_connections)
            .field("redis_url", &"[REDACTED]")
            .field("redis_database", &self.redis_database)
            .field("organization_grpc_target", &self.organization_grpc_target)
            .field(
                "credential_template_grpc_target",
                &self.credential_template_grpc_target,
            )
            .field(
                "presentation_policy_grpc_target",
                &self.presentation_policy_grpc_target,
            )
            .field("issuance_grpc_target", &self.issuance_grpc_target)
            .field("signing_keys_url", &self.signing_keys_url)
            .field("credential_template_url", &self.credential_template_url)
            .field("trust_profile_url", &self.trust_profile_url)
            .field("deployment_profile_url", &self.deployment_profile_url)
            .field(
                "signing_keys_api_key",
                &redacted(&self.signing_keys_api_key),
            )
            .field("issuance_url", &self.issuance_url)
            .field("issuance_api_key", &redacted(&self.issuance_api_key))
            .field("service_token", &redacted(&self.service_token))
            .field("webhook_secret", &redacted(&self.webhook_secret))
            .field("allow_plaintext_grpc", &self.allow_plaintext_grpc)
            .field(
                "workload_client_tls",
                &self.workload_client_tls.as_ref().map(|_| "[CONFIGURED]"),
            )
            .field(
                "workload_server_tls",
                &self.workload_server_tls.as_ref().map(|_| "[CONFIGURED]"),
            )
            .field("release_version", &self.release_version)
            .field("build_revision", &self.build_revision)
            .finish()
    }
}

impl FlowServiceConfig {
    pub fn from_env() -> Result<Self, FlowConfigError> {
        let mut values = std::env::vars().collect::<BTreeMap<_, _>>();
        load_secret_files(
            &mut values,
            &[
                "GRPC_SERVICE_TOKEN",
                "FLOW_WEBHOOK_SECRET",
                "SIGNING_KEYS_INTERNAL_API_KEY",
                "ISSUANCE_API_KEY",
            ],
        )?;
        Self::from_values(values)
    }

    pub fn from_values(
        values: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, FlowConfigError> {
        let values = values.into_iter().collect::<BTreeMap<_, _>>();
        let environment = parse_environment(value(&values, "ENVIRONMENT").unwrap_or("production"))?;
        let http_addr = listener_address(
            &values,
            "FLOW_HTTP_ADDR",
            "FLOW_SERVICE_PORT",
            DEFAULT_HTTP_ADDR,
        )?;
        let grpc_addr = listener_address(
            &values,
            "FLOW_GRPC_ADDR",
            "FLOW_GRPC_PORT",
            DEFAULT_GRPC_ADDR,
        )?;
        if http_addr == grpc_addr {
            return Err(invalid("FLOW_GRPC_ADDR"));
        }
        let public_base_url = service_url(
            &values,
            "PUBLIC_BASE_URL",
            Some("http://localhost:8000"),
            environment,
        )?;
        if environment.is_deployed() && !public_base_url.starts_with("https://") {
            return Err(invalid("PUBLIC_BASE_URL"));
        }

        let database_url = required(&values, "DATABASE_URL")?.replacen(
            "postgresql+asyncpg://",
            "postgresql://",
            1,
        );
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

        let organization_grpc_target = grpc_target_alias(
            &values,
            "ORGANIZATION_GRPC_TARGET",
            "ORG_GRPC_TARGET",
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
        let credential_template_url = service_url(
            &values,
            "CREDENTIAL_TEMPLATE_SERVICE_URL",
            Some("http://credential-template:8003"),
            environment,
        )?;
        let trust_profile_url = service_url(
            &values,
            "TRUST_PROFILE_SERVICE_URL",
            Some("http://trust-profile:8004"),
            environment,
        )?;
        let deployment_profile_url = service_url(
            &values,
            "DEPLOYMENT_PROFILE_SERVICE_URL",
            Some("http://deployment-profile:8010"),
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
        let issuance_api_key = optional_secret(&values, "ISSUANCE_API_KEY", environment)?;
        let allow_plaintext_grpc = parse_boolean(
            value(&values, "GRPC_INSECURE_ALLOWED").unwrap_or("false"),
            "GRPC_INSECURE_ALLOWED",
        )?;
        let workload_client_tls = workload_client_tls(&values, environment)?;
        let workload_server_tls = workload_server_tls(&values, environment)?;
        if environment.is_deployed()
            && !allow_plaintext_grpc
            && [
                &organization_grpc_target,
                &credential_template_grpc_target,
                &issuance_grpc_target,
            ]
            .into_iter()
            .any(|target| target.starts_with("http://"))
        {
            return Err(invalid("GRPC_INSECURE_ALLOWED"));
        }

        Ok(Self {
            environment,
            http_addr,
            grpc_addr,
            public_base_url,
            database_url,
            database_max_connections,
            redis_url,
            redis_database,
            organization_grpc_target,
            credential_template_grpc_target,
            presentation_policy_grpc_target,
            issuance_grpc_target,
            signing_keys_url,
            credential_template_url,
            trust_profile_url,
            deployment_profile_url,
            signing_keys_api_key,
            issuance_url,
            issuance_api_key,
            service_token,
            webhook_secret,
            allow_plaintext_grpc,
            workload_client_tls,
            workload_server_tls,
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

fn listener_address(
    values: &BTreeMap<String, String>,
    address_name: &'static str,
    port_name: &'static str,
    default: &'static str,
) -> Result<SocketAddr, FlowConfigError> {
    if let Some(address) = value(values, address_name) {
        return parse_address(address, address_name);
    }
    if let Some(port) = value(values, port_name) {
        let port = parse_bounded(port, port_name, 1, u32::from(u16::MAX))?;
        return parse_address(&format!("0.0.0.0:{port}"), port_name);
    }
    parse_address(default, address_name)
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

fn parse_boolean(value: &str, name: &'static str) -> Result<bool, FlowConfigError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        _ => Err(invalid(name)),
    }
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

fn grpc_target_alias(
    values: &BTreeMap<String, String>,
    name: &'static str,
    alias: &'static str,
    default: Option<&str>,
    environment: Environment,
) -> Result<String, FlowConfigError> {
    let mut aliased = values.clone();
    if !aliased.contains_key(name) {
        if let Some(value) = value(values, alias) {
            aliased.insert(name.into(), value.into());
        }
    }
    grpc_target(&aliased, name, default, environment)
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

fn workload_client_tls(
    values: &BTreeMap<String, String>,
    environment: Environment,
) -> Result<Option<WorkloadClientTlsFiles>, FlowConfigError> {
    let paths = complete_path_group(
        values,
        &[
            "GRPC_WORKLOAD_TLS_CLIENT_CERT",
            "GRPC_WORKLOAD_TLS_CLIENT_KEY",
            "GRPC_WORKLOAD_TLS_CA_CERT",
        ],
        environment,
        "GRPC_WORKLOAD_TLS_CLIENT_CERT",
    )?;
    Ok(paths.map(|paths| WorkloadClientTlsFiles {
        certificate: paths[0].clone(),
        private_key: paths[1].clone(),
        ca_certificate: paths[2].clone(),
    }))
}

fn workload_server_tls(
    values: &BTreeMap<String, String>,
    environment: Environment,
) -> Result<Option<WorkloadServerTlsFiles>, FlowConfigError> {
    let paths = complete_path_group(
        values,
        &[
            "GRPC_WORKLOAD_TLS_SERVER_CERT",
            "GRPC_WORKLOAD_TLS_SERVER_KEY",
            "GRPC_WORKLOAD_TLS_CA_CERT",
        ],
        environment,
        "GRPC_WORKLOAD_TLS_SERVER_CERT",
    )?;
    Ok(paths.map(|paths| WorkloadServerTlsFiles {
        certificate: paths[0].clone(),
        private_key: paths[1].clone(),
        ca_certificate: paths[2].clone(),
    }))
}

fn complete_path_group<const N: usize>(
    values: &BTreeMap<String, String>,
    names: &[&'static str; N],
    environment: Environment,
    error_name: &'static str,
) -> Result<Option<[PathBuf; N]>, FlowConfigError> {
    let configured = names
        .iter()
        .filter(|name| value(values, name).is_some())
        .count();
    if configured == 0 && !environment.is_deployed() {
        return Ok(None);
    }
    if configured != N {
        return Err(if configured == 0 {
            FlowConfigError::Missing { name: error_name }
        } else {
            invalid(error_name)
        });
    }
    names
        .iter()
        .map(|name| {
            value(values, name)
                .map(PathBuf::from)
                .ok_or(FlowConfigError::Missing { name: error_name })
        })
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map(Some)
        .map_err(|_| invalid(error_name))
}

const fn invalid(name: &'static str) -> FlowConfigError {
    FlowConfigError::Invalid { name }
}

fn load_secret_files(
    values: &mut BTreeMap<String, String>,
    names: &[&'static str],
) -> Result<(), FlowConfigError> {
    for &name in names {
        if value(values, name).is_some() {
            continue;
        }
        let file_name = format!("{name}_FILE");
        let Some(path) = value(values, &file_name) else {
            continue;
        };
        let secret = fs::read_to_string(path).map_err(|_| FlowConfigError::SecretFile { name })?;
        let secret = secret.trim();
        if secret.is_empty() {
            return Err(FlowConfigError::SecretFile { name });
        }
        values.insert(name.into(), secret.into());
    }
    Ok(())
}

fn redacted(value: &Option<String>) -> &'static str {
    if value.is_some() {
        "[REDACTED]"
    } else {
        "[NONE]"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_files_are_trimmed_and_unreadable_files_fail_closed() {
        let path = std::env::temp_dir().join(format!("marty-flow-secret-{}", uuid::Uuid::new_v4()));
        fs::write(&path, format!("{}\n", "s".repeat(32))).expect("write secret");
        let mut values = BTreeMap::from([(
            "GRPC_SERVICE_TOKEN_FILE".into(),
            path.to_string_lossy().into_owned(),
        )]);
        load_secret_files(&mut values, &["GRPC_SERVICE_TOKEN"]).expect("load secret");
        assert_eq!(values["GRPC_SERVICE_TOKEN"], "s".repeat(32));
        fs::remove_file(&path).expect("remove secret");

        let mut missing = BTreeMap::from([(
            "FLOW_WEBHOOK_SECRET_FILE".into(),
            path.to_string_lossy().into_owned(),
        )]);
        assert_eq!(
            load_secret_files(&mut missing, &["FLOW_WEBHOOK_SECRET"]),
            Err(FlowConfigError::SecretFile {
                name: "FLOW_WEBHOOK_SECRET"
            })
        );
    }
}
