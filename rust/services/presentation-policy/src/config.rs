use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::SocketAddr,
    path::PathBuf,
    time::Duration,
};

use thiserror::Error;
use url::Url;

const MINIMUM_SECRET_BYTES: usize = 32;

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
pub struct WorkloadServerTlsFiles {
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    pub ca_certificate: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PresentationPolicyServiceConfig {
    pub environment: RuntimeEnvironment,
    pub http_addr: SocketAddr,
    pub grpc_addr: SocketAddr,
    pub database_url: String,
    pub database_max_connections: u32,
    pub organization_grpc_target: String,
    pub trust_profile_url: String,
    pub credential_status_url_template: String,
    pub service_token: Option<String>,
    pub issuance_api_key: Option<String>,
    pub managed_issuers: Vec<String>,
    pub dependency_timeout: Duration,
    pub workload_server_tls: Option<WorkloadServerTlsFiles>,
    pub release_version: String,
    pub build_revision: String,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PresentationPolicyConfigError {
    #[error("PRESENTATION_POLICY.CONFIGURATION: {name} is required")]
    Missing { name: &'static str },
    #[error("PRESENTATION_POLICY.CONFIGURATION: {name} is invalid")]
    Invalid { name: &'static str },
    #[error("PRESENTATION_POLICY.CONFIGURATION: {name} must contain at least {minimum} bytes")]
    SecretTooShort { name: &'static str, minimum: usize },
    #[error("PRESENTATION_POLICY.CONFIGURATION: {name}_FILE could not be read")]
    SecretFile { name: &'static str },
}

impl PresentationPolicyServiceConfig {
    pub fn from_env() -> Result<Self, PresentationPolicyConfigError> {
        let mut values = std::env::vars().collect::<BTreeMap<_, _>>();
        for name in ["GRPC_SERVICE_TOKEN", "ISSUANCE_API_KEY"] {
            load_secret(&mut values, name)?;
        }
        Self::from_values(values)
    }

    pub fn from_values(
        values: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, PresentationPolicyConfigError> {
        let values = values.into_iter().collect::<BTreeMap<_, _>>();
        let environment = environment(value(&values, "ENVIRONMENT").unwrap_or("development"))?;
        let http_addr = listener(
            &values,
            "PRESENTATION_POLICY_HTTP_ADDR",
            "PRESENTATION_POLICY_SERVICE_PORT",
            8009,
        )?;
        let grpc_addr = listener(
            &values,
            "PRESENTATION_POLICY_GRPC_ADDR",
            "PP_GRPC_PORT",
            9009,
        )?;
        if http_addr == grpc_addr {
            return Err(invalid("PRESENTATION_POLICY_GRPC_ADDR"));
        }
        let database_url = required(&values, "DATABASE_URL")?.replacen(
            "postgresql+asyncpg://",
            "postgresql://",
            1,
        );
        validate_url(&database_url, "DATABASE_URL", &["postgres", "postgresql"])?;
        let database_max_connections = number(
            &values,
            "PRESENTATION_POLICY_DATABASE_MAX_CONNECTIONS",
            20_u32,
        )?;
        if database_max_connections == 0 || database_max_connections > 100 {
            return Err(invalid("PRESENTATION_POLICY_DATABASE_MAX_CONNECTIONS"));
        }
        let organization_grpc_target =
            grpc_target(value(&values, "ORG_GRPC_TARGET").unwrap_or("organization:9002"))?;
        let trust_profile_url = service_url(
            value(&values, "TRUST_PROFILE_SERVICE_URL").unwrap_or("http://trust-profile:8004"),
            "TRUST_PROFILE_SERVICE_URL",
        )?;
        let issuance_url = service_url(
            value(&values, "ISSUANCE_SERVICE_URL").unwrap_or("http://issuance:8005"),
            "ISSUANCE_SERVICE_URL",
        )?;
        let credential_status_url_template = value(&values, "MIP_CREDENTIAL_STATUS_URL_TEMPLATE")
            .map(str::to_owned)
            .unwrap_or_else(|| {
                format!("{issuance_url}/v1/issuance/credentials/{{credential_id}}/status")
            });
        validate_status_template(&credential_status_url_template)?;
        let service_token = secret(&values, "GRPC_SERVICE_TOKEN", environment)?;
        let issuance_api_key = if value(&values, "MIP_CREDENTIAL_STATUS_URL_TEMPLATE").is_some() {
            value(&values, "ISSUANCE_API_KEY").map(str::to_owned)
        } else {
            secret(&values, "ISSUANCE_API_KEY", environment)?
        };
        let managed_issuers = managed_issuers(&values);
        if environment.is_deployed() && managed_issuers.is_empty() {
            return Err(PresentationPolicyConfigError::Missing {
                name: "MIP_MANAGED_ISSUER_IDENTIFIERS",
            });
        }
        let workload_server_tls = workload_server_tls(&values, environment)?;
        Ok(Self {
            environment,
            http_addr,
            grpc_addr,
            database_url,
            database_max_connections,
            organization_grpc_target,
            trust_profile_url,
            credential_status_url_template,
            service_token,
            issuance_api_key,
            managed_issuers,
            dependency_timeout: Duration::from_secs(number(
                &values,
                "PRESENTATION_POLICY_DEPENDENCY_TIMEOUT_SECONDS",
                5_u64,
            )?),
            workload_server_tls,
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

fn environment(value: &str) -> Result<RuntimeEnvironment, PresentationPolicyConfigError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "development" | "dev" | "local" => Ok(RuntimeEnvironment::Development),
        "test" => Ok(RuntimeEnvironment::Test),
        "beta" => Ok(RuntimeEnvironment::Beta),
        "production" | "prod" => Ok(RuntimeEnvironment::Production),
        _ => Err(invalid("ENVIRONMENT")),
    }
}

fn managed_issuers(values: &BTreeMap<String, String>) -> Vec<String> {
    let mut issuers = [
        "MIP_MANAGED_ISSUER_IDENTIFIERS",
        "MIP_MANAGED_ISSUER_DIDS",
        "MARTY_ISSUER_DID",
        "CREDENTIAL_LOGIN_ISSUER_DID",
        "ISSUER_DID",
    ]
    .into_iter()
    .filter_map(|name| value(values, name))
    .flat_map(|value| value.split(','))
    .map(str::trim)
    .filter(|value| !value.is_empty())
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();

    let organization_slug = value(values, "MARTY_ORG_SLUG").unwrap_or("marty");
    if let Some(public_domain) = value(values, "PUBLIC_DOMAIN") {
        issuers.insert(format!("did:web:{public_domain}:orgs:{organization_slug}"));
    }
    for name in ["PUBLIC_BASE_URL", "ISSUER_BASE_URL", "PUBLIC_API_URL"] {
        let Some(base_url) = value(values, name) else {
            continue;
        };
        let Ok(parsed) = Url::parse(base_url) else {
            continue;
        };
        let Some(host) = parsed.host_str() else {
            continue;
        };
        if !matches!(
            host,
            "localhost" | "127.0.0.1" | "gateway" | "marty-gateway"
        ) {
            issuers.insert(format!("did:web:{host}:orgs:{organization_slug}"));
        }
    }

    issuers.into_iter().collect()
}

fn workload_server_tls(
    values: &BTreeMap<String, String>,
    environment: RuntimeEnvironment,
) -> Result<Option<WorkloadServerTlsFiles>, PresentationPolicyConfigError> {
    let names = [
        "GRPC_WORKLOAD_TLS_SERVER_CERT",
        "GRPC_WORKLOAD_TLS_SERVER_KEY",
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
            PresentationPolicyConfigError::Missing { name: names[0] }
        } else {
            invalid(names[0])
        });
    }
    Ok(Some(WorkloadServerTlsFiles {
        certificate: PathBuf::from(required(values, names[0])?),
        private_key: PathBuf::from(required(values, names[1])?),
        ca_certificate: PathBuf::from(required(values, names[2])?),
    }))
}

fn secret(
    values: &BTreeMap<String, String>,
    name: &'static str,
    environment: RuntimeEnvironment,
) -> Result<Option<String>, PresentationPolicyConfigError> {
    match value(values, name) {
        Some(value) if value.len() >= MINIMUM_SECRET_BYTES => Ok(Some(value.to_owned())),
        Some(_) => Err(PresentationPolicyConfigError::SecretTooShort {
            name,
            minimum: MINIMUM_SECRET_BYTES,
        }),
        None if environment.is_deployed() => Err(PresentationPolicyConfigError::Missing { name }),
        None => Ok(None),
    }
}

fn listener(
    values: &BTreeMap<String, String>,
    address_name: &'static str,
    port_name: &'static str,
    default_port: u16,
) -> Result<SocketAddr, PresentationPolicyConfigError> {
    if let Some(address) = value(values, address_name) {
        return address.parse().map_err(|_| invalid(address_name));
    }
    Ok(SocketAddr::from((
        [0, 0, 0, 0],
        number(values, port_name, default_port)?,
    )))
}

fn grpc_target(value: &str) -> Result<String, PresentationPolicyConfigError> {
    if value.chars().any(char::is_whitespace) {
        return Err(invalid("ORG_GRPC_TARGET"));
    }
    Ok(if value.contains("://") {
        value.into()
    } else {
        format!("http://{value}")
    })
}

fn service_url(value: &str, name: &'static str) -> Result<String, PresentationPolicyConfigError> {
    validate_url(value, name, &["http", "https"])?;
    Ok(value.trim_end_matches('/').to_owned())
}

fn validate_status_template(value: &str) -> Result<(), PresentationPolicyConfigError> {
    if !value.contains("{credential_id}") {
        return Err(invalid("MIP_CREDENTIAL_STATUS_URL_TEMPLATE"));
    }
    validate_url(
        &value.replace("{credential_id}", "test"),
        "MIP_CREDENTIAL_STATUS_URL_TEMPLATE",
        &["http", "https"],
    )
}

fn validate_url(
    value: &str,
    name: &'static str,
    schemes: &[&str],
) -> Result<(), PresentationPolicyConfigError> {
    let parsed = Url::parse(value).map_err(|_| invalid(name))?;
    if !schemes.contains(&parsed.scheme()) || parsed.host_str().is_none() {
        return Err(invalid(name));
    }
    Ok(())
}

fn number<T>(
    values: &BTreeMap<String, String>,
    name: &'static str,
    default: T,
) -> Result<T, PresentationPolicyConfigError>
where
    T: std::str::FromStr,
{
    value(values, name).map_or(Ok(default), |value| {
        value.parse().map_err(|_| invalid(name))
    })
}

fn required(
    values: &BTreeMap<String, String>,
    name: &'static str,
) -> Result<String, PresentationPolicyConfigError> {
    value(values, name)
        .map(str::to_owned)
        .ok_or(PresentationPolicyConfigError::Missing { name })
}

fn value<'a>(values: &'a BTreeMap<String, String>, name: &str) -> Option<&'a str> {
    values
        .get(name)
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn load_secret(
    values: &mut BTreeMap<String, String>,
    name: &'static str,
) -> Result<(), PresentationPolicyConfigError> {
    if value(values, name).is_some() {
        return Ok(());
    }
    let file_name = format!("{name}_FILE");
    let Some(path) = value(values, &file_name) else {
        return Ok(());
    };
    let secret =
        fs::read_to_string(path).map_err(|_| PresentationPolicyConfigError::SecretFile { name })?;
    values.insert(name.into(), secret.trim().into());
    Ok(())
}

fn invalid(name: &'static str) -> PresentationPolicyConfigError {
    PresentationPolicyConfigError::Invalid { name }
}
