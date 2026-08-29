//! Fail-closed runtime configuration for the Rust gateway executable.

use std::{
    collections::BTreeMap,
    env, fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
};

use thiserror::Error;

use crate::discovery::ReleaseIdentity;

const DEFAULT_READY_SERVICES: &[&str] = &[
    "auth",
    "organizations",
    "credential-templates",
    "trust-profiles",
    "presentation-policies",
    "deployment-profiles",
    "signing-keys",
    "flows",
    "issuance",
];

const SERVICE_URLS: &[(&str, &str, &str)] = &[
    ("auth", "AUTH_SERVICE_URL", "http://localhost:8001"),
    (
        "organizations",
        "ORGANIZATION_SERVICE_URL",
        "http://localhost:8002",
    ),
    (
        "credential-templates",
        "CREDENTIAL_TEMPLATE_SERVICE_URL",
        "http://localhost:8003",
    ),
    (
        "trust-profiles",
        "TRUST_PROFILE_SERVICE_URL",
        "http://localhost:8004",
    ),
    ("issuance", "ISSUANCE_SERVICE_URL", "http://localhost:8005"),
    (
        "applicant",
        "APPLICANT_SERVICE_URL",
        "http://localhost:8006",
    ),
    (
        "notifications",
        "NOTIFICATION_SERVICE_URL",
        "http://localhost:8007",
    ),
    (
        "compliance-profiles",
        "COMPLIANCE_PROFILE_SERVICE_URL",
        "http://localhost:8008",
    ),
    (
        "presentation-policies",
        "PRESENTATION_POLICY_SERVICE_URL",
        "http://localhost:8009",
    ),
    (
        "deployment-profiles",
        "DEPLOYMENT_PROFILE_SERVICE_URL",
        "http://localhost:8010",
    ),
    ("flows", "FLOW_SERVICE_URL", "http://localhost:8011"),
    (
        "verification",
        "VERIFICATION_SERVICE_URL",
        "http://localhost:8012",
    ),
    (
        "revocation-profiles",
        "REVOCATION_PROFILE_SERVICE_URL",
        "http://localhost:8013",
    ),
    (
        "device-registration",
        "DEVICE_REGISTRATION_SERVICE_URL",
        "http://localhost:8014",
    ),
    (
        "signing-keys",
        "SIGNING_KEYS_SERVICE_URL",
        "http://localhost:8017",
    ),
];

#[derive(Debug, Error)]
#[error("invalid gateway configuration: {0}")]
pub struct GatewayConfigError(String);

#[derive(Clone, Debug)]
pub struct GatewayConfig {
    pub address: SocketAddr,
    pub production: bool,
    pub service_urls: BTreeMap<String, String>,
    pub auth_grpc_target: String,
    pub organization_grpc_target: String,
    pub event_stream_grpc_target: String,
    pub grpc_ca_certificate: Option<PathBuf>,
    pub grpc_insecure_allowed: bool,
    pub grpc_service_token: Option<String>,
    pub signing_internal_api_key: String,
    pub issuance_api_key: String,
    pub redis_url: Option<String>,
    pub cors_origins: Vec<String>,
    pub issuer_base_url: String,
    pub public_api_url: String,
    pub public_domain: String,
    pub default_organization_id: Option<String>,
    pub required_ready_services: Vec<String>,
    pub rate_limit_rpm: u64,
    pub maximum_response_bytes: usize,
    pub hosted_pilot_auto_purge_enabled: bool,
    pub hosted_pilot_auto_purge_interval_seconds: u64,
    pub hosted_pilot_auto_purge_batch_size: usize,
    pub release_identity: ReleaseIdentity,
}

impl GatewayConfig {
    pub fn from_env() -> Result<Self, GatewayConfigError> {
        Self::from_values(&env::vars().collect())
    }

    pub fn from_values(values: &BTreeMap<String, String>) -> Result<Self, GatewayConfigError> {
        let environment = value(values, "ENVIRONMENT").unwrap_or_else(|| "development".into());
        let production = !matches!(
            environment.to_ascii_lowercase().as_str(),
            "development" | "dev" | "local" | "test"
        );
        let port = parse(values, "GATEWAY_PORT", 8000_u16)?;
        let mut service_urls = SERVICE_URLS
            .iter()
            .map(|(service, variable, default)| {
                (
                    (*service).to_owned(),
                    value(values, variable).unwrap_or_else(|| (*default).to_owned()),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let issuance_native_url = value(values, "ISSUANCE_NATIVE_SERVICE_URL")
            .unwrap_or_else(|| service_urls["issuance"].clone());
        service_urls.insert("issuance-native".into(), issuance_native_url);
        validate_service_urls(&service_urls)?;

        let grpc_service_token = secret(values, "GRPC_SERVICE_TOKEN")?;
        if production {
            validate_production_secret("GRPC_SERVICE_TOKEN", grpc_service_token.as_deref(), 32)?;
        }
        let signing_internal_api_key = secret(values, "SIGNING_KEYS_INTERNAL_API_KEY")?
            .or_else(|| (!production).then(|| "dev-signing-keys-internal-api-key".into()))
            .ok_or_else(|| error("SIGNING_KEYS_INTERNAL_API_KEY is required"))?;
        if production {
            validate_production_secret(
                "SIGNING_KEYS_INTERNAL_API_KEY",
                Some(&signing_internal_api_key),
                16,
            )?;
        }
        let issuance_api_key = secret(values, "ISSUANCE_API_KEY")?
            .or_else(|| (!production).then(|| "dev-issuance-api-key".into()))
            .ok_or_else(|| error("ISSUANCE_API_KEY is required"))?;
        if production {
            validate_production_secret("ISSUANCE_API_KEY", Some(&issuance_api_key), 16)?;
        }

        let grpc_ca_certificate = value(values, "GRPC_TLS_CA_CERT").map(PathBuf::from);
        let grpc_insecure_allowed = boolean(values, "GRPC_INSECURE_ALLOWED", false)?;
        if production && grpc_ca_certificate.is_none() && !grpc_insecure_allowed {
            return Err(error(
                "GRPC_TLS_CA_CERT is required outside development unless GRPC_INSECURE_ALLOWED is explicit",
            ));
        }

        let cors_origins = csv(value(values, "CORS_ORIGINS")
            .as_deref()
            .unwrap_or("http://localhost:3000,https://beta.elevenidllc.com,http://localhost:5173"));
        if cors_origins.is_empty() || cors_origins.iter().any(|origin| origin == "*") {
            return Err(error("credentialed CORS requires explicit origins"));
        }

        let issuer_base_url = value(values, "ISSUER_BASE_URL")
            .unwrap_or_else(|| "http://localhost:8000".into())
            .trim_end_matches('/')
            .to_owned();
        let issuer_url = url::Url::parse(&issuer_base_url)
            .map_err(|_| error("ISSUER_BASE_URL must be a valid HTTP(S) origin"))?;
        if !matches!(issuer_url.scheme(), "http" | "https")
            || issuer_url.host_str().is_none()
            || !issuer_url.username().is_empty()
            || issuer_url.password().is_some()
            || issuer_url.query().is_some()
            || issuer_url.fragment().is_some()
        {
            return Err(error(
                "ISSUER_BASE_URL must be a credential-free HTTP(S) origin",
            ));
        }
        let public_domain = value(values, "PUBLIC_DOMAIN").unwrap_or_else(|| {
            let host = issuer_url.host_str().unwrap_or("localhost");
            issuer_url
                .port()
                .map_or_else(|| host.to_owned(), |port| format!("{host}:{port}"))
        });
        let public_api_url = value(values, "PUBLIC_API_URL")
            .or_else(|| value(values, "ISSUER_BASE_URL"))
            .or_else(|| value(values, "PUBLIC_BASE_URL"))
            .unwrap_or_else(|| issuer_base_url.clone())
            .trim_end_matches('/')
            .to_owned();
        let public_api = url::Url::parse(&public_api_url)
            .map_err(|_| error("PUBLIC_API_URL must be a valid HTTP(S) URL"))?;
        if !matches!(public_api.scheme(), "http" | "https")
            || public_api.host_str().is_none()
            || !public_api.username().is_empty()
            || public_api.password().is_some()
            || public_api.query().is_some()
            || public_api.fragment().is_some()
        {
            return Err(error(
                "PUBLIC_API_URL must be a credential-free HTTP(S) URL without query or fragment",
            ));
        }

        let redis_database = parse(values, "REDIS_DB_GATEWAY", 2_u8)?;
        let redis_url = value(values, "REDIS_URL")
            .map(|raw| redis_database_url(&raw, redis_database))
            .transpose()?;
        let required_ready_services = value(values, "GATEWAY_REQUIRED_READY_SERVICES").map_or_else(
            || {
                DEFAULT_READY_SERVICES
                    .iter()
                    .map(|value| (*value).into())
                    .collect()
            },
            |configured| csv(&configured),
        );
        if required_ready_services.is_empty() {
            return Err(error("GATEWAY_REQUIRED_READY_SERVICES must not be empty"));
        }
        let hosted_pilot_auto_purge_interval_seconds =
            parse(values, "HOSTED_PILOT_AUTO_PURGE_INTERVAL_SECONDS", 3600_u64)?;
        let hosted_pilot_auto_purge_batch_size =
            parse(values, "HOSTED_PILOT_AUTO_PURGE_BATCH_SIZE", 100_usize)?;
        if hosted_pilot_auto_purge_interval_seconds == 0 || hosted_pilot_auto_purge_batch_size == 0
        {
            return Err(error(
                "Hosted Pilot auto-purge interval and batch size must be positive",
            ));
        }

        Ok(Self {
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
            production,
            service_urls,
            auth_grpc_target: grpc_target(values, "AUTH_GRPC_TARGET", "localhost:9001")?,
            organization_grpc_target: grpc_target(values, "ORG_GRPC_TARGET", "organization:9002")?,
            event_stream_grpc_target: grpc_target(values, "ES_GRPC_TARGET", "event-stream:9015")?,
            grpc_ca_certificate,
            grpc_insecure_allowed,
            grpc_service_token,
            signing_internal_api_key,
            issuance_api_key,
            redis_url,
            cors_origins,
            issuer_base_url,
            public_api_url,
            public_domain,
            default_organization_id: value(values, "DEFAULT_ORG_ID"),
            required_ready_services,
            rate_limit_rpm: parse(values, "RATE_LIMIT_RPM", 120_u64)?,
            maximum_response_bytes: parse(
                values,
                "GATEWAY_MAXIMUM_RESPONSE_BYTES",
                10 * 1024 * 1024_usize,
            )?,
            hosted_pilot_auto_purge_enabled: boolean(
                values,
                "HOSTED_PILOT_AUTO_PURGE_ENABLED",
                true,
            )?,
            hosted_pilot_auto_purge_interval_seconds,
            hosted_pilot_auto_purge_batch_size,
            release_identity: ReleaseIdentity {
                release_version: value(values, "MARTY_RELEASE_VERSION")
                    .unwrap_or_else(|| "development".into()),
                stack_version: value(values, "ELEVENID_STACK_VERSION")
                    .unwrap_or_else(|| "development".into()),
                marty_ui_sha: value(values, "MARTY_UI_SHA").unwrap_or_else(|| "unknown".into()),
                component_revisions: component_revisions(values)?,
                image_digests: image_digests(values),
            },
        })
    }
}

fn value(values: &BTreeMap<String, String>, name: &str) -> Option<String> {
    values
        .get(name)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn secret(
    values: &BTreeMap<String, String>,
    name: &str,
) -> Result<Option<String>, GatewayConfigError> {
    let direct = value(values, name);
    let file = value(values, &format!("{name}_FILE"));
    if direct.is_some() && file.is_some() {
        return Err(error(format!("both {name} and {name}_FILE are configured")));
    }
    match (direct, file) {
        (Some(value), None) => Ok(Some(value)),
        (None, Some(path)) => fs::read_to_string(path)
            .map(|value| Some(value.trim().to_owned()))
            .map_err(|_| error(format!("unable to read {name}_FILE"))),
        (None, None) => Ok(None),
        (Some(_), Some(_)) => unreachable!("handled above"),
    }
}

fn validate_production_secret(
    name: &str,
    secret: Option<&str>,
    minimum_length: usize,
) -> Result<(), GatewayConfigError> {
    let secret = secret.ok_or_else(|| error(format!("{name} is required outside development")))?;
    let normalized = secret.to_ascii_lowercase();
    if secret.len() < minimum_length
        || [
            "change-me",
            "change_me",
            "changeme",
            "dev-",
            "replace-me",
            "replace_me",
        ]
        .iter()
        .any(|prefix| normalized.starts_with(prefix))
    {
        return Err(error(format!("{name} is not production-safe")));
    }
    Ok(())
}

fn validate_service_urls(urls: &BTreeMap<String, String>) -> Result<(), GatewayConfigError> {
    for raw in urls.values() {
        let parsed = url::Url::parse(raw).map_err(|_| error("service URL is invalid"))?;
        if !matches!(parsed.scheme(), "http" | "https")
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(error("service URLs must be credential-free HTTP(S) URLs"));
        }
    }
    Ok(())
}

fn redis_database_url(raw: &str, database: u8) -> Result<String, GatewayConfigError> {
    let mut parsed = url::Url::parse(raw).map_err(|_| error("REDIS_URL is invalid"))?;
    if parsed.scheme() != "redis" && parsed.scheme() != "rediss" {
        return Err(error("REDIS_URL must use redis or rediss"));
    }
    if matches!(parsed.path(), "" | "/") {
        parsed.set_path(&format!("/{database}"));
    }
    Ok(parsed.to_string())
}

fn grpc_target(
    values: &BTreeMap<String, String>,
    name: &str,
    default: &str,
) -> Result<String, GatewayConfigError> {
    let value = value(values, name).unwrap_or_else(|| default.into());
    let target = if value.contains("://") {
        value
    } else {
        format!("http://{value}")
    };
    let parsed = url::Url::parse(&target).map_err(|_| error(format!("{name} is invalid")))?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return Err(error(format!(
            "{name} must identify an HTTP(S) gRPC endpoint"
        )));
    }
    Ok(target)
}

fn csv(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect()
}

fn parse<T>(
    values: &BTreeMap<String, String>,
    name: &str,
    default: T,
) -> Result<T, GatewayConfigError>
where
    T: std::str::FromStr,
{
    value(values, name).map_or(Ok(default), |raw| {
        raw.parse().map_err(|_| error(format!("{name} is invalid")))
    })
}

fn boolean(
    values: &BTreeMap<String, String>,
    name: &str,
    default: bool,
) -> Result<bool, GatewayConfigError> {
    match value(values, name).as_deref() {
        None => Ok(default),
        Some("1" | "true" | "yes" | "on") => Ok(true),
        Some("0" | "false" | "no" | "off") => Ok(false),
        Some(_) => Err(error(format!("{name} must be a boolean"))),
    }
}

fn image_digests(values: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    value(values, "ELEVENID_IMAGE_DIGESTS_JSON")
        .and_then(|raw| serde_json::from_str::<BTreeMap<String, String>>(&raw).ok())
        .unwrap_or_default()
}

fn component_revisions(
    values: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, GatewayConfigError> {
    let Some(raw) = value(values, "ELEVENID_COMPONENT_REVISIONS_JSON") else {
        return Ok(BTreeMap::new());
    };
    let revisions = serde_json::from_str::<BTreeMap<String, String>>(&raw)
        .map_err(|_| error("ELEVENID_COMPONENT_REVISIONS_JSON must be a JSON string map"))?;
    if revisions.iter().any(|(component, revision)| {
        component.trim().is_empty()
            || revision.len() != 40
            || !revision
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }) {
        return Err(error(
            "ELEVENID_COMPONENT_REVISIONS_JSON must map component names to full lowercase Git revisions",
        ));
    }
    Ok(revisions)
}

fn error(message: impl Into<String>) -> GatewayConfigError {
    GatewayConfigError(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn development_defaults_preserve_legacy_local_runtime() {
        let config = GatewayConfig::from_values(&BTreeMap::new()).expect("development config");
        assert!(!config.production);
        assert_eq!(config.address.port(), 8000);
        assert_eq!(config.rate_limit_rpm, 120);
        assert_eq!(config.public_domain, "localhost:8000");
        assert_eq!(
            config.service_urls["issuance-native"],
            config.service_urls["issuance"]
        );
        assert!(config.redis_url.is_none());
        assert!(config.release_identity.component_revisions.is_empty());
    }

    #[test]
    fn native_issuance_upstream_can_be_enabled_without_replacing_legacy() {
        let values = BTreeMap::from([
            ("ISSUANCE_SERVICE_URL".into(), "http://issuance:8005".into()),
            (
                "ISSUANCE_NATIVE_SERVICE_URL".into(),
                "http://issuance-native:8005".into(),
            ),
        ]);
        let config = GatewayConfig::from_values(&values).expect("split upstream config");
        assert_eq!(config.service_urls["issuance"], "http://issuance:8005");
        assert_eq!(
            config.service_urls["issuance-native"],
            "http://issuance-native:8005"
        );
    }

    #[test]
    fn release_component_revisions_are_exact_and_fail_closed() {
        let mut values = BTreeMap::from([(
            "ELEVENID_COMPONENT_REVISIONS_JSON".into(),
            format!(r#"{{"marty-ui":"{}"}}"#, "a".repeat(40)),
        )]);
        let config = GatewayConfig::from_values(&values).expect("valid component revisions");
        assert_eq!(
            config.release_identity.component_revisions["marty-ui"],
            "a".repeat(40)
        );
        values.insert(
            "ELEVENID_COMPONENT_REVISIONS_JSON".into(),
            r#"{"marty-ui":"dirty"}"#.into(),
        );
        assert!(GatewayConfig::from_values(&values).is_err());
    }

    #[test]
    fn production_requires_distributed_authentication_and_tls() {
        let mut values = BTreeMap::from([("ENVIRONMENT".into(), "production".into())]);
        assert!(GatewayConfig::from_values(&values)
            .expect_err("missing secrets")
            .to_string()
            .contains("GRPC_SERVICE_TOKEN"));
        values.insert("GRPC_SERVICE_TOKEN".into(), "g".repeat(32));
        values.insert("SIGNING_KEYS_INTERNAL_API_KEY".into(), "s".repeat(32));
        values.insert("ISSUANCE_API_KEY".into(), "i".repeat(32));
        assert!(GatewayConfig::from_values(&values)
            .expect_err("missing TLS")
            .to_string()
            .contains("GRPC_TLS_CA_CERT"));
        values.insert("GRPC_INSECURE_ALLOWED".into(), "true".into());
        assert!(GatewayConfig::from_values(&values).is_ok());
    }

    #[test]
    fn configured_redis_database_is_scoped_to_gateway() {
        let values = BTreeMap::from([
            ("REDIS_URL".into(), "redis://redis:6379".into()),
            ("REDIS_DB_GATEWAY".into(), "7".into()),
        ]);
        assert_eq!(
            GatewayConfig::from_values(&values)
                .expect("config")
                .redis_url
                .as_deref(),
            Some("redis://redis:6379/7")
        );
    }

    #[test]
    fn direct_and_file_secret_conflict_fails_closed() {
        let values = BTreeMap::from([
            ("GRPC_SERVICE_TOKEN".into(), "direct".into()),
            ("GRPC_SERVICE_TOKEN_FILE".into(), "token.txt".into()),
        ]);
        assert!(GatewayConfig::from_values(&values).is_err());
    }
}
