use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use mmf_config::{ConfigLayer, LayeredConfig};
use mmf_core::{ErrorCode, MmfError};
use serde::Deserialize;
use serde_json::{json, Map, Value};

#[derive(Clone, Eq, PartialEq)]
pub struct IssuanceServiceConfig {
    pub http_addr: SocketAddr,
    pub release_version: String,
    pub build_revision: String,
    pub issuer_base_url: String,
    pub issuer_display_name: String,
    pub cors_allowed_origins: Vec<String>,
    pub database_url: String,
    pub signing_keys_internal_url: url::Url,
    pub signing_keys_internal_api_key: Option<String>,
    pub dependency_timeout: Duration,
}

impl std::fmt::Debug for IssuanceServiceConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IssuanceServiceConfig")
            .field("http_addr", &self.http_addr)
            .field("release_version", &self.release_version)
            .field("build_revision", &self.build_revision)
            .field("issuer_base_url", &self.issuer_base_url)
            .field("issuer_display_name", &self.issuer_display_name)
            .field("cors_allowed_origins", &self.cors_allowed_origins)
            .field("database_url_configured", &!self.database_url.is_empty())
            .field("signing_keys_internal_url", &self.signing_keys_internal_url)
            .field(
                "signing_keys_internal_api_key_configured",
                &self.signing_keys_internal_api_key.is_some(),
            )
            .field("dependency_timeout", &self.dependency_timeout)
            .finish()
    }
}

#[derive(Deserialize)]
struct Settings {
    server: ServerSettings,
    build: BuildSettings,
    discovery: DiscoverySettings,
    dependencies: DependencySettings,
}

#[derive(Deserialize)]
struct ServerSettings {
    host: IpAddr,
    port: u16,
    cors_allowed_origins: Vec<String>,
}

#[derive(Deserialize)]
struct BuildSettings {
    release_version: String,
    revision: String,
}

#[derive(Deserialize)]
struct DiscoverySettings {
    issuer_base_url: String,
    issuer_display_name: String,
}

#[derive(Deserialize)]
struct DependencySettings {
    database_url: String,
    signing_keys_internal_url: String,
}

impl IssuanceServiceConfig {
    pub fn from_env() -> Result<Self, MmfError> {
        Self::from_values(std::env::vars())
    }

    pub fn from_values(
        values: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, MmfError> {
        let values = values.into_iter().collect::<BTreeMap<_, _>>();
        let defaults = ConfigLayer {
            name: "defaults".to_owned(),
            value: json!({
                "server": {
                    "host": "0.0.0.0",
                    "port": 8005,
                    "cors_allowed_origins": ["http://localhost:3000"]
                },
                "build": {
                    "release_version": env!("CARGO_PKG_VERSION"),
                    "revision": "unknown"
                },
                "discovery": {
                    "issuer_base_url": "https://beta.elevenidllc.com",
                    "issuer_display_name": "ElevenID LLC"
                },
                "dependencies": {
                    "database_url": "postgresql://marty:marty_dev@postgres:5432/marty_credentials",
                    "signing_keys_internal_url": "http://gateway:8000/internal/signing-keys"
                }
            }),
        };
        let legacy = ConfigLayer {
            name: "legacy-environment-adapter".to_owned(),
            value: legacy_environment(&values)?,
        };
        let snapshot = LayeredConfig::new()
            .with_layer(defaults)
            .with_layer(legacy)
            .with_environment("MARTY_ISSUANCE__", values.iter())?
            .build(1);
        let settings: Settings = serde_json::from_value(snapshot.value).map_err(|error| {
            MmfError::new(ErrorCode::Configuration, "invalid issuance configuration")
                .with_detail("cause", error.to_string())
        })?;
        let http_addr = SocketAddr::new(settings.server.host, settings.server.port);
        let issuer_base_url = validate_issuer_base_url(&settings.discovery.issuer_base_url)?;
        let database_url = validate_database_url(&settings.dependencies.database_url)?;
        let signing_keys_internal_url =
            validate_internal_url(&settings.dependencies.signing_keys_internal_url)?;
        let signing_keys_internal_api_key = secret_value(&values, "SIGNING_KEYS_INTERNAL_API_KEY")?
            .or(secret_value(&values, "ISSUANCE_API_KEY")?);
        Ok(Self {
            http_addr,
            release_version: settings.build.release_version,
            build_revision: settings.build.revision,
            issuer_base_url,
            issuer_display_name: settings.discovery.issuer_display_name,
            cors_allowed_origins: settings.server.cors_allowed_origins,
            database_url,
            signing_keys_internal_url,
            signing_keys_internal_api_key,
            dependency_timeout: Duration::from_secs(10),
        })
    }
}

fn legacy_environment(values: &BTreeMap<String, String>) -> Result<Value, MmfError> {
    let mut server = Map::new();
    if let Some(port) = values.get("ISSUANCE_SERVICE_PORT") {
        let parsed = port.parse::<u16>().map_err(|error| {
            MmfError::new(
                ErrorCode::Configuration,
                "ISSUANCE_SERVICE_PORT must be a valid TCP port",
            )
            .with_detail("cause", error.to_string())
        })?;
        server.insert("port".to_owned(), json!(parsed));
    }
    if let Some(origins) = values.get("CORS_ALLOWED_ORIGINS") {
        server.insert(
            "cors_allowed_origins".to_owned(),
            json!(origins
                .split(',')
                .map(str::trim)
                .filter(|origin| !origin.is_empty())
                .collect::<Vec<_>>()),
        );
    }
    let mut build = Map::new();
    if let Some(version) = values.get("MARTY_RELEASE_VERSION") {
        build.insert("release_version".to_owned(), json!(version));
    }
    if let Some(revision) = values.get("MARTY_UI_SHA") {
        build.insert("revision".to_owned(), json!(revision));
    }
    let mut discovery = Map::new();
    if let Some(issuer_base_url) = values.get("ISSUER_BASE_URL") {
        discovery.insert("issuer_base_url".to_owned(), json!(issuer_base_url));
    }
    if let Some(issuer_display_name) = values.get("ISSUER_DISPLAY_NAME") {
        discovery.insert("issuer_display_name".to_owned(), json!(issuer_display_name));
    }
    let mut dependencies = Map::new();
    if let Some(database_url) = values.get("DATABASE_URL") {
        dependencies.insert("database_url".to_owned(), json!(database_url));
    }
    if let Some(signing_keys_internal_url) = values.get("SIGNING_KEYS_INTERNAL_URL") {
        dependencies.insert(
            "signing_keys_internal_url".to_owned(),
            json!(signing_keys_internal_url),
        );
    }
    Ok(json!({
        "server": server,
        "build": build,
        "discovery": discovery,
        "dependencies": dependencies
    }))
}

fn validate_issuer_base_url(value: &str) -> Result<String, MmfError> {
    let normalized = value.trim_end_matches('/');
    let parsed = url::Url::parse(normalized).map_err(|error| {
        MmfError::new(
            ErrorCode::Configuration,
            "ISSUER_BASE_URL must be a valid HTTP(S) URL",
        )
        .with_detail("cause", error.to_string())
    })?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(MmfError::new(
            ErrorCode::Configuration,
            "ISSUER_BASE_URL must be a credential-free HTTP(S) URL without query or fragment",
        ));
    }
    Ok(normalized.to_owned())
}

fn validate_database_url(value: &str) -> Result<String, MmfError> {
    let normalized = value.replacen("postgresql+asyncpg://", "postgresql://", 1);
    let parsed = url::Url::parse(&normalized).map_err(|error| {
        MmfError::new(
            ErrorCode::Configuration,
            "DATABASE_URL must be a valid PostgreSQL URL",
        )
        .with_detail("cause", error.to_string())
    })?;
    if !matches!(parsed.scheme(), "postgres" | "postgresql") || parsed.host_str().is_none() {
        return Err(MmfError::new(
            ErrorCode::Configuration,
            "DATABASE_URL must be a valid PostgreSQL URL",
        ));
    }
    Ok(normalized)
}

fn validate_internal_url(value: &str) -> Result<url::Url, MmfError> {
    let mut parsed = url::Url::parse(value).map_err(|error| {
        MmfError::new(
            ErrorCode::Configuration,
            "SIGNING_KEYS_INTERNAL_URL must be a valid HTTP(S) URL",
        )
        .with_detail("cause", error.to_string())
    })?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(MmfError::new(
            ErrorCode::Configuration,
            "SIGNING_KEYS_INTERNAL_URL must be a credential-free HTTP(S) URL without query or fragment",
        ));
    }
    if !parsed.path().ends_with('/') {
        parsed.set_path(&format!("{}/", parsed.path()));
    }
    Ok(parsed)
}

fn secret_value(values: &BTreeMap<String, String>, name: &str) -> Result<Option<String>, MmfError> {
    if let Some(value) = values.get(name).filter(|value| !value.is_empty()) {
        return Ok(Some(value.clone()));
    }
    let file_name = format!("{name}_FILE");
    let Some(path) = values.get(&file_name).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let value = std::fs::read_to_string(path).map_err(|error| {
        MmfError::new(
            ErrorCode::Configuration,
            format!("unable to read {file_name}"),
        )
        .with_detail("cause", error.to_string())
    })?;
    let value = value.trim();
    if value.is_empty() {
        return Err(MmfError::new(
            ErrorCode::Configuration,
            format!("{file_name} is empty"),
        ));
    }
    Ok(Some(value.to_owned()))
}

#[cfg(test)]
mod tests {
    use mmf_core::ErrorCode;

    use super::IssuanceServiceConfig;

    fn values(entries: &[(&str, &str)]) -> Vec<(String, String)> {
        entries
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn defaults_preserve_the_legacy_listener() {
        let config = IssuanceServiceConfig::from_values(std::iter::empty::<(String, String)>())
            .expect("defaults");
        assert_eq!(config.http_addr.to_string(), "0.0.0.0:8005");
        assert_eq!(config.release_version, "0.1.0");
        assert_eq!(config.build_revision, "unknown");
        assert_eq!(config.issuer_base_url, "https://beta.elevenidllc.com");
        assert_eq!(config.issuer_display_name, "ElevenID LLC");
        assert_eq!(config.cors_allowed_origins, ["http://localhost:3000"]);
        assert_eq!(
            config.database_url,
            "postgresql://marty:marty_dev@postgres:5432/marty_credentials"
        );
        assert_eq!(
            config.signing_keys_internal_url.as_str(),
            "http://gateway:8000/internal/signing-keys/"
        );
        assert!(config.signing_keys_internal_api_key.is_none());
    }

    #[test]
    fn hierarchical_configuration_overrides_the_legacy_adapter() {
        let config = IssuanceServiceConfig::from_values(values(&[
            ("ISSUANCE_SERVICE_PORT", "8006"),
            ("MARTY_RELEASE_VERSION", "1.2.3"),
            ("MARTY_UI_SHA", "abc123"),
            ("MARTY_ISSUANCE__SERVER__HOST", "127.0.0.1"),
            ("MARTY_ISSUANCE__SERVER__PORT", "8010"),
            ("ISSUER_BASE_URL", "https://legacy.example/"),
            ("ISSUER_DISPLAY_NAME", "Legacy Issuer"),
            (
                "CORS_ALLOWED_ORIGINS",
                " https://wallet.example, https://admin.example ,,",
            ),
            (
                "MARTY_ISSUANCE__DISCOVERY__ISSUER_BASE_URL",
                "https://issuer.example/",
            ),
            (
                "MARTY_ISSUANCE__DISCOVERY__ISSUER_DISPLAY_NAME",
                "Example Issuer",
            ),
            (
                "DATABASE_URL",
                "postgresql+asyncpg://user:pass@postgres.example/marty",
            ),
            (
                "SIGNING_KEYS_INTERNAL_URL",
                "https://gateway.example/internal/signing-keys",
            ),
            ("ISSUANCE_API_KEY", "fallback-key"),
            ("SIGNING_KEYS_INTERNAL_API_KEY", "preferred-key"),
        ]))
        .expect("configuration");
        assert_eq!(config.http_addr.to_string(), "127.0.0.1:8010");
        assert_eq!(config.release_version, "1.2.3");
        assert_eq!(config.build_revision, "abc123");
        assert_eq!(config.issuer_base_url, "https://issuer.example");
        assert_eq!(config.issuer_display_name, "Example Issuer");
        assert_eq!(
            config.cors_allowed_origins,
            ["https://wallet.example", "https://admin.example"]
        );
        assert_eq!(
            config.database_url,
            "postgresql://user:pass@postgres.example/marty"
        );
        assert_eq!(
            config.signing_keys_internal_url.as_str(),
            "https://gateway.example/internal/signing-keys/"
        );
        assert_eq!(
            config.signing_keys_internal_api_key.as_deref(),
            Some("preferred-key")
        );
        let diagnostic = format!("{config:?}");
        assert!(!diagnostic.contains("preferred-key"));
        assert!(!diagnostic.contains("user:pass"));
    }

    #[test]
    fn invalid_legacy_port_fails_closed() {
        let error =
            IssuanceServiceConfig::from_values(values(&[("ISSUANCE_SERVICE_PORT", "not-a-port")]))
                .expect_err("invalid port");
        assert_eq!(error.code, ErrorCode::Configuration);
    }

    #[test]
    fn invalid_hierarchical_bind_address_fails_closed() {
        let error = IssuanceServiceConfig::from_values(values(&[
            ("MARTY_ISSUANCE__SERVER__HOST", "issuance.example.test"),
            ("MARTY_ISSUANCE__SERVER__PORT", "8005"),
        ]))
        .expect_err("invalid bind address");
        assert_eq!(error.code, ErrorCode::Configuration);
    }

    #[test]
    fn credentialed_or_non_http_issuer_urls_fail_closed() {
        for issuer_base_url in [
            "ftp://issuer.example",
            "https://user:password@issuer.example",
            "https://issuer.example?tenant=a",
            "not-a-url",
        ] {
            let error =
                IssuanceServiceConfig::from_values(values(&[("ISSUER_BASE_URL", issuer_base_url)]))
                    .expect_err("invalid issuer URL");
            assert_eq!(error.code, ErrorCode::Configuration);
        }
    }

    #[test]
    fn invalid_dependency_urls_fail_closed() {
        for (name, value) in [
            ("DATABASE_URL", "sqlite:///tmp/issuance.db"),
            (
                "SIGNING_KEYS_INTERNAL_URL",
                "https://user:secret@gateway.example/internal/signing-keys",
            ),
            (
                "SIGNING_KEYS_INTERNAL_URL",
                "https://gateway.example/internal/signing-keys?tenant=a",
            ),
        ] {
            let error = IssuanceServiceConfig::from_values(values(&[(name, value)]))
                .expect_err("invalid dependency URL");
            assert_eq!(error.code, ErrorCode::Configuration);
        }
    }
}
