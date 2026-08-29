use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
};

use mmf_config::{ConfigLayer, LayeredConfig};
use mmf_core::{ErrorCode, MmfError};
use serde::Deserialize;
use serde_json::{json, Map, Value};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuanceServiceConfig {
    pub http_addr: SocketAddr,
    pub release_version: String,
    pub build_revision: String,
    pub issuer_base_url: String,
    pub issuer_display_name: String,
    pub cors_allowed_origins: Vec<String>,
}

#[derive(Deserialize)]
struct Settings {
    server: ServerSettings,
    build: BuildSettings,
    discovery: DiscoverySettings,
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
        Ok(Self {
            http_addr,
            release_version: settings.build.release_version,
            build_revision: settings.build.revision,
            issuer_base_url,
            issuer_display_name: settings.discovery.issuer_display_name,
            cors_allowed_origins: settings.server.cors_allowed_origins,
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
    Ok(json!({"server": server, "build": build, "discovery": discovery}))
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
}
