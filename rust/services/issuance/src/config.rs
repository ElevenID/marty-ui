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
}

#[derive(Deserialize)]
struct Settings {
    server: ServerSettings,
    build: BuildSettings,
}

#[derive(Deserialize)]
struct ServerSettings {
    host: IpAddr,
    port: u16,
}

#[derive(Deserialize)]
struct BuildSettings {
    release_version: String,
    revision: String,
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
                "server": {"host": "0.0.0.0", "port": 8005},
                "build": {
                    "release_version": env!("CARGO_PKG_VERSION"),
                    "revision": "unknown"
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
        Ok(Self {
            http_addr,
            release_version: settings.build.release_version,
            build_revision: settings.build.revision,
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
    let mut build = Map::new();
    if let Some(version) = values.get("MARTY_RELEASE_VERSION") {
        build.insert("release_version".to_owned(), json!(version));
    }
    if let Some(revision) = values.get("MARTY_UI_SHA") {
        build.insert("revision".to_owned(), json!(revision));
    }
    Ok(json!({"server": server, "build": build}))
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
    }

    #[test]
    fn hierarchical_configuration_overrides_the_legacy_adapter() {
        let config = IssuanceServiceConfig::from_values(values(&[
            ("ISSUANCE_SERVICE_PORT", "8006"),
            ("MARTY_RELEASE_VERSION", "1.2.3"),
            ("MARTY_UI_SHA", "abc123"),
            ("MARTY_ISSUANCE__SERVER__HOST", "127.0.0.1"),
            ("MARTY_ISSUANCE__SERVER__PORT", "8010"),
        ]))
        .expect("configuration");
        assert_eq!(config.http_addr.to_string(), "127.0.0.1:8010");
        assert_eq!(config.release_version, "1.2.3");
        assert_eq!(config.build_revision, "abc123");
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
}
