use std::{collections::HashMap, env, net::SocketAddr};

const DEFAULT_HTTP_PORT: u16 = 8017;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub http_addr: SocketAddr,
    pub release_version: String,
    pub build_revision: String,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        Self::from_values(&env::vars().collect())
    }

    fn from_values(values: &HashMap<String, String>) -> Result<Self, String> {
        let port = match value(values, "SIGNING_KEYS_SERVICE_PORT") {
            Some(value) => value
                .parse::<u16>()
                .map_err(|_| "SIGNING_KEYS_SERVICE_PORT has an invalid value".to_string())?,
            None => DEFAULT_HTTP_PORT,
        };
        if port == 0 {
            return Err("SIGNING_KEYS_SERVICE_PORT must be greater than zero".into());
        }
        Ok(Self {
            http_addr: SocketAddr::from(([0, 0, 0, 0], port)),
            release_version: value(values, "MARTY_RELEASE_VERSION")
                .unwrap_or_else(|| "development".into()),
            build_revision: value(values, "MARTY_UI_SHA").unwrap_or_else(|| "unknown".into()),
        })
    }
}

fn value(values: &HashMap<String, String>, name: &str) -> Option<String> {
    values
        .get(name)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_the_existing_service_contract() {
        let config = Config::from_values(&HashMap::new()).unwrap();
        assert_eq!(config.http_addr, SocketAddr::from(([0, 0, 0, 0], 8017)));
        assert_eq!(config.release_version, "development");
        assert_eq!(config.build_revision, "unknown");
    }

    #[test]
    fn rejects_invalid_or_zero_ports() {
        for port in ["invalid", "0", "65536"] {
            let values = HashMap::from([("SIGNING_KEYS_SERVICE_PORT".into(), port.into())]);
            assert!(Config::from_values(&values).is_err());
        }
    }
}
