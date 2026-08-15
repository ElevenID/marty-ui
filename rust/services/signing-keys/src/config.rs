use std::{collections::HashMap, env, fs, net::SocketAddr};

const DEFAULT_HTTP_PORT: u16 = 8017;
const DEVELOPMENT_INTERNAL_API_KEY: &str = "dev-signing-keys-internal-api-key";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub http_addr: SocketAddr,
    pub release_version: String,
    pub build_revision: String,
    pub internal_api_key: String,
    pub registry_redis_url: String,
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
        let release_version =
            value(values, "MARTY_RELEASE_VERSION").unwrap_or_else(|| "development".into());
        let internal_api_key = secret_value(values, "SIGNING_KEYS_INTERNAL_API_KEY")?
            .unwrap_or_else(|| DEVELOPMENT_INTERNAL_API_KEY.to_string());
        if release_version != "development"
            && (internal_api_key == DEVELOPMENT_INTERNAL_API_KEY || internal_api_key.len() < 16)
        {
            return Err(
                "SIGNING_KEYS_INTERNAL_API_KEY must be configured with at least 16 characters"
                    .to_string(),
            );
        }
        Ok(Self {
            http_addr: SocketAddr::from(([0, 0, 0, 0], port)),
            release_version,
            build_revision: value(values, "MARTY_UI_SHA").unwrap_or_else(|| "unknown".into()),
            internal_api_key,
            registry_redis_url: value(values, "SIGNING_KEYS_REDIS_URL")
                .unwrap_or_else(|| "redis://localhost:6379/2".into()),
        })
    }
}

fn secret_value(values: &HashMap<String, String>, name: &str) -> Result<Option<String>, String> {
    if let Some(value) = value(values, name) {
        return Ok(Some(value));
    }
    let Some(path) = value(values, &format!("{name}_FILE")) else {
        return Ok(None);
    };
    let secret = fs::read_to_string(&path)
        .map_err(|error| format!("failed to read {name}_FILE '{path}': {error}"))?;
    let secret = secret.trim().to_string();
    if secret.is_empty() {
        return Err(format!("{name}_FILE '{path}' is empty"));
    }
    Ok(Some(secret))
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
        assert_eq!(config.internal_api_key, DEVELOPMENT_INTERNAL_API_KEY);
        assert_eq!(config.registry_redis_url, "redis://localhost:6379/2");
    }

    #[test]
    fn rejects_invalid_or_zero_ports() {
        for port in ["invalid", "0", "65536"] {
            let values = HashMap::from([("SIGNING_KEYS_SERVICE_PORT".into(), port.into())]);
            assert!(Config::from_values(&values).is_err());
        }
    }

    #[test]
    fn nondevelopment_releases_require_a_nondefault_internal_key() {
        let release_only = HashMap::from([("MARTY_RELEASE_VERSION".into(), "beta".into())]);
        assert!(Config::from_values(&release_only).is_err());

        let configured = HashMap::from([
            ("MARTY_RELEASE_VERSION".into(), "beta".into()),
            (
                "SIGNING_KEYS_INTERNAL_API_KEY".into(),
                "a-production-strength-secret".into(),
            ),
        ]);
        assert_eq!(
            Config::from_values(&configured).unwrap().internal_api_key,
            "a-production-strength-secret"
        );
    }
}
