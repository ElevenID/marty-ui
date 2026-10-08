use std::{collections::HashMap, env, fs, net::SocketAddr, path::PathBuf};

const DEFAULT_HTTP_PORT: u16 = 8017;
const DEVELOPMENT_INTERNAL_API_KEY: &str = "dev-signing-keys-internal-api-key";

#[derive(Clone, PartialEq, Eq)]
pub struct Config {
    pub http_addr: SocketAddr,
    pub release_version: String,
    pub build_revision: String,
    pub internal_api_key: String,
    pub dsc_issue_gateway_key: Option<String>,
    pub csca_issue_gateway_key: Option<String>,
    pub beta_csca_issuance_enabled: bool,
    pub registry_redis_url: String,
    pub bao_addr: Option<String>,
    pub bao_token: Option<String>,
    pub haip_kms_token_file: Option<PathBuf>,
    pub public_domain: Option<String>,
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
        let dsc_issue_gateway_key = secret_value(values, "SIGNING_KEYS_DSC_ISSUE_GATEWAY_KEY")?;
        if dsc_issue_gateway_key
            .as_ref()
            .is_some_and(|key| key.len() < 32 || key == &internal_api_key)
        {
            return Err(
                "SIGNING_KEYS_DSC_ISSUE_GATEWAY_KEY must be distinct and at least 32 characters"
                    .into(),
            );
        }
        let beta_csca_issuance_enabled =
            match value(values, "SIGNING_KEYS_BETA_CSCA_ISSUANCE_ENABLED").as_deref() {
                None | Some("false") => false,
                Some("true") => true,
                Some(_) => {
                    return Err(
                        "SIGNING_KEYS_BETA_CSCA_ISSUANCE_ENABLED must be true or false".into(),
                    )
                }
            };
        if value(values, "SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY").is_some()
            && value(values, "SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY_FILE").is_some()
        {
            return Err("CSCA certificate ceremony key must use one secret source".into());
        }
        let csca_issue_gateway_key = secret_value(values, "SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY")?;
        if (beta_csca_issuance_enabled || csca_issue_gateway_key.is_some())
            && value(values, "ENVIRONMENT").as_deref() != Some("beta")
        {
            return Err("CSCA certificate ceremony is available only in ENVIRONMENT=beta".into());
        }
        if beta_csca_issuance_enabled != csca_issue_gateway_key.is_some() {
            return Err("beta CSCA certificate ceremony requires its dedicated Gateway key".into());
        }
        if csca_issue_gateway_key.as_ref().is_some_and(|key| {
            key.len() < 32
                || key == &internal_api_key
                || dsc_issue_gateway_key.as_ref() == Some(key)
        }) {
            return Err(
                "SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY must be distinct and at least 32 characters"
                    .into(),
            );
        }
        let bao_addr = value(values, "BAO_ADDR");
        let bao_token =
            secret_value(values, "BAO_TOKEN")?.or(secret_value(values, "OPENBAO_SERVICE_TOKEN")?);
        let haip_kms_token_file = value(values, "HAIP_KMS_TOKEN_FILE").map(PathBuf::from);
        if let Some(dsc_key) = dsc_issue_gateway_key.as_deref() {
            let reused_in_environment = values.iter().any(|(name, value)| {
                name != "SIGNING_KEYS_DSC_ISSUE_GATEWAY_KEY"
                    && name != "SIGNING_KEYS_DSC_ISSUE_GATEWAY_KEY_FILE"
                    && value.contains(dsc_key)
            });
            if reused_in_environment || bao_token.as_deref() == Some(dsc_key) {
                return Err(
                    "SIGNING_KEYS_DSC_ISSUE_GATEWAY_KEY must not be reused by another configuration value"
                        .into(),
                );
            }
        }
        if let Some(csca_key) = csca_issue_gateway_key.as_deref() {
            if values.iter().any(|(name, value)| {
                name != "SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY"
                    && name != "SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY_FILE"
                    && value.contains(csca_key)
            }) || bao_token.as_deref() == Some(csca_key)
            {
                return Err("SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY must not be reused by another configuration value".into());
            }
        }
        if bao_addr.is_some() != bao_token.is_some() {
            return Err(
                "BAO_ADDR and BAO_TOKEN (or OPENBAO_SERVICE_TOKEN) must be configured together"
                    .into(),
            );
        }
        if haip_kms_token_file.is_some() && bao_addr.is_none() {
            return Err("HAIP_KMS_TOKEN_FILE requires BAO_ADDR".into());
        }
        Ok(Self {
            http_addr: SocketAddr::from(([0, 0, 0, 0], port)),
            release_version,
            build_revision: value(values, "MARTY_UI_SHA").unwrap_or_else(|| "unknown".into()),
            internal_api_key,
            dsc_issue_gateway_key,
            csca_issue_gateway_key,
            beta_csca_issuance_enabled,
            registry_redis_url: value(values, "SIGNING_KEYS_REDIS_URL")
                .unwrap_or_else(|| "redis://localhost:6379/2".into()),
            bao_addr,
            bao_token,
            haip_kms_token_file,
            public_domain: value(values, "PUBLIC_DOMAIN"),
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
        assert_eq!(config.dsc_issue_gateway_key, None);
        assert_eq!(config.csca_issue_gateway_key, None);
        assert!(!config.beta_csca_issuance_enabled);
        assert_eq!(config.registry_redis_url, "redis://localhost:6379/2");
        assert_eq!(config.bao_addr, None);
        assert_eq!(config.bao_token, None);
        assert_eq!(config.public_domain, None);
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

    #[test]
    fn openbao_envelope_provider_requires_address_and_secret_together() {
        for values in [
            HashMap::from([("BAO_ADDR".into(), "http://bao:8200".into())]),
            HashMap::from([("BAO_TOKEN".into(), "secret".into())]),
        ] {
            assert!(Config::from_values(&values).is_err());
        }
        let values = HashMap::from([
            ("BAO_ADDR".into(), "http://bao:8200".into()),
            ("OPENBAO_SERVICE_TOKEN".into(), "secret".into()),
        ]);
        let config = Config::from_values(&values).expect("OpenBao config");
        assert_eq!(config.bao_addr.as_deref(), Some("http://bao:8200"));
        assert_eq!(config.bao_token.as_deref(), Some("secret"));
    }

    #[test]
    fn dsc_gateway_key_is_optional_but_must_be_distinct_and_strong_when_enabled() {
        let mut values = HashMap::new();
        values.insert(
            "SIGNING_KEYS_INTERNAL_API_KEY".into(),
            "shared-internal-key-32-characters-long".into(),
        );
        values.insert(
            "SIGNING_KEYS_DSC_ISSUE_GATEWAY_KEY".into(),
            "shared-internal-key-32-characters-long".into(),
        );
        assert!(Config::from_values(&values).is_err());
        values.insert("SIGNING_KEYS_DSC_ISSUE_GATEWAY_KEY".into(), "short".into());
        assert!(Config::from_values(&values).is_err());
        values.insert(
            "SIGNING_KEYS_DSC_ISSUE_GATEWAY_KEY".into(),
            "separate-dsc-operator-key-32-characters".into(),
        );
        values.insert("BAO_ADDR".into(), "http://bao:8200".into());
        values.insert(
            "BAO_TOKEN".into(),
            "separate-dsc-operator-key-32-characters".into(),
        );
        assert!(Config::from_values(&values).is_err());
        values.insert("BAO_TOKEN".into(), "independent-bao-token".into());
        values.insert(
            "OTHER_SERVICE_URL".into(),
            "redis://user:separate-dsc-operator-key-32-characters@redis:6379/2".into(),
        );
        assert!(Config::from_values(&values).is_err());
        values.remove("OTHER_SERVICE_URL");
        assert!(Config::from_values(&values).is_ok());
    }

    #[test]
    fn csca_ceremony_is_beta_only_and_has_a_distinct_operator_key() {
        let mut values = HashMap::from([
            ("ENVIRONMENT".into(), "beta".into()),
            (
                "SIGNING_KEYS_BETA_CSCA_ISSUANCE_ENABLED".into(),
                "true".into(),
            ),
            (
                "SIGNING_KEYS_INTERNAL_API_KEY".into(),
                "internal-signing-key-32-characters-long".into(),
            ),
        ]);
        assert!(Config::from_values(&values).is_err());
        values.insert(
            "SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY".into(),
            "internal-signing-key-32-characters-long".into(),
        );
        assert!(Config::from_values(&values).is_err());
        values.insert(
            "SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY".into(),
            "distinct-csca-operator-key-32-characters".into(),
        );
        assert!(
            Config::from_values(&values)
                .unwrap()
                .beta_csca_issuance_enabled
        );
        values.insert(
            "SIGNING_KEYS_DSC_ISSUE_GATEWAY_KEY".into(),
            "distinct-csca-operator-key-32-characters".into(),
        );
        assert!(Config::from_values(&values).is_err());
        values.remove("SIGNING_KEYS_DSC_ISSUE_GATEWAY_KEY");
        values.insert(
            "OTHER_URL".into(),
            "redis://user:distinct-csca-operator-key-32-characters@redis".into(),
        );
        assert!(Config::from_values(&values).is_err());
        values.remove("OTHER_URL");
        values.insert("ENVIRONMENT".into(), "production".into());
        assert!(Config::from_values(&values).is_err());
        values.insert("ENVIRONMENT".into(), "beta".into());
        values.insert(
            "SIGNING_KEYS_BETA_CSCA_ISSUANCE_ENABLED".into(),
            "false".into(),
        );
        assert!(Config::from_values(&values).is_err());
        values.remove("SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY");
        values.insert(
            "SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY_FILE".into(),
            "C:/not-a-key".into(),
        );
        assert!(Config::from_values(&values).is_err());
    }

    #[test]
    fn csca_ceremony_accepts_only_one_private_file_secret_source() {
        let path =
            std::env::temp_dir().join(format!("marty-signing-csca-{}", uuid::Uuid::new_v4()));
        std::fs::write(&path, "file-backed-csca-operator-key-32-characters\n").unwrap();
        let mut values = HashMap::from([
            ("ENVIRONMENT".into(), "beta".into()),
            (
                "SIGNING_KEYS_BETA_CSCA_ISSUANCE_ENABLED".into(),
                "true".into(),
            ),
            (
                "SIGNING_KEYS_INTERNAL_API_KEY".into(),
                "independent-internal-key-32-characters".into(),
            ),
            (
                "SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY_FILE".into(),
                path.to_string_lossy().into_owned(),
            ),
        ]);
        let config = Config::from_values(&values).expect("file-backed CSCA ceremony key");
        assert_eq!(
            config.csca_issue_gateway_key.as_deref(),
            Some("file-backed-csca-operator-key-32-characters")
        );
        values.insert(
            "SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY".into(),
            "another-operator-key-32-characters".into(),
        );
        assert!(Config::from_values(&values).is_err());
        values.remove("SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY");
        values.insert("ENVIRONMENT".into(), "production".into());
        assert!(Config::from_values(&values).is_err());
        std::fs::remove_file(path).unwrap();
    }
}
