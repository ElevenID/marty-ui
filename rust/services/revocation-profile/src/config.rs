use std::{collections::HashMap, env, fs, net::SocketAddr, path::Path};

const DEFAULT_HTTP_PORT: u16 = 8013;
const DEFAULT_GRPC_PORT: u16 = 9013;
const DEFAULT_DATABASE_CONNECTIONS: u32 = 10;
const DEFAULT_STATUS_LIST_BASE_URL: &str = "https://status.example.com";
const DEVELOPMENT_ENVIRONMENTS: [&str; 4] = ["development", "dev", "local", "test"];
const PLACEHOLDER_SECRET_PREFIXES: [&str; 5] = [
    "change-me",
    "change_me",
    "changeme",
    "replace-me",
    "replace_me",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub environment: String,
    pub http_addr: SocketAddr,
    pub grpc_addr: SocketAddr,
    pub grpc_enabled: bool,
    pub database_url: String,
    pub database_max_connections: u32,
    pub redis_url: String,
    pub organization_grpc_target: String,
    pub service_token: Option<String>,
    pub status_list_base_url: String,
    pub organization_id: String,
    pub release_version: String,
    pub build_revision: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationConfig {
    pub database_url: String,
    pub database_max_connections: u32,
    pub organization_id: String,
    pub status_list_base_url: String,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let values = env::vars().collect::<HashMap<_, _>>();
        Self::from_values(&values, |path| {
            fs::read_to_string(path).map_err(|error| error.to_string())
        })
    }

    fn from_values(
        values: &HashMap<String, String>,
        read_file: impl Fn(&Path) -> Result<String, String>,
    ) -> Result<Self, String> {
        let environment = value(values, "ENVIRONMENT")
            .unwrap_or_else(|| "development".into())
            .to_ascii_lowercase();
        let is_development = DEVELOPMENT_ENVIRONMENTS.contains(&environment.as_str());
        let database_url = required(values, "DATABASE_URL")?;
        let database_url = normalize_database_url(&database_url)?;
        let redis_url = required(values, "REDIS_URL")?;
        let organization_grpc_target = required(values, "ORG_GRPC_TARGET")?;
        let service_token = read_service_token(values, &read_file)?;

        if !is_development {
            validate_production_token(service_token.as_deref())?;
        }

        let status_list_base_url = value(values, "STATUS_LIST_BASE_URL")
            .or_else(|| value(values, "PUBLIC_API_URL"))
            .unwrap_or_else(|| DEFAULT_STATUS_LIST_BASE_URL.into())
            .trim_end_matches('/')
            .to_string();
        let organization_id =
            value(values, "MARTY_ORG_ID").unwrap_or_else(|| crate::DEFAULT_ORGANIZATION_ID.into());
        if !(status_list_base_url.starts_with("https://")
            || is_development && status_list_base_url.starts_with("http://"))
        {
            return Err(
                "STATUS_LIST_BASE_URL or PUBLIC_API_URL must use HTTPS outside development".into(),
            );
        }

        let http_port = parse(values, "REVOCATION_PROFILE_SERVICE_PORT", DEFAULT_HTTP_PORT)?;
        let grpc_port = parse(values, "RP_GRPC_PORT", DEFAULT_GRPC_PORT)?;
        let database_max_connections = parse(
            values,
            "RP_DATABASE_MAX_CONNECTIONS",
            DEFAULT_DATABASE_CONNECTIONS,
        )?;
        if http_port == 0 || grpc_port == 0 {
            return Err("service ports must be greater than zero".into());
        }
        if database_max_connections == 0 {
            return Err("RP_DATABASE_MAX_CONNECTIONS must be greater than zero".into());
        }

        Ok(Self {
            environment,
            http_addr: SocketAddr::from(([0, 0, 0, 0], http_port)),
            grpc_addr: SocketAddr::from(([0, 0, 0, 0], grpc_port)),
            grpc_enabled: parse_bool(values, "RP_GRPC_ENABLED", true)?,
            database_url,
            database_max_connections,
            redis_url,
            organization_grpc_target: normalize_grpc_target(&organization_grpc_target),
            service_token,
            status_list_base_url,
            organization_id,
            release_version: value(values, "MARTY_RELEASE_VERSION")
                .unwrap_or_else(|| "development".into()),
            build_revision: value(values, "MARTY_UI_SHA").unwrap_or_else(|| "unknown".into()),
        })
    }
}

impl MigrationConfig {
    pub fn from_env() -> Result<Self, String> {
        Self::from_values(&env::vars().collect())
    }

    fn from_values(values: &HashMap<String, String>) -> Result<Self, String> {
        let environment = value(values, "ENVIRONMENT")
            .unwrap_or_else(|| "development".into())
            .to_ascii_lowercase();
        let is_development = DEVELOPMENT_ENVIRONMENTS.contains(&environment.as_str());
        let database_url = normalize_database_url(&required(values, "DATABASE_URL")?)?;
        let database_max_connections = parse(
            values,
            "RP_DATABASE_MAX_CONNECTIONS",
            DEFAULT_DATABASE_CONNECTIONS,
        )?;
        if database_max_connections == 0 {
            return Err("RP_DATABASE_MAX_CONNECTIONS must be greater than zero".into());
        }
        let organization_id =
            value(values, "MARTY_ORG_ID").unwrap_or_else(|| crate::DEFAULT_ORGANIZATION_ID.into());
        let status_list_base_url = value(values, "STATUS_LIST_BASE_URL")
            .or_else(|| value(values, "PUBLIC_API_URL"))
            .unwrap_or_else(|| DEFAULT_STATUS_LIST_BASE_URL.into())
            .trim_end_matches('/')
            .to_string();
        if !(status_list_base_url.starts_with("https://")
            || is_development && status_list_base_url.starts_with("http://"))
        {
            return Err(
                "STATUS_LIST_BASE_URL or PUBLIC_API_URL must use HTTPS outside development".into(),
            );
        }
        Ok(Self {
            database_url,
            database_max_connections,
            organization_id,
            status_list_base_url,
        })
    }
}

pub fn migration_only_from_env() -> Result<bool, String> {
    parse_bool(&env::vars().collect(), "RP_MIGRATE_ONLY", false)
}

fn value(values: &HashMap<String, String>, name: &str) -> Option<String> {
    values
        .get(name)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn required(values: &HashMap<String, String>, name: &str) -> Result<String, String> {
    value(values, name).ok_or_else(|| format!("{name} is required"))
}

fn parse<T>(values: &HashMap<String, String>, name: &str, default: T) -> Result<T, String>
where
    T: std::str::FromStr,
{
    match value(values, name) {
        Some(value) => value
            .parse()
            .map_err(|_| format!("{name} has an invalid value")),
        None => Ok(default),
    }
}

fn parse_bool(values: &HashMap<String, String>, name: &str, default: bool) -> Result<bool, String> {
    match value(values, name) {
        Some(value) if value.eq_ignore_ascii_case("true") => Ok(true),
        Some(value) if value.eq_ignore_ascii_case("false") => Ok(false),
        Some(_) => Err(format!("{name} must be true or false")),
        None => Ok(default),
    }
}

fn read_service_token(
    values: &HashMap<String, String>,
    read_file: impl Fn(&Path) -> Result<String, String>,
) -> Result<Option<String>, String> {
    let direct = value(values, "GRPC_SERVICE_TOKEN");
    let file = value(values, "GRPC_SERVICE_TOKEN_FILE");
    if direct.is_some() && file.is_some() {
        return Err(
            "Both GRPC_SERVICE_TOKEN and GRPC_SERVICE_TOKEN_FILE are set; choose one".into(),
        );
    }
    let token = match (direct, file) {
        (Some(token), None) => Some(token),
        (None, Some(path)) => Some(
            read_file(Path::new(&path))
                .map_err(|error| format!("Unable to read GRPC_SERVICE_TOKEN_FILE: {error}"))?
                .trim()
                .to_string(),
        ),
        (None, None) => None,
        (Some(_), Some(_)) => unreachable!(),
    };
    match token {
        Some(token) if token.is_empty() => Err("GRPC service token must not be empty".into()),
        token => Ok(token),
    }
}

fn validate_production_token(token: Option<&str>) -> Result<(), String> {
    let token = token.ok_or_else(|| {
        "GRPC_SERVICE_TOKEN or GRPC_SERVICE_TOKEN_FILE is required outside development".to_string()
    })?;
    let lower = token.to_ascii_lowercase();
    if PLACEHOLDER_SECRET_PREFIXES
        .iter()
        .any(|prefix| lower.starts_with(prefix))
    {
        return Err("GRPC_SERVICE_TOKEN must not be a placeholder outside development".into());
    }
    if token.len() < 32 {
        return Err(
            "GRPC_SERVICE_TOKEN must contain at least 32 characters outside development".into(),
        );
    }
    Ok(())
}

fn normalize_database_url(url: &str) -> Result<String, String> {
    let normalized = url
        .replacen("postgresql+asyncpg://", "postgresql://", 1)
        .replacen("postgresql+psycopg2://", "postgresql://", 1);
    if normalized.starts_with("postgresql://") || normalized.starts_with("postgres://") {
        Ok(normalized)
    } else {
        Err("DATABASE_URL must use PostgreSQL".into())
    }
}

fn normalize_grpc_target(target: &str) -> String {
    if target.starts_with("http://") || target.starts_with("https://") {
        target.to_string()
    } else {
        format!("http://{target}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn required_values(environment: &str) -> HashMap<String, String> {
        HashMap::from([
            ("ENVIRONMENT".into(), environment.into()),
            (
                "DATABASE_URL".into(),
                "postgresql+asyncpg://marty:secret@postgres/marty".into(),
            ),
            ("REDIS_URL".into(), "redis://redis:6379/4".into()),
            ("ORG_GRPC_TARGET".into(), "organization:9002".into()),
        ])
    }

    #[test]
    fn development_defaults_match_the_existing_service_contract() {
        let config = Config::from_values(&required_values("development"), |_| unreachable!())
            .expect("configuration");
        assert_eq!(config.http_addr.port(), 8013);
        assert_eq!(config.grpc_addr.port(), 9013);
        assert!(config.grpc_enabled);
        assert_eq!(config.organization_grpc_target, "http://organization:9002");
        assert_eq!(
            config.database_url,
            "postgresql://marty:secret@postgres/marty"
        );
        assert_eq!(config.status_list_base_url, DEFAULT_STATUS_LIST_BASE_URL);
        assert_eq!(config.organization_id, crate::DEFAULT_ORGANIZATION_ID);
        assert_eq!(config.service_token, None);
    }

    #[test]
    fn production_requires_a_strong_non_placeholder_token() {
        let values = required_values("beta");
        assert!(Config::from_values(&values, |_| unreachable!()).is_err());

        let mut values = values;
        values.insert("GRPC_SERVICE_TOKEN".into(), "change-me-not-valid".into());
        assert!(Config::from_values(&values, |_| unreachable!()).is_err());

        values.insert("GRPC_SERVICE_TOKEN".into(), "a".repeat(32));
        assert!(Config::from_values(&values, |_| unreachable!()).is_ok());
    }

    #[test]
    fn token_file_and_direct_token_are_mutually_exclusive() {
        let mut values = required_values("development");
        values.insert("GRPC_SERVICE_TOKEN".into(), "direct".into());
        values.insert("GRPC_SERVICE_TOKEN_FILE".into(), "/secret/token".into());
        let error = Config::from_values(&values, |_| Ok("file".into())).unwrap_err();
        assert!(error.contains("choose one"));
    }

    #[test]
    fn non_postgres_and_non_https_configuration_fails_closed() {
        let mut values = required_values("development");
        values.insert("DATABASE_URL".into(), "sqlite:///tmp/marty.db".into());
        assert!(Config::from_values(&values, |_| unreachable!()).is_err());

        let mut values = required_values("development");
        values.insert("STATUS_LIST_BASE_URL".into(), "ftp://status.test".into());
        assert!(Config::from_values(&values, |_| unreachable!()).is_err());

        let mut values = required_values("development");
        values.insert("RP_DATABASE_MAX_CONNECTIONS".into(), "0".into());
        assert!(Config::from_values(&values, |_| unreachable!()).is_err());
    }

    #[test]
    fn public_api_url_is_the_development_status_origin_but_production_requires_https() {
        let mut values = required_values("development");
        values.insert("PUBLIC_API_URL".into(), "http://gateway:8000/".into());
        let config = Config::from_values(&values, |_| unreachable!()).unwrap();
        assert_eq!(config.status_list_base_url, "http://gateway:8000");

        values.insert("ENVIRONMENT".into(), "beta".into());
        values.insert("GRPC_SERVICE_TOKEN".into(), "a".repeat(32));
        assert!(Config::from_values(&values, |_| unreachable!()).is_err());

        values.insert("PUBLIC_API_URL".into(), "https://beta.example.test/".into());
        let config = Config::from_values(&values, |_| unreachable!()).unwrap();
        assert_eq!(config.status_list_base_url, "https://beta.example.test");
    }

    #[test]
    fn migration_config_needs_only_database_and_public_identity_inputs() {
        let values = HashMap::from([
            (
                "DATABASE_URL".into(),
                "postgresql+asyncpg://marty:secret@postgres/marty".into(),
            ),
            ("ENVIRONMENT".into(), "beta".into()),
            ("PUBLIC_API_URL".into(), "https://beta.example.test".into()),
        ]);
        let config = MigrationConfig::from_values(&values).unwrap();
        assert_eq!(
            config.database_url,
            "postgresql://marty:secret@postgres/marty"
        );
        assert_eq!(config.organization_id, crate::DEFAULT_ORGANIZATION_ID);
        assert_eq!(config.status_list_base_url, "https://beta.example.test");
    }
}
