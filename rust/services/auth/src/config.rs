use std::{collections::HashMap, net::SocketAddr, path::PathBuf};

use thiserror::Error;
use tonic::metadata::AsciiMetadataValue;
use url::Url;

use mmf_messaging::OutboxDispatcherConfig;

use crate::{KeycloakAdminConfig, OidcConfig, SessionCookieConfig, UiOriginPolicy};

#[derive(Clone, Debug)]
pub struct AuthServiceConfig {
    pub environment: String,
    pub release_version: String,
    pub build_revision: String,
    pub http_addr: SocketAddr,
    pub grpc_addr: SocketAddr,
    pub database_url: String,
    pub database_max_connections: u32,
    pub redis_url: String,
    pub redis_database: u32,
    pub oidc: OidcConfig,
    pub ui_origins: UiOriginPolicy,
    pub session_ttl_seconds: i64,
    pub cookie: SessionCookieConfig,
    pub post_logout_redirect_uri: String,
    pub credential_login_policy_id: String,
    pub credential_login_organization_id: String,
    pub credential_login_issuer_did: String,
    pub credential_login_webhook_secret: String,
    pub auth_service_internal_url: String,
    pub applicant_service_url: String,
    pub issuance_service_url: String,
    pub canvas_lti_session_ttl_seconds: u64,
    pub impersonation_handoff_cookie_name: String,
    pub credential_login_require_existing_keycloak_user: bool,
    pub credential_login_create_users: bool,
    pub credential_callback_timestamp_skew_seconds: i64,
    pub credential_login_pending_ttl_seconds: u64,
    pub credential_login_completion_ttl_seconds: u64,
    pub credential_login_claim_lease_seconds: u64,
    pub keycloak_admin: Option<KeycloakAdminConfig>,
    pub outbound_http_timeout_seconds: u64,
    pub auth_rate_limit_rpm: u64,
    pub outbox: OutboxDispatcherConfig,
    pub flow_grpc_target: String,
    pub organization_grpc_target: String,
    pub event_stream_grpc_target: String,
    pub grpc_service_token: String,
    pub default_organization_id: String,
    pub default_organization_slug: String,
    pub default_organization_name: String,
    pub allow_plaintext_grpc: bool,
    pub workload_client_tls: Option<AuthWorkloadClientTlsFiles>,
    pub workload_server_tls: Option<AuthWorkloadServerTlsFiles>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthWorkloadClientTlsFiles {
    pub ca_certificate: PathBuf,
    pub certificate: PathBuf,
    pub private_key: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthWorkloadServerTlsFiles {
    pub ca_certificate: PathBuf,
    pub certificate: PathBuf,
    pub private_key: PathBuf,
}

#[derive(Debug, Error)]
pub enum AuthConfigError {
    #[error("AUTH.CONFIGURATION: {0}")]
    Invalid(String),
}

impl AuthServiceConfig {
    pub fn from_env() -> Result<Self, AuthConfigError> {
        Self::from_values(std::env::vars())
    }

    pub fn from_values(
        values: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, AuthConfigError> {
        let values = values.into_iter().collect::<HashMap<_, _>>();
        let get = |name: &str| values.get(name).map(String::as_str);
        let environment = get("ENVIRONMENT")
            .unwrap_or("production")
            .to_ascii_lowercase();
        let realm = required(get("KEYCLOAK_REALM"), "KEYCLOAK_REALM")?;
        let ui_base = get("UI_BASE_URL").unwrap_or("http://localhost:3000");
        let ui_additional = get("UI_ALLOWED_ORIGINS")
            .or_else(|| get("UI_ADDITIONAL_BASE_URLS"))
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>();
        let ui_origins = UiOriginPolicy::new(ui_base, ui_additional)
            .map_err(|error| invalid(error.to_string()))?;
        let issuer = get("OIDC_ISSUER_URL")
            .map(str::to_owned)
            .unwrap_or_else(|| format!("http://localhost:8180/realms/{realm}"));
        let redirect_uri = get("OIDC_REDIRECT_URI")
            .map(str::to_owned)
            .unwrap_or_else(|| format!("{}/v1/auth/callback", ui_base.trim_end_matches('/')));
        let allowed_algorithms = list(get("OIDC_ALLOWED_ALGORITHMS").unwrap_or("RS256"));
        let oidc = OidcConfig {
            issuer_url: issuer.clone(),
            external_issuer_url: get("OIDC_EXTERNAL_ISSUER_URL").unwrap_or(&issuer).into(),
            client_id: get("OIDC_CLIENT_ID").unwrap_or("marty-ui").into(),
            client_secret: get("OIDC_CLIENT_SECRET").map(str::to_owned),
            redirect_uri,
            scopes: list(get("OIDC_SCOPES").unwrap_or("openid,profile,email")),
            allowed_algorithms,
            leeway_seconds: number(get("OIDC_LEEWAY_SECONDS"), 60, "OIDC_LEEWAY_SECONDS")?,
            jwks_cache_seconds: number(
                get("OIDC_JWKS_CACHE_SECONDS"),
                300,
                "OIDC_JWKS_CACHE_SECONDS",
            )?,
        }
        .validate()
        .map_err(|error| invalid(error.to_string()))?;
        let session_ttl_seconds = number(
            get("SESSION_TTL_SECONDS"),
            86_400_i64,
            "SESSION_TTL_SECONDS",
        )?;
        if session_ttl_seconds <= 0 {
            return Err(invalid("SESSION_TTL_SECONDS must be positive"));
        }
        let allow_plaintext_grpc =
            boolean(get("ALLOW_PLAINTEXT_GRPC"), environment != "production")?;
        let (workload_client_tls, workload_server_tls) = workload_tls(&values, &environment)?;
        let flow_grpc_target = grpc_target(
            get("FLOW_GRPC_TARGET").unwrap_or("flow:9011"),
            allow_plaintext_grpc,
        )?;
        let organization_grpc_target = grpc_target(
            get("ORG_GRPC_TARGET").unwrap_or("organization:9002"),
            allow_plaintext_grpc,
        )?;
        let event_stream_grpc_target = grpc_target(
            get("ES_GRPC_TARGET").unwrap_or("event-stream:9015"),
            allow_plaintext_grpc,
        )?;
        let grpc_service_token = minimum_secret(get("GRPC_SERVICE_TOKEN"), "GRPC_SERVICE_TOKEN")?;
        AsciiMetadataValue::try_from(grpc_service_token.as_str())
            .map_err(|_| invalid("GRPC_SERVICE_TOKEN is not valid gRPC metadata"))?;
        let cookie_secure = boolean(get("COOKIE_SECURE"), true)?;
        let cookie = SessionCookieConfig {
            name: get("AUTH_SESSION_COOKIE_NAME")
                .unwrap_or("sessionId")
                .into(),
            secure: cookie_secure,
            same_site: get("COOKIE_SAMESITE").unwrap_or("lax").into(),
            maximum_age_seconds: u64::try_from(session_ttl_seconds)
                .map_err(|_| invalid("SESSION_TTL_SECONDS is out of range"))?,
            path: get("COOKIE_PATH").unwrap_or("/").into(),
        };
        cookie
            .validate()
            .map_err(|error| invalid(error.to_string()))?;
        let keycloak_admin = keycloak_admin(&values, &realm)?;
        let credential_login_organization_id = required(
            get("CREDENTIAL_LOGIN_ORGANIZATION_ID").or_else(|| get("MARTY_ORG_ID")),
            "CREDENTIAL_LOGIN_ORGANIZATION_ID",
        )?;
        let config = Self {
            environment,
            release_version: get("MARTY_RELEASE_VERSION").unwrap_or("development").into(),
            build_revision: get("MARTY_UI_SHA").unwrap_or("unknown").into(),
            http_addr: listener(get("AUTH_HTTP_ADDR"), get("AUTH_SERVICE_PORT"), 8_001)?,
            grpc_addr: listener(get("AUTH_GRPC_ADDR"), get("AUTH_GRPC_PORT"), 9_001)?,
            database_url: required(get("DATABASE_URL"), "DATABASE_URL")?,
            database_max_connections: number(
                get("AUTH_DATABASE_MAX_CONNECTIONS"),
                20,
                "AUTH_DATABASE_MAX_CONNECTIONS",
            )?,
            redis_url: required(get("REDIS_URL"), "REDIS_URL")?,
            redis_database: number(get("AUTH_REDIS_DATABASE"), 0, "AUTH_REDIS_DATABASE")?,
            oidc,
            ui_origins,
            session_ttl_seconds,
            cookie,
            post_logout_redirect_uri: get("OIDC_POST_LOGOUT_REDIRECT_URI")
                .unwrap_or(ui_base)
                .into(),
            credential_login_policy_id: required(
                get("CREDENTIAL_LOGIN_POLICY_ID"),
                "CREDENTIAL_LOGIN_POLICY_ID",
            )?,
            credential_login_organization_id: credential_login_organization_id.clone(),
            credential_login_issuer_did: required(
                get("CREDENTIAL_LOGIN_ISSUER_DID").or_else(|| get("OID4VP_ISSUER_DID")),
                "CREDENTIAL_LOGIN_ISSUER_DID",
            )?,
            credential_login_webhook_secret: minimum_secret(
                get("FLOW_WEBHOOK_SECRET"),
                "FLOW_WEBHOOK_SECRET",
            )?,
            auth_service_internal_url: origin(
                get("AUTH_SERVICE_INTERNAL_URL").unwrap_or("http://auth:8001"),
                "AUTH_SERVICE_INTERNAL_URL",
            )?,
            applicant_service_url: origin(
                get("APPLICANT_SERVICE_URL").unwrap_or("http://applicant:8006"),
                "APPLICANT_SERVICE_URL",
            )?,
            issuance_service_url: origin(
                get("ISSUANCE_SERVICE_URL").unwrap_or("http://issuance:8005"),
                "ISSUANCE_SERVICE_URL",
            )?,
            canvas_lti_session_ttl_seconds: number(
                get("CANVAS_LTI_SESSION_TTL_SECONDS"),
                u64::try_from(session_ttl_seconds)
                    .map_err(|_| invalid("SESSION_TTL_SECONDS is out of range"))?,
                "CANVAS_LTI_SESSION_TTL_SECONDS",
            )?,
            impersonation_handoff_cookie_name: get("IMPERSONATION_HANDOFF_COOKIE_NAME")
                .unwrap_or("marty_impersonation_handoff")
                .into(),
            credential_login_require_existing_keycloak_user: boolean(
                get("CREDENTIAL_LOGIN_REQUIRE_EXISTING_KEYCLOAK_USER"),
                false,
            )?,
            credential_login_create_users: boolean(get("CREDENTIAL_LOGIN_CREATE_USERS"), false)?,
            credential_callback_timestamp_skew_seconds: number(
                get("CREDENTIAL_CALLBACK_TIMESTAMP_SKEW_SECONDS"),
                300,
                "CREDENTIAL_CALLBACK_TIMESTAMP_SKEW_SECONDS",
            )?,
            credential_login_pending_ttl_seconds: number(
                get("CREDENTIAL_LOGIN_PENDING_TTL_SECONDS"),
                900,
                "CREDENTIAL_LOGIN_PENDING_TTL_SECONDS",
            )?,
            credential_login_completion_ttl_seconds: number(
                get("CREDENTIAL_LOGIN_COMPLETION_TTL_SECONDS"),
                300,
                "CREDENTIAL_LOGIN_COMPLETION_TTL_SECONDS",
            )?,
            credential_login_claim_lease_seconds: number(
                get("CREDENTIAL_LOGIN_CLAIM_LEASE_SECONDS"),
                30,
                "CREDENTIAL_LOGIN_CLAIM_LEASE_SECONDS",
            )?,
            keycloak_admin,
            outbound_http_timeout_seconds: number(
                get("AUTH_OUTBOUND_HTTP_TIMEOUT_SECONDS"),
                30,
                "AUTH_OUTBOUND_HTTP_TIMEOUT_SECONDS",
            )?,
            auth_rate_limit_rpm: number(get("AUTH_RATE_LIMIT_RPM"), 30, "AUTH_RATE_LIMIT_RPM")?,
            outbox: OutboxDispatcherConfig {
                batch_size: number(get("AUTH_OUTBOX_BATCH_SIZE"), 100, "AUTH_OUTBOX_BATCH_SIZE")?,
                lease_duration_ms: number(
                    get("AUTH_OUTBOX_LEASE_DURATION_MS"),
                    30_000,
                    "AUTH_OUTBOX_LEASE_DURATION_MS",
                )?,
                poll_interval_ms: number(
                    get("AUTH_OUTBOX_POLL_INTERVAL_MS"),
                    250,
                    "AUTH_OUTBOX_POLL_INTERVAL_MS",
                )?,
                retry_base_ms: number(
                    get("AUTH_OUTBOX_RETRY_BASE_MS"),
                    1_000,
                    "AUTH_OUTBOX_RETRY_BASE_MS",
                )?,
                retry_max_ms: number(
                    get("AUTH_OUTBOX_RETRY_MAX_MS"),
                    60_000,
                    "AUTH_OUTBOX_RETRY_MAX_MS",
                )?,
                partition: None,
            },
            flow_grpc_target,
            organization_grpc_target,
            event_stream_grpc_target,
            grpc_service_token,
            default_organization_id: get("MARTY_ORG_ID")
                .unwrap_or(&credential_login_organization_id)
                .into(),
            default_organization_slug: get("MARTY_ORG_SLUG").unwrap_or("marty").into(),
            default_organization_name: get("MARTY_ORG_NAME").unwrap_or("Marty").into(),
            allow_plaintext_grpc,
            workload_client_tls,
            workload_server_tls,
        };
        if config.http_addr == config.grpc_addr
            || config.database_max_connections == 0
            || config.canvas_lti_session_ttl_seconds == 0
            || config.impersonation_handoff_cookie_name.trim().is_empty()
            || config.credential_callback_timestamp_skew_seconds <= 0
            || config.credential_login_pending_ttl_seconds == 0
            || config.credential_login_completion_ttl_seconds == 0
            || config.credential_login_claim_lease_seconds == 0
            || config.outbound_http_timeout_seconds == 0
            || config.outbound_http_timeout_seconds > 300
            || config.auth_rate_limit_rpm == 0
            || config.outbox.validate().is_err()
            || (config.credential_login_create_users && config.keycloak_admin.is_none())
            || (config.credential_login_require_existing_keycloak_user
                && config.keycloak_admin.is_none())
        {
            return Err(invalid(
                "Auth runtime limits, listeners, and provider settings are invalid",
            ));
        }
        Ok(config)
    }
}

fn keycloak_admin(
    values: &HashMap<String, String>,
    realm: &str,
) -> Result<Option<KeycloakAdminConfig>, AuthConfigError> {
    let value = |name: &str| {
        values
            .get(name)
            .map(String::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
    };
    let admin_url = value("KEYCLOAK_ADMIN_URL");
    let client_id = value("MARTY_API_CLIENT_ID");
    let client_secret = value("MARTY_API_CLIENT_SECRET");
    let present = [admin_url, client_id, client_secret]
        .into_iter()
        .flatten()
        .count();
    if present == 0 {
        return Ok(None);
    }
    if present != 3 {
        return Err(invalid(
            "Keycloak admin integration requires KEYCLOAK_ADMIN_URL, MARTY_API_CLIENT_ID, and MARTY_API_CLIENT_SECRET",
        ));
    }
    KeycloakAdminConfig {
        admin_url: admin_url.expect("all Keycloak admin values checked").into(),
        realm: realm.into(),
        client_id: client_id.expect("all Keycloak admin values checked").into(),
        client_secret: client_secret
            .expect("all Keycloak admin values checked")
            .into(),
        timeout_seconds: number(
            value("KEYCLOAK_ADMIN_TIMEOUT_SECONDS"),
            8,
            "KEYCLOAK_ADMIN_TIMEOUT_SECONDS",
        )?,
        token_exchange_enabled: boolean(value("KEYCLOAK_TOKEN_EXCHANGE_ENABLED"), false)?,
    }
    .validate()
    .map(Some)
    .map_err(|error| invalid(error.to_string()))
}

fn required(value: Option<&str>, name: &str) -> Result<String, AuthConfigError> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| invalid(format!("{name} is required")))
}

fn minimum_secret(value: Option<&str>, name: &str) -> Result<String, AuthConfigError> {
    let value = required(value, name)?;
    if value.len() < 32 {
        Err(invalid(format!("{name} must contain at least 32 bytes")))
    } else {
        Ok(value)
    }
}

fn list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect()
}

fn number<T: std::str::FromStr + Copy>(
    value: Option<&str>,
    default: T,
    name: &str,
) -> Result<T, AuthConfigError> {
    value.map_or(Ok(default), |value| {
        value
            .parse()
            .map_err(|_| invalid(format!("{name} is invalid")))
    })
}

fn boolean(value: Option<&str>, default: bool) -> Result<bool, AuthConfigError> {
    match value.map(str::to_ascii_lowercase).as_deref() {
        None => Ok(default),
        Some("true" | "1" | "yes") => Ok(true),
        Some("false" | "0" | "no") => Ok(false),
        Some(_) => Err(invalid("boolean configuration is invalid")),
    }
}

fn listener(
    address: Option<&str>,
    port: Option<&str>,
    default_port: u16,
) -> Result<SocketAddr, AuthConfigError> {
    let value = address
        .map(str::to_owned)
        .unwrap_or_else(|| format!("0.0.0.0:{}", port.unwrap_or(&default_port.to_string())));
    value
        .parse()
        .map_err(|_| invalid(format!("listener address {value:?} is invalid")))
}

fn grpc_target(value: &str, allow_plaintext: bool) -> Result<String, AuthConfigError> {
    let value = if value.contains("://") {
        value.to_owned()
    } else {
        format!("http://{value}")
    };
    let parsed = Url::parse(&value).map_err(|_| invalid("gRPC target is invalid"))?;
    if parsed.scheme() == "http" && !allow_plaintext {
        return Err(invalid("plaintext gRPC is disabled"));
    }
    origin(&value, "gRPC target")
}

fn origin(value: &str, name: &str) -> Result<String, AuthConfigError> {
    let parsed = Url::parse(value).map_err(|_| invalid(format!("{name} is invalid")))?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || !matches!(parsed.path(), "" | "/")
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(invalid(format!(
            "{name} must be an uncredentialed HTTP(S) origin"
        )));
    }
    Ok(value.trim_end_matches('/').into())
}

fn workload_tls(
    values: &HashMap<String, String>,
    environment: &str,
) -> Result<
    (
        Option<AuthWorkloadClientTlsFiles>,
        Option<AuthWorkloadServerTlsFiles>,
    ),
    AuthConfigError,
> {
    let value = |name: &str| {
        values
            .get(name)
            .map(String::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
    };
    let client_names = [
        "GRPC_WORKLOAD_TLS_CA_CERT",
        "GRPC_WORKLOAD_TLS_CLIENT_CERT",
        "GRPC_WORKLOAD_TLS_CLIENT_KEY",
    ];
    let server_names = [
        "GRPC_WORKLOAD_TLS_SERVER_CERT",
        "GRPC_WORKLOAD_TLS_SERVER_KEY",
    ];
    let client_present = client_names
        .iter()
        .filter(|name| value(name).is_some())
        .count();
    let server_present = server_names
        .iter()
        .filter(|name| value(name).is_some())
        .count();
    if client_present != 0 && client_present != client_names.len() {
        return Err(invalid(
            "workload client TLS requires CA and client certificate/key",
        ));
    }
    if server_present != 0 && server_present != server_names.len() {
        return Err(invalid(
            "workload server TLS requires server certificate/key",
        ));
    }
    if environment == "production"
        && (client_present != client_names.len() || server_present != server_names.len())
    {
        return Err(invalid(
            "production workload TLS requires outbound client identity and inbound server identity",
        ));
    }
    let client = (client_present == client_names.len()).then(|| AuthWorkloadClientTlsFiles {
        ca_certificate: PathBuf::from(value(client_names[0]).expect("client TLS values checked")),
        certificate: PathBuf::from(value(client_names[1]).expect("client TLS values checked")),
        private_key: PathBuf::from(value(client_names[2]).expect("client TLS values checked")),
    });
    let server = (server_present == server_names.len()).then(|| AuthWorkloadServerTlsFiles {
        ca_certificate: PathBuf::from(
            value(client_names[0]).expect("server TLS requires the workload CA"),
        ),
        certificate: PathBuf::from(value(server_names[0]).expect("server TLS values checked")),
        private_key: PathBuf::from(value(server_names[1]).expect("server TLS values checked")),
    });
    Ok((client, server))
}

fn invalid(message: impl Into<String>) -> AuthConfigError {
    AuthConfigError::Invalid(message.into())
}
