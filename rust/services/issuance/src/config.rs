use std::{
    collections::{BTreeMap, BTreeSet},
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
    pub integration_secret_master_key: Option<String>,
    pub token_hmac_key: Option<String>,
    pub issuance_api_key: Option<String>,
    pub signing_keys_internal_url: url::Url,
    pub signing_keys_internal_api_key: Option<String>,
    pub revocation_profile_service_url: url::Url,
    pub internal_service_token: Option<String>,
    pub organization_grpc_target: String,
    pub credential_template_grpc_target: String,
    pub revocation_profile_grpc_target: String,
    pub credential_template_service_url: String,
    pub vcdm_related_resource_urls: Vec<String>,
    pub vcdm_related_resource_max_bytes: usize,
    pub vcdm_related_resource_timeout: Duration,
    pub didcomm_universal_resolver_url: Option<String>,
    pub didcomm_did_web_internal_base_url: Option<String>,
    pub didcomm_encryption_policy_file: Option<String>,
    pub didcomm_tls_ca_file: Option<String>,
    pub didcomm_allow_private_ips: bool,
    pub canvas_portable_enabled: bool,
    pub canvas_pilot_organizations: BTreeSet<String>,
    pub canvas_evidence_max_age: Duration,
    pub canvas_readiness_max_age: Duration,
    pub canvas_lti_state_ttl: Duration,
    pub canvas_lti_jwks_ttl: Duration,
    pub canvas_lti_experience_base_url: String,
    pub canvas_lti_experience_code_ttl: Duration,
    pub canvas_lti_experience_session_ttl: Duration,
    pub canvas_lti_tool_signing_organization_id: String,
    pub canvas_lti_tool_issuer_did: String,
    pub canvas_lti_deep_linking_issuer: Option<String>,
    pub canvas_oauth_completion_redirect_url: String,
    pub canvas_self_managed_origins: Vec<String>,
    pub canvas_private_origin_allowlist: Vec<String>,
    pub canvas_allow_private_base_urls: bool,
    pub canvas_allow_http_localhost_base_urls: bool,
    pub dependency_timeout: Duration,
    pub token_rate_limit: usize,
    pub token_rate_window: Duration,
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
            .field(
                "integration_secret_master_key_configured",
                &self.integration_secret_master_key.is_some(),
            )
            .field("token_hmac_key_configured", &self.token_hmac_key.is_some())
            .field(
                "issuance_api_key_configured",
                &self.issuance_api_key.is_some(),
            )
            .field("signing_keys_internal_url", &self.signing_keys_internal_url)
            .field(
                "signing_keys_internal_api_key_configured",
                &self.signing_keys_internal_api_key.is_some(),
            )
            .field(
                "revocation_profile_service_url",
                &self.revocation_profile_service_url,
            )
            .field(
                "internal_service_token_configured",
                &self.internal_service_token.is_some(),
            )
            .field("organization_grpc_target", &self.organization_grpc_target)
            .field(
                "credential_template_grpc_target",
                &self.credential_template_grpc_target,
            )
            .field(
                "revocation_profile_grpc_target",
                &self.revocation_profile_grpc_target,
            )
            .field(
                "credential_template_service_url",
                &self.credential_template_service_url,
            )
            .field(
                "vcdm_related_resource_url_count",
                &self.vcdm_related_resource_urls.len(),
            )
            .field(
                "vcdm_related_resource_max_bytes",
                &self.vcdm_related_resource_max_bytes,
            )
            .field(
                "vcdm_related_resource_timeout",
                &self.vcdm_related_resource_timeout,
            )
            .field(
                "didcomm_universal_resolver_configured",
                &self.didcomm_universal_resolver_url.is_some(),
            )
            .field(
                "didcomm_did_web_internal_base_configured",
                &self.didcomm_did_web_internal_base_url.is_some(),
            )
            .field(
                "didcomm_encryption_policy_configured",
                &self.didcomm_encryption_policy_file.is_some(),
            )
            .field(
                "didcomm_tls_ca_configured",
                &self.didcomm_tls_ca_file.is_some(),
            )
            .field("didcomm_allow_private_ips", &self.didcomm_allow_private_ips)
            .field("canvas_portable_enabled", &self.canvas_portable_enabled)
            .field(
                "canvas_pilot_organizations",
                &self.canvas_pilot_organizations,
            )
            .field("canvas_lti_state_ttl", &self.canvas_lti_state_ttl)
            .field("canvas_lti_jwks_ttl", &self.canvas_lti_jwks_ttl)
            .field(
                "canvas_lti_experience_base_url",
                &self.canvas_lti_experience_base_url,
            )
            .field(
                "canvas_lti_experience_code_ttl",
                &self.canvas_lti_experience_code_ttl,
            )
            .field(
                "canvas_lti_experience_session_ttl",
                &self.canvas_lti_experience_session_ttl,
            )
            .field(
                "canvas_lti_tool_signing_organization_id",
                &self.canvas_lti_tool_signing_organization_id,
            )
            .field(
                "canvas_lti_tool_issuer_did",
                &self.canvas_lti_tool_issuer_did,
            )
            .field(
                "canvas_lti_deep_linking_issuer",
                &self.canvas_lti_deep_linking_issuer,
            )
            .field(
                "canvas_oauth_completion_redirect_url",
                &self.canvas_oauth_completion_redirect_url,
            )
            .field(
                "canvas_self_managed_origin_count",
                &self.canvas_self_managed_origins.len(),
            )
            .field(
                "canvas_private_origin_allowlist_count",
                &self.canvas_private_origin_allowlist.len(),
            )
            .field(
                "canvas_allow_private_base_urls",
                &self.canvas_allow_private_base_urls,
            )
            .field(
                "canvas_allow_http_localhost_base_urls",
                &self.canvas_allow_http_localhost_base_urls,
            )
            .field("dependency_timeout", &self.dependency_timeout)
            .field("token_rate_limit", &self.token_rate_limit)
            .field("token_rate_window", &self.token_rate_window)
            .finish()
    }
}

#[derive(Deserialize)]
struct Settings {
    server: ServerSettings,
    build: BuildSettings,
    discovery: DiscoverySettings,
    dependencies: DependencySettings,
    initiation: InitiationSettings,
    didcomm: DidcommSettings,
    rate_limit: RateLimitSettings,
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
    revocation_profile_service_url: String,
}

#[derive(Deserialize)]
struct InitiationSettings {
    organization_grpc_target: String,
    credential_template_grpc_target: String,
    revocation_profile_grpc_target: String,
    credential_template_service_url: String,
    related_resource_urls: Vec<String>,
    related_resource_max_bytes: usize,
    related_resource_timeout_seconds: f64,
}

#[derive(Deserialize)]
struct DidcommSettings {
    universal_resolver_url: Option<String>,
    did_web_internal_base_url: Option<String>,
    encryption_policy_file: Option<String>,
    tls_ca_file: Option<String>,
    allow_private_ips: bool,
}

#[derive(Deserialize)]
struct RateLimitSettings {
    requests: usize,
    window_seconds: u64,
}

impl IssuanceServiceConfig {
    pub fn from_env() -> Result<Self, MmfError> {
        let config = Self::from_values(std::env::vars())?;
        if config.token_hmac_key.is_none() {
            return Err(MmfError::new(
                ErrorCode::Configuration,
                "TOKEN_HMAC_KEY or TOKEN_HMAC_KEY_FILE is required",
            ));
        }
        if config.integration_secret_master_key.is_none() {
            return Err(MmfError::new(
                ErrorCode::Configuration,
                "INTEGRATION_SECRET_MASTER_KEY or INTEGRATION_SECRET_MASTER_KEY_FILE is required",
            ));
        }
        Ok(config)
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
                    "signing_keys_internal_url": "http://gateway:8000/internal/signing-keys",
                    "revocation_profile_service_url": "http://revocation-profile:8013"
                },
                "initiation": {
                    "organization_grpc_target": "organization:9002",
                    "credential_template_grpc_target": "credential-template:9003",
                    "revocation_profile_grpc_target": "revocation-profile:9013",
                    "credential_template_service_url": "http://credential-template:8003",
                    "related_resource_urls": [],
                    "related_resource_max_bytes": 2000000,
                    "related_resource_timeout_seconds": 10.0
                },
                "didcomm": {
                    "universal_resolver_url": null,
                    "did_web_internal_base_url": null,
                    "encryption_policy_file": null,
                    "tls_ca_file": null,
                    "allow_private_ips": false
                },
                "rate_limit": {
                    "requests": 30,
                    "window_seconds": 60
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
        let revocation_profile_service_url =
            validate_internal_url(&settings.dependencies.revocation_profile_service_url)?;
        let organization_grpc_target = validate_grpc_target(
            &settings.initiation.organization_grpc_target,
            "ORG_GRPC_TARGET",
        )?;
        let credential_template_grpc_target = validate_grpc_target(
            &settings.initiation.credential_template_grpc_target,
            "CT_GRPC_TARGET",
        )?;
        let revocation_profile_grpc_target = validate_grpc_target(
            &settings.initiation.revocation_profile_grpc_target,
            "RP_GRPC_TARGET",
        )?;
        let credential_template_service_url = validate_http_base_url(
            &settings.initiation.credential_template_service_url,
            "CREDENTIAL_TEMPLATE_SERVICE_URL",
        )?;
        if settings.initiation.related_resource_max_bytes == 0 {
            return Err(MmfError::new(
                ErrorCode::Configuration,
                "VCDM_RELATED_RESOURCE_MAX_BYTES must be a positive integer",
            ));
        }
        let related_resource_timeout_seconds = settings.initiation.related_resource_timeout_seconds;
        if !related_resource_timeout_seconds.is_finite() || related_resource_timeout_seconds <= 0.0
        {
            return Err(MmfError::new(
                ErrorCode::Configuration,
                "VCDM_RELATED_RESOURCE_TIMEOUT_SECONDS must be a positive number",
            ));
        }
        let vcdm_related_resource_timeout =
            Duration::try_from_secs_f64(related_resource_timeout_seconds).map_err(|error| {
                MmfError::new(
                    ErrorCode::Configuration,
                    "VCDM_RELATED_RESOURCE_TIMEOUT_SECONDS must be within range",
                )
                .with_detail("cause", error.to_string())
            })?;
        let didcomm_universal_resolver_url = optional_http_base_url(
            settings.didcomm.universal_resolver_url,
            "DIDCOMM_UNIVERSAL_RESOLVER_URL",
        )?;
        let didcomm_did_web_internal_base_url = optional_http_base_url(
            settings.didcomm.did_web_internal_base_url,
            "DIDCOMM_DID_WEB_INTERNAL_BASE_URL",
        )?;
        let issuance_api_key = secret_value(&values, "ISSUANCE_API_KEY")?;
        let token_hmac_key = secret_value(&values, "TOKEN_HMAC_KEY")?;
        let integration_secret_key_name = values
            .get("INTEGRATION_SECRET_MASTER_KEY_ENV")
            .map(String::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("INTEGRATION_SECRET_MASTER_KEY");
        let integration_secret_master_key = secret_value(&values, integration_secret_key_name)?;
        let signing_keys_internal_api_key = secret_value(&values, "SIGNING_KEYS_INTERNAL_API_KEY")?
            .or_else(|| issuance_api_key.clone());
        let internal_service_token = secret_value(&values, "GRPC_SERVICE_TOKEN")?;
        let canvas_portable_enabled =
            environment_flag(&values, "CANVAS_PORTABLE_INTEGRATION_ENABLED");
        let canvas_pilot_organizations =
            comma_separated_values(&values, "CANVAS_PILOT_ORGANIZATION_IDS")
                .into_iter()
                .collect();
        let canvas_evidence_max_age =
            positive_seconds(&values, "CANVAS_ISSUANCE_EVIDENCE_MAX_AGE_SECONDS", 900)?;
        let canvas_readiness_max_age =
            positive_seconds(&values, "CANVAS_BINDING_READINESS_MAX_AGE_SECONDS", 900)?;
        let canvas_lti_state_ttl = positive_minutes(&values, "CANVAS_LTI_STATE_TTL_MINUTES", 10)?;
        let canvas_lti_jwks_ttl = positive_minutes(&values, "CANVAS_LTI_JWKS_TTL_MINUTES", 1440)?;
        let canvas_lti_experience_base_url = ["CANVAS_LTI_EXPERIENCE_BASE_URL", "UI_BASE_URL"]
            .into_iter()
            .find_map(|name| values.get(name).filter(|value| !value.trim().is_empty()))
            .map_or_else(
                || Ok(issuer_base_url.clone()),
                |value| validate_http_base_url(value, "Canvas LTI experience base URL"),
            )?;
        let canvas_lti_experience_code_ttl =
            positive_seconds(&values, "CANVAS_LTI_EXPERIENCE_CODE_TTL_SECONDS", 60)?;
        let canvas_lti_experience_session_ttl =
            positive_minutes(&values, "CANVAS_LTI_EXPERIENCE_SESSION_TTL_MINUTES", 30)?;
        let canvas_lti_tool_signing_organization_id = values
            .get("CANVAS_LTI_TOOL_SIGNING_ORGANIZATION_ID")
            .map_or("", String::as_str)
            .trim()
            .to_owned();
        let canvas_lti_tool_issuer_did = values
            .get("CANVAS_LTI_TOOL_ISSUER_DID")
            .map_or("", String::as_str)
            .trim()
            .to_owned();
        let canvas_lti_deep_linking_issuer = values
            .get("CANVAS_LTI_DEEP_LINKING_ISSUER")
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty());
        let canvas_oauth_completion_redirect_url = values
            .get("CANVAS_OAUTH_COMPLETION_REDIRECT_URL")
            .map(String::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map_or_else(
                || {
                    validate_canvas_oauth_completion_url(&format!(
                        "{canvas_lti_experience_base_url}/console/integrations/canvas"
                    ))
                },
                validate_canvas_oauth_completion_url,
            )?;
        let canvas_self_managed_origins =
            comma_separated_values(&values, "CANVAS_SELF_MANAGED_ORIGIN_ALLOWLIST");
        let canvas_private_origin_allowlist =
            comma_separated_values(&values, "CANVAS_PRIVATE_ORIGIN_ALLOWLIST");
        let canvas_allow_private_base_urls =
            environment_flag(&values, "CANVAS_ALLOW_PRIVATE_BASE_URLS");
        let canvas_allow_http_localhost_base_urls =
            environment_flag(&values, "CANVAS_ALLOW_HTTP_LOCALHOST_BASE_URLS");
        Ok(Self {
            http_addr,
            release_version: settings.build.release_version,
            build_revision: settings.build.revision,
            issuer_base_url,
            issuer_display_name: settings.discovery.issuer_display_name,
            cors_allowed_origins: settings.server.cors_allowed_origins,
            database_url,
            integration_secret_master_key,
            token_hmac_key,
            issuance_api_key,
            signing_keys_internal_url,
            signing_keys_internal_api_key,
            revocation_profile_service_url,
            internal_service_token,
            organization_grpc_target,
            credential_template_grpc_target,
            revocation_profile_grpc_target,
            credential_template_service_url,
            vcdm_related_resource_urls: settings.initiation.related_resource_urls,
            vcdm_related_resource_max_bytes: settings.initiation.related_resource_max_bytes,
            vcdm_related_resource_timeout,
            didcomm_universal_resolver_url,
            didcomm_did_web_internal_base_url,
            didcomm_encryption_policy_file: optional_trimmed(
                settings.didcomm.encryption_policy_file,
            ),
            didcomm_tls_ca_file: optional_trimmed(settings.didcomm.tls_ca_file),
            didcomm_allow_private_ips: settings.didcomm.allow_private_ips,
            canvas_portable_enabled,
            canvas_pilot_organizations,
            canvas_evidence_max_age,
            canvas_readiness_max_age,
            canvas_lti_state_ttl,
            canvas_lti_jwks_ttl,
            canvas_lti_experience_base_url,
            canvas_lti_experience_code_ttl,
            canvas_lti_experience_session_ttl,
            canvas_lti_tool_signing_organization_id,
            canvas_lti_tool_issuer_did,
            canvas_lti_deep_linking_issuer,
            canvas_oauth_completion_redirect_url,
            canvas_self_managed_origins,
            canvas_private_origin_allowlist,
            canvas_allow_private_base_urls,
            canvas_allow_http_localhost_base_urls,
            dependency_timeout: Duration::from_secs(10),
            token_rate_limit: settings.rate_limit.requests,
            token_rate_window: Duration::from_secs(settings.rate_limit.window_seconds),
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
    if let Some(revocation_profile_service_url) = values.get("REVOCATION_PROFILE_SERVICE_URL") {
        dependencies.insert(
            "revocation_profile_service_url".to_owned(),
            json!(revocation_profile_service_url),
        );
    }
    let mut initiation = Map::new();
    for (environment_name, setting_name) in [
        ("ORG_GRPC_TARGET", "organization_grpc_target"),
        ("CT_GRPC_TARGET", "credential_template_grpc_target"),
        ("RP_GRPC_TARGET", "revocation_profile_grpc_target"),
        (
            "CREDENTIAL_TEMPLATE_SERVICE_URL",
            "credential_template_service_url",
        ),
    ] {
        if let Some(value) = values.get(environment_name) {
            initiation.insert(setting_name.to_owned(), json!(value));
        }
    }
    if values.contains_key("VCDM_RELATED_RESOURCE_URLS") {
        initiation.insert(
            "related_resource_urls".to_owned(),
            json!(comma_separated_values(values, "VCDM_RELATED_RESOURCE_URLS")),
        );
    }
    if let Some(value) = values.get("VCDM_RELATED_RESOURCE_MAX_BYTES") {
        initiation.insert(
            "related_resource_max_bytes".to_owned(),
            json!(parse_legacy_number::<usize>(
                "VCDM_RELATED_RESOURCE_MAX_BYTES",
                value
            )?),
        );
    }
    if let Some(value) = values.get("VCDM_RELATED_RESOURCE_TIMEOUT_SECONDS") {
        initiation.insert(
            "related_resource_timeout_seconds".to_owned(),
            json!(value.parse::<f64>().map_err(|error| {
                MmfError::new(
                    ErrorCode::Configuration,
                    "VCDM_RELATED_RESOURCE_TIMEOUT_SECONDS must be a number",
                )
                .with_detail("cause", error.to_string())
            })?),
        );
    }
    let mut didcomm = Map::new();
    let resolver = values
        .get("DIDCOMM_UNIVERSAL_RESOLVER_URL")
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or_else(|| {
            values
                .get("UNIVERSAL_RESOLVER_URL")
                .map(String::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
        });
    if let Some(value) = resolver {
        didcomm.insert("universal_resolver_url".to_owned(), json!(value));
    }
    for (environment_name, setting_name) in [
        (
            "DIDCOMM_DID_WEB_INTERNAL_BASE_URL",
            "did_web_internal_base_url",
        ),
        ("DIDCOMM_ENCRYPTION_POLICY_FILE", "encryption_policy_file"),
        ("DIDCOMM_TLS_CA_FILE", "tls_ca_file"),
    ] {
        if let Some(value) = values
            .get(environment_name)
            .map(String::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            didcomm.insert(setting_name.to_owned(), json!(value));
        }
    }
    if let Some(value) = values.get("DIDCOMM_ALLOW_PRIVATE_IPS") {
        didcomm.insert(
            "allow_private_ips".to_owned(),
            json!(matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes"
            )),
        );
    }
    let mut rate_limit = Map::new();
    if let Some(requests) = values.get("TOKEN_RATE_LIMIT") {
        rate_limit.insert(
            "requests".to_owned(),
            json!(parse_legacy_number::<usize>("TOKEN_RATE_LIMIT", requests)?),
        );
    }
    if let Some(window_seconds) = values.get("TOKEN_RATE_WINDOW") {
        rate_limit.insert(
            "window_seconds".to_owned(),
            json!(parse_legacy_number::<u64>(
                "TOKEN_RATE_WINDOW",
                window_seconds
            )?),
        );
    }
    Ok(json!({
        "server": server,
        "build": build,
        "discovery": discovery,
        "dependencies": dependencies,
        "initiation": initiation,
        "didcomm": didcomm,
        "rate_limit": rate_limit
    }))
}

fn environment_flag(values: &BTreeMap<String, String>, name: &str) -> bool {
    values.get(name).is_some_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

fn positive_seconds(
    values: &BTreeMap<String, String>,
    name: &str,
    default: u64,
) -> Result<Duration, MmfError> {
    let seconds = values.get(name).map_or(Ok(default), |value| {
        value.parse::<u64>().map_err(|error| {
            MmfError::new(
                ErrorCode::Configuration,
                format!("{name} must be a positive integer"),
            )
            .with_detail("cause", error.to_string())
        })
    })?;
    if seconds == 0 || seconds > i64::MAX as u64 {
        return Err(MmfError::new(
            ErrorCode::Configuration,
            format!("{name} must be a positive integer within range"),
        ));
    }
    Ok(Duration::from_secs(seconds))
}

fn positive_minutes(
    values: &BTreeMap<String, String>,
    name: &str,
    default: u64,
) -> Result<Duration, MmfError> {
    let minutes = values.get(name).map_or(Ok(default), |value| {
        value.parse::<u64>().map_err(|error| {
            MmfError::new(
                ErrorCode::Configuration,
                format!("{name} must be a positive integer"),
            )
            .with_detail("cause", error.to_string())
        })
    })?;
    let seconds = minutes
        .checked_mul(60)
        .filter(|value| *value > 0 && *value <= i64::MAX as u64)
        .ok_or_else(|| {
            MmfError::new(
                ErrorCode::Configuration,
                format!("{name} must be a positive integer within range"),
            )
        })?;
    Ok(Duration::from_secs(seconds))
}

fn comma_separated_values(values: &BTreeMap<String, String>, name: &str) -> Vec<String> {
    values
        .get(name)
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn parse_legacy_number<T>(name: &str, value: &str) -> Result<T, MmfError>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    value.parse::<T>().map_err(|error| {
        MmfError::new(
            ErrorCode::Configuration,
            format!("{name} must be a non-negative integer"),
        )
        .with_detail("cause", error.to_string())
    })
}

pub(crate) fn normalize_grpc_target(value: &str) -> Option<String> {
    if value.is_empty() || value.chars().any(char::is_whitespace) {
        return None;
    }
    Some(if value.contains("://") {
        value.to_owned()
    } else {
        format!("http://{value}")
    })
}

fn validate_grpc_target(value: &str, name: &str) -> Result<String, MmfError> {
    let normalized = normalize_grpc_target(value).ok_or_else(|| {
        MmfError::new(
            ErrorCode::Configuration,
            format!("{name} must be a valid gRPC HTTP(S) target"),
        )
    })?;
    let parsed = url::Url::parse(&normalized).map_err(|error| {
        MmfError::new(
            ErrorCode::Configuration,
            format!("{name} must be a valid gRPC HTTP(S) target"),
        )
        .with_detail("cause", error.to_string())
    })?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path() != "/"
    {
        return Err(MmfError::new(
            ErrorCode::Configuration,
            format!("{name} must be a credential-free gRPC HTTP(S) target"),
        ));
    }
    Ok(normalized)
}

fn validate_issuer_base_url(value: &str) -> Result<String, MmfError> {
    validate_http_base_url(value, "ISSUER_BASE_URL")
}

fn validate_http_base_url(value: &str, name: &str) -> Result<String, MmfError> {
    let normalized = value.trim_end_matches('/');
    let parsed = url::Url::parse(normalized).map_err(|error| {
        MmfError::new(
            ErrorCode::Configuration,
            format!("{name} must be a valid HTTP(S) URL"),
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
            format!("{name} must be a credential-free HTTP(S) URL without query or fragment"),
        ));
    }
    Ok(normalized.to_owned())
}

fn optional_http_base_url(value: Option<String>, name: &str) -> Result<Option<String>, MmfError> {
    value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .map(|value| validate_http_base_url(&value, name))
        .transpose()
}

fn optional_trimmed(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn validate_canvas_oauth_completion_url(value: &str) -> Result<String, MmfError> {
    let parsed = url::Url::parse(value).map_err(|error| {
        MmfError::new(
            ErrorCode::Configuration,
            "CANVAS_OAUTH_COMPLETION_REDIRECT_URL must be a trusted HTTPS URL",
        )
        .with_detail("cause", error.to_string())
    })?;
    let local_http = is_loopback_http_url(&parsed);
    if (parsed.scheme() != "https" && !local_http)
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err(MmfError::new(
            ErrorCode::Configuration,
            "CANVAS_OAUTH_COMPLETION_REDIRECT_URL must be a trusted HTTPS URL",
        ));
    }
    Ok(value.to_owned())
}

pub(crate) fn is_loopback_http_url(value: &url::Url) -> bool {
    value.scheme() == "http"
        && match value.host() {
            Some(url::Host::Domain(host)) => host == "localhost",
            Some(url::Host::Ipv4(address)) => address.is_loopback(),
            Some(url::Host::Ipv6(address)) => address.is_loopback(),
            None => false,
        }
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
        assert_eq!(config.organization_grpc_target, "http://organization:9002");
        assert_eq!(
            config.credential_template_grpc_target,
            "http://credential-template:9003"
        );
        assert_eq!(
            config.revocation_profile_grpc_target,
            "http://revocation-profile:9013"
        );
        assert_eq!(
            config.credential_template_service_url,
            "http://credential-template:8003"
        );
        assert!(config.vcdm_related_resource_urls.is_empty());
        assert_eq!(config.vcdm_related_resource_max_bytes, 2_000_000);
        assert_eq!(
            config.vcdm_related_resource_timeout,
            std::time::Duration::from_secs(10)
        );
        assert!(config.didcomm_universal_resolver_url.is_none());
        assert!(config.didcomm_did_web_internal_base_url.is_none());
        assert!(config.didcomm_encryption_policy_file.is_none());
        assert!(config.didcomm_tls_ca_file.is_none());
        assert!(!config.didcomm_allow_private_ips);
        assert!(config.signing_keys_internal_api_key.is_none());
        assert!(config.issuance_api_key.is_none());
        assert!(config.token_hmac_key.is_none());
        assert_eq!(config.token_rate_limit, 30);
        assert_eq!(config.token_rate_window, std::time::Duration::from_secs(60));
        assert_eq!(
            config.canvas_lti_state_ttl,
            std::time::Duration::from_secs(600)
        );
        assert_eq!(
            config.canvas_lti_jwks_ttl,
            std::time::Duration::from_secs(86_400)
        );
        assert_eq!(
            config.canvas_lti_experience_base_url,
            "https://beta.elevenidllc.com"
        );
        assert_eq!(
            config.canvas_oauth_completion_redirect_url,
            "https://beta.elevenidllc.com/console/integrations/canvas"
        );
        assert!(config.integration_secret_master_key.is_none());
        assert_eq!(
            config.canvas_lti_experience_code_ttl,
            std::time::Duration::from_secs(60)
        );
        assert_eq!(
            config.canvas_lti_experience_session_ttl,
            std::time::Duration::from_secs(1_800)
        );
        assert!(config.canvas_lti_tool_signing_organization_id.is_empty());
        assert!(config.canvas_lti_tool_issuer_did.is_empty());
        assert!(config.canvas_lti_deep_linking_issuer.is_none());
        assert!(config.canvas_self_managed_origins.is_empty());
        assert!(config.canvas_private_origin_allowlist.is_empty());
        assert!(!config.canvas_allow_private_base_urls);
        assert!(!config.canvas_allow_http_localhost_base_urls);
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
            ("TOKEN_HMAC_KEY", "token-hmac-contract-key"),
            ("SIGNING_KEYS_INTERNAL_API_KEY", "preferred-key"),
            ("TOKEN_RATE_LIMIT", "12"),
            ("TOKEN_RATE_WINDOW", "45"),
            ("CANVAS_LTI_STATE_TTL_MINUTES", "12"),
            ("CANVAS_LTI_JWKS_TTL_MINUTES", "30"),
            ("CANVAS_LTI_EXPERIENCE_BASE_URL", "https://ui.example/"),
            ("CANVAS_LTI_EXPERIENCE_CODE_TTL_SECONDS", "90"),
            ("CANVAS_LTI_EXPERIENCE_SESSION_TTL_MINUTES", "45"),
            ("CANVAS_LTI_TOOL_SIGNING_ORGANIZATION_ID", " system-tools "),
            (
                "CANVAS_LTI_TOOL_ISSUER_DID",
                " did:web:issuer.example:canvas ",
            ),
            (
                "CANVAS_LTI_DEEP_LINKING_ISSUER",
                " elevenid-deep-link-client ",
            ),
            ("CANVAS_ALLOW_PRIVATE_BASE_URLS", "true"),
            ("CANVAS_ALLOW_HTTP_LOCALHOST_BASE_URLS", "yes"),
            (
                "CANVAS_PRIVATE_ORIGIN_ALLOWLIST",
                " https://10.0.0.4,https://canvas.internal.example ,,",
            ),
            (
                "CANVAS_SELF_MANAGED_ORIGIN_ALLOWLIST",
                " https://canvas.one.example,https://canvas.two.example ,,",
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
        assert_eq!(config.issuance_api_key.as_deref(), Some("fallback-key"));
        assert_eq!(
            config.token_hmac_key.as_deref(),
            Some("token-hmac-contract-key")
        );
        assert_eq!(config.token_rate_limit, 12);
        assert_eq!(config.token_rate_window, std::time::Duration::from_secs(45));
        assert_eq!(
            config.canvas_lti_state_ttl,
            std::time::Duration::from_secs(720)
        );
        assert_eq!(
            config.canvas_lti_jwks_ttl,
            std::time::Duration::from_secs(1_800)
        );
        assert_eq!(config.canvas_lti_experience_base_url, "https://ui.example");
        assert_eq!(
            config.canvas_lti_experience_code_ttl,
            std::time::Duration::from_secs(90)
        );
        assert_eq!(
            config.canvas_lti_experience_session_ttl,
            std::time::Duration::from_secs(2_700)
        );
        assert_eq!(
            config.canvas_lti_tool_signing_organization_id,
            "system-tools"
        );
        assert_eq!(
            config.canvas_lti_tool_issuer_did,
            "did:web:issuer.example:canvas"
        );
        assert_eq!(
            config.canvas_lti_deep_linking_issuer.as_deref(),
            Some("elevenid-deep-link-client")
        );
        assert_eq!(
            config.canvas_self_managed_origins,
            ["https://canvas.one.example", "https://canvas.two.example"]
        );
        assert_eq!(
            config.canvas_private_origin_allowlist,
            ["https://10.0.0.4", "https://canvas.internal.example"]
        );
        assert!(config.canvas_allow_private_base_urls);
        assert!(config.canvas_allow_http_localhost_base_urls);
        let diagnostic = format!("{config:?}");
        assert!(!diagnostic.contains("preferred-key"));
        assert!(!diagnostic.contains("fallback-key"));
        assert!(!diagnostic.contains("token-hmac-contract-key"));
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
    fn invalid_legacy_rate_limit_fails_closed() {
        for (name, value) in [("TOKEN_RATE_LIMIT", "-1"), ("TOKEN_RATE_WINDOW", "later")] {
            let error = IssuanceServiceConfig::from_values(values(&[(name, value)]))
                .expect_err("invalid rate limit");
            assert_eq!(error.code, ErrorCode::Configuration);
        }
    }

    #[test]
    fn legacy_initiation_configuration_is_normalized_once() {
        let config = IssuanceServiceConfig::from_values(values(&[
            ("ORG_GRPC_TARGET", "organization.internal:9102"),
            (
                "CT_GRPC_TARGET",
                "https://credential-template.internal:9103",
            ),
            ("RP_GRPC_TARGET", "http://revocation-profile.internal:9113"),
            (
                "CREDENTIAL_TEMPLATE_SERVICE_URL",
                "https://templates.internal/api/",
            ),
            (
                "VCDM_RELATED_RESOURCE_URLS",
                " https://www.w3.org/ns/credentials/v2,https://example.test/context ,,",
            ),
            ("VCDM_RELATED_RESOURCE_MAX_BYTES", "42"),
            ("VCDM_RELATED_RESOURCE_TIMEOUT_SECONDS", "0.25"),
        ]))
        .expect("initiation configuration");

        assert_eq!(
            config.organization_grpc_target,
            "http://organization.internal:9102"
        );
        assert_eq!(
            config.credential_template_grpc_target,
            "https://credential-template.internal:9103"
        );
        assert_eq!(
            config.revocation_profile_grpc_target,
            "http://revocation-profile.internal:9113"
        );
        assert_eq!(
            config.credential_template_service_url,
            "https://templates.internal/api"
        );
        assert_eq!(
            config.vcdm_related_resource_urls,
            [
                "https://www.w3.org/ns/credentials/v2",
                "https://example.test/context"
            ]
        );
        assert_eq!(config.vcdm_related_resource_max_bytes, 42);
        assert_eq!(
            config.vcdm_related_resource_timeout,
            std::time::Duration::from_millis(250)
        );
    }

    #[test]
    fn didcomm_configuration_preserves_managed_fallbacks_and_redaction() {
        let fallback = IssuanceServiceConfig::from_values(values(&[
            (
                "UNIVERSAL_RESOLVER_URL",
                "https://resolver.example/1.0/identifiers/",
            ),
            ("DIDCOMM_DID_WEB_INTERNAL_BASE_URL", "http://gateway:8000/"),
            (
                "DIDCOMM_ENCRYPTION_POLICY_FILE",
                " /run/secrets/didcomm-policy.json ",
            ),
            ("DIDCOMM_TLS_CA_FILE", " /run/secrets/didcomm-root-ca.pem "),
            ("DIDCOMM_ALLOW_PRIVATE_IPS", "yes"),
        ]))
        .expect("DIDComm fallback configuration");
        assert_eq!(
            fallback.didcomm_universal_resolver_url.as_deref(),
            Some("https://resolver.example/1.0/identifiers")
        );
        assert_eq!(
            fallback.didcomm_did_web_internal_base_url.as_deref(),
            Some("http://gateway:8000")
        );
        assert_eq!(
            fallback.didcomm_encryption_policy_file.as_deref(),
            Some("/run/secrets/didcomm-policy.json")
        );
        assert_eq!(
            fallback.didcomm_tls_ca_file.as_deref(),
            Some("/run/secrets/didcomm-root-ca.pem")
        );
        assert!(fallback.didcomm_allow_private_ips);
        let diagnostic = format!("{fallback:?}");
        assert!(!diagnostic.contains("didcomm-policy.json"));
        assert!(!diagnostic.contains("didcomm-root-ca.pem"));

        let explicit = IssuanceServiceConfig::from_values(values(&[
            ("UNIVERSAL_RESOLVER_URL", "https://fallback.example"),
            (
                "DIDCOMM_UNIVERSAL_RESOLVER_URL",
                "https://didcomm-resolver.example/api/",
            ),
            ("DIDCOMM_ALLOW_PRIVATE_IPS", "on"),
        ]))
        .expect("explicit DIDComm resolver");
        assert_eq!(
            explicit.didcomm_universal_resolver_url.as_deref(),
            Some("https://didcomm-resolver.example/api")
        );
        assert!(!explicit.didcomm_allow_private_ips);
    }

    #[test]
    fn invalid_didcomm_resolver_configuration_fails_closed() {
        for (name, value) in [
            ("DIDCOMM_UNIVERSAL_RESOLVER_URL", "ftp://resolver.example"),
            (
                "DIDCOMM_DID_WEB_INTERNAL_BASE_URL",
                "https://user:secret@gateway.example",
            ),
            (
                "UNIVERSAL_RESOLVER_URL",
                "https://resolver.example/api?caller=holder",
            ),
        ] {
            let error = IssuanceServiceConfig::from_values(values(&[(name, value)]))
                .expect_err("invalid DIDComm configuration");
            assert_eq!(error.code, ErrorCode::Configuration, "{name}={value}");
        }
    }

    #[test]
    fn invalid_initiation_configuration_fails_closed() {
        for (name, value) in [
            ("ORG_GRPC_TARGET", " organization:9002"),
            ("CT_GRPC_TARGET", "ftp://credential-template:9003"),
            ("RP_GRPC_TARGET", "http://revocation-profile:9013/path"),
            (
                "CREDENTIAL_TEMPLATE_SERVICE_URL",
                "ftp://credential-template:8003",
            ),
            ("VCDM_RELATED_RESOURCE_MAX_BYTES", "0"),
            ("VCDM_RELATED_RESOURCE_TIMEOUT_SECONDS", "0"),
            ("VCDM_RELATED_RESOURCE_TIMEOUT_SECONDS", "-1"),
        ] {
            let error = IssuanceServiceConfig::from_values(values(&[(name, value)]))
                .expect_err("invalid initiation configuration");
            assert_eq!(error.code, ErrorCode::Configuration, "{name}={value}");
        }
    }

    #[test]
    fn invalid_canvas_lti_ttls_fail_closed() {
        for name in [
            "CANVAS_LTI_STATE_TTL_MINUTES",
            "CANVAS_LTI_JWKS_TTL_MINUTES",
            "CANVAS_LTI_EXPERIENCE_CODE_TTL_SECONDS",
            "CANVAS_LTI_EXPERIENCE_SESSION_TTL_MINUTES",
        ] {
            let invalid_values = if name.ends_with("_MINUTES") {
                &[
                    "0",
                    "-1",
                    "later",
                    "153722867280912931",
                    "18446744073709551615",
                ][..]
            } else {
                &["0", "-1", "later", "18446744073709551615"][..]
            };
            for value in invalid_values {
                let error = IssuanceServiceConfig::from_values(values(&[(name, value)]))
                    .expect_err("invalid Canvas LTI TTL");
                assert_eq!(error.code, ErrorCode::Configuration);
            }
        }
    }

    #[test]
    fn canvas_lti_experience_base_url_preserves_the_python_fallback_order() {
        let ui_fallback = IssuanceServiceConfig::from_values(values(&[
            ("ISSUER_BASE_URL", "https://issuer.example"),
            ("UI_BASE_URL", "https://ui.example/"),
        ]))
        .expect("UI fallback");
        assert_eq!(
            ui_fallback.canvas_lti_experience_base_url,
            "https://ui.example"
        );

        let explicit = IssuanceServiceConfig::from_values(values(&[
            ("ISSUER_BASE_URL", "https://issuer.example"),
            ("UI_BASE_URL", "https://ui.example"),
            (
                "CANVAS_LTI_EXPERIENCE_BASE_URL",
                "https://experience.example/",
            ),
        ]))
        .expect("explicit experience URL");
        assert_eq!(
            explicit.canvas_lti_experience_base_url,
            "https://experience.example"
        );
    }

    #[test]
    fn canvas_oauth_configuration_preserves_secret_indirection_and_redaction() {
        let config = IssuanceServiceConfig::from_values(values(&[
            (
                "INTEGRATION_SECRET_MASTER_KEY_ENV",
                "ROTATED_INTEGRATION_KEY",
            ),
            ("ROTATED_INTEGRATION_KEY", "base64-encryption-key"),
            (
                "CANVAS_OAUTH_COMPLETION_REDIRECT_URL",
                "https://ui.example/console/integrations/canvas?source=oauth",
            ),
        ]))
        .expect("Canvas OAuth configuration");
        assert_eq!(
            config.integration_secret_master_key.as_deref(),
            Some("base64-encryption-key")
        );
        assert_eq!(
            config.canvas_oauth_completion_redirect_url,
            "https://ui.example/console/integrations/canvas?source=oauth"
        );
        assert!(!format!("{config:?}").contains("base64-encryption-key"));
    }

    #[test]
    fn invalid_canvas_oauth_completion_urls_fail_closed() {
        for value in [
            "http://ui.example/console/integrations/canvas",
            "ftp://ui.example/console/integrations/canvas",
            "https://user:secret@ui.example/console/integrations/canvas",
            "https://ui.example/console/integrations/canvas#token",
            "not-a-url",
        ] {
            let error = IssuanceServiceConfig::from_values(values(&[(
                "CANVAS_OAUTH_COMPLETION_REDIRECT_URL",
                value,
            )]))
            .expect_err("invalid Canvas OAuth completion URL");
            assert_eq!(error.code, ErrorCode::Configuration);
        }

        for value in [
            "http://localhost:3000/console/integrations/canvas",
            "http://127.0.0.1:3000/console/integrations/canvas",
            "http://[::1]:3000/console/integrations/canvas",
        ] {
            let config = IssuanceServiceConfig::from_values(values(&[(
                "CANVAS_OAUTH_COMPLETION_REDIRECT_URL",
                value,
            )]))
            .expect("local development completion URL");
            assert_eq!(config.canvas_oauth_completion_redirect_url, value);
        }
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
    fn invalid_canvas_lti_experience_urls_fail_closed() {
        for value in [
            "ftp://experience.example",
            "https://user:password@experience.example",
            "https://experience.example?tenant=a",
            "not-a-url",
        ] {
            let error = IssuanceServiceConfig::from_values(values(&[(
                "CANVAS_LTI_EXPERIENCE_BASE_URL",
                value,
            )]))
            .expect_err("invalid experience URL");
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

    #[test]
    fn issuance_key_is_retained_for_management_and_signing_fallback_without_debug_leakage() {
        let config = IssuanceServiceConfig::from_values(values(&[(
            "ISSUANCE_API_KEY",
            "shared-legacy-key",
        )]))
        .expect("configuration");
        assert_eq!(
            config.issuance_api_key.as_deref(),
            Some("shared-legacy-key")
        );
        assert_eq!(
            config.signing_keys_internal_api_key.as_deref(),
            Some("shared-legacy-key")
        );
        assert!(!format!("{config:?}").contains("shared-legacy-key"));
    }
}
