use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use marty_passport_auth::PassportTenantKeyring;
use mmf_config::{numeric_config::PythonConfigInteger, ConfigLayer, LayeredConfig};
use mmf_core::{ErrorCode, MmfError};
use serde::Deserialize;
use serde_json::{json, Map, Value};

#[derive(Clone, Eq, PartialEq)]
pub struct PassportNativeConfig {
    pub enabled: bool,
    pub internal_service_auth_enabled: bool,
    pub managed_issuer_signing_enabled: bool,
    pub kms_artifacts_enabled: bool,
    pub kms_callbacks_enabled: bool,
    pub bureau_url: Option<String>,
    pub bureau_api_key: Option<String>,
    pub bureau_provider_profile_id: Option<String>,
    pub beta_reconciliation_enabled: bool,
    pub beta_reconciliation_operator_token: Option<String>,
}

impl std::fmt::Debug for PassportNativeConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PassportNativeConfig")
            .field("enabled", &self.enabled)
            .field(
                "internal_service_auth_enabled",
                &self.internal_service_auth_enabled,
            )
            .field(
                "managed_issuer_signing_enabled",
                &self.managed_issuer_signing_enabled,
            )
            .field("kms_artifacts_enabled", &self.kms_artifacts_enabled)
            .field("kms_callbacks_enabled", &self.kms_callbacks_enabled)
            .field("bureau_url_configured", &self.bureau_url.is_some())
            .field("bureau_api_key_configured", &self.bureau_api_key.is_some())
            .field(
                "bureau_provider_profile_id",
                &self.bureau_provider_profile_id,
            )
            .field(
                "beta_reconciliation_enabled",
                &self.beta_reconciliation_enabled,
            )
            .field(
                "beta_reconciliation_operator_token_configured",
                &self.beta_reconciliation_operator_token.is_some(),
            )
            .finish()
    }
}

impl PassportNativeConfig {
    fn from_values(
        values: &BTreeMap<String, String>,
        tenant_keys_configured: bool,
    ) -> Result<Self, MmfError> {
        let enabled = environment_flag(values, "PASSPORT_NATIVE_HTTP_ENABLED");
        if environment_flag(values, "PHYSICAL_DOCUMENT_ALLOW_SELF_SIGNED") {
            return Err(MmfError::new(
                ErrorCode::Configuration,
                "self-signed passport signing is forbidden",
            ));
        }
        let configured = |name: &str| {
            values
                .get(name)
                .map(String::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
        };
        if values.contains_key("PHYSICAL_DOCUMENT_ARTIFACT_KEY")
            || values.contains_key("PHYSICAL_DOCUMENT_ARTIFACT_KEY_FILE")
        {
            return Err(MmfError::new(
                ErrorCode::Configuration,
                "local passport artifact-key configuration is forbidden",
            ));
        }
        if values.contains_key("PERSONALIZATION_BUREAU_WEBHOOK_SECRET")
            || values.contains_key("PERSONALIZATION_BUREAU_WEBHOOK_SECRET_FILE")
        {
            return Err(MmfError::new(
                ErrorCode::Configuration,
                "local passport callback-secret configuration is forbidden",
            ));
        }
        if values.contains_key("ICAO_DOCUMENT_SIGNER_URL")
            || values.contains_key("ICAO_DOCUMENT_SIGNER_API_KEY")
            || values.contains_key("ICAO_DOCUMENT_SIGNER_API_KEY_FILE")
        {
            return Err(MmfError::new(
                ErrorCode::Configuration,
                "external passport signer configuration is forbidden; use managed issuer signing",
            ));
        }
        if !enabled {
            return Ok(Self {
                enabled,
                internal_service_auth_enabled: false,
                managed_issuer_signing_enabled: false,
                kms_artifacts_enabled: false,
                kms_callbacks_enabled: false,
                bureau_url: None,
                bureau_api_key: None,
                bureau_provider_profile_id: None,
                beta_reconciliation_enabled: false,
                beta_reconciliation_operator_token: None,
            });
        }
        let kms_artifacts_enabled = environment_flag(values, "PASSPORT_KMS_ARTIFACTS_ENABLED");
        let kms_callbacks_enabled = environment_flag(values, "PASSPORT_KMS_CALLBACKS_ENABLED");
        let bureau_provider_profile_id = configured("PERSONALIZATION_BUREAU_PROVIDER_PROFILE_ID");
        let bureau_url = configured("PERSONALIZATION_BUREAU_URL");
        let beta_reconciliation_enabled =
            environment_flag(values, "PASSPORT_BETA_RECONCILIATION_ENABLED");
        let beta_reconciliation_operator_token =
            secret_value(values, "PASSPORT_BETA_RECONCILIATION_OPERATOR_TOKEN")?;
        if beta_reconciliation_enabled
            && !(values
                .get("ENVIRONMENT")
                .is_some_and(|value| value == "beta")
                && environment_flag(values, "PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED")
                && environment_flag(values, "PASSPORT_MANAGED_ISSUER_SIGNING_ENABLED")
                && kms_artifacts_enabled
                && environment_flag(values, "PASSPORT_KMS_CALLBACKS_ENABLED")
                && bureau_provider_profile_id.as_deref() == Some("passport-beta-bureau")
                && bureau_url.as_deref() == Some("http://passport-beta-bureau:8020")
                && beta_reconciliation_operator_token
                    .as_deref()
                    .is_some_and(|token| token.len() >= 32))
        {
            return Err(MmfError::new(
                ErrorCode::Configuration,
                "passport beta reconciliation requires the isolated beta KMS and simulator profile",
            ));
        }
        if bureau_provider_profile_id
            .as_deref()
            .is_some_and(|profile_id| profile_id.len() > 128)
        {
            return Err(MmfError::new(
                ErrorCode::Configuration,
                "PERSONALIZATION_BUREAU_PROVIDER_PROFILE_ID exceeds 128 bytes",
            ));
        }
        if kms_callbacks_enabled && bureau_url.is_some() && bureau_provider_profile_id.is_none() {
            return Err(MmfError::new(
                ErrorCode::Configuration,
                "KMS passport bureau submission requires PERSONALIZATION_BUREAU_PROVIDER_PROFILE_ID",
            ));
        }
        let config = Self {
            enabled,
            internal_service_auth_enabled: environment_flag(
                values,
                "PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED",
            ),
            managed_issuer_signing_enabled: environment_flag(
                values,
                "PASSPORT_MANAGED_ISSUER_SIGNING_ENABLED",
            ),
            kms_artifacts_enabled,
            kms_callbacks_enabled,
            bureau_url,
            bureau_api_key: secret_value(values, "PERSONALIZATION_BUREAU_API_KEY")?,
            bureau_provider_profile_id,
            beta_reconciliation_enabled,
            beta_reconciliation_operator_token,
        };
        let production = values
            .get("ENVIRONMENT")
            .or_else(|| values.get("APP_ENV"))
            .is_some_and(|value| {
                matches!(
                    value.trim().to_ascii_lowercase().as_str(),
                    "production" | "prod"
                )
            });
        if production
            && config.bureau_url.as_deref().is_some_and(|value| {
                url::Url::parse(value).ok().is_some_and(|url| {
                    url.host_str()
                        .is_some_and(|host| host.trim_end_matches('.') == "passport-beta-bureau")
                })
            })
        {
            return Err(MmfError::new(
                ErrorCode::Configuration,
                "beta passport bureau simulator cannot be selected as a production provider",
            ));
        }
        // Tenant authentication is mandatory even for the diagnostic capability
        // route. Missing providers are represented as blockers there, matching
        // the released Python surface; provider-backed operations remain 503.
        if !tenant_keys_configured && !config.internal_service_auth_enabled {
            return Err(MmfError::new(
                ErrorCode::Configuration,
                "PASSPORT_TENANT_API_KEYS is required when PASSPORT_NATIVE_HTTP_ENABLED is true",
            ));
        }
        Ok(config)
    }
}

pub use marty_service_runtime::WorkloadTlsFiles as IssuanceWorkloadServerTlsFiles;

#[derive(Clone, Eq, PartialEq)]
pub struct IssuanceServiceConfig {
    pub http_addr: SocketAddr,
    pub grpc_addr: SocketAddr,
    pub grpc_enabled: bool,
    pub workload_server_tls: Option<IssuanceWorkloadServerTlsFiles>,
    pub managed_authority_https: Option<marty_service_runtime::https::ManagedAuthorityHttpsConfig>,
    pub release_version: String,
    pub build_revision: String,
    pub issuer_base_url: String,
    pub allowed_redirect_uris: Vec<String>,
    pub issuance_offer_ttl_minutes: PythonConfigInteger,
    pub authorization_session_ttl_minutes: PythonConfigInteger,
    pub issuer_display_name: String,
    pub cors_allowed_origins: Vec<String>,
    pub database_url: String,
    pub token_hmac_key: Option<String>,
    pub issuance_api_key: Option<String>,
    pub external_observations_enabled: bool,
    pub application_ownership_enabled: bool,
    pub external_associations_enabled: bool,
    pub external_association_database_url: Option<String>,
    pub external_observation_database_url: Option<String>,
    pub passport_tenant_keys: Option<PassportTenantKeyring>,
    pub passport_native: PassportNativeConfig,
    pub signing_keys_internal_url: url::Url,
    pub signing_keys_internal_api_key: Option<String>,
    pub integration_secret_api_key: Option<String>,
    pub issuer_sign_key: Option<String>,
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
    pub dependency_timeout: Duration,
    pub token_rate_limit: PythonConfigInteger,
    pub token_rate_window: PythonConfigInteger,
}

impl std::fmt::Debug for IssuanceServiceConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IssuanceServiceConfig")
            .field("http_addr", &self.http_addr)
            .field("grpc_addr", &self.grpc_addr)
            .field("grpc_enabled", &self.grpc_enabled)
            .field(
                "workload_server_tls_configured",
                &self.workload_server_tls.is_some(),
            )
            .field("release_version", &self.release_version)
            .field("build_revision", &self.build_revision)
            .field("issuer_base_url", &self.issuer_base_url)
            .field(
                "allowed_redirect_uri_count",
                &self.allowed_redirect_uris.len(),
            )
            .field(
                "issuance_offer_ttl_minutes",
                &self.issuance_offer_ttl_minutes,
            )
            .field(
                "authorization_session_ttl_minutes",
                &self.authorization_session_ttl_minutes,
            )
            .field("issuer_display_name", &self.issuer_display_name)
            .field("cors_allowed_origins", &self.cors_allowed_origins)
            .field("database_url_configured", &!self.database_url.is_empty())
            .field("token_hmac_key_configured", &self.token_hmac_key.is_some())
            .field(
                "issuance_api_key_configured",
                &self.issuance_api_key.is_some(),
            )
            .field(
                "passport_tenant_keys_configured",
                &self.passport_tenant_keys.is_some(),
            )
            .field(
                "external_observations_enabled",
                &self.external_observations_enabled,
            )
            .field(
                "application_ownership_enabled",
                &self.application_ownership_enabled,
            )
            .field(
                "external_associations_enabled",
                &self.external_associations_enabled,
            )
            .field(
                "external_association_database_configured",
                &self.external_association_database_url.is_some(),
            )
            .field(
                "external_observation_database_configured",
                &self.external_observation_database_url.is_some(),
            )
            .field("passport_native", &self.passport_native)
            .field("signing_keys_internal_url", &self.signing_keys_internal_url)
            .field(
                "signing_keys_internal_api_key_configured",
                &self.signing_keys_internal_api_key.is_some(),
            )
            .field(
                "issuer_sign_key_configured",
                &self.issuer_sign_key.is_some(),
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
    authorization: AuthorizationSettings,
    didcomm: DidcommSettings,
    rate_limit: RateLimitSettings,
}

#[derive(Deserialize)]
struct ServerSettings {
    host: IpAddr,
    port: u16,
    grpc_port: u16,
    grpc_enabled: bool,
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
    offer_ttl_minutes: Value,
    organization_grpc_target: String,
    credential_template_grpc_target: String,
    revocation_profile_grpc_target: String,
    credential_template_service_url: String,
    related_resource_urls: Vec<String>,
    related_resource_max_bytes: usize,
    related_resource_timeout_seconds: f64,
}

#[derive(Deserialize)]
struct AuthorizationSettings {
    session_ttl_minutes: Value,
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
    requests: Value,
    window_seconds: Value,
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
        if config.signing_keys_internal_api_key.is_none() {
            return Err(MmfError::new(
                ErrorCode::Configuration,
                "SIGNING_KEYS_INTERNAL_API_KEY or ISSUANCE_API_KEY is required",
            ));
        }
        if config.integration_secret_api_key.is_none() {
            return Err(MmfError::new(
                ErrorCode::Configuration,
                "SIGNING_KEYS_INTEGRATION_SECRET_KEY is required for integration secrets",
            ));
        }
        if config.issuer_sign_key.is_none() {
            return Err(MmfError::new(
                ErrorCode::Configuration,
                "SIGNING_KEYS_ISSUER_SIGN_KEY is required for issuer signing",
            ));
        }
        validate_grpc_service_token(
            config.internal_service_token.as_deref(),
            config.grpc_enabled,
        )?;
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
                    "grpc_port": 9005,
                    "grpc_enabled": true,
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
                    "offer_ttl_minutes": crate::initiation::DEFAULT_INITIATION_OFFER_TTL_MINUTES.to_string(),
                    "organization_grpc_target": "organization:9002",
                    "credential_template_grpc_target": "credential-template:9003",
                    "revocation_profile_grpc_target": "revocation-profile:9013",
                    "credential_template_service_url": "http://credential-template:8003",
                    "related_resource_urls": [],
                    "related_resource_max_bytes": 2000000,
                    "related_resource_timeout_seconds": 10.0
                },
                "authorization": {
                    "session_ttl_minutes": "60"
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
        let grpc_addr = SocketAddr::new(settings.server.host, settings.server.grpc_port);
        let issuer_base_url = validate_issuer_base_url(&settings.discovery.issuer_base_url)?;
        let allowed_redirect_uris = comma_separated_values(&values, "ALLOWED_REDIRECT_URIS");
        // Preserve Python int() grammar and width at startup; calendar limits
        // belong to transaction creation, after existing-reservation recovery.
        let issuance_offer_ttl_minutes = parse_python_integer_setting(
            "ISSUANCE_OFFER_TTL_MINUTES",
            &settings.initiation.offer_ttl_minutes,
        )?;
        let authorization_session_ttl_minutes = parse_python_integer_setting(
            "ISSUANCE_AUTH_SESSION_TTL_MINUTES",
            &settings.authorization.session_ttl_minutes,
        )?;
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
        if environment_flag(&values, "PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED")
            && (values
                .get("PASSPORT_TENANT_API_KEYS")
                .is_some_and(|value| !value.trim().is_empty())
                || values
                    .get("PASSPORT_TENANT_API_KEYS_FILE")
                    .is_some_and(|value| !value.trim().is_empty()))
        {
            return Err(MmfError::new(
                ErrorCode::Configuration,
                "internal passport service authentication cannot be combined with a tenant keyring",
            ));
        }
        let passport_tenant_keys = secret_value(&values, "PASSPORT_TENANT_API_KEYS")?
            .map(|value| {
                PassportTenantKeyring::from_json(&value).map_err(|_| {
                    MmfError::new(
                        ErrorCode::Configuration,
                        "PASSPORT_TENANT_API_KEYS must be a valid tenant keyring",
                    )
                })
            })
            .transpose()?;
        let passport_native =
            PassportNativeConfig::from_values(&values, passport_tenant_keys.is_some())?;
        let token_hmac_key = secret_value(&values, "TOKEN_HMAC_KEY")?;
        if [
            "INTEGRATION_SECRET_MASTER_KEY",
            "INTEGRATION_SECRET_MASTER_KEY_FILE",
            "INTEGRATION_SECRET_MASTER_KEY_ENV",
        ]
        .iter()
        .any(|name| values.contains_key(*name))
        {
            return Err(MmfError::new(
                ErrorCode::Configuration,
                "legacy integration-secret master-key configuration is forbidden",
            ));
        }
        let signing_keys_internal_api_key = secret_value(&values, "SIGNING_KEYS_INTERNAL_API_KEY")?
            .or_else(|| issuance_api_key.clone());
        if values.contains_key("SIGNING_KEYS_INTEGRATION_SECRET_KEY")
            && values.contains_key("SIGNING_KEYS_INTEGRATION_SECRET_KEY_FILE")
        {
            return Err(MmfError::new(
                ErrorCode::Configuration,
                "SIGNING_KEYS_INTEGRATION_SECRET_KEY must use one secret source",
            ));
        }
        let integration_secret_api_key =
            secret_value(&values, "SIGNING_KEYS_INTEGRATION_SECRET_KEY")?;
        if integration_secret_api_key.as_ref().is_some_and(|key| {
            key.len() < 32
                || signing_keys_internal_api_key.as_ref() == Some(key)
                || issuance_api_key.as_ref() == Some(key)
        }) {
            return Err(MmfError::new(
                ErrorCode::Configuration,
                "SIGNING_KEYS_INTEGRATION_SECRET_KEY must be distinct and at least 32 characters",
            ));
        }
        if integration_secret_api_key
            .as_deref()
            .is_some_and(has_placeholder_prefix)
        {
            return Err(MmfError::new(
                ErrorCode::Configuration,
                "SIGNING_KEYS_INTEGRATION_SECRET_KEY must not be a placeholder",
            ));
        }
        if values.contains_key("SIGNING_KEYS_ISSUER_SIGN_KEY")
            && values.contains_key("SIGNING_KEYS_ISSUER_SIGN_KEY_FILE")
        {
            return Err(MmfError::new(
                ErrorCode::Configuration,
                "SIGNING_KEYS_ISSUER_SIGN_KEY must use one secret source",
            ));
        }
        let issuer_sign_key = secret_value(&values, "SIGNING_KEYS_ISSUER_SIGN_KEY")?;
        if issuer_sign_key.as_ref().is_some_and(|key| {
            key.len() < 32
                || signing_keys_internal_api_key.as_ref() == Some(key)
                || issuance_api_key.as_ref() == Some(key)
                || integration_secret_api_key.as_ref() == Some(key)
        }) {
            return Err(MmfError::new(
                ErrorCode::Configuration,
                "SIGNING_KEYS_ISSUER_SIGN_KEY must be distinct and at least 32 characters",
            ));
        }
        if values
            .get("GRPC_SERVICE_TOKEN")
            .is_some_and(|value| !value.trim().is_empty())
            && values
                .get("GRPC_SERVICE_TOKEN_FILE")
                .is_some_and(|value| !value.trim().is_empty())
        {
            return Err(MmfError::new(
                ErrorCode::Configuration,
                "GRPC_SERVICE_TOKEN and GRPC_SERVICE_TOKEN_FILE are mutually exclusive",
            ));
        }
        let internal_service_token = secret_value(&values, "GRPC_SERVICE_TOKEN")?
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty());
        if issuer_sign_key
            .as_ref()
            .is_some_and(|key| internal_service_token.as_ref() == Some(key))
        {
            return Err(MmfError::new(
                ErrorCode::Configuration,
                "SIGNING_KEYS_ISSUER_SIGN_KEY must differ from GRPC_SERVICE_TOKEN",
            ));
        }
        if passport_native.internal_service_auth_enabled
            && internal_service_token
                .as_deref()
                .is_none_or(|token| token.len() < 32 || token.starts_with("dev-"))
        {
            return Err(MmfError::new(
                ErrorCode::Configuration,
                "GRPC_SERVICE_TOKEN is required for internal passport authentication",
            ));
        }
        let environment = values
            .get("ENVIRONMENT")
            .or_else(|| values.get("APP_ENV"))
            .map_or("development", String::as_str)
            .trim()
            .to_ascii_lowercase();
        let workload_server_tls = issuance_workload_server_tls(
            &values,
            settings.server.grpc_enabled,
            matches!(environment.as_str(), "production" | "prod" | "beta"),
        )?;
        let managed_authority_https =
            marty_service_runtime::https::ManagedAuthorityHttpsConfig::from_values(|name| {
                values.get(name).map(String::as_str)
            })
            .map_err(|message| MmfError::new(ErrorCode::Configuration, message))?;
        if let Some(https) = &managed_authority_https {
            if https.address == http_addr
                || (settings.server.grpc_enabled && https.address == grpc_addr)
                || issuance_api_key
                    .as_ref()
                    .is_none_or(|key| key.trim().is_empty())
            {
                return Err(MmfError::new(
                    ErrorCode::Configuration,
                    "managed authority HTTPS requires a distinct listener and ISSUANCE_API_KEY",
                ));
            }
        }
        let external_observations_enabled =
            environment_flag(&values, "MARTY_EXTERNAL_OBSERVATIONS_ENABLED");
        let application_ownership_enabled =
            environment_flag(&values, "MARTY_APPLICATION_OWNERSHIP_ENABLED");
        let external_associations_enabled =
            environment_flag(&values, "MARTY_EXTERNAL_ASSOCIATIONS_ENABLED");
        let external_association_database_url = values
            .get("ISSUANCE_EXTERNAL_ASSOCIATION_DATABASE_URL")
            .map(|value| {
                validate_observation_database_url(value).map_err(|_| {
                    MmfError::new(
                        ErrorCode::Configuration,
                        "Invalid separate Core association database configuration",
                    )
                })
            })
            .transpose()?;
        if external_associations_enabled
            && (issuance_api_key.is_none() || external_association_database_url.is_none())
        {
            return Err(MmfError::new(ErrorCode::Configuration,"Association activation requires Gateway service authentication and separate Core database credentials"));
        }
        if application_ownership_enabled && issuance_api_key.is_none() {
            return Err(MmfError::new(
                ErrorCode::Configuration,
                "Ownership Gateway service credential is required",
            ));
        }
        let external_observation_database_url = values
            .get("ISSUANCE_EXTERNAL_OBSERVATION_DATABASE_URL")
            .map(|value| validate_observation_database_url(value))
            .transpose()?;
        if external_observations_enabled && external_observation_database_url.is_none() {
            return Err(MmfError::new(
                ErrorCode::Configuration,
                "Separate Core observation database credentials are required",
            ));
        }
        Ok(Self {
            http_addr,
            grpc_addr,
            grpc_enabled: settings.server.grpc_enabled,
            workload_server_tls,
            managed_authority_https,
            release_version: settings.build.release_version,
            build_revision: settings.build.revision,
            issuer_base_url,
            allowed_redirect_uris,
            issuance_offer_ttl_minutes,
            authorization_session_ttl_minutes,
            issuer_display_name: settings.discovery.issuer_display_name,
            cors_allowed_origins: settings.server.cors_allowed_origins,
            database_url,
            token_hmac_key,
            issuance_api_key,
            external_observations_enabled,
            application_ownership_enabled,
            external_associations_enabled,
            external_association_database_url,
            external_observation_database_url,
            passport_tenant_keys,
            passport_native,
            signing_keys_internal_url,
            signing_keys_internal_api_key,
            integration_secret_api_key,
            issuer_sign_key,
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
            dependency_timeout: Duration::from_secs(10),
            token_rate_limit: parse_python_integer_setting(
                "TOKEN_RATE_LIMIT",
                &settings.rate_limit.requests,
            )?,
            token_rate_window: parse_python_integer_setting(
                "TOKEN_RATE_WINDOW",
                &settings.rate_limit.window_seconds,
            )?,
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
    if let Some(port) = values.get("ISSUANCE_GRPC_PORT") {
        let parsed = port.parse::<u16>().map_err(|error| {
            MmfError::new(
                ErrorCode::Configuration,
                "ISSUANCE_GRPC_PORT must be a valid TCP port",
            )
            .with_detail("cause", error.to_string())
        })?;
        server.insert("grpc_port".to_owned(), json!(parsed));
    }
    if values.contains_key("ISSUANCE_GRPC_ENABLED") {
        server.insert(
            "grpc_enabled".to_owned(),
            json!(environment_flag(values, "ISSUANCE_GRPC_ENABLED")),
        );
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
    if let Some(value) = values.get("ISSUANCE_OFFER_TTL_MINUTES") {
        initiation.insert("offer_ttl_minutes".to_owned(), json!(value));
    }
    let mut authorization = Map::new();
    if let Some(value) = values.get("ISSUANCE_AUTH_SESSION_TTL_MINUTES") {
        authorization.insert("session_ttl_minutes".to_owned(), json!(value));
    }
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
        rate_limit.insert("requests".to_owned(), json!(requests));
    }
    if let Some(window_seconds) = values.get("TOKEN_RATE_WINDOW") {
        rate_limit.insert("window_seconds".to_owned(), json!(window_seconds));
    }
    Ok(json!({
        "server": server,
        "build": build,
        "discovery": discovery,
        "dependencies": dependencies,
        "initiation": initiation,
        "authorization": authorization,
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

fn parse_python_integer_setting(
    name: &str,
    value: &Value,
) -> Result<PythonConfigInteger, MmfError> {
    value
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| value.to_string())
        .parse()
        .map_err(|_| {
            MmfError::new(
                ErrorCode::Configuration,
                format!("{name} must be a Python-compatible integer"),
            )
        })
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

fn issuance_workload_server_tls(
    values: &BTreeMap<String, String>,
    grpc_enabled: bool,
    deployed: bool,
) -> Result<Option<IssuanceWorkloadServerTlsFiles>, MmfError> {
    IssuanceWorkloadServerTlsFiles::from_values(
        |name| values.get(name).map(String::as_str),
        marty_service_runtime::TlsIdentityNames::new("GRPC_WORKLOAD_TLS_SERVER"),
        "GRPC_WORKLOAD_TLS_CA_CERT",
        (deployed && grpc_enabled)
            || optional_environment_value(values, "GRPC_WORKLOAD_TLS_CA_CERT").is_some(),
        std::time::Duration::from_secs(10),
        64,
    )
    .map_err(|error| {
        MmfError::new(
            ErrorCode::Configuration,
            format!("Issuance requires a complete remote TLS identity: {error}"),
        )
    })
}

fn optional_environment_value(values: &BTreeMap<String, String>, name: &str) -> Option<String> {
    optional_trimmed(values.get(name).cloned())
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

fn validate_observation_database_url(value: &str) -> Result<String, MmfError> {
    let normalized = value.replacen("postgresql+asyncpg://", "postgresql://", 1);
    let valid = value == value.trim()
        && !value.chars().any(char::is_control)
        && url::Url::parse(&normalized).is_ok_and(|parsed| {
            matches!(parsed.scheme(), "postgres" | "postgresql")
                && parsed.host_str().is_some()
                && !parsed.username().is_empty()
                && !parsed.path().trim_matches('/').is_empty()
        });
    if !valid {
        // Never include the URL, parse cause or credentials in configuration errors.
        return Err(MmfError::new(
            ErrorCode::Configuration,
            "ISSUANCE_EXTERNAL_OBSERVATION_DATABASE_URL must be a valid PostgreSQL URL",
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

fn has_placeholder_prefix(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    [
        "change-me",
        "change_me",
        "changeme",
        "replace-me",
        "replace_me",
    ]
    .iter()
    .any(|prefix| normalized.starts_with(prefix))
}

fn validate_grpc_service_token(token: Option<&str>, grpc_enabled: bool) -> Result<(), MmfError> {
    if !grpc_enabled {
        return Ok(());
    }
    let token = token.ok_or_else(|| {
        MmfError::new(
            ErrorCode::Configuration,
            "GRPC_SERVICE_TOKEN is required when gRPC is enabled",
        )
    })?;
    if has_placeholder_prefix(token) {
        return Err(MmfError::new(
            ErrorCode::Configuration,
            "GRPC_SERVICE_TOKEN must not be a placeholder",
        ));
    }
    if token.chars().count() < 32 {
        return Err(MmfError::new(
            ErrorCode::Configuration,
            "GRPC_SERVICE_TOKEN must contain at least 32 characters",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use mmf_core::ErrorCode;

    use super::{validate_grpc_service_token, IssuanceServiceConfig, PassportNativeConfig};

    #[test]
    fn production_passport_refuses_beta_simulator_without_qualifying_an_external_provider() {
        let contract: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../contracts/passport-production-bureau-boundary.json"
        )))
        .unwrap();
        assert!(contract["external_provider_receipt"].is_null());
        for case in contract["cases"].as_array().unwrap() {
            let values = std::collections::BTreeMap::from([
                (
                    "ENVIRONMENT".into(),
                    case["environment"].as_str().unwrap().into(),
                ),
                (
                    "PASSPORT_NATIVE_HTTP_ENABLED".into(),
                    case["native_enabled"]
                        .as_bool()
                        .map_or("true", |enabled| if enabled { "true" } else { "false" })
                        .into(),
                ),
                (
                    "PERSONALIZATION_BUREAU_URL".into(),
                    case["url"].as_str().unwrap().into(),
                ),
            ]);
            let result = PassportNativeConfig::from_values(&values, true);
            assert_eq!(
                result.is_ok(),
                case["accepted"].as_bool().unwrap(),
                "{case}"
            );
        }
    }

    fn values(entries: &[(&str, &str)]) -> Vec<(String, String)> {
        entries
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    fn remote_server_tls_values() -> Vec<(String, String)> {
        values(&[
            ("GRPC_WORKLOAD_TLS_SERVER_CERT", "issuance-public.pem"),
            ("GRPC_WORKLOAD_TLS_CA_CERT", "workload-public-ca.pem"),
            ("GRPC_WORKLOAD_TLS_SERVER_KMS_ADDR", "https://bao:8200"),
            ("GRPC_WORKLOAD_TLS_SERVER_KMS_CA_CERT", "bao-public-ca.pem"),
            ("GRPC_WORKLOAD_TLS_SERVER_KMS_TOKEN_FILE", "scoped-token"),
            ("GRPC_WORKLOAD_TLS_SERVER_KMS_KEY_NAME", "issuance-server"),
            ("GRPC_WORKLOAD_TLS_SERVER_KMS_KEY_VERSION", "1"),
        ])
    }

    #[test]
    fn deployed_grpc_requires_remote_tls_and_rejects_private_key_files() {
        let deployed = values(&[("ENVIRONMENT", "beta")]);
        assert!(IssuanceServiceConfig::from_values(deployed.clone())
            .unwrap_err()
            .to_string()
            .contains("complete remote TLS identity"));
        let mut configured = deployed;
        configured.extend(remote_server_tls_values());
        assert!(IssuanceServiceConfig::from_values(configured.clone())
            .unwrap()
            .workload_server_tls
            .is_some());
        configured.push(("GRPC_WORKLOAD_TLS_SERVER_KEY".into(), "private.pem".into()));
        assert!(IssuanceServiceConfig::from_values(configured)
            .unwrap_err()
            .to_string()
            .contains("private-key files are retired"));
    }

    #[test]
    fn defaults_preserve_the_legacy_listener() {
        let config = IssuanceServiceConfig::from_values(std::iter::empty::<(String, String)>())
            .expect("defaults");
        assert_eq!(config.http_addr.to_string(), "0.0.0.0:8005");
        assert_eq!(config.grpc_addr.to_string(), "0.0.0.0:9005");
        assert!(config.grpc_enabled);
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
        assert!(config.passport_tenant_keys.is_none());
        assert!(config.token_hmac_key.is_none());
        assert_eq!(config.token_rate_limit.as_decimal(), "30");
        assert_eq!(config.token_rate_window.as_decimal(), "60");
    }

    #[test]
    fn passport_tenant_keys_are_validated_and_redacted() {
        let secret = "a".repeat(32);
        let json = format!("{{\"org-1\":\"{secret}\"}}");
        let config =
            IssuanceServiceConfig::from_values(vec![("PASSPORT_TENANT_API_KEYS".to_owned(), json)])
                .expect("valid tenant keys");
        assert_eq!(
            config
                .passport_tenant_keys
                .as_ref()
                .unwrap()
                .key_for("org-1"),
            Some(secret.as_str())
        );
        assert!(!format!("{config:?}").contains(&secret));

        let error = IssuanceServiceConfig::from_values(values(&[(
            "PASSPORT_TENANT_API_KEYS",
            "{\"org-1\":\"weak\"}",
        )]))
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::Configuration);
        assert!(!error.to_string().contains("weak"));
    }

    #[test]
    fn native_passport_is_default_off_and_requires_tenant_auth_with_redacted_configuration() {
        let config = IssuanceServiceConfig::from_values(Vec::new()).unwrap();
        assert!(!config.passport_native.enabled);
        assert!(!config.passport_native.managed_issuer_signing_enabled);
        assert!(!config.passport_native.kms_artifacts_enabled);
        assert!(!config.passport_native.kms_callbacks_enabled);
        let forbidden = IssuanceServiceConfig::from_values(values(&[(
            "PHYSICAL_DOCUMENT_ARTIFACT_KEY_FILE",
            "nonexistent-passport-key-file",
        )]))
        .unwrap_err();
        assert!(forbidden
            .to_string()
            .contains("local passport artifact-key configuration is forbidden"));

        let error =
            IssuanceServiceConfig::from_values(values(&[("PASSPORT_NATIVE_HTTP_ENABLED", "true")]))
                .unwrap_err();
        assert_eq!(error.code, ErrorCode::Configuration);
        assert!(error.to_string().contains("PASSPORT_TENANT_API_KEYS"));

        let secret = "a".repeat(32);
        let complete = values(&[
            ("PASSPORT_NATIVE_HTTP_ENABLED", "true"),
            ("PASSPORT_KMS_ARTIFACTS_ENABLED", "true"),
            (
                "PASSPORT_TENANT_API_KEYS",
                &format!("{{\"org-a\":\"{secret}\"}}"),
            ),
            ("PERSONALIZATION_BUREAU_URL", "https://bureau.example.test"),
            ("PERSONALIZATION_BUREAU_API_KEY", "bureau-secret"),
            (
                "PERSONALIZATION_BUREAU_PROVIDER_PROFILE_ID",
                "provider-reference",
            ),
        ]);
        let config = IssuanceServiceConfig::from_values(complete.clone()).unwrap();
        assert!(config.passport_native.enabled);
        assert_eq!(
            config.passport_native.bureau_provider_profile_id.as_deref(),
            Some("provider-reference")
        );
        let debug = format!("{config:?}");
        for secret in [&secret[..], "bureau-secret"] {
            assert!(!debug.contains(secret));
        }
        for name in [
            "PASSPORT_KMS_ARTIFACTS_ENABLED",
            "PERSONALIZATION_BUREAU_URL",
        ] {
            let missing = complete
                .iter()
                .filter(|(key, _)| key != name)
                .cloned()
                .collect::<Vec<_>>();
            let degraded = IssuanceServiceConfig::from_values(missing).unwrap();
            assert!(degraded.passport_native.enabled, "missing provider: {name}");
        }
        let anonymous_providers = complete
            .into_iter()
            .filter(|(name, _)| !["PERSONALIZATION_BUREAU_API_KEY"].contains(&name.as_str()))
            .collect::<Vec<_>>();
        let anonymous = IssuanceServiceConfig::from_values(anonymous_providers).unwrap();
        assert!(anonymous.passport_native.enabled);
        assert!(anonymous.passport_native.bureau_api_key.is_none());

        let too_long = IssuanceServiceConfig::from_values(values(&[
            ("PASSPORT_NATIVE_HTTP_ENABLED", "true"),
            (
                "PASSPORT_TENANT_API_KEYS",
                &format!("{{\"org-a\":\"{secret}\"}}"),
            ),
            (
                "PERSONALIZATION_BUREAU_PROVIDER_PROFILE_ID",
                &"p".repeat(129),
            ),
        ]));
        assert!(too_long.is_err());

        let mut kms_bureau = values(&[
            ("PASSPORT_NATIVE_HTTP_ENABLED", "true"),
            ("PASSPORT_KMS_CALLBACKS_ENABLED", "true"),
            (
                "PASSPORT_TENANT_API_KEYS",
                &format!("{{\"org-a\":\"{secret}\"}}"),
            ),
            ("PERSONALIZATION_BUREAU_URL", "https://bureau.example.test"),
        ]);
        let missing_profile = IssuanceServiceConfig::from_values(kms_bureau.clone()).unwrap_err();
        assert_eq!(missing_profile.code, ErrorCode::Configuration);
        assert!(missing_profile
            .to_string()
            .contains("PERSONALIZATION_BUREAU_PROVIDER_PROFILE_ID"));
        kms_bureau.push((
            "PERSONALIZATION_BUREAU_PROVIDER_PROFILE_ID".into(),
            "provider-reference".into(),
        ));
        assert!(IssuanceServiceConfig::from_values(kms_bureau).is_ok());
    }

    #[test]
    fn beta_passport_reconciliation_requires_exact_internal_profile_and_kms() {
        let mut beta = values(&[
            ("ENVIRONMENT", "beta"),
            ("PASSPORT_NATIVE_HTTP_ENABLED", "true"),
            ("PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED", "true"),
            ("PASSPORT_MANAGED_ISSUER_SIGNING_ENABLED", "true"),
            ("PASSPORT_KMS_ARTIFACTS_ENABLED", "true"),
            ("PASSPORT_KMS_CALLBACKS_ENABLED", "true"),
            ("PASSPORT_BETA_RECONCILIATION_ENABLED", "true"),
            (
                "PASSPORT_BETA_RECONCILIATION_OPERATOR_TOKEN",
                "synthetic-reconciliation-operator-token-00000001",
            ),
            (
                "GRPC_SERVICE_TOKEN",
                "synthetic-internal-passport-token-00000001",
            ),
            (
                "PERSONALIZATION_BUREAU_URL",
                "http://passport-beta-bureau:8020",
            ),
            (
                "PERSONALIZATION_BUREAU_PROVIDER_PROFILE_ID",
                "passport-beta-bureau",
            ),
        ]);
        beta.extend(remote_server_tls_values());
        assert!(
            IssuanceServiceConfig::from_values(beta.clone())
                .unwrap()
                .passport_native
                .beta_reconciliation_enabled
        );
        for (name, replacement) in [
            ("ENVIRONMENT", "production"),
            ("PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED", "false"),
            ("PASSPORT_KMS_ARTIFACTS_ENABLED", "false"),
            ("PERSONALIZATION_BUREAU_URL", "https://bureau.example.test"),
            (
                "PERSONALIZATION_BUREAU_PROVIDER_PROFILE_ID",
                "other-profile",
            ),
        ] {
            let replaced = beta
                .iter()
                .map(|(key, value)| {
                    (
                        key.clone(),
                        if key == name {
                            replacement.to_owned()
                        } else {
                            value.clone()
                        },
                    )
                })
                .collect::<Vec<_>>();
            assert!(
                IssuanceServiceConfig::from_values(replaced).is_err(),
                "{name}"
            );
        }
        beta.retain(|(key, _)| key != "PASSPORT_BETA_RECONCILIATION_ENABLED");
        assert!(
            !IssuanceServiceConfig::from_values(beta)
                .unwrap()
                .passport_native
                .beta_reconciliation_enabled
        );
    }

    #[test]
    fn managed_passport_signing_is_explicit_and_excludes_legacy_signers() {
        let tenant_keys = format!("{{\"org-a\":\"{}\"}}", "a".repeat(32));
        let configured = values(&[
            ("PASSPORT_NATIVE_HTTP_ENABLED", "true"),
            ("PASSPORT_MANAGED_ISSUER_SIGNING_ENABLED", "true"),
            ("PASSPORT_TENANT_API_KEYS", &tenant_keys),
        ]);
        let config = IssuanceServiceConfig::from_values(configured.clone()).unwrap();
        assert!(config.passport_native.managed_issuer_signing_enabled);
        let mut conflicting = configured;
        conflicting.push((
            "ICAO_DOCUMENT_SIGNER_URL".into(),
            "https://signer.example.test".into(),
        ));
        assert!(IssuanceServiceConfig::from_values(conflicting)
            .unwrap_err()
            .to_string()
            .contains("external passport signer configuration is forbidden"));
        for name in [
            "ICAO_DOCUMENT_SIGNER_API_KEY",
            "ICAO_DOCUMENT_SIGNER_API_KEY_FILE",
        ] {
            let mut disabled = values(&[]);
            disabled.push((name.into(), String::new()));
            assert!(IssuanceServiceConfig::from_values(disabled)
                .unwrap_err()
                .to_string()
                .contains("external passport signer configuration is forbidden"));
        }
    }

    #[test]
    fn internal_passport_auth_rejects_a_keyring_file_before_loading_it() {
        let token = "s".repeat(32);
        let mut values = values(&[
            ("PASSPORT_NATIVE_HTTP_ENABLED", "true"),
            ("PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED", "true"),
            ("GRPC_SERVICE_TOKEN", &token),
        ]);
        let config = IssuanceServiceConfig::from_values(values.clone()).unwrap();
        assert!(config.passport_native.internal_service_auth_enabled);
        assert!(config.passport_tenant_keys.is_none());
        values.push((
            "PASSPORT_TENANT_API_KEYS_FILE".into(),
            "nonexistent-keyring".into(),
        ));
        let error = IssuanceServiceConfig::from_values(values).unwrap_err();
        assert!(error.to_string().contains("cannot be combined"));
    }

    #[test]
    fn kms_artifact_mode_is_explicit_and_rejects_a_raw_or_file_key_before_loading() {
        let tenant_keys = format!("{{\"org-a\":\"{}\"}}", "a".repeat(32));
        let values = values(&[
            ("PASSPORT_NATIVE_HTTP_ENABLED", "true"),
            ("PASSPORT_KMS_ARTIFACTS_ENABLED", "true"),
            ("PASSPORT_TENANT_API_KEYS", &tenant_keys),
        ]);
        let config = IssuanceServiceConfig::from_values(values.clone()).unwrap();
        assert!(config.passport_native.kms_artifacts_enabled);
        for (name, value) in [
            ("PHYSICAL_DOCUMENT_ARTIFACT_KEY", "must-never-enter-process"),
            ("PHYSICAL_DOCUMENT_ARTIFACT_KEY", ""),
            (
                "PHYSICAL_DOCUMENT_ARTIFACT_KEY_FILE",
                "nonexistent-passport-key-file",
            ),
            ("PHYSICAL_DOCUMENT_ARTIFACT_KEY_FILE", ""),
        ] {
            let mut conflicting = values.clone();
            conflicting.push((name.into(), value.into()));
            let error = IssuanceServiceConfig::from_values(conflicting).unwrap_err();
            assert_eq!(error.code, ErrorCode::Configuration);
            assert!(error
                .to_string()
                .contains("artifact-key configuration is forbidden"));
            if !value.is_empty() {
                assert!(!error.to_string().contains(value));
            }
        }
    }

    #[test]
    fn kms_callback_mode_rejects_process_held_secret_before_loading_it() {
        let keyring = format!("{{\"org-a\":\"{}\"}}", "a".repeat(32));
        let values = values(&[
            ("PASSPORT_NATIVE_HTTP_ENABLED", "true"),
            ("PASSPORT_KMS_CALLBACKS_ENABLED", "true"),
            ("PASSPORT_TENANT_API_KEYS", &keyring),
        ]);
        let config = IssuanceServiceConfig::from_values(values.clone()).unwrap();
        assert!(config.passport_native.kms_callbacks_enabled);
        for (name, value) in [
            ("PERSONALIZATION_BUREAU_WEBHOOK_SECRET", "must-never-load"),
            ("PERSONALIZATION_BUREAU_WEBHOOK_SECRET", ""),
            (
                "PERSONALIZATION_BUREAU_WEBHOOK_SECRET_FILE",
                "nonexistent-webhook-key-file",
            ),
            ("PERSONALIZATION_BUREAU_WEBHOOK_SECRET_FILE", ""),
        ] {
            let mut conflicting = values.clone();
            conflicting.push((name.into(), value.into()));
            let error = IssuanceServiceConfig::from_values(conflicting).unwrap_err();
            assert_eq!(error.code, ErrorCode::Configuration);
            assert!(error
                .to_string()
                .contains("callback-secret configuration is forbidden"));
            if !value.is_empty() {
                assert!(!error.to_string().contains(value));
            }
        }
    }

    #[test]
    fn disabled_passport_rejects_retired_local_key_selectors() {
        for name in [
            "PHYSICAL_DOCUMENT_ARTIFACT_KEY",
            "PHYSICAL_DOCUMENT_ARTIFACT_KEY_FILE",
            "PERSONALIZATION_BUREAU_WEBHOOK_SECRET",
            "PERSONALIZATION_BUREAU_WEBHOOK_SECRET_FILE",
        ] {
            let error = IssuanceServiceConfig::from_values(values(&[(name, "")])).unwrap_err();
            assert_eq!(error.code, ErrorCode::Configuration, "{name}");
        }
    }

    #[test]
    fn native_passport_does_not_claim_unimplemented_self_signed_test_parity() {
        let error = IssuanceServiceConfig::from_values(values(&[
            ("PASSPORT_NATIVE_HTTP_ENABLED", "true"),
            ("PHYSICAL_DOCUMENT_ALLOW_SELF_SIGNED", "true"),
        ]))
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::Configuration);
        assert!(error
            .to_string()
            .contains("self-signed passport signing is forbidden"));
    }

    #[test]
    fn hierarchical_configuration_overrides_the_legacy_adapter() {
        let config = IssuanceServiceConfig::from_values(values(&[
            ("ISSUANCE_SERVICE_PORT", "8006"),
            ("ISSUANCE_GRPC_PORT", "9006"),
            ("ISSUANCE_GRPC_ENABLED", "false"),
            ("MARTY_RELEASE_VERSION", "1.2.3"),
            ("MARTY_UI_SHA", "abc123"),
            ("MARTY_ISSUANCE__SERVER__HOST", "127.0.0.1"),
            ("MARTY_ISSUANCE__SERVER__PORT", "8010"),
            ("MARTY_ISSUANCE__SERVER__GRPC_PORT", "9010"),
            ("MARTY_ISSUANCE__SERVER__GRPC_ENABLED", "true"),
            ("ISSUER_BASE_URL", "https://legacy.example/"),
            ("ISSUER_DISPLAY_NAME", "Legacy Issuer"),
            (
                "ALLOWED_REDIRECT_URIS",
                " https://wallet.example/callback, http://localhost:3000/callback , ,",
            ),
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
        ]))
        .expect("configuration");
        assert_eq!(config.http_addr.to_string(), "127.0.0.1:8010");
        assert_eq!(config.grpc_addr.to_string(), "127.0.0.1:9010");
        assert!(config.grpc_enabled);
        assert_eq!(config.release_version, "1.2.3");
        assert_eq!(config.build_revision, "abc123");
        assert_eq!(config.issuer_base_url, "https://issuer.example");
        assert_eq!(config.issuer_display_name, "Example Issuer");
        assert_eq!(
            config.allowed_redirect_uris,
            [
                "https://wallet.example/callback",
                "http://localhost:3000/callback"
            ]
        );
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
        assert_eq!(config.token_rate_limit.as_decimal(), "12");
        assert_eq!(config.token_rate_window.as_decimal(), "45");

        let diagnostic = format!("{config:?}");
        assert!(!diagnostic.contains("preferred-key"));
        assert!(!diagnostic.contains("fallback-key"));
        assert!(!diagnostic.contains("token-hmac-contract-key"));
        assert!(!diagnostic.contains("user:pass"));
        assert!(!diagnostic.contains("wallet.example/callback"));
        assert!(diagnostic.contains("allowed_redirect_uri_count: 2"));
    }

    #[test]
    fn empty_allowed_redirect_uri_input_preserves_unconfigured_semantics() {
        let config =
            IssuanceServiceConfig::from_values(values(&[("ALLOWED_REDIRECT_URIS", " , , ")]))
                .expect("empty redirect allowlist");
        assert!(config.allowed_redirect_uris.is_empty());
    }

    #[test]
    fn invalid_legacy_port_fails_closed() {
        for name in ["ISSUANCE_SERVICE_PORT", "ISSUANCE_GRPC_PORT"] {
            let error = IssuanceServiceConfig::from_values(values(&[(name, "not-a-port")]))
                .expect_err("invalid port");
            assert_eq!(error.code, ErrorCode::Configuration);
        }
    }

    #[test]
    fn legacy_grpc_listener_switch_preserves_python_boolean_semantics() {
        for disabled in ["false", "0", "no", "unexpected"] {
            let config =
                IssuanceServiceConfig::from_values(values(&[("ISSUANCE_GRPC_ENABLED", disabled)]))
                    .expect("disabled gRPC listener");
            assert!(!config.grpc_enabled, "{disabled}");
        }
        for enabled in ["true", "1", "yes", "TRUE"] {
            let config =
                IssuanceServiceConfig::from_values(values(&[("ISSUANCE_GRPC_ENABLED", enabled)]))
                    .expect("enabled gRPC listener");
            assert!(config.grpc_enabled, "{enabled}");
        }
    }

    #[test]
    fn grpc_service_token_configuration_fails_closed_when_listener_enabled() {
        let conflict = IssuanceServiceConfig::from_values(values(&[
            ("GRPC_SERVICE_TOKEN", "direct-token"),
            ("GRPC_SERVICE_TOKEN_FILE", "mounted-token"),
        ]))
        .expect_err("one service-token source is required");
        assert_eq!(conflict.code, ErrorCode::Configuration);

        for token in [
            "change-me-production-token-that-is-long-enough",
            "too-short",
        ] {
            assert_eq!(
                validate_grpc_service_token(Some(token), true)
                    .expect_err("weak service token")
                    .code,
                ErrorCode::Configuration
            );
        }
        assert!(validate_grpc_service_token(
            Some("production-service-token-with-at-least-32-bytes"),
            true
        )
        .is_ok());
        assert_eq!(
            validate_grpc_service_token(None, true)
                .expect_err("enabled gRPC requires a service token")
                .code,
            ErrorCode::Configuration
        );
        assert!(validate_grpc_service_token(None, false).is_ok());
    }

    #[test]
    fn integration_secret_api_key_rejects_placeholder_when_grpc_is_disabled() {
        let error = IssuanceServiceConfig::from_values(values(&[
            ("ISSUANCE_GRPC_ENABLED", "false"),
            (
                "SIGNING_KEYS_INTEGRATION_SECRET_KEY",
                "change-me-synthetic-placeholder-integration-key",
            ),
        ]))
        .expect_err("placeholder integration secret key must fail independently of gRPC");
        assert_eq!(error.code, ErrorCode::Configuration);
        assert!(error
            .message
            .contains("SIGNING_KEYS_INTEGRATION_SECRET_KEY"));
    }

    #[test]
    fn invalid_legacy_rate_limit_fails_closed() {
        for (name, value) in [("TOKEN_RATE_LIMIT", "1__0"), ("TOKEN_RATE_WINDOW", "later")] {
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
    fn initiation_offer_ttl_preserves_frozen_python_startup_grammar_and_width() {
        let frozen: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../contracts/initiation-offer-ttl-python-reference.json"
        ))
        .unwrap();
        let cases = frozen["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 18);
        for case in cases {
            let mut configured = std::collections::BTreeMap::new();
            if let Some(raw) = case["raw"].as_str() {
                configured.insert("ISSUANCE_OFFER_TTL_MINUTES".to_owned(), raw.to_owned());
            }
            let result = IssuanceServiceConfig::from_values(configured);
            if case["phase"] == "module-import" {
                assert!(result.is_err(), "{}", case["case"]);
            } else {
                assert_eq!(
                    result.unwrap().issuance_offer_ttl_minutes.as_decimal(),
                    case["parsed_minutes"]
                );
            }
        }
        let layered = IssuanceServiceConfig::from_values(values(&[
            ("ISSUANCE_OFFER_TTL_MINUTES", "45"),
            ("MARTY_ISSUANCE__INITIATION__OFFER_TTL_MINUTES", "90"),
        ]))
        .unwrap();
        assert_eq!(layered.issuance_offer_ttl_minutes.to_i64(), Some(90));
    }

    #[test]
    fn authorization_session_ttl_preserves_python_configuration() {
        let default = IssuanceServiceConfig::from_values(values(&[])).unwrap();
        assert_eq!(default.authorization_session_ttl_minutes.to_i64(), Some(60));

        let legacy = IssuanceServiceConfig::from_values(values(&[(
            "ISSUANCE_AUTH_SESSION_TTL_MINUTES",
            "75",
        )]))
        .unwrap();
        assert_eq!(legacy.authorization_session_ttl_minutes.to_i64(), Some(75));

        let layered = IssuanceServiceConfig::from_values(values(&[
            ("ISSUANCE_AUTH_SESSION_TTL_MINUTES", "75"),
            ("MARTY_ISSUANCE__AUTHORIZATION__SESSION_TTL_MINUTES", "90"),
        ]))
        .unwrap();
        assert_eq!(layered.authorization_session_ttl_minutes.to_i64(), Some(90));

        let negative = IssuanceServiceConfig::from_values(values(&[(
            "ISSUANCE_AUTH_SESSION_TTL_MINUTES",
            "-1",
        )]))
        .unwrap();
        assert_eq!(
            negative.authorization_session_ttl_minutes.to_i64(),
            Some(-1)
        );

        assert!(IssuanceServiceConfig::from_values(values(&[(
            "ISSUANCE_AUTH_SESSION_TTL_MINUTES",
            "not-an-integer"
        ),]))
        .is_err());
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

#[test]
fn observation_ingress_requires_explicit_activation_configuration() {
    assert!(
        !IssuanceServiceConfig::from_values(Vec::<(String, String)>::new())
            .unwrap()
            .external_observations_enabled
    );
    assert!(IssuanceServiceConfig::from_values(vec![(
        "MARTY_EXTERNAL_OBSERVATIONS_ENABLED".into(),
        "true".into()
    )])
    .is_err());
    let secret = "synthetic-isolated-role-password";
    let url = format!("postgresql://observation:{secret}@127.0.0.1:5432/core_database");
    let config = IssuanceServiceConfig::from_values(vec![
        ("MARTY_EXTERNAL_OBSERVATIONS_ENABLED".into(), "true".into()),
        (
            "ISSUANCE_EXTERNAL_OBSERVATION_DATABASE_URL".into(),
            url.clone(),
        ),
    ])
    .unwrap();
    assert!(config.external_observations_enabled);
    assert_eq!(
        config.external_observation_database_url.as_deref(),
        Some(url.as_str())
    );
    assert!(!format!("{config:?}").contains(secret));
    for invalid in [
        "https://user:synthetic-secret@example.test/db",
        "postgresql://",
        "postgresql://host/db",
        "postgresql://user:synthetic-secret@host/",
    ] {
        let error = validate_observation_database_url(invalid).unwrap_err();
        assert!(!format!("{error:?}").contains("synthetic-secret"));
    }
}
#[test]
fn application_ownership_requires_explicit_activation_and_service_authentication() {
    assert!(
        !IssuanceServiceConfig::from_values(Vec::<(String, String)>::new())
            .unwrap()
            .application_ownership_enabled
    );
    assert!(IssuanceServiceConfig::from_values(vec![(
        "MARTY_APPLICATION_OWNERSHIP_ENABLED".into(),
        "true".into()
    )])
    .is_err());
    let config = IssuanceServiceConfig::from_values(vec![
        ("MARTY_APPLICATION_OWNERSHIP_ENABLED".into(), "true".into()),
        (
            "ISSUANCE_API_KEY".into(),
            "synthetic-ownership-service-key-000000000001".into(),
        ),
    ])
    .unwrap();
    assert!(config.application_ownership_enabled);
    assert!(!config.external_observations_enabled);
}

#[test]
fn external_association_activation_requires_isolated_credentials_and_redacts_them() {
    let default = IssuanceServiceConfig::from_values(Vec::<(String, String)>::new()).unwrap();
    assert!(!default.external_associations_enabled);
    for values in [
        vec![("MARTY_EXTERNAL_ASSOCIATIONS_ENABLED".into(), "true".into())],
        vec![
            ("MARTY_EXTERNAL_ASSOCIATIONS_ENABLED".into(), "true".into()),
            (
                "ISSUANCE_API_KEY".into(),
                "synthetic-service-key-000000000001".into(),
            ),
        ],
    ] {
        assert!(IssuanceServiceConfig::from_values(values).is_err());
    }
    let config = IssuanceServiceConfig::from_values(vec![
        ("MARTY_EXTERNAL_ASSOCIATIONS_ENABLED".into(), "true".into()),
        (
            "ISSUANCE_API_KEY".into(),
            "synthetic-service-key-000000000001".into(),
        ),
        (
            "ISSUANCE_EXTERNAL_ASSOCIATION_DATABASE_URL".into(),
            "postgresql://association:synthetic-private-password@127.0.0.1/issuer".into(),
        ),
    ])
    .unwrap();
    assert!(config.external_associations_enabled);
    assert!(!format!("{config:?}").contains("synthetic-private-password"));
    let error = IssuanceServiceConfig::from_values(vec![(
        "ISSUANCE_EXTERNAL_ASSOCIATION_DATABASE_URL".into(),
        "invalid:synthetic-private-password".into(),
    )])
    .unwrap_err();
    assert!(!format!("{error:?}").contains("synthetic-private-password"));
}
