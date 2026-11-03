//! Typed, retained application policy for the native installer. This owner
//! never accepts generated identities, runtime paths, image references or raw
//! credentials as environment overrides. Optional credentials enter the same
//! immutable scalar-file custody as the installer's generated credentials.
#![cfg(target_os = "linux")]

use crate::{
    installer_application_env::OPTIONAL_INTEGRATION_SECRETS,
    installer_compose::ComposeInputs,
    installer_host_fs as fs,
    installer_state::{InstallerState, Journal, LockedInspection, Phase},
};
use marty_selfhost_identity::origin::PublicOrigin;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
};

type Result<T> = std::result::Result<T, String>;
const REFUSED: &str =
    "application settings are invalid, incomplete or changed; preserve installation evidence";
pub(crate) const SOURCE: &str = "application-settings-input.json";
pub(crate) const RECORD: &str = "application-settings-selection.json";
const SCHEMA: &str = "elevenid.installer-application-settings/v1";
const SELECTION_SCHEMA: &str = "elevenid.installer-application-settings-selection/v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    schema: String,
    #[serde(default)]
    values: BTreeMap<String, Value>,
    #[serde(default)]
    secret_files: BTreeMap<String, PathBuf>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Fingerprint {
    pub(crate) sha256: String,
    pub(crate) size_bytes: u64,
}

pub(crate) struct Prepared {
    raw: Vec<u8>,
    configuration: Configuration,
    managed_keycloak: bool,
    secrets: BTreeMap<String, Fingerprint>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Selection {
    schema: String,
    installation_id: uuid::Uuid,
    source_sha256: String,
    configuration: Configuration,
    managed_keycloak: bool,
    secrets: BTreeMap<String, Fingerprint>,
}

fn require(value: bool) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}

fn invalid(key: &str, expected: &str) -> String {
    // Names are fixed by the closed registry below; never print input values,
    // secret paths or parser errors containing user-controlled material.
    format!("application setting {key} requires {expected}")
}

fn digest(bytes: &[u8]) -> String {
    crate::installer_release::sha256(bytes)
}

fn fingerprint(bytes: &[u8]) -> Fingerprint {
    Fingerprint {
        sha256: digest(bytes),
        size_bytes: bytes.len() as u64,
    }
}

fn safe_path(path: &Path) -> bool {
    path.is_absolute()
        && path != Path::new("/")
        && path
            .components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
        && path.to_str().is_some_and(|text| {
            !text.ends_with('/')
                && !text
                    .chars()
                    .any(|c| c.is_control() || c == '\'' || c == '\\')
                && text
                    .split('/')
                    .skip(1)
                    .all(|p| !p.is_empty() && p != "." && p != "..")
        })
}

fn private_bytes(path: &Path) -> Result<Vec<u8>> {
    require(safe_path(path))?;
    let parent_path = path.parent().ok_or(REFUSED)?;
    let parent = fs::directory(parent_path, REFUSED)?;
    let name = path.file_name().and_then(|s| s.to_str()).ok_or(REFUSED)?;
    let bytes = fs::read_entry(&parent, name, 0o600, false, REFUSED)?;
    fs::require_directory_binding(parent_path, &parent, REFUSED)?;
    Ok(bytes)
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    require(!bytes.is_empty() && bytes.len() <= 65_536)?;
    serde_json::from_value(crate::installer_json::decode(bytes).map_err(|_| REFUSED)?)
        .map_err(|_| REFUSED.into())
}

fn scalar(value: &Value, key: &str, maximum: usize) -> Result<String> {
    let text = value.as_str().ok_or_else(|| invalid(key, "a string"))?;
    if text.len() > maximum
        || !text.is_ascii()
        || text
            .chars()
            .any(|c| c.is_control() || c == '\'' || c == '\\')
        || text.trim() != text
        || text.contains("PRIVATE KEY")
    {
        return Err(invalid(
            key,
            "a bounded ASCII value without control characters or shell quoting",
        ));
    }
    Ok(text.into())
}

fn https(text: &str, origin_only: bool) -> bool {
    url::Url::parse(text).is_ok_and(|url| {
        url.scheme() == "https"
            && url.has_host()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
            && (!origin_only
                || (url.query().is_none()
                    && url.path() == "/"
                    && text == url.origin().ascii_serialization()))
    })
}

fn identifier(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 128
        && text
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._:-".contains(&c))
}

fn list(value: &Value, key: &str, check: impl Fn(&str) -> bool) -> Result<String> {
    let items = value
        .as_array()
        .ok_or_else(|| invalid(key, "an array of strings"))?;
    if items.len() > 128 {
        return Err(invalid(key, "at most 128 unique entries"));
    }
    let mut unique = BTreeSet::new();
    let mut result = Vec::new();
    for item in items {
        let text = scalar(item, key, 2048)?;
        if text.is_empty() || text.contains(',') || !check(&text) || !unique.insert(text.clone()) {
            return Err(invalid(key, "unique entries of the documented type"));
        }
        result.push(text);
    }
    Ok(result.join(","))
}

fn string_value(
    value: &Value,
    key: &str,
    maximum: usize,
    check: impl Fn(&str) -> bool,
) -> Result<String> {
    let text = scalar(value, key, maximum)?;
    if !check(&text) {
        return Err(invalid(key, "the documented value format"));
    }
    Ok(text)
}

/// The registry is deliberately exhaustive. A newly interpolated Compose
/// setting is not automatically granted installation authority.
fn typed_value(key: &str, value: &Value) -> Result<String> {
    match key {
        "KEYCLOAK_USER_REGISTRATION_ENABLED"
        | "KEYCLOAK_VERIFY_EMAIL"
        | "KEYCLOAK_RESET_PASSWORD_ENABLED"
        | "KEYCLOAK_SOCIAL_LOGIN_ENABLED"
        | "KEYCLOAK_ORGANIZATION_IDENTITY_FIRST_ENABLED"
        | "KEYCLOAK_SMTP_SSL"
        | "KEYCLOAK_SMTP_STARTTLS"
        | "ORGANIZATION_CREATION_ENABLED"
        | "CREDENTIAL_LOGIN_REQUIRE_EXISTING_KEYCLOAK_USER"
        | "CREDENTIAL_LOGIN_CREATE_USERS"
        | "CANVAS_PORTABLE_INTEGRATION_ENABLED"
        | "CANVAS_MIRROR_WORKER_ENABLED"
        | "CANVAS_ALLOW_PRIVATE_BASE_URLS"
        | "CANVAS_ALLOW_HTTP_LOCALHOST_BASE_URLS"
        | "CANVAS_CREDENTIALS_RECIPIENT_HASHED"
        | "CANVAS_CREDENTIALS_ALLOW_DUPLICATE_AWARDS"
        | "CANVAS_MIRROR_WORKER_RETRY_FAILED"
        | "CANVAS_MIRROR_WORKER_RUN_ON_STARTUP"
        | "DID_PUBLIC_FALLBACK_ENABLED"
        | "PASSPORT_NATIVE_HTTP_ENABLED"
        | "PASSPORT_NATIVE_GATEWAY_ENABLED"
        | "PASSPORT_NATIVE_FLOW_ENABLED"
        | "PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED"
        | "PASSPORT_MANAGED_ISSUER_SIGNING_ENABLED"
        | "PASSPORT_KMS_ARTIFACTS_ENABLED"
        | "PASSPORT_KMS_CALLBACKS_ENABLED" => value
            .as_bool()
            .map(|v| v.to_string())
            .ok_or_else(|| invalid(key, "a JSON boolean")),
        "KEYCLOAK_SMTP_PORT" => number(value, key, 1, 65535),
        "RATE_LIMIT_RPM" => number(value, key, 1, 1_000_000),
        "ISSUANCE_OFFER_TTL_MINUTES" | "ISSUANCE_AUTH_SESSION_TTL_MINUTES" => {
            number(value, key, 1, 525_600)
        }
        "CANVAS_MIRROR_ALERT_WEBHOOK_TIMEOUT_SECONDS" => number(value, key, 1, 20),
        "CANVAS_BINDING_READINESS_MAX_AGE_SECONDS"
        | "CANVAS_ISSUANCE_EVIDENCE_MAX_AGE_SECONDS"
        | "CANVAS_MIRROR_PUBLISH_INTERVAL_SECONDS"
        | "CANVAS_MIRROR_STATUS_SYNC_INTERVAL_SECONDS"
        | "CANVAS_SYNC_WORKER_LEASE_SECONDS"
        | "CANVAS_SYNC_WORKER_JOB_TIMEOUT_SECONDS"
        | "CANVAS_SYNC_WORKER_POLL_SECONDS" => number(value, key, 1, 86_400),
        "CANVAS_MIRROR_WORKER_BATCH_LIMIT"
        | "CANVAS_MIRROR_FAILURE_WARNING_ATTEMPTS"
        | "CANVAS_MIRROR_FAILURE_CRITICAL_ATTEMPTS"
        | "CANVAS_BACKGROUND_ROSTER_BATCH_SIZE"
        | "CANVAS_BACKGROUND_ROSTER_MAX_SIZE"
        | "CANVAS_SYNC_WORKER_BATCH_SIZE"
        | "CANVAS_SYNC_SCHEDULE_LIMIT"
        | "CANVAS_OAUTH_REVOCATION_BATCH_SIZE" => number(value, key, 1, 1_000_000),
        "UI_ADDITIONAL_BASE_URLS"
        | "CANVAS_PRIVATE_ORIGIN_ALLOWLIST"
        | "CANVAS_SELF_MANAGED_ORIGIN_ALLOWLIST"
        | "CANVAS_CREDENTIALS_API_ORIGIN_ALLOWLIST" => list(value, key, |s| {
            https(s, true) && PublicOrigin::parse(s).is_ok()
        }),
        "CANVAS_PILOT_ORGANIZATION_IDS" | "CANVAS_CREDENTIAL_ISSUER_PROFILE_IDS" => {
            list(value, key, identifier)
        }
        "ALLOWED_REDIRECT_URIS" => list(value, key, |s| https(s, false)),
        "DID_WEB_ALLOWED_HOSTS" => list(value, key, hostname),
        "KEYCLOAK_SMTP_HOST" => string_value(value, key, 253, |s| s.is_empty() || hostname(s)),
        "KEYCLOAK_SMTP_FROM" => string_value(value, key, 254, |s| {
            s.is_empty()
                || s.split_once('@').is_some_and(|(local, host)| {
                    !local.is_empty()
                        && !local.contains('@')
                        && !local.contains(' ')
                        && hostname(host)
                })
        }),
        "KEYCLOAK_SMTP_USERNAME" | "KEYCLOAK_SMTP_FROM_DISPLAY_NAME" | "MARTY_ORG_NAME" => {
            scalar(value, key, 256)
        }
        "CREDENTIAL_LOGIN_POLICY_ID"
        | "CREDENTIAL_LOGIN_TRUST_PROFILE_ID"
        | "CANVAS_MIRROR_WORKER_ORGANIZATION_ID"
        | "CANVAS_LTI_TOOL_SIGNING_ORGANIZATION_ID"
        | "MARTY_DEFAULT_REVOCATION_PROFILE_ID" => {
            string_value(value, key, 128, |s| s.is_empty() || identifier(s))
        }
        "CANVAS_CREDENTIALS_API_BASE_URL"
        | "CANVAS_CREDENTIALS_PUBLISH_URL"
        | "CANVAS_CREDENTIALS_STATUS_SYNC_URL"
        | "CANVAS_LTI_EXPERIENCE_BASE_URL"
        | "CANVAS_OAUTH_COMPLETION_REDIRECT_URL"
        | "CANVAS_CREDENTIALS_PROVENANCE_BASE_URL"
        | "CANVAS_MIRROR_ALERT_WEBHOOK_URL"
        | "UNIVERSAL_RESOLVER_URL"
        | "PERSONALIZATION_BUREAU_URL" => {
            string_value(value, key, 2048, |s| s.is_empty() || https(s, false))
        }
        "CANVAS_CREDENTIALS_ASSERTION_URL_TEMPLATE" | "MIP_CREDENTIAL_STATUS_URL_TEMPLATE" => {
            string_value(value, key, 2048, |s| s.is_empty() || https(s, false))
        }
        "CANVAS_CREDENTIALS_ISSUER_ID"
        | "CANVAS_CREDENTIALS_BADGECLASS_ID"
        | "PERSONALIZATION_BUREAU_PROVIDER_PROFILE_ID" => string_value(value, key, 128, |s| {
            s.bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._:-".contains(&c))
        }),
        "CANVAS_CREDENTIALS_ASSERTION_NARRATIVE" => scalar(value, key, 2048),
        "CANVAS_LTI_TOOL_ISSUER_DID" | "CANVAS_LTI_TOOL_ACTIVE_KID" => {
            string_value(value, key, 2048, |s| {
                s.is_empty() || (s.starts_with("did:") && !s.contains(' '))
            })
        }
        "COOKIE_SAMESITE" => choice(value, key, &["lax", "strict", "none"]),
        "CANVAS_CREDENTIALS_PROVIDER" => choice(
            value,
            key,
            &["bridge", "badgr_api", "canvas_credentials_api"],
        ),
        "CANVAS_CREDENTIALS_ASSERTION_SCOPE" => choice(value, key, &["badgeclasses", "issuers"]),
        "LOG_LEVEL" => choice(value, key, &["TRACE", "DEBUG", "INFO", "WARN", "ERROR"]),
        "COMPLIANCE_PROFILE_RUST_LOG"
        | "DEPLOYMENT_PROFILE_RUST_LOG"
        | "REVOCATION_PROFILE_RUST_LOG" => scalar(value, key, 1024),
        "CREDENTIAL_LOGIN_LISSI_DEEP_LINK_TEMPLATE"
        | "CREDENTIAL_LOGIN_LISSI_ANDROID_DEEP_LINK_TEMPLATE"
        | "CREDENTIAL_LOGIN_LISSI_IOS_DEEP_LINK_TEMPLATE"
        | "CREDENTIAL_LOGIN_LISSI_IOS_UNIVERSAL_LINK_TEMPLATE"
        | "CREDENTIAL_LOGIN_SPRUCEKIT_DEEP_LINK_TEMPLATE"
        | "CREDENTIAL_LOGIN_SPRUCEKIT_ANDROID_DEEP_LINK_TEMPLATE"
        | "CREDENTIAL_LOGIN_SPRUCEKIT_IOS_DEEP_LINK_TEMPLATE"
        | "CREDENTIAL_LOGIN_SPRUCEKIT_IOS_UNIVERSAL_LINK_TEMPLATE" => {
            string_value(value, key, 4096, |s| {
                s.is_empty()
                    || s == "{oid4vp_uri}"
                    || [
                        "https://",
                        "openid4vp://",
                        "intent://",
                        "lissi://",
                        "spruceid://",
                    ]
                    .iter()
                    .any(|prefix| s.starts_with(prefix))
            })
        }
        "CREDENTIAL_LOGIN_LISSI_ANDROID_PACKAGE" | "CREDENTIAL_LOGIN_SPRUCEKIT_ANDROID_PACKAGE" => {
            string_value(value, key, 256, |s| {
                s.is_empty()
                    || s.split('.').all(|p| {
                        !p.is_empty() && p.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
                    })
            })
        }
        "CANVAS_LTI_TOOL_PUBLIC_JWKS" => public_jwks(value),
        "APPLICATION_TEMPLATE_MIGRATION_MAP" => {
            let map = value
                .as_object()
                .ok_or_else(|| invalid(key, "an object of template IDs"))?;
            require(
                map.len() <= 128
                    && map
                        .iter()
                        .all(|(from, to)| identifier(from) && to.as_str().is_some_and(identifier)),
            )?;
            serde_json::to_string(value).map_err(|_| REFUSED.into())
        }
        "CANVAS_LEGACY_EVENT_INGEST_ENABLED"
        | "DIDCOMM_ALLOW_PRIVATE_ENDPOINTS"
        | "DIDCOMM_ALLOW_PRIVATE_IPS"
        | "PASSPORT_PROVIDER_INGRESS_GATEWAY_ENABLED" => {
            if value == &Value::Bool(false) {
                Ok("false".into())
            } else {
                Err(invalid(
                    key,
                    "false; this production installation does not support that exception or service",
                ))
            }
        }
        _ => Err(
            "unknown or installer-owned application setting; use the documented settings matrix"
                .into(),
        ),
    }
}

fn number(value: &Value, key: &str, minimum: u64, maximum: u64) -> Result<String> {
    value
        .as_u64()
        .filter(|v| (minimum..=maximum).contains(v))
        .map(|v| v.to_string())
        .ok_or_else(|| invalid(key, "an integer within the documented range"))
}

fn choice(value: &Value, key: &str, choices: &[&str]) -> Result<String> {
    string_value(value, key, 128, |v| choices.contains(&v))
}

fn hostname(value: &str) -> bool {
    value.len() <= 253
        && !value.is_empty()
        && value == value.to_ascii_lowercase()
        && !value.ends_with('.')
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

fn public_jwks(value: &Value) -> Result<String> {
    let object = value.as_object().ok_or(REFUSED)?;
    require(object.len() == 1)?;
    let keys = object
        .get("keys")
        .and_then(Value::as_array)
        .ok_or(REFUSED)?;
    require(!keys.is_empty() && keys.len() <= 16)?;
    let mut kids = BTreeSet::new();
    for key in keys {
        let key = key.as_object().ok_or(REFUSED)?;
        require(
            key.keys()
                .all(|k| ["kty", "alg", "kid", "use", "n", "e"].contains(&k.as_str()))
                && key.get("kty") == Some(&Value::String("RSA".into()))
                && key.get("alg") == Some(&Value::String("RS256".into()))
                && key.get("use").is_none_or(|v| v == "sig"),
        )?;
        let kid = scalar(
            key.get("kid").ok_or(REFUSED)?,
            "CANVAS_LTI_TOOL_PUBLIC_JWKS",
            2048,
        )?;
        require(!kid.is_empty() && kids.insert(kid))?;
        for name in ["n", "e"] {
            let value = key.get(name).and_then(Value::as_str).ok_or(REFUSED)?;
            require(
                !value.is_empty()
                    && value.len() <= 2048
                    && value
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
            )?;
            use base64::Engine as _;
            let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(value)
                .map_err(|_| REFUSED)?;
            require(
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes) == value
                    && if name == "n" {
                        (256..=1024).contains(&bytes.len())
                            && bytes.first().is_some_and(|b| *b >= 128)
                            && bytes.last().is_some_and(|b| b & 1 == 1)
                    } else {
                        bytes == [1, 0, 1] || bytes == [3]
                    },
            )?;
        }
    }
    serde_json::to_string(value).map_err(|_| REFUSED.into())
}

fn defaults() -> BTreeMap<String, String> {
    let mut values: BTreeMap<String, String> = [
        ("KEYCLOAK_USER_REGISTRATION_ENABLED", "true"),
        ("KEYCLOAK_VERIFY_EMAIL", "false"),
        ("KEYCLOAK_RESET_PASSWORD_ENABLED", "false"),
        ("KEYCLOAK_SOCIAL_LOGIN_ENABLED", "false"),
        ("KEYCLOAK_ORGANIZATION_IDENTITY_FIRST_ENABLED", "false"),
        ("KEYCLOAK_SMTP_HOST", ""),
        ("KEYCLOAK_SMTP_USERNAME", ""),
        ("KEYCLOAK_SMTP_FROM", ""),
        ("KEYCLOAK_SMTP_PORT", "587"),
        ("KEYCLOAK_SMTP_SSL", "false"),
        ("KEYCLOAK_SMTP_STARTTLS", "true"),
        ("ORGANIZATION_CREATION_ENABLED", "false"),
        ("CANVAS_PORTABLE_INTEGRATION_ENABLED", "false"),
        ("CANVAS_LEGACY_EVENT_INGEST_ENABLED", "false"),
        ("CANVAS_MIRROR_WORKER_ENABLED", "false"),
        ("CANVAS_ALLOW_PRIVATE_BASE_URLS", "false"),
        ("CANVAS_ALLOW_HTTP_LOCALHOST_BASE_URLS", "false"),
        ("DID_PUBLIC_FALLBACK_ENABLED", "false"),
        ("DIDCOMM_ALLOW_PRIVATE_ENDPOINTS", "false"),
        ("CANVAS_CREDENTIALS_PROVIDER", "bridge"),
        ("CANVAS_CREDENTIALS_API_BASE_URL", "https://api.badgr.io"),
        ("CANVAS_CREDENTIALS_ASSERTION_SCOPE", "badgeclasses"),
        ("CANVAS_SYNC_WORKER_JOB_TIMEOUT_SECONDS", "600"),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v.into()))
    .collect();
    for key in [
        "UI_ADDITIONAL_BASE_URLS",
        "CANVAS_CREDENTIALS_PUBLISH_URL",
        "CANVAS_CREDENTIALS_STATUS_SYNC_URL",
        "CANVAS_CREDENTIALS_ISSUER_ID",
        "CANVAS_CREDENTIALS_BADGECLASS_ID",
        "CANVAS_PILOT_ORGANIZATION_IDS",
        "CANVAS_PRIVATE_ORIGIN_ALLOWLIST",
        "CANVAS_SELF_MANAGED_ORIGIN_ALLOWLIST",
        "UNIVERSAL_RESOLVER_URL",
        "DID_WEB_ALLOWED_HOSTS",
        "SMTP_HOST",
        "SMTP_USERNAME",
        "PASSPORT_TENANT_API_KEYS",
        "PASSPORT_TENANT_API_KEYS_FILE",
        "PERSONALIZATION_BUREAU_API_KEY",
        "PERSONALIZATION_BUREAU_API_KEY_FILE",
        "CANVAS_CREDENTIALS_API_TOKEN",
        "CANVAS_CREDENTIALS_API_TOKEN_FILE",
    ] {
        values.insert(key.into(), String::new());
    }
    values
}

impl Configuration {
    fn empty() -> Self {
        Self {
            schema: SCHEMA.into(),
            values: BTreeMap::new(),
            secret_files: BTreeMap::new(),
        }
    }

    fn environment(&self, managed: bool) -> Result<BTreeMap<String, String>> {
        require(
            self.schema == SCHEMA
                && self.values.len() <= 128
                && self
                    .secret_files
                    .keys()
                    .all(|name| OPTIONAL_INTEGRATION_SECRETS.contains(&name.as_str()))
                && self.secret_files.values().all(|path| safe_path(path)),
        )?;
        let mut result = defaults();
        for (key, value) in &self.values {
            result.insert(key.clone(), typed_value(key, value)?);
        }
        if !managed
            && (self.values.keys().any(|key| {
                key.starts_with("KEYCLOAK_")
                    || [
                        "CREDENTIAL_LOGIN_REQUIRE_EXISTING_KEYCLOAK_USER",
                        "CREDENTIAL_LOGIN_CREATE_USERS",
                    ]
                    .contains(&key.as_str())
            }) || ["google_client_id", "google_client_secret", "smtp_password"]
                .iter()
                .any(|k| self.secret_files.contains_key(*k)))
        {
            return Err("managed Keycloak settings and credentials cannot configure the selected external OIDC provider".into());
        }
        let text = |key: &str| result.get(key).map_or("", String::as_str);
        let on = |key: &str| text(key) == "true";
        let supplied = |key: &str| self.secret_files.contains_key(key);
        let smtp = !text("KEYCLOAK_SMTP_HOST").is_empty();
        if on("KEYCLOAK_VERIFY_EMAIL") || on("KEYCLOAK_RESET_PASSWORD_ENABLED") {
            require(smtp).map_err(|_| {
                "Keycloak verify-email and password reset require configured Keycloak SMTP"
                    .to_owned()
            })?;
        }
        if smtp {
            require(!text("KEYCLOAK_SMTP_FROM").is_empty()
                && (on("KEYCLOAK_SMTP_SSL") ^ on("KEYCLOAK_SMTP_STARTTLS"))
                && (text("KEYCLOAK_SMTP_USERNAME").is_empty() != supplied("smtp_password")))
                .map_err(|_| "Keycloak SMTP requires a sender, exactly one of SSL/STARTTLS, and matching username/password inputs".to_owned())?;
        } else {
            require(text("KEYCLOAK_SMTP_USERNAME").is_empty() && !supplied("smtp_password"))
                .map_err(|_| {
                    "Keycloak SMTP credentials require a configured host and sender".to_owned()
                })?;
        }
        require(supplied("google_client_id") == supplied("google_client_secret")).map_err(
            |_| "Google login credentials must be supplied as a complete pair".to_owned(),
        )?;
        if on("KEYCLOAK_SOCIAL_LOGIN_ENABLED") {
            require(supplied("google_client_id") && supplied("google_client_secret")).map_err(
                |_| "Google login requires both imported client credential files".to_owned(),
            )?;
        }
        if on("DID_PUBLIC_FALLBACK_ENABLED") {
            require(!text("DID_WEB_ALLOWED_HOSTS").is_empty()).map_err(|_| {
                "public DID fallback requires an explicit did:web hostname allowlist".to_owned()
            })?;
        }
        if on("CANVAS_ALLOW_PRIVATE_BASE_URLS") {
            require(!text("CANVAS_PRIVATE_ORIGIN_ALLOWLIST").is_empty()).map_err(|_| {
                "private Canvas origins require an explicit exact-origin allowlist".to_owned()
            })?;
        }
        if on("CANVAS_ALLOW_HTTP_LOCALHOST_BASE_URLS") {
            return Err("HTTP localhost Canvas providers are a development exception, not a production installer setting".into());
        }
        if on("CANVAS_PORTABLE_INTEGRATION_ENABLED") {
            for key in [
                "CANVAS_LTI_EXPERIENCE_BASE_URL",
                "CANVAS_PILOT_ORGANIZATION_IDS",
                "CANVAS_LTI_TOOL_SIGNING_ORGANIZATION_ID",
                "CANVAS_LTI_TOOL_ISSUER_DID",
                "CANVAS_LTI_TOOL_ACTIVE_KID",
                "CANVAS_LTI_TOOL_PUBLIC_JWKS",
                "CANVAS_CREDENTIAL_ISSUER_PROFILE_IDS",
            ] {
                require(!text(key).is_empty())
                    .map_err(|_| invalid(key, "a configured value for portable Canvas"))?;
            }
            require(
                matches!(
                    text("CANVAS_CREDENTIALS_PROVIDER"),
                    "badgr_api" | "canvas_credentials_api"
                ) && text("CANVAS_SYNC_WORKER_JOB_TIMEOUT_SECONDS") == "600",
            )?;
            let did = text("CANVAS_LTI_TOOL_ISSUER_DID");
            let active = text("CANVAS_LTI_TOOL_ACTIVE_KID");
            let jwks = self
                .values
                .get("CANVAS_LTI_TOOL_PUBLIC_JWKS")
                .ok_or(REFUSED)?;
            require(
                active.starts_with(&format!("{did}#"))
                    && jwks["keys"]
                        .as_array()
                        .is_some_and(|keys| keys.iter().any(|key| key["kid"] == active)),
            )?;
        }
        if on("CANVAS_MIRROR_WORKER_ENABLED") {
            require(!text("CANVAS_MIRROR_WORKER_ORGANIZATION_ID").is_empty()
                && supplied("canvas_credentials_api_token")
                && matches!(text("CANVAS_CREDENTIALS_PROVIDER"), "badgr_api" | "canvas_credentials_api")
                && !text("CANVAS_CREDENTIALS_API_BASE_URL").is_empty()
                && !text("CANVAS_CREDENTIALS_ISSUER_ID").is_empty()
                && (text("CANVAS_CREDENTIALS_ASSERTION_SCOPE") != "badgeclasses" || !text("CANVAS_CREDENTIALS_BADGECLASS_ID").is_empty()))
                .map_err(|_| "Canvas mirror requires an organization, imported API token and a real, fully identified Credentials API provider".to_owned())?;
        }
        let passport = on("PASSPORT_NATIVE_HTTP_ENABLED");
        let internal = on("PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED");
        require(!(internal && supplied("passport_tenant_api_keys"))).map_err(|_| {
            "Passport internal authentication and a tenant keyring are mutually exclusive"
                .to_owned()
        })?;
        if passport {
            require(internal || supplied("passport_tenant_api_keys"))
                .map_err(|_| "Passport requires internal service authentication or an imported tenant keyring".to_owned())?;
        }
        for key in [
            "PASSPORT_NATIVE_GATEWAY_ENABLED",
            "PASSPORT_NATIVE_FLOW_ENABLED",
            "PASSPORT_MANAGED_ISSUER_SIGNING_ENABLED",
            "PASSPORT_KMS_ARTIFACTS_ENABLED",
            "PASSPORT_KMS_CALLBACKS_ENABLED",
        ] {
            require(!on(key) || passport)
                .map_err(|_| invalid(key, "PASSPORT_NATIVE_HTTP_ENABLED=true"))?;
        }
        if !text("PERSONALIZATION_BUREAU_URL").is_empty()
            || supplied("personalization_bureau_api_key")
        {
            require(passport && !text("PERSONALIZATION_BUREAU_URL").is_empty()
                && supplied("personalization_bureau_api_key")
                && (!on("PASSPORT_KMS_CALLBACKS_ENABLED") || !text("PERSONALIZATION_BUREAU_PROVIDER_PROFILE_ID").is_empty()))
                .map_err(|_| "Passport bureau submission requires its HTTPS provider URL, imported API key and any required KMS callback profile".to_owned())?;
        }
        for (key, name) in [
            (
                "CANVAS_CREDENTIALS_API_TOKEN_FILE",
                "canvas_credentials_api_token",
            ),
            ("PASSPORT_TENANT_API_KEYS_FILE", "passport_tenant_api_keys"),
            (
                "PERSONALIZATION_BUREAU_API_KEY_FILE",
                "personalization_bureau_api_key",
            ),
        ] {
            result.insert(
                key.into(),
                if self.secret_files.contains_key(name) {
                    format!("/run/secrets/{name}")
                } else {
                    String::new()
                },
            );
        }
        Ok(result)
    }
}

fn imported_secret(name: &str, path: &Path) -> Result<Vec<u8>> {
    let bytes = private_bytes(path)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| REFUSED)?
        .trim_end_matches(['\r', '\n']);
    require(
        !text.is_empty()
            && (name == "passport_tenant_api_keys" || !text.bytes().any(|b| b.is_ascii_control()))
            && ![
                "change-me",
                "change_me",
                "changeme",
                "replace-me",
                "replace_me",
            ]
            .iter()
            .any(|prefix| text.to_ascii_lowercase().starts_with(prefix)),
    )?;
    if name == "passport_tenant_api_keys" {
        marty_passport_auth::PassportTenantKeyring::from_json(text)
            .map_err(|_| "invalid Passport tenant keyring".to_owned())?;
    }
    if name == "google_analytics_measurement_id" {
        require(
            regex::Regex::new(r"\AG-[A-Z0-9]+\z")
                .unwrap()
                .is_match(text),
        )
        .map_err(|_| "Google Analytics input requires a GA4 measurement identifier".to_owned())?;
    }
    Ok(bytes)
}

pub(crate) fn prepare(path: Option<&Path>, managed_keycloak: bool) -> Result<Prepared> {
    let raw = path
        .map(private_bytes)
        .transpose()?
        .unwrap_or_else(|| serde_json::to_vec(&Configuration::empty()).unwrap());
    let configuration: Configuration = decode(&raw)?;
    configuration.environment(managed_keycloak)?;
    let mut secrets = BTreeMap::new();
    for name in OPTIONAL_INTEGRATION_SECRETS {
        let bytes = configuration
            .secret_files
            .get(name)
            .map(|path| imported_secret(name, path))
            .transpose()?
            .unwrap_or_default();
        secrets.insert(name.into(), fingerprint(&bytes));
    }
    Ok(Prepared {
        raw,
        configuration,
        managed_keycloak,
        secrets,
    })
}

pub(crate) fn select(prepared: Prepared, state: &mut InstallerState) -> Result<()> {
    state.require_live_phase(Phase::Verified)?;
    require(state.journal().application_settings_sha256().is_none())?;
    require(
        prepared.managed_keycloak
            == state
                .with_inspection(crate::installer_foundation::load)?
                .is_none(),
    )?;
    let selection = Selection {
        schema: SELECTION_SCHEMA.into(),
        installation_id: state.journal().installation_id(),
        source_sha256: digest(&prepared.raw),
        configuration: prepared.configuration,
        managed_keycloak: prepared.managed_keycloak,
        secrets: prepared.secrets,
    };
    let raw = serde_json::to_vec(&selection).map_err(|_| REFUSED)?;
    state.write_evidence(SOURCE, &prepared.raw)?;
    state.write_evidence(RECORD, &raw)?;
    state.bind_application_settings(&digest(&raw))?;
    state.with_inspection(|view| load(view).map(|_| ()))
}

fn decoded(raw: &[u8], source: &[u8], journal: &Journal) -> Result<Selection> {
    require(Some(digest(raw).as_str()) == journal.application_settings_sha256())?;
    let selected: Selection = decode(raw)?;
    let configuration: Configuration = decode(source)?;
    require(
        selected.schema == SELECTION_SCHEMA
            && selected.installation_id == journal.installation_id()
            && selected.source_sha256 == digest(source)
            && selected.configuration == configuration
            && selected
                .secrets
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
                == OPTIONAL_INTEGRATION_SECRETS.into_iter().collect(),
    )?;
    selected
        .configuration
        .environment(selected.managed_keycloak)?;
    for (name, value) in &selected.secrets {
        require(
            value.sha256.len() == 64
                && value
                    .sha256
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
                && value.size_bytes <= 65_536
                && if selected.configuration.secret_files.contains_key(name) {
                    value.size_bytes > 0
                } else {
                    value == &fingerprint(&[])
                },
        )?;
    }
    Ok(selected)
}

pub(crate) fn load(view: &LockedInspection) -> Result<Option<Selection>> {
    let raw = view.diagnostic_record(RECORD, true)?;
    let source = view.diagnostic_record(SOURCE, true)?;
    if view.journal().application_settings_sha256().is_none() {
        require(raw.is_none() && source.is_none())?;
        return Ok(None);
    }
    let selected = decoded(
        &raw.ok_or(REFUSED)?,
        &source.ok_or(REFUSED)?,
        view.journal(),
    )?;
    require(selected.managed_keycloak == crate::installer_foundation::load(view)?.is_none())?;
    Ok(Some(selected))
}

fn at(installation: &Path) -> Result<Option<Selection>> {
    let journal = InstallerState::inspect(installation)?;
    let evidence = installation.join("evidence");
    if journal.application_settings_sha256().is_none() {
        for name in [SOURCE, RECORD] {
            match std::fs::symlink_metadata(evidence.join(name)) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                _ => return Err(REFUSED.into()),
            }
        }
        return Ok(None);
    }
    decoded(
        &private_bytes(&evidence.join(RECORD))?,
        &private_bytes(&evidence.join(SOURCE))?,
        &journal,
    )
    .map(Some)
}

pub(crate) fn for_inputs(inputs: &ComposeInputs) -> Result<Option<Selection>> {
    let selection = at(&inputs.installation)?;
    for name in [SOURCE, RECORD] {
        let path = inputs.installation.join("evidence").join(name);
        let matching: Vec<_> = inputs
            .bound_inputs
            .iter()
            .filter(|f| f.path == path)
            .collect();
        if selection.is_some() {
            require(matching.len() == 1 && matching[0].sha256 == digest(&private_bytes(&path)?))?;
        } else {
            require(matching.is_empty())?;
        }
    }
    if let Some(selection) = &selection {
        require(
            selection.managed_keycloak
                == crate::installer_foundation::for_inputs(inputs)?.is_none(),
        )?;
    }
    Ok(selection)
}

impl Selection {
    pub(crate) fn bind_inputs(&self, inputs: &mut ComposeInputs) -> Result<()> {
        for name in [SOURCE, RECORD] {
            inputs
                .bound_inputs
                .push(crate::installer_application::bound(
                    inputs.installation.join("evidence").join(name),
                )?);
        }
        Ok(())
    }

    pub(crate) fn apply_environment(&self, values: &mut BTreeMap<String, String>) -> Result<()> {
        values.extend(self.configuration.environment(self.managed_keycloak)?);
        Ok(())
    }

    pub(crate) fn initial_secrets(&self) -> Result<BTreeMap<String, Vec<u8>>> {
        let mut values = BTreeMap::new();
        for (name, expected) in &self.secrets {
            let bytes = self
                .configuration
                .secret_files
                .get(name)
                .map(|path| imported_secret(name, path))
                .transpose()?
                .unwrap_or_default();
            require(fingerprint(&bytes) == *expected)?;
            values.insert(name.clone(), bytes);
        }
        Ok(values)
    }

    pub(crate) fn fingerprints(&self) -> &BTreeMap<String, Fingerprint> {
        &self.secrets
    }

    pub(crate) fn verify_secrets(&self, root: &File) -> Result<()> {
        let secrets = fs::open_child(root, "secrets", libc::O_RDONLY | libc::O_DIRECTORY, REFUSED)?;
        let metadata = secrets.metadata().map_err(|_| REFUSED)?;
        require(
            metadata.is_dir()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o7777 == 0o700,
        )?;
        for (name, expected) in &self.secrets {
            let mut file =
                fs::open_child(&secrets, name, libc::O_RDONLY | libc::O_NONBLOCK, REFUSED)?;
            let before = file.metadata().map_err(|_| REFUSED)?;
            require(
                before.is_file()
                    && before.nlink() == 1
                    && before.uid() == unsafe { libc::geteuid() }
                    && before.mode() & 0o7777 == 0o444
                    && before.len() == expected.size_bytes,
            )?;
            let mut bytes = Vec::new();
            (&mut file)
                .take(65_537)
                .read_to_end(&mut bytes)
                .map_err(|_| REFUSED)?;
            let after = file.metadata().map_err(|_| REFUSED)?;
            let named = fs::open_child(&secrets, name, libc::O_PATH, REFUSED)?
                .metadata()
                .map_err(|_| REFUSED)?;
            let identity = |m: &std::fs::Metadata| {
                (
                    m.dev(),
                    m.ino(),
                    m.uid(),
                    m.gid(),
                    m.mode(),
                    m.nlink(),
                    m.len(),
                    m.ctime(),
                    m.ctime_nsec(),
                    m.mtime(),
                    m.mtime_nsec(),
                )
            };
            require(
                identity(&before) == identity(&after)
                    && identity(&after) == identity(&named)
                    && fingerprint(&bytes) == *expected,
            )?;
        }
        Ok(())
    }

    pub(crate) fn verify_model_secrets(&self, installation: &Path, model: &Value) -> Result<()> {
        if model["secrets"].as_object().is_some_and(|secrets| {
            secrets
                .keys()
                .any(|k| OPTIONAL_INTEGRATION_SECRETS.contains(&k.as_str()))
        }) {
            let root = fs::directory(installation, REFUSED)?;
            self.verify_secrets(&root)?;
            fs::require_directory_binding(installation, &root, REFUSED)?;
        }
        Ok(())
    }
}

pub(crate) fn apply_defaults(values: &mut BTreeMap<String, String>) {
    values.extend(defaults());
}

pub(crate) fn verify_generation(
    installation: &Path,
    files: &BTreeMap<String, crate::installer_generation_binding::GenerationFile>,
) -> Result<()> {
    // Standalone historical generation evidence is also inspected by the
    // low-level reader. It grants no installation authority without a journal.
    if let Err(error) = std::fs::symlink_metadata(installation.join("installation.json")) {
        if error.kind() == std::io::ErrorKind::NotFound
            && [SOURCE, RECORD].iter().all(|name| {
                std::fs::symlink_metadata(installation.join("evidence").join(name))
                    .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
            })
        {
            return Ok(());
        }
        return Err(REFUSED.into());
    }
    if let Some(selection) = at(installation)? {
        let root = fs::directory(installation, REFUSED)?;
        selection.verify_secrets(&root)?;
        for name in OPTIONAL_INTEGRATION_SECRETS {
            if let Some(file) = files.get(name) {
                let expected = selection.secrets.get(name).ok_or(REFUSED)?;
                require(
                    file.source == crate::installer_generation_binding::GenerationSource::Original
                        && file.size == expected.size_bytes
                        && file.sha256 == expected.sha256
                        && file.mode == 0o444
                        && file.source_mode == 0o444,
                )?;
            }
        }
        fs::require_directory_binding(installation, &root, REFUSED)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "installer_settings_tests.rs"]
mod tests;
