//! Fresh external login selection, independent of workload key custody.
//! Existing AWS foundations retain their own selection; this owner binds only
//! the optional external provider for managed OpenBao installations.
#![cfg(target_os = "linux")]

use crate::{
    installer_compose::ComposeInputs,
    installer_host_fs as fs,
    installer_state::{InstallerState, Journal, LockedInspection, Phase},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

type Result<T> = std::result::Result<T, String>;
const REFUSED: &str =
    "external OIDC selection is absent, changed or unsupported; preserve installation evidence";
const SCHEMA: &str = "elevenid.installer-external-oidc/v1";
const SELECTION_SCHEMA: &str = "elevenid.installer-external-oidc-selection/v1";
pub(crate) const RECORD: &str = "external-oidc-selection.json";
pub(crate) const LAYER: &str = "deploy-config/compose/selfhost-installer/compose.external-oidc.yml";
const SECRET: &str = "external_oidc_client_secret";
const DEFAULT_SCOPES: &str = "openid,profile,email";

fn require(condition: bool) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}
fn digest(bytes: &[u8]) -> String {
    crate::installer_release::sha256(bytes)
}
fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
}
fn scalar(value: &str) -> Result<()> {
    require(
        !value.is_empty()
            && value.len() <= 2048
            && value.trim() == value
            && !value
                .chars()
                .any(|c| c.is_control() || c == '\'' || c == '\\'),
    )
}
fn private_bytes(path: &Path) -> Result<Vec<u8>> {
    require(path.is_absolute())?;
    let parent = fs::directory(path.parent().ok_or(REFUSED)?, REFUSED)?;
    fs::read_entry(
        &parent,
        path.file_name().and_then(|v| v.to_str()).ok_or(REFUSED)?,
        0o600,
        false,
        REFUSED,
    )
}
fn decode<T: serde::de::DeserializeOwned>(raw: &[u8]) -> Result<T> {
    serde_json::from_value(crate::installer_json::decode(raw).map_err(|_| REFUSED)?)
        .map_err(|_| REFUSED.into())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ClientAuthMethod {
    None,
    ClientSecretPost,
    ClientSecretBasic,
}
impl ClientAuthMethod {
    fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ClientSecretPost => "client_secret_post",
            Self::ClientSecretBasic => "client_secret_basic",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum UserinfoMode {
    Disabled,
    Fallback,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OmitMaxAge {
    Omit,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub(crate) enum MaxAge {
    Seconds(u32),
    Omit(OmitMaxAge),
}
impl MaxAge {
    fn environment(self) -> String {
        match self {
            Self::Seconds(value) => value.to_string(),
            Self::Omit(_) => "omit".into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeSupabaseTotp {
    pub authorization_origin: String,
    pub publishable_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExternalOidc {
    pub issuer_url: String,
    pub client_id: String,
    pub admin_email: String,
    #[serde(default)]
    pub client_secret_file: Option<PathBuf>,
    #[serde(default)]
    pub trusted_endpoint_origins: Vec<String>,
    pub allowed_algorithms: Vec<String>,
    // Omission must stay absent in retained selections from earlier installers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_auth_method: Option<ClientAuthMethod>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub userinfo_mode: Option<UserinfoMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_age: Option<MaxAge>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_supabase_totp: Option<NativeSupabaseTotp>,
}

impl ExternalOidc {
    pub(crate) fn validate(&self) -> Result<()> {
        for value in [&self.issuer_url, &self.client_id, &self.admin_email] {
            scalar(value)?;
        }
        let issuer = url::Url::parse(&self.issuer_url).map_err(|_| REFUSED)?;
        // Keep the bootstrap account rule aligned with run-migrations-with-secrets.sh.
        let admin_email = self.admin_email.to_ascii_lowercase();
        require(
            issuer.scheme() == "https"
                && issuer.host_str().is_some_and(|host| !host.contains('*'))
                && issuer.username().is_empty()
                && issuer.password().is_none()
                && issuer.query().is_none()
                && issuer.fragment().is_none()
                && self.admin_email.contains('@')
                && !matches!(
                    admin_email.as_str(),
                    "admin@example.com" | "user@example.com" | "example@example.com"
                )
                && !admin_email.starts_with("change-me")
                && self.trusted_endpoint_origins.len() <= 8
                && !self.allowed_algorithms.is_empty()
                && self.allowed_algorithms.len() <= 16,
        )?;
        if let Some(path) = &self.client_secret_file {
            require(path.is_absolute())?;
        }
        let mut origins = BTreeSet::new();
        for value in &self.trusted_endpoint_origins {
            scalar(value)?;
            let origin = url::Url::parse(value).map_err(|_| REFUSED)?;
            require(
                origin.scheme() == "https"
                    && origin.host_str().is_some_and(|host| !host.contains('*'))
                    && origin.username().is_empty()
                    && origin.password().is_none()
                    && origin.query().is_none()
                    && origin.fragment().is_none()
                    && origin.path() == "/"
                    && origin.origin().ascii_serialization() == *value
                    && origins.insert(value),
            )?;
        }
        let mut algorithms = BTreeSet::new();
        for value in &self.allowed_algorithms {
            // Discovery, client authentication and actual JWKS compatibility
            // remain the existing Auth owner's fail-closed runtime checks.
            require(
                [
                    "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "EdDSA",
                ]
                .contains(&value.as_str())
                    && algorithms.insert(value),
            )?;
        }
        if let Some(scopes) = &self.scopes {
            scalar(&scopes.join(","))?;
            require(
                !scopes.is_empty()
                    && scopes.len() <= 32
                    && scopes.iter().any(|scope| scope == "openid"),
            )?;
            let mut unique = BTreeSet::new();
            for scope in scopes {
                // RFC 6749 scope-token, with comma and apostrophe excluded for
                // the existing comma-delimited, single-quoted env transport.
                require(
                    !scope.is_empty()
                        && scope.len() <= 128
                        && scope.bytes().all(|byte| {
                            (b'!'..=b'~').contains(&byte)
                                && ![b'"', b'\\', b',', b'\''].contains(&byte)
                        })
                        && unique.insert(scope),
                )?;
            }
        }
        if let Some(method) = self.client_auth_method {
            require((method != ClientAuthMethod::None) == self.client_secret_file.is_some())?;
        }
        if let Some(prompt) = &self.prompt {
            let mut unique = BTreeSet::new();
            require(
                prompt.len() <= 4 && (!prompt.iter().any(|v| v == "none") || prompt.len() == 1),
            )?;
            for value in prompt {
                require(
                    ["login", "consent", "select_account", "none"].contains(&value.as_str())
                        && unique.insert(value),
                )?;
            }
        }
        if let Some(MaxAge::Seconds(value)) = self.max_age {
            require(value <= 86400)?;
        }
        if let Some(native) = &self.native_supabase_totp {
            scalar(&native.authorization_origin)?;
            scalar(&native.publishable_key)?;
            let origin = url::Url::parse(&native.authorization_origin).map_err(|_| REFUSED)?;
            let key = native
                .publishable_key
                .strip_prefix("sb_publishable_")
                .ok_or(REFUSED)?;
            require(
                self.issuer_url.ends_with("/auth/v1")
                    && uuid::Uuid::parse_str(&self.client_id).is_ok()
                    && self.allowed_algorithms == ["ES256"]
                    && self.max_age.unwrap_or(MaxAge::Seconds(0)) == MaxAge::Seconds(0)
                    && origin.scheme() == "https"
                    && origin.origin().ascii_serialization() == native.authorization_origin
                    && (16..=256).contains(&key.len())
                    && key
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')),
            )?;
        }
        if let Some(name) = &self.provider_name {
            // The private native env transport is single-quoted. Reject its
            // unrepresentable characters before any installation side effect.
            scalar(name)?;
            require(name.len() <= 80)?;
        }
        for value in [&self.account_url, &self.recovery_url]
            .into_iter()
            .flatten()
        {
            scalar(value)?;
            let link = url::Url::parse(value).map_err(|_| REFUSED)?;
            require(
                link.scheme() == "https"
                    && link.host_str().is_some_and(|v| !v.contains('*'))
                    && link.username().is_empty()
                    && link.password().is_none()
                    && (link.origin() == issuer.origin()
                        || self
                            .trusted_endpoint_origins
                            .contains(&link.origin().ascii_serialization())),
            )?;
        }
        Ok(())
    }

    /// Optional overrides retain omission, so old authenticated Compose layers
    /// and previously serialized provider selections remain byte compatible.
    fn optional_environment(&self) -> BTreeMap<&'static str, String> {
        let mut values = BTreeMap::new();
        if let Some(value) = self.client_auth_method {
            values.insert("TOKEN_ENDPOINT_AUTH_METHOD", value.as_str().into());
        }
        if let Some(value) = self.userinfo_mode {
            values.insert(
                "USERINFO_MODE",
                match value {
                    UserinfoMode::Disabled => "disabled",
                    UserinfoMode::Fallback => "fallback",
                }
                .into(),
            );
        }
        if let Some(value) = &self.prompt {
            values.insert("PROMPT", value.join(" "));
        }
        if let Some(value) = self.max_age {
            values.insert("MAX_AGE_SECONDS", value.environment());
        }
        for (key, value) in [
            ("PROVIDER_NAME", &self.provider_name),
            ("ACCOUNT_URL", &self.account_url),
            ("RECOVERY_URL", &self.recovery_url),
        ] {
            if let Some(value) = value {
                values.insert(key, value.clone());
            }
        }
        values
    }

    pub(crate) fn preflight_environment(&self) -> Result<BTreeMap<String, String>> {
        self.validate()?;
        let mut values = BTreeMap::from([
            ("OIDC_PROVIDER_MODE".into(), "external".into()),
            ("OIDC_ISSUER_URL".into(), self.issuer_url.clone()),
            ("OIDC_EXTERNAL_ISSUER_URL".into(), self.issuer_url.clone()),
            ("OIDC_CLIENT_ID".into(), self.client_id.clone()),
            (
                "OIDC_ALLOWED_ALGORITHMS".into(),
                self.allowed_algorithms.join(","),
            ),
            (
                "OIDC_TRUSTED_ENDPOINT_ORIGINS".into(),
                self.trusted_endpoint_origins.join(","),
            ),
            (
                "OIDC_REDIRECT_URI".into(),
                "https://preflight.invalid/v1/auth/callback".into(),
            ),
        ]);
        if let Some(scopes) = &self.scopes {
            values.insert("OIDC_SCOPES".into(), scopes.join(","));
        }
        for (key, value) in self.optional_environment() {
            values.insert(format!("OIDC_{key}"), value);
        }
        // Auth's separate metadata-only parser takes an explicit client type
        // without reading or constructing operational customer credentials.
        let method = self
            .client_auth_method
            .unwrap_or(if self.client_secret_file.is_some() {
                ClientAuthMethod::ClientSecretPost
            } else {
                ClientAuthMethod::None
            });
        values.insert(
            "OIDC_TOKEN_ENDPOINT_AUTH_METHOD".into(),
            method.as_str().into(),
        );
        Ok(values)
    }

    pub(crate) fn apply_environment(&self, values: &mut BTreeMap<String, String>) -> Result<()> {
        self.validate()?;
        values.retain(|name, _| {
            !(name.starts_with("KEYCLOAK_")
                || name == "MARTY_KEYCLOAK_KMS_IMAGE"
                || name == "SELFHOST_KEYCLOAK_HOST_PORT")
        });
        for (name, value) in [
            ("MARTY_ORG_ADMIN_EMAIL", self.admin_email.clone()),
            ("MARTY_EXTERNAL_OIDC_ISSUER", self.issuer_url.clone()),
            ("MARTY_EXTERNAL_OIDC_CLIENT_ID", self.client_id.clone()),
            (
                "MARTY_EXTERNAL_OIDC_TRUSTED_ORIGINS",
                self.trusted_endpoint_origins.join(","),
            ),
            (
                "MARTY_EXTERNAL_OIDC_ALGORITHMS",
                self.allowed_algorithms.join(","),
            ),
            (
                "MARTY_EXTERNAL_OIDC_SECRET_FILE",
                self.secret_mount().into(),
            ),
        ] {
            values.insert(name.into(), value);
        }
        values.remove("MARTY_EXTERNAL_OIDC_SCOPES");
        if let Some(scopes) = &self.scopes {
            values.insert("MARTY_EXTERNAL_OIDC_SCOPES".into(), scopes.join(","));
        }
        for key in [
            "TOKEN_ENDPOINT_AUTH_METHOD",
            "USERINFO_MODE",
            "PROMPT",
            "MAX_AGE_SECONDS",
            "PROVIDER_NAME",
            "ACCOUNT_URL",
            "RECOVERY_URL",
        ] {
            values.remove(&format!("MARTY_EXTERNAL_OIDC_{key}"));
        }
        for (key, value) in self.optional_environment() {
            values.insert(format!("MARTY_EXTERNAL_OIDC_{key}"), value);
        }
        for key in [
            "NATIVE_PROOF_MODE",
            "SUPABASE_UI_ORIGIN",
            "SUPABASE_PUBLISHABLE_KEY",
        ] {
            values.remove(&format!("MARTY_EXTERNAL_OIDC_{key}"));
        }
        if let Some(native) = &self.native_supabase_totp {
            values.insert(
                "MARTY_EXTERNAL_OIDC_NATIVE_PROOF_MODE".into(),
                "supabase_totp".into(),
            );
            values.insert(
                "MARTY_EXTERNAL_OIDC_SUPABASE_UI_ORIGIN".into(),
                native.authorization_origin.clone(),
            );
            values.insert(
                "MARTY_EXTERNAL_OIDC_SUPABASE_PUBLISHABLE_KEY".into(),
                native.publishable_key.clone(),
            );
        }
        Ok(())
    }

    pub(crate) fn validate_model_scopes(
        &self,
        environment: &serde_json::Map<String, Value>,
    ) -> Result<()> {
        let selected = self.optional_environment();
        let native = self.native_supabase_totp.as_ref();
        for (name, expected) in [
            (
                "OIDC_NATIVE_PROOF_MODE",
                native.map_or("disabled", |_| "supabase_totp"),
            ),
            (
                "SUPABASE_AUTH_UI_ORIGIN",
                native.map_or("", |value| value.authorization_origin.as_str()),
            ),
            (
                "SUPABASE_PUBLISHABLE_KEY",
                native.map_or("", |value| value.publishable_key.as_str()),
            ),
        ] {
            let actual = environment.get(name).and_then(Value::as_str);
            require(
                actual == Some(expected) || (native.is_none() && !environment.contains_key(name)),
            )?;
        }
        for (key, default) in [
            ("TOKEN_ENDPOINT_AUTH_METHOD", ""),
            ("USERINFO_MODE", "disabled"),
            ("PROMPT", "consent login"),
            ("MAX_AGE_SECONDS", "0"),
            ("PROVIDER_NAME", ""),
            ("ACCOUNT_URL", ""),
            ("RECOVERY_URL", ""),
        ] {
            let actual = environment.get(&format!("OIDC_{key}"));
            if let Some(value) = selected.get(key) {
                require(actual.and_then(Value::as_str) == Some(value.replace('$', "$$").as_str()))?;
            } else {
                require(actual.is_none() || actual.and_then(Value::as_str) == Some(default))?;
            }
        }
        let actual = environment.get("OIDC_SCOPES");
        if let Some(scopes) = &self.scopes {
            // Native Compose config serializes literal dollars as doubled
            // dollars. Compare that exact representation without rewriting it.
            require(
                actual.and_then(Value::as_str)
                    == Some(scopes.join(",").replace('$', "$$").as_str()),
            )
        } else {
            // Older authenticated layers omit the variable and use Auth's
            // identical default. Keep those retained sessions readable.
            require(actual.is_none() || actual.and_then(Value::as_str) == Some(DEFAULT_SCOPES))
        }
    }

    fn secret_mount(&self) -> &'static str {
        if self.client_secret_file.is_some() {
            "/run/secrets/external_oidc_client_secret"
        } else {
            ""
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Configuration {
    schema: String,
    pub external_oidc: ExternalOidc,
}
impl Configuration {
    fn validate(&self) -> Result<()> {
        require(self.schema == SCHEMA)?;
        self.external_oidc.validate()
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Fingerprint {
    sha256: String,
    size_bytes: usize,
}
fn fingerprint(raw: &[u8]) -> Fingerprint {
    Fingerprint {
        sha256: digest(raw),
        size_bytes: raw.len(),
    }
}
fn imported_secret(oidc: &ExternalOidc) -> Result<Vec<u8>> {
    let Some(path) = &oidc.client_secret_file else {
        return Ok(Vec::new());
    };
    let raw = private_bytes(path)?;
    validate_secret_bytes(&raw)?;
    Ok(raw)
}
pub(crate) fn validate_secret_bytes(bytes: &[u8]) -> Result<()> {
    // Immutable generation files already require this transport. Fail during
    // input preparation instead of after OpenBao has minted credentials.
    require(
        !bytes.is_empty()
            && bytes.len() <= 65536
            && bytes.is_ascii()
            && !bytes.contains(&0)
            && !bytes.iter().all(u8::is_ascii_whitespace)
            && !bytes.windows(11).any(|value| value == b"PRIVATE KEY"),
    )
}
pub(crate) struct Prepared {
    source_sha256: String,
    configuration: Configuration,
    secret: Fingerprint,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Selection {
    schema: String,
    installation_id: uuid::Uuid,
    source_sha256: String,
    pub configuration: Configuration,
    secret: Fingerprint,
}

pub(crate) fn prepare(path: Option<&Path>, aws_foundation: bool) -> Result<Option<Prepared>> {
    require(!(path.is_some() && aws_foundation))?;
    let Some(path) = path else {
        return Ok(None);
    };
    let raw = private_bytes(path)?;
    let configuration: Configuration = decode(&raw)?;
    configuration.validate()?;
    let secret = fingerprint(&imported_secret(&configuration.external_oidc)?);
    Ok(Some(Prepared {
        source_sha256: digest(&raw),
        configuration,
        secret,
    }))
}

pub(crate) fn select(prepared: Option<Prepared>, state: &mut InstallerState) -> Result<()> {
    state.require_live_phase(Phase::Verified)?;
    let Some(prepared) = prepared else {
        return Ok(());
    };
    require(
        state.journal().external_oidc_selection_sha256().is_none()
            && state.journal().application_settings_sha256().is_none()
            && state
                .with_inspection(crate::installer_foundation::load)?
                .is_none(),
    )?;
    let selection = Selection {
        schema: SELECTION_SCHEMA.into(),
        installation_id: state.journal().installation_id(),
        source_sha256: prepared.source_sha256,
        configuration: prepared.configuration,
        secret: prepared.secret,
    };
    let raw = serde_json::to_vec(&selection).map_err(|_| REFUSED)?;
    state.write_evidence(RECORD, &raw)?;
    state.bind_external_oidc_selection(&digest(&raw))?;
    state.with_inspection(|view| load(view).map(|_| ()))
}

fn selected(raw: &[u8], journal: &Journal) -> Result<Selection> {
    require(journal.external_oidc_selection_sha256() == Some(digest(raw).as_str()))?;
    let selected: Selection = decode(raw)?;
    selected.configuration.validate()?;
    require(
        selected.schema == SELECTION_SCHEMA
            && selected.installation_id == journal.installation_id()
            && hash(&selected.source_sha256)
            && hash(&selected.secret.sha256)
            && selected.secret.size_bytes <= 65536
            && if selected
                .configuration
                .external_oidc
                .client_secret_file
                .is_some()
            {
                selected.secret.size_bytes > 0
            } else {
                selected.secret == fingerprint(&[])
            },
    )?;
    Ok(selected)
}

pub(crate) fn load(view: &LockedInspection) -> Result<Option<Selection>> {
    let raw = view.diagnostic_record(RECORD, true)?;
    if view.journal().external_oidc_selection_sha256().is_none() {
        require(raw.is_none())?;
        return Ok(None);
    }
    require(
        view.diagnostic_record(crate::installer_foundation::RECORD, true)?
            .is_none(),
    )?;
    selected(&raw.ok_or(REFUSED)?, view.journal()).map(Some)
}

pub(crate) fn record(
    installation: &Path,
    installation_id: uuid::Uuid,
) -> Result<Option<(Vec<u8>, Selection)>> {
    let journal = InstallerState::inspect(installation)?;
    require(journal.installation_id() == installation_id)?;
    let path = installation.join("evidence").join(RECORD);
    if journal.external_oidc_selection_sha256().is_none() {
        match std::fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            _ => return Err(REFUSED.into()),
        }
    }
    match std::fs::symlink_metadata(
        installation
            .join("evidence")
            .join(crate::installer_foundation::RECORD),
    ) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err(REFUSED.into()),
    }
    let raw = private_bytes(&path)?;
    let selected = selected(&raw, &journal)?;
    Ok(Some((raw, selected)))
}

pub(crate) fn for_inputs(inputs: &ComposeInputs) -> Result<Option<Selection>> {
    let journal = InstallerState::inspect(&inputs.installation)?;
    let selection = record(&inputs.installation, journal.installation_id())?;
    let path = inputs.installation.join("evidence").join(RECORD);
    let matching: Vec<_> = inputs
        .bound_inputs
        .iter()
        .filter(|file| file.path == path)
        .collect();
    if let Some((raw, _)) = &selection {
        require(
            inputs.project == journal.compose_project()
                && matching.len() == 1
                && matching[0].sha256 == digest(raw),
        )?;
    } else {
        require(matching.is_empty())?;
    }
    Ok(selection.map(|(_, selected)| selected))
}

/// Login-provider decisions use this resolver, never the KMS foundation alone.
pub(crate) fn external(view: &LockedInspection) -> Result<Option<ExternalOidc>> {
    let standalone = load(view)?;
    let foundation = crate::installer_foundation::load(view)?;
    require(!(standalone.is_some() && foundation.is_some()))?;
    Ok(standalone
        .map(|v| v.configuration.external_oidc)
        .or_else(|| foundation.map(|v| v.configuration.external_oidc)))
}
pub(crate) fn external_for_inputs(inputs: &ComposeInputs) -> Result<Option<ExternalOidc>> {
    let standalone = for_inputs(inputs)?;
    let foundation = crate::installer_foundation::for_inputs(inputs)?;
    require(!(standalone.is_some() && foundation.is_some()))?;
    Ok(standalone
        .map(|v| v.configuration.external_oidc)
        .or_else(|| foundation.map(|v| v.configuration.external_oidc)))
}

impl Selection {
    pub(crate) fn bind_inputs(&self, inputs: &mut ComposeInputs) -> Result<()> {
        inputs
            .bound_inputs
            .push(crate::installer_application::bound(
                inputs.installation.join("evidence").join(RECORD),
            )?);
        Ok(())
    }
    pub(crate) fn import_inputs(&self, state: &mut InstallerState) -> Result<()> {
        state.require_live_phase(Phase::Provisioning)?;
        require(self.installation_id == state.journal().installation_id())?;
        let raw = imported_secret(&self.configuration.external_oidc)?;
        require(fingerprint(&raw) == self.secret)?;
        state.stage_application_inputs(&BTreeMap::from([(SECRET.into(), raw)]))
    }
    pub(crate) fn verify_imported(&self, values: &BTreeMap<String, Vec<u8>>) -> Result<()> {
        require(
            values
                .get(SECRET)
                .is_some_and(|raw| fingerprint(raw) == self.secret),
        )
    }
    pub(crate) fn validate_model(&self, model: &Value) -> Result<()> {
        let services = model["services"].as_object().ok_or(REFUSED)?;
        require(
            !services.contains_key("keycloak") && !services.contains_key("keycloak-configurator"),
        )?;
        // Bootstrap contains only the existing OpenBao custody helpers.
        let Some(auth) = services.get("auth") else {
            return Ok(());
        };
        let oidc = &self.configuration.external_oidc;
        let env = auth["environment"].as_object().ok_or(REFUSED)?;
        oidc.validate_model_scopes(env)?;
        for (name, expected) in [
            ("OIDC_PROVIDER_MODE", "external"),
            ("OIDC_ISSUER_URL", oidc.issuer_url.as_str()),
            ("OIDC_EXTERNAL_ISSUER_URL", oidc.issuer_url.as_str()),
            ("OIDC_CLIENT_ID", oidc.client_id.as_str()),
            ("OIDC_CLIENT_SECRET_FILE", oidc.secret_mount()),
            ("KEYCLOAK_TOKEN_EXCHANGE_ENABLED", "false"),
            ("KEYCLOAK_PASSKEYS_ENABLED", "false"),
            ("CREDENTIAL_LOGIN_REQUIRE_EXISTING_KEYCLOAK_USER", "false"),
            ("CREDENTIAL_LOGIN_CREATE_USERS", "false"),
        ] {
            require(
                env.get(name).and_then(Value::as_str) == Some(expected.replace('$', "$$").as_str()),
            )?;
        }
        require(
            env.get("OIDC_ALLOWED_ALGORITHMS").and_then(Value::as_str)
                == Some(oidc.allowed_algorithms.join(",").as_str())
                && env
                    .get("OIDC_TRUSTED_ENDPOINT_ORIGINS")
                    .and_then(Value::as_str)
                    == Some(
                        oidc.trusted_endpoint_origins
                            .join(",")
                            .replace('$', "$$")
                            .as_str(),
                    ),
        )?;
        for name in [
            "KEYCLOAK_REALM",
            "KEYCLOAK_ADMIN_URL",
            "MARTY_API_CLIENT_ID",
            "MARTY_API_CLIENT_SECRET",
            "MARTY_API_CLIENT_SECRET_FILE",
            "OIDC_CLIENT_SECRET",
        ] {
            require(
                env.get(name)
                    .is_none_or(|value| value.is_null() || value == ""),
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "installer_oidc_tests.rs"]
mod tests;
