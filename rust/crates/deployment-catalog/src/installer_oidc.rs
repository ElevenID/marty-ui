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
}

impl ExternalOidc {
    pub(crate) fn validate(&self) -> Result<()> {
        for value in [&self.issuer_url, &self.client_id, &self.admin_email] {
            scalar(value)?;
        }
        let issuer = url::Url::parse(&self.issuer_url).map_err(|_| REFUSED)?;
        require(
            issuer.scheme() == "https"
                && issuer.host_str().is_some()
                && issuer.username().is_empty()
                && issuer.password().is_none()
                && issuer.query().is_none()
                && issuer.fragment().is_none()
                && self.admin_email.contains('@')
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
                    && origin.host_str().is_some()
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
                    "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384",
                    "ES512", "EdDSA",
                ]
                .contains(&value.as_str())
                    && algorithms.insert(value),
            )?;
        }
        Ok(())
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
        Ok(())
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
    let text = std::str::from_utf8(&raw).map_err(|_| REFUSED)?;
    require(!text.trim().is_empty() && !text.contains('\0') && raw.len() <= 65536)?;
    Ok(raw)
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
            require(env.get(name).and_then(Value::as_str) == Some(expected))?;
        }
        require(
            env.get("OIDC_ALLOWED_ALGORITHMS").and_then(Value::as_str)
                == Some(oidc.allowed_algorithms.join(",").as_str())
                && env
                    .get("OIDC_TRUSTED_ENDPOINT_ORIGINS")
                    .and_then(Value::as_str)
                    == Some(oidc.trusted_endpoint_origins.join(",").as_str()),
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
