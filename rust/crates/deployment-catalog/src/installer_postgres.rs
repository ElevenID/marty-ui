//! Immutable external PostgreSQL selection for fresh managed-OpenBao installs.
//! The provider owns the database and backups; this owner binds only the
//! application endpoint and its imported password, never provider credentials.
#![cfg(target_os = "linux")]

use crate::{
    installer_compose::ComposeInputs,
    installer_host_fs as fs,
    installer_state::{InstallerState, Journal, LockedInspection, Phase},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    net::IpAddr,
    path::{Path, PathBuf},
};

type Result<T> = std::result::Result<T, String>;
const REFUSED: &str = "external PostgreSQL selection is absent, changed or unsupported; preserve installation evidence";
const SCHEMA: &str = "elevenid.installer-external-postgres/v1";
const SELECTION_SCHEMA: &str = "elevenid.installer-external-postgres-selection/v1";
pub(crate) const RECORD: &str = "external-postgres-selection.json";
pub(crate) const LAYER: &str =
    "deploy-config/compose/selfhost-installer/compose.external-postgres.yml";
pub(crate) const SECRET: &str = "external_postgres_password";
const PASSWORD_MOUNT: &str = "/run/secrets/marty_db_password";
const ROOT_CERT_ENV: &str = "PGSSLROOTCERT";
const DATABASE_SERVICES: &[&str] = &[
    "revocation-profile-migrate",
    "db-migrate",
    "kms-initialize",
    "issuance-migrations",
    "auth",
    "organization",
    "credential-template",
    "trust-profile",
    "issuance",
    "issuance-native",
    "applicant",
    "notification",
    "compliance-profile",
    "presentation-policy",
    "deployment-profile",
    "flow",
    "revocation-profile",
    "device-registration",
];

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
fn identifier(value: &str) -> Result<()> {
    require(
        !value.is_empty()
            && value.len() <= 128
            && value.trim() == value
            && !value.chars().any(char::is_control),
    )
}
fn hostname(value: &str) -> Result<String> {
    if let Ok(address) = value.parse::<IpAddr>() {
        return Ok(match address {
            IpAddr::V4(value) => value.to_string(),
            IpAddr::V6(value) => format!("[{value}]"),
        });
    }
    require(
        !value.is_empty()
            && value.len() <= 253
            && value.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label.as_bytes()[0].is_ascii_alphanumeric()
                    && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                    && label
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || c == b'-')
            }),
    )?;
    Ok(value.to_ascii_lowercase())
}
fn percent_encode(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 15)]));
        }
    }
    encoded
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExternalPostgres {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub database: String,
    pub password_file: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_certificate_pem: Option<String>,
}
impl ExternalPostgres {
    pub(crate) fn validate(&self) -> Result<()> {
        hostname(&self.host)?;
        identifier(&self.username)?;
        identifier(&self.database)?;
        require(self.port != 0 && self.password_file.is_absolute())?;
        self.root_certificate()?;
        Ok(())
    }

    fn root_certificate(&self) -> Result<Option<String>> {
        let Some(pem) = self.root_certificate_pem.as_deref() else {
            return Ok(None);
        };
        require(pem.len() <= 16 * 1024)?;
        let lines: Vec<_> = pem.lines().collect();
        let [begin, body @ .., end] = lines.as_slice() else {
            return Err(REFUSED.into());
        };
        require(
            *begin == "-----BEGIN CERTIFICATE-----"
                && *end == "-----END CERTIFICATE-----"
                && !body.is_empty()
                && body.iter().all(|line| !line.is_empty()),
        )?;
        let der = STANDARD.decode(body.concat()).map_err(|_| REFUSED)?;
        require(der.first() == Some(&0x30))?;
        Ok(Some(lines.join("\n")))
    }

    pub(crate) fn append_root_certificate(&self, env: &mut Vec<u8>) -> Result<()> {
        if let Some(pem) = self.root_certificate()? {
            // Compose's dotenv parser preserves newlines in single-quoted
            // values, and SQLx accepts an inline PEM through PGSSLROOTCERT.
            // The framing and base64 checks above exclude dotenv delimiters.
            let text = std::str::from_utf8(env).map_err(|_| REFUSED)?;
            require(!text.lines().any(|line| line.starts_with("PGSSLROOTCERT=")))?;
            env.extend_from_slice(format!("{ROOT_CERT_ENV}='{pem}'\n").as_bytes());
        }
        Ok(())
    }

    fn url_template(&self) -> Result<String> {
        self.validate()?;
        Ok(format!(
            "postgresql://{}:${{MARTY_DB_PASSWORD}}@{}:{}/{}?sslmode=verify-full",
            percent_encode(&self.username),
            hostname(&self.host)?,
            self.port,
            percent_encode(&self.database),
        ))
    }

    pub(crate) fn apply_environment(&self, values: &mut BTreeMap<String, String>) -> Result<()> {
        values.insert(
            "MARTY_EXTERNAL_POSTGRES_URL_TEMPLATE".into(),
            self.url_template()?,
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Configuration {
    schema: String,
    pub external_postgres: ExternalPostgres,
}
impl Configuration {
    fn validate(&self) -> Result<()> {
        require(self.schema == SCHEMA)?;
        self.external_postgres.validate()
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
fn imported_secret(postgres: &ExternalPostgres) -> Result<Vec<u8>> {
    let raw = private_bytes(&postgres.password_file)?;
    // Shell secret loading strips trailing newlines. Refuse them at preparation
    // so the imported fingerprint always describes the actual database password.
    require(
        !raw.is_empty()
            && raw.len() <= 65536
            && raw.iter().all(|value| (b' '..=b'~').contains(value))
            && !raw.iter().all(u8::is_ascii_whitespace)
            && !raw.windows(11).any(|value| value == b"PRIVATE KEY"),
    )?;
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

pub(crate) fn prepare(
    path: Option<&Path>,
    external_oidc: bool,
    aws_foundation: bool,
) -> Result<Option<Prepared>> {
    require(path.is_none() || (external_oidc && !aws_foundation))?;
    let Some(path) = path else {
        return Ok(None);
    };
    let raw = private_bytes(path)?;
    let configuration: Configuration = decode(&raw)?;
    configuration.validate()?;
    let secret = fingerprint(&imported_secret(&configuration.external_postgres)?);
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
        state
            .journal()
            .external_postgres_selection_sha256()
            .is_none()
            && state.journal().application_settings_sha256().is_none()
            && state
                .with_inspection(crate::installer_oidc::load)?
                .is_some()
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
    state.bind_external_postgres_selection(&digest(&raw))?;
    state.with_inspection(|view| load(view).map(|_| ()))
}

fn selected(raw: &[u8], journal: &Journal) -> Result<Selection> {
    require(journal.external_postgres_selection_sha256() == Some(digest(raw).as_str()))?;
    require(journal.external_oidc_selection_sha256().is_some())?;
    let selected: Selection = decode(raw)?;
    selected.configuration.validate()?;
    require(
        selected.schema == SELECTION_SCHEMA
            && selected.installation_id == journal.installation_id()
            && hash(&selected.source_sha256)
            && hash(&selected.secret.sha256)
            && (1..=65536).contains(&selected.secret.size_bytes),
    )?;
    Ok(selected)
}

pub(crate) fn load(view: &LockedInspection) -> Result<Option<Selection>> {
    let raw = view.diagnostic_record(RECORD, true)?;
    if view
        .journal()
        .external_postgres_selection_sha256()
        .is_none()
    {
        require(raw.is_none())?;
        return Ok(None);
    }
    require(crate::installer_oidc::load(view)?.is_some())?;
    selected(&raw.ok_or(REFUSED)?, view.journal()).map(Some)
}

/// Report the responsibility boundary without probing the provider or reading
/// operational credentials. A bound selection is not a database health check,
/// backup, restore, or qualification observation.
pub(crate) fn status(view: &LockedInspection) -> Result<Option<Value>> {
    if load(view)?.is_none() {
        return Ok(None);
    }
    Ok(Some(json!({
        "mode": "external",
        "selection_verified": true,
        "provider_health": "not_observed",
        "connection_observed": false,
        "local_postgres_managed": false,
        "local_state_copy_includes_database": false,
        "backup_restore_owner": "operator_and_database_provider",
        "backup_observed": false,
        "restore_observed": false,
        "backup_restore_qualification": "not_assessed",
        "installer_password_rotation_supported": false,
        "installation_ready": false
    })))
}

pub(crate) fn record(
    installation: &Path,
    installation_id: uuid::Uuid,
) -> Result<Option<(Vec<u8>, Selection)>> {
    let journal = InstallerState::inspect(installation)?;
    require(journal.installation_id() == installation_id)?;
    let path = installation.join("evidence").join(RECORD);
    if journal.external_postgres_selection_sha256().is_none() {
        match std::fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            _ => return Err(REFUSED.into()),
        }
    }
    require(crate::installer_oidc::record(installation, installation_id)?.is_some())?;
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
        require(crate::installer_oidc::for_inputs(inputs)?.is_some())?;
    } else {
        require(matching.is_empty())?;
    }
    Ok(selection.map(|(_, selected)| selected))
}

/// The sole admitted secret alias preserves every service's established mount
/// target while the generation inventory tracks the actual imported file.
/// Ordinary names retain the exact source-name/file-name invariant.
pub(crate) fn credential_source_name(
    installation: &Path,
    root: &Path,
    name: &str,
    source: &Path,
) -> Result<String> {
    if source == root.join(name) {
        return Ok(name.to_owned());
    }
    require(name == "marty_db_password" && source == root.join(SECRET))?;
    let journal = InstallerState::inspect(installation)?;
    require(record(installation, journal.installation_id())?.is_some())?;
    Ok(SECRET.into())
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
        let raw = imported_secret(&self.configuration.external_postgres)?;
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
        for excluded in ["postgres", "keycloak", "keycloak-configurator"] {
            require(!services.contains_key(excluded))?;
        }
        for service in services.values() {
            let dependencies = &service["depends_on"];
            require(
                !dependencies
                    .as_object()
                    .is_some_and(|value| value.contains_key("postgres"))
                    && !dependencies
                        .as_array()
                        .is_some_and(|value| value.iter().any(|value| value == "postgres")),
            )?;
        }
        // The bound dotenv value contains one literal dollar. Native Compose
        // 5.6.1 serializes that dollar as two in its canonical config model.
        let template = self
            .configuration
            .external_postgres
            .url_template()?
            .replace('$', "$$");
        let root_certificate = self.configuration.external_postgres.root_certificate()?;
        let mut database_present = false;
        for name in DATABASE_SERVICES {
            let Some(service) = services.get(*name) else {
                continue;
            };
            database_present = true;
            let env = service["environment"].as_object().ok_or(REFUSED)?;
            require(
                env.get("DATABASE_URL_TEMPLATE").and_then(Value::as_str) == Some(template.as_str()),
            )?;
            require(
                env.get("MARTY_DB_PASSWORD_FILE").and_then(Value::as_str) == Some(PASSWORD_MOUNT),
            )?;
            require(match root_certificate.as_deref() {
                Some(pem) => env.get(ROOT_CERT_ENV).and_then(Value::as_str) == Some(pem),
                None => env.get(ROOT_CERT_ENV).is_none_or(Value::is_null),
            })?;
            for raw in ["DATABASE_URL", "DATABASE_URL_FILE", "MARTY_DB_PASSWORD"] {
                require(
                    env.get(raw)
                        .is_none_or(|value| value.is_null() || value == ""),
                )?;
            }
            let mounts = service["secrets"].as_array().ok_or(REFUSED)?;
            require(mounts.iter().any(|value| {
                value == "marty_db_password"
                    || (value["source"] == "marty_db_password"
                        && value
                            .get("target")
                            .is_none_or(|target| target == "marty_db_password"))
            }))?;
            if let Some((key, cap)) = pool_limit(name) {
                require(env.get(key).and_then(Value::as_str) == Some(cap))?;
            }
        }
        // Bootstrap-only models contain custody helpers and no application DB.
        if database_present {
            let source = model["secrets"]["marty_db_password"]["file"]
                .as_str()
                .ok_or(REFUSED)?;
            let path = Path::new(source);
            require(
                path.is_absolute()
                    && path.file_name().and_then(|value| value.to_str()) == Some(SECRET),
            )?;
        }
        Ok(())
    }
}

fn pool_limit(service: &str) -> Option<(&'static str, &'static str)> {
    Some(match service {
        "revocation-profile-migrate" => ("RP_DATABASE_MAX_CONNECTIONS", "1"),
        "db-migrate" | "kms-initialize" => ("NOTIFICATION_DATABASE_MAX_CONNECTIONS", "1"),
        "issuance-migrations" => ("ISSUANCE_DATABASE_MAX_CONNECTIONS", "1"),
        "auth" => ("AUTH_DATABASE_MAX_CONNECTIONS", "2"),
        "organization" => ("ORGANIZATION_DATABASE_MAX_CONNECTIONS", "2"),
        "credential-template" => ("CREDENTIAL_TEMPLATE_DATABASE_MAX_CONNECTIONS", "2"),
        "trust-profile" => ("TRUST_PROFILE_DATABASE_MAX_CONNECTIONS", "2"),
        "issuance" | "issuance-native" => ("ISSUANCE_DATABASE_MAX_CONNECTIONS", "2"),
        "notification" => ("NOTIFICATION_DATABASE_MAX_CONNECTIONS", "2"),
        "compliance-profile" => ("COMPLIANCE_PROFILE_DATABASE_MAX_CONNECTIONS", "2"),
        "presentation-policy" => ("PRESENTATION_POLICY_DATABASE_MAX_CONNECTIONS", "2"),
        "deployment-profile" => ("DEPLOYMENT_PROFILE_DATABASE_MAX_CONNECTIONS", "2"),
        "flow" => ("FLOW_DATABASE_MAX_CONNECTIONS", "2"),
        "revocation-profile" => ("RP_DATABASE_MAX_CONNECTIONS", "2"),
        "device-registration" => ("DATABASE_MAX_CONNECTIONS", "2"),
        _ => return None,
    })
}

#[cfg(test)]
#[path = "installer_postgres_tests.rs"]
mod tests;

#[cfg(test)]
pub(crate) fn test_selected_installation() -> (tempfile::TempDir, PathBuf, InstallerState, Selection)
{
    let (parent, path, mut state) = tests::installation();
    let selection = tests::choose(parent.path(), &mut state);
    (parent, path, state, selection)
}
