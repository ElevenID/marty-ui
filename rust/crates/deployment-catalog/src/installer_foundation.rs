//! Fresh infrastructure selection around the existing installer owners.
//! Keys, certificates, external OIDC and rotating workload credentials must
//! already exist. This module creates no cloud resources, credentials, registry
//! or cryptographic implementation, and does not attest IAM/network isolation.
#![cfg(target_os = "linux")]

use crate::{
    installer_compose::{config_path, ComposeInputs},
    installer_host_fs::{self as fs, CredentialProjection},
    installer_json,
    installer_state::{InstallerState, LockedInspection, Phase},
};
use marty_selfhost_identity::SELFHOST_ROLES;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

type Result<T> = std::result::Result<T, String>;
const REFUSED: &str =
    "AWS foundation inputs are absent, changed or unsupported; preserve installation evidence";
pub(crate) const RECORD: &str = "foundation-selection.json";
pub(crate) const REGISTRATION: &str = "foundation-kms-registration.json";
pub(crate) const LAYER: &str =
    "deploy-config/compose/selfhost-installer/compose.aws-foundation.yml";
pub(crate) const WORKLOADS: &[&str] = &[
    "db-migrate",
    "gateway",
    "auth",
    "organization",
    "credential-template",
    "issuance",
    "issuance-native",
    "canvas-sync-worker",
    "notification",
    "compliance-profile",
    "presentation-policy",
    "deployment-profile",
    "signing-keys",
    "flow",
    "verification",
    "revocation-profile",
    "event-stream",
    "installer-ingress",
];

fn require(condition: bool) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}
fn scalar(value: &str) -> Result<()> {
    require(
        !value.is_empty()
            && value.len() <= 2_048
            && value.trim() == value
            && !value
                .chars()
                .any(|v| v.is_control() || v == '\'' || v == '\\'),
    )
}
fn digest(bytes: &[u8]) -> String {
    crate::installer_release::sha256(bytes)
}
fn bytes(path: &Path) -> Result<Vec<u8>> {
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
fn decode<T: serde::de::DeserializeOwned>(value: &[u8]) -> Result<T> {
    serde_json::from_value(installer_json::decode(value).map_err(|_| REFUSED)?)
        .map_err(|_| REFUSED.into())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct KeyReference {
    pub region: String,
    pub key_arn: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TlsInput {
    pub region: String,
    pub key_arn: String,
    pub certificate_file: PathBuf,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
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
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityInput {
    role_arn: String,
    directory: PathBuf,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Configuration {
    schema: String,
    foundation: String,
    pub public_origin: String,
    pub external_oidc: ExternalOidc,
    workload_ca_file: PathBuf,
    ingress_ca_file: PathBuf,
    pub tls: BTreeMap<String, TlsInput>,
    signing_grant_authorities_file: PathBuf,
    pub integration_secret: KeyReference,
    pub notification_secret: KeyReference,
    workload_identities: BTreeMap<String, IdentityInput>,
    registration_file: PathBuf,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportedFile {
    source: PathBuf,
    sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WorkloadIdentity {
    pub role_arn: String,
    pub projection: CredentialProjection,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Selection {
    schema: String,
    installation_id: uuid::Uuid,
    source_sha256: String,
    pub(crate) registration_sha256: String,
    pub configuration: Configuration,
    files: BTreeMap<String, ImportedFile>,
    pub identities: BTreeMap<String, WorkloadIdentity>,
    iam_isolation_observed: bool,
    cloud_resources_created: bool,
}

impl Configuration {
    fn validate(&self) -> Result<()> {
        require(self.schema == "elevenid.installer-foundation/v1" && self.foundation == "aws-kms")?;
        crate::installer_application_env::origin_port(&self.public_origin)?;
        for value in [
            &self.external_oidc.issuer_url,
            &self.external_oidc.client_id,
            &self.external_oidc.admin_email,
        ] {
            scalar(value)?;
        }
        let issuer = url::Url::parse(&self.external_oidc.issuer_url).map_err(|_| REFUSED)?;
        require(
            issuer.scheme() == "https"
                && issuer.host_str().is_some()
                && issuer.username().is_empty()
                && issuer.password().is_none()
                && issuer.query().is_none()
                && issuer.fragment().is_none()
                && self.external_oidc.admin_email.contains('@')
                && self.external_oidc.trusted_endpoint_origins.len() <= 8
                && !self.external_oidc.allowed_algorithms.is_empty()
                && self.external_oidc.allowed_algorithms.len() <= 16,
        )?;
        let mut origins = BTreeSet::new();
        for value in &self.external_oidc.trusted_endpoint_origins {
            scalar(value)?;
            let parsed = url::Url::parse(value).map_err(|_| REFUSED)?;
            require(
                parsed.scheme() == "https"
                    && parsed.host_str().is_some()
                    && parsed.username().is_empty()
                    && parsed.password().is_none()
                    && parsed.query().is_none()
                    && parsed.fragment().is_none()
                    && parsed.path() == "/"
                    && parsed.origin().ascii_serialization() == *value
                    && origins.insert(value),
            )?;
        }
        let mut algorithms = BTreeSet::new();
        for value in &self.external_oidc.allowed_algorithms {
            scalar(value)?;
            // These are the asymmetric OIDC JOSE algorithms supported by the
            // existing ID-token owner; actual issuer metadata/JWKS remain Auth's check.
            require(
                [
                    "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384",
                    "ES512", "EdDSA",
                ]
                .contains(&value.as_str())
                    && algorithms.insert(value),
            )?;
        }
        let roles: BTreeSet<_> = SELFHOST_ROLES
            .iter()
            .map(|v| v.name)
            .chain(["installer-ingress"])
            .collect();
        require(self.tls.keys().map(String::as_str).collect::<BTreeSet<_>>() == roles)?;
        let mut keys = BTreeSet::new();
        for value in self.tls.values() {
            scalar(&value.region)?;
            scalar(&value.key_arn)?;
            mmf_aws_kms::validate_key_arn(&value.key_arn, &value.region).map_err(|_| REFUSED)?;
            require(keys.insert(&value.key_arn))?;
        }
        for value in [&self.integration_secret, &self.notification_secret] {
            scalar(&value.region)?;
            scalar(&value.key_arn)?;
            mmf_aws_kms::validate_key_arn(&value.key_arn, &value.region).map_err(|_| REFUSED)?;
            require(keys.insert(&value.key_arn))?;
        }
        require(
            self.workload_identities
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
                == WORKLOADS.iter().copied().collect(),
        )?;
        let mut identities = BTreeSet::new();
        for (workload, identity) in &self.workload_identities {
            scalar(&identity.role_arn)?;
            require(
                mmf_aws_kms::valid_role_arn(&identity.role_arn)
                    && !identity.role_arn.contains(['*', '?'])
                    && identities.insert(&identity.role_arn)
                    && identity.directory.file_name().and_then(|v| v.to_str())
                        == Some(workload.as_str()),
            )?;
        }
        Ok(())
    }

    fn imported_paths(&self) -> BTreeMap<String, PathBuf> {
        let mut paths = BTreeMap::from([
            (
                "workload_identity_ca_cert".into(),
                self.workload_ca_file.clone(),
            ),
            (
                "installer_ingress_ca_cert".into(),
                self.ingress_ca_file.clone(),
            ),
            (
                "installer_ingress_tls_cert".into(),
                self.tls["installer-ingress"].certificate_file.clone(),
            ),
            (
                "signing_grant_authorities".into(),
                self.signing_grant_authorities_file.clone(),
            ),
        ]);
        for role in SELFHOST_ROLES {
            paths.insert(
                role.cert_file.into(),
                self.tls[role.name].certificate_file.clone(),
            );
        }
        if let Some(path) = &self.external_oidc.client_secret_file {
            paths.insert("external_oidc_client_secret".into(), path.clone());
        }
        paths
    }
}

/// Called only from a fresh, authenticated install before Provisioning. The
/// record binds inputs, not a successful AWS/IAM/identity qualification.
pub(crate) fn select(path: &Path, installation: &Path, state: &mut InstallerState) -> Result<()> {
    state.require_live_phase(Phase::Verified)?;
    let raw = bytes(path)?;
    let configuration: Configuration = decode(&raw)?;
    configuration.validate()?;
    let mut files = BTreeMap::new();
    let mut imported = BTreeMap::new();
    for (name, path) in configuration.imported_paths() {
        let content = bytes(&path)?;
        files.insert(
            name.clone(),
            ImportedFile {
                source: path,
                sha256: digest(&content),
            },
        );
        imported.insert(name, content);
    }
    validate_imports(&imported)?;
    let mut identities = BTreeMap::new();
    for (workload, input) in &configuration.workload_identities {
        require(
            !input.directory.starts_with(installation)
                && !installation.starts_with(&input.directory),
        )?;
        let projection = CredentialProjection::observe(&input.directory, REFUSED)?;
        for other in identities.values() {
            let other: &WorkloadIdentity = other;
            require(
                !projection
                    .directory
                    .starts_with(&other.projection.directory)
                    && !other
                        .projection
                        .directory
                        .starts_with(&projection.directory),
            )?;
        }
        identities.insert(
            workload.clone(),
            WorkloadIdentity {
                role_arn: input.role_arn.clone(),
                projection,
            },
        );
    }
    let registration = bytes(&configuration.registration_file)?;
    crate::installer_kms::validate_registration(&registration)?;
    let selection = Selection {
        schema: "elevenid.installer-foundation-selection/v1".into(),
        installation_id: state.journal().installation_id(),
        source_sha256: digest(&raw),
        registration_sha256: digest(&registration),
        configuration,
        files,
        identities,
        iam_isolation_observed: false,
        cloud_resources_created: false,
    };
    state.write_evidence(REGISTRATION, &registration)?;
    state.write_evidence(
        RECORD,
        &serde_json::to_vec(&selection).map_err(|_| REFUSED)?,
    )
}

fn selected(raw: &[u8], installation_id: uuid::Uuid) -> Result<Selection> {
    let selected: Selection = decode(raw)?;
    selected.configuration.validate()?;
    require(
        selected.schema == "elevenid.installer-foundation-selection/v1"
            && selected.installation_id == installation_id
            && !selected.iam_isolation_observed
            && !selected.cloud_resources_created
            && selected
                .identities
                .keys()
                .eq(selected.configuration.workload_identities.keys())
            && hash(&selected.source_sha256)
            && hash(&selected.registration_sha256),
    )?;
    let paths = selected.configuration.imported_paths();
    require(
        paths.len() == selected.files.len()
            && paths.iter().all(|(name, path)| {
                selected
                    .files
                    .get(name)
                    .is_some_and(|file| &file.source == path && hash(&file.sha256))
            }),
    )?;
    for (workload, identity) in &selected.identities {
        let configured = &selected.configuration.workload_identities[workload];
        require(
            configured.role_arn == identity.role_arn
                && configured.directory == identity.projection.directory,
        )?;
        identity.projection.verify(REFUSED)?;
    }
    Ok(selected)
}

fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
}

fn validate_imports(values: &BTreeMap<String, Vec<u8>>) -> Result<()> {
    marty_signing_grant::configuration::AwsGrantConfiguration::decode(
        &values["signing_grant_authorities"],
    )
    .map_err(|_| REFUSED)?;
    for role in SELFHOST_ROLES {
        crate::operator_certificates::check_chain(
            &values[role.cert_file],
            &values["workload_identity_ca_cert"],
        )
        .map_err(|_| REFUSED)?;
    }
    crate::installer_trust::validate_imported_ingress(
        &values["installer_ingress_ca_cert"],
        &values["installer_ingress_tls_cert"],
    )
    .map_err(|_| REFUSED)?;
    Ok(())
}

pub(crate) fn load(state: &LockedInspection) -> Result<Option<Selection>> {
    state
        .diagnostic_record(RECORD, true)?
        .map(|raw| selected(&raw, state.journal().installation_id()))
        .transpose()
}

pub(crate) fn record(
    installation: &Path,
    installation_id: uuid::Uuid,
) -> Result<Option<(Vec<u8>, Selection)>> {
    let path = installation.join("evidence").join(RECORD);
    match std::fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(REFUSED.into()),
        Ok(_) => {}
    }
    let raw = bytes(&path)?;
    let selection = selected(&raw, installation_id)?;
    Ok(Some((raw, selection)))
}

pub(crate) fn for_inputs(inputs: &ComposeInputs) -> Result<Option<Selection>> {
    let path = inputs.installation.join("evidence").join(RECORD);
    if !inputs.bound_inputs.iter().any(|file| file.path == path) {
        match std::fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            _ => return Err(REFUSED.into()),
        }
    }
    let journal = InstallerState::inspect(&inputs.installation)?;
    let (raw, selection) =
        record(&inputs.installation, journal.installation_id())?.ok_or(REFUSED)?;
    require(
        inputs.project == journal.compose_project()
            && inputs.bound_inputs.iter().any(|file| {
                file.path == inputs.installation.join("evidence").join(RECORD)
                    && file.sha256 == digest(&raw)
            }),
    )?;
    Ok(Some(selection))
}

impl Selection {
    pub(crate) fn import_inputs(&self, state: &mut InstallerState) -> Result<()> {
        state.require_live_phase(Phase::Provisioning)?;
        require(self.installation_id == state.journal().installation_id())?;
        let mut values = BTreeMap::new();
        for (name, selected) in &self.files {
            let content = bytes(&selected.source)?;
            require(digest(&content) == selected.sha256)?;
            values.insert(name.clone(), content);
        }
        validate_imports(&values)?;
        values
            .entry("external_oidc_client_secret".into())
            .or_default();
        state.stage_application_inputs(&values)
    }

    pub(crate) fn apply_environment(&self, values: &mut BTreeMap<String, String>) -> Result<()> {
        let config = &self.configuration;
        values.retain(|name, _| {
            !(name.starts_with("KEYCLOAK_")
                || name.starts_with("SELFHOST_OPENBAO_")
                || name.starts_with("MARTY_KEYCLOAK_")
                || name == "MARTY_OPENBAO_DIDCOMM_IMAGE"
                || name == "BAO_ADDR"
                || name.ends_with("_TLS_KMS_ADDR")
                || name.ends_with("_TLS_KMS_KEY_NAME")
                || name.ends_with("_TLS_KMS_KEY_VERSION"))
        });
        values.insert(
            "MARTY_ORG_ADMIN_EMAIL".into(),
            config.external_oidc.admin_email.clone(),
        );
        for (name, value) in [
            (
                "MARTY_EXTERNAL_OIDC_ISSUER",
                config.external_oidc.issuer_url.clone(),
            ),
            (
                "MARTY_EXTERNAL_OIDC_CLIENT_ID",
                config.external_oidc.client_id.clone(),
            ),
            (
                "MARTY_EXTERNAL_OIDC_TRUSTED_ORIGINS",
                config.external_oidc.trusted_endpoint_origins.join(","),
            ),
            (
                "MARTY_EXTERNAL_OIDC_ALGORITHMS",
                config.external_oidc.allowed_algorithms.join(","),
            ),
            (
                "MARTY_EXTERNAL_OIDC_SECRET_FILE",
                if config.external_oidc.client_secret_file.is_some() {
                    "/run/secrets/external_oidc_client_secret".into()
                } else {
                    String::new()
                },
            ),
            (
                "MARTY_INTEGRATION_SECRET_AWS_REGION",
                config.integration_secret.region.clone(),
            ),
            (
                "MARTY_INTEGRATION_SECRET_AWS_KEY_ARN",
                config.integration_secret.key_arn.clone(),
            ),
            (
                "MARTY_NOTIFICATION_SECRET_AWS_REGION",
                config.notification_secret.region.clone(),
            ),
            (
                "MARTY_NOTIFICATION_SECRET_AWS_KEY_ARN",
                config.notification_secret.key_arn.clone(),
            ),
        ] {
            values.insert(name.into(), value);
        }
        for (role, tls) in &config.tls {
            let prefix = format!(
                "MARTY_AWS_TLS_{}",
                role.replace('-', "_").to_ascii_uppercase()
            );
            values.insert(format!("{prefix}_REGION"), tls.region.clone());
            values.insert(format!("{prefix}_KEY_ARN"), tls.key_arn.clone());
        }
        for (workload, identity) in &self.identities {
            let prefix = format!(
                "MARTY_AWS_{}",
                workload.replace('-', "_").to_ascii_uppercase()
            );
            values.insert(format!("{prefix}_ROLE_ARN"), identity.role_arn.clone());
            let path = identity.projection.directory.to_str().ok_or(REFUSED)?;
            scalar(path)?;
            values.insert(format!("{prefix}_IDENTITY_DIR"), path.into());
        }
        Ok(())
    }

    pub(crate) fn bind_inputs(&self, inputs: &mut ComposeInputs) {
        inputs.readonly_bind_roots.extend(
            self.identities
                .values()
                .map(|v| v.projection.directory.clone()),
        );
    }

    pub(crate) fn verify_imported(&self, values: &BTreeMap<String, Vec<u8>>) -> Result<()> {
        require(self.files.iter().all(|(name, file)| {
            values
                .get(name)
                .is_some_and(|value| digest(value) == file.sha256)
        }))
    }

    /// Deployment-specific wiring guard, after native Compose resolves the
    /// authenticated layers. IAM policies and network isolation are external
    /// prerequisites; structural checks cannot claim those properties.
    pub(crate) fn validate_model(&self, model: &Value) -> Result<()> {
        let services = model["services"].as_object().ok_or(REFUSED)?;
        for (role, service) in services {
            require(
                !role.contains("openbao")
                    && !["keycloak", "keycloak-configurator", "kms-initialize"]
                        .contains(&role.as_str()),
            )?;
            let environment = service["environment"].as_object().ok_or(REFUSED)?;
            require(
                environment
                    .get("AWS_EC2_METADATA_DISABLED")
                    .is_some_and(|v| v == "true"),
            )?;
            require(environment.iter().all(|(name, value)| {
                value.is_null()
                    || !(name.starts_with("BAO_")
                        || name.contains("OPENBAO")
                        || name.ends_with("_KMS_TOKEN_FILE")
                        || name.ends_with("_SIGN_GRANT_MINT_TOKEN_FILE")
                        || name == "SIGNING_KEYS_GRANT_VERIFY_TOKEN_FILE")
            }))?;
            let mounts = service["volumes"]
                .as_array()
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            require(
                ![
                    "AWS_ACCESS_KEY_ID",
                    "AWS_SECRET_ACCESS_KEY",
                    "AWS_SESSION_TOKEN",
                    "AWS_PROFILE",
                    "AWS_SHARED_CREDENTIALS_FILE",
                    "AWS_CONFIG_FILE",
                    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
                    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
                ]
                .iter()
                .any(|key| environment.get(*key).is_some_and(|v| !v.is_null())),
            )?;
            for (workload, identity) in &self.identities {
                identity.projection.verify(REFUSED)?;
                for mount in mounts.iter().filter(|mount| mount["type"] == "bind") {
                    let source = config_path(&mount["source"])?;
                    require(
                        (!source.starts_with(&identity.projection.directory)
                            && !identity.projection.directory.starts_with(&source))
                            || (source == identity.projection.directory && role == workload),
                    )?;
                }
                let projected = mounts
                    .iter()
                    .filter(|mount| {
                        mount["type"] == "bind"
                            && config_path(&mount["source"]).ok().as_ref()
                                == Some(&identity.projection.directory)
                    })
                    .collect::<Vec<_>>();
                if role == workload {
                    require(
                        projected.len() == 1
                            && projected[0]["read_only"] == true
                            && projected[0]["target"] == CredentialProjection::TARGET
                            && environment
                                .get("AWS_ROLE_ARN")
                                .is_some_and(|v| v == &identity.role_arn)
                            && environment
                                .get("AWS_WEB_IDENTITY_TOKEN_FILE")
                                .is_some_and(|v| v == "/run/aws-identity/token"),
                    )?;
                } else {
                    require(projected.is_empty())?;
                }
            }
        }
        // Native Compose can omit inactive setup profiles during ordinary
        // lifecycle operations. Every present workload is checked above.
        Ok(())
    }
}

#[cfg(test)]
#[path = "installer_foundation_tests.rs"]
mod tests;
