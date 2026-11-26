//! Immutable, explicit feature selection for a fresh native installation.
//! Selection enables service capabilities; it does not create an agent, grant,
//! consent, policy, Flow definition or signing-key authority. Those are owner
//! operations, and their configured inputs remain separately hash bound.
#![cfg(target_os = "linux")]

use crate::{
    installer_compose::ComposeInputs,
    installer_host_fs as fs,
    installer_state::{InstallerState, Journal, LockedInspection, Phase},
    installer_workflow_features as workflows,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path, PathBuf},
};

type Result<T> = std::result::Result<T, String>;
const REFUSED: &str =
    "native feature profile is absent, incomplete or changed; preserve installation evidence";
pub(crate) const SOURCE: &str = "feature-profile-input.json";
pub(crate) const RECORD: &str = "feature-profile-selection.json";
pub(crate) const CREDENTIALS: &str = "feature-profile-credentials.json";
pub(crate) const TRANSPORT: &str = "feature-postgres-transport.json";
pub(crate) const ACTIVATION: &str = "feature-profile-activation.json";
pub(crate) const DIRECTORY: &str = "feature-profile-secrets";
pub(crate) const IDENTITY_SELECTION: &str = "feature-identities.json";
pub(crate) const LAYER_ROOT: &str = "deploy-config/compose/selfhost-installer/feature-profile/";
const SCHEMA: &str = "elevenid.installer-feature-profile/v1";
const SELECTION_SCHEMA: &str = "elevenid.installer-feature-profile-selection/v1";
const MAX_INPUT: usize = 65_536;

pub(crate) fn append_layer(inputs: &mut ComposeInputs, layer: crate::installer_compose::BoundFile) {
    let index = if inputs.files.last().is_some_and(|file| {
        file.path.file_name().and_then(|name| name.to_str())
            == Some("development-signing-image.compose.json")
    }) {
        inputs.files.len() - 1
    } else {
        inputs.files.len()
    };
    inputs.files.insert(index, layer);
}
#[path = "installer_feature_generations.rs"]
pub(crate) mod generations;
pub(crate) use generations::{initialize_generations, verify_generations};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Configuration {
    schema: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) agent_trust: Option<AgentTrust>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) workflows: Option<workflows::Configuration>,
}

/// These four human/owner capabilities are selected together. There is no raw
/// environment, service URL, image, arbitrary layer, role or permission input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AgentTrust {
    pub(crate) organization_id: uuid::Uuid,
    pub(crate) enrollment: Enrollment,
    pub(crate) approval: Approval,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) delegated_use: Option<DelegatedUse>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Enrollment {
    pub(crate) audience: String,
    pub(crate) policy_profile: String,
    pub(crate) policy_revision: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Approval {
    pub(crate) profile: String,
    pub(crate) version: String,
    pub(crate) status_ref: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "activation", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum DelegatedUse {
    AwaitingOwnerConfiguration {},
    Configured {
        configuration: Box<DelegatedUseConfiguration>,
    },
}

/// Only governed identifiers and public metadata enter this document. Private
/// proofs are imported from individually owned files and never copied into the
/// public selection or Compose environment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DelegatedUseConfiguration {
    pub(crate) deployment_profile_id: uuid::Uuid,
    pub(crate) delegation_policy_id: uuid::Uuid,
    pub(crate) flow_definition_id: String,
    pub(crate) flow_definition_version: u32,
    pub(crate) public_base_url: String,
    pub(crate) verifier_did: String,
    pub(crate) verifier_display_name: String,
    pub(crate) receipt_issuer_did: String,
    pub(crate) receipt_algorithm: String,
    pub(crate) receipt_key_id: String,
    pub(crate) receipt_key_reference: String,
    pub(crate) receipt_public_jwk_file: PathBuf,
    pub(crate) workload_bindings_file: PathBuf,
    #[serde(default)]
    pub(crate) public_caller: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Fingerprint {
    sha256: String,
    size_bytes: u64,
}

pub(crate) struct Prepared {
    raw: Vec<u8>,
    configuration: Configuration,
    imports: BTreeMap<String, Fingerprint>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Selection {
    schema: String,
    installation_id: uuid::Uuid,
    source_sha256: String,
    configuration: Configuration,
    imports: BTreeMap<String, Fingerprint>,
    #[serde(skip)]
    generation: Option<generations::SelectedMaterial>,
}

fn require(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
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
fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn scalar(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.is_ascii()
        && value.trim() == value
        && !value
            .chars()
            .any(|c| c.is_control() || matches!(c, '\'' | '\\' | '$' | '`'))
        && !value.contains("PRIVATE KEY")
}
fn identifier(value: &str) -> bool {
    scalar(value, 128)
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
}
fn uri(value: &str) -> bool {
    scalar(value, 512)
        && url::Url::parse(value).is_ok_and(|url| {
            !url.scheme().is_empty()
                && url.username().is_empty()
                && url.password().is_none()
                && url.fragment().is_none()
        })
}
fn https(value: &str, origin: bool) -> bool {
    uri(value)
        && url::Url::parse(value).is_ok_and(|url| {
            url.scheme() == "https"
                && url.has_host()
                && (!origin
                    || (url.path() == "/"
                        && url.query().is_none()
                        && url.origin().ascii_serialization() == value))
        })
}
fn safe_path(path: &Path) -> bool {
    path.is_absolute()
        && path != Path::new("/")
        && path
            .components()
            .all(|p| matches!(p, Component::RootDir | Component::Normal(_)))
        && path.to_str().is_some_and(|text| {
            scalar(text, 4096)
                && !text.ends_with('/')
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
    let bytes = fs::read_entry(
        &parent,
        path.file_name().and_then(|v| v.to_str()).ok_or(REFUSED)?,
        0o600,
        false,
        REFUSED,
    )?;
    fs::require_directory_binding(parent_path, &parent, REFUSED)?;
    require(
        !bytes.is_empty()
            && bytes.len() <= MAX_INPUT
            && !bytes.windows(11).any(|v| v == b"PRIVATE KEY"),
    )?;
    Ok(bytes)
}
fn decode<T: serde::de::DeserializeOwned>(raw: &[u8]) -> Result<T> {
    require(!raw.is_empty() && raw.len() <= MAX_INPUT)?;
    serde_json::from_value(crate::installer_json::decode(raw).map_err(|_| REFUSED)?)
        .map_err(|_| REFUSED.into())
}

impl AgentTrust {
    fn validate(&self) -> Result<()> {
        require(
            !self.organization_id.is_nil()
                && uri(&self.enrollment.audience)
                && uri(&self.enrollment.policy_profile)
                && self.enrollment.policy_revision > 0
                && uri(&self.approval.profile)
                && scalar(&self.approval.version, 64)
                && self
                    .approval
                    .version
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                && https(&self.approval.status_ref, false),
        )?;
        if let Some(DelegatedUse::Configured { configuration }) = &self.delegated_use {
            configuration.validate()?;
        }
        Ok(())
    }
    pub(crate) fn use_configuration(&self) -> Option<&DelegatedUseConfiguration> {
        match &self.delegated_use {
            Some(DelegatedUse::Configured { configuration }) => Some(configuration),
            _ => None,
        }
    }
}

impl DelegatedUseConfiguration {
    fn validate(&self) -> Result<()> {
        let did = |value: &str| {
            scalar(value, 512)
                && ["did:web:", "did:jwk:", "did:key:"]
                    .iter()
                    .any(|prefix| value.starts_with(prefix))
        };
        require(
            !self.deployment_profile_id.is_nil()
                && !self.delegation_policy_id.is_nil()
                && identifier(&self.flow_definition_id)
                && self.flow_definition_version > 0
                && https(&self.public_base_url, self.public_caller)
                && !self.public_base_url.ends_with('/')
                && did(&self.verifier_did)
                && did(&self.receipt_issuer_did)
                && scalar(&self.verifier_display_name, 128)
                && matches!(self.receipt_algorithm.as_str(), "ES256" | "EdDSA")
                && scalar(&self.receipt_key_id, 512)
                && scalar(&self.receipt_key_reference, 512)
                && safe_path(&self.receipt_public_jwk_file)
                && safe_path(&self.workload_bindings_file),
        )
    }
    fn input_files(&self) -> BTreeMap<String, PathBuf> {
        BTreeMap::from([
            (
                "feature_delegated_use_receipt_public_jwk".into(),
                self.receipt_public_jwk_file.clone(),
            ),
            (
                "feature_delegated_use_workload_bindings".into(),
                self.workload_bindings_file.clone(),
            ),
        ])
    }
    fn validate_imported(&self, files: &BTreeMap<String, Vec<u8>>) -> Result<()> {
        self.validate()?;
        let jwk: Value = decode(
            files
                .get("feature_delegated_use_receipt_public_jwk")
                .ok_or(REFUSED)?,
        )?;
        let object = jwk.as_object().ok_or(REFUSED)?;
        require(
            !["d", "p", "q", "dp", "dq", "qi", "oth", "k"]
                .iter()
                .any(|key| object.contains_key(*key)),
        )?;
        require(match self.receipt_algorithm.as_str() {
            "ES256" => {
                jwk["kty"] == "EC"
                    && jwk["crv"] == "P-256"
                    && jwk["x"].is_string()
                    && jwk["y"].is_string()
            }
            "EdDSA" => jwk["kty"] == "OKP" && jwk["crv"] == "Ed25519" && jwk["x"].is_string(),
            _ => false,
        })?;
        let bindings: Value = decode(
            files
                .get("feature_delegated_use_workload_bindings")
                .ok_or(REFUSED)?,
        )?;
        let bindings = bindings.as_array().ok_or(REFUSED)?;
        require((1..=128).contains(&bindings.len()))?;
        let mut uris = BTreeSet::new();
        let mut pins = BTreeSet::new();
        for binding in bindings {
            let object = binding.as_object().ok_or(REFUSED)?;
            require(
                object.keys().map(String::as_str).collect::<BTreeSet<_>>()
                    == BTreeSet::from(["workload_uri", "leaf_sha256", "principal_id"]),
            )?;
            let workload = binding["workload_uri"].as_str().ok_or(REFUSED)?;
            let pin = binding["leaf_sha256"].as_str().ok_or(REFUSED)?;
            require(
                uri(workload)
                    && workload.starts_with("spiffe://")
                    && uris.insert(workload)
                    && pin.strip_prefix("sha256:").is_some_and(hash)
                    && pins.insert(pin)
                    && binding["principal_id"].as_str().is_some_and(uri),
            )?;
        }
        Ok(())
    }
}

impl Configuration {
    fn validate(&self) -> Result<()> {
        require(self.schema == SCHEMA && (self.agent_trust.is_some() || self.workflows.is_some()))?;
        if let Some(agent) = &self.agent_trust {
            agent.validate()?;
        }
        if let Some(workflows) = &self.workflows {
            workflows.validate()?;
        }
        Ok(())
    }
    fn input_files(&self) -> Result<BTreeMap<String, PathBuf>> {
        self.validate()?;
        let mut files = self
            .workflows
            .as_ref()
            .map(|w| w.input_files())
            .transpose()?
            .unwrap_or_default();
        if let Some(configuration) = self
            .agent_trust
            .as_ref()
            .and_then(AgentTrust::use_configuration)
        {
            files.extend(configuration.input_files());
        }
        require(files.values().collect::<BTreeSet<_>>().len() == files.len())?;
        Ok(files)
    }
    fn validate_imported(&self, files: &BTreeMap<String, Vec<u8>>) -> Result<()> {
        if let Some(workflows) = &self.workflows {
            workflows.validate_imported(files)?;
        }
        if let Some(configuration) = self
            .agent_trust
            .as_ref()
            .and_then(AgentTrust::use_configuration)
        {
            configuration.validate_imported(files)?;
        }
        Ok(())
    }
}

pub(crate) fn prepare(path: Option<&Path>, managed_postgres: bool) -> Result<Option<Prepared>> {
    let Some(path) = path else {
        return Ok(None);
    };
    require(managed_postgres)?;
    let raw = private_bytes(path)?;
    let configuration: Configuration = decode(&raw)?;
    let mut imported = BTreeMap::new();
    for (name, path) in configuration.input_files()? {
        imported.insert(name, private_bytes(&path)?);
    }
    configuration.validate_imported(&imported)?;
    let imports = imported
        .iter()
        .map(|(name, raw)| (name.clone(), fingerprint(raw)))
        .collect();
    Ok(Some(Prepared {
        raw,
        configuration,
        imports,
    }))
}

pub(crate) fn select(prepared: Option<Prepared>, state: &mut InstallerState) -> Result<()> {
    let Some(prepared) = prepared else {
        return Ok(());
    };
    state.require_live_phase(Phase::Verified)?;
    require(
        state.journal().feature_profile_sha256().is_none()
            && state
                .journal()
                .external_postgres_selection_sha256()
                .is_none()
            && state.journal().runtime().is_some_and(|runtime| {
                runtime.profile == crate::installer_state::RuntimeProfile::Rootless
            })
            && state
                .with_inspection(crate::installer_foundation::load)?
                .is_none(),
    )?;
    let selection = Selection {
        schema: SELECTION_SCHEMA.into(),
        installation_id: state.journal().installation_id(),
        source_sha256: digest(&prepared.raw),
        configuration: prepared.configuration,
        imports: prepared.imports,
        generation: None,
    };
    let raw = serde_json::to_vec(&selection).map_err(|_| REFUSED)?;
    state.write_evidence(SOURCE, &prepared.raw)?;
    state.write_evidence(RECORD, &raw)?;
    state.bind_feature_profile(&digest(&raw))?;
    state.with_inspection(|view| load(view).map(|_| ()))
}

fn decoded(raw: &[u8], source: &[u8], journal: &Journal) -> Result<Selection> {
    require(
        journal.feature_profile_sha256() == Some(digest(raw).as_str())
            && journal.external_postgres_selection_sha256().is_none()
            && journal.runtime().is_some_and(|runtime| {
                runtime.profile == crate::installer_state::RuntimeProfile::Rootless
            }),
    )?;
    let selected: Selection = decode(raw)?;
    let configuration: Configuration = decode(source)?;
    require(
        selected.schema == SELECTION_SCHEMA
            && selected.installation_id == journal.installation_id()
            && selected.source_sha256 == digest(source)
            && selected.configuration == configuration,
    )?;
    let files = configuration.input_files()?;
    require(
        files.keys().collect::<BTreeSet<_>>() == selected.imports.keys().collect::<BTreeSet<_>>()
            && selected
                .imports
                .values()
                .all(|v| hash(&v.sha256) && (1..=MAX_INPUT as u64).contains(&v.size_bytes)),
    )?;
    Ok(selected)
}

pub(crate) fn load(view: &LockedInspection) -> Result<Option<Selection>> {
    let raw = view.diagnostic_record(RECORD, true)?;
    let source = view.diagnostic_record(SOURCE, true)?;
    if view.journal().feature_profile_sha256().is_none() {
        require(raw.is_none() && source.is_none())?;
        return Ok(None);
    }
    require(crate::installer_foundation::load(view)?.is_none())?;
    decoded(
        &raw.ok_or(REFUSED)?,
        &source.ok_or(REFUSED)?,
        view.journal(),
    )
    .map(Some)
}

pub(crate) fn at(installation: &Path) -> Result<Option<Selection>> {
    let journal = InstallerState::inspect(installation)?;
    let evidence = installation.join("evidence");
    if journal.feature_profile_sha256().is_none() {
        for name in [
            SOURCE,
            RECORD,
            CREDENTIALS,
            TRANSPORT,
            ACTIVATION,
            IDENTITY_SELECTION,
            generations::RECORD,
        ] {
            require(
                std::fs::symlink_metadata(evidence.join(name))
                    .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            )?;
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
    let selection = at(&inputs.installation)?
        .map(|selection| generations::selected_for_inputs(selection, inputs))
        .transpose()?;
    for name in [
        SOURCE,
        RECORD,
        CREDENTIALS,
        TRANSPORT,
        IDENTITY_SELECTION,
        generations::RECORD,
    ] {
        let path = inputs.installation.join("evidence").join(name);
        let matches: Vec<_> = inputs
            .bound_inputs
            .iter()
            .filter(|f| f.path == path)
            .collect();
        let exists = match std::fs::symlink_metadata(&path) {
            Ok(_) => true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(_) => return Err(REFUSED.into()),
        };
        if selection.is_some() && exists {
            require(matches.len() == 1 && matches[0].sha256 == digest(&private_bytes(&path)?))?;
        } else {
            require(matches.is_empty() && !exists)?;
        }
    }
    if let Some(selected) = &selection {
        require(
            inputs.project == InstallerState::inspect(&inputs.installation)?.compose_project(),
        )?;
        selected.validate_layers(inputs)?;
    }
    Ok(selection)
}

impl Selection {
    pub(crate) fn projection_directory(&self, installation: &Path) -> PathBuf {
        self.generation.as_ref().map_or_else(
            || installation.join(DIRECTORY),
            |generation| generation.directory(installation),
        )
    }
    pub(crate) fn profile_sha256(&self) -> Result<String> {
        if let Some(generation) = &self.generation {
            return Ok(generation.feature_profile_sha256.clone());
        }
        Ok(digest(&serde_json::to_vec(self).map_err(|_| REFUSED)?))
    }
    pub(crate) fn initial_secrets(&self) -> Result<BTreeMap<String, Vec<u8>>> {
        let mut files = BTreeMap::new();
        for (name, path) in self.configuration.input_files()? {
            let bytes = private_bytes(&path)?;
            require(self.imports.get(&name) == Some(&fingerprint(&bytes)))?;
            files.insert(name, bytes);
        }
        self.configuration.validate_imported(&files)?;
        Ok(files)
    }
    pub(crate) fn identity_selection(
        &self,
    ) -> Result<Option<marty_selfhost_identity::features::Selection>> {
        let workflows = self.configuration.workflows.as_ref();
        let selected = marty_selfhost_identity::features::Selection {
            schema: marty_selfhost_identity::features::SCHEMA.into(),
            installation_id: self.installation_id.to_string(),
            feature_profile_sha256: self.profile_sha256()?,
            operation: marty_selfhost_identity::features::Operation::Provision,
            wallet_governance: workflows.is_some_and(|w| w.wallet_governance.is_some()),
            public_verification: workflows.is_some_and(|w| w.public_verification.is_some()),
            delegated_use: self
                .configuration
                .agent_trust
                .as_ref()
                .is_some_and(|a| a.delegated_use.is_some()),
        };
        if !(selected.wallet_governance || selected.public_verification || selected.delegated_use) {
            return Ok(None);
        }
        selected.validate().map_err(|_| REFUSED)?;
        Ok(Some(selected))
    }
    pub(crate) fn credential_names(&self) -> Result<BTreeSet<String>> {
        let mut names = crate::installer_feature_database::credential_names();
        names.insert("feature_postgres_ca".into());
        names.extend(self.imports.keys().cloned());
        if let Some(identity) = self.identity_selection()? {
            names.extend(identity.output_names());
            if identity.delegated_use {
                names.insert(workflows::SIGNING_READ_KEY.into());
            }
        }
        if let Some(workflows) = &self.configuration.workflows {
            names.extend(
                workflows
                    .generated_secret_names()
                    .into_iter()
                    .map(str::to_owned),
            );
        }
        Ok(names)
    }
    pub(crate) fn verify_imported(&self, values: &BTreeMap<String, Vec<u8>>) -> Result<()> {
        for (name, expected) in &self.imports {
            require(
                values
                    .get(name)
                    .is_some_and(|bytes| fingerprint(bytes) == *expected),
            )?;
        }
        self.configuration.validate_imported(values)
    }
    pub(crate) fn bind_inputs(&self, inputs: &mut ComposeInputs) -> Result<()> {
        for name in [
            SOURCE,
            RECORD,
            CREDENTIALS,
            TRANSPORT,
            ACTIVATION,
            IDENTITY_SELECTION,
            generations::RECORD,
        ] {
            let path = inputs.installation.join("evidence").join(name);
            let exists = match std::fs::symlink_metadata(&path) {
                Ok(_) => true,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
                Err(_) => return Err(REFUSED.into()),
            };
            if exists {
                let bound = crate::installer_application::bound(path)?;
                let old: Vec<_> = inputs
                    .bound_inputs
                    .iter()
                    .filter(|file| file.path == bound.path)
                    .collect();
                if old.is_empty() {
                    inputs.bound_inputs.push(bound);
                } else {
                    require(old.len() == 1 && old[0].sha256 == bound.sha256)?;
                }
            } else {
                require(![SOURCE, RECORD].contains(&name))?;
            }
        }
        Ok(())
    }
    pub(crate) fn layers(&self) -> Vec<&'static str> {
        let mut layers = vec![concat!(
            "deploy-config/compose/selfhost-installer/feature-profile/",
            "compose.database.yml"
        )];
        if self.configuration.agent_trust.is_some() {
            layers.push(concat!(
                "deploy-config/compose/selfhost-installer/feature-profile/",
                "compose.agent-trust.yml"
            ));
        }
        if let Some(workflows) = &self.configuration.workflows {
            layers.extend(workflows.layers());
        }
        if self
            .configuration
            .agent_trust
            .as_ref()
            .is_some_and(|agent| agent.delegated_use.is_some())
        {
            for layer in [
                "deploy-config/compose/selfhost-installer/feature-profile/compose.feature-signing.yml",
                "deploy-config/compose/selfhost-installer/feature-profile/compose.delegated-use-owners.yml",
            ] {
                if !layers.contains(&layer) {
                    layers.push(layer);
                }
            }
        }
        if self
            .configuration
            .agent_trust
            .as_ref()
            .and_then(AgentTrust::use_configuration)
            .is_some()
        {
            layers.push(concat!(
                "deploy-config/compose/selfhost-installer/feature-profile/",
                "compose.delegated-use.yml"
            ));
        }
        layers
    }
    pub(crate) fn append_layers(&self, inputs: &mut ComposeInputs, bundle: &Path) -> Result<()> {
        require(bundle.starts_with(&inputs.installation))?;
        for layer in self.layers() {
            append_layer(
                inputs,
                crate::installer_application::bundle_bound(bundle, layer)?,
            );
        }
        if inputs.files.iter().any(|file| {
            file.path
                .ends_with("selfhost-installer/compose.runtime.yml")
        }) {
            for layer in self.runtime_layers() {
                append_layer(
                    inputs,
                    crate::installer_application::bundle_bound(bundle, layer)?,
                );
            }
        }
        inputs
            .readonly_bind_roots
            .insert(self.projection_directory(&inputs.installation));
        inputs
            .readonly_bind_roots
            .insert(crate::installer_feature_postgres_tls::projection(
                &inputs.installation,
            ));
        Ok(())
    }
    fn runtime_layers(&self) -> Vec<&'static str> {
        let mut layers =
            vec!["deploy-config/compose/selfhost-installer/feature-profile/compose.runtime.yml"];
        if self.configuration.agent_trust.is_some() {
            layers.push("deploy-config/compose/selfhost-installer/feature-profile/compose.agent-runtime.yml");
        }
        if self
            .configuration
            .agent_trust
            .as_ref()
            .and_then(AgentTrust::use_configuration)
            .is_some()
        {
            layers.push("deploy-config/compose/selfhost-installer/feature-profile/compose.delegated-use-runtime.yml");
        }
        layers
    }
    fn validate_layers(&self, inputs: &ComposeInputs) -> Result<()> {
        let mut selected: BTreeSet<_> = self.layers().into_iter().collect();
        if inputs.files.iter().any(|file| {
            file.path
                .ends_with("selfhost-installer/compose.runtime.yml")
        }) {
            selected.extend(self.runtime_layers());
        }
        let mut found = BTreeSet::new();
        for file in &inputs.files {
            if let Some(text) = file
                .path
                .to_str()
                .and_then(|p| p.find(LAYER_ROOT).map(|at| &p[at..]))
            {
                require(
                    (selected.contains(text)
                        || (self.identity_selection()?.is_some()
                            && ["deploy-config/compose/selfhost-installer/feature-profile/compose.identities.yml",
                                "deploy-config/compose/selfhost-installer/feature-profile/compose.identities-renew.yml"].contains(&text)))
                        && found.insert(text),
                )?;
            }
        }
        // Bootstrap jobs deliberately omit the application profile. Once any
        // application layer is selected, its entire fixed selection is required.
        if found.iter().any(|name| selected.contains(name)) {
            require(selected.is_subset(&found))?;
        }
        Ok(())
    }
    pub(crate) fn append_environment(
        &self,
        env: &mut Vec<u8>,
        installation: &Path,
        images: &BTreeMap<String, String>,
    ) -> Result<()> {
        require(safe_path(installation))?;
        let mut values = BTreeMap::new();
        let original = std::str::from_utf8(env).map_err(|_| REFUSED)?.to_owned();
        for line in original.lines() {
            if let Some((key, value)) = line.split_once('=') {
                if key == "UI_BASE_URL" {
                    values.insert(key.into(), value.trim_matches('\'').into());
                }
            }
        }
        values.insert(
            "FEATURE_PROFILE_SECRET_DIR".into(),
            self.projection_directory(installation)
                .to_str()
                .ok_or(REFUSED)?
                .into(),
        );
        values.insert(
            "FEATURE_PROFILE_OPERATOR".into(),
            installation
                .join("marty-deploy")
                .to_str()
                .ok_or(REFUSED)?
                .into(),
        );
        values.insert(
            crate::installer_feature_postgres_tls::ENVIRONMENT.into(),
            crate::installer_feature_postgres_tls::projection(installation)
                .to_str()
                .ok_or(REFUSED)?
                .into(),
        );
        for (key, role) in [
            ("FEATURE_POSTGRES_IMAGE", "postgres"),
            ("FEATURE_MIGRATIONS_IMAGE", "db-migrate"),
            ("FEATURE_SERVICES_IMAGE", "gateway"),
        ] {
            values.insert(key.into(), images.get(role).ok_or(REFUSED)?.clone());
        }
        if let Some(workflows) = &self.configuration.workflows {
            workflows.apply_environment(&mut values)?;
        }
        if let Some(agent) = &self.configuration.agent_trust {
            let image = images.get("gateway").ok_or(REFUSED)?;
            let artifact = image
                .split_once('@')
                .map(|(_, value)| value)
                .filter(|v| v.strip_prefix("sha256:").is_some_and(hash))
                .ok_or(REFUSED)?;
            values.extend(BTreeMap::from([
                (
                    "FEATURE_ORGANIZATION_ID".into(),
                    agent.organization_id.to_string(),
                ),
                (
                    "FEATURE_ENROLLMENT_AUDIENCE".into(),
                    agent.enrollment.audience.clone(),
                ),
                (
                    "FEATURE_ENROLLMENT_POLICY_PROFILE".into(),
                    agent.enrollment.policy_profile.clone(),
                ),
                (
                    "FEATURE_ENROLLMENT_POLICY_REVISION".into(),
                    agent.enrollment.policy_revision.to_string(),
                ),
                (
                    "FEATURE_APPROVAL_PROFILE".into(),
                    agent.approval.profile.clone(),
                ),
                (
                    "FEATURE_APPROVAL_VERSION".into(),
                    agent.approval.version.clone(),
                ),
                ("FEATURE_APPROVAL_ARTIFACT_DIGEST".into(), artifact.into()),
                (
                    "FEATURE_DELEGATION_STATUS_REF".into(),
                    agent.approval.status_ref.clone(),
                ),
            ]));
            if let Some(selected) = agent.use_configuration() {
                for (key, value) in [
                    (
                        "FEATURE_USE_DEPLOYMENT_PROFILE_ID",
                        selected.deployment_profile_id.to_string(),
                    ),
                    (
                        "FEATURE_USE_DELEGATION_POLICY_ID",
                        selected.delegation_policy_id.to_string(),
                    ),
                    (
                        "FEATURE_USE_FLOW_DEFINITION_ID",
                        selected.flow_definition_id.clone(),
                    ),
                    (
                        "FEATURE_USE_FLOW_DEFINITION_VERSION",
                        selected.flow_definition_version.to_string(),
                    ),
                    (
                        "FEATURE_USE_PUBLIC_BASE_URL",
                        selected.public_base_url.clone(),
                    ),
                    ("FEATURE_USE_VERIFIER_DID", selected.verifier_did.clone()),
                    (
                        "FEATURE_USE_VERIFIER_DISPLAY_NAME",
                        selected.verifier_display_name.clone(),
                    ),
                    (
                        "FEATURE_USE_RECEIPT_ISSUER_DID",
                        selected.receipt_issuer_did.clone(),
                    ),
                    (
                        "FEATURE_USE_RECEIPT_ALGORITHM",
                        selected.receipt_algorithm.clone(),
                    ),
                    (
                        "FEATURE_USE_RECEIPT_KEY_ID",
                        selected.receipt_key_id.clone(),
                    ),
                    (
                        "FEATURE_USE_RECEIPT_KEY_REFERENCE",
                        selected.receipt_key_reference.clone(),
                    ),
                    (
                        "FEATURE_USE_PUBLIC_CALLER_ENABLED",
                        selected.public_caller.to_string(),
                    ),
                ] {
                    values.insert(key.into(), value);
                }
            }
        }
        for (key, value) in values {
            if key == "UI_BASE_URL" {
                continue;
            }
            require(scalar(&value, 4096))?;
            require(!original.lines().any(|line| {
                line.split_once('=')
                    .is_some_and(|(existing, _)| existing == key)
            }))?;
            env.extend_from_slice(format!("{key}='{value}'\n").as_bytes());
        }
        Ok(())
    }

    /// Every use of feature bytes is rechecked against the sealed directory and
    /// its manifest. A source selection alone cannot authorize a consumer.
    pub(crate) fn validate_model(&self, installation: &Path, model: &Value) -> Result<()> {
        let services = model["services"].as_object().ok_or(REFUSED)?;
        let consumes = services.iter().any(|(role, service)| {
            role.starts_with("feature-database-")
                || role.starts_with("feature-delegation-")
                || role.starts_with("feature-credential-")
                || service["volumes"].as_array().is_some_and(|volumes| {
                    volumes.iter().any(|volume| {
                        volume["source"].as_str().is_some_and(|source| {
                            Path::new(source).starts_with(installation.join(DIRECTORY))
                                || Path::new(source)
                                    .starts_with(installation.join(generations::ROOT))
                        })
                    })
                })
        });
        if consumes {
            let files = if let Some(generation) = &self.generation {
                generations::selected_files(installation, generation)?
            } else {
                crate::installer_feature_credentials::verify_at(
                    installation,
                    &self.credential_names()?,
                )?
            };
            require(files.keys().cloned().collect::<BTreeSet<_>>() == self.credential_names()?)?;
            self.verify_imported(&files)?;
            let database: BTreeMap<_, _> = crate::installer_feature_database::credential_names()
                .into_iter()
                .map(|name| {
                    files
                        .get(&name)
                        .cloned()
                        .map(|value| (name, value))
                        .ok_or(REFUSED)
                })
                .collect::<std::result::Result<_, _>>()?;
            crate::installer_feature_database::validate_credentials(&database)?;
        }
        self.validate_feature_mounts(installation, services)?;
        for (role, service) in services {
            if let Some((key, cap)) = core_pool_limit(role) {
                // Bootstrap models deliberately have no database layer.
                if consumes {
                    expect(service, key, cap)?;
                }
            }
            if ["delegation-approval", "delegation-commands"].contains(&role.as_str()) {
                exact_secrets(service, &["grpc_service_token"])?;
                let keys: &[&str] = if role == "delegation-approval" {
                    &[
                        "DELEGATION_APPROVAL_RUNTIME_POOL_MAX_CONNECTIONS",
                        "DELEGATION_APPROVAL_CONSENT_POOL_MAX_CONNECTIONS",
                        "DELEGATION_APPROVAL_AUTHORITY_POOL_MAX_CONNECTIONS",
                        "DELEGATION_APPROVAL_ORGANIZATION_POOL_MAX_CONNECTIONS",
                    ]
                } else {
                    &[
                        "DELEGATION_COMMAND_POOL_MAX_CONNECTIONS",
                        "DELEGATION_COMMAND_RUNTIME_POOL_MAX_CONNECTIONS",
                        "DELEGATION_COMMAND_ORGANIZATION_POOL_MAX_CONNECTIONS",
                    ]
                };
                for key in keys {
                    expect(service, key, "2")?;
                }
            }
            if ["feature-database-roles", "feature-database-grants"].contains(&role.as_str()) {
                exact_secrets(service, &["postgres_password"])?;
            }
            if ["feature-delegation-migrate", "feature-credential-migrate"].contains(&role.as_str())
            {
                exact_secrets(service, &[])?;
            }
        }
        if let Some(agent) = &self.configuration.agent_trust {
            for role in ["gateway", "organization"] {
                if let Some(service) = services.get(role) {
                    expect(service, "MARTY_AGENT_ADMIN_ENABLED", "true")?;
                    expect(service, "MARTY_AGENT_ENROLLMENT_ENABLED", "true")?;
                }
            }
            if let Some(gateway) = services.get("gateway") {
                expect(gateway, "MARTY_DELEGATION_APPROVAL_ENABLED", "true")?;
                expect(gateway, "MARTY_DELEGATION_COMMANDS_ENABLED", "true")?;
                expect(
                    gateway,
                    "DELEGATED_AUTHORITY_SERVICE_URL",
                    "http://delegation-approval:8019",
                )?;
                expect(
                    gateway,
                    "DELEGATED_COMMAND_SERVICE_URL",
                    "http://delegation-commands:8020",
                )?;
            }
            if let Some(organization) = services.get("organization") {
                // Organization startup creates this configured bootstrap
                // record. A fresh profile cannot name an unrelated UUID.
                expect(
                    organization,
                    "MARTY_ORG_ID",
                    &agent.organization_id.to_string(),
                )?;
                expect(
                    organization,
                    "MARTY_AGENT_ENROLLMENT_AUDIENCE",
                    &agent.enrollment.audience,
                )?;
                expect(
                    organization,
                    "MARTY_AGENT_ENROLLMENT_POLICY_PROFILE",
                    &agent.enrollment.policy_profile,
                )?;
                expect(
                    organization,
                    "MARTY_AGENT_ENROLLMENT_POLICY_REVISION",
                    &agent.enrollment.policy_revision.to_string(),
                )?;
            }
            for (role, prefix, port, urls) in [
                (
                    "delegation-approval",
                    "DELEGATION_APPROVAL",
                    "8019",
                    approval_databases(),
                ),
                (
                    "delegation-commands",
                    "DELEGATION_COMMAND",
                    "8020",
                    command_databases(),
                ),
            ] {
                if let Some(service) = services.get(role) {
                    private_runtime(service)?;
                    expect(
                        service,
                        &format!("{prefix}_HTTP_ADDR"),
                        &format!("0.0.0.0:{port}"),
                    )?;
                    expect(
                        service,
                        &format!("{prefix}_ORGANIZATION_ID"),
                        &agent.organization_id.to_string(),
                    )?;
                    let profile = if role == "delegation-approval" {
                        prefix.to_owned()
                    } else {
                        format!("{prefix}_APPROVAL")
                    };
                    expect(
                        service,
                        &format!("{profile}_PROFILE"),
                        &agent.approval.profile,
                    )?;
                    expect(
                        service,
                        &format!("{profile}_VERSION"),
                        &agent.approval.version,
                    )?;
                    let image = service["image"].as_str().ok_or(REFUSED)?;
                    let artifact = image
                        .split_once('@')
                        .map(|(_, value)| value)
                        .filter(|v| v.strip_prefix("sha256:").is_some_and(hash))
                        .ok_or(REFUSED)?;
                    expect(service, &format!("{profile}_ARTIFACT_DIGEST"), artifact)?;
                    for (key, file) in urls {
                        file_environment(service, key, &file)?;
                    }
                    expect(
                        service,
                        "GRPC_SERVICE_TOKEN_FILE",
                        "/run/secrets/grpc_service_token",
                    )?;
                    absent(service, "GRPC_SERVICE_TOKEN")?;
                    if role == "delegation-commands" {
                        expect(
                            service,
                            "DELEGATION_COMMAND_STATUS_REF",
                            &agent.approval.status_ref,
                        )?;
                    }
                    require(
                        service["depends_on"]["feature-database-grants"]["condition"]
                            == "service_completed_successfully"
                            || service["depends_on"]
                                .as_object()
                                .is_none_or(|deps| !deps.contains_key("feature-database-grants")),
                    )?;
                }
            }
            if let Some(configuration) = agent.use_configuration() {
                if let Some(service) = services.get("delegated-use") {
                    self.validate_delegated_use(service, agent, configuration)?;
                }
            } else {
                require(!services.contains_key("delegated-use"))?;
            }
        } else {
            for role in [
                "delegation-approval",
                "delegation-commands",
                "delegated-use",
            ] {
                require(!services.contains_key(role))?;
            }
            for role in ["gateway", "organization"] {
                if let Some(service) = services.get(role) {
                    for key in [
                        "MARTY_AGENT_ADMIN_ENABLED",
                        "MARTY_AGENT_ENROLLMENT_ENABLED",
                        "MARTY_DELEGATION_APPROVAL_ENABLED",
                        "MARTY_DELEGATION_COMMANDS_ENABLED",
                    ] {
                        require(
                            service["environment"][key].is_null()
                                || service["environment"][key] == "false",
                        )?;
                    }
                }
            }
        }
        if let Some(workflows) = &self.configuration.workflows {
            workflows.validate_model(model)?;
        }
        if self
            .identity_selection()?
            .is_some_and(|selection| selection.delegated_use || selection.public_verification)
        {
            workflows::validate_feature_signing_model(model)?;
        }
        Ok(())
    }

    fn validate_delegated_use(
        &self,
        service: &Value,
        agent: &AgentTrust,
        configuration: &DelegatedUseConfiguration,
    ) -> Result<()> {
        private_runtime(service)?;
        exact_secrets(
            service,
            &[
                "grpc_service_token",
                "issuance_api_key",
                "signing_keys_issuer_sign_key",
                "workload_identity_ca_cert",
                "openbao_tls_ca_cert",
            ],
        )?;
        for (key, value) in [
            ("SERVICE_NAME", "delegated-use"),
            ("MARTY_DELEGATED_USE_ENABLED", "true"),
            ("DELEGATED_USE_LISTEN_ADDR", "0.0.0.0:8021"),
            ("DELEGATED_USE_HEALTH_ADDR", "127.0.0.1:8022"),
            ("DELEGATED_USE_POOL_MAX_CONNECTIONS", "2"),
            (
                "DELEGATED_USE_CREDENTIAL_TEMPLATE_GRPC_TARGET",
                "https://credential-template:9003",
            ),
            (
                "DELEGATED_USE_PRESENTATION_POLICY_GRPC_TARGET",
                "https://presentation-policy:9009",
            ),
            (
                "DELEGATED_USE_ISSUANCE_NATIVE_URL",
                "https://issuance-native:8443",
            ),
            (
                "DELEGATED_USE_CREDENTIAL_TEMPLATE_URL",
                "https://credential-template:8443",
            ),
            (
                "DELEGATED_USE_TRUST_PROFILE_URL",
                "https://trust-profile:8443",
            ),
            (
                "DELEGATED_USE_DEPLOYMENT_PROFILE_URL",
                "https://deployment-profile:8443",
            ),
            (
                "DELEGATED_USE_REQUEST_SIGNING_ORIGIN",
                "https://signing-keys:8018",
            ),
            (
                "DELEGATED_USE_RECEIPT_SIGNING_ORIGIN",
                "https://signing-keys:8018",
            ),
            (
                "DELEGATED_USE_REQUEST_GRANT_OPENBAO_ORIGIN",
                "https://openbao:8200",
            ),
            (
                "DELEGATED_USE_RECEIPT_GRANT_OPENBAO_ORIGIN",
                "https://openbao:8200",
            ),
            (
                "DELEGATED_USE_SERVICE_TOKEN_FILE",
                "/run/secrets/grpc_service_token",
            ),
            (
                "DELEGATED_USE_ISSUANCE_API_KEY_FILE",
                "/run/secrets/issuance_api_key",
            ),
            (
                "DELEGATED_USE_REQUEST_SIGN_CREDENTIAL_FILE",
                "/run/secrets/signing_keys_issuer_sign_key",
            ),
            (
                "DELEGATED_USE_RECEIPT_SIGN_CREDENTIAL_FILE",
                "/run/secrets/signing_keys_issuer_sign_key",
            ),
            (
                "DELEGATED_USE_WORKLOAD_TLS_CA_CERT_FILE",
                "/run/secrets/workload_identity_ca_cert",
            ),
            ("BAO_CACERT", "/run/secrets/openbao_tls_ca_cert"),
            (
                "DELEGATED_USE_CLIENT_CA_FILES",
                "[\"/run/feature-profile/feature_workload_client_ca_der\"]",
            ),
        ] {
            expect(service, key, value)?;
        }
        for (key, value) in [
            (
                "DELEGATED_USE_ORGANIZATION_ID",
                agent.organization_id.to_string(),
            ),
            (
                "DELEGATED_USE_DEPLOYMENT_PROFILE_ID",
                configuration.deployment_profile_id.to_string(),
            ),
            (
                "DELEGATED_USE_DELEGATION_POLICY_ID",
                configuration.delegation_policy_id.to_string(),
            ),
            (
                "DELEGATED_USE_FLOW_DEFINITION_VERSION",
                configuration.flow_definition_version.to_string(),
            ),
            (
                "DELEGATED_USE_PUBLIC_CALLER_ENABLED",
                configuration.public_caller.to_string(),
            ),
        ] {
            expect(service, key, &value)?;
        }
        for (key, value) in [
            (
                "DELEGATED_USE_APPROVAL_PROFILE",
                agent.approval.profile.as_str(),
            ),
            (
                "DELEGATED_USE_APPROVAL_VERSION",
                agent.approval.version.as_str(),
            ),
            (
                "DELEGATED_USE_STATUS_REF",
                agent.approval.status_ref.as_str(),
            ),
            (
                "DELEGATED_USE_FLOW_DEFINITION_ID",
                configuration.flow_definition_id.as_str(),
            ),
            (
                "DELEGATED_USE_PUBLIC_BASE_URL",
                configuration.public_base_url.as_str(),
            ),
            (
                "DELEGATED_USE_VERIFIER_DID",
                configuration.verifier_did.as_str(),
            ),
            (
                "DELEGATED_USE_VERIFIER_DISPLAY_NAME",
                configuration.verifier_display_name.as_str(),
            ),
            (
                "DELEGATED_USE_RECEIPT_ISSUER_DID",
                configuration.receipt_issuer_did.as_str(),
            ),
            (
                "DELEGATED_USE_RECEIPT_ALGORITHM",
                configuration.receipt_algorithm.as_str(),
            ),
            (
                "DELEGATED_USE_RECEIPT_KEY_ID",
                configuration.receipt_key_id.as_str(),
            ),
            (
                "DELEGATED_USE_RECEIPT_KEY_REFERENCE",
                configuration.receipt_key_reference.as_str(),
            ),
        ] {
            expect(service, key, value)?;
        }
        let artifact = service["image"]
            .as_str()
            .and_then(|image| image.split_once('@').map(|(_, digest)| digest))
            .filter(|digest| digest.strip_prefix("sha256:").is_some_and(hash))
            .ok_or(REFUSED)?;
        expect(service, "DELEGATED_USE_APPROVAL_ARTIFACT_DIGEST", artifact)?;
        for (name, role) in delegated_databases() {
            file_environment(
                service,
                &format!("DELEGATED_USE_{name}_DATABASE_URL_FILE"),
                &format!("feature_{role}_database_url"),
            )?;
        }
        for (key, name) in [
            (
                "DELEGATED_USE_REQUEST_READ_CREDENTIAL_FILE",
                workflows::SIGNING_READ_KEY,
            ),
            (
                "DELEGATED_USE_RECEIPT_READ_CREDENTIAL_FILE",
                workflows::SIGNING_READ_KEY,
            ),
            (
                "DELEGATED_USE_REQUEST_MINT_TOKEN_FILE",
                "feature_delegated_use_request_mint_token",
            ),
            (
                "DELEGATED_USE_RECEIPT_MINT_TOKEN_FILE",
                "feature_delegated_use_receipt_mint_token",
            ),
            (
                "DELEGATED_USE_RECEIPT_PUBLIC_JWK_FILE",
                "feature_delegated_use_receipt_public_jwk",
            ),
            (
                "DELEGATED_USE_WORKLOAD_BINDINGS_FILE",
                "feature_delegated_use_workload_bindings",
            ),
        ] {
            file_environment(service, key, name)?;
        }
        for (prefix, role, key) in [
            (
                "DELEGATED_USE",
                "server",
                "feature-workload-tls-delegated-use-server",
            ),
            (
                "DELEGATED_USE_WORKLOAD",
                "client",
                "feature-workload-tls-delegated-use-client",
            ),
        ] {
            file_environment(
                service,
                &format!("{prefix}_TLS_CERT_FILE"),
                &format!("feature_delegated_use_{role}_cert"),
            )?;
            file_environment(
                service,
                &format!("{prefix}_TLS_KMS_TOKEN_FILE"),
                &format!("feature_delegated_use_{role}_tls_kms_token"),
            )?;
            for (suffix, value) in [
                ("KMS_PROVIDER", "openbao-transit"),
                ("KMS_ADDR", "https://openbao:8200"),
                ("KMS_CA_CERT_FILE", "/run/secrets/openbao_tls_ca_cert"),
                ("KMS_KEY_NAME", key),
                ("KMS_KEY_VERSION", "1"),
            ] {
                expect(service, &format!("{prefix}_TLS_{suffix}"), value)?;
            }
        }
        for key in service["environment"].as_object().ok_or(REFUSED)?.keys() {
            if key.ends_with("_FILE") {
                absent(service, key.trim_end_matches("_FILE"))?;
            }
        }
        require(
            service["healthcheck"]["test"]
                == serde_json::json!([
                    "CMD",
                    "curl",
                    "--fail",
                    "--silent",
                    "--show-error",
                    "--max-time",
                    "18",
                    "http://127.0.0.1:8022/ready"
                ]),
        )
    }

    fn validate_feature_mounts(
        &self,
        installation: &Path,
        services: &serde_json::Map<String, Value>,
    ) -> Result<()> {
        let directory = self.projection_directory(installation);
        let originals = installation.join(DIRECTORY);
        let generations = installation.join(generations::ROOT);
        let postgres_owner = installation.join(crate::installer_feature_postgres_tls::DIRECTORY);
        let postgres_projection = postgres_owner.join("server");
        let operator = installation.join("marty-deploy");
        for (role, service) in services {
            let allowed = self.mount_names(role)?;
            if role == "installer-feature-identities"
                && generations::verify_helper_projection_at(installation, service)?
            {
                continue;
            }
            let mut observed = BTreeSet::new();
            let mut postgres_mounts = 0;
            let mut probe_mounts = 0;
            for volume in service["volumes"].as_array().into_iter().flatten() {
                let Some(source) = volume["source"].as_str() else {
                    continue;
                };
                let path = Path::new(source);
                if path.starts_with(&postgres_owner) || postgres_owner.starts_with(path) {
                    require(
                        role == "postgres"
                            && path == postgres_projection
                            && volume["target"]
                                == crate::installer_feature_postgres_tls::SERVER_MOUNT
                            && volume["type"] == "bind"
                            && volume["read_only"] == true
                            && volume["bind"]["create_host_path"] == false,
                    )?;
                    postgres_mounts += 1;
                }
                if volume["target"] == "/run/feature-profile-operator" {
                    require(
                        role == "installer-ingress"
                            && path == operator
                            && volume["type"] == "bind"
                            && volume["read_only"] == true
                            && volume["bind"]["create_host_path"] == false,
                    )?;
                    probe_mounts += 1;
                }
                // A directory ancestor also reveals all owner/producer files.
                require(
                    !directory.starts_with(path)
                        && !originals.starts_with(path)
                        && !generations.starts_with(path),
                )?;
                if path.starts_with(&originals) || path.starts_with(&generations) {
                    let name = path.file_name().and_then(|v| v.to_str()).ok_or(REFUSED)?;
                    require(
                        path.parent() == Some(directory.as_path())
                            && allowed.contains(name)
                            && observed.insert(name)
                            && volume["type"] == "bind"
                            && volume["read_only"] == true
                            && volume["bind"]["create_host_path"] == false
                            && volume["target"] == format!("/run/feature-profile/{name}"),
                    )?;
                }
            }
            if role == "delegation-approval"
                || role == "delegation-commands"
                || role == "delegated-use"
                || role == "installer-ingress"
            {
                require(observed == allowed.iter().map(String::as_str).collect())?;
            }
            if role == "postgres" {
                require(postgres_mounts == 1)?;
            }
            if role == "installer-ingress" {
                require(probe_mounts == 1)?;
            }
            // A feature-owned file cannot be aliased through Compose secrets,
            // which would bypass the fixed individual bind and target contract.
            for secret in service["secrets"].as_array().into_iter().flatten() {
                let name = secret
                    .as_str()
                    .or_else(|| secret["source"].as_str())
                    .ok_or(REFUSED)?;
                require(!name.starts_with("feature_"))?;
            }
        }
        Ok(())
    }

    fn mount_names(&self, role: &str) -> Result<BTreeSet<String>> {
        let db = |names: &[&str]| {
            names
                .iter()
                .map(|name| format!("feature_{name}_database_url"))
                .chain(["feature_postgres_ca".into()])
                .collect()
        };
        let names = match role {
            "feature-database-roles" => BTreeSet::from([
                "feature_database_passwords".into(),
                "feature_postgres_ca".into(),
            ]),
            "feature-database-grants" => BTreeSet::from(["feature_postgres_ca".into()]),
            "feature-delegation-migrate" => db(&["delegation_owner"]),
            "feature-credential-migrate" => db(&["credential_owner"]),
            "delegation-approval" if self.configuration.agent_trust.is_some() => db(&[
                "approval_runtime",
                "approval_consent",
                "approval_authority",
                "approval_organization",
            ]),
            "delegation-commands" if self.configuration.agent_trust.is_some() => {
                db(&["command_writer", "command_runtime", "command_organization"])
            }
            "delegated-use"
                if self
                    .configuration
                    .agent_trust
                    .as_ref()
                    .and_then(AgentTrust::use_configuration)
                    .is_some() =>
            {
                let mut names: BTreeSet<String> = delegated_databases()
                    .into_iter()
                    .map(|(_, role)| format!("feature_{role}_database_url"))
                    .collect();
                names.extend(
                    [
                        "feature_postgres_ca",
                        "feature_workload_client_ca_der",
                        workflows::SIGNING_READ_KEY,
                        "feature_delegated_use_request_mint_token",
                        "feature_delegated_use_receipt_mint_token",
                        "feature_delegated_use_receipt_public_jwk",
                        "feature_delegated_use_workload_bindings",
                        "feature_delegated_use_server_cert",
                        "feature_delegated_use_server_tls_kms_token",
                        "feature_delegated_use_client_cert",
                        "feature_delegated_use_client_tls_kms_token",
                    ]
                    .into_iter()
                    .map(str::to_owned),
                );
                names
            }
            _ => self.workflow_mount_names(role),
        };
        Ok(names)
    }

    fn workflow_mount_names(&self, role: &str) -> BTreeSet<String> {
        let workflows = self.configuration.workflows.as_ref();
        let mut names = BTreeSet::new();
        if role == "installer-ingress" {
            names.insert("feature_postgres_ca".into());
        }
        if let Some(workflows) = workflows {
            if role == "flow" {
                if workflows.verification_prerequisite {
                    names.insert(workflows::PREREQUISITE_TOKEN.into());
                }
                if matches!(
                    workflows.public_verification,
                    Some(workflows::PublicVerification::Configured { .. })
                ) {
                    names.extend([
                        workflows::CATALOG.into(),
                        workflows::HOLDER_MINT_TOKEN.into(),
                    ]);
                }
            }
            if matches!(role, "issuance" | "issuance-native") && workflows.needs_issuance_roles() {
                names.extend([
                    "feature_issuance_runtime_database_url".into(),
                    "feature_postgres_ca".into(),
                ]);
                if workflows.external_associations {
                    names.insert("feature_association_database_url".into());
                }
                if workflows.external_observations {
                    names.insert("feature_observation_database_url".into());
                }
            }
            if matches!(role, "issuance" | "issuance-native") && workflows.verification_prerequisite
            {
                names.insert(workflows::PREREQUISITE_TOKEN.into());
            }
            if role == "trust-profile" && workflows.wallet_governance.is_some() {
                names.extend([
                    workflows::TRUST_CERTIFICATE.into(),
                    workflows::TRUST_TOKEN.into(),
                ]);
            }
        }
        let delegated = self
            .configuration
            .agent_trust
            .as_ref()
            .is_some_and(|a| a.delegated_use.is_some());
        let signing = delegated || workflows.is_some_and(|w| w.public_verification.is_some());
        if role == "signing-keys" && signing {
            names.extend([
                workflows::GRANT_VERIFY_TOKEN.into(),
                workflows::SIGNING_CUSTODY_TOKEN.into(),
            ]);
        }
        if signing
            && [
                "gateway",
                "credential-template",
                "trust-profile",
                "issuance",
                "issuance-native",
                "presentation-policy",
                "signing-keys",
                "flow",
                "delegated-use",
            ]
            .contains(&role)
        {
            names.insert(workflows::SIGNING_READ_KEY.into());
        }
        if delegated {
            match role {
                "trust-profile" => {
                    names.extend([
                        workflows::TRUST_CERTIFICATE.into(),
                        workflows::TRUST_TOKEN.into(),
                    ]);
                }
                "deployment-profile" => {
                    names.extend([
                        "feature_deployment_profile_server_cert".into(),
                        "feature_deployment_profile_tls_kms_token".into(),
                    ]);
                }
                _ => {}
            }
        }
        names
    }
}

fn exact_secrets(service: &Value, expected: &[&str]) -> Result<()> {
    let mut names = BTreeSet::new();
    for secret in service["secrets"].as_array().into_iter().flatten() {
        let source = secret
            .as_str()
            .or_else(|| secret["source"].as_str())
            .ok_or(REFUSED)?;
        require(
            names.insert(source)
                && (secret.is_string() || secret["target"].is_null() || secret["target"] == source),
        )?;
    }
    require(names == expected.iter().copied().collect())
}

fn delegated_databases() -> [(&'static str, &'static str); 14] {
    [
        ("USE_WRITER", "use_writer"),
        ("RUNTIME_READER", "use_runtime_reader"),
        ("ORGANIZATION_AUTHORITY", "use_organization_authority"),
        ("REGISTRY_SOURCE", "use_registry_source"),
        ("ACCESS_SOURCE", "use_access_source"),
        ("MACHINE_POLICY_SOURCE", "use_machine_policy_source"),
        ("MACHINE_POLICY_EVIDENCE", "use_machine_policy_evidence"),
        ("DELEGATION_POLICY_SOURCE", "use_delegation_policy_source"),
        ("MACHINE_AUDIT", "use_machine_audit"),
        ("FLOW_READER", "use_flow_reader"),
        ("FLOW_INGRESS", "use_flow_ingress"),
        ("CREDENTIAL_TRUST", "use_credential_trust"),
        ("CREDENTIAL_STATUS", "use_credential_status"),
        ("CREDENTIAL_EVIDENCE", "use_credential_evidence"),
    ]
}

fn core_pool_limit(service: &str) -> Option<(&'static str, &'static str)> {
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

fn expect(service: &Value, key: &str, expected: &str) -> Result<()> {
    require(service["environment"][key] == expected)
}
fn absent(service: &Value, key: &str) -> Result<()> {
    require(service["environment"][key].is_null() || service["environment"][key] == "")
}
fn file_environment(service: &Value, key: &str, file: &str) -> Result<()> {
    let key = key.strip_suffix("_FILE").unwrap_or(key);
    expect(
        service,
        &format!("{key}_FILE"),
        &format!("/run/feature-profile/{file}"),
    )?;
    absent(service, key)
}
fn private_runtime(service: &Value) -> Result<()> {
    require(
        service["read_only"] == true
            && service["privileged"].as_bool() != Some(true)
            && service["ports"].as_array().is_none_or(Vec::is_empty)
            && service["network_mode"].is_null()
            && service["labels"]["com.elevenid.installer.phase"] == "runtime",
    )
}
fn approval_databases() -> Vec<(&'static str, String)> {
    [
        (
            "DELEGATION_APPROVAL_RUNTIME_DATABASE_URL",
            "approval_runtime",
        ),
        (
            "DELEGATION_APPROVAL_CONSENT_DATABASE_URL",
            "approval_consent",
        ),
        (
            "DELEGATION_APPROVAL_AUTHORITY_DATABASE_URL",
            "approval_authority",
        ),
        (
            "DELEGATION_APPROVAL_ORGANIZATION_DATABASE_URL",
            "approval_organization",
        ),
    ]
    .into_iter()
    .map(|(key, role)| (key, format!("feature_{role}_database_url")))
    .collect()
}
fn command_databases() -> Vec<(&'static str, String)> {
    [
        ("DELEGATION_COMMAND_DATABASE_URL", "command_writer"),
        ("DELEGATION_COMMAND_RUNTIME_DATABASE_URL", "command_runtime"),
        (
            "DELEGATION_COMMAND_ORGANIZATION_DATABASE_URL",
            "command_organization",
        ),
    ]
    .into_iter()
    .map(|(key, role)| (key, format!("feature_{role}_database_url")))
    .collect()
}

#[cfg(test)]
#[path = "installer_features_tests.rs"]
mod tests;
