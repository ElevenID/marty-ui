//! First-boot handoff through the existing Organization and public registry owners.
//! No direct key persistence, tenant registry write or additional credential
//! issuer exists here. Immutable setup receipts extend the original app session.
#![cfg(target_os = "linux")]

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    installer_application::bound,
    installer_compose::{BoundFile, ComposeInputs, ComposeReceipt, ComposeSession},
    installer_doctor::{SavedSession, SESSION_RECORD},
    installer_foundation, installer_host_fs as fs, installer_jobs,
    installer_state::{InstallerState, LockedInspection, Phase},
};

type Result<T> = std::result::Result<T, String>;
type ExtensionRecords = Vec<(&'static str, Vec<u8>)>;
const REFUSED: &str =
    "Organization bootstrap binding refused; preserve the installation and credential evidence";
const REVOCATION_UNCERTAIN: &str = "Temporary organization credential revocation is not verified; installation cannot complete and must not reissue the credential";
pub(crate) const LAYER: &str =
    "deploy-config/compose/selfhost-installer/compose.organization-bootstrap.yml";
const REQUEST: &str = "organization-bootstrap-request.json";
const INSTALLATION: &str = "organization-bootstrap-installation.json";
const OUTPUT: &str = "organization-bootstrap-output";
const ISSUE: &str = "installer-organization-key-issue";
const REVOKE: &str = "installer-organization-key-revoke";
const ISSUED_SESSION: &str = "organization-bootstrap-issued-session.json";
const REVOKED_SESSION: &str = "organization-bootstrap-revoked-session.json";
pub(crate) const RESULT: &str = "organization-bootstrap-result.json";

fn require(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}
fn hash(bytes: &[u8]) -> String {
    crate::installer_release::sha256(bytes)
}
fn encode(value: &impl Serialize) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| REFUSED.into())
}
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    serde_json::from_value(crate::installer_json::decode(bytes).map_err(|_| REFUSED)?)
        .map_err(|_| REFUSED.into())
}
fn equal<T: Serialize>(left: &T, right: &T) -> bool {
    serde_json::to_value(left).ok() == serde_json::to_value(right).ok()
}

fn canonical_layer(inputs: &ComposeInputs) -> Result<PathBuf> {
    let application: Vec<_> = inputs
        .files
        .iter()
        .filter(|file| {
            file.path
                .file_name()
                .is_some_and(|name| name == "docker-compose.yml")
        })
        .collect();
    require(application.len() == 1)?;
    let bundle = application[0].path.parent().ok_or(REFUSED)?;
    require(bundle.starts_with(&inputs.installation) && bundle != inputs.installation)?;
    Ok(bundle.join(LAYER))
}

fn files_with_bootstrap(inputs: &ComposeInputs, layer: BoundFile) -> Result<Vec<BoundFile>> {
    require(layer.path == canonical_layer(inputs)?)?;
    let mut files = inputs.files.clone();
    let existing: Vec<_> = files
        .iter()
        .filter(|file| file.path == layer.path)
        .collect();
    if !existing.is_empty() {
        require(existing.len() == 1 && equal(existing[0], &layer))?;
        return Ok(files);
    }
    #[cfg(feature = "installer-development")]
    let position = if let Some(image) = &inputs.development_image {
        let development = image.layer_file(&inputs.installation)?;
        require(files.last().is_some_and(|file| equal(file, &development)))?;
        files.len().checked_sub(1).ok_or(REFUSED)?
    } else {
        files.len()
    };
    #[cfg(not(feature = "installer-development"))]
    let position = files.len();
    files.insert(position, layer);
    Ok(files)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionExtension {
    schema: String,
    original_session_sha256: String,
    predecessor_sha256: String,
    service: String,
    compose_result_sha256: String,
    session: SavedSession,
}

fn validate_extension(
    extension: &SessionExtension,
    original: &[u8],
    predecessor: &[u8],
    previous: &SavedSession,
    result: &[u8],
    service: &str,
) -> Result<()> {
    let current = &extension.session;
    #[cfg(feature = "installer-development")]
    require(current.inputs.development_image == previous.inputs.development_image)?;
    let receipt: ComposeReceipt = decode(result)?;
    let before = previous.receipt.resources.as_ref().ok_or(REFUSED)?;
    let after = receipt.resources.as_ref().ok_or(REFUSED)?;
    require(
        extension.schema == "elevenid.installer-organization-session/v1"
            && extension.original_session_sha256 == hash(original)
            && extension.predecessor_sha256 == hash(predecessor)
            && extension.compose_result_sha256 == hash(result)
            && extension.service == service
            && current.schema == "elevenid.installer-compose-session/v1"
            && current.installation_id == previous.installation_id
            && current.inputs.installation == previous.inputs.installation
            && current.inputs.project == previous.inputs.project
            && equal(&current.inputs.environment, &previous.inputs.environment)
            && current.inputs.approved_images == previous.inputs.approved_images
            && current.inputs.allowed_loopback_ports == previous.inputs.allowed_loopback_ports
            && current.inputs.readonly_bind_roots == previous.inputs.readonly_bind_roots
            && current.inputs.services.is_empty()
            && current.inputs.profiles == ["setup", "installer-init"]
            && current.configuration_sha256
                == crate::installer_compose::model_sha256(&current.model)?
            && current.configuration_sha256 == receipt.configuration_sha256
            && equal(&current.receipt, &receipt)
            && equal(&current.inputs.prior, &Some(receipt.clone()))
            && receipt.schema == "elevenid.installer-compose-operation/v1"
            && receipt.operation == format!("setup-{service}")
            && receipt.command_succeeded
            && receipt.observation_validated
            && receipt.client_exit_code == Some(0)
            && receipt.failure_class.is_none()
            && !receipt.installation_ready
            && receipt.engine_id == previous.receipt.engine_id
            && receipt.project == previous.receipt.project
            && before.networks == after.networks
            && before.volumes == after.volumes
            && after.containers.len() == before.containers.len() + 1
            && before
                .containers
                .iter()
                .all(|(role, identity)| after.containers.get(role) == Some(identity))
            && !before.containers.contains_key(service),
    )?;
    let job = after.containers.get(service).ok_or(REFUSED)?;
    let statuses: Vec<_> = receipt
        .status
        .iter()
        .filter(|row| row["Service"] == service)
        .collect();
    require(
        job.setup
            && job.service == service
            && job
                .setup_execution
                .as_ref()
                .is_some_and(|execution| execution.completed_without_restart)
            && job.image == current.model["services"][service]["image"]
            && statuses.len() == 1
            && statuses[0]["ID"] == job.id
            && statuses[0]["State"] == "exited"
            && statuses[0]["ExitCode"] == 0,
    )?;
    let mut roots = previous.inputs.writable_bind_roots.clone();
    roots.insert(previous.inputs.installation.join(OUTPUT));
    require(roots == current.inputs.writable_bind_roots)?;
    let previous_services = previous.model["services"].as_object().ok_or(REFUSED)?;
    let services = current.model["services"].as_object().ok_or(REFUSED)?;
    require(
        previous_services
            .iter()
            .all(|(name, model)| services.get(name) == Some(model))
            && services.keys().all(|name| {
                previous_services.contains_key(name) || [ISSUE, REVOKE].contains(&name.as_str())
            })
            && ["name", "networks", "volumes", "secrets", "configs"]
                .iter()
                .all(|name| previous.model[name] == current.model[name]),
    )?;
    let path = canonical_layer(&previous.inputs)?;
    let layers: Vec<_> = current
        .inputs
        .files
        .iter()
        .filter(|file| file.path == path)
        .collect();
    require(layers.len() == 1)?;
    require(
        equal(
            &current.inputs.files,
            &files_with_bootstrap(&previous.inputs, layers[0].clone())?,
        ) && current.inputs.bound_inputs.len() >= previous.inputs.bound_inputs.len()
            && previous
                .inputs
                .bound_inputs
                .iter()
                .zip(&current.inputs.bound_inputs)
                .all(|(left, right)| equal(left, right))
            && current.inputs.bound_inputs.iter().all(|file| {
                previous
                    .inputs
                    .bound_inputs
                    .iter()
                    .any(|candidate| equal(file, candidate))
                    || [
                        REQUEST,
                        INSTALLATION,
                        SESSION_RECORD,
                        installer_foundation::REGISTRATION,
                    ]
                    .iter()
                    .any(|name| {
                        file.path == previous.inputs.installation.join("evidence").join(name)
                    })
                    || file.path
                        == previous
                            .inputs
                            .installation
                            .join("secrets/marty_db_password")
            })
            && previous
                .receipt
                .input_files
                .iter()
                .all(|(path, digest)| receipt.input_files.get(path) == Some(digest)),
    )?;
    Ok(())
}

/// Called only after the original session has passed the ordinary doctor
/// validator. Every extension binds the unchanged original and its predecessor.
pub(crate) fn extend_session(
    state: &LockedInspection,
    original: &[u8],
    mut saved: SavedSession,
) -> Result<(SavedSession, ExtensionRecords)> {
    let mut predecessor = original.to_vec();
    let mut records = Vec::new();
    let mut missing = false;
    for (record, service) in [(ISSUED_SESSION, ISSUE), (REVOKED_SESSION, REVOKE)] {
        let Some(raw) = state.diagnostic_record(record, true)? else {
            missing = true;
            continue;
        };
        require(!missing && installer_foundation::load(state)?.is_some())?;
        let extension: SessionExtension = decode(&raw)?;
        let result_name = format!("compose-setup-{service}-result.json");
        let result = state.read_evidence(&result_name)?;
        validate_extension(&extension, original, &predecessor, &saved, &result, service)?;
        require(state.read_evidence(&result_name)? == result)?;
        saved = extension.session;
        predecessor = raw.clone();
        records.push((record, raw));
    }
    Ok((saved, records))
}

#[expect(
    clippy::too_many_arguments,
    reason = "Keep the original session, predecessor and exact setup receipt explicit."
)]
fn record_session(
    docker_path: &Path,
    state: &mut InstallerState,
    mut inputs: ComposeInputs,
    receipt: ComposeReceipt,
    original: &[u8],
    predecessor: &[u8],
    previous: &SavedSession,
    service: &str,
) -> Result<(SavedSession, Vec<u8>)> {
    inputs.services.clear();
    inputs.prior = Some(receipt.clone());
    let binding = state.journal().runtime().ok_or(REFUSED)?;
    let session = ComposeSession::new(docker_path, binding, inputs.clone())?;
    let result = state.with_inspection(|inspection| {
        inspection.read_evidence(&format!("compose-setup-{service}-result.json"))
    })?;
    let extension = SessionExtension {
        schema: "elevenid.installer-organization-session/v1".into(),
        original_session_sha256: hash(original),
        predecessor_sha256: hash(predecessor),
        service: service.into(),
        compose_result_sha256: hash(&result),
        session: SavedSession {
            schema: "elevenid.installer-compose-session/v1".into(),
            installation_id: state.journal().installation_id().to_string(),
            inputs,
            model: session.model().clone(),
            configuration_sha256: session.configuration_sha256().into(),
            receipt,
        },
    };
    validate_extension(
        &extension,
        original,
        predecessor,
        previous,
        &result,
        service,
    )?;
    let bytes = encode(&extension)?;
    state.write_evidence(
        if service == ISSUE {
            ISSUED_SESSION
        } else {
            REVOKED_SESSION
        },
        &bytes,
    )?;
    Ok((extension.session, bytes))
}

fn validate_key_receipt(
    receipt: &Value,
    intent: &[u8],
    request_id: Uuid,
    installation_id: Uuid,
    organization_id: Uuid,
    revoked: bool,
) -> Result<Uuid> {
    let key = receipt["api_key_id"]
        .as_str()
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or(REFUSED)?;
    require(
        !key.is_nil()
            && receipt["schema"] == "elevenid.installer-organization-bootstrap-receipt/v1"
            && receipt["operation"] == if revoked { "revoked" } else { "issued" }
            && receipt["installation_id"] == installation_id.to_string()
            && receipt["organization_id"] == organization_id.to_string()
            && receipt["request_id"] == request_id.to_string()
            && receipt["intent_sha256"] == hash(intent)
            && receipt["scopes"] == json!(["keys:write"])
            && receipt["revoked"] == revoked
            && receipt["automatic_replay_allowed"] == false,
    )?;
    let intent: Value = decode(intent)?;
    require(
        intent["schema"] == "elevenid.installer-organization-bootstrap-intent/v1"
            && intent["context"]["installation_id"] == installation_id.to_string()
            && intent["context"]["organization_id"] == organization_id.to_string()
            && intent["context"]["request_id"] == request_id.to_string()
            && receipt["expires_at"] == intent["expires_at"],
    )?;
    let created = DateTime::parse_from_rfc3339(intent["created_at"].as_str().ok_or(REFUSED)?)
        .map_err(|_| REFUSED)?;
    let expires = DateTime::parse_from_rfc3339(intent["expires_at"].as_str().ok_or(REFUSED)?)
        .map_err(|_| REFUSED)?;
    require(expires.signed_duration_since(created) == chrono::Duration::minutes(15))?;
    Ok(key)
}

/// Revocation is attempted after every registration outcome, including local
/// validation errors. A failed cleanup always prevents successful completion.
fn with_revocation<T, R>(
    owner: &mut T,
    operation: impl FnOnce(&mut T) -> Result<R>,
    revoke: impl FnOnce(&mut T) -> Result<()>,
) -> Result<R> {
    let result = operation(owner);
    revoke(owner).map_err(|_| REVOCATION_UNCERTAIN.to_owned())?;
    result
}

pub(crate) fn run(
    docker_path: &Path,
    installation: &Path,
    bundle: &Path,
    state: &mut InstallerState,
    images: &BTreeMap<String, String>,
    expected_operator_sha: &str,
) -> Result<()> {
    state.require_live_phase(Phase::Provisioning)?;
    let (selected, saved, original, journal, registration) =
        state.with_inspection(|inspection| {
            require(
                inspection
                    .diagnostic_record(ISSUED_SESSION, true)?
                    .is_none()
                    && inspection
                        .diagnostic_record(REVOKED_SESSION, true)?
                        .is_none(),
            )?;
            Ok((
                installer_foundation::load(inspection)?.ok_or(REFUSED)?,
                crate::installer_doctor::load_session(inspection, installation)?,
                inspection.read_evidence(SESSION_RECORD)?,
                inspection
                    .diagnostic_record("installation.json", false)?
                    .ok_or(REFUSED)?,
                inspection.read_evidence(installer_foundation::REGISTRATION)?,
            ))
        })?;
    require(hash(&registration) == selected.registration_sha256)?;
    let organization_id = saved.model["services"]["organization"]["environment"]["MARTY_ORG_ID"]
        .as_str()
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or(REFUSED)?;
    require(
        !organization_id.is_nil()
            && saved.model["services"]["db-migrate"]["environment"]["MARTY_ORG_ID"]
                == organization_id.to_string(),
    )?;
    let request_id = Uuid::new_v4();
    let installation_id = state.journal().installation_id();
    state.create_private_directory(OUTPUT)?;
    state.write_evidence(INSTALLATION, &journal)?;
    state.write_evidence(
        REQUEST,
        &encode(&json!({
            "schema":"elevenid.installer-organization-bootstrap-request/v1",
            "request_id":request_id, "created_at":Utc::now(),
            "installation_sha256":hash(&journal), "compose_session_sha256":hash(&original),
        }))?,
    )?;
    let output_path = installation.join(OUTPUT);
    let output = fs::directory(&output_path, REFUSED)?;
    require(fs::file_names(&output, REFUSED)?.is_empty())?;
    let mut inputs = saved.inputs.clone();
    let layer = crate::installer_tls_outputs::bundle_text(bundle, LAYER, 65_536)?;
    inputs.files = files_with_bootstrap(
        &inputs,
        BoundFile {
            path: bundle.join(LAYER),
            sha256: hash(layer.as_bytes()),
        },
    )?;
    inputs.writable_bind_roots.insert(output_path.clone());
    for name in [
        REQUEST,
        INSTALLATION,
        SESSION_RECORD,
        installer_foundation::REGISTRATION,
    ] {
        let file = bound(installation.join("evidence").join(name))?;
        if !inputs.bound_inputs.iter().any(|other| equal(other, &file)) {
            inputs.bound_inputs.push(file);
        }
    }
    let secrets = fs::directory(&installation.join("secrets"), REFUSED)?;
    let password = fs::read_entry(&secrets, "marty_db_password", 0o444, false, REFUSED)?;
    inputs.bound_inputs.push(BoundFile {
        path: installation.join("secrets/marty_db_password"),
        sha256: hash(&password),
    });
    inputs.profiles = vec!["setup".into(), "installer-init".into()];
    inputs.services = vec![ISSUE.into()];
    inputs.prior = Some(saved.receipt.clone());
    let image = images.get("gateway").ok_or(REFUSED)?;
    let issued = installer_jobs::run(
        docker_path,
        installation,
        bundle,
        state,
        None,
        inputs.clone(),
        ISSUE,
        image,
        expected_operator_sha,
    )?;
    // A missing/uncertain setup result never permits automatic reissuance or
    // a competing revoker while that job may still be running. The helper owns
    // its own failed-issue reconciliation and records a 15-minute expiry.
    let issued_receipt = issued.compose;
    let issued_session = record_session(
        docker_path,
        state,
        inputs.clone(),
        issued_receipt.clone(),
        &original,
        &original,
        &saved,
        ISSUE,
    );
    struct Work<'a> {
        state: &'a mut InstallerState,
        credential: Option<Vec<u8>>,
        issued_key: Option<Uuid>,
        revocation_confirmed: bool,
        public_rejection_observed: bool,
    }
    let mut work = Work {
        state,
        credential: None,
        issued_key: None,
        revocation_confirmed: false,
        public_rejection_observed: false,
    };
    let result = with_revocation(
        &mut work,
        |work| {
            issued_session.as_ref().map_err(|_| REFUSED)?;
            fs::require_directory_binding(&output_path, &output, REFUSED)?;
            let intent = fs::read_entry(&output, "issue-intent.json", 0o600, false, REFUSED)?;
            let receipt: Value = decode(&fs::read_entry(
                &output,
                "issued.json",
                0o600,
                false,
                REFUSED,
            )?)?;
            work.issued_key = Some(validate_key_receipt(
                &receipt,
                &intent,
                request_id,
                installation_id,
                organization_id,
                false,
            )?);
            work.credential = Some(fs::read_entry(&output, "api-key", 0o600, false, REFUSED)?);
            crate::installer_kms::register_locked(
                installation,
                work.state,
                organization_id,
                &registration,
                work.credential.as_deref().ok_or(REFUSED)?,
            )
        },
        |work| {
            let mut revoke_inputs = inputs.clone();
            revoke_inputs.prior = Some(issued_receipt.clone());
            revoke_inputs.services = vec![REVOKE.into()];
            let revoked = installer_jobs::run(
                docker_path,
                installation,
                bundle,
                work.state,
                None,
                revoke_inputs.clone(),
                REVOKE,
                image,
                expected_operator_sha,
            )?;
            fs::require_directory_binding(&output_path, &output, REFUSED)?;
            let intent = fs::read_entry(&output, "issue-intent.json", 0o600, false, REFUSED)?;
            let receipt: Value = decode(&fs::read_entry(
                &output,
                "revoked.json",
                0o600,
                false,
                REFUSED,
            )?)?;
            let key = validate_key_receipt(
                &receipt,
                &intent,
                request_id,
                installation_id,
                organization_id,
                true,
            )?;
            require(
                work.issued_key.is_none_or(|issued| issued == key)
                    && !fs::file_names(&output, REFUSED)?.contains("api-key"),
            )?;
            let (previous, predecessor) = issued_session.as_ref().map_err(|_| REFUSED)?;
            record_session(
                docker_path,
                work.state,
                revoke_inputs,
                revoked.compose,
                &original,
                predecessor,
                previous,
                REVOKE,
            )?;
            work.revocation_confirmed = true;
            if let Some(credential) = &work.credential {
                crate::installer_kms::verify_revoked_locked(
                    installation,
                    work.state,
                    organization_id,
                    credential,
                )?;
                work.public_rejection_observed = true;
            }
            Ok(())
        },
    );
    work.state.write_evidence(RESULT, &encode(&json!({
        "schema":"elevenid.installer-organization-registration/v1", "installation_id":installation_id,
        "organization_id":organization_id, "request_id":request_id,
        "registration_succeeded":result.is_ok(), "revocation_confirmed":work.revocation_confirmed,
        "public_rejection_observed":work.public_rejection_observed,
        "automatic_replay_allowed":false, "installation_ready":false,
    }))?)?;
    result.map(|_| ())
}

#[cfg(test)]
#[path = "installer_foundation_registration_tests.rs"]
mod tests;
