//! Fresh static seal custody, separate from Raft and application generations.
//! The protected outer directory is never mounted. Only OpenBao receives the
//! read-only child projection needed by its mapped nonroot image identity.
#![cfg(target_os = "linux")]

use crate::{
    installer_compose::{ComposeReceipt, ComposeSession},
    installer_host_fs as fs, installer_json, installer_release,
    installer_state::{InstallerState, LockedInspection, Phase},
};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::Write,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};

type Result<T> = std::result::Result<T, String>;
const REFUSED: &str = "OpenBao static seal custody differs or is unavailable; preserve the installation and restore its original protected seal material. No replacement key or store was initialized";
pub(crate) const RECORD: &str = "openbao-seal-created.json";
pub(crate) const KEY_ID: &str = "marty-selfhost-static-v1";
pub(crate) const INITIALIZATION: &str = "openbao-static-initialization.json";

fn require(value: bool) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MetadataBinding {
    device: u64,
    inode: u64,
    owner_uid: u32,
    owner_gid: u32,
    mode: u32,
    size: Option<u64>,
    changed_seconds: Option<i64>,
    changed_nanoseconds: Option<i64>,
}

impl MetadataBinding {
    fn observe(file: &File, directory: bool, mode: u32) -> Result<Self> {
        let m = file.metadata().map_err(|_| REFUSED)?;
        require(
            m.is_dir() == directory
                && (directory || (m.is_file() && m.nlink() == 1 && m.len() == 32))
                && m.uid() == unsafe { libc::geteuid() }
                && m.gid() == unsafe { libc::getegid() }
                && m.mode() & 0o7777 == mode,
        )?;
        Ok(Self {
            device: m.dev(),
            inode: m.ino(),
            owner_uid: m.uid(),
            owner_gid: m.gid(),
            mode,
            size: (!directory).then_some(m.len()),
            changed_seconds: (!directory).then_some(m.ctime()),
            changed_nanoseconds: (!directory).then_some(m.ctime_nsec()),
        })
    }
}

fn require_child_binding(
    parent: &File,
    name: &str,
    held: &File,
    directory: bool,
    mode: u32,
    captured: &MetadataBinding,
) -> Result<()> {
    let current = fs::open_child(
        parent,
        name,
        libc::O_PATH | if directory { libc::O_DIRECTORY } else { 0 },
        REFUSED,
    )?;
    require(
        &MetadataBinding::observe(held, directory, mode)? == captured
            && &MetadataBinding::observe(&current, directory, mode)? == captured,
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    schema: String,
    installation_id: uuid::Uuid,
    key_id: String,
    outer: MetadataBinding,
    projection: MetadataBinding,
    initialization: MetadataBinding,
    key: MetadataBinding,
    new_key_created: bool,
    seal_migration: bool,
    backup_observed: bool,
    installation_ready: bool,
}

fn observe(state: &LockedInspection, installation: &Path) -> Result<Receipt> {
    state.require_path_binding(installation)?;
    let outer = fs::directory(&installation.join("openbao-seal"), REFUSED)?;
    require(
        fs::file_names(&outer, REFUSED)? == ["key".to_owned(), "initialization".to_owned()].into(),
    )?;
    let projection = fs::open_child(&outer, "key", libc::O_RDONLY | libc::O_DIRECTORY, REFUSED)?;
    let initialization = fs::open_child(
        &outer,
        "initialization",
        libc::O_RDONLY | libc::O_DIRECTORY,
        REFUSED,
    )?;
    require(fs::file_names(&projection, REFUSED)? == ["static.key".to_owned()].into())?;
    // Metadata-only validation never reads or fingerprints seal material for
    // public status. A write or permission change alters the retained ctime.
    let key = fs::open_child(&projection, "static.key", libc::O_PATH, REFUSED)?;
    let receipt = Receipt {
        schema: "elevenid.installer-openbao-static-seal/v1".into(),
        installation_id: state.journal().installation_id(),
        key_id: KEY_ID.into(),
        outer: MetadataBinding::observe(&outer, true, 0o700)?,
        projection: MetadataBinding::observe(&projection, true, 0o755)?,
        initialization: MetadataBinding::observe(&initialization, true, 0o700)?,
        key: MetadataBinding::observe(&key, false, 0o444)?,
        new_key_created: true,
        seal_migration: false,
        backup_observed: false,
        installation_ready: false,
    };
    fs::require_directory_binding(&installation.join("openbao-seal"), &outer, REFUSED)?;
    require_child_binding(&outer, "key", &projection, true, 0o755, &receipt.projection)?;
    require_child_binding(
        &outer,
        "initialization",
        &initialization,
        true,
        0o700,
        &receipt.initialization,
    )?;
    require_child_binding(&projection, "static.key", &key, false, 0o444, &receipt.key)?;
    state.require_unchanged()?;
    Ok(receipt)
}

/// Missing or changed material is a recovery condition, never permission to
/// generate a substitute. Restoring an installation requires its original key.
pub(crate) fn verify(state: &LockedInspection, installation: &Path) -> Result<()> {
    let bytes = state.read_evidence(RECORD)?;
    require(bytes.len() <= 8192)?;
    let receipt: Receipt =
        serde_json::from_value(installer_json::decode(&bytes).map_err(|_| REFUSED)?)
            .map_err(|_| REFUSED)?;
    require(receipt == observe(state, installation)?)
}

/// Called once by the live fresh-install writer, before OpenBao creation. It
/// neither imports an old key nor repairs a partial creation attempt.
pub(crate) fn prepare_for_install(state: &mut InstallerState, installation: &Path) -> Result<()> {
    state.require_live_phase(Phase::Provisioning)?;
    state.with_inspection(|view| view.require_path_binding(installation))?;
    state.create_private_directory("openbao-seal")?;
    let outer = fs::directory(&installation.join("openbao-seal"), REFUSED)?;
    require(unsafe { libc::mkdirat(outer.as_raw_fd(), c"key".as_ptr(), 0o700) } == 0)?;
    require(unsafe { libc::mkdirat(outer.as_raw_fd(), c"initialization".as_ptr(), 0o700) } == 0)?;
    let initialization = fs::open_child(
        &outer,
        "initialization",
        libc::O_RDONLY | libc::O_DIRECTORY,
        REFUSED,
    )?;
    let projection = fs::open_child(&outer, "key", libc::O_RDONLY | libc::O_DIRECTORY, REFUSED)?;
    let fd = unsafe {
        libc::openat(
            projection.as_raw_fd(),
            c"static.key".as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    require(fd >= 0)?;
    let mut key = unsafe { File::from_raw_fd(fd) };
    outer
        .sync_all()
        .and_then(|_| projection.sync_all())
        .and_then(|_| initialization.sync_all())
        .map_err(|_| REFUSED)?;
    let mut entropy = [0u8; 32];
    rustls::crypto::aws_lc_rs::default_provider()
        .secure_random
        .fill(&mut entropy)
        .map_err(|_| REFUSED)?;
    let written = key.write_all(&entropy);
    entropy.fill(0);
    written.and_then(|_| key.sync_all()).map_err(|_| REFUSED)?;
    require(
        unsafe { libc::fchmod(key.as_raw_fd(), 0o444) } == 0
            && unsafe { libc::fchmod(projection.as_raw_fd(), 0o755) } == 0,
    )?;
    key.sync_all()
        .and_then(|_| projection.sync_all())
        .and_then(|_| outer.sync_all())
        .map_err(|_| REFUSED)?;
    fs::require_directory_binding(&installation.join("openbao-seal"), &outer, REFUSED)?;
    let receipt = state.with_inspection(|view| observe(view, installation))?;
    state.write_evidence(RECORD, &serde_json::to_vec(&receipt).map_err(|_| REFUSED)?)?;
    state.with_inspection(|view| verify(view, installation))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InitializationResult {
    schema: String,
    installation_id: String,
    attempt_id: String,
    cluster_id: String,
    seal_type: String,
    initialized: bool,
    unsealed_ready: bool,
    recovery_key_written: bool,
    root_token_written: bool,
    root_retired: bool,
    initialization_replayed: bool,
    installation_ready: bool,
}

impl InitializationResult {
    fn validate(&self, installation: &str, attempt: &str) -> Result<()> {
        require(
            self.schema == "elevenid.openbao-static-init-result/v1"
                && self.installation_id == installation
                && self.attempt_id == attempt
                && [installation, attempt, &self.cluster_id]
                    .into_iter()
                    .all(|value| {
                        uuid::Uuid::parse_str(value)
                            .is_ok_and(|id| !id.is_nil() && id.to_string() == value)
                    })
                && self.seal_type == "static"
                && self.initialized
                && self.unsealed_ready
                && self.recovery_key_written
                && self.root_token_written
                && !self.root_retired
                && !self.initialization_replayed
                && !self.installation_ready,
        )
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InitializationIntent {
    schema: String,
    installation_id: String,
    attempt_id: String,
    seal_type: String,
    recovery_shares: u8,
    recovery_threshold: u8,
}

fn require_intent(bytes: &[u8], result: &InitializationResult) -> Result<()> {
    let intent: InitializationIntent =
        serde_json::from_value(installer_json::decode(bytes).map_err(|_| REFUSED)?)
            .map_err(|_| REFUSED)?;
    require(
        intent.schema == "elevenid.openbao-static-init-intent/v1"
            && intent.installation_id == result.installation_id
            && intent.attempt_id == result.attempt_id
            && intent.seal_type == "static"
            && intent.recovery_shares == 1
            && intent.recovery_threshold == 1,
    )
}

fn public_result(installation: &Path) -> Result<(Vec<u8>, Vec<u8>, InitializationResult)> {
    let path = installation.join("openbao-seal/initialization");
    let directory = fs::directory(&path, REFUSED)?;
    require(
        fs::file_names(&directory, REFUSED)?
            == [
                "static-init-pending.json".into(),
                "static-init-result.json".into(),
            ]
            .into(),
    )?;
    let read = |name| -> Result<Vec<u8>> {
        let metadata = fs::open_child(&directory, name, libc::O_PATH, REFUSED)?
            .metadata()
            .map_err(|_| REFUSED)?;
        require(
            metadata.gid() == directory.metadata().map_err(|_| REFUSED)?.gid()
                && metadata.len() <= 8192,
        )?;
        let bytes = fs::read_entry(&directory, name, 0o600, false, REFUSED)?;
        let after = fs::open_child(&directory, name, libc::O_PATH, REFUSED)?
            .metadata()
            .map_err(|_| REFUSED)?;
        require(
            (
                metadata.dev(),
                metadata.ino(),
                metadata.uid(),
                metadata.gid(),
                metadata.mode(),
                metadata.nlink(),
                metadata.len(),
                metadata.ctime(),
                metadata.ctime_nsec(),
            ) == (
                after.dev(),
                after.ino(),
                after.uid(),
                after.gid(),
                after.mode(),
                after.nlink(),
                after.len(),
                after.ctime(),
                after.ctime_nsec(),
            ),
        )?;
        Ok(bytes)
    };
    let intent_bytes = read("static-init-pending.json")?;
    let result_bytes = read("static-init-result.json")?;
    let result =
        serde_json::from_value(installer_json::decode(&result_bytes).map_err(|_| REFUSED)?)
            .map_err(|_| REFUSED)?;
    require_intent(&intent_bytes, &result)?;
    fs::require_directory_binding(&path, &directory, REFUSED)?;
    Ok((intent_bytes, result_bytes, result))
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InitializationObservation {
    schema: String,
    installation_id: String,
    engine_id: String,
    container_id: String,
    initialization_container_id: String,
    image: String,
    configuration_sha256: String,
    compose_receipt_sha256: String,
    seal_creation_sha256: String,
    initialization_pending_sha256: String,
    initialization_result_sha256: String,
    initialization: InitializationResult,
    root_retired: bool,
    reboot_recovery_qualified: bool,
    installation_ready: bool,
}

/// Bind the public initialization proof to the successful owned setup job. The
/// private root token and recovery key remain in the mapped OpenBao state.
pub(crate) fn record_initialization(
    installation: &Path,
    state: &mut InstallerState,
    session: &ComposeSession,
    receipt: &ComposeReceipt,
) -> Result<()> {
    state.require_live_phase(Phase::Provisioning)?;
    state.with_inspection(|view| verify(view, installation))?;
    let owner = state.journal().installation_id().to_string();
    let runtime = state.journal().runtime().ok_or(REFUSED)?;
    let environment = &session.model()["services"]["openbao-bootstrap"]["environment"];
    let attempt = environment["MARTY_OPENBAO_STATIC_INIT_ATTEMPT_ID"]
        .as_str()
        .ok_or(REFUSED)?;
    let resources = receipt.resources.as_ref().ok_or(REFUSED)?;
    let job = resources
        .containers
        .get("openbao-bootstrap")
        .ok_or(REFUSED)?;
    let openbao = resources.containers.get("openbao").ok_or(REFUSED)?;
    require(
        environment["MARTY_OPENBAO_STATIC_SEAL"] == "1"
            && environment["MARTY_OPENBAO_LOCAL_CONTROL"] == "1"
            && environment["MARTY_INSTALLATION_ID"] == owner
            && receipt.command_succeeded
            && receipt.observation_validated
            && receipt.client_exit_code == Some(0)
            && receipt.failure_class.is_none()
            && receipt.operation == "setup-openbao-bootstrap"
            && receipt.project == state.journal().compose_project()
            && receipt.engine_id == runtime.engine_id
            && receipt.configuration_sha256 == session.configuration_sha256()
            && !receipt.installation_ready
            && job.setup
            && job.image == openbao.image
            && job
                .setup_execution
                .as_ref()
                .is_some_and(|v| v.completed_without_restart),
    )?;
    let (intent_bytes, result_bytes, result) = public_result(installation)?;
    result.validate(&owner, attempt)?;
    let seal_creation_sha256 = state.with_inspection(|view| {
        verify(view, installation)?;
        Ok(installer_release::sha256(&view.read_evidence(RECORD)?))
    })?;
    let record = InitializationObservation {
        schema: "elevenid.installer-openbao-static-initialization/v1".into(),
        installation_id: owner,
        engine_id: runtime.engine_id.clone(),
        container_id: openbao.id.clone(),
        initialization_container_id: job.id.clone(),
        image: openbao.image.clone(),
        configuration_sha256: receipt.configuration_sha256.clone(),
        compose_receipt_sha256: crate::installer_jobs::receipt_digest(receipt)?,
        seal_creation_sha256,
        initialization_pending_sha256: installer_release::sha256(&intent_bytes),
        initialization_result_sha256: installer_release::sha256(&result_bytes),
        initialization: result,
        root_retired: false,
        reboot_recovery_qualified: false,
        installation_ready: false,
    };
    let (current_intent, current_result, _) = public_result(installation)?;
    require(current_intent == intent_bytes && current_result == result_bytes)?;
    state.write_evidence(
        INITIALIZATION,
        &serde_json::to_vec(&record).map_err(|_| REFUSED)?,
    )
}

pub(crate) fn require_initialized_cluster(
    state: &LockedInspection,
    installation: &Path,
    cluster: &str,
) -> Result<()> {
    verify(state, installation)?;
    let observation: InitializationObservation = serde_json::from_value(
        installer_json::decode(&state.read_evidence(INITIALIZATION)?).map_err(|_| REFUSED)?,
    )
    .map_err(|_| REFUSED)?;
    let (intent, result_bytes, result) = public_result(installation)?;
    result.validate(
        &state.journal().installation_id().to_string(),
        &observation.initialization.attempt_id,
    )?;
    require(
        observation.schema == "elevenid.installer-openbao-static-initialization/v1"
            && observation.installation_id == result.installation_id
            && observation.engine_id == state.journal().runtime().ok_or(REFUSED)?.engine_id
            && observation.seal_creation_sha256
                == installer_release::sha256(&state.read_evidence(RECORD)?)
            && observation.initialization_pending_sha256 == installer_release::sha256(&intent)
            && observation.initialization_result_sha256 == installer_release::sha256(&result_bytes)
            && observation.initialization == result
            && result.cluster_id == cluster
            && !observation.root_retired
            && !observation.reboot_recovery_qualified
            && !observation.installation_ready,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::installer_state::Identity;
    use std::os::unix::fs::PermissionsExt;

    fn fixture() -> (tempfile::TempDir, std::path::PathBuf, InstallerState) {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let install = root.path().join("installation");
        let mut state = InstallerState::create(
            &install,
            Identity {
                release_tag: "v0.1.0".into(),
                source_sha: "a".repeat(40),
                inventory_sha256: format!("sha256:{}", "b".repeat(64)),
            },
        )
        .unwrap();
        state.create_private_directory("evidence").unwrap();
        (root, install, state)
    }

    #[test]
    fn fresh_key_is_private_outside_the_single_readable_projection_and_never_replaced() {
        let (_root, install, mut state) = fixture();
        assert!(prepare_for_install(&mut state, &install).is_err());
        assert!(!install.join("openbao-seal").exists());
        state.advance(Phase::Verified).unwrap();
        state.advance(Phase::Provisioning).unwrap();
        prepare_for_install(&mut state, &install).unwrap();
        state
            .with_inspection(|view| verify(view, &install))
            .unwrap();
        let original = std::fs::read(install.join("openbao-seal/key/static.key")).unwrap();
        assert_eq!(original.len(), 32);
        let record = std::fs::read(install.join("evidence").join(RECORD)).unwrap();
        assert!(!record.windows(32).any(|bytes| bytes == original));
        assert!(prepare_for_install(&mut state, &install).is_err());
        assert_eq!(
            std::fs::read(install.join("openbao-seal/key/static.key")).unwrap(),
            original
        );
    }

    #[test]
    fn held_seal_descriptors_do_not_admit_replaced_children_or_key() {
        let (_root, install, mut state) = fixture();
        state.advance(Phase::Verified).unwrap();
        state.advance(Phase::Provisioning).unwrap();
        prepare_for_install(&mut state, &install).unwrap();
        let outer_path = install.join("openbao-seal");
        let outer = fs::directory(&outer_path, REFUSED).unwrap();
        let projection =
            fs::open_child(&outer, "key", libc::O_RDONLY | libc::O_DIRECTORY, REFUSED).unwrap();
        let key = fs::open_child(&projection, "static.key", libc::O_PATH, REFUSED).unwrap();
        let captured_key = MetadataBinding::observe(&key, false, 0o444).unwrap();
        std::fs::rename(
            outer_path.join("key/static.key"),
            outer_path.join("saved.key"),
        )
        .unwrap();
        std::fs::write(outer_path.join("key/static.key"), [9u8; 32]).unwrap();
        std::fs::set_permissions(
            outer_path.join("key/static.key"),
            std::fs::Permissions::from_mode(0o444),
        )
        .unwrap();
        assert!(require_child_binding(
            &projection,
            "static.key",
            &key,
            false,
            0o444,
            &captured_key
        )
        .is_err());
        for (name, mode) in [("key", 0o755), ("initialization", 0o700)] {
            let held =
                fs::open_child(&outer, name, libc::O_RDONLY | libc::O_DIRECTORY, REFUSED).unwrap();
            let captured = MetadataBinding::observe(&held, true, mode).unwrap();
            std::fs::rename(
                outer_path.join(name),
                outer_path.join(format!("old-{name}")),
            )
            .unwrap();
            std::fs::create_dir(outer_path.join(name)).unwrap();
            std::fs::set_permissions(outer_path.join(name), std::fs::Permissions::from_mode(mode))
                .unwrap();
            assert!(require_child_binding(&outer, name, &held, true, mode, &captured).is_err());
        }
    }

    #[test]
    fn in_place_key_change_cannot_match_an_earlier_snapshot() {
        let (_root, install, mut state) = fixture();
        state.advance(Phase::Verified).unwrap();
        state.advance(Phase::Provisioning).unwrap();
        prepare_for_install(&mut state, &install).unwrap();
        let outer = fs::directory(&install.join("openbao-seal"), REFUSED).unwrap();
        let projection =
            fs::open_child(&outer, "key", libc::O_RDONLY | libc::O_DIRECTORY, REFUSED).unwrap();
        let held = fs::open_child(&projection, "static.key", libc::O_PATH, REFUSED).unwrap();
        let captured = MetadataBinding::observe(&held, false, 0o444).unwrap();
        let path = install.join("openbao-seal/key/static.key");
        std::thread::sleep(std::time::Duration::from_millis(2));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&path, [8u8; 32]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();
        assert_eq!(captured.inode, held.metadata().unwrap().ino());
        assert!(
            require_child_binding(&projection, "static.key", &held, false, 0o444, &captured)
                .is_err()
        );
    }

    #[test]
    fn initialization_proof_requires_static_seal_and_does_not_claim_retirement_or_recovery() {
        let id = "2e052c77-efe8-44c6-9421-9ef15fe8ee7c";
        let value = serde_json::json!({"schema":"elevenid.openbao-static-init-result/v1",
            "installation_id":id,"attempt_id":id,"cluster_id":id,"seal_type":"static",
            "initialized":true,"unsealed_ready":true,"recovery_key_written":true,"root_token_written":true,
            "root_retired":false,"initialization_replayed":false,"installation_ready":false});
        let parsed: InitializationResult = serde_json::from_value(value.clone()).unwrap();
        parsed.validate(id, id).unwrap();
        for field in value.as_object().unwrap().keys() {
            let mut missing = value.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(
                serde_json::from_value::<InitializationResult>(missing).is_err(),
                "missing {field}"
            );
            let mut changed = value.clone();
            changed[field] = match field.as_str() {
                "initialized"
                | "unsealed_ready"
                | "recovery_key_written"
                | "root_token_written" => serde_json::json!(false),
                "root_retired" | "initialization_replayed" | "installation_ready" => {
                    serde_json::json!(true)
                }
                _ => serde_json::json!("foreign"),
            };
            assert!(
                serde_json::from_value::<InitializationResult>(changed)
                    .unwrap()
                    .validate(id, id)
                    .is_err(),
                "changed {field}"
            );
        }
        let intent = serde_json::json!({"schema":"elevenid.openbao-static-init-intent/v1",
            "installation_id":id,"attempt_id":id,"seal_type":"static","recovery_shares":1,"recovery_threshold":1});
        require_intent(&serde_json::to_vec(&intent).unwrap(), &parsed).unwrap();
        let mut wrong = intent.clone();
        wrong["seal_type"] = serde_json::json!("shamir");
        assert!(require_intent(&serde_json::to_vec(&wrong).unwrap(), &parsed).is_err());
        let mut secret = value;
        secret["recovery_key"] = serde_json::json!("never-public");
        assert!(serde_json::from_value::<InitializationResult>(secret).is_err());
    }

    #[test]
    fn lost_or_changed_key_requires_restore_without_generation_or_adoption() {
        let (_root, install, mut state) = fixture();
        state.advance(Phase::Verified).unwrap();
        state.advance(Phase::Provisioning).unwrap();
        prepare_for_install(&mut state, &install).unwrap();
        let key = install.join("openbao-seal/key/static.key");
        std::fs::remove_file(&key).unwrap();
        assert!(state
            .with_inspection(|view| verify(view, &install))
            .is_err());
        assert!(!key.exists());
        std::fs::write(&key, [7u8; 32]).unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o444)).unwrap();
        assert!(state
            .with_inspection(|view| verify(view, &install))
            .is_err());
    }
}
