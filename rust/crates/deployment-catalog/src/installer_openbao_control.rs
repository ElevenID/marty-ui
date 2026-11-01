//! Bind the fresh local-control enrollment to its owned Compose setup job.
//! The receipt establishes scoped recovery authority, never root retirement,
//! listener reload, reboot recovery or complete installation readiness.
#![cfg(target_os = "linux")]

use crate::{
    installer_compose::{ComposeReceipt, ComposeSession},
    installer_host_fs as fs, installer_json, installer_release,
    installer_state::InstallerState,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use spki::der::Encode;
use std::{collections::BTreeSet, fs::File, os::unix::fs::MetadataExt, path::Path};

type Result<T> = std::result::Result<T, String>;
const REFUSED: &str = "OpenBao local-control enrollment evidence differs; retain the owned setup job and private control identity for reconciliation";
pub(crate) const OBSERVATION: &str = "openbao-control-observation.json";

fn require(value: bool) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}
fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn identifier(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| id.to_string() == value)
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct EnrollmentReceipt {
    pub schema: String,
    pub installation_id: String,
    pub attempt_id: String,
    pub cluster_id: String,
    pub issuer_id: String,
    pub ca_sha256: String,
    pub spki_sha256: String,
    pub policy_sha256: String,
    pub scoped_login_verified: bool,
    pub scoped_signing_verified: bool,
    pub forbidden_operations_denied: bool,
    pub verification_token_revoked: bool,
    pub existing_ca_key_retained: bool,
    pub node_key_preserved: bool,
    pub root_retired: bool,
}
impl EnrollmentReceipt {
    fn validate(&self, installation: &str, attempt: &str) -> Result<()> {
        require(
            self.schema == "elevenid.openbao-control-enrollment-result/v1"
                && self.installation_id == installation
                && self.attempt_id == attempt
                && [installation, attempt, &self.cluster_id, &self.issuer_id]
                    .into_iter()
                    .all(identifier)
                && [&self.ca_sha256, &self.spki_sha256, &self.policy_sha256]
                    .into_iter()
                    .all(|v| hash(v))
                && self.scoped_login_verified
                && self.scoped_signing_verified
                && self.forbidden_operations_denied
                && self.verification_token_revoked
                && self.existing_ca_key_retained
                && self.node_key_preserved
                && !self.root_retired,
        )
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollmentIntent {
    schema: String,
    installation_id: String,
    attempt_id: String,
    cluster_id: String,
    ca_sha256: String,
    spki_sha256: String,
    root_retired: bool,
    existing_ca_key_retained: bool,
}

fn require_intent(bytes: &[u8], result: &EnrollmentReceipt) -> Result<()> {
    let intent: EnrollmentIntent =
        serde_json::from_value(installer_json::decode(bytes).map_err(|_| REFUSED)?)
            .map_err(|_| REFUSED)?;
    require(
        intent.schema == "elevenid.openbao-control-enrollment-intent/v1"
            && intent.installation_id == result.installation_id
            && intent.attempt_id == result.attempt_id
            && intent.cluster_id == result.cluster_id
            && intent.ca_sha256 == result.ca_sha256
            && intent.spki_sha256 == result.spki_sha256
            && !intent.root_retired
            && intent.existing_ca_key_retained,
    )
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct DirectoryBinding {
    device: u64,
    inode: u64,
    owner_uid: u32,
    owner_gid: u32,
    mode: u32,
}

impl DirectoryBinding {
    fn observe(file: &File) -> Result<Self> {
        let metadata = file.metadata().map_err(|_| REFUSED)?;
        require(metadata.is_dir() && metadata.mode() & 0o7777 == 0o700)?;
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            owner_uid: metadata.uid(),
            owner_gid: metadata.gid(),
            mode: metadata.mode() & 0o7777,
        })
    }
}

fn mapped_directory(parent: &File, name: &str) -> Result<(File, DirectoryBinding)> {
    // The unprivileged host cannot read the image-owned 0700 directory after
    // TLS initialization. O_PATH observes the directory itself without opening
    // its contents, following links, or changing its owner or permissions.
    let file = fs::open_child(parent, name, libc::O_PATH | libc::O_DIRECTORY, REFUSED)?;
    let binding = DirectoryBinding::observe(&file)?;
    Ok((file, binding))
}

fn require_socket_creation(
    created: &Value,
    operator: DirectoryBinding,
    socket: DirectoryBinding,
    state: DirectoryBinding,
) -> Result<()> {
    let before: DirectoryBinding = serde_json::from_value(created.clone()).map_err(|_| REFUSED)?;
    require(
        before.device == socket.device
            && before.inode == socket.inode
            && before.mode == 0o700
            && socket.mode == 0o700
            && state.mode == 0o700
            && before.owner_uid == operator.owner_uid
            && before.owner_gid == operator.owner_gid
            && socket.owner_uid == state.owner_uid
            && socket.owner_gid == state.owner_gid,
    )
}

fn require_mapped_binding(
    parent: &File,
    name: &str,
    held: &File,
    original: DirectoryBinding,
) -> Result<()> {
    require(
        DirectoryBinding::observe(held)? == original
            && mapped_directory(parent, name)?.1 == original,
    )
}

fn read_public_enrollment(identity: &File, name: &str) -> Result<Vec<u8>> {
    let held = fs::open_child(identity, name, libc::O_PATH, REFUSED)?;
    let metadata = held.metadata().map_err(|_| REFUSED)?;
    let owner = identity.metadata().map_err(|_| REFUSED)?;
    require(
        metadata.is_file()
            && metadata.nlink() == 1
            && metadata.uid() == owner.uid()
            && metadata.gid() == owner.gid()
            && metadata.mode() & 0o7777 == 0o600
            && (1..=8192).contains(&metadata.len()),
    )?;
    let bytes = fs::read_entry(identity, name, 0o600, false, REFUSED)?;
    let current = fs::open_child(identity, name, libc::O_PATH, REFUSED)?
        .metadata()
        .map_err(|_| REFUSED)?;
    require(
        bytes.len() as u64 == metadata.len()
            && (
                metadata.dev(),
                metadata.ino(),
                metadata.uid(),
                metadata.gid(),
                metadata.mode(),
                metadata.nlink(),
                metadata.len(),
            ) == (
                current.dev(),
                current.ino(),
                current.uid(),
                current.gid(),
                current.mode(),
                current.nlink(),
                current.len(),
            ),
    )?;
    Ok(bytes)
}

/// Called only after the exclusive setup job completed and its exact container,
/// image, configuration, mounts and execution timestamps were re-observed.
pub(crate) fn record_enrollment(
    installation: &Path,
    state: &mut InstallerState,
    session: &ComposeSession,
    receipt: &ComposeReceipt,
) -> Result<()> {
    state.require_live_phase(crate::installer_state::Phase::Provisioning)?;
    let owner = state.journal().installation_id().to_string();
    let runtime = state.journal().runtime().ok_or(REFUSED)?;
    let command = session.model()["services"]["installer-control-enroll"]["command"]
        .as_array()
        .ok_or(REFUSED)?;
    require(
        command.len() == 4
            && command[0] == "--installation-id"
            && command[1] == owner
            && command[2] == "--attempt-id",
    )?;
    let attempt = command[3].as_str().ok_or(REFUSED)?;
    let resources = receipt.resources.as_ref().ok_or(REFUSED)?;
    let job = resources
        .containers
        .get("installer-control-enroll")
        .ok_or(REFUSED)?;
    let openbao = resources.containers.get("openbao").ok_or(REFUSED)?;
    require(
        receipt.command_succeeded
            && receipt.observation_validated
            && receipt.client_exit_code == Some(0)
            && receipt.failure_class.is_none()
            && receipt.operation == "setup-installer-control-enroll"
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
    let control_path = installation.join("openbao-control");
    let identity_path = control_path.join("identity");
    let control = fs::directory(&control_path, REFUSED)?;
    let identity = fs::directory(&identity_path, REFUSED)?;
    let (created, installation_directory) = state.with_inspection(|view| {
        view.require_path_binding(installation)?;
        Ok((
            installer_json::decode(&view.read_evidence("openbao-control-created.json")?)
                .map_err(|_| REFUSED)?,
            view.installation_directory()
                .try_clone()
                .map_err(|_| REFUSED)?,
        ))
    })?;
    let bound = |expected: &Value, observed: &std::fs::Metadata| {
        expected["device"] == observed.dev()
            && expected["inode"] == observed.ino()
            && expected["owner_uid"] == observed.uid()
            && expected["owner_gid"] == observed.gid()
            && expected["mode"] == 0o700
    };
    require(
        created["schema"] == "elevenid.installer-openbao-control-created/v1"
            && created["installation_id"] == owner
            && created["enrolled"] == false
            && bound(&created, &control.metadata().map_err(|_| REFUSED)?)
            && bound(
                &created["children"]["identity"],
                &identity.metadata().map_err(|_| REFUSED)?,
            ),
    )?;
    let (socket, socket_binding) = mapped_directory(&control, "socket")?;
    let (openbao_state, state_binding) =
        mapped_directory(&installation_directory, "openbao-state")?;
    require_socket_creation(
        &created["children"]["socket"],
        DirectoryBinding::observe(&control)?,
        socket_binding,
        state_binding,
    )?;
    require(
        fs::file_names(&identity, REFUSED)?
            == BTreeSet::from([
                "enrollment-pending.json".into(),
                "enrollment-result.json".into(),
                "recovery.json".into(),
            ]),
    )?;
    let private_identity = fs::open_child(&identity, "recovery.json", libc::O_PATH, REFUSED)?;
    let metadata = private_identity.metadata().map_err(|_| REFUSED)?;
    require(
        metadata.is_file()
            && metadata.nlink() == 1
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.gid() == identity.metadata().map_err(|_| REFUSED)?.gid()
            && metadata.mode() & 0o7777 == 0o400
            && (1..=8192).contains(&metadata.len()),
    )?;
    let result_bytes = read_public_enrollment(&identity, "enrollment-result.json")?;
    let result: EnrollmentReceipt =
        serde_json::from_value(installer_json::decode(&result_bytes).map_err(|_| REFUSED)?)
            .map_err(|_| REFUSED)?;
    result.validate(&owner, attempt)?;
    state.with_inspection(|view| {
        crate::installer_openbao_seal::require_initialized_cluster(
            view,
            installation,
            &result.cluster_id,
        )
    })?;
    let intent_bytes = read_public_enrollment(&identity, "enrollment-pending.json")?;
    require_intent(&intent_bytes, &result)?;
    let secrets = fs::directory(&installation.join("secrets"), REFUSED)?;
    let ca_pem = fs::read_entry(&secrets, "openbao_tls_ca_cert", 0o644, false, REFUSED)?;
    let ca = crate::installer_ingress_provision::certificate(
        std::str::from_utf8(&ca_pem).map_err(|_| REFUSED)?,
    )?;
    require(installer_release::sha256(&ca.to_der().map_err(|_| REFUSED)?) == result.ca_sha256)?;
    fs::require_directory_binding(&control_path, &control, REFUSED)?;
    fs::require_directory_binding(&identity_path, &identity, REFUSED)?;
    state.with_inspection(|view| view.require_path_binding(installation))?;
    require_mapped_binding(&control, "socket", &socket, socket_binding)?;
    require_mapped_binding(
        &installation_directory,
        "openbao-state",
        &openbao_state,
        state_binding,
    )?;
    require(
        read_public_enrollment(&identity, "enrollment-pending.json")? == intent_bytes
            && read_public_enrollment(&identity, "enrollment-result.json")? == result_bytes,
    )?;
    let record = json!({
        "schema": "elevenid.installer-openbao-control-observation/v1",
        "installation_id": owner, "engine_id": runtime.engine_id,
        "container_id": openbao.id, "enrollment_container_id": job.id, "image": openbao.image,
        "configuration_sha256": receipt.configuration_sha256,
        "compose_receipt_sha256": crate::installer_jobs::receipt_digest(receipt)?,
        "socket_directory": socket_binding, "openbao_state_directory": state_binding,
        "enrollment_pending_sha256": installer_release::sha256(&intent_bytes),
        "enrollment_result_sha256": installer_release::sha256(&result_bytes), "enrollment": result,
        "root_retired": false, "automatic_recovery_qualified": false, "installation_ready": false,
    });
    state.write_evidence(
        OBSERVATION,
        &serde_json::to_vec(&record).map_err(|_| REFUSED)?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn result_value() -> Value {
        let id = "2e052c77-efe8-44c6-9421-9ef15fe8ee7c";
        json!({"schema":"elevenid.openbao-control-enrollment-result/v1",
            "installation_id":id,"attempt_id":id,"cluster_id":id,"issuer_id":id,
            "ca_sha256":"a".repeat(64),"spki_sha256":"b".repeat(64),"policy_sha256":"c".repeat(64),
            "scoped_login_verified":true,"scoped_signing_verified":true,"forbidden_operations_denied":true,
            "verification_token_revoked":true,"existing_ca_key_retained":true,"node_key_preserved":true,
            "root_retired":false})
    }

    fn intent_value() -> Value {
        let result = result_value();
        json!({"schema":"elevenid.openbao-control-enrollment-intent/v1",
            "installation_id":result["installation_id"],"attempt_id":result["attempt_id"],
            "cluster_id":result["cluster_id"],"ca_sha256":result["ca_sha256"],
            "spki_sha256":result["spki_sha256"],"root_retired":false,"existing_ca_key_retained":true})
    }

    fn private_dir() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        temp
    }

    #[test]
    fn enrollment_requires_all_scoped_proofs_and_keeps_root_retirement_separate() {
        let id = "2e052c77-efe8-44c6-9421-9ef15fe8ee7c";
        let value = result_value();
        let parsed: EnrollmentReceipt = serde_json::from_value(value.clone()).unwrap();
        parsed.validate(id, id).unwrap();
        for field in [
            "scoped_login_verified",
            "scoped_signing_verified",
            "forbidden_operations_denied",
            "verification_token_revoked",
            "existing_ca_key_retained",
            "node_key_preserved",
            "root_retired",
        ] {
            let mut changed = value.clone();
            changed[field] = json!(field == "root_retired");
            assert!(serde_json::from_value::<EnrollmentReceipt>(changed)
                .unwrap()
                .validate(id, id)
                .is_err());
        }
        assert!(parsed.validate(id, "foreign").is_err());
        let mut changed = value;
        changed["private_key"] = json!("not-permitted");
        assert!(serde_json::from_value::<EnrollmentReceipt>(changed).is_err());
    }

    #[test]
    fn intent_requires_every_field_and_exact_result_binding() {
        let result: EnrollmentReceipt = serde_json::from_value(result_value()).unwrap();
        let value = intent_value();
        require_intent(&serde_json::to_vec(&value).unwrap(), &result).unwrap();
        for field in value.as_object().unwrap().keys() {
            let mut missing = value.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(
                require_intent(&serde_json::to_vec(&missing).unwrap(), &result).is_err(),
                "missing {field}"
            );
            let mut changed = value.clone();
            changed[field] = match field.as_str() {
                "root_retired" => json!(true),
                "existing_ca_key_retained" => json!(false),
                "ca_sha256" | "spki_sha256" => json!("d".repeat(64)),
                "schema" => json!("unknown-schema"),
                _ => json!("ab1fab76-d7eb-4af9-a332-2c5e5b23a36d"),
            };
            assert!(
                require_intent(&serde_json::to_vec(&changed).unwrap(), &result).is_err(),
                "changed {field}"
            );
        }
        let mut private = value.clone();
        private["secret_id"] = json!("forbidden");
        assert!(require_intent(&serde_json::to_vec(&private).unwrap(), &result).is_err());
        let encoded = serde_json::to_string(&value).unwrap();
        let duplicate = encoded.replacen('{', "{\"root_retired\":false,", 1);
        for invalid in [duplicate, format!("{encoded} {{}}"), "{".into()] {
            assert!(require_intent(invalid.as_bytes(), &result).is_err());
        }
    }

    #[test]
    fn socket_creation_requires_original_inode_and_current_mapped_state_owner() {
        let operator = DirectoryBinding {
            device: 7,
            inode: 10,
            owner_uid: 1000,
            owner_gid: 1000,
            mode: 0o700,
        };
        let before = DirectoryBinding {
            inode: 11,
            ..operator
        };
        let socket = DirectoryBinding {
            owner_uid: 101000,
            owner_gid: 101001,
            ..before
        };
        let state = DirectoryBinding {
            inode: 12,
            ..socket
        };
        let created = serde_json::to_value(before).unwrap();
        require_socket_creation(&created, operator, socket, state).unwrap();
        for bad in [
            DirectoryBinding {
                device: 8,
                ..socket
            },
            DirectoryBinding {
                inode: 13,
                ..socket
            },
            DirectoryBinding {
                owner_uid: operator.owner_uid,
                ..socket
            },
            DirectoryBinding {
                owner_gid: operator.owner_gid,
                ..socket
            },
            DirectoryBinding {
                mode: 0o750,
                ..socket
            },
        ] {
            assert!(require_socket_creation(&created, operator, bad, state).is_err());
        }
        for field in ["device", "inode", "owner_uid", "owner_gid", "mode"] {
            let mut changed = created.clone();
            changed[field] = json!(0);
            assert!(
                require_socket_creation(&changed, operator, socket, state).is_err(),
                "creation {field}"
            );
        }
    }

    #[test]
    fn mapped_directory_binding_refuses_symlinks_mode_change_and_replacement() {
        let temp = private_dir();
        let parent = fs::directory(temp.path(), REFUSED).unwrap();
        let child = temp.path().join("socket");
        std::fs::create_dir(&child).unwrap();
        std::fs::set_permissions(&child, std::fs::Permissions::from_mode(0o700)).unwrap();
        let (held, original) = mapped_directory(&parent, "socket").unwrap();
        require_mapped_binding(&parent, "socket", &held, original).unwrap();
        symlink(&child, temp.path().join("alias")).unwrap();
        assert!(mapped_directory(&parent, "alias").is_err());
        std::fs::write(temp.path().join("regular"), b"not a directory").unwrap();
        assert!(mapped_directory(&parent, "regular").is_err());
        std::fs::set_permissions(&child, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(require_mapped_binding(&parent, "socket", &held, original).is_err());
        std::fs::set_permissions(&child, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::rename(&child, temp.path().join("old-socket")).unwrap();
        std::fs::create_dir(&child).unwrap();
        std::fs::set_permissions(&child, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(require_mapped_binding(&parent, "socket", &held, original).is_err());
    }

    #[test]
    fn public_enrollment_read_refuses_links_wrong_modes_and_oversized_files() {
        let temp = private_dir();
        let identity = fs::directory(temp.path(), REFUSED).unwrap();
        let path = temp.path().join("enrollment-pending.json");
        let bytes = serde_json::to_vec(&intent_value()).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            read_public_enrollment(&identity, "enrollment-pending.json").unwrap(),
            bytes
        );
        symlink(&path, temp.path().join("alias")).unwrap();
        assert!(read_public_enrollment(&identity, "alias").is_err());
        std::fs::hard_link(&path, temp.path().join("hardlink")).unwrap();
        assert!(read_public_enrollment(&identity, "enrollment-pending.json").is_err());
        std::fs::remove_file(temp.path().join("hardlink")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_public_enrollment(&identity, "enrollment-pending.json").is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&path, vec![b' '; 8193]).unwrap();
        assert!(read_public_enrollment(&identity, "enrollment-pending.json").is_err());
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_public_enrollment(&identity, "enrollment-pending.json").is_err());
    }
}
