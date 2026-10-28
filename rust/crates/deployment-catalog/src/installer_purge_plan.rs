//! Read-only preparation of a private, point-in-time purge candidate plan.
//! This module has no CLI or deletion caller. The external coordinator must
//! authenticate the host creation receipt, stop writers, obtain confirmation,
//! and persist the exact bytes through the purge ledger before any mutation.
#![cfg(target_os = "linux")]
#![allow(dead_code)] // Dormant until the reviewed purge coordinator exists.

use crate::{
    installer_host_snapshot::{self, BuildOutcome, RootSpec},
    installer_purge_host::{HostIdentity, HostPurgeEntry},
    installer_runtime::DockerRunner,
    installer_state::{CleanupState, ExecutionScope, Journal, LockedInspection, Phase},
};
use chrono::DateTime;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};
use uuid::Uuid;

const SCHEMA: &str = "elevenid.installer-private-storage-candidate/v1";

/// All variants are fixed strings; no file path, Docker output, or label is
/// copied into a public error. None authorizes deletion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IncompleteReason {
    InstallationChanged,
    CleanupNotComplete,
    MissingCreationEvidence,
    InvalidCreationEvidence,
    HostSnapshotIncomplete,
    DockerObservationIncomplete,
    DockerIdentityChanged,
    DockerResourcesRemain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UnsupportedReason {
    ClassifiedTestInstallation,
    UnexpectedLifecyclePhase,
    LegacyOrPreApplicationCleanup,
}

pub(crate) enum PrepareOutcome {
    /// Covers only the seven authenticated storage roots. It is still an
    /// incomplete whole-installation purge plan and cannot authorize deletion.
    IncompleteKnownStorageRoots(StorageCandidate),
    Incomplete(IncompleteReason),
    Unsupported(UnsupportedReason),
}

/// Private bytes include host child names and complete Docker volume labels.
/// Keep them in the coordinator's private sibling ledger; never serialize this
/// type to an operator report. The digest is SHA-256 of these exact bytes.
pub(crate) struct StorageCandidate {
    bytes: Vec<u8>,
    sha256: String,
}
impl StorageCandidate {
    /// Review material only. The purge ledger must not accept these bytes as a
    /// complete plan until an independent top-level inventory is authenticated.
    pub(crate) fn private_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub(crate) fn sha256(&self) -> &str {
        &self.sha256
    }
}

/// These identities must have come from an independently authenticated host
/// creation receipt. A plain spec or digest is not itself authentication.
pub(crate) struct AuthenticatedHostRoots<'a> {
    pub expected_root: &'a HostIdentity,
    pub expected_mount: u64,
    pub specs: &'a [RootSpec],
    pub receipt_sha256: &'a str,
}

/// Fresh first-attempt observation only. A resumed purge must load its saved
/// ledger plan; it must not require the retained volume to still be present.
pub(crate) enum NormalProfileError {
    Incomplete(IncompleteReason),
    Unsupported(UnsupportedReason),
}

/// Completed uninstall and creation receipt have been checked, but Docker
/// readiness has not. This state cannot be used as a purge plan.
pub(crate) struct PendingNormalProfileFacts {
    installation_id: Uuid,
    journal_revision: u64,
    plan_sha256: String,
    plan: CleanupPlan,
    volume: VolumeCreation,
}

/// Typed, point-in-time facts for a fresh first attempt. These are not an
/// ownership proof, a durable snapshot, or deletion authorization.
pub(crate) struct ValidatedNormalProfileFacts {
    pub(crate) installation_id: Uuid,
    pub(crate) journal_revision: u64,
    pub(crate) engine_id: String,
    pub(crate) cleanup_plan_sha256: String,
    pub(crate) project: String,
    pub(crate) network_id: String,
    pub(crate) network_name: String,
    pub(crate) resources: Vec<CleanupResource>,
    pub(crate) volume: VolumeCreation,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CleanupResource {
    pub(crate) role: String,
    pub(crate) container_id: String,
    pub(crate) bao: bool,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CleanupPlan {
    schema: String,
    installation_id: String,
    engine_id: String,
    project: String,
    network_id: String,
    network_name: String,
    retained_redis_volume: Option<String>,
    #[serde(default)]
    absent_redis_volume: Option<String>,
    resources: Vec<CleanupResource>,
    source_hashes: BTreeMap<String, String>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VolumeCreation {
    pub(crate) schema: String,
    pub(crate) installation_id: String,
    pub(crate) engine_id: String,
    pub(crate) name: String,
    pub(crate) created_at: String,
    pub(crate) labels: BTreeMap<String, String>,
    pub(crate) driver: String,
    pub(crate) scope: String,
}
#[derive(Serialize)]
struct PrivatePlan<'a> {
    schema: &'static str,
    coverage: &'static str,
    installation_id: Uuid,
    journal_revision: u64,
    engine_id: &'a str,
    cleanup_plan_sha256: String,
    host_receipt_sha256: &'a str,
    host_root: &'a HostIdentity,
    host_mount_id: u64,
    host_entries: &'a [HostPurgeEntry],
    containers: Vec<&'a CleanupResource>,
    network_id: &'a str,
    network_name: &'a str,
    volume: &'a VolumeCreation,
    point_in_time: bool,
    deletion_eligible: bool,
    installation_root_included: bool,
    deletion_authorized: bool,
}

fn hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn supported_journal(journal: &Journal) -> Result<(), UnsupportedReason> {
    if !matches!(journal.execution_scope(), ExecutionScope::Unclassified) {
        return Err(UnsupportedReason::ClassifiedTestInstallation);
    }
    // Current normal installation intentionally remains Provisioning after
    // application startup observations. Full cleanup records, not a Ready
    // phase, establish that the 34 recorded resources were uninstalled.
    if journal.phase() != Phase::Provisioning || journal.runtime().is_none() {
        return Err(UnsupportedReason::UnexpectedLifecyclePhase);
    }
    Ok(())
}
fn lines(output: &str, names: bool) -> Option<BTreeSet<String>> {
    let mut result = BTreeSet::new();
    for item in output.lines() {
        let valid = if names {
            !item.is_empty()
                && item.len() <= 255
                && item
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        } else {
            hex64(item)
        };
        if !valid || !result.insert(item.to_owned()) {
            return None;
        }
    }
    Some(result)
}
fn single(output: &str) -> Option<serde_json::Value> {
    let value: serde_json::Value = serde_json::from_str(output).ok()?;
    let list = value.as_array()?;
    (list.len() == 1 && list[0].is_object()).then(|| list[0].clone())
}
fn volume_evidence(bytes: &[u8], id: Uuid, engine: &str, name: &str) -> Option<VolumeCreation> {
    // Installer evidence is written as compact JSON. Re-encoding with preserved
    // field order rejects duplicate object keys and ambiguous rewrites.
    let raw: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    if serde_json::to_vec(&raw).ok()?.as_slice() != bytes {
        return None;
    }
    let v: VolumeCreation = serde_json::from_slice(bytes).ok()?;
    let project = format!("marty-install-{}", id.simple());
    (v.schema == "elevenid.installer-created-volume/v1"
        && v.installation_id == id.to_string()
        && v.engine_id == engine
        && v.name == name
        && v.name == format!("{project}_redis-socket")
        && v.driver == "local"
        && v.scope == "local"
        && v.created_at.len() <= 64
        && DateTime::parse_from_rfc3339(&v.created_at).is_ok()
        && (2..=8).contains(&v.labels.len())
        && v.labels.get("com.docker.compose.project") == Some(&project)
        && v.labels
            .get("com.docker.compose.volume")
            .is_some_and(|s| s == "redis-socket")
        && v.labels.iter().all(|(k, val)| {
            !k.is_empty()
                && k.len() <= 128
                && val.len() <= 256
                && k.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                && !val.chars().any(char::is_control)
        }))
    .then_some(v)
}

trait DockerRead {
    fn engine_id(&self) -> Result<String, ()>;
    fn run(&self, args: &[&str]) -> Result<String, ()>;
}
impl DockerRead for DockerRunner {
    fn engine_id(&self) -> Result<String, ()> {
        self.preflight().map(|v| v.engine_id).map_err(|_| ())
    }
    fn run(&self, args: &[&str]) -> Result<String, ()> {
        self.run_checked(args).map_err(|_| ())
    }
}

fn docker_absent_except_volume<D: DockerRead>(
    docker: &D,
    plan: &CleanupPlan,
    volume: &VolumeCreation,
) -> Result<(), IncompleteReason> {
    use IncompleteReason::*;
    if docker
        .engine_id()
        .map_err(|_| DockerObservationIncomplete)?
        != plan.engine_id
    {
        return Err(DockerIdentityChanged);
    }
    let run = |args: &[&str]| docker.run(args).map_err(|_| DockerObservationIncomplete);
    let all_containers =
        lines(&run(&["ps", "-aq", "--no-trunc"])?, false).ok_or(DockerObservationIncomplete)?;
    let project_filter = format!("label=com.docker.compose.project={}", plan.project);
    let owned_containers = lines(
        &run(&["ps", "-aq", "--no-trunc", "--filter", &project_filter])?,
        false,
    )
    .ok_or(DockerObservationIncomplete)?;
    let install_filter = format!("label=com.elevenid.installer.id={}", plan.installation_id);
    let tagged_containers = lines(
        &run(&["ps", "-aq", "--no-trunc", "--filter", &install_filter])?,
        false,
    )
    .ok_or(DockerObservationIncomplete)?;
    if !owned_containers.is_empty()
        || !tagged_containers.is_empty()
        || plan
            .resources
            .iter()
            .any(|r| all_containers.contains(&r.container_id))
    {
        return Err(DockerResourcesRemain);
    }
    let all_networks = lines(&run(&["network", "ls", "-q", "--no-trunc"])?, false)
        .ok_or(DockerObservationIncomplete)?;
    let project_networks = lines(
        &run(&[
            "network",
            "ls",
            "-q",
            "--no-trunc",
            "--filter",
            &project_filter,
        ])?,
        false,
    )
    .ok_or(DockerObservationIncomplete)?;
    if all_networks.contains(&plan.network_id) || !project_networks.is_empty() {
        return Err(DockerResourcesRemain);
    }
    let listed = lines(
        &run(&[
            "volume",
            "ls",
            "-q",
            "--filter",
            &format!("name={}", volume.name),
        ])?,
        true,
    )
    .ok_or(DockerObservationIncomplete)?;
    if listed != BTreeSet::from([volume.name.clone()]) {
        return Err(DockerResourcesRemain);
    }
    let project_volumes = lines(
        &run(&["volume", "ls", "-q", "--filter", &project_filter])?,
        true,
    )
    .ok_or(DockerObservationIncomplete)?;
    if project_volumes != listed {
        return Err(DockerResourcesRemain);
    }
    let attached = lines(
        &run(&[
            "ps",
            "-a",
            "-q",
            "--no-trunc",
            "--filter",
            &format!("volume={}", volume.name),
        ])?,
        false,
    )
    .ok_or(DockerObservationIncomplete)?;
    if !attached.is_empty() {
        return Err(DockerResourcesRemain);
    }
    let observed =
        single(&run(&["volume", "inspect", &volume.name])?).ok_or(DockerObservationIncomplete)?;
    let labels = observed["Labels"]
        .as_object()
        .ok_or(DockerObservationIncomplete)?;
    let exact_labels = labels.len() == volume.labels.len()
        && volume
            .labels
            .iter()
            .all(|(k, v)| labels.get(k).is_some_and(|s| s == v));
    if observed["Name"] != volume.name
        || observed["CreatedAt"] != volume.created_at
        || observed["Driver"] != "local"
        || observed["Scope"] != "local"
        || !(observed["Options"].is_null() || observed["Options"] == serde_json::json!({}))
        || !exact_labels
    {
        return Err(DockerIdentityChanged);
    }
    Ok(())
}

/// Inspect only a fresh first attempt under the journal lock. The caller must
/// independently establish host custody and stop writers before planning.
pub(crate) fn completed_normal_profile_cleanup(
    locked: &LockedInspection,
    installation: &Path,
) -> Result<PendingNormalProfileFacts, NormalProfileError> {
    use IncompleteReason::*;
    if locked.require_path_binding(installation).is_err() || locked.require_unchanged().is_err() {
        return Err(NormalProfileError::Incomplete(InstallationChanged));
    }
    let journal = locked.journal();
    supported_journal(journal).map_err(NormalProfileError::Unsupported)?;
    match locked.cleanup_status() {
        Ok(status)
            if status.state == CleanupState::Completed && status.data_retained == Some(true) => {}
        Ok(_) => return Err(NormalProfileError::Incomplete(CleanupNotComplete)),
        Err(_) => return Err(NormalProfileError::Incomplete(InstallationChanged)),
    }
    let plan_bytes = match locked.diagnostic_record("uninstall-plan.json", true) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return Err(NormalProfileError::Incomplete(CleanupNotComplete)),
        Err(_) => return Err(NormalProfileError::Incomplete(InstallationChanged)),
    };
    let Ok(plan) = serde_json::from_slice::<CleanupPlan>(&plan_bytes) else {
        return Err(NormalProfileError::Incomplete(CleanupNotComplete));
    };
    let runtime = journal.runtime().expect("checked above");
    if plan.schema != "elevenid.installer-uninstall-plan/v1"
        || plan.installation_id != journal.installation_id().to_string()
        || plan.engine_id != runtime.engine_id
        || plan.project != journal.compose_project()
        || !hex64(&plan.network_id)
        || plan.network_name != format!("{}-bao_default", plan.project)
        || plan.resources.len() != 34
        || plan.retained_redis_volume.is_none()
        || plan.absent_redis_volume.is_some()
        || plan.resources.iter().any(|r| !hex64(&r.container_id))
    {
        return Err(NormalProfileError::Unsupported(
            UnsupportedReason::LegacyOrPreApplicationCleanup,
        ));
    }
    let volume_name = plan
        .retained_redis_volume
        .as_deref()
        .expect("checked above");
    let receipt_bytes = match locked.diagnostic_record("application-created-volume.json", true) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return Err(NormalProfileError::Incomplete(MissingCreationEvidence)),
        Err(_) => return Err(NormalProfileError::Incomplete(InvalidCreationEvidence)),
    };
    let Some(volume) = volume_evidence(
        &receipt_bytes,
        journal.installation_id(),
        &runtime.engine_id,
        volume_name,
    ) else {
        return Err(NormalProfileError::Incomplete(InvalidCreationEvidence));
    };
    Ok(PendingNormalProfileFacts {
        installation_id: journal.installation_id(),
        journal_revision: journal.revision(),
        plan_sha256: format!("{:x}", Sha256::digest(&plan_bytes)),
        plan,
        volume,
    })
}

impl PendingNormalProfileFacts {
    pub(crate) fn verify_docker(
        self,
        docker: &DockerRunner,
    ) -> Result<ValidatedNormalProfileFacts, IncompleteReason> {
        self.verify_docker_with(docker)
    }

    fn verify_docker_with<D: DockerRead>(
        self,
        docker: &D,
    ) -> Result<ValidatedNormalProfileFacts, IncompleteReason> {
        docker_absent_except_volume(docker, &self.plan, &self.volume)?;
        Ok(ValidatedNormalProfileFacts {
            installation_id: self.installation_id,
            journal_revision: self.journal_revision,
            engine_id: self.plan.engine_id,
            cleanup_plan_sha256: self.plan_sha256,
            project: self.plan.project,
            network_id: self.plan.network_id,
            network_name: self.plan.network_name,
            resources: self.plan.resources,
            volume: self.volume,
        })
    }
}

/// Produces only a candidate plan. The caller must hold the journal lock and
/// independently authenticate `host` against creation-time identity evidence.
pub(crate) fn prepare(
    locked: &LockedInspection,
    installation: &Path,
    host: AuthenticatedHostRoots<'_>,
    docker: &DockerRunner,
) -> PrepareOutcome {
    use IncompleteReason::*;
    if locked.require_path_binding(installation).is_err() || locked.require_unchanged().is_err() {
        return PrepareOutcome::Incomplete(InstallationChanged);
    }
    let journal = locked.journal();
    if let Err(reason) = supported_journal(journal) {
        return PrepareOutcome::Unsupported(reason);
    }
    // The snapshot builder owns the exact fixed-root set and rejects missing,
    // duplicate or unknown specifications, including auxiliary evidence roots.
    if !hex64(host.receipt_sha256) || host.expected_mount == 0 {
        return PrepareOutcome::Incomplete(HostSnapshotIncomplete);
    }
    let pending = match completed_normal_profile_cleanup(locked, installation) {
        Ok(facts) => facts,
        Err(NormalProfileError::Incomplete(reason)) => return PrepareOutcome::Incomplete(reason),
        Err(NormalProfileError::Unsupported(reason)) => return PrepareOutcome::Unsupported(reason),
    };
    let snapshot = match installer_host_snapshot::build(
        locked,
        installation,
        host.expected_root,
        host.expected_mount,
        host.specs,
    ) {
        BuildOutcome::Complete(v) => v,
        BuildOutcome::Incomplete(_) => return PrepareOutcome::Incomplete(HostSnapshotIncomplete),
    };
    if snapshot.installation_id != journal.installation_id()
        || snapshot.entries.is_empty()
        || !snapshot.not_atomic_snapshot
        || snapshot.coverage != "known_host_storage_roots_only"
        || snapshot.deletion_eligible
    {
        return PrepareOutcome::Incomplete(HostSnapshotIncomplete);
    }
    let facts = match pending.verify_docker(docker) {
        Ok(facts) => facts,
        Err(reason) => return PrepareOutcome::Incomplete(reason),
    };
    if locked.require_path_binding(installation).is_err() || locked.require_unchanged().is_err() {
        return PrepareOutcome::Incomplete(InstallationChanged);
    }
    let mut containers: Vec<_> = facts.resources.iter().collect();
    containers.sort_unstable_by(|a, b| a.container_id.cmp(&b.container_id));
    let private = PrivatePlan {
        schema: SCHEMA,
        coverage: snapshot.coverage,
        installation_id: facts.installation_id,
        journal_revision: facts.journal_revision,
        engine_id: &facts.engine_id,
        cleanup_plan_sha256: facts.cleanup_plan_sha256,
        host_receipt_sha256: host.receipt_sha256,
        host_root: &snapshot.root,
        host_mount_id: snapshot.mount_id,
        host_entries: &snapshot.entries,
        containers,
        network_id: &facts.network_id,
        network_name: &facts.network_name,
        volume: &facts.volume,
        point_in_time: true,
        deletion_eligible: false,
        installation_root_included: false,
        deletion_authorized: false,
    };
    let Ok(bytes) = serde_json::to_vec(&private) else {
        return PrepareOutcome::Incomplete(InstallationChanged);
    };
    let sha256 = format!("{:x}", Sha256::digest(&bytes));
    PrepareOutcome::IncompleteKnownStorageRoots(StorageCandidate { bytes, sha256 })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::installer_state::{Identity, InstallerState, RuntimeBinding};
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn current_normal_installer_provisioning_phase_is_supported() {
        let parent = tempfile::tempdir().unwrap();
        std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut state = InstallerState::create_with_runtime(
            &parent.path().join("installation"),
            Identity {
                source_sha: "a".repeat(40),
                release_tag: "v1.1.263".into(),
                inventory_sha256: format!("sha256:{}", "b".repeat(64)),
            },
            RuntimeBinding {
                docker_host: "unix:///var/run/docker.sock".into(),
                engine_id: "synthetic-engine".into(),
                openbao_port: 8200,
            },
        )
        .unwrap();
        assert_eq!(
            supported_journal(state.journal()),
            Err(UnsupportedReason::UnexpectedLifecyclePhase)
        );
        state.advance(Phase::Verified).unwrap();
        state.advance(Phase::Provisioning).unwrap();
        assert_eq!(supported_journal(state.journal()), Ok(()));
        state.advance(Phase::Provisioned).unwrap();
        assert_eq!(
            supported_journal(state.journal()),
            Err(UnsupportedReason::UnexpectedLifecyclePhase)
        );
    }

    fn fixture() -> (Uuid, CleanupPlan, VolumeCreation) {
        let id = Uuid::parse_str("12345678-1234-4234-8234-123456789abc").unwrap();
        let project = format!("marty-install-{}", id.simple());
        let volume = VolumeCreation {
            schema: "elevenid.installer-created-volume/v1".into(),
            installation_id: id.to_string(),
            engine_id: "synthetic-engine".into(),
            name: format!("{project}_redis-socket"),
            created_at: "2026-10-27T12:30:00Z".into(),
            labels: BTreeMap::from([
                ("com.docker.compose.project".into(), project.clone()),
                ("com.docker.compose.volume".into(), "redis-socket".into()),
            ]),
            driver: "local".into(),
            scope: "local".into(),
        };
        let plan = CleanupPlan {
            schema: "elevenid.installer-uninstall-plan/v1".into(),
            installation_id: id.to_string(),
            engine_id: "synthetic-engine".into(),
            project: project.clone(),
            network_id: "a".repeat(64),
            network_name: format!("{project}-bao_default"),
            retained_redis_volume: Some(volume.name.clone()),
            absent_redis_volume: None,
            resources: vec![CleanupResource {
                role: "synthetic".into(),
                container_id: "b".repeat(64),
                bao: false,
            }],
            source_hashes: BTreeMap::new(),
        };
        (id, plan, volume)
    }

    struct MockDocker {
        engine: String,
        outputs: BTreeMap<Vec<String>, String>,
    }
    impl DockerRead for MockDocker {
        fn engine_id(&self) -> Result<String, ()> {
            Ok(self.engine.clone())
        }
        fn run(&self, args: &[&str]) -> Result<String, ()> {
            self.outputs
                .get(&args.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>())
                .cloned()
                .ok_or(())
        }
    }
    fn docker(plan: &CleanupPlan, volume: &VolumeCreation) -> MockDocker {
        let project = format!("label=com.docker.compose.project={}", plan.project);
        let install = format!("label=com.elevenid.installer.id={}", plan.installation_id);
        let mut outputs = BTreeMap::new();
        let mut put = |args: Vec<&str>, result: String| {
            outputs.insert(args.into_iter().map(str::to_owned).collect(), result);
        };
        put(vec!["ps", "-aq", "--no-trunc"], String::new());
        put(
            vec!["ps", "-aq", "--no-trunc", "--filter", &project],
            String::new(),
        );
        put(
            vec!["ps", "-aq", "--no-trunc", "--filter", &install],
            String::new(),
        );
        put(vec!["network", "ls", "-q", "--no-trunc"], String::new());
        put(
            vec!["network", "ls", "-q", "--no-trunc", "--filter", &project],
            String::new(),
        );
        let name = format!("name={}", volume.name);
        put(
            vec!["volume", "ls", "-q", "--filter", &name],
            format!("{}\n", volume.name),
        );
        put(
            vec!["volume", "ls", "-q", "--filter", &project],
            format!("{}\n", volume.name),
        );
        let attached = format!("volume={}", volume.name);
        put(
            vec!["ps", "-a", "-q", "--no-trunc", "--filter", &attached],
            String::new(),
        );
        put(
            vec!["volume", "inspect", &volume.name],
            json!([{
                "Name": volume.name, "CreatedAt": volume.created_at,
                "Driver": "local", "Scope": "local", "Options": null,
                "Labels": volume.labels, "Mountpoint": "/secret/host/path"
            }])
            .to_string(),
        );
        MockDocker {
            engine: plan.engine_id.clone(),
            outputs,
        }
    }

    #[test]
    fn creation_receipt_requires_exact_identity_and_rejects_legacy_absence() {
        let (id, plan, volume) = fixture();
        let bytes = serde_json::to_vec(&volume).unwrap();
        assert!(volume_evidence(&bytes, id, &plan.engine_id, &volume.name).is_some());
        assert!(volume_evidence(b"{}", id, &plan.engine_id, &volume.name).is_none());
        let duplicated = String::from_utf8(bytes.clone()).unwrap().replace(
            "\"com.docker.compose.volume\":\"redis-socket\"",
            "\"com.docker.compose.volume\":\"redis-socket\",\"com.docker.compose.volume\":\"redis-socket\"",
        );
        assert!(
            volume_evidence(duplicated.as_bytes(), id, &plan.engine_id, &volume.name).is_none()
        );
        let mut changed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        changed["created_at"] = json!("2026-10-28T12:30:00Z");
        assert!(volume_evidence(
            &serde_json::to_vec(&changed).unwrap(),
            id,
            &plan.engine_id,
            &volume.name
        )
        .is_some());
        changed["labels"]["com.docker.compose.project"] = json!("foreign");
        assert!(volume_evidence(
            &serde_json::to_vec(&changed).unwrap(),
            id,
            &plan.engine_id,
            &volume.name
        )
        .is_none());
        changed = serde_json::from_slice(&bytes).unwrap();
        changed["mountpoint"] = json!("/secret/host/path");
        assert!(volume_evidence(
            &serde_json::to_vec(&changed).unwrap(),
            id,
            &plan.engine_id,
            &volume.name
        )
        .is_none());
    }

    #[test]
    fn docker_census_refuses_drift_attachments_and_command_failure() {
        let (_, plan, volume) = fixture();
        let mut mock = docker(&plan, &volume);
        assert_eq!(docker_absent_except_volume(&mock, &plan, &volume), Ok(()));
        mock.engine = "another-engine".into();
        assert_eq!(
            docker_absent_except_volume(&mock, &plan, &volume),
            Err(IncompleteReason::DockerIdentityChanged)
        );
        mock.engine = plan.engine_id.clone();
        let attachment = vec![
            "ps",
            "-a",
            "-q",
            "--no-trunc",
            "--filter",
            &format!("volume={}", volume.name),
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        mock.outputs
            .insert(attachment, format!("{}\n", "c".repeat(64)));
        assert_eq!(
            docker_absent_except_volume(&mock, &plan, &volume),
            Err(IncompleteReason::DockerResourcesRemain)
        );
        let mut changed = docker(&plan, &volume);
        let inspect_key = vec![
            "volume".to_owned(),
            "inspect".to_owned(),
            volume.name.clone(),
        ];
        let mut inspect: serde_json::Value =
            serde_json::from_str(changed.outputs.get(&inspect_key).unwrap()).unwrap();
        inspect[0]["CreatedAt"] = json!("2026-10-28T12:30:00Z");
        changed.outputs.insert(inspect_key, inspect.to_string());
        assert_eq!(
            docker_absent_except_volume(&changed, &plan, &volume),
            Err(IncompleteReason::DockerIdentityChanged)
        );
        mock.outputs
            .remove(&vec!["ps".into(), "-aq".into(), "--no-trunc".into()]);
        assert_eq!(
            docker_absent_except_volume(&mock, &plan, &volume),
            Err(IncompleteReason::DockerObservationIncomplete)
        );
    }

    #[test]
    fn verified_first_attempt_returns_exact_typed_cleanup_facts() {
        let (id, plan, volume) = fixture();
        let plan_sha256 = "a".repeat(64);
        let pending = PendingNormalProfileFacts {
            installation_id: id,
            journal_revision: 17,
            plan_sha256: plan_sha256.clone(),
            plan,
            volume,
        };
        let mock = docker(&pending.plan, &pending.volume);
        let facts = pending.verify_docker_with(&mock).unwrap();
        assert_eq!(facts.installation_id, id);
        assert_eq!(facts.journal_revision, 17);
        assert_eq!(facts.engine_id, "synthetic-engine");
        assert_eq!(facts.cleanup_plan_sha256, plan_sha256);
        assert_eq!(facts.project, format!("marty-install-{}", id.simple()));
        assert_eq!(facts.network_id, "a".repeat(64));
        assert_eq!(facts.network_name, format!("{}-bao_default", facts.project));
        assert_eq!(facts.resources.len(), 1);
        assert_eq!(facts.resources[0].container_id, "b".repeat(64));
        assert_eq!(facts.volume.name, format!("{}_redis-socket", facts.project));
        assert_eq!(facts.volume.created_at, "2026-10-27T12:30:00Z");
    }

    #[test]
    fn completed_cleanup_helper_requires_recorded_result_and_volume_receipt() {
        let parent = tempfile::tempdir().unwrap();
        std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let installation = parent.path().join("installation");
        let mut state = InstallerState::create_with_runtime(
            &installation,
            Identity {
                source_sha: "a".repeat(40),
                release_tag: "v1.1.263".into(),
                inventory_sha256: format!("sha256:{}", "b".repeat(64)),
            },
            RuntimeBinding {
                docker_host: "unix:///var/run/docker.sock".into(),
                engine_id: "synthetic-engine".into(),
                openbao_port: 8200,
            },
        )
        .unwrap();
        state.advance(Phase::Verified).unwrap();
        state.advance(Phase::Provisioning).unwrap();
        state.create_private_directory("evidence").unwrap();
        let id = state.journal().installation_id();
        let project = state.journal().compose_project();
        let (_, mut plan, mut volume) = fixture();
        plan.installation_id = id.to_string();
        plan.project = project.clone();
        plan.network_name = format!("{project}-bao_default");
        plan.retained_redis_volume = Some(format!("{project}_redis-socket"));
        plan.resources = (0..30)
            .map(|i| CleanupResource {
                role: format!("app-{i}"),
                container_id: format!("{:064x}", i + 1),
                bao: false,
            })
            .chain(
                [
                    "openbao",
                    "openbao-unseal",
                    "openbao-bootstrap",
                    "openbao-tls-init",
                ]
                .into_iter()
                .enumerate()
                .map(|(i, role)| CleanupResource {
                    role: role.into(),
                    container_id: format!("{:064x}", i + 40),
                    bao: true,
                }),
            )
            .collect();
        plan.source_hashes = [
            "evidence/application-plan.json",
            "evidence/application-compose.json",
            "evidence/application-created-resources.json",
            "root/openbao-created.json",
            "root/openbao-compose-model.json",
            "evidence/keycloak-container-removed.json",
            "evidence/tls-container-removed.json",
            "evidence/ingress-container-removed.json",
        ]
        .into_iter()
        .map(|name| (name.into(), "a".repeat(64)))
        .collect();
        volume.installation_id = id.to_string();
        volume.name = format!("{project}_redis-socket");
        volume
            .labels
            .insert("com.docker.compose.project".into(), project);
        let inspect = |state: &InstallerState| {
            state
                .with_inspection(|locked| {
                    Ok(completed_normal_profile_cleanup(locked, &installation))
                })
                .unwrap()
        };
        assert!(matches!(
            inspect(&state),
            Err(NormalProfileError::Incomplete(
                IncompleteReason::CleanupNotComplete
            ))
        ));
        state
            .write_evidence("uninstall-plan.json", &serde_json::to_vec(&plan).unwrap())
            .unwrap();
        let result = json!({
            "schema":"elevenid.installer-uninstall-result/v1",
            "installation_id":id,
            "engine_id":"synthetic-engine",
            "containers_removed":34,
            "network_removed":true,
            "host_data_retained":true,
            "credentials_retained":true,
            "images_retained":true,
            "redis_volume_retained":volume.name,
            "installation_ready":false
        });
        state
            .write_evidence(
                "uninstall-result.json",
                &serde_json::to_vec(&result).unwrap(),
            )
            .unwrap();
        assert!(matches!(
            inspect(&state),
            Err(NormalProfileError::Incomplete(
                IncompleteReason::MissingCreationEvidence
            ))
        ));
        state
            .write_evidence(
                "application-created-volume.json",
                &serde_json::to_vec(&volume).unwrap(),
            )
            .unwrap();
        let pending = inspect(&state).ok().expect("valid completed cleanup");
        assert_eq!(pending.installation_id, id);
        assert_eq!(pending.plan.resources.len(), 34);
        assert_eq!(pending.plan_sha256.len(), 64);
    }

    #[test]
    fn private_plan_digest_changes_with_exact_host_and_volume_identity() {
        use crate::installer_purge_host::Kind;
        let (id, plan, volume) = fixture();
        let root = HostIdentity {
            dev: 1,
            ino: 2,
            uid: 1000,
            gid: 1000,
            mode: 0o700,
            kind: Kind::Directory,
        };
        let entries = [HostPurgeEntry {
            relative_path: "backups/private-customer-name".into(),
            parent: root.clone(),
            target: HostIdentity {
                ino: 3,
                ..root.clone()
            },
        }];
        let make = |volume: &VolumeCreation| {
            serde_json::to_vec(&PrivatePlan {
                schema: SCHEMA,
                coverage: "known_host_storage_roots_only",
                installation_id: id,
                journal_revision: 4,
                engine_id: &plan.engine_id,
                cleanup_plan_sha256: "a".repeat(64),
                host_receipt_sha256: &"b".repeat(64),
                host_root: &root,
                host_mount_id: 8,
                host_entries: &entries,
                containers: vec![&plan.resources[0]],
                network_id: &plan.network_id,
                network_name: &plan.network_name,
                volume,
                point_in_time: true,
                deletion_eligible: false,
                installation_root_included: false,
                deletion_authorized: false,
            })
            .unwrap()
        };
        let first = make(&volume);
        assert_eq!(first, make(&volume));
        assert!(String::from_utf8_lossy(&first).contains("private-customer-name"));
        let mut changed = volume;
        changed.created_at = "2026-10-28T12:30:00Z".into();
        assert_ne!(Sha256::digest(first), Sha256::digest(make(&changed)));
    }
}
