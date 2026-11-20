//! Fresh, read-only normal-profile plan for explicit confirmation. This is a
//! point-in-time local-custody observation, never deletion authorization.
#![cfg(target_os = "linux")]
#![allow(dead_code)] // No destructive coordinator calls this dormant module.

use crate::{
    installer_compose::ProjectResources,
    installer_compose_volume_creation::VolumeIdentity,
    installer_creation_identity::ObservedDirectory,
    installer_creation_receipt_validation::{
        self, NormalInspectionOutcome, ObservedNormalCreation,
    },
    installer_host_tree_observer::{self, TreeOutcome},
    installer_purge_host::{HostIdentity, HostPurgeEntry},
    installer_purge_plan::{
        self, DockerRead, NativeCleanupBinding, NormalProfileError, ValidatedNormalProfileFacts,
    },
    installer_runtime::DockerRunner,
    installer_state::LockedInspection,
    installer_top_level_census::{self, CensusProfile, ExpectedTopLevel, TopLevelName},
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::Path};

const SCHEMA: &str = "elevenid.installer-private-normal-purge-candidate/v2";
const MAX_LEDGER_MANIFEST: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum IncompleteReason {
    InstallationChanged,
    CleanupNotComplete,
    CreationEvidenceIncomplete,
    FixedTopLevelIncomplete,
    FullTreeIncomplete,
    DockerObservationIncomplete,
    DockerResourcesRemain,
    PlanBoundExceeded,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum UnsupportedReason {
    UnsupportedLifecycle,
}

pub(crate) enum PrepareNormalOutcome {
    CompleteForConfirmation(CompleteForConfirmation),
    Incomplete(IncompleteReason),
    Unsupported(UnsupportedReason),
}

/// Private exact bytes may contain customer filenames and Docker labels. Keep
/// them only in the protected ledger. Neither this value nor its digest permits
/// a purge without a stopped-writer coordinator, confirmation and durable intent.
pub(crate) struct CompleteForConfirmation {
    bytes: Vec<u8>,
    sha256: String,
}
impl CompleteForConfirmation {
    pub(crate) fn private_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub(crate) fn sha256(&self) -> &str {
        &self.sha256
    }
}

#[derive(Serialize)]
struct CreationReceipts<'a> {
    initial_sha256: &'a str,
    credential_sha256: &'a str,
    application_sha256: &'a str,
    openbao_state_sha256: &'a str,
    openbao_owner_transition_sha256: &'a str,
    openbao_native_custody_sha256: &'a str,
    openbao_tls_completion_sha256: &'a str,
    native_storage_receipts_sha256: &'a BTreeMap<String, String>,
}

#[derive(Serialize)]
struct ExecutionQuarantinePolicy {
    relative_name: &'static str,
    creation: &'static str,
    prerequisite: &'static str,
    retirement: &'static str,
    absent_after_retry: &'static str,
}

#[derive(Serialize)]
struct PrivateNormalPlan<'a> {
    schema: &'static str,
    coverage: &'static str,
    installation_id: uuid::Uuid,
    source_sha: &'a str,
    release_tag: &'a str,
    source_inventory_sha256: &'a str,
    journal_revision: u64,
    native_cleanup: &'a NativeCleanupBinding,
    top_level_profile: &'static str,
    local_operator_password: bool,
    absolute_installation_path: &'a str,
    root: &'a HostIdentity,
    root_mount_id: u64,
    creation_receipts: CreationReceipts<'a>,
    entries_deepest_first: &'a [HostPurgeEntry],
    engine_id: &'a str,
    project: &'a str,
    native_prior_resources: &'a ProjectResources,
    retained_volumes: &'a BTreeMap<String, VolumeIdentity>,
    execution_quarantine: ExecutionQuarantinePolicy,
    not_atomic_snapshot: bool,
    deletion_eligible: bool,
    deletion_authorized: bool,
}

fn receipt_bound(
    specs: &[ExpectedTopLevel],
    name: TopLevelName,
    observed: &ObservedDirectory,
) -> bool {
    specs
        .iter()
        .any(|spec| spec.name == name && spec.identity == observed.identity)
}

fn receipts_match_fixed_specs(
    specs: &[ExpectedTopLevel],
    observed: &ObservedNormalCreation,
) -> bool {
    let credentials = &observed.application.credentials;
    let initial = &credentials.initial;
    let mount = initial.root.mount_id;
    if mount == 0
        || initial.evidence.mount_id != mount
        || initial.downloads.mount_id != mount
        || credentials.secrets.mount_id != mount
        || observed.openbao_state.mount_id != mount
        || !receipt_bound(specs, TopLevelName::Evidence, &initial.evidence)
        || !receipt_bound(specs, TopLevelName::Downloads, &initial.downloads)
        || !receipt_bound(specs, TopLevelName::Secrets, &credentials.secrets)
        || !receipt_bound(specs, TopLevelName::OpenBaoState, &observed.openbao_state)
    {
        return false;
    }
    match &credentials.operator_password {
        Some(operator)
            if operator.mount_id == mount
                && specs.iter().any(|spec| {
                    spec.name == TopLevelName::OperatorPassword
                        && spec.identity == operator.identity
                }) => {}
        None if !specs
            .iter()
            .any(|spec| spec.name == TopLevelName::OperatorPassword) => {}
        _ => return false,
    }
    for (name, top) in [
        ("openbao-control", TopLevelName::OpenBaoControl),
        ("openbao-seal", TopLevelName::OpenBaoSeal),
    ] {
        let Some(observed) = observed.native_storage_roots.get(name) else {
            return false;
        };
        if observed.mount_id != mount || !receipt_bound(specs, top, observed) {
            return false;
        }
    }
    for (name, top) in [
        ("state", TopLevelName::State),
        ("backups", TopLevelName::Backups),
        ("openbao-exports", TopLevelName::OpenBaoExports),
        (
            "openbao-snapshot-identity",
            TopLevelName::OpenBaoSnapshotIdentity,
        ),
    ] {
        let Some(directory) = observed.application.roots.get(name) else {
            return false;
        };
        if directory.mount_id != mount || !receipt_bound(specs, top, directory) {
            return false;
        }
    }
    true
}

fn map_cleanup_error(error: NormalProfileError) -> PrepareNormalOutcome {
    match error {
        NormalProfileError::Unsupported(_) => {
            PrepareNormalOutcome::Unsupported(UnsupportedReason::UnsupportedLifecycle)
        }
        NormalProfileError::Incomplete(
            installer_purge_plan::IncompleteReason::InstallationChanged,
        ) => PrepareNormalOutcome::Incomplete(IncompleteReason::InstallationChanged),
        NormalProfileError::Incomplete(
            installer_purge_plan::IncompleteReason::CleanupNotComplete,
        ) => PrepareNormalOutcome::Incomplete(IncompleteReason::CleanupNotComplete),
        NormalProfileError::Incomplete(_) => {
            PrepareNormalOutcome::Incomplete(IncompleteReason::CreationEvidenceIncomplete)
        }
    }
}

fn map_docker_error(error: installer_purge_plan::IncompleteReason) -> PrepareNormalOutcome {
    use installer_purge_plan::IncompleteReason as Prior;
    PrepareNormalOutcome::Incomplete(match error {
        Prior::DockerResourcesRemain => IncompleteReason::DockerResourcesRemain,
        _ => IncompleteReason::DockerObservationIncomplete,
    })
}

/// A fresh first attempt only. Resume must read the exact saved ledger plan,
/// since an already removed volume is no longer expected to be present.
pub(crate) fn prepare_normal(
    locked: &LockedInspection,
    installation: &Path,
    docker: &DockerRunner,
) -> PrepareNormalOutcome {
    prepare_normal_with(locked, installation, docker)
}

pub(crate) fn prepare_normal_with<D: DockerRead>(
    locked: &LockedInspection,
    installation: &Path,
    docker: &D,
) -> PrepareNormalOutcome {
    use IncompleteReason::*;
    if locked.require_path_binding(installation).is_err() || locked.require_unchanged().is_err() {
        return PrepareNormalOutcome::Incomplete(InstallationChanged);
    }
    let journal = locked.journal();
    let profile = match installer_top_level_census::current_native_profile(locked, installation) {
        Ok(profile @ CensusProfile::NativeComposeV2 { .. }) => profile,
        _ => return PrepareNormalOutcome::Unsupported(UnsupportedReason::UnsupportedLifecycle),
    };
    let CensusProfile::NativeComposeV2 {
        local_operator_password,
    } = profile
    else {
        unreachable!()
    };
    let pending = match installer_purge_plan::completed_normal_profile_cleanup(locked, installation)
    {
        Ok(facts) => facts,
        Err(error) => return map_cleanup_error(error),
    };
    let first =
        match installer_creation_receipt_validation::inspect_native_normal(locked, installation) {
            NormalInspectionOutcome::MatchedLocalReceipt(value) => value,
            NormalInspectionOutcome::Missing | NormalInspectionOutcome::Unusable => {
                return PrepareNormalOutcome::Incomplete(CreationEvidenceIncomplete);
            }
        };
    let root = &first.application.credentials.initial.root;
    let specs = match installer_top_level_census::derive_native_specs(
        locked,
        installation,
        &root.identity,
        root.mount_id,
        profile,
    ) {
        Ok(value) => value,
        Err(_) => return PrepareNormalOutcome::Incomplete(FixedTopLevelIncomplete),
    };
    if !receipts_match_fixed_specs(&specs, &first) {
        return PrepareNormalOutcome::Incomplete(CreationEvidenceIncomplete);
    }
    let tree = match installer_host_tree_observer::observe(
        locked,
        installation,
        &root.identity,
        root.mount_id,
        &specs,
    ) {
        TreeOutcome::Observed(value) => value,
        TreeOutcome::Incomplete(_) => return PrepareNormalOutcome::Incomplete(FullTreeIncomplete),
    };
    if tree.coverage != "expected_normal_profile_current_tree"
        || tree.installation_id != journal.installation_id()
        || tree.root != root.identity
        || tree.mount_id != root.mount_id
        || !tree.not_atomic_snapshot
        || tree.deletion_eligible
        || tree.entries.len() < profile.names().len()
    {
        return PrepareNormalOutcome::Incomplete(FullTreeIncomplete);
    }
    let facts: ValidatedNormalProfileFacts = match pending.verify_docker_with(docker) {
        Ok(value) => value,
        Err(error) => return map_docker_error(error),
    };
    let second =
        match installer_creation_receipt_validation::inspect_native_normal(locked, installation) {
            NormalInspectionOutcome::MatchedLocalReceipt(value) => value,
            NormalInspectionOutcome::Missing | NormalInspectionOutcome::Unusable => {
                return PrepareNormalOutcome::Incomplete(CreationEvidenceIncomplete);
            }
        };
    if first != second || !receipts_match_fixed_specs(&specs, &second) {
        return PrepareNormalOutcome::Incomplete(InstallationChanged);
    }
    if facts
        .require_current_evidence(locked, installation)
        .is_err()
    {
        return PrepareNormalOutcome::Incomplete(InstallationChanged);
    }
    // Docker observation can take time. Do not silently adopt or omit children
    // that appeared, disappeared, or changed after the first exact census.
    let final_tree = match installer_host_tree_observer::observe(
        locked,
        installation,
        &root.identity,
        root.mount_id,
        &specs,
    ) {
        TreeOutcome::Observed(value) => value,
        TreeOutcome::Incomplete(_) => return PrepareNormalOutcome::Incomplete(FullTreeIncomplete),
    };
    if final_tree.coverage != tree.coverage
        || final_tree.installation_id != tree.installation_id
        || final_tree.root != tree.root
        || final_tree.mount_id != tree.mount_id
        || final_tree.entries != tree.entries
        || final_tree.not_atomic_snapshot != tree.not_atomic_snapshot
        || final_tree.deletion_eligible != tree.deletion_eligible
    {
        return PrepareNormalOutcome::Incomplete(FullTreeIncomplete);
    }
    if locked.require_path_binding(installation).is_err() || locked.require_unchanged().is_err() {
        return PrepareNormalOutcome::Incomplete(InstallationChanged);
    }
    let canonical = match std::fs::canonicalize(installation) {
        Ok(value) if value.is_absolute() => value,
        _ => return PrepareNormalOutcome::Incomplete(InstallationChanged),
    };
    let Some(absolute_path) = canonical.to_str() else {
        return PrepareNormalOutcome::Incomplete(InstallationChanged);
    };
    if absolute_path.len() > 1024 || locked.require_path_binding(installation).is_err() {
        return PrepareNormalOutcome::Incomplete(InstallationChanged);
    }
    let receipts = CreationReceipts {
        initial_sha256: &first.application.credentials.initial.receipt_sha256,
        credential_sha256: &first.application.credentials.receipt_sha256,
        application_sha256: &first.application.receipt_sha256,
        openbao_state_sha256: &first.state_receipt_sha256,
        openbao_owner_transition_sha256: &first.transition_receipt_sha256,
        openbao_native_custody_sha256: &first.created_record_sha256,
        openbao_tls_completion_sha256: &first.completion_sha256,
        native_storage_receipts_sha256: &first.native_receipts_sha256,
    };
    let private = PrivateNormalPlan {
        schema: SCHEMA,
        coverage: tree.coverage,
        installation_id: facts.installation_id,
        source_sha: &journal.identity().source_sha,
        release_tag: &journal.identity().release_tag,
        source_inventory_sha256: &journal.identity().inventory_sha256,
        journal_revision: facts.journal_revision,
        native_cleanup: &facts.native_cleanup,
        top_level_profile: "native_compose_initial_managed_openbao_non_acme/v2",
        local_operator_password,
        absolute_installation_path: absolute_path,
        root: &tree.root,
        root_mount_id: tree.mount_id,
        creation_receipts: receipts,
        entries_deepest_first: &tree.entries,
        engine_id: &facts.engine_id,
        project: &facts.project,
        native_prior_resources: &facts.resources,
        retained_volumes: &facts.volumes,
        execution_quarantine: ExecutionQuarantinePolicy {
            relative_name: ".marty-purge-quarantine",
            creation: "exclusive_create_after_confirmation",
            prerequisite: "host_durable_intent_and_unchanged_custody_required",
            retirement: "retire_empty_before_root_last",
            absent_after_retry:
                "origin_and_quarantine_absent_only_with_prior_exact_intent_and_unchanged_custody",
        },
        not_atomic_snapshot: true,
        deletion_eligible: false,
        deletion_authorized: false,
    };
    let Ok(bytes) = serde_json::to_vec(&private) else {
        return PrepareNormalOutcome::Incomplete(PlanBoundExceeded);
    };
    if bytes.is_empty() || bytes.len() > MAX_LEDGER_MANIFEST {
        return PrepareNormalOutcome::Incomplete(PlanBoundExceeded);
    }
    if locked.require_path_binding(installation).is_err()
        || locked.require_unchanged().is_err()
        || facts
            .require_current_evidence(locked, installation)
            .is_err()
        || installer_top_level_census::current_native_profile(locked, installation).ok()
            != Some(profile)
        || !matches!(installer_creation_receipt_validation::inspect_native_normal(locked, installation),
            NormalInspectionOutcome::MatchedLocalReceipt(latest) if latest == first)
    {
        return PrepareNormalOutcome::Incomplete(InstallationChanged);
    }
    let sha256 = format!("{:x}", Sha256::digest(&bytes));
    PrepareNormalOutcome::CompleteForConfirmation(CompleteForConfirmation { bytes, sha256 })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        installer_creation_receipt_validation::tests::normal_fixture,
        installer_state::InstallerState,
    };
    use serde_json::{json, Value};
    use std::{
        collections::BTreeMap,
        fs,
        os::unix::fs::{symlink, PermissionsExt},
        path::PathBuf,
    };

    pub(crate) struct MockDocker {
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

    pub(crate) fn fixture() -> (tempfile::TempDir, PathBuf, InstallerState, MockDocker) {
        let (parent, path, mut state) = normal_fixture();
        for name in TopLevelName::REQUIRED {
            let target = path.join(name.name());
            if target.exists() {
                continue;
            }
            match name.expected_kind() {
                crate::installer_purge_host::Kind::Directory => {
                    fs::create_dir(&target).unwrap();
                    fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
                }
                crate::installer_purge_host::Kind::File => {
                    fs::write(&target, b"synthetic normal-profile file").unwrap();
                    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
                }
            }
        }
        fs::write(
            path.join("backups/private-customer-filename"),
            b"synthetic-only",
        )
        .unwrap();
        let id = state.journal().installation_id();
        let project = state.journal().compose_project();
        let volume_name = format!("{project}_redis-socket");
        let resources: Vec<_> = (0..30)
            .map(|i| json!({"role":format!("app-{i}"),"container_id":format!("{:064x}",i+1),"bao":false}))
            .chain(["openbao", "openbao-unseal", "openbao-bootstrap", "openbao-tls-init"]
                .into_iter().enumerate().map(|(i, role)| json!({"role":role,"container_id":format!("{:064x}",i+40),"bao":true})))
            .collect();
        let source_hashes: BTreeMap<_, _> = [
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
        .map(|s| (s, "a".repeat(64)))
        .collect();
        let plan = json!({
            "schema":"elevenid.installer-uninstall-plan/v1", "installation_id":id,
            "engine_id":"synthetic-engine", "project":project, "network_id":"e".repeat(64),
            "network_name":format!("{project}-bao_default"), "retained_redis_volume":volume_name,
            "resources":resources, "source_hashes":source_hashes
        });
        let result = json!({
            "schema":"elevenid.installer-uninstall-result/v1", "installation_id":id,
            "engine_id":"synthetic-engine", "containers_removed":34, "network_removed":true,
            "host_data_retained":true, "credentials_retained":true, "images_retained":true,
            "redis_volume_retained":volume_name, "installation_ready":false
        });
        let labels = BTreeMap::from([
            ("com.docker.compose.project".to_owned(), project.clone()),
            (
                "com.docker.compose.volume".to_owned(),
                "redis-socket".to_owned(),
            ),
        ]);
        let volume = json!({
            "schema":"elevenid.installer-created-volume/v1", "installation_id":id,
            "engine_id":"synthetic-engine", "name":volume_name,
            "created_at":"2026-10-27T12:30:00Z", "labels":labels,
            "driver":"local", "scope":"local"
        });
        for (name, record) in [
            ("uninstall-plan.json", plan),
            ("uninstall-result.json", result),
            ("application-created-volume.json", volume.clone()),
        ] {
            state
                .write_evidence(name, &serde_json::to_vec(&record).unwrap())
                .unwrap();
        }
        let project_filter = format!("label=com.docker.compose.project={project}");
        let install_filter = format!("label=com.elevenid.installer.id={id}");
        let volume_filter = format!("volume={volume_name}");
        let name_filter = format!("name={volume_name}");
        let mut outputs = BTreeMap::new();
        let mut put = |args: Vec<&str>, output: String| {
            outputs.insert(args.into_iter().map(str::to_owned).collect(), output);
        };
        for args in [
            vec!["ps", "-aq", "--no-trunc"],
            vec!["ps", "-aq", "--no-trunc", "--filter", &project_filter],
            vec!["ps", "-aq", "--no-trunc", "--filter", &install_filter],
            vec!["network", "ls", "-q", "--no-trunc"],
            vec![
                "network",
                "ls",
                "-q",
                "--no-trunc",
                "--filter",
                &project_filter,
            ],
            vec!["ps", "-a", "-q", "--no-trunc", "--filter", &volume_filter],
        ] {
            put(args, String::new());
        }
        put(
            vec!["volume", "ls", "-q", "--filter", &name_filter],
            format!("{volume_name}\n"),
        );
        put(
            vec!["volume", "ls", "-q", "--filter", &project_filter],
            format!("{volume_name}\n"),
        );
        put(
            vec!["volume", "inspect", &volume_name],
            json!([{
                "Name":volume_name, "CreatedAt":"2026-10-27T12:30:00Z",
                "Driver":"local", "Scope":"local", "Options":null,
                "Labels":labels, "Mountpoint":"/synthetic/private/path"
            }])
            .to_string(),
        );
        (
            parent,
            path,
            state,
            MockDocker {
                engine: "synthetic-engine".into(),
                outputs,
            },
        )
    }

    fn prepare(state: &InstallerState, path: &Path, docker: &MockDocker) -> PrepareNormalOutcome {
        state
            .with_inspection(|locked| Ok(prepare_normal_with(locked, path, docker)))
            .unwrap()
    }

    #[test]
    fn complete_synthetic_tree_binds_private_bytes_and_digest() {
        let (_parent, path, state, docker) = fixture();
        let PrepareNormalOutcome::CompleteForConfirmation(candidate) =
            prepare(&state, &path, &docker)
        else {
            panic!("expected complete read-only candidate")
        };
        assert_eq!(
            candidate.sha256(),
            format!("{:x}", Sha256::digest(candidate.private_bytes()))
        );
        let private: Value = serde_json::from_slice(candidate.private_bytes()).unwrap();
        assert_eq!(private["coverage"], "expected_normal_profile_current_tree");
        assert_eq!(private["release_tag"], "v1.1.263");
        assert_eq!(private["cleanup_result_sha256"].as_str().unwrap().len(), 64);
        assert_eq!(private["deletion_eligible"], false);
        assert_eq!(private["deletion_authorized"], false);
        assert_eq!(
            private["execution_quarantine"]["relative_name"],
            ".marty-purge-quarantine"
        );
        assert_eq!(
            private["execution_quarantine"]["creation"],
            "exclusive_create_after_confirmation"
        );
        let entries = private["entries_deepest_first"].as_array().unwrap();
        assert!(entries.len() > 31);
        assert!(entries
            .iter()
            .any(|entry| entry["relative_path"] == "backups/private-customer-filename"));
        assert!(entries.windows(2).all(|pair| {
            pair[0]["relative_path"]
                .as_str()
                .unwrap()
                .split('/')
                .count()
                >= pair[1]["relative_path"]
                    .as_str()
                    .unwrap()
                    .split('/')
                    .count()
        }));
        assert_eq!(private["creation_receipts"].as_object().unwrap().len(), 7);
        assert_eq!(private["removed_containers"].as_array().unwrap().len(), 34);
        assert_eq!(private["retained_redis_volume"]["Name"], Value::Null);
        assert_eq!(
            private["retained_redis_volume"]["name"],
            format!(
                "{}{}_redis-socket",
                "marty-install-",
                state.journal().installation_id().simple()
            )
        );
        assert!(candidate.private_bytes().len() < MAX_LEDGER_MANIFEST);
    }

    #[test]
    fn unknown_top_level_and_changed_receipt_fail_closed() {
        let (_parent, path, state, docker) = fixture();
        fs::write(path.join("unknown-secret-canary"), b"never adopt").unwrap();
        assert!(matches!(
            prepare(&state, &path, &docker),
            PrepareNormalOutcome::Incomplete(IncompleteReason::FixedTopLevelIncomplete)
        ));
        fs::remove_file(path.join("unknown-secret-canary")).unwrap();
        fs::write(
            path.join("evidence/installation-created-identity.json"),
            b"{}",
        )
        .unwrap();
        assert!(matches!(
            prepare(&state, &path, &docker),
            PrepareNormalOutcome::Incomplete(IncompleteReason::CreationEvidenceIncomplete)
        ));
    }

    #[test]
    fn preexisting_reserved_quarantine_is_unknown_top_level() {
        let (_parent, path, state, docker) = fixture();
        fs::create_dir(path.join(".marty-purge-quarantine")).unwrap();
        assert!(matches!(
            prepare(&state, &path, &docker),
            PrepareNormalOutcome::Incomplete(IncompleteReason::FixedTopLevelIncomplete)
        ));
    }

    #[test]
    fn engine_mismatch_and_unsafe_child_fail_closed() {
        let (_parent, path, state, mut docker) = fixture();
        docker.engine = "foreign-engine".into();
        assert!(matches!(
            prepare(&state, &path, &docker),
            PrepareNormalOutcome::Incomplete(IncompleteReason::DockerObservationIncomplete)
        ));
        docker.engine = "synthetic-engine".into();
        symlink(
            path.join("backups"),
            path.join("renewal-inputs/foreign-link"),
        )
        .unwrap();
        assert!(matches!(
            prepare(&state, &path, &docker),
            PrepareNormalOutcome::Incomplete(IncompleteReason::FullTreeIncomplete)
        ));
    }

    #[test]
    fn receipt_bound_file_replacement_during_docker_observation_is_refused() {
        struct ReplacingDocker {
            inner: MockDocker,
            path: PathBuf,
        }
        impl DockerRead for ReplacingDocker {
            fn engine_id(&self) -> Result<String, ()> {
                let bytes = fs::read(&self.path).unwrap();
                fs::rename(
                    &self.path,
                    self.path
                        .parent()
                        .unwrap()
                        .parent()
                        .unwrap()
                        .join("old-synthetic-password"),
                )
                .unwrap();
                fs::write(&self.path, bytes).unwrap();
                fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600)).unwrap();
                self.inner.engine_id()
            }
            fn run(&self, args: &[&str]) -> Result<String, ()> {
                self.inner.run(args)
            }
        }
        let (_parent, path, state, docker) = fixture();
        let replacing = ReplacingDocker {
            inner: docker,
            path: path.join("operator-password"),
        };
        let outcome = state
            .with_inspection(|locked| Ok(prepare_normal_with(locked, &path, &replacing)))
            .unwrap();
        assert!(matches!(
            outcome,
            PrepareNormalOutcome::Incomplete(IncompleteReason::CreationEvidenceIncomplete)
        ));
    }

    #[test]
    fn auxiliary_tree_drift_during_docker_observation_is_refused() {
        #[derive(Clone, Copy)]
        enum Change {
            Add,
            Remove,
            Replace,
            UnknownTopLevel,
        }
        struct MutatingDocker {
            inner: MockDocker,
            installation: PathBuf,
            change: Change,
        }
        impl DockerRead for MutatingDocker {
            fn engine_id(&self) -> Result<String, ()> {
                let child = self.installation.join("backups/private-customer-filename");
                match self.change {
                    Change::Add => {
                        fs::write(
                            self.installation.join("renewal-inputs/late-synthetic"),
                            b"late",
                        )
                        .unwrap();
                    }
                    Change::Remove => fs::remove_file(child).unwrap(),
                    Change::Replace => {
                        let bytes = fs::read(&child).unwrap();
                        fs::rename(
                            &child,
                            self.installation
                                .parent()
                                .unwrap()
                                .join("old-synthetic-backup"),
                        )
                        .unwrap();
                        fs::write(&child, bytes).unwrap();
                    }
                    Change::UnknownTopLevel => {
                        fs::write(self.installation.join("late-unknown-synthetic"), b"late")
                            .unwrap();
                    }
                }
                self.inner.engine_id()
            }
            fn run(&self, args: &[&str]) -> Result<String, ()> {
                self.inner.run(args)
            }
        }
        for change in [
            Change::Add,
            Change::Remove,
            Change::Replace,
            Change::UnknownTopLevel,
        ] {
            let (_parent, path, state, inner) = fixture();
            let docker = MutatingDocker {
                inner,
                installation: path.clone(),
                change,
            };
            let outcome = state
                .with_inspection(|locked| Ok(prepare_normal_with(locked, &path, &docker)))
                .unwrap();
            assert!(matches!(
                outcome,
                PrepareNormalOutcome::Incomplete(IncompleteReason::FullTreeIncomplete)
            ));
        }
    }
}
