//! Exact confirmation and durable preparation of a private normal purge plan.
//! This dormant boundary has no deletion, CLI, or resource-intent caller.
#![cfg(target_os = "linux")]
#![allow(dead_code)] // Execution and operator collection require separate review.

use crate::{
    installer_complete_purge_plan::{self, PrepareNormalOutcome},
    installer_purge_host::{HostIdentity, Kind},
    installer_purge_ledger::{self, ConfirmationBinding, DirectoryStamp, PurgeLedger},
    installer_purge_plan::{CleanupResource, DockerRead, VolumeCreation},
    installer_runtime::DockerRunner,
    installer_state::LockedInspection,
    installer_top_level_census::TopLevelName,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{CString, OsStr},
    fs::File,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::ffi::OsStrExt,
    },
    path::{Component, Path},
};
use uuid::{Variant, Version};

const SCHEMA: &str = "elevenid.installer-private-normal-purge-candidate/v1";
const MAX_PLAN: usize = 4 * 1024 * 1024;
const MAX_ENTRIES: usize = 4096;
const MAX_PATH: usize = 1024;
const MAX_DEPTH: usize = 16;

/// Fixed public reason codes contain no paths, customer filenames or Docker IDs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Refusal {
    Incomplete,
    Unsupported,
    InvalidPlan,
    ConfirmationMismatch,
    InstallationChanged,
    EngineChanged,
    LedgerUnavailable,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::installer_complete_purge_plan::tests::fixture as normal_fixture;
    use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

    struct MockDocker(&'static str);
    impl DockerRead for MockDocker {
        fn engine_id(&self) -> std::result::Result<String, ()> {
            Ok(self.0.into())
        }
        fn run(&self, _args: &[&str]) -> std::result::Result<String, ()> {
            Err(())
        }
    }
    fn private_directory(path: &Path) {
        fs::create_dir(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    #[test]
    fn fresh_complete_synthetic_plan_requires_exact_challenge_before_ledger_prepare() {
        let (temp, installation, state, docker) = normal_fixture();
        let external = temp.path().join("external-purge-ledger");
        private_directory(&external);
        let candidate = state
            .with_inspection(|locked| {
                Ok(installer_complete_purge_plan::prepare_normal_with(
                    locked,
                    &installation,
                    &docker,
                ))
            })
            .unwrap();
        let PrepareNormalOutcome::CompleteForConfirmation(candidate) = candidate else {
            panic!("normal synthetic fixture must produce a private candidate");
        };
        let plan = parse_plan(candidate.private_bytes(), candidate.sha256()).unwrap();
        let ledger_path = external.join(format!("marty-purge-{}", plan.installation_id.simple()));
        let wrong = ExplicitConfirmation {
            entered: "PURGE another-installation another-plan",
        };
        let refused = state
            .with_inspection(|locked| {
                Ok(prepare_confirmed_with(
                    locked,
                    &installation,
                    &docker,
                    &external,
                    &wrong,
                ))
            })
            .unwrap();
        assert!(matches!(refused, Err(Refusal::ConfirmationMismatch)));
        assert!(!ledger_path.exists());
        let phrase = challenge(&plan, candidate.sha256());
        let exact = ExplicitConfirmation { entered: &phrase };
        let prepared = state
            .with_inspection(|locked| {
                Ok(prepare_confirmed_with(
                    locked,
                    &installation,
                    &docker,
                    &external,
                    &exact,
                ))
            })
            .unwrap()
            .unwrap();
        assert_eq!(prepared.original_private_bytes(), candidate.private_bytes());
        assert_eq!(prepared.plan_sha256(), candidate.sha256());
        assert_eq!(
            fs::read(ledger_path.join("manifest.json")).unwrap(),
            candidate.private_bytes()
        );
        assert!(ledger_path.join("confirmation.json").exists());
        assert!(!installation.join(".marty-purge-quarantine").exists());
        assert_eq!(
            fs::read_dir(ledger_path.join("quarantine"))
                .unwrap()
                .count(),
            0
        );
    }
    fn plan(root_path: &Path) -> Plan {
        let held = File::open(root_path).unwrap();
        let stamp = installer_purge_ledger::directory_stamp(&held).unwrap();
        let root = HostIdentity {
            dev: stamp.dev,
            ino: stamp.ino,
            uid: stamp.uid,
            gid: stamp.gid,
            mode: stamp.mode,
            kind: Kind::Directory,
        };
        let mut entries: Vec<_> = TopLevelName::REQUIRED
            .iter()
            .enumerate()
            .map(|(index, name)| Entry {
                relative_path: name.name(),
                parent: root.clone(),
                target: HostIdentity {
                    dev: root.dev,
                    ino: root.ino + index as u64 + 1,
                    uid: root.uid,
                    gid: root.gid,
                    mode: if name.expected_kind() == Kind::Directory {
                        0o700
                    } else {
                        0o600
                    },
                    kind: name.expected_kind(),
                },
            })
            .collect();
        entries.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
        let receipt = digest(b"synthetic-local-receipt");
        Plan {
            schema: SCHEMA.into(),
            coverage: "expected_normal_profile_current_tree".into(),
            installation_id: uuid::Uuid::new_v4(),
            source_sha: "a".repeat(40),
            release_tag: "synthetic".into(),
            source_inventory_sha256: format!("sha256:{}", "b".repeat(64)),
            journal_revision: 3,
            cleanup_plan_sha256: digest(b"synthetic-cleanup-plan"),
            cleanup_result_sha256: digest(b"synthetic-cleanup-result"),
            absolute_installation_path: root_path.to_str().unwrap().into(),
            root,
            root_mount_id: stamp.mount_id,
            creation_receipts: Receipts {
                initial_sha256: receipt.clone(),
                credential_sha256: receipt.clone(),
                application_sha256: receipt.clone(),
                openbao_state_sha256: receipt.clone(),
                openbao_owner_transition_sha256: receipt.clone(),
                openbao_created_sha256: receipt.clone(),
                openbao_tls_completion_sha256: receipt,
            },
            entries_deepest_first: entries,
            engine_id: "synthetic-engine".into(),
            project: "synthetic-project".into(),
            removed_containers: Vec::new(),
            removed_network_id: "synthetic-network".into(),
            removed_network_name: "synthetic-name".into(),
            retained_redis_volume: VolumeCreation {
                schema: "synthetic-volume".into(),
                installation_id: String::new(),
                engine_id: "synthetic-engine".into(),
                name: "synthetic-volume".into(),
                created_at: "2026-01-01T00:00:00Z".into(),
                labels: BTreeMap::from([("x".into(), "y".into())]),
                driver: "local".into(),
                scope: "local".into(),
            },
            execution_quarantine: ExecutionQPolicy {
                relative_name: ".marty-purge-quarantine".into(),
                creation: "exclusive_create_after_confirmation".into(),
                prerequisite: "host_durable_intent_and_unchanged_custody_required".into(),
                retirement: "retire_empty_before_root_last".into(),
                absent_after_retry:
                    "origin_and_quarantine_absent_only_with_prior_exact_intent_and_unchanged_custody"
                        .into(),
            },
            not_atomic_snapshot: true,
            deletion_eligible: false,
            deletion_authorized: false,
        }
    }
    struct ResumeFixture {
        _temp: tempfile::TempDir,
        installation: PathBuf,
        installation_parent: PathBuf,
        ledger_parent: PathBuf,
        plan: Plan,
        digest: String,
        phrase: String,
    }
    fn resume_fixture() -> ResumeFixture {
        let temp = tempfile::tempdir().unwrap();
        let installation_parent = temp.path().join("installation-parent");
        let ledger_parent = temp.path().join("external-ledger-parent");
        private_directory(&installation_parent);
        private_directory(&ledger_parent);
        let installation = installation_parent.join("installation");
        private_directory(&installation);
        let plan = plan(&installation);
        let bytes = serde_json::to_vec(&plan).unwrap();
        let sha256 = digest(&bytes);
        assert!(parse_plan(&bytes, &sha256).is_ok());
        let phrase = challenge(&plan, &sha256);
        let confirmation = ExplicitConfirmation { entered: &phrase };
        let external = File::open(&ledger_parent).unwrap();
        let parent = File::open(&installation_parent).unwrap();
        let ledger =
            PurgeLedger::create_or_resume(&external, plan.installation_id, &bytes, &sha256)
                .unwrap();
        ledger
            .record_confirmation(&binding(
                &plan,
                &sha256,
                installer_purge_ledger::directory_stamp(&parent).unwrap(),
                &confirmation,
            ))
            .unwrap();
        drop(ledger);
        fs::remove_dir(&installation).unwrap();
        ResumeFixture {
            _temp: temp,
            installation,
            installation_parent,
            ledger_parent,
            plan,
            digest: sha256,
            phrase,
        }
    }
    #[test]
    fn exact_saved_plan_resumes_with_root_absence_unproven() {
        let fixture = resume_fixture();
        let confirmation = ExplicitConfirmation {
            entered: &fixture.phrase,
        };
        let result = resume_confirmed_with(
            &fixture.installation,
            &MockDocker("synthetic-engine"),
            &fixture.ledger_parent,
            fixture.plan.installation_id,
            &fixture.digest,
            &confirmation,
        )
        .unwrap();
        assert!(result.root_on_resume() == RootOnResume::AbsentUnproven);
        assert_eq!(
            result.original_private_bytes(),
            serde_json::to_vec(&fixture.plan).unwrap()
        );
        assert_eq!(result.plan_sha256(), fixture.digest);
    }
    #[test]
    fn wrong_challenge_engine_and_replaced_root_refuse() {
        let fixture = resume_fixture();
        let wrong = ExplicitConfirmation {
            entered: "PURGE wrong-id wrong-digest",
        };
        assert!(matches!(
            resume_confirmed_with(
                &fixture.installation,
                &MockDocker("synthetic-engine"),
                &fixture.ledger_parent,
                fixture.plan.installation_id,
                &fixture.digest,
                &wrong,
            ),
            Err(Refusal::ConfirmationMismatch)
        ));
        let confirmation = ExplicitConfirmation {
            entered: &fixture.phrase,
        };
        assert!(matches!(
            resume_confirmed_with(
                &fixture.installation,
                &MockDocker("replacement-engine"),
                &fixture.ledger_parent,
                fixture.plan.installation_id,
                &fixture.digest,
                &confirmation,
            ),
            Err(Refusal::EngineChanged)
        ));
        private_directory(&fixture.installation);
        assert!(matches!(
            resume_confirmed_with(
                &fixture.installation,
                &MockDocker("synthetic-engine"),
                &fixture.ledger_parent,
                fixture.plan.installation_id,
                &fixture.digest,
                &confirmation,
            ),
            Err(Refusal::InstallationChanged)
        ));
    }
    #[test]
    fn replaced_installation_parent_or_ledger_parent_refuses() {
        let fixture = resume_fixture();
        let confirmation = ExplicitConfirmation {
            entered: &fixture.phrase,
        };
        let old_parent = fixture.installation_parent.with_extension("saved");
        fs::rename(&fixture.installation_parent, &old_parent).unwrap();
        private_directory(&fixture.installation_parent);
        assert!(matches!(
            resume_confirmed_with(
                &fixture.installation,
                &MockDocker("synthetic-engine"),
                &fixture.ledger_parent,
                fixture.plan.installation_id,
                &fixture.digest,
                &confirmation,
            ),
            Err(Refusal::ConfirmationMismatch) | Err(Refusal::InstallationChanged)
        ));
        let old_ledger = fixture.ledger_parent.with_extension("saved");
        fs::rename(&fixture.ledger_parent, &old_ledger).unwrap();
        private_directory(&fixture.ledger_parent);
        assert!(matches!(
            resume_confirmed_with(
                &fixture.installation,
                &MockDocker("synthetic-engine"),
                &fixture.ledger_parent,
                fixture.plan.installation_id,
                &fixture.digest,
                &confirmation,
            ),
            Err(Refusal::LedgerUnavailable)
        ));
    }
    #[test]
    fn duplicate_nested_json_key_and_unknown_top_level_refuse() {
        let fixture = resume_fixture();
        let bytes = serde_json::to_vec(&fixture.plan).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        let duplicate = text.replace(
            "\"labels\":{\"x\":\"y\"}",
            "\"labels\":{\"x\":\"y\",\"x\":\"y\"}",
        );
        assert_ne!(duplicate, text);
        assert!(matches!(
            parse_plan(duplicate.as_bytes(), &digest(duplicate.as_bytes())),
            Err(Refusal::InvalidPlan)
        ));
        let mut changed = fixture.plan;
        changed.entries_deepest_first[0].relative_path = "foreign-customer-file".into();
        let bytes = serde_json::to_vec(&changed).unwrap();
        assert!(matches!(
            parse_plan(&bytes, &digest(&bytes)),
            Err(Refusal::InvalidPlan)
        ));
    }
}
type Result<T> = std::result::Result<T, Refusal>;

/// The caller must collect this exact text from an authenticated operator.
/// Passing synthesized text does not prove human authorization. No permit is
/// returned by this module even when the text matches.
pub(crate) struct ExplicitConfirmation<'a> {
    pub entered: &'a str,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum RootOnResume {
    PresentAndBound,
    AbsentUnproven,
}

/// Holds the external ledger lock, exact original bytes, and a checked local
/// confirmation receipt. Future execution must independently stop writers,
/// authenticate release/custody, recheck each resource and persist exact intents.
pub(crate) struct PreparedSession {
    _ledger: PurgeLedger,
    original_plan: Vec<u8>,
    plan_sha256: String,
    root_on_resume: RootOnResume,
}
impl PreparedSession {
    pub(crate) fn plan_sha256(&self) -> &str {
        &self.plan_sha256
    }
    pub(crate) fn root_on_resume(&self) -> RootOnResume {
        self.root_on_resume
    }
    fn original_private_bytes(&self) -> &[u8] {
        &self.original_plan
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Receipts {
    initial_sha256: String,
    credential_sha256: String,
    application_sha256: String,
    openbao_state_sha256: String,
    openbao_owner_transition_sha256: String,
    openbao_created_sha256: String,
    openbao_tls_completion_sha256: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ExecutionQPolicy {
    relative_name: String,
    creation: String,
    prerequisite: String,
    retirement: String,
    absent_after_retry: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    relative_path: String,
    parent: HostIdentity,
    target: HostIdentity,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    coverage: String,
    installation_id: uuid::Uuid,
    source_sha: String,
    release_tag: String,
    source_inventory_sha256: String,
    journal_revision: u64,
    cleanup_plan_sha256: String,
    cleanup_result_sha256: String,
    absolute_installation_path: String,
    root: HostIdentity,
    root_mount_id: u64,
    creation_receipts: Receipts,
    entries_deepest_first: Vec<Entry>,
    engine_id: String,
    project: String,
    removed_containers: Vec<CleanupResource>,
    removed_network_id: String,
    removed_network_name: String,
    retained_redis_volume: VolumeCreation,
    execution_quarantine: ExecutionQPolicy,
    not_atomic_snapshot: bool,
    deletion_eligible: bool,
    deletion_authorized: bool,
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_relative(path: &str) -> bool {
    path.len() <= MAX_PATH
        && !path.is_empty()
        && !path.bytes().any(|b| b == 0)
        && path.split('/').count() <= MAX_DEPTH
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}
fn parse_plan(bytes: &[u8], sha256: &str) -> Result<Plan> {
    if bytes.is_empty() || bytes.len() > MAX_PLAN || !hex64(sha256) || digest(bytes) != sha256 {
        return Err(Refusal::InvalidPlan);
    }
    let plan: Plan = serde_json::from_slice(bytes).map_err(|_| Refusal::InvalidPlan)?;
    // Equality rejects whitespace, field reordering and duplicate keys,
    // including duplicates in nested label maps.
    if serde_json::to_vec(&plan).map_err(|_| Refusal::InvalidPlan)? != bytes
        || plan.schema != SCHEMA
        || plan.coverage != "expected_normal_profile_current_tree"
        || plan.installation_id.get_version() != Some(Version::Random)
        || plan.installation_id.get_variant() != Variant::RFC4122
        || plan.root.kind != Kind::Directory
        || plan.root.mode != 0o700
        || plan.root.uid != unsafe { libc::geteuid() }
        || plan.root.dev == 0
        || plan.root.ino == 0
        || plan.root_mount_id == 0
        || plan.absolute_installation_path.len() > MAX_PATH
        || !Path::new(&plan.absolute_installation_path).is_absolute()
        || !hex64(&plan.cleanup_plan_sha256)
        || !hex64(&plan.cleanup_result_sha256)
        || ![
            &plan.creation_receipts.initial_sha256,
            &plan.creation_receipts.credential_sha256,
            &plan.creation_receipts.application_sha256,
            &plan.creation_receipts.openbao_state_sha256,
            &plan.creation_receipts.openbao_owner_transition_sha256,
            &plan.creation_receipts.openbao_created_sha256,
            &plan.creation_receipts.openbao_tls_completion_sha256,
        ]
        .iter()
        .all(|value| hex64(value))
        || plan.engine_id.is_empty()
        || plan.engine_id.len() > 128
        || plan.engine_id.bytes().any(|byte| byte.is_ascii_control())
        || plan.entries_deepest_first.len() < TopLevelName::REQUIRED.len()
        || plan.entries_deepest_first.len() > MAX_ENTRIES
        || !plan.not_atomic_snapshot
        || plan.deletion_eligible
        || plan.deletion_authorized
        || plan.execution_quarantine.relative_name != ".marty-purge-quarantine"
        || plan.execution_quarantine.creation != "exclusive_create_after_confirmation"
        || plan.execution_quarantine.prerequisite
            != "host_durable_intent_and_unchanged_custody_required"
        || plan.execution_quarantine.retirement != "retire_empty_before_root_last"
        || plan.execution_quarantine.absent_after_retry
            != "origin_and_quarantine_absent_only_with_prior_exact_intent_and_unchanged_custody"
    {
        return Err(Refusal::InvalidPlan);
    }
    let mut names = BTreeSet::new();
    let mut identities = BTreeMap::new();
    let mut previous: Option<(usize, &str)> = None;
    for entry in &plan.entries_deepest_first {
        let path = entry.relative_path.as_str();
        if !valid_relative(path) || !names.insert(path) {
            return Err(Refusal::InvalidPlan);
        }
        let depth = path.split('/').count();
        if previous.is_some_and(|(prior_depth, prior_path)| {
            prior_depth < depth || (prior_depth == depth && prior_path >= path)
        }) {
            return Err(Refusal::InvalidPlan);
        }
        previous = Some((depth, path));
        identities.insert(path, &entry.target);
    }
    let expected_top: BTreeSet<_> = TopLevelName::REQUIRED
        .iter()
        .map(|name| name.name())
        .collect();
    let observed_top: BTreeSet<_> = plan
        .entries_deepest_first
        .iter()
        .filter(|entry| !entry.relative_path.contains('/'))
        .map(|entry| entry.relative_path.clone())
        .collect();
    if observed_top != expected_top {
        return Err(Refusal::InvalidPlan);
    }
    for name in TopLevelName::REQUIRED {
        let fixed = name.name();
        if identities.get(fixed.as_str()).map(|identity| identity.kind)
            != Some(name.expected_kind())
        {
            return Err(Refusal::InvalidPlan);
        }
    }
    for entry in &plan.entries_deepest_first {
        let (parent, leaf) = match entry.relative_path.rsplit_once('/') {
            Some((parent, leaf)) => {
                let Some(identity) = identities.get(parent) else {
                    return Err(Refusal::InvalidPlan);
                };
                if identity.kind != Kind::Directory {
                    return Err(Refusal::InvalidPlan);
                }
                (*identity, leaf)
            }
            None => (&plan.root, entry.relative_path.as_str()),
        };
        if entry.parent != *parent
            || entry.target.dev != plan.root.dev
            || entry.target.ino == 0
            || leaf.is_empty()
        {
            return Err(Refusal::InvalidPlan);
        }
    }
    Ok(plan)
}

fn open_child(parent: &File, name: &OsStr, flags: i32) -> Result<Option<File>> {
    let name = CString::new(name.as_bytes()).map_err(|_| Refusal::InstallationChanged)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0,
        )
    };
    if fd < 0 {
        if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        return Err(Refusal::InstallationChanged);
    }
    Ok(Some(unsafe { File::from_raw_fd(fd) }))
}
fn open_parent(path: &Path) -> Result<(File, &OsStr)> {
    if !path.is_absolute() || path.as_os_str().as_bytes().len() > MAX_PATH {
        return Err(Refusal::InstallationChanged);
    }
    let mut parts = Vec::new();
    for part in path.components() {
        match part {
            Component::RootDir => {}
            Component::Normal(value) => parts.push(value),
            _ => return Err(Refusal::InstallationChanged),
        }
    }
    if parts.is_empty() || parts.len() > 32 {
        return Err(Refusal::InstallationChanged);
    }
    let leaf = parts.pop().ok_or(Refusal::InstallationChanged)?;
    let mut directory = File::open("/").map_err(|_| Refusal::InstallationChanged)?;
    for part in parts {
        directory = open_child(&directory, part, libc::O_RDONLY | libc::O_DIRECTORY)?
            .ok_or(Refusal::InstallationChanged)?;
    }
    Ok((directory, leaf))
}
fn open_directory(path: &Path) -> Result<File> {
    let (parent, leaf) = open_parent(path)?;
    open_child(&parent, leaf, libc::O_RDONLY | libc::O_DIRECTORY)?.ok_or(Refusal::LedgerUnavailable)
}
fn root_stamp(plan: &Plan) -> DirectoryStamp {
    DirectoryStamp {
        dev: plan.root.dev,
        ino: plan.root.ino,
        uid: plan.root.uid,
        gid: plan.root.gid,
        mode: plan.root.mode,
        mount_id: plan.root_mount_id,
    }
}
fn challenge(plan: &Plan, sha256: &str) -> String {
    format!("PURGE {} {sha256}", plan.installation_id)
}
fn explicit_matches(plan: &Plan, sha256: &str, confirmation: &ExplicitConfirmation<'_>) -> bool {
    confirmation.entered == challenge(plan, sha256)
}
fn external_parent(path: &Path, installation: &Path, root: &DirectoryStamp) -> Result<File> {
    if path.starts_with(installation) {
        return Err(Refusal::LedgerUnavailable);
    }
    let directory = open_directory(path)?;
    let stamp = installer_purge_ledger::directory_stamp(&directory)
        .map_err(|_| Refusal::LedgerUnavailable)?;
    if stamp.mode != 0o700
        || stamp.uid != unsafe { libc::geteuid() }
        || stamp.dev != root.dev
        || stamp.mount_id != root.mount_id
    {
        return Err(Refusal::LedgerUnavailable);
    }
    Ok(directory)
}
fn current_root(installation: &Path, plan: &Plan) -> Result<(File, DirectoryStamp, Option<File>)> {
    let (parent, leaf) = open_parent(installation)?;
    let parent_stamp = installer_purge_ledger::directory_stamp(&parent)
        .map_err(|_| Refusal::InstallationChanged)?;
    let root = open_child(&parent, leaf, libc::O_PATH | libc::O_DIRECTORY)?;
    if let Some(root) = &root {
        let observed = installer_purge_ledger::directory_stamp(root)
            .map_err(|_| Refusal::InstallationChanged)?;
        if observed != root_stamp(plan) {
            return Err(Refusal::InstallationChanged);
        }
    }
    Ok((parent, parent_stamp, root))
}
fn binding(
    plan: &Plan,
    sha256: &str,
    parent: DirectoryStamp,
    confirmation: &ExplicitConfirmation<'_>,
) -> ConfirmationBinding {
    ConfirmationBinding {
        installation_id: plan.installation_id,
        plan_sha256: sha256.into(),
        engine_id: plan.engine_id.clone(),
        installation_path_sha256: digest(plan.absolute_installation_path.as_bytes()),
        installation_parent: parent,
        root: root_stamp(plan),
        operator_challenge_sha256: digest(confirmation.entered.as_bytes()),
    }
}
fn journal_matches(locked: &LockedInspection, plan: &Plan, installation: &Path) -> bool {
    locked.require_path_binding(installation).is_ok()
        && locked.require_unchanged().is_ok()
        && locked.journal().installation_id() == plan.installation_id
        && locked.journal().revision() == plan.journal_revision
        && locked.journal().identity().source_sha == plan.source_sha
        && locked.journal().identity().release_tag == plan.release_tag
        && locked.journal().identity().inventory_sha256 == plan.source_inventory_sha256
}
fn fresh_binding<D: DockerRead>(
    locked: &LockedInspection,
    installation: &Path,
    docker: &D,
    plan: &Plan,
    sha256: &str,
    confirmation: &ExplicitConfirmation<'_>,
) -> Result<ConfirmationBinding> {
    if installation.to_str() != Some(plan.absolute_installation_path.as_str())
        || !journal_matches(locked, plan, installation)
    {
        return Err(Refusal::InstallationChanged);
    }
    let (_, parent, root) = current_root(installation, plan)?;
    if root.is_none()
        || parent.dev != plan.root.dev
        || parent.mount_id != plan.root_mount_id
        || installer_purge_ledger::directory_stamp(locked.installation_directory())
            .map_err(|_| Refusal::InstallationChanged)?
            != root_stamp(plan)
    {
        return Err(Refusal::InstallationChanged);
    }
    if docker.engine_id().map_err(|_| Refusal::EngineChanged)? != plan.engine_id {
        return Err(Refusal::EngineChanged);
    }
    if !explicit_matches(plan, sha256, confirmation) {
        return Err(Refusal::ConfirmationMismatch);
    }
    Ok(binding(plan, sha256, parent, confirmation))
}

/// Fresh first attempt only. The caller must have stopped all writers and
/// collected the exact challenge from an authenticated operator. No deletion
/// authority or resource-intent handle escapes this boundary.
pub(crate) fn prepare_confirmed(
    locked: &LockedInspection,
    installation: &Path,
    docker: &DockerRunner,
    external_ledger_parent: &Path,
    confirmation: &ExplicitConfirmation<'_>,
) -> Result<PreparedSession> {
    prepare_confirmed_with(
        locked,
        installation,
        docker,
        external_ledger_parent,
        confirmation,
    )
}
fn prepare_confirmed_with<D: DockerRead>(
    locked: &LockedInspection,
    installation: &Path,
    docker: &D,
    external_ledger_parent: &Path,
    confirmation: &ExplicitConfirmation<'_>,
) -> Result<PreparedSession> {
    let candidate =
        match installer_complete_purge_plan::prepare_normal_with(locked, installation, docker) {
            PrepareNormalOutcome::CompleteForConfirmation(value) => value,
            PrepareNormalOutcome::Incomplete(_) => return Err(Refusal::Incomplete),
            PrepareNormalOutcome::Unsupported(_) => return Err(Refusal::Unsupported),
        };
    let original = candidate.private_bytes().to_vec();
    let sha256 = candidate.sha256().to_owned();
    let plan = parse_plan(&original, &sha256)?;
    let first = fresh_binding(locked, installation, docker, &plan, &sha256, confirmation)?;
    let parent = external_parent(external_ledger_parent, installation, &first.root)?;
    let ledger = PurgeLedger::create_or_resume(&parent, plan.installation_id, &original, &sha256)
        .map_err(|_| Refusal::LedgerUnavailable)?;
    let final_binding = fresh_binding(locked, installation, docker, &plan, &sha256, confirmation)?;
    if final_binding != first
        || installer_purge_ledger::directory_stamp(&parent)
            .map_err(|_| Refusal::LedgerUnavailable)?
            != installer_purge_ledger::directory_stamp(&external_parent(
                external_ledger_parent,
                installation,
                &first.root,
            )?)
            .map_err(|_| Refusal::LedgerUnavailable)?
    {
        return Err(Refusal::InstallationChanged);
    }
    let final_candidate =
        match installer_complete_purge_plan::prepare_normal_with(locked, installation, docker) {
            PrepareNormalOutcome::CompleteForConfirmation(value) => value,
            _ => return Err(Refusal::Incomplete),
        };
    if final_candidate.private_bytes() != original || final_candidate.sha256() != sha256 {
        return Err(Refusal::Incomplete);
    }
    ledger
        .record_confirmation(&first)
        .map_err(|_| Refusal::LedgerUnavailable)?;
    if fresh_binding(locked, installation, docker, &plan, &sha256, confirmation)? != first {
        return Err(Refusal::InstallationChanged);
    }
    if ledger
        .confirmed_binding()
        .map_err(|_| Refusal::LedgerUnavailable)?
        != Some(first)
        || installer_purge_ledger::directory_stamp(&parent)
            .map_err(|_| Refusal::LedgerUnavailable)?
            != installer_purge_ledger::directory_stamp(&external_parent(
                external_ledger_parent,
                installation,
                &root_stamp(&plan),
            )?)
            .map_err(|_| Refusal::LedgerUnavailable)?
    {
        return Err(Refusal::LedgerUnavailable);
    }
    Ok(PreparedSession {
        _ledger: ledger,
        original_plan: original,
        plan_sha256: sha256,
        root_on_resume: RootOnResume::PresentAndBound,
    })
}

/// Resume reads the exact previously saved manifest; it never calls the fresh
/// planner or requires a volume already removed to reappear. Root absence is
/// an unproven observation, never a completion or deletion receipt.
pub(crate) fn resume_confirmed(
    installation: &Path,
    docker: &DockerRunner,
    external_ledger_parent: &Path,
    installation_id: uuid::Uuid,
    confirmed_sha256: &str,
    confirmation: &ExplicitConfirmation<'_>,
) -> Result<PreparedSession> {
    resume_confirmed_with(
        installation,
        docker,
        external_ledger_parent,
        installation_id,
        confirmed_sha256,
        confirmation,
    )
}
fn resume_confirmed_with<D: DockerRead>(
    installation: &Path,
    docker: &D,
    external_ledger_parent: &Path,
    installation_id: uuid::Uuid,
    confirmed_sha256: &str,
    confirmation: &ExplicitConfirmation<'_>,
) -> Result<PreparedSession> {
    if !hex64(confirmed_sha256) {
        return Err(Refusal::InvalidPlan);
    }
    // The external parent is opened before reading ledger bytes. A later
    // stamp comparison binds it to the root identity inside the saved plan.
    let parent = open_directory(external_ledger_parent)?;
    let (ledger, original) = PurgeLedger::open_existing(&parent, installation_id, confirmed_sha256)
        .map_err(|_| Refusal::LedgerUnavailable)?;
    let plan = parse_plan(&original, confirmed_sha256)?;
    if plan.installation_id != installation_id
        || installation.to_str() != Some(plan.absolute_installation_path.as_str())
        || !explicit_matches(&plan, confirmed_sha256, confirmation)
    {
        return Err(Refusal::ConfirmationMismatch);
    }
    let external = external_parent(external_ledger_parent, installation, &root_stamp(&plan))?;
    if installer_purge_ledger::directory_stamp(&external).map_err(|_| Refusal::LedgerUnavailable)?
        != installer_purge_ledger::directory_stamp(&parent)
            .map_err(|_| Refusal::LedgerUnavailable)?
    {
        return Err(Refusal::LedgerUnavailable);
    }
    let (_, parent_stamp, root) = current_root(installation, &plan)?;
    if parent_stamp.dev != plan.root.dev || parent_stamp.mount_id != plan.root_mount_id {
        return Err(Refusal::InstallationChanged);
    }
    let expected = binding(&plan, confirmed_sha256, parent_stamp, confirmation);
    if ledger
        .confirmed_binding()
        .map_err(|_| Refusal::LedgerUnavailable)?
        != Some(expected.clone())
    {
        return Err(Refusal::ConfirmationMismatch);
    }
    if docker.engine_id().map_err(|_| Refusal::EngineChanged)? != plan.engine_id {
        return Err(Refusal::EngineChanged);
    }
    let locked = if root.is_some() {
        let locked =
            LockedInspection::open(installation).map_err(|_| Refusal::InstallationChanged)?;
        if !journal_matches(&locked, &plan, installation) {
            return Err(Refusal::InstallationChanged);
        }
        Some(locked)
    } else {
        None
    };
    let root_on_resume = if locked.is_some() {
        RootOnResume::PresentAndBound
    } else {
        RootOnResume::AbsentUnproven
    };
    let (_, final_parent, final_root) = current_root(installation, &plan)?;
    if final_parent != expected.installation_parent
        || final_root.is_some() != root.is_some()
        || locked
            .as_ref()
            .is_some_and(|value| !journal_matches(value, &plan, installation))
        || installer_purge_ledger::directory_stamp(&external_parent(
            external_ledger_parent,
            installation,
            &root_stamp(&plan),
        )?)
        .map_err(|_| Refusal::LedgerUnavailable)?
            != installer_purge_ledger::directory_stamp(&parent)
                .map_err(|_| Refusal::LedgerUnavailable)?
    {
        return Err(Refusal::InstallationChanged);
    }
    if ledger
        .confirmed_binding()
        .map_err(|_| Refusal::LedgerUnavailable)?
        != Some(expected)
        || docker.engine_id().map_err(|_| Refusal::EngineChanged)? != plan.engine_id
    {
        return Err(Refusal::InstallationChanged);
    }
    Ok(PreparedSession {
        _ledger: ledger,
        original_plan: original,
        plan_sha256: confirmed_sha256.into(),
        root_on_resume,
    })
}
