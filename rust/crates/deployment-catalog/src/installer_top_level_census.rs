//! Read-only exact census of known installer top-level entries. A caller's
//! expected identities are assertions, not authenticated ownership evidence.
//! This observes one directory level only; contents of auxiliary directories,
//! creation provenance, and the rest of a full purge plan remain unproven.
#![cfg(target_os = "linux")]
#![allow(dead_code)] // Dormant until an authenticated receipt coordinator exists.

use crate::{
    installer_purge_host::{HostIdentity, HostPurgeEntry, Kind},
    installer_state::LockedInspection,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{CString, OsStr},
    fs::{self, File},
    io::Read,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::Path,
};

const MAX_TOP_LEVEL: usize = 64;
const COVERAGE: &str = "expected_top_level_candidates_only";
const RESOLVE_NO_XDEV: u64 = 0x01;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

/// The only dynamic top-level names are the four recorded OpenBao roles.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) enum OpenBaoRole {
    TlsInit,
    Server,
    Bootstrap,
    Unseal,
}
impl OpenBaoRole {
    fn name(self) -> &'static str {
        match self {
            Self::TlsInit => "openbao-tls-init",
            Self::Server => "openbao",
            Self::Bootstrap => "openbao-bootstrap",
            Self::Unseal => "openbao-unseal",
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) enum OpenBaoCompletedRole {
    TlsInit,
    Bootstrap,
}
impl OpenBaoCompletedRole {
    fn name(self) -> &'static str {
        match self {
            Self::TlsInit => "openbao-tls-init",
            Self::Bootstrap => "openbao-bootstrap",
        }
    }
}

/// Closed set drawn from installer_state and the native installer write paths.
/// Interrupted temporary journal/operator files are deliberately excluded.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) enum TopLevelName {
    Journal,
    Operator,
    OperatorPassword,
    Downloads,
    Evidence,
    OpenBaoState,
    Secrets,
    State,
    Backups,
    OpenBaoExports,
    OpenBaoSnapshotIdentity,
    KeycloakOutput,
    TlsOutput,
    IngressOutput,
    RenewalInputs,
    RenewalTransfer,
    GenerationInputs,
    GenerationIdentity,
    GenerationTransfer,
    ApplicationGeneration,
    FeatureProfileSecrets,
    FeaturePostgresTransport,
    FeatureIdentityOutput,
    FeatureProfileGenerations,
    OpenBaoEnv,
    OpenBaoPending,
    OpenBaoComposeRuntime,
    OpenBaoComposeModel,
    OpenBaoCreated,
    OpenBaoStart(OpenBaoRole),
    OpenBaoCompleted(OpenBaoCompletedRole),
}
impl TopLevelName {
    pub(crate) const REQUIRED: [Self; 31] = [
        Self::Journal,
        Self::Operator,
        Self::OperatorPassword,
        Self::Downloads,
        Self::Evidence,
        Self::OpenBaoState,
        Self::Secrets,
        Self::State,
        Self::Backups,
        Self::OpenBaoExports,
        Self::OpenBaoSnapshotIdentity,
        Self::KeycloakOutput,
        Self::TlsOutput,
        Self::IngressOutput,
        Self::RenewalInputs,
        Self::RenewalTransfer,
        Self::GenerationInputs,
        Self::GenerationIdentity,
        Self::GenerationTransfer,
        Self::ApplicationGeneration,
        Self::OpenBaoEnv,
        Self::OpenBaoPending,
        Self::OpenBaoComposeRuntime,
        Self::OpenBaoComposeModel,
        Self::OpenBaoCreated,
        Self::OpenBaoStart(OpenBaoRole::TlsInit),
        Self::OpenBaoStart(OpenBaoRole::Server),
        Self::OpenBaoStart(OpenBaoRole::Bootstrap),
        Self::OpenBaoStart(OpenBaoRole::Unseal),
        Self::OpenBaoCompleted(OpenBaoCompletedRole::TlsInit),
        Self::OpenBaoCompleted(OpenBaoCompletedRole::Bootstrap),
    ];
    pub(crate) fn name(self) -> String {
        match self {
            Self::Journal => "installation.json".into(),
            Self::Operator => "marty-deploy".into(),
            Self::OperatorPassword => "operator-password".into(),
            Self::Downloads => "downloads".into(),
            Self::Evidence => "evidence".into(),
            Self::OpenBaoState => "openbao-state".into(),
            Self::Secrets => "secrets".into(),
            Self::State => "state".into(),
            Self::Backups => "backups".into(),
            Self::OpenBaoExports => "openbao-exports".into(),
            Self::OpenBaoSnapshotIdentity => "openbao-snapshot-identity".into(),
            Self::KeycloakOutput => "keycloak-output".into(),
            Self::TlsOutput => "tls-output".into(),
            Self::IngressOutput => "ingress-output".into(),
            Self::RenewalInputs => "renewal-inputs".into(),
            Self::RenewalTransfer => "renewal-transfer".into(),
            Self::GenerationInputs => "generation-inputs".into(),
            Self::GenerationIdentity => "generation-identity".into(),
            Self::GenerationTransfer => "generation-transfer".into(),
            Self::ApplicationGeneration => "application-generation".into(),
            Self::FeatureProfileSecrets => "feature-profile-secrets".into(),
            Self::FeaturePostgresTransport => "feature-postgres-transport".into(),
            Self::FeatureIdentityOutput => "feature-identity-output".into(),
            Self::FeatureProfileGenerations => "feature-profile-generations".into(),
            Self::OpenBaoEnv => "openbao.env".into(),
            Self::OpenBaoPending => "openbao-pending.json".into(),
            Self::OpenBaoComposeRuntime => "openbao-compose-runtime.json".into(),
            Self::OpenBaoComposeModel => "openbao-compose-model.json".into(),
            Self::OpenBaoCreated => "openbao-created.json".into(),
            Self::OpenBaoStart(role) => format!("openbao-start-{}.json", role.name()),
            Self::OpenBaoCompleted(role) => format!("openbao-completed-{}.json", role.name()),
        }
    }
    pub(crate) fn expected_kind(self) -> Kind {
        match self {
            Self::Downloads
            | Self::Evidence
            | Self::OpenBaoState
            | Self::Secrets
            | Self::State
            | Self::Backups
            | Self::OpenBaoExports
            | Self::OpenBaoSnapshotIdentity
            | Self::KeycloakOutput
            | Self::TlsOutput
            | Self::IngressOutput
            | Self::RenewalInputs
            | Self::RenewalTransfer
            | Self::GenerationInputs
            | Self::GenerationIdentity
            | Self::GenerationTransfer
            | Self::ApplicationGeneration
            | Self::FeatureProfileSecrets
            | Self::FeaturePostgresTransport
            | Self::FeatureIdentityOutput
            | Self::FeatureProfileGenerations => Kind::Directory,
            _ => Kind::File,
        }
    }
}

/// Caller must authenticate each exact identity from creation-time evidence.
/// This type deliberately does not imply that such evidence exists today.
pub(crate) struct ExpectedTopLevel {
    pub name: TopLevelName,
    pub identity: HostIdentity,
}

/// No Serialize or Debug: even an allowed name can identify a private receipt.
pub(crate) struct TopLevelSnapshot {
    pub installation_id: uuid::Uuid,
    pub root: HostIdentity,
    pub mount_id: u64,
    pub coverage: &'static str,
    pub deletion_eligible: bool,
    pub entries: Vec<HostPurgeEntry>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IncompleteReason {
    InvalidSpecification,
    InstallationChanged,
    UnknownTopLevel,
    MissingOrChangedEntry,
    UnsafeEntry,
    EnumerationFailed,
    BoundExceeded,
}
pub(crate) enum CensusOutcome {
    ExactExpectedSetObserved(TopLevelSnapshot),
    Incomplete(IncompleteReason),
}
fn incomplete(reason: IncompleteReason) -> CensusOutcome {
    CensusOutcome::Incomplete(reason)
}

fn open_child(parent: &File, name: &OsStr) -> Result<Option<File>, ()> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes == b"." || bytes == b".." || bytes.contains(&b'/') {
        return Err(());
    }
    let name = CString::new(bytes).map_err(|_| ())?;
    let how = OpenHow {
        flags: (libc::O_PATH | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV,
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            parent.as_raw_fd(),
            name.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        return Err(());
    }
    Ok(Some(unsafe { File::from_raw_fd(fd as i32) }))
}
fn identity(file: &File) -> Result<HostIdentity, ()> {
    let m = file.metadata().map_err(|_| ())?;
    let kind = if m.is_dir() {
        Kind::Directory
    } else if m.is_file() && m.nlink() == 1 {
        Kind::File
    } else {
        return Err(());
    };
    Ok(HostIdentity {
        dev: m.dev(),
        ino: m.ino(),
        uid: m.uid(),
        gid: m.gid(),
        mode: m.mode() & 0o7777,
        kind,
    })
}
fn mount_id(file: &File) -> Result<u64, ()> {
    const PROC_SUPER_MAGIC: i64 = 0x9fa0;
    let proc = File::open("/proc/self/fdinfo").map_err(|_| ())?;
    let mut info: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(proc.as_raw_fd(), &mut info) } != 0
        || info.f_type as i64 != PROC_SUPER_MAGIC
    {
        return Err(());
    }
    let name = CString::new(file.as_raw_fd().to_string()).map_err(|_| ())?;
    let fd = unsafe {
        libc::openat(
            proc.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(());
    }
    let mut bytes = Vec::new();
    unsafe { File::from_raw_fd(fd) }
        .take(4097)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.len() > 4096 {
        return Err(());
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| ())?;
    let mut ids = text.lines().filter_map(|s| s.strip_prefix("mnt_id:"));
    let raw = ids.next().ok_or(())?.trim_ascii();
    if ids.next().is_some() || raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(());
    }
    let id = raw.parse::<u64>().map_err(|_| ())?;
    (id != 0).then_some(id).ok_or(())
}
fn names(root: &File) -> Result<BTreeSet<String>, IncompleteReason> {
    let mut result = BTreeSet::new();
    for item in fs::read_dir(format!("/proc/self/fd/{}", root.as_raw_fd()))
        .map_err(|_| IncompleteReason::EnumerationFailed)?
    {
        let item = item.map_err(|_| IncompleteReason::EnumerationFailed)?;
        let name = item
            .file_name()
            .into_string()
            .map_err(|_| IncompleteReason::UnknownTopLevel)?;
        if !result.insert(name) {
            return Err(IncompleteReason::EnumerationFailed);
        }
        if result.len() > MAX_TOP_LEVEL {
            return Err(IncompleteReason::BoundExceeded);
        }
    }
    Ok(result)
}

/// Descriptor-only current census. The caller's expected identities are not
/// authenticated by this function; host receipt checks remain in the wrapper.
pub(crate) fn inspect_held(
    root: &File,
    installation_id: uuid::Uuid,
    expected_root: &HostIdentity,
    expected_mount: u64,
    specs: &[ExpectedTopLevel],
) -> CensusOutcome {
    inspect_selected_held(
        root,
        installation_id,
        expected_root,
        expected_mount,
        specs,
        &TopLevelName::REQUIRED.into_iter().collect(),
    )
}

fn inspect_selected_held(
    root: &File,
    installation_id: uuid::Uuid,
    expected_root: &HostIdentity,
    expected_mount: u64,
    specs: &[ExpectedTopLevel],
    required: &BTreeSet<TopLevelName>,
) -> CensusOutcome {
    if expected_root.kind != Kind::Directory
        || expected_mount == 0
        || specs.is_empty()
        || specs.len() > MAX_TOP_LEVEL
        || identity(root).ok().as_ref() != Some(expected_root)
        || mount_id(root).ok() != Some(expected_mount)
    {
        return incomplete(IncompleteReason::InvalidSpecification);
    }
    let mut expected = BTreeMap::new();
    for spec in specs {
        if spec.identity.kind != spec.name.expected_kind()
            || expected.insert(spec.name.name(), &spec.identity).is_some()
        {
            return incomplete(IncompleteReason::InvalidSpecification);
        }
    }
    if expected.len() != required.len()
        || required
            .iter()
            .any(|name| !expected.contains_key(&name.name()))
    {
        return incomplete(IncompleteReason::InvalidSpecification);
    }
    let before = match names(root) {
        Ok(v) => v,
        Err(reason) => return incomplete(reason),
    };
    let expected_names: BTreeSet<_> = expected.keys().cloned().collect();
    if before != expected_names {
        return incomplete(if before.difference(&expected_names).next().is_some() {
            IncompleteReason::UnknownTopLevel
        } else {
            IncompleteReason::MissingOrChangedEntry
        });
    }
    let mut entries = Vec::with_capacity(expected.len());
    for (name, wanted) in &expected {
        let held = match open_child(root, OsStr::new(name)) {
            Ok(Some(v)) => v,
            Ok(None) => return incomplete(IncompleteReason::MissingOrChangedEntry),
            Err(_) => return incomplete(IncompleteReason::UnsafeEntry),
        };
        let observed = match identity(&held) {
            Ok(v) => v,
            Err(_) => return incomplete(IncompleteReason::UnsafeEntry),
        };
        if observed != **wanted || mount_id(&held).ok() != Some(expected_mount) {
            return incomplete(IncompleteReason::MissingOrChangedEntry);
        }
        entries.push(HostPurgeEntry {
            relative_path: name.clone(),
            parent: expected_root.clone(),
            target: observed,
        });
    }
    if names(root).ok().as_ref() != Some(&before)
        || identity(root).ok().as_ref() != Some(expected_root)
        || mount_id(root).ok() != Some(expected_mount)
    {
        return incomplete(IncompleteReason::InstallationChanged);
    }
    for (name, wanted) in &expected {
        let latest = open_child(root, OsStr::new(name)).ok().flatten();
        if latest.as_ref().and_then(|f| identity(f).ok()).as_ref() != Some(wanted)
            || latest.as_ref().and_then(|f| mount_id(f).ok()) != Some(expected_mount)
        {
            return incomplete(IncompleteReason::InstallationChanged);
        }
    }
    CensusOutcome::ExactExpectedSetObserved(TopLevelSnapshot {
        installation_id,
        root: expected_root.clone(),
        mount_id: expected_mount,
        coverage: COVERAGE,
        deletion_eligible: false,
        entries,
    })
}

/// Requires the journal lock, but authenticating the caller's expected map and
/// proving auxiliary directory contents are separate future coordinator work.
pub(crate) fn inspect(
    locked: &LockedInspection,
    installation: &Path,
    expected_root: &HostIdentity,
    expected_mount: u64,
    specs: &[ExpectedTopLevel],
) -> CensusOutcome {
    if locked.require_path_binding(installation).is_err() || locked.require_unchanged().is_err() {
        return incomplete(IncompleteReason::InstallationChanged);
    }
    let mut required: BTreeSet<_> = TopLevelName::REQUIRED.into_iter().collect();
    let features =
        match crate::installer_host_storage_inventory::verified_feature_roots(locked, installation)
        {
            Ok(features) => features,
            Err(_) => return incomplete(IncompleteReason::MissingOrChangedEntry),
        };
    required.extend(features);
    let result = inspect_selected_held(
        locked.installation_directory(),
        locked.journal().installation_id(),
        expected_root,
        expected_mount,
        specs,
        &required,
    );
    if locked.require_path_binding(installation).is_err() || locked.require_unchanged().is_err() {
        return incomplete(IncompleteReason::InstallationChanged);
    }
    result
}

/// Derive the closed normal-profile names from the held directory for a fresh
/// observation. The caller must separately compare receipt-bound identities;
/// current metadata alone is not historical ownership evidence.
pub(crate) fn derive_current_fixed_specs(
    locked: &LockedInspection,
    installation: &Path,
    expected_root: &HostIdentity,
    expected_mount: u64,
) -> Result<Vec<ExpectedTopLevel>, IncompleteReason> {
    locked
        .require_path_binding(installation)
        .and_then(|_| locked.require_unchanged())
        .map_err(|_| IncompleteReason::InstallationChanged)?;
    let mut required: BTreeSet<_> = TopLevelName::REQUIRED.into_iter().collect();
    required.extend(
        crate::installer_host_storage_inventory::verified_feature_roots(locked, installation)
            .map_err(|_| IncompleteReason::MissingOrChangedEntry)?,
    );
    let result = derive_selected_specs_held(
        locked.installation_directory(),
        expected_root,
        expected_mount,
        &required,
    );
    locked
        .require_path_binding(installation)
        .and_then(|_| locked.require_unchanged())
        .map_err(|_| IncompleteReason::InstallationChanged)?;
    result
}

/// Enumerate only the fixed 31-name current profile beneath a held root FD.
/// `expected_mount` belongs to this caller's mount namespace. This does not
/// authenticate ownership or prove that the observed children may be deleted.
pub(crate) fn derive_current_fixed_specs_held(
    root: &File,
    expected_root: &HostIdentity,
    expected_mount: u64,
) -> Result<Vec<ExpectedTopLevel>, IncompleteReason> {
    derive_selected_specs_held(
        root,
        expected_root,
        expected_mount,
        &TopLevelName::REQUIRED.into_iter().collect(),
    )
}

fn derive_selected_specs_held(
    root: &File,
    expected_root: &HostIdentity,
    expected_mount: u64,
    required: &BTreeSet<TopLevelName>,
) -> Result<Vec<ExpectedTopLevel>, IncompleteReason> {
    if identity(root).ok().as_ref() != Some(expected_root)
        || mount_id(root).ok() != Some(expected_mount)
        || expected_mount == 0
    {
        return Err(IncompleteReason::InstallationChanged);
    }
    let observed_names = names(root)?;
    let required_names: BTreeSet<_> = required.iter().map(|name| name.name()).collect();
    if observed_names != required_names {
        return Err(
            if observed_names.difference(&required_names).next().is_some() {
                IncompleteReason::UnknownTopLevel
            } else {
                IncompleteReason::MissingOrChangedEntry
            },
        );
    }
    let mut specs = Vec::with_capacity(required.len());
    for name in required.iter().copied() {
        let held = open_child(root, OsStr::new(&name.name()))
            .map_err(|_| IncompleteReason::UnsafeEntry)?
            .ok_or(IncompleteReason::MissingOrChangedEntry)?;
        let observed = identity(&held).map_err(|_| IncompleteReason::UnsafeEntry)?;
        if observed.kind != name.expected_kind() || mount_id(&held).ok() != Some(expected_mount) {
            return Err(IncompleteReason::UnsafeEntry);
        }
        specs.push(ExpectedTopLevel {
            name,
            identity: observed,
        });
    }
    if names(root)? != observed_names
        || identity(root).ok().as_ref() != Some(expected_root)
        || mount_id(root).ok() != Some(expected_mount)
    {
        return Err(IncompleteReason::InstallationChanged);
    }
    Ok(specs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn fixture() -> (
        tempfile::TempDir,
        File,
        HostIdentity,
        u64,
        Vec<ExpectedTopLevel>,
    ) {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut specs = Vec::new();
        for name in TopLevelName::REQUIRED {
            let path = temp.path().join(name.name());
            match name.expected_kind() {
                Kind::Directory => {
                    fs::create_dir(&path).unwrap();
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
                }
                Kind::File => {
                    fs::write(&path, b"synthetic fixture").unwrap();
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
                }
            }
            specs.push(ExpectedTopLevel {
                name,
                identity: identity(&File::open(&path).unwrap()).unwrap(),
            });
        }
        let root = File::open(temp.path()).unwrap();
        let root_identity = identity(&root).unwrap();
        let mount = mount_id(&root).unwrap();
        (temp, root, root_identity, mount, specs)
    }

    #[test]
    fn descriptor_only_fixed_derivation_rejects_wrong_root_mount_and_unknown_name() {
        let (temp, root, wanted, mount, _specs) = fixture();
        let derived = derive_current_fixed_specs_held(&root, &wanted, mount).unwrap();
        assert_eq!(derived.len(), TopLevelName::REQUIRED.len());
        let observed = inspect_held(&root, uuid::Uuid::new_v4(), &wanted, mount, &derived);
        assert!(matches!(
            observed,
            CensusOutcome::ExactExpectedSetObserved(_)
        ));
        let mut wrong = wanted.clone();
        wrong.ino = wrong.ino.wrapping_add(1);
        assert!(matches!(
            derive_current_fixed_specs_held(&root, &wrong, mount),
            Err(IncompleteReason::InstallationChanged)
        ));
        assert!(matches!(
            derive_current_fixed_specs_held(&root, &wanted, mount + 1),
            Err(IncompleteReason::InstallationChanged)
        ));
        fs::write(temp.path().join("unknown-private-canary"), b"synthetic").unwrap();
        assert!(matches!(
            derive_current_fixed_specs_held(&root, &wanted, mount),
            Err(IncompleteReason::UnknownTopLevel)
        ));
    }

    #[test]
    fn exact_normal_like_top_level_set_is_observed_but_not_eligible() {
        let (_temp, root, expected_root, mount, specs) = fixture();
        let id = uuid::Uuid::new_v4();
        let CensusOutcome::ExactExpectedSetObserved(snapshot) =
            inspect_held(&root, id, &expected_root, mount, &specs)
        else {
            panic!("expected exact census")
        };
        assert_eq!(snapshot.entries.len(), specs.len());
        assert_eq!(snapshot.coverage, "expected_top_level_candidates_only");
        assert!(!snapshot.deletion_eligible);
        assert_eq!(snapshot.installation_id, id);
    }

    #[test]
    fn feature_names_require_a_selected_owner_set_and_never_become_deletion_authority() {
        let (temp, root, expected_root, mount, old_specs) = fixture();
        assert_eq!(TopLevelName::REQUIRED.len(), 31);
        let mut selected: BTreeSet<_> = TopLevelName::REQUIRED.into_iter().collect();
        for name in [
            TopLevelName::FeatureProfileSecrets,
            TopLevelName::FeaturePostgresTransport,
            TopLevelName::FeatureIdentityOutput,
            TopLevelName::FeatureProfileGenerations,
        ] {
            fs::create_dir(temp.path().join(name.name())).unwrap();
            selected.insert(name);
        }
        let id = uuid::Uuid::new_v4();
        assert!(matches!(
            inspect_held(&root, id, &expected_root, mount, &old_specs),
            CensusOutcome::Incomplete(IncompleteReason::UnknownTopLevel)
        ));
        let specs = derive_selected_specs_held(&root, &expected_root, mount, &selected).unwrap();
        let CensusOutcome::ExactExpectedSetObserved(snapshot) =
            inspect_selected_held(&root, id, &expected_root, mount, &specs, &selected)
        else {
            panic!("expected exact selected set")
        };
        assert_eq!(snapshot.entries.len(), 35);
        assert!(!snapshot.deletion_eligible);
        fs::write(temp.path().join("feature-other-credentials"), b"unclaimed").unwrap();
        assert!(matches!(
            derive_selected_specs_held(&root, &expected_root, mount, &selected),
            Err(IncompleteReason::UnknownTopLevel)
        ));
    }

    #[test]
    fn unknown_canary_and_symlink_refuse_exact_census() {
        let (temp, root, expected_root, mount, specs) = fixture();
        let id = uuid::Uuid::new_v4();
        fs::write(temp.path().join("private-canary"), b"never owned").unwrap();
        assert!(matches!(
            inspect_held(&root, id, &expected_root, mount, &specs),
            CensusOutcome::Incomplete(IncompleteReason::UnknownTopLevel)
        ));
        fs::remove_file(temp.path().join("private-canary")).unwrap();
        fs::remove_file(temp.path().join("openbao-start-openbao.json")).unwrap();
        symlink(
            "openbao-created.json",
            temp.path().join("openbao-start-openbao.json"),
        )
        .unwrap();
        assert!(matches!(
            inspect_held(&root, id, &expected_root, mount, &specs),
            CensusOutcome::Incomplete(IncompleteReason::UnsafeEntry)
        ));
    }

    #[test]
    fn identity_mount_and_missing_entry_drift_are_incomplete() {
        let (temp, root, expected_root, mount, mut specs) = fixture();
        let id = uuid::Uuid::new_v4();
        let removed_spec = specs.pop().unwrap();
        assert!(matches!(
            inspect_held(&root, id, &expected_root, mount, &specs),
            CensusOutcome::Incomplete(IncompleteReason::InvalidSpecification)
        ));
        specs.push(removed_spec);
        assert!(matches!(
            inspect_held(&root, id, &expected_root, mount + 1, &specs),
            CensusOutcome::Incomplete(IncompleteReason::InvalidSpecification)
        ));
        fs::remove_file(temp.path().join("openbao-created.json")).unwrap();
        assert!(matches!(
            inspect_held(&root, id, &expected_root, mount, &specs),
            CensusOutcome::Incomplete(IncompleteReason::MissingOrChangedEntry)
        ));
    }
}
