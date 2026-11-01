//! Private atomic storage for timing-only ACME checkpoints. The parent owns
//! schema, phase-anchor and conservative timing validation; this child owns
//! held-path identity, complete publication and bounded crash staging.
use crate::{
    installer_host_fs as host,
    installer_state::{LockedInspection, LockedMaintenance},
};
use std::{
    ffi::CString,
    fs::{File, Metadata},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
};

type Result<T> = std::result::Result<T, String>;
const REFUSED: &str = "ACME timing checkpoint publication is uncertain or differs; preserve the installation lock and retained phase evidence";
const MAX_BYTES: usize = 16 * 1024;

fn require(value: bool) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}

fn require_name(name: &str) -> Result<()> {
    let (environment, cycle) = name
        .strip_prefix("acme-poll-")
        .and_then(|value| value.strip_suffix(".json"))
        .and_then(|value| value.split_once('-'))
        .ok_or(REFUSED)?;
    require(
        ["staging", "production"].contains(&environment)
            && cycle.len() == 20
            && cycle.bytes().all(|value| value.is_ascii_digit()),
    )?;
    let cycle = cycle.parse::<u64>().map_err(|_| REFUSED)?;
    require(name == format!("acme-poll-{environment}-{cycle:020}.json"))
}

type DirectoryIdentity = (u64, u64, u32, u32, u32);
type FileIdentity = (u64, u64, u32, u32, u32, u64, u64);

fn directory_identity(metadata: &Metadata) -> Result<DirectoryIdentity> {
    require(
        metadata.is_dir()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o7777 == 0o700,
    )?;
    Ok((
        metadata.dev(),
        metadata.ino(),
        metadata.uid(),
        metadata.gid(),
        metadata.mode(),
    ))
}

fn file_identity(metadata: &Metadata) -> Result<FileIdentity> {
    require(
        metadata.is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o7777 == 0o600
            && metadata.nlink() == 1
            && (1..=MAX_BYTES as u64).contains(&metadata.len()),
    )?;
    Ok((
        metadata.dev(),
        metadata.ino(),
        metadata.uid(),
        metadata.gid(),
        metadata.mode(),
        metadata.nlink(),
        metadata.len(),
    ))
}

struct StoredFile {
    file: File,
    identity: FileIdentity,
    bytes: Vec<u8>,
}

fn stored_file(directory: &File, name: &str) -> Result<Option<StoredFile>> {
    let name = CString::new(name).map_err(|_| REFUSED)?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            Ok(None)
        } else {
            Err(REFUSED.into())
        };
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    let identity = file_identity(&file.metadata().map_err(|_| REFUSED)?)?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| REFUSED)?;
    require(
        file_identity(&file.metadata().map_err(|_| REFUSED)?)? == identity
            && bytes.len() as u64 == identity.6,
    )?;
    Ok(Some(StoredFile {
        file,
        identity,
        bytes,
    }))
}

fn same_file(before: &StoredFile, after: &StoredFile) -> Result<()> {
    require(
        before.identity == after.identity
            && file_identity(&before.file.metadata().map_err(|_| REFUSED)?)? == before.identity
            && before.bytes == after.bytes,
    )
}

struct Store {
    path: PathBuf,
    installation: File,
    installation_identity: DirectoryIdentity,
    evidence: File,
    evidence_identity: DirectoryIdentity,
}

impl Store {
    fn open(path: &Path, installation: File) -> Result<Self> {
        let installation_identity =
            directory_identity(&installation.metadata().map_err(|_| REFUSED)?)?;
        let evidence = host::open_child(
            &installation,
            "evidence",
            libc::O_RDONLY | libc::O_DIRECTORY,
            REFUSED,
        )?;
        let evidence_identity = directory_identity(&evidence.metadata().map_err(|_| REFUSED)?)?;
        let store = Self {
            path: path.into(),
            installation,
            installation_identity,
            evidence,
            evidence_identity,
        };
        store.require_bound()?;
        Ok(store)
    }

    fn from_view(view: &LockedInspection) -> Result<Self> {
        view.require_unchanged()?;
        let installation = view
            .installation_directory()
            .try_clone()
            .map_err(|_| REFUSED)?;
        let path = std::fs::read_link(format!("/proc/self/fd/{}", installation.as_raw_fd()))
            .map_err(|_| REFUSED)?;
        view.require_path_binding(&path)?;
        Self::open(&path, installation)
    }

    fn require_bound(&self) -> Result<()> {
        require(
            directory_identity(&self.installation.metadata().map_err(|_| REFUSED)?)?
                == self.installation_identity
                && directory_identity(&self.evidence.metadata().map_err(|_| REFUSED)?)?
                    == self.evidence_identity,
        )?;
        let installation = host::directory(&self.path, REFUSED)?;
        require(
            directory_identity(&installation.metadata().map_err(|_| REFUSED)?)?
                == self.installation_identity,
        )?;
        let evidence = host::open_child(
            &self.installation,
            "evidence",
            libc::O_RDONLY | libc::O_DIRECTORY,
            REFUSED,
        )?;
        require(
            directory_identity(&evidence.metadata().map_err(|_| REFUSED)?)?
                == self.evidence_identity,
        )
    }

    fn require_file(&self, name: &str, expected: Option<&StoredFile>) -> Result<()> {
        match (expected, stored_file(&self.evidence, name)?) {
            (None, None) => Ok(()),
            (Some(before), Some(after)) => same_file(before, &after),
            _ => Err(REFUSED.into()),
        }
    }

    fn unlink(&self, name: &str, expected: &StoredFile) -> Result<()> {
        self.require_bound()?;
        self.require_file(name, Some(expected))?;
        let name = CString::new(name).map_err(|_| REFUSED)?;
        require(unsafe { libc::unlinkat(self.evidence.as_raw_fd(), name.as_ptr(), 0) } == 0)?;
        self.evidence.sync_all().map_err(|_| REFUSED)?;
        self.require_bound()
    }
}

fn read_part(view: &LockedInspection, name: &str, pending: bool) -> Result<Option<Vec<u8>>> {
    require_name(name)?;
    let store = Store::from_view(view)?;
    let current = stored_file(&store.evidence, name)?;
    let temporary_name = format!("{name}.next");
    let temporary = stored_file(&store.evidence, &temporary_name)?;
    // Inspect both objects even when only one is requested. A hostile staging
    // object must not be silently ignored, and this read never removes it.
    store.require_bound()?;
    store.require_file(name, current.as_ref())?;
    store.require_file(&temporary_name, temporary.as_ref())?;
    store.require_bound()?;
    view.require_path_binding(&store.path)?;
    view.require_unchanged()?;
    Ok(if pending { temporary } else { current }.map(|value| value.bytes))
}

pub(super) fn read(view: &LockedInspection, name: &str) -> Result<Option<Vec<u8>>> {
    read_part(view, name, false)
}

/// The semantic owner must merge applicable timing from this fully written
/// staged checkpoint with the current checkpoint before any next remote call.
/// After an exchange it instead contains the displaced, validated predecessor.
pub(super) fn read_pending(view: &LockedInspection, name: &str) -> Result<Option<Vec<u8>>> {
    read_part(view, name, true)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Boundary {
    RecoveryPublished,
    Recovered,
    Anonymous,
    Staged,
    Published,
    Cleaned,
}

fn replace(
    store: &Store,
    name: &str,
    previous: Option<&[u8]>,
    next: &[u8],
    validate: &impl Fn(&[u8]) -> Result<()>,
    covers: &impl Fn(&[u8], &[u8]) -> Result<bool>,
    mut boundary: impl FnMut(Boundary) -> Result<()>,
) -> Result<()> {
    require_name(name)?;
    require(!next.is_empty() && next.len() <= MAX_BYTES)?;
    validate(next)?;
    store.require_bound()?;
    let mut old = stored_file(&store.evidence, name)?;
    require(old.as_ref().map(|value| value.bytes.as_slice()) == previous)?;
    if let Some(old) = &old {
        validate(&old.bytes)?;
        require(covers(next, &old.bytes)?)?;
    }
    let temporary_name = format!("{name}.next");
    if let Some(temporary) = stored_file(&store.evidence, &temporary_name)? {
        // A staged checkpoint may be the only durable copy of a later CA
        // lower bound. An in-memory merge into `next` does not permit deleting
        // it: a failure before the next publication would lose that bound.
        validate(&temporary.bytes)?;
        require(covers(next, &temporary.bytes)?)?;
        store.require_file(name, old.as_ref())?;
        if old
            .as_ref()
            .map(|current| covers(&current.bytes, &temporary.bytes))
            .transpose()?
            .unwrap_or(false)
        {
            // The retained current already contains every applicable bound.
            // A prior process may have stopped between rename and fsync, so
            // establish its durability before retiring the other record.
            old.as_ref()
                .ok_or(REFUSED)?
                .file
                .sync_all()
                .map_err(|_| REFUSED)?;
            store.evidence.sync_all().map_err(|_| REFUSED)?;
            store.require_bound()?;
            store.require_file(name, old.as_ref())?;
            store.unlink(&temporary_name, &temporary)?;
        } else {
            // All records written by this owner are comparable within an
            // unchanged phase. A newer staged checkpoint is first promoted
            // and made durable; only then can its weaker predecessor go.
            if let Some(current) = &old {
                require(covers(&temporary.bytes, &current.bytes)?)?;
            }
            let promoted = select_staged(store, name, old.as_ref(), &temporary, || {
                boundary(Boundary::RecoveryPublished)
            })?;
            if let Some(previous) = &old {
                let displaced = stored_file(&store.evidence, &temporary_name)?.ok_or(REFUSED)?;
                validate(&displaced.bytes)?;
                same_file(previous, &displaced)?;
                require(covers(&promoted.bytes, &displaced.bytes)?)?;
                store.unlink(&temporary_name, &displaced)?;
            } else {
                store.require_file(&temporary_name, None)?;
            }
            old = Some(promoted);
        }
        boundary(Boundary::Recovered)?;
        store.require_bound()?;
        store.require_file(name, old.as_ref())?;
        store.require_file(&temporary_name, None)?;
    }
    if old.as_ref().is_some_and(|current| current.bytes == next) {
        store.require_file(name, old.as_ref())?;
        return store.require_bound();
    }

    // A named partial write cannot be validated after a crash. Linux
    // O_TMPFILE keeps it unreachable until complete bytes/mode are durable.
    // Unsupported filesystems fail closed; there is no named-partial fallback.
    let fd = unsafe {
        libc::openat(
            store.evidence.as_raw_fd(),
            c".".as_ptr(),
            libc::O_TMPFILE | libc::O_RDWR | libc::O_CLOEXEC,
            0o600,
        )
    };
    require(fd >= 0)?;
    let mut output = unsafe { File::from_raw_fd(fd) };
    output.write_all(next).map_err(|_| REFUSED)?;
    require(unsafe { libc::fchmod(output.as_raw_fd(), 0o600) } == 0)?;
    output.sync_all().map_err(|_| REFUSED)?;
    let anonymous = output.metadata().map_err(|_| REFUSED)?;
    require(
        anonymous.is_file()
            && anonymous.uid() == unsafe { libc::geteuid() }
            && anonymous.mode() & 0o7777 == 0o600
            && anonymous.nlink() == 0
            && anonymous.len() as usize == next.len(),
    )?;
    boundary(Boundary::Anonymous)?;
    store.require_bound()?;
    store.require_file(name, old.as_ref())?;
    let source =
        CString::new(format!("/proc/self/fd/{}", output.as_raw_fd())).map_err(|_| REFUSED)?;
    let temporary = CString::new(temporary_name.as_str()).map_err(|_| REFUSED)?;
    // /proc/self/fd plus AT_SYMLINK_FOLLOW is the unprivileged O_TMPFILE
    // linking form; AT_EMPTY_PATH would require CAP_DAC_READ_SEARCH.
    require(
        unsafe {
            libc::linkat(
                libc::AT_FDCWD,
                source.as_ptr(),
                store.evidence.as_raw_fd(),
                temporary.as_ptr(),
                libc::AT_SYMLINK_FOLLOW,
            )
        } == 0,
    )?;
    output.sync_all().map_err(|_| REFUSED)?;
    store.evidence.sync_all().map_err(|_| REFUSED)?;
    let staged = stored_file(&store.evidence, &temporary_name)?.ok_or(REFUSED)?;
    require(
        staged.bytes == next
            && staged.identity == file_identity(&output.metadata().map_err(|_| REFUSED)?)?,
    )?;
    boundary(Boundary::Staged)?;
    let published = select_staged(store, name, old.as_ref(), &staged, || {
        boundary(Boundary::Published)
    })?;
    require(
        published.identity == file_identity(&output.metadata().map_err(|_| REFUSED)?)?
            && published.bytes == next,
    )?;
    if let Some(old) = old {
        let displaced = stored_file(&store.evidence, &temporary_name)?.ok_or(REFUSED)?;
        validate(&displaced.bytes)?;
        same_file(&old, &displaced)?;
        require(covers(&published.bytes, &displaced.bytes)?)?;
        store.unlink(&temporary_name, &displaced)?;
    } else {
        store.require_file(&temporary_name, None)?;
    }
    boundary(Boundary::Cleaned)?;
    store.require_bound()?;
    store.require_file(name, Some(&published))?;
    store.require_file(&temporary_name, None)?;
    store.require_bound()
}

/// Select one already complete checkpoint while retaining its displaced
/// predecessor. Cleanup is separate and requires semantic dominance after the
/// rename has been synced and the selected path/inode have been read back.
fn select_staged(
    store: &Store,
    name: &str,
    old: Option<&StoredFile>,
    staged: &StoredFile,
    boundary: impl FnOnce() -> Result<()>,
) -> Result<StoredFile> {
    let temporary_name = format!("{name}.next");
    store.require_bound()?;
    store.require_file(name, old)?;
    store.require_file(&temporary_name, Some(staged))?;
    staged.file.sync_all().map_err(|_| REFUSED)?;
    let temporary = CString::new(temporary_name).map_err(|_| REFUSED)?;
    let target = CString::new(name).map_err(|_| REFUSED)?;
    require(
        unsafe {
            libc::renameat2(
                store.evidence.as_raw_fd(),
                temporary.as_ptr(),
                store.evidence.as_raw_fd(),
                target.as_ptr(),
                if old.is_some() {
                    libc::RENAME_EXCHANGE
                } else {
                    libc::RENAME_NOREPLACE
                },
            )
        } == 0,
    )?;
    store.evidence.sync_all().map_err(|_| REFUSED)?;
    boundary()?;
    store.require_bound()?;
    let published = stored_file(&store.evidence, name)?.ok_or(REFUSED)?;
    same_file(staged, &published)?;
    Ok(published)
}

/// The caller supplies exact current bytes and semantic validation for every
/// checkpoint, including abandoned complete staging. `covers` must authenticate
/// both records and prove that discarding the second cannot lose applicable
/// timing, observation time or backoff history. Any failed or panicking
/// publication poisons the held maintenance writer until it is dropped.
pub(super) fn publish(
    state: &mut LockedMaintenance,
    name: &str,
    previous: Option<&[u8]>,
    next: &[u8],
    validate: impl Fn(&[u8]) -> Result<()>,
    covers: impl Fn(&[u8], &[u8]) -> Result<bool>,
) -> Result<()> {
    require_name(name)?;
    require(!next.is_empty() && next.len() <= MAX_BYTES)?;
    validate(next)?;
    state.with_atomic_publication(|view| {
        let store = Store::from_view(view)?;
        replace(&store, name, previous, next, &validate, &covers, |_| Ok(()))?;
        view.require_path_binding(&store.path)?;
        view.require_unchanged()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    const NAME: &str = "acme-poll-production-00000000000000000000.json";
    const FIRST: &[u8] = br#"{"checkpoint":1}"#;
    const NEXT: &[u8] = br#"{"checkpoint":2}"#;
    const LATEST: &[u8] = br#"{"checkpoint":3}"#;

    fn fixture() -> (tempfile::TempDir, Store) {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::create_dir(root.path().join("evidence")).unwrap();
        std::fs::set_permissions(
            root.path().join("evidence"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let store =
            Store::open(root.path(), host::directory(root.path(), REFUSED).unwrap()).unwrap();
        (root, store)
    }

    fn validate(bytes: &[u8]) -> Result<()> {
        let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| REFUSED)?;
        require(
            value.as_object().is_some_and(|map| map.len() == 1)
                && value["checkpoint"].as_u64().is_some(),
        )
    }

    fn covers(candidate: &[u8], retained: &[u8]) -> Result<bool> {
        validate(candidate)?;
        validate(retained)?;
        let candidate: serde_json::Value =
            serde_json::from_slice(candidate).map_err(|_| REFUSED)?;
        let retained: serde_json::Value = serde_json::from_slice(retained).map_err(|_| REFUSED)?;
        Ok(candidate["checkpoint"].as_u64() >= retained["checkpoint"].as_u64())
    }

    fn bytes(store: &Store, name: &str) -> Option<Vec<u8>> {
        stored_file(&store.evidence, name)
            .unwrap()
            .map(|value| value.bytes)
    }

    fn write(path: &Path, bytes: &[u8], mode: u32) {
        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn timing_replacement_is_private_exact_and_bounded() {
        let (_root, store) = fixture();
        let mut previous = None;
        for value in 0..64 {
            let next = format!("{{\"checkpoint\":{value}}}").into_bytes();
            replace(
                &store,
                NAME,
                previous.as_deref(),
                &next,
                &validate,
                &covers,
                |_| Ok(()),
            )
            .unwrap();
            assert_eq!(bytes(&store, NAME), Some(next.clone()));
            assert_eq!(host::file_names(&store.evidence, REFUSED).unwrap().len(), 1);
            previous = Some(next);
        }
        assert!(replace(&store, NAME, None, NEXT, &validate, &covers, |_| Ok(())).is_err());
        assert!(
            replace(&store, NAME, Some(FIRST), NEXT, &validate, &covers, |_| Ok(
                ()
            ))
            .is_err()
        );
    }

    #[test]
    fn every_visible_crash_stage_is_complete_and_recovers_without_extra_files() {
        for replacement in [false, true] {
            for stop in [
                Boundary::Anonymous,
                Boundary::Staged,
                Boundary::Published,
                Boundary::Cleaned,
            ] {
                let (root, store) = fixture();
                if replacement {
                    replace(&store, NAME, None, FIRST, &validate, &covers, |_| Ok(())).unwrap();
                }
                assert!(replace(
                    &store,
                    NAME,
                    replacement.then_some(FIRST),
                    NEXT,
                    &validate,
                    &covers,
                    |at| {
                        if at == stop {
                            Err("simulated interruption".into())
                        } else {
                            Ok(())
                        }
                    }
                )
                .is_err());
                drop(store);
                let reopened =
                    Store::open(root.path(), host::directory(root.path(), REFUSED).unwrap())
                        .unwrap();
                let current = bytes(&reopened, NAME);
                let pending = bytes(&reopened, &format!("{NAME}.next"));
                if let Some(pending) = &pending {
                    validate(pending).unwrap();
                }
                match stop {
                    Boundary::RecoveryPublished | Boundary::Recovered => unreachable!(),
                    Boundary::Anonymous => assert!(pending.is_none()),
                    Boundary::Staged => assert_eq!(pending.as_deref(), Some(NEXT)),
                    Boundary::Published | Boundary::Cleaned => {
                        assert_eq!(current.as_deref(), Some(NEXT))
                    }
                }
                replace(
                    &reopened,
                    NAME,
                    current.as_deref(),
                    NEXT,
                    &validate,
                    &covers,
                    |_| Ok(()),
                )
                .unwrap();
                assert_eq!(bytes(&reopened, NAME).as_deref(), Some(NEXT));
                assert_eq!(
                    host::file_names(&reopened.evidence, REFUSED).unwrap().len(),
                    1
                );
            }
        }
    }

    #[test]
    fn stronger_staged_timing_survives_every_recovery_and_replacement_gap() {
        for (predecessor, first_stop) in [
            (false, Boundary::Staged),
            (true, Boundary::Staged),
            (true, Boundary::Published),
        ] {
            for stop in [
                Boundary::RecoveryPublished,
                Boundary::Recovered,
                Boundary::Anonymous,
                Boundary::Staged,
                Boundary::Published,
                Boundary::Cleaned,
            ] {
                if first_stop == Boundary::Published && stop == Boundary::RecoveryPublished {
                    continue;
                }
                let (root, store) = fixture();
                if predecessor {
                    replace(&store, NAME, None, FIRST, &validate, &covers, |_| Ok(())).unwrap();
                }
                assert!(replace(
                    &store,
                    NAME,
                    predecessor.then_some(FIRST),
                    NEXT,
                    &validate,
                    &covers,
                    |at| {
                        if at == first_stop {
                            Err("original publication interrupted".into())
                        } else {
                            Ok(())
                        }
                    },
                )
                .is_err());
                drop(store);
                let reopened =
                    Store::open(root.path(), host::directory(root.path(), REFUSED).unwrap())
                        .unwrap();
                let current = bytes(&reopened, NAME);
                assert!(replace(
                    &reopened,
                    NAME,
                    current.as_deref(),
                    LATEST,
                    &validate,
                    &covers,
                    |at| {
                        if at == stop {
                            Err("recovery or new publication interrupted".into())
                        } else {
                            Ok(())
                        }
                    },
                )
                .is_err());
                drop(reopened);
                let recovered =
                    Store::open(root.path(), host::directory(root.path(), REFUSED).unwrap())
                        .unwrap();
                let current = bytes(&recovered, NAME);
                let pending = bytes(&recovered, &format!("{NAME}.next"));
                // The later bound must still be on disk even when interruption
                // occurs immediately after old staging cleanup, before the
                // next O_TMPFILE exists. In-memory merging is insufficient.
                assert!(current
                    .iter()
                    .chain(pending.iter())
                    .any(|value| covers(value, NEXT).unwrap()));
                assert!(
                    host::file_names(&recovered.evidence, REFUSED)
                        .unwrap()
                        .len()
                        <= 2
                );
                replace(
                    &recovered,
                    NAME,
                    current.as_deref(),
                    LATEST,
                    &validate,
                    &covers,
                    |_| Ok(()),
                )
                .unwrap();
                assert_eq!(bytes(&recovered, NAME).as_deref(), Some(LATEST));
                assert_eq!(
                    host::file_names(&recovered.evidence, REFUSED)
                        .unwrap()
                        .len(),
                    1
                );
            }
        }
    }

    #[test]
    fn incomparable_or_regressive_timing_is_refused_without_losing_either_record() {
        let (root, store) = fixture();
        replace(&store, NAME, None, FIRST, &validate, &covers, |_| Ok(())).unwrap();
        let pending_path = root.path().join("evidence").join(format!("{NAME}.next"));
        write(&pending_path, NEXT, 0o600);
        // Both predecessors fit beneath the proposed next, but they do not
        // dominate one another. Cleanup must not invent that permission.
        let incomparable = |candidate: &[u8], retained: &[u8]| -> Result<bool> {
            validate(candidate)?;
            validate(retained)?;
            Ok(candidate == LATEST || candidate == retained)
        };
        for (next, dominance) in [
            (
                LATEST,
                &incomparable as &dyn Fn(&[u8], &[u8]) -> Result<bool>,
            ),
            (FIRST, &covers as &dyn Fn(&[u8], &[u8]) -> Result<bool>),
        ] {
            assert!(replace(
                &store,
                NAME,
                Some(FIRST),
                next,
                &validate,
                &dominance,
                |_| Ok(()),
            )
            .is_err());
            assert_eq!(bytes(&store, NAME).as_deref(), Some(FIRST));
            assert_eq!(std::fs::read(&pending_path).unwrap(), NEXT);
        }
    }

    #[test]
    fn recovery_promotion_rechecks_selected_inode_and_held_directory_before_cleanup() {
        for exchange_directory in [false, true] {
            let (root, store) = fixture();
            replace(&store, NAME, None, FIRST, &validate, &covers, |_| Ok(())).unwrap();
            let pending_path = root.path().join("evidence").join(format!("{NAME}.next"));
            write(&pending_path, NEXT, 0o600);
            assert!(replace(
                &store,
                NAME,
                Some(FIRST),
                LATEST,
                &validate,
                &covers,
                |at| {
                    if at == Boundary::RecoveryPublished {
                        if exchange_directory {
                            std::fs::rename(
                                root.path().join("evidence"),
                                root.path().join("displaced-evidence"),
                            )
                            .unwrap();
                            std::fs::create_dir(root.path().join("evidence")).unwrap();
                            std::fs::set_permissions(
                                root.path().join("evidence"),
                                std::fs::Permissions::from_mode(0o700),
                            )
                            .unwrap();
                        } else {
                            let current = root.path().join("evidence").join(NAME);
                            std::fs::rename(&current, root.path().join("displaced-current"))
                                .unwrap();
                            write(&current, NEXT, 0o600);
                        }
                    }
                    Ok(())
                },
            )
            .is_err());
            // Neither hostile replacement allows deleting the held old
            // current after promotion, even when its content is identical.
            assert_eq!(
                bytes(&store, &format!("{NAME}.next")).as_deref(),
                Some(FIRST)
            );
        }
    }

    #[test]
    fn abandoned_unvalidated_staging_is_never_deleted_or_adopted() {
        let (root, store) = fixture();
        replace(&store, NAME, None, FIRST, &validate, &covers, |_| Ok(())).unwrap();
        let temporary = root.path().join("evidence").join(format!("{NAME}.next"));
        write(&temporary, br#"{"other":1}"#, 0o600);
        assert!(
            replace(&store, NAME, Some(FIRST), NEXT, &validate, &covers, |_| Ok(
                ()
            ))
            .is_err()
        );
        assert_eq!(bytes(&store, NAME).as_deref(), Some(FIRST));
        assert!(temporary.exists());
    }

    #[test]
    fn same_content_predecessor_and_published_inode_replacements_are_refused() {
        for stop in [Boundary::Staged, Boundary::Published] {
            let (root, store) = fixture();
            replace(&store, NAME, None, FIRST, &validate, &covers, |_| Ok(())).unwrap();
            let path = root.path().join("evidence").join(NAME);
            assert!(
                replace(&store, NAME, Some(FIRST), NEXT, &validate, &covers, |at| {
                    if at == stop {
                        let current = std::fs::read(&path).unwrap();
                        std::fs::rename(&path, root.path().join("evidence/displaced")).unwrap();
                        write(&path, &current, 0o600);
                    }
                    Ok(())
                })
                .is_err()
            );
        }
    }

    #[test]
    fn evidence_directory_exchange_is_refused_before_and_after_selection() {
        for stop in [Boundary::Staged, Boundary::Published] {
            let (root, store) = fixture();
            assert!(replace(&store, NAME, None, NEXT, &validate, &covers, |at| {
                if at == stop {
                    std::fs::rename(root.path().join("evidence"), root.path().join("displaced"))
                        .unwrap();
                    std::fs::create_dir(root.path().join("evidence")).unwrap();
                    std::fs::set_permissions(
                        root.path().join("evidence"),
                        std::fs::Permissions::from_mode(0o700),
                    )
                    .unwrap();
                }
                Ok(())
            })
            .is_err());
            assert!(!root.path().join("evidence").join(NAME).exists());
        }
    }

    #[test]
    fn checkpoint_reads_refuse_unsafe_current_or_staging_files() {
        for suffix in ["", ".next"] {
            for kind in ["symlink", "hardlink", "mode", "empty", "directory"] {
                let (root, store) = fixture();
                let name = format!("{NAME}{suffix}");
                let path = root.path().join("evidence").join(&name);
                let source = root.path().join("source");
                write(&source, FIRST, 0o600);
                match kind {
                    "symlink" => symlink(&source, &path).unwrap(),
                    "hardlink" => std::fs::hard_link(&source, &path).unwrap(),
                    "mode" => write(&path, FIRST, 0o644),
                    "empty" => write(&path, b"", 0o600),
                    "directory" => std::fs::create_dir(&path).unwrap(),
                    _ => unreachable!(),
                }
                assert!(stored_file(&store.evidence, &name).is_err());
            }
        }
    }

    #[test]
    fn only_fixed_environment_and_cycle_names_are_writable() {
        for valid in [NAME, "acme-poll-staging-00000000000000000001.json"] {
            require_name(valid).unwrap();
        }
        for invalid in [
            "acme-production-000000.json",
            "acme-poll-production-1.json",
            "acme-poll-production-00000000000000000000.json.next",
            "../checkpoint.json",
            "acme-poll-production-99999999999999999999.json",
            "acme-poll-unknown-00000000000000000000.json",
        ] {
            assert!(require_name(invalid).is_err());
        }
    }
}
