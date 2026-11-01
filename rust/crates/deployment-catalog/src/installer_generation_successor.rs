//! Successor publication shares the original generation owner's filesystem
//! admission. The original application-generation directory is never changed.
use super::*;
use crate::installer_state::LockedMaintenance;

fn ensure_child(parent: &File, name: &str) -> Result<File> {
    safe_name(name)?;
    let label = CString::new(name).map_err(|_| REFUSED)?;
    if unsafe { libc::mkdirat(parent.as_raw_fd(), label.as_ptr(), 0o700) } != 0 {
        require(std::io::Error::last_os_error().raw_os_error() == Some(libc::EEXIST))?;
    }
    parent.sync_all().map_err(|_| REFUSED)?;
    child(parent, name)
}
fn atomic_copy(parent: &File, name: &str, bytes: &[u8]) -> Result<()> {
    safe_name(name)?;
    let temporary = format!("copy-{name}.tmp");
    let existing = names(parent)?;
    if existing.contains(name) {
        require(read(parent, name, false)?.0 == bytes)?;
        require(!existing.contains(&temporary))?;
        return Ok(());
    }
    if existing.contains(&temporary) {
        let mut file = open(parent, &temporary, libc::O_RDONLY, 0)?;
        let metadata = file.metadata().map_err(|_| REFUSED)?;
        require(
            metadata.is_file()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.nlink() == 1
                && [0o600, 0o444].contains(&(metadata.mode() & 0o7777))
                && metadata.len() <= bytes.len() as u64,
        )?;
        let mut partial = Vec::new();
        file.read_to_end(&mut partial).map_err(|_| REFUSED)?;
        require(bytes.starts_with(&partial))?;
        let temporary = CString::new(temporary.as_str()).map_err(|_| REFUSED)?;
        require(unsafe { libc::unlinkat(parent.as_raw_fd(), temporary.as_ptr(), 0) } == 0)?;
        parent.sync_all().map_err(|_| REFUSED)?;
    }
    let mut file = open(
        parent,
        &temporary,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        0o600,
    )?;
    file.write_all(bytes).map_err(|_| REFUSED)?;
    require(unsafe { libc::fchmod(file.as_raw_fd(), 0o444) } == 0)?;
    file.sync_all().map_err(|_| REFUSED)?;
    let source = CString::new(temporary).map_err(|_| REFUSED)?;
    let target = CString::new(name).map_err(|_| REFUSED)?;
    require(
        unsafe {
            libc::renameat2(
                parent.as_raw_fd(),
                source.as_ptr(),
                parent.as_raw_fd(),
                target.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } == 0,
    )?;
    parent.sync_all().map_err(|_| REFUSED.into())
}

pub(crate) fn stage_successor(
    installation: &Path,
    state: &mut LockedMaintenance,
    parent: &GenerationBinding,
    native_operation: &str,
) -> Result<GenerationBinding> {
    state.inspection().require_path_binding(installation)?;
    parent.validate()?;
    require(parent.public_ingress())?;
    let sequence = parent.sequence().checked_add(1).ok_or(REFUSED)?;
    let successor = SuccessorBinding {
        sequence,
        parent_binding_sha256: parent.sha256()?,
        native_operation: native_operation.into(),
    };
    let (receipt, candidates, plan) = candidate_at(
        installation,
        &parent.installation_id,
        &parent.engine_id,
        Some(&successor),
    )?;
    let plan = plan.ok_or(REFUSED)?;
    plan.require_saved(state.inspection())?;
    plan.validate_current_certificate()?;
    let mut files = BTreeMap::new();
    let mut values = BTreeMap::new();
    for (name, previous) in &parent.files {
        let (bytes, source) = if let Some(bytes) = candidates.get(name) {
            (bytes.clone(), GenerationSource::Candidate)
        } else {
            (parent.read(installation, name)?, GenerationSource::Original)
        };
        files.insert(
            name.clone(),
            GenerationFile {
                source,
                sha256: digest(&bytes),
                size: bytes.len() as u64,
                source_mode: previous.mode,
                mode: 0o444,
            },
        );
        values.insert(name.clone(), bytes);
    }
    let result = GenerationBinding {
        schema: "elevenid.installer-application-generation/v4".into(),
        installation_id: parent.installation_id.clone(),
        engine_id: parent.engine_id.clone(),
        network_id: parent.network_id.clone(),
        generation_receipt_sha256: digest(&receipt),
        files,
        activated: false,
        root_retired: false,
        installation_ready: false,
        successor: Some(successor),
    };
    result.validate()?;
    let bytes = serde_json::to_vec(&result).map_err(|_| REFUSED)?;
    let pending = format!("generation-{sequence:020}-binding-pending.json");
    match state.read_evidence(&pending)? {
        Some(saved) => require(saved == bytes)?,
        None => {
            require(
                !result
                    .secret_dir(installation)?
                    .try_exists()
                    .map_err(|_| REFUSED)?,
            )?;
            state.write_evidence_exclusive(&pending, &bytes)?;
        }
    }
    let root = directory(installation)?;
    let generations = ensure_child(&root, "application-generations")?;
    let name = format!("{sequence:020}-{}", result.sha256()?);
    let output = ensure_child(&generations, &name)?;
    let allowed: BTreeSet<String> = values
        .keys()
        .flat_map(|name| [name.clone(), format!("copy-{name}.tmp")])
        .collect();
    require(names(&output)?.is_subset(&allowed))?;
    for (name, value) in &values {
        atomic_copy(&output, name, value)?;
    }
    binding(&result.secret_dir(installation)?, &output)?;
    verify(installation, &result)?;
    state.require_unchanged()?;
    let record = format!("generation-{sequence:020}-binding.json");
    match state.read_evidence(&record)? {
        Some(saved) => require(saved == bytes)?,
        None => state.write_evidence_exclusive(&record, &bytes)?,
    }
    Ok(result)
}

/// The immutable-generation owner publishes only this exact private selector;
/// compare-before-replace and all candidate/activation records are rechecked.
pub(crate) fn publish_current(
    installation: &Path,
    state: &mut LockedMaintenance,
    expected: Option<&[u8]>,
    next: &[u8],
) -> Result<()> {
    state.inspection().require_path_binding(installation)?;
    crate::installer_generation_maintenance::require_selection_publication(
        state.inspection(),
        installation,
        next,
    )?;
    state.with_atomic_publication(|view| {
        replace_selector(installation, expected, next, |_| {})?;
        view.require_path_binding(installation)?;
        view.require_unchanged()
    })
}

fn selector_file(directory: &File, name: &str) -> Result<Option<(File, Vec<u8>)>> {
    if !names(directory)?.contains(name) {
        return Ok(None);
    }
    let mut file = open(directory, name, libc::O_RDONLY, 0)?;
    let before = file.metadata().map_err(|_| REFUSED)?;
    require(
        before.is_file()
            && before.uid() == unsafe { libc::geteuid() }
            && before.nlink() == 1
            && before.mode() & 0o7777 == 0o600
            && (1..=262144).contains(&before.len()),
    )?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|_| REFUSED)?;
    let after = file.metadata().map_err(|_| REFUSED)?;
    require(file_identity(&before) == file_identity(&after) && bytes.len() as u64 == before.len())?;
    Ok(Some((file, bytes)))
}
fn file_identity(m: &std::fs::Metadata) -> (u64, u64, u32, u32, u32, u64, u64) {
    (
        m.dev(),
        m.ino(),
        m.uid(),
        m.gid(),
        m.mode(),
        m.nlink(),
        m.len(),
    )
}
fn require_same_file(expected: &File, current: &File) -> Result<()> {
    require(
        file_identity(&expected.metadata().map_err(|_| REFUSED)?)
            == file_identity(&current.metadata().map_err(|_| REFUSED)?),
    )
}
fn replace_selector(
    installation: &Path,
    expected: Option<&[u8]>,
    next: &[u8],
    mut boundary: impl FnMut(u8),
) -> Result<()> {
    require(!next.is_empty() && next.len() <= 262144)?;
    let root = directory(installation)?;
    let evidence = child(&root, "evidence")?;
    let selector = crate::installer_generation_maintenance::SELECTOR;
    let old = selector_file(&evidence, selector)?;
    require(old.as_ref().map(|(_, bytes)| bytes.as_slice()) == expected)?;
    let temporary = format!("generation-selector-{}.tmp", uuid::Uuid::new_v4().simple());
    let mut output = open(
        &evidence,
        &temporary,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        0o600,
    )?;
    output
        .write_all(next)
        .and_then(|_| output.sync_all())
        .map_err(|_| REFUSED)?;
    boundary(1);
    binding(installation, &root)?;
    binding(&installation.join("evidence"), &evidence)?;
    let recheck = selector_file(&evidence, selector)?;
    require(recheck.as_ref().map(|(_, bytes)| bytes.as_slice()) == expected)?;
    match (&old, &recheck) {
        (Some((held, _)), Some((current, _))) => require_same_file(held, current)?,
        (None, None) => (),
        _ => return Err(REFUSED.into()),
    }
    let from = CString::new(temporary).map_err(|_| REFUSED)?;
    let to = CString::new(selector).map_err(|_| REFUSED)?;
    require(
        unsafe {
            libc::renameat2(
                evidence.as_raw_fd(),
                from.as_ptr(),
                evidence.as_raw_fd(),
                to.as_ptr(),
                if old.is_some() {
                    libc::RENAME_EXCHANGE
                } else {
                    libc::RENAME_NOREPLACE
                },
            )
        } == 0,
    )?;
    evidence.sync_all().map_err(|_| REFUSED)?;
    boundary(2);
    binding(installation, &root)?;
    binding(&installation.join("evidence"), &evidence)?;
    let (published, bytes) = selector_file(&evidence, selector)?.ok_or(REFUSED)?;
    require(bytes == next)?;
    require_same_file(&output, &published)?;
    if let Some((held, previous)) = old {
        // Exchange preserves the predecessor until both inode bindings and
        // contents are checked after the atomic selection change.
        let (displaced, bytes) =
            selector_file(&evidence, from.to_str().map_err(|_| REFUSED)?)?.ok_or(REFUSED)?;
        require(bytes == previous)?;
        require_same_file(&held, &displaced)?;
        require(unsafe { libc::unlinkat(evidence.as_raw_fd(), from.as_ptr(), 0) } == 0)?;
        evidence.sync_all().map_err(|_| REFUSED)?;
        binding(&installation.join("evidence"), &evidence)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn immutable_copy_recovers_partial_private_temporary_without_overwriting_published_files() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let directory = directory(temp.path()).unwrap();
        let bytes = b"retained-public-and-scoped-input";
        std::fs::write(temp.path().join("copy-value.tmp"), &bytes[..7]).unwrap();
        std::fs::set_permissions(
            temp.path().join("copy-value.tmp"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        atomic_copy(&directory, "value", bytes).unwrap();
        atomic_copy(&directory, "value", bytes).unwrap();
        assert!(atomic_copy(&directory, "value", b"different").is_err());
        assert_eq!(std::fs::read(temp.path().join("value")).unwrap(), bytes);
        assert!(!temp.path().join("copy-value.tmp").exists());
    }

    fn selector_fixture() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::create_dir(temp.path().join("evidence")).unwrap();
        std::fs::set_permissions(
            temp.path().join("evidence"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        temp
    }
    #[test]
    fn selector_create_and_exchange_keep_exact_predecessor_and_published_inode() {
        let temp = selector_fixture();
        let path = temp.path();
        replace_selector(path, None, b"first", |_| {}).unwrap();
        replace_selector(path, Some(b"first"), b"second", |_| {}).unwrap();
        assert_eq!(
            std::fs::read(
                path.join("evidence")
                    .join(crate::installer_generation_maintenance::SELECTOR)
            )
            .unwrap(),
            b"second"
        );
        assert!(replace_selector(path, None, b"foreign", |_| {}).is_err());
        assert!(replace_selector(path, Some(b"first"), b"foreign", |_| {}).is_err());
    }
    #[test]
    fn selector_refuses_same_bytes_on_exchanged_predecessor_inode() {
        let temp = selector_fixture();
        let path = temp.path();
        replace_selector(path, None, b"first", |_| {}).unwrap();
        let target = path
            .join("evidence")
            .join(crate::installer_generation_maintenance::SELECTOR);
        assert!(replace_selector(path, Some(b"first"), b"next", |stage| {
            if stage == 1 {
                std::fs::rename(&target, path.join("evidence/displaced")).unwrap();
                std::fs::write(&target, b"first").unwrap();
                std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
        })
        .is_err());
        assert_eq!(std::fs::read(target).unwrap(), b"first");
    }
    #[test]
    fn selector_refuses_evidence_directory_exchange_before_or_after_rename() {
        for stage in [1, 2] {
            let temp = selector_fixture();
            let path = temp.path();
            assert!(replace_selector(path, None, b"next", |at| {
                if at == stage {
                    std::fs::rename(path.join("evidence"), path.join("displaced")).unwrap();
                    std::fs::create_dir(path.join("evidence")).unwrap();
                    std::fs::set_permissions(
                        path.join("evidence"),
                        std::fs::Permissions::from_mode(0o700),
                    )
                    .unwrap();
                }
            })
            .is_err());
            assert!(!path
                .join("evidence")
                .join(crate::installer_generation_maintenance::SELECTOR)
                .exists());
        }
    }
}
