//! Separately owned, append-only feature projections. Baseline credential
//! directories and receipts are never rewritten or used as a feature mount.
use super::*;
use crate::{installer_filesystem::DeviceBinding, installer_state::LockedMaintenance};
use std::{
    ffi::CString,
    fs::File,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
};

pub(crate) const ROOT: &str = "feature-profile-generations";
pub(crate) const RECORD: &str = "feature-profile-generations.json";
const ROOT_SCHEMA: &str = "elevenid.installer-feature-generations/v1";
const MATERIAL_SCHEMA: &str = "elevenid.installer-feature-generation-material/v1";
#[path = "installer_feature_activation.rs"]
mod activation;
#[path = "installer_feature_renewal.rs"]
mod renewal;
pub(crate) use activation::{
    activate, complete_baseline_activation, extend_session, require_session_extension,
    ActivationPermit,
};
pub(crate) use renewal::verify_helper_projection_at;
pub(crate) use renewal::{
    has_pending_baseline_renewal, load_staged_baseline, stage_renewal_for_baseline, RenewalPermit,
    StagedRenewal,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectoryIdentity {
    device: DeviceBinding,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
}
impl DirectoryIdentity {
    fn observe(directory: &File) -> Result<Self> {
        let m = directory.metadata().map_err(|_| REFUSED)?;
        require(m.is_dir() && m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o7777 == 0o700)?;
        Ok(Self {
            device: DeviceBinding::observe(directory, REFUSED)?,
            inode: m.ino(),
            uid: m.uid(),
            gid: m.gid(),
            mode: m.mode(),
        })
    }
    fn matches(&self, mut observed: Self) -> bool {
        if !self.device.matches(observed.device) {
            return false;
        }
        observed.device = self.device;
        observed == *self
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootReceipt {
    schema: String,
    installation_id: uuid::Uuid,
    engine_id: String,
    feature_profile_sha256: String,
    original_credentials_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    original_identity_receipt_sha256: Option<String>,
    directory: DirectoryIdentity,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SelectedMaterial {
    schema: String,
    sequence: u32,
    installation_id: uuid::Uuid,
    engine_id: String,
    pub(super) feature_profile_sha256: String,
    root_receipt_sha256: String,
    parent_material_sha256: String,
    activation_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    renewal_receipt_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    caller_binding_rotation: Option<crate::installer_feature_caller_binding::RotationReceipt>,
    configuration: Configuration,
    imports: BTreeMap<String, Fingerprint>,
    directory: DirectoryIdentity,
    files_directory: DirectoryIdentity,
    files: BTreeMap<String, Fingerprint>,
}
impl SelectedMaterial {
    fn leaf(&self) -> String {
        format!("{:06}", self.sequence)
    }
    pub(super) fn directory(&self, installation: &Path) -> PathBuf {
        installation.join(ROOT).join(self.leaf()).join("files")
    }
    fn record(&self) -> String {
        format!("generation-feature-{:06}-binding.json", self.sequence)
    }
}

fn encoded<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| REFUSED.into())
}
fn read_record(installation: &Path, name: &str) -> Result<Vec<u8>> {
    crate::installer_verify::read_private_bytes(
        &installation.join("evidence").join(name),
        4 * 1024 * 1024,
    )
}
fn optional_record(installation: &Path, name: &str) -> Result<Option<Vec<u8>>> {
    match std::fs::symlink_metadata(installation.join("evidence").join(name)) {
        Ok(_) => read_record(installation, name).map(Some),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(REFUSED.into()),
    }
}
fn store_once(
    state: &mut LockedMaintenance,
    installation: &Path,
    name: &str,
    bytes: &[u8],
) -> Result<()> {
    if let Some(old) = optional_record(installation, name)? {
        require(old == bytes)?;
        state.require_unchanged()
    } else {
        state.write_evidence_exclusive(name, bytes)
    }
}
fn decode_record<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    serde_json::from_value(crate::installer_json::decode(bytes).map_err(|_| REFUSED)?)
        .map_err(|_| REFUSED.into())
}

pub(crate) fn initialize_generations(
    state: &mut InstallerState,
    installation: &Path,
) -> Result<()> {
    let Some(selection) = state.with_inspection(super::load)? else {
        return Ok(());
    };
    state.require_live_phase(Phase::Provisioning)?;
    state.with_inspection(|view| {
        view.require_path_binding(installation)?;
        crate::installer_feature_credentials::verify(view, &selection.credential_names()?)?;
        if let Some(identity) = selection.identity_selection()? {
            crate::installer_feature_identity::verify_retained(view, installation, &identity)?;
        }
        Ok(())
    })?;
    let directory = state.create_feature_directory(ROOT)?;
    let identity = DirectoryIdentity::observe(&directory)?;
    require(fs::file_names(&directory, REFUSED)?.is_empty())?;
    let receipt = RootReceipt {
        schema: ROOT_SCHEMA.into(),
        installation_id: state.journal().installation_id(),
        engine_id: state.journal().runtime().ok_or(REFUSED)?.engine_id.clone(),
        feature_profile_sha256: selection.profile_sha256()?,
        original_credentials_sha256: digest(
            &state.with_inspection(|view| view.read_evidence(CREDENTIALS))?,
        ),
        original_identity_receipt_sha256: selection
            .identity_selection()?
            .map(|_| {
                state
                    .with_inspection(|view| {
                        view.read_evidence(crate::installer_feature_identity::RECORD)
                    })
                    .map(|bytes| digest(&bytes))
            })
            .transpose()?,
        directory: identity.clone(),
    };
    fs::require_directory_binding(&installation.join(ROOT), &directory, REFUSED)?;
    require(DirectoryIdentity::observe(&directory)? == identity)?;
    state.write_evidence(RECORD, &encoded(&receipt)?)?;
    state.with_inspection(|view| verify_generations(view, installation))
}

fn root_at(installation: &Path) -> Result<Option<(File, RootReceipt, Vec<u8>)>> {
    let journal = InstallerState::inspect(installation)?;
    let path = installation.join(ROOT);
    let Some(raw) = optional_record(installation, RECORD)? else {
        require(
            std::fs::symlink_metadata(&path)
                .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        )?;
        return Ok(None);
    };
    let receipt: RootReceipt = decode_record(&raw)?;
    require(
        receipt.schema == ROOT_SCHEMA
            && receipt.installation_id == journal.installation_id()
            && journal
                .runtime()
                .is_some_and(|runtime| runtime.engine_id == receipt.engine_id)
            && journal.feature_profile_sha256() == Some(receipt.feature_profile_sha256.as_str())
            && digest(&read_record(installation, CREDENTIALS)?)
                == receipt.original_credentials_sha256,
    )?;
    let selection = super::at(installation)?.ok_or(REFUSED)?;
    require(
        match (
            &receipt.original_identity_receipt_sha256,
            selection.identity_selection()?,
        ) {
            (Some(expected), Some(_)) => {
                digest(&read_record(
                    installation,
                    crate::installer_feature_identity::RECORD,
                )?) == *expected
            }
            (None, None) => true,
            _ => false,
        },
    )?;
    let directory = fs::directory(&path, REFUSED)?;
    require(
        receipt
            .directory
            .matches(DirectoryIdentity::observe(&directory)?),
    )?;
    Ok(Some((directory, receipt, raw)))
}

fn read_file(directory: &File, name: &str) -> Result<Vec<u8>> {
    let mut file = fs::open_child(directory, name, libc::O_RDONLY | libc::O_NONBLOCK, REFUSED)?;
    let m = file.metadata().map_err(|_| REFUSED)?;
    require(
        name.starts_with("feature_")
            && name.len() <= 127
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            && m.is_file()
            && m.uid() == unsafe { libc::geteuid() }
            && m.mode() & 0o7777 == 0o444
            && m.nlink() == 1
            && (1..=65_536).contains(&m.len()),
    )?;
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(65_537)
        .read_to_end(&mut bytes)
        .map_err(|_| REFUSED)?;
    require(bytes.len() as u64 == m.len())?;
    if name == "feature_workload_client_ca_der" {
        use x509_cert::der::Decode;
        require(bytes.len() <= 16_384 && x509_cert::Certificate::from_der(&bytes).is_ok())?;
    } else {
        require(
            bytes.is_ascii()
                && !bytes.contains(&0)
                && !bytes.windows(11).any(|v| v == b"PRIVATE KEY"),
        )?;
    }
    Ok(bytes)
}

fn verify_material(
    installation: &Path,
    root: &File,
    receipt: &RootReceipt,
    root_raw: &[u8],
    material: &SelectedMaterial,
) -> Result<BTreeMap<String, Vec<u8>>> {
    require(
        material.schema == MATERIAL_SCHEMA
            && (1..=999_999).contains(&material.sequence)
            && material.installation_id == receipt.installation_id
            && material.engine_id == receipt.engine_id
            && material.feature_profile_sha256 == receipt.feature_profile_sha256
            && material.root_receipt_sha256 == digest(root_raw)
            && hash(&material.parent_material_sha256)
            && material.activation_sha256.as_deref().is_none_or(hash),
    )?;
    require(
        encoded(material)?
            == encoded(&decode_record::<SelectedMaterial>(&read_record(
                installation,
                &material_intent_name(material.sequence),
            )?)?)?,
    )?;
    let child = fs::open_child(
        root,
        &material.leaf(),
        libc::O_RDONLY | libc::O_DIRECTORY,
        REFUSED,
    )?;
    require(
        material
            .directory
            .matches(DirectoryIdentity::observe(&child)?),
    )?;
    require(
        fs::file_names(&child, REFUSED)?
            == if material.renewal_receipt_sha256.is_some() {
                BTreeSet::from(["files".into(), "input".into(), "output".into()])
            } else {
                BTreeSet::from(["files".into()])
            },
    )?;
    let files = fs::open_child(&child, "files", libc::O_RDONLY | libc::O_DIRECTORY, REFUSED)?;
    let before = DirectoryIdentity::observe(&files)?;
    require(
        material.files_directory.matches(before.clone())
            && fs::file_names(&files, REFUSED)? == material.files.keys().cloned().collect()
            && !material.files.is_empty()
            && material.files.len() <= 128,
    )?;
    let values: BTreeMap<_, _> = material
        .files
        .iter()
        .map(|(name, expected)| {
            let bytes = read_file(&files, name)?;
            require(fingerprint(&bytes) == *expected)?;
            Ok((name.clone(), bytes))
        })
        .collect::<Result<_>>()?;
    material.configuration.validate_imported(&values)?;
    activation::verify_material_configuration(installation, material, &values)?;
    renewal::verify_retained_material(installation, material, &values)?;
    for (name, expected) in &material.imports {
        require(
            values
                .get(name)
                .is_some_and(|bytes| fingerprint(bytes) == *expected),
        )?;
    }
    fs::require_directory_binding(&material.directory(installation), &files, REFUSED)?;
    require(DirectoryIdentity::observe(&files)? == before)?;
    Ok(values)
}

fn materials(installation: &Path) -> Result<Vec<(SelectedMaterial, Vec<u8>)>> {
    let Some((root, receipt, root_raw)) = root_at(installation)? else {
        return Ok(Vec::new());
    };
    let before = DirectoryIdentity::observe(&root)?;
    let names = fs::file_names(&root, REFUSED)?;
    require(names.len() <= 1024)?;
    let mut result = Vec::new();
    let mut previous = digest(&root_raw);
    for (offset, name) in names.iter().enumerate() {
        let sequence = u32::try_from(offset + 1).map_err(|_| REFUSED)?;
        require(name == &format!("{sequence:06}"))?;
        let Some(raw) = optional_record(
            installation,
            &format!("generation-feature-{sequence:06}-binding.json"),
        )?
        else {
            require(offset + 1 == names.len())?;
            if optional_record(installation, &material_intent_name(sequence))?.is_some() {
                verify_prepared_material(installation, sequence)?;
            } else {
                renewal::verify_preparation_at(installation, sequence)?;
            }
            break;
        };
        let material: SelectedMaterial = decode_record(&raw)?;
        require(material.sequence == sequence && material.parent_material_sha256 == previous)?;
        verify_material(installation, &root, &receipt, &root_raw, &material)?;
        previous = digest(&raw);
        result.push((material, raw));
    }
    fs::require_directory_binding(&installation.join(ROOT), &root, REFUSED)?;
    require(DirectoryIdentity::observe(&root)? == before)?;
    Ok(result)
}

pub(crate) fn verify_generations(view: &LockedInspection, installation: &Path) -> Result<()> {
    view.require_path_binding(installation)?;
    materials(installation)?;
    view.require_unchanged()
}

pub(super) fn selected_for_inputs(
    selection: Selection,
    inputs: &ComposeInputs,
) -> Result<Selection> {
    let candidates: Vec<_> = inputs
        .bound_inputs
        .iter()
        .filter(|file| {
            file.path
                .file_name()
                .and_then(|v| v.to_str())
                .is_some_and(|name| {
                    name.starts_with("generation-feature-") && name.ends_with("-binding.json")
                })
        })
        .collect();
    if candidates.is_empty() {
        return Ok(selection);
    }
    require(candidates.len() == 1)?;
    let file = candidates[0];
    require(file.path.parent() == Some(inputs.installation.join("evidence").as_path()))?;
    let material = materials(&inputs.installation)?
        .into_iter()
        .find_map(|(material, raw)| {
            (file.path.file_name().and_then(|v| v.to_str()) == Some(material.record().as_str())
                && file.sha256 == digest(&raw))
            .then_some(material)
        })
        .ok_or(REFUSED)?;
    require(material.feature_profile_sha256 == selection.profile_sha256()?)?;
    let mut selected = selection;
    selected.configuration = material.configuration.clone();
    selected.imports = material.imports.clone();
    selected.generation = Some(material);
    Ok(selected)
}

pub(super) fn selected_files(
    installation: &Path,
    material: &SelectedMaterial,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let (root, receipt, raw) = root_at(installation)?.ok_or(REFUSED)?;
    verify_material(installation, &root, &receipt, &raw, material)
}

fn mkdir_owned(parent: &File, name: &str) -> Result<File> {
    require(!name.contains('/') && !name.is_empty() && name != "." && name != "..")?;
    let name = CString::new(name).map_err(|_| REFUSED)?;
    require(unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } == 0)?;
    let child = fs::open_child(
        parent,
        name.to_str().map_err(|_| REFUSED)?,
        libc::O_RDONLY | libc::O_DIRECTORY,
        REFUSED,
    )?;
    DirectoryIdentity::observe(&child)?;
    child
        .sync_all()
        .and_then(|_| parent.sync_all())
        .map_err(|_| REFUSED)?;
    Ok(child)
}
fn write_exclusive(parent: &File, name: &str, bytes: &[u8], mode: u32) -> Result<()> {
    require(
        !name.contains('/')
            && !name.is_empty()
            && name != "."
            && name != ".."
            && (1..=65_536).contains(&bytes.len()),
    )?;
    let name = CString::new(name).map_err(|_| REFUSED)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    require(fd >= 0)?;
    let mut output = unsafe { File::from_raw_fd(fd) };
    output
        .write_all(bytes)
        .and_then(|_| output.sync_all())
        .map_err(|_| REFUSED)?;
    require(unsafe { libc::fchmod(output.as_raw_fd(), mode) } == 0)?;
    output
        .sync_all()
        .and_then(|_| parent.sync_all())
        .map_err(|_| REFUSED.into())
}

fn material_intent_name(sequence: u32) -> String {
    format!("generation-feature-{sequence:06}-material-intent.json")
}

/// The exact directory and every intended byte are retained before copying.
/// An interruption may leave only a subset of those immutable files; neither
/// an extra file nor a changed existing file is adopted during continuation.
fn verify_prepared_material(installation: &Path, sequence: u32) -> Result<SelectedMaterial> {
    let material: SelectedMaterial =
        decode_record(&read_record(installation, &material_intent_name(sequence))?)?;
    let (root, receipt, raw) = root_at(installation)?.ok_or(REFUSED)?;
    require(
        material.schema == MATERIAL_SCHEMA
            && material.sequence == sequence
            && (1..=1024).contains(&sequence)
            && material.installation_id == receipt.installation_id
            && material.engine_id == receipt.engine_id
            && material.feature_profile_sha256 == receipt.feature_profile_sha256
            && material.root_receipt_sha256 == digest(&raw)
            && material.parent_material_sha256
                == if sequence == 1 {
                    digest(&raw)
                } else {
                    digest(&read_record(
                        installation,
                        &format!("generation-feature-{:06}-binding.json", sequence - 1),
                    )?)
                }
            && !material.files.is_empty()
            && material.files.len() <= 128,
    )?;
    material.configuration.validate()?;
    let child = fs::open_child(
        &root,
        &material.leaf(),
        libc::O_RDONLY | libc::O_DIRECTORY,
        REFUSED,
    )?;
    let child_now = DirectoryIdentity::observe(&child)?;
    require(material.directory.matches(child_now.clone()))?;
    require(
        fs::file_names(&child, REFUSED)?
            == if material.renewal_receipt_sha256.is_some() {
                BTreeSet::from(["files".into(), "input".into(), "output".into()])
            } else {
                BTreeSet::from(["files".into()])
            },
    )?;
    let files = fs::open_child(&child, "files", libc::O_RDONLY | libc::O_DIRECTORY, REFUSED)?;
    let files_now = DirectoryIdentity::observe(&files)?;
    require(material.files_directory.matches(files_now.clone()))?;
    for name in fs::file_names(&files, REFUSED)? {
        require(material.files.get(&name) == Some(&fingerprint(&read_file(&files, &name)?)))?;
    }
    if material.renewal_receipt_sha256.is_some() {
        renewal::verify_preparation_at(installation, sequence)?;
    } else {
        require(
            material.activation_sha256.as_ref()
                == Some(&digest(&read_record(installation, ACTIVATION)?)),
        )?;
    }
    fs::require_directory_binding(
        &installation.join(ROOT).join(material.leaf()),
        &child,
        REFUSED,
    )?;
    fs::require_directory_binding(&material.directory(installation), &files, REFUSED)?;
    require(
        DirectoryIdentity::observe(&child)? == child_now
            && DirectoryIdentity::observe(&files)? == files_now,
    )?;
    Ok(material)
}

fn complete_material_files(
    state: &mut LockedMaintenance,
    installation: &Path,
    material: &SelectedMaterial,
    values: &BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    require(
        material.files
            == values
                .iter()
                .map(|(name, bytes)| (name.clone(), fingerprint(bytes)))
                .collect(),
    )?;
    store_once(
        state,
        installation,
        &material_intent_name(material.sequence),
        &encoded(material)?,
    )?;
    let retained = verify_prepared_material(installation, material.sequence)?;
    require(encoded(&retained)? == encoded(material)?)?;
    let files = fs::directory(&material.directory(installation), REFUSED)?;
    complete_immutable_files(
        &material.directory(installation),
        &files,
        &material.files,
        values,
    )?;
    store_once(state, installation, &material.record(), &encoded(material)?)?;
    verify_generations(state.inspection(), installation)
}

fn complete_immutable_files(
    path: &Path,
    files: &File,
    expected: &BTreeMap<String, Fingerprint>,
    values: &BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    let before = DirectoryIdentity::observe(files)?;
    let existing = fs::file_names(files, REFUSED)?;
    require(
        *expected
            == values
                .iter()
                .map(|(name, bytes)| (name.clone(), fingerprint(bytes)))
                .collect(),
    )?;
    require(existing.is_subset(&expected.keys().cloned().collect()))?;
    fs::require_directory_binding(path, files, REFUSED)?;
    // Validate the entire retained subset before writing even one missing file.
    for name in &existing {
        require(read_file(files, name)? == *values.get(name).ok_or(REFUSED)?)?;
    }
    for (name, bytes) in values {
        if !existing.contains(name) {
            write_exclusive(files, name, bytes, 0o444)?;
        }
    }
    fs::require_directory_binding(path, files, REFUSED)?;
    require(DirectoryIdentity::observe(files)? == before)
}

fn stage_material(
    state: &mut LockedMaintenance,
    installation: &Path,
    selection: &Selection,
    configuration: Configuration,
    imports: BTreeMap<String, Fingerprint>,
    values: &BTreeMap<String, Vec<u8>>,
    activation_sha256: Option<String>,
) -> Result<SelectedMaterial> {
    state.inspection().require_path_binding(installation)?;
    let previous = materials(installation)?;
    let (root, receipt, raw) = root_at(installation)?.ok_or(REFUSED)?;
    let root_now = DirectoryIdentity::observe(&root)?;
    let sequence = u32::try_from(previous.len() + 1).map_err(|_| REFUSED)?;
    require(sequence <= 1024 && selection.profile_sha256()? == receipt.feature_profile_sha256)?;
    let parent_material_sha256 = previous
        .last()
        .map_or_else(|| digest(&raw), |(_, raw)| digest(raw));
    let name = format!("{sequence:06}");
    let prepared = optional_record(installation, &material_intent_name(sequence))?;
    let (child, child_now, files, files_now) = if prepared.is_some() {
        let material = verify_prepared_material(installation, sequence)?;
        let child = fs::open_child(&root, &name, libc::O_RDONLY | libc::O_DIRECTORY, REFUSED)?;
        let files = fs::open_child(&child, "files", libc::O_RDONLY | libc::O_DIRECTORY, REFUSED)?;
        (child, material.directory, files, material.files_directory)
    } else {
        let child = mkdir_owned(&root, &name)?;
        let child_now = DirectoryIdentity::observe(&child)?;
        let files = mkdir_owned(&child, "files")?;
        let files_now = DirectoryIdentity::observe(&files)?;
        (child, child_now, files, files_now)
    };
    let material = SelectedMaterial {
        schema: MATERIAL_SCHEMA.into(),
        sequence,
        installation_id: receipt.installation_id,
        engine_id: receipt.engine_id,
        feature_profile_sha256: receipt.feature_profile_sha256,
        root_receipt_sha256: digest(&raw),
        parent_material_sha256,
        activation_sha256,
        renewal_receipt_sha256: None,
        caller_binding_rotation: None,
        configuration,
        imports,
        directory: child_now.clone(),
        files_directory: files_now.clone(),
        files: values
            .iter()
            .map(|(name, bytes)| (name.clone(), fingerprint(bytes)))
            .collect(),
    };
    require(
        DirectoryIdentity::observe(&root)? == root_now
            && child_now.matches(DirectoryIdentity::observe(&child)?)
            && files_now.matches(DirectoryIdentity::observe(&files)?),
    )?;
    fs::require_directory_binding(&installation.join(ROOT), &root, REFUSED)?;
    fs::require_directory_binding(&installation.join(ROOT).join(&name), &child, REFUSED)?;
    fs::require_directory_binding(&material.directory(installation), &files, REFUSED)?;
    complete_material_files(state, installation, &material, values)?;
    Ok(material)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn generation_names_are_fixed_and_projection_never_uses_baseline_credentials() {
        let path = Path::new("/installation");
        assert!(!path
            .join(ROOT)
            .starts_with(path.join("application-generation")));
        assert!(!path.join(ROOT).starts_with(path.join("secrets")));
        let parent = tempfile::tempdir().unwrap();
        std::fs::set_permissions(
            parent.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let held = fs::directory(parent.path(), REFUSED).unwrap();
        let child = mkdir_owned(&held, "000001").unwrap();
        assert!(mkdir_owned(&held, "000001").is_err());
        assert!(mkdir_owned(&held, "../other").is_err());
        write_exclusive(&child, "feature_one", b"first", 0o444).unwrap();
        assert!(write_exclusive(&child, "feature_one", b"second", 0o444).is_err());
        assert_eq!(read_file(&child, "feature_one").unwrap(), b"first");
    }

    #[test]
    fn interrupted_material_copy_preserves_prior_inode_and_refuses_changed_or_extra_files() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let held = fs::directory(root.path(), REFUSED).unwrap();
        let values: BTreeMap<String, Vec<u8>> = BTreeMap::from([
            ("feature_first".into(), b"first".to_vec()),
            ("feature_second".into(), b"second".to_vec()),
        ]);
        let expected = values
            .iter()
            .map(|(name, bytes)| (name.clone(), fingerprint(bytes)))
            .collect();
        write_exclusive(&held, "feature_first", b"first", 0o444).unwrap();
        let inode = std::fs::metadata(root.path().join("feature_first"))
            .unwrap()
            .ino();
        complete_immutable_files(root.path(), &held, &expected, &values).unwrap();
        assert_eq!(
            std::fs::metadata(root.path().join("feature_first"))
                .unwrap()
                .ino(),
            inode
        );
        assert_eq!(read_file(&held, "feature_second").unwrap(), b"second");
        complete_immutable_files(root.path(), &held, &expected, &values).unwrap();
        write_exclusive(&held, "feature_unclaimed", b"extra", 0o444).unwrap();
        assert!(complete_immutable_files(root.path(), &held, &expected, &values).is_err());
        std::fs::remove_file(root.path().join("feature_unclaimed")).unwrap();
        std::fs::set_permissions(
            root.path().join("feature_first"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        std::fs::write(root.path().join("feature_first"), b"changed").unwrap();
        std::fs::set_permissions(
            root.path().join("feature_first"),
            std::fs::Permissions::from_mode(0o444),
        )
        .unwrap();
        assert!(complete_immutable_files(root.path(), &held, &expected, &values).is_err());
        assert_eq!(read_file(&held, "feature_first").unwrap(), b"changed");
    }
}
