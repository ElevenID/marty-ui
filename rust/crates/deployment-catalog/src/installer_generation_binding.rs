//! Immutable application credential selection. Originals and orphan producer evidence remain intact.
#![cfg(target_os = "linux")]
use crate::installer_state::{InstallerState, Phase};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fs::File,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::{Component, Path, PathBuf},
};
type Result<T> = std::result::Result<T, String>;
type CandidateFiles = BTreeMap<String, Vec<u8>>;
const REFUSED: &str = "application generation binding refused; preserve installation for recovery";
const ROOT: &str = "application-generation";
const RECORD: &str = "application-generation.json";
const PENDING: &str = "application-generation-pending.json";
const IMPORTED_PROVENANCE: &str = "application-generation-imported-provenance.json";
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GenerationSource {
    Original,
    Candidate,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GenerationFile {
    pub source: GenerationSource,
    pub sha256: String,
    pub size: u64,
    pub source_mode: u32,
    pub mode: u32,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GenerationBinding {
    pub schema: String,
    pub installation_id: String,
    pub engine_id: String,
    // Imported AWS certificates precede network creation. Only the canonical
    // successful application Compose receipt can observe that runtime network.
    pub network_id: Option<String>,
    pub generation_receipt_sha256: String,
    pub files: BTreeMap<String, GenerationFile>,
    pub activated: bool,
    pub root_retired: bool,
    pub installation_ready: bool,
}
fn require(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}
fn hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn safe_name(name: &str) -> Result<()> {
    require(
        !name.is_empty()
            && name.len() <= 128
            && name.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-' || b == b'.'
            })
            && name != "."
            && name != "..",
    )
}
fn open(parent: &File, name: &str, flags: i32, mode: u32) -> Result<File> {
    safe_name(name)?;
    let name = CString::new(name).map_err(|_| REFUSED)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            mode,
        )
    };
    require(fd >= 0)?;
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn directory(path: &Path) -> Result<File> {
    require(
        path.is_absolute()
            && path != Path::new("/")
            && path
                .components()
                .all(|c| matches!(c, Component::RootDir | Component::Normal(_))),
    )?;
    let fd = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    require(fd >= 0)?;
    let mut held = unsafe { File::from_raw_fd(fd) };
    for component in path.components() {
        let Component::Normal(part) = component else {
            continue;
        };
        let m = held.metadata().map_err(|_| REFUSED)?;
        require(
            m.is_dir()
                && [0, unsafe { libc::geteuid() }].contains(&m.uid())
                && (m.mode() & 0o022 == 0 || (m.uid() == 0 && m.mode() & 0o1000 != 0)),
        )?;
        let name = CString::new(part.as_encoded_bytes()).map_err(|_| REFUSED)?;
        let next = unsafe {
            libc::openat(
                held.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY
                    | libc::O_DIRECTORY
                    | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC
                    | libc::O_NONBLOCK,
            )
        };
        require(next >= 0)?;
        held = unsafe { File::from_raw_fd(next) };
    }
    private(&held)?;
    Ok(held)
}
fn private(file: &File) -> Result<()> {
    let m = file.metadata().map_err(|_| REFUSED)?;
    require(m.is_dir() && m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o7777 == 0o700)
}
fn child(parent: &File, name: &str) -> Result<File> {
    let file = open(parent, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
    private(&file)?;
    Ok(file)
}
fn names(dir: &File) -> Result<BTreeSet<String>> {
    std::fs::read_dir(format!("/proc/self/fd/{}", dir.as_raw_fd()))
        .map_err(|_| REFUSED)?
        .map(|entry| {
            entry
                .map_err(|_| REFUSED.into())
                .and_then(|e| e.file_name().into_string().map_err(|_| REFUSED.into()))
        })
        .collect()
}
fn binding(path: &Path, held: &File) -> Result<()> {
    let a = directory(path)?.metadata().map_err(|_| REFUSED)?;
    let b = held.metadata().map_err(|_| REFUSED)?;
    require(
        (a.dev(), a.ino(), a.uid(), a.gid(), a.mode())
            == (b.dev(), b.ino(), b.uid(), b.gid(), b.mode()),
    )
}
fn read(dir: &File, name: &str, record: bool) -> Result<(Vec<u8>, u32)> {
    let file = open(dir, name, libc::O_RDONLY, 0)?;
    let m = file.metadata().map_err(|_| REFUSED)?;
    let mode = m.mode() & 0o7777;
    require(
        m.is_file()
            && m.nlink() == 1
            && [unsafe { libc::geteuid() }, 0].contains(&m.uid())
            && m.len() <= if record { 262144 } else { 65536 },
    )?;
    require(if record {
        mode == 0o600
    } else {
        mode == 0o444 || (name == "openbao_tls_ca_cert" && mode == 0o644)
    })?;
    let mut bytes = Vec::new();
    file.take(262145)
        .read_to_end(&mut bytes)
        .map_err(|_| REFUSED)?;
    require(
        bytes.len() as u64 == m.len()
            && bytes.is_ascii()
            && !bytes.contains(&0)
            && !bytes.windows(11).any(|v| v == b"PRIVATE KEY"),
    )?;
    require(
        !bytes.is_empty()
            || (!record
                && (crate::installer_application_env::OPTIONAL_EMPTY_SECRETS.contains(&name)
                    || name == "external_oidc_client_secret")),
    )?;
    Ok((bytes, mode))
}
fn decode(path: &str) -> Result<PathBuf> {
    crate::installer_compose::config_path(&json!(path))
}
fn closure(installation: &Path, model: &serde_json::Value, root: &str) -> Result<BTreeSet<String>> {
    let mut result = BTreeSet::new();
    let base = installation.join(root);
    for service in model["services"].as_object().ok_or(REFUSED)?.values() {
        for reference in service["secrets"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or(&[])
        {
            let name = reference["source"].as_str().ok_or(REFUSED)?;
            safe_name(name)?;
            require(
                decode(model["secrets"][name]["file"].as_str().ok_or(REFUSED)?)? == base.join(name),
            )?;
            result.insert(name.into());
        }
        for mount in service["volumes"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or(&[])
        {
            if mount["type"] != "bind" {
                continue;
            }
            let path = decode(mount["source"].as_str().ok_or(REFUSED)?)?;
            if path.starts_with(&base) {
                require(path.parent() == Some(base.as_path()) && mount["read_only"] == true)?;
                let name = path.file_name().and_then(|n| n.to_str()).ok_or(REFUSED)?;
                safe_name(name)?;
                result.insert(name.into());
            } else {
                require(
                    !path.starts_with(installation.join("secrets"))
                        && !path.starts_with(installation.join(ROOT)),
                )?;
            }
        }
    }
    Ok(result)
}
impl GenerationBinding {
    pub(crate) fn imported_foundation(&self) -> bool {
        self.schema == "elevenid.installer-application-generation/v2"
    }
    pub fn secret_dir(&self, installation: &Path) -> Result<PathBuf> {
        self.validate()?;
        Ok(installation.join(ROOT))
    }
    pub fn read(&self, installation: &Path, name: &str) -> Result<Vec<u8>> {
        self.validate()?;
        let expected = self.files.get(name).ok_or(REFUSED)?;
        let dir = directory(&self.secret_dir(installation)?)?;
        let (bytes, mode) = read(&dir, name, false)?;
        require(
            mode == expected.mode
                && bytes.len() as u64 == expected.size
                && digest(&bytes) == expected.sha256,
        )?;
        Ok(bytes)
    }
    fn validate(&self) -> Result<()> {
        crate::installer_renewal_bootstrap::validate_id(&self.installation_id)?;
        require(
            (self.schema == "elevenid.installer-application-generation/v1"
                || self.imported_foundation())
                && !self.engine_id.is_empty()
                && self.engine_id.len() <= 128
                && !self.activated
                && !self.root_retired
                && !self.installation_ready
                && self.files.len() >= if self.imported_foundation() { 1 } else { 40 }
                && self.files.len() <= 128,
        )?;
        let hash = |s: &str| {
            s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        require(
            hash(&self.generation_receipt_sha256)
                && if self.imported_foundation() {
                    self.network_id.is_none()
                } else {
                    self.network_id.as_deref().is_some_and(hash)
                },
        )?;
        let renewable = crate::installer_renewal_bootstrap::current_inputs();
        for (name, file) in &self.files {
            safe_name(name)?;
            require(
                hash(&file.sha256)
                    && file.size <= 65536
                    && (file.size > 0
                        || crate::installer_application_env::OPTIONAL_EMPTY_SECRETS
                            .contains(&name.as_str())
                        || (self.imported_foundation() && name == "external_oidc_client_secret"))
                    && file.mode == 0o444
                    && (file.source_mode == 0o444
                        || (name == "openbao_tls_ca_cert" && file.source_mode == 0o644))
                    && if self.imported_foundation() {
                        file.source == GenerationSource::Original
                    } else {
                        (file.source == GenerationSource::Candidate) == renewable.contains(name)
                    },
            )?;
        }
        require(
            self.imported_foundation()
                || renewable.is_subset(&self.files.keys().cloned().collect()),
        )
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    schema: String,
    installation_id: String,
    engine_id: String,
    container_id: String,
    container_name: String,
    network_id: String,
    image: String,
    root_retired: bool,
    ingress_renewal: bool,
    candidate_validated: bool,
    activated: bool,
    candidate_sha256: BTreeMap<String, String>,
    outputs: Vec<String>,
    container_removed: bool,
    compose_receipt_sha256: String,
    job_completed_successfully: bool,
    installation_ready: bool,
}
fn candidate(installation: &Path, id: &str, engine: &str) -> Result<(Vec<u8>, CandidateFiles)> {
    let evidence = directory(&installation.join("evidence"))?;
    let bytes = read(&evidence, "generation-observation.json", true)?.0;
    let r: Receipt = serde_json::from_slice(&bytes).map_err(|_| REFUSED)?;
    require(
        r.schema == "elevenid.installer-generation-host/v2"
            && r.installation_id == id
            && r.engine_id == engine
            && hex(&r.container_id)
            && r.container_name
                == format!(
                    "marty-install-{}-installer-generation-1",
                    id.replace('-', "")
                )
            && hex(&r.network_id)
            && r.image
                .strip_prefix("ghcr.io/elevenid/marty-ui-oss/services@sha256:")
                .is_some_and(hex)
            && !r.root_retired
            && !r.ingress_renewal
            && r.candidate_validated
            && !r.activated
            && !r.container_removed
            && r.job_completed_successfully
            && hex(&r.compose_receipt_sha256)
            && !r.installation_ready,
    )?;
    let operation = read(
        &evidence,
        "compose-setup-installer-generation-result.json",
        true,
    )?
    .0;
    require(digest(&operation) == r.compose_receipt_sha256)?;
    let proof: crate::installer_compose::ComposeReceipt =
        serde_json::from_slice(&operation).map_err(|_| REFUSED)?;
    let resources = proof.resources.as_ref().ok_or(REFUSED)?;
    let helper = resources
        .containers
        .get("installer-generation")
        .ok_or(REFUSED)?;
    require(
        proof.schema == "elevenid.installer-compose-operation/v1"
            && proof.project == format!("marty-install-{}", id.replace('-', ""))
            && proof.engine_id == engine
            && proof.command_succeeded
            && proof.observation_validated
            && helper.id == r.container_id
            && helper.image == r.image
            && helper.setup
            && resources.networks.values().any(|n| n == &r.network_id)
            && proof.status.iter().any(|v| {
                v["Service"] == "installer-generation"
                    && v["State"] == "exited"
                    && v["ExitCode"] == 0
            }),
    )?;
    let transfer = directory(&installation.join("generation-transfer"))?;
    let delivered = child(&transfer, "delivered")?;
    let current_dir = directory(&installation.join("generation-inputs"))?;
    let identity_dir = directory(&installation.join("generation-identity"))?;
    let mut current = BTreeMap::new();
    let mut outputs = BTreeMap::new();
    for name in crate::installer_renewal_bootstrap::current_inputs() {
        current.insert(name.clone(), read(&current_dir, &name, false)?.0);
        outputs.insert(name.clone(), read(&delivered, &name, false)?.0);
    }
    let mut identity = BTreeMap::new();
    for name in [
        "renewal-role-id",
        "renewal-secret-id",
        "renewal-leaf-policies.json",
    ] {
        identity.insert(name.into(), read(&identity_dir, name, true)?.0);
    }
    require(names(&current_dir)? == crate::installer_renewal_bootstrap::current_inputs())?;
    require(names(&identity_dir)? == identity.keys().cloned().collect())?;
    let mut delivered_names = crate::installer_renewal_bootstrap::current_inputs();
    delivered_names.extend(["pending.json", "validated.json", "completed.json"].map(String::from));
    require(names(&delivered)? == delivered_names && r.outputs.len() == 40)?;
    let kc = read(&evidence, "keycloak-observation.json", true)?.0;
    let records = ["pending.json", "validated.json", "completed.json"]
        .into_iter()
        .map(|n| Ok((n.into(), read(&delivered, n, true)?.0)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    let hashes = crate::installer_generation::validate_records(
        &records,
        &outputs,
        &crate::installer_generation::GenerationProof {
            owner: id,
            current: &current,
            identity: &identity,
            keycloak_receipt: &kc,
        },
    )?;
    require(
        hashes == r.candidate_sha256
            && r.outputs.into_iter().collect::<BTreeSet<_>>() == outputs.keys().cloned().collect(),
    )?;
    let secrets = directory(&installation.join("secrets"))?;
    for (name, bytes) in current {
        require(read(&secrets, &name, false)?.0 == bytes)?;
    }
    Ok((bytes, outputs))
}

struct Provenance {
    bytes: Vec<u8>,
    candidates: CandidateFiles,
    network_id: Option<String>,
    foundation: Option<crate::installer_foundation::Selection>,
}

fn provenance(installation: &Path, id: &str, engine: &str) -> Result<Provenance> {
    let id_uuid = uuid::Uuid::parse_str(id).map_err(|_| REFUSED)?;
    if let Some((selected, foundation)) =
        crate::installer_foundation::record(installation, id_uuid)?
    {
        let bytes = serde_json::to_vec(&json!({"schema":"elevenid.installer-imported-generation-provenance/v1",
            "installation_id":id,"engine_id":engine,"project":format!("marty-install-{}",id.replace('-',"")),
            "network_id":null,"network_observed":false,"foundation_selection_sha256":digest(&selected),
            "cloud_resources_created":false,"iam_isolation_observed":false,"installation_ready":false})).map_err(|_| REFUSED)?;
        Ok(Provenance {
            bytes,
            candidates: BTreeMap::new(),
            network_id: None,
            foundation: Some(foundation),
        })
    } else {
        let (bytes, candidates) = candidate(installation, id, engine)?;
        let record: Receipt = serde_json::from_slice(&bytes).map_err(|_| REFUSED)?;
        Ok(Provenance {
            bytes,
            candidates,
            network_id: Some(record.network_id),
            foundation: None,
        })
    }
}

pub fn stage(
    installation: &Path,
    state: &mut InstallerState,
    model: &serde_json::Value,
    network_id: Option<&str>,
) -> Result<GenerationBinding> {
    state.require_live_phase(Phase::Provisioning)?;
    let id = state.journal().installation_id().to_string();
    let engine = state.journal().runtime().ok_or(REFUSED)?.engine_id.clone();
    let wanted = closure(installation, model, "secrets")?;
    let proof = provenance(installation, &id, &engine)?;
    require(
        proof.network_id.as_deref() == network_id
            && model["name"] == format!("marty-install-{}", id.replace('-', "")),
    )?;
    let source = directory(&installation.join("secrets"))?;
    let mut values = BTreeMap::new();
    let mut files = BTreeMap::new();
    for name in wanted {
        let (bytes, source_mode, category) = if let Some(v) = proof.candidates.get(&name) {
            (v.clone(), 0o444, GenerationSource::Candidate)
        } else {
            let (v, m) = read(&source, &name, false)?;
            (v, m, GenerationSource::Original)
        };
        files.insert(
            name.clone(),
            GenerationFile {
                source: category,
                sha256: digest(&bytes),
                size: bytes.len() as u64,
                source_mode,
                mode: 0o444,
            },
        );
        values.insert(name, bytes);
    }
    if let Some(foundation) = &proof.foundation {
        foundation.verify_imported(&values)?;
        state.write_evidence(IMPORTED_PROVENANCE, &proof.bytes)?;
    }
    let result = GenerationBinding {
        schema: if proof.foundation.is_some() {
            "elevenid.installer-application-generation/v2"
        } else {
            "elevenid.installer-application-generation/v1"
        }
        .into(),
        installation_id: id,
        engine_id: engine,
        network_id: proof.network_id,
        generation_receipt_sha256: digest(&proof.bytes),
        files,
        activated: false,
        root_retired: false,
        installation_ready: false,
    };
    result.validate()?;
    let encoded = serde_json::to_vec(&result).map_err(|_| REFUSED)?;
    state.write_evidence(PENDING, &encoded)?;
    state.create_private_directory(ROOT)?;
    let output = directory(&installation.join(ROOT))?;
    require(names(&output)?.is_empty())?;
    for (name, bytes) in &values {
        let mut file = open(
            &output,
            name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )?;
        output.sync_all().map_err(|_| REFUSED)?;
        file.write_all(bytes).map_err(|_| REFUSED)?;
        require(unsafe { libc::fchmod(file.as_raw_fd(), 0o444) } == 0)?;
        file.sync_all()
            .and_then(|_| output.sync_all())
            .map_err(|_| REFUSED)?;
    }
    binding(&installation.join("secrets"), &source)?;
    binding(&installation.join(ROOT), &output)?;
    verify(installation, &result)?;
    state.require_live_phase(Phase::Provisioning)?;
    state.write_evidence(RECORD, &encoded)?;
    Ok(result)
}
pub fn verify(installation: &Path, b: &GenerationBinding) -> Result<()> {
    b.validate()?;
    let proof = provenance(installation, &b.installation_id, &b.engine_id)?;
    require(
        digest(&proof.bytes) == b.generation_receipt_sha256
            && proof.network_id == b.network_id
            && b.imported_foundation() == proof.foundation.is_some(),
    )?;
    if proof.foundation.is_some() {
        let evidence = directory(&installation.join("evidence"))?;
        require(read(&evidence, IMPORTED_PROVENANCE, true)?.0 == proof.bytes)?;
    }
    let output = directory(&installation.join(ROOT))?;
    let source = directory(&installation.join("secrets"))?;
    require(names(&output)? == b.files.keys().cloned().collect())?;
    let mut originals = BTreeMap::new();
    for (name, item) in &b.files {
        let (bytes, mode) = match item.source {
            GenerationSource::Candidate => {
                (proof.candidates.get(name).ok_or(REFUSED)?.clone(), 0o444)
            }
            GenerationSource::Original => read(&source, name, false)?,
        };
        require(
            mode == item.source_mode
                && bytes.len() as u64 == item.size
                && digest(&bytes) == item.sha256
                && b.read(installation, name)? == bytes,
        )?;
        originals.insert(name.clone(), bytes);
    }
    if let Some(foundation) = &proof.foundation {
        foundation.verify_imported(&originals)?;
    }
    Ok(())
}

#[derive(Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Selection {
    schema: String,
    installation_id: String,
    engine_id: String,
    binding_sha256: String,
    native_model_sha256: String,
    env_sha256: String,
    activated: bool,
    installation_ready: bool,
}
fn selection_bytes(installation: &Path, b: &GenerationBinding) -> Result<Selection> {
    let evidence = directory(&installation.join("evidence"))?;
    let binding = read(&evidence, RECORD, true)?.0;
    require(serde_json::from_slice::<GenerationBinding>(&binding).map_err(|_| REFUSED)? == *b)?;
    let model_bytes = read(&evidence, "application-native-model.json", true)?.0;
    let model: serde_json::Value = serde_json::from_slice(&model_bytes).map_err(|_| REFUSED)?;
    let env = read(&evidence, "application.env", true)?.0;
    let source = read(&evidence, "application-source.env", true)?.0;
    require(crate::installer_application_env::select_generation(&source, installation)? == env)?;
    verify_model(installation, b, &model, b.network_id.as_deref())?;
    Ok(Selection {
        schema: "elevenid.installer-application-generation-selection/v2".into(),
        installation_id: b.installation_id.clone(),
        engine_id: b.engine_id.clone(),
        binding_sha256: digest(&binding),
        native_model_sha256: digest(&model_bytes),
        env_sha256: digest(&env),
        activated: false,
        installation_ready: false,
    })
}
pub fn publish_selection(
    installation: &Path,
    state: &mut InstallerState,
    b: &GenerationBinding,
) -> Result<()> {
    state.require_live_phase(Phase::Provisioning)?;
    verify(installation, b)?;
    state.write_evidence(
        "application-generation-selection.json",
        &serde_json::to_vec(&selection_bytes(installation, b)?).map_err(|_| REFUSED)?,
    )
}
pub fn load_verified(
    installation: &Path,
    id: &str,
    engine: &str,
) -> Result<Option<GenerationBinding>> {
    let evidence = directory(&installation.join("evidence"))?;
    let mut present = Vec::new();
    for path in [
        installation.join(ROOT),
        installation.join("evidence").join(PENDING),
        installation.join("evidence").join(RECORD),
        installation.join("evidence/application-generation-selection.json"),
    ] {
        present.push(match std::fs::symlink_metadata(path) {
            Ok(_) => true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(_) => return Err(REFUSED.into()),
        });
    }
    if present.iter().all(|v| !*v) {
        return Ok(None);
    }
    require(present.iter().all(|v| *v))?;
    let bytes = read(&evidence, RECORD, true)?.0;
    require(bytes == read(&evidence, PENDING, true)?.0)?;
    let value: GenerationBinding = serde_json::from_slice(&bytes).map_err(|_| REFUSED)?;
    require(value.installation_id == id && value.engine_id == engine)?;
    verify(installation, &value)?;
    let selection: Selection =
        serde_json::from_slice(&read(&evidence, "application-generation-selection.json", true)?.0)
            .map_err(|_| REFUSED)?;
    require(
        serde_json::to_value(selection).map_err(|_| REFUSED)?
            == serde_json::to_value(selection_bytes(installation, &value)?).map_err(|_| REFUSED)?,
    )?;
    Ok(Some(value))
}
/// Read-only check of the native Compose result. Runtime configuration is
/// selected by a dotenv path; no service definition is rewritten in Rust.
pub fn verify_model(
    installation: &Path,
    b: &GenerationBinding,
    model: &serde_json::Value,
    network_id: Option<&str>,
) -> Result<()> {
    b.validate()?;
    require(
        network_id == b.network_id.as_deref()
            && model["name"] == format!("marty-install-{}", b.installation_id.replace('-', "")),
    )?;
    require(closure(installation, model, ROOT)? == b.files.keys().cloned().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    const ID: &str = "2e052c77-efe8-44c6-9421-9ef15fe8ee7c";
    fn fixture() -> (GenerationBinding, serde_json::Value) {
        let renewable = crate::installer_renewal_bootstrap::current_inputs();
        let mut files = BTreeMap::new();
        let mut declarations = serde_json::Map::new();
        let mut references = Vec::new();
        for name in renewable
            .iter()
            .map(String::as_str)
            .chain(["smtp_password", "operator_bootstrap_password"])
        {
            files.insert(
                name.into(),
                GenerationFile {
                    source: if renewable.contains(name) {
                        GenerationSource::Candidate
                    } else {
                        GenerationSource::Original
                    },
                    sha256: digest(b"synthetic"),
                    size: 9,
                    source_mode: 0o444,
                    mode: 0o444,
                },
            );
            declarations.insert(
                name.into(),
                json!({"file":format!("/private/install $$path/application-generation/{name}")}),
            );
            references.push(json!({"source":name,"target":format!("/run/secrets/{name}")}));
        }
        let model = json!({"name":format!("marty-install-{}", ID.replace('-', "")),
            "services":{"synthetic":{"secrets":references}},"secrets":declarations});
        (
            GenerationBinding {
                schema: "elevenid.installer-application-generation/v1".into(),
                installation_id: ID.into(),
                engine_id: "engine".into(),
                network_id: Some("a".repeat(64)),
                generation_receipt_sha256: "b".repeat(64),
                files,
                activated: false,
                root_retired: false,
                installation_ready: false,
            },
            model,
        )
    }
    #[test]
    fn native_secret_selection_rejects_external_or_original_paths_without_rewriting() {
        let root = Path::new("/private/install $path");
        let (binding, model) = fixture();
        verify_model(root, &binding, &model, Some(&"a".repeat(64))).unwrap();
        let saved = model.clone();
        assert_eq!(model, saved);
        for path in [
            "/etc/shadow",
            "/private/install $$path/secrets/smtp_password",
        ] {
            let mut changed = model.clone();
            changed["secrets"]["smtp_password"]["file"] = json!(path);
            assert!(verify_model(root, &binding, &changed, binding.network_id.as_deref()).is_err());
        }
        assert!(verify_model(root, &binding, &model, Some(&"c".repeat(64))).is_err());
    }
    #[test]
    fn closed_binding_forbids_source_downgrade_missing_candidates_and_ready_claims() {
        let (binding, _) = fixture();
        binding.validate().unwrap();
        let renewable = crate::installer_renewal_bootstrap::current_inputs()
            .into_iter()
            .next()
            .unwrap();
        let mut bad = binding.clone();
        bad.files.get_mut(&renewable).unwrap().source = GenerationSource::Original;
        assert!(bad.validate().is_err());
        let mut bad = binding.clone();
        bad.files.remove(&renewable);
        assert!(bad.validate().is_err());
        let mut bad = binding.clone();
        bad.files.get_mut(&renewable).unwrap().size = 0;
        assert!(bad.validate().is_err());
        let mut empty_optional = binding.clone();
        empty_optional.files.get_mut("smtp_password").unwrap().size = 0;
        assert!(empty_optional.validate().is_ok());
        let mut bad = binding.clone();
        bad.activated = true;
        assert!(bad.validate().is_err());
        let mut bad = binding.clone();
        bad.files.get_mut("smtp_password").unwrap().mode = 0o644;
        assert!(bad.validate().is_err());
        let mut json = serde_json::to_value(&binding).unwrap();
        json["unknown"] = json!(true);
        assert!(serde_json::from_value::<GenerationBinding>(json).is_err());
    }
    fn private(path: &Path) {
        std::fs::create_dir(path).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    #[test]
    fn snapshot_reads_refuse_hash_drift_links_and_partial_binding() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        private(&temp.path().join("evidence"));
        assert!(load_verified(temp.path(), ID, "engine").unwrap().is_none());
        private(&temp.path().join(ROOT));
        assert!(load_verified(temp.path(), ID, "engine").is_err());
        let (binding, _) = fixture();
        let path = temp.path().join(ROOT).join("smtp_password");
        std::fs::write(&path, b"synthetic").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();
        assert_eq!(
            binding.read(temp.path(), "smtp_password").unwrap(),
            b"synthetic"
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&path, b"different").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();
        assert!(binding.read(temp.path(), "smtp_password").is_err());
        std::fs::remove_file(&path).unwrap();
        symlink(temp.path().join("missing"), &path).unwrap();
        assert!(binding.read(temp.path(), "smtp_password").is_err());
        let alias = temp.path().join("alias");
        symlink(temp.path().join(ROOT), &alias).unwrap();
        assert!(directory(&alias).is_err());
    }
}
