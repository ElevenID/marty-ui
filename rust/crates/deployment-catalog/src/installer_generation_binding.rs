//! Immutable application credential selection. Originals and orphan producer evidence remain intact.
#![cfg(target_os = "linux")]
use crate::{
    installer_generation_maintenance::{GenerationMaterial, GenerationPlan, PlanSource},
    installer_state::{InstallerState, Phase},
};
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
#[path = "installer_generation_successor.rs"]
mod successor;
pub(crate) use successor::{publish_current, stage_successor};
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) successor: Option<SuccessorBinding>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct SuccessorBinding {
    pub sequence: u64,
    #[serde(
        default,
        skip_serializing_if = "crate::installer_generation_maintenance::attempt::is_zero"
    )]
    pub attempt: u64,
    #[serde(
        default,
        skip_serializing_if = "crate::installer_generation_maintenance::attempt::is_zero"
    )]
    pub parent_attempt: u64,
    pub parent_binding_sha256: String,
    pub native_operation: String,
}

/// In-memory evidence for the immediately preceding generation in one forward
/// lineage walk. It has no public constructor or persisted representation;
/// candidate validation cannot recursively reload an already checked ancestor.
pub(crate) struct VerifiedGeneration {
    binding: GenerationBinding,
    public_metadata: Option<crate::installer_public_ingress::PublicIngressMetadata>,
    managed_metadata: Option<crate::installer_ingress_outputs::IngressMetadata>,
}
impl VerifiedGeneration {
    pub(crate) fn binding(&self) -> &GenerationBinding {
        &self.binding
    }
    pub(crate) fn public_metadata(
        &self,
    ) -> Option<&crate::installer_public_ingress::PublicIngressMetadata> {
        self.public_metadata.as_ref()
    }
    pub(crate) fn managed_metadata(
        &self,
    ) -> Option<&crate::installer_ingress_outputs::IngressMetadata> {
        self.managed_metadata.as_ref()
    }
    pub(crate) fn material(&self) -> Result<GenerationMaterial> {
        match (&self.public_metadata, &self.managed_metadata) {
            (Some(value), None) => Ok(GenerationMaterial::Public(Box::new(value.clone()))),
            (None, Some(value)) => Ok(GenerationMaterial::Managed(Box::new(value.clone()))),
            _ => Err(REFUSED.into()),
        }
    }
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
    pub(crate) fn sequence(&self) -> u64 {
        self.successor.as_ref().map_or(0, |value| value.sequence)
    }
    pub(crate) fn attempt(&self) -> u64 {
        self.successor.as_ref().map_or(0, |value| value.attempt)
    }
    pub(crate) fn attempt_id(&self) -> crate::installer_generation_maintenance::attempt::Attempt {
        crate::installer_generation_maintenance::attempt::Attempt::new(
            self.sequence(),
            self.attempt(),
        )
    }
    pub(crate) fn parent_attempt(&self) -> u64 {
        self.successor
            .as_ref()
            .map_or(0, |value| value.parent_attempt)
    }
    pub(crate) fn record_name(&self, kind: &str) -> String {
        self.attempt_id().record(kind)
    }
    pub(crate) fn sha256(&self) -> Result<String> {
        self.validate()?;
        Ok(digest(&serde_json::to_vec(self).map_err(|_| REFUSED)?))
    }
    pub(crate) fn selected_evidence(
        &self,
        installation: &Path,
    ) -> Result<BTreeMap<String, String>> {
        self.validate()?;
        if self.successor.is_none() {
            return Ok(BTreeMap::new());
        }
        crate::installer_generation_maintenance::selected_evidence(installation, self)
    }
    pub(crate) fn imported_foundation(&self) -> bool {
        self.schema == "elevenid.installer-application-generation/v2"
    }
    pub(crate) fn managed_ingress(&self) -> bool {
        self.schema == "elevenid.installer-application-generation/v3"
    }
    pub(crate) fn public_ingress(&self) -> bool {
        self.schema == "elevenid.installer-application-generation/v4"
    }
    /// Public metadata of the exact leaf selected for this generation. The
    /// original installer receipt remains immutable and is not the renewed
    /// certificate's provenance.
    pub(crate) fn ingress_metadata(
        &self,
        installation: &Path,
    ) -> Result<Option<crate::installer_ingress_outputs::IngressMetadata>> {
        self.validate()?;
        if !self.managed_ingress() {
            return Ok(None);
        }
        if self.successor.is_some() {
            let verified = load_verified_attempt(installation, self.sequence(), self.attempt())?;
            require(verified.binding == *self)?;
            return Ok(verified.managed_metadata);
        }
        let evidence = directory(&installation.join("evidence"))?;
        let bytes = read(&evidence, "generation-observation.json", true)?.0;
        require(digest(&bytes) == self.generation_receipt_sha256)?;
        let record: Receipt = serde_json::from_slice(&bytes).map_err(|_| REFUSED)?;
        require(
            record.schema == "elevenid.installer-generation-host/v3"
                && record.ingress_renewal
                && record.installation_id == self.installation_id
                && record.engine_id == self.engine_id,
        )?;
        let metadata = record.ingress.ok_or(REFUSED)?;
        require(
            metadata.ca_pem_sha256
                == self
                    .files
                    .get("installer_ingress_ca_cert")
                    .ok_or(REFUSED)?
                    .sha256
                && metadata.certificate_pem_sha256
                    == self
                        .files
                        .get("installer_ingress_tls_cert")
                        .ok_or(REFUSED)?
                        .sha256,
        )?;
        self.read(installation, "installer_ingress_ca_cert")?;
        self.read(installation, "installer_ingress_tls_cert")?;
        Ok(Some(metadata))
    }
    /// Public ACME provenance is validated independently of the private CA
    /// branch. No CA file or caller-supplied production trust is synthesized.
    pub(crate) fn public_ingress_metadata(
        &self,
        installation: &Path,
    ) -> Result<Option<crate::installer_public_ingress::PublicIngressMetadata>> {
        self.validate()?;
        if !self.public_ingress() {
            return Ok(None);
        }
        if self.attempt() > 0 {
            let verified = load_verified_attempt(installation, self.sequence(), self.attempt())?;
            require(verified.binding == *self)?;
            return Ok(verified.public_metadata);
        }
        let (bytes, outputs, plan) = candidate_at(
            installation,
            &self.installation_id,
            &self.engine_id,
            self.successor.as_ref(),
        )?;
        public_metadata_from_candidate(
            installation,
            self,
            &bytes,
            &outputs,
            plan.as_ref().and_then(GenerationPlan::public),
        )
    }
    pub fn secret_dir(&self, installation: &Path) -> Result<PathBuf> {
        self.validate()?;
        if let Some(successor) = &self.successor {
            Ok(installation.join("application-generations").join(format!(
                "{:020}-{}",
                successor.sequence,
                self.sha256()?
            )))
        } else {
            Ok(installation.join(ROOT))
        }
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
        if let Some(successor) = &self.successor {
            require(
                (self.public_ingress() || self.managed_ingress())
                    && successor.sequence > 0
                    && (successor.sequence > 1 || successor.parent_attempt == 0)
                    && hex(&successor.parent_binding_sha256)
                    && regex::Regex::new(&format!(
                        r"\A{}-wait-[0-9]{{6}}\z",
                        self.attempt_id().operation_prefix()
                    ))
                    .map_err(|_| REFUSED)?
                    .is_match(&successor.native_operation),
            )?;
        }
        require(
            (self.schema == "elevenid.installer-application-generation/v1"
                || self.imported_foundation()
                || self.managed_ingress()
                || self.public_ingress())
                && !self.engine_id.is_empty()
                && self.engine_id.len() <= 128
                && !self.activated
                && !self.root_retired
                && !self.installation_ready
                && self.files.len()
                    >= if self.imported_foundation() {
                        1
                    } else if self.managed_ingress() {
                        43
                    } else if self.public_ingress() {
                        42
                    } else {
                        40
                    }
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
        let renewable = if self.public_ingress() {
            require(!self.files.contains_key("installer_ingress_ca_cert"))?;
            crate::installer_renewal_bootstrap::public_inputs()
        } else {
            crate::installer_renewal_bootstrap::inventory(self.managed_ingress())
        };
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
    #[serde(default)]
    ingress: Option<crate::installer_ingress_outputs::IngressMetadata>,
    #[serde(default)]
    public_ingress: Option<crate::installer_public_ingress::PublicIngressMetadata>,
    #[serde(default)]
    managed_renewal_plan_sha256: Option<String>,
    candidate_validated: bool,
    activated: bool,
    candidate_sha256: BTreeMap<String, String>,
    outputs: Vec<String>,
    container_removed: bool,
    compose_receipt_sha256: String,
    job_completed_successfully: bool,
    installation_ready: bool,
}
type CandidateProvenance = (Vec<u8>, CandidateFiles, Option<GenerationPlan>);
fn candidate(installation: &Path, id: &str, engine: &str) -> Result<CandidateProvenance> {
    candidate_at(installation, id, engine, None)
}
fn candidate_at(
    installation: &Path,
    id: &str,
    engine: &str,
    successor: Option<&SuccessorBinding>,
) -> Result<CandidateProvenance> {
    let parent = successor
        .map(|next| {
            load_verified_attempt(
                installation,
                next.sequence.checked_sub(1).ok_or(REFUSED)?,
                next.parent_attempt,
            )
        })
        .transpose()?;
    candidate_with_parent(installation, id, engine, successor, parent.as_ref())
}

fn candidate_with_parent(
    installation: &Path,
    id: &str,
    engine: &str,
    successor: Option<&SuccessorBinding>,
    parent: Option<&VerifiedGeneration>,
) -> Result<CandidateProvenance> {
    require(successor.is_some() == parent.is_some())?;
    if let (Some(next), Some(parent)) = (successor, parent) {
        require(
            parent.binding.sequence().checked_add(1) == Some(next.sequence)
                && parent.binding.attempt() == next.parent_attempt
                && parent.binding.sha256()? == next.parent_binding_sha256
                && parent.binding.installation_id == id
                && parent.binding.engine_id == engine,
        )?;
    }
    #[cfg(test)]
    candidate_visits::record(successor.map_or(0, |next| next.sequence));
    let evidence = directory(&installation.join("evidence"))?;
    let record_name = successor.map_or_else(
        || "generation-observation.json".into(),
        |v| {
            crate::installer_generation_maintenance::attempt::Attempt::new(v.sequence, v.attempt)
                .record("candidate")
        },
    );
    let bytes = read(&evidence, &record_name, true)?.0;
    let r: Receipt = serde_json::from_slice(&bytes).map_err(|_| REFUSED)?;
    let managed_successor = r.schema == "elevenid.installer-generation-host/v5";
    let managed_ingress = r.schema == "elevenid.installer-generation-host/v3" || managed_successor;
    let public_ingress = r.schema == "elevenid.installer-generation-host/v4";
    require(
        (successor.is_none() || public_ingress || managed_successor)
            && (!managed_successor || successor.is_some())
            && r.managed_renewal_plan_sha256.is_some() == managed_successor,
    )?;
    let inventory = if public_ingress {
        crate::installer_renewal_bootstrap::public_inputs()
    } else {
        crate::installer_renewal_bootstrap::inventory(managed_ingress)
    };
    require(
        !names(&evidence)?.contains(crate::installer_hosting::RECORD)
            || managed_ingress
            || public_ingress,
    )?;
    require(
        (r.schema == "elevenid.installer-generation-host/v2" || managed_ingress || public_ingress)
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
            && r.ingress_renewal == (managed_ingress || public_ingress)
            && r.ingress.is_some() == managed_ingress
            && r.public_ingress.is_some() == public_ingress
            && r.candidate_validated
            && !r.activated
            && !r.container_removed
            && r.job_completed_successfully
            && hex(&r.compose_receipt_sha256)
            && !r.installation_ready,
    )?;
    let plan = if let Some(next) = successor {
        let scope = crate::installer_generation_maintenance::attempt::Attempt::new(
            next.sequence,
            next.attempt,
        );
        let (source, expected) = if public_ingress {
            (
                PlanSource::Public,
                r.public_ingress
                    .as_ref()
                    .ok_or(REFUSED)?
                    .plan_sha256
                    .as_str(),
            )
        } else {
            require(managed_successor)?;
            (
                PlanSource::Managed,
                r.managed_renewal_plan_sha256.as_deref().ok_or(REFUSED)?,
            )
        };
        Some(GenerationPlan::load(installation, scope, source, expected)?)
    } else {
        r.public_ingress
            .as_ref()
            .map(|metadata| {
                let bytes = read(
                    &evidence,
                    crate::installer_public_ingress::PUBLIC_INGRESS_PLAN_RECORD,
                    true,
                )?
                .0;
                let plan = crate::installer_public_ingress::PublicIngressPlan::parse_authenticated(
                    &bytes,
                    &metadata.plan_sha256,
                )?;
                require(
                    plan.installation_id() == id
                        && plan.record_name()
                            == crate::installer_public_ingress::PUBLIC_INGRESS_PLAN_RECORD,
                )?;
                Ok::<_, String>(GenerationPlan::Public(Box::new(plan)))
            })
            .transpose()?
    };
    let operation_name = successor.map_or_else(
        || "compose-setup-installer-generation-result.json".into(),
        |v| format!("generation-compose-{}-result.json", v.native_operation),
    );
    let operation = read(&evidence, &operation_name, true)?.0;
    if let Some(next) = successor {
        require(
            read(
                &evidence,
                &crate::installer_generation_maintenance::attempt::Attempt::new(
                    next.sequence,
                    next.attempt,
                )
                .record("helper"),
                true,
            )?
            .0 == operation,
        )?;
        crate::installer_generation_maintenance::require_producer_journal_at(
            installation,
            crate::installer_generation_maintenance::attempt::Attempt::new(
                next.sequence,
                next.attempt,
            ),
            &r.container_id,
            &next.native_operation,
        )?;
    }
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
    if public_ingress || successor.is_some() {
        require(
            proof.operation
                == successor.map_or("setup-installer-generation", |v| {
                    v.native_operation.as_str()
                })
                && proof.client_exit_code == Some(0)
                && proof.failure_class.is_none()
                && !proof.installation_ready
                && helper
                    .setup_execution
                    .as_ref()
                    .is_some_and(|execution| execution.completed_without_restart)
                && proof.status.iter().any(|row| {
                    row["Service"] == "installer-generation"
                        && row["ID"] == helper.id
                        && row["State"] == "exited"
                        && row["ExitCode"] == 0
                }),
        )?;
    }
    let work = successor.map(|v| {
        crate::installer_generation_maintenance::attempt::Attempt::new(v.sequence, v.attempt)
            .work(installation)
    });
    let transfer = directory(&work.as_ref().map_or_else(
        || installation.join("generation-transfer"),
        |v| v.join("transfer"),
    ))?;
    let delivered = child(&transfer, "delivered")?;
    let current_dir = directory(&work.as_ref().map_or_else(
        || installation.join("generation-inputs"),
        |v| v.join("current"),
    ))?;
    let identity_dir = directory(&work.as_ref().map_or_else(
        || installation.join("generation-identity"),
        |v| v.join("identity"),
    ))?;
    let mut current = BTreeMap::new();
    let mut outputs = BTreeMap::new();
    let current_names = names(&current_dir)?;
    require(
        crate::installer_renewal_bootstrap::source_inventory(&current_names, public_ingress)?
            == inventory,
    )?;
    for name in &current_names {
        current.insert(name.clone(), read(&current_dir, name, false)?.0);
    }
    for name in &inventory {
        outputs.insert(name.clone(), read(&delivered, name, false)?.0);
    }
    let mut identity = BTreeMap::new();
    for name in [
        "renewal-role-id",
        "renewal-secret-id",
        "renewal-leaf-policies.json",
    ] {
        identity.insert(name.into(), read(&identity_dir, name, true)?.0);
    }
    require(names(&current_dir)? == current_names)?;
    require(names(&identity_dir)? == identity.keys().cloned().collect())?;
    let mut delivered_names = inventory.clone();
    delivered_names.extend(["pending.json", "validated.json", "completed.json"].map(String::from));
    require(names(&delivered)? == delivered_names && r.outputs.len() == inventory.len())?;
    let kc = read(&evidence, "keycloak-observation.json", true)?.0;
    let records = ["pending.json", "validated.json", "completed.json"]
        .into_iter()
        .map(|n| Ok((n.into(), read(&delivered, n, true)?.0)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    let generation_proof = crate::installer_generation::GenerationProof {
        owner: id,
        current: &current,
        identity: &identity,
        keycloak_receipt: &kc,
        public_ingress_plan: plan.as_ref().and_then(GenerationPlan::public),
    };
    let hashes = if let Some(managed) = plan.as_ref().and_then(GenerationPlan::managed) {
        crate::installer_generation::validate_managed_records(
            &records,
            &outputs,
            &generation_proof,
            managed,
        )?
    } else {
        crate::installer_generation::validate_records(&records, &outputs, &generation_proof)?
    };
    require(crate::installer_generation::recorded_ingress(&records)? == r.ingress)?;
    require(crate::installer_generation::recorded_public_ingress(&records)? == r.public_ingress)?;
    require(
        hashes == r.candidate_sha256
            && r.outputs.into_iter().collect::<BTreeSet<_>>() == outputs.keys().cloned().collect(),
    )?;
    if let Some(next) = successor {
        let parent = parent.ok_or(REFUSED)?;
        require(
            parent.binding.sha256()? == next.parent_binding_sha256
                && parent.binding.installation_id == id
                && parent.binding.engine_id == engine,
        )?;
        plan.as_ref()
            .ok_or(REFUSED)?
            .require_verified_parent(installation, parent)?;
        for (name, bytes) in current {
            require(parent.binding.read(installation, &name)? == bytes)?;
        }
    } else {
        let secrets = directory(&installation.join("secrets"))?;
        for (name, bytes) in current {
            require(read(&secrets, &name, false)?.0 == bytes)?;
        }
    }
    Ok((bytes, outputs, plan))
}

struct Provenance {
    bytes: Vec<u8>,
    candidates: CandidateFiles,
    network_id: Option<String>,
    foundation: Option<crate::installer_foundation::Selection>,
    public_plan: Option<crate::installer_public_ingress::PublicIngressPlan>,
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
            public_plan: None,
        })
    } else {
        let (bytes, candidates, plan) = candidate(installation, id, engine)?;
        let public_plan = match plan {
            Some(GenerationPlan::Public(value)) => Some(*value),
            None => None,
            Some(GenerationPlan::Managed(_)) => return Err(REFUSED.into()),
        };
        let record: Receipt = serde_json::from_slice(&bytes).map_err(|_| REFUSED)?;
        Ok(Provenance {
            bytes,
            candidates,
            network_id: Some(record.network_id),
            foundation: None,
            public_plan,
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
    if let Some(plan) = &proof.public_plan {
        state.with_inspection(|view| {
            view.require_path_binding(installation)?;
            plan.require_saved(view)
        })?;
        plan.validate_current_certificate()?;
    }
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
        } else if proof.public_plan.is_some() {
            "elevenid.installer-application-generation/v4"
        } else if proof.candidates.keys().cloned().collect::<BTreeSet<_>>()
            == crate::installer_renewal_bootstrap::managed_inputs()
        {
            "elevenid.installer-application-generation/v3"
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
        successor: None,
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
fn public_metadata_from_candidate(
    installation: &Path,
    binding: &GenerationBinding,
    bytes: &[u8],
    outputs: &CandidateFiles,
    plan: Option<&crate::installer_public_ingress::PublicIngressPlan>,
) -> Result<Option<crate::installer_public_ingress::PublicIngressMetadata>> {
    if !binding.public_ingress() {
        require(plan.is_none())?;
        return Ok(None);
    }
    require(digest(bytes) == binding.generation_receipt_sha256)?;
    let plan = plan.ok_or(REFUSED)?;
    require(
        outputs
            .get("installer_ingress_tls_cert")
            .is_some_and(|value| value == plan.fullchain_pem().as_bytes()),
    )?;
    let record: Receipt = serde_json::from_slice(bytes).map_err(|_| REFUSED)?;
    let metadata = record.public_ingress.ok_or(REFUSED)?;
    for name in crate::installer_public_ingress::PUBLIC_OUTPUTS {
        require(binding.read(installation, name)? == *outputs.get(name).ok_or(REFUSED)?)?;
    }
    Ok(Some(metadata))
}

fn managed_metadata_from_candidate(
    installation: &Path,
    binding: &GenerationBinding,
    bytes: &[u8],
    outputs: &CandidateFiles,
) -> Result<Option<crate::installer_ingress_outputs::IngressMetadata>> {
    if !binding.managed_ingress() {
        return Ok(None);
    }
    require(digest(bytes) == binding.generation_receipt_sha256)?;
    let record: Receipt = serde_json::from_slice(bytes).map_err(|_| REFUSED)?;
    require(
        record.schema
            == if binding.successor.is_some() {
                "elevenid.installer-generation-host/v5"
            } else {
                "elevenid.installer-generation-host/v3"
            },
    )?;
    let metadata = record.ingress.ok_or(REFUSED)?;
    for name in &crate::installer_ingress_provision::OUTPUTS[..3] {
        require(binding.read(installation, name)? == *outputs.get(*name).ok_or(REFUSED)?)?;
    }
    Ok(Some(metadata))
}

/// Validate exactly one generation against its already verified predecessor.
/// Every candidate/42-file proof remains checked; there are no recursive loads.
fn verify_one(
    installation: &Path,
    b: GenerationBinding,
    parent: Option<&VerifiedGeneration>,
) -> Result<VerifiedGeneration> {
    if b.successor.is_none() || b.attempt() == 0 {
        return verify_one_attempt(installation, b, parent);
    }
    let parent = parent.ok_or(REFUSED)?;
    let incoming = verify_predecessor_attempts(installation, parent, b.sequence(), b.attempt())?;
    let admitted = verify_one_attempt(installation, b, Some(parent))?;
    crate::installer_generation_maintenance::require_attempt_incoming(
        installation,
        &admitted.binding,
        &parent.binding,
        incoming.as_ref(),
    )?;
    Ok(admitted)
}

/// Completed attempts carry real producer output. An unused predecessor has
/// no binding or helper authority, and is admitted only by its immutable
/// absence/expiry/native proof. Keep one incoming baseline during this walk.
fn verify_predecessor_attempts(
    installation: &Path,
    parent: &VerifiedGeneration,
    sequence: u64,
    attempts: u64,
) -> Result<Option<crate::installer_generation_maintenance::GenerationRecoveryBaseline>> {
    use crate::installer_generation_maintenance::{self as maintenance, attempt::Attempt};
    require(parent.binding.sequence().checked_add(1) == Some(sequence))?;
    let evidence = directory(&installation.join("evidence"))?;
    let retained = names(&evidence)?;
    let mut incoming = None;
    for number in 0..attempts {
        let scope = Attempt::new(sequence, number);
        incoming = Some(if retained.contains(&scope.record("binding")) {
            let candidate = read_attempt(&evidence, sequence, number)?;
            require(candidate.parent_attempt() == parent.binding.attempt())?;
            let admitted = verify_one_attempt(installation, candidate, Some(parent))?;
            maintenance::require_attempt_incoming(
                installation,
                &admitted.binding,
                &parent.binding,
                incoming.as_ref(),
            )?;
            maintenance::completed_predecessor(
                installation,
                &parent.binding,
                &admitted.binding,
                &admitted.material()?,
            )?
        } else {
            maintenance::unused_predecessor(installation, parent, scope, incoming.as_ref())?
        });
    }
    binding(&installation.join("evidence"), &evidence)?;
    Ok(incoming)
}

/// Authenticate a positive attempt's incoming native capability without
/// requiring that attempt to have created a helper or produced a binding.
pub(crate) fn load_preparation_baseline(
    installation: &Path,
    scope: crate::installer_generation_maintenance::attempt::Attempt,
    parent_attempt: u64,
) -> Result<crate::installer_generation_maintenance::GenerationRecoveryBaseline> {
    require(scope.sequence > 0 && scope.number > 0)?;
    let root = directory(installation)?;
    let parent = load_verified_attempt(installation, scope.sequence - 1, parent_attempt)?;
    let result = verify_predecessor_attempts(installation, &parent, scope.sequence, scope.number)?
        .ok_or(REFUSED)?;
    binding(installation, &root)?;
    Ok(result)
}

fn verify_one_attempt(
    installation: &Path,
    b: GenerationBinding,
    parent: Option<&VerifiedGeneration>,
) -> Result<VerifiedGeneration> {
    b.validate()?;
    if let Some(successor) = &b.successor {
        let parent = parent.ok_or(REFUSED)?;
        let (bytes, candidates, plan) = candidate_with_parent(
            installation,
            &b.installation_id,
            &b.engine_id,
            Some(successor),
            Some(parent),
        )?;
        require(
            parent.binding.sha256()? == successor.parent_binding_sha256
                && plan.is_some()
                && digest(&bytes) == b.generation_receipt_sha256
                && b.network_id == parent.binding.network_id
                && b.files.keys().collect::<BTreeSet<_>>() == parent.binding.files.keys().collect(),
        )?;
        let output = directory(&b.secret_dir(installation)?)?;
        require(names(&output)? == b.files.keys().cloned().collect())?;
        for (name, item) in &b.files {
            let bytes = if item.source == GenerationSource::Candidate {
                candidates.get(name).cloned().ok_or(REFUSED)?
            } else {
                parent.binding.read(installation, name)?
            };
            require(
                bytes.len() as u64 == item.size
                    && digest(&bytes) == item.sha256
                    && b.read(installation, name)? == bytes,
            )?;
        }
        let public_metadata = public_metadata_from_candidate(
            installation,
            &b,
            &bytes,
            &candidates,
            plan.as_ref().and_then(GenerationPlan::public),
        )?;
        let managed_metadata =
            managed_metadata_from_candidate(installation, &b, &bytes, &candidates)?;
        return Ok(VerifiedGeneration {
            binding: b,
            public_metadata,
            managed_metadata,
        });
    }
    require(parent.is_none())?;
    let proof = provenance(installation, &b.installation_id, &b.engine_id)?;
    require(
        digest(&proof.bytes) == b.generation_receipt_sha256
            && proof.network_id == b.network_id
            && b.imported_foundation() == proof.foundation.is_some()
            && b.public_ingress() == proof.public_plan.is_some(),
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
    let public_metadata = public_metadata_from_candidate(
        installation,
        &b,
        &proof.bytes,
        &proof.candidates,
        proof.public_plan.as_ref(),
    )?;
    let managed_metadata =
        managed_metadata_from_candidate(installation, &b, &proof.bytes, &proof.candidates)?;
    Ok(VerifiedGeneration {
        binding: b,
        public_metadata,
        managed_metadata,
    })
}

pub fn verify(installation: &Path, b: &GenerationBinding) -> Result<()> {
    b.validate()?;
    let root = directory(installation)?;
    let evidence = child(&root, "evidence")?;
    let parent = b
        .successor
        .as_ref()
        .map(|next| {
            load_verified_attempt(
                installation,
                next.sequence.checked_sub(1).ok_or(REFUSED)?,
                next.parent_attempt,
            )
        })
        .transpose()?;
    verify_one(installation, b.clone(), parent.as_ref())?;
    binding(installation, &root)?;
    binding(&installation.join("evidence"), &evidence)
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
pub fn load_initial_verified(
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
pub fn load_verified(
    installation: &Path,
    id: &str,
    engine: &str,
) -> Result<Option<GenerationBinding>> {
    if let Some(selected) =
        crate::installer_generation_maintenance::load_selected_binding(installation, id, engine)?
    {
        return Ok(Some(selected));
    }
    load_initial_verified(installation, id, engine)
}
#[cfg(test)]
fn load_sequence(installation: &Path, sequence: u64) -> Result<GenerationBinding> {
    load_attempt(installation, sequence, 0)
}
pub(crate) fn load_attempt(
    installation: &Path,
    sequence: u64,
    attempt: u64,
) -> Result<GenerationBinding> {
    Ok(load_verified_attempt(installation, sequence, attempt)?.binding)
}

/// Read canonical binding syntax for an already verified lineage's model
/// comparison. This deliberately grants no candidate or activation authority.
pub(crate) fn read_recorded_attempt(
    installation: &Path,
    sequence: u64,
    attempt: u64,
) -> Result<GenerationBinding> {
    let root = directory(installation)?;
    let evidence = child(&root, "evidence")?;
    let value = read_attempt(&evidence, sequence, attempt)?;
    binding(installation, &root)?;
    binding(&installation.join("evidence"), &evidence)?;
    Ok(value)
}

fn read_attempt(evidence: &File, sequence: u64, attempt: u64) -> Result<GenerationBinding> {
    require(sequence > 0 || attempt == 0)?;
    let name = if sequence == 0 {
        RECORD.into()
    } else {
        crate::installer_generation_maintenance::attempt::Attempt::new(sequence, attempt)
            .record("binding")
    };
    let bytes = read(evidence, &name, true)?.0;
    let binding: GenerationBinding =
        serde_json::from_value(crate::installer_json::decode(&bytes).map_err(|_| REFUSED)?)
            .map_err(|_| REFUSED)?;
    require(
        binding.sequence() == sequence
            && binding.attempt() == attempt
            && serde_json::to_vec(&binding).map_err(|_| REFUSED)? == bytes,
    )?;
    binding.validate()?;
    Ok(binding)
}

pub(crate) fn load_verified_attempt(
    installation: &Path,
    sequence: u64,
    attempt: u64,
) -> Result<VerifiedGeneration> {
    let root = directory(installation)?;
    let evidence = child(&root, "evidence")?;
    // Pin exact chosen attempts while walking backward, then authenticate the
    // contiguous lineage once forward. This remains linear and never adopts
    // another in-flight attempt merely because its sequence number matches.
    let mut chain = Vec::new();
    let mut current = sequence;
    let mut chosen = attempt;
    loop {
        let next = read_attempt(&evidence, current, chosen)?;
        chain.push((current, chosen));
        if current == 0 {
            break;
        }
        chosen = next.parent_attempt();
        current -= 1;
    }
    let mut previous = None;
    for (current, chosen) in chain.into_iter().rev() {
        let next = read_attempt(&evidence, current, chosen)?;
        previous = Some(verify_one(installation, next, previous.as_ref())?);
    }
    binding(installation, &root)?;
    binding(&installation.join("evidence"), &evidence)?;
    previous.ok_or_else(|| REFUSED.into())
}

#[cfg(test)]
mod candidate_visits {
    use std::cell::RefCell;
    thread_local! {
        static VISITS: RefCell<Option<Vec<u64>>> = const { RefCell::new(None) };
    }
    pub(super) fn record(sequence: u64) {
        VISITS.with(|value| {
            if let Some(visits) = value.borrow_mut().as_mut() {
                visits.push(sequence);
            }
        });
    }
    pub(super) fn measure<T>(operation: impl FnOnce() -> T) -> (T, Vec<u64>) {
        VISITS.with(|value| assert!(value.replace(Some(Vec::new())).is_none()));
        let result = operation();
        let visits = VISITS.with(|value| value.replace(None).unwrap());
        (result, visits)
    }
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
    if b.successor.is_some() {
        return crate::installer_generation_maintenance::require_runtime_model(
            installation,
            b,
            model,
        );
    }
    let directory = b.secret_dir(installation)?;
    let relative = directory
        .strip_prefix(installation)
        .map_err(|_| REFUSED)?
        .to_str()
        .ok_or(REFUSED)?;
    require(closure(installation, model, relative)? == b.files.keys().cloned().collect())
}

#[cfg(test)]
#[path = "installer_generation_lineage_tests.rs"]
mod lineage_tests;

#[cfg(test)]
pub(crate) fn test_lineage_fixture(last: u64) -> (tempfile::TempDir, Vec<GenerationBinding>) {
    let fixture = lineage_tests::Fixture::new(last);
    (fixture.root, fixture.generations)
}
#[cfg(test)]
pub(crate) fn test_lineage_visits<T>(operation: impl FnOnce() -> T) -> (T, Vec<u64>) {
    candidate_visits::measure(operation)
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
                successor: None,
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
    fn managed_generation_requires_all_three_ingress_files_from_renewed_candidate() {
        let (mut binding, _) = fixture();
        binding.schema = "elevenid.installer-application-generation/v3".into();
        assert!(binding.validate().is_err());
        for name in crate::installer_ingress_provision::OUTPUTS[..3]
            .iter()
            .copied()
        {
            binding.files.insert(
                name.into(),
                GenerationFile {
                    source: GenerationSource::Candidate,
                    sha256: digest(b"synthetic"),
                    size: 9,
                    source_mode: 0o444,
                    mode: 0o444,
                },
            );
        }
        binding.validate().unwrap();
        for name in crate::installer_ingress_provision::OUTPUTS[..3]
            .iter()
            .copied()
        {
            let mut changed = binding.clone();
            changed.files.get_mut(name).unwrap().source = GenerationSource::Original;
            assert!(changed.validate().is_err());
            let mut missing = binding.clone();
            missing.files.remove(name);
            assert!(missing.validate().is_err());
        }
        binding.schema = "elevenid.installer-application-generation/v1".into();
        assert!(binding.validate().is_err());
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
    #[test]
    fn public_generation_requires_exact_public_candidates_without_private_ca() {
        let (mut binding, _) = fixture();
        binding.schema = "elevenid.installer-application-generation/v4".into();
        assert!(binding.validate().is_err());
        for name in crate::installer_public_ingress::PUBLIC_OUTPUTS {
            binding.files.insert(
                name.into(),
                GenerationFile {
                    source: GenerationSource::Candidate,
                    sha256: digest(b"public fixture"),
                    size: 14,
                    source_mode: 0o444,
                    mode: 0o444,
                },
            );
        }
        binding.validate().unwrap();
        assert!(binding.public_ingress());
        assert!(!binding.managed_ingress());
        for name in crate::installer_public_ingress::PUBLIC_OUTPUTS {
            let mut bad = binding.clone();
            bad.files.remove(name);
            assert!(bad.validate().is_err());
            let mut bad = binding.clone();
            bad.files.get_mut(name).unwrap().source = GenerationSource::Original;
            assert!(bad.validate().is_err());
        }
        let mut bad = binding.clone();
        bad.files.insert(
            "installer_ingress_ca_cert".into(),
            GenerationFile {
                source: GenerationSource::Original,
                sha256: digest(b"synthetic"),
                size: 9,
                source_mode: 0o444,
                mode: 0o444,
            },
        );
        assert!(bad.validate().is_err());
        binding.schema = "elevenid.installer-application-generation/v3".into();
        assert!(binding.validate().is_err());
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

#[cfg(test)]
#[path = "installer_generation_managed_lineage_tests.rs"]
mod managed_lineage_tests;
