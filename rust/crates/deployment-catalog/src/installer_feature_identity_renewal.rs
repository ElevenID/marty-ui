//! Preparation/admission only. The feature generation owner creates the private
//! directories and journals create-without-start, exact helper ID, start and
//! wait. No function here starts, retries, adopts or replaces a credential job.
use super::*;
use crate::installer_state::{Journal, LockedMaintenance};
use std::path::PathBuf;

const GENERATIONS: &str = "feature-profile-generations";
const INPUT_NAMES: [&str; 5] = [
    "ca.crt",
    "feature-identities.json",
    "role-id",
    "secret-id",
    "workload-ca.crt",
];

pub(crate) fn renewal_input_names() -> BTreeSet<String> {
    INPUT_NAMES.into_iter().map(str::to_string).collect()
}

/// These readers grant no mutation authority. The `_at` implementation is for
/// Compose admission under its caller's existing installation lock; acquiring a
/// second flock there would deadlock the native generation transaction.
trait RenewalInspection {
    fn journal(&self) -> &Journal;
    fn read_evidence(&self, name: &str) -> Result<Vec<u8>>;
    fn profile(&self) -> Result<crate::installer_features::Selection>;
    fn credentials(&self, names: &BTreeSet<String>) -> Result<BTreeMap<String, Vec<u8>>>;
    fn require_path_binding(&self, installation: &Path) -> Result<()>;
    fn require_unchanged(&self) -> Result<()>;
}

impl RenewalInspection for LockedInspection {
    fn journal(&self) -> &Journal {
        LockedInspection::journal(self)
    }
    fn read_evidence(&self, name: &str) -> Result<Vec<u8>> {
        LockedInspection::read_evidence(self, name)
    }
    fn profile(&self) -> Result<crate::installer_features::Selection> {
        crate::installer_features::load(self)?.ok_or_else(|| REFUSED.into())
    }
    fn credentials(&self, names: &BTreeSet<String>) -> Result<BTreeMap<String, Vec<u8>>> {
        crate::installer_feature_credentials::verify(self, names)
    }
    fn require_path_binding(&self, installation: &Path) -> Result<()> {
        LockedInspection::require_path_binding(self, installation)
    }
    fn require_unchanged(&self) -> Result<()> {
        LockedInspection::require_unchanged(self)
    }
}

struct InspectionAt {
    installation: PathBuf,
    journal: Journal,
    directory: File,
    evidence: File,
    directory_identity: DirectoryIdentity,
    evidence_identity: DirectoryIdentity,
}

impl InspectionAt {
    fn open(installation: &Path) -> Result<Self> {
        let journal = InstallerState::inspect(installation)?;
        let directory = fs::directory(installation, REFUSED)?;
        let evidence = fs::open_child(
            &directory,
            "evidence",
            libc::O_RDONLY | libc::O_DIRECTORY,
            REFUSED,
        )?;
        let directory_identity = DirectoryIdentity::observe(&directory)?;
        let evidence_identity = DirectoryIdentity::observe(&evidence)?;
        require(evidence_identity.uid == unsafe { libc::geteuid() })?;
        let inspection = Self {
            installation: installation.into(),
            journal,
            directory,
            evidence,
            directory_identity,
            evidence_identity,
        };
        inspection.require_unchanged()?;
        Ok(inspection)
    }
}

impl RenewalInspection for InspectionAt {
    fn journal(&self) -> &Journal {
        &self.journal
    }
    fn read_evidence(&self, name: &str) -> Result<Vec<u8>> {
        self.require_unchanged()?;
        let bytes = read_bound_file(&self.evidence, name, 0o600, 4 * 1024 * 1024)?;
        self.require_unchanged()?;
        Ok(bytes)
    }
    fn profile(&self) -> Result<crate::installer_features::Selection> {
        self.require_unchanged()?;
        let profile = crate::installer_features::at(&self.installation)?.ok_or(REFUSED)?;
        self.require_unchanged()?;
        Ok(profile)
    }
    fn credentials(&self, names: &BTreeSet<String>) -> Result<BTreeMap<String, Vec<u8>>> {
        self.require_unchanged()?;
        let values = crate::installer_feature_credentials::verify_at(&self.installation, names)?;
        self.require_unchanged()?;
        Ok(values)
    }
    fn require_path_binding(&self, installation: &Path) -> Result<()> {
        require(installation == self.installation)?;
        self.require_unchanged()
    }
    fn require_unchanged(&self) -> Result<()> {
        fs::require_directory_binding(&self.installation, &self.directory, REFUSED)?;
        fs::require_directory_binding(
            &self.installation.join("evidence"),
            &self.evidence,
            REFUSED,
        )?;
        require(
            DirectoryIdentity::observe(&self.directory)? == self.directory_identity
                && DirectoryIdentity::observe(&self.evidence)? == self.evidence_identity
                && InstallerState::inspect(&self.installation)? == self.journal,
        )
    }
}

fn read_bound_file(directory: &File, name: &str, mode: u32, maximum: u64) -> Result<Vec<u8>> {
    require(
        (1..=128).contains(&name.len())
            && name.as_bytes()[0].is_ascii_lowercase()
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
            && (1..=4 * 1024 * 1024).contains(&maximum),
    )?;
    let file = fs::open_child(directory, name, libc::O_RDONLY | libc::O_NONBLOCK, REFUSED)?;
    let before = file.metadata().map_err(|_| REFUSED)?;
    require(
        before.is_file()
            && before.nlink() == 1
            && before.uid() == unsafe { libc::geteuid() }
            && before.mode() & 0o7777 == mode
            && (1..=maximum).contains(&before.len()),
    )?;
    let mut bytes = Vec::new();
    (&file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| REFUSED)?;
    let snapshot = |m: &std::fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.uid(),
            m.gid(),
            m.mode(),
            m.nlink(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    };
    let current = fs::open_child(directory, name, libc::O_PATH, REFUSED)?;
    require(
        bytes.len() as u64 == before.len()
            && snapshot(&file.metadata().map_err(|_| REFUSED)?) == snapshot(&before)
            && snapshot(&current.metadata().map_err(|_| REFUSED)?) == snapshot(&before),
    )?;
    Ok(bytes)
}

/// Do not derive Debug/Serialize: this contains the scoped owner credentials.
pub(crate) struct RenewalMaterial {
    pub(crate) selection: Selection,
    pub(crate) input_files: BTreeMap<String, Vec<u8>>,
    pub(crate) initial_receipt_sha256: String,
    image: String,
}

/// The generation owner retains this alongside its own authenticated directory
/// receipt before the helper is created. It is not independent path authority.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RenewalOutputBinding {
    sequence: u32,
    directory: DirectoryIdentity,
}

pub(crate) struct HeldRenewalOutput {
    directory: File,
    path: PathBuf,
    current: DirectoryIdentity,
    binding: RenewalOutputBinding,
}
impl HeldRenewalOutput {
    pub(crate) fn binding(&self) -> RenewalOutputBinding {
        self.binding.clone()
    }
}

#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RenewalReceipt {
    schema: String,
    installation_id: String,
    feature_profile_sha256: String,
    sequence: u32,
    initial_identity_receipt_sha256: String,
    create_receipt_sha256: String,
    start_receipt_sha256: String,
    completed_receipt_sha256: String,
    engine_id: String,
    container_id: String,
    image: String,
    output_directory: RenewalOutputBinding,
    files: BTreeMap<String, String>,
    qualified_at_unix_seconds: u64,
    governed_authority_created: bool,
    generation_activated: bool,
    installation_ready: bool,
}

fn generation(installation: &Path, sequence: u32) -> Result<PathBuf> {
    require(installation.is_absolute() && (1..=999_999).contains(&sequence))?;
    Ok(installation
        .join(GENERATIONS)
        .join(format!("{sequence:06}")))
}

/// The caller supplies the public OpenBao CA from its authenticated current
/// OpenBao custody. This module does not discover a host, provider, or user path.
/// Only the original manifest's AppRole credentials are staged; root.token is
/// not read and no expiring login token is retained as future renewal authority.
pub(crate) fn prepare_renewal(
    view: &LockedInspection,
    installation: &Path,
    openbao_ca: &[u8],
) -> Result<RenewalMaterial> {
    prepare_with(view, installation, openbao_ca)
}

fn prepare_with(
    view: &impl RenewalInspection,
    installation: &Path,
    openbao_ca: &[u8],
) -> Result<RenewalMaterial> {
    view.require_path_binding(installation)?;
    let profile = view.profile()?;
    let mut selection = profile.identity_selection()?.ok_or(REFUSED)?;
    require(selection.operation == Operation::Provision)?;
    let raw = view.read_evidence(RECORD)?;
    let original = verify_retained_records(
        view.journal(),
        installation,
        &selection,
        &raw,
        &view.read_evidence("compose-setup-installer-feature-identities-result.json")?,
    )?;
    let values = view.credentials(&profile.credential_names()?)?;
    let role_id = values.get(features::RENEWAL_ROLE_ID).ok_or(REFUSED)?;
    let secret_id = values.get(features::RENEWAL_SECRET_ID).ok_or(REFUSED)?;
    for credential in [role_id, secret_id] {
        require(
            (20..=1024).contains(&credential.len()) && credential.iter().all(u8::is_ascii_graphic),
        )?;
    }
    require(role_id != secret_id)?;
    require(openbao_ca.len() <= 65_536 && !openbao_ca.windows(11).any(|v| v == b"PRIVATE KEY"))?;
    let ca = Certificate::from_pem(openbao_ca).map_err(|_| REFUSED)?;
    require(
        ca.tbs_certificate
            .get::<BasicConstraints>()
            .map_err(|_| REFUSED)?
            .is_some_and(|(_, v)| v.ca),
    )?;
    selection.operation = Operation::Renew;
    selection.validate().map_err(|_| REFUSED)?;
    let input_files = BTreeMap::from([
        ("ca.crt".into(), openbao_ca.to_vec()),
        (
            "feature-identities.json".into(),
            serde_json::to_vec(&selection).map_err(|_| REFUSED)?,
        ),
        ("role-id".into(), role_id.clone()),
        ("secret-id".into(), secret_id.clone()),
        (
            "workload-ca.crt".into(),
            values.get(features::WORKLOAD_CA).ok_or(REFUSED)?.clone(),
        ),
    ]);
    view.require_unchanged()?;
    Ok(RenewalMaterial {
        selection,
        input_files,
        initial_receipt_sha256: crate::installer_release::sha256(&raw),
        image: original.image,
    })
}

/// The supplied FD must be the generation owner's original exclusive output
/// child, captured at creation. A reopened named directory is not a substitute.
pub(crate) fn hold_renewal_output(
    installation: &Path,
    sequence: u32,
    owned_output: File,
) -> Result<HeldRenewalOutput> {
    let path = generation(installation, sequence)?.join("output");
    fs::require_directory_binding(&path, &owned_output, REFUSED)?;
    let current = DirectoryIdentity::observe(&owned_output)?;
    require(
        current.uid == unsafe { libc::geteuid() }
            && fs::file_names(&owned_output, REFUSED)?.is_empty(),
    )?;
    Ok(HeldRenewalOutput {
        directory: owned_output,
        path,
        current: current.clone(),
        binding: RenewalOutputBinding {
            sequence,
            directory: current,
        },
    })
}

/// Resume inspection under the generation owner's verified immutable receipt.
/// This opens no new path and performs no helper execution or output mutation.
pub(crate) fn resume_renewal_output(
    installation: &Path,
    retained: &RenewalOutputBinding,
    owned_output: File,
) -> Result<HeldRenewalOutput> {
    let path = generation(installation, retained.sequence)?.join("output");
    fs::require_directory_binding(&path, &owned_output, REFUSED)?;
    let current = DirectoryIdentity::observe(&owned_output)?;
    require(
        current.uid == unsafe { libc::geteuid() } && retained.directory.matches(current.clone()),
    )?;
    Ok(HeldRenewalOutput {
        directory: owned_output,
        path,
        current,
        binding: retained.clone(),
    })
}

fn empty(value: Option<&serde_json::Value>) -> bool {
    value.is_none_or(|v| {
        v.is_null()
            || v.as_array().is_some_and(Vec::is_empty)
            || v.as_object().is_some_and(serde_json::Map::is_empty)
    })
}

/// The ordinary native Compose admission remains mandatory. This additional
/// check closes the feature producer's exact renewal inputs and output mounts.
pub(crate) fn validate_renewal_model(
    material: &RenewalMaterial,
    model: &serde_json::Value,
    installation: &Path,
    sequence: u32,
    services_image: &str,
) -> Result<()> {
    require(material.selection.operation == Operation::Renew && material.image == services_image)?;
    material.selection.validate().map_err(|_| REFUSED)?;
    let child = generation(installation, sequence)?;
    let service = &model["services"][SERVICE];
    require(
        service.is_object()
            && service["image"] == services_image
            && service["entrypoint"] == json!(["/usr/local/bin/marty-feature-identity-bootstrap"])
            && empty(service.get("command"))
            && service["profiles"] == json!(["setup"])
            && service["user"] == "0:0"
            && service["read_only"] == true
            && service["restart"] == "no"
            && service["cap_drop"] == json!(["ALL"])
            && empty(service.get("cap_add"))
            && service.get("privileged").is_none_or(|v| v == false)
            && empty(service.get("ports"))
            && empty(service.get("secrets"))
            && empty(service.get("configs"))
            && empty(service.get("devices"))
            && service
                .get("network_mode")
                .is_none_or(serde_json::Value::is_null)
            && service["labels"]["com.elevenid.installer.id"] == material.selection.installation_id
            && service["labels"]["com.elevenid.installer.phase"] == "setup",
    )?;
    require(
        service["environment"]
            == json!({
                "BAO_ADDR":"https://openbao:8200", "BAO_CACERT":"/input/ca.crt",
                "FEATURE_IDENTITY_RENEWAL_ROLE_ID_FILE":"/input/role-id",
                "FEATURE_IDENTITY_RENEWAL_SECRET_ID_FILE":"/input/secret-id",
                "FEATURE_IDENTITY_SELECTION_FILE":"/input/feature-identities.json",
                "FEATURE_IDENTITY_WORKLOAD_CA_FILE":"/input/workload-ca.crt",
                "FEATURE_IDENTITY_OUTPUT_DIR":"/output",
            }),
    )?;
    let mounts = service["volumes"].as_array().ok_or(REFUSED)?;
    require(mounts.len() == INPUT_NAMES.len() + 1)?;
    let expected: BTreeMap<_, _> = INPUT_NAMES
        .into_iter()
        .map(|name| {
            (
                format!("/input/{name}"),
                (child.join("input").join(name), true),
            )
        })
        .chain([("/output".into(), (child.join("output"), false))])
        .collect();
    let mut seen = BTreeSet::new();
    for mount in mounts {
        let target = mount["target"].as_str().ok_or(REFUSED)?;
        let (source, readonly) = expected.get(target).ok_or(REFUSED)?;
        let readonly_matches = if *readonly {
            mount["read_only"] == true
        } else {
            mount.get("read_only").is_none_or(|value| value == false)
        };
        require(
            seen.insert(target)
                && mount["type"] == "bind"
                && mount["source"].as_str() == source.to_str()
                && readonly_matches
                && mount["bind"]
                    .get("create_host_path")
                    .is_none_or(|v| v == false),
        )?;
    }
    require(
        material
            .input_files
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            == INPUT_NAMES.into_iter().collect(),
    )
}

/// The generation owner must first authenticate its preparation receipt, which
/// pins these five inputs and their directories. The CA is not discovered from
/// a provider or accepted as authority merely because it exists at this path.
fn staged_material(
    view: &impl RenewalInspection,
    installation: &Path,
    sequence: u32,
) -> Result<RenewalMaterial> {
    view.require_path_binding(installation)?;
    let child_path = generation(installation, sequence)?;
    let root_path = installation.join(GENERATIONS);
    let root = fs::directory(&root_path, REFUSED)?;
    let root_identity = DirectoryIdentity::observe(&root)?;
    let child = fs::open_child(
        &root,
        &format!("{sequence:06}"),
        libc::O_RDONLY | libc::O_DIRECTORY,
        REFUSED,
    )?;
    let child_identity = DirectoryIdentity::observe(&child)?;
    let input = fs::open_child(&child, "input", libc::O_RDONLY | libc::O_DIRECTORY, REFUSED)?;
    let input_identity = DirectoryIdentity::observe(&input)?;
    require(
        child_identity.uid == unsafe { libc::geteuid() }
            && input_identity.uid == unsafe { libc::geteuid() }
            && fs::file_names(&input, REFUSED)?
                == INPUT_NAMES.into_iter().map(str::to_string).collect(),
    )?;
    let files = INPUT_NAMES
        .into_iter()
        .map(|name| {
            read_bound_file(&input, name, 0o600, 65_536).map(|bytes| (name.to_string(), bytes))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let material = prepare_with(view, installation, files.get("ca.crt").ok_or(REFUSED)?)?;
    require(material.input_files == files)?;
    fs::require_directory_binding(&root_path, &root, REFUSED)?;
    fs::require_directory_binding(&child_path, &child, REFUSED)?;
    fs::require_directory_binding(&child_path.join("input"), &input, REFUSED)?;
    require(
        DirectoryIdentity::observe(&root)? == root_identity
            && DirectoryIdentity::observe(&child)? == child_identity
            && DirectoryIdentity::observe(&input)? == input_identity
            && fs::file_names(&input, REFUSED)?
                == INPUT_NAMES.into_iter().map(str::to_string).collect(),
    )?;
    view.require_unchanged()?;
    Ok(material)
}

/// Exact helper admission under the caller's existing installation lock and
/// independently verified preparation receipt. This takes no second flock.
pub(crate) fn validate_renewal_model_at(
    installation: &Path,
    sequence: u32,
    model: &serde_json::Value,
) -> Result<()> {
    let view = InspectionAt::open(installation)?;
    let material = staged_material(&view, installation, sequence)?;
    validate_renewal_model(&material, model, installation, sequence, &material.image)?;
    view.require_unchanged()
}

fn retained_receipt(
    view: &impl RenewalInspection,
    sequence: u32,
    suffix: &str,
    receipt: &ComposeReceipt,
) -> Result<String> {
    let operation = format!("feature-{sequence:06}-{suffix}");
    let name = format!("generation-compose-{operation}-result.json");
    let raw = view.read_evidence(&name)?;
    let digest = crate::installer_release::sha256(&raw);
    require(
        digest == installer_jobs::receipt_digest(receipt)?
            && receipt.schema == "elevenid.installer-compose-operation/v1"
            && receipt.operation == operation
            && receipt.project == view.journal().compose_project()
            && view
                .journal()
                .runtime()
                .is_some_and(|r| receipt.engine_id == r.engine_id)
            && receipt.command_succeeded
            && receipt.client_exit_code == Some(0)
            && receipt.failure_class.is_none()
            && receipt.observation_validated
            && !receipt.installation_ready,
    )?;
    Ok(digest)
}

fn helper(receipt: &ComposeReceipt) -> Result<&crate::installer_compose::ContainerIdentity> {
    let identity = receipt
        .resources
        .as_ref()
        .and_then(|r| r.containers.get(SERVICE))
        .ok_or(REFUSED)?;
    require(
        identity.setup
            && identity.service == SERVICE
            && identity.id.len() == 64
            && identity.id.bytes().all(|b| b.is_ascii_hexdigit()),
    )?;
    Ok(identity)
}

/// Accept only a single observed helper execution which the generation owner
/// created and recorded before starting. All original outputs remain retained.
pub(crate) fn admit_renewal_output(
    state: &LockedMaintenance,
    material: &RenewalMaterial,
    output: &HeldRenewalOutput,
    created: &ComposeReceipt,
    started: &ComposeReceipt,
    completed: &ComposeReceipt,
) -> Result<(BTreeMap<String, Vec<u8>>, RenewalReceipt)> {
    state.require_unchanged()?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| REFUSED)?
        .as_secs();
    let result = admit_at(
        state.inspection(),
        material,
        output,
        created,
        started,
        completed,
        now,
    )?;
    state.require_unchanged()?;
    Ok(result)
}

fn admit_at(
    view: &impl RenewalInspection,
    material: &RenewalMaterial,
    output: &HeldRenewalOutput,
    created: &ComposeReceipt,
    started: &ComposeReceipt,
    completed: &ComposeReceipt,
    now: u64,
) -> Result<(BTreeMap<String, Vec<u8>>, RenewalReceipt)> {
    view.require_unchanged()?;
    let original = view.profile()?;
    let mut expected = original.identity_selection()?.ok_or(REFUSED)?;
    expected.operation = Operation::Renew;
    let retained = view.credentials(&original.credential_names()?)?;
    require(
        material.selection == expected
            && material.selection.installation_id == view.journal().installation_id().to_string()
            && view.journal().feature_profile_sha256()
                == Some(material.selection.feature_profile_sha256.as_str())
            && crate::installer_release::sha256(&view.read_evidence(RECORD)?)
                == material.initial_receipt_sha256
            && material.input_files.get("role-id") == retained.get(features::RENEWAL_ROLE_ID)
            && material.input_files.get("secret-id") == retained.get(features::RENEWAL_SECRET_ID)
            && material.input_files.get("workload-ca.crt") == retained.get(features::WORKLOAD_CA)
            && material.input_files.get("feature-identities.json")
                == Some(&serde_json::to_vec(&expected).map_err(|_| REFUSED)?),
    )?;
    let sequence = output.binding.sequence;
    let create_hash = retained_receipt(view, sequence, "create", created)?;
    let start_hash = retained_receipt(view, sequence, "start", started)?;
    let wait_hash = retained_receipt(view, sequence, "wait", completed)?;
    let before = helper(created)?;
    let begun = helper(started)?;
    let finished = helper(completed)?;
    require(
        before.id == begun.id
            && before.id == finished.id
            && before.image == material.image
            && begun.image == before.image
            && finished.image == before.image
            && before.config_hash == begun.config_hash
            && before.config_hash == finished.config_hash
            && created.configuration_sha256 == started.configuration_sha256
            && created.configuration_sha256 == completed.configuration_sha256
            && created.input_files == started.input_files
            && created.input_files == completed.input_files
            && finished
                .setup_execution
                .as_ref()
                .is_some_and(|v| v.completed_without_restart)
            && created
                .status
                .iter()
                .filter(|v| v["Service"] == SERVICE)
                .count()
                == 1
            && created.status.iter().any(|v| {
                v["Service"] == SERVICE && v["ID"] == before.id && v["State"] == "created"
            })
            && completed
                .status
                .iter()
                .filter(|v| v["Service"] == SERVICE)
                .count()
                == 1
            && completed.status.iter().any(|v| {
                v["Service"] == SERVICE
                    && v["ID"] == before.id
                    && v["State"] == "exited"
                    && v["ExitCode"] == 0
            }),
    )?;
    let input = output.path.parent().ok_or(REFUSED)?.join("input");
    for (name, bytes) in &material.input_files {
        require(
            created.input_files.get(&input.join(name))
                == Some(&crate::installer_release::sha256(bytes)),
        )?;
    }
    fs::require_directory_binding(&output.path, &output.directory, REFUSED)?;
    require(DirectoryIdentity::observe(&output.directory)? == output.current)?;
    let binding = view.journal().runtime().ok_or(REFUSED)?;
    let files = payloads(
        &output.directory,
        installer_helper_output::expected_host_uid(binding)?.uid(),
        &material.selection,
    )?;
    validate_payloads(
        &material.selection,
        &files,
        material.input_files.get("workload-ca.crt").ok_or(REFUSED)?,
        &[
            material.input_files.get("role-id").ok_or(REFUSED)?.clone(),
            material
                .input_files
                .get("secret-id")
                .ok_or(REFUSED)?
                .clone(),
        ],
        now,
    )?;
    fs::require_directory_binding(&output.path, &output.directory, REFUSED)?;
    require(DirectoryIdentity::observe(&output.directory)? == output.current)?;
    view.require_unchanged()?;
    let receipt = RenewalReceipt {
        schema: "elevenid.installer-feature-identity-renewal/v1".into(),
        installation_id: material.selection.installation_id.clone(),
        feature_profile_sha256: material.selection.feature_profile_sha256.clone(),
        sequence,
        initial_identity_receipt_sha256: material.initial_receipt_sha256.clone(),
        create_receipt_sha256: create_hash,
        start_receipt_sha256: start_hash,
        completed_receipt_sha256: wait_hash,
        engine_id: completed.engine_id.clone(),
        container_id: finished.id.clone(),
        image: finished.image.clone(),
        output_directory: output.binding.clone(),
        files: files
            .iter()
            .map(|(name, bytes)| (name.clone(), crate::installer_release::sha256(bytes)))
            .collect(),
        qualified_at_unix_seconds: now,
        governed_authority_created: false,
        generation_activated: false,
        installation_ready: false,
    };
    Ok((files, receipt))
}

/// Historical verification for Compose admission under its caller's lock. The
/// generation owner has already bound the preparation receipt and must retain
/// it; payload validation uses the original successful qualification time only.
pub(crate) fn verify_renewal_receipt_at(
    installation: &Path,
    receipt: &RenewalReceipt,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let view = InspectionAt::open(installation)?;
    let material = staged_material(&view, installation, receipt.sequence)?;
    verify_receipt_with(&view, installation, &material, receipt)
}

fn verify_receipt_with(
    view: &impl RenewalInspection,
    installation: &Path,
    material: &RenewalMaterial,
    receipt: &RenewalReceipt,
) -> Result<BTreeMap<String, Vec<u8>>> {
    view.require_path_binding(installation)?;
    require(
        receipt.schema == "elevenid.installer-feature-identity-renewal/v1"
            && receipt.sequence == receipt.output_directory.sequence
            && receipt.qualified_at_unix_seconds > 0,
    )?;
    let path = generation(installation, receipt.sequence)?.join("output");
    let held = resume_renewal_output(
        installation,
        &receipt.output_directory,
        fs::directory(&path, REFUSED)?,
    )?;
    let read = |phase: &str| -> Result<ComposeReceipt> {
        let name = format!(
            "generation-compose-feature-{:06}-{phase}-result.json",
            receipt.sequence
        );
        serde_json::from_value(
            crate::installer_json::decode(&view.read_evidence(&name)?).map_err(|_| REFUSED)?,
        )
        .map_err(|_| REFUSED.into())
    };
    let (files, observed) = admit_at(
        view,
        material,
        &held,
        &read("create")?,
        &read("start")?,
        &read("wait")?,
        receipt.qualified_at_unix_seconds,
    )?;
    require(observed == *receipt)?;
    view.require_path_binding(installation)?;
    view.require_unchanged()?;
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn material() -> RenewalMaterial {
        RenewalMaterial {
            selection: Selection {
                schema: features::SCHEMA.into(),
                installation_id: "00000000-0000-4000-8000-000000000001".into(),
                feature_profile_sha256: "a".repeat(64),
                operation: Operation::Renew,
                wallet_governance: true,
                public_verification: false,
                delegated_use: false,
            },
            input_files: INPUT_NAMES
                .into_iter()
                .map(|name| (name.into(), b"synthetic staged input".to_vec()))
                .collect(),
            initial_receipt_sha256: "b".repeat(64),
            image: format!("ghcr.io/elevenid/services@sha256:{}", "c".repeat(64)),
        }
    }
    fn model(material: &RenewalMaterial) -> serde_json::Value {
        let child = Path::new("/native/install/feature-profile-generations/000001");
        let mounts:Vec<_>=INPUT_NAMES.into_iter().map(|name| json!({
            "type":"bind","source":child.join("input").join(name),"target":format!("/input/{name}"),
            "read_only":true,"bind":{"create_host_path":false},
        })).chain([json!({"type":"bind","source":child.join("output"),"target":"/output",
            "read_only":false,"bind":{"create_host_path":false}})]).collect();
        json!({"services":{SERVICE:{
            "image":material.image,"entrypoint":["/usr/local/bin/marty-feature-identity-bootstrap"],
            "profiles":["setup"],"user":"0:0","read_only":true,"restart":"no","cap_drop":["ALL"],
            "labels":{"com.elevenid.installer.id":material.selection.installation_id,"com.elevenid.installer.phase":"setup"},
            "environment":{"BAO_ADDR":"https://openbao:8200","BAO_CACERT":"/input/ca.crt",
                "FEATURE_IDENTITY_RENEWAL_ROLE_ID_FILE":"/input/role-id",
                "FEATURE_IDENTITY_RENEWAL_SECRET_ID_FILE":"/input/secret-id",
                "FEATURE_IDENTITY_SELECTION_FILE":"/input/feature-identities.json",
                "FEATURE_IDENTITY_WORKLOAD_CA_FILE":"/input/workload-ca.crt","FEATURE_IDENTITY_OUTPUT_DIR":"/output"},
            "volumes":mounts,
        }}})
    }

    #[test]
    fn renewal_model_refuses_root_authority_broad_mounts_writable_inputs_and_old_output() {
        let material = material();
        let valid = model(&material);
        validate_renewal_model(
            &material,
            &valid,
            Path::new("/native/install"),
            1,
            &material.image,
        )
        .unwrap();
        for case in [
            "root-authority",
            "broad-mount",
            "writable-input",
            "null-input-permission",
            "old-output",
            "raw-token",
            "image",
            "automatic-create",
        ] {
            let mut changed = valid.clone();
            let service = &mut changed["services"][SERVICE];
            match case {
                "root-authority" => {
                    service["environment"]["FEATURE_IDENTITY_AUTHORITY_TOKEN_FILE"] =
                        json!("/input/root.token")
                }
                "broad-mount" => {
                    service["volumes"][0]["source"] = json!("/native/install/openbao-state")
                }
                "writable-input" => service["volumes"][0]["read_only"] = json!(false),
                "null-input-permission" => service["volumes"][0]["read_only"] = json!(null),
                "old-output" => {
                    service["volumes"][INPUT_NAMES.len()]["source"] =
                        json!("/native/install/feature-identity-output")
                }
                "raw-token" => service["environment"]["BAO_TOKEN"] = json!("synthetic-secret"),
                "image" => service["image"] = json!("unreviewed:latest"),
                _ => service["volumes"][0]["bind"]["create_host_path"] = json!(true),
            }
            assert!(
                validate_renewal_model(
                    &material,
                    &changed,
                    Path::new("/native/install"),
                    1,
                    &material.image
                )
                .is_err(),
                "{case}"
            );
        }
    }

    #[test]
    fn interrupted_output_is_resumed_only_under_its_original_directory_binding() {
        let temp = tempfile::tempdir().unwrap();
        let output = temp
            .path()
            .join("feature-profile-generations/000001/output");
        std::fs::create_dir_all(&output).unwrap();
        std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o700)).unwrap();
        let held = hold_renewal_output(temp.path(), 1, File::open(&output).unwrap()).unwrap();
        let original = held.binding();
        std::fs::write(output.join("uncertain-output"), b"retain").unwrap();
        assert!(hold_renewal_output(temp.path(), 1, File::open(&output).unwrap()).is_err());
        resume_renewal_output(temp.path(), &original, File::open(&output).unwrap()).unwrap();
        let preserved = output.with_file_name("preserved-output");
        std::fs::rename(&output, &preserved).unwrap();
        std::fs::create_dir(&output).unwrap();
        std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            resume_renewal_output(temp.path(), &original, File::open(&output).unwrap()).is_err()
        );
        assert_eq!(
            std::fs::read(preserved.join("uncertain-output")).unwrap(),
            b"retain"
        );
    }
}
