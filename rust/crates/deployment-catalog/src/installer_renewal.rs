//! Compose-managed first-install setup; completed jobs and uncertain outputs are retained.
#![cfg(target_os = "linux")]
use crate::{
    installer_compose::{ComposeInputs, ComposeReceipt},
    installer_helper_output::{self, HelperOutputOwner},
    installer_jobs,
    installer_openbao::OpenBaoInventory,
    installer_renewal_bootstrap,
    installer_state::{InstallerState, Phase},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    os::unix::fs::MetadataExt,
    path::Path,
};
type Result<T> = std::result::Result<T, String>;
const REFUSAL: &str = "Renewal provisioning refused; preserve installation state for recovery";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenewalReceipt {
    pub schema: String,
    pub installation_id: String,
    pub engine_id: String,
    pub container_id: String,
    pub container_name: String,
    pub network_id: String,
    pub image: String,
    pub root_retired: bool,
    pub ingress_renewal: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_renewal_authority_plan_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_identity_sha256: Option<BTreeMap<String, String>>,
    pub private_identity_validated: bool,
    pub outputs: Vec<String>,
    pub compose_receipt_sha256: String,
    pub job_completed_successfully: bool,
    pub container_removed: bool,
    pub installation_ready: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    schema: String,
    installation_id: String,
    root_retired: bool,
    ingress_renewal: bool,
    #[serde(default)]
    public_renewal_authority_plan_sha256: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Completed {
    schema: String,
    installation_id: String,
    identity_files: Vec<String>,
    policy_count: u64,
    scoped_login_verified: bool,
    verification_token_revoked: bool,
    root_retired: bool,
    ingress_renewal: bool,
    #[serde(default)]
    public_renewal_authority_plan_sha256: Option<String>,
}

const IDENTITY_FILES: [&str; 3] = [
    "renewal-role-id",
    "renewal-secret-id",
    "renewal-leaf-policies.json",
];

fn require(condition: bool) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(REFUSAL.into())
    }
}

fn directory(path: &Path) -> Result<File> {
    crate::installer_host_fs::directory(path, REFUSAL)
}

fn file_names(dir: &File) -> Result<BTreeSet<String>> {
    crate::installer_host_fs::file_names(dir, REFUSAL)
}

fn read_entry(dir: &File, name: &str, mode: u32, allow_root: bool) -> Result<Vec<u8>> {
    crate::installer_host_fs::read_entry(dir, name, mode, allow_root, REFUSAL)
}

fn read_inputs(secrets: &File) -> Result<BTreeMap<String, Vec<u8>>> {
    let available = file_names(secrets)?;
    let managed = crate::installer_ingress_provision::OUTPUTS[..3]
        .iter()
        .any(|name| available.contains(*name));
    let values = installer_renewal_bootstrap::inventory(managed)
        .into_iter()
        .map(|name| {
            let value = read_entry(secrets, &name, 0o444, true)?;
            Ok((name, value))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    installer_renewal_bootstrap::validate_current(&values).map_err(|_| REFUSAL)?;
    Ok(values)
}

fn stage_inputs(secrets: &File, output: &File) -> Result<BTreeMap<String, Vec<u8>>> {
    crate::installer_host_fs::stage_inputs(secrets, output, read_inputs, REFUSAL)
}

fn require_directory_binding(path: &Path, held: &File) -> Result<()> {
    crate::installer_host_fs::require_directory_binding(path, held, REFUSAL)
}

fn open_child(parent: &File, name: &str, flags: i32) -> Result<File> {
    crate::installer_host_fs::open_child(parent, name, flags, REFUSAL)
}

fn validate_retained_entries(held: &File, expected_host_uid: HelperOutputOwner) -> Result<()> {
    installer_helper_output::validate_retained_entries(held, expected_host_uid, REFUSAL)
}

fn validate_delivery(
    parent: &Path,
    held: &File,
    owner: &str,
    expected_host_uid: HelperOutputOwner,
    managed_ingress: bool,
    public_plan_sha256: Option<&str>,
) -> Result<Vec<String>> {
    require_directory_binding(parent, held)?;
    require(
        file_names(held)?
            == BTreeSet::from([
                "transfer-pending.json".into(),
                "output".into(),
                "delivered".into(),
            ]),
    )?;
    validate_retained_entries(held, expected_host_uid)?;
    let delivered = open_child(held, "delivered", libc::O_RDONLY | libc::O_DIRECTORY)?;
    let m = delivered.metadata().map_err(|_| REFUSAL)?;
    require(m.is_dir() && m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o7777 == 0o700)?;
    let result = validate_delivered(&delivered, owner, managed_ingress, public_plan_sha256)?;
    require_directory_binding(parent, held)?;
    Ok(result)
}

fn validate_delivered(
    delivered: &File,
    owner: &str,
    managed_ingress: bool,
    public_plan_sha256: Option<&str>,
) -> Result<Vec<String>> {
    let expected: BTreeSet<String> = IDENTITY_FILES
        .into_iter()
        .chain(["pending.json", "completed.json"])
        .map(String::from)
        .collect();
    require(file_names(delivered)? == expected)?;
    let pending: Pending =
        serde_json::from_slice(&read_entry(delivered, "pending.json", 0o600, false)?)
            .map_err(|_| REFUSAL)?;
    require(
        pending.schema
            == if public_plan_sha256.is_some() {
                "elevenid.installer-renewal-bootstrap-intent/v3"
            } else if managed_ingress {
                "elevenid.installer-renewal-bootstrap-intent/v2"
            } else {
                "elevenid.installer-renewal-bootstrap-intent/v1"
            }
            && pending.installation_id == owner
            && !pending.root_retired
            && pending.ingress_renewal == managed_ingress
            && pending.public_renewal_authority_plan_sha256.as_deref() == public_plan_sha256,
    )?;
    let completed: Completed =
        serde_json::from_slice(&read_entry(delivered, "completed.json", 0o600, false)?)
            .map_err(|_| REFUSAL)?;
    require(
        completed.schema
            == if public_plan_sha256.is_some() {
                "elevenid.installer-renewal-bootstrap-result/v3"
            } else if managed_ingress {
                "elevenid.installer-renewal-bootstrap-result/v2"
            } else {
                "elevenid.installer-renewal-bootstrap-result/v1"
            }
            && completed.installation_id == owner
            && completed.identity_files == IDENTITY_FILES
            && completed.policy_count == if managed_ingress { 22 } else { 21 }
            && completed.scoped_login_verified
            && completed.verification_token_revoked
            && !completed.root_retired
            && completed.ingress_renewal == managed_ingress
            && completed.public_renewal_authority_plan_sha256.as_deref() == public_plan_sha256,
    )?;
    let mut credentials = BTreeSet::new();
    for name in ["renewal-role-id", "renewal-secret-id"] {
        let raw = read_entry(delivered, name, 0o600, false)?;
        let value = std::str::from_utf8(&raw).map_err(|_| REFUSAL)?.trim();
        require(
            (20..=512).contains(&value.len())
                && value.bytes().all(|v| v.is_ascii_graphic())
                && credentials.insert(value.to_owned()),
        )?;
    }
    let policies: Vec<String> = serde_json::from_slice(&read_entry(
        delivered,
        "renewal-leaf-policies.json",
        0o600,
        false,
    )?)
    .map_err(|_| REFUSAL)?;
    require(
        policies.len() == if managed_ingress { 22 } else { 21 }
            && policies.iter().collect::<BTreeSet<_>>().len() == policies.len()
            && policies.iter().all(|v| {
                !v.is_empty()
                    && v.len() <= 160
                    && !["root", "default", "selfhost-kms-renewal"].contains(&v.as_str())
                    && v.bytes()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
            }),
    )?;
    let ingress = crate::installer_ingress_provision::resource_name(owner)?;
    require(
        policies.iter().any(|name| name == &ingress) == managed_ingress
            && policies
                .iter()
                .filter(|name| name.starts_with("installer-ingress-"))
                .count()
                == usize::from(managed_ingress),
    )?;
    Ok(IDENTITY_FILES.map(String::from).to_vec())
}

fn identity_hashes(delivered: &File) -> Result<BTreeMap<String, String>> {
    IDENTITY_FILES
        .into_iter()
        .map(|name| {
            Ok((
                name.into(),
                crate::installer_release::sha256(&read_entry(delivered, name, 0o600, false)?),
            ))
        })
        .collect()
}

/// Public binding of the already completed private renewal enrollment. This
/// contains hashes and policy names only, never the RoleID or SecretID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ManagedEnrolment {
    pub receipt_sha256: String,
    pub generation_intent_sha256: String,
    pub identity_sha256: BTreeMap<String, String>,
    pub leaf_policies: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagedGenerationIntent {
    schema: String,
    installation_id: String,
    engine_id: String,
    operator_sha256: String,
    keycloak_receipt_sha256: String,
    renewal_receipt_sha256: String,
    input_sha256: BTreeMap<String, String>,
    identity_sha256: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagedRenewalIntent {
    schema: String,
    installation_id: String,
    engine_id: String,
    operator_sha256: String,
    input_sha256: BTreeMap<String, String>,
}

fn managed_native_receipt(
    result: &RenewalReceipt,
    operation: &ComposeReceipt,
    owner: &str,
    engine: &str,
    project: &str,
) -> Result<()> {
    let hash = |value: &str| {
        value.len() == 64
            && value
                .bytes()
                .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
    };
    require(
        result.schema == "elevenid.installer-renewal-host/v3"
            && result.installation_id == owner
            && result.engine_id == engine
            && result.container_name == format!("{project}-installer-renewal-1")
            && hash(&result.container_id)
            && hash(&result.network_id)
            && result
                .image
                .strip_prefix("ghcr.io/elevenid/marty-ui-oss/services@sha256:")
                .is_some_and(hash)
            && result.ingress_renewal
            && !result.root_retired
            && result.private_identity_validated
            && result.public_renewal_authority_plan_sha256.is_none()
            && result.public_identity_sha256.is_none()
            && result.outputs == IDENTITY_FILES
            && result.job_completed_successfully
            && !result.container_removed
            && !result.installation_ready,
    )?;
    let resources = operation.resources.as_ref().ok_or(REFUSAL)?;
    let helper = resources
        .containers
        .get("installer-renewal")
        .ok_or(REFUSAL)?;
    require(
        operation.schema == "elevenid.installer-compose-operation/v1"
            && operation.operation == "setup-installer-renewal"
            && operation.project == project
            && operation.engine_id == engine
            && operation.command_succeeded
            && operation.client_exit_code == Some(0)
            && operation.failure_class.is_none()
            && !operation.installation_ready
            && operation.observation_validated
            && helper.setup
            && helper
                .setup_execution
                .as_ref()
                .is_some_and(|execution| execution.completed_without_restart)
            && helper.id == result.container_id
            && helper.image == result.image
            && resources
                .networks
                .values()
                .any(|id| id == &result.network_id)
            && operation.status.iter().any(|row| {
                row["Service"] == "installer-renewal"
                    && row["ID"] == helper.id
                    && row["State"] == "exited"
                    && row["ExitCode"] == 0
            }),
    )
}

/// Restore only the original, successfully enrolled private renewal authority.
/// Old workload tokens are historical evidence, not login credentials. This
/// reader performs no OpenBao request and never recreates or repairs enrollment.
pub(crate) fn require_managed_enrolment(
    state: &crate::installer_state::LockedInspection,
    installation: &Path,
) -> Result<ManagedEnrolment> {
    use crate::{installer_generation_binding as generation, installer_hosting};
    state.require_path_binding(installation)?;
    require(
        installer_hosting::resolve(state)?.certificate_source()
            == installer_hosting::CertificateSource::ManagedCa,
    )?;
    let owner = state.journal().installation_id().to_string();
    let runtime = state.journal().runtime().ok_or(REFUSAL)?;
    // Generation zero independently authenticates the original private
    // producer and its exact input/identity/output receipts. It cannot recurse
    // through a new managed successor or turn an imported foundation into one.
    let initial = generation::load_initial_verified(installation, &owner, &runtime.engine_id)?
        .ok_or(REFUSAL)?;
    require(initial.managed_ingress() && !initial.imported_foundation())?;
    let bytes = state.read_evidence("renewal-result.json")?;
    require(state.read_evidence("renewal-observation.json")? == bytes)?;
    let result: RenewalReceipt =
        serde_json::from_value(crate::installer_json::decode(&bytes).map_err(|_| REFUSAL)?)
            .map_err(|_| REFUSAL)?;
    let native = state.read_evidence("compose-setup-installer-renewal-result.json")?;
    require(crate::installer_release::sha256(&native) == result.compose_receipt_sha256)?;
    let native: ComposeReceipt =
        serde_json::from_value(crate::installer_json::decode(&native).map_err(|_| REFUSAL)?)
            .map_err(|_| REFUSAL)?;
    managed_native_receipt(
        &result,
        &native,
        &owner,
        &runtime.engine_id,
        &state.journal().compose_project(),
    )?;
    require(initial.network_id.as_deref() == Some(result.network_id.as_str()))?;

    let generation_intent_bytes = state.read_evidence("generation-pending.json")?;
    let intent: ManagedGenerationIntent = serde_json::from_value(
        crate::installer_json::decode(&generation_intent_bytes).map_err(|_| REFUSAL)?,
    )
    .map_err(|_| REFUSAL)?;
    let renewal_intent: ManagedRenewalIntent = serde_json::from_value(
        crate::installer_json::decode(&state.read_evidence("renewal-pending.json")?)
            .map_err(|_| REFUSAL)?,
    )
    .map_err(|_| REFUSAL)?;
    let keycloak = state.read_evidence("keycloak-observation.json")?;
    crate::installer_generation::original_nonce(&keycloak, &owner)?;
    let hashes_valid = |values: &BTreeMap<String, String>| {
        values.values().all(|value| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
        })
    };
    require(
        intent.schema == "elevenid.installer-generation-host-intent/v2"
            && renewal_intent.schema == "elevenid.installer-renewal-intent/v2"
            && intent.installation_id == owner
            && renewal_intent.installation_id == owner
            && intent.engine_id == runtime.engine_id
            && renewal_intent.engine_id == runtime.engine_id
            && intent.renewal_receipt_sha256 == crate::installer_release::sha256(&bytes)
            && intent.keycloak_receipt_sha256 == crate::installer_release::sha256(&keycloak)
            && intent.operator_sha256 == renewal_intent.operator_sha256
            && hashes_valid(&BTreeMap::from([(
                "operator".into(),
                intent.operator_sha256.clone(),
            )]))
            && intent.input_sha256 == renewal_intent.input_sha256
            && intent.input_sha256.keys().cloned().collect::<BTreeSet<_>>()
                == installer_renewal_bootstrap::managed_inputs()
            && hashes_valid(&intent.input_sha256)
            && intent
                .identity_sha256
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
                == IDENTITY_FILES.into()
            && hashes_valid(&intent.identity_sha256),
    )?;
    let parent = open_child(
        state.installation_directory(),
        "renewal-transfer",
        libc::O_RDONLY | libc::O_DIRECTORY,
    )?;
    let delivered = open_child(&parent, "delivered", libc::O_RDONLY | libc::O_DIRECTORY)?;
    for directory in [&parent, &delivered] {
        let m = directory.metadata().map_err(|_| REFUSAL)?;
        require(m.is_dir() && m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o7777 == 0o700)?;
    }
    require(validate_delivered(&delivered, &owner, true, None)? == IDENTITY_FILES)?;
    require(identity_hashes(&delivered)? == intent.identity_sha256)?;
    let staged_path = installation.join("generation-identity");
    let staged = directory(&staged_path)?;
    let staged_identity = crate::installer_generation_host::staged_identity(&staged)?;
    require(crate::installer_generation::hashes(&staged_identity) == intent.identity_sha256)?;
    for name in IDENTITY_FILES {
        require(read_entry(&delivered, name, 0o600, false)? == staged_identity[name])?;
    }
    for name in ["generation-inputs", "renewal-inputs"] {
        let path = installation.join(name);
        let held = directory(&path)?;
        require(file_names(&held)? == installer_renewal_bootstrap::managed_inputs())?;
        require(crate::installer_generation::hashes(&read_inputs(&held)?) == intent.input_sha256)?;
        require_directory_binding(&path, &held)?;
    }
    let leaf_policies: Vec<String> =
        serde_json::from_slice(&staged_identity["renewal-leaf-policies.json"])
            .map_err(|_| REFUSAL)?;
    require_directory_binding(&staged_path, &staged)?;
    require_directory_binding(&installation.join("renewal-transfer"), &parent)?;
    require_directory_binding(&installation.join("renewal-transfer/delivered"), &delivered)?;
    require(identity_hashes(&delivered)? == intent.identity_sha256)?;
    state.require_unchanged()?;
    Ok(ManagedEnrolment {
        receipt_sha256: crate::installer_release::sha256(&bytes),
        generation_intent_sha256: crate::installer_release::sha256(&generation_intent_bytes),
        identity_sha256: intent.identity_sha256,
        leaf_policies,
    })
}

/// Revalidate completed pre-CA enrollment without logging in or requiring
/// original leaf credentials to remain live after a certificate order wait.
pub(crate) fn require_public_enrolment(
    state: &crate::installer_state::LockedInspection,
    plan: &crate::installer_public_ingress::PublicRenewalAuthorityPlan,
) -> Result<String> {
    plan.require_saved(state)?;
    let bytes = state.read_evidence("renewal-result.json")?;
    let result: RenewalReceipt =
        serde_json::from_value(crate::installer_json::decode(&bytes).map_err(|_| REFUSAL)?)
            .map_err(|_| REFUSAL)?;
    require(state.read_evidence("renewal-observation.json")? == bytes)?;
    let runtime = state.journal().runtime().ok_or(REFUSAL)?;
    let owner = state.journal().installation_id().to_string();
    let digest = plan.sha256()?;
    let hex = |value: &str| {
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    require(
        result.schema == "elevenid.installer-renewal-host/v4"
            && result.installation_id == owner
            && result.engine_id == runtime.engine_id
            && result.container_name
                == format!("{}-installer-renewal-1", state.journal().compose_project())
            && hex(&result.container_id)
            && hex(&result.network_id)
            && result
                .image
                .strip_prefix("ghcr.io/elevenid/marty-ui-oss/services@sha256:")
                .is_some_and(hex)
            && result.ingress_renewal
            && !result.root_retired
            && result.private_identity_validated
            && result.public_renewal_authority_plan_sha256.as_deref() == Some(digest.as_str())
            && result.outputs == IDENTITY_FILES
            && result.job_completed_successfully
            && !result.container_removed
            && !result.installation_ready,
    )?;
    let operation = state.read_evidence("compose-setup-installer-renewal-result.json")?;
    require(crate::installer_release::sha256(&operation) == result.compose_receipt_sha256)?;
    let operation: ComposeReceipt =
        serde_json::from_value(crate::installer_json::decode(&operation).map_err(|_| REFUSAL)?)
            .map_err(|_| REFUSAL)?;
    let resources = operation.resources.as_ref().ok_or(REFUSAL)?;
    let helper = resources
        .containers
        .get("installer-renewal")
        .ok_or(REFUSAL)?;
    require(
        operation.schema == "elevenid.installer-compose-operation/v1"
            && operation.operation == "setup-installer-renewal"
            && operation.project == state.journal().compose_project()
            && operation.engine_id == runtime.engine_id
            && operation.command_succeeded
            && operation.client_exit_code == Some(0)
            && operation.failure_class.is_none()
            && !operation.installation_ready
            && operation.observation_validated
            && helper.setup
            && helper
                .setup_execution
                .as_ref()
                .is_some_and(|execution| execution.completed_without_restart)
            && helper.id == result.container_id
            && helper.image == result.image
            && resources
                .networks
                .values()
                .any(|id| id == &result.network_id)
            && operation.status.iter().any(|row| {
                row["Service"] == "installer-renewal"
                    && row["ID"] == helper.id
                    && row["State"] == "exited"
                    && row["ExitCode"] == 0
            }),
    )?;
    let parent = open_child(
        state.installation_directory(),
        "renewal-transfer",
        libc::O_RDONLY | libc::O_DIRECTORY,
    )?;
    let delivered = open_child(&parent, "delivered", libc::O_RDONLY | libc::O_DIRECTORY)?;
    for directory in [&parent, &delivered] {
        let metadata = directory.metadata().map_err(|_| REFUSAL)?;
        require(
            metadata.is_dir()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o7777 == 0o700,
        )?;
    }
    require(validate_delivered(&delivered, &owner, true, Some(&digest))? == IDENTITY_FILES)?;
    require(result.public_identity_sha256.as_ref() == Some(&identity_hashes(&delivered)?))?;
    state.require_unchanged()?;
    Ok(crate::installer_release::sha256(&bytes))
}

#[expect(
    clippy::too_many_arguments,
    reason = "Keep independently bound provisioning inputs explicit at this boundary."
)]
pub fn provision(
    dockerpath: &Path,
    installation: &Path,
    bundle: &Path,
    state: &mut InstallerState,
    bao: &OpenBaoInventory,
    services_image: &str,
    inputs: ComposeInputs,
    expected_operator_sha: &str,
) -> Result<(ComposeReceipt, RenewalReceipt)> {
    provision_selected(
        dockerpath,
        installation,
        bundle,
        state,
        bao,
        services_image,
        inputs,
        expected_operator_sha,
        None,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "Keep independently bound provisioning inputs explicit."
)]
pub fn provision_public(
    dockerpath: &Path,
    installation: &Path,
    bundle: &Path,
    state: &mut InstallerState,
    bao: &OpenBaoInventory,
    services_image: &str,
    inputs: ComposeInputs,
    expected_operator_sha: &str,
    plan: &crate::installer_public_ingress::PublicRenewalAuthorityPlan,
) -> Result<(ComposeReceipt, RenewalReceipt)> {
    provision_selected(
        dockerpath,
        installation,
        bundle,
        state,
        bao,
        services_image,
        inputs,
        expected_operator_sha,
        Some(plan),
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "Both sources use the existing owned provisioning transaction."
)]
fn provision_selected(
    dockerpath: &Path,
    installation: &Path,
    bundle: &Path,
    state: &mut InstallerState,
    bao: &OpenBaoInventory,
    services_image: &str,
    inputs: ComposeInputs,
    expected_operator_sha: &str,
    public_plan: Option<&crate::installer_public_ingress::PublicRenewalAuthorityPlan>,
) -> Result<(ComposeReceipt, RenewalReceipt)> {
    state.require_live_phase(Phase::Provisioning)?;
    let public_digest = public_plan.map(|plan| plan.sha256()).transpose()?;
    if let Some(plan) = public_plan {
        state.with_inspection(|view| plan.require_saved(view))?;
    }
    require(InstallerState::inspect(installation)? == *state.journal())?;
    let binding = state.journal().runtime().ok_or(REFUSAL)?.clone();
    let owner = state.journal().installation_id().to_string();
    crate::installer_ingress_provision::resource_name(&owner)?;
    let secrets = directory(&installation.join("secrets"))?;
    state.create_private_directory("renewal-transfer")?;
    state.create_private_directory("renewal-inputs")?;
    let staged = directory(&installation.join("renewal-inputs"))?;
    let source_snapshot = stage_inputs(&secrets, &staged)?;
    let managed_ingress = installer_renewal_bootstrap::has_managed_ingress(&source_snapshot)?;
    // This producer is for fresh managed OpenBao installations. Retained v1
    // receipts remain readable, but may not downgrade a new provisioning run.
    require(managed_ingress)?;
    let output_path = installation.join("renewal-transfer");
    let output = directory(&output_path)?;
    let mut pending = json!({
        "schema":"elevenid.installer-renewal-intent/v2", "installation_id":owner,
        "engine_id":binding.engine_id,"operator_sha256":expected_operator_sha,
        "input_sha256":crate::installer_generation::hashes(&source_snapshot)
    });
    if let Some(digest) = &public_digest {
        pending["schema"] = json!("elevenid.installer-renewal-intent/v3");
        pending["public_renewal_authority_plan_sha256"] = json!(digest);
    }
    state.write_evidence(
        "renewal-pending.json",
        &serde_json::to_vec(&pending).map_err(|_| REFUSAL)?,
    )?;
    require_directory_binding(&output_path, &output)?;
    require(
        file_names(&staged)? == installer_renewal_bootstrap::inventory(managed_ingress)
            && read_inputs(&staged)? == source_snapshot
            && read_inputs(&secrets)? == source_snapshot,
    )?;
    if let Some(plan) = public_plan {
        plan.require_job_inputs(dockerpath, &binding, &inputs, "installer-renewal")?;
    }
    let job = installer_jobs::run(
        dockerpath,
        installation,
        bundle,
        state,
        Some(bao),
        inputs,
        "installer-renewal",
        services_image,
        expected_operator_sha,
    )?;
    require_directory_binding(&installation.join("secrets"), &secrets)?;
    require_directory_binding(&installation.join("renewal-inputs"), &staged)?;
    require(read_inputs(&secrets)? == source_snapshot && read_inputs(&staged)? == source_snapshot)?;
    let delivered = validate_delivery(
        &output_path,
        &output,
        &owner,
        installer_helper_output::expected_host_uid(&binding)?,
        managed_ingress,
        public_digest.as_deref(),
    )?;
    if let Some(plan) = public_plan {
        state.with_inspection(|view| plan.require_saved(view))?;
    }
    let receipt = RenewalReceipt {
        schema: if public_plan.is_some() {
            "elevenid.installer-renewal-host/v4"
        } else {
            "elevenid.installer-renewal-host/v3"
        }
        .into(),
        installation_id: owner,
        engine_id: binding.engine_id,
        container_id: job.container_id,
        container_name: job.container_name,
        network_id: bao.network_id.clone(),
        image: job.image,
        root_retired: false,
        ingress_renewal: true,
        public_renewal_authority_plan_sha256: public_digest,
        public_identity_sha256: public_plan
            .map(|_| identity_hashes(&directory(&output_path.join("delivered"))?))
            .transpose()?,
        private_identity_validated: true,
        outputs: delivered,
        compose_receipt_sha256: installer_jobs::receipt_digest(&job.compose)?,
        job_completed_successfully: true,
        container_removed: false,
        installation_ready: false,
    };
    state.write_evidence(
        "renewal-result.json",
        &serde_json::to_vec(&receipt).map_err(|_| REFUSAL)?,
    )?;
    Ok((job.compose, receipt))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    const OWNER: &str = "12345678-1234-4234-8234-123456789abc";
    #[test]
    fn managed_enrolment_requires_completed_exact_native_job_and_private_source() {
        let project = format!("marty-install-{}", OWNER.replace('-', ""));
        let image = format!(
            "ghcr.io/elevenid/marty-ui-oss/services@sha256:{}",
            "c".repeat(64)
        );
        let result = json!({"schema":"elevenid.installer-renewal-host/v3","installation_id":OWNER,
            "engine_id":"engine-identity-123","container_id":"a".repeat(64),
            "container_name":format!("{project}-installer-renewal-1"),"network_id":"b".repeat(64),"image":image,
            "root_retired":false,"ingress_renewal":true,"private_identity_validated":true,
            "outputs":IDENTITY_FILES,"compose_receipt_sha256":"d".repeat(64),
            "job_completed_successfully":true,"container_removed":false,"installation_ready":false});
        let operation = json!({"schema":"elevenid.installer-compose-operation/v1",
            "project":project,"engine_id":"engine-identity-123","operation":"setup-installer-renewal",
            "configuration_sha256":"e".repeat(64),"input_files":{},"command_succeeded":true,"client_exit_code":0,
            "failure_class":null,"observation_validated":true,"installation_ready":false,
            "resources":{"containers":{"installer-renewal":{"id":"a".repeat(64),"service":"installer-renewal",
                "image":image,"config_hash":"f".repeat(64),"setup":true,
                "setup_execution":{"started_at":"2026-01-01T00:00:00Z","finished_at":"2026-01-01T00:01:00Z","completed_without_restart":true},
                "health_required":false,"cap_add":[],"cap_drop":["ALL"],"read_only":true,"memory_limit":134217728}},
                "networks":{"default":"b".repeat(64)},"volumes":[]},
            "status":[{"Service":"installer-renewal","ID":"a".repeat(64),"State":"exited","ExitCode":0}]});
        let parsed_result: RenewalReceipt = serde_json::from_value(result.clone()).unwrap();
        let parsed_operation: ComposeReceipt = serde_json::from_value(operation.clone()).unwrap();
        managed_native_receipt(
            &parsed_result,
            &parsed_operation,
            OWNER,
            "engine-identity-123",
            &project,
        )
        .unwrap();
        for (field, value) in [
            ("schema", json!("elevenid.installer-renewal-host/v4")),
            ("private_identity_validated", json!(false)),
            ("job_completed_successfully", json!(false)),
            ("container_removed", json!(true)),
            ("root_retired", json!(true)),
            ("installation_ready", json!(true)),
            (
                "public_renewal_authority_plan_sha256",
                json!("f".repeat(64)),
            ),
            ("public_identity_sha256", json!({})),
            ("container_id", json!("f".repeat(64))),
            ("network_id", json!("f".repeat(64))),
        ] {
            let mut changed = result.clone();
            changed[field] = value;
            assert!(
                managed_native_receipt(
                    &serde_json::from_value(changed).unwrap(),
                    &parsed_operation,
                    OWNER,
                    "engine-identity-123",
                    &project
                )
                .is_err(),
                "accepted {field}"
            );
        }
        for (pointer, value) in [
            ("/operation", json!("up")),
            ("/client_exit_code", json!(1)),
            ("/command_succeeded", json!(false)),
            ("/failure_class", json!("client_failure")),
            ("/observation_validated", json!(false)),
            (
                "/resources/containers/installer-renewal/setup",
                json!(false),
            ),
            (
                "/resources/containers/installer-renewal/setup_execution/completed_without_restart",
                json!(false),
            ),
            ("/status/0/ID", json!("f".repeat(64))),
            ("/status/0/ExitCode", json!(1)),
        ] {
            let mut changed = operation.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            assert!(
                managed_native_receipt(
                    &parsed_result,
                    &serde_json::from_value(changed).unwrap(),
                    OWNER,
                    "engine-identity-123",
                    &project
                )
                .is_err(),
                "accepted {pointer}"
            );
        }
    }
    fn host_output_owner_for_test() -> installer_helper_output::HelperOutputOwner {
        let uid = unsafe { libc::geteuid() };
        let profile = if uid == 0 {
            crate::installer_state::RuntimeProfile::Rootful
        } else {
            crate::installer_state::RuntimeProfile::Rootless
        };
        installer_helper_output::expected_host_uid(&crate::installer_state::RuntimeBinding {
            docker_host: if uid == 0 {
                "unix:///var/run/docker.sock".into()
            } else {
                format!("unix:///run/user/{uid}/docker.sock")
            },
            engine_id: "engine-identity-123".into(),
            openbao_port: 18200,
            profile,
        })
        .unwrap()
    }

    #[test]
    fn retained_container_outputs_bind_host_owner_and_remain_private() {
        let owner = host_output_owner_for_test();
        let uid = unsafe { libc::geteuid() };
        assert_eq!(owner.uid(), uid);
        let rootful =
            installer_helper_output::expected_host_uid(&crate::installer_state::RuntimeBinding {
                docker_host: "unix:///var/run/docker.sock".into(),
                engine_id: "engine-identity-123".into(),
                openbao_port: 18200,
                profile: crate::installer_state::RuntimeProfile::Rootful,
            })
            .unwrap();
        assert_eq!(rootful.uid(), 0);
        for mutation in [
            "none",
            "pending-mode",
            "output-mode",
            "pending-link",
            "output-link",
            "hardlink",
            "pending-directory",
            "output-file",
        ] {
            let temp = tempfile::tempdir().unwrap();
            std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            let output = temp.path().join("output");
            let pending = temp.path().join("transfer-pending.json");
            std::fs::create_dir(&output).unwrap();
            std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::write(&pending, b"synthetic retained transfer intent").unwrap();
            std::fs::set_permissions(&pending, std::fs::Permissions::from_mode(0o600)).unwrap();
            let held = directory(temp.path()).unwrap();
            let snapshot = |path: &Path| {
                let m = std::fs::symlink_metadata(path).unwrap();
                (
                    m.dev(),
                    m.ino(),
                    m.uid(),
                    m.gid(),
                    m.mode(),
                    m.nlink(),
                    m.len(),
                )
            };
            let before = (snapshot(&output), snapshot(&pending));
            validate_retained_entries(&held, owner).unwrap();
            if uid != 0 {
                // Rootful UID 0 is not an alternate accepted owner on rootless hosts.
                assert!(validate_retained_entries(&held, rootful).is_err());
            }
            assert_eq!((snapshot(&output), snapshot(&pending)), before);
            assert_eq!(
                std::fs::read(&pending).unwrap(),
                b"synthetic retained transfer intent"
            );
            match mutation {
                "none" => continue,
                "pending-mode" => {
                    std::fs::set_permissions(&pending, std::fs::Permissions::from_mode(0o644))
                        .unwrap()
                }
                "output-mode" => {
                    std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o750))
                        .unwrap()
                }
                "pending-link" => {
                    let original = temp.path().join("original-pending");
                    std::fs::rename(&pending, &original).unwrap();
                    symlink(original, &pending).unwrap();
                }
                "output-link" => {
                    let original = temp.path().join("original-output");
                    std::fs::rename(&output, &original).unwrap();
                    symlink(original, &output).unwrap();
                }
                "hardlink" => {
                    std::fs::hard_link(&pending, temp.path().join("linked-pending")).unwrap()
                }
                "pending-directory" => {
                    std::fs::remove_file(&pending).unwrap();
                    std::fs::create_dir(&pending).unwrap();
                    std::fs::set_permissions(&pending, std::fs::Permissions::from_mode(0o600))
                        .unwrap();
                }
                "output-file" => {
                    std::fs::remove_dir(&output).unwrap();
                    std::fs::write(&output, b"not a directory").unwrap();
                    std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o700))
                        .unwrap();
                }
                _ => unreachable!(),
            }
            assert_eq!(
                validate_retained_entries(&held, owner).unwrap_err(),
                REFUSAL,
                "accepted {mutation}"
            );
        }
    }
    fn private() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        temp
    }

    #[test]
    fn held_transfer_directory_rejects_replacement_and_linked_delivery() {
        let temp = private();
        let transfer = temp.path().join("transfer");
        std::fs::create_dir(&transfer).unwrap();
        std::fs::set_permissions(&transfer, std::fs::Permissions::from_mode(0o700)).unwrap();
        let held = directory(&transfer).unwrap();
        require_directory_binding(&transfer, &held).unwrap();
        std::fs::rename(&transfer, temp.path().join("original")).unwrap();
        std::fs::create_dir(&transfer).unwrap();
        std::fs::set_permissions(&transfer, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(require_directory_binding(&transfer, &held).is_err());
        assert!(validate_delivery(
            &transfer,
            &held,
            OWNER,
            host_output_owner_for_test(),
            false,
            None
        )
        .is_err());
        symlink(&transfer, temp.path().join("original/delivered")).unwrap();
        assert!(open_child(&held, "delivered", libc::O_RDONLY | libc::O_DIRECTORY).is_err());
    }

    fn put(root: &Path, name: &str, value: &[u8], mode: u32) {
        std::fs::write(root.join(name), value).unwrap();
        std::fs::set_permissions(root.join(name), std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn exact_snapshot_is_exclusive_and_preserves_only_reviewed_inputs() {
        let source = private();
        let target = private();
        for (i, name) in installer_renewal_bootstrap::current_inputs()
            .iter()
            .enumerate()
        {
            let value = if name.ends_with("_token") {
                format!("token-{i:040}")
            } else {
                "-----BEGIN CERTIFICATE-----\npublic\n-----END CERTIFICATE-----\n".into()
            };
            put(source.path(), name, value.as_bytes(), 0o444);
        }
        put(
            source.path(),
            "operator_bootstrap_password",
            b"not-copied",
            0o444,
        );
        let src = directory(source.path()).unwrap();
        let dst = directory(target.path()).unwrap();
        let snapshot = stage_inputs(&src, &dst).unwrap();
        assert_eq!(snapshot.len(), 40);
        assert_eq!(
            file_names(&dst).unwrap(),
            installer_renewal_bootstrap::current_inputs()
        );
        assert!(stage_inputs(&src, &dst).is_err());
        let name = snapshot.keys().find(|n| n.ends_with("_token")).unwrap();
        std::fs::set_permissions(
            target.path().join(name),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(read_inputs(&dst).is_err());
    }

    #[test]
    fn delivered_identity_requires_private_files_complete_receipt_and_exact_inventory() {
        let temp = private();
        let dir = directory(temp.path()).unwrap();
        let pending = json!({"schema":"elevenid.installer-renewal-bootstrap-intent/v1","installation_id":OWNER,"root_retired":false,"ingress_renewal":false});
        let completed = json!({"schema":"elevenid.installer-renewal-bootstrap-result/v1","installation_id":OWNER,"identity_files":IDENTITY_FILES,"policy_count":21,"scoped_login_verified":true,"verification_token_revoked":true,"root_retired":false,"ingress_renewal":false});
        put(
            temp.path(),
            "pending.json",
            &serde_json::to_vec(&pending).unwrap(),
            0o600,
        );
        put(
            temp.path(),
            "completed.json",
            &serde_json::to_vec(&completed).unwrap(),
            0o600,
        );
        put(
            temp.path(),
            "renewal-role-id",
            b"11111111-1111-4111-8111-111111111111\n",
            0o600,
        );
        put(
            temp.path(),
            "renewal-secret-id",
            b"22222222-2222-4222-8222-222222222222\n",
            0o600,
        );
        put(
            temp.path(),
            "renewal-leaf-policies.json",
            &serde_json::to_vec(&(0..21).map(|i| format!("policy-{i}")).collect::<Vec<_>>())
                .unwrap(),
            0o600,
        );
        assert_eq!(
            validate_delivered(&dir, OWNER, false, None).unwrap().len(),
            3
        );
        for (field, value) in [
            ("root_retired", json!(true)),
            ("verification_token_revoked", json!(false)),
            ("installation_id", json!("foreign")),
            ("extra", json!(true)),
        ] {
            let mut bad = completed.clone();
            bad[field] = value;
            put(
                temp.path(),
                "completed.json",
                &serde_json::to_vec(&bad).unwrap(),
                0o600,
            );
            assert!(validate_delivered(&dir, OWNER, false, None).is_err());
        }
        put(
            temp.path(),
            "completed.json",
            &serde_json::to_vec(&completed).unwrap(),
            0o600,
        );
        std::fs::set_permissions(
            temp.path().join("renewal-secret-id"),
            std::fs::Permissions::from_mode(0o444),
        )
        .unwrap();
        assert!(validate_delivered(&dir, OWNER, false, None).is_err());
        std::fs::set_permissions(
            temp.path().join("renewal-secret-id"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        put(temp.path(), "unexpected", b"extra", 0o600);
        assert!(validate_delivered(&dir, OWNER, false, None).is_err());
    }

    #[test]
    fn held_output_directory_refuses_aliases_and_nonprivate_mode() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = temp.path().join("output");
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(directory(&path).is_ok());
        let alias = temp.path().join("alias");
        symlink(&path, &alias).unwrap();
        assert!(directory(&alias).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o750)).unwrap();
        assert!(directory(&path).is_err());
    }
}
