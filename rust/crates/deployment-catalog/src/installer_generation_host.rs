//! Owned one-shot orphan generation, never activation or root retirement. Never retries a mutation or removes an
//! uncertain container. Durable intent, ID and surviving outputs are retained.
#![cfg(target_os = "linux")]
use crate::{
    installer_openbao::{self, OpenBaoInventory},
    installer_renewal_bootstrap,
    installer_runtime::DockerRunner,
    installer_state::{InstallerState, Phase},
    installer_verify,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fs::File,
    io::Write,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
    time::Duration,
};
type Result<T> = std::result::Result<T, String>;
const REFUSAL: &str = "Generation provisioning refused; preserve installation state for recovery";
#[derive(Serialize)]
pub struct GenerationReceipt {
    pub schema: &'static str,
    pub installation_id: String,
    pub engine_id: String,
    pub container_id: String,
    pub container_name: String,
    pub network_id: String,
    pub image: String,
    pub root_retired: bool,
    pub ingress_renewal: bool,
    pub candidate_validated: bool,
    pub activated: bool,
    pub candidate_sha256: BTreeMap<String, String>,
    pub outputs: Vec<String>,
    pub container_removed: bool,
    pub installation_ready: bool,
}
struct Contract {
    name: String,
    owner: String,
    image: String,
    image_id: String,
    network_id: String,
    network_name: String,
    environment: BTreeMap<String, String>,
    mounts: BTreeMap<String, (PathBuf, bool)>,
}
fn require(condition: bool) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(REFUSAL.into())
    }
}
fn id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn path_text(path: &Path) -> Result<&str> {
    let value = path.to_str().ok_or(REFUSAL)?;
    require(path.is_absolute() && !value.chars().any(|c| c.is_control() || c == ','))?;
    Ok(value)
}
fn command(contract: &Contract) -> Result<Vec<String>> {
    crate::installer_ingress_provision::resource_name(&contract.owner)?;
    let mut args = vec![
        "create".into(),
        "--name".into(),
        contract.name.clone(),
        "--pull=never".into(),
        "--network".into(),
        contract.network_id.clone(),
        "--user".into(),
        "0:0".into(),
        "--read-only".into(),
        "--cap-drop".into(),
        "ALL".into(),
        "--cap-add".into(),
        "DAC_OVERRIDE".into(),
        "--cap-add".into(),
        "CHOWN".into(),
        "--security-opt".into(),
        "no-new-privileges".into(),
        "--restart=no".into(),
        "--label".into(),
        format!("com.elevenid.installer.id={}", contract.owner),
        "--label".into(),
        "com.elevenid.installer.stage=generation".into(),
        "--entrypoint".into(),
        "/input/marty-deploy".into(),
    ];
    for (target, (source, readonly)) in &contract.mounts {
        args.extend([
            "--mount".into(),
            format!(
                "type=bind,src={},dst={target}{}",
                path_text(source)?,
                if *readonly { ",readonly" } else { "" }
            ),
        ]);
    }
    for (key, value) in &contract.environment {
        args.extend(["--env".into(), format!("{key}={value}")]);
    }
    args.extend([
        contract.image.clone(),
        "installer-generation-provision-transfer".into(),
        "--installation-id".into(),
        contract.owner.clone(),
    ]);
    Ok(args)
}
fn run(docker: &DockerRunner, args: &[String]) -> Result<String> {
    docker.run_checked(&args.iter().map(String::as_str).collect::<Vec<_>>())
}
fn inspect(docker: &DockerRunner, container: &str) -> Result<Value> {
    crate::installer_container::inspect(docker, container, REFUSAL)
}
fn empty_or_null(value: &Value) -> bool {
    crate::installer_container::empty_or_null(value)
}
fn validate_observation(
    c: &Value,
    container: &str,
    contract: &Contract,
    terminal: bool,
) -> Result<()> {
    let host = &c["HostConfig"];
    let config = &c["Config"];
    crate::installer_container::validate_identity_and_security(
        c,
        &crate::installer_container::ExpectedContainer {
            id: container,
            name: &contract.name,
            owner: &contract.owner,
            image: &contract.image,
            image_id: &contract.image_id,
            network_id: &contract.network_id,
            stage: "generation",
            entrypoint: json!(["/input/marty-deploy"]),
            command: json!([
                "installer-generation-provision-transfer",
                "--installation-id",
                contract.owner
            ]),
        },
        REFUSAL,
    )?;
    require(capabilities(&host["CapAdd"]) && empty_or_null(&host["Tmpfs"]))?;
    require(environment_map(&config["Env"])? == contract.environment)?;
    crate::installer_container::validate_network(
        c,
        &contract.network_name,
        &contract.network_id,
        terminal,
        REFUSAL,
    )?;
    let mut mounts = BTreeMap::new();
    for mount in c["Mounts"].as_array().ok_or(REFUSAL)? {
        require(mount["Type"] == "bind")?;
        let target = mount["Destination"].as_str().ok_or(REFUSAL)?;
        require(target != "/tmp")?;
        let source = mount["Source"].as_str().ok_or(REFUSAL)?;
        let writable = mount["RW"].as_bool().ok_or(REFUSAL)?;
        require(
            mounts
                .insert(target.to_owned(), (PathBuf::from(source), !writable))
                .is_none(),
        )?;
    }
    require(mounts == contract.mounts)?;
    crate::installer_container::validate_stopped_state(c, terminal, REFUSAL)?;
    Ok(())
}
fn directory(path: &Path) -> Result<File> {
    crate::installer_host_fs::directory(path, REFUSAL)
}

fn capabilities(value: &Value) -> bool {
    let Some(items) = value.as_array() else {
        return false;
    };
    items.len() == 2
        && items
            .iter()
            .map(|v| {
                v.as_str()
                    .unwrap_or("")
                    .strip_prefix("CAP_")
                    .unwrap_or(v.as_str().unwrap_or(""))
            })
            .collect::<BTreeSet<_>>()
            == BTreeSet::from(["CHOWN", "DAC_OVERRIDE"])
}

fn file_names(dir: &File) -> Result<BTreeSet<String>> {
    crate::installer_host_fs::file_names(dir, REFUSAL)
}

fn read_entry(dir: &File, name: &str, mode: u32, allow_root: bool) -> Result<Vec<u8>> {
    crate::installer_host_fs::read_entry(dir, name, mode, allow_root, REFUSAL)
}

fn read_inputs(secrets: &File) -> Result<BTreeMap<String, Vec<u8>>> {
    let values = installer_renewal_bootstrap::current_inputs()
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

const IDENTITY_FILES: [&str; 3] = [
    "renewal-role-id",
    "renewal-secret-id",
    "renewal-leaf-policies.json",
];
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RenewalEvidence {
    schema: String,
    installation_id: String,
    engine_id: String,
    container_id: String,
    container_name: String,
    network_id: String,
    image: String,
    root_retired: bool,
    ingress_renewal: bool,
    private_identity_validated: bool,
    outputs: Vec<String>,
    container_removed: bool,
    installation_ready: bool,
}
fn read_identity(source: &File) -> Result<BTreeMap<String, Vec<u8>>> {
    require(
        file_names(source)?
            == IDENTITY_FILES
                .into_iter()
                .chain(["pending.json", "completed.json"])
                .map(String::from)
                .collect(),
    )?;
    let mut values = BTreeMap::new();
    for name in IDENTITY_FILES {
        values.insert(name.into(), read_entry(source, name, 0o600, false)?);
    }
    let mut credentials = BTreeSet::new();
    for name in ["renewal-role-id", "renewal-secret-id"] {
        let value = std::str::from_utf8(&values[name])
            .map_err(|_| REFUSAL)?
            .trim();
        require(
            (20..=512).contains(&value.len())
                && value.bytes().all(|v| v.is_ascii_graphic())
                && credentials.insert(value.to_owned()),
        )?;
    }
    let policies: Vec<String> =
        serde_json::from_slice(&values["renewal-leaf-policies.json"]).map_err(|_| REFUSAL)?;
    require(
        policies.len() == 21
            && policies.iter().collect::<BTreeSet<_>>().len() == 21
            && policies.iter().all(|p| {
                !p.is_empty()
                    && p.len() <= 160
                    && !["root", "default", "selfhost-kms-renewal"].contains(&p.as_str())
                    && p.bytes()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
            }),
    )?;
    Ok(values)
}
fn stage_identity(values: &BTreeMap<String, Vec<u8>>, output: &File) -> Result<()> {
    require(
        file_names(output)?.is_empty()
            && values.keys().map(String::as_str).collect::<BTreeSet<_>>() == IDENTITY_FILES.into(),
    )?;
    for (name, value) in values {
        let name = CString::new(name.as_str()).map_err(|_| REFUSAL)?;
        let fd = unsafe {
            libc::openat(
                output.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        require(fd >= 0)?;
        let mut file = unsafe { File::from_raw_fd(fd) };
        output.sync_all().map_err(|_| REFUSAL)?;
        file.write_all(value)
            .and_then(|_| file.sync_all())
            .and_then(|_| output.sync_all())
            .map_err(|_| REFUSAL)?;
    }
    Ok(())
}
fn staged_identity(output: &File) -> Result<BTreeMap<String, Vec<u8>>> {
    require(file_names(output)? == IDENTITY_FILES.map(String::from).into())?;
    IDENTITY_FILES
        .into_iter()
        .map(|n| Ok((n.into(), read_entry(output, n, 0o600, false)?)))
        .collect()
}
fn validate_delivered(
    delivered: &File,
    proof: &crate::installer_generation::GenerationProof<'_>,
) -> Result<BTreeMap<String, String>> {
    let mut expected = installer_renewal_bootstrap::current_inputs();
    expected.extend(["pending.json", "validated.json", "completed.json"].map(String::from));
    require(file_names(delivered)? == expected)?;
    let outputs = read_inputs(delivered)?;
    // Every transferred file is owned by this installer, not merely root-readable.
    for name in installer_renewal_bootstrap::current_inputs() {
        read_entry(delivered, &name, 0o444, false)?;
    }
    let mut records = BTreeMap::new();
    for name in ["pending.json", "validated.json", "completed.json"] {
        records.insert(name.into(), read_entry(delivered, name, 0o600, false)?);
    }
    crate::installer_generation::validate_records(&records, &outputs, proof)
}

fn require_directory_binding(path: &Path, held: &File) -> Result<()> {
    crate::installer_host_fs::require_directory_binding(path, held, REFUSAL)
}

fn open_child(parent: &File, name: &str, flags: i32) -> Result<File> {
    crate::installer_host_fs::open_child(parent, name, flags, REFUSAL)
}

fn validate_delivery(
    parent: &Path,
    held: &File,
    proof: &crate::installer_generation::GenerationProof<'_>,
) -> Result<BTreeMap<String, String>> {
    require_directory_binding(parent, held)?;
    require(
        file_names(held)?
            == BTreeSet::from([
                "transfer-pending.json".into(),
                "output".into(),
                "delivered".into(),
            ]),
    )?;
    for (name, is_dir, mode) in [
        ("output", true, 0o700),
        ("transfer-pending.json", false, 0o600),
    ] {
        let m = open_child(held, name, libc::O_PATH)?
            .metadata()
            .map_err(|_| REFUSAL)?;
        require(
            !m.file_type().is_symlink()
                && m.is_dir() == is_dir
                && (is_dir || (m.is_file() && m.nlink() == 1))
                && m.uid() == 0
                && m.mode() & 0o7777 == mode,
        )?;
    }
    let delivered = open_child(held, "delivered", libc::O_RDONLY | libc::O_DIRECTORY)?;
    let m = delivered.metadata().map_err(|_| REFUSAL)?;
    require(m.is_dir() && m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o7777 == 0o700)?;
    let result = validate_delivered(&delivered, proof)?;
    require_directory_binding(parent, held)?;
    Ok(result)
}

fn environment_map(value: &Value) -> Result<BTreeMap<String, String>> {
    crate::installer_container::environment_map(value, REFUSAL)
}
// The image is digest-admitted; no host environment is inherited. This fixed
// native helper receives its authority through readonly files, never env values.
fn bootstrap_environment(inherited: &Value) -> Result<BTreeMap<String, String>> {
    crate::installer_container::bootstrap_environment(inherited, REFUSAL)
}

/// Caller has authenticated the shared gateway/signing-keys services digest.
/// Every failure preserves owned intent/container/output; never resumes minting.
pub fn provision(
    dockerpath: &Path,
    installation: &Path,
    bundle: &Path,
    state: &mut InstallerState,
    bao: &OpenBaoInventory,
    services_image: &str,
    expected_operator_sha: &str,
) -> Result<GenerationReceipt> {
    state.require_live_phase(Phase::Provisioning)?;
    require(InstallerState::inspect(installation)? == *state.journal())?;
    require(
        regex::Regex::new(r"\Aghcr\.io/elevenid/marty-ui-oss/services@sha256:[0-9a-f]{64}\z")
            .unwrap()
            .is_match(services_image),
    )?;
    let binding = state.journal().runtime().ok_or(REFUSAL)?.clone();
    let docker = DockerRunner::new(
        dockerpath,
        &binding.docker_host,
        &binding.engine_id,
        installation,
    )?;
    installer_openbao::verify_observation(&docker, installation, bundle, state, bao)?;
    let operator = installation.join("marty-deploy");
    require(installer_verify::operator_digest(&operator)? == expected_operator_sha)?;
    let secrets = directory(&installation.join("secrets"))?;

    let owner = state.journal().installation_id().to_string();
    crate::installer_ingress_provision::resource_name(&owner)?;
    let evidence = directory(&installation.join("evidence"))?;
    let keycloak_receipt = read_entry(&evidence, "keycloak-observation.json", 0o600, false)?;
    crate::installer_generation::original_nonce(&keycloak_receipt, &owner)?;
    require(
        keycloak_receipt == read_entry(&evidence, "keycloak-container-removed.json", 0o600, false)?,
    )?;
    let kc: Value = serde_json::from_slice(&keycloak_receipt).map_err(|_| REFUSAL)?;
    require(
        kc["engine_id"] == binding.engine_id
            && kc["network_id"] == bao.network_id
            && kc["image"] == bao.image,
    )?;
    let renewal_receipt = read_entry(&evidence, "renewal-container-removed.json", 0o600, false)?;
    let renewal: RenewalEvidence = serde_json::from_slice(&renewal_receipt).map_err(|_| REFUSAL)?;
    require(
        renewal.schema == "elevenid.installer-renewal-host/v1"
            && renewal.installation_id == owner
            && renewal.engine_id == binding.engine_id
            && renewal.network_id == bao.network_id
            && renewal.image == services_image
            && renewal.container_name
                == format!("{}-renewal-inputs", state.journal().compose_project())
            && id(&renewal.container_id)
            && renewal.container_removed
            && renewal.private_identity_validated
            && !renewal.root_retired
            && !renewal.ingress_renewal
            && !renewal.installation_ready
            && renewal.outputs == IDENTITY_FILES,
    )?;
    for previous in [
        kc["container_id"].as_str().ok_or(REFUSAL)?,
        renewal.container_id.as_str(),
    ] {
        require(
            docker
                .run_checked(&[
                    "ps",
                    "-aq",
                    "--no-trunc",
                    "--filter",
                    &format!("id={previous}"),
                ])?
                .trim()
                .is_empty(),
        )?;
    }
    let identity_source_path = installation.join("renewal-transfer/delivered");
    let identity_source = directory(&identity_source_path)?;
    let identity_snapshot = read_identity(&identity_source)?;
    let name = format!("{}-generation-inputs", state.journal().compose_project());
    let name_filter = format!("name=^/{name}$");
    let owner_filter = format!("label=com.elevenid.installer.id={owner}");
    for filters in [
        vec!["ps", "-aq", "--filter", &name_filter],
        vec![
            "ps",
            "-aq",
            "--filter",
            &owner_filter,
            "--filter",
            "label=com.elevenid.installer.stage=generation",
        ],
    ] {
        require(docker.run_checked(&filters)?.trim().is_empty())?;
    }
    // Pull is bounded and precedes remote KMS mutation; no registry credentials.
    docker.run_checked_with_timeout(&["pull", services_image], Duration::from_secs(600))?;
    let local: Value =
        serde_json::from_str(&docker.run_checked(&["image", "inspect", services_image])?)
            .map_err(|_| REFUSAL)?;
    let images = local.as_array().ok_or(REFUSAL)?;
    require(
        images.len() == 1
            && empty_or_null(&images[0]["Config"]["Volumes"])
            && images[0]["RepoDigests"]
                .as_array()
                .is_some_and(|v| v.contains(&json!(services_image))),
    )?;
    let image_id = images[0]["Id"].as_str().ok_or(REFUSAL)?.to_owned();
    require(image_id.strip_prefix("sha256:").is_some_and(id))?;
    let environment = bootstrap_environment(&images[0]["Config"]["Env"])?;
    let output = installation.join("generation-transfer");
    let contract = Contract {
        name,
        owner,
        image: services_image.into(),
        image_id,
        network_id: bao.network_id.clone(),
        network_name: bao.network_name.clone(),
        environment,
        mounts: BTreeMap::from([
            ("/input/marty-deploy".into(), (operator, true)),
            (
                "/input/identity".into(),
                (installation.join("generation-identity"), true),
            ),
            (
                "/input/ca.crt".into(),
                (installation.join("openbao-state/tls/ca.crt"), true),
            ),
            ("/transfer".into(), (output.clone(), false)),
            (
                "/input/keycloak-receipt.json".into(),
                (
                    installation.join("evidence/keycloak-observation.json"),
                    true,
                ),
            ),
            (
                "/input/current".into(),
                (installation.join("generation-inputs"), true),
            ),
        ]),
    };
    let args = command(&contract)?;
    state.create_private_directory("generation-transfer")?;
    state.create_private_directory("generation-inputs")?;
    state.create_private_directory("generation-identity")?;
    let identity_staged = directory(&installation.join("generation-identity"))?;
    stage_identity(&identity_snapshot, &identity_staged)?;
    let source_snapshot = stage_inputs(
        &secrets,
        &directory(&installation.join("generation-inputs"))?,
    )?;
    let output_directory = directory(&output)?;
    let intent = json!({"schema":"elevenid.installer-generation-host-intent/v1","installation_id":contract.owner,"container_name":contract.name,"image":contract.image,"image_id":contract.image_id,"network_id":contract.network_id,"engine_id":binding.engine_id,"operator_sha256":expected_operator_sha,"mounts":contract.mounts,"environment":contract.environment,
        "keycloak_receipt_sha256":format!("{:x}",Sha256::digest(&keycloak_receipt)),
        "renewal_receipt_sha256":format!("{:x}",Sha256::digest(&renewal_receipt)),
        "input_sha256":crate::installer_generation::hashes(&source_snapshot),"identity_sha256":crate::installer_generation::hashes(&identity_snapshot)});
    state.write_evidence(
        "generation-pending.json",
        &serde_json::to_vec(&intent).map_err(|_| REFUSAL)?,
    )?;
    state.require_live_phase(Phase::Provisioning)?;
    installer_openbao::verify_observation(&docker, installation, bundle, state, bao)?;
    let created = run(&docker, &args)?;
    let container = created.trim();
    require(id(container))?;
    state.write_evidence("generation-container.json",&serde_json::to_vec(&json!({"container_id":container,"container_name":contract.name,"engine_id":binding.engine_id})).map_err(|_|REFUSAL)?)?;
    validate_observation(&inspect(&docker, container)?, container, &contract, false)?;
    require(
        installer_verify::operator_digest(&installation.join("marty-deploy"))?
            == expected_operator_sha,
    )?;
    state.require_live_phase(Phase::Provisioning)?;
    let staged = directory(&installation.join("generation-inputs"))?;
    require_directory_binding(&installation.join("secrets"), &secrets)?;
    require_directory_binding(&identity_source_path, &identity_source)?;
    require_directory_binding(&installation.join("evidence"), &evidence)?;
    require_directory_binding(&installation.join("generation-identity"), &identity_staged)?;
    require(
        read_identity(&identity_source)? == identity_snapshot
            && staged_identity(&identity_staged)? == identity_snapshot
            && read_entry(&evidence, "keycloak-observation.json", 0o600, false)?
                == keycloak_receipt
            && read_entry(&evidence, "renewal-container-removed.json", 0o600, false)?
                == renewal_receipt,
    )?;
    require_directory_binding(&output, &output_directory)?;
    require(
        file_names(&staged)? == installer_renewal_bootstrap::current_inputs()
            && read_inputs(&staged)? == source_snapshot
            && read_inputs(&secrets)? == source_snapshot,
    )?;
    docker.run_checked(&["start", container])?;
    require(
        docker
            .run_checked_with_timeout(&["wait", container], Duration::from_secs(900))?
            .trim()
            == "0",
    )?;
    validate_observation(&inspect(&docker, container)?, container, &contract, true)?;
    installer_openbao::verify_observation(&docker, installation, bundle, state, bao)?;
    state.require_live_phase(Phase::Provisioning)?;
    require_directory_binding(&installation.join("secrets"), &secrets)?;
    require_directory_binding(&installation.join("generation-inputs"), &staged)?;
    require_directory_binding(&identity_source_path, &identity_source)?;
    require_directory_binding(&installation.join("evidence"), &evidence)?;
    require_directory_binding(&installation.join("generation-identity"), &identity_staged)?;
    require(
        read_inputs(&secrets)? == source_snapshot
            && read_inputs(&staged)? == source_snapshot
            && read_identity(&identity_source)? == identity_snapshot
            && staged_identity(&identity_staged)? == identity_snapshot
            && read_entry(&evidence, "keycloak-observation.json", 0o600, false)?
                == keycloak_receipt
            && read_entry(&evidence, "renewal-container-removed.json", 0o600, false)?
                == renewal_receipt,
    )?;
    let proof = crate::installer_generation::GenerationProof {
        owner: &contract.owner,
        current: &source_snapshot,
        identity: &identity_snapshot,
        keycloak_receipt: &keycloak_receipt,
    };
    let delivered = validate_delivery(&output, &output_directory, &proof)?;
    drop(output_directory);
    let mut receipt = GenerationReceipt {
        schema: "elevenid.installer-generation-host/v1",
        installation_id: contract.owner.clone(),
        engine_id: binding.engine_id,
        container_id: container.to_owned(),
        container_name: contract.name.clone(),
        network_id: contract.network_id.clone(),
        image: contract.image.clone(),
        root_retired: false,
        ingress_renewal: false,
        candidate_validated: true,
        activated: false,
        candidate_sha256: delivered.clone(),
        outputs: delivered.keys().cloned().collect(),
        container_removed: false,
        installation_ready: false,
    };
    state.write_evidence(
        "generation-result.json",
        &serde_json::to_vec(&receipt).map_err(|_| REFUSAL)?,
    )?;
    validate_observation(&inspect(&docker, container)?, container, &contract, true)?;
    state.require_live_phase(Phase::Provisioning)?;
    docker.run_checked(&["rm", container])?;
    let filter = format!("id={container}");
    require(
        docker
            .run_checked(&["ps", "-aq", "--no-trunc", "--filter", &filter])?
            .trim()
            .is_empty(),
    )?;
    receipt.container_removed = true;
    state.write_evidence(
        "generation-container-removed.json",
        &serde_json::to_vec(&receipt).map_err(|_| REFUSAL)?,
    )?;
    Ok(receipt)
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    const OWNER: &str = "12345678-1234-4234-8234-123456789abc";
    fn contract() -> Contract {
        Contract {
            name: "owned-generation-inputs".into(),
            owner: OWNER.into(),
            image: format!(
                "ghcr.io/elevenid/marty-ui-oss/services@sha256:{}",
                "a".repeat(64)
            ),
            image_id: format!("sha256:{}", "b".repeat(64)),
            network_id: "c".repeat(64),
            network_name: "owned-bao_default".into(),
            environment: bootstrap_environment(&json!([
                "PATH=/usr/local/bin:/usr/bin:/bin",
                "SERVICE_NAME=all",
                "MARTY_RELEASE_VERSION=v1.2.3"
            ]))
            .unwrap(),
            mounts: BTreeMap::from([
                (
                    "/input/keycloak-receipt.json".into(),
                    (
                        PathBuf::from("/owned/evidence/keycloak-observation.json"),
                        true,
                    ),
                ),
                (
                    "/input/current".into(),
                    (PathBuf::from("/owned/generation-inputs"), true),
                ),
                (
                    "/input/marty-deploy".into(),
                    (PathBuf::from("/owned/marty-deploy"), true),
                ),
                (
                    "/input/identity".into(),
                    (PathBuf::from("/owned/generation-identity"), true),
                ),
                (
                    "/input/ca.crt".into(),
                    (PathBuf::from("/owned/openbao-state/tls/ca.crt"), true),
                ),
                (
                    "/transfer".into(),
                    (PathBuf::from("/owned/generation-transfer"), false),
                ),
            ]),
        }
    }
    fn observed(c: &Contract, terminal: bool) -> Value {
        let env: Vec<_> = c
            .environment
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
        let mounts:Vec<_>=c.mounts.iter().map(|(target,(source,readonly))|json!({"Type":"bind","Source":source,"Destination":target,"RW":!readonly})).collect();
        let mut networks = serde_json::Map::new();
        networks.insert(
            c.network_name.clone(),
            json!({"NetworkID":if terminal {c.network_id.clone()} else {String::new()}}),
        );
        json!({"Id":"d".repeat(64),"Image":c.image_id,"Name":format!("/{}",c.name),"Config":{"Image":c.image,"User":"0:0","Entrypoint":["/input/marty-deploy"],"Cmd":["installer-generation-provision-transfer","--installation-id",c.owner],"Env":env,"Labels":{"com.elevenid.installer.id":c.owner,"com.elevenid.installer.stage":"generation"}},
            "HostConfig":{"ReadonlyRootfs":true,"Privileged":false,"CapDrop":["ALL"],"CapAdd":["DAC_OVERRIDE","CHOWN"],"SecurityOpt":["no-new-privileges"],"NetworkMode":c.network_id,"AutoRemove":false,"RestartPolicy":{"Name":"no"},"PidMode":"","UsernsMode":"","IpcMode":"private","Binds":null,"PortBindings":{},"Devices":[],"DeviceRequests":null,"Tmpfs":null},"NetworkSettings":{"Networks":networks},"Mounts":mounts,"State":{"Running":false,"Status":if terminal {"exited"} else {"created"},"ExitCode":0,"OOMKilled":false}})
    }
    #[test]
    fn fixed_native_command_has_only_scoped_inputs_no_shell_or_cleanup_flags() {
        let mut c = contract();
        let args = command(&c).unwrap();
        assert_eq!(
            &args[args.len() - 3..],
            &[
                "installer-generation-provision-transfer".to_string(),
                "--installation-id".into(),
                OWNER.into()
            ]
        );
        assert_eq!(args.iter().filter(|v| v.as_str() == "--mount").count(), 6);
        assert!(args
            .windows(2)
            .any(|w| w == ["--entrypoint", "/input/marty-deploy"]));
        assert!(!args.iter().any(|v| {
            [
                "--rm",
                "--force",
                "--privileged",
                "--tmpfs",
                "/bin/sh",
                "-ec",
            ]
            .contains(&v.as_str())
        }));
        assert!(!args.iter().any(|v| v.contains("/var/run/docker.sock")));
        c.mounts.get_mut("/transfer").unwrap().0 = "/unsafe,source".into();
        assert!(command(&c).is_err());
        c = contract();
        c.owner = "--other-option".into();
        assert!(command(&c).is_err());
    }
    #[test]
    fn image_environment_is_exact_and_authority_or_proxy_overrides_are_refused() {
        for env in [
            json!(["PATH=a", "PATH=b"]),
            json!(["BAO_TOKEN=secret"]),
            json!(["http_proxy=http://foreign"]),
            json!(["LD_PRELOAD=/foreign"]),
            json!(["SELFHOST_TLS_OUTPUT_DIR=/foreign"]),
            json!(["PATH=a\nb"]),
        ] {
            assert!(bootstrap_environment(&env).is_err());
        }
        assert_eq!(contract().environment["SERVICE_NAME"], "all");
    }
    #[test]
    fn observation_refuses_authority_mount_execution_and_lifecycle_drift() {
        let c = contract();
        let container = "d".repeat(64);
        validate_observation(&observed(&c, false), &container, &c, false).unwrap();
        validate_observation(&observed(&c, true), &container, &c, true).unwrap();
        for (pointer, value) in [
            (
                "/Config/Cmd",
                json!([
                    "installer-generation-provision-transfer",
                    "--installation-id",
                    "wrong"
                ]),
            ),
            ("/Config/Entrypoint", json!(["/bin/sh"])),
            ("/Config/User", json!("1000:1000")),
            ("/Config/Labels/com.elevenid.installer.stage", json!("tls")),
            ("/HostConfig/CapAdd", json!(["SYS_ADMIN"])),
            ("/HostConfig/UsernsMode", json!("host")),
            ("/HostConfig/NetworkMode", json!("host")),
            ("/HostConfig/ReadonlyRootfs", json!(false)),
            ("/HostConfig/AutoRemove", json!(true)),
            ("/HostConfig/Tmpfs", json!({"/tmp":"rw"})),
            ("/Image", json!("wrong")),
            ("/State/Running", json!(true)),
            ("/State/ExitCode", json!(1)),
            ("/State/OOMKilled", json!(true)),
        ] {
            let mut value_model = observed(&c, true);
            *value_model.pointer_mut(pointer).unwrap() = value;
            assert!(
                validate_observation(&value_model, &container, &c, true).is_err(),
                "accepted {pointer}"
            );
        }
        for mutation in [
            "source",
            "write-input",
            "extra-mount",
            "duplicate",
            "terminal-empty-network",
            "extra-network",
            "environment",
        ] {
            let mut v = observed(&c, true);
            match mutation {
                "source" => v["Mounts"][0]["Source"] = json!("/foreign"),
                "write-input" => v["Mounts"][0]["RW"] = json!(true),
                "extra-mount" => v["Mounts"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"Type":"bind","Source":"/","Destination":"/host","RW":false})),
                "duplicate" => {
                    let first = v["Mounts"][0].clone();
                    v["Mounts"].as_array_mut().unwrap().push(first);
                }
                "terminal-empty-network" => {
                    v["NetworkSettings"]["Networks"][&c.network_name]["NetworkID"] = json!("")
                }
                "extra-network" => {
                    v["NetworkSettings"]["Networks"]["foreign"] =
                        json!({"NetworkID":"e".repeat(64)})
                }
                _ => v["Config"]["Env"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!("BAO_TOKEN=secret")),
            }
            assert!(
                validate_observation(&v, &container, &c, true).is_err(),
                "accepted {mutation}"
            );
        }
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
    #[test]
    fn held_transfer_binding_refuses_same_mode_replacement() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = temp.path().join("transfer");
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let held = directory(&path).unwrap();
        require_directory_binding(&path, &held).unwrap();
        std::fs::rename(&path, temp.path().join("original")).unwrap();
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(require_directory_binding(&path, &held).is_err());
    }
    #[test]
    fn identity_staging_is_private_exclusive_and_exact() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let dir = directory(temp.path()).unwrap();
        let values = IDENTITY_FILES
            .into_iter()
            .map(|name| (name.to_owned(), format!("synthetic-{name}").into_bytes()))
            .collect();
        stage_identity(&values, &dir).unwrap();
        assert_eq!(staged_identity(&dir).unwrap(), values);
        assert!(stage_identity(&values, &dir).is_err());
        for name in IDENTITY_FILES {
            assert_eq!(
                std::fs::metadata(temp.path().join(name)).unwrap().mode() & 0o7777,
                0o600
            );
        }
        std::fs::write(temp.path().join("extra"), b"extra").unwrap();
        assert!(staged_identity(&dir).is_err());
    }
}
