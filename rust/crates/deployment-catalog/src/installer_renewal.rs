//! Owned one-shot renewal authority bootstrap, never root retirement. Never retries a mutation or removes an
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
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::Duration,
};
type Result<T> = std::result::Result<T, String>;
const REFUSAL: &str = "Renewal provisioning refused; preserve installation state for recovery";
#[derive(Serialize)]
pub struct RenewalReceipt {
    pub schema: &'static str,
    pub installation_id: String,
    pub engine_id: String,
    pub container_id: String,
    pub container_name: String,
    pub network_id: String,
    pub image: String,
    pub root_retired: bool,
    pub ingress_renewal: bool,
    pub private_identity_validated: bool,
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
        "com.elevenid.installer.stage=renewal".into(),
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
        "installer-renewal-bootstrap-transfer".into(),
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
            stage: "renewal",
            entrypoint: json!(["/input/marty-deploy"]),
            command: json!([
                "installer-renewal-bootstrap-transfer",
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    schema: String,
    installation_id: String,
    root_retired: bool,
    ingress_renewal: bool,
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
}
const IDENTITY_FILES: [&str; 3] = [
    "renewal-role-id",
    "renewal-secret-id",
    "renewal-leaf-policies.json",
];

fn require_directory_binding(path: &Path, held: &File) -> Result<()> {
    crate::installer_host_fs::require_directory_binding(path, held, REFUSAL)
}

fn open_child(parent: &File, name: &str, flags: i32) -> Result<File> {
    crate::installer_host_fs::open_child(parent, name, flags, REFUSAL)
}

fn validate_delivery(parent: &Path, held: &File, owner: &str) -> Result<Vec<String>> {
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
    let result = validate_delivered(&delivered, owner)?;
    require_directory_binding(parent, held)?;
    Ok(result)
}

fn validate_delivered(delivered: &File, owner: &str) -> Result<Vec<String>> {
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
        pending.schema == "elevenid.installer-renewal-bootstrap-intent/v1"
            && pending.installation_id == owner
            && !pending.root_retired
            && !pending.ingress_renewal,
    )?;
    let completed: Completed =
        serde_json::from_slice(&read_entry(delivered, "completed.json", 0o600, false)?)
            .map_err(|_| REFUSAL)?;
    require(
        completed.schema == "elevenid.installer-renewal-bootstrap-result/v1"
            && completed.installation_id == owner
            && completed.identity_files == IDENTITY_FILES
            && completed.policy_count == 21
            && completed.scoped_login_verified
            && completed.verification_token_revoked
            && !completed.root_retired
            && !completed.ingress_renewal,
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
        policies.len() == 21
            && policies.iter().collect::<BTreeSet<_>>().len() == 21
            && policies.iter().all(|v| {
                !v.is_empty()
                    && v.len() <= 160
                    && !["root", "default", "selfhost-kms-renewal"].contains(&v.as_str())
                    && v.bytes()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
            }),
    )?;
    Ok(IDENTITY_FILES.map(String::from).to_vec())
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
) -> Result<RenewalReceipt> {
    state.require_live_phase(Phase::Provisioning)?;
    require(InstallerState::inspect(installation)? == *state.journal())?;
    require(
        regex::Regex::new(r"\Aghcr\.io/elevenid/marty-ui-oss/services@sha256:[0-9a-f]{64}\z")
            .unwrap()
            .is_match(services_image),
    )?;
    let binding = state.journal().runtime().ok_or(REFUSAL)?.clone();
    let docker = DockerRunner::from_binding(dockerpath, &binding, installation)?;
    installer_openbao::verify_observation(&docker, installation, bundle, state, bao)?;
    let operator = installation.join("marty-deploy");
    require(installer_verify::operator_digest(&operator)? == expected_operator_sha)?;
    let secrets = directory(&installation.join("secrets"))?;

    let owner = state.journal().installation_id().to_string();
    crate::installer_ingress_provision::resource_name(&owner)?;
    let name = format!("{}-renewal-inputs", state.journal().compose_project());
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
            "label=com.elevenid.installer.stage=renewal",
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
    let output = installation.join("renewal-transfer");
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
                "/input/root.token".into(),
                (installation.join("openbao-state/root.token"), true),
            ),
            (
                "/input/ca.crt".into(),
                (installation.join("openbao-state/tls/ca.crt"), true),
            ),
            ("/transfer".into(), (output.clone(), false)),
            (
                "/input/current".into(),
                (installation.join("renewal-inputs"), true),
            ),
        ]),
    };
    let args = command(&contract)?;
    state.create_private_directory("renewal-transfer")?;
    state.create_private_directory("renewal-inputs")?;
    let source_snapshot =
        stage_inputs(&secrets, &directory(&installation.join("renewal-inputs"))?)?;
    let output_directory = directory(&output)?;
    let intent = json!({"schema":"elevenid.installer-renewal-intent/v1","installation_id":contract.owner,"container_name":contract.name,"image":contract.image,"image_id":contract.image_id,"network_id":contract.network_id,"engine_id":binding.engine_id,"operator_sha256":expected_operator_sha,"mounts":contract.mounts,"environment":contract.environment});
    state.write_evidence(
        "renewal-pending.json",
        &serde_json::to_vec(&intent).map_err(|_| REFUSAL)?,
    )?;
    state.require_live_phase(Phase::Provisioning)?;
    installer_openbao::verify_observation(&docker, installation, bundle, state, bao)?;
    let created = run(&docker, &args)?;
    let container = created.trim();
    require(id(container))?;
    state.write_evidence("renewal-container.json",&serde_json::to_vec(&json!({"container_id":container,"container_name":contract.name,"engine_id":binding.engine_id})).map_err(|_|REFUSAL)?)?;
    validate_observation(&inspect(&docker, container)?, container, &contract, false)?;
    require(
        installer_verify::operator_digest(&installation.join("marty-deploy"))?
            == expected_operator_sha,
    )?;
    state.require_live_phase(Phase::Provisioning)?;
    let staged = directory(&installation.join("renewal-inputs"))?;
    require_directory_binding(&output, &output_directory)?;
    require(
        file_names(&staged)? == installer_renewal_bootstrap::current_inputs()
            && read_inputs(&staged)? == source_snapshot
            && read_inputs(&secrets)? == source_snapshot,
    )?;
    docker.run_checked(&["start", container])?;
    require(
        docker
            .run_checked_with_timeout(&["wait", container], Duration::from_secs(600))?
            .trim()
            == "0",
    )?;
    validate_observation(&inspect(&docker, container)?, container, &contract, true)?;
    installer_openbao::verify_observation(&docker, installation, bundle, state, bao)?;
    state.require_live_phase(Phase::Provisioning)?;
    require(read_inputs(&secrets)? == source_snapshot)?;
    let delivered = validate_delivery(&output, &output_directory, &contract.owner)?;
    drop(output_directory);
    let mut receipt = RenewalReceipt {
        schema: "elevenid.installer-renewal-host/v1",
        installation_id: contract.owner.clone(),
        engine_id: binding.engine_id,
        container_id: container.to_owned(),
        container_name: contract.name.clone(),
        network_id: contract.network_id.clone(),
        image: contract.image.clone(),
        root_retired: false,
        ingress_renewal: false,
        private_identity_validated: true,
        outputs: delivered,
        container_removed: false,
        installation_ready: false,
    };
    state.write_evidence(
        "renewal-result.json",
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
        "renewal-container-removed.json",
        &serde_json::to_vec(&receipt).map_err(|_| REFUSAL)?,
    )?;
    Ok(receipt)
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    const OWNER: &str = "12345678-1234-4234-8234-123456789abc";
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
        assert!(validate_delivery(&transfer, &held, OWNER).is_err());
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
        assert_eq!(validate_delivered(&dir, OWNER).unwrap().len(), 3);
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
            assert!(validate_delivered(&dir, OWNER).is_err());
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
        assert!(validate_delivered(&dir, OWNER).is_err());
        std::fs::set_permissions(
            temp.path().join("renewal-secret-id"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        put(temp.path(), "unexpected", b"extra", 0o600);
        assert!(validate_delivered(&dir, OWNER).is_err());
    }
    fn contract() -> Contract {
        Contract {
            name: "owned-renewal-inputs".into(),
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
                    "/input/current".into(),
                    (PathBuf::from("/owned/renewal-inputs"), true),
                ),
                (
                    "/input/marty-deploy".into(),
                    (PathBuf::from("/owned/marty-deploy"), true),
                ),
                (
                    "/input/root.token".into(),
                    (PathBuf::from("/owned/openbao-state/root.token"), true),
                ),
                (
                    "/input/ca.crt".into(),
                    (PathBuf::from("/owned/openbao-state/tls/ca.crt"), true),
                ),
                (
                    "/transfer".into(),
                    (PathBuf::from("/owned/renewal-transfer"), false),
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
        json!({"Id":"d".repeat(64),"Image":c.image_id,"Name":format!("/{}",c.name),"Config":{"Image":c.image,"User":"0:0","Entrypoint":["/input/marty-deploy"],"Cmd":["installer-renewal-bootstrap-transfer","--installation-id",c.owner],"Env":env,"Labels":{"com.elevenid.installer.id":c.owner,"com.elevenid.installer.stage":"renewal"}},
            "HostConfig":{"ReadonlyRootfs":true,"Privileged":false,"CapDrop":["ALL"],"CapAdd":["DAC_OVERRIDE","CHOWN"],"SecurityOpt":["no-new-privileges"],"NetworkMode":c.network_id,"AutoRemove":false,"RestartPolicy":{"Name":"no"},"PidMode":"","UsernsMode":"","IpcMode":"private","Binds":null,"PortBindings":{},"Devices":[],"DeviceRequests":null,"Tmpfs":null},"NetworkSettings":{"Networks":networks},"Mounts":mounts,"State":{"Running":false,"Status":if terminal {"exited"} else {"created"},"ExitCode":0,"OOMKilled":false}})
    }
    #[test]
    fn fixed_native_command_has_only_scoped_inputs_no_shell_or_cleanup_flags() {
        let mut c = contract();
        let args = command(&c).unwrap();
        assert_eq!(
            &args[args.len() - 3..],
            &[
                "installer-renewal-bootstrap-transfer".to_string(),
                "--installation-id".into(),
                OWNER.into()
            ]
        );
        assert_eq!(args.iter().filter(|v| v.as_str() == "--mount").count(), 5);
        assert!(args
            .windows(2)
            .any(|w| w == ["--entrypoint", "/input/marty-deploy"]));
        assert!(!args.iter().any(|v| [
            "--rm",
            "--force",
            "--privileged",
            "--tmpfs",
            "/bin/sh",
            "-ec"
        ]
        .contains(&v.as_str())));
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
                    "installer-renewal-bootstrap-transfer",
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
}
