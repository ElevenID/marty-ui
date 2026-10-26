//! Owned one-shot ingress provisioning. Never retries a mutation or removes an
//! uncertain container. Durable intent, ID and outputs survive every failure.
#![cfg(target_os = "linux")]
use crate::{
    installer_ingress_outputs,
    installer_openbao::{self, OpenBaoInventory},
    installer_runtime::DockerRunner,
    installer_state::{InstallerState, Phase},
    installer_verify,
};
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::Duration,
};
type Result<T> = std::result::Result<T, String>;
const REFUSAL: &str = "Ingress provisioning refused; preserve installation state for recovery";
#[derive(Serialize)]
pub struct IngressReceipt {
    pub schema: &'static str,
    pub installation_id: String,
    pub engine_id: String,
    pub container_id: String,
    pub container_name: String,
    pub network_id: String,
    pub image: String,
    pub authority_name: String,
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
        "--security-opt".into(),
        "no-new-privileges".into(),
        "--restart=no".into(),
        "--label".into(),
        format!("com.elevenid.installer.id={}", contract.owner),
        "--label".into(),
        "com.elevenid.installer.stage=ingress".into(),
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
        "installer-ingress-provision".into(),
        "--installation-id".into(),
        contract.owner.clone(),
    ]);
    Ok(args)
}
fn run(docker: &DockerRunner, args: &[String]) -> Result<String> {
    docker.run_checked(&args.iter().map(String::as_str).collect::<Vec<_>>())
}
fn inspect(docker: &DockerRunner, container: &str) -> Result<Value> {
    let result: Value =
        serde_json::from_str(&docker.run_checked(&["inspect", container])?).map_err(|_| REFUSAL)?;
    let list = result.as_array().ok_or(REFUSAL)?;
    require(list.len() == 1)?;
    Ok(list[0].clone())
}
fn empty_or_null(value: &Value) -> bool {
    value.is_null()
        || value.as_array().is_some_and(Vec::is_empty)
        || value.as_object().is_some_and(serde_json::Map::is_empty)
}
fn validate_observation(
    c: &Value,
    container: &str,
    contract: &Contract,
    terminal: bool,
) -> Result<()> {
    let host = &c["HostConfig"];
    let config = &c["Config"];
    require(
        c["Id"] == container
            && c["Image"] == contract.image_id
            && c["Name"] == format!("/{}", contract.name)
            && config["Image"] == contract.image
            && config["User"] == "0:0"
            && config["Entrypoint"] == json!(["/input/marty-deploy"])
            && config["Cmd"]
                == json!([
                    "installer-ingress-provision",
                    "--installation-id",
                    contract.owner
                ])
            && config["Labels"]["com.elevenid.installer.id"] == contract.owner
            && config["Labels"]["com.elevenid.installer.stage"] == "ingress"
            && host["ReadonlyRootfs"] == true
            && host["Privileged"] == false
            && host["CapDrop"] == json!(["ALL"])
            && (host["CapAdd"] == json!(["DAC_OVERRIDE"])
                || host["CapAdd"] == json!(["CAP_DAC_OVERRIDE"]))
            && (host["SecurityOpt"] == json!(["no-new-privileges"])
                || host["SecurityOpt"] == json!(["no-new-privileges:true"]))
            && host["NetworkMode"] == contract.network_id
            && host["AutoRemove"] == false
            && host["RestartPolicy"]["Name"] == "no"
            && host["PidMode"].as_str().is_some_and(str::is_empty)
            && host["UsernsMode"].as_str().is_some_and(str::is_empty)
            && matches!(host["IpcMode"].as_str(), Some("private" | ""))
            && empty_or_null(&host["PortBindings"])
            && empty_or_null(&host["Devices"])
            && empty_or_null(&host["DeviceRequests"])
            && empty_or_null(&host["Binds"])
            && empty_or_null(&host["Tmpfs"]),
    )?;
    require(environment_map(&config["Env"])? == contract.environment)?;
    let networks = c["NetworkSettings"]["Networks"]
        .as_object()
        .ok_or(REFUSAL)?;
    require(networks.len() == 1 && networks.contains_key(&contract.network_name))?;
    let network_id = &networks[&contract.network_name]["NetworkID"];
    require(network_id == &json!(contract.network_id) || (!terminal && network_id == ""))?;
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
    require(mounts == contract.mounts && c["State"]["Running"] == false)?;
    if terminal {
        require(
            c["State"]["Status"] == "exited"
                && c["State"]["ExitCode"] == 0
                && c["State"]["OOMKilled"] == false,
        )?;
    } else {
        require(c["State"]["Status"] == "created")?;
    }
    Ok(())
}
fn directory(path: &Path) -> Result<File> {
    require(path.canonicalize().map_err(|_| REFUSAL)? == path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| REFUSAL)?;
    let metadata = file.metadata().map_err(|_| REFUSAL)?;
    require(
        metadata.is_dir()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o7777 == 0o700,
    )?;
    Ok(file)
}

fn environment_map(value: &Value) -> Result<BTreeMap<String, String>> {
    let mut result = BTreeMap::new();
    for item in value.as_array().ok_or(REFUSAL)? {
        let (key, value) = item
            .as_str()
            .ok_or(REFUSAL)?
            .split_once('=')
            .ok_or(REFUSAL)?;
        require(
            !key.is_empty()
                && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                && !value.chars().any(char::is_control)
                && result.insert(key.to_owned(), value.to_owned()).is_none(),
        )?;
    }
    Ok(result)
}
// The image is digest-admitted; no host environment is inherited. This fixed
// native helper receives its authority through readonly files, never env values.
fn bootstrap_environment(inherited: &Value) -> Result<BTreeMap<String, String>> {
    let environment = environment_map(inherited)?;
    require(!environment.keys().any(|key| {
        key.starts_with("BAO_")
            || key.starts_with("MARTY_TLS_")
            || key.starts_with("SELFHOST_")
            || [
                "HTTP_PROXY",
                "HTTPS_PROXY",
                "ALL_PROXY",
                "NO_PROXY",
                "LD_PRELOAD",
                "LD_LIBRARY_PATH",
            ]
            .contains(&key.to_ascii_uppercase().as_str())
    }))?;
    Ok(environment)
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
) -> Result<IngressReceipt> {
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
    installer_ingress_outputs::preflight(&secrets)?;
    let owner = state.journal().installation_id().to_string();
    let authority_name = crate::installer_ingress_provision::resource_name(&owner)?;
    let name = format!("{}-ingress-inputs", state.journal().compose_project());
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
            "label=com.elevenid.installer.stage=ingress",
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
            && images[0]["RepoDigests"]
                .as_array()
                .is_some_and(|v| v.contains(&json!(services_image))),
    )?;
    let image_id = images[0]["Id"].as_str().ok_or(REFUSAL)?.to_owned();
    require(image_id.strip_prefix("sha256:").is_some_and(id))?;
    let environment = bootstrap_environment(&images[0]["Config"]["Env"])?;
    let output = installation.join("ingress-output");
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
            ("/output".into(), (output.clone(), false)),
        ]),
    };
    let args = command(&contract)?;
    state.create_private_directory("ingress-output")?;
    let output_directory = directory(&output)?;
    let intent = json!({"schema":"elevenid.installer-ingress-intent/v1","installation_id":contract.owner,"container_name":contract.name,"authority_name":authority_name,"image":contract.image,"image_id":contract.image_id,"network_id":contract.network_id,"engine_id":binding.engine_id,"operator_sha256":expected_operator_sha,"mounts":contract.mounts,"environment":contract.environment});
    state.write_evidence(
        "ingress-pending.json",
        &serde_json::to_vec(&intent).map_err(|_| REFUSAL)?,
    )?;
    state.require_live_phase(Phase::Provisioning)?;
    installer_openbao::verify_observation(&docker, installation, bundle, state, bao)?;
    let created = run(&docker, &args)?;
    let container = created.trim();
    require(id(container))?;
    state.write_evidence("ingress-container.json",&serde_json::to_vec(&json!({"container_id":container,"container_name":contract.name,"engine_id":binding.engine_id})).map_err(|_|REFUSAL)?)?;
    validate_observation(&inspect(&docker, container)?, container, &contract, false)?;
    require(
        installer_verify::operator_digest(&installation.join("marty-deploy"))?
            == expected_operator_sha,
    )?;
    state.require_live_phase(Phase::Provisioning)?;
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
    let validated = installer_ingress_outputs::validate_and_transfer(
        &output_directory,
        &secrets,
        &contract.owner,
    )?;
    state.write_evidence("installer-ingress.json", &validated.metadata_bytes)?;
    let mut receipt = IngressReceipt {
        schema: "elevenid.installer-ingress-host/v1",
        installation_id: contract.owner.clone(),
        engine_id: binding.engine_id,
        container_id: container.to_owned(),
        container_name: contract.name.clone(),
        network_id: contract.network_id.clone(),
        image: contract.image.clone(),
        authority_name,
        outputs: validated.outputnames,
        container_removed: false,
        installation_ready: false,
    };
    state.write_evidence(
        "ingress-result.json",
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
        "ingress-container-removed.json",
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
            name: "owned-ingress-inputs".into(),
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
                    "/output".into(),
                    (PathBuf::from("/owned/ingress-output"), false),
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
        json!({"Id":"d".repeat(64),"Image":c.image_id,"Name":format!("/{}",c.name),"Config":{"Image":c.image,"User":"0:0","Entrypoint":["/input/marty-deploy"],"Cmd":["installer-ingress-provision","--installation-id",c.owner],"Env":env,"Labels":{"com.elevenid.installer.id":c.owner,"com.elevenid.installer.stage":"ingress"}},
            "HostConfig":{"ReadonlyRootfs":true,"Privileged":false,"CapDrop":["ALL"],"CapAdd":["DAC_OVERRIDE"],"SecurityOpt":["no-new-privileges"],"NetworkMode":c.network_id,"AutoRemove":false,"RestartPolicy":{"Name":"no"},"PidMode":"","UsernsMode":"","IpcMode":"private","Binds":null,"PortBindings":{},"Devices":[],"DeviceRequests":null,"Tmpfs":null},"NetworkSettings":{"Networks":networks},"Mounts":mounts,"State":{"Running":false,"Status":if terminal {"exited"} else {"created"},"ExitCode":0,"OOMKilled":false}})
    }
    #[test]
    fn fixed_native_command_has_only_scoped_inputs_no_shell_or_cleanup_flags() {
        let mut c = contract();
        let args = command(&c).unwrap();
        assert_eq!(
            &args[args.len() - 3..],
            &[
                "installer-ingress-provision".to_string(),
                "--installation-id".into(),
                OWNER.into()
            ]
        );
        assert_eq!(args.iter().filter(|v| v.as_str() == "--mount").count(), 4);
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
        c.mounts.get_mut("/output").unwrap().0 = "/unsafe,source".into();
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
                json!(["installer-ingress-provision", "--installation-id", "wrong"]),
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
