//! Owned one-shot TLS provisioning. Never retries a mutation or removes an
//! uncertain container. Durable intent, ID and outputs survive every failure.
#![cfg(target_os = "linux")]
use crate::{
    installer_helper_output,
    installer_openbao::{self, OpenBaoInventory},
    installer_runtime::DockerRunner,
    installer_state::{InstallerState, Phase},
    installer_tls_outputs, installer_verify,
};
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs::File,
    path::{Path, PathBuf},
    time::Duration,
};
type Result<T> = std::result::Result<T, String>;
const BOOTSTRAP: &str = "/usr/local/bin/marty-passport-tls-bootstrap >/dev/null 2>&1 && exec /input/marty-deploy installer-tls-finalize";
const REFUSAL: &str = "TLS provisioning refused; preserve installation state for recovery";
#[derive(Serialize)]
pub struct TlsReceipt {
    pub schema: &'static str,
    pub installation_id: String,
    pub engine_id: String,
    pub container_id: String,
    pub container_name: String,
    pub network_id: String,
    pub image: String,
    pub bootstrap_project: String,
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
    project: String,
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
        "com.elevenid.installer.stage=tls".into(),
        "--entrypoint".into(),
        "/bin/sh".into(),
        "--tmpfs".into(),
        "/tmp:rw,mode=1777".into(),
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
    args.extend([contract.image.clone(), "-ec".into(), BOOTSTRAP.into()]);
    Ok(args)
}
fn run(docker: &DockerRunner, args: &[String]) -> Result<String> {
    docker.run_checked(&args.iter().map(String::as_str).collect::<Vec<_>>())
}
fn inspect(docker: &DockerRunner, container: &str) -> Result<Value> {
    crate::installer_container::inspect(docker, container, REFUSAL)
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
            stage: "tls",
            entrypoint: json!(["/bin/sh"]),
            command: json!(["-ec", BOOTSTRAP]),
        },
        REFUSAL,
    )?;
    require(
        (host["CapAdd"] == json!(["DAC_OVERRIDE"])
            || host["CapAdd"] == json!(["CAP_DAC_OVERRIDE"]))
            && host["Tmpfs"] == json!({"/tmp":"rw,mode=1777"}),
    )?;
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
        if mount["Type"] == "tmpfs" {
            require(
                mount["Destination"] == "/tmp"
                    && mount["RW"] == true
                    && mount["Source"].as_str().is_none_or(str::is_empty),
            )?;
            require(!mounts.contains_key("/tmp"))?;
            mounts.insert("/tmp".into(), (PathBuf::new(), false));
            continue;
        }
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
    mounts.remove("/tmp");
    require(mounts == contract.mounts)?;
    crate::installer_container::validate_stopped_state(c, terminal, REFUSAL)?;
    Ok(())
}
fn directory(path: &Path) -> Result<File> {
    crate::installer_host_fs::directory(path, REFUSAL)
}

fn environment_map(value: &Value) -> Result<BTreeMap<String, String>> {
    crate::installer_container::environment_map(value, REFUSAL)
}
fn bootstrap_environment(inherited: &Value, project: &str) -> Result<BTreeMap<String, String>> {
    let mut environment = environment_map(inherited)?;
    require(!environment.keys().any(|key| {
        ["BAO_", "MARTY_TLS_", "MARTY_SELFHOST_", "SELFHOST_TLS_"]
            .iter()
            .any(|prefix| key.starts_with(prefix))
    }))?;
    for (key, value) in [
        ("BAO_ADDR", "https://openbao:8200"),
        ("BAO_CACERT", "/input/ca.crt"),
        ("BAO_ROOT_TOKEN_FILE", "/input/root.token"),
        ("MARTY_TLS_BOOTSTRAP_PROFILE", "selfhost-disposable"),
        ("MARTY_SELFHOST_DISPOSABLE_OPENBAO", "1"),
        ("MARTY_SELFHOST_PROJECT", project),
        ("SELFHOST_TLS_OUTPUT_DIR", "/output"),
    ] {
        environment.insert(key.into(), value.into());
    }
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
) -> Result<TlsReceipt> {
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
    installer_tls_outputs::preflight(&secrets, bundle)?;
    let owner = state.journal().installation_id().to_string();
    let project = format!(
        "marty-selfhost-disposable-{}",
        state.journal().installation_id().simple()
    );
    let name = format!("{}-tls-inputs", state.journal().compose_project());
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
            "label=com.elevenid.installer.stage=tls",
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
    let environment = bootstrap_environment(&images[0]["Config"]["Env"], &project)?;
    let output = installation.join("tls-output");
    let contract = Contract {
        name,
        owner,
        image: services_image.into(),
        image_id,
        network_id: bao.network_id.clone(),
        network_name: bao.network_name.clone(),
        project,
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
    state.create_private_directory("tls-output")?;
    let output_directory = directory(&output)?;
    let intent = json!({"schema":"elevenid.installer-tls-intent/v1","installation_id":contract.owner,"container_name":contract.name,"bootstrap_project":contract.project,"image":contract.image,"image_id":contract.image_id,"network_id":contract.network_id,"engine_id":binding.engine_id,"operator_sha256":expected_operator_sha,"mounts":contract.mounts,"environment":contract.environment});
    state.write_evidence(
        "tls-pending.json",
        &serde_json::to_vec(&intent).map_err(|_| REFUSAL)?,
    )?;
    state.require_live_phase(Phase::Provisioning)?;
    installer_openbao::verify_observation(&docker, installation, bundle, state, bao)?;
    let created = run(&docker, &args)?;
    let container = created.trim();
    require(id(container))?;
    state.write_evidence("tls-container.json",&serde_json::to_vec(&json!({"container_id":container,"container_name":contract.name,"engine_id":binding.engine_id})).map_err(|_|REFUSAL)?)?;
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
    let validated = installer_tls_outputs::validate_and_transfer(
        &output_directory,
        &secrets,
        bundle,
        installer_helper_output::expected_host_uid(&binding)?,
    )?;
    state.write_evidence("selfhost-tls-kms-roles.json", &validated.metadata_bytes)?;
    state.write_evidence(
        "selfhost-tls-kms.env.fragment",
        validated.env_fragment.as_bytes(),
    )?;
    let mut receipt = TlsReceipt {
        schema: "elevenid.installer-tls/v1",
        installation_id: contract.owner.clone(),
        engine_id: binding.engine_id,
        container_id: container.to_owned(),
        container_name: contract.name.clone(),
        network_id: contract.network_id.clone(),
        image: contract.image.clone(),
        bootstrap_project: contract.project.clone(),
        outputs: validated.outputnames,
        container_removed: false,
        installation_ready: false,
    };
    state.write_evidence(
        "tls-result.json",
        &serde_json::to_vec(&receipt).map_err(|_| REFUSAL)?,
    )?;
    validate_observation(&inspect(&docker, container)?, container, &contract, true)?;
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
        "tls-container-removed.json",
        &serde_json::to_vec(&receipt).map_err(|_| REFUSAL)?,
    )?;
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn contract() -> Contract {
        let project = "marty-selfhost-disposable-0123456789abcdef";
        Contract {
            name: "owned-tls-inputs".into(),
            owner: "installation-id".into(),
            image: format!(
                "ghcr.io/elevenid/marty-ui-oss/services@sha256:{}",
                "a".repeat(64)
            ),
            image_id: format!("sha256:{}", "b".repeat(64)),
            network_id: "c".repeat(64),
            network_name: "owned-bao_default".into(),
            project: project.into(),
            environment: bootstrap_environment(
                &json!(["PATH=/usr/local/bin:/usr/bin:/bin", "SERVICE_NAME=all"]),
                project,
            )
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
                    (PathBuf::from("/owned/tls-output"), false),
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
        json!({"Id":"d".repeat(64),"Image":c.image_id,"Name":format!("/{}",c.name),"Config":{"Image":c.image,"User":"0:0","Entrypoint":["/bin/sh"],"Cmd":["-ec",BOOTSTRAP],"Env":env,"Labels":{"com.elevenid.installer.id":c.owner,"com.elevenid.installer.stage":"tls"}},
            "HostConfig":{"ReadonlyRootfs":true,"Privileged":false,"CapDrop":["ALL"],"CapAdd":["DAC_OVERRIDE"],"SecurityOpt":["no-new-privileges"],"NetworkMode":c.network_id,"AutoRemove":false,"RestartPolicy":{"Name":"no"},"PidMode":"","UsernsMode":"","IpcMode":"private","Binds":null,"PortBindings":{},"Devices":[],"DeviceRequests":null,"Tmpfs":{"/tmp":"rw,mode=1777"}},"NetworkSettings":{"Networks":networks},"Mounts":mounts,"State":{"Running":false,"Status":if terminal {"exited"} else {"created"},"ExitCode":0,"OOMKilled":false}})
    }
    #[test]
    fn create_uses_fixed_shell_finalizer_and_narrow_mounts() {
        let mut c = contract();
        let args = command(&c).unwrap();
        assert_eq!(
            &args[args.len() - 2..],
            &["-ec".to_owned(), BOOTSTRAP.to_owned()]
        );
        assert!(BOOTSTRAP.contains(" >/dev/null 2>&1 && exec "));
        assert_eq!(args.iter().filter(|v| v.as_str() == "--mount").count(), 4);
        assert!(args.contains(&"/tmp:rw,mode=1777".into()));
        assert!(!args
            .iter()
            .any(|v| v == "--rm" || v == "--force" || v == "--privileged"));
        c.mounts.get_mut("/output").unwrap().0 = PathBuf::from("/unsafe,source");
        assert!(command(&c).is_err());
    }
    #[test]
    fn environment_refuses_duplicates_controls_and_bootstrap_overrides() {
        for input in [
            json!(["PATH=a", "PATH=b"]),
            json!(["MARTY_SELFHOST_WORKLOAD_PKI_MOUNT=other"]),
            json!(["BAO_TOKEN=secret"]),
            json!(["PATH=a\nb"]),
        ] {
            assert!(bootstrap_environment(&input, "marty-selfhost-disposable-owned").is_err());
        }
        let c = contract();
        assert_eq!(c.environment["BAO_ADDR"], "https://openbao:8200");
        assert_eq!(c.environment["SELFHOST_TLS_OUTPUT_DIR"], "/output");
    }
    #[test]
    fn exact_runtime_contract_allows_only_expected_tmpfs_and_environment() {
        let c = contract();
        let container = "d".repeat(64);
        validate_observation(&observed(&c, false), &container, &c, false).unwrap();
        validate_observation(&observed(&c, true), &container, &c, true).unwrap();
        let mut tmpfs = observed(&c, true);
        tmpfs["Mounts"]
            .as_array_mut()
            .unwrap()
            .push(json!({"Type":"tmpfs","Source":"","Destination":"/tmp","RW":true}));
        validate_observation(&tmpfs, &container, &c, true).unwrap();
        for mutation in [
            "env",
            "command",
            "cap",
            "network",
            "tmpfs",
            "bind-tmp",
            "source",
            "writable-root",
            "image",
            "entrypoint",
            "status",
        ] {
            let mut v = observed(&c, true);
            match mutation {
                "env" => v["Config"]["Env"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!("BAO_TOKEN=secret")),
                "command" => v["Config"]["Cmd"] = json!(["-ec", "env"]),
                "cap" => v["HostConfig"]["CapAdd"] = json!(["SYS_ADMIN"]),
                "network" => {
                    v["NetworkSettings"]["Networks"][&c.network_name]["NetworkID"] = json!("wrong")
                }
                "tmpfs" => v["HostConfig"]["Tmpfs"] = json!({"/tmp":"rw,mode=0777"}),
                "bind-tmp" => v["Mounts"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"Type":"bind","Source":"/host","Destination":"/tmp","RW":true})),
                "source" => v["Mounts"][0]["Source"] = json!("/foreign"),
                "writable-root" => v["HostConfig"]["ReadonlyRootfs"] = json!(false),
                "image" => v["Image"] = json!("wrong"),
                "entrypoint" => v["Config"]["Entrypoint"] = json!(["/bin/bash"]),
                _ => v["State"]["ExitCode"] = json!(1),
            }
            assert!(
                validate_observation(&v, &container, &c, true).is_err(),
                "accepted {mutation}"
            );
        }
    }
}
