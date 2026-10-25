//! Execute the initial, isolated OpenBao bootstrap from an authenticated bundle.
//! The caller retains InstallerState's lock, has admitted the image/bundle, and
//! persists returned observations before proceeding. No rollback or replay is
//! attempted: pending intent and private state survive every failure.
#![cfg(target_os = "linux")]

use crate::{
    installer_runtime::DockerRunner,
    installer_state::{InstallerState, Phase, SCALAR_SECRETS},
};
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::Write,
    net::TcpListener,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

pub type Result<T> = std::result::Result<T, String>;
const OUTPUTS: [&str; 6] = [
    "openbao_service_token",
    "openbao_bootstrap_token",
    "signing_keys_openbao_token",
    "didcomm_issuance_openbao_token",
    "notification_openbao_token",
    "haip_kms_token",
];
const ROLES: [&str; 4] = [
    "openbao-tls-init",
    "openbao",
    "openbao-unseal",
    "openbao-bootstrap",
];

#[derive(Debug, Serialize)]
pub struct OpenBaoInventory {
    pub installation_id: String,
    pub engine_id: String,
    pub project: String,
    pub image: String,
    pub host_port: u16,
    pub network_name: String,
    pub network_id: String,
    pub container_ids: BTreeMap<String, String>,
    pub pending_receipt: PathBuf,
}
fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}
fn keys(value: &Value) -> Result<BTreeSet<&str>> {
    Ok(value
        .as_object()
        .ok_or("invalid OpenBao model object")?
        .keys()
        .map(String::as_str)
        .collect())
}
fn private(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path).map_err(|_| "OpenBao private path unavailable")?;
    require(
        path.is_absolute()
            && path
                .canonicalize()
                .map_err(|_| "OpenBao private path unavailable")?
                == path
            && m.is_dir()
            && m.uid() == unsafe { libc::geteuid() }
            && m.mode() & 0o7777 == 0o700,
        "OpenBao path must be owned, private and non-linked",
    )
}
fn canonical_bundle(path: &Path) -> Result<()> {
    require(
        path.is_absolute()
            && path.canonicalize().map_err(|_| "bundle unavailable")? == path
            && path.is_dir(),
        "bundle path is not canonical",
    )?;
    for name in [
        "docker-compose.selfhost.openbao.yml",
        "docker/openbao-selfhost.hcl",
        "docker/openbao-init.sh",
        "docker/openbao-selfhost-init.sh",
        "docker/openbao-haip-workload-policy.hcl",
    ] {
        let entry = path.join(name);
        let metadata =
            fs::symlink_metadata(&entry).map_err(|_| "OpenBao bundle resource absent")?;
        require(
            metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.nlink() == 1
                && entry
                    .canonicalize()
                    .map_err(|_| "bundle resource unavailable")?
                    == entry,
            "OpenBao bundle resource is linked or not ordinary",
        )?;
    }
    Ok(())
}
fn exclusive(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| "OpenBao evidence already exists or cannot be created")?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| "cannot persist OpenBao intent")?;
    File::open(path.parent().ok_or("missing evidence parent")?)
        .and_then(|p| p.sync_all())
        .map_err(|_| "cannot persist OpenBao evidence directory".to_string())
}
fn environment(image: &str, state: &Path, secrets: &Path, port: u16) -> Result<String> {
    let mut output = String::new();
    for (name, value) in [
        ("MARTY_OPENBAO_DIDCOMM_IMAGE", image.to_owned()),
        (
            "SELFHOST_OPENBAO_STATE_DIR",
            state.to_str().ok_or("state path is not UTF-8")?.to_owned(),
        ),
        (
            "SELFHOST_SECRET_DIR",
            secrets
                .to_str()
                .ok_or("secret path is not UTF-8")?
                .to_owned(),
        ),
        ("SELFHOST_OPENBAO_HOST_PORT", port.to_string()),
    ] {
        // Compose dotenv single quotes preserve spaces, # and $. Reject quote,
        // slash escapes and controls rather than allowing interpolation ambiguity.
        require(
            !value
                .chars()
                .any(|c| c.is_control() || c == '\'' || c == '\\'),
            "OpenBao path cannot be encoded safely in Compose environment",
        )?;
        output.push_str(&format!("{name}='{value}'\n"));
    }
    Ok(output)
}
fn compose(docker: &DockerRunner, base: &[String], args: &[&str]) -> Result<String> {
    let mut command: Vec<&str> = base.iter().map(String::as_str).collect();
    command.extend_from_slice(args);
    docker.run_checked(&command)
}
fn expected_mounts(
    role: &str,
    state: &Path,
    secrets: &Path,
    bundle: &Path,
) -> BTreeMap<String, (PathBuf, bool)> {
    let mut result = BTreeMap::from([(
        "/bao/data".into(),
        (state.to_path_buf(), role == "openbao-unseal"),
    )]);
    if role == "openbao" {
        result.insert(
            "/bao/config/openbao.hcl".into(),
            (bundle.join("docker/openbao-selfhost.hcl"), true),
        );
    }
    if role == "openbao-bootstrap" {
        result.insert("/bao/runtime".into(), (secrets.to_path_buf(), false));
        for name in [
            "openbao-init.sh",
            "openbao-haip-workload-policy.hcl",
            "openbao-selfhost-init.sh",
        ] {
            result.insert(
                format!("/scripts/{name}"),
                (bundle.join("docker").join(name), true),
            );
        }
    }
    result
}
fn verify_model(
    model: &Value,
    image: &str,
    state: &Path,
    secrets: &Path,
    bundle: &Path,
    port: u16,
    project: &str,
) -> Result<()> {
    require(
        keys(model)? == BTreeSet::from(["name", "networks", "services"])
            && model["name"] == project,
        "OpenBao Compose project differs",
    )?;
    require(
        keys(&model["networks"])? == BTreeSet::from(["default"]),
        "OpenBao network set differs",
    )?;
    let network = &model["networks"]["default"];
    require(
        keys(network)?.is_subset(&BTreeSet::from(["name", "ipam"]))
            && network["name"] == format!("{project}_default")
            && network.get("ipam").unwrap_or(&json!({})) == &json!({}),
        "OpenBao network configuration differs",
    )?;
    require(
        keys(&model["services"])? == BTreeSet::from(ROLES),
        "OpenBao service set differs",
    )?;
    for role in ROLES {
        let service = &model["services"][role];
        let mut allowed = BTreeSet::from([
            "image",
            "networks",
            "restart",
            "volumes",
            "entrypoint",
            "command",
        ]);
        match role {
            "openbao" => allowed.extend(["depends_on", "ports", "healthcheck"]),
            "openbao-unseal" => allowed.extend(["depends_on", "environment"]),
            "openbao-bootstrap" => allowed.extend(["depends_on", "environment", "profiles"]),
            _ => (),
        }
        require(
            keys(service)?.is_subset(&allowed)
                && service["image"] == image
                && service["networks"] == json!({"default":null}),
            "OpenBao service image or runtime overrides differ",
        )?;
        let entrypoint = match role {
            "openbao-tls-init" => json!(["/usr/local/bin/selfhost-tls-init"]),
            "openbao-unseal" => json!(["/usr/local/bin/selfhost-unseal"]),
            "openbao-bootstrap" => json!(["/bin/sh", "/scripts/openbao-selfhost-init.sh"]),
            _ => Value::Null,
        };
        let command = if role == "openbao" {
            json!(["server", "-config=/bao/config/openbao.hcl"])
        } else {
            Value::Null
        };
        let dependency = match role {
            "openbao" => {
                json!({"openbao-tls-init":{"condition":"service_completed_successfully","required":true}})
            }
            "openbao-unseal" | "openbao-bootstrap" => {
                json!({"openbao":{"condition":"service_started","required":true}})
            }
            _ => Value::Null,
        };
        require(
            service["entrypoint"] == entrypoint
                && service["command"] == command
                && service["depends_on"] == dependency
                && service["restart"]
                    == if matches!(role, "openbao" | "openbao-unseal") {
                        "unless-stopped"
                    } else {
                        "no"
                    },
            "OpenBao startup contract differs",
        )?;
        if role == "openbao" {
            require(
                service["healthcheck"]
                    == json!({"test":["CMD-SHELL","bao status -address=https://127.0.0.1:8200 -ca-cert=/bao/data/tls/ca.crt >/dev/null 2>&1"],"timeout":"5s","interval":"10s","retries":12,"start_period":"20s"}),
                "OpenBao healthcheck differs",
            )?;
            let ports = service["ports"].as_array().ok_or("OpenBao ports absent")?;
            require(
                ports.len() == 1
                    && ports[0]["host_ip"] == "127.0.0.1"
                    && ports[0]["target"] == 8200
                    && ports[0]["protocol"] == "tcp"
                    && (ports[0]["published"] == port.to_string() || ports[0]["published"] == port),
                "OpenBao loopback binding differs",
            )?;
        } else {
            require(
                service.get("ports").is_none_or(|v| v == &json!([])),
                "OpenBao helper publishes a port",
            )?;
        }
        if role == "openbao-bootstrap" {
            require(
                service["profiles"] == json!(["kms-init"])
                    && service["environment"]
                        == json!({
                "BAO_ADDR":"https://openbao:8200","BAO_BOOTSTRAP_TOKEN_FILE":"/bao/runtime/openbao_bootstrap_token","BAO_CACERT":"/bao/data/tls/ca.crt",
                "BAO_DIDCOMM_ISSUANCE_TOKEN_FILE":"/bao/runtime/didcomm_issuance_openbao_token","BAO_HAIP_POLICY_FILE":"/scripts/openbao-haip-workload-policy.hcl",
                "BAO_HAIP_TOKEN_FILE":"/bao/runtime/haip_kms_token","BAO_INIT_FILE":"/bao/data/selfhost-init.json","BAO_NOTIFICATION_TOKEN_FILE":"/bao/runtime/notification_openbao_token",
                "BAO_ROOT_TOKEN_FILE":"/bao/data/root.token","BAO_SERVICE_TOKEN_FILE":"/bao/runtime/openbao_service_token","BAO_SIGNING_KEYS_TOKEN_FILE":"/bao/runtime/signing_keys_openbao_token",
                "BAO_UNSEAL_KEY_FILE":"/bao/data/unseal.key","DIDCOMM_KMS_PLUGIN_REQUIRED":"true"}),
                "OpenBao bootstrap environment differs",
            )?;
        }
        if role == "openbao-unseal" {
            require(
                service["environment"]
                    == json!({"BAO_ADDR":"https://openbao:8200","BAO_CACERT":"/bao/data/tls/ca.crt","BAO_UNSEAL_KEY_FILE":"/bao/data/unseal.key"}),
                "OpenBao unseal environment differs",
            )?;
        }
        let mut actual = BTreeMap::new();
        for mount in service["volumes"]
            .as_array()
            .ok_or("OpenBao volumes absent")?
        {
            require(
                keys(mount)?.is_subset(&BTreeSet::from([
                    "type",
                    "source",
                    "target",
                    "read_only",
                    "bind",
                ])) && mount["type"] == "bind",
                "OpenBao mount options differ",
            )?;
            let source = mount["source"]
                .as_str()
                .ok_or("OpenBao mount source invalid")?;
            let target = mount["target"]
                .as_str()
                .ok_or("OpenBao mount target invalid")?;
            let expected = expected_mounts(role, state, secrets, bundle);
            let bundle_file = expected.get(target).is_some_and(|(path, readonly)| {
                *readonly && path.starts_with(bundle) && path == Path::new(source)
            });
            let bind = mount.get("bind").cloned().unwrap_or_else(|| json!({}));
            require(
                bind == json!({})
                    || bind == json!({"create_host_path":false})
                    || (bundle_file && bind == json!({"create_host_path":true})),
                "OpenBao bind options differ",
            )?;
            let readonly = mount
                .get("read_only")
                .map(|v| v.as_bool().ok_or("OpenBao mount access invalid"))
                .transpose()?
                .unwrap_or(false);
            require(
                actual
                    .insert(target.to_owned(), (PathBuf::from(source), readonly))
                    .is_none(),
                "duplicate OpenBao mount",
            )?;
        }
        require(
            actual == expected_mounts(role, state, secrets, bundle),
            "OpenBao mounts differ from owned installation",
        )?;
    }
    Ok(())
}
fn id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn json_output(docker: &DockerRunner, args: &[&str]) -> Result<Value> {
    serde_json::from_str(&docker.run_checked(args)?)
        .map_err(|_| "invalid Docker observation".to_string())
}
fn fresh(docker: &DockerRunner, project: &str) -> Result<()> {
    let label = format!("label=com.docker.compose.project={project}");
    let name = format!("name=^{project}_default$");
    for args in [
        vec!["ps", "-aq", "--filter", &label],
        vec!["network", "ls", "-q", "--filter", &label],
        vec!["network", "ls", "-q", "--filter", &name],
        vec!["volume", "ls", "-q", "--filter", &label],
    ] {
        require(
            docker.run_checked(&args)?.trim().is_empty(),
            "OpenBao project resources already exist; refusing adoption",
        )?;
    }
    Ok(())
}
fn observations(
    docker: &DockerRunner,
    project: &str,
    image: &str,
    state: &Path,
    secrets: &Path,
    bundle: &Path,
    port: u16,
) -> Result<(String, BTreeMap<String, String>)> {
    let label = format!("label=com.docker.compose.project={project}");
    let listed = docker.run_checked(&["ps", "-aq", "--no-trunc", "--filter", &label])?;
    let ids: Vec<_> = listed.split_whitespace().collect();
    require(
        ids.len() == 3 && ids.iter().all(|v| id(v)),
        "unexpected OpenBao container inventory",
    )?;
    let mut args = vec!["inspect"];
    args.extend_from_slice(&ids);
    let inspected = json_output(docker, &args)?;
    let containers = inspected
        .as_array()
        .ok_or("invalid container observations")?;
    require(containers.len() == 3, "OpenBao container count changed")?;
    let mut result = BTreeMap::new();
    let network_name = format!("{project}_default");
    let mut network_id = String::new();
    for c in containers {
        let labels = &c["Config"]["Labels"];
        let role = labels["com.docker.compose.service"]
            .as_str()
            .ok_or("OpenBao role label absent")?;
        let container_id = c["Id"].as_str().ok_or("OpenBao container ID absent")?;
        require(
            matches!(role, "openbao-tls-init" | "openbao" | "openbao-unseal")
                && labels["com.docker.compose.project"] == project
                && c["Config"]["Image"] == image
                && id(container_id)
                && ids.contains(&container_id)
                && result
                    .insert(role.to_owned(), container_id.to_owned())
                    .is_none(),
            "OpenBao container identity differs",
        )?;
        if role == "openbao-tls-init" {
            require(
                c["State"]["Status"] == "exited" && c["State"]["ExitCode"] == 0,
                "OpenBao TLS initializer did not finish",
            )?;
        } else {
            require(c["State"]["Running"] == true, "OpenBao service stopped")?;
        }
        let mut mounts = BTreeMap::new();
        for mount in c["Mounts"]
            .as_array()
            .ok_or("OpenBao runtime mounts absent")?
        {
            require(
                mount["Type"] == "bind",
                "unexpected OpenBao runtime mount type",
            )?;
            let source = mount["Source"]
                .as_str()
                .ok_or("runtime mount source absent")?;
            let target = mount["Destination"]
                .as_str()
                .ok_or("runtime mount target absent")?;
            let writable = mount["RW"].as_bool().ok_or("runtime mount access absent")?;
            require(
                mounts
                    .insert(target.to_owned(), (PathBuf::from(source), !writable))
                    .is_none(),
                "duplicate runtime mount",
            )?;
        }
        require(
            mounts == expected_mounts(role, state, secrets, bundle),
            "OpenBao runtime mounts differ",
        )?;
        if role == "openbao" {
            require(
                c["State"]["Health"]["Status"] == "healthy",
                "OpenBao not healthy",
            )?;
            let ports = json!({"8200/tcp":[{"HostIp":"127.0.0.1","HostPort":port.to_string()}]});
            require(
                c["HostConfig"]["PortBindings"] == ports
                    && c["NetworkSettings"]["Ports"]
                        .as_object()
                        .is_some_and(|observed| {
                            observed.get("8200/tcp") == ports.get("8200/tcp")
                                && observed
                                    .iter()
                                    .all(|(name, value)| name == "8200/tcp" || value.is_null())
                        }),
                "OpenBao runtime port binding differs",
            )?;
            require(
                keys(&c["NetworkSettings"]["Networks"])? == BTreeSet::from([network_name.as_str()]),
                "OpenBao runtime network differs",
            )?;
            let n = &c["NetworkSettings"]["Networks"][&network_name];
            require(
                n["Aliases"]
                    .as_array()
                    .is_some_and(|a| a.contains(&json!("openbao"))),
                "OpenBao network alias absent",
            )?;
            network_id = n["NetworkID"]
                .as_str()
                .ok_or("OpenBao network ID absent")?
                .to_owned();
            require(id(&network_id), "OpenBao network ID invalid")?;
        }
    }
    let networks = json_output(docker, &["network", "inspect", &network_id])?;
    let network = networks
        .as_array()
        .filter(|v| v.len() == 1)
        .and_then(|v| v.first())
        .ok_or("OpenBao network observation absent")?;
    require(
        network["Id"] == network_id
            && network["Name"] == network_name
            && network["Labels"]["com.docker.compose.project"] == project
            && network["Labels"]["com.docker.compose.network"] == "default",
        "OpenBao network owner differs",
    )?;
    Ok((network_id, result))
}

/// Starts only the fresh OpenBao portion. The journal must already be durably
/// Provisioning. Never advances the journal or reports whole-stack readiness.
/// `plugin_image` must have passed the caller's authenticated bundle/image gate.
pub fn start_openbao(
    docker_executable: &Path,
    installation: &Path,
    bundle: &Path,
    state: &InstallerState,
    plugin_image: &str,
) -> Result<OpenBaoInventory> {
    state.require_live_phase(Phase::Provisioning)?;
    let journal = state.journal();
    require(
        journal.phase() == Phase::Provisioning
            && InstallerState::inspect(installation)? == *journal,
        "OpenBao requires durable owned provisioning intent",
    )?;
    let binding = journal.runtime().ok_or("OpenBao runtime binding absent")?;
    binding.validate()?;
    require(
        regex::Regex::new(
            r"\Aghcr\.io/elevenid/marty-ui-oss/openbao-didcomm@sha256:[0-9a-f]{64}\z",
        )
        .unwrap()
        .is_match(plugin_image),
        "OpenBao image is not an admitted plugin digest",
    )?;
    private(installation)?;
    canonical_bundle(bundle)?;
    let secrets = installation.join("secrets");
    private(&secrets)?;
    let names: BTreeSet<String> = fs::read_dir(&secrets)
        .map_err(|_| "secret inventory unavailable")?
        .map(|entry| {
            entry
                .map_err(|_| "secret inventory unavailable")
                .and_then(|e| {
                    e.file_name()
                        .into_string()
                        .map_err(|_| "invalid secret filename")
                })
        })
        .collect::<std::result::Result<_, _>>()?;
    require(
        names == SCALAR_SECRETS.iter().map(|s| s.to_string()).collect(),
        "OpenBao requires fresh scalar secrets only",
    )?;
    for name in SCALAR_SECRETS {
        let m = fs::symlink_metadata(secrets.join(name)).map_err(|_| "scalar credential absent")?;
        require(
            m.is_file()
                && m.nlink() == 1
                && m.uid() == unsafe { libc::geteuid() }
                && m.mode() & 0o7777 == 0o444
                && m.len() == 64,
            "scalar credential metadata differs",
        )?;
    }
    let project = format!("{}-bao", journal.compose_project());
    let docker = DockerRunner::new(
        docker_executable,
        &binding.docker_host,
        &binding.engine_id,
        installation,
    )?;
    docker.preflight()?;
    fresh(&docker, &project)?;
    let listener = TcpListener::bind(("127.0.0.1", binding.openbao_port))
        .map_err(|_| "OpenBao loopback port unavailable")?;
    let state_root = installation.join("openbao-state");
    let env_file = installation.join("openbao.env");
    let pending = installation.join("openbao-pending.json");
    let env = environment(plugin_image, &state_root, &secrets, binding.openbao_port)?;
    state.require_live_phase(Phase::Provisioning)?;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&state_root)
        .map_err(|_| "OpenBao state exists or cannot be created")?;
    private(&state_root)?;
    exclusive(&env_file, env.as_bytes())?;
    let compose_file = bundle.join("docker-compose.selfhost.openbao.yml");
    let base = vec![
        "compose".into(),
        "--project-name".into(),
        project.clone(),
        "--env-file".into(),
        env_file.to_str().ok_or("environment path invalid")?.into(),
        "-f".into(),
        compose_file.to_str().ok_or("compose path invalid")?.into(),
    ];
    let model: Value = serde_json::from_str(&compose(
        &docker,
        &base,
        &["--profile", "kms-init", "config", "--format", "json"],
    )?)
    .map_err(|_| "invalid OpenBao Compose model")?;
    verify_model(
        &model,
        plugin_image,
        &state_root,
        &secrets,
        bundle,
        binding.openbao_port,
        &project,
    )?;
    let intent = json!({"schema":"elevenid.installer-openbao-intent/v1","installation_id":journal.installation_id(),"source_sha":journal.identity().source_sha,"project":project,"docker_host":binding.docker_host,"engine_id":binding.engine_id,"image":plugin_image,"host_port":binding.openbao_port,"state_root":state_root,"secret_root":secrets,"compose_file":compose_file});
    exclusive(
        &pending,
        &serde_json::to_vec(&intent).map_err(|_| "cannot encode OpenBao intent")?,
    )?;
    state.require_live_phase(Phase::Provisioning)?;
    compose(&docker, &base, &["pull", "openbao"])?;
    // Recheck project emptiness immediately before first resource creation.
    fresh(&docker, &project)?;
    drop(listener);
    compose(
        &docker,
        &base,
        &["up", "-d", "--pull", "never", "--no-build", "openbao"],
    )?;
    compose(
        &docker,
        &base,
        &[
            "run",
            "--no-deps",
            "--rm",
            "--pull",
            "never",
            "openbao-bootstrap",
        ],
    )?;
    compose(
        &docker,
        &base,
        &[
            "up",
            "-d",
            "--no-deps",
            "--no-build",
            "--pull",
            "never",
            "openbao-unseal",
        ],
    )?;
    let deadline = Instant::now() + Duration::from_secs(120);
    let container = compose(&docker, &base, &["ps", "-q", "openbao"])?;
    let container = container.trim();
    require(
        container.len() >= 12
            && container.len() <= 64
            && container
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "OpenBao container ID invalid",
    )?;
    loop {
        let health =
            docker.run_checked(&["inspect", "--format", "{{.State.Health.Status}}", container])?;
        if health.trim() == "healthy" {
            break;
        }
        require(
            matches!(health.trim(), "starting" | "unhealthy") && Instant::now() < deadline,
            "OpenBao failed bounded readiness check",
        )?;
        std::thread::sleep(Duration::from_secs(2));
    }
    let (network_id, container_ids) = observations(
        &docker,
        &project,
        plugin_image,
        &state_root,
        &secrets,
        bundle,
        binding.openbao_port,
    )?;
    for name in OUTPUTS.into_iter().chain(["openbao_tls_ca_cert"]) {
        let m =
            fs::symlink_metadata(secrets.join(name)).map_err(|_| "OpenBao scoped output absent")?;
        require(
            m.is_file()
                && m.nlink() == 1
                && m.len() > 0
                && m.len() <= 65536
                && m.mode() & 0o022 == 0,
            "OpenBao output is linked, empty, oversized or writable by others",
        )?;
    }
    Ok(OpenBaoInventory {
        installation_id: journal.installation_id().to_string(),
        engine_id: binding.engine_id.clone(),
        project: project.clone(),
        image: plugin_image.into(),
        host_port: binding.openbao_port,
        network_name: format!("{project}_default"),
        network_id,
        container_ids,
        pending_receipt: pending,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    fn intent_is_private_exclusive_and_never_replaces_existing_evidence() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let evidence = root.path().join("pending.json");
        exclusive(&evidence, b"original intent").unwrap();
        assert_eq!(fs::metadata(&evidence).unwrap().mode() & 0o777, 0o600);
        assert!(exclusive(&evidence, b"replacement").is_err());
        assert_eq!(fs::read(&evidence).unwrap(), b"original intent");
        let linked = root.path().join("linked.json");
        symlink(&evidence, &linked).unwrap();
        assert!(exclusive(&linked, b"replacement").is_err());
        assert_eq!(fs::read(&evidence).unwrap(), b"original intent");
    }

    #[test]
    fn private_path_rejects_symlink_and_public_directory() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        private(root.path()).unwrap();
        let link = root.path().join("linked");
        symlink(root.path(), &link).unwrap();
        assert!(private(&link).is_err());
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(private(root.path()).is_err());
    }
    #[test]
    fn admits_normalized_production_model_and_refuses_mount_mutations() {
        let validate = |model: &Value| {
            verify_model(
                model,
                "image",
                Path::new("/private/openbao-state"),
                Path::new("/private/secrets"),
                Path::new("/bundle"),
                18200,
                "owned",
            )
        };
        validate(&production_model()).unwrap();
        for mutation in [
            "source",
            "read_only",
            "unknown-bind",
            "wrong-type",
            "state-create",
            "secrets-create",
        ] {
            let mut model = production_model();
            match mutation {
                "source" => {
                    model["services"]["openbao"]["volumes"][1]["source"] = json!("/foreign/config")
                }
                "read_only" => {
                    model["services"]["openbao"]["volumes"][1]["read_only"] = json!(false)
                }
                "unknown-bind" => {
                    model["services"]["openbao"]["volumes"][1]["bind"]["propagation"] =
                        json!("rshared")
                }
                "wrong-type" => {
                    model["services"]["openbao"]["volumes"][1]["bind"]["create_host_path"] =
                        json!("true")
                }
                "state-create" => {
                    model["services"]["openbao"]["volumes"][0]["bind"] =
                        json!({"create_host_path":true})
                }
                _ => {
                    model["services"]["openbao-bootstrap"]["volumes"][1]["bind"] =
                        json!({"create_host_path":true})
                }
            }
            assert!(validate(&model).is_err(), "accepted {mutation}");
        }
        for option in [json!({}), json!({"create_host_path":false})] {
            let mut model = production_model();
            for service in model["services"].as_object_mut().unwrap().values_mut() {
                for mount in service["volumes"].as_array_mut().unwrap() {
                    mount["bind"] = option.clone();
                }
            }
            validate(&model).unwrap();
        }
    }

    #[test]
    fn canonical_bundle_requires_every_resource_and_refuses_links() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("docker")).unwrap();
        let resources = [
            "docker-compose.selfhost.openbao.yml",
            "docker/openbao-selfhost.hcl",
            "docker/openbao-init.sh",
            "docker/openbao-selfhost-init.sh",
            "docker/openbao-haip-workload-policy.hcl",
        ];
        for name in resources {
            fs::write(root.path().join(name), b"fixture").unwrap();
        }
        canonical_bundle(root.path()).unwrap();
        for name in resources {
            let resource = root.path().join(name);
            fs::remove_file(&resource).unwrap();
            assert!(
                canonical_bundle(root.path()).is_err(),
                "accepted absent {name}"
            );
            symlink("/etc/passwd", &resource).unwrap();
            assert!(
                canonical_bundle(root.path()).is_err(),
                "accepted linked {name}"
            );
            fs::remove_file(&resource).unwrap();
            fs::write(&resource, b"fixture").unwrap();
        }
    }

    fn production_model() -> Value {
        serde_json::from_str(
            r##"{
  "name": "owned",
  "networks": {
    "default": {
      "name": "owned_default"
    }
  },
  "services": {
    "openbao-tls-init": {
      "image": "image",
      "networks": {
        "default": null
      },
      "entrypoint": [
        "/usr/local/bin/selfhost-tls-init"
      ],
      "restart": "no",
      "volumes": [
        {
          "type": "bind",
          "source": "/private/openbao-state",
          "target": "/bao/data",
          "read_only": false
        }
      ]
    },
    "openbao": {
      "image": "image",
      "networks": {
        "default": null
      },
      "entrypoint": null,
      "command": [
        "server",
        "-config=/bao/config/openbao.hcl"
      ],
      "restart": "unless-stopped",
      "depends_on": {
        "openbao-tls-init": {
          "condition": "service_completed_successfully",
          "required": true
        }
      },
      "healthcheck": {
        "test": [
          "CMD-SHELL",
          "bao status -address=https://127.0.0.1:8200 -ca-cert=/bao/data/tls/ca.crt >/dev/null 2>&1"
        ],
        "timeout": "5s",
        "interval": "10s",
        "retries": 12,
        "start_period": "20s"
      },
      "ports": [
        {
          "host_ip": "127.0.0.1",
          "target": 8200,
          "published": "18200",
          "protocol": "tcp"
        }
      ],
      "volumes": [
        {
          "type": "bind",
          "source": "/private/openbao-state",
          "target": "/bao/data",
          "read_only": false
        },
        {
          "type": "bind",
          "source": "/bundle/docker/openbao-selfhost.hcl",
          "target": "/bao/config/openbao.hcl",
          "read_only": true,
          "bind": {
            "create_host_path": true
          }
        }
      ]
    },
    "openbao-unseal": {
      "image": "image",
      "networks": {
        "default": null
      },
      "entrypoint": [
        "/usr/local/bin/selfhost-unseal"
      ],
      "restart": "unless-stopped",
      "depends_on": {
        "openbao": {
          "condition": "service_started",
          "required": true
        }
      },
      "environment": {
        "BAO_ADDR": "https://openbao:8200",
        "BAO_CACERT": "/bao/data/tls/ca.crt",
        "BAO_UNSEAL_KEY_FILE": "/bao/data/unseal.key"
      },
      "volumes": [
        {
          "type": "bind",
          "source": "/private/openbao-state",
          "target": "/bao/data",
          "read_only": true
        }
      ]
    },
    "openbao-bootstrap": {
      "image": "image",
      "networks": {
        "default": null
      },
      "entrypoint": [
        "/bin/sh",
        "/scripts/openbao-selfhost-init.sh"
      ],
      "profiles": [
        "kms-init"
      ],
      "restart": "no",
      "depends_on": {
        "openbao": {
          "condition": "service_started",
          "required": true
        }
      },
      "environment": {
        "BAO_ADDR": "https://openbao:8200",
        "BAO_BOOTSTRAP_TOKEN_FILE": "/bao/runtime/openbao_bootstrap_token",
        "BAO_CACERT": "/bao/data/tls/ca.crt",
        "BAO_DIDCOMM_ISSUANCE_TOKEN_FILE": "/bao/runtime/didcomm_issuance_openbao_token",
        "BAO_HAIP_POLICY_FILE": "/scripts/openbao-haip-workload-policy.hcl",
        "BAO_HAIP_TOKEN_FILE": "/bao/runtime/haip_kms_token",
        "BAO_INIT_FILE": "/bao/data/selfhost-init.json",
        "BAO_NOTIFICATION_TOKEN_FILE": "/bao/runtime/notification_openbao_token",
        "BAO_ROOT_TOKEN_FILE": "/bao/data/root.token",
        "BAO_SERVICE_TOKEN_FILE": "/bao/runtime/openbao_service_token",
        "BAO_SIGNING_KEYS_TOKEN_FILE": "/bao/runtime/signing_keys_openbao_token",
        "BAO_UNSEAL_KEY_FILE": "/bao/data/unseal.key",
        "DIDCOMM_KMS_PLUGIN_REQUIRED": "true"
      },
      "volumes": [
        {
          "type": "bind",
          "source": "/private/openbao-state",
          "target": "/bao/data",
          "read_only": false
        },
        {
          "type": "bind",
          "source": "/private/secrets",
          "target": "/bao/runtime",
          "read_only": false
        },
        {
          "type": "bind",
          "source": "/bundle/docker/openbao-init.sh",
          "target": "/scripts/openbao-init.sh",
          "read_only": true,
          "bind": {
            "create_host_path": true
          }
        },
        {
          "type": "bind",
          "source": "/bundle/docker/openbao-haip-workload-policy.hcl",
          "target": "/scripts/openbao-haip-workload-policy.hcl",
          "read_only": true,
          "bind": {
            "create_host_path": true
          }
        },
        {
          "type": "bind",
          "source": "/bundle/docker/openbao-selfhost-init.sh",
          "target": "/scripts/openbao-selfhost-init.sh",
          "read_only": true,
          "bind": {
            "create_host_path": true
          }
        }
      ]
    }
  }
}"##,
        )
        .unwrap()
    }
    #[test]
    fn dotenv_quotes_literal_dollars_hashes_and_spaces() {
        let result = environment(
            "image@sha256:abc",
            Path::new("/private/a $x #b"),
            Path::new("/private/secrets"),
            18200,
        )
        .unwrap();
        assert!(result.contains("SELFHOST_OPENBAO_STATE_DIR='/private/a $x #b'\n"));
        for bad in ["/private/a'b", "/private/a\nb", "/private/a\\b"] {
            assert!(environment(
                "image",
                Path::new(bad),
                Path::new("/private/secrets"),
                18200
            )
            .is_err());
        }
    }
    #[test]
    fn exact_mount_contract_retains_root_state_only_in_bao_roles() {
        let state = Path::new("/private/state");
        let secrets = Path::new("/private/secrets");
        let bundle = Path::new("/private/bundle");
        assert_eq!(expected_mounts("openbao", state, secrets, bundle).len(), 2);
        assert_eq!(
            expected_mounts("openbao-bootstrap", state, secrets, bundle).len(),
            5
        );
        assert_eq!(
            expected_mounts("openbao-unseal", state, secrets, bundle)["/bao/data"],
            (state.to_path_buf(), true)
        );
    }
    #[test]
    fn rejects_unrecognized_model_before_execution() {
        assert!(verify_model(
            &json!({"name":"other","services":{},"networks":{}}),
            "image",
            Path::new("/state"),
            Path::new("/secrets"),
            Path::new("/bundle"),
            18200,
            "owned"
        )
        .is_err());
    }
}
