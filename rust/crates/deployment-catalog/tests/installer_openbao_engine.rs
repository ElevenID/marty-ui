//! Opt-in four-role OpenBao execution qualification. Uses real canonical files
//! and the real production pull/create/start path, not release admission or a
//! clean-host installer acceptance claim. Never adopts existing resources.
#![cfg(target_os = "linux")]
use marty_deployment_catalog::{
    installer_openbao::start_openbao,
    installer_runtime::DockerRunner,
    installer_state::{Identity, InstallerState, Phase, RuntimeBinding, PASSWORD_POLICY},
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    io::{Read, Seek, SeekFrom},
    net::TcpListener,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};
type Result<T> = std::result::Result<T, String>;
fn require(ok: bool, reason: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(reason.into())
    }
}
fn id(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn single(raw: &str) -> Result<Value> {
    let value: Value = serde_json::from_str(raw).map_err(|_| "invalid Docker observation")?;
    let array = value.as_array().ok_or("Docker observation array absent")?;
    require(
        array.len() == 1 && array[0].is_object(),
        "ambiguous Docker observation",
    )?;
    Ok(array[0].clone())
}
fn snapshot(docker: &DockerRunner) -> Result<[BTreeSet<String>; 3]> {
    let lines = |s: String| s.lines().map(str::to_owned).collect();
    Ok([
        lines(docker.run_checked(&["ps", "-aq", "--no-trunc"])?),
        lines(docker.run_checked(&["network", "ls", "-q", "--no-trunc"])?),
        lines(docker.run_checked(&["volume", "ls", "-q"])?),
    ])
}
fn private_directory(path: &Path) -> Result<()> {
    fs::create_dir(path).map_err(|_| "cannot create owned fixture directory")?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|_| "cannot protect fixture directory".into())
}
fn observe_owned(
    docker: &DockerRunner,
    container: &str,
    project: &str,
    role: &str,
    image: &str,
    image_id: &str,
) -> Result<Value> {
    require(id(container), "invalid owned container ID")?;
    let c = single(&docker.run_checked(&["inspect", "--type", "container", container])?)?;
    require(
        c["Id"] == container
            && c["Name"] == format!("/{project}-{role}-1")
            && c["Config"]["Labels"]["com.docker.compose.project"] == project
            && c["Config"]["Labels"]["com.docker.compose.service"] == role
            && c["Config"]["Labels"]["com.docker.compose.oneoff"] == "False"
            && c["Config"]["Image"] == image
            && c["Image"] == image_id,
        "owned fixture identity changed; preserve resources",
    )?;
    Ok(c)
}

#[test]
#[ignore = "requires explicit anonymously pullable OpenBao digest and exact local Engine; creates four isolated owned containers"]
fn actual_four_role_openbao_records_ownership_before_start() -> Result<()> {
    run_fixture(false)
}

#[test]
#[ignore = "requires current static operator, published services/OpenBao digests and exact local Engine; creates isolated owned OpenBao and sequential provisioning helpers"]
fn actual_renewal_bootstrap_uses_live_keycloak_and_workload_inputs() -> Result<()> {
    run_fixture(true)
}

fn persist_fixture_operator(root: &Path, state: &mut InstallerState) -> Result<String> {
    let source = PathBuf::from(std::env::var("MARTY_INSTALLER_TEST_OPERATOR").map_err(|_| {
        "set MARTY_INSTALLER_TEST_OPERATOR to the current static linux/amd64 marty-deploy"
    })?);
    let metadata = fs::symlink_metadata(&source).map_err(|_| "fixture operator unavailable")?;
    require(
        source.is_absolute()
            && metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.len() >= 64
            && metadata.len() <= 512 * 1024 * 1024,
        "fixture operator must be a bounded ordinary absolute executable",
    )?;
    let staging = root.join("operator-input");
    private_directory(&staging)?;
    let path = staging.join("marty-deploy");
    fs::copy(&source, &path).map_err(|_| "cannot stage fixture operator")?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
        .map_err(|_| "cannot protect fixture operator")?;
    let mut file = fs::File::open(&path).map_err(|_| "cannot read fixture operator")?;
    let mut header = [0u8; 64];
    file.read_exact(&mut header)
        .map_err(|_| "invalid ELF header")?;
    require(
        &header[..7] == b"\x7fELF\x02\x01\x01"
            && u16::from_le_bytes([header[18], header[19]]) == 62,
        "fixture operator must be linux/amd64 ELF64",
    )?;
    let offset = u64::from_le_bytes(header[32..40].try_into().unwrap());
    let size = u16::from_le_bytes(header[54..56].try_into().unwrap()) as u64;
    let count = u16::from_le_bytes(header[56..58].try_into().unwrap()) as u64;
    require(
        size == 56
            && count > 0
            && count <= 256
            && offset >= 64
            && offset
                .checked_add(size * count)
                .is_some_and(|end| end <= metadata.len()),
        "invalid ELF program table",
    )?;
    file.seek(SeekFrom::Start(offset))
        .map_err(|_| "invalid ELF program table")?;
    for _ in 0..count {
        let mut entry = [0u8; 56];
        file.read_exact(&mut entry)
            .map_err(|_| "invalid ELF program table")?;
        require(
            u32::from_le_bytes(entry[..4].try_into().unwrap()) != 3,
            "fixture operator requires dynamic interpreter",
        )?;
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| "cannot hash fixture operator")?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let n = file
            .read(&mut buffer)
            .map_err(|_| "cannot hash fixture operator")?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    let digest = format!("{:x}", hasher.finalize());
    state.persist_operator(&path, &digest)?;
    Ok(digest)
}

fn run_fixture(renewal: bool) -> Result<()> {
    let image = std::env::var("MARTY_INSTALLER_TEST_OPENBAO_IMAGE").map_err(|_| {
        "set MARTY_INSTALLER_TEST_OPENBAO_IMAGE to an actual published plugin digest"
    })?;
    require(
        image
            .strip_prefix("ghcr.io/elevenid/marty-ui-oss/openbao-didcomm@sha256:")
            .is_some_and(id),
        "fixture requires published OpenBao repository digest; local aliases are not substituted",
    )?;
    let engine = std::env::var("MARTY_INSTALLER_TEST_ENGINE_ID")
        .map_err(|_| "set exact MARTY_INSTALLER_TEST_ENGINE_ID")?;
    let executable = PathBuf::from(
        std::env::var("MARTY_INSTALLER_TEST_DOCKER").unwrap_or_else(|_| "/usr/bin/docker".into()),
    );
    let temporary = tempfile::tempdir().map_err(|_| "cannot create fixture parent")?;
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
        .map_err(|_| "cannot protect fixture parent")?;
    let root = temporary.keep();
    eprintln!(
        "OpenBao qualification recovery directory: {}",
        root.display()
    );
    let listener =
        TcpListener::bind(("127.0.0.1", 0)).map_err(|_| "cannot reserve fixture port")?;
    let port = listener
        .local_addr()
        .map_err(|_| "cannot observe fixture port")?
        .port();
    require(port >= 1024, "fixture port must be unprivileged")?;
    let installation = root.join("installation");
    // This isolated test journal is explicitly synthetic; no signed release
    // admission or installed-journey evidence is manufactured by this fixture.
    let mut state = InstallerState::create_with_runtime(
        &installation,
        Identity {
            source_sha: "a".repeat(40),
            release_tag: "v0.0.0".into(),
            inventory_sha256: format!("sha256:{}", "b".repeat(64)),
        },
        RuntimeBinding {
            docker_host: "unix:///var/run/docker.sock".into(),
            engine_id: engine.clone(),
            openbao_port: port,
        },
    )?;
    state.create_private_directory("evidence")?;
    let operator_sha = if renewal {
        Some(persist_fixture_operator(&root, &mut state)?)
    } else {
        None
    };
    let services_image = if renewal {
        let image = std::env::var("MARTY_INSTALLER_TEST_SERVICES_IMAGE")
            .map_err(|_| "set published MARTY_INSTALLER_TEST_SERVICES_IMAGE")?;
        require(
            image
                .strip_prefix("ghcr.io/elevenid/marty-ui-oss/services@sha256:")
                .is_some_and(id),
            "fixture services image must be a published immutable digest",
        )?;
        Some(image)
    } else {
        None
    };
    state.advance(Phase::Verified)?;
    state.advance(Phase::Provisioning)?;
    state.generate_local_credentials(&json!({"passwordPolicy":PASSWORD_POLICY}))?;
    let bundle = installation.join("bundle");
    private_directory(&bundle)?;
    private_directory(&bundle.join("docker"))?;
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    for resource in [
        "docker-compose.selfhost.openbao.yml",
        "docker/openbao-selfhost.hcl",
        "docker/openbao-init.sh",
        "docker/openbao-selfhost-init.sh",
        "docker/openbao-haip-workload-policy.hcl",
    ] {
        let destination = bundle.join(resource);
        fs::copy(source.join(resource), &destination)
            .map_err(|_| "cannot stage canonical OpenBao resource")?;
        fs::set_permissions(destination, fs::Permissions::from_mode(0o444))
            .map_err(|_| "cannot protect staged resource")?;
    }
    if renewal {
        for (input, output) in [
            (
                ".env.selfhost.production.example",
                ".env.selfhost.production.example",
            ),
            ("docker-compose.selfhost.prod.yml", "docker-compose.yml"),
        ] {
            fs::copy(source.join(input), bundle.join(output))
                .map_err(|_| "cannot stage canonical TLS wiring")?;
            fs::set_permissions(bundle.join(output), fs::Permissions::from_mode(0o644))
                .map_err(|_| "cannot protect TLS wiring")?;
        }
    }
    let docker = DockerRunner::new(
        &executable,
        "unix:///var/run/docker.sock",
        &engine,
        &installation,
    )?;
    docker.preflight()?;
    let before = snapshot(&docker)?;
    state.write_evidence(
        "engine-fixture-baseline.json",
        &serde_json::to_vec(&json!({"neighbors":before,"image":image,"port":port}))
            .map_err(|_| "cannot encode fixture baseline")?,
    )?;
    drop(listener);
    // Deliberately retain the mandatory production pull, including anonymous
    // registry authorization and digest checks. No cached/local image bypass.
    let receipt = start_openbao(&executable, &installation, &bundle, &state, &image)?;
    state.write_evidence(
        "openbao-observation.json",
        &serde_json::to_vec(&receipt).map_err(|_| "cannot encode OpenBao receipt")?,
    )?;
    if let (Some(operator), Some(services)) = (operator_sha.as_deref(), services_image.as_deref()) {
        let keycloak = marty_deployment_catalog::installer_keycloak::provision(
            &executable,
            &installation,
            &bundle,
            &mut state,
            &receipt,
            operator,
        )?;
        require(
            keycloak.container_removed && keycloak.outputs.len() == 7,
            "Keycloak helper did not complete scoped removal",
        )?;
        state.write_evidence(
            "keycloak-observation.json",
            &serde_json::to_vec(&keycloak).map_err(|_| "cannot encode Keycloak receipt")?,
        )?;
        let tls = marty_deployment_catalog::installer_tls::provision(
            &executable,
            &installation,
            &bundle,
            &mut state,
            &receipt,
            services,
            operator,
        )?;
        require(
            tls.container_removed && tls.outputs.len() == 33,
            "TLS helper did not complete scoped removal",
        )?;
        state.write_evidence(
            "tls-observation.json",
            &serde_json::to_vec(&tls).map_err(|_| "cannot encode TLS receipt")?,
        )?;
        let renewed = marty_deployment_catalog::installer_renewal::provision(
            &executable,
            &installation,
            &bundle,
            &mut state,
            &receipt,
            services,
            operator,
        )?;
        require(
            renewed.container_removed
                && renewed.private_identity_validated
                && !renewed.root_retired
                && !renewed.ingress_renewal
                && !renewed.installation_ready
                && renewed.outputs.len() == 3,
            "renewal authority result differs",
        )?;
        state.write_evidence(
            "renewal-observation.json",
            &serde_json::to_vec(&renewed).map_err(|_| "cannot encode renewal receipt")?,
        )?;
        for (stage, container) in [
            ("keycloak", &keycloak.container_id),
            ("tls", &tls.container_id),
            ("renewal", &renewed.container_id),
        ] {
            let removed: Value = serde_json::from_slice(
                &fs::read(installation.join(format!("evidence/{stage}-container-removed.json")))
                    .map_err(|_| "helper removal receipt absent")?,
            )
            .map_err(|_| "helper removal receipt invalid")?;
            require(
                removed["container_id"] == *container && removed["container_removed"] == true,
                "helper removal identity differs",
            )?;
            require(
                docker
                    .run_checked(&[
                        "ps",
                        "-aq",
                        "--no-trunc",
                        "--filter",
                        &format!("id={container}"),
                    ])?
                    .trim()
                    .is_empty(),
                "helper remains; preserve resources",
            )?;
        }
    }
    let roles = BTreeSet::from([
        "openbao-tls-init",
        "openbao",
        "openbao-bootstrap",
        "openbao-unseal",
    ]);
    require(
        receipt
            .container_ids
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            == roles
            && receipt
                .container_ids
                .values()
                .collect::<BTreeSet<_>>()
                .len()
                == 4,
        "four-role inventory is incomplete",
    )?;
    let created: Value = serde_json::from_slice(
        &fs::read(installation.join("openbao-created.json"))
            .map_err(|_| "creation receipt absent")?,
    )
    .map_err(|_| "creation receipt invalid")?;
    require(
        created["container_ids"] == json!(receipt.container_ids)
            && created["network_id"] == receipt.network_id
            && created["engine_id"] == engine,
        "created and final resource inventories differ",
    )?;
    let image_id = created["image_id"]
        .as_str()
        .filter(|s| s.strip_prefix("sha256:").is_some_and(id))
        .ok_or("created image ID invalid")?;
    for role in &roles {
        let c = observe_owned(
            &docker,
            &receipt.container_ids[*role],
            &receipt.project,
            role,
            &image,
            image_id,
        )?;
        let completed = matches!(*role, "openbao-tls-init" | "openbao-bootstrap");
        require(
            if completed {
                c["State"]["Status"] == "exited" && c["State"]["ExitCode"] == 0
            } else {
                c["State"]["Running"] == true
            },
            "OpenBao final role state differs",
        )?;
        require(
            installation
                .join(format!("openbao-start-{role}.json"))
                .is_file(),
            "durable start intent absent",
        )?;
    }
    let network = single(&docker.run_checked(&["network", "inspect", &receipt.network_id])?)?;
    let endpoints = network["Containers"]
        .as_object()
        .ok_or("network membership absent")?;
    require(
        endpoints
            .keys()
            .all(|key| receipt.container_ids.values().any(|owned| owned == key)),
        "foreign network attachment; refuse cleanup",
    )?;
    state.write_evidence(
        "engine-fixture-cleanup-intent.json",
        &serde_json::to_vec(
            &json!({"containers":receipt.container_ids,"network_id":receipt.network_id}),
        )
        .map_err(|_| "cannot encode cleanup intent")?,
    )?;
    // Stop only recorded running identities. A timeout leaves all remaining
    // resources and private key material available for explicit reconciliation.
    for role in [
        "openbao-unseal",
        "openbao",
        "openbao-bootstrap",
        "openbao-tls-init",
    ] {
        let container = &receipt.container_ids[role];
        let c = observe_owned(&docker, container, &receipt.project, role, &image, image_id)?;
        if c["State"]["Running"] == true {
            docker.run_checked(&["stop", "--timeout", "30", container])?;
        }
        let stopped = observe_owned(&docker, container, &receipt.project, role, &image, image_id)?;
        require(
            stopped["State"]["Running"] == false && stopped["State"]["Status"] == "exited",
            "owned container did not stop; refuse removal",
        )?;
        docker.run_checked(&["rm", container])?;
    }
    let network = single(&docker.run_checked(&["network", "inspect", &receipt.network_id])?)?;
    require(
        network["Id"] == receipt.network_id
            && network["Name"] == receipt.network_name
            && network["Labels"]["com.docker.compose.project"] == receipt.project
            && network["Labels"]["com.docker.compose.network"] == "default"
            && network["Containers"]
                .as_object()
                .is_some_and(|v| v.is_empty()),
        "owned network changed or still attached",
    )?;
    docker.run_checked(&["network", "rm", &receipt.network_id])?;
    require(
        snapshot(&docker)? == before,
        "neighbor resource identity sets changed",
    )?;
    state.write_evidence("engine-fixture-complete.json",&serde_json::to_vec(&json!({"owned_resources_remaining":0,"neighbor_resource_identity_sets_unchanged":true,"recovery_data_retained":true,"installation_ready":false})).map_err(|_|"cannot encode qualification result")?)?;
    Ok(())
}
