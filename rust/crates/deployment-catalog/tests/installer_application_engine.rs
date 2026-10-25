//! Explicit, ignored qualification against a real rootful local Docker Engine.
//! No pulls, ports, global pruning or automatic uncertain-failure cleanup.
//! The supplied digest image must provide /bin/sh, sleep, test and touch. Its
//! /data VOLUME is covered by the owned named volume (the qualified Redis image).
#![cfg(target_os = "linux")]
use marty_deployment_catalog::{
    installer_application::compose_document,
    installer_application_model::ApplicationModelPlan,
    installer_application_observation::{validate_container, validate_volume, ContainerPhase},
    installer_runtime::DockerRunner,
};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    thread,
    time::{Duration, Instant},
};
type Result<T> = std::result::Result<T, String>;
fn require(ok: bool, message: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(message.into())
    }
}
fn id(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn single(raw: &str) -> Result<Value> {
    let v: Value = serde_json::from_str(raw).map_err(|_| "invalid Docker JSON")?;
    let values = v.as_array().ok_or("expected Docker object array")?;
    require(
        values.len() == 1 && values[0].is_object(),
        "ambiguous Docker observation",
    )?;
    Ok(values[0].clone())
}
fn lines(raw: &str) -> BTreeSet<String> {
    raw.lines().map(str::to_owned).collect()
}
fn snapshot(docker: &DockerRunner) -> Result<[BTreeSet<String>; 3]> {
    Ok([
        lines(&docker.run_checked(&["ps", "-aq", "--no-trunc"])?),
        lines(&docker.run_checked(&["network", "ls", "-q", "--no-trunc"])?),
        lines(&docker.run_checked(&["volume", "ls", "-q"])?),
    ])
}
fn save(path: &Path, v: &Value) -> Result<()> {
    use std::io::Write;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| "cannot preserve qualification evidence")?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|_| "cannot protect evidence")?;
    f.write_all(&serde_json::to_vec(v).map_err(|_| "cannot encode evidence")?)
        .and_then(|_| f.sync_all())
        .map_err(|_| "cannot persist evidence")?;
    fs::File::open(path.parent().ok_or("evidence parent absent")?)
        .and_then(|f| f.sync_all())
        .map_err(|_| "cannot persist evidence directory".into())
}
fn private_dir(path: &Path) -> Result<()> {
    fs::create_dir(path).map_err(|_| "cannot create fresh private directory")?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|_| "cannot protect private directory".into())
}
fn checked_network(docker: &DockerRunner, network: &str, name: &str, project: &str) -> Result<()> {
    require(id(network), "invalid owned network ID")?;
    let n = single(&docker.run_checked(&["network", "inspect", network])?)?;
    require(
        n["Id"] == network
            && n["Name"] == name
            && n["Driver"] == "bridge"
            && n["Labels"]["com.elevenid.installer.engine-test"] == project,
        "owned network identity differs",
    )
}

#[test]
#[ignore = "requires explicit cached digest image and exact local Engine identity; creates isolated owned resources"]
fn actual_compose_container_and_volume_observations() -> Result<()> {
    let image = std::env::var("MARTY_INSTALLER_TEST_IMAGE")
        .map_err(|_| "set MARTY_INSTALLER_TEST_IMAGE to the already cached digest")?;
    require(
        image
            .split_once("@sha256:")
            .is_some_and(|(repo, hash)| !repo.is_empty() && !repo.starts_with('-') && id(hash)),
        "image must be digest pinned",
    )?;
    let engine = std::env::var("MARTY_INSTALLER_TEST_ENGINE_ID")
        .map_err(|_| "set exact MARTY_INSTALLER_TEST_ENGINE_ID")?;
    let executable =
        std::env::var("MARTY_INSTALLER_TEST_DOCKER").unwrap_or_else(|_| "/usr/bin/docker".into());
    let temporary = tempfile::tempdir().map_err(|_| "cannot create qualification directory")?;
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
        .map_err(|_| "cannot protect qualification directory")?;
    // Deliberately preserve the directory on every failure, including panic.
    let root = temporary.keep();
    eprintln!(
        "Docker qualification recovery directory: {}",
        root.display()
    );
    let docker = DockerRunner::new(
        Path::new(&executable),
        "unix:///var/run/docker.sock",
        &engine,
        &root,
    )?;
    docker.preflight()?;
    let before = snapshot(&docker)?;
    let image_record = single(&docker.run_checked(&["image", "inspect", &image])?)?;
    save(&root.join("image-inspect.json"), &image_record)?;
    require(
        image_record["RepoDigests"]
            .as_array()
            .is_some_and(|v| v.contains(&json!(image))),
        "cached image digest differs",
    )?;
    let project = format!("marty-installer-engine-{}", uuid::Uuid::new_v4().simple());
    let network_name = format!("{project}-bao_default");
    let volume_name = format!("{project}_redis-socket");
    let fixture = root.join("fixture $literal #path");
    private_dir(&fixture)?;
    // Public fixture bytes are traversable by the capless container UID. The
    // host installation parent remains 0700; no private credential is exposed.
    fs::set_permissions(&fixture, fs::Permissions::from_mode(0o755))
        .map_err(|_| "cannot make ordinary fixture readable")?;
    fs::write(fixture.join("input"), b"ordinary fixture").map_err(|_| "cannot write fixture")?;
    fs::set_permissions(fixture.join("input"), fs::Permissions::from_mode(0o444))
        .map_err(|_| "cannot protect ordinary fixture")?;
    let secret = root.join("secret $literal");
    fs::write(&secret, b"fixture-only").map_err(|_| "cannot write fixture secret")?;
    fs::set_permissions(&secret, fs::Permissions::from_mode(0o444))
        .map_err(|_| "cannot protect fixture secret")?;
    let network_filter = format!("name=^{network_name}$");
    let project_filter = format!("label=com.docker.compose.project={project}");
    require(
        docker
            .run_checked(&["network", "ls", "-q", "--filter", &network_filter])?
            .trim()
            .is_empty(),
        "network collision",
    )?;
    require(
        docker
            .run_checked(&["ps", "-aq", "--filter", &project_filter])?
            .trim()
            .is_empty()
            && !before[2].contains(&volume_name),
        "project collision",
    )?;
    save(
        &root.join("intent.json"),
        &json!({"project":project,"engine":engine,"network_name":network_name,"volume_name":volume_name,"image":image,"neighbors":before}),
    )?;
    let label = format!("com.elevenid.installer.engine-test={project}");
    let network = docker
        .run_checked(&[
            "network",
            "create",
            "--driver",
            "bridge",
            "--label",
            &label,
            &network_name,
        ])?
        .trim()
        .to_owned();
    require(
        id(&network),
        "network creation returned invalid ID; preserve intent",
    )?;
    save(&root.join("network.json"), &json!({"network_id":network}))?;
    checked_network(&docker, &network, &network_name, &project)?;
    let literal_path = |path: &Path| -> Result<String> {
        Ok(path
            .to_str()
            .ok_or("fixture path invalid")?
            .replace('$', "$$"))
    };
    let model = json!({"name":project,"services":{"app":{
        "image":image,"pull_policy":"never","user":"0:0","read_only":true,"restart":"no",
        "cap_drop":["ALL"],"security_opt":["no-new-privileges:true"],
        "entrypoint":["/bin/sh"],"command":["-ec","test \"$$LITERAL\" = '$$dollar #value'; test \"$$(cat /run/secrets/test_secret)\" = 'fixture-only'; test -f /fixture/input; test -d /data; while [ ! -f /fixture/stop ]; do sleep 1; done"],
        "environment":{"LITERAL":"$$dollar #value"},"networks":{"default":null},
        "healthcheck":{"test":["CMD","test","-f","/fixture/input"],"interval":"1s","timeout":"1s","retries":3},
        "secrets":[{"source":"test_secret","target":"test_secret"}],
        "volumes":[{"type":"bind","source":literal_path(&fixture)?,"target":"/fixture","read_only":true,"bind":{"create_host_path":false}},
        {"type":"volume","source":"redis-socket","target":"/data"}]}},
        "secrets":{"test_secret":{"file":literal_path(&secret)?}},
        "volumes":{"redis-socket":{"name":volume_name}},
        "networks":{"default":{"name":network_name,"external":true}}});
    let document = root.join("compose.json");
    save(&document, &model)?;
    let doc = document.to_str().ok_or("invalid Compose path")?;
    let raw = docker.run_checked(&[
        "compose",
        "--project-name",
        &project,
        "-f",
        doc,
        "config",
        "--format",
        "json",
    ])?;
    let normalized: Value =
        serde_json::from_str(&raw).map_err(|_| "invalid normalized Compose model")?;
    save(&root.join("normalized-observation.json"), &normalized)?;
    let plan = ApplicationModelPlan {
        model: normalized,
        selected_services: vec!["app".into()],
        expected_network_id: network.clone(),
        installation_ready: false,
    };
    let final_document = root.join("normalized.json");
    fs::write(&final_document, compose_document(&plan.model)?)
        .map_err(|_| "cannot write normalized document")?;
    fs::set_permissions(&final_document, fs::Permissions::from_mode(0o600))
        .map_err(|_| "cannot protect normalized document")?;
    let final_doc = final_document.to_str().ok_or("invalid normalized path")?;
    docker.run_checked(&[
        "compose",
        "--project-name",
        &project,
        "-f",
        final_doc,
        "create",
        "--no-build",
        "--pull",
        "never",
        "app",
    ])?;
    let ids =
        lines(&docker.run_checked(&["ps", "-aq", "--no-trunc", "--filter", &project_filter])?);
    save(
        &root.join("created.json"),
        &json!({"container_ids":ids,"volume_name":volume_name}),
    )?;
    require(ids.len() == 1, "unexpected created container set")?;
    let container = ids.iter().next().ok_or("container absent")?;
    require(id(container), "invalid container ID")?;
    let observe = || -> Result<Value> {
        single(&docker.run_checked(&["inspect", "--type", "container", container])?)
    };
    let created = observe()?;
    save(&root.join("created-inspect.json"), &created)?;
    validate_container(
        &created,
        container,
        "app",
        &plan,
        &image_record,
        ContainerPhase::Created,
    )?;
    validate_volume(
        &single(&docker.run_checked(&["volume", "inspect", &volume_name])?)?,
        &plan,
    )?;
    checked_network(&docker, &network, &network_name, &project)?;
    docker.run_checked(&["start", container])?;
    let started = Instant::now();
    let mut first_observation = true;
    loop {
        require(
            started.elapsed() < Duration::from_secs(60),
            "health deadline exceeded; preserve recorded resources",
        )?;
        let c = observe()?;
        if first_observation {
            save(&root.join("running-inspect.json"), &c)?;
            first_observation = false;
        }
        validate_container(
            &c,
            container,
            "app",
            &plan,
            &image_record,
            ContainerPhase::Running,
        )?;
        require(c["RestartCount"] == 0, "unexpected container restart")?;
        if c["State"]["Health"]["Status"] == "healthy" {
            break;
        }
        require(
            c["State"]["Health"]["Status"] == "starting",
            "unexpected unhealthy fixture",
        )?;
        thread::sleep(Duration::from_millis(200));
    }
    // A host-created marker requests normal process exit without stopping or
    // signaling any container selected by a name, wildcard or neighboring label.
    fs::write(fixture.join("stop"), b"stop").map_err(|_| "cannot signal owned fixture")?;
    require(
        docker.run_checked(&["wait", container])?.trim() == "0",
        "owned fixture did not exit successfully",
    )?;
    let exited = observe()?;
    save(&root.join("exited-inspect.json"), &exited)?;
    validate_container(
        &exited,
        container,
        "app",
        &plan,
        &image_record,
        ContainerPhase::ExitedSuccessfully,
    )?;
    save(
        &root.join("observed.json"),
        &json!({"container_id":container,"phases":["created","running-healthy","exited-zero"],"network_id":network,"volume_name":volume_name}),
    )?;
    docker.run_checked(&["rm", container])?;
    require(
        docker
            .run_checked(&["ps", "-aq", "--no-trunc", "--filter", &project_filter])?
            .trim()
            .is_empty(),
        "owned container remains",
    )?;
    validate_volume(
        &single(&docker.run_checked(&["volume", "inspect", &volume_name])?)?,
        &plan,
    )?;
    docker.run_checked(&["volume", "rm", &volume_name])?;
    checked_network(&docker, &network, &network_name, &project)?;
    docker.run_checked(&["network", "rm", &network])?;
    require(
        snapshot(&docker)? == before,
        "engine resources changed beyond the owned qualification",
    )?;
    save(
        &root.join("complete.json"),
        &json!({"owned_resources_remaining":0,"neighbor_resource_identity_sets_unchanged":true}),
    )?;
    // Keep the small, private evidence directory even on success for review.
    Ok(())
}
