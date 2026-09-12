//! Read-only inner base-runtime test in the exact-owned PostgreSQL namespace.
//! No host gateway/native publications, Docker socket, checkout directory or
//! operator configuration is mounted. This helper never accepts a database URL.

use super::{
    base_runtime_redis::OwnedRedis,
    canvas_published_database::{
        docker, docker_with_timeout, inspect, inspect_with_timeout, PublishedDatabase,
    },
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use uuid::Uuid;

const LABEL: &str = "com.elevenid.test.base-native-container";
const SENTINEL: &str = "MARTY_BASE_COMPOSITION_COMPLETE_V1";
const CHILD: &str = "base_profile_gateway_composition_child";
const COMPOSE_SHA256: &str = "837fd1d35bf6a494f41b5b5988269a7be79de337cf1a1a6ff0e45ab51bb4e9be";
const ASSETS: &[&str] = &[
    "docker-compose.base.yml",
    "docker-compose.profile.issuance-native.yml",
    "docker-compose.profile.issuance-native-authcrypt.yml",
    "docker-compose.service.issuance-native-runtime.yml",
    "docker-compose.service.issuance-native.yml",
    "rust/services/issuance/src/config.rs",
    "rust/services/gateway/src/config.rs",
    "scripts/render_base_native_runtime_fixture.py",
    "scripts/test_base_native_issuance_compose.py",
    "scripts/test_beta_application_image_compose.py",
    "scripts/conformance_native.py",
    "scripts/validate_beta_didcomm_configuration.py",
    "scripts/prepare_official_beta_release.py",
    "scripts/test_conformance_native_compose.py",
    "scripts/conformance_stack.py",
    "scripts/test_canvas_worker_compose_render.py",
    "scripts/didcomm_wallet_fixture.py",
    "scripts/test_canvas_lti_https.py",
];

fn require(condition: bool, message: &str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn exact_id(id: &str) -> Result<(), String> {
    require(
        id.len() == 64 && id.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "Exact owned container ID is required",
    )
}

fn regular_file(path: &Path) -> Result<PathBuf, String> {
    let metadata = path
        .symlink_metadata()
        .map_err(|_| "Required base runtime artifact is missing")?;
    require(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "Base runtime artifacts must be regular files",
    )?;
    let path = path
        .canonicalize()
        .map_err(|_| "Base runtime artifact path is unavailable")?;
    let text = path
        .to_str()
        .ok_or("Base runtime artifact path is not UTF-8")?;
    require(
        !text
            .chars()
            .any(|character| matches!(character, ',' | '\n' | '\r')),
        "Base runtime artifact path is not mount-safe",
    )?;
    Ok(path)
}

fn digest(path: &Path) -> Result<String, String> {
    let mut file = File::open(path).map_err(|_| "Base runtime artifact cannot be read")?;
    require(
        file.metadata()
            .map_err(|_| "Base runtime artifact metadata unavailable")?
            .len()
            <= 2 * 1024 * 1024 * 1024,
        "Base runtime artifact exceeds its size bound",
    )?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| "Base runtime artifact read failed")?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn executable(path: &Path) -> Result<PathBuf, String> {
    let path = regular_file(path)?;
    let mut header = [0_u8; 4];
    File::open(&path)
        .and_then(|mut file| file.read_exact(&mut header))
        .map_err(|_| "Native Linux executable is unreadable")?;
    require(
        header == *b"\x7fELF",
        "Base runtime requires real Linux ELF artifacts",
    )?;
    Ok(path)
}

fn checked_assets(root: &Path, assets: &[PathBuf]) -> Result<Vec<PathBuf>, String> {
    let expected: BTreeSet<_> = ASSETS.iter().map(|asset| root.join(asset)).collect();
    let supplied: BTreeSet<_> = assets.iter().cloned().collect();
    require(
        supplied.len() == assets.len() && supplied == expected,
        "Base runtime asset allowlist differs",
    )?;
    expected
        .into_iter()
        .map(|path| {
            let actual = regular_file(&path)?;
            require(
                actual == path,
                "Base runtime asset escapes its exact source path",
            )?;
            Ok(actual)
        })
        .collect()
}

fn source_root() -> Result<PathBuf, String> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .map_err(|_| "Base runtime source root is unavailable".into())
}

pub(super) fn source_assets() -> Result<Vec<PathBuf>, String> {
    let root = source_root()?;
    let paths: Vec<_> = ASSETS.iter().map(|asset| root.join(asset)).collect();
    checked_assets(&root, &paths)
}

struct OwnedContainer {
    scope: String,
    network: String,
    image: String,
    executable: String,
    renderer: String,
    mounts: BTreeSet<String>,
    id: Option<String>,
    creation_attempted: bool,
}

impl OwnedContainer {
    fn checked(&self, info: &Value, id: &str) -> Result<(), String> {
        exact_id(id)?;
        require(
            info["Id"] == id
                && info["Config"]["Labels"][LABEL] == self.scope
                && info["Config"]["Image"] == self.image
                && info["Config"]["Entrypoint"] == serde_json::json!([self.executable])
                && info["Config"]["Cmd"]
                    == serde_json::json!([CHILD, "--exact", "--nocapture", "--test-threads=1"])
                && info["HostConfig"]["NetworkMode"] == self.network
                && info["HostConfig"]["ReadonlyRootfs"] == true
                && info["HostConfig"]["Tmpfs"] == serde_json::json!({"/tmp":"rw,mode=1777"})
                && info["HostConfig"]["CapDrop"] == serde_json::json!(["ALL"])
                && info["HostConfig"]["SecurityOpt"] == serde_json::json!(["no-new-privileges"])
                && info["HostConfig"]["PortBindings"]
                    .as_object()
                    .is_some_and(|ports| ports.is_empty())
                && info["NetworkSettings"]["Ports"]
                    .as_object()
                    .is_some_and(|ports| ports.is_empty()),
            "Refusing base runtime access or cleanup: ownership/isolation mismatch",
        )?;
        let mounts = info["Mounts"]
            .as_array()
            .ok_or("Missing base runtime mounts")?;
        let mut actual = BTreeSet::new();
        for mount in mounts {
            let source = mount["Source"]
                .as_str()
                .ok_or("Invalid base runtime mount")?;
            require(
                mount["Type"] == "bind" && mount["RW"] == false && mount["Destination"] == source,
                "Base runtime mount must be exact and read-only",
            )?;
            require(
                actual.insert(source.to_owned()),
                "Duplicate base runtime mount",
            )?;
        }
        require(
            actual == self.mounts,
            "Base runtime mount allowlist differs",
        )?;
        let env = info["Config"]["Env"]
            .as_array()
            .ok_or("Missing base runtime child configuration")?;
        for (name, expected) in [
            ("MARTY_BASE_RUNTIME_CHILD", "1"),
            ("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST", "1"),
            ("MARTY_DIDCOMM_TEST_PYTHON", "python"),
            ("MARTY_BASE_COMPOSE_BINARY", self.renderer.as_str()),
            ("PYTHONDONTWRITEBYTECODE", "1"),
        ] {
            let prefix = format!("{name}=");
            let values: Vec<_> = env
                .iter()
                .filter_map(Value::as_str)
                .filter_map(|value| value.strip_prefix(&prefix))
                .collect();
            require(
                values == [expected],
                "Base runtime child configuration differs",
            )?;
        }
        Ok(())
    }

    fn cleanup(&mut self) -> Result<(), String> {
        if !self.creation_attempted {
            return Ok(());
        }
        let filter = format!("label={LABEL}={}", self.scope);
        let found = docker(&["ps", "--all", "--quiet", "--no-trunc", "--filter", &filter])?;
        let ids: Vec<_> = found.lines().collect();
        require(
            ids.len() <= 1 && self.id.as_ref().is_none_or(|id| ids == [id.as_str()]),
            "Base runtime resource identity is missing or ambiguous",
        )?;
        for id in ids {
            self.checked(&inspect(id)?, id)?;
            docker(&["rm", "--force", id])?;
            let filter = format!("id={id}");
            require(
                docker(&["ps", "--all", "--quiet", "--no-trunc", "--filter", &filter])?.is_empty(),
                "Owned base runtime container remained after cleanup",
            )?;
        }
        self.id = None;
        self.creation_attempted = false;
        Ok(())
    }
}

impl Drop for OwnedContainer {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            eprintln!("Owned base runtime cleanup requires inspection: {error}");
        }
    }
}

fn completed(status: &Value, output: &str) -> Result<(), String> {
    require(
        status["State"]["Running"] == false && status["State"]["ExitCode"] == 0,
        "Base runtime child did not exit successfully",
    )?;
    require(
        output.len() <= 2 * 1024 * 1024
            && output
                .lines()
                .filter(|line| line.trim() == SENTINEL)
                .count()
                == 1,
        "Base runtime child completion evidence is missing or ambiguous",
    )
}

pub(super) async fn run(
    owned: &PublishedDatabase,
    redis: &OwnedRedis,
    assets: &[PathBuf],
) -> Result<(), String> {
    require(
        cfg!(target_os = "linux"),
        "Isolated base runtime requires Linux artifacts; not qualified on this host",
    )?;
    redis.verify_published_namespace(owned)?;
    let descriptor = owned.borrow_descriptor()?;
    let value: Value =
        serde_json::from_str(&descriptor).map_err(|_| "Invalid owned database descriptor")?;
    let postgres = value["postgres_id"]
        .as_str()
        .ok_or("Missing verified database ID")?;
    exact_id(postgres)?;
    let root = source_root()?;
    let test_executable =
        executable(&std::env::current_exe().map_err(|_| "Base test executable is unavailable")?)?;
    let issuance = executable_path()?;
    let gateway = executable(&issuance.with_file_name("marty-gateway"))?;
    let renderer = regular_file(&PathBuf::from(
        std::env::var_os("MARTY_BASE_COMPOSE_BINARY")
            .ok_or("Pinned Compose renderer is required")?,
    ))?;
    require(
        digest(&renderer)? == COMPOSE_SHA256,
        "Pinned Compose renderer identity differs",
    )?;
    let mut paths = checked_assets(&root, assets)?;
    paths.extend([test_executable.clone(), issuance, gateway, renderer.clone()]);
    let mut hashes = BTreeMap::new();
    for path in paths {
        require(
            hashes.insert(path.clone(), digest(&path)?).is_none(),
            "Duplicate base runtime artifact",
        )?;
    }
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/canvas-worker-consumer-range-oracle.json"
    ))
    .map_err(|_| "Invalid pinned runtime fixture")?;
    let image = fixture["observed_image"]
        .as_str()
        .ok_or("Missing pinned runtime image")?
        .to_owned();
    let records: Value = serde_json::from_str(&docker(&["image", "inspect", &image])?)
        .map_err(|_| "Invalid runtime image inspection")?;
    require(
        records.as_array().is_some_and(|rows| rows.len() == 1)
            && records[0]["Os"] == "linux"
            && records[0]["RepoDigests"]
                .as_array()
                .is_some_and(|values| values.iter().any(|value| value == &image)),
        "Pinned Linux runtime image is not locally available",
    )?;
    let mut container = OwnedContainer {
        scope: Uuid::new_v4().to_string(),
        network: format!("container:{postgres}"),
        image,
        executable: test_executable
            .to_str()
            .ok_or("Invalid test executable path")?
            .to_owned(),
        renderer: renderer.to_str().ok_or("Invalid renderer path")?.to_owned(),
        mounts: hashes
            .keys()
            .map(|path| path.to_str().unwrap().to_owned())
            .collect(),
        id: None,
        creation_attempted: false,
    };
    let result = execute(&mut container).await;
    let cleanup = container.cleanup();
    cleanup?;
    for (path, expected) in hashes {
        require(
            digest(&path)? == expected,
            "Base runtime source/artifact changed during qualification",
        )?;
    }
    PublishedDatabase::borrowed_url(&descriptor)?;
    redis.verify_published_namespace(owned)?;
    result
}

fn executable_path() -> Result<PathBuf, String> {
    executable(Path::new(env!("CARGO_BIN_EXE_marty-issuance-service")))
}

async fn execute(container: &mut OwnedContainer) -> Result<(), String> {
    let label = format!("{LABEL}={}", container.scope);
    let renderer_env = format!("MARTY_BASE_COMPOSE_BINARY={}", container.renderer);
    let mounts: Vec<_> = container
        .mounts
        .iter()
        .map(|path| format!("type=bind,source={path},target={path},readonly"))
        .collect();
    let mut arguments = vec![
        "create",
        "--pull=never",
        "--label",
        &label,
        "--network",
        &container.network,
        "--read-only",
        "--tmpfs",
        "/tmp:rw,mode=1777",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--env",
        "MARTY_BASE_RUNTIME_CHILD=1",
        "--env",
        "MARTY_CANVAS_PUBLISHED_SCHEMA_TEST=1",
        "--env",
        "MARTY_DIDCOMM_TEST_PYTHON=python",
        "--env",
        &renderer_env,
        "--env",
        "PYTHONDONTWRITEBYTECODE=1",
    ];
    for mount in &mounts {
        arguments.extend(["--mount", mount]);
    }
    arguments.extend([
        "--entrypoint",
        &container.executable,
        &container.image,
        CHILD,
        "--exact",
        "--nocapture",
        "--test-threads=1",
    ]);
    container.creation_attempted = true;
    let id = docker(&arguments)?;
    exact_id(&id)?;
    container.id = Some(id.clone());
    container.checked(&inspect(&id)?, &id)?;
    let deadline = Instant::now() + Duration::from_secs(240);
    docker_with_timeout(
        &["start", &id],
        deadline.saturating_duration_since(Instant::now()),
    )?;
    loop {
        let state = inspect_with_timeout(&id, deadline.saturating_duration_since(Instant::now()))?;
        container.checked(&state, &id)?;
        if state["State"]["Running"] == false {
            // Do not echo child logs or panic contents: only its closed completion
            // sentinel and successful exit qualify the inner assertions.
            return completed(
                &state,
                &docker_with_timeout(
                    &["logs", &id],
                    deadline.saturating_duration_since(Instant::now()),
                )?,
            );
        }
        require(
            Instant::now() < deadline,
            "Base runtime child deadline exceeded",
        )?;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn container_inspection_closes_network_mount_and_child_identity_boundaries() {
        let id = "a".repeat(64);
        let mut container = OwnedContainer {
            scope: "12345678-1234-4234-8234-123456789abc".into(),
            network: format!("container:{}", "b".repeat(64)),
            image: format!("synthetic.invalid/runtime@sha256:{}", "c".repeat(64)),
            executable: "/synthetic/test".into(),
            renderer: "/synthetic/compose".into(),
            mounts: BTreeSet::from(["/synthetic/test".into(), "/synthetic/compose".into()]),
            id: None,
            creation_attempted: false,
        };
        let info = json!({
            "Id":id,"Config":{"Labels":{LABEL:container.scope},"Image":container.image,
              "Entrypoint":[container.executable],"Cmd":[CHILD,"--exact","--nocapture","--test-threads=1"],
              "Env":["MARTY_BASE_RUNTIME_CHILD=1","MARTY_CANVAS_PUBLISHED_SCHEMA_TEST=1",
                     "MARTY_DIDCOMM_TEST_PYTHON=python","MARTY_BASE_COMPOSE_BINARY=/synthetic/compose","PYTHONDONTWRITEBYTECODE=1"]},
            "HostConfig":{"NetworkMode":container.network,"ReadonlyRootfs":true,"Tmpfs":{"/tmp":"rw,mode=1777"},
              "CapDrop":["ALL"],"SecurityOpt":["no-new-privileges"],"PortBindings":{}},
            "NetworkSettings":{"Ports":{}},
            "Mounts":[{"Type":"bind","Source":"/synthetic/test","Destination":"/synthetic/test","RW":false},
                      {"Type":"bind","Source":"/synthetic/compose","Destination":"/synthetic/compose","RW":false}]
        });
        container.checked(&info, &id).unwrap();
        for (pointer, value) in [
            ("/Id", json!("d".repeat(64))),
            (
                "/Config/Labels/com.elevenid.test.base-native-container",
                json!("foreign"),
            ),
            ("/Config/Image", json!("other-image")),
            ("/Config/Entrypoint", json!(["/bin/sh"])),
            ("/Config/Cmd", json!(["other-test"])),
            ("/Config/Env", json!(["MARTY_BASE_RUNTIME_CHILD=0"])),
            ("/HostConfig/NetworkMode", json!("host")),
            ("/HostConfig/ReadonlyRootfs", json!(false)),
            ("/HostConfig/Tmpfs", json!({})),
            ("/HostConfig/PortBindings", json!({"8005/tcp":[]})),
            ("/NetworkSettings/Ports", json!({"8005/tcp":[]})),
            ("/Mounts/0/RW", json!(true)),
            ("/Mounts/0/Source", json!("/var/run/docker.sock")),
            ("/Mounts/0/Destination", json!("/other")),
            ("/Mounts", json!([])),
        ] {
            let mut changed = info.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            assert!(container.checked(&changed, &id).is_err(), "{pointer}");
        }
        // Never exercise Drop against synthetic identities from a pure test.
        container.creation_attempted = false;
    }

    #[test]
    fn completion_requires_unique_exact_marker_and_successful_exit() {
        let status = json!({"State":{"Running":false,"ExitCode":0}});
        completed(&status, SENTINEL).unwrap();
        for output in [
            String::new(),
            format!("prefix-{SENTINEL}"),
            format!("{SENTINEL}\n{SENTINEL}"),
        ] {
            assert!(completed(&status, &output).is_err());
        }
        for status in [
            json!({"State":{"Running":true,"ExitCode":0}}),
            json!({"State":{"Running":false,"ExitCode":1}}),
        ] {
            assert!(completed(&status, SENTINEL).is_err());
        }
        assert_eq!(ASSETS.len(), 18);
        assert_eq!(ASSETS.iter().collect::<BTreeSet<_>>().len(), 18);
    }
}
