//! Read-only inner base-runtime test in the exact-owned PostgreSQL namespace.
//! No host gateway/native publications, Docker socket, checkout directory or
//! operator configuration is mounted. This helper never accepts a database URL.

use super::{
    base_runtime_redis::OwnedRedis,
    canvas_published_database::{
        docker, docker_output_with_timeout, docker_with_timeout, inspect, inspect_with_timeout,
        PublishedDatabase,
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
const ENVOY_CHILD: &str = "base_profile_envoy_composition_child";
const KUBERNETES_CHILD: &str = "kubernetes_profile_gateway_composition_child";
const COMPOSE_SHA256: &str = "837fd1d35bf6a494f41b5b5988269a7be79de337cf1a1a6ff0e45ab51bb4e9be";
const COMPAT_TEST_EXECUTABLE: &str = "MARTY_BASE_RUNTIME_COMPAT_TEST_EXECUTABLE";
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

pub(super) fn regular_file(path: &Path) -> Result<PathBuf, String> {
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

pub(super) fn digest(path: &Path) -> Result<String, String> {
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

#[derive(Debug, PartialEq)]
struct RuntimeExecutables {
    test: PathBuf,
    issuance: PathBuf,
    gateway: PathBuf,
}

fn compatible_executable_paths(test: &Path) -> Result<RuntimeExecutables, String> {
    require(
        test.is_absolute(),
        "Compatible base runtime test executable must be absolute",
    )?;
    let name = test
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("Compatible base runtime test executable name is invalid")?;
    let hash = name
        .strip_prefix("canvas_published_schema_contract-")
        .ok_or("Compatible base runtime test executable has the wrong target name")?;
    require(
        hash.len() == 16
            && hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "Compatible base runtime test executable has an invalid Cargo hash",
    )?;
    let deps = test
        .parent()
        .ok_or("Compatible base runtime test executable has no parent")?;
    require(
        deps.file_name().and_then(|name| name.to_str()) == Some("deps"),
        "Compatible base runtime test executable is not in Cargo's deps directory",
    )?;
    let debug = deps
        .parent()
        .ok_or("Compatible base runtime target directory is unavailable")?;
    Ok(RuntimeExecutables {
        test: test.to_path_buf(),
        issuance: debug.join("marty-issuance-service"),
        gateway: debug.join("marty-gateway"),
    })
}

fn runtime_executables() -> Result<RuntimeExecutables, String> {
    let candidates = if let Some(test) = std::env::var_os(COMPAT_TEST_EXECUTABLE) {
        compatible_executable_paths(Path::new(&test))?
    } else {
        let test = std::env::current_exe().map_err(|_| "Base test executable is unavailable")?;
        let issuance = PathBuf::from(env!("CARGO_BIN_EXE_marty-issuance-service"));
        let gateway = issuance.with_file_name("marty-gateway");
        RuntimeExecutables {
            test,
            issuance,
            gateway,
        }
    };
    Ok(RuntimeExecutables {
        test: executable(&candidates.test)?,
        issuance: executable(&candidates.issuance)?,
        gateway: executable(&candidates.gateway)?,
    })
}

fn checked_assets(root: &Path, assets: &[PathBuf]) -> Result<Vec<PathBuf>, String> {
    checked_asset_set(
        ASSETS.iter().map(|asset| root.join(asset)).collect(),
        assets,
    )
}

fn checked_asset_set(
    expected: BTreeSet<PathBuf>,
    assets: &[PathBuf],
) -> Result<Vec<PathBuf>, String> {
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

pub(super) fn kubernetes_source_assets() -> Result<Vec<PathBuf>, String> {
    let root = source_root()?;
    let assets: Vec<_> = super::resolved_kubernetes_runtime::SOURCE_FILES
        .iter()
        .copied()
        .chain([
            "scripts/didcomm_wallet_fixture.py",
            "scripts/test_canvas_lti_https.py",
        ])
        .map(|asset| root.join(asset))
        .collect();
    checked_asset_set(assets.iter().cloned().collect(), &assets)
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
    child: &'static str,
    prepared: Option<(String, String)>,
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
                    == serde_json::json!([
                        self.child,
                        "--exact",
                        "--nocapture",
                        "--test-threads=1"
                    ])
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
        for (name, expected) in [
            (
                "MARTY_KUBERNETES_RUNTIME_CHILD",
                self.prepared.as_ref().map(|_| "1"),
            ),
            (
                "MARTY_KUBERNETES_PREPARED_MODEL",
                self.prepared.as_ref().map(|v| v.0.as_str()),
            ),
            (
                "MARTY_KUBERNETES_PREPARED_SHA256",
                self.prepared.as_ref().map(|v| v.1.as_str()),
            ),
        ] {
            let prefix = format!("{name}=");
            let found: Vec<_> = env
                .iter()
                .filter_map(Value::as_str)
                .filter_map(|v| v.strip_prefix(&prefix))
                .collect();
            require(
                found == expected.into_iter().collect::<Vec<_>>(),
                "Kubernetes child identity differs",
            )?;
        }
        require(
            (self.child == KUBERNETES_CHILD) == self.prepared.is_some(),
            "Kubernetes prepared model/profile differs",
        )?;
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
    run_child(owned, redis, assets, CHILD).await
}

pub(super) async fn run_envoy(
    owned: &PublishedDatabase,
    redis: &OwnedRedis,
    assets: &[PathBuf],
) -> Result<(), String> {
    run_child(owned, redis, assets, ENVOY_CHILD).await
}

pub(super) async fn run_kubernetes(
    owned: &PublishedDatabase,
    redis: &OwnedRedis,
) -> Result<(), String> {
    run_child(owned, redis, &kubernetes_source_assets()?, KUBERNETES_CHILD).await
}

pub(super) fn retain_failure(
    result: Result<(), String>,
    verification: Result<(), String>,
) -> Result<(), String> {
    match (result, verification) {
        (Ok(()), result) | (result, Ok(())) => result,
        (Err(primary), Err(secondary)) => Err(format!("{primary}; additionally: {secondary}")),
    }
}

async fn run_child(
    owned: &PublishedDatabase,
    redis: &OwnedRedis,
    assets: &[PathBuf],
    child: &'static str,
) -> Result<(), String> {
    require(
        matches!(child, CHILD | ENVOY_CHILD | KUBERNETES_CHILD),
        "Unrecognized owned base child",
    )?;
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
    let executables = runtime_executables()?;
    let test_executable = executables.test;
    let issuance = executables.issuance;
    let gateway = executables.gateway;
    let renderer = regular_file(&PathBuf::from(
        std::env::var_os("MARTY_BASE_COMPOSE_BINARY")
            .ok_or("Pinned Compose renderer is required")?,
    ))?;
    require(
        digest(&renderer)? == COMPOSE_SHA256,
        "Pinned Compose renderer identity differs",
    )?;
    let mut paths = if child == KUBERNETES_CHILD {
        checked_asset_set(kubernetes_source_assets()?.into_iter().collect(), assets)?
    } else {
        checked_assets(&root, assets)?
    };
    let mut prepared = if child == KUBERNETES_CHILD {
        Some(
            super::resolved_kubernetes_runtime::PreparedArtifact::create()
                .map_err(str::to_owned)?,
        )
    } else {
        None
    };
    if let Some(prepared) = &prepared {
        paths.push(regular_file(&prepared.path)?);
    }
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
        child,
        prepared: prepared
            .as_ref()
            .map(|v| (v.path.to_str().unwrap().to_owned(), v.hash.clone())),
    };
    // All Linux executable, renderer, asset and image preconditions above are
    // checked before creating the optional sidecar. The separate image-only
    // gate may still validate Linux Envoy from a Windows host.
    let mut envoy = Vec::new();
    if child == ENVOY_CHILD {
        envoy.push(super::envoy_runtime_sidecar::OwnedEnvoy::start_baseline(owned).await?);
        match super::envoy_runtime_sidecar::OwnedEnvoy::start(owned).await {
            Ok(candidate) => envoy.push(candidate),
            Err(error) => return retain_failure(Err(error), envoy[0].close_verified()),
        }
    }
    let result = execute(&mut container).await;
    let cleanup = container.cleanup();
    // Never short-circuit cleanup of the second owner after the first fails.
    let mut envoy_cleanup = Ok(());
    for envoy in &mut envoy {
        envoy_cleanup = retain_failure(envoy_cleanup, envoy.close_verified());
    }
    let verification = (|| {
        for (path, expected) in hashes {
            require(
                digest(&path)? == expected,
                "Base runtime source/artifact changed during qualification",
            )?;
        }
        PublishedDatabase::borrowed_url(&descriptor)?;
        redis.verify_published_namespace(owned)
    })();
    let result = retain_failure(
        retain_failure(retain_failure(result, cleanup), envoy_cleanup),
        verification,
    );
    let cleanup = prepared
        .as_mut()
        .map_or(Ok(()), |v| v.close().map_err(str::to_owned));
    retain_failure(result, cleanup)
}

#[test]
fn child_failure_is_retained_when_cleanup_or_verification_also_fails() {
    assert_eq!(retain_failure(Ok(()), Ok(())), Ok(()));
    assert_eq!(
        retain_failure(Err("child".into()), Ok(())),
        Err("child".into())
    );
    assert_eq!(
        retain_failure(Ok(()), Err("cleanup".into())),
        Err("cleanup".into())
    );
    assert_eq!(
        retain_failure(Err("child".into()), Err("cleanup".into())),
        Err("child; additionally: cleanup".into())
    );
}

async fn execute(container: &mut OwnedContainer) -> Result<(), String> {
    // Validate optional CI-owned output storage before creating any container.
    let diagnostics = super::runtime_failure_diagnostics::Diagnostics::from_environment()?;
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
    let prepared_env: Vec<_> = container
        .prepared
        .as_ref()
        .map_or_else(Vec::new, |(path, hash)| {
            vec![
                "MARTY_KUBERNETES_RUNTIME_CHILD=1".to_owned(),
                format!("MARTY_KUBERNETES_PREPARED_MODEL={path}"),
                format!("MARTY_KUBERNETES_PREPARED_SHA256={hash}"),
            ]
        });
    for variable in &prepared_env {
        arguments.extend(["--env", variable]);
    }
    for mount in &mounts {
        arguments.extend(["--mount", mount]);
    }
    arguments.extend([
        "--entrypoint",
        &container.executable,
        &container.image,
        container.child,
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
            // Docker logs routes container stderr separately. Preserve both
            // bounded streams in failure artifacts, never in console errors.
            let output = docker_output_with_timeout(
                &["logs", &id],
                deadline.saturating_duration_since(Instant::now()),
                super::runtime_failure_diagnostics::STREAM_LIMIT,
            )?;
            let result = std::str::from_utf8(&output.stdout)
                .map_err(|_| "Docker returned invalid UTF-8".to_owned())
                .and_then(|stdout| completed(&state, stdout.trim()));
            return super::runtime_failure_diagnostics::record_failure(
                result,
                diagnostics.as_ref(),
                &id,
                &state,
                &output.stdout,
                &output.stderr,
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
    fn compatible_executable_selector_derives_only_exact_cargo_siblings() {
        let test = if cfg!(windows) {
            PathBuf::from(r"C:\target\debug\deps\canvas_published_schema_contract-0123456789abcdef")
        } else {
            PathBuf::from("/target/debug/deps/canvas_published_schema_contract-0123456789abcdef")
        };
        assert_eq!(
            compatible_executable_paths(&test).unwrap(),
            RuntimeExecutables {
                test: test.clone(),
                issuance: test
                    .parent()
                    .unwrap()
                    .parent()
                    .unwrap()
                    .join("marty-issuance-service"),
                gateway: test
                    .parent()
                    .unwrap()
                    .parent()
                    .unwrap()
                    .join("marty-gateway"),
            }
        );
        for invalid in [
            PathBuf::from("debug/deps/canvas_published_schema_contract-0123456789abcdef"),
            test.with_file_name("other-0123456789abcdef"),
            test.with_file_name("canvas_published_schema_contract-0123456789abcde"),
            test.with_file_name("canvas_published_schema_contract-0123456789abcdeF"),
            test.parent()
                .unwrap()
                .parent()
                .unwrap()
                .join(test.file_name().unwrap()),
        ] {
            assert!(
                compatible_executable_paths(&invalid).is_err(),
                "{invalid:?}"
            );
        }
    }

    #[test]
    fn container_inspection_closes_network_mount_and_child_identity_boundaries() {
        let id = "a".repeat(64);
        let mut container = OwnedContainer {
            child: CHILD,
            scope: "12345678-1234-4234-8234-123456789abc".into(),
            network: format!("container:{}", "b".repeat(64)),
            image: format!("synthetic.invalid/runtime@sha256:{}", "c".repeat(64)),
            executable: "/synthetic/test".into(),
            renderer: "/synthetic/compose".into(),
            mounts: BTreeSet::from(["/synthetic/test".into(), "/synthetic/compose".into()]),
            id: None,
            creation_attempted: false,
            prepared: None,
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
        container.child = KUBERNETES_CHILD;
        container.prepared = Some(("/synthetic/prepared.json".into(), "a".repeat(64)));
        container.mounts.insert("/synthetic/prepared.json".into());
        let mut kubernetes = info.clone();
        kubernetes["Config"]["Cmd"][0] = json!(KUBERNETES_CHILD);
        kubernetes["Config"]["Env"].as_array_mut().unwrap().extend([
            json!("MARTY_KUBERNETES_RUNTIME_CHILD=1"),
            json!("MARTY_KUBERNETES_PREPARED_MODEL=/synthetic/prepared.json"),
            json!(format!(
                "MARTY_KUBERNETES_PREPARED_SHA256={}",
                "a".repeat(64)
            )),
        ]);
        kubernetes["Mounts"].as_array_mut().unwrap().push(json!({"Type":"bind","Source":"/synthetic/prepared.json","Destination":"/synthetic/prepared.json","RW":false}));
        container.checked(&kubernetes, &id).unwrap();
        for fault in [
            "missing-marker",
            "wrong-hash",
            "duplicate-model",
            "writable-model",
            "wrong-child",
        ] {
            let mut changed = kubernetes.clone();
            match fault {
                "missing-marker" => {
                    changed["Config"]["Env"].as_array_mut().unwrap().remove(5);
                }
                "wrong-hash" => {
                    changed["Config"]["Env"][7] = json!(format!(
                        "MARTY_KUBERNETES_PREPARED_SHA256={}",
                        "b".repeat(64)
                    ))
                }
                "duplicate-model" => {
                    let duplicate = changed["Config"]["Env"][6].clone();
                    changed["Config"]["Env"]
                        .as_array_mut()
                        .unwrap()
                        .push(duplicate);
                }
                "writable-model" => changed["Mounts"][2]["RW"] = json!(true),
                "wrong-child" => changed["Config"]["Cmd"][0] = json!(CHILD),
                _ => unreachable!(),
            }
            assert!(container.checked(&changed, &id).is_err(), "{fault}");
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
        assert_eq!(kubernetes_source_assets().unwrap().len(), 7);
    }
}
