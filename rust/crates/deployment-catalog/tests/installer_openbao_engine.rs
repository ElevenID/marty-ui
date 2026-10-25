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
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Read, Seek, SeekFrom},
    net::TcpListener,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
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
    run_fixture(false, false, false)
}

#[test]
#[ignore = "requires current static operator, published services/OpenBao digests and exact local Engine; creates isolated owned OpenBao and sequential provisioning helpers"]
fn actual_renewal_bootstrap_uses_live_keycloak_and_workload_inputs() -> Result<()> {
    run_fixture(true, false, false)
}

#[test]
#[ignore = "requires current static operator, published digests and exact local Engine; creates isolated owned renewal and generation helpers"]
fn actual_orphan_generation_stages_verified_candidate_without_activation() -> Result<()> {
    run_fixture(true, true, false)
}

#[test]
#[ignore = "requires current static operator, exact immutable image lock, Compose plugin and local Engine; prepares real application generation without starting applications"]
fn actual_application_generation_prepares_full_snapshot_without_starting_services() -> Result<()> {
    run_fixture(true, true, true)
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureImageLock {
    schema: String,
    release: String,
    services: BTreeMap<String, String>,
    openbao_didcomm_image: String,
}
fn bounded_fixture_lock(path: &Path) -> Result<Vec<u8>> {
    require(path.is_absolute(), "image lock must be absolute")?;
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| "fixture image lock unavailable")?;
    let m = file
        .metadata()
        .map_err(|_| "fixture image lock metadata unavailable")?;
    require(
        m.is_file() && m.nlink() == 1 && m.len() > 0 && m.len() <= 1024 * 1024,
        "fixture image lock must be bounded ordinary file",
    )?;
    let mut bytes = Vec::new();
    file.take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read fixture image lock")?;
    require(bytes.len() as u64 == m.len(), "fixture image lock changed")?;
    Ok(bytes)
}

fn git_metadata_line(path: &Path) -> Result<String> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| "Git metadata unavailable")?;
    let metadata = file.metadata().map_err(|_| "Git metadata unavailable")?;
    require(
        metadata.is_file() && metadata.nlink() == 1 && metadata.len() > 0 && metadata.len() <= 4096,
        "Git metadata is not bounded ordinary data",
    )?;
    let mut text = String::new();
    file.take(4097)
        .read_to_string(&mut text)
        .map_err(|_| "Git metadata is not text")?;
    require(text.len() as u64 == metadata.len(), "Git metadata changed")?;
    let line = text.trim_end_matches(['\r', '\n']);
    require(
        !line.is_empty() && !line.chars().any(char::is_control),
        "Git metadata is not a single line",
    )?;
    Ok(line.into())
}
fn git_metadata_path(value: &str, relative_to: &Path) -> Result<PathBuf> {
    require(
        !value.is_empty()
            && value.len() <= 4096
            && !value.chars().any(char::is_control)
            && !value.contains('\\'),
        "Git metadata path unsupported",
    )?;
    let bytes = value.as_bytes();
    if bytes.get(1) == Some(&b':') {
        require(
            bytes[0].is_ascii_alphabetic()
                && bytes.get(2) == Some(&b'/')
                && !value[2..].contains(':'),
            "Git drive path unsupported",
        )?;
        let tail = &value[3..];
        require(
            !tail.is_empty()
                && tail
                    .split('/')
                    .all(|p| !p.is_empty() && p != "." && p != ".."),
            "Git drive path contains traversal",
        )?;
        return Ok(PathBuf::from(format!(
            "/mnt/{}/{}",
            (bytes[0] as char).to_ascii_lowercase(),
            tail
        )));
    }
    require(
        !value.contains(':') && !value.starts_with("//"),
        "Git metadata path unsupported",
    )?;
    let path = Path::new(value);
    Ok(if path.is_absolute() {
        path.into()
    } else {
        relative_to.join(path)
    })
}
fn source_git_directory(source: &Path) -> Result<PathBuf> {
    let source = source
        .canonicalize()
        .map_err(|_| "source directory unavailable")?;
    let marker = source.join(".git");
    let metadata = fs::symlink_metadata(&marker).map_err(|_| "source Git marker unavailable")?;
    require(
        !metadata.file_type().is_symlink(),
        "source Git marker is linked",
    )?;
    if metadata.is_dir() {
        return marker
            .canonicalize()
            .map_err(|_| "source Git directory unavailable".into());
    }
    let line = git_metadata_line(&marker)?;
    let registry = git_metadata_path(
        line.strip_prefix("gitdir: ")
            .ok_or("source Git marker malformed")?,
        &source,
    )?
    .canonicalize()
    .map_err(|_| "worktree registry unavailable")?;
    require(registry.is_dir(), "worktree registry is not directory")?;
    let backpointer = git_metadata_path(&git_metadata_line(&registry.join("gitdir"))?, &registry)?
        .canonicalize()
        .map_err(|_| "worktree backpointer unavailable")?;
    require(
        backpointer == marker,
        "worktree backpointer differs from source",
    )?;
    Ok(registry)
}
#[test]
fn fixture_git_registry_translation_is_bounded_and_backpointer_bound() {
    assert_eq!(
        git_metadata_path(
            "C:/Users/example/repo/.git/worktrees/task",
            Path::new("/unused")
        )
        .unwrap(),
        Path::new("/mnt/c/Users/example/repo/.git/worktrees/task")
    );
    for invalid in [
        "C:/../repo",
        "C:/repo/./git",
        "C:\\repo",
        "//host/share",
        "C:/repo//git",
        "C:relative",
        "C:/repo\nother",
    ] {
        assert!(git_metadata_path(invalid, Path::new("/unused")).is_err());
    }
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    let registry = temp.path().join("registry");
    fs::create_dir(&source).unwrap();
    fs::create_dir(&registry).unwrap();
    fs::write(source.join(".git"), "gitdir: ../registry\n").unwrap();
    fs::write(
        registry.join("gitdir"),
        source.join(".git").to_str().unwrap(),
    )
    .unwrap();
    assert_eq!(source_git_directory(&source).unwrap(), registry);
    fs::write(
        registry.join("gitdir"),
        registry.join("gitdir").to_str().unwrap(),
    )
    .unwrap();
    assert!(source_git_directory(&source).is_err());
    fs::write(registry.join("gitdir"), "x".repeat(4097)).unwrap();
    assert!(source_git_directory(&source).is_err());
    fs::remove_file(registry.join("gitdir")).unwrap();
    std::os::unix::fs::symlink(source.join(".git"), registry.join("gitdir")).unwrap();
    assert!(source_git_directory(&source).is_err());
    let ordinary = temp.path().join("ordinary");
    fs::create_dir(&ordinary).unwrap();
    fs::create_dir(ordinary.join(".git")).unwrap();
    assert_eq!(
        source_git_directory(&ordinary).unwrap(),
        ordinary.join(".git")
    );
}

fn source_head(source: &Path) -> Result<String> {
    use std::{
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    let registry = source_git_directory(source)?;
    let mut output = tempfile::tempfile().map_err(|_| "cannot capture source identity")?;
    let mut child = Command::new("/usr/bin/git")
        .arg("--git-dir")
        .arg(&registry)
        .arg("--work-tree")
        .arg(source)
        .args(["rev-parse", "--verify", "HEAD"])
        .current_dir(source)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .stdout(
            output
                .try_clone()
                .map_err(|_| "cannot capture source identity")?,
        )
        .spawn()
        .map_err(|_| "cannot inspect source identity")?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        let bounded = output.metadata().is_ok_and(|m| m.len() <= 128);
        if !bounded || Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err("source identity command exceeded bounds".into());
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("cannot observe source identity command".into());
            }
        }
    };
    require(
        status.success() && output.metadata().is_ok_and(|m| m.len() <= 128),
        "source identity command failed",
    )?;
    output
        .seek(SeekFrom::Start(0))
        .map_err(|_| "cannot read source identity")?;
    let mut value = String::new();
    output
        .take(129)
        .read_to_string(&mut value)
        .map_err(|_| "cannot read source identity")?;
    let value = value.trim();
    require(
        value.len() == 40
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "source identity is invalid",
    )?;
    require(
        source_git_directory(source)? == registry,
        "worktree registry changed during identity observation",
    )?;
    Ok(value.to_owned())
}

fn stage_application_bundle(
    source: &Path,
    root: &Path,
    bundle: &Path,
    bao: &str,
    services: &str,
    operator_sha: &str,
    state: &mut InstallerState,
) -> Result<BTreeMap<String, String>> {
    let source_sha = source_head(source)?;
    let supplied = PathBuf::from(
        std::env::var("MARTY_INSTALLER_TEST_IMAGE_LOCK")
            .map_err(|_| "set adapted fixture MARTY_INSTALLER_TEST_IMAGE_LOCK")?,
    );
    let bytes = bounded_fixture_lock(&supplied)?;
    let original_path = PathBuf::from(
        std::env::var("MARTY_INSTALLER_TEST_ORIGINAL_IMAGE_LOCK")
            .map_err(|_| "set retained published MARTY_INSTALLER_TEST_ORIGINAL_IMAGE_LOCK")?,
    );
    let original_bytes = bounded_fixture_lock(&original_path)?;
    let original: FixtureImageLock =
        serde_json::from_slice(&original_bytes).map_err(|_| "invalid original image lock")?;
    let lock: FixtureImageLock =
        serde_json::from_slice(&bytes).map_err(|_| "invalid fixture image lock")?;
    require(
        original.schema == lock.schema
            && original.services == lock.services
            && original.openbao_didcomm_image == lock.openbao_didcomm_image
            && original.release != lock.release,
        "fixture adaptation may change only release label",
    )?;
    let original_local = root.join("fixture-original-image-lock.json");
    fs::write(&original_local, &original_bytes).map_err(|_| "cannot retain original image lock")?;
    fs::set_permissions(&original_local, fs::Permissions::from_mode(0o600))
        .map_err(|_| "cannot protect original image lock")?;
    let pinned = regex::Regex::new(r"\A[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}\z").unwrap();
    require(
        lock.schema == "marty.selfhost-image-lock/v1"
            && lock.services.len() == 32
            && lock.openbao_didcomm_image == bao
            && lock.services.values().all(|v| pinned.is_match(v)),
        "fixture image lock closure or immutable digests differ",
    )?;
    for role in ["gateway", "signing-keys", "issuance", "issuance-native"] {
        require(
            lock.services.get(role).map(String::as_str) == Some(services),
            "services image differs from provisioning helpers",
        )?;
    }
    require(
        lock.services.get("keycloak") == lock.services.get("keycloak-configurator"),
        "Keycloak image role mismatch",
    )?;
    let stack: Value = serde_json::from_slice(
        &fs::read(source.join("release/stack-lock.json"))
            .map_err(|_| "source stack lock unavailable")?,
    )
    .map_err(|_| "source stack lock invalid")?;
    require(
        stack["release"] == lock.release,
        "fixture lock must match source release",
    )?;
    let local = root.join("fixture-image-lock.json");
    fs::write(&local, &bytes).map_err(|_| "cannot stage fixture image lock")?;
    fs::set_permissions(&local, fs::Permissions::from_mode(0o600))
        .map_err(|_| "cannot protect fixture image lock")?;
    let executable = std::env::var_os("MARTY_INSTALLER_COMPOSE_EXECUTABLE")
        .ok_or("set standalone MARTY_INSTALLER_COMPOSE_EXECUTABLE")?;
    require(
        Path::new(&executable).is_absolute(),
        "Compose executable must be absolute",
    )?;
    marty_selfhost_bundle::package_with_image_lock(
        &marty_selfhost_bundle::Options {
            repo: source.into(),
            output: bundle.into(),
            archive: None,
            replace: false,
        },
        |directory, args| {
            marty_selfhost_bundle::process::compose(directory, args, Some(&executable))
        },
        &local,
    )?;
    // WSL source checkout permissions can reflect the mounted Windows filesystem.
    // Normalize only freshly packaged public fixture assets to their ordinary
    // container-readable modes; bytes/production marker remain unchanged.
    fn protect(path: &Path) -> Result<()> {
        let m = fs::symlink_metadata(path).map_err(|_| "fixture package metadata unavailable")?;
        require(
            !m.file_type().is_symlink(),
            "fixture package contains a link",
        )?;
        if m.is_dir() {
            for entry in fs::read_dir(path).map_err(|_| "fixture package unavailable")? {
                protect(
                    &entry
                        .map_err(|_| "fixture package entry unavailable")?
                        .path(),
                )?;
            }
            fs::set_permissions(path, fs::Permissions::from_mode(0o755))
                .map_err(|_| "cannot protect fixture package directory")?;
        } else {
            require(
                m.is_file() && m.nlink() == 1,
                "fixture package contains special file",
            )?;
            let executable = path.extension().is_some_and(|e| e == "sh");
            fs::set_permissions(
                path,
                fs::Permissions::from_mode(if executable { 0o755 } else { 0o644 }),
            )
            .map_err(|_| "cannot protect fixture package file")?;
        }
        Ok(())
    }
    protect(bundle)?;
    fs::set_permissions(bundle, fs::Permissions::from_mode(0o700))
        .map_err(|_| "cannot protect fixture bundle root")?;
    let marker: Value = serde_json::from_slice(
        &fs::read(bundle.join(marty_selfhost_bundle::MARKER))
            .map_err(|_| "package marker unavailable")?,
    )
    .map_err(|_| "package marker invalid")?;
    for (name, expected) in marker["files"]
        .as_object()
        .ok_or("package marker files absent")?
    {
        require(
            format!(
                "{:x}",
                Sha256::digest(fs::read(bundle.join(name)).map_err(|_| "packaged file absent")?)
            ) == expected.as_str().ok_or("package marker hash invalid")?,
            "fixture package bytes changed",
        )?;
    }
    state.write_evidence("engine-fixture-package.json",&serde_json::to_vec(&json!({"schema":"elevenid.installer-engine-fixture-package/v1","source_sha":source_sha,"operator_sha256":operator_sha,"synthetic_journal_release":"v0.0.0","image_lock_sha256":format!("{:x}",Sha256::digest(&bytes)),"release":lock.release,"original_image_lock_sha256":format!("{:x}",Sha256::digest(&original_bytes)),"original_release":original.release,"adaptation":"release label only for source-based preparation qualification; image mapping unchanged","signed_release_admission":false,"application_started":false})).map_err(|_|"cannot encode package fixture receipt")?)?;
    let mut images = lock.services;
    images.insert("openbao_didcomm_image".into(), bao.into());
    Ok(images)
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

fn run_fixture(renewal: bool, generation: bool, application: bool) -> Result<()> {
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
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let application_images = if application {
        Some(stage_application_bundle(
            &source,
            &root,
            &bundle,
            &image,
            services_image
                .as_deref()
                .ok_or("application fixture needs services image")?,
            operator_sha
                .as_deref()
                .ok_or("application fixture needs static operator")?,
            &mut state,
        )?)
    } else {
        private_directory(&bundle)?;
        private_directory(&bundle.join("docker"))?;
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
        None
    };
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
        let ingress = if application {
            let ingress = marty_deployment_catalog::installer_ingress::provision(
                &executable,
                &installation,
                &bundle,
                &mut state,
                &receipt,
                services,
                operator,
            )?;
            require(
                ingress.container_removed && !ingress.installation_ready,
                "ingress helper did not complete scoped removal",
            )?;
            state.write_evidence(
                "ingress-observation.json",
                &serde_json::to_vec(&ingress).map_err(|_| "cannot encode ingress receipt")?,
            )?;
            Some(ingress)
        } else {
            None
        };
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
        let candidate = if generation {
            let candidate = marty_deployment_catalog::installer_generation_host::provision(
                &executable,
                &installation,
                &bundle,
                &mut state,
                &receipt,
                services,
                operator,
            )?;
            require(
                candidate.container_removed
                    && candidate.candidate_validated
                    && candidate.outputs.len() == 40
                    && candidate.candidate_sha256.len() == 40
                    && !candidate.ingress_renewal
                    && !candidate.activated
                    && !candidate.root_retired
                    && !candidate.installation_ready,
                "candidate generation result differs",
            )?;
            state.write_evidence(
                "generation-observation.json",
                &serde_json::to_vec(&candidate)
                    .map_err(|_| "cannot encode candidate generation receipt")?,
            )?;
            Some(candidate)
        } else {
            None
        };

        if application {
            let mut original_hashes = BTreeMap::new();
            for entry in fs::read_dir(installation.join("secrets"))
                .map_err(|_| "original secrets unavailable")?
            {
                let entry = entry.map_err(|_| "original secret entry unavailable")?;
                let metadata = fs::symlink_metadata(entry.path())
                    .map_err(|_| "original secret metadata unavailable")?;
                require(
                    metadata.is_file()
                        && !metadata.file_type().is_symlink()
                        && metadata.nlink() == 1,
                    "original secret must be ordinary",
                )?;
                original_hashes.insert(
                    entry.file_name(),
                    format!(
                        "{:x}",
                        Sha256::digest(
                            fs::read(entry.path()).map_err(|_| "original secret unreadable")?
                        )
                    ),
                );
            }
            let prepared =
                marty_deployment_catalog::installer_application::prepare_with_generation(
                    &executable,
                    &installation,
                    &bundle,
                    &mut state,
                    &receipt,
                    application_images
                        .as_ref()
                        .ok_or("application image map absent")?,
                )?;
            let selected = marty_deployment_catalog::installer_generation_binding::load_verified(
                &installation,
                &state.journal().installation_id().to_string(),
                &engine,
            )?
            .ok_or("application generation binding absent")?;
            marty_deployment_catalog::installer_generation_binding::verify_model(
                &installation,
                &selected,
                &prepared.plan,
            )?;
            marty_deployment_catalog::installer_application_observation::validate_inputs_with_generation(&prepared.plan,&installation,&bundle,Some(&selected))?;
            require(
                prepared.plan.model["services"]
                    .as_object()
                    .is_some_and(|s| s.len() == 30)
                    && prepared.plan.selected_services.len() == 29
                    && !prepared.plan.installation_ready
                    && !selected.activated
                    && !selected.root_retired
                    && !selected.installation_ready,
                "prepared application must remain unstarted and unready",
            )?;
            for (name, hash) in original_hashes {
                require(
                    format!(
                        "{:x}",
                        Sha256::digest(
                            fs::read(installation.join("secrets").join(name))
                                .map_err(|_| "original secret disappeared")?
                        )
                    ) == hash,
                    "application preparation changed original secret",
                )?;
            }
            let candidate = candidate
                .as_ref()
                .ok_or("application fixture candidate absent")?;
            for (name, hash) in &candidate.candidate_sha256 {
                require(selected.files.get(name).is_some_and(|f|f.source==marty_deployment_catalog::installer_generation_binding::GenerationSource::Candidate&&&f.sha256==hash)&&format!("{:x}",Sha256::digest(selected.read(&installation,name)?))==*hash,"selected candidate bytes differ")?;
            }
            require(
                docker
                    .run_checked(&[
                        "ps",
                        "-aq",
                        "--no-trunc",
                        "--filter",
                        &format!(
                            "label=com.docker.compose.project={}",
                            state.journal().compose_project()
                        ),
                    ])?
                    .trim()
                    .is_empty(),
                "application preparation unexpectedly created containers",
            )?;
            state.write_evidence("engine-fixture-application-prepared.json",&serde_json::to_vec(&json!({"schema":"elevenid.installer-engine-fixture-application/v1","files":selected.files.len(),"candidate_files":40,"selected_services":29,"execution_services":30,"application_started":false,"root_retired":false,"installation_ready":false})).map_err(|_|"cannot encode fixture preparation receipt")?)?;
            drop(prepared); // release only this fixture's four still-held reservations
        }
        let mut helpers = vec![
            ("keycloak", &keycloak.container_id),
            ("tls", &tls.container_id),
            ("renewal", &renewed.container_id),
        ];
        if let Some(candidate) = &candidate {
            helpers.push(("generation", &candidate.container_id));
        }
        if let Some(ingress) = &ingress {
            helpers.push(("ingress", &ingress.container_id));
        }
        for (stage, container) in helpers {
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
