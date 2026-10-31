//! Explicitly opted-in real-component development qualification.
//!
//! The published fixture package is authenticated and retained unchanged. A
//! separate unsigned development copy adds only the three compile-time installer
//! layers. Neither that copy nor the local executable is represented as a signed
//! release. No production verifier, dispatch, credential contract or policy is
//! bypassed or modified by this test-only module.
#![cfg(all(test, target_os = "linux"))]

use crate::{
    installer_artifacts, installer_bundle,
    installer_command::{provision_runtime, RuntimeCompletion, RuntimeInvocation},
    installer_release as release,
    installer_runtime::{self, DockerRunner},
    installer_state::{
        CandidateTestScope, Identity, InstallerState, Phase, RuntimeBinding, RuntimeProfile,
    },
    installer_verify,
};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Instant,
};

type Result<T> = std::result::Result<T, String>;
const TAG: &str = "v1.1.263-nightly.20261029.40946723707";
const SOURCE: &str = "225818494f4ba716e75df7225d6c43d71b038879";
const INVENTORY_SHA: &str = "972cf706ba3c98a5d8e76eb8df1cc29d6e48631895b1115302791399c284b319";
const HOLD: &str = "Owned application startup observations recorded. Explicit local CA trust onboarding and installed journey qualification remain incomplete; preserve the reported state for recovery. Installation is not ready.";
#[cfg(not(feature = "installer-development"))]
const HELPER_IDENTITY: &str = "unknown:unreleased";
#[cfg(feature = "installer-development")]
const HELPER_IDENTITY: &str = crate::installer_development_image::HELPER_IDENTITY;
const LAYERS: [(&str, &[u8]); 3] = [
    (
        "deploy-config/compose/selfhost-installer/compose.bootstrap.yml",
        include_bytes!(
            "../../../../deploy-config/compose/selfhost-installer/compose.bootstrap.yml"
        ),
    ),
    (
        "deploy-config/compose/selfhost-installer/compose.installer.yml",
        include_bytes!(
            "../../../../deploy-config/compose/selfhost-installer/compose.installer.yml"
        ),
    ),
    (
        "deploy-config/compose/selfhost-installer/compose.runtime.yml",
        include_bytes!("../../../../deploy-config/compose/selfhost-installer/compose.runtime.yml"),
    ),
];

fn need(value: bool, message: &str) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn input(name: &str) -> Result<String> {
    std::env::var(name)
        .ok()
        .filter(|v| !v.is_empty() && v.len() <= 4096 && !v.bytes().any(|b| b.is_ascii_control()))
        .ok_or_else(|| format!("explicit unsigned development input required: {name}"))
}

fn digest_shape(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn parent(path: &Path) -> Result<()> {
    installer_runtime::private_parent(path)?;
    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor.join("installation.json")) {
            Ok(_) => return Err("development parent is inside an existing installation".into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err("development parent ancestry is uncertain".into()),
        }
    }
    Ok(())
}

fn static_helper(path: &Path, expected: &str) -> Result<()> {
    need(
        digest_shape(expected) && installer_verify::operator_digest(path)? == expected,
        "development helper digest differs",
    )?;
    let mut file = File::open(path).map_err(|_| "development helper unavailable")?;
    let size = file
        .metadata()
        .map_err(|_| "development helper metadata unavailable")?
        .len();
    let mut header = [0u8; 64];
    file.read_exact(&mut header)
        .map_err(|_| "development helper ELF header unavailable")?;
    need(
        &header[..7] == b"\x7fELF\x02\x01\x01"
            && u16::from_le_bytes([header[18], header[19]]) == 62,
        "development helper must be amd64 ELF",
    )?;
    let offset = u64::from_le_bytes(header[32..40].try_into().unwrap());
    let count = u16::from_le_bytes([header[56], header[57]]);
    need(
        u16::from_le_bytes([header[54], header[55]]) == 56
            && (1..=128).contains(&count)
            && offset >= 64
            && offset
                .checked_add(u64::from(count) * 56)
                .is_some_and(|end| end <= size),
        "development helper ELF table invalid",
    )?;
    file.seek(SeekFrom::Start(offset))
        .map_err(|_| "development helper ELF seek failed")?;
    let mut load = false;
    for _ in 0..count {
        let mut entry = [0u8; 56];
        file.read_exact(&mut entry)
            .map_err(|_| "development helper ELF entry unavailable")?;
        let kind = u32::from_le_bytes(entry[..4].try_into().unwrap());
        need(
            kind != 3,
            "development helper must not require a dynamic interpreter",
        )?;
        load |= kind == 1;
    }
    need(load, "development helper has no loadable segment")?;
    let output = std::process::Command::new(path)
        .arg("--build-identity")
        .output()
        .map_err(|_| "development build identity unavailable")?;
    need(
        output.status.success()
            && output.stdout == format!("{HELPER_IDENTITY}\n").as_bytes()
            && output.stderr.is_empty(),
        "development helper must explicitly identify as unreleased",
    )?;
    need(
        installer_verify::operator_digest(path)? == expected,
        "development helper changed",
    )
}

fn exclusive(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| "development evidence already exists or cannot be created")?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| "development evidence write failed")?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|_| "development evidence mode failed")?;
    File::open(path.parent().ok_or("development evidence parent absent")?)
        .and_then(|p| p.sync_all())
        .map_err(|_| "development evidence sync failed".into())
}

#[cfg(feature = "installer-development")]
fn import_signing_image(
    state: &mut InstallerState,
    installation: &Path,
    docker: &DockerRunner,
    artifact_bytes: &[u8],
    archive_source: &Path,
) -> Result<()> {
    use crate::installer_development_image::{self as development, Artifact, DevelopmentImage};
    let artifact = Artifact::parse(artifact_bytes)?;
    artifact.verify_archive(archive_source)?;
    let archive = installation.join("downloads").join(development::ARCHIVE);
    let mut source = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(archive_source)
        .map_err(|_| "development image archive unavailable")?;
    let mut destination = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&archive)
        .map_err(|_| "development image archive destination must be new")?;
    let copied = std::io::copy(
        &mut (&mut source).take(artifact.archive_size + 1),
        &mut destination,
    )
    .map_err(|_| "development image archive staging failed")?;
    destination
        .sync_all()
        .map_err(|_| "development image archive sync failed")?;
    need(
        copied == artifact.archive_size,
        "development image archive size changed",
    )?;
    artifact.verify_archive(&archive)?;
    artifact.verify_archive(archive_source)?;
    state.write_evidence(development::ARTIFACT_RECORD, artifact_bytes)?;
    for tag in [
        format!("{}:latest", artifact.archive_tag),
        format!(
            "elevenid/marty-ui-installer-development:{}",
            artifact.archive_tag
        ),
    ] {
        let filter = format!("reference={tag}");
        let existing = docker.run_checked(&[
            "image",
            "ls",
            "--no-trunc",
            "--format",
            "{{json .}}",
            "--filter",
            &filter,
        ])?;
        let entries: Vec<_> = existing
            .lines()
            .filter(|line| !line.trim().is_empty())
            .collect();
        need(
            entries.len() <= 1,
            "development archive tag has ambiguous existing ownership",
        )?;
        if !entries.is_empty() {
            let observed = docker.run_checked(&["image", "inspect", &tag])?;
            let values: Vec<Value> = serde_json::from_value(
                crate::installer_json::decode(observed.as_bytes())
                    .map_err(|_| "existing development tag inspection invalid")?,
            )
            .map_err(|_| "existing development tag inspection invalid")?;
            need(
                values.len() == 1,
                "existing development tag inspection is ambiguous",
            )?;
            DevelopmentImage::from_inspected(artifact_bytes, &values[0])?;
        }
    }
    state.write_evidence("development-signing-image-load-intent.json", &encoded(&json!({
        "schema":"elevenid.installer-development-image-load/v1", "installation_id":state.journal().installation_id(),
        "engine_id":state.journal().runtime().ok_or("development runtime absent")?.engine_id,
        "artifact_sha256":release::sha256(artifact_bytes), "archive":archive,
        "publisher_authenticated":false, "installation_ready":false
    }))?)?;
    let loaded = docker.run_checked_with_timeout(
        &[
            "image",
            "load",
            "--input",
            archive.to_str().ok_or("development archive path invalid")?,
        ],
        std::time::Duration::from_secs(900),
    );
    state.write_evidence("development-signing-image-load-result.json", &encoded(&json!({
        "succeeded":loaded.is_ok(), "output":loaded.as_ref().ok(), "error":loaded.as_ref().err(),
        "automatic_retry":false, "publisher_authenticated":false
    }))?)?;
    loaded?;
    artifact.verify_archive(&archive)?;
    let mut selected = None;
    for reference in [&artifact.manifest_digest, &artifact.config_digest] {
        let Ok(output) = docker.run_checked(&["image", "inspect", reference]) else {
            continue;
        };
        let values: Vec<Value> = serde_json::from_value(
            crate::installer_json::decode(output.as_bytes())
                .map_err(|_| "development image inspection invalid")?,
        )
        .map_err(|_| "development image inspection invalid")?;
        need(
            values.len() == 1,
            "development image inspection is ambiguous",
        )?;
        selected = Some(DevelopmentImage::from_inspected(
            artifact_bytes,
            &values[0],
        )?);
        break;
    }
    let selected =
        selected.ok_or("loaded development image cannot be bound to its OCI identity")?;
    state.write_evidence(
        development::BINDING_RECORD,
        &serde_json::to_vec(&selected).map_err(|_| "development image binding encoding failed")?,
    )?;
    state.write_evidence(development::LAYER_RECORD, &selected.layer_bytes()?)?;
    state.with_inspection(|view| {
        need(
            development::load(view)?.as_ref() == Some(&selected),
            "development image readback differs",
        )
    })
}

fn encoded(value: &Value) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| "development evidence encoding failed".into())
}

/// Exercise the real-layer native parser assertion before any container is
/// created. The nonsecret environment uses the same production renderer, but
/// none of its prospective paths, ports or accounts is materialized here.
fn actual_layer_parser_gate(
    installation: &Path,
    bundle: &Path,
    state: &mut InstallerState,
    inventory: &release::Inventory,
) -> Result<()> {
    let tests = PathBuf::from(input("MARTY_DEV_COMPOSE_NATIVE_TESTS")?);
    let tests_sha = input("MARTY_DEV_COMPOSE_NATIVE_TESTS_SHA256")?;
    need(
        digest_shape(&tests_sha) && installer_verify::operator_digest(&tests)? == tests_sha,
        "native parser test artifact differs",
    )?;
    let compose = PathBuf::from(input("MARTY_DEV_COMPOSE_EXECUTABLE")?);
    let compose_sha = input("MARTY_DEV_COMPOSE_EXECUTABLE_SHA256")?;
    let metadata =
        fs::symlink_metadata(&compose).map_err(|_| "native Compose executable unavailable")?;
    need(
        compose.is_absolute()
            && compose
                .canonicalize()
                .map_err(|_| "native Compose path unavailable")?
                == compose
            && metadata.is_file()
            && metadata.uid() == 0
            && metadata.mode() & 0o022 == 0
            && digest_shape(&compose_sha)
            && release::sha256(
                &fs::read(&compose).map_err(|_| "native Compose executable unreadable")?,
            ) == compose_sha,
        "native Compose executable binding differs",
    )?;
    let example = crate::installer_tls_outputs::bundle_text(
        bundle,
        ".env.selfhost.production.example",
        16384,
    )?;
    let canonical =
        crate::installer_tls_outputs::bundle_text(bundle, "docker-compose.yml", 262144)?;
    let tls_fragment = example
        .lines()
        .filter(|line| {
            line.split_once('=')
                .is_some_and(|(key, _)| key.contains("_TLS_KMS_KEY_") && !key.starts_with('#'))
        })
        .collect::<Vec<_>>()
        .join("\n");
    let binding = state
        .journal()
        .runtime()
        .ok_or("development runtime binding absent")?;
    let parameters = crate::installer_application_env::ApplicationParameters {
        installation: installation.into(),
        applicant_container_group: crate::installer_state::applicant_container_group(binding)?,
        version: inventory.release_tag.clone(),
        origin: "https://localhost:10443".into(),
        gateway_port: 18080,
        keycloak_port: 18081,
        edge_port: 18082,
        openbao_port: 18200,
    };
    let mut environment = crate::installer_application_env::render(
        &example,
        &canonical,
        &tls_fragment,
        &parameters,
        &inventory.images,
    )?
    .env_bytes;
    for (key, value) in [
        (
            "MARTY_INSTALLATION_DIR",
            installation
                .to_str()
                .ok_or("parser installation path invalid")?
                .into(),
        ),
        (
            "MARTY_INSTALLATION_ID",
            state.journal().installation_id().to_string(),
        ),
        (
            "MARTY_INSTALLER_SERVICES_IMAGE",
            inventory
                .images
                .get("gateway")
                .ok_or("parser services image absent")?
                .clone(),
        ),
        ("MARTY_KEYCLOAK_NONCE", "parser-only-native-compose".into()),
        (
            "MARTY_SELFHOST_PROJECT",
            format!(
                "marty-selfhost-disposable-{}",
                state.journal().installation_id().simple()
            ),
        ),
        (
            "MARTY_INSTALLER_ID",
            state.journal().installation_id().to_string(),
        ),
        (
            "MARTY_INSTALLER_APPLICANT_CONTAINER_GID",
            parameters
                .applicant_container_group
                .container_gid()
                .to_string(),
        ),
        (
            "MARTY_INSTALLER_NGINX_CONFIG",
            installation
                .join("evidence/parser-only-nginx.conf")
                .to_str()
                .ok_or("parser input path invalid")?
                .into(),
        ),
        (
            "MARTY_INSTALLER_HELPER_IMAGE",
            inventory
                .images
                .get("gateway")
                .ok_or("parser gateway image absent")?
                .clone(),
        ),
        ("MARTY_INSTALLER_HTTPS_PORT", "10443".into()),
        (
            "MARTY_INSTALLER_INGRESS_KEY_NAME",
            crate::installer_ingress_provision::resource_name(
                &state.journal().installation_id().to_string(),
            )?,
        ),
    ] {
        need(
            !value
                .chars()
                .any(|c| c.is_control() || c == '\'' || c == '\\'),
            "parser input is not encodable",
        )?;
        environment.extend_from_slice(format!("{key}='{value}'\n").as_bytes());
    }
    state.write_evidence("development-parser.env", &environment)?;
    let test = "actual_installer_layers_keep_native_dependencies_and_exclude_setup_on_restart";
    let mut command = std::process::Command::new(&tests);
    command
        .args([test, "--exact", "--ignored", "--test-threads=1"])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", installation)
        .env("LANG", "C.UTF-8")
        .env("MARTY_INSTALLER_COMPOSE_EXECUTABLE", &compose)
        .env("MARTY_INSTALLER_COMPOSE_BUNDLE", bundle)
        .env(
            "MARTY_INSTALLER_COMPOSE_TEST_ENV",
            installation.join("evidence/development-parser.env"),
        )
        .env("MARTY_INSTALLER_SOURCE_ROOT", bundle)
        .stdin(std::process::Stdio::null());
    #[cfg(feature = "installer-development")]
    let development_image = state.with_inspection(crate::installer_development_image::load)?;
    #[cfg(feature = "installer-development")]
    if let Some(image) = &development_image {
        command
            .arg("--nocapture")
            .env(
                "MARTY_INSTALLER_DEVELOPMENT_IMAGE_LAYER",
                image.layer_file(installation)?.path,
            )
            .env("MARTY_INSTALLER_DEVELOPMENT_IMAGE_ID", &image.image_id);
    }
    let output = command
        .output()
        .map_err(|_| "native parser test could not start")?;
    #[cfg(not(feature = "installer-development"))]
    let development_parsed = true;
    #[cfg(feature = "installer-development")]
    let development_parsed = development_image.as_ref().is_none_or(|image| {
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .any(|line| line == format!("UNSIGNED_SIGNING_IMAGE_PARSED={}", image.image_id))
    });
    need(
        output.stdout.len() <= 1048576 && output.stderr.len() <= 1048576,
        "native parser evidence exceeds bounds",
    )?;
    if !output.stdout.is_empty() {
        state.write_evidence("development-parser.stdout", &output.stdout)?;
    }
    if !output.stderr.is_empty() {
        state.write_evidence("development-parser.stderr", &output.stderr)?;
    }
    state.write_evidence(
        "development-parser-result.json",
        &encoded(&json!({
        "schema":"elevenid.unsigned-compose-development-parser/v1", "test":test,
        "native_tests_sha256":tests_sha, "compose_sha256":compose_sha,
        "exit_code":output.status.code(), "passed":output.status.success() && development_parsed,
        "stdout_bytes":output.stdout.len(), "stderr_bytes":output.stderr.len(),
        "config_only":true, "application_resources_started":false,
        "local_package_publisher_authenticated":false}))?,
    )?;
    need(
        installer_verify::operator_digest(&tests)? == tests_sha
            && release::sha256(
                &fs::read(&compose).map_err(|_| "native Compose executable unavailable")?,
            ) == compose_sha,
        "parser executable changed during config-only gate",
    )?;
    need(
        output.status.success() && development_parsed,
        "actual installer-layer native parser gate failed; inspect private parser evidence",
    )
}

fn copy_bundle(source: &Path, destination: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(source).map_err(|_| "development fixture unavailable")?;
    need(
        !metadata.file_type().is_symlink() && metadata.uid() == unsafe { libc::geteuid() },
        "development fixture type or owner differs",
    )?;
    if metadata.is_dir() {
        need(
            metadata.mode() & 0o7777 == 0o755,
            "authenticated bundle directory mode differs",
        )?;
        fs::create_dir(destination).map_err(|_| "development bundle destination must be new")?;
        fs::set_permissions(destination, fs::Permissions::from_mode(0o755))
            .map_err(|_| "development directory mode failed")?;
        for entry in fs::read_dir(source).map_err(|_| "development bundle enumeration failed")? {
            let entry = entry.map_err(|_| "development bundle entry unavailable")?;
            copy_bundle(&entry.path(), &destination.join(entry.file_name()))?;
        }
    } else {
        need(
            metadata.is_file()
                && metadata.nlink() == 1
                && matches!(metadata.mode() & 0o7777, 0o644 | 0o755),
            "authenticated bundle file policy differs",
        )?;
        let mut incoming = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(source)
            .map_err(|_| "authenticated bundle source unavailable")?;
        let mut outgoing = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(metadata.mode() & 0o7777)
            .custom_flags(libc::O_NOFOLLOW)
            .open(destination)
            .map_err(|_| "development bundle file already exists")?;
        let count = std::io::copy(&mut incoming, &mut outgoing)
            .map_err(|_| "development bundle copy failed")?;
        need(count == metadata.len(), "development bundle source changed")?;
        outgoing
            .sync_all()
            .map_err(|_| "development bundle copy sync failed")?;
        fs::set_permissions(
            destination,
            fs::Permissions::from_mode(metadata.mode() & 0o7777),
        )
        .map_err(|_| "development bundle copy mode failed")?;
    }
    Ok(())
}

fn development_bundle(installation: &Path, authenticated: &Path) -> Result<(PathBuf, Value)> {
    let outer = installation.join("development-package");
    fs::create_dir(&outer).map_err(|_| "development package parent must be new")?;
    fs::set_permissions(&outer, fs::Permissions::from_mode(0o700))
        .map_err(|_| "development package parent mode failed")?;
    let bundle = outer.join("selfhost-prepared");
    copy_bundle(authenticated, &bundle)?;
    let marker_path = bundle.join(".marty-selfhost-bundle.json");
    let original = fs::read(&marker_path).map_err(|_| "development package marker unavailable")?;
    let mut marker: Value =
        serde_json::from_slice(&original).map_err(|_| "development package marker invalid")?;
    let mut directories: BTreeSet<String> = marker["directories"]
        .as_array()
        .ok_or("bundle directories missing")?
        .iter()
        .map(|v| {
            v.as_str()
                .map(str::to_owned)
                .ok_or("bundle directory invalid".into())
        })
        .collect::<Result<_>>()?;
    let mut records = Vec::new();
    for (name, bytes) in LAYERS {
        need(
            marker["files"].get(name).is_none(),
            "published fixture unexpectedly already includes development layer",
        )?;
        let relative = Path::new(name);
        let mut ancestors: Vec<_> = relative
            .parent()
            .ok_or("layer directory absent")?
            .ancestors()
            .collect();
        ancestors.reverse();
        for ancestor in ancestors {
            if ancestor.as_os_str().is_empty() {
                continue;
            }
            let child = bundle.join(ancestor);
            if !child.exists() {
                fs::create_dir(&child)
                    .map_err(|_| "development layer directory creation failed")?;
                fs::set_permissions(&child, fs::Permissions::from_mode(0o755))
                    .map_err(|_| "development layer directory mode failed")?;
            }
            directories.insert(
                ancestor
                    .to_str()
                    .ok_or("development layer path invalid")?
                    .into(),
            );
        }
        exclusive(&bundle.join(name), bytes, 0o644)?;
        let hash = release::sha256(bytes);
        marker["files"]
            .as_object_mut()
            .ok_or("development marker files absent")?
            .insert(name.into(), json!(hash));
        records.push(json!({"path":name,"sha256":hash,"bytes":bytes.len(),"authentication":"compiled into unsigned development test executable"}));
    }
    marker["directories"] = json!(directories);
    let bytes = encoded(&marker)?;
    // Only this fresh development copy's non-authenticating file marker changes.
    // The original extraction, archive, signatures and inventory remain intact.
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&marker_path)
        .map_err(|_| "development marker unavailable")?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| "development marker write failed")?;
    Ok((
        bundle,
        json!({"classification":"UNSIGNED DEVELOPMENT ONLY","original_marker_sha256":release::sha256(&original),
        "development_marker_sha256":release::sha256(&bytes),"local_layers":records,
        "original_authenticated_extraction_preserved":true,"local_package_publisher_authenticated":false}),
    ))
}

fn container_ids(docker: &DockerRunner) -> Result<BTreeSet<String>> {
    let text = docker.run_checked(&["ps", "-aq", "--no-trunc"])?;
    let names: Vec<_> = text.lines().filter(|s| !s.is_empty()).collect();
    need(
        names.iter().all(|s| digest_shape(s)),
        "development container inventory invalid",
    )?;
    let ids: BTreeSet<_> = names.iter().map(|s| (*s).to_owned()).collect();
    need(
        ids.len() == names.len(),
        "development container inventory ambiguous",
    )?;
    Ok(ids)
}

#[test]
fn local_development_layers_preserve_authenticated_original_and_refuse_replacement() -> Result<()> {
    let directory = tempfile::tempdir().map_err(|_| "temporary fixture unavailable")?;
    let installation = directory.path().join("installation");
    let authenticated = directory.path().join("selfhost-prepared");
    fs::create_dir(&installation).map_err(|_| "fixture installation unavailable")?;
    fs::create_dir(&authenticated).map_err(|_| "fixture bundle unavailable")?;
    fs::set_permissions(&authenticated, fs::Permissions::from_mode(0o755))
        .map_err(|_| "fixture mode failed")?;
    let original_bytes = b"authenticated original fixture bytes\n";
    exclusive(&authenticated.join("original.txt"), original_bytes, 0o644)?;
    let original_marker = encoded(&json!({"schema":"marty.selfhost-bundle-files/v1",
        "files":{"original.txt":release::sha256(original_bytes)},"directories":[""]}))?;
    exclusive(
        &authenticated.join(".marty-selfhost-bundle.json"),
        &original_marker,
        0o644,
    )?;
    let (developed, record) = development_bundle(&installation, &authenticated)?;
    need(
        fs::read(authenticated.join(".marty-selfhost-bundle.json"))
            .map_err(|_| "original marker missing")?
            == original_marker,
        "development overlay changed original marker",
    )?;
    need(
        fs::read(authenticated.join("original.txt")).map_err(|_| "original fixture missing")?
            == original_bytes
            && fs::read(developed.join("original.txt")).map_err(|_| "copied fixture missing")?
                == original_bytes,
        "development overlay changed existing payload",
    )?;
    need(
        !authenticated.join("deploy-config").exists()
            && record["local_package_publisher_authenticated"] == false,
        "development overlay changed original tree or claimed authentication",
    )?;
    let marker: Value = serde_json::from_slice(
        &fs::read(developed.join(".marty-selfhost-bundle.json"))
            .map_err(|_| "development marker missing")?,
    )
    .map_err(|_| "development marker invalid")?;
    need(
        marker["files"]
            .as_object()
            .ok_or("development marker files missing")?
            .len()
            == 4,
        "development overlay added an unexpected file",
    )?;
    for (name, bytes) in LAYERS {
        need(
            fs::read(developed.join(name)).map_err(|_| "development layer missing")? == bytes
                && marker["files"][name] == release::sha256(bytes),
            "development layer content binding differs",
        )?;
    }
    let another = directory.path().join("another-installation");
    fs::create_dir(&another).map_err(|_| "second fixture installation unavailable")?;
    need(
        development_bundle(&another, &developed).is_err(),
        "development overlay replaced already inventoried layers",
    )
}

#[test]
#[ignore = "explicit opt-in only: unsigned local Compose implementation with authenticated pinned Marty image fixtures"]
fn actual_pinned_marty_components_with_unsigned_compose_layers() -> Result<()> {
    need(
        input("MARTY_DEV_COMPOSE_OPT_IN")? == "I_ACCEPT_UNSIGNED_DEVELOPMENT_COMPOSE",
        "development opt-in absent",
    )?;
    crate::installer_command::require_rootless_process()?;
    let parent_path = PathBuf::from(input("MARTY_DEV_COMPOSE_PARENT")?);
    let fixtures = PathBuf::from(input("MARTY_DEV_COMPOSE_FIXTURES")?);
    let tools_path = PathBuf::from(input("MARTY_DEV_COMPOSE_TOOLS")?);
    let gh = PathBuf::from(input("MARTY_DEV_COMPOSE_GH")?);
    let docker = PathBuf::from(input("MARTY_DEV_COMPOSE_DOCKER")?);
    let helper = PathBuf::from(input("MARTY_DEV_COMPOSE_HELPER")?);
    let helper_sha = input("MARTY_DEV_COMPOSE_HELPER_SHA256")?;
    for directory in [&parent_path, &fixtures, &tools_path] {
        parent(directory)?;
    }
    static_helper(&helper, &helper_sha)?;
    #[cfg(feature = "installer-development")]
    let (development_artifact, development_archive) = {
        let bytes = installer_verify::read_private_record(&PathBuf::from(input(
            "MARTY_DEV_COMPOSE_SIGNING_IMAGE_ARTIFACT",
        )?))?;
        let artifact = crate::installer_development_image::Artifact::parse(&bytes)?;
        need(
            release::sha256(&bytes) == input("MARTY_DEV_COMPOSE_SIGNING_IMAGE_ARTIFACT_SHA256")?
                && artifact.source_sha == input("MARTY_DEV_COMPOSE_SIGNING_IMAGE_SOURCE")?,
            "development image artifact or selected source differs",
        )?;
        let archive = PathBuf::from(input("MARTY_DEV_COMPOSE_SIGNING_IMAGE_ARCHIVE")?);
        artifact.verify_archive(&archive)?;
        (bytes, archive)
    };
    let inventory_path = fixtures.join("installer-inventory.json");
    let inventory_bytes = installer_verify::read_private_record(&inventory_path)?;
    need(
        release::sha256(&inventory_bytes) == INVENTORY_SHA,
        "published fixture inventory differs",
    )?;
    let inventory = release::parse_inventory(&inventory_bytes)?;
    need(
        inventory.release_tag == TAG && inventory.source_sha == SOURCE,
        "published fixture identity differs",
    )?;
    let tools = installer_verify::VerificationTools::new(&tools_path, &gh)?;
    let workflow = release::build_workflow(&inventory.release_tag)?;
    let mut sidecars = Vec::new();
    for name in [
        "installer-inventory.json",
        "prepared-selfhost-images.json",
        "prepared-selfhost-bundle.zip",
    ] {
        let subject = fixtures.join(name);
        let expected = if name == "installer-inventory.json" {
            INVENTORY_SHA
        } else {
            let artifact = inventory.artifact(name)?;
            installer_verify::check_private_asset(&subject, &artifact.sha256, artifact.size)?;
            &artifact.sha256
        };
        let observed: Vec<_> = [".sigstore.json", ".provenance.jsonl"]
            .into_iter()
            .map(|suffix| {
                let name = format!("{name}{suffix}");
                installer_verify::read_private_bytes(&fixtures.join(&name), 1048576)
                    .map(|bytes| (name, bytes))
            })
            .collect::<Result<_>>()?;
        need(
            tools.verify(
                &subject,
                workflow,
                &inventory.source_sha,
                inventory.build_run_id,
                inventory.build_run_attempt,
            )? == expected,
            "published fixture authentication failed",
        )?;
        for (name, bytes) in observed {
            need(
                installer_verify::read_private_bytes(&fixtures.join(&name), 1048576)? == bytes,
                "fixture proof changed",
            )?;
            sidecars.push((name, bytes));
        }
    }
    need(
        installer_verify::read_private_record(&inventory_path)? == inventory_bytes,
        "fixture inventory changed",
    )?;
    let lock =
        installer_verify::read_private_record(&fixtures.join("prepared-selfhost-images.json"))?;
    let reservation = std::net::TcpListener::bind(("127.0.0.1", 0))
        .map_err(|_| "development OpenBao port reservation failed")?;
    let binding = RuntimeBinding {
        docker_host: format!("unix:///run/user/{}/docker.sock", unsafe {
            libc::geteuid()
        }),
        engine_id: input("MARTY_DEV_COMPOSE_ENGINE_ID")?,
        openbao_port: reservation
            .local_addr()
            .map_err(|_| "reserved port unavailable")?
            .port(),
        profile: RuntimeProfile::Rootless,
    };
    let observer = DockerRunner::from_binding(&docker, &binding, &parent_path)?;
    let observed = observer.preflight()?;
    let before = container_ids(&observer)?;
    let installation = parent_path.join(format!(
        "marty-development-compose-{}",
        uuid::Uuid::new_v4().simple()
    ));
    eprintln!(
        "UNSIGNED DEVELOPMENT Compose evidence: {}",
        installation.display()
    );
    let identity = Identity {
        source_sha: inventory.source_sha.clone(),
        release_tag: inventory.release_tag.clone(),
        inventory_sha256: format!("sha256:{INVENTORY_SHA}"),
    };
    let fixture_scope = CandidateTestScope {
        inventory_sha256: INVENTORY_SHA.into(),
        build_run_id: inventory.build_run_id,
        build_run_attempt: inventory.build_run_attempt,
    };
    #[cfg(not(feature = "installer-development"))]
    let mut state =
        InstallerState::create_test_with_runtime(&installation, identity, binding, fixture_scope)?;
    #[cfg(feature = "installer-development")]
    let mut state = InstallerState::create_development_with_runtime(
        &installation,
        identity,
        binding,
        crate::installer_state::UnsignedDevelopmentScope {
            fixture: fixture_scope,
            artifact_sha256: release::sha256(&development_artifact),
        },
    )?;
    let started = Instant::now();
    let mut stage = "authenticated fixture staging";
    let mut canary_restored = false;
    let outcome = (|| -> Result<()> {
        state.create_private_directory("evidence")?;
        state.create_private_directory("downloads")?;
        state.write_evidence("development-scope.json", &encoded(&json!({"schema":"elevenid.unsigned-compose-development/v1",
            "classification":"UNSIGNED DEVELOPMENT ONLY","helper_sha256":helper_sha,"helper_build_identity":HELPER_IDENTITY,
            "helper_publisher_authenticated":false,"fixture_inventory_sha256":INVENTORY_SHA,"fixture_release":TAG,"fixture_source":SOURCE,
            "journal_identity_identifies_published_fixtures_only":true,"fixture_inventory_authenticates_local_operator":false,
            "runtime_provisioning_authorized":true,"release_admission":false,"installation_ready":false,"automatic_failure_cleanup":false}))?)?;
        for name in ["candidate-test-inventory.json", "installer-inventory.json"] {
            state.write_evidence(name, &inventory_bytes)?;
        }
        state.write_evidence("prepared-selfhost-images.json", &lock)?;
        for (name, bytes) in sidecars {
            state.write_evidence(&name, &bytes)?;
        }
        #[cfg(feature = "installer-development")]
        {
            stage = "bind unsigned Signing Keys artifact to the native image";
            eprintln!("UNSIGNED DEVELOPMENT Compose stage: {stage}");
            import_signing_image(
                &mut state,
                &installation,
                &observer,
                &development_artifact,
                &development_archive,
            )?;
        }
        state.write_evidence(
            "docker-preflight.json",
            &serde_json::to_vec(&observed).map_err(|_| "Docker preflight encoding failed")?,
        )?;
        state.write_evidence(
            "development-existing-container-ids.json",
            &json!(before).to_string().into_bytes(),
        )?;
        state.persist_operator(&helper, &helper_sha)?;
        let authenticated = installer_artifacts::extract_bundle(
            &fixtures.join("prepared-selfhost-bundle.zip"),
            &installation.join("downloads/extracted"),
            &inventory.artifact("prepared-selfhost-bundle.zip")?.sha256,
        )?;
        let original_report = installer_bundle::validate_bundle(&authenticated, &inventory, &lock)?;
        state.write_evidence(
            "authenticated-fixture-bundle-validation.json",
            &serde_json::to_vec(&original_report).map_err(|_| "fixture report encoding failed")?,
        )?;
        let (bundle, development) = development_bundle(&installation, &authenticated)?;
        let report = installer_bundle::validate_bundle(&bundle, &inventory, &lock)?;
        state.write_evidence("development-package.json", &encoded(&development)?)?;
        state.write_evidence(
            "bundle-validation.json",
            &serde_json::to_vec(&report).map_err(|_| "development report encoding failed")?,
        )?;
        let original_after = installer_bundle::validate_bundle(&authenticated, &inventory, &lock)?;
        need(
            original_after.marker_sha256 == original_report.marker_sha256,
            "authenticated original bundle changed",
        )?;
        stage = "actual installer-layer native parser gate (config only)";
        eprintln!("UNSIGNED DEVELOPMENT Compose stage: {stage}");
        actual_layer_parser_gate(&installation, &bundle, &mut state, &inventory)?;
        state.advance(Phase::Verified)?;
        stage = "rootless storage ownership canary";
        eprintln!("UNSIGNED DEVELOPMENT Compose stage: {stage}");
        crate::installer_rootless_storage_canary::qualify_candidate(
            &docker,
            &installation,
            &mut state,
            &inventory,
            &helper_sha,
        )?;
        state.with_inspection(|view| {
            let result: Value =
                serde_json::from_slice(&view.read_evidence("rootless-canary-result.json")?)
                    .map_err(|_| "canary result invalid")?;
            need(
                result["host_traversal_restored"] == true
                    && result["deletion_authorized"] == false
                    && result["installation_ready"] == false,
                "rootless canary restoration incomplete",
            )
        })?;
        canary_restored = true;
        stage = "fresh application storage preflight";
        eprintln!("UNSIGNED DEVELOPMENT Compose stage: {stage}");
        let mut absent_storage_paths = Vec::new();
        for relative in [
            "state",
            "state/postgres",
            "state/redis",
            "state/applicant",
            "backups",
            "openbao-exports",
            "openbao-snapshot-identity",
        ] {
            let path = installation.join(relative);
            need(
                matches!(fs::symlink_metadata(&path), Err(error)
                    if error.kind() == std::io::ErrorKind::NotFound),
                "fresh development application storage already exists or is uncertain",
            )?;
            absent_storage_paths.push(path);
        }
        need(
            container_ids(&observer)? == before,
            "container inventory changed before fresh application provisioning",
        )?;
        let metadata = fs::symlink_metadata(&installation)
            .map_err(|_| "fresh development installation metadata unavailable")?;
        let fresh = encoded(&json!({
            "schema":"elevenid.unsigned-compose-fresh-state/v1",
            "classification":"UNSIGNED DEVELOPMENT ONLY",
            "installation":installation,"installation_id":state.journal().installation_id(),
            "installation_device":metadata.dev(),"installation_inode":metadata.ino(),
            "installation_uid":metadata.uid(),"installation_gid":metadata.gid(),
            "installation_mode":metadata.mode() & 0o7777,
            "helper_sha256":helper_sha,"helper_build_identity":HELPER_IDENTITY,
            "fixture_inventory_sha256":INVENTORY_SHA,"fixture_source":SOURCE,
            "absent_storage_paths":absent_storage_paths,
            "application_storage_absent_before_provisioning":true,
            "preexisting_container_inventory_unchanged":true,
            "canary_host_traversal_restored":true,"application_provisioning_started":false,
            "docker_host_and_image_cache_retained":true,"installation_ready":false
        }))?;
        state.write_evidence("development-fresh-state.json", &fresh)?;
        stage = "real Compose provisioning and required HTTPS validation";
        eprintln!("UNSIGNED DEVELOPMENT Compose stage: {stage}");
        match provision_runtime(
            &docker,
            &installation,
            &bundle,
            &inventory,
            &mut state,
            RuntimeInvocation {
                operator_sha: &helper_sha,
                completion: RuntimeCompletion::HoldIncomplete,
            },
            reservation,
        ) {
            Err(error) if error == HOLD => {
                state.require_live_phase(Phase::Provisioning)?;
                Ok(())
            }
            Err(error) => Err(error),
            Ok(()) => Err("development readiness hold was unexpectedly absent".into()),
        }
    })();
    let after = container_ids(&observer);
    let retained = after.as_ref().is_ok_and(|ids| before.is_subset(ids));
    exclusive(
        &installation.join("development-outcome.json"),
        &encoded(&json!({
        "schema":"elevenid.unsigned-compose-development-outcome/v1","classification":"UNSIGNED DEVELOPMENT ONLY",
        "orchestration_and_required_validation_passed":outcome.is_ok(),"last_stage":stage,"canary_host_traversal_restored":canary_restored,
        "elapsed_milliseconds":started.elapsed().as_millis(),"containers_before":before.len(),"containers_after":after.as_ref().ok().map(BTreeSet::len),
        "existing_container_ids_retained":retained,"error":outcome.as_ref().err(),"automatic_failure_cleanup":false,
        "local_package_publisher_authenticated":false,"published_signed_release_qualified":false,"installation_ready":false}))?,
        0o600,
    )?;
    outcome?;
    need(
        retained,
        "a preexisting container disappeared during development",
    )?;
    eprintln!("UNSIGNED DEVELOPMENT Compose runtime and required validation passed; all resources and evidence retained; release readiness not claimed");
    Ok(())
}
