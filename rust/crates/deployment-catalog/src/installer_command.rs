//! Native install entry point. Runtime completion is deliberately fail-closed
//! until every application/TLS/readiness stage is implemented and qualified.
#![cfg(target_os = "linux")]

use crate::{
    installer_release as release,
    installer_state::{CandidateTestScope, Identity, InstallerState, Phase, RuntimeBinding},
    installer_verify::{self, VerificationTools},
};
use std::{
    collections::BTreeMap,
    io::{BufRead, Read, Write},
    path::{Path, PathBuf},
};

type Result<T> = std::result::Result<T, String>;
struct Options {
    version: String,
    admission: PathBuf,
    tools: PathBuf,
    gh: PathBuf,
    docker: PathBuf,
    host: String,
    engine: String,
    directory: Option<PathBuf>,
    channel: Option<(String, PathBuf)>,
    yes: bool,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum InstallMode {
    Admitted,
    CandidateTest,
}
fn options(args: &[String]) -> Result<Options> {
    let mut values = BTreeMap::new();
    let mut yes = false;
    let mut index = 0;
    while index < args.len() {
        let key = args[index].as_str();
        if key == "--yes" {
            if yes {
                return Err("repeated --yes".into());
            }
            yes = true;
            index += 1;
            continue;
        }
        if ![
            "--version",
            "--verified-admission",
            "--verification-tools",
            "--gh-bin",
            "--docker-host",
            "--docker-engine-id",
            "--docker-bin",
            "--install-dir",
            "--channel",
            "--verified-channel",
        ]
        .contains(&key)
        {
            return Err("unknown installer option".into());
        }
        let value = args
            .get(index + 1)
            .filter(|v| !v.is_empty() && !v.starts_with("--"))
            .ok_or("installer option requires a value")?;
        if values.insert(key, value.clone()).is_some() {
            return Err("repeated installer option".into());
        }
        index += 2;
    }
    let mut take = |name| {
        values
            .remove(name)
            .ok_or_else(|| format!("required installer option missing: {name}"))
    };
    let version = take("--version")?;
    release::release_tier(&version)?;
    let admission = PathBuf::from(take("--verified-admission")?);
    let tools = PathBuf::from(take("--verification-tools")?);
    let gh = PathBuf::from(take("--gh-bin")?);
    let docker = PathBuf::from(take("--docker-bin")?);
    let host = take("--docker-host")?;
    let engine = take("--docker-engine-id")?;
    let directory = values.remove("--install-dir").map(PathBuf::from);
    let channel = match (
        values.remove("--channel"),
        values.remove("--verified-channel"),
    ) {
        (None, None) => None,
        (Some(name), Some(path)) if ["nightly", "stable"].contains(&name.as_str()) => {
            Some((name, PathBuf::from(path)))
        }
        _ => return Err("channel selection requires its verified record".into()),
    };
    if [&admission, &tools, &gh, &docker]
        .iter()
        .any(|p| !p.is_absolute())
        || directory.as_ref().is_some_and(|p| !p.is_absolute())
        || channel.as_ref().is_some_and(|(_, p)| !p.is_absolute())
    {
        return Err("installer paths must be absolute".into());
    }
    RuntimeBinding {
        docker_host: host.clone(),
        engine_id: engine.clone(),
        openbao_port: 18200,
    }
    .validate()?;
    Ok(Options {
        version,
        admission,
        tools,
        gh,
        docker,
        host,
        engine,
        directory,
        channel,
        yes,
    })
}
fn candidate_test_options(args: &[String]) -> Result<Options> {
    if args
        .iter()
        .filter(|arg| arg.as_str() == "--verified-inventory")
        .count()
        != 1
        || args.iter().any(|arg| {
            ["--verified-admission", "--channel", "--verified-channel"].contains(&arg.as_str())
        })
    {
        return Err("candidate testing requires only a signed nightly inventory".into());
    }
    let mut rewritten = args.to_vec();
    let position = rewritten
        .iter()
        .position(|arg| arg == "--verified-inventory")
        .ok_or("candidate inventory missing")?;
    rewritten[position] = "--verified-admission".into();
    let selected = options(&rewritten)?;
    if !selected.version.contains("-nightly.") || selected.channel.is_some() {
        return Err("candidate testing requires an exact nightly version".into());
    }
    Ok(selected)
}
fn confirm(directory: &Path) -> Result<()> {
    let mut tty=std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty")
        .map_err(|_| "installation confirmation requires a terminal; use --yes to accept the documented defaults")?;
    writeln!(
        tty,
        "Create an isolated Marty installation at {}? [y/N]",
        directory.display()
    )
    .map_err(|_| "cannot request confirmation")?;
    tty.flush().map_err(|_| "cannot request confirmation")?;
    let mut response = String::new();
    std::io::BufReader::new(tty)
        .take(16)
        .read_line(&mut response)
        .map_err(|_| "cannot read confirmation")?;
    if !["y", "yes"].contains(&response.trim().to_ascii_lowercase().as_str()) {
        return Err("installation declined".into());
    }
    Ok(())
}
fn persist_signed(
    state: &mut InstallerState,
    source: &Path,
    name: &str,
    bytes: &[u8],
) -> Result<()> {
    state.write_evidence(name, bytes)?;
    for suffix in [".sigstore.json", ".provenance.jsonl"] {
        let mut path = source.as_os_str().to_owned();
        path.push(suffix);
        state.write_evidence(
            &format!("{name}{suffix}"),
            &installer_verify::read_private_bytes(Path::new(&path), 1048576)?,
        )?;
    }
    Ok(())
}

pub fn install(args: &[String], build_identity: &str) -> Result<()> {
    install_inner(args, build_identity, InstallMode::Admitted)
}
pub fn candidate_test(args: &[String], build_identity: &str) -> Result<()> {
    install_inner(args, build_identity, InstallMode::CandidateTest)
}
fn install_inner(args: &[String], build_identity: &str, mode: InstallMode) -> Result<()> {
    let o = match mode {
        InstallMode::Admitted => options(args)?,
        InstallMode::CandidateTest => candidate_test_options(args)?,
    };
    if unsafe { libc::geteuid() } == 0 || !cfg!(target_arch = "x86_64") {
        return Err("installer requires a regular Docker-enabled Linux amd64 user".into());
    }
    let (source, version) = build_identity
        .split_once(':')
        .ok_or("invalid operator build identity")?;
    if source.len() != 40
        || !source
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || version != o.version
    {
        return Err("installer requires an exact release-built operator".into());
    }
    let tools = VerificationTools::new(&o.tools, &o.gh)?;
    let operator_sha = installer_verify::current_operator_digest()?;
    let admitted = if mode == InstallMode::Admitted {
        let bytes = installer_verify::read_private_record(&o.admission)?;
        let record = release::parse_admission(&bytes)?;
        if record.source_sha != source
            || record.release_tag != version
            || record.operator_sha256 != operator_sha
            || tools.verify(
                &o.admission,
                release::PROMOTION_WORKFLOW,
                &record.promotion_source_sha,
                record.promotion_run_id,
                record.promotion_run_attempt,
            )? != release::sha256(&bytes)
        {
            return Err("admission does not match running installer".into());
        }
        Some((bytes, record))
    } else {
        None
    };
    let testing = if mode == InstallMode::CandidateTest {
        let bytes = installer_verify::read_private_record(&o.admission)?;
        let record = release::parse_inventory(&bytes)?;
        if record.source_sha != source
            || record.release_tag != version
            || record.artifact("marty-deploy-linux-amd64")?.sha256 != operator_sha
            || tools.verify(
                &o.admission,
                release::build_workflow(version)?,
                source,
                record.build_run_id,
                record.build_run_attempt,
            )? != release::sha256(&bytes)
        {
            return Err("candidate inventory does not match running installer".into());
        }
        Some((bytes, record))
    } else {
        None
    };
    let directory = o.directory.unwrap_or_else(|| {
        PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
            .join(format!(".marty-install-{}", uuid::Uuid::new_v4().simple()))
    });
    if !directory.is_absolute() || directory.starts_with(&o.tools) {
        return Err(
            "installation must use persistent absolute storage outside bootstrap staging".into(),
        );
    }
    if !o.yes {
        confirm(&directory)?;
    }
    let port_reservation = std::net::TcpListener::bind(("127.0.0.1", 0))
        .map_err(|_| "cannot select local OpenBao port")?;
    let runtime = RuntimeBinding {
        docker_host: o.host,
        engine_id: o.engine,
        openbao_port: port_reservation
            .local_addr()
            .map_err(|_| "cannot inspect local port")?
            .port(),
    };
    let docker = o.docker.as_path();
    let observed = crate::installer_runtime::DockerRunner::new(
        docker,
        &runtime.docker_host,
        &runtime.engine_id,
        &o.tools,
    )?
    .preflight()?;
    let inventory_sha = if let Some((_, record)) = &admitted {
        record.inventory_sha256.clone()
    } else {
        release::sha256(&testing.as_ref().ok_or("candidate inventory missing")?.0)
    };
    let identity = Identity {
        source_sha: source.into(),
        release_tag: version.into(),
        inventory_sha256: format!("sha256:{inventory_sha}"),
    };
    let mut state = if let Some((_, record)) = &testing {
        InstallerState::create_test_with_runtime(
            &directory,
            identity,
            runtime,
            CandidateTestScope {
                inventory_sha256: inventory_sha.clone(),
                build_run_id: record.build_run_id,
                build_run_attempt: record.build_run_attempt,
            },
        )?
    } else {
        InstallerState::create_with_runtime(&directory, identity, runtime)?
    };
    eprintln!("Marty installation state: {}", directory.display());
    state.create_private_directory("evidence")?;
    state.create_private_directory("downloads")?;
    if testing.is_none() {
        state.persist_initial_creation_receipt(&directory)?;
    }
    if let Some((bytes, _)) = &admitted {
        persist_signed(&mut state, &o.admission, "installer-admission.json", bytes)?;
    } else if let Some((bytes, _)) = &testing {
        persist_signed(
            &mut state,
            &o.admission,
            "candidate-test-inventory.json",
            bytes,
        )?;
    }
    state.persist_operator(
        &std::env::current_exe().map_err(|_| "cannot locate running installer")?,
        &operator_sha,
    )?;
    eprintln!(
        "Marty management executable: {}",
        directory.join("marty-deploy").display()
    );
    state.write_evidence(
        "docker-preflight.json",
        &serde_json::to_vec(&observed).map_err(|_| "cannot encode Docker observation")?,
    )?;
    let downloads = directory.join("downloads");
    let executor = tokio::runtime::Runtime::new().map_err(|_| "cannot start installer runtime")?;
    let prepared = if mode == InstallMode::Admitted {
        executor.block_on(crate::installer_prepare::prepare_release(
            &o.admission,
            o.channel.as_ref().map(|(n, p)| (n.as_str(), p.as_path())),
            &tools,
            &downloads,
            source,
            version,
            &operator_sha,
        ))?
    } else {
        executor.block_on(crate::installer_prepare::prepare_candidate_test(
            &o.admission,
            &tools,
            &downloads,
            source,
            version,
            &operator_sha,
        ))?
    };
    if let Some((bytes, _)) = &admitted {
        if prepared.admission_bytes != *bytes {
            return Err("admission changed during preparation".into());
        }
    } else if let Some((bytes, _)) = &testing {
        if prepared.inventory_bytes != *bytes
            || installer_verify::read_private_record(&o.admission)? != *bytes
        {
            return Err("candidate inventory changed during preparation".into());
        }
    }
    let inventory_evidence_path = if mode == InstallMode::Admitted {
        downloads.join("installer-inventory.json")
    } else {
        o.admission.clone()
    };
    persist_signed(
        &mut state,
        &inventory_evidence_path,
        "installer-inventory.json",
        &prepared.inventory_bytes,
    )?;
    if let (Some((_, path)), Some(bytes)) = (&o.channel, &prepared.channel_bytes) {
        persist_signed(&mut state, path, "installer-channel.json", bytes)?;
    }
    let lock =
        installer_verify::read_private_record(&downloads.join("prepared-selfhost-images.json"))?;
    let bundle =
        crate::installer_bundle::validate_bundle(&prepared.bundle, &prepared.inventory, &lock)?;
    state.write_evidence(
        "bundle-validation.json",
        &serde_json::to_vec(&bundle).map_err(|_| "cannot encode bundle validation")?,
    )?;
    state.advance(Phase::Verified)?;
    provision_runtime(
        docker,
        &directory,
        &prepared.bundle,
        &prepared.inventory,
        &mut state,
        &operator_sha,
        port_reservation,
    )
}

/// Shared runtime stage for independently authenticated release entry points.
/// The caller must authenticate the inventory and operator, validate the bundle,
/// persist that evidence, and retain exclusive private-path ownership. This
/// function grants no admission and does not advance the installation to Ready.
/// Ownership of the port reservation preserves its lifetime through credential
/// generation; the exact existing release point precedes OpenBao creation.
pub(crate) fn provision_runtime(
    docker: &Path,
    installation: &Path,
    bundle: &Path,
    inventory: &release::Inventory,
    state: &mut InstallerState,
    operator_sha: &str,
    port_reservation: std::net::TcpListener,
) -> Result<()> {
    state.require_live_phase(Phase::Verified)?;
    let realm_path = bundle.join("config/keycloak/11id-realm.json");
    let realm: serde_json::Value = serde_json::from_slice(
        &std::fs::read(realm_path).map_err(|_| "packaged Keycloak realm unavailable")?,
    )
    .map_err(|_| "packaged Keycloak realm invalid")?;
    state.advance(Phase::Provisioning)?;
    state.generate_local_credentials(&realm)?;
    state.persist_credential_creation_receipt(installation)?;
    drop(port_reservation);
    let plugin = inventory
        .images
        .get("openbao_didcomm_image")
        .ok_or("admitted OpenBao image missing")?;
    let infrastructure =
        crate::installer_openbao::start_openbao(docker, installation, bundle, state, plugin)?;
    state.write_evidence(
        "openbao-observation.json",
        &serde_json::to_vec(&infrastructure).map_err(|_| "cannot encode OpenBao observation")?,
    )?;
    let keycloak = crate::installer_keycloak::provision(
        docker,
        installation,
        bundle,
        state,
        &infrastructure,
        operator_sha,
    )?;
    state.write_evidence(
        "keycloak-observation.json",
        &serde_json::to_vec(&keycloak).map_err(|_| "cannot encode Keycloak observation")?,
    )?;
    let services_image = inventory
        .images
        .get("gateway")
        .ok_or("admitted gateway image missing")?;
    if inventory.images.get("signing-keys") != Some(services_image) {
        return Err(
            "TLS bootstrap requires identical admitted gateway and signing-keys images".into(),
        );
    }
    let tls = crate::installer_tls::provision(
        docker,
        installation,
        bundle,
        state,
        &infrastructure,
        services_image,
        operator_sha,
    )?;
    state.write_evidence(
        "tls-observation.json",
        &serde_json::to_vec(&tls).map_err(|_| "cannot encode TLS observation")?,
    )?;
    let ingress = crate::installer_ingress::provision(
        docker,
        installation,
        bundle,
        state,
        &infrastructure,
        services_image,
        operator_sha,
    )?;
    state.write_evidence(
        "ingress-observation.json",
        &serde_json::to_vec(&ingress).map_err(|_| "cannot encode ingress observation")?,
    )?;
    let renewal = crate::installer_renewal::provision(
        docker,
        installation,
        bundle,
        state,
        &infrastructure,
        services_image,
        operator_sha,
    )?;
    state.write_evidence(
        "renewal-observation.json",
        &serde_json::to_vec(&renewal).map_err(|_| "cannot encode renewal observation")?,
    )?;
    let generation = crate::installer_generation_host::provision(
        docker,
        installation,
        bundle,
        state,
        &infrastructure,
        services_image,
        operator_sha,
    )?;
    state.write_evidence(
        "generation-observation.json",
        &serde_json::to_vec(&generation).map_err(|_| "cannot encode generation observation")?,
    )?;
    let application = crate::installer_application::prepare_with_generation(
        docker,
        installation,
        bundle,
        state,
        &infrastructure,
        &inventory.images,
    )?;
    crate::installer_application_start::start(
        docker,
        installation,
        bundle,
        state,
        &infrastructure,
        application,
    )?;
    state.with_inspection(|inspection| {
        crate::installer_validation::run_locked(installation, docker, inspection, false)
    })?;
    Err("Owned application startup observations recorded. Explicit local CA trust onboarding and installed journey qualification remain incomplete; preserve the reported state for recovery. Installation is not ready.".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_runtime_refuses_unverified_state_before_reading_bundle_or_running_docker() {
        use std::os::unix::fs::PermissionsExt;
        let parent = tempfile::tempdir().unwrap();
        std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let directory = parent.path().join("installation");
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/installer-candidate-records.json"
        ))
        .unwrap();
        let inventory_bytes = fixture["inventory"].as_str().unwrap().as_bytes();
        let inventory = release::parse_inventory(inventory_bytes).unwrap();
        let mut state = InstallerState::create(
            &directory,
            Identity {
                source_sha: inventory.source_sha.clone(),
                release_tag: inventory.release_tag.clone(),
                inventory_sha256: format!("sha256:{}", release::sha256(inventory_bytes)),
            },
        )
        .unwrap();
        let before = std::fs::read(directory.join("installation.json")).unwrap();
        let result = provision_runtime(
            Path::new("/nonexistent-docker"),
            &directory,
            &directory.join("nonexistent-bundle"),
            &inventory,
            &mut state,
            &"a".repeat(64),
            std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap(),
        );
        assert!(result.is_err());
        assert_eq!(
            std::fs::read(directory.join("installation.json")).unwrap(),
            before
        );
        assert!(!directory.join("secrets").exists());
    }

    #[test]
    fn refuses_unknown_duplicate_partial_and_unsafe_inputs() {
        for args in [
            vec!["--skip-verification"],
            vec!["--yes", "--yes"],
            vec!["--version"],
            vec!["--version", "../../bad"],
        ] {
            assert!(options(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>()).is_err());
        }
    }

    #[test]
    fn candidate_testing_is_exact_nightly_and_cannot_take_admission_or_channel() {
        let mut args = [
            ("--version", "v1.1.263-nightly.20261027.42"),
            ("--verified-inventory", "/private/inventory.json"),
            ("--verification-tools", "/private/tools"),
            ("--gh-bin", "/private/tools/gh"),
            ("--docker-host", "unix:///var/run/docker.sock"),
            ("--docker-engine-id", "exact-engine"),
            ("--docker-bin", "/usr/bin/docker"),
        ]
        .into_iter()
        .flat_map(|(key, value)| [key.to_owned(), value.to_owned()])
        .collect::<Vec<_>>();
        assert!(candidate_test_options(&args).is_ok());
        assert!(options(&args).is_err());
        args[1] = "v1.1.263".into();
        assert!(candidate_test_options(&args).is_err());
        args[1] = "v1.1.263-nightly.20261027.42".into();
        args.push("--verified-admission".into());
        args.push("/private/admission.json".into());
        assert!(candidate_test_options(&args).is_err());
        args.truncate(args.len() - 2);
        args.push("--channel".into());
        args.push("nightly".into());
        assert!(candidate_test_options(&args).is_err());
    }
}
