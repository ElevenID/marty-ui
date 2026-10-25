//! Internal acceptance-only execution. This never creates consumer Admission.
//! Controller dispatch consumption must be authenticated before the guest claim;
//! the guest registry must survive failures, alternate install paths and cleanup.
#![cfg(target_os = "linux")]

use crate::{
    installer_candidate_nonce::{self, Consumption},
    installer_release::{self as release, CandidateContext, CandidatePhase},
    installer_runtime::DockerRunner,
    installer_state::{AcceptanceScope, Identity, InstallerState, Phase, RuntimeBinding},
    installer_verify::{self, VerificationTools},
};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::Write,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
type Result<T> = std::result::Result<T, String>;
const REFUSED: &str = "Acceptance-only candidate execution refused or incomplete; preserve controller consumption, guest registry and installation evidence. Consumer admission and installation readiness are not granted.";

struct Options {
    authorization: PathBuf,
    controller: PathBuf,
    inputs: PathBuf,
    tools: PathBuf,
    gh: PathBuf,
    docker: PathBuf,
    installation: PathBuf,
    engine: String,
    harness: String,
    phase: CandidatePhase,
    run: u64,
    attempt: u64,
    nonce: String,
}
fn require(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}
fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn path(value: String) -> Result<PathBuf> {
    let path = PathBuf::from(value);
    require(
        path.is_absolute()
            && path
                .components()
                .all(|c| matches!(c, Component::RootDir | Component::Normal(_))),
    )?;
    Ok(path)
}
fn options(args: &[String]) -> Result<Options> {
    let names = [
        "--authorization",
        "--controller-consumption",
        "--inputs-dir",
        "--verification-tools",
        "--gh-bin",
        "--docker-bin",
        "--install-dir",
        "--docker-engine-id",
        "--harness-source-sha",
        "--phase",
        "--run-id",
        "--run-attempt",
        "--nonce",
    ];
    require(args.len() == names.len() * 2)?;
    let mut values = BTreeMap::new();
    for pair in args.chunks_exact(2) {
        require(
            names.contains(&pair[0].as_str())
                && !pair[1].is_empty()
                && !pair[1].starts_with("--")
                && values.insert(pair[0].as_str(), pair[1].clone()).is_none(),
        )?;
    }
    let mut take = |key| values.remove(key).ok_or_else(|| REFUSED.to_owned());
    let authorization = path(take("--authorization")?)?;
    let controller = path(take("--controller-consumption")?)?;
    let inputs = path(take("--inputs-dir")?)?;
    let tools = path(take("--verification-tools")?)?;
    let gh = path(take("--gh-bin")?)?;
    let docker = path(take("--docker-bin")?)?;
    let installation = path(take("--install-dir")?)?;
    let engine = take("--docker-engine-id")?;
    let harness = take("--harness-source-sha")?;
    let nonce = take("--nonce")?;
    require(hex(&harness, 40) && hex(&nonce, 64))?;
    let phase = match take("--phase")?.as_str() {
        "staged" => CandidatePhase::Staged,
        "published" => CandidatePhase::Published,
        _ => return Err(REFUSED.into()),
    };
    let number = |value: String| -> Result<u64> {
        require(value.bytes().all(|b| b.is_ascii_digit()))?;
        let n = value.parse::<u64>().map_err(|_| REFUSED)?;
        require(n > 0 && n < 9_007_199_254_740_992)?;
        Ok(n)
    };
    let run = number(take("--run-id")?)?;
    let attempt = number(take("--run-attempt")?)?;
    Ok(Options {
        authorization,
        controller,
        inputs,
        tools,
        gh,
        docker,
        installation,
        engine,
        harness,
        phase,
        run,
        attempt,
        nonce,
    })
}
fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| REFUSED.into())
}
fn account_home() -> Result<PathBuf> {
    // HOME is caller-controlled; bind the fixed registry to the current account
    // so changing an environment variable cannot select a fresh nonce ledger.
    use std::os::unix::ffi::OsStrExt;
    let mut entry = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut buffer = vec![0u8; 65536];
    let mut result = std::ptr::null_mut();
    let status = unsafe {
        libc::getpwuid_r(
            libc::geteuid(),
            entry.as_mut_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    require(status == 0 && !result.is_null())?;
    let entry = unsafe { entry.assume_init() };
    require(!entry.pw_dir.is_null())?;
    let home = PathBuf::from(std::ffi::OsStr::from_bytes(
        unsafe { std::ffi::CStr::from_ptr(entry.pw_dir) }.to_bytes(),
    ));
    require(home.is_absolute() && std::fs::canonicalize(&home).map_err(|_| REFUSED)? == home)?;
    require(std::env::var_os("HOME").is_some_and(|value| value == home.as_os_str()))?;
    Ok(home)
}
fn persist_signed(
    state: &mut InstallerState,
    source: &Path,
    name: &str,
    bytes: &[u8],
) -> Result<()> {
    state.write_evidence(name, bytes)?;
    for suffix in [".sigstore.json", ".provenance.jsonl"] {
        let mut file = source.as_os_str().to_owned();
        file.push(suffix);
        state.write_evidence(
            &format!("{name}{suffix}"),
            &installer_verify::read_private_bytes(Path::new(&file), 1048576)?,
        )?;
    }
    Ok(())
}

fn held_private_directory(path: &Path) -> Result<File> {
    crate::installer_runtime::private_parent(path)?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| REFUSED)?;
    directory_unchanged(&directory, path)?;
    Ok(directory)
}

fn directory_unchanged(directory: &File, path: &Path) -> Result<()> {
    crate::installer_runtime::private_parent(path)?;
    let held = directory.metadata().map_err(|_| REFUSED)?;
    let named = std::fs::symlink_metadata(path).map_err(|_| REFUSED)?;
    require(held.dev() == named.dev() && held.ino() == named.ino())
}

fn durable_new(directory: &File, parent: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    directory_unchanged(directory, parent)?;
    require(matches!(
        name,
        "public-acquisition-intent.json" | "public-acquisition-result.json"
    ))?;
    let name = std::ffi::CString::new(name).map_err(|_| REFUSED)?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    require(fd >= 0)?;
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(bytes).map_err(|_| REFUSED)?;
    file.sync_all().map_err(|_| REFUSED)?;
    directory.sync_all().map_err(|_| REFUSED)?;
    directory_unchanged(directory, parent)?;
    Ok(())
}

/// Acceptance-only public acquisition on the already authenticated guest.
/// The controller must first bootstrap this executable from the public release
/// and verify its signature and pinned digest before calling this entry.
pub fn fetch_published(args: &[String], build_identity: &str) -> Result<()> {
    fetch_published_inner(args, build_identity).map_err(|_| REFUSED.into())
}

fn fetch_published_inner(args: &[String], build_identity: &str) -> Result<()> {
    let o = options(args)?;
    require(o.phase == CandidatePhase::Published && unsafe { libc::geteuid() } != 0)?;
    require(cfg!(target_arch = "x86_64"))?;
    let (source, version) = build_identity.split_once(':').ok_or(REFUSED)?;
    require(hex(source, 40))?;
    release::release_tier(version)?;
    account_home()?;
    let base = o.inputs.parent().ok_or(REFUSED)?;
    crate::installer_runtime::private_parent(&o.inputs)?;
    let held_base = held_private_directory(base)?;
    require(o.authorization.starts_with(base) && o.controller.starts_with(base))?;
    let tools = VerificationTools::new(&o.tools, &o.gh)?;
    let expected = CandidateContext {
        operator_sha: installer_verify::current_operator_digest()?,
        source_sha: source.into(),
        release_tag: version.into(),
        phase: o.phase,
        nonce: o.nonce,
        harness_source_sha: o.harness,
        run_id: o.run,
        run_attempt: o.attempt,
    };
    let auth = installer_verify::read_private_record(&o.authorization)?;
    let controller = installer_verify::read_private_record(&o.controller)?;
    for (file, bytes) in [(&o.authorization, &auth), (&o.controller, &controller)] {
        require(
            tools.verify(
                file,
                release::ACCEPTANCE_WORKFLOW,
                &expected.harness_source_sha,
                expected.run_id,
                expected.run_attempt,
            )? == release::sha256(bytes),
        )?;
    }
    let context_hash = release::candidate_context_sha256(&expected)?;
    durable_new(
        &held_base,
        base,
        "public-acquisition-intent.json",
        &serde_json::to_vec(&serde_json::json!({
            "schema": "elevenid.installer-public-acquisition-intent/v1",
            "context_sha256": context_hash,
            "authorization_sha256": release::sha256(&auth),
            "controller_consumption_sha256": release::sha256(&controller),
            "started_at": now()?,
            "installation_ready": false
        }))
        .map_err(|_| REFUSED)?,
    )?;
    let runtime = tokio::runtime::Runtime::new().map_err(|_| REFUSED)?;
    let receipts = runtime.block_on(crate::installer_candidate_prepare::fetch_published_inputs(
        &o.authorization,
        &o.inputs,
        &tools,
        &expected,
        source,
        version,
    ))?;
    directory_unchanged(&held_base, base)?;
    let inventory =
        installer_verify::read_private_record(&o.inputs.join("installer-inventory.json"))?;
    release::bind_controller_consumption(
        &controller,
        &auth,
        &inventory,
        &expected,
        &o.engine,
        now()?,
    )?;
    require(
        installer_verify::read_private_record(&o.authorization)? == auth
            && installer_verify::read_private_record(&o.controller)? == controller,
    )?;
    durable_new(
        &held_base,
        base,
        "public-acquisition-result.json",
        &serde_json::to_vec(&serde_json::json!({
            "schema": "elevenid.installer-public-acquisition-result/v1",
            "context_sha256": context_hash,
            "authorization_sha256": release::sha256(&auth),
            "controller_consumption_sha256": release::sha256(&controller),
            "inventory_sha256": release::sha256(&inventory),
            "receipts": receipts,
            "installation_ready": false
        }))
        .map_err(|_| REFUSED)?,
    )?;
    Ok(())
}
/// The controller chooses expected run/phase/nonce independently of the signed
/// records. This entry does not prove guest origin or public acquisition itself.
pub fn install(args: &[String], build_identity: &str) -> Result<()> {
    install_inner(args, build_identity).map_err(|_| REFUSED.into())
}
fn install_inner(args: &[String], build_identity: &str) -> Result<()> {
    let o = options(args)?;
    require(unsafe { libc::geteuid() } != 0 && cfg!(target_arch = "x86_64"))?;
    let (source, version) = build_identity.split_once(':').ok_or(REFUSED)?;
    require(hex(source, 40))?;
    release::release_tier(version)?;
    let home = account_home()?;
    let registry = home.join(".marty-installer-candidate-nonces");
    crate::installer_runtime::private_parent(&registry)?;
    crate::installer_runtime::private_parent(o.installation.parent().ok_or(REFUSED)?)?;
    for staging in [
        &o.inputs,
        &o.tools,
        o.authorization.parent().ok_or(REFUSED)?,
        o.controller.parent().ok_or(REFUSED)?,
        &registry,
    ] {
        require(!o.installation.starts_with(staging) && !staging.starts_with(&o.installation))?;
    }
    match std::fs::symlink_metadata(&o.installation) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err(REFUSED.into()),
    }
    let tools = VerificationTools::new(&o.tools, &o.gh)?;
    let operator_sha = installer_verify::current_operator_digest()?;
    let expected = CandidateContext {
        operator_sha: operator_sha.clone(),
        source_sha: source.into(),
        release_tag: version.into(),
        phase: o.phase,
        nonce: o.nonce,
        harness_source_sha: o.harness,
        run_id: o.run,
        run_attempt: o.attempt,
    };
    let auth = installer_verify::read_private_record(&o.authorization)?;
    let controller = installer_verify::read_private_record(&o.controller)?;
    let inventory_path = o.inputs.join("installer-inventory.json");
    let inventory = installer_verify::read_private_record(&inventory_path)?;
    // Authenticate both grants before trusting the controller-selected UUID or
    // creating either local consumption or installation state.
    for (file, bytes) in [(&o.authorization, &auth), (&o.controller, &controller)] {
        require(
            tools.verify(
                file,
                release::ACCEPTANCE_WORKFLOW,
                &expected.harness_source_sha,
                expected.run_id,
                expected.run_attempt,
            )? == release::sha256(bytes),
        )?;
    }
    let receipt = release::bind_controller_consumption(
        &controller,
        &auth,
        &inventory,
        &expected,
        &o.engine,
        now()?,
    )?;
    let installation_id = uuid::Uuid::parse_str(&receipt.installation_id).map_err(|_| REFUSED)?;
    let port = std::net::TcpListener::bind(("127.0.0.1", 0)).map_err(|_| REFUSED)?;
    let runtime = RuntimeBinding {
        docker_host: "unix:///var/run/docker.sock".into(),
        engine_id: o.engine.clone(),
        openbao_port: port.local_addr().map_err(|_| REFUSED)?.port(),
    };
    let observed = DockerRunner::new(
        &o.docker,
        &runtime.docker_host,
        &runtime.engine_id,
        &o.tools,
    )?
    .preflight()?;
    let consumed = installer_candidate_nonce::consume(
        &registry,
        &Consumption {
            nonce: expected.nonce.clone(),
            authorization_sha256: release::sha256(&auth),
            context_sha256: receipt.context_sha256.clone(),
            installation_id,
            engine_id: o.engine.clone(),
        },
    )?;
    let mut state = InstallerState::create_candidate_with_runtime(
        &o.installation,
        Identity {
            source_sha: source.into(),
            release_tag: version.into(),
            inventory_sha256: format!("sha256:{}", release::sha256(&inventory)),
        },
        runtime,
        AcceptanceScope {
            authorization_sha256: release::sha256(&auth),
            context_sha256: receipt.context_sha256.clone(),
            consumption_id: consumed.consumption_id.clone(),
        },
        installation_id,
    )?;
    state.create_private_directory("evidence")?;
    state.create_private_directory("downloads")?;
    persist_signed(
        &mut state,
        &o.authorization,
        "installer-candidate-authorization.json",
        &auth,
    )?;
    persist_signed(
        &mut state,
        &o.controller,
        "installer-controller-consumption.json",
        &controller,
    )?;
    state.persist_operator(
        &std::env::current_exe().map_err(|_| REFUSED)?,
        &operator_sha,
    )?;
    state.write_evidence(
        "docker-preflight.json",
        &serde_json::to_vec(&observed).map_err(|_| REFUSED)?,
    )?;
    let prepared = crate::installer_candidate_prepare::prepare_candidate(
        &o.authorization,
        &o.inputs,
        &o.installation.join("downloads/extracted"),
        &tools,
        &expected,
        source,
        version,
    )?;
    require(prepared.authorization_bytes == auth && prepared.inventory_bytes == inventory)?;
    persist_signed(
        &mut state,
        &inventory_path,
        "installer-inventory.json",
        &inventory,
    )?;
    let bundle = crate::installer_bundle::validate_bundle(
        &prepared.bundle,
        &prepared.inventory,
        &prepared.image_lock_bytes,
    )?;
    state.write_evidence(
        "bundle-validation.json",
        &serde_json::to_vec(&bundle).map_err(|_| REFUSED)?,
    )?;
    // Expired grants never enter runtime, even after slow verification/extraction.
    release::bind_controller_consumption(
        &controller,
        &auth,
        &inventory,
        &expected,
        &o.engine,
        now()?,
    )?;
    state.advance(Phase::Verified)?;
    let result = crate::installer_command::provision_runtime(
        &o.docker,
        &o.installation,
        &prepared.bundle,
        &prepared.inventory,
        &mut state,
        &operator_sha,
        port,
    );
    drop(consumed);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn valid_options() -> Vec<String> {
        [
            ("--authorization", "/private/proofs/authorization".into()),
            (
                "--controller-consumption",
                "/private/proofs/controller".into(),
            ),
            ("--inputs-dir", "/private/inputs".into()),
            ("--verification-tools", "/private/tools".into()),
            ("--gh-bin", "/private/tools/gh".into()),
            ("--docker-bin", "/usr/bin/docker".into()),
            ("--install-dir", "/persistent/candidate".into()),
            ("--docker-engine-id", "test-engine-12345".into()),
            ("--harness-source-sha", "a".repeat(40)),
            ("--phase", "staged".into()),
            ("--run-id", "10".into()),
            ("--run-attempt", "1".into()),
            ("--nonce", "b".repeat(64)),
        ]
        .into_iter()
        .flat_map(|(key, value)| [key.to_owned(), value])
        .collect()
    }
    #[test]
    fn candidate_options_require_complete_independent_context_and_absolute_paths() {
        let good = valid_options();
        let parsed = options(&good).unwrap();
        assert_eq!(parsed.run, 10);
        assert_eq!(parsed.phase, CandidatePhase::Staged);
        for (key, bad) in [
            ("--run-id", "0"),
            ("--run-attempt", "9007199254740992"),
            ("--nonce", "bad"),
            ("--harness-source-sha", "bad"),
            ("--phase", "channel"),
            ("--inputs-dir", "relative"),
            ("--install-dir", "/private/../elsewhere"),
        ] {
            let mut changed = good.clone();
            let index = changed.iter().position(|v| v == key).unwrap();
            changed[index + 1] = bad.into();
            assert!(options(&changed).is_err());
        }
        let mut duplicate = good;
        duplicate[0] = "--nonce".into();
        assert!(options(&duplicate).is_err());
    }
    #[test]
    fn candidate_entry_refuses_missing_duplicate_and_bypass_options() {
        for args in [
            vec![],
            vec!["--skip-verification", "true"],
            vec!["--phase", "channel"],
            vec!["--nonce", "sensitive-input"],
        ] {
            let args = args.into_iter().map(str::to_owned).collect::<Vec<_>>();
            assert!(options(&args).is_err());
            let error = install(&args, "not-a-build").unwrap_err();
            assert_eq!(error, REFUSED);
            assert!(!error.contains("sensitive-input"));
        }
    }

    #[test]
    fn public_acquisition_refuses_staged_phase_before_creating_evidence() {
        let args = valid_options();
        assert_eq!(fetch_published(&args, "not-a-build").unwrap_err(), REFUSED);
    }

    #[test]
    fn acquisition_intent_is_private_durable_and_cannot_be_replaced() {
        let parent = tempfile::tempdir().unwrap();
        std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = parent.path().join("public-acquisition-intent.json");
        let directory = held_private_directory(parent.path()).unwrap();
        durable_new(
            &directory,
            parent.path(),
            "public-acquisition-intent.json",
            b"first",
        )
        .unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
            0o600
        );
        assert!(durable_new(
            &directory,
            parent.path(),
            "public-acquisition-intent.json",
            b"second"
        )
        .is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
    }

    #[test]
    fn acquisition_rejects_replaced_staging_directory() {
        let root = tempfile::tempdir().unwrap();
        let base = root.path().join("base");
        std::fs::create_dir(&base).unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        let directory = held_private_directory(&base).unwrap();
        durable_new(
            &directory,
            &base,
            "public-acquisition-intent.json",
            b"intent",
        )
        .unwrap();
        let moved = root.path().join("old-base");
        std::fs::rename(&base, &moved).unwrap();
        std::fs::create_dir(&base).unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(durable_new(
            &directory,
            &base,
            "public-acquisition-result.json",
            b"result"
        )
        .is_err());
        assert!(!base.join("public-acquisition-result.json").exists());
        assert!(!moved.join("public-acquisition-result.json").exists());
        assert_eq!(
            std::fs::read(moved.join("public-acquisition-intent.json")).unwrap(),
            b"intent"
        );
    }
}
