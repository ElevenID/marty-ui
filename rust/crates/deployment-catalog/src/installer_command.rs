//! Native install entry point. Runtime completion is deliberately fail-closed
//! until every application/TLS/readiness stage is implemented and qualified.
#![cfg(target_os = "linux")]

use crate::{
    installer_release as release,
    installer_state::{Identity, InstallerState, Phase, RuntimeBinding},
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
    let o = options(args)?;
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
    let admission_bytes = installer_verify::read_private_record(&o.admission)?;
    let admission = release::parse_admission(&admission_bytes)?;
    if admission.source_sha != source
        || admission.release_tag != version
        || admission.operator_sha256 != operator_sha
    {
        return Err("admission does not match running installer".into());
    }
    if tools.verify(
        &o.admission,
        release::PROMOTION_WORKFLOW,
        &admission.promotion_source_sha,
        admission.promotion_run_id,
        admission.promotion_run_attempt,
    )? != release::sha256(&admission_bytes)
    {
        return Err("admission changed".into());
    }
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
    let mut state = InstallerState::create_with_runtime(
        &directory,
        Identity {
            source_sha: source.into(),
            release_tag: version.into(),
            inventory_sha256: format!("sha256:{}", admission.inventory_sha256),
        },
        runtime,
    )?;
    eprintln!("Marty installation state: {}", directory.display());
    state.create_private_directory("evidence")?;
    state.create_private_directory("downloads")?;
    persist_signed(
        &mut state,
        &o.admission,
        "installer-admission.json",
        &admission_bytes,
    )?;
    state.write_evidence(
        "docker-preflight.json",
        &serde_json::to_vec(&observed).map_err(|_| "cannot encode Docker observation")?,
    )?;
    let downloads = directory.join("downloads");
    let executor = tokio::runtime::Runtime::new().map_err(|_| "cannot start installer runtime")?;
    let prepared = executor.block_on(crate::installer_prepare::prepare_release(
        &o.admission,
        o.channel.as_ref().map(|(n, p)| (n.as_str(), p.as_path())),
        &tools,
        &downloads,
        source,
        version,
        &operator_sha,
    ))?;
    if prepared.admission_bytes != admission_bytes {
        return Err("admission changed during preparation".into());
    }
    persist_signed(
        &mut state,
        &downloads.join("installer-inventory.json"),
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
    let realm_path = prepared.bundle.join("config/keycloak/11id-realm.json");
    let realm: serde_json::Value = serde_json::from_slice(
        &std::fs::read(realm_path).map_err(|_| "packaged Keycloak realm unavailable")?,
    )
    .map_err(|_| "packaged Keycloak realm invalid")?;
    state.advance(Phase::Provisioning)?;
    state.generate_local_credentials(&realm)?;
    drop(port_reservation);
    let plugin = prepared
        .inventory
        .images
        .get("openbao_didcomm_image")
        .ok_or("admitted OpenBao image missing")?;
    let infrastructure = crate::installer_openbao::start_openbao(
        docker,
        &directory,
        &prepared.bundle,
        &state,
        plugin,
    )?;
    state.write_evidence(
        "openbao-observation.json",
        &serde_json::to_vec(&infrastructure).map_err(|_| "cannot encode OpenBao observation")?,
    )?;
    Err("OpenBao provisioning recorded; application and local HTTPS stages are not yet implemented. Installation is incomplete; preserve the reported state for recovery.".into())
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
