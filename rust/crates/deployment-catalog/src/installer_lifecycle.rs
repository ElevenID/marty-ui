//! Customer-owned user-systemd integration for an existing, bound Compose stack.
//! No daemon management, privileged setup replay, credential renewal or repair.
#![cfg(target_os = "linux")]

use crate::{
    installer_doctor, installer_host_fs, installer_json, installer_release,
    installer_state::{
        Identity, LockedInspection, LockedMaintenance, RuntimeBinding, RuntimeProfile,
    },
    installer_uninstall, installer_validation, installer_verify,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    os::{
        fd::AsRawFd,
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path, PathBuf},
};

type Result<T> = std::result::Result<T, String>;
const CONFIGURATION: &str = "lifecycle-configuration.json";
const CONFIGURATION_SCHEMA: &str = "elevenid.installer-lifecycle-configuration/v1";
const INTENT_SCHEMA: &str = "elevenid.installer-lifecycle-intent/v1";
const REFUSED: &str = "Installer lifecycle refused; preserve the installation-scoped units and intent evidence. No provisioning, repair or automatic renewal was attempted";
const MAX_INTENTS: usize = 10000;

fn require(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Action {
    Export,
    Install,
    Status,
    Boot,
    Shutdown,
    Check,
}

struct Arguments {
    action: Action,
    installation: PathBuf,
    docker: PathBuf,
}

fn path_text(path: &Path) -> Result<&str> {
    let text = path.to_str().ok_or(REFUSED)?;
    require(
        path.is_absolute()
            && text.len() <= 4096
            && text.len() > 1
            && !text.chars().any(char::is_control)
            && !text
                .split('/')
                .skip(1)
                .any(|part| part.is_empty() || part == "." || part == "..")
            && path
                .components()
                .all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
    )?;
    Ok(text)
}

fn installation_text(path: &Path) -> Result<&str> {
    let text = path_text(path)?;
    // systemd rejects these in the executable name even after correct argv
    // unquoting. The retained operator lives directly under this directory.
    if text.contains(['\'', '"', '\\']) {
        return Err("Lifecycle installation paths cannot contain quotes or backslashes: systemd rejects them in executable paths".into());
    }
    Ok(text)
}

fn arguments(args: &[String]) -> Result<Arguments> {
    let action = match args.first().map(String::as_str) {
        Some("export") => Action::Export,
        Some("install") => Action::Install,
        Some("status") => Action::Status,
        Some("boot") => Action::Boot,
        Some("shutdown") => Action::Shutdown,
        Some("check") => Action::Check,
        _ => return Err("Expected lifecycle export|install|status|boot|shutdown|check --install-dir ABS [--docker-bin ABS]".into()),
    };
    require((args.len() - 1).is_multiple_of(2))?;
    let mut values = BTreeMap::new();
    for pair in args[1..].chunks_exact(2) {
        require(
            ["--install-dir", "--docker-bin"].contains(&pair[0].as_str())
                && values.insert(pair[0].as_str(), pair[1].as_str()).is_none(),
        )?;
    }
    let installation = PathBuf::from(*values.get("--install-dir").ok_or(REFUSED)?);
    let docker = PathBuf::from(*values.get("--docker-bin").unwrap_or(&"/usr/bin/docker"));
    installation_text(&installation)?;
    path_text(&docker)?;
    Ok(Arguments {
        action,
        installation,
        docker,
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    schema: String,
    installation_id: uuid::Uuid,
    installation: PathBuf,
    owner_uid: u32,
    release: Identity,
    runtime: RuntimeBinding,
    compose_project: String,
    compose_configuration_sha256: String,
    operator_sha256: String,
    docker: PathBuf,
    units: BTreeMap<String, String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum DesiredState {
    Running,
    Paused,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum IntentReason {
    Installed,
    ManualStart,
    ManualStop,
    Uninstall,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    schema: String,
    installation_id: uuid::Uuid,
    configuration_sha256: String,
    sequence: usize,
    desired_state: DesiredState,
    reason: IntentReason,
    previous_sha256: Option<String>,
}

struct Loaded {
    configuration: Configuration,
    configuration_sha256: String,
    intent: Intent,
    intent_sha256: String,
}

fn unit_names(id: uuid::Uuid) -> [String; 3] {
    let prefix = format!("lifecycle-marty-{id}");
    [
        format!("{prefix}.service"),
        format!("{prefix}-check.service"),
        format!("{prefix}-check.timer"),
    ]
}

/// systemd parses this argv directly. ':' disables dollar expansion; percent
/// specifiers still need escaping. No shell, EnvironmentFile or secret value.
fn systemd_argument(value: &str) -> Result<String> {
    require(
        !value.is_empty()
            && value.len() <= 8192
            && !value.chars().any(char::is_control)
            && value != ";",
    )?;
    Ok(format!(
        "\"{}\"",
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
    ))
}

fn command(configuration: &Configuration, action: &str) -> Result<String> {
    installation_text(&configuration.installation)?;
    let operator = configuration.installation.join("marty-deploy");
    let argv = [
        path_text(&operator)?,
        "lifecycle",
        action,
        "--install-dir",
        path_text(&configuration.installation)?,
        "--docker-bin",
        path_text(&configuration.docker)?,
    ];
    Ok(format!(
        ":{}",
        argv.into_iter()
            .map(systemd_argument)
            .collect::<Result<Vec<_>>>()?
            .join(" ")
    ))
}

fn render_units(configuration: &Configuration) -> Result<BTreeMap<String, String>> {
    let id = configuration.installation_id;
    let [boot, check, timer] = unit_names(id);
    let boot_text = format!(
        "# Generated for Marty installation {id}; customer enables this user unit.\n\
[Unit]\nDescription=Marty installation {id}\nWants=docker.service\nAfter=docker.service\n\
StartLimitIntervalSec=900\nStartLimitBurst=3\n\n\
[Service]\nType=oneshot\nRemainAfterExit=yes\nNoNewPrivileges=yes\nUMask=0077\n\
TimeoutStartSec=1800\nTimeoutStopSec=900\nRestart=on-failure\nRestartSec=15\n\
ExecStart={}\nExecStop={}\n\n[Install]\nWantedBy=default.target\n",
        command(configuration, "boot")?,
        command(configuration, "shutdown")?
    );
    let check_text = format!(
        "# Read-only validation; no renewal, restart or recovery action.\n\
[Unit]\nDescription=Marty deployment check {id}\nAfter=docker.service {boot}\n\n\
[Service]\nType=oneshot\nNoNewPrivileges=yes\nUMask=0077\nTimeoutStartSec=150\nExecStart={}\n",
        command(configuration, "check")?
    );
    let timer_text = format!(
        "[Unit]\nDescription=Marty deployment check schedule {id}\n\n\
[Timer]\nOnCalendar=*-*-* *:00/5:00\nPersistent=true\nRandomizedDelaySec=30\nUnit={check}\n\n\
[Install]\nWantedBy=timers.target\n"
    );
    Ok([(boot, boot_text), (check, check_text), (timer, timer_text)].into())
}

fn prepare(state: &LockedInspection, installation: &Path, docker: &Path) -> Result<Configuration> {
    installation_text(installation)?;
    path_text(docker)?;
    state.require_path_binding(installation)?;
    let journal = state.journal();
    let runtime = journal.runtime().ok_or(REFUSED)?;
    runtime.validate()?;
    require(runtime.profile == RuntimeProfile::Rootless)?;
    let saved = installer_doctor::load_session(state, installation)?;
    require(saved.schema != installer_doctor::FAILED_RUNTIME_SESSION_SCHEMA)?;
    let inventory_bytes = state.read_evidence("installer-inventory.json")?;
    require(
        format!("sha256:{}", installer_release::sha256(&inventory_bytes))
            == journal.identity().inventory_sha256,
    )?;
    let inventory = installer_release::parse_inventory(&inventory_bytes)?;
    let operator_sha256 = installer_verify::operator_digest(&installation.join("marty-deploy"))?;
    require(inventory.artifact("marty-deploy-linux-amd64")?.sha256 == operator_sha256)?;
    let mut configuration = Configuration {
        schema: CONFIGURATION_SCHEMA.into(),
        installation_id: journal.installation_id(),
        installation: installation.into(),
        owner_uid: unsafe { libc::geteuid() },
        release: journal.identity().clone(),
        runtime: runtime.clone(),
        compose_project: journal.compose_project(),
        compose_configuration_sha256: saved.configuration_sha256,
        operator_sha256,
        docker: docker.into(),
        units: BTreeMap::new(),
    };
    configuration.units = render_units(&configuration)?
        .into_iter()
        .map(|(name, text)| (name, installer_release::sha256(text.as_bytes())))
        .collect();
    state.require_path_binding(installation)?;
    Ok(configuration)
}

/// Enumerate only lifecycle artifacts through the locked installation. Re-reading
/// their private records validates ownership, type, mode and single-link custody.
fn record_names(state: &LockedInspection) -> Result<BTreeSet<String>> {
    state.require_unchanged()?;
    let evidence = installer_host_fs::open_child(
        state.installation_directory(),
        "evidence",
        libc::O_RDONLY | libc::O_DIRECTORY,
        REFUSED,
    )?;
    let metadata = evidence.metadata().map_err(|_| REFUSED)?;
    require(
        metadata.is_dir()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o7777 == 0o700,
    )?;
    let mut names = BTreeSet::new();
    for entry in
        std::fs::read_dir(format!("/proc/self/fd/{}", evidence.as_raw_fd())).map_err(|_| REFUSED)?
    {
        let name = entry.map_err(|_| REFUSED)?.file_name();
        if name.as_bytes().starts_with(b"lifecycle-") {
            let name = name.to_str().ok_or(REFUSED)?;
            require(names.len() < MAX_INTENTS + 4 && name.len() <= 128)?;
            names.insert(name.to_owned());
        }
    }
    state.require_unchanged()?;
    Ok(names)
}

fn intent_name(sequence: usize) -> String {
    format!("lifecycle-intent-{sequence:08}.json")
}

fn intent_chain(
    state: &LockedInspection,
    configuration: &Configuration,
    configuration_sha256: &str,
    names: &BTreeSet<String>,
) -> Result<Option<(Intent, String)>> {
    let mut allowed = BTreeSet::from([CONFIGURATION.to_owned()]);
    allowed.extend(configuration.units.keys().cloned());
    let intent_names: Vec<_> = names.difference(&allowed).collect();
    require(intent_names.len() <= MAX_INTENTS)?;
    let mut previous = None;
    let mut latest = None;
    for (index, name) in intent_names.iter().enumerate() {
        let sequence = index + 1;
        require(**name == intent_name(sequence))?;
        let bytes = state.read_evidence(name)?;
        require(bytes.len() <= 4096)?;
        let intent: Intent =
            serde_json::from_value(installer_json::decode(&bytes).map_err(|_| REFUSED)?)
                .map_err(|_| REFUSED)?;
        let valid_reason = match intent.reason {
            IntentReason::Installed => {
                sequence == 1 && intent.desired_state == DesiredState::Paused
            }
            IntentReason::ManualStart => {
                sequence > 1 && intent.desired_state == DesiredState::Running
            }
            IntentReason::ManualStop | IntentReason::Uninstall => {
                sequence > 1 && intent.desired_state == DesiredState::Paused
            }
        };
        require(
            intent.schema == INTENT_SCHEMA
                && intent.installation_id == configuration.installation_id
                && intent.configuration_sha256 == configuration_sha256
                && intent.sequence == sequence
                && intent.previous_sha256 == previous
                && valid_reason,
        )?;
        let digest = installer_release::sha256(&bytes);
        previous = Some(digest.clone());
        latest = Some((intent, digest));
    }
    Ok(latest)
}

fn configured(
    state: &LockedInspection,
    installation: &Path,
    docker: &Path,
) -> Result<Option<Loaded>> {
    let names = record_names(state)?;
    let Some(bytes) = state.diagnostic_record(CONFIGURATION, true)? else {
        require(names.is_empty())?;
        return Ok(None);
    };
    require(bytes.len() <= 65536)?;
    let configuration: Configuration =
        serde_json::from_value(installer_json::decode(&bytes).map_err(|_| REFUSED)?)
            .map_err(|_| REFUSED)?;
    require(configuration == prepare(state, installation, docker)?)?;
    for (name, text) in render_units(&configuration)? {
        require(state.read_evidence(&name)? == text.as_bytes())?;
    }
    let configuration_sha256 = installer_release::sha256(&bytes);
    let (intent, intent_sha256) =
        intent_chain(state, &configuration, &configuration_sha256, &names)?.ok_or(REFUSED)?;
    require(record_names(state)? == names)?;
    state.require_path_binding(installation)?;
    Ok(Some(Loaded {
        configuration,
        configuration_sha256,
        intent,
        intent_sha256,
    }))
}

fn append_intent(
    state: &mut LockedMaintenance,
    configuration: &Configuration,
    configuration_sha256: &str,
    previous: Option<(&Intent, &str)>,
    reason: IntentReason,
) -> Result<Intent> {
    let sequence = previous.map_or(1, |(intent, _)| intent.sequence + 1);
    require(sequence <= MAX_INTENTS && (sequence == 1) == (reason == IntentReason::Installed))?;
    let intent = Intent {
        schema: INTENT_SCHEMA.into(),
        installation_id: configuration.installation_id,
        configuration_sha256: configuration_sha256.into(),
        sequence,
        desired_state: if reason == IntentReason::ManualStart {
            DesiredState::Running
        } else {
            DesiredState::Paused
        },
        reason,
        previous_sha256: previous.map(|(_, digest)| digest.into()),
    };
    state.write_evidence_exclusive(
        &intent_name(sequence),
        &serde_json::to_vec(&intent).map_err(|_| REFUSED)?,
    )?;
    Ok(intent)
}

/// Called under the same operation lock, before any manual Docker mutation.
/// Even a failed stop/down leaves durable pause intent; native operation evidence
/// still gates further mutations and never becomes retry permission.
pub(crate) fn record_manual_intent_if_configured(
    state: &mut LockedMaintenance,
    installation: &Path,
    docker: &Path,
    action: &str,
) -> Result<()> {
    let reason = match action {
        "start" => IntentReason::ManualStart,
        "stop" => IntentReason::ManualStop,
        "down" => IntentReason::Uninstall,
        _ => return Err(REFUSED.into()),
    };
    if let Some(loaded) = configured(state.inspection(), installation, docker)? {
        append_intent(
            state,
            &loaded.configuration,
            &loaded.configuration_sha256,
            Some((&loaded.intent, &loaded.intent_sha256)),
            reason,
        )?;
    }
    Ok(())
}

fn persist_exact(state: &mut LockedMaintenance, name: &str, bytes: &[u8]) -> Result<()> {
    if let Some(existing) = state.read_evidence(name)? {
        require(existing == bytes)
    } else {
        state.write_evidence_exclusive(name, bytes)
    }
}

fn install(state: &mut LockedMaintenance, installation: &Path, docker: &Path) -> Result<Loaded> {
    let configuration = prepare(state.inspection(), installation, docker)?;
    let bytes = serde_json::to_vec(&configuration).map_err(|_| REFUSED)?;
    let configuration_sha256 = installer_release::sha256(&bytes);
    let names = record_names(state.inspection())?;
    // Complete only byte-identical interrupted exports. Unknown, foreign or
    // non-contiguous intent artifacts never become a new installation.
    let prior = intent_chain(
        state.inspection(),
        &configuration,
        &configuration_sha256,
        &names,
    )?;
    if !names.is_empty() {
        require(names.contains(CONFIGURATION))?;
    }
    let units = render_units(&configuration)?;
    // Inspect every pre-existing artifact before completing a partial export.
    for (name, expected) in std::iter::once((CONFIGURATION, bytes.as_slice())).chain(
        units
            .iter()
            .map(|(name, text)| (name.as_str(), text.as_bytes())),
    ) {
        if let Some(observed) = state.read_evidence(name)? {
            require(observed == expected)?;
        }
    }
    persist_exact(state, CONFIGURATION, &bytes)?;
    for (name, text) in units {
        persist_exact(state, &name, text.as_bytes())?;
    }
    if prior.is_none() {
        append_intent(
            state,
            &configuration,
            &configuration_sha256,
            None,
            IntentReason::Installed,
        )?;
    }
    configured(state.inspection(), installation, docker)?.ok_or_else(|| REFUSED.into())
}

fn next_actions(configuration: &Configuration) -> Value {
    let [boot, check, timer] = unit_names(configuration.installation_id);
    let evidence = configuration.installation.join("evidence");
    let commands: Vec<Vec<String>> = vec![
        vec![
            configuration
                .installation
                .join("marty-deploy")
                .to_string_lossy()
                .to_string(),
            "start".into(),
            "--install-dir".into(),
            configuration.installation.to_string_lossy().to_string(),
            "--docker-bin".into(),
            configuration.docker.to_string_lossy().to_string(),
        ],
        vec![
            "systemctl".into(),
            "--user".into(),
            "link".into(),
            evidence.join(&boot).to_string_lossy().to_string(),
            evidence.join(&check).to_string_lossy().to_string(),
            evidence.join(&timer).to_string_lossy().to_string(),
        ],
        vec!["systemctl".into(), "--user".into(), "daemon-reload".into()],
        vec![
            "systemctl".into(),
            "--user".into(),
            "enable".into(),
            "--now".into(),
            boot,
            timer,
        ],
    ];
    json!({
        "required_prerequisites":["customer-managed rootless docker.service", "customer-enabled user lingering for unattended boot"],
        "commands":commands,
        "commands_executed":false,
        "note":"Use retained start only when running is intended. Use retained stop for persistent maintenance pause. Generated units do not enable lingering or manage Docker."
    })
}

/// A paused boot/check/shutdown is a successful no-op before any Docker call.
/// The timer never changes desired state, and host shutdown never appends pause.
fn scheduled_operation(
    action: Action,
    desired_state: DesiredState,
) -> Result<Option<&'static str>> {
    require(matches!(
        action,
        Action::Boot | Action::Shutdown | Action::Check
    ))?;
    if desired_state == DesiredState::Paused {
        return Ok(None);
    }
    Ok(Some(match action {
        Action::Boot => "start",
        Action::Shutdown => "stop",
        Action::Check => "validate",
        _ => unreachable!(),
    }))
}

fn scheduled(
    state: &mut LockedMaintenance,
    installation: &Path,
    docker: &Path,
    action: Action,
    loaded: &Loaded,
) -> Result<Value> {
    let Some(operation) = scheduled_operation(action, loaded.intent.desired_state)? else {
        return Ok(json!({"outcome":"paused", "docker_invoked":false, "intent_preserved":true}));
    };
    if operation == "validate" {
        installer_validation::run_locked(installation, docker, state.inspection(), false)?;
        return Ok(
            json!({"outcome":"validation_passed", "read_only":true, "intent_preserved":true}),
        );
    }
    let report = installer_uninstall::execute_locked(installation, docker, operation, state)?;
    let report: Value = installer_json::decode(report.as_bytes()).map_err(|_| REFUSED)?;
    require(report["command_succeeded"] == true && report["observation_validated"] == true)?;
    Ok(json!({"outcome":"completed", "compose_operation":report, "intent_preserved":true}))
}

pub fn run(args: &[String]) -> Result<String> {
    let args = arguments(args)?;
    let mut state = LockedMaintenance::open(&args.installation)?;
    let mut report = json!({"schema":"elevenid.installer-lifecycle/v1", "installation_id":state.journal().installation_id(),
        "systemd_controlled":false, "systemd_enablement_observed":false, "installation_ready":false,
        "automatic_renewal":"not_implemented", "expired_credential_recovery":"not_qualified",
        "boot_recovery_qualification":"not_assessed", "scheduler":"customer_user_systemd"});
    if args.action == Action::Export {
        let configuration = prepare(state.inspection(), &args.installation, &args.docker)?;
        report["operation"] = json!("export");
        report["units"] = json!(render_units(&configuration)?);
        report["next_actions"] = next_actions(&configuration);
        report["files_written"] = json!(false);
    } else {
        let loaded = if args.action == Action::Install {
            Some(install(&mut state, &args.installation, &args.docker)?)
        } else {
            configured(state.inspection(), &args.installation, &args.docker)?
        };
        report["configured"] = json!(loaded.is_some());
        if let Some(loaded) = loaded {
            report["desired_state"] = json!(loaded.intent.desired_state);
            report["intent_sequence"] = json!(loaded.intent.sequence);
            report["intent_reason"] = json!(loaded.intent.reason);
            report["unit_sha256"] = json!(loaded.configuration.units);
            match args.action {
                Action::Install | Action::Status => {
                    report["operation"] = json!(if args.action == Action::Install {
                        "install"
                    } else {
                        "status"
                    });
                    report["next_actions"] = next_actions(&loaded.configuration);
                    report["compose_maintenance"] =
                        installer_uninstall::status(state.inspection())?;
                    report["current_container_state_observed"] = json!(false);
                }
                action => {
                    report["operation"] = json!(match action {
                        Action::Boot => "boot",
                        Action::Shutdown => "shutdown",
                        _ => "check",
                    });
                    report["result"] = scheduled(
                        &mut state,
                        &args.installation,
                        &args.docker,
                        action,
                        &loaded,
                    )?;
                }
            }
        } else if args.action != Action::Status {
            return Err("Lifecycle is not configured; use lifecycle install and review the returned customer enablement commands".into());
        }
    }
    state.require_unchanged()?;
    serde_json::to_string(&report).map_err(|_| REFUSED.into())
}

#[cfg(test)]
#[path = "installer_lifecycle_tests.rs"]
mod tests;
