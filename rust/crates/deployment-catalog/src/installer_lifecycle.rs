//! Customer-owned user-systemd integration for an existing, bound Compose stack.
//! The operator serializes bounded recovery; Docker owns process restarts.
//! Customer maintenance intent always precedes a runtime mutation.
#![cfg(target_os = "linux")]

use crate::{
    installer_doctor, installer_generation_maintenance, installer_health, installer_host_fs,
    installer_json, installer_openbao_recovery, installer_release, installer_root_retirement,
    installer_runtime,
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
    time::Duration,
};

type Result<T> = std::result::Result<T, String>;
const CONFIGURATION: &str = "lifecycle-configuration.json";
const CONFIGURATION_SCHEMA: &str = "elevenid.installer-lifecycle-configuration/v2";
const INTENT_SCHEMA: &str = "elevenid.installer-lifecycle-intent/v2";
const REFUSED: &str = "Installer lifecycle could not establish its next postcondition; preserve the installation-scoped units, intent and operation evidence";
const MAX_INTENTS: usize = 10000;
const SCHEDULED_LOCK_WAIT: Duration = Duration::from_secs(30);

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
    Maintain,
    Pause,
    Resume,
    SecuritySeal,
}

struct Arguments {
    action: Action,
    installation: PathBuf,
    docker: PathBuf,
    scheduled: bool,
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
        Some("maintain") => Action::Maintain,
        Some("pause") => Action::Pause,
        Some("resume") => Action::Resume,
        Some("security-seal") => Action::SecuritySeal,
        _ => return Err("Expected lifecycle export|install|status|boot|shutdown|check|maintain|pause|resume|security-seal --install-dir ABS [--docker-bin ABS] [--scheduled (check|maintain only)]".into()),
    };
    let mut values = BTreeMap::new();
    let mut scheduled = false;
    let mut options = args[1..].iter();
    while let Some(option) = options.next() {
        if option == "--scheduled" {
            require(!scheduled && matches!(action, Action::Check | Action::Maintain))?;
            scheduled = true;
            continue;
        }
        let value = options.next().ok_or(REFUSED)?;
        require(
            ["--install-dir", "--docker-bin"].contains(&option.as_str())
                && values.insert(option.as_str(), value.as_str()).is_none(),
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
        scheduled,
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
    SecuritySealed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum IntentReason {
    Installed,
    ManualStart,
    ManualStop,
    Uninstall,
    Pause,
    Resume,
    SecuritySeal,
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

fn unit_names(id: uuid::Uuid) -> [String; 5] {
    operator_unit_names(id, None)
}

pub(crate) fn operator_unit_names(id: uuid::Uuid, sequence: Option<u64>) -> [String; 5] {
    let prefix = sequence.map_or_else(
        || format!("lifecycle-marty-{id}"),
        |sequence| format!("lifecycle-marty-{id}-operator-{sequence:04}"),
    );
    [
        format!("{prefix}.service"),
        format!("{prefix}-check.service"),
        format!("{prefix}-check.timer"),
        format!("{prefix}-maintenance.service"),
        format!("{prefix}-maintenance.timer"),
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
    let operator = configuration.installation.join("marty-deploy");
    command_for_operator(configuration, action, &operator)
}

fn command_for_operator(
    configuration: &Configuration,
    action: &str,
    operator: &Path,
) -> Result<String> {
    installation_text(&configuration.installation)?;
    let argv = [
        path_text(operator)?,
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
    render_operator_units(
        configuration,
        &configuration.installation.join("marty-deploy"),
        None,
    )
}

fn render_operator_units(
    configuration: &Configuration,
    operator: &Path,
    sequence: Option<u64>,
) -> Result<BTreeMap<String, String>> {
    let id = configuration.installation_id;
    let [boot, check, timer, maintenance, maintenance_timer] = operator_unit_names(id, sequence);
    let selected_command = |action| {
        if sequence.is_some() {
            command_for_operator(configuration, action, operator)
        } else {
            command(configuration, action)
        }
    };
    let boot_text = format!(
        "# Generated for Marty installation {id}; customer enables this user unit.\n\
[Unit]\nDescription=Marty installation {id}\nWants=docker.service\nAfter=docker.service\n\
StartLimitIntervalSec=900\nStartLimitBurst=3\n\n\
[Service]\nType=oneshot\nRemainAfterExit=yes\nNoNewPrivileges=yes\nUMask=0077\n\
TimeoutStartSec=1800\nTimeoutStopSec=900\nRestart=on-failure\nRestartSec=15\n\
ExecStart={}\nExecStop={}\n\n[Install]\nWantedBy=default.target\n",
        selected_command("boot")?,
        selected_command("shutdown")?
    );
    let check_text = format!(
        "# Read-only validation; no renewal, restart or recovery action.\n\
[Unit]\nDescription=Marty deployment check {id}\nAfter=docker.service {boot}\n\n\
[Service]\nType=oneshot\nNoNewPrivileges=yes\nUMask=0077\nTimeoutStartSec=180\nExecStart={} \"--scheduled\"\n",
        selected_command("check")?
    );
    let timer_text = format!(
        "[Unit]\nDescription=Marty deployment check schedule {id}\n\n\
[Timer]\nOnCalendar=*-*-* *:00/5:00\nPersistent=true\nRandomizedDelaySec=30\nUnit={check}\n\n\
[Install]\nWantedBy=timers.target\n"
    );
    let maintenance_text = format!(
        "# Bounded operator reconciliation under the installation lock.\n\
[Unit]\nDescription=Marty maintenance {id}\nWants=docker.service\nAfter=docker.service {boot}\n\n\
[Service]\nType=oneshot\nNoNewPrivileges=yes\nUMask=0077\nTimeoutStartSec=1830\nExecStart={} \"--scheduled\"\n",
        selected_command("maintain")?
    );
    let maintenance_timer_text = format!(
        "[Unit]\nDescription=Marty maintenance schedule {id}\n\n\
[Timer]\nOnCalendar=*-*-* *:00/5:00\nPersistent=true\nRandomizedDelaySec=30\nUnit={maintenance}\n\n\
[Install]\nWantedBy=timers.target\n"
    );
    Ok([
        (boot, boot_text),
        (check, check_text),
        (timer, timer_text),
        (maintenance, maintenance_text),
        (maintenance_timer, maintenance_timer_text),
    ]
    .into())
}

/// Successor exports have distinct unit names and explicit executable paths.
/// The original configuration and pause/security-seal intent remain authoritative.
pub(crate) fn successor_unit_exports(
    state: &LockedInspection,
    installation: &Path,
    docker: &Path,
    operator: &Path,
    sequence: u64,
) -> Result<BTreeMap<String, String>> {
    require((1..=32).contains(&sequence) && operator.starts_with(installation.join("operators")))?;
    let loaded = configured(state, installation, docker)?.ok_or(REFUSED)?;
    render_operator_units(&loaded.configuration, operator, Some(sequence))
}

fn prepare(state: &LockedInspection, installation: &Path, docker: &Path) -> Result<Configuration> {
    installation_text(installation)?;
    path_text(docker)?;
    state.require_path_binding(installation)?;
    let journal = state.journal();
    let runtime = journal.runtime().ok_or(REFUSED)?;
    runtime.validate()?;
    require(runtime.profile == RuntimeProfile::Rootless)?;
    // Later credential activations replace runtime inputs. The customer unit
    // binding remains anchored to the original admitted application session.
    let saved = installer_doctor::load_initial_session(state, installation)?;
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
            require(names.len() < MAX_INTENTS + 6 && name.len() <= 128)?;
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
            IntentReason::ManualStart | IntentReason::Resume => {
                sequence > 1 && intent.desired_state == DesiredState::Running
            }
            IntentReason::ManualStop | IntentReason::Uninstall | IntentReason::Pause => {
                sequence > 1 && intent.desired_state == DesiredState::Paused
            }
            IntentReason::SecuritySeal => {
                sequence > 1 && intent.desired_state == DesiredState::SecuritySealed
            }
        };
        if let Some((prior, _)) = &latest {
            let prior: &Intent = prior;
            require(
                prior.desired_state != DesiredState::SecuritySealed
                    || matches!(
                        intent.reason,
                        IntentReason::Resume | IntentReason::SecuritySeal
                    ),
            )?;
        }
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
    require(previous.is_none_or(|(intent, _)| {
        intent.desired_state != DesiredState::SecuritySealed
            || matches!(reason, IntentReason::Resume | IntentReason::SecuritySeal)
    }))?;
    let intent = Intent {
        schema: INTENT_SCHEMA.into(),
        installation_id: configuration.installation_id,
        configuration_sha256: configuration_sha256.into(),
        sequence,
        desired_state: match reason {
            IntentReason::ManualStart | IntentReason::Resume => DesiredState::Running,
            IntentReason::SecuritySeal => DesiredState::SecuritySealed,
            _ => DesiredState::Paused,
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
        if loaded.intent.desired_state == DesiredState::SecuritySealed {
            if reason == IntentReason::ManualStart {
                return Err("This installation is deliberately security-sealed; use lifecycle resume to explicitly authorize recovery".into());
            }
            // A stop or uninstall must not turn a deliberate seal into a pause
            // that an ordinary start could subsequently clear.
            return Ok(());
        }
        if (reason == IntentReason::ManualStart
            && loaded.intent.desired_state == DesiredState::Running)
            || (reason == loaded.intent.reason)
        {
            return Ok(());
        }
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

/// Fresh installation prepares immutable user units after native application
/// validation. Customer service enablement and the initial resume stay explicit.
pub(crate) fn install_locked(
    state: &mut LockedMaintenance,
    installation: &Path,
    docker: &Path,
) -> Result<Value> {
    let loaded = install(state, installation, docker)?;
    let prerequisites = installer_runtime::observe_user_systemd_prerequisites(installation);
    Ok(json!({"schema":"elevenid.installer-lifecycle-export/v2",
        "installation_id":loaded.configuration.installation_id,
        "configured":true,"desired_state":loaded.intent.desired_state,
        "unit_sha256":loaded.configuration.units,
        "user_systemd_prerequisites":prerequisites,
        "unattended_eligible":unattended_eligible(loaded.configuration.owner_uid, &prerequisites),
        "unattended_eligibility_scope":"user_systemd_prerequisites_only",
        "next_actions":next_actions(&loaded.configuration, &prerequisites),
        "systemd_controlled":false,"systemd_enablement_observed":false,
        "installation_ready":false}))
}

/// Unknown observations cannot authorize unattended startup. A known missing
/// prerequisite remains false even when a different observation is unavailable.
/// This is not evidence that Marty units are enabled or reboot-qualified.
fn unattended_eligible(
    owner_uid: u32,
    prerequisites: &installer_runtime::UserSystemdPrerequisites,
) -> Option<bool> {
    if owner_uid == 0 || prerequisites.uid != owner_uid {
        return Some(false);
    }
    let observed = [
        prerequisites.linger_enabled,
        prerequisites.docker_unit_loaded,
        prerequisites.docker_unit_enabled,
        prerequisites.docker_unit_active,
    ];
    if observed.contains(&Some(false)) {
        Some(false)
    } else if observed.iter().all(|value| *value == Some(true)) {
        Some(true)
    } else {
        None
    }
}

fn next_actions(
    configuration: &Configuration,
    prerequisites: &installer_runtime::UserSystemdPrerequisites,
) -> Value {
    let [boot, check, timer, maintenance, maintenance_timer] =
        unit_names(configuration.installation_id);
    let evidence = configuration.installation.join("evidence");
    let eligible = unattended_eligible(configuration.owner_uid, prerequisites);
    let manual_recovery_command = vec![
        configuration
            .installation
            .join("marty-deploy")
            .to_string_lossy()
            .to_string(),
        "lifecycle".into(),
        "resume".into(),
        "--install-dir".into(),
        configuration.installation.to_string_lossy().to_string(),
        "--docker-bin".into(),
        configuration.docker.to_string_lossy().to_string(),
    ];
    let mut commands: Vec<Vec<String>> = vec![
        manual_recovery_command.clone(),
        vec![
            "systemctl".into(),
            "--user".into(),
            "link".into(),
            evidence.join(&boot).to_string_lossy().to_string(),
            evidence.join(&check).to_string_lossy().to_string(),
            evidence.join(&timer).to_string_lossy().to_string(),
            evidence.join(&maintenance).to_string_lossy().to_string(),
            evidence
                .join(&maintenance_timer)
                .to_string_lossy()
                .to_string(),
        ],
        vec!["systemctl".into(), "--user".into(), "daemon-reload".into()],
        vec![
            "systemctl".into(),
            "--user".into(),
            "enable".into(),
            "--now".into(),
            boot,
            timer,
            maintenance_timer,
        ],
    ];
    if eligible != Some(true) {
        commands.clear();
    }
    let mut remediation = Vec::new();
    if configuration.owner_uid == 0 || prerequisites.uid != configuration.owner_uid {
        remediation.push(json!({
            "prerequisite":"installation_owner_user_manager",
            "observed":false,
            "customer_action":"Run lifecycle status as the recorded non-root installation owner in that user's systemd session; root or another user's manager cannot establish unattended eligibility."
        }));
    }
    for (name, observed, missing, unknown) in [
        (
            "linger_enabled",
            prerequisites.linger_enabled,
            format!("Ask the host administrator to enable lingering for installation owner UID {}; then rerun lifecycle status as that owner.", configuration.owner_uid),
            "Verify the installation owner's lingering state from the owner's host session; an unavailable observation does not prove reboot startup.".into(),
        ),
        (
            "docker_unit_loaded",
            prerequisites.docker_unit_loaded,
            "Install or repair the customer's rootless docker.service in the installation owner's user manager; then rerun lifecycle status.".into(),
            "Inspect docker.service from the installation owner's user manager and resolve an unavailable user bus or unit before enabling unattended Marty startup.".into(),
        ),
        (
            "docker_unit_enabled",
            prerequisites.docker_unit_enabled,
            "Enable the customer's rootless docker.service persistently in the installation owner's user manager; runtime-only enablement does not survive reboot.".into(),
            "Verify persistent enablement of docker.service from the installation owner's user manager; unknown enablement does not authorize unattended startup.".into(),
        ),
        (
            "docker_unit_active",
            prerequisites.docker_unit_active,
            "Start or repair the customer's rootless docker.service in the installation owner's user manager; then rerun lifecycle status.".into(),
            "Verify that the customer's rootless docker.service is active in the installation owner's user manager before enabling unattended Marty startup.".into(),
        ),
    ] {
        if observed != Some(true) {
            remediation.push(json!({
                "prerequisite":name,"observed":observed,
                "customer_action":if observed == Some(false) {missing} else {unknown}
            }));
        }
    }
    json!({
        "required_prerequisites":["customer-managed rootless docker.service", "customer-enabled user lingering for unattended boot"],
        "unattended_eligible":eligible,
        "unattended_eligibility_scope":"user_systemd_prerequisites_only",
        "manual_recovery_command":manual_recovery_command,
        "prerequisite_remediation":remediation,
        "prerequisite_verification_commands":[
            ["/usr/bin/loginctl","show-user",&configuration.owner_uid.to_string(),"--property=Linger","--value"],
            ["/usr/bin/systemctl","--user","show","docker.service","--property=LoadState","--property=UnitFileState","--property=ActiveState"]
        ],
        "commands":commands,
        "commands_executed":false,
        "enablement_condition":"Enable the exported Marty units only after lifecycle status observes every user-systemd prerequisite as true for the recorded installation owner. Eligibility does not prove Marty-unit enablement or host reboot recovery.",
        "note":"Manual lifecycle resume remains available without lingering or user-service enablement when Docker is accessible and running is intended. Stop, lifecycle pause and security-seal persist across timers and reboot. The customer manages Docker and lingering."
    })
}

/// Scheduling never changes intent. A pending stop is reconciled separately;
/// an initial paused export needs no Docker operation at all.
fn scheduled_operation(
    action: Action,
    desired_state: DesiredState,
) -> Result<Option<&'static str>> {
    require(matches!(
        action,
        Action::Boot | Action::Shutdown | Action::Check | Action::Maintain
    ))?;
    if desired_state != DesiredState::Running {
        return Ok(None);
    }
    Ok(Some(match action {
        Action::Boot => "start",
        Action::Shutdown => "stop",
        Action::Check => "validate",
        Action::Maintain => "maintain",
        _ => unreachable!(),
    }))
}

fn compose_result(report: String) -> Result<Value> {
    let report: Value = installer_json::decode(report.as_bytes()).map_err(|_| REFUSED)?;
    require(report["command_succeeded"] == true && report["observation_validated"] == true)?;
    Ok(report)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ApplicationRecoveryStep {
    MaintainGeneration,
    RepairHealth,
    StartRetained,
    ValidateSelected,
}

struct ApplicationRecovery {
    generation: Value,
    health: Value,
    application: Value,
}

/// A currently usable selection can serve while optional provider maintenance
/// runs. The health owner is invoked exactly once in either order; a successor
/// is started by the generation owner and receives a final read-only check.
fn recover_application_in_order(
    start_before_maintenance: bool,
    mut execute: impl FnMut(ApplicationRecoveryStep) -> Result<Value>,
) -> Result<ApplicationRecovery> {
    let generation = if start_before_maintenance {
        None
    } else {
        Some(execute(ApplicationRecoveryStep::MaintainGeneration)?)
    };
    let health = execute(ApplicationRecoveryStep::RepairHealth)?;
    let application = execute(ApplicationRecoveryStep::StartRetained)?;
    execute(ApplicationRecoveryStep::ValidateSelected)?;
    let generation = if let Some(generation) = generation {
        generation
    } else {
        let generation = execute(ApplicationRecoveryStep::MaintainGeneration)?;
        execute(ApplicationRecoveryStep::ValidateSelected)?;
        generation
    };
    Ok(ApplicationRecovery {
        generation,
        health,
        application,
    })
}

/// Cold recovery uses the local Unix authority before opening OpenBao HTTPS.
/// The generation owner is the only writer of the application selection. This
/// sequence is also used after daemon restarts and explicit customer resume.
fn recover_running(
    state: &mut LockedMaintenance,
    installation: &Path,
    docker: &Path,
) -> Result<Value> {
    // A lost replacement response can leave an authenticated mixture of old
    // and new container IDs. Only the transaction owner may reconcile it;
    // ordinary doctor/health admission must not run against that intermediate
    // state and strand the pending activation.
    installer_generation_maintenance::reconcile_pending_locked(installation, docker, state)
        .map_err(|error| format!("Lifecycle blocked at pending generation recovery: {error}"))?;
    let initial = installer_doctor::load_initial_session(state.inspection(), installation)?;
    installer_generation_maintenance::require_lineage(
        state.inspection(),
        installation,
        &initial.configuration_sha256,
    )?;
    let infrastructure_health =
        installer_health::reconcile_infrastructure_locked(installation, docker, state)?;
    let (_, session) = installer_doctor::open_session(state.inspection(), installation, docker)?;
    let resources = session.observe_resources()?;
    let infrastructure: Vec<String> = ["openbao", "openbao-unseal", "installer-acme-http01"]
        .into_iter()
        .filter(|role| resources.containers.contains_key(*role))
        .map(String::from)
        .collect();
    let infrastructure_report = if infrastructure.is_empty() {
        Value::Null
    } else {
        compose_result(
            installer_uninstall::start_selected_locked(
                installation,
                docker,
                &infrastructure,
                state,
            )
            .map_err(|error| {
                format!("Lifecycle blocked while starting retained infrastructure: {error}")
            })?,
        )?
    };
    let openbao = if resources.containers.contains_key("openbao") {
        let (_, current) =
            installer_doctor::open_session(state.inspection(), installation, docker)?;
        serde_json::to_value(
            installer_openbao_recovery::reconcile_locked(installation, docker, state, &current)
                .map_err(|error| {
                    format!("Lifecycle blocked at OpenBao local TLS recovery: {error}")
                })?,
        )
        .map_err(|_| REFUSED)?
    } else {
        Value::Null
    };
    let retirement = if resources.containers.contains_key("openbao") {
        let (_, current) =
            installer_doctor::open_session(state.inspection(), installation, docker)?;
        serde_json::to_value(
            installer_root_retirement::resume_pending_locked(installation, docker, state, &current)
                .map_err(|error| {
                    format!("Lifecycle blocked while reconciling initial-root retirement: {error}")
                })?,
        )
        .map_err(|_| REFUSED)?
    } else {
        Value::Null
    };
    let usability: installer_generation_maintenance::CurrentGenerationUsability =
        installer_generation_maintenance::current_startup_usability(
            state.inspection(),
            installation,
        )
        .map_err(|error| {
            format!("Lifecycle blocked at selected-generation startup validation: {error}")
        })?;
    let start_before_maintenance = usability.can_start_before_maintenance();
    let application = recover_application_in_order(start_before_maintenance, |step| match step {
        ApplicationRecoveryStep::MaintainGeneration => serde_json::to_value(
            installer_generation_maintenance::reconcile_locked(installation, docker, state)
                .map_err(|error| {
                    format!("Lifecycle blocked at credential generation reconciliation: {error}")
                })?,
        )
        .map_err(|_| REFUSED.into()),
        ApplicationRecoveryStep::RepairHealth => {
            installer_health::reconcile_locked(installation, docker, state)
                .map_err(|error| format!("Lifecycle blocked at bounded health recovery: {error}"))
        }
        ApplicationRecoveryStep::StartRetained => compose_result(
            installer_uninstall::execute_locked(installation, docker, "start", state).map_err(
                |error| {
                    format!(
                        "Lifecycle blocked while starting retained application services: {error}"
                    )
                },
            )?,
        ),
        ApplicationRecoveryStep::ValidateSelected => {
            installer_validation::run_locked(installation, docker, state.inspection(), false)
                .map_err(|error| format!("Lifecycle blocked at application validation: {error}"))?;
            Ok(Value::Null)
        }
    })?;
    Ok(
        json!({"outcome":"reconciled", "infrastructure":infrastructure_report,
        "infrastructure_health":infrastructure_health,
        "openbao_tls":openbao,"root_retirement":retirement,"generation":application.generation,"health":application.health,
        "current_generation_startup":usability,
        "application_started_before_generation_maintenance":start_before_maintenance,
        "application":application.application,"validation_passed":true,"intent_preserved":true,
        "reboot_qualification_established":false,"installation_ready":false}),
    )
}

fn stop_for_intent(
    state: &mut LockedMaintenance,
    installation: &Path,
    docker: &Path,
    desired: DesiredState,
) -> Result<Value> {
    let operation = compose_result(installer_uninstall::execute_locked(
        installation,
        docker,
        "stop",
        state,
    )?)?;
    Ok(
        json!({"outcome":if desired == DesiredState::SecuritySealed { "security_sealed" } else { "paused" },
        "compose_operation":operation,"intent_preserved":true,
        "seal_method":if desired == DesiredState::SecuritySealed { Some("owned_runtime_stopped") } else { None },
        "seal_key_preserved":true,"openbao_api_seal_invoked":false,"installation_ready":false}),
    )
}

fn scheduled(
    state: &mut LockedMaintenance,
    installation: &Path,
    docker: &Path,
    action: Action,
    loaded: &Loaded,
) -> Result<Value> {
    let Some(operation) = scheduled_operation(action, loaded.intent.desired_state)? else {
        // An interrupted deliberate stop must converge to stopped. Checks stay
        // read-only, and an initial export or completed uninstall cannot start
        // or recreate a missing project.
        if action != Action::Check
            && matches!(
                loaded.intent.reason,
                IntentReason::ManualStop | IntentReason::Pause | IntentReason::SecuritySeal
            )
        {
            return stop_for_intent(state, installation, docker, loaded.intent.desired_state);
        }
        return Ok(
            json!({"outcome":if loaded.intent.desired_state == DesiredState::SecuritySealed { "security_sealed" } else { "paused" },
            "docker_invoked":false, "intent_preserved":true}),
        );
    };
    if operation == "validate" {
        installer_validation::run_locked(installation, docker, state.inspection(), false)?;
        let (_, session) =
            installer_doctor::open_session(state.inspection(), installation, docker)?;
        let openbao = if session
            .observe_resources()?
            .containers
            .contains_key("openbao")
        {
            serde_json::to_value(installer_openbao_recovery::inspect_locked(
                installation,
                docker,
                state,
                &session,
            )?)
            .map_err(|_| REFUSED)?
        } else {
            Value::Null
        };
        return Ok(json!({"outcome":"validation_passed", "read_only":true,
            "openbao_tls":openbao,"intent_preserved":true}));
    }
    if operation == "start" || operation == "maintain" {
        return recover_running(state, installation, docker);
    }
    let report = compose_result(installer_uninstall::execute_locked(
        installation,
        docker,
        operation,
        state,
    )?)?;
    Ok(json!({"outcome":"completed", "compose_operation":report, "intent_preserved":true}))
}

fn manual_control(
    state: &mut LockedMaintenance,
    installation: &Path,
    docker: &Path,
    action: Action,
    loaded: &Loaded,
) -> Result<Value> {
    let reason = match action {
        Action::Pause => IntentReason::Pause,
        Action::Resume => IntentReason::Resume,
        Action::SecuritySeal => IntentReason::SecuritySeal,
        _ => return Err(REFUSED.into()),
    };
    let keep_seal =
        loaded.intent.desired_state == DesiredState::SecuritySealed && action != Action::Resume;
    let desired = if keep_seal {
        DesiredState::SecuritySealed
    } else if reason == loaded.intent.reason {
        loaded.intent.desired_state
    } else {
        append_intent(
            state,
            &loaded.configuration,
            &loaded.configuration_sha256,
            Some((&loaded.intent, &loaded.intent_sha256)),
            reason,
        )?
        .desired_state
    };
    if desired == DesiredState::Running {
        recover_running(state, installation, docker)
    } else {
        stop_for_intent(state, installation, docker, desired)
    }
}

/// A configured ordinary start shares the cold-recovery path. The caller has
/// already persisted manual intent under this same lock.
pub(crate) fn start_if_configured(
    state: &mut LockedMaintenance,
    installation: &Path,
    docker: &Path,
) -> Result<Option<String>> {
    let Some(loaded) = configured(state.inspection(), installation, docker)? else {
        return Ok(None);
    };
    require(loaded.intent.desired_state == DesiredState::Running)?;
    let report = recover_running(state, installation, docker)?;
    serde_json::to_string(&report)
        .map(Some)
        .map_err(|_| REFUSED.into())
}

/// Destructive initial-root retirement is a separate operator command and must
/// not run during a durable customer pause or security seal.
pub(crate) fn require_running_intent(
    state: &LockedMaintenance,
    installation: &Path,
    docker: &Path,
) -> Result<()> {
    let loaded = configured(state.inspection(), installation, docker)?.ok_or(REFUSED)?;
    require(loaded.intent.desired_state == DesiredState::Running)
}

/// Revalidate a permit against current durable intent without contacting Docker.
/// The retained configuration supplies only the executable path; `configured`
/// still rechecks the release, operator, units and full append-only intent chain.
pub(crate) fn require_recorded_running_intent(
    state: &LockedInspection,
    installation: &Path,
) -> Result<()> {
    state.require_path_binding(installation)?;
    let bytes = state.read_evidence(CONFIGURATION)?;
    require(bytes.len() <= 65536)?;
    let configuration: Configuration =
        serde_json::from_value(installer_json::decode(&bytes).map_err(|_| REFUSED)?)
            .map_err(|_| REFUSED)?;
    let loaded = configured(state, installation, &configuration.docker)?.ok_or(REFUSED)?;
    require(loaded.intent.desired_state == DesiredState::Running)
}

pub fn run(args: &[String]) -> Result<String> {
    run_with_lock_wait(args, SCHEDULED_LOCK_WAIT)
}

fn run_with_lock_wait(args: &[String], scheduled_wait: Duration) -> Result<String> {
    let args = arguments(args)?;
    let mut state = if args.scheduled {
        let Some(state) = LockedMaintenance::open_waiting(&args.installation, scheduled_wait)?
        else {
            // There is no installation observation without the lock. A busy
            // schedule is deferred, never reported as validation or recovery.
            return serde_json::to_string(&json!({
                "schema":"elevenid.installer-lifecycle/v2",
                "operation":if args.action == Action::Check { "check" } else { "maintain" },
                "scheduled":true,"installation_ready":false,
                "runtime_observed":false,"qualification":"not_assessed",
                "result":{"outcome":"deferred","reason":"installation_lock_busy",
                    "lock_wait_seconds":scheduled_wait.as_secs(),"operation_performed":false,
                    "docker_invoked":false,"intent_modified":false}
            }))
            .map_err(|_| REFUSED.into());
        };
        state
    } else {
        LockedMaintenance::open(&args.installation)?
    };
    let operator_owner =
        crate::installer_operator_upgrade::status_locked(state.inspection(), &args.installation)?;
    if !matches!(args.action, Action::Status | Action::Export) {
        crate::installer_operator_upgrade::require_selected_caller(
            state.inspection(),
            &args.installation,
        )?;
    } else if !operator_owner["pending_sequence"].is_null() {
        if args.action == Action::Status {
            return serde_json::to_string(&json!({"schema":"elevenid.installer-lifecycle/v2", "operation":"status",
                "operator_owner":operator_owner, "runtime_observed":false, "installation_ready":false}))
                .map_err(|_| REFUSED.into());
        }
        return Err(
            "Reconcile the pending operator successor before exporting lifecycle units".into(),
        );
    }
    let prerequisites = installer_runtime::observe_user_systemd_prerequisites(&args.installation);
    let mut report = json!({"schema":"elevenid.installer-lifecycle/v2", "installation_id":state.journal().installation_id(),
        "systemd_controlled":false, "systemd_enablement_observed":false, "installation_ready":false,
        "automatic_renewal":"selection_specific_see_generation_status", "automatic_renewal_supported":null,
        "expired_credential_recovery":"owner_specific_qualification_required",
        "maintenance_capabilities":{
            "openbao_listener_tls":"retained_local_control_recovery",
            "public_generation_credentials":"selected_generation_owner",
            "private_generation_renewal":"selected_generation_owner",
            "imported_foundation_credentials":"customer_managed"
        },
        "user_systemd_prerequisites":prerequisites,
        "unattended_eligible":unattended_eligible(prerequisites.uid, &prerequisites),
        "unattended_eligibility_scope":"user_systemd_prerequisites_only",
        "boot_recovery_qualification":"not_assessed", "scheduler":"customer_user_systemd"});
    if args.action == Action::Export {
        let configuration = prepare(state.inspection(), &args.installation, &args.docker)?;
        report["operation"] = json!("export");
        report["units"] = json!(render_units(&configuration)?);
        report["unattended_eligible"] =
            json!(unattended_eligible(configuration.owner_uid, &prerequisites));
        report["next_actions"] = next_actions(&configuration, &prerequisites);
        report["files_written"] = json!(false);
    } else {
        let loaded = if args.action == Action::Install {
            Some(install(&mut state, &args.installation, &args.docker)?)
        } else {
            configured(state.inspection(), &args.installation, &args.docker)?
        };
        report["configured"] = json!(loaded.is_some());
        if let Some(loaded) = loaded {
            report["unattended_eligible"] = json!(unattended_eligible(
                loaded.configuration.owner_uid,
                &prerequisites
            ));
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
                    report["next_actions"] = next_actions(&loaded.configuration, &prerequisites);
                    report["compose_maintenance"] =
                        installer_uninstall::status(state.inspection())?;
                    report["generation"] = installer_generation_maintenance::status_locked(
                        state.inspection(),
                        &args.installation,
                    )
                    .unwrap_or_else(|_| {
                        json!({
                            "available":false,
                            "first_blocking_dependency":"generation_evidence_unavailable",
                            "read_only":true,"installation_ready":false
                        })
                    });
                    report["automatic_renewal_supported"] =
                        report["generation"]["automatic_renewal_supported"].clone();
                    report["current_container_state_observed"] = json!(false);
                }
                action => {
                    report["operation"] = json!(match action {
                        Action::Boot => "boot",
                        Action::Shutdown => "shutdown",
                        Action::Maintain => "maintain",
                        Action::Pause => "pause",
                        Action::Resume => "resume",
                        Action::SecuritySeal => "security-seal",
                        Action::Check => "check",
                        _ => return Err(REFUSED.into()),
                    });
                    report["result"] = if matches!(
                        action,
                        Action::Pause | Action::Resume | Action::SecuritySeal
                    ) {
                        manual_control(
                            &mut state,
                            &args.installation,
                            &args.docker,
                            action,
                            &loaded,
                        )?
                    } else {
                        scheduled(
                            &mut state,
                            &args.installation,
                            &args.docker,
                            action,
                            &loaded,
                        )?
                    };
                    let current = configured(state.inspection(), &args.installation, &args.docker)?
                        .ok_or(REFUSED)?;
                    report["desired_state"] = json!(current.intent.desired_state);
                    report["intent_sequence"] = json!(current.intent.sequence);
                    report["intent_reason"] = json!(current.intent.reason);
                }
            }
        } else if args.action != Action::Status {
            return Err("Lifecycle is not configured; use lifecycle install and review the returned customer enablement commands".into());
        }
    }
    report["operator_owner"] = operator_owner;
    if !report["operator_owner"]["selected_operator"].is_null() {
        let owner = &report["operator_owner"]["selected_operator"];
        report["next_actions"] = json!({"manual_recovery_command":[owner["entrypoint"], "lifecycle", "resume", "--install-dir", args.installation, "--docker-bin", args.docker],
            "successor_unit_directory":owner["unit_directory"], "successor_unit_sha256":owner["units"],
            "customer_action":"Link the distinct successor unit exports in the installation owner's user manager; keep every predecessor unit masked. Enablement and boot qualification require separate observation.",
            "systemd_controlled":false, "scheduler_activation":"not_assessed"});
        if args.action == Action::Export {
            report["units"] = json!(crate::installer_operator_upgrade::selected_unit_exports(
                state.inspection(),
                &args.installation
            )?);
        }
    }
    state.require_unchanged()?;
    serde_json::to_string(&report).map_err(|_| REFUSED.into())
}

#[cfg(test)]
#[path = "installer_lifecycle_tests.rs"]
mod tests;
