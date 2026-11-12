//! An explicitly admitted Linux operator successor, retaining the installed
//! product, original bootstrap operator and every historical installation record.
//! Staging is not activation. Selection requires the predecessor user units to
//! be observably quiescent; an old binary cannot understand this owner selector.
#![cfg(target_os = "linux")]

use crate::{
    installer_compose::ComposeSession,
    installer_doctor, installer_generation_maintenance, installer_json,
    installer_release as release,
    installer_state::{
        ExecutionScope, Identity, LockedInspection, LockedMaintenance, Phase, RuntimeBinding,
        RuntimeProfile,
    },
    installer_verify::{self, VerificationTools},
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

#[path = "installer_operator_upgrade_fs.rs"]
mod private;
use private::Directory;

type Result<T> = std::result::Result<T, String>;
const REFUSED: &str = "Operator-only successor admission or publication is incomplete; retain the original installation and reconcile the same upgrade attempt";
const SELECTOR: &str = "operator-owner-current.json";
const MAX_RECORD: usize = 4 * 1024 * 1024;
const MAX_ATTEMPTS: u64 = 32;
const ORIGINAL_SOURCE: &str = "b7c7055830722d10512ccac042b1e0abe0e1ecec";
const ASSETS: [&str; 6] = [
    "installer-admission.json",
    "installer-admission.json.sigstore.json",
    "installer-admission.json.provenance.jsonl",
    "installer-inventory.json",
    "installer-inventory.json.sigstore.json",
    "installer-inventory.json.provenance.jsonl",
];

fn require(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}
fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| REFUSED.into())
}
fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    require(!bytes.is_empty() && bytes.len() <= MAX_RECORD)?;
    serde_json::from_value(installer_json::decode(bytes).map_err(|_| REFUSED)?)
        .map_err(|_| REFUSED.into())
}
fn digest<T: Serialize>(value: &T) -> Result<String> {
    Ok(release::sha256(&encode(value)?))
}
fn record(sequence: u64, kind: &str) -> String {
    format!("operator-upgrade-{sequence:04}-{kind}.json")
}

/// The target binary itself declares the compatibility policy. The caller
/// cannot provide a replacement contract, schema migration or product model.
pub fn contract() -> Value {
    json!({"schema":"elevenid.installer-operator-compatibility/v1",
        "operation":"retained-linux-operator-only", "platform":"linux/amd64",
        "original_source_sha":ORIGINAL_SOURCE,
        "journal_schema":"elevenid.installer-state/v1",
        "compose_session_schema":"elevenid.installer-compose-session/v1",
        "lifecycle_schema":"elevenid.installer-lifecycle-configuration/v2",
        "product_images":"original-authenticated-closure", "product_model":"retained-exact",
        "database_schema":"unchanged", "database_migration":false, "credential_issuance":false,
        "key_custody_change":false, "bootstrap_operator_replacement":false,
        "credential_successors":"existing-verified-lineage", "scheduler_takeover":"explicit-quiescent-predecessor"})
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Operator {
    source_sha: String,
    release_tag: String,
    sha256: String,
    size: u64,
    inventory_sha256: String,
    admission_sha256: String,
}
impl Operator {
    fn path(&self, installation: &Path) -> PathBuf {
        installation
            .join("operators")
            .join(&self.sha256)
            .join("marty-deploy")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Retained {
    installation_id: uuid::Uuid,
    installation: PathBuf,
    journal_sha256: String,
    original_release: Identity,
    original_operator: Operator,
    runtime: RuntimeBinding,
    project: String,
    initial_model_sha256: String,
    product_images_sha256: String,
    lifecycle_configuration_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Transition {
    session_sha256: String,
    generation_selector_sha256: Option<String>,
    resources_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Selector {
    schema: String,
    installation_id: uuid::Uuid,
    sequence: u64,
    intent_sha256: String,
    staged_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    schema: String,
    sequence: u64,
    retained: Retained,
    transition: Transition,
    previous: Option<Selector>,
    target: Operator,
    assets: BTreeMap<String, String>,
    compatibility: Value,
    docker: PathBuf,
    unit_files: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Staged {
    schema: String,
    sequence: u64,
    intent_sha256: String,
    operator_sha256: String,
    units_sha256: String,
    selected: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Terminal {
    schema: String,
    sequence: u64,
    intent_sha256: String,
    selector_sha256: Option<String>,
}

#[derive(Clone)]
struct Attempt {
    intent: Intent,
    staged: Option<Staged>,
    activation: bool,
    completed: bool,
    canceled: bool,
}
struct History {
    attempts: Vec<Attempt>,
    selector: Option<Selector>,
    selector_bytes: Option<Vec<u8>>,
    incomplete_intent: Option<u64>,
}
impl History {
    fn pending(&self) -> Option<&Attempt> {
        self.attempts.last().filter(|v| !v.completed && !v.canceled)
    }
    fn selected(&self) -> Option<&Attempt> {
        self.selector.as_ref().and_then(|s| {
            self.attempts
                .iter()
                .find(|a| a.intent.sequence == s.sequence)
        })
    }
    fn pending_sequence(&self) -> Option<u64> {
        self.pending()
            .map(|a| a.intent.sequence)
            .or(self.incomplete_intent)
    }
}

fn target_from(
    admission: &[u8],
    inventory: &[u8],
    sha: &str,
    source: &str,
    tag: &str,
) -> Result<Operator> {
    let (a, i) = release::bind_release(admission, inventory, sha, source, tag)?;
    Ok(Operator {
        source_sha: a.source_sha,
        release_tag: a.release_tag,
        sha256: sha.into(),
        size: i.artifact("marty-deploy-linux-amd64")?.size,
        inventory_sha256: release::sha256(inventory),
        admission_sha256: release::sha256(admission),
    })
}

fn retained(view: &LockedInspection, installation: &Path) -> Result<Retained> {
    view.require_path_binding(installation)?;
    let journal = view.journal();
    require(
        journal.phase() == Phase::Ready
            && matches!(journal.execution_scope(), ExecutionScope::Unclassified)
            && journal.identity().source_sha == ORIGINAL_SOURCE,
    )?;
    let runtime = journal.runtime().ok_or(REFUSED)?.clone();
    require(runtime.profile == RuntimeProfile::Rootless)?;
    runtime.validate()?;
    let initial = installer_doctor::load_initial_session(view, installation)?;
    require(initial.schema == "elevenid.installer-compose-session/v1")?;
    let inventory = view.read_evidence("installer-inventory.json")?;
    let admission = view.read_evidence("installer-admission.json")?;
    let original_operator = target_from(
        &admission,
        &inventory,
        &installer_verify::operator_digest(&installation.join("marty-deploy"))?,
        &journal.identity().source_sha,
        &journal.identity().release_tag,
    )?;
    require(
        journal.identity().inventory_sha256
            == format!("sha256:{}", original_operator.inventory_sha256),
    )?;
    let lifecycle = view.read_evidence("lifecycle-configuration.json")?;
    let lifecycle_value = installer_json::decode(&lifecycle).map_err(|_| REFUSED)?;
    require(
        lifecycle_value["schema"] == contract()["lifecycle_schema"]
            && lifecycle_value["installation_id"] == journal.installation_id().to_string()
            && lifecycle_value["operator_sha256"] == original_operator.sha256,
    )?;
    view.require_unchanged()?;
    Ok(Retained {
        installation_id: journal.installation_id(),
        installation: installation.into(),
        journal_sha256: release::sha256(
            &Directory::open(installation)?
                .read("installation.json", 65536, 0o600)?
                .ok_or(REFUSED)?,
        ),
        original_release: journal.identity().clone(),
        original_operator,
        runtime,
        project: journal.compose_project(),
        initial_model_sha256: initial.configuration_sha256,
        product_images_sha256: digest(&initial.inputs.approved_images)?,
        lifecycle_configuration_sha256: release::sha256(&lifecycle),
    })
}

fn transition(view: &LockedInspection, installation: &Path, docker: &Path) -> Result<Transition> {
    require(!installer_generation_maintenance::has_pending_generation(
        view,
        installation,
    )?)?;
    crate::installer_root_retirement::require_no_pending_for_generation(view)?;
    let history = crate::installer_uninstall::status(view)?;
    require(
        history["pending_operations"]
            .as_object()
            .is_some_and(|v| v.is_empty())
            && history["operations"]["down"] == "not_started",
    )?;
    let saved = installer_doctor::load_session(view, installation)?;
    require(saved.schema == "elevenid.installer-compose-session/v1")?;
    let mut inputs = saved.inputs.clone();
    inputs.services = saved
        .receipt
        .resources
        .as_ref()
        .ok_or(REFUSED)?
        .containers
        .values()
        .filter(|v| !v.setup)
        .map(|v| v.service.clone())
        .collect();
    require(!inputs.services.is_empty())?;
    let session = ComposeSession::new_runtime_recovery(
        docker,
        view.journal().runtime().ok_or(REFUSED)?,
        inputs,
    )?;
    require(
        session.model() == &saved.model
            && session.configuration_sha256() == saved.configuration_sha256,
    )?;
    let resources = session.observe_resources()?;
    require(saved.receipt.resources.as_ref() == Some(&resources))?;
    let rows = session.status()?;
    require(rows.iter().all(|row| {
        row["Service"].as_str().is_some_and(|role| {
            resources.containers.get(role).is_some_and(|container| {
                !container.setup || row["State"] == "exited" || row["State"] == "created"
            })
        })
    }))?;
    let selector = view.diagnostic_record(installer_generation_maintenance::SELECTOR, true)?;
    view.require_unchanged()?;
    Ok(Transition {
        session_sha256: digest(&saved)?,
        generation_selector_sha256: selector.as_deref().map(release::sha256),
        resources_sha256: digest(&resources)?,
    })
}

fn release_order(tag: &str) -> Result<(u64, u64, u64, bool, u64, u64)> {
    release::release_tier(tag)?;
    let (base, nightly) = tag
        .strip_prefix('v')
        .ok_or(REFUSED)?
        .split_once("-nightly.")
        .map_or((tag.strip_prefix('v').ok_or(REFUSED)?, None), |(a, b)| {
            (a, Some(b))
        });
    let numbers: Vec<u64> = base
        .split('.')
        .map(|s| s.parse().map_err(|_| REFUSED))
        .collect::<std::result::Result<_, _>>()?;
    require(numbers.len() == 3)?;
    let (date, run) = if let Some(nightly) = nightly {
        let (date, run) = nightly.split_once('.').ok_or(REFUSED)?;
        (
            date.parse().map_err(|_| REFUSED)?,
            run.parse().map_err(|_| REFUSED)?,
        )
    } else {
        (0, 0)
    };
    Ok((
        numbers[0],
        numbers[1],
        numbers[2],
        nightly.is_none(),
        date,
        run,
    ))
}

fn validate_intent(
    intent: &Intent,
    base: &Retained,
    previous: Option<&Selector>,
    predecessor: &Operator,
) -> Result<()> {
    require(
        intent.schema == "elevenid.installer-operator-upgrade-intent/v1"
            && (1..=MAX_ATTEMPTS).contains(&intent.sequence)
            && &intent.retained == base
            && intent.previous.as_ref() == previous
            && intent.compatibility == contract()
            && intent.target.sha256 != predecessor.sha256
            && intent.target.source_sha != predecessor.source_sha
            && release_order(&intent.target.release_tag)?
                > release_order(&predecessor.release_tag)?
            && intent
                .assets
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
                == ASSETS.into_iter().collect()
            && intent.assets.values().all(|s| valid_sha(s))
            && valid_sha(&intent.target.sha256)
            && valid_sha(&intent.target.inventory_sha256)
            && valid_sha(&intent.target.admission_sha256)
            && intent.target.size > 0
            && intent.target.size <= 536870912
            && intent.docker.is_absolute()
            && !intent.unit_files.is_empty(),
    )?;
    require(
        intent.assets["installer-inventory.json"] == intent.target.inventory_sha256
            && intent.assets["installer-admission.json"] == intent.target.admission_sha256,
    )
}
fn valid_sha(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn staged_for(intent: &Intent) -> Result<Staged> {
    Ok(Staged {
        schema: "elevenid.installer-operator-staged/v1".into(),
        sequence: intent.sequence,
        intent_sha256: digest(intent)?,
        operator_sha256: intent.target.sha256.clone(),
        units_sha256: digest(&intent.unit_files)?,
        selected: false,
    })
}
fn selected_for(intent: &Intent, staged: &Staged) -> Result<Selector> {
    Ok(Selector {
        schema: "elevenid.installer-operator-owner/v1".into(),
        installation_id: intent.retained.installation_id,
        sequence: intent.sequence,
        intent_sha256: digest(intent)?,
        staged_sha256: digest(staged)?,
    })
}
fn terminal_for(intent: &Intent, phase: &str, selector: Option<&Selector>) -> Result<Terminal> {
    Ok(Terminal {
        schema: format!("elevenid.installer-operator-{phase}/v1"),
        sequence: intent.sequence,
        intent_sha256: digest(intent)?,
        selector_sha256: selector.map(digest).transpose()?,
    })
}

fn operator_directory(installation: &Path, operator: &Operator, create: bool) -> Result<Directory> {
    Directory::open(installation)?
        .child("operators", create)?
        .child(&operator.sha256, create)
}
fn verify_staged(installation: &Path, intent: &Intent) -> Result<()> {
    let directory = operator_directory(installation, &intent.target, false)?;
    directory.verify_operator(&intent.target)?;
    for (name, expected) in &intent.assets {
        require(
            directory
                .read(name, MAX_RECORD, 0o600)?
                .is_some_and(|b| release::sha256(&b) == *expected),
        )?;
    }
    let admitted = target_from(
        &directory
            .read("installer-admission.json", MAX_RECORD, 0o600)?
            .ok_or(REFUSED)?,
        &directory
            .read("installer-inventory.json", MAX_RECORD, 0o600)?
            .ok_or(REFUSED)?,
        &intent.target.sha256,
        &intent.target.source_sha,
        &intent.target.release_tag,
    )?;
    require(admitted == intent.target)?;
    let units = directory.child(&format!("units-{:04}", intent.sequence), false)?;
    require(units.names()? == intent.unit_files.keys().cloned().collect())?;
    for (name, expected) in &intent.unit_files {
        require(
            units
                .read(name, 65536, 0o600)?
                .is_some_and(|b| release::sha256(&b) == *expected),
        )?;
    }
    directory.require()
}

fn history(view: &LockedInspection, installation: &Path) -> Result<History> {
    view.require_path_binding(installation)?;
    if !Directory::open(installation)?.names()?.contains("evidence") {
        return Ok(History {
            attempts: Vec::new(),
            selector: None,
            selector_bytes: None,
            incomplete_intent: None,
        });
    }
    let evidence = Directory::open(&installation.join("evidence"))?;
    let names = evidence.names()?;
    let selector_bytes = evidence.read(SELECTOR, MAX_RECORD, 0o600)?;
    let selector: Option<Selector> = selector_bytes.as_deref().map(decode).transpose()?;
    let has_records = names
        .iter()
        .any(|n| n.starts_with("operator-upgrade-") || n.starts_with("partial-operator-upgrade-"));
    if !has_records {
        require(selector.is_none())?;
        return Ok(History {
            attempts: Vec::new(),
            selector,
            selector_bytes,
            incomplete_intent: None,
        });
    }
    let base = retained(view, installation)?;
    let mut attempts = Vec::new();
    let mut previous: Option<Selector> = None;
    let mut predecessor = base.original_operator.clone();
    let mut allowed = BTreeSet::new();
    let mut pending = false;
    let mut incomplete_intent = None;
    for sequence in 1..=MAX_ATTEMPTS {
        let Some(bytes) = evidence.read(&record(sequence, "intent"), MAX_RECORD, 0o600)? else {
            let partial = format!("partial-{}", record(sequence, "intent"));
            if evidence.read_partial(&partial, MAX_RECORD)?.is_some() {
                require(!pending)?;
                incomplete_intent = Some(sequence);
                allowed.insert(partial);
            }
            break;
        };
        require(!pending)?;
        let intent: Intent = decode(&bytes)?;
        require(intent.sequence == sequence && encode(&intent)? == bytes)?;
        validate_intent(&intent, &base, previous.as_ref(), &predecessor)?;
        for kind in ["intent", "staged", "activation", "complete", "canceled"] {
            allowed.insert(record(sequence, kind));
        }
        allowed.insert(format!("operator-upgrade-{sequence:04}-selector.tmp"));
        allowed.insert(format!(
            "partial-operator-upgrade-{sequence:04}-selector.tmp"
        ));
        allowed.extend(
            ["intent", "staged", "activation", "complete", "canceled"]
                .into_iter()
                .map(|k| format!("partial-{}", record(sequence, k))),
        );
        let staged: Option<Staged> = evidence
            .read(&record(sequence, "staged"), MAX_RECORD, 0o600)?
            .as_deref()
            .map(decode)
            .transpose()?;
        if let Some(staged) = &staged {
            require(staged == &staged_for(&intent)?)?;
            verify_staged(installation, &intent)?;
        }
        let activation = evidence.read(&record(sequence, "activation"), MAX_RECORD, 0o600)?;
        if let Some(bytes) = &activation {
            require(
                staged.is_some()
                    && decode::<Terminal>(bytes)?
                        == terminal_for(&intent, "activation-requested", None)?,
            )?;
        }
        let completed = evidence.read(&record(sequence, "complete"), MAX_RECORD, 0o600)?;
        let canceled = evidence.read(&record(sequence, "canceled"), MAX_RECORD, 0o600)?;
        require(completed.is_none() || canceled.is_none())?;
        let expected = staged
            .as_ref()
            .map(|s| selected_for(&intent, s))
            .transpose()?;
        if let Some(bytes) = &completed {
            require(
                activation.is_some()
                    && decode::<Terminal>(bytes)?
                        == terminal_for(&intent, "selection-complete", expected.as_ref())?,
            )?;
            previous = expected;
            predecessor = intent.target.clone();
        } else if let Some(bytes) = &canceled {
            require(
                activation.is_none()
                    && decode::<Terminal>(bytes)? == terminal_for(&intent, "canceled", None)?,
            )?;
        } else {
            pending = true;
        }
        attempts.push(Attempt {
            intent,
            staged,
            activation: activation.is_some(),
            completed: completed.is_some(),
            canceled: canceled.is_some(),
        });
    }
    require(!attempts.is_empty() || incomplete_intent.is_some())?;
    require(
        names
            .iter()
            .filter(|n| {
                n.starts_with("operator-upgrade-") || n.starts_with("partial-operator-upgrade-")
            })
            .all(|n| allowed.contains(n)),
    )?;
    let pending_selector = attempts
        .last()
        .filter(|a| a.activation && !a.completed && !a.canceled)
        .map(|a| selected_for(&a.intent, a.staged.as_ref().ok_or(REFUSED)?))
        .transpose()?;
    require(selector == previous || (pending_selector.is_some() && selector == pending_selector))?;
    view.require_unchanged()?;
    Ok(History {
        attempts,
        selector,
        selector_bytes,
        incomplete_intent,
    })
}

fn persist(
    state: &mut LockedMaintenance,
    installation: &Path,
    name: &str,
    bytes: &[u8],
) -> Result<()> {
    state.with_atomic_publication(|view| {
        view.require_path_binding(installation)?;
        Directory::open(&installation.join("evidence"))?.publish(name, bytes, 0o600)?;
        view.require_path_binding(installation)
    })
}

struct Authenticated {
    target: Operator,
    assets: BTreeMap<String, Vec<u8>>,
    executable: PathBuf,
}
fn authenticate(
    view: &LockedInspection,
    installation: &Path,
    assets: &Path,
    tools: &VerificationTools,
    build: &str,
) -> Result<Authenticated> {
    let original = retained(view, installation)?;
    let verify = |directory: &Path, expected: &Operator| -> Result<()> {
        let admission_path = directory.join("installer-admission.json");
        let inventory_path = directory.join("installer-inventory.json");
        let admission_bytes = installer_verify::read_private_record(&admission_path)?;
        let inventory_bytes = installer_verify::read_private_record(&inventory_path)?;
        require(
            target_from(
                &admission_bytes,
                &inventory_bytes,
                &expected.sha256,
                &expected.source_sha,
                &expected.release_tag,
            )? == *expected,
        )?;
        let admission = release::parse_admission(&admission_bytes)?;
        let inventory = release::parse_inventory(&inventory_bytes)?;
        require(
            tools.verify(
                &admission_path,
                release::PROMOTION_WORKFLOW,
                &admission.promotion_source_sha,
                admission.promotion_run_id,
                admission.promotion_run_attempt,
            )? == expected.admission_sha256,
        )?;
        require(
            tools.verify(
                &inventory_path,
                release::build_workflow(&expected.release_tag)?,
                &expected.source_sha,
                inventory.build_run_id,
                inventory.build_run_attempt,
            )? == expected.inventory_sha256,
        )
    };
    verify(&installation.join("evidence"), &original.original_operator)?;
    let (source, tag) = build.split_once(':').ok_or(REFUSED)?;
    let executable = std::env::current_exe().map_err(|_| REFUSED)?;
    let records = ASSETS
        .into_iter()
        .map(|name| {
            Ok((
                name.into(),
                installer_verify::read_private_bytes(&assets.join(name), 1048576)?,
            ))
        })
        .collect::<Result<BTreeMap<String, Vec<u8>>>>()?;
    let target = target_from(
        &records["installer-admission.json"],
        &records["installer-inventory.json"],
        &installer_verify::operator_digest(&executable)?,
        source,
        tag,
    )?;
    verify(assets, &target)?;
    // Retain the complete proof closure that was present during admission.
    // A later replacement of either sidecar cannot become the staged evidence.
    for (name, before) in &records {
        require(installer_verify::read_private_bytes(&assets.join(name), 1048576)? == *before)?;
    }
    view.require_unchanged()?;
    Ok(Authenticated {
        target,
        assets: records,
        executable,
    })
}

fn predecessor_units(base: &Retained, history: &History) -> BTreeSet<String> {
    let mut names: BTreeSet<String> =
        crate::installer_lifecycle::operator_unit_names(base.installation_id, None)
            .into_iter()
            .collect();
    for attempt in history.attempts.iter().filter(|a| a.completed) {
        names.extend(attempt.intent.unit_files.keys().cloned());
    }
    names
}
fn require_quiescent(installation: &Path, names: &BTreeSet<String>) -> Result<()> {
    let observed =
        crate::installer_runtime::observe_operator_predecessor_units(installation, names)?;
    require(observed.len() == names.len() && observed.values().all(|v| v.quiescent()))
}

fn stage_files(
    state: &mut LockedMaintenance,
    intent: &Intent,
    authenticated: &Authenticated,
    units: &BTreeMap<String, String>,
) -> Result<()> {
    let installation = &intent.retained.installation;
    require(
        authenticated.target == intent.target
            && units
                .iter()
                .map(|(k, v)| (k.clone(), release::sha256(v.as_bytes())))
                .collect::<BTreeMap<_, _>>()
                == intent.unit_files,
    )?;
    state.with_atomic_publication(|view| {
        view.require_path_binding(installation)?;
        let directory = operator_directory(installation, &intent.target, true)?;
        for (name, bytes) in &authenticated.assets {
            require(intent.assets.get(name) == Some(&release::sha256(bytes)))?;
            directory.publish(name, bytes, 0o600)?;
        }
        directory.copy_operator(&authenticated.executable, &intent.target)?;
        let output = directory.child(&format!("units-{:04}", intent.sequence), true)?;
        for (name, text) in units {
            output.publish(name, text.as_bytes(), 0o600)?;
        }
        verify_staged(installation, intent)?;
        view.require_path_binding(installation)
    })?;
    persist(
        state,
        installation,
        &record(intent.sequence, "staged"),
        &encode(&staged_for(intent)?)?,
    )
}

fn activate(
    state: &mut LockedMaintenance,
    intent: &Intent,
    history: &History,
    reconcile: bool,
) -> Result<()> {
    let installation = &intent.retained.installation;
    require(
        retained(state.inspection(), installation)? == intent.retained
            && transition(state.inspection(), installation, &intent.docker)? == intent.transition,
    )?;
    verify_staged(installation, intent)?;
    let names = predecessor_units(&intent.retained, history);
    select_with(state, intent, history, reconcile, || {
        require_quiescent(installation, &names)
    })
}

fn select_with(
    state: &mut LockedMaintenance,
    intent: &Intent,
    history: &History,
    reconcile: bool,
    mut quiescent: impl FnMut() -> Result<()>,
) -> Result<()> {
    let installation = &intent.retained.installation;
    let staged = staged_for(intent)?;
    let next = selected_for(intent, &staged)?;
    let next_bytes = encode(&next)?;
    let previous_bytes = intent.previous.as_ref().map(encode).transpose()?;
    let selected = history.selector_bytes.as_deref();
    require(
        selected == previous_bytes.as_deref()
            || (reconcile && selected == Some(next_bytes.as_slice())),
    )?;
    quiescent()?;
    if !history.attempts.last().ok_or(REFUSED)?.activation {
        persist(
            state,
            installation,
            &record(intent.sequence, "activation"),
            &encode(&terminal_for(intent, "activation-requested", None)?)?,
        )?;
    }
    // No swallowed systemctl failure can establish quiescence. Observe under
    // the same installation lock immediately before the atomic selection.
    state.with_atomic_publication(|view| {
        view.require_path_binding(installation)?;
        let evidence = Directory::open(&installation.join("evidence"))?;
        if selected != Some(next_bytes.as_slice()) {
            private::replace_selector(
                &evidence,
                previous_bytes.as_deref(),
                &next_bytes,
                intent.sequence,
                |boundary| {
                    if boundary == 1 {
                        quiescent()?;
                    }
                    Ok(())
                },
            )?;
        } else {
            require(
                evidence.read(SELECTOR, MAX_RECORD, 0o600)?.as_deref()
                    == Some(next_bytes.as_slice()),
            )?;
            private::reconcile_selector_temporary(
                &evidence,
                intent.sequence,
                previous_bytes.as_deref(),
            )?;
        }
        view.require_path_binding(installation)
    })?;
    persist(
        state,
        installation,
        &record(intent.sequence, "complete"),
        &encode(&terminal_for(intent, "selection-complete", Some(&next))?)?,
    )
}

/// Resolve the complete private owner chain. Historical product/session
/// authority remains anchored to the original installation, never the target's
/// product images. Normal credential successors retain their existing owner.
pub(crate) fn require_selected_caller(view: &LockedInspection, installation: &Path) -> Result<()> {
    let history = history(view, installation)?;
    require(history.pending_sequence().is_none())?;
    if let Some(selected) = history.selected() {
        let expected = selected.intent.target.path(installation);
        require(
            std::env::current_exe().map_err(|_| REFUSED)? == expected
                && installer_verify::current_operator_digest()? == selected.intent.target.sha256,
        )?;
        installer_doctor::load_session(view, installation)?;
        let predecessors = History {
            attempts: history
                .attempts
                .iter()
                .filter(|a| a.intent.sequence < selected.intent.sequence)
                .cloned()
                .collect(),
            selector: None,
            selector_bytes: None,
            incomplete_intent: None,
        };
        require_quiescent(
            installation,
            &predecessor_units(&selected.intent.retained, &predecessors),
        )?;
    }
    Ok(())
}

pub(crate) fn selected_unit_exports(
    view: &LockedInspection,
    installation: &Path,
) -> Result<BTreeMap<String, String>> {
    let history = history(view, installation)?;
    require(history.pending_sequence().is_none())?;
    let selected = history.selected().ok_or(REFUSED)?;
    let units = operator_directory(installation, &selected.intent.target, false)?
        .child(&format!("units-{:04}", selected.intent.sequence), false)?;
    selected
        .intent
        .unit_files
        .keys()
        .map(|name| {
            let bytes = units.read(name, 65536, 0o600)?.ok_or(REFUSED)?;
            Ok((name.clone(), String::from_utf8(bytes).map_err(|_| REFUSED)?))
        })
        .collect()
}

pub fn status_locked(view: &LockedInspection, installation: &Path) -> Result<Value> {
    let history = history(view, installation)?;
    let selected = history.selected();
    let pending = history.pending();
    let phase = if history.incomplete_intent.is_some() {
        "intent_incomplete"
    } else if let Some(pending) = pending {
        if pending.activation {
            "selection_pending"
        } else if pending.staged.is_some() {
            "staged"
        } else {
            "staging_incomplete"
        }
    } else if selected.is_some() {
        "selected"
    } else {
        "original"
    };
    let selected_operator = selected.filter(|a| a.completed).map(|a| json!({"sequence":a.intent.sequence,
        "operator":a.intent.target,"entrypoint":a.intent.target.path(installation),
        "unit_directory":installation.join("operators").join(&a.intent.target.sha256).join(format!("units-{:04}",a.intent.sequence)),
        "units":a.intent.unit_files}));
    Ok(
        json!({"schema":"elevenid.installer-operator-status/v1", "phase":phase,
        "original_product_release":view.journal().identity(), "selected_operator":selected_operator,
        "pending_sequence":history.pending_sequence(), "selector_observed":history.selector,
        "runtime_activated":false, "runtime_observed":false, "scheduler_activation":"not_assessed",
        "boot_recovery_qualification":"not_assessed", "product_changed":false,
        "historical_operator_preserved":true, "historical_units_retargeted":false}),
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Action {
    Stage,
    Activate,
    Reconcile,
    Cancel,
    Status,
}
struct Arguments {
    action: Action,
    installation: PathBuf,
    assets: Option<PathBuf>,
    tools: Option<PathBuf>,
    gh: Option<PathBuf>,
    docker: PathBuf,
    sequence: Option<u64>,
}
fn arguments(args: &[String]) -> Result<Arguments> {
    let action = match args.first().map(String::as_str) {
        Some("stage")=>Action::Stage, Some("activate")=>Action::Activate, Some("reconcile")=>Action::Reconcile,
        Some("cancel")=>Action::Cancel, Some("status")=>Action::Status,
        _=>return Err("usage: operator-upgrade stage|activate|reconcile|cancel|status --install-dir ABS [--target-assets ABS --tools-dir ABS --gh-bin ABS --docker-bin ABS] [--sequence N]".into()),
    };
    require((args.len() - 1).is_multiple_of(2))?;
    let mut values = BTreeMap::new();
    for pair in args[1..].chunks_exact(2) {
        require(
            [
                "--install-dir",
                "--target-assets",
                "--tools-dir",
                "--gh-bin",
                "--docker-bin",
                "--sequence",
            ]
            .contains(&pair[0].as_str())
                && values.insert(pair[0].as_str(), pair[1].as_str()).is_none(),
        )?;
    }
    let path = |name: &str| -> Result<Option<PathBuf>> {
        values
            .get(name)
            .map(|s| {
                let p = PathBuf::from(s);
                require(p.is_absolute() && !s.chars().any(char::is_control))?;
                Ok(p)
            })
            .transpose()
    };
    let installation = path("--install-dir")?.ok_or(REFUSED)?;
    let assets = path("--target-assets")?;
    let tools = path("--tools-dir")?;
    let gh = path("--gh-bin")?;
    let docker = path("--docker-bin")?.unwrap_or_else(|| PathBuf::from("/usr/bin/docker"));
    let sequence = values
        .get("--sequence")
        .map(|s| s.parse::<u64>().map_err(|_| REFUSED))
        .transpose()?;
    require(sequence.is_none_or(|n| (1..=MAX_ATTEMPTS).contains(&n)))?;
    if action == Action::Status {
        require(values.len() == 1)?;
    } else if action == Action::Cancel {
        require(values.len() == 2 && sequence.is_some())?;
    } else {
        require(
            assets.is_some()
                && tools.is_some()
                && gh.is_some()
                && (sequence.is_none() == (action == Action::Stage)),
        )?;
    }
    Ok(Arguments {
        action,
        installation,
        assets,
        tools,
        gh,
        docker,
        sequence,
    })
}

fn authenticated_attempt(
    intent: &Intent,
    authenticated: &Authenticated,
    docker: &Path,
) -> Result<()> {
    require(
        authenticated.target == intent.target
            && docker == intent.docker
            && authenticated
                .assets
                .iter()
                .map(|(k, v)| (k.clone(), release::sha256(v)))
                .collect::<BTreeMap<_, _>>()
                == intent.assets,
    )
}

fn reconcile_completed(
    view: &LockedInspection,
    installation: &Path,
    history: &History,
    sequence: u64,
    authenticated: &Authenticated,
    docker: &Path,
) -> Result<()> {
    require(history.pending_sequence().is_none())?;
    let selected = history.selected().ok_or(REFUSED)?;
    require(
        selected.completed
            && selected.intent.sequence == sequence
            && retained(view, installation)? == selected.intent.retained,
    )?;
    authenticated_attempt(&selected.intent, authenticated, docker)?;
    // A lost final response is observed without republishing the selector or
    // replaying activation. Later credential generations may already have
    // advanced the transition snapshot; the durable completed owner remains.
    verify_staged(installation, &selected.intent)
}

pub fn run(args: &[String], build_identity: &str) -> Result<String> {
    let args = arguments(args)?;
    let mut state = LockedMaintenance::open(&args.installation)?;
    if args.action == Action::Status {
        return serde_json::to_string(&status_locked(state.inspection(), &args.installation)?)
            .map_err(|_| REFUSED.into());
    }
    crate::installer_command::require_rootless_process()?;
    require(cfg!(target_arch = "x86_64"))?;
    let history = history(state.inspection(), &args.installation)?;
    if args.action == Action::Cancel {
        let pending = history.pending().ok_or(REFUSED)?;
        require(
            Some(pending.intent.sequence) == args.sequence
                && !pending.activation
                && history.selector == pending.intent.previous,
        )?;
        persist(
            &mut state,
            &args.installation,
            &record(pending.intent.sequence, "canceled"),
            &encode(&terminal_for(&pending.intent, "canceled", None)?)?,
        )?;
    } else {
        let tools = VerificationTools::new(
            args.tools.as_deref().ok_or(REFUSED)?,
            args.gh.as_deref().ok_or(REFUSED)?,
        )?;
        let authenticated = authenticate(
            state.inspection(),
            &args.installation,
            args.assets.as_deref().ok_or(REFUSED)?,
            &tools,
            build_identity,
        )?;
        if args.action == Action::Stage
            || (args.action == Action::Reconcile && history.incomplete_intent == args.sequence)
        {
            require(history.pending().is_none())?;
            require(args.action != Action::Stage || history.incomplete_intent.is_none())?;
            let sequence = u64::try_from(history.attempts.len())
                .map_err(|_| REFUSED)?
                .checked_add(1)
                .ok_or(REFUSED)?;
            require(sequence <= MAX_ATTEMPTS)?;
            let base = retained(state.inspection(), &args.installation)?;
            require_quiescent(&args.installation, &predecessor_units(&base, &history))?;
            let units = crate::installer_lifecycle::successor_unit_exports(
                state.inspection(),
                &args.installation,
                &args.docker,
                &authenticated.target.path(&args.installation),
                sequence,
            )?;
            let intent = Intent {
                schema: "elevenid.installer-operator-upgrade-intent/v1".into(),
                sequence,
                transition: transition(state.inspection(), &args.installation, &args.docker)?,
                retained: base.clone(),
                previous: history.selector.clone(),
                target: authenticated.target.clone(),
                assets: authenticated
                    .assets
                    .iter()
                    .map(|(k, v)| (k.clone(), release::sha256(v)))
                    .collect(),
                compatibility: contract(),
                docker: args.docker.clone(),
                unit_files: units
                    .iter()
                    .map(|(k, v)| (k.clone(), release::sha256(v.as_bytes())))
                    .collect(),
            };
            validate_intent(
                &intent,
                &base,
                history.selector.as_ref(),
                history
                    .selected()
                    .map(|a| &a.intent.target)
                    .unwrap_or(&base.original_operator),
            )?;
            persist(
                &mut state,
                &args.installation,
                &record(sequence, "intent"),
                &encode(&intent)?,
            )?;
            stage_files(&mut state, &intent, &authenticated, &units)?;
        } else if args.action == Action::Reconcile && history.pending_sequence().is_none() {
            reconcile_completed(
                state.inspection(),
                &args.installation,
                &history,
                args.sequence.ok_or(REFUSED)?,
                &authenticated,
                &args.docker,
            )?;
        } else {
            let pending = history.pending().ok_or(REFUSED)?;
            let intent = &pending.intent;
            require(Some(intent.sequence) == args.sequence)?;
            authenticated_attempt(intent, &authenticated, &args.docker)?;
            require(
                retained(state.inspection(), &args.installation)? == intent.retained
                    && transition(state.inspection(), &args.installation, &intent.docker)?
                        == intent.transition,
            )?;
            if args.action == Action::Reconcile && pending.staged.is_none() {
                require(!pending.activation)?;
                let units = crate::installer_lifecycle::successor_unit_exports(
                    state.inspection(),
                    &args.installation,
                    &intent.docker,
                    &intent.target.path(&args.installation),
                    intent.sequence,
                )?;
                stage_files(&mut state, intent, &authenticated, &units)?;
            } else if args.action == Action::Activate || pending.activation {
                require(pending.staged.is_some())?;
                activate(
                    &mut state,
                    intent,
                    &history,
                    args.action == Action::Reconcile,
                )?;
            } else {
                verify_staged(&args.installation, intent)?;
            }
        }
    }
    state.require_unchanged()?;
    serde_json::to_string(&status_locked(state.inspection(), &args.installation)?)
        .map_err(|_| REFUSED.into())
}

#[cfg(test)]
#[path = "installer_operator_upgrade_tests.rs"]
mod tests;
