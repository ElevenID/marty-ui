//! Recurring credential/certificate generations under the installation lock.
//! Immutable evidence binds every producer and native activation. The only
//! replaceable application record is the exact current-generation selector.
#![cfg(target_os = "linux")]

use crate::{
    installer_acme::{self, AcmeCandidate, EnrolmentInputs},
    installer_acme_certificates::RetainedIngressKey,
    installer_acme_configuration::{AcmeEnvironment, BoundAcmeConfiguration},
    installer_compose::{self, ComposeInputs},
    installer_doctor::{self, SavedSession},
    installer_generation_binding::{self as generation, GenerationBinding},
    installer_json, installer_release,
    installer_state::{LockedInspection, LockedMaintenance},
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

type Result<T> = std::result::Result<T, String>;
const REFUSED: &str = "Generation selection or retained transaction differs; preserve its immutable evidence for reconciliation";
pub(crate) const SELECTOR: &str = "application-generation-current.json";
pub(crate) const LAYER: &str = "deploy-config/compose/selfhost-installer/compose.generation.yml";
const KINDS: [&str; 9] = [
    "intent",
    "public-ingress-plan",
    "helper",
    "candidate",
    "binding",
    "activation-intent",
    "activation",
    "session",
    "selection",
];
fn require(value: bool) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}
fn hash(bytes: &[u8]) -> String {
    installer_release::sha256(bytes)
}
fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    serde_json::from_value(installer_json::decode(bytes).map_err(|_| REFUSED)?)
        .map_err(|_| REFUSED.into())
}
fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| REFUSED.into())
}
fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_secs())
        .map_err(|_| REFUSED.into())
}
pub(crate) fn record_name(sequence: u64, kind: &str) -> String {
    format!("generation-{sequence:020}-{kind}.json")
}
pub(crate) fn installation_path(view: &LockedInspection) -> Result<PathBuf> {
    let path = std::fs::read_link(format!(
        "/proc/self/fd/{}",
        view.installation_directory().as_raw_fd()
    ))
    .map_err(|_| REFUSED)?;
    view.require_path_binding(&path)?;
    Ok(path)
}
fn read(installation: &Path, name: &str) -> Result<Vec<u8>> {
    require(!name.contains('/') && !name.contains('\\') && name.len() <= 128)?;
    crate::installer_verify::read_private_bytes(
        &installation.join("evidence").join(name),
        4 * 1024 * 1024,
    )
}
fn optional(installation: &Path, name: &str) -> Result<Option<Vec<u8>>> {
    match std::fs::symlink_metadata(installation.join("evidence").join(name)) {
        Ok(_) => read(installation, name).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(REFUSED.into()),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Selector {
    schema: String,
    installation_id: String,
    engine_id: String,
    sequence: u64,
    selection_sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    schema: String,
    installation_id: String,
    engine_id: String,
    sequence: u64,
    initial_configuration_sha256: String,
    parent_binding_sha256: String,
    evidence_sha256: BTreeMap<String, String>,
    selected_at: u64,
    activated: bool,
    installation_ready: bool,
}
struct Selected {
    selector: Selector,
    selection: Selection,
    evidence: BTreeMap<String, Vec<u8>>,
    binding: GenerationBinding,
    session: SavedSession,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProducerRecord {
    schema: String,
    installation_id: String,
    sequence: u64,
    parent_binding_sha256: String,
    container_id: String,
    create_operation: String,
    created_receipt_sha256: String,
    create_intent_operation: String,
    create_intent_sha256: String,
}
pub(crate) fn require_producer_journal(
    installation: &Path,
    sequence: u64,
    container_id: &str,
    wait_operation: &str,
) -> Result<()> {
    let producer: ProducerRecord =
        decode(&read(installation, &record_name(sequence, "producer"))?)?;
    require(
        producer.schema == "elevenid.installer-generation-producer/v1"
            && producer.sequence == sequence
            && sequence > 0
            && producer.container_id == container_id
            && valid_hash(container_id)
            && valid_hash(&producer.parent_binding_sha256)
            && regex::Regex::new(&format!(
                r"\Ag{sequence:020}-(?:create|observe-created)-[0-9]{{6}}\z"
            ))
            .map_err(|_| REFUSED)?
            .is_match(&producer.create_operation)
            && regex::Regex::new(&format!(r"\Ag{sequence:020}-wait-[0-9]{{6}}\z"))
                .map_err(|_| REFUSED)?
                .is_match(wait_operation),
    )?;
    let created = read(
        installation,
        &format!(
            "generation-compose-{}-result.json",
            producer.create_operation
        ),
    )?;
    require(hash(&created) == producer.created_receipt_sha256)?;
    let receipt: crate::installer_compose::ComposeReceipt = decode(&created)?;
    require(
        regex::Regex::new(&format!(r"\Ag{sequence:020}-create-[0-9]{{6}}\z"))
            .map_err(|_| REFUSED)?
            .is_match(&producer.create_intent_operation),
    )?;
    let create_intent = read(
        installation,
        &format!(
            "generation-compose-{}-intent.json",
            producer.create_intent_operation
        ),
    )?;
    require(
        valid_hash(&producer.create_intent_sha256)
            && hash(&create_intent) == producer.create_intent_sha256,
    )?;
    let create_intent: Value = decode(&create_intent)?;
    require(
        create_intent["schema"] == "elevenid.installer-compose-intent/v1"
            && create_intent["project"] == receipt.project
            && create_intent["engine_id"] == receipt.engine_id
            && create_intent["configuration_sha256"] == receipt.configuration_sha256
            && create_intent["input_files"]
                == serde_json::to_value(&receipt.input_files).map_err(|_| REFUSED)?
            && create_intent["command"]
                == json!([
                    "up",
                    "--no-build",
                    "--pull",
                    "never",
                    "--no-deps",
                    "--no-start",
                    "--force-recreate",
                    "--timeout",
                    "60"
                ])
            && create_intent["selected_services"] == json!(["installer-generation"])
            && create_intent["prior_resources"]["containers"]["installer-generation"]["id"]
                != container_id
            && create_intent["automatic_retry"] == false
            && create_intent["installation_ready"] == false,
    )?;
    let helper = receipt
        .resources
        .as_ref()
        .and_then(|v| v.containers.get("installer-generation"))
        .ok_or(REFUSED)?;
    require(
        receipt.operation == producer.create_operation
            && receipt.command_succeeded
            && receipt.client_exit_code == Some(0)
            && receipt.failure_class.is_none()
            && receipt.observation_validated
            && !receipt.installation_ready
            && receipt.project
                == format!(
                    "marty-install-{}",
                    producer.installation_id.replace('-', "")
                )
            && helper.id == container_id
            && helper.setup
            && receipt.status.iter().any(|row| {
                row["Service"] == "installer-generation"
                    && row["ID"] == container_id
                    && row["State"] == "created"
            }),
    )?;
    let start: Value = decode(&read(
        installation,
        &format!("generation-compose-g{sequence:020}-start-000000-intent.json"),
    )?)?;
    require(
        start["schema"] == "elevenid.installer-compose-intent/v1"
            && start["command"] == json!(["start", "installer-generation"])
            && start["prior_resources"]["containers"]["installer-generation"]["id"] == container_id
            && start["configuration_sha256"] == receipt.configuration_sha256
            && start["input_files"]
                == serde_json::to_value(receipt.input_files).map_err(|_| REFUSED)?
            && start["automatic_retry"] == false
            && start["installation_ready"] == false,
    )
}
fn selected(installation: &Path) -> Result<Option<Selected>> {
    let Some(pointer) = optional(installation, SELECTOR)? else {
        return Ok(None);
    };
    selected_from(installation, &pointer).map(Some)
}
fn selected_from(installation: &Path, pointer: &[u8]) -> Result<Selected> {
    let selector: Selector = decode(pointer)?;
    require(
        selector.schema == "elevenid.installer-application-generation-current/v1"
            && selector.sequence > 0
            && valid_hash(&selector.selection_sha256),
    )?;
    let selection_bytes = read(installation, &record_name(selector.sequence, "selection"))?;
    require(hash(&selection_bytes) == selector.selection_sha256)?;
    let selection: Selection = decode(&selection_bytes)?;
    require(
        selection.schema == "elevenid.installer-generation-selection/v1"
            && selection.sequence == selector.sequence
            && selection.installation_id == selector.installation_id
            && selection.engine_id == selector.engine_id
            && selection.activated
            && !selection.installation_ready
            && selection.selected_at > 0
            && valid_hash(&selection.initial_configuration_sha256)
            && valid_hash(&selection.parent_binding_sha256)
            && selection
                .evidence_sha256
                .keys()
                .map(String::as_str)
                .collect::<std::collections::BTreeSet<_>>()
                == KINDS
                    .into_iter()
                    .filter(|kind| *kind != "selection")
                    .collect(),
    )?;
    let mut evidence = BTreeMap::new();
    for (kind, digest) in &selection.evidence_sha256 {
        let bytes = read(installation, &record_name(selector.sequence, kind))?;
        require(valid_hash(digest) && hash(&bytes) == *digest)?;
        evidence.insert(kind.clone(), bytes);
    }
    evidence.insert("selection".into(), selection_bytes);
    evidence.insert("selector".into(), pointer.to_vec());
    let binding: GenerationBinding = decode(&evidence["binding"])?;
    require(
        binding.sequence() == selector.sequence
            && binding.installation_id == selector.installation_id
            && binding.engine_id == selector.engine_id
            && binding
                .successor
                .as_ref()
                .is_some_and(|v| v.parent_binding_sha256 == selection.parent_binding_sha256),
    )?;
    generation::verify(installation, &binding)?;
    let session: SavedSession = decode(&evidence["session"])?;
    require(
        session.installation_id == selector.installation_id
            && session.inputs.installation == installation
            && session.receipt.engine_id == selector.engine_id
            && session.configuration_sha256 == installer_compose::model_sha256(&session.model)?
            && session.configuration_sha256 == session.receipt.configuration_sha256
            && session.receipt.command_succeeded
            && session.receipt.client_exit_code == Some(0)
            && session.receipt.failure_class.is_none()
            && session.receipt.observation_validated
            && !session.receipt.installation_ready
            && serde_json::to_value(&session.inputs.prior).map_err(|_| REFUSED)?
                == serde_json::to_value(Some(&session.receipt)).map_err(|_| REFUSED)?,
    )?;
    generation::verify_model(
        installation,
        &binding,
        &session.model,
        binding.network_id.as_deref(),
    )?;
    tx::require_activation(installation, selector.sequence, &binding, &session)?;
    installer_compose::verify_input_files(installation, &session.receipt.input_files)?;
    Ok(Selected {
        selector,
        selection,
        evidence,
        binding,
        session,
    })
}
pub(crate) fn require_selection_publication(
    view: &LockedInspection,
    installation: &Path,
    next: &[u8],
) -> Result<()> {
    view.require_path_binding(installation)?;
    let next = selected_from(installation, next)?;
    let initial = installer_doctor::load_initial_session(view, installation)?;
    require(
        next.binding.installation_id == view.journal().installation_id().to_string()
            && next.binding.engine_id == view.journal().runtime().ok_or(REFUSED)?.engine_id
            && next.selection.initial_configuration_sha256 == initial.configuration_sha256,
    )?;
    let old = selected(installation)?;
    let parent = if let Some(old) = old {
        require(old.binding.sequence().checked_add(1) == Some(next.binding.sequence()))?;
        old.binding
    } else {
        generation::load_initial_verified(
            installation,
            &next.binding.installation_id,
            &next.binding.engine_id,
        )?
        .ok_or(REFUSED)?
    };
    require(
        parent.sha256()? == next.selection.parent_binding_sha256
            && parent.sequence().checked_add(1) == Some(next.binding.sequence()),
    )?;
    let metadata = next
        .binding
        .public_ingress_metadata(installation)?
        .ok_or(REFUSED)?;
    metadata.validate_selected_at(
        &next
            .binding
            .read(installation, "installer_ingress_tls_cert")?,
        now()?,
    )?;
    tx::require_candidate_fresh(installation, &next.binding, now()?)?;
    view.require_unchanged()
}
pub(crate) fn load_selected_binding(
    installation: &Path,
    id: &str,
    engine: &str,
) -> Result<Option<GenerationBinding>> {
    selected(installation)?
        .map(|value| {
            require(value.binding.installation_id == id && value.binding.engine_id == engine)?;
            Ok(value.binding)
        })
        .transpose()
}
pub(crate) fn selected_evidence(
    installation: &Path,
    binding: &GenerationBinding,
) -> Result<BTreeMap<String, String>> {
    let selected = selected(installation)?.ok_or(REFUSED)?;
    require(selected.binding == *binding)?;
    Ok(selected
        .evidence
        .into_iter()
        .map(|(kind, bytes)| {
            (
                if kind == "selector" {
                    SELECTOR.into()
                } else {
                    record_name(binding.sequence(), &kind)
                },
                hash(&bytes),
            )
        })
        .collect())
}
pub(crate) fn current_session(
    view: &LockedInspection,
    installation: &Path,
) -> Result<Option<SavedSession>> {
    view.require_path_binding(installation)?;
    let Some(selected) = selected(installation)? else {
        return Ok(None);
    };
    let initial = installer_doctor::load_initial_session(view, installation)?;
    require(
        selected.binding.installation_id == view.journal().installation_id().to_string()
            && selected.binding.engine_id == view.journal().runtime().ok_or(REFUSED)?.engine_id
            && selected.selection.initial_configuration_sha256 == initial.configuration_sha256
            && selected.session.inputs.approved_images == initial.inputs.approved_images
            && selected.session.inputs.project == initial.inputs.project,
    )?;
    view.require_unchanged()?;
    Ok(Some(selected.session))
}
pub(crate) fn require_lineage(
    view: &LockedInspection,
    installation: &Path,
    initial_sha: &str,
) -> Result<()> {
    view.require_path_binding(installation)?;
    let initial = installer_doctor::load_initial_session(view, installation)?;
    require(initial.configuration_sha256 == initial_sha)?;
    if let Some(selected) = selected(installation)? {
        require(selected.selection.initial_configuration_sha256 == initial_sha)?;
        let parent = generation::load_sequence(installation, selected.binding.sequence() - 1)?;
        require(parent.sha256()? == selected.selection.parent_binding_sha256)?;
    }
    view.require_unchanged()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PermitData {
    schema: String,
    installation_id: String,
    environment: AcmeEnvironment,
    cycle: u64,
    prior_cycle: u64,
    prior_candidate: Value,
    configuration_sha256: String,
    generation_sequence: u64,
    generation_binding_sha256: String,
    initial_configuration_sha256: String,
    schedule_sha256: String,
    created_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    terminal_predecessor: Option<installer_acme::TerminalRetryEvidence>,
}
/// Constructible only by a retained due decision under the generation owner.
#[derive(Clone, Debug)]
pub(crate) struct RenewalPermit {
    data: PermitData,
    prior: AcmeCandidate,
    digest: String,
}
impl RenewalPermit {
    pub(crate) fn record_name(cycle: u64) -> String {
        format!("generation-acme-{cycle:020}-intent.json")
    }
    pub(crate) fn cycle(&self) -> u64 {
        self.data.cycle
    }
    pub(crate) fn prior_candidate(&self) -> &AcmeCandidate {
        &self.prior
    }
    pub(crate) fn configuration_sha256(&self) -> &str {
        &self.data.configuration_sha256
    }
    pub(crate) fn generation_binding_sha256(&self) -> &str {
        &self.data.generation_binding_sha256
    }
    pub(crate) fn schedule_sha256(&self) -> &str {
        &self.data.schedule_sha256
    }
    pub(crate) fn sha256(&self) -> &str {
        &self.digest
    }
    pub(crate) fn created_at(&self) -> u64 {
        self.data.created_at
    }
    pub(crate) fn load(view: &LockedInspection, cycle: u64) -> Result<Self> {
        let bytes = view.read_evidence(&Self::record_name(cycle))?;
        let data: PermitData = decode(&bytes)?;
        require(
            data.schema == "elevenid.installer-generation-acme-intent/v1"
                && data.cycle == cycle
                && cycle > 0
                && data.prior_cycle < cycle
                && data.environment == AcmeEnvironment::Production
                && data.installation_id == view.journal().installation_id().to_string()
                && data.created_at > 0
                && [
                    &data.configuration_sha256,
                    &data.generation_binding_sha256,
                    &data.initial_configuration_sha256,
                    &data.schedule_sha256,
                ]
                .into_iter()
                .all(|v| valid_hash(v)),
        )?;
        let prior = installer_acme::retained_candidate(view, data.environment, data.prior_cycle)?;
        require(serde_json::to_value(&prior).map_err(|_| REFUSED)? == data.prior_candidate)?;
        if let Some(terminal) = &data.terminal_predecessor {
            require(terminal.cycle() > data.prior_cycle && terminal.cycle() < data.cycle)?;
            installer_acme::require_terminal_retry_evidence(
                view,
                &installation_path(view)?,
                data.environment,
                &prior,
                terminal,
                data.created_at,
            )?;
        }
        Ok(Self {
            data,
            prior,
            digest: hash(&bytes),
        })
    }
    pub(crate) fn require_current(
        &self,
        view: &LockedInspection,
        installation: &Path,
        inputs: &ComposeInputs,
        configuration: &BoundAcmeConfiguration,
        ingress: &RetainedIngressKey,
    ) -> Result<()> {
        crate::installer_lifecycle::require_recorded_running_intent(view, installation)?;
        let retained = Self::load(view, self.cycle())?;
        require(
            retained.digest == self.digest
                && hash(&encode(configuration)?) == self.data.configuration_sha256,
        )?;
        crate::installer_acme_renewal::require_due_evidence(
            view,
            &self.prior,
            self.schedule_sha256(),
            self.created_at(),
        )?;
        require_lineage(view, installation, &self.data.initial_configuration_sha256)?;
        let saved = current_session(view, installation)?
            .map(Ok)
            .unwrap_or_else(|| installer_doctor::load_initial_session(view, installation))?;
        require(
            serde_json::to_value(&saved.inputs).map_err(|_| REFUSED)?
                == serde_json::to_value(inputs).map_err(|_| REFUSED)?,
        )?;
        let binding = generation::load_verified(
            installation,
            &self.data.installation_id,
            &saved.receipt.engine_id,
        )?
        .ok_or(REFUSED)?;
        let original = generation::load_sequence(installation, self.data.generation_sequence)?;
        let metadata = binding
            .public_ingress_metadata(installation)?
            .ok_or(REFUSED)?;
        require(
            original.sha256()? == self.data.generation_binding_sha256
                && binding.sequence() >= original.sequence()
                && metadata.enrolment_receipt_sha256 == self.prior.enrolment_receipt_sha256()
                && metadata.certificate_admission == *self.prior.metadata()
                && metadata.key_name == ingress.transit_key_name()
                && metadata.key_version == ingress.key_version(),
        )?;
        view.require_unchanged()
    }
    pub(crate) fn require_worker(
        &self,
        view: &LockedInspection,
        inputs: &EnrolmentInputs<'_>,
    ) -> Result<()> {
        let saved = current_session(view, inputs.installation)?
            .map(Ok)
            .unwrap_or_else(|| installer_doctor::load_initial_session(view, inputs.installation))?;
        self.require_current(
            view,
            inputs.installation,
            &saved.inputs,
            inputs.configuration,
            inputs.ingress_key,
        )
    }
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct RetirementGenerations {
    pub installation_id: String,
    pub engine_id: String,
    pub current_generation_sha256: String,
    pub rollback_generation_sha256: String,
    pub current_helper_receipt_sha256: String,
    pub rollback_helper_receipt_sha256: String,
    pub selected_session_sha256: String,
    pub configuration_sha256: String,
    pub activation_receipt_sha256: String,
    pub selection_receipt_sha256: String,
    pub public_renewal_enrollment_sha256: String,
    pub public_identity_sha256: BTreeMap<String, String>,
}
pub(crate) fn retirement_view(
    view: &LockedInspection,
    installation: &Path,
) -> Result<Option<RetirementGenerations>> {
    view.require_path_binding(installation)?;
    let Some(selected) = selected(installation)? else {
        return Ok(None);
    };
    let parent = generation::load_sequence(installation, selected.binding.sequence() - 1)?;
    let renewal: Value = decode(&view.read_evidence("renewal-result.json")?)?;
    let previous_helper = if parent.sequence() == 0 {
        read(
            installation,
            "compose-setup-installer-generation-result.json",
        )?
    } else {
        read(installation, &record_name(parent.sequence(), "helper"))?
    };
    require_lineage(
        view,
        installation,
        &selected.selection.initial_configuration_sha256,
    )?;
    Ok(Some(RetirementGenerations {
        installation_id: selected.binding.installation_id.clone(),
        engine_id: selected.binding.engine_id.clone(),
        current_generation_sha256: selected.binding.sha256()?,
        rollback_generation_sha256: parent.sha256()?,
        current_helper_receipt_sha256: hash(&selected.evidence["helper"]),
        rollback_helper_receipt_sha256: hash(&previous_helper),
        selected_session_sha256: hash(&selected.evidence["session"]),
        configuration_sha256: selected.session.configuration_sha256,
        activation_receipt_sha256: hash(&selected.evidence["activation"]),
        selection_receipt_sha256: selected.selector.selection_sha256,
        public_renewal_enrollment_sha256: hash(&view.read_evidence("renewal-result.json")?),
        public_identity_sha256: serde_json::from_value(renewal["public_identity_sha256"].clone())
            .map_err(|_| REFUSED)?,
    }))
}

fn plan_for_binding(
    view: &LockedInspection,
    installation: &Path,
    binding: &GenerationBinding,
) -> Result<crate::installer_public_ingress::PublicIngressPlan> {
    let metadata = binding
        .public_ingress_metadata(installation)?
        .ok_or(REFUSED)?;
    let name = if binding.sequence() == 0 {
        crate::installer_public_ingress::PUBLIC_INGRESS_PLAN_RECORD.into()
    } else {
        record_name(binding.sequence(), "public-ingress-plan")
    };
    let plan = crate::installer_public_ingress::PublicIngressPlan::parse_authenticated(
        &view.read_evidence(&name)?,
        &metadata.plan_sha256,
    )?;
    plan.require_saved(view)?;
    Ok(plan)
}
fn candidate_for_binding(
    view: &LockedInspection,
    installation: &Path,
    binding: &GenerationBinding,
) -> Result<AcmeCandidate> {
    let plan = plan_for_binding(view, installation, binding)?;
    let candidate = installer_acme::retained_candidate(
        view,
        AcmeEnvironment::Production,
        plan.enrolment_cycle(),
    )?;
    require(
        candidate.fullchain_pem() == plan.fullchain_pem()
            && candidate.metadata() == plan.certificate_admission(),
    )?;
    Ok(candidate)
}
pub(crate) fn reconcile_pending_locked(
    installation: &Path,
    docker: &Path,
    state: &mut LockedMaintenance,
) -> Result<()> {
    tx::reconcile_pending(installation, docker, state).map(|_| ())
}
pub(crate) fn has_pending_generation(view: &LockedInspection, installation: &Path) -> Result<bool> {
    view.require_path_binding(installation)?;
    let sequence = selected(installation)?.map_or(0, |value| value.binding.sequence());
    if optional(
        installation,
        &record_name(sequence.checked_add(1).ok_or(REFUSED)?, "intent"),
    )?
    .is_some()
    {
        return Ok(true);
    }
    let current = generation::load_verified(
        installation,
        &view.journal().installation_id().to_string(),
        &view.journal().runtime().ok_or(REFUSED)?.engine_id,
    )?;
    let Some(binding) = current else {
        return Ok(false);
    };
    let Some(_metadata) = binding.public_ingress_metadata(installation)? else {
        return Ok(false);
    };
    let current_cycle = plan_for_binding(view, installation, &binding)?.enrolment_cycle();
    let evidence = crate::installer_host_fs::directory(&installation.join("evidence"), REFUSED)?;
    let names = crate::installer_host_fs::file_names(&evidence, REFUSED)?;
    for name in names {
        if name.starts_with("generation-acme-") && name.ends_with("-intent.json") {
            let permit: PermitData = decode(&view.read_evidence(&name)?)?;
            require(name == RenewalPermit::record_name(permit.cycle))?;
            if permit.cycle <= current_cycle {
                continue;
            }
            let stream = crate::installer_acme_state::Ledger::load_cycle(
                view,
                AcmeEnvironment::Production,
                permit.cycle,
            )?;
            if stream.as_ref().is_none_or(|saved| {
                saved.state.stage != crate::installer_acme_state::Stage::Terminal
            }) {
                return Ok(true);
            }
        }
    }
    view.require_unchanged()?;
    Ok(false)
}
pub(crate) fn stop_pending_locked(
    installation: &Path,
    docker: &Path,
    state: &mut LockedMaintenance,
) -> Result<Option<Value>> {
    tx::stop_pending(installation, docker, state)
}
#[path = "installer_generation_models.rs"]
mod model;
#[path = "installer_generation_maintenance_tx.rs"]
mod tx;
pub(crate) use model::require_runtime_model;
#[path = "installer_generation_schedule.rs"]
mod schedule;
pub(crate) use schedule::{reconcile_locked, status_locked};
#[path = "installer_generation_usability.rs"]
mod usability;
pub(crate) use usability::{current_startup_usability, CurrentGenerationUsability};
