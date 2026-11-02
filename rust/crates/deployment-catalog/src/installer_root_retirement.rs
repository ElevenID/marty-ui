//! Initial-root retirement after installed qualification. The lifecycle owner
//! supplies the authoritative generation selection observer and references to
//! real installed proof artifacts; no component-test receipt can open this gate.
#![cfg(target_os = "linux")]

use crate::{
    installer_compose::ComposeSession,
    installer_json,
    installer_openbao_recovery::{LocalControlBinding, OwnedLocalControl},
    installer_release::sha256,
    installer_runtime::DockerRunner,
    installer_state::{Identity, LockedInspection, LockedMaintenance},
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

type Result<T> = std::result::Result<T, String>;
const REFUSED: &str = "initial OpenBao root retirement evidence differs; preserve the installation and its exact pending intent";
const BLOCKED: &str = "initial OpenBao root retirement requires current installed qualification and independent selected and rollback authority";
const PENDING: &str = "initial OpenBao root retirement is incomplete; retry the same retained intent after restoring its bound local control";
const INTENT: &str = "openbao-root-retirement-intent.json";
const COMPLETION: &str = "openbao-root-retirement-complete.json";
const FRESHNESS: u64 = 15 * 60;

fn require(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}
fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
}
fn uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| id.to_string() == value)
}
fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    require(!bytes.is_empty() && bytes.len() <= 65_536)?;
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

/// All fields come from the generation owner's read-only validated retirement
/// view. They are public artifact digests, never root/recovery-key digests.
/// The observer must return None until a completed successor/rollback pair and
/// its exact native selection transaction exist; historical startup is not one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RetirementSelection {
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
impl RetirementSelection {
    fn validate(&self, view: &LockedInspection) -> Result<()> {
        require(
            self.installation_id == view.journal().installation_id().to_string()
                && view
                    .journal()
                    .runtime()
                    .is_some_and(|v| v.engine_id == self.engine_id)
                && self.current_generation_sha256 != self.rollback_generation_sha256
                && self.current_helper_receipt_sha256 != self.rollback_helper_receipt_sha256
                && [
                    &self.current_generation_sha256,
                    &self.rollback_generation_sha256,
                    &self.current_helper_receipt_sha256,
                    &self.rollback_helper_receipt_sha256,
                    &self.selected_session_sha256,
                    &self.configuration_sha256,
                    &self.activation_receipt_sha256,
                    &self.selection_receipt_sha256,
                    &self.public_renewal_enrollment_sha256,
                ]
                .into_iter()
                .all(|v| hash(v))
                && !self.public_identity_sha256.is_empty()
                && self.public_identity_sha256.len() <= 16
                && self.public_identity_sha256.iter().all(|(name, digest)| {
                    !name.is_empty()
                        && name.len() <= 128
                        && name.bytes().all(|v| {
                            v.is_ascii_lowercase() || v.is_ascii_digit() || b"-_.".contains(&v)
                        })
                        && hash(digest)
                }),
        )
    }
}

/// An append-only installed evidence artifact. The filename is selected by the
/// qualification owner; only the exact typed scope's fixed basename is accepted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ArtifactRef {
    pub name: String,
    pub sha256: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProofKind {
    Application,
    ScopedAuthorities,
    Restart,
    Restore,
}
impl ProofKind {
    fn label(self) -> &'static str {
        match self {
            Self::Application => "application",
            Self::ScopedAuthorities => "scoped-authorities",
            Self::Restart => "restart",
            Self::Restore => "restore",
        }
    }
    fn checks(self) -> &'static [&'static str] {
        match self {
            Self::Application => &[
                "canonical_https_verified",
                "authenticated_credential_journey",
                "selected_generation_active",
            ],
            Self::ScopedAuthorities => &[
                "selected_workload_login_and_sign",
                "rollback_workload_login_and_sign",
                "workload_credentials_independent",
                "public_renewal_login_and_sign",
                "acme_account_login_and_sign",
                "ingress_csr_login_and_sign",
                "local_tcp_recovery_login_and_sign",
                "scope_constraints_verified",
                "verification_tokens_revoked",
            ],
            Self::Restart => &[
                "same_cluster_after_restart",
                "static_key_retained",
                "scoped_authorities_after_restart",
                "selected_application_after_restart",
                "initial_root_unavailable_during_restart",
                "initialization_not_replayed",
                "unseal_not_called",
            ],
            Self::Restore => &[
                "source_offline_before_restore",
                "normal_snapshot_endpoint",
                "original_static_key_restored",
                "same_cluster_after_restore",
                "retained_issuer_and_transit_keys",
                "scoped_authorities_after_restore",
                "selected_and_rollback_credentials_restored",
                "external_identity_files_restored",
                "customer_backup_transport_qualified",
                "installed_image_restore_qualified",
            ],
        }
    }
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RetirementEvidence {
    pub application: Option<ArtifactRef>,
    pub scoped_authorities: Option<ArtifactRef>,
    pub restart: Option<ArtifactRef>,
    pub restore: Option<ArtifactRef>,
}
impl RetirementEvidence {
    fn entries(&self) -> [(ProofKind, Option<&ArtifactRef>); 4] {
        [
            (ProofKind::Application, self.application.as_ref()),
            (
                ProofKind::ScopedAuthorities,
                self.scoped_authorities.as_ref(),
            ),
            (ProofKind::Restart, self.restart.as_ref()),
            (ProofKind::Restore, self.restore.as_ref()),
        ]
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct QualificationContext {
    pub release: Identity,
    pub selection: RetirementSelection,
    pub local_control: LocalControlBinding,
}
/// Written only by an installed qualification owner after performing the exact
/// checks. This module reads these records and never manufactures them from an
/// isolated binary/image proof, an enrollment flag, or a startup report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InstalledProof {
    pub schema: String,
    pub proof_id: String,
    pub kind: ProofKind,
    pub subject: String,
    pub context: QualificationContext,
    pub started_at: u64,
    pub completed_at: u64,
    pub checks: BTreeMap<String, bool>,
    pub initial_root_used: bool,
    pub initialization_replayed: bool,
    pub installation_ready: bool,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct RequirementStatus {
    pub requirement: String,
    pub satisfied: bool,
    pub reason: String,
}
#[derive(Clone, Debug, Serialize)]
pub(crate) struct RetirementStatus {
    pub schema: &'static str,
    pub installation_id: String,
    pub phase: &'static str,
    pub eligible: bool,
    pub root_retired: bool,
    pub attempt_id: Option<String>,
    pub requirements: Vec<RequirementStatus>,
    pub installation_ready: bool,
}
fn requirement(name: &str, reason: Option<&str>) -> RequirementStatus {
    RequirementStatus {
        requirement: name.into(),
        satisfied: reason.is_none(),
        reason: reason.unwrap_or("verified").into(),
    }
}

fn proof_reason(
    bytes: &[u8],
    reference: &ArtifactRef,
    kind: ProofKind,
    context: &QualificationContext,
    as_of: u64,
) -> Option<&'static str> {
    if !hash(&reference.sha256) || sha256(bytes) != reference.sha256 {
        return Some("artifact_digest_differs");
    }
    let Ok(proof) = decode::<InstalledProof>(bytes) else {
        return Some("installed_proof_schema_required");
    };
    if proof.schema != "elevenid.installed-root-retirement-proof/v1"
        || !uuid(&proof.proof_id)
        || proof.kind != kind
        || reference.name
            != format!(
                "openbao-root-retirement-{}-{}.json",
                kind.label(),
                proof.proof_id
            )
        || proof.subject != "installed_deployment"
    {
        return Some("installed_proof_scope_required");
    }
    if proof.context != *context {
        return Some("selected_authority_binding_differs");
    }
    if proof.started_at == 0
        || proof.started_at > proof.completed_at
        || proof.completed_at > as_of
        || as_of - proof.completed_at > FRESHNESS
    {
        return Some("fresh_installed_proof_required");
    }
    if proof.initial_root_used
        || proof.initialization_replayed
        || proof.installation_ready
        || proof
            .checks
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            != kind.checks().iter().copied().collect()
        || !proof.checks.values().all(|v| *v)
    {
        return Some("required_installed_checks_incomplete");
    }
    None
}

fn assess(
    view: &LockedInspection,
    context: &QualificationContext,
    evidence: &RetirementEvidence,
    as_of: u64,
) -> Result<Vec<RequirementStatus>> {
    let mut result = Vec::new();
    for (kind, reference) in evidence.entries() {
        let reason = match reference {
            None => Some("installed_evidence_missing"),
            Some(reference) => {
                // Reject paths and unexpected names before a filesystem lookup.
                let prefix = format!("openbao-root-retirement-{}-", kind.label());
                if !reference.name.starts_with(&prefix)
                    || !reference.name.ends_with(".json")
                    || !uuid(
                        reference
                            .name
                            .strip_prefix(&prefix)
                            .and_then(|v| v.strip_suffix(".json"))
                            .unwrap_or(""),
                    )
                {
                    Some("installed_artifact_name_required")
                } else {
                    match view.diagnostic_record(&reference.name, true)? {
                        Some(bytes) => proof_reason(&bytes, reference, kind, context, as_of),
                        None => Some("installed_evidence_missing"),
                    }
                }
            }
        };
        result.push(requirement(kind.label(), reason));
    }
    Ok(result)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    schema: String,
    installation_id: String,
    attempt_id: String,
    created_at: u64,
    context: QualificationContext,
    evidence: RetirementEvidence,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HelperReceipt {
    schema: String,
    installation_id: String,
    attempt_id: String,
    intent_sha256: String,
    cluster_id: String,
    root_rejection_observed: bool,
    root_token_removed: bool,
    recovery_key_preserved: bool,
    original_authority_verified: bool,
    authority_record_preserved: bool,
    initialization_replayed: bool,
    installation_ready: bool,
}
impl HelperReceipt {
    fn validate(&self, intent: &Intent, digest: &str) -> Result<()> {
        require(
            self.schema == "elevenid.openbao-initial-root-retirement-result/v1"
                && self.installation_id == intent.installation_id
                && self.attempt_id == intent.attempt_id
                && self.intent_sha256 == digest
                && self.cluster_id == intent.context.local_control.cluster_id
                && self.root_rejection_observed
                && self.root_token_removed
                && self.recovery_key_preserved
                && self.original_authority_verified
                && self.authority_record_preserved
                && !self.initialization_replayed
                && !self.installation_ready,
        )
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Completion {
    schema: String,
    installation_id: String,
    attempt_id: String,
    intent_sha256: String,
    completed_at: u64,
    helper_receipt: HelperReceipt,
    root_retired: bool,
    installation_ready: bool,
}

fn retained(view: &LockedInspection, at: u64) -> Result<Option<(Intent, Vec<u8>, bool)>> {
    let intent_bytes = view.diagnostic_record(INTENT, true)?;
    let completion_bytes = view.diagnostic_record(COMPLETION, true)?;
    let Some(intent_bytes) = intent_bytes else {
        require(completion_bytes.is_none())?;
        return Ok(None);
    };
    let intent: Intent = decode(&intent_bytes)?;
    require(
        intent.schema == "elevenid.installer-openbao-root-retirement-intent/v1"
            && intent.installation_id == view.journal().installation_id().to_string()
            && uuid(&intent.attempt_id)
            && intent.created_at > 0
            && intent.created_at <= at
            && intent.context.release == *view.journal().identity(),
    )?;
    intent.context.selection.validate(view)?;
    let control = &intent.context.local_control;
    require(
        control.installation_id == intent.installation_id
            && control.engine_id == intent.context.selection.engine_id
            && control.project == view.journal().compose_project()
            && uuid(&control.cluster_id)
            && uuid(&control.issuer_id)
            && [
                &control.container_id,
                &control.config_hash,
                &control.resources_sha256,
                &control.control_observation_sha256,
                &control.ca_sha256,
                &control.spki_sha256,
            ]
            .into_iter()
            .all(|v| hash(v)),
    )?;
    // Freshness was required at authorization. Retries days later reconcile the
    // same already-authorized attempt; they cannot create another root operation.
    require(
        assess(view, &intent.context, &intent.evidence, intent.created_at)?
            .iter()
            .all(|v| v.satisfied),
    )?;
    let complete = if let Some(bytes) = completion_bytes {
        let completed: Completion = decode(&bytes)?;
        let digest = sha256(&intent_bytes);
        require(
            completed.schema == "elevenid.installer-openbao-root-retirement-complete/v1"
                && completed.installation_id == intent.installation_id
                && completed.attempt_id == intent.attempt_id
                && completed.intent_sha256 == digest
                && completed.completed_at >= intent.created_at
                && completed.completed_at <= at
                && completed.root_retired
                && !completed.installation_ready,
        )?;
        completed.helper_receipt.validate(&intent, &digest)?;
        true
    } else {
        false
    };
    view.require_unchanged()?;
    Ok(Some((intent, intent_bytes, complete)))
}

fn history(
    state: &LockedMaintenance,
    context: &QualificationContext,
    at: u64,
) -> Result<Option<(Intent, Vec<u8>, bool)>> {
    let Some((intent, bytes, complete)) = retained(state.inspection(), at)? else {
        return Ok(None);
    };
    if complete {
        // Later legitimate application generations do not undo a completed
        // retirement or permit another one. Keep the original Bao authority
        // binding while accepting the currently validated application census.
        let original = &intent.context.local_control;
        let current = &context.local_control;
        require(
            original.installation_id == current.installation_id
                && original.engine_id == current.engine_id
                && original.project == current.project
                && original.container_id == current.container_id
                && original.image == current.image
                && original.config_hash == current.config_hash
                && original.control_observation_sha256 == current.control_observation_sha256
                && original.cluster_id == current.cluster_id
                && original.issuer_id == current.issuer_id
                && original.ca_sha256 == current.ca_sha256
                && original.spki_sha256 == current.spki_sha256,
        )?;
    } else {
        require(intent.context == *context)?;
    }
    Ok(Some((intent, bytes, complete)))
}

/// Every generation mutation (including resuming activation/selection) passes
/// this gate first. Lifecycle resumes the authorized root operation after Unix
/// TLS recovery and before generation work, preserving its original context.
pub(crate) fn require_no_pending_for_generation(view: &LockedInspection) -> Result<()> {
    if retained(view, now()?)?.is_some_and(|(_, _, complete)| !complete) {
        return Err("initial OpenBao root retirement is pending; reconcile that retained attempt before advancing an application generation".into());
    }
    Ok(())
}

fn authorize(
    state: &mut LockedMaintenance,
    context: &QualificationContext,
    evidence: &RetirementEvidence,
    at: u64,
) -> Result<(Intent, Vec<u8>, bool)> {
    if let Some(retained) = history(state, context, at)? {
        return Ok(retained);
    }
    if !assess(state.inspection(), context, evidence, at)?
        .iter()
        .all(|v| v.satisfied)
    {
        return Err(BLOCKED.into());
    }
    let intent = Intent {
        schema: "elevenid.installer-openbao-root-retirement-intent/v1".into(),
        installation_id: context.selection.installation_id.clone(),
        attempt_id: uuid::Uuid::new_v4().to_string(),
        created_at: at,
        context: context.clone(),
        evidence: evidence.clone(),
    };
    let bytes = encode(&intent)?;
    state.write_evidence_exclusive(INTENT, &bytes)?;
    Ok((intent, bytes, false))
}

/// The observer is the generation owner's read-only retirement_view adapter,
/// called repeatedly under this lock. It must validate the selected pointer,
/// both generations, native receipts and closed activation transaction itself.
pub(crate) fn status_locked(
    installation: &Path,
    state: &LockedMaintenance,
    session: &ComposeSession,
    selection: &impl Fn(&LockedInspection, &Path) -> Result<Option<RetirementSelection>>,
    evidence: &RetirementEvidence,
) -> Result<RetirementStatus> {
    let mut status = RetirementStatus {
        schema: "elevenid.installer-openbao-root-retirement-status/v1",
        installation_id: state.journal().installation_id().to_string(),
        phase: "blocked",
        eligible: false,
        root_retired: false,
        attempt_id: None,
        requirements: Vec::new(),
        installation_ready: false,
    };
    state.require_unchanged()?;
    state.inspection().require_path_binding(installation)?;
    let Some(selected) = selection(state.inspection(), installation)? else {
        status.requirements.push(requirement(
            "selected-and-rollback-generations",
            Some("completed_independent_generation_pair_missing"),
        ));
        for (kind, _) in evidence.entries() {
            status.requirements.push(requirement(
                kind.label(),
                Some("generation_binding_unavailable"),
            ));
        }
        return Ok(status);
    };
    selected.validate(state.inspection())?;
    let target = OwnedLocalControl::capture(state, installation, session)?;
    require(selected.configuration_sha256 == session.configuration_sha256())?;
    let context = QualificationContext {
        release: state.journal().identity().clone(),
        selection: selected,
        local_control: target.binding().clone(),
    };
    let at = now()?;
    let retained = history(state, &context, at)?;
    status
        .requirements
        .push(requirement("selected-and-rollback-generations", None));
    status.requirements.push(requirement(
        "generation-transaction",
        crate::installer_generation_maintenance::has_pending_generation(
            state.inspection(),
            installation,
        )?
        .then_some("generation_reconciliation_pending"),
    ));
    status
        .requirements
        .extend(assess(state.inspection(), &context, evidence, at)?);
    status.eligible = status.requirements.iter().all(|v| v.satisfied);
    if let Some((intent, _, complete)) = retained {
        status.attempt_id = Some(intent.attempt_id);
        status.root_retired = complete;
        status.phase = if complete { "completed" } else { "pending" };
        status.eligible = false;
    } else if status.eligible {
        status.phase = "eligible";
    }
    require(selection(state.inspection(), installation)?.as_ref() == Some(&context.selection))?;
    target.require_unchanged(state, installation, session)?;
    Ok(status)
}

/// The caller additionally requires durable running lifecycle intent. No fresh
/// retirement starts without all four installed proof categories. A timeout or
/// lost helper result retains exactly this host attempt; the in-container lock
/// serializes a helper that outlives its Docker client.
pub(crate) fn retire_locked(
    installation: &Path,
    docker_binary: &Path,
    state: &mut LockedMaintenance,
    session: &ComposeSession,
    selection: &impl Fn(&LockedInspection, &Path) -> Result<Option<RetirementSelection>>,
    evidence: &RetirementEvidence,
) -> Result<RetirementStatus> {
    perform_retirement(
        installation,
        docker_binary,
        state,
        session,
        selection,
        evidence,
        None,
    )
}

fn existing_authorization(
    state: &LockedMaintenance,
    context: &QualificationContext,
    expected: &[u8],
    at: u64,
) -> Result<(Intent, Vec<u8>, bool)> {
    let retained = history(state, context, at)?.ok_or(REFUSED)?;
    require(retained.1 == expected)?;
    Ok(retained)
}

fn perform_retirement(
    installation: &Path,
    docker_binary: &Path,
    state: &mut LockedMaintenance,
    session: &ComposeSession,
    selection: &impl Fn(&LockedInspection, &Path) -> Result<Option<RetirementSelection>>,
    evidence: &RetirementEvidence,
    expected_intent: Option<&[u8]>,
) -> Result<RetirementStatus> {
    state.require_unchanged()?;
    state.inspection().require_path_binding(installation)?;
    if crate::installer_generation_maintenance::has_pending_generation(
        state.inspection(),
        installation,
    )? {
        return Err("application generation reconciliation is pending; complete it before authorizing initial OpenBao root retirement".into());
    }
    let selected = selection(state.inspection(), installation)?.ok_or(BLOCKED)?;
    selected.validate(state.inspection())?;
    require(selected.configuration_sha256 == session.configuration_sha256())?;
    let target = OwnedLocalControl::capture(state, installation, session)?;
    let context = QualificationContext {
        release: state.journal().identity().clone(),
        selection: selected,
        local_control: target.binding().clone(),
    };
    let at = now()?;
    require(selection(state.inspection(), installation)?.as_ref() == Some(&context.selection))?;
    target.require_unchanged(state, installation, session)?;
    let (intent, bytes, complete) = match expected_intent {
        Some(expected) => existing_authorization(state, &context, expected, at)?,
        None => authorize(state, &context, evidence, at)?,
    };
    if complete {
        return status_locked(installation, state, session, selection, evidence);
    }
    let digest = sha256(&bytes);
    let binding = state.journal().runtime().ok_or(REFUSED)?.clone();
    let docker = DockerRunner::from_binding(docker_binary, &binding, installation)?
        .with_deadline(Instant::now() + Duration::from_secs(125));
    target.require_unchanged(state, installation, session)?;
    require(
        selection(state.inspection(), installation)?.as_ref() == Some(&context.selection)
            && state.read_evidence(INTENT)?.as_deref() == Some(bytes.as_slice())
            && !crate::installer_generation_maintenance::has_pending_generation(
                state.inspection(),
                installation,
            )?,
    )?;
    require(
        assess(
            state.inspection(),
            &context,
            &intent.evidence,
            intent.created_at,
        )?
        .iter()
        .all(|v| v.satisfied),
    )?;
    let output = docker
        .retire_openbao_initial_root(
            &context.local_control.container_id,
            &intent.installation_id,
            &intent.attempt_id,
            &digest,
        )
        .map_err(|_| PENDING)?;
    let receipt: HelperReceipt = decode(output.as_bytes())?;
    receipt.validate(&intent, &digest)?;
    target.require_unchanged(state, installation, session)?;
    require(
        selection(state.inspection(), installation)?.as_ref() == Some(&context.selection)
            && state.read_evidence(INTENT)?.as_deref() == Some(bytes.as_slice()),
    )?;
    require(
        assess(
            state.inspection(),
            &context,
            &intent.evidence,
            intent.created_at,
        )?
        .iter()
        .all(|v| v.satisfied),
    )?;
    let complete = Completion {
        schema: "elevenid.installer-openbao-root-retirement-complete/v1".into(),
        installation_id: intent.installation_id,
        attempt_id: intent.attempt_id,
        intent_sha256: digest,
        completed_at: now()?,
        helper_receipt: receipt,
        root_retired: true,
        installation_ready: false,
    };
    state.write_evidence_exclusive(COMPLETION, &encode(&complete)?)?;
    status_locked(installation, state, session, selection, evidence)
}

/// Resume only a durable, already-authorized retirement. This entry point never
/// mints proof or an attempt, and returns None without Docker when no unfinished
/// operation exists. It is ordered after local TLS recovery and before any
/// generation advancement by the lifecycle owner.
pub(crate) fn resume_pending_locked(
    installation: &Path,
    docker_binary: &Path,
    state: &mut LockedMaintenance,
    session: &ComposeSession,
) -> Result<Option<RetirementStatus>> {
    state.inspection().require_path_binding(installation)?;
    let Some((intent, bytes, complete)) = retained(state.inspection(), now()?)? else {
        return Ok(None);
    };
    if complete {
        return Ok(None);
    }
    crate::installer_lifecycle::require_running_intent(state, installation, docker_binary)?;
    let report = perform_retirement(
        installation,
        docker_binary,
        state,
        session,
        &selected_generations,
        &intent.evidence,
        Some(&bytes),
    )?;
    Ok(Some(report))
}

fn selected_generations(
    view: &LockedInspection,
    installation: &Path,
) -> Result<Option<RetirementSelection>> {
    crate::installer_generation_maintenance::retirement_view(view, installation).map(|value| {
        value.map(|v| RetirementSelection {
            installation_id: v.installation_id,
            engine_id: v.engine_id,
            current_generation_sha256: v.current_generation_sha256,
            rollback_generation_sha256: v.rollback_generation_sha256,
            current_helper_receipt_sha256: v.current_helper_receipt_sha256,
            rollback_helper_receipt_sha256: v.rollback_helper_receipt_sha256,
            selected_session_sha256: v.selected_session_sha256,
            configuration_sha256: v.configuration_sha256,
            activation_receipt_sha256: v.activation_receipt_sha256,
            selection_receipt_sha256: v.selection_receipt_sha256,
            public_renewal_enrollment_sha256: v.public_renewal_enrollment_sha256,
            public_identity_sha256: v.public_identity_sha256,
        })
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Action {
    Status,
    Retire,
}
#[derive(Debug)]
struct Arguments {
    action: Action,
    installation: PathBuf,
    docker: PathBuf,
    evidence: Option<PathBuf>,
}
fn absolute(path: &Path) -> Result<()> {
    let text = path.to_str().ok_or(REFUSED)?;
    require(
        path.is_absolute()
            && text.len() > 1
            && text.len() <= 4096
            && !text.chars().any(char::is_control)
            && !text
                .split('/')
                .skip(1)
                .any(|part| part.is_empty() || part == "." || part == "..")
            && path
                .components()
                .all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
    )
}
fn arguments(args: &[String]) -> Result<Arguments> {
    let action = match args.first().map(String::as_str) {
        Some("status") => Action::Status,
        Some("retire") => Action::Retire,
        _ => return Err("Expected root-retirement status|retire --install-dir ABS [--docker-bin ABS] [--evidence ABS]".into()),
    };
    require((args.len() - 1).is_multiple_of(2))?;
    let mut values = BTreeMap::new();
    for pair in args[1..].chunks_exact(2) {
        require(
            ["--install-dir", "--docker-bin", "--evidence"].contains(&pair[0].as_str())
                && values.insert(pair[0].as_str(), pair[1].as_str()).is_none(),
        )?;
    }
    let installation = PathBuf::from(*values.get("--install-dir").ok_or(REFUSED)?);
    let docker = PathBuf::from(*values.get("--docker-bin").unwrap_or(&"/usr/bin/docker"));
    let evidence = values.get("--evidence").map(|value| PathBuf::from(*value));
    absolute(&installation)?;
    absolute(&docker)?;
    if let Some(path) = &evidence {
        absolute(path)?;
    }
    Ok(Arguments {
        action,
        installation,
        docker,
        evidence,
    })
}

fn read_evidence_input(path: Option<&Path>) -> Result<RetirementEvidence> {
    let Some(path) = path else {
        return Ok(RetirementEvidence::default());
    };
    absolute(path)?;
    let parent_path = path.parent().ok_or(REFUSED)?;
    let name = path.file_name().and_then(|v| v.to_str()).ok_or(REFUSED)?;
    let parent = crate::installer_host_fs::directory(parent_path, REFUSED)?;
    let held = crate::installer_host_fs::open_child(&parent, name, libc::O_PATH, REFUSED)?;
    let original = held.metadata().map_err(|_| REFUSED)?;
    let mode = original.mode() & 0o7777;
    require(
        original.is_file()
            && original.nlink() == 1
            && original.uid() == unsafe { libc::geteuid() }
            && (mode == 0o400 || mode == 0o600)
            && (1..=65_536).contains(&original.len()),
    )?;
    let bytes = crate::installer_host_fs::read_entry(&parent, name, mode, false, REFUSED)?;
    let value = decode(&bytes)?;
    let current = crate::installer_host_fs::open_child(&parent, name, libc::O_PATH, REFUSED)?
        .metadata()
        .map_err(|_| REFUSED)?;
    let binding = |m: &std::fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.uid(),
            m.gid(),
            m.mode(),
            m.nlink(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    };
    require(
        binding(&original) == binding(&current)
            && crate::installer_host_fs::read_entry(&parent, name, mode, false, REFUSED)? == bytes,
    )?;
    crate::installer_host_fs::require_directory_binding(parent_path, &parent, REFUSED)?;
    Ok(value)
}

fn no_selection_status(state: &LockedMaintenance, generation_pending: bool) -> RetirementStatus {
    let mut requirements = vec![requirement(
        "selected-and-rollback-generations",
        Some("completed_independent_generation_pair_missing"),
    )];
    requirements.push(requirement(
        "generation-transaction",
        generation_pending.then_some("generation_reconciliation_pending"),
    ));
    for kind in [
        ProofKind::Application,
        ProofKind::ScopedAuthorities,
        ProofKind::Restart,
        ProofKind::Restore,
    ] {
        requirements.push(requirement(
            kind.label(),
            Some("generation_binding_unavailable"),
        ));
    }
    RetirementStatus {
        schema: "elevenid.installer-openbao-root-retirement-status/v1",
        installation_id: state.journal().installation_id().to_string(),
        phase: "blocked",
        eligible: false,
        root_retired: false,
        attempt_id: None,
        requirements,
        installation_ready: false,
    }
}

/// Closed operator interface: the optional file supplies references only. It
/// cannot produce a qualification, change its checks or override generation or
/// local-control identities. Status never starts services or writes evidence.
pub fn run(args: &[String]) -> Result<String> {
    let args = arguments(args)?;
    let mut state = LockedMaintenance::open(&args.installation)?;
    let evidence = read_evidence_input(args.evidence.as_deref())?;
    let selected = selected_generations(state.inspection(), &args.installation)?;
    if selected.is_none() {
        if args.action == Action::Retire {
            return Err(BLOCKED.into());
        }
        require(
            state.read_evidence(INTENT)?.is_none() && state.read_evidence(COMPLETION)?.is_none(),
        )?;
        let pending = crate::installer_generation_maintenance::has_pending_generation(
            state.inspection(),
            &args.installation,
        )?;
        return serde_json::to_string_pretty(&no_selection_status(&state, pending))
            .map_err(|_| REFUSED.into());
    }
    if args.action == Action::Retire {
        crate::installer_lifecycle::require_running_intent(
            &state,
            &args.installation,
            &args.docker,
        )?;
    }
    let (_, session) = crate::installer_doctor::open_session(
        state.inspection(),
        &args.installation,
        &args.docker,
    )?;
    let status = match args.action {
        Action::Status => status_locked(
            &args.installation,
            &state,
            &session,
            &selected_generations,
            &evidence,
        )?,
        Action::Retire => retire_locked(
            &args.installation,
            &args.docker,
            &mut state,
            &session,
            &selected_generations,
            &evidence,
        )?,
    };
    serde_json::to_string_pretty(&status).map_err(|_| REFUSED.into())
}

#[cfg(test)]
#[path = "installer_root_retirement_tests.rs"]
mod tests;
