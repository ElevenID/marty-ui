//! A completed stale producer can authorize one new immutable attempt. The
//! selected generation does not advance until fresh native activation succeeds.
use super::*;

const SUPERSESSION_SCHEMA: &str = "elevenid.installer-generation-supersession/v1";
const BASELINE_SCHEMA: &str = "elevenid.installer-generation-recovery-baseline/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StaleReason {
    CredentialFreshnessElapsed,
    PublicCertificateExpired,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Supersession {
    schema: String,
    installation_id: String,
    engine_id: String,
    sequence: u64,
    attempt: u64,
    previous_attempt: u64,
    parent_attempt: u64,
    parent_binding_sha256: String,
    parent_session_sha256: String,
    previous_evidence_sha256: BTreeMap<String, String>,
    previous_container_id: String,
    previous_token_observed_at: u64,
    previous_credential_fresh_until: u64,
    previous_certificate_not_after: u64,
    reason: StaleReason,
    runtime_replacement_started: bool,
    original_create_intents: BTreeMap<String, String>,
    before_resources: ProjectResources,
    observed_at: u64,
}
impl Supersession {
    fn scope(&self) -> Attempt {
        Attempt::new(self.sequence, self.attempt)
    }
    fn previous(&self) -> Attempt {
        Attempt::new(self.sequence, self.previous_attempt)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Baseline {
    schema: String,
    installation_id: String,
    engine_id: String,
    sequence: u64,
    attempt: u64,
    supersession_sha256: String,
    inputs: ComposeInputs,
    model: Value,
    configuration_sha256: String,
    observation: NativeReference,
    create_intents: BTreeMap<String, String>,
    stopped_services: BTreeSet<String>,
    runtime_generation_root: PathBuf,
    observed_at: u64,
    activation_performed: bool,
    installation_ready: bool,
}

/// A factual, fully owned native census after stale-attempt convergence. This
/// capability is never a replacement for the selected generation/session and
/// grants no initial setup, account registration or arbitrary order authority.
#[derive(Clone)]
pub(crate) struct GenerationRecoveryBaseline {
    data: Baseline,
    digest: String,
}
impl GenerationRecoveryBaseline {
    pub(crate) fn inputs(&self) -> &ComposeInputs {
        &self.data.inputs
    }
    pub(super) fn scope(&self) -> Attempt {
        Attempt::new(self.data.sequence, self.data.attempt)
    }
    pub(super) fn sha256(&self) -> &str {
        &self.digest
    }
    pub(super) fn receipt(&self) -> Result<&ComposeReceipt> {
        self.data
            .inputs
            .prior
            .as_ref()
            .ok_or_else(|| REFUSED.into())
    }
    pub(super) fn runtime_root(&self) -> &Path {
        &self.data.runtime_generation_root
    }
    pub(super) fn observed_at(&self) -> u64 {
        self.data.observed_at
    }
    pub(super) fn previous_work(&self, installation: &Path) -> Result<PathBuf> {
        let previous = self.scope().number.checked_sub(1).ok_or(REFUSED)?;
        Ok(Attempt::new(self.scope().sequence, previous).work(installation))
    }

    pub(crate) fn require_current(
        &self,
        view: &LockedInspection,
        installation: &Path,
        permit: &RenewalPermit,
        configuration: &BoundAcmeConfiguration,
        ingress: &RetainedIngressKey,
    ) -> Result<()> {
        self.require_selected(view, installation)?;
        // Issuance authority remains the actual selected session. The native
        // baseline is separately authenticated and never presented as it.
        let selected = parent_session(view, installation)?;
        permit.require_current(view, installation, &selected.inputs, configuration, ingress)
    }

    pub(crate) fn require_selected(
        &self,
        view: &LockedInspection,
        installation: &Path,
    ) -> Result<()> {
        view.require_path_binding(installation)?;
        crate::installer_lifecycle::require_recorded_running_intent(view, installation)?;
        crate::installer_root_retirement::require_no_pending_for_generation(view)?;
        let retained = load_baseline(view, installation, self.scope())?;
        require(retained.digest == self.digest && encode(&retained.data)? == encode(&self.data)?)?;
        require(optional(installation, &self.scope().record("intent"))?.is_none())?;
        let selected = generation::load_verified(
            installation,
            &self.data.installation_id,
            &self.data.engine_id,
        )?
        .ok_or(REFUSED)?;
        let supersession = load_supersession(view, installation, self.scope())?;
        require(
            selected.sequence().checked_add(1) == Some(self.data.sequence)
                && selected.attempt() == supersession.parent_attempt
                && selected.sha256()? == supersession.parent_binding_sha256,
        )?;
        view.require_unchanged()
    }

    pub(crate) fn require_live(
        &self,
        docker: &Path,
        runtime: &crate::installer_state::RuntimeBinding,
    ) -> Result<()> {
        let session = ComposeSession::new_generation(docker, runtime, self.data.inputs.clone())?;
        require(
            session.model() == &self.data.model
                && session.configuration_sha256() == self.data.configuration_sha256
                && session.observe_resources()?
                    == *self.receipt()?.resources.as_ref().ok_or(REFUSED)?,
        )?;
        require_baseline_status(
            self.receipt()?.resources.as_ref().ok_or(REFUSED)?,
            &session.status()?,
            &self.data.stopped_services,
        )
    }
}

fn require_baseline_status(
    resources: &ProjectResources,
    rows: &[Value],
    stopped: &BTreeSet<String>,
) -> Result<()> {
    require(rows.len() == resources.containers.len())?;
    let mut seen = BTreeSet::new();
    for row in rows {
        let role = row["Service"].as_str().ok_or(REFUSED)?;
        let identity = resources.containers.get(role).ok_or(REFUSED)?;
        require(seen.insert(role) && row["ID"] == identity.id)?;
        if identity.setup {
            require(
                row["State"] == "exited"
                    && row["ExitCode"] == 0
                    && identity
                        .setup_execution
                        .as_ref()
                        .is_some_and(|value| value.completed_without_restart),
            )?;
        } else {
            require(
                ["created", "exited", "running"].contains(&row["State"].as_str().ok_or(REFUSED)?),
            )?;
            if stopped.contains(role) {
                require(row["State"] != "running")?;
            }
        }
    }
    require(stopped.iter().all(|role| {
        resources
            .containers
            .get(role)
            .is_some_and(|identity| !identity.setup)
            && !["openbao", "openbao-unseal", "installer-acme-http01"].contains(&role.as_str())
    }))
}

fn stale_material(
    installation: &Path,
    binding: &GenerationBinding,
    at: u64,
) -> Result<Option<StaleReason>> {
    let metadata = binding
        .public_ingress_metadata(installation)?
        .ok_or(REFUSED)?;
    stale_metadata(
        &metadata,
        &binding.read(installation, "installer_ingress_tls_cert")?,
        at,
    )
}
pub(super) fn requires_supersession(
    installation: &Path,
    binding: &GenerationBinding,
    at: u64,
) -> Result<bool> {
    stale_material(installation, binding, at).map(|value| value.is_some())
}
fn stale_metadata(
    metadata: &crate::installer_public_ingress::PublicIngressMetadata,
    bytes: &[u8],
    at: u64,
) -> Result<Option<StaleReason>> {
    let (_, due) = super::super::schedule::credential_due(
        metadata.token_observed_at,
        metadata.token_ttl_seconds,
        at,
    )?;
    // Invalid trust/signature/SAN/key evidence is never interpreted as expiry.
    metadata.validate_selected_at(bytes, metadata.token_observed_at)?;
    let before = metadata.certificate_admission["not_before"]
        .as_u64()
        .ok_or(REFUSED)?;
    let after = metadata.certificate_admission["not_after"]
        .as_u64()
        .ok_or(REFUSED)?;
    require(at >= before && after > before)?;
    if at >= after {
        return Ok(Some(StaleReason::PublicCertificateExpired));
    }
    metadata.validate_selected_at(bytes, at)?;
    Ok(due.then_some(StaleReason::CredentialFreshnessElapsed))
}

fn old_evidence(installation: &Path, scope: Attempt) -> Result<BTreeMap<String, String>> {
    let mut result = BTreeMap::new();
    for kind in [
        "intent",
        "public-ingress-plan",
        "producer",
        "helper",
        "candidate",
        "binding",
        "binding-pending",
        "activation-intent",
        "runtime-created",
        "runtime-started",
        "session",
        "activation",
        "selection",
    ] {
        if let Some(bytes) = optional(installation, &scope.record(kind))? {
            result.insert(kind.into(), hash(&bytes));
        }
    }
    require(
        [
            "intent",
            "public-ingress-plan",
            "producer",
            "helper",
            "candidate",
            "binding",
            "binding-pending",
        ]
        .into_iter()
        .all(|kind| result.contains_key(kind)),
    )?;
    Ok(result)
}

fn completed_helper(installation: &Path, intent: &Intent) -> Result<ComposeReceipt> {
    let helper: ComposeReceipt = decode(&read(installation, &intent.scope().record("helper"))?)?;
    let reference = NativeReference {
        operation: helper.operation.clone(),
        sha256: hash(&read(installation, &intent.scope().record("helper"))?),
    };
    let helper = native(installation, &reference)?;
    let container = helper
        .resources
        .as_ref()
        .and_then(|resources| resources.containers.get("installer-generation"))
        .ok_or(REFUSED)?;
    require_producer_journal_at(
        installation,
        intent.scope(),
        &container.id,
        &helper.operation,
    )?;
    require(
        container
            .setup_execution
            .as_ref()
            .is_some_and(|value| value.completed_without_restart)
            && helper.status.iter().any(|row| {
                row["Service"] == "installer-generation"
                    && row["ID"] == container.id
                    && row["State"] == "exited"
                    && row["ExitCode"] == 0
            }),
    )?;
    Ok(helper)
}

fn load_supersession(
    view: &LockedInspection,
    installation: &Path,
    scope: Attempt,
) -> Result<Supersession> {
    let value: Supersession = decode(&read(installation, &scope.record("supersession-intent"))?)?;
    require(
        scope.sequence > 0
            && scope.number > 0
            && value.schema == SUPERSESSION_SCHEMA
            && value.scope() == scope
            && value.previous_attempt.checked_add(1) == Some(scope.number)
            && value.installation_id == view.journal().installation_id().to_string()
            && value.engine_id == view.journal().runtime().ok_or(REFUSED)?.engine_id,
    )?;
    let previous = generation::load_attempt(installation, scope.sequence, value.previous_attempt)?;
    let intent: Intent = decode(&read(installation, &value.previous().record("intent"))?)?;
    let metadata = previous
        .public_ingress_metadata(installation)?
        .ok_or(REFUSED)?;
    require_supersession(installation, &value, &intent, &previous, &metadata)?;
    view.require_unchanged()?;
    Ok(value)
}

fn require_supersession(
    installation: &Path,
    value: &Supersession,
    intent: &Intent,
    previous: &GenerationBinding,
    metadata: &crate::installer_public_ingress::PublicIngressMetadata,
) -> Result<()> {
    let helper = completed_helper(installation, intent)?;
    require(
        value.schema == SUPERSESSION_SCHEMA
            && value.scope().sequence == previous.sequence()
            && value.previous() == intent.scope()
            && value.installation_id == previous.installation_id
            && value.engine_id == previous.engine_id
            && value.previous_attempt == previous.attempt()
            && value.attempt == previous.attempt().checked_add(1).ok_or(REFUSED)?
            && value.parent_attempt == intent.parent_attempt
            && value.parent_binding_sha256 == intent.parent_binding_sha256
            && value.parent_session_sha256 == hash(&encode(&intent.parent_session)?)
            && value.previous_evidence_sha256 == old_evidence(installation, intent.scope())?
            && value.previous_container_id
                == helper.resources.as_ref().ok_or(REFUSED)?.containers["installer-generation"].id
            && value.previous_token_observed_at == metadata.token_observed_at
            && value.previous_credential_fresh_until
                == metadata
                    .token_observed_at
                    .checked_add(1800)
                    .ok_or(REFUSED)?
            && value.previous_certificate_not_after
                == metadata.certificate_admission["not_after"]
                    .as_u64()
                    .ok_or(REFUSED)?
            && value.observed_at >= intent.created_at
            && stale_metadata(
                metadata,
                &previous.read(installation, "installer_ingress_tls_cert")?,
                value.observed_at,
            )? == Some(value.reason),
    )?;
    let original = helper.resources.as_ref().ok_or(REFUSED)?;
    require(
        value.before_resources.networks == original.networks
            && value.before_resources.volumes == original.volumes
            && value
                .before_resources
                .containers
                .get("installer-generation")
                == original.containers.get("installer-generation"),
    )?;
    let (creates, roles) =
        if optional(installation, &intent.scope().record("activation-intent"))?.is_some() {
            let activation = load_activation_intent(installation, intent, previous)?;
            let roles = activation.services.into_iter().collect::<BTreeSet<_>>();
            let files = input_files(&activation.inputs)?;
            let context = CreateAuthority {
                project: &activation.inputs.project,
                engine: &intent.engine_id,
                configuration: &activation.configuration_sha256,
                input_files: &files,
                prior: original,
                allowed: &roles,
            };
            (
                recorded_creates(installation, intent.scope(), "activate-create", &context)?,
                roles,
            )
        } else {
            (BTreeMap::new(), BTreeSet::new())
        };
    require(creates == value.original_create_intents)?;
    let mutated = !creates.is_empty()
        || roles.iter().any(|role| {
            value.before_resources.containers.get(role) != original.containers.get(role)
        });
    require(mutated == value.runtime_replacement_started)?;
    require_replacements_authorized(
        installation,
        &creates,
        original,
        &value.before_resources,
        &roles,
    )?;
    for (role, identity) in &original.containers {
        if !roles.contains(role) {
            require(value.before_resources.containers.get(role) == Some(identity))?;
        }
    }
    require(
        value
            .before_resources
            .containers
            .keys()
            .all(|role| original.containers.contains_key(role)),
    )?;
    Ok(())
}

fn load_baseline(
    view: &LockedInspection,
    installation: &Path,
    scope: Attempt,
) -> Result<GenerationRecoveryBaseline> {
    let supersession = load_supersession(view, installation, scope)?;
    let bytes = read(installation, &scope.record("supersession-baseline"))?;
    let data: Baseline = decode(&bytes)?;
    let old: Intent = decode(&read(
        installation,
        &supersession.previous().record("intent"),
    )?)?;
    let previous =
        generation::load_attempt(installation, scope.sequence, supersession.previous_attempt)?;
    let parent = old.parent(installation)?;
    require_baseline(installation, &supersession, &old, &previous, &parent, &data)?;
    Ok(GenerationRecoveryBaseline {
        data,
        digest: hash(&bytes),
    })
}

fn require_baseline(
    installation: &Path,
    supersession: &Supersession,
    old: &Intent,
    previous: &GenerationBinding,
    parent: &GenerationBinding,
    data: &Baseline,
) -> Result<()> {
    require(
        data.schema == BASELINE_SCHEMA
            && data.installation_id == supersession.installation_id
            && data.engine_id == supersession.engine_id
            && data.sequence == supersession.sequence
            && data.attempt == supersession.attempt
            && data.supersession_sha256
                == hash(&read(
                    installation,
                    &supersession.scope().record("supersession-intent"),
                )?)
            && data.configuration_sha256 == installer_compose::model_sha256(&data.model)?
            && data.observed_at >= supersession.observed_at
            && !data.activation_performed
            && !data.installation_ready,
    )?;
    let receipt = native(installation, &data.observation)?;
    require(
        receipt.operation.starts_with(&format!(
            "{}-supersede-baseline-",
            supersession.scope().operation_prefix()
        )) && receipt.configuration_sha256 == data.configuration_sha256
            && encode(data.inputs.prior.as_ref().ok_or(REFUSED)?)? == encode(&receipt)?
            && data.inputs.installation == installation
            && data.inputs.services.is_empty()
            && data.inputs.profiles == old.parent_session.inputs.profiles,
    )?;
    let resources = receipt.resources.as_ref().ok_or(REFUSED)?;
    require_baseline_status(resources, &receipt.status, &data.stopped_services)?;
    let helper = completed_helper(installation, old)?;
    let prior = helper.resources.as_ref().ok_or(REFUSED)?;
    require(
        resources.networks == prior.networks
            && resources.volumes == prior.volumes
            && resources.containers.keys().eq(prior.containers.keys()),
    )?;
    let (original_inputs, roles) = if supersession.runtime_replacement_started {
        let activation = load_activation_intent(installation, old, previous)?;
        model::require_transition_model(
            installation,
            parent,
            previous,
            &old.parent_session.model,
            &old.helper_model,
            &data.model,
            true,
        )?;
        (
            activation.inputs,
            activation.services.into_iter().collect::<BTreeSet<_>>(),
        )
    } else {
        require(data.model == old.helper_model)?;
        (old.helper_inputs.clone(), BTreeSet::new())
    };
    require(data.stopped_services == roles)?;
    require(
        data.runtime_generation_root
            == runtime_root_before(
                installation,
                old,
                previous,
                parent,
                supersession.runtime_replacement_started,
            )?,
    )?;
    let files = input_files(&original_inputs)?;
    let configuration = if supersession.runtime_replacement_started {
        load_activation_intent(installation, old, previous)?.configuration_sha256
    } else {
        old.helper_configuration_sha256.clone()
    };
    let authority = CreateAuthority {
        project: &original_inputs.project,
        engine: &old.engine_id,
        configuration: &configuration,
        input_files: &files,
        prior,
        allowed: &roles,
    };
    let mut creates = supersession.original_create_intents.clone();
    for (operation, digest) in recorded_creates(
        installation,
        supersession.scope(),
        "supersede-create",
        &authority,
    )? {
        require(
            supersession.runtime_replacement_started && creates.insert(operation, digest).is_none(),
        )?;
    }
    require(creates == data.create_intents)?;
    for (role, before) in &prior.containers {
        let after = resources.containers.get(role).ok_or(REFUSED)?;
        require(if roles.contains(role) {
            !before.setup && !after.setup && before.image == after.image && before.id != after.id
        } else {
            before == after
        })?;
    }
    require_replacements_authorized(installation, &data.create_intents, prior, resources, &roles)?;
    let mut expected = original_inputs;
    expected.profiles = old.parent_session.inputs.profiles.clone();
    expected.services.clear();
    expected.prior = Some(receipt.clone());
    require(encode(&expected)? == encode(&data.inputs)?)?;
    installer_compose::verify_input_files(installation, &receipt.input_files)
}

fn runtime_root_before(
    installation: &Path,
    old: &Intent,
    previous: &GenerationBinding,
    parent: &GenerationBinding,
    replaced: bool,
) -> Result<PathBuf> {
    if replaced {
        return previous.secret_dir(installation);
    }
    if old.attempt == 0 {
        return parent.secret_dir(installation);
    }
    // The immediately preceding attempt is already authenticated by the
    // forward binding walk. Read its exact pinned baseline without recursion.
    let bytes = read(installation, &old.scope().record("supersession-baseline"))?;
    require(old.recovery_baseline_sha256.as_deref() == Some(hash(&bytes).as_str()))?;
    let baseline: Baseline = decode(&bytes)?;
    require(baseline.sequence == old.sequence && baseline.attempt == old.attempt)?;
    Ok(baseline.runtime_generation_root)
}

/// The binding owner supplies already-verified adjacent attempts and their
/// common selected parent during one forward walk. No ancestry is recursively
/// reloaded here, and another attempt's outputs cannot substitute by sequence.
pub(crate) fn require_completed_attempt_link(
    installation: &Path,
    current: &GenerationBinding,
    parent: &GenerationBinding,
    previous: &GenerationBinding,
    previous_metadata: &crate::installer_public_ingress::PublicIngressMetadata,
) -> Result<()> {
    let scope = current.attempt_id();
    require(
        scope.number > 0
            && previous.sequence() == scope.sequence
            && previous.attempt().checked_add(1) == Some(scope.number)
            && parent.sequence().checked_add(1) == Some(scope.sequence)
            && current.parent_attempt() == parent.attempt()
            && previous.parent_attempt() == parent.attempt(),
    )?;
    let supersession: Supersession =
        decode(&read(installation, &scope.record("supersession-intent"))?)?;
    let old: Intent = decode(&read(installation, &previous.record_name("intent"))?)?;
    require_supersession(
        installation,
        &supersession,
        &old,
        previous,
        previous_metadata,
    )?;
    require(
        supersession.scope() == scope && supersession.parent_binding_sha256 == parent.sha256()?,
    )?;
    let bytes = read(installation, &scope.record("supersession-baseline"))?;
    let baseline: Baseline = decode(&bytes)?;
    require_baseline(
        installation,
        &supersession,
        &old,
        previous,
        parent,
        &baseline,
    )?;
    let next: Intent = decode(&read(installation, &current.record_name("intent"))?)?;
    require(
        next.scope() == scope
            && next.parent_attempt == parent.attempt()
            && next.parent_binding_sha256 == parent.sha256()?
            && next.recovery_baseline_sha256.as_deref() == Some(hash(&bytes).as_str())
            && encode(&next.parent_session)? == encode(&old.parent_session)?
            && next.created_at >= baseline.observed_at
            && encode(next.helper_inputs.prior.as_ref().ok_or(REFUSED)?)?
                == encode(baseline.inputs.prior.as_ref().ok_or(REFUSED)?)?,
    )?;
    Ok(())
}

pub(super) fn require_intent_baseline(
    view: &LockedInspection,
    installation: &Path,
    intent: &Intent,
) -> Result<()> {
    if intent.attempt == 0 {
        return require(intent.recovery_baseline_sha256.is_none());
    }
    let baseline = load_baseline(view, installation, intent.scope())?;
    require(
        intent.recovery_baseline_sha256.as_deref() == Some(baseline.sha256())
            && encode(intent.helper_inputs.prior.as_ref().ok_or(REFUSED)?)?
                == encode(baseline.receipt()?)?
            && intent.created_at >= baseline.data.observed_at,
    )
}
pub(super) fn runtime_root_for_intent(
    installation: &Path,
    intent: &Intent,
) -> Result<Option<PathBuf>> {
    let Some(expected) = &intent.recovery_baseline_sha256 else {
        return Ok(None);
    };
    let bytes = read(
        installation,
        &intent.scope().record("supersession-baseline"),
    )?;
    require(hash(&bytes) == *expected)?;
    let value: Baseline = decode(&bytes)?;
    require(value.sequence == intent.sequence && value.attempt == intent.attempt)?;
    Ok(Some(value.runtime_generation_root))
}

fn previous_session(
    installation: &Path,
    docker: &Path,
    runtime: &crate::installer_state::RuntimeBinding,
    old: &Intent,
    binding: &GenerationBinding,
    replacement: bool,
) -> Result<(
    ComposeSession,
    ComposeInputs,
    GenerationOperation,
    BTreeSet<String>,
)> {
    let (inputs, kind, roles) = if replacement {
        let activation = load_activation_intent(installation, old, binding)?;
        (
            activation.inputs,
            GenerationOperation::Activate,
            activation.services.into_iter().collect(),
        )
    } else {
        (
            old.helper_inputs.clone(),
            GenerationOperation::Candidate,
            BTreeSet::new(),
        )
    };
    let session = ComposeSession::new_generation(docker, runtime, inputs.clone())?;
    Ok((session, inputs, kind, roles))
}

fn creation_authority(
    installation: &Path,
    value: &Supersession,
    session: &ComposeSession,
    original: &ProjectResources,
    roles: &BTreeSet<String>,
) -> Result<BTreeMap<String, String>> {
    let mut creates = if value.runtime_replacement_started {
        authorized_creates(
            installation,
            value.previous(),
            "activate-create",
            session,
            original,
            roles,
        )?
    } else {
        BTreeMap::new()
    };
    require(creates == value.original_create_intents)?;
    for (operation, digest) in authorized_creates(
        installation,
        value.scope(),
        "supersede-create",
        session,
        original,
        roles,
    )? {
        require(value.runtime_replacement_started && creates.insert(operation, digest).is_none())?;
    }
    Ok(creates)
}

fn observe_previous(
    installation: &Path,
    value: &Supersession,
    old: &Intent,
    session: &ComposeSession,
    kind: GenerationOperation,
    roles: &BTreeSet<String>,
) -> Result<(ProjectResources, BTreeMap<String, String>)> {
    let observed = session.observe_generation_transition(kind)?;
    let helper = completed_helper(installation, old)?;
    let original = helper.resources.as_ref().ok_or(REFUSED)?;
    let creates = creation_authority(installation, value, session, original, roles)?;
    require_replacements_authorized(installation, &creates, original, &observed, roles)?;
    require(
        observed.containers.get("installer-generation")
            == original.containers.get("installer-generation"),
    )?;
    let rows = session.status()?;
    let expected = observed
        .containers
        .get("installer-generation")
        .ok_or(REFUSED)?;
    require(
        rows.iter()
            .filter(|row| row["Service"] == "installer-generation")
            .count()
            == 1
            && rows.iter().any(|row| {
                row["Service"] == "installer-generation"
                    && row["ID"] == expected.id
                    && row["State"] == "exited"
                    && row["ExitCode"] == 0
            }),
    )?;
    Ok((observed, creates))
}

fn admit(
    installation: &Path,
    docker: &Path,
    state: &mut LockedMaintenance,
    old: &Intent,
    previous: &GenerationBinding,
) -> Result<Supersession> {
    let scope = Attempt::new(old.sequence, old.attempt.checked_add(1).ok_or(REFUSED)?);
    if optional(installation, &scope.record("supersession-intent"))?.is_some() {
        return load_supersession(state.inspection(), installation, scope);
    }
    crate::installer_lifecycle::require_recorded_running_intent(state.inspection(), installation)?;
    crate::installer_root_retirement::require_no_pending_for_generation(state.inspection())?;
    require(old.scope() == previous.attempt_id())?;
    let selected = generation::load_verified(installation, &old.installation_id, &old.engine_id)?
        .ok_or(REFUSED)?;
    require(
        selected.sequence().checked_add(1) == Some(old.sequence)
            && selected.attempt() == old.parent_attempt
            && selected.sha256()? == old.parent_binding_sha256,
    )?;
    let helper = completed_helper(installation, old)?;
    let original = helper.resources.as_ref().ok_or(REFUSED)?;
    let mut creates = BTreeMap::new();
    let mut replacement = false;
    if optional(installation, &old.scope().record("activation-intent"))?.is_some() {
        let (session, _, kind, roles) = previous_session(
            installation,
            docker,
            state.journal().runtime().ok_or(REFUSED)?,
            old,
            previous,
            true,
        )?;
        let observed = admitted_transition(installation, old, &session, kind)?;
        creates = authorized_creates(
            installation,
            old.scope(),
            "activate-create",
            &session,
            original,
            &roles,
        )?;
        replacement = !creates.is_empty()
            || roles
                .iter()
                .any(|role| observed.containers.get(role) != original.containers.get(role));
    }
    let (session, _, kind, _) = previous_session(
        installation,
        docker,
        state.journal().runtime().ok_or(REFUSED)?,
        old,
        previous,
        replacement,
    )?;
    let observed = admitted_transition(installation, old, &session, kind)?;
    require(
        observed.containers.get("installer-generation")
            == original.containers.get("installer-generation"),
    )?;
    let expected = original
        .containers
        .get("installer-generation")
        .ok_or(REFUSED)?;
    require(session.status()?.iter().any(|row| {
        row["Service"] == "installer-generation"
            && row["ID"] == expected.id
            && row["State"] == "exited"
            && row["ExitCode"] == 0
    }))?;
    let at = now()?;
    let reason = stale_material(installation, previous, at)?.ok_or(REFUSED)?;
    let metadata = previous
        .public_ingress_metadata(installation)?
        .ok_or(REFUSED)?;
    let value = Supersession {
        schema: SUPERSESSION_SCHEMA.into(),
        installation_id: old.installation_id.clone(),
        engine_id: old.engine_id.clone(),
        sequence: scope.sequence,
        attempt: scope.number,
        previous_attempt: old.attempt,
        parent_attempt: old.parent_attempt,
        parent_binding_sha256: old.parent_binding_sha256.clone(),
        parent_session_sha256: hash(&encode(&old.parent_session)?),
        previous_evidence_sha256: old_evidence(installation, old.scope())?,
        previous_container_id: expected.id.clone(),
        previous_token_observed_at: metadata.token_observed_at,
        previous_credential_fresh_until: metadata
            .token_observed_at
            .checked_add(1800)
            .ok_or(REFUSED)?,
        previous_certificate_not_after: metadata.certificate_admission["not_after"]
            .as_u64()
            .ok_or(REFUSED)?,
        reason,
        runtime_replacement_started: replacement,
        original_create_intents: creates,
        before_resources: observed,
        observed_at: at,
    };
    require_supersession(installation, &value, old, previous, &metadata)?;
    store(
        state,
        &scope.record("supersession-intent"),
        &encode(&value)?,
    )?;
    load_supersession(state.inspection(), installation, scope)
}

fn capture_baseline(
    installation: &Path,
    docker: &Path,
    state: &mut LockedMaintenance,
    value: &Supersession,
) -> Result<GenerationRecoveryBaseline> {
    let scope = value.scope();
    if optional(installation, &scope.record("supersession-baseline"))?.is_some() {
        let saved = load_baseline(state.inspection(), installation, scope)?;
        saved.require_live(docker, state.journal().runtime().ok_or(REFUSED)?)?;
        return Ok(saved);
    }
    crate::installer_lifecycle::require_recorded_running_intent(state.inspection(), installation)?;
    crate::installer_root_retirement::require_no_pending_for_generation(state.inspection())?;
    let old = load_intent(state.inspection(), installation, value.previous())?;
    let previous = generation::load_attempt(installation, value.sequence, value.previous_attempt)?;
    let (session, mut inputs, kind, roles) = previous_session(
        installation,
        docker,
        state.journal().runtime().ok_or(REFUSED)?,
        &old,
        &previous,
        value.runtime_replacement_started,
    )?;
    observe_previous(installation, value, &old, &session, kind, &roles)?;
    if value.runtime_replacement_started {
        let stop = operation(state.inspection(), scope, "supersede-stop")?;
        session.stop_generation_consumers(state, &stop)?;
        let (observed, _) = observe_previous(installation, value, &old, &session, kind, &roles)?;
        let helper = completed_helper(installation, &old)?;
        let original = helper.resources.as_ref().ok_or(REFUSED)?;
        let incomplete = roles.iter().any(|role| {
            observed.containers.get(role).is_none_or(|current| {
                original
                    .containers
                    .get(role)
                    .is_some_and(|before| before.id == current.id)
            })
        });
        if incomplete {
            let create = operation(state.inspection(), scope, "supersede-create")?;
            // This closes only the already authorized stale footprint. Every
            // new container remains stopped and the old selector is retained.
            session.create_generation_replacements(state, &create, kind)?;
        }
    }
    let op = operation(state.inspection(), scope, "supersede-observe")?;
    observe_previous(installation, value, &old, &session, kind, &roles)?;
    let observed = session.observe_created_generation(state, &op, kind)?;
    let (_, creates) = observe_previous(installation, value, &old, &session, kind, &roles)?;
    require_baseline_status(
        observed.resources.as_ref().ok_or(REFUSED)?,
        &observed.status,
        &roles,
    )?;
    inputs.prior = Some(observed);
    inputs.services.clear();
    inputs.profiles = old.parent_session.inputs.profiles.clone();
    let complete = ComposeSession::new_generation(
        docker,
        state.journal().runtime().ok_or(REFUSED)?,
        inputs.clone(),
    )?;
    let model = complete.model().clone();
    let configuration_sha256 = complete.configuration_sha256().to_owned();
    let op = operation(state.inspection(), scope, "supersede-baseline")?;
    let receipt = complete.checkpoint_generation_baseline(state, &op, &roles)?;
    let observation = native_reference(state, &receipt)?;
    inputs.prior = Some(receipt);
    let data = Baseline {
        schema: BASELINE_SCHEMA.into(),
        installation_id: value.installation_id.clone(),
        engine_id: value.engine_id.clone(),
        sequence: scope.sequence,
        attempt: scope.number,
        supersession_sha256: hash(&read(installation, &scope.record("supersession-intent"))?),
        inputs,
        model,
        configuration_sha256,
        observation,
        create_intents: creates,
        stopped_services: roles,
        runtime_generation_root: runtime_root_before(
            installation,
            &old,
            &previous,
            &old.parent(installation)?,
            value.runtime_replacement_started,
        )?,
        observed_at: now()?,
        activation_performed: false,
        installation_ready: false,
    };
    require_baseline(
        installation,
        value,
        &old,
        &previous,
        &old.parent(installation)?,
        &data,
    )?;
    store(
        state,
        &scope.record("supersession-baseline"),
        &encode(&data)?,
    )?;
    load_baseline(state.inspection(), installation, scope)
}

/// Find the last immutable attempt for the one next selected sequence. The
/// latest supersession authenticates all completed predecessor attempts in a
/// forward binding walk; directory enumeration must not silently skip a gap.
pub(super) fn pending_scope(
    view: &LockedInspection,
    installation: &Path,
    current: &GenerationBinding,
) -> Result<Option<Attempt>> {
    view.require_path_binding(installation)?;
    let sequence = current.sequence().checked_add(1).ok_or(REFUSED)?;
    let first = Attempt::new(sequence, 0);
    let held = directory(&installation.join("evidence"))?;
    let names = fs::file_names(&held, REFUSED)?;
    let prefix = format!("generation-{sequence:020}-attempt-");
    let mut numbers = BTreeSet::new();
    for name in &names {
        let Some(suffix) = name.strip_prefix(&prefix) else {
            continue;
        };
        let (number, _) = suffix.split_once('-').ok_or(REFUSED)?;
        require(number.len() == 20 && number.bytes().all(|value| value.is_ascii_digit()))?;
        let number: u64 = number.parse().map_err(|_| REFUSED)?;
        require(number > 0)?;
        numbers.insert(number);
    }
    for (index, number) in numbers.iter().enumerate() {
        require(
            u64::try_from(index)
                .ok()
                .and_then(|value| value.checked_add(1))
                == Some(*number)
                && names.contains(&Attempt::new(sequence, *number).record("supersession-intent")),
        )?;
    }
    if !names.contains(&first.record("intent")) {
        require(numbers.is_empty())?;
        fs::require_directory_binding(&installation.join("evidence"), &held, REFUSED)?;
        view.require_unchanged()?;
        return Ok(None);
    }
    let scope = Attempt::new(sequence, numbers.last().copied().unwrap_or(0));
    if scope.number > 0 {
        let value = load_supersession(view, installation, scope)?;
        require(
            value.parent_attempt == current.attempt()
                && value.parent_binding_sha256 == current.sha256()?,
        )?;
    } else {
        let value = load_intent(view, installation, scope)?;
        require(
            value.parent_attempt == current.attempt()
                && value.parent_binding_sha256 == current.sha256()?,
        )?;
    }
    fs::require_directory_binding(&installation.join("evidence"), &held, REFUSED)?;
    view.require_unchanged()?;
    Ok(Some(scope))
}

pub(super) fn supersede(
    installation: &Path,
    docker: &Path,
    state: &mut LockedMaintenance,
    old: &Intent,
    previous: &GenerationBinding,
) -> Result<GenerationBinding> {
    let value = admit(installation, docker, state, old, previous)?;
    resume(installation, docker, state, value.scope())
}

pub(super) fn resume(
    installation: &Path,
    docker: &Path,
    state: &mut LockedMaintenance,
    scope: Attempt,
) -> Result<GenerationBinding> {
    require(scope.number > 0 && optional(installation, &scope.record("intent"))?.is_none())?;
    let value = load_supersession(state.inspection(), installation, scope)?;
    let baseline = capture_baseline(installation, docker, state, &value)?;
    baseline.require_selected(state.inspection(), installation)?;
    let parent = generation::load_attempt(installation, scope.sequence - 1, value.parent_attempt)?;
    let previous = generation::load_attempt(installation, scope.sequence, value.previous_attempt)?;
    let candidate = super::super::schedule::candidate_for_recovery(
        installation,
        docker,
        state,
        &parent,
        &previous,
        &baseline,
    )?;
    // This immutable intent is the sole new helper authority. A response lost
    // after it is written returns through the ordinary attempt dispatcher.
    let intent = begin(
        installation,
        docker,
        state,
        &parent,
        &candidate,
        scope,
        Some(&baseline),
    )?;
    reconcile(installation, docker, state, &intent, false)
}

/// An intentional stop must work even between supersession and the new
/// helper intent. It neither converges a stale footprint nor starts a helper.
pub(super) fn stop_before_attempt(
    installation: &Path,
    docker: &Path,
    state: &mut LockedMaintenance,
    scope: Attempt,
) -> Result<Value> {
    require(scope.number > 0 && optional(installation, &scope.record("intent"))?.is_none())?;
    let value = load_supersession(state.inspection(), installation, scope)?;
    let old = load_intent(state.inspection(), installation, value.previous())?;
    let previous = generation::load_attempt(installation, scope.sequence, value.previous_attempt)?;
    let (session, _, kind, roles) = previous_session(
        installation,
        docker,
        state.journal().runtime().ok_or(REFUSED)?,
        &old,
        &previous,
        value.runtime_replacement_started,
    )?;
    observe_previous(installation, &value, &old, &session, kind, &roles)?;
    let op = operation(state.inspection(), scope, "supersede-pause")?;
    let receipt = session.stop_generation_runtime(state, &op, kind)?;
    Ok(json!({"schema":"elevenid.installer-generation-stop/v1",
        "installation_id":value.installation_id,"sequence":scope.sequence,"attempt":scope.number,
        "command_succeeded":receipt.command_succeeded,"observation_validated":receipt.observation_validated,
        "activation_advanced":false,"supersession_pending":true,"producer_replayed":false,
        "producer_start_outcome_unknown":false,"producer_failed":false,"producer_completion_admitted":false,
        "installation_ready":false,"compose_receipt":receipt}))
}

#[cfg(test)]
#[path = "installer_generation_supersession_tests.rs"]
mod tests;
