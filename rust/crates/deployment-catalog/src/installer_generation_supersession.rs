//! A completed stale producer can authorize one new immutable attempt. The
//! selected generation does not advance until fresh native activation succeeds.
use super::*;

#[path = "installer_generation_unused.rs"]
mod unused;

const SUPERSESSION_SCHEMA: &str = "elevenid.installer-generation-supersession/v1";
const BASELINE_SCHEMA: &str = "elevenid.installer-generation-recovery-baseline/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StaleReason {
    CredentialFreshnessElapsed,
    PublicCertificateExpired,
    PrivateCertificateExpired,
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
    data: BaselineRecord,
    digest: String,
}
#[derive(Clone)]
enum BaselineRecord {
    Completed(Box<Baseline>),
    Unused(Box<unused::UnusedPreparation>),
}
impl GenerationRecoveryBaseline {
    pub(crate) fn inputs(&self) -> &ComposeInputs {
        match &self.data {
            BaselineRecord::Completed(value) => &value.inputs,
            BaselineRecord::Unused(value) => &value.inputs,
        }
    }
    pub(super) fn scope(&self) -> Attempt {
        match &self.data {
            BaselineRecord::Completed(value) => Attempt::new(value.sequence, value.attempt),
            BaselineRecord::Unused(value) => value.scope(),
        }
    }
    pub(super) fn sha256(&self) -> &str {
        &self.digest
    }
    pub(super) fn receipt(&self) -> Result<&ComposeReceipt> {
        self.inputs().prior.as_ref().ok_or_else(|| REFUSED.into())
    }
    pub(super) fn runtime_root(&self) -> &Path {
        match &self.data {
            BaselineRecord::Completed(value) => &value.runtime_generation_root,
            BaselineRecord::Unused(value) => &value.runtime_generation_root,
        }
    }
    pub(super) fn observed_at(&self) -> u64 {
        match &self.data {
            BaselineRecord::Completed(value) => value.observed_at,
            BaselineRecord::Unused(value) => value.observed_at,
        }
    }
    fn last_helper(&self) -> Result<Option<Attempt>> {
        match &self.data {
            BaselineRecord::Completed(value) => Ok(Some(Attempt::new(
                value.sequence,
                value.attempt.checked_sub(1).ok_or(REFUSED)?,
            ))),
            BaselineRecord::Unused(value) => Ok(value.last_helper),
        }
    }
    pub(super) fn previous_work(&self, installation: &Path) -> Result<Option<PathBuf>> {
        Ok(self.last_helper()?.map(|value| value.work(installation)))
    }
    fn model(&self) -> &Value {
        match &self.data {
            BaselineRecord::Completed(value) => &value.model,
            BaselineRecord::Unused(value) => &value.model,
        }
    }
    fn configuration_sha256(&self) -> &str {
        match &self.data {
            BaselineRecord::Completed(value) => &value.configuration_sha256,
            BaselineRecord::Unused(value) => &value.configuration_sha256,
        }
    }
    fn stopped_services(&self) -> &BTreeSet<String> {
        match &self.data {
            BaselineRecord::Completed(value) => &value.stopped_services,
            BaselineRecord::Unused(value) => &value.stopped_services,
        }
    }
    fn bytes(&self) -> Result<Vec<u8>> {
        match &self.data {
            BaselineRecord::Completed(value) => encode(value),
            BaselineRecord::Unused(value) => encode(value),
        }
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
        require(retained.digest == self.digest && retained.bytes()? == self.bytes()?)?;
        require(optional(installation, &self.scope().record("intent"))?.is_none())?;
        let selected = generation::load_verified(
            installation,
            &view.journal().installation_id().to_string(),
            &view.journal().runtime().ok_or(REFUSED)?.engine_id,
        )?
        .ok_or(REFUSED)?;
        let (parent_attempt, parent_sha256) = recorded_parent(installation, self.scope())?;
        require(
            selected.sequence().checked_add(1) == Some(self.scope().sequence)
                && selected.attempt() == parent_attempt
                && selected.sha256()? == parent_sha256,
        )?;
        view.require_unchanged()
    }

    pub(crate) fn require_live(
        &self,
        docker: &Path,
        runtime: &crate::installer_state::RuntimeBinding,
    ) -> Result<()> {
        let session = ComposeSession::new_generation(docker, runtime, self.inputs().clone())?;
        require(
            session.model() == self.model()
                && session.configuration_sha256() == self.configuration_sha256()
                && session.observe_resources()?
                    == *self.receipt()?.resources.as_ref().ok_or(REFUSED)?,
        )?;
        require_baseline_status(
            self.receipt()?.resources.as_ref().ok_or(REFUSED)?,
            &session.status()?,
            self.stopped_services(),
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
    stale_from_material(
        installation,
        binding,
        &GenerationMaterial::load(installation, binding)?,
        at,
    )
}
fn stale_from_material(
    installation: &Path,
    binding: &GenerationBinding,
    material: &GenerationMaterial,
    at: u64,
) -> Result<Option<StaleReason>> {
    if let GenerationMaterial::Public(metadata) = material {
        require(binding.public_ingress())?;
        return stale_metadata(
            metadata,
            &binding.read(installation, "installer_ingress_tls_cert")?,
            at,
        );
    }
    require(binding.managed_ingress())?;
    let (_, due) =
        super::super::schedule::credential_due(material.observed_at(), material.ttl(), at)?;
    material.validate_historical(installation, binding)?;
    let before = material.not_before(installation, binding)?;
    let after = material.expires_at()?;
    require(at >= before && after > before)?;
    if at >= after {
        return Ok(Some(StaleReason::PrivateCertificateExpired));
    }
    material.validate_selected_at(installation, binding, at)?;
    Ok(due.then_some(StaleReason::CredentialFreshnessElapsed))
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
    let intent: Intent = decode(&read(installation, &scope.record("intent"))?)?;
    require(intent.scope() == scope)?;
    let plan_kind = match intent.source()? {
        PlanSource::Public => "public-ingress-plan",
        PlanSource::Managed => "managed-renewal-plan",
    };
    let mut result = BTreeMap::new();
    for kind in [
        "intent",
        plan_kind,
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
            plan_kind,
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
    let metadata = GenerationMaterial::load(installation, &previous)?;
    require_supersession(installation, &value, &intent, &previous, &metadata)?;
    view.require_unchanged()?;
    Ok(value)
}

fn require_supersession(
    installation: &Path,
    value: &Supersession,
    intent: &Intent,
    previous: &GenerationBinding,
    metadata: &GenerationMaterial,
) -> Result<()> {
    let helper = completed_helper(installation, intent)?;
    require(match intent.source()? {
        PlanSource::Public => previous.public_ingress(),
        PlanSource::Managed => previous.managed_ingress(),
    })?;
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
            && value.previous_token_observed_at == metadata.observed_at()
            && value.previous_credential_fresh_until
                == metadata.observed_at().checked_add(1800).ok_or(REFUSED)?
            && value.previous_certificate_not_after == metadata.expires_at()?
            && value.observed_at >= intent.created_at
            && stale_from_material(installation, previous, metadata, value.observed_at)?
                == Some(value.reason),
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

fn recorded_parent(installation: &Path, scope: Attempt) -> Result<(u64, String)> {
    let completed = optional(installation, &scope.record("supersession-intent"))?;
    let unused = optional(installation, &scope.record("unused-preparation"))?;
    require(scope.number > 0 && completed.is_some() != unused.is_some())?;
    if let Some(bytes) = completed {
        let value: Supersession = decode(&bytes)?;
        require(value.scope() == scope && value.schema == SUPERSESSION_SCHEMA)?;
        Ok((value.parent_attempt, value.parent_binding_sha256))
    } else {
        let value: unused::UnusedPreparation = decode(&unused.ok_or(REFUSED)?)?;
        require(value.scope() == scope)?;
        Ok((value.parent_attempt, value.parent_binding_sha256))
    }
}

fn load_baseline(
    view: &LockedInspection,
    installation: &Path,
    scope: Attempt,
) -> Result<GenerationRecoveryBaseline> {
    view.require_path_binding(installation)?;
    let (parent_attempt, _) = recorded_parent(installation, scope)?;
    let result = generation::load_preparation_baseline(installation, scope, parent_attempt)?;
    require(
        result.receipt()?.engine_id == view.journal().runtime().ok_or(REFUSED)?.engine_id
            && result.receipt()?.project
                == format!(
                    "marty-install-{}",
                    view.journal().installation_id().simple()
                ),
    )?;
    view.require_unchanged()?;
    Ok(result)
}

// This is only a canonical record reader for an already-verified forward
// lineage or an intent's exact retained digest. It grants no native authority.
fn recorded_baseline(installation: &Path, scope: Attempt) -> Result<GenerationRecoveryBaseline> {
    let completed = optional(installation, &scope.record("supersession-baseline"))?;
    let unused = optional(installation, &scope.record("unused-preparation"))?;
    require(scope.number > 0 && completed.is_some() != unused.is_some())?;
    let (bytes, data) = if let Some(bytes) = completed {
        let value: Baseline = decode(&bytes)?;
        require(
            value.schema == BASELINE_SCHEMA
                && value.sequence == scope.sequence
                && value.attempt == scope.number,
        )?;
        (bytes, BaselineRecord::Completed(Box::new(value)))
    } else {
        let bytes = unused.ok_or(REFUSED)?;
        let value: unused::UnusedPreparation = decode(&bytes)?;
        require(value.scope() == scope)?;
        (bytes, BaselineRecord::Unused(Box::new(value)))
    };
    let result = GenerationRecoveryBaseline {
        data,
        digest: hash(&bytes),
    };
    require(result.bytes()? == bytes)?;
    Ok(result)
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
    // The forward attempt walk already authenticated this exact incoming
    // source, which may cross one or more retired unused preparations.
    let value = recorded_baseline(installation, old.scope())?;
    require(old.recovery_baseline_sha256.as_deref() == Some(value.sha256()))?;
    Ok(value.runtime_root().into())
}

/// Admit one completed predecessor using the already-verified common selected
/// parent. The binding owner calls this in its single forward attempt walk.
pub(crate) fn completed_predecessor(
    installation: &Path,
    parent: &GenerationBinding,
    previous: &GenerationBinding,
    previous_metadata: &GenerationMaterial,
) -> Result<GenerationRecoveryBaseline> {
    let scope = Attempt::new(
        previous.sequence(),
        previous.attempt().checked_add(1).ok_or(REFUSED)?,
    );
    require(
        parent.sequence().checked_add(1) == Some(scope.sequence)
            && previous.parent_attempt() == parent.attempt()
            && optional(installation, &scope.record("unused-preparation"))?.is_none(),
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
    let result = recorded_baseline(installation, scope)?;
    let BaselineRecord::Completed(data) = &result.data else {
        return Err(REFUSED.into());
    };
    require_baseline(installation, &supersession, &old, previous, parent, data)?;
    Ok(result)
}

pub(crate) fn unused_predecessor(
    installation: &Path,
    parent: &crate::installer_generation_binding::VerifiedGeneration,
    previous: Attempt,
    incoming: Option<&GenerationRecoveryBaseline>,
) -> Result<GenerationRecoveryBaseline> {
    unused::historical(installation, parent, previous, incoming)
}

pub(crate) fn require_attempt_incoming(
    installation: &Path,
    current: &GenerationBinding,
    parent: &GenerationBinding,
    incoming: Option<&GenerationRecoveryBaseline>,
) -> Result<()> {
    let scope = current.attempt_id();
    if scope.number == 0 {
        // Keep legacy attempt-zero candidate proofs byte compatible.
        return require(incoming.is_none());
    }
    let baseline = incoming.ok_or(REFUSED)?;
    let next: Intent = decode(&read(installation, &current.record_name("intent"))?)?;
    let saved = match &baseline.data {
        BaselineRecord::Completed(_) => {
            // Preserve the original completed-attempt link and its exact
            // retained parent-session bytes for existing v1 histories.
            let previous = Attempt::new(scope.sequence, scope.number - 1);
            decode::<Intent>(&read(installation, &previous.record("intent"))?)?.parent_session
        }
        BaselineRecord::Unused(_) => unused::recorded_parent_session(installation, parent)?,
    };
    require(
        baseline.scope() == scope
            && next.scope() == scope
            && next.parent_attempt == parent.attempt()
            && next.parent_binding_sha256 == parent.sha256()?
            && next.recovery_baseline_sha256.as_deref() == Some(baseline.sha256())
            && encode(&next.parent_session)? == encode(&saved)?
            && next.created_at >= baseline.observed_at()
            && encode(next.helper_inputs.prior.as_ref().ok_or(REFUSED)?)?
                == encode(baseline.receipt()?)?,
    )
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
            && intent.created_at >= baseline.observed_at(),
    )
}
pub(super) fn runtime_root_for_intent(
    installation: &Path,
    intent: &Intent,
) -> Result<Option<PathBuf>> {
    let Some(expected) = &intent.recovery_baseline_sha256 else {
        return Ok(None);
    };
    let value = recorded_baseline(installation, intent.scope())?;
    require(value.sha256() == expected)?;
    Ok(Some(value.runtime_root().into()))
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
    let metadata = GenerationMaterial::load(installation, previous)?;
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
        previous_token_observed_at: metadata.observed_at(),
        previous_credential_fresh_until: metadata.observed_at().checked_add(1800).ok_or(REFUSED)?,
        previous_certificate_not_after: metadata.expires_at()?,
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
        let next = Attempt::new(sequence, *number);
        require(
            u64::try_from(index)
                .ok()
                .and_then(|value| value.checked_add(1))
                == Some(*number)
                && (names.contains(&next.record("supersession-intent"))
                    != names.contains(&next.record("unused-preparation"))),
        )?;
    }
    if !names.contains(&first.record("intent"))
        && !names.contains(&first.record("public-ingress-plan"))
        && !names.contains(&first.record("managed-renewal-plan"))
    {
        require(numbers.is_empty() && !unused::orphan_evidence(&names, first))?;
        fs::require_directory_binding(&installation.join("evidence"), &held, REFUSED)?;
        view.require_unchanged()?;
        return Ok(None);
    }
    let scope = Attempt::new(sequence, numbers.last().copied().unwrap_or(0));
    if names.contains(&scope.record("intent")) {
        let value = load_intent(view, installation, scope)?;
        require(
            value.parent_attempt == current.attempt()
                && value.parent_binding_sha256 == current.sha256()?,
        )?;
    } else if names.contains(&scope.record("public-ingress-plan")) {
        unused::require_preparation(view, installation, scope, current)?;
    } else if names.contains(&scope.record("managed-renewal-plan")) {
        unused::require_managed_preparation(view, installation, scope, current)?;
    } else if names.contains(&scope.record("unused-preparation")) {
        let value = load_baseline(view, installation, scope)?;
        let (parent_attempt, parent_sha256) = recorded_parent(installation, value.scope())?;
        require(parent_attempt == current.attempt() && parent_sha256 == current.sha256()?)?;
    } else {
        let value = load_supersession(view, installation, scope)?;
        require(
            value.parent_attempt == current.attempt()
                && value.parent_binding_sha256 == current.sha256()?,
        )?;
    }
    fs::require_directory_binding(&installation.join("evidence"), &held, REFUSED)?;
    view.require_unchanged()?;
    Ok(Some(scope))
}

pub(super) fn saved_preparation_status(installation: &Path, scope: Attempt) -> Result<(u64, bool)> {
    unused::saved_status(installation, scope)
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
    require(optional(installation, &scope.record("intent"))?.is_none())?;
    if optional(installation, &scope.record("public-ingress-plan"))?.is_some() {
        return unused::resume_preparation(installation, docker, state, scope);
    }
    if optional(installation, &scope.record("managed-renewal-plan"))?.is_some() {
        return unused::resume_managed_preparation(installation, docker, state, scope);
    }
    require(scope.number > 0)?;
    if optional(installation, &scope.record("unused-preparation"))?.is_some() {
        return unused::resume_retired(installation, docker, state, scope);
    }
    let value = load_supersession(state.inspection(), installation, scope)?;
    let baseline = capture_baseline(installation, docker, state, &value)?;
    baseline.require_selected(state.inspection(), installation)?;
    let parent = generation::load_attempt(installation, scope.sequence - 1, value.parent_attempt)?;
    if parent.managed_ingress() {
        let intent = begin_managed(installation, docker, state, &parent, scope, Some(&baseline))?;
        return reconcile(installation, docker, state, &intent, false);
    }
    require(parent.public_ingress())?;
    let previous = generation::load_attempt(installation, scope.sequence, value.previous_attempt)?;
    let previous = candidate_for_binding(state.inspection(), installation, &previous)?;
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
    require(optional(installation, &scope.record("intent"))?.is_none())?;
    if scope.number == 0
        || optional(installation, &scope.record("unused-preparation"))?.is_some()
        || optional(installation, &scope.record("public-ingress-plan"))?.is_some()
        || optional(installation, &scope.record("managed-renewal-plan"))?.is_some()
    {
        return unused::stop_preparation(installation, docker, state, scope);
    }
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

#[cfg(test)]
fn completed_test_fixture() -> (tempfile::TempDir, GenerationBinding, GenerationBinding) {
    tests::completed_fixture()
}
