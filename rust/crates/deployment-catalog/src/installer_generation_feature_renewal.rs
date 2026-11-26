//! Joint base and feature credential renewal under the existing native lock.
//! Both credential owners finish their immutable material before runtime starts.
use super::*;
use crate::installer_features::generations::{self as features, StagedRenewal};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JointRenewal {
    schema: String,
    installation_id: String,
    engine_id: String,
    baseline_sequence: u64,
    baseline_attempt: u64,
    baseline_binding_sha256: String,
    baseline_helper_sha256: String,
    logical_parent_sha256: String,
    feature_sequence: u32,
    feature_material_sha256: String,
    feature_producer_sha256: String,
}

/// Constructed only from the baseline owner's authenticated candidate and
/// completed producer. It cannot create an arbitrary logical/runtime parent.
pub(crate) struct FeatureRenewalContext {
    logical: SavedSession,
    runtime: SavedSession,
    scope: Attempt,
    binding_sha256: String,
}

impl FeatureRenewalContext {
    pub(crate) fn logical_parent(&self) -> &SavedSession {
        &self.logical
    }
    pub(crate) fn runtime_parent(&self) -> &SavedSession {
        &self.runtime
    }
    pub(crate) fn sequence(&self) -> u64 {
        self.scope.sequence
    }
    pub(crate) fn attempt(&self) -> u64 {
        self.scope.number
    }
    pub(crate) fn binding_sha256(&self) -> &str {
        &self.binding_sha256
    }
}

/// Reconstruct historical producer authority without consulting current feature
/// selection or acquiring a second installation lock. Freshness is a separate
/// activation check; this read must remain valid after old leaves expire.
pub(crate) fn verify_feature_renewal_context(
    installation: &Path,
    sequence: u64,
    attempt: u64,
    binding_sha256: &str,
) -> Result<FeatureRenewalContext> {
    require(sequence > 0 && valid_hash(binding_sha256))?;
    let scope = Attempt::new(sequence, attempt);
    let intent: Intent = decode(&read(installation, &scope.record("intent"))?)?;
    require(
        intent.source().is_ok()
            && intent.scope() == scope
            && intent.helper_inputs.installation == installation
            && intent.helper_configuration_sha256
                == installer_compose::model_sha256(&intent.helper_model)?
            && intent.parent_session.configuration_sha256
                == installer_compose::model_sha256(&intent.parent_session.model)?,
    )?;
    let binding = generation::load_attempt(installation, sequence, attempt)?;
    require(
        binding.sha256()? == binding_sha256
            && binding.installation_id == intent.installation_id
            && binding.engine_id == intent.engine_id
            && binding.parent_attempt() == intent.parent_attempt
            && binding
                .successor
                .as_ref()
                .is_some_and(|next| next.parent_binding_sha256 == intent.parent_binding_sha256),
    )?;
    let raw = read(installation, &scope.record("helper"))?;
    let decoded: ComposeReceipt = decode(&raw)?;
    let helper = native(
        installation,
        &NativeReference {
            operation: decoded.operation.clone(),
            sha256: hash(&raw),
        },
    )?;
    require(
        helper.configuration_sha256 == intent.helper_configuration_sha256
            && helper.project == intent.parent_session.inputs.project
            && helper.engine_id == intent.engine_id,
    )?;
    let before = intent
        .helper_inputs
        .prior
        .as_ref()
        .and_then(|value| value.resources.as_ref())
        .ok_or(REFUSED)?;
    let after = helper.resources.as_ref().ok_or(REFUSED)?;
    require(
        before.networks == after.networks
            && before.volumes == after.volumes
            && before.containers.keys().eq(after.containers.keys())
            && before.containers.iter().all(|(role, old)| {
                role == "installer-generation" || after.containers.get(role) == Some(old)
            }),
    )?;
    for file in intent
        .helper_inputs
        .files
        .iter()
        .chain(std::iter::once(&intent.helper_inputs.environment))
        .chain(&intent.helper_inputs.bound_inputs)
    {
        require(helper.input_files.get(&file.path) == Some(&file.sha256))?;
    }
    installer_compose::verify_input_files(installation, &helper.input_files)?;
    let mut inputs = intent.helper_inputs;
    inputs.prior = Some(helper.clone());
    let runtime = SavedSession {
        schema: "elevenid.installer-compose-session/v1".into(),
        installation_id: intent.installation_id,
        inputs,
        model: intent.helper_model,
        configuration_sha256: intent.helper_configuration_sha256,
        receipt: helper,
    };
    Ok(FeatureRenewalContext {
        logical: intent.parent_session,
        runtime,
        scope,
        binding_sha256: binding_sha256.into(),
    })
}

fn retained(
    installation: &Path,
    scope: Attempt,
) -> Result<Option<(JointRenewal, StagedRenewal, String)>> {
    let Some(raw) = optional(installation, &scope.record("feature-renewal"))? else {
        return Ok(None);
    };
    let value: JointRenewal = decode(&raw)?;
    require(
        value.schema == "elevenid.installer-joint-feature-renewal/v1"
            && value.baseline_sequence == scope.sequence
            && value.baseline_attempt == scope.number
            && value.feature_sequence > 0,
    )?;
    let context = verify_feature_renewal_context(
        installation,
        scope.sequence,
        scope.number,
        &value.baseline_binding_sha256,
    )?;
    let staged = features::load_staged_baseline(installation, value.feature_sequence)?;
    require(
        value.installation_id == context.logical_parent().installation_id
            && value.engine_id == context.runtime_parent().receipt.engine_id
            && value.baseline_helper_sha256 == hash(&read(installation, &scope.record("helper"))?)
            && value.logical_parent_sha256 == hash(&encode(context.logical_parent())?)
            && encode(staged.parent_session())? == encode(context.logical_parent())?
            && value.feature_material_sha256 == staged.material_sha256(installation)?
            && value.feature_producer_sha256
                == crate::installer_jobs::receipt_digest(staged.producer_receipt())?,
    )?;
    Ok(Some((value, staged, hash(&raw))))
}

pub(super) fn prepare(
    installation: &Path,
    docker: &Path,
    state: &mut LockedMaintenance,
    intent: &Intent,
    binding: &GenerationBinding,
) -> Result<()> {
    if let Some((_, staged, _)) = retained(installation, intent.scope())? {
        return staged.require_current(installation);
    }
    // An existing runtime activation is immutable. It must never acquire a
    // later feature selection merely because another clock has become due.
    if optional(installation, &intent.scope().record("activation-intent"))?.is_some()
        || crate::installer_features::at(installation)?.is_none()
    {
        return Ok(());
    }
    let context = verify_feature_renewal_context(
        installation,
        intent.sequence,
        intent.attempt,
        &binding.sha256()?,
    )?;
    let Some(staged) = features::stage_renewal_for_baseline(state, installation, docker, &context)?
    else {
        return Ok(());
    };
    staged.require_current(installation)?;
    require(encode(staged.parent_session())? == encode(&intent.parent_session)?)?;
    let value = JointRenewal {
        schema: "elevenid.installer-joint-feature-renewal/v1".into(),
        installation_id: intent.installation_id.clone(),
        engine_id: intent.engine_id.clone(),
        baseline_sequence: intent.sequence,
        baseline_attempt: intent.attempt,
        baseline_binding_sha256: binding.sha256()?,
        baseline_helper_sha256: hash(&read(installation, &intent.scope().record("helper"))?),
        logical_parent_sha256: hash(&encode(&intent.parent_session)?),
        feature_sequence: staged.sequence(),
        feature_material_sha256: staged.material_sha256(installation)?,
        feature_producer_sha256: crate::installer_jobs::receipt_digest(staged.producer_receipt())?,
    };
    store(
        state,
        &intent.scope().record("feature-renewal"),
        &encode(&value)?,
    )?;
    require(retained(installation, intent.scope())?.is_some())
}

pub(super) fn digest(installation: &Path, scope: Attempt) -> Result<Option<String>> {
    Ok(retained(installation, scope)?.map(|(_, _, digest)| digest))
}

pub(super) fn runtime_parent(
    installation: &Path,
    intent: &Intent,
    baseline_helper: &ComposeReceipt,
) -> Result<ComposeReceipt> {
    Ok(match retained(installation, intent.scope())? {
        Some((_, staged, _)) => staged.producer_receipt().clone(),
        None => baseline_helper.clone(),
    })
}

pub(super) fn project_inputs(
    state: &mut LockedMaintenance,
    installation: &Path,
    intent: &Intent,
    inputs: ComposeInputs,
) -> Result<ComposeInputs> {
    let Some((_, staged, digest)) = retained(installation, intent.scope())? else {
        return Ok(inputs);
    };
    let mut inputs = staged.project_baseline_inputs(state, installation, inputs)?;
    let previous =
        regex::Regex::new(r"\Ageneration-[0-9]{20}(?:-attempt-[0-9]{20})?-feature-renewal\.json\z")
            .map_err(|_| REFUSED)?;
    inputs.bound_inputs.retain(|file| {
        !file
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| previous.is_match(name))
    });
    inputs.bound_inputs.push(BoundFile {
        path: installation
            .join("evidence")
            .join(intent.scope().record("feature-renewal")),
        sha256: digest,
    });
    inputs.prior = Some(staged.producer_receipt().clone());
    Ok(inputs)
}

pub(super) fn retain_helper_roots(
    installation: &Path,
    parent: &SavedSession,
    inputs: &mut ComposeInputs,
) -> Result<()> {
    let service = &parent.model["services"]["installer-feature-identities"];
    if service.is_null() || !features::verify_helper_projection_at(installation, service)? {
        return Ok(());
    }
    // A later baseline-only refresh still observes the retained feature
    // producer. Carry only its individually authenticated mounts, never every
    // historical writable feature directory from the previous input set.
    let root = installation.join(features::ROOT);
    for volume in service["volumes"].as_array().into_iter().flatten() {
        if volume["type"] != "bind" {
            continue;
        }
        let path = installer_compose::config_path(&volume["source"])?;
        if path.starts_with(&root) {
            if volume["read_only"] == true {
                inputs.readonly_bind_roots.insert(path);
            } else {
                require(volume["target"] == "/output")?;
                inputs.writable_bind_roots.insert(path);
            }
        }
    }
    Ok(())
}

pub(crate) fn project_feature_joint_model(
    installation: &Path,
    binding: &GenerationBinding,
    model: &mut Value,
    include_setup: bool,
) -> Result<()> {
    if let Some((joint, staged, _)) = retained(installation, binding.attempt_id())? {
        require(joint.baseline_binding_sha256 == binding.sha256()?)?;
        staged.project_baseline_model(installation, model, include_setup)?;
    }
    Ok(())
}

pub(super) fn require_fresh(installation: &Path, scope: Attempt) -> Result<()> {
    if let Some((_, staged, _)) = retained(installation, scope)? {
        staged.require_current(installation)?;
    }
    Ok(())
}

/// Shared activation receipts are checked by their original native owner.
/// Material validation is independent of feature completion, avoiding a cycle
/// between the baseline journal and the feature journal.
pub(crate) fn verify_feature_joint_activation(
    installation: &Path,
    sequence: u64,
    attempt: u64,
    feature_sequence: u32,
) -> Result<(SavedSession, SavedSession)> {
    let scope = Attempt::new(sequence, attempt);
    let (joint, staged, _) = retained(installation, scope)?.ok_or(REFUSED)?;
    require(joint.feature_sequence == feature_sequence)?;
    let binding = generation::load_attempt(installation, sequence, attempt)?;
    require(binding.sha256()? == joint.baseline_binding_sha256)?;
    let saved: SavedSession = decode(&read(installation, &scope.record("session"))?)?;
    require_activation(installation, scope, &binding, &saved)?;
    Ok((staged.parent_session().clone(), saved))
}

pub(crate) fn feature_joint_activation_observed_at(
    installation: &Path,
    sequence: u64,
    attempt: u64,
    feature_sequence: u32,
) -> Result<u64> {
    verify_feature_joint_activation(installation, sequence, attempt, feature_sequence)?;
    let activation: Activation = decode(&read(
        installation,
        &Attempt::new(sequence, attempt).record("activation"),
    )?)?;
    Ok(activation.observed_at)
}

pub(super) fn complete(
    state: &mut LockedMaintenance,
    installation: &Path,
    scope: Attempt,
) -> Result<()> {
    if let Some((joint, _, _)) = retained(installation, scope)? {
        features::complete_baseline_activation(
            state,
            installation,
            scope.sequence,
            scope.number,
            joint.feature_sequence,
        )?;
    }
    Ok(())
}

pub(super) fn repair_selected_completion(
    state: &mut LockedMaintenance,
    installation: &Path,
) -> Result<()> {
    let Some(pointer) = optional(installation, SELECTOR)? else {
        return Ok(());
    };
    let selector: Selector = decode(&pointer)?;
    let scope = Attempt::new(selector.sequence, selector.attempt);
    if optional(installation, &scope.record("feature-renewal"))?.is_some() {
        // Authenticate the already-published baseline before completing its
        // second journal. No runtime command or producer is repeated here.
        let selected = selected_from(installation, &pointer)?;
        require(selected.binding.attempt_id() == scope)?;
        complete(state, installation, scope)?;
    }
    Ok(())
}
