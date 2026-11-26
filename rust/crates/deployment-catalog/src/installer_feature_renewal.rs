//! Scoped native feature renewal; a retained helper mint is never replayed.
use super::*;
use crate::{
    installer_compose::{BoundFile, ComposeInputs, ComposeSession},
    installer_doctor::SavedSession,
    installer_feature_identity as identity,
};
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};
use x509_cert::{der::DecodePem, Certificate};
const LAYER: &str =
    "deploy-config/compose/selfhost-installer/feature-profile/compose.identities-renew.yml";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Preparation {
    schema: String,
    sequence: u32,
    installation_id: uuid::Uuid,
    feature_profile_sha256: String,
    root_receipt_sha256: String,
    parent_material_sha256: String,
    parent_session: SavedSession,
    parent_session_sha256: String,
    runtime_parent_session: SavedSession,
    baseline_sequence: u64,
    baseline_attempt: u64,
    baseline_binding_sha256: String,
    directory: DirectoryIdentity,
    input_directory: DirectoryIdentity,
    output: identity::RenewalOutputBinding,
    input_sha256: BTreeMap<String, String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProducerPlan {
    schema: String,
    sequence: u32,
    preparation_sha256: String,
    inputs: ComposeInputs,
    model: Value,
    configuration_sha256: String,
}
pub(crate) struct RenewalPermit {
    plan: ProducerPlan,
}

/// A successful, immutable producer result which has not by itself changed
/// any runtime consumer. The activation owner must bind this exact material
/// and receipt before it may start consumers.
pub(crate) struct StagedRenewal {
    material: SelectedMaterial,
    parent: SavedSession,
    producer: crate::installer_compose::ComposeReceipt,
}
impl StagedRenewal {
    pub(crate) fn parent_session(&self) -> &SavedSession {
        &self.parent
    }
    pub(crate) fn producer_receipt(&self) -> &crate::installer_compose::ComposeReceipt {
        &self.producer
    }
    pub(crate) fn sequence(&self) -> u32 {
        self.material.sequence
    }
    pub(crate) fn material_record(&self) -> String {
        self.material.record()
    }
    pub(crate) fn material_sha256(&self, installation: &Path) -> Result<String> {
        let raw = read_record(installation, &self.material.record())?;
        require(encoded(&decode_record::<SelectedMaterial>(&raw)?)? == encoded(&self.material)?)?;
        Ok(digest(&raw))
    }
    pub(crate) fn require_current(&self, installation: &Path) -> Result<()> {
        self.require_usable_at(installation, now()?)
    }
    pub(crate) fn require_usable_at(&self, installation: &Path, at: u64) -> Result<()> {
        require_parent(installation, self.material.sequence, &self.parent)?;
        require_fresh_at(installation, &self.material, at)
    }

    pub(crate) fn project_baseline_inputs(
        &self,
        state: &mut LockedMaintenance,
        installation: &Path,
        mut inputs: ComposeInputs,
    ) -> Result<ComposeInputs> {
        self.require_current(installation)?;
        let previous = super::super::for_inputs(&self.parent.inputs)?.ok_or(REFUSED)?;
        let selected = super::super::for_inputs(&inputs)?.ok_or(REFUSED)?;
        require(
            previous.configuration == selected.configuration
                && previous.generation.as_ref().map(SelectedMaterial::record)
                    == selected.generation.as_ref().map(SelectedMaterial::record),
        )?;
        let old = previous.projection_directory(installation);
        let new = self.material.directory(installation);
        let child = installation
            .join(ROOT)
            .join(format!("{:06}", self.sequence()));
        clear_producer_bindings(&mut inputs);
        inputs.bound_inputs.retain(|file| {
            !file
                .path
                .file_name()
                .and_then(|v| v.to_str())
                .is_some_and(|name| {
                    name.starts_with("generation-feature-") && name.ends_with("-binding.json")
                })
        });
        for record in [self.material.record(), name(self.sequence(), "preparation")] {
            inputs
                .bound_inputs
                .push(crate::installer_application::bound(
                    installation.join("evidence").join(record),
                )?);
        }
        for file in identity::renewal_input_names() {
            inputs
                .bound_inputs
                .push(crate::installer_application::bound(
                    child.join("input").join(file),
                )?);
        }
        inputs.files.retain(|file| {
            !file
                .path
                .ends_with("feature-profile/compose.identities.yml")
                && !file
                    .path
                    .ends_with("feature-profile/compose.identities-renew.yml")
        });
        let bundle = inputs
            .files
            .first()
            .and_then(|file| file.path.parent())
            .ok_or(REFUSED)?
            .to_owned();
        append_layer(
            &mut inputs,
            crate::installer_application::bundle_bound(&bundle, LAYER)?,
        );
        inputs
            .readonly_bind_roots
            .extend([old.clone(), new.clone(), child.join("input")]);
        inputs.writable_bind_roots.insert(child.join("output"));
        let source = crate::installer_verify::read_private_bytes(&inputs.environment.path, 65_536)?;
        let text = std::str::from_utf8(&source).map_err(|_| REFUSED)?;
        let mut env = Vec::new();
        let mut roots = 0;
        let mut work = 0;
        for line in text.lines() {
            if let Some(value) = line.strip_prefix("FEATURE_PROFILE_SECRET_DIR=") {
                require(value == format!("'{}'", old.to_str().ok_or(REFUSED)?))?;
                roots += 1;
                env.extend_from_slice(
                    format!(
                        "FEATURE_PROFILE_SECRET_DIR='{}'\n",
                        new.to_str().ok_or(REFUSED)?
                    )
                    .as_bytes(),
                );
            } else if line.starts_with("FEATURE_IDENTITY_WORK_DIR=") {
                work += 1;
            } else {
                env.extend_from_slice(line.as_bytes());
                env.push(b'\n');
            }
        }
        require(roots == 1 && work <= 1)?;
        env.extend_from_slice(
            format!(
                "FEATURE_IDENTITY_WORK_DIR='{}'\n",
                child.to_str().ok_or(REFUSED)?
            )
            .as_bytes(),
        );
        let env_name = format!(
            "generation-feature-{:06}-baseline-application.env",
            self.sequence()
        );
        store_once(state, installation, &env_name, &env)?;
        inputs.environment = BoundFile {
            path: installation.join("evidence").join(env_name),
            sha256: digest(&env),
        };
        inputs.prior = Some(self.producer.clone());
        Ok(inputs)
    }

    pub(crate) fn project_baseline_model(
        &self,
        installation: &Path,
        model: &mut Value,
        include_setup: bool,
    ) -> Result<()> {
        // This is a historical comparison and deliberately has no wall-clock
        // freshness check. Starting consumers separately requires_current.
        let retained = load_staged_baseline(installation, self.sequence())?;
        require(
            retained.material_sha256(installation)? == self.material_sha256(installation)?
                && encoded(retained.parent_session())? == encoded(self.parent_session())?,
        )?;
        let previous = super::super::for_inputs(&self.parent.inputs)?.ok_or(REFUSED)?;
        let old = previous.projection_directory(installation);
        let new = self.material.directory(installation);
        for service in model["services"]
            .as_object_mut()
            .ok_or(REFUSED)?
            .values_mut()
        {
            for volume in service["volumes"].as_array_mut().into_iter().flatten() {
                if volume["type"] != "bind" {
                    continue;
                }
                let source = crate::installer_compose::config_path(&volume["source"])?;
                if source.starts_with(&old) {
                    require(source.parent() == Some(old.as_path()))?;
                    volume["source"] = json!(new
                        .join(source.file_name().ok_or(REFUSED)?)
                        .to_str()
                        .ok_or(REFUSED)?
                        .replace('$', "$$"));
                }
            }
        }
        if include_setup {
            let plan: ProducerPlan = decode_record(&read_record(
                installation,
                &name(self.sequence(), "producer-plan"),
            )?)?;
            require(
                plan.configuration_sha256 == crate::installer_compose::model_sha256(&plan.model)?
                    && plan.model["services"]["installer-feature-identities"].is_object(),
            )?;
            identity::validate_renewal_model_at(installation, self.sequence(), &plan.model)?;
            model["services"]["installer-feature-identities"] =
                plan.model["services"]["installer-feature-identities"].clone();
        }
        Ok(())
    }
}
impl RenewalPermit {
    pub(crate) fn sequence(&self) -> u32 {
        self.plan.sequence
    }
    pub(crate) fn operation(&self, phase: &str) -> String {
        format!("feature-{:06}-{phase}", self.plan.sequence)
    }
    pub(crate) fn require_session(&self, inputs: &ComposeInputs, model: &Value) -> Result<()> {
        require(
            encoded(inputs)? == encoded(&self.plan.inputs)?
                && *model == self.plan.model
                && crate::installer_compose::model_sha256(model)? == self.plan.configuration_sha256,
        )?;
        let raw = read_record(
            &inputs.installation,
            &name(self.plan.sequence, "producer-plan"),
        )?;
        require(encoded(&decode_record::<ProducerPlan>(&raw)?)? == encoded(&self.plan)?)?;
        let (preparation, raw) = preparation(&inputs.installation, self.plan.sequence)?;
        require(
            self.plan.schema == "elevenid.installer-feature-renewal-producer-plan/v1"
                && self.plan.preparation_sha256 == digest(&raw)
                && encoded(inputs.prior.as_ref().ok_or(REFUSED)?)?
                    == encoded(&preparation.runtime_parent_session.receipt)?,
        )?;
        verify_preparation_at(&inputs.installation, self.plan.sequence)?;
        identity::validate_renewal_model_at(&inputs.installation, self.plan.sequence, model)
    }
}
fn name(sequence: u32, suffix: &str) -> String {
    format!("generation-feature-{sequence:06}-{suffix}.json")
}
fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_secs())
        .map_err(|_| REFUSED.into())
}
pub(super) fn require_parent(
    installation: &Path,
    sequence: u32,
    parent: &SavedSession,
) -> Result<()> {
    let (preparation, _) = preparation(installation, sequence)?;
    require(
        preparation.parent_session_sha256 == digest(&encoded(parent)?)
            && encoded(&preparation.parent_session)? == encoded(parent)?,
    )
}
fn preparation(installation: &Path, sequence: u32) -> Result<(Preparation, Vec<u8>)> {
    let raw = read_record(installation, &name(sequence, "preparation"))?;
    let value: Preparation = decode_record(&raw)?;
    let (_, root, root_raw) = root_at(installation)?.ok_or(REFUSED)?;
    require(
        value.schema == "elevenid.installer-feature-renewal-preparation/v1"
            && value.sequence == sequence
            && sequence > 0
            && value.installation_id == root.installation_id
            && value.feature_profile_sha256 == root.feature_profile_sha256
            && value.root_receipt_sha256 == digest(&root_raw)
            && value.parent_session_sha256 == digest(&encoded(&value.parent_session)?)
            && value.parent_material_sha256
                == if sequence == 1 {
                    digest(&root_raw)
                } else {
                    digest(&read_record(installation, &name(sequence - 1, "binding"))?)
                },
    )?;
    let context = crate::installer_generation_maintenance::verify_feature_renewal_context(
        installation,
        value.baseline_sequence,
        value.baseline_attempt,
        &value.baseline_binding_sha256,
    )?;
    require(
        encoded(context.logical_parent())? == encoded(&value.parent_session)?
            && encoded(context.runtime_parent())? == encoded(&value.runtime_parent_session)?,
    )?;
    Ok((value, raw))
}
pub(super) fn verify_preparation_at(installation: &Path, sequence: u32) -> Result<()> {
    let (value, _) = preparation(installation, sequence)?;
    let path = installation.join(ROOT).join(format!("{sequence:06}"));
    let child = fs::directory(&path, REFUSED)?;
    let before = DirectoryIdentity::observe(&child)?;
    require(value.directory.matches(before.clone()))?;
    let names = fs::file_names(&child, REFUSED)?;
    require(
        names == BTreeSet::from(["input".into(), "output".into()])
            || names == BTreeSet::from(["input".into(), "output".into(), "files".into()]),
    )?;
    let input = fs::open_child(&child, "input", libc::O_RDONLY | libc::O_DIRECTORY, REFUSED)?;
    require(
        value
            .input_directory
            .matches(DirectoryIdentity::observe(&input)?),
    )?;
    require(
        fs::file_names(&input, REFUSED)? == value.input_sha256.keys().cloned().collect()
            && value.input_sha256.keys().cloned().collect::<BTreeSet<_>>()
                == identity::renewal_input_names(),
    )?;
    for (name, expected) in &value.input_sha256 {
        require(digest(&fs::read_entry(&input, name, 0o600, false, REFUSED)?) == *expected)?;
    }
    let output = fs::open_child(
        &child,
        "output",
        libc::O_RDONLY | libc::O_DIRECTORY,
        REFUSED,
    )?;
    identity::resume_renewal_output(installation, &value.output, output)?;
    fs::require_directory_binding(&path, &child, REFUSED)?;
    require(DirectoryIdentity::observe(&child)? == before)
}
pub(crate) fn verify_helper_projection_at(installation: &Path, service: &Value) -> Result<bool> {
    let Some(path) = service["volumes"]
        .as_array()
        .and_then(|volumes| volumes.iter().find(|volume| volume["target"] == "/output"))
        .and_then(|volume| volume["source"].as_str())
    else {
        return Ok(false);
    };
    let root = installation.join(ROOT);
    let path = Path::new(path);
    if !path.starts_with(&root) {
        return Ok(false);
    }
    let leaf = path
        .parent()
        .and_then(|path| path.file_name())
        .and_then(|value| value.to_str())
        .ok_or(REFUSED)?;
    require(
        leaf.len() == 6
            && leaf.bytes().all(|v| v.is_ascii_digit())
            && path.file_name().and_then(|value| value.to_str()) == Some("output"),
    )?;
    let sequence: u32 = leaf.parse().map_err(|_| REFUSED)?;
    verify_preparation_at(installation, sequence)?;
    identity::validate_renewal_model_at(
        installation,
        sequence,
        &json!({"services":{"installer-feature-identities":service}}),
    )?;
    Ok(true)
}
fn due(
    selection: &Selection,
    values: &BTreeMap<String, Vec<u8>>,
    qualified_at: u64,
    at: u64,
) -> Result<bool> {
    let Some(identity) = selection.identity_selection()? else {
        return Ok(false);
    };
    require(qualified_at > 0 && qualified_at <= at.saturating_add(120))?;
    let mut earliest = qualified_at
        .checked_add(marty_selfhost_identity::features::MAX_LEAF_SECONDS)
        .ok_or(REFUSED)?;
    for role in identity.identities() {
        let certificate = Certificate::from_pem(values.get(role.certificate).ok_or(REFUSED)?)
            .map_err(|_| REFUSED)?;
        let validity = &certificate.tbs_certificate.validity;
        require(validity.not_before.to_unix_duration().as_secs() <= at.saturating_add(60))?;
        earliest = earliest.min(validity.not_after.to_unix_duration().as_secs());
    }
    Ok(earliest <= at.saturating_add(7200))
}

fn clear_producer_bindings(inputs: &mut ComposeInputs) {
    let root = inputs.installation.join(ROOT);
    let evidence = inputs.installation.join("evidence");
    inputs.bound_inputs.retain(|file| {
        if file.path.starts_with(&root) {
            return false;
        }
        !(file.path.parent() == Some(evidence.as_path())
            && file
                .path
                .file_name()
                .and_then(|v| v.to_str())
                .is_some_and(|name| {
                    name.starts_with("generation-feature-")
                        && (name.ends_with("-preparation.json")
                            || name.ends_with("-producer-plan.json"))
                }))
    });
}
fn helper_inputs(
    state: &mut LockedMaintenance,
    installation: &Path,
    sequence: u32,
    parent: &SavedSession,
    raw: &[u8],
) -> Result<ComposeInputs> {
    let mut inputs = parent.inputs.clone();
    inputs.profiles = vec!["setup".into()];
    inputs.services = vec!["installer-feature-identities".into()];
    clear_producer_bindings(&mut inputs);
    inputs.files.retain(|file| {
        !file
            .path
            .ends_with("feature-profile/compose.identities.yml")
            && !file
                .path
                .ends_with("feature-profile/compose.identities-renew.yml")
    });
    let bundle = inputs.files[0].path.parent().ok_or(REFUSED)?.to_owned();
    append_layer(
        &mut inputs,
        crate::installer_application::bundle_bound(&bundle, LAYER)?,
    );
    let child = installation.join(ROOT).join(format!("{sequence:06}"));
    inputs.readonly_bind_roots.insert(child.join("input"));
    inputs.writable_bind_roots.insert(child.join("output"));
    let source =
        crate::installer_verify::read_private_bytes(&parent.inputs.environment.path, 65_536)?;
    let mut env = Vec::new();
    let mut prior_work = 0;
    for line in std::str::from_utf8(&source).map_err(|_| REFUSED)?.lines() {
        if line.starts_with("FEATURE_IDENTITY_WORK_DIR=") {
            prior_work += 1;
        } else {
            env.extend_from_slice(line.as_bytes());
            env.push(b'\n');
        }
    }
    require(prior_work <= 1)?;
    env.extend_from_slice(
        format!(
            "FEATURE_IDENTITY_WORK_DIR='{}'\n",
            child.to_str().ok_or(REFUSED)?
        )
        .as_bytes(),
    );
    let env_name = format!("generation-feature-{sequence:06}-producer.env");
    store_once(state, installation, &env_name, &env)?;
    inputs.environment = BoundFile {
        path: installation.join("evidence").join(env_name),
        sha256: digest(&env),
    };
    inputs.bound_inputs.push(BoundFile {
        path: installation
            .join("evidence")
            .join(name(sequence, "preparation")),
        sha256: digest(raw),
    });
    for entry in identity::renewal_input_names() {
        inputs
            .bound_inputs
            .push(crate::installer_application::bound(
                child.join("input").join(entry),
            )?);
    }
    inputs.prior = Some(parent.receipt.clone());
    Ok(inputs)
}
fn pending_sequence(installation: &Path) -> Result<Option<u32>> {
    let all = materials(installation)?;
    let Some((root, _, _)) = root_at(installation)? else {
        return Ok(None);
    };
    let count = fs::file_names(&root, REFUSED)?.len();
    require(count == all.len() || count == all.len() + 1)?;
    if count > all.len() {
        let sequence = u32::try_from(count).map_err(|_| REFUSED)?;
        verify_preparation_at(installation, sequence)?;
        return Ok(Some(sequence));
    }
    if let Some((material, _)) = all.last() {
        if optional_record(installation, &name(material.sequence, "completed"))?.is_none() {
            require(material.renewal_receipt_sha256.is_some())?;
            return Ok(Some(material.sequence));
        }
    }
    Ok(None)
}

pub(crate) fn has_pending_baseline_renewal(
    installation: &Path,
    baseline_sequence: u64,
    baseline_attempt: u64,
) -> Result<bool> {
    let Some(sequence) = pending_sequence(installation)? else {
        return Ok(false);
    };
    let (retained, _) = preparation(installation, sequence)?;
    Ok(retained.baseline_sequence == baseline_sequence
        && retained.baseline_attempt == baseline_attempt)
}

pub(crate) fn stage_renewal_for_baseline(
    state: &mut LockedMaintenance,
    installation: &Path,
    docker: &Path,
    context: &crate::installer_generation_maintenance::FeatureRenewalContext,
) -> Result<Option<StagedRenewal>> {
    let Some(original) = super::super::load(state.inspection())? else {
        return Ok(None);
    };
    if original.identity_selection()?.is_none() {
        return Ok(None);
    }
    crate::installer_lifecycle::require_recorded_running_intent(state.inspection(), installation)?;
    if let Some(sequence) = pending_sequence(installation)? {
        let (retained, _) = preparation(installation, sequence)?;
        require(
            retained.baseline_sequence == context.sequence()
                && retained.baseline_attempt == context.attempt()
                && retained.baseline_binding_sha256 == context.binding_sha256()
                && encoded(&retained.parent_session)? == encoded(context.logical_parent())?
                && encoded(&retained.runtime_parent_session)? == encoded(context.runtime_parent())?,
        )?;
        return continue_renewal(state, installation, docker, sequence).map(Some);
    }
    let parent = context.logical_parent().clone();
    let selected = super::super::for_inputs(&parent.inputs)?.ok_or(REFUSED)?;
    let values = if let Some(material) = &selected.generation {
        selected_files(installation, material)?
    } else {
        crate::installer_feature_credentials::verify(
            state.inspection(),
            &selected.credential_names()?,
        )?
    };
    identity::verify_retained(
        state.inspection(),
        installation,
        &original.identity_selection()?.ok_or(REFUSED)?,
    )?;
    let qualified = materials(installation)?
        .into_iter()
        .rev()
        .find(|(material, _)| material.renewal_receipt_sha256.is_some())
        .map_or_else(
            || read_record(installation, "feature-identities-result.json"),
            |(material, _)| read_record(installation, &name(material.sequence, "identity-result")),
        )?;
    let qualified_at = decode_record::<Value>(&qualified)?["qualified_at_unix_seconds"]
        .as_u64()
        .ok_or(REFUSED)?;
    if !due(&selected, &values, qualified_at, now()?)? {
        return Ok(None);
    }
    let mut runtime_inputs = context.runtime_parent().inputs.clone();
    runtime_inputs.prior = Some(context.runtime_parent().receipt.clone());
    ComposeSession::new_generation(
        docker,
        state.journal().runtime().ok_or(REFUSED)?,
        runtime_inputs,
    )?
    .observe_resources()?;
    let baseline = crate::installer_generation_binding::load_verified(
        installation,
        &parent.installation_id,
        &parent.receipt.engine_id,
    )?
    .ok_or(REFUSED)?;
    let ca = baseline.read(installation, "openbao_tls_ca_cert")?;
    let renewal = identity::prepare_renewal(state.inspection(), installation, &ca)?;
    let previous = materials(installation)?;
    let sequence = u32::try_from(previous.len() + 1).map_err(|_| REFUSED)?;
    let (root, root_receipt, root_raw) = root_at(installation)?.ok_or(REFUSED)?;
    let child = mkdir_owned(&root, &format!("{sequence:06}"))?;
    let input = mkdir_owned(&child, "input")?;
    let output = mkdir_owned(&child, "output")?;
    let held_output = identity::hold_renewal_output(installation, sequence, output)?;
    for (name, bytes) in &renewal.input_files {
        write_exclusive(&input, name, bytes, 0o600)?;
    }
    let preparation = Preparation {
        schema: "elevenid.installer-feature-renewal-preparation/v1".into(),
        sequence,
        installation_id: root_receipt.installation_id,
        feature_profile_sha256: root_receipt.feature_profile_sha256.clone(),
        root_receipt_sha256: digest(&root_raw),
        parent_material_sha256: previous
            .last()
            .map_or_else(|| digest(&root_raw), |(_, raw)| digest(raw)),
        parent_session_sha256: digest(&encoded(&parent)?),
        parent_session: parent.clone(),
        runtime_parent_session: context.runtime_parent().clone(),
        baseline_sequence: context.sequence(),
        baseline_attempt: context.attempt(),
        baseline_binding_sha256: context.binding_sha256().into(),
        directory: DirectoryIdentity::observe(&child)?,
        input_directory: DirectoryIdentity::observe(&input)?,
        output: held_output.binding(),
        input_sha256: renewal
            .input_files
            .iter()
            .map(|(name, bytes)| (name.clone(), digest(bytes)))
            .collect(),
    };
    let raw = encoded(&preparation)?;
    state.write_evidence_exclusive(&name(sequence, "preparation"), &raw)?;
    continue_renewal(state, installation, docker, sequence).map(Some)
}

fn retained_producer(
    state: &LockedMaintenance,
    installation: &Path,
    session: &ComposeSession,
    permit: &RenewalPermit,
    phase: &str,
    prior: &crate::installer_compose::ComposeReceipt,
) -> Result<Option<crate::installer_compose::ComposeReceipt>> {
    let operation = permit.operation(phase);
    let result_name = format!("generation-compose-{operation}-result.json");
    let intent_name = format!("generation-compose-{operation}-intent.json");
    let Some(raw) = optional_record(installation, &result_name)? else {
        require(optional_record(installation, &intent_name)?.is_none())?;
        return Ok(None);
    };
    let receipt = decode_record(&raw)?;
    session.retained_feature_producer_receipt(state, permit, phase, &receipt)?;
    let intent: Value = decode_record(&read_record(installation, &intent_name)?)?;
    let resources = prior.resources.as_ref().ok_or(REFUSED)?;
    let command = match phase {
        "create" => json!([
            "up",
            "--no-build",
            "--pull",
            "never",
            "--no-deps",
            "--no-start",
            "--force-recreate",
            "--timeout",
            "60"
        ]),
        "start" | "wait" => json!([
            phase,
            resources
                .containers
                .get("installer-feature-identities")
                .ok_or(REFUSED)?
                .id
        ]),
        _ => return Err(REFUSED.into()),
    };
    let observed: crate::installer_compose::ProjectResources =
        serde_json::from_value(intent["prior_resources"].clone()).map_err(|_| REFUSED)?;
    if phase == "wait" {
        let mut normalized = observed.clone();
        let expected = resources
            .containers
            .get("installer-feature-identities")
            .ok_or(REFUSED)?;
        let current = normalized
            .containers
            .get_mut("installer-feature-identities")
            .ok_or(REFUSED)?;
        require(
            current.setup_execution.as_ref().ok_or(REFUSED)?.started_at
                == expected.setup_execution.as_ref().ok_or(REFUSED)?.started_at,
        )?;
        current.setup_execution = expected.setup_execution.clone();
        require(normalized == *resources)?;
    } else {
        require(observed == *resources)?;
    }
    require(
        intent["schema"] == "elevenid.installer-compose-intent/v1"
            && intent["project"] == receipt.project
            && intent["engine_id"] == receipt.engine_id
            && intent["configuration_sha256"] == receipt.configuration_sha256
            && intent["input_files"]
                == serde_json::to_value(&receipt.input_files).map_err(|_| REFUSED)?
            && intent["selected_services"] == json!(["installer-feature-identities"])
            && intent["command"] == command
            && intent["automatic_retry"] == false
            && intent["installation_ready"] == false,
    )?;
    Ok(Some(receipt))
}

fn continue_renewal(
    state: &mut LockedMaintenance,
    installation: &Path,
    docker: &Path,
    sequence: u32,
) -> Result<StagedRenewal> {
    verify_preparation_at(installation, sequence)?;
    let (preparation, raw) = preparation(installation, sequence)?;
    let parent = preparation.parent_session.clone();
    let selected = super::super::for_inputs(&parent.inputs)?.ok_or(REFUSED)?;
    let mut values = if let Some(material) = &selected.generation {
        selected_files(installation, material)?
    } else {
        crate::installer_feature_credentials::verify(
            state.inspection(),
            &selected.credential_names()?,
        )?
    };
    let child_path = installation.join(ROOT).join(format!("{sequence:06}"));
    let child = fs::directory(&child_path, REFUSED)?;
    let input = fs::open_child(&child, "input", libc::O_RDONLY | libc::O_DIRECTORY, REFUSED)?;
    let ca = fs::read_entry(&input, "ca.crt", 0o600, false, REFUSED)?;
    let renewal = identity::prepare_renewal(state.inspection(), installation, &ca)?;
    require(
        renewal
            .input_files
            .iter()
            .map(|(name, bytes)| (name.clone(), digest(bytes)))
            .collect::<BTreeMap<_, _>>()
            == preparation.input_sha256,
    )?;
    let held_output = identity::resume_renewal_output(
        installation,
        &preparation.output,
        fs::open_child(
            &child,
            "output",
            libc::O_RDONLY | libc::O_DIRECTORY,
            REFUSED,
        )?,
    )?;
    let inputs = helper_inputs(
        state,
        installation,
        sequence,
        &preparation.runtime_parent_session,
        &raw,
    )?;
    let binding = state.journal().runtime().ok_or(REFUSED)?.clone();
    let session = ComposeSession::new_generation(docker, &binding, inputs.clone())?;
    identity::validate_renewal_model(
        &renewal,
        session.model(),
        installation,
        sequence,
        parent.model["services"]["gateway"]["image"]
            .as_str()
            .ok_or(REFUSED)?,
    )?;
    let plan = ProducerPlan {
        schema: "elevenid.installer-feature-renewal-producer-plan/v1".into(),
        sequence,
        preparation_sha256: digest(&raw),
        inputs,
        model: session.model().clone(),
        configuration_sha256: session.configuration_sha256().into(),
    };
    store_once(
        state,
        installation,
        &name(sequence, "producer-plan"),
        &encoded(&plan)?,
    )?;
    let permit = RenewalPermit { plan };
    let retained_created = retained_producer(
        state,
        installation,
        &session,
        &permit,
        "create",
        &preparation.runtime_parent_session.receipt,
    )?;
    let created = if let Some(receipt) = retained_created {
        receipt
    } else {
        session.create_feature_producer(state, &permit)?
    };
    let retained_started =
        retained_producer(state, installation, &session, &permit, "start", &created)?;
    // Preparation may have been retained before the host stopped, even when
    // creation itself succeeds in this invocation. Recover the exact retained
    // provider infrastructure before every first start; a healthy provider
    // needs no native start operation and the producer is never replayed.
    let recovery = ComposeSession::new_generation(docker, &binding, permit.plan.inputs.clone())?
        .into_feature_producer_recovery(state, &permit, &created, retained_started.as_ref())?;
    crate::installer_openbao_recovery::reconcile_locked(installation, docker, state, &recovery)?;
    let started = if let Some(receipt) = retained_started {
        receipt
    } else {
        session.start_feature_producer(state, &permit, &created)?
    };
    let completed = if let Some(receipt) =
        retained_producer(state, installation, &session, &permit, "wait", &started)?
    {
        receipt
    } else {
        session.wait_feature_producer(state, &permit, &created, &started)?
    };
    let (output, renewal_raw) =
        if let Some(raw) = optional_record(installation, &name(sequence, "identity-result"))? {
            let receipt: identity::RenewalReceipt = decode_record(&raw)?;
            (
                identity::verify_renewal_receipt_at(installation, &receipt)?,
                raw,
            )
        } else {
            let (output, receipt) = identity::admit_renewal_output(
                state,
                &renewal,
                &held_output,
                &created,
                &started,
                &completed,
            )?;
            let raw = encoded(&receipt)?;
            state.write_evidence_exclusive(&name(sequence, "identity-result"), &raw)?;
            (output, raw)
        };
    let caller_binding_rotation =
        if let Some(bindings) = values.get("feature_delegated_use_workload_bindings") {
            let native = marty_selfhost_identity::features::NATIVE_CALLER;
            let (updated, receipt) = crate::installer_feature_caller_binding::rotate(
                bindings,
                values.get(native.certificate).ok_or(REFUSED)?,
                output.get(native.certificate).ok_or(REFUSED)?,
            )?;
            values.insert("feature_delegated_use_workload_bindings".into(), updated);
            receipt
        } else {
            None
        };
    for (name, bytes) in output {
        require(values.contains_key(&name))?;
        values.insert(name, bytes);
    }
    let files_now = if optional_record(installation, &material_intent_name(sequence))?.is_some() {
        verify_prepared_material(installation, sequence)?.files_directory
    } else {
        DirectoryIdentity::observe(&mkdir_owned(&child, "files")?)?
    };
    let material = SelectedMaterial {
        schema: MATERIAL_SCHEMA.into(),
        sequence,
        installation_id: preparation.installation_id,
        engine_id: binding.engine_id.clone(),
        feature_profile_sha256: preparation.feature_profile_sha256,
        root_receipt_sha256: preparation.root_receipt_sha256,
        parent_material_sha256: preparation.parent_material_sha256,
        activation_sha256: selected
            .generation
            .as_ref()
            .and_then(|value| value.activation_sha256.clone()),
        renewal_receipt_sha256: Some(digest(&renewal_raw)),
        caller_binding_rotation,
        configuration: selected.configuration.clone(),
        imports: selected
            .configuration
            .input_files()?
            .keys()
            .map(|name| Ok((name.clone(), fingerprint(values.get(name).ok_or(REFUSED)?))))
            .collect::<Result<_>>()?,
        directory: preparation.directory.clone(),
        files_directory: files_now,
        files: values
            .iter()
            .map(|(name, bytes)| (name.clone(), fingerprint(bytes)))
            .collect(),
    };
    require(
        material
            .directory
            .matches(DirectoryIdentity::observe(&child)?),
    )?;
    fs::require_directory_binding(&child_path, &child, REFUSED)?;
    complete_material_files(state, installation, &material, &values)?;
    let staged = StagedRenewal {
        material,
        parent,
        producer: completed,
    };
    staged.require_current(installation)?;
    Ok(staged)
}

pub(crate) fn load_staged_baseline(installation: &Path, sequence: u32) -> Result<StagedRenewal> {
    verify_preparation_at(installation, sequence)?;
    let (preparation, _) = preparation(installation, sequence)?;
    let material: SelectedMaterial =
        decode_record(&read_record(installation, &name(sequence, "binding"))?)?;
    require(
        material.sequence == sequence
            && material.renewal_receipt_sha256.is_some()
            && material.parent_material_sha256 == preparation.parent_material_sha256,
    )?;
    selected_files(installation, &material)?;
    let producer: crate::installer_compose::ComposeReceipt = decode_record(&read_record(
        installation,
        &format!("generation-compose-feature-{sequence:06}-wait-result.json"),
    )?)?;
    // The material verifier replays the exact historical identity receipt,
    // including all three native receipts and their original qualification.
    require(
        producer.operation == format!("feature-{sequence:06}-wait")
            && producer.project == preparation.runtime_parent_session.inputs.project
            && producer.engine_id == preparation.runtime_parent_session.receipt.engine_id
            && producer.command_succeeded
            && producer.observation_validated
            && producer.failure_class.is_none()
            && producer.client_exit_code == Some(0)
            && !producer.installation_ready,
    )?;
    Ok(StagedRenewal {
        material,
        parent: preparation.parent_session,
        producer,
    })
}
pub(super) fn verify_retained_material(
    installation: &Path,
    material: &SelectedMaterial,
    values: &BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    let Some(expected) = &material.renewal_receipt_sha256 else {
        return Ok(());
    };
    verify_preparation_at(installation, material.sequence)?;
    let raw = read_record(installation, &name(material.sequence, "identity-result"))?;
    require(digest(&raw) == *expected)?;
    let receipt: identity::RenewalReceipt = decode_record(&raw)?;
    let retained = identity::verify_renewal_receipt_at(installation, &receipt)?;
    for (name, bytes) in retained {
        require(values.get(&name) == Some(&bytes))?;
    }
    if let Some(current) = values.get("feature_delegated_use_workload_bindings") {
        let previous = prior_caller_values(installation, material)?;
        let native = marty_selfhost_identity::features::NATIVE_CALLER;
        let (updated, receipt) = crate::installer_feature_caller_binding::rotate(
            previous
                .get("feature_delegated_use_workload_bindings")
                .ok_or(REFUSED)?,
            previous.get(native.certificate).ok_or(REFUSED)?,
            values.get(native.certificate).ok_or(REFUSED)?,
        )?;
        require(*current == updated && material.caller_binding_rotation == receipt)?;
    } else {
        require(material.caller_binding_rotation.is_none())?;
    }
    Ok(())
}

fn prior_caller_values(
    installation: &Path,
    material: &SelectedMaterial,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let names = [
        "feature_delegated_use_workload_bindings",
        marty_selfhost_identity::features::NATIVE_CALLER.certificate,
    ];
    if material.sequence == 1 {
        let original = super::super::at(installation)?.ok_or(REFUSED)?;
        return crate::installer_feature_credentials::verify_at(
            installation,
            &original.credential_names()?,
        );
    }
    let raw = read_record(installation, &name(material.sequence - 1, "binding"))?;
    require(digest(&raw) == material.parent_material_sha256)?;
    let previous: SelectedMaterial = decode_record(&raw)?;
    let directory = fs::directory(&previous.directory(installation), REFUSED)?;
    let before = DirectoryIdentity::observe(&directory)?;
    require(
        previous.files_directory.matches(before.clone())
            && fs::file_names(&directory, REFUSED)? == previous.files.keys().cloned().collect(),
    )?;
    let mut values = BTreeMap::new();
    for name in names {
        let bytes = read_file(&directory, name)?;
        require(previous.files.get(name) == Some(&fingerprint(&bytes)))?;
        values.insert(name.into(), bytes);
    }
    fs::require_directory_binding(&previous.directory(installation), &directory, REFUSED)?;
    require(DirectoryIdentity::observe(&directory)? == before)?;
    Ok(values)
}
pub(super) fn require_fresh(installation: &Path, material: &SelectedMaterial) -> Result<()> {
    require_fresh_at(installation, material, now()?)
}
fn require_fresh_at(installation: &Path, material: &SelectedMaterial, at: u64) -> Result<()> {
    let selected = super::super::at(installation)?.ok_or(REFUSED)?;
    let Some(selection) = selected.identity_selection()? else {
        return Ok(());
    };
    let values = selected_files(installation, material)?;
    let mut qualified = read_record(installation, identity::RECORD)?;
    for sequence in (1..=material.sequence).rev() {
        let previous: SelectedMaterial = if sequence == material.sequence {
            material.clone()
        } else {
            decode_record(&read_record(installation, &name(sequence, "binding"))?)?
        };
        if let Some(expected) = previous.renewal_receipt_sha256 {
            qualified = read_record(installation, &name(sequence, "identity-result"))?;
            require(digest(&qualified) == expected)?;
            let receipt: identity::RenewalReceipt = decode_record(&qualified)?;
            for (name, bytes) in identity::verify_renewal_receipt_at(installation, &receipt)? {
                require(values.get(&name) == Some(&bytes))?;
            }
            break;
        }
    }
    let qualified_at = decode_record::<Value>(&qualified)?["qualified_at_unix_seconds"]
        .as_u64()
        .ok_or(REFUSED)?;
    require(
        at >= qualified_at.saturating_sub(120)
            && at
                < qualified_at
                    .checked_add(marty_selfhost_identity::features::MAX_LEAF_SECONDS)
                    .ok_or(REFUSED)?,
    )?;
    identity::validate_material_at(&selection, &values, at)
}
