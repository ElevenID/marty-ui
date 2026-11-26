//! Native activation of the two deliberately pending feature selections.
//! Operator-provided owner receipts bind configuration; runtime readiness still
//! checks the actual governed records. No receipt here creates that authority.
use super::*;
use crate::{
    installer_compose::{
        BoundFile, ComposeInputs, ComposeReceipt, ComposeSession, RuntimeOperationOwner,
    },
    installer_doctor::SavedSession,
};
use serde_json::json;
use std::time::Duration;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicActivation {
    receipt: workflows::PublicVerificationActivation,
    catalog_file: PathBuf,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivationInput {
    schema: String,
    installation_id: uuid::Uuid,
    feature_profile_sha256: String,
    owner_api_receipt_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    delegated_use: Option<DelegatedUseConfiguration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    public_verification: Option<PublicActivation>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    schema: String,
    installation_id: uuid::Uuid,
    feature_profile_sha256: String,
    activation_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    producer_receipt_sha256: Option<String>,
    parent_session: SavedSession,
    parent_session_sha256: String,
    sequence: u32,
    configuration: Configuration,
    material_files: BTreeMap<String, Fingerprint>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    installation_id: uuid::Uuid,
    sequence: u32,
    material_sha256: String,
    parent_session_sha256: String,
    inputs: ComposeInputs,
    model: Value,
    configuration_sha256: String,
    service_hashes: BTreeMap<String, String>,
    selected: BTreeSet<String>,
    added: BTreeSet<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Completed {
    schema: String,
    installation_id: uuid::Uuid,
    sequence: u32,
    material_sha256: String,
    intent_sha256: String,
    plan_sha256: String,
    create_receipt_sha256: String,
    start_receipt_sha256: String,
    checkpoint_receipt_sha256: String,
    session: SavedSession,
    activated: bool,
    installation_ready: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JointCompleted {
    schema: String,
    installation_id: uuid::Uuid,
    sequence: u32,
    material_sha256: String,
    baseline_sequence: u64,
    baseline_attempt: u64,
    parent_session_sha256: String,
    session_sha256: String,
    activated: bool,
    installation_ready: bool,
}

/// No public constructor: only the immutable feature owner can authorize this
/// narrowly reviewed model delta and the one possible new delegated-use role.
pub(crate) struct ActivationPermit {
    plan: Plan,
}
impl ActivationPermit {
    pub(crate) fn selected(&self) -> &BTreeSet<String> {
        &self.plan.selected
    }
    pub(crate) fn added(&self) -> &BTreeSet<String> {
        &self.plan.added
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
        let raw = read_record(&inputs.installation, &record(self.plan.sequence, "plan"))?;
        require(encoded(&decode_record::<Plan>(&raw)?)? == encoded(&self.plan)?)
    }
}
fn record(sequence: u32, kind: &str) -> String {
    format!("generation-feature-{sequence:06}-{kind}.json")
}
fn native_record(sequence: u32, phase: &str) -> String {
    format!("generation-compose-feature-{sequence:06}-{phase}-result.json")
}
fn session_hash(session: &SavedSession) -> Result<String> {
    Ok(digest(&encoded(session)?))
}

fn configured(
    selection: &Selection,
    input: &ActivationInput,
    application_origin: &str,
    captured: Option<&BTreeMap<String, Vec<u8>>>,
) -> Result<(Configuration, BTreeMap<String, Vec<u8>>)> {
    require(
        input.schema == "elevenid.installer-feature-activation/v1"
            && input.installation_id == selection.installation_id
            && input.feature_profile_sha256 == selection.profile_sha256()?
            && hash(&input.owner_api_receipt_sha256)
            && (input.delegated_use.is_some() || input.public_verification.is_some()),
    )?;
    let mut next = selection.configuration.clone();
    let mut files = BTreeMap::new();
    if let Some(configuration) = &input.delegated_use {
        let agent = next.agent_trust.as_mut().ok_or(REFUSED)?;
        require(matches!(
            agent.delegated_use,
            Some(DelegatedUse::AwaitingOwnerConfiguration {})
        ))?;
        configuration.validate()?;
        for (name, path) in configuration.input_files() {
            let bytes = if let Some(captured) = captured {
                captured.get(&name).cloned().ok_or(REFUSED)?
            } else {
                private_bytes(&path)?
            };
            files.insert(name, bytes);
        }
        agent.delegated_use = Some(DelegatedUse::Configured {
            configuration: Box::new(configuration.clone()),
        });
    }
    if let Some(public) = &input.public_verification {
        require(public.receipt.owner_api_receipt_sha256 == input.owner_api_receipt_sha256)?;
        let bytes = if let Some(captured) = captured {
            captured.get(workflows::CATALOG).cloned().ok_or(REFUSED)?
        } else {
            private_bytes(&public.catalog_file)?
        };
        next.workflows = Some(
            next.workflows
                .as_ref()
                .ok_or(REFUSED)?
                .activate_public_verification(
                    &public.receipt,
                    &bytes,
                    public.catalog_file.clone(),
                    selection.installation_id,
                    &selection.profile_sha256()?,
                    application_origin,
                )?,
        );
        files.insert(workflows::CATALOG.into(), bytes);
    }
    // This explicit activation is once-only: every selected pending runtime is
    // configured together. Subsequent generations renew material, not policy.
    require(
        !next.agent_trust.as_ref().is_some_and(|agent| {
            matches!(
                agent.delegated_use,
                Some(DelegatedUse::AwaitingOwnerConfiguration {})
            )
        }) && !next.workflows.as_ref().is_some_and(|w| {
            matches!(
                w.public_verification,
                Some(workflows::PublicVerification::AwaitingOwnerConfiguration {})
            )
        }),
    )?;
    next.validate()?;
    Ok((next, files))
}

fn environment_origin(bytes: &[u8]) -> Result<String> {
    let text = std::str::from_utf8(bytes).map_err(|_| REFUSED)?;
    let values: Vec<_> = text
        .lines()
        .filter_map(|line| line.strip_prefix("UI_BASE_URL="))
        .collect();
    require(values.len() == 1)?;
    let value = values[0].trim_matches('\'');
    require(https(value, true))?;
    Ok(value.into())
}

pub(super) fn verify_material_configuration(
    installation: &Path,
    material: &SelectedMaterial,
    values: &BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    let original = super::super::at(installation)?.ok_or(REFUSED)?;
    require(material.feature_profile_sha256 == original.profile_sha256()?)?;
    let expected = if let Some(expected) = &material.activation_sha256 {
        let raw = read_record(installation, ACTIVATION)?;
        require(digest(&raw) == *expected)?;
        let input: ActivationInput = decode(&raw)?;
        let origin = input
            .public_verification
            .as_ref()
            .map_or("", |public| public.receipt.application_origin.as_str());
        configured(&original, &input, origin, Some(values))?.0
    } else {
        original.configuration.clone()
    };
    require(expected == material.configuration)?;
    let expected_imports: BTreeMap<_, _> = expected
        .input_files()?
        .keys()
        .map(|name| Ok((name.clone(), fingerprint(values.get(name).ok_or(REFUSED)?))))
        .collect::<Result<_>>()?;
    require(expected_imports == material.imports)?;
    let mut selected = original.clone();
    selected.configuration = expected;
    selected.imports = material.imports.clone();
    selected.generation = Some(material.clone());
    require(values.keys().cloned().collect::<BTreeSet<_>>() == selected.credential_names()?)?;
    let old = if material.sequence == 1 {
        crate::installer_feature_credentials::verify_at(
            installation,
            &original.credential_names()?,
        )?
        .into_iter()
        .map(|(name, bytes)| (name, fingerprint(&bytes)))
        .collect()
    } else {
        let raw = read_record(
            installation,
            &format!(
                "generation-feature-{:06}-binding.json",
                material.sequence - 1
            ),
        )?;
        require(digest(&raw) == material.parent_material_sha256)?;
        decode_record::<SelectedMaterial>(&raw)?.files
    };
    let mut renewable = BTreeSet::new();
    if material.renewal_receipt_sha256.is_some() {
        let mut identity = original.identity_selection()?.ok_or(REFUSED)?;
        identity.operation = marty_selfhost_identity::features::Operation::Renew;
        renewable = identity.output_names();
        if material.caller_binding_rotation.is_some() {
            renewable.insert("feature_delegated_use_workload_bindings".into());
        }
    } else {
        require(material.caller_binding_rotation.is_none())?;
    }
    for (name, expected) in &old {
        if !renewable.contains(name) {
            require(material.files.get(name) == Some(expected))?;
        }
    }
    let added: BTreeSet<_> = material
        .files
        .keys()
        .filter(|name| !old.contains_key(*name))
        .cloned()
        .collect();
    require(added.is_subset(&material.imports.keys().cloned().collect()))
}
fn next_inputs(
    state: &mut LockedMaintenance,
    installation: &Path,
    material: &SelectedMaterial,
    parent: &SavedSession,
) -> Result<ComposeInputs> {
    let mut selection = super::super::at(installation)?.ok_or(REFUSED)?;
    selection.configuration = material.configuration.clone();
    selection.imports = material.imports.clone();
    selection.generation = Some(material.clone());
    let mut inputs = parent.inputs.clone();
    inputs.services.clear();
    inputs.profiles.clear();
    inputs.files.retain(|file| {
        !file
            .path
            .to_str()
            .is_some_and(|path| path.contains(LAYER_ROOT))
            || file
                .path
                .ends_with("feature-profile/compose.identities.yml")
            || file
                .path
                .ends_with("feature-profile/compose.identities-renew.yml")
    });
    inputs.bound_inputs.retain(|file| {
        !file
            .path
            .file_name()
            .and_then(|v| v.to_str())
            .is_some_and(|name| {
                name.starts_with("generation-feature-") && name.ends_with("-binding.json")
            })
    });
    let bundle = inputs
        .files
        .first()
        .and_then(|file| file.path.parent())
        .ok_or(REFUSED)?
        .to_owned();
    selection.append_layers(&mut inputs, &bundle)?;
    selection.bind_inputs(&mut inputs)?;
    inputs
        .bound_inputs
        .push(crate::installer_application::bound(
            installation.join("evidence").join(material.record()),
        )?);
    // All removed keys belong to this closed typed profile; unrelated base
    // generation/hosting/database/credential selections remain byte exact.
    let source =
        crate::installer_verify::read_private_bytes(&parent.inputs.environment.path, 65_536)?;
    let mut environment = Vec::new();
    for line in std::str::from_utf8(&source).map_err(|_| REFUSED)?.lines() {
        let key = line.split_once('=').map_or(line, |(key, _)| key);
        if (key.starts_with("FEATURE_") && key != "FEATURE_IDENTITY_WORK_DIR")
            || [
                "MARTY_APPLICATION_OWNERSHIP_ENABLED",
                "MARTY_EXTERNAL_ASSOCIATIONS_ENABLED",
                "MARTY_EXTERNAL_OBSERVATIONS_ENABLED",
                "WALLET_FLOW_PRODUCER_ID",
            ]
            .contains(&key)
        {
            continue;
        }
        environment.extend_from_slice(line.as_bytes());
        environment.push(b'\n');
    }
    let inventory = crate::installer_release::parse_inventory(
        &state
            .inspection()
            .read_evidence("installer-inventory.json")?,
    )?;
    selection.append_environment(&mut environment, installation, &inventory.images)?;
    let name = format!(
        "generation-feature-{:06}-application.env",
        material.sequence
    );
    store_once(state, installation, &name, &environment)?;
    inputs.environment = BoundFile {
        path: installation.join("evidence").join(name),
        sha256: digest(&environment),
    };
    inputs.prior = Some(parent.receipt.clone());
    Ok(inputs)
}

fn normalize(model: &mut Value) {
    if let Some(services) = model["services"].as_object_mut() {
        for service in services.values_mut() {
            for field in ["volumes", "secrets", "configs"] {
                if let Some(values) = service[field].as_array_mut() {
                    values.sort_by_key(|v| {
                        v["target"]
                            .as_str()
                            .or_else(|| v["source"].as_str())
                            .unwrap_or("")
                            .to_owned()
                    });
                }
            }
        }
    }
}
fn project(model: &Value) -> Result<Value> {
    let mut model = model.clone();
    let services = model["services"].as_object_mut().ok_or(REFUSED)?;
    services.retain(|_, service| service["labels"]["com.elevenid.installer.phase"] != "setup");
    let mut names = BTreeSet::new();
    for service in services.values() {
        for secret in service["secrets"].as_array().into_iter().flatten() {
            names.insert(secret["source"].as_str().ok_or(REFUSED)?.to_owned());
        }
    }
    if let Some(secrets) = model["secrets"].as_object_mut() {
        secrets.retain(|name, _| names.contains(name));
    }
    normalize(&mut model);
    Ok(model)
}

fn require_model_transition(
    installation: &Path,
    parent: &SavedSession,
    selection: &Selection,
    material: &SelectedMaterial,
    model: &Value,
) -> Result<BTreeSet<String>> {
    let previous = super::super::for_inputs(&parent.inputs)?.ok_or(REFUSED)?;
    let old = previous.projection_directory(installation);
    let new = material.directory(installation);
    let mut expected = parent.model.clone();
    for service in expected["services"]
        .as_object_mut()
        .ok_or(REFUSED)?
        .values_mut()
    {
        for volume in service["volumes"].as_array_mut().into_iter().flatten() {
            if let Some(source) = volume["source"].as_str() {
                let path = Path::new(source);
                if path.starts_with(&old) {
                    require(path.parent() == Some(old.as_path()))?;
                    volume["source"] = json!(new
                        .join(path.file_name().ok_or(REFUSED)?)
                        .to_str()
                        .ok_or(REFUSED)?);
                }
            }
        }
    }
    let mut actual = model.clone();
    let mut added = BTreeSet::new();
    let new_use = selection
        .configuration
        .agent_trust
        .as_ref()
        .and_then(AgentTrust::use_configuration)
        .is_some();
    let old_use = previous
        .configuration
        .agent_trust
        .as_ref()
        .and_then(AgentTrust::use_configuration)
        .is_some();
    if new_use && !old_use {
        require(
            actual["services"]["delegated-use"].is_object()
                && expected["services"]["delegated-use"].is_null(),
        )?;
        actual["services"]
            .as_object_mut()
            .ok_or(REFUSED)?
            .remove("delegated-use");
        added.insert("delegated-use".into());
    }
    let pending_public = previous.configuration.workflows.as_ref().is_some_and(|w| {
        matches!(
            w.public_verification,
            Some(workflows::PublicVerification::AwaitingOwnerConfiguration {})
        )
    });
    let configured_public = selection.configuration.workflows.as_ref().is_some_and(|w| {
        matches!(
            w.public_verification,
            Some(workflows::PublicVerification::Configured { .. })
        )
    });
    if pending_public && configured_public {
        let flow = &mut actual["services"]["flow"];
        for key in [
            "MARTY_SIGNING_GRANT_PROVIDER",
            "FLOW_PUBLIC_VERIFICATION_CONFIG_FILE",
            "FLOW_DEMO_HOLDER_SIGN_GRANT_MINT_TOKEN_FILE",
        ] {
            let old = &expected["services"]["flow"]["environment"][key];
            if old.is_null() {
                flow["environment"]
                    .as_object_mut()
                    .ok_or(REFUSED)?
                    .remove(key);
            } else {
                flow["environment"][key] = old.clone();
            }
        }
        flow["volumes"]
            .as_array_mut()
            .ok_or(REFUSED)?
            .retain(|volume| {
                ![
                    format!("/run/feature-profile/{}", workflows::CATALOG),
                    format!("/run/feature-profile/{}", workflows::HOLDER_MINT_TOKEN),
                ]
                .iter()
                .any(|target| volume["target"] == *target)
            });
    }
    require(project(&actual)? == project(&expected)?)?;
    Ok(added)
}

fn check_native(receipt: &ComposeReceipt, installation_id: uuid::Uuid, engine: &str) -> Result<()> {
    require(
        receipt.schema == "elevenid.installer-compose-operation/v1"
            && receipt.project == format!("marty-install-{}", installation_id.simple())
            && receipt.engine_id == engine
            && receipt.command_succeeded
            && receipt.client_exit_code == Some(0)
            && receipt.failure_class.is_none()
            && receipt.observation_validated
            && !receipt.installation_ready
            && receipt.resources.is_some(),
    )
}

pub(crate) fn activate(
    state: &mut LockedMaintenance,
    installation: &Path,
    docker: &Path,
    input_path: &Path,
) -> Result<()> {
    state.inspection().require_path_binding(installation)?;
    crate::installer_lifecycle::require_recorded_running_intent(state.inspection(), installation)?;
    let raw = private_bytes(input_path)?;
    let input: ActivationInput = decode(&raw)?;
    if let Some(retained) = optional_record(installation, ACTIVATION)? {
        require(retained == raw)?;
        let material = materials(installation)?
            .into_iter()
            .find(|(material, _)| {
                material.activation_sha256.as_deref() == Some(digest(&raw).as_str())
                    && material.renewal_receipt_sha256.is_none()
            })
            .map(|(material, _)| material);
        let intent = activation_intent(installation, &digest(&raw))?;
        let material = if let Some(material) = material {
            if optional_record(installation, &record(material.sequence, "completed"))?.is_some() {
                completed_sessions(installation)?;
                return Ok(());
            }
            material
        } else {
            let selection =
                super::super::for_inputs(&intent.parent_session.inputs)?.ok_or(REFUSED)?;
            let env = crate::installer_verify::read_private_bytes(
                &intent.parent_session.inputs.environment.path,
                65_536,
            )?;
            let (configuration, imports) =
                configured(&selection, &input, &environment_origin(&env)?, None)?;
            let mut values = if let Some(material) = &selection.generation {
                selected_files(installation, material)?
            } else {
                crate::installer_feature_credentials::verify(
                    state.inspection(),
                    &selection.credential_names()?,
                )?
            };
            for (name, bytes) in imports {
                require(values.insert(name, bytes).is_none())?;
            }
            require(
                configuration == intent.configuration
                    && intent.material_files
                        == values
                            .iter()
                            .map(|(name, bytes)| (name.clone(), fingerprint(bytes)))
                            .collect(),
            )?;
            let imports = configuration
                .input_files()?
                .keys()
                .map(|name| Ok((name.clone(), fingerprint(values.get(name).ok_or(REFUSED)?))))
                .collect::<Result<_>>()?;
            let material = stage_material(
                state,
                installation,
                &selection,
                configuration,
                imports,
                &values,
                Some(digest(&raw)),
            )?;
            require(material.sequence == intent.sequence)?;
            material
        };
        return activate_material(state, installation, docker, &material, &intent);
    }
    let (parent, session) =
        crate::installer_doctor::open_session(state.inspection(), installation, docker)?;
    session.observe_resources()?;
    let selection = super::super::for_inputs(&parent.inputs)?.ok_or(REFUSED)?;
    let env = crate::installer_verify::read_private_bytes(&parent.inputs.environment.path, 65_536)?;
    let (configuration, imports) =
        configured(&selection, &input, &environment_origin(&env)?, None)?;
    let mut values = if let Some(material) = &selection.generation {
        selected_files(installation, material)?
    } else {
        crate::installer_feature_credentials::verify(
            state.inspection(),
            &selection.credential_names()?,
        )?
    };
    for (name, bytes) in imports {
        require(values.insert(name, bytes).is_none())?;
    }
    configuration.validate_imported(&values)?;
    let fingerprints = configuration
        .input_files()?
        .keys()
        .map(|name| Ok((name.clone(), fingerprint(values.get(name).ok_or(REFUSED)?))))
        .collect::<Result<_>>()?;
    let sequence = u32::try_from(materials(installation)?.len() + 1).map_err(|_| REFUSED)?;
    let intent = Intent {
        schema: "elevenid.installer-feature-generation-intent/v1".into(),
        installation_id: selection.installation_id,
        feature_profile_sha256: selection.profile_sha256()?,
        activation_sha256: digest(&raw),
        producer_receipt_sha256: None,
        parent_session_sha256: session_hash(&parent)?,
        parent_session: parent.clone(),
        sequence,
        configuration: configuration.clone(),
        material_files: values
            .iter()
            .map(|(name, bytes)| (name.clone(), fingerprint(bytes)))
            .collect(),
    };
    store_once(
        state,
        installation,
        &record(sequence, "intent"),
        &encoded(&intent)?,
    )?;
    store_once(state, installation, ACTIVATION, &raw)?;
    let material = stage_material(
        state,
        installation,
        &selection,
        configuration,
        fingerprints,
        &values,
        Some(digest(&raw)),
    )?;
    activate_material(state, installation, docker, &material, &intent)
}

fn activation_intent(installation: &Path, activation_sha256: &str) -> Result<Intent> {
    let evidence = fs::directory(&installation.join("evidence"), REFUSED)?;
    let mut selected = None;
    for name in fs::file_names(&evidence, REFUSED)? {
        if !name.starts_with("generation-feature-")
            || !name.ends_with("-intent.json")
            || name.ends_with("-material-intent.json")
        {
            continue;
        }
        let intent: Intent = decode_record(&read_record(installation, &name)?)?;
        if intent.activation_sha256 != activation_sha256 {
            continue;
        }
        require(
            name == record(intent.sequence, "intent")
                && selected.is_none()
                && intent.schema == "elevenid.installer-feature-generation-intent/v1"
                && intent.parent_session_sha256 == session_hash(&intent.parent_session)?
                && intent.producer_receipt_sha256.is_none(),
        )?;
        selected = Some(intent);
    }
    selected.ok_or_else(|| REFUSED.into())
}

fn activate_material(
    state: &mut LockedMaintenance,
    installation: &Path,
    docker: &Path,
    material: &SelectedMaterial,
    intent: &Intent,
) -> Result<()> {
    require(
        intent.schema == "elevenid.installer-feature-generation-intent/v1"
            && intent.sequence == material.sequence
            && intent.installation_id == material.installation_id
            && intent.feature_profile_sha256 == material.feature_profile_sha256
            && intent.activation_sha256 == material.activation_sha256.clone().ok_or(REFUSED)?
            && intent.parent_session_sha256 == session_hash(&intent.parent_session)?
            && intent.configuration == material.configuration
            && intent.material_files == material.files
            && intent.producer_receipt_sha256.is_none(),
    )?;
    require_current_material(installation, material)?;
    let mut inputs = next_inputs(state, installation, material, &intent.parent_session)?;
    inputs.prior = Some(runtime_parent(installation, intent)?);
    let binding = state.journal().runtime().ok_or(REFUSED)?.clone();
    let initial = ComposeSession::new_generation(docker, &binding, inputs.clone())?;
    let selected = super::super::for_inputs(&inputs)?.ok_or(REFUSED)?;
    let added = require_model_transition(
        installation,
        &intent.parent_session,
        &selected,
        material,
        initial.model(),
    )?;
    let roles = initial.feature_changed_services(&intent.parent_session.model, &added)?;
    require(!roles.is_empty())?;
    inputs.services = roles.iter().cloned().collect();
    let plan = Plan {
        schema: "elevenid.installer-feature-activation-plan/v1".into(),
        installation_id: material.installation_id,
        sequence: material.sequence,
        material_sha256: digest(&read_record(installation, &material.record())?),
        parent_session_sha256: intent.parent_session_sha256.clone(),
        inputs: inputs.clone(),
        model: initial.model().clone(),
        configuration_sha256: initial.configuration_sha256().into(),
        service_hashes: initial.feature_service_hashes(),
        selected: roles,
        added,
    };
    store_once(
        state,
        installation,
        &record(material.sequence, "plan"),
        &encoded(&plan)?,
    )?;
    let permit = ActivationPermit { plan: plan.clone() };
    let session = ComposeSession::new_generation(docker, &binding, inputs.clone())?;
    let created = if let Some(receipt) = retained_native(
        installation,
        material,
        "activate-create",
        &plan,
        inputs.prior.as_ref().ok_or(REFUSED)?,
        session.configuration_sha256(),
    )? {
        receipt
    } else {
        require(
            optional_record(
                installation,
                &format!(
                    "generation-compose-{}-intent.json",
                    permit.operation("activate-create")
                ),
            )?
            .is_none(),
        )?;
        session.create_feature_replacements(state, &permit)?
    };
    require_current_material(installation, material)?;
    inputs.prior = Some(created.clone());
    let session = ComposeSession::new_generation(docker, &binding, inputs.clone())?;
    let started = if let Some(receipt) = retained_native(
        installation,
        material,
        "activate-start",
        &plan,
        inputs.prior.as_ref().ok_or(REFUSED)?,
        session.configuration_sha256(),
    )? {
        receipt
    } else {
        require(
            optional_record(
                installation,
                &format!(
                    "generation-compose-{}-intent.json",
                    permit.operation("activate-start")
                ),
            )?
            .is_none(),
        )?;
        session.start_existing_owned(
            state,
            RuntimeOperationOwner::Generation,
            &permit.operation("activate-start"),
            Duration::from_secs(180),
        )?
    };
    inputs.prior = Some(started.clone());
    inputs.services.clear();
    inputs.profiles = intent.parent_session.inputs.profiles.clone();
    let session = ComposeSession::new_generation(docker, &binding, inputs.clone())?;
    let model = session.model().clone();
    let configuration_sha256 = session.configuration_sha256().to_owned();
    let checkpoint = if let Some(receipt) = retained_native(
        installation,
        material,
        "checkpoint",
        &plan,
        inputs.prior.as_ref().ok_or(REFUSED)?,
        session.configuration_sha256(),
    )? {
        receipt
    } else {
        require(
            optional_record(
                installation,
                &format!(
                    "generation-compose-{}-intent.json",
                    permit.operation("checkpoint")
                ),
            )?
            .is_none(),
        )?;
        session.checkpoint_generation(state, &permit.operation("checkpoint"))?
    };
    require_current_material(installation, material)?;
    inputs.prior = Some(checkpoint.clone());
    let saved = SavedSession {
        schema: "elevenid.installer-compose-session/v1".into(),
        installation_id: material.installation_id.to_string(),
        inputs,
        model,
        configuration_sha256,
        receipt: checkpoint,
    };
    let complete = Completed {
        schema: "elevenid.installer-feature-generation-completed/v1".into(),
        installation_id: material.installation_id,
        sequence: material.sequence,
        material_sha256: digest(&read_record(installation, &material.record())?),
        intent_sha256: digest(&read_record(
            installation,
            &record(material.sequence, "intent"),
        )?),
        plan_sha256: digest(&read_record(
            installation,
            &record(material.sequence, "plan"),
        )?),
        create_receipt_sha256: digest(&read_record(
            installation,
            &native_record(material.sequence, "activate-create"),
        )?),
        start_receipt_sha256: digest(&read_record(
            installation,
            &native_record(material.sequence, "activate-start"),
        )?),
        checkpoint_receipt_sha256: digest(&read_record(
            installation,
            &native_record(material.sequence, "checkpoint"),
        )?),
        session: saved,
        activated: true,
        installation_ready: false,
    };
    store_once(
        state,
        installation,
        &record(material.sequence, "completed"),
        &encoded(&complete)?,
    )?;
    completed_sessions(installation)?;
    state.require_unchanged()
}

fn completed_sessions(installation: &Path) -> Result<Vec<(SavedSession, SavedSession)>> {
    let mut result = Vec::new();
    let all = materials(installation)?;
    for (position, (material, raw)) in all.iter().enumerate() {
        let Some(bytes) = optional_record(installation, &record(material.sequence, "completed"))?
        else {
            require(position + 1 == all.len())?;
            break;
        };
        if decode_record::<Value>(&bytes)?["schema"]
            == "elevenid.installer-feature-joint-completed/v1"
        {
            let complete: JointCompleted = decode_record(&bytes)?;
            require(
                complete.installation_id == material.installation_id
                    && complete.sequence == material.sequence
                    && complete.material_sha256 == digest(raw)
                    && complete.activated
                    && !complete.installation_ready
                    && material.renewal_receipt_sha256.is_some(),
            )?;
            let (parent, session) =
                crate::installer_generation_maintenance::verify_feature_joint_activation(
                    installation,
                    complete.baseline_sequence,
                    complete.baseline_attempt,
                    material.sequence,
                )?;
            require(
                complete.parent_session_sha256 == session_hash(&parent)?
                    && complete.session_sha256 == session_hash(&session)?,
            )?;
            require_joint_session(installation, material, &parent, &session)?;
            result.push((parent, session));
            continue;
        }
        let complete: Completed = decode_record(&bytes)?;
        let intent_raw = read_record(installation, &record(material.sequence, "intent"))?;
        let intent: Intent = decode_record(&intent_raw)?;
        let plan_raw = read_record(installation, &record(material.sequence, "plan"))?;
        let plan: Plan = decode_record(&plan_raw)?;
        require(
            complete.schema == "elevenid.installer-feature-generation-completed/v1"
                && complete.sequence == material.sequence
                && complete.installation_id == material.installation_id
                && complete.material_sha256 == digest(raw)
                && complete.intent_sha256 == digest(&intent_raw)
                && complete.plan_sha256 == digest(&plan_raw)
                && complete.activated
                && !complete.installation_ready
                && intent.schema == "elevenid.installer-feature-generation-intent/v1"
                && intent.sequence == material.sequence
                && intent.installation_id == material.installation_id
                && intent.feature_profile_sha256 == material.feature_profile_sha256
                && intent.parent_session_sha256 == session_hash(&intent.parent_session)?
                && intent.configuration == material.configuration
                && intent.material_files == material.files
                && intent.producer_receipt_sha256.is_none()
                && plan.schema == "elevenid.installer-feature-activation-plan/v1"
                && plan.sequence == material.sequence
                && plan.material_sha256 == digest(raw)
                && plan.parent_session_sha256 == intent.parent_session_sha256
                && plan.installation_id == material.installation_id,
        )?;
        let selected = super::super::for_inputs(&plan.inputs)?.ok_or(REFUSED)?;
        require(
            plan.added
                == require_model_transition(
                    installation,
                    &intent.parent_session,
                    &selected,
                    material,
                    &plan.model,
                )?
                && plan.configuration_sha256
                    == crate::installer_compose::model_sha256(&plan.model)?,
        )?;
        for (phase, expected) in [
            ("activate-create", &complete.create_receipt_sha256),
            ("activate-start", &complete.start_receipt_sha256),
            ("checkpoint", &complete.checkpoint_receipt_sha256),
        ] {
            let native_raw = read_record(installation, &native_record(material.sequence, phase))?;
            require(digest(&native_raw) == *expected)?;
            let native: ComposeReceipt = decode_record(&native_raw)?;
            check_native(&native, material.installation_id, &material.engine_id)?;
            require(native.operation == format!("feature-{:06}-{phase}", material.sequence))?;
            if phase == "checkpoint" {
                require(
                    encoded(&native)? == encoded(&complete.session.receipt)?
                        && native.configuration_sha256 == complete.session.configuration_sha256,
                )?;
            } else {
                require(native.configuration_sha256 == plan.configuration_sha256)?;
            }
        }
        require_native_chain(installation, material, &intent, &plan, &complete)?;
        require(
            complete.session.schema == "elevenid.installer-compose-session/v1"
                && complete.session.installation_id == material.installation_id.to_string()
                && complete.session.configuration_sha256
                    == crate::installer_compose::model_sha256(&complete.session.model)?
                && project(&complete.session.model)? == project(&plan.model)?
                && encoded(&complete.session.inputs.prior)?
                    == encoded(&Some(&complete.session.receipt))?,
        )?;
        crate::installer_compose::verify_input_files(
            installation,
            &complete.session.receipt.input_files,
        )?;
        result.push((intent.parent_session, complete.session));
    }
    Ok(result)
}

fn require_native_chain(
    installation: &Path,
    material: &SelectedMaterial,
    intent: &Intent,
    plan: &Plan,
    complete: &Completed,
) -> Result<()> {
    let parent_receipt = runtime_parent(installation, intent)?;
    let parent = parent_receipt.resources.as_ref().ok_or(REFUSED)?;
    let create: ComposeReceipt = decode_record(&read_record(
        installation,
        &native_record(material.sequence, "activate-create"),
    )?)?;
    let start: ComposeReceipt = decode_record(&read_record(
        installation,
        &native_record(material.sequence, "activate-start"),
    )?)?;
    let checkpoint = &complete.session.receipt;
    let created = create.resources.as_ref().ok_or(REFUSED)?;
    let started = start.resources.as_ref().ok_or(REFUSED)?;
    require(
        created.networks == parent.networks
            && created.volumes == parent.volumes
            && created == started
            && checkpoint.resources.as_ref() == Some(started)
            && created.containers.len() == parent.containers.len() + plan.added.len()
            && plan.selected == plan.inputs.services.iter().cloned().collect()
            && plan.added.is_subset(&plan.selected)
            && encoded(plan.inputs.prior.as_ref().ok_or(REFUSED)?)? == encoded(&parent_receipt)?,
    )?;
    let model_services = plan.model["services"].as_object().ok_or(REFUSED)?;
    let changed: BTreeSet<_> = model_services
        .keys()
        .filter(|role| {
            parent
                .containers
                .get(*role)
                .is_none_or(|old| plan.service_hashes.get(*role) != Some(&old.config_hash))
        })
        .cloned()
        .collect();
    require(
        changed == plan.selected
            && model_services.keys().all(|role| {
                plan.service_hashes
                    .get(role)
                    .is_some_and(|value| hash(value))
            }),
    )?;
    for (role, before) in &parent.containers {
        let after = created.containers.get(role).ok_or(REFUSED)?;
        if !plan.selected.contains(role) {
            require(before == after)?;
        } else {
            require(before.id != after.id && !before.setup)?;
        }
    }
    for role in &plan.selected {
        let after = created.containers.get(role).ok_or(REFUSED)?;
        require(
            !after.setup
                && plan.service_hashes.get(role) == Some(&after.config_hash)
                && model_services[role]["image"] == after.image
                && create
                    .status
                    .iter()
                    .filter(|row| row["Service"] == role.as_str())
                    .count()
                    == 1
                && create.status.iter().any(|row| {
                    row["Service"] == role.as_str()
                        && row["ID"] == after.id
                        && row["State"] == "created"
                }),
        )?;
    }
    for (phase, receipt, prior, command, selected) in [
        (
            "activate-create",
            &create,
            parent,
            json!([
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
            plan.inputs.services.clone(),
        ),
        (
            "activate-start",
            &start,
            created,
            json!(["start", "--wait", "--wait-timeout", "180"]),
            plan.inputs.services.clone(),
        ),
        (
            "checkpoint",
            checkpoint,
            started,
            json!(["ps", "--all", "--no-trunc", "--format", "json"]),
            Vec::<String>::new(),
        ),
    ] {
        let native: Value = decode_record(&read_record(
            installation,
            &format!(
                "generation-compose-feature-{:06}-{phase}-intent.json",
                material.sequence
            ),
        )?)?;
        require(
            native["schema"] == "elevenid.installer-compose-intent/v1"
                && native["project"] == receipt.project
                && native["engine_id"] == receipt.engine_id
                && native["configuration_sha256"] == receipt.configuration_sha256
                && native["input_files"]
                    == serde_json::to_value(&receipt.input_files).map_err(|_| REFUSED)?
                && native["prior_resources"] == serde_json::to_value(prior).map_err(|_| REFUSED)?
                && native["command"] == command
                && native["selected_services"] == json!(selected)
                && native["automatic_retry"] == false
                && native["installation_ready"] == false,
        )?;
    }
    for file in plan
        .inputs
        .files
        .iter()
        .chain(std::iter::once(&plan.inputs.environment))
        .chain(&plan.inputs.bound_inputs)
    {
        require(create.input_files.get(&file.path) == Some(&file.sha256))?;
    }
    Ok(())
}

fn retained_native(
    installation: &Path,
    material: &SelectedMaterial,
    phase: &str,
    plan: &Plan,
    prior: &ComposeReceipt,
    configuration_sha256: &str,
) -> Result<Option<ComposeReceipt>> {
    let Some(raw) = optional_record(installation, &native_record(material.sequence, phase))? else {
        return Ok(None);
    };
    let receipt: ComposeReceipt = decode_record(&raw)?;
    check_native(&receipt, material.installation_id, &material.engine_id)?;
    require(
        receipt.operation == format!("feature-{:06}-{phase}", material.sequence)
            && receipt.configuration_sha256 == configuration_sha256,
    )?;
    let before = prior.resources.as_ref().ok_or(REFUSED)?;
    let after = receipt.resources.as_ref().ok_or(REFUSED)?;
    require(before.networks == after.networks && before.volumes == after.volumes)?;
    let command = match phase {
        "activate-create" => json!([
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
        "activate-start" => json!(["start", "--wait", "--wait-timeout", "180"]),
        "checkpoint" => json!(["ps", "--all", "--no-trunc", "--format", "json"]),
        _ => return Err(REFUSED.into()),
    };
    let native: Value = decode_record(&read_record(
        installation,
        &format!("generation-compose-{}-intent.json", receipt.operation),
    )?)?;
    require(
        native["schema"] == "elevenid.installer-compose-intent/v1"
            && native["project"] == receipt.project
            && native["engine_id"] == receipt.engine_id
            && native["configuration_sha256"] == configuration_sha256
            && native["input_files"]
                == serde_json::to_value(&receipt.input_files).map_err(|_| REFUSED)?
            && native["prior_resources"] == serde_json::to_value(before).map_err(|_| REFUSED)?
            && native["command"] == command
            && native["selected_services"]
                == if phase == "checkpoint" {
                    json!([])
                } else {
                    json!(plan.inputs.services)
                }
            && native["automatic_retry"] == false
            && native["installation_ready"] == false,
    )?;
    if phase == "activate-create" {
        require(after.containers.len() == before.containers.len() + plan.added.len())?;
        for (role, old) in &before.containers {
            let new = after.containers.get(role).ok_or(REFUSED)?;
            if !plan.selected.contains(role) {
                require(old == new)?;
            } else {
                require(!old.setup && old.id != new.id)?;
            }
        }
        for role in &plan.selected {
            let new = after.containers.get(role).ok_or(REFUSED)?;
            require(
                !new.setup
                    && plan.service_hashes.get(role) == Some(&new.config_hash)
                    && plan.model["services"][role]["image"] == new.image
                    && receipt
                        .status
                        .iter()
                        .filter(|row| row["Service"] == role.as_str())
                        .count()
                        == 1
                    && receipt.status.iter().any(|row| {
                        row["Service"] == role.as_str()
                            && row["ID"] == new.id
                            && row["State"] == "created"
                    }),
            )?;
        }
    } else {
        require(before == after)?;
    }
    crate::installer_compose::verify_input_files(installation, &receipt.input_files)?;
    Ok(Some(receipt))
}

fn runtime_parent(installation: &Path, intent: &Intent) -> Result<ComposeReceipt> {
    if let Some(expected) = &intent.producer_receipt_sha256 {
        let raw = read_record(
            installation,
            &format!(
                "generation-compose-feature-{:06}-wait-result.json",
                intent.sequence
            ),
        )?;
        require(digest(&raw) == *expected)?;
        renewal::require_parent(installation, intent.sequence, &intent.parent_session)?;
        let receipt: ComposeReceipt = decode_record(&raw)?;
        check_native(
            &receipt,
            intent.installation_id,
            &intent.parent_session.receipt.engine_id,
        )?;
        Ok(receipt)
    } else {
        Ok(intent.parent_session.receipt.clone())
    }
}

fn require_current_material(installation: &Path, material: &SelectedMaterial) -> Result<()> {
    let original = super::super::at(installation)?.ok_or(REFUSED)?;
    if let Some(selection) = original.identity_selection()? {
        identity_current(&selection, &selected_files(installation, material)?)?;
    }
    renewal::require_fresh(installation, material)
}
fn identity_current(
    selection: &marty_selfhost_identity::features::Selection,
    values: &BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    crate::installer_feature_identity::validate_current_material(selection, values)
}

pub(crate) fn complete_baseline_activation(
    state: &mut LockedMaintenance,
    installation: &Path,
    baseline_sequence: u64,
    baseline_attempt: u64,
    feature_sequence: u32,
) -> Result<()> {
    let staged = renewal::load_staged_baseline(installation, feature_sequence)?;
    let material: SelectedMaterial =
        decode_record(&read_record(installation, &staged.material_record())?)?;
    let (parent, session) =
        crate::installer_generation_maintenance::verify_feature_joint_activation(
            installation,
            baseline_sequence,
            baseline_attempt,
            feature_sequence,
        )?;
    require_joint_session(installation, &material, &parent, &session)?;
    let observed_at =
        crate::installer_generation_maintenance::feature_joint_activation_observed_at(
            installation,
            baseline_sequence,
            baseline_attempt,
            feature_sequence,
        )?;
    staged.require_usable_at(installation, observed_at)?;
    let complete = JointCompleted {
        schema: "elevenid.installer-feature-joint-completed/v1".into(),
        installation_id: material.installation_id,
        sequence: material.sequence,
        material_sha256: staged.material_sha256(installation)?,
        baseline_sequence,
        baseline_attempt,
        parent_session_sha256: session_hash(&parent)?,
        session_sha256: session_hash(&session)?,
        activated: true,
        installation_ready: false,
    };
    store_once(
        state,
        installation,
        &record(material.sequence, "completed"),
        &encoded(&complete)?,
    )?;
    completed_sessions(installation)?;
    state.require_unchanged()
}

fn require_joint_session(
    installation: &Path,
    material: &SelectedMaterial,
    parent: &SavedSession,
    session: &SavedSession,
) -> Result<()> {
    renewal::require_parent(installation, material.sequence, parent)?;
    let previous = super::super::for_inputs(&parent.inputs)?.ok_or(REFUSED)?;
    let selected = super::super::for_inputs(&session.inputs)?.ok_or(REFUSED)?;
    require(
        previous.configuration == material.configuration
            && selected.configuration == material.configuration
            && selected
                .generation
                .as_ref()
                .is_some_and(|value| value.record() == material.record())
            && session.schema == "elevenid.installer-compose-session/v1"
            && session.installation_id == material.installation_id.to_string()
            && session.configuration_sha256
                == crate::installer_compose::model_sha256(&session.model)?
            && encoded(&session.inputs.prior)? == encoded(&Some(&session.receipt))?,
    )?;
    check_native(
        &session.receipt,
        material.installation_id,
        &material.engine_id,
    )?;
    crate::installer_compose::verify_input_files(installation, &session.receipt.input_files)
}

pub(crate) fn require_session_extension(
    installation: &Path,
    recorded: &SavedSession,
    successor: &SavedSession,
) -> Result<()> {
    let initial = session_hash(recorded)?;
    let mut target = session_hash(successor)?;
    if target == initial {
        return Ok(());
    }
    for (parent, session) in completed_sessions(installation)?.into_iter().rev() {
        if session_hash(&session)? == target {
            target = session_hash(&parent)?;
            if target == initial {
                return Ok(());
            }
        }
    }
    Err(REFUSED.into())
}

pub(crate) fn extend_session(
    view: &LockedInspection,
    installation: &Path,
    baseline: SavedSession,
) -> Result<SavedSession> {
    view.require_path_binding(installation)?;
    if super::super::load(view)?.is_none() {
        return Ok(baseline);
    }
    let sessions = completed_sessions(installation)?;
    if let Some((root, _, _)) = root_at(installation)? {
        require(fs::file_names(&root, REFUSED)?.len() == sessions.len())?;
    }
    let Some((_, latest)) = sessions.last() else {
        return Ok(baseline);
    };
    if require_session_extension(installation, &baseline, latest).is_ok() {
        return Ok(latest.clone());
    }
    // A newer base credential generation has already incorporated this exact
    // feature projection. Its own immutable parent-model validator proves that
    // ancestry, so retain the newer native IDs and base credentials.
    let current = super::super::for_inputs(&baseline.inputs)?.ok_or(REFUSED)?;
    let latest_selection = super::super::for_inputs(&latest.inputs)?.ok_or(REFUSED)?;
    require(
        current.generation.as_ref().map(|v| v.record())
            == latest_selection.generation.as_ref().map(|v| v.record())
            && current.generation.is_some()
            && current.configuration == latest_selection.configuration,
    )?;
    current.validate_model(installation, &baseline.model)?;
    view.require_unchanged()?;
    Ok(baseline)
}
