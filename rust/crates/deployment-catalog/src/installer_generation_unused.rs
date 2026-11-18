//! Retire a preparation which expired before the immutable helper intent.
//! Absence is proved against the held installation and the actual unchanged
//! native census; a stopped or failed producer is never an unused preparation.
use super::*;

const SCHEMA: &str = "elevenid.installer-generation-unused-preparation/v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Source {
    Selected {
        session_sha256: String,
    },
    Recovery {
        attempt: u64,
        baseline_sha256: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Node {
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
    length: u64,
    modified_at: i64,
    modified_ns: i64,
    changed_at: i64,
    changed_ns: i64,
}
impl Node {
    fn of(file: &File) -> Result<Self> {
        let value = file.metadata().map_err(|_| REFUSED)?;
        require(value.uid() == unsafe { libc::geteuid() })?;
        Ok(Self {
            device: value.dev(),
            inode: value.ino(),
            uid: value.uid(),
            gid: value.gid(),
            mode: value.mode(),
            links: value.nlink(),
            length: value.len(),
            modified_at: value.mtime(),
            modified_ns: value.mtime_nsec(),
            changed_at: value.ctime(),
            changed_ns: value.ctime_nsec(),
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreparedFile {
    node: Node,
    sha256: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreparedDirectory {
    node: Node,
    files: BTreeMap<String, PreparedFile>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Preparation {
    evidence_sha256: BTreeMap<String, String>,
    current: Option<PreparedDirectory>,
    identity: Option<PreparedDirectory>,
    transfer: Option<Node>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct UnusedPreparation {
    schema: String,
    installation_id: String,
    engine_id: String,
    sequence: u64,
    attempt: u64,
    previous_attempt: u64,
    pub(super) parent_attempt: u64,
    pub(super) parent_binding_sha256: String,
    parent_session_sha256: String,
    source: Source,
    public_plan_sha256: String,
    certificate_not_after: u64,
    preparation: Preparation,
    pub(super) inputs: ComposeInputs,
    pub(super) model: Value,
    pub(super) configuration_sha256: String,
    observation: NativeReference,
    pub(super) stopped_services: BTreeSet<String>,
    pub(super) runtime_generation_root: PathBuf,
    pub(super) last_helper: Option<Attempt>,
    pub(super) observed_at: u64,
    helper_authorized: bool,
    activation_performed: bool,
    installation_ready: bool,
}
impl UnusedPreparation {
    pub(super) fn scope(&self) -> Attempt {
        Attempt::new(self.sequence, self.attempt)
    }
    fn previous(&self) -> Attempt {
        Attempt::new(self.sequence, self.previous_attempt)
    }
}

pub(super) fn recorded_parent_session(
    installation: &Path,
    parent: &GenerationBinding,
) -> Result<SavedSession> {
    let name = if parent.sequence() == 0 {
        installer_doctor::SESSION_RECORD.into()
    } else {
        parent.record_name("session")
    };
    let bytes = read(installation, &name)?;
    let saved: SavedSession = decode(&bytes)?;
    require(
        saved.installation_id == parent.installation_id
            && saved.inputs.installation == installation
            && saved.receipt.engine_id == parent.engine_id
            && saved.receipt.configuration_sha256 == saved.configuration_sha256
            && installer_compose::model_sha256(&saved.model)? == saved.configuration_sha256,
    )?;
    Ok(saved)
}

struct Origin {
    source: Source,
    inputs: ComposeInputs,
    model: Value,
    configuration_sha256: String,
    runtime_root: PathBuf,
    stopped: BTreeSet<String>,
    last_helper: Option<Attempt>,
    observed_at: u64,
}
fn origin(
    installation: &Path,
    previous: Attempt,
    parent: &GenerationBinding,
    saved: &SavedSession,
    incoming: Option<&GenerationRecoveryBaseline>,
) -> Result<Origin> {
    require(parent.sequence().checked_add(1) == Some(previous.sequence))?;
    if previous.number == 0 {
        require(incoming.is_none())?;
        let mut inputs = saved.inputs.clone();
        inputs.prior = Some(saved.receipt.clone());
        inputs.services.clear();
        Ok(Origin {
            source: Source::Selected {
                session_sha256: hash(&encode(saved)?),
            },
            inputs,
            model: saved.model.clone(),
            configuration_sha256: saved.configuration_sha256.clone(),
            runtime_root: parent.secret_dir(installation)?,
            stopped: BTreeSet::new(),
            last_helper: (parent.sequence() > 0).then_some(parent.attempt_id()),
            observed_at: 0,
        })
    } else {
        let incoming = incoming.ok_or(REFUSED)?;
        require(incoming.scope() == previous)?;
        Ok(Origin {
            source: Source::Recovery {
                attempt: previous.number,
                baseline_sha256: incoming.sha256().into(),
            },
            inputs: incoming.inputs().clone(),
            model: incoming.model().clone(),
            configuration_sha256: incoming.configuration_sha256().into(),
            runtime_root: incoming.runtime_root().into(),
            stopped: incoming.stopped_services().clone(),
            last_helper: incoming.last_helper()?,
            observed_at: incoming.observed_at(),
        })
    }
}

fn saved_plan(installation: &Path, scope: Attempt) -> Result<PublicIngressPlan> {
    let bytes = read(installation, &scope.record("public-ingress-plan"))?;
    let plan = PublicIngressPlan::parse_authenticated(&bytes, &hash(&bytes))?;
    require(plan.record_name() == scope.record("public-ingress-plan"))?;
    Ok(plan)
}
fn expired(plan: &PublicIngressPlan, at: u64) -> Result<bool> {
    // Parsing the plan already proves the original public trust path, exact
    // SAN/key and original admission. Local wall time is a separate check.
    let admission = plan.certificate_admission();
    let observed = admission["observed_at"].as_u64().ok_or(REFUSED)?;
    let before = admission["not_before"].as_u64().ok_or(REFUSED)?;
    let after = admission["not_after"].as_u64().ok_or(REFUSED)?;
    require(
        after > before
            && before <= observed
            && observed < after
            && at >= before
            && observed <= at.saturating_add(120),
    )?;
    Ok(at >= after)
}

fn own_evidence(name: &str, scope: Attempt) -> bool {
    let prefix = if scope.number == 0 {
        format!("generation-{:020}-", scope.sequence)
    } else {
        format!(
            "generation-{:020}-attempt-{:020}-",
            scope.sequence, scope.number
        )
    };
    name.strip_prefix(&prefix)
        .is_some_and(|suffix| scope.number > 0 || !suffix.starts_with("attempt-"))
}
fn native_suffix(name: &str, scope: Attempt) -> Option<&str> {
    let prefix = format!("generation-compose-{}-", scope.operation_prefix());
    let suffix = name.strip_prefix(&prefix)?;
    if scope.number == 0
        && suffix.strip_prefix('a').is_some_and(|v| {
            v.len() > 20
                && v.as_bytes()[..20].iter().all(u8::is_ascii_digit)
                && v.as_bytes()[20] == b'-'
        })
    {
        None
    } else {
        Some(suffix)
    }
}

pub(super) fn orphan_evidence(names: &BTreeSet<String>, scope: Attempt) -> bool {
    names
        .iter()
        .any(|name| own_evidence(name, scope) || native_suffix(name, scope).is_some())
}
pub(super) fn saved_status(installation: &Path, scope: Attempt) -> Result<(u64, bool)> {
    let plan = saved_plan(installation, scope)?;
    Ok((
        plan.certificate_admission()["not_after"]
            .as_u64()
            .ok_or(REFUSED)?,
        expired(&plan, now()?)?,
    ))
}

/// No intent or native producer execution can be hidden behind an absent
/// result. Only the separately verified incoming recovery's operations and
/// exact read-only/stop observations may precede this preparation.
fn evidence(
    installation: &Path,
    scope: Attempt,
    incoming: Option<&GenerationRecoveryBaseline>,
    plan_kind: &str,
) -> Result<BTreeMap<String, String>> {
    let held = directory(&installation.join("evidence"))?;
    let names = fs::file_names(&held, REFUSED)?;
    let mut allowed = BTreeSet::from([scope.record(plan_kind), scope.environment_name("helper")]);
    match incoming.map(|v| &v.data) {
        Some(BaselineRecord::Completed(_)) => {
            allowed.insert(scope.record("supersession-intent"));
            allowed.insert(scope.record("supersession-baseline"));
        }
        Some(BaselineRecord::Unused(_)) => {
            allowed.insert(scope.record("unused-preparation"));
        }
        None => require(scope.number == 0)?,
    }
    let mut result = BTreeMap::new();
    for name in &names {
        if own_evidence(name, scope) {
            require(allowed.contains(name))?;
            result.insert(name.clone(), hash(&read(installation, name)?));
        } else if let Some(suffix) = native_suffix(name, scope) {
            let (operation, kind) = suffix.rsplit_once('-').ok_or(REFUSED)?;
            require(["intent.json", "result.json"].contains(&kind))?;
            let (phase, ordinal) = operation.rsplit_once('-').ok_or(REFUSED)?;
            require(ordinal.len() == 6 && ordinal.bytes().all(|v| v.is_ascii_digit()))?;
            let incoming_operation = matches!(
                incoming.map(|v| &v.data),
                Some(BaselineRecord::Completed(_))
            ) && [
                "supersede-stop",
                "supersede-create",
                "supersede-observe",
                "supersede-baseline",
                "supersede-pause",
            ]
            .contains(&phase);
            require(incoming_operation || ["unused-baseline", "unused-pause"].contains(&phase))?;
            let intent_name = format!(
                "generation-compose-{}-{operation}-intent.json",
                scope.operation_prefix()
            );
            let intent: Value = decode(&read(installation, &intent_name)?)?;
            let command = intent["command"].as_array().ok_or(REFUSED)?;
            if ["unused-baseline", "supersede-baseline", "supersede-observe"].contains(&phase) {
                require(
                    command
                        == &vec![
                            json!("ps"),
                            json!("--all"),
                            json!("--no-trunc"),
                            json!("--format"),
                            json!("json"),
                        ],
                )?;
            } else if phase == "unused-pause"
                || phase == "supersede-pause"
                || phase == "supersede-stop"
            {
                require(
                    command.len() > 3
                        && command[..3] == [json!("stop"), json!("--timeout"), json!("60")]
                        && command[3..]
                            .iter()
                            .all(|v| v.as_str().is_some_and(|v| v != "installer-generation")),
                )?;
            } else if phase == "supersede-create" {
                require(
                    command.iter().any(|v| v == "--no-start")
                        && !command.iter().any(|v| v == "installer-generation"),
                )?;
            } else {
                return Err(REFUSED.into());
            }
            result.insert(name.clone(), hash(&read(installation, name)?));
        }
    }
    require(result.contains_key(&scope.record(plan_kind)))?;
    require(fs::file_names(&held, REFUSED)? == names)?;
    fs::require_directory_binding(&installation.join("evidence"), &held, REFUSED)?;
    Ok(result)
}

fn optional_directory(parent: &File, name: &str) -> Result<Option<File>> {
    if !fs::file_names(parent, REFUSED)?.contains(name) {
        return Ok(None);
    }
    let value = fs::open_child(parent, name, libc::O_RDONLY | libc::O_DIRECTORY, REFUSED)?;
    let node = Node::of(&value)?;
    require(node.mode & 0o7777 == 0o700)?;
    Ok(Some(value))
}
fn prepared_file(
    dir: &File,
    name: &str,
    expected: &[u8],
    mode: u32,
    partial: bool,
) -> Result<PreparedFile> {
    let mut file = fs::open_child(dir, name, libc::O_RDONLY | libc::O_NONBLOCK, REFUSED)?;
    let node = Node::of(&file)?;
    require(
        node.mode & libc::S_IFMT == libc::S_IFREG
            && node.links == 1
            && node.length <= expected.len() as u64
            && if partial {
                [0o600, mode].contains(&(node.mode & 0o7777))
            } else {
                node.mode & 0o7777 == mode
            },
    )?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| REFUSED)?;
    require(
        bytes.len() as u64 == node.length
            && Node::of(&file)? == node
            && if partial {
                expected.starts_with(&bytes) && (node.mode & 0o7777 == 0o600 || bytes == expected)
            } else {
                bytes == expected
            },
    )?;
    // Match the held inode again, not just equivalent bytes in a new file.
    require(
        Node::of(&fs::open_child(
            dir,
            name,
            libc::O_RDONLY | libc::O_NONBLOCK,
            REFUSED,
        )?)? == node,
    )?;
    Ok(PreparedFile {
        node,
        sha256: hash(&bytes),
    })
}
fn copied_directory(
    parent: &File,
    name: &str,
    expected: &BTreeMap<String, Vec<u8>>,
    mode: u32,
) -> Result<Option<PreparedDirectory>> {
    let Some(dir) = optional_directory(parent, name)? else {
        return Ok(None);
    };
    let node = Node::of(&dir)?;
    let names = fs::file_names(&dir, REFUSED)?;
    let mut files = BTreeMap::new();
    let mut seen = BTreeSet::new();
    for name in &names {
        let (key, partial) = if expected.contains_key(name) {
            (name.as_str(), false)
        } else {
            (
                name.strip_prefix("copy-")
                    .and_then(|v| v.strip_suffix(".tmp"))
                    .ok_or(REFUSED)?,
                true,
            )
        };
        require(seen.insert(key))?;
        files.insert(
            name.clone(),
            prepared_file(&dir, name, expected.get(key).ok_or(REFUSED)?, mode, partial)?,
        );
    }
    require(
        fs::file_names(&dir, REFUSED)? == names
            && Node::of(&dir)? == node
            && Node::of(&fs::open_child(
                parent,
                name,
                libc::O_RDONLY | libc::O_DIRECTORY,
                REFUSED,
            )?)? == node,
    )?;
    Ok(Some(PreparedDirectory { node, files }))
}

fn snapshot(
    installation: &Path,
    scope: Attempt,
    parent: &GenerationBinding,
    saved: &SavedSession,
    plan: &PublicIngressPlan,
    incoming: Option<&GenerationRecoveryBaseline>,
) -> Result<Preparation> {
    snapshot_plan(
        installation,
        scope,
        parent,
        saved,
        &GenerationPlan::Public(Box::new(plan.clone())),
        incoming,
    )
}
fn snapshot_plan(
    installation: &Path,
    scope: Attempt,
    parent: &GenerationBinding,
    saved: &SavedSession,
    plan: &GenerationPlan,
    incoming: Option<&GenerationRecoveryBaseline>,
) -> Result<Preparation> {
    let evidence_sha256 = evidence(installation, scope, incoming, plan.plan_kind())?;
    let env_name = scope.environment_name("helper");
    if evidence_sha256.contains_key(&env_name) {
        let mut values = plan.environment(installation)?;
        values.insert(
            "MARTY_GENERATION_WORK_DIR",
            path_text(&scope.work(installation))?.into(),
        );
        let expected = environment(
            &crate::installer_verify::read_private_bytes(&saved.inputs.environment.path, 65536)?,
            &values,
        )?;
        require(read(installation, &env_name)? == expected)?;
    }
    let mut result = Preparation {
        evidence_sha256,
        current: None,
        identity: None,
        transfer: None,
    };
    let root = directory(installation)?;
    let Some(work) = optional_directory(&root, "generation-work")? else {
        require(!fs::file_names(&root, REFUSED)?.contains("generation-work"))?;
        fs::require_directory_binding(installation, &root, REFUSED)?;
        return Ok(result);
    };
    let sequence_name = format!("{:020}", scope.sequence);
    let Some(sequence) = optional_directory(&work, &sequence_name)? else {
        require(!fs::file_names(&work, REFUSED)?.contains(&sequence_name))?;
        fs::require_directory_binding(&installation.join("generation-work"), &work, REFUSED)?;
        fs::require_directory_binding(installation, &root, REFUSED)?;
        return Ok(result);
    };
    let held = if scope.number == 0 {
        sequence.try_clone().map_err(|_| REFUSED)?
    } else {
        let Some(attempt) =
            optional_directory(&sequence, &format!("attempt-{:020}", scope.number))?
        else {
            require(
                !fs::file_names(&sequence, REFUSED)?
                    .contains(&format!("attempt-{:020}", scope.number)),
            )?;
            fs::require_directory_binding(
                &installation.join("generation-work").join(&sequence_name),
                &sequence,
                REFUSED,
            )?;
            fs::require_directory_binding(&installation.join("generation-work"), &work, REFUSED)?;
            fs::require_directory_binding(installation, &root, REFUSED)?;
            return Ok(result);
        };
        attempt
    };
    let names = fs::file_names(&held, REFUSED)?;
    require(names.iter().all(|name| {
        ["current", "identity", "transfer"].contains(&name.as_str())
            || (scope.number == 0
                && name.strip_prefix("attempt-").is_some_and(|v| {
                    v.len() == 20
                        && v.bytes().all(|v| v.is_ascii_digit())
                        && v != "00000000000000000000"
                }))
    }))?;
    let source = plan
        .inputs()
        .into_iter()
        .map(|name| Ok((name.clone(), parent.read(installation, &name)?)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    result.current = copied_directory(&held, "current", &source, 0o444)?;
    if names.contains("identity") {
        let identities = host::read_identity(&directory(
            &installation.join("renewal-transfer/delivered"),
        )?)?;
        result.identity = copied_directory(&held, "identity", &identities, 0o600)?;
    }
    if let Some(transfer) = optional_directory(&held, "transfer")? {
        let node = Node::of(&transfer)?;
        require(
            fs::file_names(&transfer, REFUSED)?.is_empty()
                && Node::of(&fs::open_child(
                    &held,
                    "transfer",
                    libc::O_RDONLY | libc::O_DIRECTORY,
                    REFUSED,
                )?)? == node,
        )?;
        result.transfer = Some(node);
    }
    require(fs::file_names(&held, REFUSED)? == names)?;
    fs::require_directory_binding(&scope.work(installation), &held, REFUSED)?;
    fs::require_directory_binding(
        &installation.join("generation-work").join(sequence_name),
        &sequence,
        REFUSED,
    )?;
    fs::require_directory_binding(&installation.join("generation-work"), &work, REFUSED)?;
    fs::require_directory_binding(installation, &root, REFUSED)?;
    Ok(result)
}

fn require_record(
    installation: &Path,
    parent: &crate::installer_generation_binding::VerifiedGeneration,
    previous: Attempt,
    incoming: Option<&GenerationRecoveryBaseline>,
    value: &UnusedPreparation,
) -> Result<()> {
    let binding = parent.binding();
    let saved = recorded_parent_session(installation, binding)?;
    let source = origin(installation, previous, binding, &saved, incoming)?;
    let plan = saved_plan(installation, previous)?;
    plan.require_verified_parent(installation, parent)?;
    require(
        value.schema == SCHEMA
            && value.scope().sequence == previous.sequence
            && value.previous() == previous
            && previous.number.checked_add(1) == Some(value.attempt)
            && value.installation_id == binding.installation_id
            && value.engine_id == binding.engine_id
            && value.parent_attempt == binding.attempt()
            && value.parent_binding_sha256 == binding.sha256()?
            && value.parent_session_sha256 == hash(&encode(&saved)?)
            && value.source == source.source
            && value.public_plan_sha256 == plan.sha256()?
            && value.certificate_not_after
                == plan.certificate_admission()["not_after"]
                    .as_u64()
                    .ok_or(REFUSED)?
            && expired(&plan, value.observed_at)?
            && value.observed_at >= source.observed_at
            && value.observed_at <= now()?.saturating_add(120)
            && value.model == source.model
            && value.configuration_sha256 == source.configuration_sha256
            && value.runtime_generation_root == source.runtime_root
            && value.stopped_services == source.stopped
            && value.last_helper == source.last_helper
            && !value.helper_authorized
            && !value.activation_performed
            && !value.installation_ready
            && optional(installation, &value.scope().record("supersession-intent"))?.is_none()
            && optional(installation, &value.scope().record("supersession-baseline"))?.is_none(),
    )?;
    require(
        value.preparation == snapshot(installation, previous, binding, &saved, &plan, incoming)?,
    )?;
    let receipt = native(installation, &value.observation)?;
    require(
        receipt.operation.starts_with(&format!(
            "{}-unused-baseline-",
            value.scope().operation_prefix()
        )) && receipt.engine_id == value.engine_id
            && receipt.project == source.inputs.project
            && receipt.configuration_sha256 == value.configuration_sha256
            && receipt.resources == source.inputs.prior.as_ref().ok_or(REFUSED)?.resources,
    )?;
    require_baseline_status(
        receipt.resources.as_ref().ok_or(REFUSED)?,
        &receipt.status,
        &source.stopped,
    )?;
    let mut expected = source.inputs;
    expected.prior = Some(receipt.clone());
    require(
        encode(&expected)? == encode(&value.inputs)?
            && receipt.input_files == input_files(&value.inputs)?,
    )?;
    let observation: Value = decode(&read(
        installation,
        &format!("generation-compose-{}-intent.json", receipt.operation,),
    )?)?;
    require(
        observation["schema"] == "elevenid.installer-compose-intent/v1"
            && observation["project"] == receipt.project
            && observation["engine_id"] == receipt.engine_id
            && observation["configuration_sha256"] == receipt.configuration_sha256
            && observation["input_files"]
                == serde_json::to_value(&receipt.input_files).map_err(|_| REFUSED)?
            && observation["prior_resources"]
                == serde_json::to_value(&receipt.resources).map_err(|_| REFUSED)?
            && observation["command"] == json!(["ps", "--all", "--no-trunc", "--format", "json"])
            && observation["selected_services"] == json!([])
            && observation["automatic_retry"] == false
            && observation["installation_ready"] == false,
    )?;
    installer_compose::verify_input_files(installation, &receipt.input_files)
}

pub(super) fn historical(
    installation: &Path,
    parent: &crate::installer_generation_binding::VerifiedGeneration,
    previous: Attempt,
    incoming: Option<&GenerationRecoveryBaseline>,
) -> Result<GenerationRecoveryBaseline> {
    let next = Attempt::new(
        previous.sequence,
        previous.number.checked_add(1).ok_or(REFUSED)?,
    );
    let result = recorded_baseline(installation, next)?;
    let BaselineRecord::Unused(value) = &result.data else {
        return Err(REFUSED.into());
    };
    require_record(installation, parent, previous, incoming, value)?;
    Ok(result)
}

pub(super) fn require_preparation(
    view: &LockedInspection,
    installation: &Path,
    scope: Attempt,
    parent: &GenerationBinding,
) -> Result<()> {
    view.require_path_binding(installation)?;
    let plan = saved_plan(installation, scope)?;
    plan.require_saved(view)?;
    plan.require_parent(installation, parent)?;
    let saved = parent_session(view, installation)?;
    require(encode(&saved)? == encode(&recorded_parent_session(installation, parent)?)?)?;
    let incoming = if scope.number > 0 {
        Some(load_baseline(view, installation, scope)?)
    } else {
        None
    };
    origin(installation, scope, parent, &saved, incoming.as_ref())?;
    snapshot(
        installation,
        scope,
        parent,
        &saved,
        &plan,
        incoming.as_ref(),
    )?;
    view.require_unchanged()
}

fn managed_plan(installation: &Path, scope: Attempt) -> Result<GenerationPlan> {
    let bytes = read(installation, &scope.record("managed-renewal-plan"))?;
    GenerationPlan::load(installation, scope, PlanSource::Managed, &hash(&bytes))
}
pub(super) fn require_managed_preparation(
    view: &LockedInspection,
    installation: &Path,
    scope: Attempt,
    parent: &GenerationBinding,
) -> Result<()> {
    view.require_path_binding(installation)?;
    require(parent.managed_ingress())?;
    let plan = managed_plan(installation, scope)?;
    plan.require_saved(view)?;
    plan.require_parent(installation, parent)?;
    let saved = parent_session(view, installation)?;
    require(encode(&saved)? == encode(&recorded_parent_session(installation, parent)?)?)?;
    let incoming = if scope.number > 0 {
        Some(load_baseline(view, installation, scope)?)
    } else {
        None
    };
    origin(installation, scope, parent, &saved, incoming.as_ref())?;
    snapshot_plan(
        installation,
        scope,
        parent,
        &saved,
        &plan,
        incoming.as_ref(),
    )?;
    view.require_unchanged()
}
pub(super) fn resume_managed_preparation(
    installation: &Path,
    docker: &Path,
    state: &mut LockedMaintenance,
    scope: Attempt,
) -> Result<GenerationBinding> {
    crate::installer_lifecycle::require_recorded_running_intent(state.inspection(), installation)?;
    crate::installer_root_retirement::require_no_pending_for_generation(state.inspection())?;
    let parent = selected_parent(state.inspection(), installation)?;
    require_managed_preparation(state.inspection(), installation, scope, &parent)?;
    let incoming = if scope.number > 0 {
        Some(load_baseline(state.inspection(), installation, scope)?)
    } else {
        None
    };
    let plan = managed_plan(installation, scope)?;
    // Old private tokens/leaf are authenticated historical input, not an
    // expiring public candidate. Resume this exact plan and fixed issuer.
    let intent = begin_with_plan(
        installation,
        docker,
        state,
        &parent,
        &plan,
        scope,
        incoming.as_ref(),
    )?;
    reconcile(installation, docker, state, &intent, false)
}

fn live_origin(
    docker: &Path,
    runtime: &crate::installer_state::RuntimeBinding,
    source: &Origin,
) -> Result<ComposeSession> {
    let session = ComposeSession::new_generation(docker, runtime, source.inputs.clone())?;
    require(
        session.model() == &source.model
            && session.configuration_sha256() == source.configuration_sha256
            && session.observe_resources()?
                == *source
                    .inputs
                    .prior
                    .as_ref()
                    .ok_or(REFUSED)?
                    .resources
                    .as_ref()
                    .ok_or(REFUSED)?,
    )?;
    require_baseline_status(
        source
            .inputs
            .prior
            .as_ref()
            .ok_or(REFUSED)?
            .resources
            .as_ref()
            .ok_or(REFUSED)?,
        &session.status()?,
        &source.stopped,
    )?;
    Ok(session)
}

fn retire(
    installation: &Path,
    docker: &Path,
    state: &mut LockedMaintenance,
    previous: Attempt,
    parent: &GenerationBinding,
    incoming: Option<&GenerationRecoveryBaseline>,
) -> Result<GenerationRecoveryBaseline> {
    crate::installer_lifecycle::require_recorded_running_intent(state.inspection(), installation)?;
    crate::installer_root_retirement::require_no_pending_for_generation(state.inspection())?;
    require_preparation(state.inspection(), installation, previous, parent)?;
    let next = Attempt::new(
        previous.sequence,
        previous.number.checked_add(1).ok_or(REFUSED)?,
    );
    require(
        optional(installation, &next.record("unused-preparation"))?.is_none()
            && optional(installation, &next.record("supersession-intent"))?.is_none()
            && optional(installation, &next.record("intent"))?.is_none(),
    )?;
    let saved = parent_session(state.inspection(), installation)?;
    let source = origin(installation, previous, parent, &saved, incoming)?;
    let plan = saved_plan(installation, previous)?;
    let at = now()?;
    require(expired(&plan, at)? && at >= source.observed_at)?;
    let before = snapshot(installation, previous, parent, &saved, &plan, incoming)?;
    let session = live_origin(docker, state.journal().runtime().ok_or(REFUSED)?, &source)?;
    // This native operation is a read. Its durable result cannot create or
    // start a helper, including if the controller dies before the proof below.
    let operation = operation(state.inspection(), next, "unused-baseline")?;
    let receipt = session.checkpoint_generation_baseline(state, &operation, &source.stopped)?;
    let observation = native_reference(state, &receipt)?;
    require(
        receipt.resources == source.inputs.prior.as_ref().ok_or(REFUSED)?.resources
            && before == snapshot(installation, previous, parent, &saved, &plan, incoming)?,
    )?;
    live_origin(docker, state.journal().runtime().ok_or(REFUSED)?, &source)?;
    let mut inputs = source.inputs;
    inputs.prior = Some(receipt);
    let value = UnusedPreparation {
        schema: SCHEMA.into(),
        installation_id: parent.installation_id.clone(),
        engine_id: parent.engine_id.clone(),
        sequence: next.sequence,
        attempt: next.number,
        previous_attempt: previous.number,
        parent_attempt: parent.attempt(),
        parent_binding_sha256: parent.sha256()?,
        parent_session_sha256: hash(&encode(&saved)?),
        source: source.source,
        public_plan_sha256: plan.sha256()?,
        certificate_not_after: plan.certificate_admission()["not_after"]
            .as_u64()
            .ok_or(REFUSED)?,
        preparation: before,
        inputs,
        model: source.model,
        configuration_sha256: source.configuration_sha256,
        observation,
        stopped_services: source.stopped,
        runtime_generation_root: source.runtime_root,
        last_helper: source.last_helper,
        observed_at: now()?,
        helper_authorized: false,
        activation_performed: false,
        installation_ready: false,
    };
    let verified_parent =
        generation::load_verified_attempt(installation, parent.sequence(), parent.attempt())?;
    require(verified_parent.binding() == parent)?;
    require_record(installation, &verified_parent, previous, incoming, &value)?;
    // This proof is the sole authority to allocate the next immutable
    // attempt. All previous preparation bytes and inode bindings remain.
    store(state, &next.record("unused-preparation"), &encode(&value)?)?;
    load_baseline(state.inspection(), installation, next)
}

pub(super) fn resume_preparation(
    installation: &Path,
    docker: &Path,
    state: &mut LockedMaintenance,
    scope: Attempt,
) -> Result<GenerationBinding> {
    crate::installer_lifecycle::require_recorded_running_intent(state.inspection(), installation)?;
    crate::installer_root_retirement::require_no_pending_for_generation(state.inspection())?;
    let parent = selected_parent(state.inspection(), installation)?;
    require_preparation(state.inspection(), installation, scope, &parent)?;
    let incoming = if scope.number > 0 {
        Some(load_baseline(state.inspection(), installation, scope)?)
    } else {
        None
    };
    let plan = saved_plan(installation, scope)?;
    if expired(&plan, now()?)? {
        let baseline = retire(
            installation,
            docker,
            state,
            scope,
            &parent,
            incoming.as_ref(),
        )?;
        return resume_retired(installation, docker, state, baseline.scope());
    }
    // A still-usable plan belongs to this attempt exactly. Do not substitute
    // another CA result or rewrite its immutable environment after a crash.
    plan.validate_current_certificate()?;
    let candidate = candidate_for_plan(state.inspection(), &plan)?;
    let intent = begin(
        installation,
        docker,
        state,
        &parent,
        &candidate,
        scope,
        incoming.as_ref(),
    )?;
    reconcile(installation, docker, state, &intent, false)
}

pub(super) fn resume_retired(
    installation: &Path,
    docker: &Path,
    state: &mut LockedMaintenance,
    scope: Attempt,
) -> Result<GenerationBinding> {
    let baseline = load_baseline(state.inspection(), installation, scope)?;
    baseline.require_selected(state.inspection(), installation)?;
    let BaselineRecord::Unused(value) = &baseline.data else {
        return Err(REFUSED.into());
    };
    let parent = generation::load_attempt(installation, scope.sequence - 1, value.parent_attempt)?;
    let previous = candidate_for_plan(
        state.inspection(),
        &saved_plan(installation, value.previous())?,
    )?;
    let candidate = super::super::super::schedule::candidate_for_recovery(
        installation,
        docker,
        state,
        &parent,
        &previous,
        &baseline,
    )?;
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

pub(super) fn stop_preparation(
    installation: &Path,
    docker: &Path,
    state: &mut LockedMaintenance,
    scope: Attempt,
) -> Result<Value> {
    let parent = selected_parent(state.inspection(), installation)?;
    let incoming = if scope.number > 0 {
        Some(load_baseline(state.inspection(), installation, scope)?)
    } else {
        None
    };
    if optional(installation, &scope.record("public-ingress-plan"))?.is_some() {
        require_preparation(state.inspection(), installation, scope, &parent)?;
    } else if optional(installation, &scope.record("managed-renewal-plan"))?.is_some() {
        require_managed_preparation(state.inspection(), installation, scope, &parent)?;
    } else {
        require(incoming.is_some())?;
    }
    let saved = parent_session(state.inspection(), installation)?;
    let source = origin(installation, scope, &parent, &saved, incoming.as_ref())?;
    let session = live_origin(docker, state.journal().runtime().ok_or(REFUSED)?, &source)?;
    let operation = operation(state.inspection(), scope, "unused-pause")?;
    let receipt = session.stop_retained_generation_runtime(state, &operation)?;
    Ok(
        json!({"schema":"elevenid.installer-generation-stop/v1", "installation_id":parent.installation_id,
        "sequence":scope.sequence,"attempt":scope.number,"command_succeeded":receipt.command_succeeded,
        "observation_validated":receipt.observation_validated,"activation_advanced":false,
        "unused_preparation_pending":true,"producer_replayed":false,"producer_start_outcome_unknown":false,
        "producer_failed":false,"producer_completion_admitted":false,"installation_ready":false,"compose_receipt":receipt}),
    )
}

fn selected_parent(view: &LockedInspection, installation: &Path) -> Result<GenerationBinding> {
    view.require_path_binding(installation)?;
    let parent = generation::load_verified(
        installation,
        &view.journal().installation_id().to_string(),
        &view.journal().runtime().ok_or(REFUSED)?.engine_id,
    )?
    .ok_or(REFUSED)?;
    view.require_unchanged()?;
    Ok(parent)
}

#[cfg(test)]
#[path = "installer_generation_unused_tests.rs"]
mod tests;
