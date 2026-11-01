//! Durable generation producer and activation transaction. All paths are
//! derived from the held installation and its next immutable generation.
use super::*;
use crate::{
    installer_acme_host,
    installer_compose::{
        BoundFile, ComposeReceipt, ComposeSession, GenerationOperation, ProjectResources,
        RuntimeOperationOwner,
    },
    installer_generation_host as host, installer_host_fs as fs,
    installer_public_ingress::{
        PublicIngressPlan, PublicRenewalAuthorityPlan, AUTHORITY_PLAN_DIGEST_ENV, PLAN_DIGEST_ENV,
        PUBLIC_RENEWAL_AUTHORITY_PLAN_RECORD,
    },
};
use std::{
    collections::BTreeSet,
    ffi::CString,
    fs::File,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    time::Duration,
};

#[path = "installer_generation_supersession.rs"]
mod supersession;
pub(super) use supersession::require_completed_attempt_link;
pub(crate) use supersession::GenerationRecoveryBaseline;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    schema: String,
    installation_id: String,
    engine_id: String,
    sequence: u64,
    #[serde(default, skip_serializing_if = "attempt::is_zero")]
    attempt: u64,
    #[serde(default, skip_serializing_if = "attempt::is_zero")]
    parent_attempt: u64,
    parent_binding_sha256: String,
    initial_configuration_sha256: String,
    parent_session: SavedSession,
    public_plan_sha256: String,
    source_sha256: BTreeMap<String, String>,
    identity_sha256: BTreeMap<String, String>,
    helper_inputs: ComposeInputs,
    helper_configuration_sha256: String,
    helper_model: Value,
    created_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recovery_baseline_sha256: Option<String>,
}
impl Intent {
    fn scope(&self) -> Attempt {
        Attempt::new(self.sequence, self.attempt)
    }
    fn parent(&self, installation: &Path) -> Result<GenerationBinding> {
        generation::load_attempt(
            installation,
            self.sequence.checked_sub(1).ok_or(REFUSED)?,
            self.parent_attempt,
        )
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivationIntent {
    schema: String,
    installation_id: String,
    sequence: u64,
    #[serde(default, skip_serializing_if = "attempt::is_zero")]
    attempt: u64,
    binding_sha256: String,
    helper_receipt_sha256: String,
    inputs: ComposeInputs,
    model: Value,
    configuration_sha256: String,
    services: Vec<String>,
    created_at: u64,
}
#[derive(Debug, PartialEq, Eq)]
enum CandidateExecution {
    StartOnce,
    Wait,
}
fn candidate_execution(state: &str, start_intent: bool) -> Result<CandidateExecution> {
    match (state, start_intent) {
        ("created", false) => Ok(CandidateExecution::StartOnce),
        ("running" | "exited", true) => Ok(CandidateExecution::Wait),
        _ => Err("Generation producer start outcome is uncertain; retain the same full container ID and never replay its credential minting".into()),
    }
}
fn require_candidate_fresh_at(observed_at: u64, ttl: u64, at: u64) -> Result<()> {
    // Every workload leaf was proven to have at least one hour remaining
    // after this ingress observation. Keep half that floor for activation.
    require(observed_at > 0 && ttl >= 3600 && observed_at <= at.saturating_add(120))?;
    if at >= observed_at.checked_add(1800).ok_or(REFUSED)? {
        return Err("Generation candidate credentials need a new retained producer attempt before activation; preserve the interrupted transaction".into());
    }
    Ok(())
}
pub(super) fn require_candidate_fresh(
    installation: &Path,
    binding: &GenerationBinding,
    at: u64,
) -> Result<()> {
    let metadata = binding
        .public_ingress_metadata(installation)?
        .ok_or(REFUSED)?;
    require_candidate_fresh_at(metadata.token_observed_at, metadata.token_ttl_seconds, at)?;
    // The leaf can expire inside a long activation even while newly minted
    // workload credentials remain fresh. Recheck both clocks at every native
    // create/start and selector boundary, including historical activation.
    metadata.validate_selected_at(
        &binding.read(installation, "installer_ingress_tls_cert")?,
        at,
    )?;
    Ok(())
}
fn store(state: &mut LockedMaintenance, name: &str, bytes: &[u8]) -> Result<()> {
    match state.read_evidence(name)? {
        Some(old) => require(old == bytes),
        None => state.write_evidence_exclusive(name, bytes),
    }
}
fn directory(path: &Path) -> Result<File> {
    fs::directory(path, REFUSED)
}
fn mkdir(parent: &File, name: &str) -> Result<File> {
    require(!name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))?;
    let name = CString::new(name).map_err(|_| REFUSED)?;
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
        require(std::io::Error::last_os_error().raw_os_error() == Some(libc::EEXIST))?;
    }
    parent.sync_all().map_err(|_| REFUSED)?;
    let child = fs::open_child(
        parent,
        name.to_str().map_err(|_| REFUSED)?,
        libc::O_RDONLY | libc::O_DIRECTORY,
        REFUSED,
    )?;
    let metadata = child.metadata().map_err(|_| REFUSED)?;
    require(metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o7777 == 0o700)?;
    Ok(child)
}
fn copy(directory: &File, name: &str, bytes: &[u8], mode: u32) -> Result<()> {
    require(
        [0o444, 0o600].contains(&mode)
            && !name.is_empty()
            && !name.contains('/')
            && !name.contains('\\')
            && bytes.len() <= 65536,
    )?;
    if fs::file_names(directory, REFUSED)?.contains(name) {
        return require(fs::read_entry(directory, name, mode, false, REFUSED)? == bytes);
    }
    let temporary = format!("copy-{name}.tmp");
    if fs::file_names(directory, REFUSED)?.contains(&temporary) {
        let file = fs::open_child(directory, &temporary, libc::O_RDONLY, REFUSED)?;
        let metadata = file.metadata().map_err(|_| REFUSED)?;
        require(
            metadata.is_file()
                && metadata.nlink() == 1
                && metadata.uid() == unsafe { libc::geteuid() }
                && [0o600, mode].contains(&(metadata.mode() & 0o7777))
                && metadata.len() <= bytes.len() as u64,
        )?;
        let mut partial = Vec::new();
        file.take(65537)
            .read_to_end(&mut partial)
            .map_err(|_| REFUSED)?;
        require(
            bytes.starts_with(&partial) && (metadata.mode() & 0o7777 == 0o600 || partial == bytes),
        )?;
        let temporary = CString::new(temporary.as_str()).map_err(|_| REFUSED)?;
        require(unsafe { libc::unlinkat(directory.as_raw_fd(), temporary.as_ptr(), 0) } == 0)?;
    }
    let label = CString::new(temporary).map_err(|_| REFUSED)?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            label.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    require(fd >= 0)?;
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| REFUSED)?;
    require(unsafe { libc::fchmod(file.as_raw_fd(), mode) } == 0)?;
    file.sync_all().map_err(|_| REFUSED)?;
    let target = CString::new(name).map_err(|_| REFUSED)?;
    require(
        unsafe {
            libc::renameat2(
                directory.as_raw_fd(),
                label.as_ptr(),
                directory.as_raw_fd(),
                target.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } == 0,
    )?;
    directory.sync_all().map_err(|_| REFUSED.into())
}
fn work(installation: &Path, scope: Attempt) -> PathBuf {
    scope.work(installation)
}
fn path_text(path: &Path) -> Result<&str> {
    let text = path.to_str().ok_or(REFUSED)?;
    require(
        path.is_absolute()
            && !text
                .chars()
                .any(|c| c.is_control() || c == '\'' || c == '\\'),
    )?;
    Ok(text)
}
fn environment(source: &[u8], values: &BTreeMap<&str, String>) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(source).map_err(|_| REFUSED)?;
    require(text.len() <= 65536 && text.is_ascii())?;
    let mut seen = BTreeSet::new();
    let mut lines = Vec::new();
    for line in text.lines() {
        if line.is_empty() || line.starts_with('#') {
            lines.push(line.to_owned());
            continue;
        }
        let (key, _) = line.split_once('=').ok_or(REFUSED)?;
        require(seen.insert(key.to_owned()))?;
        if !values.contains_key(key) {
            lines.push(line.to_owned());
        }
    }
    for (key, value) in values {
        require(
            !value
                .chars()
                .any(|c| c.is_control() || c == '\'' || c == '\\'),
        )?;
        lines.push(format!("{key}='{value}'"));
    }
    Ok(format!("{}\n", lines.join("\n")).into_bytes())
}
fn receipt_bytes(state: &LockedMaintenance, operation: &str) -> Result<Vec<u8>> {
    state
        .read_evidence(&format!("generation-compose-{operation}-result.json"))?
        .ok_or_else(|| REFUSED.into())
}
fn authorized_creates(
    installation: &Path,
    scope: Attempt,
    phase: &str,
    session: &ComposeSession,
    prior: &ProjectResources,
    allowed: &BTreeSet<String>,
) -> Result<BTreeMap<String, String>> {
    let authority = CreateAuthority {
        project: session.model()["name"].as_str().ok_or(REFUSED)?,
        engine: &session.runtime_binding().engine_id,
        configuration: session.configuration_sha256(),
        input_files: session.input_files(),
        prior,
        allowed,
    };
    recorded_creates(installation, scope, phase, &authority)
}
fn recorded_creates(
    installation: &Path,
    scope: Attempt,
    phase: &str,
    authority: &CreateAuthority<'_>,
) -> Result<BTreeMap<String, String>> {
    let prefix = format!("generation-compose-{}-{phase}-", scope.operation_prefix());
    let mut result = BTreeMap::new();
    for name in fs::file_names(&directory(&installation.join("evidence"))?, REFUSED)? {
        let Some(ordinal) = name
            .strip_prefix(&prefix)
            .and_then(|part| part.strip_suffix("-intent.json"))
        else {
            continue;
        };
        require(ordinal.len() == 6 && ordinal.bytes().all(|byte| byte.is_ascii_digit()))?;
        let bytes = read(installation, &name)?;
        let value: Value = decode(&bytes)?;
        authority.require(&value)?;
        let operation = name
            .strip_prefix("generation-compose-")
            .and_then(|name| name.strip_suffix("-intent.json"))
            .ok_or(REFUSED)?;
        result.insert(operation.into(), hash(&bytes));
    }
    Ok(result)
}
struct CreateAuthority<'a> {
    project: &'a str,
    engine: &'a str,
    configuration: &'a str,
    input_files: &'a BTreeMap<PathBuf, String>,
    prior: &'a ProjectResources,
    allowed: &'a BTreeSet<String>,
}
impl CreateAuthority<'_> {
    fn require(&self, value: &Value) -> Result<()> {
        let roles: Vec<String> =
            serde_json::from_value(value["selected_services"].clone()).map_err(|_| REFUSED)?;
        let selected: BTreeSet<_> = roles.iter().cloned().collect();
        require(
            !selected.is_empty()
                && selected.len() == roles.len()
                && selected.is_subset(self.allowed)
                && value["schema"] == "elevenid.installer-compose-intent/v1"
                && value["project"] == self.project
                && value["engine_id"] == self.engine
                && value["configuration_sha256"] == self.configuration
                && value["input_files"]
                    == serde_json::to_value(self.input_files).map_err(|_| REFUSED)?
                && value["command"]
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
                && value["automatic_retry"] == false
                && value["installation_ready"] == false,
        )?;
        let observed: ProjectResources =
            serde_json::from_value(value["prior_resources"].clone()).map_err(|_| REFUSED)?;
        require(
            observed.networks == self.prior.networks && observed.volumes == self.prior.volumes,
        )?;
        for (role, identity) in &self.prior.containers {
            if !self.allowed.contains(role) {
                require(observed.containers.get(role) == Some(identity))?;
            }
        }
        require(
            observed
                .containers
                .keys()
                .all(|role| self.prior.containers.contains_key(role)),
        )
    }
}
fn input_files(inputs: &ComposeInputs) -> Result<BTreeMap<PathBuf, String>> {
    let mut result = inputs.prior.as_ref().ok_or(REFUSED)?.input_files.clone();
    for file in inputs
        .files
        .iter()
        .chain(std::iter::once(&inputs.environment))
        .chain(&inputs.bound_inputs)
    {
        if let Some(previous) = result.insert(file.path.clone(), file.sha256.clone()) {
            require(previous == file.sha256)?;
        }
    }
    Ok(result)
}
fn operation(state: &LockedInspection, scope: Attempt, phase: &str) -> Result<String> {
    // The ordinal is per phase/transaction, not a lifetime renewal limit.
    let path = installation_path(state)?;
    let directory = directory(&path.join("evidence"))?;
    let prefix = format!("generation-compose-{}-{phase}-", scope.operation_prefix());
    let mut maximum = None;
    for name in fs::file_names(&directory, REFUSED)? {
        if let Some(part) = name
            .strip_prefix(&prefix)
            .and_then(|s| s.strip_suffix("-intent.json"))
        {
            require(part.len() == 6 && part.bytes().all(|b| b.is_ascii_digit()))?;
            let value = part.parse::<u64>().map_err(|_| REFUSED)?;
            maximum = Some(maximum.map_or(value, |old: u64| old.max(value)));
        }
    }
    let next = maximum
        .map_or(Some(0), |value| value.checked_add(1))
        .ok_or(REFUSED)?;
    require(next < 1_000_000)?;
    Ok(scope.operation(phase, next))
}
fn parent_session(view: &LockedInspection, installation: &Path) -> Result<SavedSession> {
    current_session(view, installation)?
        .map(Ok)
        .unwrap_or_else(|| installer_doctor::load_initial_session(view, installation))
}
fn load_intent(view: &LockedInspection, installation: &Path, scope: Attempt) -> Result<Intent> {
    let sequence = scope.sequence;
    let intent: Intent = decode(&view.read_evidence(&scope.record("intent"))?)?;
    require(
        intent.schema == "elevenid.installer-generation-maintenance-intent/v1"
            && intent.sequence == sequence
            && intent.attempt == scope.number
            && sequence > 0
            && intent.installation_id == view.journal().installation_id().to_string()
            && intent.engine_id == view.journal().runtime().ok_or(REFUSED)?.engine_id
            && valid_hash(&intent.parent_binding_sha256)
            && valid_hash(&intent.public_plan_sha256)
            && intent.created_at > 0
            && intent.helper_inputs.installation == installation,
    )?;
    require(
        installer_compose::model_sha256(&intent.helper_model)?
            == intent.helper_configuration_sha256,
    )?;
    let parent = intent.parent(installation)?;
    require(parent.sha256()? == intent.parent_binding_sha256)?;
    let current = parent_session(view, installation)?;
    require(encode(&current)? == encode(&intent.parent_session)?)?;
    let plan = PublicIngressPlan::parse_authenticated(
        &view.read_evidence(&scope.record("public-ingress-plan"))?,
        &intent.public_plan_sha256,
    )?;
    plan.require_saved(view)?;
    let current_dir = directory(&work(installation, scope).join("current"))?;
    let before = host::read_inputs_for_source(&current_dir, true)?;
    require(crate::installer_generation::hashes(&before) == intent.source_sha256)?;
    for (name, value) in &before {
        require(parent.read(installation, name)? == *value)?;
    }
    let identities =
        host::staged_identity(&directory(&work(installation, scope).join("identity"))?)?;
    require(crate::installer_generation::hashes(&identities) == intent.identity_sha256)?;
    let authority = PublicRenewalAuthorityPlan::load(view)?;
    crate::installer_renewal::require_public_enrolment(view, &authority)?;
    let enrolled = host::read_identity(&directory(
        &installation.join("renewal-transfer/delivered"),
    )?)?;
    require(identities == enrolled)?;
    installer_compose::verify_input_files(
        installation,
        &intent
            .helper_inputs
            .prior
            .as_ref()
            .ok_or(REFUSED)?
            .input_files,
    )?;
    supersession::require_intent_baseline(view, installation, &intent)?;
    view.require_unchanged()?;
    Ok(intent)
}

pub(super) fn has_pending_activation(
    view: &LockedInspection,
    installation: &Path,
    current: &GenerationBinding,
) -> Result<bool> {
    supersession::pending_scope(view, installation, current).map(|value| value.is_some())
}
pub(super) fn pending_status(
    view: &LockedInspection,
    installation: &Path,
    current: &GenerationBinding,
) -> Result<Option<Value>> {
    let Some(scope) = supersession::pending_scope(view, installation, current)? else {
        return Ok(None);
    };
    let has = |kind: &str| optional(installation, &scope.record(kind)).map(|value| value.is_some());
    let stage = if !has("intent")? {
        if has("supersession-baseline")? {
            "supersession_baseline_captured"
        } else {
            "supersession_pending"
        }
    } else {
        let _ = load_intent(view, installation, scope)?;
        if has("activation")? {
            "selection_pending"
        } else if has("activation-intent")? {
            "runtime_replacement_pending"
        } else if has("helper")? {
            "producer_completed"
        } else if optional(
            installation,
            &format!(
                "generation-compose-{}-intent.json",
                scope.operation("start", 0)
            ),
        )?
        .is_some()
        {
            "producer_start_outcome_unobserved"
        } else {
            "producer_pending"
        }
    };
    let mut value = json!({"sequence":scope.sequence,"attempt":scope.number,"stage":stage,
        "installation_ready":false,"read_only":true});
    if has("binding")? {
        let binding = generation::load_attempt(installation, scope.sequence, scope.number)?;
        let metadata = binding
            .public_ingress_metadata(installation)?
            .ok_or(REFUSED)?;
        let at = now()?;
        value["credential_fresh_until"] = json!(metadata
            .token_observed_at
            .checked_add(1800)
            .ok_or(REFUSED)?);
        value["certificate_not_after"] = metadata.certificate_admission["not_after"].clone();
        value["completed_attempt_stale"] = json!(supersession::requires_supersession(
            installation,
            &binding,
            at
        )?);
    }
    view.require_unchanged()?;
    Ok(Some(value))
}

fn begin(
    installation: &Path,
    docker: &Path,
    state: &mut LockedMaintenance,
    parent: &GenerationBinding,
    candidate: &AcmeCandidate,
    scope: Attempt,
    baseline: Option<&GenerationRecoveryBaseline>,
) -> Result<Intent> {
    let context = installer_acme_host::maintenance_context(state.inspection())?;
    let saved = parent_session(state.inspection(), installation)?;
    let initial = installer_doctor::load_initial_session(state.inspection(), installation)?;
    let sequence = parent.sequence().checked_add(1).ok_or(REFUSED)?;
    require(scope.sequence == sequence)?;
    require((scope.number > 0) == baseline.is_some())?;
    if let Some(baseline) = baseline {
        require(baseline.scope() == scope)?;
        baseline.require_selected(state.inspection(), installation)?;
        baseline.require_live(docker, state.journal().runtime().ok_or(REFUSED)?)?;
    }
    require(state.read_evidence(&scope.record("intent"))?.is_none())?;
    let plan = PublicIngressPlan::from_successor_attempt(
        state.inspection(),
        installation,
        candidate,
        parent,
        scope.number,
    )?;
    let plan_path = plan.record_for_maintenance(state)?;
    let root = directory(installation)?;
    let work_root = mkdir(&root, "generation-work")?;
    let sequence_root = mkdir(&work_root, &format!("{sequence:020}"))?;
    let held = if scope.number == 0 {
        sequence_root
    } else {
        mkdir(&sequence_root, &format!("attempt-{:020}", scope.number))?
    };
    let current = mkdir(&held, "current")?;
    let identity = mkdir(&held, "identity")?;
    let transfer = mkdir(&held, "transfer")?;
    require(fs::file_names(&transfer, REFUSED)?.is_empty())?;
    let source = crate::installer_renewal_bootstrap::public_inputs()
        .into_iter()
        .map(|name| Ok((name.clone(), parent.read(installation, &name)?)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    let credentials = host::read_identity(&directory(
        &installation.join("renewal-transfer/delivered"),
    )?)?;
    for (name, bytes) in &source {
        copy(&current, name, bytes, 0o444)?;
    }
    for (name, bytes) in &credentials {
        copy(&identity, name, bytes, 0o600)?;
    }
    require(
        fs::file_names(&current, REFUSED)? == source.keys().cloned().collect()
            && fs::file_names(&identity, REFUSED)? == credentials.keys().cloned().collect(),
    )?;
    // Observe/stop the entire retained application census, including its bound
    // listener and port policy. The initial bootstrap model cannot represent
    // those runtime roles after the first application has started.
    let mut inputs = saved.inputs.clone();
    inputs.prior = Some(match baseline {
        Some(value) => value.receipt()?.clone(),
        None => saved.receipt.clone(),
    });
    inputs.profiles = vec!["setup".into()];
    inputs.services = vec!["installer-generation".into()];
    let layer = context.bundle.join(LAYER);
    let expected = include_bytes!(
        "../../../../deploy-config/compose/selfhost-installer/compose.generation.yml"
    );
    require(std::fs::read(&layer).map_err(|_| REFUSED)?.as_slice() == expected)?;
    if let Some(existing) = inputs.files.iter().find(|file| file.path == layer) {
        require(existing.sha256 == hash(expected))?;
    } else {
        inputs.files.push(BoundFile {
            path: layer,
            sha256: hash(expected),
        });
    }
    let values = BTreeMap::from([
        (
            "MARTY_GENERATION_WORK_DIR",
            path_text(&work(installation, scope))?.into(),
        ),
        (
            "MARTY_GENERATION_PUBLIC_INGRESS_PLAN",
            path_text(&plan_path)?.into(),
        ),
        (PLAN_DIGEST_ENV, plan.sha256()?),
        (
            AUTHORITY_PLAN_DIGEST_ENV,
            plan.renewal_authority_plan_sha256().into(),
        ),
    ]);
    let bytes = environment(
        &crate::installer_verify::read_private_bytes(&inputs.environment.path, 65536)?,
        &values,
    )?;
    let name = scope.environment_name("helper");
    store(state, &name, &bytes)?;
    inputs.environment = BoundFile {
        path: installation.join("evidence").join(name),
        sha256: hash(&bytes),
    };
    inputs.bound_inputs.retain(|file| {
        !file
            .path
            .file_name()
            .and_then(|v| v.to_str())
            .is_some_and(|v| {
                v.starts_with("generation-") && v.ends_with("public-ingress-plan.json")
            })
    });
    inputs.bound_inputs.push(BoundFile {
        path: plan_path,
        sha256: plan.sha256()?,
    });
    let authority_path = installation
        .join("evidence")
        .join(PUBLIC_RENEWAL_AUTHORITY_PLAN_RECORD);
    if !inputs
        .bound_inputs
        .iter()
        .any(|file| file.path == authority_path)
    {
        inputs.bound_inputs.push(BoundFile {
            path: authority_path,
            sha256: plan.renewal_authority_plan_sha256().into(),
        });
    }
    // Admission needs the original immutable paths, the genuinely selected
    // generation and at most the one actual stale runtime/helper baseline.
    // Do not accumulate writable roots across every superseded attempt.
    inputs.readonly_bind_roots = initial.inputs.readonly_bind_roots.clone();
    inputs.writable_bind_roots = initial.inputs.writable_bind_roots.clone();
    inputs
        .readonly_bind_roots
        .insert(parent.secret_dir(installation)?);
    if let Some(baseline) = baseline {
        inputs
            .readonly_bind_roots
            .insert(baseline.runtime_root().into());
        let previous = baseline.previous_work(installation)?;
        inputs
            .readonly_bind_roots
            .extend([previous.join("current"), previous.join("identity")]);
        inputs.writable_bind_roots.insert(previous.join("transfer"));
    } else {
        inputs
            .readonly_bind_roots
            .extend(saved.inputs.readonly_bind_roots.iter().cloned());
        inputs
            .writable_bind_roots
            .extend(saved.inputs.writable_bind_roots.iter().cloned());
    }
    inputs
        .writable_bind_roots
        .insert(work(installation, scope).join("transfer"));
    inputs.readonly_bind_roots.extend([
        work(installation, scope).join("current"),
        work(installation, scope).join("identity"),
    ]);
    plan.require_job_inputs(
        docker,
        state.journal().runtime().ok_or(REFUSED)?,
        &inputs,
        "installer-generation",
    )?;
    let session = ComposeSession::new_generation(
        docker,
        state.journal().runtime().ok_or(REFUSED)?,
        inputs.clone(),
    )?;
    session.observe_resources()?;
    let created_at = now()?;
    if let Some(baseline) = baseline {
        require(created_at >= baseline.observed_at())?;
    }
    let intent = Intent {
        schema: "elevenid.installer-generation-maintenance-intent/v1".into(),
        installation_id: parent.installation_id.clone(),
        engine_id: parent.engine_id.clone(),
        sequence,
        attempt: scope.number,
        parent_attempt: parent.attempt(),
        parent_binding_sha256: parent.sha256()?,
        initial_configuration_sha256: initial.configuration_sha256,
        parent_session: saved,
        public_plan_sha256: plan.sha256()?,
        source_sha256: crate::installer_generation::hashes(&source),
        identity_sha256: crate::installer_generation::hashes(&credentials),
        helper_inputs: inputs,
        helper_configuration_sha256: session.configuration_sha256().into(),
        helper_model: session.model().clone(),
        created_at,
        recovery_baseline_sha256: baseline.map(|value| value.sha256().into()),
    };
    store(state, &scope.record("intent"), &encode(&intent)?)?;
    load_intent(state.inspection(), installation, scope)
}

fn producer(
    installation: &Path,
    docker: &Path,
    state: &mut LockedMaintenance,
    intent: &Intent,
) -> Result<ComposeReceipt> {
    let sequence = intent.sequence;
    let scope = intent.scope();
    let session = ComposeSession::new_generation(
        docker,
        state.journal().runtime().ok_or(REFUSED)?,
        intent.helper_inputs.clone(),
    )?;
    require(session.configuration_sha256() == intent.helper_configuration_sha256)?;
    let binding = intent.parent(installation)?;
    let plan = PublicIngressPlan::parse_authenticated(
        &state
            .inspection()
            .read_evidence(&scope.record("public-ingress-plan"))?,
        &intent.public_plan_sha256,
    )?;
    if state.read_evidence(&scope.record("helper"))?.is_none() {
        let producer_name = scope.record("producer");
        let prepared = if let Some(bytes) = state.read_evidence(&producer_name)? {
            decode::<ProducerRecord>(&bytes)?
        } else {
            let observed = admitted_transition(
                installation,
                intent,
                &session,
                GenerationOperation::Candidate,
            )?;
            let previous = intent
                .helper_inputs
                .prior
                .as_ref()
                .ok_or(REFUSED)?
                .resources
                .as_ref()
                .ok_or(REFUSED)?
                .containers
                .get("installer-generation")
                .ok_or(REFUSED)?;
            let replacement = observed
                .containers
                .get("installer-generation")
                .filter(|value| value.id != previous.id);
            let allowed = BTreeSet::from(["installer-generation".into()]);
            let prior = intent
                .helper_inputs
                .prior
                .as_ref()
                .ok_or(REFUSED)?
                .resources
                .as_ref()
                .ok_or(REFUSED)?;
            let previous_creates =
                authorized_creates(installation, scope, "create", &session, prior, &allowed)?;
            if replacement.is_some() {
                require(!previous_creates.is_empty())?;
            }
            let operation = operation(
                state.inspection(),
                scope,
                if replacement.is_some() {
                    "observe-created"
                } else {
                    "create"
                },
            )?;
            let created = if replacement.is_some() {
                session.observe_created_generation(
                    state,
                    &operation,
                    GenerationOperation::Candidate,
                )?
            } else {
                session.create_generation_replacements(
                    state,
                    &operation,
                    GenerationOperation::Candidate,
                )?
            };
            let helper = created
                .resources
                .as_ref()
                .and_then(|v| v.containers.get("installer-generation"))
                .ok_or(REFUSED)?;
            require(created.status.iter().any(|row| {
                row["Service"] == "installer-generation"
                    && row["ID"] == helper.id
                    && row["State"] == "created"
            }))?;
            let creates =
                authorized_creates(installation, scope, "create", &session, prior, &allowed)?;
            let (create_intent_operation, create_intent_sha256) =
                creates.last_key_value().ok_or(REFUSED)?;
            let prepared = ProducerRecord {
                schema: "elevenid.installer-generation-producer/v1".into(),
                installation_id: intent.installation_id.clone(),
                sequence,
                attempt: scope.number,
                parent_binding_sha256: binding.sha256()?,
                container_id: helper.id.clone(),
                create_operation: operation.clone(),
                created_receipt_sha256: hash(&receipt_bytes(state, &operation)?),
                create_intent_operation: create_intent_operation.clone(),
                create_intent_sha256: create_intent_sha256.clone(),
            };
            store(state, &producer_name, &encode(&prepared)?)?;
            prepared
        };
        require(
            prepared.installation_id == intent.installation_id
                && prepared.sequence == sequence
                && prepared.attempt == scope.number
                && prepared.parent_binding_sha256 == binding.sha256()?,
        )?;
        let live = session.observe_generation_transition(GenerationOperation::Candidate)?;
        require(
            live.containers
                .get("installer-generation")
                .is_some_and(|helper| helper.id == prepared.container_id),
        )?;
        let rows = session.status()?;
        let row = rows
            .iter()
            .find(|row| {
                row["Service"] == "installer-generation" && row["ID"] == prepared.container_id
            })
            .ok_or(REFUSED)?;
        let start = scope.operation("start", 0);
        let started = state
            .read_evidence(&format!("generation-compose-{start}-intent.json"))?
            .is_some();
        match candidate_execution(row["State"].as_str().ok_or(REFUSED)?, started)? {
            CandidateExecution::StartOnce => {
                session.start_generation_candidate(state, &start, &prepared.container_id)?;
            }
            CandidateExecution::Wait => (),
        }
        let wait = operation(state.inspection(), scope, "wait")?;
        session.wait_generation_candidate(state, &wait, &prepared.container_id)?;
        require_producer_journal_at(installation, scope, &prepared.container_id, &wait)?;
        store(
            state,
            &scope.record("helper"),
            &receipt_bytes(state, &wait)?,
        )?;
    }
    let native_bytes = state.inspection().read_evidence(&scope.record("helper"))?;
    let native: ComposeReceipt = decode(&native_bytes)?;
    let helper = native
        .resources
        .as_ref()
        .and_then(|v| v.containers.get("installer-generation"))
        .ok_or(REFUSED)?;
    require_producer_journal_at(installation, scope, &helper.id, &native.operation)?;
    let base = work(installation, scope);
    let current = host::read_inputs_for_source(&directory(&base.join("current"))?, true)?;
    let identity = host::staged_identity(&directory(&base.join("identity"))?)?;
    let keycloak = state
        .inspection()
        .read_evidence("keycloak-observation.json")?;
    let proof = crate::installer_generation::GenerationProof {
        owner: &intent.installation_id,
        current: &current,
        identity: &identity,
        keycloak_receipt: &keycloak,
        public_ingress_plan: Some(&plan),
    };
    let output = directory(&base.join("transfer"))?;
    let hashes = host::validate_delivery(
        &base.join("transfer"),
        &output,
        &proof,
        crate::installer_helper_output::expected_host_uid(
            state.journal().runtime().ok_or(REFUSED)?,
        )?,
    )?;
    let delivered = directory(&base.join("transfer/delivered"))?;
    let records = ["pending.json", "validated.json", "completed.json"]
        .into_iter()
        .map(|name| {
            Ok((
                name.into(),
                fs::read_entry(&delivered, name, 0o600, false, REFUSED)?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let public = crate::installer_generation::recorded_public_ingress(&records)?.ok_or(REFUSED)?;
    let candidate = host::GenerationReceipt {
        schema: "elevenid.installer-generation-host/v4",
        installation_id: intent.installation_id.clone(),
        engine_id: intent.engine_id.clone(),
        container_id: helper.id.clone(),
        container_name: format!("{}-installer-generation-1", intent.helper_inputs.project),
        network_id: binding.network_id.clone().ok_or(REFUSED)?,
        image: helper.image.clone(),
        root_retired: false,
        ingress_renewal: true,
        ingress: None,
        public_ingress: Some(public),
        candidate_validated: true,
        activated: false,
        candidate_sha256: hashes.clone(),
        outputs: hashes.keys().cloned().collect(),
        compose_receipt_sha256: hash(&native_bytes),
        job_completed_successfully: true,
        container_removed: false,
        installation_ready: false,
    };
    store(state, &scope.record("candidate"), &encode(&candidate)?)?;
    Ok(native)
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeReference {
    operation: String,
    sha256: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Activation {
    schema: String,
    installation_id: String,
    engine_id: String,
    sequence: u64,
    #[serde(default, skip_serializing_if = "attempt::is_zero")]
    attempt: u64,
    binding_sha256: String,
    parent_binding_sha256: String,
    activation_intent_sha256: String,
    helper_receipt_sha256: String,
    create_intents: BTreeMap<String, String>,
    created: NativeReference,
    started: NativeReference,
    checkpoint: NativeReference,
    observed_at: u64,
    activated: bool,
    installation_ready: bool,
}
fn native_reference(
    state: &LockedMaintenance,
    receipt: &ComposeReceipt,
) -> Result<NativeReference> {
    let bytes = receipt_bytes(state, &receipt.operation)?;
    require(encode(receipt)? == encode(&decode::<ComposeReceipt>(&bytes)?)?)?;
    Ok(NativeReference {
        operation: receipt.operation.clone(),
        sha256: hash(&bytes),
    })
}
fn native(installation: &Path, reference: &NativeReference) -> Result<ComposeReceipt> {
    require(
        valid_hash(&reference.sha256)
            && reference.operation.len() < 96
            && reference
                .operation
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'),
    )?;
    let bytes = read(
        installation,
        &format!("generation-compose-{}-result.json", reference.operation),
    )?;
    require(hash(&bytes) == reference.sha256)?;
    let receipt: ComposeReceipt = decode(&bytes)?;
    require(
        receipt.operation == reference.operation
            && receipt.schema == "elevenid.installer-compose-operation/v1"
            && receipt.command_succeeded
            && receipt.client_exit_code == Some(0)
            && receipt.failure_class.is_none()
            && receipt.observation_validated
            && !receipt.installation_ready
            && receipt.resources.is_some(),
    )?;
    Ok(receipt)
}
fn require_replacements_authorized(
    installation: &Path,
    creates: &BTreeMap<String, String>,
    prior: &ProjectResources,
    observed: &ProjectResources,
    roles: &BTreeSet<String>,
) -> Result<()> {
    for role in roles {
        let changed = observed.containers.get(role).is_none_or(|identity| {
            prior
                .containers
                .get(role)
                .is_none_or(|old| old.id != identity.id)
        });
        if !changed {
            continue;
        }
        let mut authorized = false;
        for (operation, digest) in creates {
            let bytes = read(
                installation,
                &format!("generation-compose-{operation}-intent.json"),
            )?;
            require(hash(&bytes) == *digest)?;
            let intent: Value = decode(&bytes)?;
            if intent["selected_services"]
                .as_array()
                .is_some_and(|selected| selected.iter().any(|value| value == role))
            {
                authorized = true;
            }
        }
        require(authorized)?;
    }
    Ok(())
}
fn admitted_transition(
    installation: &Path,
    intent: &Intent,
    session: &ComposeSession,
    kind: GenerationOperation,
) -> Result<ProjectResources> {
    let (phase, prior, roles) = match kind {
        GenerationOperation::Candidate => (
            "create",
            intent
                .helper_inputs
                .prior
                .as_ref()
                .ok_or(REFUSED)?
                .resources
                .as_ref()
                .ok_or(REFUSED)?
                .clone(),
            BTreeSet::from(["installer-generation".into()]),
        ),
        GenerationOperation::Activate => {
            let activation: ActivationIntent = decode(&read(
                installation,
                &intent.scope().record("activation-intent"),
            )?)?;
            (
                "activate-create",
                activation
                    .inputs
                    .prior
                    .as_ref()
                    .and_then(|prior| prior.resources.clone())
                    .ok_or(REFUSED)?,
                activation.services.into_iter().collect(),
            )
        }
    };
    let observed = session.observe_generation_transition(kind)?;
    let creates = authorized_creates(installation, intent.scope(), phase, session, &prior, &roles)?;
    require_replacements_authorized(installation, &creates, &prior, &observed, &roles)?;
    Ok(observed)
}

fn activation_inputs(
    installation: &Path,
    state: &mut LockedMaintenance,
    intent: &Intent,
    binding: &GenerationBinding,
    helper: &ComposeReceipt,
) -> Result<ComposeInputs> {
    let mut inputs = intent.parent_session.inputs.clone();
    inputs.prior = Some(helper.clone());
    inputs.profiles.clear();
    inputs.services.clear();
    let layer = intent
        .helper_inputs
        .files
        .iter()
        .find(|file| file.path.ends_with(LAYER))
        .ok_or(REFUSED)?
        .clone();
    if let Some(existing) = inputs.files.iter().find(|file| file.path == layer.path) {
        require(existing.path == layer.path && existing.sha256 == layer.sha256)?;
    } else {
        inputs.files.push(layer);
    }
    let plan_path = installation
        .join("evidence")
        .join(intent.scope().record("public-ingress-plan"));
    let plan = PublicIngressPlan::parse_authenticated(
        &state
            .inspection()
            .read_evidence(&intent.scope().record("public-ingress-plan"))?,
        &intent.public_plan_sha256,
    )?;
    let values = BTreeMap::from([
        (
            "SELFHOST_SECRET_DIR",
            path_text(&binding.secret_dir(installation)?)?.into(),
        ),
        (
            "MARTY_GENERATION_WORK_DIR",
            path_text(&work(installation, intent.scope()))?.into(),
        ),
        (
            "MARTY_GENERATION_PUBLIC_INGRESS_PLAN",
            path_text(&plan_path)?.into(),
        ),
        (PLAN_DIGEST_ENV, plan.sha256()?),
        (
            AUTHORITY_PLAN_DIGEST_ENV,
            plan.renewal_authority_plan_sha256().into(),
        ),
    ]);
    let bytes = environment(
        &crate::installer_verify::read_private_bytes(&inputs.environment.path, 65536)?,
        &values,
    )?;
    let name = intent.scope().environment_name("application");
    store(state, &name, &bytes)?;
    inputs.environment = BoundFile {
        path: installation.join("evidence").join(name),
        sha256: hash(&bytes),
    };
    inputs.bound_inputs.retain(|file| {
        !file
            .path
            .file_name()
            .and_then(|v| v.to_str())
            .is_some_and(|v| {
                v.starts_with("generation-") && v.ends_with("public-ingress-plan.json")
            })
    });
    inputs.bound_inputs.push(BoundFile {
        path: plan_path,
        sha256: plan.sha256()?,
    });
    let initial = installer_doctor::load_initial_session(state.inspection(), installation)?;
    inputs.readonly_bind_roots = initial.inputs.readonly_bind_roots;
    inputs.readonly_bind_roots.extend([
        binding.secret_dir(installation)?,
        work(installation, intent.scope()).join("current"),
        work(installation, intent.scope()).join("identity"),
    ]);
    inputs.writable_bind_roots = initial.inputs.writable_bind_roots;
    inputs
        .writable_bind_roots
        .insert(work(installation, intent.scope()).join("transfer"));
    // Creation admission must still inspect the exact old runtime bind roots.
    inputs.readonly_bind_roots.insert(
        generation::read_recorded_attempt(
            installation,
            intent.sequence - 1,
            intent.parent_attempt,
        )?
        .secret_dir(installation)?,
    );
    if let Some(root) = supersession::runtime_root_for_intent(installation, intent)? {
        inputs.readonly_bind_roots.insert(root);
    }
    Ok(inputs)
}
fn load_activation_intent(
    installation: &Path,
    intent: &Intent,
    binding: &GenerationBinding,
) -> Result<ActivationIntent> {
    let value: ActivationIntent = decode(&read(
        installation,
        &intent.scope().record("activation-intent"),
    )?)?;
    require(
        value.schema == "elevenid.installer-generation-activation-intent/v1"
            && value.installation_id == intent.installation_id
            && value.sequence == intent.sequence
            && value.attempt == intent.attempt
            && value.binding_sha256 == binding.sha256()?
            && value.helper_receipt_sha256
                == hash(&read(installation, &intent.scope().record("helper"))?)
            && value.configuration_sha256 == installer_compose::model_sha256(&value.model)?
            && value.inputs.installation == installation
            && value.inputs.profiles.is_empty()
            && value.inputs.services == value.services
            && !value.services.is_empty()
            && value.created_at >= intent.created_at,
    )?;
    let helper: ComposeReceipt = decode(&read(installation, &intent.scope().record("helper"))?)?;
    require(encode(value.inputs.prior.as_ref().ok_or(REFUSED)?)? == encode(&helper)?)?;
    let parent = generation::read_recorded_attempt(
        installation,
        intent.sequence - 1,
        intent.parent_attempt,
    )?;
    model::require_transition_model(
        installation,
        &parent,
        binding,
        &intent.parent_session.model,
        &intent.helper_model,
        &value.model,
        false,
    )?;
    let selected: BTreeSet<_> = value.services.iter().cloned().collect();
    let required =
        ComposeSession::generation_reference_changes(&intent.parent_session.model, &value.model)?;
    require(
        selected.len() == value.services.len()
            && required.is_subset(&selected)
            && selected.iter().all(|role| {
                value.model["services"][role].is_object()
                    && !["openbao", "openbao-unseal", "installer-acme-http01"]
                        .contains(&role.as_str())
            }),
    )?;
    Ok(value)
}
fn prepare_activation(
    installation: &Path,
    docker: &Path,
    state: &mut LockedMaintenance,
    intent: &Intent,
    binding: &GenerationBinding,
    helper: &ComposeReceipt,
) -> Result<ActivationIntent> {
    let name = intent.scope().record("activation-intent");
    if state.read_evidence(&name)?.is_some() {
        return load_activation_intent(installation, intent, binding);
    }
    let mut inputs = activation_inputs(installation, state, intent, binding, helper)?;
    let session = ComposeSession::new_generation(
        docker,
        state.journal().runtime().ok_or(REFUSED)?,
        inputs.clone(),
    )?;
    let parent = generation::read_recorded_attempt(
        installation,
        intent.sequence - 1,
        intent.parent_attempt,
    )?;
    model::require_transition_model(
        installation,
        &parent,
        binding,
        &intent.parent_session.model,
        &intent.helper_model,
        session.model(),
        false,
    )?;
    let services = session.changed_generation_services(&intent.parent_session.model)?;
    require(
        !services.is_empty()
            && !services.iter().any(|role| {
                ["openbao", "openbao-unseal", "installer-acme-http01"].contains(&role.as_str())
            }),
    )?;
    inputs.services = services.clone();
    let value = ActivationIntent {
        schema: "elevenid.installer-generation-activation-intent/v1".into(),
        installation_id: intent.installation_id.clone(),
        sequence: intent.sequence,
        attempt: intent.attempt,
        binding_sha256: binding.sha256()?,
        helper_receipt_sha256: hash(&read(installation, &intent.scope().record("helper"))?),
        inputs,
        model: session.model().clone(),
        configuration_sha256: session.configuration_sha256().into(),
        services,
        created_at: now()?,
    };
    store(state, &name, &encode(&value)?)?;
    load_activation_intent(installation, intent, binding)
}

fn activate(
    installation: &Path,
    docker: &Path,
    state: &mut LockedMaintenance,
    intent: &Intent,
    binding: &GenerationBinding,
    helper: &ComposeReceipt,
) -> Result<()> {
    let sequence = intent.sequence;
    let scope = intent.scope();
    let planned = prepare_activation(installation, docker, state, intent, binding, helper)?;
    require_candidate_fresh(installation, binding, now()?)?;
    let session = ComposeSession::new_generation(
        docker,
        state.journal().runtime().ok_or(REFUSED)?,
        planned.inputs.clone(),
    )?;
    require(
        session.model() == &planned.model
            && session.configuration_sha256() == planned.configuration_sha256,
    )?;
    require(
        planned.services == session.changed_generation_services(&intent.parent_session.model)?,
    )?;
    let roles: BTreeSet<_> = planned.services.iter().cloned().collect();
    let created_name = scope.record("runtime-created");
    let created: ComposeReceipt = if let Some(bytes) = state.read_evidence(&created_name)? {
        decode(&bytes)?
    } else {
        let observed = admitted_transition(
            installation,
            intent,
            &session,
            GenerationOperation::Activate,
        )?;
        let prior = helper.resources.as_ref().ok_or(REFUSED)?;
        let complete = roles.iter().all(|role| {
            observed.containers.get(role).is_some_and(|identity| {
                prior
                    .containers
                    .get(role)
                    .is_some_and(|old| old.id != identity.id)
            })
        });
        let op = operation(
            state.inspection(),
            scope,
            if complete {
                "activate-observe"
            } else {
                "activate-create"
            },
        )?;
        let receipt = if complete {
            session.observe_created_generation(state, &op, GenerationOperation::Activate)?
        } else {
            session.create_generation_replacements(state, &op, GenerationOperation::Activate)?
        };
        store(state, &created_name, &receipt_bytes(state, &op)?)?;
        receipt
    };
    let created_ref = native_reference(state, &created)?;
    let created = native(installation, &created_ref)?;
    require(created.configuration_sha256 == planned.configuration_sha256)?;
    let creates = authorized_creates(
        installation,
        scope,
        "activate-create",
        &session,
        helper.resources.as_ref().ok_or(REFUSED)?,
        &roles,
    )?;
    require_replacements_authorized(
        installation,
        &creates,
        helper.resources.as_ref().ok_or(REFUSED)?,
        created.resources.as_ref().ok_or(REFUSED)?,
        &roles,
    )?;
    let started_name = scope.record("runtime-started");
    require_candidate_fresh(installation, binding, now()?)?;
    let prior_started = state.read_evidence(&started_name)?;
    if let Some(bytes) = &prior_started {
        let previous: ComposeReceipt = decode(bytes)?;
        require(
            previous.resources == created.resources
                && previous.configuration_sha256 == planned.configuration_sha256,
        )?;
        native(installation, &native_reference(state, &previous)?)?;
    }
    // Runtime start is idempotent and cannot select a setup job. Reissue it
    // after an interruption even if the earlier healthy observation survived:
    // a reboot may have stopped these same already-created runtime IDs.
    let started: ComposeReceipt = {
        let mut inputs = planned.inputs.clone();
        inputs.prior = Some(created.clone());
        inputs.services = planned.model["services"]
            .as_object()
            .ok_or(REFUSED)?
            .keys()
            .cloned()
            .collect();
        let session = ComposeSession::new_generation(
            docker,
            state.journal().runtime().ok_or(REFUSED)?,
            inputs,
        )?;
        let op = operation(state.inspection(), scope, "activate-start")?;
        let receipt = session.start_existing_owned(
            state,
            RuntimeOperationOwner::Generation,
            &op,
            Duration::from_secs(720),
        )?;
        if prior_started.is_none() {
            store(state, &started_name, &receipt_bytes(state, &op)?)?;
        }
        receipt
    };
    let started_ref = native_reference(state, &started)?;
    let started = native(installation, &started_ref)?;
    require(
        started.resources == created.resources
            && started.configuration_sha256 == planned.configuration_sha256,
    )?;
    let session_name = scope.record("session");
    let saved: SavedSession = if let Some(bytes) = state.read_evidence(&session_name)? {
        decode(&bytes)?
    } else {
        let mut inputs = planned.inputs.clone();
        inputs.prior = Some(started.clone());
        inputs.services.clear();
        inputs.profiles = intent.parent_session.inputs.profiles.clone();
        let session = ComposeSession::new_generation(
            docker,
            state.journal().runtime().ok_or(REFUSED)?,
            inputs.clone(),
        )?;
        let parent =
            generation::read_recorded_attempt(installation, sequence - 1, intent.parent_attempt)?;
        model::require_transition_model(
            installation,
            &parent,
            binding,
            &intent.parent_session.model,
            &intent.helper_model,
            session.model(),
            true,
        )?;
        let model = session.model().clone();
        let configuration_sha256 = session.configuration_sha256().to_owned();
        let op = operation(state.inspection(), scope, "checkpoint")?;
        let checkpoint = session.checkpoint_generation(state, &op)?;
        inputs.prior = Some(checkpoint.clone());
        let saved = SavedSession {
            schema: "elevenid.installer-compose-session/v1".into(),
            installation_id: intent.installation_id.clone(),
            inputs,
            model,
            configuration_sha256,
            receipt: checkpoint,
        };
        store(state, &session_name, &encode(&saved)?)?;
        saved
    };
    let checkpoint_ref = native_reference(state, &saved.receipt)?;
    require_candidate_fresh(installation, binding, now()?)?;
    let activation_name = scope.record("activation");
    if state.read_evidence(&activation_name)?.is_none() {
        let value = Activation {
            schema: "elevenid.installer-generation-activation/v1".into(),
            installation_id: intent.installation_id.clone(),
            engine_id: intent.engine_id.clone(),
            sequence,
            attempt: scope.number,
            binding_sha256: binding.sha256()?,
            parent_binding_sha256: intent.parent_binding_sha256.clone(),
            activation_intent_sha256: hash(&read(
                installation,
                &scope.record("activation-intent"),
            )?),
            helper_receipt_sha256: hash(&read(installation, &scope.record("helper"))?),
            create_intents: creates,
            created: created_ref,
            started: started_ref,
            checkpoint: checkpoint_ref,
            observed_at: now()?,
            activated: true,
            installation_ready: false,
        };
        store(state, &activation_name, &encode(&value)?)?;
    }
    require_activation(installation, scope, binding, &saved)?;
    let selection_name = scope.record("selection");
    if state.read_evidence(&selection_name)?.is_none() {
        let evidence_sha256 = KINDS
            .into_iter()
            .filter(|kind| *kind != "selection")
            .map(|kind| Ok((kind.into(), hash(&read(installation, &scope.record(kind))?))))
            .collect::<Result<_>>()?;
        let selection = Selection {
            schema: "elevenid.installer-generation-selection/v1".into(),
            installation_id: intent.installation_id.clone(),
            engine_id: intent.engine_id.clone(),
            sequence,
            attempt: scope.number,
            initial_configuration_sha256: intent.initial_configuration_sha256.clone(),
            parent_binding_sha256: intent.parent_binding_sha256.clone(),
            evidence_sha256,
            selected_at: now()?,
            activated: true,
            installation_ready: false,
        };
        store(state, &selection_name, &encode(&selection)?)?;
    }
    let pointer = Selector {
        schema: "elevenid.installer-application-generation-current/v1".into(),
        installation_id: intent.installation_id.clone(),
        engine_id: intent.engine_id.clone(),
        sequence,
        attempt: scope.number,
        selection_sha256: hash(&read(installation, &selection_name)?),
    };
    let next = encode(&pointer)?;
    require_candidate_fresh(installation, binding, now()?)?;
    let before = optional(installation, SELECTOR)?;
    if before.as_deref() != Some(&next) {
        generation::publish_current(installation, state, before.as_deref(), &next)?;
    }
    require(selected(installation)?.is_some_and(|selected| selected.binding == *binding))
}

pub(super) fn require_activation(
    installation: &Path,
    scope: Attempt,
    binding: &GenerationBinding,
    saved: &SavedSession,
) -> Result<()> {
    let sequence = scope.sequence;
    let intent: Intent = decode(&read(installation, &scope.record("intent"))?)?;
    let plan = load_activation_intent(installation, &intent, binding)?;
    let activation: Activation = decode(&read(installation, &scope.record("activation"))?)?;
    require_candidate_fresh(installation, binding, activation.observed_at)?;
    require(
        activation.schema == "elevenid.installer-generation-activation/v1"
            && activation.installation_id == binding.installation_id
            && activation.engine_id == binding.engine_id
            && activation.sequence == sequence
            && activation.attempt == scope.number
            && binding.attempt_id() == scope
            && activation.binding_sha256 == binding.sha256()?
            && activation.parent_binding_sha256 == intent.parent_binding_sha256
            && activation.activation_intent_sha256
                == hash(&read(installation, &scope.record("activation-intent"))?)
            && activation.helper_receipt_sha256
                == hash(&read(installation, &scope.record("helper"))?)
            && activation.observed_at >= plan.created_at
            && activation.activated
            && !activation.installation_ready,
    )?;
    let created = native(installation, &activation.created)?;
    let started = native(installation, &activation.started)?;
    let checkpoint = native(installation, &activation.checkpoint)?;
    for receipt in [&created, &started, &checkpoint] {
        require(
            receipt.project == intent.parent_session.inputs.project
                && receipt.engine_id == intent.engine_id,
        )?;
    }
    require(
        created.configuration_sha256 == plan.configuration_sha256
            && started.configuration_sha256 == plan.configuration_sha256
            && created.resources == started.resources
            && started.resources == checkpoint.resources
            && encode(&checkpoint)? == encode(&saved.receipt)?
            && checkpoint.configuration_sha256 == saved.configuration_sha256
            && saved.schema == "elevenid.installer-compose-session/v1",
    )?;
    let helper: ComposeReceipt = decode(&read(installation, &scope.record("helper"))?)?;
    let before = helper.resources.as_ref().ok_or(REFUSED)?;
    let after = checkpoint.resources.as_ref().ok_or(REFUSED)?;
    let roles: BTreeSet<_> = plan.services.iter().cloned().collect();
    let referenced_changed =
        ComposeSession::generation_reference_changes(&intent.parent_session.model, &plan.model)?;
    let expected_roles: BTreeSet<_> = plan.model["services"]
        .as_object()
        .ok_or(REFUSED)?
        .keys()
        .filter(|role| {
            referenced_changed.contains(*role)
                || before.containers.get(*role).map(|value| &value.config_hash)
                    != after.containers.get(*role).map(|value| &value.config_hash)
        })
        .cloned()
        .collect();
    require(roles == expected_roles)?;
    require(
        before.networks == after.networks
            && before.volumes == after.volumes
            && before.containers.keys().eq(after.containers.keys()),
    )?;
    for (role, old) in &before.containers {
        let current = after.containers.get(role).ok_or(REFUSED)?;
        require(if roles.contains(role) {
            !old.setup && !current.setup && old.image == current.image && old.id != current.id
        } else {
            old == current
        })?;
    }
    require_replacements_authorized(
        installation,
        &activation.create_intents,
        before,
        after,
        &roles,
    )?;
    for (operation, digest) in &activation.create_intents {
        require(
            operation.starts_with(&format!("{}-activate-create-", scope.operation_prefix()))
                && valid_hash(digest),
        )?;
        let bytes = read(
            installation,
            &format!("generation-compose-{operation}-intent.json"),
        )?;
        require(hash(&bytes) == *digest)?;
        let native: Value = decode(&bytes)?;
        require(
            native["configuration_sha256"] == plan.configuration_sha256
                && native["input_files"]
                    == serde_json::to_value(&created.input_files).map_err(|_| REFUSED)?
                && native["command"]
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
                && native["automatic_retry"] == false
                && native["installation_ready"] == false,
        )?;
    }
    let mut expected = plan.inputs.clone();
    expected.services.clear();
    expected.profiles = intent.parent_session.inputs.profiles.clone();
    expected.prior = Some(checkpoint);
    require(encode(&expected)? == encode(&saved.inputs)?)?;
    installer_compose::verify_input_files(installation, &saved.receipt.input_files)?;
    Ok(())
}

fn recover_infrastructure(
    installation: &Path,
    docker: &Path,
    state: &mut LockedMaintenance,
    intent: &Intent,
) -> Result<()> {
    let (inputs, kind) =
        if optional(installation, &intent.scope().record("activation-intent"))?.is_some() {
            let binding = generation::load_attempt(installation, intent.sequence, intent.attempt)?;
            (
                load_activation_intent(installation, intent, &binding)?.inputs,
                GenerationOperation::Activate,
            )
        } else {
            (intent.helper_inputs.clone(), GenerationOperation::Candidate)
        };
    let session =
        ComposeSession::new_generation(docker, state.journal().runtime().ok_or(REFUSED)?, inputs)?;
    admitted_transition(installation, intent, &session, kind)?;
    let op = operation(state.inspection(), intent.scope(), "infrastructure")?;
    session.start_generation_infrastructure(state, &op, kind)?;
    let view = session.into_generation_observation(kind)?;
    crate::installer_openbao_recovery::reconcile_locked(installation, docker, state, &view)?;
    Ok(())
}
fn reconcile(
    installation: &Path,
    docker: &Path,
    state: &mut LockedMaintenance,
    intent: &Intent,
    allow_new_attempt: bool,
) -> Result<GenerationBinding> {
    crate::installer_lifecycle::require_recorded_running_intent(state.inspection(), installation)?;
    crate::installer_root_retirement::require_no_pending_for_generation(state.inspection())?;
    recover_infrastructure(installation, docker, state, intent)?;
    let helper = producer(installation, docker, state, intent)?;
    let parent = intent.parent(installation)?;
    let binding = if state
        .read_evidence(&intent.scope().record("binding"))?
        .is_some()
    {
        generation::load_attempt(installation, intent.sequence, intent.attempt)?
    } else {
        generation::stage_successor(
            installation,
            state,
            &parent,
            intent.attempt,
            &helper.operation,
        )?
    };
    let observed_at = now()?;
    if supersession::requires_supersession(installation, &binding, observed_at)? {
        if allow_new_attempt {
            return supersession::supersede(installation, docker, state, intent, &binding);
        }
        return Err("The new generation attempt completed after its admission deadline; retain its evidence for the next bounded recovery invocation".into());
    }
    require_candidate_fresh(installation, &binding, observed_at)?;
    activate(installation, docker, state, intent, &binding, &helper)?;
    Ok(binding)
}
pub(super) fn begin_and_reconcile(
    installation: &Path,
    docker: &Path,
    state: &mut LockedMaintenance,
    parent: &GenerationBinding,
    candidate: &AcmeCandidate,
) -> Result<GenerationBinding> {
    state.inspection().require_path_binding(installation)?;
    crate::installer_lifecycle::require_recorded_running_intent(state.inspection(), installation)?;
    crate::installer_root_retirement::require_no_pending_for_generation(state.inspection())?;
    require(
        generation::load_verified(installation, &parent.installation_id, &parent.engine_id)?
            .as_ref()
            == Some(parent),
    )?;
    let intent = begin(
        installation,
        docker,
        state,
        parent,
        candidate,
        Attempt::new(parent.sequence().checked_add(1).ok_or(REFUSED)?, 0),
        None,
    )?;
    reconcile(installation, docker, state, &intent, false)
}
pub(super) fn reconcile_pending(
    installation: &Path,
    docker: &Path,
    state: &mut LockedMaintenance,
) -> Result<Option<GenerationBinding>> {
    state.inspection().require_path_binding(installation)?;
    let Some(parent) = generation::load_verified(
        installation,
        &state.journal().installation_id().to_string(),
        &state.journal().runtime().ok_or(REFUSED)?.engine_id,
    )?
    else {
        return Ok(None);
    };
    let Some(scope) = supersession::pending_scope(state.inspection(), installation, &parent)?
    else {
        return Ok(None);
    };
    // No pending transaction returns above before the retirement mutation gate.
    if state.read_evidence(&scope.record("intent"))?.is_none() {
        return supersession::resume(installation, docker, state, scope).map(Some);
    }
    let intent = load_intent(state.inspection(), installation, scope)?;
    reconcile(installation, docker, state, &intent, true).map(Some)
}
pub(super) fn stop_pending(
    installation: &Path,
    docker: &Path,
    state: &mut LockedMaintenance,
) -> Result<Option<Value>> {
    state.inspection().require_path_binding(installation)?;
    let Some(parent) = generation::load_verified(
        installation,
        &state.journal().installation_id().to_string(),
        &state.journal().runtime().ok_or(REFUSED)?.engine_id,
    )?
    else {
        return Ok(None);
    };
    let Some(scope) = supersession::pending_scope(state.inspection(), installation, &parent)?
    else {
        return Ok(None);
    };
    let sequence = scope.sequence;
    if state.read_evidence(&scope.record("intent"))?.is_none() {
        return supersession::stop_before_attempt(installation, docker, state, scope).map(Some);
    }
    let intent = load_intent(state.inspection(), installation, scope)?;
    let (inputs, kind) = if state
        .read_evidence(&scope.record("activation-intent"))?
        .is_some()
    {
        let binding = generation::load_attempt(installation, sequence, scope.number)?;
        (
            load_activation_intent(installation, &intent, &binding)?.inputs,
            GenerationOperation::Activate,
        )
    } else {
        (intent.helper_inputs.clone(), GenerationOperation::Candidate)
    };
    let session =
        ComposeSession::new_generation(docker, state.journal().runtime().ok_or(REFUSED)?, inputs)?;
    let resources = admitted_transition(installation, &intent, &session, kind)?;
    let mut producer_start_outcome_unknown = false;
    let mut producer_failed = false;
    if matches!(kind, GenerationOperation::Candidate) {
        if let Some(helper) = resources
            .containers
            .get("installer-generation")
            .filter(|helper| {
                intent
                    .helper_inputs
                    .prior
                    .as_ref()
                    .and_then(|saved| saved.resources.as_ref())
                    .and_then(|resources| resources.containers.get("installer-generation"))
                    .is_some_and(|old| old.id != helper.id)
            })
        {
            let row = session
                .status()?
                .into_iter()
                .find(|row| row["Service"] == "installer-generation" && row["ID"] == helper.id)
                .ok_or(REFUSED)?;
            let started = state
                .read_evidence(&format!(
                    "generation-compose-{}-intent.json",
                    scope.operation("start", 0)
                ))?
                .is_some();
            if row["State"] == "created" {
                producer_start_outcome_unknown = started;
            } else if row["State"] == "running" {
                require(started)?;
                let op = operation(state.inspection(), scope, "pause-wait")?;
                // Waiting issues no mint/restart. A nonzero producer exit is
                // retained as failure, but does not prevent runtime shutdown.
                let _wait_result = session.wait_generation_candidate(state, &op, &helper.id);
                state.require_unchanged()?;
                let observed = admitted_transition(installation, &intent, &session, kind)?;
                require(
                    observed
                        .containers
                        .get("installer-generation")
                        .is_some_and(|value| value.id == helper.id),
                )?;
                let terminal = session
                    .status()?
                    .into_iter()
                    .find(|row| row["Service"] == "installer-generation" && row["ID"] == helper.id)
                    .ok_or(REFUSED)?;
                require(terminal["State"] == "exited")?;
                producer_failed = terminal["ExitCode"] != 0;
            } else {
                require(row["State"] == "exited")?;
                producer_failed = row["ExitCode"] != 0;
            }
        }
    }
    let op = operation(state.inspection(), scope, "stop")?;
    let receipt = session.stop_generation_runtime(state, &op, kind)?;
    Ok(Some(
        json!({"schema":"elevenid.installer-generation-stop/v1","installation_id":intent.installation_id,"sequence":sequence,
        "command_succeeded":receipt.command_succeeded,"observation_validated":receipt.observation_validated,
        "activation_advanced":false,"producer_replayed":false,"producer_start_outcome_unknown":producer_start_outcome_unknown,
        "producer_failed":producer_failed,"producer_completion_admitted":false,"installation_ready":false,"compose_receipt":receipt}),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn readonly_temporary_copy_is_resumed_after_fchmod_before_publish() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let held = directory(root.path()).unwrap();
        let bytes = b"exact retained input";
        std::fs::write(root.path().join("copy-value.tmp"), bytes).unwrap();
        std::fs::set_permissions(
            root.path().join("copy-value.tmp"),
            std::fs::Permissions::from_mode(0o444),
        )
        .unwrap();
        copy(&held, "value", bytes, 0o444).unwrap();
        assert_eq!(std::fs::read(root.path().join("value")).unwrap(), bytes);
        assert!(copy(&held, "value", b"foreign", 0o444).is_err());
    }
    #[test]
    fn readonly_partial_copy_is_not_adopted_as_a_completed_write() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let held = directory(root.path()).unwrap();
        std::fs::write(root.path().join("copy-value.tmp"), b"part").unwrap();
        std::fs::set_permissions(
            root.path().join("copy-value.tmp"),
            std::fs::Permissions::from_mode(0o444),
        )
        .unwrap();
        assert!(copy(&held, "value", b"partial expected bytes", 0o444).is_err());
    }
    #[test]
    fn activation_uses_the_minted_credential_floor_and_historical_validation_keeps_diagnosis() {
        assert!(require_candidate_fresh_at(10_000, 28_800, 10_000).is_ok());
        assert!(require_candidate_fresh_at(10_000, 28_800, 11_799).is_ok());
        assert!(require_candidate_fresh_at(10_000, 28_800, 11_800).is_err());
        assert!(require_candidate_fresh_at(10_000, 28_800, 40_000).is_err());
        assert!(require_candidate_fresh_at(10_000, 28_800, 10_100).is_ok());
        assert!(require_candidate_fresh_at(10_000, 3599, 10_100).is_err());
        assert!(require_candidate_fresh_at(10_000, 3600, 9_879).is_err());
        assert!(require_candidate_fresh_at(u64::MAX - 1, 3600, u64::MAX).is_err());
    }
}
#[cfg(test)]
#[path = "installer_generation_transaction_tests.rs"]
mod transaction_tests;
