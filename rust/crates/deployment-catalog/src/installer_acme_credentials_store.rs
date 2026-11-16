//! Private identity custody and bounded public authentication observations.
//! These purpose-directory locks serialize credential I/O; they are not a second
//! installer scheduler and do not acquire or mutate the installation journal.
use super::*;
use crate::installer_state::{lock, LockedDirectory};
use std::{
    ffi::CString,
    fs::File,
    io::Write,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::PathBuf,
};

const MAX_UNCERTAINTIES: usize = 32;
const IDENTITY_NAME: &str = "identity.json";
const CURRENT_NAME: &str = "refresh-current.json";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SecretIdentity {
    schema: String,
    plan_sha256: String,
    purpose: Purpose,
    role_id: String,
    secret_id: String,
}
impl SecretIdentity {
    pub(super) fn new(
        plan: &CredentialResourcePlan,
        purpose: Purpose,
        role_id: &str,
        secret_id: &str,
    ) -> Result<Self> {
        let identity = Self {
            schema: "elevenid.installer-acme-private-identity/v1".into(),
            plan_sha256: plan.sha256()?,
            purpose,
            role_id: role_id.into(),
            secret_id: secret_id.into(),
        };
        identity.validate(plan, purpose)?;
        Ok(identity)
    }
    pub(super) fn validate(&self, plan: &CredentialResourcePlan, purpose: Purpose) -> Result<()> {
        require(
            self.schema == "elevenid.installer-acme-private-identity/v1"
                && self.plan_sha256 == plan.sha256()?
                && self.purpose == purpose,
        )?;
        uuid_text(&self.role_id)?;
        uuid_text(&self.secret_id)?;
        require(self.role_id != self.secret_id)
    }
    pub(super) fn read(
        directory: &File,
        name: &str,
        plan: &CredentialResourcePlan,
        purpose: Purpose,
    ) -> Result<Self> {
        let bytes = installer_host_fs::read_entry(directory, name, 0o600, false, REFUSED)?;
        let identity: Self =
            serde_json::from_value(crate::installer_json::decode(&bytes).map_err(|_| REFUSED)?)
                .map_err(|_| REFUSED)?;
        identity.validate(plan, purpose)?;
        Ok(identity)
    }
    pub(super) fn role_id(&self) -> &str {
        &self.role_id
    }
    pub(super) fn login_body(&self) -> Value {
        json!({"role_id":self.role_id,"secret_id":self.secret_id})
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObjectIdentity {
    device: u64,
    inode: u64,
    owner: u32,
    group: u32,
    mode: u32,
}
impl ObjectIdentity {
    fn observe(file: &File, directory: bool) -> Result<Self> {
        let meta = file.metadata().map_err(|_| REFUSED)?;
        require(
            meta.uid() == unsafe { libc::geteuid() }
                && meta.mode() & 0o7777 == if directory { 0o700 } else { 0o600 }
                && if directory {
                    meta.is_dir()
                } else {
                    meta.is_file() && meta.nlink() == 1 && (1..=65536).contains(&meta.len())
                },
        )?;
        Ok(Self {
            device: meta.dev(),
            inode: meta.ino(),
            owner: meta.uid(),
            group: meta.gid(),
            mode: meta.mode(),
        })
    }
    fn require_file(&self, file: &File, directory: bool) -> Result<()> {
        require(Self::observe(file, directory)? == *self)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PurposeIdentity {
    directory: ObjectIdentity,
    identity: ObjectIdentity,
}
/// Public filesystem binding only: no token, SecretID, or credential hash is
/// included in installation evidence. Private identity contents are revalidated
/// against their exact plan and actual AppRole at every login.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InstalledIdentity {
    schema: String,
    plan_sha256: String,
    directory: ObjectIdentity,
    account: PurposeIdentity,
    csr: PurposeIdentity,
}

fn child(directory: &File, name: &str, is_directory: bool) -> Result<File> {
    let file = installer_host_fs::open_child(
        directory,
        name,
        libc::O_RDONLY
            | if is_directory {
                libc::O_DIRECTORY
            } else {
                libc::O_NONBLOCK
            },
        REFUSED,
    )?;
    ObjectIdentity::observe(&file, is_directory)?;
    Ok(file)
}
fn mkdir(directory: &File, name: &str) -> Result<File> {
    let name_c = CString::new(name).map_err(|_| REFUSED)?;
    require(unsafe { libc::mkdirat(directory.as_raw_fd(), name_c.as_ptr(), 0o700) } == 0)?;
    directory.sync_all().map_err(|_| REFUSED)?;
    child(directory, name, true)
}
fn temporary_name(name: &str) -> bool {
    name.strip_prefix("acme-write-")
        .and_then(|v| v.strip_suffix(".tmp"))
        .is_some_and(|id| uuid_text(id).is_ok())
}
/// Publish complete bytes with Linux RENAME_NOREPLACE. A crash before publication
/// leaves only a private preparation file; no remote request follows until the
/// final name and parent directory are durable. A crash cannot leave torn JSON
/// at a final state name. Read-only restore retains abandoned preparations;
/// an active refresh removes validated unpublished files under its purpose lock.
pub(super) fn write_exclusive(directory: &File, name: &str, bytes: &[u8]) -> Result<()> {
    publish(directory, name, bytes, None)
}
fn publish(directory: &File, name: &str, bytes: &[u8], previous: Option<&[u8]>) -> Result<()> {
    require(
        !bytes.is_empty()
            && bytes.len() <= 65536
            && !name.contains('/')
            && !name.contains('\\')
            && name != "."
            && name != "..",
    )?;
    if let Some(previous) = previous {
        require(
            installer_host_fs::read_entry(directory, name, 0o600, false, REFUSED)? == previous,
        )?;
    }
    let staging =
        CString::new(format!("acme-write-{}.tmp", uuid::Uuid::new_v4())).map_err(|_| REFUSED)?;
    let target = CString::new(name).map_err(|_| REFUSED)?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            staging.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    require(fd >= 0)?;
    let mut output = unsafe { File::from_raw_fd(fd) };
    output
        .write_all(bytes)
        .and_then(|_| output.sync_all())
        .map_err(|_| REFUSED)?;
    ObjectIdentity::observe(&output, false)?;
    if let Some(previous) = previous {
        require(
            installer_host_fs::read_entry(directory, name, 0o600, false, REFUSED)? == previous,
        )?;
    }
    crate::installer_host_fs::rename_at(
        directory,
        &staging,
        directory,
        &target,
        if previous.is_some() {
            crate::installer_host_fs::RenameMode::Replace
        } else {
            crate::installer_host_fs::RenameMode::NoReplace
        },
    )
    .map_err(|_| REFUSED)?;
    directory.sync_all().map_err(|_| REFUSED)?;
    require(installer_host_fs::read_entry(directory, name, 0o600, false, REFUSED)? == bytes)
}
pub(super) fn install(
    state: &LockedInspection,
    plan: &CredentialResourcePlan,
    account: &SecretIdentity,
    csr: &SecretIdentity,
) -> Result<InstalledIdentity> {
    state.require_unchanged()?;
    account.validate(plan, Purpose::Account)?;
    csr.validate(plan, Purpose::Csr)?;
    require(account.role_id != csr.role_id && account.secret_id != csr.secret_id)?;
    let directory = mkdir(state.installation_directory(), &plan.directory())?;
    let mut saved = Vec::new();
    for (purpose, identity) in [(Purpose::Account, account), (Purpose::Csr, csr)] {
        let folder = mkdir(&directory, purpose.name())?;
        write_exclusive(
            &folder,
            IDENTITY_NAME,
            &serde_json::to_vec(identity).map_err(|_| REFUSED)?,
        )?;
        saved.push(PurposeIdentity {
            directory: ObjectIdentity::observe(&folder, true)?,
            identity: ObjectIdentity::observe(&child(&folder, IDENTITY_NAME, false)?, false)?,
        });
    }
    let csr = saved.pop().ok_or(REFUSED)?;
    let account = saved.pop().ok_or(REFUSED)?;
    let result = InstalledIdentity {
        schema: "elevenid.installer-acme-identity-storage/v1".into(),
        plan_sha256: plan.sha256()?,
        directory: ObjectIdentity::observe(&directory, true)?,
        account,
        csr,
    };
    state.require_unchanged()?;
    Ok(result)
}

pub(super) struct IdentityStorage {
    installation_path: PathBuf,
    installation: File,
    directory: File,
    installed: InstalledIdentity,
}
impl IdentityStorage {
    pub(super) fn require_initialized(
        &self,
        plan: &CredentialResourcePlan,
        purpose: Purpose,
    ) -> Result<()> {
        require(self.lock(plan, purpose)?.history.current.is_some())
    }
    pub(super) fn open(
        state: &LockedInspection,
        installation: &Path,
        plan: &CredentialResourcePlan,
        installed: &InstalledIdentity,
        purpose: Purpose,
    ) -> Result<Self> {
        state.require_path_binding(installation)?;
        require(
            installed.schema == "elevenid.installer-acme-identity-storage/v1"
                && installed.plan_sha256 == plan.sha256()?,
        )?;
        let root = state
            .installation_directory()
            .try_clone()
            .map_err(|_| REFUSED)?;
        let directory = child(&root, &plan.directory(), true)?;
        installed.directory.require_file(&directory, true)?;
        require(
            installer_host_fs::file_names(&directory, REFUSED)?
                == BTreeSet::from(["account".into(), "csr".into()]),
        )?;
        let storage = Self {
            installation_path: installation.into(),
            installation: root,
            directory,
            installed: installed.clone(),
        };
        // Opening or restoring observes existing records, never changes them.
        storage.lock(plan, purpose)?;
        state.require_unchanged()?;
        Ok(storage)
    }
    pub(super) fn lock(&self, plan: &CredentialResourcePlan, purpose: Purpose) -> Result<Attempt> {
        installer_host_fs::require_directory_binding(
            &self.installation_path,
            &self.installation,
            REFUSED,
        )?;
        let directory = child(&self.installation, &plan.directory(), true)?;
        self.installed.directory.require_file(&directory, true)?;
        self.installed
            .directory
            .require_file(&self.directory, true)?;
        let file = child(&directory, purpose.name(), true)?;
        let binding = match purpose {
            Purpose::Account => &self.installed.account,
            Purpose::Csr => &self.installed.csr,
        };
        binding.directory.require_file(&file, true)?;
        // A fresh open file description is essential: dup'd flock handles could
        // otherwise allow two futures in one process to enter concurrently.
        let locked = lock(file).map_err(|_| AUTH_UNAVAILABLE)?;
        binding
            .identity
            .require_file(&child(&locked, IDENTITY_NAME, false)?, false)?;
        let identity = SecretIdentity::read(&locked, IDENTITY_NAME, plan, purpose)?;
        let ledger = History::load(&locked, plan, purpose)?;
        Ok(Attempt {
            directory: locked,
            identity,
            history: ledger,
            started: None,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RefreshIntent {
    schema: String,
    plan_sha256: String,
    purpose: Purpose,
    sequence: u64,
    previous_result_sha256: Option<String>,
    observed_server_time: u64,
    request_budget_seconds: u64,
    owner_explicit_max_ttl: u64,
    operation_explicit_max_ttl: u64,
    operation_token_requested: bool,
    previous_failures: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Outcome {
    Verified,
    UnknownBoundedAuthentication,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RefreshResult {
    schema: String,
    intent_sha256: String,
    outcome: Outcome,
    unknown_short_lived_token: bool,
    next_attempt_server_time: u64,
    consecutive_failures: u32,
}
fn result(intent: &RefreshIntent, success: bool) -> Result<RefreshResult> {
    let failures = if success {
        0
    } else {
        intent.previous_failures.saturating_add(1)
    };
    let backoff = if success {
        0
    } else {
        5u64.saturating_mul(1u64 << failures.saturating_sub(1).min(6))
            .min(300)
    };
    let next = intent
        .observed_server_time
        .checked_add(if success {
            0
        } else {
            REFRESH_BUDGET.as_secs() + backoff
        })
        .ok_or(REFUSED)?;
    Ok(RefreshResult {
        schema: "elevenid.installer-acme-authentication-result/v1".into(),
        intent_sha256: digest(intent)?,
        outcome: if success {
            Outcome::Verified
        } else {
            Outcome::UnknownBoundedAuthentication
        },
        unknown_short_lived_token: !success,
        next_attempt_server_time: next,
        consecutive_failures: failures,
    })
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Current {
    schema: String,
    intent: RefreshIntent,
    result: Option<RefreshResult>,
}
impl Current {
    fn validate(&self, plan: &CredentialResourcePlan, purpose: Purpose) -> Result<()> {
        let intent = &self.intent;
        require(
            self.schema == "elevenid.installer-acme-authentication-current/v1"
                && intent.schema == "elevenid.installer-acme-authentication-intent/v1"
                && intent.plan_sha256 == plan.sha256()?
                && intent.purpose == purpose
                && intent.observed_server_time > 0
                && intent.request_budget_seconds == REFRESH_BUDGET.as_secs()
                && intent.owner_explicit_max_ttl == OWNER_TTL
                && intent.operation_explicit_max_ttl == LEAF_TTL
                && if intent.sequence == 0 {
                    intent.previous_result_sha256.is_none() && intent.previous_failures == 0
                } else {
                    intent
                        .previous_result_sha256
                        .as_deref()
                        .is_some_and(valid_digest)
                },
        )?;
        if let Some(observed) = &self.result {
            require(result(intent, observed.outcome == Outcome::Verified)? == *observed)?;
        }
        Ok(())
    }
}
fn decode_current(
    bytes: &[u8],
    plan: &CredentialResourcePlan,
    purpose: Purpose,
) -> Result<Current> {
    let value: Current =
        serde_json::from_value(crate::installer_json::decode(bytes).map_err(|_| REFUSED)?)
            .map_err(|_| REFUSED)?;
    value.validate(plan, purpose)?;
    Ok(value)
}
fn archive_name(sequence: u64) -> String {
    format!("refresh-unknown-{sequence:020}.json")
}
fn archive_sequence(name: &str) -> Option<u64> {
    let text = name
        .strip_prefix("refresh-unknown-")?
        .strip_suffix(".json")?;
    let sequence: u64 = text.parse().ok()?;
    (archive_name(sequence) == name).then_some(sequence)
}
fn unlink(directory: &File, name: &str) -> Result<()> {
    let name = CString::new(name).map_err(|_| REFUSED)?;
    require(unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } == 0)
}
struct History {
    current: Option<Current>,
    bytes: Option<Vec<u8>>,
    archives: Vec<String>,
    preparations: Vec<String>,
}
impl History {
    fn load(directory: &File, plan: &CredentialResourcePlan, purpose: Purpose) -> Result<Self> {
        let mut names = installer_host_fs::file_names(directory, REFUSED)?;
        require(names.remove(IDENTITY_NAME))?;
        let bytes = if names.remove(CURRENT_NAME) {
            Some(installer_host_fs::read_entry(
                directory,
                CURRENT_NAME,
                0o600,
                false,
                REFUSED,
            )?)
        } else {
            None
        };
        let current = bytes
            .as_deref()
            .map(|bytes| decode_current(bytes, plan, purpose))
            .transpose()?;
        let preparations = names
            .iter()
            .filter(|name| temporary_name(name))
            .cloned()
            .collect::<Vec<_>>();
        require(preparations.len() <= 64)?;
        for name in &preparations {
            let file = installer_host_fs::open_child(
                directory,
                name,
                libc::O_RDONLY | libc::O_NONBLOCK,
                REFUSED,
            )?;
            let meta = file.metadata().map_err(|_| REFUSED)?;
            require(
                meta.is_file()
                    && meta.uid() == unsafe { libc::geteuid() }
                    && meta.mode() & 0o7777 == 0o600
                    && meta.nlink() == 1
                    && meta.len() <= 65536,
            )?;
            names.remove(name);
        }
        // One additional durable uncertainty is allowed when a crash interrupts
        // pruning after publication. The next authentication removes only
        // validated older observations, never identity or current-state data.
        require(names.len() <= MAX_UNCERTAINTIES + 1)?;
        for name in &names {
            let sequence = archive_sequence(name).ok_or(REFUSED)?;
            let retained = current.as_ref().ok_or(REFUSED)?;
            require(sequence <= retained.intent.sequence)?;
            let archived = decode_current(
                &installer_host_fs::read_entry(directory, name, 0o600, false, REFUSED)?,
                plan,
                purpose,
            )?;
            require(
                archived.intent.sequence == sequence
                    && archived.result.as_ref().is_some_and(|value| {
                        value.outcome == Outcome::UnknownBoundedAuthentication
                    })
                    && archived.intent.observed_server_time <= retained.intent.observed_server_time
                    && (sequence != retained.intent.sequence || archived == *retained),
            )?;
        }
        Ok(Self {
            current,
            bytes,
            archives: names.into_iter().collect(),
            preparations,
        })
    }
    fn persist(&mut self, directory: &File, current: Current) -> Result<()> {
        let bytes = serde_json::to_vec(&current).map_err(|_| REFUSED)?;
        // The current state is deliberately replaceable, under the independent
        // purpose lock. Every replacement checks the prior complete bytes and
        // publishes atomically before any next authentication side effect.
        publish(directory, CURRENT_NAME, &bytes, self.bytes.as_deref())?;
        self.current = Some(current);
        self.bytes = Some(bytes);
        Ok(())
    }
    fn maintain(&mut self, directory: &File) -> Result<()> {
        // A surviving preparation was never published, and no other credential
        // writer can be active under this purpose's flock. Cleaning it cannot
        // erase a committed uncertainty observation or a durable identity.
        for name in self.preparations.drain(..) {
            unlink(directory, &name)?;
        }
        if let Some(current) = &self.current {
            if current
                .result
                .as_ref()
                .is_some_and(|value| value.outcome == Outcome::UnknownBoundedAuthentication)
            {
                let name = archive_name(current.intent.sequence);
                if !self.archives.contains(&name) {
                    write_exclusive(
                        directory,
                        &name,
                        &serde_json::to_vec(current).map_err(|_| REFUSED)?,
                    )?;
                    self.archives.push(name);
                    self.archives.sort();
                }
            }
        }
        while self.archives.len() > MAX_UNCERTAINTIES {
            unlink(directory, &self.archives.remove(0))?;
        }
        directory.sync_all().map_err(|_| REFUSED)?;
        Ok(())
    }
}

pub(super) struct Attempt {
    directory: LockedDirectory,
    pub(super) identity: SecretIdentity,
    history: History,
    started: Option<RefreshIntent>,
}
impl Attempt {
    pub(super) fn begin(
        &mut self,
        plan: &CredentialResourcePlan,
        purpose: Purpose,
        server_time: u64,
        mint: bool,
    ) -> Result<()> {
        require(self.started.is_none())?;
        self.history.maintain(&self.directory)?;
        if let Some(current) = &self.history.current {
            require(server_time >= current.intent.observed_server_time)?;
            if current.result.is_none() {
                // Retryable authentication uncertainty is preserved before a
                // fresh attempt. It is not an unknown key/account/order.
                let mut recovered = current.clone();
                recovered.result = Some(result(&recovered.intent, false)?);
                self.history.persist(&self.directory, recovered)?;
            }
        }
        self.history.maintain(&self.directory)?;
        let (sequence, previous_result_sha256, previous_failures) = match &self.history.current {
            Some(current) => {
                let previous = current.result.as_ref().ok_or(REFUSED)?;
                if server_time < previous.next_attempt_server_time {
                    return Err(BACKOFF.into());
                }
                (
                    current.intent.sequence.checked_add(1).ok_or(REFUSED)?,
                    Some(digest(previous)?),
                    previous.consecutive_failures,
                )
            }
            None => (0, None, 0),
        };
        let intent = RefreshIntent {
            schema: "elevenid.installer-acme-authentication-intent/v1".into(),
            plan_sha256: plan.sha256()?,
            purpose,
            sequence,
            previous_result_sha256,
            observed_server_time: server_time,
            request_budget_seconds: REFRESH_BUDGET.as_secs(),
            owner_explicit_max_ttl: OWNER_TTL,
            operation_explicit_max_ttl: LEAF_TTL,
            operation_token_requested: mint,
            previous_failures,
        };
        let current = Current {
            schema: "elevenid.installer-acme-authentication-current/v1".into(),
            intent: intent.clone(),
            result: None,
        };
        current.validate(plan, purpose)?;
        self.history.persist(&self.directory, current)?;
        self.started = Some(intent);
        Ok(())
    }
    pub(super) fn complete(&mut self, success: bool) -> Result<()> {
        let intent = self.started.as_ref().ok_or(REFUSED)?;
        let current = Current {
            schema: "elevenid.installer-acme-authentication-current/v1".into(),
            intent: intent.clone(),
            result: Some(result(intent, success)?),
        };
        self.history.persist(&self.directory, current)?;
        self.history.maintain(&self.directory)?;
        self.started = None;
        Ok(())
    }
}
