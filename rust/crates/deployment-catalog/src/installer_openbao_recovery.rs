//! Installer-owned renewal of the private OpenBao TCP listener certificate.
//! The caller retains the installation lock and permits mutation only for a
//! durable running intent. Local infrastructure is started before this module;
//! application readiness, public ACME orders, init and unseal are outside it.
#![cfg(target_os = "linux")]

use crate::{
    installer_compose::{ComposeSession, ProjectResources},
    installer_host_fs as fs, installer_json,
    installer_openbao_control::{EnrollmentReceipt, OBSERVATION},
    installer_release::sha256,
    installer_runtime::DockerRunner,
    installer_state::{LockedInspection, LockedMaintenance},
};
use chrono::{DateTime, SecondsFormat, Utc};
use marty_selfhost_identity::origin::PublicOrigin;
use rustls::pki_types::{CertificateDer, UnixTime};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use spki::der::{Decode, Encode};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    os::unix::fs::MetadataExt,
    path::Path,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

type Result<T> = std::result::Result<T, String>;
const REFUSED: &str = "OpenBao local TLS recovery evidence or authority differs; preserve the installation and retry only after restoring its retained binding";
const RETRY: &str = "OpenBao local TLS recovery has not completed; its durable attempt remains resumable on the next running check";
const PREFIX: &str = "openbao-tls-recovery-";
const HORIZON: u64 = 7 * 24 * 60 * 60;

fn require(value: bool) -> Result<()> {
    if value {
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
    uuid::Uuid::parse_str(value).is_ok_and(|v| v.to_string() == value)
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
fn timestamp(value: &str) -> Result<u64> {
    let parsed = DateTime::parse_from_rfc3339(value).map_err(|_| REFUSED)?;
    require(parsed.to_rfc3339_opts(SecondsFormat::Secs, true) == value && parsed.timestamp() >= 0)?;
    Ok(parsed.timestamp() as u64)
}
fn clock(value: u64) -> Result<String> {
    DateTime::<Utc>::from_timestamp(value.try_into().map_err(|_| REFUSED)?, 0)
        .map(|v| v.to_rfc3339_opts(SecondsFormat::Secs, true))
        .ok_or_else(|| REFUSED.into())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectoryBinding {
    device: u64,
    inode: u64,
    owner_uid: u32,
    owner_gid: u32,
    mode: u32,
}
impl DirectoryBinding {
    fn observe(file: &File) -> Result<Self> {
        let m = file.metadata().map_err(|_| REFUSED)?;
        require(m.is_dir() && m.mode() & 0o7777 == 0o700)?;
        Ok(Self {
            device: m.dev(),
            inode: m.ino(),
            owner_uid: m.uid(),
            owner_gid: m.gid(),
            mode: m.mode() & 0o7777,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlObservation {
    schema: String,
    installation_id: String,
    engine_id: String,
    container_id: String,
    enrollment_container_id: String,
    image: String,
    configuration_sha256: String,
    compose_receipt_sha256: String,
    socket_directory: DirectoryBinding,
    openbao_state_directory: DirectoryBinding,
    enrollment_pending_sha256: String,
    enrollment_result_sha256: String,
    enrollment: EnrollmentReceipt,
    root_retired: bool,
    automatic_recovery_qualified: bool,
    installation_ready: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollmentIntent {
    schema: String,
    installation_id: String,
    attempt_id: String,
    cluster_id: String,
    ca_sha256: String,
    spki_sha256: String,
    root_retired: bool,
    existing_ca_key_retained: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Authority {
    observation: ControlObservation,
    observation_sha256: String,
    ca: Vec<u8>,
}

fn authority(view: &LockedInspection, installation: &Path) -> Result<Authority> {
    view.require_path_binding(installation)?;
    let bytes = view.read_evidence(OBSERVATION)?;
    let observation: ControlObservation = decode(&bytes)?;
    let installation_id = view.journal().installation_id().to_string();
    let runtime = view.journal().runtime().ok_or(REFUSED)?;
    let result = &observation.enrollment;
    require(
        observation.schema == "elevenid.installer-openbao-control-observation/v1"
            && observation.installation_id == installation_id
            && observation.engine_id == runtime.engine_id
            && hash(&observation.container_id)
            && hash(&observation.enrollment_container_id)
            && [
                &observation.configuration_sha256,
                &observation.compose_receipt_sha256,
                &observation.enrollment_pending_sha256,
                &observation.enrollment_result_sha256,
                &result.ca_sha256,
                &result.spki_sha256,
                &result.policy_sha256,
            ]
            .into_iter()
            .all(|v| hash(v))
            && !observation.root_retired
            && !observation.automatic_recovery_qualified
            && !observation.installation_ready
            && result.schema == "elevenid.openbao-control-enrollment-result/v1"
            && result.installation_id == installation_id
            && [&result.attempt_id, &result.cluster_id, &result.issuer_id]
                .into_iter()
                .all(|v| uuid(v))
            && result.scoped_login_verified
            && result.scoped_signing_verified
            && result.forbidden_operations_denied
            && result.verification_token_revoked
            && result.existing_ca_key_retained
            && result.node_key_preserved
            && !result.root_retired,
    )?;
    crate::installer_openbao_seal::require_initialized_cluster(
        view,
        installation,
        &result.cluster_id,
    )?;
    let control_path = installation.join("openbao-control");
    let identity_path = control_path.join("identity");
    let control = fs::directory(&control_path, REFUSED)?;
    let identity = fs::directory(&identity_path, REFUSED)?;
    let created = installer_json::decode(&view.read_evidence("openbao-control-created.json")?)
        .map_err(|_| REFUSED)?;
    let outer = DirectoryBinding::observe(&control)?;
    let identity_binding = DirectoryBinding::observe(&identity)?;
    let bound = |value: &Value, m: &DirectoryBinding| {
        value["device"] == m.device
            && value["inode"] == m.inode
            && value["owner_uid"] == m.owner_uid
            && value["owner_gid"] == m.owner_gid
            && value["mode"] == m.mode
    };
    require(
        created["schema"] == "elevenid.installer-openbao-control-created/v1"
            && created["installation_id"] == installation_id
            && created["enrolled"] == false
            && bound(&created, &outer)
            && bound(&created["children"]["identity"], &identity_binding),
    )?;
    let socket = fs::open_child(
        &control,
        "socket",
        libc::O_PATH | libc::O_DIRECTORY,
        REFUSED,
    )?;
    let mapped = fs::open_child(
        view.installation_directory(),
        "openbao-state",
        libc::O_PATH | libc::O_DIRECTORY,
        REFUSED,
    )?;
    require(
        DirectoryBinding::observe(&socket)? == observation.socket_directory
            && DirectoryBinding::observe(&mapped)? == observation.openbao_state_directory
            && observation.socket_directory.owner_uid
                == observation.openbao_state_directory.owner_uid
            && observation.socket_directory.owner_gid
                == observation.openbao_state_directory.owner_gid
            && created["children"]["socket"]["device"] == observation.socket_directory.device
            && created["children"]["socket"]["inode"] == observation.socket_directory.inode
            && created["children"]["socket"]["mode"] == 0o700
            && created["children"]["socket"]["owner_uid"] == outer.owner_uid
            && created["children"]["socket"]["owner_gid"] == outer.owner_gid,
    )?;
    require(
        fs::file_names(&identity, REFUSED)?
            == BTreeSet::from([
                "recovery.json".into(),
                "enrollment-pending.json".into(),
                "enrollment-result.json".into(),
            ]),
    )?;
    // The host only observes private identity metadata; it never reads the
    // AppRole SecretID or node key into installer state, argv, or diagnostics.
    let private = fs::open_child(&identity, "recovery.json", libc::O_PATH, REFUSED)?;
    let private_meta = private.metadata().map_err(|_| REFUSED)?;
    require(
        private_meta.is_file()
            && private_meta.nlink() == 1
            && private_meta.mode() & 0o7777 == 0o400
            && private_meta.uid() == identity_binding.owner_uid
            && private_meta.gid() == identity_binding.owner_gid
            && (1..=8192).contains(&private_meta.len()),
    )?;
    let result_bytes = fs::read_entry(&identity, "enrollment-result.json", 0o600, false, REFUSED)?;
    let pending_bytes =
        fs::read_entry(&identity, "enrollment-pending.json", 0o600, false, REFUSED)?;
    require(
        sha256(&result_bytes) == observation.enrollment_result_sha256
            && sha256(&pending_bytes) == observation.enrollment_pending_sha256
            && decode::<EnrollmentReceipt>(&result_bytes)? == *result,
    )?;
    let pending: EnrollmentIntent = decode(&pending_bytes)?;
    require(
        pending.schema == "elevenid.openbao-control-enrollment-intent/v1"
            && pending.installation_id == installation_id
            && pending.attempt_id == result.attempt_id
            && pending.cluster_id == result.cluster_id
            && pending.ca_sha256 == result.ca_sha256
            && pending.spki_sha256 == result.spki_sha256
            && !pending.root_retired
            && pending.existing_ca_key_retained,
    )?;
    let secrets = fs::directory(&installation.join("secrets"), REFUSED)?;
    let ca = fs::read_entry(&secrets, "openbao_tls_ca_cert", 0o644, false, REFUSED)?;
    let cert = crate::installer_ingress_provision::certificate(
        std::str::from_utf8(&ca).map_err(|_| REFUSED)?,
    )?;
    require(sha256(&cert.to_der().map_err(|_| REFUSED)?) == result.ca_sha256)?;
    fs::require_directory_binding(&control_path, &control, REFUSED)?;
    fs::require_directory_binding(&identity_path, &identity, REFUSED)?;
    require(
        DirectoryBinding::observe(&fs::open_child(
            &control,
            "socket",
            libc::O_PATH | libc::O_DIRECTORY,
            REFUSED,
        )?)? == observation.socket_directory
            && DirectoryBinding::observe(&fs::open_child(
                view.installation_directory(),
                "openbao-state",
                libc::O_PATH | libc::O_DIRECTORY,
                REFUSED,
            )?)? == observation.openbao_state_directory
            && fs::read_entry(&identity, "enrollment-result.json", 0o600, false, REFUSED)?
                == result_bytes
            && fs::read_entry(&identity, "enrollment-pending.json", 0o600, false, REFUSED)?
                == pending_bytes,
    )?;
    view.require_path_binding(installation)?;
    Ok(Authority {
        observation,
        observation_sha256: sha256(&bytes),
        ca,
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalReceipt {
    schema: String,
    installation_id: String,
    attempt_id: String,
    cluster_id: String,
    issuer_id: String,
    previous_certificate_sha256: String,
    certificate_sha256: String,
    ca_sha256: String,
    spki_sha256: String,
    not_after: String,
    node_key_preserved: bool,
    certificate_published: bool,
    reload_performed: bool,
    network_tls_verified: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalTransaction {
    schema: String,
    installation_id: String,
    attempt_id: String,
    cluster_id: String,
    issuer_id: String,
    previous_certificate_sha256: String,
    ca_sha256: String,
    spki_sha256: String,
    phase: String,
    certificate_pem: String,
    certificate_sha256: String,
    not_after: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    supersedes_attempt_id: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Supersession {
    schema: String,
    previous_transaction: LocalTransaction,
    previous_journal_sha256: String,
    replacement_attempt_id: String,
    observed_active_certificate_sha256: String,
    recorded_at: String,
    reason: String,
    previous_certificate_published: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Inspection {
    schema: String,
    installation_id: String,
    cluster_id: String,
    issuer_id: String,
    ca_sha256: String,
    spki_sha256: String,
    certificate_pem: String,
    certificate_sha256: String,
    not_before: String,
    not_after: String,
    ca_not_after: String,
    node_key_matches: bool,
    renewal_issuer_usable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    transaction: Option<LocalTransaction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    transaction_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    completed_receipt: Option<LocalReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    completed_receipt_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    supersession: Option<Supersession>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    supersession_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending_supersession: Option<Supersession>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending_supersession_sha256: Option<String>,
}

fn bound_leaf(
    pem: &str,
    expected: &str,
    authority: &Authority,
    now: u64,
) -> Result<(Vec<u8>, u64, u64)> {
    let cert = crate::installer_ingress_provision::certificate(pem)?;
    let der = cert.to_der().map_err(|_| REFUSED)?;
    let spki = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| REFUSED)?;
    let before = cert
        .tbs_certificate
        .validity
        .not_before
        .to_unix_duration()
        .as_secs();
    let after = cert
        .tbs_certificate
        .validity
        .not_after
        .to_unix_duration()
        .as_secs();
    require(
        hash(expected)
            && sha256(&der) == expected
            && sha256(&spki) == authority.observation.enrollment.spki_sha256
            && before <= now
            && after > before,
    )?;
    // History remains verifiable after natural expiry. This historical time is
    // used only for local public evidence, never for the live TLS connection.
    crate::installer_transport::validate_server_chain_for_origin(
        &authority.ca,
        &[CertificateDer::from(der.clone())],
        UnixTime::since_unix_epoch(Duration::from_secs(now.min(after - 1))),
        &PublicOrigin::parse("https://127.0.0.1")?,
    )?;
    Ok((der, before, after))
}
impl LocalTransaction {
    fn validate(&self, authority: &Authority, now: u64) -> Result<()> {
        let enrolled = &authority.observation.enrollment;
        require(
            self.schema == "elevenid.openbao-tcp-recovery-transaction/v1"
                && self.installation_id == enrolled.installation_id
                && uuid(&self.attempt_id)
                && self.cluster_id == enrolled.cluster_id
                && self.issuer_id == enrolled.issuer_id
                && self.ca_sha256 == enrolled.ca_sha256
                && self.spki_sha256 == enrolled.spki_sha256
                && hash(&self.previous_certificate_sha256)
                && self
                    .supersedes_attempt_id
                    .as_ref()
                    .is_none_or(|v| uuid(v) && *v != self.attempt_id),
        )?;
        if self.phase == "issuing" {
            return require(
                self.certificate_pem.is_empty()
                    && self.certificate_sha256.is_empty()
                    && self.not_after.is_empty(),
            );
        }
        require(
            matches!(self.phase.as_str(), "candidate" | "published")
                && self.previous_certificate_sha256 != self.certificate_sha256,
        )?;
        let (_, before, after) = bound_leaf(
            &self.certificate_pem,
            &self.certificate_sha256,
            authority,
            now,
        )?;
        require(after == timestamp(&self.not_after)? && after - before <= 31 * 86400)
    }
    fn receipt(&self) -> LocalReceipt {
        LocalReceipt {
            schema: "elevenid.openbao-tcp-recovery-result/v1".into(),
            installation_id: self.installation_id.clone(),
            attempt_id: self.attempt_id.clone(),
            cluster_id: self.cluster_id.clone(),
            issuer_id: self.issuer_id.clone(),
            previous_certificate_sha256: self.previous_certificate_sha256.clone(),
            certificate_sha256: self.certificate_sha256.clone(),
            ca_sha256: self.ca_sha256.clone(),
            spki_sha256: self.spki_sha256.clone(),
            not_after: self.not_after.clone(),
            node_key_preserved: true,
            certificate_published: true,
            reload_performed: false,
            network_tls_verified: false,
        }
    }
}
impl Supersession {
    fn validate(&self, authority: &Authority, now: u64) -> Result<()> {
        self.previous_transaction.validate(authority, now)?;
        let previous = &self.previous_transaction;
        require(
            self.schema == "elevenid.openbao-tcp-recovery-supersession/v1"
                && self.reason == "candidate_expired"
                && previous.phase == "candidate"
                && uuid(&self.replacement_attempt_id)
                && self.replacement_attempt_id != previous.attempt_id
                && hash(&self.previous_journal_sha256)
                && timestamp(&self.recorded_at)? <= now
                && timestamp(&self.recorded_at)? >= timestamp(&previous.not_after)?
                && (self.observed_active_certificate_sha256
                    == previous.previous_certificate_sha256
                    || self.observed_active_certificate_sha256 == previous.certificate_sha256)
                && self.previous_certificate_published
                    == (self.observed_active_certificate_sha256 == previous.certificate_sha256),
        )
    }
}
impl Inspection {
    fn validate(&self, authority: &Authority, now: u64) -> Result<()> {
        let enrolled = &authority.observation.enrollment;
        require(
            self.schema == "elevenid.openbao-tcp-inspection/v1"
                && self.installation_id == enrolled.installation_id
                && self.cluster_id == enrolled.cluster_id
                && self.issuer_id == enrolled.issuer_id
                && self.ca_sha256 == enrolled.ca_sha256
                && self.spki_sha256 == enrolled.spki_sha256
                && self.node_key_matches,
        )?;
        let (_, before, after) = bound_leaf(
            &self.certificate_pem,
            &self.certificate_sha256,
            authority,
            now,
        )?;
        let ca = crate::installer_ingress_provision::certificate(
            std::str::from_utf8(&authority.ca).map_err(|_| REFUSED)?,
        )?;
        let ca_after = ca
            .tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_secs();
        require(
            before == timestamp(&self.not_before)?
                && after == timestamp(&self.not_after)?
                && ca_after == timestamp(&self.ca_not_after)?
                && self.renewal_issuer_usable == (ca_after > now.saturating_add(31 * 86400)),
        )?;
        for (present, digest) in [
            (self.transaction.is_some(), &self.transaction_sha256),
            (
                self.completed_receipt.is_some(),
                &self.completed_receipt_sha256,
            ),
            (self.supersession.is_some(), &self.supersession_sha256),
            (
                self.pending_supersession.is_some(),
                &self.pending_supersession_sha256,
            ),
        ] {
            require(present == digest.is_some() && digest.as_ref().is_none_or(|v| hash(v)))?;
        }
        if let Some(transaction) = &self.transaction {
            transaction.validate(authority, now)?;
            require(match transaction.phase.as_str() {
                "issuing" => self.certificate_sha256 == transaction.previous_certificate_sha256,
                "candidate" => {
                    self.certificate_sha256 == transaction.previous_certificate_sha256
                        || self.certificate_sha256 == transaction.certificate_sha256
                }
                "published" => self.certificate_sha256 == transaction.certificate_sha256,
                _ => false,
            })?;
            if let Some(receipt) = &self.completed_receipt {
                require(
                    *receipt == transaction.receipt()
                        && transaction.phase != "issuing"
                        && self.certificate_sha256 == transaction.certificate_sha256,
                )?;
            }
            require(transaction.supersedes_attempt_id.is_some() == self.supersession.is_some())?;
            if let Some(link) = &self.supersession {
                link.validate(authority, now)?;
                require(
                    Some(&link.previous_transaction.attempt_id)
                        == transaction.supersedes_attempt_id.as_ref()
                        && link.replacement_attempt_id == transaction.attempt_id
                        && link.observed_active_certificate_sha256
                            == transaction.previous_certificate_sha256,
                )?;
            }
            if let Some(link) = &self.pending_supersession {
                link.validate(authority, now)?;
                require(
                    link.previous_transaction == *transaction
                        && Some(&link.previous_journal_sha256) == self.transaction_sha256.as_ref()
                        && link.observed_active_certificate_sha256 == self.certificate_sha256,
                )?;
            }
        } else {
            require(
                self.completed_receipt.is_none()
                    && self.supersession.is_none()
                    && self.pending_supersession.is_none(),
            )?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    schema: String,
    installation_id: String,
    engine_id: String,
    project: String,
    container_id: String,
    image: String,
    config_hash: String,
    authority_sha256: String,
    attempt_id: String,
    sequence: u64,
    previous_attempt_id: Option<String>,
    previous_intent_sha256: Option<String>,
    reason: String,
    previous_certificate_sha256: String,
    created_at: String,
    superseded_transaction: Option<LocalTransaction>,
    superseded_transaction_sha256: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Publication {
    schema: String,
    intent_sha256: String,
    receipt: LocalReceipt,
    receipt_sha256: String,
    certificate_pem: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReloadIntent {
    schema: String,
    intent_sha256: String,
    publication_sha256: String,
    container_id: String,
    signal: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reload {
    schema: String,
    reload_intent_sha256: String,
    command_acknowledged: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Completion {
    schema: String,
    intent_sha256: String,
    publication_sha256: String,
    reload_sha256: String,
    certificate_sha256: String,
    ca_sha256: String,
    spki_sha256: String,
    cluster_id: String,
    verified_at: String,
    file_publication_observed: bool,
    reload_requested: bool,
    network_tls_verified: bool,
    installation_ready: bool,
}
#[derive(Clone, Debug)]
struct Attempt {
    intent: Intent,
    intent_sha256: String,
    publication: Option<Publication>,
    publication_sha256: Option<String>,
    reload_intent: Option<ReloadIntent>,
    reload_intent_sha256: Option<String>,
    reload: Option<Reload>,
    reload_sha256: Option<String>,
    complete: Option<Completion>,
}
fn record_name(attempt: &str, phase: &str) -> String {
    format!("{PREFIX}{attempt}-{phase}.json")
}
fn read_phase<T: DeserializeOwned>(
    state: &LockedMaintenance,
    attempt: &str,
    phase: &str,
) -> Result<(Option<T>, Option<String>)> {
    match state.read_evidence(&record_name(attempt, phase))? {
        Some(bytes) => Ok((Some(decode(&bytes)?), Some(sha256(&bytes)))),
        None => Ok((None, None)),
    }
}
fn persist<T: Serialize>(
    state: &mut LockedMaintenance,
    attempt: &str,
    phase: &str,
    value: &T,
) -> Result<()> {
    state.write_evidence_exclusive(&record_name(attempt, phase), &encode(value)?)
}

fn history(
    state: &LockedMaintenance,
    authority: &Authority,
    resources: &ProjectResources,
    now: u64,
) -> Result<Vec<Attempt>> {
    let evidence = fs::open_child(
        state.inspection().installation_directory(),
        "evidence",
        libc::O_RDONLY | libc::O_DIRECTORY,
        REFUSED,
    )?;
    let pattern = regex::Regex::new(r"\Aopenbao-tls-recovery-([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})-(intent|publication|reload-intent|reload|complete)\.json\z").map_err(|_| REFUSED)?;
    let mut names = BTreeMap::<String, BTreeSet<String>>::new();
    for name in fs::file_names(&evidence, REFUSED)?
        .into_iter()
        .filter(|v| v.starts_with(PREFIX))
    {
        let capture = pattern.captures(&name).ok_or(REFUSED)?;
        require(uuid(&capture[1]))?;
        names
            .entry(capture[1].into())
            .or_default()
            .insert(capture[2].into());
    }
    let mut attempts = Vec::new();
    for (id, phases) in names {
        require(phases.contains("intent"))?;
        let (intent, digest) = read_phase::<Intent>(state, &id, "intent")?;
        let (publication, publication_sha256) = read_phase(state, &id, "publication")?;
        let (reload_intent, reload_intent_sha256) = read_phase(state, &id, "reload-intent")?;
        let (reload, reload_sha256) = read_phase(state, &id, "reload")?;
        let (complete, _) = read_phase(state, &id, "complete")?;
        let attempt = Attempt {
            intent: intent.ok_or(REFUSED)?,
            intent_sha256: digest.ok_or(REFUSED)?,
            publication,
            publication_sha256,
            reload_intent,
            reload_intent_sha256,
            reload,
            reload_sha256,
            complete,
        };
        require(attempt.intent.attempt_id == id)?;
        attempts.push(attempt);
    }
    attempts.sort_by_key(|a| a.intent.sequence);
    validate_history(
        &attempts,
        authority,
        resources,
        &state.journal().compose_project(),
        now,
    )?;
    Ok(attempts)
}

fn validate_history(
    attempts: &[Attempt],
    authority: &Authority,
    resources: &ProjectResources,
    project: &str,
    now: u64,
) -> Result<()> {
    let openbao = resources.containers.get("openbao").ok_or(REFUSED)?;
    let enrolled = &authority.observation.enrollment;
    for (index, entry) in attempts.iter().enumerate() {
        let intent = &entry.intent;
        require(
            intent.schema == "elevenid.installer-openbao-tls-recovery-intent/v1"
                && intent.installation_id == enrolled.installation_id
                && intent.engine_id == authority.observation.engine_id
                && intent.project == project
                && intent.container_id == openbao.id
                && intent.image == openbao.image
                && intent.config_hash == openbao.config_hash
                && intent.authority_sha256 == authority.observation_sha256
                && uuid(&intent.attempt_id)
                && intent.sequence == index as u64 + 1
                && hash(&intent.previous_certificate_sha256)
                && timestamp(&intent.created_at)? <= now,
        )?;
        if index == 0 {
            require(
                intent.previous_attempt_id.is_none()
                    && intent.previous_intent_sha256.is_none()
                    && intent.reason == "renewal_due",
            )?;
        } else {
            let previous = &attempts[index - 1];
            require(
                intent.previous_attempt_id.as_ref() == Some(&previous.intent.attempt_id)
                    && intent.previous_intent_sha256.as_ref() == Some(&previous.intent_sha256)
                    && timestamp(&intent.created_at)? >= timestamp(&previous.intent.created_at)?,
            )?;
            if previous.complete.is_some() {
                require(intent.reason == "renewal_due")?;
            } else {
                require(matches!(
                    intent.reason.as_str(),
                    "candidate_expired" | "published_certificate_expired"
                ))?;
            }
        }
        if intent.reason == "renewal_due" {
            require(
                intent.superseded_transaction.is_none()
                    && intent.superseded_transaction_sha256.is_none(),
            )?;
            if index > 0 {
                require(attempts[index - 1].publication.as_ref().is_some_and(|v| {
                    v.receipt.certificate_sha256 == intent.previous_certificate_sha256
                }))?;
            }
        } else {
            let previous = attempts
                .get(index.checked_sub(1).ok_or(REFUSED)?)
                .ok_or(REFUSED)?;
            let superseded = intent.superseded_transaction.as_ref().ok_or(REFUSED)?;
            superseded.validate(authority, now)?;
            require(
                intent
                    .superseded_transaction_sha256
                    .as_ref()
                    .is_some_and(|v| hash(v))
                    && superseded.attempt_id == previous.intent.attempt_id
                    && superseded.previous_certificate_sha256
                        == previous.intent.previous_certificate_sha256
                    && timestamp(&superseded.not_after)? <= timestamp(&intent.created_at)?
                    && match intent.reason.as_str() {
                        "candidate_expired" => {
                            superseded.phase == "candidate"
                                && (intent.previous_certificate_sha256
                                    == superseded.previous_certificate_sha256
                                    || intent.previous_certificate_sha256
                                        == superseded.certificate_sha256)
                        }
                        "published_certificate_expired" => {
                            superseded.phase == "published"
                                && intent.previous_certificate_sha256
                                    == superseded.certificate_sha256
                                && previous
                                    .publication
                                    .as_ref()
                                    .is_some_and(|v| v.receipt == superseded.receipt())
                        }
                        _ => false,
                    },
            )?;
        }
        if let Some(published) = &entry.publication {
            let receipt = &published.receipt;
            require(
                published.schema == "elevenid.installer-openbao-tls-publication/v1"
                    && published.intent_sha256 == entry.intent_sha256
                    && hash(&published.receipt_sha256)
                    && receipt.schema == "elevenid.openbao-tcp-recovery-result/v1"
                    && receipt.installation_id == intent.installation_id
                    && receipt.attempt_id == intent.attempt_id
                    && receipt.cluster_id == enrolled.cluster_id
                    && receipt.issuer_id == enrolled.issuer_id
                    && receipt.ca_sha256 == enrolled.ca_sha256
                    && receipt.spki_sha256 == enrolled.spki_sha256
                    && receipt.previous_certificate_sha256 == intent.previous_certificate_sha256
                    && receipt.certificate_sha256 != receipt.previous_certificate_sha256
                    && receipt.node_key_preserved
                    && receipt.certificate_published
                    && !receipt.reload_performed
                    && !receipt.network_tls_verified,
            )?;
            let (_, before, after) = bound_leaf(
                &published.certificate_pem,
                &receipt.certificate_sha256,
                authority,
                now,
            )?;
            require(after == timestamp(&receipt.not_after)? && after - before <= 31 * 86400)?;
        }
        if let Some(reload) = &entry.reload_intent {
            require(
                entry.publication.is_some()
                    && reload.schema == "elevenid.installer-openbao-tls-reload-intent/v1"
                    && reload.intent_sha256 == entry.intent_sha256
                    && Some(&reload.publication_sha256) == entry.publication_sha256.as_ref()
                    && reload.container_id == intent.container_id
                    && reload.signal == "HUP",
            )?;
        }
        if let Some(reload) = &entry.reload {
            require(
                entry.reload_intent.is_some()
                    && reload.schema == "elevenid.installer-openbao-tls-reload/v1"
                    && Some(&reload.reload_intent_sha256) == entry.reload_intent_sha256.as_ref()
                    && reload.command_acknowledged,
            )?;
        }
        if let Some(complete) = &entry.complete {
            let receipt = &entry.publication.as_ref().ok_or(REFUSED)?.receipt;
            require(
                entry.reload.is_some()
                    && complete.schema == "elevenid.installer-openbao-tls-recovery-complete/v1"
                    && complete.intent_sha256 == entry.intent_sha256
                    && Some(&complete.publication_sha256) == entry.publication_sha256.as_ref()
                    && Some(&complete.reload_sha256) == entry.reload_sha256.as_ref()
                    && complete.certificate_sha256 == receipt.certificate_sha256
                    && complete.ca_sha256 == enrolled.ca_sha256
                    && complete.spki_sha256 == enrolled.spki_sha256
                    && complete.cluster_id == enrolled.cluster_id
                    && timestamp(&complete.verified_at)? <= now
                    && timestamp(&complete.verified_at)? >= timestamp(&intent.created_at)?
                    && timestamp(&complete.verified_at)? < timestamp(&receipt.not_after)?
                    && complete.file_publication_observed
                    && complete.reload_requested
                    && complete.network_tls_verified
                    && !complete.installation_ready,
            )?;
        }
    }
    Ok(())
}

fn bind_current(attempts: &[Attempt], inspected: &Inspection) -> Result<()> {
    let Some(current) = attempts.last() else {
        return require(inspected.transaction.is_none());
    };
    let intent = &current.intent;
    let Some(transaction) = &inspected.transaction else {
        return require(
            attempts.len() == 1
                && current.publication.is_none()
                && intent.reason == "renewal_due"
                && inspected.certificate_sha256 == intent.previous_certificate_sha256,
        );
    };
    if transaction.attempt_id == intent.attempt_id {
        require(
            transaction.previous_certificate_sha256 == intent.previous_certificate_sha256
                && inspected.pending_supersession.is_none(),
        )?;
        if intent.reason == "candidate_expired" {
            let link = inspected.supersession.as_ref().ok_or(REFUSED)?;
            require(
                Some(&link.previous_transaction) == intent.superseded_transaction.as_ref()
                    && Some(&link.previous_journal_sha256)
                        == intent.superseded_transaction_sha256.as_ref()
                    && link.observed_active_certificate_sha256
                        == intent.previous_certificate_sha256,
            )?;
        } else {
            require(
                transaction.supersedes_attempt_id.is_none() && inspected.supersession.is_none(),
            )?;
        }
        if let Some(publication) = &current.publication {
            require(
                inspected.completed_receipt.as_ref() == Some(&publication.receipt)
                    && inspected.completed_receipt_sha256.as_ref()
                        == Some(&publication.receipt_sha256)
                    && transaction.phase == "published"
                    && inspected.certificate_pem == publication.certificate_pem,
            )?;
        }
        return Ok(());
    }
    require(
        current.publication.is_none()
            && current.reload_intent.is_none()
            && current.reload.is_none()
            && current.complete.is_none()
            && Some(&transaction.attempt_id) == intent.previous_attempt_id.as_ref(),
    )?;
    if intent.reason == "renewal_due" {
        let previous = attempts.get(attempts.len() - 2).ok_or(REFUSED)?;
        require(
            previous.complete.is_some()
                && inspected.pending_supersession.is_none()
                && transaction.phase == "published"
                && previous.publication.as_ref().is_some_and(|v| {
                    inspected.completed_receipt.as_ref() == Some(&v.receipt)
                        && inspected.completed_receipt_sha256.as_ref() == Some(&v.receipt_sha256)
                })
                && inspected.certificate_sha256 == intent.previous_certificate_sha256,
        )
    } else {
        require(
            Some(transaction) == intent.superseded_transaction.as_ref()
                && inspected.transaction_sha256 == intent.superseded_transaction_sha256
                && inspected.certificate_sha256 == intent.previous_certificate_sha256,
        )?;
        if let Some(link) = &inspected.pending_supersession {
            require(
                intent.reason == "candidate_expired"
                    && link.replacement_attempt_id == intent.attempt_id,
            )?;
        }
        Ok(())
    }
}

fn owned_resources(session: &ComposeSession, authority: &Authority) -> Result<ProjectResources> {
    let resources = session.observe_resources()?;
    let bao = resources.containers.get("openbao").ok_or(REFUSED)?;
    let enrollment = resources
        .containers
        .get("installer-control-enroll")
        .ok_or(REFUSED)?;
    require(
        bao.id == authority.observation.container_id
            && bao.image == authority.observation.image
            && !bao.setup
            && bao.service == "openbao"
            && enrollment.id == authority.observation.enrollment_container_id
            && enrollment.image == bao.image
            && enrollment.setup
            && enrollment
                .setup_execution
                .as_ref()
                .is_some_and(|v| v.completed_without_restart),
    )?;
    let rows = session.status()?;
    let found: Vec<_> = rows.iter().filter(|v| v["Service"] == "openbao").collect();
    require(found.len() == 1 && found[0]["ID"] == bao.id && found[0]["State"] == "running")?;
    Ok(resources)
}
fn stable(
    state: &LockedMaintenance,
    installation: &Path,
    session: &ComposeSession,
    retained: &Authority,
    resources: &ProjectResources,
) -> Result<()> {
    state.require_unchanged()?;
    require(
        authority(state.inspection(), installation)? == *retained
            && owned_resources(session, retained)? == *resources,
    )
}

/// Shared, opaque ownership guard for the two fixed local-control operations.
/// Capturing it reads public enrollment and private-file metadata only; it never
/// opens the initial root, recovery share, node key or AppRole SecretID.
pub(crate) struct OwnedLocalControl {
    authority: Authority,
    resources: ProjectResources,
    binding: LocalControlBinding,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LocalControlBinding {
    pub installation_id: String,
    pub engine_id: String,
    pub project: String,
    pub container_id: String,
    pub image: String,
    pub config_hash: String,
    pub resources_sha256: String,
    pub control_observation_sha256: String,
    pub cluster_id: String,
    pub issuer_id: String,
    pub ca_sha256: String,
    pub spki_sha256: String,
}

impl OwnedLocalControl {
    pub(crate) fn capture(
        state: &LockedMaintenance,
        installation: &Path,
        session: &ComposeSession,
    ) -> Result<Self> {
        let authority = authority(state.inspection(), installation)?;
        let resources = owned_resources(session, &authority)?;
        let container = resources.containers.get("openbao").ok_or(REFUSED)?;
        let enrollment = &authority.observation.enrollment;
        let binding = LocalControlBinding {
            installation_id: authority.observation.installation_id.clone(),
            engine_id: authority.observation.engine_id.clone(),
            project: state.journal().compose_project(),
            container_id: container.id.clone(),
            image: container.image.clone(),
            config_hash: container.config_hash.clone(),
            resources_sha256: sha256(&encode(&resources)?),
            control_observation_sha256: authority.observation_sha256.clone(),
            cluster_id: enrollment.cluster_id.clone(),
            issuer_id: enrollment.issuer_id.clone(),
            ca_sha256: enrollment.ca_sha256.clone(),
            spki_sha256: enrollment.spki_sha256.clone(),
        };
        stable(state, installation, session, &authority, &resources)?;
        Ok(Self {
            authority,
            resources,
            binding,
        })
    }

    pub(crate) fn binding(&self) -> &LocalControlBinding {
        &self.binding
    }

    pub(crate) fn require_unchanged(
        &self,
        state: &LockedMaintenance,
        installation: &Path,
        session: &ComposeSession,
    ) -> Result<()> {
        stable(
            state,
            installation,
            session,
            &self.authority,
            &self.resources,
        )
    }
}

fn inspect(docker: &DockerRunner, authority: &Authority, now: u64) -> Result<Inspection> {
    let output = docker.inspect_openbao_tls(
        &authority.observation.container_id,
        &authority.observation.installation_id,
    )?;
    let observation: Inspection = decode(output.as_bytes())?;
    observation.validate(authority, now)?;
    Ok(observation)
}

async fn verify_network(authority: &Authority, observation: &Inspection, port: u16) -> Result<()> {
    require(port >= 1024 && timestamp(&observation.not_after)? > now()?)?;
    let ca = crate::installer_ingress_provision::certificate(
        std::str::from_utf8(&authority.ca).map_err(|_| REFUSED)?,
    )?;
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(ca.to_der().map_err(|_| REFUSED)?))
        .map_err(|_| REFUSED)?;
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| REFUSED)?
    .with_root_certificates(roots)
    .with_no_client_auth();
    // A fresh connection and ordinary CA/name/time verification. No credential
    // is sent; the additional leaf/SPKI pins and cluster check narrow this
    // read-only health result to the installation's exact published identity.
    let client = reqwest::Client::builder()
        .https_only(true)
        .http1_only()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .use_preconfigured_tls(tls)
        .tls_info(true)
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|_| RETRY)?;
    let mut response = client
        .get(format!("https://127.0.0.1:{port}/v1/sys/health"))
        .send()
        .await
        .map_err(|_| RETRY)?;
    require(response.status() == reqwest::StatusCode::OK)?;
    let peer = response
        .extensions()
        .get::<reqwest::tls::TlsInfo>()
        .and_then(|v| v.peer_certificate())
        .ok_or(RETRY)?;
    let peer = x509_cert::Certificate::from_der(peer).map_err(|_| REFUSED)?;
    require(
        sha256(&peer.to_der().map_err(|_| REFUSED)?) == observation.certificate_sha256
            && sha256(
                &peer
                    .tbs_certificate
                    .subject_public_key_info
                    .to_der()
                    .map_err(|_| REFUSED)?,
            ) == observation.spki_sha256,
    )?;
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| RETRY)? {
        require(body.len().saturating_add(chunk.len()) <= 65_536)?;
        body.extend_from_slice(&chunk);
    }
    let health = installer_json::decode(&body).map_err(|_| REFUSED)?;
    require(
        health["initialized"] == true
            && health["sealed"] == false
            && health["cluster_id"] == observation.cluster_id,
    )
}
fn verified_network(authority: &Authority, observation: &Inspection, port: u16) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| RETRY)?;
    runtime.block_on(async {
        for attempt in 0..3 {
            if verify_network(authority, observation, port).await.is_ok() {
                return Ok(());
            }
            if attempt < 2 {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
        Err(RETRY.into())
    })
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct RecoveryReport {
    pub schema: &'static str,
    pub installation_id: String,
    pub attempt_id: Option<String>,
    pub certificate_sha256: String,
    pub certificate_expires_at: String,
    pub renewal_due: bool,
    pub file_publication_observed: bool,
    pub reload_requested: bool,
    pub network_tls_verified: bool,
    pub installation_ready: bool,
}
fn report(
    observation: &Inspection,
    latest: Option<&Attempt>,
    verified: bool,
) -> Result<RecoveryReport> {
    Ok(RecoveryReport {
        schema: "elevenid.installer-openbao-tls-recovery/v1",
        installation_id: observation.installation_id.clone(),
        attempt_id: latest.map(|v| v.intent.attempt_id.clone()),
        certificate_sha256: observation.certificate_sha256.clone(),
        certificate_expires_at: observation.not_after.clone(),
        renewal_due: timestamp(&observation.not_after)? <= now()?.saturating_add(HORIZON),
        file_publication_observed: latest.is_some_and(|v| v.publication.is_some()),
        reload_requested: latest.is_some_and(|v| v.reload.is_some()),
        network_tls_verified: verified,
        installation_ready: false,
    })
}

/// Read-only inspection is permitted independently of durable running intent.
/// It requires a running owned OpenBao container to execute the fixed inspector;
/// a stopped container is reported as unavailable, never started here.
pub(crate) fn inspect_locked(
    installation: &Path,
    docker_binary: &Path,
    state: &LockedMaintenance,
    session: &ComposeSession,
) -> Result<RecoveryReport> {
    let retained = authority(state.inspection(), installation)?;
    let resources = owned_resources(session, &retained)?;
    let binding = state.journal().runtime().ok_or(REFUSED)?;
    let docker = DockerRunner::from_binding(docker_binary, binding, installation)?
        .with_deadline(Instant::now() + Duration::from_secs(120));
    let observed = inspect(&docker, &retained, now()?)?;
    let attempts = history(state, &retained, &resources, now()?)?;
    bind_current(&attempts, &observed)?;
    stable(state, installation, session, &retained, &resources)?;
    report(&observed, attempts.last(), false)
}

fn begin(
    state: &mut LockedMaintenance,
    retained: &Authority,
    resources: &ProjectResources,
    attempts: &[Attempt],
    observed: &Inspection,
    reason: &str,
    now: u64,
) -> Result<()> {
    let previous = attempts.last();
    let bao = resources.containers.get("openbao").ok_or(REFUSED)?;
    let superseded = (reason != "renewal_due")
        .then(|| observed.transaction.clone())
        .flatten();
    let intent = Intent {
        schema: "elevenid.installer-openbao-tls-recovery-intent/v1".into(),
        installation_id: observed.installation_id.clone(),
        engine_id: retained.observation.engine_id.clone(),
        project: state.journal().compose_project(),
        container_id: bao.id.clone(),
        image: bao.image.clone(),
        config_hash: bao.config_hash.clone(),
        authority_sha256: retained.observation_sha256.clone(),
        attempt_id: uuid::Uuid::new_v4().to_string(),
        sequence: previous.map_or(Ok(1), |v| v.intent.sequence.checked_add(1).ok_or(REFUSED))?,
        previous_attempt_id: previous.map(|v| v.intent.attempt_id.clone()),
        previous_intent_sha256: previous.map(|v| v.intent_sha256.clone()),
        reason: reason.into(),
        previous_certificate_sha256: observed.certificate_sha256.clone(),
        created_at: clock(now)?,
        superseded_transaction_sha256: if superseded.is_some() {
            observed.transaction_sha256.clone()
        } else {
            None
        },
        superseded_transaction: superseded,
    };
    let mut proposed = attempts.to_vec();
    proposed.push(Attempt {
        intent: intent.clone(),
        intent_sha256: sha256(&encode(&intent)?),
        publication: None,
        publication_sha256: None,
        reload_intent: None,
        reload_intent_sha256: None,
        reload: None,
        reload_sha256: None,
        complete: None,
    });
    validate_history(
        &proposed,
        retained,
        resources,
        &state.journal().compose_project(),
        now,
    )?;
    persist(state, &intent.attempt_id, "intent", &intent)
}
fn publish_observation(
    state: &mut LockedMaintenance,
    current: &Attempt,
    observed: &Inspection,
) -> Result<()> {
    if current.publication.is_some() {
        return Ok(());
    }
    let transaction = observed.transaction.as_ref().ok_or(REFUSED)?;
    require(
        transaction.attempt_id == current.intent.attempt_id && transaction.phase == "published",
    )?;
    let publication = Publication {
        schema: "elevenid.installer-openbao-tls-publication/v1".into(),
        intent_sha256: current.intent_sha256.clone(),
        receipt: observed.completed_receipt.clone().ok_or(REFUSED)?,
        receipt_sha256: observed.completed_receipt_sha256.clone().ok_or(REFUSED)?,
        certificate_pem: observed.certificate_pem.clone(),
    };
    persist(
        state,
        &current.intent.attempt_id,
        "publication",
        &publication,
    )
}

/// Mutation entry point: the lifecycle caller must first establish durable
/// running intent under this same lock. Ordinary failures leave the same UUID
/// resumable. Only natural expiry can link an unfinished candidate to a new
/// fixed-key local attempt; this never retries public ACME account/order work.
pub(crate) fn reconcile_locked(
    installation: &Path,
    docker_binary: &Path,
    state: &mut LockedMaintenance,
    session: &ComposeSession,
) -> Result<RecoveryReport> {
    let retained = authority(state.inspection(), installation)?;
    let resources = owned_resources(session, &retained)?;
    let binding = state.journal().runtime().ok_or(REFUSED)?.clone();
    let docker = DockerRunner::from_binding(docker_binary, &binding, installation)?
        .with_deadline(Instant::now() + Duration::from_secs(300));
    let mut helper_calls = 0;
    // At most an expired prior attempt and one replacement can be advanced in
    // one invocation. There is no lifetime history cap on later renewals.
    for _ in 0..8 {
        stable(state, installation, session, &retained, &resources)?;
        let current_time = now()?;
        let observed = inspect(&docker, &retained, current_time)?;
        let attempts = history(state, &retained, &resources, current_time)?;
        bind_current(&attempts, &observed)?;
        stable(state, installation, session, &retained, &resources)?;
        let current = attempts.last();
        if current.is_none_or(|v| v.complete.is_some()) {
            if timestamp(&observed.not_after)? > current_time.saturating_add(HORIZON) {
                verified_network(&retained, &observed, binding.openbao_port)?;
                stable(state, installation, session, &retained, &resources)?;
                let final_observed = inspect(&docker, &retained, now()?)?;
                require(final_observed == observed)?;
                return report(&observed, current, true);
            }
            require(observed.renewal_issuer_usable)?;
            begin(
                state,
                &retained,
                &resources,
                &attempts,
                &observed,
                "renewal_due",
                current_time,
            )?;
            continue;
        }
        let current = current.ok_or(REFUSED)?;
        if let Some(transaction) = observed
            .transaction
            .as_ref()
            .filter(|v| v.attempt_id == current.intent.attempt_id)
        {
            if transaction.phase == "candidate"
                && timestamp(&transaction.not_after)? <= current_time
            {
                require(observed.renewal_issuer_usable)?;
                begin(
                    state,
                    &retained,
                    &resources,
                    &attempts,
                    &observed,
                    "candidate_expired",
                    current_time,
                )?;
                continue;
            }
            if transaction.phase == "published" && observed.completed_receipt.is_some() {
                publish_observation(state, current, &observed)?;
                if timestamp(&observed.not_after)? <= current_time {
                    require(observed.renewal_issuer_usable)?;
                    let attempts = history(state, &retained, &resources, current_time)?;
                    begin(
                        state,
                        &retained,
                        &resources,
                        &attempts,
                        &observed,
                        "published_certificate_expired",
                        current_time,
                    )?;
                    continue;
                }
                let attempts = history(state, &retained, &resources, current_time)?;
                let current = attempts.last().ok_or(REFUSED)?;
                if current.reload_intent.is_none() {
                    persist(
                        state,
                        &current.intent.attempt_id,
                        "reload-intent",
                        &ReloadIntent {
                            schema: "elevenid.installer-openbao-tls-reload-intent/v1".into(),
                            intent_sha256: current.intent_sha256.clone(),
                            publication_sha256: current
                                .publication_sha256
                                .clone()
                                .ok_or(REFUSED)?,
                            container_id: current.intent.container_id.clone(),
                            signal: "HUP".into(),
                        },
                    )?;
                }
                stable(state, installation, session, &retained, &resources)?;
                // Repeating HUP on the exact retained ID is safe, including
                // after a lost Docker acknowledgement or a later process boot.
                let mut acknowledged = false;
                for _ in 0..2 {
                    let result = docker.reload_openbao_tls(&retained.observation.container_id);
                    stable(state, installation, session, &retained, &resources)?;
                    require(inspect(&docker, &retained, now()?)? == observed)?;
                    if result.is_ok() {
                        acknowledged = true;
                        break;
                    }
                }
                if !acknowledged {
                    return Err(RETRY.into());
                }
                let attempts = history(state, &retained, &resources, now()?)?;
                let current = attempts.last().ok_or(REFUSED)?;
                if current.reload.is_none() {
                    persist(
                        state,
                        &current.intent.attempt_id,
                        "reload",
                        &Reload {
                            schema: "elevenid.installer-openbao-tls-reload/v1".into(),
                            reload_intent_sha256: current
                                .reload_intent_sha256
                                .clone()
                                .ok_or(REFUSED)?,
                            command_acknowledged: true,
                        },
                    )?;
                }
                verified_network(&retained, &observed, binding.openbao_port)?;
                stable(state, installation, session, &retained, &resources)?;
                require(inspect(&docker, &retained, now()?)? == observed)?;
                let attempts = history(state, &retained, &resources, now()?)?;
                let current = attempts.last().ok_or(REFUSED)?;
                persist(
                    state,
                    &current.intent.attempt_id,
                    "complete",
                    &Completion {
                        schema: "elevenid.installer-openbao-tls-recovery-complete/v1".into(),
                        intent_sha256: current.intent_sha256.clone(),
                        publication_sha256: current.publication_sha256.clone().ok_or(REFUSED)?,
                        reload_sha256: current.reload_sha256.clone().ok_or(REFUSED)?,
                        certificate_sha256: observed.certificate_sha256.clone(),
                        ca_sha256: observed.ca_sha256.clone(),
                        spki_sha256: observed.spki_sha256.clone(),
                        cluster_id: observed.cluster_id.clone(),
                        verified_at: clock(now()?)?,
                        file_publication_observed: true,
                        reload_requested: true,
                        network_tls_verified: true,
                        installation_ready: false,
                    },
                )?;
                return report(
                    &observed,
                    history(state, &retained, &resources, now()?)?.last(),
                    true,
                );
            }
        }
        require(observed.renewal_issuer_usable)?;
        if helper_calls >= 3 {
            return Err(RETRY.into());
        }
        helper_calls += 1;
        stable(state, installation, session, &retained, &resources)?;
        let output = docker.recover_openbao_tls(
            &retained.observation.container_id,
            &retained.observation.installation_id,
            &current.intent.attempt_id,
        );
        stable(state, installation, session, &retained, &resources)?;
        let after = inspect(&docker, &retained, now()?)?;
        bind_current(&attempts, &after)?;
        if let Ok(output) = output {
            require(
                after.completed_receipt.as_ref()
                    == Some(&decode::<LocalReceipt>(output.as_bytes())?),
            )?;
        }
        // A lost response may already have published its retained result. A
        // fresh inspection settles that fact; otherwise the same UUID retries.
    }
    Err(RETRY.into())
}

#[cfg(test)]
#[path = "installer_openbao_recovery_tests.rs"]
mod tests;
