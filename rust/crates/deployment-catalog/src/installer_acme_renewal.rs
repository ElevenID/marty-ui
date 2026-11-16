//! Durable, candidate-bound ACME renewal scheduling. This owner only reads ARI;
//! it cannot sign, create an order, activate a leaf or refresh workload tokens.
#![cfg(target_os = "linux")]

use crate::{
    installer_acme::AcmeCandidate,
    installer_acme_configuration::AcmeEnvironment,
    installer_acme_state::{self as enrolment, Ledger, Stage},
    installer_host_fs, installer_json,
    installer_state::{InstallerState, LockedInspection, LockedMaintenance, Phase},
};
use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use marty_acme_client::{
    protocol::{
        Account, CertificateIdentifier, Error as ProtocolError, ExternalAccountSigner, HttpClient,
        RenewalInfo,
    },
    AcmeHttps,
};
use rustls::pki_types::pem::PemObject;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use spki::der::{asn1::AnyRef, Decode, Encode};
use std::{
    collections::{BTreeMap, BTreeSet},
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use x509_cert::{ext::pkix::AuthorityKeyIdentifier, Certificate};

type Result<T> = std::result::Result<T, String>;
const REFUSED: &str = "ACME renewal scheduling refused; retain the candidate and schedule receipts for reconciliation. No order or certificate activation was attempted";
const SCHEMA: &str = "elevenid.installer-acme-renewal/v1";
const MIN_REFRESH: u64 = 60;
const LONG_ERROR_REFRESH: u64 = 6 * 3600;
const MAX_FAILURES: u32 = 8;
const WORK_DEADLINE: Duration = Duration::from_secs(25);
// A 160-hour leaf at the minimum one-minute interval needs fewer than 20,000
// intent/result receipts. Normal LE intervals require only a few dozen.
const MAX_RECORDS: usize = 32_768;
const MAX_RECORD_BYTES: usize = 16 * 1024;

fn require(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}
fn now() -> Result<u64> {
    #[cfg(test)]
    if let Some(value) = TEST_TIME.with(std::cell::Cell::get) {
        return Ok(value);
    }
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .map_err(|_| REFUSED.into())
}
#[cfg(test)]
thread_local! { static TEST_TIME: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) }; }

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    installation_id: uuid::Uuid,
    environment: AcmeEnvironment,
    #[serde(default, skip_serializing_if = "enrolment::initial_cycle")]
    cycle: u64,
    enrolment_receipt_sha256: String,
    enrolment_binding_sha256: String,
    directory_url: String,
    account_url: String,
    account_public_sec1: Vec<u8>,
    leaf_der_sha256: String,
    fullchain_pem_sha256: String,
    certificate_identifier: Option<String>,
    not_before: u64,
    not_after: u64,
    fallback_renew_at: u64,
}
impl Binding {
    fn from_enrolment(state: &LockedInspection, environment: AcmeEnvironment) -> Result<Self> {
        Self::from_cycle(state, environment, 0)
    }
    fn from_cycle(
        state: &LockedInspection,
        environment: AcmeEnvironment,
        cycle: u64,
    ) -> Result<Self> {
        let saved = Ledger::load_cycle(state, environment, cycle)?.ok_or(REFUSED)?;
        require(saved.state.stage == Stage::Complete)?;
        let configuration = saved.binding.configuration(state)?;
        let certificate = saved.state.certificate.as_ref().ok_or(REFUSED)?;
        let mut certificates =
            rustls::pki_types::CertificateDer::pem_slice_iter(certificate.fullchain_pem.as_bytes());
        let leaf_der = certificates.next().ok_or(REFUSED)?.map_err(|_| REFUSED)?;
        let leaf = Certificate::from_der(leaf_der.as_ref()).map_err(|_| REFUSED)?;
        let not_before = leaf
            .tbs_certificate
            .validity
            .not_before
            .to_unix_duration()
            .as_secs();
        let not_after = leaf
            .tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_secs();
        let lifetime = not_after
            .checked_sub(not_before)
            .filter(|value| *value > 0)
            .ok_or(REFUSED)?;
        let account_public_sec1: Vec<u8> =
            serde_json::from_value(saved.binding.account_key["public_sec1"].clone())
                .map_err(|_| REFUSED)?;
        require(
            account_public_sec1.len() == 65
                && account_public_sec1[0] == 4
                && certificate.metadata["leaf_der_sha256"] == enrolment::hash(leaf_der.as_ref())
                && certificate.metadata["fullchain_pem_sha256"]
                    == enrolment::hash(certificate.fullchain_pem.as_bytes())
                && certificate.metadata["not_before"] == not_before
                && certificate.metadata["not_after"] == not_after,
        )?;
        let fallback_elapsed = if lifetime < 10 * 24 * 3600 {
            lifetime / 2
        } else {
            ((u128::from(lifetime) * 2) / 3)
                .try_into()
                .map_err(|_| REFUSED)?
        };
        Ok(Self {
            installation_id: saved.binding.installation_id,
            environment,
            cycle,
            enrolment_receipt_sha256: saved.digest.clone(),
            enrolment_binding_sha256: saved.binding.digest()?,
            directory_url: configuration.parameters().directory_url().into(),
            account_url: saved.state.account_url.ok_or(REFUSED)?,
            account_public_sec1,
            leaf_der_sha256: enrolment::hash(leaf_der.as_ref()),
            fullchain_pem_sha256: enrolment::hash(certificate.fullchain_pem.as_bytes()),
            certificate_identifier: certificate_identifier(&leaf)?.map(|value| value.to_string()),
            not_before,
            not_after,
            fallback_renew_at: not_before.checked_add(fallback_elapsed).ok_or(REFUSED)?,
        })
    }
    fn from_candidate(state: &LockedInspection, candidate: &AcmeCandidate) -> Result<Self> {
        let binding = Self::from_cycle(state, candidate.environment(), candidate.cycle())?;
        require(
            binding.enrolment_receipt_sha256 == candidate.enrolment_receipt_sha256()
                && binding.leaf_der_sha256 == candidate.metadata()["leaf_der_sha256"]
                && binding.fullchain_pem_sha256
                    == enrolment::hash(candidate.fullchain_pem().as_bytes())
                && binding.not_before == candidate.metadata()["not_before"]
                && binding.not_after == candidate.metadata()["not_after"],
        )?;
        Ok(binding)
    }
}

fn certificate_identifier(leaf: &Certificate) -> Result<Option<CertificateIdentifier<'static>>> {
    let Some((_, authority)) = leaf
        .tbs_certificate
        .get::<AuthorityKeyIdentifier>()
        .map_err(|_| REFUSED)?
    else {
        return Ok(None);
    };
    let Some(key_identifier) = authority.key_identifier else {
        return Ok(None);
    };
    require(!key_identifier.as_bytes().is_empty() && key_identifier.as_bytes().len() <= 1024)?;
    // RFC 9773 uses the DER INTEGER contents, including a leading sign byte.
    // SerialNumber::as_bytes() strips that byte and must not be used here.
    let serial_der = leaf
        .tbs_certificate
        .serial_number
        .to_der()
        .map_err(|_| REFUSED)?;
    let serial = AnyRef::from_der(&serial_der).map_err(|_| REFUSED)?;
    require(
        !serial.value().is_empty() && serial.value().len() <= 21 && serial.value()[0] & 0x80 == 0,
    )?;
    Ok(Some(CertificateIdentifier {
        authority_key_identifier: URL_SAFE_NO_PAD.encode(key_identifier.as_bytes()).into(),
        serial: URL_SAFE_NO_PAD.encode(serial.value()).into(),
    }))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ScheduleStage {
    Prepared,
    FetchPending,
    Available,
    Unavailable,
    Expired,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Window {
    start: u64,
    end: u64,
    selected_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScheduleState {
    stage: ScheduleStage,
    window: Option<Window>,
    next_refresh_at: Option<u64>,
    last_attempt_at: Option<u64>,
    last_success_at: Option<u64>,
    failures: u32,
    failure: Option<String>,
    http_status: Option<u16>,
}
impl ScheduleState {
    fn initial(binding: &Binding, observed: u64) -> Self {
        let expired = observed >= binding.not_after;
        let supported = binding.certificate_identifier.is_some();
        Self {
            stage: if expired {
                ScheduleStage::Expired
            } else if supported {
                ScheduleStage::Prepared
            } else {
                ScheduleStage::Unavailable
            },
            window: None,
            next_refresh_at: (!expired && supported).then_some(observed),
            last_attempt_at: None,
            last_success_at: None,
            failures: 0,
            failure: (!supported).then(|| "certificate_identifier_unavailable".into()),
            http_status: None,
        }
    }
    fn validate(&self, binding: &Binding, observed: u64) -> Result<()> {
        require(self.failures <= MAX_FAILURES)?;
        if let Some(window) = &self.window {
            require(
                window.start < window.end
                    && window.end <= binding.not_after
                    && window.selected_at >= window.start
                    && window.selected_at < window.end
                    && self.last_success_at.is_some(),
            )?;
        }
        require(
            self.last_attempt_at.is_none_or(|value| value <= observed)
                && self.last_success_at.is_none_or(|value| value <= observed),
        )?;
        if let Some(failure) = &self.failure {
            require(
                [
                    "certificate_identifier_unavailable",
                    "fetch_interrupted_or_pending",
                    "temporary",
                    "rate_limited",
                    "unsupported",
                    "invalid_response",
                    "long_term",
                ]
                .contains(&failure.as_str()),
            )?;
        }
        if self.stage == ScheduleStage::Available {
            require(
                self.window.is_some()
                    && self.last_success_at.is_some()
                    && self.failures == 0
                    && self.failure.is_none(),
            )?;
        }
        if self.stage == ScheduleStage::FetchPending {
            require(
                self.failures > 0
                    && self.last_attempt_at.is_some()
                    && self.failure.as_deref() == Some("fetch_interrupted_or_pending"),
            )?;
        }
        if self.stage == ScheduleStage::Expired {
            require(observed >= binding.not_after && self.next_refresh_at.is_none())?;
        } else if binding.certificate_identifier.is_some() {
            require(
                self.next_refresh_at
                    .is_some_and(|value| value > 0 && value <= binding.not_after),
            )?;
        } else {
            require(
                self.stage == ScheduleStage::Unavailable
                    && self.next_refresh_at.is_none()
                    && self.window.is_none(),
            )?;
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: String,
    sequence: usize,
    previous_sha256: Option<String>,
    observed_at: u64,
    binding: Binding,
    state: ScheduleState,
}

/// Evidence of a scheduling decision for one admitted leaf. This is not an
/// active-generation, order-creation or automatic-renewal capability.
#[derive(Clone, Debug)]
pub struct RenewalSchedule {
    binding: Binding,
    state: ScheduleState,
    sequence: usize,
    observed_at: u64,
    digest: String,
    selected_windows: BTreeMap<(u64, u64), u64>,
}
impl RenewalSchedule {
    pub(crate) fn receipt_sha256(&self) -> &str {
        &self.digest
    }
    pub(crate) fn not_after(&self) -> u64 {
        self.binding.not_after
    }
    pub(crate) fn effective_renew_at(&self) -> u64 {
        let selected = self.state.window.as_ref().map(|window| window.selected_at);
        if self.state.failure.is_some() {
            selected
                .unwrap_or(self.binding.fallback_renew_at)
                .min(self.binding.fallback_renew_at)
        } else {
            selected.unwrap_or(self.binding.fallback_renew_at)
        }
    }
    /// An expired certificate still needs replacement. This is a due decision,
    /// not certificate admission; no expired leaf is activated by this owner.
    pub(crate) fn is_due(&self) -> Result<bool> {
        let observed = now()?;
        require(observed.saturating_add(120) >= self.observed_at)?;
        Ok(observed >= self.effective_renew_at())
    }
    pub fn report(&self) -> Result<Value> {
        let observed = now()?;
        let expired = observed >= self.binding.not_after;
        let selected = self.state.window.as_ref().map(|window| window.selected_at);
        let effective = self.effective_renew_at();
        Ok(
            json!({"schema":"elevenid.installer-acme-renewal-status/v1", "installation_id":self.binding.installation_id,
            "environment":self.binding.environment, "cycle":self.binding.cycle, "leaf_der_sha256":self.binding.leaf_der_sha256,
            "enrolment_receipt_sha256":self.binding.enrolment_receipt_sha256, "schedule_receipt_sha256":self.digest,
            "sequence":self.sequence, "stage":if expired {ScheduleStage::Expired}else{self.state.stage},
            "not_before":self.binding.not_before,"not_after":self.binding.not_after,
            "fallback_renew_at":self.binding.fallback_renew_at,"ari_window":self.state.window,
            "selected_renew_at":selected,"effective_renew_at":effective,"renewal_due":self.is_due()?,
            "next_refresh_at":if expired {None}else{self.state.next_refresh_at},"failure":self.state.failure,
            "expired":expired,"certificate_activation":"not_assessed","order_created":false,
            "automatic_renewal":false,"installation_ready":false}),
        )
    }
    fn append(
        &mut self,
        state: &mut LockedMaintenance,
        next: ScheduleState,
        observed: u64,
    ) -> Result<()> {
        require(
            self.sequence + 1 < MAX_RECORDS && observed.saturating_add(120) >= self.observed_at,
        )?;
        state.require_unchanged()?;
        next.validate(&self.binding, observed)?;
        transition(&self.state, &next)?;
        remember_window(&mut self.selected_windows, next.window.as_ref())?;
        let record = Record {
            schema: SCHEMA.into(),
            sequence: self.sequence + 1,
            previous_sha256: Some(self.digest.clone()),
            observed_at: observed,
            binding: self.binding.clone(),
            state: next.clone(),
        };
        let bytes = serde_json::to_vec(&record).map_err(|_| REFUSED)?;
        require(bytes.len() <= MAX_RECORD_BYTES)?;
        state.write_evidence_exclusive(&record_name(&self.binding, record.sequence), &bytes)?;
        self.sequence = record.sequence;
        self.state = next;
        self.observed_at = observed;
        self.digest = enrolment::hash(&bytes);
        Ok(())
    }
}

fn transition(before: &ScheduleState, after: &ScheduleState) -> Result<()> {
    if before.stage == ScheduleStage::Expired {
        return require(before == after);
    }
    require(before.window.is_none() || after.window.is_some())?;
    require(
        before
            .last_success_at
            .is_none_or(|value| after.last_success_at.is_some_and(|next| next >= value)),
    )?;
    require(
        before == after
            || after.stage == ScheduleStage::Expired
            || after.stage == ScheduleStage::FetchPending
            || (before.stage == ScheduleStage::FetchPending
                && matches!(
                    after.stage,
                    ScheduleStage::Available | ScheduleStage::Unavailable
                )),
    )
}
fn remember_window(windows: &mut BTreeMap<(u64, u64), u64>, window: Option<&Window>) -> Result<()> {
    if let Some(window) = window {
        if let Some(retained) = windows.insert((window.start, window.end), window.selected_at) {
            require(retained == window.selected_at)?;
        }
    }
    Ok(())
}
fn prefix(binding: &Binding) -> String {
    if binding.cycle == 0 {
        format!(
            "acme-renewal-{}-{}-",
            binding.environment.as_str(),
            binding.leaf_der_sha256
        )
    } else {
        format!(
            "acme-renewal-{}-order-{:020}-{}-",
            binding.environment.as_str(),
            binding.cycle,
            binding.leaf_der_sha256
        )
    }
}
fn record_name(binding: &Binding, sequence: usize) -> String {
    format!("{}{sequence:06}.json", prefix(binding))
}

fn load(state: &LockedInspection, binding: &Binding) -> Result<Option<RenewalSchedule>> {
    load_history(state, binding, None).map(|(latest, _)| latest)
}

struct DueEvidence {
    observed_at: u64,
    effective_renew_at: u64,
}
fn load_history(
    state: &LockedInspection,
    binding: &Binding,
    wanted_receipt: Option<&str>,
) -> Result<(Option<RenewalSchedule>, Option<DueEvidence>)> {
    state.require_unchanged()?;
    let evidence = installer_host_fs::open_child(
        state.installation_directory(),
        "evidence",
        libc::O_RDONLY | libc::O_DIRECTORY,
        REFUSED,
    )?;
    let metadata = evidence.metadata().map_err(|_| REFUSED)?;
    require(
        metadata.is_dir()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o7777 == 0o700,
    )?;
    let prefix = prefix(binding);
    let mut names = BTreeSet::new();
    for entry in
        std::fs::read_dir(format!("/proc/self/fd/{}", evidence.as_raw_fd())).map_err(|_| REFUSED)?
    {
        let name = entry.map_err(|_| REFUSED)?.file_name();
        let name = name.to_str().ok_or(REFUSED)?;
        if name.starts_with(&prefix) {
            require(names.len() < MAX_RECORDS && name.len() <= 128)?;
            names.insert(name.to_owned());
        }
    }
    let mut prior: Option<RenewalSchedule> = None;
    let mut matched = None;
    for (sequence, name) in names.iter().enumerate() {
        require(*name == record_name(binding, sequence))?;
        let bytes = state.read_evidence(name)?;
        require(bytes.len() <= MAX_RECORD_BYTES)?;
        let record: Record =
            serde_json::from_value(installer_json::decode(&bytes).map_err(|_| REFUSED)?)
                .map_err(|_| REFUSED)?;
        require(
            record.schema == SCHEMA
                && record.sequence == sequence
                && record.binding == *binding
                && record.observed_at > 0,
        )?;
        record.state.validate(binding, record.observed_at)?;
        let mut windows = BTreeMap::new();
        if let Some(prior) = prior {
            require(
                record.previous_sha256.as_deref() == Some(&prior.digest)
                    && record.observed_at.saturating_add(120) >= prior.observed_at,
            )?;
            transition(&prior.state, &record.state)?;
            windows = prior.selected_windows;
        } else {
            require(
                record.previous_sha256.is_none()
                    && record.state == ScheduleState::initial(binding, record.observed_at),
            )?;
        }
        remember_window(&mut windows, record.state.window.as_ref())?;
        prior = Some(RenewalSchedule {
            binding: binding.clone(),
            state: record.state,
            sequence,
            observed_at: record.observed_at,
            digest: enrolment::hash(&bytes),
            selected_windows: windows,
        });
        if let Some(saved) = prior
            .as_ref()
            .filter(|saved| wanted_receipt == Some(saved.digest.as_str()))
        {
            require(matched.is_none())?;
            matched = Some(DueEvidence {
                observed_at: saved.observed_at,
                effective_renew_at: saved.effective_renew_at(),
            });
        }
    }
    state.require_unchanged()?;
    Ok((prior, matched))
}

/// Persist the actual-lifetime fallback for this exact completed enrolment.
/// No OpenBao or CA request occurs, including when the certificate is expired.
pub(crate) fn ensure_for_candidate(
    state: &mut LockedMaintenance,
    candidate: &AcmeCandidate,
) -> Result<RenewalSchedule> {
    let binding = Binding::from_candidate(state.inspection(), candidate)?;
    let observed = now()?;
    let mut schedule = if let Some(saved) = load(state.inspection(), &binding)? {
        saved
    } else {
        let initial = ScheduleState::initial(&binding, observed);
        initial.validate(&binding, observed)?;
        let record = Record {
            schema: SCHEMA.into(),
            sequence: 0,
            previous_sha256: None,
            observed_at: observed,
            binding: binding.clone(),
            state: initial.clone(),
        };
        let bytes = serde_json::to_vec(&record).map_err(|_| REFUSED)?;
        require(bytes.len() <= MAX_RECORD_BYTES)?;
        state.write_evidence_exclusive(&record_name(&binding, 0), &bytes)?;
        RenewalSchedule {
            binding,
            state: initial,
            sequence: 0,
            observed_at: observed,
            digest: enrolment::hash(&bytes),
            selected_windows: BTreeMap::new(),
        }
    };
    require(observed.saturating_add(120) >= schedule.observed_at)?;
    if observed >= schedule.binding.not_after && schedule.state.stage != ScheduleStage::Expired {
        let mut next = schedule.state.clone();
        next.stage = ScheduleStage::Expired;
        next.next_refresh_at = None;
        schedule.append(state, next, observed)?;
    }
    Ok(schedule)
}

/// Inspect a retained schedule without a CA request or certificate activation.
pub fn status(
    state: &LockedInspection,
    environment: AcmeEnvironment,
    leaf_sha256: &str,
) -> Result<Option<Value>> {
    let binding = Binding::from_enrolment(state, environment)?;
    require(binding.leaf_der_sha256 == leaf_sha256)?;
    load(state, &binding)?
        .map(|schedule| {
            let mut report = schedule.report()?;
            report["read_only"] = json!(true);
            Ok(report)
        })
        .transpose()
}

/// Read the exact candidate's retained scheduling decision without refreshing
/// ARI, creating a schedule, signing, or changing any installation state.
pub(crate) fn for_candidate(
    state: &LockedInspection,
    candidate: &AcmeCandidate,
) -> Result<Option<RenewalSchedule>> {
    let binding = Binding::from_candidate(state, candidate)?;
    load(state, &binding)
}

/// Verify the retained due decision at permit creation, even after newer
/// anonymous ARI reads have advanced the current scheduling receipt.
pub(crate) fn require_due_evidence(
    state: &LockedInspection,
    candidate: &AcmeCandidate,
    receipt_sha256: &str,
    observed_at: u64,
) -> Result<()> {
    require(
        receipt_sha256.len() == 64
            && receipt_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            && observed_at > 0
            && observed_at <= now()?.saturating_add(120),
    )?;
    let binding = Binding::from_candidate(state, candidate)?;
    let (_, recorded) = load_history(state, &binding, Some(receipt_sha256))?;
    let recorded = recorded.ok_or(REFUSED)?;
    require(observed_at >= recorded.observed_at && observed_at >= recorded.effective_renew_at)
}

/// Read the selected CA's anonymous ARI endpoint when its retained deadline is
/// due. No key or credentials are accepted by this API, and signing is disabled.
pub(crate) fn refresh_for_candidate(
    state: &mut LockedMaintenance,
    candidate: &AcmeCandidate,
) -> Result<RenewalSchedule> {
    require(tokio::runtime::Handle::try_current().is_err())?;
    let http = AcmeHttps::new(candidate.environment().directory_url()).map_err(|_| REFUSED)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| REFUSED)?;
    runtime.block_on(refresh_with_http(state, candidate, Box::new(http)))
}

/// Explicit initial-install ARI read under the existing writer's lock. This
/// preserves the Provisioning phase and is independent of credential refresh.
pub fn refresh_for_install(
    state: &mut InstallerState,
    candidate: &AcmeCandidate,
) -> Result<RenewalSchedule> {
    state.require_live_phase(Phase::Provisioning)?;
    require(tokio::runtime::Handle::try_current().is_err())?;
    state.with_maintenance(|state| refresh_for_candidate(state, candidate))
}

struct PublicReadSigner {
    public: Vec<u8>,
}
#[async_trait]
impl ExternalAccountSigner for PublicReadSigner {
    fn public_key(&self) -> &[u8] {
        &self.public
    }
    async fn sign(&self, _input: &[u8]) -> std::result::Result<[u8; 64], ProtocolError> {
        Err(ProtocolError::Str(
            "ARI scheduling has no account-signing authority",
        ))
    }
}

fn random_below(bound: u64) -> Result<u64> {
    require(bound > 0)?;
    let zone = u64::MAX - u64::MAX % bound;
    let random = rustls::crypto::aws_lc_rs::default_provider().secure_random;
    for _ in 0..32 {
        let mut bytes = [0u8; 8];
        random.fill(&mut bytes).map_err(|_| REFUSED)?;
        let value = u64::from_be_bytes(bytes);
        if value < zone {
            return Ok(value % bound);
        }
    }
    Err(REFUSED.into())
}
fn retry_delay(failures: u32) -> Result<u64> {
    let base = MIN_REFRESH
        .saturating_mul(1u64 << failures.saturating_sub(1).min(7))
        .min(LONG_ERROR_REFRESH);
    Ok(base + random_below(base / 4 + 1)?)
}

async fn refresh_with_http(
    state: &mut LockedMaintenance,
    candidate: &AcmeCandidate,
    http: Box<dyn HttpClient>,
) -> Result<RenewalSchedule> {
    let mut saved = ensure_for_candidate(state, candidate)?;
    let observed = now()?;
    if saved.state.stage == ScheduleStage::Expired
        || saved
            .state
            .next_refresh_at
            .is_none_or(|deadline| deadline > observed)
    {
        return Ok(saved);
    }
    let failures = saved.state.failures.saturating_add(1).min(MAX_FAILURES);
    let mut pending = saved.state.clone();
    pending.stage = ScheduleStage::FetchPending;
    pending.failures = failures;
    pending.failure = Some("fetch_interrupted_or_pending".into());
    pending.http_status = None;
    pending.last_attempt_at = Some(observed);
    pending.next_refresh_at = Some(
        observed
            .saturating_add(retry_delay(failures)?)
            .min(saved.binding.not_after),
    );
    saved.append(state, pending, observed)?;
    let result = tokio::time::timeout(WORK_DEADLINE, async {
        let signer = Arc::new(PublicReadSigner {
            public: saved.binding.account_public_sec1.clone(),
        });
        let prepared = Account::builder_with_http(http)
            .prepare_with_signer(signer, saved.binding.directory_url.clone())
            .await?;
        // Directory preparation and ARI are GET-only. Reading public renewal
        // information neither registers an account nor agrees to changed terms.
        let account = prepared.restore(saved.binding.account_url.clone());
        let identifier_text = saved
            .binding
            .certificate_identifier
            .as_ref()
            .ok_or(ProtocolError::Str("certificate identifier unavailable"))?;
        let identifier_json = serde_json::to_string(identifier_text)?;
        let identifier: CertificateIdentifier<'_> = serde_json::from_str(&identifier_json)?;
        // A slow directory fetch must not lead to a new ARI request after the
        // retained certificate expired during that fetch.
        if now().map_err(|_| ProtocolError::Str("renewal clock unavailable"))?
            >= saved.binding.not_after
        {
            return Err(ProtocolError::Str("renewal certificate expired"));
        }
        account.renewal_info(&identifier).await
    })
    .await;
    let result = match result {
        Ok(value) => value,
        Err(_) => Err(ProtocolError::Str("ACME request timed out")),
    };
    let observed = now()?;
    if observed >= saved.binding.not_after {
        let mut next = saved.state.clone();
        next.stage = ScheduleStage::Expired;
        next.next_refresh_at = None;
        saved.append(state, next, observed)?;
        return Ok(saved);
    }
    match result {
        Ok((info, retry)) => match selected_window(&saved, &info) {
            Ok(window) => {
                let mut next = saved.state.clone();
                next.stage = ScheduleStage::Available;
                next.window = Some(window);
                next.failures = 0;
                next.failure = None;
                next.http_status = Some(200);
                next.last_success_at = Some(observed);
                // Round up the maintained client's relative hint so seconds
                // conversion cannot send a request before the actual header.
                // A local polling cadence must not shorten the CA's lower
                // bound; a hint beyond expiry becomes expiry handling only.
                let delay = retry
                    .as_secs()
                    .saturating_add(u64::from(retry.subsec_nanos() > 0))
                    .max(MIN_REFRESH);
                next.next_refresh_at =
                    Some(observed.saturating_add(delay).min(saved.binding.not_after));
                saved.append(state, next, observed)?;
            }
            Err(_) => record_error(
                state,
                &mut saved,
                &ProtocolError::Str("invalid ARI window"),
                observed,
            )?,
        },
        Err(error) => record_error(state, &mut saved, &error, observed)?,
    }
    Ok(saved)
}

fn selected_window(saved: &RenewalSchedule, info: &RenewalInfo) -> Result<Window> {
    let start: u64 = info
        .suggested_window
        .start
        .unix_timestamp()
        .try_into()
        .map_err(|_| REFUSED)?;
    let end: u64 = info
        .suggested_window
        .end
        .unix_timestamp()
        .try_into()
        .map_err(|_| REFUSED)?;
    require(start < end && end <= saved.binding.not_after)?;
    let selected_at = match saved.selected_windows.get(&(start, end)) {
        Some(value) => *value,
        None => start
            .checked_add(random_below(end - start)?)
            .ok_or(REFUSED)?,
    };
    Ok(Window {
        start,
        end,
        selected_at,
    })
}

fn record_error(
    state: &mut LockedMaintenance,
    saved: &mut RenewalSchedule,
    error: &ProtocolError,
    observed: u64,
) -> Result<()> {
    let (category, temporary, hints) = match error {
        ProtocolError::Api(problem) => {
            let status = problem.response_metadata.map(|value| value.status);
            (
                if status == Some(429) {
                    "rate_limited"
                } else if status.is_some_and(|value| (500..600).contains(&value)) {
                    "temporary"
                } else {
                    "long_term"
                },
                status.is_some_and(|value| (500..600).contains(&value)),
                problem.response_metadata,
            )
        }
        ProtocolError::Unsupported(_) => ("unsupported", false, None),
        ProtocolError::Json(_) => ("invalid_response", false, None),
        ProtocolError::Str("missing Retry-After header" | "invalid ARI window") => {
            ("invalid_response", false, None)
        }
        _ => ("temporary", true, None),
    };
    let mut next = saved.state.clone();
    next.stage = ScheduleStage::Unavailable;
    next.failure = Some(category.into());
    next.http_status = hints.map(|value| value.status);
    let deadline = if temporary && next.failures < MAX_FAILURES {
        next.next_refresh_at
            .ok_or(REFUSED)?
            .max(observed.saturating_add(MIN_REFRESH))
    } else {
        observed.saturating_add(LONG_ERROR_REFRESH)
    };
    let server = hints
        .and_then(|value| value.retry_after)
        .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |value| {
            value
                .as_secs()
                .saturating_add(u64::from(value.subsec_nanos() > 0))
        });
    next.next_refresh_at = Some(deadline.max(server).min(saved.binding.not_after));
    saved.append(state, next, observed)
}

#[cfg(test)]
#[path = "installer_acme_renewal_tests.rs"]
mod tests;
