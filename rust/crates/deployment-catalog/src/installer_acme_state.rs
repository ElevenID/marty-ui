//! Installation-owned, append-only ACME enrolment receipts.
//! The adapter has no persistence and this ledger never advances installer phase.
#![cfg(target_os = "linux")]

use crate::{
    installer_acme_configuration::{AcmeEnvironment, AcmeParameters, BoundAcmeConfiguration},
    installer_host_fs, installer_json, installer_release,
    installer_state::{LockedInspection, LockedMaintenance},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
};

pub(crate) type Result<T> = std::result::Result<T, String>;
pub(crate) const REFUSED: &str = "ACME enrolment refused; retain installation-scoped account, order, CSR and challenge receipts for reconciliation. No certificate activation was attempted";
const SCHEMA: &str = "elevenid.installer-acme-enrolment/v1";
const MAX_RECORDS: usize = 512;
const MAX_RECORD_BYTES: usize = 128 * 1024;
// Ordinary work needs at most eight phase writes in one invocation. Keep a
// separate reserve for completion, known-order terminal proof and withdrawal.
const COMPLETION_RESERVE: usize = 64;
const MAX_ORDINARY_WRITES: usize = 8;

#[path = "installer_acme_polling.rs"]
pub(crate) mod polling;

pub(crate) fn require(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}
pub(crate) fn hash(bytes: &[u8]) -> String {
    installer_release::sha256(bytes)
}
pub(crate) fn initial_cycle(value: &u64) -> bool {
    *value == 0
}
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// A subsequent order starts with a previously admitted account and exact CSR.
/// The generation owner supplies the unforgeable in-process permit; these
/// public fields preserve that decision across process interruption.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RenewalBinding {
    pub permit_sha256: String,
    pub configuration_sha256: String,
    pub reason: IssuanceReason,
    pub prior_cycle: u64,
    pub prior_enrolment_receipt_sha256: String,
    pub account_url: String,
    pub created_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum IssuanceReason {
    SelectedGenerationDue {
        generation_binding_sha256: String,
        schedule_sha256: String,
    },
    InitialCandidateExpired {
        host_intent_sha256: String,
        host_prepared_sha256: String,
    },
}
impl IssuanceReason {
    fn validate(&self) -> Result<()> {
        let hashes = match self {
            Self::SelectedGenerationDue {
                generation_binding_sha256,
                schedule_sha256,
            } => [generation_binding_sha256, schedule_sha256],
            Self::InitialCandidateExpired {
                host_intent_sha256,
                host_prepared_sha256,
            } => [host_intent_sha256, host_prepared_sha256],
        };
        require(hashes.into_iter().all(|value| digest(value)))
    }
}

/// Public material only. Equality with a freshly bound configuration and
/// custody observation is required each time the worker is entered.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Binding {
    pub installation_id: uuid::Uuid,
    pub environment: AcmeEnvironment,
    #[serde(default, skip_serializing_if = "initial_cycle")]
    pub cycle: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renewal: Option<RenewalBinding>,
    pub configuration: Value,
    pub release: Value,
    pub runtime: Value,
    pub account_key: Value,
    pub ingress_key_name: String,
    pub ingress_key_version: u64,
    pub ingress_spki_base64: String,
    pub csr_pem: String,
    pub csr_der_base64: String,
    pub csr_sha256: String,
    pub csr_metadata: Value,
    pub staging_roots_sha256: Option<String>,
}
impl Binding {
    pub fn configuration(&self, state: &LockedInspection) -> Result<BoundAcmeConfiguration> {
        let parameters = AcmeParameters::parse(
            &serde_json::to_vec(&self.configuration["parameters"]).map_err(|_| REFUSED)?,
        )?;
        let configured = BoundAcmeConfiguration::bind(state, parameters)?;
        require(
            self.installation_id == state.journal().installation_id()
                && self.environment == configured.parameters().environment()
                && self.configuration == serde_json::to_value(&configured).map_err(|_| REFUSED)?
                && self.release
                    == serde_json::to_value(state.journal().identity()).map_err(|_| REFUSED)?
                && self.runtime
                    == serde_json::to_value(state.journal().runtime()).map_err(|_| REFUSED)?
                && self.ingress_key_name
                    == crate::installer_ingress_provision::resource_name(
                        &self.installation_id.to_string(),
                    )?
                && self.ingress_key_version == 1
                && self.csr_pem.len() <= 16 * 1024
                && !self.csr_pem.contains("PRIVATE KEY")
                && self.csr_metadata["installation_id"] == self.installation_id.to_string()
                && self.csr_metadata["csr_der_sha256"] == self.csr_sha256
                && self.csr_metadata["csr_signature_verified"] == true
                && self.csr_metadata["activation_performed"] == false,
        )?;
        let der = STANDARD.decode(&self.csr_der_base64).map_err(|_| REFUSED)?;
        require(!der.is_empty() && der.len() <= 16 * 1024 && hash(&der) == self.csr_sha256)?;
        require(STANDARD.encode(&der) == self.csr_der_base64)?;
        let spki = STANDARD
            .decode(&self.ingress_spki_base64)
            .map_err(|_| REFUSED)?;
        require(
            !spki.is_empty()
                && spki.len() <= 1024
                && STANDARD.encode(&spki) == self.ingress_spki_base64,
        )?;
        require(
            self.staging_roots_sha256.is_some() == (self.environment == AcmeEnvironment::Staging),
        )?;
        match (&self.renewal, self.cycle) {
            (None, 0) => {}
            (Some(renewal), cycle) if cycle > 0 => {
                require(
                    renewal.prior_cycle < cycle
                        && renewal.created_at > 0
                        && [
                            &renewal.permit_sha256,
                            &renewal.configuration_sha256,
                            &renewal.prior_enrolment_receipt_sha256,
                        ]
                        .into_iter()
                        .all(|value| digest(value))
                        && renewal.configuration_sha256
                            == hash(&serde_json::to_vec(&configured).map_err(|_| REFUSED)?),
                )?;
                renewal.reason.validate()?;
                same_origin_url(
                    configured.parameters().directory_url(),
                    &renewal.account_url,
                )?;
            }
            _ => return Err(REFUSED.into()),
        }
        Ok(configured)
    }
    pub fn digest(&self) -> Result<String> {
        Ok(hash(&serde_json::to_vec(self).map_err(|_| REFUSED)?))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Stage {
    Prepared,
    AccountPending,
    AccountAbsent,
    AccountBound,
    OrderPending,
    OrderRejected,
    OrderBound,
    PublicationPending,
    ChallengesPublished,
    ChallengeReadyPending,
    AwaitingOrder,
    FinalizePending,
    CertificatePending,
    CertificateAdmitted,
    Complete,
    Terminal,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OrderRecord {
    pub url: String,
    pub finalize_url: String,
    pub authorization_urls: Vec<String>,
    pub expires_at: u64,
    pub identifiers: Value,
    pub profile: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuthorizationRecord {
    pub identifier: String,
    pub url: String,
    pub expires_at: u64,
    pub status: String,
    pub challenge_url: Option<String>,
    pub token: Option<String>,
    pub key_authorization: Option<String>,
    pub ready_observed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Projection {
    pub snapshot: String,
    pub sha256: String,
    pub previous_sha256: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CertificateRecord {
    pub fullchain_pem: String,
    pub metadata: Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Retry {
    pub failures: u32,
    pub next_attempt_at: u64,
    pub category: String,
    pub http_status: Option<u16>,
}

/// Only these authenticated, known-order outcomes permit another recurring
/// attempt. An exhausted transport retry budget is not an order-status proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TerminalReason {
    OrderInvalid,
    OrderExpired,
    AuthorizationInvalid,
    AuthorizationExpired,
}
impl TerminalReason {
    pub fn from_code(code: &str) -> Option<Self> {
        match code {
            "order_invalid" => Some(Self::OrderInvalid),
            "order_expired" => Some(Self::OrderExpired),
            "authorization_invalid" => Some(Self::AuthorizationInvalid),
            "authorization_expired" => Some(Self::AuthorizationExpired),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OrderInvalid => "order_invalid",
            Self::OrderExpired => "order_expired",
            Self::AuthorizationInvalid => "authorization_invalid",
            Self::AuthorizationExpired => "authorization_expired",
        }
    }
}

pub(crate) fn terminal_cooldown(attempt: u64) -> u64 {
    300u64
        .saturating_mul(1u64 << attempt.saturating_sub(1).min(7))
        .min(6 * 3600)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TerminalRetry {
    pub reason: TerminalReason,
    pub observed_at: u64,
    pub attempt: u64,
    /// Includes the latest CA hint and any longer retained retry/poll deadline.
    pub retry_not_before: Option<u64>,
    pub eligible_at: u64,
    /// Recorded only after actual withdrawal publication and readback. A later
    /// successor may then publish a different projection without erasing proof.
    pub withdrawal_confirmed_at: Option<u64>,
    pub withdrawn_projection_sha256: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct State {
    pub stage: Stage,
    pub account_url: Option<String>,
    pub order: Option<OrderRecord>,
    pub authorizations: Vec<AuthorizationRecord>,
    pub projection: Option<Projection>,
    pub pending_challenge: Option<String>,
    pub certificate: Option<CertificateRecord>,
    pub retry: Option<Retry>,
    pub next_poll_at: Option<u64>,
    pub failure: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_retry: Option<TerminalRetry>,
}
impl State {
    pub fn prepared() -> Self {
        Self {
            stage: Stage::Prepared,
            account_url: None,
            order: None,
            authorizations: Vec::new(),
            projection: None,
            pending_challenge: None,
            certificate: None,
            retry: None,
            next_poll_at: None,
            failure: None,
            terminal_retry: None,
        }
    }
    fn initial(binding: &Binding) -> Self {
        let mut initial = Self::prepared();
        if let Some(renewal) = &binding.renewal {
            initial.stage = Stage::AccountBound;
            initial.account_url = Some(renewal.account_url.clone());
        }
        initial
    }
    fn validate(&self, binding: &Binding) -> Result<()> {
        use marty_selfhost_identity::origin::PublicOrigin;
        let configured: Value = binding.configuration.clone();
        let directory = configured["parameters"]["directory_url"]
            .as_str()
            .ok_or(REFUSED)?;
        let canonical =
            PublicOrigin::parse(configured["canonical_origin"].as_str().ok_or(REFUSED)?)
                .map_err(|_| REFUSED)?;
        let dns = canonical.dns_name().ok_or(REFUSED)?;
        let mut expected_order_identifiers = vec![json!({"type":"dns","value":dns})];
        let mut expected_authorization_identifiers = BTreeSet::from([dns.to_owned()]);
        if let Some(alias) = configured["public_entry_origin"].as_str() {
            let ip = PublicOrigin::parse(alias)
                .map_err(|_| REFUSED)?
                .ip_address()
                .ok_or(REFUSED)?;
            expected_order_identifiers.push(json!({"type":"ip","value":ip.to_string()}));
            expected_authorization_identifiers.insert(ip.to_string());
        }
        if let Some(account) = &self.account_url {
            same_origin_url(directory, account)?;
        }
        if let Some(renewal) = &binding.renewal {
            require(
                self.account_url.as_deref() == Some(renewal.account_url.as_str())
                    && !matches!(
                        self.stage,
                        Stage::Prepared | Stage::AccountPending | Stage::AccountAbsent
                    ),
            )?;
        }
        if let Some(order) = &self.order {
            require(self.account_url.is_some())?;
            same_origin_url(directory, &order.url)?;
            same_origin_url(directory, &order.finalize_url)?;
            require(
                order.identifiers == Value::Array(expected_order_identifiers)
                    && order.authorization_urls.len() == expected_authorization_identifiers.len()
                    && order
                        .authorization_urls
                        .iter()
                        .collect::<BTreeSet<_>>()
                        .len()
                        == order.authorization_urls.len()
                    && order.profile == "shortlived"
                    && order.expires_at > 0,
            )?;
            for url in &order.authorization_urls {
                same_origin_url(directory, url)?;
            }
        }
        require(self.authorizations.len() <= 2)?;
        let mut urls = BTreeSet::new();
        let mut identifiers = BTreeSet::new();
        for authorization in &self.authorizations {
            require(
                urls.insert(&authorization.url) && identifiers.insert(&authorization.identifier),
            )?;
            same_origin_url(directory, &authorization.url)?;
            require(
                self.order
                    .as_ref()
                    .is_some_and(|order| order.authorization_urls.contains(&authorization.url)),
            )?;
            require(["pending", "valid", "processing"].contains(&authorization.status.as_str()))?;
            require(authorization.expires_at > 0)?;
            if let Some(url) = &authorization.challenge_url {
                same_origin_url(directory, url)?;
            }
            require(
                authorization.challenge_url.is_some() == authorization.token.is_some()
                    && authorization.token.is_some() == authorization.key_authorization.is_some(),
            )?;
        }
        if !self.authorizations.is_empty() {
            require(
                identifiers.into_iter().cloned().collect::<BTreeSet<_>>()
                    == expected_authorization_identifiers,
            )?;
        }
        if let Some(projection) = &self.projection {
            use marty_selfhost_identity::acme_http01::{AllowedIdentifiers, Snapshot};
            require(hash(projection.snapshot.as_bytes()) == projection.sha256)?;
            let snapshot: Snapshot = serde_json::from_value(
                installer_json::decode(projection.snapshot.as_bytes()).map_err(|_| REFUSED)?,
            )
            .map_err(|_| REFUSED)?;
            let allowed = AllowedIdentifiers::from_origins(
                configured["canonical_origin"].as_str().ok_or(REFUSED)?,
                configured["public_entry_origin"].as_str(),
            )
            .map_err(|_| REFUSED)?;
            Snapshot::parse(
                projection.snapshot.as_bytes(),
                &allowed,
                snapshot.created_at,
            )
            .map_err(|_| REFUSED)?;
            for challenge in snapshot.challenges {
                require(self.authorizations.iter().any(|authorization| {
                    authorization.identifier == challenge.identifier
                        && authorization.token.as_deref() == Some(challenge.token.as_str())
                        && authorization.key_authorization.as_deref()
                            == Some(challenge.key_authorization.as_str())
                }))?;
            }
        }
        if let Some(pending) = &self.pending_challenge {
            require(
                self.authorizations
                    .iter()
                    .any(|authorization| authorization.url == *pending),
            )?;
        }
        if let Some(certificate) = &self.certificate {
            require(
                self.order.is_some()
                    && !certificate.fullchain_pem.is_empty()
                    && certificate.fullchain_pem.len() <= 64 * 1024
                    && !certificate.fullchain_pem.contains("PRIVATE KEY")
                    && certificate.metadata["installation_id"]
                        == binding.installation_id.to_string()
                    && certificate.metadata["fullchain_pem_sha256"]
                        == hash(certificate.fullchain_pem.as_bytes())
                    && certificate.metadata["activation_performed"] == false
                    && certificate.metadata["installation_ready"] == false
                    && certificate.metadata["trust_class"]
                        == if binding.environment == AcmeEnvironment::Production {
                            "production_public"
                        } else {
                            "staging_test"
                        },
            )?;
        }
        if let Some(retry) = &self.retry {
            require(
                retry.failures > 0
                    && retry.failures <= 32
                    && retry.next_attempt_at > 0
                    && ["rate_limited", "temporary", "bad_nonce"]
                        .contains(&retry.category.as_str()),
            )?;
        }
        if let Some(failure) = &self.failure {
            require(
                [
                    "order_outcome_unknown",
                    "account_unavailable",
                    "order_invalid",
                    "order_expired",
                    "authorization_invalid",
                    "authorization_expired",
                    "retry_limit",
                    "certificate_refused",
                ]
                .contains(&failure.as_str()),
            )?;
        }
        if let Some(terminal) = &self.terminal_retry {
            require(
                self.stage == Stage::Terminal
                    && binding.cycle > 0
                    && binding.renewal.as_ref().is_some_and(|renewal| {
                        matches!(renewal.reason, IssuanceReason::SelectedGenerationDue { .. })
                    })
                    && self.order.is_some()
                    && self.certificate.is_none()
                    && self.failure.as_deref() == Some(terminal.reason.as_str())
                    && self.retry.is_none()
                    && self.next_poll_at.is_none()
                    && self.pending_challenge.is_none()
                    && terminal.observed_at > 0
                    && terminal.attempt > 0
                    && terminal.retry_not_before.is_none_or(|value| value > 0)
                    && terminal.eligible_at
                        == terminal
                            .observed_at
                            .checked_add(terminal_cooldown(terminal.attempt))
                            .ok_or(REFUSED)?
                            .max(terminal.retry_not_before.unwrap_or(0)),
            )?;
            if let Some(confirmed) = terminal.withdrawal_confirmed_at {
                require(
                    confirmed >= terminal.observed_at
                        && terminal
                            .withdrawn_projection_sha256
                            .as_deref()
                            .is_none_or(digest),
                )?;
                if let Some(projection) = &self.projection {
                    require(
                        terminal.withdrawn_projection_sha256.as_deref()
                            == Some(projection.sha256.as_str()),
                    )?;
                    let snapshot: marty_selfhost_identity::acme_http01::Snapshot =
                        serde_json::from_slice(projection.snapshot.as_bytes())
                            .map_err(|_| REFUSED)?;
                    require(snapshot.challenges.is_empty())?;
                }
            } else {
                require(terminal.withdrawn_projection_sha256.is_none())?;
            }
        }
        match self.stage {
            Stage::Prepared | Stage::AccountPending | Stage::AccountAbsent => {
                require(self.account_url.is_none() && self.order.is_none())?
            }
            Stage::AccountBound | Stage::OrderPending | Stage::OrderRejected => {
                require(self.account_url.is_some() && self.order.is_none())?
            }
            Stage::Terminal => require(self.failure.is_some())?,
            _ => require(self.account_url.is_some() && self.order.is_some())?,
        }
        if matches!(
            self.stage,
            Stage::PublicationPending | Stage::ChallengesPublished | Stage::ChallengeReadyPending
        ) {
            require(self.projection.is_some())?;
        }
        if self.stage == Stage::ChallengeReadyPending {
            require(self.pending_challenge.is_some())?;
        }
        if matches!(self.stage, Stage::CertificateAdmitted | Stage::Complete) {
            require(self.certificate.is_some())?;
        }
        Ok(())
    }
}

pub(crate) fn same_origin_url(directory: &str, value: &str) -> Result<()> {
    require(value.len() <= 2048 && value.is_ascii())?;
    let base = url::Url::parse(directory).map_err(|_| REFUSED)?;
    let value = url::Url::parse(value).map_err(|_| REFUSED)?;
    require(
        value.scheme() == "https"
            && value.origin() == base.origin()
            && value.username().is_empty()
            && value.password().is_none()
            && value.fragment().is_none(),
    )
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: String,
    sequence: usize,
    previous_sha256: Option<String>,
    binding_sha256: String,
    observed_at: u64,
    binding: Binding,
    state: State,
}

pub(crate) struct Ledger {
    pub binding: Binding,
    pub state: State,
    pub observed_at: u64,
    pub sequence: usize,
    pub digest: String,
    history: Vec<polling::Anchor>,
    polling: polling::Observed,
}

fn prefix(environment: AcmeEnvironment, cycle: u64) -> String {
    if cycle == 0 {
        format!("acme-{}-", environment.as_str())
    } else {
        format!("acme-{}-order-{cycle:020}-", environment.as_str())
    }
}
fn record_name(environment: AcmeEnvironment, cycle: u64, sequence: usize) -> String {
    format!("{}{sequence:06}.json", prefix(environment, cycle))
}

fn names(
    state: &LockedInspection,
    environment: AcmeEnvironment,
    cycle: u64,
) -> Result<Vec<String>> {
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
    let prefix = prefix(environment, cycle);
    let mut result = BTreeSet::new();
    for entry in
        std::fs::read_dir(format!("/proc/self/fd/{}", evidence.as_raw_fd())).map_err(|_| REFUSED)?
    {
        let name = entry.map_err(|_| REFUSED)?.file_name();
        let name = name.to_str().ok_or(REFUSED)?;
        // Custody/configuration receipts have separate nonnumeric suffixes.
        if name.strip_prefix(&prefix).is_some_and(|suffix| {
            cycle > 0 || suffix.as_bytes().first().is_some_and(u8::is_ascii_digit)
        }) {
            require(result.len() < MAX_RECORDS && name.len() <= 128)?;
            result.insert(name.to_owned());
        }
    }
    state.require_unchanged()?;
    Ok(result.into_iter().collect())
}

fn require_terminal_time(state: &State, observed_at: u64) -> Result<()> {
    if let Some(terminal) = &state.terminal_retry {
        require(
            terminal.observed_at <= observed_at
                && terminal
                    .withdrawal_confirmed_at
                    .is_none_or(|value| value <= observed_at),
        )?;
    }
    Ok(())
}

fn require_terminal_event_time(before: &State, after: &State, observed_at: u64) -> Result<()> {
    match (&before.terminal_retry, &after.terminal_retry) {
        (None, Some(terminal)) => require(
            terminal.observed_at == observed_at && terminal.withdrawal_confirmed_at.is_none(),
        )?,
        (Some(previous), Some(terminal))
            if previous.withdrawal_confirmed_at.is_none()
                && terminal.withdrawal_confirmed_at.is_some() =>
        {
            require(terminal.withdrawal_confirmed_at == Some(observed_at))?;
        }
        _ => {}
    }
    Ok(())
}

fn transition(before: &State, after: &State) -> Result<()> {
    if before.account_url.is_some() {
        require(before.account_url == after.account_url)?;
    }
    if before.order.is_some() {
        require(before.order == after.order)?;
    }
    if before.certificate.is_some() {
        require(before.certificate == after.certificate)?;
    }
    if before.stage == Stage::Terminal {
        require(before.failure == after.failure)?;
    }
    if let Some(previous) = &before.terminal_retry {
        let current = after.terminal_retry.as_ref().ok_or(REFUSED)?;
        let mut comparable = current.clone();
        comparable.withdrawal_confirmed_at = previous.withdrawal_confirmed_at;
        comparable.withdrawn_projection_sha256 = previous.withdrawn_projection_sha256.clone();
        require(comparable == *previous)?;
        if previous.withdrawal_confirmed_at.is_some() {
            require(current == previous)?;
        }
    } else if after.terminal_retry.is_some() {
        // A legacy terminal failure cannot acquire an inferred retry proof.
        require(before.stage != Stage::Terminal)?;
    }
    let allowed = before.stage == after.stage
        || after.stage == Stage::Terminal
        || matches!(
            (before.stage, after.stage),
            (Stage::Prepared, Stage::AccountPending)
                | (Stage::AccountPending, Stage::AccountAbsent)
                | (Stage::AccountAbsent, Stage::AccountPending)
                | (Stage::AccountPending, Stage::AccountBound)
                | (Stage::AccountBound, Stage::OrderPending)
                | (Stage::OrderPending, Stage::OrderBound)
                | (Stage::OrderPending, Stage::OrderRejected)
                | (Stage::OrderRejected, Stage::OrderPending)
                | (
                    Stage::OrderBound
                        | Stage::AwaitingOrder
                        | Stage::ChallengeReadyPending
                        | Stage::ChallengesPublished,
                    Stage::PublicationPending
                )
                | (Stage::PublicationPending, Stage::ChallengesPublished)
                | (
                    Stage::ChallengesPublished
                        | Stage::AwaitingOrder
                        | Stage::ChallengeReadyPending,
                    Stage::ChallengeReadyPending
                )
                | (
                    Stage::ChallengeReadyPending | Stage::ChallengesPublished | Stage::OrderBound,
                    Stage::AwaitingOrder
                )
                | (
                    Stage::OrderBound
                        | Stage::AwaitingOrder
                        | Stage::ChallengeReadyPending
                        | Stage::ChallengesPublished,
                    Stage::FinalizePending
                )
                | (
                    Stage::OrderBound
                        | Stage::AwaitingOrder
                        | Stage::ChallengeReadyPending
                        | Stage::ChallengesPublished
                        | Stage::FinalizePending,
                    Stage::CertificatePending
                )
                | (Stage::CertificatePending, Stage::CertificateAdmitted)
                | (Stage::CertificateAdmitted, Stage::Complete)
        );
    require(allowed && (before.stage != Stage::Complete || before == after))
}

impl Ledger {
    /// Enumerate explicitly recorded streams; there is no lifetime cycle cap.
    /// Every returned stream is still parsed and hash-checked by load_cycle.
    pub fn cycles(state: &LockedInspection, environment: AcmeEnvironment) -> Result<Vec<u64>> {
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
        let prefix = format!("acme-{}-order-", environment.as_str());
        let mut cycles = BTreeSet::from([0]);
        for entry in std::fs::read_dir(format!("/proc/self/fd/{}", evidence.as_raw_fd()))
            .map_err(|_| REFUSED)?
        {
            let name = entry.map_err(|_| REFUSED)?.file_name();
            let name = name.to_str().ok_or(REFUSED)?;
            if let Some(suffix) = name.strip_prefix(&prefix) {
                let (cycle, sequence) = suffix.split_once('-').ok_or(REFUSED)?;
                require(cycle.len() == 20 && cycle.bytes().all(|byte| byte.is_ascii_digit()))?;
                let cycle: u64 = cycle.parse().map_err(|_| REFUSED)?;
                let sequence = sequence.strip_suffix(".json").ok_or(REFUSED)?;
                require(
                    cycle > 0
                        && sequence.len() == 6
                        && sequence.bytes().all(|byte| byte.is_ascii_digit()),
                )?;
                cycles.insert(cycle);
            }
        }
        state.require_unchanged()?;
        Ok(cycles.into_iter().collect())
    }
    pub fn load(state: &LockedInspection, environment: AcmeEnvironment) -> Result<Option<Self>> {
        Self::load_cycle(state, environment, 0)
    }
    pub fn load_cycle(
        state: &LockedInspection,
        environment: AcmeEnvironment,
        cycle: u64,
    ) -> Result<Option<Self>> {
        let names = names(state, environment, cycle)?;
        let mut previous: Option<Self> = None;
        let mut history = Vec::new();
        for (sequence, name) in names.iter().enumerate() {
            require(*name == record_name(environment, cycle, sequence))?;
            let bytes = state.read_evidence(name)?;
            require(bytes.len() <= MAX_RECORD_BYTES)?;
            let record: Record =
                serde_json::from_value(installer_json::decode(&bytes).map_err(|_| REFUSED)?)
                    .map_err(|_| REFUSED)?;
            require(
                record.schema == SCHEMA
                    && record.sequence == sequence
                    && record.binding.environment == environment
                    && record.binding.cycle == cycle
                    && record.observed_at > 0
                    && record.binding_sha256 == record.binding.digest()?,
            )?;
            record.binding.configuration(state)?;
            record.state.validate(&record.binding)?;
            require_terminal_time(&record.state, record.observed_at)?;
            if let Some(prior) = &previous {
                require(
                    record.previous_sha256.as_deref() == Some(prior.digest.as_str())
                        && record.binding == prior.binding,
                )?;
                transition(&prior.state, &record.state)?;
                require_terminal_event_time(&prior.state, &record.state, record.observed_at)?;
            } else {
                require(
                    record.previous_sha256.is_none()
                        && record.state == State::initial(&record.binding),
                )?;
            }
            let digest = hash(&bytes);
            history.push(polling::Anchor::new(
                digest.clone(),
                &record.state,
                record.observed_at,
            )?);
            previous = Some(Self {
                binding: record.binding,
                state: record.state,
                observed_at: record.observed_at,
                sequence,
                digest,
                history: Vec::new(),
                polling: polling::Observed::default(),
            });
        }
        if let Some(saved) = &mut previous {
            saved.history = history;
            saved.polling = polling::restore(state, saved)?;
        } else {
            polling::require_absent(state, environment, cycle)?;
        }
        Ok(previous)
    }
    pub fn begin(state: &mut LockedMaintenance, binding: Binding, now: u64) -> Result<Self> {
        require(
            Self::load_cycle(state.inspection(), binding.environment, binding.cycle)?.is_none(),
        )?;
        binding.configuration(state.inspection())?;
        let initial = State::initial(&binding);
        initial.validate(&binding)?;
        let record = Record {
            schema: SCHEMA.into(),
            sequence: 0,
            previous_sha256: None,
            binding_sha256: binding.digest()?,
            observed_at: now,
            binding: binding.clone(),
            state: initial.clone(),
        };
        let bytes = serde_json::to_vec(&record).map_err(|_| REFUSED)?;
        require(now > 0 && bytes.len() <= MAX_RECORD_BYTES)?;
        state.write_evidence_exclusive(
            &record_name(binding.environment, binding.cycle, 0),
            &bytes,
        )?;
        let digest = hash(&bytes);
        let history = vec![polling::Anchor::new(digest.clone(), &initial, now)?];
        Ok(Self {
            binding,
            state: initial,
            observed_at: now,
            sequence: 0,
            digest,
            history,
            polling: polling::Observed::default(),
        })
    }
    pub fn append(&mut self, state: &mut LockedMaintenance, next: State, now: u64) -> Result<()> {
        require(self.sequence + 1 < MAX_RECORDS && now > 0)?;
        state.require_unchanged()?;
        next.validate(&self.binding)?;
        require_terminal_time(&next, now)?;
        transition(&self.state, &next)?;
        require_terminal_event_time(&self.state, &next, now)?;
        let record = Record {
            schema: SCHEMA.into(),
            sequence: self.sequence + 1,
            previous_sha256: Some(self.digest.clone()),
            binding_sha256: self.binding.digest()?,
            observed_at: now,
            binding: self.binding.clone(),
            state: next.clone(),
        };
        let bytes = serde_json::to_vec(&record).map_err(|_| REFUSED)?;
        require(bytes.len() <= MAX_RECORD_BYTES)?;
        state.write_evidence_exclusive(
            &record_name(
                self.binding.environment,
                self.binding.cycle,
                record.sequence,
            ),
            &bytes,
        )?;
        self.state = next;
        self.sequence = record.sequence;
        self.observed_at = now;
        self.digest = hash(&bytes);
        self.history
            .push(polling::Anchor::new(self.digest.clone(), &self.state, now)?);
        self.polling.refresh(&self.history);
        Ok(())
    }
    pub(crate) fn retry(&self) -> Option<&Retry> {
        self.polling.retry(&self.state)
    }
    pub(crate) fn next_poll_at(&self) -> Option<u64> {
        self.polling.next_poll_at(&self.state)
    }
    pub(crate) fn timing_observed_at(&self) -> u64 {
        self.polling.observed_at(self.observed_at)
    }
    pub(crate) fn ordinary_phase_available(&self) -> bool {
        self.sequence + 1 + MAX_ORDINARY_WRITES <= MAX_RECORDS - COMPLETION_RESERVE
    }
    pub fn report(&self) -> Value {
        json!({"environment":self.binding.environment,"cycle":self.binding.cycle,"sequence":self.sequence,"stage":self.state.stage,
            "account_url_recorded":self.state.account_url.is_some(),"order_url_recorded":self.state.order.is_some(),
            "order_outcome_unknown":self.state.stage==Stage::OrderPending,"candidate_admitted":self.state.certificate.is_some(),
            "next_attempt_at":self.retry().map(|retry|retry.next_attempt_at),"failure":self.state.failure,
            "next_poll_at":self.next_poll_at(),"candidate_currently_valid":"not_assessed",
            "ordinary_phase_budget_reserved":!self.ordinary_phase_available(),
            "activation_performed":false,"installation_ready":false,"automatic_renewal":false,
            "public_reachability":"not_assessed","boot_recovery_qualification":"not_assessed"})
    }
}
