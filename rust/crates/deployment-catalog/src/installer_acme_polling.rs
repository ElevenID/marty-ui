//! Bounded timing only. This file can defer a known phase but cannot supply any
//! account/order/CSR/challenge/certificate or terminal authority.
use super::*;

#[path = "installer_acme_polling_store.rs"]
mod store;

const POLLING_SCHEMA: &str = "elevenid.installer-acme-polling/v1";
const MAX_CHECKPOINT_BYTES: usize = 4096;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Required {
    schema: String,
    installation_id: uuid::Uuid,
    environment: AcmeEnvironment,
    cycle: u64,
    binding_sha256: String,
    anchor_sequence: usize,
    anchor_sha256: String,
}
fn required_name(environment: AcmeEnvironment, cycle: u64) -> String {
    format!(
        "acme-poll-required-{}-{cycle:020}.json",
        environment.as_str()
    )
}
fn require_marker(view: &LockedInspection, saved: &Ledger) -> Result<bool> {
    let Some(bytes) = view.diagnostic_record(
        &required_name(saved.binding.environment, saved.binding.cycle),
        true,
    )?
    else {
        return Ok(false);
    };
    require(bytes.len() <= MAX_CHECKPOINT_BYTES)?;
    let marker: Required =
        serde_json::from_value(installer_json::decode(&bytes).map_err(|_| REFUSED)?)
            .map_err(|_| REFUSED)?;
    require(
        marker.schema == "elevenid.installer-acme-polling-required/v1"
            && marker.installation_id == saved.binding.installation_id
            && marker.environment == saved.binding.environment
            && marker.cycle == saved.binding.cycle
            && marker.binding_sha256 == saved.binding.digest()?
            && saved
                .history
                .get(marker.anchor_sequence)
                .is_some_and(|anchor| anchor.digest == marker.anchor_sha256),
    )?;
    Ok(true)
}

#[derive(Clone)]
pub(super) struct Anchor {
    digest: String,
    authority_sha256: String,
    observed_at: u64,
    legacy_deadline: u64,
}
impl Anchor {
    pub(super) fn new(digest: String, state: &State, observed_at: u64) -> Result<Self> {
        let mut authority = state.clone();
        authority.retry = None;
        authority.next_poll_at = None;
        Ok(Self {
            digest,
            authority_sha256: hash(&serde_json::to_vec(&authority).map_err(|_| REFUSED)?),
            observed_at,
            legacy_deadline: state
                .retry
                .as_ref()
                .map_or(0, |retry| retry.next_attempt_at)
                .max(state.next_poll_at.unwrap_or(0)),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Timing {
    observed_at: u64,
    retry: Option<Retry>,
    next_poll_at: Option<u64>,
}
impl Timing {
    fn validate(&self) -> Result<()> {
        require(self.observed_at > 0 && (self.retry.is_some() || self.next_poll_at.is_some()))?;
        if let Some(retry) = &self.retry {
            require(
                (1..=32).contains(&retry.failures)
                    && retry.next_attempt_at >= self.observed_at
                    && ["rate_limited", "temporary", "bad_nonce"]
                        .contains(&retry.category.as_str())
                    && retry
                        .http_status
                        .is_none_or(|status| (100..=599).contains(&status)),
            )?;
        }
        require(
            self.next_poll_at
                .is_none_or(|value| value >= self.observed_at),
        )
    }
    fn deadline(&self) -> u64 {
        self.retry
            .as_ref()
            .map_or(0, |retry| retry.next_attempt_at)
            .max(self.next_poll_at.unwrap_or(0))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    schema: String,
    installation_id: uuid::Uuid,
    environment: AcmeEnvironment,
    cycle: u64,
    binding_sha256: String,
    anchor_sequence: usize,
    anchor_sha256: String,
    timing: Timing,
}
impl Checkpoint {
    fn parse(bytes: &[u8], saved: &Ledger) -> Result<Self> {
        require(!bytes.is_empty() && bytes.len() <= MAX_CHECKPOINT_BYTES)?;
        let value: Self =
            serde_json::from_value(installer_json::decode(bytes).map_err(|_| REFUSED)?)
                .map_err(|_| REFUSED)?;
        let anchor = saved.history.get(value.anchor_sequence).ok_or(REFUSED)?;
        require(
            value.schema == POLLING_SCHEMA
                && value.installation_id == saved.binding.installation_id
                && value.environment == saved.binding.environment
                && value.cycle == saved.binding.cycle
                && value.binding_sha256 == saved.binding.digest()?
                && value.anchor_sha256 == anchor.digest
                && value.timing.observed_at >= anchor.observed_at,
        )?;
        if let Some(superseding) = saved.history[value.anchor_sequence + 1..]
            .iter()
            .find(|later| later.authority_sha256 != anchor.authority_sha256)
        {
            // A legitimate stale file was prepared before the real transition.
            // A fabricated old anchor cannot make a newer delay disappear.
            require(value.timing.observed_at <= superseding.observed_at.saturating_add(120))?;
        }
        value.timing.validate()?;
        Ok(value)
    }
    fn applies(&self, history: &[Anchor]) -> bool {
        let anchor = &history[self.anchor_sequence];
        // Every entry was validated by Ledger::load_cycle/append. A duplicate
        // receipt or old timing-only append never discards a retained deadline.
        history[self.anchor_sequence + 1..]
            .iter()
            .all(|later| later.authority_sha256 == anchor.authority_sha256)
    }
}

/// Used only to retire or promote already complete checkpoint files. A
/// superseded authority has no current timing requirement; otherwise every
/// applicable bound/history value must be retained by the surviving file.
fn covers(candidate: &[u8], retained: &[u8], saved: &Ledger) -> Result<bool> {
    let candidate = Checkpoint::parse(candidate, saved)?;
    let retained = Checkpoint::parse(retained, saved)?;
    if !retained.applies(&saved.history) {
        return Ok(true);
    }
    if !candidate.applies(&saved.history) {
        return Ok(false);
    }
    let legacy = saved.polling.legacy_deadline;
    Ok(candidate.timing.observed_at >= retained.timing.observed_at
        && candidate.timing.deadline().max(legacy) >= retained.timing.deadline().max(legacy)
        && candidate
            .timing
            .retry
            .as_ref()
            .map_or(0, |retry| retry.failures)
            >= retained
                .timing
                .retry
                .as_ref()
                .map_or(0, |retry| retry.failures))
}

#[derive(Default)]
pub(super) struct Observed {
    current_bytes: Option<Vec<u8>>,
    records: Vec<Checkpoint>,
    effective: Option<Timing>,
    legacy_deadline: u64,
    required: bool,
}
impl Observed {
    pub(super) fn refresh(&mut self, history: &[Anchor]) {
        self.legacy_deadline = history.last().map_or(0, |latest| {
            history
                .iter()
                .rev()
                .take_while(|anchor| anchor.authority_sha256 == latest.authority_sha256)
                .map(|anchor| anchor.legacy_deadline)
                .max()
                .unwrap_or(0)
        });
        let mut effective: Option<Timing> = None;
        for record in self.records.iter().filter(|record| record.applies(history)) {
            let mut next = record.timing.clone();
            if self.legacy_deadline > next.deadline() {
                next.next_poll_at = Some(self.legacy_deadline);
            }
            effective = Some(match effective {
                None => next.clone(),
                Some(previous) => {
                    let deadline = previous.deadline().max(next.deadline());
                    let retry = [previous.retry.as_ref(), next.retry.as_ref()]
                        .into_iter()
                        .flatten()
                        .max_by_key(|value| value.failures)
                        .cloned()
                        .map(|mut retry| {
                            retry.next_attempt_at = deadline;
                            retry
                        });
                    Timing {
                        observed_at: previous.observed_at.max(next.observed_at),
                        retry,
                        next_poll_at: Some(deadline),
                    }
                }
            });
        }
        self.effective = effective;
    }
    pub(super) fn retry<'a>(&'a self, state: &'a State) -> Option<&'a Retry> {
        match &self.effective {
            Some(value) => value.retry.as_ref(),
            None => state.retry.as_ref(),
        }
    }
    pub(super) fn next_poll_at(&self, state: &State) -> Option<u64> {
        let next = match &self.effective {
            Some(value) => value.next_poll_at,
            None => state.next_poll_at,
        };
        next.into_iter()
            .chain((self.legacy_deadline > 0).then_some(self.legacy_deadline))
            .max()
    }
    pub(super) fn observed_at(&self, phase_observed_at: u64) -> u64 {
        self.effective.as_ref().map_or(phase_observed_at, |value| {
            phase_observed_at.max(value.observed_at)
        })
    }
}

pub(super) fn filename(environment: AcmeEnvironment, cycle: u64) -> String {
    format!("acme-poll-{}-{cycle:020}.json", environment.as_str())
}

pub(super) fn require_absent(
    view: &LockedInspection,
    environment: AcmeEnvironment,
    cycle: u64,
) -> Result<()> {
    let name = filename(environment, cycle);
    require(
        store::read(view, &name)?.is_none()
            && store::read_pending(view, &name)?.is_none()
            && view
                .diagnostic_record(&required_name(environment, cycle), true)?
                .is_none(),
    )
}

pub(super) fn restore(view: &LockedInspection, saved: &Ledger) -> Result<Observed> {
    let name = filename(saved.binding.environment, saved.binding.cycle);
    let current_bytes = store::read(view, &name)?;
    let pending = store::read_pending(view, &name)?;
    let records = current_bytes
        .iter()
        .chain(pending.iter())
        .map(|bytes| Checkpoint::parse(bytes, saved))
        .collect::<Result<Vec<_>>>()?;
    let required = require_marker(view, saved)?;
    // After the first current file was flushed and the marker committed,
    // every supported replacement preserves a current name. A lone staged
    // predecessor cannot prove the missing current timing was no later.
    require(!required || current_bytes.is_some())?;
    let mut observed = Observed {
        current_bytes,
        records,
        effective: None,
        legacy_deadline: 0,
        required,
    };
    observed.refresh(&saved.history);
    Ok(observed)
}

/// Publish before returning a retry/poll outcome. A visible prepared checkpoint
/// is also honored after interruption; no retained CA lower bound is discarded
/// while the same immutable phase/authority remains current.
pub(crate) fn record(
    state: &mut LockedMaintenance,
    saved: &mut Ledger,
    mut retry: Option<Retry>,
    mut next_poll_at: Option<u64>,
    observed_at: u64,
) -> Result<()> {
    require(!matches!(
        saved.state.stage,
        Stage::OrderPending | Stage::Terminal | Stage::Complete | Stage::CertificateAdmitted
    ))?;
    require(observed_at >= saved.timing_observed_at())?;
    let retained_deadline = saved
        .retry()
        .map_or(0, |retry| retry.next_attempt_at)
        .max(saved.next_poll_at().unwrap_or(0));
    // Complete current/staged checkpoints must remain ordered for bounded
    // crash recovery. Keep retry history through unchanged successful polls;
    // only a genuine phase/authority transition resets this counter.
    if let Some(previous) = saved.retry() {
        if retry
            .as_ref()
            .is_none_or(|next| next.failures < previous.failures)
        {
            retry = Some(previous.clone());
        }
    }
    let next_deadline = retained_deadline
        .max(retry.as_ref().map_or(0, |retry| retry.next_attempt_at))
        .max(next_poll_at.unwrap_or(0))
        .max(observed_at);
    if let Some(value) = &mut retry {
        value.next_attempt_at = next_deadline;
    }
    if let Some(value) = &mut next_poll_at {
        *value = next_deadline;
    }
    let next = Checkpoint {
        schema: POLLING_SCHEMA.into(),
        installation_id: saved.binding.installation_id,
        environment: saved.binding.environment,
        cycle: saved.binding.cycle,
        binding_sha256: saved.binding.digest()?,
        anchor_sequence: saved.sequence,
        anchor_sha256: saved.digest.clone(),
        timing: Timing {
            observed_at,
            retry,
            next_poll_at,
        },
    };
    let bytes = serde_json::to_vec(&next).map_err(|_| REFUSED)?;
    Checkpoint::parse(&bytes, saved)?;
    store::publish(
        state,
        &filename(saved.binding.environment, saved.binding.cycle),
        saved.polling.current_bytes.as_deref(),
        &bytes,
        |bytes| Checkpoint::parse(bytes, saved).map(|_| ()),
        |candidate, retained| covers(candidate, retained, saved),
    )?;
    if !saved.polling.required {
        let marker = Required {
            schema: "elevenid.installer-acme-polling-required/v1".into(),
            installation_id: saved.binding.installation_id,
            environment: saved.binding.environment,
            cycle: saved.binding.cycle,
            binding_sha256: saved.binding.digest()?,
            anchor_sequence: saved.sequence,
            anchor_sha256: saved.digest.clone(),
        };
        state.write_evidence_exclusive(
            &required_name(saved.binding.environment, saved.binding.cycle),
            &serde_json::to_vec(&marker).map_err(|_| REFUSED)?,
        )?;
    }
    saved.polling = Observed {
        current_bytes: Some(bytes),
        records: vec![next],
        effective: None,
        legacy_deadline: 0,
        required: true,
    };
    saved.polling.refresh(&saved.history);
    Ok(())
}
