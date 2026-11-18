//! A certainly terminal recurring order can authorize a later attempt only
//! after retained cooldown and actual challenge withdrawal. This reader cannot
//! allocate an order or turn unknown outcomes into terminal observations.
use super::*;
use crate::installer_acme_state::{
    terminal_cooldown, IssuanceReason, TerminalReason, TerminalRetry,
};
use serde::Deserialize;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TerminalRetryEvidence {
    cycle: u64,
    receipt_sha256: String,
    eligible_at: u64,
}
impl TerminalRetryEvidence {
    pub fn cycle(&self) -> u64 {
        self.cycle
    }
    pub fn receipt_sha256(&self) -> &str {
        &self.receipt_sha256
    }
    pub fn eligible_at(&self) -> u64 {
        self.eligible_at
    }
}

pub(crate) struct TerminalRetryDecision {
    evidence: Option<TerminalRetryEvidence>,
    due: bool,
    dependency: &'static str,
}
impl TerminalRetryDecision {
    pub fn evidence(&self) -> Option<TerminalRetryEvidence> {
        self.evidence.clone()
    }
    pub fn eligible_at(&self) -> Option<u64> {
        self.evidence
            .as_ref()
            .map(TerminalRetryEvidence::eligible_at)
    }
    pub fn is_due(&self) -> bool {
        self.due
    }
    pub fn blocking_dependency(&self) -> &'static str {
        self.dependency
    }
    pub fn withdrawal_pending(&self) -> bool {
        self.dependency == "acme_terminal_withdrawal_pending"
    }
    fn hold(dependency: &'static str) -> Self {
        Self {
            evidence: None,
            due: false,
            dependency,
        }
    }
}

/// Count only failures against this exact completed predecessor. A successful
/// selected certificate starts a new series; there is no lifetime attempt cap.
fn attempt(state: &LockedInspection, saved: &Ledger) -> Result<u64> {
    let renewal = saved.binding.renewal.as_ref().ok_or(REFUSED)?;
    require(matches!(
        renewal.reason,
        IssuanceReason::SelectedGenerationDue { .. }
    ))?;
    let mut next = 1u64;
    for cycle in Ledger::cycles(state, saved.binding.environment)? {
        if cycle == 0 || cycle >= saved.binding.cycle {
            continue;
        }
        let earlier =
            Ledger::load_cycle(state, saved.binding.environment, cycle)?.ok_or(REFUSED)?;
        let Some(link) = &earlier.binding.renewal else {
            return Err(REFUSED.into());
        };
        if link.prior_enrolment_receipt_sha256 != renewal.prior_enrolment_receipt_sha256 {
            continue;
        }
        recurrent::same_material(&earlier.binding, &saved.binding)?;
        recurrent::require_lineage(state, &earlier)?;
        if earlier.state.stage == Stage::Terminal {
            let terminal = earlier.state.terminal_retry.as_ref().ok_or(REFUSED)?;
            require(terminal.attempt == next && terminal.withdrawal_confirmed_at.is_some())?;
            next = next.checked_add(1).ok_or(REFUSED)?;
        } else {
            // A completed but unselected certificate may itself expire. An
            // unresolved earlier order cannot be skipped to start another one.
            require(earlier.state.stage == Stage::Complete)?;
        }
    }
    Ok(next)
}

pub(super) fn observation(
    state: &LockedInspection,
    saved: &Ledger,
    code: &str,
    hints: Option<ResponseMetadata>,
    observed_at: u64,
) -> Result<Option<TerminalRetry>> {
    let Some(reason) = TerminalReason::from_code(code) else {
        return Ok(None);
    };
    if saved.binding.cycle == 0
        || saved.binding.renewal.as_ref().is_none_or(|renewal| {
            !matches!(renewal.reason, IssuanceReason::SelectedGenerationDue { .. })
        })
    {
        return Ok(None);
    }
    require(
        saved.state.order.is_some()
            && saved.state.certificate.is_none()
            && saved.state.stage != Stage::OrderPending
            && observed_at > 0
            && observed_at >= saved.observed_at,
    )?;
    recurrent::require_lineage(state, saved)?;
    let attempt = attempt(state, saved)?;
    let retry_not_before = hints
        .and_then(|value| value.retry_after)
        .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
        .map(|value| {
            value
                .as_secs()
                .saturating_add(u64::from(value.subsec_nanos() > 0))
        })
        .into_iter()
        .chain(saved.retry().map(|value| value.next_attempt_at))
        .chain(saved.next_poll_at())
        .filter(|value| *value > 0)
        .max();
    let eligible_at = observed_at
        .checked_add(terminal_cooldown(attempt))
        .ok_or(REFUSED)?
        .max(retry_not_before.unwrap_or(0));
    Ok(Some(TerminalRetry {
        reason,
        observed_at,
        attempt,
        retry_not_before,
        eligible_at,
        withdrawal_confirmed_at: None,
        withdrawn_projection_sha256: None,
    }))
}

/// None means publication is not yet confirmed; Some(None) means no challenge
/// projection exists and this order never published one.
pub(super) fn withdrawn_projection(
    state: &LockedInspection,
    installation: &Path,
    saved: &Ledger,
) -> Result<Option<Option<String>>> {
    let directory = projection_directory(state, installation)?;
    let current = read_projection(&directory)?;
    require_projection_directory(state, installation, &directory)?;
    let Some(bytes) = current else {
        return Ok(saved.state.projection.is_none().then_some(None));
    };
    let digest = ledger::hash(&bytes);
    let snapshot: Snapshot = serde_json::from_slice(&bytes).map_err(|_| REFUSED)?;
    let configuration = saved.binding.configuration(state)?;
    let allowed = AllowedIdentifiers::from_origins(
        configuration.canonical_origin(),
        configuration.public_entry_origin(),
    )
    .map_err(|_| REFUSED)?;
    Snapshot::parse(&bytes, &allowed, snapshot.created_at).map_err(|_| REFUSED)?;
    if !snapshot.challenges.is_empty() {
        return Ok(None);
    }
    if let Some(projection) = &saved.state.projection {
        return Ok((projection.sha256 == digest).then_some(Some(digest)));
    }
    // A new order may be rejected before publishing anything; the public empty
    // projection must still belong to a retained completed/terminal predecessor.
    for cycle in Ledger::cycles(state, saved.binding.environment)? {
        if cycle > saved.binding.cycle {
            continue;
        }
        if let Some(earlier) = Ledger::load_cycle(state, saved.binding.environment, cycle)? {
            if matches!(earlier.state.stage, Stage::Complete | Stage::Terminal)
                && earlier
                    .state
                    .projection
                    .as_ref()
                    .is_some_and(|projection| projection.sha256 == digest)
            {
                return Ok(Some(Some(digest)));
            }
        }
    }
    Ok(None)
}

pub(super) fn confirm_withdrawal(
    state: &mut LockedMaintenance,
    inputs: &EnrolmentInputs<'_>,
    saved: &mut Ledger,
) -> Result<()> {
    let Some(terminal) = saved.state.terminal_observation() else {
        return Ok(());
    };
    if terminal.withdrawal_confirmed_at.is_some() {
        return Ok(());
    }
    let projection =
        withdrawn_projection(state.inspection(), inputs.installation, saved)?.ok_or(REFUSED)?;
    let mut next = saved.state.clone();
    let terminal = next.terminal_observation_mut().ok_or(REFUSED)?;
    let observed = now()?;
    require(observed >= terminal.observed_at)?;
    terminal.withdrawal_confirmed_at = Some(observed);
    terminal.withdrawn_projection_sha256 = projection;
    saved.append(state, next, observed)
}

fn historical_evidence(
    state: &LockedInspection,
    saved: &Ledger,
) -> Result<Option<TerminalRetryEvidence>> {
    let Some(terminal) = &saved.state.terminal_retry else {
        return Ok(None);
    };
    recurrent::require_lineage(state, saved)?;
    require(terminal.attempt == attempt(state, saved)?)?;
    let Some(confirmed) = terminal.withdrawal_confirmed_at else {
        return Ok(None);
    };
    Ok(Some(TerminalRetryEvidence {
        cycle: saved.binding.cycle,
        receipt_sha256: saved.digest.clone(),
        eligible_at: terminal.eligible_at.max(confirmed),
    }))
}

/// Read-only decision for the currently latest order. A preexisting next permit
/// remains its owner's responsibility and must be resumed before asking this
/// reader whether yet another cycle is eligible.
pub(crate) fn terminal_retry_decision(
    state: &LockedInspection,
    installation: &Path,
    environment: AcmeEnvironment,
    cycle: u64,
    observed_at: u64,
) -> Result<TerminalRetryDecision> {
    state.require_path_binding(installation)?;
    require(observed_at > 0 && observed_at <= now()?.saturating_add(120))?;
    let saved = Ledger::load_cycle(state, environment, cycle)?.ok_or(REFUSED)?;
    if saved.state.stage == Stage::OrderPending {
        return Ok(TerminalRetryDecision::hold("acme_order_outcome_unknown"));
    }
    if saved.state.stage != Stage::Terminal {
        return Ok(TerminalRetryDecision::hold("acme_order_not_terminal"));
    }
    let Some(terminal) = &saved.state.terminal_retry else {
        return Ok(TerminalRetryDecision::hold(
            "acme_terminal_retry_evidence_unavailable",
        ));
    };
    require(observed_at >= terminal.observed_at)?;
    let evidence = historical_evidence(state, &saved)?;
    if evidence.is_none() || withdrawn_projection(state, installation, &saved)?.is_none() {
        return Ok(TerminalRetryDecision::hold(
            "acme_terminal_withdrawal_pending",
        ));
    }
    let due = observed_at >= evidence.as_ref().ok_or(REFUSED)?.eligible_at;
    state.require_unchanged()?;
    Ok(TerminalRetryDecision {
        evidence,
        due,
        dependency: if due {
            "acme_terminal_retry_due"
        } else {
            "acme_terminal_retry_cooldown"
        },
    })
}

/// Historical permit admission binds the exact selected predecessor, recorded
/// terminal observation, cooldown and completed withdrawal. It intentionally
/// does not require the old public projection after a valid successor uses it.
pub(crate) fn require_terminal_retry_evidence(
    state: &LockedInspection,
    installation: &Path,
    environment: AcmeEnvironment,
    prior_candidate: &AcmeCandidate,
    evidence: &TerminalRetryEvidence,
    at: u64,
) -> Result<()> {
    state.require_path_binding(installation)?;
    require(
        environment == prior_candidate.environment()
            && evidence.cycle > prior_candidate.cycle()
            && at > 0
            && at <= now()?.saturating_add(120),
    )?;
    let saved = Ledger::load_cycle(state, environment, evidence.cycle)?.ok_or(REFUSED)?;
    require(saved.state.stage == Stage::Terminal && saved.digest == evidence.receipt_sha256())?;
    let link = saved.binding.renewal.as_ref().ok_or(REFUSED)?;
    require(
        matches!(link.reason, IssuanceReason::SelectedGenerationDue { .. })
            && link.prior_cycle == prior_candidate.cycle()
            && link.prior_enrolment_receipt_sha256 == prior_candidate.enrolment_receipt_sha256(),
    )?;
    let retained = retained_candidate(state, environment, prior_candidate.cycle())?;
    require(
        serde_json::to_value(&retained).map_err(|_| REFUSED)?
            == serde_json::to_value(prior_candidate).map_err(|_| REFUSED)?,
    )?;
    require(
        historical_evidence(state, &saved)?.as_ref() == Some(evidence)
            && at >= evidence.eligible_at,
    )?;
    state.require_unchanged()
}
