//! Retry authority for a positively terminal order in a still-pristine initial
//! installation. It never confers selected-generation or maintenance authority.
use super::*;
use crate::installer_acme_state::{
    terminal_cooldown, InitialTerminalRetry, IssuanceReason, TerminalReason, TerminalRetry,
};
use serde::Deserialize;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InitialTerminalEvidence {
    cycle: u64,
    receipt_sha256: String,
    eligible_at: u64,
}
impl InitialTerminalEvidence {
    pub(crate) fn cycle(&self) -> u64 {
        self.cycle
    }
    pub(crate) fn receipt_sha256(&self) -> &str {
        &self.receipt_sha256
    }
}

/// Inspect only the immediate predecessor here. The caller validates the whole
/// chain iteratively, so historical admission cannot recursively follow permits.
fn attempt(state: &LockedInspection, saved: &Ledger) -> Result<u64> {
    let Some(link) = &saved.binding.renewal else {
        require(saved.binding.cycle == 0)?;
        return Ok(1);
    };
    let prior =
        Ledger::load_cycle(state, saved.binding.environment, link.prior_cycle)?.ok_or(REFUSED)?;
    require(
        prior.binding.cycle.checked_add(1) == Some(saved.binding.cycle)
            && prior.digest == link.prior_enrolment_receipt_sha256
            && prior.state.account_url.as_deref() == Some(link.account_url.as_str()),
    )?;
    recurrent::same_material(&prior.binding, &saved.binding)?;
    match &link.reason {
        IssuanceReason::InitialCandidateExpired { .. } => {
            require(prior.state.stage == Stage::Complete)?;
            Ok(1)
        }
        IssuanceReason::InitialOrderTerminal { .. } => {
            let previous = prior.state.initial_terminal_retry.as_ref().ok_or(REFUSED)?;
            previous.authority.validate(&saved.binding)?;
            require(
                prior.state.stage == Stage::Terminal
                    && previous.observation.withdrawal_confirmed_at.is_some()
                    && previous.observation.eligible_at <= link.created_at
                    && previous.observation.withdrawal_confirmed_at <= Some(link.created_at),
            )?;
            previous
                .observation
                .attempt
                .checked_add(1)
                .ok_or_else(|| REFUSED.into())
        }
        IssuanceReason::SelectedGenerationDue { .. } => Err(REFUSED.into()),
    }
}

/// This is called only while recording a new positive terminal observation.
/// An old untyped Terminal receipt is deliberately ineligible for retrofitting.
pub(super) fn observation(
    state: &LockedInspection,
    saved: &Ledger,
    code: &str,
    hints: Option<ResponseMetadata>,
    observed_at: u64,
) -> Result<Option<InitialTerminalRetry>> {
    let Some(reason) = TerminalReason::from_code(code) else {
        return Ok(None);
    };
    let Some(authority) =
        crate::installer_acme_host::initial_order_authority(state, &saved.binding, true)?
    else {
        return Ok(None);
    };
    require(
        saved.state.order.is_some()
            && saved.state.account_url.is_some()
            && saved.state.certificate.is_none()
            && !matches!(saved.state.stage, Stage::OrderPending | Stage::Terminal)
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
    Ok(Some(InitialTerminalRetry {
        schema: "elevenid.installer-acme-initial-terminal/v1".into(),
        authority,
        observation: TerminalRetry {
            reason,
            observed_at,
            attempt,
            retry_not_before,
            eligible_at,
            withdrawal_confirmed_at: None,
            withdrawn_projection_sha256: None,
        },
    }))
}

/// No lineage recursion and no current projection requirement: an authenticated
/// successor may already own that projection. Every caller which admits a new
/// stream additionally validates the complete predecessor chain.
pub(crate) fn historical_evidence_local(
    state: &LockedInspection,
    saved: &Ledger,
) -> Result<Option<InitialTerminalEvidence>> {
    let Some(proof) = &saved.state.initial_terminal_retry else {
        return Ok(None);
    };
    require(
        saved.state.stage == Stage::Terminal
            && saved.state.terminal_retry.is_none()
            && proof.observation.attempt == attempt(state, saved)?
            && crate::installer_acme_host::initial_order_authority(state, &saved.binding, false)?
                .as_ref()
                == Some(&proof.authority),
    )?;
    let Some(confirmed) = proof.observation.withdrawal_confirmed_at else {
        return Ok(None);
    };
    Ok(Some(InitialTerminalEvidence {
        cycle: saved.binding.cycle,
        receipt_sha256: saved.digest.clone(),
        eligible_at: proof.observation.eligible_at.max(confirmed),
    }))
}

pub(crate) fn require_evidence_local(
    state: &LockedInspection,
    saved: &Ledger,
    evidence: &InitialTerminalEvidence,
    at: u64,
) -> Result<()> {
    require(
        at > 0
            && at <= now()?.saturating_add(120)
            && at >= evidence.eligible_at
            && historical_evidence_local(state, saved)?.as_ref() == Some(evidence),
    )
}

/// A new permit needs the current empty projection as well as the durable
/// withdrawal receipt. Unknown orders, legacy Terminal and cooldown stay held.
pub(crate) fn due_evidence(
    state: &LockedInspection,
    installation: &Path,
    saved: &Ledger,
    at: u64,
) -> Result<Option<InitialTerminalEvidence>> {
    state.require_path_binding(installation)?;
    require(at > 0 && at <= now()?.saturating_add(120))?;
    recurrent::require_lineage(state, saved)?;
    let Some(evidence) = historical_evidence_local(state, saved)? else {
        return Ok(None);
    };
    if at < evidence.eligible_at
        || terminal::withdrawn_projection(state, installation, saved)?.is_none()
    {
        return Ok(None);
    }
    state.require_unchanged()?;
    Ok(Some(evidence))
}
