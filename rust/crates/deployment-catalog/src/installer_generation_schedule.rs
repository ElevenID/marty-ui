//! Separate public-certificate and workload-credential clocks. Only a retained
//! due decision can create an ACME cycle; token refresh reuses the selected leaf.
use super::*;
use crate::{
    installer_acme_host::{self, HostInputs},
    installer_acme_renewal as renewal,
    installer_acme_state::{Ledger, Stage},
    installer_root_retirement,
};

const CREDENTIAL_REFRESH_SECONDS: u64 = 1800;
const NEW_LEAF_MINIMUM_SECONDS: u64 = 3600;

#[derive(Debug, Serialize)]
pub(crate) struct GenerationMaintenanceReport {
    pub schema: &'static str,
    pub selected_sequence: u64,
    pub generation_sha256: String,
    pub credential_refresh_due: bool,
    pub certificate_renewal_due: bool,
    pub activation_performed: bool,
    pub automatic_renewal_supported: bool,
    pub first_blocking_dependency: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acme: Option<Value>,
    pub installation_ready: bool,
}

fn binding(view: &LockedInspection, installation: &Path) -> Result<GenerationBinding> {
    generation::load_verified(
        installation,
        &view.journal().installation_id().to_string(),
        &view.journal().runtime().ok_or(REFUSED)?.engine_id,
    )?
    .ok_or_else(|| REFUSED.into())
}

fn expires(candidate: &AcmeCandidate) -> Result<u64> {
    candidate.metadata()["not_after"]
        .as_u64()
        .ok_or_else(|| REFUSED.into())
}

fn new_leaf_usable(candidate: &AcmeCandidate, at: u64) -> Result<bool> {
    Ok(expires(candidate)? >= at.checked_add(NEW_LEAF_MINIMUM_SECONDS).ok_or(REFUSED)?)
}

pub(super) fn credential_due(observed: u64, ttl: u64, at: u64) -> Result<(u64, bool)> {
    require(observed > 0 && observed <= at.saturating_add(120) && ttl >= 3600)?;
    let due = observed
        .checked_add(CREDENTIAL_REFRESH_SECONDS)
        .ok_or(REFUSED)?;
    Ok((due, at >= due))
}

struct Cycles {
    maximum: u64,
    latest: Option<RenewalPermit>,
}

/// Permit creation can precede the worker's first ledger write. Count both
/// namespaces so losing that response cannot allocate the same cycle twice.
fn cycles(view: &LockedInspection, installation: &Path, current: &AcmeCandidate) -> Result<Cycles> {
    view.require_path_binding(installation)?;
    let held = crate::installer_host_fs::directory(&installation.join("evidence"), REFUSED)?;
    let names = crate::installer_host_fs::file_names(&held, REFUSED)?;
    let streams = Ledger::cycles(view, AcmeEnvironment::Production)?;
    let mut maximum = streams.iter().copied().max().unwrap_or(0);
    let mut permits = BTreeMap::new();
    for name in names {
        let Some(value) = name.strip_prefix("generation-acme-") else {
            continue;
        };
        let digits = value.strip_suffix("-intent.json").ok_or(REFUSED)?;
        require(digits.len() == 20 && digits.bytes().all(|v| v.is_ascii_digit()))?;
        let cycle = digits.parse::<u64>().map_err(|_| REFUSED)?;
        require(cycle > 0 && name == RenewalPermit::record_name(cycle))?;
        maximum = maximum.max(cycle);
        let permit = RenewalPermit::load(view, cycle)?;
        if cycle > current.cycle() {
            require(
                permit.data.prior_cycle == current.cycle()
                    && serde_json::to_value(&permit.prior).map_err(|_| REFUSED)?
                        == serde_json::to_value(current).map_err(|_| REFUSED)?,
            )?;
        }
        require(permits.insert(cycle, permit).is_none())?;
    }
    // Positive pre-activation streams are at or before the selected candidate.
    // A later unowned stream cannot silently become a generation-owner order.
    require(
        streams
            .iter()
            .all(|cycle| *cycle <= current.cycle() || permits.contains_key(cycle)),
    )?;
    let latest = permits
        .into_iter()
        .rev()
        .find_map(|(_, permit)| (permit.data.prior_cycle == current.cycle()).then_some(permit));
    if let Some(permit) = &latest {
        require(
            serde_json::to_value(&permit.prior).map_err(|_| REFUSED)?
                == serde_json::to_value(current).map_err(|_| REFUSED)?,
        )?;
        renewal::require_due_evidence(
            view,
            current,
            permit.schedule_sha256(),
            permit.created_at(),
        )?;
    }
    crate::installer_host_fs::require_directory_binding(
        &installation.join("evidence"),
        &held,
        REFUSED,
    )?;
    view.require_unchanged()?;
    Ok(Cycles { maximum, latest })
}

impl RenewalPermit {
    fn admit_due(
        state: &mut LockedMaintenance,
        installation: &Path,
        parent: &GenerationBinding,
        current: &AcmeCandidate,
        schedule_receipt_sha256: &str,
        maximum: u64,
        terminal_predecessor: Option<installer_acme::TerminalRetryEvidence>,
    ) -> Result<Self> {
        crate::installer_lifecycle::require_recorded_running_intent(
            state.inspection(),
            installation,
        )?;
        installer_root_retirement::require_no_pending_for_generation(state.inspection())?;
        require(parent.public_ingress())?;
        let at = now()?;
        renewal::require_due_evidence(state.inspection(), current, schedule_receipt_sha256, at)?;
        if let Some(terminal) = &terminal_predecessor {
            require(terminal.cycle() == maximum && terminal.cycle() > current.cycle())?;
            installer_acme::require_terminal_retry_evidence(
                state.inspection(),
                installation,
                AcmeEnvironment::Production,
                current,
                terminal,
                at,
            )?;
        }
        require(binding(state.inspection(), installation)? == *parent)?;
        let configuration = BoundAcmeConfiguration::from_selection(state.inspection())?;
        let initial = installer_doctor::load_initial_session(state.inspection(), installation)?;
        let data = PermitData {
            schema: "elevenid.installer-generation-acme-intent/v1".into(),
            installation_id: state.journal().installation_id().to_string(),
            environment: AcmeEnvironment::Production,
            cycle: maximum.checked_add(1).ok_or(REFUSED)?,
            prior_cycle: current.cycle(),
            prior_candidate: serde_json::to_value(current).map_err(|_| REFUSED)?,
            configuration_sha256: hash(&encode(&configuration)?),
            generation_sequence: parent.sequence(),
            generation_binding_sha256: parent.sha256()?,
            initial_configuration_sha256: initial.configuration_sha256,
            schedule_sha256: schedule_receipt_sha256.into(),
            created_at: at,
            terminal_predecessor,
        };
        state.write_evidence_exclusive(&Self::record_name(data.cycle), &encode(&data)?)?;
        Self::load(state.inspection(), data.cycle)
    }
}

fn pending_status(
    view: &LockedInspection,
    installation: &Path,
    permit: &RenewalPermit,
) -> Result<Value> {
    let stream = Ledger::load_cycle(view, AcmeEnvironment::Production, permit.cycle())?;
    let mut report = json!({"cycle":permit.cycle(),"permit_sha256":permit.sha256(),
        "stage":stream.as_ref().map(|value| value.state.stage),
        "failure":stream.as_ref().and_then(|value| value.state.failure.as_deref()),
        "next_attempt_at":stream.as_ref().and_then(|value| value.retry().map(|retry|retry.next_attempt_at)),
        "next_poll_at":stream.as_ref().and_then(|value| value.next_poll_at()),
        "read_only":true});
    if stream
        .as_ref()
        .is_some_and(|value| value.state.stage == Stage::Terminal)
    {
        let decision = installer_acme::terminal_retry_decision(
            view,
            installation,
            AcmeEnvironment::Production,
            permit.cycle(),
            now()?,
        )?;
        report["terminal_retry_at"] = json!(decision.eligible_at());
        report["terminal_retry_due"] = json!(decision.is_due());
        report["terminal_receipt_sha256"] = json!(decision
            .evidence()
            .map(|value| value.receipt_sha256().to_owned()));
        report["first_blocking_dependency"] = json!(decision.blocking_dependency());
    }
    Ok(report)
}

fn private_status(
    view: &LockedInspection,
    installation: &Path,
    binding: &GenerationBinding,
) -> Result<Value> {
    let metadata = binding.ingress_metadata(installation)?;
    let at = now()?;
    let (due_at, due, expired) = if let Some(metadata) = &metadata {
        let (due_at, due) =
            credential_due(metadata.token_observed_at, metadata.token_ttl_seconds, at)?;
        (Some(due_at), due, at >= metadata.certificate_expires_at)
    } else {
        (None, false, false)
    };
    view.require_path_binding(installation)?;
    Ok(json!({"schema":"elevenid.installer-generation-status/v1",
        "selected_sequence":binding.sequence(),"generation_sha256":binding.sha256()?,
        "automatic_renewal_supported":false,"credential_refresh_due":due,
        "credential_refresh_at":due_at,"certificate_expired":expired,
        "certificate_expires_at":metadata.as_ref().map(|value|value.certificate_expires_at),
        "first_blocking_dependency":if due || expired { Some("private_generation_renewal_not_implemented") }
            else if binding.imported_foundation() { Some("customer_managed_foundation_credentials") } else { None },
        "read_only":true,"installation_ready":false}))
}

pub(crate) fn status_locked(view: &LockedInspection, installation: &Path) -> Result<Value> {
    view.require_path_binding(installation)?;
    let binding = binding(view, installation)?;
    if !binding.public_ingress() {
        return private_status(view, installation, &binding);
    }
    let metadata = binding
        .public_ingress_metadata(installation)?
        .ok_or(REFUSED)?;
    let candidate = candidate_for_binding(view, installation, &binding)?;
    let schedule = renewal::for_candidate(view, &candidate)?.ok_or(REFUSED)?;
    let at = now()?;
    let (refresh_at, refresh_due) =
        credential_due(metadata.token_observed_at, metadata.token_ttl_seconds, at)?;
    let pending = cycles(view, installation, &candidate)?.latest;
    let pending = pending
        .as_ref()
        .map(|permit| pending_status(view, installation, permit))
        .transpose()?;
    let blocker = if pending
        .as_ref()
        .is_some_and(|value| value["stage"] == "terminal")
    {
        pending
            .as_ref()
            .and_then(|value| value["first_blocking_dependency"].as_str())
    } else if pending
        .as_ref()
        .is_some_and(|value| value["stage"] == "order_pending")
    {
        Some("acme_order_outcome_unknown")
    } else if at >= schedule.not_after() {
        Some("public_certificate_expired")
    } else if pending.is_some() {
        Some("acme_order_pending")
    } else {
        None
    };
    Ok(json!({"schema":"elevenid.installer-generation-status/v1",
        "selected_sequence":binding.sequence(),"generation_sha256":binding.sha256()?,
        "certificate_expires_at":schedule.not_after(),
        "signer_token_expires_at":metadata.token_observed_at.checked_add(metadata.token_ttl_seconds).ok_or(REFUSED)?,
        "credential_refresh_at":refresh_at,"credential_refresh_due":refresh_due,
        "certificate_renewal_due":schedule.is_due()?,"certificate_renew_at":schedule.effective_renew_at(),
        "certificate_expired":at>=schedule.not_after(),"automatic_renewal_supported":true,
        "first_blocking_dependency":blocker,"pending_acme":pending,
        "last_successful_activation":selected(installation)?.map(|value|value.selection.selected_at),
        "read_only":true,"installation_ready":false}))
}

fn report(
    binding: &GenerationBinding,
    credential_due: bool,
    certificate_due: bool,
    activated: bool,
    supported: bool,
    blocker: Option<&'static str>,
    acme: Option<Value>,
) -> Result<GenerationMaintenanceReport> {
    Ok(GenerationMaintenanceReport {
        schema: "elevenid.installer-generation-maintenance/v1",
        selected_sequence: binding.sequence(),
        generation_sha256: binding.sha256()?,
        credential_refresh_due: credential_due,
        certificate_renewal_due: certificate_due,
        activation_performed: activated,
        automatic_renewal_supported: supported,
        first_blocking_dependency: blocker,
        acme,
        installation_ready: false,
    })
}

pub(crate) fn reconcile_locked(
    installation: &Path,
    docker: &Path,
    state: &mut LockedMaintenance,
) -> Result<GenerationMaintenanceReport> {
    crate::installer_lifecycle::require_running_intent(state, installation, docker)?;
    installer_root_retirement::require_no_pending_for_generation(state.inspection())?;
    reconcile_pending_locked(installation, docker, state)?;
    let parent = binding(state.inspection(), installation)?;
    if !parent.public_ingress() {
        let status = private_status(state.inspection(), installation, &parent)?;
        if status["credential_refresh_due"] == true || status["certificate_expired"] == true {
            return Err("Private generation renewal is due but its automatic replacement policy is not implemented; preserve the selected generation and scoped authority".into());
        }
        return report(
            &parent,
            false,
            false,
            false,
            false,
            parent
                .imported_foundation()
                .then_some("customer_managed_foundation_credentials"),
            None,
        );
    }
    let current = candidate_for_binding(state.inspection(), installation, &parent)?;
    // ARI reads have their own durable cadence/backoff and cannot sign or order.
    let schedule = renewal::refresh_for_candidate(state, &current)?;
    let due = schedule.is_due()?;
    let mut allocation_due = due;
    let mut due_receipt = schedule.receipt_sha256().to_owned();
    let known = cycles(state.inspection(), installation, &current)?;
    let mut permit = known.latest;
    let mut candidate = None;
    let mut acme = None;
    let mut blocker = None;
    let mut terminal_predecessor = None;
    let mut withdraw_terminal = false;
    if let Some(existing) = &permit {
        if let Some(stream) = Ledger::load_cycle(
            state.inspection(),
            AcmeEnvironment::Production,
            existing.cycle(),
        )? {
            match stream.state.stage {
                Stage::Complete => {
                    let retained = installer_acme::retained_candidate(
                        state.inspection(),
                        AcmeEnvironment::Production,
                        existing.cycle(),
                    )?;
                    if new_leaf_usable(&retained, now()?)? {
                        candidate = Some(retained);
                    } else if expires(&retained)? <= now()? {
                        allocation_due = true;
                        due_receipt = existing.schedule_sha256().to_owned();
                        permit = None;
                    } else {
                        blocker = Some("completed_certificate_too_close_to_expiry");
                    }
                }
                Stage::Terminal => {
                    let decision = installer_acme::terminal_retry_decision(
                        state.inspection(),
                        installation,
                        AcmeEnvironment::Production,
                        existing.cycle(),
                        now()?,
                    )?;
                    if decision.is_due() {
                        terminal_predecessor = Some(decision.evidence().ok_or(REFUSED)?);
                        allocation_due = true;
                        due_receipt = existing.schedule_sha256().to_owned();
                        permit = None;
                    } else {
                        blocker = Some(decision.blocking_dependency());
                        withdraw_terminal = decision.withdrawal_pending();
                    }
                }
                Stage::OrderPending => blocker = Some("acme_order_outcome_unknown"),
                _ => {}
            }
        }
    }
    if allocation_due && permit.is_none() && candidate.is_none() {
        permit = Some(RenewalPermit::admit_due(
            state,
            installation,
            &parent,
            &current,
            &due_receipt,
            known.maximum,
            terminal_predecessor,
        )?);
    }
    let metadata = parent
        .public_ingress_metadata(installation)?
        .ok_or(REFUSED)?;
    let (_, token_due) = credential_due(
        metadata.token_observed_at,
        metadata.token_ttl_seconds,
        now()?,
    )?;
    let mut selected = parent.clone();
    // A scoped account-credential outage or CA timeout must not starve the
    // independent workload renewal authority. Commit a due token-only
    // successor first when its selected public leaf remains valid. An order
    // permit explicitly admits same-leaf descendants, so it remains usable
    // after this selection. Integrity failures are still errors, not retries.
    if candidate.is_none() && token_due && expires(&current)? > now()? {
        selected =
            super::tx::begin_and_reconcile(installation, docker, state, &selected, &current)?;
    }
    if candidate.is_none() && (blocker.is_none() || withdraw_terminal) {
        if let Some(permit) = &permit {
            let context = installer_acme_host::maintenance_context(state.inspection())?;
            let saved = installer_doctor::load_session(state.inspection(), installation)?;
            let inputs = HostInputs {
                docker,
                installation,
                bundle: &context.bundle,
                infrastructure: &context.infrastructure,
                services_image: &context.services_image,
                operator_sha256: &context.operator_sha256,
            };
            let outcome =
                installer_acme_host::renew_for_maintenance(&inputs, state, &saved.inputs, permit)?;
            candidate = outcome.candidate;
            acme = Some(outcome.report);
            if candidate.is_none() {
                blocker = Some(
                    match acme.as_ref().and_then(|value| value["stage"].as_str()) {
                        Some("terminal") => {
                            let decision = installer_acme::terminal_retry_decision(
                                state.inspection(),
                                installation,
                                AcmeEnvironment::Production,
                                permit.cycle(),
                                now()?,
                            )?;
                            if let Some(report) = acme.as_mut() {
                                report["terminal_retry_at"] = json!(decision.eligible_at());
                                report["terminal_retry_due"] = json!(decision.is_due());
                            }
                            decision.blocking_dependency()
                        }
                        Some("order_pending") => "acme_order_outcome_unknown",
                        _ => "acme_order_pending",
                    },
                );
            }
        }
    }
    let certificate_changed = candidate.as_ref().is_some_and(|value| {
        value.enrolment_receipt_sha256() != current.enrolment_receipt_sha256()
    });
    if certificate_changed {
        let candidate = candidate.as_ref().ok_or(REFUSED)?;
        if expires(candidate)? <= now()? {
            return Err("Public certificate is expired and a replacement is not yet admitted; retained order and serving generation were preserved".into());
        }
        selected =
            super::tx::begin_and_reconcile(installation, docker, state, &selected, candidate)?;
    }
    if expires(&current)? <= now()? && !certificate_changed {
        return Err("Public certificate recovery is waiting for its retained ACME order; no expired certificate was newly selected".into());
    }
    let activated = selected.sequence() != parent.sequence();
    let selected_candidate = if certificate_changed {
        candidate.as_ref().ok_or(REFUSED)?
    } else {
        &current
    };
    let selected_schedule =
        renewal::for_candidate(state.inspection(), selected_candidate)?.ok_or(REFUSED)?;
    let selected_metadata = selected
        .public_ingress_metadata(installation)?
        .ok_or(REFUSED)?;
    let (_, token_due) = credential_due(
        selected_metadata.token_observed_at,
        selected_metadata.token_ttl_seconds,
        now()?,
    )?;
    state.inspection().require_path_binding(installation)?;
    report(
        &selected,
        token_due,
        selected_schedule.is_due()?,
        activated,
        true,
        blocker,
        acme,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn credential_clock_is_separate_and_never_moves_with_certificate_due_time() {
        assert_eq!(credential_due(10000, 28800, 11799).unwrap(), (11800, false));
        assert_eq!(credential_due(10000, 3600, 11800).unwrap(), (11800, true));
        assert_eq!(credential_due(10000, 28800, 50000).unwrap(), (11800, true));
        assert!(credential_due(10000, 3599, 10000).is_err());
        assert!(credential_due(10000, 28800, 9879).is_err());
        assert!(credential_due(u64::MAX - 10, 28800, u64::MAX).is_err());
    }
}
