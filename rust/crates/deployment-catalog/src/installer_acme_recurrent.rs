//! A new issuance stream needs the generation owner's due-renewal permit.
//! Account registration and CSR generation remain initial-enrollment operations.
use super::*;
use crate::{
    installer_acme_state::{IssuanceReason, RenewalBinding},
    installer_generation_maintenance::RenewalPermit,
};

pub(super) fn same_material(left: &Binding, right: &Binding) -> Result<()> {
    let mut left = left.clone();
    let mut right = right.clone();
    left.cycle = 0;
    left.renewal = None;
    right.cycle = 0;
    right.renewal = None;
    require(left == right)
}

pub(super) fn require_lineage(state: &LockedInspection, saved: &Ledger) -> Result<()> {
    let mut binding = saved.binding.clone();
    while let Some(renewal) = &binding.renewal {
        let record_name = match renewal.reason {
            IssuanceReason::SelectedGenerationDue { .. } => {
                RenewalPermit::record_name(binding.cycle)
            }
            IssuanceReason::InitialCandidateExpired { .. } => {
                crate::installer_acme_host::InitialRolloverPermit::record_name(
                    binding.environment,
                    binding.cycle,
                )
            }
        };
        let intent = state.read_evidence(&record_name)?;
        require(ledger::hash(&intent) == renewal.permit_sha256)?;
        let prior =
            Ledger::load_cycle(state, binding.environment, renewal.prior_cycle)?.ok_or(REFUSED)?;
        require(
            prior.state.stage == Stage::Complete
                && prior.digest == renewal.prior_enrolment_receipt_sha256
                && prior.state.account_url.as_deref() == Some(renewal.account_url.as_str()),
        )?;
        same_material(&binding, &prior.binding)?;
        binding = prior.binding;
    }
    require(binding.cycle == 0)
}

/// Reconstruct a historically admitted Complete candidate, including after its
/// expiry. This does not assess present freshness or confer activation authority.
/// Production remains anchored exclusively in the compiled public root set.
pub fn retained_candidate(
    state: &LockedInspection,
    environment: AcmeEnvironment,
    cycle: u64,
) -> Result<AcmeCandidate> {
    let saved = Ledger::load_cycle(state, environment, cycle)?.ok_or(REFUSED)?;
    require(saved.state.stage == Stage::Complete)?;
    let certificate = retained_certificate(state, &saved)?;
    outcome(&saved, Some(certificate))
        .candidate
        .ok_or_else(|| REFUSED.into())
}

pub(super) fn retained_certificate(
    state: &LockedInspection,
    saved: &Ledger,
) -> Result<ValidatedCertificate> {
    require(matches!(
        saved.state.stage,
        Stage::CertificateAdmitted | Stage::Complete
    ))?;
    let environment = saved.binding.environment;
    require_lineage(state, saved)?;
    let configuration = saved.binding.configuration(state)?;
    let spki = STANDARD
        .decode(&saved.binding.ingress_spki_base64)
        .map_err(|_| REFUSED)?;
    let ingress_key = RetainedIngressKey::from_recorded_public_key(
        &saved.binding.installation_id.to_string(),
        saved.binding.ingress_key_version,
        &spki,
    )?;
    retained_csr_from_ledger(saved, &configuration, &ingress_key)?;
    let recorded = saved.state.certificate.as_ref().ok_or(REFUSED)?;
    let observed = recorded.metadata["observed_at"].as_u64().ok_or(REFUSED)?;
    require(
        observed > 0
            && observed <= saved.observed_at.saturating_add(120)
            && observed <= now()?.saturating_add(120),
    )?;
    let identity = configuration.certificate_identity()?;
    let certificate = match environment {
        AcmeEnvironment::Production => certificates::admit_production_at(
            recorded.fullchain_pem.as_bytes(),
            &identity,
            &ingress_key,
            Duration::from_secs(observed),
        )?,
        AcmeEnvironment::Staging => {
            let roots = state.read_evidence("staging-acme-roots.pem")?;
            require(saved.binding.staging_roots_sha256.as_deref() == Some(&ledger::hash(&roots)))?;
            certificates::admit_staging_test_at(
                recorded.fullchain_pem.as_bytes(),
                &roots,
                &identity,
                &ingress_key,
                Duration::from_secs(observed),
            )?
        }
    };
    require(
        certificate.fullchain_pem() == recorded.fullchain_pem
            && *certificate.metadata() == recorded.metadata
            && recorded.metadata["not_after"]
                .as_u64()
                .zip(recorded.metadata["not_before"].as_u64())
                .and_then(|(after, before)| after.checked_sub(before))
                .is_some_and(|lifetime| lifetime <= SHORTLIVED_MAXIMUM_SECONDS),
    )?;
    Ok(certificate)
}

fn prior_for_permit(state: &LockedInspection, permit: &RenewalPermit) -> Result<Ledger> {
    require(permit.cycle() > 0 && permit.prior_candidate().cycle() < permit.cycle())?;
    let candidate = retained_candidate(
        state,
        permit.prior_candidate().environment(),
        permit.prior_candidate().cycle(),
    )?;
    require(
        serde_json::to_value(&candidate).map_err(|_| REFUSED)?
            == serde_json::to_value(permit.prior_candidate()).map_err(|_| REFUSED)?,
    )?;
    Ledger::load_cycle(state, candidate.environment(), candidate.cycle())?
        .ok_or_else(|| REFUSED.into())
}

fn renewal_link(permit: &RenewalPermit, prior: &Ledger) -> Result<RenewalBinding> {
    Ok(RenewalBinding {
        permit_sha256: permit.sha256().into(),
        configuration_sha256: permit.configuration_sha256().into(),
        reason: IssuanceReason::SelectedGenerationDue {
            generation_binding_sha256: permit.generation_binding_sha256().into(),
            schedule_sha256: permit.schedule_sha256().into(),
        },
        prior_cycle: prior.binding.cycle,
        prior_enrolment_receipt_sha256: prior.digest.clone(),
        account_url: prior.state.account_url.clone().ok_or(REFUSED)?,
        created_at: permit.created_at(),
    })
}

/// Reuse exact signed CSR bytes from the admitted prior stream. If this cycle
/// already exists, it must retain those same bytes and the same permit.
pub(crate) fn retained_csr_for_renewal(
    state: &LockedInspection,
    configuration: &BoundAcmeConfiguration,
    ingress_key: &RetainedIngressKey,
    permit: &RenewalPermit,
) -> Result<ValidatedCsr> {
    require(
        permit.configuration_sha256()
            == ledger::hash(&serde_json::to_vec(configuration).map_err(|_| REFUSED)?),
    )?;
    let prior = prior_for_permit(state, permit)?;
    let csr = retained_csr_from_ledger(&prior, configuration, ingress_key)?;
    if let Some(saved) = Ledger::load_cycle(state, prior.binding.environment, permit.cycle())? {
        same_material(&saved.binding, &prior.binding)?;
        require(saved.binding.renewal.as_ref() == Some(&renewal_link(permit, &prior)?))?;
        let retained = retained_csr_from_ledger(&saved, configuration, ingress_key)?;
        require(retained.der() == csr.der())?;
    }
    Ok(csr)
}

/// The sole production recurring entry point consumes a generation-bound due
/// permit before constructing an account signer or making a CA request.
pub(crate) fn run_renewal_locked(
    state: &mut LockedMaintenance,
    inputs: &EnrolmentInputs<'_>,
    bao: OpenBaoHttp,
    credentials: Arc<dyn WorkloadCredentials>,
    permit: &RenewalPermit,
) -> Result<EnrolmentOutcome> {
    permit.require_worker(state.inspection(), inputs)?;
    require(inputs.configuration.parameters().environment() == AcmeEnvironment::Production)?;
    let prior = prior_for_permit(state.inspection(), permit)?;
    let mut binding = bind_inputs(state.inspection(), inputs)?;
    same_material(&binding, &prior.binding)?;
    binding.cycle = permit.cycle();
    binding.renewal = Some(renewal_link(permit, &prior)?);
    binding.configuration(state.inspection())?;
    require(now()?.saturating_add(120) >= permit.created_at())?;
    run_with_binding(state, inputs, binding, bao, credentials)
}

/// Initial expiry uses its own original-preparation capability. It has no
/// selected-generation fiction and cannot run after application activation.
pub(crate) fn run_initial_rollover_locked(
    state: &mut LockedMaintenance,
    inputs: &EnrolmentInputs<'_>,
    bao: OpenBaoHttp,
    credentials: Arc<dyn WorkloadCredentials>,
    permit: &crate::installer_acme_host::InitialRolloverPermit,
) -> Result<EnrolmentOutcome> {
    permit.require_worker(state.inspection(), inputs)?;
    let prior = Ledger::load_cycle(
        state.inspection(),
        permit.prior_candidate().environment(),
        permit.prior_candidate().cycle(),
    )?
    .ok_or(REFUSED)?;
    require(
        prior.state.stage == Stage::Complete
            && prior.digest == permit.prior_candidate().enrolment_receipt_sha256(),
    )?;
    let mut binding = bind_inputs(state.inspection(), inputs)?;
    same_material(&binding, &prior.binding)?;
    binding.cycle = permit.cycle();
    binding.renewal = Some(RenewalBinding {
        permit_sha256: permit.sha256().into(),
        configuration_sha256: permit.configuration_sha256().into(),
        reason: permit.reason(),
        prior_cycle: prior.binding.cycle,
        prior_enrolment_receipt_sha256: prior.digest,
        account_url: prior.state.account_url.ok_or(REFUSED)?,
        created_at: permit.created_at(),
    });
    binding.configuration(state.inspection())?;
    run_with_binding(state, inputs, binding, bao, credentials)
}
