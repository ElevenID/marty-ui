//! An expired first-install candidate may be replaced before any application
//! generation starts. Its permit is distinct from maintenance's due decision.
use super::*;
use crate::{
    installer_acme::{AcmeCandidate, EnrolmentInputs},
    installer_acme_state::{IssuanceReason, Ledger, Stage},
    installer_state::LockedMaintenance,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PermitData {
    schema: String,
    installation_id: uuid::Uuid,
    environment: AcmeEnvironment,
    cycle: u64,
    prior_cycle: u64,
    prior_candidate: Value,
    configuration_sha256: String,
    host_intent_sha256: String,
    host_prepared_sha256: String,
    created_at: u64,
}

/// Only a complete, still-pristine original preparation and a historically
/// admitted expired candidate can create this capability. No setup is replayed.
#[derive(Clone, Debug)]
pub(crate) struct InitialRolloverPermit {
    data: PermitData,
    prior: AcmeCandidate,
    digest: String,
}
impl InitialRolloverPermit {
    pub(crate) fn record_name(environment: AcmeEnvironment, cycle: u64) -> String {
        format!(
            "acme-initial-{}-order-{cycle:020}-intent.json",
            environment.as_str()
        )
    }
    pub(crate) fn cycle(&self) -> u64 {
        self.data.cycle
    }
    pub(crate) fn prior_candidate(&self) -> &AcmeCandidate {
        &self.prior
    }
    pub(crate) fn configuration_sha256(&self) -> &str {
        &self.data.configuration_sha256
    }
    pub(crate) fn sha256(&self) -> &str {
        &self.digest
    }
    pub(crate) fn created_at(&self) -> u64 {
        self.data.created_at
    }
    pub(crate) fn reason(&self) -> IssuanceReason {
        IssuanceReason::InitialCandidateExpired {
            host_intent_sha256: self.data.host_intent_sha256.clone(),
            host_prepared_sha256: self.data.host_prepared_sha256.clone(),
        }
    }
    fn load(state: &LockedInspection, environment: AcmeEnvironment, cycle: u64) -> Result<Self> {
        let bytes = state.read_evidence(&Self::record_name(environment, cycle))?;
        let data: PermitData = decode(&bytes)?;
        require(
            data.schema == "elevenid.installer-acme-initial-rollover/v1"
                && data.installation_id == state.journal().installation_id()
                && data.environment == environment
                && data.cycle == cycle
                && cycle > 0
                && data.prior_cycle.checked_add(1) == Some(cycle)
                && data.created_at > 0
                && data.created_at <= installer_acme::now()?.saturating_add(120)
                && [
                    &data.configuration_sha256,
                    &data.host_intent_sha256,
                    &data.host_prepared_sha256,
                ]
                .into_iter()
                .all(|value| hash_valid(value))
                && encode(&data)? == bytes,
        )?;
        let prior = installer_acme::retained_candidate(state, environment, data.prior_cycle)?;
        require(
            value(&prior)? == data.prior_candidate
                && prior.metadata()["not_after"]
                    .as_u64()
                    .is_some_and(|expiry| expiry <= data.created_at),
        )?;
        Ok(Self {
            data,
            prior,
            digest: sha(&bytes),
        })
    }
    fn require_current(
        &self,
        state: &LockedInspection,
        installation: &Path,
        configuration: &BoundAcmeConfiguration,
        ingress: &RetainedIngressKey,
    ) -> Result<()> {
        before_application(state)?;
        state.require_path_binding(installation)?;
        let retained = Self::load(state, self.data.environment, self.data.cycle)?;
        let (intent, _, configured) = load_prepared(state)?;
        require(
            retained.digest == self.digest
                && configured == *configuration
                && sha(&serde_json::to_vec(configuration).map_err(|_| REFUSED)?)
                    == self.data.configuration_sha256
                && intent.ingress_key.bind(intent.installation_id)? == *ingress
                && sha(&state.read_evidence(&name(self.data.environment, "intent"))?)
                    == self.data.host_intent_sha256
                && sha(&state.read_evidence(&name(self.data.environment, "prepared"))?)
                    == self.data.host_prepared_sha256,
        )?;
        state.require_unchanged()
    }
    pub(crate) fn require_worker(
        &self,
        state: &LockedInspection,
        inputs: &EnrolmentInputs<'_>,
    ) -> Result<()> {
        self.require_current(
            state,
            inputs.installation,
            inputs.configuration,
            inputs.ingress_key,
        )
    }
}

fn before_application(state: &LockedInspection) -> Result<()> {
    require(state.journal().phase() == Phase::Provisioning)?;
    let directory = fs::open_child(
        state.installation_directory(),
        "evidence",
        libc::O_RDONLY | libc::O_DIRECTORY,
        REFUSED,
    )?;
    for entry in fs::file_names(&directory, REFUSED)? {
        require(
            !(entry.starts_with("generation-")
                || (entry.starts_with("application-")
                    && entry != crate::installer_creation_identity::APPLICATION_RECEIPT)
                || entry.starts_with("compose-generation-")
                || entry.starts_with("compose-application-")
                || entry.starts_with("lifecycle-")
                || entry.starts_with("uninstall-")
                || entry == "compose-session.json"
                || entry == "installer-nginx.conf"),
        )?;
    }
    state.require_unchanged()
}

fn cycles(state: &LockedInspection, environment: AcmeEnvironment) -> Result<Vec<u64>> {
    let directory = fs::open_child(
        state.installation_directory(),
        "evidence",
        libc::O_RDONLY | libc::O_DIRECTORY,
        REFUSED,
    )?;
    let prefix = format!("acme-initial-{}-order-", environment.as_str());
    let mut found = BTreeSet::new();
    for entry in fs::file_names(&directory, REFUSED)? {
        if let Some(suffix) = entry.strip_prefix(&prefix) {
            let number = suffix.strip_suffix("-intent.json").ok_or(REFUSED)?;
            require(number.len() == 20 && number.bytes().all(|byte| byte.is_ascii_digit()))?;
            let cycle: u64 = number.parse().map_err(|_| REFUSED)?;
            require(cycle > 0 && entry == InitialRolloverPermit::record_name(environment, cycle))?;
            found.insert(cycle);
        }
    }
    for (index, cycle) in found.iter().enumerate() {
        require(
            u64::try_from(index)
                .ok()
                .and_then(|value| value.checked_add(1))
                == Some(*cycle),
        )?;
    }
    Ok(found.into_iter().collect())
}

/// At most one new cycle is admitted per invocation. Pending/uncertain orders
/// retain their existing permit. Only a Complete expired predecessor permits
/// another order; account creation, key creation and setup remain impossible.
pub(super) fn select(
    state: &mut LockedMaintenance,
    configuration: &BoundAcmeConfiguration,
    ingress: &RetainedIngressKey,
) -> Result<Option<InitialRolloverPermit>> {
    before_application(state.inspection())?;
    let (intent, prepared, configured) = load_prepared(state.inspection())?;
    require(
        configured == *configuration
            && intent.ingress_key.bind(intent.installation_id)? == *ingress,
    )?;
    let environment = configuration.parameters().environment();
    let permits = cycles(state.inspection(), environment)?;
    let latest = permits.last().copied().unwrap_or(0);
    let streams = Ledger::cycles(state.inspection(), environment)?;
    require(streams.iter().all(|cycle| *cycle <= latest))?;
    for cycle in permits.iter().copied().filter(|cycle| *cycle < latest) {
        InitialRolloverPermit::load(state.inspection(), environment, cycle)?;
        require(
            Ledger::load_cycle(state.inspection(), environment, cycle)?
                .is_some_and(|saved| saved.state.stage == Stage::Complete),
        )?;
    }
    let permit = (latest > 0)
        .then(|| InitialRolloverPermit::load(state.inspection(), environment, latest))
        .transpose()?;
    if let Some(permit) = &permit {
        permit.require_current(
            state.inspection(),
            &prepared.inputs.installation,
            configuration,
            ingress,
        )?;
    }
    let Some(saved) = Ledger::load_cycle(state.inspection(), environment, latest)? else {
        return Ok(permit);
    };
    if saved.state.stage != Stage::Complete {
        return Ok(permit);
    }
    let prior = installer_acme::retained_candidate(state.inspection(), environment, latest)?;
    let observed = installer_acme::now()?;
    if prior.metadata()["not_after"].as_u64().ok_or(REFUSED)? > observed {
        return Ok(permit);
    }
    let cycle = latest.checked_add(1).ok_or(REFUSED)?;
    let data = PermitData {
        schema: "elevenid.installer-acme-initial-rollover/v1".into(),
        installation_id: state.journal().installation_id(),
        environment,
        cycle,
        prior_cycle: latest,
        prior_candidate: value(&prior)?,
        configuration_sha256: sha(&serde_json::to_vec(configuration).map_err(|_| REFUSED)?),
        host_intent_sha256: sha(&state
            .inspection()
            .read_evidence(&name(environment, "intent"))?),
        host_prepared_sha256: sha(&state
            .inspection()
            .read_evidence(&name(environment, "prepared"))?),
        created_at: observed,
    };
    state.write_evidence_exclusive(
        &InitialRolloverPermit::record_name(environment, cycle),
        &encode(&data)?,
    )?;
    let permit = InitialRolloverPermit::load(state.inspection(), environment, cycle)?;
    permit.require_current(
        state.inspection(),
        &prepared.inputs.installation,
        configuration,
        ingress,
    )?;
    Ok(Some(permit))
}

#[cfg(test)]
#[path = "installer_acme_initial_rollover_tests.rs"]
mod tests;
