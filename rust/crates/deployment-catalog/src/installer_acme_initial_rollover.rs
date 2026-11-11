//! An initial order may be replaced after a confirmed terminal failure or an
//! admitted candidate's expiry, before any application generation starts.
use super::*;
use crate::{
    installer_acme::{initial_terminal, AcmeCandidate, EnrolmentInputs},
    installer_acme_state::{Binding, IssuanceReason, Ledger, Stage},
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum InitialPredecessor {
    ExpiredCandidate {
        candidate: Value,
    },
    ConfirmedInitialTerminal {
        evidence: initial_terminal::InitialTerminalEvidence,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PermitDataV2 {
    schema: String,
    installation_id: uuid::Uuid,
    environment: AcmeEnvironment,
    cycle: u64,
    prior_cycle: u64,
    predecessor: InitialPredecessor,
    configuration_sha256: String,
    host_intent_sha256: String,
    host_prepared_sha256: String,
    created_at: u64,
}

/// Complete, still-pristine original preparation remains mandatory for either
/// initial retry reason. This capability never authorizes maintenance issuance.
#[derive(Clone, Debug)]
pub(crate) struct InitialRolloverPermit {
    data: PermitDataV2,
    prior: Option<AcmeCandidate>,
    prior_digest: String,
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
    pub(crate) fn prior_candidate(&self) -> Option<&AcmeCandidate> {
        self.prior.as_ref()
    }
    pub(crate) fn environment(&self) -> AcmeEnvironment {
        self.data.environment
    }
    pub(crate) fn prior_cycle(&self) -> u64 {
        self.data.prior_cycle
    }
    pub(crate) fn prior_receipt_sha256(&self) -> &str {
        &self.prior_digest
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
        match self.data.predecessor {
            InitialPredecessor::ExpiredCandidate { .. } => {
                IssuanceReason::InitialCandidateExpired {
                    host_intent_sha256: self.data.host_intent_sha256.clone(),
                    host_prepared_sha256: self.data.host_prepared_sha256.clone(),
                }
            }
            InitialPredecessor::ConfirmedInitialTerminal { .. } => {
                IssuanceReason::InitialOrderTerminal {
                    host_intent_sha256: self.data.host_intent_sha256.clone(),
                    host_prepared_sha256: self.data.host_prepared_sha256.clone(),
                }
            }
        }
    }
    fn parse(
        state: &LockedInspection,
        environment: AcmeEnvironment,
        cycle: u64,
    ) -> Result<(PermitDataV2, Vec<u8>)> {
        let bytes = state.read_evidence(&Self::record_name(environment, cycle))?;
        let source: Value = decode(&bytes)?;
        let data: PermitDataV2 = match source["schema"].as_str() {
            Some("elevenid.installer-acme-initial-rollover/v1") => {
                let legacy: PermitData = decode(&bytes)?;
                require(encode(&legacy)? == bytes)?;
                PermitDataV2 {
                    schema: "elevenid.installer-acme-initial-rollover/v2".into(),
                    installation_id: legacy.installation_id,
                    environment: legacy.environment,
                    cycle: legacy.cycle,
                    prior_cycle: legacy.prior_cycle,
                    predecessor: InitialPredecessor::ExpiredCandidate {
                        candidate: legacy.prior_candidate,
                    },
                    configuration_sha256: legacy.configuration_sha256,
                    host_intent_sha256: legacy.host_intent_sha256,
                    host_prepared_sha256: legacy.host_prepared_sha256,
                    created_at: legacy.created_at,
                }
            }
            Some("elevenid.installer-acme-initial-rollover/v2") => {
                let data: PermitDataV2 = decode(&bytes)?;
                require(encode(&data)? == bytes)?;
                data
            }
            _ => return Err(REFUSED.into()),
        };
        require(
            data.schema == "elevenid.installer-acme-initial-rollover/v2"
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
                .all(|value| hash_valid(value)),
        )?;
        Ok((data, bytes))
    }

    /// Validate one link without following its predecessor recursively. The
    /// worker's iterative lineage reader validates every older link separately.
    fn predecessor(
        state: &LockedInspection,
        data: &PermitDataV2,
        prior: &Ledger,
    ) -> Result<Option<AcmeCandidate>> {
        require(
            prior.binding.cycle == data.prior_cycle
                && prior.binding.environment == data.environment
                && prior.binding.installation_id == data.installation_id
                && sha(&serde_json::to_vec(&prior.binding.configuration(state)?)
                    .map_err(|_| REFUSED)?)
                    == data.configuration_sha256
                && prior.binding.renewal.as_ref().is_none_or(|link| {
                    !matches!(link.reason, IssuanceReason::SelectedGenerationDue { .. })
                }),
        )?;
        match &data.predecessor {
            InitialPredecessor::ExpiredCandidate { candidate } => {
                let retained = installer_acme::retained_candidate_material(state, prior)?;
                require(
                    value(&retained)? == *candidate
                        && retained.metadata()["not_after"]
                            .as_u64()
                            .is_some_and(|expiry| expiry <= data.created_at),
                )?;
                Ok(Some(retained))
            }
            InitialPredecessor::ConfirmedInitialTerminal { evidence } => {
                require(
                    evidence.cycle() == data.prior_cycle
                        && evidence.receipt_sha256() == prior.digest,
                )?;
                initial_terminal::require_evidence_local(state, prior, evidence, data.created_at)?;
                let authority = &prior
                    .state
                    .initial_terminal_retry
                    .as_ref()
                    .ok_or(REFUSED)?
                    .authority;
                require(
                    authority.host_intent_sha256 == data.host_intent_sha256
                        && authority.host_prepared_sha256 == data.host_prepared_sha256,
                )?;
                Ok(None)
            }
        }
    }

    fn load(state: &LockedInspection, environment: AcmeEnvironment, cycle: u64) -> Result<Self> {
        let (data, bytes) = Self::parse(state, environment, cycle)?;
        let saved = Ledger::load_cycle(state, environment, data.prior_cycle)?.ok_or(REFUSED)?;
        installer_acme::require_retained_lineage(state, &saved)?;
        let prior = Self::predecessor(state, &data, &saved)?;
        Ok(Self {
            data,
            prior,
            prior_digest: saved.digest,
            digest: sha(&bytes),
        })
    }

    pub(crate) fn require_link(
        state: &LockedInspection,
        binding: &Binding,
        prior: &Ledger,
    ) -> Result<()> {
        let link = binding.renewal.as_ref().ok_or(REFUSED)?;
        let (data, bytes) = Self::parse(state, binding.environment, binding.cycle)?;
        let previous = Self::predecessor(state, &data, prior)?;
        let permit = Self {
            data,
            prior: previous,
            prior_digest: prior.digest.clone(),
            digest: sha(&bytes),
        };
        require(
            permit.digest == link.permit_sha256
                && permit.reason() == link.reason
                && permit.data.prior_cycle == link.prior_cycle
                && permit.prior_digest == link.prior_enrolment_receipt_sha256
                && permit.data.configuration_sha256 == link.configuration_sha256
                && permit.data.created_at == link.created_at,
        )
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

pub(super) fn before_application(state: &LockedInspection) -> Result<()> {
    require(state.journal().phase() == Phase::Provisioning)?;
    // Settings are selected while Verified, before application ownership. Only
    // the journal-authenticated pair may cross this initial-order boundary.
    let has_application_settings = crate::installer_settings::load(state)?.is_some();
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
                    && entry != crate::installer_creation_identity::APPLICATION_RECEIPT
                    && !(has_application_settings
                        && matches!(
                            entry.as_str(),
                            crate::installer_settings::SOURCE | crate::installer_settings::RECORD
                        )))
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

/// At most one new cycle is admitted per invocation. A saved permit is always
/// resumed before allocating another; pending/unknown orders never authorize it.
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
    for cycle in permits.iter().copied() {
        let permit = InitialRolloverPermit::load(state.inspection(), environment, cycle)?;
        if let Some(saved) = Ledger::load_cycle(state.inspection(), environment, cycle)? {
            installer_acme::require_retained_lineage(state.inspection(), &saved)?;
            require(saved.binding.renewal.as_ref().is_some_and(|link| {
                link.permit_sha256 == permit.digest && link.reason == permit.reason()
            }))?;
            if cycle < latest {
                require(matches!(
                    saved.state.stage,
                    Stage::Complete | Stage::Terminal
                ))?;
            }
        } else {
            require(cycle == latest)?;
        }
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
    let observed = installer_acme::now()?;
    installer_acme::require_retained_lineage(state.inspection(), &saved)?;
    let predecessor = match saved.state.stage {
        Stage::Complete => {
            let prior =
                installer_acme::retained_candidate(state.inspection(), environment, latest)?;
            if prior.metadata()["not_after"].as_u64().ok_or(REFUSED)? > observed {
                return Ok(permit);
            }
            InitialPredecessor::ExpiredCandidate {
                candidate: value(&prior)?,
            }
        }
        Stage::Terminal => {
            let Some(evidence) = initial_terminal::due_evidence(
                state.inspection(),
                &prepared.inputs.installation,
                &saved,
                observed,
            )?
            else {
                return Ok(permit);
            };
            InitialPredecessor::ConfirmedInitialTerminal { evidence }
        }
        _ => return Ok(permit),
    };
    let cycle = latest.checked_add(1).ok_or(REFUSED)?;
    let data = PermitDataV2 {
        schema: "elevenid.installer-acme-initial-rollover/v2".into(),
        installation_id: state.journal().installation_id(),
        environment,
        cycle,
        prior_cycle: latest,
        predecessor,
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
