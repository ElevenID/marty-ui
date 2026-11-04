//! Fixed diagnostic labels around the existing ACME host admission checks.
//! A report is a passive observation, never authority to replay or continue.

use super::*;

/// Closed codes are shared by native refusal messages and read-only status.
/// Inner errors may contain private paths or backend responses and are discarded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Check {
    Configuration,
    Context,
    InitialInputs,
    InitialIngress,
    OpenbaoConnection,
    OpenbaoServer,
    ResponderModel,
    RuntimeContext,
    PreparedRead,
    PreparedDecode,
    IntentRead,
    IntentDecode,
    InstallationPath,
    ApplicationPreparation,
    ApplicationProvenance,
    PublicRenewal,
    StagingTrust,
    Schemas,
    InstallationIdentity,
    ConfigurationBinding,
    ReleaseRuntime,
    PreparationState,
    ServiceSelection,
    EnvironmentPath,
    EvidenceFingerprints,
    ApplicationProofDigest,
    PriorReceipt,
    Projection,
    AuthorityDigests,
    IngressKey,
    BundleFiles,
    OperatorBinding,
    PriorOperation,
    ResponderOperation,
    ResponderReceipt,
    CurrentInputReceipt,
    HistoricalInputReceipt,
    InputCustody,
    CustodyJob,
    CredentialsJob,
    Http01Port,
    EnvironmentDerivation,
    ComposeLayers,
    BoundInputs,
    RuntimeInputs,
    Resources,
    Unchanged,
    PresenceEvidence,
    PreparedRecordMissing,
    ContinuationBinding,
    RuntimeModel,
    LiveResources,
    RuntimeHealth,
}

impl Check {
    pub(super) fn code(self) -> &'static str {
        match self {
            Self::Configuration => "configuration",
            Self::Context => "context",
            Self::InitialInputs => "initial_inputs",
            Self::InitialIngress => "initial_ingress",
            Self::OpenbaoConnection => "openbao_connection",
            Self::OpenbaoServer => "openbao_server",
            Self::ResponderModel => "responder_model",
            Self::RuntimeContext => "runtime_context",
            Self::PreparedRead => "prepared_read",
            Self::PreparedDecode => "prepared_decode",
            Self::IntentRead => "intent_read",
            Self::IntentDecode => "intent_decode",
            Self::InstallationPath => "installation_path",
            Self::ApplicationPreparation => "application_preparation",
            Self::ApplicationProvenance => "application_provenance",
            Self::PublicRenewal => "public_renewal",
            Self::StagingTrust => "staging_trust",
            Self::Schemas => "schemas",
            Self::InstallationIdentity => "installation_identity",
            Self::ConfigurationBinding => "configuration_binding",
            Self::ReleaseRuntime => "release_runtime",
            Self::PreparationState => "preparation_state",
            Self::ServiceSelection => "service_selection",
            Self::EnvironmentPath => "environment_path",
            Self::EvidenceFingerprints => "evidence_fingerprints",
            Self::ApplicationProofDigest => "application_proof_digest",
            Self::PriorReceipt => "prior_receipt",
            Self::Projection => "projection",
            Self::AuthorityDigests => "authority_digests",
            Self::IngressKey => "ingress_key",
            Self::BundleFiles => "bundle_files",
            Self::OperatorBinding => "operator_binding",
            Self::PriorOperation => "prior_operation",
            Self::ResponderOperation => "responder_operation",
            Self::ResponderReceipt => "responder_receipt",
            Self::CurrentInputReceipt => "current_input_receipt",
            Self::HistoricalInputReceipt => "historical_input_receipt",
            Self::InputCustody => "input_custody",
            Self::CustodyJob => "custody_job",
            Self::CredentialsJob => "credentials_job",
            Self::Http01Port => "http01_port",
            Self::EnvironmentDerivation => "environment_derivation",
            Self::ComposeLayers => "compose_layers",
            Self::BoundInputs => "bound_inputs",
            Self::RuntimeInputs => "runtime_inputs",
            Self::Resources => "resources",
            Self::Unchanged => "unchanged",
            Self::PresenceEvidence => "presence_evidence",
            Self::PreparedRecordMissing => "prepared_record_missing",
            Self::ContinuationBinding => "continuation_binding",
            Self::RuntimeModel => "runtime_model",
            Self::LiveResources => "live_resources",
            Self::RuntimeHealth => "runtime_health",
        }
    }

    pub(super) fn refusal(self) -> String {
        format!("{REFUSED}; check={}", self.code())
    }
}

pub(super) type Checked<T> = std::result::Result<T, Check>;

pub(super) fn checked<T>(check: Check, action: impl FnOnce() -> Result<T>) -> Checked<T> {
    action().map_err(|_| check)
}

pub(super) fn checkpoint<T>(check: Check, action: impl FnOnce() -> Result<T>) -> Result<T> {
    checked(check, action).map_err(Check::refusal)
}

fn report(
    state: &'static str,
    check: Option<Check>,
    intent_present: bool,
    prepared_present: bool,
    initial: Option<Checked<()>>,
) -> Value {
    let initial_preparation = match initial {
        None => serde_json::json!({"checked":false,"matches":false,"check":null}),
        Some(Ok(())) => serde_json::json!({"checked":true,"matches":true,"check":null}),
        Some(Err(check)) => serde_json::json!({"checked":true,"matches":false,"check":check}),
    };
    serde_json::json!({
        "schema":"elevenid.installer-acme-host-status/v1",
        "state":state,"check":check,
        "intent_present":intent_present,"prepared_present":prepared_present,
        "initial_preparation":initial_preparation,
        "read_only":true,"runtime_observed":false,
        "continuation_authorized":false,"setup_replay_authorized":false,
        "activation_performed":false,"installation_ready":false
    })
}

fn inspect_status(state: &LockedInspection) -> Value {
    let hosting = match checked(Check::Configuration, || installer_hosting::load(state)) {
        Ok(hosting) => hosting,
        Err(check) => return report("refused", Some(check), false, false, None),
    };
    let Some(parameters) = hosting.as_ref().and_then(|hosting| hosting.acme_parameters()) else {
        return report("not_selected", None, false, false, None);
    };
    let environment = parameters.environment();
    let names = [
        name(environment, "intent"),
        name(environment, "prepared"),
        name(environment, "custody"),
        name(environment, "credentials"),
        CUSTODY_PLAN.into(),
        CREDENTIAL_PLAN.into(),
        format!("compose-{RESPONDER_OPERATION}-result.json"),
    ];
    let present = match checked(Check::PresenceEvidence, || {
        names
            .iter()
            .map(|name| {
                state
                    .diagnostic_record(name, true)
                    .map(|value| value.is_some())
            })
            .collect::<Result<Vec<_>>>()
    }) {
        Ok(present) => present,
        Err(check) => return report("refused", Some(check), false, false, None),
    };
    if !present.iter().any(|value| *value) {
        return report("not_started", None, false, false, None);
    }
    if !present[1] {
        return report(
            "incomplete",
            Some(Check::PreparedRecordMissing),
            present[0],
            false,
            None,
        );
    }
    if let Err(check) = inspect_retained_setup(state, false) {
        return report("refused", Some(check), present[0], true, None);
    }
    // Application activity may legitimately change the original storage proof.
    // Keep historical setup provenance distinct from the pristine initial gate.
    let initial = inspect_retained_setup(state, true).map(|_| ());
    report("prepared", None, present[0], true, Some(initial))
}

/// Uses the same admission owner as continuation and maintenance. This reports
/// retained evidence only; no Docker, OpenBao, credentials or CA request occurs.
pub(crate) fn preparation_status(state: &LockedInspection) -> Value {
    let report_value = inspect_status(state);
    match checked(Check::Unchanged, || state.require_unchanged()) {
        Ok(()) => report_value,
        Err(check) => report("refused", Some(check), false, false, None),
    }
}

#[cfg(test)]
#[path = "installer_acme_host_diagnostics_tests.rs"]
mod tests;
