//! Trusted delegated challenge admission into the existing OID4VP Flow owner.
//!
//! This is an internal composition API, not a public start route. The caller
//! supplies a sealed admission from the delegated-authority service; all Flow
//! definition, reference, verifier and request settings come from trusted
//! configuration. Standard verification finalization cannot consume these
//! challenges until the delegated final-use transaction is integrated.

use chrono::{DateTime, SecondsFormat, Utc};
use marty_delegated_authority::{
    DelegationChallengeAdmission, DelegationFlowContextV1, DelegationOid4vpChallenge,
    PrincipalType, DELEGATION_FLOW_CONTEXT_KEY,
};
use mmf_push::WebhookDestinationRegistry;
use serde_json::json;
use uuid::Uuid;

use crate::{
    defined_verification::prepare_admitted_defined_verification_start, definition_references,
    presentation_request::load_frozen_flow_presentation_request, validate_definition_references,
    FlowDefinitionRecord, FlowInstanceRecord, FlowProviderRegistry, PostgresFlowRepository,
    VerificationDefinitionBinding, VerificationRequestResponse, VerificationStartContext,
    VerificationStartOptions,
};

/// The protocol verifier audience is separate from the delegated operation's
/// domain audience. Freeze it behind Flow's existing reserved-context boundary.
pub(crate) const DELEGATION_VERIFIER_CLIENT_ID_KEY: &str =
    "_marty_delegation_verifier_client_id_v1";
const PREPARATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

#[derive(Clone)]
pub struct DelegatedVerificationStartConfiguration {
    pub definition: VerificationDefinitionBinding,
    pub issuer_did: String,
    pub public_base_url: String,
    pub allow_http_loopback: bool,
    pub options: VerificationStartOptions,
}

#[derive(Clone)]
pub struct FlowDelegatedVerificationStarter {
    repository: PostgresFlowRepository,
    providers: FlowProviderRegistry,
    configuration: DelegatedVerificationStartConfiguration,
    preparation_timeout: std::time::Duration,
}

/// Errors retain the service-issued challenge identifier for reconciliation.
/// A storage error can include an ambiguous COMMIT outcome; it does not prove
/// that no row exists, and callers must not blindly issue another challenge.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum FlowDelegationStartError {
    #[error("FLOW.DELEGATION_ADMISSION_REJECTED: {challenge_id}")]
    Admission { challenge_id: Uuid },
    #[error("FLOW.DELEGATION_CONFIGURATION_UNAVAILABLE: {challenge_id}")]
    Configuration { challenge_id: Uuid },
    #[error("FLOW.DELEGATION_PREPARATION_REJECTED: {challenge_id}")]
    Preparation { challenge_id: Uuid },
    #[error("FLOW.DELEGATION_START_STORAGE: {challenge_id}")]
    Storage { challenge_id: Uuid },
    #[error("FLOW.DELEGATION_START_CONFLICT: {challenge_id}")]
    Conflict { challenge_id: Uuid },
}

impl FlowDelegatedVerificationStarter {
    pub fn new(
        repository: PostgresFlowRepository,
        providers: FlowProviderRegistry,
        configuration: DelegatedVerificationStartConfiguration,
    ) -> Self {
        Self {
            repository,
            providers,
            configuration,
            preparation_timeout: PREPARATION_TIMEOUT,
        }
    }

    /// Return the wallet request only after its guarded database transaction
    /// committed. Request construction/signing and nonce generation retain the
    /// existing Flow owners; no request-body-to-private-context path is exposed.
    pub async fn start(
        &self,
        admission: DelegationChallengeAdmission,
    ) -> Result<VerificationRequestResponse, FlowDelegationStartError> {
        let challenge_id = admission.binding().challenge_id;
        // Only the read/preparation phase is cancelled on timeout. Never wrap
        // COMMIT in this deadline or mistake cancellation for proven rollback.
        let deadline = tokio::time::Instant::now() + self.preparation_timeout;
        let mut prepared = tokio::time::timeout_at(deadline, self.prepare(admission))
            .await
            .map_err(|_| FlowDelegationStartError::Preparation { challenge_id })??;
        if tokio::time::Instant::now() >= deadline {
            return Err(FlowDelegationStartError::Preparation { challenge_id });
        }
        let inserted = self
            .repository
            .save_delegated_verification_start(&mut prepared)
            .await
            .map_err(|_| FlowDelegationStartError::Storage { challenge_id })?;
        if !inserted {
            return Err(FlowDelegationStartError::Conflict { challenge_id });
        }
        Ok(prepared.response)
    }

    pub(crate) async fn prepare(
        &self,
        admission: DelegationChallengeAdmission,
    ) -> Result<PreparedDelegatedVerificationStart, FlowDelegationStartError> {
        let challenge_id = admission.binding().challenge_id;
        admission
            .check_live()
            .map_err(|_| FlowDelegationStartError::Admission { challenge_id })?;
        let definition = self
            .repository
            .definition(&self.configuration.definition.definition_id)
            .await
            .map_err(|_| FlowDelegationStartError::Storage { challenge_id })?
            .ok_or(FlowDelegationStartError::Configuration { challenge_id })?;
        prepare_delegated_verification_start(
            &self.providers,
            &self.configuration,
            definition,
            admission,
        )
        .await
    }
}

/// Sealed preparation accepted only by the guarded persistence path. Neither
/// the request URI nor its mutable record is exposed before durable admission.
pub(crate) struct PreparedDelegatedVerificationStart {
    admission: DelegationChallengeAdmission,
    definition: FlowDefinitionRecord,
    instance: FlowInstanceRecord,
    response: VerificationRequestResponse,
}

impl PreparedDelegatedVerificationStart {
    pub(crate) fn instance(&self) -> &FlowInstanceRecord {
        &self.instance
    }
    pub(crate) fn definition(&self) -> &FlowDefinitionRecord {
        &self.definition
    }

    /// Re-resolve the current grant/consent/session before entering the database
    /// transaction. Evidence refresh can shorten this start, never extend it.
    pub(crate) async fn revalidate(&mut self) -> Result<(), FlowDelegationStartError> {
        let challenge_id = self.admission.binding().challenge_id;
        self.admission
            .revalidate()
            .await
            .map_err(|_| FlowDelegationStartError::Admission { challenge_id })?;
        self.cap_expiry()?;
        self.check_live_at(
            self.admission
                .check_live()
                .map_err(|_| FlowDelegationStartError::Admission { challenge_id })?,
        )
    }

    fn cap_expiry(&mut self) -> Result<(), FlowDelegationStartError> {
        let challenge_id = self.admission.binding().challenge_id;
        let expiry = self
            .instance
            .expires_at
            .ok_or(FlowDelegationStartError::Preparation { challenge_id })?
            .min(self.admission.valid_until());
        self.instance.expires_at = Some(expiry);
        self.response.expires_at = expiry.to_rfc3339_opts(SecondsFormat::AutoSi, true);
        Ok(())
    }

    pub(crate) fn check_live_at(&self, now: DateTime<Utc>) -> Result<(), FlowDelegationStartError> {
        let binding = self.admission.binding();
        let challenge_id = binding.challenge_id;
        let invalid = || FlowDelegationStartError::Preparation { challenge_id };
        self.admission
            .check_live_at(now)
            .map_err(|_| FlowDelegationStartError::Admission { challenge_id })?;
        self.admission
            .check_live()
            .map_err(|_| FlowDelegationStartError::Admission { challenge_id })?;
        let stored = validate_delegation_snapshot(&self.instance).map_err(|_| invalid())?;
        if &stored.binding != binding
            || self.instance.flow_definition_id != self.definition.id
            || self.instance.organization_id != self.definition.organization_id
            || self
                .instance
                .expires_at
                .is_none_or(|expiry| expiry <= now || expiry > self.admission.valid_until())
            || self.instance.created_at < self.admission.admitted_at()
            || self.instance.created_at > now
            || self.instance.started_at != Some(self.instance.created_at)
            || self.instance.completed_at.is_some()
            || self.instance.result.is_some()
            || self.instance.error.is_some()
            || self.instance.status != marty_verification::flow::FlowInstanceStatus::AwaitingWallet
        {
            return Err(invalid());
        }
        Ok(())
    }
}

/// Validate only the persisted binding's shape and immutable Flow association.
/// This does not create an admission or validate cryptographic proof.
pub(crate) fn validate_delegation_snapshot(
    instance: &FlowInstanceRecord,
) -> Result<DelegationOid4vpChallenge, ()> {
    let binding: DelegationFlowContextV1 = serde_json::from_value(
        instance
            .context
            .get(DELEGATION_FLOW_CONTEXT_KEY)
            .cloned()
            .ok_or(())?,
    )
    .map_err(|_| ())?;
    binding.validate().map_err(|_| ())?;
    let verifier = instance
        .context
        .get(DELEGATION_VERIFIER_CLIENT_ID_KEY)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(())?;
    if binding.challenge_id.to_string() != instance.id
        || binding.organization_id.to_string() != instance.organization_id
        || instance
            .context
            .get("oid4vp_client_id")
            .and_then(serde_json::Value::as_str)
            != Some(verifier)
    {
        return Err(());
    }
    let frozen = load_frozen_flow_presentation_request(instance).map_err(|_| ())?;
    Ok(DelegationOid4vpChallenge {
        binding,
        verifier_client_id: verifier.to_owned(),
        nonce: frozen.nonce,
        expires_at: instance.expires_at.ok_or(())?,
    })
}

async fn prepare_delegated_verification_start(
    providers: &FlowProviderRegistry,
    configuration: &DelegatedVerificationStartConfiguration,
    definition: FlowDefinitionRecord,
    mut admission: DelegationChallengeAdmission,
) -> Result<PreparedDelegatedVerificationStart, FlowDelegationStartError> {
    let challenge_id = admission.binding().challenge_id;
    admission
        .revalidate()
        .await
        .map_err(|_| FlowDelegationStartError::Admission { challenge_id })?;
    let now = admission
        .check_live()
        .map_err(|_| FlowDelegationStartError::Admission { challenge_id })?;
    let binding = admission.binding();
    let unavailable = || FlowDelegationStartError::Configuration { challenge_id };
    if configuration.definition.organization_id != binding.organization_id.to_string() {
        return Err(unavailable());
    }
    configuration
        .definition
        .validate(&definition)
        .map_err(|_| unavailable())?;
    validate_definition_references(
        providers,
        &binding.actor.id,
        &definition.organization_id,
        &definition_references(&definition),
        true,
    )
    .await
    .map_err(|_| unavailable())?;
    let prepared = prepare_admitted_defined_verification_start(
        providers,
        &WebhookDestinationRegistry::default(),
        &definition,
        &configuration.definition,
        &configuration.issuer_did,
        &configuration.options,
        VerificationStartContext {
            public_base_url: &configuration.public_base_url,
            allow_http_loopback: configuration.allow_http_loopback,
            principal_id: &binding.actor.id,
            now,
        },
        challenge_id,
        None,
    )
    .await
    .map_err(|_| FlowDelegationStartError::Preparation { challenge_id })?;
    let mut instance = prepared.instance;
    let verifier = instance
        .context
        .get("oid4vp_client_id")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(FlowDelegationStartError::Preparation { challenge_id })?
        .to_owned();
    instance.context[DELEGATION_FLOW_CONTEXT_KEY] = serde_json::to_value(binding)
        .map_err(|_| FlowDelegationStartError::Preparation { challenge_id })?;
    instance.context[DELEGATION_VERIFIER_CLIENT_ID_KEY] = json!(verifier);
    // Attribute this proof Flow to its actual delegate. The represented subject
    // and grantor remain separate roles in the authoritative grant.
    instance.subject_id = Some(binding.actor.id.clone());
    instance.subject_type = match binding.actor.principal_type {
        PrincipalType::User => "user",
        PrincipalType::Organization => "organization",
        PrincipalType::ServiceAccount => "service_account",
        PrincipalType::MachineIdentity => "machine_identity",
        PrincipalType::External => "external",
    }
    .into();
    let mut prepared = PreparedDelegatedVerificationStart {
        admission,
        definition,
        instance,
        response: prepared.response,
    };
    prepared.revalidate().await?;
    Ok(prepared)
}

#[cfg(test)]
#[path = "delegation_start_tests.rs"]
mod tests;
