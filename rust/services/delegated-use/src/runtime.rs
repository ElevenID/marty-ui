//! Explicit serving composition for the selected managed KEY/EXACT_OPERATION
//! profile. Local identity, authority, policy and evidence owners remain concrete;
//! the production constructor only supplies existing protected remote adapters.

use std::{fmt, sync::Arc, time::Duration};

use async_trait::async_trait;
use axum::Router;
use chrono::{DateTime, Utc};
use marty_delegated_authority::{
    approval::organization_principal,
    machine_auth::MartyMachineOid4vpProofVerifier,
    machine_credentials::MartyNestedJwtVcMachineCredentialVerifier,
    machine_evidence::{
        AuditedMachineOid4vpProofVerifier, PgMachineAuthenticationEvidenceRepository,
    },
    machine_policy_source::{
        AuditedMmfMachineAuthorizationVerifier, OrganizationMachineCedarPolicySource,
        PgMachineAuthorizationEvidenceRepository,
    },
    organization_machine_state::OrganizationMachineAuthenticationStateSource,
    use_http::{
        delegated_use_command_router, DelegationUseHttpAuthenticator, DelegationUseHttpState,
    },
    use_receipt_http::{delegated_use_receipt_router, DelegationUseReceiptHttpState},
    AuthorityMode, ConfiguredConsentEvidenceVerifier, ConstraintMode, ConstraintVerificationError,
    DelegatedDecisionReceiptIssuer, DelegatedDecisionReceiptSigner, DelegationAuthorityService,
    DelegationChallengeIssuer, DelegationCommandCaller, DelegationGrant, DelegationUseAuthorizer,
    DelegationUseCommandAuthorizer, DelegationUseCommandError, DelegationUseCommandService,
    DelegationUseIntent, DelegationUseRequest, ExternalConstraintVerifier,
    HttpManagedDelegatedReceiptSigner, MmfCedarEvaluator, OrganizationDelegationCedarPolicySource,
    OrganizationDelegationUseCommandAuthorizer, OrganizationRepresentationAuthorityProvider,
    PgConsentEvidenceProvider, PgDelegationGrantRepository, PgDelegationUseRepository, Principal,
    SystemDelegationClock, VerifiedConstraintEvidence, VerifiedDelegationCommandAccess,
    DELEGATED_DECISION_JWS_PURPOSE,
};
use marty_flow::{
    delegated_use_flow_router, resolve_flow_presentation_policy, FlowDefinitionRecord,
    FlowDelegatedReadProviders, FlowDelegatedUseHttpState, FlowDelegatedUseIngress,
    FlowDelegatedUseOwner, FlowDelegationOid4vpChallengeStore, FlowProviderRegistry,
    HttpFlowReferenceProvider, HttpSigningProvider, PostgresFlowRepository,
    VerificationDefinitionBinding,
};
use marty_machine_credential_source::PgOwnedMachineJwtVcAuthoritySource;
use marty_organization::{
    delegation_use_policy::PgDelegationUsePolicySource,
    machine_authorization::PgMachineAuthorizationPolicySource,
    machine_registry::{MachineRegistrySelection, PgMachineRegistrySource},
    machine_use_access::{MachineUseAccessSelection, PgMachineUseAccessSource},
    postgres::PostgresOrganizationStore,
};
use marty_signing_grant::{minter::GrantMinter, SigningOrigin};
use uuid::Uuid;

use crate::{config::DelegatedUseHostConfig, database::DatabasePools};

const READINESS_TIMEOUT: Duration = Duration::from_secs(15);

/// Stable diagnostics never contain connection strings, credentials, proofs or
/// upstream response bodies. The owner-specific errors remain private.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("delegated use runtime is unavailable: {0}")]
pub struct DelegatedUseRuntimeError(pub &'static str);

type Result<T> = std::result::Result<T, DelegatedUseRuntimeError>;

struct RemoteReadiness {
    signing: Arc<HttpSigningProvider>,
    references: Arc<HttpFlowReferenceProvider>,
}

/// A verified local composition. No migration owner, confirmation producer,
/// authority producer or human administration credential is held here.
pub struct DelegatedUseRuntime {
    pools: DatabasePools,
    grant_repository: PgDelegationGrantRepository,
    use_repository: PgDelegationUseRepository,
    state: Arc<OrganizationMachineAuthenticationStateSource>,
    credentials: Arc<PgOwnedMachineJwtVcAuthoritySource>,
    machine_policy: Arc<OrganizationMachineCedarPolicySource>,
    delegated_policy: Arc<OrganizationDelegationCedarPolicySource>,
    machine_proof: Arc<AuditedMachineOid4vpProofVerifier>,
    access: Arc<OrganizationDelegationUseCommandAuthorizer>,
    commands: Arc<DelegationUseCommandService>,
    ingress: Arc<FlowDelegatedUseIngress>,
    authenticator: Arc<DelegationUseHttpAuthenticator>,
    providers: FlowProviderRegistry,
    receipt_signer: Arc<dyn DelegatedDecisionReceiptSigner>,
    receipt_issuer: Principal,
    organization_id: Uuid,
    definition: VerificationDefinitionBinding,
    remote: Option<RemoteReadiness>,
}

impl fmt::Debug for DelegatedUseRuntime {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.debug_struct("DelegatedUseRuntime")
            .field("organization_id", &self.organization_id)
            .finish_non_exhaustive()
    }
}

impl DelegatedUseRuntime {
    /// Production entrypoint. This uses actual PostgreSQL owners, protected
    /// Flow read/signing adapters and a pinned managed receipt signer. Startup
    /// does not migrate, grant privileges, mint signing grants or sign a request.
    pub async fn connect(configuration: &DelegatedUseHostConfig) -> Result<Self> {
        let pools = DatabasePools::connect(&configuration.database_urls)
            .await
            .map_err(|_| DelegatedUseRuntimeError("database connections"))?;
        pools
            .readiness()
            .await
            .map_err(|_| DelegatedUseRuntimeError("database role boundary"))?;
        let (providers, remote) = connect_flow_providers(configuration).await?;
        let selected = &configuration.receipt_signing;
        let minter = GrantMinter::for_managed_openbao(
            &selected.grant_openbao_origin,
            SigningOrigin::DelegatedDecision,
            selected.mint_token_file.clone(),
        )
        .map_err(|_| DelegatedUseRuntimeError("receipt grant authority"))?;
        let receipt_signer = Arc::new(
            HttpManagedDelegatedReceiptSigner::new(
                &selected.origin,
                selected.read_credential.clone(),
                selected.sign_credential.clone(),
                selected.key.clone(),
                minter,
            )
            .map_err(|_| DelegatedUseRuntimeError("managed receipt signer"))?,
        );
        let mut runtime = Self::assemble(configuration, pools, providers, receipt_signer).await?;
        runtime.remote = Some(remote);
        runtime.readiness().await?;
        Ok(runtime)
    }

    /// Explicit trusted composition seam for owner acceptance tests and hosts
    /// with independently qualified remote adapters. All PostgreSQL authority
    /// owners and privilege checks remain concrete. Injected providers establish
    /// no production qualification. The executable calls `connect`, and this
    /// method still constructs only the selected mutual-TLS HTTP authenticator.
    pub async fn assemble(
        configuration: &DelegatedUseHostConfig,
        pools: DatabasePools,
        providers: FlowProviderRegistry,
        receipt_signer: Arc<dyn DelegatedDecisionReceiptSigner>,
    ) -> Result<Self> {
        validate_selection(configuration, &providers)?;
        pools
            .readiness()
            .await
            .map_err(|_| DelegatedUseRuntimeError("database role boundary"))?;
        let clock = Arc::new(SystemDelegationClock);
        let grant_repository = PgDelegationGrantRepository::new(pools.runtime_reader.clone());
        let consent = ConfiguredConsentEvidenceVerifier::new(
            [configuration.approval_configuration.consent_profile()],
            Arc::new(PgConsentEvidenceProvider::new(pools.runtime_reader.clone())),
            Arc::new(
                OrganizationRepresentationAuthorityProvider::from_read_sources(
                    PostgresOrganizationStore::new(pools.organization_authority.clone()),
                    pools.runtime_reader.clone(),
                    configuration.approval_configuration.clone(),
                    clock,
                ),
            ),
        )
        .map_err(|_| DelegatedUseRuntimeError("consent selection"))?;
        let lifecycle = Arc::new(
            DelegationAuthorityService::new(
                Arc::new(grant_repository.clone()),
                Arc::new(consent),
                configuration.authority.clone(),
            )
            .map_err(|_| DelegatedUseRuntimeError("managed authority selection"))?,
        );
        let organization_id = configuration.organization_id;
        let deployment_id = configuration.deployment_profile_id;
        let access = Arc::new(OrganizationDelegationUseCommandAuthorizer::new(
            PgMachineUseAccessSource::new(
                pools.access_source.clone(),
                MachineUseAccessSelection::new(organization_id, deployment_id)
                    .map_err(|_| DelegatedUseRuntimeError("use access selection"))?,
            ),
        ));
        let state = Arc::new(OrganizationMachineAuthenticationStateSource::new(
            PgMachineRegistrySource::new(
                pools.registry_source.clone(),
                MachineRegistrySelection::new(organization_id, deployment_id)
                    .map_err(|_| DelegatedUseRuntimeError("registry selection"))?,
            ),
        ));
        let credentials = Arc::new(
            PgOwnedMachineJwtVcAuthoritySource::connect(
                pools.credential_trust.clone(),
                pools.credential_status.clone(),
                pools.credential_evidence.clone(),
            )
            .await
            .map_err(|_| DelegatedUseRuntimeError("credential sources"))?,
        );
        let machine_policy = Arc::new(
            OrganizationMachineCedarPolicySource::new(
                PgMachineAuthorizationPolicySource::new(pools.machine_policy_source.clone()),
                PgMachineAuthorizationEvidenceRepository::new(
                    pools.machine_policy_evidence.clone(),
                ),
                organization_id,
                deployment_id,
            )
            .map_err(|_| DelegatedUseRuntimeError("machine policy selection"))?,
        );
        let flow_repository = PostgresFlowRepository::new(pools.flow_reader.clone());
        let machine_verifier = Arc::new(MartyMachineOid4vpProofVerifier::new(
            Arc::new(FlowDelegationOid4vpChallengeStore::new(
                flow_repository.clone(),
            )),
            state.clone(),
            Some(Arc::new(MartyNestedJwtVcMachineCredentialVerifier::new(
                credentials.clone(),
            ))),
            // A MAP requiring attestation fails the existing machine gate when
            // this optional provider is absent. No positive placeholder exists.
            None,
            Some(Arc::new(AuditedMmfMachineAuthorizationVerifier::new(
                machine_policy.clone(),
            ))),
        ));
        let machine_proof = Arc::new(AuditedMachineOid4vpProofVerifier::new(
            machine_verifier,
            PgMachineAuthenticationEvidenceRepository::new(pools.machine_audit.clone()),
        ));
        let delegated_policy = Arc::new(
            OrganizationDelegationCedarPolicySource::new(
                PgDelegationUsePolicySource::new(pools.delegation_policy_source.clone()),
                organization_id,
                configuration.delegation_policy_id,
            )
            .map_err(|_| DelegatedUseRuntimeError("delegated policy selection"))?,
        );
        let evaluation = Arc::new(DelegationUseAuthorizer::new(
            lifecycle.clone(),
            machine_proof.clone(),
            Arc::new(UnsupportedExternalConstraints),
            Arc::new(MmfCedarEvaluator::new(delegated_policy.clone())),
        ));
        let challenges = Arc::new(
            DelegationChallengeIssuer::new(
                lifecycle.clone(),
                None,
                configuration.challenge_lifetime_seconds,
            )
            .map_err(|_| DelegatedUseRuntimeError("challenge selection"))?,
        );
        let receipt_issuer = configuration.receipt_signing.issuer.clone();
        let receipts = Arc::new(
            DelegatedDecisionReceiptIssuer::new(
                receipt_signer.clone(),
                receipt_issuer.clone(),
                configuration.receipt_lifetime_seconds,
            )
            .map_err(|_| DelegatedUseRuntimeError("receipt selection"))?,
        );
        let flow = Arc::new(
            FlowDelegatedUseOwner::new(
                flow_repository,
                providers.clone(),
                configuration.flow_start.clone(),
            )
            .await
            .map_err(|_| DelegatedUseRuntimeError("Flow transaction owner"))?,
        );
        let use_repository = PgDelegationUseRepository::new(pools.use_writer.clone());
        let commands = Arc::new(DelegationUseCommandService::new(
            use_repository.clone(),
            lifecycle,
            challenges,
            evaluation,
            receipts,
            flow,
            Arc::new(ExactOperationAccess {
                inner: access.clone(),
            }),
        ));
        let ingress = Arc::new(
            FlowDelegatedUseIngress::new(
                PostgresFlowRepository::new(pools.flow_ingress.clone()),
                providers.clone(),
                access.clone(),
                configuration.public_base_url.clone(),
                configuration.request_options.clone(),
            )
            .await
            .map_err(|_| DelegatedUseRuntimeError("Flow ingress"))?,
        );
        let authenticator = Arc::new(
            DelegationUseHttpAuthenticator::mutual_tls(
                organization_id,
                configuration.workload_bindings.clone(),
            )
            .map_err(|_| DelegatedUseRuntimeError("workload identity selection"))?,
        );
        let runtime = Self {
            pools,
            grant_repository,
            use_repository,
            state,
            credentials,
            machine_policy,
            delegated_policy,
            machine_proof,
            access,
            commands,
            ingress,
            authenticator,
            providers,
            receipt_signer,
            receipt_issuer,
            organization_id,
            definition: configuration.flow_start.definition.clone(),
            remote: None,
        };
        runtime.readiness().await?;
        Ok(runtime)
    }

    /// Recheck actual roles, schemas, source boundaries and selected read-only
    /// remote dependencies. This operation performs no signing or data repair.
    pub async fn readiness(&self) -> Result<()> {
        tokio::time::timeout(READINESS_TIMEOUT, self.check_readiness())
            .await
            .map_err(|_| DelegatedUseRuntimeError("readiness deadline"))?
    }

    async fn check_readiness(&self) -> Result<()> {
        self.pools
            .readiness()
            .await
            .map_err(|_| DelegatedUseRuntimeError("database role boundary"))?;
        self.grant_repository
            .readiness()
            .await
            .map_err(|_| DelegatedUseRuntimeError("grant schema"))?;
        self.use_repository
            .readiness()
            .await
            .map_err(|_| DelegatedUseRuntimeError("use schema"))?;
        self.state
            .readiness()
            .await
            .map_err(|_| DelegatedUseRuntimeError("registry source"))?;
        self.credentials
            .readiness()
            .await
            .map_err(|_| DelegatedUseRuntimeError("credential sources"))?;
        self.machine_policy
            .readiness()
            .await
            .map_err(|_| DelegatedUseRuntimeError("machine policy source"))?;
        self.delegated_policy
            .readiness()
            .await
            .map_err(|_| DelegatedUseRuntimeError("delegated policy source"))?;
        self.machine_proof
            .readiness()
            .await
            .map_err(|_| DelegatedUseRuntimeError("machine audit"))?;
        self.access
            .readiness()
            .await
            .map_err(|_| DelegatedUseRuntimeError("use access source"))?;
        marty_flow::validate_delegated_use_lock_schema(&self.pools.flow_reader)
            .await
            .map_err(|_| DelegatedUseRuntimeError("Flow serving lock schema"))?;
        self.ingress
            .readiness()
            .await
            .map_err(|_| DelegatedUseRuntimeError("Flow ingress"))?;
        let definition = PostgresFlowRepository::new(self.pools.flow_reader.clone())
            .definition(&self.definition.definition_id)
            .await
            .map_err(|_| DelegatedUseRuntimeError("Flow definition"))?
            .ok_or(DelegatedUseRuntimeError("Flow definition"))?;
        validate_host_definition(&self.definition, &definition)?;
        let policy_id = definition
            .presentation_policy_id
            .as_deref()
            .ok_or(DelegatedUseRuntimeError("Flow policy selection"))?;
        resolve_flow_presentation_policy(
            &self.providers,
            policy_id,
            &self.organization_id.to_string(),
        )
        .await
        .map_err(|_| DelegatedUseRuntimeError("Flow policy source"))?;
        let key = self
            .receipt_signer
            .resolve_key(
                self.organization_id,
                &self.receipt_issuer,
                DELEGATED_DECISION_JWS_PURPOSE,
            )
            .await
            .map_err(|_| DelegatedUseRuntimeError("receipt key selection"))?;
        if key.issuer != self.receipt_issuer
            || key.purpose != DELEGATED_DECISION_JWS_PURPOSE
            || !matches!(key.algorithm.as_str(), "ES256" | "EdDSA")
        {
            return Err(DelegatedUseRuntimeError("receipt key selection"));
        }
        if let Some(remote) = &self.remote {
            remote
                .signing
                .health_check()
                .await
                .map_err(|_| DelegatedUseRuntimeError("request signing service"))?;
            remote
                .references
                .health_check()
                .await
                .map_err(|_| DelegatedUseRuntimeError("Flow reference services"))?;
        }
        Ok(())
    }

    /// Only internal commands, original receipts and protected request/proof routes are mounted.
    /// The host installs authenticated health/readiness probes separately.
    pub fn router(&self) -> Router {
        delegated_use_command_router(DelegationUseHttpState::with_authenticator(
            self.commands.clone(),
            self.authenticator.clone(),
        ))
        .merge(delegated_use_flow_router(FlowDelegatedUseHttpState::new(
            self.ingress.clone(),
            self.authenticator.clone(),
        )))
        .merge(delegated_use_receipt_router(
            DelegationUseReceiptHttpState::with_authenticator(
                self.commands.clone(),
                self.authenticator.clone(),
            ),
        ))
    }

    pub fn commands(&self) -> Arc<DelegationUseCommandService> {
        self.commands.clone()
    }

    pub fn ingress(&self) -> Arc<FlowDelegatedUseIngress> {
        self.ingress.clone()
    }

    pub fn authenticator(&self) -> Arc<DelegationUseHttpAuthenticator> {
        self.authenticator.clone()
    }

    pub async fn close(&self) {
        self.pools.close().await;
    }
}

fn validate_selection(
    configuration: &DelegatedUseHostConfig,
    providers: &FlowProviderRegistry,
) -> Result<()> {
    if configuration.organization_id.is_nil()
        || configuration.deployment_profile_id.is_nil()
        || configuration.delegation_policy_id.is_nil()
        || configuration.approval_configuration.organization_id() != configuration.organization_id
        || configuration.authority.mode != AuthorityMode::Managed
        || configuration.authority.issuer != organization_principal(configuration.organization_id)
        || configuration.flow_start.definition.organization_id
            != configuration.organization_id.to_string()
        || configuration.flow_start.public_base_url != configuration.public_base_url
        || configuration.flow_start.options.request_object != configuration.request_options
        || configuration.flow_start.allow_http_loopback
        || providers.gateway_api_key_actor.is_some()
        || providers.credential_template.is_none()
        || providers.presentation_policy.is_none()
        || providers.signing_identity.is_none()
        || providers.reference_catalog.is_none()
    {
        return Err(DelegatedUseRuntimeError("inconsistent explicit selection"));
    }
    Ok(())
}

fn validate_host_definition(
    selected: &VerificationDefinitionBinding,
    definition: &FlowDefinitionRecord,
) -> Result<()> {
    selected
        .validate(definition)
        .map_err(|_| DelegatedUseRuntimeError("Flow definition selection"))?;
    // These existing catalog routes authorize X-User-ID through human
    // Organization membership. A machine delegate cannot use that identity
    // projection. Keep the selected host closed until a typed read adapter
    // exists; a configured profile must never be silently ignored.
    if definition.trust_profile_id.is_some()
        || definition.deployment_profile_id.is_some()
        || !definition.deployment_profile_ids.is_empty()
    {
        return Err(DelegatedUseRuntimeError(
            "Flow references require a machine read adapter",
        ));
    }
    Ok(())
}

fn request_signing_endpoint(origin: &str) -> Result<url::Url> {
    let origin =
        url::Url::parse(origin).map_err(|_| DelegatedUseRuntimeError("request signing origin"))?;
    if origin.scheme() != "https"
        || origin.host_str().is_none()
        || origin.path() != "/"
        || !origin.username().is_empty()
        || origin.password().is_some()
        || origin.query().is_some()
        || origin.fragment().is_some()
    {
        return Err(DelegatedUseRuntimeError("request signing origin"));
    }
    // The shared Flow adapter accepts the internal API base and appends
    // compat/. Host configuration deliberately accepts only a bare origin.
    origin
        .join("internal/")
        .map_err(|_| DelegatedUseRuntimeError("request signing origin"))
}

async fn connect_flow_providers(
    configuration: &DelegatedUseHostConfig,
) -> Result<(FlowProviderRegistry, RemoteReadiness)> {
    let read = FlowDelegatedReadProviders::connect(
        &configuration.credential_template_grpc_target,
        &configuration.presentation_policy_grpc_target,
        &configuration.workload_client_tls,
        &configuration.service_token,
    )
    .await
    .map_err(|_| DelegatedUseRuntimeError("Flow read transports"))?;
    let selected = &configuration.request_signing;
    let minter = GrantMinter::for_managed_openbao(
        &selected.grant_openbao_origin,
        SigningOrigin::FlowWalletRequest,
        selected.mint_token_file.clone(),
    )
    .map_err(|_| DelegatedUseRuntimeError("request grant authority"))?;
    let signing_endpoint = request_signing_endpoint(&selected.origin)?;
    let signing = Arc::new(
        HttpSigningProvider::new(
            signing_endpoint.as_str(),
            &selected.read_credential,
            &selected.sign_credential,
        )
        .map_err(|_| DelegatedUseRuntimeError("request signing selection"))?
        .with_grant_minter(minter),
    );
    let references = Arc::new(
        HttpFlowReferenceProvider::new(
            &configuration.issuance_native_url,
            &configuration.issuance_api_key,
            &configuration.credential_template_url,
            &configuration.trust_profile_url,
            &configuration.deployment_profile_url,
            Some(&configuration.service_token),
        )
        .map_err(|_| DelegatedUseRuntimeError("Flow reference selection"))?,
    );
    let providers = FlowProviderRegistry {
        credential_template: Some(Arc::new(read.credential_template)),
        presentation_policy: Some(Arc::new(read.presentation_policy)),
        signing_identity: Some(signing.clone()),
        reference_catalog: Some(references.clone()),
        ..Default::default()
    };
    Ok((
        providers,
        RemoteReadiness {
            signing,
            references,
        },
    ))
}

/// EXACT_OPERATION is evaluated by the existing authorizer. This source must
/// never return positive evidence for a consumer-owned external profile.
struct UnsupportedExternalConstraints;

#[async_trait]
impl ExternalConstraintVerifier for UnsupportedExternalConstraints {
    async fn verify(
        &self,
        _grant: &DelegationGrant,
        _request: &DelegationUseRequest,
        _now: DateTime<Utc>,
    ) -> std::result::Result<VerifiedConstraintEvidence, ConstraintVerificationError> {
        Err(ConstraintVerificationError)
    }
}

struct ExactOperationAccess {
    inner: Arc<OrganizationDelegationUseCommandAuthorizer>,
}

#[async_trait]
impl DelegationUseCommandAuthorizer for ExactOperationAccess {
    async fn authorize(
        &self,
        caller: &DelegationCommandCaller,
        intent: &DelegationUseIntent,
        grant: &DelegationGrant,
        now: DateTime<Utc>,
    ) -> std::result::Result<VerifiedDelegationCommandAccess, DelegationUseCommandError> {
        if grant.terms.constraints.mode != ConstraintMode::ExactOperation {
            return Err(DelegationUseCommandError::AccessDenied);
        }
        self.inner.authorize(caller, intent, grant, now).await
    }

    async fn authorize_recovery(
        &self,
        caller: &DelegationCommandCaller,
        original_grant: &DelegationGrant,
        now: DateTime<Utc>,
    ) -> std::result::Result<VerifiedDelegationCommandAccess, DelegationUseCommandError> {
        self.inner
            .authorize_recovery(caller, original_grant, now)
            .await
    }
}

#[cfg(test)]
mod serving_selection_tests {
    use super::*;
    use marty_flow::{create_definition_record, parse_request, DefinitionStatus};
    use serde_json::json;

    #[test]
    fn request_signing_uses_the_actual_internal_compatibility_routes() {
        for origin in ["https://keys.example", "https://keys.example:8443/"] {
            let endpoint = request_signing_endpoint(origin).unwrap();
            for operation in ["resolve-issuer-did", "issuer-dids/sign"] {
                let target = endpoint.join(&format!("compat/{operation}")).unwrap();
                assert_eq!(target.path(), format!("/internal/compat/{operation}"));
                assert_eq!(target.origin(), url::Url::parse(origin).unwrap().origin());
            }
        }
        for origin in [
            "http://keys.example",
            "https://keys.example/internal",
            "https://user:secret@keys.example",
            "https://keys.example?redirect=elsewhere",
            "https://keys.example#issuer",
        ] {
            assert!(request_signing_endpoint(origin).is_err());
        }
    }

    #[test]
    fn machine_host_rejects_human_only_catalog_references() {
        let mut definition = create_definition_record(
            parse_request(json!({
                "organization_id": Uuid::new_v4(),
                "name": "Host selection",
                "flow_type": "oid4vp_presentation",
                "presentation_policy_id": "policy-1"
            }))
            .unwrap(),
            Utc::now(),
        )
        .unwrap();
        definition.status = DefinitionStatus::Active;
        let selected = VerificationDefinitionBinding {
            organization_id: definition.organization_id.clone(),
            definition_id: definition.id.clone(),
            version: definition.version,
        };
        validate_host_definition(&selected, &definition).unwrap();
        for unsupported in ["trust", "deployment", "legacy_deployment"] {
            let mut definition = definition.clone();
            match unsupported {
                "trust" => definition.trust_profile_id = Some("trust-1".into()),
                "deployment" => definition
                    .deployment_profile_ids
                    .push("deployment-1".into()),
                _ => definition.deployment_profile_id = Some("deployment-1".into()),
            }
            // These remain valid generic Flow definitions. The selected host
            // must reject the unsupported principal projection explicitly.
            selected.validate(&definition).unwrap();
            assert_eq!(
                validate_host_definition(&selected, &definition),
                Err(DelegatedUseRuntimeError(
                    "Flow references require a machine read adapter"
                )),
            );
        }
    }
}
