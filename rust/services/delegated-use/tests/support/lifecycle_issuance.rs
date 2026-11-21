//! Fresh bootstrap credential through real Issuance owner state transitions,
//! native holder proof verification and managed Signing Keys HTTPS signing.
//! Only the selected no-status template's status/lifecycle dependencies are
//! fixture ports. This does not qualify admin activation or status publication.
use std::{path::PathBuf, sync::Arc, time::Duration};

use async_trait::async_trait;
use marty_credential_template::{
    CredentialTemplate, PostgresCredentialTemplateStore, TemplateStatus,
};
use marty_issuance_service::{
    client_auth::RegisteredClientAuthenticator,
    credential::{
        AllocatedCredentialStatus, CredentialIssuanceDisposition, CredentialIssuanceError,
        CredentialIssuanceService, CredentialLifecycle, CredentialPorts, CredentialRepository,
        CredentialRequest, CredentialTransaction, CredentialTransactionStatus, IssuedCredential,
        IssuerContext, UuidNotificationIdGenerator,
    },
    credential_builder::HttpCredentialBuilder,
    credential_issuer::{HttpIssuerContextResolver, NativeCredentialProofVerifier},
    credential_postgres::PostgresCredentialRepository,
    dpop::MartyDpopProofVerifier,
    ephemeral_postgres::PostgresProofNonceRepository,
    initiation::{
        InitiationDependencyError, InitiationOrganizationValidator, InitiationPorts,
        InitiationRelatedResourceValidator, InitiationRequest,
        InitiationRevocationProfileValidator, InitiationService, InitiationTemplate,
        InitiationTemplateResolver, OrganizationValidation, SecureInitiationSeedGenerator,
        SystemInitiationClock,
    },
    initiation_dependencies::PostgresInitiationApplicationClaimsResolver,
    proof_nonce::{ProofNonceService, SecureProofNonceGenerator},
    token_exchange::{
        MartyTokenGenerator, TokenExchangeRequest, TokenExchangeService, PRE_AUTHORIZED_GRANT,
    },
    token_postgres::PostgresTokenExchangeRepository,
};
use marty_organization::{postgres::PostgresOrganizationStore, OrganizationStatus};
use marty_signing_grant::{minter::GrantMinter, SigningOrigin};
use p256::ecdsa::SigningKey;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

use super::{
    super::live_support::{setting, READ_KEY, SIGN_KEY},
    SigningKeys,
};
use crate::support::{
    crypto::{compact_jws, public_jwk},
    TestResult,
};

const ISSUER_BASE: &str = "https://machine-issuance.example.test";
const TOKEN_HMAC_KEY: &str = "separate-live-lifecycle-issuance-token-hmac-000000001";

pub struct IssuedMachineCredential {
    pub credential_id: Uuid,
    pub transaction_id: String,
    pub compact: String,
    pub issuer: String,
    pub kid: String,
    pub jwk: Value,
}

pub async fn issue(
    keys: &SigningKeys,
    pool: &PgPool,
    organization: Uuid,
    template: &CredentialTemplate,
    subject: &str,
    machine_key: &SigningKey,
) -> TestResult<IssuedMachineCredential> {
    let metadata = Arc::new(BootstrapMetadata {
        pool: pool.clone(),
        organization,
        template: template.clone(),
        issuer: keys.credential.issuer.clone(),
        subject: subject.into(),
    });
    metadata.validate_template(template)?;
    let repository = Arc::new(PostgresCredentialRepository::new(
        pool.clone(),
        TOKEN_HMAC_KEY,
    ));
    let token_repository = Arc::new(PostgresTokenExchangeRepository::new(
        pool.clone(),
        TOKEN_HMAC_KEY,
    ));
    let resolver = Arc::new(HttpIssuerContextResolver::new_for_native_owner(
        keys.server.origin().parse()?,
        Some(READ_KEY),
        Duration::from_secs(5),
    )?);
    let initiation = InitiationService::new(
        InitiationPorts {
            repository: repository.clone(),
            organizations: metadata.clone(),
            clients: token_repository.clone(),
            templates: metadata.clone(),
            revocation_profiles: metadata.clone(),
            applications: Arc::new(PostgresInitiationApplicationClaimsResolver::new(
                pool.clone(),
            )),
            related_resources: metadata.clone(),
            issuer_resolver: resolver.clone(),
            seeds: Arc::new(SecureInitiationSeedGenerator),
            clock: Arc::new(SystemInitiationClock),
        },
        ISSUER_BASE,
    )?;
    let reservation = initiation
        .initiate(
            &InitiationRequest {
                organization_id: organization.to_string(),
                issuer_did: keys.credential.issuer.clone(),
                credential_template_id: Some(template.id.clone()),
                subject_did: Some(subject.into()),
                delivery_mode: "wallet_only".into(),
                credential_subject: Some(json!({"id":subject})),
                ..Default::default()
            },
            None,
        )
        .await?;
    assert!(reservation.created);
    assert_eq!(
        reservation.transaction.status,
        CredentialTransactionStatus::Pending
    );
    let transaction_id = reservation.transaction.id.clone();
    let token_service = TokenExchangeService::new(
        token_repository.clone(),
        Arc::new(RegisteredClientAuthenticator::new(token_repository)),
        Arc::new(MartyDpopProofVerifier),
        Arc::new(MartyTokenGenerator),
        ISSUER_BASE,
    );
    let access = token_service
        .exchange(
            &TokenExchangeRequest {
                grant_type: PRE_AUTHORIZED_GRANT.into(),
                pre_authorized_code: Some(reservation.transaction.pre_authorized_code),
                ..Default::default()
            },
            None,
            &format!("{ISSUER_BASE}/oid4vci/token"),
        )
        .await?;
    let nonces = Arc::new(PostgresProofNonceRepository::new(pool.clone()));
    let nonce = ProofNonceService::new(nonces.clone(), Arc::new(SecureProofNonceGenerator))
        .issue()
        .await?
        .c_nonce;
    let proof = compact_jws(
        machine_key,
        &json!({"typ":"openid4vci-proof+jwt","alg":"ES256","jwk":public_jwk(machine_key)}),
        &json!({"iss":subject,"aud":format!("{ISSUER_BASE}/org/{organization}"),
            "nonce":nonce,"iat":chrono::Utc::now().timestamp()}),
    );
    let request: CredentialRequest = serde_json::from_value(json!({
        "credential_configuration_id":template.credential_type,"proofs":{"jwt":[proof]}
    }))?;
    let minter = GrantMinter::for_managed_openbao(
        &setting("MARTY_TEST_OPENBAO_URL"),
        SigningOrigin::IssuanceCredential,
        PathBuf::from(setting("MARTY_TEST_LIFECYCLE_ISSUANCE_MINT_TOKEN_FILE")),
    )?;
    let builder = HttpCredentialBuilder::new_for_native_owner_with_grant(
        keys.server.origin().parse()?,
        Some(SIGN_KEY),
        Duration::from_secs(5),
        minter,
    )?
    .with_machine_nested_vc2_jwt_profile();
    let service = CredentialIssuanceService::new(
        CredentialPorts {
            repository: repository.clone(),
            nonce_repository: nonces,
            dpop_verifier: Arc::new(MartyDpopProofVerifier),
            proof_verifier: Arc::new(NativeCredentialProofVerifier),
            issuer_resolver: resolver,
            builder: Arc::new(builder),
            lifecycle: metadata,
            notification_ids: Arc::new(UuidNotificationIdGenerator),
        },
        ISSUER_BASE,
    );
    let outcome = service
        .issue_with_outcome(
            &request,
            Some(&format!("Bearer {}", access.access_token)),
            None,
            &format!("{ISSUER_BASE}/oid4vci/credential"),
        )
        .await?;
    assert_eq!(
        outcome.disposition,
        CredentialIssuanceDisposition::Committed
    );
    let issued = outcome
        .issued_credential
        .ok_or("fresh managed issuance did not commit")?;
    assert_eq!(issued.transaction_id, transaction_id);
    assert_eq!(issued.subject_did.as_deref(), Some(subject));
    assert_eq!(issued.issuer_did, keys.credential.issuer);
    let stored = repository
        .credential_by_transaction(&transaction_id)
        .await?
        .ok_or("managed credential was not persisted by Issuance")?;
    assert_eq!(stored.id, issued.id);
    assert_eq!(stored.credential, issued.credential);
    let transaction = repository
        .transaction_by_id(&transaction_id)
        .await?
        .ok_or("managed issuance transaction missing")?;
    assert_eq!(transaction.status, CredentialTransactionStatus::Issued);
    let credential_id: Uuid = issued
        .id
        .strip_prefix("urn:uuid:")
        .ok_or("managed machine credential identifier is not a UUID URN")?
        .parse()?;
    Ok(IssuedMachineCredential {
        credential_id,
        transaction_id,
        compact: issued.credential,
        issuer: keys.credential.issuer.clone(),
        kid: keys.credential.kid.clone(),
        jwk: keys.credential.jwk.clone(),
    })
}

/// Deliberately closed bootstrap dependencies. Actual Organization/Template
/// stores supply metadata; no-status lifecycle approval cannot accept another
/// template, organization, issuer, subject, status profile, or delivery mode.
struct BootstrapMetadata {
    pool: PgPool,
    organization: Uuid,
    template: CredentialTemplate,
    issuer: String,
    subject: String,
}
impl BootstrapMetadata {
    fn validate_template(
        &self,
        template: &CredentialTemplate,
    ) -> Result<(), InitiationDependencyError> {
        if template != &self.template
            || template.organization_id != self.organization.to_string()
            || template.status != TemplateStatus::Active
            || template.credential_type != "MachineCredential"
            || template.credential_payload_format != "VC_JWT"
            || template.jwt_vc_profile.is_some()
            || template.issuer_did.as_deref() != Some(self.issuer.as_str())
            || template.issuer_algorithm.as_deref() != Some("ES256")
            || template.verification_prerequisite.is_some()
            || template.revocation_profile_id.is_some()
            || template.application_template_id.is_some()
            || !template.wallet_configs.is_empty()
            || template.validity_rules.renewable
            || template.validity_rules.default_validity_days != 1
            || template.issuance_protocol != "OID4VCI_PRE_AUTH"
        {
            return Err(InitiationDependencyError::Invalid(
                "unselected machine bootstrap template".into(),
            ));
        }
        Ok(())
    }
    fn validate_transaction(
        &self,
        transaction: &CredentialTransaction,
    ) -> Result<(), CredentialIssuanceError> {
        if transaction.organization_id != self.organization.to_string()
            || transaction.credential_template_id != self.template.id
            || transaction.issuer_did.as_deref() != Some(self.issuer.as_str())
            || transaction.subject_did.as_deref() != Some(self.subject.as_str())
            || transaction.credential_type.as_deref() != Some("MachineCredential")
            || transaction.credential_payload_format != "jwt_vc_json"
            || transaction.jwt_vc_profile.is_some()
            || transaction.jwt_vc_signing_timing.is_some()
            || transaction.issuance_intent.is_some()
            || transaction.revocation_profile_id.is_some()
            || transaction.application_id.is_some()
            || transaction.renewal_of_credential_id.is_some()
            || transaction.delivery_mode != "wallet_only"
            || transaction.validity_days != 1
            || transaction.renewable
            || !transaction.wallet_configs.is_empty()
        {
            return Err(CredentialIssuanceError::LifecycleUnavailable(
                "unselected machine bootstrap transaction".into(),
            ));
        }
        Ok(())
    }
}
#[async_trait]
impl InitiationOrganizationValidator for BootstrapMetadata {
    async fn validate(&self, id: &str) -> OrganizationValidation {
        if id != self.organization.to_string() {
            return OrganizationValidation::NotFound;
        }
        match PostgresOrganizationStore::new(self.pool.clone())
            .organization_by_id(self.organization)
            .await
        {
            Ok(Some(organization)) if organization.status == OrganizationStatus::Active => {
                OrganizationValidation::Found
            }
            _ => OrganizationValidation::NotFound,
        }
    }
}
#[async_trait]
impl InitiationTemplateResolver for BootstrapMetadata {
    async fn resolve(&self, id: &str) -> Result<InitiationTemplate, InitiationDependencyError> {
        if id != self.template.id {
            return Err(InitiationDependencyError::NotFound);
        }
        let template = PostgresCredentialTemplateStore::new(self.pool.clone())
            .template_by_id(id)
            .await
            .map_err(|_| InitiationDependencyError::Unavailable)?
            .ok_or(InitiationDependencyError::NotFound)?;
        self.validate_template(&template)?;
        Ok(InitiationTemplate {
            credential_type: template.credential_type,
            vct: Some(template.vct),
            credential_payload_format: "jwt_vc_json".into(),
            template_version: template.version,
            issuance_protocol: template.issuance_protocol,
            issuer_did: template.issuer_did,
            issuer_algorithm: template.issuer_algorithm,
            validity_days: i64::from(template.validity_rules.default_validity_days),
            not_before_offset_seconds: i64::from(template.validity_rules.not_before_offset_seconds),
            renewable: false,
            ..Default::default()
        })
    }
}
#[async_trait]
impl InitiationRevocationProfileValidator for BootstrapMetadata {
    async fn validate_active(
        &self,
        organization: &str,
        profile: Option<&str>,
    ) -> Result<(), InitiationDependencyError> {
        if organization != self.organization.to_string() || profile.is_some() {
            return Err(InitiationDependencyError::Invalid(
                "only the selected no-status bootstrap is available".into(),
            ));
        }
        Ok(())
    }
}
#[async_trait]
impl InitiationRelatedResourceValidator for BootstrapMetadata {
    async fn validate(&self, _: &Value) -> Result<(), InitiationDependencyError> {
        Err(InitiationDependencyError::Invalid(
            "machine bootstrap accepts no external credential document".into(),
        ))
    }
}
#[async_trait]
impl CredentialLifecycle for BootstrapMetadata {
    async fn ensure_ready(
        &self,
        transaction: &CredentialTransaction,
        issuer: &IssuerContext,
    ) -> Result<(), CredentialIssuanceError> {
        self.validate_transaction(transaction)?;
        if issuer.issuer_did != self.issuer || issuer.algorithm != "ES256" {
            return Err(CredentialIssuanceError::LifecycleUnavailable(
                "unselected machine bootstrap issuer".into(),
            ));
        }
        Ok(())
    }
    async fn allocate_status(
        &self,
        transaction: &CredentialTransaction,
        id: &str,
        format: &str,
    ) -> Result<AllocatedCredentialStatus, CredentialIssuanceError> {
        self.validate_transaction(transaction)?;
        if format != "jwt_vc_json"
            || transaction.reserved_credential_id.as_deref() != Some(id)
            || transaction.status != CredentialTransactionStatus::Signing
        {
            return Err(CredentialIssuanceError::LifecycleUnavailable(
                "machine bootstrap has no matching signing claim".into(),
            ));
        }
        Ok(AllocatedCredentialStatus::default())
    }
    async fn after_issued(
        &self,
        transaction: &CredentialTransaction,
        credential: &IssuedCredential,
        format: &str,
    ) -> Result<(), CredentialIssuanceError> {
        self.validate_transaction(transaction)?;
        if format != "jwt_vc_json"
            || credential.transaction_id != transaction.id
            || credential.organization_id != transaction.organization_id
            || credential.issuer_did != self.issuer
            || credential.subject_did.as_deref() != Some(self.subject.as_str())
            || credential.revocation_profile_id.is_some()
            || !credential.status_list_entries.is_empty()
        {
            return Err(CredentialIssuanceError::LifecycleUnavailable(
                "machine bootstrap completion mismatch".into(),
            ));
        }
        Ok(())
    }
}
