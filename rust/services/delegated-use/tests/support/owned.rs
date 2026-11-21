//! Real owner records for the selected exact-operation profile. Only remote
//! presentation metadata, transport authentication and signing custody are
//! explicit fixtures; current permissions/consent/policy are actual owners.
use std::sync::{atomic::AtomicUsize, Arc};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Duration, Utc};
use marty_delegated_authority::{
    approval::{organization_principal, user_principal},
    command_postgres::PgOrganizationCommandService,
    ApprovalAdapterPin, ApprovalDecision, AuthenticatedApprovalSession, Authority, AuthorityMode,
    Binding, BindingMethod, CommandGrantReference, ConstraintMode, Constraints,
    DelegationCommandResult, DelegationGrant, ExplicitApprovalConfirmation, GrantTerms,
    OrganizationApprovalConfiguration, PgOrganizationApprovalService,
    PgOrganizationAuthorityProducer, Principal, PrincipalType, RetainedUseChallenge,
    SystemDelegationClock, DELEGATION_COMMAND_PROFILE,
};
use marty_flow::{
    create_definition_record, parse_request, DefinitionStatus,
    DelegatedVerificationStartConfiguration, PostgresFlowRepository, VerificationDefinitionBinding,
    VerificationStartOptions,
};
use marty_oid4vp_contract::machine_jwt_vc::MACHINE_NESTED_JWT_AUTHORIZATIONS;
use marty_organization::{
    catalog::seed_system_roles,
    delegation_use_policy::{DelegationUsePolicyInput, DelegationUsePolicyOwner},
    machine_authorization::{MachineAuthorizationPolicyInput, MachineAuthorizationPolicyOwner},
    machine_registry::{MachineRegistryDocuments, MachineRegistryService},
    machine_use_access::{MachineUseAccessInput, MachineUseAccessOwner, MachineUsePermission},
    postgres::PostgresOrganizationStore,
    CedarPolicyDocument, ForwardedPrincipal, JoinMechanism, Organization, OrganizationCreate,
    OrganizationType,
};
use marty_principal_runtime_binding::{jwk_sha256_thumbprint, ThumbprintEncoding};
use marty_trust_profile::{
    CascadeRevocationPolicy, ComplianceStatus, IssuerEntity, IssuerEntityComplianceStatus,
    IssuerEntityType, PostgresTrustProfileRepository, TrustProfile, TrustProfileIssuer,
    TrustProfileRepository, TrustProfileStatus, TrustProfileType, TrustPurpose,
    TrustRelationshipStatus,
};
use p256::ecdsa::SigningKey;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use super::{
    crypto::{
        compact_jws, public_jwk, signing_key, FlowPorts, ReceiptSigner, PRESENTATION_POLICY,
        RECEIPT_ISSUER, REQUEST_ISSUER,
    },
    database::Database,
    TestResult,
};

pub const ACTION: &str = "urn:example:read";
pub const RESOURCE: &str = "urn:example:dataset";
pub const AUDIENCE: &str = "https://consumer.example.test";
pub const OPERATION_PROFILE: &str = "urn:example:operation:v1";
pub const VERIFIER_CLIENT_ID: &str = "decentralized_identifier:did:web:delegated-host.example.test";
pub const PUBLIC_BASE: &str = "https://delegated-host.example.test";

pub fn now() -> DateTime<Utc> {
    DateTime::from_timestamp_micros(Utc::now().timestamp_micros()).unwrap()
}

pub fn operation_digest() -> String {
    format!("sha256:{}", "b3".repeat(32))
}

pub fn all_rights() -> Vec<MachineUsePermission> {
    vec![
        MachineUsePermission::StartUse,
        MachineUsePermission::FinalizeUse,
        MachineUsePermission::RecoverResult,
        MachineUsePermission::RetrieveRequest,
        MachineUsePermission::SubmitProof,
    ]
}

pub struct Owned {
    pub organization: Uuid,
    pub user: Uuid,
    pub human: ForwardedPrincipal,
    pub deployment: Uuid,
    pub machine_id: Uuid,
    pub principal: Principal,
    pub machine_key: SigningKey,
    pub machine_jwk: Value,
    pub machine_thumbprint: String,
    pub credential: String,
    pub delegated_policy: Uuid,
    pub flow: DelegatedVerificationStartConfiguration,
    pub approval: OrganizationApprovalConfiguration,
    pub authority: Authority,
    pub ports: Arc<FlowPorts>,
    pub receipts: Arc<ReceiptSigner>,
}

impl Owned {
    pub async fn seed(admin: &PgPool) -> TestResult<Self> {
        let time = now();
        let user = Uuid::new_v4();
        let (organization, member) = Organization::create(OrganizationCreate {
            name: format!("Delegated host acceptance {}", Uuid::new_v4()),
            owner_id: user.to_string(),
            org_type: OrganizationType::Enterprise,
            display_name: None,
            description: None,
            join_mechanism: JoinMechanism::Invite,
            requires_approval: false,
            is_discoverable: false,
            now: time,
        })?;
        let store = PostgresOrganizationStore::new(admin.clone());
        store.save_organization(&organization).await?;
        store.save_member(&member).await?;
        let roles = seed_system_roles(&store, organization.id, time).await?;
        store
            .set_member_roles(member.id, &[roles["owner"].id])
            .await?;
        let human = ForwardedPrincipal::User {
            user_id: user.to_string(),
        };
        let machine_policy = MachineAuthorizationPolicyOwner::new(store.clone());
        let policy = machine_policy
            .create(
                organization.id,
                &human,
                MachineAuthorizationPolicyInput {
                    name: "Exact host machine authentication".into(),
                    description: None,
                    policies: vec![CedarPolicyDocument {
                        policy_id: "selected-machine".into(),
                        effect: "permit".into(),
                        cedar_text: format!(
                            "permit(principal is MartyMachine::Principal, action == MartyMachine::Action::\"urn:marty:machine:authenticate\", resource is MartyMachine::Identity) when {{ context.grant_revision > 0 && context.requested_action == \"{ACTION}\" }};"
                        ),
                        description: None,
                        enabled: true,
                    }],
                },
            )
            .await?;
        machine_policy
            .activate(organization.id, &human, policy.policy_set_id, 1)
            .await?;
        let use_policy = DelegationUsePolicyOwner::new(store.clone());
        let delegated_policy = use_policy
            .create(
                organization.id,
                &human,
                DelegationUsePolicyInput {
                    name: "Exact host delegated operation".into(),
                    description: None,
                    actions: vec![ACTION.into()],
                    policies: vec![CedarPolicyDocument {
                        policy_id: "selected-use".into(),
                        effect: "permit".into(),
                        cedar_text: format!(
                            "permit(principal is MartyDelegatedUse::Principal, action == MartyDelegatedUse::Action::\"{ACTION}\", resource == MartyDelegatedUse::Resource::\"{RESOURCE}\") when {{ context.audience == \"{AUDIENCE}\" && context.delegate_proof_verified && context.consent_and_authority_verified }};"
                        ),
                        description: None,
                        enabled: true,
                    }],
                },
            )
            .await?;
        use_policy
            .activate(organization.id, &human, delegated_policy.policy_id, 1)
            .await?;

        let machine_key = signing_key();
        let machine_jwk = public_jwk(&machine_key);
        let principal = Principal {
            principal_type: PrincipalType::MachineIdentity,
            id: format!(
                "did:jwk:{}",
                URL_SAFE_NO_PAD.encode(machine_jwk.to_string())
            ),
        };
        let thumb = jwk_sha256_thumbprint(&serde_json::to_vec(&machine_jwk)?)?;
        let machine_thumbprint = thumb
            .reencode(ThumbprintEncoding::MipSha256Hex)
            .encoded_value()
            .to_owned();
        let key = json!({
            "basis":"JWK_RFC7638_SHA256","encoding":"BASE64URL_SHA256",
            "value":thumb.reencode(ThumbprintEncoding::Base64urlSha256).encoded_value()
        });
        let (trust_profile, credential_id, credential, credential_issuer, credential_public_jwk) =
            credential(admin, organization.id, &principal.id).await?;
        let deployment = Uuid::new_v4();
        let machine_id = Uuid::new_v4();
        let runtime = format!("urn:test:host-runtime:{machine_id}");
        let documents = json!({
            "configuration":{
                "profile":"urn:marty:principal-runtime-binding-configuration:v1",
                "organization_id":organization.id,"deployment_profile_id":deployment,"principal":principal,
                "authentication_source":{"issuer":principal.id,"subject":principal.id},
                "allowed_audiences":[VERIFIER_CLIENT_ID],
                "runtime":{"kind":"MANAGED","instance_ref":runtime,"machine_identity_id":machine_id,
                    "active_key_id":"host-machine-key","stored_thumbprint_encoding":"MIP_SHA256_HEX"},
                "expected_key_algorithm":"ES256","expected_key_thumbprint":key,"shared_runtime":false
            },
            "record":{
                "profile":"urn:marty:principal-runtime-binding:v1","organization_id":organization.id,
                "principal":principal,"authentication":{"issuer":principal.id,"subject":principal.id,
                    "audience":VERIFIER_CLIENT_ID,"key_algorithm":"ES256","key_thumbprint":key},
                "runtime":{"kind":"MANAGED","instance_ref":runtime,"machine_identity_id":machine_id}
            },
            "machine":{
                "id":machine_id,"organization_id":organization.id,"machine_id":principal.id,
                "display_name":"Actual host machine","machine_type":"SECURE_PROCESSING_RUNTIME","status":"ACTIVE",
                "identity_keys":[{"key_id":"host-machine-key","thumbprint":machine_thumbprint,"algorithm":"ES256",
                    "status":"ACTIVE","public_key_jwk":machine_jwk,"valid_from":time-Duration::minutes(1),
                    "valid_until":time+Duration::hours(1)}],
                "assignments":{"deployment_profile_id":deployment,"operator_organization_id":organization.id},
                "credential_ids":[credential_id],"created_at":time-Duration::minutes(1)
            },
            "map":{
                "id":Uuid::new_v4(),"organization_id":organization.id,"name":"Selected host machine MAP",
                "trust_profile_id":trust_profile,"required_credential_types":["MachineCredential","RuntimeMembership"],
                "allowed_machine_types":["SECURE_PROCESSING_RUNTIME"],
                "machine_binding":{"binding_methods":["MACHINE_KEY"],"proof_profiles":["OID4VP_VERIFIABLE_PRESENTATION"],
                    "proof_freshness":{"challenge_required":true,"audience_binding_required":true,
                        "replay_detection_required":true,"max_proof_age_seconds":120}},
                "authorization_policy_set_id":policy.policy_set_id,
                "status":"ACTIVE","created_at":time-Duration::minutes(1)
            }
        });
        MachineRegistryService::new(store.clone())
            .register(
                organization.id,
                &human,
                MachineRegistryDocuments {
                    binding_record: serde_json::to_vec(&documents["record"])?,
                    binding_configuration: serde_json::to_vec(&documents["configuration"])?,
                    machine_identity: serde_json::to_vec(&documents["machine"])?,
                    machine_authentication_policy: serde_json::to_vec(&documents["map"])?,
                },
            )
            .await?;
        MachineUseAccessOwner::new(store)
            .grant(
                organization.id,
                &human,
                machine_id,
                MachineUseAccessInput {
                    permissions: all_rights(),
                    valid_from: time - Duration::seconds(1),
                    valid_until: time + Duration::hours(1),
                },
            )
            .await?;

        let mut definition = create_definition_record(
            parse_request(json!({
                "organization_id":organization.id,
                "name":"Selected host delegated verification",
                "flow_type":"oid4vp_presentation",
                "presentation_policy_id":PRESENTATION_POLICY
            }))?,
            time,
        )?;
        definition.status = DefinitionStatus::Active;
        PostgresFlowRepository::new(admin.clone())
            .save_definition(&definition)
            .await?;
        let mut options = VerificationStartOptions::default();
        options.request_object.strict_client_metadata = true;
        let flow = DelegatedVerificationStartConfiguration {
            definition: VerificationDefinitionBinding {
                organization_id: organization.id.to_string(),
                definition_id: definition.id.clone(),
                version: definition.version,
            },
            issuer_did: REQUEST_ISSUER.into(),
            public_base_url: PUBLIC_BASE.into(),
            allow_http_loopback: false,
            options,
        };
        let approval = OrganizationApprovalConfiguration::new(
            organization.id,
            organization_principal(organization.id),
            ApprovalAdapterPin {
                profile: "urn:test:host-organization-approval:v1".into(),
                version: "1.0.0".into(),
                artifact_digest: format!("sha256:{}", "a7".repeat(32)),
            },
            120,
            300,
            15,
        )?;
        let authority = Authority {
            mode: AuthorityMode::Managed,
            issuer: organization_principal(organization.id),
            status_ref: "https://delegated-host.example.test/status".into(),
            source_profile: None,
            source_evidence_ref: None,
            source_evidence_digest: None,
            source_expires_at: None,
        };
        let ports = Arc::new(FlowPorts {
            organization: organization.id,
            principal_id: principal.id.clone(),
            credential_issuer: credential_issuer.clone(),
            credential_public_jwk,
            key: signing_key(),
            calls: AtomicUsize::new(0),
        });
        let receipts = Arc::new(ReceiptSigner {
            organization: organization.id,
            issuer: Principal {
                principal_type: PrincipalType::Organization,
                id: RECEIPT_ISSUER.into(),
            },
            key: signing_key(),
            calls: AtomicUsize::new(0),
        });
        Ok(Self {
            organization: organization.id,
            user,
            human,
            deployment,
            machine_id,
            principal,
            machine_key,
            machine_jwk,
            machine_thumbprint,
            credential,
            delegated_policy: delegated_policy.policy_id,
            flow,
            approval,
            authority,
            ports,
            receipts,
        })
    }

    pub fn session(&self) -> TestResult<AuthenticatedApprovalSession> {
        let time = now();
        Ok(
            AuthenticatedApprovalSession::from_authenticated_gateway_context(
                self.organization,
                self.user,
                format!("urn:marty:session:sha256:{}", "6b".repeat(32)),
                time,
                time + Duration::seconds(25),
            )?,
        )
    }

    pub fn terms(&self) -> GrantTerms {
        let time = now();
        GrantTerms {
            grantor: user_principal(self.user),
            subject: organization_principal(self.organization),
            delegate: self.principal.clone(),
            binding: Binding {
                method: BindingMethod::Key,
                key_thumbprint: Some(self.machine_thumbprint.clone()),
                session_ref: None,
                establishment_evidence_ref: None,
            },
            actions: vec![ACTION.into()],
            audiences: vec![AUDIENCE.into()],
            resources: vec![RESOURCE.into()],
            valid_from: time - Duration::seconds(1),
            valid_until: time + Duration::minutes(10),
            subdelegation_allowed: false,
            constraints: Constraints {
                mode: ConstraintMode::ExactOperation,
                request_profile: Some(OPERATION_PROFILE.into()),
                request_digest: Some(operation_digest()),
                profile: None,
                document_ref: None,
                document_digest: None,
                evaluator: None,
            },
        }
    }

    pub async fn grant(&self, db: &Database) -> TestResult<DelegationGrant> {
        // Human gateway authentication remains a fixture. Its current RBAC,
        // exact review/confirmation, independent authority and grant command
        // mutations use their actual separately credentialed owners.
        let lifecycle = self.lifecycle(db)?;
        lifecycle.readiness().await?;
        let create = serde_json::to_vec(&json!({
            "profile":DELEGATION_COMMAND_PROFILE,"command":"CREATE_GRANT",
            "command_id":Uuid::new_v4(),"terms":self.terms()
        }))?;
        let pending = lifecycle.execute(&self.session()?, &create).await?;
        let DelegationCommandResult::GrantSnapshot { grant } = pending.result;
        let producer = Arc::new(PgOrganizationAuthorityProducer::new(
            PostgresOrganizationStore::new(db.organization_authority.clone()),
            db.authority_writer.clone(),
            self.approval.clone(),
            Arc::new(SystemDelegationClock),
        ));
        let approvals = PgOrganizationApprovalService::new(
            db.runtime_reader.clone(),
            db.consent_writer.clone(),
            producer,
            self.approval.clone(),
            Arc::new(SystemDelegationClock),
        )?;
        approvals.readiness().await?;
        let reference = CommandGrantReference {
            id: grant.id,
            revision: grant.revision,
            terms_digest: grant.terms_digest.clone(),
        };
        let session = self.session()?;
        let review = approvals.review(&session, &reference).await?;
        let confirmation = approvals
            .confirm(
                &session,
                grant.id,
                review.review_id,
                &ExplicitApprovalConfirmation {
                    confirmation_id: Uuid::new_v4(),
                    terms_digest: grant.terms_digest.clone(),
                    decision: ApprovalDecision::Confirm,
                },
            )
            .await?;
        let approve = serde_json::to_vec(&json!({
            "profile":DELEGATION_COMMAND_PROFILE,"command":"APPROVE_GRANT",
            "command_id":Uuid::new_v4(),"grant":reference,
            "confirmation_id":confirmation.confirmation_id
        }))?;
        let active = lifecycle.execute(&self.session()?, &approve).await?;
        let DelegationCommandResult::GrantSnapshot { grant } = active.result;
        assert_eq!(grant.status, marty_delegated_authority::GrantStatus::Active);
        assert_eq!(grant.revision, 2);
        Ok(grant)
    }

    pub fn lifecycle(&self, db: &Database) -> TestResult<PgOrganizationCommandService> {
        Ok(PgOrganizationCommandService::new(
            db.lifecycle_writer.clone(),
            db.runtime_reader.clone(),
            PostgresOrganizationStore::new(db.organization_authority.clone()),
            self.approval.clone(),
            self.authority.clone(),
            Arc::new(SystemDelegationClock),
        )?)
    }

    pub async fn revoke_grant(&self, db: &Database, grant: &DelegationGrant) -> TestResult<()> {
        let raw = serde_json::to_vec(&json!({
            "profile":DELEGATION_COMMAND_PROFILE,"command":"REVOKE_GRANT",
            "command_id":Uuid::new_v4(),
            "grant":{"id":grant.id,"revision":grant.revision,"terms_digest":grant.terms_digest}
        }))?;
        let response = self.lifecycle(db)?.execute(&self.session()?, &raw).await?;
        let DelegationCommandResult::GrantSnapshot { grant } = response.result;
        assert_eq!(
            grant.status,
            marty_delegated_authority::GrantStatus::Revoked
        );
        Ok(())
    }

    pub fn proof(&self, challenge: &RetainedUseChallenge) -> Vec<u8> {
        let time = Utc::now().timestamp();
        compact_jws(
            &self.machine_key,
            &json!({"typ":"JWT","alg":"ES256","jwk":self.machine_jwk}),
            &json!({
                "iss":self.principal.id,"sub":self.principal.id,
                "aud":challenge.verifier_id,"nonce":challenge.nonce,
                "iat":time,"nbf":time,"exp":time+90,
                "vp":{"@context":["https://www.w3.org/ns/credentials/v2"],
                    "type":["VerifiablePresentation"],"holder":self.principal.id,
                    "verifiableCredential":[self.credential]}
            }),
        )
        .into_bytes()
    }
}

async fn credential(
    admin: &PgPool,
    organization: Uuid,
    subject: &str,
) -> TestResult<(Uuid, Uuid, String, String, Value)> {
    let issued = DateTime::from_timestamp(Utc::now().timestamp() - 10, 0).unwrap();
    let expires = issued + Duration::hours(1);
    let signer = signing_key();
    let issuer_name = format!("did:web:{}.issuer.example.test", Uuid::new_v4().simple());
    let kid = format!("{issuer_name}#credential");
    let mut key = public_jwk(&signer);
    key["kid"] = json!(kid);
    key["alg"] = json!("ES256");
    key["use"] = json!("sig");
    let mut profile = TrustProfile {
        id: Uuid::new_v4(),
        organization_id: organization.to_string(),
        name: "Host machine credential authority".into(),
        description: None,
        status: TrustProfileStatus::Active,
        profile_type: TrustProfileType::Custom,
        compliance_status: ComplianceStatus::Compliant,
        trust_purposes: Some(vec![TrustPurpose::CredentialIssuer]),
        trust_sources: vec![],
        validation_rules: Default::default(),
        allowed_issuers: None,
        denied_issuers: None,
        system_issuer_overrides: serde_json::Map::new(),
        compatible_compliance_codes: vec![],
        verification_policy_set_id: None,
        auto_generated: false,
        revocation_policy: Default::default(),
        revocation_profile_id: None,
        time_policy: Default::default(),
        supported_formats: vec!["VC_JWT".into()],
        trusted_assertion_formats: None,
        created_at: issued,
        updated_at: issued,
    };
    profile.revocation_policy.check_ocsp = false;
    profile.revocation_policy.check_crl = false;
    profile.revocation_policy.check_status_list = false;
    let issuer = IssuerEntity {
        id: Uuid::new_v4(),
        organization_id: Some(organization.to_string()),
        issuer_id: issuer_name.clone(),
        issuer_type: IssuerEntityType::Organization,
        display_name: "Host fixture credential issuer".into(),
        description: None,
        is_system_issuer: false,
        compliance_status: IssuerEntityComplianceStatus::Compliant,
        accreditation_body: None,
        accreditations: vec![],
        accreditation_date: None,
        valid_from: issued,
        valid_until: Some(expires),
        trust_anchor_id: None,
        revoked_at: None,
        revocation_reason: None,
        revoked_by: None,
        metadata: json!({"verification_keys":[key]}),
        created_at: issued,
        updated_at: issued,
    };
    let relationship = TrustProfileIssuer {
        id: Uuid::new_v4(),
        trust_profile_id: profile.id,
        issuer_id: issuer.id,
        trust_level: 80,
        relationship_status: TrustRelationshipStatus::Trusted,
        cascade_revocation_policy: CascadeRevocationPolicy::Manual,
        metadata: json!({
            MACHINE_NESTED_JWT_AUTHORIZATIONS:["MachineCredential","RuntimeMembership"]
        }),
        created_at: issued,
        updated_at: issued,
    };
    let repository = PostgresTrustProfileRepository::new(admin.clone());
    repository.save_profile(&profile, None).await?;
    repository.save_issuer_entity(&issuer).await?;
    repository.save_profile_issuer(&relationship).await?;
    let credential_id = Uuid::new_v4();
    let credential_uri = format!("urn:uuid:{credential_id}");
    let credential = compact_jws(
        &signer,
        &json!({"typ":"JWT","alg":"ES256","kid":kid}),
        &json!({
            "iss":issuer_name,"sub":subject,"jti":credential_uri,
            "iat":issued.timestamp(),"nbf":issued.timestamp(),"exp":expires.timestamp(),
            "vc":{"@context":["https://www.w3.org/ns/credentials/v2"],
                "id":credential_uri,"issuer":issuer_name,
                "type":["VerifiableCredential","MachineCredential","RuntimeMembership"],
                "credentialSubject":{"id":subject},
                "validFrom":issued.to_rfc3339(),"validUntil":expires.to_rfc3339()}
        }),
    );
    // Test-issued original bytes seed the actual Issuance owner store. The
    // serving host subsequently uses its real restricted current-status reader.
    let transaction = Uuid::new_v4().to_string();
    let template = Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO issuance_service.issuance_transactions
        (id,organization_id,credential_template_id,subject_did,status,pre_auth_code,claims,
         created_at,expires_at,issued_at,credential_type,credential_payload_format,
         reserved_credential_id,issuer_did_override,issuer_algorithm)
        VALUES($1,$2,$3,$4,'issued',$5,'{}',$6,$7,$6,'MachineCredential','jwt_vc_json',$8,$9,'ES256')")
        .bind(&transaction).bind(organization.to_string()).bind(&template).bind(subject)
        .bind(Uuid::new_v4().to_string()).bind(issued).bind(expires)
        .bind(&credential_uri).bind(&issuer_name).execute(admin).await?;
    sqlx::query(
        "INSERT INTO issuance_service.issued_credentials
        (id,transaction_id,organization_id,credential_template_id,subject_did,issuer_did,
         credential_jwt,credential_hash,status,status_updated_at,revoked,issued_at,expires_at)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,'active',$9,false,$9,$10)",
    )
    .bind(&credential_uri)
    .bind(&transaction)
    .bind(organization.to_string())
    .bind(&template)
    .bind(subject)
    .bind(&issuer_name)
    .bind(&credential)
    .bind(format!("{:x}", Sha256::digest(credential.as_bytes())))
    .bind(issued)
    .bind(expires)
    .execute(admin)
    .await?;
    Ok((
        profile.id,
        credential_id,
        credential,
        issuer_name,
        public_jwk(&signer),
    ))
}
