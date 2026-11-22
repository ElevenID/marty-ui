//! Composition of the new durable machine/credential/policy owners. Flow's
//! original challenge and the grant/authority/lifecycle are fixture inputs;
//! proof ingress, consent, grant qualification and final-use are not claimed.

use super::*;
use marty_delegated_authority::{
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
    Authority, AuthorityMode, Binding, BindingMethod, ConstraintMode, Constraints,
    DelegationFlowContextV1, DelegationGrant, DelegationOid4vpChallenge,
    DelegationOid4vpChallengeStore, DelegationOid4vpChallengeStoreError, DelegationUseRequest,
    GrantTerms, PgDelegationGrantRepository,
};
use marty_organization::{
    catalog::seed_system_roles,
    machine_authorization::{
        MachineAuthorizationPolicyInput, MachineAuthorizationPolicyOwner,
        PgMachineAuthorizationPolicySource,
    },
    machine_registry::{
        MachineRegistryDocuments, MachineRegistryLifecycle, MachineRegistrySelection,
        MachineRegistryService, PgMachineRegistrySource,
    },
    migration::migrate_organization_schema,
    postgres::PostgresOrganizationStore,
    CedarPolicyDocument, ForwardedPrincipal, JoinMechanism, Organization, OrganizationCreate,
    OrganizationType,
};
use marty_principal_runtime_binding::{jwk_sha256_thumbprint, ThumbprintEncoding};

struct OriginalChallenge(DelegationOid4vpChallenge);
#[async_trait]
impl DelegationOid4vpChallengeStore for OriginalChallenge {
    async fn load_active(
        &self,
        organization: Uuid,
        grant: Uuid,
        challenge: Uuid,
    ) -> Result<DelegationOid4vpChallenge, DelegationOid4vpChallengeStoreError> {
        if self.0.binding.organization_id != organization
            || self.0.binding.grant_id != grant
            || self.0.binding.challenge_id != challenge
        {
            return Err(DelegationOid4vpChallengeStoreError);
        }
        Ok(self.0.clone())
    }
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL admin URL; composes actual authoritative owners"]
async fn all_owned_sources_actual_crypto_cedar_and_aggregate_audit() {
    let db = Database::new().await;
    migrate_organization_schema(&db.admin).await.unwrap();
    PgDelegationGrantRepository::new(db.admin.clone())
        .migrate()
        .await
        .unwrap();
    let fixture = Fixture::new(&db, true).await;
    let credential_source = Arc::new(db.source().await);
    let scope = &fixture.selection.scope;
    let organization_id = scope.organization_id;
    let now = Utc::now();
    let actor_id = format!("composed-owner-{}", Uuid::new_v4());
    let (mut org, mut member) = Organization::create(OrganizationCreate {
        name: format!("Composed source {}", Uuid::new_v4()),
        owner_id: actor_id.clone(),
        org_type: OrganizationType::Enterprise,
        display_name: None,
        description: None,
        join_mechanism: JoinMechanism::Invite,
        requires_approval: false,
        is_discoverable: false,
        now,
    })
    .unwrap();
    org.id = organization_id;
    member.organization_id = organization_id;
    let store = PostgresOrganizationStore::new(db.admin.clone());
    store.save_organization(&org).await.unwrap();
    store.save_member(&member).await.unwrap();
    let roles = seed_system_roles(&store, organization_id, now)
        .await
        .unwrap();
    store
        .set_member_roles(member.id, &[roles["owner"].id])
        .await
        .unwrap();
    let actor = ForwardedPrincipal::User { user_id: actor_id };
    let policy_owner = MachineAuthorizationPolicyOwner::new(store.clone());
    let policy=policy_owner.create(organization_id,&actor,MachineAuthorizationPolicyInput {
        name:format!("Composed authentication {}",Uuid::new_v4()),description:None,
        policies:vec![CedarPolicyDocument {
            policy_id:"machine-authenticate".into(),effect:"permit".into(),
            cedar_text:"permit(principal is MartyMachine::Principal, action == MartyMachine::Action::\"urn:marty:machine:authenticate\", resource is MartyMachine::Identity) when { context.grant_revision > 0 && context.requested_action == \"credential:issue\" };".into(),
            description:None,enabled:true,
        }],
    }).await.unwrap();
    policy_owner
        .activate(organization_id, &actor, policy.policy_set_id, 1)
        .await
        .unwrap();

    let header: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(fixture.presentation.split('.').next().unwrap())
            .unwrap(),
    )
    .unwrap();
    let holder_key = &header["jwk"];
    let thumb = jwk_sha256_thumbprint(&serde_json::to_vec(holder_key).unwrap()).unwrap();
    let fingerprint = thumb
        .reencode(ThumbprintEncoding::MipSha256Hex)
        .encoded_value()
        .to_owned();
    let key = json!({"basis":"JWK_RFC7638_SHA256","encoding":"BASE64URL_SHA256",
        "value":thumb.reencode(ThumbprintEncoding::Base64urlSha256).encoded_value()});
    let principal = serde_json::to_value(&scope.principal).unwrap();
    let verifier_audience = "https://machine-verifier.example.test";
    let documents = json!({
        "configuration": {
            "profile":"urn:marty:principal-runtime-binding-configuration:v1",
            "organization_id":organization_id,"deployment_profile_id":scope.deployment_profile_id,"principal":principal,
            "authentication_source":{"issuer":scope.principal.id,"subject":scope.principal.id},
            "allowed_audiences":[verifier_audience],
            "runtime":{"kind":"MANAGED","instance_ref":scope.runtime_instance_ref,"machine_identity_id":scope.machine_identity_id,
                "active_key_id":"machine-key","stored_thumbprint_encoding":"MIP_SHA256_HEX"},
            "expected_key_algorithm":fixture.selection.algorithm.as_str(),"expected_key_thumbprint":key,"shared_runtime":false
        },
        "record": {
            "profile":"urn:marty:principal-runtime-binding:v1","organization_id":organization_id,"principal":principal,
            "authentication":{"issuer":scope.principal.id,"subject":scope.principal.id,"audience":verifier_audience,
                "key_algorithm":fixture.selection.algorithm.as_str(),"key_thumbprint":key},
            "runtime":{"kind":"MANAGED","instance_ref":scope.runtime_instance_ref,"machine_identity_id":scope.machine_identity_id}
        },
        "machine": {
            "id":scope.machine_identity_id,"organization_id":organization_id,"machine_id":scope.principal.id,
            "display_name":"Composed full machine","machine_type":"SECURE_PROCESSING_RUNTIME","status":"ACTIVE",
            "identity_keys":[{"key_id":"machine-key","thumbprint":fingerprint,"algorithm":fixture.selection.algorithm.as_str(),
                "status":"ACTIVE","public_key_jwk":holder_key,"valid_from":(now-Duration::minutes(1)).to_rfc3339(),
                "valid_until":(now+Duration::minutes(10)).to_rfc3339()}],
            "assignments":{"deployment_profile_id":scope.deployment_profile_id,"operator_organization_id":organization_id},
            "credential_ids":[fixture.selection.credential_id],"created_at":(now-Duration::minutes(1)).to_rfc3339()
        },
        "map": {
            "id":scope.policy_id,"organization_id":organization_id,"name":"Composed selected MAP",
            "trust_profile_id":fixture.profile.id,"required_credential_types":["MachineCredential","RuntimeMembership"],
            "allowed_machine_types":["SECURE_PROCESSING_RUNTIME"],
            "machine_binding":{"binding_methods":["MACHINE_KEY"],"proof_profiles":["OID4VP_VERIFIABLE_PRESENTATION"],
                "proof_freshness":{"challenge_required":true,"audience_binding_required":true,"replay_detection_required":true,"max_proof_age_seconds":120}},
            "authorization_policy_set_id":policy.policy_set_id,"status":"ACTIVE","created_at":(now-Duration::minutes(1)).to_rfc3339()
        }
    });
    let machine_owner = MachineRegistryService::new(store);
    machine_owner
        .register(
            organization_id,
            &actor,
            MachineRegistryDocuments {
                binding_record: serde_json::to_vec(&documents["record"]).unwrap(),
                binding_configuration: serde_json::to_vec(&documents["configuration"]).unwrap(),
                machine_identity: serde_json::to_vec(&documents["machine"]).unwrap(),
                machine_authentication_policy: serde_json::to_vec(&documents["map"]).unwrap(),
            },
        )
        .await
        .unwrap();
    let machine_pool=db.scoped_pool("GRANT USAGE ON SCHEMA organization_service TO $ROLE;
        GRANT SELECT ON organization_service.rust_schema_versions,organization_service.organizations,
        organization_service.machine_registry_entries,organization_service.machine_registry_history,
        organization_service.machine_registry_observations TO $ROLE;
        GRANT INSERT ON organization_service.machine_registry_observations TO $ROLE;").await;
    let machine_source = Arc::new(OrganizationMachineAuthenticationStateSource::new(
        PgMachineRegistrySource::new(
            machine_pool,
            MachineRegistrySelection::new(organization_id, scope.deployment_profile_id).unwrap(),
        ),
    ));
    machine_source.readiness().await.unwrap();
    let policy_reader=db.scoped_pool("GRANT USAGE ON SCHEMA organization_service TO $ROLE;
        GRANT SELECT ON organization_service.rust_schema_versions,organization_service.organizations,
        organization_service.policy_sets,organization_service.machine_authorization_policy_history TO $ROLE;").await;
    let policy_writer=db.scoped_pool("GRANT USAGE ON SCHEMA delegated_authority_service TO $ROLE;
        GRANT SELECT ON delegated_authority_service.schema_migrations,delegated_authority_service.machine_authorization_evidence TO $ROLE;
        GRANT INSERT ON delegated_authority_service.machine_authorization_evidence TO $ROLE;").await;
    let policy_evidence = PgMachineAuthorizationEvidenceRepository::new(policy_writer);
    let policy_source = Arc::new(
        OrganizationMachineCedarPolicySource::new(
            PgMachineAuthorizationPolicySource::new(policy_reader),
            policy_evidence.clone(),
            organization_id,
            scope.deployment_profile_id,
        )
        .unwrap(),
    );
    policy_source.readiness().await.unwrap();
    let audit_pool=db.scoped_pool("GRANT USAGE ON SCHEMA delegated_authority_service TO $ROLE;
        GRANT SELECT ON delegated_authority_service.schema_migrations,delegated_authority_service.machine_authentication_evidence,
        delegated_authority_service.machine_authorization_evidence TO $ROLE;
        GRANT INSERT ON delegated_authority_service.machine_authentication_evidence TO $ROLE;").await;
    let aggregate_evidence = PgMachineAuthenticationEvidenceRepository::new(audit_pool);
    let grantor = Principal {
        principal_type: PrincipalType::User,
        id: "urn:test:composed-grantor".into(),
    };
    let grant = DelegationGrant::pending(
        organization_id,
        Authority {
            mode: AuthorityMode::Managed,
            issuer: Principal {
                principal_type: PrincipalType::Organization,
                id: format!("urn:uuid:{organization_id}"),
            },
            status_ref: "https://authority.example.test/delegations".into(),
            source_profile: None,
            source_evidence_ref: None,
            source_evidence_digest: None,
            source_expires_at: None,
        },
        GrantTerms {
            grantor: grantor.clone(),
            subject: grantor,
            delegate: scope.principal.clone(),
            binding: Binding {
                method: BindingMethod::Key,
                key_thumbprint: Some(fingerprint),
                session_ref: None,
                establishment_evidence_ref: None,
            },
            actions: vec![scope.action.clone()],
            audiences: vec![scope.audience.clone()],
            resources: vec![scope.resource.clone()],
            valid_from: now - Duration::seconds(1),
            valid_until: now + Duration::minutes(5),
            subdelegation_allowed: false,
            constraints: Constraints {
                mode: ConstraintMode::ExactOperation,
                request_profile: Some(scope.operation_profile.clone()),
                request_digest: Some(scope.operation_digest.clone()),
                profile: None,
                document_ref: None,
                document_digest: None,
                evaluator: None,
            },
        },
        now,
    )
    .unwrap();
    let request = DelegationUseRequest {
        organization_id,
        grant_id: grant.id,
        expected_revision: grant.revision,
        challenge_id: scope.challenge_id,
        actor: scope.principal.clone(),
        action: scope.action.clone(),
        audience: scope.audience.clone(),
        resource: scope.resource.clone(),
        operation_profile: scope.operation_profile.clone(),
        operation_digest: scope.operation_digest.clone(),
        proof: fixture.presentation.as_bytes().to_vec(),
    };
    let challenge = OriginalChallenge(DelegationOid4vpChallenge {
        binding: DelegationFlowContextV1 {
            challenge_id: request.challenge_id,
            organization_id,
            grant_id: grant.id,
            grant_revision: grant.revision,
            actor: request.actor.clone(),
            action: request.action.clone(),
            audience: request.audience.clone(),
            resource: request.resource.clone(),
            operation_profile: request.operation_profile.clone(),
            operation_digest: request.operation_digest.clone(),
            session_ref: None,
            establishment_evidence_ref: None,
            session_key_thumbprint: None,
        },
        verifier_client_id: verifier_audience.into(),
        nonce: "original-source-nonce-at-least-thirty-two-characters".into(),
        expires_at: now + Duration::minutes(2),
    });
    let machine = Arc::new(MartyMachineOid4vpProofVerifier::new(
        Arc::new(challenge),
        machine_source,
        Some(Arc::new(MartyNestedJwtVcMachineCredentialVerifier::new(
            credential_source,
        ))),
        None,
        Some(Arc::new(AuditedMmfMachineAuthorizationVerifier::new(
            policy_source,
        ))),
    ));
    let verifier = AuditedMachineOid4vpProofVerifier::new(machine, aggregate_evidence.clone());
    verifier.readiness().await.unwrap();
    let proof = verifier
        .verify_retained(&grant, &request, Utc::now())
        .await
        .unwrap();
    let authenticated = proof.authenticated();
    assert_eq!(
        authenticated.scope().machine_identity_id,
        scope.machine_identity_id
    );
    let aggregate_ref = authenticated.evidence_ref().to_owned();
    let aggregate_bytes = authenticated.evidence_bytes().to_vec();
    let audit = aggregate_evidence
        .recover(organization_id, &aggregate_ref)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(audit.evidence_bytes(), aggregate_bytes);
    let credential_ref = authenticated.evidence_document()["credentials"]["credentials"][0]
        ["evidence_ref"]
        .as_str()
        .unwrap();
    assert!(PgMachineCredentialSourceEvidence::new(db.evidence.clone())
        .recover(organization_id, credential_ref)
        .await
        .unwrap()
        .is_some());
    let policy_ref = authenticated.evidence_document()["machine_authorization"]["evidence_ref"]
        .as_str()
        .unwrap();
    assert!(policy_evidence
        .recover(organization_id, policy_ref)
        .await
        .unwrap()
        .is_some());
    let registry_count:i64=sqlx::query_scalar("SELECT count(*) FROM organization_service.machine_registry_observations WHERE organization_id=$1")
        .bind(organization_id).fetch_one(&db.admin).await.unwrap();
    assert_eq!(registry_count, 1);
    // Current owner changes invalidate the next proof while old retained
    // evidence stays historical; none of these lookups reactivates authority.
    sqlx::query("UPDATE issuance_service.issued_credentials SET status='revoked',revoked=true,status_updated_at=clock_timestamp() WHERE id=$1")
        .bind(format!("urn:uuid:{}",fixture.selection.credential_id)).execute(&db.admin).await.unwrap();
    assert!(verifier
        .verify_retained(&grant, &request, Utc::now())
        .await
        .is_err());
    sqlx::query("UPDATE issuance_service.issued_credentials SET status='active',revoked=false,status_updated_at=clock_timestamp() WHERE id=$1")
        .bind(format!("urn:uuid:{}",fixture.selection.credential_id)).execute(&db.admin).await.unwrap();
    policy_owner
        .archive(organization_id, &actor, policy.policy_set_id, 2)
        .await
        .unwrap();
    assert!(verifier
        .verify_retained(&grant, &request, Utc::now())
        .await
        .is_err());
    policy_owner
        .activate(organization_id, &actor, policy.policy_set_id, 3)
        .await
        .unwrap();
    machine_owner
        .transition(
            organization_id,
            &actor,
            scope.machine_identity_id,
            1,
            MachineRegistryLifecycle::Suspend,
        )
        .await
        .unwrap();
    assert!(verifier
        .verify_retained(&grant, &request, Utc::now())
        .await
        .is_err());
    let historical = aggregate_evidence
        .recover(organization_id, &aggregate_ref)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(historical.evidence_bytes(), aggregate_bytes);
}
