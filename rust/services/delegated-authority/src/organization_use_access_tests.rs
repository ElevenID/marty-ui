//! Actual Organization access owner/source through both DA access ports.
use super::*;
use crate::*;
use chrono::Duration;
use marty_organization::{
    catalog::seed_system_roles, machine_registry::*, machine_use_access::*,
    migration::migrate_organization_schema, postgres::PostgresOrganizationStore,
    ForwardedPrincipal, JoinMechanism, Organization, OrganizationCreate, OrganizationType,
};
use marty_principal_runtime_binding::{parse_thumbprint, ThumbprintEncoding};
use serde_json::{json, Value};
use sqlx::{postgres::PgPoolOptions, AssertSqlSafe};
fn documents(
    organization: Uuid,
) -> (
    MachineRegistryDocuments,
    MachineRegistrySelection,
    MachineRegistryUseScope,
) {
    let now = Utc::now();
    let mut value: Value = serde_json::from_str(include_str!(concat!(env!("CARGO_MANIFEST_DIR"),
        "/../../crates/principal-runtime-binding/tests/fixtures/managed-service-with-rotating-candidate.json"))).unwrap();
    let machine = Uuid::new_v4();
    let deployment = Uuid::new_v4();
    let principal = format!("urn:application-test:machine:{machine}");
    let runtime = format!("urn:application-test:runtime:{machine}");
    for target in ["configuration", "record"] {
        value[target]["organization_id"] = json!(organization);
        value[target]["principal"] = json!({"type":"MACHINE_IDENTITY","id":principal});
        value[target]["runtime"]["machine_identity_id"] = json!(machine);
        value[target]["runtime"]["instance_ref"] = json!(runtime);
    }
    value["configuration"]["deployment_profile_id"] = json!(deployment);
    value["configuration"]["authentication_source"] =
        json!({"issuer":principal,"subject":principal});
    value["record"]["authentication"]["issuer"] = json!(principal);
    value["record"]["authentication"]["subject"] = json!(principal);
    value["machine_identity"]["id"] = json!(machine);
    value["machine_identity"]["organization_id"] = json!(organization);
    value["machine_identity"]["machine_id"] = json!(principal);
    value["machine_identity"]["assignments"] =
        json!({"deployment_profile_id":deployment,"operator_organization_id":organization});
    value["machine_identity"]["credential_ids"] = json!([Uuid::new_v4()]);
    value["machine_identity"]["created_at"] = json!((now - Duration::days(1)).to_rfc3339());
    value["machine_identity"]
        .as_object_mut()
        .unwrap()
        .remove("updated_at");
    value["machine_identity"]["identity_keys"][0]["valid_until"] =
        json!((now + Duration::hours(1)).to_rfc3339());
    let policy = json!({
        "id":Uuid::new_v4(),"organization_id":organization,"name":"Selected local full-machine MAP",
        "trust_profile_id":Uuid::new_v4(),"required_credential_types":["MachineCredential"],
        "allowed_machine_types":["SECURE_PROCESSING_RUNTIME"],
        "machine_binding":{"binding_methods":["MACHINE_KEY"],"proof_profiles":["OID4VP_VERIFIABLE_PRESENTATION"],
            "proof_freshness":{"challenge_required":true,"audience_binding_required":true,"replay_detection_required":true,"max_proof_age_seconds":120}},
        "status":"ACTIVE","created_at":(now-Duration::hours(1)).to_rfc3339()
    });
    let fingerprint = parse_thumbprint(
        &serde_json::to_vec(&value["record"]["authentication"]["key_thumbprint"]).unwrap(),
    )
    .unwrap()
    .reencode(ThumbprintEncoding::MipSha256Hex)
    .encoded_value();
    let scope = MachineRegistryUseScope {
        organization_id: organization,
        principal_id: principal,
        key_thumbprint: fingerprint,
        grant_id: Uuid::new_v4(),
        grant_revision: 1,
        challenge_id: Uuid::new_v4(),
        action: "urn:application-test:action".into(),
        audience: "https://application-tests.invalid/resource".into(),
        resource: "urn:application-test:resource".into(),
        operation_profile: "urn:application-test:operation".into(),
        operation_digest: format!("sha256:{}", "a".repeat(64)),
    };
    (
        MachineRegistryDocuments {
            binding_record: serde_json::to_vec(&value["record"]).unwrap(),
            binding_configuration: serde_json::to_vec(&value["configuration"]).unwrap(),
            machine_identity: serde_json::to_vec(&value["machine_identity"]).unwrap(),
            machine_authentication_policy: serde_json::to_vec(&policy).unwrap(),
        },
        MachineRegistrySelection::new(organization, deployment).unwrap(),
        scope,
    )
}

struct Fixture {
    owner: MachineUseAccessOwner,
    registry: MachineRegistryService,
    actor: ForwardedPrincipal,
    machine: MachineRegistryRecord,
    authorizer: OrganizationDelegationUseCommandAuthorizer,
    grant: DelegationGrant,
    caller: DelegationCommandCaller,
}
impl Fixture {
    async fn new() -> Self {
        let url = std::env::var("DELEGATED_AUTHORITY_TEST_DATABASE_URL")
            .expect("explicit disposable local PostgreSQL");
        assert!(matches!(
            url::Url::parse(&url).unwrap().host_str(),
            Some("127.0.0.1" | "[::1]")
        ));
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(&url)
            .await
            .unwrap();
        migrate_organization_schema(&pool).await.unwrap();
        sqlx::query("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
            .execute(&pool)
            .await
            .unwrap();
        let store = PostgresOrganizationStore::new(pool.clone());
        let user_id = format!("use-adapter-owner-{}", Uuid::new_v4());
        let actor = ForwardedPrincipal::User {
            user_id: user_id.clone(),
        };
        let (organization, member) = Organization::create(OrganizationCreate {
            name: format!("Access adapter {}", Uuid::new_v4()),
            owner_id: user_id,
            org_type: OrganizationType::Enterprise,
            display_name: None,
            description: None,
            join_mechanism: JoinMechanism::Invite,
            requires_approval: false,
            is_discoverable: false,
            now: Utc::now(),
        })
        .unwrap();
        store.save_organization(&organization).await.unwrap();
        store.save_member(&member).await.unwrap();
        let roles = seed_system_roles(&store, organization.id, Utc::now())
            .await
            .unwrap();
        store
            .set_member_roles(member.id, &[roles["owner"].id])
            .await
            .unwrap();
        let registry = MachineRegistryService::new(store.clone());
        let (docs, selection, scope) = documents(organization.id);
        let machine = registry
            .register(organization.id, &actor, docs)
            .await
            .unwrap();
        let owner = MachineUseAccessOwner::new(store);
        let now = DateTime::from_timestamp_micros(Utc::now().timestamp_micros()).unwrap();
        owner
            .grant(
                organization.id,
                &actor,
                machine.machine_identity_id(),
                MachineUseAccessInput {
                    permissions: vec![
                        MachineUsePermission::StartUse,
                        MachineUsePermission::FinalizeUse,
                        MachineUsePermission::RecoverResult,
                        MachineUsePermission::RetrieveRequest,
                        MachineUsePermission::SubmitProof,
                    ],
                    valid_from: now - Duration::seconds(1),
                    valid_until: now + Duration::hours(1),
                },
            )
            .await
            .unwrap();
        let role = format!("use_adapter_reader_{}", Uuid::new_v4().simple());
        sqlx::raw_sql(AssertSqlSafe(format!("CREATE ROLE {role} LOGIN; GRANT USAGE ON SCHEMA organization_service TO {role}; GRANT SELECT ON organization_service.rust_schema_versions,organization_service.organizations,organization_service.machine_registry_entries,organization_service.machine_registry_history,organization_service.machine_use_access,organization_service.machine_use_access_history TO {role}"))).execute(&pool).await.unwrap();
        let source_pool = PgPoolOptions::new()
            .max_connections(3)
            .connect_with(pool.connect_options().as_ref().clone().username(&role))
            .await
            .unwrap();
        let authorizer =
            OrganizationDelegationUseCommandAuthorizer::new(PgMachineUseAccessSource::new(
                source_pool,
                MachineUseAccessSelection::new(organization.id, selection.deployment_profile_id())
                    .unwrap(),
            ));
        authorizer.readiness().await.unwrap();
        let caller = DelegationCommandCaller::from_authenticated_context(
            organization.id,
            Principal {
                principal_type: PrincipalType::MachineIdentity,
                id: scope.principal_id,
            },
        )
        .unwrap();
        let mut grant = crate::test_support::pending_grant();
        grant.organization_id = organization.id;
        grant.terms.delegate = caller.actor().clone();
        grant.terms.binding = Binding {
            method: BindingMethod::Key,
            key_thumbprint: Some(scope.key_thumbprint),
            session_ref: None,
            establishment_evidence_ref: None,
        };
        grant.created_at = now - Duration::seconds(10);
        grant.updated_at = now - Duration::seconds(1);
        grant.terms.valid_from = now - Duration::seconds(20);
        grant.terms.valid_until = now + Duration::hours(1);
        grant.terms_digest = grant.calculate_terms_digest().unwrap();
        grant.status = GrantStatus::Active;
        grant.revision = 2;
        grant.approval = Some(GrantApproval {
            profile: "urn:test:approval".into(),
            grant_id: grant.id,
            approver: grant.terms.grantor.clone(),
            evidence_ref: "urn:test:consent".into(),
            authority_evidence_ref: "urn:test:authority".into(),
            terms_digest: grant.terms_digest.clone(),
            approved_at: grant.updated_at,
        });
        grant.validate().unwrap();
        Self {
            owner,
            registry,
            actor,
            machine,
            authorizer,
            grant,
            caller,
        }
    }
    fn start(&self) -> DelegationUseIntent {
        DelegationUseIntent::Start {
            grant: CommandGrantReference {
                id: self.grant.id,
                revision: self.grant.revision,
                terms_digest: self.grant.terms_digest.clone(),
            },
            operation: DelegationUseOperation {
                action: self.grant.terms.actions[0].clone(),
                resource_id: self.grant.terms.resources[0].clone(),
                audience: self.grant.terms.audiences[0].clone(),
                request_profile: "urn:test:operation".into(),
                request_digest: format!("sha256:{}", "a".repeat(64)),
            },
        }
    }
}

#[tokio::test]
async fn organization_use_access_adapter_checks_typed_scope_and_separate_current_rights() {
    if std::env::var("DELEGATED_AUTHORITY_TEST_DATABASE_URL").is_err() {
        return;
    }
    let _lock = crate::postgres::POSTGRES_TEST_LOCK.lock().await;
    let f = Fixture::new().await;
    let now = Utc::now();
    let access = f
        .authorizer
        .authorize(&f.caller, &f.start(), &f.grant, now)
        .await
        .unwrap();
    assert!(access.observed_at >= now);
    assert!(access.valid_until <= now + Duration::seconds(30));
    let finalize = DelegationUseIntent::Finalize {
        challenge_id: Uuid::new_v4(),
        proof_submission_id: Uuid::new_v4(),
    };
    f.authorizer
        .authorize(&f.caller, &finalize, &f.grant, Utc::now())
        .await
        .unwrap();
    for op in [
        DelegationUseIngressOperation::RequestRead,
        DelegationUseIngressOperation::ProofSubmit,
    ] {
        f.authorizer
            .authorize_ingress(&f.caller, Uuid::new_v4(), op, Utc::now())
            .await
            .unwrap();
    }
    let wrong = DelegationCommandCaller::from_authenticated_context(
        f.caller.organization_id(),
        Principal {
            principal_type: PrincipalType::ServiceAccount,
            id: f.caller.actor().id.clone(),
        },
    )
    .unwrap();
    assert!(f
        .authorizer
        .authorize(&wrong, &f.start(), &f.grant, Utc::now())
        .await
        .is_err());
    assert!(f
        .authorizer
        .authorize_ingress(
            &wrong,
            Uuid::new_v4(),
            DelegationUseIngressOperation::RequestRead,
            Utc::now()
        )
        .await
        .is_err());
    let wrong_org = DelegationCommandCaller::from_authenticated_context(
        Uuid::new_v4(),
        f.caller.actor().clone(),
    )
    .unwrap();
    assert!(f
        .authorizer
        .authorize_recovery(&wrong_org, &f.grant, Utc::now())
        .await
        .is_err());
    let mut stale = f.start();
    if let DelegationUseIntent::Start { grant, .. } = &mut stale {
        grant.revision += 1;
    }
    assert!(f
        .authorizer
        .authorize(&f.caller, &stale, &f.grant, Utc::now())
        .await
        .is_err());
    assert!(f
        .authorizer
        .authorize_ingress(
            &f.caller,
            Uuid::nil(),
            DelegationUseIngressOperation::ProofSubmit,
            Utc::now()
        )
        .await
        .is_err());
    let now = DateTime::from_timestamp_micros(Utc::now().timestamp_micros()).unwrap();
    f.owner
        .replace(
            f.caller.organization_id(),
            &f.actor,
            f.machine.machine_identity_id(),
            1,
            MachineUseAccessInput {
                permissions: vec![MachineUsePermission::RetrieveRequest],
                valid_from: now - Duration::seconds(1),
                valid_until: now + Duration::hours(1),
            },
        )
        .await
        .unwrap();
    assert!(f
        .authorizer
        .authorize(&f.caller, &f.start(), &f.grant, Utc::now())
        .await
        .is_err());
    assert!(f
        .authorizer
        .authorize(&f.caller, &finalize, &f.grant, Utc::now())
        .await
        .is_err());
    assert!(f
        .authorizer
        .authorize_recovery(&f.caller, &f.grant, Utc::now())
        .await
        .is_err());
    assert!(f
        .authorizer
        .authorize_ingress(
            &f.caller,
            Uuid::new_v4(),
            DelegationUseIngressOperation::ProofSubmit,
            Utc::now()
        )
        .await
        .is_err());
    f.authorizer
        .authorize_ingress(
            &f.caller,
            Uuid::new_v4(),
            DelegationUseIngressOperation::RequestRead,
            Utc::now(),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn organization_use_access_recovery_survives_old_grant_revocation_but_requires_current_owner_state(
) {
    if std::env::var("DELEGATED_AUTHORITY_TEST_DATABASE_URL").is_err() {
        return;
    }
    let _lock = crate::postgres::POSTGRES_TEST_LOCK.lock().await;
    let mut f = Fixture::new().await;
    let now = Utc::now();
    f.grant.status = GrantStatus::Revoked;
    f.grant.created_at = now - Duration::hours(2);
    f.grant.terms.valid_from = now - Duration::hours(1);
    f.grant.terms.valid_until = now - Duration::seconds(2);
    f.grant.updated_at = now - Duration::seconds(1);
    f.grant.terms_digest = f.grant.calculate_terms_digest().unwrap();
    let approval = f.grant.approval.as_mut().unwrap();
    approval.approved_at = now - Duration::hours(1);
    approval.terms_digest = f.grant.terms_digest.clone();
    f.grant.validate().unwrap();
    f.authorizer
        .authorize_recovery(&f.caller, &f.grant, Utc::now())
        .await
        .unwrap();
    assert!(f
        .authorizer
        .authorize(&f.caller, &f.start(), &f.grant, Utc::now())
        .await
        .is_err());
    f.owner
        .revoke(
            f.caller.organization_id(),
            &f.actor,
            f.machine.machine_identity_id(),
            1,
        )
        .await
        .unwrap();
    assert!(f
        .authorizer
        .authorize_recovery(&f.caller, &f.grant, Utc::now())
        .await
        .is_err());
    // A fresh identity with active current read rights still cannot recover
    // after the authoritative registry transitions to a terminal state.
    let f2 = Fixture::new().await;
    f2.registry
        .transition(
            f2.caller.organization_id(),
            &f2.actor,
            f2.machine.machine_identity_id(),
            1,
            MachineRegistryLifecycle::Revoke,
        )
        .await
        .unwrap();
    assert!(f2
        .authorizer
        .authorize_recovery(&f2.caller, &f2.grant, Utc::now())
        .await
        .is_err());
    assert!(f2
        .authorizer
        .authorize_ingress(
            &f2.caller,
            Uuid::new_v4(),
            DelegationUseIngressOperation::RequestRead,
            Utc::now()
        )
        .await
        .is_err());
}
