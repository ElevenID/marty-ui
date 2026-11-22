//! Real Organization ownership and real MMF evaluation. The supplied request
//! is an internal policy fixture, not a qualified caller/proof/grant lifecycle.
use super::*;
use crate::{CedarDecision, DelegationCedarEvaluator, MmfCedarEvaluator, PrincipalType};
use marty_organization::{
    catalog::seed_system_roles,
    delegation_use_policy::{DelegationUsePolicyInput, DelegationUsePolicyOwner},
    migration::migrate_organization_schema,
    postgres::PostgresOrganizationStore,
    CedarPolicyDocument, ForwardedPrincipal, JoinMechanism, Organization, OrganizationCreate,
    OrganizationType,
};
use serde_json::json;
use sqlx::{postgres::PgPoolOptions, AssertSqlSafe, PgPool};

struct Fixture {
    pool: PgPool,
    owner: DelegationUsePolicyOwner,
    actor: ForwardedPrincipal,
    organization: Uuid,
    policy: Uuid,
    reader: PgDelegationUsePolicySource,
}
impl Fixture {
    async fn new() -> Self {
        let url = std::env::var("DELEGATED_AUTHORITY_TEST_DATABASE_URL")
            .expect("disposable loopback PostgreSQL required");
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
        let store = PostgresOrganizationStore::new(pool.clone());
        let user = format!("delegation-policy-{}", Uuid::new_v4());
        let (organization, member) = Organization::create(OrganizationCreate {
            name: format!("Delegation Cedar {}", Uuid::new_v4()),
            owner_id: user.clone(),
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
        let owner = DelegationUsePolicyOwner::new(store);
        let actor = ForwardedPrincipal::User { user_id: user };
        let draft=owner.create(organization.id,&actor,DelegationUsePolicyInput {name:"Current exact-operation permission".into(),description:None,actions:vec!["urn:example:read".into(),"urn:example:write".into()],policies:vec![CedarPolicyDocument {policy_id:"exact-read".into(),effect:"permit".into(),cedar_text:"permit(principal is MartyDelegatedUse::Principal,action == MartyDelegatedUse::Action::\"urn:example:read\",resource == MartyDelegatedUse::Resource::\"urn:example:record\") when {context.grant_revision == 2 && context.audience == \"urn:example:relying-party\" && context.delegate_proof_verified && context.consent_and_authority_verified};".into(),description:None,enabled:true}]}).await.unwrap();
        owner
            .activate(organization.id, &actor, draft.policy_id, 1)
            .await
            .unwrap();
        let role = format!("delegation_cedar_{}", Uuid::new_v4().simple());
        sqlx::raw_sql(AssertSqlSafe(format!("CREATE ROLE {role} LOGIN NOINHERIT; GRANT USAGE ON SCHEMA organization_service TO {role}; GRANT SELECT ON organization_service.rust_schema_versions,organization_service.organizations,organization_service.delegation_use_policies,organization_service.delegation_use_policy_history,organization_service.delegation_use_policy_observations TO {role}; GRANT INSERT ON organization_service.delegation_use_policy_observations TO {role};"))).execute(&pool).await.unwrap();
        let reader_pool = PgPoolOptions::new()
            .max_connections(3)
            .connect_with(pool.connect_options().as_ref().clone().username(&role))
            .await
            .unwrap();
        Self {
            pool,
            owner,
            actor,
            organization: organization.id,
            policy: draft.policy_id,
            reader: PgDelegationUsePolicySource::new(reader_pool),
        }
    }
    fn source(&self) -> OrganizationDelegationCedarPolicySource {
        OrganizationDelegationCedarPolicySource::new(
            self.reader.clone(),
            self.organization,
            self.policy,
        )
        .unwrap()
    }
    fn request(&self) -> CedarEvaluationRequest {
        let machine = Principal {
            principal_type: PrincipalType::MachineIdentity,
            id: format!("urn:uuid:{}", Uuid::new_v4()),
        };
        let user = Principal {
            principal_type: PrincipalType::User,
            id: "urn:example:person".into(),
        };
        let digest = format!("sha256:{}", "a".repeat(64));
        CedarEvaluationRequest {
            organization_id: self.organization,
            grant_id: Uuid::new_v4(),
            grant_revision: 2,
            actor: machine.clone(),
            delegate: machine,
            grantor: user.clone(),
            subject: user,
            action: "urn:example:read".into(),
            audience: "urn:example:relying-party".into(),
            resource: "urn:example:record".into(),
            operation_profile: "urn:example:request:v1".into(),
            operation_digest: digest.clone(),
            constraint_evidence_digest: digest.clone(),
            constraint_context: json!({"mode":"EXACT_OPERATION","request_profile":"urn:example:request:v1","request_digest":digest}),
        }
    }
}

#[tokio::test]
#[ignore = "requires disposable local PostgreSQL"]
async fn owned_delegation_policy_runs_current_exact_operation_through_real_mmf() {
    let _lock = crate::postgres::POSTGRES_TEST_LOCK.lock().await;
    let f = Fixture::new().await;
    let source = f.source();
    source.readiness().await.unwrap();
    let evaluator = MmfCedarEvaluator::new(Arc::new(source));
    let request = f.request();
    let result = evaluator
        .evaluate(request.clone(), Utc::now())
        .await
        .unwrap();
    assert_eq!(result.decision, CedarDecision::Permit);
    assert_eq!(result.policy_revision, 2);
    assert_eq!(
        result.policy_id,
        format!(
            "urn:marty:delegation-use-policy:{}:{}",
            f.organization, f.policy
        )
    );
    let snapshot = f
        .owner
        .inspect(f.organization, &f.actor, f.policy)
        .await
        .unwrap();
    assert_eq!(result.policy_digest, snapshot.policy_digest);
    for changed in ["action", "resource", "audience", "revision"] {
        let mut changed_request = request.clone();
        match changed {
            "action" => changed_request.action = "urn:example:write".into(),
            "resource" => changed_request.resource = "urn:example:other".into(),
            "audience" => changed_request.audience = "urn:example:other".into(),
            _ => changed_request.grant_revision = 3,
        }
        assert_eq!(
            evaluator
                .evaluate(changed_request, Utc::now())
                .await
                .unwrap()
                .decision,
            CedarDecision::Forbid
        );
    }
    let rows:Vec<(String,Vec<u8>)>=sqlx::query_as("SELECT evidence_ref,evidence_bytes FROM organization_service.delegation_use_policy_observations WHERE organization_id=$1 ORDER BY retained_at").bind(f.organization).fetch_all(&f.pool).await.unwrap();
    assert_eq!(rows.len(), 5);
    let first: serde_json::Value = serde_json::from_slice(&rows[0].1).unwrap();
    assert_eq!(first["scope"]["grant_id"], request.grant_id.to_string());
    assert_eq!(
        first["scope"]["actor"],
        serde_json::to_value(&request.actor).unwrap()
    );
    assert_eq!(first["scope"]["operation_digest"], request.operation_digest);
    assert_eq!(
        first["scope"]["constraint_context"],
        request.constraint_context
    );
    assert_eq!(first["policy_digest"], result.policy_digest);
    assert_eq!(first["schema"], snapshot.schema);
    f.owner
        .archive(f.organization, &f.actor, f.policy, 2)
        .await
        .unwrap();
    assert!(evaluator.evaluate(request, Utc::now()).await.is_err());
    assert_eq!(
        f.reader
            .recover(f.organization, &rows[0].0)
            .await
            .unwrap()
            .unwrap()
            .bytes(),
        rows[0].1
    );
}

struct FixedClock(DateTime<Utc>);
impl DelegationClock for FixedClock {
    fn now(&self) -> DateTime<Utc> {
        self.0
    }
}

#[tokio::test]
#[ignore = "requires disposable local PostgreSQL"]
async fn owned_delegation_policy_rejects_scope_substitution_external_context_and_clock_regression()
{
    let _lock = crate::postgres::POSTGRES_TEST_LOCK.lock().await;
    let f = Fixture::new().await;
    let source = f.source();
    let request = f.request();
    for changed in ["tenant", "delegate", "action", "digest", "external"] {
        let mut q = request.clone();
        match changed {
            "tenant" => q.organization_id = Uuid::new_v4(),
            "delegate" => q.delegate.id = "urn:example:other".into(),
            "action" => q.action = "urn:example:unregistered".into(),
            "digest" => q.operation_digest = format!("sha256:{}", "b".repeat(64)),
            _ => q.constraint_context = json!({"mode":"EXTERNAL_PROFILE","authorized":true}),
        }
        assert!(
            source.resolve_active(&q, Utc::now()).await.is_err(),
            "{changed}"
        );
    }
    let regression = OrganizationDelegationCedarPolicySource::with_clock(
        f.reader.clone(),
        f.organization,
        f.policy,
        Arc::new(FixedClock(Utc::now() - Duration::seconds(1))),
    )
    .unwrap();
    assert!(regression
        .resolve_active(&request, Utc::now())
        .await
        .is_err());
    assert!(source
        .resolve_active(&request, Utc::now() - Duration::seconds(31))
        .await
        .is_err());
    assert!(
        OrganizationDelegationCedarPolicySource::new(f.reader.clone(), Uuid::nil(), f.policy)
            .is_err()
    );
    assert!(OrganizationDelegationCedarPolicySource::new(
        f.reader.clone(),
        f.organization,
        Uuid::nil()
    )
    .is_err());
}
