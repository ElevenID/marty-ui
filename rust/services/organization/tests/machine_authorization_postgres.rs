//! Concrete owner/source tests. These use actual local PostgreSQL, current
//! Organization membership/RBAC and the canonical MMF policy engine.
use chrono::{Duration, Utc};
use marty_organization::{
    catalog::seed_system_roles, machine_authorization::*, migration::migrate_organization_schema,
    postgres::PostgresOrganizationStore, CedarPolicyDocument, ForwardedPrincipal, JoinMechanism,
    Member, MemberStatus, Organization, OrganizationCreate, OrganizationType, PolicySet,
    PolicySetSpec, PolicySetStatus, PolicySetType,
};
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    AssertSqlSafe, PgPool,
};
use std::str::FromStr;
use tokio::sync::{Mutex, MutexGuard};
use uuid::Uuid;

static DATABASE_LOCK: Mutex<()> = Mutex::const_new(());
fn input() -> MachineAuthorizationPolicyInput {
    MachineAuthorizationPolicyInput{name:format!("Machine authentication {}",Uuid::new_v4()),description:Some("Explicit local owner policy".into()),policies:vec![CedarPolicyDocument{
        policy_id:"machine-authentication".into(),effect:"permit".into(),
        cedar_text:"permit(principal is MartyMachine::Principal,action == MartyMachine::Action::\"urn:marty:machine:authenticate\",resource is MartyMachine::Identity) when { context.grant_revision > 0 };".into(),description:None,enabled:true,
    }]}
}
struct Fixture {
    _lock: MutexGuard<'static, ()>,
    pool: PgPool,
    store: PostgresOrganizationStore,
    owner: MachineAuthorizationPolicyOwner,
    org: Uuid,
    actor: ForwardedPrincipal,
    member: Uuid,
    url: String,
}
impl Fixture {
    async fn new() -> Self {
        let lock = DATABASE_LOCK.lock().await;
        let url = std::env::var("ORGANIZATION_MACHINE_AUTHORIZATION_TEST_DATABASE_URL")
            .expect("explicit disposable local PostgreSQL URL");
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
        let actor = ForwardedPrincipal::User {
            user_id: format!("machine-policy-owner-{}", Uuid::new_v4()),
        };
        let ForwardedPrincipal::User { user_id } = &actor else {
            unreachable!()
        };
        let (organization, member) = Organization::create(OrganizationCreate {
            name: format!("Machine policy {}", Uuid::new_v4()),
            owner_id: user_id.clone(),
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
        Self {
            _lock: lock,
            owner: MachineAuthorizationPolicyOwner::new(store.clone()),
            store,
            pool,
            org: organization.id,
            actor,
            member: member.id,
            url,
        }
    }
    async fn reader(&self) -> PgMachineAuthorizationPolicySource {
        let role = format!("mp_reader_{}", Uuid::new_v4().simple());
        sqlx::raw_sql(AssertSqlSafe(format!("CREATE ROLE {role} LOGIN; GRANT USAGE ON SCHEMA organization_service TO {role}; GRANT SELECT ON organization_service.rust_schema_versions,organization_service.organizations,organization_service.policy_sets,organization_service.machine_authorization_policy_history TO {role}")))
            .execute(&self.pool).await.unwrap();
        let options = PgConnectOptions::from_str(&self.url)
            .unwrap()
            .username(&role);
        let pool = PgPoolOptions::new()
            .max_connections(3)
            .connect_with(options)
            .await
            .unwrap();
        let reader = PgMachineAuthorizationPolicySource::new(pool);
        reader.readiness().await.unwrap();
        reader
    }
}

#[test]
fn machine_policy_schema_accepts_exact_context_and_rejects_invented_authority() {
    validate_policy_input(&input()).unwrap();
    for policy in [
        "permit(principal,action,resource) when { principal.isOwner };",
        "permit(principal,action == MIP::Action::\"applications:approve\",resource);",
        "permit(principal,action,resource) when { context.grant_revision == \"1\" };",
        "permit(principal,action,resource) when { context.authorized };",
    ] {
        let mut request = input();
        request.policies[0].cedar_text = policy.into();
        assert!(validate_policy_input(&request).is_err(), "{policy}");
    }
    let mut request = input();
    request.policies.push(request.policies[0].clone());
    assert!(validate_policy_input(&request).is_err());
    let mut request = input();
    request.policies[0].enabled = false;
    assert!(validate_policy_input(&request).is_err());
}

#[tokio::test]
#[ignore = "requires disposable local PostgreSQL"]
async fn machine_policy_owner_retains_attributable_revisions_and_current_active_source() {
    let f = Fixture::new().await;
    let reader = f.reader().await;
    let draft = f.owner.create(f.org, &f.actor, input()).await.unwrap();
    assert_eq!(draft.revision, 1);
    assert_eq!(draft.status, PolicySetStatus::Draft);
    assert!(reader
        .observe_current(f.org, draft.policy_set_id, Utc::now())
        .await
        .is_err());
    let active = f
        .owner
        .activate(f.org, &f.actor, draft.policy_set_id, 1)
        .await
        .unwrap();
    let observed = reader
        .observe_current(f.org, active.policy_set_id, Utc::now())
        .await
        .unwrap();
    assert_eq!(observed.snapshot().revision, 2);
    assert!(observed
        .history_ref()
        .contains(&active.policy_set_id.to_string()));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(observed.snapshot_bytes()).unwrap(),
        serde_json::to_value(&active).unwrap()
    );
    assert!(observed.valid_until() <= observed.observed_at() + Duration::seconds(30));
    assert!(reader
        .observe_current(Uuid::new_v4(), active.policy_set_id, Utc::now())
        .await
        .is_err());
    assert!(reader
        .observe_current(
            f.org,
            active.policy_set_id,
            Utc::now() - Duration::seconds(31)
        )
        .await
        .is_err());
    assert!(f
        .owner
        .replace(f.org, &f.actor, active.policy_set_id, 2, input())
        .await
        .is_err());
    assert!(f
        .owner
        .archive(f.org, &f.actor, active.policy_set_id, 1)
        .await
        .is_err());
    let archived = f
        .owner
        .archive(f.org, &f.actor, active.policy_set_id, 2)
        .await
        .unwrap();
    assert_eq!(archived.revision, 3);
    assert!(reader
        .observe_current(f.org, active.policy_set_id, Utc::now())
        .await
        .is_err());
    let mut replacement = input();
    replacement.name = archived.name.clone();
    let replaced = f
        .owner
        .replace(f.org, &f.actor, active.policy_set_id, 3, replacement)
        .await
        .unwrap();
    assert_eq!(replaced.revision, 4);
    let reactivated = f
        .owner
        .activate(f.org, &f.actor, active.policy_set_id, 4)
        .await
        .unwrap();
    assert_eq!(reactivated.revision, 5);
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM organization_service.machine_authorization_policy_history WHERE organization_id=$1 AND policy_set_id=$2").bind(f.org).bind(active.policy_set_id).fetch_one(&f.pool).await.unwrap();
    assert_eq!(count, 5);
    // Source shutdown does not erase history, and an old observation is never
    // substituted for a new current status read.
    sqlx::query("UPDATE organization_service.organizations SET status='suspended' WHERE id=$1")
        .bind(f.org)
        .execute(&f.pool)
        .await
        .unwrap();
    assert!(reader
        .observe_current(f.org, active.policy_set_id, Utc::now())
        .await
        .is_err());
    assert_eq!(observed.snapshot().revision, 2);
}

#[tokio::test]
#[ignore = "requires disposable local PostgreSQL"]
async fn machine_policy_owner_requires_current_human_permission_and_blocks_general_writers() {
    let f = Fixture::new().await;
    let outsider = ForwardedPrincipal::User {
        user_id: format!("ordinary-member-{}", Uuid::new_v4()),
    };
    let ForwardedPrincipal::User { user_id } = &outsider else {
        unreachable!()
    };
    let member = Member::create(
        f.org,
        user_id.clone(),
        None,
        MemberStatus::Active,
        Utc::now(),
    );
    f.store.save_member(&member).await.unwrap();
    assert!(f.owner.create(f.org, &outsider, input()).await.is_err());
    let api = ForwardedPrincipal::ApiKey {
        user_id: "api".into(),
        api_key_id: Uuid::new_v4().to_string(),
        organization_id: f.org,
        authorized_permission: "machine-authorization-policy:create".into(),
    };
    assert!(f.owner.create(f.org, &api, input()).await.is_err());
    let draft = f.owner.create(f.org, &f.actor, input()).await.unwrap();
    assert!(f
        .store
        .policy_set_by_id(f.org, draft.policy_set_id)
        .await
        .unwrap()
        .is_none());
    assert!(f
        .store
        .policy_sets_by_organization(f.org, None)
        .await
        .unwrap()
        .is_empty());
    let row = PolicySet {
        id: draft.policy_set_id,
        organization_id: f.org,
        name: draft.name.clone(),
        description: draft.description.clone(),
        policy_type: PolicySetType::MachineAuthorization,
        status: draft.status,
        cedar_policies: serde_json::to_string(&draft.policies).unwrap(),
        cedar_schema_version: draft.schema_version.clone(),
        created_by: Some(draft.created_by.clone()),
        created_at: draft.created_at,
        updated_at: draft.updated_at,
    };
    assert!(f.store.save_policy_set(&row).await.is_err());
    assert!(!f
        .store
        .delete_policy_set(f.org, draft.policy_set_id)
        .await
        .unwrap());
    let mut disguised = row.clone();
    disguised.policy_type = PolicySetType::Custom;
    assert!(f.store.save_policy_set(&disguised).await.is_err());
    let generic = PolicySet::create(PolicySetSpec {
        organization_id: f.org,
        name: format!("General {}", Uuid::new_v4()),
        cedar_policies: "permit(principal,action,resource);".into(),
        policy_type: PolicySetType::Custom,
        description: None,
        created_by: None,
        cedar_schema_version: None,
        now: Utc::now(),
    });
    f.store.save_policy_set(&generic).await.unwrap();
    let visible = f
        .store
        .policy_sets_by_organization(f.org, None)
        .await
        .unwrap();
    assert_eq!(visible.len(), 1);
    assert_eq!(visible[0].id, generic.id);
    let mut tx = f.store.begin_transaction().await.unwrap();
    assert!(f
        .store
        .policy_set_by_id_for_update_in_transaction(&mut tx, f.org, draft.policy_set_id)
        .await
        .unwrap()
        .is_none());
    let locked = f
        .store
        .policy_sets_by_organization_for_update_in_transaction(&mut tx, f.org)
        .await
        .unwrap();
    assert_eq!(locked.len(), 1);
    assert_eq!(locked[0].id, generic.id);
    tx.rollback().await.unwrap();
    let reader = f.reader().await;
    assert!(reader
        .observe_current(f.org, generic.id, Utc::now())
        .await
        .is_err());
    // A source role must not be owner/admin or a broad organization writer.
    assert!(PgMachineAuthorizationPolicySource::new(f.pool.clone())
        .readiness()
        .await
        .is_err());
    sqlx::query("UPDATE organization_service.members SET status='deactivated' WHERE id=$1")
        .bind(f.member)
        .execute(&f.pool)
        .await
        .unwrap();
    assert!(f
        .owner
        .activate(f.org, &f.actor, draft.policy_set_id, 1)
        .await
        .is_err());
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT status FROM organization_service.policy_sets WHERE id=$1"
        )
        .bind(draft.policy_set_id)
        .fetch_one(&f.pool)
        .await
        .unwrap(),
        "DRAFT"
    );
}

#[tokio::test]
#[ignore = "requires disposable local PostgreSQL"]
async fn machine_policy_database_guards_reject_history_rewrite_and_unpaired_or_retyped_state() {
    let f = Fixture::new().await;
    let draft = f.owner.create(f.org, &f.actor, input()).await.unwrap();
    for query in [
        "UPDATE organization_service.machine_authorization_policy_history SET actor_user_id='forged' WHERE policy_set_id=$1",
        "DELETE FROM organization_service.machine_authorization_policy_history WHERE policy_set_id=$1",
        "DELETE FROM organization_service.policy_sets WHERE id=$1",
        "UPDATE organization_service.policy_sets SET policy_type='CUSTOM',machine_policy_revision=NULL WHERE id=$1",
        "UPDATE organization_service.policy_sets SET status='ACTIVE',machine_policy_revision=machine_policy_revision+1,updated_at=clock_timestamp() WHERE id=$1",
    ]{assert!(sqlx::query(query).bind(draft.policy_set_id).execute(&f.pool).await.is_err(),"{query}");}
    assert!(
        sqlx::raw_sql("TRUNCATE organization_service.machine_authorization_policy_history")
            .execute(&f.pool)
            .await
            .is_err()
    );
    let current = f
        .owner
        .inspect(f.org, &f.actor, draft.policy_set_id)
        .await
        .unwrap();
    assert_eq!(current.revision, 1);
    assert_eq!(current.status, PolicySetStatus::Draft);
}
