//! Actual owner, RBAC, PostgreSQL source and immutable evidence regressions.
use chrono::{Duration, Utc};
use marty_organization::{
    catalog::seed_system_roles, delegation_use_policy::*, migration::migrate_organization_schema,
    postgres::PostgresOrganizationStore, CedarPolicyDocument, ForwardedPrincipal, JoinMechanism,
    Member, MemberStatus, Organization, OrganizationCreate, OrganizationType,
};
use serde_json::json;
use sqlx::{postgres::PgPoolOptions, AssertSqlSafe, PgPool};
use tokio::sync::{Mutex, MutexGuard};
use uuid::Uuid;

static DATABASE_LOCK: Mutex<()> = Mutex::const_new(());
fn input() -> DelegationUsePolicyInput {
    DelegationUsePolicyInput {name:"Exact delegated use".into(),description:None,actions:vec!["urn:example:read".into(),"urn:example:write".into()],policies:vec![CedarPolicyDocument {
        policy_id:"exact-use".into(),effect:"permit".into(),cedar_text:"permit(principal is MartyDelegatedUse::Principal,action == MartyDelegatedUse::Action::\"urn:example:read\",resource is MartyDelegatedUse::Resource) when {context.grant_revision > 0 && context.delegate_proof_verified && context.consent_and_authority_verified && context.constraint_context.mode == \"EXACT_OPERATION\"};".into(),description:None,enabled:true,
    }]}
}
fn scope(organization: Uuid) -> DelegationUsePolicyScope {
    let principal = DelegationPolicyPrincipal {
        principal_type: "MACHINE_IDENTITY".into(),
        id: format!("urn:uuid:{}", Uuid::new_v4()),
    };
    let human = DelegationPolicyPrincipal {
        principal_type: "USER".into(),
        id: "urn:example:person".into(),
    };
    let digest = format!("sha256:{}", "a".repeat(64));
    DelegationUsePolicyScope {
        organization_id: organization,
        grant_id: Uuid::new_v4(),
        grant_revision: 2,
        actor: principal.clone(),
        delegate: principal,
        grantor: human.clone(),
        subject: human,
        action: "urn:example:read".into(),
        audience: "urn:example:relying-party".into(),
        resource: "urn:example:record".into(),
        operation_profile: "urn:example:request:v1".into(),
        operation_digest: digest.clone(),
        constraint_evidence_digest: digest.clone(),
        constraint_context: json!({"mode":"EXACT_OPERATION","request_profile":"urn:example:request:v1","request_digest":digest}),
    }
}
struct Fixture {
    _lock: MutexGuard<'static, ()>,
    pool: PgPool,
    store: PostgresOrganizationStore,
    owner: DelegationUsePolicyOwner,
    organization: Uuid,
    actor: ForwardedPrincipal,
    member: Uuid,
}
struct Reader {
    source: PgDelegationUsePolicySource,
    role: String,
    pool: PgPool,
}
impl Fixture {
    async fn new() -> Self {
        let lock = DATABASE_LOCK.lock().await;
        let url = std::env::var("ORGANIZATION_POSTGRES_TEST_URL")
            .expect("explicit disposable PostgreSQL");
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
        let user_id = format!("delegation-policy-owner-{}", Uuid::new_v4());
        let (organization, member) = Organization::create(OrganizationCreate {
            name: format!("Delegation policy {}", Uuid::new_v4()),
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
            pool,
            owner: DelegationUsePolicyOwner::new(store.clone()),
            store,
            organization: organization.id,
            actor: ForwardedPrincipal::User { user_id },
            member: member.id,
        }
    }
    async fn sql(&self, sql: &str) {
        sqlx::raw_sql(AssertSqlSafe(sql.to_owned()))
            .execute(&self.pool)
            .await
            .unwrap();
    }
    async fn reader(&self) -> Reader {
        let role = format!("delegation_policy_reader_{}", Uuid::new_v4().simple());
        self.sql(&format!("CREATE ROLE {role} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; GRANT USAGE ON SCHEMA organization_service TO {role}; GRANT SELECT ON organization_service.rust_schema_versions,organization_service.organizations,organization_service.delegation_use_policies,organization_service.delegation_use_policy_history,organization_service.delegation_use_policy_observations TO {role}; GRANT INSERT ON organization_service.delegation_use_policy_observations TO {role};")).await;
        let pool = PgPoolOptions::new()
            .max_connections(3)
            .connect_with(self.pool.connect_options().as_ref().clone().username(&role))
            .await
            .unwrap();
        let source = PgDelegationUsePolicySource::new(pool.clone());
        source.readiness().await.unwrap();
        Reader { source, role, pool }
    }
    async fn active(&self) -> DelegationUsePolicySnapshot {
        let draft = self
            .owner
            .create(self.organization, &self.actor, input())
            .await
            .unwrap();
        self.owner
            .activate(
                self.organization,
                &self.actor,
                draft.policy_id,
                draft.revision,
            )
            .await
            .unwrap()
    }
}

#[test]
fn finite_fixed_context_schema_rejects_invented_roles_domains_and_actions() {
    validate_policy_input(&input()).unwrap();
    for text in [
        "permit(principal,action,resource) when {principal.isOwner};",
        "permit(principal,action,resource) when {context.budget_available};",
        "permit(principal,action,resource) when {context.grant_revision == \"2\"};",
        "permit(principal,action == MartyDelegatedUse::Action::\"urn:other:action\",resource);",
    ] {
        let mut v = input();
        v.policies[0].cedar_text = text.into();
        assert!(validate_policy_input(&v).is_err(), "{text}");
    }
    let mut v = input();
    v.actions.push(v.actions[0].clone());
    assert!(validate_policy_input(&v).is_err());
    let mut v = input();
    v.actions = vec!["urn:example:*".into()];
    assert!(validate_policy_input(&v).is_err());
    let mut v = input();
    v.policies[0].enabled = false;
    assert!(validate_policy_input(&v).is_err());
    let mut s = scope(Uuid::new_v4());
    s.validate().unwrap();
    s.constraint_context = json!({"mode":"EXTERNAL_PROFILE","authorized":true});
    assert!(s.validate().is_err());
}

#[tokio::test]
#[ignore = "requires disposable local PostgreSQL"]
async fn source_retains_exact_scope_and_immutable_policy_revisions() {
    let f = Fixture::new().await;
    let r = f.reader().await;
    let s = scope(f.organization);
    let draft = f
        .owner
        .create(f.organization, &f.actor, input())
        .await
        .unwrap();
    assert!(r
        .source
        .observe_current(draft.policy_id, &s, Utc::now())
        .await
        .is_err());
    let active = f
        .owner
        .activate(f.organization, &f.actor, draft.policy_id, 1)
        .await
        .unwrap();
    let original = Utc::now();
    let current = r
        .source
        .observe_current(active.policy_id, &s, original)
        .await
        .unwrap();
    assert_eq!(current.snapshot().revision, 2);
    assert_eq!(current.scope(), &s);
    assert!(current.valid_until() <= original + Duration::seconds(30));
    let history = r
        .source
        .recover(f.organization, current.evidence_ref())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(history.bytes(), current.evidence_bytes());
    assert_eq!(
        history.document()["scope"],
        serde_json::to_value(&s).unwrap()
    );
    assert_eq!(
        history.document()["policy_snapshot"],
        serde_json::to_value(&active).unwrap()
    );
    assert!(r
        .source
        .recover(Uuid::new_v4(), current.evidence_ref())
        .await
        .unwrap()
        .is_none());
    assert!(r
        .source
        .observe_current(active.policy_id, &scope(Uuid::new_v4()), Utc::now())
        .await
        .is_err());
    assert!(r
        .source
        .observe_current(active.policy_id, &s, Utc::now() - Duration::seconds(31))
        .await
        .is_err());
    assert!(r
        .source
        .observe_current(active.policy_id, &s, Utc::now() + Duration::seconds(1))
        .await
        .is_err());
    let mut unknown = s.clone();
    unknown.action = "urn:example:unregistered".into();
    assert!(r
        .source
        .observe_current(active.policy_id, &unknown, Utc::now())
        .await
        .is_err());
    assert!(f
        .owner
        .replace(f.organization, &f.actor, active.policy_id, 2, input())
        .await
        .is_err());
    assert!(f
        .owner
        .archive(f.organization, &f.actor, active.policy_id, 1)
        .await
        .is_err());
    let archived = f
        .owner
        .archive(f.organization, &f.actor, active.policy_id, 2)
        .await
        .unwrap();
    assert_eq!(archived.revision, 3);
    assert!(r
        .source
        .observe_current(active.policy_id, &s, Utc::now())
        .await
        .is_err());
    assert_eq!(
        r.source
            .recover(f.organization, current.evidence_ref())
            .await
            .unwrap()
            .unwrap()
            .bytes(),
        history.bytes()
    );
    let replaced = f
        .owner
        .replace(f.organization, &f.actor, active.policy_id, 3, input())
        .await
        .unwrap();
    assert_eq!(replaced.revision, 4);
    let reactivated = f
        .owner
        .activate(f.organization, &f.actor, active.policy_id, 4)
        .await
        .unwrap();
    assert_eq!(reactivated.revision, 5);
    let fresh = r
        .source
        .observe_current(active.policy_id, &s, Utc::now())
        .await
        .unwrap();
    assert_eq!(fresh.snapshot().revision, 5);
    assert_ne!(fresh.evidence_ref(), current.evidence_ref());
    assert_eq!(
        r.source
            .recover(f.organization, current.evidence_ref())
            .await
            .unwrap()
            .unwrap()
            .bytes(),
        history.bytes()
    );
    let generic: i64 =
        sqlx::query_scalar("SELECT count(*) FROM organization_service.policy_sets WHERE id=$1")
            .bind(active.policy_id)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(generic, 0);
    sqlx::query("UPDATE organization_service.organizations SET status='suspended' WHERE id=$1")
        .bind(f.organization)
        .execute(&f.pool)
        .await
        .unwrap();
    assert!(r
        .source
        .observe_current(active.policy_id, &s, Utc::now())
        .await
        .is_err());
    assert_eq!(
        r.source
            .recover(f.organization, current.evidence_ref())
            .await
            .unwrap()
            .unwrap()
            .bytes(),
        history.bytes()
    );
}

#[tokio::test]
#[ignore = "requires disposable local PostgreSQL"]
async fn owner_checks_current_human_permission_and_dedicated_policy_identity() {
    let f = Fixture::new().await;
    let outsider_id = format!("ordinary-{}", Uuid::new_v4());
    let outsider = Member::create(
        f.organization,
        outsider_id.clone(),
        None,
        MemberStatus::Active,
        Utc::now(),
    );
    f.store.save_member(&outsider).await.unwrap();
    assert!(f
        .owner
        .create(
            f.organization,
            &ForwardedPrincipal::User {
                user_id: outsider_id
            },
            input()
        )
        .await
        .is_err());
    let active = f.active().await;
    assert!(f
        .owner
        .inspect(Uuid::new_v4(), &f.actor, active.policy_id)
        .await
        .is_err());
    f.store.set_member_roles(f.member, &[]).await.unwrap();
    assert!(f
        .owner
        .inspect(f.organization, &f.actor, active.policy_id)
        .await
        .is_err());
    assert!(f
        .owner
        .archive(f.organization, &f.actor, active.policy_id, active.revision)
        .await
        .is_err());
}

#[tokio::test]
#[ignore = "requires disposable local PostgreSQL"]
async fn actual_source_login_rejects_privilege_and_schema_drift() {
    let f = Fixture::new().await;
    let r = f.reader().await;
    let active = f.active().await;
    let s = scope(f.organization);
    assert!(PgDelegationUsePolicySource::new(f.pool.clone())
        .readiness()
        .await
        .is_err());
    let role = r.role.clone();
    let masked = PgPoolOptions::new()
        .max_connections(1)
        .after_connect(move |connection, _| {
            let command = format!("SET ROLE {role}");
            Box::pin(async move {
                sqlx::raw_sql(AssertSqlSafe(command))
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect_with(f.pool.connect_options().as_ref().clone())
        .await
        .unwrap();
    assert!(PgDelegationUsePolicySource::new(masked)
        .readiness()
        .await
        .is_err());
    for capability in ["pg_execute_server_program", "pg_monitor"] {
        f.sql(&format!("GRANT {capability} TO {}", r.role)).await;
        assert!(r.source.readiness().await.is_err());
        assert!(r
            .source
            .observe_current(active.policy_id, &s, Utc::now())
            .await
            .is_err());
        f.sql(&format!("REVOKE {capability} FROM {}", r.role)).await;
        r.source.readiness().await.unwrap();
    }
    f.sql(&format!("ALTER ROLE {} REPLICATION", r.role)).await;
    assert!(r.source.readiness().await.is_err());
    f.sql(&format!("ALTER ROLE {} NOREPLICATION", r.role)).await;
    r.source.readiness().await.unwrap();
    for grant in [
        "UPDATE(snapshot) ON organization_service.delegation_use_policies",
        "REFERENCES(policy_id) ON organization_service.delegation_use_policies",
        "SELECT ON organization_service.policy_sets",
    ] {
        f.sql(&format!("GRANT {grant} TO {}", r.role)).await;
        assert!(r.source.readiness().await.is_err());
        f.sql(&format!("REVOKE {grant} FROM {}", r.role)).await;
        r.source.readiness().await.unwrap();
    }
    let version: i32 = sqlx::query_scalar("SELECT current_setting('server_version_num')::INT")
        .fetch_one(&f.pool)
        .await
        .unwrap();
    if version >= 170000 {
        f.sql(&format!(
            "GRANT MAINTAIN ON organization_service.delegation_use_policies TO {}",
            r.role
        ))
        .await;
        assert!(r.source.readiness().await.is_err());
        f.sql(&format!(
            "REVOKE MAINTAIN ON organization_service.delegation_use_policies FROM {}",
            r.role
        ))
        .await;
        r.source.readiness().await.unwrap();
    }
    // `pgx_` is a normal user schema. SQL LIKE 'pg_%' would incorrectly
    // classify it as a reserved PostgreSQL namespace because '_' is wildcard.
    f.sql("CREATE SCHEMA pgx_delegation_policy_test; CREATE FUNCTION pgx_delegation_policy_test.unused_probe() RETURNS INT LANGUAGE SQL SECURITY DEFINER SET search_path=pg_catalog AS 'SELECT 1'; REVOKE ALL ON FUNCTION pgx_delegation_policy_test.unused_probe() FROM PUBLIC;").await;
    f.sql(&format!("GRANT USAGE ON SCHEMA pgx_delegation_policy_test TO {}; GRANT EXECUTE ON FUNCTION pgx_delegation_policy_test.unused_probe() TO {}",r.role,r.role)).await;
    assert!(r.source.readiness().await.is_err());
    // The privileged function is deliberately never invoked.
    f.sql("DROP SCHEMA pgx_delegation_policy_test CASCADE")
        .await;
    r.source.readiness().await.unwrap();
    f.sql("ALTER TABLE organization_service.delegation_use_policy_observations DISABLE TRIGGER delegation_policy_observation_guard").await;
    assert!(r.source.readiness().await.is_err());
    f.sql("ALTER TABLE organization_service.delegation_use_policy_observations ENABLE TRIGGER delegation_policy_observation_guard").await;
    r.source.readiness().await.unwrap();
    let definition:String=sqlx::query_scalar("SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid='organization_service.delegation_use_policy_observations'::regclass AND conname='delegation_policy_observation_times'").fetch_one(&f.pool).await.unwrap();
    f.sql("ALTER TABLE organization_service.delegation_use_policy_observations DROP CONSTRAINT delegation_policy_observation_times, ADD CONSTRAINT delegation_policy_observation_times CHECK(true)").await;
    assert!(r.source.readiness().await.is_err());
    f.sql(&format!("ALTER TABLE organization_service.delegation_use_policy_observations DROP CONSTRAINT delegation_policy_observation_times, ADD CONSTRAINT delegation_policy_observation_times {definition}")).await;
    r.source.readiness().await.unwrap();
    for sql in [
        "DELETE FROM organization_service.delegation_use_policy_history",
        "TRUNCATE organization_service.delegation_use_policies CASCADE",
        "UPDATE organization_service.delegation_use_policy_history SET action='REPLACE'",
    ] {
        assert!(sqlx::raw_sql(AssertSqlSafe(sql))
            .execute(&f.pool)
            .await
            .is_err());
    }
    let mut tx = f.pool.begin().await.unwrap();
    sqlx::query("UPDATE organization_service.delegation_use_policies SET revision=revision+1,status='ARCHIVED',snapshot=(snapshot||jsonb_build_object('revision',revision+1,'status','ARCHIVED','updated_at',clock_timestamp())) WHERE organization_id=$1 AND policy_id=$2").bind(f.organization).bind(active.policy_id).execute(&mut *tx).await.unwrap_err();
    tx.rollback().await.unwrap();
    assert!(r.pool.size() > 0);
}

#[tokio::test]
#[ignore = "requires disposable local PostgreSQL"]
async fn committed_source_survives_caller_cancellation_without_returning_authority() {
    let f = Fixture::new().await;
    let r = f.reader().await;
    let active = f.active().await;
    let s = scope(f.organization);
    f.sql("CREATE FUNCTION organization_service.delegation_policy_test_delay() RETURNS TRIGGER LANGUAGE plpgsql SET search_path=pg_catalog AS $$ BEGIN PERFORM pg_sleep(0.5); RETURN NEW; END $$; CREATE CONSTRAINT TRIGGER z_delegation_policy_test_delay AFTER INSERT ON organization_service.delegation_use_policy_observations DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION organization_service.delegation_policy_test_delay();").await;
    let source = r.source.clone();
    let original = s.clone();
    let task = tokio::spawn(async move {
        source
            .observe_current(active.policy_id, &original, Utc::now())
            .await
    });
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
    loop {
        let committing:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename=$1 AND query='COMMIT' AND wait_event='PgSleep')").bind(&r.role).fetch_one(&f.pool).await.unwrap();
        if committing {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "source reached its final COMMIT"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    task.abort();
    assert!(matches!(task.await,Err(error) if error.is_cancelled()));
    loop {
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM organization_service.delegation_use_policy_observations WHERE organization_id=$1").bind(f.organization).fetch_one(&f.pool).await.unwrap();
        if count == 1 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "final COMMIT completed despite caller cancellation"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    f.sql("DROP TRIGGER z_delegation_policy_test_delay ON organization_service.delegation_use_policy_observations; DROP FUNCTION organization_service.delegation_policy_test_delay();").await;
}
