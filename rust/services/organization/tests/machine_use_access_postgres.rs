//! Real PostgreSQL qualification for explicit component access, independent of
//! cryptographic proof and domain authorization.
use chrono::{DateTime, Duration, Utc};
use marty_organization::{
    catalog::seed_system_roles, machine_registry::*, machine_use_access::*,
    migration::migrate_organization_schema, postgres::PostgresOrganizationStore,
    ForwardedPrincipal, JoinMechanism, Organization, OrganizationCreate, OrganizationType,
};
use marty_principal_runtime_binding::{parse_thumbprint, ThumbprintEncoding};
use serde_json::{json, Value};
use sqlx::{postgres::PgPoolOptions, AssertSqlSafe, PgPool};
use tokio::sync::{Mutex, MutexGuard};
use uuid::Uuid;
static DATABASE_LOCK: Mutex<()> = Mutex::const_new(());
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

fn precise(value: DateTime<Utc>) -> DateTime<Utc> {
    DateTime::from_timestamp_micros(value.timestamp_micros()).unwrap()
}
fn all_rights() -> Vec<MachineUsePermission> {
    vec![
        MachineUsePermission::StartUse,
        MachineUsePermission::FinalizeUse,
        MachineUsePermission::RecoverResult,
        MachineUsePermission::RetrieveRequest,
        MachineUsePermission::SubmitProof,
    ]
}
fn input(permissions: Vec<MachineUsePermission>) -> MachineUseAccessInput {
    let now = precise(Utc::now());
    MachineUseAccessInput {
        permissions,
        valid_from: now - Duration::seconds(1),
        valid_until: now + Duration::hours(1),
    }
}
struct Fixture {
    _lock: MutexGuard<'static, ()>,
    pool: PgPool,
    owner: MachineUseAccessOwner,
    actor: ForwardedPrincipal,
    org: Uuid,
    member: Uuid,
    key: String,
    registry: MachineRegistryService,
    machine: MachineRegistryRecord,
}
impl Fixture {
    async fn new(key_lifetime: Option<Duration>) -> Self {
        let lock = DATABASE_LOCK.lock().await;
        let url = std::env::var("ORGANIZATION_MACHINE_REGISTRY_TEST_DATABASE_URL")
            .expect("explicit disposable local PostgreSQL");
        assert!(matches!(
            url::Url::parse(&url).unwrap().host_str(),
            Some("127.0.0.1" | "[::1]")
        ));
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(&url)
            .await
            .unwrap();
        migrate_organization_schema(&pool).await.unwrap();
        sqlx::query("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
            .execute(&pool)
            .await
            .unwrap();
        let store = PostgresOrganizationStore::new(pool.clone());
        let user_id = format!("use-access-owner-{}", Uuid::new_v4());
        let actor = ForwardedPrincipal::User {
            user_id: user_id.clone(),
        };
        let (org, member) = Organization::create(OrganizationCreate {
            name: format!("Use access {}", Uuid::new_v4()),
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
        store.save_organization(&org).await.unwrap();
        store.save_member(&member).await.unwrap();
        let roles = seed_system_roles(&store, org.id, Utc::now()).await.unwrap();
        store
            .set_member_roles(member.id, &[roles["owner"].id])
            .await
            .unwrap();
        let registry = MachineRegistryService::new(store.clone());
        let (mut docs, _, scope) = documents(org.id);
        if let Some(lifetime) = key_lifetime {
            let mut machine: Value = serde_json::from_slice(&docs.machine_identity).unwrap();
            machine["identity_keys"][0]["valid_until"] = json!(Utc::now() + lifetime);
            docs.machine_identity = serde_json::to_vec(&machine).unwrap();
        }
        let machine = registry.register(org.id, &actor, docs).await.unwrap();
        Self {
            _lock: lock,
            owner: MachineUseAccessOwner::new(store.clone()),
            pool,
            actor,
            org: org.id,
            member: member.id,
            key: scope.key_thumbprint,
            registry,
            machine,
        }
    }
    fn scope(&self, request: MachineUseAccessRequest) -> MachineUseAccessScope {
        MachineUseAccessScope {
            organization_id: self.org,
            principal_id: self.machine.principal_id().into(),
            request,
        }
    }
    fn request(&self, permission: MachineUsePermission) -> MachineUseAccessRequest {
        let grant = Uuid::new_v4();
        let challenge = Uuid::new_v4();
        let terms_digest = format!("sha256:{}", "a".repeat(64));
        match permission {
            MachineUsePermission::StartUse => MachineUseAccessRequest::Start {
                grant_id: grant,
                grant_revision: 1,
                terms_digest,
                key_thumbprint: self.key.clone(),
            },
            MachineUsePermission::FinalizeUse => MachineUseAccessRequest::Finalize {
                grant_id: grant,
                grant_revision: 1,
                terms_digest,
                key_thumbprint: self.key.clone(),
                challenge_id: challenge,
            },
            MachineUsePermission::RecoverResult => MachineUseAccessRequest::Recover {
                grant_id: grant,
                grant_revision: 1,
                terms_digest,
            },
            MachineUsePermission::RetrieveRequest => MachineUseAccessRequest::RequestRead {
                challenge_id: challenge,
            },
            MachineUsePermission::SubmitProof => MachineUseAccessRequest::ProofSubmit {
                challenge_id: challenge,
            },
        }
    }
    async fn source(&self) -> (PgMachineUseAccessSource, String) {
        let role = format!("machine_use_reader_{}", Uuid::new_v4().simple());
        self.sql(&format!("CREATE ROLE {role} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
            GRANT USAGE ON SCHEMA organization_service TO {role};
            GRANT SELECT ON organization_service.rust_schema_versions,organization_service.organizations,organization_service.machine_registry_entries,organization_service.machine_registry_history,organization_service.machine_use_access,organization_service.machine_use_access_history TO {role};")).await;
        let pool = PgPoolOptions::new()
            .max_connections(3)
            .connect_with(self.pool.connect_options().as_ref().clone().username(&role))
            .await
            .unwrap();
        let source = PgMachineUseAccessSource::new(
            pool,
            MachineUseAccessSelection::new(self.org, self.machine.deployment_profile_id()).unwrap(),
        );
        source.readiness().await.unwrap();
        (source, role)
    }
    async fn sql(&self, query: &str) {
        sqlx::raw_sql(AssertSqlSafe(query.to_owned()))
            .execute(&self.pool)
            .await
            .unwrap();
    }
}

#[tokio::test]
#[ignore = "requires disposable local PostgreSQL"]
async fn machine_use_access_owner_separates_rights_and_retains_exact_attributable_history() {
    let f = Fixture::new(None).await;
    let (source, _) = f.source().await;
    assert!(source
        .observe(
            f.scope(f.request(MachineUsePermission::StartUse)),
            Utc::now()
        )
        .await
        .is_err());
    let access = f
        .owner
        .grant(
            f.org,
            &f.actor,
            f.machine.machine_identity_id(),
            input(all_rights()),
        )
        .await
        .unwrap();
    assert_eq!(access.revision, 1);
    let original:Vec<u8>=sqlx::query_scalar("SELECT snapshot_bytes FROM organization_service.machine_use_access_history WHERE organization_id=$1 AND machine_identity_id=$2 AND revision=1")
        .bind(f.org).bind(f.machine.machine_identity_id()).fetch_one(&f.pool).await.unwrap();
    for right in all_rights() {
        let scope = f.scope(f.request(right));
        let observed = source.observe(scope.clone(), Utc::now()).await.unwrap();
        assert_eq!(observed.scope(), &scope);
        assert_eq!(observed.record(), &access);
        assert_eq!(observed.snapshot_bytes(), original);
        assert!(observed.valid_until() <= observed.observed_at() + Duration::seconds(30));
        assert!(observed
            .history_ref()
            .contains(&f.machine.machine_identity_id().to_string()));
    }
    let foreign = ForwardedPrincipal::User {
        user_id: format!("unassigned-{}", Uuid::new_v4()),
    };
    assert!(f
        .owner
        .inspect(f.org, &foreign, f.machine.machine_identity_id())
        .await
        .is_err());
    assert!(f
        .owner
        .grant(f.org, &f.actor, Uuid::new_v4(), input(all_rights()))
        .await
        .is_err());
    assert!(f
        .owner
        .replace(
            f.org,
            &f.actor,
            f.machine.machine_identity_id(),
            2,
            input(all_rights())
        )
        .await
        .is_err());
    let replaced = f
        .owner
        .replace(
            f.org,
            &f.actor,
            f.machine.machine_identity_id(),
            1,
            input(vec![MachineUsePermission::RecoverResult]),
        )
        .await
        .unwrap();
    assert_eq!(replaced.revision, 2);
    for right in all_rights() {
        assert_eq!(
            source
                .observe(f.scope(f.request(right)), Utc::now())
                .await
                .is_ok(),
            right == MachineUsePermission::RecoverResult
        );
    }
    let old:Vec<u8>=sqlx::query_scalar("SELECT snapshot_bytes FROM organization_service.machine_use_access_history WHERE organization_id=$1 AND machine_identity_id=$2 AND revision=1")
        .bind(f.org).bind(f.machine.machine_identity_id()).fetch_one(&f.pool).await.unwrap();
    assert_eq!(old, original);
    let revoked = f
        .owner
        .revoke(f.org, &f.actor, f.machine.machine_identity_id(), 2)
        .await
        .unwrap();
    assert_eq!(revoked.status, "REVOKED");
    assert!(source
        .observe(
            f.scope(f.request(MachineUsePermission::RecoverResult)),
            Utc::now()
        )
        .await
        .is_err());
    assert!(f
        .owner
        .replace(
            f.org,
            &f.actor,
            f.machine.machine_identity_id(),
            3,
            input(all_rights())
        )
        .await
        .is_err());
    assert_eq!(
        f.owner
            .inspect(f.org, &f.actor, f.machine.machine_identity_id())
            .await
            .unwrap(),
        revoked
    );
}

#[tokio::test]
#[ignore = "requires disposable local PostgreSQL"]
async fn machine_use_access_source_rejects_cross_scope_expiry_identity_loss_and_preserves_history_recovery(
) {
    let f = Fixture::new(Some(Duration::seconds(3))).await;
    let (source, role) = f.source().await;
    f.owner
        .grant(
            f.org,
            &f.actor,
            f.machine.machine_identity_id(),
            input(all_rights()),
        )
        .await
        .unwrap();
    let start = f.scope(f.request(MachineUsePermission::StartUse));
    let bounded = source.observe(start.clone(), Utc::now()).await.unwrap();
    assert_eq!(bounded.valid_until().timestamp_subsec_nanos() % 1000, 0);
    let mut wrong = start.clone();
    wrong.organization_id = Uuid::new_v4();
    assert!(source.observe(wrong, Utc::now()).await.is_err());
    let mut wrong = start.clone();
    wrong.principal_id = "urn:foreign:machine".into();
    assert!(source.observe(wrong, Utc::now()).await.is_err());
    let mut wrong = start.clone();
    if let MachineUseAccessRequest::Start { key_thumbprint, .. } = &mut wrong.request {
        *key_thumbprint = format!("sha256:{}", "f".repeat(64));
    }
    assert!(source.observe(wrong, Utc::now()).await.is_err());
    assert!(source
        .observe(start.clone(), Utc::now() - Duration::seconds(31))
        .await
        .is_err());
    assert!(source
        .observe(start.clone(), Utc::now() + Duration::seconds(1))
        .await
        .is_err());
    let other_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(f.pool.connect_options().as_ref().clone().username(&role))
        .await
        .unwrap();
    let other = PgMachineUseAccessSource::new(
        other_pool,
        MachineUseAccessSelection::new(f.org, Uuid::new_v4()).unwrap(),
    );
    assert!(other.observe(start.clone(), Utc::now()).await.is_err());
    tokio::time::sleep(std::time::Duration::from_millis(3100)).await;
    assert!(source.observe(start, Utc::now()).await.is_err());
    assert!(source
        .observe(
            f.scope(f.request(MachineUsePermission::RetrieveRequest)),
            Utc::now()
        )
        .await
        .is_err());
    source
        .observe(
            f.scope(f.request(MachineUsePermission::RecoverResult)),
            Utc::now(),
        )
        .await
        .unwrap();
    f.registry
        .transition(
            f.org,
            &f.actor,
            f.machine.machine_identity_id(),
            1,
            MachineRegistryLifecycle::Suspend,
        )
        .await
        .unwrap();
    assert!(source
        .observe(
            f.scope(f.request(MachineUsePermission::RecoverResult)),
            Utc::now()
        )
        .await
        .is_err());
}

#[tokio::test]
#[ignore = "requires disposable local PostgreSQL"]
async fn machine_use_access_admin_rechecks_permission_after_member_lock_wait() {
    let f = Fixture::new(None).await;
    f.owner
        .grant(
            f.org,
            &f.actor,
            f.machine.machine_identity_id(),
            input(all_rights()),
        )
        .await
        .unwrap();
    let mut block = f.pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM organization_service.members WHERE id=$1 FOR UPDATE")
        .bind(f.member)
        .execute(&mut *block)
        .await
        .unwrap();
    let owner = f.owner.clone();
    let org = f.org;
    let actor = f.actor.clone();
    let machine = f.machine.machine_identity_id();
    let operation = tokio::spawn(async move {
        owner
            .replace(
                org,
                &actor,
                machine,
                1,
                input(vec![MachineUsePermission::RecoverResult]),
            )
            .await
    });
    let mut saw_lock = false;
    for _ in 0..100 {
        saw_lock=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid<>pg_backend_pid() AND wait_event_type='Lock' AND query LIKE '%organization_service.members%')").fetch_one(&f.pool).await.unwrap();
        if saw_lock {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(saw_lock, "owner waits on the current member row");
    sqlx::query("DELETE FROM organization_service.role_permissions rp USING organization_service.permissions p,organization_service.member_roles mr WHERE rp.permission_id=p.id AND rp.role_id=mr.role_id AND mr.member_id=$1 AND p.resource='machine-use-access' AND p.action='update'")
        .bind(f.member).execute(&mut *block).await.unwrap();
    block.commit().await.unwrap();
    assert!(operation.await.unwrap().is_err());
    assert_eq!(
        f.owner
            .inspect(f.org, &f.actor, f.machine.machine_identity_id())
            .await
            .unwrap()
            .revision,
        1
    );
}

#[tokio::test]
#[ignore = "requires disposable local PostgreSQL"]
async fn machine_use_access_readiness_rejects_actual_role_and_schema_drift() {
    let f = Fixture::new(None).await;
    let (source, role) = f.source().await;
    let record = f
        .owner
        .grant(
            f.org,
            &f.actor,
            f.machine.machine_identity_id(),
            input(all_rights()),
        )
        .await
        .unwrap();
    let selection =
        MachineUseAccessSelection::new(f.org, f.machine.deployment_profile_id()).unwrap();
    assert!(PgMachineUseAccessSource::new(f.pool.clone(), selection)
        .readiness()
        .await
        .is_err());
    let masked_role = role.clone();
    let masked = PgPoolOptions::new()
        .max_connections(1)
        .after_connect(move |connection, _| {
            let query = format!("SET ROLE {masked_role}");
            Box::pin(async move {
                sqlx::raw_sql(AssertSqlSafe(query))
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect_with(f.pool.connect_options().as_ref().clone())
        .await
        .unwrap();
    assert!(PgMachineUseAccessSource::new(masked, selection)
        .readiness()
        .await
        .is_err());
    for permission in [
        "SELECT ON organization_service.members",
        "UPDATE(permissions) ON organization_service.machine_use_access",
        "REFERENCES(organization_id) ON organization_service.machine_use_access",
        "INSERT ON organization_service.machine_use_access_history",
        "SELECT ON organization_service.machine_use_access WITH GRANT OPTION",
    ] {
        if let Some(permission) = permission.strip_suffix(" WITH GRANT OPTION") {
            f.sql(&format!("GRANT {permission} TO {role} WITH GRANT OPTION"))
                .await;
        } else {
            f.sql(&format!("GRANT {permission} TO {role}")).await;
        }
        assert!(source.readiness().await.is_err(), "{permission}");
        if permission.ends_with("WITH GRANT OPTION") {
            f.sql(&format!("REVOKE GRANT OPTION FOR SELECT ON organization_service.machine_use_access FROM {role}")).await;
        } else {
            f.sql(&format!("REVOKE {permission} FROM {role}")).await;
        }
        source.readiness().await.unwrap();
    }
    let server_version: i32 =
        sqlx::query_scalar("SELECT current_setting('server_version_num')::INT")
            .fetch_one(&f.pool)
            .await
            .unwrap();
    if server_version >= 170000 {
        f.sql(&format!(
            "GRANT MAINTAIN ON organization_service.machine_use_access TO {role}"
        ))
        .await;
        assert!(source.readiness().await.is_err());
        f.sql(&format!(
            "REVOKE MAINTAIN ON organization_service.machine_use_access FROM {role}"
        ))
        .await;
        source.readiness().await.unwrap();
    }
    for capability in ["pg_execute_server_program", "pg_monitor"] {
        f.sql(&format!("GRANT {capability} TO {role}")).await;
        assert!(source.readiness().await.is_err());
        assert!(source
            .observe(
                f.scope(f.request(MachineUsePermission::StartUse)),
                Utc::now()
            )
            .await
            .is_err());
        f.sql(&format!("REVOKE {capability} FROM {role}")).await;
        source.readiness().await.unwrap();
    }
    f.sql(&format!(
        "CREATE SCHEMA pgx_use_access_role_probe;
         CREATE FUNCTION pgx_use_access_role_probe.owner_function() RETURNS INT LANGUAGE SQL SECURITY DEFINER SET search_path=pg_catalog AS 'SELECT 1';
         REVOKE ALL ON FUNCTION pgx_use_access_role_probe.owner_function() FROM PUBLIC;
         GRANT USAGE ON SCHEMA pgx_use_access_role_probe TO {role};
         GRANT EXECUTE ON FUNCTION pgx_use_access_role_probe.owner_function() TO {role};"
    )).await;
    assert!(source.readiness().await.is_err());
    assert!(source
        .observe(
            f.scope(f.request(MachineUsePermission::StartUse)),
            Utc::now()
        )
        .await
        .is_err());
    f.sql("DROP SCHEMA pgx_use_access_role_probe CASCADE").await;
    source.readiness().await.unwrap();
    f.sql(&format!("ALTER ROLE {role} REPLICATION")).await;
    assert!(source.readiness().await.is_err());
    f.sql(&format!("ALTER ROLE {role} NOREPLICATION")).await;
    source.readiness().await.unwrap();
    for (table, trigger) in [
        ("machine_use_access", "machine_use_access_guard"),
        ("machine_use_access", "machine_use_access_no_removal"),
        ("machine_use_access", "machine_use_access_complete"),
        (
            "machine_use_access_history",
            "machine_use_access_history_guard",
        ),
        (
            "machine_use_access_history",
            "machine_use_access_history_immutable",
        ),
    ] {
        f.sql(&format!(
            "ALTER TABLE organization_service.{table} DISABLE TRIGGER {trigger}"
        ))
        .await;
        assert!(source.readiness().await.is_err());
        f.sql(&format!(
            "ALTER TABLE organization_service.{table} ENABLE TRIGGER {trigger}"
        ))
        .await;
        source.readiness().await.unwrap();
    }
    for (table, constraint) in [
        ("machine_use_access", "machine_use_access_bytes"),
        ("machine_use_access", "machine_use_access_digest"),
        ("machine_use_access", "machine_use_access_window"),
        ("machine_use_access", "machine_use_access_permissions"),
        (
            "machine_use_access_history",
            "machine_use_access_history_bytes",
        ),
        (
            "machine_use_access_history",
            "machine_use_access_history_digest",
        ),
    ] {
        let mut definition:String=sqlx::query_scalar("SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid=to_regclass($1) AND conname=$2")
            .bind(format!("organization_service.{table}")).bind(constraint).fetch_one(&f.pool).await.unwrap();
        if constraint == "machine_use_access_permissions" {
            // PostgreSQL's pretty-printer expands BETWEEN, and reparsing it
            // flattens the original BoolExpr. Restore the reviewed bundled SQL
            // exactly; the readiness check intentionally rejects shape drift.
            definition = include_str!("../migrations/0007_machine_use_access.sql")
                .lines()
                .find_map(|line| {
                    line.trim()
                        .strip_prefix("CONSTRAINT machine_use_access_permissions ")
                })
                .unwrap()
                .to_owned();
        }
        f.sql(&format!("ALTER TABLE organization_service.{table} DROP CONSTRAINT {constraint}, ADD CONSTRAINT {constraint} CHECK(true)")).await;
        assert!(source.readiness().await.is_err());
        f.sql(&format!("ALTER TABLE organization_service.{table} DROP CONSTRAINT {constraint}, ADD CONSTRAINT {constraint} {definition}")).await;
        source.readiness().await.unwrap();
    }
    let body:String=sqlx::query_scalar("SELECT prosrc FROM pg_proc WHERE oid='organization_service.guard_machine_use_access()'::regprocedure").fetch_one(&f.pool).await.unwrap();
    f.sql("CREATE OR REPLACE FUNCTION organization_service.guard_machine_use_access() RETURNS TRIGGER LANGUAGE plpgsql SET search_path=pg_catalog AS 'BEGIN RETURN NEW; END'").await;
    assert!(source.readiness().await.is_err());
    assert!(!body.contains("$restore$"));
    f.sql(&format!("CREATE OR REPLACE FUNCTION organization_service.guard_machine_use_access() RETURNS TRIGGER LANGUAGE plpgsql SET search_path=pg_catalog AS $restore${body}$restore$")).await;
    source.readiness().await.unwrap();
    assert!(sqlx::query("UPDATE organization_service.machine_use_access_history SET actor_user_id='other' WHERE organization_id=$1")
        .bind(f.org).execute(&f.pool).await.is_err());
    assert!(sqlx::query(
        "DELETE FROM organization_service.machine_use_access WHERE organization_id=$1"
    )
    .bind(f.org)
    .execute(&f.pool)
    .await
    .is_err());
    let mut unpaired = record.clone();
    unpaired.revision += 1;
    unpaired.updated_at = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&f.pool)
        .await
        .unwrap();
    let bytes = serde_json::to_vec(&unpaired).unwrap();
    assert!(sqlx::query("UPDATE organization_service.machine_use_access SET revision=$1,updated_at=$2,snapshot=$3,snapshot_bytes=$4,snapshot_digest='sha256:'||encode(sha256($4),'hex') WHERE organization_id=$5 AND machine_identity_id=$6")
        .bind(unpaired.revision as i64).bind(unpaired.updated_at).bind(serde_json::to_value(&unpaired).unwrap()).bind(bytes).bind(f.org).bind(f.machine.machine_identity_id()).execute(&f.pool).await.is_err(),"unpaired revision cannot commit");
    assert_eq!(
        f.owner
            .inspect(f.org, &f.actor, f.machine.machine_identity_id())
            .await
            .unwrap(),
        record
    );
}
