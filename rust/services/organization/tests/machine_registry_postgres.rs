//! Local application scenarios for a real owner and restricted source. Public
//! fixture keys and registered credential IDs do not assert workload/issuer trust.
use std::str::FromStr;

use chrono::{Duration, Utc};
use marty_organization::{
    catalog::seed_system_roles, machine_registry::*, migration::migrate_organization_schema,
    postgres::PostgresOrganizationStore, ForwardedPrincipal, JoinMechanism, Member, MemberStatus,
    Organization, OrganizationCreate, OrganizationType, Role,
};
use marty_principal_runtime_binding::{parse_thumbprint, ThumbprintEncoding};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    AssertSqlSafe, PgPool,
};
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

struct Fixture {
    _guard: MutexGuard<'static, ()>,
    pool: PgPool,
    store: PostgresOrganizationStore,
    owner: ForwardedPrincipal,
    organization: Uuid,
    service: MachineRegistryService,
    url: String,
}
impl Fixture {
    async fn new() -> Self {
        let guard = DATABASE_LOCK.lock().await;
        let url = std::env::var("ORGANIZATION_MACHINE_REGISTRY_TEST_DATABASE_URL")
            .expect("explicit disposable local database URL required");
        let parsed = url::Url::parse(&url).unwrap();
        assert!(matches!(parsed.host_str(), Some("127.0.0.1" | "[::1]")));
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
        let user_id = format!("machine-registry-owner-{}", Uuid::new_v4());
        let (organization, member) = Organization::create(OrganizationCreate {
            name: format!("Machine registry {}", Uuid::new_v4()),
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
            _guard: guard,
            pool,
            service: MachineRegistryService::new(store.clone()),
            store,
            owner: ForwardedPrincipal::User { user_id },
            organization: organization.id,
            url,
        }
    }
    async fn source(
        &self,
        selection: MachineRegistrySelection,
    ) -> (PgMachineRegistrySource, String, PgPool) {
        let role = format!("machine_registry_source_{}", Uuid::new_v4().simple());
        sqlx::raw_sql(AssertSqlSafe(format!("CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
            GRANT USAGE ON SCHEMA organization_service TO {role};
            GRANT SELECT ON organization_service.rust_schema_versions,organization_service.organizations,
                organization_service.machine_registry_entries,organization_service.machine_registry_history,
                organization_service.machine_registry_observations TO {role};
            GRANT INSERT ON organization_service.machine_registry_observations TO {role};")))
            .execute(&self.pool).await.unwrap();
        let options = PgConnectOptions::from_str(&self.url)
            .unwrap()
            .username(&role);
        let pool = PgPoolOptions::new()
            .max_connections(3)
            .after_connect(|connection, _| {
                Box::pin(async move {
                    // Differently configured reader/owner sessions must agree on
                    // the exact source snapshot's timestamp representation.
                    sqlx::query("SET TIME ZONE 'Europe/Paris'")
                        .execute(connection)
                        .await?;
                    Ok(())
                })
            })
            .connect_with(options)
            .await
            .unwrap();
        (
            PgMachineRegistrySource::new(pool.clone(), selection),
            role,
            pool,
        )
    }
    async fn operator(&self, permissions: &[&str]) -> (ForwardedPrincipal, Uuid, Uuid) {
        let now = Utc::now();
        let member = Member::create(
            self.organization,
            format!("machine-operator-{}", Uuid::new_v4()),
            None,
            MemberStatus::Active,
            now,
        );
        self.store.save_member(&member).await.unwrap();
        let mut resolved = Vec::new();
        for permission in permissions {
            let (resource, action) = permission.split_once(':').unwrap();
            resolved.push(
                self.store
                    .permission_by_key(resource, action)
                    .await
                    .unwrap()
                    .expect("catalog permission"),
            );
        }
        let role = Role {
            id: Uuid::new_v4(),
            organization_id: self.organization,
            name: format!("machine-operator-{}", Uuid::new_v4()),
            display_name: None,
            description: None,
            is_system: false,
            is_default_for_new_members: false,
            permissions: resolved,
            created_at: now,
            updated_at: now,
        };
        self.store.save_role(&role).await.unwrap();
        self.store
            .set_member_roles(member.id, &[role.id])
            .await
            .unwrap();
        (
            ForwardedPrincipal::User {
                user_id: member.user_id,
            },
            member.id,
            role.id,
        )
    }
}

#[tokio::test]
#[ignore = "requires disposable local PostgreSQL"]
async fn machine_registry_full_source_retains_exact_selected_history_without_inventory_promotion() {
    let f = Fixture::new().await;
    let (docs, selection, scope) = documents(f.organization);
    let record = f
        .service
        .register(f.organization, &f.owner, docs.clone())
        .await
        .unwrap();
    assert_eq!(record.revision(), 1);
    assert_eq!(record.status(), "ACTIVE");
    let (source, _, source_pool) = f.source(selection).await;
    source.readiness().await.unwrap();
    let original = Utc::now();
    let observed = source.observe(scope.clone(), original).await.unwrap();
    assert!(observed.observed_at() >= original);
    assert_eq!(
        observed.valid_until(),
        chrono::DateTime::from_timestamp_micros(
            (original + Duration::seconds(30)).timestamp_micros()
        )
        .unwrap()
    );
    let retained = source.recover(observed.evidence_ref()).await.unwrap();
    assert_eq!(
        retained.document()["scope"],
        serde_json::to_value(scope).unwrap()
    );
    assert_eq!(
        retained.document()["source_snapshot"]["documents"],
        *record.documents()
    );
    let saved: Value = serde_json::from_slice(retained.evidence_bytes()).unwrap();
    assert_eq!(saved, *retained.document());
    assert!(sqlx::query(
        "UPDATE organization_service.machine_registry_entries SET status='SUSPENDED'"
    )
    .execute(&source_pool)
    .await
    .is_err());
    assert!(
        sqlx::query("DELETE FROM organization_service.machine_registry_observations")
            .execute(&source_pool)
            .await
            .is_err()
    );
    let inventory: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM organization_service.agent_identities WHERE organization_id=$1",
    )
    .bind(f.organization)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(inventory, 0);
    let audit:i64=sqlx::query_scalar("SELECT count(*) FROM organization_service.audit_events WHERE organization_id=$1 AND event_type='machine_registry.changed'")
        .bind(f.organization).fetch_one(&f.pool).await.unwrap();
    assert_eq!(audit, 1);
}

#[tokio::test]
#[ignore = "requires disposable local PostgreSQL"]
async fn machine_registry_human_permissions_are_current_and_map_assignment_is_separate() {
    let f = Fixture::new().await;
    let (docs, _, _) = documents(f.organization);
    let api = ForwardedPrincipal::ApiKey {
        user_id: "owner".into(),
        api_key_id: "key".into(),
        organization_id: f.organization,
        authorized_permission: "machine-identity:create".into(),
    };
    assert_eq!(
        f.service
            .register(f.organization, &api, docs.clone())
            .await
            .unwrap_err(),
        MachineRegistryError::AccessDenied
    );
    let (partial, _, _) = f.operator(&["machine-identity:create"]).await;
    assert_eq!(
        f.service
            .register(f.organization, &partial, docs.clone())
            .await
            .unwrap_err(),
        MachineRegistryError::AccessDenied
    );
    let (actor, member, _) = f
        .operator(&[
            "machine-identity:create",
            "machine-authentication-policy:assign",
        ])
        .await;
    let mut blocker = f.pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM organization_service.members WHERE id=$1 FOR UPDATE")
        .bind(member)
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    let service = f.service.clone();
    let organization = f.organization;
    let work = tokio::spawn(async move { service.register(organization, &actor, docs).await });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(!work.is_finished());
    sqlx::query("UPDATE organization_service.members SET status='deactivated' WHERE id=$1")
        .bind(member)
        .execute(&mut *blocker)
        .await
        .unwrap();
    blocker.commit().await.unwrap();
    assert_eq!(
        work.await.unwrap().unwrap_err(),
        MachineRegistryError::AccessDenied
    );
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM organization_service.machine_registry_entries WHERE organization_id=$1")
        .bind(f.organization).fetch_one(&f.pool).await.unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
#[ignore = "requires disposable local PostgreSQL"]
async fn machine_registry_revision_replacement_revocation_and_historical_evidence_stay_distinct() {
    let f = Fixture::new().await;
    let (mut docs, selection, scope) = documents(f.organization);
    let registered = f
        .service
        .register(f.organization, &f.owner, docs.clone())
        .await
        .unwrap();
    let (source, _, _) = f.source(selection).await;
    let observed = source.observe(scope.clone(), Utc::now()).await.unwrap();
    let old = source.recover(observed.evidence_ref()).await.unwrap();
    let mut policy: Value = serde_json::from_slice(&docs.machine_authentication_policy).unwrap();
    policy["name"] = json!("Explicitly replaced selected MAP");
    docs.machine_authentication_policy = serde_json::to_vec(&policy).unwrap();
    assert_eq!(
        f.service
            .replace(
                f.organization,
                &f.owner,
                registered.machine_identity_id(),
                7,
                docs.clone()
            )
            .await
            .unwrap_err(),
        MachineRegistryError::Conflict
    );
    let changed = f
        .service
        .replace(
            f.organization,
            &f.owner,
            registered.machine_identity_id(),
            1,
            docs.clone(),
        )
        .await
        .unwrap();
    assert_eq!(changed.revision(), 2);
    let fresh = source.observe(scope.clone(), Utc::now()).await.unwrap();
    let new = source.recover(fresh.evidence_ref()).await.unwrap();
    assert_ne!(
        old.document()["source_snapshot"]["policy_digest"],
        new.document()["source_snapshot"]["policy_digest"]
    );
    assert_eq!(
        old.document()["source_snapshot"]["documents"]["machine_authentication_policy"]["name"],
        "Selected local full-machine MAP"
    );
    let revoked = f
        .service
        .transition(
            f.organization,
            &f.owner,
            registered.machine_identity_id(),
            2,
            MachineRegistryLifecycle::Revoke,
        )
        .await
        .unwrap();
    assert_eq!(revoked.revision(), 3);
    assert!(source.observe(scope, Utc::now()).await.is_err());
    assert_eq!(
        f.service
            .replace(
                f.organization,
                &f.owner,
                registered.machine_identity_id(),
                3,
                docs
            )
            .await
            .unwrap_err(),
        MachineRegistryError::InvalidTransition
    );
    let recovered = source.recover(observed.evidence_ref()).await.unwrap();
    assert_eq!(old.evidence_bytes(), recovered.evidence_bytes());
    assert_eq!(old.retained_at(), recovered.retained_at());
    assert!(sqlx::query(
        "UPDATE organization_service.machine_registry_history SET actor_user_id='other'"
    )
    .execute(&f.pool)
    .await
    .is_err());
    assert!(
        sqlx::query("TRUNCATE organization_service.machine_registry_observations")
            .execute(&f.pool)
            .await
            .is_err()
    );
    assert!(sqlx::query("UPDATE organization_service.machine_registry_entries SET revision=revision+1,updated_at=clock_timestamp(),status='ACTIVE' WHERE organization_id=$1")
        .bind(f.organization).execute(&f.pool).await.is_err());
}

#[tokio::test]
#[ignore = "requires disposable local PostgreSQL"]
async fn machine_registry_source_rejects_foreign_scope_expiry_and_excessive_roles() {
    let f = Fixture::new().await;
    let (docs, selection, scope) = documents(f.organization);
    f.service
        .register(f.organization, &f.owner, docs)
        .await
        .unwrap();
    assert_eq!(
        PgMachineRegistrySource::new(f.pool.clone(), selection)
            .readiness()
            .await
            .unwrap_err(),
        MachineRegistryError::AccessDenied
    );
    let (source, role, _) = f.source(selection).await;
    source.readiness().await.unwrap();
    for field in 0..5 {
        let mut wrong = scope.clone();
        match field {
            0 => wrong.organization_id = Uuid::new_v4(),
            1 => wrong.principal_id = "urn:other:machine".into(),
            2 => wrong.key_thumbprint = format!("sha256:{}", "b".repeat(64)),
            3 => wrong.grant_revision = 0,
            _ => wrong.operation_digest = "unqualified".into(),
        }
        assert!(
            source.observe(wrong, Utc::now()).await.is_err(),
            "accepted field {field}"
        );
    }
    assert!(source
        .observe(scope.clone(), Utc::now() - Duration::seconds(31))
        .await
        .is_err());
    assert!(source
        .observe(scope.clone(), Utc::now() + Duration::seconds(31))
        .await
        .is_err());
    let (foreign, _, _) = f
        .source(MachineRegistrySelection::new(f.organization, Uuid::new_v4()).unwrap())
        .await;
    assert!(foreign.observe(scope.clone(), Utc::now()).await.is_err());
    sqlx::raw_sql(AssertSqlSafe(format!(
        "GRANT UPDATE ON organization_service.machine_registry_entries TO {role}"
    )))
    .execute(&f.pool)
    .await
    .unwrap();
    assert_eq!(
        source.observe(scope, Utc::now()).await.unwrap_err(),
        MachineRegistryError::AccessDenied
    );
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM organization_service.machine_registry_observations WHERE organization_id=$1")
        .bind(f.organization).fetch_one(&f.pool).await.unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
#[ignore = "requires disposable local PostgreSQL"]
async fn machine_registry_lock_wait_cannot_renew_the_original_observation_deadline() {
    let f = Fixture::new().await;
    let (docs, selection, scope) = documents(f.organization);
    f.service
        .register(f.organization, &f.owner, docs)
        .await
        .unwrap();
    let (source, _, _) = f.source(selection).await;
    let mut blocker = f.pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE organization_service.machine_registry_observations IN SHARE MODE")
        .execute(&mut *blocker)
        .await
        .unwrap();
    let work = tokio::spawn(async move {
        source
            .observe(scope, Utc::now() - Duration::milliseconds(29_500))
            .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(800)).await;
    assert!(!work.is_finished());
    blocker.commit().await.unwrap();
    assert!(work.await.unwrap().is_err());
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM organization_service.machine_registry_observations WHERE organization_id=$1")
        .bind(f.organization).fetch_one(&f.pool).await.unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
#[ignore = "requires disposable local PostgreSQL"]
async fn machine_registry_rejects_service_account_documents_missing_credentials_and_identity_changes(
) {
    let f = Fixture::new().await;
    let (original, _, _) = documents(f.organization);
    for field in 0..4 {
        let mut docs = original.clone();
        if field == 0 {
            let mut record: Value = serde_json::from_slice(&docs.binding_record).unwrap();
            let mut config: Value = serde_json::from_slice(&docs.binding_configuration).unwrap();
            record["principal"]["type"] = json!("SERVICE_ACCOUNT");
            config["principal"]["type"] = json!("SERVICE_ACCOUNT");
            docs.binding_record = serde_json::to_vec(&record).unwrap();
            docs.binding_configuration = serde_json::to_vec(&config).unwrap();
        } else if field == 1 {
            let mut machine: Value = serde_json::from_slice(&docs.machine_identity).unwrap();
            machine["credential_ids"] = json!([]);
            docs.machine_identity = serde_json::to_vec(&machine).unwrap();
        } else if field == 2 {
            let mut policy: Value =
                serde_json::from_slice(&docs.machine_authentication_policy).unwrap();
            policy["status"] = json!("DRAFT");
            docs.machine_authentication_policy = serde_json::to_vec(&policy).unwrap();
        } else {
            docs.machine_authentication_policy =
                b"{\"status\":\"ACTIVE\",\"status\":\"ACTIVE\"}".to_vec();
        }
        assert_eq!(
            f.service
                .register(f.organization, &f.owner, docs)
                .await
                .unwrap_err(),
            MachineRegistryError::InvalidRequest
        );
    }
    let registered = f
        .service
        .register(f.organization, &f.owner, original.clone())
        .await
        .unwrap();
    let mut wrong = original;
    let mut config: Value = serde_json::from_slice(&wrong.binding_configuration).unwrap();
    let mut record: Value = serde_json::from_slice(&wrong.binding_record).unwrap();
    for value in [&mut config, &mut record] {
        value["runtime"]["instance_ref"] = json!("urn:other:runtime");
    }
    wrong.binding_configuration = serde_json::to_vec(&config).unwrap();
    wrong.binding_record = serde_json::to_vec(&record).unwrap();
    assert_eq!(
        f.service
            .replace(
                f.organization,
                &f.owner,
                registered.machine_identity_id(),
                1,
                wrong
            )
            .await
            .unwrap_err(),
        MachineRegistryError::InvalidRequest
    );
}

#[tokio::test]
#[ignore = "requires disposable local PostgreSQL"]
async fn machine_registry_rotation_rejects_old_grant_key_and_historical_key_reactivation() {
    let f = Fixture::new().await;
    let (original, selection, old_scope) = documents(f.organization);
    let registered = f
        .service
        .register(f.organization, &f.owner, original.clone())
        .await
        .unwrap();
    let mut machine: Value = serde_json::from_slice(&original.machine_identity).unwrap();
    let mut config: Value = serde_json::from_slice(&original.binding_configuration).unwrap();
    let mut record: Value = serde_json::from_slice(&original.binding_record).unwrap();
    machine["identity_keys"][0]["status"] = json!("REVOKED");
    machine["identity_keys"][1]["status"] = json!("ACTIVE");
    machine["identity_keys"][1]["valid_from"] =
        json!((Utc::now() - Duration::seconds(1)).to_rfc3339());
    machine["identity_keys"][1]["valid_until"] =
        json!((Utc::now() + Duration::hours(1)).to_rfc3339());
    let key_id = machine["identity_keys"][1]["key_id"].clone();
    let encoded = machine["identity_keys"][1]["thumbprint"]
        .as_str()
        .unwrap()
        .strip_prefix("sha256:")
        .unwrap();
    let typed = json!({"basis":"JWK_RFC7638_SHA256","encoding":"BASE64URL_SHA256","value":encoded});
    config["runtime"]["active_key_id"] = key_id;
    config["expected_key_algorithm"] = json!("ES256");
    config["expected_key_thumbprint"] = typed.clone();
    record["authentication"]["key_algorithm"] = json!("ES256");
    record["authentication"]["key_thumbprint"] = typed.clone();
    let rotated = MachineRegistryDocuments {
        binding_record: serde_json::to_vec(&record).unwrap(),
        binding_configuration: serde_json::to_vec(&config).unwrap(),
        machine_identity: serde_json::to_vec(&machine).unwrap(),
        machine_authentication_policy: original.machine_authentication_policy.clone(),
    };
    f.service
        .replace(
            f.organization,
            &f.owner,
            registered.machine_identity_id(),
            1,
            rotated,
        )
        .await
        .unwrap();
    let (source, _, _) = f.source(selection).await;
    assert!(source.observe(old_scope.clone(), Utc::now()).await.is_err());
    let mut new_scope = old_scope;
    new_scope.key_thumbprint = parse_thumbprint(&serde_json::to_vec(&typed).unwrap())
        .unwrap()
        .reencode(ThumbprintEncoding::MipSha256Hex)
        .encoded_value();
    source.observe(new_scope, Utc::now()).await.unwrap();
    assert!(f
        .service
        .replace(
            f.organization,
            &f.owner,
            registered.machine_identity_id(),
            2,
            original
        )
        .await
        .is_err());
    let history: i64 = sqlx::query_scalar("SELECT count(*) FROM organization_service.machine_registry_history WHERE organization_id=$1")
        .bind(f.organization).fetch_one(&f.pool).await.unwrap();
    assert_eq!(history, 2);
}

#[tokio::test]
#[ignore = "requires disposable local PostgreSQL"]
async fn machine_registry_requires_complete_audit_and_unexpired_commit() {
    let f = Fixture::new().await;
    let (docs, selection, scope) = documents(f.organization);
    let registered = f
        .service
        .register(f.organization, &f.owner, docs)
        .await
        .unwrap();
    let mut incomplete = f.pool.begin().await.unwrap();
    sqlx::query("WITH candidate AS MATERIALIZED (
        SELECT organization_id,machine_identity_id,clock_timestamp() AS changed_at,jsonb_set(documents,'{machine_identity,display_name}','\"Unattributed change\"'::jsonb) AS doc
        FROM organization_service.machine_registry_entries WHERE organization_id=$1 AND machine_identity_id=$2)
        UPDATE organization_service.machine_registry_entries r SET documents=c.doc,document_bytes=convert_to(c.doc::text,'UTF8'),
          document_digest='sha256:'||encode(sha256(convert_to(c.doc::text,'UTF8')),'hex'),revision=revision+1,
          documents_recorded_at=c.changed_at,updated_at=c.changed_at
        FROM candidate c WHERE r.organization_id=c.organization_id AND r.machine_identity_id=c.machine_identity_id")
        .bind(f.organization).bind(registered.machine_identity_id()).execute(&mut *incomplete).await.unwrap();
    assert!(incomplete.commit().await.is_err());
    let (source, _, source_pool) = f.source(selection).await;
    let observed = source.observe(scope, Utc::now()).await.unwrap();
    let history = source.recover(observed.evidence_ref()).await.unwrap();
    let mut document = history.document().clone();
    let now = chrono::DateTime::from_timestamp_micros(Utc::now().timestamp_micros()).unwrap();
    let until = now + Duration::milliseconds(200);
    document["started_at"] = json!(now);
    document["observed_at"] = json!(now);
    document["valid_until"] = json!(until);
    document["scope"]["challenge_id"] = json!(Uuid::new_v4());
    let bytes = serde_json::to_vec(&document).unwrap();
    let hex = format!("{:x}", Sha256::digest(&bytes));
    let mut tx = source_pool.begin().await.unwrap();
    sqlx::query("SET LOCAL TIME ZONE 'UTC'")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("INSERT INTO organization_service.machine_registry_observations
        (organization_id,machine_identity_id,revision,evidence_ref,evidence_digest,document,evidence_bytes,observed_at,valid_until)
        VALUES ($1,$2,1,$3,$4,$5,$6,$7,$8)")
        .bind(f.organization).bind(registered.machine_identity_id())
        .bind(format!("{MACHINE_REGISTRY_SOURCE_REF_PREFIX}{hex}")).bind(format!("sha256:{hex}"))
        .bind(document).bind(bytes).bind(now).bind(until).execute(&mut *tx).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    assert!(tx.commit().await.is_err());
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM organization_service.machine_registry_observations WHERE organization_id=$1")
        .bind(f.organization).fetch_one(&f.pool).await.unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
#[ignore = "requires disposable local PostgreSQL"]
async fn machine_registry_cancelled_provider_does_not_cancel_an_in_progress_commit() {
    let f = Fixture::new().await;
    let (docs, selection, scope) = documents(f.organization);
    f.service
        .register(f.organization, &f.owner, docs)
        .await
        .unwrap();
    let (source, role, _) = f.source(selection).await;
    // Explicit test-only delayed deferred trigger; reviewed source guards remain
    // unchanged. This simulates COMMIT I/O that outlives the caller's timeout.
    sqlx::raw_sql(
        "CREATE OR REPLACE FUNCTION organization_service.machine_registry_test_delay_commit()
        RETURNS TRIGGER LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
        BEGIN PERFORM pg_sleep(0.6); RETURN NULL; END $fn$;
        CREATE CONSTRAINT TRIGGER machine_registry_test_delay_commit AFTER INSERT
        ON organization_service.machine_registry_observations DEFERRABLE INITIALLY DEFERRED
        FOR EACH ROW EXECUTE FUNCTION organization_service.machine_registry_test_delay_commit();",
    )
    .execute(&f.pool)
    .await
    .unwrap();
    let work = tokio::spawn(async move { source.observe(scope, Utc::now()).await });
    let mut committing = false;
    for _ in 0..40 {
        committing = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename=$1 AND query='COMMIT' AND wait_event='PgSleep')")
            .bind(&role).fetch_one(&f.pool).await.unwrap();
        if committing {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(
        committing,
        "source reached the final commit before cancellation"
    );
    work.abort();
    assert!(
        work.await.unwrap_err().is_cancelled(),
        "caller received no positive observation"
    );
    tokio::time::sleep(std::time::Duration::from_millis(650)).await;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM organization_service.machine_registry_observations WHERE organization_id=$1")
        .bind(f.organization).fetch_one(&f.pool).await.unwrap();
    sqlx::raw_sql("DROP TRIGGER machine_registry_test_delay_commit ON organization_service.machine_registry_observations;
        DROP FUNCTION organization_service.machine_registry_test_delay_commit();")
        .execute(&f.pool).await.unwrap();
    assert_eq!(count, 1, "the already-started commit finished exactly once");
}

#[tokio::test]
#[ignore = "requires disposable local PostgreSQL"]
async fn machine_registry_readiness_rejects_check_replacement_and_privilege_delegation() {
    let f = Fixture::new().await;
    let (docs, selection, scope) = documents(f.organization);
    f.service
        .register(f.organization, &f.owner, docs)
        .await
        .unwrap();
    let (source, role, _) = f.source(selection).await;
    source.readiness().await.unwrap();
    sqlx::raw_sql(AssertSqlSafe(format!("GRANT SELECT(principal_id) ON organization_service.machine_registry_entries TO {role} WITH GRANT OPTION")))
        .execute(&f.pool).await.unwrap();
    assert_eq!(
        source.readiness().await.unwrap_err(),
        MachineRegistryError::AccessDenied
    );
    sqlx::raw_sql(AssertSqlSafe(format!("REVOKE GRANT OPTION FOR SELECT(principal_id) ON organization_service.machine_registry_entries FROM {role}")))
        .execute(&f.pool).await.unwrap();
    source.readiness().await.unwrap();
    sqlx::raw_sql("ALTER TABLE organization_service.machine_registry_observations DROP CONSTRAINT machine_registry_observation_digest;
        ALTER TABLE organization_service.machine_registry_observations ADD CONSTRAINT machine_registry_observation_digest CHECK (true);")
        .execute(&f.pool).await.unwrap();
    assert_eq!(
        source.observe(scope, Utc::now()).await.unwrap_err(),
        MachineRegistryError::Unavailable
    );
    sqlx::raw_sql("ALTER TABLE organization_service.machine_registry_observations DROP CONSTRAINT machine_registry_observation_digest;
        ALTER TABLE organization_service.machine_registry_observations ADD CONSTRAINT machine_registry_observation_digest CHECK (evidence_digest='sha256:'||encode(sha256(evidence_bytes),'hex'));")
        .execute(&f.pool).await.unwrap();
    source.readiness().await.unwrap();
}

#[tokio::test]
#[ignore = "requires disposable local PostgreSQL"]
async fn machine_registry_key_expiry_bounds_source_but_preserves_history_and_terminal_administration(
) {
    let f = Fixture::new().await;
    let (mut docs, selection, scope) = documents(f.organization);
    let key_until = chrono::DateTime::from_timestamp_micros(
        (Utc::now() + Duration::seconds(2)).timestamp_micros(),
    )
    .unwrap();
    let mut machine: Value = serde_json::from_slice(&docs.machine_identity).unwrap();
    machine["identity_keys"][0]["valid_until"] = json!(key_until);
    docs.machine_identity = serde_json::to_vec(&machine).unwrap();
    let registered = f
        .service
        .register(f.organization, &f.owner, docs)
        .await
        .unwrap();
    let (source, _, _) = f.source(selection).await;
    let original = source.observe(scope.clone(), Utc::now()).await.unwrap();
    assert_eq!(original.valid_until(), key_until);
    let retained = source.recover(original.evidence_ref()).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(2_100)).await;
    assert!(source.observe(scope, Utc::now()).await.is_err());
    let recovered = source.recover(original.evidence_ref()).await.unwrap();
    assert_eq!(retained.evidence_bytes(), recovered.evidence_bytes());
    let inspected = f
        .service
        .inspect(f.organization, &f.owner, registered.machine_identity_id())
        .await
        .unwrap();
    assert_eq!(inspected.document_bytes(), registered.document_bytes());
    let revoked = f
        .service
        .transition(
            f.organization,
            &f.owner,
            registered.machine_identity_id(),
            1,
            MachineRegistryLifecycle::Revoke,
        )
        .await
        .unwrap();
    assert_eq!(revoked.status(), "REVOKED");
    assert_eq!(
        revoked.documents_recorded_at(),
        registered.documents_recorded_at()
    );
    assert!(revoked.updated_at() > registered.updated_at());
}

#[tokio::test]
#[ignore = "requires disposable local PostgreSQL"]
async fn machine_registry_rejects_predefined_role_membership_and_replication() {
    let f = Fixture::new().await;
    let (docs, selection, scope) = documents(f.organization);
    f.service
        .register(f.organization, &f.owner, docs)
        .await
        .unwrap();
    let (source, role, _) = f.source(selection).await;
    source.readiness().await.unwrap();
    // Permission inspection only: no server-file or server-program function is
    // invoked. The existing source instance must observe privilege drift.
    sqlx::raw_sql(AssertSqlSafe(format!(
        "GRANT pg_execute_server_program TO {role}"
    )))
    .execute(&f.pool)
    .await
    .unwrap();
    assert_eq!(
        source.readiness().await.unwrap_err(),
        MachineRegistryError::AccessDenied
    );
    assert_eq!(
        source.observe(scope.clone(), Utc::now()).await.unwrap_err(),
        MachineRegistryError::AccessDenied
    );
    sqlx::raw_sql(AssertSqlSafe(format!(
        "REVOKE pg_execute_server_program FROM {role}; ALTER ROLE {role} REPLICATION;"
    )))
    .execute(&f.pool)
    .await
    .unwrap();
    assert_eq!(
        source.readiness().await.unwrap_err(),
        MachineRegistryError::AccessDenied
    );
    assert_eq!(
        source.observe(scope, Utc::now()).await.unwrap_err(),
        MachineRegistryError::AccessDenied
    );
    sqlx::raw_sql(AssertSqlSafe(format!("ALTER ROLE {role} NOREPLICATION")))
        .execute(&f.pool)
        .await
        .unwrap();
    source.readiness().await.unwrap();
}
