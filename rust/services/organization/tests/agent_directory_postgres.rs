//! Locally authored application scenarios. No private protocol corpus is bundled.
//! Live cases are explicit ignores until a disposable PostgreSQL URL is supplied.
use chrono::Utc;
use marty_organization::{
    agent_directory::*,
    catalog::seed_system_roles,
    migration::{migrate_organization_schema, validate_organization_schema},
    postgres::PostgresOrganizationStore,
    ForwardedPrincipal, JoinMechanism, Member, MemberStatus, Organization, OrganizationCreate,
    OrganizationType, Role,
};
use marty_principal_runtime_binding::parse_thumbprint;
use serde_json::{json, Value};
use sqlx::{postgres::PgPoolOptions, AssertSqlSafe, PgPool};
use tokio::sync::{Mutex, MutexGuard};
use uuid::Uuid;

static DATABASE_LOCK: Mutex<()> = Mutex::const_new(());

fn key(name: &str) -> Value {
    let values: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../crates/principal-runtime-binding/tests/fixtures/public-keys.json"
    )))
    .unwrap();
    values["keys"][name]["jwk"].clone()
}
fn request(kind: AgentKind) -> RegisterAgentRequest {
    RegisterAgentRequest {
        kind,
        display_name: "Local inventory worker".into(),
        description: Some("Public synthetic example".into()),
        logical_application_ref: "urn:application-test:inventory-app".into(),
        issuer: "https://identity.application-tests.invalid/issuer".into(),
        subject: format!("inventory-worker-{}", Uuid::new_v4()),
        runtime_instance_ref: format!("urn:application-test:runtime:{}", Uuid::new_v4()),
        public_key_jwk: key("external_worker"),
    }
}
struct Fixture {
    _guard: MutexGuard<'static, ()>,
    pool: PgPool,
    store: PostgresOrganizationStore,
    service: AgentDirectoryService,
    organization: Uuid,
    owner: ForwardedPrincipal,
    owner_member: Uuid,
}
impl Fixture {
    async fn new() -> Self {
        let guard = DATABASE_LOCK.lock().await;
        let url = std::env::var("ORGANIZATION_AGENT_DIRECTORY_TEST_DATABASE_URL")
            .expect("explicit disposable database URL required for ignored agent-directory cases");
        let parsed = url::Url::parse(&url).unwrap();
        assert!(
            matches!(parsed.host_str(), Some("127.0.0.1" | "[::1]")),
            "agent directory database must be disposable and local"
        );
        let pool = PgPoolOptions::new()
            .max_connections(6)
            .connect(&url)
            .await
            .unwrap();
        migrate_organization_schema(&pool).await.unwrap();
        validate_organization_schema(&pool).await.unwrap();
        let store = PostgresOrganizationStore::new(pool.clone());
        let owner_id = format!("agent-directory-owner-{}", Uuid::new_v4());
        let (organization, member) = Organization::create(OrganizationCreate {
            name: format!("Agent directory {}", Uuid::new_v4()),
            owner_id: owner_id.clone(),
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
            service: AgentDirectoryService::new(store.clone()),
            store,
            organization: organization.id,
            owner: ForwardedPrincipal::User { user_id: owner_id },
            owner_member: member.id,
        }
    }
    async fn register(&self, kind: AgentKind) -> AgentIdentity {
        self.service
            .register(self.organization, &self.owner, request(kind))
            .await
            .unwrap()
    }
    async fn counts(&self) -> (i64, i64, i64, i64) {
        let mut counts = Vec::new();
        for query in [
            "SELECT count(*) FROM organization_service.agent_identities WHERE organization_id=$1",
            "SELECT count(*) FROM organization_service.agent_identity_keys WHERE organization_id=$1",
            "SELECT count(*) FROM organization_service.agent_identity_history WHERE organization_id=$1",
            "SELECT count(*) FROM organization_service.audit_events WHERE organization_id=$1 AND event_type='agent_identity.changed'",
        ] { counts.push(sqlx::query_scalar::<_,i64>(query).bind(self.organization).fetch_one(&self.pool).await.unwrap()); }
        (counts[0], counts[1], counts[2], counts[3])
    }
    async fn operator(&self, permissions: &[&str]) -> (ForwardedPrincipal, Uuid, Uuid) {
        let now = Utc::now();
        let member = Member::create(
            self.organization,
            format!("directory-operator-{}", Uuid::new_v4()),
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
                    .unwrap(),
            );
        }
        let role = Role {
            id: Uuid::new_v4(),
            organization_id: self.organization,
            name: format!("directory-operator-{}", Uuid::new_v4()),
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

#[test]
fn agent_directory_raw_requests_reject_owned_fields_ambiguity_and_type_confusion() {
    let body = json!({"kind":"EXTERNAL","display_name":"Local worker","logical_application_ref":"urn:application-test:app","issuer":"https://id.application-tests.invalid","subject":"worker","runtime_instance_ref":"urn:application-test:runtime","public_key_jwk":key("external_worker")});
    assert!(
        decode_agent_request::<RegisterAgentRequest>(&serde_json::to_vec(&body).unwrap()).is_ok()
    );
    for field in [
        "owner_user_id",
        "created_by",
        "organization_id",
        "id",
        "status",
        "assurance",
        "managed_enrollment",
        "principal",
    ] {
        let mut changed = body.clone();
        changed[field] = json!("caller-selected");
        assert_eq!(
            decode_agent_request::<RegisterAgentRequest>(&serde_json::to_vec(&changed).unwrap())
                .unwrap_err(),
            AgentDirectoryError::InvalidRequest
        );
    }
    for raw in [
        br#"{"expected_revision":1,"expected_revision":2}"#.as_slice(),
        br#"{"expected_revision":true}"#,
        br#"{"expected_revision":1.0}"#,
        br#"{"expected_revision":1e0}"#,
        br#"{"expected_revision":1,"owner":null}"#,
        br#"{"expected_revision":1,"nested":{"a":1,"a":2}}"#,
    ] {
        assert!(decode_agent_request::<AgentLifecycleRequest>(raw).is_err());
    }
    assert!(
        decode_agent_request::<RegisterAgentRequest>(&vec![b' '; MAX_AGENT_REQUEST_BYTES + 1])
            .is_err()
    );
}

#[tokio::test]
#[ignore = "requires ORGANIZATION_AGENT_DIRECTORY_TEST_DATABASE_URL and actual PostgreSQL"]
async fn agent_directory_registration_is_accountable_and_managed_stays_unqualified() {
    let f = Fixture::new().await;
    let request_id = Uuid::new_v4();
    let external = f
        .service
        .clone()
        .with_request_id(request_id)
        .register(f.organization, &f.owner, request(AgentKind::External))
        .await
        .unwrap();
    let ForwardedPrincipal::User { user_id } = &f.owner else {
        unreachable!()
    };
    assert_eq!(external.created_by, *user_id);
    assert_eq!(external.owner_user_id, *user_id);
    assert_eq!(external.status, AgentIdentityStatus::Active);
    assert_eq!(external.principal.principal_type, "EXTERNAL");
    assert_eq!(external.authority_status, "NOT_ASSESSED");
    let binding = f
        .service
        .lookup_current(
            f.organization,
            external.id,
            &external.keys[0].fingerprint.typed().unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(binding.identity(), &external);
    let managed = f.register(AgentKind::Managed).await;
    assert_eq!(managed.status, AgentIdentityStatus::Provisioned);
    assert_eq!(managed.principal.principal_type, "SERVICE_ACCOUNT");
    assert_eq!(managed.provenance.managed_enrollment, "NOT_ASSESSED");
    assert_eq!(
        f.service
            .lookup_current(
                f.organization,
                managed.id,
                &managed.keys[0].fingerprint.typed().unwrap()
            )
            .await
            .unwrap_err(),
        AgentDirectoryError::AccessDenied
    );
    let history = f
        .service
        .history(f.organization, &f.owner, external.id, 20, 0)
        .await
        .unwrap();
    assert_eq!(history.total, 1);
    assert_eq!(history.items[0].request_id, request_id);
    assert_eq!(history.items[0].snapshot, external);
    assert_eq!(f.counts().await, (2, 2, 2, 2));
    assert_eq!(
        f.service
            .list(f.organization, &f.owner, 20, 0)
            .await
            .unwrap()
            .total,
        2
    );
    assert!(matches!(
        f.service
            .inspect(Uuid::new_v4(), &f.owner, external.id)
            .await,
        Err(AgentDirectoryError::AccessDenied)
    ));
    let mut certificate = serde_json::to_value(&external.keys[0].fingerprint).unwrap();
    certificate["basis"] = json!("X509_CERTIFICATE_DER_SHA256");
    let certificate = parse_thumbprint(&serde_json::to_vec(&certificate).unwrap()).unwrap();
    assert_eq!(
        f.service
            .lookup_current(f.organization, external.id, &certificate)
            .await
            .unwrap_err(),
        AgentDirectoryError::AccessDenied
    );
}

#[tokio::test]
#[ignore = "requires ORGANIZATION_AGENT_DIRECTORY_TEST_DATABASE_URL and actual PostgreSQL"]
async fn agent_directory_key_replacement_preserves_old_evidence_and_denies_old_keys() {
    let f = Fixture::new().await;
    let original = f.register(AgentKind::External).await;
    let old_key = original.keys[0].fingerprint.typed().unwrap();
    let rotated = f
        .service
        .rotate_key(
            f.organization,
            &f.owner,
            original.id,
            RotateAgentKeyRequest {
                expected_revision: 1,
                public_key_jwk: key("managed_worker"),
            },
        )
        .await
        .unwrap();
    assert_eq!(rotated.revision, 2);
    assert_ne!(rotated.keys[0].key_id, original.keys[0].key_id);
    assert_eq!(
        f.service
            .lookup_current(f.organization, original.id, &old_key)
            .await
            .unwrap_err(),
        AgentDirectoryError::AccessDenied
    );
    assert!(f
        .service
        .lookup_current(
            f.organization,
            original.id,
            &rotated.keys[0].fingerprint.typed().unwrap()
        )
        .await
        .is_ok());
    let history = f
        .service
        .history(f.organization, &f.owner, original.id, 20, 0)
        .await
        .unwrap();
    assert_eq!(history.items[1].snapshot, original);
    assert_eq!(
        f.service
            .rotate_key(
                f.organization,
                &f.owner,
                original.id,
                RotateAgentKeyRequest {
                    expected_revision: 2,
                    public_key_jwk: key("external_worker")
                }
            )
            .await
            .unwrap_err(),
        AgentDirectoryError::Conflict
    );
    let old_status: String = sqlx::query_scalar(
        "SELECT status FROM organization_service.agent_identity_keys WHERE key_id=$1",
    )
    .bind(original.keys[0].key_id)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(old_status, "RETIRED");
    let mut private = key("rotation_candidate");
    private["d"] = json!("not-a-public-member");
    assert_eq!(
        f.service
            .rotate_key(
                f.organization,
                &f.owner,
                original.id,
                RotateAgentKeyRequest {
                    expected_revision: 2,
                    public_key_jwk: private
                }
            )
            .await
            .unwrap_err(),
        AgentDirectoryError::InvalidRequest
    );
    assert_eq!(f.counts().await, (1, 2, 2, 2));
}

#[tokio::test]
#[ignore = "requires ORGANIZATION_AGENT_DIRECTORY_TEST_DATABASE_URL and actual PostgreSQL"]
async fn agent_directory_suspend_revoke_and_retire_never_reactivate_identity() {
    let f = Fixture::new().await;
    let original = f.register(AgentKind::External).await;
    let suspended = f
        .service
        .transition(
            f.organization,
            &f.owner,
            original.id,
            AgentLifecycleAction::Suspend,
            AgentLifecycleRequest {
                expected_revision: 1,
            },
        )
        .await
        .unwrap();
    assert_eq!(suspended.status, AgentIdentityStatus::Suspended);
    assert_eq!(
        f.service
            .lookup_current(
                f.organization,
                original.id,
                &original.keys[0].fingerprint.typed().unwrap()
            )
            .await
            .unwrap_err(),
        AgentDirectoryError::AccessDenied
    );
    let rotated = f
        .service
        .rotate_key(
            f.organization,
            &f.owner,
            original.id,
            RotateAgentKeyRequest {
                expected_revision: 2,
                public_key_jwk: key("support_session"),
            },
        )
        .await
        .unwrap();
    assert_eq!(rotated.status, AgentIdentityStatus::Suspended);
    let revoked = f
        .service
        .transition(
            f.organization,
            &f.owner,
            original.id,
            AgentLifecycleAction::Revoke,
            AgentLifecycleRequest {
                expected_revision: 3,
            },
        )
        .await
        .unwrap();
    assert_eq!(revoked.status, AgentIdentityStatus::Revoked);
    assert!(revoked.keys.is_empty());
    assert_eq!(
        f.service
            .rotate_key(
                f.organization,
                &f.owner,
                original.id,
                RotateAgentKeyRequest {
                    expected_revision: 4,
                    public_key_jwk: key("rotation_candidate")
                }
            )
            .await
            .unwrap_err(),
        AgentDirectoryError::InvalidTransition
    );
    let retired = f
        .service
        .transition(
            f.organization,
            &f.owner,
            original.id,
            AgentLifecycleAction::Retire,
            AgentLifecycleRequest {
                expected_revision: 4,
            },
        )
        .await
        .unwrap();
    assert_eq!(retired.status, AgentIdentityStatus::Retired);
    assert_eq!(
        f.service
            .transition(
                f.organization,
                &f.owner,
                original.id,
                AgentLifecycleAction::Revoke,
                AgentLifecycleRequest {
                    expected_revision: 5
                }
            )
            .await
            .unwrap_err(),
        AgentDirectoryError::InvalidTransition
    );
    assert_eq!(
        f.service
            .history(f.organization, &f.owner, original.id, 20, 0)
            .await
            .unwrap()
            .total,
        5
    );
}

#[tokio::test]
#[ignore = "requires ORGANIZATION_AGENT_DIRECTORY_TEST_DATABASE_URL and actual PostgreSQL"]
async fn agent_directory_metadata_compare_and_swap_has_one_winner() {
    let f = Fixture::new().await;
    let original = f.register(AgentKind::External).await;
    let a = UpdateAgentMetadataRequest {
        expected_revision: 1,
        display_name: "Updated A".into(),
        description: None,
        logical_application_ref: "urn:application-test:app:a".into(),
    };
    let b = UpdateAgentMetadataRequest {
        expected_revision: 1,
        display_name: "Updated B".into(),
        description: None,
        logical_application_ref: "urn:application-test:app:b".into(),
    };
    let (a, b) = tokio::join!(
        f.service
            .update_metadata(f.organization, &f.owner, original.id, a),
        f.service
            .update_metadata(f.organization, &f.owner, original.id, b)
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert!(
        matches!(a, Err(AgentDirectoryError::Conflict))
            || matches!(b, Err(AgentDirectoryError::Conflict))
    );
    let current = f
        .service
        .inspect(f.organization, &f.owner, original.id)
        .await
        .unwrap();
    assert_eq!(current.owner_user_id, original.owner_user_id);
    assert_eq!(current.issuer, original.issuer);
    assert_eq!(current.runtime_instance_ref, original.runtime_instance_ref);
    assert_eq!(current.keys, original.keys);
    assert_eq!(f.counts().await, (1, 1, 2, 2));
}

#[tokio::test]
#[ignore = "requires ORGANIZATION_AGENT_DIRECTORY_TEST_DATABASE_URL and actual PostgreSQL"]
async fn agent_directory_api_keys_inactive_members_and_missing_permissions_are_denied() {
    let f = Fixture::new().await;
    let ForwardedPrincipal::User { user_id } = &f.owner else {
        unreachable!()
    };
    let api = ForwardedPrincipal::ApiKey {
        user_id: user_id.clone(),
        api_key_id: Uuid::new_v4().to_string(),
        organization_id: f.organization,
        authorized_permission: "agent-identity:create".into(),
    };
    assert_eq!(
        f.service
            .register(f.organization, &api, request(AgentKind::External))
            .await
            .unwrap_err(),
        AgentDirectoryError::AccessDenied
    );
    assert_eq!(
        f.service
            .list(f.organization, &api, 20, 0)
            .await
            .unwrap_err(),
        AgentDirectoryError::AccessDenied
    );
    let (no_permission, _, _) = f.operator(&[]).await;
    assert_eq!(
        f.service
            .register(f.organization, &no_permission, request(AgentKind::External))
            .await
            .unwrap_err(),
        AgentDirectoryError::AccessDenied
    );
    sqlx::query("UPDATE organization_service.members SET status='deactivated' WHERE id=$1")
        .bind(f.owner_member)
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        f.service
            .register(f.organization, &f.owner, request(AgentKind::Managed))
            .await
            .unwrap_err(),
        AgentDirectoryError::AccessDenied
    );
    assert_eq!(f.counts().await, (0, 0, 0, 0));
}

#[tokio::test]
#[ignore = "requires ORGANIZATION_AGENT_DIRECTORY_TEST_DATABASE_URL and actual PostgreSQL"]
async fn agent_directory_permission_revocation_during_lock_wait_fails_closed() {
    let f = Fixture::new().await;
    let (operator, _, role) = f.operator(&["agent-identity:create"]).await;
    let mut blocker = f.pool.begin().await.unwrap();
    sqlx::query("DELETE FROM organization_service.role_permissions WHERE role_id=$1")
        .bind(role)
        .execute(&mut *blocker)
        .await
        .unwrap();
    let service = f.service.clone();
    let organization = f.organization;
    let attempt = tokio::spawn(async move {
        service
            .register(organization, &operator, request(AgentKind::External))
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(3),async {
        loop {
            let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%FOR SHARE OF rp,p%')").fetch_one(&f.pool).await.unwrap();
            if waiting { break; } tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }).await.expect("directory authorization must actually wait on the changed permission edge");
    blocker.commit().await.unwrap();
    assert_eq!(
        attempt.await.unwrap().unwrap_err(),
        AgentDirectoryError::AccessDenied
    );
    assert_eq!(f.counts().await, (0, 0, 0, 0));
}

#[tokio::test]
#[ignore = "requires ORGANIZATION_AGENT_DIRECTORY_TEST_DATABASE_URL and actual PostgreSQL"]
async fn agent_directory_history_failure_rolls_back_identity_key_and_audit() {
    let f = Fixture::new().await;
    // A fixture-only constraint forces failure after the entity/key writes.
    sqlx::raw_sql("ALTER TABLE organization_service.agent_identity_history ADD CONSTRAINT agent_directory_test_reject CHECK (false) NOT VALID").execute(&f.pool).await.unwrap();
    let result = f
        .service
        .register(f.organization, &f.owner, request(AgentKind::External))
        .await;
    sqlx::raw_sql("ALTER TABLE organization_service.agent_identity_history DROP CONSTRAINT agent_directory_test_reject").execute(&f.pool).await.unwrap();
    assert_eq!(result.unwrap_err(), AgentDirectoryError::Unavailable);
    assert_eq!(f.counts().await, (0, 0, 0, 0));
    let _ = f.register(AgentKind::External).await;
    assert_eq!(f.counts().await, (1, 1, 1, 1));
}

#[tokio::test]
#[ignore = "requires ORGANIZATION_AGENT_DIRECTORY_TEST_DATABASE_URL and actual PostgreSQL"]
async fn agent_directory_database_guards_preserve_history_and_exactly_one_key() {
    let f = Fixture::new().await;
    let original = f.register(AgentKind::Managed).await;
    let mut tx = f.pool.begin().await.unwrap();
    sqlx::query("UPDATE organization_service.agent_identity_keys SET status='RETIRED',ended_at=clock_timestamp() WHERE organization_id=$1 AND agent_id=$2")
        .bind(f.organization).bind(original.id).execute(&mut *tx).await.unwrap();
    assert!(
        tx.commit().await.is_err(),
        "losing the only active managed inventory key must fail at commit"
    );
    assert!(sqlx::query(
        "DELETE FROM organization_service.agent_identity_history WHERE organization_id=$1"
    )
    .bind(f.organization)
    .execute(&f.pool)
    .await
    .is_err());
    assert!(sqlx::query("UPDATE organization_service.agent_identity_history SET action=action WHERE organization_id=$1").bind(f.organization).execute(&f.pool).await.is_err());
    assert!(sqlx::query(
        "DELETE FROM organization_service.agent_identities WHERE organization_id=$1"
    )
    .bind(f.organization)
    .execute(&f.pool)
    .await
    .is_err());
    let snapshot = f
        .service
        .inspect(f.organization, &f.owner, original.id)
        .await
        .unwrap();
    assert_eq!(snapshot, original);
    assert_eq!(f.counts().await, (1, 1, 1, 1));
}

#[tokio::test]
#[ignore = "requires ORGANIZATION_AGENT_DIRECTORY_TEST_DATABASE_URL and actual PostgreSQL"]
async fn agent_directory_lifecycle_history_cannot_conceal_metadata_or_key_changes() {
    let f = Fixture::new().await;
    let original = f.register(AgentKind::External).await;
    for (action, status, hidden_change) in [
        ("SUSPEND", "SUSPENDED", "metadata"),
        ("SUSPEND", "SUSPENDED", "keys"),
        ("REVOKE", "REVOKED", "metadata"),
        ("REVOKE", "REVOKED", "retained_keys"),
        ("RETIRE", "RETIRED", "metadata"),
        ("RETIRE", "RETIRED", "retained_keys"),
    ] {
        let mut tx = f.pool.begin().await.unwrap();
        let occurred_at: chrono::DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        let mut snapshot = serde_json::to_value(&original).unwrap();
        snapshot["revision"] = json!(2);
        snapshot["status"] = json!(status);
        snapshot["updated_at"] = json!(occurred_at);
        if action != "SUSPEND" && hidden_change != "retained_keys" {
            snapshot["keys"] = json!([]);
        }
        if hidden_change == "metadata" {
            snapshot["metadata"]["display_name"] = json!("Hidden metadata mutation");
        } else if hidden_change == "keys" {
            snapshot["keys"] = json!([]);
        }
        sqlx::query("UPDATE organization_service.agent_identities SET status=$1,revision=2,document=$2,updated_at=$3 WHERE organization_id=$4 AND id=$5")
            .bind(status).bind(&snapshot).bind(occurred_at).bind(f.organization).bind(original.id)
            .execute(&mut *tx).await.unwrap();
        let failure = sqlx::query("INSERT INTO organization_service.agent_identity_history (organization_id,agent_id,revision,action,actor_user_id,request_id,occurred_at,snapshot) VALUES ($1,$2,2,$3,$4,$5,$6,$7)")
            .bind(f.organization).bind(original.id).bind(action).bind(&original.created_by)
            .bind(Uuid::new_v4()).bind(occurred_at).bind(snapshot)
            .execute(&mut *tx).await.unwrap_err();
        assert!(failure
            .to_string()
            .contains("agent history action is inconsistent"));
        tx.rollback().await.unwrap();
    }
    assert_eq!(f.counts().await, (1, 1, 1, 1));
    assert_eq!(
        f.service
            .inspect(f.organization, &f.owner, original.id)
            .await
            .unwrap(),
        original
    );
}

#[tokio::test]
#[ignore = "requires ORGANIZATION_AGENT_DIRECTORY_TEST_DATABASE_URL and actual PostgreSQL"]
async fn agent_directory_schema_validation_rejects_same_name_ineffective_guards() {
    let f = Fixture::new().await;
    // Each drift preserves the original object name and a superficially valid
    // enabled trigger/index. Startup must inspect the actual binding and shape.
    for (table, name, replacement) in [
        (
            "agent_identities",
            "agent_identity_guard",
            "CREATE TRIGGER agent_identity_guard BEFORE INSERT OR UPDATE ON organization_service.agent_identities FOR EACH ROW EXECUTE FUNCTION organization_service.guard_agent_key()",
        ),
        (
            "agent_identities",
            "agent_identity_guard",
            "CREATE TRIGGER agent_identity_guard AFTER INSERT OR UPDATE ON organization_service.agent_identities FOR EACH ROW EXECUTE FUNCTION organization_service.guard_agent_identity()",
        ),
        (
            "agent_identities",
            "agent_identity_guard",
            "CREATE TRIGGER agent_identity_guard BEFORE INSERT OR UPDATE OF document ON organization_service.agent_identities FOR EACH ROW EXECUTE FUNCTION organization_service.guard_agent_identity()",
        ),
        (
            "agent_identities",
            "agent_identity_complete",
            "CREATE TRIGGER agent_identity_complete AFTER INSERT OR UPDATE ON organization_service.agent_identities FOR EACH ROW EXECUTE FUNCTION organization_service.check_agent_inventory_complete()",
        ),
        (
            "agent_identities",
            "agent_identity_complete",
            "CREATE CONSTRAINT TRIGGER agent_identity_complete AFTER INSERT OR UPDATE ON organization_service.agent_identities DEFERRABLE INITIALLY IMMEDIATE FOR EACH ROW EXECUTE FUNCTION organization_service.check_agent_inventory_complete()",
        ),
        (
            "agent_identity_history",
            "agent_history_immutable",
            "CREATE TRIGGER agent_history_immutable BEFORE UPDATE ON organization_service.agent_identity_history FOR EACH STATEMENT EXECUTE FUNCTION organization_service.reject_agent_directory_mutation()",
        ),
    ] {
        let original: String = sqlx::query_scalar(
            "SELECT pg_get_triggerdef(oid) FROM pg_trigger WHERE tgrelid=to_regclass($1) AND tgname=$2",
        )
        .bind(format!("organization_service.{table}"))
        .bind(name)
        .fetch_one(&f.pool)
        .await
        .unwrap();
        // Audited fixture DDL: identifiers and mutations are fixed test literals;
        // the restoration comes only from this disposable database's own
        // pg_get_triggerdef output. No caller text enters these SQL strings.
        let drop = format!("DROP TRIGGER {name} ON organization_service.{table}");
        sqlx::raw_sql(AssertSqlSafe(format!("{drop}; {replacement}")))
            .execute(&f.pool)
            .await
            .unwrap();
        let result = validate_organization_schema(&f.pool).await;
        sqlx::raw_sql(AssertSqlSafe(format!("{drop}; {original}")))
            .execute(&f.pool)
            .await
            .unwrap();
        validate_organization_schema(&f.pool).await.unwrap();
        assert!(result.is_err(), "ineffective trigger accepted: {replacement}");
    }
    let index_name = "organization_service.agent_identity_one_active_key";
    let original: String = sqlx::query_scalar("SELECT pg_get_indexdef($1::regclass)")
        .bind(index_name)
        .fetch_one(&f.pool)
        .await
        .unwrap();
    for replacement in [
        "CREATE UNIQUE INDEX agent_identity_one_active_key ON organization_service.agent_identity_keys(organization_id,key_id) WHERE status='ACTIVE'",
        "CREATE UNIQUE INDEX agent_identity_one_active_key ON organization_service.agent_identity_keys(organization_id,agent_id) WHERE status='RETIRED'",
        "CREATE UNIQUE INDEX agent_identity_one_active_key ON organization_service.agent_identities(organization_id,id) WHERE status='ACTIVE'",
    ] {
        // Fixed fixture identifiers and pg_get_indexdef from the same isolated
        // database; no HTTP, environment or other caller values are interpolated.
        sqlx::raw_sql(AssertSqlSafe(format!("DROP INDEX {index_name}; {replacement}")))
            .execute(&f.pool)
            .await
            .unwrap();
        let result = validate_organization_schema(&f.pool).await;
        sqlx::raw_sql(AssertSqlSafe(format!("DROP INDEX {index_name}; {original}")))
            .execute(&f.pool)
            .await
            .unwrap();
        validate_organization_schema(&f.pool).await.unwrap();
        assert!(result.is_err(), "ineffective key index accepted: {replacement}");
    }
    for mutation in ["SET search_path=public", "SECURITY DEFINER"] {
        sqlx::raw_sql(AssertSqlSafe(format!(
            "ALTER FUNCTION organization_service.guard_agent_identity() {mutation}"
        )))
        .execute(&f.pool)
        .await
        .unwrap();
        let result = validate_organization_schema(&f.pool).await;
        sqlx::raw_sql(
            "ALTER FUNCTION organization_service.guard_agent_identity() SET search_path=pg_catalog; ALTER FUNCTION organization_service.guard_agent_identity() SECURITY INVOKER",
        )
        .execute(&f.pool)
        .await
        .unwrap();
        validate_organization_schema(&f.pool).await.unwrap();
        assert!(
            result.is_err(),
            "unsafe guard configuration accepted: {mutation}"
        );
    }
}
