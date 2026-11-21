//! Actual Organization policy/source storage and MMF evaluation. Upstream
//! machine/credential/proof inputs here are explicit synthetic qualified-fixture
//! inputs; these tests do not claim live workload authentication or attestation.
use super::*;
use crate::{DelegationUseRequest, Principal, VerifiedDelegateProof};
use chrono::Duration;
use marty_organization::{
    catalog::seed_system_roles,
    machine_authorization::{MachineAuthorizationPolicyInput, MachineAuthorizationPolicyOwner},
    migration::migrate_organization_schema,
    postgres::PostgresOrganizationStore,
    CedarPolicyDocument, ForwardedPrincipal, JoinMechanism, Organization, OrganizationCreate,
    OrganizationType,
};
use marty_principal_runtime_binding::{
    machine_policy::{
        qualify_machine_binding, MachineAuthenticationPolicy, QualifiedMachineBinding,
    },
    parse_binding_record, parse_configuration, parse_machine_snapshot,
};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::AssertSqlSafe;
use std::{
    str::FromStr,
    sync::atomic::{AtomicUsize, Ordering},
};
use tokio::sync::{Mutex, MutexGuard};

static DATABASE_LOCK: Mutex<()> = Mutex::const_new(());
struct Fixture {
    _lock: MutexGuard<'static, ()>,
    pool: PgPool,
    org: Uuid,
    deployment: Uuid,
    owner: MachineAuthorizationPolicyOwner,
    actor: ForwardedPrincipal,
    policy_id: Uuid,
    source: Arc<OrganizationMachineCedarPolicySource>,
    evidence: PgMachineAuthorizationEvidenceRepository,
}
fn input(permit: bool) -> MachineAuthorizationPolicyInput {
    let effect = if permit { "permit" } else { "forbid" };
    MachineAuthorizationPolicyInput{name:format!("Scoped machine policy {}",Uuid::new_v4()),description:None,policies:vec![CedarPolicyDocument{policy_id:"machine-decision".into(),effect:effect.into(),cedar_text:format!("{effect}(principal is MartyMachine::Principal,action == MartyMachine::Action::\"urn:marty:machine:authenticate\",resource is MartyMachine::Identity) when {{ context.requested_action == \"urn:application-test:perform\" && context.grant_revision > 0 }};"),description:None,enabled:true}]}
}
impl Fixture {
    async fn new() -> Self {
        let lock = DATABASE_LOCK.lock().await;
        let url = std::env::var("MACHINE_POLICY_SOURCE_TEST_DATABASE_URL")
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
        crate::PgDelegationGrantRepository::new(pool.clone())
            .migrate()
            .await
            .unwrap();
        let store = PostgresOrganizationStore::new(pool.clone());
        let user_id = format!("machine-policy-admin-{}", Uuid::new_v4());
        let (org, member) = Organization::create(OrganizationCreate {
            name: format!("Machine source {}", Uuid::new_v4()),
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
        store.save_organization(&org).await.unwrap();
        store.save_member(&member).await.unwrap();
        let roles = seed_system_roles(&store, org.id, Utc::now()).await.unwrap();
        store
            .set_member_roles(member.id, &[roles["owner"].id])
            .await
            .unwrap();
        let actor = ForwardedPrincipal::User { user_id };
        let owner = MachineAuthorizationPolicyOwner::new(store);
        let draft = owner.create(org.id, &actor, input(true)).await.unwrap();
        owner
            .activate(org.id, &actor, draft.policy_set_id, 1)
            .await
            .unwrap();
        let reader = format!("mp_source_{}", Uuid::new_v4().simple());
        let writer = format!("mp_audit_{}", Uuid::new_v4().simple());
        sqlx::raw_sql(AssertSqlSafe(format!("CREATE ROLE {reader} LOGIN; GRANT USAGE ON SCHEMA organization_service TO {reader}; GRANT SELECT ON organization_service.rust_schema_versions,organization_service.organizations,organization_service.policy_sets,organization_service.machine_authorization_policy_history TO {reader}; CREATE ROLE {writer} LOGIN; GRANT USAGE ON SCHEMA delegated_authority_service TO {writer}; GRANT SELECT ON delegated_authority_service.schema_migrations,delegated_authority_service.machine_authorization_evidence TO {writer}; GRANT INSERT ON delegated_authority_service.machine_authorization_evidence TO {writer};")))
            .execute(&pool).await.unwrap();
        let options = PgConnectOptions::from_str(&url).unwrap();
        let reader = PgPoolOptions::new()
            .max_connections(3)
            .connect_with(options.clone().username(&reader))
            .await
            .unwrap();
        let writer = PgPoolOptions::new()
            .max_connections(3)
            .connect_with(options.username(&writer))
            .await
            .unwrap();
        let evidence = PgMachineAuthorizationEvidenceRepository::new(writer);
        let deployment = Uuid::new_v4();
        let source = Arc::new(
            OrganizationMachineCedarPolicySource::new(
                PgMachineAuthorizationPolicySource::new(reader),
                evidence.clone(),
                org.id,
                deployment,
            )
            .unwrap(),
        );
        source.readiness().await.unwrap();
        Self {
            _lock: lock,
            pool,
            org: org.id,
            deployment,
            owner,
            actor,
            policy_id: draft.policy_set_id,
            source,
            evidence,
        }
    }
    async fn counts(&self) -> (i64, i64) {
        let source:i64=sqlx::query_scalar("SELECT count(*) FROM delegated_authority_service.machine_authorization_evidence WHERE organization_id=$1 AND kind='SOURCE'").bind(self.org).fetch_one(&self.pool).await.unwrap();
        let evaluation:i64=sqlx::query_scalar("SELECT count(*) FROM delegated_authority_service.machine_authorization_evidence WHERE organization_id=$1 AND kind='EVALUATION'").bind(self.org).fetch_one(&self.pool).await.unwrap();
        (source, evaluation)
    }
}
struct Request {
    scope: MachineAuthenticationScope,
    policy: MachineAuthenticationPolicy,
    qualified: QualifiedMachineBinding,
    operation: DelegationUseRequest,
    proof: VerifiedDelegateProof,
}
impl Request {
    fn new(f: &Fixture) -> Self {
        let now = Utc::now();
        let mut d:Value=serde_json::from_str(include_str!("../../../crates/principal-runtime-binding/tests/fixtures/managed-service-with-rotating-candidate.json")).unwrap();
        let principal = Principal {
            principal_type: PrincipalType::MachineIdentity,
            id: d["machine_identity"]["machine_id"].as_str().unwrap().into(),
        };
        for target in ["configuration", "record"] {
            d[target]["organization_id"] = json!(f.org);
            d[target]["principal"] = json!(principal);
        }
        d["configuration"]["authentication_source"] =
            json!({"issuer":principal.id,"subject":principal.id});
        d["record"]["authentication"]["issuer"] = json!(principal.id);
        d["record"]["authentication"]["subject"] = json!(principal.id);
        d["configuration"]["deployment_profile_id"] = json!(f.deployment);
        d["machine_identity"]["organization_id"] = json!(f.org);
        d["machine_identity"]["assignments"]["deployment_profile_id"] = json!(f.deployment);
        d["machine_identity"]["assignments"]["operator_organization_id"] = json!(f.org);
        d["machine_identity"]["credential_ids"] = json!([Uuid::new_v4()]);
        d["machine_identity"]["identity_keys"][0]["valid_until"] =
            json!((now + Duration::hours(1)).to_rfc3339());
        let policy=MachineAuthenticationPolicy::from_trusted_document(&serde_json::to_vec(&json!({
            "id":Uuid::new_v4(),"organization_id":f.org,"name":"Synthetic upstream MAP for owner tests","trust_profile_id":Uuid::new_v4(),
            "required_credential_types":["MachineCredential"],"allowed_machine_types":["SECURE_PROCESSING_RUNTIME"],
            "machine_binding":{"binding_methods":["MACHINE_KEY"],"proof_profiles":["OID4VP_VERIFIABLE_PRESENTATION"],"proof_freshness":{"challenge_required":true,"audience_binding_required":true,"replay_detection_required":true,"max_proof_age_seconds":120}},
            "authorization_policy_set_id":f.policy_id,"status":"ACTIVE","created_at":(now-Duration::hours(1)).to_rfc3339()
        })).unwrap()).unwrap();
        let record = parse_binding_record(&serde_json::to_vec(&d["record"]).unwrap()).unwrap();
        let config =
            parse_configuration(&serde_json::to_vec(&d["configuration"]).unwrap()).unwrap();
        let machine =
            parse_machine_snapshot(&serde_json::to_vec(&d["machine_identity"]).unwrap()).unwrap();
        let qualified =
            qualify_machine_binding(f.org, &policy, &record, &config, &machine, now).unwrap();
        let scope = MachineAuthenticationScope {
            organization_id: f.org,
            machine_identity_id: qualified.machine_identity_id(),
            deployment_profile_id: f.deployment,
            principal: principal.clone(),
            runtime_instance_ref: qualified.binding().runtime_instance_ref().into(),
            key_id: qualified.key_id().into(),
            key_thumbprint: qualified
                .binding()
                .key_thumbprint()
                .delegation_key_thumbprint()
                .unwrap(),
            policy_id: policy.id(),
            policy_digest: policy.digest().into(),
            grant_id: Uuid::new_v4(),
            grant_revision: 2,
            challenge_id: Uuid::new_v4(),
            challenge_digest: format!("sha256:{}", "a".repeat(64)),
            proof_evidence_ref: format!("urn:marty:oid4vp-proof:{}", "b".repeat(64)),
            action: "urn:application-test:perform".into(),
            audience: "urn:application-test:audience".into(),
            resource: "urn:application-test:resource".into(),
            operation_profile: "urn:application-test:operation:v1".into(),
            operation_digest: format!("sha256:{}", "c".repeat(64)),
        };
        let operation = DelegationUseRequest {
            organization_id: f.org,
            grant_id: scope.grant_id,
            expected_revision: scope.grant_revision,
            challenge_id: scope.challenge_id,
            actor: principal,
            action: scope.action.clone(),
            audience: scope.audience.clone(),
            resource: scope.resource.clone(),
            operation_profile: scope.operation_profile.clone(),
            operation_digest: scope.operation_digest.clone(),
            proof: vec![],
        };
        let proof = VerifiedDelegateProof {
            evidence_ref: scope.proof_evidence_ref.clone(),
            challenge: "synthetic-upstream-challenge".into(),
            verified_at: now,
            valid_until: now + Duration::seconds(60),
        };
        Self {
            scope,
            policy,
            qualified,
            operation,
            proof,
        }
    }
    fn evidence(&self) -> MachineEvidenceRequest<'_> {
        MachineEvidenceRequest {
            scope: &self.scope,
            policy: &self.policy,
            qualified_binding: &self.qualified,
            operation: &self.operation,
            proof: &self.proof,
            now: Utc::now(),
        }
    }
}

#[tokio::test]
#[ignore = "requires disposable local PostgreSQL"]
async fn machine_policy_source_retains_exact_policy_schema_scope_and_real_mmf_permit() {
    let f = Fixture::new().await;
    let request = Request::new(&f);
    let verifier = AuditedMmfMachineAuthorizationVerifier::new(f.source.clone());
    verifier.readiness().await.unwrap();
    let result = verifier.verify_permitted(request.evidence()).await.unwrap();
    assert_eq!(result.scope, request.scope);
    assert_eq!(result.policy_set_id, f.policy_id);
    assert_eq!(result.revision, 2);
    assert_eq!(f.counts().await, (1, 1));
    let history = f
        .evidence
        .recover(f.org, &result.evidence_ref)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        history.evidence_document()["scope"],
        serde_json::to_value(&request.scope).unwrap()
    );
    assert_eq!(history.evidence_document()["decision"], "PERMIT");
    let source_ref = history.evidence_document()["source_evidence_ref"]
        .as_str()
        .unwrap();
    let source = f
        .evidence
        .recover(f.org, source_ref)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        source.evidence_document()["schema"],
        MACHINE_AUTHORIZATION_SCHEMA
    );
    assert_eq!(
        source.evidence_document()["policy_snapshot"]["policy_set_id"],
        f.policy_id.to_string()
    );
    assert_eq!(source.evidence_document()["policy_snapshot"]["revision"], 2);
    assert_eq!(
        source.evidence_document()["entities"][0]["attrs"],
        json!({})
    );
    assert!(f
        .evidence
        .recover(Uuid::new_v4(), &result.evidence_ref)
        .await
        .unwrap()
        .is_none());
    // Original bytes and retention time are not rewritten by exact duplicate.
    let document = history.evidence_document();
    let observed = DateTime::parse_from_rfc3339(document["observed_at"].as_str().unwrap())
        .unwrap()
        .with_timezone(&Utc);
    let completed = DateTime::parse_from_rfc3339(document["evaluated_at"].as_str().unwrap())
        .unwrap()
        .with_timezone(&Utc);
    let expiry = DateTime::parse_from_rfc3339(document["valid_until"].as_str().unwrap())
        .unwrap()
        .with_timezone(&Utc);
    f.evidence
        .retain("EVALUATION", document, observed, completed, expiry)
        .await
        .unwrap();
    let duplicate = f
        .evidence
        .recover(f.org, &result.evidence_ref)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(duplicate.evidence_bytes(), history.evidence_bytes());
    assert_eq!(duplicate.retained_at(), history.retained_at());
    f.owner
        .archive(f.org, &f.actor, f.policy_id, 2)
        .await
        .unwrap();
    assert!(verifier.verify_permitted(request.evidence()).await.is_err());
    assert_eq!(
        f.evidence
            .recover(f.org, &result.evidence_ref)
            .await
            .unwrap()
            .unwrap()
            .evidence_bytes(),
        history.evidence_bytes()
    );
    assert_eq!(f.counts().await, (1, 1));
}

#[tokio::test]
#[ignore = "requires disposable local PostgreSQL"]
async fn machine_policy_source_fails_foreign_scope_unknown_policy_and_real_forbid() {
    let f = Fixture::new().await;
    let request = Request::new(&f);
    for scope in [
        {
            let mut s = request.scope.clone();
            s.organization_id = Uuid::new_v4();
            s
        },
        {
            let mut s = request.scope.clone();
            s.deployment_profile_id = Uuid::new_v4();
            s
        },
        {
            let mut s = request.scope.clone();
            s.principal.principal_type = PrincipalType::ServiceAccount;
            s
        },
    ] {
        assert!(f
            .source
            .resolve_current(&scope, f.policy_id, Utc::now())
            .await
            .is_err());
    }
    assert!(f
        .source
        .resolve_current(&request.scope, Uuid::new_v4(), Utc::now())
        .await
        .is_err());
    assert_eq!(f.counts().await, (0, 0));
    f.owner
        .archive(f.org, &f.actor, f.policy_id, 2)
        .await
        .unwrap();
    f.owner
        .replace(f.org, &f.actor, f.policy_id, 3, input(false))
        .await
        .unwrap();
    f.owner
        .activate(f.org, &f.actor, f.policy_id, 4)
        .await
        .unwrap();
    let verifier = AuditedMmfMachineAuthorizationVerifier::new(f.source.clone());
    assert!(verifier.verify_permitted(request.evidence()).await.is_err());
    assert_eq!(f.counts().await, (1, 0));
}

struct ExpiringClock {
    calls: AtomicUsize,
    expire_on: usize,
}
impl DelegationClock for ExpiringClock {
    fn now(&self) -> DateTime<Utc> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        Utc::now()
            + if n >= self.expire_on {
                Duration::seconds(31)
            } else {
                Duration::zero()
            }
    }
}
#[tokio::test]
#[ignore = "requires disposable local PostgreSQL"]
async fn machine_policy_source_and_evaluation_commit_cannot_renew_original_deadline() {
    let f = Fixture::new().await;
    let request = Request::new(&f);
    let source = OrganizationMachineCedarPolicySource::with_clock(
        f.source.owner.clone(),
        f.evidence.clone(),
        f.org,
        f.deployment,
        Arc::new(ExpiringClock {
            calls: AtomicUsize::new(0),
            expire_on: 2,
        }),
    )
    .unwrap();
    assert!(source
        .resolve_current(&request.scope, f.policy_id, Utc::now())
        .await
        .is_err());
    assert_eq!(f.counts().await, (1, 0));
    let verifier = AuditedMmfMachineAuthorizationVerifier::with_clock(
        f.source.clone(),
        Arc::new(ExpiringClock {
            calls: AtomicUsize::new(0),
            expire_on: 4,
        }),
    );
    assert!(verifier.verify_permitted(request.evidence()).await.is_err());
    assert_eq!(f.counts().await, (2, 1));
    // Expiry returns no authority although immutable historical records remain.
    let refs:Vec<String>=sqlx::query_scalar("SELECT evidence_ref FROM delegated_authority_service.machine_authorization_evidence WHERE organization_id=$1").bind(f.org).fetch_all(&f.pool).await.unwrap();
    for reference in refs {
        assert!(f
            .evidence
            .recover(f.org, &reference)
            .await
            .unwrap()
            .is_some());
    }
}

#[tokio::test]
#[ignore = "requires disposable local PostgreSQL"]
async fn machine_policy_audit_guards_and_role_boundaries_reject_rewrite_or_missing_source() {
    let f = Fixture::new().await;
    let request = Request::new(&f);
    let result = AuditedMmfMachineAuthorizationVerifier::new(f.source.clone())
        .verify_permitted(request.evidence())
        .await
        .unwrap();
    for query in ["UPDATE delegated_authority_service.machine_authorization_evidence SET kind='SOURCE' WHERE organization_id=$1","DELETE FROM delegated_authority_service.machine_authorization_evidence WHERE organization_id=$1"] {
        assert!(sqlx::query(query).bind(f.org).execute(&f.pool).await.is_err());
    }
    assert!(
        sqlx::raw_sql("TRUNCATE delegated_authority_service.machine_authorization_evidence")
            .execute(&f.pool)
            .await
            .is_err()
    );
    assert!(
        PgMachineAuthorizationEvidenceRepository::new(f.pool.clone())
            .readiness()
            .await
            .is_err()
    );
    let writer_role: String = sqlx::query_scalar("SELECT current_user::TEXT")
        .fetch_one(&f.evidence.pool)
        .await
        .unwrap();
    let masked_writer = masked_admin_pool(&f.pool, writer_role.clone()).await;
    assert!(
        PgMachineAuthorizationEvidenceRepository::new(masked_writer)
            .readiness()
            .await
            .is_err(),
        "SET ROLE cannot hide a privileged login"
    );
    let reader_role = format!("mp_masked_reader_{}", Uuid::new_v4().simple());
    sqlx::raw_sql(AssertSqlSafe(format!("CREATE ROLE {reader_role} LOGIN; GRANT USAGE ON SCHEMA organization_service TO {reader_role}; GRANT SELECT ON organization_service.rust_schema_versions,organization_service.organizations,organization_service.policy_sets,organization_service.machine_authorization_policy_history TO {reader_role};")))
        .execute(&f.pool).await.unwrap();
    let reader_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(
            f.pool
                .connect_options()
                .as_ref()
                .clone()
                .username(&reader_role),
        )
        .await
        .unwrap();
    let policy_reader = PgMachineAuthorizationPolicySource::new(reader_pool);
    policy_reader.readiness().await.unwrap();
    let masked_reader = masked_admin_pool(&f.pool, reader_role.clone()).await;
    assert!(
        PgMachineAuthorizationPolicySource::new(masked_reader)
            .readiness()
            .await
            .is_err(),
        "SET ROLE cannot hide a privileged owner-reader login"
    );
    // These predefined capabilities do not appear as application-table writes
    // or security-definer function access. No source needs them. Exercise real
    // role grants/attributes without invoking any privileged functionality.
    for (role, is_reader) in [(&writer_role, false), (&reader_role, true)] {
        assert!(role.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'));
        for capability in ["pg_execute_server_program", "pg_monitor"] {
            sqlx::raw_sql(AssertSqlSafe(format!("GRANT {capability} TO {role}")))
                .execute(&f.pool)
                .await
                .unwrap();
            let allowed = if is_reader {
                policy_reader.readiness().await.is_ok()
            } else {
                f.evidence.readiness().await.is_ok()
            };
            assert!(!allowed, "{role} must reject {capability} membership");
            sqlx::raw_sql(AssertSqlSafe(format!("REVOKE {capability} FROM {role}")))
                .execute(&f.pool)
                .await
                .unwrap();
            let allowed = if is_reader {
                policy_reader.readiness().await.is_ok()
            } else {
                f.evidence.readiness().await.is_ok()
            };
            assert!(allowed, "minimal privileges recover after revocation");
        }
        sqlx::raw_sql(AssertSqlSafe(format!("ALTER ROLE {role} REPLICATION")))
            .execute(&f.pool)
            .await
            .unwrap();
        let allowed = if is_reader {
            policy_reader.readiness().await.is_ok()
        } else {
            f.evidence.readiness().await.is_ok()
        };
        assert!(!allowed, "{role} must reject replication capability");
        sqlx::raw_sql(AssertSqlSafe(format!("ALTER ROLE {role} NOREPLICATION")))
            .execute(&f.pool)
            .await
            .unwrap();
        let allowed = if is_reader {
            policy_reader.readiness().await.is_ok()
        } else {
            f.evidence.readiness().await.is_ok()
        };
        assert!(
            allowed,
            "minimal privileges recover after removing replication"
        );
    }
    let history = f
        .evidence
        .recover(f.org, &result.evidence_ref)
        .await
        .unwrap()
        .unwrap();
    let mut document = history.evidence_document().clone();
    document["source_evidence_ref"] = json!(format!("{SOURCE_PREFIX}sha256:{}", "f".repeat(64)));
    let observed = DateTime::parse_from_rfc3339(document["observed_at"].as_str().unwrap())
        .unwrap()
        .with_timezone(&Utc);
    let completed = DateTime::parse_from_rfc3339(document["evaluated_at"].as_str().unwrap())
        .unwrap()
        .with_timezone(&Utc);
    let expiry = DateTime::parse_from_rfc3339(document["valid_until"].as_str().unwrap())
        .unwrap()
        .with_timezone(&Utc);
    assert!(f
        .evidence
        .retain("EVALUATION", &document, observed, completed, expiry)
        .await
        .is_err());
    // Every retained scope member is compared to its committed source. A
    // different valid-looking operation cannot reuse the original permit.
    for key in history.evidence_document()["scope"]
        .as_object()
        .unwrap()
        .keys()
    {
        let mut changed = history.evidence_document().clone();
        changed["scope"][key] = match key.as_str() {
            "grant_revision" => json!(99),
            "principal" => {
                json!({"type":"MACHINE_IDENTITY","id":"urn:application-test:another-machine"})
            }
            "organization_id"
            | "machine_identity_id"
            | "deployment_profile_id"
            | "policy_id"
            | "grant_id"
            | "challenge_id" => json!(Uuid::new_v4()),
            _ => json!("urn:application-test:changed-scope"),
        };
        assert!(
            f.evidence
                .retain("EVALUATION", &changed, observed, completed, expiry)
                .await
                .is_err(),
            "{key}"
        );
    }
    assert_eq!(f.counts().await, (1, 1));
    sqlx::query("ALTER TABLE delegated_authority_service.machine_authorization_evidence DISABLE TRIGGER machine_authorization_evidence_commit").execute(&f.pool).await.unwrap();
    assert!(f.evidence.readiness().await.is_err());
    sqlx::query("ALTER TABLE delegated_authority_service.machine_authorization_evidence ENABLE TRIGGER machine_authorization_evidence_commit").execute(&f.pool).await.unwrap();
    f.evidence.readiness().await.unwrap();
    // Matching names alone cannot qualify a weakened constraint or guard.
    sqlx::raw_sql("ALTER TABLE delegated_authority_service.machine_authorization_evidence DROP CONSTRAINT machine_authorization_evidence_digest; ALTER TABLE delegated_authority_service.machine_authorization_evidence ADD CONSTRAINT machine_authorization_evidence_digest CHECK(true)")
        .execute(&f.pool).await.unwrap();
    assert!(f.evidence.readiness().await.is_err());
    sqlx::raw_sql("ALTER TABLE delegated_authority_service.machine_authorization_evidence DROP CONSTRAINT machine_authorization_evidence_digest; ALTER TABLE delegated_authority_service.machine_authorization_evidence ADD CONSTRAINT machine_authorization_evidence_digest CHECK(evidence_digest='sha256:'||encode(sha256(evidence_bytes),'hex'))")
        .execute(&f.pool).await.unwrap();
    f.evidence.readiness().await.unwrap();
    let body:String=sqlx::query_scalar("SELECT prosrc FROM pg_proc WHERE oid='delegated_authority_service.guard_machine_authorization_evidence()'::regprocedure").fetch_one(&f.pool).await.unwrap();
    sqlx::raw_sql("CREATE OR REPLACE FUNCTION delegated_authority_service.guard_machine_authorization_evidence() RETURNS TRIGGER LANGUAGE plpgsql SET search_path=pg_catalog AS $$ BEGIN RETURN NEW; END $$;")
        .execute(&f.pool).await.unwrap();
    assert!(f.evidence.readiness().await.is_err());
    // Exact reviewed body was read from this fixture's own original function;
    // it contains no delimiter below and no user-supplied SQL identifier.
    assert!(!body.contains("$restore$"));
    sqlx::raw_sql(AssertSqlSafe(format!("CREATE OR REPLACE FUNCTION delegated_authority_service.guard_machine_authorization_evidence() RETURNS TRIGGER LANGUAGE plpgsql SET search_path=pg_catalog AS $restore${body}$restore$;")))
        .execute(&f.pool).await.unwrap();
    f.evidence.readiness().await.unwrap();
}

async fn masked_admin_pool(admin: &PgPool, role: String) -> PgPool {
    assert!(role.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'));
    PgPoolOptions::new()
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
        .connect_with(admin.connect_options().as_ref().clone())
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "requires disposable local PostgreSQL"]
async fn machine_policy_cancelled_caller_does_not_cancel_inflight_commit_or_get_a_permit() {
    let f = Fixture::new().await;
    let request = Request::new(&f);
    let verifier = AuditedMmfMachineAuthorizationVerifier::new(f.source.clone());
    let lock_key = 73_006_008_i64;
    let mut blocker = f.pool.acquire().await.unwrap();
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(lock_key)
        .execute(&mut *blocker)
        .await
        .unwrap();
    // A test-only deferred guard makes COMMIT observable while the actual
    // permit, exact source and table guards remain in effect.
    sqlx::raw_sql(AssertSqlSafe(format!("CREATE FUNCTION delegated_authority_service.machine_policy_test_commit_wait() RETURNS TRIGGER LANGUAGE plpgsql SET search_path=pg_catalog AS $test$ BEGIN IF NEW.organization_id='{}'::UUID AND NEW.kind='EVALUATION' THEN PERFORM pg_advisory_xact_lock({lock_key}); END IF; RETURN NEW; END $test$; CREATE CONSTRAINT TRIGGER machine_policy_test_commit_wait AFTER INSERT ON delegated_authority_service.machine_authorization_evidence DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION delegated_authority_service.machine_policy_test_commit_wait();",f.org)))
        .execute(&f.pool).await.unwrap();
    let task = tokio::spawn(async move { verifier.verify_permitted(request.evidence()).await });
    let mut waiting = false;
    for _ in 0..200 {
        waiting=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND NOT granted AND objid=($1::BIGINT)::OID)").bind(lock_key).fetch_one(&f.pool).await.unwrap();
        if waiting {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(waiting, "evaluation must reach a real blocked COMMIT");
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(lock_key)
        .execute(&mut *blocker)
        .await
        .unwrap();
    let mut retained = false;
    for _ in 0..200 {
        retained = f.counts().await == (1, 1);
        if retained {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(
        retained,
        "detached COMMIT finishes only as immutable history"
    );
    sqlx::raw_sql("DROP TRIGGER machine_policy_test_commit_wait ON delegated_authority_service.machine_authorization_evidence; DROP FUNCTION delegated_authority_service.machine_policy_test_commit_wait();").execute(&f.pool).await.unwrap();
}
