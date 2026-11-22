//! Synthetic key-control scenarios against a disposable, real PostgreSQL host.
//! These signatures establish no operational MAP or delegated authority claim.
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{Duration, Utc};
use ed25519_dalek::{Signer, SigningKey};
use marty_organization::{
    agent_directory::*,
    catalog::seed_system_roles,
    migration::{migrate_organization_schema, validate_organization_schema},
    postgres::PostgresOrganizationStore,
    ForwardedPrincipal, JoinMechanism, Member, MemberStatus, Organization, OrganizationCreate,
    OrganizationType, Role,
};
use serde_json::{json, Value};
use sqlx::{postgres::PgPoolOptions, AssertSqlSafe, PgPool};
use tokio::sync::{Mutex, MutexGuard};
use tower::ServiceExt;
use uuid::Uuid;

static DATABASE_LOCK: Mutex<()> = Mutex::const_new(());
const AUDIENCE: &str = "urn:application-test:managed-enrollment";
const POLICY: &str = "urn:application-test:enrollment-policy:v1";

fn configuration(age: u32) -> AgentEnrollmentConfiguration {
    AgentEnrollmentConfiguration::new(AUDIENCE.into(), POLICY.into(), 1, age).unwrap()
}
fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
fn jwk(seed: u8) -> Value {
    json!({"kty":"OKP","crv":"Ed25519","x":URL_SAFE_NO_PAD.encode(key(seed).verifying_key().as_bytes())})
}
fn sign(challenge: &AgentEnrollmentChallenge, seed: u8) -> String {
    let header = json!({"typ":"marty-managed-enrollment+jws","alg":"EdDSA","kid":challenge.challenge["key_id"]});
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
        challenge.signing_payload
    );
    format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(key(seed).sign(input.as_bytes()).to_bytes())
    )
}

struct Fixture {
    _guard: MutexGuard<'static, ()>,
    pool: PgPool,
    store: PostgresOrganizationStore,
    service: AgentDirectoryService,
    org: Uuid,
    user: Uuid,
    owner: ForwardedPrincipal,
}
impl Fixture {
    async fn new() -> Self {
        let guard = DATABASE_LOCK.lock().await;
        let url = std::env::var("ORGANIZATION_AGENT_DIRECTORY_TEST_DATABASE_URL")
            .expect("explicit disposable local PostgreSQL URL required");
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
        validate_organization_schema(&pool).await.unwrap();
        let store = PostgresOrganizationStore::new(pool.clone());
        let user = Uuid::new_v4();
        let (organization, member) = Organization::create(OrganizationCreate {
            name: format!("Managed enrollment {}", Uuid::new_v4()),
            owner_id: user.to_string(),
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
            service: AgentDirectoryService::new(store.clone()).with_enrollment(configuration(120)),
            store,
            org: organization.id,
            user,
            owner: ForwardedPrincipal::User {
                user_id: user.to_string(),
            },
        }
    }
    fn session_for(&self, user: Uuid, marker: char) -> AgentEnrollmentSession {
        let now = Utc::now();
        AgentEnrollmentSession::new(
            self.org,
            user,
            format!("urn:marty:session:sha256:{}", marker.to_string().repeat(64)),
            now - Duration::milliseconds(100),
            now + Duration::seconds(20),
        )
        .unwrap()
    }
    fn session(&self) -> AgentEnrollmentSession {
        self.session_for(self.user, 'a')
    }
    async fn register(&self, kind: AgentKind, seed: u8) -> AgentIdentity {
        self.service
            .register(
                self.org,
                &self.owner,
                RegisterAgentRequest {
                    kind,
                    display_name: "Synthetic managed worker".into(),
                    description: None,
                    logical_application_ref: "urn:application-test:worker".into(),
                    issuer: "https://issuer.application-tests.invalid".into(),
                    subject: Uuid::new_v4().to_string(),
                    runtime_instance_ref: format!(
                        "urn:application-test:runtime:{}",
                        Uuid::new_v4()
                    ),
                    public_key_jwk: jwk(seed),
                },
            )
            .await
            .unwrap()
    }
    async fn challenge(&self, identity: &AgentIdentity) -> AgentEnrollmentChallenge {
        self.service
            .create_enrollment_challenge(
                self.org,
                &self.owner,
                &self.session(),
                identity.id,
                CreateAgentEnrollmentChallenge {
                    expected_revision: identity.revision,
                },
            )
            .await
            .unwrap()
    }
    async fn complete(
        &self,
        identity: &AgentIdentity,
        challenge: &AgentEnrollmentChallenge,
        seed: u8,
    ) -> Result<AgentEnrollmentResult, AgentDirectoryError> {
        self.service
            .complete_enrollment(
                self.org,
                &self.owner,
                &self.session(),
                identity.id,
                challenge.challenge_id,
                CompleteAgentEnrollment {
                    proof: sign(challenge, seed),
                },
            )
            .await
    }
    async fn inspect(
        &self,
        identity: &AgentIdentity,
        challenge: &AgentEnrollmentChallenge,
    ) -> AgentEnrollmentRecord {
        self.service
            .inspect_enrollment_challenge(
                self.org,
                &self.owner,
                &self.session(),
                identity.id,
                challenge.challenge_id,
            )
            .await
            .unwrap()
    }
    async fn counts(&self) -> (i64, i64, i64, i64, i64) {
        let mut values = Vec::new();
        for sql in [
            "SELECT count(*) FROM organization_service.agent_enrollment_challenges WHERE organization_id=$1",
            "SELECT count(*) FROM organization_service.agent_enrollment_outcomes WHERE organization_id=$1",
            "SELECT count(*) FROM organization_service.agent_enrollment_invalidations WHERE organization_id=$1",
            "SELECT count(*) FROM organization_service.agent_identity_history WHERE organization_id=$1",
            "SELECT count(*) FROM organization_service.audit_events WHERE organization_id=$1 AND event_type='agent_identity.enrollment'",
        ] { values.push(sqlx::query_scalar::<_,i64>(sql).bind(self.org).fetch_one(&self.pool).await.unwrap()); }
        (values[0], values[1], values[2], values[3], values[4])
    }
    async fn operator(&self, keys: &[&str]) -> (Uuid, ForwardedPrincipal, Uuid) {
        let user = Uuid::new_v4();
        let member = Member::create(
            self.org,
            user.to_string(),
            None,
            MemberStatus::Active,
            Utc::now(),
        );
        self.store.save_member(&member).await.unwrap();
        let mut permissions = Vec::new();
        for key in keys {
            let (resource, action) = key.split_once(':').unwrap();
            permissions.push(
                self.store
                    .permission_by_key(resource, action)
                    .await
                    .unwrap()
                    .unwrap(),
            );
        }
        let role = Role {
            id: Uuid::new_v4(),
            organization_id: self.org,
            name: format!("enrollment-operator-{user}"),
            display_name: None,
            description: None,
            is_system: false,
            is_default_for_new_members: false,
            permissions,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        self.store.save_role(&role).await.unwrap();
        self.store
            .set_member_roles(member.id, &[role.id])
            .await
            .unwrap();
        (
            user,
            ForwardedPrincipal::User {
                user_id: user.to_string(),
            },
            role.id,
        )
    }
}

#[tokio::test]
#[ignore = "requires disposable local ORGANIZATION_AGENT_DIRECTORY_TEST_DATABASE_URL"]
async fn enrollment_exact_key_success_retains_original_result_without_authority() {
    let f = Fixture::new().await;
    let identity = f.register(AgentKind::Managed, 17).await;
    assert_eq!(identity.status, AgentIdentityStatus::Provisioned);
    let challenge = f.challenge(&identity).await;
    assert!(!challenge.recovered);
    assert_eq!(challenge.challenge["organization_id"], json!(f.org));
    assert_eq!(challenge.challenge["administrator_id"], json!(f.user));
    assert_eq!(f.inspect(&identity, &challenge).await.state, "PENDING");
    let result = f.complete(&identity, &challenge, 17).await.unwrap();
    assert!(!result.recovered);
    assert_eq!(result.identity.status, AgentIdentityStatus::Active);
    assert_eq!(result.enrolled_revision, 2);
    assert_eq!(result.enrollment, "KEY_CONTROL_VERIFIED");
    assert_eq!(
        result.identity.provenance.managed_enrollment,
        "KEY_CONTROL_VERIFIED"
    );
    assert_eq!(
        result.identity.provenance.external_authentication,
        "NOT_ASSESSED"
    );
    assert_eq!(result.authority_status, "NOT_ASSESSED");
    assert_eq!(result.identity.authority_status, "NOT_ASSESSED");
    assert_eq!(result.identity.updated_at, result.completed_at);
    assert_eq!(result.identity.keys, identity.keys);
    f.service
        .lookup_current(
            f.org,
            identity.id,
            &identity.keys[0].fingerprint.typed().unwrap(),
        )
        .await
        .unwrap();
    let recovered = f.complete(&identity, &challenge, 17).await.unwrap();
    let mut expected = result.clone();
    expected.recovered = true;
    assert_eq!(recovered, expected);
    assert_eq!(
        f.inspect(&identity, &challenge).await.result,
        Some(expected.clone())
    );
    assert_eq!(f.counts().await, (1, 1, 0, 2, 2));
    let rotated = f
        .service
        .rotate_key(
            f.org,
            &f.owner,
            identity.id,
            RotateAgentKeyRequest {
                expected_revision: 2,
                public_key_jwk: jwk(18),
            },
        )
        .await
        .unwrap();
    assert_eq!(rotated.status, AgentIdentityStatus::Provisioned);
    assert_eq!(rotated.provenance.managed_enrollment, "NOT_ASSESSED");
    assert_eq!(
        f.complete(&identity, &challenge, 17).await.unwrap(),
        expected
    );
    assert_eq!(
        f.service
            .inspect(f.org, &f.owner, identity.id)
            .await
            .unwrap(),
        rotated
    );
    assert_eq!(
        f.service
            .lookup_current(
                f.org,
                identity.id,
                &rotated.keys[0].fingerprint.typed().unwrap()
            )
            .await
            .unwrap_err(),
        AgentDirectoryError::AccessDenied
    );
    let new_session = f.session_for(f.user, 'b');
    assert_eq!(
        f.service
            .inspect_enrollment_challenge(
                f.org,
                &f.owner,
                &new_session,
                identity.id,
                challenge.challenge_id
            )
            .await
            .unwrap()
            .result,
        Some(expected)
    );
    assert_eq!(
        f.service
            .complete_enrollment(
                f.org,
                &f.owner,
                &new_session,
                identity.id,
                challenge.challenge_id,
                CompleteAgentEnrollment {
                    proof: sign(&challenge, 17)
                }
            )
            .await
            .unwrap_err(),
        AgentDirectoryError::AccessDenied
    );
}

#[tokio::test]
#[ignore = "requires disposable local ORGANIZATION_AGENT_DIRECTORY_TEST_DATABASE_URL"]
async fn enrollment_pending_create_recovery_and_concurrent_completion_are_single_use() {
    let f = Fixture::new().await;
    let identity = f.register(AgentKind::Managed, 17).await;
    let session = f.session();
    let (a, b) = tokio::join!(
        f.service.create_enrollment_challenge(
            f.org,
            &f.owner,
            &session,
            identity.id,
            CreateAgentEnrollmentChallenge {
                expected_revision: 1
            }
        ),
        f.service.create_enrollment_challenge(
            f.org,
            &f.owner,
            &session,
            identity.id,
            CreateAgentEnrollmentChallenge {
                expected_revision: 1
            }
        )
    );
    let (a, b) = (a.unwrap(), b.unwrap());
    assert_eq!(a.challenge_id, b.challenge_id);
    assert_ne!(a.recovered, b.recovered);
    assert_eq!(a.signing_payload, b.signing_payload);
    assert_eq!(a.expires_at, b.expires_at);
    let (first, second) =
        tokio::join!(f.complete(&identity, &a, 17), f.complete(&identity, &b, 17));
    let (first, second) = (first.unwrap(), second.unwrap());
    assert_ne!(first.recovered, second.recovered);
    assert_eq!(first.enrolled_revision, second.enrolled_revision);
    assert_eq!(first.completed_at, second.completed_at);
    assert_eq!(f.counts().await, (1, 1, 0, 2, 2));
}

#[tokio::test]
#[ignore = "requires disposable local ORGANIZATION_AGENT_DIRECTORY_TEST_DATABASE_URL"]
async fn enrollment_rejects_wrong_signer_context_cross_agent_and_cross_tenant() {
    let f = Fixture::new().await;
    let identity = f.register(AgentKind::Managed, 17).await;
    let other = f.register(AgentKind::Managed, 17).await;
    let challenge = f.challenge(&identity).await;
    let other_challenge = f.challenge(&other).await;
    assert_eq!(
        f.complete(&identity, &challenge, 18).await.unwrap_err(),
        AgentDirectoryError::AccessDenied
    );
    let mut changed = challenge.clone();
    let mut payload: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&challenge.signing_payload).unwrap())
            .unwrap();
    payload["expected_revision"] = json!(2);
    changed.signing_payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
    assert_eq!(
        f.complete(&identity, &changed, 17).await.unwrap_err(),
        AgentDirectoryError::AccessDenied
    );
    assert_eq!(
        f.service
            .complete_enrollment(
                f.org,
                &f.owner,
                &f.session(),
                other.id,
                other_challenge.challenge_id,
                CompleteAgentEnrollment {
                    proof: sign(&challenge, 17)
                }
            )
            .await
            .unwrap_err(),
        AgentDirectoryError::AccessDenied
    );
    assert_eq!(
        f.service
            .complete_enrollment(
                f.org,
                &f.owner,
                &f.session(),
                other.id,
                challenge.challenge_id,
                CompleteAgentEnrollment {
                    proof: sign(&challenge, 17)
                }
            )
            .await
            .unwrap_err(),
        AgentDirectoryError::NotFound
    );
    assert_eq!(
        f.service
            .complete_enrollment(
                Uuid::new_v4(),
                &f.owner,
                &f.session(),
                identity.id,
                challenge.challenge_id,
                CompleteAgentEnrollment {
                    proof: sign(&challenge, 17)
                }
            )
            .await
            .unwrap_err(),
        AgentDirectoryError::AccessDenied
    );
    assert_eq!(f.counts().await, (2, 0, 0, 2, 2));
    f.complete(&identity, &challenge, 17).await.unwrap();
    assert_eq!(
        f.complete(&identity, &challenge, 18).await.unwrap_err(),
        AgentDirectoryError::Conflict
    );
}

#[tokio::test]
#[ignore = "requires disposable local ORGANIZATION_AGENT_DIRECTORY_TEST_DATABASE_URL"]
async fn enrollment_rotation_and_lifecycle_invalidate_intent_without_resume() {
    let f = Fixture::new().await;
    let identity = f.register(AgentKind::Managed, 17).await;
    let old = f.challenge(&identity).await;
    let rotated = f
        .service
        .rotate_key(
            f.org,
            &f.owner,
            identity.id,
            RotateAgentKeyRequest {
                expected_revision: 1,
                public_key_jwk: jwk(18),
            },
        )
        .await
        .unwrap();
    assert_eq!(f.inspect(&identity, &old).await.state, "INVALIDATED");
    assert_eq!(
        f.complete(&identity, &old, 17).await.unwrap_err(),
        AgentDirectoryError::Conflict
    );
    let current = f.challenge(&rotated).await;
    assert_eq!(
        f.complete(&rotated, &current, 17).await.unwrap_err(),
        AgentDirectoryError::AccessDenied
    );
    let enrolled = f.complete(&rotated, &current, 18).await.unwrap();
    let suspended = f
        .service
        .transition(
            f.org,
            &f.owner,
            identity.id,
            AgentLifecycleAction::Suspend,
            AgentLifecycleRequest {
                expected_revision: enrolled.enrolled_revision,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        f.service
            .create_enrollment_challenge(
                f.org,
                &f.owner,
                &f.session(),
                identity.id,
                CreateAgentEnrollmentChallenge {
                    expected_revision: suspended.revision
                }
            )
            .await
            .unwrap_err(),
        AgentDirectoryError::InvalidTransition
    );
    let rotated_suspended = f
        .service
        .rotate_key(
            f.org,
            &f.owner,
            identity.id,
            RotateAgentKeyRequest {
                expected_revision: suspended.revision,
                public_key_jwk: jwk(19),
            },
        )
        .await
        .unwrap();
    assert_eq!(rotated_suspended.status, AgentIdentityStatus::Suspended);
    assert_eq!(
        rotated_suspended.provenance.managed_enrollment,
        "NOT_ASSESSED"
    );
    f.complete(&rotated, &current, 18).await.unwrap();
    assert_eq!(
        f.service
            .inspect(f.org, &f.owner, identity.id)
            .await
            .unwrap()
            .status,
        AgentIdentityStatus::Suspended
    );
    let external = f.register(AgentKind::External, 17).await;
    assert_eq!(
        f.service
            .create_enrollment_challenge(
                f.org,
                &f.owner,
                &f.session(),
                external.id,
                CreateAgentEnrollmentChallenge {
                    expected_revision: 1
                }
            )
            .await
            .unwrap_err(),
        AgentDirectoryError::InvalidTransition
    );
}

#[tokio::test]
#[ignore = "requires disposable local ORGANIZATION_AGENT_DIRECTORY_TEST_DATABASE_URL"]
async fn enrollment_new_session_supersedes_pending_challenge_without_extending_it() {
    let f = Fixture::new().await;
    let identity = f.register(AgentKind::Managed, 17).await;
    let old = f.challenge(&identity).await;
    let new = f
        .service
        .create_enrollment_challenge(
            f.org,
            &f.owner,
            &f.session_for(f.user, 'b'),
            identity.id,
            CreateAgentEnrollmentChallenge {
                expected_revision: 1,
            },
        )
        .await
        .unwrap();
    assert_ne!(old.challenge_id, new.challenge_id);
    assert_ne!(old.challenge["nonce"], new.challenge["nonce"]);
    assert_eq!(f.inspect(&identity, &old).await.state, "INVALIDATED");
    assert_eq!(
        f.complete(&identity, &old, 17).await.unwrap_err(),
        AgentDirectoryError::Conflict
    );
    assert_eq!(
        f.complete(&identity, &new, 17).await.unwrap_err(),
        AgentDirectoryError::AccessDenied
    );
    f.service
        .complete_enrollment(
            f.org,
            &f.owner,
            &f.session_for(f.user, 'b'),
            identity.id,
            new.challenge_id,
            CompleteAgentEnrollment {
                proof: sign(&new, 17),
            },
        )
        .await
        .unwrap();
    assert_eq!(f.counts().await, (2, 1, 1, 2, 3));
}

#[tokio::test]
#[ignore = "requires disposable local ORGANIZATION_AGENT_DIRECTORY_TEST_DATABASE_URL"]
async fn enrollment_requires_both_current_permissions_and_original_human() {
    let f = Fixture::new().await;
    let identity = f.register(AgentKind::Managed, 17).await;
    for permissions in [
        &[][..],
        &["agent-identity:view"][..],
        &["agent-identity:enroll"][..],
    ] {
        let (user, principal, _) = f.operator(permissions).await;
        assert_eq!(
            f.service
                .create_enrollment_challenge(
                    f.org,
                    &principal,
                    &f.session_for(user, 'a'),
                    identity.id,
                    CreateAgentEnrollmentChallenge {
                        expected_revision: 1
                    }
                )
                .await
                .unwrap_err(),
            AgentDirectoryError::AccessDenied
        );
    }
    let (user, principal, role) = f
        .operator(&["agent-identity:view", "agent-identity:enroll"])
        .await;
    let session = f.session_for(user, 'a');
    let challenge = f
        .service
        .create_enrollment_challenge(
            f.org,
            &principal,
            &session,
            identity.id,
            CreateAgentEnrollmentChallenge {
                expected_revision: 1,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        f.service
            .inspect_enrollment_challenge(
                f.org,
                &f.owner,
                &f.session(),
                identity.id,
                challenge.challenge_id
            )
            .await
            .unwrap_err(),
        AgentDirectoryError::AccessDenied
    );
    assert_eq!(
        f.complete(&identity, &challenge, 17).await.unwrap_err(),
        AgentDirectoryError::AccessDenied
    );
    sqlx::query("DELETE FROM organization_service.role_permissions WHERE role_id=$1 AND permission_id IN (SELECT id FROM organization_service.permissions WHERE resource='agent-identity' AND action='enroll')")
        .bind(role).execute(&f.pool).await.unwrap();
    assert_eq!(
        f.service
            .complete_enrollment(
                f.org,
                &principal,
                &session,
                identity.id,
                challenge.challenge_id,
                CompleteAgentEnrollment {
                    proof: sign(&challenge, 17)
                }
            )
            .await
            .unwrap_err(),
        AgentDirectoryError::AccessDenied
    );
    assert_eq!(
        f.service
            .inspect_enrollment_challenge(
                f.org,
                &principal,
                &f.session_for(user, 'b'),
                identity.id,
                challenge.challenge_id
            )
            .await
            .unwrap()
            .state,
        "PENDING"
    );
    assert_eq!(f.counts().await, (1, 0, 0, 1, 1));
}

#[tokio::test]
#[ignore = "requires disposable local ORGANIZATION_AGENT_DIRECTORY_TEST_DATABASE_URL"]
async fn enrollment_audit_failure_rolls_back_activation_outcome_and_history() {
    let f = Fixture::new().await;
    let identity = f.register(AgentKind::Managed, 17).await;
    let challenge = f.challenge(&identity).await;
    sqlx::raw_sql("ALTER TABLE organization_service.audit_events ADD CONSTRAINT enrollment_test_reject CHECK (event_type<>'agent_identity.enrollment' OR action<>'KEY_CONTROL_VERIFIED') NOT VALID").execute(&f.pool).await.unwrap();
    let result = f.complete(&identity, &challenge, 17).await;
    sqlx::raw_sql(
        "ALTER TABLE organization_service.audit_events DROP CONSTRAINT enrollment_test_reject",
    )
    .execute(&f.pool)
    .await
    .unwrap();
    assert_eq!(result.unwrap_err(), AgentDirectoryError::Unavailable);
    assert_eq!(
        f.service
            .inspect(f.org, &f.owner, identity.id)
            .await
            .unwrap(),
        identity
    );
    assert_eq!(f.inspect(&identity, &challenge).await.state, "PENDING");
    assert_eq!(f.counts().await, (1, 0, 0, 1, 1));
    f.complete(&identity, &challenge, 17).await.unwrap();
    assert_eq!(f.counts().await, (1, 1, 0, 2, 2));
}

async fn wait_for_identity_lock(pool: &PgPool) {
    tokio::time::timeout(std::time::Duration::from_secs(3),async {
        loop {
            let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE 'SELECT id,organization_id,kind,status,revision,%FOR UPDATE')").fetch_one(pool).await.unwrap();
            if waiting {break;} tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }).await.expect("enrollment must actually wait for current identity state");
}

#[tokio::test]
#[ignore = "requires disposable local ORGANIZATION_AGENT_DIRECTORY_TEST_DATABASE_URL"]
async fn enrollment_rechecks_session_and_challenge_expiry_after_identity_lock_wait() {
    let f = Fixture::new().await;
    for expired_session in [true, false] {
        let identity = f.register(AgentKind::Managed, 17).await;
        let service = if expired_session {
            f.service.clone()
        } else {
            f.service.clone().with_enrollment(configuration(2))
        };
        let challenge = service
            .create_enrollment_challenge(
                f.org,
                &f.owner,
                &f.session(),
                identity.id,
                CreateAgentEnrollmentChallenge {
                    expected_revision: 1,
                },
            )
            .await
            .unwrap();
        let session = if expired_session {
            let now = Utc::now();
            AgentEnrollmentSession::new(
                f.org,
                f.user,
                format!("urn:marty:session:sha256:{}", "a".repeat(64)),
                now - Duration::milliseconds(50),
                now + Duration::milliseconds(500),
            )
            .unwrap()
        } else {
            f.session()
        };
        let mut blocker = f.pool.begin().await.unwrap();
        sqlx::query("SELECT id FROM organization_service.agent_identities WHERE id=$1 FOR UPDATE")
            .bind(identity.id)
            .execute(&mut *blocker)
            .await
            .unwrap();
        let org = f.org;
        let principal = f.owner.clone();
        let proof = sign(&challenge, 17);
        let id = identity.id;
        let challenge_id = challenge.challenge_id;
        let attempt = tokio::spawn(async move {
            service
                .complete_enrollment(
                    org,
                    &principal,
                    &session,
                    id,
                    challenge_id,
                    CompleteAgentEnrollment { proof },
                )
                .await
        });
        wait_for_identity_lock(&f.pool).await;
        tokio::time::sleep(std::time::Duration::from_millis(if expired_session {
            650
        } else {
            2100
        }))
        .await;
        blocker.commit().await.unwrap();
        assert_eq!(
            attempt.await.unwrap().unwrap_err(),
            if expired_session {
                AgentDirectoryError::AccessDenied
            } else {
                AgentDirectoryError::Conflict
            }
        );
        assert_eq!(
            f.service
                .inspect(f.org, &f.owner, identity.id)
                .await
                .unwrap(),
            identity
        );
    }
    assert_eq!(f.counts().await, (2, 0, 0, 2, 2));
}

#[tokio::test]
#[ignore = "requires disposable local ORGANIZATION_AGENT_DIRECTORY_TEST_DATABASE_URL"]
async fn enrollment_current_permission_revocation_during_wait_fails_closed() {
    let f = Fixture::new().await;
    let identity = f.register(AgentKind::Managed, 17).await;
    let (user, principal, role) = f
        .operator(&["agent-identity:view", "agent-identity:enroll"])
        .await;
    let session = f.session_for(user, 'a');
    let challenge = f
        .service
        .create_enrollment_challenge(
            f.org,
            &principal,
            &session,
            identity.id,
            CreateAgentEnrollmentChallenge {
                expected_revision: 1,
            },
        )
        .await
        .unwrap();
    let mut blocker = f.pool.begin().await.unwrap();
    sqlx::query("DELETE FROM organization_service.role_permissions WHERE role_id=$1")
        .bind(role)
        .execute(&mut *blocker)
        .await
        .unwrap();
    let service = f.service.clone();
    let org = f.org;
    let id = identity.id;
    let proof = sign(&challenge, 17);
    let attempt = tokio::spawn(async move {
        service
            .complete_enrollment(
                org,
                &principal,
                &session,
                id,
                challenge.challenge_id,
                CompleteAgentEnrollment { proof },
            )
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(3),async {
        loop {let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%FOR SHARE OF rp,p%')").fetch_one(&f.pool).await.unwrap();
            if waiting {break;} tokio::time::sleep(std::time::Duration::from_millis(10)).await;}
    }).await.unwrap();
    blocker.commit().await.unwrap();
    assert_eq!(
        attempt.await.unwrap().unwrap_err(),
        AgentDirectoryError::AccessDenied
    );
    assert_eq!(f.counts().await, (1, 0, 0, 1, 1));
}

#[tokio::test]
#[ignore = "requires disposable local ORGANIZATION_AGENT_DIRECTORY_TEST_DATABASE_URL"]
async fn enrollment_database_retention_and_no_evidence_activation_guards_hold() {
    let f = Fixture::new().await;
    let identity = f.register(AgentKind::Managed, 17).await;
    let challenge = f.challenge(&identity).await;
    let mut tx = f.pool.begin().await.unwrap();
    let mut forged = identity.clone();
    forged.status = AgentIdentityStatus::Active;
    forged.provenance.managed_enrollment = "KEY_CONTROL_VERIFIED".into();
    forged.revision = 2;
    // Match the database's microsecond clock precision; otherwise a host
    // nanosecond timestamp can test representation rounding instead of evidence.
    forged.updated_at = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    sqlx::query("UPDATE organization_service.agent_identities SET status='ACTIVE',revision=2,document=$1,updated_at=$2 WHERE id=$3")
        .bind(serde_json::to_value(&forged).unwrap()).bind(forged.updated_at).bind(identity.id).execute(&mut *tx).await.unwrap();
    assert!(
        tx.commit().await.is_err(),
        "ACTIVE without retained exact-key enrollment must fail at commit"
    );
    f.complete(&identity, &challenge, 17).await.unwrap();
    for sql in [
        "UPDATE organization_service.agent_enrollment_challenges SET expires_at=expires_at",
        "DELETE FROM organization_service.agent_enrollment_challenges",
        "TRUNCATE organization_service.agent_enrollment_challenges CASCADE",
        "UPDATE organization_service.agent_enrollment_outcomes SET proof_digest=proof_digest",
        "DELETE FROM organization_service.agent_enrollment_outcomes",
        "TRUNCATE organization_service.agent_enrollment_outcomes",
        "UPDATE organization_service.agent_enrollment_invalidations SET reason=reason",
        "DELETE FROM organization_service.agent_enrollment_invalidations",
        "TRUNCATE organization_service.agent_enrollment_invalidations",
    ] {
        assert!(
            sqlx::raw_sql(sql).execute(&f.pool).await.is_err(),
            "retained record mutation allowed: {sql}"
        );
    }
    assert_eq!(f.counts().await, (1, 1, 0, 2, 2));
}

#[tokio::test]
#[ignore = "requires disposable local ORGANIZATION_AGENT_DIRECTORY_TEST_DATABASE_URL"]
async fn enrollment_schema_validation_checks_deferred_clock_and_retention_trigger_shape() {
    let f = Fixture::new().await;
    for (table,name,replacement) in [
        ("agent_enrollment_outcomes","agent_enrollment_outcome_commit","CREATE CONSTRAINT TRIGGER agent_enrollment_outcome_commit AFTER INSERT ON organization_service.agent_enrollment_outcomes DEFERRABLE INITIALLY IMMEDIATE FOR EACH ROW EXECUTE FUNCTION organization_service.check_agent_enrollment_commit()"),
        ("agent_enrollment_challenges","agent_enrollment_challenge_guard","CREATE TRIGGER agent_enrollment_challenge_guard BEFORE INSERT ON organization_service.agent_enrollment_challenges FOR EACH ROW EXECUTE FUNCTION organization_service.guard_agent_key()"),
        ("agent_enrollment_invalidations","agent_enrollment_invalidation_immutable","CREATE TRIGGER agent_enrollment_invalidation_immutable BEFORE UPDATE ON organization_service.agent_enrollment_invalidations FOR EACH STATEMENT EXECUTE FUNCTION organization_service.reject_agent_directory_mutation()"),
    ] {
        let original:String=sqlx::query_scalar("SELECT pg_get_triggerdef(oid) FROM pg_trigger WHERE tgrelid=to_regclass($1) AND tgname=$2").bind(format!("organization_service.{table}")).bind(name).fetch_one(&f.pool).await.unwrap();
        // Identifiers and DDL are fixed fixture literals; restoration is the
        // exact trigger definition read from this disposable database only.
        let drop=format!("DROP TRIGGER {name} ON organization_service.{table}");
        sqlx::raw_sql(AssertSqlSafe(format!("{drop}; {replacement}"))).execute(&f.pool).await.unwrap();
        let result=validate_organization_schema(&f.pool).await;
        sqlx::raw_sql(AssertSqlSafe(format!("{drop}; {original}"))).execute(&f.pool).await.unwrap();
        assert!(result.is_err());validate_organization_schema(&f.pool).await.unwrap();
    }
}

#[tokio::test]
#[ignore = "requires disposable local ORGANIZATION_AGENT_DIRECTORY_TEST_DATABASE_URL"]
async fn enrollment_policy_change_requires_new_exact_challenge_and_keeps_old_intent_retained() {
    let f = Fixture::new().await;
    let identity = f.register(AgentKind::Managed, 17).await;
    let old = f.challenge(&identity).await;
    let changed = f.service.clone().with_enrollment(
        AgentEnrollmentConfiguration::new(AUDIENCE.into(), POLICY.into(), 2, 120).unwrap(),
    );
    assert_eq!(
        changed
            .complete_enrollment(
                f.org,
                &f.owner,
                &f.session(),
                identity.id,
                old.challenge_id,
                CompleteAgentEnrollment {
                    proof: sign(&old, 17)
                }
            )
            .await
            .unwrap_err(),
        AgentDirectoryError::Conflict
    );
    let current = changed
        .create_enrollment_challenge(
            f.org,
            &f.owner,
            &f.session(),
            identity.id,
            CreateAgentEnrollmentChallenge {
                expected_revision: 1,
            },
        )
        .await
        .unwrap();
    assert_ne!(old.challenge_id, current.challenge_id);
    assert_eq!(current.challenge["policy"]["revision"], json!(2));
    assert_eq!(f.inspect(&identity, &old).await.state, "INVALIDATED");
    changed
        .complete_enrollment(
            f.org,
            &f.owner,
            &f.session(),
            identity.id,
            current.challenge_id,
            CompleteAgentEnrollment {
                proof: sign(&current, 17),
            },
        )
        .await
        .unwrap();
    assert_eq!(f.counts().await, (2, 1, 1, 2, 3));
}

#[tokio::test]
#[ignore = "requires disposable local ORGANIZATION_AGENT_DIRECTORY_TEST_DATABASE_URL"]
async fn enrollment_rechecks_expiry_after_audit_wait_and_rolls_back_all_changes() {
    let f = Fixture::new().await;
    let identity = f.register(AgentKind::Managed, 17).await;
    let service = f.service.clone().with_enrollment(configuration(2));
    let challenge = service
        .create_enrollment_challenge(
            f.org,
            &f.owner,
            &f.session(),
            identity.id,
            CreateAgentEnrollmentChallenge {
                expected_revision: 1,
            },
        )
        .await
        .unwrap();
    // The delay occurs after activation/outcome/history writes, at the actual
    // audit boundary. The subsequent current-clock check must abort all writes.
    sqlx::raw_sql("CREATE FUNCTION organization_service.enrollment_test_audit_delay() RETURNS TRIGGER LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(2.1); RETURN NEW; END $$; CREATE TRIGGER enrollment_test_audit_delay BEFORE INSERT ON organization_service.audit_events FOR EACH ROW WHEN (NEW.event_type='agent_identity.enrollment' AND NEW.action='KEY_CONTROL_VERIFIED') EXECUTE FUNCTION organization_service.enrollment_test_audit_delay()")
        .execute(&f.pool).await.unwrap();
    let result = service
        .complete_enrollment(
            f.org,
            &f.owner,
            &f.session(),
            identity.id,
            challenge.challenge_id,
            CompleteAgentEnrollment {
                proof: sign(&challenge, 17),
            },
        )
        .await;
    sqlx::raw_sql("DROP TRIGGER enrollment_test_audit_delay ON organization_service.audit_events; DROP FUNCTION organization_service.enrollment_test_audit_delay()").execute(&f.pool).await.unwrap();
    assert_eq!(result.unwrap_err(), AgentDirectoryError::Conflict);
    assert_eq!(
        f.service
            .inspect(f.org, &f.owner, identity.id)
            .await
            .unwrap(),
        identity
    );
    assert_eq!(f.inspect(&identity, &challenge).await.state, "EXPIRED");
    assert_eq!(f.counts().await, (1, 0, 0, 1, 1));
}

fn http_request(f: &Fixture, method: &str, path: &str, body: Value) -> Request<Body> {
    let now = Utc::now();
    Request::builder()
        .method(method)
        .uri(path)
        .header(
            "x-service-token",
            "synthetic-enrollment-http-postgres-token",
        )
        .header("x-organization-id", f.org.to_string())
        .header("x-user-id", f.user.to_string())
        .header(
            "x-required-permission",
            if method == "GET" {
                "agent-identity:view"
            } else {
                "agent-identity:enroll"
            },
        )
        .header("content-type", "application/json")
        .header("x-marty-enrollment-organization-id", f.org.to_string())
        .header("x-marty-enrollment-user-id", f.user.to_string())
        .header(
            "x-marty-enrollment-session-ref",
            format!("urn:marty:session:sha256:{}", "a".repeat(64)),
        )
        .header(
            "x-marty-enrollment-observed-at",
            (now - Duration::milliseconds(100)).to_rfc3339(),
        )
        .header(
            "x-marty-enrollment-valid-until",
            (now + Duration::seconds(20)).to_rfc3339(),
        )
        .body(if method == "GET" {
            Body::empty()
        } else {
            Body::from(serde_json::to_vec(&body).unwrap())
        })
        .unwrap()
}

#[tokio::test]
#[ignore = "requires disposable local ORGANIZATION_AGENT_DIRECTORY_TEST_DATABASE_URL"]
async fn enrollment_http_roundtrip_signs_server_payload_and_returns_original_snapshot() {
    use marty_organization::agent_directory_http::{
        organization_agent_admin_router, AgentDirectoryHttpState,
    };
    let f = Fixture::new().await;
    let identity = f.register(AgentKind::Managed, 17).await;
    let app = organization_agent_admin_router(
        AgentDirectoryHttpState::new(
            f.service.clone(),
            "synthetic-enrollment-http-postgres-token".into(),
        )
        .unwrap(),
    );
    let base = format!(
        "/v1/organizations/{}/agents/{}/enrollment-challenges",
        f.org, identity.id
    );
    let response = app
        .clone()
        .oneshot(http_request(
            &f,
            "POST",
            &base,
            json!({"expected_revision":1}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let challenge: AgentEnrollmentChallenge =
        serde_json::from_slice(&to_bytes(response.into_body(), 16384).await.unwrap()).unwrap();
    let response = app
        .clone()
        .oneshot(http_request(
            &f,
            "POST",
            &base,
            json!({"expected_revision":1}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let recovered: AgentEnrollmentChallenge =
        serde_json::from_slice(&to_bytes(response.into_body(), 16384).await.unwrap()).unwrap();
    assert!(recovered.recovered);
    assert_eq!(recovered.challenge_id, challenge.challenge_id);
    let item = format!("{base}/{}", challenge.challenge_id);
    let response = app
        .clone()
        .oneshot(http_request(
            &f,
            "POST",
            &format!("{item}/complete"),
            json!({"proof":sign(&challenge,17)}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let completed: AgentEnrollmentResult =
        serde_json::from_slice(&to_bytes(response.into_body(), 16384).await.unwrap()).unwrap();
    assert_eq!(completed.identity.status, AgentIdentityStatus::Active);
    let response = app
        .oneshot(http_request(&f, "GET", &item, Value::Null))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let record: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 32768).await.unwrap()).unwrap();
    assert_eq!(record["state"], json!("CONSUMED"));
    assert_eq!(record["result"]["recovered"], json!(true));
    assert_eq!(
        record["result"]["identity"],
        serde_json::to_value(&completed.identity).unwrap()
    );
    assert_eq!(f.counts().await, (1, 1, 0, 2, 2));
}
