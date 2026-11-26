// SPDX-License-Identifier: AGPL-3.0-only
//! Disposable PostgreSQL contract tests. Fixture authority is NOT a production
//! adapter: real key and application owners still need a serialized integration.
use crate::external_observation_admission::*;
use crate::external_observation_postgres::*;
use async_trait::async_trait;
use sqlx::{postgres::PgPoolOptions, PgConnection, PgPool, Row};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
};
use tokio::sync::{Barrier, Notify};

#[derive(Clone)]
enum Hook {
    None,
    FailFinal,
    ChangeRevision,
    DelayFinal,
    PauseFinal(Arc<Notify>, Arc<Notify>),
}
struct FixtureAuthority {
    hook: Hook,
    calls: AtomicUsize,
    saw_staged_receipt: AtomicBool,
}
#[async_trait]
impl ObservationAuthority for FixtureAuthority {
    async fn lock_current(
        &self,
        connection: &mut PgConnection,
        _identity: &ProducerIdentity,
        binding: &str,
    ) -> Result<LockedAuthority, JournalError> {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 1 {
            let count: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM issuance_service.external_observation_receipts",
            )
            .fetch_one(&mut *connection)
            .await
            .map_err(|_| JournalError::Unavailable)?;
            self.saw_staged_receipt.store(count > 0, Ordering::SeqCst);
            match &self.hook {
                Hook::FailFinal => return Err(JournalError::Unavailable),
                Hook::ChangeRevision => {
                    sqlx::query("UPDATE observation_test.authority SET application_revision = application_revision + 1 WHERE binding_id = $1")
                    .bind(binding).execute(&mut *connection).await.map_err(|_| JournalError::Unavailable)?;
                }
                Hook::DelayFinal => {
                    sqlx::query("SELECT pg_sleep(1.3)")
                        .execute(&mut *connection)
                        .await
                        .map_err(|_| JournalError::Unavailable)?;
                }
                Hook::PauseFinal(entered, release) => {
                    entered.notify_one();
                    release.notified().await;
                }
                Hook::None => {}
            }
        }
        let row = sqlx::query(
            "SELECT * FROM observation_test.authority WHERE binding_id = $1 FOR UPDATE",
        )
        .bind(binding)
        .fetch_optional(&mut *connection)
        .await
        .map_err(|error| {
            if error.as_database_error().and_then(|e| e.code()).as_deref() == Some("40001") {
                JournalError::Conflict
            } else {
                JournalError::Unavailable
            }
        })?
        .ok_or(JournalError::Denied(Denial::NotAuthorized))?;
        let organization: String = row.get("organization_id");
        let key: String = row.get("key_id");
        let source: String = row.get("source_id");
        let application: String = row.get("application_id");
        let subject: String = row.get("subject_id");
        Ok(LockedAuthority {
            principal: AuthenticatedApiKey {
                id: key.clone(),
                organization_id: organization.clone(),
                revision: row.get::<i64, _>("key_revision") as u64,
                active: row.get("key_active"),
                expires_at_ms: row.get::<i64, _>("key_expiry") as u64,
                scopes: row.get::<Vec<String>, _>("scopes").into_iter().collect(),
            },
            grant: ProducerGrant {
                organization_id: organization.clone(),
                source_id: source.clone(),
                api_key_id: key,
                revision: row.get::<i64, _>("grant_revision") as u64,
                active: row.get("grant_active"),
                expires_at_ms: row.get::<i64, _>("grant_expiry") as u64,
                bindings: BTreeSet::from([binding.to_owned()]),
            },
            binding: EvidenceBinding {
                id: binding.to_owned(),
                revision: row.get::<i64, _>("binding_revision") as u64,
                active: row.get("binding_active"),
                organization_id: organization.clone(),
                source_id: source,
                provider: "synthetic-lms".into(),
                application_id: application.clone(),
                subject_id: subject.clone(),
                fact_type: "learning.score".into(),
                resource_scope: BTreeMap::from([("course_id".into(), "synthetic-course".into())]),
                claims: BTreeMap::from([
                    (
                        "completed".into(),
                        ClaimRule {
                            kind: ClaimKind::Boolean,
                            required: true,
                            nullable: false,
                        },
                    ),
                    (
                        "score".into(),
                        ClaimRule {
                            kind: ClaimKind::Number {
                                minimum: 0.0,
                                maximum: 100.0,
                            },
                            required: false,
                            nullable: true,
                        },
                    ),
                ]),
                max_age_ms: 900_000,
                max_clock_skew_ms: 30_000,
            },
            application: ApplicationSnapshot {
                id: application,
                organization_id: organization,
                subject_id: subject,
                revision: row.get::<i64, _>("application_revision") as u64,
                expires_at_ms: crate::external_observation_admission::MAX_SAFE_INTEGER,
                accepts_observations: row.get("application_open"),
            },
        })
    }
}

struct Fixture {
    pool: PgPool,
    now: u64,
}
impl Fixture {
    async fn new() -> Self {
        assert_eq!(
            std::env::var("EXTERNAL_OBSERVATION_CONTRACT_TEST").as_deref(),
            Ok("synthetic-local-only"),
            "This test must run against the explicitly enabled disposable fixture; it never skips"
        );
        let port: u16 = std::env::var("EXTERNAL_OBSERVATION_TEST_PORT")
            .unwrap_or_else(|_| "5432".into())
            .parse()
            .unwrap();
        // Deliberately no DATABASE_URL, cloud hostname, real credentials or arbitrary database override.
        let url = format!("postgresql://postgres:observation-fixture-only@127.0.0.1:{port}/external_observation_contract_test");
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(&url)
            .await
            .expect("disposable PostgreSQL fixture");
        let database: String = sqlx::query_scalar("SELECT current_database()")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(database, "external_observation_contract_test");
        sqlx::raw_sql("DROP SCHEMA IF EXISTS issuance_service CASCADE; DROP SCHEMA IF EXISTS organization_service CASCADE; DROP SCHEMA IF EXISTS observation_test CASCADE;")
            .execute(&pool).await.unwrap();
        sqlx::raw_sql("CREATE SCHEMA organization_service;
            CREATE TABLE organization_service.organizations (id uuid PRIMARY KEY,status varchar(50) NOT NULL DEFAULT 'active');
            CREATE TABLE organization_service.api_keys (
                id uuid PRIMARY KEY, organization_id uuid NOT NULL REFERENCES organization_service.organizations(id),
                scopes text[] NOT NULL DEFAULT ARRAY[]::text[], scope_type text NOT NULL DEFAULT 'ORGANIZATION',
                deployment_profile_id uuid, status text NOT NULL DEFAULT 'active', enabled boolean NOT NULL DEFAULT true,
                expires_at timestamptz, updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
            );
            CREATE SCHEMA issuance_service;
            CREATE TABLE issuance_service.applications (
                id varchar PRIMARY KEY, organization_id varchar NOT NULL, applicant_identifier varchar NOT NULL,
                status varchar NOT NULL, updated_at timestamptz NOT NULL, expires_at timestamptz NOT NULL
            );")
            .execute(&pool).await.unwrap();
        sqlx::raw_sql("CREATE TABLE organization_service.members(id uuid PRIMARY KEY,organization_id uuid,user_id varchar(255),status varchar(50));
      CREATE TABLE organization_service.roles(id uuid PRIMARY KEY,organization_id uuid);
      CREATE TABLE organization_service.member_roles(member_id uuid,role_id uuid,PRIMARY KEY(member_id,role_id));
      CREATE TABLE organization_service.permissions(id uuid PRIMARY KEY,resource varchar(100),action varchar(100));
      CREATE TABLE organization_service.role_permissions(role_id uuid,permission_id uuid,PRIMARY KEY(role_id,permission_id));
      CREATE TABLE organization_service.audit_events(id uuid PRIMARY KEY,organization_id uuid,event_type varchar(120),action varchar(120),
        category varchar(100),resource_type varchar(100),resource_id varchar(255),actor_id varchar(255),actor_type varchar(50),
        severity varchar(50),message text,changes jsonb,metadata jsonb,created_at timestamptz);")
            .execute(&pool).await.unwrap();
        sqlx::raw_sql(OBSERVATION_SCHEMA)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::raw_sql(crate::external_observation_schema::LOCK_MIGRATION_SQL)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::raw_sql(crate::external_observation_schema::MATERIALIZATION_MIGRATION_SQL)
            .execute(&pool)
            .await
            .unwrap();
        // Synthetic registered-schema fixture, not qualification of the entire
        // protected owner CLI. Real owner-command integration is tested separately.
        sqlx::query(
            "CREATE TABLE issuance_service.rust_schema_migrations(version text PRIMARY KEY)",
        )
        .execute(&pool)
        .await
        .unwrap();
        for version in [
            crate::external_observation_schema::JOURNAL_VERSION,
            crate::external_observation_schema::VERSION,
            crate::external_observation_schema::MATERIALIZATION_VERSION,
        ] {
            sqlx::query("INSERT INTO issuance_service.rust_schema_migrations(version) VALUES ($1)")
                .bind(version)
                .execute(&pool)
                .await
                .unwrap();
        }
        sqlx::raw_sql("CREATE SCHEMA observation_test; CREATE TABLE observation_test.authority (
            binding_id text PRIMARY KEY, organization_id text NOT NULL, key_id text NOT NULL, source_id text NOT NULL,
            application_id text NOT NULL, subject_id text NOT NULL, key_revision bigint NOT NULL DEFAULT 1,
            key_active boolean NOT NULL DEFAULT true, key_expiry bigint NOT NULL, scopes text[] NOT NULL,
            grant_revision bigint NOT NULL DEFAULT 1, grant_active boolean NOT NULL DEFAULT true, grant_expiry bigint NOT NULL,
            binding_revision bigint NOT NULL DEFAULT 1, binding_active boolean NOT NULL DEFAULT true,
            application_revision bigint NOT NULL DEFAULT 1, application_open boolean NOT NULL DEFAULT true);")
            .execute(&pool).await.unwrap();
        let now: i64 = sqlx::query_scalar(
            "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO observation_test.authority
            (binding_id, organization_id, key_id, source_id, application_id, subject_id, key_expiry, scopes, grant_expiry)
            VALUES ('binding-one', 'org-one', 'key-one', 'source-one', 'application-one', 'learner-one', $1, ARRAY['evidence:submit'], $1)")
            .bind(now + 120_000).execute(&pool).await.unwrap();
        Self {
            pool,
            now: now as u64,
        }
    }
    fn identity() -> ProducerIdentity {
        ProducerIdentity {
            api_key_id: "key-one".into(),
            organization_id: "org-one".into(),
        }
    }
    fn input(&self) -> Observation {
        Observation {
            binding_id: "binding-one".into(),
            binding_revision: 1,
            observation_id: "observation-one".into(),
            sequence: 1,
            observed_at_ms: self.now,
            effective_at_ms: self.now,
            claims: BTreeMap::from([
                ("completed".into(), Scalar::Boolean(false)),
                ("score".into(), Scalar::Null),
            ]),
        }
    }
    fn journal(&self, hook: Hook) -> (PostgresObservationJournal, Arc<FixtureAuthority>) {
        let authority = Arc::new(FixtureAuthority {
            hook,
            calls: AtomicUsize::new(0),
            saw_staged_receipt: AtomicBool::new(false),
        });
        (
            PostgresObservationJournal::new(self.pool.clone(), authority.clone()),
            authority,
        )
    }
    async fn counts(&self) -> (i64, i64, i64) {
        let row = sqlx::query(
            "SELECT
            (SELECT count(*) FROM issuance_service.external_observation_receipts) AS receipts,
            (SELECT count(*) FROM issuance_service.external_observation_audit) AS audit,
            (SELECT count(*) FROM issuance_service.external_observation_heads) AS heads",
        )
        .fetch_one(&self.pool)
        .await
        .unwrap();
        (row.get("receipts"), row.get("audit"), row.get("heads"))
    }
}

#[tokio::test]
async fn receipt_audit_head_commit_together_and_exact_retry_is_read_only() {
    let f = Fixture::new().await;
    let (journal, _) = f.journal(Hook::None);
    let input = f.input();
    let first = journal
        .submit(&Fixture::identity(), &input, &input.observation_id)
        .await
        .unwrap();
    assert!(!first.replayed);
    assert!(uuid::Uuid::parse_str(&first.receipt_id).is_ok());
    let second = journal
        .submit(&Fixture::identity(), &input, &input.observation_id)
        .await
        .unwrap();
    assert!(second.replayed);
    assert_eq!(first.receipt_id, second.receipt_id);
    assert_eq!(f.counts().await, (1, 1, 1));
    let stored: serde_json::Value =
        sqlx::query_scalar("SELECT envelope FROM issuance_service.external_observation_receipts")
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(stored["claims"]["completed"], false);
    assert!(stored["claims"]["score"].is_null());
    assert!(stored.get("verified").is_none());
    f.pool.close().await;
}

#[tokio::test]
async fn lower_sequence_and_changed_replay_do_not_write() {
    let f = Fixture::new().await;
    let (journal, _) = f.journal(Hook::None);
    let mut input = f.input();
    input.sequence = 3;
    journal
        .submit(&Fixture::identity(), &input, &input.observation_id)
        .await
        .unwrap();
    let mut changed = input.clone();
    changed
        .claims
        .insert("completed".into(), Scalar::Boolean(true));
    assert_eq!(
        journal
            .submit(&Fixture::identity(), &changed, &changed.observation_id)
            .await,
        Err(JournalError::Denied(Denial::ReplayConflict))
    );
    changed.observation_id = "older-attempt".into();
    changed.sequence = 2;
    assert_eq!(
        journal
            .submit(&Fixture::identity(), &changed, &changed.observation_id)
            .await,
        Err(JournalError::Denied(Denial::OutOfOrder))
    );
    assert_eq!(f.counts().await, (1, 1, 1));
    f.pool.close().await;
}

#[tokio::test]
async fn foreign_identity_and_missing_authority_fail_closed() {
    let f = Fixture::new().await;
    let (journal, _) = f.journal(Hook::None);
    let mut input = f.input();
    for identity in [
        ProducerIdentity {
            api_key_id: "other-key".into(),
            organization_id: "org-one".into(),
        },
        ProducerIdentity {
            api_key_id: "key-one".into(),
            organization_id: "other-org".into(),
        },
    ] {
        assert_eq!(
            journal
                .submit(&identity, &input, &input.observation_id)
                .await,
            Err(JournalError::Denied(Denial::NotAuthorized))
        );
    }
    input.binding_id = "missing-binding".into();
    assert_eq!(
        journal
            .submit(&Fixture::identity(), &input, &input.observation_id)
            .await,
        Err(JournalError::Denied(Denial::NotAuthorized))
    );
    assert_eq!(f.counts().await, (0, 0, 0));
    f.pool.close().await;
}

#[tokio::test]
async fn source_wide_observation_identity_cannot_be_reused_for_another_binding() {
    let f = Fixture::new().await;
    let (journal, _) = f.journal(Hook::None);
    let mut input = f.input();
    journal
        .submit(&Fixture::identity(), &input, &input.observation_id)
        .await
        .unwrap();
    sqlx::query("INSERT INTO observation_test.authority
        (binding_id, organization_id, key_id, source_id, application_id, subject_id, key_expiry, scopes, grant_expiry)
        SELECT 'binding-two', organization_id, key_id, source_id, application_id, subject_id, key_expiry, scopes, grant_expiry
        FROM observation_test.authority WHERE binding_id = 'binding-one'").execute(&f.pool).await.unwrap();
    input.binding_id = "binding-two".into();
    assert_eq!(
        journal
            .submit(&Fixture::identity(), &input, &input.observation_id)
            .await,
        Err(JournalError::Denied(Denial::ReplayConflict))
    );
    assert_eq!(f.counts().await, (1, 1, 1));
    f.pool.close().await;
}

#[tokio::test]
async fn final_authority_failure_rolls_back_all_staged_records() {
    let f = Fixture::new().await;
    let (journal, authority) = f.journal(Hook::FailFinal);
    let input = f.input();
    assert_eq!(
        journal
            .submit(&Fixture::identity(), &input, &input.observation_id)
            .await,
        Err(JournalError::Unavailable)
    );
    assert!(authority.saw_staged_receipt.load(Ordering::SeqCst));
    assert_eq!(f.counts().await, (0, 0, 0));
    f.pool.close().await;
}

#[tokio::test]
async fn changed_application_revision_rolls_back_staged_receipt_audit_and_head() {
    let f = Fixture::new().await;
    let (journal, authority) = f.journal(Hook::ChangeRevision);
    let input = f.input();
    assert_eq!(
        journal
            .submit(&Fixture::identity(), &input, &input.observation_id)
            .await,
        Err(JournalError::Conflict)
    );
    assert!(authority.saw_staged_receipt.load(Ordering::SeqCst));
    assert_eq!(f.counts().await, (0, 0, 0));
    f.pool.close().await;
}

#[tokio::test]
async fn elapsed_key_expiry_without_revision_change_rolls_back_after_writes() {
    let f = Fixture::new().await;
    sqlx::query("UPDATE observation_test.authority SET key_expiry = floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint + 1000")
        .execute(&f.pool).await.unwrap();
    let (journal, authority) = f.journal(Hook::DelayFinal);
    let input = f.input();
    assert_eq!(
        journal
            .submit(&Fixture::identity(), &input, &input.observation_id)
            .await,
        Err(JournalError::Denied(Denial::AuthenticationRequired))
    );
    assert!(authority.saw_staged_receipt.load(Ordering::SeqCst));
    assert_eq!(f.counts().await, (0, 0, 0));
    f.pool.close().await;
}

#[tokio::test]
async fn head_constraint_failure_rolls_back_receipt() {
    let f = Fixture::new().await;
    let (journal, _) = f.journal(Hook::None);
    let input = f.input();
    sqlx::query("ALTER TABLE issuance_service.external_observation_heads ADD CONSTRAINT fixture_failure CHECK (false) NOT VALID")
        .execute(&f.pool).await.unwrap();
    assert_eq!(
        journal
            .submit(&Fixture::identity(), &input, &input.observation_id)
            .await,
        Err(JournalError::Unavailable)
    );
    assert_eq!(f.counts().await, (0, 0, 0));
    f.pool.close().await;
}

#[tokio::test]
async fn audit_constraint_failure_rolls_back_receipt_and_head() {
    let f = Fixture::new().await;
    let (journal, _) = f.journal(Hook::None);
    let input = f.input();
    sqlx::query("ALTER TABLE issuance_service.external_observation_audit ADD CONSTRAINT fixture_failure CHECK (false) NOT VALID")
        .execute(&f.pool).await.unwrap();
    assert_eq!(
        journal
            .submit(&Fixture::identity(), &input, &input.observation_id)
            .await,
        Err(JournalError::Unavailable)
    );
    assert_eq!(f.counts().await, (0, 0, 0));
    f.pool.close().await;
}

#[tokio::test]
async fn corrupted_stored_envelope_is_not_a_new_submission() {
    let f = Fixture::new().await;
    let (journal, _) = f.journal(Hook::None);
    let input = f.input();
    journal
        .submit(&Fixture::identity(), &input, &input.observation_id)
        .await
        .unwrap();
    sqlx::query("UPDATE issuance_service.external_observation_receipts SET envelope = jsonb_set(envelope, '{claims,completed}', '[]'::jsonb)")
        .execute(&f.pool).await.unwrap();
    assert_eq!(
        journal
            .submit(&Fixture::identity(), &input, &input.observation_id)
            .await,
        Err(JournalError::InvalidStoredState)
    );
    assert_eq!(f.counts().await, (1, 1, 1));
    f.pool.close().await;
}

#[tokio::test]
async fn receipt_lookup_failure_is_not_absence() {
    let f = Fixture::new().await;
    let (journal, _) = f.journal(Hook::None);
    let input = f.input();
    sqlx::query(
        "ALTER TABLE issuance_service.external_observation_receipts RENAME TO unavailable_receipts",
    )
    .execute(&f.pool)
    .await
    .unwrap();
    assert_eq!(
        journal
            .submit(&Fixture::identity(), &input, &input.observation_id)
            .await,
        Err(JournalError::Unavailable)
    );
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM issuance_service.unavailable_receipts")
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(count, 0);
    f.pool.close().await;
}

#[tokio::test]
async fn concurrent_exact_deliveries_have_one_durable_effect_and_reconcile_by_same_id() {
    let f = Fixture::new().await;
    let (journal, _) = f.journal(Hook::None);
    let journal = Arc::new(journal);
    let barrier = Arc::new(Barrier::new(3));
    let mut tasks = Vec::new();
    for _ in 0..2 {
        let journal = journal.clone();
        let barrier = barrier.clone();
        let input = f.input();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            journal
                .submit(&Fixture::identity(), &input, &input.observation_id)
                .await
        }));
    }
    barrier.wait().await;
    let a = tasks.remove(0).await.unwrap();
    let b = tasks.remove(0).await.unwrap();
    assert!(a.is_ok() || b.is_ok());
    for result in [&a, &b] {
        assert!(result.is_ok() || *result == Err(JournalError::Conflict));
    }
    let input = f.input();
    let reconciled = journal
        .submit(&Fixture::identity(), &input, &input.observation_id)
        .await
        .unwrap();
    assert!(reconciled.replayed);
    for acknowledged in [a, b].into_iter().flatten() {
        assert_eq!(acknowledged.receipt_id, reconciled.receipt_id);
    }
    assert_eq!(f.counts().await, (1, 1, 1));
    f.pool.close().await;
}

#[tokio::test]
async fn concurrent_conflicting_deliveries_never_overwrite_the_winner() {
    let f = Fixture::new().await;
    let (journal, _) = f.journal(Hook::None);
    let journal = Arc::new(journal);
    let barrier = Arc::new(Barrier::new(3));
    let mut tasks = Vec::new();
    for completed in [false, true] {
        let journal = journal.clone();
        let barrier = barrier.clone();
        let mut input = f.input();
        input
            .claims
            .insert("completed".into(), Scalar::Boolean(completed));
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            journal
                .submit(&Fixture::identity(), &input, &input.observation_id)
                .await
        }));
    }
    barrier.wait().await;
    let a = tasks.remove(0).await.unwrap();
    let b = tasks.remove(0).await.unwrap();
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    let rejected = if a.is_err() { a } else { b };
    assert!(matches!(
        rejected,
        Err(JournalError::Conflict | JournalError::Denied(Denial::ReplayConflict))
    ));
    assert_eq!(f.counts().await, (1, 1, 1));
    f.pool.close().await;
}

#[tokio::test]
async fn authority_lock_orders_concurrent_revocation_and_retry_is_denied() {
    let f = Fixture::new().await;
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let (journal, _) = f.journal(Hook::PauseFinal(entered.clone(), release.clone()));
    let journal = Arc::new(journal);
    let task_journal = journal.clone();
    let input = f.input();
    let task_input = input.clone();
    let submit = tokio::spawn(async move {
        task_journal
            .submit(
                &Fixture::identity(),
                &task_input,
                &task_input.observation_id,
            )
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), entered.notified())
        .await
        .unwrap();
    let pool = f.pool.clone();
    let mut revoke = tokio::spawn(async move {
        sqlx::query("UPDATE observation_test.authority SET key_active = false, key_revision = key_revision + 1")
        .execute(&pool).await
    });
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), &mut revoke)
            .await
            .is_err(),
        "revocation must wait for authority lock"
    );
    release.notify_one();
    assert!(submit.await.unwrap().is_ok());
    revoke.await.unwrap().unwrap();
    assert_eq!(
        journal
            .submit(&Fixture::identity(), &input, &input.observation_id)
            .await,
        Err(JournalError::Denied(Denial::AuthenticationRequired))
    );
    assert_eq!(f.counts().await, (1, 1, 1));
    f.pool.close().await;
}

#[tokio::test]
async fn closed_application_allows_only_exact_receipt_replay() {
    let f = Fixture::new().await;
    let (journal, _) = f.journal(Hook::None);
    let mut input = f.input();
    let original = journal
        .submit(&Fixture::identity(), &input, &input.observation_id)
        .await
        .unwrap();
    sqlx::query("UPDATE observation_test.authority SET application_open = false, application_revision = application_revision + 1")
        .execute(&f.pool).await.unwrap();
    let replay = journal
        .submit(&Fixture::identity(), &input, &input.observation_id)
        .await
        .unwrap();
    assert_eq!(replay.receipt_id, original.receipt_id);
    assert!(replay.replayed);
    input.observation_id = "later-observation".into();
    input.sequence = 2;
    assert_eq!(
        journal
            .submit(&Fixture::identity(), &input, &input.observation_id)
            .await,
        Err(JournalError::Denied(Denial::ApplicationClosed))
    );
    assert_eq!(f.counts().await, (1, 1, 1));
    f.pool.close().await;
}

#[tokio::test]
async fn binding_revision_does_not_reset_sequence_history() {
    let f = Fixture::new().await;
    let (journal, _) = f.journal(Hook::None);
    let mut input = f.input();
    journal
        .submit(&Fixture::identity(), &input, &input.observation_id)
        .await
        .unwrap();
    sqlx::query("UPDATE observation_test.authority SET binding_revision = 2")
        .execute(&f.pool)
        .await
        .unwrap();
    input.binding_revision = 2;
    input.observation_id = "next-observation".into();
    input.sequence = 2;
    journal
        .submit(&Fixture::identity(), &input, &input.observation_id)
        .await
        .unwrap();
    input.observation_id = "old-sequence".into();
    input.sequence = 1;
    assert_eq!(
        journal
            .submit(&Fixture::identity(), &input, &input.observation_id)
            .await,
        Err(JournalError::Denied(Denial::OutOfOrder))
    );
    assert_eq!(f.counts().await, (2, 2, 1));
    let head: i64 =
        sqlx::query_scalar("SELECT sequence FROM issuance_service.external_observation_heads")
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(head, 2);
    f.pool.close().await;
}
