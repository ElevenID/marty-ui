// SPDX-License-Identifier: AGPL-3.0-only
use super::Fixture;
use crate::external_observation_admission::{plan_admission, Admission, Denial, ReplaySnapshot};
use crate::external_observation_authority_postgres::PostgresObservationAuthority;
use crate::external_observation_postgres::{ObservationAuthority, ProducerIdentity};
use std::time::Duration;
use uuid::Uuid;

const ORGANIZATION: &str = "20000000-0000-4000-8000-000000000001";
const API_KEY: &str = "10000000-0000-4000-8000-000000000001";
const OTHER_ORGANIZATION: &str = "20000000-0000-4000-8000-000000000002";
const GRANT: &str = "30000000-0000-4000-8000-000000000001";

fn identity() -> ProducerIdentity {
    ProducerIdentity {
        api_key_id: API_KEY.into(),
        organization_id: ORGANIZATION.into(),
    }
}

async fn seed_authority(fixture: &Fixture) {
    let pool = &fixture.pool;
    let organization = Uuid::parse_str(ORGANIZATION).unwrap();
    let key = Uuid::parse_str(API_KEY).unwrap();
    let grant = Uuid::parse_str(GRANT).unwrap();

    sqlx::query("INSERT INTO organization_service.organizations (id) VALUES ($1)")
        .bind(organization)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO organization_service.api_keys
         (id, organization_id, scopes, scope_type, status, enabled, expires_at, updated_at)
         VALUES ($1, $2, ARRAY['evidence:submit'], 'ORGANIZATION', 'active', true,
                 clock_timestamp() + interval '2 minutes', clock_timestamp())",
    )
    .bind(key)
    .bind(organization)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO issuance_service.applications
         (id, organization_id, applicant_identifier, status, updated_at, expires_at)
         VALUES ('application-one', $1, 'learner-one', 'pending', clock_timestamp(),
                 clock_timestamp() + interval '1 day')",
    )
    .bind(ORGANIZATION)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO issuance_service.external_observation_producer_grants
         (id, organization_id, source_id, api_key_id, active, expires_at,
          created_by, approved_by, approved_at)
         VALUES ($1, $2, 'source-one', $3, true, clock_timestamp() + interval '2 minutes',
                 'organization-owner', 'organization-approver', clock_timestamp())",
    )
    .bind(grant)
    .bind(organization)
    .bind(key)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO issuance_service.external_observation_bindings
         (id, organization_id, source_id, application_id, subject_id, provider, fact_type,
          resource_scope, claim_rules, max_age_ms, max_clock_skew_ms, active,
          created_by, updated_by)
         VALUES (
           'binding-one', $1, 'source-one', 'application-one', 'learner-one',
           'synthetic-lms', 'learning.score',
           '{"course_id":"synthetic-course"}'::jsonb,
           '{"completed":{"kind":"boolean","required":true,"nullable":false},
             "score":{"kind":"number","minimum":0,"maximum":100,"required":false,"nullable":true}}'::jsonb,
           900000, 30000, true, 'organization-owner', 'organization-owner'
         )",
    )
    .bind(organization)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO issuance_service.external_observation_grant_bindings
         (grant_id, binding_id, organization_id, source_id)
         VALUES ($1, 'binding-one', $2, 'source-one')",
    )
    .bind(grant)
    .bind(organization)
    .execute(pool)
    .await
    .unwrap();
}

#[tokio::test]
async fn production_authority_loads_canonical_key_grant_binding_and_application() {
    let fixture = Fixture::new().await;
    seed_authority(&fixture).await;
    let mut transaction = fixture.pool.begin().await.unwrap();
    let locked = PostgresObservationAuthority::default()
        .lock_current(&mut transaction, &identity(), "binding-one")
        .await
        .unwrap();

    assert_eq!(locked.principal.id, API_KEY);
    assert_eq!(locked.principal.organization_id, ORGANIZATION);
    assert!(locked.principal.active);
    assert!(locked.principal.scopes.contains("evidence:submit"));
    assert_eq!(locked.grant.organization_id, ORGANIZATION);
    assert_eq!(locked.grant.source_id, "source-one");
    assert_eq!(locked.grant.api_key_id, API_KEY);
    assert_eq!(locked.grant.revision, 2); // grant-binding insert bumped the revision
    assert!(locked.grant.active);
    assert!(locked.grant.bindings.contains("binding-one"));
    assert_eq!(locked.binding.application_id, "application-one");
    assert_eq!(locked.binding.subject_id, "learner-one");
    assert_eq!(locked.binding.provider, "synthetic-lms");
    assert_eq!(locked.binding.fact_type, "learning.score");
    assert_eq!(locked.binding.claims.len(), 2);
    assert!(locked.application.accepts_observations);

    let decision = plan_admission(
        &locked.principal,
        &locked.grant,
        &locked.binding,
        &locked.application,
        &fixture.input(),
        "observation-one",
        ReplaySnapshot::Missing { current_sequence: 0 },
        fixture.now,
    )
    .unwrap();
    assert!(matches!(decision, Admission::Insert(_)));
    transaction.rollback().await.unwrap();
}

#[tokio::test]
async fn canonical_scope_revocation_and_lifecycle_changes_fail_closed() {
    let fixture = Fixture::new().await;
    seed_authority(&fixture).await;
    let key = Uuid::parse_str(API_KEY).unwrap();

    sqlx::query("UPDATE organization_service.api_keys SET scopes=ARRAY['integrations:write'] WHERE id=$1")
        .bind(key).execute(&fixture.pool).await.unwrap();
    let mut transaction = fixture.pool.begin().await.unwrap();
    let locked = PostgresObservationAuthority::default()
        .lock_current(&mut transaction, &identity(), "binding-one").await.unwrap();
    let denied = plan_admission(
        &locked.principal, &locked.grant, &locked.binding, &locked.application,
        &fixture.input(), "observation-one", ReplaySnapshot::Missing { current_sequence: 0 },
        fixture.now,
    ).unwrap_err();
    assert_eq!(denied, Denial::ScopeMissing);
    transaction.rollback().await.unwrap();

    sqlx::query("UPDATE organization_service.api_keys SET scopes=ARRAY['evidence:submit'], status='revoked' WHERE id=$1")
        .bind(key).execute(&fixture.pool).await.unwrap();
    let mut transaction = fixture.pool.begin().await.unwrap();
    let locked = PostgresObservationAuthority::default()
        .lock_current(&mut transaction, &identity(), "binding-one").await.unwrap();
    let denied = plan_admission(
        &locked.principal, &locked.grant, &locked.binding, &locked.application,
        &fixture.input(), "observation-one", ReplaySnapshot::Missing { current_sequence: 0 },
        fixture.now,
    ).unwrap_err();
    assert_eq!(denied, Denial::NotAuthorized);
    transaction.rollback().await.unwrap();

    sqlx::query("UPDATE organization_service.api_keys SET status='active' WHERE id=$1")
        .bind(key).execute(&fixture.pool).await.unwrap();
    sqlx::query("UPDATE issuance_service.applications SET status='approved', updated_at=clock_timestamp() WHERE id='application-one'")
        .execute(&fixture.pool).await.unwrap();
    let mut transaction = fixture.pool.begin().await.unwrap();
    let locked = PostgresObservationAuthority::default()
        .lock_current(&mut transaction, &identity(), "binding-one").await.unwrap();
    assert!(!locked.application.accepts_observations);
    let denied = plan_admission(
        &locked.principal, &locked.grant, &locked.binding, &locked.application,
        &fixture.input(), "observation-one", ReplaySnapshot::Missing { current_sequence: 0 },
        fixture.now,
    ).unwrap_err();
    assert_eq!(denied, Denial::ApplicationClosed);
    transaction.rollback().await.unwrap();
}

#[tokio::test]
async fn tenant_mismatch_and_missing_grant_binding_are_not_authorized() {
    let fixture = Fixture::new().await;
    seed_authority(&fixture).await;
    let adapter = PostgresObservationAuthority::default();
    let wrong_tenant = ProducerIdentity {
        api_key_id: API_KEY.into(),
        organization_id: OTHER_ORGANIZATION.into(),
    };
    let mut transaction = fixture.pool.begin().await.unwrap();
    assert!(adapter.lock_current(&mut transaction, &wrong_tenant, "binding-one").await.is_err());
    transaction.rollback().await.unwrap();

    sqlx::query("DELETE FROM issuance_service.external_observation_grant_bindings WHERE binding_id='binding-one'")
        .execute(&fixture.pool).await.unwrap();
    let mut transaction = fixture.pool.begin().await.unwrap();
    assert!(adapter.lock_current(&mut transaction, &identity(), "binding-one").await.is_err());
    transaction.rollback().await.unwrap();
}

#[tokio::test]
async fn api_key_revocation_waits_for_admission_authority_lock() {
    let fixture = Fixture::new().await;
    seed_authority(&fixture).await;
    let mut transaction = fixture.pool.begin().await.unwrap();
    PostgresObservationAuthority::default()
        .lock_current(&mut transaction, &identity(), "binding-one")
        .await
        .unwrap();

    let pool = fixture.pool.clone();
    let key = Uuid::parse_str(API_KEY).unwrap();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let update = tokio::spawn(async move {
        let mut connection = pool.acquire().await.unwrap();
        let _ = started_tx.send(());
        sqlx::query("UPDATE organization_service.api_keys SET status='revoked', updated_at=clock_timestamp() WHERE id=$1")
            .bind(key).execute(&mut *connection).await.unwrap();
    });
    started_rx.await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!update.is_finished(), "revocation must wait for the admission transaction's key row lock");

    transaction.commit().await.unwrap();
    update.await.unwrap();
    let status: String = sqlx::query_scalar("SELECT status FROM organization_service.api_keys WHERE id=$1")
        .bind(key).fetch_one(&fixture.pool).await.unwrap();
    assert_eq!(status, "revoked");
}
