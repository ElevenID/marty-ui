// SPDX-License-Identifier: AGPL-3.0-only
use super::Fixture;
use crate::external_observation_admin::{lock_admin, revoke_grant, AdminError};
use uuid::Uuid;
const ORG: &str = "20000000-0000-4000-8000-000000000001";
const GRANT: &str = "30000000-0000-4000-8000-000000000001";
async fn setup() -> Fixture {
    let fixture = Fixture::new().await;
    super::authority_tests::seed_authority(&fixture).await;
    sqlx::raw_sql("CREATE TABLE organization_service.members(id uuid PRIMARY KEY,organization_id uuid,user_id varchar(255),status varchar(50));
      CREATE TABLE organization_service.roles(id uuid PRIMARY KEY,organization_id uuid);
      CREATE TABLE organization_service.member_roles(member_id uuid,role_id uuid,PRIMARY KEY(member_id,role_id));
      CREATE TABLE organization_service.permissions(id uuid PRIMARY KEY,resource varchar(100),action varchar(100));
      CREATE TABLE organization_service.role_permissions(role_id uuid,permission_id uuid,PRIMARY KEY(role_id,permission_id));
      CREATE TABLE organization_service.audit_events(id uuid PRIMARY KEY,organization_id uuid,event_type varchar(120),action varchar(120),
        category varchar(100),resource_type varchar(100),resource_id varchar(255),actor_id varchar(255),actor_type varchar(50),
        severity varchar(50),message text,changes jsonb,metadata jsonb,created_at timestamptz);
      INSERT INTO organization_service.members VALUES ('40000000-0000-4000-8000-000000000001','20000000-0000-4000-8000-000000000001','admin-one','active');
      INSERT INTO organization_service.roles VALUES ('50000000-0000-4000-8000-000000000001','20000000-0000-4000-8000-000000000001');
      INSERT INTO organization_service.member_roles VALUES ('40000000-0000-4000-8000-000000000001','50000000-0000-4000-8000-000000000001');
      INSERT INTO organization_service.permissions VALUES ('60000000-0000-4000-8000-000000000001','external-observation','manage');
      INSERT INTO organization_service.role_permissions VALUES ('50000000-0000-4000-8000-000000000001','60000000-0000-4000-8000-000000000001');")
      .execute(&fixture.pool).await.unwrap();
    fixture
}
#[tokio::test]
async fn canonical_admin_revokes_with_revision_fence_and_atomic_audit() {
    let f = setup().await;
    let org = Uuid::parse_str(ORG).unwrap();
    let grant = Uuid::parse_str(GRANT).unwrap();
    assert_eq!(
        revoke_grant(&f.pool, org, "wrong-actor", grant, 2)
            .await
            .unwrap_err(),
        AdminError::NotAuthorized
    );
    assert_eq!(
        revoke_grant(&f.pool, org, "admin-one", grant, 1)
            .await
            .unwrap_err(),
        AdminError::Conflict
    );
    let result = revoke_grant(&f.pool, org, "admin-one", grant, 2)
        .await
        .unwrap();
    assert_eq!(result.revision, 3);
    let journal = crate::external_observation_postgres::PostgresObservationJournal::new(
        f.pool.clone(),
        std::sync::Arc::new(
            crate::external_observation_authority_postgres::PostgresObservationAuthority,
        ),
    );
    let identity = crate::external_observation_postgres::ProducerIdentity {
        api_key_id: "10000000-0000-4000-8000-000000000001".into(),
        organization_id: ORG.into(),
    };
    assert_eq!(
        journal
            .submit(&identity, &f.input(), "observation-one")
            .await
            .unwrap_err(),
        crate::external_observation_postgres::JournalError::Denied(
            crate::external_observation_admission::Denial::NotAuthorized
        )
    );
    let active: bool = sqlx::query_scalar(
        "SELECT active FROM issuance_service.external_observation_producer_grants",
    )
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert!(!active);
    let event: (String, String) = sqlx::query_as(
        "SELECT event_type,actor_id FROM organization_service.audit_events WHERE id=$1",
    )
    .bind(result.audit_id)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(
        event,
        (
            "external_observation_grant_revoked".into(),
            "admin-one".into()
        )
    );
    assert_eq!(
        revoke_grant(&f.pool, org, "admin-one", grant, 2)
            .await
            .unwrap_err(),
        AdminError::Conflict
    );
    f.pool.close().await;
}
#[tokio::test]
async fn audit_failure_rolls_back_revocation_and_permission_removal_denies() {
    let f = setup().await;
    let org = Uuid::parse_str(ORG).unwrap();
    let grant = Uuid::parse_str(GRANT).unwrap();
    sqlx::query("ALTER TABLE organization_service.audit_events ADD CONSTRAINT synthetic_audit_failure CHECK(false) NOT VALID").execute(&f.pool).await.unwrap();
    assert_eq!(
        revoke_grant(&f.pool, org, "admin-one", grant, 2)
            .await
            .unwrap_err(),
        AdminError::Unavailable
    );
    let active: bool = sqlx::query_scalar(
        "SELECT active FROM issuance_service.external_observation_producer_grants",
    )
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert!(active);
    sqlx::query("DELETE FROM organization_service.role_permissions")
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        revoke_grant(&f.pool, org, "admin-one", grant, 2)
            .await
            .unwrap_err(),
        AdminError::NotAuthorized
    );
    f.pool.close().await;
}
#[tokio::test]
async fn concurrent_permission_removal_waits_for_admin_authorization_lock() {
    let f = setup().await;
    let mut transaction = f.pool.begin().await.unwrap();
    lock_admin(&mut transaction, Uuid::parse_str(ORG).unwrap(), "admin-one")
        .await
        .unwrap();
    let mut writer = f.pool.acquire().await.unwrap();
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *writer)
        .await
        .unwrap();
    let change = tokio::spawn(async move {
        sqlx::query("DELETE FROM organization_service.role_permissions")
            .execute(&mut *writer)
            .await
            .unwrap();
    });
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let blocked: bool = sqlx::query_scalar("SELECT cardinality(pg_blocking_pids($1))>0")
                .bind(pid)
                .fetch_one(&f.pool)
                .await
                .unwrap();
            if blocked {
                break;
            }
            assert!(!change.is_finished());
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    transaction.commit().await.unwrap();
    change.await.unwrap();
    assert_eq!(
        revoke_grant(
            &f.pool,
            Uuid::parse_str(ORG).unwrap(),
            "admin-one",
            Uuid::parse_str(GRANT).unwrap(),
            2
        )
        .await
        .unwrap_err(),
        AdminError::NotAuthorized
    );
    f.pool.close().await;
}
