// SPDX-License-Identifier: AGPL-3.0-only
use crate::external_observation_admin::AdminError;
use crate::external_observation_authority_postgres::PostgresObservationAuthority;
use crate::external_observation_grant_lifecycle::{approve_grant, rotate_grant_api_key};
use crate::external_observation_postgres::{PostgresObservationJournal, ProducerIdentity};
use std::sync::Arc;
use uuid::Uuid;
const ORG: &str = "20000000-0000-4000-8000-000000000001";
const GRANT: &str = "30000000-0000-4000-8000-000000000001";
const OLD: &str = "10000000-0000-4000-8000-000000000001";
const NEW: &str = "10000000-0000-4000-8000-000000000002";
fn id(v: &str) -> Uuid {
    Uuid::parse_str(v).unwrap()
}
async fn replacement(f: &super::Fixture) {
    sqlx::query("INSERT INTO organization_service.api_keys(id,organization_id,scopes,scope_type,status,enabled,expires_at,updated_at) VALUES ($1,$2,ARRAY['evidence:submit'],'ORGANIZATION','active',true,clock_timestamp()+interval '2 minutes',clock_timestamp())")
        .bind(id(NEW)).bind(id(ORG)).execute(&f.pool).await.unwrap();
}
#[tokio::test]
async fn rotation_denies_old_and_new_keys_until_fresh_canonical_approval() {
    let f = super::admin_tests::setup().await;
    replacement(&f).await;
    let rotated = rotate_grant_api_key(&f.pool, id(ORG), "admin-one", id(GRANT), 2, id(NEW))
        .await
        .unwrap();
    assert_eq!(rotated.revision, 3);
    let journal =
        PostgresObservationJournal::new(f.pool.clone(), Arc::new(PostgresObservationAuthority));
    for key in [OLD, NEW] {
        let identity = ProducerIdentity {
            api_key_id: key.into(),
            organization_id: ORG.into(),
        };
        assert!(journal
            .submit(&identity, &f.input(), "observation-one")
            .await
            .is_err());
    }
    assert_eq!(
        approve_grant(&f.pool, id(ORG), "admin-one", id(GRANT), 2)
            .await
            .unwrap_err(),
        AdminError::Conflict
    );
    let approved = approve_grant(&f.pool, id(ORG), "admin-one", id(GRANT), 3)
        .await
        .unwrap();
    assert_eq!(approved.revision, 4);
    assert_eq!(
        approve_grant(&f.pool, id(ORG), "admin-one", id(GRANT), 4)
            .await
            .unwrap_err(),
        AdminError::Conflict
    );
    let identity = ProducerIdentity {
        api_key_id: NEW.into(),
        organization_id: ORG.into(),
    };
    journal
        .submit(&identity, &f.input(), "observation-one")
        .await
        .unwrap();
    let old = ProducerIdentity {
        api_key_id: OLD.into(),
        organization_id: ORG.into(),
    };
    assert!(journal
        .submit(&old, &f.input(), "observation-one")
        .await
        .is_err());
    let events: Vec<(String, String)> = sqlx::query_as(
        "SELECT event_type,actor_id FROM organization_service.audit_events ORDER BY created_at,id",
    )
    .fetch_all(&f.pool)
    .await
    .unwrap();
    assert_eq!(
        events,
        vec![
            (
                "external_observation_grant_key_rotated".into(),
                "admin-one".into()
            ),
            (
                "external_observation_grant_approved".into(),
                "admin-one".into()
            )
        ]
    );
    f.pool.close().await;
}
#[tokio::test]
async fn rotation_rejects_noncanonical_or_cross_tenant_keys_and_stale_authority() {
    let f = super::admin_tests::setup().await;
    replacement(&f).await;
    assert_eq!(
        rotate_grant_api_key(&f.pool, id(ORG), "wrong-actor", id(GRANT), 2, id(NEW))
            .await
            .unwrap_err(),
        AdminError::NotAuthorized
    );
    assert_eq!(
        rotate_grant_api_key(&f.pool, id(ORG), "admin-one", id(GRANT), 1, id(NEW))
            .await
            .unwrap_err(),
        AdminError::Conflict
    );
    for statement in [
        "UPDATE organization_service.api_keys SET scopes=ARRAY['admin:full'] WHERE id=$1",
        "UPDATE organization_service.api_keys SET scope_type='DEPLOYMENT_PROFILE' WHERE id=$1",
        "UPDATE organization_service.api_keys SET status='revoked' WHERE id=$1",
        "UPDATE organization_service.api_keys SET enabled=false WHERE id=$1",
        "UPDATE organization_service.api_keys SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1",
    ] {
        sqlx::query(statement)
        .bind(id(NEW))
        .execute(&f.pool)
        .await
        .unwrap();
        assert_eq!(
            rotate_grant_api_key(&f.pool, id(ORG), "admin-one", id(GRANT), 2, id(NEW))
                .await
                .unwrap_err(),
            AdminError::NotAuthorized
        );
        sqlx::query("UPDATE organization_service.api_keys SET scopes=ARRAY['evidence:submit'],scope_type='ORGANIZATION',status='active',enabled=true,expires_at=clock_timestamp()+interval '2 minutes' WHERE id=$1").bind(id(NEW)).execute(&f.pool).await.unwrap();
    }
    sqlx::query("INSERT INTO organization_service.organizations(id) VALUES ($1)")
        .bind(id("20000000-0000-4000-8000-000000000002"))
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE organization_service.api_keys SET organization_id=$1 WHERE id=$2")
        .bind(id("20000000-0000-4000-8000-000000000002"))
        .bind(id(NEW))
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        rotate_grant_api_key(&f.pool, id(ORG), "admin-one", id(GRANT), 2, id(NEW))
            .await
            .unwrap_err(),
        AdminError::NotAuthorized
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM organization_service.audit_events")
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    let revision: i64 = sqlx::query_scalar(
        "SELECT revision FROM issuance_service.external_observation_producer_grants",
    )
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(revision, 2);
    f.pool.close().await;
}
#[tokio::test]
async fn rotation_and_approval_roll_back_when_audit_fails() {
    let f = super::admin_tests::setup().await;
    replacement(&f).await;
    sqlx::query("ALTER TABLE organization_service.audit_events ADD CONSTRAINT reject_admin_changes CHECK (event_type='not-a-real-event')").execute(&f.pool).await.unwrap();
    assert_eq!(
        rotate_grant_api_key(&f.pool, id(ORG), "admin-one", id(GRANT), 2, id(NEW))
            .await
            .unwrap_err(),
        AdminError::Unavailable
    );
    let key: Uuid = sqlx::query_scalar(
        "SELECT api_key_id FROM issuance_service.external_observation_producer_grants",
    )
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(key, id(OLD));
    sqlx::query("UPDATE issuance_service.external_observation_producer_grants SET active=false")
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        approve_grant(&f.pool, id(ORG), "admin-one", id(GRANT), 3)
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
    assert!(!active);
    f.pool.close().await;
}
#[tokio::test]
async fn key_expiry_during_audit_rolls_back_rotation() {
    let f = super::admin_tests::setup().await;
    replacement(&f).await;
    sqlx::raw_sql("CREATE FUNCTION organization_service.delay_admin_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.5); RETURN NEW; END $$; CREATE TRIGGER delay_admin_audit BEFORE INSERT ON organization_service.audit_events FOR EACH ROW EXECUTE FUNCTION organization_service.delay_admin_audit();").execute(&f.pool).await.unwrap();
    sqlx::query("UPDATE organization_service.api_keys SET expires_at=clock_timestamp()+interval '200 milliseconds' WHERE id=$1").bind(id(NEW)).execute(&f.pool).await.unwrap();
    assert_eq!(
        rotate_grant_api_key(&f.pool, id(ORG), "admin-one", id(GRANT), 2, id(NEW))
            .await
            .unwrap_err(),
        AdminError::NotAuthorized
    );
    let key: Uuid = sqlx::query_scalar(
        "SELECT api_key_id FROM issuance_service.external_observation_producer_grants",
    )
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(key, id(OLD));
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM organization_service.audit_events")
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    f.pool.close().await;
}

#[tokio::test]
async fn concurrent_rotation_has_one_revision_fenced_audit_effect() {
    let f = super::admin_tests::setup().await;
    replacement(&f).await;
    let (a, b) = tokio::join!(
        rotate_grant_api_key(&f.pool, id(ORG), "admin-one", id(GRANT), 2, id(NEW)),
        rotate_grant_api_key(&f.pool, id(ORG), "admin-one", id(GRANT), 2, id(NEW))
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    let error = if let Err(e) = a { e } else { b.unwrap_err() };
    assert_eq!(error, AdminError::Conflict);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM organization_service.audit_events")
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    f.pool.close().await;
}

#[tokio::test]
async fn suspended_organization_denies_observation_and_administrative_mutations() {
    let f = super::admin_tests::setup().await;
    replacement(&f).await;
    sqlx::query("UPDATE organization_service.organizations SET status='suspended'")
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        rotate_grant_api_key(&f.pool, id(ORG), "admin-one", id(GRANT), 2, id(NEW))
            .await
            .unwrap_err(),
        AdminError::NotAuthorized
    );
    assert_eq!(
        approve_grant(&f.pool, id(ORG), "admin-one", id(GRANT), 2)
            .await
            .unwrap_err(),
        AdminError::NotAuthorized
    );
    assert_eq!(
        crate::external_observation_admin::revoke_grant(
            &f.pool,
            id(ORG),
            "admin-one",
            id(GRANT),
            2
        )
        .await
        .unwrap_err(),
        AdminError::NotAuthorized
    );
    let journal =
        PostgresObservationJournal::new(f.pool.clone(), Arc::new(PostgresObservationAuthority));
    let identity = ProducerIdentity {
        api_key_id: OLD.into(),
        organization_id: ORG.into(),
    };
    assert!(journal
        .submit(&identity, &f.input(), "observation-one")
        .await
        .is_err());
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM organization_service.audit_events")
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    f.pool.close().await;
}
#[tokio::test]
async fn organization_suspension_waits_for_admission_authority_lock() {
    use crate::external_observation_postgres::ObservationAuthority;
    let f = super::admin_tests::setup().await;
    let identity = ProducerIdentity {
        api_key_id: OLD.into(),
        organization_id: ORG.into(),
    };
    let mut transaction = f.pool.begin().await.unwrap();
    PostgresObservationAuthority
        .lock_current(&mut transaction, &identity, "binding-one")
        .await
        .unwrap();
    let mut writer = f.pool.acquire().await.unwrap();
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *writer)
        .await
        .unwrap();
    let change = tokio::spawn(async move {
        sqlx::query("UPDATE organization_service.organizations SET status='suspended'")
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
    let journal =
        PostgresObservationJournal::new(f.pool.clone(), Arc::new(PostgresObservationAuthority));
    assert!(journal
        .submit(&identity, &f.input(), "observation-one")
        .await
        .is_err());
    f.pool.close().await;
}
