// SPDX-License-Identifier: AGPL-3.0-only
use crate::external_observation_admin::AdminError;
use crate::external_observation_grant_edit::{change_grant_expiry, create_grant};
use sqlx::Row;
use uuid::Uuid;
const ORG: &str = "20000000-0000-4000-8000-000000000001";
const KEY: &str = "10000000-0000-4000-8000-000000000001";
const GRANT: &str = "30000000-0000-4000-8000-000000000001";
#[tokio::test]
async fn startup_rejects_legacy_nonnullable_approval_columns() {
    let f = super::admin_tests::setup().await;
    sqlx::query("ALTER TABLE issuance_service.external_observation_producer_grants ALTER COLUMN approved_by SET NOT NULL, ALTER COLUMN approved_at SET NOT NULL").execute(&f.pool).await.unwrap();
    assert!(crate::external_observation_startup::verify_storage(&f.pool)
        .await
        .is_err());
    sqlx::query("ALTER TABLE issuance_service.external_observation_producer_grants ALTER COLUMN approved_by DROP NOT NULL, ALTER COLUMN approved_at DROP NOT NULL").execute(&f.pool).await.unwrap();
    crate::external_observation_startup::verify_storage(&f.pool)
        .await
        .unwrap();
    f.pool.close().await;
}
fn id(value: &str) -> Uuid {
    Uuid::parse_str(value).unwrap()
}
async fn future(pool: &sqlx::PgPool) -> i64 {
    sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint+60000")
        .fetch_one(pool)
        .await
        .unwrap()
}
async fn counts(pool: &sqlx::PgPool) -> (i64, i64) {
    sqlx::query_as("SELECT (SELECT count(*) FROM issuance_service.external_observation_producer_grants),(SELECT count(*) FROM organization_service.audit_events)").fetch_one(pool).await.unwrap()
}
#[tokio::test]
async fn creation_is_inactive_unapproved_and_without_membership_or_new_key() {
    let f = super::admin_tests::setup().await;
    let grant = Uuid::new_v4();
    let result = create_grant(
        &f.pool,
        id(ORG),
        "admin-one",
        grant,
        id(KEY),
        "source-new",
        future(&f.pool).await,
    )
    .await
    .unwrap();
    assert_eq!(result.revision, 1);
    let row=sqlx::query("SELECT active,approved_by,approved_at,created_by,api_key_id,source_id FROM issuance_service.external_observation_producer_grants WHERE id=$1").bind(grant).fetch_one(&f.pool).await.unwrap();
    assert!(!row.get::<bool, _>("active"));
    assert!(row.get::<Option<String>, _>("approved_by").is_none());
    assert!(row
        .get::<Option<chrono::DateTime<chrono::Utc>>, _>("approved_at")
        .is_none());
    assert_eq!(row.get::<String, _>("created_by"), "admin-one");
    assert_eq!(row.get::<Uuid, _>("api_key_id"), id(KEY));
    assert_eq!(row.get::<String, _>("source_id"), "source-new");
    let members:i64=sqlx::query_scalar("SELECT count(*) FROM issuance_service.external_observation_grant_bindings WHERE grant_id=$1").bind(grant).fetch_one(&f.pool).await.unwrap();
    assert_eq!(members, 0);
    let keys: i64 = sqlx::query_scalar("SELECT count(*) FROM organization_service.api_keys")
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(keys, 1);
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
            "external_observation_grant_created".into(),
            "admin-one".into()
        )
    );
    assert!(sqlx::query("UPDATE issuance_service.external_observation_producer_grants SET active=true WHERE id=$1").bind(grant).execute(&f.pool).await.is_err(),"schema must reject active grants with no approval");
    f.pool.close().await;
}
#[tokio::test]
async fn expiry_change_deactivates_preserves_membership_and_requires_fresh_approval() {
    let f = super::admin_tests::setup().await;
    let result = change_grant_expiry(
        &f.pool,
        id(ORG),
        "admin-one",
        id(GRANT),
        2,
        future(&f.pool).await,
    )
    .await
    .unwrap();
    assert_eq!(result.revision, 3);
    let row:(bool,Option<String>,Uuid,String)=sqlx::query_as("SELECT active,approved_by,api_key_id,source_id FROM issuance_service.external_observation_producer_grants WHERE id=$1").bind(id(GRANT)).fetch_one(&f.pool).await.unwrap();
    assert_eq!(row, (false, None, id(KEY), "source-one".into()));
    let members:i64=sqlx::query_scalar("SELECT count(*) FROM issuance_service.external_observation_grant_bindings WHERE grant_id=$1").bind(id(GRANT)).fetch_one(&f.pool).await.unwrap();
    assert_eq!(members, 1);
    let journal = crate::external_observation_postgres::PostgresObservationJournal::new(
        f.pool.clone(),
        std::sync::Arc::new(
            crate::external_observation_authority_postgres::PostgresObservationAuthority,
        ),
    );
    let principal = crate::external_observation_postgres::ProducerIdentity {
        api_key_id: KEY.into(),
        organization_id: ORG.into(),
    };
    assert_eq!(
        journal
            .submit(&principal, &f.input(), "observation-one")
            .await
            .unwrap_err(),
        crate::external_observation_postgres::JournalError::Denied(
            crate::external_observation_admission::Denial::NotAuthorized
        )
    );
    let approved = crate::external_observation_grant_lifecycle::approve_grant(
        &f.pool,
        id(ORG),
        "admin-one",
        id(GRANT),
        3,
    )
    .await
    .unwrap();
    assert_eq!(approved.revision, 4);
    assert_eq!(counts(&f.pool).await, (1, 2));
    f.pool.close().await;
}
#[tokio::test]
async fn creation_requires_current_actor_tenant_and_exact_eligible_key() {
    let f = super::admin_tests::setup().await;
    let expires = future(&f.pool).await;
    for actor in ["producer", "", "admin-one\n"] {
        assert_eq!(
            create_grant(
                &f.pool,
                id(ORG),
                actor,
                Uuid::new_v4(),
                id(KEY),
                "source-new",
                expires
            )
            .await
            .unwrap_err(),
            AdminError::NotAuthorized
        );
    }
    assert_eq!(
        create_grant(
            &f.pool,
            Uuid::new_v4(),
            "admin-one",
            Uuid::new_v4(),
            id(KEY),
            "source-new",
            expires
        )
        .await
        .unwrap_err(),
        AdminError::NotAuthorized
    );
    for update in [
        "UPDATE organization_service.api_keys SET scopes=ARRAY['*','evidence:*','admin:full']",
        "UPDATE organization_service.api_keys SET scope_type='PERSONAL'",
        "UPDATE organization_service.api_keys SET enabled=false",
        "UPDATE organization_service.api_keys SET status='revoked'",
        "UPDATE organization_service.api_keys SET expires_at=clock_timestamp()-interval '1 second'",
        "UPDATE organization_service.api_keys SET deployment_profile_id='90000000-0000-4000-8000-000000000001'",
    ] {
        sqlx::query("UPDATE organization_service.api_keys SET scopes=ARRAY['evidence:submit'],scope_type='ORGANIZATION',enabled=true,status='active',expires_at=clock_timestamp()+interval '2 minutes',deployment_profile_id=NULL").execute(&f.pool).await.unwrap();
        sqlx::query(update)
        .execute(&f.pool)
        .await
        .unwrap();
        assert_eq!(
            create_grant(
                &f.pool,
                id(ORG),
                "admin-one",
                Uuid::new_v4(),
                id(KEY),
                "source-new",
                expires
            )
            .await
            .unwrap_err(),
            AdminError::NotAuthorized,
            "{update}"
        );
    }
    assert_eq!(counts(&f.pool).await, (1, 0));
    f.pool.close().await;
}
#[tokio::test]
async fn stale_duplicate_invalid_and_past_inputs_do_not_write_or_reapprove() {
    let f = super::admin_tests::setup().await;
    let expires = future(&f.pool).await;
    for source in ["", "a.b", "a/b", " space", "x\n"] {
        assert_eq!(
            create_grant(
                &f.pool,
                id(ORG),
                "admin-one",
                Uuid::new_v4(),
                id(KEY),
                source,
                expires
            )
            .await
            .unwrap_err(),
            AdminError::Conflict
        );
    }
    assert_eq!(
        create_grant(
            &f.pool,
            id(ORG),
            "admin-one",
            Uuid::nil(),
            id(KEY),
            "new",
            expires
        )
        .await
        .unwrap_err(),
        AdminError::Conflict
    );
    assert_eq!(
        create_grant(
            &f.pool,
            id(ORG),
            "admin-one",
            Uuid::new_v4(),
            id(KEY),
            "new",
            1
        )
        .await
        .unwrap_err(),
        AdminError::Conflict
    );
    assert_eq!(
        change_grant_expiry(&f.pool, id(ORG), "admin-one", id(GRANT), 1, expires)
            .await
            .unwrap_err(),
        AdminError::Conflict
    );
    assert_eq!(
        create_grant(
            &f.pool,
            id(ORG),
            "admin-one",
            id(GRANT),
            id(KEY),
            "source-new",
            expires
        )
        .await
        .unwrap_err(),
        AdminError::Conflict
    );
    assert_eq!(
        create_grant(
            &f.pool,
            id(ORG),
            "admin-one",
            Uuid::new_v4(),
            id(KEY),
            "source-one",
            expires
        )
        .await
        .unwrap_err(),
        AdminError::Conflict
    );
    assert_eq!(counts(&f.pool).await, (1, 0));
    f.pool.close().await;
}
#[tokio::test]
async fn failed_audit_rolls_back_creation_and_expiry_change() {
    let f = super::admin_tests::setup().await;
    let expires = future(&f.pool).await;
    sqlx::query("ALTER TABLE organization_service.audit_events ADD CONSTRAINT synthetic_audit_failure CHECK(false) NOT VALID").execute(&f.pool).await.unwrap();
    assert_eq!(
        create_grant(
            &f.pool,
            id(ORG),
            "admin-one",
            Uuid::new_v4(),
            id(KEY),
            "source-new",
            expires
        )
        .await
        .unwrap_err(),
        AdminError::Unavailable
    );
    assert_eq!(
        change_grant_expiry(&f.pool, id(ORG), "admin-one", id(GRANT), 2, expires)
            .await
            .unwrap_err(),
        AdminError::Unavailable
    );
    let original: (bool, i64) = sqlx::query_as(
        "SELECT active,revision FROM issuance_service.external_observation_producer_grants",
    )
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(original, (true, 2));
    assert_eq!(counts(&f.pool).await, (1, 0));
    f.pool.close().await;
}
#[tokio::test]
async fn concurrent_same_revision_mutations_and_same_id_creations_have_one_winner() {
    let f = super::admin_tests::setup().await;
    let expires = future(&f.pool).await;
    let (a, b) = tokio::join!(
        change_grant_expiry(&f.pool, id(ORG), "admin-one", id(GRANT), 2, expires),
        change_grant_expiry(&f.pool, id(ORG), "admin-one", id(GRANT), 2, expires + 1000)
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert_eq!(a.err().or(b.err()), Some(AdminError::Conflict));
    let grant = Uuid::new_v4();
    let (a, b) = tokio::join!(
        create_grant(
            &f.pool,
            id(ORG),
            "admin-one",
            grant,
            id(KEY),
            "source-new",
            expires
        ),
        create_grant(
            &f.pool,
            id(ORG),
            "admin-one",
            grant,
            id(KEY),
            "source-new",
            expires
        )
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert_eq!(a.err().or(b.err()), Some(AdminError::Conflict));
    assert_eq!(counts(&f.pool).await, (2, 2));
    f.pool.close().await;
}
async fn delay_audit(pool: &sqlx::PgPool) {
    sqlx::raw_sql("CREATE FUNCTION organization_service.delay_synthetic_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.4); RETURN NEW; END $$; CREATE TRIGGER delay_synthetic_audit BEFORE INSERT ON organization_service.audit_events FOR EACH ROW EXECUTE FUNCTION organization_service.delay_synthetic_audit();").execute(pool).await.unwrap();
}
#[tokio::test]
async fn expiry_crossing_during_audit_rolls_back_both_operations() {
    let f = super::admin_tests::setup().await;
    delay_audit(&f.pool).await;
    let expires = future(&f.pool).await - 59700;
    assert_eq!(
        create_grant(
            &f.pool,
            id(ORG),
            "admin-one",
            Uuid::new_v4(),
            id(KEY),
            "source-new",
            expires
        )
        .await
        .unwrap_err(),
        AdminError::Conflict
    );
    let expires = future(&f.pool).await - 59700;
    assert_eq!(
        change_grant_expiry(&f.pool, id(ORG), "admin-one", id(GRANT), 2, expires)
            .await
            .unwrap_err(),
        AdminError::Conflict
    );
    assert_eq!(counts(&f.pool).await, (1, 0));
    let original: (bool, i64) = sqlx::query_as(
        "SELECT active,revision FROM issuance_service.external_observation_producer_grants",
    )
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(original, (true, 2));
    f.pool.close().await;
}
#[tokio::test]
async fn key_expiry_crossing_during_audit_rolls_back_creation() {
    let f = super::admin_tests::setup().await;
    delay_audit(&f.pool).await;
    let expires = future(&f.pool).await;
    sqlx::query("UPDATE organization_service.api_keys SET expires_at=clock_timestamp()+interval '300 milliseconds'").execute(&f.pool).await.unwrap();
    assert_eq!(
        create_grant(
            &f.pool,
            id(ORG),
            "admin-one",
            Uuid::new_v4(),
            id(KEY),
            "source-new",
            expires
        )
        .await
        .unwrap_err(),
        AdminError::NotAuthorized
    );
    assert_eq!(counts(&f.pool).await, (1, 0));
    f.pool.close().await;
}
#[tokio::test]
async fn public_admin_mount_strict_creation_and_expiry_contract() {
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    let f = super::admin_tests::setup().await;
    let expires = future(&f.pool).await;
    let key = "synthetic-gateway-service-key-for-grant-edits";
    let router =
        crate::external_observation_startup::prepare_observation_router(&f.pool, true, Some(key))
            .await
            .unwrap()
            .unwrap();
    let grant = Uuid::new_v4();
    let path = format!("/v1/organizations/{ORG}/external-observation-producers/{grant}/create");
    let request = |path: &str, body: String| {
        Request::builder()
            .method("POST")
            .uri(path)
            .header("x-api-key", key)
            .header("x-user-id", "admin-one")
            .header("x-organization-id", ORG)
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap()
    };
    let valid =
        serde_json::json!({"api_key_id":KEY,"source_id":"source-new","expires_at_ms":expires});
    for body in [format!("{{\"api_key_id\":\"{KEY}\",\"api_key_id\":\"{KEY}\",\"source_id\":\"new\",\"expires_at_ms\":{expires}}}"),format!("{{\"api_key_id\":\"{KEY}\",\"source_id\":\"new\",\"expires_at_ms\":{expires},\"active\":true}}"),serde_json::json!({"api_key_id":Uuid::nil(),"source_id":"new","expires_at_ms":expires}).to_string()] {
        assert_eq!(router.clone().oneshot(request(&path,body)).await.unwrap().status(),StatusCode::BAD_REQUEST);
    }
    let mut producer = request(&path, valid.to_string());
    producer
        .headers_mut()
        .insert("x-api-key-id", KEY.parse().unwrap());
    assert_eq!(
        router.clone().oneshot(producer).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    let mut wrong_actor = request(&path, valid.to_string());
    wrong_actor
        .headers_mut()
        .insert("x-user-id", "producer-not-admin".parse().unwrap());
    assert_eq!(
        router.clone().oneshot(wrong_actor).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let response = router
        .clone()
        .oneshot(request(&path, valid.to_string()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let body: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(body["revision"], 1);
    assert!(body["audit_id"].as_str().is_some());
    assert_eq!(body.as_object().unwrap().len(), 2);
    assert_eq!(
        router
            .clone()
            .oneshot(request(&path, valid.to_string()))
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    let expiry_path = path.replace("/create", "/change-expiry");
    assert_eq!(
        router
            .clone()
            .oneshot(request(
                &expiry_path,
                serde_json::json!({"expected_revision":1,"expires_at_ms":expires+1000}).to_string()
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        router
            .oneshot(request(
                &expiry_path,
                serde_json::json!({"expected_revision":1,"expires_at_ms":expires+2000}).to_string()
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(counts(&f.pool).await, (2, 2));
    f.pool.close().await;
}
