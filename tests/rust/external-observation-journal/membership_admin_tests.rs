// SPDX-License-Identifier: AGPL-3.0-only
use crate::external_observation_admin::AdminError;
use crate::external_observation_membership_admin::{replace_grant_bindings, BindingSelection};
use sqlx::PgPool;
use uuid::Uuid;
const ORG: &str = "20000000-0000-4000-8000-000000000001";
const KEY: &str = "10000000-0000-4000-8000-000000000001";
const GRANT: &str = "30000000-0000-4000-8000-000000000001";
fn id(v: &str) -> Uuid {
    Uuid::parse_str(v).unwrap()
}
fn selected(v: &str, revision: i64) -> BindingSelection {
    BindingSelection {
        binding_id: v.into(),
        expected_revision: revision,
    }
}
async fn clone_binding(pool: &PgPool, name: &str) {
    sqlx::query("INSERT INTO issuance_service.external_observation_bindings(id,organization_id,source_id,application_id,subject_id,provider,fact_type,resource_scope,claim_rules,max_age_ms,max_clock_skew_ms,active,created_by,updated_by)
      SELECT $1,organization_id,source_id,application_id,subject_id,provider,fact_type,resource_scope,claim_rules,max_age_ms,max_clock_skew_ms,active,created_by,updated_by FROM issuance_service.external_observation_bindings WHERE id='binding-one'")
      .bind(name).execute(pool).await.unwrap();
}
async fn members(pool: &PgPool) -> std::collections::BTreeSet<String> {
    sqlx::query_scalar("SELECT binding_id FROM issuance_service.external_observation_grant_bindings WHERE grant_id=$1").bind(id(GRANT)).fetch_all(pool).await.unwrap().into_iter().collect()
}
async fn audits(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM organization_service.audit_events")
        .fetch_one(pool)
        .await
        .unwrap()
}
#[tokio::test]
async fn replacement_preserves_key_source_and_bindings_but_requires_fresh_approval() {
    let f = super::admin_tests::setup().await;
    clone_binding(&f.pool, "Z-bind").await;
    clone_binding(&f.pool, "a-bind").await;
    let selection = [selected("a-bind", 1), selected("Z-bind", 1)];
    let result = replace_grant_bindings(&f.pool, id(ORG), "admin-one", id(GRANT), 2, &selection)
        .await
        .unwrap();
    assert!(result.revision > 2);
    assert_eq!(
        members(&f.pool).await,
        std::collections::BTreeSet::from(["a-bind".into(), "Z-bind".into()])
    );
    let state:(Uuid,String,bool,Option<String>,i64)=sqlx::query_as("SELECT api_key_id,source_id,active,approved_by,revision FROM issuance_service.external_observation_producer_grants WHERE id=$1").bind(id(GRANT)).fetch_one(&f.pool).await.unwrap();
    assert_eq!(
        state,
        (id(KEY), "source-one".into(), false, None, result.revision)
    );
    let definitions:i64=sqlx::query_scalar("SELECT count(*) FROM issuance_service.external_observation_bindings WHERE active AND revision=1").fetch_one(&f.pool).await.unwrap();
    assert_eq!(definitions, 3);
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
            "external_observation_grant_bindings_replaced".into(),
            "admin-one".into()
        )
    );
    crate::external_observation_grant_lifecycle::approve_grant(
        &f.pool,
        id(ORG),
        "admin-one",
        id(GRANT),
        result.revision,
    )
    .await
    .unwrap();
    assert_eq!(audits(&f.pool).await, 2);
    f.pool.close().await;
}
#[tokio::test]
async fn explicit_empty_set_removes_all_members_and_deactivates() {
    let f = super::admin_tests::setup().await;
    let result = replace_grant_bindings(&f.pool, id(ORG), "admin-one", id(GRANT), 2, &[])
        .await
        .unwrap();
    assert!(result.revision > 2);
    assert!(members(&f.pool).await.is_empty());
    let active: bool = sqlx::query_scalar(
        "SELECT active FROM issuance_service.external_observation_producer_grants",
    )
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert!(!active);
    assert_eq!(audits(&f.pool).await, 1);
    f.pool.close().await;
}
#[tokio::test]
async fn missing_foreign_stale_duplicate_and_invalid_selections_write_nothing() {
    let f = super::admin_tests::setup().await;
    clone_binding(&f.pool, "other-source").await;
    sqlx::query("UPDATE issuance_service.external_observation_bindings SET source_id='other-source' WHERE id='other-source'").execute(&f.pool).await.unwrap();
    clone_binding(&f.pool, "foreign-org").await;
    sqlx::query("INSERT INTO organization_service.organizations(id) VALUES ('20000000-0000-4000-8000-000000000002')").execute(&f.pool).await.unwrap();
    sqlx::query("UPDATE issuance_service.external_observation_bindings SET organization_id='20000000-0000-4000-8000-000000000002' WHERE id='foreign-org'").execute(&f.pool).await.unwrap();
    for name in ["missing", "other-source", "foreign-org"] {
        assert_eq!(
            replace_grant_bindings(
                &f.pool,
                id(ORG),
                "admin-one",
                id(GRANT),
                2,
                &[selected(name, 1)]
            )
            .await
            .unwrap_err(),
            AdminError::NotAuthorized
        );
    }
    for selection in [
        vec![selected("binding-one", 2)],
        vec![selected("binding-one", 1), selected("binding-one", 1)],
        vec![selected("bad/name", 1)],
        vec![selected("binding-one", 0)],
        (0..33).map(|i| selected(&format!("b-{i}"), 1)).collect(),
    ] {
        assert_eq!(
            replace_grant_bindings(&f.pool, id(ORG), "admin-one", id(GRANT), 2, &selection)
                .await
                .unwrap_err(),
            AdminError::Conflict
        );
    }
    assert_eq!(
        replace_grant_bindings(&f.pool, id(ORG), "admin-one", id(GRANT), 1, &[])
            .await
            .unwrap_err(),
        AdminError::Conflict
    );
    assert_eq!(
        members(&f.pool).await,
        std::collections::BTreeSet::from(["binding-one".into()])
    );
    assert_eq!(audits(&f.pool).await, 0);
    f.pool.close().await;
}
#[tokio::test]
async fn current_actor_tenant_and_key_scope_cannot_be_replaced_by_membership_input() {
    let f = super::admin_tests::setup().await;
    assert_eq!(
        replace_grant_bindings(&f.pool, id(ORG), "producer", id(GRANT), 2, &[])
            .await
            .unwrap_err(),
        AdminError::NotAuthorized
    );
    assert_eq!(
        replace_grant_bindings(&f.pool, Uuid::new_v4(), "admin-one", id(GRANT), 2, &[])
            .await
            .unwrap_err(),
        AdminError::NotAuthorized
    );
    sqlx::query(
        "UPDATE organization_service.api_keys SET scopes=ARRAY['*','admin:full','evidence:*']",
    )
    .execute(&f.pool)
    .await
    .unwrap();
    assert_eq!(
        replace_grant_bindings(&f.pool, id(ORG), "admin-one", id(GRANT), 2, &[])
            .await
            .unwrap_err(),
        AdminError::NotAuthorized
    );
    assert_eq!(audits(&f.pool).await, 0);
    f.pool.close().await;
}
#[tokio::test]
async fn audit_failure_and_same_transaction_binding_revision_change_roll_back_every_write() {
    let f = super::admin_tests::setup().await;
    clone_binding(&f.pool, "new-bind").await;
    sqlx::query("ALTER TABLE organization_service.audit_events ADD CONSTRAINT synthetic_audit_failure CHECK(false) NOT VALID").execute(&f.pool).await.unwrap();
    assert_eq!(
        replace_grant_bindings(
            &f.pool,
            id(ORG),
            "admin-one",
            id(GRANT),
            2,
            &[selected("new-bind", 1)]
        )
        .await
        .unwrap_err(),
        AdminError::Unavailable
    );
    sqlx::query(
        "ALTER TABLE organization_service.audit_events DROP CONSTRAINT synthetic_audit_failure",
    )
    .execute(&f.pool)
    .await
    .unwrap();
    sqlx::raw_sql("CREATE FUNCTION organization_service.synthetic_change_binding() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN UPDATE issuance_service.external_observation_bindings SET active=active WHERE id='new-bind'; RETURN NEW; END $$; CREATE TRIGGER synthetic_change_binding BEFORE INSERT ON organization_service.audit_events FOR EACH ROW EXECUTE FUNCTION organization_service.synthetic_change_binding();").execute(&f.pool).await.unwrap();
    assert_eq!(
        replace_grant_bindings(
            &f.pool,
            id(ORG),
            "admin-one",
            id(GRANT),
            2,
            &[selected("new-bind", 1)]
        )
        .await
        .unwrap_err(),
        AdminError::Conflict
    );
    let state: (bool, i64) = sqlx::query_as(
        "SELECT active,revision FROM issuance_service.external_observation_producer_grants",
    )
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(state, (true, 2));
    assert_eq!(
        members(&f.pool).await,
        std::collections::BTreeSet::from(["binding-one".into()])
    );
    assert_eq!(audits(&f.pool).await, 0);
    f.pool.close().await;
}
#[tokio::test]
async fn concurrent_replacements_have_one_revision_fenced_effect() {
    let f = super::admin_tests::setup().await;
    let selection = [selected("binding-one", 1)];
    let (a, b) = tokio::join!(
        replace_grant_bindings(&f.pool, id(ORG), "admin-one", id(GRANT), 2, &[]),
        replace_grant_bindings(&f.pool, id(ORG), "admin-one", id(GRANT), 2, &selection)
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert_eq!(a.err().or(b.err()), Some(AdminError::Conflict));
    assert_eq!(audits(&f.pool).await, 1);
    f.pool.close().await;
}
#[tokio::test]
async fn binding_revision_change_while_waiting_for_binding_lock_denies_stale_selection() {
    let f = super::admin_tests::setup().await;
    let mut blocker = f.pool.begin().await.unwrap();
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    sqlx::query("SELECT id FROM issuance_service.external_observation_bindings WHERE id='binding-one' FOR UPDATE").execute(&mut *blocker).await.unwrap();
    let pool = f.pool.clone();
    let operation = tokio::spawn(async move {
        replace_grant_bindings(
            &pool,
            id(ORG),
            "admin-one",
            id(GRANT),
            2,
            &[selected("binding-one", 1)],
        )
        .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let blocked: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))",
            )
            .bind(pid)
            .fetch_one(&f.pool)
            .await
            .unwrap();
            if blocked {
                break;
            }
            assert!(!operation.is_finished());
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    sqlx::query("UPDATE issuance_service.external_observation_bindings SET active=active WHERE id='binding-one'").execute(&mut *blocker).await.unwrap();
    blocker.commit().await.unwrap();
    assert_eq!(operation.await.unwrap().unwrap_err(), AdminError::Conflict);
    assert_eq!(audits(&f.pool).await, 0);
    assert_eq!(
        members(&f.pool).await,
        std::collections::BTreeSet::from(["binding-one".into()])
    );
    f.pool.close().await;
}
#[tokio::test]
async fn grant_and_key_expiry_during_delayed_audit_roll_back_membership_change() {
    let f = super::admin_tests::setup().await;
    sqlx::raw_sql("CREATE FUNCTION organization_service.synthetic_delay_membership_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.4); RETURN NEW; END $$; CREATE TRIGGER synthetic_delay_membership_audit BEFORE INSERT ON organization_service.audit_events FOR EACH ROW EXECUTE FUNCTION organization_service.synthetic_delay_membership_audit();").execute(&f.pool).await.unwrap();
    sqlx::query("UPDATE issuance_service.external_observation_producer_grants SET expires_at=clock_timestamp()+interval '300 milliseconds'").execute(&f.pool).await.unwrap();
    assert_eq!(
        replace_grant_bindings(&f.pool, id(ORG), "admin-one", id(GRANT), 3, &[])
            .await
            .unwrap_err(),
        AdminError::Conflict
    );
    sqlx::query("UPDATE issuance_service.external_observation_producer_grants SET expires_at=clock_timestamp()+interval '2 minutes'").execute(&f.pool).await.unwrap();
    sqlx::query("UPDATE organization_service.api_keys SET expires_at=clock_timestamp()+interval '300 milliseconds'").execute(&f.pool).await.unwrap();
    assert_eq!(
        replace_grant_bindings(&f.pool, id(ORG), "admin-one", id(GRANT), 4, &[])
            .await
            .unwrap_err(),
        AdminError::NotAuthorized
    );
    assert_eq!(
        members(&f.pool).await,
        std::collections::BTreeSet::from(["binding-one".into()])
    );
    assert_eq!(audits(&f.pool).await, 0);
    f.pool.close().await;
}
#[tokio::test]
async fn mounted_membership_http_rejects_authority_fields_duplicates_and_producer_identity() {
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    let f = super::admin_tests::setup().await;
    let key = "synthetic-gateway-service-key-for-membership";
    let router =
        crate::external_observation_startup::prepare_observation_router(&f.pool, true, Some(key))
            .await
            .unwrap()
            .unwrap();
    let path =
        format!("/v1/organizations/{ORG}/external-observation-producers/{GRANT}/replace-bindings");
    let request = |body: &str| {
        Request::builder()
            .method("POST")
            .uri(&path)
            .header("x-api-key", key)
            .header("x-user-id", "admin-one")
            .header("x-organization-id", ORG)
            .header("content-type", "application/json")
            .body(Body::from(body.to_owned()))
            .unwrap()
    };
    for invalid in [
        r#"{"expected_revision":2,"bindings":[],"active":true}"#,
        r#"{"expected_revision":2,"bindings":[{"binding_id":"binding-one","expected_revision":1,"subject_id":"forged"}]}"#,
        r#"{"expected_revision":2,"bindings":[{"binding_id":"binding-one","binding_id":"forged","expected_revision":1}]}"#,
        r#"{"expected_revision":2,"bindings":[{"binding_id":"binding-one","expected_revision":1},{"binding_id":"binding-one","expected_revision":1}]}"#,
    ] {
        assert_eq!(
            router
                .clone()
                .oneshot(request(invalid))
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    let valid = r#"{"expected_revision":2,"bindings":[]}"#;
    let mut producer = request(valid);
    producer
        .headers_mut()
        .insert("x-api-key-id", KEY.parse().unwrap());
    assert_eq!(
        router.clone().oneshot(producer).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    let response = router.oneshot(request(valid)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let body: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
    assert!(body["revision"].as_i64().unwrap() > 2);
    assert!(body["audit_id"].as_str().is_some());
    assert_eq!(body.as_object().unwrap().len(), 2);
    assert!(members(&f.pool).await.is_empty());
    assert_eq!(audits(&f.pool).await, 1);
    f.pool.close().await;
}
