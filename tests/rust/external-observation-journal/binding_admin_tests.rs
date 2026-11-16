// SPDX-License-Identifier: AGPL-3.0-only
use crate::external_observation_admin::AdminError;
use crate::external_observation_binding_admin::{
    create_binding, set_binding_active, BindingDefinition,
};
use uuid::Uuid;
const ORG: &str = "20000000-0000-4000-8000-000000000001";
const KEY: &str = "10000000-0000-4000-8000-000000000001";
const GRANT: &str = "30000000-0000-4000-8000-000000000001";
fn id(value: &str) -> Uuid {
    Uuid::parse_str(value).unwrap()
}
async fn app_revision(pool: &sqlx::PgPool) -> i64 {
    sqlx::query_scalar("SELECT (extract(epoch FROM updated_at)*1000000)::bigint FROM issuance_service.applications WHERE id='application-one'").fetch_one(pool).await.unwrap()
}
async fn definition(pool: &sqlx::PgPool) -> BindingDefinition {
    serde_json::from_value(serde_json::json!({"source_id":"source-one","application_id":"application-one","expected_application_revision":app_revision(pool).await,"provider":"synthetic-lms","fact_type":"learning.score","resource_scope":{"course_id":"synthetic-course"},"claim_rules":{"completed":{"kind":"boolean","required":true,"nullable":false},"score":{"kind":"number","minimum":0,"maximum":100,"required":false,"nullable":true}},"max_age_ms":900000,"max_clock_skew_ms":30000})).unwrap()
}
async fn audits(pool: &sqlx::PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM organization_service.audit_events")
        .fetch_one(pool)
        .await
        .unwrap()
}
#[tokio::test]
async fn creation_derives_subject_from_current_application_and_starts_inactive() {
    let f = super::admin_tests::setup().await;
    let value = definition(&f.pool).await;
    let result = create_binding(&f.pool, id(ORG), "admin-one", "new-binding", &value)
        .await
        .unwrap();
    assert_eq!(result.revision, 1);
    let row:(String,String,bool,i64)=sqlx::query_as("SELECT application_id,subject_id,active,revision FROM issuance_service.external_observation_bindings WHERE id='new-binding'").fetch_one(&f.pool).await.unwrap();
    assert_eq!(
        row,
        ("application-one".into(), "learner-one".into(), false, 1)
    );
    let memberships:i64=sqlx::query_scalar("SELECT count(*) FROM issuance_service.external_observation_grant_bindings WHERE binding_id='new-binding'").fetch_one(&f.pool).await.unwrap();
    assert_eq!(memberships, 0);
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
            "external_observation_binding_created".into(),
            "admin-one".into()
        )
    );
    assert_eq!(
        create_binding(&f.pool, id(ORG), "admin-one", "new-binding", &value)
            .await
            .unwrap_err(),
        AdminError::Conflict
    );
    assert_eq!(audits(&f.pool).await, 1);
    f.pool.close().await;
}
#[tokio::test]
async fn activation_and_deactivation_invalidate_existing_grant_approvals() {
    let f = super::admin_tests::setup().await;
    let app = app_revision(&f.pool).await;
    let result = set_binding_active(&f.pool, id(ORG), "admin-one", "binding-one", 1, Some(app))
        .await
        .unwrap();
    assert_eq!(result.revision, 2);
    let grant:(bool,Option<String>,i64)=sqlx::query_as("SELECT active,approved_by,revision FROM issuance_service.external_observation_producer_grants").fetch_one(&f.pool).await.unwrap();
    assert_eq!(grant, (false, None, 3));
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
    let mut observation = f.input();
    observation.binding_revision = 2;
    assert_eq!(
        journal
            .submit(&principal, &observation, "observation-one")
            .await
            .unwrap_err(),
        crate::external_observation_postgres::JournalError::Denied(
            crate::external_observation_admission::Denial::NotAuthorized
        )
    );
    crate::external_observation_grant_lifecycle::approve_grant(
        &f.pool,
        id(ORG),
        "admin-one",
        id(GRANT),
        3,
    )
    .await
    .unwrap();
    journal
        .submit(&principal, &observation, "observation-one")
        .await
        .unwrap();
    set_binding_active(&f.pool, id(ORG), "admin-one", "binding-one", 2, None)
        .await
        .unwrap();
    let active: bool = sqlx::query_scalar(
        "SELECT active FROM issuance_service.external_observation_producer_grants",
    )
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert!(!active);
    let status: String = sqlx::query_scalar(
        "SELECT status FROM issuance_service.applications WHERE id='application-one'",
    )
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(status, "pending");
    assert_eq!(audits(&f.pool).await, 3);
    f.pool.close().await;
}
#[tokio::test]
async fn invalid_definition_and_stale_or_foreign_application_write_nothing() {
    let f = super::admin_tests::setup().await;
    let valid = definition(&f.pool).await;
    for field in ["source_id", "provider", "fact_type"] {
        let mut value = serde_json::to_value(&valid).unwrap();
        value[field] = serde_json::json!("bad/name");
        let input = serde_json::from_value(value).unwrap();
        assert_eq!(
            create_binding(&f.pool, id(ORG), "admin-one", "new-binding", &input)
                .await
                .unwrap_err(),
            AdminError::Conflict
        );
    }
    let mut reserved = serde_json::to_value(&valid).unwrap();
    reserved["claim_rules"] =
        serde_json::json!({"verified":{"kind":"boolean","required":true,"nullable":false}});
    assert_eq!(
        create_binding(
            &f.pool,
            id(ORG),
            "admin-one",
            "new-binding",
            &serde_json::from_value(reserved).unwrap()
        )
        .await
        .unwrap_err(),
        AdminError::Conflict
    );
    let mut stale = valid.clone();
    stale.expected_application_revision -= 1;
    assert_eq!(
        create_binding(&f.pool, id(ORG), "admin-one", "new-binding", &stale)
            .await
            .unwrap_err(),
        AdminError::Conflict
    );
    sqlx::query("UPDATE issuance_service.applications SET organization_id='20000000-0000-4000-8000-000000000002' WHERE id='application-one'").execute(&f.pool).await.unwrap();
    assert_eq!(
        create_binding(&f.pool, id(ORG), "admin-one", "new-binding", &valid)
            .await
            .unwrap_err(),
        AdminError::NotAuthorized
    );
    assert_eq!(audits(&f.pool).await, 0);
    f.pool.close().await;
}
#[tokio::test]
async fn canonical_actor_permission_and_tenant_are_required_for_binding_administration() {
    let f = super::admin_tests::setup().await;
    let value = definition(&f.pool).await;
    let rev = app_revision(&f.pool).await;
    assert_eq!(
        create_binding(&f.pool, id(ORG), "producer", "new-binding", &value)
            .await
            .unwrap_err(),
        AdminError::NotAuthorized
    );
    assert_eq!(
        set_binding_active(&f.pool, id(ORG), "producer", "binding-one", 1, Some(rev))
            .await
            .unwrap_err(),
        AdminError::NotAuthorized
    );
    assert_eq!(
        set_binding_active(&f.pool, Uuid::new_v4(), "admin-one", "binding-one", 1, None)
            .await
            .unwrap_err(),
        AdminError::NotAuthorized
    );
    sqlx::query("DELETE FROM organization_service.role_permissions")
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        create_binding(&f.pool, id(ORG), "admin-one", "new-binding", &value)
            .await
            .unwrap_err(),
        AdminError::NotAuthorized
    );
    assert_eq!(audits(&f.pool).await, 0);
    f.pool.close().await;
}
#[tokio::test]
async fn audit_failure_rolls_back_binding_creation_state_and_all_grant_changes() {
    let f = super::admin_tests::setup().await;
    let value = definition(&f.pool).await;
    sqlx::query("ALTER TABLE organization_service.audit_events ADD CONSTRAINT synthetic_audit_failure CHECK(false) NOT VALID").execute(&f.pool).await.unwrap();
    assert_eq!(
        create_binding(&f.pool, id(ORG), "admin-one", "new-binding", &value)
            .await
            .unwrap_err(),
        AdminError::Unavailable
    );
    assert_eq!(
        set_binding_active(&f.pool, id(ORG), "admin-one", "binding-one", 1, None)
            .await
            .unwrap_err(),
        AdminError::Unavailable
    );
    let state: (bool, i64) = sqlx::query_as(
        "SELECT active,revision FROM issuance_service.external_observation_producer_grants",
    )
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(state, (true, 2));
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM issuance_service.external_observation_bindings")
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(count, 1);
    assert_eq!(audits(&f.pool).await, 0);
    f.pool.close().await;
}
#[tokio::test]
async fn closed_application_and_subject_mismatch_deny_activation_but_allow_deactivation() {
    let f = super::admin_tests::setup().await;
    let rev = app_revision(&f.pool).await;
    sqlx::query(
        "UPDATE issuance_service.applications SET status='issued' WHERE id='application-one'",
    )
    .execute(&f.pool)
    .await
    .unwrap();
    assert_eq!(
        set_binding_active(&f.pool, id(ORG), "admin-one", "binding-one", 1, Some(rev))
            .await
            .unwrap_err(),
        AdminError::NotAuthorized
    );
    sqlx::query("UPDATE issuance_service.applications SET status='pending',applicant_identifier='different-subject' WHERE id='application-one'").execute(&f.pool).await.unwrap();
    assert_eq!(
        set_binding_active(&f.pool, id(ORG), "admin-one", "binding-one", 1, Some(rev))
            .await
            .unwrap_err(),
        AdminError::NotAuthorized
    );
    sqlx::query(
        "UPDATE issuance_service.applications SET status='issued' WHERE id='application-one'",
    )
    .execute(&f.pool)
    .await
    .unwrap();
    set_binding_active(&f.pool, id(ORG), "admin-one", "binding-one", 1, None)
        .await
        .unwrap();
    assert_eq!(audits(&f.pool).await, 1);
    f.pool.close().await;
}
#[tokio::test]
async fn application_expiry_during_delayed_audit_rolls_back_creation_and_activation() {
    let f = super::admin_tests::setup().await;
    let value = definition(&f.pool).await;
    sqlx::raw_sql("CREATE FUNCTION organization_service.synthetic_delay_binding_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.4); RETURN NEW; END $$; CREATE TRIGGER synthetic_delay_binding_audit BEFORE INSERT ON organization_service.audit_events FOR EACH ROW EXECUTE FUNCTION organization_service.synthetic_delay_binding_audit();").execute(&f.pool).await.unwrap();
    sqlx::query("UPDATE issuance_service.applications SET expires_at=clock_timestamp()+interval '300 milliseconds'").execute(&f.pool).await.unwrap();
    assert_eq!(
        create_binding(&f.pool, id(ORG), "admin-one", "new-binding", &value)
            .await
            .unwrap_err(),
        AdminError::NotAuthorized
    );
    sqlx::query("UPDATE issuance_service.applications SET expires_at=clock_timestamp()+interval '300 milliseconds'").execute(&f.pool).await.unwrap();
    assert_eq!(
        set_binding_active(
            &f.pool,
            id(ORG),
            "admin-one",
            "binding-one",
            1,
            Some(value.expected_application_revision)
        )
        .await
        .unwrap_err(),
        AdminError::NotAuthorized
    );
    let state: (bool, i64) = sqlx::query_as(
        "SELECT active,revision FROM issuance_service.external_observation_producer_grants",
    )
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(state, (true, 2));
    assert_eq!(audits(&f.pool).await, 0);
    f.pool.close().await;
}
#[tokio::test]
async fn same_transaction_audit_trigger_cannot_reactivate_grant_or_modify_new_binding() {
    let f = super::admin_tests::setup().await;
    let value = definition(&f.pool).await;
    sqlx::raw_sql("CREATE FUNCTION organization_service.synthetic_rewrite_binding_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.event_type='external_observation_binding_created' THEN UPDATE issuance_service.external_observation_bindings SET fact_type='changed' WHERE id='new-binding'; ELSE UPDATE issuance_service.external_observation_producer_grants SET active=true,approved_by='synthetic-trigger',approved_at=clock_timestamp(); END IF; RETURN NEW; END $$; CREATE TRIGGER synthetic_rewrite_binding_audit BEFORE INSERT ON organization_service.audit_events FOR EACH ROW EXECUTE FUNCTION organization_service.synthetic_rewrite_binding_audit();").execute(&f.pool).await.unwrap();
    assert_eq!(
        create_binding(&f.pool, id(ORG), "admin-one", "new-binding", &value)
            .await
            .unwrap_err(),
        AdminError::Conflict
    );
    assert_eq!(
        set_binding_active(&f.pool, id(ORG), "admin-one", "binding-one", 1, None)
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
    assert_eq!(audits(&f.pool).await, 0);
    f.pool.close().await;
}
#[tokio::test]
async fn concurrent_binding_state_changes_have_one_revision_fenced_effect() {
    let f = super::admin_tests::setup().await;
    let app = app_revision(&f.pool).await;
    let (a, b) = tokio::join!(
        set_binding_active(&f.pool, id(ORG), "admin-one", "binding-one", 1, Some(app)),
        set_binding_active(&f.pool, id(ORG), "admin-one", "binding-one", 1, None)
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert_eq!(a.err().or(b.err()), Some(AdminError::Conflict));
    assert_eq!(audits(&f.pool).await, 1);
    f.pool.close().await;
}
#[tokio::test]
async fn membership_insertion_after_discovery_conflicts_with_stale_binding_state_change() {
    let f = super::admin_tests::setup().await;
    let new_key = id("10000000-0000-4000-8000-000000000002");
    let new_grant = Uuid::new_v4();
    sqlx::query("INSERT INTO organization_service.api_keys(id,organization_id,scopes,scope_type,status,enabled,expires_at,updated_at) VALUES ($1,$2,ARRAY['evidence:submit'],'ORGANIZATION','active',true,clock_timestamp()+interval '2 minutes',clock_timestamp())").bind(new_key).bind(id(ORG)).execute(&f.pool).await.unwrap();
    sqlx::query("INSERT INTO issuance_service.external_observation_producer_grants(id,organization_id,source_id,api_key_id,active,expires_at,created_by) VALUES ($1,$2,'source-one',$3,false,clock_timestamp()+interval '2 minutes','admin-one')").bind(new_grant).bind(id(ORG)).bind(new_key).execute(&f.pool).await.unwrap();
    let mut blocker = f.pool.begin().await.unwrap();
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    sqlx::query("SELECT id FROM organization_service.api_keys WHERE id=$1 FOR UPDATE")
        .bind(id(KEY))
        .execute(&mut *blocker)
        .await
        .unwrap();
    let pool = f.pool.clone();
    let operation = tokio::spawn(async move {
        set_binding_active(&pool, id(ORG), "admin-one", "binding-one", 1, None).await
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
    crate::external_observation_membership_admin::replace_grant_bindings(
        &f.pool,
        id(ORG),
        "admin-one",
        new_grant,
        1,
        &[
            crate::external_observation_membership_admin::BindingSelection {
                binding_id: "binding-one".into(),
                expected_revision: 1,
            },
        ],
    )
    .await
    .unwrap();
    blocker.commit().await.unwrap();
    assert_eq!(operation.await.unwrap().unwrap_err(), AdminError::Conflict);
    let state:(bool,i64)=sqlx::query_as("SELECT active,revision FROM issuance_service.external_observation_bindings WHERE id='binding-one'").fetch_one(&f.pool).await.unwrap();
    assert_eq!(state, (true, 1));
    let active: bool = sqlx::query_scalar(
        "SELECT active FROM issuance_service.external_observation_producer_grants WHERE id=$1",
    )
    .bind(new_grant)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert!(!active);
    assert_eq!(audits(&f.pool).await, 1);
    f.pool.close().await;
}
#[tokio::test]
async fn binding_http_rejects_nested_duplicate_keys_unknown_subject_and_producer_identity() {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    let f = super::admin_tests::setup().await;
    let key = "synthetic-gateway-service-key-for-binding-contract";
    let router =
        crate::external_observation_startup::prepare_observation_router(&f.pool, true, Some(key))
            .await
            .unwrap()
            .unwrap();
    let value = serde_json::to_string(&definition(&f.pool).await).unwrap();
    let path = format!("/v1/organizations/{ORG}/external-observation-bindings/new-binding/create");
    let request = |body: String| {
        Request::builder()
            .method("POST")
            .uri(&path)
            .header("x-api-key", key)
            .header("x-user-id", "admin-one")
            .header("x-organization-id", ORG)
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap()
    };
    for invalid in [value.replace("\"course_id\":\"synthetic-course\"","\"course_id\":\"synthetic-course\",\"course_id\":\"other\""),value.replace("\"completed\":{","\"completed\":{\"kind\":\"boolean\",\"required\":true,\"nullable\":false},\"completed\":{") ,value.replacen("\"kind\":\"boolean\"","\"kind\":\"boolean\",\"kind\":\"boolean\"",1),value.replacen('{',"{\"subject_id\":\"forged\",",1)] {
        assert_eq!(router.clone().oneshot(request(invalid)).await.unwrap().status(),StatusCode::BAD_REQUEST);
    }
    let mut producer = request(value.clone());
    producer
        .headers_mut()
        .insert("x-api-key-id", KEY.parse().unwrap());
    assert_eq!(
        router.clone().oneshot(producer).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        router.oneshot(request(value)).await.unwrap().status(),
        StatusCode::OK
    );
    assert_eq!(audits(&f.pool).await, 1);
    f.pool.close().await;
}
