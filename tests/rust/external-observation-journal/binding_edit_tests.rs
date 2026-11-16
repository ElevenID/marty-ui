// SPDX-License-Identifier: AGPL-3.0-only
use crate::external_observation_admin::AdminError;
use crate::external_observation_binding_admin::{
    replace_binding_definition, set_binding_active, BindingReplacement,
};
use uuid::Uuid;
const ORG: &str = "20000000-0000-4000-8000-000000000001";
const KEY: &str = "10000000-0000-4000-8000-000000000001";
const GRANT: &str = "30000000-0000-4000-8000-000000000001";
fn id(value: &str) -> Uuid {
    Uuid::parse_str(value).unwrap()
}
async fn replacement(pool: &sqlx::PgPool) -> BindingReplacement {
    serde_json::from_value(serde_json::json!({"expected_revision":1,"expected_application_revision":super::binding_admin_tests::app_revision(pool).await,"resource_scope":{"course_id":"new-course"},"claim_rules":{"completed":{"kind":"boolean","required":true,"nullable":false},"effective_time_source":{"kind":"text","required":true,"nullable":false,"max_bytes":32}},"max_age_ms":300000,"max_clock_skew_ms":1000})).unwrap()
}
async fn audit_count(pool: &sqlx::PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM organization_service.audit_events")
        .fetch_one(pool)
        .await
        .unwrap()
}
async fn unchanged(pool: &sqlx::PgPool) {
    let binding:(bool,i64,serde_json::Value)=sqlx::query_as("SELECT active,revision,resource_scope FROM issuance_service.external_observation_bindings WHERE id='binding-one'").fetch_one(pool).await.unwrap();
    assert_eq!(
        binding,
        (true, 1, serde_json::json!({"course_id":"synthetic-course"}))
    );
    let grant:(bool,i64)=sqlx::query_as("SELECT active,revision FROM issuance_service.external_observation_producer_grants WHERE id=$1").bind(id(GRANT)).fetch_one(pool).await.unwrap();
    assert_eq!(grant, (true, 2));
    assert_eq!(audit_count(pool).await, 0);
}
#[tokio::test]
async fn replacement_preserves_identity_invalidates_approvals_and_requires_provenance_contract() {
    let f = super::admin_tests::setup().await;
    let value = replacement(&f.pool).await;
    let before:(Uuid,String,String,String,String,String)=sqlx::query_as("SELECT organization_id,source_id,application_id,subject_id,provider,fact_type FROM issuance_service.external_observation_bindings WHERE id='binding-one'").fetch_one(&f.pool).await.unwrap();
    let result = replace_binding_definition(&f.pool, id(ORG), "admin-one", "binding-one", &value)
        .await
        .unwrap();
    assert_eq!(result.revision, 2);
    let after:(Uuid,String,String,String,String,String)=sqlx::query_as("SELECT organization_id,source_id,application_id,subject_id,provider,fact_type FROM issuance_service.external_observation_bindings WHERE id='binding-one'").fetch_one(&f.pool).await.unwrap();
    assert_eq!(before, after);
    let state:(bool,i64,serde_json::Value,i64,i64)=sqlx::query_as("SELECT active,revision,resource_scope,max_age_ms,max_clock_skew_ms FROM issuance_service.external_observation_bindings WHERE id='binding-one'").fetch_one(&f.pool).await.unwrap();
    assert_eq!(
        state,
        (
            false,
            2,
            serde_json::json!({"course_id":"new-course"}),
            300000,
            1000
        )
    );
    let grant:(bool,Option<String>,i64)=sqlx::query_as("SELECT active,approved_by,revision FROM issuance_service.external_observation_producer_grants WHERE id=$1").bind(id(GRANT)).fetch_one(&f.pool).await.unwrap();
    assert_eq!(grant, (false, None, 3));
    let event: (String, serde_json::Value) = sqlx::query_as(
        "SELECT event_type,changes FROM organization_service.audit_events WHERE id=$1",
    )
    .bind(result.audit_id)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(event.0, "external_observation_binding_definition_replaced");
    assert_eq!(event.1["deactivated_grant_count"], 1);
    set_binding_active(
        &f.pool,
        id(ORG),
        "admin-one",
        "binding-one",
        2,
        Some(value.expected_application_revision),
    )
    .await
    .unwrap();
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
    observation.binding_revision = 3;
    observation.claims.remove("score");
    assert!(
        journal
            .submit(&principal, &observation, "observation-one")
            .await
            .is_err(),
        "activation must not reapprove producer"
    );
    crate::external_observation_grant_lifecycle::approve_grant(
        &f.pool,
        id(ORG),
        "admin-one",
        id(GRANT),
        4,
    )
    .await
    .unwrap();
    assert!(
        journal
            .submit(&principal, &observation, "observation-one")
            .await
            .is_err(),
        "required provenance cannot be omitted"
    );
    let receipts: i64 =
        sqlx::query_scalar("SELECT count(*) FROM issuance_service.external_observation_receipts")
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(receipts, 0);
    observation.claims.insert(
        "effective_time_source".into(),
        crate::external_observation_admission::Scalar::Text("provider_event".into()),
    );
    journal
        .submit(&principal, &observation, "observation-one")
        .await
        .unwrap();
    let status: String = sqlx::query_scalar(
        "SELECT status FROM issuance_service.applications WHERE id='application-one'",
    )
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(status, "pending");
    f.pool.close().await;
}
#[tokio::test]
async fn invalid_stale_and_unauthorized_replacements_leave_current_authority_unchanged() {
    let f = super::admin_tests::setup().await;
    let valid = replacement(&f.pool).await;
    assert_eq!(
        replace_binding_definition(&f.pool, id(ORG), "producer", "binding-one", &valid)
            .await
            .unwrap_err(),
        AdminError::NotAuthorized
    );
    assert_eq!(
        replace_binding_definition(&f.pool, Uuid::new_v4(), "admin-one", "binding-one", &valid)
            .await
            .unwrap_err(),
        AdminError::NotAuthorized
    );
    let mut stale = valid.clone();
    stale.expected_revision = 2;
    assert_eq!(
        replace_binding_definition(&f.pool, id(ORG), "admin-one", "binding-one", &stale)
            .await
            .unwrap_err(),
        AdminError::Conflict
    );
    stale = valid.clone();
    stale.expected_application_revision -= 1;
    assert_eq!(
        replace_binding_definition(&f.pool, id(ORG), "admin-one", "binding-one", &stale)
            .await
            .unwrap_err(),
        AdminError::Conflict
    );
    for (field, bad) in [
        ("resource_scope", serde_json::json!({})),
        ("max_age_ms", serde_json::json!(900001)),
        ("max_clock_skew_ms", serde_json::json!(30001)),
        (
            "claim_rules",
            serde_json::json!({"verified":{"kind":"boolean","required":true,"nullable":false}}),
        ),
    ] {
        let mut v = serde_json::to_value(&valid).unwrap();
        v[field] = bad;
        assert_eq!(
            replace_binding_definition(
                &f.pool,
                id(ORG),
                "admin-one",
                "binding-one",
                &serde_json::from_value(v).unwrap()
            )
            .await
            .unwrap_err(),
            AdminError::Conflict
        );
    }
    unchanged(&f.pool).await;
    f.pool.close().await;
}
#[tokio::test]
async fn audit_failure_and_postwrite_constraint_mutation_roll_back_definition_and_grants() {
    let f = super::admin_tests::setup().await;
    let value = replacement(&f.pool).await;
    sqlx::query("ALTER TABLE organization_service.audit_events ADD CONSTRAINT synthetic_edit_audit_failure CHECK(false) NOT VALID").execute(&f.pool).await.unwrap();
    assert_eq!(
        replace_binding_definition(&f.pool, id(ORG), "admin-one", "binding-one", &value)
            .await
            .unwrap_err(),
        AdminError::Unavailable
    );
    unchanged(&f.pool).await;
    sqlx::query("ALTER TABLE organization_service.audit_events DROP CONSTRAINT synthetic_edit_audit_failure").execute(&f.pool).await.unwrap();
    sqlx::raw_sql("CREATE FUNCTION organization_service.synthetic_mutate_edit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN UPDATE issuance_service.external_observation_bindings SET resource_scope='{}'::jsonb WHERE id='binding-one'; RETURN NEW; END $$; CREATE TRIGGER synthetic_mutate_edit BEFORE INSERT ON organization_service.audit_events FOR EACH ROW EXECUTE FUNCTION organization_service.synthetic_mutate_edit();").execute(&f.pool).await.unwrap();
    assert_eq!(
        replace_binding_definition(&f.pool, id(ORG), "admin-one", "binding-one", &value)
            .await
            .unwrap_err(),
        AdminError::Conflict
    );
    unchanged(&f.pool).await;
    f.pool.close().await;
}
#[tokio::test]
async fn concurrent_replacements_commit_one_definition_and_one_audit() {
    let f = super::admin_tests::setup().await;
    let a = replacement(&f.pool).await;
    let mut b = a.clone();
    b.resource_scope
        .0
        .insert("course_id".into(), "competing-course".into());
    let (a, b) = tokio::join!(
        replace_binding_definition(&f.pool, id(ORG), "admin-one", "binding-one", &a),
        replace_binding_definition(&f.pool, id(ORG), "admin-one", "binding-one", &b)
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert_eq!(a.err().or(b.err()), Some(AdminError::Conflict));
    assert_eq!(audit_count(&f.pool).await, 1);
    let active: bool = sqlx::query_scalar(
        "SELECT active FROM issuance_service.external_observation_bindings WHERE id='binding-one'",
    )
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert!(!active);
    f.pool.close().await;
}
#[tokio::test]
async fn application_expiry_during_audit_rolls_back_definition_replacement() {
    let f = super::admin_tests::setup().await;
    let value = replacement(&f.pool).await;
    sqlx::raw_sql("CREATE FUNCTION organization_service.synthetic_delay_edit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.4); RETURN NEW; END $$; CREATE TRIGGER synthetic_delay_edit BEFORE INSERT ON organization_service.audit_events FOR EACH ROW EXECUTE FUNCTION organization_service.synthetic_delay_edit();").execute(&f.pool).await.unwrap();
    sqlx::query("UPDATE issuance_service.applications SET expires_at=clock_timestamp()+interval '300 milliseconds' WHERE id='application-one'").execute(&f.pool).await.unwrap();
    assert_eq!(
        replace_binding_definition(&f.pool, id(ORG), "admin-one", "binding-one", &value)
            .await
            .unwrap_err(),
        AdminError::NotAuthorized
    );
    unchanged(&f.pool).await;
    f.pool.close().await;
}
#[tokio::test]
async fn membership_inserted_after_editor_discovery_conflicts_instead_of_inheriting_new_definition()
{
    let f = super::admin_tests::setup().await;
    let value = replacement(&f.pool).await;
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
        replace_binding_definition(&pool, id(ORG), "admin-one", "binding-one", &value).await
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
    assert_eq!(audit_count(&f.pool).await, 1);
    f.pool.close().await;
}
#[tokio::test]
async fn replacement_http_rejects_identity_changes_nested_duplicates_and_producer_auth() {
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    let f = super::admin_tests::setup().await;
    let service = "synthetic-gateway-service-key-for-binding-edit";
    let router = crate::external_observation_startup::prepare_observation_router(
        &f.pool,
        true,
        Some(service),
    )
    .await
    .unwrap()
    .unwrap();
    let value = serde_json::to_value(replacement(&f.pool).await).unwrap();
    let text = value.to_string();
    let path = format!(
        "/v1/organizations/{ORG}/external-observation-bindings/binding-one/replace-definition"
    );
    let request = |body: String| {
        Request::builder()
            .method("POST")
            .uri(&path)
            .header("x-api-key", service)
            .header("x-user-id", "admin-one")
            .header("x-organization-id", ORG)
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap()
    };
    for field in [
        "organization_id",
        "source_id",
        "application_id",
        "subject_id",
        "provider",
        "fact_type",
        "active",
    ] {
        let mut invalid = value.clone();
        invalid[field] = serde_json::json!("forged");
        assert_eq!(
            router
                .clone()
                .oneshot(request(invalid.to_string()))
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    for invalid in [
        text.replace(
            "\"course_id\":\"new-course\"",
            "\"course_id\":\"new-course\",\"course_id\":\"other\"",
        ),
        text.replacen(
            "\"kind\":\"boolean\"",
            "\"kind\":\"boolean\",\"kind\":\"boolean\"",
            1,
        ),
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
    let mut producer = request(text.clone());
    producer
        .headers_mut()
        .insert("x-api-key-id", KEY.parse().unwrap());
    assert_eq!(
        router.clone().oneshot(producer).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    let response = router.clone().oneshot(request(text.clone())).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let body: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(body["revision"], 2);
    assert!(body["audit_id"].as_str().is_some());
    assert_eq!(body.as_object().unwrap().len(), 2);
    assert_eq!(
        router.oneshot(request(text)).await.unwrap().status(),
        StatusCode::CONFLICT
    );
    assert_eq!(audit_count(&f.pool).await, 1);
    f.pool.close().await;
}
