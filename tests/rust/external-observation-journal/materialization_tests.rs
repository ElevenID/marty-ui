// SPDX-License-Identifier: AGPL-3.0-only
use crate::external_observation_admin::AdminError;
use crate::external_observation_materialization::{inspect_materialization, materialize};
use crate::external_observation_postgres::{PostgresObservationJournal, ProducerIdentity};
use serde_json::{json, Value};
use sqlx::Row;
use std::sync::Arc;
use uuid::Uuid;
const ORG: &str = "20000000-0000-4000-8000-000000000001";
const KEY: &str = "10000000-0000-4000-8000-000000000001";
fn org() -> Uuid {
    Uuid::parse_str(ORG).unwrap()
}
async fn setup() -> super::Fixture {
    let f = super::admin_tests::setup().await;
    install_evidence_schema(&f.pool).await;
    f
}
pub(super) async fn install_evidence_schema(pool: &sqlx::PgPool) {
    // Exact production table and constraint definitions, not a parallel schema.
    let baseline = include_str!(
        "../../../rust/services/issuance/migrations/0000_issuance_service_baseline.sql"
    );
    for name in ["evidence_facts", "evidence_fact_heads", "issuance_events"] {
        let start = baseline
            .find(&format!("CREATE TABLE issuance_service.{name} ("))
            .unwrap();
        let end = baseline[start..].find("\n);").unwrap() + start + 3;
        sqlx::raw_sql(&baseline[start..end])
            .execute(pool)
            .await
            .unwrap();
    }
    for name in [
        "evidence_facts_pkey",
        "evidence_fact_heads_pkey",
        "evidence_fact_heads_fact_id_key",
        "issuance_events_pkey",
        "evidence_facts_application_id_fkey",
        "evidence_fact_heads_application_id_fkey",
        "evidence_fact_heads_fact_id_fkey",
    ] {
        let end = baseline.find(&format!("ADD CONSTRAINT {name} ")).unwrap();
        let start = baseline[..end].rfind("ALTER TABLE ONLY ").unwrap();
        let finish = end + baseline[end..].find(';').unwrap() + 1;
        sqlx::raw_sql(&baseline[start..finish])
            .execute(pool)
            .await
            .unwrap();
    }
}
async fn revision(f: &super::Fixture) -> i64 {
    super::binding_admin_tests::app_revision(&f.pool).await
}
async fn submit(f: &super::Fixture, n: u64) {
    let mut input = f.input();
    input.sequence = n;
    input.observation_id = format!("observation-{n}");
    PostgresObservationJournal::new(
        f.pool.clone(),
        Arc::new(crate::external_observation_authority_postgres::PostgresObservationAuthority),
    )
    .submit(
        &ProducerIdentity {
            api_key_id: KEY.into(),
            organization_id: ORG.into(),
        },
        &input,
        &input.observation_id,
    )
    .await
    .unwrap();
}
async fn counts(f: &super::Fixture) -> (i64, i64, i64) {
    sqlx::query_as("SELECT (SELECT count(*) FROM issuance_service.evidence_facts),(SELECT count(*) FROM issuance_service.evidence_fact_heads),(SELECT count(*) FROM issuance_service.issuance_events)").fetch_one(&f.pool).await.unwrap()
}
#[tokio::test]
async fn materialization_attaches_unsigned_fact_and_invalidates_stale_application_snapshot() {
    let f = setup().await;
    submit(&f, 1).await;
    let before = revision(&f).await;
    let r = materialize(
        &f.pool,
        org(),
        "admin-one",
        "source-one",
        "observation-1",
        before,
    )
    .await
    .unwrap();
    assert!(!r.replayed);
    assert!(r.application_revision > before);
    assert_eq!(revision(&f).await, r.application_revision);
    let row = sqlx::query("SELECT * FROM issuance_service.evidence_facts")
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        row.get::<Value, _>("verification"),
        json!({"status":"UNVERIFIED","method":"UNSIGNED_PRODUCER_ATTESTATION"})
    );
    assert_eq!(row.get::<String, _>("organization_id"), ORG);
    assert_eq!(row.get::<String, _>("application_id"), "application-one");
    assert_eq!(row.get::<Value, _>("assertion")["completed"], false);
    assert_eq!(
        row.get::<Value, _>("source")["receipt_id"],
        r.receipt_id.to_string()
    );
    assert_eq!(row.get::<Option<String>, _>("requirement_id"), None);
    assert_eq!(counts(&f).await, (1, 1, 1));
    let lifecycle: String = sqlx::query_scalar("SELECT status FROM issuance_service.applications")
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(lifecycle, "pending");
    let tx: Option<String> =
        sqlx::query_scalar("SELECT transaction_id FROM issuance_service.issuance_events")
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(tx, None);
    // The first intent revision remains mandatory, including after closure.
    sqlx::query("UPDATE issuance_service.applications SET status='approved'")
        .execute(&f.pool)
        .await
        .unwrap();
    let retry = materialize(
        &f.pool,
        org(),
        "admin-one",
        "source-one",
        "observation-1",
        before,
    )
    .await
    .unwrap();
    assert!(retry.replayed);
    assert_eq!(retry.fact_id, r.fact_id);
    assert_eq!(counts(&f).await, (1, 1, 1));
    assert_eq!(
        materialize(
            &f.pool,
            org(),
            "admin-one",
            "source-one",
            "observation-1",
            r.application_revision
        )
        .await
        .unwrap_err(),
        AdminError::Conflict
    );
    let inspection =
        inspect_materialization(&f.pool, org(), "admin-one", "source-one", "observation-1")
            .await
            .unwrap();
    assert_eq!(inspection["record"]["materialized_by"], "admin-one");
    f.pool.close().await;
}
#[tokio::test]
async fn older_receipts_cannot_regress_heads_but_historical_replay_survives_supersession() {
    let f = setup().await;
    submit(&f, 1).await;
    let original = revision(&f).await;
    let first = materialize(
        &f.pool,
        org(),
        "admin-one",
        "source-one",
        "observation-1",
        original,
    )
    .await
    .unwrap();
    submit(&f, 2).await;
    let second = materialize(
        &f.pool,
        org(),
        "admin-one",
        "source-one",
        "observation-2",
        revision(&f).await,
    )
    .await
    .unwrap();
    let superseded: Option<String> = sqlx::query_scalar(
        "SELECT superseded_fact_id FROM issuance_service.evidence_facts WHERE id=$1",
    )
    .bind(&second.fact_id)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(superseded, Some(first.fact_id.clone()));
    materialize(
        &f.pool,
        org(),
        "admin-one",
        "source-one",
        "observation-1",
        original,
    )
    .await
    .unwrap();
    let current: String =
        sqlx::query_scalar("SELECT fact_id FROM issuance_service.evidence_fact_heads")
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(current, second.fact_id);
    assert_eq!(counts(&f).await, (2, 1, 2));
    f.pool.close().await;
    let f = setup().await;
    submit(&f, 1).await;
    submit(&f, 2).await;
    assert_eq!(
        materialize(
            &f.pool,
            org(),
            "admin-one",
            "source-one",
            "observation-1",
            revision(&f).await
        )
        .await
        .unwrap_err(),
        AdminError::Conflict
    );
    assert_eq!(counts(&f).await, (0, 0, 0));
    f.pool.close().await;
}
#[tokio::test]
async fn current_authority_subject_lifecycle_and_revision_are_required_without_partial_writes() {
    for mutation in ["UPDATE organization_service.members SET status='inactive'", "UPDATE issuance_service.external_observation_bindings SET active=false", "UPDATE issuance_service.applications SET status='approved'", "UPDATE issuance_service.applications SET expires_at=clock_timestamp()-interval '1 second'", "UPDATE issuance_service.applications SET applicant_identifier='different-subject'", "UPDATE issuance_service.applications SET updated_at=updated_at+interval '1 second'", "UPDATE issuance_service.external_observation_bindings SET resource_scope='{\"course_id\":\"different\"}'"] {
        let f=setup().await;submit(&f,1).await;let before=revision(&f).await;
        sqlx::query(mutation).execute(&f.pool).await.unwrap();
        assert!(materialize(&f.pool,org(),"admin-one","source-one","observation-1",before).await.is_err(),"{mutation}");
        assert_eq!(counts(&f).await,(0,0,0));f.pool.close().await;
    }
}
#[tokio::test]
async fn canonical_transaction_rolls_back_fact_head_event_and_application_revision() {
    let f = setup().await;
    submit(&f, 1).await;
    let before = revision(&f).await;
    sqlx::raw_sql("CREATE FUNCTION observation_test.fail_materialization() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic audit failure'; END $$; CREATE TRIGGER fail_materialization BEFORE INSERT ON issuance_service.issuance_events FOR EACH ROW EXECUTE FUNCTION observation_test.fail_materialization();").execute(&f.pool).await.unwrap();
    assert_eq!(
        materialize(
            &f.pool,
            org(),
            "admin-one",
            "source-one",
            "observation-1",
            before
        )
        .await
        .unwrap_err(),
        AdminError::Unavailable
    );
    assert_eq!(counts(&f).await, (0, 0, 0));
    assert_eq!(revision(&f).await, before);
    assert_eq!(
        inspect_materialization(&f.pool, org(), "admin-one", "source-one", "observation-1")
            .await
            .unwrap()["found"],
        false
    );
    f.pool.close().await;
}
#[tokio::test]
async fn source_and_tenant_cannot_be_substituted_and_reads_require_current_authority() {
    let f = setup().await;
    submit(&f, 1).await;
    let before = revision(&f).await;
    assert_eq!(
        materialize(
            &f.pool,
            org(),
            "admin-one",
            "other-source",
            "observation-1",
            before
        )
        .await
        .unwrap_err(),
        AdminError::Conflict
    );
    assert_eq!(
        materialize(
            &f.pool,
            Uuid::new_v4(),
            "admin-one",
            "source-one",
            "observation-1",
            before
        )
        .await
        .unwrap_err(),
        AdminError::NotAuthorized
    );
    materialize(
        &f.pool,
        org(),
        "admin-one",
        "source-one",
        "observation-1",
        before,
    )
    .await
    .unwrap();
    assert_eq!(
        inspect_materialization(&f.pool, org(), "admin-one", "other-source", "observation-1")
            .await
            .unwrap()["found"],
        false
    );
    sqlx::query("DELETE FROM organization_service.role_permissions")
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        inspect_materialization(&f.pool, org(), "admin-one", "source-one", "observation-1")
            .await
            .unwrap_err(),
        AdminError::NotAuthorized
    );
    f.pool.close().await;
}
#[tokio::test]
async fn verified_head_is_never_overwritten_by_unsigned_materialization() {
    let f = setup().await;
    submit(&f, 1).await;
    materialize(
        &f.pool,
        org(),
        "admin-one",
        "source-one",
        "observation-1",
        revision(&f).await,
    )
    .await
    .unwrap();
    sqlx::query(
        "UPDATE issuance_service.evidence_facts SET verification='{\"status\":\"VERIFIED\"}'",
    )
    .execute(&f.pool)
    .await
    .unwrap();
    submit(&f, 2).await;
    let before = revision(&f).await;
    assert_eq!(
        materialize(
            &f.pool,
            org(),
            "admin-one",
            "source-one",
            "observation-2",
            before
        )
        .await
        .unwrap_err(),
        AdminError::Conflict
    );
    assert_eq!(counts(&f).await, (1, 1, 1));
    assert_eq!(revision(&f).await, before);
    f.pool.close().await;
}
#[tokio::test]
async fn concurrent_same_receipt_has_one_committed_fact_and_original_intent_reconciles() {
    let f = setup().await;
    submit(&f, 1).await;
    let before = revision(&f).await;
    let (a, b) = tokio::join!(
        materialize(
            &f.pool,
            org(),
            "admin-one",
            "source-one",
            "observation-1",
            before
        ),
        materialize(
            &f.pool,
            org(),
            "admin-one",
            "source-one",
            "observation-1",
            before
        )
    );
    assert!(a.is_ok() || b.is_ok());
    assert_eq!(counts(&f).await, (1, 1, 1));
    let original = materialize(
        &f.pool,
        org(),
        "admin-one",
        "source-one",
        "observation-1",
        before,
    )
    .await
    .unwrap();
    assert!(original.replayed);
    f.pool.close().await;
}

#[tokio::test]
async fn expiry_crossing_during_event_and_staged_authority_or_output_changes_roll_back() {
    for action in [
        "PERFORM pg_sleep(1.5);",
        "DELETE FROM organization_service.role_permissions;",
        "UPDATE issuance_service.evidence_facts SET verification='{\"status\":\"VERIFIED\"}';",
        "UPDATE issuance_service.external_observation_bindings SET active=false;",
    ] {
        let f = setup().await;
        submit(&f, 1).await;
        if action.starts_with("PERFORM") {
            sqlx::query("UPDATE issuance_service.applications SET expires_at=clock_timestamp()+interval '1 second'").execute(&f.pool).await.unwrap();
        }
        let before = revision(&f).await;
        // action is selected exclusively from the four fixed SQL literals above.
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE FUNCTION observation_test.alter_materialization() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN {action} RETURN NEW; END $$; CREATE TRIGGER alter_materialization BEFORE INSERT ON issuance_service.issuance_events FOR EACH ROW EXECUTE FUNCTION observation_test.alter_materialization();"))).execute(&f.pool).await.unwrap();
        assert!(materialize(
            &f.pool,
            org(),
            "admin-one",
            "source-one",
            "observation-1",
            before
        )
        .await
        .is_err());
        assert_eq!(counts(&f).await, (0, 0, 0));
        assert_eq!(revision(&f).await, before);
        f.pool.close().await;
    }
}
#[tokio::test]
async fn inconsistent_persisted_envelope_or_admission_audit_never_becomes_a_fact() {
    for mutation in ["UPDATE issuance_service.external_observation_receipts SET envelope=jsonb_set(envelope,'{effective_at_ms}',to_jsonb((envelope->>'observed_at_ms')::bigint+1))", "UPDATE issuance_service.external_observation_audit SET received_at_ms=received_at_ms+1"] {
        let f=setup().await;submit(&f,1).await;let before=revision(&f).await;
        // Deliberate administrator-only corruption fixture. Runtime cannot bypass
        // journal immutability. Decoder must nevertheless fail closed.
        sqlx::raw_sql("ALTER TABLE issuance_service.external_observation_receipts DISABLE TRIGGER USER; ALTER TABLE issuance_service.external_observation_audit DISABLE TRIGGER USER;").execute(&f.pool).await.unwrap();
        sqlx::query(mutation).execute(&f.pool).await.unwrap();
        assert_eq!(materialize(&f.pool,org(),"admin-one","source-one","observation-1",before).await.unwrap_err(),AdminError::Unavailable);
        assert_eq!(counts(&f).await,(0,0,0));assert_eq!(revision(&f).await,before);f.pool.close().await;
    }
}
#[tokio::test]
async fn public_materialization_requires_trusted_session_context_and_strict_original_body() {
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    let f = setup().await;
    submit(&f, 1).await;
    let service = "synthetic-gateway-service-key-for-materialization";
    let router = crate::external_observation_admin_http::materialization_router(
        f.pool.clone(),
        service.as_bytes(),
    )
    .unwrap();
    let request = |action: &str, body: String| {
        Request::builder()
            .method("POST")
            .uri(format!(
                "/v1/organizations/{ORG}/external-observation-receipts/observation-1/{action}"
            ))
            .header("x-api-key", service)
            .header("x-user-id", "admin-one")
            .header("x-organization-id", ORG)
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap()
    };
    let valid =
        json!({"source_id":"source-one","expected_application_revision":revision(&f).await})
            .to_string();
    let mut producer = request("materialize", valid.clone());
    producer
        .headers_mut()
        .insert("x-api-key-id", KEY.parse().unwrap());
    assert_eq!(
        router.clone().oneshot(producer).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    for body in [r#"{"source_id":"source-one","source_id":"source-one","expected_application_revision":1}"#.to_string(),r#"{"source_id":"source-one","expected_application_revision":1,"verification":{"status":"VERIFIED"}}"#.to_string(),r#"{"source_id":"source-one","expected_application_revision":0}"#.to_string()] {
        assert_eq!(router.clone().oneshot(request("materialize",body)).await.unwrap().status(),StatusCode::BAD_REQUEST);
    }
    let response = router
        .clone()
        .oneshot(request("materialize", valid))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let result: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(result["replayed"], false);
    let response = router
        .oneshot(request(
            "materialization",
            r#"{"source_id":"source-one"}"#.into(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(counts(&f).await, (1, 1, 1));
    f.pool.close().await;
}
