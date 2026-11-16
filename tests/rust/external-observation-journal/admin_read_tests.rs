// SPDX-License-Identifier: AGPL-3.0-only
use crate::external_observation_admin::AdminError;
use crate::external_observation_admin_read::{
    inspect, AdminRead, AuditCursor, GrantPage, ResourceKind,
};
use uuid::Uuid;
const ORG: &str = "20000000-0000-4000-8000-000000000001";
const KEY: &str = "10000000-0000-4000-8000-000000000001";
const GRANT: &str = "30000000-0000-4000-8000-000000000001";
fn id(v: &str) -> Uuid {
    Uuid::parse_str(v).unwrap()
}
fn grant(page: GrantPage) -> AdminRead {
    AdminRead::Grant {
        grant: id(GRANT),
        page,
    }
}
fn first() -> GrantPage {
    GrantPage {
        after_binding_id: None,
        expected_revision: None,
    }
}
fn receipt(source: &str) -> AdminRead {
    AdminRead::Receipt {
        source: source.into(),
        observation: "observation-one".into(),
    }
}
async fn submit(f: &super::Fixture) {
    let journal = crate::external_observation_postgres::PostgresObservationJournal::new(
        f.pool.clone(),
        std::sync::Arc::new(
            crate::external_observation_authority_postgres::PostgresObservationAuthority,
        ),
    );
    journal
        .submit(
            &crate::external_observation_postgres::ProducerIdentity {
                api_key_id: KEY.into(),
                organization_id: ORG.into(),
            },
            &f.input(),
            "observation-one",
        )
        .await
        .unwrap();
}
async fn counts(pool: &sqlx::PgPool) -> (i64, i64, i64, i64) {
    sqlx::query_as("SELECT (SELECT revision FROM issuance_service.external_observation_producer_grants WHERE id='30000000-0000-4000-8000-000000000001'),(SELECT count(*) FROM organization_service.audit_events),(SELECT count(*) FROM issuance_service.external_observation_receipts),(SELECT count(*) FROM issuance_service.external_observation_audit)").fetch_one(pool).await.unwrap()
}
#[tokio::test]
async fn authorized_snapshots_do_not_change_authority_or_audit_and_do_not_return_secrets() {
    let f = super::admin_tests::setup().await;
    let before = counts(&f.pool).await;
    let g = inspect(&f.pool, id(ORG), "admin-one", grant(first()))
        .await
        .unwrap();
    assert_eq!(g["found"], true);
    assert_eq!(g["record"]["revision"], 2);
    assert_eq!(g["record"]["bindings"], serde_json::json!(["binding-one"]));
    assert!(g["snapshot_at_ms"].as_i64().unwrap() > 0);
    assert!(g["record"].get("secret").is_none());
    let b = inspect(
        &f.pool,
        id(ORG),
        "admin-one",
        AdminRead::Binding {
            binding: "binding-one".into(),
        },
    )
    .await
    .unwrap();
    assert_eq!(b["record"]["subject_id"], "learner-one");
    assert_eq!(
        b["record"]["application_revision"],
        super::binding_admin_tests::app_revision(&f.pool).await
    );
    assert!(b["record"].get("metadata").is_none());
    assert_eq!(counts(&f.pool).await, before);
    f.pool.close().await;
}
#[tokio::test]
async fn absence_is_snapshot_only_and_later_commit_appears_under_same_identity() {
    let f = super::admin_tests::setup().await;
    let missing = inspect(&f.pool, id(ORG), "admin-one", receipt("source-one"))
        .await
        .unwrap();
    assert_eq!(missing["found"], false);
    assert!(missing["record"].is_null());
    assert!(missing.get("retry_allowed").is_none());
    submit(&f).await;
    let committed = inspect(&f.pool, id(ORG), "admin-one", receipt("source-one"))
        .await
        .unwrap();
    assert_eq!(committed["found"], true);
    assert_eq!(committed["record"]["kind"], "unsigned_producer_attestation");
    assert_eq!(committed["record"]["sequence"], 1);
    assert_eq!(
        committed["record"]["envelope"]["observation_id"],
        "observation-one"
    );
    assert_eq!(committed["record"]["head_sequence"], 1);
    let repeat = inspect(&f.pool, id(ORG), "admin-one", receipt("source-one"))
        .await
        .unwrap();
    assert_eq!(committed["record"], repeat["record"]);
    assert_eq!(counts(&f.pool).await, (2, 0, 1, 1));
    f.pool.close().await;
}
#[tokio::test]
async fn administrator_reconciles_original_receipt_after_producer_revocation_without_cross_source_leak(
) {
    let f = super::admin_tests::setup().await;
    submit(&f).await;
    crate::external_observation_admin::revoke_grant(&f.pool, id(ORG), "admin-one", id(GRANT), 2)
        .await
        .unwrap();
    sqlx::query("UPDATE organization_service.api_keys SET status='revoked',enabled=false,scopes=ARRAY[]::text[]").execute(&f.pool).await.unwrap();
    let value = inspect(&f.pool, id(ORG), "admin-one", receipt("source-one"))
        .await
        .unwrap();
    assert_eq!(value["found"], true);
    assert_eq!(value["record"]["api_key_id"], KEY);
    assert_eq!(value["record"]["envelope"]["binding_revision"], 1);
    assert_eq!(
        inspect(&f.pool, id(ORG), "admin-one", receipt("other-source"))
            .await
            .unwrap()["found"],
        false
    );
    assert_eq!(
        inspect(&f.pool, Uuid::new_v4(), "admin-one", receipt("source-one"))
            .await
            .unwrap_err(),
        AdminError::NotAuthorized
    );
    assert_eq!(
        inspect(&f.pool, id(ORG), "producer", receipt("source-one"))
            .await
            .unwrap_err(),
        AdminError::NotAuthorized
    );
    assert_eq!(counts(&f.pool).await, (3, 1, 1, 1));
    f.pool.close().await;
}
#[tokio::test]
async fn inconsistent_receipt_audit_and_missing_storage_are_errors_never_absence() {
    let f = super::admin_tests::setup().await;
    submit(&f).await;
    sqlx::query(
        "UPDATE issuance_service.external_observation_audit SET received_at_ms=received_at_ms+1",
    )
    .execute(&f.pool)
    .await
    .unwrap();
    assert_eq!(
        inspect(&f.pool, id(ORG), "admin-one", receipt("source-one"))
            .await
            .unwrap_err(),
        AdminError::Unavailable
    );
    sqlx::query(
        "UPDATE issuance_service.external_observation_audit SET received_at_ms=received_at_ms-1",
    )
    .execute(&f.pool)
    .await
    .unwrap();
    sqlx::raw_sql("ALTER TABLE issuance_service.external_observation_receipts DROP CONSTRAINT external_observation_requires_audit; DELETE FROM issuance_service.external_observation_audit;").execute(&f.pool).await.unwrap();
    assert_eq!(
        inspect(&f.pool, id(ORG), "admin-one", receipt("source-one"))
            .await
            .unwrap_err(),
        AdminError::Unavailable
    );
    sqlx::query("ALTER TABLE issuance_service.external_observation_receipts RENAME TO synthetic_unavailable_receipts").execute(&f.pool).await.unwrap();
    assert_eq!(
        inspect(&f.pool, id(ORG), "admin-one", receipt("source-one"))
            .await
            .unwrap_err(),
        AdminError::Unavailable
    );
    f.pool.close().await;
}
#[tokio::test]
async fn grant_membership_pages_are_bounded_and_revision_fenced() {
    let f = super::admin_tests::setup().await;
    for n in 0..33 {
        let name = format!("binding-{n:02}");
        sqlx::query("INSERT INTO issuance_service.external_observation_bindings(id,organization_id,source_id,application_id,subject_id,provider,fact_type,resource_scope,claim_rules,max_age_ms,max_clock_skew_ms,active,created_by,updated_by) SELECT $1,organization_id,source_id,application_id,subject_id,provider,fact_type,resource_scope,claim_rules,max_age_ms,max_clock_skew_ms,active,created_by,updated_by FROM issuance_service.external_observation_bindings WHERE id='binding-one'").bind(&name).execute(&f.pool).await.unwrap();
        sqlx::query("INSERT INTO issuance_service.external_observation_grant_bindings(grant_id,binding_id,organization_id,source_id) VALUES ($1,$2,$3,'source-one')").bind(id(GRANT)).bind(name).bind(id(ORG)).execute(&f.pool).await.unwrap();
    }
    let a = inspect(&f.pool, id(ORG), "admin-one", grant(first()))
        .await
        .unwrap();
    assert_eq!(a["record"]["bindings"].as_array().unwrap().len(), 32);
    let after = a["next_binding_id"].as_str().unwrap().to_owned();
    let revision = a["record"]["revision"].as_i64().unwrap();
    let b = inspect(
        &f.pool,
        id(ORG),
        "admin-one",
        grant(GrantPage {
            after_binding_id: Some(after.clone()),
            expected_revision: Some(revision),
        }),
    )
    .await
    .unwrap();
    assert_eq!(b["record"]["bindings"].as_array().unwrap().len(), 2);
    assert!(b["next_binding_id"].is_null());
    let mut all = std::collections::BTreeSet::new();
    for page in [&a, &b] {
        for binding in page["record"]["bindings"].as_array().unwrap() {
            assert!(all.insert(binding.as_str().unwrap()));
        }
    }
    assert_eq!(all.len(), 34);
    sqlx::query("UPDATE issuance_service.external_observation_producer_grants SET active=active WHERE id=$1").bind(id(GRANT)).execute(&f.pool).await.unwrap();
    assert_eq!(
        inspect(
            &f.pool,
            id(ORG),
            "admin-one",
            grant(GrantPage {
                after_binding_id: Some(after),
                expected_revision: Some(revision)
            })
        )
        .await
        .unwrap_err(),
        AdminError::Conflict
    );
    f.pool.close().await;
}
#[tokio::test]
async fn audit_pages_use_timestamp_uuid_ties_redact_unknown_fields_and_survive_resource_removal() {
    let f = super::admin_tests::setup().await;
    let mut revision = 2;
    for _ in 0..11 {
        revision = crate::external_observation_admin::revoke_grant(
            &f.pool,
            id(ORG),
            "admin-one",
            id(GRANT),
            revision,
        )
        .await
        .unwrap()
        .revision;
    }
    sqlx::query("UPDATE organization_service.audit_events SET created_at='2026-11-16T00:00:00Z',metadata='{\"synthetic_secret\":\"never-export\"}'::jsonb,changes=changes||'{\"client_secret\":\"never-export\"}'::jsonb").execute(&f.pool).await.unwrap();
    let query = |cursor| AdminRead::Audit {
        kind: ResourceKind::Producer,
        resource: GRANT.into(),
        cursor,
    };
    let a = inspect(&f.pool, id(ORG), "admin-one", query(None))
        .await
        .unwrap();
    assert_eq!(a["events"].as_array().unwrap().len(), 8);
    assert!(!a.to_string().contains("never-export"));
    let cursor = serde_json::from_value::<AuditCursor>(a["next_cursor"].clone()).unwrap();
    let b = inspect(&f.pool, id(ORG), "admin-one", query(Some(cursor)))
        .await
        .unwrap();
    assert_eq!(b["events"].as_array().unwrap().len(), 3);
    assert!(b["next_cursor"].is_null());
    let mut seen = std::collections::BTreeSet::new();
    for page in [&a, &b] {
        for event in page["events"].as_array().unwrap() {
            assert!(seen.insert(event["id"].as_str().unwrap()));
            assert!(event.get("metadata").is_none());
            assert!(event["changes"].get("client_secret").is_none());
        }
    }
    assert_eq!(seen.len(), 11);
    sqlx::query("DELETE FROM issuance_service.external_observation_producer_grants WHERE id=$1")
        .bind(id(GRANT))
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        inspect(&f.pool, id(ORG), "admin-one", query(None))
            .await
            .unwrap()["events"]
            .as_array()
            .unwrap()
            .len(),
        8
    );
    sqlx::query(
        "UPDATE organization_service.audit_events SET changes='{\"revision\":\"invalid\"}'::jsonb",
    )
    .execute(&f.pool)
    .await
    .unwrap();
    assert_eq!(
        inspect(&f.pool, id(ORG), "admin-one", query(None))
            .await
            .unwrap_err(),
        AdminError::Unavailable
    );
    f.pool.close().await;
}
#[tokio::test]
async fn removed_permission_denies_reads_even_for_committed_receipt() {
    let f = super::admin_tests::setup().await;
    submit(&f).await;
    sqlx::query("DELETE FROM organization_service.role_permissions")
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        inspect(&f.pool, id(ORG), "admin-one", receipt("source-one"))
            .await
            .unwrap_err(),
        AdminError::NotAuthorized
    );
    assert_eq!(counts(&f.pool).await, (2, 0, 1, 1));
    f.pool.close().await;
}
#[tokio::test]
async fn mounted_read_queries_require_trusted_administrator_strict_body_and_no_store() {
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    let f = super::admin_tests::setup().await;
    let service = "synthetic-gateway-service-key-for-admin-reads";
    let router = crate::external_observation_startup::prepare_observation_router(
        &f.pool,
        true,
        Some(service),
    )
    .await
    .unwrap()
    .unwrap();
    let request = |tail: &str, body: &str| {
        Request::builder()
            .method("POST")
            .uri(format!("/v1/organizations/{ORG}/{tail}"))
            .header("x-api-key", service)
            .header("x-user-id", "admin-one")
            .header("x-organization-id", ORG)
            .header("content-type", "application/json")
            .body(Body::from(body.to_owned()))
            .unwrap()
    };
    let grant_path = format!("external-observation-producers/{GRANT}/inspect");
    let grant_audit = format!("external-observation-producers/{GRANT}/audit");
    for (tail, body) in [
        (grant_path.as_str(), "{}"),
        (grant_audit.as_str(), "{}"),
        ("external-observation-bindings/binding-one/inspect", "{}"),
        ("external-observation-bindings/binding-one/audit", "{}"),
        (
            "external-observation-receipts/observation-one/inspect",
            r#"{"source_id":"source-one"}"#,
        ),
    ] {
        let mut producer = request(tail, body);
        producer
            .headers_mut()
            .insert("x-api-key-id", KEY.parse().unwrap());
        assert_eq!(
            router.clone().oneshot(producer).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
        let response = router.clone().oneshot(request(tail, body)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "no-store");
        let bytes = to_bytes(response.into_body(), 131072).await.unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(value["snapshot_at_ms"].as_i64().unwrap() > 0);
    }
    for invalid in [
        r#"{"organization_id":"forged"}"#,
        r#"{"after_binding_id":"binding-one"}"#,
        r#"{"expected_revision":2,"expected_revision":2}"#,
    ] {
        assert_eq!(
            router
                .clone()
                .oneshot(request(&grant_path, invalid))
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    for invalid in [
        "{}",
        r#"{"source_id":"source-one","source_id":"other-source"}"#,
        r#"{"source_id":"source-one","api_key_id":"forged"}"#,
    ] {
        assert_eq!(
            router
                .clone()
                .oneshot(request(
                    "external-observation-receipts/observation-one/inspect",
                    invalid
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    let mut wrong_actor = request(&grant_path, "{}");
    wrong_actor
        .headers_mut()
        .insert("x-user-id", "producer-not-admin".parse().unwrap());
    assert_eq!(
        router.clone().oneshot(wrong_actor).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let mut missing_service = request(&grant_path, "{}");
    missing_service.headers_mut().remove("x-api-key");
    assert_eq!(
        router
            .clone()
            .oneshot(missing_service)
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(counts(&f.pool).await, (2, 0, 0, 0));
    f.pool.close().await;
}
