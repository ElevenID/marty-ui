// SPDX-License-Identifier: AGPL-3.0-only
// Explicit disposable-database harness only; never a default service unit test.
use axum::{
    body::{to_bytes, Body},
    extract::Request,
    http::StatusCode,
    Router,
};
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use std::time::Duration;
use tower::ServiceExt;
use uuid::Uuid;
const KEY: &str = "synthetic-gateway-service-key-000000000001";
#[tokio::test]
async fn actual_rust_router_and_restricted_postgres_preserve_original_receipts_and_current_revocation(
) {
    assert_eq!(
        std::env::var("APPLICATION_OWNERSHIP_CONTRACT_TEST").as_deref(),
        Ok("synthetic-local-only")
    );
    let port: u16 = std::env::var("APPLICATION_OWNERSHIP_TEST_PORT")
        .unwrap()
        .parse()
        .unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&format!(
            "postgresql://ownership_runtime:synthetic-runtime-only@127.0.0.1:{port}/postgres"
        ))
        .await
        .unwrap();
    let role: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(role, "ownership_runtime");
    crate::application_ownership_startup::verify_storage(&pool)
        .await
        .unwrap();
    assert!(
        crate::application_ownership_startup::prepare_router(&pool, false, None)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        crate::application_ownership_startup::prepare_router(&pool, true, None)
            .await
            .is_err()
    );
    let owner = PgPoolOptions::new()
        .max_connections(1)
        .connect(&format!(
            "postgresql://postgres:synthetic-only@127.0.0.1:{port}/postgres"
        ))
        .await
        .unwrap();
    sqlx::raw_sql("CREATE ROLE ownership_hidden NOLOGIN NOINHERIT;
        GRANT UPDATE(actor_id) ON issuance_service.application_ownership_operations TO ownership_hidden;
        GRANT ownership_hidden TO ownership_runtime WITH INHERIT FALSE;")
        .execute(&owner).await.unwrap();
    assert!(crate::application_ownership_startup::verify_storage(&pool)
        .await
        .is_err());
    sqlx::raw_sql("REVOKE ownership_hidden FROM ownership_runtime;
        REVOKE UPDATE(actor_id) ON issuance_service.application_ownership_operations FROM ownership_hidden;
        DROP ROLE ownership_hidden;").execute(&owner).await.unwrap();
    sqlx::query("DELETE FROM issuance_service.rust_schema_migrations WHERE version='0016_application_ownership'")
        .execute(&owner).await.unwrap();
    assert!(crate::application_ownership_startup::verify_storage(&pool)
        .await
        .is_err());
    sqlx::query(
        "INSERT INTO issuance_service.rust_schema_migrations VALUES('0016_application_ownership')",
    )
    .execute(&owner)
    .await
    .unwrap();
    crate::application_ownership_startup::verify_storage(&pool)
        .await
        .unwrap();
    let shadow = PgPoolOptions::new()
        .max_connections(1)
        .after_connect(|connection, _| {
            Box::pin(async move {
                sqlx::query("SET ROLE ownership_runtime")
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect(&format!(
            "postgresql://postgres:synthetic-only@127.0.0.1:{port}/postgres"
        ))
        .await
        .unwrap();
    assert!(
        crate::application_ownership_startup::verify_storage(&shadow)
            .await
            .is_err()
    );
    shadow.close().await;
    sqlx::query("GRANT pg_execute_server_program TO ownership_runtime WITH INHERIT FALSE")
        .execute(&owner)
        .await
        .unwrap();
    assert!(crate::application_ownership_startup::verify_storage(&pool)
        .await
        .is_err());
    sqlx::query("REVOKE pg_execute_server_program FROM ownership_runtime")
        .execute(&owner)
        .await
        .unwrap();
    sqlx::query("GRANT SET ON PARAMETER session_replication_role TO ownership_runtime")
        .execute(&owner)
        .await
        .unwrap();
    assert!(crate::application_ownership_startup::verify_storage(&pool)
        .await
        .is_err());
    let replica = PgPoolOptions::new()
        .max_connections(1)
        .after_connect(|connection, _| {
            Box::pin(async move {
                sqlx::query("SET session_replication_role=replica")
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect(&format!(
            "postgresql://ownership_runtime:synthetic-runtime-only@127.0.0.1:{port}/postgres"
        ))
        .await
        .unwrap();
    sqlx::query("REVOKE SET ON PARAMETER session_replication_role FROM ownership_runtime")
        .execute(&owner)
        .await
        .unwrap();
    assert!(
        crate::application_ownership_startup::verify_storage(&replica)
            .await
            .is_err()
    );
    replica.close().await;
    crate::application_ownership_startup::verify_storage(&pool)
        .await
        .unwrap();
    owner.close().await;
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SET TRANSACTION READ ONLY")
        .execute(&mut *tx)
        .await
        .unwrap();
    crate::application_ownership_schema::validate(&mut tx)
        .await
        .unwrap();
    tx.rollback().await.unwrap();
    let revision:i64=sqlx::query_scalar("SELECT (extract(epoch FROM updated_at)*1000000)::bigint FROM issuance_service.applications WHERE id='rust-application'")
        .fetch_one(&pool).await.unwrap();
    let router = crate::application_ownership_startup::prepare_router(&pool, true, Some(KEY))
        .await
        .unwrap()
        .unwrap();
    async fn call(
        router: Router,
        actor: &str,
        action: &str,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let org = "10000000-0000-4000-8000-000000000001";
        let path =
            format!("/v1/organizations/{org}/application-ownerships/rust-application/{action}");
        let public = Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        // Exact production Gateway guard; identity-provider authentication is
        // outside this local composition and is not claimed by this fixture.
        let mut request =
            crate::gateway_ownership_guard::admit_admin(public, true, Some(org), actor, true)
                .await
                .unwrap();
        request
            .headers_mut()
            .insert("x-api-key", KEY.parse().unwrap());
        request
            .headers_mut()
            .insert("x-organization-id", org.parse().unwrap());
        request
            .headers_mut()
            .insert("x-user-id", actor.parse().unwrap());
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }
    let propose = Uuid::new_v4();
    let confirm = Uuid::new_v4();
    let proposed = json!({"operation_id":propose,"expected_revision":0,"expected_application_revision":revision,"user_id":"learner-one"});
    assert_eq!(
        call(router.clone(), "admin-one", "propose", proposed)
            .await
            .0,
        StatusCode::OK
    );
    let intent = json!({"operation_id":confirm,"expected_revision":1,"expected_application_revision":revision});
    assert_eq!(
        call(router.clone(), "other-learner", "confirm", intent.clone())
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let (status, receipt) = call(router.clone(), "learner-one", "confirm", intent.clone()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(receipt["status"], "confirmed");
    // Treat the successful command's reply as lost; receipt reconciliation
    // must preserve it without another write or regenerated operation.
    let (status, recovered) = call(
        router.clone(),
        "learner-one",
        "receipt",
        json!({"operation_id":confirm}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(recovered["receipt"], receipt);
    assert_eq!(
        call(router.clone(), "learner-one", "confirm", intent)
            .await
            .1,
        receipt
    );
    let (_, current) = call(router.clone(), "learner-one", "inspect", json!({})).await;
    assert_eq!(current["record"]["current"], true);
    let revoked = json!({"operation_id":Uuid::new_v4(),"expected_revision":2,"expected_application_revision":revision});
    assert_eq!(
        call(router.clone(), "admin-one", "revoke", revoked).await.0,
        StatusCode::OK
    );
    let (_, current) = call(router.clone(), "learner-one", "inspect", json!({})).await;
    assert_eq!(current["record"]["current"], false);
    assert_eq!(current["record"]["status"], "revoked");
    let (_, history) = call(
        router,
        "learner-one",
        "receipt",
        json!({"operation_id":confirm}),
    )
    .await;
    assert_eq!(history["receipt"], receipt);
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM issuance_service.application_ownership_operations WHERE application_id='rust-application'")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(count, 3);
    pool.close().await;
}
