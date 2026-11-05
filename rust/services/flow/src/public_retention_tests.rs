//! Destructive storage qualification uses only a fresh task-owned local DB.
use super::tests::{setup_with_key, OpaqueSigner, ORG};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{Duration, Utc};
use serde_json::json;
use std::{str::FromStr, sync::Arc};
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires a fresh task-owned loopback marty_public_verification_test PostgreSQL"]
async fn public_retention_postgres_erases_payloads_preserves_quota_and_replay_receipts() {
    let url =
        std::env::var("FLOW_PUBLIC_VERIFICATION_TEST_URL").expect("disposable DB URL required");
    let options = sqlx::postgres::PgConnectOptions::from_str(&url).unwrap();
    assert!(matches!(options.get_host(), "127.0.0.1" | "localhost"));
    assert_eq!(
        options.get_database(),
        Some("marty_public_verification_test")
    );
    let pool = sqlx::PgPool::connect_with(options.clone()).await.unwrap();
    sqlx::raw_sql("CREATE SCHEMA deployment_profile_service; CREATE TABLE deployment_profile_service.deployment_profiles (id text PRIMARY KEY, enabled_flow_ids jsonb NOT NULL DEFAULT '[]'::jsonb)").execute(&pool).await.unwrap();
    sqlx::query("CREATE ROLE marty NOLOGIN")
        .execute(&pool)
        .await
        .unwrap();
    crate::migrate_flow_schema(&pool).await.unwrap();
    crate::migrate_flow_schema(&pool).await.unwrap();
    crate::validate_flow_schema(&pool).await.unwrap();
    let repository = crate::PostgresFlowRepository::new(pool.clone());
    let grants:(bool,bool,bool,bool)=sqlx::query_as("SELECT has_table_privilege('marty','flow_service.public_verification_receipts','SELECT'),has_table_privilege('marty','flow_service.public_verification_receipts','INSERT'),has_table_privilege('marty','flow_service.public_verification_receipts','DELETE'),has_table_privilege('marty','flow_service.public_verification_receipts','UPDATE,TRUNCATE,TRIGGER')").fetch_one(&pool).await.unwrap();
    assert_eq!(grants, (true, true, true, false));
    sqlx::raw_sql("GRANT USAGE ON SCHEMA flow_service TO marty; GRANT SELECT,INSERT,UPDATE,DELETE ON flow_service.flow_instances TO marty; GRANT SELECT,DELETE ON flow_service.flow_nonce_consumptions TO marty").execute(&pool).await.unwrap();
    let app_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .after_connect(|connection, _| {
            Box::pin(async move {
                sqlx::query("SET ROLE marty").execute(connection).await?;
                Ok(())
            })
        })
        .connect_with(options)
        .await
        .unwrap();
    let sweeper = crate::PostgresFlowRepository::new(app_pool.clone());
    let limits: crate::PublicVerificationLimits = serde_json::from_value(
        json!({"starts_per_minute":100,"starts_per_day":3,"maximum_active":100}),
    )
    .unwrap();
    let mut instances = Vec::new();
    for seed in 1..=3 {
        let (_, mut instance, _, _, _) =
            setup_with_key(Arc::new(OpaqueSigner::new()), None, seed).await;
        instance.expires_at = instance
            .expires_at
            .map(|v| chrono::DateTime::from_timestamp_micros(v.timestamp_micros()).unwrap());
        instance.context["sensitive_fixture"] = json!("synthetic-holder-data-must-be-erased");
        assert!(repository
            .save_public_verification_start(&instance, limits)
            .await
            .unwrap());
        let (delete_after,receipt_after,created):(chrono::DateTime<Utc>,chrono::DateTime<Utc>,chrono::DateTime<Utc>)=sqlx::query_as("SELECT payload_delete_after,receipt_delete_after,created_at FROM flow_service.public_verification_receipts WHERE instance_id=$1").bind(&instance.id).fetch_one(&pool).await.unwrap();
        assert_eq!(
            delete_after,
            instance.expires_at.unwrap() + Duration::seconds(600)
        );
        assert_eq!(
            receipt_after - created,
            Duration::days(i64::from(crate::PUBLIC_VERIFICATION_RECEIPT_DAYS))
        );
        let receipt:serde_json::Value=sqlx::query_scalar("SELECT to_jsonb(receipt) FROM flow_service.public_verification_receipts AS receipt WHERE instance_id=$1").bind(&instance.id).fetch_one(&pool).await.unwrap();
        assert_eq!(receipt.as_object().unwrap().len(), 5);
        assert!(
            !receipt.to_string().contains("synthetic-holder-data")
                && !receipt.to_string().contains("key_hash")
        );
        instances.push(instance);
    }
    // An ordinary record, even with a similar private marker, is not a public
    // insertion receipt and cannot be swept. Tenant configuration is untouched.
    let (_, mut ordinary, _, _, _) = setup_with_key(Arc::new(OpaqueSigner::new()), None, 9).await;
    ordinary.organization_id = "another-tenant".into();
    ordinary.context["sensitive_fixture"] = json!("unrelated-data-to-preserve");
    assert!(repository
        .save_started_instance(&ordinary, None)
        .await
        .unwrap());
    let before = sweeper
        .sweep_public_verification_retention(100)
        .await
        .unwrap();
    assert_eq!(before, crate::PublicVerificationRetentionSweep::default());

    // Advance only these fixture sessions' complete retention clocks. No shared
    // database resets or caller-controlled clock arguments exist in production.
    for instance in &instances[1..] {
        let mut expired = instance.clone();
        expired.created_at -= Duration::minutes(21);
        expired.updated_at -= Duration::minutes(21);
        expired.started_at = expired.started_at.map(|v| v - Duration::minutes(21));
        expired.expires_at = expired.expires_at.map(|v| v - Duration::minutes(21));
        // The receipt is the janitor's authority; mutation of generic context
        // neither creates nor extends it.
        repository.save_instance(&expired).await.unwrap();
        sqlx::query("UPDATE flow_service.public_verification_receipts SET created_at=created_at-INTERVAL '21 minutes', payload_delete_after=payload_delete_after-INTERVAL '21 minutes', receipt_delete_after=receipt_delete_after-INTERVAL '21 minutes' WHERE instance_id=$1").bind(&instance.id).execute(&pool).await.unwrap();
    }
    let artifact_id = Uuid::new_v4().to_string();
    let callback_id = Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO flow_service.flow_instance_artifacts (id,flow_instance_id,status,wallet_metadata,qr_payload) VALUES ($1,$2,'pending',$3,'synthetic-private-offer')").bind(&artifact_id).bind(&instances[1].id).bind(json!({"private":"synthetic-wallet-data"})).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO flow_service.flow_callback_outbox (event_id,flow_instance_id,organization_id,destination_url,audience,event_type,payload,next_attempt_at,expires_at) VALUES ($1,$2,$3,'https://example.invalid/test','fixture','fixture',$4,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP+INTERVAL '1 hour')").bind(&callback_id).bind(&instances[1].id).bind(ORG).bind(json!({"private":"synthetic-callback-data"})).execute(&pool).await.unwrap();
    for (index, instance) in instances[1..].iter().enumerate() {
        sqlx::query("INSERT INTO flow_service.flow_nonce_consumptions (nonce_digest,flow_instance_id,expires_at) VALUES ($1,$2,$3)").bind(format!("{:064x}",index+1)).bind(&instance.id).bind(if index==0 {Utc::now()-Duration::seconds(1)}else{Utc::now()+Duration::minutes(1)}).execute(&pool).await.unwrap();
    }
    sqlx::query("INSERT INTO flow_service.flow_nonce_consumptions (nonce_digest,flow_instance_id,expires_at) VALUES ($1,$2,CURRENT_TIMESTAMP-INTERVAL '1 day')").bind("f".repeat(64)).bind(&ordinary.id).execute(&pool).await.unwrap();
    let (a, b) = tokio::join!(
        sweeper.sweep_public_verification_retention(1),
        sweeper.sweep_public_verification_retention(1)
    );
    let a = a.unwrap();
    let b = b.unwrap();
    assert_eq!(a.sessions + b.sessions, 2);
    assert_eq!(a.nonces + b.nonces, 1);
    assert_eq!(a.receipts + b.receipts, 0);
    for instance in &instances[1..] {
        assert!(repository.instance(&instance.id).await.unwrap().is_none());
        assert!(repository
            .public_verification_receipt_exists(&instance.id)
            .await
            .unwrap());
        assert!(!repository
            .save_public_verification_start(instance, limits)
            .await
            .unwrap());
    }
    assert!(repository
        .instance(&instances[0].id)
        .await
        .unwrap()
        .is_some());
    assert_eq!(
        repository
            .instance(&ordinary.id)
            .await
            .unwrap()
            .unwrap()
            .context["sensitive_fixture"],
        "unrelated-data-to-preserve"
    );
    let children:i64=sqlx::query_scalar("SELECT (SELECT COUNT(*) FROM flow_service.flow_instance_artifacts WHERE id=$1)+(SELECT COUNT(*) FROM flow_service.flow_callback_outbox WHERE event_id=$2)").bind(&artifact_id).bind(&callback_id).fetch_one(&pool).await.unwrap();
    assert_eq!(children, 0);
    let (_, extra, _, _, _) = setup_with_key(Arc::new(OpaqueSigner::new()), None, 5).await;
    assert!(
        matches!(
            repository
                .save_public_verification_start(&extra, limits)
                .await,
            Err(crate::RepositoryError::PublicVerificationCapacityExceeded)
        ),
        "deletion must not reset the daily quota"
    );

    // A removed payload's original capability must not become a new launch.
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    let mut definition=crate::create_definition_record(crate::parse_request(json!({"organization_id":ORG,"name":"Retention fixture","flow_type":"oid4vp_presentation","presentation_policy_id":"policy"})).unwrap(),Utc::now()).unwrap();
    definition.status = crate::DefinitionStatus::Active;
    repository.save_definition(&definition).await.unwrap();
    let configuration = json!({"principal_id":"operator","issuer_did":"did:web:demo.example:verifier","limits":{"starts_per_minute":100,"starts_per_day":100,"maximum_active":100},"catalog":{"organization_id":ORG,"application_origin":"https://demo.example","notice":"Use fictional data.","scenarios":[{"id":"age","label":"Age","choices":[{"id":"over-18","label":"18 or older","definition":{"organization_id":ORG,"definition_id":definition.id,"version":definition.version},"presentation_policy_id":"policy","policy_configuration_digest":format!("sha256:{}","a".repeat(64))}]}]}});
    let catalog =
        crate::PublicVerificationCatalog::from_json(&configuration["catalog"].to_string(), false)
            .unwrap();
    let router = crate::flow_read_router(crate::FlowHttpState {
        service_authenticator: None,
        repository: repository.clone(),
        providers: Arc::new(crate::FlowProviderRegistry::default()),
        public_base_url: "https://demo.example".into(),
        verification: crate::FlowHttpVerificationOptions {
            public_verification: Some(
                crate::PublicVerificationOptions::from_json(&configuration.to_string(), false)
                    .unwrap(),
            ),
            ..Default::default()
        },
        application_approval: Default::default(),
    });
    let response=router.oneshot(Request::builder().method("POST").uri("/v1/flows/public/verification/sessions").header("origin","https://demo.example").header("x-verification-session",URL_SAFE_NO_PAD.encode([2;32])).header("content-type","application/json").body(Body::from(json!({"catalog_revision":catalog.public_view().revision,"scenario_id":"age","choice_id":"over-18","consent":true}).to_string())).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    // Age the expired minimal receipts to their own fixed 30-day deadline.
    sqlx::query("UPDATE flow_service.public_verification_receipts SET created_at=created_at-INTERVAL '720 hours',payload_delete_after=payload_delete_after-INTERVAL '720 hours',receipt_delete_after=receipt_delete_after-INTERVAL '720 hours' WHERE instance_id IN ($1,$2)").bind(&instances[1].id).bind(&instances[2].id).execute(&pool).await.unwrap();
    sqlx::query("UPDATE flow_service.flow_nonce_consumptions SET expires_at=CURRENT_TIMESTAMP-INTERVAL '1 second' WHERE flow_instance_id=$1").bind(&instances[2].id).execute(&pool).await.unwrap();
    let purged = sweeper
        .sweep_public_verification_retention(100)
        .await
        .unwrap();
    assert_eq!(purged.nonces, 1);
    assert_eq!(purged.receipts, 2);
    assert!(!repository
        .public_verification_receipt_exists(&instances[1].id)
        .await
        .unwrap());
    let ordinary_nonce: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM flow_service.flow_nonce_consumptions WHERE flow_instance_id=$1",
    )
    .bind(&ordinary.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(ordinary_nonce, 1);
    assert!(repository
        .save_public_verification_start(&extra, limits)
        .await
        .unwrap());
    assert!(sweeper
        .sweep_public_verification_retention(0)
        .await
        .is_err());
    app_pool.close().await;
    pool.close().await;
}
