//! The opt-in lifecycle is admitted only after the actual Issuance owner guards
//! are installed, and neither unaware writers nor changed schema can remove it.

use chrono::{DateTime, Utc};
use marty_credential_template::{
    catalog::marty_login_badge,
    migration::{migrate_credential_template_schema, validate_credential_template_schema},
    CredentialFormat, CredentialTemplate, PostgresCredentialTemplateStore, TemplateStatus,
};
use serde_json::{json, Value};
use sqlx::{postgres::PgPoolOptions, PgPool};

const OWNER_MIGRATION: &str =
    include_str!("../../issuance/migrations/0018_verification_prerequisites.sql");
const POLICY_CHECK: &str = "credential_template_service.template_verification_prerequisite_valid(jsonb,text,text,text,jsonb,jsonb,jsonb,text,jsonb,integer)";

fn template() -> CredentialTemplate {
    let now = DateTime::from_timestamp_micros(Utc::now().timestamp_micros()).unwrap();
    let mut template = marty_login_badge(
        now,
        "org-prerequisite-test",
        "https://issuer.example",
        "did:web:issuer.example",
    );
    template.id = "ct-prerequisite-test".into();
    template.name = "Guarded issuance fixture".into();
    template.credential_type = "GuardedCredential".into();
    template.vct = "https://issuer.example/guarded".into();
    template.doctype = None;
    template.status = TemplateStatus::Draft;
    template.credential_payload_format = "SD_JWT_VC".into();
    template.supported_formats = vec![CredentialFormat::SdJwtVc];
    template.issuance_protocol = "OID4VCI_PRE_AUTH".into();
    template.wallet_configs.clear();
    template.application_template_id = None;
    template.jwt_vc_profile = None;
    template.validity_rules.renewable = false;
    template.verification_prerequisite = Some(
        serde_json::from_value(json!({
            "profile": "managed_sd_jwt_dcql_same_holder_v1",
            "flow_definition_id": "flow-prerequisite-test",
            "flow_definition_version": 3,
            "policy": {"id": "policy-prerequisite-test", "version": 7,
                "content_digest": format!("sha256:{}", "a".repeat(64))},
            "verifier_issuer_did": "did:web:verifier.example",
            "ttl_seconds": 300
        }))
        .unwrap(),
    );
    template
}

async fn restore_owner_guards(pool: &PgPool) {
    sqlx::raw_sql(OWNER_MIGRATION)
        .execute(pool)
        .await
        .expect("the checked-in Issuance migration must restore its exact guards");
}

async fn rejected_update(pool: &PgPool, assignment: &'static str) {
    let statement = format!(
        "UPDATE credential_template_service.credential_templates SET {assignment} \
         WHERE id='ct-prerequisite-test'"
    );
    assert!(
        sqlx::query(sqlx::AssertSqlSafe(statement))
            .execute(pool)
            .await
            .is_err(),
        "{assignment}"
    );
}

#[tokio::test]
#[ignore = "requires an explicitly supplied disposable local credential-template prerequisite database"]
async fn prerequisite_postgres_readiness_roundtrip_downgrade_and_schema_tampering() {
    let database_url = std::env::var("CREDENTIAL_TEMPLATE_PREREQUISITE_TEST_URL")
        .expect("set the disposable prerequisite PostgreSQL database URL");
    let url = url::Url::parse(&database_url).unwrap();
    assert!(matches!(
        url.host_str(),
        Some("localhost" | "127.0.0.1" | "[::1]")
    ));
    assert!(url.path().ends_with("_test"));
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&database_url)
        .await
        .unwrap();
    sqlx::raw_sql(
        "DROP SCHEMA IF EXISTS credential_template_service CASCADE; \
         DROP SCHEMA IF EXISTS issuance_service CASCADE;",
    )
    .execute(&pool)
    .await
    .unwrap();
    migrate_credential_template_schema(&pool).await.unwrap();
    validate_credential_template_schema(&pool).await.unwrap();
    let store = PostgresCredentialTemplateStore::new(pool.clone());
    let mut guarded = template();

    // Existing unconfigured templates keep their original lifecycle. New
    // opt-in drafts cannot be persisted before Issuance has the required guard.
    let mut legacy = guarded.clone();
    legacy.id = "ct-legacy-test".into();
    legacy.verification_prerequisite = None;
    store.save_template(&legacy).await.unwrap();
    assert!(store.save_template(&guarded).await.is_err());
    assert!(store.template_by_id(&guarded.id).await.unwrap().is_none());

    // Install real owner SQL, rather than same-named placeholder functions.
    // The baseline and profile migrations provide the columns used by 0018.
    let mut installation = pool.begin().await.unwrap();
    for source in [
        include_str!("../../issuance/migrations/0000_issuance_service_baseline.sql"),
        "SET check_function_bodies=true; SET search_path=pg_catalog,public;",
        include_str!("../../issuance/migrations/0001_oid4vci_public_protocol.sql"),
        include_str!("../../issuance/migrations/0013_explicit_jwt_vc_profile.sql"),
    ] {
        sqlx::raw_sql(source)
            .execute(&mut *installation)
            .await
            .unwrap();
    }
    installation.commit().await.unwrap();
    assert!(store.save_template(&guarded).await.is_err());
    restore_owner_guards(&pool).await;
    store.save_template(&guarded).await.unwrap();
    assert_eq!(
        store.template_by_id(&guarded.id).await.unwrap(),
        Some(guarded.clone())
    );
    let raw_status: String = sqlx::query_scalar(
        "SELECT status FROM credential_template_service.credential_templates WHERE id=$1",
    )
    .bind(&guarded.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(raw_status, "prerequisite1_draft");
    assert!(
        TemplateStatus::parse(&raw_status).is_err(),
        "unaware readers fail closed"
    );

    guarded.status = TemplateStatus::Active;
    store.save_template(&guarded).await.unwrap();
    assert_eq!(
        store.template_by_id(&guarded.id).await.unwrap(),
        Some(guarded.clone())
    );
    assert_eq!(
        store
            .templates_by_organization(&guarded.organization_id, Some(TemplateStatus::Active))
            .await
            .unwrap(),
        vec![guarded.clone()],
    );
    assert!(store
        .templates_by_organization("foreign-tenant", Some(TemplateStatus::Active))
        .await
        .unwrap()
        .is_empty());

    // Old writers that omit the new property cannot strip the stored policy.
    let mut old_writer = guarded.clone();
    old_writer.verification_prerequisite = None;
    assert!(store.save_template(&old_writer).await.is_err());
    for assignment in [
        "verification_prerequisite=NULL, status='active'",
        "status='active'",
        "status='prerequisite1_draft'",
        "verification_prerequisite='null'::jsonb",
        "verification_prerequisite=jsonb_set(verification_prerequisite,'{policy,version}','8')",
        "verification_prerequisite=verification_prerequisite || '{\"extension\":true}'::jsonb",
        "organization_id='foreign-tenant'",
        "version=version+1",
        "credential_payload_format='VC_JWT'",
        "issuance_protocol='OID4VCI_AUTH_CODE'",
        "wallet_configs='[{\"wallet_id\":\"unqualified\"}]'::jsonb",
        "validity_rules=jsonb_set(validity_rules::jsonb,'{renewable}','true')",
        "application_template_id='application-not-supported'",
    ] {
        rejected_update(&pool, assignment).await;
    }
    assert_eq!(
        store.template_by_id(&guarded.id).await.unwrap(),
        Some(guarded.clone())
    );

    // Omitting the intent at the other owner cannot bypass an opted-in saved
    // template, including when the caller predates this feature entirely.
    let insert_old_transaction = |template_id: &str, transaction_id: &str| {
        sqlx::query(
            "INSERT INTO issuance_service.issuance_transactions \
             (id,organization_id,credential_template_id,status,pre_auth_code,claims,created_at,expires_at) \
             VALUES ($1,'org-prerequisite-test',$2,'pending',$1,'{}',clock_timestamp(),clock_timestamp()+interval '5 minutes')",
        ).bind(transaction_id.to_owned()).bind(template_id.to_owned())
    };
    assert!(insert_old_transaction(&guarded.id, "tx-guarded-omission")
        .execute(&pool)
        .await
        .is_err());
    insert_old_transaction(&legacy.id, "tx-unconfigured-legacy")
        .execute(&pool)
        .await
        .unwrap();

    // Every required owner trigger and its exact function body participates in
    // readiness. A same-named no-op, disabled guard, or changed call is refused.
    for (table, guard) in [
        (
            "issuance_transactions",
            "guard_verification_prerequisite_transaction",
        ),
        (
            "issuance_prerequisite_continuations",
            "guard_verification_prerequisite_continuation",
        ),
        (
            "authorization_sessions",
            "guard_verification_prerequisite_authorization",
        ),
    ] {
        // Identifiers below are fixed fixture literals, never request data.
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "ALTER TABLE issuance_service.{table} DISABLE TRIGGER {guard}"
        )))
        .execute(&pool)
        .await
        .unwrap();
        assert!(
            store.save_template(&guarded).await.is_err(),
            "disabled {guard}"
        );
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "ALTER TABLE issuance_service.{table} ENABLE TRIGGER {guard}"
        )))
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "CREATE OR REPLACE FUNCTION issuance_service.{guard}() RETURNS trigger \
             LANGUAGE plpgsql AS $noop$ BEGIN RETURN NEW; END; $noop$;",
        )))
        .execute(&pool)
        .await
        .unwrap();
        assert!(
            store.save_template(&guarded).await.is_err(),
            "changed {guard}"
        );
        restore_owner_guards(&pool).await;
        store.save_template(&guarded).await.unwrap();
    }

    validate_credential_template_schema(&pool).await.unwrap();
    sqlx::query(
        "ALTER TABLE credential_template_service.credential_templates \
         DISABLE TRIGGER guard_verification_prerequisite_readiness",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert!(validate_credential_template_schema(&pool).await.is_err());
    sqlx::query(
        "ALTER TABLE credential_template_service.credential_templates \
         ENABLE TRIGGER guard_verification_prerequisite_readiness",
    )
    .execute(&pool)
    .await
    .unwrap();
    validate_credential_template_schema(&pool).await.unwrap();

    let predicate: String = sqlx::query_scalar("SELECT pg_get_functiondef(to_regprocedure($1))")
        .bind(POLICY_CHECK)
        .fetch_one(&pool)
        .await
        .unwrap();
    let altered = predicate.replace(
        "BEGIN\n    IF verification_prerequisite IS NULL THEN",
        "BEGIN\n    RETURN true;\n    IF verification_prerequisite IS NULL THEN",
    );
    assert_ne!(predicate, altered);
    // These DDL strings come only from the local catalog just installed from
    // checked-in migrations, with the explicit test mutations shown above.
    sqlx::raw_sql(sqlx::AssertSqlSafe(altered))
        .execute(&pool)
        .await
        .unwrap();
    assert!(validate_credential_template_schema(&pool).await.is_err());
    sqlx::raw_sql(sqlx::AssertSqlSafe(predicate))
        .execute(&pool)
        .await
        .unwrap();
    validate_credential_template_schema(&pool).await.unwrap();

    let constraint: String = sqlx::query_scalar(
        "SELECT pg_get_constraintdef(oid) FROM pg_constraint \
         WHERE conrelid='credential_template_service.credential_templates'::regclass \
           AND conname='ck_template_verification_prerequisite'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let weakened = constraint.replacen(" IS TRUE)", " IS TRUE OR status IS NOT NULL)", 1);
    assert_ne!(weakened, constraint);
    for (definition, valid) in [(&weakened, false), (&constraint, true)] {
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "ALTER TABLE credential_template_service.credential_templates \
             DROP CONSTRAINT ck_template_verification_prerequisite; \
             ALTER TABLE credential_template_service.credential_templates \
             ADD CONSTRAINT ck_template_verification_prerequisite {definition}",
        )))
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(
            validate_credential_template_schema(&pool).await.is_ok(),
            valid
        );
    }

    let persisted: Value = sqlx::query_scalar(
        "SELECT verification_prerequisite FROM credential_template_service.credential_templates WHERE id=$1",
    ).bind(&guarded.id).fetch_one(&pool).await.unwrap();
    assert_eq!(
        persisted,
        serde_json::to_value(&guarded.verification_prerequisite).unwrap()
    );
    migrate_credential_template_schema(&pool).await.unwrap();
    validate_credential_template_schema(&pool).await.unwrap();
    assert_eq!(
        store.template_by_id(&guarded.id).await.unwrap(),
        Some(guarded)
    );
}
