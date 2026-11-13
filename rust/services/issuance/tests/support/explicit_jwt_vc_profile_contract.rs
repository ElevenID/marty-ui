//! Real PostgreSQL controls inside the existing issuance_credential CI obligation.
//! Dynamic DDL below uses only the fixed identifiers in these test matrices or
//! definitions read from objects this test just created in its disposable schema.
//! No request data, URL content, or caller-controlled identifier enters that DDL.
use super::*;
use marty_credential_template::{
    catalog::marty_login_badge,
    migration::{migrate_credential_template_schema, validate_credential_template_schema},
    CredentialFormat, PostgresCredentialTemplateStore, TemplateStatus,
};
use marty_issuance_service::migration::{migrate_jwt_vc_profile, validate_jwt_vc_profile};
use marty_jwt_vc_issuance::{JwtVcIssuanceSelection, JwtVcTemplatePolicy};

#[tokio::test]
async fn explicit_profile_migrations_old_writers_and_concurrent_claims_fail_closed_on_postgres() {
    let Ok(database_url) = std::env::var("ISSUANCE_POSTGRES_TEST_URL") else {
        eprintln!("not executed: explicit JWT-VC PostgreSQL controls require ISSUANCE_POSTGRES_TEST_URL; the existing issuance_credential CI obligation supplies it");
        return;
    };
    assert!(Url::parse(&database_url).unwrap().path().ends_with("_test"));
    let _guard = POSTGRES_CONTRACT_LOCK.lock().await;
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .unwrap();
    create_contract_schema(&pool).await;
    sqlx::query("DROP TABLE credential_template_service.credential_templates")
        .execute(&pool)
        .await
        .unwrap();
    migrate_credential_template_schema(&pool).await.unwrap();
    let store = PostgresCredentialTemplateStore::new(pool.clone());
    let mut legacy = marty_login_badge(
        Utc::now(),
        "org-profile",
        "https://issuer.example",
        "did:web:issuer.example",
    );
    legacy.id = "legacy-profile-fixture".into();
    legacy.credential_type = "EmployeeCredential".into();
    legacy.credential_payload_format = "VC_JWT".into();
    legacy.supported_formats = vec![CredentialFormat::VcJwt];
    store.save_template(&legacy).await.unwrap();
    let mut direct = legacy.clone();
    direct.id = "direct-profile-fixture".into();
    direct.status = TemplateStatus::Active;
    direct.credential_payload_format = "VC_JWT_DIRECT_V1".into();
    direct.supported_formats = vec![CredentialFormat::VcJwtDirectV1];
    direct.jwt_vc_profile = Some(JwtVcTemplatePolicy::new(3600).unwrap());
    direct.issuance_protocol = "OID4VCI_PRE_AUTH".into();
    direct.selective_disclosure_fields.clear();
    direct.zk_predicate_claims.clear();
    direct.wallet_configs.clear();
    direct.validity_rules.renewable = false;
    direct.validity_rules.default_validity_days = 2;
    direct.validity_rules.not_before_offset_seconds = -30;
    // Template-first rollout cannot expose even a draft until the exact issuance guards exist.
    assert!(store.save_template(&direct).await.is_err());
    assert!(store.template_by_id(&direct.id).await.unwrap().is_none());
    // Simulate a pre-upgrade session, including the old same-type legacy-template fallback.
    sqlx::query("INSERT INTO issuance_service.authorization_sessions (id, organization_id, credential_configuration_ids, access_token, access_token_expires_at)
        VALUES ('pre-upgrade-direct-session','org-profile','[\"EmployeeCredential#vc2-jose-2026-v1\"]', 'old-session-token-hash',clock_timestamp()+interval '30 minutes')")
        .execute(&pool).await.unwrap();
    migrate_jwt_vc_profile(&pool).await.unwrap();
    validate_jwt_vc_profile(&pool).await.unwrap();
    for (table, trigger) in [
        ("issuance_transactions", "guard_explicit_jwt_vc_transaction"),
        (
            "authorization_sessions",
            "guard_explicit_jwt_vc_authorization",
        ),
    ] {
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "ALTER TABLE issuance_service.{table} DISABLE TRIGGER {trigger}"
        )))
        .execute(&pool)
        .await
        .unwrap();
        assert!(validate_jwt_vc_profile(&pool).await.is_err());
        assert!(store.save_template(&direct).await.is_err());
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "ALTER TABLE issuance_service.{table} ENABLE TRIGGER {trigger}"
        )))
        .execute(&pool)
        .await
        .unwrap();
    }
    assert_check_and_trigger_drift(&pool, &store, &direct).await;
    store.save_template(&direct).await.unwrap();
    let restored = store.template_by_id(&direct.id).await.unwrap().unwrap();
    assert_eq!(restored.jwt_vc_profile, direct.jwt_vc_profile);
    assert_eq!(restored.status, TemplateStatus::Active);
    assert_eq!(restored.credential_payload_format, "VC_JWT_DIRECT_V1");
    assert_eq!(
        store
            .template_by_id(&legacy.id)
            .await
            .unwrap()
            .unwrap()
            .jwt_vc_profile,
        None
    );
    let old_visible: Vec<String> = sqlx::query_scalar("SELECT id FROM credential_template_service.credential_templates WHERE organization_id=$1 AND status IN ('active','draft')")
        .bind("org-profile").fetch_all(&pool).await.unwrap();
    assert!(old_visible.contains(&legacy.id));
    assert!(!old_visible.contains(&direct.id));
    let raw_status: String = sqlx::query_scalar(
        "SELECT status FROM credential_template_service.credential_templates WHERE id=$1",
    )
    .bind(&direct.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(TemplateStatus::parse(&raw_status).is_err());
    // A stale old UPSERT omits the new column: EXCLUDED defaults it to NULL,
    // while the existing direct row retains its profile. The iff check refuses downgrade.
    let stale = sqlx::query("INSERT INTO credential_template_service.credential_templates
        (id,organization_id,name,status,credential_type,vct,credential_payload_format,compliance_profile_id,created_at,updated_at)
        VALUES ($1,'org-profile','stale old template','active','EmployeeCredential','https://issuer.example/credential','VC_JWT','public-compliance',clock_timestamp(),clock_timestamp())
        ON CONFLICT(id) DO UPDATE SET status=EXCLUDED.status,credential_payload_format=EXCLUDED.credential_payload_format")
        .bind(&direct.id).execute(&pool).await;
    assert!(stale.is_err());
    assert_eq!(
        store
            .template_by_id(&direct.id)
            .await
            .unwrap()
            .unwrap()
            .jwt_vc_profile,
        direct.jwt_vc_profile
    );
    // New services preserve normal legacy discovery and add only the separately marked row.
    let discovery = PostgresTenantDiscoveryRepository::new(pool.clone());
    assert_eq!(discovery.templates("org-profile").await.unwrap().len(), 1);
    assert_eq!(
        discovery
            .profiled_templates("org-profile")
            .await
            .unwrap()
            .len(),
        1
    );
    for configuration in [
        "EmployeeCredential#vc2-jose-2026-v1",
        "Other#vc2-jose-2026-v1",
    ] {
        assert!(sqlx::query("INSERT INTO issuance_service.authorization_sessions (id, organization_id, credential_configuration_ids) VALUES ($1,'org-profile',$2)")
            .bind(configuration).bind(json!([configuration])).execute(&pool).await.is_err());
    }
    assert!(sqlx::query("INSERT INTO issuance_service.issuance_transactions (id,organization_id,status,pre_auth_code,access_token)
        VALUES ('old-auth-fallback','org-profile','authorized','old-auth-fallback','old-session-token-hash')")
        .execute(&pool).await.is_err());

    let key = b"public-synthetic-profile-contract-hmac-key";
    let repository = PostgresCredentialRepository::new(pool.clone(), key);
    let mut transaction =
        seed_signing_claim(&pool, &repository, key, "legacy-seed", "legacy-seed-token").await;
    transaction.id = "explicit-claim".into();
    transaction.organization_id = "org-profile".into();
    transaction.credential_template_id = direct.id.clone();
    transaction.credential_type = Some("EmployeeCredential".into());
    transaction.credential_payload_format = "VC_JWT_DIRECT_V1".into();
    transaction.jwt_vc_profile = Some(
        JwtVcIssuanceSelection::new(
            direct.jwt_vc_profile.clone().unwrap(),
            "EmployeeCredential",
            &direct.id,
            direct.version,
            2 * 86400,
            -30,
        )
        .unwrap(),
    );
    transaction.application_id = None;
    transaction.renewable = false;
    transaction.validity_days = 2;
    transaction.status = CredentialTransactionStatus::Pending;
    transaction.pre_authorized_code = "explicit-preauth".into();
    transaction.nonce = None;
    repository.reserve_idempotently(&transaction).await.unwrap();
    assert!(sqlx::query("INSERT INTO issuance_service.authorization_sessions (id,organization_id,issuer_state,credential_configuration_ids) VALUES ('direct-issuer-state','org-profile','explicit-preauth','[\"EmployeeCredential\"]')")
        .execute(&pool).await.is_err());
    // Create a genuinely old linked session while the test owns a disabled trigger,
    // then run the unchanged production old binding UPDATE through the repository.
    sqlx::query("ALTER TABLE issuance_service.authorization_sessions DISABLE TRIGGER guard_explicit_jwt_vc_authorization").execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO issuance_service.authorization_sessions (id,client_id,organization_id,issuer_state,credential_configuration_ids,access_token,access_token_expires_at)
        VALUES ('pre-upgrade-link','wallet-client','org-profile','explicit-preauth','[\"EmployeeCredential\"]',$1,clock_timestamp()+interval '30 minutes')")
        .bind(token_digest(key,"pre-upgrade-link-token")).execute(&pool).await.unwrap();
    sqlx::query("ALTER TABLE issuance_service.authorization_sessions ENABLE TRIGGER guard_explicit_jwt_vc_authorization").execute(&pool).await.unwrap();
    let session = repository
        .authorization_by_access_token("pre-upgrade-link-token")
        .await
        .unwrap()
        .unwrap();
    assert!(repository
        .ensure_authorization_transaction(&session, "pre-upgrade-link-token")
        .await
        .is_err());
    assert_eq!(
        repository
            .transaction_by_id(&transaction.id)
            .await
            .unwrap()
            .unwrap()
            .status,
        CredentialTransactionStatus::Pending
    );
    sqlx::query("UPDATE issuance_service.issuance_transactions SET status='authorized',access_token=$1,access_token_expires_at=clock_timestamp()+interval '30 minutes',c_nonce='nonce-direct' WHERE id='explicit-claim'")
        .bind(token_digest(key,"explicit-token")).execute(&pool).await.unwrap();
    assert!(sqlx::query("UPDATE issuance_service.issuance_transactions SET status='signing',reserved_credential_id='old-claim' WHERE id='explicit-claim'").execute(&pool).await.is_err());
    let admitted = repository
        .transaction_by_access_token("explicit-token")
        .await
        .unwrap()
        .unwrap();
    let authority = CredentialSigningAuthorization {
        transaction: &admitted,
        authorization_session: None,
        access_token: "explicit-token",
    };
    let before: chrono::DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&pool)
        .await
        .unwrap();
    let (first, second) = tokio::join!(
        repository.claim_for_signing(&admitted, "urn:credential:first", &authority),
        repository.claim_for_signing(&admitted, "urn:credential:second", &authority)
    );
    let winners: Vec<_> = [first.unwrap(), second.unwrap()]
        .into_iter()
        .flatten()
        .collect();
    assert_eq!(winners.len(), 1);
    let timing = winners[0].jwt_vc_signing_timing.unwrap();
    assert!(timing.signature_issued_at() >= before.timestamp());
    assert_eq!(
        timing.signature_expires_at() - timing.signature_issued_at(),
        3600
    );
    assert_eq!(
        timing.credential_valid_from().timestamp(),
        timing.signature_issued_at() - 30
    );
    assert_eq!(
        timing.credential_valid_until().unwrap().timestamp(),
        timing.signature_issued_at() - 30 + 2 * 86400
    );
    assert!(sqlx::query("UPDATE issuance_service.issuance_transactions SET jwt_vc_signing_timing=NULL WHERE id='explicit-claim'").execute(&pool).await.is_err());
    assert!(sqlx::query("UPDATE issuance_service.issuance_transactions SET jwt_vc_profile=NULL WHERE id='explicit-claim'").execute(&pool).await.is_err());
    assert!(sqlx::query("UPDATE issuance_service.issuance_transactions SET credential_payload_format='jwt_vc_json' WHERE id='explicit-claim'").execute(&pool).await.is_err());
    // Repeat both real owners on the mixed legacy/direct installation.
    migrate_jwt_vc_profile(&pool).await.unwrap();
    migrate_credential_template_schema(&pool).await.unwrap();
    validate_credential_template_schema(&pool).await.unwrap();
    validate_jwt_vc_profile(&pool).await.unwrap();
    assert_eq!(
        repository
            .transaction_by_id("explicit-claim")
            .await
            .unwrap()
            .unwrap()
            .jwt_vc_signing_timing,
        Some(timing)
    );
    drop_contract_schema(&pool).await;
    pool.close().await;
}

async fn assert_check_and_trigger_drift(
    pool: &sqlx::PgPool,
    store: &PostgresCredentialTemplateStore,
    direct: &marty_credential_template::CredentialTemplate,
) {
    for (schema, table, check, predicate) in [
        ("issuance_service", "issuance_transactions", "ck_issuance_explicit_jwt_vc_profile", "issuance_service.issuance_explicit_jwt_vc_profile_valid(jsonb,jsonb,text,text,text,text,text,text,jsonb,boolean,text)"),
        ("credential_template_service", "credential_templates", "ck_template_explicit_jwt_vc_profile", "credential_template_service.template_explicit_jwt_vc_profile_valid(jsonb,text,text,text,jsonb,jsonb,jsonb)"),
    ] {
        let check_definition: String = sqlx::query_scalar("SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid=to_regclass($1) AND conname=$2")
            .bind(format!("{schema}.{table}")).bind(check).fetch_one(pool).await.unwrap();
        sqlx::query(sqlx::AssertSqlSafe(format!("ALTER TABLE {schema}.{table} DROP CONSTRAINT {check}"))).execute(pool).await.unwrap();
        sqlx::query(sqlx::AssertSqlSafe(format!("ALTER TABLE {schema}.{table} ADD CONSTRAINT {check} CHECK (TRUE)"))).execute(pool).await.unwrap();
        if schema == "issuance_service" {
            assert!(validate_jwt_vc_profile(pool).await.is_err());
            assert!(store.save_template(direct).await.is_err());
        } else {
            assert!(validate_credential_template_schema(pool).await.is_err());
        }
        sqlx::query(sqlx::AssertSqlSafe(format!("ALTER TABLE {schema}.{table} DROP CONSTRAINT {check}"))).execute(pool).await.unwrap();
        sqlx::query(sqlx::AssertSqlSafe(format!("ALTER TABLE {schema}.{table} ADD CONSTRAINT {check} {check_definition} NOT VALID"))).execute(pool).await.unwrap();
        if schema == "issuance_service" {
            assert!(validate_jwt_vc_profile(pool).await.is_err());
            assert!(store.save_template(direct).await.is_err());
        } else {
            assert!(validate_credential_template_schema(pool).await.is_err());
        }
        sqlx::query(sqlx::AssertSqlSafe(format!("ALTER TABLE {schema}.{table} VALIDATE CONSTRAINT {check}"))).execute(pool).await.unwrap();
        let function: String = sqlx::query_scalar("SELECT pg_get_functiondef(to_regprocedure($1))")
            .bind(predicate).fetch_one(pool).await.unwrap();
        let marker = function.find("AS $function$").expect("PostgreSQL function deparser delimiter");
        let altered = format!("{}AS $function$ BEGIN RETURN NULL; END; $function$", &function[..marker]);
        sqlx::raw_sql(sqlx::AssertSqlSafe(altered.as_str())).execute(pool).await.unwrap();
        if schema == "issuance_service" {
            assert!(validate_jwt_vc_profile(pool).await.is_err());
            assert!(store.save_template(direct).await.is_err());
        } else {
            assert!(validate_credential_template_schema(pool).await.is_err());
            assert!(store.save_template(direct).await.is_err(), "CHECK IS TRUE must reject a NULL predicate result");
        }
        sqlx::raw_sql(sqlx::AssertSqlSafe(function.as_str())).execute(pool).await.unwrap();
        if schema == "credential_template_service" {
            assert_json_overload_is_not_the_owned_predicate(pool, &function).await;
        }
    }
    for (schema, table, trigger) in [
        (
            "issuance_service",
            "issuance_transactions",
            "guard_explicit_jwt_vc_transaction",
        ),
        (
            "issuance_service",
            "authorization_sessions",
            "guard_explicit_jwt_vc_authorization",
        ),
        (
            "credential_template_service",
            "credential_templates",
            "guard_jwt_vc_profile_readiness",
        ),
    ] {
        let original: String = sqlx::query_scalar("SELECT pg_get_triggerdef(oid) FROM pg_trigger WHERE tgrelid=to_regclass($1) AND tgname=$2")
            .bind(format!("{schema}.{table}")).bind(trigger).fetch_one(pool).await.unwrap();
        let column = if table == "authorization_sessions" {
            "issuer_state"
        } else {
            "status"
        };
        for (event, when) in [
            ("INSERT OR UPDATE".to_owned(), "WHEN (false)"),
            (format!("INSERT OR UPDATE OF {column}"), ""),
        ] {
            sqlx::query(sqlx::AssertSqlSafe(format!(
                "DROP TRIGGER {trigger} ON {schema}.{table}"
            )))
            .execute(pool)
            .await
            .unwrap();
            sqlx::query(sqlx::AssertSqlSafe(format!("CREATE TRIGGER {trigger} BEFORE {event} ON {schema}.{table} FOR EACH ROW {when} EXECUTE FUNCTION {schema}.{trigger}()")))
                .execute(pool).await.unwrap();
            if schema == "issuance_service" {
                assert!(validate_jwt_vc_profile(pool).await.is_err());
                assert!(store.save_template(direct).await.is_err());
            } else {
                assert!(validate_credential_template_schema(pool).await.is_err());
            }
            sqlx::query(sqlx::AssertSqlSafe(format!(
                "DROP TRIGGER {trigger} ON {schema}.{table}"
            )))
            .execute(pool)
            .await
            .unwrap();
            sqlx::query(sqlx::AssertSqlSafe(original.as_str()))
                .execute(pool)
                .await
                .unwrap();
        }
    }
    validate_jwt_vc_profile(pool).await.unwrap();
    validate_credential_template_schema(pool).await.unwrap();
}

async fn assert_json_overload_is_not_the_owned_predicate(pool: &sqlx::PgPool, function: &str) {
    // A historical JSON column can select an overload whose deparsed call is
    // identical after harmless JSONB casts are removed. The owned original
    // function remains present and byte-correct; the constraint's dependency
    // must still point to that exact signature.
    sqlx::query("ALTER TABLE credential_template_service.credential_templates ALTER COLUMN wallet_configs TYPE json USING wallet_configs::json")
        .execute(pool).await.unwrap();
    let definition: String = sqlx::query_scalar("SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid='credential_template_service.credential_templates'::regclass AND conname='ck_template_explicit_jwt_vc_profile'")
        .fetch_one(pool).await.unwrap();
    let marker = function.find("AS $function$").unwrap();
    let header = function[..marker].replace("wallet_configs jsonb", "wallet_configs json");
    assert_ne!(header, function[..marker]);
    let overload = format!("{header}AS $function$ BEGIN RETURN TRUE; END; $function$");
    sqlx::raw_sql(sqlx::AssertSqlSafe(overload.as_str()))
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("ALTER TABLE credential_template_service.credential_templates DROP CONSTRAINT ck_template_explicit_jwt_vc_profile")
        .execute(pool).await.unwrap();
    sqlx::query("ALTER TABLE credential_template_service.credential_templates ADD CONSTRAINT ck_template_explicit_jwt_vc_profile CHECK (credential_template_service.template_explicit_jwt_vc_profile_valid(jwt_vc_profile::jsonb, credential_payload_format::text, status::text, issuance_protocol::text, supported_formats::jsonb, wallet_configs, validity_rules::jsonb) IS TRUE)")
        .execute(pool).await.unwrap();
    let wrong_definition: String = sqlx::query_scalar("SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid='credential_template_service.credential_templates'::regclass AND conname='ck_template_explicit_jwt_vc_profile'")
        .fetch_one(pool).await.unwrap();
    let normalized = |value: &str| -> String {
        value
            .replace("::text", "")
            .replace("::jsonb", "")
            .chars()
            .filter(|ch| !ch.is_whitespace() && !matches!(ch, '(' | ')'))
            .collect()
    };
    assert_eq!(normalized(&definition), normalized(&wrong_definition));
    let bound_to_overload: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_constraint c JOIN pg_depend d ON d.classid='pg_constraint'::regclass AND d.objid=c.oid WHERE c.conrelid='credential_template_service.credential_templates'::regclass AND c.conname='ck_template_explicit_jwt_vc_profile' AND d.refclassid='pg_proc'::regclass AND d.refobjid=to_regprocedure('credential_template_service.template_explicit_jwt_vc_profile_valid(jsonb,text,text,text,jsonb,json,jsonb)'))")
        .fetch_one(pool).await.unwrap();
    assert!(bound_to_overload);
    assert!(validate_credential_template_schema(pool).await.is_err());
    sqlx::query("ALTER TABLE credential_template_service.credential_templates DROP CONSTRAINT ck_template_explicit_jwt_vc_profile")
        .execute(pool).await.unwrap();
    sqlx::query(sqlx::AssertSqlSafe(format!("ALTER TABLE credential_template_service.credential_templates ADD CONSTRAINT ck_template_explicit_jwt_vc_profile {definition}")))
        .execute(pool).await.unwrap();
    sqlx::query("DROP FUNCTION credential_template_service.template_explicit_jwt_vc_profile_valid(jsonb,text,text,text,jsonb,json,jsonb)")
        .execute(pool).await.unwrap();
    sqlx::query("ALTER TABLE credential_template_service.credential_templates ALTER COLUMN wallet_configs TYPE jsonb USING wallet_configs::jsonb")
        .execute(pool).await.unwrap();
    validate_credential_template_schema(pool).await.unwrap();
}
