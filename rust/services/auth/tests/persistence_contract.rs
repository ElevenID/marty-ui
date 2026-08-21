use std::collections::BTreeSet;

use chrono::{TimeZone as _, Utc};
use marty_auth::{
    migrate_auth_schema, validate_auth_schema, ApplicantProvisioningStore, ApplicantUpsert,
    AuditLogFilter, AuthAuditSink, AuthenticatedUser, PostgresAuthRepository, Session, SessionSpec,
    SessionStatus, UserType,
};
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

fn fixture() -> Value {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../contracts/auth-persistence-behavior.json"
    )))
    .expect("auth persistence fixture must be valid JSON")
}

#[test]
fn migration_and_repository_preserve_the_language_neutral_contract() {
    let fixture = fixture();
    let migration = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/migrations/0001_auth_schema.sql"
    ));
    let migration_source = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/migration.rs"));
    let repository_source = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/postgres.rs"));
    let uppercase = migration.to_uppercase();
    assert!(!uppercase.contains("DROP TABLE"));
    assert!(!uppercase.contains("DROP SCHEMA"));
    assert!(migration_source.contains("pg_advisory_xact_lock"));
    assert!(migration.contains(fixture["migration_head"].as_str().unwrap()));

    let tables: BTreeSet<_> = fixture["owned_tables"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect();
    for table in tables {
        assert!(migration.contains(&format!("auth_service.{table}")));
    }
    assert!(!migration.contains("CREATE TABLE IF NOT EXISTS public.applicants"));
    for column in fixture["shared_applicant_columns"].as_array().unwrap() {
        assert!(migration_source.contains(column.as_str().unwrap()));
    }
    for event in fixture["audit_pairs"]
        .as_object()
        .unwrap()
        .values()
        .flat_map(|events| events.as_array().unwrap())
    {
        assert!(repository_source.contains(event.as_str().unwrap()));
    }
}

#[tokio::test]
async fn postgres_jit_and_audit_behavior_matches_contract_when_configured() {
    let Ok(database_url) = std::env::var("AUTH_POSTGRES_TEST_URL") else {
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&database_url)
        .await
        .expect("Auth PostgreSQL contract database must connect");
    install_shared_applicant_contract(&pool).await;
    migrate_auth_schema(&pool)
        .await
        .expect("migration must pass");
    migrate_auth_schema(&pool)
        .await
        .expect("migration must be idempotent");
    validate_auth_schema(&pool)
        .await
        .expect("owned and shared schemas must validate");

    let tag = Uuid::new_v4().to_string();
    let account_id = format!("account-{tag}");
    let email = format!("{tag}@example.com");
    let now = Utc.with_ymd_and_hms(2026, 8, 20, 12, 0, 0).unwrap();
    let repository = PostgresAuthRepository::new(pool.clone());
    let created = repository
        .upsert(&ApplicantUpsert {
            new_id: tag.clone(),
            account_id: account_id.clone(),
            email: email.clone(),
            given_names: Some("Alice".into()),
            surname: Some("Smith".into()),
            fallback_given_names: "Unknown".into(),
            fallback_surname: "Unknown".into(),
            date_of_birth: now.date_naive(),
            nationality: "UNK".into(),
            extra_data_patch: json!({"first": true, "preserved": "yes"}),
            now,
        })
        .await
        .expect("first-login applicant must be created");
    let updated = repository
        .upsert(&ApplicantUpsert {
            new_id: Uuid::new_v4().to_string(),
            account_id,
            email: email.clone(),
            given_names: None,
            surname: None,
            fallback_given_names: "Unknown".into(),
            fallback_surname: "Unknown".into(),
            date_of_birth: now.date_naive(),
            nationality: "UNK".into(),
            extra_data_patch: json!({"second": true}),
            now,
        })
        .await
        .expect("repeat login must update the applicant");
    assert_eq!(updated.id, created.id);
    assert_eq!(updated.given_names, "Alice");
    assert_eq!(updated.surname, "Smith");
    assert_eq!(updated.extra_data["preserved"], "yes");
    assert_eq!(updated.extra_data["second"], true);

    let mut session = Session::create(SessionSpec {
        user: test_user(&created.id, &email),
        ttl_seconds: 3_600,
        now,
        ip_address: Some("127.0.0.1".into()),
        user_agent: Some("auth-contract".into()),
        id_token: None,
        refresh_token: None,
        oidc_claims: None,
    });
    repository
        .record_authentication(&session, "oidc")
        .await
        .expect("authentication audit pair must commit");
    session.status = SessionStatus::Revoked;
    repository
        .record_logout(&session)
        .await
        .expect("logout audit pair must commit");
    let logs = repository
        .get_audit_logs(&AuditLogFilter {
            user_id: Some(created.id.clone()),
            limit: 100,
            ..AuditLogFilter::default()
        })
        .await
        .expect("audit query must pass");
    let events: BTreeSet<_> = logs.iter().map(|log| log.event_type.as_str()).collect();
    assert_eq!(
        events,
        BTreeSet::from([
            "logout",
            "session_created",
            "session_revoked",
            "user_authenticated"
        ])
    );
    let history = repository
        .get_session_history(&marty_auth::SessionHistoryFilter {
            user_id: Some(created.id.clone()),
            limit: 100,
            ..marty_auth::SessionHistoryFilter::default()
        })
        .await
        .expect("history query must pass");
    assert_eq!(history.len(), 1);
    assert!(history[0].revoked_at.is_some());
    assert_eq!(history[0].revocation_reason.as_deref(), Some("logout"));

    sqlx::query("DELETE FROM auth_service.audit_logs WHERE user_id=$1")
        .bind(&created.id)
        .execute(&pool)
        .await
        .expect("scoped audit cleanup must pass");
    sqlx::query("DELETE FROM auth_service.session_history WHERE user_id=$1")
        .bind(&created.id)
        .execute(&pool)
        .await
        .expect("scoped history cleanup must pass");
    sqlx::query("DELETE FROM public.applicants WHERE id=$1")
        .bind(&created.id)
        .execute(&pool)
        .await
        .expect("scoped applicant cleanup must pass");
}

async fn install_shared_applicant_contract(pool: &sqlx::PgPool) {
    sqlx::raw_sql(
        "CREATE TABLE IF NOT EXISTS public.applicants (
            id VARCHAR(36) PRIMARY KEY,
            account_id VARCHAR(255) UNIQUE,
            email VARCHAR(255) NOT NULL UNIQUE,
            surname VARCHAR(255) NOT NULL,
            given_names VARCHAR(255) NOT NULL,
            date_of_birth DATE NOT NULL,
            nationality VARCHAR(3) NOT NULL,
            identity_proofing_completed BOOLEAN NOT NULL DEFAULT FALSE,
            identity_proofing_date TIMESTAMPTZ,
            active BOOLEAN NOT NULL DEFAULT TRUE,
            suspended BOOLEAN NOT NULL DEFAULT FALSE,
            extra_data JSON,
            created_at TIMESTAMPTZ NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL,
            deleted_at TIMESTAMPTZ
        )",
    )
    .execute(pool)
    .await
    .expect("shared applicant test contract must install");
}

fn test_user(user_id: &str, email: &str) -> AuthenticatedUser {
    AuthenticatedUser {
        user_id: user_id.into(),
        email: email.into(),
        username: Some("alice".into()),
        given_name: Some("Alice".into()),
        family_name: Some("Smith".into()),
        user_type: UserType::Applicant,
        applicant_id: Some(user_id.into()),
        roles: vec!["applicant".into()],
        organization_id: Some("org-1".into()),
        organization_name: Some("Marty".into()),
        organization: None,
        default_organization_id: Some("org-1".into()),
        default_organization_name: Some("Marty".into()),
        organizations: Vec::new(),
        organization_context_unavailable: false,
        organization_context_error: None,
        onboarding_completed: None,
        picture: None,
        impersonation: None,
        did_subject: None,
    }
}
