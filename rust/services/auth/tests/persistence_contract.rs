use std::collections::BTreeSet;

use chrono::{TimeZone as _, Utc};
use marty_auth::{
    migrate_auth_schema, validate_auth_schema, AuditLogFilter, AuthAuditSink, AuthenticatedUser,
    PostgresAuthRepository, Session, SessionSpec, SessionStatus, UserType,
};
use serde_json::Value;
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
    assert!(!migration_source.contains("public.applicants"));
    assert!(!repository_source.contains("public.applicants"));
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
async fn postgres_audit_behavior_matches_contract_when_configured() {
    let Ok(database_url) = std::env::var("AUTH_POSTGRES_TEST_URL") else {
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&database_url)
        .await
        .expect("Auth PostgreSQL contract database must connect");
    migrate_auth_schema(&pool)
        .await
        .expect("migration must pass");
    migrate_auth_schema(&pool)
        .await
        .expect("migration must be idempotent");
    validate_auth_schema(&pool)
        .await
        .expect("owned schema must validate");

    let tag = Uuid::new_v4().to_string();
    let email = format!("{tag}@example.com");
    let now = Utc.with_ymd_and_hms(2026, 8, 20, 12, 0, 0).unwrap();
    let repository = PostgresAuthRepository::new(pool.clone());

    let mut session = Session::create(SessionSpec {
        user: test_user(&tag, &email),
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
            user_id: Some(tag.clone()),
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
            user_id: Some(tag.clone()),
            limit: 100,
            ..marty_auth::SessionHistoryFilter::default()
        })
        .await
        .expect("history query must pass");
    assert_eq!(history.len(), 1);
    assert!(history[0].revoked_at.is_some());
    assert_eq!(history[0].revocation_reason.as_deref(), Some("logout"));

    sqlx::query("DELETE FROM auth_service.audit_logs WHERE user_id=$1")
        .bind(&tag)
        .execute(&pool)
        .await
        .expect("scoped audit cleanup must pass");
    sqlx::query("DELETE FROM auth_service.session_history WHERE user_id=$1")
        .bind(&tag)
        .execute(&pool)
        .await
        .expect("scoped history cleanup must pass");
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
