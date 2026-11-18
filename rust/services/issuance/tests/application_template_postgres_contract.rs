use chrono::{Duration, TimeZone, Utc};
use marty_issuance_service::{
    application_template_domain::{
        ApplicationTemplateCreate, ApplicationTemplatePatch, ApplicationTemplateStatus,
    },
    application_template_postgres::PostgresApplicationTemplateRepository,
    application_template_service::{
        ApplicationTemplateIdempotencyBinding, ApplicationTemplateRepository,
        ApplicationTemplateRepositoryError,
    },
};
use serde_json::json;
use sqlx::postgres::PgPoolOptions;

#[tokio::test]
async fn application_template_repository_is_tenant_idempotent_and_compare_and_set_safe() {
    let Ok(database_url) = std::env::var("ISSUANCE_POSTGRES_TEST_URL") else {
        return;
    };
    let database_name = url::Url::parse(&database_url)
        .expect("issuance PostgreSQL contract URL must parse")
        .path()
        .trim_start_matches('/')
        .to_owned();
    assert!(
        database_name.ends_with("_test"),
        "ISSUANCE_POSTGRES_TEST_URL must name a dedicated *_test database"
    );
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&database_url)
        .await
        .expect("issuance PostgreSQL contract database must connect");

    for statement in [
        "CREATE SCHEMA IF NOT EXISTS issuance_service",
        "CREATE SCHEMA IF NOT EXISTS organization_service",
        "DROP TABLE IF EXISTS issuance_service.application_templates CASCADE",
        "DROP TABLE IF EXISTS organization_service.policy_sets CASCADE",
        "CREATE TABLE issuance_service.application_templates (
            id TEXT PRIMARY KEY,
            organization_id TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            credential_template_id TEXT,
            form_fields JSON NOT NULL DEFAULT '[]'::json,
            evidence_requirements JSON NOT NULL DEFAULT '[]'::json,
            claim_collection_rules JSON NOT NULL DEFAULT '[]'::json,
            required_checks JSON NOT NULL DEFAULT '[]'::json,
            approval_strategy TEXT NOT NULL,
            approval_policy_set_id TEXT,
            application_validity_days INTEGER NOT NULL,
            ui_config JSON NOT NULL DEFAULT '{}'::json,
            notification_config JSON NOT NULL DEFAULT '{}'::json,
            status TEXT NOT NULL,
            management_version BIGINT NOT NULL DEFAULT 1
                CHECK (management_version > 0),
            idempotency_key_hash VARCHAR(64),
            idempotency_request_hash VARCHAR(64),
            created_at TIMESTAMPTZ NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL,
            CONSTRAINT ck_application_templates_idempotency_pair CHECK (
                (idempotency_key_hash IS NULL AND idempotency_request_hash IS NULL)
                OR
                (idempotency_key_hash IS NOT NULL AND idempotency_request_hash IS NOT NULL)
            )
        )",
        "CREATE UNIQUE INDEX ux_application_templates_org_idempotency_key_hash
            ON issuance_service.application_templates (
                organization_id,
                idempotency_key_hash
            ) WHERE idempotency_key_hash IS NOT NULL",
        "CREATE TABLE organization_service.policy_sets (
            id TEXT NOT NULL,
            organization_id TEXT NOT NULL,
            policy_type TEXT NOT NULL,
            status TEXT NOT NULL,
            PRIMARY KEY (organization_id, id)
        )",
    ] {
        sqlx::query(statement)
            .execute(&pool)
            .await
            .expect("Application Template contract schema statement must succeed");
    }

    let repository = PostgresApplicationTemplateRepository::new(pool.clone());
    let observed_at = Utc
        .with_ymd_and_hms(2026, 9, 19, 12, 0, 0)
        .single()
        .expect("fixed timestamp");
    let canonical_request = request("org-a", "Membership application");
    let original = canonical_request
        .clone()
        .into_record("template-original".to_owned(), observed_at)
        .expect("valid template");
    let replay_candidate = canonical_request
        .clone()
        .into_record(
            "template-replay".to_owned(),
            observed_at + Duration::seconds(1),
        )
        .expect("valid replay template");
    let canonical_binding = binding('a', 'b');

    let (first, replay) = tokio::join!(
        repository.reserve_idempotently(&original, &canonical_binding),
        repository.reserve_idempotently(&replay_candidate, &canonical_binding),
    );
    let first = first.expect("first concurrent reservation");
    let replay = replay.expect("replayed concurrent reservation");
    assert_ne!(first.created, replay.created);
    assert_eq!(first.template.id, replay.template.id);
    let stored_id = first.template.id;
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM issuance_service.application_templates
             WHERE organization_id = 'org-a'",
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );

    let conflict = repository
        .reserve_idempotently(&replay_candidate, &binding('a', 'c'))
        .await;
    assert_eq!(
        conflict,
        Err(ApplicationTemplateRepositoryError::IdempotencyConflict)
    );

    let later = request("org-a", "Later application")
        .into_record(
            "template-later".to_owned(),
            observed_at + Duration::seconds(2),
        )
        .expect("later template");
    repository
        .reserve_idempotently(&later, &binding('d', 'e'))
        .await
        .expect("later reservation");
    let foreign = request("org-b", "Foreign application")
        .into_record("template-foreign".to_owned(), observed_at)
        .expect("foreign template");
    repository
        .reserve_idempotently(&foreign, &binding('a', 'b'))
        .await
        .expect("same key is independently scoped by tenant");

    assert!(repository
        .get("org-b", &stored_id)
        .await
        .expect("foreign lookup")
        .is_none());
    let listed = repository.list("org-a").await.expect("tenant list");
    assert_eq!(
        listed
            .iter()
            .map(|template| template.id.as_str())
            .collect::<Vec<_>>(),
        vec![stored_id.as_str(), "template-later"]
    );

    let observed = repository
        .get("org-a", &stored_id)
        .await
        .expect("template lookup")
        .expect("stored template");
    let mut winning_update = observed.clone();
    patch("Winning update")
        .apply(&mut winning_update, observed_at + Duration::seconds(3))
        .expect("valid winning patch");
    let mut stale_update = observed.clone();
    patch("Stale update")
        .apply(&mut stale_update, observed_at + Duration::seconds(4))
        .expect("valid stale patch");
    repository
        .replace_if_version(&winning_update, observed.version)
        .await
        .expect("first compare-and-set update");
    assert_eq!(
        repository
            .replace_if_version(&stale_update, observed.version)
            .await,
        Err(ApplicationTemplateRepositoryError::ConcurrentModification)
    );
    let persisted = repository.get("org-a", &stored_id).await.unwrap().unwrap();
    assert_eq!(persisted.name, "Winning update");
    assert_eq!(persisted.version, 2);

    assert_eq!(
        repository.delete_if_version("org-b", &stored_id, 2).await,
        Err(ApplicationTemplateRepositoryError::ConcurrentModification)
    );
    assert_eq!(
        repository.delete_if_version("org-a", &stored_id, 1).await,
        Err(ApplicationTemplateRepositoryError::ConcurrentModification)
    );
    repository
        .delete_if_version("org-a", &stored_id, 2)
        .await
        .expect("current draft can be deleted atomically");
    assert!(repository.get("org-a", &stored_id).await.unwrap().is_none());

    sqlx::query(
        "INSERT INTO organization_service.policy_sets (
            id, organization_id, policy_type, status
         ) VALUES ('policy-1', 'org-a', 'APPROVAL_RULES', 'ACTIVE')",
    )
    .execute(&pool)
    .await
    .expect("approval policy fixture");
    assert_eq!(
        repository
            .approval_policy("org-a", "policy-1")
            .await
            .expect("approval policy lookup")
            .expect("approval policy")
            .policy_type,
        "APPROVAL_RULES"
    );
    assert!(repository
        .approval_policy("org-b", "policy-1")
        .await
        .expect("foreign approval policy lookup")
        .is_none());

    sqlx::query(
        "UPDATE issuance_service.application_templates
         SET status = 'active' WHERE id = 'template-later'",
    )
    .execute(&pool)
    .await
    .expect("legacy lowercase status fixture");
    assert_eq!(
        repository
            .get("org-a", "template-later")
            .await
            .unwrap()
            .unwrap()
            .status,
        ApplicationTemplateStatus::Active
    );

    sqlx::query("DROP TABLE issuance_service.application_templates CASCADE")
        .execute(&pool)
        .await
        .expect("Application Template contract table must clean up");
    sqlx::query("DROP TABLE organization_service.policy_sets CASCADE")
        .execute(&pool)
        .await
        .expect("approval policy contract table must clean up");
}

fn request(organization_id: &str, name: &str) -> ApplicationTemplateCreate {
    serde_json::from_value(json!({
        "organization_id": organization_id,
        "name": name,
        "credential_template_id": "credential-template-1",
        "form_fields": [{
            "field_id": "membership_number",
            "label": "Membership number",
            "field_type": "TEXT",
            "required": true
        }]
    }))
    .expect("valid request fixture")
}

fn patch(name: &str) -> ApplicationTemplatePatch {
    serde_json::from_value(json!({"name": name})).expect("valid patch fixture")
}

fn binding(key: char, request: char) -> ApplicationTemplateIdempotencyBinding {
    ApplicationTemplateIdempotencyBinding {
        key_hash: key.to_string().repeat(64),
        request_hash: request.to_string().repeat(64),
    }
}
