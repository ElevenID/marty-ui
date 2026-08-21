use std::sync::Arc;

use chrono::Utc;
use marty_organization::postgres::PostgresOrganizationStore;
use marty_organization::{
    CreateOrganizationCommand, JoinMechanism, OrganizationApplication, OrganizationCache,
    OrganizationType, UpdateOrganizationCommand, UpdateOrganizationPatch,
};
use mmf_data::MemoryCache;
use sqlx::postgres::PgPoolOptions;

#[tokio::test]
async fn mutations_commit_domain_audit_and_outbox_state_together_when_configured() {
    let Ok(database_url) = std::env::var("ORGANIZATION_POSTGRES_TEST_URL") else {
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&database_url)
        .await
        .expect("organization PostgreSQL contract database must connect");
    let cache = OrganizationCache::new(
        Arc::new(MemoryCache::default()),
        Arc::new(MemoryCache::default()),
        Arc::new(MemoryCache::default()),
    );
    let application =
        OrganizationApplication::new(PostgresOrganizationStore::new(pool.clone()), cache)
            .expect("application must compose");
    application
        .initialize()
        .await
        .expect("organization and MMF outbox migrations must pass");

    let now = Utc::now();
    let created = application
        .create_organization(CreateOrganizationCommand {
            name: "rust-application-contract".into(),
            owner_id: "application-owner".into(),
            org_type: OrganizationType::Education,
            display_name: Some("Rust Application Contract".into()),
            description: Some("transactional behavior".into()),
            contact_email: Some("owner@example.com".into()),
            visibility: "PRIVATE".into(),
            join_mechanism: JoinMechanism::Invite,
            requires_approval: false,
            now,
        })
        .await
        .expect("transactional creation must pass");
    assert!(created.warnings.is_empty());
    let organization_id = created.value.id;

    let owner = application
        .store()
        .member_by_user_and_organization("application-owner", organization_id)
        .await
        .expect("owner lookup must pass")
        .expect("owner membership must be committed");
    assert!(owner.is_owner());
    assert_eq!(
        application
            .store()
            .roles_by_organization(organization_id)
            .await
            .expect("role lookup must pass")
            .len(),
        8
    );
    assert_eq!(
        application
            .store()
            .list_audit_events(
                organization_id,
                &marty_organization::AuditEventQuery {
                    limit: 10,
                    ..marty_organization::AuditEventQuery::default()
                },
            )
            .await
            .expect("audit lookup must pass")
            .len(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM mmf_messaging.outbox_messages
             WHERE source_service='organization' AND tenant_id=$1",
        )
        .bind(organization_id.to_string())
        .fetch_one(&pool)
        .await
        .expect("outbox lookup must pass"),
        1
    );

    let updated = application
        .update_organization(UpdateOrganizationCommand {
            organization_id,
            patch: UpdateOrganizationPatch {
                description: Some(None),
                visibility: Some("PUBLIC".into()),
                join_mechanism: Some(JoinMechanism::Open),
                ..UpdateOrganizationPatch::default()
            },
            now: Utc::now(),
        })
        .await
        .expect("transactional update must pass");
    assert!(updated.warnings.is_empty());
    assert_eq!(updated.value.description, None);
    assert!(updated.value.is_discoverable);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM organization_service.audit_events WHERE organization_id=$1",
        )
        .bind(organization_id)
        .fetch_one(&pool)
        .await
        .expect("audit count must pass"),
        2
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM mmf_messaging.outbox_messages
             WHERE source_service='organization' AND tenant_id=$1",
        )
        .bind(organization_id.to_string())
        .fetch_one(&pool)
        .await
        .expect("outbox count must pass"),
        2
    );

    application
        .store()
        .delete_organization(organization_id)
        .await
        .expect("organization cleanup must pass");
    sqlx::query(
        "DELETE FROM mmf_messaging.outbox_messages
         WHERE source_service='organization' AND tenant_id=$1",
    )
    .bind(organization_id.to_string())
    .execute(&pool)
    .await
    .expect("outbox cleanup must pass");
}
