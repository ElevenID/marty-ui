use chrono::{Duration, Utc};
use marty_organization::{
    catalog::seed_system_roles, migration::migrate_organization_schema,
    postgres::PostgresOrganizationStore, ApiKey, ApiKeySpec, AuditEvent, AuditEventQuery,
    ConsoleContextPreference, JoinCode, JoinMechanism, Member, MemberStatus, Organization,
    OrganizationStatus, OrganizationType, Permission, PolicySet, PolicySetSpec, PolicySetStatus,
    PolicySetType, Role, ViewMode,
};
use serde_json::{json, Map};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

#[tokio::test]
async fn complete_repository_round_trip_is_tenant_bound_when_configured() {
    let Ok(database_url) = std::env::var("ORGANIZATION_POSTGRES_TEST_URL") else {
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&database_url)
        .await
        .expect("organization PostgreSQL contract database must connect");
    migrate_organization_schema(&pool)
        .await
        .expect("Organization migration must pass");
    let store = PostgresOrganizationStore::new(pool);

    let organization_id = Uuid::new_v5(&Uuid::NAMESPACE_URL, b"marty:organization:rust-contract");
    store
        .delete_organization(organization_id)
        .await
        .expect("contract cleanup must pass");
    let now = Utc::now();
    let mut settings = Map::new();
    settings.insert("pilot_retention_enabled".to_owned(), json!(true));
    let organization = Organization {
        id: organization_id,
        name: "rust-contract-org".to_owned(),
        display_name: Some("Rust Contract Organization".to_owned()),
        slug: "rust-contract-org-fixed".to_owned(),
        description: Some("Organization repository contract".to_owned()),
        org_type: OrganizationType::Enterprise,
        status: OrganizationStatus::Active,
        owner_id: "owner-subject".to_owned(),
        join_code: None,
        visibility: "PUBLIC".to_owned(),
        join_mechanism: JoinMechanism::Code,
        requires_approval: true,
        is_discoverable: true,
        contact_email: Some("operator@example.com".to_owned()),
        contact_phone: None,
        website: Some("https://example.com".to_owned()),
        plan: "hosted-pilot".to_owned(),
        plan_expires_at: Some(now + Duration::days(30)),
        settings,
        created_at: now,
        updated_at: now,
    };
    store
        .save_organization(&organization)
        .await
        .expect("organization save must pass");
    assert_eq!(
        store
            .organization_by_slug(&organization.slug)
            .await
            .expect("organization slug lookup must pass")
            .expect("organization must exist")
            .id,
        organization_id
    );
    assert!(store
        .list_discoverable_organizations(
            Some("Contract"),
            Some(OrganizationType::Enterprise),
            Some(JoinMechanism::Code),
            10,
            0,
        )
        .await
        .expect("discoverable lookup must pass")
        .iter()
        .any(|item| item.id == organization_id));

    let seeded_roles = seed_system_roles(&store, organization_id, now)
        .await
        .expect("permission catalog and system roles must seed");
    assert_eq!(seeded_roles.len(), 8);
    assert!(seeded_roles["applicant"].is_default_for_new_members);

    let permission = Permission {
        id: Uuid::new_v5(&organization_id, b"audit:view"),
        resource: format!("audit-{organization_id}"),
        action: "view".to_owned(),
        description: Some("View contract audit events".to_owned()),
    };
    store
        .save_permission(&permission)
        .await
        .expect("permission save must pass");
    let role = Role {
        id: Uuid::new_v5(&organization_id, b"contract-role"),
        organization_id,
        name: "contract-reviewer".to_owned(),
        display_name: Some("Contract Reviewer".to_owned()),
        description: None,
        is_system: false,
        is_default_for_new_members: false,
        permissions: vec![permission.clone()],
        created_at: now,
        updated_at: now,
    };
    store.save_role(&role).await.expect("role save must pass");

    let member_id = Uuid::new_v5(&organization_id, b"contract-member");
    let member = Member {
        id: member_id,
        organization_id,
        user_id: "contract-subject".to_owned(),
        email: Some("Person@Example.com".to_owned()),
        status: MemberStatus::Active,
        roles: Vec::new(),
        invited_by: None,
        invited_at: None,
        joined_at: Some(now),
        created_at: now,
        updated_at: now,
    };
    store
        .save_member(&member)
        .await
        .expect("member save must pass");
    store
        .set_member_roles(member_id, &[role.id])
        .await
        .expect("member-role assignment must pass");
    let hydrated_member = store
        .member_by_email_and_organization("person@example.com", organization_id)
        .await
        .expect("case-insensitive member lookup must pass")
        .expect("member must exist");
    assert!(hydrated_member.has_permission(&permission.key(), None));

    let deployment_profile_id = Uuid::new_v5(&organization_id, b"deployment-profile");
    let mut api_key = ApiKey::from_raw(
        ApiKeySpec {
            organization_id,
            name: "contract-key".to_owned(),
            created_by: "owner-subject".to_owned(),
            scopes: Some(vec!["credentials:read".to_owned()]),
            description: None,
            expires_at: Some(now + Duration::days(1)),
            now,
        },
        "mk_test_organization-contract-secret",
    );
    api_key.scope_type = "DEPLOYMENT_PROFILE".to_owned();
    api_key.deployment_profile_id = Some(deployment_profile_id);
    api_key.rate_limit = Some(120);
    store
        .save_api_key(&api_key)
        .await
        .expect("API-key save must pass");
    let stored_key = store
        .api_key_by_hash(&api_key.key_hash)
        .await
        .expect("API-key hash lookup must pass")
        .expect("API key must exist");
    assert_eq!(
        stored_key.deployment_profile_id,
        Some(deployment_profile_id)
    );
    assert_eq!(stored_key.scope_type, "DEPLOYMENT_PROFILE");

    let preference = ConsoleContextPreference {
        id: Uuid::new_v5(&organization_id, b"preference"),
        user_id: "contract-subject".to_owned(),
        last_view_mode: ViewMode::OrgAdmin,
        last_active_org_id: Some(organization_id),
        created_at: now,
        updated_at: now,
    };
    store
        .save_preference(&preference)
        .await
        .expect("preference save must pass");
    assert_eq!(
        store
            .preference_by_user(&preference.user_id)
            .await
            .expect("preference lookup must pass")
            .expect("preference must exist")
            .last_view_mode,
        ViewMode::OrgAdmin
    );

    let join_code = JoinCode {
        id: Uuid::new_v5(&organization_id, b"join-code"),
        organization_id,
        code: "RUST2345".to_owned(),
        created_by: "owner-subject".to_owned(),
        expires_at: Some(now + Duration::hours(1)),
        max_uses: Some(2),
        use_count: 1,
        is_active: true,
        created_at: now,
        updated_at: now,
    };
    store
        .save_join_code(&join_code)
        .await
        .expect("join-code save must pass");
    assert!(store
        .join_code_by_code(&join_code.code)
        .await
        .expect("join-code lookup must pass")
        .expect("join code must exist")
        .is_valid_at(now));

    let policy_set = PolicySet::create(PolicySetSpec {
        organization_id,
        name: "Contract policy".to_owned(),
        cedar_policies: "permit(principal, action, resource);".to_owned(),
        policy_type: PolicySetType::AccessControl,
        description: None,
        created_by: Some("owner-subject".to_owned()),
        cedar_schema_version: None,
        now,
    });
    store
        .save_policy_set(&policy_set)
        .await
        .expect("policy-set save must pass");
    assert_eq!(
        store
            .policy_sets_by_organization(organization_id, Some(PolicySetStatus::Draft))
            .await
            .expect("policy-set list must pass")
            .len(),
        1
    );

    let event = AuditEvent {
        id: Uuid::new_v5(&organization_id, b"audit-event"),
        organization_id,
        event_type: "member.added".to_owned(),
        action: "create".to_owned(),
        category: "team".to_owned(),
        resource_type: "member".to_owned(),
        resource_id: Some(member_id.to_string()),
        resource_name: Some("contract-subject".to_owned()),
        actor_id: Some("owner-subject".to_owned()),
        actor_type: "user".to_owned(),
        severity: "info".to_owned(),
        message: "Contract member added".to_owned(),
        changes: None,
        metadata: json!({"source":"rust-contract"}),
        timestamp: now,
    };
    store
        .save_audit_event(&event)
        .await
        .expect("audit save must pass");
    let events = store
        .list_audit_events(
            organization_id,
            &AuditEventQuery {
                category: Some("team".to_owned()),
                limit: 10,
                ..AuditEventQuery::default()
            },
        )
        .await
        .expect("audit query must pass");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].id, event.id);

    assert!(store
        .delete_organization(organization_id)
        .await
        .expect("organization delete must pass"));
    assert!(store
        .member_by_id(member_id)
        .await
        .expect("cascade member lookup must pass")
        .is_none());
    assert!(store
        .api_key_by_id(api_key.id)
        .await
        .expect("cascade API-key lookup must pass")
        .is_none());
}
