use std::sync::Arc;

use chrono::Utc;
use marty_organization::postgres::PostgresOrganizationStore;
use marty_organization::{
    AcceptInvitationCommand, AddMemberDirectCommand, CreateOrganizationCommand,
    InviteMemberCommand, JoinByCodeCommand, JoinCode, JoinMechanism, JoinOrganizationCommand,
    OrganizationApplication, OrganizationApplicationError, OrganizationCache, OrganizationType,
    RemoveMemberCommand, SetMemberRolesCommand, UpdateOrganizationCommand, UpdateOrganizationPatch,
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

    let roles = application
        .store()
        .roles_by_organization(organization_id)
        .await
        .expect("role lookup must pass");
    let applicant_role = roles
        .iter()
        .find(|role| role.name == "applicant")
        .expect("applicant role")
        .clone();
    let reviewer_role = roles
        .iter()
        .find(|role| role.name == "reviewer")
        .expect("reviewer role")
        .clone();

    let owner_role_error = application
        .set_member_roles(SetMemberRolesCommand {
            member_id: owner.id,
            organization_id,
            role_ids: vec![applicant_role.id],
            updated_by: "application-owner".into(),
            now: Utc::now(),
        })
        .await
        .expect_err("owner role removal must fail closed");
    assert!(matches!(
        owner_role_error,
        OrganizationApplicationError::OwnerRoleRequired
    ));

    let invitation = application
        .invite_member(InviteMemberCommand {
            organization_id,
            email: "invited@example.com".into(),
            role_ids: vec![applicant_role.id],
            invited_by: "application-owner".into(),
            now: Utc::now(),
        })
        .await
        .expect("invitation must commit");
    let accepted = application
        .accept_invitation(AcceptInvitationCommand {
            member_id: invitation.value.id,
            user_id: "invited-user".into(),
            now: Utc::now(),
        })
        .await
        .expect("invitation acceptance must commit");
    let assigned = application
        .set_member_roles(SetMemberRolesCommand {
            member_id: accepted.value.id,
            organization_id,
            role_ids: vec![reviewer_role.id],
            updated_by: "application-owner".into(),
            now: Utc::now(),
        })
        .await
        .expect("member role replacement must commit");
    assert_eq!(assigned.value.roles[0].name, "reviewer");
    application
        .remove_member(RemoveMemberCommand {
            member_id: accepted.value.id,
            removed_by: "application-owner".into(),
            now: Utc::now(),
        })
        .await
        .expect("member removal must commit");
    assert!(application
        .get_membership("invited-user", organization_id)
        .await
        .expect("membership lookup must pass")
        .is_none());

    let join_code = JoinCode {
        id: uuid::Uuid::new_v4(),
        organization_id,
        code: format!("RUST{}", &organization_id.simple().to_string()[..8]).to_uppercase(),
        created_by: "application-owner".into(),
        expires_at: None,
        max_uses: Some(2),
        use_count: 0,
        is_active: true,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    application
        .store()
        .save_join_code(&join_code)
        .await
        .expect("join-code seed must pass");
    let joined_by_code = application
        .join_by_code(JoinByCodeCommand {
            user_id: "code-user".into(),
            code: join_code.code.to_lowercase(),
            email: "code@example.com".into(),
            now: Utc::now(),
        })
        .await
        .expect("code join must commit");
    assert!(joined_by_code.value.1.has_role(&["applicant"]));
    assert_eq!(
        application
            .store()
            .join_code_by_code(&join_code.code)
            .await
            .expect("join-code lookup must pass")
            .expect("join code must exist")
            .use_count,
        1
    );

    let joined_directly = application
        .join_organization(JoinOrganizationCommand {
            user_id: "open-user".into(),
            organization_id,
            email: "open@example.com".into(),
            now: Utc::now(),
        })
        .await
        .expect("open join must commit");
    assert!(joined_directly.value.1.has_role(&["applicant"]));
    let provisioned = application
        .add_member_direct(AddMemberDirectCommand {
            organization_id,
            user_id: "provisioned-user".into(),
            email: Some("provisioned@example.com".into()),
            role_ids: Some(vec![reviewer_role.id]),
            now: Utc::now(),
        })
        .await
        .expect("direct provisioning must commit");
    assert!(provisioned.value.has_role(&["reviewer"]));

    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM organization_service.audit_events WHERE organization_id=$1",
        )
        .bind(organization_id)
        .fetch_one(&pool)
        .await
        .expect("final audit count must pass"),
        8
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM mmf_messaging.outbox_messages
             WHERE source_service='organization' AND tenant_id=$1",
        )
        .bind(organization_id.to_string())
        .fetch_one(&pool)
        .await
        .expect("final outbox count must pass"),
        8
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
