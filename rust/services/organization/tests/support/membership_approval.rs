//! Executed by the existing organization_application PostgreSQL CI obligation.
use std::{str::FromStr, sync::Arc, time::Duration};

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use chrono::{TimeDelta, Timelike, Utc};
use marty_organization::{
    organization_core_router,
    postgres::{PostgresOrganizationStore, RepositoryError},
    ApproveMemberCommand, AuditEventQuery, CreateOrganizationCommand, DomainError,
    InviteMemberCommand, JoinMechanism, JoinOrganizationCommand, Member, MemberStatus,
    OrganizationApplication, OrganizationApplicationError, OrganizationCache,
    OrganizationCacheKeys, OrganizationHttpState, OrganizationType, PrincipalSource,
};
use mmf_data::{CacheStore, MemoryCache};
use mmf_security::ServiceTokenAuthenticator;
use serde_json::Value;
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    PgPool,
};
use tower::ServiceExt;
use uuid::Uuid;

const TOKEN: &str = "0123456789abcdef0123456789abcdef";
const REVIEWER: &str = "approval-contract-owner";

async fn waiting_for_member_locks(pool: &PgPool, application_name: &str, expected: i64) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let waiting: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM pg_stat_activity WHERE application_name=$1
                 AND wait_event_type='Lock' AND query LIKE '%organization_service.members%FOR UPDATE%'",
            )
            .bind(application_name)
            .fetch_one(pool)
            .await
            .unwrap();
            if waiting >= expected { break; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("competing approvals must reach the held member lock");
}

fn approval(member: &Member) -> ApproveMemberCommand {
    ApproveMemberCommand {
        organization_id: member.organization_id,
        member_id: member.id,
        approved_by: REVIEWER.into(),
        approved_by_source: PrincipalSource::Session,
        now: member.created_at + TimeDelta::minutes(1),
    }
}

async fn pending(
    application: &OrganizationApplication,
    organization_id: Uuid,
    user: &str,
    seconds: i64,
) -> Member {
    application
        .join_organization(JoinOrganizationCommand {
            organization_id,
            user_id: user.into(),
            email: format!("{user}@example.test"),
            now: Utc::now().with_nanosecond(0).unwrap() + TimeDelta::seconds(seconds),
        })
        .await
        .unwrap()
        .value
        .1
}

async fn call(router: &axum::Router, method: &str, path: &str, user: &str) -> (StatusCode, Value) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header("x-service-token", TOKEN)
                .header("x-user-id", user)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

async fn approval_audit_count(
    application: &OrganizationApplication,
    organization_id: Uuid,
) -> usize {
    application
        .store()
        .list_audit_events(
            organization_id,
            &AuditEventQuery {
                action: Some("team.member.approved".into()),
                limit: 100,
                ..AuditEventQuery::default()
            },
        )
        .await
        .unwrap()
        .len()
}

async fn call_as_api_key(
    router: &axum::Router,
    path: &str,
    organization_id: Uuid,
) -> (StatusCode, Value) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("x-service-token", TOKEN)
                .header("x-user-id", "api_key:reviewer-key")
                .header("x-api-key-id", "reviewer-key")
                .header("x-organization-id", organization_id.to_string())
                .header("x-required-permission", "team:manage")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

async fn approval_outbox_count(pool: &PgPool, organization_id: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM mmf_messaging.outbox_messages
        WHERE source_service='organization' AND tenant_id=$1
        AND message->>'message_type'='member.approved.event'",
    )
    .bind(organization_id.to_string())
    .fetch_one(pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn pending_approval_is_tenant_scoped_atomic_and_single_winner_when_configured() {
    let Ok(database_url) = std::env::var("ORGANIZATION_POSTGRES_TEST_URL") else {
        eprintln!("PostgreSQL membership approval regression NOT EXECUTED: ORGANIZATION_POSTGRES_TEST_URL is absent");
        return;
    };
    let application_name = format!("membership-approval-{}", Uuid::new_v4().simple());
    let pool = PgPoolOptions::new()
        .max_connections(6)
        .connect_with(
            PgConnectOptions::from_str(&database_url)
                .unwrap()
                .application_name(&application_name),
        )
        .await
        .expect("organization approval PostgreSQL contract database must connect");
    let memberships = Arc::new(MemoryCache::default());
    let permissions = Arc::new(MemoryCache::default());
    let application = Arc::new(
        OrganizationApplication::new(
            PostgresOrganizationStore::new(pool.clone()),
            OrganizationCache::new(
                memberships.clone(),
                permissions.clone(),
                Arc::new(MemoryCache::default()),
            ),
        )
        .unwrap(),
    );
    application.initialize().await.unwrap();
    let now = Utc::now().with_nanosecond(0).unwrap();
    let organization_id = application
        .create_organization(CreateOrganizationCommand {
            name: format!("approval-contract-{}", Uuid::new_v4().simple()),
            owner_id: REVIEWER.into(),
            org_type: OrganizationType::Education,
            display_name: None,
            description: None,
            contact_email: None,
            visibility: "PUBLIC".into(),
            join_mechanism: JoinMechanism::Open,
            requires_approval: true,
            now,
        })
        .await
        .unwrap()
        .value
        .id;
    let original = pending(&application, organization_id, "approval-first", 1).await;
    assert_eq!(original.status, MemberStatus::Pending);
    let key = OrganizationCacheKeys::member(&original.user_id, organization_id).unwrap();
    memberships
        .set(&key, b"pending-membership".to_vec(), None, 0)
        .await
        .unwrap();
    permissions
        .set(&key, b"pending-permissions".to_vec(), None, 0)
        .await
        .unwrap();

    // Hold the persisted row until both callers are waiting, then release them together.
    // Without the row lock/current-state check both decisions can write Active and emit events.
    let mut held = application.store().begin_transaction().await.unwrap();
    application
        .store()
        .member_by_id_for_update_in_transaction(&mut held, original.id)
        .await
        .unwrap()
        .unwrap();
    let left_app = application.clone();
    let right_app = application.clone();
    let command = approval(&original);
    let right_command = command.clone();
    let left = tokio::spawn(async move { left_app.approve_member(command).await });
    let right = tokio::spawn(async move { right_app.approve_member(right_command).await });
    waiting_for_member_locks(&pool, &application_name, 2).await;
    assert!(memberships.exists(&key, 0).await.unwrap());
    assert!(permissions.exists(&key, 0).await.unwrap());
    held.commit().await.unwrap();
    let (left, right) = tokio::time::timeout(Duration::from_secs(10), async {
        (left.await.unwrap(), right.await.unwrap())
    })
    .await
    .expect("approval decisions must finish after releasing the row");
    let results = [left, right];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(
                result,
                Err(OrganizationApplicationError::Domain(
                    DomainError::MembershipNotPending
                ))
            ))
            .count(),
        1
    );
    let saved = application
        .store()
        .member_by_id(original.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(saved.status, MemberStatus::Active);
    assert_eq!(saved.joined_at, Some(approval(&original).now));
    assert_eq!(saved.updated_at, approval(&original).now);
    assert_eq!(saved.created_at, original.created_at);
    assert_eq!(saved.user_id, original.user_id);
    assert_eq!(saved.email, original.email);
    assert_eq!(saved.roles, original.roles);
    assert!(!memberships.exists(&key, 0).await.unwrap());
    assert!(!permissions.exists(&key, 0).await.unwrap());
    assert_eq!(approval_audit_count(&application, organization_id).await, 1);
    assert_eq!(approval_outbox_count(&pool, organization_id).await, 1);
    let audit = application
        .store()
        .list_audit_events(
            organization_id,
            &AuditEventQuery {
                action: Some("team.member.approved".into()),
                limit: 10,
                ..AuditEventQuery::default()
            },
        )
        .await
        .unwrap()
        .remove(0);
    assert_eq!(audit.actor_id.as_deref(), Some(REVIEWER));
    assert_eq!(audit.actor_type, "user");
    assert_eq!(
        audit.resource_id.as_deref(),
        Some(original.id.to_string().as_str())
    );
    let outbox: Value = sqlx::query_scalar(
        "SELECT message FROM mmf_messaging.outbox_messages
        WHERE tenant_id=$1 AND message->>'message_type'='member.approved.event'",
    )
    .bind(organization_id.to_string())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(outbox["payload"]["data"]["approved_by"], REVIEWER);
    assert_eq!(outbox["payload"]["data"]["user_id"], original.user_id);
    assert_eq!(
        audit.metadata["source_event_id"],
        outbox["metadata"]["message_id"]
    );

    let pending_a = pending(&application, organization_id, "approval-second", 2).await;
    let pending_b = pending(&application, organization_id, "approval-third", 3).await;
    let deactivated = Member::create(
        organization_id,
        "deactivated-member",
        None,
        MemberStatus::Deactivated,
        now,
    );
    application.store().save_member(&deactivated).await.unwrap();

    // Model the parent-first lock held by join_organization. Approval must not
    // wait on it while retaining the target lock; audit's parent FK needs the
    // same key-share lock, so this guard must run before state/audit writes.
    let contention_key =
        OrganizationCacheKeys::member(&pending_b.user_id, organization_id).unwrap();
    memberships
        .set(&contention_key, b"pending".to_vec(), None, 0)
        .await
        .unwrap();
    permissions
        .set(&contention_key, b"pending".to_vec(), None, 0)
        .await
        .unwrap();
    let mut joining = application.store().begin_transaction().await.unwrap();
    application
        .store()
        .organization_by_id_for_update_in_transaction(&mut joining, organization_id)
        .await
        .unwrap()
        .unwrap();
    let contention = tokio::time::timeout(
        Duration::from_secs(2),
        application.approve_member(approval(&pending_b)),
    )
    .await
    .expect("approval must fail promptly instead of completing a join lock cycle")
    .expect_err("the parent row is held by a join transaction");
    match contention {
        OrganizationApplicationError::Repository(RepositoryError::Database(
            sqlx::Error::Database(error),
        )) => {
            assert_eq!(error.code().as_deref(), Some("55P03"));
        }
        other => panic!("expected pre-write lock contention, got {other}"),
    }
    let still_pending = tokio::time::timeout(
        Duration::from_secs(2),
        application
            .store()
            .member_by_id_for_update_in_transaction(&mut joining, pending_b.id),
    )
    .await
    .expect("failed approval must release the member for the parent-first join")
    .unwrap()
    .unwrap();
    assert_eq!(still_pending, pending_b);
    assert_eq!(approval_audit_count(&application, organization_id).await, 1);
    assert_eq!(approval_outbox_count(&pool, organization_id).await, 1);
    assert!(memberships.exists(&contention_key, 0).await.unwrap());
    assert!(permissions.exists(&contention_key, 0).await.unwrap());
    joining.commit().await.unwrap();
    let invitation = application
        .invite_member(InviteMemberCommand {
            organization_id,
            email: "invited@example.test".into(),
            role_ids: original.roles.iter().map(|role| role.id).collect(),
            invited_by: REVIEWER.into(),
            now: now + TimeDelta::seconds(4),
        })
        .await
        .unwrap()
        .value;
    let router = organization_core_router(OrganizationHttpState {
        application: application.clone(),
        service_authenticator: Arc::new(
            ServiceTokenAuthenticator::new(Some(TOKEN.into()), true).unwrap(),
        ),
        organization_creation_enabled: true,
        marty_organization_id: None,
    });
    for (offset, expected) in [(0, Some(pending_a.id)), (1, Some(pending_b.id)), (2, None)] {
        let (status, body) = call(
            &router,
            "GET",
            &format!(
            "/v1/organizations/{organization_id}/members?status=pending&limit=1&offset={offset}"),
            REVIEWER,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let rows = body.as_array().unwrap();
        if let Some(id) = expected {
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0]["id"], id.to_string());
            assert_eq!(rows[0]["status"], "pending");
        } else {
            assert!(rows.is_empty());
        }
    }
    let (status, snapshot) = call(
        &router,
        "GET",
        &format!("/v1/organizations/{organization_id}/team/snapshot"),
        REVIEWER,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(snapshot["pending_invites"].as_array().unwrap().len(), 1);
    assert_eq!(
        snapshot["pending_invites"][0]["id"],
        invitation.id.to_string()
    );

    let mut wrong_tenant = approval(&pending_a);
    wrong_tenant.organization_id = Uuid::new_v4();
    assert!(matches!(
        application.approve_member(wrong_tenant).await,
        Err(OrganizationApplicationError::MemberNotFound(_))
    ));
    let pending_path = format!(
        "/v1/organizations/{organization_id}/members/{}/approve",
        pending_a.id
    );
    let (status, _) = call(&router, "POST", &pending_path, &pending_a.user_id).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a pending applicant cannot approve itself"
    );
    for member in [&saved, &invitation, &deactivated] {
        let (status, body) = call(
            &router,
            "POST",
            &format!(
                "/v1/organizations/{organization_id}/members/{}/approve",
                member.id
            ),
            REVIEWER,
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["detail"], "ORGANIZATION.MEMBERSHIP_NOT_PENDING");
    }
    let (status, _) = call(
        &router,
        "POST",
        &format!(
            "/v1/organizations/{organization_id}/members/{}/approve",
            Uuid::new_v4()
        ),
        REVIEWER,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(approval_audit_count(&application, organization_id).await, 1);

    let other_organization_id = Uuid::new_v4();
    let (status, _) = call_as_api_key(
        &router,
        &format!(
            "/v1/organizations/{other_organization_id}/members/{}/approve",
            pending_a.id
        ),
        other_organization_id,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "an authorized reviewer in another tenant cannot approve this member"
    );

    // Reject only this test organization's next approval outbox row. Audit insertion
    // has already run at that point, so the failure must roll both state and audit back.
    let rollback_key = OrganizationCacheKeys::member(&pending_a.user_id, organization_id).unwrap();
    memberships
        .set(&rollback_key, b"still-pending".to_vec(), None, 0)
        .await
        .unwrap();
    permissions
        .set(&rollback_key, b"still-pending".to_vec(), None, 0)
        .await
        .unwrap();
    let constraint = format!("approval_outbox_{}", Uuid::new_v4().simple());
    // Audited dynamic DDL: the identifier is a fixed prefix plus generated UUID hex,
    // and the tenant literal is a typed UUID. Neither value is external SQL input.
    sqlx::query(sqlx::AssertSqlSafe(format!("ALTER TABLE mmf_messaging.outbox_messages ADD CONSTRAINT {constraint}
        CHECK (tenant_id <> '{organization_id}' OR message->>'message_type' <> 'member.approved.event') NOT VALID")))
        .execute(&pool).await.unwrap();
    let failed = application.approve_member(approval(&pending_a)).await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "ALTER TABLE mmf_messaging.outbox_messages DROP CONSTRAINT {constraint}"
    )))
    .execute(&pool)
    .await
    .unwrap();
    assert!(matches!(
        failed,
        Err(OrganizationApplicationError::Messaging(_))
    ));
    let unchanged = application
        .store()
        .member_by_id(pending_a.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        unchanged, pending_a,
        "failed outbox write must not activate or rewrite the membership"
    );
    assert_eq!(approval_audit_count(&application, organization_id).await, 1);
    assert_eq!(approval_outbox_count(&pool, organization_id).await, 1);
    assert!(memberships.exists(&rollback_key, 0).await.unwrap());
    assert!(permissions.exists(&rollback_key, 0).await.unwrap());

    let (status, approved) = call(&router, "POST", &pending_path, REVIEWER).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(approved["id"], pending_a.id.to_string());
    assert_eq!(approved["organization_id"], organization_id.to_string());
    assert_eq!(approved["user_id"], pending_a.user_id);
    assert_eq!(approved["email"], pending_a.email.unwrap());
    assert_eq!(approved["status"], "active");
    assert!(approved["joined_at"].is_string());
    assert!(approved["roles"]
        .as_array()
        .is_some_and(|roles| !roles.is_empty()));
    assert_eq!(approval_audit_count(&application, organization_id).await, 2);
    assert_eq!(approval_outbox_count(&pool, organization_id).await, 2);
    assert!(!memberships.exists(&rollback_key, 0).await.unwrap());
    assert!(!permissions.exists(&rollback_key, 0).await.unwrap());

    let (status, approved_by_key) = call_as_api_key(
        &router,
        &format!(
            "/v1/organizations/{organization_id}/members/{}/approve",
            pending_b.id
        ),
        organization_id,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "approval can be retried after parent contention clears"
    );
    assert_eq!(approved_by_key["status"], "active");
    let audit = application
        .store()
        .list_audit_events(
            organization_id,
            &AuditEventQuery {
                action: Some("team.member.approved".into()),
                limit: 100,
                ..AuditEventQuery::default()
            },
        )
        .await
        .unwrap()
        .into_iter()
        .find(|event| event.resource_id.as_deref() == Some(pending_b.id.to_string().as_str()))
        .unwrap();
    assert_eq!(audit.actor_id.as_deref(), Some("api_key:reviewer-key"));
    assert_eq!(audit.actor_type, "api_key");
    assert_eq!(approval_audit_count(&application, organization_id).await, 3);
    assert_eq!(approval_outbox_count(&pool, organization_id).await, 3);
    assert!(!memberships.exists(&contention_key, 0).await.unwrap());
    assert!(!permissions.exists(&contention_key, 0).await.unwrap());

    application
        .store()
        .delete_organization(organization_id)
        .await
        .unwrap();
    sqlx::query("DELETE FROM mmf_messaging.outbox_messages WHERE source_service='organization' AND tenant_id=$1")
        .bind(organization_id.to_string()).execute(&pool).await.unwrap();
    pool.close().await;
}
