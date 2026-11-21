//! Real owner sources and independent connected roles, not HTTP provider mocks.
use super::*;
use crate::{
    command_postgres::PgOrganizationCommandService, DelegationCommandError,
    DelegationCommandResponse, DelegationCommandResult, GrantStatus, DELEGATION_COMMAND_PROFILE,
};
use serde_json::{json, Value};

struct CommandFixture {
    source: Fixture,
    writer: PgPool,
    writer_role: String,
    host: PgOrganizationCommandService,
}
impl CommandFixture {
    async fn new() -> Option<Self> {
        let source = Fixture::new().await?;
        let writer_role = format!("command_writer_{}", Uuid::new_v4().simple());
        assert!(writer_role
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_'));
        sqlx::raw_sql(AssertSqlSafe(format!(
            "CREATE ROLE {writer_role} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
             GRANT USAGE ON SCHEMA delegated_authority_service TO {writer_role};
             GRANT EXECUTE ON FUNCTION delegated_authority_service.grant_instant(TEXT) TO {writer_role};
             GRANT INSERT,UPDATE ON delegated_authority_service.delegation_grants TO {writer_role};
             GRANT INSERT ON delegated_authority_service.command_results TO {writer_role};
             GRANT SELECT,INSERT ON delegated_authority_service.command_identities TO {writer_role};"
        ))).execute(&source.owner).await.unwrap();
        for table in EVIDENCE_READ_TABLES {
            sqlx::raw_sql(AssertSqlSafe(format!(
                "GRANT SELECT ON delegated_authority_service.{table} TO {writer_role}"
            )))
            .execute(&source.owner)
            .await
            .unwrap();
        }
        let mut url =
            url::Url::parse(&std::env::var("DELEGATED_AUTHORITY_TEST_DATABASE_URL").unwrap())
                .unwrap();
        url.set_username(&writer_role).unwrap();
        let writer = PgPoolOptions::new()
            .max_connections(4)
            .connect(url.as_str())
            .await
            .unwrap();
        let store = PostgresOrganizationStore::new(source.owner.clone());
        for action in ["create", "suspend", "reinstate", "revoke"] {
            let permission = match store
                .permission_by_key("delegation-grant", action)
                .await
                .unwrap()
            {
                Some(permission) => permission,
                None => {
                    let permission = Permission::new("delegation-grant", action);
                    store.save_permission(&permission).await.unwrap();
                    permission
                }
            };
            sqlx::query("INSERT INTO organization_service.role_permissions (role_id,permission_id) VALUES($1,$2) ON CONFLICT DO NOTHING")
                .bind(source.role).bind(permission.id).execute(&source.owner).await.unwrap();
        }
        let host = Self::host_with(&source, &writer, source.configuration.clone());
        Some(Self {
            source,
            writer,
            writer_role,
            host,
        })
    }
    fn host_with(
        source: &Fixture,
        writer: &PgPool,
        configuration: OrganizationApprovalConfiguration,
    ) -> PgOrganizationCommandService {
        PgOrganizationCommandService::new(
            writer.clone(),
            source.read.clone(),
            PostgresOrganizationStore::new(source.organization_read.clone()),
            configuration,
            source.grant.authority.clone(),
            Arc::new(SystemDelegationClock),
        )
        .unwrap()
    }
    async fn execute(
        &self,
        document: &Value,
    ) -> Result<DelegationCommandResponse, DelegationCommandError> {
        self.host
            .execute(
                &self.source.session(),
                &serde_json::to_vec(document).unwrap(),
            )
            .await
    }
    fn command(&self, name: &str, grant: &DelegationGrant) -> Value {
        json!({"profile":DELEGATION_COMMAND_PROFILE, "command":name, "command_id":Uuid::new_v4(),
            "grant":{"id":grant.id,"revision":grant.revision,"terms_digest":grant.terms_digest}})
    }
    async fn remove_permission(&self, action: &str) {
        sqlx::query("DELETE FROM organization_service.role_permissions WHERE role_id=$1 AND permission_id IN
            (SELECT id FROM organization_service.permissions WHERE resource='delegation-grant' AND action=$2)")
            .bind(self.source.role).bind(action).execute(&self.source.owner).await.unwrap();
    }
    async fn command_count(&self) -> i64 {
        self.source.count("command_results").await
    }
    async fn wait_for_grant_lock(&self) {
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND usename=$1 AND wait_event_type='Lock' AND query LIKE '%delegation_grants%FOR UPDATE%')")
                    .bind(&self.writer_role).fetch_one(&self.source.owner).await.unwrap();
                if waiting { break; }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }).await.expect("the command must reach its actual grant-row lock wait");
    }
}
fn snapshot(response: &DelegationCommandResponse) -> &DelegationGrant {
    let DelegationCommandResult::GrantSnapshot { grant } = &response.result;
    grant
}
fn recovery(response: &DelegationCommandResponse) -> Value {
    json!({"profile":DELEGATION_COMMAND_PROFILE,"command":"RECOVER_RESULT",
        "original_command_id":response.original_command_id,"expected_command_digest":response.command_digest})
}

#[tokio::test]
async fn real_command_host_create_and_recovery_require_current_independent_permissions() {
    let Some(f) = CommandFixture::new().await else {
        return;
    };
    f.host.readiness().await.unwrap();
    let create = json!({"profile":DELEGATION_COMMAND_PROFILE,"command":"CREATE_GRANT",
        "command_id":Uuid::new_v4(),"terms":f.source.grant.terms});
    let created = f.execute(&create).await.unwrap();
    assert!(!created.recovered);
    assert_eq!(snapshot(&created).status, GrantStatus::Pending);
    assert_eq!(snapshot(&created).authority, f.source.grant.authority);
    f.remove_permission("create").await;
    let recovered = f.execute(&recovery(&created)).await.unwrap();
    assert!(recovered.recovered);
    assert_eq!(snapshot(&created), snapshot(&recovered));
    // Explicit resubmission of identical bytes is original-result recovery. It
    // cannot execute a new mutation after action permission has been revoked.
    assert!(f.execute(&create).await.unwrap().recovered);
    let mut new_create = create.clone();
    new_create["command_id"] = json!(Uuid::new_v4());
    assert_eq!(
        f.execute(&new_create).await.unwrap_err(),
        DelegationCommandError::AccessDenied
    );
    assert_eq!(f.command_count().await, 1);
    f.remove_permission("view").await;
    assert_eq!(
        f.execute(&recovery(&created)).await.unwrap_err(),
        DelegationCommandError::AccessDenied
    );
}

#[tokio::test]
async fn real_command_host_lifecycle_uses_original_confirmation_and_never_writes_sources() {
    let Some(f) = CommandFixture::new().await else {
        return;
    };
    let (_, _, confirmed) = f.source.confirmed().await;
    let before_consent = f.source.count("consent_confirmations").await;
    let before_authority = f.source.count("organization_authority_observations").await;
    let mut approve = f.command("APPROVE_GRANT", &f.source.grant);
    approve["confirmation_id"] = json!(confirmed.confirmation_id);
    let active = f.execute(&approve).await.unwrap();
    assert_eq!(snapshot(&active).status, GrantStatus::Active);
    let suspended = f
        .execute(&f.command("SUSPEND_GRANT", snapshot(&active)))
        .await
        .unwrap();
    assert_eq!(snapshot(&suspended).status, GrantStatus::Suspended);
    let reinstated = f
        .execute(&f.command("REINSTATE_GRANT", snapshot(&suspended)))
        .await
        .unwrap();
    assert_eq!(snapshot(&reinstated).status, GrantStatus::Active);
    let revoked = f
        .execute(&f.command("REVOKE_GRANT", snapshot(&reinstated)))
        .await
        .unwrap();
    assert_eq!(snapshot(&revoked).status, GrantStatus::Revoked);
    assert_eq!(snapshot(&revoked).revision, 5);
    assert_eq!(
        f.source.count("consent_confirmations").await,
        before_consent
    );
    assert_eq!(
        f.source.count("organization_authority_observations").await,
        before_authority
    );
    assert_eq!(f.command_count().await, 4);
    f.remove_permission("approve").await;
    let historical = f.execute(&recovery(&active)).await.unwrap();
    assert_eq!(snapshot(&historical), snapshot(&active));
    assert_eq!(snapshot(&historical).revision, 2);
}

#[tokio::test]
async fn real_command_host_rejects_wrong_session_pin_and_withdrawn_confirmation() {
    let Some(f) = CommandFixture::new().await else {
        return;
    };
    let (_, _, confirmed) = f.source.confirmed().await;
    let mut approve = f.command("APPROVE_GRANT", &f.source.grant);
    approve["confirmation_id"] = json!(confirmed.confirmation_id);
    let raw = serde_json::to_vec(&approve).unwrap();
    let mut other_session = f.source.session();
    other_session.session_ref = format!("urn:marty:session:sha256:{}", "12".repeat(32));
    assert_eq!(
        f.host.execute(&other_session, &raw).await.unwrap_err(),
        DelegationCommandError::ConfirmationUnavailable
    );
    let mut other_pin = f.source.configuration.clone();
    other_pin.pin.artifact_digest = format!("sha256:{}", "a8".repeat(32));
    let other_host = CommandFixture::host_with(&f.source, &f.writer, other_pin);
    assert_eq!(
        other_host
            .execute(&f.source.session(), &raw)
            .await
            .unwrap_err(),
        DelegationCommandError::ConfirmationUnavailable
    );
    f.source
        .service
        .withdraw(
            &f.source.session(),
            f.source.grant.id,
            confirmed.confirmation_id,
        )
        .await
        .unwrap();
    assert_eq!(
        f.execute(&approve).await.unwrap_err(),
        DelegationCommandError::ConfirmationUnavailable
    );
    assert_eq!(f.command_count().await, 0);
    assert_eq!(
        PgDelegationGrantRepository::new(f.source.read.clone())
            .get(f.source.grant.organization_id, f.source.grant.id)
            .await
            .unwrap()
            .unwrap(),
        f.source.grant
    );
}

#[tokio::test]
async fn real_command_host_rechecks_membership_after_actual_grant_lock_wait() {
    let Some(f) = CommandFixture::new().await else {
        return;
    };
    let command = f.command("REVOKE_GRANT", &f.source.grant);
    let mut blocker = f.source.owner.begin().await.unwrap();
    sqlx::query(
        "SELECT id FROM delegated_authority_service.delegation_grants WHERE id=$1 FOR UPDATE",
    )
    .bind(f.source.grant.id)
    .fetch_one(&mut *blocker)
    .await
    .unwrap();
    let host = f.host.clone();
    let session = f.source.session();
    let raw = serde_json::to_vec(&command).unwrap();
    let work = tokio::spawn(async move { host.execute(&session, &raw).await });
    f.wait_for_grant_lock().await;
    sqlx::query("UPDATE organization_service.members SET status='deactivated' WHERE organization_id=$1 AND user_id=$2")
        .bind(f.source.grant.organization_id).bind(f.source.user.to_string()).execute(&f.source.owner).await.unwrap();
    blocker.rollback().await.unwrap();
    assert_eq!(
        work.await.unwrap().unwrap_err(),
        DelegationCommandError::Unavailable
    );
    let stored = PgDelegationGrantRepository::new(f.source.read.clone())
        .get(f.source.grant.organization_id, f.source.grant.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored, f.source.grant);
    assert_eq!(f.command_count().await, 0);
    assert_eq!(f.source.count("grant_lifecycle_events").await, 1);
}

#[tokio::test]
async fn real_command_host_other_admin_cannot_reinstate_after_grantor_revoked_during_lock() {
    use marty_organization::domain::{Member, MemberStatus};
    let Some(f) = CommandFixture::new().await else {
        return;
    };
    let (_, _, confirmed) = f.source.confirmed().await;
    let mut approve = f.command("APPROVE_GRANT", &f.source.grant);
    approve["confirmation_id"] = json!(confirmed.confirmation_id);
    let active = f.execute(&approve).await.unwrap();
    let suspended = f
        .execute(&f.command("SUSPEND_GRANT", snapshot(&active)))
        .await
        .unwrap();
    let other_user = Uuid::new_v4();
    let member = Member::create(
        f.source.grant.organization_id,
        other_user.to_string(),
        None,
        MemberStatus::Active,
        Utc::now(),
    );
    let store = PostgresOrganizationStore::new(f.source.owner.clone());
    store.save_member(&member).await.unwrap();
    store
        .add_member_role(member.id, f.source.role)
        .await
        .unwrap();
    let mut other_session = f.source.session();
    other_session.user_id = other_user;
    other_session.session_ref = format!("urn:marty:session:sha256:{}", "31".repeat(32));
    let command = f.command("REINSTATE_GRANT", snapshot(&suspended));
    let mut blocker = f.source.owner.begin().await.unwrap();
    sqlx::query(
        "SELECT id FROM delegated_authority_service.delegation_grants WHERE id=$1 FOR UPDATE",
    )
    .bind(f.source.grant.id)
    .fetch_one(&mut *blocker)
    .await
    .unwrap();
    let host = f.host.clone();
    let raw = serde_json::to_vec(&command).unwrap();
    let work = tokio::spawn(async move { host.execute(&other_session, &raw).await });
    f.wait_for_grant_lock().await;
    sqlx::query("UPDATE organization_service.members SET status='deactivated' WHERE organization_id=$1 AND user_id=$2")
        .bind(f.source.grant.organization_id).bind(f.source.user.to_string()).execute(&f.source.owner).await.unwrap();
    blocker.rollback().await.unwrap();
    assert_eq!(
        work.await.unwrap().unwrap_err(),
        DelegationCommandError::Unavailable
    );
    let stored = PgDelegationGrantRepository::new(f.source.read.clone())
        .get(f.source.grant.organization_id, f.source.grant.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&stored, snapshot(&suspended));
    assert_eq!(f.command_count().await, 2);
    assert_eq!(f.source.count("grant_lifecycle_events").await, 3);
}

#[tokio::test]
async fn real_command_host_readiness_rejects_producer_privileges_and_unsafe_role_paths() {
    let Some(f) = CommandFixture::new().await else {
        return;
    };
    f.host.readiness().await.unwrap();
    for (grant, revoke) in [
        (
            format!(
                "GRANT SELECT ON delegated_authority_service.use_receipts TO {}",
                f.writer_role
            ),
            format!(
                "REVOKE SELECT ON delegated_authority_service.use_receipts FROM {}",
                f.writer_role
            ),
        ),
        (
            format!(
                "GRANT INSERT ON delegated_authority_service.consent_confirmations TO {}",
                f.writer_role
            ),
            format!(
                "REVOKE INSERT ON delegated_authority_service.consent_confirmations FROM {}",
                f.writer_role
            ),
        ),
        (
            format!(
                "GRANT UPDATE ON delegated_authority_service.command_results TO {}",
                f.writer_role
            ),
            format!(
                "REVOKE UPDATE ON delegated_authority_service.command_results FROM {}",
                f.writer_role
            ),
        ),
        (
            format!(
                "GRANT INSERT ON organization_service.role_permissions TO {}",
                f.writer_role
            ),
            format!(
                "REVOKE INSERT ON organization_service.role_permissions FROM {}",
                f.writer_role
            ),
        ),
    ] {
        sqlx::raw_sql(AssertSqlSafe(grant))
            .execute(&f.source.owner)
            .await
            .unwrap();
        assert!(f.host.readiness().await.is_err());
        sqlx::raw_sql(AssertSqlSafe(revoke))
            .execute(&f.source.owner)
            .await
            .unwrap();
        f.host.readiness().await.unwrap();
    }
    let unsafe_role = format!("command_unsafe_{}", Uuid::new_v4().simple());
    sqlx::raw_sql(AssertSqlSafe(format!(
        "CREATE ROLE {unsafe_role} NOLOGIN CREATEROLE; GRANT {unsafe_role} TO {}",
        f.writer_role
    )))
    .execute(&f.source.owner)
    .await
    .unwrap();
    assert!(f.host.readiness().await.is_err());
    sqlx::raw_sql(AssertSqlSafe(format!(
        "REVOKE {unsafe_role} FROM {}",
        f.writer_role
    )))
    .execute(&f.source.owner)
    .await
    .unwrap();
    f.host.readiness().await.unwrap();
    let same_role = PgOrganizationCommandService::new(
        f.writer.clone(),
        f.writer.clone(),
        PostgresOrganizationStore::new(f.source.organization_read.clone()),
        f.source.configuration.clone(),
        f.source.grant.authority.clone(),
        Arc::new(SystemDelegationClock),
    )
    .unwrap();
    assert!(same_role.readiness().await.is_err());
}
