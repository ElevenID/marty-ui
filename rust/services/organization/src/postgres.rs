use serde_json::Value;
use sqlx::{postgres::PgRow, PgConnection, PgPool, Postgres, QueryBuilder, Row, Transaction};
use thiserror::Error;
use uuid::Uuid;

use crate::domain::{
    ApiKey, ApiKeyStatus, AuditEvent, AuditEventQuery, ConsoleContextPreference, JoinCode,
    JoinMechanism, Member, MemberStatus, Organization, OrganizationStatus, OrganizationType,
    Permission, PolicySet, PolicySetStatus, PolicySetType, Role, ViewMode,
};

#[derive(Debug, Error)]
pub enum RepositoryError {
    #[error("ORGANIZATION.REPOSITORY_DATABASE: {0}")]
    Database(#[from] sqlx::Error),
    #[error("ORGANIZATION.REPOSITORY_INVALID_DATA: {field}={value}")]
    InvalidData { field: &'static str, value: String },
}

#[derive(Debug, Clone)]
pub struct PostgresOrganizationStore {
    pool: PgPool,
}

impl PostgresOrganizationStore {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn begin_transaction(&self) -> Result<Transaction<'_, Postgres>, RepositoryError> {
        self.pool.begin().await.map_err(RepositoryError::from)
    }

    pub async fn save_organization(
        &self,
        organization: &Organization,
    ) -> Result<(), RepositoryError> {
        let mut connection = self.pool.acquire().await?;
        save_organization_on(&mut connection, organization).await
    }

    pub async fn save_organization_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        organization: &Organization,
    ) -> Result<(), RepositoryError> {
        save_organization_on(&mut *transaction, organization).await
    }

    pub async fn organization_by_id(
        &self,
        organization_id: Uuid,
    ) -> Result<Option<Organization>, RepositoryError> {
        let row = sqlx::query("SELECT * FROM organization_service.organizations WHERE id=$1")
            .bind(organization_id)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(organization_from_row).transpose()
    }

    pub async fn organization_by_id_for_update_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        organization_id: Uuid,
    ) -> Result<Option<Organization>, RepositoryError> {
        let row =
            sqlx::query("SELECT * FROM organization_service.organizations WHERE id=$1 FOR UPDATE")
                .bind(organization_id)
                .fetch_optional(&mut **transaction)
                .await?;
        row.as_ref().map(organization_from_row).transpose()
    }

    pub async fn organization_by_slug(
        &self,
        slug: &str,
    ) -> Result<Option<Organization>, RepositoryError> {
        let row = sqlx::query("SELECT * FROM organization_service.organizations WHERE slug=$1")
            .bind(slug)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(organization_from_row).transpose()
    }

    pub async fn list_organizations(
        &self,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<Organization>, RepositoryError> {
        let rows = sqlx::query(
            "SELECT * FROM organization_service.organizations
             ORDER BY created_at DESC LIMIT $1 OFFSET $2",
        )
        .bind(i64::from(limit.min(1_000)))
        .bind(i64::from(offset))
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(organization_from_row).collect()
    }

    pub async fn list_discoverable_organizations(
        &self,
        search: Option<&str>,
        org_type: Option<OrganizationType>,
        join_mechanism: Option<JoinMechanism>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<Organization>, RepositoryError> {
        let rows = sqlx::query(
            "SELECT * FROM organization_service.organizations
             WHERE is_discoverable=true AND status='active'
               AND ($1::text IS NULL OR name ILIKE '%' || $1 || '%'
                    OR display_name ILIKE '%' || $1 || '%')
               AND ($2::text IS NULL OR org_type=$2)
               AND ($3::text IS NULL OR join_mechanism=$3)
             ORDER BY created_at DESC LIMIT $4 OFFSET $5",
        )
        .bind(search)
        .bind(org_type.map(OrganizationType::as_str))
        .bind(join_mechanism.map(JoinMechanism::as_str))
        .bind(i64::from(limit.min(1_000)))
        .bind(i64::from(offset))
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(organization_from_row).collect()
    }

    pub async fn delete_organization(
        &self,
        organization_id: Uuid,
    ) -> Result<bool, RepositoryError> {
        let result = sqlx::query("DELETE FROM organization_service.organizations WHERE id=$1")
            .bind(organization_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn save_member(&self, member: &Member) -> Result<(), RepositoryError> {
        let mut connection = self.pool.acquire().await?;
        save_member_on(&mut connection, member).await
    }

    pub async fn save_member_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        member: &Member,
    ) -> Result<(), RepositoryError> {
        save_member_on(&mut *transaction, member).await
    }

    pub async fn member_by_id(&self, member_id: Uuid) -> Result<Option<Member>, RepositoryError> {
        let row = sqlx::query("SELECT * FROM organization_service.members WHERE id=$1")
            .bind(member_id)
            .fetch_optional(&self.pool)
            .await?;
        self.hydrate_optional_member(row).await
    }

    pub async fn member_by_id_for_update_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        member_id: Uuid,
    ) -> Result<Option<Member>, RepositoryError> {
        let row = sqlx::query("SELECT * FROM organization_service.members WHERE id=$1 FOR UPDATE")
            .bind(member_id)
            .fetch_optional(&mut **transaction)
            .await?;
        hydrate_optional_member_in_transaction(transaction, row).await
    }

    pub async fn member_by_user_and_organization(
        &self,
        user_id: &str,
        organization_id: Uuid,
    ) -> Result<Option<Member>, RepositoryError> {
        let row = sqlx::query(
            "SELECT * FROM organization_service.members
             WHERE user_id=$1 AND organization_id=$2",
        )
        .bind(user_id)
        .bind(organization_id)
        .fetch_optional(&self.pool)
        .await?;
        self.hydrate_optional_member(row).await
    }

    pub async fn member_by_user_and_organization_for_update_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        user_id: &str,
        organization_id: Uuid,
    ) -> Result<Option<Member>, RepositoryError> {
        let row = sqlx::query(
            "SELECT * FROM organization_service.members
             WHERE user_id=$1 AND organization_id=$2 FOR UPDATE",
        )
        .bind(user_id)
        .bind(organization_id)
        .fetch_optional(&mut **transaction)
        .await?;
        hydrate_optional_member_in_transaction(transaction, row).await
    }

    pub async fn member_by_email_and_organization(
        &self,
        email: &str,
        organization_id: Uuid,
    ) -> Result<Option<Member>, RepositoryError> {
        let row = sqlx::query(
            "SELECT * FROM organization_service.members
             WHERE lower(email)=lower($1) AND organization_id=$2",
        )
        .bind(email)
        .bind(organization_id)
        .fetch_optional(&self.pool)
        .await?;
        self.hydrate_optional_member(row).await
    }

    pub async fn member_by_email_and_organization_for_update_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        email: &str,
        organization_id: Uuid,
    ) -> Result<Option<Member>, RepositoryError> {
        let row = sqlx::query(
            "SELECT * FROM organization_service.members
             WHERE lower(email)=lower($1) AND organization_id=$2 FOR UPDATE",
        )
        .bind(email)
        .bind(organization_id)
        .fetch_optional(&mut **transaction)
        .await?;
        hydrate_optional_member_in_transaction(transaction, row).await
    }

    pub async fn members_by_organization(
        &self,
        organization_id: Uuid,
    ) -> Result<Vec<Member>, RepositoryError> {
        let rows = sqlx::query(
            "SELECT * FROM organization_service.members
             WHERE organization_id=$1 ORDER BY created_at,id",
        )
        .bind(organization_id)
        .fetch_all(&self.pool)
        .await?;
        self.hydrate_members(rows).await
    }

    pub async fn memberships_by_user(&self, user_id: &str) -> Result<Vec<Member>, RepositoryError> {
        let rows = sqlx::query(
            "SELECT * FROM organization_service.members WHERE user_id=$1 ORDER BY created_at,id",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        self.hydrate_members(rows).await
    }

    pub async fn delete_member(&self, member_id: Uuid) -> Result<bool, RepositoryError> {
        let result = sqlx::query("DELETE FROM organization_service.members WHERE id=$1")
            .bind(member_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn delete_member_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        member_id: Uuid,
    ) -> Result<bool, RepositoryError> {
        let result = sqlx::query("DELETE FROM organization_service.members WHERE id=$1")
            .bind(member_id)
            .execute(&mut **transaction)
            .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn hydrate_optional_member(
        &self,
        row: Option<PgRow>,
    ) -> Result<Option<Member>, RepositoryError> {
        match row {
            Some(row) => Ok(Some(self.hydrate_member(&row).await?)),
            None => Ok(None),
        }
    }

    async fn hydrate_members(&self, rows: Vec<PgRow>) -> Result<Vec<Member>, RepositoryError> {
        let mut members = Vec::with_capacity(rows.len());
        for row in rows {
            members.push(self.hydrate_member(&row).await?);
        }
        Ok(members)
    }

    async fn hydrate_member(&self, row: &PgRow) -> Result<Member, RepositoryError> {
        let member_id: Uuid = row.try_get("id")?;
        let mut member = member_from_row(row)?;
        member.roles = self.roles_for_member(member_id).await?;
        Ok(member)
    }

    pub async fn save_api_key(&self, api_key: &ApiKey) -> Result<(), RepositoryError> {
        let mut connection = self.pool.acquire().await?;
        save_api_key_on(&mut connection, api_key).await
    }

    pub async fn save_api_key_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        api_key: &ApiKey,
    ) -> Result<(), RepositoryError> {
        save_api_key_on(&mut *transaction, api_key).await
    }

    pub async fn api_key_by_id(&self, key_id: Uuid) -> Result<Option<ApiKey>, RepositoryError> {
        self.api_key_by("id", key_id.to_string()).await
    }

    pub async fn api_key_by_id_for_update_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        key_id: Uuid,
    ) -> Result<Option<ApiKey>, RepositoryError> {
        let row = sqlx::query("SELECT * FROM organization_service.api_keys WHERE id=$1 FOR UPDATE")
            .bind(key_id)
            .fetch_optional(&mut **transaction)
            .await?;
        row.as_ref().map(api_key_from_row).transpose()
    }

    pub async fn api_key_by_hash(&self, key_hash: &str) -> Result<Option<ApiKey>, RepositoryError> {
        self.api_key_by("key_hash", key_hash.to_owned()).await
    }

    async fn api_key_by(
        &self,
        column: &'static str,
        value: String,
    ) -> Result<Option<ApiKey>, RepositoryError> {
        let sql = match column {
            "id" => "SELECT * FROM organization_service.api_keys WHERE id::text=$1",
            "key_hash" => "SELECT * FROM organization_service.api_keys WHERE key_hash=$1",
            _ => unreachable!("API-key lookup columns are static"),
        };
        let row = sqlx::query(sql)
            .bind(value)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(api_key_from_row).transpose()
    }

    pub async fn api_keys_by_organization(
        &self,
        organization_id: Uuid,
    ) -> Result<Vec<ApiKey>, RepositoryError> {
        let rows = sqlx::query(
            "SELECT * FROM organization_service.api_keys
             WHERE organization_id=$1 ORDER BY created_at DESC,id",
        )
        .bind(organization_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(api_key_from_row).collect()
    }

    pub async fn delete_api_key(&self, key_id: Uuid) -> Result<bool, RepositoryError> {
        let result = sqlx::query("DELETE FROM organization_service.api_keys WHERE id=$1")
            .bind(key_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn save_preference(
        &self,
        preference: &ConsoleContextPreference,
    ) -> Result<(), RepositoryError> {
        let mut connection = self.pool.acquire().await?;
        save_preference_on(&mut connection, preference).await
    }

    pub async fn save_preference_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        preference: &ConsoleContextPreference,
    ) -> Result<(), RepositoryError> {
        save_preference_on(&mut *transaction, preference).await
    }

    pub async fn preference_by_user(
        &self,
        user_id: &str,
    ) -> Result<Option<ConsoleContextPreference>, RepositoryError> {
        let row = sqlx::query(
            "SELECT * FROM organization_service.console_context_preferences WHERE user_id=$1",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(preference_from_row).transpose()
    }

    pub async fn preference_by_user_for_update_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        user_id: &str,
    ) -> Result<Option<ConsoleContextPreference>, RepositoryError> {
        let row = sqlx::query(
            "SELECT * FROM organization_service.console_context_preferences
             WHERE user_id=$1 FOR UPDATE",
        )
        .bind(user_id)
        .fetch_optional(&mut **transaction)
        .await?;
        row.as_ref().map(preference_from_row).transpose()
    }

    pub async fn save_join_code(&self, join_code: &JoinCode) -> Result<(), RepositoryError> {
        let mut connection = self.pool.acquire().await?;
        save_join_code_on(&mut connection, join_code).await
    }

    pub async fn save_join_code_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        join_code: &JoinCode,
    ) -> Result<(), RepositoryError> {
        save_join_code_on(&mut *transaction, join_code).await
    }

    pub async fn join_code_by_code_for_update_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        code: &str,
    ) -> Result<Option<JoinCode>, RepositoryError> {
        let row =
            sqlx::query("SELECT * FROM organization_service.join_codes WHERE code=$1 FOR UPDATE")
                .bind(code)
                .fetch_optional(&mut **transaction)
                .await?;
        row.as_ref().map(join_code_from_row).transpose()
    }

    pub async fn join_code_by_code(&self, code: &str) -> Result<Option<JoinCode>, RepositoryError> {
        let row = sqlx::query("SELECT * FROM organization_service.join_codes WHERE code=$1")
            .bind(code)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(join_code_from_row).transpose()
    }

    pub async fn join_codes_by_organization(
        &self,
        organization_id: Uuid,
    ) -> Result<Vec<JoinCode>, RepositoryError> {
        let rows = sqlx::query(
            "SELECT * FROM organization_service.join_codes
             WHERE organization_id=$1 ORDER BY created_at DESC,id",
        )
        .bind(organization_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(join_code_from_row).collect()
    }

    pub async fn delete_join_code(&self, code_id: Uuid) -> Result<bool, RepositoryError> {
        let result = sqlx::query("DELETE FROM organization_service.join_codes WHERE id=$1")
            .bind(code_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn save_permission(&self, permission: &Permission) -> Result<(), RepositoryError> {
        let mut connection = self.pool.acquire().await?;
        save_permission_on(&mut connection, permission).await
    }

    pub async fn save_permission_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        permission: &Permission,
    ) -> Result<(), RepositoryError> {
        save_permission_on(&mut *transaction, permission).await
    }

    pub async fn upsert_permission_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        permission: &Permission,
    ) -> Result<Permission, RepositoryError> {
        upsert_permission_on(&mut *transaction, permission).await
    }

    pub async fn list_permissions(&self) -> Result<Vec<Permission>, RepositoryError> {
        let rows =
            sqlx::query("SELECT * FROM organization_service.permissions ORDER BY resource,action")
                .fetch_all(&self.pool)
                .await?;
        rows.iter().map(permission_from_row).collect()
    }

    pub async fn permission_by_key(
        &self,
        resource: &str,
        action: &str,
    ) -> Result<Option<Permission>, RepositoryError> {
        let row = sqlx::query(
            "SELECT * FROM organization_service.permissions WHERE resource=$1 AND action=$2",
        )
        .bind(resource)
        .bind(action)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(permission_from_row).transpose()
    }

    pub async fn permissions_by_ids(
        &self,
        permission_ids: &[Uuid],
    ) -> Result<Vec<Permission>, RepositoryError> {
        let rows = sqlx::query(
            "SELECT * FROM organization_service.permissions WHERE id = ANY($1)
             ORDER BY resource,action",
        )
        .bind(permission_ids)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(permission_from_row).collect()
    }

    pub async fn permissions_by_ids_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        permission_ids: &[Uuid],
    ) -> Result<Vec<Permission>, RepositoryError> {
        let rows = sqlx::query(
            "SELECT * FROM organization_service.permissions WHERE id=ANY($1)
             ORDER BY resource,action",
        )
        .bind(permission_ids)
        .fetch_all(&mut **transaction)
        .await?;
        rows.iter().map(permission_from_row).collect()
    }

    pub async fn save_role(&self, role: &Role) -> Result<(), RepositoryError> {
        let mut transaction = self.pool.begin().await?;
        save_role_on(&mut transaction, role).await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn save_role_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        role: &Role,
    ) -> Result<(), RepositoryError> {
        save_role_on(&mut *transaction, role).await
    }

    pub async fn add_member_role_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        member_id: Uuid,
        role_id: Uuid,
    ) -> Result<(), RepositoryError> {
        add_member_role_on(&mut *transaction, member_id, role_id).await
    }

    pub async fn role_by_id(&self, role_id: Uuid) -> Result<Option<Role>, RepositoryError> {
        let row = sqlx::query("SELECT * FROM organization_service.roles WHERE id=$1")
            .bind(role_id)
            .fetch_optional(&self.pool)
            .await?;
        match row {
            Some(row) => Ok(Some(self.hydrate_role(&row).await?)),
            None => Ok(None),
        }
    }

    pub async fn role_by_id_for_update_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        role_id: Uuid,
    ) -> Result<Option<Role>, RepositoryError> {
        let row = sqlx::query("SELECT * FROM organization_service.roles WHERE id=$1 FOR UPDATE")
            .bind(role_id)
            .fetch_optional(&mut **transaction)
            .await?;
        match row {
            Some(row) => Ok(Some(hydrate_role_in_transaction(transaction, &row).await?)),
            None => Ok(None),
        }
    }

    pub async fn role_by_name(
        &self,
        organization_id: Uuid,
        name: &str,
    ) -> Result<Option<Role>, RepositoryError> {
        let row = sqlx::query(
            "SELECT * FROM organization_service.roles WHERE organization_id=$1 AND name=$2",
        )
        .bind(organization_id)
        .bind(name)
        .fetch_optional(&self.pool)
        .await?;
        match row {
            Some(row) => Ok(Some(self.hydrate_role(&row).await?)),
            None => Ok(None),
        }
    }

    pub async fn roles_by_organization(
        &self,
        organization_id: Uuid,
    ) -> Result<Vec<Role>, RepositoryError> {
        let rows = sqlx::query(
            "SELECT * FROM organization_service.roles WHERE organization_id=$1
             ORDER BY is_system DESC,name",
        )
        .bind(organization_id)
        .fetch_all(&self.pool)
        .await?;
        let mut roles = Vec::with_capacity(rows.len());
        for row in rows {
            roles.push(self.hydrate_role(&row).await?);
        }
        Ok(roles)
    }

    pub async fn roles_by_ids_for_organization_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        organization_id: Uuid,
        role_ids: &[Uuid],
    ) -> Result<Vec<Role>, RepositoryError> {
        let rows = sqlx::query(
            "SELECT * FROM organization_service.roles
             WHERE organization_id=$1 AND id=ANY($2)
             ORDER BY is_system DESC,name",
        )
        .bind(organization_id)
        .bind(role_ids)
        .fetch_all(&mut **transaction)
        .await?;
        hydrate_roles_in_transaction(transaction, rows).await
    }

    pub async fn default_roles_for_organization_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        organization_id: Uuid,
    ) -> Result<Vec<Role>, RepositoryError> {
        let rows = sqlx::query(
            "SELECT * FROM organization_service.roles
             WHERE organization_id=$1 AND is_default_for_new_members=true
             ORDER BY is_system DESC,name",
        )
        .bind(organization_id)
        .fetch_all(&mut **transaction)
        .await?;
        hydrate_roles_in_transaction(transaction, rows).await
    }

    pub async fn role_by_name_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        organization_id: Uuid,
        name: &str,
    ) -> Result<Option<Role>, RepositoryError> {
        let row = sqlx::query(
            "SELECT * FROM organization_service.roles
             WHERE organization_id=$1 AND name=$2",
        )
        .bind(organization_id)
        .bind(name)
        .fetch_optional(&mut **transaction)
        .await?;
        match row {
            Some(row) => Ok(Some(hydrate_role_in_transaction(transaction, &row).await?)),
            None => Ok(None),
        }
    }

    pub async fn role_by_name_for_update_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        organization_id: Uuid,
        name: &str,
    ) -> Result<Option<Role>, RepositoryError> {
        let row = sqlx::query(
            "SELECT * FROM organization_service.roles
             WHERE organization_id=$1 AND name=$2 FOR UPDATE",
        )
        .bind(organization_id)
        .bind(name)
        .fetch_optional(&mut **transaction)
        .await?;
        match row {
            Some(row) => Ok(Some(hydrate_role_in_transaction(transaction, &row).await?)),
            None => Ok(None),
        }
    }

    pub async fn roles_by_organization_for_update_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        organization_id: Uuid,
    ) -> Result<Vec<Role>, RepositoryError> {
        let rows = sqlx::query(
            "SELECT * FROM organization_service.roles
             WHERE organization_id=$1 ORDER BY is_system DESC,name FOR UPDATE",
        )
        .bind(organization_id)
        .fetch_all(&mut **transaction)
        .await?;
        hydrate_roles_in_transaction(transaction, rows).await
    }

    pub async fn roles_for_member(&self, member_id: Uuid) -> Result<Vec<Role>, RepositoryError> {
        let rows = sqlx::query(
            "SELECT roles.* FROM organization_service.roles roles
             JOIN organization_service.member_roles links ON links.role_id=roles.id
             WHERE links.member_id=$1 ORDER BY roles.is_system DESC,roles.name",
        )
        .bind(member_id)
        .fetch_all(&self.pool)
        .await?;
        let mut roles = Vec::with_capacity(rows.len());
        for row in rows {
            roles.push(self.hydrate_role(&row).await?);
        }
        Ok(roles)
    }

    pub async fn roles_for_member_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        member_id: Uuid,
    ) -> Result<Vec<Role>, RepositoryError> {
        let rows = sqlx::query(
            "SELECT roles.* FROM organization_service.roles roles
             JOIN organization_service.member_roles links ON links.role_id=roles.id
             WHERE links.member_id=$1 ORDER BY roles.is_system DESC,roles.name",
        )
        .bind(member_id)
        .fetch_all(&mut **transaction)
        .await?;
        hydrate_roles_in_transaction(transaction, rows).await
    }

    async fn hydrate_role(&self, row: &PgRow) -> Result<Role, RepositoryError> {
        let role_id: Uuid = row.try_get("id")?;
        let permissions = self.permissions_for_role(role_id).await?;
        role_from_row(row, permissions)
    }

    async fn permissions_for_role(
        &self,
        role_id: Uuid,
    ) -> Result<Vec<Permission>, RepositoryError> {
        let rows = sqlx::query(
            "SELECT permissions.* FROM organization_service.permissions permissions
             JOIN organization_service.role_permissions links
               ON links.permission_id=permissions.id
             WHERE links.role_id=$1 ORDER BY permissions.resource,permissions.action",
        )
        .bind(role_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(permission_from_row).collect()
    }

    pub async fn set_member_roles(
        &self,
        member_id: Uuid,
        role_ids: &[Uuid],
    ) -> Result<(), RepositoryError> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query("DELETE FROM organization_service.member_roles WHERE member_id=$1")
            .bind(member_id)
            .execute(&mut *transaction)
            .await?;
        for role_id in role_ids {
            add_member_role_on(&mut transaction, member_id, *role_id).await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    pub async fn set_member_roles_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        member_id: Uuid,
        role_ids: &[Uuid],
    ) -> Result<(), RepositoryError> {
        sqlx::query("DELETE FROM organization_service.member_roles WHERE member_id=$1")
            .bind(member_id)
            .execute(&mut **transaction)
            .await?;
        for role_id in role_ids {
            add_member_role_on(&mut *transaction, member_id, *role_id).await?;
        }
        Ok(())
    }

    pub async fn add_member_role(
        &self,
        member_id: Uuid,
        role_id: Uuid,
    ) -> Result<(), RepositoryError> {
        let mut transaction = self.pool.begin().await?;
        add_member_role_on(&mut transaction, member_id, role_id).await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn remove_member_role(
        &self,
        member_id: Uuid,
        role_id: Uuid,
    ) -> Result<bool, RepositoryError> {
        let result = sqlx::query(
            "DELETE FROM organization_service.member_roles WHERE member_id=$1 AND role_id=$2",
        )
        .bind(member_id)
        .bind(role_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn remove_member_role_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        member_id: Uuid,
        role_id: Uuid,
    ) -> Result<bool, RepositoryError> {
        let result = sqlx::query(
            "DELETE FROM organization_service.member_roles WHERE member_id=$1 AND role_id=$2",
        )
        .bind(member_id)
        .bind(role_id)
        .execute(&mut **transaction)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn member_permissions(
        &self,
        member_id: Uuid,
    ) -> Result<Vec<Permission>, RepositoryError> {
        let rows = sqlx::query(
            "SELECT DISTINCT permissions.* FROM organization_service.permissions permissions
             JOIN organization_service.role_permissions role_links
               ON role_links.permission_id=permissions.id
             JOIN organization_service.member_roles member_links
               ON member_links.role_id=role_links.role_id
             WHERE member_links.member_id=$1 ORDER BY permissions.resource,permissions.action",
        )
        .bind(member_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(permission_from_row).collect()
    }

    pub async fn member_ids_with_role(&self, role_id: Uuid) -> Result<Vec<Uuid>, RepositoryError> {
        let rows = sqlx::query(
            "SELECT member_id FROM organization_service.member_roles
             WHERE role_id=$1 ORDER BY member_id",
        )
        .bind(role_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| row.try_get("member_id").map_err(RepositoryError::from))
            .collect()
    }

    pub async fn member_ids_with_role_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        role_id: Uuid,
    ) -> Result<Vec<Uuid>, RepositoryError> {
        let rows = sqlx::query(
            "SELECT member_id FROM organization_service.member_roles
             WHERE role_id=$1 ORDER BY member_id FOR UPDATE",
        )
        .bind(role_id)
        .fetch_all(&mut **transaction)
        .await?;
        rows.iter()
            .map(|row| row.try_get("member_id").map_err(RepositoryError::from))
            .collect()
    }

    pub async fn delete_role(&self, role_id: Uuid) -> Result<bool, RepositoryError> {
        let result = sqlx::query("DELETE FROM organization_service.roles WHERE id=$1")
            .bind(role_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn delete_role_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        role_id: Uuid,
    ) -> Result<bool, RepositoryError> {
        let result = sqlx::query("DELETE FROM organization_service.roles WHERE id=$1")
            .bind(role_id)
            .execute(&mut **transaction)
            .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn save_policy_set(&self, policy_set: &PolicySet) -> Result<(), RepositoryError> {
        let mut connection = self.pool.acquire().await?;
        save_policy_set_on(&mut connection, policy_set).await
    }

    pub async fn save_policy_set_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        policy_set: &PolicySet,
    ) -> Result<(), RepositoryError> {
        save_policy_set_on(&mut *transaction, policy_set).await
    }

    pub async fn policy_set_by_id_for_update_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        organization_id: Uuid,
        policy_set_id: Uuid,
    ) -> Result<Option<PolicySet>, RepositoryError> {
        let row = sqlx::query(
            "SELECT * FROM organization_service.policy_sets
             WHERE organization_id=$1 AND id=$2 FOR UPDATE",
        )
        .bind(organization_id)
        .bind(policy_set_id)
        .fetch_optional(&mut **transaction)
        .await?;
        row.as_ref().map(policy_set_from_row).transpose()
    }

    pub async fn policy_sets_by_organization_for_update_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        organization_id: Uuid,
    ) -> Result<Vec<PolicySet>, RepositoryError> {
        let rows = sqlx::query(
            "SELECT * FROM organization_service.policy_sets
             WHERE organization_id=$1 ORDER BY created_at DESC,id FOR UPDATE",
        )
        .bind(organization_id)
        .fetch_all(&mut **transaction)
        .await?;
        rows.iter().map(policy_set_from_row).collect()
    }

    pub async fn delete_policy_set_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        organization_id: Uuid,
        policy_set_id: Uuid,
    ) -> Result<bool, RepositoryError> {
        let result = sqlx::query(
            "DELETE FROM organization_service.policy_sets WHERE organization_id=$1 AND id=$2",
        )
        .bind(organization_id)
        .bind(policy_set_id)
        .execute(&mut **transaction)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn policy_set_by_id(
        &self,
        organization_id: Uuid,
        policy_set_id: Uuid,
    ) -> Result<Option<PolicySet>, RepositoryError> {
        let row = sqlx::query(
            "SELECT * FROM organization_service.policy_sets
             WHERE organization_id=$1 AND id=$2",
        )
        .bind(organization_id)
        .bind(policy_set_id)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(policy_set_from_row).transpose()
    }

    pub async fn policy_sets_by_organization(
        &self,
        organization_id: Uuid,
        status: Option<PolicySetStatus>,
    ) -> Result<Vec<PolicySet>, RepositoryError> {
        let rows = sqlx::query(
            "SELECT * FROM organization_service.policy_sets
             WHERE organization_id=$1 AND ($2::text IS NULL OR status=$2)
             ORDER BY created_at DESC,id",
        )
        .bind(organization_id)
        .bind(status.map(PolicySetStatus::as_str))
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(policy_set_from_row).collect()
    }

    pub async fn delete_policy_set(
        &self,
        organization_id: Uuid,
        policy_set_id: Uuid,
    ) -> Result<bool, RepositoryError> {
        let result = sqlx::query(
            "DELETE FROM organization_service.policy_sets WHERE organization_id=$1 AND id=$2",
        )
        .bind(organization_id)
        .bind(policy_set_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn save_audit_event(&self, event: &AuditEvent) -> Result<(), RepositoryError> {
        let mut connection = self.pool.acquire().await?;
        save_audit_event_on(&mut connection, event).await
    }

    pub async fn save_audit_event_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        event: &AuditEvent,
    ) -> Result<(), RepositoryError> {
        save_audit_event_on(&mut *transaction, event).await
    }

    pub async fn audit_event_by_id(
        &self,
        organization_id: Uuid,
        event_id: Uuid,
    ) -> Result<Option<AuditEvent>, RepositoryError> {
        let row = sqlx::query(
            "SELECT * FROM organization_service.audit_events
             WHERE organization_id=$1 AND id=$2",
        )
        .bind(organization_id)
        .bind(event_id)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(audit_event_from_row).transpose()
    }

    pub async fn list_audit_events(
        &self,
        organization_id: Uuid,
        query: &AuditEventQuery,
    ) -> Result<Vec<AuditEvent>, RepositoryError> {
        let mut builder = QueryBuilder::new(
            "SELECT * FROM organization_service.audit_events WHERE organization_id=",
        );
        builder.push_bind(organization_id);
        push_audit_filters(&mut builder, query);
        builder
            .push(" ORDER BY created_at DESC,id LIMIT ")
            .push_bind(i64::from(query.limit.clamp(1, 1_000)))
            .push(" OFFSET ")
            .push_bind(i64::from(query.offset));
        let rows = builder.build().fetch_all(&self.pool).await?;
        rows.iter().map(audit_event_from_row).collect()
    }

    pub async fn count_audit_events(
        &self,
        organization_id: Uuid,
        query: &AuditEventQuery,
    ) -> Result<u64, RepositoryError> {
        let mut builder = QueryBuilder::new(
            "SELECT count(*) FROM organization_service.audit_events WHERE organization_id=",
        );
        builder.push_bind(organization_id);
        push_audit_filters(&mut builder, query);
        let count = builder
            .build_query_scalar::<i64>()
            .fetch_one(&self.pool)
            .await?;
        u64::try_from(count).map_err(|_| RepositoryError::InvalidData {
            field: "audit_events.count",
            value: count.to_string(),
        })
    }
}

async fn save_policy_set_on(
    connection: &mut PgConnection,
    policy_set: &PolicySet,
) -> Result<(), RepositoryError> {
    sqlx::query(
        "INSERT INTO organization_service.policy_sets (
            id,organization_id,name,description,policy_type,status,cedar_policies,
            cedar_schema_version,created_by,created_at,updated_at
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
         ON CONFLICT (id) DO UPDATE SET
            name=EXCLUDED.name,description=EXCLUDED.description,
            policy_type=EXCLUDED.policy_type,status=EXCLUDED.status,
            cedar_policies=EXCLUDED.cedar_policies,
            cedar_schema_version=EXCLUDED.cedar_schema_version,
            updated_at=EXCLUDED.updated_at",
    )
    .bind(policy_set.id)
    .bind(policy_set.organization_id)
    .bind(&policy_set.name)
    .bind(&policy_set.description)
    .bind(policy_set.policy_type.as_str())
    .bind(policy_set.status.as_str())
    .bind(&policy_set.cedar_policies)
    .bind(&policy_set.cedar_schema_version)
    .bind(&policy_set.created_by)
    .bind(policy_set.created_at)
    .bind(policy_set.updated_at)
    .execute(connection)
    .await?;
    Ok(())
}

async fn save_organization_on(
    connection: &mut PgConnection,
    organization: &Organization,
) -> Result<(), RepositoryError> {
    sqlx::query(
        "INSERT INTO organization_service.organizations (
            id,name,display_name,description,status,owner_id,slug,org_type,
            contact_email,contact_phone,website,settings,plan,plan_expires_at,
            join_mechanism,requires_approval,is_discoverable,created_at,updated_at
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
         ON CONFLICT (id) DO UPDATE SET
            name=EXCLUDED.name,display_name=EXCLUDED.display_name,
            description=EXCLUDED.description,status=EXCLUDED.status,
            owner_id=EXCLUDED.owner_id,slug=EXCLUDED.slug,org_type=EXCLUDED.org_type,
            contact_email=EXCLUDED.contact_email,contact_phone=EXCLUDED.contact_phone,
            website=EXCLUDED.website,settings=EXCLUDED.settings,plan=EXCLUDED.plan,
            plan_expires_at=EXCLUDED.plan_expires_at,
            join_mechanism=EXCLUDED.join_mechanism,
            requires_approval=EXCLUDED.requires_approval,
            is_discoverable=EXCLUDED.is_discoverable,updated_at=EXCLUDED.updated_at",
    )
    .bind(organization.id)
    .bind(&organization.name)
    .bind(&organization.display_name)
    .bind(&organization.description)
    .bind(organization.status.as_str())
    .bind(&organization.owner_id)
    .bind(&organization.slug)
    .bind(organization.org_type.as_str())
    .bind(&organization.contact_email)
    .bind(&organization.contact_phone)
    .bind(&organization.website)
    .bind(Value::Object(organization.settings.clone()))
    .bind(&organization.plan)
    .bind(organization.plan_expires_at)
    .bind(organization.join_mechanism.as_str())
    .bind(organization.requires_approval)
    .bind(organization.is_discoverable)
    .bind(organization.created_at)
    .bind(organization.updated_at)
    .execute(connection)
    .await?;
    Ok(())
}

async fn save_member_on(
    connection: &mut PgConnection,
    member: &Member,
) -> Result<(), RepositoryError> {
    sqlx::query(
        "INSERT INTO organization_service.members (
            id,organization_id,user_id,email,status,invited_by,invited_at,joined_at,
            created_at,updated_at
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
         ON CONFLICT (id) DO UPDATE SET
            user_id=EXCLUDED.user_id,email=EXCLUDED.email,status=EXCLUDED.status,
            invited_by=EXCLUDED.invited_by,invited_at=EXCLUDED.invited_at,
            joined_at=EXCLUDED.joined_at,updated_at=EXCLUDED.updated_at",
    )
    .bind(member.id)
    .bind(member.organization_id)
    .bind(&member.user_id)
    .bind(&member.email)
    .bind(member.status.as_str())
    .bind(&member.invited_by)
    .bind(member.invited_at)
    .bind(member.joined_at)
    .bind(member.created_at)
    .bind(member.updated_at)
    .execute(connection)
    .await?;
    Ok(())
}

async fn save_api_key_on(
    connection: &mut PgConnection,
    api_key: &ApiKey,
) -> Result<(), RepositoryError> {
    let rate_limit = api_key
        .rate_limit
        .map(i32::try_from)
        .transpose()
        .map_err(|_| {
            invalid(
                "api_keys.rate_limit",
                api_key.rate_limit.unwrap().to_string(),
            )
        })?;
    sqlx::query(
        "INSERT INTO organization_service.api_keys (
            id,organization_id,name,description,key_prefix,key_hash,scopes,scope_type,
            deployment_profile_id,status,enabled,rate_limit,created_by,last_used_at,
            last_used_ip,expires_at,created_at,updated_at
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
         ON CONFLICT (id) DO UPDATE SET
            name=EXCLUDED.name,description=EXCLUDED.description,scopes=EXCLUDED.scopes,
            scope_type=EXCLUDED.scope_type,deployment_profile_id=EXCLUDED.deployment_profile_id,
            status=EXCLUDED.status,enabled=EXCLUDED.enabled,rate_limit=EXCLUDED.rate_limit,
            last_used_at=EXCLUDED.last_used_at,last_used_ip=EXCLUDED.last_used_ip,
            expires_at=EXCLUDED.expires_at,updated_at=EXCLUDED.updated_at",
    )
    .bind(api_key.id)
    .bind(api_key.organization_id)
    .bind(&api_key.name)
    .bind(&api_key.description)
    .bind(&api_key.key_prefix)
    .bind(&api_key.key_hash)
    .bind(&api_key.scopes)
    .bind(&api_key.scope_type)
    .bind(api_key.deployment_profile_id)
    .bind(api_key.status.as_str())
    .bind(api_key.enabled)
    .bind(rate_limit)
    .bind(&api_key.created_by)
    .bind(api_key.last_used_at)
    .bind(&api_key.last_used_ip)
    .bind(api_key.expires_at)
    .bind(api_key.created_at)
    .bind(api_key.updated_at)
    .execute(connection)
    .await?;
    Ok(())
}

async fn save_preference_on(
    connection: &mut PgConnection,
    preference: &ConsoleContextPreference,
) -> Result<(), RepositoryError> {
    sqlx::query(
        "INSERT INTO organization_service.console_context_preferences (
            id,user_id,last_view_mode,last_active_org_id,created_at,updated_at
         ) VALUES ($1,$2,$3,$4,$5,$6)
         ON CONFLICT (user_id) DO UPDATE SET
            last_view_mode=EXCLUDED.last_view_mode,
            last_active_org_id=EXCLUDED.last_active_org_id,
            updated_at=EXCLUDED.updated_at",
    )
    .bind(preference.id)
    .bind(&preference.user_id)
    .bind(preference.last_view_mode.as_str())
    .bind(preference.last_active_org_id)
    .bind(preference.created_at)
    .bind(preference.updated_at)
    .execute(connection)
    .await?;
    Ok(())
}

async fn save_join_code_on(
    connection: &mut PgConnection,
    join_code: &JoinCode,
) -> Result<(), RepositoryError> {
    let max_uses = join_code
        .max_uses
        .map(i32::try_from)
        .transpose()
        .map_err(|_| {
            invalid(
                "join_codes.max_uses",
                join_code.max_uses.unwrap().to_string(),
            )
        })?;
    let use_count = i32::try_from(join_code.use_count)
        .map_err(|_| invalid("join_codes.use_count", join_code.use_count.to_string()))?;
    sqlx::query(
        "INSERT INTO organization_service.join_codes (
            id,organization_id,code,created_by,expires_at,max_uses,use_count,is_active,
            created_at,updated_at
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
         ON CONFLICT (id) DO UPDATE SET
            code=EXCLUDED.code,expires_at=EXCLUDED.expires_at,max_uses=EXCLUDED.max_uses,
            use_count=EXCLUDED.use_count,is_active=EXCLUDED.is_active,
            updated_at=EXCLUDED.updated_at",
    )
    .bind(join_code.id)
    .bind(join_code.organization_id)
    .bind(&join_code.code)
    .bind(&join_code.created_by)
    .bind(join_code.expires_at)
    .bind(max_uses)
    .bind(use_count)
    .bind(join_code.is_active)
    .bind(join_code.created_at)
    .bind(join_code.updated_at)
    .execute(connection)
    .await?;
    Ok(())
}

async fn save_permission_on(
    connection: &mut PgConnection,
    permission: &Permission,
) -> Result<(), RepositoryError> {
    upsert_permission_on(connection, permission).await?;
    Ok(())
}

async fn upsert_permission_on(
    connection: &mut PgConnection,
    permission: &Permission,
) -> Result<Permission, RepositoryError> {
    let row = sqlx::query(
        "INSERT INTO organization_service.permissions (id,resource,action,description)
         VALUES ($1,$2,$3,$4)
         ON CONFLICT (resource,action) DO UPDATE SET description=EXCLUDED.description
         RETURNING id,resource,action,description",
    )
    .bind(permission.id)
    .bind(&permission.resource)
    .bind(&permission.action)
    .bind(&permission.description)
    .fetch_one(connection)
    .await?;
    permission_from_row(&row)
}

async fn save_role_on(connection: &mut PgConnection, role: &Role) -> Result<(), RepositoryError> {
    sqlx::query(
        "INSERT INTO organization_service.roles (
            id,organization_id,name,display_name,description,is_system,
            is_default_for_new_members,created_at,updated_at
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
         ON CONFLICT (id) DO UPDATE SET
            name=EXCLUDED.name,display_name=EXCLUDED.display_name,
            description=EXCLUDED.description,is_system=EXCLUDED.is_system,
            is_default_for_new_members=EXCLUDED.is_default_for_new_members,
            updated_at=EXCLUDED.updated_at",
    )
    .bind(role.id)
    .bind(role.organization_id)
    .bind(&role.name)
    .bind(&role.display_name)
    .bind(&role.description)
    .bind(role.is_system)
    .bind(role.is_default_for_new_members)
    .bind(role.created_at)
    .bind(role.updated_at)
    .execute(&mut *connection)
    .await?;
    sqlx::query("DELETE FROM organization_service.role_permissions WHERE role_id=$1")
        .bind(role.id)
        .execute(&mut *connection)
        .await?;
    for permission in &role.permissions {
        sqlx::query(
            "INSERT INTO organization_service.role_permissions(role_id,permission_id)
             VALUES ($1,$2) ON CONFLICT DO NOTHING",
        )
        .bind(role.id)
        .bind(permission.id)
        .execute(&mut *connection)
        .await?;
    }
    Ok(())
}

async fn save_audit_event_on(
    connection: &mut PgConnection,
    event: &AuditEvent,
) -> Result<(), RepositoryError> {
    sqlx::query(
        "INSERT INTO organization_service.audit_events (
            id,organization_id,event_type,action,category,resource_type,resource_id,
            resource_name,actor_id,actor_type,severity,message,changes,metadata,created_at
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(event.id)
    .bind(event.organization_id)
    .bind(&event.event_type)
    .bind(&event.action)
    .bind(&event.category)
    .bind(&event.resource_type)
    .bind(&event.resource_id)
    .bind(&event.resource_name)
    .bind(&event.actor_id)
    .bind(&event.actor_type)
    .bind(&event.severity)
    .bind(&event.message)
    .bind(&event.changes)
    .bind(&event.metadata)
    .bind(event.timestamp)
    .execute(connection)
    .await?;
    Ok(())
}

async fn add_member_role_on(
    connection: &mut PgConnection,
    member_id: Uuid,
    role_id: Uuid,
) -> Result<(), RepositoryError> {
    sqlx::query(
        "INSERT INTO organization_service.member_roles(member_id,role_id)
         VALUES ($1,$2) ON CONFLICT DO NOTHING",
    )
    .bind(member_id)
    .bind(role_id)
    .execute(connection)
    .await?;
    Ok(())
}

async fn hydrate_optional_member_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    row: Option<PgRow>,
) -> Result<Option<Member>, RepositoryError> {
    match row {
        Some(row) => Ok(Some(
            hydrate_member_in_transaction(transaction, &row).await?,
        )),
        None => Ok(None),
    }
}

async fn hydrate_member_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    row: &PgRow,
) -> Result<Member, RepositoryError> {
    let member_id: Uuid = row.try_get("id")?;
    let role_rows = sqlx::query(
        "SELECT roles.* FROM organization_service.roles roles
         JOIN organization_service.member_roles links ON links.role_id=roles.id
         WHERE links.member_id=$1 ORDER BY roles.is_system DESC,roles.name",
    )
    .bind(member_id)
    .fetch_all(&mut **transaction)
    .await?;
    let mut member = member_from_row(row)?;
    member.roles = hydrate_roles_in_transaction(transaction, role_rows).await?;
    Ok(member)
}

async fn hydrate_roles_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    rows: Vec<PgRow>,
) -> Result<Vec<Role>, RepositoryError> {
    let mut roles = Vec::with_capacity(rows.len());
    for row in rows {
        roles.push(hydrate_role_in_transaction(transaction, &row).await?);
    }
    Ok(roles)
}

async fn hydrate_role_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    row: &PgRow,
) -> Result<Role, RepositoryError> {
    let role_id: Uuid = row.try_get("id")?;
    let permission_rows = sqlx::query(
        "SELECT permissions.* FROM organization_service.permissions permissions
         JOIN organization_service.role_permissions links
           ON links.permission_id=permissions.id
         WHERE links.role_id=$1 ORDER BY permissions.resource,permissions.action",
    )
    .bind(role_id)
    .fetch_all(&mut **transaction)
    .await?;
    let permissions = permission_rows
        .iter()
        .map(permission_from_row)
        .collect::<Result<Vec<_>, _>>()?;
    role_from_row(row, permissions)
}

fn push_optional_filter(
    builder: &mut QueryBuilder<Postgres>,
    column: &'static str,
    value: Option<&str>,
) {
    if let Some(value) = value {
        builder
            .push(" AND ")
            .push(column)
            .push(" = ")
            .push_bind(value);
    }
}

fn push_audit_filters(builder: &mut QueryBuilder<Postgres>, query: &AuditEventQuery) {
    push_optional_filter(builder, "category", query.category.as_deref());
    push_optional_filter(builder, "event_type", query.event_type.as_deref());
    push_optional_filter(builder, "resource_type", query.resource_type.as_deref());
    push_optional_filter(builder, "resource_id", query.resource_id.as_deref());
    push_optional_filter(builder, "action", query.action.as_deref());
    push_optional_filter(builder, "severity", query.severity.as_deref());
    if let Some(actor_id) = query.actor_id.as_deref() {
        builder
            .push(" AND actor_id ILIKE ")
            .push_bind(format!("%{actor_id}%"));
    }
    if let Some(ip_address) = query.ip_address.as_deref() {
        builder
            .push(" AND metadata::text ILIKE ")
            .push_bind(format!("%{ip_address}%"));
    }
    if let Some(from) = query.from {
        builder.push(" AND created_at >= ").push_bind(from);
    }
    if let Some(to) = query.to {
        builder.push(" AND created_at <= ").push_bind(to);
    }
    if let Some(search) = query.search.as_deref() {
        let pattern = format!("%{search}%");
        builder
            .push(" AND (event_type ILIKE ")
            .push_bind(pattern.clone())
            .push(" OR action ILIKE ")
            .push_bind(pattern.clone())
            .push(" OR message ILIKE ")
            .push_bind(pattern.clone())
            .push(" OR resource_type ILIKE ")
            .push_bind(pattern.clone())
            .push(" OR resource_id ILIKE ")
            .push_bind(pattern.clone())
            .push(" OR resource_name ILIKE ")
            .push_bind(pattern.clone())
            .push(" OR actor_id ILIKE ")
            .push_bind(pattern.clone())
            .push(" OR metadata::text ILIKE ")
            .push_bind(pattern)
            .push(")");
    }
}

fn organization_from_row(row: &PgRow) -> Result<Organization, RepositoryError> {
    let settings: Value = row.try_get("settings")?;
    let settings = settings
        .as_object()
        .cloned()
        .ok_or_else(|| invalid("organizations.settings", settings.to_string()))?;
    let is_discoverable: bool = row.try_get("is_discoverable")?;
    Ok(Organization {
        id: row.try_get("id")?,
        name: row.try_get("name")?,
        display_name: row.try_get("display_name")?,
        slug: row.try_get("slug")?,
        description: row.try_get("description")?,
        org_type: parse_organization_type(row.try_get("org_type")?)?,
        status: parse_organization_status(row.try_get("status")?)?,
        owner_id: row
            .try_get::<Option<String>, _>("owner_id")?
            .unwrap_or_default(),
        join_code: None,
        visibility: if is_discoverable { "PUBLIC" } else { "PRIVATE" }.to_owned(),
        join_mechanism: parse_join_mechanism(row.try_get("join_mechanism")?)?,
        requires_approval: row.try_get("requires_approval")?,
        is_discoverable,
        contact_email: row.try_get("contact_email")?,
        contact_phone: row.try_get("contact_phone")?,
        website: row.try_get("website")?,
        plan: row.try_get("plan")?,
        plan_expires_at: row.try_get("plan_expires_at")?,
        settings,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn member_from_row(row: &PgRow) -> Result<Member, RepositoryError> {
    Ok(Member {
        id: row.try_get("id")?,
        organization_id: row.try_get("organization_id")?,
        user_id: row
            .try_get::<Option<String>, _>("user_id")?
            .unwrap_or_default(),
        email: row.try_get("email")?,
        status: parse_member_status(row.try_get("status")?)?,
        roles: Vec::new(),
        invited_by: row.try_get("invited_by")?,
        invited_at: row.try_get("invited_at")?,
        joined_at: row.try_get("joined_at")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn api_key_from_row(row: &PgRow) -> Result<ApiKey, RepositoryError> {
    Ok(ApiKey {
        id: row.try_get("id")?,
        organization_id: row.try_get("organization_id")?,
        name: row.try_get("name")?,
        description: row.try_get("description")?,
        key_prefix: row.try_get("key_prefix")?,
        key_hash: row.try_get("key_hash")?,
        scopes: row
            .try_get::<Option<Vec<String>>, _>("scopes")?
            .unwrap_or_default(),
        scope_type: row.try_get("scope_type")?,
        deployment_profile_id: row.try_get("deployment_profile_id")?,
        status: parse_api_key_status(row.try_get("status")?)?,
        enabled: row.try_get("enabled")?,
        rate_limit: row
            .try_get::<Option<i32>, _>("rate_limit")?
            .map(|value| value.max(0) as u32),
        created_by: row.try_get("created_by")?,
        last_used_at: row.try_get("last_used_at")?,
        last_used_ip: row.try_get("last_used_ip")?,
        expires_at: row.try_get("expires_at")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn preference_from_row(row: &PgRow) -> Result<ConsoleContextPreference, RepositoryError> {
    Ok(ConsoleContextPreference {
        id: row.try_get("id")?,
        user_id: row.try_get("user_id")?,
        last_view_mode: parse_view_mode(row.try_get("last_view_mode")?)?,
        last_active_org_id: row.try_get("last_active_org_id")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn join_code_from_row(row: &PgRow) -> Result<JoinCode, RepositoryError> {
    let max_uses = row.try_get::<Option<i32>, _>("max_uses")?;
    let use_count = row.try_get::<i32, _>("use_count")?;
    if max_uses.is_some_and(|value| value < 0) || use_count < 0 {
        return Err(invalid(
            "join_codes.usage",
            format!("max_uses={max_uses:?},use_count={use_count}"),
        ));
    }
    Ok(JoinCode {
        id: row.try_get("id")?,
        organization_id: row.try_get("organization_id")?,
        code: row.try_get("code")?,
        created_by: row.try_get("created_by")?,
        expires_at: row.try_get("expires_at")?,
        max_uses: max_uses.map(|value| value as u32),
        use_count: use_count as u32,
        is_active: row.try_get("is_active")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn permission_from_row(row: &PgRow) -> Result<Permission, RepositoryError> {
    Ok(Permission {
        id: row.try_get("id")?,
        resource: row.try_get("resource")?,
        action: row.try_get("action")?,
        description: row.try_get("description")?,
    })
}

fn role_from_row(row: &PgRow, permissions: Vec<Permission>) -> Result<Role, RepositoryError> {
    Ok(Role {
        id: row.try_get("id")?,
        organization_id: row.try_get("organization_id")?,
        name: row.try_get("name")?,
        display_name: row.try_get("display_name")?,
        description: row.try_get("description")?,
        is_system: row.try_get("is_system")?,
        is_default_for_new_members: row.try_get("is_default_for_new_members")?,
        permissions,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn policy_set_from_row(row: &PgRow) -> Result<PolicySet, RepositoryError> {
    Ok(PolicySet {
        id: row.try_get("id")?,
        organization_id: row.try_get("organization_id")?,
        name: row.try_get("name")?,
        description: row.try_get("description")?,
        policy_type: parse_policy_set_type(row.try_get("policy_type")?)?,
        status: parse_policy_set_status(row.try_get("status")?)?,
        cedar_policies: row.try_get("cedar_policies")?,
        cedar_schema_version: row.try_get("cedar_schema_version")?,
        created_by: row.try_get("created_by")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn audit_event_from_row(row: &PgRow) -> Result<AuditEvent, RepositoryError> {
    Ok(AuditEvent {
        id: row.try_get("id")?,
        organization_id: row.try_get("organization_id")?,
        event_type: row.try_get("event_type")?,
        action: row.try_get("action")?,
        category: row.try_get("category")?,
        resource_type: row.try_get("resource_type")?,
        resource_id: row.try_get("resource_id")?,
        resource_name: row.try_get("resource_name")?,
        actor_id: row.try_get("actor_id")?,
        actor_type: row.try_get("actor_type")?,
        severity: row.try_get("severity")?,
        message: row.try_get("message")?,
        changes: row.try_get("changes")?,
        metadata: row.try_get("metadata")?,
        timestamp: row.try_get("created_at")?,
    })
}

fn parse_organization_type(value: String) -> Result<OrganizationType, RepositoryError> {
    match value.as_str() {
        "enterprise" => Ok(OrganizationType::Enterprise),
        "startup" => Ok(OrganizationType::Startup),
        "individual" => Ok(OrganizationType::Individual),
        "government" => Ok(OrganizationType::Government),
        "education" => Ok(OrganizationType::Education),
        "healthcare" => Ok(OrganizationType::Healthcare),
        "financial" => Ok(OrganizationType::Financial),
        "other" => Ok(OrganizationType::Other),
        _ => Err(invalid("organizations.org_type", value)),
    }
}

fn parse_organization_status(value: String) -> Result<OrganizationStatus, RepositoryError> {
    match value.as_str() {
        "active" => Ok(OrganizationStatus::Active),
        "suspended" => Ok(OrganizationStatus::Suspended),
        "pending" => Ok(OrganizationStatus::Pending),
        _ => Err(invalid("organizations.status", value)),
    }
}

fn parse_join_mechanism(value: String) -> Result<JoinMechanism, RepositoryError> {
    match value.as_str() {
        "open" => Ok(JoinMechanism::Open),
        "code" => Ok(JoinMechanism::Code),
        "invite" => Ok(JoinMechanism::Invite),
        "domain" => Ok(JoinMechanism::Domain),
        _ => Err(invalid("organizations.join_mechanism", value)),
    }
}

fn parse_member_status(value: String) -> Result<MemberStatus, RepositoryError> {
    match value.to_lowercase().as_str() {
        "active" => Ok(MemberStatus::Active),
        "pending" | "draft" => Ok(MemberStatus::Pending),
        "invited" => Ok(MemberStatus::Invited),
        "deactivated" => Ok(MemberStatus::Deactivated),
        _ => Err(invalid("members.status", value)),
    }
}

fn parse_api_key_status(value: String) -> Result<ApiKeyStatus, RepositoryError> {
    match value.as_str() {
        "active" => Ok(ApiKeyStatus::Active),
        "revoked" => Ok(ApiKeyStatus::Revoked),
        "expired" => Ok(ApiKeyStatus::Expired),
        _ => Err(invalid("api_keys.status", value)),
    }
}

fn parse_view_mode(value: String) -> Result<ViewMode, RepositoryError> {
    match value.as_str() {
        "applicant" => Ok(ViewMode::Applicant),
        "org_admin" => Ok(ViewMode::OrgAdmin),
        _ => Err(invalid("console_context_preferences.last_view_mode", value)),
    }
}

fn parse_policy_set_status(value: String) -> Result<PolicySetStatus, RepositoryError> {
    match value.to_uppercase().as_str() {
        "DRAFT" => Ok(PolicySetStatus::Draft),
        "ACTIVE" => Ok(PolicySetStatus::Active),
        "ARCHIVED" => Ok(PolicySetStatus::Archived),
        _ => Err(invalid("policy_sets.status", value)),
    }
}

fn parse_policy_set_type(value: String) -> Result<PolicySetType, RepositoryError> {
    match value.to_uppercase().as_str() {
        "ACCESS_CONTROL" => Ok(PolicySetType::AccessControl),
        "CREDENTIAL_VERIFICATION" => Ok(PolicySetType::CredentialVerification),
        "APPROVAL_RULES" => Ok(PolicySetType::ApprovalRules),
        "CUSTOM" => Ok(PolicySetType::Custom),
        _ => Err(invalid("policy_sets.policy_type", value)),
    }
}

fn invalid(field: &'static str, value: String) -> RepositoryError {
    RepositoryError::InvalidData { field, value }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persisted_enum_parsers_fail_closed() {
        assert!(parse_organization_type("unknown".to_owned()).is_err());
        assert!(parse_organization_status("enabled".to_owned()).is_err());
        assert!(parse_join_mechanism("magic".to_owned()).is_err());
        assert!(parse_member_status("unknown".to_owned()).is_err());
        assert!(parse_api_key_status("disabled".to_owned()).is_err());
        assert!(parse_view_mode("owner".to_owned()).is_err());
        assert!(parse_policy_set_status("unknown".to_owned()).is_err());
        assert!(parse_policy_set_type("unknown".to_owned()).is_err());
    }

    #[test]
    fn legacy_member_and_policy_values_remain_compatible() {
        assert_eq!(
            parse_member_status("DRAFT".to_owned()).expect("legacy DRAFT remains supported"),
            MemberStatus::Pending
        );
        assert_eq!(
            parse_policy_set_status("active".to_owned())
                .expect("legacy lowercase policy status remains supported"),
            PolicySetStatus::Active
        );
    }
}
