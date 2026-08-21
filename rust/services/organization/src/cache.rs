use std::sync::Arc;

use mmf_data::{CacheStore, DataError, RedisCache};
use thiserror::Error;
use uuid::Uuid;

const MEMBERSHIP_NAMESPACE: &str = "org_membership";
const PERMISSIONS_NAMESPACE: &str = "member_permissions";
const PLAN_NAMESPACE: &str = "org";

#[derive(Debug, Error)]
pub enum OrganizationCacheError {
    #[error("ORGANIZATION.CACHE_INVALID_IDENTIFIER: {0}")]
    InvalidIdentifier(&'static str),
    #[error("ORGANIZATION.CACHE_BACKEND: {0}")]
    Backend(#[from] DataError),
}

#[derive(Clone, Copy, Debug, Default)]
pub struct OrganizationCacheKeys;

impl OrganizationCacheKeys {
    #[must_use]
    pub const fn membership_namespace() -> &'static str {
        MEMBERSHIP_NAMESPACE
    }

    #[must_use]
    pub const fn permissions_namespace() -> &'static str {
        PERMISSIONS_NAMESPACE
    }

    #[must_use]
    pub const fn plan_namespace() -> &'static str {
        PLAN_NAMESPACE
    }

    pub fn member(user_id: &str, organization_id: Uuid) -> Result<String, OrganizationCacheError> {
        let user_id = required(user_id, "user_id")?;
        Ok(format!("{user_id}:{organization_id}"))
    }

    #[must_use]
    pub fn plan(organization_id: Uuid) -> String {
        format!("{organization_id}:plan")
    }
}

#[derive(Clone)]
pub struct OrganizationCache {
    memberships: Arc<dyn CacheStore>,
    permissions: Arc<dyn CacheStore>,
    plans: Arc<dyn CacheStore>,
}

impl OrganizationCache {
    #[must_use]
    pub fn new(
        memberships: Arc<dyn CacheStore>,
        permissions: Arc<dyn CacheStore>,
        plans: Arc<dyn CacheStore>,
    ) -> Self {
        Self {
            memberships,
            permissions,
            plans,
        }
    }

    pub fn from_redis(redis: &RedisCache) -> Result<Self, OrganizationCacheError> {
        Ok(Self::new(
            Arc::new(redis.with_key_space(MEMBERSHIP_NAMESPACE, "")?),
            Arc::new(redis.with_key_space(PERMISSIONS_NAMESPACE, "")?),
            Arc::new(redis.with_key_space(PLAN_NAMESPACE, "")?),
        ))
    }

    pub async fn invalidate_member(
        &self,
        user_id: &str,
        organization_id: Uuid,
    ) -> Result<(), OrganizationCacheError> {
        let key = OrganizationCacheKeys::member(user_id, organization_id)?;
        self.memberships.delete(&key).await?;
        self.permissions.delete(&key).await?;
        Ok(())
    }

    pub async fn store_plan(
        &self,
        organization_id: Uuid,
        plan: &str,
        now_ms: u64,
    ) -> Result<(), OrganizationCacheError> {
        let plan = required(plan, "plan")?;
        self.plans
            .set(
                &OrganizationCacheKeys::plan(organization_id),
                plan.as_bytes().to_vec(),
                None,
                now_ms,
            )
            .await?;
        Ok(())
    }

    pub async fn load_plan(
        &self,
        organization_id: Uuid,
        now_ms: u64,
    ) -> Result<Option<String>, OrganizationCacheError> {
        self.plans
            .get(&OrganizationCacheKeys::plan(organization_id), now_ms)
            .await?
            .map(|value| {
                String::from_utf8(value).map_err(|_| {
                    OrganizationCacheError::Backend(DataError::Serialization(
                        "organization plan cache value is not UTF-8".into(),
                    ))
                })
            })
            .transpose()
    }
}

fn required<'a>(value: &'a str, field: &'static str) -> Result<&'a str, OrganizationCacheError> {
    let value = value.trim();
    if value.is_empty() {
        Err(OrganizationCacheError::InvalidIdentifier(field))
    } else {
        Ok(value)
    }
}
