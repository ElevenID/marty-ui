use crate::{
    ComplianceError, ComplianceProfile, ComplianceProfileResponse, ComplianceRepository,
    ComplianceStatus, CreateComplianceProfileRequest, UpdateComplianceProfileRequest,
};
use chrono::Utc;
use mmf_security::{
    authorize_tenant_membership, TenantAuthorizationFailure, TenantMembershipProvider,
};
use std::sync::Arc;

#[derive(Clone)]
pub struct ComplianceService {
    repository: Arc<dyn ComplianceRepository>,
    memberships: Arc<dyn TenantMembershipProvider>,
}
impl ComplianceService {
    pub fn new(
        repository: Arc<dyn ComplianceRepository>,
        memberships: Arc<dyn TenantMembershipProvider>,
    ) -> Self {
        Self {
            repository,
            memberships,
        }
    }
    pub async fn create(
        &self,
        r: CreateComplianceProfileRequest,
        user: &str,
    ) -> Result<ComplianceProfileResponse, ComplianceError> {
        let org = r.organization_id.clone().ok_or_else(|| {
            ComplianceError::BadRequest(
                "organization_id is required for non-system compliance profiles".into(),
            )
        })?;
        self.authorize(user, &org, "compliance-profile:create")
            .await?;
        let p = ComplianceProfile::new(r, Utc::now())?;
        self.repository.save(p.clone()).await?;
        Ok(p.response())
    }
    pub async fn list(
        &self,
        org: &str,
        limit: usize,
        offset: usize,
        user: &str,
    ) -> Result<Vec<ComplianceProfileResponse>, ComplianceError> {
        self.authorize(user, org, "compliance-profile:view").await?;
        Ok(self
            .repository
            .list(org)
            .await?
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(|p| p.response())
            .collect())
    }
    pub async fn discoverable(&self) -> Result<Vec<ComplianceProfileResponse>, ComplianceError> {
        Ok(self
            .repository
            .discoverable()
            .await?
            .into_iter()
            .map(|p| p.response())
            .collect())
    }
    pub async fn get(
        &self,
        id: &str,
        user: &str,
    ) -> Result<ComplianceProfileResponse, ComplianceError> {
        let p = self.profile(id).await?;
        if let Some(org) = &p.organization_id {
            self.authorize(user, org, "compliance-profile:view").await?;
        }
        Ok(p.response())
    }
    pub async fn update(
        &self,
        id: &str,
        r: UpdateComplianceProfileRequest,
        user: &str,
    ) -> Result<ComplianceProfileResponse, ComplianceError> {
        let mut p = self.profile(id).await?;
        let org = p.organization_id.as_deref().ok_or_else(|| {
            ComplianceError::Forbidden("System compliance profiles are immutable".into())
        })?;
        self.authorize(user, org, "compliance-profile:edit").await?;
        p.apply(r, Utc::now())?;
        self.repository.save(p.clone()).await?;
        Ok(p.response())
    }
    pub async fn activate(
        &self,
        id: &str,
        user: &str,
    ) -> Result<ComplianceProfileResponse, ComplianceError> {
        self.transition(
            id,
            user,
            ComplianceStatus::Active,
            "compliance-profile:activate",
        )
        .await
    }
    pub async fn suspend(
        &self,
        id: &str,
        user: &str,
    ) -> Result<ComplianceProfileResponse, ComplianceError> {
        self.transition(
            id,
            user,
            ComplianceStatus::Suspended,
            "compliance-profile:suspend",
        )
        .await
    }
    pub async fn delete(&self, id: &str, user: &str) -> Result<(), ComplianceError> {
        let p = self.profile(id).await?;
        let org = p.organization_id.as_deref().ok_or_else(|| {
            ComplianceError::Forbidden("System compliance profiles are immutable".into())
        })?;
        self.authorize(user, org, "compliance-profile:delete")
            .await?;
        self.repository.delete(id).await
    }
    async fn transition(
        &self,
        id: &str,
        user: &str,
        status: ComplianceStatus,
        permission: &str,
    ) -> Result<ComplianceProfileResponse, ComplianceError> {
        let mut p = self.profile(id).await?;
        let org = p.organization_id.as_deref().ok_or_else(|| {
            ComplianceError::Forbidden("System compliance profiles are immutable".into())
        })?;
        self.authorize(user, org, permission).await?;
        p.status = status;
        p.updated_at = Utc::now();
        self.repository.save(p.clone()).await?;
        Ok(p.response())
    }
    async fn profile(&self, id: &str) -> Result<ComplianceProfile, ComplianceError> {
        self.repository
            .get(id)
            .await?
            .ok_or_else(|| ComplianceError::NotFound("Compliance Profile not found".into()))
    }
    async fn authorize(
        &self,
        user: &str,
        org: &str,
        permission: &str,
    ) -> Result<(), ComplianceError> {
        if user.trim().is_empty() {
            return Err(ComplianceError::Unauthorized(
                "Authentication required".into(),
            ));
        }
        let m =
            self.memberships.membership(user, org).await.map_err(|_| {
                ComplianceError::Dependency("Organization service unavailable".into())
            })?;
        authorize_tenant_membership(permission, user, org, m.as_ref(), false).map_err(|e| match e {
            TenantAuthorizationFailure::AuthenticationRequired => {
                ComplianceError::Unauthorized("Authentication required".into())
            }
            _ => ComplianceError::Forbidden("Permission denied".into()),
        })
    }
}
