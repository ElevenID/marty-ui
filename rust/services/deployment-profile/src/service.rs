use std::sync::Arc;

use chrono::Utc;
use mmf_security::{
    authorize_tenant_membership, TenantAuthorizationFailure, TenantMembershipProvider,
};

use crate::{
    ApiKeyResponse, AssignDeviceRequest, CreateDeploymentProfileRequest, CreateLaneRequest,
    DeploymentError, DeploymentProfile, DeploymentProfileResponse, DeploymentRepository, Lane,
    LaneResponse, ProfileStatus, UpdateDeploymentProfileRequest, UpdateLaneRequest,
};

#[derive(Clone)]
pub struct DeploymentService {
    repository: Arc<dyn DeploymentRepository>,
    memberships: Arc<dyn TenantMembershipProvider>,
}

impl DeploymentService {
    #[must_use]
    pub fn new(
        repository: Arc<dyn DeploymentRepository>,
        memberships: Arc<dyn TenantMembershipProvider>,
    ) -> Self {
        Self {
            repository,
            memberships,
        }
    }

    pub async fn create(
        &self,
        request: CreateDeploymentProfileRequest,
        user_id: &str,
    ) -> Result<DeploymentProfileResponse, DeploymentError> {
        self.authorize(
            user_id,
            &request.organization_id,
            "deployment-profile:create",
        )
        .await?;
        let profile = DeploymentProfile::new(request, Utc::now())?;
        self.repository.save_profile(profile.clone()).await?;
        Ok(profile.response(Vec::new()))
    }

    pub async fn list(
        &self,
        organization_id: &str,
        limit: usize,
        offset: usize,
        user_id: &str,
    ) -> Result<Vec<DeploymentProfileResponse>, DeploymentError> {
        self.authorize(user_id, organization_id, "deployment-profile:view")
            .await?;
        let profiles = self.repository.profiles(organization_id).await?;
        let mut results = Vec::new();
        for profile in profiles.into_iter().skip(offset).take(limit) {
            let lanes = self.repository.lanes(&profile.id).await?;
            results.push(profile.response(lanes));
        }
        Ok(results)
    }

    pub async fn get(
        &self,
        profile_id: &str,
        user_id: &str,
    ) -> Result<DeploymentProfileResponse, DeploymentError> {
        let profile = self.profile(profile_id).await?;
        self.authorize(user_id, &profile.organization_id, "deployment-profile:view")
            .await?;
        let lanes = self.repository.lanes(profile_id).await?;
        Ok(profile.response(lanes))
    }

    pub async fn update(
        &self,
        profile_id: &str,
        request: UpdateDeploymentProfileRequest,
        user_id: &str,
    ) -> Result<DeploymentProfileResponse, DeploymentError> {
        let mut profile = self.profile(profile_id).await?;
        self.authorize(user_id, &profile.organization_id, "deployment-profile:edit")
            .await?;
        profile.apply(request, Utc::now())?;
        self.repository.save_profile(profile.clone()).await?;
        let lanes = self.repository.lanes(profile_id).await?;
        Ok(profile.response(lanes))
    }

    pub async fn activate(
        &self,
        profile_id: &str,
        user_id: &str,
    ) -> Result<DeploymentProfileResponse, DeploymentError> {
        self.transition(
            profile_id,
            user_id,
            ProfileStatus::Active,
            "deployment-profile:activate",
        )
        .await
    }

    pub async fn suspend(
        &self,
        profile_id: &str,
        user_id: &str,
    ) -> Result<DeploymentProfileResponse, DeploymentError> {
        self.transition(
            profile_id,
            user_id,
            ProfileStatus::Suspended,
            "deployment-profile:suspend",
        )
        .await
    }

    pub async fn generate_api_key(
        &self,
        profile_id: &str,
        user_id: &str,
    ) -> Result<ApiKeyResponse, DeploymentError> {
        let mut profile = self.profile(profile_id).await?;
        self.authorize(user_id, &profile.organization_id, "api-key:create")
            .await?;
        let response = profile.generate_api_key();
        self.repository.save_profile(profile).await?;
        Ok(response)
    }

    pub async fn delete(&self, profile_id: &str, user_id: &str) -> Result<(), DeploymentError> {
        let profile = self.profile(profile_id).await?;
        self.authorize(
            user_id,
            &profile.organization_id,
            "deployment-profile:delete",
        )
        .await?;
        if profile.status == ProfileStatus::Active {
            return Err(DeploymentError::BadRequest(
                "Cannot delete an active profile. Suspend it first.".into(),
            ));
        }
        let lanes = self.repository.lanes(profile_id).await?;
        if !lanes.is_empty() {
            return Err(DeploymentError::Conflict(format!(
                "Cannot delete profile with {} lane(s). Remove all lanes first.",
                lanes.len()
            )));
        }
        self.repository.delete_profile(profile_id).await
    }

    pub async fn create_lane(
        &self,
        profile_id: &str,
        request: CreateLaneRequest,
        user_id: &str,
    ) -> Result<LaneResponse, DeploymentError> {
        let profile = self.profile(profile_id).await?;
        self.authorize(user_id, &profile.organization_id, "deployment-profile:edit")
            .await?;
        let lane = Lane::new(profile_id, request, Utc::now())?;
        self.repository.save_lane(lane.clone()).await?;
        Ok(lane.response())
    }

    pub async fn list_lanes(
        &self,
        profile_id: &str,
        limit: usize,
        offset: usize,
        user_id: &str,
    ) -> Result<Vec<LaneResponse>, DeploymentError> {
        let profile = self.profile(profile_id).await?;
        self.authorize(user_id, &profile.organization_id, "deployment-profile:view")
            .await?;
        Ok(self
            .repository
            .lanes(profile_id)
            .await?
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(|lane| lane.response())
            .collect())
    }

    pub async fn get_lane(
        &self,
        profile_id: &str,
        lane_id: &str,
        user_id: &str,
    ) -> Result<LaneResponse, DeploymentError> {
        let profile = self.profile(profile_id).await?;
        self.authorize(user_id, &profile.organization_id, "deployment-profile:view")
            .await?;
        Ok(self.lane(profile_id, lane_id).await?.response())
    }

    pub async fn update_lane(
        &self,
        profile_id: &str,
        lane_id: &str,
        request: UpdateLaneRequest,
        user_id: &str,
    ) -> Result<LaneResponse, DeploymentError> {
        let profile = self.profile(profile_id).await?;
        self.authorize(user_id, &profile.organization_id, "deployment-profile:edit")
            .await?;
        let mut lane = self.lane(profile_id, lane_id).await?;
        lane.apply(request, Utc::now())?;
        self.repository.save_lane(lane.clone()).await?;
        Ok(lane.response())
    }

    pub async fn delete_lane(
        &self,
        profile_id: &str,
        lane_id: &str,
        user_id: &str,
    ) -> Result<(), DeploymentError> {
        let profile = self.profile(profile_id).await?;
        self.authorize(user_id, &profile.organization_id, "deployment-profile:edit")
            .await?;
        let lane = self.lane(profile_id, lane_id).await?;
        if !lane.device_ids.is_empty() {
            return Err(DeploymentError::Conflict(format!(
                "Cannot delete lane with {} assigned device(s). Unassign devices first.",
                lane.device_ids.len()
            )));
        }
        self.repository.delete_lane(lane_id).await
    }

    pub async fn assign_device(
        &self,
        profile_id: &str,
        lane_id: &str,
        request: AssignDeviceRequest,
        user_id: &str,
    ) -> Result<LaneResponse, DeploymentError> {
        if request.device_id.trim().is_empty() {
            return Err(DeploymentError::BadRequest("device_id is required".into()));
        }
        let profile = self.profile(profile_id).await?;
        self.authorize(user_id, &profile.organization_id, "deployment-profile:edit")
            .await?;
        self.lane(profile_id, lane_id).await?;
        Ok(self
            .repository
            .assign_device(profile_id, lane_id, &request.device_id)
            .await?
            .response())
    }

    async fn transition(
        &self,
        profile_id: &str,
        user_id: &str,
        status: ProfileStatus,
        permission: &str,
    ) -> Result<DeploymentProfileResponse, DeploymentError> {
        let mut profile = self.profile(profile_id).await?;
        self.authorize(user_id, &profile.organization_id, permission)
            .await?;
        profile.status = status;
        profile.updated_at = Utc::now();
        self.repository.save_profile(profile.clone()).await?;
        let lanes = self.repository.lanes(profile_id).await?;
        Ok(profile.response(lanes))
    }

    async fn profile(&self, id: &str) -> Result<DeploymentProfile, DeploymentError> {
        self.repository
            .profile(id)
            .await?
            .ok_or_else(|| DeploymentError::NotFound("Deployment Profile not found".into()))
    }

    async fn lane(&self, profile_id: &str, id: &str) -> Result<Lane, DeploymentError> {
        self.repository
            .lane(id)
            .await?
            .filter(|lane| lane.deployment_profile_id == profile_id)
            .ok_or_else(|| DeploymentError::NotFound("Lane not found".into()))
    }

    async fn authorize(
        &self,
        user_id: &str,
        organization_id: &str,
        permission: &str,
    ) -> Result<(), DeploymentError> {
        if user_id.trim().is_empty() {
            return Err(DeploymentError::Unauthorized(
                "Authentication required".into(),
            ));
        }
        let membership = self
            .memberships
            .membership(user_id, organization_id)
            .await
            .map_err(|_| DeploymentError::Dependency("Organization service unavailable".into()))?;
        authorize_tenant_membership(
            permission,
            user_id,
            organization_id,
            membership.as_ref(),
            false,
        )
        .map_err(authorization_error)
    }
}

fn authorization_error(error: TenantAuthorizationFailure) -> DeploymentError {
    match error {
        TenantAuthorizationFailure::AuthenticationRequired => {
            DeploymentError::Unauthorized("Authentication required".into())
        }
        _ => DeploymentError::Forbidden("Permission denied".into()),
    }
}
