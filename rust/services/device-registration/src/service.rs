//! Keyless device registration and metadata lifecycle.

use chrono::{DateTime, Utc};
use std::sync::Arc;

use crate::{
    CreateRegistration, DeviceError, DeviceRegistration, DeviceRepository, UpdateRegistration,
};

#[derive(Clone)]
pub struct DeviceService {
    repository: Arc<dyn DeviceRepository>,
}

impl std::fmt::Debug for DeviceService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeviceService")
            .finish_non_exhaustive()
    }
}

impl DeviceService {
    pub fn new(repository: Arc<dyn DeviceRepository>) -> Self {
        Self { repository }
    }

    pub fn repository(&self) -> &Arc<dyn DeviceRepository> {
        &self.repository
    }

    pub async fn register(
        &self,
        user_id: &str,
        body: CreateRegistration,
    ) -> Result<DeviceRegistration, DeviceError> {
        if body
            .user_id
            .as_deref()
            .is_some_and(|value| value != user_id)
        {
            return Err(DeviceError::Forbidden(
                "user_id must match authenticated user".into(),
            ));
        }
        nonempty_max("device_id", &body.device_id, 255)?;
        if let Some(token) = body.fcm_token.as_deref() {
            nonempty_max("fcm_token", token, 4096)?;
        }
        self.repository
            .save(DeviceRegistration::new(user_id.into(), body, Utc::now()))
            .await
    }

    pub async fn list(
        &self,
        user_id: &str,
        organization_id: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<DeviceRegistration>, DeviceError> {
        let values = self
            .repository
            .list_for_user(user_id, organization_id)
            .await?;
        Ok(values
            .into_iter()
            .skip(offset)
            .take(limit.min(500))
            .collect())
    }

    pub async fn get(
        &self,
        user_id: &str,
        registration_id: &str,
    ) -> Result<DeviceRegistration, DeviceError> {
        self.repository
            .get(registration_id)
            .await?
            .filter(|value| value.user_id == user_id)
            .ok_or_else(|| DeviceError::NotFound("Device registration not found".into()))
    }

    pub async fn update(
        &self,
        user_id: &str,
        registration_id: &str,
        body: UpdateRegistration,
    ) -> Result<DeviceRegistration, DeviceError> {
        let mut registration = self.get(user_id, registration_id).await?;
        if body.is_active == Some(true) && !registration.is_active {
            return Err(DeviceError::Conflict(
                "a deactivated device must be registered again".into(),
            ));
        }
        if body.is_active == Some(false) {
            return self
                .repository
                .deactivate(registration_id)
                .await?
                .ok_or_else(|| DeviceError::NotFound("Device registration not found".into()));
        }
        if let Some(value) = body.fcm_token {
            nonempty_max("fcm_token", &value, 4096)?;
            registration.fcm_token = Some(value);
        }
        if let Some(value) = body.app_version {
            registration.app_version = Some(value);
        }
        if let Some(value) = body.os_version {
            registration.os_version = Some(value);
        }
        if let Some(value) = body.device_model {
            registration.device_model = Some(value);
        }
        if let Some(value) = body.preferences {
            registration.preferences = value;
        }
        registration.last_seen_at = match body.last_seen_at {
            Some(value) => Some(
                DateTime::parse_from_rfc3339(&value)
                    .map_err(|_| DeviceError::BadRequest("Invalid timestamp".into()))?
                    .with_timezone(&Utc),
            ),
            None => Some(Utc::now()),
        };
        registration.updated_at = Utc::now();
        self.repository.save(registration).await
    }

    pub async fn delete(&self, user_id: &str, registration_id: &str) -> Result<(), DeviceError> {
        self.get(user_id, registration_id).await?;
        self.repository.deactivate(registration_id).await?;
        Ok(())
    }
}

fn nonempty_max(name: &str, value: &str, max: usize) -> Result<(), DeviceError> {
    if value.is_empty() || value.len() > max {
        return Err(DeviceError::BadRequest(format!(
            "{name} must contain between 1 and {max} characters"
        )));
    }
    Ok(())
}
