use async_trait::async_trait;
use chrono::Utc;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;

use crate::{DeviceError, DeviceRegistration};

#[async_trait]
pub trait DeviceRepository: Send + Sync {
    async fn save(
        &self,
        registration: DeviceRegistration,
    ) -> Result<DeviceRegistration, DeviceError>;
    async fn get(&self, registration_id: &str) -> Result<Option<DeviceRegistration>, DeviceError>;
    async fn list_for_user(
        &self,
        user_id: &str,
        organization_id: Option<&str>,
    ) -> Result<Vec<DeviceRegistration>, DeviceError>;
    async fn deactivate(
        &self,
        registration_id: &str,
    ) -> Result<Option<DeviceRegistration>, DeviceError>;
}

#[derive(Debug, Clone, Default)]
pub struct MemoryDeviceRepository {
    registrations: Arc<Mutex<HashMap<String, DeviceRegistration>>>,
}

#[async_trait]
impl DeviceRepository for MemoryDeviceRepository {
    async fn save(
        &self,
        mut registration: DeviceRegistration,
    ) -> Result<DeviceRegistration, DeviceError> {
        let preferences = serde_json::to_value(&registration.preferences)
            .map_err(|error| DeviceError::Persistence(error.to_string()))?;
        crate::domain::reject_private_preferences(&preferences)?;
        let mut registrations = self.registrations.lock().await;
        if let Some(current) = registrations.get(&registration.id) {
            if current.user_id != registration.user_id
                || current.organization_id != registration.organization_id
                || current.device_id != registration.device_id
            {
                return Err(DeviceError::Conflict(
                    "device registration identity is immutable".into(),
                ));
            }
            if !current.is_active && registration.is_active {
                return Err(DeviceError::Conflict(
                    "deactivated device cannot be reactivated".into(),
                ));
            }
            if current.is_active && !registration.is_active {
                return Err(DeviceError::Conflict(
                    "device deactivation must use the revocation transition".into(),
                ));
            }
        }
        if let Some(existing) = registrations
            .values()
            .find(|candidate| {
                candidate.is_active
                    && candidate.user_id == registration.user_id
                    && candidate.device_id == registration.device_id
                    && candidate.organization_id == registration.organization_id
            })
            .cloned()
        {
            if !registration.is_active {
                return Err(DeviceError::Conflict(
                    "device deactivation must use the revocation transition".into(),
                ));
            }
            registration.id = existing.id;
            registration.created_at = existing.created_at;
        }
        registrations.insert(registration.id.clone(), registration.clone());
        Ok(registration)
    }

    async fn get(&self, registration_id: &str) -> Result<Option<DeviceRegistration>, DeviceError> {
        Ok(self
            .registrations
            .lock()
            .await
            .get(registration_id)
            .cloned())
    }

    async fn list_for_user(
        &self,
        user_id: &str,
        organization_id: Option<&str>,
    ) -> Result<Vec<DeviceRegistration>, DeviceError> {
        let mut values: Vec<_> = self
            .registrations
            .lock()
            .await
            .values()
            .filter(|item| {
                item.user_id == user_id
                    && organization_id.is_none_or(|id| item.organization_id.as_deref() == Some(id))
            })
            .cloned()
            .collect();
        values.sort_by_key(|item| std::cmp::Reverse(item.updated_at));
        Ok(values)
    }

    async fn deactivate(
        &self,
        registration_id: &str,
    ) -> Result<Option<DeviceRegistration>, DeviceError> {
        let mut registrations = self.registrations.lock().await;
        let Some(registration) = registrations.get_mut(registration_id) else {
            return Ok(None);
        };
        if registration.is_active {
            registration.is_active = false;
            registration.updated_at = Utc::now();
        }
        Ok(Some(registration.clone()))
    }
}
