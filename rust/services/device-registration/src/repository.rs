use async_trait::async_trait;
use chrono::{Duration, Utc};
use marty_verification::device_auth::{
    evaluate_device_key_eligibility, DeviceChallengeRecord, DeviceKeyEligibilityRequest,
    DeviceKeyRecord, DeviceKeyState, MAX_KEY_VERSION, MAX_ROTATION_GRACE_SECONDS,
};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::{DeviceError, DeviceRegistration, NewDeviceKey};

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
    async fn rotate_key(
        &self,
        registration_id: &str,
        expected_version: u64,
        public_key_der: &str,
        public_key_kid: &str,
        grace_seconds: u64,
    ) -> Result<DeviceRegistration, DeviceError>;
    async fn deactivate(
        &self,
        registration_id: &str,
    ) -> Result<Option<DeviceRegistration>, DeviceError>;
    async fn resolve_challenge_key(
        &self,
        challenge: &DeviceChallengeRecord,
        purpose: &str,
        audience: &str,
    ) -> Result<Option<DeviceKeyRecord>, DeviceError>;
}

#[derive(Debug, Default)]
struct MemoryState {
    registrations: HashMap<String, DeviceRegistration>,
    keys: HashMap<String, HashMap<u64, DeviceKeyRecord>>,
}

#[derive(Debug, Clone, Default)]
pub struct MemoryDeviceRepository {
    state: Arc<Mutex<MemoryState>>,
}

#[async_trait]
impl DeviceRepository for MemoryDeviceRepository {
    async fn save(
        &self,
        mut registration: DeviceRegistration,
    ) -> Result<DeviceRegistration, DeviceError> {
        let mut state = self.state.lock().await;
        let existing = state
            .registrations
            .values()
            .find(|candidate| {
                candidate.is_active
                    && candidate.user_id == registration.user_id
                    && candidate.device_id == registration.device_id
                    && candidate.organization_id == registration.organization_id
            })
            .cloned();
        if let Some(existing) = existing {
            registration.id = existing.id.clone();
            registration.created_at = existing.created_at;
            if existing.key_version.is_some()
                && (registration.public_key_der != existing.public_key_der
                    || registration.public_key_kid != existing.public_key_kid)
            {
                return Err(DeviceError::Conflict(
                    "existing device keys must use the rotation transition".into(),
                ));
            }
            if existing.key_version.is_some() {
                registration.key_version = existing.key_version;
                registration.key_valid_from = existing.key_valid_from;
                registration.key_valid_until = existing.key_valid_until;
            }
        }
        if registration.public_key_der.is_some() && registration.key_version.is_none() {
            let now = Utc::now();
            registration.key_version = Some(1);
            registration.key_valid_from = Some(now);
            let key = NewDeviceKey::current(
                Uuid::new_v4().to_string(),
                registration.id.clone(),
                1,
                registration.public_key_der.clone().expect("checked"),
                registration.public_key_kid.clone().expect("validated"),
                now,
            );
            state
                .keys
                .entry(registration.id.clone())
                .or_default()
                .insert(1, key);
        }
        state
            .registrations
            .insert(registration.id.clone(), registration.clone());
        Ok(registration)
    }

    async fn get(&self, registration_id: &str) -> Result<Option<DeviceRegistration>, DeviceError> {
        Ok(self
            .state
            .lock()
            .await
            .registrations
            .get(registration_id)
            .cloned())
    }

    async fn list_for_user(
        &self,
        user_id: &str,
        organization_id: Option<&str>,
    ) -> Result<Vec<DeviceRegistration>, DeviceError> {
        let mut values: Vec<_> = self
            .state
            .lock()
            .await
            .registrations
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

    async fn rotate_key(
        &self,
        registration_id: &str,
        expected_version: u64,
        public_key_der: &str,
        public_key_kid: &str,
        grace_seconds: u64,
    ) -> Result<DeviceRegistration, DeviceError> {
        if grace_seconds > MAX_ROTATION_GRACE_SECONDS {
            return Err(DeviceError::BadRequest(
                "device key rotation grace is outside server bounds".into(),
            ));
        }
        let mut state = self.state.lock().await;
        let registration = state
            .registrations
            .get(registration_id)
            .cloned()
            .ok_or_else(|| DeviceError::Conflict("device registration no longer exists".into()))?;
        if !registration.is_active {
            return Err(DeviceError::Conflict(
                "inactive device registrations cannot rotate keys".into(),
            ));
        }
        if registration.key_version != Some(expected_version) {
            return Err(DeviceError::Conflict(
                "current device key version changed".into(),
            ));
        }
        if expected_version >= MAX_KEY_VERSION {
            return Err(DeviceError::Conflict(
                "device key version limit reached".into(),
            ));
        }
        let now = Utc::now();
        let keys = state
            .keys
            .get_mut(registration_id)
            .ok_or_else(|| DeviceError::Conflict("current device key version changed".into()))?;
        let mut old = keys
            .get(&expected_version)
            .cloned()
            .filter(|key| key.state == DeviceKeyState::Current)
            .ok_or_else(|| DeviceError::Conflict("current device key version changed".into()))?;
        old.state = DeviceKeyState::Retiring;
        old.rotated_at = Some(now.to_rfc3339());
        old.retire_at = Some((now + Duration::seconds(grace_seconds as i64)).to_rfc3339());
        keys.insert(expected_version, old);
        let new_version = expected_version + 1;
        keys.insert(
            new_version,
            NewDeviceKey::current(
                Uuid::new_v4().to_string(),
                registration_id.into(),
                new_version,
                public_key_der.into(),
                public_key_kid.into(),
                now,
            ),
        );
        let registration = state
            .registrations
            .get_mut(registration_id)
            .expect("locked registration");
        registration.public_key_der = Some(public_key_der.into());
        registration.public_key_kid = Some(public_key_kid.into());
        registration.key_valid_from = Some(now);
        registration.key_valid_until = None;
        registration.key_version = Some(new_version);
        registration.updated_at = now;
        registration.last_seen_at = Some(now);
        Ok(registration.clone())
    }

    async fn deactivate(
        &self,
        registration_id: &str,
    ) -> Result<Option<DeviceRegistration>, DeviceError> {
        let mut state = self.state.lock().await;
        let Some(existing) = state.registrations.get(registration_id).cloned() else {
            return Ok(None);
        };
        if !existing.is_active {
            return Ok(Some(existing));
        }
        let now = Utc::now();
        if let Some(keys) = state.keys.get_mut(registration_id) {
            for key in keys.values_mut() {
                if matches!(
                    key.state,
                    DeviceKeyState::Current | DeviceKeyState::Retiring
                ) {
                    key.state = DeviceKeyState::Revoked;
                    key.revoked_at = Some(now.to_rfc3339());
                }
            }
        }
        let registration = state
            .registrations
            .get_mut(registration_id)
            .expect("locked registration");
        registration.is_active = false;
        registration.public_key_der = None;
        registration.public_key_kid = None;
        registration.key_valid_from = None;
        registration.key_valid_until = None;
        registration.key_version = None;
        registration.updated_at = now;
        Ok(Some(registration.clone()))
    }

    async fn resolve_challenge_key(
        &self,
        challenge: &DeviceChallengeRecord,
        purpose: &str,
        audience: &str,
    ) -> Result<Option<DeviceKeyRecord>, DeviceError> {
        let (Some(registration_id), Some(version)) =
            (&challenge.registration_id, challenge.key_version)
        else {
            return Ok(None);
        };
        let state = self.state.lock().await;
        let Some(registration) = state.registrations.get(registration_id) else {
            return Ok(None);
        };
        let Some(key) = state
            .keys
            .get(registration_id)
            .and_then(|keys| keys.get(&version))
            .cloned()
        else {
            return Ok(None);
        };
        let result = evaluate_device_key_eligibility(&DeviceKeyEligibilityRequest {
            key: key.clone(),
            registration_active: registration.is_active,
            challenge: challenge.clone(),
            purpose: purpose.into(),
            audience: audience.into(),
            now: Utc::now().to_rfc3339(),
        })?;
        Ok(result.eligible.then_some(key))
    }
}
