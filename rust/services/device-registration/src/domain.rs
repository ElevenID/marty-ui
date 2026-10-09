use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Ios,
    Android,
    Web,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevicePreferences {
    #[serde(default = "yes")]
    pub credential_notifications: bool,
    #[serde(default = "yes")]
    pub verification_notifications: bool,
    #[serde(default = "yes")]
    pub system_notifications: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quiet_hours_start: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quiet_hours_end: Option<String>,
}

const fn yes() -> bool {
    true
}

impl Default for DevicePreferences {
    fn default() -> Self {
        Self {
            credential_notifications: true,
            verification_notifications: true,
            system_notifications: true,
            quiet_hours_start: None,
            quiet_hours_end: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceRegistration {
    pub id: String,
    pub user_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    pub device_id: String,
    pub platform: Platform,
    pub fcm_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_model: Option<String>,
    #[serde(default)]
    pub preferences: DevicePreferences,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen_at: Option<DateTime<Utc>>,
}

impl DeviceRegistration {
    pub fn new(user_id: String, input: CreateRegistration, now: DateTime<Utc>) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            user_id,
            organization_id: input.organization_id,
            device_id: input.device_id,
            platform: input.platform,
            fcm_token: input.fcm_token,
            app_version: input.app_version,
            os_version: input.os_version,
            device_model: input.device_model,
            preferences: input.preferences,
            is_active: input.is_active,
            created_at: now,
            updated_at: now,
            last_seen_at: Some(now),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateRegistration {
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub organization_id: Option<String>,
    pub device_id: String,
    pub platform: Platform,
    pub fcm_token: String,
    #[serde(default)]
    pub app_version: Option<String>,
    #[serde(default)]
    pub os_version: Option<String>,
    #[serde(default)]
    pub device_model: Option<String>,
    #[serde(default)]
    pub preferences: DevicePreferences,
    #[serde(default = "yes")]
    pub is_active: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateRegistration {
    pub fcm_token: Option<String>,
    pub app_version: Option<String>,
    pub os_version: Option<String>,
    pub device_model: Option<String>,
    pub preferences: Option<DevicePreferences>,
    pub is_active: Option<bool>,
    pub last_seen_at: Option<String>,
}

#[derive(Debug, Error)]
pub enum DeviceError {
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    Forbidden(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Conflict(String),
    #[error("device persistence is unavailable: {0}")]
    Persistence(String),
    #[error("device pairing storage is unavailable: {0}")]
    PairingStore(String),
    #[error("organization authorization is unavailable")]
    AuthorizationUnavailable,
}

pub fn detail(error: &DeviceError) -> Value {
    Value::String(error.to_string())
}

pub(crate) fn reject_private_preferences(value: &Value) -> Result<(), DeviceError> {
    if marty_key_material_policy::contains_private_key(value) {
        return Err(DeviceError::BadRequest(
            "device preferences cannot contain private key material".into(),
        ));
    }
    Ok(())
}
