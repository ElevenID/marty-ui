use chrono::{DateTime, Utc};
use marty_verification::device_auth::{DeviceKeyRecord, DeviceKeyState, MAX_KEY_VERSION};
use serde::{de::Error as _, Deserialize, Deserializer, Serialize};
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key_der: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key_kid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_valid_from: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_valid_until: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_version: Option<u64>,
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
            public_key_der: input.public_key_der,
            public_key_kid: input.public_key_kid,
            key_valid_from: None,
            key_valid_until: None,
            key_version: None,
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
    #[serde(default)]
    pub public_key_der: Option<String>,
    #[serde(default)]
    pub public_key_kid: Option<String>,
    #[serde(default)]
    pub key_valid_from: Option<String>,
    #[serde(default)]
    pub key_valid_until: Option<String>,
    #[serde(default = "yes")]
    pub is_active: bool,
}

#[derive(Debug, Clone, Default)]
pub struct UpdateRegistration {
    pub fcm_token: Option<String>,
    pub app_version: Option<String>,
    pub os_version: Option<String>,
    pub device_model: Option<String>,
    pub preferences: Option<DevicePreferences>,
    pub public_key_der: Option<String>,
    pub public_key_kid: Option<String>,
    pub key_valid_from: Option<String>,
    pub key_valid_until: Option<String>,
    pub expected_key_version: Option<u64>,
    pub is_active: Option<bool>,
    pub last_seen_at: Option<String>,
    #[doc(hidden)]
    pub additional_field_was_provided: bool,
}

impl UpdateRegistration {
    pub fn has_metadata_with_key_rotation(&self) -> bool {
        self.public_key_der.is_some() && self.additional_field_was_provided
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateRegistrationWire {
    fcm_token: Option<String>,
    app_version: Option<String>,
    os_version: Option<String>,
    device_model: Option<String>,
    preferences: Option<DevicePreferences>,
    public_key_der: Option<String>,
    public_key_kid: Option<String>,
    key_valid_from: Option<String>,
    key_valid_until: Option<String>,
    expected_key_version: Option<u64>,
    is_active: Option<bool>,
    last_seen_at: Option<String>,
}

impl<'de> Deserialize<'de> for UpdateRegistration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        let additional_field_was_provided = value.as_object().is_some_and(|object| {
            object.keys().any(|field| {
                !matches!(
                    field.as_str(),
                    "public_key_der" | "public_key_kid" | "expected_key_version"
                )
            })
        });
        let wire: UpdateRegistrationWire =
            serde_json::from_value(value).map_err(D::Error::custom)?;
        Ok(Self {
            fcm_token: wire.fcm_token,
            app_version: wire.app_version,
            os_version: wire.os_version,
            device_model: wire.device_model,
            preferences: wire.preferences,
            public_key_der: wire.public_key_der,
            public_key_kid: wire.public_key_kid,
            key_valid_from: wire.key_valid_from,
            key_valid_until: wire.key_valid_until,
            expected_key_version: wire.expected_key_version,
            is_active: wire.is_active,
            last_seen_at: wire.last_seen_at,
            additional_field_was_provided,
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengeRequest {
    pub device_id: String,
    pub public_key_der: String,
    pub public_key_kid: String,
    #[serde(default)]
    pub registration_id: Option<String>,
    #[serde(default)]
    pub expected_key_version: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChallengeResponse {
    pub challenge_id: String,
    pub challenge: String,
    pub algorithm: &'static str,
    pub audience: &'static str,
    pub expires_in: u64,
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
    #[error("native device-auth operation failed: {0}")]
    Native(String),
    #[error("device persistence is unavailable: {0}")]
    Persistence(String),
    #[error("device challenge storage is unavailable: {0}")]
    ChallengeStore(String),
    #[error("organization authorization is unavailable")]
    AuthorizationUnavailable,
}

impl From<marty_verification::device_auth::DeviceAuthError> for DeviceError {
    fn from(value: marty_verification::device_auth::DeviceAuthError) -> Self {
        Self::BadRequest(value.to_string())
    }
}

pub struct NewDeviceKey;

impl NewDeviceKey {
    pub fn current(
        id: String,
        registration_id: String,
        key_version: u64,
        public_key_der: String,
        public_key_kid: String,
        now: DateTime<Utc>,
    ) -> DeviceKeyRecord {
        DeviceKeyRecord {
            id,
            registration_id,
            key_version: key_version.min(MAX_KEY_VERSION),
            public_key_der,
            public_key_kid,
            state: DeviceKeyState::Current,
            valid_from: now.to_rfc3339(),
            valid_until: None,
            rotated_at: None,
            retire_at: None,
            revoked_at: None,
            created_at: Some(now.to_rfc3339()),
        }
    }
}

pub fn detail(error: &DeviceError) -> Value {
    Value::String(error.to_string())
}
