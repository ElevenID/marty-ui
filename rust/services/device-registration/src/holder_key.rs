//! Reference-only metadata for durable OpenBao holder signing keys.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{holder_credential::eligible, DeviceError, DeviceRegistration};
use marty_holder_key_reference::belongs_to;
use marty_key_material_policy::contains_private_key;

pub use marty_holder_key_reference::new_reference;

const INVALID: &str = "managed holder key metadata is invalid";

#[derive(Clone)]
pub struct HolderKeyRecord {
    pub id: String,
    pub registration_id: String,
    pub user_id: String,
    pub organization_id: String,
    pub purpose: String,
    pub algorithm: String,
    pub provider_reference: String,
    pub remote_version: i64,
    pub public_x: String,
    pub public_y: Option<String>,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

fn public_coordinate(value: &Value, name: &str) -> Result<String, DeviceError> {
    let encoded = value
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| DeviceError::BadRequest(INVALID.into()))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| DeviceError::BadRequest(INVALID.into()))?;
    if bytes.len() != 32 || URL_SAFE_NO_PAD.encode(bytes) != encoded {
        return Err(DeviceError::BadRequest(INVALID.into()));
    }
    Ok(encoded.into())
}

impl HolderKeyRecord {
    pub fn from_provider(
        registration: &DeviceRegistration,
        purpose: &str,
        algorithm: &str,
        provider_reference: &str,
        metadata: &Value,
        now: DateTime<Utc>,
    ) -> Result<Self, DeviceError> {
        if !eligible(registration)
            || contains_private_key(metadata)
            || !matches!(purpose, "holder_binding" | "presentation_signing")
            || !matches!(algorithm, "EdDSA" | "ES256")
            || !registration
                .organization_id
                .as_deref()
                .is_some_and(|organization| {
                    belongs_to(provider_reference, organization, &registration.id, purpose)
                })
            || metadata.get("status").and_then(Value::as_str) != Some("active")
            || metadata.get("exportable").and_then(Value::as_bool) != Some(false)
            || metadata
                .get("allow_plaintext_backup")
                .and_then(Value::as_bool)
                != Some(false)
            || metadata.get("deletion_allowed").and_then(Value::as_bool) != Some(false)
            || metadata.get("type").and_then(Value::as_str)
                != Some(if algorithm == "EdDSA" {
                    "ed25519"
                } else {
                    "ecdsa-p256"
                })
        {
            return Err(DeviceError::BadRequest(INVALID.into()));
        }
        let remote_version = metadata
            .get("latest_version")
            .and_then(Value::as_i64)
            .filter(|value| *value > 0)
            .ok_or_else(|| DeviceError::BadRequest(INVALID.into()))?;
        let expected_version = remote_version.to_string();
        if metadata.get("selected_version").and_then(Value::as_str)
            != Some(expected_version.as_str())
        {
            return Err(DeviceError::BadRequest(INVALID.into()));
        }
        let jwk = metadata
            .get("public_jwk")
            .and_then(Value::as_object)
            .ok_or_else(|| DeviceError::BadRequest(INVALID.into()))?;
        if jwk
            .keys()
            .any(|name| !matches!(name.as_str(), "kty" | "crv" | "x" | "y" | "kid"))
            || jwk.get("kid").and_then(Value::as_str) != Some(provider_reference)
            || jwk.get("kty").and_then(Value::as_str)
                != Some(if algorithm == "EdDSA" { "OKP" } else { "EC" })
            || jwk.get("crv").and_then(Value::as_str)
                != Some(if algorithm == "EdDSA" {
                    "Ed25519"
                } else {
                    "P-256"
                })
            || (algorithm == "EdDSA" && jwk.contains_key("y"))
        {
            return Err(DeviceError::BadRequest(INVALID.into()));
        }
        let public_x = public_coordinate(&metadata["public_jwk"], "x")?;
        let public_y = (algorithm == "ES256")
            .then(|| public_coordinate(&metadata["public_jwk"], "y"))
            .transpose()?;
        Ok(Self {
            id: Uuid::new_v4().to_string(),
            registration_id: registration.id.clone(),
            user_id: registration.user_id.clone(),
            organization_id: registration
                .organization_id
                .clone()
                .expect("eligible scope"),
            purpose: purpose.into(),
            algorithm: algorithm.into(),
            provider_reference: provider_reference.into(),
            remote_version,
            public_x,
            public_y,
            created_at: now,
            revoked_at: None,
        })
    }

    pub fn valid_for(&self, registration: &DeviceRegistration) -> bool {
        eligible(registration)
            && self.revoked_at.is_none()
            && self.registration_id == registration.id
            && self.user_id == registration.user_id
            && registration.organization_id.as_deref() == Some(self.organization_id.as_str())
            && belongs_to(
                &self.provider_reference,
                &self.organization_id,
                &self.registration_id,
                &self.purpose,
            )
            && self.remote_version > 0
            && matches!(
                self.purpose.as_str(),
                "holder_binding" | "presentation_signing"
            )
            && matches!(self.algorithm.as_str(), "EdDSA" | "ES256")
            && self.public_y.is_some() == (self.algorithm == "ES256")
            && public_coordinate(&self.public_jwk(), "x").is_ok()
            && (self.algorithm == "EdDSA" || public_coordinate(&self.public_jwk(), "y").is_ok())
    }

    pub fn public_jwk(&self) -> Value {
        match self.public_y.as_deref() {
            Some(y) => {
                json!({"kty":"EC","crv":"P-256","x":self.public_x,"y":y,"kid":self.provider_reference})
            }
            None => {
                json!({"kty":"OKP","crv":"Ed25519","x":self.public_x,"kid":self.provider_reference})
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CreateRegistration, DevicePreferences, Platform};

    fn registration() -> DeviceRegistration {
        DeviceRegistration::new(
            "user-a".into(),
            CreateRegistration {
                user_id: None,
                organization_id: Some("org-a".into()),
                device_id: "device-a".into(),
                platform: Platform::Android,
                fcm_token: Some("push-a".into()),
                app_version: None,
                os_version: None,
                device_model: None,
                preferences: DevicePreferences::default(),
                is_active: true,
            },
            Utc::now(),
        )
    }

    #[test]
    fn accepts_only_non_exportable_tenant_scoped_public_provider_metadata() {
        let registration = registration();
        let reference = new_reference("org-a", &registration.id, "holder_binding").unwrap();
        assert!(reference.starts_with("cred-holder-"));
        let mut metadata = json!({
            "status":"active", "type":"ed25519", "latest_version":1, "selected_version":"1",
            "exportable":false, "allow_plaintext_backup":false,
            "deletion_allowed":false,
            "public_jwk":{
                "kty":"OKP", "crv":"Ed25519", "x":URL_SAFE_NO_PAD.encode([7_u8;32]),
                "kid":reference,
            }
        });
        let record = HolderKeyRecord::from_provider(
            &registration,
            "holder_binding",
            "EdDSA",
            &reference,
            &metadata,
            Utc::now(),
        )
        .unwrap();
        assert!(record.valid_for(&registration));
        assert_eq!(record.public_jwk()["kid"], reference);
        assert!(record.public_jwk().get("d").is_none());
        let presenter = new_reference("org-a", &registration.id, "presentation_signing").unwrap();
        assert!(presenter.starts_with("cred-presenter-"));
        assert!(HolderKeyRecord::from_provider(
            &registration,
            "presentation_signing",
            "EdDSA",
            &reference,
            &metadata,
            Utc::now(),
        )
        .is_err());
        assert!(HolderKeyRecord::from_provider(
            &registration,
            "holder_binding",
            "EdDSA",
            &new_reference("org-b", &registration.id, "holder_binding").unwrap(),
            &metadata,
            Utc::now(),
        )
        .is_err());
        metadata["selected_version"] = json!("2");
        assert!(HolderKeyRecord::from_provider(
            &registration,
            "holder_binding",
            "EdDSA",
            &reference,
            &metadata,
            Utc::now(),
        )
        .is_err());
        metadata["selected_version"] = json!("1");
        metadata["public_jwk"]["d"] = json!("private-key-material");
        assert!(HolderKeyRecord::from_provider(
            &registration,
            "holder_binding",
            "EdDSA",
            &reference,
            &metadata,
            Utc::now(),
        )
        .is_err());
        metadata["public_jwk"].as_object_mut().unwrap().remove("d");
        metadata["private_jwk"] = json!({"kty":"OKP","d":"private-key-material"});
        assert!(HolderKeyRecord::from_provider(
            &registration,
            "holder_binding",
            "EdDSA",
            &reference,
            &metadata,
            Utc::now(),
        )
        .is_err());
        metadata.as_object_mut().unwrap().remove("private_jwk");
        metadata["exportable"] = json!(true);
        assert!(HolderKeyRecord::from_provider(
            &registration,
            "holder_binding",
            "EdDSA",
            &reference,
            &metadata,
            Utc::now(),
        )
        .is_err());
    }
}
