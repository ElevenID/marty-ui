//! Opaque, revocable device credential for future remote holder signing.
//!
//! The bearer is returned once at enrollment. Persistence receives only its
//! digest and scoped metadata; this module never creates a device private key.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Duration, Utc};
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::{DeviceError, DeviceRegistration};

const TOKEN_BYTES: usize = 32;
const TOKEN_CHARS: usize = 43; // unpadded URL-safe base64 of 32 bytes
const MAX_LIFETIME_SECONDS: i64 = 30 * 24 * 60 * 60;
const INVALID: &str = "holder device credential is invalid";

#[derive(Clone)]
pub struct HolderCredentialRecord {
    pub id: String,
    pub registration_id: String,
    pub user_id: String,
    pub organization_id: String,
    pub token_sha256: [u8; 32],
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

pub struct IssuedHolderCredential {
    pub bearer: String,
    pub record: HolderCredentialRecord,
}

pub(crate) fn eligible(registration: &DeviceRegistration) -> bool {
    registration.is_active
        && !registration.user_id.trim().is_empty()
        && !registration.device_id.trim().is_empty()
        && registration
            .organization_id
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
        && registration.public_key_der.is_none()
        && registration.public_key_kid.is_none()
        && registration.key_valid_from.is_none()
        && registration.key_valid_until.is_none()
        && registration.key_version.is_none()
}

pub(crate) fn valid_record_for(
    record: &HolderCredentialRecord,
    registration: &DeviceRegistration,
    now: DateTime<Utc>,
) -> bool {
    eligible(registration)
        && record.registration_id == registration.id
        && record.user_id == registration.user_id
        && registration.organization_id.as_deref() == Some(record.organization_id.as_str())
        && record.revoked_at.is_none()
        && record.issued_at <= now
        && record.expires_at > now
        && record.expires_at > record.issued_at
        && record.expires_at - record.issued_at <= Duration::seconds(MAX_LIFETIME_SECONDS)
}

pub fn issue(
    registration: &DeviceRegistration,
    now: DateTime<Utc>,
    lifetime: Duration,
) -> Result<IssuedHolderCredential, DeviceError> {
    if !eligible(registration) {
        return Err(DeviceError::Forbidden(INVALID.into()));
    }
    let seconds = lifetime.num_seconds();
    if !(1..=MAX_LIFETIME_SECONDS).contains(&seconds) || lifetime != Duration::seconds(seconds) {
        return Err(DeviceError::BadRequest(
            "holder device credential lifetime is outside server bounds".into(),
        ));
    }
    let expires_at = now.checked_add_signed(lifetime).ok_or_else(|| {
        DeviceError::BadRequest("holder device credential expiry is invalid".into())
    })?;
    let mut random = [0_u8; TOKEN_BYTES];
    rand::rng().fill_bytes(&mut random);
    let bearer = URL_SAFE_NO_PAD.encode(random);
    let token_sha256: [u8; 32] = Sha256::digest(bearer.as_bytes()).into();
    Ok(IssuedHolderCredential {
        bearer,
        record: HolderCredentialRecord {
            id: Uuid::new_v4().to_string(),
            registration_id: registration.id.clone(),
            user_id: registration.user_id.clone(),
            organization_id: registration
                .organization_id
                .clone()
                .expect("eligible scope"),
            token_sha256,
            issued_at: now,
            expires_at,
            revoked_at: None,
        },
    })
}

pub fn authorize(
    record: &HolderCredentialRecord,
    bearer: &str,
    registration: &DeviceRegistration,
    user_id: &str,
    organization_id: &str,
    now: DateTime<Utc>,
) -> Result<(), DeviceError> {
    let digest: [u8; 32] = Sha256::digest(bearer.as_bytes()).into();
    let token_matches = digest.ct_eq(&record.token_sha256).unwrap_u8() == 1;
    if !token_matches
        || bearer.len() != TOKEN_CHARS
        || !bearer
            .bytes()
            .all(|value| value.is_ascii_alphanumeric() || value == b'-' || value == b'_')
        || !valid_record_for(record, registration, now)
        || record.user_id != user_id
        || record.organization_id != organization_id
    {
        return Err(DeviceError::Forbidden(INVALID.into()));
    }
    Ok(())
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
                fcm_token: "push-a".into(),
                app_version: None,
                os_version: None,
                device_model: None,
                preferences: DevicePreferences::default(),
                public_key_der: None,
                public_key_kid: None,
                key_valid_from: None,
                key_valid_until: None,
                is_active: true,
            },
            Utc::now(),
        )
    }

    #[test]
    fn one_time_bearer_is_scoped_and_only_digest_is_retained() {
        let now = Utc::now();
        let registration = registration();
        let first = issue(&registration, now, Duration::hours(1)).unwrap();
        let second = issue(&registration, now, Duration::hours(1)).unwrap();
        assert_ne!(first.bearer, second.bearer);
        assert_eq!(first.bearer.len(), TOKEN_CHARS);
        assert_ne!(first.record.token_sha256, second.record.token_sha256);
        assert_ne!(
            first.record.token_sha256.as_slice(),
            first.bearer.as_bytes()
        );
        assert!(authorize(
            &first.record,
            &first.bearer,
            &registration,
            "user-a",
            "org-a",
            now
        )
        .is_ok());
        for (bearer, user, org) in [
            (second.bearer.as_str(), "user-a", "org-a"),
            (first.bearer.as_str(), "user-b", "org-a"),
            (first.bearer.as_str(), "user-a", "org-b"),
        ] {
            assert!(authorize(&first.record, bearer, &registration, user, org, now).is_err());
        }
        let mut other_registration = registration.clone();
        other_registration.id = Uuid::new_v4().to_string();
        assert!(authorize(
            &first.record,
            &first.bearer,
            &other_registration,
            "user-a",
            "org-a",
            now
        )
        .is_err());
    }

    #[test]
    fn expired_revoked_inactive_or_local_key_registration_is_denied() {
        let now = Utc::now();
        let mut registration = registration();
        let mut issued = issue(&registration, now, Duration::hours(1)).unwrap();
        assert!(authorize(
            &issued.record,
            &issued.bearer,
            &registration,
            "user-a",
            "org-a",
            now + Duration::hours(1)
        )
        .is_err());
        issued.record.revoked_at = Some(now);
        assert!(authorize(
            &issued.record,
            &issued.bearer,
            &registration,
            "user-a",
            "org-a",
            now
        )
        .is_err());
        registration.is_active = false;
        assert!(issue(&registration, now, Duration::hours(1)).is_err());
        registration.is_active = true;
        registration.public_key_der = Some("legacy-local-key".into());
        assert!(issue(&registration, now, Duration::hours(1)).is_err());
        registration.public_key_der = None;
        assert!(issue(&registration, now, Duration::zero()).is_err());
        assert!(issue(&registration, now, Duration::days(31)).is_err());
    }
}
