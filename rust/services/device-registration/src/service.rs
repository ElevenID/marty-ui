use chrono::{DateTime, Utc};
use marty_verification::device_auth::{
    evaluate_device_challenge_binding, validate_device_public_key,
    verify_device_challenge_signature, DeviceChallengeBindingRequest, CHALLENGE_AUDIENCE,
    MAX_KEY_VERSION, MAX_ROTATION_GRACE_SECONDS,
};
use std::sync::Arc;

use crate::{
    challenge::{ChallengeIssue, ChallengeRepository},
    ChallengeRequest, ChallengeResponse, CreateRegistration, DeviceError, DeviceRegistration,
    DeviceRepository, UpdateRegistration,
};

#[derive(Debug, Clone, Default)]
pub struct ProofHeaders {
    pub challenge_id: Option<String>,
    pub signature: Option<String>,
}

struct ProofContext<'a> {
    user_id: &'a str,
    device_id: &'a str,
    public_key_der: &'a str,
    public_key_kid: Option<&'a str>,
    proof: ProofHeaders,
    registration_id: Option<String>,
    key_version: Option<u64>,
    purpose: &'a str,
}

#[derive(Clone)]
pub struct DeviceService {
    repository: Arc<dyn DeviceRepository>,
    challenges: Arc<dyn ChallengeRepository>,
    rotation_grace_seconds: u64,
}

impl std::fmt::Debug for DeviceService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeviceService")
            .field("rotation_grace_seconds", &self.rotation_grace_seconds)
            .finish_non_exhaustive()
    }
}

impl DeviceService {
    pub fn new(
        repository: Arc<dyn DeviceRepository>,
        challenges: Arc<dyn ChallengeRepository>,
        rotation_grace_seconds: u64,
    ) -> Result<Self, DeviceError> {
        if rotation_grace_seconds > MAX_ROTATION_GRACE_SECONDS {
            return Err(DeviceError::BadRequest(format!("DEVICE_KEY_ROTATION_GRACE_SECONDS must be between 0 and {MAX_ROTATION_GRACE_SECONDS}")));
        }
        Ok(Self {
            repository,
            challenges,
            rotation_grace_seconds,
        })
    }

    pub fn repository(&self) -> &Arc<dyn DeviceRepository> {
        &self.repository
    }

    pub async fn request_challenge(
        &self,
        user_id: &str,
        body: ChallengeRequest,
    ) -> Result<ChallengeResponse, DeviceError> {
        validate_challenge_input(&body)?;
        let inspection = validate_device_public_key(&body.public_key_der, &body.public_key_kid)?;
        let registration = if let Some(registration_id) = body.registration_id.as_deref() {
            let registration = self.repository.get(registration_id).await?;
            match registration {
                Some(value) if value.user_id == user_id && value.device_id == body.device_id => {
                    Some(value)
                }
                _ => {
                    return Err(DeviceError::NotFound(
                        "Device registration not found".into(),
                    ))
                }
            }
        } else {
            let matches: Vec<_> = self
                .repository
                .list_for_user(user_id, None)
                .await?
                .into_iter()
                .filter(|candidate| candidate.device_id == body.device_id && candidate.is_active)
                .collect();
            if matches.len() > 1 {
                return Err(DeviceError::BadRequest(
                    "registration_id is required for an ambiguous device_id".into(),
                ));
            }
            matches.into_iter().next()
        };
        if registration.as_ref().is_some_and(|value| !value.is_active) {
            return Err(DeviceError::Conflict(
                "Device registration is inactive".into(),
            ));
        }
        let expected_version = registration.as_ref().and_then(|value| value.key_version);
        let purpose = if let Some(expected) = expected_version {
            let supplied = body.expected_key_version.ok_or_else(|| {
                DeviceError::BadRequest("expected_key_version is required for key rotation".into())
            })?;
            if supplied != expected {
                return Err(DeviceError::Conflict(
                    "Current device key version changed".into(),
                ));
            }
            "device_key_rotation"
        } else {
            if body.expected_key_version.is_some() {
                return Err(DeviceError::BadRequest(
                    "expected_key_version requires an existing current key".into(),
                ));
            }
            "device_registration"
        };
        let record = self
            .challenges
            .issue(ChallengeIssue {
                user_id: user_id.into(),
                device_id: body.device_id.clone(),
                public_key_kid: body.public_key_kid.clone(),
                public_key_sha256: inspection.public_key_sha256,
                registration_id: registration.as_ref().map(|value| value.id.clone()),
                key_version: expected_version,
                purpose: purpose.into(),
            })
            .await?;
        Ok(ChallengeResponse {
            challenge_id: record.challenge_id.clone(),
            challenge: record.encoded_message()?,
            algorithm: "PS256",
            audience: CHALLENGE_AUDIENCE,
            expires_in: self.challenges.ttl_seconds(),
        })
    }

    pub async fn register(
        &self,
        user_id: &str,
        body: CreateRegistration,
        proof: ProofHeaders,
    ) -> Result<DeviceRegistration, DeviceError> {
        validate_create(user_id, &body)?;
        let mut registration = DeviceRegistration::new(user_id.into(), body, Utc::now());
        if let Some(public_key_der) = registration.public_key_der.as_deref() {
            registration.public_key_kid = Some(
                self.consume_proof(ProofContext {
                    user_id,
                    device_id: &registration.device_id,
                    public_key_der,
                    public_key_kid: registration.public_key_kid.as_deref(),
                    proof,
                    registration_id: None,
                    key_version: None,
                    purpose: "device_registration",
                })
                .await?,
            );
        }
        self.repository.save(registration).await
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
        proof: ProofHeaders,
    ) -> Result<DeviceRegistration, DeviceError> {
        let mut registration = self.get(user_id, registration_id).await?;
        if body.key_valid_from.is_some() || body.key_valid_until.is_some() {
            return Err(DeviceError::BadRequest(
                "key validity timestamps are server-assigned".into(),
            ));
        }
        if body.has_metadata_with_key_rotation() {
            return Err(DeviceError::BadRequest(
                "key rotation cannot be combined with registration metadata changes".into(),
            ));
        }
        if let Some(public_key_der) = body.public_key_der.as_deref() {
            let expected = registration.key_version;
            if expected.is_some() && body.expected_key_version.is_none() {
                return Err(DeviceError::BadRequest(
                    "expected_key_version is required for key rotation".into(),
                ));
            }
            if body.expected_key_version != expected {
                return Err(DeviceError::Conflict(
                    "Current device key version changed".into(),
                ));
            }
            let purpose = if expected.is_some() {
                "device_key_rotation"
            } else {
                "device_registration"
            };
            let kid = self
                .consume_proof(ProofContext {
                    user_id,
                    device_id: &registration.device_id,
                    public_key_der,
                    public_key_kid: body.public_key_kid.as_deref(),
                    proof,
                    registration_id: Some(registration_id.into()),
                    key_version: expected,
                    purpose,
                })
                .await?;
            return if let Some(expected) = expected {
                self.repository
                    .rotate_key(
                        registration_id,
                        expected,
                        public_key_der,
                        &kid,
                        self.rotation_grace_seconds,
                    )
                    .await
            } else {
                registration.public_key_der = Some(public_key_der.into());
                registration.public_key_kid = Some(kid);
                self.repository.save(registration).await
            };
        }
        if body.public_key_kid.is_some() {
            return Err(DeviceError::BadRequest(
                "public_key_kid cannot change without public_key_der and proof".into(),
            ));
        }
        if body.expected_key_version.is_some() {
            return Err(DeviceError::BadRequest(
                "expected_key_version requires a public key rotation".into(),
            ));
        }
        if body.is_active == Some(true) && !registration.is_active {
            return Err(DeviceError::Conflict(
                "a deactivated device must be registered with a new key".into(),
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
            registration.fcm_token = value
        }
        if let Some(value) = body.app_version {
            registration.app_version = Some(value)
        }
        if let Some(value) = body.os_version {
            registration.os_version = Some(value)
        }
        if let Some(value) = body.device_model {
            registration.device_model = Some(value)
        }
        if let Some(value) = body.preferences {
            registration.preferences = value
        }
        registration.last_seen_at = match body.last_seen_at {
            Some(value) => Some(parse_time(&value)?),
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

    async fn consume_proof(&self, context: ProofContext<'_>) -> Result<String, DeviceError> {
        let kid = context.public_key_kid.ok_or_else(|| {
            DeviceError::BadRequest(
                "public_key_kid is required when public_key_der is present".into(),
            )
        })?;
        let inspection = validate_device_public_key(context.public_key_der, kid)?;
        let challenge_id = context.proof.challenge_id.ok_or_else(|| {
            DeviceError::BadRequest(
                "device challenge id and signature are required for public key changes".into(),
            )
        })?;
        let signature = context.proof.signature.ok_or_else(|| {
            DeviceError::BadRequest(
                "device challenge id and signature are required for public key changes".into(),
            )
        })?;
        let record = self.challenges.get(&challenge_id).await?.ok_or_else(|| {
            DeviceError::BadRequest("Device challenge is invalid or expired".into())
        })?;
        let binding = evaluate_device_challenge_binding(&DeviceChallengeBindingRequest {
            challenge: record.clone(),
            user_id: context.user_id.into(),
            device_id: context.device_id.into(),
            public_key_kid: kid.into(),
            public_key_sha256: inspection.public_key_sha256,
            registration_id: context.registration_id,
            key_version: context.key_version,
            purpose: context.purpose.into(),
            audience: CHALLENGE_AUDIENCE.into(),
            now: Utc::now().to_rfc3339(),
        })?;
        if !binding.eligible {
            return Err(DeviceError::BadRequest(
                "Device challenge binding mismatch".into(),
            ));
        }
        verify_device_challenge_signature(context.public_key_der, &record, &signature)?;
        if !self.challenges.consume(&record).await? {
            return Err(DeviceError::Conflict(
                "Device challenge was already consumed".into(),
            ));
        }
        Ok(kid.into())
    }
}

fn validate_challenge_input(body: &ChallengeRequest) -> Result<(), DeviceError> {
    nonempty_max("device_id", &body.device_id, 255)?;
    nonempty_max("public_key_der", &body.public_key_der, 8192)?;
    if body.public_key_kid.len() != 43 {
        return Err(DeviceError::BadRequest(
            "public_key_kid must contain exactly 43 characters".into(),
        ));
    }
    if body
        .registration_id
        .as_ref()
        .is_some_and(|value| value.len() > 36)
    {
        return Err(DeviceError::BadRequest(
            "registration_id exceeds 36 characters".into(),
        ));
    }
    if body
        .expected_key_version
        .is_some_and(|value| value == 0 || value > MAX_KEY_VERSION)
    {
        return Err(DeviceError::BadRequest(
            "expected_key_version is outside its supported range".into(),
        ));
    }
    Ok(())
}

fn validate_create(user_id: &str, body: &CreateRegistration) -> Result<(), DeviceError> {
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
    nonempty_max("fcm_token", &body.fcm_token, 4096)?;
    if body.public_key_der.is_some() && !body.is_active {
        return Err(DeviceError::BadRequest(
            "an initial device key requires an active registration".into(),
        ));
    }
    if body.key_valid_from.is_some() || body.key_valid_until.is_some() {
        return Err(DeviceError::BadRequest(
            "key validity timestamps are server-assigned".into(),
        ));
    }
    if body.public_key_der.is_none() && body.public_key_kid.is_some() {
        return Err(DeviceError::BadRequest(
            "public_key_kid requires public_key_der".into(),
        ));
    }
    Ok(())
}

fn nonempty_max(name: &str, value: &str, max: usize) -> Result<(), DeviceError> {
    if value.is_empty() || value.len() > max {
        return Err(DeviceError::BadRequest(format!(
            "{name} must contain between 1 and {max} characters"
        )));
    }
    Ok(())
}

fn parse_time(value: &str) -> Result<DateTime<Utc>, DeviceError> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| DeviceError::BadRequest("Invalid key timestamp".into()))
}
