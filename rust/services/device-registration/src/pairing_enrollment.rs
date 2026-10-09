//! Ticket-bound enrollment with server-owned identity and remote-only holder keys.

use chrono::Duration;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;

use crate::{
    control_plane::MembershipAuthorizer,
    holder_credential_repository::PostgresHolderCredentialRepository,
    holder_key_provisioner::HolderKeyProvisioner, pairing_ticket::PairingTicketRepository,
    CreateRegistration, DeviceError, DevicePreferences, DeviceService, Platform,
};

const CREDENTIAL_LIFETIME: Duration = Duration::days(1);
const INVALID_TICKET: &str = "pairing ticket is invalid or expired";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingRedeemRequest {
    pub pairing_code: String,
    pub platform: Platform,
    #[serde(default)]
    pub fcm_token: Option<String>,
    pub app_version: Option<String>,
    pub os_version: Option<String>,
    pub device_model: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PairingRedeemResult {
    pub registration_id: String,
    pub device_id: String,
    pub device_credential: String,
    pub credential_expires_at: chrono::DateTime<chrono::Utc>,
    pub holder_binding_public_jwk: Value,
    pub presentation_signing_public_jwk: Value,
}

pub struct PairingEnrollment {
    tickets: Arc<dyn PairingTicketRepository>,
    memberships: Arc<dyn MembershipAuthorizer>,
    devices: Arc<DeviceService>,
    keys: HolderKeyProvisioner,
    credentials: PostgresHolderCredentialRepository,
}

impl PairingEnrollment {
    pub fn new(
        tickets: Arc<dyn PairingTicketRepository>,
        memberships: Arc<dyn MembershipAuthorizer>,
        devices: Arc<DeviceService>,
        keys: HolderKeyProvisioner,
        credentials: PostgresHolderCredentialRepository,
    ) -> Self {
        Self {
            tickets,
            memberships,
            devices,
            keys,
            credentials,
        }
    }

    /// The ticket is consumed before any database or KMS side effect. A failed
    /// enrollment needs a new browser-approved ticket, never a token replay.
    pub async fn redeem(
        &self,
        input: PairingRedeemRequest,
    ) -> Result<PairingRedeemResult, DeviceError> {
        if !matches!(input.platform, Platform::Ios | Platform::Android)
            || input
                .fcm_token
                .as_deref()
                .is_some_and(|token| token.is_empty() || token.len() > 4096)
        {
            return Err(DeviceError::BadRequest(
                "mobile pairing metadata is invalid".into(),
            ));
        }
        let scope = self
            .tickets
            .take(&input.pairing_code)
            .await?
            .ok_or_else(|| DeviceError::Forbidden(INVALID_TICKET.into()))?;
        self.memberships
            .require_active(&scope.user_id, &scope.organization_id)
            .await?;
        let registration = self
            .devices
            .register(
                &scope.user_id,
                CreateRegistration {
                    user_id: None,
                    organization_id: Some(scope.organization_id.clone()),
                    device_id: Uuid::new_v4().to_string(),
                    platform: input.platform,
                    fcm_token: input.fcm_token,
                    app_version: input.app_version,
                    os_version: input.os_version,
                    device_model: input.device_model,
                    preferences: DevicePreferences::default(),
                    is_active: true,
                },
            )
            .await?;
        let provisioned = async {
            let binding = self
                .keys
                .provision(
                    &scope.user_id,
                    &scope.organization_id,
                    &registration.id,
                    "holder_binding",
                    "EdDSA",
                )
                .await?;
            let presentation = self
                .keys
                .provision(
                    &scope.user_id,
                    &scope.organization_id,
                    &registration.id,
                    "presentation_signing",
                    "ES256",
                )
                .await?;
            self.memberships
                .require_active(&scope.user_id, &scope.organization_id)
                .await?;
            let issued = self
                .credentials
                .issue_for_registration(
                    &registration.id,
                    &scope.user_id,
                    &scope.organization_id,
                    CREDENTIAL_LIFETIME,
                )
                .await?;
            Ok::<_, DeviceError>(PairingRedeemResult {
                registration_id: registration.id.clone(),
                device_id: registration.device_id.clone(),
                device_credential: issued.bearer,
                credential_expires_at: issued.record.expires_at,
                holder_binding_public_jwk: binding.public_jwk(),
                presentation_signing_public_jwk: presentation.public_jwk(),
            })
        }
        .await;
        if provisioned.is_err() {
            // Deactivation atomically revokes any issued bearer and queues all
            // bound remote keys for durable deletion. Provision reservations
            // have their own stale-cleanup path.
            self.devices
                .delete(&scope.user_id, &registration.id)
                .await?;
        }
        provisioned
    }
}
