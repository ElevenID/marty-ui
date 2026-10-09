//! Reserve, remotely create, and bind one non-exportable holder key.

use chrono::Utc;
use marty_holder_key_reference::{new_reference, CreateHolderKeyRequest, HolderKeyScope};
use std::sync::Arc;

use crate::{
    holder_credential::eligible, holder_key::HolderKeyRecord, holder_key_client::HolderKeyClient,
    holder_key_repository::PostgresHolderKeyRepository, DeviceError, DeviceRepository,
};

pub struct HolderKeyProvisioner {
    devices: Arc<dyn DeviceRepository>,
    keys: PostgresHolderKeyRepository,
    client: HolderKeyClient,
}

impl HolderKeyProvisioner {
    pub fn new(
        devices: Arc<dyn DeviceRepository>,
        keys: PostgresHolderKeyRepository,
        client: HolderKeyClient,
    ) -> Self {
        Self {
            devices,
            keys,
            client,
        }
    }

    /// The caller must authorize enrollment separately. No public route calls
    /// this until the device-pairing or step-up policy is settled.
    pub async fn provision(
        &self,
        user_id: &str,
        organization_id: &str,
        registration_id: &str,
        purpose: &str,
        algorithm: &str,
    ) -> Result<HolderKeyRecord, DeviceError> {
        let registration =
            self.devices.get(registration_id).await?.ok_or_else(|| {
                DeviceError::Forbidden("managed holder enrollment is invalid".into())
            })?;
        if registration.user_id != user_id
            || registration.organization_id.as_deref() != Some(organization_id)
            || !eligible(&registration)
        {
            return Err(DeviceError::Forbidden(
                "managed holder enrollment is invalid".into(),
            ));
        }
        let provider_reference = new_reference(organization_id, registration_id, purpose)
            .ok_or_else(|| DeviceError::BadRequest("managed holder purpose is invalid".into()))?;
        self.keys
            .reserve(registration_id, purpose, algorithm, &provider_reference)
            .await?;
        let outcome = async {
            let metadata = self
                .client
                .create(&CreateHolderKeyRequest {
                    scope: HolderKeyScope {
                        organization_id: organization_id.into(),
                        registration_id: registration_id.into(),
                        purpose: purpose.into(),
                        provider_reference: provider_reference.clone(),
                    },
                    algorithm: algorithm.into(),
                })
                .await?;
            let now = Utc::now();
            let record = HolderKeyRecord::from_provider(
                &registration,
                purpose,
                algorithm,
                &provider_reference,
                &metadata,
                now,
            )?;
            self.keys.bind(record.clone(), now).await?;
            Ok(record)
        }
        .await;
        if outcome.is_err() {
            // The reservation persists even if this update fails or the process
            // crashes; its original deadline still triggers remote cleanup.
            let _ = self.keys.abandon_provision(&provider_reference).await;
        }
        outcome
    }
}
