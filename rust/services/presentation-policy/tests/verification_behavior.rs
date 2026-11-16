//! Consumer boundary: managed observations cannot acquire provenance through
//! legacy control-plane configuration, even when credentials are configured.

use marty_presentation_policy::{NativePresentationControlPlane, PresentationTrustResolver};
use std::time::Duration;
use uuid::Uuid;

#[tokio::test]
async fn managed_freeze_requires_dedicated_authenticated_owner_configuration() {
    for origin in ["http://127.0.0.1:1", "https://unconfigured-owner.example"] {
        let control = NativePresentationControlPlane::connect_lazy(
            "127.0.0.1:1",
            origin,
            "http://127.0.0.1:1/v1/issuance/credentials/{credential_id}/status",
            Some("configured-service-token"),
            Some("configured-api-key"),
            Duration::from_millis(50),
        )
        .unwrap();
        assert!(control
            .freeze_credential_authority(Uuid::from_u128(1), Uuid::from_u128(2))
            .await
            .is_err());
    }
}
