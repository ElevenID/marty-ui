//! Real loopback TLS transport trust rotation, not repository/issuance replay.
use std::time::Duration;

use marty_issuance_service::initiation_didcomm::{
    DidcommEndpointValidator, DidcommTransport, DidcommTransportOutcome,
};
use serde_json::json;

use super::didcomm_wallet_fixture::WalletFixture;

pub(super) async fn run() {
    tokio::time::timeout(Duration::from_secs(45), async {
        let first = WalletFixture::start(200);
        let second = WalletFixture::start(200);
        let ca_path = first
            .ca_file
            .parent()
            .unwrap()
            .join("rotating-operator-ca.pem");
        let transport = DidcommTransport::new(ca_path.to_str()).unwrap();
        let validator = DidcommEndpointValidator::new(true);
        let first_endpoint = validator
            .validate(&format!("{}/inbox", first.origin))
            .await
            .unwrap();
        let second_endpoint = validator
            .validate(&format!("{}/inbox", second.origin))
            .await
            .unwrap();
        let first_ca = std::fs::read(&first.ca_file).unwrap();
        let second_ca = std::fs::read(&second.ca_file).unwrap();
        assert_ne!(first_ca, second_ca);

        // All rejected configurations precede TLS connection and HTTP POST.
        assert_eq!(
            transport
                .deliver(&first_endpoint, "synthetic-missing".into())
                .await,
            DidcommTransportOutcome::TlsUnavailable
        );
        std::fs::create_dir(&ca_path).unwrap();
        assert_eq!(
            transport
                .deliver(&first_endpoint, "synthetic-directory".into())
                .await,
            DidcommTransportOutcome::TlsUnavailable
        );
        std::fs::remove_dir(&ca_path).unwrap();
        let mut mixed = first_ca.clone();
        mixed.extend_from_slice(
            b"\n-----BEGIN CERTIFICATE-----\n!invalid-base64!\n-----END CERTIFICATE-----\n",
        );
        for bytes in [Vec::new(), vec![b'x'; 1024 * 1024 + 1], mixed] {
            std::fs::write(&ca_path, bytes).unwrap();
            assert_eq!(
                transport
                    .deliver(&first_endpoint, "synthetic-invalid".into())
                    .await,
                DidcommTransportOutcome::TlsUnavailable
            );
        }
        assert_eq!(first.captures().await, json!({"messages":[],"failures":0}));
        assert_eq!(second.captures().await, json!({"messages":[],"failures":0}));

        // Same transport instance/path: trust A, replace with B, reject old A,
        // accept B. This catches caching after the first successful CA load.
        std::fs::write(&ca_path, &first_ca).unwrap();
        assert_eq!(
            transport
                .deliver(&first_endpoint, "synthetic-first".into())
                .await,
            DidcommTransportOutcome::Delivered
        );
        std::fs::write(&ca_path, &second_ca).unwrap();
        assert_eq!(
            transport
                .deliver(&first_endpoint, "synthetic-old-root".into())
                .await,
            DidcommTransportOutcome::OutcomeUnknown
        );
        assert_eq!(
            transport
                .deliver(&second_endpoint, "synthetic-second".into())
                .await,
            DidcommTransportOutcome::Delivered
        );
        let mut bundle = first_ca;
        bundle.extend_from_slice(&second_ca);
        std::fs::write(&ca_path, bundle).unwrap();
        for (endpoint, message) in [
            (&first_endpoint, "synthetic-bundle-first"),
            (&second_endpoint, "synthetic-bundle-second"),
        ] {
            assert_eq!(
                transport.deliver(endpoint, message.into()).await,
                DidcommTransportOutcome::Delivered
            );
        }
        assert_eq!(
            first.captures().await,
            json!({"messages":["synthetic-first","synthetic-bundle-first"],"failures":1})
        );
        assert_eq!(
            second.captures().await,
            json!({"messages":["synthetic-second","synthetic-bundle-second"],"failures":0})
        );
        first.close_verified();
        second.close_verified();
    })
    .await
    .expect("bounded owned CA rotation transport contract");
}
