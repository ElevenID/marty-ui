use std::collections::BTreeSet;

use chrono::{TimeZone, Utc};
use marty_credential_template::catalog::{
    system_delivery_destination_catalog, system_wallet_catalog,
};
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../contracts/credential-template-system-catalog.json"
    )))
    .expect("valid system catalog fixture")
}

#[test]
fn rust_catalog_preserves_every_intended_system_entry_and_capability() {
    let fixture = fixture();
    assert_eq!(fixture["schema_version"], 1);
    let now = Utc.with_ymd_and_hms(2026, 8, 21, 12, 0, 0).unwrap();
    let wallets = system_wallet_catalog(now);
    let destinations = system_delivery_destination_catalog(now);
    assert_eq!(wallets.len(), 10);
    assert_eq!(destinations.len(), 4);
    assert_eq!(
        wallets
            .iter()
            .map(|item| item.id.as_str())
            .collect::<BTreeSet<_>>(),
        fixture["wallet_ids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item.as_str().unwrap())
            .collect::<BTreeSet<_>>()
    );
    assert_eq!(
        destinations
            .iter()
            .map(|item| item.id.as_str())
            .collect::<BTreeSet<_>>(),
        fixture["destination_ids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item.as_str().unwrap())
            .collect::<BTreeSet<_>>()
    );

    let walt = wallets
        .iter()
        .find(|item| item.id == "wr-waltid-001")
        .unwrap();
    assert!(!walt.is_active);
    let google = wallets
        .iter()
        .find(|item| item.id == "wr-google-001")
        .unwrap();
    assert!(google.supports_digital_credentials);
    assert_eq!(google.supported_protocols, ["CREDENTIAL_MANAGER"]);
    let apple = wallets
        .iter()
        .find(|item| item.id == "wr-apple-001")
        .unwrap();
    assert!(apple.supports_digital_credentials);
    assert_eq!(apple.supported_protocols, ["APPLE_WALLET"]);
    let didcomm = wallets
        .iter()
        .find(|item| item.id == "wr-didcomm-001")
        .unwrap();
    assert!(!didcomm.supports_qr);
    assert!(!didcomm.supports_deeplink);
    assert_eq!(didcomm.supported_protocols, ["DIDCOMM_V2"]);

    for destination in destinations {
        assert!(destination.is_system);
        assert!(destination.organization_id.is_none());
        let expected = &fixture["destination_invariants"][&destination.id];
        assert_eq!(destination.provider, expected["provider"].as_str().unwrap());
        assert_eq!(destination.mode, expected["mode"].as_str().unwrap());
        assert_eq!(
            destination.requires_consent,
            expected["requires_consent"].as_bool().unwrap_or(false)
        );
    }
    assert_eq!(fixture["seed_policy"], "insert_missing_preserve_existing");
}
