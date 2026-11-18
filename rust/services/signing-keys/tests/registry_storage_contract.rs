use marty_signing_keys::registry::{storage_key, RegistryStore};
use redis::AsyncCommands;
use serde_json::Value;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires MARTY_TEST_REDIS_URL"]
async fn redis_round_trip_preserves_the_python_keyspace_and_registry_behavior() {
    let redis_url = std::env::var("MARTY_TEST_REDIS_URL").expect("test Redis URL");
    let organization_id = format!("rust-signing-registry-{}", Uuid::new_v4());
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/registry_vectors.json")).unwrap();
    let input = &fixture["normalize_registry_cases"][0]["input"];
    let expected = &fixture["normalize_registry_cases"][0]["expected"];
    let store = RegistryStore::connect(&redis_url).await.unwrap();

    assert_eq!(
        store.load(&organization_id).await.unwrap(),
        serde_json::json!({
            "services": [],
            "default_service_id": null,
            "format_defaults": {},
            "type_defaults": {},
            "key_reference_purposes": {},
        })
    );
    assert_eq!(
        store.save(&organization_id, input).await.unwrap(),
        *expected
    );
    assert_eq!(store.load(&organization_id).await.unwrap(), *expected);

    let client = redis::Client::open(redis_url).unwrap();
    let mut connection = client.get_connection_manager().await.unwrap();
    let _: () = connection.del(storage_key(&organization_id)).await.unwrap();
}
