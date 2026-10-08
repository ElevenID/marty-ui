use chrono::Utc;
use marty_device_registration::{
    migration, postgres::PostgresDeviceRepository, CreateRegistration, DeviceRegistration,
    DeviceRepository, Platform,
};
use sqlx::postgres::PgPoolOptions;

#[tokio::test]
async fn fresh_schema_stores_only_public_device_key_metadata() {
    let Ok(database_url) = std::env::var("DEVICE_REGISTRATION_POSTGRES_TEST_URL") else {
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .expect("disposable Device Registration PostgreSQL must connect");
    migration::migrate(&pool)
        .await
        .expect("clean Device Registration schema must migrate");
    let suspect: Vec<(String, String)> = sqlx::query_as(
        "SELECT table_name, column_name FROM information_schema.columns
         WHERE table_schema='device_registration_service'
           AND (table_name ~* '(private|secret|jwk|pem)'
                OR column_name ~* '(private|secret|jwk|pem)')",
    )
    .fetch_all(&pool)
    .await
    .expect("Device Registration schema inspection");
    assert!(
        suspect.is_empty(),
        "private-key-shaped columns: {suspect:?}"
    );

    let store = PostgresDeviceRepository::new(pool.clone());
    let registration = DeviceRegistration::new(
        "synthetic-user".into(),
        CreateRegistration {
            user_id: None,
            organization_id: None,
            device_id: "synthetic-device".into(),
            platform: Platform::Web,
            fcm_token: "synthetic-push-token".into(),
            app_version: None,
            os_version: None,
            device_model: None,
            preferences: Default::default(),
            public_key_der: None,
            public_key_kid: None,
            key_valid_from: None,
            key_valid_until: None,
            is_active: true,
        },
        Utc::now(),
    );
    let saved = store.save(registration).await.expect("public-only save");
    assert!(store.get(&saved.id).await.expect("lookup").is_some());
    let mut rejected = saved.clone();
    rejected.preferences.quiet_hours_start =
        Some("-----BEGIN PRIVATE KEY-----synthetic-----END PRIVATE KEY-----".into());
    assert!(store.save(rejected).await.is_err());
    let stored: serde_json::Value = sqlx::query_scalar(
        "SELECT preferences FROM device_registration_service.device_registrations WHERE id=$1",
    )
    .bind(&saved.id)
    .fetch_one(&pool)
    .await
    .expect("stored public preferences");
    assert!(!marty_key_material_policy::contains_private_key(&stored));
}
