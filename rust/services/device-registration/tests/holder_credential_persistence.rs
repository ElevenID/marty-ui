use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{Duration, Utc};
use marty_device_registration::{
    holder_credential::{authorize, issue},
    holder_credential_repository::{
        authorize_bearer, HolderCredentialRepository, PostgresHolderCredentialRepository,
    },
    holder_key::{new_reference, HolderKeyRecord},
    holder_key_cleanup::HolderKeyCleanup,
    holder_key_repository::PostgresHolderKeyRepository,
    migration,
    postgres::PostgresDeviceRepository,
    CreateRegistration, DeviceRegistration, DeviceRepository, Platform,
};
use sqlx::{postgres::PgPoolOptions, Row};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use uuid::Uuid;

async fn disposable_revoke(
    State(fail_once): State<Arc<AtomicBool>>,
    headers: HeaderMap,
    Json(scope): Json<serde_json::Value>,
) -> StatusCode {
    if headers
        .get("x-device-registration-key")
        .and_then(|value| value.to_str().ok())
        != Some("disposable-device-signing-key-32-chars")
        || scope["purpose"] != "holder_binding"
        || scope["organization_id"].as_str().is_none()
        || scope["registration_id"].as_str().is_none()
        || scope["provider_reference"].as_str().is_none()
    {
        return StatusCode::UNAUTHORIZED;
    }
    if fail_once.swap(false, Ordering::SeqCst) {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::OK
    }
}

#[tokio::test]
async fn durable_holder_digest_rotates_and_deactivation_revokes() {
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
        .expect("fresh schema migration");
    let devices = PostgresDeviceRepository::new(pool.clone());
    let holders = PostgresHolderCredentialRepository::new(pool.clone());
    let holder_keys = PostgresHolderKeyRepository::new(pool.clone());
    let now = Utc::now() - Duration::seconds(10);
    let registration = devices
        .save(DeviceRegistration::new(
            format!("user-{}", Uuid::new_v4()),
            CreateRegistration {
                user_id: None,
                organization_id: Some(Uuid::new_v4().to_string()),
                device_id: Uuid::new_v4().to_string(),
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
            now,
        ))
        .await
        .expect("keyless registration");

    let first = issue(&registration, now, Duration::hours(1)).expect("first bearer");
    holders
        .replace(first.record.clone(), now)
        .await
        .expect("store digest");
    let stored = holders
        .find_by_digest(&first.record.token_sha256)
        .await
        .expect("lookup")
        .expect("first digest");
    assert!(authorize(
        &stored,
        &first.bearer,
        &registration,
        &registration.user_id,
        registration.organization_id.as_deref().unwrap(),
        now,
    )
    .is_ok());
    assert!(authorize_bearer(
        &holders,
        &devices,
        &first.bearer,
        &registration.user_id,
        registration.organization_id.as_deref().unwrap(),
        now,
    )
    .await
    .is_ok());
    assert!(authorize_bearer(
        &holders,
        &devices,
        &first.bearer,
        "wrong-user",
        registration.organization_id.as_deref().unwrap(),
        now,
    )
    .await
    .is_err());
    let raw: Vec<u8> = sqlx::query_scalar("SELECT token_sha256 FROM device_registration_service.device_holder_credentials WHERE id=$1")
        .bind(&first.record.id)
        .fetch_one(&pool)
        .await
        .expect("stored digest");
    assert_eq!(raw, first.record.token_sha256);
    assert_ne!(raw, first.bearer.as_bytes());

    let second = issue(
        &registration,
        now + Duration::seconds(1),
        Duration::hours(1),
    )
    .expect("replacement bearer");
    holders
        .replace(second.record.clone(), now + Duration::seconds(1))
        .await
        .expect("atomic replacement");
    let retired = holders
        .find_by_digest(&first.record.token_sha256)
        .await
        .expect("retired lookup")
        .expect("retired audit row");
    assert!(retired.revoked_at.is_some());
    assert!(authorize_bearer(
        &holders,
        &devices,
        &first.bearer,
        &registration.user_id,
        registration.organization_id.as_deref().unwrap(),
        now + Duration::seconds(1),
    )
    .await
    .is_err());
    assert!(authorize(
        &retired,
        &first.bearer,
        &registration,
        &registration.user_id,
        registration.organization_id.as_deref().unwrap(),
        now + Duration::seconds(1),
    )
    .is_err());
    let active: i64 = sqlx::query("SELECT count(*) AS count FROM device_registration_service.device_holder_credentials WHERE registration_id=$1 AND revoked_at IS NULL")
        .bind(&registration.id)
        .fetch_one(&pool)
        .await
        .expect("active digest count")
        .try_get("count")
        .expect("count");
    assert_eq!(active, 1);

    let mut invalid = issue(
        &registration,
        now + Duration::seconds(2),
        Duration::hours(1),
    )
    .expect("invalid candidate")
    .record;
    invalid.user_id = "wrong-user".into();
    assert!(holders
        .replace(invalid, now + Duration::seconds(2))
        .await
        .is_err());
    let still_current = holders
        .find_by_digest(&second.record.token_sha256)
        .await
        .expect("current lookup")
        .expect("current row");
    assert!(still_current.revoked_at.is_none());

    let mut duplicate_id = issue(
        &registration,
        now + Duration::seconds(2),
        Duration::hours(1),
    )
    .expect("duplicate candidate")
    .record;
    duplicate_id.id = first.record.id.clone();
    assert!(holders
        .replace(duplicate_id, now + Duration::seconds(2))
        .await
        .is_err());
    let still_current = holders
        .find_by_digest(&second.record.token_sha256)
        .await
        .expect("current lookup after rollback")
        .expect("current row after rollback");
    assert!(still_current.revoked_at.is_none());

    holders
        .revoke(&registration.id, now + Duration::seconds(2))
        .await
        .expect("explicit revocation");
    assert!(holders
        .find_by_digest(&second.record.token_sha256)
        .await
        .expect("revoked lookup")
        .expect("revoked audit row")
        .revoked_at
        .is_some());
    let third = issue(
        &registration,
        now + Duration::seconds(3),
        Duration::hours(1),
    )
    .expect("credential after revocation");
    holders
        .replace(third.record.clone(), now + Duration::seconds(3))
        .await
        .expect("store third digest");

    let first_reference = new_reference(
        registration.organization_id.as_deref().unwrap(),
        &registration.id,
        "holder_binding",
    )
    .unwrap();
    let public_x = URL_SAFE_NO_PAD.encode([7_u8; 32]);
    let first_metadata = serde_json::json!({
        "status":"active", "type":"ed25519", "latest_version":1, "selected_version":"1",
        "exportable":false, "allow_plaintext_backup":false, "deletion_allowed":false,
        "public_jwk":{"kty":"OKP", "crv":"Ed25519", "x":public_x, "kid":first_reference}
    });
    let first_key = HolderKeyRecord::from_provider(
        &registration,
        "holder_binding",
        "EdDSA",
        &first_reference,
        &first_metadata,
        now,
    )
    .expect("provider metadata projection");
    holder_keys
        .bind(first_key.clone(), now)
        .await
        .expect("bind first reference");
    let active_key = holder_keys
        .current(&registration.id, "holder_binding")
        .await
        .expect("key lookup")
        .expect("current holder reference");
    assert_eq!(active_key.provider_reference, first_reference);
    assert_eq!(active_key.public_jwk(), first_key.public_jwk());
    assert!(active_key.valid_for(&registration));

    let second_reference = new_reference(
        registration.organization_id.as_deref().unwrap(),
        &registration.id,
        "holder_binding",
    )
    .unwrap();
    let mut second_metadata = first_metadata.clone();
    second_metadata["public_jwk"]["kid"] = serde_json::json!(second_reference);
    let second_key = HolderKeyRecord::from_provider(
        &registration,
        "holder_binding",
        "EdDSA",
        &second_reference,
        &second_metadata,
        now + Duration::seconds(1),
    )
    .expect("second provider metadata");
    holder_keys
        .bind(second_key.clone(), now + Duration::seconds(1))
        .await
        .expect("rotate reference");
    assert_eq!(
        holder_keys
            .current(&registration.id, "holder_binding")
            .await
            .expect("rotated lookup")
            .expect("rotated reference")
            .provider_reference,
        second_reference
    );
    let pending: Vec<String> = sqlx::query_scalar("SELECT d.provider_reference FROM device_registration_service.device_holder_key_deletions d JOIN device_registration_service.device_holder_keys k USING (provider_reference) WHERE k.registration_id=$1 AND d.deleted_at IS NULL ORDER BY d.provider_reference")
        .bind(&registration.id)
        .fetch_all(&pool)
        .await
        .expect("rotation deletion queue");
    assert_eq!(pending, vec![first_reference.clone()]);
    let wrong_reference = HolderKeyRecord::from_provider(
        &registration,
        "holder_binding",
        "EdDSA",
        &new_reference(
            registration.organization_id.as_deref().unwrap(),
            &registration.id,
            "holder_binding",
        )
        .unwrap(),
        &second_metadata,
        now + Duration::seconds(2),
    );
    assert!(wrong_reference.is_err());
    // A failed database insert must also roll back the retirement of current.
    let mut duplicate_id = second_key.clone();
    duplicate_id.id = first_key.id.clone();
    duplicate_id.provider_reference = new_reference(
        registration.organization_id.as_deref().unwrap(),
        &registration.id,
        "holder_binding",
    )
    .unwrap();
    assert!(holder_keys
        .bind(duplicate_id, now + Duration::seconds(2))
        .await
        .is_err());
    assert_eq!(
        holder_keys
            .current(&registration.id, "holder_binding")
            .await
            .expect("post-rollback lookup")
            .expect("post-rollback reference")
            .provider_reference,
        second_reference
    );
    let pending: Vec<String> = sqlx::query_scalar("SELECT d.provider_reference FROM device_registration_service.device_holder_key_deletions d JOIN device_registration_service.device_holder_keys k USING (provider_reference) WHERE k.registration_id=$1 AND d.deleted_at IS NULL ORDER BY d.provider_reference")
        .bind(&registration.id)
        .fetch_all(&pool)
        .await
        .expect("rollback did not queue current key");
    assert_eq!(pending, vec![first_reference.clone()]);

    devices
        .deactivate(&registration.id)
        .await
        .expect("deactivate")
        .expect("registration");
    let revoked = holders
        .find_by_digest(&third.record.token_sha256)
        .await
        .expect("revoked lookup")
        .expect("second audit row");
    assert!(revoked.revoked_at.is_some());
    assert!(holder_keys
        .current(&registration.id, "holder_binding")
        .await
        .expect("deactivated key lookup")
        .is_none());
    let pending: Vec<String> = sqlx::query_scalar("SELECT d.provider_reference FROM device_registration_service.device_holder_key_deletions d JOIN device_registration_service.device_holder_keys k USING (provider_reference) WHERE k.registration_id=$1 AND d.deleted_at IS NULL ORDER BY d.provider_reference")
        .bind(&registration.id)
        .fetch_all(&pool)
        .await
        .expect("deactivation deletion queue");
    let mut expected = vec![first_reference, second_reference];
    expected.sort();
    assert_eq!(pending, expected);
    let pending = holder_keys
        .pending_deletions(100)
        .await
        .expect("remote cleanup work")
        .into_iter()
        .filter(|entry| entry.registration_id == registration.id)
        .collect::<Vec<_>>();
    assert_eq!(pending.len(), 2);
    for entry in &pending {
        assert_eq!(
            entry.organization_id,
            registration.organization_id.as_deref().unwrap()
        );
        assert_eq!(entry.purpose, "holder_binding");
    }
    holder_keys
        .mark_deleted(&pending[0].provider_reference, Utc::now())
        .await
        .expect("mark confirmed remote deletion");
    assert!(
        holder_keys
            .pending_deletions(100)
            .await
            .expect("remaining cleanup work")
            .iter()
            .filter(|entry| entry.registration_id == registration.id)
            .count()
            == 1
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("disposable holder revoke listener");
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route(
                    "/internal/device-registration/holder-keys/revoke",
                    post(disposable_revoke),
                )
                .with_state(Arc::new(AtomicBool::new(true))),
        )
        .await
    });
    let cleanup = HolderKeyCleanup::new(
        holder_keys.clone(),
        &origin,
        "disposable-device-signing-key-32-chars".into(),
    )
    .expect("cleanup client");
    assert_eq!(
        cleanup.run_once().await.expect("failed remote attempt"),
        (0, 1)
    );
    let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM device_registration_service.device_holder_key_deletions d JOIN device_registration_service.device_holder_keys k USING (provider_reference) WHERE k.registration_id=$1 AND d.deleted_at IS NULL")
        .bind(&registration.id)
        .fetch_one(&pool)
        .await
        .expect("remote failure leaves durable work");
    assert_eq!(remaining, 1);
    sqlx::query("UPDATE device_registration_service.device_holder_key_deletions SET retry_after=now() WHERE provider_reference=$1")
        .bind(&pending[1].provider_reference)
        .execute(&pool)
        .await
        .expect("advance disposable retry");
    assert_eq!(
        cleanup.run_once().await.expect("successful remote retry"),
        (1, 0)
    );
    holder_keys
        .mark_deleted(&pending[1].provider_reference, Utc::now())
        .await
        .expect("completion is idempotent across workers");
    assert!(holder_keys
        .pending_deletions(100)
        .await
        .expect("completed cleanup queue")
        .iter()
        .all(|entry| entry.registration_id != registration.id));
    server.abort();
    assert!(holders
        .replace(
            issue(
                &registration,
                now + Duration::seconds(2),
                Duration::hours(1)
            )
            .expect("candidate bearer")
            .record,
            now + Duration::seconds(2),
        )
        .await
        .is_err());
}
