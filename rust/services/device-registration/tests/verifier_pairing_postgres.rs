//! Runs only against the newly created, nonce-guarded disposable fixture.
use marty_device_registration::{
    migration,
    pairing_confirmation::PostgresPairingConfirmations,
    pairing_ticket::{MemoryPairingTickets, PairingTicketRepository},
};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires newly created disposable PostgreSQL and nonce sentinel"]
async fn additive_verifier_migration_preserves_legacy_pairing_and_rejects_scope_substitution() {
    let url = std::env::var("DEVICE_REGISTRATION_POSTGRES_TEST_URL").expect("owned fixture URL");
    let nonce = std::env::var("MARTY_TEST_POSTGRES_DISPOSABLE_NONCE").expect("owned fixture nonce");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    let sentinel: String = sqlx::query_scalar("SELECT nonce FROM public.marty_disposable_guard")
        .fetch_one(&pool)
        .await
        .expect("fixture sentinel");
    assert_eq!(sentinel, nonce);
    assert!(!nonce.is_empty());
    let existing: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM information_schema.schemata WHERE schema_name='device_registration_service')")
        .fetch_one(&pool).await.unwrap();
    assert!(
        !existing,
        "migration qualification requires a newly created empty fixture"
    );
    // Model an existing schema only inside this fresh disposable database.
    sqlx::raw_sql(include_str!("../migrations/0001_device_registration.sql"))
        .execute(&pool)
        .await
        .unwrap();
    let already_bound: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema='device_registration_service' AND table_name='device_pairing_confirmations' AND column_name='verifier_trust_profile_id')")
        .fetch_one(&pool).await.unwrap();
    assert!(
        !already_bound,
        "starting schema must precede the verifier binding migration"
    );
    let legacy = Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO device_registration_service.device_pairing_confirmations (pairing_id,user_id,organization_id,trust_profile_id,issued_at,expires_at) VALUES ($1,'legacy-user','org-a',$2,clock_timestamp(),clock_timestamp()+interval '10 minutes')")
        .bind(&legacy).bind(Uuid::new_v4().to_string()).execute(&pool).await.unwrap();
    migration::migrate(&pool).await.unwrap();
    migration::migrate(&pool).await.unwrap();
    migration::validate(&pool).await.unwrap();
    let preserved: bool = sqlx::query_scalar("SELECT verifier_trust_profile_id IS NULL AND user_id='legacy-user' FROM device_registration_service.device_pairing_confirmations WHERE pairing_id=$1")
        .bind(&legacy).fetch_one(&pool).await.unwrap();
    assert!(
        preserved,
        "legacy pairing must survive without a new authority grant"
    );
    let confirmations = PostgresPairingConfirmations::new(pool.clone());
    let issuer = Uuid::new_v4().to_string();
    let verifier = Uuid::new_v4().to_string();
    let tickets = MemoryPairingTickets::new(300);
    let issued = tickets
        .issue_with_verifier_profile("browser-user", "org-a", &issuer, Some(&verifier))
        .await
        .unwrap();
    let scope = issued.scope;
    assert!(
        confirmations.validate_issued_scope(&scope).await.is_err(),
        "Redis data alone is not browser authority"
    );
    confirmations.record_issued(&scope).await.unwrap();
    confirmations.validate_issued_scope(&scope).await.unwrap();
    for field in 0..7 {
        let mut changed = scope.clone();
        match field {
            0 => changed.user_id = "other-user".into(),
            1 => changed.organization_id = "other-org".into(),
            2 => changed.trust_profile_id = Uuid::new_v4().to_string(),
            3 => changed.verifier_trust_profile_id = Some(Uuid::new_v4().to_string()),
            4 => changed.verifier_trust_profile_id = None,
            5 => changed.issued_at -= chrono::Duration::seconds(1),
            _ => changed.expires_at += chrono::Duration::seconds(1),
        }
        assert!(
            confirmations.validate_issued_scope(&changed).await.is_err(),
            "substituted field {field}"
        );
    }
    // A pairing cancellation that occurs between issue and redemption fails closed.
    sqlx::query("UPDATE device_registration_service.device_pairing_confirmations SET expired_at=clock_timestamp() WHERE pairing_id=$1")
        .bind(&scope.pairing_id).execute(&pool).await.unwrap();
    assert!(confirmations.validate_issued_scope(&scope).await.is_err());
    qualify_current_governance_scope(&pool).await;
}

async fn qualify_current_governance_scope(pool: &sqlx::PgPool) {
    use marty_device_registration::{
        holder_credential,
        holder_credential_repository::{
            HolderCredentialRepository, PostgresHolderCredentialRepository,
        },
        holder_key::new_reference,
        postgres::PostgresDeviceRepository,
        CreateRegistration, DeviceRegistration, DeviceRepository, Platform,
    };
    use serde_json::json;
    let now = chrono::Utc::now();
    let org = Uuid::new_v4().to_string();
    let mut device = DeviceRegistration::new(
        "governed-user".into(),
        CreateRegistration {
            user_id: None,
            organization_id: Some(org.clone()),
            device_id: Uuid::new_v4().to_string(),
            platform: Platform::Android,
            fcm_token: None,
            app_version: None,
            os_version: None,
            device_model: None,
            preferences: Default::default(),
            is_active: true,
        },
        now,
    );
    device.user_id = "governed-user".into();
    let devices = PostgresDeviceRepository::new(pool.clone());
    devices.save(device.clone()).await.unwrap();
    let credential = holder_credential::issue(&device, now, chrono::Duration::hours(1)).unwrap();
    let credentials = PostgresHolderCredentialRepository::new(pool.clone());
    credentials
        .replace(credential.record.clone(), now)
        .await
        .unwrap();
    let pairing = Uuid::new_v4().to_string();
    let issuer = Uuid::new_v4().to_string();
    let verifier = Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO device_registration_service.device_pairing_confirmations (pairing_id,user_id,organization_id,trust_profile_id,verifier_trust_profile_id,registration_id,issued_at,expires_at,confirmed_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$7)")
        .bind(&pairing).bind(&device.user_id).bind(&org).bind(&issuer).bind(&verifier).bind(&device.id).bind(now).bind(now+chrono::Duration::minutes(10)).execute(pool).await.unwrap();
    for (purpose, algorithm, x, y) in [
        (
            "holder_binding",
            "EdDSA",
            "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
            None,
        ),
        (
            "presentation_signing",
            "ES256",
            "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY",
            Some("T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"),
        ),
    ] {
        sqlx::query("INSERT INTO device_registration_service.device_holder_keys (id,registration_id,user_id,organization_id,purpose,algorithm,provider_reference,remote_version,public_x,public_y,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,1,$8,$9,$10)")
            .bind(Uuid::new_v4().to_string()).bind(&device.id).bind(&device.user_id).bind(&org).bind(purpose).bind(algorithm)
            .bind(new_reference(&org,&device.id,purpose).unwrap()).bind(x).bind(y).bind(now).execute(pool).await.unwrap();
    }
    let confirmations = PostgresPairingConfirmations::new(pool.clone());
    let original = confirmations
        .governance_for_bearer(&credential.bearer)
        .await
        .unwrap();
    let value = serde_json::to_value(&original).unwrap();
    assert_eq!(value["pairing_id"], pairing);
    assert_eq!(value["registration_id"], device.id);
    assert_eq!(value["issuer_trust_profile_id"], issuer);
    assert_eq!(value["verifier_trust_profile_id"], verifier);
    assert!(value["presentation_signing_key"]["public_jwk"]
        .get("kid")
        .is_none());
    assert!(!value.to_string().contains(&credential.bearer));
    assert!(!value.to_string().contains("cred-presenter-"));
    assert_eq!(
        value["presentation_signing_key"]["public_jwk"]["crv"],
        "P-256"
    );
    assert_ne!(
        value["presentation_signing_key"]["jwk_thumbprint"],
        value["holder_binding_key"]["jwk_thumbprint"]
    );
    for (column, replacement) in [
        ("device_id", json!("replacement-device")),
        ("user_id", json!("other-user")),
        ("is_active", json!(false)),
    ] {
        let sql=match column {"device_id"=>"UPDATE device_registration_service.device_registrations SET device_id=$2 WHERE id=$1", "user_id"=>"UPDATE device_registration_service.device_registrations SET user_id=$2 WHERE id=$1", _=>"UPDATE device_registration_service.device_registrations SET is_active=$2 WHERE id=$1"};
        if column == "is_active" {
            sqlx::query(sql)
                .bind(&device.id)
                .bind(false)
                .execute(pool)
                .await
                .unwrap();
        } else {
            sqlx::query(sql)
                .bind(&device.id)
                .bind(replacement.as_str().unwrap())
                .execute(pool)
                .await
                .unwrap();
        }
        let changed = confirmations
            .governance_for_bearer(&credential.bearer)
            .await;
        if column == "device_id" {
            assert!(changed.unwrap() != original);
        } else {
            assert!(changed.is_err());
        }
        sqlx::query("UPDATE device_registration_service.device_registrations SET device_id=$2,user_id=$3,is_active=true WHERE id=$1")
            .bind(&device.id).bind(&device.device_id).bind(&device.user_id).execute(pool).await.unwrap();
    }
    sqlx::query("UPDATE device_registration_service.device_holder_keys SET remote_version=2 WHERE registration_id=$1 AND purpose='presentation_signing'").bind(&device.id).execute(pool).await.unwrap();
    assert!(
        confirmations
            .governance_for_bearer(&credential.bearer)
            .await
            .unwrap()
            != original
    );
    let rotated =
        holder_credential::issue(&device, chrono::Utc::now(), chrono::Duration::hours(1)).unwrap();
    credentials
        .replace(rotated.record.clone(), chrono::Utc::now())
        .await
        .unwrap();
    assert!(confirmations
        .governance_for_bearer(&credential.bearer)
        .await
        .is_err());
    let current = confirmations
        .governance_for_bearer(&rotated.bearer)
        .await
        .unwrap();
    assert_ne!(current.credential_id, original.credential_id);
    sqlx::query("UPDATE device_registration_service.device_pairing_confirmations SET verifier_trust_profile_id=NULL WHERE pairing_id=$1").bind(&pairing).execute(pool).await.unwrap();
    assert!(confirmations
        .governance_for_bearer(&rotated.bearer)
        .await
        .is_err());
    sqlx::query("UPDATE device_registration_service.device_pairing_confirmations SET verifier_trust_profile_id=$2 WHERE pairing_id=$1").bind(&pairing).bind(&verifier).execute(pool).await.unwrap();
    sqlx::query("UPDATE device_registration_service.device_holder_keys SET revoked_at=clock_timestamp() WHERE registration_id=$1 AND purpose='presentation_signing'").bind(&device.id).execute(pool).await.unwrap();
    assert!(confirmations
        .governance_for_bearer(&rotated.bearer)
        .await
        .is_err());
}
