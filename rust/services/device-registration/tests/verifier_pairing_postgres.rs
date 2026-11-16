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
}
