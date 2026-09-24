use chrono::{TimeZone, Utc};
use marty_issuance_service::passport_repository::{PassportJobInsert, PostgresPassportRepository};
use marty_passport_auth::PassportTenantKeyring;
use sqlx::postgres::PgPoolOptions;

#[tokio::test]
async fn passport_jobs_survive_restart_without_cross_tenant_reads() {
    let Ok(database_url) = std::env::var("MARTY_PASSPORT_POSTGRES_TEST_URL") else {
        return;
    };
    let database_name = url::Url::parse(&database_url)
        .expect("passport contract URL must parse")
        .path()
        .trim_start_matches('/')
        .to_owned();
    assert_eq!(
        database_name, "marty_passport_contract_test",
        "passport contract requires its dedicated disposable database"
    );
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .expect("passport contract database must connect");
    sqlx::query("DROP SCHEMA IF EXISTS issuance_service CASCADE")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("CREATE SCHEMA issuance_service")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "CREATE TABLE issuance_service.physical_document_jobs (
            id text PRIMARY KEY,
            organization_id text NOT NULL,
            flow_execution_id text NOT NULL,
            application_id text NOT NULL UNIQUE,
            application_template_id text NOT NULL,
            credential_template_id text NOT NULL,
            revocation_profile_id text,
            delivery_destination_profile_id varchar(128) NOT NULL,
            document_type varchar(3) NOT NULL,
            country_code varchar(3) NOT NULL,
            secure_artifact_ciphertext text NOT NULL,
            secure_artifact_reference varchar(512) NOT NULL,
            sod_sha256 varchar(64),
            bureau_job_id varchar(255),
            tracking_number varchar(255),
            status varchar(40) NOT NULL,
            quality_result json,
            error_code varchar(128),
            error_message varchar(1024),
            submitted_at timestamptz,
            completed_at timestamptz,
            created_at timestamptz NOT NULL,
            updated_at timestamptz NOT NULL
        )",
    )
    .execute(&pool)
    .await
    .unwrap();

    let key_a = "a".repeat(32);
    let key_b = "b".repeat(32);
    let keyring = PassportTenantKeyring::from_json(&format!(
        "{{\"org-a\":\"{key_a}\",\"org-b\":\"{key_b}\"}}"
    ))
    .unwrap();
    let org_a = keyring.authenticate(Some("org-a"), Some(&key_a)).unwrap();
    let org_b = keyring.authenticate(Some("org-b"), Some(&key_b)).unwrap();
    let repository = PostgresPassportRepository::new(pool.clone());
    let now = Utc
        .with_ymd_and_hms(2026, 9, 24, 12, 0, 0)
        .single()
        .unwrap();
    let job = PassportJobInsert {
        id: "job-a".into(),
        application_id: "application-a".into(),
        flow_execution_id: "flow-a".into(),
        application_template_id: "template-a".into(),
        credential_template_id: "credential-a".into(),
        revocation_profile_id: Some("revocation-a".into()),
        delivery_destination_profile_id: "destination-a".into(),
        document_type: "TD2".into(),
        country_code: "USA".into(),
        secure_artifact_ciphertext: "encrypted-artifact-a".into(),
        secure_artifact_reference: "physical-artifact://job-a".into(),
    };
    let inserted = repository.insert(&org_a, &job, now).await.unwrap();
    assert_eq!(inserted.organization_id, "org-a");
    assert_eq!(inserted.status, "DRAFT");
    assert_eq!(inserted.document_type, "TD2");
    assert_eq!(
        inserted.revocation_profile_id.as_deref(),
        Some("revocation-a")
    );
    assert!(repository
        .get(&org_b, "application-a")
        .await
        .unwrap()
        .is_none());

    pool.close().await;
    let restarted_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .unwrap();
    let restarted = PostgresPassportRepository::new(restarted_pool);
    let recovered = restarted
        .get(&org_a, "application-a")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(recovered.secure_artifact_ciphertext, "encrypted-artifact-a");
    assert_eq!(recovered.created_at, now);
    assert!(restarted
        .get(&org_b, "application-a")
        .await
        .unwrap()
        .is_none());
}
