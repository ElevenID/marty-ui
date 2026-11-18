use marty_trust_profile::run_migrations;
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;

#[tokio::test]
#[ignore = "requires a newly owned marked disposable PostgreSQL database"]
async fn native_migration_is_additive_idempotent_and_scrubs_private_custody_metadata() {
    let database_url = std::env::var("TEST_POSTGRES_URL").expect("owned PostgreSQL URL");
    let nonce =
        std::env::var("MARTY_TEST_POSTGRES_DISPOSABLE_NONCE").expect("owned PostgreSQL marker");
    let url = url::Url::parse(&database_url).unwrap();
    assert_eq!(url.host_str(), Some("127.0.0.1"));
    assert!(url.port().is_some() && nonce.len() >= 32);
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&database_url)
        .await
        .unwrap();
    let guard: String = sqlx::query_scalar("SELECT nonce FROM public.marty_disposable_guard")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(guard, nonce);
    let exists: bool =
        sqlx::query_scalar("SELECT to_regnamespace('trust_profile_service') IS NOT NULL")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(!exists, "refuse an existing service installation");

    let first = run_migrations(&pool).await.unwrap();
    assert_eq!(first.metadata_rows_sanitized, 0);
    assert_eq!(trust_purpose_column_count(&pool).await, 2);
    sqlx::raw_sql(
        "ALTER TABLE trust_profile_service.trust_profiles
         DROP COLUMN trust_purposes,
         DROP COLUMN trusted_assertion_formats",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO trust_profile_service.organization_trust_profiles
         (id,organization_id,framework_id,name,compliance_status,metadata)
         VALUES('11111111-1111-4111-8111-111111111111','org-a',
                '22222222-2222-4222-8222-222222222222','Legacy','SETUP_REQUIRED',$1)",
    )
    .bind(json!({
        "public": "kept",
        "nested": {"kms_provider": "vault", "jwk": {"kty": "EC", "x": "x", "d": "private"}}
    }))
    .execute(&pool)
    .await
    .unwrap();

    let upgraded = run_migrations(&pool).await.unwrap();
    assert_eq!(upgraded.metadata_rows_sanitized, 1);
    assert_eq!(trust_purpose_column_count(&pool).await, 2);
    let metadata: Value = sqlx::query_scalar(
        "SELECT metadata FROM trust_profile_service.organization_trust_profiles
         WHERE id='11111111-1111-4111-8111-111111111111'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        metadata,
        json!({"public": "kept", "nested": {"jwk": {"kty": "EC", "x": "x"}}})
    );
    let idempotent = run_migrations(&pool).await.unwrap();
    assert_eq!(idempotent.metadata_rows_sanitized, 0);

    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/trust-profile-service-behavior.json"
    ))
    .unwrap();
    for table in contract["persistence_tables"].as_array().unwrap() {
        let present: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
            .bind(format!("trust_profile_service.{}", table.as_str().unwrap()))
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(present);
    }

    credential_authority_revision_contract(&pool).await;

    sqlx::raw_sql("DROP SCHEMA trust_profile_service CASCADE")
        .execute(&pool)
        .await
        .unwrap();
}

async fn credential_authority_revision_contract(pool: &sqlx::PgPool) {
    use chrono::{Duration, Utc};
    use marty_trust_profile::{
        CascadeRevocationPolicy, ComplianceStatus, IssuerEntity, IssuerEntityComplianceStatus,
        IssuerEntityType, PostgresTrustProfileRepository, TrustProfile, TrustProfileIssuer,
        TrustProfileRepository, TrustProfileStatus, TrustProfileType, TrustPurpose,
        TrustRelationshipStatus,
    };
    use serde_json::Map;
    use uuid::Uuid;

    let recorded: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM trust_profile_service.native_migrations
         WHERE version='trust-profile-credential-authority-v1'",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(recorded, 1);
    let repository = PostgresTrustProfileRepository::new(pool.clone());
    let now = Utc::now();
    let mut profile = TrustProfile {
        id: Uuid::new_v4(),
        organization_id: "authority-org".into(),
        name: "Owner revision".into(),
        description: None,
        status: TrustProfileStatus::Active,
        profile_type: TrustProfileType::Custom,
        compliance_status: ComplianceStatus::Compliant,
        trust_purposes: Some(vec![TrustPurpose::CredentialIssuer]),
        trust_sources: vec![],
        validation_rules: Default::default(),
        allowed_issuers: None,
        denied_issuers: None,
        system_issuer_overrides: Map::new(),
        compatible_compliance_codes: vec![],
        verification_policy_set_id: None,
        auto_generated: false,
        revocation_policy: Default::default(),
        revocation_profile_id: None,
        time_policy: Default::default(),
        supported_formats: vec!["SD_JWT_VC".into()],
        trusted_assertion_formats: None,
        created_at: now,
        updated_at: now,
    };
    profile.revocation_policy.check_ocsp = false;
    profile.revocation_policy.check_crl = false;
    profile.revocation_policy.check_status_list = false;
    let mut issuer = IssuerEntity {
        id: Uuid::new_v4(),
        organization_id: Some(profile.organization_id.clone()),
        issuer_id: "https://issuer.example.test/authority".into(),
        issuer_type: IssuerEntityType::Organization,
        display_name: "Owner issuer".into(),
        description: None,
        is_system_issuer: false,
        compliance_status: IssuerEntityComplianceStatus::Compliant,
        accreditation_body: None,
        accreditations: vec![],
        accreditation_date: None,
        valid_from: now - Duration::days(1),
        valid_until: None,
        trust_anchor_id: None,
        revoked_at: None,
        revocation_reason: None,
        revoked_by: None,
        metadata: json!({"verification_keys":[{"kty":"OKP","crv":"Ed25519","alg":"EdDSA","use":"sig",
            "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}]}),
        created_at: now,
        updated_at: now,
    };
    let mut relationship = TrustProfileIssuer {
        id: Uuid::new_v4(),
        trust_profile_id: profile.id,
        issuer_id: issuer.id,
        trust_level: 70,
        relationship_status: TrustRelationshipStatus::Trusted,
        cascade_revocation_policy: CascadeRevocationPolicy::Manual,
        metadata: json!({"marty_credential_authorizations_v1":[{"format":"SD_JWT_VC","vct":"https://type.example.test/Employee"}]}),
        created_at: now,
        updated_at: now,
    };
    repository.save_profile(&profile, None).await.unwrap();
    repository.save_issuer_entity(&issuer).await.unwrap();
    repository.save_profile_issuer(&relationship).await.unwrap();
    // A concurrent first-row insert may wait, but it cannot allocate two
    // different versions for the same observed graph.
    let (first, simultaneous) = tokio::join!(
        repository.credential_authority_snapshot("authority-org", profile.id),
        repository.credential_authority_snapshot("authority-org", profile.id),
    );
    let first = first.unwrap().unwrap();
    assert_eq!(first.profile.version, 1);
    assert_eq!(first, simultaneous.unwrap().unwrap());
    assert!(repository
        .credential_authority_snapshot("other-org", profile.id)
        .await
        .unwrap()
        .is_none());
    let (wallet_first, wallet_simultaneous) = tokio::join!(
        repository.wallet_issuer_authority_snapshot("authority-org", profile.id),
        repository.wallet_issuer_authority_snapshot("authority-org", profile.id)
    );
    let wallet_first = wallet_first.unwrap().unwrap();
    assert_eq!(wallet_first.revision.version, 1);
    assert_eq!(wallet_first, wallet_simultaneous.unwrap().unwrap());
    assert!(repository
        .wallet_issuer_authority_snapshot("other-org", profile.id)
        .await
        .unwrap()
        .is_none());
    relationship.metadata["marty_wallet_issuance_authorizations_v1"] = json!([{
        "credential_issuer":"https://service.example.test/tenant","credential_configuration_id":"employee",
        "format":"dc+sd-jwt","vct":"https://type.example.test/Employee",
        "authorization_server":null,"token_endpoint":null}]);
    repository.save_profile_issuer(&relationship).await.unwrap();
    let mapped = repository
        .wallet_issuer_authority_snapshot("authority-org", profile.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(mapped.revision.version, 2);
    assert_ne!(
        mapped.revision.content_digest,
        wallet_first.revision.content_digest
    );
    assert_eq!(
        repository
            .credential_authority_snapshot("authority-org", profile.id)
            .await
            .unwrap()
            .unwrap(),
        first
    );
    let projection =
        marty_trust_profile::wallet_issuer_authority::project(&mapped, Utc::now()).unwrap();
    assert_eq!(projection["issuer_keys"][0]["issuer"], issuer.issuer_id);
    assert_eq!(
        projection["issuer_keys"][0]["issuance_authorizations"][0]["credential_issuer"],
        "https://service.example.test/tenant"
    );
    // A reader waiting on the wallet publication row must observe the service
    // grant committed while it waited, not a graph read before that lock.
    let mut wallet_writer = pool.begin().await.unwrap();
    sqlx::query("SELECT version FROM trust_profile_service.wallet_issuer_authority_revisions WHERE profile_id=$1 FOR UPDATE")
        .bind(profile.id.to_string()).fetch_one(&mut *wallet_writer).await.unwrap();
    let wallet_reader = repository.clone();
    let wallet_id = profile.id;
    let wallet_pending = tokio::spawn(async move {
        wallet_reader
            .wallet_issuer_authority_snapshot("authority-org", wallet_id)
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(5),async {
        loop {
            let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND wait_event_type='Lock' AND query LIKE '%wallet_issuer_authority_revisions%' AND query LIKE '%FOR UPDATE%')").fetch_one(pool).await.unwrap();
            if waiting {break;}
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }).await.expect("wallet owner reader must wait on its revision row");
    relationship.metadata["marty_wallet_issuance_authorizations_v1"][0]
        ["credential_configuration_id"] = json!("changed-configuration");
    sqlx::query("UPDATE trust_profile_service.trust_profile_issuers SET metadata=$2 WHERE id=$1")
        .bind(relationship.id.to_string())
        .bind(&relationship.metadata)
        .execute(&mut *wallet_writer)
        .await
        .unwrap();
    wallet_writer.commit().await.unwrap();
    let after_wait = wallet_pending.await.unwrap().unwrap().unwrap();
    assert_eq!(after_wait.revision.version, 3);
    assert_eq!(
        after_wait.issuance_authorizations[&issuer.issuer_id][0].credential_configuration_id,
        "changed-configuration"
    );
    assert_eq!(
        repository
            .credential_authority_snapshot("authority-org", profile.id)
            .await
            .unwrap()
            .unwrap(),
        first
    );
    issuer.metadata["verification_keys"][0]["x"] =
        json!("PUAXw-hDiVqStwqnTRt-vJyYLM8uxJaMwM1V8Sr0Zgw");
    repository.save_issuer_entity(&issuer).await.unwrap();
    let changed_key = repository
        .credential_authority_snapshot("authority-org", profile.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(changed_key.profile.version, 2);
    assert_ne!(
        changed_key.profile.content_digest,
        first.profile.content_digest
    );
    assert_eq!(
        changed_key.basis.issuer_relationships[0].issuer_updated_at,
        first.basis.issuer_relationships[0].issuer_updated_at
    );
    relationship.metadata["marty_credential_authorizations_v1"][0]["vct"] =
        json!("https://type.example.test/Manager");
    repository.save_profile_issuer(&relationship).await.unwrap();
    let changed_grant = repository
        .credential_authority_snapshot("authority-org", profile.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(changed_grant.profile.version, 3);

    // Hold the publication lock, then wait until the real repository operation
    // blocks on it. Update both graph rows while it waits. Its graph observation
    // must happen after the lock, and in one snapshot, so both changes appear.
    let mut writer = pool.begin().await.unwrap();
    sqlx::query("SELECT version FROM trust_profile_service.credential_authority_revisions WHERE profile_id=$1 FOR UPDATE")
        .bind(profile.id.to_string()).fetch_one(&mut *writer).await.unwrap();
    let reader = repository.clone();
    let selected_id = profile.id;
    let pending = tokio::spawn(async move {
        reader
            .credential_authority_snapshot("authority-org", selected_id)
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity
                 WHERE datname=current_database() AND pid<>pg_backend_pid()
                   AND wait_event_type='Lock' AND query LIKE '%credential_authority_revisions%'
                   AND query LIKE '%FOR UPDATE%')",
            )
            .fetch_one(pool)
            .await
            .unwrap();
            if waiting {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("authority reader should wait on revision lock");
    profile.time_policy.require_not_before = false;
    sqlx::query("UPDATE trust_profile_service.trust_profiles SET time_policy=$2 WHERE id=$1")
        .bind(profile.id.to_string())
        .bind(json!(profile.time_policy))
        .execute(&mut *writer)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE trust_profile_service.issuer_entities SET compliance_status='REVOKED' WHERE id=$1",
    )
    .bind(issuer.id.to_string())
    .execute(&mut *writer)
    .await
    .unwrap();
    writer.commit().await.unwrap();
    let newest = pending.await.unwrap().unwrap().unwrap();
    assert_eq!(newest.profile.version, 4);
    assert!(!newest.basis.policy_controls.time_policy.require_not_before);
    assert_eq!(
        newest.basis.issuer_relationships[0].compliance_status,
        "REVOKED"
    );
    assert_eq!(
        repository
            .credential_authority_snapshot("authority-org", profile.id)
            .await
            .unwrap()
            .unwrap(),
        newest
    );
    repository.delete_profile(profile.id).await.unwrap();
    let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM trust_profile_service.credential_authority_revisions WHERE profile_id=$1")
        .bind(profile.id.to_string()).fetch_one(pool).await.unwrap();
    assert_eq!(remaining, 0);
    let wallet_remaining:i64=sqlx::query_scalar("SELECT count(*) FROM trust_profile_service.wallet_issuer_authority_revisions WHERE profile_id=$1")
        .bind(profile.id.to_string()).fetch_one(pool).await.unwrap();
    assert_eq!(wallet_remaining, 0);
}

async fn trust_purpose_column_count(pool: &sqlx::PgPool) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*)
         FROM information_schema.columns
         WHERE table_schema = 'trust_profile_service'
           AND table_name = 'trust_profiles'
           AND column_name IN ('trust_purposes', 'trusted_assertion_formats')
           AND data_type = 'jsonb'",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}
