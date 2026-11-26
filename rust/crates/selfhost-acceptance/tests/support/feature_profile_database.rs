//! Exact native feature bootstrap SQL against an owned TLS-only PostgreSQL.
//! No provider URL, account, container, or existing database is accepted.
use super::{
    assert_tls_rejected, installer_feature_database as credentials, managed_postgres, migrate_all,
    CertificateRejection,
};
use marty_delegated_authority::{
    approval::organization_principal, command_postgres::PgOrganizationCommandService,
    ApprovalAdapterPin, Authority, AuthorityMode, OrganizationApprovalConfiguration,
    PgDelegationGrantRepository, PgOrganizationApprovalService, PgOrganizationAuthorityProducer,
    SystemDelegationClock,
};
use marty_delegated_use::database::DatabasePools;
use marty_organization::postgres::PostgresOrganizationStore;
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    ConnectOptions, Connection, PgConnection, PgPool,
};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    process::Command,
    sync::Arc,
    time::{Duration, Instant},
};

const CASE: &str = "feature_profile::fresh_native_feature_roles_qualify_over_verified_tls";
const CHILD: &str = "MARTY_NATIVE_FEATURE_DATABASE_CHILD";
const ADMIN_PASSWORD: &str = "synthetic-native-profile-admin-only";
const CORE_PASSWORD: &str = "synthetic-native-profile-core-only";

#[tokio::test]
#[ignore = "requires owned local PostgreSQL executables via MARTY_TEST_POSTGRES_BIN_DIR"]
async fn fresh_native_feature_roles_qualify_over_verified_tls() {
    if std::env::var_os(CHILD).is_none() {
        let output = managed_postgres::run(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", CASE, "--ignored", "--nocapture"])
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env(CHILD, "1")
                .env(
                    "MARTY_TEST_POSTGRES_BIN_DIR",
                    std::env::var_os("MARTY_TEST_POSTGRES_BIN_DIR")
                        .expect("native PostgreSQL executables are required"),
                )
                .env("NOTIFICATION_SECRET_KMS_PROVIDER", "aws-kms")
                .env("NOTIFICATION_SECRET_AWS_REGION", "us-east-2")
                .env(
                    "NOTIFICATION_SECRET_AWS_KEY_ARN",
                    "arn:aws:kms:us-east-2:111122223333:key/schema-only-fixture",
                )
                .env("AWS_EC2_METADATA_DISABLED", "true"),
            240,
        );
        assert!(
            output.status.success(),
            "native feature SQL qualification failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        print!("{}", String::from_utf8_lossy(&output.stdout));
        return;
    }
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut database = managed_postgres::Database::start_feature_profile();
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut bootstrap = loop {
        database.assert_running();
        if let Ok(connection) =
            PgConnection::connect_with(&database.admin_options("postgres")).await
        {
            break connection;
        }
        assert!(
            Instant::now() < deadline,
            "owned PostgreSQL did not become ready"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    let version: i32 = sqlx::query_scalar("SELECT current_setting('server_version_num')::int")
        .fetch_one(&mut bootstrap)
        .await
        .unwrap();
    assert!(
        (150000..160000).contains(&version),
        "the native feature qualification requires the managed PostgreSQL 15 major"
    );
    println!("native feature PostgreSQL version: {version}");
    sqlx::raw_sql(
        "CREATE ROLE postgres LOGIN SUPERUSER NOINHERIT PASSWORD 'synthetic-native-profile-admin-only';
         CREATE ROLE marty LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT
           NOREPLICATION NOBYPASSRLS PASSWORD 'synthetic-native-profile-core-only';",
    ).execute(&mut bootstrap).await.unwrap();
    sqlx::query("CREATE DATABASE marty OWNER marty")
        .execute(&mut bootstrap)
        .await
        .unwrap();
    bootstrap.close().await.unwrap();
    let admin_options = database
        .admin_options("marty")
        .username("postgres")
        .password(ADMIN_PASSWORD);
    assert_tls_rejected(
        PgConnectOptions::new()
            .host("127.0.0.1")
            .port(admin_options.get_port())
            .database("marty")
            .username("postgres")
            .password(ADMIN_PASSWORD)
            .ssl_mode(sqlx::postgres::PgSslMode::VerifyFull),
        CertificateRejection::Untrusted,
    )
    .await;
    assert_tls_rejected(
        admin_options.clone().host("localhost"),
        CertificateRejection::Hostname,
    )
    .await;
    let admin = connect(admin_options.clone(), 1).await;
    assert_feature_connection_budget(&admin).await;
    let generated = credentials::generate_credentials().unwrap();
    credentials::validate_credentials(&generated).unwrap();
    let inventory = std::str::from_utf8(&generated[credentials::PASSWORD_INVENTORY]).unwrap();
    qualify_psql_transport(&database);

    // Phase order is deliberate. The roles phase is fresh-only, and grants
    // refuse before the exact source-owned schemas have been migrated.
    assert!(setup_phase(&database, "roles", inventory));
    assert!(!setup_phase(&database, "grants", inventory));
    let before = role_password_fingerprints(&admin).await;
    assert!(!setup_phase(&database, "roles", inventory));
    assert!(
        before == role_password_fingerprints(&admin).await,
        "replaying bootstrap must not rotate any role password"
    );
    let core = connect(
        database
            .admin_options("marty")
            .username("marty")
            .password(CORE_PASSWORD),
        2,
    )
    .await;
    let envelope = marty_notification::webhook::WebhookSecretEnvelope::from_environment().unwrap();
    migrate_all(&core, &envelope).await;
    for role in credentials::MIGRATION_ROLES {
        let owner = connect(role_options(&database, &generated, role), 1).await;
        match *role {
            "delegation_owner" => PgDelegationGrantRepository::new(owner.clone())
                .migrate()
                .await
                .unwrap(),
            "credential_owner" => marty_machine_credential_source::run_migrations(&owner)
                .await
                .unwrap(),
            _ => unreachable!("fixed owner inventory"),
        }
        owner.close().await;
    }
    let ungranted = connect(role_options(&database, &generated, "use_writer"), 2).await;
    denied(
        &ungranted,
        "SELECT * FROM delegated_authority_service.delegation_grants",
    )
    .await;
    ungranted.close().await;
    assert!(setup_phase(&database, "grants", inventory));

    let mut pools = BTreeMap::new();
    for role in credentials::RUNTIME_ROLES {
        let pool = connect(role_options(&database, &generated, role), 2).await;
        let identity: (String, bool) = sqlx::query_as(
            "SELECT current_user::text,(SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid())",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(identity, (format!("feature_{role}"), true));
        pools.insert(*role, pool);
    }
    assert_role_capacities(&admin).await;
    let get = |role| pools.get(role).expect("fixed runtime role").clone();
    let configuration = OrganizationApprovalConfiguration::new(
        uuid::Uuid::from_u128(1),
        organization_principal(uuid::Uuid::from_u128(1)),
        ApprovalAdapterPin {
            profile: "urn:marty:test:native-feature-approval".into(),
            version: "1.0.0".into(),
            artifact_digest: format!("sha256:{}", "a".repeat(64)),
        },
        120,
        120,
        15,
    )
    .unwrap();
    let clock = Arc::new(SystemDelegationClock);
    let approval = PgOrganizationApprovalService::new(
        get("approval_runtime"),
        get("approval_consent"),
        Arc::new(PgOrganizationAuthorityProducer::new(
            PostgresOrganizationStore::new(get("approval_organization")),
            get("approval_authority"),
            configuration.clone(),
            clock.clone(),
        )),
        configuration.clone(),
        clock.clone(),
    )
    .unwrap();
    approval.readiness().await.unwrap();
    let commands = PgOrganizationCommandService::new(
        get("command_writer"),
        get("command_runtime"),
        PostgresOrganizationStore::new(get("command_organization")),
        configuration,
        Authority {
            mode: AuthorityMode::Managed,
            issuer: organization_principal(uuid::Uuid::from_u128(1)),
            status_ref: "https://authority.invalid/native-feature-status".into(),
            source_profile: None,
            source_evidence_ref: None,
            source_evidence_digest: None,
            source_expires_at: None,
        },
        clock,
    )
    .unwrap();
    commands.readiness().await.unwrap();
    let delegated = DatabasePools {
        use_writer: get("use_writer"),
        runtime_reader: get("use_runtime_reader"),
        organization_authority: get("use_organization_authority"),
        registry_source: get("use_registry_source"),
        access_source: get("use_access_source"),
        machine_policy_source: get("use_machine_policy_source"),
        machine_policy_evidence: get("use_machine_policy_evidence"),
        delegation_policy_source: get("use_delegation_policy_source"),
        machine_audit: get("use_machine_audit"),
        flow_reader: get("use_flow_reader"),
        flow_ingress: get("use_flow_ingress"),
        credential_trust: get("use_credential_trust"),
        credential_status: get("use_credential_status"),
        credential_evidence: get("use_credential_evidence"),
    };
    delegated.readiness().await.unwrap();
    marty_machine_credential_source::PgOwnedMachineJwtVcAuthoritySource::connect(
        get("use_credential_trust"),
        get("use_credential_status"),
        get("use_credential_evidence"),
    )
    .await
    .unwrap();
    let canonical = &pools["issuance_runtime"];
    // Two real process-sized pools can hold two connections each. A fifth
    // connection must fail at PostgreSQL's fixed aggregate role limit.
    let second_alias = connect(role_options(&database, &generated, "issuance_runtime"), 2).await;
    let held = [
        canonical.acquire().await.unwrap(),
        canonical.acquire().await.unwrap(),
        second_alias.acquire().await.unwrap(),
        second_alias.acquire().await.unwrap(),
    ];
    let excess = match tokio::time::timeout(
        Duration::from_secs(5),
        PgConnection::connect_with(&role_options(&database, &generated, "issuance_runtime")),
    )
    .await
    .expect("role connection limit check must finish")
    {
        Err(error) => error,
        Ok(connection) => {
            connection.close().await.unwrap();
            panic!("canonical role admitted a fifth concurrent connection");
        }
    };
    assert_eq!(
        excess
            .as_database_error()
            .and_then(|error| error.code())
            .as_deref(),
        Some("53300")
    );
    drop(held);
    second_alias.close().await;
    marty_issuance_service::migration::verify_owned_schema(canonical)
        .await
        .unwrap();
    marty_issuance_service::application_ownership_startup::verify_storage(canonical)
        .await
        .unwrap();
    marty_issuance_service::external_observation_materialization::verify_materialization_storage(
        canonical,
    )
    .await
    .unwrap();
    marty_issuance_service::external_observation_startup::verify_storage(&pools["observation"])
        .await
        .unwrap();
    marty_issuance_service::external_observation_startup::verify_runtime_role(
        &pools["observation"],
    )
    .await
    .unwrap();
    marty_issuance_service::external_association_startup::verify_storage(&pools["association"])
        .await
        .unwrap();
    qualify_template_row_locks(&core, canonical).await;

    // Effective authority is tested with real SQL, not only GRANT strings.
    for role in credentials::RUNTIME_ROLES {
        denied(&pools[role], "CREATE SCHEMA forbidden_runtime_owner").await;
        denied(&pools[role], "SET ROLE feature_delegation_owner").await;
    }
    for statement in [
        "UPDATE issuance_service.external_observation_receipts SET envelope=envelope",
        "DELETE FROM issuance_service.external_observation_receipts",
        "TRUNCATE issuance_service.external_observation_receipts",
        "UPDATE issuance_service.external_observation_audit SET event_type=event_type",
        "DELETE FROM issuance_service.external_observation_audit",
        "TRUNCATE issuance_service.external_observation_audit",
        "UPDATE issuance_service.external_observation_bindings SET revision=revision",
        "UPDATE issuance_service.external_observation_heads SET receipt_id=receipt_id",
    ] {
        denied(canonical, statement).await;
    }
    denied(
        &pools["approval_runtime"],
        "UPDATE organization_service.organizations SET name=name",
    )
    .await;
    denied(
        &pools["command_writer"],
        "DELETE FROM delegated_authority_service.consent_confirmations",
    )
    .await;
    denied(
        &pools["observation"],
        "UPDATE issuance_service.applications SET updated_at=updated_at",
    )
    .await;
    denied(
        &pools["association"],
        "DELETE FROM issuance_service.application_ownerships",
    )
    .await;

    // Membership is an escalation even with NOINHERIT. The actual runtime
    // qualifier must refuse it and recover only after the test owner revokes it.
    sqlx::query("GRANT feature_delegation_owner TO feature_use_writer")
        .execute(&admin)
        .await
        .unwrap();
    assert!(delegated.readiness().await.is_err());
    sqlx::query("REVOKE feature_delegation_owner FROM feature_use_writer")
        .execute(&admin)
        .await
        .unwrap();
    delegated.readiness().await.unwrap();
    sqlx::query("REVOKE EXECUTE ON FUNCTION issuance_service.materialization_lock_journal(uuid,text) FROM feature_issuance_runtime")
        .execute(&admin).await.unwrap();
    assert!(marty_issuance_service::external_observation_materialization::verify_materialization_storage(canonical).await.is_err());

    for pool in pools.values() {
        pool.close().await;
    }
    core.close().await;
    admin.close().await;
    database.stop();
    println!(
        "native feature profile: exact bootstrap, migrations, TLS, 24 runtime roles and negative boundaries passed"
    );
}

async fn qualify_template_row_locks(owner: &PgPool, canonical: &PgPool) {
    let organization = uuid::Uuid::new_v4().to_string();
    let template = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO credential_template_service.credential_templates
         (id,organization_id,name,credential_type,vct,created_at,updated_at)
         VALUES ($1,$2,'Restricted issuance fixture','NativeFeatureCredential',
           'https://issuer.invalid/native-feature',clock_timestamp(),clock_timestamp())",
    )
    .bind(&template)
    .bind(&organization)
    .execute(owner)
    .await
    .unwrap();
    let insert = "INSERT INTO issuance_service.issuance_transactions
        (id,organization_id,credential_template_id,status,pre_auth_code,claims,created_at,expires_at)
        VALUES ($1,$2,$3,'pending',$1,'{}',clock_timestamp(),clock_timestamp()+interval '5 minutes')";
    let transaction_id = uuid::Uuid::new_v4().to_string();
    let mut admitted = canonical.begin().await.unwrap();
    sqlx::query(insert)
        .bind(&transaction_id)
        .bind(&organization)
        .bind(&template)
        .execute(&mut *admitted)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE issuance_service.issuance_transactions SET status='authorized' WHERE id=$1",
    )
    .bind(&transaction_id)
    .execute(&mut *admitted)
    .await
    .unwrap();
    // A real owner edit conflicts with the retained FOR SHARE lock even though
    // the runtime itself has no UPDATE authority over the template table.
    let mut competing = owner.begin().await.unwrap();
    sqlx::query("SET LOCAL lock_timeout='50ms'")
        .execute(&mut *competing)
        .await
        .unwrap();
    let conflict = sqlx::query(
        "UPDATE credential_template_service.credential_templates SET name=name WHERE id=$1",
    )
    .bind(&template)
    .execute(&mut *competing)
    .await
    .unwrap_err();
    assert_eq!(
        conflict
            .as_database_error()
            .and_then(|e| e.code())
            .as_deref(),
        Some("55P03")
    );
    competing.rollback().await.unwrap();
    admitted.commit().await.unwrap();
    denied(
        canonical,
        "UPDATE credential_template_service.credential_templates SET name=name",
    )
    .await;

    let guarded = uuid::Uuid::new_v4().to_string();
    let policy = serde_json::json!({
        "profile":"managed_sd_jwt_dcql_same_holder_v1",
        "flow_definition_id":"native-feature-flow","flow_definition_version":1,
        "policy":{"id":"native-feature-policy","version":1,
            "content_digest":format!("sha256:{}","a".repeat(64))},
        "verifier_issuer_did":"did:web:verifier.invalid","ttl_seconds":120,
    });
    sqlx::query(
        "INSERT INTO credential_template_service.credential_templates
         (id,organization_id,name,credential_type,vct,status,credential_payload_format,
          issuance_protocol,supported_formats,validity_rules,issuer_did,
          verification_prerequisite,created_at,updated_at)
         VALUES ($1,$2,'Guarded restricted issuance fixture','NativeFeatureCredential',
          'https://issuer.invalid/native-feature','prerequisite1_active','SD_JWT_VC',
          'OID4VCI_PRE_AUTH','[\"SD_JWT_VC\"]','{\"renewable\":false}',
          'did:web:issuer.invalid',$3,clock_timestamp(),clock_timestamp())",
    )
    .bind(&guarded)
    .bind(&organization)
    .bind(&policy)
    .execute(owner)
    .await
    .unwrap();
    let guarded_transaction = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "WITH stamp AS (SELECT clock_timestamp() AS observed)
         INSERT INTO issuance_service.issuance_transactions
         (id,organization_id,credential_template_id,status,pre_auth_code,claims,
          created_at,expires_at,credential_type,credential_payload_format,issuer_did_override,issuance_intent)
         SELECT $1,$2,$3,'pending',$1,'{}',observed,observed+interval '120 seconds',
          'NativeFeatureCredential','SD_JWT_VC','did:web:issuer.invalid',
          jsonb_build_object('contract','marty.issuance-intent/v1',
            'organization_id',$2::text,'transaction_id',$1::text,
            'initiating_principal_id','native-feature-user','applicant_id',NULL,
            'application_id',NULL,'subject_did',NULL,'credential_template_id',$3::text,
            'credential_template_version',1,'credential_configuration_id','NativeFeatureCredential#sd-jwt',
            'credential_payload_format','SD_JWT_VC','issuer_did','did:web:issuer.invalid',
            'dataset_digest','sha256:'||repeat('a',64),'prerequisite',$4::jsonb,
            'flow_instance_id',$1::text,'created_at_epoch_micros',extract(epoch FROM observed)*1000000,
            'expires_at_epoch_micros',extract(epoch FROM observed+interval '120 seconds')*1000000,
            'intent_digest','sha256:'||repeat('b',64)) FROM stamp",
    )
    .bind(&guarded_transaction)
    .bind(&organization)
    .bind(&guarded)
    .bind(&policy)
    .execute(canonical)
    .await
    .unwrap();
    let other_organization = uuid::Uuid::new_v4().to_string();
    for tenant in [&organization, &other_organization] {
        let error = sqlx::query(insert)
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(tenant)
            .bind(&guarded)
            .execute(canonical)
            .await
            .unwrap_err();
        assert_eq!(
            error.as_database_error().and_then(|e| e.code()).as_deref(),
            Some("P0001"),
            "omitted intent or a wrong tenant must still hit the prerequisite guard"
        );
    }
    sqlx::query("REVOKE EXECUTE ON FUNCTION issuance_service.verification_prerequisite_lock_template(text,text) FROM feature_issuance_runtime")
        .execute(owner).await.unwrap();
    assert!(
        marty_issuance_service::verification_prerequisite::validate(canonical)
            .await
            .is_err()
    );
    let error = sqlx::query(insert)
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&organization)
        .bind(&template)
        .execute(canonical)
        .await
        .unwrap_err();
    assert_eq!(
        error.as_database_error().and_then(|e| e.code()).as_deref(),
        Some("42501")
    );
    sqlx::query("GRANT EXECUTE ON FUNCTION issuance_service.verification_prerequisite_lock_template(text,text) TO feature_issuance_runtime")
        .execute(owner).await.unwrap();
    marty_issuance_service::verification_prerequisite::validate(canonical)
        .await
        .unwrap();
}

fn role_options(
    database: &managed_postgres::Database,
    generated: &BTreeMap<String, Vec<u8>>,
    role: &str,
) -> PgConnectOptions {
    // Only the disposable transport endpoint and public CA differ. The exact
    // owner-generated LOGIN/password, database and verify-full selection remain.
    let raw = std::str::from_utf8(&generated[&format!("feature_{role}_database_url")]).unwrap();
    raw.parse::<PgConnectOptions>()
        .unwrap()
        .host("127.0.0.1")
        .port(database.admin_options("marty").get_port())
        .ssl_root_cert(database.ca())
        .disable_statement_logging()
}

async fn connect(options: PgConnectOptions, maximum: u32) -> PgPool {
    PgPoolOptions::new()
        .max_connections(maximum)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(options.disable_statement_logging())
        .await
        .unwrap()
}

async fn assert_feature_connection_budget(admin: &PgPool) {
    let compose: serde_yaml::Value = serde_yaml::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../deploy-config/compose/selfhost-installer/feature-profile/compose.database.yml"
    )))
    .unwrap();
    let limits: Vec<_> = compose["services"]["postgres"]["command"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(serde_yaml::Value::as_str)
        .filter(|argument| argument.starts_with("max_connections="))
        .collect();
    assert_eq!(limits, ["max_connections=100"]);
    let (maximum, reserved): (i32, i32) = sqlx::query_as(
        "SELECT current_setting('max_connections')::int,
                current_setting('superuser_reserved_connections')::int",
    )
    .fetch_one(admin)
    .await
    .unwrap();
    assert_eq!(maximum, 100);
    // Every retained runtime pool may reach two connections; Issuance's second
    // process adds two more. Core migration and admin pools retain two and one.
    let required = 2 * i32::try_from(credentials::RUNTIME_ROLES.len()).unwrap() + 2 + 2 + 1;
    assert!(
        maximum - reserved >= required,
        "the owned feature database cannot admit its complete bounded pool inventory"
    );
    println!(
        "native feature database capacity: {maximum}, reserved: {reserved}, pool bound: {required}"
    );
}

fn setup_phase(database: &managed_postgres::Database, phase: &str, inventory: &str) -> bool {
    assert!(matches!(phase, "roles" | "grants"));
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../deploy-config/compose/selfhost-installer/feature-profile")
        .join(format!("database-{phase}.sql"));
    std::fs::read(&source)
        .expect("native feature source SQL must be readable by the fixture owner");
    let output = managed_postgres::run(
        psql_command(database)
            .arg("--file")
            .arg(source)
            .env("FEATURE_DATABASE_PASSWORDS", inventory),
        45,
    );
    // An error may contain SQL context. Never print credentials or inventory.
    if !output.status.success() {
        println!("native feature {phase} phase refused");
    }
    output.status.success()
}

fn psql_command(database: &managed_postgres::Database) -> Command {
    let bin = PathBuf::from(std::env::var_os("MARTY_TEST_POSTGRES_BIN_DIR").unwrap());
    assert!(bin.join("psql").is_file(), "native psql is required");
    let mut command = Command::new(bin.join("psql"));
    command
        .args(["-X", "--no-password", "--quiet", "--set", "ON_ERROR_STOP=1"])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("PGHOST", "127.0.0.1")
        .env(
            "PGPORT",
            database.admin_options("marty").get_port().to_string(),
        )
        .env("PGDATABASE", "marty")
        .env("PGUSER", "postgres")
        .env("PGPASSWORD", ADMIN_PASSWORD)
        .env("PGSSLMODE", "verify-full")
        .env("PGSSLROOTCERT", database.ca())
        .env("PGCONNECT_TIMEOUT", "5");
    command
}

fn qualify_psql_transport(database: &managed_postgres::Database) {
    let output = managed_postgres::run(
        psql_command(database).args([
            "--no-align",
            "--tuples-only",
            "--command",
            "SELECT current_user='postgres' AND current_database()='marty' AND (SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid())",
        ]),
        15,
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let category = if stderr.contains("certificate verify failed") {
        "certificate-verification"
    } else if stderr.contains("does not match host name") {
        "hostname-verification"
    } else if stderr.contains("password authentication failed") {
        "authentication"
    } else {
        "connection-or-owner"
    };
    assert!(
        output.status.success() && output.stdout == b"t\n",
        "native psql/libpq verify-full transport preflight refused: {category}"
    );
    println!("native feature psql/libpq verified TLS transport passed");
}

async fn role_password_fingerprints(admin: &PgPool) -> Vec<(String, String)> {
    sqlx::query_as("SELECT rolname::text,md5(rolpassword) FROM pg_authid WHERE left(rolname,8)='feature_' ORDER BY rolname")
        .fetch_all(admin).await.unwrap()
}

async fn assert_role_capacities(admin: &PgPool) {
    let roles: Vec<(String, i32, bool)> = sqlx::query_as(
        "SELECT rolname::text,rolconnlimit,rolcanlogin AND NOT (rolsuper OR rolcreatedb OR rolcreaterole OR rolinherit OR rolreplication OR rolbypassrls)
           FROM pg_roles WHERE left(rolname,8)='feature_' ORDER BY rolname",
    ).fetch_all(admin).await.unwrap();
    assert_eq!(roles.len(), 26);
    for (name, limit, safe) in roles {
        let expected = match name.as_str() {
            "feature_delegation_owner" | "feature_credential_owner" => 1,
            "feature_issuance_runtime" => 4,
            _ => 2,
        };
        assert!(
            safe && limit == expected,
            "fixed role authority/capacity differs: {name}"
        );
    }
    let mutable_owners: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_roles WHERE rolname IN ('feature_delegation_owner','feature_credential_owner')
          AND has_database_privilege(oid,'marty','CREATE')",
    ).fetch_one(admin).await.unwrap();
    assert_eq!(
        mutable_owners, 0,
        "temporary schema bootstrap authority must be revoked"
    );
}

async fn denied(pool: &PgPool, statement: &str) {
    let error = sqlx::query(sqlx::AssertSqlSafe(statement))
        .execute(pool)
        .await
        .unwrap_err();
    assert_eq!(
        error
            .as_database_error()
            .and_then(|error| error.code())
            .as_deref(),
        Some("42501"),
        "operation must fail specifically at the role boundary"
    );
}
