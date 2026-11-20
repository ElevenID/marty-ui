use super::*;
use crate::{
    credential::{
        CredentialRepository, CredentialSigningAuthorization, CredentialTransactionStatus,
    },
    credential_postgres::PostgresCredentialRepository,
    initiation::InitiationRepository,
};
use marty_oid4vp_contract::{
    issuance_prerequisite::IssuancePrerequisiteProfileV1, FrozenPolicyIdentity,
};
use sqlx::{postgres::PgPoolOptions, Row};

fn policy() -> IssuancePrerequisitePolicyV1 {
    IssuancePrerequisitePolicyV1 {
        profile: IssuancePrerequisiteProfileV1::ManagedSdJwtDcqlSameHolderV1,
        flow_definition_id: "flow-definition-one".into(),
        flow_definition_version: 1,
        policy: FrozenPolicyIdentity {
            id: "policy-one".into(),
            version: 1,
            content_digest: format!("sha256:{}", "a".repeat(64)),
        },
        verifier_issuer_did: "did:web:verifier.example".into(),
        ttl_seconds: 120,
    }
}

fn transaction(id: &str) -> CredentialTransaction {
    let now = chrono::DateTime::<Utc>::from_timestamp_micros(now_micros()).unwrap();
    let mut transaction = CredentialTransaction {
        id: id.into(),
        organization_id: "organization-one".into(),
        credential_template_id: "template-one".into(),
        revocation_profile_id: Some("revocation-one".into()),
        renewal_of_credential_id: None,
        applicant_id: Some("applicant-one".into()),
        application_id: None,
        subject_did: None,
        idempotency_key_hash: None,
        idempotency_request_hash: None,
        status: CredentialTransactionStatus::Pending,
        pre_authorized_code: format!("preauth-{id}"),
        nonce: None,
        claims: serde_json::from_value(json!({"role":"member"})).unwrap(),
        credential_type: Some("EmployeeCredential".into()),
        selective_disclosure_claims: vec!["role".into()],
        zk_predicate_claims: Vec::new(),
        credential_payload_format: "SD_JWT_VC".into(),
        jwt_vc_profile: None,
        jwt_vc_signing_timing: None,
        issuance_intent: None,
        wallet_configs: Vec::new(),
        validity_days: 365,
        renewable: false,
        renewal_window_days: 30,
        delivery_mode: "wallet_only".into(),
        issuer_profile_id: Some("issuer-profile-one".into()),
        issuer_mode: "org_managed".into(),
        issuer_did: Some("did:web:issuer.example".into()),
        issuer_algorithm: Some("ES256".into()),
        signing_service_id: Some("signing-owner-one".into()),
        reserved_credential_id: None,
        oid4vci_client_id: None,
        created_at: now,
        expires_at: now + chrono::Duration::seconds(120),
    };
    transaction.issuance_intent = Some(bind_intent(&transaction, 1, "user-one", policy()).unwrap());
    transaction
}

#[tokio::test]
#[ignore = "requires ISSUANCE_POSTGRES_TEST_URL pointing to a dedicated local PostgreSQL test database"]
async fn prerequisite_postgres_fences_omission_retargeting_unsupported_writers_and_replay() {
    let database_url = std::env::var("ISSUANCE_POSTGRES_TEST_URL")
        .expect("dedicated local PostgreSQL fixture required");
    assert!(url::Url::parse(&database_url)
        .unwrap()
        .path()
        .ends_with("_test"));
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&database_url)
        .await
        .unwrap();
    sqlx::raw_sql("DROP SCHEMA IF EXISTS issuance_service CASCADE; DROP SCHEMA IF EXISTS credential_template_service CASCADE;")
        .execute(&pool).await.unwrap();
    for source in [
        include_str!("../migrations/0000_issuance_service_baseline.sql"),
        include_str!("../migrations/0001_oid4vci_public_protocol.sql"),
        include_str!("../migrations/0013_explicit_jwt_vc_profile.sql"),
    ] {
        sqlx::raw_sql(source).execute(&pool).await.unwrap();
    }
    migrate(&pool).await.unwrap();
    validate(&pool).await.unwrap();
    sqlx::raw_sql("ALTER TABLE issuance_service.issuance_prerequisite_continuations DROP CONSTRAINT issuance_prerequisite_continuations_evidence_digest_key;
        ALTER TABLE issuance_service.issuance_prerequisite_continuations ADD CONSTRAINT fixture_duplicate_transaction UNIQUE (transaction_id);")
        .execute(&pool).await.unwrap();
    assert!(
        validate(&pool).await.is_err(),
        "duplicating another unique column cannot replace evidence uniqueness"
    );
    sqlx::raw_sql("ALTER TABLE issuance_service.issuance_prerequisite_continuations DROP CONSTRAINT fixture_duplicate_transaction;
        ALTER TABLE issuance_service.issuance_prerequisite_continuations ADD CONSTRAINT issuance_prerequisite_continuations_evidence_digest_key UNIQUE (evidence_digest);")
        .execute(&pool).await.unwrap();
    validate(&pool).await.unwrap();
    sqlx::raw_sql("CREATE SCHEMA credential_template_service;
        CREATE TABLE credential_template_service.credential_templates (
          id text PRIMARY KEY, organization_id text NOT NULL, version integer NOT NULL,
          status text NOT NULL, credential_payload_format text NOT NULL, issuance_protocol text NOT NULL,
          issuer_did text NOT NULL, verification_prerequisite jsonb);")
        .execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO credential_template_service.credential_templates VALUES
        ('template-one','organization-one',1,'prerequisite1_active','SD_JWT_VC','OID4VCI_PRE_AUTH','did:web:issuer.example',$1)")
        .bind(json!(policy())).execute(&pool).await.unwrap();
    let repository = PostgresCredentialRepository::new(pool.clone(), "prerequisite-test-hmac-key");

    let mut omitted = transaction("omitted");
    omitted.issuance_intent = None;
    assert!(repository.reserve_idempotently(&omitted).await.is_err());
    let mut wrong_tenant = transaction("wrong-tenant-omitted");
    wrong_tenant.organization_id = "organization-two".into();
    wrong_tenant.issuance_intent = None;
    assert!(repository
        .reserve_idempotently(&wrong_tenant)
        .await
        .is_err());
    let mut wrong_version = transaction("wrong-version");
    wrong_version
        .issuance_intent
        .as_mut()
        .unwrap()
        .credential_template_version = 2;
    wrong_version.issuance_intent = Some(
        wrong_version
            .issuance_intent
            .take()
            .unwrap()
            .seal()
            .unwrap(),
    );
    assert!(repository
        .reserve_idempotently(&wrong_version)
        .await
        .is_err());
    let mut wrong_policy = transaction("wrong-policy");
    wrong_policy
        .issuance_intent
        .as_mut()
        .unwrap()
        .prerequisite
        .policy
        .version = 2;
    wrong_policy.issuance_intent =
        Some(wrong_policy.issuance_intent.take().unwrap().seal().unwrap());
    assert!(repository
        .reserve_idempotently(&wrong_policy)
        .await
        .is_err());
    let mut missing_template = transaction("missing-template");
    missing_template.credential_template_id = "unknown-template".into();
    missing_template.issuance_intent =
        Some(bind_intent(&missing_template, 1, "user-one", policy()).unwrap());
    assert!(repository
        .reserve_idempotently(&missing_template)
        .await
        .is_err());
    let mut legacy = transaction("legacy-unknown-template");
    legacy.credential_template_id = "unknown-legacy-template".into();
    legacy.issuance_intent = None;
    assert!(repository.reserve_idempotently(&legacy).await.is_ok());
    let reserved = repository
        .reserve_idempotently(&transaction("guarded-one"))
        .await
        .unwrap()
        .transaction;
    assert!(validate_transaction(&reserved).is_ok());

    for statement in [
        "UPDATE issuance_service.issuance_transactions SET issuance_intent=NULL WHERE id='guarded-one'",
        "UPDATE issuance_service.issuance_transactions SET issuance_intent=jsonb_set(issuance_intent,'{initiating_principal_id}','\"applicant-one\"') WHERE id='guarded-one'",
        "UPDATE issuance_service.issuance_transactions SET claims='{\"role\":\"administrator\"}' WHERE id='guarded-one'",
        "UPDATE issuance_service.issuance_transactions SET issuer_algorithm='ES384' WHERE id='guarded-one'",
        "UPDATE issuance_service.issuance_transactions SET application_id='application-one' WHERE id='guarded-one'",
        "UPDATE issuance_service.issuance_transactions SET renewal_of_credential_id='credential-old' WHERE id='guarded-one'",
        "UPDATE issuance_service.issuance_transactions SET delivery_mode='didcomm' WHERE id='guarded-one'",
        "UPDATE issuance_service.issuance_transactions SET oid4vci_client_id='oauth-client' WHERE id='guarded-one'",
        "UPDATE issuance_service.issuance_transactions SET credential_payload_format='MSO_MDOC' WHERE id='guarded-one'",
        "UPDATE issuance_service.issuance_transactions SET status='signing',reserved_credential_id='credential-one' WHERE id='guarded-one'",
        "INSERT INTO issuance_service.authorization_sessions (id,code,client_id,issuer_state) VALUES ('session-one','code-one','oauth-client','preauth-guarded-one')",
    ] { assert!(sqlx::query(statement).execute(&pool).await.is_err(), "{statement}"); }
    let token = "credential-access-token";
    sqlx::query("UPDATE issuance_service.issuance_transactions SET status='authorized',access_token=$1,access_token_expires_at=expires_at WHERE id='guarded-one'")
        .bind(crate::token_postgres::hash_access_token(b"prerequisite-test-hmac-key", token)).execute(&pool).await.unwrap();
    let admitted = repository
        .transaction_by_id("guarded-one")
        .await
        .unwrap()
        .unwrap();
    let authorization = CredentialSigningAuthorization {
        transaction: &admitted,
        authorization_session: None,
        access_token: token,
        prerequisite: None,
        holder_key_thumbprint: Some("caller-supplied"),
    };
    assert_eq!(
        repository
            .claim_for_signing(&admitted, "credential-one", &authorization)
            .await,
        Err(CredentialIssuanceError::ApplicationEligibilityDenied)
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM issuance_service.issuance_prerequisite_continuations"
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        0
    );

    // These rows exercise database invariants only. They are deliberately
    // inserted by the disposable schema owner, never exposed as an authenticated
    // acquisition or used to claim a successful native verification.
    let insert_receipt = "INSERT INTO issuance_service.issuance_prerequisite_continuations
        (transaction_id,organization_id,intent_digest,evidence_digest,flow_instance_id,holder_key_thumbprint,credential_id,created_at,expires_at,consumed_at)
        SELECT id,organization_id,issuance_intent->>'intent_digest',$1,issuance_intent->>'flow_instance_id',$2,'credential-one',clock_timestamp(),expires_at,clock_timestamp()+interval '1 second'
        FROM issuance_service.issuance_transactions WHERE id='guarded-one'";
    // Both receipt timestamps must come from one observation, not two clocks.
    assert!(sqlx::query(insert_receipt)
        .bind(format!("sha256:{}", "b".repeat(64)))
        .bind("A".repeat(43))
        .execute(&pool)
        .await
        .is_err());
    let insert_receipt = "INSERT INTO issuance_service.issuance_prerequisite_continuations
        (transaction_id,organization_id,intent_digest,evidence_digest,flow_instance_id,holder_key_thumbprint,credential_id,created_at,expires_at,consumed_at)
        SELECT id,organization_id,issuance_intent->>'intent_digest',$1,issuance_intent->>'flow_instance_id',$2,'credential-one',$3,expires_at,$3
        FROM issuance_service.issuance_transactions WHERE id='guarded-one'";
    let mut rollback = pool.begin().await.unwrap();
    sqlx::query(insert_receipt)
        .bind(format!("sha256:{}", "b".repeat(64)))
        .bind("A".repeat(43))
        .bind(Utc::now())
        .execute(&mut *rollback)
        .await
        .unwrap();
    sqlx::query("UPDATE issuance_service.issuance_transactions SET status='signing',reserved_credential_id='credential-one' WHERE id='guarded-one'")
        .execute(&mut *rollback).await.unwrap();
    rollback.rollback().await.unwrap();
    assert_eq!(
        repository
            .transaction_by_id("guarded-one")
            .await
            .unwrap()
            .unwrap()
            .status,
        CredentialTransactionStatus::Authorized
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM issuance_service.issuance_prerequisite_continuations"
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        0
    );
    let mut committed = pool.begin().await.unwrap();
    sqlx::query(insert_receipt)
        .bind(format!("sha256:{}", "b".repeat(64)))
        .bind("A".repeat(43))
        .bind(Utc::now())
        .execute(&mut *committed)
        .await
        .unwrap();
    sqlx::query("UPDATE issuance_service.issuance_transactions SET status='signing',reserved_credential_id='credential-one' WHERE id='guarded-one'")
        .execute(&mut *committed).await.unwrap();
    committed.commit().await.unwrap();
    for statement in [
        "UPDATE issuance_service.issuance_prerequisite_continuations SET credential_id='other-credential'",
        "DELETE FROM issuance_service.issuance_prerequisite_continuations",
        "UPDATE issuance_service.issuance_transactions SET reserved_credential_id='other-credential' WHERE id='guarded-one'",
        "UPDATE issuance_service.issuance_transactions SET status='authorized' WHERE id='guarded-one'",
    ] { assert!(sqlx::query(statement).execute(&pool).await.is_err(), "{statement}"); }
    let row = sqlx::query("SELECT credential_id,consumed_at,created_at FROM issuance_service.issuance_prerequisite_continuations WHERE transaction_id='guarded-one'")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(row.get::<String, _>("credential_id"), "credential-one");
    assert_eq!(
        row.get::<chrono::DateTime<Utc>, _>("consumed_at"),
        row.get::<chrono::DateTime<Utc>, _>("created_at")
    );
    sqlx::query("ALTER TABLE issuance_service.issuance_transactions DISABLE TRIGGER guard_verification_prerequisite_transaction").execute(&pool).await.unwrap();
    assert!(validate(&pool).await.is_err());
    sqlx::query("ALTER TABLE issuance_service.issuance_transactions ENABLE TRIGGER guard_verification_prerequisite_transaction").execute(&pool).await.unwrap();
    validate(&pool).await.unwrap();
    qualify_expired_prerequisite_retention(&pool, &repository).await;
    pool.close().await;
}

async fn qualify_expired_prerequisite_retention(
    pool: &sqlx::PgPool,
    repository: &PostgresCredentialRepository,
) {
    use crate::retention::{PostgresRetentionRepository, RetentionRepository};
    use std::time::Duration;

    // Explicit schema-owner historical rows exercise real retention/trigger
    // behavior. They are never turned into native acquisition capabilities or
    // represented as successful cryptographic verification.
    sqlx::raw_sql("ALTER TABLE issuance_service.issuance_transactions DISABLE TRIGGER guard_verification_prerequisite_transaction;
        ALTER TABLE issuance_service.issuance_prerequisite_continuations DISABLE TRIGGER guard_verification_prerequisite_continuation;")
        .execute(pool).await.unwrap();
    let now = Utc::now();
    let mut historical = Vec::new();
    for (id, status, expires_at) in [
        (
            "retention-expired",
            CredentialTransactionStatus::Issued,
            now - chrono::Duration::seconds(120),
        ),
        (
            "retention-inflight",
            CredentialTransactionStatus::Signing,
            now - chrono::Duration::seconds(120),
        ),
        (
            "retention-soon",
            CredentialTransactionStatus::Issued,
            now + chrono::Duration::seconds(5),
        ),
        (
            "retention-mismatch",
            CredentialTransactionStatus::Issued,
            now - chrono::Duration::seconds(120),
        ),
    ] {
        let mut item = transaction(id);
        item.created_at = expires_at - chrono::Duration::seconds(120);
        item.expires_at = expires_at;
        item.status = status;
        item.reserved_credential_id = Some(format!("credential-{id}"));
        item.issuance_intent = Some(bind_intent(&item, 1, "user-one", policy()).unwrap());
        repository.reserve_idempotently(&item).await.unwrap();
        let intent = item.issuance_intent.as_ref().unwrap();
        let receipt_intent = if id == "retention-mismatch" {
            format!("sha256:{}", "d".repeat(64))
        } else {
            intent.intent_digest.clone()
        };
        sqlx::query("INSERT INTO issuance_service.issuance_prerequisite_continuations
            (transaction_id,organization_id,intent_digest,evidence_digest,flow_instance_id,holder_key_thumbprint,credential_id,created_at,expires_at,consumed_at)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$8)")
            .bind(id).bind(&item.organization_id).bind(receipt_intent)
            .bind(digest_domain_json("fixture.expired-retention-evidence/v1", &json!({"id":id})).unwrap())
            .bind(&intent.flow_instance_id).bind("A".repeat(43)).bind(&item.reserved_credential_id)
            .bind(item.created_at + chrono::Duration::seconds(1)).bind(item.expires_at)
            .execute(pool).await.unwrap();
        if status == CredentialTransactionStatus::Issued {
            sqlx::query("INSERT INTO issuance_service.issued_credentials
                (id,transaction_id,organization_id,credential_template_id,credential_jwt,credential_hash,status,status_updated_at,revoked,issued_at)
                VALUES ($1,$2,$3,$4,'schema-owner-retention-fixture',$2,'active',$5,false,$5)")
                .bind(&item.reserved_credential_id).bind(id).bind(&item.organization_id)
                .bind(&item.credential_template_id).bind(item.created_at).execute(pool).await.unwrap();
        }
        sqlx::query("INSERT INTO issuance_service.issuance_events (id,transaction_id,organization_id,event_type,created_at)
            VALUES ($1,$1,$2,'retention_fixture',$3)")
            .bind(id).bind(&item.organization_id).bind(item.created_at).execute(pool).await.unwrap();
        historical.push(item);
    }
    sqlx::raw_sql("ALTER TABLE issuance_service.issuance_transactions ENABLE TRIGGER guard_verification_prerequisite_transaction;
        ALTER TABLE issuance_service.issuance_prerequisite_continuations ENABLE TRIGGER guard_verification_prerequisite_continuation;")
        .execute(pool).await.unwrap();
    validate(pool).await.unwrap();
    for id in ["retention-soon", "retention-inflight"] {
        assert!(sqlx::query("DELETE FROM issuance_service.issuance_prerequisite_continuations WHERE transaction_id=$1")
            .bind(id).execute(pool).await.is_err(), "retain live and in-flight authority: {id}");
    }
    let retention = PostgresRetentionRepository::new(pool.clone());
    let cutoff = Utc::now() + chrono::Duration::seconds(1);
    let snapshot = retention.summary("organization-one", cutoff).await.unwrap();
    assert_eq!(snapshot.eligible_for_purge.issuance_transactions, 3);
    assert!(retention.purge("organization-one", cutoff).await.is_err());
    for id in [
        "legacy-unknown-template",
        "retention-expired",
        "retention-mismatch",
    ] {
        assert!(
            repository.transaction_by_id(id).await.unwrap().is_some(),
            "mismatched receipt rolls back the whole purge: {id}"
        );
    }
    // Repair the deliberately malformed historical row as schema owner; no
    // running service can mutate a continuation through the enabled guard.
    sqlx::raw_sql("ALTER TABLE issuance_service.issuance_prerequisite_continuations DISABLE TRIGGER guard_verification_prerequisite_continuation;
        UPDATE issuance_service.issuance_prerequisite_continuations continuation SET intent_digest=tx.issuance_intent->>'intent_digest'
        FROM issuance_service.issuance_transactions tx WHERE tx.id=continuation.transaction_id AND tx.id='retention-mismatch';
        ALTER TABLE issuance_service.issuance_prerequisite_continuations ENABLE TRIGGER guard_verification_prerequisite_continuation;")
        .execute(pool).await.unwrap();
    validate(pool).await.unwrap();
    let soon = &historical[2];
    let mut parent_lock = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM issuance_service.issuance_transactions WHERE id=$1 FOR UPDATE")
        .bind(&soon.id)
        .fetch_one(&mut *parent_lock)
        .await
        .unwrap();
    let worker = PostgresRetentionRepository::new(pool.clone());
    let purge = tokio::spawn(async move { worker.purge("organization-one", cutoff).await });
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM pg_stat_activity
                WHERE wait_event_type='Lock' AND query LIKE '%ORDER BY id FOR UPDATE%')",
            )
            .fetch_one(pool)
            .await
            .unwrap();
            if waiting {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let remaining = (soon.expires_at - Utc::now()).num_microseconds().unwrap();
    assert!(
        remaining > 0,
        "the retention lock must straddle actual intent expiry"
    );
    tokio::time::sleep(Duration::from_micros(remaining as u64) + Duration::from_millis(2)).await;
    parent_lock.commit().await.unwrap();
    let purged = purge.await.unwrap().unwrap();
    assert_eq!(purged.issuance_transactions, 4);
    assert_eq!(purged.issued_credentials, 3);
    assert_eq!(purged.issuance_events, 3);
    assert!(repository
        .transaction_by_id("legacy-unknown-template")
        .await
        .unwrap()
        .is_none());
    for id in ["guarded-one", "retention-inflight"] {
        assert!(repository.transaction_by_id(id).await.unwrap().is_some());
    }
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM issuance_service.issuance_prerequisite_continuations"
        )
        .fetch_one(pool)
        .await
        .unwrap(),
        2
    );
    let mut old = historical[0].clone();
    assert!(old
        .issuance_intent
        .as_ref()
        .unwrap()
        .validate_at(now_micros())
        .is_err());
    old.status = CredentialTransactionStatus::Pending;
    old.reserved_credential_id = None;
    assert!(
        repository.reserve_idempotently(&old).await.is_err(),
        "expired intent cannot reopen after retention"
    );
    sqlx::query("UPDATE issuance_service.issuance_transactions SET status='failed' WHERE id='retention-inflight'")
        .execute(pool).await.unwrap();
    let reconciled = retention.purge("organization-one", cutoff).await.unwrap();
    assert_eq!(reconciled.issuance_transactions, 1);
    assert_eq!(reconciled.issuance_events, 1);
    assert!(repository
        .transaction_by_id("guarded-one")
        .await
        .unwrap()
        .is_some());
}
