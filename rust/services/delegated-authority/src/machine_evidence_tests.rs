//! Synthetic owner/provider fixtures, real Core Ed25519 VP verification and
//! real PostgreSQL storage. Neither the source records nor the transport-shaped
//! receipt fixture below qualify a production issuer, attestation or signer.
use super::*;
use crate::machine_evidence::*;
use crate::{DelegationGrantRepository, PgDelegationGrantRepository, RepositoryError};
use ed25519_dalek::{Signer, SigningKey};
use sqlx::{postgres::PgPoolOptions, AssertSqlSafe, PgPool};

impl Harness {
    fn current() -> Self {
        let mut h = Self::new();
        let now = Utc::now();
        h.now = now;
        h.clock.set(now);
        h.grant.created_at = now - Duration::seconds(10);
        h.grant.updated_at = h.grant.created_at;
        h.grant.terms.valid_from = h.grant.created_at;
        h.grant.terms.valid_until = now + Duration::hours(1);
        // Ephemeral test-only key. No private material is checked in or retained.
        let mut seed = [0u8; 32];
        seed[..16].copy_from_slice(Uuid::new_v4().as_bytes());
        seed[16..].copy_from_slice(Uuid::new_v4().as_bytes());
        let key = SigningKey::from_bytes(&seed);
        let jwk = json!({"kty":"OKP","crv":"Ed25519","x":URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes())});
        let canonical_jwk = format!(
            r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#,
            jwk["x"].as_str().unwrap()
        );
        let thumbprint = Sha256::digest(canonical_jwk.as_bytes());
        let fingerprint = format!("sha256:{thumbprint:x}");
        h.grant.terms.binding.key_thumbprint = Some(fingerprint.clone());
        h.grant.terms_digest = h.grant.calculate_terms_digest().unwrap();
        let mut challenge = h.challenges.0.lock().unwrap();
        challenge.expires_at = now + Duration::seconds(90);
        let payload = json!({"iss":h.request.actor.id,"sub":h.request.actor.id,"aud":challenge.verifier_client_id,
            "nonce":challenge.nonce,"iat":now.timestamp(),"nbf":now.timestamp(),"exp":now.timestamp()+90,
            "vp":{"@context":["https://www.w3.org/2018/credentials/v1"],"type":["VerifiablePresentation"],"holder":h.request.actor.id}});
        let header = json!({"alg":"EdDSA","typ":"JWT","jwk":jwk});
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap())
        );
        h.request.proof = format!(
            "{input}.{}",
            URL_SAFE_NO_PAD.encode(key.sign(input.as_bytes()).to_bytes())
        )
        .into_bytes();
        drop(challenge);
        let mut documents = h.state.documents.lock().unwrap();
        let typed_key = json!({"basis":"JWK_RFC7638_SHA256","encoding":"BASE64URL_SHA256","value":URL_SAFE_NO_PAD.encode(thumbprint)});
        documents["configuration"]["expected_key_thumbprint"] = typed_key.clone();
        documents["record"]["authentication"]["key_thumbprint"] = typed_key;
        let identity = &mut documents["machine_identity"];
        identity["created_at"] = json!(now - Duration::days(1));
        identity["identity_keys"][0]["thumbprint"] = json!(fingerprint);
        identity["identity_keys"][0]["public_key_jwk"] = jwk;
        identity["identity_keys"][0]["valid_from"] = json!(now - Duration::hours(1));
        identity["identity_keys"][0]["valid_until"] = json!(now + Duration::hours(1));
        documents["policy"]["created_at"] = json!(now - Duration::hours(1));
        // This suite isolates aggregate retention. A selected machine policy
        // now requires real retained source/evaluation records (migration 0008),
        // exercised by machine_policy_source and the composed owner gate tests.
        documents["policy"]
            .as_object_mut()
            .unwrap()
            .remove("authorization_policy_set_id");
        drop(documents);
        h
    }
}

struct Database {
    owner: PgPool,
    writer: PgPool,
    role: String,
    evidence: PgMachineAuthenticationEvidenceRepository,
}
impl Database {
    async fn new() -> Option<Self> {
        let url = std::env::var("DELEGATED_AUTHORITY_TEST_DATABASE_URL").ok()?;
        let parsed = url::Url::parse(&url).unwrap();
        assert!(
            matches!(parsed.host_str(), Some("127.0.0.1" | "::1")),
            "test database must be disposable loopback"
        );
        let owner = PgPoolOptions::new()
            .max_connections(6)
            .connect(&url)
            .await
            .unwrap();
        PgDelegationGrantRepository::new(owner.clone())
            .migrate()
            .await
            .unwrap();
        let role = format!("machine_audit_{}", Uuid::new_v4().simple());
        let password = Uuid::new_v4().simple().to_string();
        // Test-only role and password literals contain only the fixed prefix
        // and generated UUIDs, never external SQL text.
        assert!(role.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'));
        sqlx::raw_sql(AssertSqlSafe(format!("CREATE ROLE {role} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '{password}';
            GRANT USAGE ON SCHEMA delegated_authority_service TO {role};
            GRANT SELECT ON delegated_authority_service.schema_migrations,delegated_authority_service.machine_authorization_evidence TO {role};
            GRANT SELECT,INSERT ON delegated_authority_service.machine_authentication_evidence TO {role};")))
            .execute(&owner).await.unwrap();
        let writer = PgPoolOptions::new()
            .max_connections(4)
            .connect_with(
                owner
                    .connect_options()
                    .as_ref()
                    .clone()
                    .username(&role)
                    .password(&password),
            )
            .await
            .unwrap();
        let evidence = PgMachineAuthenticationEvidenceRepository::new(writer.clone());
        Some(Self {
            owner,
            writer,
            role,
            evidence,
        })
    }
    fn audited(&self, h: &Harness) -> AuditedMachineOid4vpProofVerifier {
        AuditedMachineOid4vpProofVerifier::new(Arc::new(h.verifier.clone()), self.evidence.clone())
    }
    async fn count(&self, org: Uuid) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM delegated_authority_service.machine_authentication_evidence WHERE organization_id=$1")
            .bind(org).fetch_one(&self.owner).await.unwrap()
    }
    async fn sql(&self, sql: &str) {
        sqlx::raw_sql(AssertSqlSafe(sql.to_owned()))
            .execute(&self.owner)
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn postgres_retains_exact_crypto_evidence_and_recovers_original_immutable_bytes() {
    let _lock = crate::postgres::POSTGRES_TEST_LOCK.lock().await;
    let Some(db) = Database::new().await else {
        return;
    };
    db.evidence.readiness().await.unwrap();
    assert!(
        PgMachineAuthenticationEvidenceRepository::new(db.owner.clone())
            .readiness()
            .await
            .is_err()
    );
    let h = Harness::current();
    let proof = h.verify().await.unwrap();
    let retained = db
        .audited(&h)
        .verify_retained(&h.grant, &h.request, h.now)
        .await
        .unwrap();
    assert_eq!(
        retained.authenticated().evidence_bytes(),
        proof.evidence_bytes()
    );
    let original = db
        .evidence
        .recover(h.grant.organization_id, proof.evidence_ref())
        .await
        .unwrap()
        .unwrap();
    let (left, right) = tokio::join!(db.evidence.retain(&proof), db.evidence.retain(&proof));
    left.unwrap();
    right.unwrap();
    let duplicate = db
        .evidence
        .recover(h.grant.organization_id, proof.evidence_ref())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(duplicate.retained_at(), original.retained_at());
    assert_eq!(duplicate.evidence_bytes(), proof.evidence_bytes());
    assert_eq!(duplicate.evidence_document(), proof.evidence_document());
    assert_eq!(
        duplicate.evidence_digest(),
        format!("sha256:{:x}", Sha256::digest(proof.evidence_bytes()))
    );
    assert_eq!(duplicate.original_valid_until(), proof.valid_until());
    assert_eq!(db.count(h.grant.organization_id).await, 1);
    assert!(db
        .evidence
        .recover(Uuid::new_v4(), proof.evidence_ref())
        .await
        .unwrap()
        .is_none());
    assert!(db
        .evidence
        .recover(Uuid::nil(), proof.evidence_ref())
        .await
        .is_err());
    assert!(db
        .evidence
        .recover(h.grant.organization_id, "caller-selected-evidence")
        .await
        .is_err());
    assert_eq!(
        format!("{retained:?}"),
        "RetainedMachineAuthenticationProof { <private> }"
    );
    assert_eq!(
        format!("{original:?}"),
        "HistoricalMachineAuthenticationEvidence { <private> }"
    );
    assert_eq!(
        retained.into_delegate_proof().evidence_ref,
        proof.evidence_ref()
    );
    for statement in [
        "UPDATE delegated_authority_service.machine_authentication_evidence SET actor_id=actor_id",
        "DELETE FROM delegated_authority_service.machine_authentication_evidence",
        "TRUNCATE delegated_authority_service.machine_authentication_evidence",
    ] {
        assert!(sqlx::raw_sql(statement).execute(&db.owner).await.is_err());
    }
    assert!(
        sqlx::query("SELECT * FROM delegated_authority_service.delegation_grants")
            .fetch_all(&db.writer)
            .await
            .is_err()
    );
    assert!(
        sqlx::query("SELECT * FROM delegated_authority_service.use_receipts")
            .fetch_all(&db.writer)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn postgres_expired_history_does_not_recreate_or_refresh_authentication() {
    let _lock = crate::postgres::POSTGRES_TEST_LOCK.lock().await;
    let Some(db) = Database::new().await else {
        return;
    };
    let h = Harness::current();
    *h.state.lifetime.lock().unwrap() = 1;
    let proof = h.verify().await.unwrap();
    db.evidence.retain(&proof).await.unwrap();
    let original = db
        .evidence
        .recover(h.grant.organization_id, proof.evidence_ref())
        .await
        .unwrap()
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(1050)).await;
    assert!(db.evidence.retain(&proof).await.is_err());
    assert!(db
        .audited(&h)
        .verify(&h.grant, &h.request, h.now)
        .await
        .is_err());
    let recovered = db
        .evidence
        .recover(h.grant.organization_id, proof.evidence_ref())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(original.evidence_bytes(), recovered.evidence_bytes());
    assert_eq!(original.retained_at(), recovered.retained_at());
    assert_eq!(
        original.original_valid_until(),
        recovered.original_valid_until()
    );
    assert!(recovered.original_valid_until() < Utc::now());
    assert_eq!(db.count(h.grant.organization_id).await, 1);
}

#[tokio::test]
async fn postgres_storage_failure_and_unverified_proof_never_return_qualified_result() {
    let _lock = crate::postgres::POSTGRES_TEST_LOCK.lock().await;
    let Some(db) = Database::new().await else {
        return;
    };
    let mut h = Harness::current();
    let last = h.request.proof.last_mut().unwrap();
    *last = if *last == b'A' { b'B' } else { b'A' };
    assert!(db
        .audited(&h)
        .verify(&h.grant, &h.request, h.now)
        .await
        .is_err());
    assert_eq!(db.count(h.grant.organization_id).await, 0);
    db.sql("CREATE FUNCTION delegated_authority_service.machine_test_failure() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RAISE EXCEPTION ''synthetic storage failure''; END';
        CREATE TRIGGER z_machine_test_failure BEFORE INSERT ON delegated_authority_service.machine_authentication_evidence FOR EACH ROW EXECUTE FUNCTION delegated_authority_service.machine_test_failure();").await;
    let h = Harness::current();
    assert!(db
        .audited(&h)
        .verify(&h.grant, &h.request, h.now)
        .await
        .is_err());
    assert_eq!(db.count(h.grant.organization_id).await, 0);
    db.sql("DROP TRIGGER z_machine_test_failure ON delegated_authority_service.machine_authentication_evidence; DROP FUNCTION delegated_authority_service.machine_test_failure();").await;
}

#[tokio::test]
async fn postgres_deadline_is_checked_after_insert_and_after_committed_io() {
    let _lock = crate::postgres::POSTGRES_TEST_LOCK.lock().await;
    let Some(db) = Database::new().await else {
        return;
    };
    db.sql("CREATE FUNCTION delegated_authority_service.machine_test_delay() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN PERFORM pg_sleep(1.1); RETURN NEW; END';
        CREATE TRIGGER z_machine_test_delay BEFORE INSERT ON delegated_authority_service.machine_authentication_evidence FOR EACH ROW EXECUTE FUNCTION delegated_authority_service.machine_test_delay();").await;
    let h = Harness::current();
    *h.state.lifetime.lock().unwrap() = 1;
    assert!(db
        .audited(&h)
        .verify(&h.grant, &h.request, h.now)
        .await
        .is_err());
    assert_eq!(db.count(h.grant.organization_id).await, 0);
    db.sql("DROP TRIGGER z_machine_test_delay ON delegated_authority_service.machine_authentication_evidence;
        CREATE CONSTRAINT TRIGGER aaa_machine_test_delay AFTER INSERT ON delegated_authority_service.machine_authentication_evidence DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION delegated_authority_service.machine_test_delay();").await;
    let h = Harness::current();
    *h.state.lifetime.lock().unwrap() = 1;
    assert!(db
        .audited(&h)
        .verify(&h.grant, &h.request, h.now)
        .await
        .is_err());
    assert_eq!(
        db.count(h.grant.organization_id).await,
        0,
        "deferred guard rejects an expired commit"
    );
    db.sql("DROP TRIGGER aaa_machine_test_delay ON delegated_authority_service.machine_authentication_evidence;
        CREATE CONSTRAINT TRIGGER z_machine_test_delay AFTER INSERT ON delegated_authority_service.machine_authentication_evidence DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION delegated_authority_service.machine_test_delay();").await;
    let h = Harness::current();
    *h.state.lifetime.lock().unwrap() = 1;
    let proof = h.verify().await.unwrap();
    assert!(db
        .audited(&h)
        .verify(&h.grant, &h.request, h.now)
        .await
        .is_err());
    assert_eq!(
        db.count(h.grant.organization_id).await,
        1,
        "post-COMMIT expiry leaves history, never usable proof"
    );
    assert_eq!(
        db.evidence
            .recover(h.grant.organization_id, proof.evidence_ref())
            .await
            .unwrap()
            .unwrap()
            .evidence_bytes(),
        proof.evidence_bytes()
    );
    db.sql("DROP TRIGGER z_machine_test_delay ON delegated_authority_service.machine_authentication_evidence; DROP FUNCTION delegated_authority_service.machine_test_delay();").await;
}

#[tokio::test]
async fn postgres_audit_role_and_all_guards_are_required_for_readiness() {
    let _lock = crate::postgres::POSTGRES_TEST_LOCK.lock().await;
    let Some(db) = Database::new().await else {
        return;
    };
    db.evidence.readiness().await.unwrap();
    // Grant dangerous role paths without invoking their privileged operations.
    // NOINHERIT does not make membership safe: the login can still SET ROLE.
    db.sql(&format!("GRANT pg_execute_server_program TO {}", db.role))
        .await;
    assert!(db.evidence.readiness().await.is_err());
    db.sql(&format!(
        "REVOKE pg_execute_server_program FROM {}",
        db.role
    ))
    .await;
    db.sql(&format!("ALTER ROLE {} REPLICATION", db.role)).await;
    assert!(db.evidence.readiness().await.is_err());
    db.sql(&format!("ALTER ROLE {} NOREPLICATION", db.role))
        .await;
    db.evidence.readiness().await.unwrap();
    let pg_version: i32 = sqlx::query_scalar("SELECT current_setting('server_version_num')::INT")
        .fetch_one(&db.owner)
        .await
        .unwrap();
    if pg_version >= 170000 {
        db.sql(&format!(
            "GRANT MAINTAIN ON delegated_authority_service.machine_authentication_evidence TO {}",
            db.role
        ))
        .await;
        assert!(db.evidence.readiness().await.is_err());
        db.sql(&format!("REVOKE MAINTAIN ON delegated_authority_service.machine_authentication_evidence FROM {}", db.role)).await;
        db.evidence.readiness().await.unwrap();
    }
    let masked_role = db.role.clone();
    let masked_owner = PgPoolOptions::new()
        .max_connections(1)
        .after_connect(move |connection, _| {
            let command = format!("SET ROLE {masked_role}");
            Box::pin(async move {
                sqlx::raw_sql(AssertSqlSafe(command))
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect_with(db.owner.connect_options().as_ref().clone())
        .await
        .unwrap();
    assert!(
        PgMachineAuthenticationEvidenceRepository::new(masked_owner)
            .readiness()
            .await
            .is_err(),
        "SET ROLE cannot hide the privileged login behind a minimal audit role"
    );
    for (table, trigger) in [
        (
            "machine_authentication_evidence",
            "machine_authentication_evidence_binding",
        ),
        (
            "machine_authentication_evidence",
            "machine_authentication_evidence_commit",
        ),
        (
            "machine_authentication_evidence",
            "machine_authentication_evidence_immutable",
        ),
        (
            "machine_authentication_evidence",
            "machine_authentication_evidence_no_truncate",
        ),
        ("use_receipts", "use_receipts_machine_evidence"),
    ] {
        db.sql(&format!(
            "ALTER TABLE delegated_authority_service.{table} DISABLE TRIGGER {trigger}"
        ))
        .await;
        assert_eq!(
            PgDelegationGrantRepository::new(db.owner.clone())
                .readiness()
                .await,
            Err(RepositoryError::SchemaNotReady)
        );
        assert!(db.evidence.readiness().await.is_err());
        db.sql(&format!(
            "ALTER TABLE delegated_authority_service.{table} ENABLE TRIGGER {trigger}"
        ))
        .await;
    }
    db.sql("ALTER TABLE delegated_authority_service.machine_authentication_evidence DROP CONSTRAINT machine_authentication_evidence_pkey").await;
    assert!(db.evidence.readiness().await.is_err());
    db.sql("ALTER TABLE delegated_authority_service.machine_authentication_evidence ADD PRIMARY KEY (organization_id,evidence_ref)").await;
    for constraint in [
        "machine_evidence_digest_matches_bytes",
        "machine_evidence_document_matches_bytes",
        "machine_evidence_reference_matches_digest",
    ] {
        let definition:String=sqlx::query_scalar("SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid='delegated_authority_service.machine_authentication_evidence'::regclass AND conname=$1")
            .bind(constraint).fetch_one(&db.owner).await.unwrap();
        db.sql(&format!("ALTER TABLE delegated_authority_service.machine_authentication_evidence DROP CONSTRAINT {constraint}")).await;
        assert!(db.evidence.readiness().await.is_err());
        db.sql(&format!("ALTER TABLE delegated_authority_service.machine_authentication_evidence ADD CONSTRAINT {constraint} CHECK(true)")).await;
        assert!(db.evidence.readiness().await.is_err());
        db.sql(&format!("ALTER TABLE delegated_authority_service.machine_authentication_evidence DROP CONSTRAINT {constraint}, ADD CONSTRAINT {constraint} {definition}")).await;
    }
    for grant in [
        "SELECT ON delegated_authority_service.delegation_grants",
        "UPDATE ON delegated_authority_service.machine_authentication_evidence",
        "INSERT ON delegated_authority_service.use_receipts",
    ] {
        db.sql(&format!("GRANT {grant} TO {}", db.role)).await;
        assert!(db.evidence.readiness().await.is_err());
        db.sql(&format!("REVOKE {grant} FROM {}", db.role)).await;
    }
    db.sql("CREATE SCHEMA pgx_machine_audit_source; CREATE TABLE pgx_machine_audit_source.current_state(id INT);
        CREATE FUNCTION pgx_machine_audit_source.forge_state() RETURNS INT LANGUAGE SQL SECURITY DEFINER SET search_path=pg_catalog AS 'SELECT 1';
        REVOKE ALL ON FUNCTION pgx_machine_audit_source.forge_state() FROM PUBLIC;").await;
    for grant in [
        "SELECT ON pgx_machine_audit_source.current_state",
        "INSERT ON pgx_machine_audit_source.current_state",
        "EXECUTE ON FUNCTION pgx_machine_audit_source.forge_state()",
    ] {
        db.sql(&format!("GRANT {grant} TO {}", db.role)).await;
        assert!(db.evidence.readiness().await.is_err());
        db.sql(&format!("REVOKE {grant} FROM {}", db.role)).await;
    }
    db.sql("DROP SCHEMA pgx_machine_audit_source CASCADE").await;
    db.evidence.readiness().await.unwrap();
}

// Seed a real use ledger with explicitly synthetic consent/receipt-signing
// provenance. The machine VP and retained opaque proof remain Core-verified.
async fn seed_use_ledger(db: &Database, h: &mut Harness) -> (Uuid, Uuid, Value) {
    PgDelegationGrantRepository::new(db.owner.clone())
        .insert(h.grant.clone())
        .await
        .unwrap();
    let approved = h.now - Duration::milliseconds(1);
    let mut grant = serde_json::to_value(&h.grant).unwrap();
    grant["status"] = json!("ACTIVE");
    grant["revision"] = json!(2);
    grant["updated_at"] = json!(approved);
    grant["approval"] = json!({"profile":"urn:synthetic:approval:v1","grant_id":h.grant.id,
        "approver":h.grant.terms.grantor,"evidence_ref":"urn:synthetic:consent","authority_evidence_ref":"urn:synthetic:authority",
        "terms_digest":h.grant.terms_digest,"approved_at":approved});
    sqlx::query("UPDATE delegated_authority_service.delegation_grants SET status='ACTIVE',revision=2,updated_at=($1::TEXT)::TIMESTAMPTZ,grant_document=$2 WHERE organization_id=$3 AND id=$4")
        .bind(approved.to_rfc3339()).bind(&grant).bind(h.grant.organization_id).bind(h.grant.id).execute(&db.owner).await.unwrap();
    h.grant = serde_json::from_value(grant.clone()).unwrap();
    h.request.expected_revision = 2;
    h.challenges.0.lock().unwrap().binding.grant_revision = 2;
    let start_id = Uuid::new_v4();
    let final_id = Uuid::new_v4();
    let submission = Uuid::new_v4();
    let operation = json!({"action":h.request.action,"resource_id":h.request.resource,"audience":h.request.audience,
        "request_profile":h.request.operation_profile,"request_digest":h.request.operation_digest});
    let reference = json!({"id":h.grant.id,"revision":2,"terms_digest":h.grant.terms_digest});
    let start = json!({"profile":"urn:marty:delegation-command:v1","command":"START_USE","command_id":start_id,"grant":reference,"operation":operation});
    let final_command = json!({"profile":"urn:marty:delegation-command:v1","command":"FINALIZE_USE","command_id":final_id,"challenge_id":h.request.challenge_id,"proof_submission_id":submission});
    for (id, name, command) in [
        (start_id, "START_USE", start),
        (final_id, "FINALIZE_USE", final_command),
    ] {
        sqlx::query("INSERT INTO delegated_authority_service.use_command_claims (organization_id,actor_type,actor_id,command_id,command_name,command_digest,command_document,challenge_id,grant_id,grant_revision,grant_document) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,2,$10)")
            .bind(h.grant.organization_id).bind(serde_json::to_value(&h.request.actor).unwrap()["type"].as_str().unwrap())
            .bind(&h.request.actor.id).bind(id).bind(name).bind(format!("sha256:{:x}",Sha256::digest(serde_json::to_vec(&command).unwrap())))
            .bind(command).bind(h.request.challenge_id).bind(h.grant.id).bind(&grant).execute(&db.owner).await.unwrap();
    }
    let challenge = h.challenges.0.lock().unwrap().clone();
    let admission = json!({"organization_id":h.grant.organization_id,"challenge_id":h.request.challenge_id,"grant":grant,"operation":operation,
        "verifier_id":challenge.verifier_client_id,"nonce":challenge.nonce,"created_at":h.now,"expires_at":challenge.expires_at});
    sqlx::query("INSERT INTO delegated_authority_service.use_admissions (organization_id,challenge_id,actor_type,actor_id,command_id,verifier_id,nonce,challenge_document,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,($9::TEXT)::TIMESTAMPTZ,($10::TEXT)::TIMESTAMPTZ)")
        .bind(h.grant.organization_id).bind(h.request.challenge_id).bind(serde_json::to_value(&h.request.actor).unwrap()["type"].as_str().unwrap())
        .bind(&h.request.actor.id).bind(start_id).bind(&challenge.verifier_client_id).bind(&challenge.nonce).bind(admission)
        .bind(h.now.to_rfc3339()).bind(challenge.expires_at.to_rfc3339()).execute(&db.owner).await.unwrap();
    (
        final_id,
        submission,
        json!({"organization_id":h.grant.organization_id,"actor":h.request.actor,"grant":reference,
        "challenge":challenge.nonce,"operation":operation,"binding":h.grant.terms.binding,"evaluated_at":Utc::now()}),
    )
}
async fn insert_receipt(
    db: &Database,
    h: &Harness,
    command: Uuid,
    submission: Uuid,
    evaluation: Value,
    expires: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    let id = Uuid::new_v4();
    let payload = json!({"profile":"urn:marty:delegated-decision-receipt:v1","id":id,"decision":"PERMIT","evaluation":evaluation,"issued_at":Utc::now(),"expires_at":expires});
    // Intentionally synthetic transport-shaped JWS. These tests exercise SQL
    // evidence linkage; signing authority is covered by the signer owner tests.
    let compact = format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(b"{\"alg\":\"EdDSA\"}"),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap()),
        URL_SAFE_NO_PAD.encode([0; 64])
    );
    sqlx::query("INSERT INTO delegated_authority_service.use_receipts (organization_id,challenge_id,actor_type,actor_id,command_id,proof_submission_id,proof_digest,receipt_ref,receipt_digest,compact_jws,receipt_document,recorded_at,authorization_expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,clock_timestamp(),($12::TEXT)::TIMESTAMPTZ)")
        .bind(h.grant.organization_id).bind(h.request.challenge_id).bind(serde_json::to_value(&h.request.actor).unwrap()["type"].as_str().unwrap())
        .bind(&h.request.actor.id).bind(command).bind(submission).bind(format!("sha256:{:x}",Sha256::digest(&h.request.proof)))
        .bind(format!("urn:marty:delegated-receipt:{id}")).bind(format!("sha256:{:x}",Sha256::digest(compact.as_bytes())))
        .bind(compact).bind(payload).bind(expires.to_rfc3339()).execute(&db.owner).await.map(|_|())
}

#[tokio::test]
async fn postgres_final_use_requires_retained_machine_scope_and_original_deadline() {
    let _lock = crate::postgres::POSTGRES_TEST_LOCK.lock().await;
    let Some(db) = Database::new().await else {
        return;
    };
    let mut h = Harness::current();
    let (command, submission, mut evaluation) = seed_use_ledger(&db, &mut h).await;
    let proof = h.verify().await.unwrap();
    evaluation["proof_evidence_ref"] = json!(proof.evidence_ref());
    evaluation["proof_verified_at"] = proof.evidence_document()["proof"]["verified_at"].clone();
    evaluation["proof_valid_until"] = json!(proof.valid_until());
    let expiry = proof.valid_until() - Duration::seconds(1);
    let error = insert_receipt(&db, &h, command, submission, evaluation.clone(), expiry)
        .await
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("DA_USE_MACHINE_EVIDENCE_REQUIRED"));
    db.evidence.retain(&proof).await.unwrap();
    evaluation["evaluated_at"] = json!(Utc::now());
    for (path, value) in [
        (
            "/proof_evidence_ref",
            json!("urn:marty:oid4vp-proof:plain-key-proof"),
        ),
        (
            "/binding/key_thumbprint",
            json!(format!("sha256:{}", "a".repeat(64))),
        ),
        (
            "/proof_valid_until",
            json!(proof.valid_until() + Duration::seconds(1)),
        ),
        ("/proof_verified_at", json!(h.now - Duration::seconds(1))),
        ("/evaluated_at", json!(proof.valid_until())),
    ] {
        let mut bad = evaluation.clone();
        *bad.pointer_mut(path).unwrap() = value;
        let error = insert_receipt(&db, &h, command, submission, bad, expiry)
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("DA_USE_MACHINE_EVIDENCE"),
            "{error}"
        );
    }
    let error = insert_receipt(
        &db,
        &h,
        command,
        submission,
        evaluation.clone(),
        proof.valid_until() + Duration::seconds(1),
    )
    .await
    .unwrap_err();
    assert!(error
        .to_string()
        .contains("DA_USE_MACHINE_EVIDENCE_BINDING"));
    let original_proof = h.request.proof.clone();
    h.request.proof = b"different submitted bytes".to_vec();
    let error = insert_receipt(&db, &h, command, submission, evaluation.clone(), expiry)
        .await
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("DA_USE_MACHINE_EVIDENCE_BINDING"));
    h.request.proof = original_proof;
    // A separately verified audit for the same nonce but a different retained
    // operation cannot stand in for this admission's exact operation digest.
    h.request.operation_digest = format!("sha256:{}", "d".repeat(64));
    h.challenges.0.lock().unwrap().binding.operation_digest = h.request.operation_digest.clone();
    let other = h.verify().await.unwrap();
    db.evidence.retain(&other).await.unwrap();
    let mut wrong = evaluation.clone();
    wrong["proof_evidence_ref"] = json!(other.evidence_ref());
    let error = insert_receipt(&db, &h, command, submission, wrong, expiry)
        .await
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("DA_USE_MACHINE_EVIDENCE_BINDING"));
    insert_receipt(&db, &h, command, submission, evaluation, expiry)
        .await
        .unwrap();
}

#[tokio::test]
async fn postgres_service_account_cannot_claim_machine_authentication_reference() {
    let _lock = crate::postgres::POSTGRES_TEST_LOCK.lock().await;
    let Some(db) = Database::new().await else {
        return;
    };
    let mut h = Harness::current();
    h.grant.terms.delegate.principal_type = PrincipalType::ServiceAccount;
    h.request.actor = h.grant.terms.delegate.clone();
    h.grant.terms_digest = h.grant.calculate_terms_digest().unwrap();
    let (command, submission, mut evaluation) = seed_use_ledger(&db, &mut h).await;
    evaluation["proof_evidence_ref"] = json!(format!(
        "urn:marty:machine-authentication:sha256:{}",
        "a".repeat(64)
    ));
    let expiry = h.now + Duration::seconds(10);
    let error = insert_receipt(&db, &h, command, submission, evaluation.clone(), expiry)
        .await
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("DA_USE_MACHINE_EVIDENCE_BINDING"));
    evaluation["proof_evidence_ref"] = json!("urn:synthetic:service-account-key-proof");
    insert_receipt(&db, &h, command, submission, evaluation, expiry)
        .await
        .unwrap();
}
