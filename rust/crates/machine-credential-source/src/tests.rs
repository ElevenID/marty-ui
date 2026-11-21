//! Real owner tables/roles, append-only retention and ephemeral signatures.
//! Administrative fixtures are test data, not deployed issuer qualification.

use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::Signer;
use marty_delegated_authority::{machine_auth::MachineAuthenticationScope, Principal};
use marty_oid4vci::{types::SigningAlgorithm, verify_jwt_vc_presentation_with_profile};
use marty_oid4vp_contract::machine_jwt_vc::MACHINE_NESTED_JWT_AUTHORIZATIONS;
use marty_trust_profile::{
    CascadeRevocationPolicy, ComplianceStatus, IssuerEntity, IssuerEntityComplianceStatus,
    IssuerEntityType, PostgresTrustProfileRepository, TrustProfile, TrustProfileIssuer,
    TrustProfileRepository, TrustProfileStatus, TrustProfileType, TrustPurpose,
    TrustRelationshipStatus,
};
use p256::ecdsa::signature::Signer as _;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::AssertSqlSafe;

#[path = "composed_tests.rs"]
mod composed;
use std::{io::Read, str::FromStr};

enum SignerKey {
    Ed(ed25519_dalek::SigningKey),
    Es(p256::ecdsa::SigningKey),
}
impl SignerKey {
    fn new(es: bool) -> Self {
        loop {
            let mut seed = [0_u8; 32];
            std::fs::File::open("/dev/urandom")
                .unwrap()
                .read_exact(&mut seed)
                .unwrap();
            if !es {
                return Self::Ed(ed25519_dalek::SigningKey::from_bytes(&seed));
            }
            if let Ok(key) = p256::ecdsa::SigningKey::from_slice(&seed) {
                return Self::Es(key);
            }
        }
    }
    fn algorithm(&self) -> SigningAlgorithm {
        match self {
            Self::Ed(_) => SigningAlgorithm::EdDSA,
            Self::Es(_) => SigningAlgorithm::ES256,
        }
    }
    fn public(&self) -> Value {
        match self {
            Self::Ed(key) => {
                json!({"kty":"OKP","crv":"Ed25519","x":URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes())})
            }
            Self::Es(key) => {
                let point = key.verifying_key().to_sec1_point(false);
                json!({"kty":"EC","crv":"P-256","x":URL_SAFE_NO_PAD.encode(point.x().unwrap()),"y":URL_SAFE_NO_PAD.encode(point.y().unwrap())})
            }
        }
    }
    fn sign(&self, header: &Value, claims: &Value) -> String {
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let signature = match self {
            Self::Ed(key) => key.sign(input.as_bytes()).to_bytes().to_vec(),
            Self::Es(key) => {
                let signature: p256::ecdsa::Signature = key.sign(input.as_bytes());
                signature.normalize_s().to_bytes().to_vec()
            }
        };
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
    }
}

struct Database {
    admin: PgPool,
    options: PgConnectOptions,
    trust: PgPool,
    status: PgPool,
    evidence: PgPool,
    roles: [String; 3],
}
impl Database {
    async fn new() -> Self {
        let url = std::env::var("MACHINE_CREDENTIAL_SOURCE_TEST_DATABASE_URL")
            .expect("explicit disposable PostgreSQL URL is required");
        let base = PgConnectOptions::from_str(&url).unwrap();
        let control = PgPoolOptions::new()
            .max_connections(2)
            .connect_with(base.clone())
            .await
            .unwrap();
        let suffix = Uuid::new_v4().simple().to_string();
        let name = format!("machine_credential_test_{suffix}");
        // Dynamic identifiers are fixed prefixes plus generated lower-case UUID
        // hex. No URL, credential, caller input or arbitrary identifier enters SQL.
        sqlx::query(AssertSqlSafe(format!("CREATE DATABASE {name}")))
            .execute(&control)
            .await
            .unwrap();
        let options = base.database(&name);
        let admin = PgPoolOptions::new()
            .max_connections(6)
            .connect_with(options.clone())
            .await
            .unwrap();
        marty_organization::migration::migrate_organization_schema(&admin)
            .await
            .unwrap();
        marty_credential_template::migration::migrate_credential_template_schema(&admin)
            .await
            .unwrap();
        marty_trust_profile::run_migrations(&admin).await.unwrap();
        marty_issuance_service::migration::migrate_owned_schema(&admin, Uuid::new_v4())
            .await
            .unwrap();
        run_migrations(&admin).await.unwrap();
        run_migrations(&admin).await.unwrap();
        let roles = [
            format!("mc_trust_{suffix}"),
            format!("mc_status_{suffix}"),
            format!("mc_audit_{suffix}"),
        ];
        for role in &roles {
            sqlx::query(AssertSqlSafe(format!("CREATE ROLE {role} LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE")))
                .execute(&admin).await.unwrap();
        }
        sqlx::raw_sql(AssertSqlSafe(format!(
            "GRANT USAGE ON SCHEMA trust_profile_service TO {trust};
             GRANT SELECT ON trust_profile_service.trust_profiles,trust_profile_service.issuer_entities,
                trust_profile_service.trust_profile_issuers TO {trust};
             GRANT SELECT,INSERT,UPDATE ON trust_profile_service.machine_jwt_vc_authority_revisions TO {trust};
             GRANT USAGE ON SCHEMA issuance_service TO {status};
             GRANT SELECT ON issuance_service.issued_credentials,issuance_service.issuance_transactions TO {status};
             GRANT USAGE ON SCHEMA machine_credential_source TO {audit};
             GRANT SELECT ON machine_credential_source.schema_migrations TO {audit};
             GRANT SELECT,INSERT ON machine_credential_source.observations TO {audit};",
            trust=roles[0],status=roles[1],audit=roles[2],
        ))).execute(&admin).await.unwrap();
        let mut pools = Vec::new();
        for role in &roles {
            pools.push(
                PgPoolOptions::new()
                    .max_connections(4)
                    .connect_with(options.clone().username(role))
                    .await
                    .unwrap(),
            );
        }
        control.close().await;
        Self {
            admin,
            options,
            trust: pools[0].clone(),
            status: pools[1].clone(),
            evidence: pools[2].clone(),
            roles,
        }
    }
    async fn source(&self) -> PgOwnedMachineJwtVcAuthoritySource {
        PgOwnedMachineJwtVcAuthoritySource::connect(
            self.trust.clone(),
            self.status.clone(),
            self.evidence.clone(),
        )
        .await
        .unwrap()
    }
    async fn scoped_pool(&self, grants: &str) -> PgPool {
        let role = format!("mc_composed_{}", Uuid::new_v4().simple());
        // `grants` is one of this private fixture's constant SQL templates.
        sqlx::raw_sql(AssertSqlSafe(format!("CREATE ROLE {role} LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE; {}",grants.replace("$ROLE",&role))))
            .execute(&self.admin).await.unwrap();
        PgPoolOptions::new()
            .max_connections(3)
            .connect_with(self.options.clone().username(&role))
            .await
            .unwrap()
    }
}

struct Fixture {
    selection: MachineJwtVcSelection,
    profile: TrustProfile,
    issuer: IssuerEntity,
    relationship: TrustProfileIssuer,
    credential: String,
    presentation: String,
    transaction_id: String,
}
impl Fixture {
    async fn new(db: &Database, es: bool) -> Self {
        let now = Utc::now();
        let issued = DateTime::from_timestamp(now.timestamp() - 20, 0).unwrap();
        let expires = issued + Duration::minutes(10);
        let organization = Uuid::new_v4();
        let signer = SignerKey::new(es);
        let holder = SignerKey::new(es);
        let holder_key = holder.public();
        let subject = format!("did:jwk:{}", URL_SAFE_NO_PAD.encode(holder_key.to_string()));
        let issuer_name = format!("did:web:{}.example.test", Uuid::new_v4().simple());
        let kid = format!("{issuer_name}#credential");
        let mut key = signer.public();
        key["kid"] = json!(kid);
        key["alg"] = json!(signer.algorithm().as_str());
        key["use"] = json!("sig");
        let mut profile = TrustProfile {
            id: Uuid::new_v4(),
            organization_id: organization.to_string(),
            name: "Selected machine issuer".into(),
            description: None,
            status: TrustProfileStatus::Active,
            profile_type: TrustProfileType::Custom,
            compliance_status: ComplianceStatus::Compliant,
            trust_purposes: Some(vec![TrustPurpose::CredentialIssuer]),
            trust_sources: vec![],
            validation_rules: Default::default(),
            allowed_issuers: None,
            denied_issuers: None,
            system_issuer_overrides: serde_json::Map::new(),
            compatible_compliance_codes: vec![],
            verification_policy_set_id: None,
            auto_generated: false,
            revocation_policy: Default::default(),
            revocation_profile_id: None,
            time_policy: Default::default(),
            supported_formats: vec!["VC_JWT".into()],
            trusted_assertion_formats: None,
            created_at: issued,
            updated_at: issued,
        };
        profile.revocation_policy.check_ocsp = false;
        profile.revocation_policy.check_crl = false;
        profile.revocation_policy.check_status_list = false;
        let issuer = IssuerEntity {
            id: Uuid::new_v4(),
            organization_id: Some(organization.to_string()),
            issuer_id: issuer_name.clone(),
            issuer_type: IssuerEntityType::Organization,
            display_name: "Selected issuer".into(),
            description: None,
            is_system_issuer: false,
            compliance_status: IssuerEntityComplianceStatus::Compliant,
            accreditation_body: None,
            accreditations: vec![],
            accreditation_date: None,
            valid_from: issued,
            valid_until: Some(expires),
            trust_anchor_id: None,
            revoked_at: None,
            revocation_reason: None,
            revoked_by: None,
            metadata: json!({"verification_keys":[key]}),
            created_at: issued,
            updated_at: issued,
        };
        let relationship = TrustProfileIssuer {
            id: Uuid::new_v4(),
            trust_profile_id: profile.id,
            issuer_id: issuer.id,
            trust_level: 80,
            relationship_status: TrustRelationshipStatus::Trusted,
            cascade_revocation_policy: CascadeRevocationPolicy::Manual,
            metadata: json!({MACHINE_NESTED_JWT_AUTHORIZATIONS:["MachineCredential","RuntimeMembership"]}),
            created_at: issued,
            updated_at: issued,
        };
        let repository = PostgresTrustProfileRepository::new(db.admin.clone());
        repository.save_profile(&profile, None).await.unwrap();
        repository.save_issuer_entity(&issuer).await.unwrap();
        repository.save_profile_issuer(&relationship).await.unwrap();
        let credential_id = Uuid::new_v4();
        let credential_uri = format!("urn:uuid:{credential_id}");
        let claims = json!({"iss":issuer_name,"sub":subject,"jti":credential_uri,
            "iat":issued.timestamp(),"nbf":issued.timestamp(),"exp":expires.timestamp(),
            "vc":{"@context":["https://www.w3.org/ns/credentials/v2"],"id":credential_uri,"issuer":issuer_name,
            "type":["VerifiableCredential","MachineCredential","RuntimeMembership"],"credentialSubject":{"id":subject},
            "validFrom":issued.to_rfc3339(),"validUntil":expires.to_rfc3339()}});
        let credential = signer.sign(
            &json!({"typ":"JWT","alg":signer.algorithm().as_str(),"kid":kid}),
            &claims,
        );
        let presentation = holder.sign(&json!({"typ":"JWT","alg":holder.algorithm().as_str(),"jwk":holder_key}),
            &json!({"iss":subject,"sub":subject,"aud":"https://machine-verifier.example.test","nonce":"original-source-nonce-at-least-thirty-two-characters",
                "iat":now.timestamp(),"nbf":now.timestamp(),"exp":now.timestamp()+120,
                "vp":{"@context":["https://www.w3.org/ns/credentials/v2"],"type":["VerifiablePresentation"],
                    "holder":subject,"verifiableCredential":[credential]}}));
        let transaction_id = Uuid::new_v4().to_string();
        let template_id = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO issuance_service.issuance_transactions
            (id,organization_id,credential_template_id,subject_did,status,pre_auth_code,claims,created_at,expires_at,issued_at,
             credential_type,credential_payload_format,reserved_credential_id,issuer_did_override,issuer_algorithm)
            VALUES($1,$2,$3,$4,'issued',$5,'{}',$6,$7,$6,'MachineCredential','jwt_vc_json',$8,$9,$10)")
            .bind(&transaction_id).bind(organization.to_string()).bind(&template_id).bind(&subject)
            .bind(Uuid::new_v4().to_string()).bind(issued).bind(expires).bind(&credential_uri).bind(&issuer_name)
            .bind(signer.algorithm().as_str()).execute(&db.admin).await.unwrap();
        sqlx::query("INSERT INTO issuance_service.issued_credentials
            (id,transaction_id,organization_id,credential_template_id,subject_did,issuer_did,credential_jwt,credential_hash,
             status,status_updated_at,revoked,issued_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'active',$9,false,$9,$10)")
            .bind(&credential_uri).bind(&transaction_id).bind(organization.to_string()).bind(&template_id)
            .bind(&subject).bind(&issuer_name).bind(&credential).bind(format!("{:x}",Sha256::digest(credential.as_bytes())))
            .bind(issued).bind(expires).execute(&db.admin).await.unwrap();
        let selection = MachineJwtVcSelection {
            scope: MachineAuthenticationScope {
                organization_id: organization,
                machine_identity_id: Uuid::new_v4(),
                deployment_profile_id: Uuid::new_v4(),
                principal: Principal {
                    principal_type: PrincipalType::MachineIdentity,
                    id: subject,
                },
                runtime_instance_ref: "urn:runtime:owned-source-test".into(),
                key_id: "machine-key".into(),
                key_thumbprint: format!("sha256:{}", "1".repeat(64)),
                policy_id: Uuid::new_v4(),
                policy_digest: format!("sha256:{}", "2".repeat(64)),
                grant_id: Uuid::new_v4(),
                grant_revision: 1,
                challenge_id: Uuid::new_v4(),
                challenge_digest: format!("sha256:{}", "3".repeat(64)),
                proof_evidence_ref: format!(
                    "urn:marty:oid4vp-proof:{:x}",
                    Sha256::digest(presentation.as_bytes())
                ),
                action: "credential:issue".into(),
                audience: "https://resource.example.test".into(),
                resource: "urn:resource:one".into(),
                operation_profile: "urn:operation:issue:v1".into(),
                operation_digest: format!("sha256:{}", "4".repeat(64)),
            },
            trust_profile_id: profile.id,
            securing_profile: JwtVcSecuringProfile::MartyNestedVc2JwtV1,
            credential_id,
            credential_digest: format!("sha256:{:x}", Sha256::digest(credential.as_bytes())),
            issuer: issuer_name,
            verification_method_id: kid,
            algorithm: signer.algorithm(),
        };
        Self {
            selection,
            profile,
            issuer,
            relationship,
            credential,
            presentation,
            transaction_id,
        }
    }
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL admin URL; creates fresh owned databases"]
async fn owned_machine_credentials_real_postgres_crypto_and_history() {
    let db = Database::new().await;
    let source = db.source().await;
    for es in [false, true] {
        let fixture = Fixture::new(&db, es).await;
        let authority = source
            .resolve_current(&fixture.selection, Utc::now())
            .await
            .unwrap();
        assert!(authority.selection == fixture.selection);
        assert_eq!(authority.trust_profile_revision, 1);
        let keys = TrustedSdJwtIssuerKeys::new(vec![authority.issuer_key.clone()]).unwrap();
        let verified = verify_jwt_vc_presentation_with_profile(
            &fixture.presentation,
            &keys,
            "original-source-nonce-at-least-thirty-two-characters",
            "https://machine-verifier.example.test",
            Utc::now().timestamp(),
            JwtVcSecuringProfile::MartyNestedVc2JwtV1,
        )
        .unwrap();
        assert_eq!(verified.credential_jwt(), fixture.credential);
        let repository = PgMachineCredentialSourceEvidence::new(db.evidence.clone());
        let retained = repository
            .recover(
                fixture.selection.scope.organization_id,
                &authority.evidence_ref,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            retained.document()["scope"],
            serde_json::to_value(&fixture.selection.scope).unwrap()
        );
        assert_eq!(
            retained.document()["status"]["transaction_id"],
            fixture.transaction_id
        );
        assert_eq!(retained.document()["trust"]["profile_revision"], 1);
        assert!(!String::from_utf8_lossy(retained.bytes()).contains(&fixture.credential));
        assert!(!String::from_utf8_lossy(retained.bytes()).contains(&fixture.presentation));
        assert!(retained.retained_at() < authority.valid_until);
        assert!(repository
            .recover(Uuid::new_v4(), &authority.evidence_ref)
            .await
            .unwrap()
            .is_none());
        assert!(verify_jwt_vc_presentation_with_profile(
            &fixture.presentation,
            &keys,
            "different-nonce",
            "https://machine-verifier.example.test",
            Utc::now().timestamp(),
            JwtVcSecuringProfile::MartyNestedVc2JwtV1
        )
        .is_err());
        let mut changed = fixture.selection.clone();
        changed.scope.grant_revision += 1;
        let second = source.resolve_current(&changed, Utc::now()).await.unwrap();
        assert_ne!(second.evidence_ref, authority.evidence_ref);
        assert_eq!(second.trust_profile_revision, 1);
        let recovered = repository
            .recover(
                fixture.selection.scope.organization_id,
                &authority.evidence_ref,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(recovered.bytes(), retained.bytes());
        for statement in [
            "UPDATE machine_credential_source.observations SET retained_at=retained_at",
            "DELETE FROM machine_credential_source.observations",
            "TRUNCATE machine_credential_source.observations",
        ] {
            assert!(sqlx::query(statement).execute(&db.admin).await.is_err());
        }
    }
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL admin URL; creates fresh owned databases"]
async fn owned_machine_credentials_current_revocation_profile_and_exact_artifact() {
    let db = Database::new().await;
    let source = db.source().await;
    let mut fixture = Fixture::new(&db, false).await;
    let repository = PostgresTrustProfileRepository::new(db.admin.clone());
    let original = source
        .resolve_current(&fixture.selection, Utc::now())
        .await
        .unwrap();
    for status in ["suspended", "revoked"] {
        sqlx::query("UPDATE issuance_service.issued_credentials SET status=$2,revoked=($2='revoked'),status_updated_at=clock_timestamp() WHERE id=$1")
            .bind(format!("urn:uuid:{}",fixture.selection.credential_id)).bind(status).execute(&db.admin).await.unwrap();
        assert!(source
            .resolve_current(&fixture.selection, Utc::now())
            .await
            .is_err());
    }
    sqlx::query("UPDATE issuance_service.issued_credentials SET status='active',revoked=false,status_updated_at=clock_timestamp() WHERE id=$1")
        .bind(format!("urn:uuid:{}",fixture.selection.credential_id)).execute(&db.admin).await.unwrap();
    let metadata = fixture.relationship.metadata.clone();
    fixture.relationship.metadata = json!({"marty_credential_authorizations_v1":[{"format":"SD_JWT_VC","vct":"https://type.example.test/MachineCredential"}]});
    repository
        .save_profile_issuer(&fixture.relationship)
        .await
        .unwrap();
    assert!(source
        .resolve_current(&fixture.selection, Utc::now())
        .await
        .is_err());
    fixture.relationship.metadata = metadata;
    repository
        .save_profile_issuer(&fixture.relationship)
        .await
        .unwrap();
    let restored = source
        .resolve_current(&fixture.selection, Utc::now())
        .await
        .unwrap();
    assert_eq!(restored.trust_profile_revision, 3);
    for fault in 0..7 {
        let mut profile = fixture.profile.clone();
        let mut issuer = fixture.issuer.clone();
        let mut relationship = fixture.relationship.clone();
        match fault {
            0 => profile.status = TrustProfileStatus::Suspended,
            1 => profile.revocation_policy.check_status_list = true,
            2 => issuer.revoked_at = Some(Utc::now()),
            3 => issuer.metadata = json!({"verification_keys":[]}),
            4 => relationship.relationship_status = TrustRelationshipStatus::Denied,
            5 => {
                relationship.metadata =
                    json!({MACHINE_NESTED_JWT_AUTHORIZATIONS:["MachineCredential"]})
            }
            6 => profile.trust_purposes = Some(vec![TrustPurpose::PresentationVerifier]),
            _ => unreachable!(),
        }
        repository.save_profile(&profile, None).await.unwrap();
        repository.save_issuer_entity(&issuer).await.unwrap();
        repository.save_profile_issuer(&relationship).await.unwrap();
        assert!(
            source
                .resolve_current(&fixture.selection, Utc::now())
                .await
                .is_err(),
            "fault {fault}"
        );
        repository
            .save_profile(&fixture.profile, None)
            .await
            .unwrap();
        repository
            .save_issuer_entity(&fixture.issuer)
            .await
            .unwrap();
        repository
            .save_profile_issuer(&fixture.relationship)
            .await
            .unwrap();
    }
    for fault in 0..7 {
        let mut changed = fixture.selection.clone();
        match fault {
            0 => changed.scope.organization_id = Uuid::new_v4(),
            1 => changed.trust_profile_id = Uuid::new_v4(),
            2 => changed.credential_id = Uuid::new_v4(),
            3 => changed.credential_digest = format!("sha256:{}", "0".repeat(64)),
            4 => changed.issuer = "did:web:elsewhere.example.test".into(),
            5 => changed.scope.principal.id = "did:key:other-subject".into(),
            6 => changed.securing_profile = JwtVcSecuringProfile::W3cVc2Jose2026V1,
            _ => unreachable!(),
        }
        assert!(
            source.resolve_current(&changed, Utc::now()).await.is_err(),
            "selection {fault}"
        );
    }
    for (field, value) in [
        ("credential_hash", "wrong-hash"),
        ("credential_jwt", "not-a-jwt"),
    ] {
        // The column is one of the two literal names immediately above.
        sqlx::query(AssertSqlSafe(format!(
            "UPDATE issuance_service.issued_credentials SET {field}=$2 WHERE id=$1"
        )))
        .bind(format!("urn:uuid:{}", fixture.selection.credential_id))
        .bind(value)
        .execute(&db.admin)
        .await
        .unwrap();
        assert!(source
            .resolve_current(&fixture.selection, Utc::now())
            .await
            .is_err());
        sqlx::query("UPDATE issuance_service.issued_credentials SET credential_hash=$2,credential_jwt=$3 WHERE id=$1")
            .bind(format!("urn:uuid:{}",fixture.selection.credential_id))
            .bind(format!("{:x}",Sha256::digest(fixture.credential.as_bytes()))).bind(&fixture.credential)
            .execute(&db.admin).await.unwrap();
    }
    sqlx::query("UPDATE issuance_service.issuance_transactions SET status='signing' WHERE id=$1")
        .bind(&fixture.transaction_id)
        .execute(&db.admin)
        .await
        .unwrap();
    assert!(source
        .resolve_current(&fixture.selection, Utc::now())
        .await
        .is_err());
    sqlx::query("UPDATE issuance_service.issuance_transactions SET status='issued' WHERE id=$1")
        .bind(&fixture.transaction_id)
        .execute(&db.admin)
        .await
        .unwrap();
    sqlx::query("UPDATE issuance_service.issued_credentials SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1")
        .bind(format!("urn:uuid:{}",fixture.selection.credential_id)).execute(&db.admin).await.unwrap();
    assert!(source
        .resolve_current(&fixture.selection, Utc::now())
        .await
        .is_err());
    let history = PgMachineCredentialSourceEvidence::new(db.evidence.clone())
        .recover(
            fixture.selection.scope.organization_id,
            &original.evidence_ref,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(history.document()["status"]["state"], "ACTIVE");
    assert_eq!(history.document()["trust"]["profile_revision"], 1);
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL admin URL; creates fresh owned databases"]
async fn owned_machine_credentials_role_schema_and_commit_deadline_guards() {
    let db = Database::new().await;
    let source = db.source().await;
    let fixture = Fixture::new(&db, true).await;
    for (index, role) in db.roles.iter().enumerate() {
        for (escalate, restore) in [
            (
                format!("GRANT pg_execute_server_program TO {role}"),
                format!("REVOKE pg_execute_server_program FROM {role}"),
            ),
            (
                format!("ALTER ROLE {role} REPLICATION"),
                format!("ALTER ROLE {role} NOREPLICATION"),
            ),
        ] {
            // All identifiers are generated by this private fixture. Each
            // escalation is exercised through the original actual LOGIN pool.
            sqlx::query(AssertSqlSafe(escalate))
                .execute(&db.admin)
                .await
                .unwrap();
            assert!(source
                .resolve_current(&fixture.selection, Utc::now())
                .await
                .is_err());
            let owner_rejected = match index {
                0 => PgMachineJwtVcTrustAuthority::new(db.trust.clone())
                    .check_role_readiness()
                    .await
                    .is_err(),
                1 => PgMachineJwtVcStatusAuthority::new(db.status.clone())
                    .check_role_readiness()
                    .await
                    .is_err(),
                _ => PgMachineCredentialSourceEvidence::new(db.evidence.clone())
                    .readiness()
                    .await
                    .is_err(),
            };
            assert!(owner_rejected, "each owner rejects administrative roles");
            sqlx::query(AssertSqlSafe(restore))
                .execute(&db.admin)
                .await
                .unwrap();
            source.readiness().await.unwrap();
        }
    }
    let restricted_role = db.roles[0].clone();
    let disguised = PgPoolOptions::new()
        .max_connections(1)
        .after_connect(move |connection, _| {
            let restricted_role = restricted_role.clone();
            Box::pin(async move {
                sqlx::query(AssertSqlSafe(format!("SET ROLE {restricted_role}")))
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect_with(db.options.clone())
        .await
        .unwrap();
    assert!(
        PgOwnedMachineJwtVcAuthoritySource::connect(
            disguised,
            db.status.clone(),
            db.evidence.clone()
        )
        .await
        .is_err(),
        "privileged session cannot qualify through SET ROLE"
    );
    assert!(PgOwnedMachineJwtVcAuthoritySource::connect(
        db.admin.clone(),
        db.status.clone(),
        db.evidence.clone()
    )
    .await
    .is_err());
    sqlx::query(AssertSqlSafe(format!(
        "GRANT REFERENCES(profile_id) ON trust_profile_service.machine_jwt_vc_authority_revisions TO {}",
        db.roles[0]
    )))
    .execute(&db.admin)
    .await
    .unwrap();
    assert!(source
        .resolve_current(&fixture.selection, Utc::now())
        .await
        .is_err());
    sqlx::query(AssertSqlSafe(format!(
        "REVOKE REFERENCES(profile_id) ON trust_profile_service.machine_jwt_vc_authority_revisions FROM {}",
        db.roles[0]
    )))
    .execute(&db.admin)
    .await
    .unwrap();
    sqlx::query(AssertSqlSafe(format!(
        "GRANT UPDATE(metadata) ON trust_profile_service.issuer_entities TO {}",
        db.roles[0]
    )))
    .execute(&db.admin)
    .await
    .unwrap();
    assert!(PgOwnedMachineJwtVcAuthoritySource::connect(
        db.trust.clone(),
        db.status.clone(),
        db.evidence.clone()
    )
    .await
    .is_err());
    assert!(source
        .resolve_current(&fixture.selection, Utc::now())
        .await
        .is_err());
    sqlx::query(AssertSqlSafe(format!(
        "REVOKE UPDATE(metadata) ON trust_profile_service.issuer_entities FROM {}",
        db.roles[0]
    )))
    .execute(&db.admin)
    .await
    .unwrap();
    let observation = source
        .resolve_current(&fixture.selection, Utc::now())
        .await
        .unwrap();
    let audit = PgMachineCredentialSourceEvidence::new(db.evidence.clone());
    let history = audit
        .recover(
            fixture.selection.scope.organization_id,
            &observation.evidence_ref,
        )
        .await
        .unwrap()
        .unwrap();
    let mut record: SourceEvidence = serde_json::from_slice(history.bytes()).unwrap();
    let deadline = Utc::now() + Duration::milliseconds(150);
    record.valid_until = deadline;
    record.status.valid_until = deadline;
    record.trust.valid_until = deadline;
    record.completed_at = Utc::now();
    sqlx::raw_sql("CREATE FUNCTION machine_credential_source.test_delay() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.25); RETURN NEW; END $$;
        CREATE CONSTRAINT TRIGGER a_test_delay AFTER INSERT ON machine_credential_source.observations DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION machine_credential_source.test_delay();")
        .execute(&db.admin).await.unwrap();
    assert!(audit.readiness().await.is_err());
    assert!(
        audit.retain(&record).await.is_err(),
        "deferred source deadline must abort delayed commit"
    );
    // Cancel the caller while a live COMMIT is actually waiting in PostgreSQL.
    // Only COMMIT survives; the caller receives no positive authority result.
    sqlx::raw_sql("CREATE OR REPLACE FUNCTION machine_credential_source.test_delay() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.6); RETURN NEW; END $$")
        .execute(&db.admin).await.unwrap();
    let mut live: SourceEvidence = serde_json::from_slice(history.bytes()).unwrap();
    live.completed_at = Utc::now();
    let live_bytes = serde_json::to_vec(&live).unwrap();
    let live_ref = format!(
        "urn:marty:machine-credential-source:sha256:{:x}",
        Sha256::digest(&live_bytes)
    );
    let retaining = audit.clone();
    let pending = tokio::spawn(async move { retaining.retain(&live).await });
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let committing: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename=$1 AND query LIKE 'COMMIT%' AND wait_event='PgSleep')")
                .bind(&db.roles[2]).fetch_one(&db.admin).await.unwrap();
            if committing { break; }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }).await.expect("retention reached its protected COMMIT");
    pending.abort();
    assert!(pending.await.unwrap_err().is_cancelled());
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if audit
                .recover(fixture.selection.scope.organization_id, &live_ref)
                .await
                .unwrap()
                .is_some()
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("detached COMMIT completed without retry");
    sqlx::raw_sql("DROP TRIGGER a_test_delay ON machine_credential_source.observations; DROP FUNCTION machine_credential_source.test_delay()")
        .execute(&db.admin).await.unwrap();
    audit.readiness().await.unwrap();
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM machine_credential_source.observations")
            .fetch_one(&db.admin)
            .await
            .unwrap();
    assert_eq!(count, 2);
    sqlx::query("ALTER TABLE machine_credential_source.observations DISABLE TRIGGER machine_credential_source_immutable")
        .execute(&db.admin).await.unwrap();
    assert!(audit.readiness().await.is_err());
    sqlx::query("ALTER TABLE machine_credential_source.observations ENABLE TRIGGER machine_credential_source_immutable")
        .execute(&db.admin).await.unwrap();
    audit.readiness().await.unwrap();
    sqlx::raw_sql("ALTER TABLE machine_credential_source.observations DROP CONSTRAINT machine_credential_source_digest;
        ALTER TABLE machine_credential_source.observations ADD CONSTRAINT machine_credential_source_digest CHECK(true)")
        .execute(&db.admin).await.unwrap();
    assert!(
        audit.readiness().await.is_err(),
        "a matching constraint name is insufficient"
    );
    sqlx::raw_sql("ALTER TABLE machine_credential_source.observations DROP CONSTRAINT machine_credential_source_digest;
        ALTER TABLE machine_credential_source.observations ADD CONSTRAINT machine_credential_source_digest CHECK(evidence_digest='sha256:'||encode(sha256(evidence_bytes),'hex'));
        DROP TRIGGER machine_credential_source_binding ON machine_credential_source.observations;
        CREATE TRIGGER machine_credential_source_binding BEFORE INSERT ON machine_credential_source.observations FOR EACH ROW WHEN(false) EXECUTE FUNCTION machine_credential_source.check_observation();")
        .execute(&db.admin).await.unwrap();
    assert!(
        audit.readiness().await.is_err(),
        "a WHEN(false) guard cannot qualify"
    );
}
