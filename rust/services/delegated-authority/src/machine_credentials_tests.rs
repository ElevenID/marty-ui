//! Synthetic source records plus actual ephemeral issuer/holder signatures.
//! These tests qualify cryptographic composition, never a live source owner.

use super::*;
use std::{
    io::Read,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    },
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::Signer;
use marty_principal_runtime_binding::{
    machine_policy::{
        qualify_machine_binding, MachineAuthenticationPolicy, QualifiedMachineBinding,
    },
    parse_binding_record, parse_configuration, parse_machine_snapshot,
};
use p256::ecdsa::signature::Signer as _;
use serde_json::json;

use crate::{
    machine_auth::{
        MachineAuthenticationStateSource, MartyMachineOid4vpProofVerifier,
        ResolvedMachineAuthenticationState,
    },
    test_support::pending_grant,
    Binding, BindingMethod, DelegateProofVerifier, DelegationFlowContextV1, DelegationGrant,
    DelegationOid4vpChallenge, DelegationOid4vpChallengeStore, DelegationOid4vpChallengeStoreError,
    DelegationUseRequest, MartyOid4vpDelegateProofVerifier, Principal, VerifiedDelegateProof,
};

const NOW: i64 = 1_795_219_200;
const ISSUER: &str = "did:web:machine-issuer.example";
const KID: &str = "did:web:machine-issuer.example#credential-signing";
const VERIFIER: &str = "https://machine-verifier.example";
const NONCE: &str = "synthetic-source-owned-machine-challenge-0123456789";
const SOURCE_REF: &str = "urn:synthetic:machine-credential-authority:retained-record:1";

enum EphemeralSigner {
    Ed(ed25519_dalek::SigningKey),
    Es(p256::ecdsa::SigningKey),
}

impl EphemeralSigner {
    fn new(es256: bool) -> Self {
        // Private test material is created only at execution, never committed
        // or copied from a private Protocol corpus.
        loop {
            let mut seed = [0_u8; 32];
            std::fs::File::open("/dev/urandom")
                .unwrap()
                .read_exact(&mut seed)
                .unwrap();
            if !es256 {
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
            Self::Ed(key) => json!({
                "kty":"OKP", "crv":"Ed25519",
                "x":URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes())
            }),
            Self::Es(key) => {
                let point = key.verifying_key().to_sec1_point(false);
                json!({
                    "kty":"EC", "crv":"P-256",
                    "x":URL_SAFE_NO_PAD.encode(point.x().unwrap()),
                    "y":URL_SAFE_NO_PAD.encode(point.y().unwrap())
                })
            }
        }
    }

    fn sign_raw(&self, header: &str, claims: &str) -> String {
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(claims)
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

    fn sign(&self, header: &Value, claims: &Value) -> String {
        self.sign_raw(&header.to_string(), &claims.to_string())
    }
}

struct Clock {
    value: Mutex<DateTime<Utc>>,
    calls: AtomicUsize,
    change_on_call: Mutex<Option<(usize, DateTime<Utc>)>>,
}

impl Clock {
    fn new(now: DateTime<Utc>) -> Self {
        Self {
            value: Mutex::new(now),
            calls: AtomicUsize::new(0),
            change_on_call: Mutex::new(None),
        }
    }
}

impl DelegationClock for Clock {
    fn now(&self) -> DateTime<Utc> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        let mut value = self.value.lock().unwrap();
        if let Some((selected, next)) = *self.change_on_call.lock().unwrap() {
            if call == selected {
                *value = next;
            }
        }
        *value
    }
}

#[derive(Clone, Copy, Debug)]
enum Fault {
    None,
    Scope(usize),
    Selection(usize),
    State(usize, MachineCredentialSourceStatus),
    WrongIssuerKey,
    WrongIssuerIdentity,
    WrongKeyId,
    WrongAlgorithm,
    PrivateKey,
    DuplicateJwkMember,
    MissingTypeAuthority,
    DuplicateTypeAuthority,
    EmptyTypeAuthority,
    Revision,
    ProfileDigest,
    EvidenceRef,
    Future,
    Stale,
    EmptyWindow,
    Overlong,
    Advance(i64),
    Unavailable,
}

struct FixtureAuthoritySource {
    public: Value,
    algorithm: SigningAlgorithm,
    fault: Mutex<Fault>,
    clock: Arc<Clock>,
    calls: AtomicUsize,
}

#[async_trait]
impl MachineJwtVcAuthoritySource for FixtureAuthoritySource {
    async fn resolve_current(
        &self,
        selection: &MachineJwtVcSelection,
        now: DateTime<Utc>,
    ) -> Result<ResolvedMachineJwtVcAuthority, MachineEvidenceError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mut record = ResolvedMachineJwtVcAuthority {
            selection: selection.clone(),
            trust_profile_revision: 4,
            trust_profile_digest: format!("sha256:{}", "a".repeat(64)),
            trust_profile_status: MachineCredentialSourceStatus::Active,
            issuer_status: MachineCredentialSourceStatus::Active,
            issuer_key_status: MachineCredentialSourceStatus::Active,
            credential_status: MachineCredentialSourceStatus::Active,
            issuer_key: ResolvedSdJwtIssuerKey::new(
                ISSUER,
                Some(KID.into()),
                self.algorithm,
                self.public.to_string(),
            ),
            authorized_credential_types: vec![
                "MachineCredential".into(),
                "RuntimeMembership".into(),
            ],
            evidence_ref: SOURCE_REF.into(),
            observed_at: now,
            valid_until: now + Duration::seconds(20),
        };
        match *self.fault.lock().unwrap() {
            Fault::None => {}
            Fault::Scope(field) => change_scope(&mut record.selection.scope, field),
            Fault::Selection(field) => match field {
                0 => record.selection.trust_profile_id = Uuid::new_v4(),
                1 => record.selection.securing_profile = JwtVcSecuringProfile::W3cVc2Jose2026V1,
                2 => record.selection.credential_id = Uuid::new_v4(),
                3 => record.selection.credential_digest = format!("sha256:{}", "0".repeat(64)),
                4 => record.selection.issuer = "did:web:other.example".into(),
                5 => record.selection.verification_method_id = "did:web:other.example#key".into(),
                6 => record.selection.algorithm = SigningAlgorithm::RS256,
                _ => unreachable!(),
            },
            Fault::State(field, status) => match field {
                0 => record.trust_profile_status = status,
                1 => record.issuer_status = status,
                2 => record.issuer_key_status = status,
                3 => record.credential_status = status,
                _ => unreachable!(),
            },
            Fault::WrongIssuerKey => {
                let mut public =
                    EphemeralSigner::new(self.algorithm == SigningAlgorithm::ES256).public();
                public["kid"] = json!(KID);
                record.issuer_key = ResolvedSdJwtIssuerKey::new(
                    ISSUER,
                    Some(KID.into()),
                    self.algorithm,
                    public.to_string(),
                );
            }
            Fault::WrongIssuerIdentity => {
                record.issuer_key = ResolvedSdJwtIssuerKey::new(
                    "did:web:other.example",
                    Some(KID.into()),
                    self.algorithm,
                    self.public.to_string(),
                )
            }
            Fault::WrongKeyId => {
                record.issuer_key = ResolvedSdJwtIssuerKey::new(
                    ISSUER,
                    Some("did:web:machine-issuer.example#other".into()),
                    self.algorithm,
                    self.public.to_string(),
                )
            }
            Fault::WrongAlgorithm => {
                record.issuer_key = ResolvedSdJwtIssuerKey::new(
                    ISSUER,
                    Some(KID.into()),
                    SigningAlgorithm::RS256,
                    self.public.to_string(),
                )
            }
            Fault::PrivateKey => {
                let mut public = self.public.clone();
                public["d"] = json!("not-public-material");
                record.issuer_key = ResolvedSdJwtIssuerKey::new(
                    ISSUER,
                    Some(KID.into()),
                    self.algorithm,
                    public.to_string(),
                );
            }
            Fault::DuplicateJwkMember => {
                record.issuer_key = ResolvedSdJwtIssuerKey::new(
                    ISSUER,
                    Some(KID.into()),
                    self.algorithm,
                    self.public
                        .to_string()
                        .replacen('{', "{\"kty\":\"OKP\",", 1),
                )
            }
            Fault::MissingTypeAuthority => record.authorized_credential_types.truncate(1),
            Fault::DuplicateTypeAuthority => record
                .authorized_credential_types
                .push("MachineCredential".into()),
            Fault::EmptyTypeAuthority => record.authorized_credential_types.clear(),
            Fault::Revision => record.trust_profile_revision = 0,
            Fault::ProfileDigest => record.trust_profile_digest = "not-a-digest".into(),
            Fault::EvidenceRef => record.evidence_ref = "unretained relative path".into(),
            Fault::Future => record.observed_at = now + Duration::seconds(1),
            Fault::Stale => {
                record.observed_at = now - Duration::seconds(31);
                record.valid_until = now - Duration::seconds(1);
            }
            Fault::EmptyWindow => record.valid_until = now,
            Fault::Overlong => record.valid_until = now + Duration::seconds(31),
            Fault::Advance(seconds) => {
                *self.clock.value.lock().unwrap() = now + Duration::seconds(seconds)
            }
            Fault::Unavailable => return Err(MachineEvidenceError),
        }
        Ok(record)
    }
}

fn change_scope(scope: &mut MachineAuthenticationScope, field: usize) {
    match field {
        0 => scope.organization_id = Uuid::new_v4(),
        1 => scope.machine_identity_id = Uuid::new_v4(),
        2 => scope.deployment_profile_id = Uuid::new_v4(),
        3 => scope.principal.id = "did:web:other-machine.example".into(),
        4 => scope.principal.principal_type = PrincipalType::ServiceAccount,
        5 => scope.runtime_instance_ref = "urn:synthetic:runtime:other".into(),
        6 => scope.key_id = "other-key".into(),
        7 => scope.key_thumbprint = format!("sha256:{}", "0".repeat(64)),
        8 => scope.policy_id = Uuid::new_v4(),
        9 => scope.policy_digest = format!("sha256:{}", "0".repeat(64)),
        10 => scope.grant_id = Uuid::new_v4(),
        11 => scope.grant_revision += 1,
        12 => scope.challenge_id = Uuid::new_v4(),
        13 => scope.challenge_digest = format!("sha256:{}", "0".repeat(64)),
        14 => scope.proof_evidence_ref = "urn:synthetic:other-proof".into(),
        15 => scope.action = "urn:synthetic:other-action".into(),
        16 => scope.audience = "https://other-audience.example".into(),
        17 => scope.resource = "urn:synthetic:other-resource".into(),
        18 => scope.operation_profile = "urn:synthetic:other-profile".into(),
        19 => scope.operation_digest = format!("sha256:{}", "0".repeat(64)),
        _ => unreachable!(),
    }
}

#[derive(Clone)]
struct Challenges(DelegationOid4vpChallenge);

#[async_trait]
impl DelegationOid4vpChallengeStore for Challenges {
    async fn load_active(
        &self,
        _: Uuid,
        _: Uuid,
        _: Uuid,
    ) -> Result<DelegationOid4vpChallenge, DelegationOid4vpChallengeStoreError> {
        Ok(self.0.clone())
    }
}

struct FixtureState(Value);

#[async_trait]
impl MachineAuthenticationStateSource for FixtureState {
    async fn resolve_current(
        &self,
        _: &DelegationGrant,
        _: &DelegationUseRequest,
        now: DateTime<Utc>,
    ) -> Result<ResolvedMachineAuthenticationState, MachineEvidenceError> {
        Ok(ResolvedMachineAuthenticationState {
            binding_record: serde_json::to_vec(&self.0["record"]).unwrap(),
            binding_configuration: serde_json::to_vec(&self.0["configuration"]).unwrap(),
            machine_identity: serde_json::to_vec(&self.0["machine"]).unwrap(),
            machine_authentication_policy: serde_json::to_vec(&self.0["policy"]).unwrap(),
            evidence_ref: "urn:synthetic:machine-state:retained-record:1".into(),
            observed_at: now,
            valid_until: now + Duration::seconds(30),
        })
    }
}

struct Harness {
    now: DateTime<Utc>,
    clock: Arc<Clock>,
    issuer: EphemeralSigner,
    holder: EphemeralSigner,
    inner_header: Value,
    inner_claims: Value,
    outer_header: Value,
    outer_claims: Value,
    documents: Value,
    credential_id: Uuid,
    policy: MachineAuthenticationPolicy,
    qualified: QualifiedMachineBinding,
    grant: DelegationGrant,
    request: DelegationUseRequest,
    challenges: Arc<Challenges>,
    source: Arc<FixtureAuthoritySource>,
    verifier: MartyNestedJwtVcMachineCredentialVerifier,
}

impl Harness {
    fn new(es256: bool) -> Self {
        let now = DateTime::from_timestamp(NOW, 0).unwrap();
        let clock = Arc::new(Clock::new(now));
        let issuer = EphemeralSigner::new(es256);
        let holder = EphemeralSigner::new(es256);
        let mut issuer_public = issuer.public();
        issuer_public["kid"] = json!(KID);
        let holder_public = holder.public();
        let holder_id = format!(
            "did:jwk:{}",
            URL_SAFE_NO_PAD.encode(holder_public.to_string())
        );
        let credential_id = Uuid::new_v4();
        let credential_uri = format!("urn:uuid:{credential_id}");
        let inner_header = json!({"typ":"JWT", "alg":issuer.algorithm().as_str(), "kid":KID});
        let inner_claims = json!({
            "iss":ISSUER, "sub":holder_id, "jti":credential_uri,
            "iat":NOW-30, "nbf":NOW-30, "exp":NOW+3600,
            "vc": {
                "@context":["https://www.w3.org/ns/credentials/v2"],
                "id":credential_uri, "issuer":ISSUER,
                "type":["VerifiableCredential", "MachineCredential", "RuntimeMembership"],
                "credentialSubject":{"id":holder_id},
                "validFrom":(now-Duration::seconds(30)).to_rfc3339(),
                "validUntil":(now+Duration::minutes(10)).to_rfc3339()
            }
        });
        let inner = issuer.sign(&inner_header, &inner_claims);
        let outer_header =
            json!({"typ":"JWT", "alg":holder.algorithm().as_str(), "jwk":holder_public});
        let outer_claims = json!({
            "iss":holder_id, "sub":holder_id, "aud":VERIFIER, "nonce":NONCE,
            "iat":NOW-1, "nbf":NOW-1, "exp":NOW+90,
            "vp":{
                "@context":["https://www.w3.org/ns/credentials/v2"],
                "type":["VerifiablePresentation"], "holder":holder_id,
                "verifiableCredential":[inner]
            }
        });
        let thumbprint =
            jwk_sha256_thumbprint(&serde_json::to_vec(&holder_public).unwrap()).unwrap();
        let thumbprint_hex = thumbprint
            .reencode(ThumbprintEncoding::MipSha256Hex)
            .encoded_value();
        let typed_key = json!({
            "basis":"JWK_RFC7638_SHA256", "encoding":"BASE64URL_SHA256",
            "value":thumbprint.reencode(ThumbprintEncoding::Base64urlSha256).encoded_value()
        });
        let mut grant = pending_grant();
        grant.terms.delegate = Principal {
            principal_type: PrincipalType::MachineIdentity,
            id: holder_id.clone(),
        };
        grant.terms.binding = Binding {
            method: BindingMethod::Key,
            key_thumbprint: Some(thumbprint_hex.clone()),
            session_ref: None,
            establishment_evidence_ref: None,
        };
        grant.terms_digest = grant.calculate_terms_digest().unwrap();
        let request = DelegationUseRequest {
            organization_id: grant.organization_id,
            grant_id: grant.id,
            expected_revision: grant.revision,
            challenge_id: Uuid::new_v4(),
            actor: grant.terms.delegate.clone(),
            action: grant.terms.actions[0].clone(),
            audience: grant.terms.audiences[0].clone(),
            resource: grant.terms.resources[0].clone(),
            operation_profile: "urn:synthetic:machine-operation:v1".into(),
            operation_digest: format!("sha256:{}", "c".repeat(64)),
            proof: holder.sign(&outer_header, &outer_claims).into_bytes(),
        };
        let machine_id = Uuid::new_v4();
        let deployment = Uuid::new_v4();
        let principal = json!({"type":"MACHINE_IDENTITY", "id":holder_id});
        let documents = json!({
            "configuration":{
                "profile":"urn:marty:principal-runtime-binding-configuration:v1",
                "organization_id":grant.organization_id, "deployment_profile_id":deployment,
                "principal":principal, "authentication_source":{"issuer":holder_id, "subject":holder_id},
                "allowed_audiences":[VERIFIER],
                "runtime":{"kind":"MANAGED", "instance_ref":"urn:synthetic:runtime:1", "machine_identity_id":machine_id,
                    "active_key_id":"machine-key", "stored_thumbprint_encoding":"MIP_SHA256_HEX"},
                "expected_key_algorithm":holder.algorithm().as_str(), "expected_key_thumbprint":typed_key,
                "shared_runtime":false
            },
            "record":{
                "profile":"urn:marty:principal-runtime-binding:v1",
                "organization_id":grant.organization_id, "principal":principal,
                "authentication":{"issuer":holder_id, "subject":holder_id, "audience":VERIFIER,
                    "key_algorithm":holder.algorithm().as_str(), "key_thumbprint":typed_key},
                "runtime":{"kind":"MANAGED", "instance_ref":"urn:synthetic:runtime:1", "machine_identity_id":machine_id}
            },
            "machine":{
                "id":machine_id, "organization_id":grant.organization_id, "machine_id":holder_id,
                "display_name":"Synthetic full machine", "machine_type":"SECURE_PROCESSING_RUNTIME", "status":"ACTIVE",
                "identity_keys":[{"key_id":"machine-key", "thumbprint":thumbprint_hex,
                    "algorithm":holder.algorithm().as_str(), "status":"ACTIVE", "public_key_jwk":holder_public,
                    "valid_from":(now-Duration::hours(1)).to_rfc3339(), "valid_until":(now+Duration::hours(1)).to_rfc3339()}],
                "assignments":{"deployment_profile_id":deployment, "operator_organization_id":grant.organization_id},
                "credential_ids":[credential_id], "created_at":(now-Duration::days(1)).to_rfc3339()
            },
            "policy":{
                "id":Uuid::new_v4(), "organization_id":grant.organization_id, "name":"Synthetic selected MAP",
                "trust_profile_id":Uuid::new_v4(), "required_credential_types":["MachineCredential", "RuntimeMembership"],
                "allowed_machine_types":["SECURE_PROCESSING_RUNTIME"],
                "machine_binding":{"binding_methods":["MACHINE_KEY"], "proof_profiles":["OID4VP_VERIFIABLE_PRESENTATION"],
                    "proof_freshness":{"challenge_required":true, "audience_binding_required":true,
                    "replay_detection_required":true, "max_proof_age_seconds":120}},
                "status":"ACTIVE", "created_at":(now-Duration::hours(1)).to_rfc3339()
            }
        });
        let policy = MachineAuthenticationPolicy::from_trusted_document(
            &serde_json::to_vec(&documents["policy"]).unwrap(),
        )
        .unwrap();
        let qualified = qualify(&documents, &policy, grant.organization_id, now);
        let challenges = Arc::new(Challenges(DelegationOid4vpChallenge {
            binding: DelegationFlowContextV1 {
                challenge_id: request.challenge_id,
                organization_id: request.organization_id,
                grant_id: request.grant_id,
                grant_revision: request.expected_revision,
                actor: request.actor.clone(),
                action: request.action.clone(),
                audience: request.audience.clone(),
                resource: request.resource.clone(),
                operation_profile: request.operation_profile.clone(),
                operation_digest: request.operation_digest.clone(),
                session_ref: None,
                establishment_evidence_ref: None,
                session_key_thumbprint: None,
            },
            verifier_client_id: VERIFIER.into(),
            nonce: NONCE.into(),
            expires_at: now + Duration::seconds(90),
        }));
        let source = Arc::new(FixtureAuthoritySource {
            public: issuer_public,
            algorithm: issuer.algorithm(),
            fault: Mutex::new(Fault::None),
            clock: clock.clone(),
            calls: AtomicUsize::new(0),
        });
        let verifier =
            MartyNestedJwtVcMachineCredentialVerifier::with_clock(source.clone(), clock.clone());
        Self {
            now,
            clock,
            issuer,
            holder,
            inner_header,
            inner_claims,
            outer_header,
            outer_claims,
            documents,
            credential_id,
            policy,
            qualified,
            grant,
            request,
            challenges,
            source,
            verifier,
        }
    }

    fn sign_outer(&mut self) {
        self.request.proof = self
            .holder
            .sign(&self.outer_header, &self.outer_claims)
            .into_bytes();
    }

    fn sign_both(&mut self) {
        self.outer_claims["vp"]["verifiableCredential"] =
            json!([self.issuer.sign(&self.inner_header, &self.inner_claims)]);
        self.sign_outer();
    }

    async fn prepared(
        &self,
    ) -> Result<(VerifiedDelegateProof, MachineAuthenticationScope), MachineEvidenceError> {
        let proof = MartyOid4vpDelegateProofVerifier::new(self.challenges.clone(), 120)
            .unwrap()
            .verify(&self.grant, &self.request, self.now)
            .await
            .map_err(|_| MachineEvidenceError)?;
        let scope = MachineAuthenticationScope {
            organization_id: self.request.organization_id,
            machine_identity_id: self.qualified.machine_identity_id(),
            deployment_profile_id: Uuid::parse_str(
                self.qualified.binding().deployment_profile_id(),
            )
            .unwrap(),
            principal: self.request.actor.clone(),
            runtime_instance_ref: self.qualified.binding().runtime_instance_ref().into(),
            key_id: self.qualified.key_id().into(),
            key_thumbprint: self.grant.terms.binding.key_thumbprint.clone().unwrap(),
            policy_id: self.policy.id(),
            policy_digest: self.policy.digest().into(),
            grant_id: self.request.grant_id,
            grant_revision: self.request.expected_revision,
            challenge_id: self.request.challenge_id,
            challenge_digest: format!("sha256:{:x}", Sha256::digest(NONCE)),
            proof_evidence_ref: proof.evidence_ref.clone(),
            action: self.request.action.clone(),
            audience: self.request.audience.clone(),
            resource: self.request.resource.clone(),
            operation_profile: self.request.operation_profile.clone(),
            operation_digest: self.request.operation_digest.clone(),
        };
        Ok((proof, scope))
    }

    async fn verify(&self) -> Result<VerifiedMachineCredentials, MachineEvidenceError> {
        let (proof, scope) = self.prepared().await?;
        self.verifier
            .verify_required(MachineEvidenceRequest {
                scope: &scope,
                policy: &self.policy,
                qualified_binding: &self.qualified,
                operation: &self.request,
                proof: &proof,
                now: self.now,
            })
            .await
    }

    fn full_gate(&self) -> MartyMachineOid4vpProofVerifier {
        MartyMachineOid4vpProofVerifier::with_clock(
            self.challenges.clone(),
            Arc::new(FixtureState(self.documents.clone())),
            Some(Arc::new(self.verifier.clone())),
            None,
            None,
            self.clock.clone(),
        )
    }
}

fn qualify(
    documents: &Value,
    policy: &MachineAuthenticationPolicy,
    org: Uuid,
    now: DateTime<Utc>,
) -> QualifiedMachineBinding {
    qualify_machine_binding(
        org,
        policy,
        &parse_binding_record(&serde_json::to_vec(&documents["record"]).unwrap()).unwrap(),
        &parse_configuration(&serde_json::to_vec(&documents["configuration"]).unwrap()).unwrap(),
        &parse_machine_snapshot(&serde_json::to_vec(&documents["machine"]).unwrap()).unwrap(),
        now,
    )
    .unwrap()
}

#[tokio::test]
async fn actual_ed25519_and_es256_issuer_holder_crypto_close_the_selected_gate() {
    for es256 in [false, true] {
        let h = Harness::new(es256);
        let result = h.verify().await.unwrap();
        assert_eq!(result.credentials.len(), 1);
        assert_eq!(result.credentials[0].credential_id, h.credential_id);
        assert_eq!(result.credentials[0].credential_types.len(), 3);
        assert_eq!(result.credentials[0].evidence_ref, SOURCE_REF);
        assert_eq!(result.valid_until, h.now + Duration::seconds(20));
        assert_eq!(result.trust_profile_id, h.policy.trust_profile_id());
        assert!(result.scope == h.prepared().await.unwrap().1);
        assert_ne!(
            result.scope.audience, VERIFIER,
            "operation and verifier audience stay distinct"
        );
        let gate = h
            .full_gate()
            .verify_machine(&h.grant, &h.request, h.now)
            .await
            .unwrap();
        assert_eq!(gate.valid_until(), h.now + Duration::seconds(20));
        assert_eq!(gate.evidence_refs(), &[SOURCE_REF.to_owned()]);
        assert!(gate.evidence_document()["credentials"].is_object());
        let stored = std::str::from_utf8(gate.evidence_bytes()).unwrap();
        assert!(!stored.contains(std::str::from_utf8(&h.request.proof).unwrap()));
    }
}

#[tokio::test]
async fn issuer_signature_is_required_even_with_a_valid_holder_proof_and_active_source() {
    for es256 in [false, true] {
        let mut h = Harness::new(es256);
        h.outer_claims["vp"]["verifiableCredential"] =
            json!([EphemeralSigner::new(es256).sign(&h.inner_header, &h.inner_claims)]);
        h.sign_outer();
        assert!(h.prepared().await.is_ok(), "holder-only gate succeeds");
        assert!(h.verify().await.is_err(), "issuer signature must fail");
        assert_eq!(h.source.calls.load(Ordering::SeqCst), 1);
        assert!(h
            .full_gate()
            .verify_machine(&h.grant, &h.request, h.now)
            .await
            .is_err());
    }
}

#[tokio::test]
async fn unauthenticated_holder_wrong_nonce_audience_and_current_key_never_resolve_a_source() {
    for field in 0..5 {
        let mut h = Harness::new(false);
        match field {
            0 => h.outer_claims["nonce"] = json!("wrong-source-owned-nonce-0123456789"),
            1 => h.outer_claims["aud"] = json!(h.request.audience),
            2 => {
                h.sign_outer();
                let last = h.request.proof.len() - 4;
                h.request.proof[last] = if h.request.proof[last] == b'A' {
                    b'B'
                } else {
                    b'A'
                };
            }
            3 => {
                let other = EphemeralSigner::new(false);
                h.outer_header["jwk"] = other.public();
                h.request.proof = other.sign(&h.outer_header, &h.outer_claims).into_bytes();
            }
            4 => h.outer_claims["vp"]["holder"] = json!("did:web:another-machine.example"),
            _ => unreachable!(),
        }
        if matches!(field, 0 | 1 | 4) {
            h.sign_outer();
        }
        assert!(h.verify().await.is_err(), "fault {field}");
        assert_eq!(h.source.calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn trusted_source_is_exactly_bound_to_every_scope_and_selection_field() {
    for fault in (0..20)
        .map(Fault::Scope)
        .chain((0..7).map(Fault::Selection))
    {
        let h = Harness::new(false);
        *h.source.fault.lock().unwrap() = fault;
        assert!(h.verify().await.is_err(), "fault {fault:?}");
        assert_eq!(h.source.calls.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn all_nonactive_profile_issuer_key_and_credential_statuses_fail_closed() {
    for field in 0..4 {
        for status in [
            MachineCredentialSourceStatus::Suspended,
            MachineCredentialSourceStatus::Revoked,
            MachineCredentialSourceStatus::Expired,
            MachineCredentialSourceStatus::Unknown,
        ] {
            let h = Harness::new(false);
            *h.source.fault.lock().unwrap() = Fault::State(field, status);
            assert!(
                h.verify().await.is_err(),
                "field {field}, status {status:?}"
            );
        }
    }
}

#[tokio::test]
async fn issuer_authority_requires_matching_public_key_types_revision_digest_and_retained_ref() {
    for fault in [
        Fault::WrongIssuerKey,
        Fault::WrongIssuerIdentity,
        Fault::WrongKeyId,
        Fault::WrongAlgorithm,
        Fault::PrivateKey,
        Fault::DuplicateJwkMember,
        Fault::MissingTypeAuthority,
        Fault::DuplicateTypeAuthority,
        Fault::EmptyTypeAuthority,
        Fault::Revision,
        Fault::ProfileDigest,
        Fault::EvidenceRef,
        Fault::Unavailable,
    ] {
        let h = Harness::new(false);
        *h.source.fault.lock().unwrap() = fault;
        assert!(h.verify().await.is_err(), "fault {fault:?}");
    }
}

#[tokio::test]
async fn credential_identity_types_subject_and_closed_profile_are_authenticated() {
    for field in 0..12 {
        let mut h = Harness::new(false);
        match field {
            0 => {
                h.inner_claims["vc"]["type"] = json!(["VerifiableCredential", "MachineCredential"])
            }
            1 => {
                h.inner_claims["vc"]["type"] = json!([
                    "VerifiableCredential",
                    "MachineCredential",
                    "RuntimeMembership",
                    "RuntimeMembership"
                ])
            }
            2 => {
                let other = format!("urn:uuid:{}", Uuid::new_v4());
                h.inner_claims["jti"] = json!(other);
                h.inner_claims["vc"]["id"] = json!(other);
            }
            3 => {
                h.inner_claims["jti"] = json!(h.credential_id.to_string());
                h.inner_claims["vc"]["id"] = json!(h.credential_id.to_string());
            }
            4 => {
                let alias = format!("urn:uuid:{}", h.credential_id.to_string().to_uppercase());
                h.inner_claims["jti"] = json!(alias);
                h.inner_claims["vc"]["id"] = json!(alias);
            }
            5 => {
                h.inner_claims["sub"] = json!("did:web:other-machine.example");
                h.inner_claims["vc"]["credentialSubject"]["id"] =
                    json!("did:web:other-machine.example");
            }
            6 => h.inner_header["jwk"] = h.issuer.public(),
            7 => {
                h.inner_header.as_object_mut().unwrap().remove("kid");
            }
            8 => h.inner_header["alg"] = json!("none"),
            9 => {
                h.inner_claims["iss"] = json!("did:web:other-issuer.example");
                h.inner_claims["vc"]["issuer"] = json!("did:web:other-issuer.example");
            }
            10 => h.inner_header["kid"] = json!("did:web:machine-issuer.example#other-key"),
            11 => h.inner_header["typ"] = json!("sd-jwt"),
            _ => unreachable!(),
        }
        h.sign_both();
        assert!(h.verify().await.is_err(), "fault {field}");
    }
}

#[tokio::test]
async fn ambiguous_duplicate_and_other_profile_presentations_do_not_fallback() {
    for field in 0..4 {
        let mut h = Harness::new(false);
        match field {
            0 => {
                h.outer_claims["vp"]["verifiableCredential"] = json!([
                    h.outer_claims["vp"]["verifiableCredential"][0].clone(),
                    h.outer_claims["vp"]["verifiableCredential"][0].clone()
                ])
            }
            1 => {
                let duplicate = h.inner_claims.to_string().replacen(
                    '{',
                    &format!("{{\"iss\":\"{ISSUER}\","),
                    1,
                );
                h.outer_claims["vp"]["verifiableCredential"] =
                    json!([h.issuer.sign_raw(&h.inner_header.to_string(), &duplicate)]);
            }
            2 => h.outer_header["typ"] = json!("vp+jwt"),
            3 => {
                h.outer_claims["vp"]["verifiableCredential"] = json!([{
                    "type":["EnvelopedVerifiableCredential"],
                    "id":format!("data:application/vc+jwt,{}", h.outer_claims["vp"]["verifiableCredential"][0].as_str().unwrap())
                }])
            }
            _ => unreachable!(),
        }
        h.sign_outer();
        assert!(h.verify().await.is_err(), "fault {field}");
        assert_eq!(h.source.calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn credential_signature_and_vc_date_intervals_fail_closed() {
    for field in 0..5 {
        let mut h = Harness::new(false);
        match field {
            0 => h.inner_claims["exp"] = json!(NOW),
            1 => h.inner_claims["iat"] = json!(NOW + 31),
            2 => h.inner_claims["nbf"] = json!(NOW + 1),
            3 => h.inner_claims["vc"]["validUntil"] = json!(h.now.to_rfc3339()),
            4 => {
                h.inner_claims["vc"]["validFrom"] =
                    json!((h.now + Duration::seconds(1)).to_rfc3339())
            }
            _ => unreachable!(),
        }
        h.sign_both();
        assert!(h.verify().await.is_err(), "fault {field}");
        assert_eq!(h.source.calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn source_and_completion_clocks_cannot_renew_or_outlive_any_observation() {
    for fault in [
        Fault::Future,
        Fault::Stale,
        Fault::EmptyWindow,
        Fault::Overlong,
        Fault::Advance(-1),
        Fault::Advance(20),
        Fault::Advance(31),
    ] {
        let h = Harness::new(false);
        *h.source.fault.lock().unwrap() = fault;
        assert!(h.verify().await.is_err(), "fault {fault:?}");
    }
    for final_offset in [-1, 20] {
        let h = Harness::new(false);
        *h.clock.change_on_call.lock().unwrap() =
            Some((3, h.now + Duration::seconds(final_offset)));
        assert!(
            h.verify().await.is_err(),
            "clock moved at crypto completion by {final_offset}"
        );
        assert_eq!(h.source.calls.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn earliest_signature_credential_proof_or_registered_key_deadline_is_preserved() {
    for field in 0..4 {
        let mut h = Harness::new(false);
        let until = h.now + Duration::seconds(7);
        match field {
            0 => h.inner_claims["exp"] = json!(until.timestamp()),
            1 => h.inner_claims["vc"]["validUntil"] = json!(until.to_rfc3339()),
            2 => h.outer_claims["exp"] = json!(until.timestamp()),
            3 => {
                h.documents["machine"]["identity_keys"][0]["valid_until"] =
                    json!(until.to_rfc3339());
                h.qualified = qualify(&h.documents, &h.policy, h.grant.organization_id, h.now);
            }
            _ => unreachable!(),
        }
        h.sign_both();
        assert_eq!(
            h.verify().await.unwrap().valid_until,
            until,
            "field {field}"
        );
    }
}

#[tokio::test]
async fn forged_internal_scope_is_rejected_before_the_trusted_source() {
    for field in 0..20 {
        let h = Harness::new(false);
        let (proof, mut scope) = h.prepared().await.unwrap();
        change_scope(&mut scope, field);
        assert!(
            h.verifier
                .verify_required(MachineEvidenceRequest {
                    scope: &scope,
                    policy: &h.policy,
                    qualified_binding: &h.qualified,
                    operation: &h.request,
                    proof: &proof,
                    now: h.now,
                })
                .await
                .is_err(),
            "field {field}"
        );
        assert_eq!(h.source.calls.load(Ordering::SeqCst), 0);
    }
}
