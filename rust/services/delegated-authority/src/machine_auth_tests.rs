use super::*;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use mmf_security::cedar::{CedarConfig, CedarEntityTypes, CedarPolicyEngine};
use serde_json::{json, Value};

use crate::{
    machine_cedar::{
        MachineCedarPolicySource, MmfMachineAuthorizationVerifier, ResolvedMachineCedarPolicy,
    },
    test_support::pending_grant,
    Binding, DelegationFlowContextV1,
};

const CREDENTIAL: &str = "0c53f847-e5f4-4209-916d-eb944a9d7802";

struct Clock(Mutex<DateTime<Utc>>);
impl DelegationClock for Clock {
    fn now(&self) -> DateTime<Utc> {
        *self.0.lock().unwrap()
    }
}
impl Clock {
    fn set(&self, now: DateTime<Utc>) {
        *self.0.lock().unwrap() = now;
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Fault {
    None,
    Error,
    Pending,
    Scope(usize),
    WrongTrust,
    MissingType,
    UnknownCredential,
    DuplicateCredential,
    FutureObservation,
    TooLong,
    Expired,
    Advance(i64),
    BadFormat,
    OldAttestation,
    FutureAttestation,
    WrongPolicyType,
    WrongPolicyId,
    BadRevision,
    BadDigest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stage {
    Credentials,
    Attestation,
    Authorization,
}

struct Providers {
    clock: Arc<Clock>,
    fault: Mutex<(Stage, Fault)>,
    calls: [AtomicUsize; 3],
}

impl Providers {
    fn fault(&self, stage: Stage) -> Fault {
        let configured = *self.fault.lock().unwrap();
        if configured.0 == stage {
            configured.1
        } else {
            Fault::None
        }
    }
    async fn before(
        &self,
        stage: Stage,
        now: DateTime<Utc>,
    ) -> Result<Fault, MachineEvidenceError> {
        let index = match stage {
            Stage::Credentials => 0,
            Stage::Attestation => 1,
            Stage::Authorization => 2,
        };
        self.calls[index].fetch_add(1, Ordering::SeqCst);
        let fault = self.fault(stage);
        match fault {
            Fault::Error => return Err(MachineEvidenceError),
            Fault::Pending => std::future::pending::<()>().await,
            Fault::Advance(seconds) => self.clock.set(now + Duration::seconds(seconds)),
            _ => {}
        }
        Ok(fault)
    }
    fn window(
        &self,
        now: DateTime<Utc>,
        seconds: i64,
        fault: Fault,
    ) -> (DateTime<Utc>, DateTime<Utc>) {
        match fault {
            Fault::FutureObservation => {
                (now + Duration::seconds(1), now + Duration::seconds(seconds))
            }
            Fault::TooLong => (now, now + Duration::seconds(31)),
            Fault::Expired => (now - Duration::seconds(1), now),
            _ => (now, now + Duration::seconds(seconds)),
        }
    }
}

fn corrupt_scope(scope: &MachineAuthenticationScope, fault: Fault) -> MachineAuthenticationScope {
    let mut scope = scope.clone();
    if let Fault::Scope(field) = fault {
        match field {
            0 => scope.organization_id = Uuid::new_v4(),
            1 => scope.machine_identity_id = Uuid::new_v4(),
            2 => scope.deployment_profile_id = Uuid::new_v4(),
            3 => scope.principal.id = "urn:other:machine".into(),
            4 => scope.principal.principal_type = PrincipalType::ServiceAccount,
            5 => scope.runtime_instance_ref = "urn:other:runtime".into(),
            6 => scope.key_id = "other-key".into(),
            7 => scope.key_thumbprint = format!("sha256:{}", "b".repeat(64)),
            8 => scope.policy_id = Uuid::new_v4(),
            9 => scope.policy_digest = format!("sha256:{}", "b".repeat(64)),
            10 => scope.grant_id = Uuid::new_v4(),
            11 => scope.grant_revision += 1,
            12 => scope.challenge_id = Uuid::new_v4(),
            13 => scope.challenge_digest = format!("sha256:{}", "b".repeat(64)),
            14 => scope.proof_evidence_ref = "urn:other:proof".into(),
            15 => scope.action = "urn:other:action".into(),
            16 => scope.audience = "https://other.example/audience".into(),
            17 => scope.resource = "urn:other:resource".into(),
            18 => scope.operation_profile = "urn:other:operation-profile".into(),
            19 => scope.operation_digest = format!("sha256:{}", "b".repeat(64)),
            _ => panic!("invalid field"),
        }
    }
    scope
}

#[async_trait]
impl MachineCredentialVerifier for Providers {
    async fn verify_required(
        &self,
        request: MachineEvidenceRequest<'_>,
    ) -> Result<VerifiedMachineCredentials, MachineEvidenceError> {
        let fault = self.before(Stage::Credentials, request.now).await?;
        let (observed_at, valid_until) = self.window(request.now, 20, fault);
        let credential = || VerifiedMachineCredential {
            credential_id: if fault == Fault::UnknownCredential {
                Uuid::new_v4()
            } else {
                Uuid::parse_str(CREDENTIAL).unwrap()
            },
            credential_types: if fault == Fault::MissingType {
                vec!["UnrelatedCredential".into()]
            } else {
                vec!["MachineCredential".into()]
            },
            evidence_ref: "urn:synthetic:verified-credential:1".into(),
        };
        let mut credentials = vec![credential()];
        if fault == Fault::DuplicateCredential {
            credentials.push(credential());
        }
        Ok(VerifiedMachineCredentials {
            scope: corrupt_scope(request.scope, fault),
            trust_profile_id: if fault == Fault::WrongTrust {
                Uuid::new_v4()
            } else {
                request.policy.trust_profile_id()
            },
            credentials,
            observed_at,
            valid_until,
        })
    }
}

#[async_trait]
impl MachineAttestationVerifier for Providers {
    async fn verify_required(
        &self,
        request: MachineEvidenceRequest<'_>,
    ) -> Result<VerifiedMachineAttestation, MachineEvidenceError> {
        let fault = self.before(Stage::Attestation, request.now).await?;
        let (observed_at, valid_until) = self.window(request.now, 18, fault);
        Ok(VerifiedMachineAttestation {
            scope: corrupt_scope(request.scope, fault),
            verifier_trust_profile_id: if fault == Fault::WrongTrust {
                Uuid::new_v4()
            } else {
                request
                    .policy
                    .required_attestation()
                    .unwrap()
                    .verifier_trust_profile_id()
                    .unwrap()
            },
            format: if fault == Fault::BadFormat {
                "TPM_QUOTE".into()
            } else {
                "EAT".into()
            },
            result_digest: if fault == Fault::BadDigest {
                "unsigned".into()
            } else {
                format!("sha256:{}", "e".repeat(64))
            },
            evidence_ref: "urn:synthetic:verified-attestation:1".into(),
            produced_at: match fault {
                Fault::OldAttestation => request.now - Duration::seconds(61),
                Fault::FutureAttestation => request.now + Duration::seconds(1),
                _ => request.now - Duration::seconds(1),
            },
            observed_at,
            valid_until,
        })
    }
}

#[async_trait]
impl MachineAuthorizationVerifier for Providers {
    async fn verify_permitted(
        &self,
        request: MachineEvidenceRequest<'_>,
    ) -> Result<VerifiedMachineAuthorization, MachineEvidenceError> {
        let fault = self.before(Stage::Authorization, request.now).await?;
        let (observed_at, valid_until) = self.window(request.now, 15, fault);
        Ok(VerifiedMachineAuthorization {
            scope: corrupt_scope(request.scope, fault),
            policy_set_id: if fault == Fault::WrongPolicyId {
                Uuid::new_v4()
            } else {
                request.policy.authorization_policy_set_id().unwrap()
            },
            policy_type: if fault == Fault::WrongPolicyType {
                "ACCESS_CONTROL".into()
            } else {
                "MACHINE_AUTHORIZATION".into()
            },
            revision: if fault == Fault::BadRevision { 0 } else { 3 },
            policy_digest: if fault == Fault::BadDigest {
                "not-a-digest".into()
            } else {
                format!("sha256:{}", "d".repeat(64))
            },
            evidence_ref: "urn:synthetic:machine-authorization:1".into(),
            observed_at,
            valid_until,
        })
    }
}

struct State {
    documents: Mutex<Value>,
    clock: Arc<Clock>,
    advance: Mutex<i64>,
    lifetime: Mutex<i64>,
}

#[async_trait]
impl MachineAuthenticationStateSource for State {
    async fn resolve_current(
        &self,
        _grant: &DelegationGrant,
        _request: &DelegationUseRequest,
        now: DateTime<Utc>,
    ) -> Result<ResolvedMachineAuthenticationState, MachineEvidenceError> {
        self.clock
            .set(now + Duration::seconds(*self.advance.lock().unwrap()));
        let documents = self.documents.lock().unwrap();
        Ok(ResolvedMachineAuthenticationState {
            binding_record: serde_json::to_vec(&documents["record"]).unwrap(),
            binding_configuration: serde_json::to_vec(&documents["configuration"]).unwrap(),
            machine_identity: serde_json::to_vec(&documents["machine_identity"]).unwrap(),
            machine_authentication_policy: serde_json::to_vec(&documents["policy"]).unwrap(),
            evidence_ref: "urn:synthetic:current-machine-source:1".into(),
            observed_at: now,
            valid_until: now + Duration::seconds(*self.lifetime.lock().unwrap()),
        })
    }
}

struct Challenges(Mutex<DelegationOid4vpChallenge>);
#[async_trait]
impl DelegationOid4vpChallengeStore for Challenges {
    async fn load_active(
        &self,
        _organization_id: Uuid,
        _grant_id: Uuid,
        _challenge_id: Uuid,
    ) -> Result<DelegationOid4vpChallenge, DelegationOid4vpChallengeStoreError> {
        Ok(self.0.lock().unwrap().clone())
    }
}

struct Harness {
    grant: DelegationGrant,
    request: DelegationUseRequest,
    verifier: MartyMachineOid4vpProofVerifier,
    state: Arc<State>,
    providers: Arc<Providers>,
    challenges: Arc<Challenges>,
    clock: Arc<Clock>,
    now: DateTime<Utc>,
}

fn vectors() -> Value {
    serde_json::from_str(include_str!(
        "../tests/fixtures/oid4vp-delegate-proofs.json"
    ))
    .unwrap()
}

impl Harness {
    fn new() -> Self {
        let vectors = vectors();
        let now = DateTime::from_timestamp(vectors["evaluated_at"].as_i64().unwrap(), 0).unwrap();
        let clock = Arc::new(Clock(Mutex::new(now)));
        let mut grant = pending_grant();
        grant.terms.delegate.principal_type = PrincipalType::MachineIdentity;
        grant.terms.binding = Binding {
            method: BindingMethod::Key,
            key_thumbprint: Some(vectors["signer_thumbprint"].as_str().unwrap().into()),
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
            operation_profile: "https://commerce.example/profiles/desk-lamp-purchase/v1".into(),
            operation_digest: format!("sha256:{}", "c".repeat(64)),
            proof: vectors["vectors"]["valid"]
                .as_str()
                .unwrap()
                .as_bytes()
                .to_vec(),
        };
        let challenges = Arc::new(Challenges(Mutex::new(DelegationOid4vpChallenge {
            binding: DelegationFlowContextV1 {
                challenge_id: request.challenge_id,
                organization_id: grant.organization_id,
                grant_id: grant.id,
                grant_revision: grant.revision,
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
            verifier_client_id: request.audience.clone(),
            nonce: vectors["nonce"].as_str().unwrap().into(),
            expires_at: now + Duration::seconds(90),
        })));
        let header: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(
                    std::str::from_utf8(&request.proof)
                        .unwrap()
                        .split('.')
                        .next()
                        .unwrap(),
                )
                .unwrap(),
        )
        .unwrap();
        let fingerprint = vectors["signer_thumbprint"].as_str().unwrap();
        let fingerprint_b64 =
            URL_SAFE_NO_PAD.encode(hex::decode(&fingerprint["sha256:".len()..]).unwrap());
        let machine_id = Uuid::new_v4();
        let deployment_id = Uuid::new_v4();
        let policy_id = Uuid::new_v4();
        let trust_id = Uuid::new_v4();
        let principal = json!({"type": "MACHINE_IDENTITY", "id": request.actor.id});
        let typed_key = json!({"basis": "JWK_RFC7638_SHA256", "encoding": "BASE64URL_SHA256", "value": fingerprint_b64});
        let documents = json!({
            "configuration": {
                "profile": "urn:marty:principal-runtime-binding-configuration:v1",
                "organization_id": grant.organization_id,
                "deployment_profile_id": deployment_id,
                "principal": principal,
                "authentication_source": {"issuer": request.actor.id, "subject": request.actor.id},
                "allowed_audiences": [request.audience],
                "runtime": {"kind": "MANAGED", "instance_ref": "urn:synthetic:machine:runtime:1", "machine_identity_id": machine_id, "active_key_id": "current-machine-key", "stored_thumbprint_encoding": "MIP_SHA256_HEX"},
                "expected_key_algorithm": "EdDSA", "expected_key_thumbprint": typed_key,
                "shared_runtime": false
            },
            "record": {
                "profile": "urn:marty:principal-runtime-binding:v1",
                "organization_id": grant.organization_id, "principal": principal,
                "authentication": {"issuer": request.actor.id, "subject": request.actor.id, "audience": request.audience, "key_algorithm": "EdDSA", "key_thumbprint": typed_key},
                "runtime": {"kind": "MANAGED", "instance_ref": "urn:synthetic:machine:runtime:1", "machine_identity_id": machine_id}
            },
            "machine_identity": {
                "id": machine_id, "organization_id": grant.organization_id,
                "machine_id": request.actor.id, "display_name": "Synthetic full machine",
                "machine_type": "SECURE_PROCESSING_RUNTIME", "status": "ACTIVE",
                "identity_keys": [{"key_id": "current-machine-key", "thumbprint": fingerprint,
                    "algorithm": "EdDSA", "status": "ACTIVE", "public_key_jwk": header["jwk"],
                    "valid_from": (now - Duration::hours(1)).to_rfc3339(), "valid_until": (now + Duration::hours(1)).to_rfc3339()}],
                "assignments": {"deployment_profile_id": deployment_id, "operator_organization_id": grant.organization_id},
                "credential_ids": [CREDENTIAL], "created_at": (now - Duration::days(1)).to_rfc3339()
            },
            "policy": {
                "id": policy_id, "organization_id": grant.organization_id,
                "name": "Synthetic selected full MAP", "trust_profile_id": trust_id,
                "required_credential_types": ["MachineCredential"],
                "allowed_machine_types": ["SECURE_PROCESSING_RUNTIME"],
                "machine_binding": {
                    "binding_methods": ["MACHINE_KEY"], "proof_profiles": ["OID4VP_VERIFIABLE_PRESENTATION"],
                    "proof_freshness": {"challenge_required": true, "audience_binding_required": true, "replay_detection_required": true, "max_proof_age_seconds": 120}
                },
                "attestation_requirement": {
                    "required": true, "accepted_formats": ["EAT"], "verifier_trust_profile_id": Uuid::new_v4(),
                    "max_age_seconds": 60, "challenge_required": true, "identity_key_binding_required": true
                },
                "authorization_policy_set_id": Uuid::new_v4(), "status": "ACTIVE",
                "created_at": (now - Duration::hours(1)).to_rfc3339()
            }
        });
        let state = Arc::new(State {
            documents: Mutex::new(documents),
            clock: clock.clone(),
            advance: Mutex::new(0),
            lifetime: Mutex::new(30),
        });
        let providers = Arc::new(Providers {
            clock: clock.clone(),
            fault: Mutex::new((Stage::Credentials, Fault::None)),
            calls: [
                AtomicUsize::new(0),
                AtomicUsize::new(0),
                AtomicUsize::new(0),
            ],
        });
        let verifier = MartyMachineOid4vpProofVerifier::with_clock(
            challenges.clone(),
            state.clone(),
            Some(providers.clone()),
            Some(providers.clone()),
            Some(providers.clone()),
            clock.clone(),
        );
        Self {
            grant,
            request,
            verifier,
            state,
            providers,
            challenges,
            clock,
            now,
        }
    }
    async fn verify(&self) -> Result<AuthenticatedMachineProof, MachineEvidenceError> {
        self.verifier
            .verify_machine(&self.grant, &self.request, self.now)
            .await
    }
}

#[tokio::test]
async fn actual_core_crypto_and_all_selected_requirements_produce_bounded_opaque_output() {
    let h = Harness::new();
    let verified = h.verify().await.unwrap();
    assert_eq!(verified.scope().principal, h.request.actor);
    assert_eq!(verified.scope().challenge_id, h.request.challenge_id);
    assert_eq!(
        verified.scope().operation_digest,
        h.request.operation_digest
    );
    assert_eq!(verified.valid_until(), h.now + Duration::seconds(15));
    assert_eq!(verified.evidence_refs().len(), 3);
    assert!(verified
        .source_evidence_ref()
        .contains("current-machine-source"));
    assert!(verified.ensure_current(h.now).is_ok());
    assert!(verified
        .ensure_current(h.now - Duration::nanoseconds(1))
        .is_err());
    assert!(verified.ensure_current(verified.valid_until()).is_err());
    assert_eq!(
        format!("{verified:?}"),
        "AuthenticatedMachineProof { <private> }"
    );
    assert_eq!(
        h.providers
            .calls
            .each_ref()
            .map(|value| value.load(Ordering::SeqCst)),
        [1, 1, 1]
    );
    let proof = verified.into_delegate_proof();
    assert!(proof
        .evidence_ref
        .starts_with("urn:marty:machine-authentication:sha256:"));
    assert_eq!(proof.challenge, vectors()["nonce"].as_str().unwrap());
    assert!(h.verifier.verify(&h.grant, &h.request, h.now).await.is_ok());
}

#[tokio::test]
async fn generic_proof_reference_retains_the_complete_map_qualification_digest() {
    let h = Harness::new();
    let verified = h.verify().await.unwrap();
    let document = verified.evidence_document().clone();
    assert_eq!(document["profile"], MACHINE_AUTHENTICATION_EVIDENCE_PROFILE);
    assert_eq!(
        document["scope"]["operation_digest"],
        h.request.operation_digest
    );
    assert_eq!(
        document["scope"]["proof_evidence_ref"],
        document["proof"]["evidence_ref"]
    );
    assert!(document["proof"]["evidence_ref"]
        .as_str()
        .unwrap()
        .starts_with("urn:marty:oid4vp-proof:"));
    assert_eq!(
        document["credentials"]["credentials"][0]["credential_id"],
        CREDENTIAL
    );
    assert_eq!(document["attestation"]["format"], "EAT");
    assert_eq!(
        document["machine_authorization"]["policy_type"],
        "MACHINE_AUTHORIZATION"
    );
    assert_eq!(document["machine_authorization"]["revision"], 3);
    assert_eq!(
        serde_json::from_slice::<Value>(verified.evidence_bytes()).unwrap(),
        document
    );
    let expected = format!(
        "urn:marty:machine-authentication:sha256:{:x}",
        Sha256::digest(verified.evidence_bytes())
    );
    assert_eq!(verified.into_delegate_proof().evidence_ref, expected);
    assert_eq!(
        h.verify().await.unwrap().into_delegate_proof().evidence_ref,
        expected
    );
    h.state.documents.lock().unwrap()["policy"]["name"] =
        json!("A separately selected policy snapshot");
    let changed = h.verify().await.unwrap();
    assert_eq!(changed.evidence_document()["proof"], document["proof"]);
    assert_ne!(changed.into_delegate_proof().evidence_ref, expected);
}

#[tokio::test]
async fn bad_actual_signatures_nonce_holder_key_and_enrollment_proofs_never_reach_evidence_providers(
) {
    for (name, token) in vectors()["vectors"].as_object().unwrap() {
        if name.starts_with("valid") {
            continue;
        }
        let mut h = Harness::new();
        h.request.proof = token.as_str().unwrap().as_bytes().to_vec();
        assert!(h.verify().await.is_err(), "accepted {name}");
        assert_eq!(h.providers.calls[0].load(Ordering::SeqCst), 0);
    }
    let enrollment: Value = serde_json::from_str(include_str!(
        "../../../crates/principal-runtime-binding/tests/fixtures/node-managed-enrollment.json"
    ))
    .unwrap();
    for vector in enrollment["vectors"].as_array().unwrap() {
        let mut h = Harness::new();
        h.request.proof = vector["proof"].as_str().unwrap().as_bytes().to_vec();
        assert!(h.verify().await.is_err());
        assert_eq!(h.providers.calls[0].load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn each_selected_provider_is_mandatory_and_provider_failure_is_not_a_permit() {
    for index in 0..3 {
        let mut h = Harness::new();
        match index {
            0 => h.verifier.credentials = None,
            1 => h.verifier.attestation = None,
            _ => h.verifier.authorization = None,
        }
        assert!(h.verify().await.is_err());
    }
    for stage in [Stage::Credentials, Stage::Attestation, Stage::Authorization] {
        let h = Harness::new();
        *h.providers.fault.lock().unwrap() = (stage, Fault::Error);
        assert!(h.verify().await.is_err());
    }
    let mut h = Harness::new();
    {
        let mut documents = h.state.documents.lock().unwrap();
        documents["policy"]
            .as_object_mut()
            .unwrap()
            .remove("attestation_requirement");
        documents["policy"]
            .as_object_mut()
            .unwrap()
            .remove("authorization_policy_set_id");
    }
    h.verifier.attestation = None;
    h.verifier.authorization = None;
    let verified = h.verify().await.unwrap();
    assert_eq!(verified.valid_until(), h.now + Duration::seconds(20));
    assert_eq!(verified.evidence_refs().len(), 1);
}

#[tokio::test]
async fn credential_results_bind_every_identity_runtime_policy_and_operation_dimension() {
    for field in 0..20 {
        let h = Harness::new();
        *h.providers.fault.lock().unwrap() = (Stage::Credentials, Fault::Scope(field));
        assert!(h.verify().await.is_err(), "accepted scope field {field}");
        assert_eq!(h.providers.calls[1].load(Ordering::SeqCst), 0);
    }
    for stage in [Stage::Attestation, Stage::Authorization] {
        let h = Harness::new();
        *h.providers.fault.lock().unwrap() = (stage, Fault::Scope(13));
        assert!(h.verify().await.is_err());
    }
}

#[tokio::test]
async fn credential_type_registration_trust_and_duplicates_are_enforced() {
    for fault in [
        Fault::WrongTrust,
        Fault::MissingType,
        Fault::UnknownCredential,
        Fault::DuplicateCredential,
    ] {
        let h = Harness::new();
        *h.providers.fault.lock().unwrap() = (Stage::Credentials, fault);
        assert!(h.verify().await.is_err(), "accepted {fault:?}");
    }
    let h = Harness::new();
    h.state.documents.lock().unwrap()["policy"]["required_credential_types"] =
        json!(["MachineCredential", "AdditionalMachineCredential"]);
    assert!(h.verify().await.is_err());
}

#[tokio::test]
async fn required_attestation_and_machine_authorization_are_exact_not_generic_success_flags() {
    for fault in [
        Fault::WrongTrust,
        Fault::BadFormat,
        Fault::OldAttestation,
        Fault::FutureAttestation,
        Fault::BadDigest,
    ] {
        let h = Harness::new();
        *h.providers.fault.lock().unwrap() = (Stage::Attestation, fault);
        assert!(h.verify().await.is_err(), "accepted attestation {fault:?}");
    }
    for fault in [
        Fault::WrongPolicyType,
        Fault::WrongPolicyId,
        Fault::BadRevision,
        Fault::BadDigest,
    ] {
        let h = Harness::new();
        *h.providers.fault.lock().unwrap() = (Stage::Authorization, fault);
        assert!(
            h.verify().await.is_err(),
            "accepted authorization {fault:?}"
        );
    }
}

#[tokio::test]
async fn all_source_and_provider_deadlines_are_current_bounded_and_nonextending() {
    for stage in [Stage::Credentials, Stage::Attestation, Stage::Authorization] {
        for fault in [
            Fault::FutureObservation,
            Fault::TooLong,
            Fault::Expired,
            Fault::Advance(31),
            Fault::Advance(-1),
        ] {
            let h = Harness::new();
            *h.providers.fault.lock().unwrap() = (stage, fault);
            assert!(h.verify().await.is_err(), "accepted {stage:?} {fault:?}");
        }
    }
    for seconds in [-1, 0, 31] {
        let h = Harness::new();
        *h.state.lifetime.lock().unwrap() = seconds;
        assert!(h.verify().await.is_err());
    }
    for advance in [-1, 30] {
        let h = Harness::new();
        *h.state.advance.lock().unwrap() = advance;
        assert!(h.verify().await.is_err());
    }
    let h = Harness::new();
    *h.state.lifetime.lock().unwrap() = 5;
    *h.providers.fault.lock().unwrap() = (Stage::Credentials, Fault::Advance(1));
    assert_eq!(
        h.verify().await.unwrap().valid_until(),
        h.now + Duration::seconds(5)
    );
    let h = Harness::new();
    *h.state.lifetime.lock().unwrap() = 5;
    *h.providers.fault.lock().unwrap() = (Stage::Authorization, Fault::Advance(5));
    assert!(h.verify().await.is_err());
}

#[tokio::test]
async fn real_machine_current_key_source_identity_and_audience_are_required() {
    let mutations: &[fn(&mut Value)] = &[
        |d| {
            for target in ["configuration", "record"] {
                d[target]["principal"]["type"] = json!("SERVICE_ACCOUNT");
            }
        },
        |d| d["machine_identity"]["status"] = json!("SUSPENDED"),
        |d| {
            d["machine_identity"]["identity_keys"][0]["valid_until"] = json!("2026-11-17T17:00:01Z")
        },
        |d| {
            d["configuration"]["authentication_source"]["issuer"] =
                json!("https://different.example")
        },
        |d| {
            d["configuration"]["authentication_source"]["issuer"] =
                json!("https://different.example");
            d["record"]["authentication"]["issuer"] = json!("https://different.example");
        },
        |d| {
            d["configuration"]["authentication_source"]["subject"] = json!("different-subject");
            d["record"]["authentication"]["subject"] = json!("different-subject");
        },
        |d| {
            d["configuration"]["allowed_audiences"] = json!(["https://other.example"]);
            d["record"]["authentication"]["audience"] = json!("https://other.example");
        },
        |d| d["policy"]["status"] = json!("DRAFT"),
        |d| d["policy"]["machine_binding"]["proof_profiles"] = json!(["SIGNED_CHALLENGE"]),
        |d| d["machine_identity"]["credential_ids"] = json!([]),
    ];
    for (index, mutation) in mutations.iter().enumerate() {
        let h = Harness::new();
        mutation(&mut h.state.documents.lock().unwrap());
        assert!(h.verify().await.is_err(), "accepted mutation {index}");
        assert_eq!(h.providers.calls[0].load(Ordering::SeqCst), 0);
    }
    let mut h = Harness::new();
    h.request.actor.principal_type = PrincipalType::ServiceAccount;
    h.grant.terms.delegate = h.request.actor.clone();
    assert!(h.verify().await.is_err());
}

#[tokio::test]
async fn proof_verifier_audience_remains_distinct_from_relying_operation_audience() {
    let mut h = Harness::new();
    h.request.audience = "https://relying-service.example".into();
    h.grant.terms.audiences = vec![h.request.audience.clone()];
    h.grant.terms_digest = h.grant.calculate_terms_digest().unwrap();
    h.challenges.0.lock().unwrap().binding.audience = h.request.audience.clone();
    // Existing signed proof and private source retain https://merchant.example
    // as the OID4VP verifier. The new relying audience is independently bound.
    let result = h.verify().await.unwrap();
    assert_eq!(result.scope().audience, h.request.audience);
}

#[tokio::test]
async fn pending_providers_are_bounded_without_consuming_the_challenge() {
    for stage in [Stage::Credentials, Stage::Attestation, Stage::Authorization] {
        let mut h = Harness::new();
        h.verifier.timeout = std::time::Duration::from_millis(25);
        *h.providers.fault.lock().unwrap() = (stage, Fault::Pending);
        assert!(h.verify().await.is_err());
        *h.providers.fault.lock().unwrap() = (stage, Fault::None);
        assert!(h.verify().await.is_ok());
    }
}

const MACHINE_SCHEMA: &str = r#"
namespace Machine {
  entity Identity { status: String };
  entity State {};
  action "urn:marty:machine:authenticate" appliesTo {
    principal: [Identity], resource: [State],
    context: {
      organization_id: String, machine_identity_id: String, deployment_profile_id: String,
      runtime_instance_ref: String, key_id: String, key_thumbprint: String,
      machine_authentication_policy_id: String, machine_authentication_policy_digest: String,
      grant_id: String, grant_revision: Long, challenge_id: String, challenge_digest: String,
      proof_evidence_ref: String, requested_action: String, requested_audience: String,
      requested_resource: String, operation_profile: String, operation_digest: String
    }
  };
}
"#;

struct CedarSource {
    clock: Arc<Clock>,
    deny: bool,
    fault: usize,
}

#[async_trait]
impl MachineCedarPolicySource for CedarSource {
    async fn resolve_current(
        &self,
        scope: &MachineAuthenticationScope,
        policy_set_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<ResolvedMachineCedarPolicy, MachineEvidenceError> {
        let types = CedarEntityTypes {
            principal: "Machine::Identity".into(),
            action: "Machine::Action".into(),
            resource: "Machine::State".into(),
        };
        let mut policy = format!(
            r#"
permit (
  principal is Machine::Identity,
  action == Machine::Action::"urn:marty:machine:authenticate",
  resource is Machine::State
)
when {{
  principal.status == "ACTIVE"
  && context.organization_id == "{}"
  && context.key_thumbprint == "{}"
  && context.operation_digest == "{}"
}};"#,
            scope.organization_id, scope.key_thumbprint, scope.operation_digest
        );
        if self.deny {
            policy.push_str("forbid (principal, action, resource);");
        }
        let engine = CedarPolicyEngine::from_human_schema(
            &policy,
            MACHINE_SCHEMA,
            CedarConfig {
                entity_types: types.clone(),
                ..CedarConfig::default()
            },
        )
        .unwrap();
        let mut result = ResolvedMachineCedarPolicy {
            scope: scope.clone(),
            policy_set_id,
            policy_type: "MACHINE_AUTHORIZATION".into(),
            status: "ACTIVE".into(),
            revision: 7,
            policy_digest: format!("sha256:{}", "f".repeat(64)),
            observed_at: now,
            valid_until: now + Duration::seconds(12),
            entity_types: types,
            entities: json!([
                {"uid":{"type":"Machine::Identity","id":scope.principal.id},"attrs":{"status":"ACTIVE"},"parents":[]},
                {"uid":{"type":"Machine::State","id":scope.machine_identity_id.to_string()},"attrs":{},"parents":[]}
            ]),
            engine: Arc::new(engine),
        };
        match self.fault {
            0 => {}
            1 => result.scope.organization_id = Uuid::new_v4(),
            2 => result.policy_set_id = Uuid::new_v4(),
            3 => result.policy_type = "ACCESS_CONTROL".into(),
            4 => result.status = "DRAFT".into(),
            5 => result.revision = 0,
            6 => result.policy_digest = "unsigned".into(),
            7 => result.observed_at = now + Duration::seconds(1),
            8 => result.valid_until = now,
            9 => result.valid_until = now + Duration::seconds(31),
            10 => result.entities[0]["attrs"]["status"] = json!("SUSPENDED"),
            11 => result.entities[0]["attrs"]["unexpected"] = json!(true),
            12 => self.clock.set(now + Duration::seconds(12)),
            13 => self.clock.set(now - Duration::seconds(1)),
            _ => panic!("invalid fault"),
        }
        Ok(result)
    }
}

#[tokio::test]
async fn concrete_mmf_cedar_machine_policy_is_separate_and_deny_by_default() {
    let mut h = Harness::new();
    h.verifier.authorization = Some(Arc::new(MmfMachineAuthorizationVerifier::with_clock(
        Arc::new(CedarSource {
            clock: h.clock.clone(),
            deny: false,
            fault: 0,
        }),
        h.clock.clone(),
    )));
    let proof = h.verify().await.unwrap();
    assert_eq!(proof.valid_until(), h.now + Duration::seconds(12));
    assert!(proof
        .evidence_refs()
        .last()
        .unwrap()
        .starts_with("urn:marty:machine-authorization:sha256:"));
    h.verifier.authorization = Some(Arc::new(MmfMachineAuthorizationVerifier::with_clock(
        Arc::new(CedarSource {
            clock: h.clock.clone(),
            deny: true,
            fault: 0,
        }),
        h.clock.clone(),
    )));
    assert!(h.verify().await.is_err());
}

#[tokio::test]
async fn concrete_cedar_rejects_wrong_policy_source_schema_and_clock_state() {
    for fault in 1..=13 {
        let mut h = Harness::new();
        h.verifier.authorization = Some(Arc::new(MmfMachineAuthorizationVerifier::with_clock(
            Arc::new(CedarSource {
                clock: h.clock.clone(),
                deny: false,
                fault,
            }),
            h.clock.clone(),
        )));
        assert!(h.verify().await.is_err(), "accepted Cedar fault {fault}");
    }
}

#[path = "machine_evidence_tests.rs"]
mod evidence_tests;
