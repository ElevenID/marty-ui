//! Application-authored, synthetic crypto vectors. These exercise an offline
//! consumer, not live custody, protocol certification, or public integration.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Duration, SecondsFormat, TimeZone, Utc};
use ed25519_dalek::Signer as _;
use marty_delegated_receipt_consumer::*;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const ORG: &str = "33333333-3333-4333-8333-333333333333";
const GRANT: &str = "11111111-1111-4111-8111-111111111111";
const RECEIPT: &str = "22222222-2222-4222-8222-222222222222";
const ISSUER: &str = "did:web:receipt.example.test";
const KID: &str = "did:web:receipt.example.test#receipt-key-1";
const NONCE: &str = "independent_challenge_nonce_0123456789";

fn at() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 11, 22, 0, 0, 0)
        .single()
        .unwrap()
}
fn stamp(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Nanos, true)
}
fn digest(seed: char) -> String {
    format!("sha256:{}", seed.to_string().repeat(64))
}
fn principal(kind: PrincipalType, id: &str) -> Principal {
    Principal {
        principal_type: kind,
        id: id.into(),
    }
}
fn issuer() -> Principal {
    principal(PrincipalType::Organization, ISSUER)
}
fn grant() -> GrantReference {
    GrantReference {
        id: Uuid::parse_str(GRANT).unwrap(),
        revision: 3,
        terms_digest: digest('a'),
    }
}
fn operation() -> Operation {
    Operation {
        action: "urn:example:order:create".into(),
        resource_id: "urn:example:product:42".into(),
        audience: "https://merchant.example.test/api".into(),
        request_profile: "urn:example:order:v1".into(),
        request_digest: digest('b'),
    }
}
fn context() -> ReceiptContext {
    ReceiptContext {
        organization_id: Uuid::parse_str(ORG).unwrap(),
        grant: grant(),
        actor: principal(PrincipalType::MachineIdentity, "urn:example:machine:7"),
        subject: principal(PrincipalType::Organization, "urn:example:represented-org"),
        binding: Binding::Key {
            key_thumbprint: digest('c'),
        },
        operation: operation(),
        challenge: NONCE.into(),
        status_issuer: principal(PrincipalType::Organization, "urn:example:authority"),
        status_state: StatusState::Active,
        policy: PolicyExpectation {
            id: "urn:example:delegation-policy:9".into(),
            version_digest: None,
        },
        domain_evidence: None,
        context_created_at: at() - Duration::seconds(5),
        context_expires_at: at() + Duration::seconds(60),
    }
}
fn retained(compact: &[u8], decision: Decision) -> RetainedReceiptBinding {
    RetainedReceiptBinding {
        receipt_ref: format!("{RECEIPT_REFERENCE_PREFIX}{RECEIPT}"),
        receipt_digest: format!("sha256:{:x}", Sha256::digest(compact)),
        decision,
        recorded_at: at() + Duration::seconds(1),
        authorization_expires_at: at() + Duration::seconds(20),
    }
}
fn expected(compact: &[u8], decision: Decision) -> ReceiptExpectation {
    ReceiptExpectation::new(context(), retained(compact, decision)).unwrap()
}
fn freshness() -> FreshnessPolicy {
    FreshnessPolicy::new(30, 30).unwrap()
}
fn payload(decision: Decision) -> Value {
    let c = context();
    json!({"profile":RECEIPT_PROFILE,"id":RECEIPT,"issuer":issuer(),"decision":decision,
      "evaluation":{"profile":EVALUATION_PROFILE,"organization_id":ORG,"grant":c.grant,
        "actor":c.actor,"subject":c.subject,"binding":c.binding,"operation":c.operation,
        "approval_evidence_ref":"urn:example:approval:generated","authority_evidence_ref":"urn:example:authority:generated",
        "proof_evidence_ref":"urn:example:proof:generated","challenge":NONCE,
        "proof_verified_at":stamp(at()-Duration::seconds(1)),"proof_valid_until":stamp(at()+Duration::seconds(40)),
        "status":{"issuer":c.status_issuer,"grant":grant(),"state":"ACTIVE","checked_at":stamp(at()-Duration::seconds(2)),
          "valid_until":stamp(at()+Duration::seconds(35)),"evidence_ref":"urn:example:status:generated"},"evaluated_at":stamp(at())},
      "policy":{"id":c.policy.id,"version_digest":digest('d')},"issued_at":stamp(at()),"expires_at":stamp(at()+Duration::seconds(20))})
}
fn header(algorithm: Algorithm) -> Value {
    json!({"alg":algorithm.as_str(),"kid":KID,"typ":RECEIPT_JWS_TYPE})
}

enum Key {
    Es(SigningKey),
    Ed(ed25519_dalek::SigningKey),
}
impl Key {
    fn new(algorithm: Algorithm, seed: u8) -> Self {
        match algorithm {
            Algorithm::Es256 => Self::Es(SigningKey::from_slice(&[seed; 32]).unwrap()),
            Algorithm::EdDsa => Self::Ed(ed25519_dalek::SigningKey::from_bytes(&[seed; 32])),
        }
    }
    fn jwk(&self) -> Value {
        match self {
            Self::Es(key) => {
                let p = key.verifying_key().to_sec1_point(false);
                json!({"kty":"EC","crv":"P-256","x":URL_SAFE_NO_PAD.encode(p.x().unwrap()),"y":URL_SAFE_NO_PAD.encode(p.y().unwrap())})
            }
            Self::Ed(key) => {
                json!({"kty":"OKP","crv":"Ed25519","x":URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes())})
            }
        }
    }
    fn signature(&self, input: &[u8]) -> Vec<u8> {
        match self {
            Self::Es(key) => {
                let signature: Signature = key.sign(input);
                signature.to_bytes().to_vec()
            }
            Self::Ed(key) => key.sign(input).to_bytes().to_vec(),
        }
    }
    fn sign_raw(&self, protected: &[u8], body: &[u8]) -> Vec<u8> {
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(protected),
            URL_SAFE_NO_PAD.encode(body)
        );
        format!(
            "{input}.{}",
            URL_SAFE_NO_PAD.encode(self.signature(input.as_bytes()))
        )
        .into_bytes()
    }
    fn sign(&self, algorithm: Algorithm, body: &Value) -> Vec<u8> {
        self.sign_raw(
            &serde_json::to_vec(&header(algorithm)).unwrap(),
            &serde_json::to_vec(body).unwrap(),
        )
    }
    fn pin(&self, algorithm: Algorithm) -> PinnedReceiptKey {
        PinnedReceiptKey::new(
            Uuid::parse_str(ORG).unwrap(),
            issuer(),
            algorithm,
            KID.into(),
            &serde_json::to_vec(&self.jwk()).unwrap(),
        )
        .unwrap()
    }
}
fn fresh(
    compact: &[u8],
    key: &Key,
    algorithm: Algorithm,
    expectation: &ReceiptExpectation,
) -> Result<FreshReceiptEvidence, ReceiptVerificationError> {
    verify_fresh(
        compact,
        &key.pin(algorithm),
        expectation,
        at() + Duration::seconds(2),
        freshness(),
    )
}

#[test]
fn both_algorithms_verify_independent_context_and_attested_claims() {
    for algorithm in [Algorithm::Es256, Algorithm::EdDsa] {
        let key = Key::new(algorithm, 7);
        let compact = key.sign(algorithm, &payload(Decision::Permit));
        let expectation = expected(&compact, Decision::Permit);
        let checked = fresh(&compact, &key, algorithm, &expectation).unwrap();
        assert_eq!(checked.decision(), Decision::Permit);
        assert_eq!(checked.semantics(), "EVIDENCE_ONLY");
        assert_eq!(checked.context(), &context());
        assert_eq!(
            checked.receipt_digest(),
            retained(&compact, Decision::Permit).receipt_digest
        );
        assert_eq!(
            checked.evidence_references().proof,
            "urn:example:proof:generated"
        );
        assert_eq!(checked.policy().version_digest, digest('d'));
        let history = verify_historical(
            &compact,
            &key.pin(algorithm),
            &expectation,
            at() + Duration::days(365),
        )
        .unwrap();
        assert_eq!(history.expires_at(), checked.expires_at());
        assert_eq!(history.recorded_at(), checked.recorded_at());
        assert_eq!(history.receipt_digest(), checked.receipt_digest());
        assert_eq!(history.decision(), Decision::Permit);
    }
}

#[test]
fn signed_denial_is_history_and_cannot_be_fresh_evidence() {
    for algorithm in [Algorithm::Es256, Algorithm::EdDsa] {
        let key = Key::new(algorithm, 9);
        let compact = key.sign(algorithm, &payload(Decision::Deny));
        let expectation = expected(&compact, Decision::Deny);
        assert_eq!(
            fresh(&compact, &key, algorithm, &expectation).unwrap_err(),
            ReceiptVerificationError::DecisionDenied
        );
        let history = verify_historical(
            &compact,
            &key.pin(algorithm),
            &expectation,
            at() + Duration::days(7),
        )
        .unwrap();
        assert_eq!(history.decision(), Decision::Deny);
        assert_eq!(history.expires_at(), at() + Duration::seconds(20));
    }
}

#[test]
fn expiration_is_exclusive_and_recovery_never_renews_the_original_window() {
    let a = Algorithm::Es256;
    let key = Key::new(a, 7);
    let compact = key.sign(a, &payload(Decision::Permit));
    let expectation = expected(&compact, Decision::Permit);
    let expires = at() + Duration::seconds(20);
    assert!(verify_fresh(
        &compact,
        &key.pin(a),
        &expectation,
        expires - Duration::nanoseconds(1),
        freshness()
    )
    .is_ok());
    assert_eq!(
        verify_fresh(&compact, &key.pin(a), &expectation, expires, freshness()).unwrap_err(),
        ReceiptVerificationError::Expired
    );
    assert_eq!(
        verify_fresh(
            &compact,
            &key.pin(a),
            &expectation,
            at() - Duration::nanoseconds(1),
            freshness()
        )
        .unwrap_err(),
        ReceiptVerificationError::NotYetIssued
    );
    assert_eq!(
        verify_historical(&compact, &key.pin(a), &expectation, at()).unwrap_err(),
        ReceiptVerificationError::NotYetIssued
    );
    assert_eq!(
        verify_historical(
            &compact,
            &key.pin(a),
            &expectation,
            expires + Duration::days(10)
        )
        .unwrap()
        .expires_at(),
        expires
    );
    let mut changed = payload(Decision::Permit);
    changed["expires_at"] = json!(stamp(expires + Duration::seconds(5)));
    let changed = key.sign(a, &changed);
    assert_eq!(
        verify_historical(
            &changed,
            &key.pin(a),
            &expectation,
            expires + Duration::days(10)
        )
        .unwrap_err(),
        ReceiptVerificationError::RetentionMismatch
    );
}

#[test]
fn exact_compact_digest_is_checked_without_json_reserialization() {
    let a = Algorithm::Es256;
    let key = Key::new(a, 7);
    let body = payload(Decision::Permit);
    let compact = key.sign(a, &body);
    let expectation = expected(&compact, Decision::Permit);
    let pretty = key.sign_raw(
        &serde_json::to_vec_pretty(&header(a)).unwrap(),
        &serde_json::to_vec_pretty(&body).unwrap(),
    );
    assert_ne!(pretty, compact);
    assert_eq!(
        fresh(&pretty, &key, a, &expectation).unwrap_err(),
        ReceiptVerificationError::RetentionMismatch
    );
    assert!(fresh(&pretty, &key, a, &expected(&pretty, Decision::Permit)).is_ok());
}

#[test]
fn signature_and_protected_identity_are_independent_of_receipt_claims() {
    for a in [Algorithm::Es256, Algorithm::EdDsa] {
        let key = Key::new(a, 7);
        let other = Key::new(a, 8);
        let compact = key.sign(a, &payload(Decision::Permit));
        assert_eq!(
            fresh(&compact, &other, a, &expected(&compact, Decision::Permit)).unwrap_err(),
            ReceiptVerificationError::InvalidSignature
        );
        for (field, value) in [
            ("alg", json!("none")),
            ("alg", json!("HS256")),
            ("kid", json!("did:web:attacker.test#key")),
            ("typ", json!("JWT")),
            ("crit", json!("unknown")),
            ("jwk", key.jwk()),
            ("jku", json!("https://attacker.test/keys")),
            ("b64", json!("false")),
        ] {
            let mut h = header(a);
            h[field] = value;
            let changed = key.sign_raw(
                &serde_json::to_vec(&h).unwrap(),
                &serde_json::to_vec(&payload(Decision::Permit)).unwrap(),
            );
            assert!(
                fresh(&changed, &key, a, &expected(&changed, Decision::Permit)).is_err(),
                "accepted header field {field}"
            );
        }
        let mut parts = String::from_utf8(compact.clone())
            .unwrap()
            .split('.')
            .map(str::to_string)
            .collect::<Vec<_>>();
        let mut signature = URL_SAFE_NO_PAD.decode(&parts[2]).unwrap();
        signature[10] ^= 1;
        parts[2] = URL_SAFE_NO_PAD.encode(signature);
        let changed = parts.join(".").into_bytes();
        assert_eq!(
            fresh(&changed, &key, a, &expected(&changed, Decision::Permit)).unwrap_err(),
            ReceiptVerificationError::InvalidSignature
        );
    }
}

#[test]
fn every_independently_known_context_component_is_exact() {
    let a = Algorithm::Es256;
    let key = Key::new(a, 7);
    let compact = key.sign(a, &payload(Decision::Permit));
    let mutations: Vec<Box<dyn Fn(&mut ReceiptContext)>> = vec![
        Box::new(|c| c.organization_id = Uuid::new_v4()),
        Box::new(|c| c.grant.id = Uuid::new_v4()),
        Box::new(|c| c.grant.revision += 1),
        Box::new(|c| c.grant.terms_digest = digest('e')),
        Box::new(|c| c.actor.principal_type = PrincipalType::ServiceAccount),
        Box::new(|c| c.actor.id = "urn:example:machine:8".into()),
        Box::new(|c| c.subject.principal_type = PrincipalType::User),
        Box::new(|c| c.subject.id = "urn:example:other-org".into()),
        Box::new(|c| {
            c.binding = Binding::Key {
                key_thumbprint: digest('e'),
            }
        }),
        Box::new(|c| c.operation.action = "urn:example:order:cancel".into()),
        Box::new(|c| c.operation.resource_id = "urn:example:product:43".into()),
        Box::new(|c| c.operation.audience = "https://MERCHANT.example.test/api".into()),
        Box::new(|c| c.operation.audience = "https://merchant.example.test/%61pi".into()),
        Box::new(|c| c.operation.request_profile = "urn:example:order:v2".into()),
        Box::new(|c| c.operation.request_digest = digest('e')),
        Box::new(|c| c.challenge = "different_challenge_nonce_0123456789".into()),
        Box::new(|c| c.status_issuer.principal_type = PrincipalType::External),
        Box::new(|c| c.status_issuer.id = "urn:example:other-authority".into()),
        Box::new(|c| c.policy.id = "urn:example:other-policy".into()),
        Box::new(|c| c.policy.version_digest = Some(digest('e'))),
        Box::new(|c| c.context_created_at = at()),
    ];
    for (index, change) in mutations.iter().enumerate() {
        let mut c = context();
        change(&mut c);
        let expectation = ReceiptExpectation::new(c, retained(&compact, Decision::Permit)).unwrap();
        assert_eq!(
            fresh(&compact, &key, a, &expectation).unwrap_err(),
            ReceiptVerificationError::ContextMismatch,
            "mutation {index}"
        );
    }
}

#[test]
fn retained_metadata_cannot_change_id_digest_decision_or_deadline() {
    let a = Algorithm::EdDsa;
    let key = Key::new(a, 7);
    let compact = key.sign(a, &payload(Decision::Permit));
    let changes: Vec<Box<dyn Fn(&mut RetainedReceiptBinding)>> = vec![
        Box::new(|r| r.receipt_ref = format!("{RECEIPT_REFERENCE_PREFIX}{}", Uuid::new_v4())),
        Box::new(|r| r.receipt_digest = digest('e')),
        Box::new(|r| r.decision = Decision::Deny),
        Box::new(|r| r.authorization_expires_at += Duration::seconds(1)),
        Box::new(|r| r.recorded_at = at() - Duration::seconds(1)),
    ];
    for change in changes {
        let mut r = retained(&compact, Decision::Permit);
        change(&mut r);
        let expectation = ReceiptExpectation::new(context(), r).unwrap();
        assert_eq!(
            fresh(&compact, &key, a, &expectation).unwrap_err(),
            ReceiptVerificationError::RetentionMismatch
        );
    }
}

#[test]
fn optional_reference_and_policy_pins_are_checked_but_generated_refs_need_no_fake_trust() {
    let a = Algorithm::Es256;
    let key = Key::new(a, 7);
    let compact = key.sign(a, &payload(Decision::Permit));
    for pins in [
        EvidenceReferencePins {
            approval: Some("urn:example:wrong".into()),
            ..Default::default()
        },
        EvidenceReferencePins {
            authority: Some("urn:example:wrong".into()),
            ..Default::default()
        },
        EvidenceReferencePins {
            proof: Some("urn:example:wrong".into()),
            ..Default::default()
        },
        EvidenceReferencePins {
            status: Some("urn:example:wrong".into()),
            ..Default::default()
        },
    ] {
        let expectation = expected(&compact, Decision::Permit)
            .with_evidence_reference_pins(pins)
            .unwrap();
        assert_eq!(
            fresh(&compact, &key, a, &expectation).unwrap_err(),
            ReceiptVerificationError::ContextMismatch
        );
    }
    let mut c = context();
    c.policy.version_digest = Some(digest('d'));
    let expectation = ReceiptExpectation::new(c, retained(&compact, Decision::Permit))
        .unwrap()
        .with_evidence_reference_pins(EvidenceReferencePins {
            proof: Some("urn:example:proof:generated".into()),
            ..Default::default()
        })
        .unwrap();
    assert!(fresh(&compact, &key, a, &expectation).is_ok());
}

#[test]
fn session_shape_remains_exact_evidence_without_qualifying_a_session_runtime() {
    let a = Algorithm::EdDsa;
    let key = Key::new(a, 7);
    let binding = Binding::Session {
        session_ref: "urn:example:session:1".into(),
        establishment_evidence_ref: "urn:example:establishment:1".into(),
    };
    let mut body = payload(Decision::Permit);
    body["evaluation"]["binding"] = serde_json::to_value(&binding).unwrap();
    let compact = key.sign(a, &body);
    let mut c = context();
    c.binding = binding;
    let expectation = ReceiptExpectation::new(c, retained(&compact, Decision::Permit)).unwrap();
    assert!(fresh(&compact, &key, a, &expectation).is_ok());
    assert_eq!(
        fresh(&compact, &key, a, &expected(&compact, Decision::Permit)).unwrap_err(),
        ReceiptVerificationError::ContextMismatch
    );
    body["evaluation"]["binding"]["key_thumbprint"] = json!(digest('c'));
    let compact = key.sign(a, &body);
    assert_eq!(
        fresh(&compact, &key, a, &expected(&compact, Decision::Permit)).unwrap_err(),
        ReceiptVerificationError::InvalidWire
    );
}

fn domain() -> Value {
    json!({"evaluator":{"type":"EXTERNAL","id":"urn:example:constraint-owner"},"profile":"urn:example:constraint:v1","document_digest":digest('f'),
    "grant":grant(),"operation":operation(),"decision":"PERMIT","checked_at":stamp(at()-Duration::seconds(1)),"valid_until":stamp(at()+Duration::seconds(25)),"evidence_ref":"urn:example:domain:generated"})
}
fn domain_context() -> DomainEvidenceContext {
    DomainEvidenceContext {
        evaluator: principal(PrincipalType::External, "urn:example:constraint-owner"),
        profile: "urn:example:constraint:v1".into(),
        document_digest: digest('f'),
        evidence_ref: None,
    }
}

#[test]
fn selected_domain_evidence_requires_exact_source_document_and_correspondence() {
    let a = Algorithm::Es256;
    let key = Key::new(a, 7);
    let mut body = payload(Decision::Permit);
    body["evaluation"]["domain_evidence"] = domain();
    let compact = key.sign(a, &body);
    let mut c = context();
    c.domain_evidence = Some(domain_context());
    let expectation =
        ReceiptExpectation::new(c.clone(), retained(&compact, Decision::Permit)).unwrap();
    assert_eq!(
        fresh(&compact, &key, a, &expectation)
            .unwrap()
            .domain_evidence()
            .unwrap()
            .evidence_ref,
        "urn:example:domain:generated"
    );
    assert_eq!(
        fresh(&compact, &key, a, &expected(&compact, Decision::Permit)).unwrap_err(),
        ReceiptVerificationError::ContextMismatch
    );
    for (path, value) in [
        ("/grant/id", json!(Uuid::new_v4().to_string())),
        ("/operation/request_digest", json!(digest('e'))),
        ("/decision", json!("DENY")),
        ("/checked_at", json!(stamp(at() + Duration::seconds(1)))),
        ("/valid_until", json!(stamp(at() + Duration::seconds(19)))),
        ("/profile", json!("urn:example:other-profile")),
        ("/document_digest", json!(digest('e'))),
        ("/evaluator/id", json!("urn:example:other-evaluator")),
    ] {
        let mut altered = body.clone();
        *altered["evaluation"]["domain_evidence"]
            .pointer_mut(path)
            .unwrap() = value;
        let signed = key.sign(a, &altered);
        let expectation =
            ReceiptExpectation::new(c.clone(), retained(&signed, Decision::Permit)).unwrap();
        assert!(
            fresh(&signed, &key, a, &expectation).is_err(),
            "accepted domain mutation {path}"
        );
    }
    let mut wrong = c;
    wrong.domain_evidence.as_mut().unwrap().evidence_ref = Some("urn:example:wrong".into());
    assert_eq!(
        fresh(
            &compact,
            &key,
            a,
            &ReceiptExpectation::new(wrong, retained(&compact, Decision::Permit)).unwrap()
        )
        .unwrap_err(),
        ReceiptVerificationError::ContextMismatch
    );
}

#[test]
fn all_intrinsic_time_and_status_correspondence_is_enforced_before_history() {
    let a = Algorithm::Es256;
    let key = Key::new(a, 7);
    for (path, value) in [
        (
            "/evaluation/status/grant/id",
            json!(Uuid::new_v4().to_string()),
        ),
        ("/evaluation/status/state", json!("REVOKED")),
        (
            "/evaluation/status/checked_at",
            json!(stamp(at() + Duration::seconds(1))),
        ),
        (
            "/evaluation/status/valid_until",
            json!(stamp(at() + Duration::seconds(19))),
        ),
        (
            "/evaluation/proof_verified_at",
            json!(stamp(at() + Duration::seconds(1))),
        ),
        (
            "/evaluation/proof_valid_until",
            json!(stamp(at() + Duration::seconds(19))),
        ),
        (
            "/evaluation/evaluated_at",
            json!(stamp(at() + Duration::seconds(1))),
        ),
        ("/expires_at", json!(stamp(at()))),
    ] {
        let mut body = payload(Decision::Permit);
        *body.pointer_mut(path).unwrap() = value;
        let compact = key.sign(a, &body);
        assert!(
            verify_historical(
                &compact,
                &key.pin(a),
                &expected(&compact, Decision::Permit),
                at() + Duration::days(2)
            )
            .is_err(),
            "accepted {path}"
        );
    }
}

#[test]
fn freshness_checks_evidence_age_and_selected_lifetime_without_default_clock_skew() {
    let a = Algorithm::Es256;
    let key = Key::new(a, 7);
    let compact = key.sign(a, &payload(Decision::Permit));
    let expectation = expected(&compact, Decision::Permit);
    for policy in [
        FreshnessPolicy::new(19, 30).unwrap(),
        FreshnessPolicy::new(30, 3).unwrap(),
    ] {
        assert_eq!(
            verify_fresh(
                &compact,
                &key.pin(a),
                &expectation,
                at() + Duration::seconds(2),
                policy
            )
            .unwrap_err(),
            ReceiptVerificationError::Stale
        );
    }
    assert!(FreshnessPolicy::new(0, 30).is_err());
    assert!(FreshnessPolicy::new(30, 0).is_err());
    assert!(FreshnessPolicy::new(601, 30).is_err());
}

#[test]
fn closed_schema_rejects_signed_unknown_missing_null_and_wrong_typed_fields() {
    let a = Algorithm::Es256;
    let key = Key::new(a, 7);
    for (path, value) in [
        ("/profile", json!("urn:example:other")),
        ("/decision", json!("ALLOW")),
        ("/id", json!("{22222222-2222-4222-8222-222222222222}")),
        (
            "/evaluation/organization_id",
            json!("00000000-0000-0000-0000-000000000000"),
        ),
        ("/evaluation/grant/revision", json!(0)),
        (
            "/evaluation/grant/revision",
            json!(9_007_199_254_740_992u64),
        ),
        ("/evaluation/grant/terms_digest", json!(digest('A'))),
        ("/evaluation/actor/type", json!("AGENT")),
        (
            "/evaluation/operation/audience",
            json!("https:///merchant.example.test"),
        ),
        ("/evaluation/proof_evidence_ref", json!("urn:example:%GG")),
        ("/evaluation/challenge", json!("short")),
        ("/policy/version_digest", json!("sha256:00")),
        ("/issued_at", json!("2026-11-22T00:00:00+00:00")),
        ("/issued_at", json!("+012026-11-22T00:00:00Z")),
        ("/issued_at", json!("2026-11-22T00:00:60Z")),
        ("/issued_at", json!("2026-11-22T00:00:00.1234567891Z")),
    ] {
        let mut body = payload(Decision::Permit);
        *body.pointer_mut(path).unwrap() = value;
        let compact = key.sign(a, &body);
        assert!(
            fresh(&compact, &key, a, &expected(&compact, Decision::Permit)).is_err(),
            "accepted {path}"
        );
    }
    for field in ["unknown", "domain_evidence"] {
        let mut body = payload(Decision::Permit);
        body["evaluation"][field] = Value::Null;
        let compact = key.sign(a, &body);
        assert_eq!(
            fresh(&compact, &key, a, &expected(&compact, Decision::Permit)).unwrap_err(),
            ReceiptVerificationError::InvalidWire
        );
    }
    let mut body = payload(Decision::Permit);
    body.as_object_mut().unwrap().remove("policy");
    let compact = key.sign(a, &body);
    assert_eq!(
        fresh(&compact, &key, a, &expected(&compact, Decision::Permit)).unwrap_err(),
        ReceiptVerificationError::InvalidWire
    );
}

#[test]
fn raw_json_duplicate_members_and_lexical_numbers_cannot_be_lost_before_validation() {
    let a = Algorithm::Es256;
    let key = Key::new(a, 7);
    let raw = serde_json::to_string(&payload(Decision::Permit)).unwrap();
    let malformed = [
        raw.replacen("\"revision\":3", "\"revision\":3,\"revision\":3", 1),
        raw.replacen("\"revision\":3", "\"revision\":3.0", 1),
        raw.replacen("\"revision\":3", "\"revision\":3e0", 1),
        raw.replacen("\"revision\":3", "\"revision\":-0", 1),
        raw.replacen(
            "\"revision\":3",
            "\"revision\":{\"$serde_json::private::Number\":\"3\"}",
            1,
        ),
        format!("{raw} {{}}"),
    ];
    for body in malformed {
        let compact = key.sign_raw(&serde_json::to_vec(&header(a)).unwrap(), body.as_bytes());
        assert_eq!(
            fresh(&compact, &key, a, &expected(&compact, Decision::Permit)).unwrap_err(),
            ReceiptVerificationError::InvalidWire
        );
    }
    let protected = format!(
        "{{\"alg\":\"ES256\",\"alg\":\"ES256\",\"kid\":\"{KID}\",\"typ\":\"{RECEIPT_JWS_TYPE}\"}}"
    );
    let compact = key.sign_raw(protected.as_bytes(), raw.as_bytes());
    assert_eq!(
        fresh(&compact, &key, a, &expected(&compact, Decision::Permit)).unwrap_err(),
        ReceiptVerificationError::InvalidWire
    );
}

#[test]
fn compact_encoding_is_bounded_canonical_and_exactly_three_segments() {
    let a = Algorithm::Es256;
    let key = Key::new(a, 7);
    let original = key.sign(a, &payload(Decision::Permit));
    let expectation = expected(&original, Decision::Permit);
    let text = String::from_utf8(original.clone()).unwrap();
    let parts = text.split('.').collect::<Vec<_>>();
    for compact in [
        Vec::new(),
        format!("{text}.extra").into_bytes(),
        format!("{text}\n").into_bytes(),
        format!("{}.{}", parts[0], parts[1]).into_bytes(),
        format!("{}.{}.{}=", parts[0], parts[1], parts[2]).into_bytes(),
        format!("{}..{}", parts[0], parts[2]).into_bytes(),
        format!(
            "{}.{}.{}",
            parts[0],
            parts[1],
            URL_SAFE_NO_PAD.encode([0u8; 63])
        )
        .into_bytes(),
        vec![b'a'; MAX_COMPACT_RECEIPT_BYTES + 1],
    ] {
        assert!(fresh(&compact, &key, a, &expectation).is_err());
    }
    let deep = format!("{}0{}", "{\"nested\":".repeat(30), "}".repeat(30));
    let compact = key.sign_raw(&serde_json::to_vec(&header(a)).unwrap(), deep.as_bytes());
    assert_eq!(
        fresh(&compact, &key, a, &expected(&compact, Decision::Permit)).unwrap_err(),
        ReceiptVerificationError::InvalidWire
    );
}

#[test]
fn public_trust_rejects_private_or_discovered_metadata_and_invalid_points() {
    for a in [Algorithm::Es256, Algorithm::EdDsa] {
        let key = Key::new(a, 7);
        for (field, value) in [
            ("d", json!("private")),
            ("kid", json!(KID)),
            ("alg", json!(a.as_str())),
            ("jku", json!("https://attacker.test")),
            ("x", json!(URL_SAFE_NO_PAD.encode([0u8; 32]))),
        ] {
            let mut jwk = key.jwk();
            jwk[field] = value;
            assert!(
                PinnedReceiptKey::new(
                    Uuid::parse_str(ORG).unwrap(),
                    issuer(),
                    a,
                    KID.into(),
                    &serde_json::to_vec(&jwk).unwrap()
                )
                .is_err(),
                "accepted {field}"
            );
        }
        assert!(PinnedReceiptKey::new(
            Uuid::nil(),
            issuer(),
            a,
            KID.into(),
            &serde_json::to_vec(&key.jwk()).unwrap()
        )
        .is_err());
        assert!(PinnedReceiptKey::new(
            Uuid::parse_str(ORG).unwrap(),
            issuer(),
            a,
            "did:web:other.test#key".into(),
            &serde_json::to_vec(&key.jwk()).unwrap()
        )
        .is_err());
    }
}

#[test]
fn invalid_independent_expectations_fail_before_a_receipt_can_be_promoted() {
    let a = Algorithm::Es256;
    let key = Key::new(a, 7);
    let compact = key.sign(a, &payload(Decision::Permit));
    for change in [
        (|c: &mut ReceiptContext| c.organization_id = Uuid::nil()) as fn(&mut ReceiptContext),
        |c| c.grant.revision = 0,
        |c| c.challenge = "*".into(),
        |c| c.context_expires_at = c.context_created_at,
        |c| c.operation.audience = "decentralized_identifier:did:web:verifier.example".into(),
        |c| c.policy.version_digest = Some("bad".into()),
        |c| c.status_state = StatusState::Revoked,
    ] {
        let mut c = context();
        change(&mut c);
        assert!(ReceiptExpectation::new(c, retained(&compact, Decision::Permit)).is_err());
    }
    let mut r = retained(&compact, Decision::Permit);
    r.receipt_ref = "https://receipt.example.test/2".into();
    assert!(ReceiptExpectation::new(context(), r).is_err());
    assert!(expected(&compact, Decision::Permit)
        .with_evidence_reference_pins(EvidenceReferencePins {
            proof: Some("*".into()),
            ..Default::default()
        })
        .is_err());
    let error = ReceiptVerificationError::ContextMismatch;
    assert!(!format!("{error:?} {error}").contains(ISSUER));
}

#[test]
fn valid_signature_cannot_cross_pinned_tenant_or_complete_issuer_type() {
    let a = Algorithm::Es256;
    let key = Key::new(a, 7);
    let compact = key.sign(a, &payload(Decision::Permit));
    let expectation = expected(&compact, Decision::Permit);
    let foreign = PinnedReceiptKey::new(
        Uuid::new_v4(),
        issuer(),
        a,
        KID.into(),
        &serde_json::to_vec(&key.jwk()).unwrap(),
    )
    .unwrap();
    assert_eq!(
        verify_fresh(
            &compact,
            &foreign,
            &expectation,
            at() + Duration::seconds(2),
            freshness()
        )
        .unwrap_err(),
        ReceiptVerificationError::KeyMismatch
    );
    let typed = PinnedReceiptKey::new(
        Uuid::parse_str(ORG).unwrap(),
        principal(PrincipalType::User, ISSUER),
        a,
        KID.into(),
        &serde_json::to_vec(&key.jwk()).unwrap(),
    )
    .unwrap();
    assert_eq!(
        verify_fresh(
            &compact,
            &typed,
            &expectation,
            at() + Duration::seconds(2),
            freshness()
        )
        .unwrap_err(),
        ReceiptVerificationError::KeyMismatch
    );
    for invalid in [
        "did:",
        "did:WEB:issuer.example",
        "did:web:",
        "did:web:issuer.example/path",
        "did:web:issuer.example?query",
    ] {
        assert!(PinnedReceiptKey::new(
            Uuid::parse_str(ORG).unwrap(),
            principal(PrincipalType::Organization, invalid),
            a,
            format!("{invalid}#key"),
            &serde_json::to_vec(&key.jwk()).unwrap()
        )
        .is_err());
    }
}

#[test]
fn repeated_verification_preserves_original_identity_times_and_does_not_consume_business_replay() {
    let a = Algorithm::EdDsa;
    let key = Key::new(a, 7);
    let compact = key.sign(a, &payload(Decision::Permit));
    let expectation = expected(&compact, Decision::Permit);
    let first = verify_fresh(
        &compact,
        &key.pin(a),
        &expectation,
        at() + Duration::seconds(2),
        freshness(),
    )
    .unwrap();
    let again = verify_fresh(
        &compact,
        &key.pin(a),
        &expectation,
        at() + Duration::seconds(10),
        freshness(),
    )
    .unwrap();
    assert_eq!(first.receipt_id(), again.receipt_id());
    assert_eq!(first.receipt_digest(), again.receipt_digest());
    assert_eq!(first.expires_at(), again.expires_at());
    assert_eq!(first.evidence_times(), again.evidence_times());
    assert_ne!(first.verified_at(), again.verified_at());
}

#[test]
fn effective_freshness_deadline_is_exclusive_and_can_precede_original_expiry() {
    let a = Algorithm::Es256;
    let key = Key::new(a, 7);
    let compact = key.sign(a, &payload(Decision::Permit));
    let expectation = expected(&compact, Decision::Permit);
    let policy = FreshnessPolicy::new(30, 10).unwrap();
    let checked = verify_fresh(
        &compact,
        &key.pin(a),
        &expectation,
        at() + Duration::seconds(2),
        policy,
    )
    .unwrap();
    assert_eq!(checked.fresh_until(), at() + Duration::seconds(8));
    assert_eq!(checked.expires_at(), at() + Duration::seconds(20));
    assert!(verify_fresh(
        &compact,
        &key.pin(a),
        &expectation,
        checked.fresh_until() - Duration::nanoseconds(1),
        policy
    )
    .is_ok());
    assert_eq!(
        verify_fresh(
            &compact,
            &key.pin(a),
            &expectation,
            checked.fresh_until(),
            policy
        )
        .unwrap_err(),
        ReceiptVerificationError::Stale
    );
    let history = verify_historical(
        &compact,
        &key.pin(a),
        &expectation,
        at() + Duration::days(1),
    )
    .unwrap();
    assert_eq!(history.expires_at(), checked.expires_at());
}

#[test]
fn signed_denial_still_requires_the_selected_producers_active_and_domain_permit_invariants() {
    let a = Algorithm::EdDsa;
    let key = Key::new(a, 7);
    for state in ["PENDING", "SUSPENDED", "REVOKED", "EXPIRED"] {
        let mut body = payload(Decision::Deny);
        body["evaluation"]["status"]["state"] = json!(state);
        let compact = key.sign(a, &body);
        assert_eq!(
            verify_historical(
                &compact,
                &key.pin(a),
                &expected(&compact, Decision::Deny),
                at() + Duration::days(1)
            )
            .unwrap_err(),
            ReceiptVerificationError::InvalidWire
        );
    }
    let mut body = payload(Decision::Deny);
    body["evaluation"]["domain_evidence"] = domain();
    let mut c = context();
    c.domain_evidence = Some(domain_context());
    let compact = key.sign(a, &body);
    let expectation =
        ReceiptExpectation::new(c.clone(), retained(&compact, Decision::Deny)).unwrap();
    assert_eq!(
        verify_historical(
            &compact,
            &key.pin(a),
            &expectation,
            at() + Duration::days(1)
        )
        .unwrap()
        .decision(),
        Decision::Deny
    );
    body["evaluation"]["domain_evidence"]["decision"] = json!("DENY");
    let compact = key.sign(a, &body);
    let expectation = ReceiptExpectation::new(c, retained(&compact, Decision::Deny)).unwrap();
    assert_eq!(
        verify_historical(
            &compact,
            &key.pin(a),
            &expectation,
            at() + Duration::days(1)
        )
        .unwrap_err(),
        ReceiptVerificationError::InvalidWire
    );
}
