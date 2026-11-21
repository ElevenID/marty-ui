use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Duration, Utc};
use marty_principal_runtime_binding::{
    jwk_sha256_thumbprint,
    managed_enrollment::{
        verify_enrollment_proof, EnrollmentAlgorithm, EnrollmentChallenge,
        EnrollmentChallengeParameters, EnrollmentPolicy, EnrollmentProofError, ENROLLMENT_JWS_TYPE,
        ENROLLMENT_PROFILE, ENROLLMENT_SESSION_PREFIX, MAX_ENROLLMENT_PROOF_BYTES,
        MAX_SAFE_JSON_INTEGER,
    },
    ThumbprintEncoding,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const ISSUED_AT: i64 = 1_800_000_000;

// Deterministic synthetic test-only seeds, never deployment identities/keys.
enum TestSigner {
    P256(p256::ecdsa::SigningKey),
    Ed25519(ed25519_dalek::SigningKey),
}

impl TestSigner {
    fn new(algorithm: EnrollmentAlgorithm, seed: u8) -> Self {
        match algorithm {
            EnrollmentAlgorithm::ES256 => {
                Self::P256(p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap())
            }
            EnrollmentAlgorithm::EdDSA => {
                Self::Ed25519(ed25519_dalek::SigningKey::from_bytes(&[seed; 32]))
            }
        }
    }
    fn algorithm(&self) -> EnrollmentAlgorithm {
        match self {
            Self::P256(_) => EnrollmentAlgorithm::ES256,
            Self::Ed25519(_) => EnrollmentAlgorithm::EdDSA,
        }
    }
    fn public_jwk(&self) -> Value {
        match self {
            Self::P256(key) => {
                let point = key.verifying_key().to_sec1_point(false);
                json!({"kty":"EC", "crv":"P-256",
                    "x":URL_SAFE_NO_PAD.encode(point.x().unwrap()),
                    "y":URL_SAFE_NO_PAD.encode(point.y().unwrap())})
            }
            Self::Ed25519(key) => json!({"kty":"OKP", "crv":"Ed25519",
                "x": URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes())}),
        }
    }
    fn sign(&self, input: &[u8]) -> Vec<u8> {
        match self {
            Self::P256(key) => {
                use p256::ecdsa::signature::Signer;
                let signature: p256::ecdsa::Signature = key.sign(input);
                signature.normalize_s().to_bytes().to_vec()
            }
            Self::Ed25519(key) => {
                use ed25519_dalek::Signer;
                key.sign(input).to_bytes().to_vec()
            }
        }
    }
    fn compact(&self, header: &[u8], payload: &[u8]) -> String {
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(payload)
        );
        format!(
            "{}.{}",
            input,
            URL_SAFE_NO_PAD.encode(self.sign(input.as_bytes()))
        )
    }
    fn proof(&self, challenge: &EnrollmentChallenge) -> String {
        self.compact(
            &serde_json::to_vec(&header(challenge)).unwrap(),
            challenge.payload(),
        )
    }
}

fn now() -> DateTime<Utc> {
    DateTime::from_timestamp(ISSUED_AT + 10, 123_456_789).unwrap()
}
fn id(index: u128) -> Uuid {
    Uuid::from_u128(0x1abcf234_5abc_4def_8abc_123456789000 + index)
}
fn policy(algorithms: Vec<EnrollmentAlgorithm>) -> EnrollmentPolicy {
    EnrollmentPolicy::new(
        "urn:example:enrollment-policy:v1".into(),
        3,
        algorithms,
        120,
    )
    .unwrap()
}
fn parameters(signer: &TestSigner) -> EnrollmentChallengeParameters {
    EnrollmentChallengeParameters {
        challenge_id: id(1),
        organization_id: id(2),
        agent_id: id(3),
        key_id: id(4),
        administrator_id: id(5),
        expected_revision: 7,
        key_algorithm: signer.algorithm(),
        key_thumbprint: jwk_sha256_thumbprint(&serde_json::to_vec(&signer.public_jwk()).unwrap())
            .unwrap(),
        runtime_instance_ref: "urn:example:runtime:fixture".into(),
        issuer: "https://issuer.example.test".into(),
        subject: "managed-agent-fixture".into(),
        session_ref: format!("{ENROLLMENT_SESSION_PREFIX}{}", "ab".repeat(32)),
        audience: "https://organization.example.test/managed-enrollment".into(),
        nonce: [29; 32],
        issued_at: ISSUED_AT,
        expires_at: ISSUED_AT + 120,
        policy: policy(vec![EnrollmentAlgorithm::EdDSA, EnrollmentAlgorithm::ES256]),
    }
}
fn header(challenge: &EnrollmentChallenge) -> Value {
    json!({"typ":ENROLLMENT_JWS_TYPE, "alg":challenge.key_algorithm(), "kid":challenge.key_id().to_string()})
}
fn verify(
    challenge: &EnrollmentChallenge,
    signer: &TestSigner,
    compact: &str,
) -> Result<
    marty_principal_runtime_binding::managed_enrollment::VerifiedEnrollmentProof,
    EnrollmentProofError,
> {
    verify_enrollment_proof(
        challenge,
        &serde_json::to_vec(&signer.public_jwk()).unwrap(),
        compact,
        now(),
    )
}
fn replace_segment(compact: &str, index: usize, segment: String) -> String {
    let mut parts: Vec<String> = compact.split('.').map(str::to_owned).collect();
    parts[index] = segment;
    parts.join(".")
}
fn hash(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

#[test]
fn both_selected_algorithms_verify_actual_signatures_and_public_digests() {
    for algorithm in [EnrollmentAlgorithm::ES256, EnrollmentAlgorithm::EdDSA] {
        let signer = TestSigner::new(algorithm, 7);
        let challenge = EnrollmentChallenge::new(parameters(&signer)).unwrap();
        let compact = signer.proof(&challenge);
        let proof = verify(&challenge, &signer, &compact).unwrap();
        assert_eq!(proof.challenge_id(), challenge.challenge_id());
        assert_eq!(proof.organization_id(), challenge.organization_id());
        assert_eq!(proof.agent_id(), challenge.agent_id());
        assert_eq!(proof.key_id(), challenge.key_id());
        assert_eq!(proof.expected_revision(), 7);
        assert_eq!(proof.verified_at(), now());
        assert_eq!(proof.proof_digest(), hash(compact.as_bytes()));
        assert_eq!(proof.payload_digest(), hash(challenge.payload()));
        assert_eq!(proof.policy_digest(), challenge.policy().digest());
        assert!(proof
            .key_thumbprint()
            .same_binding(challenge.key_thumbprint()));
        assert!(proof.ensure_current(now() + Duration::seconds(1)).is_ok());
        assert_eq!(
            challenge.document()["policy"]["allowed_algorithms"],
            json!(["ES256", "EdDSA"])
        );
    }
}

#[test]
fn trusted_restore_preserves_exact_payload_across_jsonb_order_and_whitespace() {
    let signer = TestSigner::new(EnrollmentAlgorithm::EdDSA, 7);
    let mut params = parameters(&signer);
    params.key_thumbprint = params
        .key_thumbprint
        .reencode(ThumbprintEncoding::MipSha256Hex);
    let challenge = EnrollmentChallenge::new(params).unwrap();
    let pretty = serde_json::to_vec_pretty(&challenge.document()).unwrap();
    let restored = EnrollmentChallenge::from_trusted_document(&pretty).unwrap();
    assert_eq!(restored.payload(), challenge.payload());
    assert_eq!(
        restored.payload_b64url(),
        URL_SAFE_NO_PAD.encode(challenge.payload())
    );
    assert_eq!(restored.digest(), challenge.digest());
    assert_eq!(restored.policy_digest(), challenge.policy_digest());
    assert!(verify(&restored, &signer, &signer.proof(&challenge)).is_ok());
    // Explicitly recursively sorted payload, independent of serde_json features.
    assert!(std::str::from_utf8(challenge.payload())
        .unwrap()
        .starts_with("{\"administrator_id\":"));
    assert_eq!(
        challenge.document()["key_thumbprint"]["encoding"],
        "BASE64URL_SHA256"
    );
}

#[test]
fn every_retained_binding_field_is_covered_even_with_a_valid_signature() {
    let signer = TestSigner::new(EnrollmentAlgorithm::EdDSA, 7);
    let challenge = EnrollmentChallenge::new(parameters(&signer)).unwrap();
    let changes = [
        ("profile", json!("urn:marty:operational-authentication:v1")),
        ("purpose", json!("AUTHENTICATE_MACHINE")),
        ("challenge_id", json!(id(99))),
        ("organization_id", json!(id(99))),
        ("agent_id", json!(id(99))),
        ("key_id", json!(id(99))),
        ("administrator_id", json!(id(99))),
        ("expected_revision", json!(8)),
        ("key_algorithm", json!("ES256")),
        (
            "key_thumbprint",
            json!({"basis":"JWK_RFC7638_SHA256","encoding":"BASE64URL_SHA256","value":URL_SAFE_NO_PAD.encode([0;32])}),
        ),
        ("runtime_instance_ref", json!("urn:example:runtime:other")),
        ("issuer", json!("https://other.example.test")),
        ("subject", json!("other-agent")),
        (
            "session_ref",
            json!(format!("{ENROLLMENT_SESSION_PREFIX}{}", "cd".repeat(32))),
        ),
        ("audience", json!("https://other.example.test/enrollment")),
        ("nonce", json!(URL_SAFE_NO_PAD.encode([30; 32]))),
        ("iat", json!(ISSUED_AT - 1)),
        ("exp", json!(ISSUED_AT + 121)),
        (
            "policy",
            json!({"profile":"urn:example:other-policy", "revision":3,"allowed_algorithms":["ES256","EdDSA"],"max_age_seconds":120}),
        ),
    ];
    for (field, changed) in changes {
        let mut payload = challenge.document();
        payload[field] = changed;
        let compact = signer.compact(
            &serde_json::to_vec(&header(&challenge)).unwrap(),
            &serde_json::to_vec(&payload).unwrap(),
        );
        assert_eq!(
            verify(&challenge, &signer, &compact).unwrap_err(),
            EnrollmentProofError::PayloadMismatch,
            "field {field}"
        );
    }
    for (field, changed) in [
        ("revision", json!(4)),
        ("allowed_algorithms", json!(["EdDSA"])),
        ("max_age_seconds", json!(119)),
    ] {
        let mut payload = challenge.document();
        payload["policy"][field] = changed;
        let compact = signer.compact(
            &serde_json::to_vec(&header(&challenge)).unwrap(),
            &serde_json::to_vec(&payload).unwrap(),
        );
        assert_eq!(
            verify(&challenge, &signer, &compact).unwrap_err(),
            EnrollmentProofError::PayloadMismatch
        );
    }
}

#[test]
fn proof_cannot_be_replayed_against_another_server_challenge() {
    let signer = TestSigner::new(EnrollmentAlgorithm::EdDSA, 7);
    let challenge = EnrollmentChallenge::new(parameters(&signer)).unwrap();
    let compact = signer.proof(&challenge);
    for change in 0..6 {
        let mut params = parameters(&signer);
        match change {
            0 => params.challenge_id = id(100),
            1 => params.nonce = [31; 32],
            2 => params.organization_id = id(100),
            3 => params.agent_id = id(100),
            4 => params.expected_revision += 1,
            _ => params.session_ref = format!("{ENROLLMENT_SESSION_PREFIX}{}", "ff".repeat(32)),
        }
        let other = EnrollmentChallenge::new(params).unwrap();
        assert_eq!(
            verify(&other, &signer, &compact).unwrap_err(),
            EnrollmentProofError::PayloadMismatch
        );
    }
    // Cryptographic verification deliberately has no durable replay-store effect.
    // The owning Organization transaction must make challenge consumption unique.
    assert!(verify(&challenge, &signer, &compact).is_ok());
    assert!(verify(&challenge, &signer, &compact).is_ok());
}

#[test]
fn closed_protected_header_rejects_extensions_wrong_algorithm_and_wrong_key_id() {
    let signer = TestSigner::new(EnrollmentAlgorithm::EdDSA, 7);
    let challenge = EnrollmentChallenge::new(parameters(&signer)).unwrap();
    for (field, value) in [
        ("typ", json!("JWT")),
        ("typ", Value::Null),
        ("alg", json!("none")),
        ("alg", json!("HS256")),
        ("alg", json!("Ed25519")),
        ("alg", json!("ES256")),
        ("kid", json!(id(99))),
        ("kid", json!(challenge.key_id().to_string().to_uppercase())),
        ("jwk", signer.public_jwk()),
        ("jku", json!("https://key.example.test")),
        ("x5u", json!("https://key.example.test")),
        ("crit", json!([])),
        ("b64", json!(false)),
        ("verified", json!(true)),
        ("unknown", Value::Null),
    ] {
        let mut changed = header(&challenge);
        changed[field] = value;
        let compact = signer.compact(&serde_json::to_vec(&changed).unwrap(), challenge.payload());
        assert_eq!(
            verify(&challenge, &signer, &compact).unwrap_err(),
            EnrollmentProofError::InvalidProtectedHeader,
            "field {field}"
        );
    }
    let duplicate = format!("{{\"typ\":\"{ENROLLMENT_JWS_TYPE}\",\"typ\":\"{ENROLLMENT_JWS_TYPE}\",\"alg\":\"EdDSA\",\"kid\":\"{}\"}}", challenge.key_id());
    assert_eq!(
        verify(
            &challenge,
            &signer,
            &signer.compact(duplicate.as_bytes(), challenge.payload())
        )
        .unwrap_err(),
        EnrollmentProofError::DuplicateJsonField
    );
}

#[test]
fn exact_payload_rejects_whitespace_duplicates_nulls_and_number_spellings() {
    let signer = TestSigner::new(EnrollmentAlgorithm::EdDSA, 7);
    let challenge = EnrollmentChallenge::new(parameters(&signer)).unwrap();
    let original = std::str::from_utf8(challenge.payload()).unwrap();
    let alternatives = [
        serde_json::to_string_pretty(&challenge.document()).unwrap(),
        original.replacen("{", "{\"profile\":null,", 1),
        original.replace("\"expected_revision\":7", "\"expected_revision\":7.0"),
        original.replace("\"expected_revision\":7", "\"expected_revision\":7e0"),
        original.replace("\"iat\":1800000000", "\"iat\":1.8e9"),
        original.replace("\"exp\":1800000120", "\"exp\":null"),
        original.replacen("{", "{\"verified\":true,", 1),
    ];
    for payload in alternatives {
        assert_ne!(payload.as_bytes(), challenge.payload());
        assert_eq!(
            verify(
                &challenge,
                &signer,
                &signer.compact(
                    &serde_json::to_vec(&header(&challenge)).unwrap(),
                    payload.as_bytes()
                )
            )
            .unwrap_err(),
            EnrollmentProofError::PayloadMismatch
        );
    }
}

#[test]
fn compact_encoding_rejects_padding_trailing_bits_and_extra_or_empty_segments() {
    let signer = TestSigner::new(EnrollmentAlgorithm::EdDSA, 7);
    let challenge = EnrollmentChallenge::new(parameters(&signer)).unwrap();
    let compact = signer.proof(&challenge);
    let parts: Vec<_> = compact.split('.').collect();
    for index in 0..3 {
        for replacement in [
            format!("{}=", parts[index]),
            format!("{} ", parts[index]),
            String::new(),
            "+bad/".into(),
        ] {
            assert_eq!(
                verify(
                    &challenge,
                    &signer,
                    &replace_segment(&compact, index, replacement)
                )
                .unwrap_err(),
                EnrollmentProofError::NonCanonicalEncoding
            );
        }
    }
    let mut signature = parts[2].as_bytes().to_vec();
    // A 64-byte signature has only two significant bits in its last base64 char.
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let final_index = ALPHABET
        .iter()
        .position(|value| Some(value) == signature.last())
        .unwrap();
    *signature.last_mut().unwrap() = ALPHABET[final_index + 1];
    assert_eq!(
        verify(
            &challenge,
            &signer,
            &replace_segment(&compact, 2, String::from_utf8(signature).unwrap())
        )
        .unwrap_err(),
        EnrollmentProofError::NonCanonicalEncoding
    );
    for malformed in [
        format!("{compact}.extra"),
        "one.two".into(),
        "one".into(),
        "x".repeat(MAX_ENROLLMENT_PROOF_BYTES + 1),
    ] {
        assert_eq!(
            verify(&challenge, &signer, &malformed).unwrap_err(),
            EnrollmentProofError::InvalidCompactJws
        );
    }
}

#[test]
fn current_public_key_and_signature_are_both_required() {
    for algorithm in [EnrollmentAlgorithm::ES256, EnrollmentAlgorithm::EdDSA] {
        let signer = TestSigner::new(algorithm, 7);
        let other = TestSigner::new(algorithm, 8);
        let challenge = EnrollmentChallenge::new(parameters(&signer)).unwrap();
        assert_eq!(
            verify(&challenge, &other, &signer.proof(&challenge)).unwrap_err(),
            EnrollmentProofError::KeyBindingMismatch
        );
        assert_eq!(
            verify(&challenge, &signer, &other.proof(&challenge)).unwrap_err(),
            EnrollmentProofError::InvalidSignature
        );
        let compact = signer.proof(&challenge);
        let mut signature = URL_SAFE_NO_PAD
            .decode(compact.split('.').nth(2).unwrap())
            .unwrap();
        signature[0] ^= 1;
        assert_eq!(
            verify(
                &challenge,
                &signer,
                &replace_segment(&compact, 2, URL_SAFE_NO_PAD.encode(signature))
            )
            .unwrap_err(),
            EnrollmentProofError::InvalidSignature
        );
        let other_algorithm = TestSigner::new(
            if algorithm == EnrollmentAlgorithm::ES256 {
                EnrollmentAlgorithm::EdDSA
            } else {
                EnrollmentAlgorithm::ES256
            },
            7,
        );
        assert_eq!(
            verify(&challenge, &other_algorithm, &compact).unwrap_err(),
            EnrollmentProofError::AlgorithmMismatch
        );
    }
}

#[test]
fn p256_rejects_high_s_zero_scalars_and_non_raw_signatures() {
    let signer = TestSigner::new(EnrollmentAlgorithm::ES256, 7);
    let challenge = EnrollmentChallenge::new(parameters(&signer)).unwrap();
    let compact = signer.proof(&challenge);
    let raw = URL_SAFE_NO_PAD
        .decode(compact.split('.').nth(2).unwrap())
        .unwrap();
    let low = p256::ecdsa::Signature::from_slice(&raw).unwrap();
    let high =
        p256::ecdsa::Signature::from_scalars(low.r().to_bytes(), (-low.s()).to_bytes()).unwrap();
    assert_ne!(low, high);
    assert_eq!(high.normalize_s(), low);
    // The high-S form is mathematically valid, but outside this local profile.
    if let TestSigner::P256(key) = &signer {
        use p256::ecdsa::signature::Verifier;
        let input = compact.rsplit_once('.').unwrap().0;
        key.verifying_key().verify(input.as_bytes(), &high).unwrap();
    }
    assert_eq!(
        verify(
            &challenge,
            &signer,
            &replace_segment(&compact, 2, URL_SAFE_NO_PAD.encode(high.to_bytes()))
        )
        .unwrap_err(),
        EnrollmentProofError::NonCanonicalSignature
    );
    for bytes in [vec![0; 64], vec![0; 63], vec![0xff; 64], vec![0x30; 72]] {
        assert!(verify(
            &challenge,
            &signer,
            &replace_segment(&compact, 2, URL_SAFE_NO_PAD.encode(bytes))
        )
        .is_err());
    }
}

#[test]
fn ed25519_rejects_noncanonical_scalars_and_weak_or_noncanonical_points() {
    let signer = TestSigner::new(EnrollmentAlgorithm::EdDSA, 7);
    let challenge = EnrollmentChallenge::new(parameters(&signer)).unwrap();
    let compact = signer.proof(&challenge);
    let raw = URL_SAFE_NO_PAD
        .decode(compact.split('.').nth(2).unwrap())
        .unwrap();
    let mut bad_scalar = raw.clone();
    bad_scalar[32..].fill(0xff);
    let mut weak_r = raw;
    weak_r[..32].fill(0);
    weak_r[0] = 1;
    for signature in [bad_scalar, weak_r] {
        assert_eq!(
            verify(
                &challenge,
                &signer,
                &replace_segment(&compact, 2, URL_SAFE_NO_PAD.encode(signature))
            )
            .unwrap_err(),
            EnrollmentProofError::InvalidSignature
        );
    }
    let mut identity = [0; 32];
    identity[0] = 1;
    let mut noncanonical = [0xff; 32];
    noncanonical[31] = 0x7f;
    for point in [[0; 32], identity, noncanonical] {
        let public = serde_json::to_vec(
            &json!({"kty":"OKP","crv":"Ed25519","x":URL_SAFE_NO_PAD.encode(point)}),
        )
        .unwrap();
        let mut params = parameters(&signer);
        params.key_thumbprint = jwk_sha256_thumbprint(&public).unwrap();
        let bad_challenge = EnrollmentChallenge::new(params).unwrap();
        assert_eq!(
            verify_enrollment_proof(
                &bad_challenge,
                &public,
                &signer.proof(&bad_challenge),
                now()
            )
            .unwrap_err(),
            EnrollmentProofError::InvalidPublicKey
        );
    }
}

#[test]
fn independent_key_must_be_bounded_public_only_and_have_valid_metadata() {
    let signer = TestSigner::new(EnrollmentAlgorithm::EdDSA, 7);
    let challenge = EnrollmentChallenge::new(parameters(&signer)).unwrap();
    let compact = signer.proof(&challenge);
    for (field, value) in [
        ("d", json!("not-private-fixture")),
        ("k", Value::Null),
        ("alg", json!("HS256")),
        ("use", json!("enc")),
        ("key_ops", json!(["sign"])),
        ("x", json!("bad=")),
        ("jku", json!("https://key.example.test")),
    ] {
        let mut jwk = signer.public_jwk();
        jwk[field] = value;
        assert_eq!(
            verify_enrollment_proof(
                &challenge,
                &serde_json::to_vec(&jwk).unwrap(),
                &compact,
                now()
            )
            .unwrap_err(),
            EnrollmentProofError::InvalidPublicKey
        );
    }
    let mut jwk = signer.public_jwk();
    jwk["alg"] = json!("EdDSA");
    jwk["use"] = json!("sig");
    jwk["key_ops"] = json!(["verify"]);
    jwk["kid"] = json!("metadata-is-not-header-key-id");
    assert!(verify_enrollment_proof(
        &challenge,
        &serde_json::to_vec(&jwk).unwrap(),
        &compact,
        now()
    )
    .is_ok());
}

#[test]
fn fresh_clock_has_no_leeway_and_commit_recheck_rejects_regression() {
    let signer = TestSigner::new(EnrollmentAlgorithm::EdDSA, 7);
    let challenge = EnrollmentChallenge::new(parameters(&signer)).unwrap();
    let compact = signer.proof(&challenge);
    let key = serde_json::to_vec(&signer.public_jwk()).unwrap();
    let issued = DateTime::from_timestamp(ISSUED_AT, 0).unwrap();
    let expired = DateTime::from_timestamp(ISSUED_AT + 120, 0).unwrap();
    assert_eq!(
        verify_enrollment_proof(
            &challenge,
            &key,
            &compact,
            issued - Duration::nanoseconds(1)
        )
        .unwrap_err(),
        EnrollmentProofError::NotYetValid
    );
    assert!(verify_enrollment_proof(&challenge, &key, &compact, issued).is_ok());
    assert!(verify_enrollment_proof(
        &challenge,
        &key,
        &compact,
        expired - Duration::nanoseconds(1)
    )
    .is_ok());
    assert_eq!(
        verify_enrollment_proof(&challenge, &key, &compact, expired).unwrap_err(),
        EnrollmentProofError::Expired
    );
    let proof = verify(&challenge, &signer, &compact).unwrap();
    assert_eq!(
        proof
            .ensure_current(now() - Duration::nanoseconds(1))
            .unwrap_err(),
        EnrollmentProofError::ClockRegression
    );
    assert_eq!(
        proof.ensure_current(expired).unwrap_err(),
        EnrollmentProofError::Expired
    );
}

#[test]
fn policy_construction_rejects_missing_duplicate_or_unbounded_rules() {
    for (profile, revision, algorithms, age) in [
        ("relative", 1, vec![EnrollmentAlgorithm::EdDSA], 120),
        (
            "urn:example:policy",
            0,
            vec![EnrollmentAlgorithm::EdDSA],
            120,
        ),
        (
            "urn:example:policy",
            MAX_SAFE_JSON_INTEGER + 1,
            vec![EnrollmentAlgorithm::EdDSA],
            120,
        ),
        ("urn:example:policy", 1, vec![], 120),
        (
            "urn:example:policy",
            1,
            vec![EnrollmentAlgorithm::EdDSA, EnrollmentAlgorithm::EdDSA],
            120,
        ),
        ("urn:example:policy", 1, vec![EnrollmentAlgorithm::EdDSA], 0),
        (
            "urn:example:policy",
            1,
            vec![EnrollmentAlgorithm::EdDSA],
            301,
        ),
    ] {
        assert_eq!(
            EnrollmentPolicy::new(profile.into(), revision, algorithms, age).unwrap_err(),
            EnrollmentProofError::InvalidPolicy
        );
    }
    let signer = TestSigner::new(EnrollmentAlgorithm::EdDSA, 7);
    let mut params = parameters(&signer);
    params.policy = policy(vec![EnrollmentAlgorithm::ES256]);
    assert_eq!(
        EnrollmentChallenge::new(params).unwrap_err(),
        EnrollmentProofError::AlgorithmMismatch
    );
}

#[test]
fn challenge_construction_bounds_ids_revisions_session_nonce_and_clock() {
    let signer = TestSigner::new(EnrollmentAlgorithm::EdDSA, 7);
    for index in 0..17 {
        let mut params = parameters(&signer);
        match index {
            0 => params.challenge_id = Uuid::nil(),
            1 => params.organization_id = Uuid::nil(),
            2 => params.agent_id = Uuid::nil(),
            3 => params.key_id = Uuid::nil(),
            4 => params.administrator_id = Uuid::nil(),
            5 => params.expected_revision = 0,
            6 => params.expected_revision = MAX_SAFE_JSON_INTEGER,
            7 => params.expected_revision = u64::MAX,
            8 => params.nonce = [0; 32],
            9 => params.session_ref = format!("sha256:{}", "ab".repeat(32)),
            10 => params.session_ref = format!("{ENROLLMENT_SESSION_PREFIX}{}", "AB".repeat(32)),
            11 => params.issued_at = -1,
            12 => params.expires_at = params.issued_at,
            13 => params.expires_at += 1,
            14 => params.issued_at = i64::MIN,
            15 => params.audience = "https://*.example.test".into(),
            _ => params.subject = "subject\nwith-control".into(),
        }
        assert_eq!(
            EnrollmentChallenge::new(params).unwrap_err(),
            EnrollmentProofError::InvalidChallenge,
            "case {index}"
        );
    }
    let mut params = parameters(&signer);
    params.expected_revision = MAX_SAFE_JSON_INTEGER - 1;
    assert!(EnrollmentChallenge::new(params).is_ok());
}

#[test]
fn stored_challenges_reject_noncanonical_values_unknown_null_duplicate_and_numeric_fields() {
    let signer = TestSigner::new(EnrollmentAlgorithm::EdDSA, 7);
    let challenge = EnrollmentChallenge::new(parameters(&signer)).unwrap();
    for (field, value) in [
        ("profile", json!("urn:example:other")),
        ("purpose", json!("RESUME_MACHINE")),
        (
            "key_id",
            json!(challenge.key_id().to_string().to_uppercase()),
        ),
        ("key_algorithm", json!("Ed25519")),
        ("verified", json!(true)),
        ("exp", Value::Null),
        (
            "nonce",
            json!(format!("{}=", URL_SAFE_NO_PAD.encode([29; 32]))),
        ),
        ("expected_revision", json!(MAX_SAFE_JSON_INTEGER)),
    ] {
        let mut value_document = challenge.document();
        value_document[field] = value;
        assert!(
            EnrollmentChallenge::from_trusted_document(
                &serde_json::to_vec(&value_document).unwrap()
            )
            .is_err(),
            "field {field}"
        );
    }
    let mut changed = challenge.document();
    changed["policy"]["allowed_algorithms"] = json!(["EdDSA", "ES256"]);
    assert!(
        EnrollmentChallenge::from_trusted_document(&serde_json::to_vec(&changed).unwrap()).is_err()
    );
    let mut changed = challenge.document();
    changed["policy"]["unknown"] = Value::Null;
    assert!(
        EnrollmentChallenge::from_trusted_document(&serde_json::to_vec(&changed).unwrap()).is_err()
    );
    let raw = std::str::from_utf8(challenge.payload()).unwrap();
    for changed in [
        raw.replacen("{", "{\"profile\":null,", 1),
        raw.replace("\"iat\":1800000000", "\"iat\":1.8e9"),
        raw.replace("\"expected_revision\":7", "\"expected_revision\":7.0"),
    ] {
        assert!(EnrollmentChallenge::from_trusted_document(changed.as_bytes()).is_err());
    }
}

#[test]
fn diagnostic_output_never_echoes_proof_or_challenge_material() {
    let signer = TestSigner::new(EnrollmentAlgorithm::EdDSA, 7);
    let params = parameters(&signer);
    let challenge = EnrollmentChallenge::new(params.clone()).unwrap();
    let compact = signer.proof(&challenge);
    let proof = verify(&challenge, &signer, &compact).unwrap();
    let diagnostic = format!(
        "{params:?} {challenge:?} {proof:?} {}",
        EnrollmentProofError::InvalidSignature
    );
    for private in [
        compact,
        params.session_ref,
        URL_SAFE_NO_PAD.encode(params.nonce),
        params.subject,
    ] {
        assert!(!diagnostic.contains(&private));
    }
    assert_eq!(challenge.document()["profile"], ENROLLMENT_PROFILE);
}

#[test]
fn independently_generated_node_signatures_verify_in_rust() {
    let fixture: Value =
        serde_json::from_slice(include_bytes!("fixtures/node-managed-enrollment.json")).unwrap();
    assert_eq!(
        fixture["profile"],
        "urn:marty:managed-key-enrollment-public-test-vectors:v1"
    );
    assert_eq!(fixture["provenance"]["private_material_retained"], false);
    assert_eq!(
        fixture["provenance"]["generator"],
        "scripts/generate_managed_enrollment_vectors.mjs"
    );
    let vectors = fixture["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 2);
    for (vector, algorithm) in vectors.iter().zip(["ES256", "EdDSA"]) {
        assert_eq!(vector["algorithm"], algorithm);
        let retained = &vector["challenge"];
        let challenge = EnrollmentChallenge::from_trusted_document(
            &serde_json::to_vec(&retained["challenge"]).unwrap(),
        )
        .unwrap();
        assert_eq!(challenge.payload_b64url(), retained["signing_payload"]);
        assert_eq!(challenge.digest(), retained["challenge_digest"]);
        assert_eq!(challenge.key_algorithm().as_str(), algorithm);
        let public = serde_json::to_vec(&vector["public_jwk"]).unwrap();
        let compact = vector["proof"].as_str().unwrap();
        let verified_at = vector["verification_time"]
            .as_str()
            .unwrap()
            .parse::<DateTime<Utc>>()
            .unwrap();
        let proof = verify_enrollment_proof(&challenge, &public, compact, verified_at).unwrap();
        assert_eq!(proof.payload_digest(), challenge.digest());
        assert_eq!(proof.proof_digest(), hash(compact.as_bytes()));
        assert_eq!(proof.verified_at(), verified_at);
        let mut wrong_challenge = challenge.document();
        wrong_challenge["nonce"] = json!(URL_SAFE_NO_PAD.encode([31; 32]));
        let wrong_challenge = EnrollmentChallenge::from_trusted_document(
            &serde_json::to_vec(&wrong_challenge).unwrap(),
        )
        .unwrap();
        assert_eq!(
            verify_enrollment_proof(&wrong_challenge, &public, compact, verified_at).unwrap_err(),
            EnrollmentProofError::PayloadMismatch
        );
    }
}
