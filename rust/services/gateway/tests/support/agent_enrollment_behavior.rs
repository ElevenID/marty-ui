const ENROLLMENT_KEY: &str = "66666666-6666-4666-8666-666666666666";

// This is an authored transport fixture, not a cryptographic verification test.
// The Organization and binding suites verify real signatures independently.
fn enrollment_fixture(age_seconds: i64) -> (Value, String, Value) {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use marty_principal_runtime_binding::{
        jwk_sha256_thumbprint,
        managed_enrollment::{
            EnrollmentAlgorithm, EnrollmentChallenge, EnrollmentChallengeParameters,
            EnrollmentPolicy,
        },
    };
    use sha2::{Digest, Sha256};
    use uuid::Uuid;
    let jwk =
        json!({"crv":"Ed25519","kty":"OKP","x":"unPJ9ULpvU0f_1lwt90H2wh0Suyy7V-ebOWJUv3ihQo"});
    let fingerprint = jwk_sha256_thumbprint(&serde_json::to_vec(&jwk).unwrap()).unwrap();
    let now = Utc::now().timestamp() - age_seconds;
    let challenge = EnrollmentChallenge::new(EnrollmentChallengeParameters {
        challenge_id: Uuid::parse_str(ADMIN_REVIEW).unwrap(),
        organization_id: Uuid::parse_str(ADMIN_ORG).unwrap(),
        agent_id: Uuid::parse_str(ADMIN_AGENT).unwrap(),
        key_id: Uuid::parse_str(ENROLLMENT_KEY).unwrap(),
        administrator_id: Uuid::parse_str(ADMIN_USER).unwrap(),
        expected_revision: 1,
        key_algorithm: EnrollmentAlgorithm::EdDSA,
        key_thumbprint: fingerprint.clone(),
        runtime_instance_ref: "urn:test:runtime".into(),
        issuer: "https://issuer.example.invalid".into(),
        subject: "synthetic-agent".into(),
        session_ref: format!(
            "urn:marty:session:sha256:{:x}",
            Sha256::digest(ADMIN_SESSION.as_bytes())
        ),
        audience: "https://api.example/enrollment".into(),
        nonce: [7; 32],
        issued_at: now,
        expires_at: now + 120,
        policy: EnrollmentPolicy::new(
            "urn:test:enrollment-policy:v1".into(),
            1,
            vec![EnrollmentAlgorithm::ES256, EnrollmentAlgorithm::EdDSA],
            120,
        )
        .unwrap(),
    })
    .unwrap();
    let created = chrono::DateTime::<Utc>::from_timestamp(now, 0)
        .unwrap()
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let expires = chrono::DateTime::<Utc>::from_timestamp(now + 120, 0)
        .unwrap()
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let header = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(
            &json!({"alg":"EdDSA","typ":"marty-managed-enrollment+jws","kid":ENROLLMENT_KEY}),
        )
        .unwrap(),
    );
    let proof = format!(
        "{header}.{}.{}",
        challenge.payload_b64url(),
        URL_SAFE_NO_PAD.encode([1; 64])
    );
    let outer = json!({"profile":"urn:marty:managed-key-enrollment:v1","challenge_id":ADMIN_REVIEW,"organization_id":ADMIN_ORG,"agent_id":ADMIN_AGENT,"expected_revision":1,
        "challenge":challenge.document(),"signing_payload":challenge.payload_b64url(),"challenge_digest":challenge.digest(),"expires_at":expires,"recovered":false});
    let mut identity = synthetic_agent();
    identity["kind"] = json!("MANAGED");
    identity["revision"] = json!(2);
    identity["updated_at"] = json!(created);
    identity["principal"] =
        json!({"type":"SERVICE_ACCOUNT","id":format!("urn:marty:machine:{ADMIN_AGENT}")});
    identity["provenance"]["managed_enrollment"] = json!("KEY_CONTROL_VERIFIED");
    identity["keys"] = json!([{"key_id":ENROLLMENT_KEY,"algorithm":"EdDSA","status":"ACTIVE","public_key_jwk":jwk,"created_at":created,
        "fingerprint":{"basis":"JWK_RFC7638_SHA256","encoding":"BASE64URL_SHA256","value":fingerprint.encoded_value()}}]);
    let result = json!({"challenge_id":ADMIN_REVIEW,"organization_id":ADMIN_ORG,"agent_id":ADMIN_AGENT,"key_id":ENROLLMENT_KEY,
        "previous_revision":1,"enrolled_revision":2,"completed_at":created,"proof_digest":format!("sha256:{:x}",Sha256::digest(proof.as_bytes())),
        "challenge_digest":challenge.digest(),"enrollment":"KEY_CONTROL_VERIFIED","authority_status":"NOT_ASSESSED","identity":identity,"recovered":false});
    (outer, proof, result)
}

#[tokio::test]
async fn enrollment_requires_its_own_selection_and_forwards_current_session_only() {
    let path = format!("/v1/organizations/{ADMIN_ORG}/agents/{ADMIN_AGENT}/enrollment-challenges");
    let (state, _, upstream) = candidate_admin_test_state(true, false, false);
    assert_eq!(
        gateway_router(state)
            .oneshot(admin_request("POST", &path, r#"{"expected_revision":1}"#))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    assert!(upstream.calls.lock().unwrap().is_empty());
    let (state, provider, upstream) = candidate_admin_test_state(true, false, true);
    let (challenge, _, _) = enrollment_fixture(0);
    *upstream.response.lock().unwrap() = Some((200, challenge));
    let app = gateway_router(state);
    let mut request = admin_request("POST", &path, r#"{"expected_revision":1}"#);
    request
        .headers_mut()
        .insert("x-marty-enrollment-user-id", ADMIN_AGENT.parse().unwrap());
    request.headers_mut().insert(
        "x-marty-enrollment-session-ref",
        "attacker".parse().unwrap(),
    );
    assert_eq!(
        app.clone().oneshot(request).await.unwrap().status(),
        StatusCode::OK
    );
    {
        let calls = upstream.calls.lock().unwrap();
        let (_, request) = &calls[0];
        assert_eq!(
            admin_header(request, "x-marty-enrollment-user-id"),
            ADMIN_USER
        );
        assert_eq!(
            admin_header(request, "x-marty-enrollment-organization-id"),
            ADMIN_ORG
        );
        assert_eq!(
            admin_header(request, "x-required-permission"),
            "agent-identity:enroll"
        );
        assert!(admin_header(request, "x-marty-enrollment-session-ref")
            .starts_with("urn:marty:session:sha256:"));
        assert!(!request
            .headers
            .keys()
            .any(|key| key.eq_ignore_ascii_case("cookie")));
    }
    provider.mode.store(1, Ordering::SeqCst);
    assert_eq!(
        app.clone()
            .oneshot(admin_request("POST", &path, r#"{"expected_revision":1}"#))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(upstream.calls.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn enrollment_rejects_retargeted_or_noncanonical_challenge_presentations() {
    let path = format!("/v1/organizations/{ADMIN_ORG}/agents/{ADMIN_AGENT}/enrollment-challenges");
    let (state, _, upstream) = candidate_admin_test_state(true, false, true);
    let app = gateway_router(state);
    let (challenge, _, _) = enrollment_fixture(0);
    for (pointer, value) in [
        ("/challenge/organization_id", json!(ADMIN_AGENT)),
        ("/challenge/agent_id", json!(ADMIN_ORG)),
        ("/challenge/administrator_id", json!(ADMIN_AGENT)),
        (
            "/challenge/session_ref",
            json!(format!("urn:marty:session:sha256:{}", "f".repeat(64))),
        ),
        ("/expected_revision", json!(2)),
        ("/signing_payload", json!("replaced")),
        (
            "/challenge_digest",
            json!(format!("sha256:{}", "f".repeat(64))),
        ),
        ("/expires_at", json!("2020-01-01T00:00:00Z")),
    ] {
        let mut changed = challenge.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        *upstream.response.lock().unwrap() = Some((200, changed));
        assert_eq!(
            app.clone()
                .oneshot(admin_request("POST", &path, r#"{"expected_revision":1}"#))
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_GATEWAY,
            "{pointer}"
        );
    }
}

#[tokio::test]
async fn enrollment_completion_is_bound_to_submitted_proof_and_original_result() {
    let path = format!("/v1/organizations/{ADMIN_ORG}/agents/{ADMIN_AGENT}/enrollment-challenges/{ADMIN_REVIEW}/complete");
    let (state, _, upstream) = candidate_admin_test_state(true, false, true);
    let app = gateway_router(state);
    let (_, proof, result) = enrollment_fixture(0);
    let body = json!({"proof":proof}).to_string();
    *upstream.response.lock().unwrap() = Some((200, result.clone()));
    let response = app
        .clone()
        .oneshot(admin_request("POST", &path, &body))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    for (pointer, value) in [
        ("/proof_digest", json!(format!("sha256:{}", "f".repeat(64)))),
        ("/enrolled_revision", json!(3)),
        (
            "/identity/provenance/managed_enrollment",
            json!("NOT_ASSESSED"),
        ),
        ("/identity/keys/0/key_id", json!(ADMIN_AGENT)),
        (
            "/identity/keys/0/fingerprint/value",
            json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        ),
        ("/authority_status", json!("AUTHORIZED")),
        ("/challenge_id", json!(ADMIN_ORG)),
    ] {
        let mut changed = result.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        *upstream.response.lock().unwrap() = Some((200, changed));
        assert_eq!(
            app.clone()
                .oneshot(admin_request("POST", &path, &body))
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_GATEWAY,
            "{pointer}"
        );
    }
    for body in [
        r#"{"proof":"caller-asserted-success"}"#.to_owned(),
        json!({"proof":proof,"verified":true}).to_string(),
        json!({"proof":format!("{proof}=")}).to_string(),
    ] {
        assert_eq!(
            app.clone()
                .oneshot(admin_request("POST", &path, &body))
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
}

#[tokio::test]
async fn enrollment_read_returns_historical_consumed_snapshot_after_expiry() {
    let path = format!(
        "/v1/organizations/{ADMIN_ORG}/agents/{ADMIN_AGENT}/enrollment-challenges/{ADMIN_REVIEW}"
    );
    let (state, _, upstream) = candidate_admin_test_state(true, false, true);
    let (challenge, _, mut result) = enrollment_fixture(3600);
    result["recovered"] = json!(true);
    let record =
        json!({"challenge":challenge,"state":"CONSUMED","result":result,"invalidated_at":null});
    *upstream.response.lock().unwrap() = Some((200, record.clone()));
    let response = gateway_router(state)
        .oneshot(admin_request("GET", &path, ""))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        serde_json::from_slice::<Value>(&to_bytes(response.into_body(), 131072).await.unwrap())
            .unwrap(),
        record
    );
    assert_eq!(
        admin_header(
            &upstream.calls.lock().unwrap()[0].1,
            "x-required-permission"
        ),
        "agent-identity:view"
    );
}
