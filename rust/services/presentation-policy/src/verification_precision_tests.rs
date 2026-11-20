use std::sync::atomic::AtomicUsize;

fn precise_fixture(
    mode: Mode,
    prepared_offset_micros: i64,
    evaluated_offset_micros: i64,
) -> (Fixture, Arc<AtomicUsize>) {
    let (mut fixture, owners) = fixture(mode, 0);
    let base = i64::try_from(fixture.now).unwrap() * 1_000_000;
    let reads = Arc::new(AtomicUsize::new(0));
    let observed_reads = reads.clone();
    fixture.orchestrator = VerifiedFactsOrchestrator::with_microsecond_clock(
        Arc::new(RustCredentialKernel),
        owners.clone(),
        owners,
        Arc::new(
            move || match observed_reads.fetch_add(1, Ordering::SeqCst) {
                0 => base + prepared_offset_micros,
                1 => base + evaluated_offset_micros,
                _ => {
                    panic!("one preparation and one final observation supply both clock precisions")
                }
            },
        ),
    )
    .unwrap();
    (fixture, reads)
}

#[tokio::test]
async fn native_managed_evaluation_preserves_same_second_post_intent_ordering() {
    // These offsets reproduce the real owner rejection: flooring the Policy
    // observation to seconds placed it 307,581 microseconds before the intent.
    let (fixture, reads) = precise_fixture(Mode::Valid, 325_905, 900_001);
    let base = i64::try_from(fixture.now).unwrap() * 1_000_000;
    let intent_created_at = base + 307_581;
    let material = fixture.verify(&fixture.request).await;
    assert_eq!(reads.load(Ordering::SeqCst), 2);
    assert_eq!(
        material.policy_facts()["evaluation_time_epoch_seconds"],
        fixture.now
    );
    let query = material.authenticated_sd_jwt_query().unwrap().clone();
    let authority = material.managed_credential_authority().unwrap().clone();
    let public_query = serde_json::to_value(&query).unwrap();
    assert_eq!(public_query["checked_at_epoch_seconds"], fixture.now);
    assert!(public_query.get("observed_at").is_none());
    assert!(public_query.get("checked_at_epoch_micros").is_none());

    let output =
        evaluate_verified_material_for_policy(material, &fixture.policy, &fixture.request).unwrap();
    let evidence = marty_oid4vp_contract::ManagedPolicyEvidenceProjectionV2::from_json(
        &output[marty_oid4vp_contract::MANAGED_POLICY_EVIDENCE_V2].to_string(),
    )
    .unwrap();
    assert_eq!(evidence.validity.evaluated_at_epoch_micros, base + 900_001);
    assert!(evidence.validity.evaluated_at_epoch_micros >= intent_created_at);
    assert_eq!(
        chrono::DateTime::parse_from_rfc3339(output["evaluation_timestamp"].as_str().unwrap())
            .unwrap()
            .timestamp_micros(),
        evidence.validity.evaluated_at_epoch_micros
    );
    assert_eq!(
        evidence.validity.valid_until_epoch_micros,
        base + 60_000_000,
        "retaining precision must not extend any authenticated deadline"
    );

    for false_time in [base, base + 900_002] {
        let mut relabeled = output.clone();
        relabeled["evaluation_timestamp"] =
            json!(chrono::DateTime::from_timestamp_micros(false_time)
                .unwrap()
                .to_rfc3339());
        assert!(crate::evaluation_validity::managed_validity(
            &fixture.policy,
            &fixture.request,
            &query,
            &authority,
            &relabeled,
        )
        .is_err());
    }
}

#[tokio::test]
async fn native_managed_evaluation_derives_both_precisions_from_one_boundary_sample() {
    let (fixture, reads) = precise_fixture(Mode::Valid, 999_999, 1_000_001);
    let base = i64::try_from(fixture.now).unwrap() * 1_000_000;
    let material = fixture.verify(&fixture.request).await;
    assert_eq!(reads.load(Ordering::SeqCst), 2);
    assert_eq!(
        material.policy_facts()["evaluation_time_epoch_seconds"],
        fixture.now + 1
    );
    let output =
        evaluate_verified_material_for_policy(material, &fixture.policy, &fixture.request).unwrap();
    let evidence = marty_oid4vp_contract::ManagedPolicyEvidenceProjectionV2::from_json(
        &output[marty_oid4vp_contract::MANAGED_POLICY_EVIDENCE_V2].to_string(),
    )
    .unwrap();
    assert_eq!(
        evidence.validity.evaluated_at_epoch_micros,
        base + 1_000_001
    );
    assert_eq!(
        evidence.policy_result["evaluation_time_epoch_seconds"],
        fixture.now + 1
    );
    evidence.validate_historical().unwrap();
}

#[tokio::test]
async fn native_managed_evaluation_rejects_subsecond_clock_rollback() {
    let (fixture, reads) = precise_fixture(Mode::Valid, 500_001, 500_000);
    let result = fixture
        .orchestrator
        .verify_material(&fixture.policy, &fixture.request)
        .await;
    assert_eq!(reads.load(Ordering::SeqCst), 2);
    assert!(matches!(
        result,
        Err(PresentationVerificationError::Failed(ref code))
            if code == "PRESENTATION_POLICY.SD_JWT_EXPIRED_DURING_EVALUATION"
    ));
}

#[tokio::test]
async fn native_managed_evaluation_keeps_fractional_holder_deadline_exclusive() {
    for (evaluated_offset_micros, expected_allow) in [(3_249_999, true), (3_250_000, false)] {
        let (mut fixture, reads) = precise_fixture(Mode::Valid, 1, evaluated_offset_micros);
        fixture.request = fixture.request_for_token(bind_disclosed_sd_jwt_with_claims(
            &disclosed_sd_jwt(&fixture.claims, &["email"]),
            json!({
                "aud": AUDIENCE,
                "nonce": fixture.nonce,
                "iat": fixture.now,
                "exp": fixture.now as f64 + 3.25,
            }),
        ));
        let material = fixture.verify(&fixture.request).await;
        assert_eq!(reads.load(Ordering::SeqCst), 2);
        let output =
            evaluate_verified_material_for_policy(material, &fixture.policy, &fixture.request);
        assert_eq!(output.is_ok(), expected_allow);
        if let Ok(output) = output {
            let validity = marty_oid4vp_contract::PolicyEvaluationValidityV1::from_json(
                &output[marty_oid4vp_contract::POLICY_EVALUATION_VALIDITY].to_string(),
            )
            .unwrap();
            let base = i64::try_from(fixture.now).unwrap() * 1_000_000;
            assert_eq!(validity.evaluated_at_epoch_micros, base + 3_249_999);
            assert_eq!(validity.valid_until_epoch_micros, base + 3_250_000);
            validity.validate_at(base + 3_249_999).unwrap();
            assert!(validity.validate_at(base + 3_250_000).is_err());
        }
    }
}

#[tokio::test]
async fn native_managed_evaluation_rejects_facts_relabeling_the_sealed_observation() {
    let (fixture, _) = precise_fixture(Mode::Valid, 1, 999_999);
    let mut material = fixture.verify(&fixture.request).await;
    material.policy_facts["evaluation_time_epoch_seconds"] = json!(fixture.now + 1);
    assert!(
        evaluate_verified_material_for_policy(material, &fixture.policy, &fixture.request).is_err()
    );
}
