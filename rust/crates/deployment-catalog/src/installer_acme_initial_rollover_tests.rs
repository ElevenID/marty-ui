use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};

#[test]
fn expired_candidate_reference_alone_cannot_grant_original_preparation_authority() {
    let fixture = crate::installer_acme::tests::Fixture::new();
    let prior = fixture.finish().candidate.unwrap();
    let expiry = prior.metadata()["not_after"].as_u64().unwrap();
    let environment = prior.environment();
    let mut state = LockedMaintenance::open(fixture.installation()).unwrap();
    let configuration = BoundAcmeConfiguration::from_selection(state.inspection()).unwrap();
    let data = PermitData {
        schema: "elevenid.installer-acme-initial-rollover/v1".into(),
        installation_id: state.journal().installation_id(),
        environment,
        cycle: 1,
        prior_cycle: 0,
        prior_candidate: value(&prior).unwrap(),
        configuration_sha256: sha(&serde_json::to_vec(&configuration).unwrap()),
        // These are deliberately only fixture references. The test proves that
        // even a valid expired predecessor cannot bypass the actual setup gate.
        host_intent_sha256: "a".repeat(64),
        host_prepared_sha256: "b".repeat(64),
        created_at: expiry,
    };
    state
        .write_evidence_exclusive(
            &InitialRolloverPermit::record_name(environment, 1),
            &encode(&data).unwrap(),
        )
        .unwrap();
    assert!(
        InitialRolloverPermit::load(state.inspection(), environment, 1).is_err(),
        "future expiry cannot grant an early replacement"
    );
    fixture.advance(expiry - installer_acme::now().unwrap());
    let permit = InitialRolloverPermit::load(state.inspection(), environment, 1).unwrap();
    assert_eq!(permit.cycle(), 1);
    assert_eq!(
        permit.prior_candidate().unwrap().metadata(),
        prior.metadata()
    );
    assert!(matches!(
        permit.reason(),
        IssuanceReason::InitialCandidateExpired { .. }
    ));
    let saved = Ledger::load(state.inspection(), environment)
        .unwrap()
        .unwrap();
    let key = RetainedIngressKey::from_recorded_public_key(
        &state.journal().installation_id().to_string(),
        saved.binding.ingress_key_version,
        &STANDARD.decode(saved.binding.ingress_spki_base64).unwrap(),
    )
    .unwrap();
    assert!(permit
        .require_current(
            state.inspection(),
            fixture.installation(),
            &configuration,
            &key
        )
        .is_err());
    assert!(
        Ledger::load_cycle(state.inspection(), environment, 1)
            .unwrap()
            .is_none(),
        "no order stream is created without full original preparation"
    );
    assert_eq!(
        InitialRolloverPermit::load(state.inspection(), environment, 1)
            .unwrap()
            .sha256(),
        permit.sha256()
    );
}

#[test]
fn initial_replacement_refuses_a_live_predecessor_or_missing_completed_cycle() {
    let fixture = crate::installer_acme::tests::Fixture::new();
    let prior = fixture.finish().candidate.unwrap();
    let expiry = prior.metadata()["not_after"].as_u64().unwrap();
    fixture.advance(expiry - installer_acme::now().unwrap());
    let mut state = LockedMaintenance::open(fixture.installation()).unwrap();
    let configuration = BoundAcmeConfiguration::from_selection(state.inspection()).unwrap();
    for (cycle, prior_cycle, created_at) in [(1, 0, expiry - 1), (2, 1, expiry)] {
        let data = PermitData {
            schema: "elevenid.installer-acme-initial-rollover/v1".into(),
            installation_id: state.journal().installation_id(),
            environment: prior.environment(),
            cycle,
            prior_cycle,
            prior_candidate: value(&prior).unwrap(),
            configuration_sha256: sha(&serde_json::to_vec(&configuration).unwrap()),
            host_intent_sha256: "a".repeat(64),
            host_prepared_sha256: "b".repeat(64),
            created_at,
        };
        state
            .write_evidence_exclusive(
                &InitialRolloverPermit::record_name(prior.environment(), cycle),
                &encode(&data).unwrap(),
            )
            .unwrap();
        assert!(
            InitialRolloverPermit::load(state.inspection(), prior.environment(), cycle).is_err()
        );
        assert!(
            Ledger::load_cycle(state.inspection(), prior.environment(), cycle)
                .unwrap()
                .is_none()
        );
    }
}
