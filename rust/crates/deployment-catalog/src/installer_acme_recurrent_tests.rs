// The private driver is exercised with in-memory CA fixtures. These public
// fixture intents do not construct a production generation-renewal capability.
use super::*;
use crate::installer_acme_state::{IssuanceReason, RenewalBinding};

fn fixture_cycle(fixture: &Fixture, cycle: u64, prior_cycle: u64) -> Binding {
    let mut state = LockedMaintenance::open(&fixture.installation).unwrap();
    let prior = Ledger::load_cycle(state.inspection(), AcmeEnvironment::Staging, prior_cycle)
        .unwrap()
        .unwrap();
    assert_eq!(prior.state.stage, Stage::Complete);
    let permit = serde_json::to_vec(&json!({"fixture_only":true,"cycle":cycle,
        "prior_receipt":prior.digest,"created_at":now().unwrap()}))
    .unwrap();
    state
        .write_evidence_exclusive(
            &crate::installer_generation_maintenance::RenewalPermit::record_name(cycle),
            &permit,
        )
        .unwrap();
    let mut binding = bind_inputs(state.inspection(), &fixture.inputs()).unwrap();
    binding.cycle = cycle;
    binding.renewal = Some(RenewalBinding {
        permit_sha256: ledger::hash(&permit),
        configuration_sha256: ledger::hash(&serde_json::to_vec(&fixture.configuration).unwrap()),
        reason: IssuanceReason::SelectedGenerationDue {
            generation_binding_sha256: "a".repeat(64),
            schedule_sha256: "b".repeat(64),
        },
        prior_cycle,
        prior_enrolment_receipt_sha256: prior.digest,
        account_url: prior.state.account_url.unwrap(),
        created_at: now().unwrap(),
    });
    binding.configuration(state.inspection()).unwrap();
    binding
}

fn next_certificate(fixture: &mut Fixture, serial: u8) {
    let mut leaf = Certificate::from_pem(&fixture.ca.certificate).unwrap();
    leaf.tbs_certificate.serial_number =
        x509_cert::serial_number::SerialNumber::new(&[serial]).unwrap();
    let expiry = leaf.tbs_certificate.validity.not_after.to_unix_duration();
    leaf.tbs_certificate.validity.not_after = (UNIX_EPOCH + expiry + Duration::from_secs(120))
        .try_into()
        .unwrap();
    fixture.ca.certificate = sign_certificate(leaf, &fixture.ca_key)
        .to_pem(LineEnding::LF)
        .unwrap();
    let mut ca = fixture.ca.state.lock().unwrap();
    ca.order_exists = false;
    ca.order_invalid = false;
    ca.terminal_retry_after = None;
    ca.ready = [false; 2];
    ca.finalized = false;
    ca.authorization_reads = [0; 2];
    ca.target_change = None;
    ca.valid_order_expires = None;
}

fn run_cycle(fixture: &Fixture, binding: &Binding) -> Result<EnrolmentOutcome> {
    let mut state = LockedMaintenance::open(&fixture.installation)?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(drive(
            &mut state,
            &fixture.inputs(),
            binding.clone(),
            fixture.signer.clone(),
            Box::new(fixture.ca.clone()),
        ))
}

fn finish_cycle(fixture: &Fixture, binding: &Binding) -> AcmeCandidate {
    for _ in 0..8 {
        let result = run_cycle(fixture, binding).unwrap();
        if let Some(candidate) = result.candidate {
            return candidate;
        }
        fixture.advance(20);
    }
    panic!("fixture did not finish its recurring stream")
}

#[test]
fn two_subsequent_cycles_keep_one_account_and_exact_csr_with_independent_receipts() {
    let mut fixture = Fixture::new();
    let initial = fixture.finish().candidate.unwrap();
    assert_eq!(initial.cycle(), 0);
    assert!(serde_json::to_value(&initial)
        .unwrap()
        .get("cycle")
        .is_none());
    let initial_digest = initial.enrolment_receipt_sha256().to_owned();
    let mut previous = initial;
    for cycle in 1..=2 {
        next_certificate(&mut fixture, (cycle + 1) as u8);
        let binding = fixture_cycle(&fixture, cycle, cycle - 1);
        let candidate = finish_cycle(&fixture, &binding);
        assert_eq!(candidate.cycle(), cycle);
        assert_eq!(serde_json::to_value(&candidate).unwrap()["cycle"], cycle);
        assert_ne!(candidate.order_url, previous.order_url);
        assert_ne!(
            candidate.metadata()["leaf_der_sha256"],
            previous.metadata()["leaf_der_sha256"]
        );
        assert_eq!(candidate.csr_sha256, previous.csr_sha256);
        let view = LockedInspection::open(&fixture.installation).unwrap();
        let saved = Ledger::load_cycle(&view, AcmeEnvironment::Staging, cycle)
            .unwrap()
            .unwrap();
        assert_eq!(saved.state.stage, Stage::Complete);
        assert_eq!(
            saved.binding.csr_der_base64,
            STANDARD.encode(fixture.csr.der())
        );
        assert_eq!(
            Ledger::load(&view, AcmeEnvironment::Staging)
                .unwrap()
                .unwrap()
                .digest,
            initial_digest
        );
        let reopened = retained_candidate(&view, AcmeEnvironment::Staging, cycle).unwrap();
        assert_eq!(
            serde_json::to_value(&reopened).unwrap(),
            serde_json::to_value(&candidate).unwrap()
        );
        let schedule = crate::installer_acme_renewal::for_candidate(&view, &candidate)
            .unwrap()
            .unwrap();
        assert_eq!(schedule.report().unwrap()["cycle"], cycle);
        assert_eq!(
            schedule.report().unwrap()["schedule_receipt_sha256"],
            schedule.receipt_sha256()
        );
        previous = candidate;
    }
    let ca = fixture.ca.state.lock().unwrap();
    assert_eq!(ca.registration_posts, 1);
    assert_eq!(ca.lookup_posts, 0);
    assert_eq!(ca.new_orders, 3);
    assert_eq!(ca.finalizations, 3);
}

#[test]
fn uncertain_recurring_new_order_is_retained_and_never_reposted() {
    let mut fixture = Fixture::new();
    fixture.finish();
    next_certificate(&mut fixture, 2);
    let binding = fixture_cycle(&fixture, 1, 0);
    fixture.ca.state.lock().unwrap().lose_order = true;
    let pending = run_cycle(&fixture, &binding).unwrap();
    assert_eq!(pending.report["order_outcome_unknown"], true);
    assert!(pending.candidate.is_none());
    let requests = fixture.ca.state.lock().unwrap().requests.clone();
    fixture.advance(24 * 3600);
    let retry = run_cycle(&fixture, &binding).unwrap();
    assert_eq!(retry.report["stage"], "order_pending");
    assert_eq!(fixture.ca.state.lock().unwrap().requests, requests);
    assert_eq!(fixture.ca.state.lock().unwrap().new_orders, 2);
    let view = LockedInspection::open(&fixture.installation).unwrap();
    assert_eq!(
        Ledger::load(&view, AcmeEnvironment::Staging)
            .unwrap()
            .unwrap()
            .state
            .stage,
        Stage::Complete
    );
    assert!(retained_candidate(&view, AcmeEnvironment::Staging, 1).is_err());
}

#[test]
fn known_recurring_order_resumes_after_lost_finalize_without_new_account_or_order() {
    let mut fixture = Fixture::new();
    fixture.finish();
    next_certificate(&mut fixture, 2);
    let binding = fixture_cycle(&fixture, 1, 0);
    fixture.ca.state.lock().unwrap().lose_finalize = true;
    let candidate = finish_cycle(&fixture, &binding);
    assert_eq!(candidate.cycle(), 1);
    let ca = fixture.ca.state.lock().unwrap();
    assert_eq!(ca.new_orders, 2);
    assert_eq!(ca.finalizations, 2);
    assert_eq!(ca.registration_posts, 1);
    assert_eq!(ca.lookup_posts, 0);
}

#[test]
fn expired_complete_candidate_is_historical_and_keeps_original_admission_timestamp() {
    let fixture = Fixture::new();
    let initial = fixture.finish().candidate.unwrap();
    let expired = initial.metadata()["not_after"].as_u64().unwrap() + 1;
    TEST_TIME.with(|value| value.set(Some(expired)));
    let view = LockedInspection::open(&fixture.installation).unwrap();
    let historical = retained_candidate(&view, AcmeEnvironment::Staging, 0).unwrap();
    assert_eq!(historical.metadata(), initial.metadata());
    assert_eq!(
        historical.enrolment_receipt_sha256(),
        initial.enrolment_receipt_sha256()
    );
    assert!(certificates::admit_staging_test_at(
        historical.fullchain_pem().as_bytes(),
        fixture.root_pem.as_bytes(),
        &fixture.configuration.certificate_identity().unwrap(),
        &fixture.ingress_key,
        Duration::from_secs(expired),
    )
    .is_err());
}

#[test]
fn retained_recurring_candidate_rejects_changed_permit_and_cross_cycle_rebinding() {
    let mut fixture = Fixture::new();
    fixture.finish();
    next_certificate(&mut fixture, 2);
    let binding = fixture_cycle(&fixture, 1, 0);
    finish_cycle(&fixture, &binding);
    let view = LockedInspection::open(&fixture.installation).unwrap();
    let source = fixture
        .installation
        .join("evidence/acme-staging-order-00000000000000000001-000000.json");
    let copied = fixture
        .installation
        .join("evidence/acme-staging-order-00000000000000000002-000000.json");
    std::fs::copy(source, &copied).unwrap();
    std::fs::set_permissions(&copied, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(Ledger::load_cycle(&view, AcmeEnvironment::Staging, 2).is_err());
    std::fs::remove_file(copied).unwrap();
    let intent = fixture
        .installation
        .join("evidence")
        .join(crate::installer_generation_maintenance::RenewalPermit::record_name(1));
    let original = std::fs::read(&intent).unwrap();
    let mut changed = original.clone();
    changed.push(b' ');
    std::fs::write(&intent, changed).unwrap();
    assert!(retained_candidate(&view, AcmeEnvironment::Staging, 1).is_err());
    std::fs::write(&intent, original).unwrap();
    assert!(retained_candidate(&view, AcmeEnvironment::Staging, 1).is_ok());
}

#[test]
fn recurring_stream_has_no_account_creation_stages_and_original_bytes_omit_new_fields() {
    let fixture = Fixture::new();
    fixture.finish();
    let binding = fixture_cycle(&fixture, 1, 0);
    let mut state = LockedMaintenance::open(&fixture.installation).unwrap();
    let mut saved = Ledger::begin(&mut state, binding, now().unwrap()).unwrap();
    assert_eq!(saved.state.stage, Stage::AccountBound);
    assert_eq!(
        saved.state.account_url.as_deref(),
        Some(format!("{CA}/account/1").as_str())
    );
    assert!(saved
        .append(&mut state, ledger::State::prepared(), now().unwrap())
        .is_err());
    let original = Ledger::load(state.inspection(), AcmeEnvironment::Staging)
        .unwrap()
        .unwrap();
    let json = serde_json::to_value(original.binding).unwrap();
    assert!(json.get("cycle").is_none());
    assert!(json.get("renewal").is_none());
}

#[test]
fn a_new_order_cannot_relabel_the_old_leaf_or_its_unchanged_expiry_as_a_renewal() {
    for identical_leaf in [true, false] {
        let mut fixture = Fixture::new();
        fixture.finish();
        let original = fixture.ca.certificate.clone();
        next_certificate(&mut fixture, 2);
        if identical_leaf {
            fixture.ca.certificate = original;
        } else {
            let mut leaf = Certificate::from_pem(&fixture.ca.certificate).unwrap();
            leaf.tbs_certificate.validity.not_after = Certificate::from_pem(&original)
                .unwrap()
                .tbs_certificate
                .validity
                .not_after;
            fixture.ca.certificate = sign_certificate(leaf, &fixture.ca_key)
                .to_pem(LineEnding::LF)
                .unwrap();
        }
        let binding = fixture_cycle(&fixture, 1, 0);
        let mut stopped = false;
        for _ in 0..8 {
            let result = run_cycle(&fixture, &binding).unwrap();
            assert!(result.candidate.is_none());
            if result.report["stage"] == "terminal" {
                assert_eq!(result.report["failure"], "certificate_refused");
                stopped = true;
                break;
            }
            fixture.advance(20);
        }
        assert!(stopped);
        assert_eq!(fixture.ca.state.lock().unwrap().new_orders, 2);
    }
}

#[path = "installer_acme_terminal_tests.rs"]
mod terminal_retry;
