use super::*;

fn decision(fixture: &Fixture, cycle: u64) -> terminal::TerminalRetryDecision {
    let view = LockedInspection::open(&fixture.installation).unwrap();
    terminal_retry_decision(
        &view,
        &fixture.installation,
        AcmeEnvironment::Staging,
        cycle,
        now().unwrap(),
    )
    .unwrap()
}

#[test]
fn authenticated_terminal_response_keeps_long_retry_after_across_reopen() {
    let mut fixture = Fixture::new();
    let prior = fixture.finish().candidate.unwrap();
    next_certificate(&mut fixture, 2);
    let binding = fixture_cycle(&fixture, 1, 0);
    let at = now().unwrap();
    let retry_at = at + 48 * 3600;
    {
        let mut ca = fixture.ca.state.lock().unwrap();
        ca.order_invalid = true;
        ca.terminal_retry_after = Some(retry_at);
    }
    let result = run_cycle(&fixture, &binding).unwrap();
    assert_eq!(result.report["stage"], "terminal");
    assert_eq!(result.report["failure"], "order_invalid");
    let first = decision(&fixture, 1);
    assert_eq!(first.eligible_at(), Some(retry_at));
    assert!(!first.is_due());
    assert_eq!(first.blocking_dependency(), "acme_terminal_retry_cooldown");
    let evidence = first.evidence().unwrap();
    assert_eq!(evidence.cycle(), 1);
    assert_eq!(evidence.receipt_sha256().len(), 64);
    let requests = fixture.ca.state.lock().unwrap().requests.clone();
    fixture.advance(48 * 3600 - 1);
    assert_eq!(decision(&fixture, 1).evidence(), Some(evidence.clone()));
    assert!(!decision(&fixture, 1).is_due());
    fixture.advance(1);
    assert!(decision(&fixture, 1).is_due());
    let view = LockedInspection::open(&fixture.installation).unwrap();
    require_terminal_retry_evidence(
        &view,
        &fixture.installation,
        AcmeEnvironment::Staging,
        &prior,
        &evidence,
        retry_at,
    )
    .unwrap();
    let mut different_predecessor = prior.clone();
    different_predecessor.enrolment_receipt_sha256 = "e".repeat(64);
    assert!(require_terminal_retry_evidence(
        &view,
        &fixture.installation,
        AcmeEnvironment::Staging,
        &different_predecessor,
        &evidence,
        retry_at,
    )
    .is_err());
    assert!(require_terminal_retry_evidence(
        &view,
        &fixture.installation,
        AcmeEnvironment::Staging,
        &prior,
        &evidence,
        retry_at - 1,
    )
    .is_err());
    let changed: terminal::TerminalRetryEvidence = serde_json::from_value(json!({
        "cycle":1,"receipt_sha256":evidence.receipt_sha256(),"eligible_at":retry_at-1
    }))
    .unwrap();
    assert!(require_terminal_retry_evidence(
        &view,
        &fixture.installation,
        AcmeEnvironment::Staging,
        &prior,
        &changed,
        retry_at,
    )
    .is_err());
    assert_eq!(fixture.ca.state.lock().unwrap().requests, requests);
}

#[test]
fn terminal_authorization_retains_earlier_successful_response_floor() {
    for terminal_point in ["initial_invalid", "refresh_invalid", "refresh_expired"] {
        for order_hint_is_later in [false, true] {
            let mut fixture = Fixture::new();
            let prior = fixture.finish().candidate.unwrap();
            next_certificate(&mut fixture, 2);
            let binding = fixture_cycle(&fixture, 1, 0);
            if terminal_point != "initial_invalid" {
                // Preserve a real published challenge before the later exact-
                // target refresh becomes terminal without its own retry hint.
                run_cycle(&fixture, &binding).unwrap();
                fixture.advance(20);
            }
            let observed = now().unwrap();
            let floor = observed + 1800;
            {
                let mut ca = fixture.ca.state.lock().unwrap();
                ca.terminal_retry_after = Some(observed + if order_hint_is_later { 1800 } else { 900 });
                ca.authorization_retry_after = Some(observed + if order_hint_is_later { 900 } else { 1800 });
                // Only the successful first authorization carries this hint;
                // the later terminal authorization has no Retry-After header.
                ca.authorization_retry_after_first_only = true;
                if terminal_point == "refresh_expired" {
                    ca.target_change = Some(TargetChange::ExpiredOnRefresh);
                } else {
                    ca.authorization_terminal_index = Some(1);
                    ca.authorization_terminal_after_reads = if terminal_point == "initial_invalid" { 1 } else { 3 };
                }
            }
            let result = run_cycle(&fixture, &binding).unwrap();
            assert_eq!(result.report["stage"], "terminal");
            assert_eq!(result.report["failure"], if terminal_point == "refresh_expired" { "authorization_expired" } else { "authorization_invalid" });
            let evidence = decision(&fixture, 1).evidence().unwrap();
            assert_eq!(evidence.eligible_at(), floor);
            assert!(!decision(&fixture, 1).is_due());
            {
                let view = LockedInspection::open(&fixture.installation).unwrap();
                let ledger = Ledger::load_cycle(&view, AcmeEnvironment::Staging, 1).unwrap().unwrap();
                let terminal = ledger.state.terminal_retry.as_ref().unwrap();
                assert_eq!(terminal.retry_not_before, Some(floor));
                assert!(terminal.withdrawal_confirmed_at.is_some());
            }
            let requests = fixture.ca.state.lock().unwrap().requests.clone();
            fixture.advance(1799);
            assert!(!decision(&fixture, 1).is_due());
            run_cycle(&fixture, &binding).unwrap();
            assert_eq!(fixture.ca.state.lock().unwrap().requests, requests);
            fixture.advance(1);
            assert!(decision(&fixture, 1).is_due());
            let view = LockedInspection::open(&fixture.installation).unwrap();
            require_terminal_retry_evidence(&view, &fixture.installation, AcmeEnvironment::Staging, &prior, &evidence, floor).unwrap();
            let ca = fixture.ca.state.lock().unwrap();
            assert_eq!(ca.new_orders, 2);
            assert_eq!(ca.finalizations, 1);
        }
    }
}

#[test]
fn expired_known_order_preserves_its_previously_retained_later_deadline() {
    let mut fixture = Fixture::new();
    fixture.finish();
    next_certificate(&mut fixture, 2);
    let binding = fixture_cycle(&fixture, 1, 0);
    run_cycle(&fixture, &binding).unwrap();
    let deadline = {
        let mut state = LockedMaintenance::open(&fixture.installation).unwrap();
        let mut saved = Ledger::load_cycle(state.inspection(), AcmeEnvironment::Staging, 1)
            .unwrap()
            .unwrap();
        let deadline = saved.state.order.as_ref().unwrap().expires_at + 1200;
        let mut next = saved.state.clone();
        next.next_poll_at = Some(deadline);
        saved.append(&mut state, next, now().unwrap()).unwrap();
        deadline
    };
    fixture.advance(deadline - 1199 - now().unwrap());
    let requests = fixture.ca.state.lock().unwrap().requests.clone();
    let result = run_cycle(&fixture, &binding).unwrap();
    assert_eq!(result.report["failure"], "order_expired");
    assert_eq!(decision(&fixture, 1).eligible_at(), Some(deadline));
    assert_eq!(fixture.ca.state.lock().unwrap().requests, requests);
}

#[test]
fn interrupted_withdrawal_is_local_only_and_new_projection_preserves_historical_proof() {
    let mut fixture = Fixture::new();
    let prior = fixture.finish().candidate.unwrap();
    next_certificate(&mut fixture, 2);
    let binding = fixture_cycle(&fixture, 1, 0);
    run_cycle(&fixture, &binding).unwrap();
    {
        let mut state = LockedMaintenance::open(&fixture.installation).unwrap();
        let mut saved = Ledger::load_cycle(state.inspection(), AcmeEnvironment::Staging, 1)
            .unwrap()
            .unwrap();
        let observed = now().unwrap();
        let terminal = terminal::observation(
            state.inspection(),
            &saved,
            "authorization_invalid",
            None,
            observed,
        )
        .unwrap();
        let mut next = saved.state.clone();
        next.stage = Stage::Terminal;
        next.failure = Some("authorization_invalid".into());
        next.retry = None;
        next.next_poll_at = None;
        next.pending_challenge = None;
        next.terminal_retry = terminal;
        saved.append(&mut state, next, observed).unwrap();
        // Simulate interruption after recording the empty projection but before
        // publishing it: the actual response file still contains challenges.
        let mut next = saved.state.clone();
        next.projection = Some(
            projection_for(
                &fixture.inputs(),
                &saved.state.authorizations,
                0,
                saved.state.projection.as_ref(),
                true,
            )
            .unwrap(),
        );
        saved.append(&mut state, next, observed).unwrap();
    }
    let waiting = decision(&fixture, 1);
    assert!(waiting.withdrawal_pending());
    assert!(!waiting.is_due());
    assert!(waiting.evidence().is_none());
    let requests = fixture.ca.state.lock().unwrap().requests.clone();
    assert_eq!(
        run_cycle(&fixture, &binding).unwrap().report["stage"],
        "terminal"
    );
    assert_eq!(fixture.ca.state.lock().unwrap().requests, requests);
    fixture.advance(300);
    let evidence = decision(&fixture, 1).evidence().unwrap();
    assert!(decision(&fixture, 1).is_due());
    let admitted_at = now().unwrap();
    next_certificate(&mut fixture, 3);
    let successor = fixture_cycle(&fixture, 2, 0);
    let intent_path = fixture
        .installation
        .join("evidence")
        .join(crate::installer_generation_maintenance::RenewalPermit::record_name(2));
    let intent = std::fs::read(&intent_path).unwrap();
    {
        let view = LockedInspection::open(&fixture.installation).unwrap();
        assert!(Ledger::load_cycle(&view, AcmeEnvironment::Staging, 2)
            .unwrap()
            .is_none());
    }
    // Reopening after the permit but before record zero uses the same binding.
    run_cycle(&fixture, &successor).unwrap();
    let new_orders = fixture.ca.state.lock().unwrap().new_orders;
    run_cycle(&fixture, &successor).unwrap();
    assert_eq!(fixture.ca.state.lock().unwrap().new_orders, new_orders);
    assert_eq!(std::fs::read(&intent_path).unwrap(), intent);
    let view = LockedInspection::open(&fixture.installation).unwrap();
    require_terminal_retry_evidence(
        &view,
        &fixture.installation,
        AcmeEnvironment::Staging,
        &prior,
        &evidence,
        admitted_at,
    )
    .unwrap();
    assert_eq!(fixture.ca.state.lock().unwrap().registration_posts, 1);
}

#[test]
fn repeated_known_terminal_attempts_increase_cooldown_with_a_bounded_delay() {
    let mut fixture = Fixture::new();
    fixture.finish();
    for cycle in 1..=3 {
        next_certificate(&mut fixture, (cycle + 1) as u8);
        let binding = fixture_cycle(&fixture, cycle, 0);
        fixture.ca.state.lock().unwrap().order_invalid = true;
        let observed = now().unwrap();
        run_cycle(&fixture, &binding).unwrap();
        let expected = 300u64 << (cycle - 1);
        assert_eq!(
            decision(&fixture, cycle).eligible_at(),
            Some(observed + expected)
        );
        fixture.advance(expected);
        assert!(decision(&fixture, cycle).is_due());
    }
    assert_eq!(ledger::terminal_cooldown(100_000), 6 * 3600);
}

#[test]
fn unknown_orders_and_unproven_terminal_reasons_never_authorize_a_new_cycle() {
    for reason in [
        "order_outcome_unknown",
        "retry_limit",
        "account_unavailable",
        "certificate_refused",
        "legacy_order_expired",
    ] {
        let mut fixture = Fixture::new();
        fixture.finish();
        next_certificate(&mut fixture, 2);
        let binding = fixture_cycle(&fixture, 1, 0);
        if reason == "order_outcome_unknown" {
            fixture.ca.state.lock().unwrap().lose_order = true;
            run_cycle(&fixture, &binding).unwrap();
        } else {
            run_cycle(&fixture, &binding).unwrap();
            let mut state = LockedMaintenance::open(&fixture.installation).unwrap();
            let mut saved = Ledger::load_cycle(state.inspection(), AcmeEnvironment::Staging, 1)
                .unwrap()
                .unwrap();
            if reason == "legacy_order_expired" {
                let mut next = saved.state.clone();
                next.stage = Stage::Terminal;
                next.failure = Some("order_expired".into());
                next.retry = None;
                next.next_poll_at = None;
                next.pending_challenge = None;
                saved.append(&mut state, next, now().unwrap()).unwrap();
                withdraw(&mut state, &fixture.inputs(), &mut saved).unwrap();
            } else {
                terminal(&mut state, &fixture.inputs(), &mut saved, reason).unwrap();
            }
        }
        let requests = fixture.ca.state.lock().unwrap().requests.clone();
        fixture.advance(48 * 3600);
        let decision = decision(&fixture, 1);
        assert!(!decision.is_due());
        assert!(decision.evidence().is_none());
        assert_eq!(fixture.ca.state.lock().unwrap().requests, requests);
    }
}

#[test]
fn lost_finalize_crossing_old_expiry_during_backoff_never_becomes_a_terminal_retry() {
    let mut fixture = Fixture::with_certificate_lifetime(72);
    fixture.finish();
    next_certificate(&mut fixture, 2);
    let binding = fixture_cycle(&fixture, 1, 0);
    run_cycle(&fixture, &binding).unwrap();
    fixture.advance(20);
    run_cycle(&fixture, &binding).unwrap();
    let expiry = {
        let view = LockedInspection::open(&fixture.installation).unwrap();
        Ledger::load_cycle(&view, AcmeEnvironment::Staging, 1)
            .unwrap()
            .unwrap()
            .state
            .order
            .unwrap()
            .expires_at
    };
    fixture.advance(expiry - 1 - now().unwrap());
    fixture.ca.state.lock().unwrap().lose_finalize = true;
    let pending = run_cycle(&fixture, &binding).unwrap();
    assert_eq!(pending.report["stage"], "finalize_pending");
    assert!(fixture.ca.state.lock().unwrap().finalized);
    let requests = fixture.ca.state.lock().unwrap().requests.clone();
    fixture.advance(2);
    let pending = run_cycle(&fixture, &binding).unwrap();
    assert_eq!(pending.report["stage"], "finalize_pending");
    assert!(pending.candidate.is_none());
    assert_eq!(fixture.ca.state.lock().unwrap().requests, requests);
    let retry = decision(&fixture, 1);
    assert!(!retry.is_due());
    assert!(retry.evidence().is_none());
    fixture.advance(20);
    let complete = run_cycle(&fixture, &binding).unwrap();
    assert!(complete.candidate.is_some());
    assert_eq!(complete.report["stage"], "complete");
    let ca = fixture.ca.state.lock().unwrap();
    assert_eq!(ca.registration_posts, 1);
    assert_eq!(ca.new_orders, 2);
    assert_eq!(ca.finalizations, 2);
}
