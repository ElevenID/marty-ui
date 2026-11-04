//! Offline real-protocol regressions. Each run reopens retained state; the CA
//! and clock are fixtures, not a live CA, process reboot or deployed host.
use super::*;

fn retained(fixture: &Fixture) -> Ledger {
    let view = LockedInspection::open(&fixture.installation).unwrap();
    Ledger::load(&view, AcmeEnvironment::Staging)
        .unwrap()
        .unwrap()
}

fn advance_to_due(fixture: &Fixture) {
    let saved = retained(fixture);
    advance_to_retained_due(fixture, &saved);
}

fn advance_to_retained_due(fixture: &Fixture, saved: &Ledger) {
    let deadline = saved
        .retry()
        .map(|retry| retry.next_attempt_at)
        .into_iter()
        .chain(saved.next_poll_at())
        .max()
        .expect("retained retry or poll deadline");
    fixture.advance(deadline.saturating_sub(now().unwrap()));
}

fn public_snapshot(fixture: &Fixture) -> Snapshot {
    serde_json::from_slice(&std::fs::read(&fixture.ca.projection).unwrap()).unwrap()
}

fn processing(fixture: &Fixture) -> Ledger {
    fixture.ca.state.lock().unwrap().hold_processing = true;
    for _ in 0..8 {
        let result = fixture.run().unwrap();
        if result.report["stage"] == "certificate_pending" {
            return retained(fixture);
        }
        advance_to_due(fixture);
    }
    panic!("fixture did not reach its known processing order");
}

#[test]
fn unchanged_pending_polls_exceed_the_phase_ledger_limit_and_still_complete() {
    let fixture = Fixture::new();
    fixture.ca.state.lock().unwrap().hold_pending = true;
    // Complete both challenge notifications, then observe their Valid states
    // while the order itself remains Pending. The following polls are equal.
    for _ in 0..3 {
        let outcome = fixture.run().unwrap();
        assert!(outcome.candidate.is_none());
        advance_to_due(&fixture);
    }
    let baseline = retained(&fixture);
    assert_eq!(baseline.state.stage, Stage::AwaitingOrder);
    assert!(baseline
        .state
        .authorizations
        .iter()
        .all(|authorization| authorization.status == "valid"));
    let projection = std::fs::read(&fixture.ca.projection).unwrap();
    for _ in 0..520 {
        let outcome = fixture.run().unwrap();
        assert_eq!(outcome.report["stage"], "awaiting_order");
        assert!(outcome.candidate.is_none());
        let saved = retained(&fixture);
        assert_eq!(saved.sequence, baseline.sequence);
        assert_eq!(saved.digest, baseline.digest);
        assert_eq!(saved.state.order, baseline.state.order);
        assert_eq!(std::fs::read(&fixture.ca.projection).unwrap(), projection);
        advance_to_retained_due(&fixture, &saved);
    }
    fixture.ca.state.lock().unwrap().hold_pending = false;
    assert!(fixture.finish().candidate.is_some());
    assert!(public_snapshot(&fixture).challenges.is_empty());
    let ca = fixture.ca.state.lock().unwrap();
    assert_eq!(ca.registration_posts, 1);
    assert_eq!(ca.new_orders, 1);
    assert_eq!(ca.challenge_posts, [1, 1]);
    assert_eq!(ca.finalizations, 1);
}

#[test]
fn unchanged_processing_polls_exceed_the_phase_ledger_limit_and_still_complete() {
    let fixture = Fixture::new();
    let baseline = processing(&fixture);
    let projection = std::fs::read(&fixture.ca.projection).unwrap();
    advance_to_retained_due(&fixture, &baseline);
    for _ in 0..520 {
        let outcome = fixture.run().unwrap();
        assert_eq!(outcome.report["stage"], "certificate_pending");
        assert!(outcome.candidate.is_none());
        let saved = retained(&fixture);
        assert_eq!(saved.sequence, baseline.sequence);
        assert_eq!(saved.digest, baseline.digest);
        assert_eq!(saved.state.order, baseline.state.order);
        assert_eq!(std::fs::read(&fixture.ca.projection).unwrap(), projection);
        advance_to_retained_due(&fixture, &saved);
    }
    fixture.ca.state.lock().unwrap().hold_processing = false;
    assert!(fixture.run().unwrap().candidate.is_some());
    assert!(public_snapshot(&fixture).challenges.is_empty());
    let ca = fixture.ca.state.lock().unwrap();
    assert_eq!(ca.registration_posts, 1);
    assert_eq!(ca.new_orders, 1);
    assert_eq!(ca.finalizations, 1);
}

#[test]
fn processing_retry_after_survives_reopen_without_an_early_request() {
    let fixture = Fixture::new();
    let baseline = processing(&fixture);
    let retry_at = now().unwrap() + 900;
    fixture.ca.state.lock().unwrap().terminal_retry_after = Some(retry_at);
    advance_to_due(&fixture);
    let waiting = fixture.run().unwrap();
    assert_eq!(waiting.report["next_poll_at"], retry_at);
    let saved = retained(&fixture);
    assert_eq!(saved.sequence, baseline.sequence);
    assert_eq!(saved.next_poll_at(), Some(retry_at));
    let requests = fixture.ca.state.lock().unwrap().requests.clone();
    for at in [now().unwrap(), retry_at - 1] {
        fixture.advance(at - now().unwrap());
        let reopened = fixture.run().unwrap();
        assert_eq!(reopened.report["next_poll_at"], retry_at);
        assert_eq!(fixture.ca.state.lock().unwrap().requests, requests);
        assert_eq!(retained(&fixture).next_poll_at(), Some(retry_at));
    }
    fixture.advance(1);
    fixture.run().unwrap();
    let ca = fixture.ca.state.lock().unwrap();
    assert!(ca.requests.len() > requests.len());
    assert_eq!(ca.new_orders, 1);
    assert_eq!(ca.finalizations, 1);
}

#[test]
fn prior_authorization_retry_after_survives_a_later_auth_or_ready_transport_failure() {
    for authorization_read_failure in [false, true] {
        let fixture = Fixture::new();
        let retry_at = now().unwrap() + 3600;
        {
            let mut ca = fixture.ca.state.lock().unwrap();
            // No order-level hint can accidentally satisfy this regression.
            ca.authorization_retry_after = Some(retry_at);
            ca.authorization_read_failure = authorization_read_failure;
            ca.challenge_failures_remaining = usize::from(!authorization_read_failure);
        }
        let waiting = fixture.run().unwrap();
        assert_eq!(waiting.report["next_attempt_at"], retry_at);
        assert!(waiting.candidate.is_none());
        let saved = retained(&fixture);
        assert!(saved.state.order.is_some());
        assert_ne!(saved.state.stage, Stage::Terminal);
        assert_eq!(saved.retry().unwrap().next_attempt_at, retry_at);
        assert_eq!(saved.retry().unwrap().failures, 1);
        let requests = fixture.ca.state.lock().unwrap().requests.clone();
        for at in [now().unwrap(), retry_at - 1] {
            fixture.advance(at - now().unwrap());
            let reopened = fixture.run().unwrap();
            assert_eq!(reopened.report["next_attempt_at"], retry_at);
            assert_eq!(fixture.ca.state.lock().unwrap().requests, requests);
        }
        let ca = fixture.ca.state.lock().unwrap();
        assert_eq!(ca.registration_posts, 1);
        assert_eq!(ca.new_orders, 1);
        assert_eq!(ca.finalizations, 0);
    }
}

#[test]
fn a_known_processing_order_regressing_after_expiry_cannot_replay_finalize_or_become_terminal() {
    for reported in ["ready", "pending"] {
        let fixture = Fixture::with_certificate_lifetime(72);
        let baseline = processing(&fixture);
        let expiry = baseline.state.order.as_ref().unwrap().expires_at;
        fixture.advance(expiry + 1 - now().unwrap());
        let retry_at = now().unwrap() + 600;
        {
            let mut ca = fixture.ca.state.lock().unwrap();
            ca.regressed_order_status = Some(reported);
            ca.terminal_retry_after = Some(retry_at);
        }
        let waiting = fixture.run().unwrap();
        assert_eq!(waiting.report["stage"], "certificate_pending");
        assert_eq!(waiting.report["next_poll_at"], retry_at);
        assert!(waiting.candidate.is_none());
        let saved = retained(&fixture);
        assert_eq!(saved.sequence, baseline.sequence);
        assert_eq!(saved.digest, baseline.digest);
        assert_eq!(saved.state.order, baseline.state.order);
        assert!(saved.state.failure.is_none());
        assert!(saved.state.terminal_retry.is_none());
        {
            let view = LockedInspection::open(&fixture.installation).unwrap();
            let decision = terminal_retry_decision(
                &view,
                &fixture.installation,
                AcmeEnvironment::Staging,
                0,
                now().unwrap(),
            )
            .unwrap();
            assert!(!decision.is_due());
            assert!(decision.evidence().is_none());
        }
        let requests = fixture.ca.state.lock().unwrap().requests.clone();
        fixture.advance(retry_at - 1 - now().unwrap());
        fixture.run().unwrap();
        assert_eq!(fixture.ca.state.lock().unwrap().requests, requests);
        {
            let mut ca = fixture.ca.state.lock().unwrap();
            assert_eq!(ca.new_orders, 1);
            assert_eq!(ca.finalizations, 1);
            ca.regressed_order_status = None;
            ca.hold_processing = false;
            ca.terminal_retry_after = None;
        }
        fixture.advance(1);
        assert!(fixture.run().unwrap().candidate.is_some());
        assert!(public_snapshot(&fixture).challenges.is_empty());
        let ca = fixture.ca.state.lock().unwrap();
        assert_eq!(ca.registration_posts, 1);
        assert_eq!(ca.new_orders, 1);
        assert_eq!(ca.finalizations, 1);
    }
}

#[test]
fn more_than_thirty_two_temporary_failures_recover_the_same_known_order() {
    let fixture = Fixture::new();
    let baseline = processing(&fixture);
    fixture
        .ca
        .state
        .lock()
        .unwrap()
        .directory_failures_remaining = 40;
    for failures in 1u32..=40 {
        advance_to_due(&fixture);
        let waiting = fixture.run().unwrap();
        assert_eq!(waiting.report["stage"], "certificate_pending");
        assert!(waiting.candidate.is_none());
        let saved = retained(&fixture);
        assert_eq!(saved.sequence, baseline.sequence);
        assert_eq!(saved.digest, baseline.digest);
        assert_eq!(saved.state.order, baseline.state.order);
        // The bounded backoff counter may saturate; the known order must not
        // acquire a terminal failure when that counter reaches its ceiling.
        assert_eq!(saved.retry().unwrap().failures, failures.min(32));
        assert!(saved.retry().unwrap().next_attempt_at > now().unwrap());
        assert!(saved.state.failure.is_none());
        let requests = fixture.ca.state.lock().unwrap().requests.len();
        let retry_at = saved.retry().unwrap().next_attempt_at;
        // An immediate reopened run cannot redraw jitter or consume another
        // protocol attempt, even once the former failure limit is exceeded.
        assert_eq!(fixture.run().unwrap().report["next_attempt_at"], retry_at);
        assert_eq!(fixture.ca.state.lock().unwrap().requests.len(), requests);
    }
    assert!(now().unwrap() < baseline.state.order.as_ref().unwrap().expires_at);
    fixture.ca.state.lock().unwrap().hold_processing = false;
    advance_to_due(&fixture);
    assert!(fixture.run().unwrap().candidate.is_some());
    assert!(public_snapshot(&fixture).challenges.is_empty());
    let ca = fixture.ca.state.lock().unwrap();
    assert_eq!(ca.directory_failures_remaining, 0);
    assert_eq!(ca.registration_posts, 1);
    assert_eq!(ca.new_orders, 1);
    assert_eq!(ca.finalizations, 1);
}

#[test]
fn terminal_authorization_without_expiry_is_recorded_and_withdrawn() {
    for after_publication in [false, true] {
        let fixture = Fixture::new();
        {
            let mut ca = fixture.ca.state.lock().unwrap();
            if after_publication {
                ca.target_change = Some(TargetChange::TerminalWithoutExpiry);
            } else {
                ca.authorization_terminal = true;
            }
        }
        let outcome = fixture.run().unwrap();
        assert_eq!(outcome.report["stage"], "terminal");
        assert_eq!(outcome.report["failure"], "authorization_invalid");
        assert!(outcome.candidate.is_none());
        assert_eq!(retained(&fixture).state.stage, Stage::Terminal);
        if after_publication {
            assert!(public_snapshot(&fixture).challenges.is_empty());
        } else {
            assert!(!fixture.ca.projection.exists());
        }
        let requests = fixture.ca.state.lock().unwrap().requests.clone();
        assert_eq!(fixture.run().unwrap().report["stage"], "terminal");
        let ca = fixture.ca.state.lock().unwrap();
        assert_eq!(ca.requests, requests);
        assert_eq!(ca.new_orders, 1);
        assert_eq!(ca.challenge_posts, [0, 0]);
        assert_eq!(ca.finalizations, 0);
    }
}

#[test]
fn pending_authorization_without_expiry_uses_the_bound_order_deadline() {
    let fixture = Fixture::new();
    fixture
        .ca
        .state
        .lock()
        .unwrap()
        .authorization_expiry_omitted = true;
    assert_eq!(fixture.run().unwrap().report["stage"], "awaiting_order");
    let saved = retained(&fixture);
    let expiry = saved.state.order.as_ref().unwrap().expires_at;
    assert_eq!(saved.state.authorizations.len(), 2);
    assert!(saved
        .state
        .authorizations
        .iter()
        .all(|authorization| authorization.expires_at == expiry));
    assert_eq!(public_snapshot(&fixture).expires_at, expiry);
    assert_eq!(fixture.ca.state.lock().unwrap().new_orders, 1);
}

#[test]
fn omitted_pending_expiry_never_extends_an_earlier_authorization_deadline() {
    let fixture = Fixture::new();
    fixture.ca.state.lock().unwrap().target_change = Some(TargetChange::OmittedExpiry);
    assert_eq!(fixture.run().unwrap().report["stage"], "awaiting_order");
    let initial = retained(&fixture);
    let expiry = fixture.ca.created_at + 3600;
    assert!(initial.state.order.as_ref().unwrap().expires_at > expiry);
    assert!(initial
        .state
        .authorizations
        .iter()
        .all(|authorization| authorization.expires_at == expiry));
    assert_eq!(public_snapshot(&fixture).expires_at, expiry);
    {
        let mut ca = fixture.ca.state.lock().unwrap();
        ca.target_change = None;
        ca.authorization_expiry_omitted = true;
    }
    advance_to_due(&fixture);
    fixture.run().unwrap();
    assert!(retained(&fixture)
        .state
        .authorizations
        .iter()
        .all(|authorization| authorization.expires_at == expiry));
    assert_eq!(public_snapshot(&fixture).expires_at, expiry);
    fixture
        .ca
        .state
        .lock()
        .unwrap()
        .authorization_expiry_omitted = false;
    assert!(fixture.finish().candidate.is_some());
    assert_eq!(fixture.ca.state.lock().unwrap().new_orders, 1);
}

#[test]
fn valid_authorization_without_required_expiry_is_not_a_terminal_retry_or_ready_post() {
    let fixture = Fixture::new();
    fixture.ca.state.lock().unwrap().target_change = Some(TargetChange::ValidWithoutExpiry);
    assert!(fixture.run().is_err());
    let saved = retained(&fixture);
    assert_ne!(saved.state.stage, Stage::Terminal);
    assert!(saved.state.terminal_retry.is_none());
    assert!(saved.state.order.is_some());
    let ca = fixture.ca.state.lock().unwrap();
    assert_eq!(ca.new_orders, 1);
    assert_eq!(ca.challenge_posts, [0, 0]);
    assert_eq!(ca.finalizations, 0);
}

#[test]
fn lost_finalize_processing_past_recorded_expiry_waits_for_authoritative_valid_or_invalid() {
    for eventually_invalid in [false, true] {
        let fixture = Fixture::with_certificate_lifetime(72);
        fixture.run().unwrap();
        advance_to_due(&fixture);
        fixture.run().unwrap();
        let expiry = retained(&fixture).state.order.unwrap().expires_at;
        fixture.advance(expiry - 1 - now().unwrap());
        {
            let mut ca = fixture.ca.state.lock().unwrap();
            ca.lose_finalize = true;
            ca.hold_processing = true;
        }
        let lost = fixture.run().unwrap();
        assert_eq!(lost.report["stage"], "finalize_pending");
        assert!(fixture.ca.state.lock().unwrap().finalized);
        let retry_at = retained(&fixture).retry().unwrap().next_attempt_at;
        assert!(retry_at > expiry);
        for _ in 0..3 {
            advance_to_due(&fixture);
            let waiting = fixture.run().unwrap();
            assert!(now().unwrap() > expiry);
            assert_eq!(waiting.report["stage"], "certificate_pending");
            assert!(waiting.candidate.is_none());
            let view = LockedInspection::open(&fixture.installation).unwrap();
            let decision = terminal_retry_decision(
                &view,
                &fixture.installation,
                AcmeEnvironment::Staging,
                0,
                now().unwrap(),
            )
            .unwrap();
            assert!(!decision.is_due());
            assert!(decision.evidence().is_none());
            let saved = Ledger::load(&view, AcmeEnvironment::Staging)
                .unwrap()
                .unwrap();
            assert!(saved.state.failure.is_none());
            assert!(saved.state.terminal_retry.is_none());
        }
        {
            let mut ca = fixture.ca.state.lock().unwrap();
            ca.hold_processing = false;
            ca.order_invalid = eventually_invalid;
        }
        advance_to_due(&fixture);
        let observed = fixture.run().unwrap();
        if eventually_invalid {
            assert_eq!(observed.report["stage"], "terminal");
            assert_eq!(observed.report["failure"], "order_invalid");
            assert!(observed.candidate.is_none());
        } else {
            assert_eq!(observed.report["stage"], "complete");
            assert!(observed.candidate.is_some());
        }
        assert!(public_snapshot(&fixture).challenges.is_empty());
        let durable = retained(&fixture);
        assert_eq!(durable.state.stage == Stage::Terminal, eventually_invalid);
        assert_eq!(durable.state.stage == Stage::Complete, !eventually_invalid);
        let ca = fixture.ca.state.lock().unwrap();
        assert_eq!(ca.registration_posts, 1);
        assert_eq!(ca.new_orders, 1);
        assert_eq!(ca.finalizations, 1);
    }
}

fn complete_after_retained_retry_floor(fixture: &Fixture, retry_at: u64) {
    let waiting = retained(fixture);
    assert_eq!(waiting.retry().unwrap().next_attempt_at, retry_at);
    assert_eq!(waiting.retry().unwrap().failures, 1);
    let requests = {
        let mut ca = fixture.ca.state.lock().unwrap();
        // Reopened workers must honor persisted evidence even when the next
        // server response would no longer contain the original timing hint.
        ca.terminal_retry_after = None;
        ca.finalize_retry_after = None;
        ca.requests.clone()
    };
    for at in [now().unwrap(), retry_at - 1] {
        fixture.advance(at - now().unwrap());
        let reopened = fixture.run().unwrap();
        assert_eq!(reopened.report["next_attempt_at"], retry_at);
        assert!(reopened.candidate.is_none());
        assert_eq!(fixture.ca.state.lock().unwrap().requests, requests);
        let saved = retained(fixture);
        assert_eq!(saved.sequence, waiting.sequence);
        assert_eq!(saved.digest, waiting.digest);
        assert_eq!(saved.state.order, waiting.state.order);
        assert_eq!(saved.retry().unwrap().next_attempt_at, retry_at);
    }
    fixture.advance(1);
    let complete = fixture.run().unwrap();
    assert_eq!(complete.report["stage"], "complete");
    assert!(complete.candidate.is_some());
    assert_eq!(retained(fixture).state.order, waiting.state.order);
    assert!(public_snapshot(fixture).challenges.is_empty());
    let ca = fixture.ca.state.lock().unwrap();
    assert!(ca.requests.len() > requests.len());
    assert_eq!(ca.registration_posts, 1);
    assert_eq!(ca.new_orders, 1);
    assert_eq!(ca.finalizations, 1);
}

#[test]
fn ready_order_hint_survives_a_lost_finalize_response_and_restart() {
    let fixture = Fixture::new();
    // Reach Ready without a long hint on an earlier authorization response.
    for _ in 0..2 {
        assert!(fixture.run().unwrap().candidate.is_none());
        advance_to_due(&fixture);
    }
    let original = retained(&fixture);
    let retry_at = now().unwrap() + 3600;
    {
        let mut ca = fixture.ca.state.lock().unwrap();
        assert!(ca.ready.iter().all(|value| *value));
        assert_eq!(ca.finalizations, 0);
        ca.terminal_retry_after = Some(retry_at);
        ca.lose_finalize = true;
    }
    let waiting = fixture.run().unwrap();
    assert_eq!(waiting.report["stage"], "finalize_pending");
    assert_eq!(waiting.report["next_attempt_at"], retry_at);
    assert!(waiting.candidate.is_none());
    assert!(fixture.ca.state.lock().unwrap().finalized);
    assert_eq!(retained(&fixture).state.order, original.state.order);
    complete_after_retained_retry_floor(&fixture, retry_at);
}

#[test]
fn valid_order_hint_survives_certificate_transport_failure_and_restart() {
    let fixture = Fixture::new();
    let original = processing(&fixture);
    advance_to_due(&fixture);
    let retry_at = now().unwrap() + 3600;
    {
        let mut ca = fixture.ca.state.lock().unwrap();
        ca.hold_processing = false;
        ca.terminal_retry_after = Some(retry_at);
        ca.certificate_failures_remaining = 1;
    }
    let waiting = fixture.run().unwrap();
    assert_eq!(waiting.report["stage"], "certificate_pending");
    assert_eq!(waiting.report["next_attempt_at"], retry_at);
    assert!(waiting.candidate.is_none());
    assert_eq!(
        fixture
            .ca
            .state
            .lock()
            .unwrap()
            .certificate_failures_remaining,
        0
    );
    let saved = retained(&fixture);
    assert_eq!(saved.sequence, original.sequence);
    assert_eq!(saved.digest, original.digest);
    assert_eq!(saved.state.order, original.state.order);
    complete_after_retained_retry_floor(&fixture, retry_at);
}

#[test]
fn successful_finalize_keeps_the_later_ready_or_finalize_hint_after_certificate_failure() {
    for (ready_delay, finalize_delay) in [(3600u64, 300u64), (300, 3600)] {
        let fixture = Fixture::new();
        for _ in 0..2 {
            assert!(fixture.run().unwrap().candidate.is_none());
            advance_to_due(&fixture);
        }
        let original = retained(&fixture);
        let observed = now().unwrap();
        let retry_at = observed + ready_delay.max(finalize_delay);
        {
            let mut ca = fixture.ca.state.lock().unwrap();
            assert!(ca.ready.iter().all(|value| *value));
            assert_eq!(ca.finalizations, 0);
            ca.terminal_retry_after = Some(observed + ready_delay);
            ca.finalize_retry_after = Some(observed + finalize_delay);
            ca.certificate_failures_remaining = 1;
        }
        let waiting = fixture.run().unwrap();
        assert_eq!(waiting.report["stage"], "certificate_pending");
        assert_eq!(waiting.report["next_attempt_at"], retry_at);
        assert!(waiting.candidate.is_none());
        assert_eq!(retained(&fixture).state.order, original.state.order);
        {
            let ca = fixture.ca.state.lock().unwrap();
            assert!(ca.finalized);
            assert_eq!(ca.certificate_failures_remaining, 0);
            assert_eq!(ca.finalizations, 1);
        }
        complete_after_retained_retry_floor(&fixture, retry_at);
    }
}
