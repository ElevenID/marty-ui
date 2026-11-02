//! These cases retain the actual original preparation and reuse the in-memory
//! protocol driver. Native observations remain explicit synthetic fixture data;
//! no test grants deployment readiness or public-CA qualification.
use super::*;
use crate::{
    installer_acme::{initial_terminal, tests::Fixture},
    installer_acme_state::{IssuanceReason, Ledger, Stage},
    installer_state::LockedMaintenance,
};

fn choose(state: &mut LockedMaintenance, acme: &Fixture) -> Result<Option<InitialRolloverPermit>> {
    let inputs = acme.inputs();
    initial_rollover::select(state, inputs.configuration, inputs.ingress_key)
}

fn retained(state: &LockedInspection, cycle: u64) -> Ledger {
    Ledger::load_cycle(state, AcmeEnvironment::Staging, cycle)
        .unwrap()
        .unwrap()
}

#[test]
#[ignore = "requires an ordinary nonroot OS identity for rootless prepared-boundary admission"]
fn initial_terminal_retry_retains_long_cooldown_and_reuses_unstarted_permit() {
    let mut boundary = boundary_fixture_with_staging(true);
    let mut acme = boundary.acme.take().unwrap();
    let floor = installer_acme::now().unwrap() + 12 * 3600;
    acme.reject_initial_order(Some(floor));
    let failed = boundary
        .state
        .with_maintenance(|state| acme.run_initial_locked(state, None))
        .unwrap();
    assert_eq!(failed.report["failure"], "order_invalid");
    assert_eq!(failed.report["initial_terminal_retry_at"], floor);
    assert_eq!(failed.report["initial_terminal_withdrawal_confirmed"], true);
    let original = boundary
        .state
        .with_inspection(|state| Ok(retained(state, 0)))
        .unwrap();
    assert!(original.state.terminal_retry.is_none());
    assert_eq!(
        original
            .state
            .initial_terminal_retry
            .as_ref()
            .unwrap()
            .observation
            .attempt,
        1
    );
    assert!(boundary
        .state
        .with_maintenance(|state| choose(state, &acme))
        .unwrap()
        .is_none());
    let requests = acme.request_count();
    acme.advance(floor - installer_acme::now().unwrap() - 1);
    assert!(boundary
        .state
        .with_maintenance(|state| choose(state, &acme))
        .unwrap()
        .is_none());
    boundary
        .state
        .with_maintenance(|state| acme.run_initial_locked(state, None))
        .unwrap();
    assert_eq!(acme.request_count(), requests);
    acme.advance(1);
    let permit = boundary
        .state
        .with_maintenance(|state| choose(state, &acme))
        .unwrap()
        .unwrap();
    assert_eq!(permit.cycle(), 1);
    assert!(permit.prior_candidate().is_none());
    assert!(matches!(
        permit.reason(),
        IssuanceReason::InitialOrderTerminal { .. }
    ));
    let path = boundary
        .installation
        .join("evidence")
        .join(InitialRolloverPermit::record_name(
            AcmeEnvironment::Staging,
            1,
        ));
    let bytes = files::read(&path).unwrap();
    let data: Value = decode(&bytes).unwrap();
    assert_eq!(
        data["schema"],
        "elevenid.installer-acme-initial-rollover/v2"
    );
    assert_eq!(data["predecessor"]["kind"], "confirmed_initial_terminal");
    let digest = permit.sha256().to_owned();
    drop(boundary.state);
    let mut reopened = LockedMaintenance::open(&boundary.installation).unwrap();
    let permit = choose(&mut reopened, &acme).unwrap().unwrap();
    assert_eq!(permit.sha256(), digest);
    assert!(
        Ledger::load_cycle(reopened.inspection(), AcmeEnvironment::Staging, 1)
            .unwrap()
            .is_none()
    );
    acme.next_initial_order(2);
    let candidate = acme
        .finish_initial_locked(&mut reopened, Some(&permit))
        .unwrap()
        .candidate
        .unwrap();
    assert_eq!(candidate.cycle(), 1);
    assert_eq!(acme.initial_counts(), (1, 0, 2, 1));
    let current = retained(reopened.inspection(), 1);
    assert_eq!(
        current.binding.csr_der_base64,
        original.binding.csr_der_base64
    );
    assert_eq!(current.binding.account_key, original.binding.account_key);
    assert_eq!(current.state.account_url, original.state.account_url);
    assert_eq!(retained(reopened.inspection(), 0).digest, original.digest);
    assert_eq!(files::read(path).unwrap(), bytes);
    // Historical initial proof survives later legitimate application storage
    // mutation, while that mutation cannot authorize another initial order.
    files::set_permissions(
        boundary.installation.join("state/postgres"),
        files::Permissions::from_mode(0o770),
    )
    .unwrap();
    installer_acme::retained_candidate(reopened.inspection(), AcmeEnvironment::Staging, 1).unwrap();
    assert!(choose(&mut reopened, &acme).is_err());
}

#[test]
#[ignore = "requires an ordinary nonroot OS identity for rootless prepared-boundary admission"]
fn consecutive_initial_terminal_orders_count_only_the_immediate_initial_chain() {
    let mut boundary = boundary_fixture_with_staging(true);
    let mut acme = boundary.acme.take().unwrap();
    let mut permit = None;
    for cycle in 0..3 {
        if cycle > 0 {
            acme.next_initial_order((cycle + 1) as u8);
        }
        acme.reject_initial_order(None);
        let at = installer_acme::now().unwrap();
        boundary
            .state
            .with_maintenance(|state| acme.run_initial_locked(state, permit.as_ref()))
            .unwrap();
        let saved = boundary
            .state
            .with_inspection(|state| Ok(retained(state, cycle)))
            .unwrap();
        let proof = saved.state.initial_terminal_retry.as_ref().unwrap();
        assert_eq!(proof.observation.attempt, cycle + 1);
        assert_eq!(proof.observation.eligible_at, at + (300 << cycle));
        assert!(saved.state.terminal_retry.is_none());
        boundary
            .state
            .with_inspection(|state| {
                let decision = installer_acme::terminal_retry_decision(
                    state,
                    &boundary.installation,
                    AcmeEnvironment::Staging,
                    cycle,
                    installer_acme::now()?,
                )?;
                assert!(!decision.is_due());
                assert!(decision.evidence().is_none());
                Ok(())
            })
            .unwrap();
        acme.advance(300 << cycle);
        permit = boundary
            .state
            .with_maintenance(|state| choose(state, &acme))
            .unwrap();
        let successor = permit.as_ref().unwrap();
        assert_eq!(successor.cycle(), cycle + 1);
        assert_eq!(successor.prior_cycle(), cycle);
        assert_eq!(successor.prior_receipt_sha256(), saved.digest);
    }
    assert_eq!(acme.initial_counts(), (1, 0, 3, 0));
}

#[test]
#[ignore = "requires an ordinary nonroot OS identity for rootless prepared-boundary admission"]
fn failed_replacement_after_expired_initial_candidate_has_distinct_initial_retry_authority() {
    let mut boundary = boundary_fixture_with_staging(true);
    let mut acme = boundary.acme.take().unwrap();
    let prior = boundary
        .state
        .with_maintenance(|state| acme.finish_initial_locked(state, None))
        .unwrap()
        .candidate
        .unwrap();
    let expires = prior.metadata()["not_after"].as_u64().unwrap();
    acme.advance(expires - installer_acme::now().unwrap());
    let expired = boundary
        .state
        .with_maintenance(|state| choose(state, &acme))
        .unwrap()
        .unwrap();
    assert!(matches!(
        expired.reason(),
        IssuanceReason::InitialCandidateExpired { .. }
    ));
    acme.next_initial_order(2);
    acme.reject_initial_order(None);
    boundary
        .state
        .with_maintenance(|state| acme.run_initial_locked(state, Some(&expired)))
        .unwrap();
    let terminal = boundary
        .state
        .with_inspection(|state| Ok(retained(state, 1)))
        .unwrap();
    assert_eq!(
        terminal
            .state
            .initial_terminal_retry
            .as_ref()
            .unwrap()
            .observation
            .attempt,
        1
    );
    acme.advance(300);
    let replacement = boundary
        .state
        .with_maintenance(|state| choose(state, &acme))
        .unwrap()
        .unwrap();
    assert_eq!(replacement.cycle(), 2);
    assert_eq!(replacement.prior_cycle(), 1);
    assert!(replacement.prior_candidate().is_none());
    boundary
        .state
        .with_inspection(|state| {
            let evidence = initial_terminal::historical_evidence_local(state, &terminal)?.unwrap();
            let selected_evidence =
                serde_json::from_value::<installer_acme::TerminalRetryEvidence>(value(&evidence)?)
                    .unwrap();
            assert!(installer_acme::require_terminal_retry_evidence(
                state,
                &boundary.installation,
                AcmeEnvironment::Staging,
                &prior,
                &selected_evidence,
                installer_acme::now()?
            )
            .is_err());
            let mut binding = acme.initial_binding(state, &replacement)?;
            binding.renewal.as_mut().unwrap().reason = IssuanceReason::SelectedGenerationDue {
                generation_binding_sha256: "a".repeat(64),
                schedule_sha256: "b".repeat(64),
            };
            assert!(InitialRolloverPermit::require_link(state, &binding, &terminal).is_err());
            Ok(())
        })
        .unwrap();
    acme.next_initial_order(3);
    let next = boundary
        .state
        .with_maintenance(|state| acme.finish_initial_locked(state, Some(&replacement)))
        .unwrap()
        .candidate
        .unwrap();
    assert_eq!(next.cycle(), 2);
    assert_ne!(
        next.metadata()["leaf_der_sha256"],
        prior.metadata()["leaf_der_sha256"]
    );
    assert!(next.metadata()["not_after"].as_u64().unwrap() > expires);
    assert_eq!(acme.initial_counts(), (1, 0, 3, 2));
    boundary
        .state
        .with_inspection(|state| {
            installer_acme::retained_candidate(state, AcmeEnvironment::Staging, 2).map(|_| ())
        })
        .unwrap();
}

#[test]
#[ignore = "requires an ordinary nonroot OS identity for rootless prepared-boundary admission"]
fn initial_terminal_retry_waits_for_actual_withdrawal_and_never_retrofits_legacy_failure() {
    for typed in [true, false] {
        let mut boundary = boundary_fixture_with_staging(true);
        let acme = boundary.acme.take().unwrap();
        boundary
            .state
            .with_maintenance(|state| acme.run_initial_locked(state, None))
            .unwrap();
        boundary
            .state
            .with_maintenance(|state| acme.interrupt_initial_terminal(state, 0, typed))
            .unwrap();
        let pending = boundary
            .state
            .with_inspection(|state| Ok(retained(state, 0)))
            .unwrap();
        assert_eq!(pending.state.stage, Stage::Terminal);
        assert!(pending
            .state
            .initial_terminal_retry
            .as_ref()
            .is_none_or(|proof| proof.observation.withdrawal_confirmed_at.is_none()));
        let requests = acme.request_count();
        acme.advance(300);
        assert!(boundary
            .state
            .with_maintenance(|state| choose(state, &acme))
            .unwrap()
            .is_none());
        boundary
            .state
            .with_maintenance(|state| acme.run_initial_locked(state, None))
            .unwrap();
        assert_eq!(
            acme.request_count(),
            requests,
            "terminal continuation only withdraws locally"
        );
        let permit = boundary
            .state
            .with_maintenance(|state| choose(state, &acme))
            .unwrap();
        assert_eq!(permit.is_some(), typed);
        assert_eq!(acme.initial_counts(), (1, 0, 1, 0));
    }
}

#[test]
#[ignore = "requires an ordinary nonroot OS identity for rootless prepared-boundary admission"]
fn unknown_initial_order_outcome_cannot_create_terminal_retry_authority() {
    let mut boundary = boundary_fixture_with_staging(true);
    let acme = boundary.acme.take().unwrap();
    acme.lose_initial_order_response();
    let result = boundary
        .state
        .with_maintenance(|state| acme.run_initial_locked(state, None))
        .unwrap();
    assert_eq!(result.report["order_outcome_unknown"], true);
    let requests = acme.request_count();
    acme.advance(48 * 3600);
    assert!(boundary
        .state
        .with_maintenance(|state| choose(state, &acme))
        .unwrap()
        .is_none());
    let result = boundary
        .state
        .with_maintenance(|state| acme.run_initial_locked(state, None))
        .unwrap();
    assert_eq!(result.report["order_outcome_unknown"], true);
    assert_eq!(acme.request_count(), requests);
    let saved = boundary
        .state
        .with_inspection(|state| Ok(retained(state, 0)))
        .unwrap();
    assert!(saved.state.initial_terminal_retry.is_none());
    assert_eq!(acme.initial_counts(), (1, 0, 1, 0));
}

#[test]
#[ignore = "requires an ordinary nonroot OS identity for rootless prepared-boundary admission"]
fn initial_terminal_proof_rejects_wrong_host_binding_and_later_ownership() {
    for marker in [
        "generation-pending.json",
        "application-started.json",
        "compose-session.json",
        "lifecycle-config.json",
        "uninstall-intent.json",
    ] {
        let mut boundary = boundary_fixture_with_staging(true);
        let acme = boundary.acme.take().unwrap();
        acme.reject_initial_order(None);
        boundary
            .state
            .with_maintenance(|state| acme.run_initial_locked(state, None))
            .unwrap();
        acme.advance(300);
        let permit = boundary
            .state
            .with_maintenance(|state| choose(state, &acme))
            .unwrap()
            .unwrap();
        boundary
            .state
            .with_inspection(|state| {
                let mut saved = retained(state, 0);
                saved
                    .state
                    .initial_terminal_retry
                    .as_mut()
                    .unwrap()
                    .authority
                    .host_prepared_sha256 = "f".repeat(64);
                assert!(initial_terminal::historical_evidence_local(state, &saved).is_err());
                Ok(())
            })
            .unwrap();
        boundary.state.write_evidence(marker, b"{}").unwrap();
        boundary
            .state
            .with_inspection(|state| {
                assert!(
                    permit.require_worker(state, &acme.inputs()).is_err(),
                    "{marker}"
                );
                Ok(())
            })
            .unwrap();
        assert!(
            boundary
                .state
                .with_maintenance(|state| choose(state, &acme))
                .is_err(),
            "{marker}"
        );
        assert_eq!(acme.initial_counts(), (1, 0, 1, 0));
    }
}
