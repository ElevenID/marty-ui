// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

const NOW: u64 = 1_800_000_000_000;
struct Fixture {
    key: AuthenticatedApiKey,
    grant: ProducerGrant,
    binding: EvidenceBinding,
    application: ApplicationSnapshot,
    input: Observation,
}
impl Fixture {
    fn new() -> Self {
        Self {
            key: AuthenticatedApiKey {
                id: "key-one".into(),
                organization_id: "org-one".into(),
                revision: 4,
                active: true,
                expires_at_ms: NOW + 60_000,
                scopes: BTreeSet::from([SUBMIT_SCOPE.into()]),
            },
            grant: ProducerGrant {
                organization_id: "org-one".into(),
                source_id: "source-one".into(),
                api_key_id: "key-one".into(),
                revision: 5,
                active: true,
                expires_at_ms: NOW + 120_000,
                bindings: BTreeSet::from(["binding-one".into()]),
            },
            binding: EvidenceBinding {
                id: "binding-one".into(),
                revision: 7,
                active: true,
                organization_id: "org-one".into(),
                source_id: "source-one".into(),
                provider: "synthetic-lms".into(),
                application_id: "application-one".into(),
                subject_id: "urn:synthetic:learner-one".into(),
                fact_type: "learning.score".into(),
                resource_scope: BTreeMap::from([("course_id".into(), "course-one".into())]),
                claims: BTreeMap::from([
                    (
                        "completed".into(),
                        ClaimRule {
                            kind: ClaimKind::Boolean,
                            required: true,
                            nullable: false,
                        },
                    ),
                    (
                        "score".into(),
                        ClaimRule {
                            kind: ClaimKind::Number {
                                minimum: 0.0,
                                maximum: 200.0,
                            },
                            required: false,
                            nullable: true,
                        },
                    ),
                    (
                        "activity_name".into(),
                        ClaimRule {
                            kind: ClaimKind::Text { max_bytes: 64 },
                            required: false,
                            nullable: false,
                        },
                    ),
                ]),
                max_age_ms: 900_000,
                max_clock_skew_ms: 30_000,
            },
            application: ApplicationSnapshot {
                id: "application-one".into(),
                organization_id: "org-one".into(),
                subject_id: "urn:synthetic:learner-one".into(),
                revision: 9,
                accepts_observations: true,
            },
            input: Observation {
                binding_id: "binding-one".into(),
                binding_revision: 7,
                observation_id: "observation-one".into(),
                sequence: 11,
                observed_at_ms: NOW - 1000,
                effective_at_ms: NOW - 2000,
                claims: BTreeMap::from([
                    ("completed".into(), Scalar::Boolean(true)),
                    ("score".into(), Scalar::Number(95.0)),
                ]),
            },
        }
    }
    fn plan(&self, replay: ReplaySnapshot<'_>, now: u64) -> Result<Admission, Denial> {
        plan_admission(
            &self.key,
            &self.grant,
            &self.binding,
            &self.application,
            &self.input,
            &self.input.observation_id,
            replay,
            now,
        )
    }
    fn fresh(&self) -> Result<Admission, Denial> {
        self.plan(
            ReplaySnapshot::Missing {
                current_sequence: 10,
            },
            NOW,
        )
    }
    fn receipt(&self) -> StoredReceipt {
        StoredReceipt {
            id: "receipt-one".into(),
            organization_id: self.key.organization_id.clone(),
            source_id: self.grant.source_id.clone(),
            api_key_id: self.key.id.clone(),
            observation: self.input.clone(),
        }
    }
}

#[test]
fn accepted_plan_derives_identity_scope_and_complete_fence_from_core() {
    let f = Fixture::new();
    let Ok(Admission::Insert(plan)) = f.fresh() else {
        panic!("expected insertion plan")
    };
    assert_eq!(plan.organization_id, "org-one");
    assert_eq!(plan.api_key_id, "key-one");
    assert_eq!(plan.source_id, "source-one");
    assert_eq!(plan.provider, "synthetic-lms");
    assert_eq!(plan.application_id, "application-one");
    assert_eq!(plan.subject_id, "urn:synthetic:learner-one");
    assert_eq!(plan.fact_type, "learning.score");
    assert_eq!(plan.resource_scope, f.binding.resource_scope);
    assert_eq!(plan.received_at_ms, NOW);
    assert_eq!(
        plan.fence,
        AuthorityFence {
            api_key_revision: 4,
            grant_revision: 5,
            binding_revision: 7,
            application_revision: 9,
            previous_sequence: 10,
            authorization_expires_at_ms: NOW + 60_000,
            observation_expires_at_ms: NOW + 899_000
        }
    );
}

#[test]
fn credential_or_application_privileges_do_not_imply_evidence_submission() {
    for scopes in [
        vec![],
        vec!["integrations:write"],
        vec!["applications:approve"],
        vec!["credentials:issue"],
        vec!["*"],
        vec!["evidence:*"],
        vec!["evidence:read"],
    ] {
        let mut f = Fixture::new();
        f.key.scopes = scopes.into_iter().map(str::to_owned).collect();
        assert_eq!(f.fresh().err(), Some(Denial::ScopeMissing));
    }
}

#[test]
fn disabled_and_expired_api_keys_fail_even_for_exact_retries() {
    for change in 0..3 {
        let mut f = Fixture::new();
        let receipt = f.receipt();
        match change {
            0 => f.key.active = false,
            1 => f.key.expires_at_ms = NOW,
            _ => f.key.expires_at_ms = NOW - 1,
        }
        assert_eq!(f.fresh().err(), Some(Denial::AuthenticationRequired));
        assert_eq!(
            f.plan(ReplaySnapshot::Existing(&receipt), NOW).err(),
            Some(Denial::AuthenticationRequired)
        );
    }
}

#[test]
fn tenant_source_key_binding_application_and_subject_must_all_match() {
    for change in 0..13 {
        let mut f = Fixture::new();
        match change {
            0 => f.key.organization_id = "foreign".into(),
            1 => f.grant.organization_id = "foreign".into(),
            2 => f.grant.api_key_id = "other-key-same-org".into(),
            3 => f.binding.organization_id = "foreign".into(),
            4 => f.binding.source_id = "foreign".into(),
            5 => f.grant.bindings.clear(),
            6 => f.input.binding_id = "foreign".into(),
            7 => f.application.id = "foreign".into(),
            8 => f.application.subject_id = "foreign".into(),
            9 => f.application.organization_id = "foreign".into(),
            10 => f.grant.active = false,
            11 => f.binding.active = false,
            _ => f.grant.expires_at_ms = NOW,
        }
        assert_eq!(
            f.fresh().err(),
            Some(Denial::NotAuthorized),
            "case {change}"
        );
    }
}

#[test]
fn binding_revision_change_invalidates_new_and_replayed_requests() {
    let mut f = Fixture::new();
    let receipt = f.receipt();
    f.binding.revision += 1;
    assert_eq!(f.fresh().err(), Some(Denial::BindingChanged));
    assert_eq!(
        f.plan(ReplaySnapshot::Existing(&receipt), NOW).err(),
        Some(Denial::BindingChanged)
    );
}

#[test]
fn new_observations_cannot_reopen_closed_applications() {
    let mut f = Fixture::new();
    f.application.accepts_observations = false;
    assert_eq!(f.fresh().err(), Some(Denial::ApplicationClosed));
}

#[test]
fn exact_retry_returns_original_receipt_without_refreshing_or_reopening() {
    let mut f = Fixture::new();
    let receipt = f.receipt();
    f.key.expires_at_ms = NOW + 2_000_000;
    f.grant.expires_at_ms = NOW + 2_000_000;
    f.application.accepts_observations = false;
    let result = f.plan(ReplaySnapshot::Existing(&receipt), NOW + 1_000_000);
    assert!(matches!(result, Ok(Admission::Replay { receipt_id }) if receipt_id == "receipt-one"));
}

#[test]
fn replay_cannot_cross_tenant_source_key_or_envelope() {
    for change in 0..12 {
        let f = Fixture::new();
        let mut receipt = f.receipt();
        match change {
            0 => receipt.organization_id = "foreign".into(),
            1 => receipt.source_id = "foreign".into(),
            2 => receipt.api_key_id = "another-key".into(),
            3 => receipt.observation.binding_id = "foreign".into(),
            4 => receipt.observation.binding_revision += 1,
            5 => receipt.observation.sequence += 1,
            6 => receipt.observation.observed_at_ms += 1,
            7 => receipt.observation.effective_at_ms += 1,
            8 => {
                receipt
                    .observation
                    .claims
                    .insert("score".into(), Scalar::Number(100.0));
            }
            9 => receipt.observation.observation_id = "other-observation".into(),
            10 => {
                receipt.observation.claims.remove("score");
            }
            _ => receipt.id.clear(),
        }
        assert_eq!(
            f.plan(ReplaySnapshot::Existing(&receipt), NOW).err(),
            Some(Denial::ReplayConflict),
            "case {change}"
        );
    }
}

#[test]
fn monotonic_sequences_reject_old_or_same_new_ids_and_record_cas_head() {
    let f = Fixture::new();
    for seq in [11, 12, MAX_SAFE_INTEGER] {
        assert_eq!(
            f.plan(
                ReplaySnapshot::Missing {
                    current_sequence: seq
                },
                NOW
            )
            .err(),
            Some(Denial::OutOfOrder)
        );
    }
    let Ok(Admission::Insert(plan)) = f.plan(
        ReplaySnapshot::Missing {
            current_sequence: 0,
        },
        NOW,
    ) else {
        panic!("first observation")
    };
    assert_eq!(plan.fence.previous_sequence, 0);
    assert_eq!(
        f.plan(
            ReplaySnapshot::Missing {
                current_sequence: u64::MAX
            },
            NOW
        )
        .err(),
        Some(Denial::InvalidAuthority)
    );
}

#[test]
fn freshness_boundaries_fail_closed_and_never_use_effective_time_as_freshness() {
    let mut f = Fixture::new();
    f.input.observed_at_ms = NOW - 900_000;
    f.input.effective_at_ms = 1;
    assert_eq!(f.fresh().err(), Some(Denial::StaleObservation));
    f.input.observed_at_ms += 1;
    assert!(f.fresh().is_ok());
    f.input.observed_at_ms = NOW + 30_000;
    assert!(f.fresh().is_ok());
    f.input.observed_at_ms += 1;
    assert_eq!(f.fresh().err(), Some(Denial::FutureObservation));
}

#[test]
fn unsafe_numbers_bad_ids_and_future_effective_time_are_rejected() {
    for change in 0..11 {
        let mut f = Fixture::new();
        match change {
            0 => f.input.sequence = 0,
            1 => f.input.sequence = MAX_SAFE_INTEGER + 1,
            2 => f.input.observed_at_ms = 0,
            3 => f.input.effective_at_ms = f.input.observed_at_ms + 1,
            4 => f.input.observation_id = "../other".into(),
            5 => f.input.observation_id = "x".repeat(129),
            6 => f.input.binding_id = "foreign/path".into(),
            7 => f.input.binding_revision = 0,
            8 => f.input.binding_revision = u64::MAX,
            9 => f.input.observed_at_ms = u64::MAX,
            _ => f.input.effective_at_ms = 0,
        }
        assert_eq!(
            f.fresh().err(),
            Some(Denial::InvalidRequest),
            "case {change}"
        );
    }
}

#[test]
fn header_cannot_name_a_different_logical_attempt() {
    let f = Fixture::new();
    let result = plan_admission(
        &f.key,
        &f.grant,
        &f.binding,
        &f.application,
        &f.input,
        "other-request",
        ReplaySnapshot::Missing {
            current_sequence: 10,
        },
        NOW,
    );
    assert_eq!(result.err(), Some(Denial::InvalidRequest));
}

#[test]
fn claims_follow_exact_operator_schema_and_cannot_smuggle_authority() {
    for change in 0..9 {
        let mut f = Fixture::new();
        match change {
            0 => {
                f.input
                    .claims
                    .insert("verified".into(), Scalar::Boolean(true));
            }
            1 => {
                f.input.claims.remove("completed");
            }
            2 => {
                f.input
                    .claims
                    .insert("completed".into(), Scalar::Text("true".into()));
            }
            3 => {
                f.input.claims.insert("completed".into(), Scalar::Null);
            }
            4 => {
                f.input
                    .claims
                    .insert("score".into(), Scalar::Number(f64::NAN));
            }
            5 => {
                f.input
                    .claims
                    .insert("score".into(), Scalar::Number(f64::INFINITY));
            }
            6 => {
                f.input.claims.insert("score".into(), Scalar::Number(201.0));
            }
            7 => {
                f.input
                    .claims
                    .insert("activity_name".into(), Scalar::Text("x".repeat(65)));
            }
            _ => {
                f.input.claims.insert(
                    "activity_name".into(),
                    Scalar::Text("hidden\ncontrol".into()),
                );
            }
        }
        assert_eq!(
            f.fresh().err(),
            Some(Denial::InvalidClaims),
            "case {change}"
        );
    }
}

#[test]
fn explicit_negative_and_nullable_observations_are_not_transport_failures() {
    let mut f = Fixture::new();
    f.input
        .claims
        .insert("completed".into(), Scalar::Boolean(false));
    f.input.claims.insert("score".into(), Scalar::Null);
    assert!(matches!(f.fresh(), Ok(Admission::Insert(_))));
}

#[test]
fn malformed_operator_configuration_cannot_weaken_policy() {
    for change in 0..12 {
        let mut f = Fixture::new();
        match change {
            0 => f.binding.max_age_ms = MAX_AGE_MS + 1,
            1 => f.binding.max_age_ms = 0,
            2 => f.binding.max_clock_skew_ms = MAX_SKEW_MS + 1,
            3 => f.binding.resource_scope.clear(),
            4 => f.binding.claims.clear(),
            5 => f.key.revision = 0,
            6 => f.grant.revision = 0,
            7 => f.application.revision = 0,
            8 => {
                f.binding.claims.insert(
                    "Verified".into(),
                    ClaimRule {
                        kind: ClaimKind::Boolean,
                        required: false,
                        nullable: false,
                    },
                );
            }
            9 => {
                f.binding.claims.get_mut("score").unwrap().kind = ClaimKind::Number {
                    minimum: f64::NAN,
                    maximum: 100.0,
                };
            }
            10 => {
                f.binding.claims.get_mut("activity_name").unwrap().kind =
                    ClaimKind::Text { max_bytes: 513 };
            }
            _ => f.key.expires_at_ms = u64::MAX,
        }
        assert_eq!(
            f.fresh().err(),
            Some(Denial::InvalidAuthority),
            "case {change}"
        );
    }
}

#[test]
fn snapshots_are_not_mutated_and_claim_maps_are_detached() {
    let f = Fixture::new();
    let Ok(Admission::Insert(mut plan)) = f.fresh() else {
        panic!("plan")
    };
    plan.observation.claims.clear();
    plan.resource_scope.clear();
    assert_eq!(f.input.claims.len(), 2);
    assert_eq!(f.binding.resource_scope.len(), 1);
}
