use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use marty_presentation_policy::{
    ClaimConstraint, ConstraintType, CredentialRequirement, CredentialStatusEvidence,
    CredentialStatusResolver, CredentialVerificationContext, CredentialVerificationEvidence,
    CredentialVerificationKernel, DisplayMetadata, FreshnessPolicy, HolderBinding,
    IssuerTrustEvidence, PolicyStatus, PresentationPolicy, PresentationTrustResolver,
    PresentationVerificationError, PresentationVerificationOrchestrator, RequestPurpose,
    RequestedClaim, ResolvedTrustProfile, RustCredentialKernel, VerifiedFactsOrchestrator,
};
use marty_verification::credential_format::DetectedCredentialFormat;
use serde_json::{json, Value};
use uuid::Uuid;

const ORGANIZATION_ID: Uuid = Uuid::from_u128(1);
const POLICY_PROFILE_ID: Uuid = Uuid::from_u128(2);
const REQUEST_PROFILE_ID: Uuid = Uuid::from_u128(3);

#[derive(Default)]
struct Kernel {
    evidence: Mutex<CredentialVerificationEvidence>,
    calls: Mutex<Vec<CredentialVerificationContext>>,
}

#[async_trait]
impl CredentialVerificationKernel for Kernel {
    async fn verify(
        &self,
        context: &CredentialVerificationContext,
    ) -> Result<CredentialVerificationEvidence, PresentationVerificationError> {
        self.calls.lock().unwrap().push(context.clone());
        Ok(self.evidence.lock().unwrap().clone())
    }
}

struct Trust {
    evidence: IssuerTrustEvidence,
    fail_load: bool,
    profile_organization_id: Option<Uuid>,
    profile_document: Option<Value>,
    loads: Mutex<Vec<(Uuid, Uuid)>>,
}

#[async_trait]
impl PresentationTrustResolver for Trust {
    async fn load_profile(
        &self,
        profile_id: Uuid,
        organization_id: Uuid,
    ) -> Result<ResolvedTrustProfile, PresentationVerificationError> {
        self.loads
            .lock()
            .unwrap()
            .push((profile_id, organization_id));
        if self.fail_load {
            return Err(PresentationVerificationError::Unavailable);
        }
        Ok(ResolvedTrustProfile {
            id: profile_id,
            organization_id: self.profile_organization_id.unwrap_or(organization_id),
            document: self
                .profile_document
                .clone()
                .unwrap_or_else(|| json!({"public_verification_material": true})),
        })
    }

    async fn evaluate_issuer(
        &self,
        _profile: &ResolvedTrustProfile,
        _issuer_id: &str,
        _format: DetectedCredentialFormat,
    ) -> Result<IssuerTrustEvidence, PresentationVerificationError> {
        Ok(self.evidence.clone())
    }
}

struct Status {
    evidence: CredentialStatusEvidence,
    calls: Mutex<Vec<(Uuid, String, Vec<String>)>>,
}

#[async_trait]
impl CredentialStatusResolver for Status {
    async fn resolve(
        &self,
        organization_id: Uuid,
        issuer_id: &str,
        credential_ids: &[String],
    ) -> Result<CredentialStatusEvidence, PresentationVerificationError> {
        self.calls.lock().unwrap().push((
            organization_id,
            issuer_id.to_owned(),
            credential_ids.to_vec(),
        ));
        Ok(self.evidence.clone())
    }
}

fn policy() -> PresentationPolicy {
    let now = chrono::DateTime::from_timestamp(1_787_240_000, 0).unwrap();
    PresentationPolicy {
        id: Uuid::from_u128(4),
        organization_id: ORGANIZATION_ID,
        name: "Email login".into(),
        description: None,
        status: PolicyStatus::Active,
        display_metadata: DisplayMetadata {
            title: "Email login".into(),
            description: String::new(),
            purpose: RequestPurpose::IdentityVerification,
            purpose_description: None,
            verifier_name: "Marty".into(),
            verifier_logo_url: None,
            privacy_policy_url: None,
            terms_of_service_url: None,
        },
        required_claims: Vec::new(),
        accepted_credential_types: Vec::new(),
        credential_requirements: vec![CredentialRequirement {
            id: Uuid::from_u128(5),
            credential_template_id: "template-email".into(),
            display_name: "Email".into(),
            description: None,
            required: true,
            credential_payload_format: "W3C_VCDM_V2_DI".into(),
            requested_claims: vec![RequestedClaim {
                id: Uuid::from_u128(6),
                claim_name: "email".into(),
                display_name: "Email".into(),
                description: None,
                required: true,
                selective_disclosure: true,
                accept_derived: false,
                predicate_spec: None,
                constraints: vec![ClaimConstraint {
                    id: Uuid::from_u128(7),
                    claim_name: "email".into(),
                    constraint_type: ConstraintType::Presence,
                    value: None,
                    description: None,
                }],
            }],
            trust_profile_id: None,
            max_age_seconds: None,
            require_fresh_issuance: false,
        }],
        alternative_requirements: Vec::new(),
        presentation_proof_required: true,
        trust_profile_id: Some(POLICY_PROFILE_ID),
        holder_binding: HolderBinding {
            required: true,
            binding_methods: vec!["DEVICE_KEY".into()],
            proof_profiles: vec!["OID4VP_VERIFIABLE_PRESENTATION".into()],
            proof_freshness: [
                ("challenge_required".into(), true),
                ("audience_binding_required".into(), true),
                ("replay_detection_required".into(), true),
            ]
            .into_iter()
            .collect(),
        },
        freshness: None,
        issuer_constraints: None,
        credential_ranking_strategy: "FIRST_VALID".into(),
        credential_ranking_weights: None,
        purpose: None,
        compliance_profile_id: None,
        prefer_predicates: false,
        fallback_policy: None,
        supported_circuits: Vec::new(),
        version: 1,
        created_at: now,
        updated_at: now,
    }
}

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../../contracts/presentation-verification-facts.json"
    ))
    .unwrap()
}

#[tokio::test]
async fn hosted_ob2_cannot_turn_parsed_claims_into_policy_trust() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/governed_ob2.json")).unwrap();
    let mut assertion = fixture["assertion"].clone();
    assertion.as_object_mut().unwrap().remove("signature");
    assertion.as_object_mut().unwrap().remove("verification");
    let trust = Arc::new(Trust {
        evidence: IssuerTrustEvidence {
            verified: true,
            trust_level: Some(90),
            ..Default::default()
        },
        fail_load: false,
        profile_organization_id: None,
        profile_document: Some(json!({
            "resolved_verification_methods": [fixture["governed_method"]]
        })),
        loads: Mutex::new(Vec::new()),
    });
    let status = Arc::new(Status {
        evidence: CredentialStatusEvidence::default(),
        calls: Mutex::new(Vec::new()),
    });
    let orchestrator = VerifiedFactsOrchestrator::with_clock(
        Arc::new(RustCredentialKernel),
        trust,
        status.clone(),
        Arc::new(|| 1_787_240_300),
    )
    .unwrap();
    let mut request = marty_presentation_policy::EvaluatePresentationRequest {
        vp_token: json!({"credential": assertion, "document_store": fixture["document_store"]}),
        trust_profile_id: None,
        nonce: None,
        audience: None,
        context: serde_json::Map::new(),
        oid4vp_transport: None,
        trusted_internal_context: false,
    };
    let facts = orchestrator.verify(&policy(), &request).await.unwrap();
    assert_eq!(facts["credentials"][0]["signature_verified"], false);
    assert_eq!(facts["credentials"][0]["trust_profile_verified"], false);
    assert_eq!(facts["credentials"][0]["claims"], json!({}));
    assert!(status.calls.lock().unwrap().is_empty());

    let mut referenced = fixture["assertion"].clone();
    referenced.as_object_mut().unwrap().remove("issuer");
    referenced["signature"] = json!("eyJhbGciOiJFZERTQSJ9.eyJAY29udGV4dCI6Imh0dHBzOi8vdzNpZC5vcmcvb3BlbmJhZGdlcy92MiIsInR5cGUiOiJBc3NlcnRpb24iLCJpZCI6InVybjp1dWlkOmFzc2VydGlvbi0xIiwiYmFkZ2UiOiJ1cm46dXVpZDpiYWRnZS0xIiwidmVyaWZpY2F0aW9uIjp7InR5cGUiOiJzaWduZWQiLCJjcmVhdG9yIjoiZGlkOmV4YW1wbGU6aXNzdWVyI2tleS0xIn19.4V1FG094iFdrKZhCbOV8-XbSD_y944YcqFR6urKJL3QqrYMbcNX4HqfWAlIXtxqHaCUjReNGPJXmrnHC7vzEBQ");
    request.vp_token =
        json!({"credential": referenced, "document_store": fixture["document_store"]});
    let standard = orchestrator.verify(&policy(), &request).await.unwrap();
    assert_eq!(standard["credentials"][0]["signature_verified"], true);
    assert_eq!(standard["credentials"][0]["trust_profile_verified"], false);
    assert_eq!(standard["credentials"][0]["issuer_id"], "unknown");
    assert!(standard["credentials"][0]["claims"]
        .get("issuer_id")
        .is_none());
}

#[tokio::test]
async fn native_evidence_projects_to_the_language_neutral_verified_facts_contract() {
    let fixture = fixture();
    let vector = &fixture["valid_data_integrity"];
    let kernel = Arc::new(Kernel {
        evidence: Mutex::new(serde_json::from_value(vector["kernel_evidence"].clone()).unwrap()),
        calls: Mutex::new(Vec::new()),
    });
    let trust = Arc::new(Trust {
        evidence: serde_json::from_value(vector["trust_evidence"].clone()).unwrap(),
        fail_load: false,
        profile_organization_id: None,
        profile_document: None,
        loads: Mutex::new(Vec::new()),
    });
    let status = Arc::new(Status {
        evidence: serde_json::from_value(vector["status_evidence"].clone()).unwrap(),
        calls: Mutex::new(Vec::new()),
    });
    let orchestrator = VerifiedFactsOrchestrator::with_clock(
        kernel.clone(),
        trust.clone(),
        status.clone(),
        Arc::new(|| 1_787_240_300),
    )
    .unwrap();
    let request = marty_presentation_policy::EvaluatePresentationRequest {
        vp_token: vector["vp_token"].clone(),
        trust_profile_id: Some(REQUEST_PROFILE_ID.to_string()),
        nonce: Some("nonce-1".into()),
        audience: Some("verifier-1".into()),
        context: serde_json::Map::new(),
        oid4vp_transport: None,
        trusted_internal_context: false,
    };

    let actual = orchestrator.verify(&policy(), &request).await.unwrap();
    assert_eq!(actual, vector["expected"]);

    let calls = kernel.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].nonce.as_deref(), Some("nonce-1"));
    assert_eq!(calls[0].audience.as_deref(), Some("verifier-1"));
    assert_eq!(
        calls[0].trust_profile.as_ref().unwrap().id,
        REQUEST_PROFILE_ID
    );
    assert_eq!(
        trust.loads.lock().unwrap().as_slice(),
        &[(REQUEST_PROFILE_ID, ORGANIZATION_ID)]
    );
    assert_eq!(status.calls.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn malformed_presentations_are_denied_without_invoking_any_format_kernel() {
    let kernel = Arc::new(Kernel::default());
    let trust = Arc::new(Trust {
        evidence: IssuerTrustEvidence::default(),
        fail_load: false,
        profile_organization_id: None,
        profile_document: None,
        loads: Mutex::new(Vec::new()),
    });
    let status = Arc::new(Status {
        evidence: CredentialStatusEvidence::default(),
        calls: Mutex::new(Vec::new()),
    });
    let orchestrator = VerifiedFactsOrchestrator::with_clock(
        kernel.clone(),
        trust,
        status,
        Arc::new(|| 1_787_240_300),
    )
    .unwrap();
    let request = marty_presentation_policy::EvaluatePresentationRequest {
        vp_token: Value::String("not-a-credential".into()),
        trust_profile_id: None,
        nonce: None,
        audience: None,
        context: serde_json::Map::new(),
        oid4vp_transport: None,
        trusted_internal_context: false,
    };

    let result = orchestrator.verify(&policy(), &request).await.unwrap();
    assert_eq!(result["credentials"][0]["signature_verified"], false);
    assert_eq!(result["credentials"][0]["claims"], json!({}));
    assert!(kernel.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn unavailable_trust_backend_fails_closed_before_cryptographic_verification() {
    let fixture = fixture();
    let kernel = Arc::new(Kernel::default());
    let trust = Arc::new(Trust {
        evidence: IssuerTrustEvidence::default(),
        fail_load: true,
        profile_organization_id: None,
        profile_document: None,
        loads: Mutex::new(Vec::new()),
    });
    let status = Arc::new(Status {
        evidence: CredentialStatusEvidence::default(),
        calls: Mutex::new(Vec::new()),
    });
    let orchestrator = VerifiedFactsOrchestrator::new(kernel.clone(), trust, status).unwrap();
    let request = marty_presentation_policy::EvaluatePresentationRequest {
        vp_token: fixture["valid_data_integrity"]["vp_token"].clone(),
        trust_profile_id: None,
        nonce: None,
        audience: None,
        context: serde_json::Map::new(),
        oid4vp_transport: None,
        trusted_internal_context: false,
    };

    let error = orchestrator.verify(&policy(), &request).await.unwrap_err();
    assert!(matches!(error, PresentationVerificationError::Unavailable));
    assert!(kernel.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn cross_tenant_trust_profile_evidence_is_rejected_before_kernel_use() {
    let fixture = fixture();
    let kernel = Arc::new(Kernel::default());
    let trust = Arc::new(Trust {
        evidence: IssuerTrustEvidence::default(),
        fail_load: false,
        profile_organization_id: Some(Uuid::from_u128(999)),
        profile_document: None,
        loads: Mutex::new(Vec::new()),
    });
    let status = Arc::new(Status {
        evidence: CredentialStatusEvidence::default(),
        calls: Mutex::new(Vec::new()),
    });
    let orchestrator = VerifiedFactsOrchestrator::new(kernel.clone(), trust, status).unwrap();
    let request = marty_presentation_policy::EvaluatePresentationRequest {
        vp_token: fixture["valid_data_integrity"]["vp_token"].clone(),
        trust_profile_id: None,
        nonce: None,
        audience: None,
        context: serde_json::Map::new(),
        oid4vp_transport: None,
        trusted_internal_context: false,
    };

    let error = orchestrator.verify(&policy(), &request).await.unwrap_err();
    assert!(matches!(error, PresentationVerificationError::Failed(_)));
    assert!(kernel.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn only_authenticated_internal_oid4vp_context_can_project_replay_evidence() {
    let fixture = fixture();
    let vector = &fixture["valid_data_integrity"];
    let context_vector = &fixture["trusted_oid4vp_context"];
    let mut evidence: CredentialVerificationEvidence =
        serde_json::from_value(vector["kernel_evidence"].clone()).unwrap();
    evidence.holder_binding_method = context_vector["kernel_binding_method"]
        .as_str()
        .map(str::to_owned);
    evidence.proof_profile = context_vector["kernel_proof_profile"]
        .as_str()
        .map(str::to_owned);
    evidence.replay_check_verified = false;

    let verify = |trusted_internal_context| {
        let kernel = Arc::new(Kernel {
            evidence: Mutex::new(evidence.clone()),
            calls: Mutex::new(Vec::new()),
        });
        let orchestrator = VerifiedFactsOrchestrator::with_clock(
            kernel,
            Arc::new(Trust {
                evidence: serde_json::from_value(vector["trust_evidence"].clone()).unwrap(),
                fail_load: false,
                profile_organization_id: None,
                profile_document: None,
                loads: Mutex::new(Vec::new()),
            }),
            Arc::new(Status {
                evidence: CredentialStatusEvidence::default(),
                calls: Mutex::new(Vec::new()),
            }),
            Arc::new(|| 1_787_240_300),
        )
        .unwrap();
        let request = marty_presentation_policy::EvaluatePresentationRequest {
            vp_token: vector["vp_token"].clone(),
            trust_profile_id: None,
            nonce: Some("nonce-1".into()),
            audience: Some("verifier-1".into()),
            context: context_vector["context"].as_object().unwrap().clone(),
            oid4vp_transport: None,
            trusted_internal_context,
        };
        (orchestrator, request)
    };

    let (orchestrator, request) = verify(true);
    let trusted = orchestrator.verify(&policy(), &request).await.unwrap();
    assert_eq!(
        trusted["holder_binding_method"],
        context_vector["expected_binding_method"]
    );
    assert_eq!(
        trusted["proof_profile"],
        context_vector["expected_proof_profile"]
    );
    assert_eq!(
        trusted["replay_check_verified"],
        context_vector["expected_replay_check_verified"]
    );

    // Transport structure is not proof: it must not alter the current facts.
    let (orchestrator, mut request) = verify(true);
    let query = serde_json::json!({"credentials": [{"id": "member"}]});
    request.oid4vp_transport = Some(marty_oid4vp_contract::Oid4vpEvaluationTransportV1 {
        query_kind: marty_oid4vp_contract::QueryKind::Dcql,
        query_digest: marty_oid4vp_contract::digest_query_document(&query).unwrap(),
        query_document: query,
        presentation_submission: Some(serde_json::json!({"id": "untrusted"})),
        vp_token_raw: "header.payload.signature".into(),
        verifier_client_id: "did:web:verifier.example".into(),
        request_nonce: "nonce-with-at-least-32-bytes-1234567890".into(),
    });
    assert_eq!(
        orchestrator.verify(&policy(), &request).await.unwrap(),
        trusted
    );

    let (orchestrator, request) = verify(false);
    let untrusted = orchestrator.verify(&policy(), &request).await.unwrap();
    assert_eq!(
        untrusted["replay_check_verified"],
        context_vector["untrusted_http_replay_check_verified"]
    );
    assert_eq!(
        untrusted["holder_binding_method"],
        context_vector["kernel_binding_method"]
    );
}

#[tokio::test]
async fn cedar_authorization_uses_only_complete_verified_evidence_and_denies_weak_algorithms() {
    let fixture = fixture();
    let vector = &fixture["valid_data_integrity"];
    for (algorithm, expected_evaluated, expected_allowed) in [
        (None, false, false),
        (
            fixture["cedar_evidence"]["weak_algorithm"].as_str(),
            true,
            fixture["cedar_evidence"]["weak_algorithm_allowed"]
                .as_bool()
                .unwrap(),
        ),
    ] {
        let mut evidence: CredentialVerificationEvidence =
            serde_json::from_value(vector["kernel_evidence"].clone()).unwrap();
        evidence.algorithm = algorithm.map(str::to_owned);
        let orchestrator = VerifiedFactsOrchestrator::with_clock(
            Arc::new(Kernel {
                evidence: Mutex::new(evidence),
                calls: Mutex::new(Vec::new()),
            }),
            Arc::new(Trust {
                evidence: serde_json::from_value(vector["trust_evidence"].clone()).unwrap(),
                fail_load: false,
                profile_organization_id: None,
                profile_document: None,
                loads: Mutex::new(Vec::new()),
            }),
            Arc::new(Status {
                evidence: serde_json::from_value(vector["status_evidence"].clone()).unwrap(),
                calls: Mutex::new(Vec::new()),
            }),
            Arc::new(|| 1_787_240_300),
        )
        .unwrap();
        let request = marty_presentation_policy::EvaluatePresentationRequest {
            vp_token: vector["vp_token"].clone(),
            trust_profile_id: None,
            nonce: None,
            audience: None,
            context: serde_json::Map::new(),
            oid4vp_transport: None,
            trusted_internal_context: false,
        };

        let facts = orchestrator.verify(&policy(), &request).await.unwrap();
        assert_eq!(
            facts["external_authorization"]["evaluated"],
            expected_evaluated
        );
        assert_eq!(facts["external_authorization"]["allowed"], expected_allowed);
        if algorithm.is_none() {
            assert_eq!(
                facts["external_authorization"]["errors"][0],
                fixture["cedar_evidence"]["missing_algorithm_error"]
            );
        } else {
            assert_eq!(
                facts["external_authorization"]["reasons"][0],
                "deny-weak-algorithms"
            );
        }
    }
}

#[tokio::test]
async fn presentation_only_verification_bypasses_credential_trust_status_and_cedar() {
    let fixture = fixture();
    let vector = &fixture["valid_data_integrity"];
    let kernel = Arc::new(Kernel {
        evidence: Mutex::new(serde_json::from_value(vector["kernel_evidence"].clone()).unwrap()),
        calls: Mutex::new(Vec::new()),
    });
    let trust = Arc::new(Trust {
        evidence: IssuerTrustEvidence::default(),
        fail_load: true,
        profile_organization_id: None,
        profile_document: None,
        loads: Mutex::new(Vec::new()),
    });
    let status = Arc::new(Status {
        evidence: serde_json::from_value(vector["status_evidence"].clone()).unwrap(),
        calls: Mutex::new(Vec::new()),
    });
    let orchestrator = VerifiedFactsOrchestrator::with_clock(
        kernel,
        trust.clone(),
        status.clone(),
        Arc::new(|| 1_787_240_300),
    )
    .unwrap();
    let mut presentation_policy = policy();
    presentation_policy.credential_requirements.clear();
    let request = marty_presentation_policy::EvaluatePresentationRequest {
        vp_token: vector["vp_token"].clone(),
        trust_profile_id: Some(REQUEST_PROFILE_ID.to_string()),
        nonce: Some("nonce-1".into()),
        audience: Some("verifier-1".into()),
        context: serde_json::Map::new(),
        oid4vp_transport: None,
        trusted_internal_context: false,
    };

    let facts = orchestrator
        .verify(&presentation_policy, &request)
        .await
        .unwrap();
    assert_eq!(facts["credentials"], json!([]));
    assert_eq!(facts["external_authorization"], Value::Null);
    assert!(trust.loads.lock().unwrap().is_empty());
    assert!(status.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn exact_mdoc_direct_pin_relationship_supplies_governed_lifecycle_status() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/presentation-mdoc-lifecycle-behavior.json"
    ))
    .unwrap();
    let fingerprint = contract["issuer_certificate_sha256"].as_str().unwrap();
    let issuer_id = format!("x509-sha256:{fingerprint}");
    let mut relationship = contract["relationship"].clone();
    relationship["issuer_id"] = Value::String(issuer_id.clone());
    let profile = json!({
        "status": "active",
        "trust_sources": [{
            "source_type": "PINNED_ISSUER",
            "enabled": true,
            "certificate_pem": contract["certificate_pem"]
        }],
        "issuer_relationships": [relationship]
    });
    let kernel = Arc::new(Kernel {
        evidence: Mutex::new(CredentialVerificationEvidence {
            verified: true,
            claims: serde_json::from_value(json!({"email": "holder@example.com"})).unwrap(),
            issuer_id: Some(issuer_id),
            issued_at_epoch_seconds: Some(1_787_240_270),
            algorithm: Some("ES256".into()),
            validity_checked: true,
            is_expired: Some(false),
            presentation_verified: true,
            presentation_count: Some(1),
            holder_binding_verified: true,
            holder_binding_method: Some("DEVICE_KEY".into()),
            proof_profile: Some("OID4VP_VERIFIABLE_PRESENTATION".into()),
            challenge_verified: true,
            audience_verified: true,
            ..Default::default()
        }),
        calls: Mutex::new(Vec::new()),
    });
    let status = Arc::new(Status {
        evidence: CredentialStatusEvidence::default(),
        calls: Mutex::new(Vec::new()),
    });
    let orchestrator = VerifiedFactsOrchestrator::with_clock(
        kernel,
        Arc::new(Trust {
            evidence: IssuerTrustEvidence {
                verified: true,
                trust_level: Some(87),
                compliance_statuses: vec!["ACCREDITED".into()],
                accreditations: vec!["ISO27001".into()],
                ..Default::default()
            },
            fail_load: false,
            profile_organization_id: None,
            profile_document: Some(profile),
            loads: Mutex::new(Vec::new()),
        }),
        status.clone(),
        Arc::new(|| 1_787_240_300),
    )
    .unwrap();
    let mut mdoc_policy = policy();
    mdoc_policy.credential_requirements[0].credential_payload_format = "MDOC".into();
    mdoc_policy.freshness = Some(FreshnessPolicy {
        max_age_seconds: None,
        require_not_revoked: true,
        revocation_grace_seconds: None,
    });
    let request = marty_presentation_policy::EvaluatePresentationRequest {
        vp_token: Value::String("\\x010203".into()),
        trust_profile_id: None,
        nonce: Some("nonce-1".into()),
        audience: Some("verifier-1".into()),
        context: serde_json::Map::new(),
        oid4vp_transport: None,
        trusted_internal_context: false,
    };

    let facts = orchestrator.verify(&mdoc_policy, &request).await.unwrap();
    assert_eq!(
        facts["credentials"][0]["revocation_checked_at_epoch_seconds"], 1_787_240_300_u64,
        "{facts}"
    );
    assert_eq!(facts["credentials"][0]["not_revoked"], true);
    assert_eq!(facts["external_authorization"]["allowed"], true);
    assert!(status.calls.lock().unwrap().is_empty());
}

struct ForeignPublicKeyResolver {
    keys: Vec<Value>,
}
#[async_trait]
impl marty_issuer_key_resolution::IssuerKeyResolver for ForeignPublicKeyResolver {
    async fn resolve(
        &self,
        _: &str,
    ) -> Result<
        marty_issuer_key_resolution::IssuerKeyResolution,
        marty_issuer_key_resolution::IssuerKeyResolutionError,
    > {
        Ok(marty_issuer_key_resolution::IssuerKeyResolution {
            verification_keys: self.keys.clone(),
            source: "test-resolver".into(),
            retrieved_at: "2026-01-01T00:00:00Z".into(),
            content_sha256: "test".into(),
        })
    }
}

struct NativeForeignTrust {
    issuer: String,
}
#[async_trait]
impl PresentationTrustResolver for NativeForeignTrust {
    async fn load_profile(
        &self,
        profile_id: Uuid,
        organization_id: Uuid,
    ) -> Result<ResolvedTrustProfile, PresentationVerificationError> {
        Ok(ResolvedTrustProfile {
            id: profile_id,
            organization_id,
            document: json!({"status":"ACTIVE","allowed_issuers":[self.issuer],"issuer_relationships":[]}),
        })
    }
    async fn evaluate_issuer(
        &self,
        profile: &ResolvedTrustProfile,
        issuer: &str,
        format: DetectedCredentialFormat,
    ) -> Result<IssuerTrustEvidence, PresentationVerificationError> {
        let control = marty_presentation_policy::NativePresentationControlPlane::connect_lazy(
            "http://127.0.0.1:9",
            "http://127.0.0.1:9",
            "http://127.0.0.1:9/{credential_id}",
            None,
            None,
            std::time::Duration::from_secs(1),
        )?;
        control.evaluate_issuer(profile, issuer, format).await
    }
}

#[tokio::test]
async fn resolved_foreign_signature_does_not_establish_policy_trust() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/foreign_ob3_jwt.json")).unwrap();
    let raw = marty_verification::vcdm::verify_open_badge_v3_jwt_json_async(
        &json!({"token":fixture["token"],"issuer_public_jwk":fixture["public_jwk"]}).to_string(),
    )
    .await;
    let result: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(result["valid"], true, "{}", result["errors"]);
    for trusted in [false, true] {
        let trust = Arc::new(NativeForeignTrust {
            issuer: if trusted {
                fixture["issuer"].as_str().unwrap().into()
            } else {
                "did:web:trusted.example".into()
            },
        });
        let status = Arc::new(Status {
            evidence: CredentialStatusEvidence::default(),
            calls: Mutex::new(Vec::new()),
        });
        let kernel = marty_presentation_policy::ResolvingCredentialKernel::new(Arc::new(
            ForeignPublicKeyResolver {
                keys: vec![fixture["public_jwk"].clone()],
            },
        ));
        let orchestrator = VerifiedFactsOrchestrator::with_clock(
            Arc::new(kernel),
            trust,
            status,
            Arc::new(|| 1_787_240_300),
        )
        .unwrap();
        let mut policy = policy();
        policy.credential_requirements[0].credential_payload_format = "openbadge-v3".into();
        let request = marty_presentation_policy::EvaluatePresentationRequest {
            vp_token: fixture["token"].clone(),
            trust_profile_id: None,
            nonce: None,
            audience: None,
            context: serde_json::Map::new(),
            oid4vp_transport: None,
            trusted_internal_context: false,
        };
        let facts = orchestrator.verify(&policy, &request).await.unwrap();
        assert_eq!(
            facts["credentials"][0]["signature_verified"], true,
            "{facts}"
        );
        assert_eq!(
            facts["credentials"][0]["trust_profile_verified"], trusted,
            "{facts}"
        );
        assert_eq!(facts["credentials"][0]["issuer_id"], fixture["issuer"]);
        if !trusted {
            assert_eq!(
                facts["credentials"][0]["trust_failure_reason"],
                "Issuer is not in Trust Profile allowed_issuers"
            );
        }
    }
}

#[tokio::test]
async fn foreign_key_resolution_rejects_tampering_private_and_ambiguous_keys() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/foreign_ob3_jwt.json")).unwrap();
    let mut private = fixture["public_jwk"].clone();
    private["d"] = json!("prohibited");
    let mut wrong_kid = fixture["public_jwk"].clone();
    wrong_kid["kid"] = json!("did:web:other.example#key");
    let key = fixture["public_jwk"].clone();
    for keys in [
        vec![private],
        vec![wrong_kid],
        vec![key.clone(), key.clone()],
    ] {
        let kernel = marty_presentation_policy::ResolvingCredentialKernel::new(Arc::new(
            ForeignPublicKeyResolver { keys },
        ));
        let context = CredentialVerificationContext {
            presentation_only: false,
            resolved_issuer_public_jwk: Some(key.clone()),
            format: DetectedCredentialFormat::OpenbadgeV3,
            token: fixture["token"].clone(),
            nonce: None,
            audience: None,
            verifier_context: serde_json::Map::new(),
            trust_profile: None,
        };
        assert!(!kernel.verify(&context).await.unwrap().verified);
    }
    let kernel = marty_presentation_policy::ResolvingCredentialKernel::new(Arc::new(
        ForeignPublicKeyResolver { keys: vec![key] },
    ));
    let mut token = fixture["token"].as_str().unwrap().to_owned();
    let start = token.rfind('.').unwrap() + 1;
    token.replace_range(
        start..start + 1,
        if &token[start..start + 1] == "A" {
            "B"
        } else {
            "A"
        },
    );
    let context = CredentialVerificationContext {
        presentation_only: false,
        resolved_issuer_public_jwk: None,
        format: DetectedCredentialFormat::OpenbadgeV3,
        token: json!(token),
        nonce: None,
        audience: None,
        verifier_context: serde_json::Map::new(),
        trust_profile: None,
    };
    assert!(!kernel.verify(&context).await.unwrap().verified);
}

struct MustNotResolve;
#[async_trait]
impl marty_issuer_key_resolution::IssuerKeyResolver for MustNotResolve {
    async fn resolve(
        &self,
        _: &str,
    ) -> Result<
        marty_issuer_key_resolution::IssuerKeyResolution,
        marty_issuer_key_resolution::IssuerKeyResolutionError,
    > {
        panic!("governed issuer must not trigger network key discovery")
    }
}

#[tokio::test]
async fn existing_governed_key_remains_authoritative_without_resolution() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/foreign_ob3_jwt.json")).unwrap();
    let context = CredentialVerificationContext {
        presentation_only: false,
        resolved_issuer_public_jwk: None,
        format: DetectedCredentialFormat::OpenbadgeV3,
        token: fixture["token"].clone(),
        nonce: None,
        audience: None,
        verifier_context: serde_json::Map::new(),
        trust_profile: Some(ResolvedTrustProfile {
            id: POLICY_PROFILE_ID,
            organization_id: ORGANIZATION_ID,
            document: json!({"status":"ACTIVE","issuer_relationships":[{
                "issuer_id":fixture["issuer"],"relationship_status":"TRUSTED","compliance_status":"COMPLIANT",
                "verification_keys":[fixture["public_jwk"]]}]}),
        }),
    };
    let kernel =
        marty_presentation_policy::ResolvingCredentialKernel::new(Arc::new(MustNotResolve));
    assert!(kernel.verify(&context).await.unwrap().verified);
}
