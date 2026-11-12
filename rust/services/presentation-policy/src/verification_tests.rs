// Native proof fixtures live inside the crate so their owner provenance constructor
// is compiled only for unit tests, never exposed through the production API.

use std::sync::{Arc, Mutex};

use crate::{
    ClaimConstraint, ConstraintType, CredentialRequirement, CredentialStatusEvidence,
    CredentialStatusResolver, CredentialVerificationContext, CredentialVerificationEvidence,
    CredentialVerificationKernel, DisplayMetadata, FreshnessPolicy, HolderBinding,
    IssuerTrustEvidence, PolicyStatus, PresentationPolicy, PresentationTrustResolver,
    PresentationVerificationError, PresentationVerificationOrchestrator, RequestPurpose,
    RequestedClaim, ResolvedCredentialTemplate, ResolvedTrustProfile, ResolvedVerificationPolicy,
    RustCredentialKernel, VerifiedFactsOrchestrator,
};
use async_trait::async_trait;
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
    template_vct: Option<&'static str>,
    evidence: IssuerTrustEvidence,
    fail_load: bool,
    profile_organization_id: Option<Uuid>,
    profile_document: Option<Value>,
    loads: Mutex<Vec<(Uuid, Uuid)>>,
}

#[async_trait]
impl PresentationTrustResolver for Trust {
    async fn load_credential_template(
        &self,
        template_id: &str,
        organization_id: Uuid,
    ) -> Result<ResolvedCredentialTemplate, PresentationVerificationError> {
        assert_eq!(template_id, "template-email");
        Ok(ResolvedCredentialTemplate {
            id: template_id.into(),
            organization_id,
            credential_type: "EmailCredential".into(),
            vct: Some(self.template_vct.unwrap_or("EmailCredential").into()),
            doctype: Some("EmailCredential".into()),
            status: "ACTIVE".into(),
        })
    }

    async fn load_verification_policy(
        &self,
        id: Uuid,
        organization_id: Uuid,
    ) -> Result<ResolvedVerificationPolicy, PresentationVerificationError> {
        Ok(ResolvedVerificationPolicy { id, organization_id, revision: "explicit-test-policy".into(), cedar_policies: r#"
            permit(principal, action == MIP::Action::"credentials:verify", resource);
            forbid(principal, action == MIP::Action::"credentials:verify", resource) when { context.algorithm == "RS256" };
        "#.into() })
    }

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
                .unwrap_or_else(|| json!({"public_verification_material": true, "allowed_algorithms":["ES256","EdDSA"]})),
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
        prerequisite_evidence_profile: None,
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
async fn retired_ob2_never_produces_verified_policy_material() {
    let fixture: Value =
        serde_json::from_str(include_str!("../tests/fixtures/governed_ob2.json")).unwrap();
    let mut assertion = fixture["assertion"].clone();
    assertion.as_object_mut().unwrap().remove("signature");
    assertion.as_object_mut().unwrap().remove("verification");
    let trust = Arc::new(Trust {
        template_vct: None,
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
    let mut request = crate::EvaluatePresentationRequest {
        vp_token: json!({"credential": assertion, "document_store": fixture["document_store"]}),
        trust_profile_id: None,
        nonce: None,
        audience: None,
        context: serde_json::Map::new(),
        oid4vp_transport: None,
        trusted_internal_context: false,
    };
    request
        .context
        .insert("authenticated_outer_jti".into(), json!("urn:uuid:forged"));
    let material = orchestrator
        .verify_material(&policy(), &request)
        .await
        .unwrap();
    assert!(material.authenticated_outer_jti().is_none());
    let facts = material.policy_facts();
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
    assert_eq!(standard["credentials"][0]["signature_verified"], false);
    assert_eq!(standard["credentials"][0]["trust_profile_verified"], false);
    assert_eq!(standard["credentials"][0]["issuer_id"], "unknown");
    assert_eq!(standard["credentials"][0]["claims"], json!({}));
    assert_eq!(
        standard["credentials"][0]["signature_failure_reason"],
        "Open Badges 2.0 is retired; request a newly issued Open Badges 3.0 credential"
    );
    assert!(status.calls.lock().unwrap().is_empty());
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
        template_vct: None,
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
    let request = crate::EvaluatePresentationRequest {
        vp_token: vector["vp_token"].clone(),
        trust_profile_id: Some(POLICY_PROFILE_ID.to_string()),
        nonce: Some("nonce-1".into()),
        audience: Some("verifier-1".into()),
        context: serde_json::Map::new(),
        oid4vp_transport: None,
        trusted_internal_context: false,
    };

    let material = orchestrator
        .verify_material(&policy(), &request)
        .await
        .unwrap();
    assert_eq!(material.policy_facts(), &vector["expected"]);
    assert!(material.authenticated_outer_jti().is_none());

    {
        let calls = kernel.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].nonce.as_deref(), Some("nonce-1"));
        assert_eq!(calls[0].audience.as_deref(), Some("verifier-1"));
        assert_eq!(
            calls[0].trust_profile.as_ref().unwrap().id,
            POLICY_PROFILE_ID
        );
    }
    assert_eq!(
        trust.loads.lock().unwrap().as_slice(),
        &[(POLICY_PROFILE_ID, ORGANIZATION_ID)]
    );
    assert_eq!(status.calls.lock().unwrap().len(), 1);
    kernel.evidence.lock().unwrap().credential_id = None;
    let without_id = orchestrator
        .verify_material(&policy(), &request)
        .await
        .unwrap();
    assert_eq!(
        without_id.policy_facts()["credentials"][0]["credential_id"],
        "presented-credential"
    );
    assert!(without_id.authenticated_outer_jti().is_none());
}

#[tokio::test]
async fn malformed_presentations_are_denied_without_invoking_any_format_kernel() {
    let kernel = Arc::new(Kernel::default());
    let trust = Arc::new(Trust {
        template_vct: None,
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
    let request = crate::EvaluatePresentationRequest {
        vp_token: Value::String("not-a-credential".into()),
        trust_profile_id: None,
        nonce: None,
        audience: None,
        context: serde_json::Map::new(),
        oid4vp_transport: None,
        trusted_internal_context: false,
    };

    let material = orchestrator
        .verify_material(&policy(), &request)
        .await
        .unwrap();
    assert!(material.authenticated_outer_jti().is_none());
    let result = material.policy_facts();
    assert_eq!(result["credentials"][0]["signature_verified"], false);
    assert_eq!(result["credentials"][0]["claims"], json!({}));
    assert!(kernel.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn unavailable_trust_backend_fails_closed_before_cryptographic_verification() {
    let fixture = fixture();
    let kernel = Arc::new(Kernel::default());
    let trust = Arc::new(Trust {
        template_vct: None,
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
    let request = crate::EvaluatePresentationRequest {
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
        template_vct: None,
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
    let request = crate::EvaluatePresentationRequest {
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

    let verify = |trusted_internal_context: bool| {
        let kernel = Arc::new(Kernel {
            evidence: Mutex::new(evidence.clone()),
            calls: Mutex::new(Vec::new()),
        });
        let orchestrator = VerifiedFactsOrchestrator::with_clock(
            kernel,
            Arc::new(Trust {
                template_vct: None,
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
        let request = crate::EvaluatePresentationRequest {
            vp_token: vector["vp_token"].clone(),
            trust_profile_id: None,
            nonce: Some("nonce-1".into()),
            audience: Some("verifier-1".into()),
            context: context_vector["context"].as_object().unwrap().clone(),
            oid4vp_transport: trusted_internal_context.then(|| {
                let query = json!({"credentials":[{"id":"email","format":"ldp_vc","meta":{"type_values":[["VerifiableCredential","EmailCredential"]]},"claims":[{"id":"email","path":["credentialSubject","email"]}]}]});
                marty_oid4vp_contract::Oid4vpEvaluationTransportV1 {
                    credential_authority: None,
                    query_kind: marty_oid4vp_contract::QueryKind::Dcql,
                    query_digest: marty_oid4vp_contract::digest_query_document(&query).unwrap(), query_document: query,
                    presentation_submission: None,
                    vp_token_raw: serde_json::to_string(&vector["vp_token"].to_string()).unwrap(),
                    verifier_client_id: "verifier-1".into(), request_nonce: "nonce-1".into(),
                }
            }),
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

    // A different or incomplete query cannot be ignored in favor of selected-token facts.
    let (orchestrator, mut request) = verify(true);
    let query = serde_json::json!({"credentials": [{"id": "member"}]});
    request.oid4vp_transport = Some(marty_oid4vp_contract::Oid4vpEvaluationTransportV1 {
        credential_authority: None,
        query_kind: marty_oid4vp_contract::QueryKind::Dcql,
        query_digest: marty_oid4vp_contract::digest_query_document(&query).unwrap(),
        query_document: query,
        presentation_submission: Some(serde_json::json!({"id": "untrusted"})),
        vp_token_raw: "header.payload.signature".into(),
        verifier_client_id: "did:web:verifier.example".into(),
        request_nonce: "nonce-with-at-least-32-bytes-1234567890".into(),
    });
    assert!(orchestrator.verify(&policy(), &request).await.is_err());
    let (orchestrator, mut request) = verify(true);
    request.oid4vp_transport = None;
    assert!(orchestrator.verify(&policy(), &request).await.is_err());

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
async fn linked_cedar_policy_uses_complete_evidence_and_its_configured_algorithm_rule() {
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
                template_vct: None,
                evidence: serde_json::from_value(vector["trust_evidence"].clone()).unwrap(),
                fail_load: false,
                profile_organization_id: None,
                profile_document: Some(json!({"verification_policy_set_id": Uuid::from_u128(41)})),
                loads: Mutex::new(Vec::new()),
            }),
            Arc::new(Status {
                evidence: serde_json::from_value(vector["status_evidence"].clone()).unwrap(),
                calls: Mutex::new(Vec::new()),
            }),
            Arc::new(|| 1_787_240_300),
        )
        .unwrap();
        let request = crate::EvaluatePresentationRequest {
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
            facts["credentials"][0]["external_authorization"]["evaluated"],
            expected_evaluated
        );
        assert_eq!(
            facts["credentials"][0]["external_authorization"]["allowed"],
            expected_allowed
        );
        if algorithm.is_none() {
            assert_eq!(
                facts["credentials"][0]["external_authorization"]["errors"][0],
                fixture["cedar_evidence"]["missing_algorithm_error"]
            );
        } else {
            assert!(facts["credentials"][0]["external_authorization"]["reasons"]
                .as_array()
                .unwrap()
                .iter()
                .any(|reason| reason == "policy1"));
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
        template_vct: None,
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
    let request = crate::EvaluatePresentationRequest {
        vp_token: vector["vp_token"].clone(),
        trust_profile_id: None,
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
async fn mdoc_issuer_relationship_does_not_prove_credential_non_revocation() {
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
        "verification_policy_set_id": Uuid::from_u128(41),
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
            credential_types: vec!["EmailCredential".into()],
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
            template_vct: None,
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
    let request = crate::EvaluatePresentationRequest {
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
        !facts["credentials"][0]["not_revoked"].is_null(),
        contract["expected"]["credential_status_evidence_present"]
            .as_bool()
            .unwrap()
    );
    assert!(facts["credentials"][0]["revocation_checked_at_epoch_seconds"].is_null());
    assert_eq!(
        facts["credentials"][0]["external_authorization"]["allowed"],
        false
    );
    assert!(
        facts["credentials"][0]["external_authorization"]["errors"][0]
            .as_str()
            .unwrap()
            .contains("non-revocation")
    );
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
            content_sha256: "a".repeat(64),
        })
    }
}

struct NativeForeignTrust {
    issuer: String,
}
#[async_trait]
impl PresentationTrustResolver for NativeForeignTrust {
    async fn load_credential_template(
        &self,
        template_id: &str,
        organization_id: Uuid,
    ) -> Result<ResolvedCredentialTemplate, PresentationVerificationError> {
        Ok(ResolvedCredentialTemplate {
            id: template_id.into(),
            organization_id,
            credential_type: "OpenBadgeCredential".into(),
            vct: None,
            doctype: None,
            status: "ACTIVE".into(),
        })
    }
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
        let control = crate::NativePresentationControlPlane::connect_lazy(
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
    let fixture: Value = serde_json::from_str(include_str!(
        "../tests/fixtures/foreign_ob3_with_criteria_jwt.json"
    ))
    .unwrap();
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
        let kernel = crate::ResolvingCredentialKernel::new(Arc::new(ForeignPublicKeyResolver {
            keys: vec![fixture["public_jwk"].clone()],
        }));
        let orchestrator = VerifiedFactsOrchestrator::with_clock(
            Arc::new(kernel),
            trust,
            status,
            Arc::new(|| 1_787_240_300),
        )
        .unwrap();
        let mut policy = policy();
        policy.credential_requirements[0].credential_payload_format = "openbadge-v3".into();
        let mut request = crate::EvaluatePresentationRequest {
            vp_token: fixture["token"].clone(),
            trust_profile_id: None,
            nonce: None,
            audience: None,
            context: serde_json::Map::new(),
            oid4vp_transport: None,
            trusted_internal_context: false,
        };
        request.context.insert(
            "authenticated_outer_jti".into(),
            json!("urn:uuid:forged-by-caller"),
        );
        let material = orchestrator
            .verify_material(&policy, &request)
            .await
            .unwrap();
        assert_eq!(
            material.authenticated_outer_jti(),
            Some("urn:uuid:ob3-credential-1")
        );
        let facts = material.policy_facts();
        assert!(facts.get("authenticated_outer_jti").is_none());
        assert!(facts["credentials"][0]
            .get("authenticated_outer_jti")
            .is_none());
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
async fn historical_foreign_ob3_signature_remains_authentic_but_missing_criteria_is_denied() {
    let fixture: Value =
        serde_json::from_str(include_str!("../tests/fixtures/foreign_ob3_jwt.json")).unwrap();
    let request =
        json!({"token":fixture["token"],"issuer_public_jwk":fixture["public_jwk"]}).to_string();
    let generic = marty_verification::vcdm::verify_vcdm_jwt_json_async(&request).await;
    let generic: Value = serde_json::from_str(&generic).unwrap();
    assert_eq!(generic["valid"], true, "{}", generic["errors"]);

    let profile = marty_verification::vcdm::verify_open_badge_v3_jwt_json_async(&request).await;
    let profile: Value = serde_json::from_str(&profile).unwrap();
    assert_eq!(profile["valid"], false);
    assert!(profile["errors"].as_array().unwrap().iter().any(|error| {
        error
            .as_str()
            .is_some_and(|error| error.contains("achievement criteria"))
    }));
}

#[tokio::test]
async fn foreign_key_resolution_rejects_tampering_private_and_ambiguous_keys() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../tests/fixtures/foreign_ob3_with_criteria_jwt.json"
    ))
    .unwrap();
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
        let kernel =
            crate::ResolvingCredentialKernel::new(Arc::new(ForeignPublicKeyResolver { keys }));
        let context = CredentialVerificationContext {
            presentation_only: false,
            sd_jwt_dcql: None,
            resolved_issuer_key: Some(crate::ResolvedIssuerKey {
                issuer_id: fixture["issuer"].as_str().unwrap().into(),
                public_jwk: key.clone(),
                provenance: crate::IssuerKeyProvenance {
                    mechanism: crate::IssuerKeyMechanism::TrustProfileKey,
                    trust_profile_id: None,
                    organization_id: None,
                    issuer_organization_id: None,
                    source: "caller-supplied-must-be-cleared".into(),
                    retrieved_at: None,
                    content_sha256: None,
                },
            }),
            format: DetectedCredentialFormat::OpenbadgeV3,
            token: fixture["token"].clone(),
            nonce: None,
            audience: None,
            verifier_context: serde_json::Map::new(),
            trust_profile: None,
        };
        assert!(!kernel.verify(&context).await.unwrap().verified);
    }
    let kernel = crate::ResolvingCredentialKernel::new(Arc::new(ForeignPublicKeyResolver {
        keys: vec![key],
    }));
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
        sd_jwt_dcql: None,
        resolved_issuer_key: None,
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
    let fixture: Value = serde_json::from_str(include_str!(
        "../tests/fixtures/foreign_ob3_with_criteria_jwt.json"
    ))
    .unwrap();
    let context = CredentialVerificationContext {
        presentation_only: false,
        sd_jwt_dcql: None,
        resolved_issuer_key: None,
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
    let kernel = crate::ResolvingCredentialKernel::new(Arc::new(MustNotResolve));
    assert!(kernel.verify(&context).await.unwrap().verified);
}

#[tokio::test]
async fn explicit_profile_key_authority_cannot_downgrade_to_public_discovery() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../tests/fixtures/foreign_ob3_with_criteria_jwt.json"
    ))
    .unwrap();
    let issuer = fixture["issuer"].as_str().unwrap();
    let mut mismatched_key = fixture["public_jwk"].clone();
    mismatched_key["kid"] = json!(format!("{issuer}#different-pinned-key"));
    let relationship = json!({
        "issuer_id":issuer, "relationship_status":"TRUSTED", "compliance_status":"COMPLIANT",
        "verification_keys":[mismatched_key]
    });
    for profile in [
        json!({"status":"ACTIVE", "issuer_relationships":[relationship]}),
        json!({"status":"ACTIVE", "system_issuer_overrides":{issuer:{"public_jwk":mismatched_key}}}),
        json!({"status":"ACTIVE", "system_issuer_overrides":{issuer:{"public_jwk":mismatched_key}},
            "issuer_relationships":[{"issuer_id":issuer,"relationship_status":"TRUSTED",
                "compliance_status":"COMPLIANT","verification_keys":[fixture["public_jwk"]]}]}),
        json!({"status":"ACTIVE", "issuer_relationships":[relationship.clone(), relationship]}),
    ] {
        let context = CredentialVerificationContext {
            presentation_only: false,
            sd_jwt_dcql: None,
            resolved_issuer_key: None,
            format: DetectedCredentialFormat::OpenbadgeV3,
            token: fixture["token"].clone(),
            nonce: None,
            audience: None,
            verifier_context: serde_json::Map::new(),
            trust_profile: Some(ResolvedTrustProfile {
                id: POLICY_PROFILE_ID,
                organization_id: ORGANIZATION_ID,
                document: profile,
            }),
        };
        let kernel = crate::ResolvingCredentialKernel::new(Arc::new(MustNotResolve));
        let rejected = kernel.verify(&context).await.unwrap();
        assert!(!rejected.verified);
        assert!(rejected.claims.is_empty() && rejected.authenticated_issuer.is_none());
        assert_eq!(
            rejected.failure_reason.as_deref(),
            Some("Trust Profile does not authorize this issuer signing key")
        );
    }
}

mod bounded_sd_jwt_query_evidence {
    use super::*;
    use crate::{
        evaluate_verified_facts_for_policy, evaluate_verified_material_for_policy, policy_revision,
        EvaluatePresentationRequest, VerifiedPolicyMaterial,
    };
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use ed25519_dalek::{Signer, SigningKey};
    use marty_oid4vp_contract::{
        digest_audience, digest_domain_json, digest_nonce, digest_query_document,
        digest_response_item, Oid4vpEvaluationTransportV1, QueryKind,
    };
    use p256::ecdsa::{
        signature::Signer as _, Signature as P256Signature, SigningKey as P256SigningKey,
    };
    use sha2::{Digest, Sha256};
    use std::sync::atomic::{AtomicBool, Ordering};

    const ISSUER: &str = "did:web:prerequisite-issuer.example";
    const ISSUER_KEY_ID: &str = "did:web:prerequisite-issuer.example#assertion";
    const SUBJECT: &str = "issuer-local-prerequisite-subject-001";
    const EMAIL: &str = "private-selected-email@example.test";
    const VCT: &str = "urn:example:prerequisite-email";
    const AUDIENCE: &str = "did:web:prerequisite-verifier.example";

    fn issuer_key() -> SigningKey {
        SigningKey::from_bytes(&[31; 32])
    }

    fn holder_key() -> SigningKey {
        SigningKey::from_bytes(&[79; 32])
    }

    fn public_key(key: &SigningKey) -> Value {
        json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes()),
        })
    }

    fn sign_jwt(key: &SigningKey, header: Value, claims: &Value) -> String {
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string()),
        );
        format!(
            "{input}.{}",
            URL_SAFE_NO_PAD.encode(key.sign(input.as_bytes()).to_bytes()),
        )
    }

    fn issuer_jwt(claims: &Value) -> String {
        sign_jwt(
            &issuer_key(),
            json!({"alg": "EdDSA", "typ": "dc+sd-jwt", "kid": ISSUER_KEY_ID}),
            claims,
        )
    }

    fn bind_issuer_jwt(issuer_jwt: &str, nonce: &str, audience: &str, now: u64) -> String {
        let disclosed = format!("{issuer_jwt}~");
        bind_disclosed_sd_jwt(&disclosed, nonce, audience, now)
    }

    fn bind_disclosed_sd_jwt(disclosed: &str, nonce: &str, audience: &str, now: u64) -> String {
        bind_disclosed_sd_jwt_with_claims(
            disclosed,
            json!({"aud": audience, "nonce": nonce, "iat": now}),
        )
    }

    fn bind_disclosed_sd_jwt_with_claims(disclosed: &str, mut claims: Value) -> String {
        claims["sd_hash"] = json!(URL_SAFE_NO_PAD.encode(Sha256::digest(disclosed.as_bytes())));
        let holder_jwt = sign_jwt(
            &holder_key(),
            json!({"alg": "EdDSA", "typ": "kb+jwt"}),
            &claims,
        );
        format!("{disclosed}{holder_jwt}")
    }

    fn presentation(claims: &Value, nonce: &str, audience: &str, now: u64) -> String {
        bind_disclosed_sd_jwt(&disclosed_sd_jwt(claims, &["email"]), nonce, audience, now)
    }

    fn disclosed_sd_jwt(claims: &Value, selected: &[&str]) -> String {
        let mut issued_claims = claims.clone();
        // Exercise actual SD-JWT reconstruction: the requested email value is
        // carried only in a disclosure authenticated by the issuer's digest.
        let disclosures = selected
            .iter()
            .filter_map(|name| {
                issued_claims
                    .as_object_mut()
                    .unwrap()
                    .remove(*name)
                    .map(|value| {
                        URL_SAFE_NO_PAD.encode(
                            json!(["synthetic-fixed-disclosure-salt", name, value]).to_string(),
                        )
                    })
            })
            .collect::<Vec<_>>();
        issued_claims["_sd"] = json!(disclosures
            .iter()
            .map(|value| URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes())))
            .collect::<Vec<_>>());
        let issuer = issuer_jwt(&issued_claims);
        if disclosures.is_empty() {
            format!("{issuer}~")
        } else {
            format!("{issuer}~{}~", disclosures.join("~"))
        }
    }

    fn generic_core_verification(
        token: &str,
        nonce: &str,
    ) -> marty_oid4vci::formats::sd_jwt::AuthenticatedSdJwt {
        marty_oid4vci::formats::sd_jwt::verify_sd_jwt_with_policy(
            token,
            &public_key(&issuer_key()).to_string(),
            &marty_oid4vci::formats::sd_jwt::SdJwtVerificationPolicy {
                expected_issuer: ISSUER.into(),
                issuer_algorithm: marty_oid4vci::types::SigningAlgorithm::EdDSA,
                holder_algorithms: vec![marty_oid4vci::types::SigningAlgorithm::EdDSA],
            },
            Some(AUDIENCE.into()),
            Some(nonce.into()),
        )
        .expect("the generic Core verifier must accept genuine issuer and holder signatures")
    }

    fn tamper_signature(jwt: &str) -> String {
        let mut changed = jwt.to_owned();
        let start = changed.rfind('.').unwrap() + 1;
        changed.replace_range(
            start..start + 1,
            if &jwt[start..start + 1] == "A" {
                "B"
            } else {
                "A"
            },
        );
        changed
    }

    struct Fixture {
        policy: PresentationPolicy,
        request: EvaluatePresentationRequest,
        orchestrator: VerifiedFactsOrchestrator,
        claims: Value,
        nonce: String,
        now: u64,
        query_id: String,
    }

    impl Fixture {
        fn new() -> Self {
            Self::with_kernel(Arc::new(RustCredentialKernel))
        }

        fn with_kernel(kernel: Arc<dyn CredentialVerificationKernel>) -> Self {
            Self::with_kernel_and_clock_advance(kernel, 0)
        }

        fn with_kernel_and_clock_advance(
            kernel: Arc<dyn CredentialVerificationKernel>,
            final_clock_advance: u64,
        ) -> Self {
            let now = u64::try_from(chrono::Utc::now().timestamp()).unwrap();
            let nonce = Uuid::new_v4().to_string();
            let mut policy = policy();
            policy.credential_requirements[0].credential_payload_format = "SD_JWT_VC".into();
            let query_id = policy.credential_requirements[0].id.to_string();
            let claims = json!({
                "iss": ISSUER,
                "sub": SUBJECT,
                "jti": "urn:example:prerequisite-credential-001",
                "vct": VCT,
                "iat": now - 60,
                "exp": now + 600,
                "cnf": {"jwk": public_key(&holder_key())},
                "_sd_alg": "sha-256",
                "_sd": [],
                "email": EMAIL,
            });
            let token = presentation(&claims, &nonce, AUDIENCE, now);
            let query = json!({"credentials": [{
                "id": query_id,
                "format": "dc+sd-jwt",
                "meta": {"vct_values": [VCT]},
                "claims": [{"id": "email", "path": ["email"]}],
            }]});
            let transport = Oid4vpEvaluationTransportV1 {
                credential_authority: None,
                query_kind: QueryKind::Dcql,
                query_digest: digest_query_document(&query).unwrap(),
                query_document: query,
                presentation_submission: None,
                vp_token_raw: json!({(query_id.clone()): [token.clone()]}).to_string(),
                verifier_client_id: AUDIENCE.into(),
                request_nonce: nonce.clone(),
            };
            transport.validate_transport().unwrap();
            let request = EvaluatePresentationRequest {
                vp_token: json!(token),
                trust_profile_id: None,
                nonce: Some(nonce.clone()),
                audience: Some(AUDIENCE.into()),
                context: serde_json::Map::new(),
                oid4vp_transport: Some(transport),
                trusted_internal_context: true,
            };
            let mut issuer_jwk = public_key(&issuer_key());
            issuer_jwk["kid"] = json!(ISSUER_KEY_ID);
            let first_clock_read = AtomicBool::new(true);
            let orchestrator = VerifiedFactsOrchestrator::with_clock(
                kernel,
                Arc::new(Trust {
                    template_vct: Some(VCT),
                    evidence: IssuerTrustEvidence {
                        verified: true,
                        trust_level: Some(90),
                        ..Default::default()
                    },
                    fail_load: false,
                    profile_organization_id: None,
                    profile_document: Some(json!({
                        "status": "ACTIVE",
                        "allowed_algorithms": ["EdDSA", "ES256"],
                        "issuer_relationships": [{
                            "issuer_id": ISSUER,
                            "relationship_status": "TRUSTED",
                            "compliance_status": "COMPLIANT",
                            "verification_keys": [issuer_jwk],
                        }],
                    })),
                    loads: Mutex::new(Vec::new()),
                }),
                Arc::new(Status {
                    evidence: CredentialStatusEvidence {
                        checked_at_epoch_seconds: Some(now),
                        not_revoked: Some(true),
                        credential_status: Some("active".into()),
                        warnings: Vec::new(),
                    },
                    calls: Mutex::new(Vec::new()),
                }),
                Arc::new(move || {
                    if first_clock_read.swap(false, Ordering::SeqCst) {
                        now
                    } else {
                        now + final_clock_advance
                    }
                }),
            )
            .unwrap();
            Self {
                policy,
                request,
                orchestrator,
                claims,
                nonce,
                now,
                query_id,
            }
        }

        fn different_nonce(&self) -> String {
            loop {
                let nonce = Uuid::new_v4().to_string();
                if nonce != self.nonce {
                    return nonce;
                }
            }
        }

        fn request_for_token(&self, token: String) -> EvaluatePresentationRequest {
            let mut request = self.request.clone();
            request.vp_token = json!(token);
            request.oid4vp_transport.as_mut().unwrap().vp_token_raw =
                json!({(self.query_id.clone()): [request.vp_token.clone()]}).to_string();
            request
        }

        async fn verify(&self, request: &EvaluatePresentationRequest) -> VerifiedPolicyMaterial {
            self.orchestrator
                .verify_material(&self.policy, request)
                .await
                .expect("synthetic trust/status ports remain available")
        }

        async fn assert_no_evidence(&self, label: &str, request: &EvaluatePresentationRequest) {
            match self
                .orchestrator
                .verify_material(&self.policy, request)
                .await
            {
                Ok(material) => assert!(
                    material.authenticated_sd_jwt_query().is_none(),
                    "{label} must not produce authenticated query evidence",
                ),
                Err(PresentationVerificationError::Failed(_))
                | Err(PresentationVerificationError::CredentialAuthorityChanged) => {}
                Err(PresentationVerificationError::Unavailable) => {
                    panic!("{label} must reject input, not lose its synthetic backend")
                }
            }
        }
    }

    fn refresh_query_digest(request: &mut EvaluatePresentationRequest) {
        let transport = request.oid4vp_transport.as_mut().unwrap();
        transport.query_digest = digest_query_document(&transport.query_document).unwrap();
    }

    #[tokio::test]
    async fn real_sd_jwt_produces_query_subject_and_holder_bound_evidence() {
        let fixture = Fixture::new();
        let material = fixture.verify(&fixture.request).await;
        let evidence = material
            .authenticated_sd_jwt_query()
            .expect("real governed issuer and holder proofs satisfy the frozen query");
        let actual = serde_json::to_value(evidence).unwrap();
        let holder_x = URL_SAFE_NO_PAD.encode(holder_key().verifying_key().to_bytes());
        // RFC 7638 requires this exact lexicographic member order, without kid.
        let holder_canonical = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{holder_x}"}}"#);
        assert_eq!(actual["contract"], "marty.sd-jwt-dcql-query-evidence/v1");
        assert_eq!(actual["query_id"], fixture.query_id);
        assert_eq!(
            actual["query_digest"],
            fixture
                .request
                .oid4vp_transport
                .as_ref()
                .unwrap()
                .query_digest,
        );
        assert_eq!(
            actual["response_token_digest"],
            digest_response_item(
                fixture.request.vp_token.as_str().unwrap(),
                &fixture.query_id,
                "0",
            )
            .unwrap(),
        );
        assert_eq!(actual["organization_id"], ORGANIZATION_ID.to_string());
        assert_eq!(
            actual["policy"],
            serde_json::to_value(policy_revision(&fixture.policy).unwrap()).unwrap(),
        );
        assert_eq!(actual["credential_template_id"], "template-email");
        assert_eq!(actual["issuer_id"], ISSUER);
        assert_eq!(
            actual["issuer_scoped_subject_digest"],
            digest_domain_json(
                "marty.oid4vp/issuer-scoped-subject/v1",
                &json!({"issuer_id": ISSUER, "subject_id": SUBJECT}),
            )
            .unwrap(),
        );
        assert_eq!(
            actual["holder_key_thumbprint"],
            URL_SAFE_NO_PAD.encode(Sha256::digest(holder_canonical.as_bytes())),
        );
        assert_eq!(actual["vct"], VCT);
        assert_eq!(actual["issuer_algorithm"], "EdDSA");
        assert_eq!(actual["matched_claims"], json!(["email"]));
        assert_eq!(
            actual["nonce_digest"],
            digest_nonce(&fixture.nonce).unwrap()
        );
        assert_eq!(
            actual["audience_digest"],
            digest_audience(AUDIENCE).unwrap()
        );
        assert_eq!(actual["checked_at_epoch_seconds"], fixture.now);
        let serialized = actual.to_string();
        for private_input in [
            SUBJECT,
            EMAIL,
            fixture.request.vp_token.as_str().unwrap(),
            holder_x.as_str(),
            &fixture.nonce,
            AUDIENCE,
        ] {
            assert!(
                !serialized.contains(private_input),
                "typed prerequisite evidence must not retain raw presentation inputs",
            );
        }
        assert_eq!(material.policy_facts()["holder_binding_verified"], true);
        assert_eq!(material.policy_facts()["challenge_verified"], true);
        assert_eq!(material.policy_facts()["audience_verified"], true);
        assert_eq!(
            material.policy_facts()["replay_check_verified"],
            false,
            "query authentication alone does not prove durable replay consumption",
        );

        let disclosed_identity = bind_disclosed_sd_jwt(
            &disclosed_sd_jwt(&fixture.claims, &["email", "sub", "iat"]),
            &fixture.nonce,
            AUDIENCE,
            fixture.now,
        );
        let material = fixture
            .verify(&fixture.request_for_token(disclosed_identity))
            .await;
        let disclosed_evidence =
            serde_json::to_value(material.authenticated_sd_jwt_query().unwrap()).unwrap();
        assert_eq!(
            disclosed_evidence["issuer_scoped_subject_digest"],
            actual["issuer_scoped_subject_digest"],
            "issuer-authenticated disclosed sub and iat remain valid in this profile",
        );
        assert_eq!(
            disclosed_evidence["holder_key_thumbprint"],
            actual["holder_key_thumbprint"],
        );
    }

    #[tokio::test]
    async fn eddsa_issuer_and_es256_holder_use_independent_algorithms_and_public_thumbprint() {
        let fixture = Fixture::new();
        let holder = P256SigningKey::from_bytes(&[82u8; 32].into()).unwrap();
        let holder_point = holder.verifying_key().to_sec1_point(false);
        let x = URL_SAFE_NO_PAD.encode(holder_point.x().unwrap());
        let y = URL_SAFE_NO_PAD.encode(holder_point.y().unwrap());
        let mut claims = fixture.claims.clone();
        claims["cnf"]["jwk"] = json!({
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y,
            "kid": "synthetic-holder-key-id-excluded-from-thumbprint",
        });
        let disclosed = disclosed_sd_jwt(&claims, &["email"]);
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(json!({"alg": "ES256", "typ": "kb+jwt"}).to_string()),
            URL_SAFE_NO_PAD.encode(
                json!({
                    "aud": AUDIENCE,
                    "nonce": &fixture.nonce,
                    "iat": fixture.now,
                    "sd_hash": URL_SAFE_NO_PAD.encode(Sha256::digest(disclosed.as_bytes())),
                })
                .to_string()
            ),
        );
        let signature: P256Signature = holder.sign(input.as_bytes());
        let request = fixture.request_for_token(format!(
            "{disclosed}{input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        ));
        let material = fixture.verify(&request).await;
        let actual = serde_json::to_value(material.authenticated_sd_jwt_query().unwrap()).unwrap();
        let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
        assert_eq!(actual["issuer_algorithm"], "EdDSA");
        assert_eq!(
            actual["holder_key_thumbprint"],
            URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes())),
        );
        assert_eq!(material.policy_facts()["holder_binding_verified"], true);
        let projected =
            evaluate_verified_material_for_policy(material, &fixture.policy, &request).unwrap();
        assert_eq!(
            projected["credential_results"][0]["authenticated_sd_jwt_query"],
            actual,
        );
    }

    #[tokio::test]
    async fn invalid_signed_identity_or_holder_proof_cannot_produce_query_evidence() {
        let fixture = Fixture::new();
        let mut variants = vec![
            (
                "wrong holder nonce",
                presentation(
                    &fixture.claims,
                    &fixture.different_nonce(),
                    AUDIENCE,
                    fixture.now,
                ),
            ),
            (
                "wrong holder audience",
                presentation(
                    &fixture.claims,
                    &fixture.nonce,
                    "did:web:other-verifier.example",
                    fixture.now,
                ),
            ),
            (
                "tampered issuer signature with a valid holder hash",
                bind_issuer_jwt(
                    &tamper_signature(&issuer_jwt(&fixture.claims)),
                    &fixture.nonce,
                    AUDIENCE,
                    fixture.now,
                ),
            ),
            (
                "tampered holder signature",
                tamper_signature(fixture.request.vp_token.as_str().unwrap()),
            ),
        ];
        for (label, protected_type) in [
            ("missing issuer protected type", None),
            ("generic JWT protected type", Some("JWT")),
            ("legacy SD-JWT protected type", Some("vc+sd-jwt")),
        ] {
            let mut header = json!({"alg": "EdDSA", "kid": ISSUER_KEY_ID});
            if let Some(protected_type) = protected_type {
                header["typ"] = json!(protected_type);
            }
            let issuer = sign_jwt(&issuer_key(), header, &fixture.claims);
            let token = bind_issuer_jwt(&issuer, &fixture.nonce, AUDIENCE, fixture.now);
            // These are genuine issuer and holder signatures accepted by the
            // generic Core verifier. The selected DCQL VC profile must reject
            // them specifically because their protected type is not dc+sd-jwt.
            generic_core_verification(&token, &fixture.nonce);
            variants.push((label, token));
        }
        for (label, field) in [
            ("selectively disclosed VCT", "vct"),
            ("selectively disclosed expiry", "exp"),
            ("selectively disclosed not-before time", "nbf"),
        ] {
            let mut claims = fixture.claims.clone();
            if field == "nbf" {
                claims[field] = json!(fixture.now - 30);
            }
            let token = bind_disclosed_sd_jwt(
                &disclosed_sd_jwt(&claims, &["email", field]),
                &fixture.nonce,
                AUDIENCE,
                fixture.now,
            );
            let generic = generic_core_verification(&token, &fixture.nonce);
            assert_eq!(
                generic.claims()[field],
                claims[field],
                "the generic verifier must authenticate and reconstruct {field}",
            );
            variants.push((label, token));
        }
        for (label, field, replacement) in [
            (
                "wrong signed issuer",
                "iss",
                Some(json!("did:web:foreign-issuer.example")),
            ),
            ("missing subject", "sub", None),
            ("empty subject", "sub", Some(json!(""))),
            (
                "expired issuer credential",
                "exp",
                Some(json!(fixture.now - 1)),
            ),
            ("missing issuer expiry", "exp", None),
            (
                "future issuer issuance",
                "iat",
                Some(json!(fixture.now + 1)),
            ),
            ("missing issuer issuance time", "iat", None),
            (
                "future issuer not-before time",
                "nbf",
                Some(json!(fixture.now + 1)),
            ),
            ("missing holder confirmation", "cnf", None),
            (
                "different confirmed holder key",
                "cnf",
                Some(json!({"jwk": public_key(&SigningKey::from_bytes(&[80; 32]))})),
            ),
            (
                "wrong signed VCT",
                "vct",
                Some(json!("urn:example:other-type")),
            ),
            ("missing requested claim", "email", None),
            (
                "nonscalar requested claim",
                "email",
                Some(json!({"address": EMAIL})),
            ),
        ] {
            let mut claims = fixture.claims.clone();
            if let Some(value) = replacement {
                claims[field] = value;
            } else {
                claims.as_object_mut().unwrap().remove(field);
            }
            variants.push((
                label,
                presentation(&claims, &fixture.nonce, AUDIENCE, fixture.now),
            ));
        }
        for (label, token) in variants {
            fixture
                .assert_no_evidence(label, &fixture.request_for_token(token))
                .await;
        }
    }

    #[tokio::test]
    async fn production_projection_retains_partial_evidence_only_from_native_material() {
        let fixture = Fixture::new();
        let material = fixture.verify(&fixture.request).await;
        let expected =
            serde_json::to_value(material.authenticated_sd_jwt_query().unwrap()).unwrap();
        let facts = material.policy_facts().clone();
        let projected =
            evaluate_verified_material_for_policy(material, &fixture.policy, &fixture.request)
                .unwrap();
        let credentials = projected["credential_results"].as_array().unwrap();
        assert_eq!(credentials.len(), 1, "{projected}");
        assert_eq!(credentials[0]["signature_valid"], true, "{projected}");
        assert_eq!(credentials[0]["credential_template_id"], "template-email");
        assert_eq!(credentials[0]["issuer_did"], ISSUER);
        assert_eq!(credentials[0]["authenticated_sd_jwt_query"], expected);
        assert!(projected.get("authenticated_sd_jwt_query").is_none());
        assert_eq!(
            projected["decision"], "deny",
            "partial query authentication must not satisfy required replay consumption",
        );

        let mut caller = fixture.request.clone();
        caller
            .context
            .insert("authenticated_sd_jwt_query".into(), expected.clone());
        let facts_only =
            evaluate_verified_facts_for_policy(facts.clone(), &fixture.policy, &caller).unwrap();
        assert_eq!(facts_only["credential_results"][0]["signature_valid"], true);
        assert!(facts_only["credential_results"][0]
            .get("authenticated_sd_jwt_query")
            .is_none());
        assert!(facts_only.get("authenticated_sd_jwt_query").is_none());

        for inject_on_credential in [false, true] {
            let mut forged_facts = facts.clone();
            if inject_on_credential {
                forged_facts["credentials"][0]["authenticated_sd_jwt_query"] = expected.clone();
            } else {
                forged_facts["authenticated_sd_jwt_query"] = expected.clone();
            }
            assert!(
                evaluate_verified_facts_for_policy(forged_facts, &fixture.policy, &caller).is_err(),
                "generic facts cannot manufacture native query evidence",
            );
        }
    }

    #[tokio::test]
    async fn production_projection_rejects_material_from_another_policy_or_request() {
        let fixture = Fixture::new();
        let mut foreign_policy = fixture.policy.clone();
        foreign_policy.id = Uuid::from_u128(90);
        let mut foreign_organization = fixture.policy.clone();
        foreign_organization.organization_id = Uuid::from_u128(91);
        let mut newer_revision = fixture.policy.clone();
        newer_revision.version += 1;
        let mut duplicate_requirement = fixture.policy.clone();
        let mut extra_requirement = duplicate_requirement.credential_requirements[0].clone();
        extra_requirement.id = Uuid::from_u128(92);
        duplicate_requirement
            .credential_requirements
            .push(extra_requirement);

        for (label, policy) in [
            (
                "another policy with the same template and issuer",
                foreign_policy,
            ),
            ("another organization", foreign_organization),
            ("a newer saved policy revision", newer_revision),
            (
                "multiple results for the same template",
                duplicate_requirement,
            ),
        ] {
            let material = fixture.verify(&fixture.request).await;
            assert!(
                evaluate_verified_material_for_policy(material, &policy, &fixture.request).is_err(),
                "authentic query evidence cannot be projected under {label}",
            );
        }

        let mut other_claims = fixture.claims.clone();
        other_claims["sub"] = json!("another-authenticated-subject");
        let another_token = fixture.request_for_token(presentation(
            &other_claims,
            &fixture.nonce,
            AUDIENCE,
            fixture.now,
        ));
        let mut another_nonce = fixture.request.clone();
        let changed_nonce = fixture.different_nonce();
        another_nonce.nonce = Some(changed_nonce.clone());
        another_nonce
            .oid4vp_transport
            .as_mut()
            .unwrap()
            .request_nonce = changed_nonce;
        let mut another_audience = fixture.request.clone();
        let changed_audience = "did:web:another-verifier.example";
        another_audience.audience = Some(changed_audience.into());
        another_audience
            .oid4vp_transport
            .as_mut()
            .unwrap()
            .verifier_client_id = changed_audience.into();
        let mut another_query = fixture.request.clone();
        another_query
            .oid4vp_transport
            .as_mut()
            .unwrap()
            .query_document["credentials"][0]["claims"][0]["id"] = json!("new-email-alias");
        refresh_query_digest(&mut another_query);
        let mut another_trust_profile = fixture.request.clone();
        another_trust_profile.trust_profile_id = Some(REQUEST_PROFILE_ID.to_string());
        for (label, request) in [
            ("another selected token", another_token),
            ("another request nonce", another_nonce),
            ("another verifier audience", another_audience),
            ("another frozen query document", another_query),
            ("another selected Trust Profile", another_trust_profile),
        ] {
            let material = fixture.verify(&fixture.request).await;
            assert!(
                evaluate_verified_material_for_policy(material, &fixture.policy, &request).is_err(),
                "authentic query evidence cannot be projected with {label}",
            );
        }
    }

    #[derive(Default)]
    struct CachedNativeKernel {
        first_result: Mutex<Option<CredentialVerificationEvidence>>,
    }

    #[async_trait]
    impl CredentialVerificationKernel for CachedNativeKernel {
        async fn verify(
            &self,
            context: &CredentialVerificationContext,
        ) -> Result<CredentialVerificationEvidence, PresentationVerificationError> {
            let cached = self.first_result.lock().unwrap().clone();
            if let Some(cached) = cached {
                return Ok(cached);
            }
            let verified = RustCredentialKernel.verify(context).await?;
            *self.first_result.lock().unwrap() = Some(verified.clone());
            Ok(verified)
        }
    }

    #[tokio::test]
    async fn cached_native_evidence_cannot_authenticate_a_different_response() {
        let fixture = Fixture::with_kernel(Arc::new(CachedNativeKernel::default()));
        let original = fixture.verify(&fixture.request).await;
        assert!(original.authenticated_sd_jwt_query().is_some());
        evaluate_verified_material_for_policy(original, &fixture.policy, &fixture.request).unwrap();
        let mut explicit_original_profile = fixture.request.clone();
        explicit_original_profile.trust_profile_id = Some(POLICY_PROFILE_ID.to_string());
        let original_again = fixture.verify(&explicit_original_profile).await;
        evaluate_verified_material_for_policy(
            original_again,
            &fixture.policy,
            &explicit_original_profile,
        )
        .expect("the same selected Trust Profile must retain genuine native evidence");
        let mut other_claims = fixture.claims.clone();
        other_claims["sub"] = json!("different-authenticated-subject");
        let other_request = fixture.request_for_token(presentation(
            &other_claims,
            &fixture.nonce,
            AUDIENCE,
            fixture.now,
        ));
        let result = fixture
            .orchestrator
            .verify_material(&fixture.policy, &other_request)
            .await;
        assert!(matches!(
            result,
            Err(PresentationVerificationError::Failed(ref reason))
                if reason == "PRESENTATION_POLICY.AUTHENTICATED_QUERY_EVIDENCE_MISMATCH"
        ));

        let mut other_profile = fixture.request.clone();
        other_profile.trust_profile_id = Some(REQUEST_PROFILE_ID.to_string());
        let result = fixture
            .orchestrator
            .verify_material(&fixture.policy, &other_profile)
            .await;
        assert!(matches!(
            result,
            Err(PresentationVerificationError::Failed(ref reason))
                if reason.contains("cannot replace")
        ));
    }

    struct ClaimsReplacingNativeKernel;

    #[async_trait]
    impl CredentialVerificationKernel for ClaimsReplacingNativeKernel {
        async fn verify(
            &self,
            context: &CredentialVerificationContext,
        ) -> Result<CredentialVerificationEvidence, PresentationVerificationError> {
            let mut verified = RustCredentialKernel.verify(context).await?;
            verified.claims.insert(
                "email".into(),
                json!("substituted-policy-claim@example.test"),
            );
            Ok(verified)
        }
    }

    #[tokio::test]
    async fn authentic_query_evidence_cannot_be_combined_with_substituted_policy_claims() {
        let fixture = Fixture::with_kernel(Arc::new(ClaimsReplacingNativeKernel));
        let result = fixture
            .orchestrator
            .verify_material(&fixture.policy, &fixture.request)
            .await;
        assert!(matches!(
            result,
            Err(PresentationVerificationError::Failed(ref reason))
                if reason == "PRESENTATION_POLICY.AUTHENTICATED_QUERY_EVIDENCE_MISMATCH"
        ));
    }

    #[tokio::test]
    async fn final_observation_rechecks_credential_lifetime_after_awaited_work() {
        let expired = Fixture::with_kernel_and_clock_advance(Arc::new(RustCredentialKernel), 1_000);
        let result = expired
            .orchestrator
            .verify_material(&expired.policy, &expired.request)
            .await;
        assert!(matches!(
            result,
            Err(PresentationVerificationError::Failed(ref reason))
                if reason == "PRESENTATION_POLICY.SD_JWT_EXPIRED_DURING_EVALUATION"
        ));

        let stale_holder =
            Fixture::with_kernel_and_clock_advance(Arc::new(RustCredentialKernel), 301);
        let mut long_lived_claims = stale_holder.claims.clone();
        long_lived_claims["exp"] = json!(stale_holder.now + 3_600);
        let request = stale_holder.request_for_token(presentation(
            &long_lived_claims,
            &stale_holder.nonce,
            AUDIENCE,
            stale_holder.now,
        ));
        // The issuer credential remains live. Only the authenticated KB-JWT's
        // 300-second freshness window expires while the awaited work runs.
        let result = stale_holder
            .orchestrator
            .verify_material(&stale_holder.policy, &request)
            .await;
        assert!(matches!(
            result,
            Err(PresentationVerificationError::Failed(ref reason))
                if reason == "PRESENTATION_POLICY.SD_JWT_HOLDER_PROOF_EXPIRED_DURING_EVALUATION"
        ));

        let expired_holder =
            Fixture::with_kernel_and_clock_advance(Arc::new(RustCredentialKernel), 120);
        let mut long_lived_claims = expired_holder.claims.clone();
        long_lived_claims["exp"] = json!(expired_holder.now + 3_600);
        let request = expired_holder.request_for_token(bind_disclosed_sd_jwt_with_claims(
            &disclosed_sd_jwt(&long_lived_claims, &["email"]),
            json!({
                "aud": AUDIENCE,
                "nonce": &expired_holder.nonce,
                "iat": expired_holder.now,
                "exp": expired_holder.now + 1,
                "nbf": expired_holder.now - 1,
            }),
        ));
        // The proof remains within Core's 300-second iat window, but its
        // shorter authenticated exp must still invalidate the final result.
        let result = expired_holder
            .orchestrator
            .verify_material(&expired_holder.policy, &request)
            .await;
        assert!(matches!(
            result,
            Err(PresentationVerificationError::Failed(ref reason))
                if reason == "PRESENTATION_POLICY.SD_JWT_HOLDER_PROOF_EXPIRED_DURING_EVALUATION"
        ));

        let fresh = Fixture::with_kernel_and_clock_advance(Arc::new(RustCredentialKernel), 5);
        let request = fresh.request_for_token(bind_disclosed_sd_jwt_with_claims(
            &disclosed_sd_jwt(&fresh.claims, &["email"]),
            json!({
                "aud": AUDIENCE,
                "nonce": &fresh.nonce,
                "iat": fresh.now,
                "exp": fresh.now + 60,
                "nbf": fresh.now - 1,
            }),
        ));
        let material = fresh.verify(&request).await;
        let evidence =
            serde_json::to_value(material.authenticated_sd_jwt_query().unwrap()).unwrap();
        assert_eq!(evidence["checked_at_epoch_seconds"], fresh.now + 5);
        assert_eq!(
            material.policy_facts()["evaluation_time_epoch_seconds"],
            fresh.now + 5,
        );
        let projected =
            evaluate_verified_material_for_policy(material, &fresh.policy, &request).unwrap();
        assert_eq!(
            projected["credential_results"][0]["authenticated_sd_jwt_query"]
                ["checked_at_epoch_seconds"],
            fresh.now + 5,
            "projection must preserve the final live observation",
        );
    }

    #[tokio::test]
    async fn exact_query_and_selected_response_are_required_for_authenticated_evidence() {
        let fixture = Fixture::new();
        let mut changed_vct = fixture.request.clone();
        changed_vct
            .oid4vp_transport
            .as_mut()
            .unwrap()
            .query_document["credentials"][0]["meta"]["vct_values"] =
            json!(["urn:example:changed-query-type"]);
        refresh_query_digest(&mut changed_vct);

        let mut changed_token = fixture.request.clone();
        let mut other_claims = fixture.claims.clone();
        other_claims["sub"] = json!("another-authenticated-subject");
        let other_token = presentation(&other_claims, &fixture.nonce, AUDIENCE, fixture.now);
        changed_token
            .oid4vp_transport
            .as_mut()
            .unwrap()
            .vp_token_raw = json!({(fixture.query_id.clone()): [other_token]}).to_string();

        let mut wrong_response_id = fixture.request.clone();
        wrong_response_id
            .oid4vp_transport
            .as_mut()
            .unwrap()
            .vp_token_raw =
            json!({"different-query": [fixture.request.vp_token.clone()]}).to_string();

        let mut extra_response_id = fixture.request.clone();
        extra_response_id
            .oid4vp_transport
            .as_mut()
            .unwrap()
            .vp_token_raw = json!({
            (fixture.query_id.clone()): [fixture.request.vp_token.clone()],
            "additional-query": [fixture.request.vp_token.clone()],
        })
        .to_string();

        let mut multiple_tokens = fixture.request.clone();
        multiple_tokens
            .oid4vp_transport
            .as_mut()
            .unwrap()
            .vp_token_raw = json!({
            (fixture.query_id.clone()): [fixture.request.vp_token.clone(), other_token],
        })
        .to_string();

        let mut wrong_query_id = fixture.request.clone();
        wrong_query_id
            .oid4vp_transport
            .as_mut()
            .unwrap()
            .query_document["credentials"][0]["id"] = json!(Uuid::from_u128(90).to_string());
        wrong_query_id
            .oid4vp_transport
            .as_mut()
            .unwrap()
            .vp_token_raw =
            json!({(Uuid::from_u128(90).to_string()): [fixture.request.vp_token.clone()]})
                .to_string();
        refresh_query_digest(&mut wrong_query_id);

        let mut extra_query_id = fixture.request.clone();
        let transport = extra_query_id.oid4vp_transport.as_mut().unwrap();
        let mut extra_requirement = transport.query_document["credentials"][0].clone();
        extra_requirement["id"] = json!(Uuid::from_u128(91).to_string());
        transport.query_document["credentials"]
            .as_array_mut()
            .unwrap()
            .push(extra_requirement);
        refresh_query_digest(&mut extra_query_id);

        let mut wrong_digest = fixture.request.clone();
        wrong_digest.oid4vp_transport.as_mut().unwrap().query_digest = "0".repeat(64);

        for (label, request) in [
            ("changed query VCT with a recomputed digest", changed_vct),
            ("different selected response token", changed_token),
            ("wrong response query ID", wrong_response_id),
            ("extra response query ID", extra_response_id),
            ("multiple tokens for one query", multiple_tokens),
            (
                "query ID differs from the saved policy requirement",
                wrong_query_id,
            ),
            ("additional query requirement", extra_query_id),
            ("query document digest mismatch", wrong_digest),
        ] {
            fixture.assert_no_evidence(label, &request).await;
        }
    }

    #[tokio::test]
    async fn workload_transport_and_both_standard_verifier_bindings_are_required() {
        let fixture = Fixture::new();
        let mut untrusted = fixture.request.clone();
        untrusted.trusted_internal_context = false;
        let mut missing_transport = fixture.request.clone();
        missing_transport.oid4vp_transport = None;
        let mut no_audience = fixture.request.clone();
        no_audience.audience = None;
        let mut no_nonce = fixture.request.clone();
        no_nonce.nonce = None;
        let mut changed_audience = fixture.request.clone();
        changed_audience
            .oid4vp_transport
            .as_mut()
            .unwrap()
            .verifier_client_id = "did:web:substituted-verifier.example".into();
        let mut changed_nonce = fixture.request.clone();
        changed_nonce
            .oid4vp_transport
            .as_mut()
            .unwrap()
            .request_nonce = fixture.different_nonce();
        for (label, request) in [
            ("untrusted transport context", untrusted),
            ("missing query transport", missing_transport),
            ("absent standard audience, including DC API", no_audience),
            ("missing nonce", no_nonce),
            ("transport client ID mismatch", changed_audience),
            ("transport nonce mismatch", changed_nonce),
        ] {
            fixture.assert_no_evidence(label, &request).await;
        }
    }

    #[tokio::test]
    async fn caller_json_cannot_create_or_replace_authenticated_query_identity() {
        let fixture = Fixture::new();
        let mut forged = fixture.request.clone();
        let false_identity = json!({
            "issuer_id": "did:web:caller-selected.example",
            "issuer_scoped_subject_digest": "f".repeat(64),
            "holder_key_thumbprint": "caller-selected-holder",
            "matched_claims": ["administrator"],
            "verified": true,
        });
        forged
            .context
            .insert("authenticated_sd_jwt_query".into(), false_identity);
        forged.context.insert(
            "verified_claims".into(),
            json!({
                "iss": "did:web:caller-selected.example",
                "sub": "caller-selected-subject",
                "cnf": {"jwk": public_key(&SigningKey::from_bytes(&[81; 32]))},
            }),
        );
        let authentic = fixture.verify(&fixture.request).await;
        let material = fixture.verify(&forged).await;
        assert!(material.authenticated_sd_jwt_query().is_some());
        assert_eq!(
            serde_json::to_value(material.authenticated_sd_jwt_query().unwrap()).unwrap(),
            serde_json::to_value(authentic.authenticated_sd_jwt_query().unwrap()).unwrap(),
            "caller JSON cannot replace native authenticated identity",
        );
        let mut unproved = fixture.request_for_token("unverified-presentation".into());
        unproved.context = forged.context;
        fixture
            .assert_no_evidence("forged identity without a valid presentation", &unproved)
            .await;
    }

    mod managed_authority {
        use super::*;
        use crate::owner_channel::{test_owner_response, Owner};
        use crate::{AuthenticatedOwnerResponse, PrerequisiteEvidenceProfile};
        use marty_oid4vp_contract::{
            managed_status::*, trust_authority::*, EvidenceCheckOutcome, EvidenceProfileReference,
        };
        use std::sync::atomic::AtomicU64;

        #[derive(Clone, Copy)]
        enum Mode {
            Valid,
            WrongTrustScope,
            WrongStatusArtifact,
            WrongTrustRole,
            WrongStatusRole,
            Denied,
            Revoked,
            Changed,
            WrongTemplate,
            StaleAfterTemplate,
        }

        struct Owners {
            snapshot: CredentialAuthoritySnapshotV1,
            now: i64,
            mode: Mode,
            clock: Arc<AtomicU64>,
            trust_calls: Mutex<Vec<CredentialTrustEvaluationRequestV1>>,
            status_calls: Mutex<Vec<ManagedCredentialStatusRequestV1>>,
        }

        #[async_trait]
        impl PresentationTrustResolver for Owners {
            async fn load_credential_template(
                &self,
                template_id: &str,
                organization_id: Uuid,
            ) -> Result<ResolvedCredentialTemplate, PresentationVerificationError> {
                assert_eq!(template_id, "template-email");
                assert_eq!(organization_id, ORGANIZATION_ID);
                if matches!(self.mode, Mode::StaleAfterTemplate) {
                    self.clock.store(self.now as u64 + 60, Ordering::SeqCst);
                }
                Ok(ResolvedCredentialTemplate {
                    id: template_id.into(),
                    organization_id,
                    credential_type: "EmailCredential".into(),
                    vct: Some(
                        if matches!(self.mode, Mode::WrongTemplate) {
                            "urn:example:another-email-template"
                        } else {
                            VCT
                        }
                        .into(),
                    ),
                    doctype: None,
                    status: "ACTIVE".into(),
                })
            }

            async fn freeze_credential_authority(
                &self,
                organization_id: Uuid,
                profile_id: Uuid,
            ) -> Result<
                AuthenticatedOwnerResponse<CredentialAuthoritySnapshotV1>,
                PresentationVerificationError,
            > {
                assert_eq!(organization_id.to_string(), self.snapshot.organization_id);
                assert_eq!(profile_id.to_string(), self.snapshot.profile.id);
                Ok(test_owner_response(
                    Owner::TrustProfile,
                    self.snapshot.clone(),
                ))
            }

            async fn evaluate_credential_authority(
                &self,
                request: &CredentialTrustEvaluationRequestV1,
            ) -> Result<
                AuthenticatedOwnerResponse<CredentialTrustEvaluationResponseV1>,
                PresentationVerificationError,
            > {
                self.trust_calls.lock().unwrap().push(request.clone());
                assert_eq!(request.expected_profile, self.snapshot.profile);
                assert_eq!(request.issuer_id, ISSUER);
                assert_eq!(request.vct, VCT);
                assert_eq!(request.format, "SD_JWT_VC");
                assert_eq!(request.issuer_algorithm, "EdDSA");
                assert_eq!(
                    request.issuer_key_thumbprint,
                    issuer_public_key_thumbprint(&public_key(&issuer_key())).unwrap()
                );
                if matches!(self.mode, Mode::Changed) {
                    return Err(PresentationVerificationError::CredentialAuthorityChanged);
                }
                let denied = matches!(self.mode, Mode::Denied);
                let mut response = CredentialTrustEvaluationResponseV1 {
                    contract: CREDENTIAL_TRUST_EVALUATION_CONTRACT.into(),
                    organization_id: request.organization_id.clone(),
                    profile: request.expected_profile.clone(),
                    issuer_id: request.issuer_id.clone(),
                    format: request.format.clone(),
                    vct: request.vct.clone(),
                    issuer_algorithm: request.issuer_algorithm.clone(),
                    issuer_key_thumbprint: request.issuer_key_thumbprint.clone(),
                    request_binding_digest: request.request_binding_digest.clone(),
                    outcome: if denied {
                        EvidenceCheckOutcome::Failed
                    } else {
                        EvidenceCheckOutcome::Passed
                    },
                    reason_code: if denied {
                        "TRUST_PROFILE.CREDENTIAL_NOT_AUTHORIZED"
                    } else {
                        "TRUST_PROFILE.CREDENTIAL_AUTHORIZED"
                    }
                    .into(),
                    trust_level: (!denied).then_some(90),
                    compliance_statuses: if denied {
                        vec![]
                    } else {
                        vec!["COMPLIANT".into()]
                    },
                    accreditations: vec![],
                    checked_at_epoch_seconds: self.now,
                    valid_until_epoch_seconds: self.now + 60,
                    evidence_digest: String::new(),
                };
                if matches!(self.mode, Mode::WrongTrustScope) {
                    response.request_binding_digest = format!("sha256:{}", "b".repeat(64));
                }
                response.evidence_digest = credential_trust_evaluation_digest(&response).unwrap();
                Ok(test_owner_response(
                    if matches!(self.mode, Mode::WrongTrustRole) {
                        Owner::Issuance
                    } else {
                        Owner::TrustProfile
                    },
                    response,
                ))
            }

            async fn load_profile(
                &self,
                _: Uuid,
                _: Uuid,
            ) -> Result<ResolvedTrustProfile, PresentationVerificationError> {
                panic!("managed prerequisite keys must come from the frozen owner basis")
            }

            async fn evaluate_issuer(
                &self,
                _: &ResolvedTrustProfile,
                _: &str,
                _: DetectedCredentialFormat,
            ) -> Result<IssuerTrustEvidence, PresentationVerificationError> {
                panic!("generic issuer acceptance cannot replace exact VCT authorization")
            }
        }

        #[async_trait]
        impl CredentialStatusResolver for Owners {
            async fn observe_managed_status(
                &self,
                request: &ManagedCredentialStatusRequestV1,
            ) -> Result<
                AuthenticatedOwnerResponse<ManagedCredentialStatusObservationV1>,
                PresentationVerificationError,
            > {
                self.status_calls.lock().unwrap().push(request.clone());
                let mut response = ManagedCredentialStatusObservationV1 {
                    contract: MANAGED_STATUS_CONTRACT.into(),
                    authority: MANAGED_STATUS_AUTHORITY.into(),
                    request: request.clone(),
                    state: if matches!(self.mode, Mode::Revoked) {
                        ManagedCredentialStatusState::Revoked
                    } else {
                        ManagedCredentialStatusState::Active
                    },
                    status_updated_at_epoch_seconds: self.now - 1,
                    checked_at_epoch_seconds: self.now,
                    valid_until_epoch_seconds: self.now + 60,
                    credential_expires_at_epoch_seconds: self.now + 600,
                    evidence_digest: String::new(),
                };
                if matches!(self.mode, Mode::WrongStatusArtifact) {
                    response.request.issuer_jwt_digest = format!("sha256:{}", "c".repeat(64));
                }
                response.evidence_digest = digest_managed_status_observation(&response).unwrap();
                Ok(test_owner_response(
                    if matches!(self.mode, Mode::WrongStatusRole) {
                        Owner::TrustProfile
                    } else {
                        Owner::Issuance
                    },
                    response,
                ))
            }

            async fn resolve(
                &self,
                _: Uuid,
                _: &str,
                _: &[String],
            ) -> Result<CredentialStatusEvidence, PresentationVerificationError> {
                panic!("mutable public status IDs cannot replace exact native artifact binding")
            }
        }

        fn fixture(mode: Mode, advance: u64) -> (Fixture, Arc<Owners>) {
            let mut fixture = Fixture::new();
            fixture.policy.prerequisite_evidence_profile =
                Some(PrerequisiteEvidenceProfile::ManagedSdJwtDcqlV1);
            fixture.policy.freshness = Some(FreshnessPolicy {
                max_age_seconds: None,
                require_not_revoked: true,
                revocation_grace_seconds: None,
            });
            fixture.policy.validate().unwrap();
            fixture.claims["nbf"] = json!(fixture.now - 60);
            fixture.request = fixture.request_for_token(presentation(
                &fixture.claims,
                &fixture.nonce,
                AUDIENCE,
                fixture.now,
            ));
            let timestamp = chrono::DateTime::from_timestamp(fixture.now as i64 - 3600, 0)
                .unwrap()
                .to_rfc3339();
            let mut key = public_key(&issuer_key());
            key["kid"] = json!(ISSUER_KEY_ID);
            key["use"] = json!("sig");
            let basis: CredentialAuthorityBasisV1 = serde_json::from_value(json!({
                "id": POLICY_PROFILE_ID, "organization_id": ORGANIZATION_ID,
                "status": "active", "compliance_status": "COMPLIANT",
                "trust_purposes": ["CREDENTIAL_ISSUER"], "supported_formats": ["SD_JWT_VC"],
                "allowed_algorithms": ["EdDSA"], "allowed_issuers": null, "denied_issuers": [],
                "policy_controls": {
                    "validation_rules": {"min_key_size_rsa":2048,"min_key_size_ec":256,"require_key_usage":true,"max_chain_depth":5,"allow_self_signed":false},
                    "time_policy": {"max_clock_skew_seconds":0,"credential_freshness_hours":null,"require_not_before":true,"require_expiration":true},
                    "revocation_policy": {"check_mode":"HARD_FAIL","check_ocsp":false,"check_crl":false,"check_status_list":false,"offline_grace_period_hours":0,"cache_duration_hours":0},
                    "trusted_assertion_formats":null,"unsupported_configuration_fields":[],
                    "unsupported_configuration_digest": format!("sha256:{}", "0".repeat(64)),
                },
                "created_at": timestamp, "updated_at": timestamp,
                "issuer_relationships": [{
                    "relationship_id": Uuid::from_u128(100), "issuer_entity_id": Uuid::from_u128(101),
                    "issuer_id": ISSUER, "issuer_organization_id": ORGANIZATION_ID, "is_system_issuer": false,
                    "relationship_status": "TRUSTED", "trust_level": 90, "compliance_status": "COMPLIANT",
                    "accreditations": [], "valid_from": timestamp, "valid_until": null, "revoked_at": null,
                    "verification_keys": [key], "credential_authorizations": [{"format": "SD_JWT_VC", "vct": VCT}],
                    "issuer_created_at": timestamp, "issuer_updated_at": timestamp,
                    "relationship_created_at": timestamp, "relationship_updated_at": timestamp,
                }],
            })).unwrap();
            let mut snapshot = CredentialAuthoritySnapshotV1 {
                contract: CREDENTIAL_AUTHORITY_SNAPSHOT_CONTRACT.into(),
                organization_id: ORGANIZATION_ID.to_string(),
                profile: EvidenceProfileReference {
                    id: POLICY_PROFILE_ID.to_string(),
                    version: 7,
                    content_digest: credential_authority_basis_digest(&basis).unwrap(),
                },
                basis,
                response_digest: String::new(),
            };
            snapshot.response_digest = credential_authority_snapshot_digest(&snapshot).unwrap();
            snapshot.validate().unwrap();
            fixture
                .request
                .oid4vp_transport
                .as_mut()
                .unwrap()
                .credential_authority = Some(snapshot.clone());
            fixture
                .request
                .context
                .insert("oid4vp_verifier_context".into(), json!(true));
            fixture
                .request
                .context
                .insert("replay_check_verified".into(), json!(true));
            let clock = Arc::new(AtomicU64::new(fixture.now));
            let owners = Arc::new(Owners {
                snapshot,
                now: fixture.now as i64,
                mode,
                clock: clock.clone(),
                trust_calls: Mutex::new(Vec::new()),
                status_calls: Mutex::new(Vec::new()),
            });
            let now = fixture.now;
            let first = AtomicBool::new(true);
            fixture.orchestrator = VerifiedFactsOrchestrator::with_clock(
                Arc::new(RustCredentialKernel),
                owners.clone(),
                owners.clone(),
                Arc::new(move || {
                    if first.swap(false, Ordering::SeqCst) {
                        now
                    } else {
                        clock.load(Ordering::SeqCst) + advance
                    }
                }),
            )
            .unwrap();
            (fixture, owners)
        }

        #[tokio::test]
        async fn native_managed_evaluation_binds_both_owners_and_minimizes_projection() {
            let (fixture, owners) = fixture(Mode::Valid, 0);
            let frozen = fixture
                .orchestrator
                .freeze_credential_authority(&fixture.policy)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(frozen, owners.snapshot);
            let material = fixture.verify(&fixture.request).await;
            let authority =
                serde_json::to_value(material.managed_credential_authority().unwrap()).unwrap();
            assert_eq!(authority["contract"], "marty.managed-sd-jwt-authority/v1");
            assert_eq!(
                authority["trust"]["profile"],
                serde_json::to_value(&owners.snapshot.profile).unwrap()
            );
            assert_eq!(authority["status"]["state"], "active");
            assert!(authority["status"].get("request").is_none());
            let serialized = authority.to_string();
            for private in [SUBJECT, EMAIL, "urn:example:prerequisite-credential-001"] {
                assert!(!serialized.contains(private));
            }
            let facts = material.policy_facts().clone();
            assert!(
                evaluate_verified_facts_for_policy(facts, &fixture.policy, &fixture.request)
                    .is_err(),
                "managed profile cannot accept cached or forged verification booleans"
            );
            let output =
                evaluate_verified_material_for_policy(material, &fixture.policy, &fixture.request)
                    .unwrap();
            assert_eq!(output["decision"], "allow", "{output}");
            assert_eq!(
                output["credential_results"][0]["managed_sd_jwt_authority"],
                authority
            );
            assert!(output.get("authenticated_oid4vp_evidence").is_none());
            assert!(output.get("issuance_continuation").is_none());
            let trust = owners.trust_calls.lock().unwrap();
            let status = owners.status_calls.lock().unwrap();
            assert_eq!(trust.len(), 1);
            assert_eq!(status.len(), 1);
            assert_eq!(
                status[0].credential_id,
                "urn:example:prerequisite-credential-001"
            );
            assert_eq!(status[0].credential_template_id, "template-email");
            assert_eq!(
                status[0].issuer_jwt_digest,
                digest_sd_jwt_issuer_jws(fixture.request.vp_token.as_str().unwrap()).unwrap()
            );
            assert_eq!(
                trust[0].request_binding_digest,
                status[0].request_binding_digest
            );
        }

        #[tokio::test]
        async fn managed_authority_does_not_confer_catalog_template_membership() {
            let (fixture, owners) = fixture(Mode::WrongTemplate, 0);
            let material = fixture.verify(&fixture.request).await;
            assert!(material.managed_credential_authority().is_some());
            assert_eq!(
                material.policy_facts()["credentials"][0]["credential_template_ids"],
                json!([])
            );
            let output =
                evaluate_verified_material_for_policy(material, &fixture.policy, &fixture.request)
                    .unwrap();
            assert_eq!(output["decision"], "deny", "{output}");
            assert!(output["credential_results"][0]
                .get("managed_sd_jwt_authority")
                .is_none());
            assert_eq!(owners.trust_calls.lock().unwrap().len(), 1);
            assert_eq!(owners.status_calls.lock().unwrap().len(), 1);
        }

        #[tokio::test]
        async fn managed_observations_must_remain_live_after_catalog_resolution() {
            let (fixture, owners) = fixture(Mode::StaleAfterTemplate, 0);
            assert!(fixture
                .orchestrator
                .verify_material(&fixture.policy, &fixture.request)
                .await
                .is_err());
            assert_eq!(owners.trust_calls.lock().unwrap().len(), 1);
            assert_eq!(owners.status_calls.lock().unwrap().len(), 1);
            assert_eq!(owners.clock.load(Ordering::SeqCst), fixture.now + 60);
        }

        #[tokio::test]
        async fn wrong_owner_scope_expired_observation_and_revision_changes_fail_closed() {
            for (mode, advance) in [
                (Mode::WrongTrustScope, 0),
                (Mode::WrongStatusArtifact, 0),
                (Mode::WrongTrustRole, 0),
                (Mode::WrongStatusRole, 0),
                (Mode::Valid, 60),
                (Mode::Changed, 0),
            ] {
                let (fixture, _) = fixture(mode, advance);
                assert!(fixture
                    .orchestrator
                    .verify_material(&fixture.policy, &fixture.request)
                    .await
                    .is_err());
            }
            for mode in [Mode::Denied, Mode::Revoked] {
                let (fixture, _) = fixture(mode, 0);
                let material = fixture.verify(&fixture.request).await;
                assert!(material.managed_credential_authority().is_some());
                let output = evaluate_verified_material_for_policy(
                    material,
                    &fixture.policy,
                    &fixture.request,
                )
                .unwrap();
                assert_eq!(output["decision"], "deny", "{output}");
            }
        }

        #[tokio::test]
        async fn managed_profile_has_no_missing_snapshot_override_or_credential_id_fallback() {
            let (fixture, owners) = fixture(Mode::Valid, 0);
            let mut missing = fixture.request.clone();
            missing
                .oid4vp_transport
                .as_mut()
                .unwrap()
                .credential_authority = None;
            assert!(fixture
                .orchestrator
                .verify_material(&fixture.policy, &missing)
                .await
                .is_err());
            let mut foreign = fixture.request.clone();
            foreign.trust_profile_id = Some(REQUEST_PROFILE_ID.to_string());
            assert!(fixture
                .orchestrator
                .verify_material(&fixture.policy, &foreign)
                .await
                .is_err());
            let mut claims = fixture.claims.clone();
            claims.as_object_mut().unwrap().remove("nbf");
            let missing_not_before = fixture.request_for_token(presentation(
                &claims,
                &fixture.nonce,
                AUDIENCE,
                fixture.now,
            ));
            fixture
                .assert_no_evidence("configured not-before requirement", &missing_not_before)
                .await;
            claims = fixture.claims.clone();
            claims.as_object_mut().unwrap().remove("jti");
            let missing_id = fixture.request_for_token(presentation(
                &claims,
                &fixture.nonce,
                AUDIENCE,
                fixture.now,
            ));
            assert!(fixture
                .orchestrator
                .verify_material(&fixture.policy, &missing_id)
                .await
                .is_err());
            assert!(owners.trust_calls.lock().unwrap().is_empty());
            assert!(owners.status_calls.lock().unwrap().is_empty());
        }

        #[tokio::test]
        async fn mutable_public_status_ids_cannot_change_the_owner_request() {
            struct SubstitutedIds;
            #[async_trait]
            impl CredentialVerificationKernel for SubstitutedIds {
                async fn verify(
                    &self,
                    context: &CredentialVerificationContext,
                ) -> Result<CredentialVerificationEvidence, PresentationVerificationError>
                {
                    let mut evidence = RustCredentialKernel.verify(context).await?;
                    evidence.credential_status_ids = vec!["attacker-selected-record".into()];
                    evidence.status = CredentialStatusEvidence {
                        checked_at_epoch_seconds: Some(u64::MAX),
                        not_revoked: Some(true),
                        credential_status: Some("active".into()),
                        warnings: vec![],
                    };
                    Ok(evidence)
                }
            }
            let (mut fixture, owners) = fixture(Mode::Revoked, 0);
            let now = fixture.now;
            fixture.orchestrator = VerifiedFactsOrchestrator::with_clock(
                Arc::new(SubstitutedIds),
                owners.clone(),
                owners.clone(),
                Arc::new(move || now),
            )
            .unwrap();
            let material = fixture.verify(&fixture.request).await;
            assert_eq!(
                material.policy_facts()["credentials"][0]["not_revoked"],
                false
            );
            assert_eq!(
                owners.status_calls.lock().unwrap()[0].credential_id,
                "urn:example:prerequisite-credential-001"
            );
        }

        #[test]
        fn managed_policy_admission_requires_every_opt_in_obligation() {
            let (fixture, _) = fixture(Mode::Valid, 0);
            for mutation in 0..7 {
                let mut policy = fixture.policy.clone();
                match mutation {
                    0 => policy.trust_profile_id = None,
                    1 => policy.freshness = None,
                    2 => policy.holder_binding.required = false,
                    3 => {
                        policy
                            .holder_binding
                            .proof_freshness
                            .insert("replay_detection_required".into(), false);
                    }
                    4 => policy.credential_requirements[0].required = false,
                    5 => {
                        policy.credential_requirements[0].credential_payload_format =
                            "W3C_VCDM_V2_DI".into()
                    }
                    6 => {
                        policy.credential_requirements[0].trust_profile_id =
                            Some(REQUEST_PROFILE_ID)
                    }
                    _ => unreachable!(),
                }
                assert!(policy.validate().is_err(), "mutation {mutation}");
            }
        }
    }
}
