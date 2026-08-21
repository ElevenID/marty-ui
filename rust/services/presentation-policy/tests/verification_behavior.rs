use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use marty_presentation_policy::{
    ClaimConstraint, ConstraintType, CredentialRequirement, CredentialStatusEvidence,
    CredentialStatusResolver, CredentialVerificationContext, CredentialVerificationEvidence,
    CredentialVerificationKernel, DisplayMetadata, HolderBinding, IssuerTrustEvidence,
    PolicyStatus, PresentationPolicy, PresentationTrustResolver, PresentationVerificationError,
    PresentationVerificationOrchestrator, RequestPurpose, RequestedClaim, ResolvedTrustProfile,
    VerifiedFactsOrchestrator,
};
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
            document: json!({"public_verification_material": true}),
        })
    }

    async fn evaluate_issuer(
        &self,
        _profile: &ResolvedTrustProfile,
        _issuer_id: &str,
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
    );
    let request = marty_presentation_policy::EvaluatePresentationRequest {
        vp_token: vector["vp_token"].clone(),
        trust_profile_id: Some(REQUEST_PROFILE_ID.to_string()),
        nonce: Some("nonce-1".into()),
        audience: Some("verifier-1".into()),
        context: serde_json::Map::new(),
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
    );
    let request = marty_presentation_policy::EvaluatePresentationRequest {
        vp_token: Value::String("not-a-credential".into()),
        trust_profile_id: None,
        nonce: None,
        audience: None,
        context: serde_json::Map::new(),
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
        loads: Mutex::new(Vec::new()),
    });
    let status = Arc::new(Status {
        evidence: CredentialStatusEvidence::default(),
        calls: Mutex::new(Vec::new()),
    });
    let orchestrator = VerifiedFactsOrchestrator::new(kernel.clone(), trust, status);
    let request = marty_presentation_policy::EvaluatePresentationRequest {
        vp_token: fixture["valid_data_integrity"]["vp_token"].clone(),
        trust_profile_id: None,
        nonce: None,
        audience: None,
        context: serde_json::Map::new(),
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
        loads: Mutex::new(Vec::new()),
    });
    let status = Arc::new(Status {
        evidence: CredentialStatusEvidence::default(),
        calls: Mutex::new(Vec::new()),
    });
    let orchestrator = VerifiedFactsOrchestrator::new(kernel.clone(), trust, status);
    let request = marty_presentation_policy::EvaluatePresentationRequest {
        vp_token: fixture["valid_data_integrity"]["vp_token"].clone(),
        trust_profile_id: None,
        nonce: None,
        audience: None,
        context: serde_json::Map::new(),
    };

    let error = orchestrator.verify(&policy(), &request).await.unwrap_err();
    assert!(matches!(error, PresentationVerificationError::Failed(_)));
    assert!(kernel.calls.lock().unwrap().is_empty());
}
