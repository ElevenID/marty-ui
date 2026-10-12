use std::{io::Read, sync::Arc};

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use marty_presentation_policy::{
    evaluate_verified_facts_for_policy, CredentialRequirement, CredentialStatusEvidence,
    CredentialStatusResolver, DisplayMetadata, EvaluatePresentationRequest, FreshnessPolicy,
    HolderBinding, IssuerTrustEvidence, PolicyStatus, PresentationPolicy,
    PresentationTrustResolver, PresentationVerificationOrchestrator, RequestPurpose,
    RequestedClaim, ResolvedTrustProfile, RustCredentialKernel, VerifiedFactsOrchestrator,
};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use uuid::Uuid;

const ISSUER: &str = "did:example:verifier-runtime-gate-issuer";
const ISSUER_KID: &str = "did:example:verifier-runtime-gate-issuer#key-1";
const EMAIL: &str = "runtime-gate@example.invalid";
const NONCE: &str = "runtime-gate-nonce-with-at-least-32-bytes";
const AUDIENCE: &str = "https://verifier.runtime-gate.invalid";

// The shipping probe verifies public input produced by the KMS and test wallet.
const MAX_INPUT_BYTES: usize = 128 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GateInput {
    presentation: String,
    issuer_public_jwk: Value,
}

impl GateInput {
    fn validate(&self) -> Result<(), String> {
        require(
            !self.presentation.is_empty() && self.presentation.len() <= MAX_INPUT_BYTES,
            "runtime gate presentation size rejected",
        )?;
        let jwk = self
            .issuer_public_jwk
            .as_object()
            .ok_or("runtime gate requires a public JWK")?;
        require(
            jwk.len() == 6
                && ["kty", "crv", "x", "y", "kid", "alg"]
                    .iter()
                    .all(|name| jwk.contains_key(*name)),
            "runtime gate requires only public JWK fields",
        )?;
        require(
            jwk["kty"] == "EC"
                && jwk["crv"] == "P-256"
                && jwk["kid"] == ISSUER_KID
                && jwk["alg"] == "ES256",
            "runtime gate issuer key identity rejected",
        )?;
        for coordinate in ["x", "y"] {
            let value = jwk[coordinate]
                .as_str()
                .ok_or("runtime gate public coordinate rejected")?;
            let decoded = URL_SAFE_NO_PAD
                .decode(value)
                .map_err(|_| "runtime gate public coordinate rejected")?;
            require(
                decoded.len() == 32,
                "runtime gate public coordinate rejected",
            )?;
        }
        Ok(())
    }
}

fn read_input(reader: impl Read) -> Result<GateInput, String> {
    let mut encoded = Vec::new();
    reader
        .take((MAX_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut encoded)
        .map_err(|_| "runtime gate input unavailable")?;
    require(
        encoded.len() <= MAX_INPUT_BYTES,
        "runtime gate input too large",
    )?;
    let input: GateInput =
        serde_json::from_slice(&encoded).map_err(|_| "runtime gate input rejected")?;
    input.validate()?;
    Ok(input)
}

#[derive(Clone)]
struct GateTrust {
    profile: ResolvedTrustProfile,
}

#[async_trait]
impl PresentationTrustResolver for GateTrust {
    async fn load_profile(
        &self,
        profile_id: Uuid,
        organization_id: Uuid,
    ) -> Result<ResolvedTrustProfile, marty_presentation_policy::PresentationVerificationError>
    {
        if profile_id != self.profile.id || organization_id != self.profile.organization_id {
            return Err(
                marty_presentation_policy::PresentationVerificationError::Failed(
                    "runtime gate trust identity mismatch".into(),
                ),
            );
        }
        Ok(self.profile.clone())
    }

    async fn evaluate_issuer(
        &self,
        profile: &ResolvedTrustProfile,
        issuer_id: &str,
        _format: marty_verification::credential_format::DetectedCredentialFormat,
    ) -> Result<IssuerTrustEvidence, marty_presentation_policy::PresentationVerificationError> {
        if profile != &self.profile || issuer_id != ISSUER {
            return Ok(IssuerTrustEvidence {
                failure_reason: Some("runtime gate issuer was not governed".into()),
                ..IssuerTrustEvidence::default()
            });
        }
        Ok(IssuerTrustEvidence {
            verified: true,
            trust_level: Some(100),
            compliance_statuses: vec!["ACCREDITED".into()],
            accreditations: vec!["runtime-gate".into()],
            ..IssuerTrustEvidence::default()
        })
    }
}

#[derive(Clone)]
struct GateStatus {
    checked_at: u64,
    organization_id: Uuid,
}

#[async_trait]
impl CredentialStatusResolver for GateStatus {
    async fn resolve(
        &self,
        organization_id: Uuid,
        issuer_id: &str,
        credential_ids: &[String],
    ) -> Result<CredentialStatusEvidence, marty_presentation_policy::PresentationVerificationError>
    {
        if organization_id != self.organization_id
            || issuer_id != ISSUER
            || credential_ids.len() != 1
        {
            return Err(
                marty_presentation_policy::PresentationVerificationError::Failed(
                    "runtime gate status identity mismatch".into(),
                ),
            );
        }
        Ok(CredentialStatusEvidence {
            checked_at_epoch_seconds: Some(self.checked_at),
            not_revoked: Some(true),
            credential_status: Some("active".into()),
            warnings: Vec::new(),
        })
    }
}

fn gate_policy(organization_id: Uuid, trust_profile_id: Uuid) -> PresentationPolicy {
    let now = Utc::now();
    PresentationPolicy {
        id: Uuid::from_u128(3),
        organization_id,
        name: "Exact image positive OID4VP gate".into(),
        description: None,
        status: PolicyStatus::Active,
        display_metadata: DisplayMetadata {
            title: "Runtime gate".into(),
            description: String::new(),
            purpose: RequestPurpose::Authorization,
            purpose_description: None,
            verifier_name: "ElevenID".into(),
            verifier_logo_url: None,
            privacy_policy_url: None,
            terms_of_service_url: None,
        },
        required_claims: Vec::new(),
        accepted_credential_types: Vec::new(),
        credential_requirements: vec![CredentialRequirement {
            id: Uuid::from_u128(4),
            credential_template_id: "runtime-gate-template".into(),
            display_name: "Runtime gate credential".into(),
            description: None,
            required: true,
            credential_payload_format: "ietf_sd_jwt".into(),
            requested_claims: vec![RequestedClaim {
                id: Uuid::from_u128(5),
                claim_name: "email".into(),
                display_name: "Email".into(),
                description: None,
                required: true,
                selective_disclosure: true,
                accept_derived: false,
                predicate_spec: None,
                constraints: Vec::new(),
            }],
            trust_profile_id: Some(trust_profile_id),
            max_age_seconds: Some(600),
            require_fresh_issuance: true,
        }],
        alternative_requirements: Vec::new(),
        presentation_proof_required: true,
        trust_profile_id: Some(trust_profile_id),
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
        freshness: Some(FreshnessPolicy {
            max_age_seconds: Some(600),
            require_not_revoked: true,
            revocation_grace_seconds: None,
        }),
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

fn require(condition: bool, message: &str) -> Result<(), String> {
    condition.then_some(()).ok_or_else(|| message.into())
}

async fn execute(input: GateInput) -> Result<Value, String> {
    input.validate()?;
    let GateInput {
        presentation,
        issuer_public_jwk,
    } = input;
    let organization_id = Uuid::from_u128(1);
    let trust_profile_id = Uuid::from_u128(2);
    let now = u64::try_from(Utc::now().timestamp()).map_err(|_| "runtime clock rejected")?;
    let profile = ResolvedTrustProfile {
        id: trust_profile_id,
        organization_id,
        document: json!({
            "status": "active",
            "issuer_relationships": [{
                "issuer_id": ISSUER,
                "relationship_status": "TRUSTED",
                "compliance_status": "ACCREDITED",
                "revoked_at": null,
                "verification_keys": [issuer_public_jwk],
            }],
        }),
    };
    let orchestrator = VerifiedFactsOrchestrator::with_clock(
        Arc::new(RustCredentialKernel),
        Arc::new(GateTrust { profile }),
        Arc::new(GateStatus {
            checked_at: now,
            organization_id,
        }),
        Arc::new(move || now),
    )
    .map_err(|_| "native verifier initialization failed")?;
    let policy = gate_policy(organization_id, trust_profile_id);
    policy
        .validate()
        .map_err(|_| "runtime gate policy rejected")?;
    let request = EvaluatePresentationRequest {
        vp_token: Value::String(presentation),
        trust_profile_id: Some(trust_profile_id.to_string()),
        nonce: Some(NONCE.into()),
        audience: Some(AUDIENCE.into()),
        context: Map::from_iter([
            ("oid4vp_verifier_context".into(), json!(true)),
            ("replay_check_verified".into(), json!(true)),
        ]),
        oid4vp_transport: None,
        trusted_internal_context: true,
    };
    let facts = orchestrator
        .verify(&policy, &request)
        .await
        .map_err(|_| "native verifier rejected the runtime presentation")?;
    let credential = facts["credentials"]
        .as_array()
        .and_then(|values| values.first())
        .ok_or("runtime verifier omitted credential evidence")?;
    require(
        facts["presentation_verified"] == true,
        "presentation proof did not pass",
    )?;
    require(
        credential["signature_verified"] == true,
        "credential proof did not pass",
    )?;
    require(
        credential["trust_profile_verified"] == true,
        "issuer trust did not pass",
    )?;
    require(
        credential["not_revoked"] == true,
        "credential status did not pass",
    )?;
    require(
        facts["holder_binding_verified"] == true,
        "holder binding did not pass",
    )?;
    require(
        facts["challenge_verified"] == true
            && facts["audience_verified"] == true
            && facts["replay_check_verified"] == true,
        "transaction binding did not pass",
    )?;
    require(
        credential["claims"]["email"] == EMAIL,
        "authenticated claim projection changed",
    )?;
    let evaluated = evaluate_verified_facts_for_policy(facts, &policy, &request)
        .map_err(|_| "canonical policy evaluation failed")?;
    require(
        evaluated["result"] == "passed",
        "canonical policy result did not pass",
    )?;
    require(
        evaluated["decision"] == "allow",
        "canonical policy decision did not allow",
    )?;
    require(
        evaluated["verified_claims"]["email"] == EMAIL,
        "verified claim was not projected",
    )?;

    let checks = [
        ("presentation.structure", "PRESENTATION_STRUCTURE_VALID"),
        ("presentation.proof", "PRESENTATION_PROOF_VALID"),
        ("credential.proof", "CREDENTIAL_PROOFS_VALID"),
        ("issuer.trust", "ISSUER_TRUST_VALID"),
        ("credential.status", "CREDENTIAL_STATUS_VALID"),
        ("holder.binding", "HOLDER_BINDING_VALID"),
        ("transaction.binding", "TRANSACTION_BINDING_VALID"),
        ("claim.constraints", "CLAIM_CONSTRAINTS_SATISFIED"),
    ]
    .into_iter()
    .map(|(check_id, code)| json!({"check_id":check_id,"outcome":"PASSED","code":code}))
    .collect::<Vec<_>>();
    Ok(json!({
        "schema": "elevenid.credentials-verifier-positive-runtime/v1",
        "status": "passed",
        "decision": "PASS",
        "verified_claims": {"email": EMAIL},
        "checks": checks,
    }))
}

#[tokio::main]
async fn main() {
    let result = match read_input(std::io::stdin().lock()) {
        Ok(input) => execute(input).await,
        Err(error) => Err(error),
    };
    match result {
        Ok(evidence) => println!("{evidence}"),
        Err(error) => {
            eprintln!("positive OID4VP runtime gate failed: {error}");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn public_fixture() -> Value {
        // Parser-only data. This is deliberately not a signed acceptance fixture.
        json!({
            "presentation": "invalid.unsigned.presentation",
            "issuer_public_jwk": {
                "kty": "EC", "crv": "P-256", "alg": "ES256", "kid": ISSUER_KID,
                "x": URL_SAFE_NO_PAD.encode([0u8; 32]),
                "y": URL_SAFE_NO_PAD.encode([0u8; 32]),
            }
        })
    }

    #[test]
    fn fixture_input_rejects_private_material_unknown_fields_and_oversized_streams() {
        let input = public_fixture();
        assert!(read_input(input.to_string().as_bytes()).is_ok());
        for member in ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
            let mut private = input.clone();
            private["issuer_public_jwk"][member] = json!("private-fixture");
            assert!(read_input(private.to_string().as_bytes()).is_err());
        }
        let mut unknown = input;
        unknown["unchecked"] = json!(true);
        assert!(read_input(unknown.to_string().as_bytes()).is_err());
        assert!(read_input(std::io::repeat(b' ')).is_err());
        assert!(read_input(&b""[..]).is_err());
    }

    #[tokio::test]
    async fn public_input_cannot_claim_success_without_valid_signatures() {
        let encoded = public_fixture().to_string();
        let input = read_input(encoded.as_bytes()).expect("parser-only fixture");
        assert!(execute(input).await.is_err());
    }
}
