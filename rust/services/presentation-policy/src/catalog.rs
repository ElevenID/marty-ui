use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{
    CredentialRequirement, DisplayMetadata, FreshnessPolicy, HolderBinding, PolicyRepository,
    PolicyStatus, PresentationPolicy, RequestPurpose, RequestedClaim,
};

const MARTY_ORG: Uuid = Uuid::from_u128(1);
const ELEVEN_ID_ORG: Uuid = Uuid::from_u128(0x2222_2222_2222_2222_2222_2222_2222_2222);
const MARTY_TRUST_PROFILE: Uuid = Uuid::from_u128(0x6000_0000_0000_0000_0000_0000_0000_0001);
const CATALOG_NAMESPACE: Uuid = Uuid::from_u128(0x9d96_b1f3_0d84_46c8_aab4_b82a_4db1_6f51);

pub async fn reconcile_builtin_policies(
    repository: &dyn PolicyRepository,
) -> Result<usize, String> {
    let policies = built_in_presentation_policies();
    for policy in &policies {
        policy.validate().map_err(|error| error.to_string())?;
        repository.save(policy).await?;
    }
    Ok(policies.len())
}

#[must_use]
pub fn built_in_presentation_policies() -> Vec<PresentationPolicy> {
    vec![
        login_policy(
            "50000000-0000-0000-0000-000000000001",
            ELEVEN_ID_ORG,
            "MemberLogin",
            "40000000-0000-0000-0000-000000000010",
            "Member Credential",
            "ietf_sd_jwt",
            None,
            "Credential-based login policy. Requests only email from a MemberCredential. Organisation and role context are resolved from Keycloak during login.",
            2,
            "2026-02-27T00:00:00Z",
        ),
        login_policy(
            "50000000-0000-0000-0000-000000000002",
            MARTY_ORG,
            "MemberLogin-SD-JWT",
            "50000000-0000-0000-0000-000000000010",
            "Member Login Credential",
            "ietf_sd_jwt",
            None,
            "Marty organisation credential-based login policy (SD-JWT format). Requests only email from a MemberCredential. Organisation and role context are resolved from Keycloak during login.",
            2,
            "2026-03-22T00:00:00Z",
        ),
        login_policy(
            "50000000-0000-0000-0000-000000000003",
            MARTY_ORG,
            "MemberLogin-mDoc",
            "50000000-0000-0000-0000-000000000030",
            "Membership ID (mDoc)",
            "mso_mdoc",
            None,
            "Marty organisation credential-based login policy (mDoc format). Requests only email from a Membership ID (mDoc) credential. Organisation and role context are resolved from Keycloak during login.",
            2,
            "2026-03-22T00:00:00Z",
        ),
        open_badge_policy(),
        private_age_policy(),
    ]
}

#[allow(clippy::too_many_arguments)]
fn login_policy(
    id: &str,
    organization_id: Uuid,
    name: &str,
    template_id: &str,
    display_name: &str,
    format: &str,
    trust_profile_id: Option<Uuid>,
    description: &str,
    version: u32,
    created_at: &str,
) -> PresentationPolicy {
    policy(
        id,
        organization_id,
        name,
        description,
        DisplayMetadata {
            title: "Member Login Verification".into(),
            description: String::new(),
            purpose: RequestPurpose::Authorization,
            purpose_description: Some("Verify your membership credential to log in without a password. Only your email will be shared.".into()),
            verifier_name: "ElevenID LLC".into(),
            verifier_logo_url: None,
            privacy_policy_url: None,
            terms_of_service_url: None,
        },
        requirement(id, template_id, display_name, None, format, trust_profile_id, email_claim(id, true, false)),
        None,
        version,
        created_at,
    )
}

fn open_badge_policy() -> PresentationPolicy {
    policy(
        "50000000-0000-0000-0000-000000000004",
        MARTY_ORG,
        "OpenBadgeLogin",
        "Passwordless login using a trusted, active Open Badges 3.0 membership credential.",
        DisplayMetadata {
            title: "Marty Open Badge Login".into(),
            description: String::new(),
            purpose: RequestPurpose::Authorization,
            purpose_description: Some(
                "Present your membership badge and account email to sign in without a password."
                    .into(),
            ),
            verifier_name: "ElevenID LLC".into(),
            verifier_logo_url: None,
            privacy_policy_url: None,
            terms_of_service_url: None,
        },
        requirement(
            "50000000-0000-0000-0000-000000000004",
            "50000000-0000-0000-0000-000000000040",
            "Marty Verified Member Badge",
            Some("Present your Open Badge 3.0 verified membership badge."),
            "openbadge-v3",
            Some(MARTY_TRUST_PROFILE),
            email_claim("50000000-0000-0000-0000-000000000004", false, false),
        ),
        Some(FreshnessPolicy {
            max_age_seconds: Some(86_400),
            require_not_revoked: true,
            revocation_grace_seconds: None,
        }),
        2,
        "2026-05-05T00:00:00Z",
    )
}

fn private_age_policy() -> PresentationPolicy {
    let id = "50000000-0000-0000-0000-000000000005";
    policy(
        id,
        MARTY_ORG,
        "Private Online Age Proof",
        "Requests only age_over_21 from a trusted mDL; no date of birth, predicates, range proofs, or ZKP are requested.",
        DisplayMetadata {
            title: "Private Online Age Proof".into(),
            description: String::new(),
            purpose: RequestPurpose::AgeVerification,
            purpose_description: Some("Confirm age eligibility by requesting only the age_over_21 mDL element.".into()),
            verifier_name: "ElevenID LLC".into(),
            verifier_logo_url: None,
            privacy_policy_url: None,
            terms_of_service_url: None,
        },
        requirement(
            id,
            "50000000-0000-0000-0000-000000000020",
            "Mobile Driving Licence",
            Some("Present only the pre-issued age_over_21 element from a trusted mDL."),
            "mso_mdoc",
            Some(MARTY_TRUST_PROFILE),
            RequestedClaim {
                id: stable_id(id, "age_over_21"),
                claim_name: "age_over_21".into(),
                display_name: "Age Over 21".into(),
                description: Some("Confirm eligibility without disclosing date of birth or identity details".into()),
                required: true,
                selective_disclosure: true,
                accept_derived: true,
                predicate_spec: None,
                constraints: Vec::new(),
            },
        ),
        None,
        1,
        "2026-07-18T00:00:00Z",
    )
}

fn requirement(
    seed: &str,
    template_id: &str,
    display_name: &str,
    description: Option<&str>,
    format: &str,
    trust_profile_id: Option<Uuid>,
    claim: RequestedClaim,
) -> CredentialRequirement {
    CredentialRequirement {
        id: stable_id(seed, "requirement"),
        credential_template_id: template_id.into(),
        display_name: display_name.into(),
        description: description.map(str::to_owned),
        required: true,
        credential_payload_format: format.into(),
        requested_claims: vec![claim],
        trust_profile_id,
        max_age_seconds: None,
        require_fresh_issuance: false,
    }
}

fn email_claim(seed: &str, selective_disclosure: bool, accept_derived: bool) -> RequestedClaim {
    RequestedClaim {
        id: stable_id(seed, "email"),
        claim_name: "email".into(),
        display_name: "Email Address".into(),
        description: Some("Identify your account".into()),
        required: true,
        selective_disclosure,
        accept_derived,
        predicate_spec: None,
        constraints: Vec::new(),
    }
}

#[allow(clippy::too_many_arguments)]
fn policy(
    id: &str,
    organization_id: Uuid,
    name: &str,
    description: &str,
    display_metadata: DisplayMetadata,
    requirement: CredentialRequirement,
    freshness: Option<FreshnessPolicy>,
    version: u32,
    created_at: &str,
) -> PresentationPolicy {
    let created_at = timestamp(created_at);
    PresentationPolicy {
        id: id.parse().expect("catalog policy UUID"),
        organization_id,
        name: name.into(),
        description: Some(description.into()),
        status: PolicyStatus::Active,
        display_metadata,
        required_claims: Vec::new(),
        accepted_credential_types: Vec::new(),
        credential_requirements: vec![requirement],
        alternative_requirements: Vec::new(),
        presentation_proof_required: false,
        trust_profile_id: None,
        holder_binding: HolderBinding::default(),
        freshness,
        issuer_constraints: None,
        credential_ranking_strategy: "FRESHEST_FIRST".into(),
        credential_ranking_weights: None,
        purpose: None,
        compliance_profile_id: None,
        prefer_predicates: false,
        fallback_policy: None,
        supported_circuits: Vec::new(),
        version,
        created_at,
        updated_at: created_at,
    }
}

fn stable_id(seed: &str, kind: &str) -> Uuid {
    Uuid::new_v5(&CATALOG_NAMESPACE, format!("{seed}:{kind}").as_bytes())
}

fn timestamp(value: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(value)
        .expect("catalog timestamp")
        .with_timezone(&Utc)
}
