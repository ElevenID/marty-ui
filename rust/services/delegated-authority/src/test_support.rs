use chrono::{Duration, Utc};
use uuid::Uuid;
use crate::*;
pub fn pending_grant() -> DelegationGrant {
    let now = Utc::now();
    let principal = |id: String, principal_type| Principal { principal_type, id };
    let grantor = principal("https://identity.example/users/customer-1".into(), PrincipalType::User);
    let delegate = principal("https://agents.example/agents/shopper-1".into(), PrincipalType::External);
    let evaluator = principal("https://commerce.example/evaluators/checkout-v1".into(), PrincipalType::External);
    let terms = GrantTerms {
        grantor: grantor.clone(), subject: grantor,
        delegate,
        binding: Binding { method: BindingMethod::Session, key_thumbprint: None,
            session_ref: Some("https://identity.example/sessions/session-1".into()),
            establishment_evidence_ref: Some("https://identity.example/evidence/binding-1".into()) },
        actions: vec!["urn:commerce:action:purchase.complete".into()],
        audiences: vec!["https://merchant.example".into()],
        resources: vec!["urn:commerce:product:lamp-001".into()],
        valid_from: now - Duration::seconds(1), valid_until: now + Duration::hours(2),
        subdelegation_allowed: false,
        constraints: Constraints { mode: ConstraintMode::ExternalProfile,
            request_profile: None, request_digest: None,
            profile: Some("https://commerce.example/profiles/desk-lamp-purchase/v1".into()),
            document_ref: Some("https://commerce.example/policies/desk-lamp-purchase/v1".into()),
            document_digest: Some(format!("sha256:{}", "a".repeat(64))), evaluator: Some(evaluator) },
    };
    DelegationGrant::pending(Uuid::new_v4(), Authority { mode: AuthorityMode::Managed,
        issuer: principal("https://identity.example/issuers/marty".into(), PrincipalType::Organization),
        status_ref: "https://identity.example/v1/delegations/status".into(),
        source_profile: None, source_evidence_ref: None, source_evidence_digest: None,
        source_expires_at: None }, terms, now).unwrap()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn grant_starts_pending_with_digest() {
        let grant = pending_grant();
        assert_eq!(grant.status, GrantStatus::Pending);
        assert_eq!(grant.revision, 1);
        assert!(grant.terms_digest.starts_with("sha256:"));
        grant.validate().unwrap();
    }
    #[test]
    fn rejects_subdelegation() {
        let mut grant = pending_grant();
        grant.terms.subdelegation_allowed = true;
        assert_eq!(grant.terms.validate(), Err(GrantValidationError::SubdelegationUnsupported));
    }
    #[test]
    fn detects_term_tampering() {
        let mut grant = pending_grant();
        grant.terms.resources[0] = "urn:commerce:product:other".into();
        assert_eq!(grant.validate(Utc::now()), Err(GrantValidationError::TermsDigestMismatch));
    }
    #[test]
    fn expiry_is_derived_from_terms() {
        let grant = pending_grant();
        assert_eq!(grant.current_status(grant.terms.valid_until + Duration::seconds(1)), GrantStatus::Expired);
    }
}

#[test]
fn matches_marty_protocol_rfc8785_terms_digest_vector() {
    let grant: DelegationGrant = serde_json::from_str(r#"
{
  "profile":"urn:marty:delegation-grant:v1",
  "id":"00000000-0000-4000-8000-000000000001",
  "organization_id":"00000000-0000-4000-8000-000000000002",
  "authority":{"mode":"MANAGED","issuer":{"type":"SERVICE_ACCOUNT","id":"urn:example:authority"},"status_ref":"https://authority.example/grants/1"},
  "terms":{
    "grantor":{"type":"USER","id":"urn:example:customer"},
    "subject":{"type":"USER","id":"urn:example:customer"},
    "delegate":{"type":"SERVICE_ACCOUNT","id":"urn:example:agent"},
    "binding":{"method":"KEY","key_thumbprint":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
    "actions":["urn:example:checkout:prepare"],
    "audiences":["https://merchant.example"],
    "resources":["urn:example:checkout:1"],
    "valid_from":"2026-11-17T17:00:00Z",
    "valid_until":"2026-11-17T18:00:00Z",
    "subdelegation_allowed":false,
    "constraints":{"mode":"EXACT_OPERATION","request_profile":"urn:example:checkout:v1","request_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
  },
  "terms_digest":"sha256:246febf8b6c26aa095bc1e83fcfcb131c8dff65c067d95f446a704aff92ac4b9",
  "status":"ACTIVE",
  "revision":1,
  "created_at":"2026-11-17T16:59:00Z",
  "updated_at":"2026-11-17T17:00:00Z",
  "approval":{
    "profile":"urn:example:trusted-surface:v1",
    "grant_id":"00000000-0000-4000-8000-000000000001",
    "approver":{"type":"USER","id":"urn:example:customer"},
    "evidence_ref":"urn:example:approval:1",
    "authority_evidence_ref":"urn:example:authority-evidence:1",
    "terms_digest":"sha256:246febf8b6c26aa095bc1e83fcfcb131c8dff65c067d95f446a704aff92ac4b9",
    "approved_at":"2026-11-17T17:00:00Z"
  }
}
    "#).unwrap();
    assert_eq!(grant.calculate_terms_digest().unwrap(),
        "sha256:246febf8b6c26aa095bc1e83fcfcb131c8dff65c067d95f446a704aff92ac4b9");
    grant.validate().unwrap();
}
