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
        grant.validate(Utc::now()).unwrap();
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
