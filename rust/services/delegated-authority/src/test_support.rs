use crate::*;
use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;
pub fn pending_grant() -> DelegationGrant {
    let now = DateTime::parse_from_rfc3339("2026-11-17T17:00:00Z")
        .unwrap()
        .with_timezone(&Utc);
    let principal = |id: String, principal_type| Principal { principal_type, id };
    let grantor = principal(
        "https://identity.example/users/customer-1".into(),
        PrincipalType::User,
    );
    let delegate = principal(
        "https://agents.example/agents/shopper-1".into(),
        PrincipalType::External,
    );
    let evaluator = principal(
        "https://commerce.example/evaluators/checkout-v1".into(),
        PrincipalType::External,
    );
    let terms = GrantTerms {
        grantor: grantor.clone(),
        subject: grantor,
        delegate,
        binding: Binding {
            method: BindingMethod::Session,
            key_thumbprint: None,
            session_ref: Some("https://identity.example/sessions/session-1".into()),
            establishment_evidence_ref: Some("https://identity.example/evidence/binding-1".into()),
        },
        actions: vec!["urn:commerce:action:purchase.complete".into()],
        audiences: vec!["https://merchant.example".into()],
        resources: vec!["urn:commerce:product:lamp-001".into()],
        valid_from: now - Duration::seconds(1),
        valid_until: now + Duration::hours(2),
        subdelegation_allowed: false,
        constraints: Constraints {
            mode: ConstraintMode::ExternalProfile,
            request_profile: None,
            request_digest: None,
            profile: Some("https://commerce.example/profiles/desk-lamp-purchase/v1".into()),
            document_ref: Some("https://commerce.example/policies/desk-lamp-purchase/v1".into()),
            document_digest: Some(format!("sha256:{}", "a".repeat(64))),
            evaluator: Some(evaluator),
        },
    };
    DelegationGrant::pending(
        Uuid::new_v4(),
        Authority {
            mode: AuthorityMode::Managed,
            issuer: principal(
                "https://identity.example/issuers/marty".into(),
                PrincipalType::Organization,
            ),
            status_ref: "https://identity.example/v1/delegations/status".into(),
            source_profile: None,
            source_evidence_ref: None,
            source_evidence_digest: None,
            source_expires_at: None,
        },
        terms,
        now,
    )
    .unwrap()
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
        assert_eq!(
            grant.terms.validate(),
            Err(GrantValidationError::SubdelegationUnsupported)
        );
    }
    #[test]
    fn detects_term_tampering() {
        let mut grant = pending_grant();
        grant.terms.resources[0] = "urn:commerce:product:other".into();
        assert_eq!(
            grant.validate(),
            Err(GrantValidationError::TermsDigestMismatch)
        );
    }
    #[test]
    fn expiry_is_derived_from_terms() {
        let grant = pending_grant();
        assert_eq!(
            grant.current_status(grant.terms.valid_until + Duration::seconds(1)),
            GrantStatus::Expired
        );
    }
}

#[test]
fn computes_stable_rfc8785_terms_digest_for_protocol_grant_shape() {
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
    "binding":{"method":"KEY","key_thumbprint":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
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
    grant.terms_digest = grant.calculate_terms_digest().unwrap();
    grant.approval.as_mut().unwrap().terms_digest = grant.terms_digest.clone();
    assert!(grant.terms_digest.starts_with("sha256:"));
    assert_eq!(grant.calculate_terms_digest().unwrap(), grant.terms_digest);
    grant.validate().unwrap();
}

#[test]
fn protocol_transition_rejects_terms_substitution_even_with_recomputed_digest() {
    let previous = pending_grant();
    let mut current = previous.clone();
    current.status = GrantStatus::Revoked;
    current.revision = previous.revision + 1;
    current.updated_at = previous.updated_at + Duration::seconds(1);
    current.terms.resources[0] = "urn:commerce:product:substituted".into();
    current.terms_digest = current.calculate_terms_digest().unwrap();
    assert_eq!(
        validate_transition(&previous, &current),
        Err(GrantValidationError::ImmutableGrantDataChanged)
    );
}

#[test]
fn principal_roles_remain_distinct_even_when_identifiers_match() {
    let mut grant = pending_grant();
    grant.terms.delegate = grant.terms.grantor.clone();
    grant.terms_digest = grant.calculate_terms_digest().unwrap();
    grant.validate().unwrap();
}

#[test]
fn uri_validation_rejects_repaired_urls_and_bad_percent_escapes() {
    for invalid in [
        "1urn:principal",
        "urn:has space",
        "urn:bad%escape",
        "urn:bad%0",
        "urn:bad\\path",
        "https://",
        "urn:has\ncontrol",
        "urn:nonascii:é",
        "urn:wildcard:*",
    ] {
        let mut grant = pending_grant();
        grant.terms.delegate.id = invalid.into();
        assert_eq!(
            grant.terms.validate(),
            Err(GrantValidationError::InvalidPrincipal),
            "{invalid:?}"
        );
    }
}

#[test]
fn oversized_programmatic_snapshot_cannot_be_persisted() {
    let mut grant = pending_grant();
    grant.terms.resources = (0..64)
        .map(|i| format!("urn:resource:{i}:{}", "x".repeat(990)))
        .collect();
    grant.terms_digest = grant.calculate_terms_digest().unwrap();
    assert_eq!(
        grant.validate(),
        Err(GrantValidationError::DocumentTooLarge)
    );
}

#[test]
fn external_snapshots_validate_but_local_transitions_are_rejected() {
    let mut grant = pending_grant();
    grant.authority.mode = AuthorityMode::External;
    grant.authority.source_profile = Some("urn:example:source:v1".into());
    grant.authority.source_evidence_ref = Some("urn:example:evidence:1".into());
    grant.authority.source_evidence_digest = Some(format!("sha256:{}", "a".repeat(64)));
    grant.authority.source_expires_at = Some(grant.terms.valid_until);
    grant.terms_digest = grant.calculate_terms_digest().unwrap();
    grant.validate().unwrap();
    let mut revoked = grant.clone();
    revoked.revision += 1;
    revoked.updated_at += Duration::seconds(1);
    revoked.status = GrantStatus::Revoked;
    assert_eq!(
        validate_transition(&grant, &revoked),
        Err(GrantValidationError::ExternalAuthorityReadOnly)
    );
}

#[test]
fn reference_transition_permits_revocation_after_validity_ends() {
    let previous = pending_grant();
    let mut revoked = previous.clone();
    revoked.revision += 1;
    revoked.updated_at = previous.terms.valid_until + Duration::seconds(1);
    revoked.status = GrantStatus::Revoked;
    validate_transition(&previous, &revoked).unwrap();
}

#[test]
fn canonical_projection_uses_utf16_key_order_and_rejects_numbers() {
    let value = serde_json::json!({"\u{e000}": "last", "\u{1f600}": "first", "a": [true, false, null, "\n\"\\"]});
    assert_eq!(
        String::from_utf8(crate::domain::canonical_json(&value).unwrap()).unwrap(),
        "{\"a\":[true,false,null,\"\\n\\\"\\\\\"],\"😀\":\"first\",\"\u{e000}\":\"last\"}"
    );
    assert_eq!(
        crate::domain::canonical_json(&serde_json::json!({"number": 1})),
        Err(GrantValidationError::UnsupportedCanonicalNumber)
    );
}

#[test]
fn managed_timestamps_reject_leap_seconds_without_normalizing_them() {
    let mut grant = pending_grant();
    grant.terms.valid_until = DateTime::parse_from_rfc3339("2026-12-31T23:59:60Z")
        .unwrap()
        .with_timezone(&Utc);
    assert_eq!(
        grant.terms.validate(),
        Err(GrantValidationError::InvalidTimestamp)
    );
}

#[test]
fn key_binding_thumbprints_use_rfc7638_base64url_encoding() {
    let mut grant = pending_grant();
    grant.terms.binding = Binding {
        method: BindingMethod::Key,
        key_thumbprint: Some(format!("sha256:{}", "a".repeat(43))),
        session_ref: None,
        establishment_evidence_ref: None,
    };
    grant.terms_digest = grant.calculate_terms_digest().unwrap();
    assert!(grant.validate().is_ok());

    grant.terms.binding.key_thumbprint = Some(format!("sha256:{}", "a".repeat(64)));
    grant.terms_digest = grant.calculate_terms_digest().unwrap();
    assert_eq!(
        grant.terms.validate(),
        Err(GrantValidationError::InvalidBinding)
    );
}
