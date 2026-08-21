use async_trait::async_trait;
use marty_auth::{
    apply_credential_login_defaults, build_credential_login_user, AuthenticatedUser,
    CredentialIdentityProvisioner, OidcUserInfo, PortError, UserType,
};
use serde_json::json;

struct FixedProvisioner {
    user: AuthenticatedUser,
    fails: bool,
}

#[async_trait]
impl CredentialIdentityProvisioner for FixedProvisioner {
    async fn provision_credential_identity(
        &self,
        _user: &OidcUserInfo,
    ) -> Result<AuthenticatedUser, PortError> {
        if self.fails {
            Err(PortError::new("provisioning_failed", "offline"))
        } else {
            Ok(self.user.clone())
        }
    }
}

fn provisioned_user() -> AuthenticatedUser {
    AuthenticatedUser {
        user_id: "provisioned-user".to_owned(),
        email: "alice@example.com".to_owned(),
        username: Some("alice".to_owned()),
        given_name: Some("Alice".to_owned()),
        family_name: Some("Smith".to_owned()),
        user_type: UserType::Applicant,
        applicant_id: Some("provisioned-applicant".to_owned()),
        roles: vec!["applicant".to_owned(), "admin".to_owned()],
        organization_id: Some("marty-org".to_owned()),
        organization_name: Some("Marty".to_owned()),
        organization: Some(json!({"marty-org": {"name": "Marty"}})),
        default_organization_id: Some("marty-org".to_owned()),
        default_organization_name: Some("Marty".to_owned()),
        organizations: vec![json!({"id": "marty-org"})],
        organization_context_unavailable: false,
        organization_context_error: None,
        onboarding_completed: None,
        picture: None,
        impersonation: None,
        did_subject: None,
    }
}

#[tokio::test]
async fn credential_claims_build_a_complete_fallback_identity() {
    let user = build_credential_login_user(
        &json!({
            "email": "alice@example.com",
            "given_name": "Alice",
            "family_name": "Smith",
            "role": "vendor",
            "organization_id": "org-123",
            "organization_name": "Acme",
            "member_id": "member-123"
        }),
        None,
        None,
    )
    .await
    .expect("credential user");
    assert_eq!(user.user_type, UserType::Vendor);
    assert_eq!(user.organization_id.as_deref(), Some("org-123"));
    assert_eq!(user.applicant_id.as_deref(), Some("member-123"));
}

#[tokio::test]
async fn keycloak_and_provisioned_context_merge_without_losing_credential_role_or_did() {
    let keycloak = OidcUserInfo {
        sub: "kc-user".to_owned(),
        email: "alice@example.com".to_owned(),
        email_verified: true,
        name: None,
        given_name: Some("Alice".to_owned()),
        family_name: Some("Smith".to_owned()),
        preferred_username: Some("alice".to_owned()),
        picture: None,
        locale: None,
        organization_id: Some("org-1".to_owned()),
        organization_name: Some("Acme".to_owned()),
        organization: Some(json!({"org-1": {"name": "Acme"}})),
        roles: vec!["administrator".to_owned(), "manage-users".to_owned()],
    };
    let provisioner = FixedProvisioner {
        user: provisioned_user(),
        fails: false,
    };
    let did = "did:web:example.com:users:alice";
    let user = build_credential_login_user(
        &json!({
            "email": "alice@example.com",
            "preferred_username": "badge-alice",
            "member_id": "member-123",
            "role": "applicant",
            "credentialSubject": {"id": did}
        }),
        Some(&provisioner),
        Some(&keycloak),
    )
    .await
    .expect("merged credential user");
    assert_eq!(user.user_type, UserType::Administrator);
    assert_eq!(user.username.as_deref(), Some("badge-alice"));
    assert_eq!(user.applicant_id.as_deref(), Some("member-123"));
    assert_eq!(user.organization_id.as_deref(), Some("marty-org"));
    assert_eq!(user.roles, ["applicant", "admin"]);
    assert_eq!(user.did_subject.as_deref(), Some(did));
    assert_eq!(user.default_organization_id.as_deref(), Some("marty-org"));
}

#[tokio::test]
async fn provisioning_failure_falls_back_to_verified_credential_and_keycloak_context() {
    let keycloak = OidcUserInfo {
        sub: "kc-user".to_owned(),
        email: "alice@example.com".to_owned(),
        email_verified: true,
        name: None,
        given_name: None,
        family_name: None,
        preferred_username: Some("alice".to_owned()),
        picture: None,
        locale: None,
        organization_id: Some("org-1".to_owned()),
        organization_name: Some("Acme".to_owned()),
        organization: None,
        roles: vec!["vendor".to_owned()],
    };
    let provisioner = FixedProvisioner {
        user: provisioned_user(),
        fails: true,
    };
    let user = build_credential_login_user(
        &json!({"email": "alice@example.com", "role": "applicant"}),
        Some(&provisioner),
        Some(&keycloak),
    )
    .await
    .expect("fallback credential user");
    assert_eq!(user.user_id, "kc-user");
    assert_eq!(user.user_type, UserType::Vendor);
    assert_eq!(user.roles, ["vendor", "applicant"]);
    assert_eq!(user.organization_id.as_deref(), Some("org-1"));
}

#[tokio::test]
async fn deterministic_email_identity_and_did_fallback_match_legacy_behavior() {
    let first = build_credential_login_user(
        &json!({"email": "Case@Example.com", "sub": "did:key:zExample"}),
        None,
        None,
    )
    .await
    .expect("DID subject user");
    assert_eq!(first.user_id, "did:key:zExample");
    assert_eq!(first.did_subject.as_deref(), Some("did:key:zExample"));

    let derived = build_credential_login_user(&json!({"email": "Case@Example.com"}), None, None)
        .await
        .expect("derived user");
    assert_eq!(derived.user_id, "8333ff5a-2174-67a0-083a-8e7ebd6bdaf9");
}

#[test]
fn default_organization_is_not_applied_to_canvas_lti_learners() {
    let mut ordinary = provisioned_user();
    ordinary.organization_id = None;
    let ordinary = apply_credential_login_defaults(ordinary, "marty-org");
    assert_eq!(ordinary.organization_id.as_deref(), Some("marty-org"));

    let mut canvas = provisioned_user();
    canvas.organization_id = None;
    canvas.roles.push("canvas_lti_learner".to_owned());
    let canvas = apply_credential_login_defaults(canvas, "marty-org");
    assert!(canvas.organization_id.is_none());
}
