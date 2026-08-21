use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use marty_auth::{
    applicant_upsert, extract_applicant_names, ApplicantProvisioningStore, JitProvisioningConfig,
    JitUserProvisioner, MemoryApplicantProvisioningStore, OidcUserInfo, OrganizationContext,
    OrganizationProvisioning, PortError, UserType,
};
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../contracts/auth-behavior.json"
    )))
    .expect("auth behavior fixture")
}

fn now() -> DateTime<Utc> {
    "2026-08-20T12:00:00Z".parse().expect("timestamp")
}

fn oidc_user() -> OidcUserInfo {
    OidcUserInfo {
        sub: "account-1".to_owned(),
        email: "alice@example.com".to_owned(),
        email_verified: true,
        name: Some("Alice Smith".to_owned()),
        given_name: Some("Alice".to_owned()),
        family_name: Some("Smith".to_owned()),
        preferred_username: Some("alice".to_owned()),
        picture: Some("https://images.example/alice.png".to_owned()),
        locale: None,
        organization_id: None,
        organization_name: None,
        organization: None,
        roles: vec!["applicant".to_owned()],
    }
}

#[derive(Default)]
struct FakeOrganizations {
    add_error: Mutex<bool>,
    context_error: Mutex<bool>,
    context: Mutex<Option<OrganizationContext>>,
}

#[async_trait]
impl OrganizationProvisioning for FakeOrganizations {
    async fn ensure_default_member(&self, _user_id: &str, _email: &str) -> Result<(), PortError> {
        if *self.add_error.lock().expect("add lock") {
            Err(PortError::new("organization_unavailable", "add failed"))
        } else {
            Ok(())
        }
    }

    async fn resolve_default_context(
        &self,
        _user_id: &str,
    ) -> Result<Option<OrganizationContext>, PortError> {
        if *self.context_error.lock().expect("context error lock") {
            Err(PortError::new("organization_unavailable", "lookup failed"))
        } else {
            Ok(self.context.lock().expect("context lock").clone())
        }
    }
}

fn provisioner(organizations: Arc<FakeOrganizations>) -> JitUserProvisioner {
    JitUserProvisioner::new(
        Arc::new(MemoryApplicantProvisioningStore::default()),
        organizations,
        JitProvisioningConfig {
            default_organization_id: "00000000-0000-0000-0000-000000000001".to_owned(),
            default_organization_slug: "marty".to_owned(),
            default_organization_name: "Marty".to_owned(),
        },
    )
}

#[test]
fn applicant_name_extraction_matches_shared_vectors() {
    for case in fixture()["provisioning_name_cases"]
        .as_array()
        .expect("name cases")
    {
        let mut user = oidc_user();
        user.given_name = case["given_name"].as_str().map(str::to_owned);
        user.family_name = case["family_name"].as_str().map(str::to_owned);
        user.name = case["name"].as_str().map(str::to_owned);
        let (given, family) = extract_applicant_names(&user);
        assert_eq!(given.as_deref(), case["expected_given_name"].as_str());
        assert_eq!(family.as_deref(), case["expected_family_name"].as_str());
    }
}

#[tokio::test]
async fn applicant_upsert_preserves_existing_names_when_claims_become_incomplete() {
    let store = MemoryApplicantProvisioningStore::default();
    let original = oidc_user();
    let first = store
        .upsert(&applicant_upsert(&original, now()))
        .await
        .expect("initial upsert");
    let mut incomplete = original;
    incomplete.given_name = None;
    incomplete.family_name = None;
    incomplete.name = None;
    let second = store
        .upsert(&applicant_upsert(
            &incomplete,
            "2026-08-21T12:00:00Z".parse().expect("timestamp"),
        ))
        .await
        .expect("update upsert");
    assert_eq!(second.id, first.id);
    assert_eq!(second.given_names, "Alice");
    assert_eq!(second.surname, "Smith");
    assert_eq!(second.extra_data["oidc_claims_incomplete"], true);
}

#[tokio::test]
async fn provisioning_enriches_roles_type_and_browser_organization_shape() {
    let organizations = Arc::new(FakeOrganizations::default());
    *organizations.context.lock().expect("context lock") = Some(OrganizationContext {
        organization_id: "org-1".to_owned(),
        organization_name: Some("Marty Health".to_owned()),
        role_names: vec!["reviewer".to_owned(), "owner".to_owned()],
        has_org_console_access: true,
    });
    let user = provisioner(organizations)
        .provision_at(&oidc_user(), now())
        .await
        .expect("provision user");
    assert_eq!(user.user_type, UserType::Vendor);
    assert_eq!(user.roles, ["applicant", "reviewer", "owner"]);
    assert_eq!(user.organization_id.as_deref(), Some("org-1"));
    assert_eq!(
        user.default_organization_name.as_deref(),
        Some("Marty Health")
    );
    assert_eq!(user.organizations[0]["name"], "marty");
    assert_eq!(user.organizations[0]["membership"]["is_owner"], true);
    assert_eq!(
        user.organizations[0]["membership"]["has_org_console_access"],
        true
    );
    assert!(!user.organization_context_unavailable);
}

#[tokio::test]
async fn organization_outage_is_observable_without_discarding_valid_identity() {
    let organizations = Arc::new(FakeOrganizations::default());
    *organizations.add_error.lock().expect("add lock") = true;
    *organizations
        .context_error
        .lock()
        .expect("context error lock") = true;
    let user = provisioner(organizations)
        .provision_at(&oidc_user(), now())
        .await
        .expect("provision despite optional organization outage");
    assert!(user.organization_context_unavailable);
    assert_eq!(
        user.organization_context_error.as_deref(),
        Some("marty_organization_context_unavailable")
    );
    assert!(user.organization_id.is_none());
}
