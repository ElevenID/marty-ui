//! Gateway-specific tenant authorization classification.
//!
//! Cedar policy parsing and evaluation belongs to `mmf-security`. This module
//! contains only Marty gateway product semantics: route-to-permission mapping,
//! resource-owner lookup routing, public authorization skips, and API-key
//! scope compatibility.

use std::{collections::BTreeSet, sync::LazyLock};

use async_trait::async_trait;
use mmf_security::SecurityError;
use regex::Regex;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequiredPermission {
    pub permission: &'static str,
    pub resource: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceLookup {
    pub service: &'static str,
    pub path: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrganizationMembership {
    pub user_id: String,
    pub organization_id: String,
    pub status: String,
    pub role_names: BTreeSet<String>,
    pub permissions: BTreeSet<String>,
    pub is_owner: bool,
}

impl OrganizationMembership {
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.status == "active"
    }

    #[must_use]
    pub fn allows(&self, required_permission: &str) -> bool {
        if required_permission == "organization:transfer-ownership" {
            self.is_owner
        } else {
            self.permissions.contains(required_permission)
        }
    }
}

#[async_trait]
pub trait OrganizationMembershipProvider: Send + Sync {
    async fn get_membership(
        &self,
        user_id: &str,
        organization_id: &str,
    ) -> Result<Option<OrganizationMembership>, SecurityError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TenantAuthorizationFailure {
    ApiKeyOrganizationMismatch,
    ApiKeyPermissionMissing,
    AuthenticationRequired,
    MembershipMissing,
    MembershipInactive,
    ActionNotAuthorized,
}

pub fn authorize_api_key(
    required_permission: &str,
    organization_id: &str,
    api_key_organization_id: Option<&str>,
    scopes: &[String],
) -> Result<(), TenantAuthorizationFailure> {
    if api_key_organization_id != Some(organization_id) {
        return Err(TenantAuthorizationFailure::ApiKeyOrganizationMismatch);
    }
    if !api_key_allowed(required_permission, scopes) {
        return Err(TenantAuthorizationFailure::ApiKeyPermissionMissing);
    }
    Ok(())
}

pub fn authorize_membership(
    required_permission: &str,
    user_id: &str,
    organization_id: &str,
    membership: Option<&OrganizationMembership>,
) -> Result<(), TenantAuthorizationFailure> {
    if user_id.trim().is_empty() {
        return Err(TenantAuthorizationFailure::AuthenticationRequired);
    }
    let membership = membership.ok_or(TenantAuthorizationFailure::MembershipMissing)?;
    if membership.user_id != user_id || membership.organization_id != organization_id {
        return Err(TenantAuthorizationFailure::MembershipMissing);
    }
    if !membership.is_active() {
        return Err(TenantAuthorizationFailure::MembershipInactive);
    }
    if !membership.allows(required_permission) {
        return Err(TenantAuthorizationFailure::ActionNotAuthorized);
    }
    Ok(())
}

struct RouteRule {
    pattern: Regex,
    methods: &'static [(&'static str, &'static str)],
    resource: &'static str,
}

fn rule(
    pattern: &str,
    methods: &'static [(&'static str, &'static str)],
    resource: &'static str,
) -> RouteRule {
    RouteRule {
        pattern: Regex::new(pattern).expect("gateway authorization regex must be valid"),
        methods,
        resource,
    }
}

static SPECIAL_RULES: LazyLock<Vec<RouteRule>> = LazyLock::new(|| {
    vec![
        rule(
            r"^/v1/api-keys(?:/[^/]+)?$",
            &[
                ("GET", "api-key:view"),
                ("POST", "api-key:create"),
                ("DELETE", "api-key:revoke"),
            ],
            "api-key",
        ),
        // Gateway compatibility rules are intentionally first, matching the
        // Python prepend semantics used before this classifier was canonical.
        rule(
            r"^/v1/webhooks/[^/]+/test$",
            &[("POST", "webhook:test")],
            "webhook",
        ),
        rule(
            r"^/v1/webhooks/[^/]+/regenerate-secret$",
            &[("POST", "webhook:edit")],
            "webhook",
        ),
        rule(
            r"^/v1/webhooks(?:/|$)",
            &[
                ("GET", "webhook:view"),
                ("HEAD", "webhook:view"),
                ("OPTIONS", "webhook:view"),
                ("POST", "webhook:create"),
                ("PUT", "webhook:edit"),
                ("PATCH", "webhook:edit"),
                ("DELETE", "webhook:delete"),
            ],
            "webhook",
        ),
        rule(
            r"^/v1/subscriptions(?:/|$)",
            &[
                ("GET", "webhook:view"),
                ("HEAD", "webhook:view"),
                ("OPTIONS", "webhook:view"),
                ("POST", "webhook:create"),
                ("PUT", "webhook:edit"),
                ("PATCH", "webhook:edit"),
                ("DELETE", "webhook:delete"),
            ],
            "webhook",
        ),
        rule(
            r"^/v1/notifications/send$",
            &[("POST", "notification:send")],
            "notification",
        ),
        rule(
            r"^/v1/notifications(?:/|$)",
            &[
                ("GET", "notification:view"),
                ("HEAD", "notification:view"),
                ("OPTIONS", "notification:view"),
                ("POST", "notification:view"),
                ("PUT", "notification:view"),
                ("PATCH", "notification:view"),
                ("DELETE", "notification:view"),
            ],
            "notification",
        ),
        rule(
            r"^/v1/issuance/delivery-records/canvas-credentials/provenance$",
            &[("GET", "integration-connector:view")],
            "integration-connector",
        ),
        rule(
            r"^/v1/issuance/delivery-records/canvas-credentials/(?:process-pending|process-status-sync-failures|run-automation-cycle)$",
            &[("POST", "integration-connector:edit")],
            "integration-connector",
        ),
        rule(
            r"^/v1/issuance/organizations/[^/]+/canvas-mirror-health$",
            &[("GET", "integration-connector:view")],
            "integration-connector",
        ),
        rule(
            r"^/v1/vc-api/credentials/issue$",
            &[("POST", "issuance:initiate")],
            "issuance",
        ),
        rule(
            r"^/v1/vc-api/(?:credentials|presentations)/verify$",
            &[("POST", "verification:execute")],
            "verification",
        ),
        rule(
            r"^/v1/delivery-destinations(?:/[^/]+)?$",
            &[
                ("GET", "wallet:view"),
                ("HEAD", "wallet:view"),
                ("OPTIONS", "wallet:view"),
                ("POST", "integration-connector:create"),
                ("PATCH", "integration-connector:edit"),
                ("DELETE", "integration-connector:delete"),
            ],
            "delivery-destination",
        ),
        rule(
            r"^/v1/wallet-registry(?:/|$)",
            &[
                ("GET", "wallet:view"),
                ("HEAD", "wallet:view"),
                ("OPTIONS", "wallet:view"),
                ("POST", "wallet:write"),
                ("PUT", "wallet:write"),
                ("PATCH", "wallet:write"),
                ("DELETE", "wallet:write"),
            ],
            "wallet",
        ),
        rule(
            r"^/v1/signing-keys/issuer-identities/dsc-certificate$",
            &[("POST", "passport-certificate:issue")],
            "passport-certificate",
        ),
        rule(
            r"^/v1/signing-keys/issuer-identities/csca-self-signed-certificate$",
            &[("POST", "passport-certificate:issue-csca")],
            "passport-certificate",
        ),
        rule(
            r"^/v1/signing-keys(?:/|$)",
            &[
                ("GET", "signing-key:view"),
                ("HEAD", "signing-key:view"),
                ("OPTIONS", "signing-key:view"),
                ("POST", "signing-key:create"),
                ("PUT", "signing-key:create"),
                ("PATCH", "signing-key:create"),
                ("DELETE", "signing-key:delete"),
            ],
            "signing-key",
        ),
        // Canonical marty-common route semantics, including all released
        // fixes through the inline policy-evaluation classifier.
        rule(
            r"^/v1/integrations/canvas/platforms/[^/]+/(?:registration-config|readiness)$",
            &[("GET", "integration-connector:view")],
            "integration-connector",
        ),
        rule(
            r"^/v1/integrations/canvas/platforms/[^/]+/scope-discovery$",
            &[("POST", "integration-connector:view")],
            "integration-connector",
        ),
        rule(
            r"^/v1/integrations/canvas/platforms/[^/]+/(?:sandbox-probe|jwks-refresh|oauth/start|oauth/authorizations)$",
            &[("POST", "integration-connector:edit")],
            "integration-connector",
        ),
        rule(
            r"^/v1/integrations/canvas/platforms/[^/]+/lti-installation$",
            &[("PUT", "integration-connector:edit")],
            "integration-connector",
        ),
        rule(
            r"^/v1/integrations/canvas/program-bindings/[^/]+/(?:validate|activate|deactivate)$",
            &[("POST", "integration-connector:edit")],
            "integration-connector",
        ),
        rule(
            r"^/v1/integrations/canvas/applications/[^/]+/(?:approve|canvas-sync)$",
            &[("POST", "integration-connector:edit")],
            "integration-connector",
        ),
        rule(
            r"^/v1/integrations/canvas/canvas-sync-jobs/[^/]+/(?:retry|resolve)$",
            &[("POST", "integration-connector:edit")],
            "integration-connector",
        ),
        rule(
            r"^/v1/integrations/canvas/evidence-policy-reviews/[^/]+/(?:resolve|reconcile-revocation)$",
            &[("POST", "integration-connector:edit")],
            "integration-connector",
        ),
        rule(
            r"^/v1/integrations/canvas/platforms/[^/]+/oauth$",
            &[("DELETE", "integration-connector:edit")],
            "integration-connector",
        ),
        rule(
            r"^/v1/integrations/canvas/canvas-credentials/validate$",
            &[("POST", "integration-connector:view")],
            "integration-connector",
        ),
        rule(
            r"^/v1/compliance-profiles/[^/]+/activate$",
            &[("POST", "compliance-profile:activate")],
            "compliance-profile",
        ),
        rule(
            r"^/v1/compliance-profiles/[^/]+/suspend$",
            &[("POST", "compliance-profile:suspend")],
            "compliance-profile",
        ),
        rule(
            r"^/v1/credential-templates/[^/]+/activate$",
            &[("POST", "credential-template:activate")],
            "credential-template",
        ),
        rule(
            r"^/v1/credential-templates/[^/]+/deprecate$",
            &[("POST", "credential-template:deprecate")],
            "credential-template",
        ),
        rule(
            r"^/v1/credential-templates/[^/]+/new-version$",
            &[("POST", "credential-template:version")],
            "credential-template",
        ),
        rule(
            r"^/v1/revocation-profiles/[^/]+/activate$",
            &[("POST", "revocation-profile:activate")],
            "revocation-profile",
        ),
        rule(
            r"^/v1/presentation-policies/[^/]+/suspend$",
            &[("POST", "presentation-policy:edit")],
            "presentation-policy",
        ),
        rule(
            r"^/v1/issued-credentials/[^/]+/(?:revoke|suspend|reinstate)$",
            &[("POST", "issuance:revoke")],
            "issued-credential",
        ),
        rule(
            r"^/v1/issued-credentials/[^/]+/renew$",
            &[("POST", "issuance:initiate")],
            "issued-credential",
        ),
        rule(
            r"^/v1/issued-credentials(?:/[^/]+)?$",
            &[
                ("GET", "issuance:view"),
                ("HEAD", "issuance:view"),
                ("OPTIONS", "issuance:view"),
            ],
            "issued-credential",
        ),
        rule(
            r"^/v1/issuance/didcomm/deliver$",
            &[("POST", "issuance:initiate")],
            "issuance",
        ),
        rule(
            r"^/v1/issuance/[^/]+/revocation-status$",
            &[
                ("GET", "issuance:view"),
                ("HEAD", "issuance:view"),
                ("OPTIONS", "issuance:view"),
            ],
            "issuance",
        ),
        rule(
            r"^/v1/issuance/[^/]+/revoke$",
            &[("POST", "issuance:revoke")],
            "issued-credential",
        ),
        rule(
            r"^/v1/issuance(?:/[^/]+)?$",
            &[
                ("GET", "issuance:view"),
                ("POST", "issuance:initiate"),
                ("HEAD", "issuance:view"),
                ("OPTIONS", "issuance:view"),
            ],
            "issuance",
        ),
        rule(
            r"^/v1/organizations/[^/]+/dashboard/applicant-stats$",
            &[("GET", "application:review")],
            "application",
        ),
        rule(
            r"^/v1/organizations/[^/]+/applicants(?:/[^/]+)?/issue$",
            &[("POST", "issuance:initiate")],
            "application",
        ),
        rule(
            r"^/v1/organizations/[^/]+/applicants/[^/]+/approve$",
            &[("POST", "application:approve")],
            "application",
        ),
        rule(
            r"^/v1/organizations/[^/]+/applicants/[^/]+/reject$",
            &[("POST", "application:reject")],
            "application",
        ),
        rule(
            r"^/v1/organizations/[^/]+/applicants/[^/]+/retire-offer$",
            &[("POST", "issuance:revoke")],
            "application",
        ),
        rule(
            r"^/v1/organizations/[^/]+/applicants(?:/[^/]+)?$",
            &[
                ("GET", "application:view"),
                ("HEAD", "application:view"),
                ("OPTIONS", "application:view"),
                ("POST", "application:review"),
                ("PATCH", "application:review"),
                ("DELETE", "application:review"),
            ],
            "application",
        ),
        rule(
            r"^/v1/organizations/[^/]+/applicants(?:/.*)?$",
            &[
                ("GET", "application:review"),
                ("POST", "application:review"),
                ("PATCH", "application:review"),
                ("DELETE", "application:review"),
                ("HEAD", "application:review"),
                ("OPTIONS", "application:review"),
            ],
            "application",
        ),
        rule(
            r"^/v1/flows/verify$",
            &[("POST", "verification:execute")],
            "verification",
        ),
        rule(
            r"^/v1/flows/definitions/[^/]+/activate$",
            &[("POST", "flow-definition:activate")],
            "flow-definition",
        ),
        rule(
            r"^/v1/flows/definitions/[^/]+/validate$",
            &[("POST", "flow-definition:view")],
            "flow-definition",
        ),
        rule(
            r"^/v1/flows/instances(?:/[^/]+)?(?:/advance)?$",
            &[
                ("GET", "flow-instance:view"),
                ("POST", "flow-instance:start"),
                ("HEAD", "flow-instance:view"),
                ("OPTIONS", "flow-instance:view"),
            ],
            "flow-instance",
        ),
        rule(
            r"^/v1/flows/definitions(?:/[^/]+)?(?:/activate)?$",
            &[
                ("GET", "flow-definition:view"),
                ("POST", "flow-definition:create"),
                ("PUT", "flow-definition:edit"),
                ("PATCH", "flow-definition:edit"),
                ("DELETE", "flow-definition:delete"),
            ],
            "flow-definition",
        ),
        rule(
            r"^/v1/organizations/[a-f0-9\-]{36}/transfer-ownership$",
            &[("POST", "organization:transfer-ownership")],
            "organization",
        ),
        rule(
            r"^/v1/organizations/[a-f0-9\-]{36}/members/me/permissions$",
            &[("GET", "organization:view")],
            "organization",
        ),
        rule(
            r"^/v1/organizations/[a-f0-9\-]{36}/members/[^/]+/roles(?:/[^/]+)?$",
            &[
                ("PUT", "role:assign"),
                ("POST", "role:assign"),
                ("DELETE", "role:assign"),
            ],
            "role",
        ),
        rule(
            r"^/v1/organizations/[a-f0-9\-]{36}/roles(?:/[^/]+)?$",
            &[
                ("GET", "role:view"),
                ("POST", "role:create"),
                ("PUT", "role:edit"),
                ("PATCH", "role:edit"),
                ("DELETE", "role:delete"),
            ],
            "role",
        ),
        rule(
            r"^/v1/organizations/[a-f0-9\-]{36}/permissions$",
            &[("GET", "role:view")],
            "role",
        ),
        rule(
            r"^/v1/organizations/[a-f0-9\-]{36}/members(?:/[^/]+)?$",
            &[
                ("GET", "team:view"),
                ("POST", "team:invite"),
                ("PUT", "team:manage"),
                ("PATCH", "team:manage"),
                ("DELETE", "team:manage"),
            ],
            "team",
        ),
        rule(
            r"^/v1/organizations/[a-f0-9\-]{36}/api-keys(?:/[^/]+)?$",
            &[
                ("GET", "api-key:view"),
                ("POST", "api-key:create"),
                ("PUT", "api-key:edit"),
                ("PATCH", "api-key:edit"),
                ("DELETE", "api-key:revoke"),
            ],
            "api-key",
        ),
        rule(
            r"^/v1(?:/organizations/[a-f0-9\-]{36})?/policy-sets/[^/]+/activate$",
            &[("POST", "policy-set:activate")],
            "policy-set",
        ),
        rule(
            r"^/v1(?:/organizations/[a-f0-9\-]{36})?/policy-sets/[^/]+/archive$",
            &[("POST", "policy-set:archive")],
            "policy-set",
        ),
        rule(
            r"^/v1(?:/organizations/[a-f0-9\-]{36})?/policy-sets/validate$",
            &[("POST", "policy-set:validate")],
            "policy-set",
        ),
        rule(
            r"^/v1(?:/organizations/[a-f0-9\-]{36})?/policy-sets/[^/]+/validate$",
            &[("POST", "policy-set:validate")],
            "policy-set",
        ),
        rule(
            r"^/v1/organizations/[a-f0-9\-]{36}/lifecycle$",
            &[("GET", "organization:view")],
            "organization",
        ),
        rule(
            r"^/v1/organizations/[a-f0-9\-]{36}/lifecycle/purge$",
            &[("POST", "organization:edit")],
            "organization",
        ),
        rule(
            r"^/v1/organizations/[a-f0-9\-]{36}/runtime/status$",
            &[("GET", "organization:view")],
            "organization",
        ),
        rule(
            r"^/v1/organizations/[a-f0-9\-]{36}/dashboard/applicant-stats$",
            &[("GET", "application:review")],
            "application",
        ),
        rule(
            r"^/v1/organizations/[a-f0-9\-]{36}/integration-info$",
            &[("GET", "organization:view")],
            "organization",
        ),
        rule(
            r"^/v1/organizations/[a-f0-9\-]{36}/audit-events/export$",
            &[("GET", "audit:export")],
            "audit",
        ),
        rule(
            r"^/v1/organizations/[a-f0-9\-]{36}/offline-verification-events(?:/[^/]+)?$",
            &[("GET", "audit:ingest"), ("POST", "audit:ingest")],
            "audit",
        ),
        rule(
            r"^/v1/organizations/[a-f0-9\-]{36}/audit-events(?:/[^/]+)?$",
            &[("GET", "audit:view")],
            "audit",
        ),
        rule(
            r"^/v1/organizations/[a-f0-9\-]{36}/scim/v2/Users(?:/[^/]+)?$",
            &[
                ("GET", "team:view"),
                ("POST", "team:invite"),
                ("PUT", "team:manage"),
                ("PATCH", "team:manage"),
                ("DELETE", "team:manage"),
            ],
            "team",
        ),
        rule(
            r"^/v1/organizations/[a-f0-9\-]{36}/scim/v2/Groups(?:/[^/]+)?$",
            &[
                ("GET", "role:view"),
                ("POST", "role:create"),
                ("PUT", "role:edit"),
                ("PATCH", "role:edit"),
                ("DELETE", "role:delete"),
            ],
            "role",
        ),
        rule(
            r"^/v1/organizations/[a-f0-9\-]{36}/scim/v2/(?:ServiceProviderConfig|Schemas|ResourceTypes)$",
            &[("GET", "organization:view")],
            "organization",
        ),
    ]
});

static ORG_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^/v1/organizations/([a-f0-9\-]{36})(?:/|$)").expect("organization path regex")
});
static ORG_RESOURCE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^/v1/organizations/[a-f0-9\-]{36}/([^/]+)").expect("organization resource regex")
});
static TOP_LEVEL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^/v1/([^/]+)(?:/|$)").expect("top-level regex"));
static TOP_LEVEL_RESOURCE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^/v1/([^/]+)/([^/]+)(?:/|$)").expect("resource lookup regex"));
static FLOW_RESOURCE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^/v1/flows/(definitions|instances)/([^/]+)(?:/|$)").expect("flow lookup regex")
});
static CANVAS_PLATFORM: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^/v1/integrations/canvas/platforms/([^/]+)(?:/|$)")
        .expect("Canvas platform lookup regex")
});
static CANVAS_BINDING: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^/v1/integrations/canvas/program-bindings/([^/]+)(?:/|$)")
        .expect("Canvas binding lookup regex")
});

pub fn resolve_action(method: &str, path: &str) -> Option<RequiredPermission> {
    let method = method.to_ascii_uppercase();
    for route_rule in SPECIAL_RULES.iter() {
        if route_rule.pattern.is_match(path) {
            return route_rule
                .methods
                .iter()
                .find(|(candidate, _)| *candidate == method)
                .map(|(_, permission)| RequiredPermission {
                    permission,
                    resource: route_rule.resource,
                });
        }
    }

    let segment = ORG_RESOURCE
        .captures(path)
        .and_then(|captures| captures.get(1))
        .or_else(|| {
            TOP_LEVEL
                .captures(path)
                .and_then(|captures| captures.get(1))
        })?
        .as_str();
    generic_permission(&method, segment)
}

fn generic_permission(method: &str, segment: &str) -> Option<RequiredPermission> {
    let (permission_resource, resource) = match segment {
        "credential-templates" => ("credential-template", "credential-template"),
        "trust-profiles" => ("trust-profile", "trust-profile"),
        "issuer-entities" => ("trusted-issuer", "issuer-entity"),
        "compliance-profiles" => ("compliance-profile", "compliance-profile"),
        "presentation-policies" => ("presentation-policy", "presentation-policy"),
        "revocation-profiles" => ("revocation-profile", "revocation-profile"),
        "deployment-profiles" => ("deployment-profile", "deployment-profile"),
        "flows" => ("flow-definition", "flow-definition"),
        "flow-instances" => ("flow-instance", "flow-instance"),
        "application-templates" => ("application-template", "application-template"),
        "verification" => ("verification", "verification"),
        "integrations" => ("integration-connector", "integration-connector"),
        "policy-sets" => ("policy-set", "policy-set"),
        _ => return None,
    };
    let action = match method {
        "GET" | "HEAD" | "OPTIONS" => "view",
        "POST" if permission_resource == "verification" => "execute",
        "POST" if permission_resource == "flow-instance" => "start",
        "POST" => "create",
        "PUT" | "PATCH" if permission_resource == "verification" => "execute",
        "PUT" | "PATCH" => "edit",
        "DELETE" => "delete",
        _ => return None,
    };
    Some(RequiredPermission {
        permission: leak_permission(permission_resource, action),
        resource,
    })
}

fn leak_permission(resource: &str, action: &str) -> &'static str {
    // The finite generic map keeps returned permissions stable without adding
    // allocation to the authorization hot path.
    match (resource, action) {
        ("credential-template", "view") => "credential-template:view",
        ("credential-template", "create") => "credential-template:create",
        ("credential-template", "edit") => "credential-template:edit",
        ("credential-template", "delete") => "credential-template:delete",
        ("trust-profile", "view") => "trust-profile:view",
        ("trust-profile", "create") => "trust-profile:create",
        ("trust-profile", "edit") => "trust-profile:edit",
        ("trust-profile", "delete") => "trust-profile:delete",
        ("trusted-issuer", "view") => "trusted-issuer:view",
        ("trusted-issuer", "create") => "trusted-issuer:create",
        ("trusted-issuer", "edit") => "trusted-issuer:edit",
        ("trusted-issuer", "delete") => "trusted-issuer:delete",
        ("compliance-profile", "view") => "compliance-profile:view",
        ("compliance-profile", "create") => "compliance-profile:create",
        ("compliance-profile", "edit") => "compliance-profile:edit",
        ("compliance-profile", "delete") => "compliance-profile:delete",
        ("presentation-policy", "view") => "presentation-policy:view",
        ("presentation-policy", "create") => "presentation-policy:create",
        ("presentation-policy", "edit") => "presentation-policy:edit",
        ("presentation-policy", "delete") => "presentation-policy:delete",
        ("revocation-profile", "view") => "revocation-profile:view",
        ("revocation-profile", "create") => "revocation-profile:create",
        ("revocation-profile", "edit") => "revocation-profile:edit",
        ("revocation-profile", "delete") => "revocation-profile:delete",
        ("deployment-profile", "view") => "deployment-profile:view",
        ("deployment-profile", "create") => "deployment-profile:create",
        ("deployment-profile", "edit") => "deployment-profile:edit",
        ("deployment-profile", "delete") => "deployment-profile:delete",
        ("flow-definition", "view") => "flow-definition:view",
        ("flow-definition", "create") => "flow-definition:create",
        ("flow-definition", "edit") => "flow-definition:edit",
        ("flow-definition", "delete") => "flow-definition:delete",
        ("flow-instance", "view") => "flow-instance:view",
        ("flow-instance", "start") => "flow-instance:start",
        ("flow-instance", "edit") => "flow-instance:edit",
        ("flow-instance", "delete") => "flow-instance:delete",
        ("application-template", "view") => "application-template:view",
        ("application-template", "create") => "application-template:create",
        ("application-template", "edit") => "application-template:edit",
        ("application-template", "delete") => "application-template:delete",
        ("verification", "view") => "verification:view",
        ("verification", "execute") => "verification:execute",
        ("verification", "delete") => "verification:delete",
        ("integration-connector", "view") => "integration-connector:view",
        ("integration-connector", "create") => "integration-connector:create",
        ("integration-connector", "edit") => "integration-connector:edit",
        ("integration-connector", "delete") => "integration-connector:delete",
        ("policy-set", "view") => "policy-set:view",
        ("policy-set", "create") => "policy-set:create",
        ("policy-set", "edit") => "policy-set:edit",
        ("policy-set", "delete") => "policy-set:delete",
        _ => unreachable!("generic permission map is finite"),
    }
}

pub fn extract_org_id(path: &str) -> Option<&str> {
    ORG_PATH
        .captures(path)
        .and_then(|captures| captures.get(1))
        .map(|value| value.as_str())
}

pub fn resolve_resource_lookup(path: &str) -> Option<ResourceLookup> {
    if let Some(id) = capture_id(&CANVAS_PLATFORM, path, 1) {
        return Some(ResourceLookup {
            service: "issuance",
            path: format!("/v1/integrations/canvas/platforms/{id}"),
        });
    }
    if let Some(id) = capture_id(&CANVAS_BINDING, path, 1) {
        return Some(ResourceLookup {
            service: "issuance",
            path: format!("/v1/integrations/canvas/program-bindings/{id}"),
        });
    }
    if let Some(captures) = FLOW_RESOURCE.captures(path) {
        return Some(ResourceLookup {
            service: "flows",
            path: format!(
                "/internal/v1/resource-owners/flows/{}/{}",
                &captures[1], &captures[2]
            ),
        });
    }

    let captures = TOP_LEVEL_RESOURCE.captures(path)?;
    let segment = &captures[1];
    let id = &captures[2];
    let (service, template, reserved): (&str, &str, &[&str]) = match segment {
        "credential-templates" => (
            "credential-templates",
            "/internal/v1/resource-owners/credential-templates/{id}",
            &["issuer-options"],
        ),
        "trust-profiles" => (
            "trust-profiles",
            "/internal/v1/resource-owners/trust-profiles/{id}",
            &[],
        ),
        "issuer-entities" => (
            "trust-profiles",
            "/internal/v1/resource-owners/issuer-entities/{id}",
            &[],
        ),
        "compliance-profiles" => (
            "compliance-profiles",
            "/internal/v1/resource-owners/compliance-profiles/{id}",
            &["system"],
        ),
        "presentation-policies" => (
            "presentation-policies",
            "/internal/v1/resource-owners/presentation-policies/{id}",
            &["evaluate"],
        ),
        "deployment-profiles" => (
            "deployment-profiles",
            "/internal/v1/resource-owners/deployment-profiles/{id}",
            &[],
        ),
        "revocation-profiles" => (
            "revocation-profiles",
            "/internal/v1/resource-owners/revocation-profiles/{id}",
            &[],
        ),
        "flows" => (
            "flows",
            "/v1/flows/{id}",
            &[
                "capabilities",
                "definitions",
                "instances",
                "siop",
                "verify",
                "webhooks",
            ],
        ),
        "application-templates" => (
            "issuance-native",
            "/internal/v1/resource-owners/application-templates/{id}",
            &["validate-artifacts"],
        ),
        "issued-credentials" => (
            "issuance-native",
            "/internal/v1/resource-owners/issued-credentials/{id}",
            &["mine"],
        ),
        "issuance" => (
            "issuance-native",
            "/internal/v1/resource-owners/issuance-transactions/{id}",
            &[
                "offers",
                "token",
                "credential",
                "nonce",
                "notification",
                "deferred-credential",
                "authorize",
                "par",
                "didcomm",
                "initiate",
                "transactions",
                "delivery-records",
                "oid4vci-clients",
                "organizations",
            ],
        ),
        "policy-sets" => ("organizations", "/v1/policy-sets/{id}", &["validate"]),
        "wallet-registry" => (
            "credential-templates",
            "/v1/wallet-registry/{id}",
            &["resolve"],
        ),
        "delivery-destinations" => (
            "credential-templates",
            "/v1/delivery-destinations/{id}",
            &[],
        ),
        // Notification resources deliberately require an explicit authorized
        // organization selector; unscoped owner lookup is unsafe here.
        "webhooks" | "subscriptions" | "notifications" => return None,
        _ => return None,
    };
    if reserved.contains(&id) {
        return None;
    }
    Some(ResourceLookup {
        service,
        path: template.replace("{id}", id),
    })
}

fn capture_id<'a>(regex: &Regex, path: &'a str, index: usize) -> Option<&'a str> {
    regex
        .captures(path)
        .and_then(|captures| captures.get(index))
        .map(|value| value.as_str())
}

static SKIP_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r"^/v1/flows/capabilities$",
        r"^/v1/issued-credentials/mine$",
        r"^/v1/organizations$",
        r"^/v1/organizations/mine$",
        r"^/v1/organizations/discover",
        r"^/v1/organizations/join/",
        r"^/v1/organizations/[^/]+/join$",
        r"^/v1/organizations/invitations/",
        r"^/v1/organizations/[^/]+/revocation-profiles/[^/]+/status-lists/[^/]+/[^/]+$",
        r"^/v1/integrations/canvas/lti/jwks/?$",
        r"^/v1/integrations/canvas/lti/config/[^/]+/?$",
        r"^/v1/integrations/canvas/lti/platforms/[^/]+/(?:login|experience-login|launch|experience)/?$",
        r"^/v1/integrations/canvas/oauth/callback/?$",
        r"^/v1/integrations/canvas/lti/experience-sessions/(?:exchange|current(?:/(?:bootstrap|evidence-sync|evidence-status|deep-linking-response|claim))?)/?$",
        r"^/health",
        r"^/(?:openapi\.json|docs|redoc)$",
        r"^/\.well-known/",
        r"^/internal/signing-keys(?:/|$)",
        r"^/v1/(?:flows/instances|verify)/[^/]+/(?:request|submit)$",
    ]
    .into_iter()
    .map(|pattern| Regex::new(pattern).expect("authorization skip regex must be valid"))
    .collect()
});

pub fn skips_tenant_authorization(path: &str) -> bool {
    SKIP_PATTERNS.iter().any(|pattern| pattern.is_match(path))
}

pub use marty_api_key_policy::api_key_allowed;

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct Contract {
        schema_version: u32,
        action_cases: Vec<ActionCase>,
        lookup_cases: Vec<LookupCase>,
        api_key_cases: Vec<ApiKeyCase>,
        tenant_authorization_cases: Vec<TenantAuthorizationCase>,
        skip_cases: Vec<SkipCase>,
    }

    #[derive(Debug, Deserialize)]
    struct ActionCase {
        method: String,
        path: String,
        permission: Option<String>,
        resource: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    struct LookupCase {
        path: String,
        service: Option<String>,
        lookup_path: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    struct ApiKeyCase {
        permission: String,
        scopes: Vec<String>,
        allowed: bool,
    }

    #[derive(Debug, Deserialize)]
    struct SkipCase {
        path: String,
        skipped: bool,
    }

    #[derive(Debug, Deserialize)]
    struct TenantAuthorizationCase {
        principal: String,
        permission: String,
        organization_id: String,
        principal_organization_id: Option<String>,
        user_id: Option<String>,
        membership_status: Option<String>,
        permissions: Vec<String>,
        is_owner: bool,
        scopes: Vec<String>,
        allowed: bool,
    }

    fn contract() -> Contract {
        serde_json::from_str(include_str!(
            "../../../../contracts/gateway-authorization-behavior.json"
        ))
        .expect("valid gateway authorization contract")
    }

    #[test]
    fn delivery_grants_exist_in_the_organization_catalog_and_keep_api_key_reads_separate() {
        let catalog: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../contracts/organization-permission-catalog.json"
        ))
        .unwrap();
        for (method, permission) in [
            ("GET", "wallet:view"),
            ("POST", "integration-connector:create"),
            ("PATCH", "integration-connector:edit"),
            ("DELETE", "integration-connector:delete"),
        ] {
            let required =
                resolve_action(method, "/v1/delivery-destinations/destination-one").unwrap();
            assert_eq!(required.permission, permission);
            assert!(catalog["permissions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| format!(
                    "{}:{}",
                    item["resource"].as_str().unwrap(),
                    item["action"].as_str().unwrap()
                ) == permission));
        }
        assert!(api_key_allowed("wallet:view", &["wallet:read".into()]));
        for action in ["create", "edit", "delete"] {
            let permission = format!("integration-connector:{action}");
            assert!(!api_key_allowed(&permission, &["wallet:read".into()]));
            assert!(!api_key_allowed(&permission, &["integrations:read".into()]));
            assert!(api_key_allowed(&permission, &["integrations:write".into()]));
        }
    }

    #[test]
    fn language_neutral_authorization_contract() {
        let contract = contract();
        assert_eq!(contract.schema_version, 1);
        for case in contract.action_cases {
            let actual = resolve_action(&case.method, &case.path);
            assert_eq!(
                actual.map(|value| value.permission),
                case.permission.as_deref(),
                "{} {} permission",
                case.method,
                case.path
            );
            assert_eq!(
                actual.map(|value| value.resource),
                case.resource.as_deref(),
                "{} {} resource",
                case.method,
                case.path
            );
        }
        for case in contract.lookup_cases {
            let actual = resolve_resource_lookup(&case.path);
            assert_eq!(
                actual.as_ref().map(|value| value.service),
                case.service.as_deref()
            );
            assert_eq!(
                actual.as_ref().map(|value| value.path.as_str()),
                case.lookup_path.as_deref()
            );
        }
        for case in contract.api_key_cases {
            assert_eq!(
                api_key_allowed(&case.permission, &case.scopes),
                case.allowed
            );
        }
        for case in contract.tenant_authorization_cases {
            let result = if case.principal == "api_key" {
                authorize_api_key(
                    &case.permission,
                    &case.organization_id,
                    case.principal_organization_id.as_deref(),
                    &case.scopes,
                )
            } else {
                let membership = OrganizationMembership {
                    user_id: case.user_id.clone().unwrap_or_default(),
                    organization_id: case.principal_organization_id.unwrap_or_default(),
                    status: case.membership_status.unwrap_or_default(),
                    role_names: BTreeSet::new(),
                    permissions: case.permissions.into_iter().collect(),
                    is_owner: case.is_owner,
                };
                authorize_membership(
                    &case.permission,
                    case.user_id.as_deref().unwrap_or_default(),
                    &case.organization_id,
                    Some(&membership),
                )
            };
            assert_eq!(result.is_ok(), case.allowed);
        }
        for case in contract.skip_cases {
            assert_eq!(skips_tenant_authorization(&case.path), case.skipped);
        }
    }

    #[test]
    fn canvas_review_recovery_requires_the_existing_integration_edit_permission() {
        let path = "/v1/integrations/canvas/evidence-policy-reviews/review-1/reconcile-revocation";
        let required = resolve_action("POST", path).unwrap();
        assert_eq!(required.permission, "integration-connector:edit");
        assert_eq!(required.resource, "integration-connector");
        assert!(!api_key_allowed(
            required.permission,
            &["integrations:read".into()]
        ));
        assert!(api_key_allowed(
            required.permission,
            &["integrations:write".into()]
        ));
    }

    #[test]
    fn presentation_policy_owner_lookup_uses_internal_projection_and_preserves_scopes() {
        let lookup = resolve_resource_lookup(
            "/v1/presentation-policies/11111111-1111-1111-1111-111111111111",
        )
        .unwrap();
        assert_eq!(lookup.service, "presentation-policies");
        assert_eq!(
            lookup.path,
            "/internal/v1/resource-owners/presentation-policies/11111111-1111-1111-1111-111111111111"
        );
        assert!(resolve_resource_lookup("/v1/presentation-policies/evaluate").is_none());
        assert!(api_key_allowed(
            "presentation-policy:view",
            &["trust:read".into()]
        ));
        assert!(!api_key_allowed(
            "presentation-policy:edit",
            &["trust:read".into()]
        ));
        assert!(!api_key_allowed(
            "presentation-policy:view",
            &["templates:read".into()]
        ));
        assert!(authorize_api_key(
            "presentation-policy:view",
            "org-1",
            Some("org-1"),
            &["trust:read".into()]
        )
        .is_ok());
        assert!(authorize_api_key(
            "presentation-policy:view",
            "org-2",
            Some("org-1"),
            &["trust:read".into()]
        )
        .is_err());
    }

    #[test]
    fn consumer_profile_ownership_uses_service_only_projections_instead_of_human_reads() {
        for resource in [
            "compliance-profiles",
            "deployment-profiles",
            "revocation-profiles",
            "flows/definitions",
            "flows/instances",
        ] {
            let lookup = resolve_resource_lookup(&format!(
                "/v1/{resource}/11111111-1111-4111-8111-111111111111"
            ))
            .unwrap();
            assert_eq!(
                lookup.path,
                format!(
                    "/internal/v1/resource-owners/{resource}/11111111-1111-4111-8111-111111111111"
                )
            );
        }
        assert!(resolve_resource_lookup("/v1/flows/capabilities").is_none());
        assert!(resolve_resource_lookup("/v1/compliance-profiles/system/discoverable").is_none());
    }

    #[test]
    fn organization_id_matches_published_lowercase_shape() {
        let id = "11111111-1111-1111-1111-111111111111";
        assert_eq!(
            extract_org_id(&format!("/v1/organizations/{id}/roles")),
            Some(id)
        );
        assert_eq!(extract_org_id("/v1/organizations/NOT-A-UUID/roles"), None);
    }

    #[test]
    fn unsupported_method_on_special_route_does_not_fall_through() {
        assert_eq!(resolve_action("PATCH", "/v1/flows/verify"), None);
    }

    #[test]
    fn tenant_authorization_is_exact_and_fail_closed() {
        let membership = OrganizationMembership {
            user_id: "user-1".into(),
            organization_id: "org-1".into(),
            status: "active".into(),
            role_names: BTreeSet::from(["issuer".into()]),
            permissions: BTreeSet::from(["credential-template:view".into()]),
            is_owner: false,
        };
        assert_eq!(
            authorize_membership(
                "credential-template:view",
                "user-1",
                "org-1",
                Some(&membership)
            ),
            Ok(())
        );
        assert_eq!(
            authorize_membership(
                "credential-template:edit",
                "user-1",
                "org-1",
                Some(&membership)
            ),
            Err(TenantAuthorizationFailure::ActionNotAuthorized)
        );
        assert_eq!(
            authorize_api_key(
                "credential-template:view",
                "org-2",
                Some("org-1"),
                &["templates:read".into()]
            ),
            Err(TenantAuthorizationFailure::ApiKeyOrganizationMismatch)
        );
    }

    #[test]
    fn applicant_read_key_cannot_review_or_approve() {
        let collection = "/v1/organizations/org-1/applicants";
        let item = "/v1/organizations/org-1/applicants/app-1";
        let read_scopes = ["applications:read".to_owned()];
        for path in [collection, item] {
            let permission = resolve_action("GET", path)
                .expect("applicant read route")
                .permission;
            assert_eq!(permission, "application:view");
            assert!(api_key_allowed(permission, &read_scopes));
            for method in ["POST", "PATCH", "DELETE"] {
                if let Some(write) = resolve_action(method, path) {
                    assert!(!api_key_allowed(write.permission, &read_scopes));
                }
            }
        }
        let approve = resolve_action("POST", "/v1/organizations/org-1/applicants/app-1/approve")
            .expect("approval route");
        assert_eq!(approve.permission, "application:approve");
        assert!(!api_key_allowed(approve.permission, &read_scopes));
        let retire = resolve_action(
            "POST",
            "/v1/organizations/org-1/applicants/app-1/retire-offer",
        )
        .expect("offer retirement route");
        assert_eq!(retire.permission, "issuance:revoke");
        assert!(!api_key_allowed(retire.permission, &read_scopes));
    }

    #[test]
    fn compliance_system_catalog_is_not_a_resource_id() {
        assert!(resolve_resource_lookup("/v1/compliance-profiles/system/discoverable").is_none());
        assert!(resolve_resource_lookup(
            "/v1/compliance-profiles/10000000-0000-0000-0000-000000000003"
        )
        .is_some());
        assert_eq!(
            resolve_action("GET", "/v1/compliance-profiles/system/discoverable")
                .unwrap()
                .permission,
            "compliance-profile:view"
        );
    }
    #[test]
    fn compliance_lifecycle_uses_native_actions_and_readers_never_gain_writes() {
        for action in ["activate", "suspend"] {
            let path = format!("/v1/compliance-profiles/profile-one/{action}");
            let requirement = resolve_action("POST", &path).unwrap();
            assert_eq!(
                requirement.permission,
                format!("compliance-profile:{action}")
            );
            assert_eq!(
                resolve_resource_lookup(&path).unwrap().path,
                "/internal/v1/resource-owners/compliance-profiles/profile-one"
            );
            assert!(!api_key_allowed(
                requirement.permission,
                &["compliance:read".into()]
            ));
            assert!(!api_key_allowed(
                requirement.permission,
                &["templates:write".into()]
            ));
            assert!(api_key_allowed(
                requirement.permission,
                &["compliance:write".into()]
            ));
        }
    }
}
