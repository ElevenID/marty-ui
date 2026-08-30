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
            r"^/v1/integrations/canvas/evidence-policy-reviews/[^/]+/resolve$",
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
            path: format!("/v1/flows/{}/{}", &captures[1], &captures[2]),
        });
    }

    let captures = TOP_LEVEL_RESOURCE.captures(path)?;
    let segment = &captures[1];
    let id = &captures[2];
    let (service, template, reserved): (&str, &str, &[&str]) = match segment {
        "credential-templates" => ("credential-templates", "/v1/credential-templates/{id}", &[]),
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
        "compliance-profiles" => ("compliance-profiles", "/v1/compliance-profiles/{id}", &[]),
        "presentation-policies" => (
            "presentation-policies",
            "/v1/presentation-policies/{id}",
            &["evaluate"],
        ),
        "deployment-profiles" => ("deployment-profiles", "/v1/deployment-profiles/{id}", &[]),
        "revocation-profiles" => ("revocation-profiles", "/v1/revocation-profiles/{id}", &[]),
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
            "issuance",
            "/internal/v1/resource-owners/application-templates/{id}",
            &["validate-artifacts"],
        ),
        "issued-credentials" => (
            "issuance",
            "/internal/v1/resource-owners/issued-credentials/{id}",
            &["mine"],
        ),
        "issuance" => (
            "issuance",
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
        r"^/v1/integrations/canvas/lti/experience-sessions/(?:exchange|current(?:/(?:bootstrap|evidence-sync|evidence-status|deep-linking-response))?)/?$",
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

pub fn api_key_allowed(required_permission: &str, scopes: &[String]) -> bool {
    let scopes = scopes.iter().map(String::as_str).collect::<BTreeSet<_>>();
    if scopes.contains("admin:full") {
        return true;
    }
    if required_permission == "webhook:test" {
        return scopes.contains("webhooks:write");
    }
    if required_permission == "notification:send" {
        return scopes.contains("notifications:send");
    }
    if required_permission == "application:approve" {
        return scopes.contains("applications:approve") || scopes.contains("applications:write");
    }

    let Some((resource, action)) = required_permission.split_once(':') else {
        return false;
    };
    match resource {
        "wallet" => match action {
            "view" => scopes.contains("wallet:read") || scopes.contains("wallet:write"),
            "write" => scopes.contains("wallet:write"),
            _ => false,
        },
        "signing-key" => match action {
            "view" => scopes.contains("keys:read") || scopes.contains("keys:write"),
            "activate" | "archive" | "create" | "delete" | "edit" | "rotate" | "update"
            | "validate" | "write" => scopes.contains("keys:write"),
            _ => false,
        },
        "flow-instance" => scopes.contains("flows:execute") || scopes.contains("flows:write"),
        "flow-definition" if matches!(action, "view" | "read" | "list") => {
            scopes.contains("flows:read")
                || scopes.contains("flows:write")
                || scopes.contains("flows:execute")
        }
        "flow-definition" => scopes.contains("flows:write"),
        "api-key" => false,
        "verification" => scopes.contains("flows:execute") || scopes.contains("credentials:read"),
        "issued-credential" if matches!(action, "issue" | "create") => {
            scopes.contains("credentials:issue")
        }
        "issued-credential" if matches!(action, "revoke" | "delete") => {
            scopes.contains("credentials:revoke")
        }
        "issued-credential" => {
            scopes.contains("credentials:read") || scopes.contains("credentials:issue")
        }
        "issuance" if action == "initiate" => scopes.contains("credentials:issue"),
        "issuance" if action == "revoke" => scopes.contains("credentials:revoke"),
        "issuance" => scopes.contains("credentials:read") || scopes.contains("credentials:issue"),
        _ => mapped_api_key_scope(resource, action, &scopes),
    }
}

fn mapped_api_key_scope(resource: &str, action: &str, scopes: &BTreeSet<&str>) -> bool {
    let (read_scope, write_scope) = match resource {
        "credential-template" => ("templates:read", "templates:write"),
        "application-template" | "application" => ("applications:read", "applications:write"),
        "trust-profile" | "issuer-entity" | "presentation-policy" => ("trust:read", "trust:write"),
        "compliance-profile" => ("compliance:read", "compliance:write"),
        "deployment-profile" => ("deployment:read", "deployment:write"),
        "webhook" => ("webhooks:read", "webhooks:write"),
        "notification" => ("notifications:read", "notifications:send"),
        "team" => ("users:read", "users:invite"),
        "role" => ("roles:read", "roles:write"),
        "policy-set" => ("trust:read", "trust:admin"),
        "organization" => ("users:read", "users:invite"),
        "integration-connector" => ("integrations:read", "integrations:write"),
        _ => return false,
    };
    if matches!(action, "view" | "read" | "list") {
        scopes.contains(read_scope) || scopes.contains(write_scope)
    } else if matches!(
        action,
        "create" | "edit" | "delete" | "write" | "activate" | "archive" | "validate"
    ) {
        scopes.contains(write_scope)
    } else {
        false
    }
}

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
}
