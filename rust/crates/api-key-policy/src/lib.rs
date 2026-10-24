//! Shared API-key scope policy for gateway and native service principals.
use std::collections::BTreeSet;

/// Claims supplied by a gateway whose service credential has already been
/// authenticated. Parsing this type does not authenticate HTTP headers.
#[derive(Clone, Debug)]
pub struct GatewayApiKeyActor {
    key_id: uuid::Uuid,
    organization_id: uuid::Uuid,
    scopes: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidGatewayApiKeyActor;

impl GatewayApiKeyActor {
    pub fn parse(
        key_id: &str,
        organization_id: &str,
        scopes: &str,
    ) -> Result<Self, InvalidGatewayApiKeyActor> {
        let key_id = uuid::Uuid::parse_str(key_id).map_err(|_| InvalidGatewayApiKeyActor)?;
        let organization_id =
            uuid::Uuid::parse_str(organization_id).map_err(|_| InvalidGatewayApiKeyActor)?;
        if key_id.is_nil() || organization_id.is_nil() {
            return Err(InvalidGatewayApiKeyActor);
        }
        Ok(Self {
            key_id,
            organization_id,
            scopes: scopes
                .split(',')
                .map(str::trim)
                .filter(|scope| !scope.is_empty())
                .map(str::to_owned)
                .collect(),
        })
    }

    #[must_use]
    pub fn principal_id(&self) -> String {
        self.key_id.to_string()
    }

    #[must_use]
    pub fn organization_id(&self) -> String {
        self.organization_id.to_string()
    }

    #[must_use]
    pub fn scopes_csv(&self) -> String {
        self.scopes.join(",")
    }

    #[must_use]
    pub fn authorizes(&self, principal: &str, organization: &str, permission: &str) -> bool {
        uuid::Uuid::parse_str(principal).ok() == Some(self.key_id)
            && uuid::Uuid::parse_str(organization).ok() == Some(self.organization_id)
            && api_key_allowed(permission, &self.scopes)
    }
}

pub fn api_key_allowed(required_permission: &str, scopes: &[String]) -> bool {
    let scopes = scopes.iter().map(String::as_str).collect::<BTreeSet<_>>();
    // Offline event ingestion is an explicitly granted reporting capability;
    // broad legacy keys and audit readers do not gain a new write boundary.
    if required_permission == "audit:ingest" {
        return scopes.contains("audit:write");
    }
    // DSC issuance requires a tenant-bound human operator grant. API keys,
    // including broad legacy scopes, must not mint document certificates.
    if matches!(
        required_permission,
        "passport-certificate:issue" | "passport-certificate:issue-csca"
    ) {
        return false;
    }
    if scopes.contains("admin:full") {
        return true;
    }
    if required_permission == "webhook:test" {
        return scopes.contains("webhooks:write");
    }
    if required_permission == "notification:send" {
        return scopes.contains("notifications:send");
    }
    // Applicant mutation and evidence-review routes already require this action.
    // Preserve the read-only boundary while honoring the published writer scope.
    if required_permission == "application:review" {
        return scopes.contains("applications:write");
    }
    if required_permission == "application:approve" {
        return scopes.contains("applications:approve") || scopes.contains("applications:write");
    }

    let Some((resource, action)) = required_permission.split_once(':') else {
        return false;
    };
    match resource {
        // Discovery follows trust-read scope. Existing privileged revocation
        // writes remain behind their original scope rules.
        "revocation-profile" if matches!(action, "view" | "read" | "list") => {
            scopes.contains("trust:read") || scopes.contains("trust:write")
        }
        "compliance-profile" if action == "suspend" => scopes.contains("compliance:write"),
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
mod application_review_tests {
    use super::api_key_allowed;

    #[test]
    fn application_writer_can_review_with_existing_documented_scope() {
        assert!(api_key_allowed(
            "application:review",
            &["applications:write".into()]
        ));
    }

    #[test]
    fn application_reader_and_approver_do_not_gain_review_writes() {
        for scope in [
            "applications:read",
            "applications:approve",
            "integrations:write",
        ] {
            assert!(!api_key_allowed("application:review", &[scope.into()]));
        }
        assert!(!api_key_allowed("application:review", &[]));
    }

    #[test]
    fn application_review_grant_does_not_allow_key_or_api_key_administration() {
        let scopes = ["applications:write".into()];
        assert!(!api_key_allowed("signing-key:write", &scopes));
        assert!(!api_key_allowed("api-key:edit", &scopes));
        assert!(!api_key_allowed("credential-template:edit", &scopes));
    }
}

#[cfg(test)]
mod gateway_actor_tests {
    use super::{api_key_allowed, GatewayApiKeyActor};
    const KEY: &str = "10000000-0000-4000-8000-000000000001";
    const ORG: &str = "20000000-0000-4000-8000-000000000001";
    const OTHER: &str = "20000000-0000-4000-8000-000000000002";

    #[test]
    fn gateway_reader_remains_bound_to_actor_tenant_and_read_scope() {
        let actor =
            GatewayApiKeyActor::parse(KEY, ORG, "deployment:read, compliance:read,trust:read")
                .unwrap();
        for permission in [
            "deployment-profile:view",
            "compliance-profile:view",
            "revocation-profile:view",
        ] {
            assert!(actor.authorizes(KEY, ORG, permission));
            assert!(!actor.authorizes(OTHER, ORG, permission));
            assert!(!actor.authorizes(KEY, OTHER, permission));
        }
        for permission in [
            "deployment-profile:edit",
            "compliance-profile:create",
            "revocation-profile:activate",
            "signing-key:view",
        ] {
            assert!(!actor.authorizes(KEY, ORG, permission));
        }
    }

    #[test]
    fn malformed_or_nil_gateway_actor_is_not_a_principal() {
        for id in ["", "not-a-uuid", "00000000-0000-0000-0000-000000000000"] {
            assert!(GatewayApiKeyActor::parse(id, ORG, "admin:full").is_err());
            assert!(GatewayApiKeyActor::parse(KEY, id, "admin:full").is_err());
        }
        let actor = GatewayApiKeyActor::parse(KEY, ORG, "admin:full").unwrap();
        assert!(!actor.authorizes(KEY, OTHER, "deployment-profile:view"));
        assert!(
            !GatewayApiKeyActor::parse(KEY, ORG, "").unwrap().authorizes(
                KEY,
                ORG,
                "deployment-profile:view"
            )
        );
    }

    #[test]
    fn revocation_profile_discovery_does_not_expand_privileged_write_scopes() {
        assert!(api_key_allowed(
            "revocation-profile:view",
            &["trust:read".into()]
        ));
        assert!(!api_key_allowed(
            "revocation-profile:activate",
            &["trust:read".into()]
        ));
        assert!(!api_key_allowed(
            "revocation-profile:activate",
            &["trust:write".into()]
        ));
        assert!(!api_key_allowed(
            "revocation-profile:view",
            &["credentials:issue".into()]
        ));
    }
}
