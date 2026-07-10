// ============================================================================
// MIP Default Gateway Policies — Role-Based Access Control
// ============================================================================
//
// These policies implement the Owner/Admin/Member/Viewer role model using
// Cedar's formal policy language. They are evaluated by the gateway's
// CedarAuthMiddleware for all org-scoped API requests.
//
// Evaluation: deny-by-default. At least one permit must match, and zero
// forbid policies may match, for the request to be authorized.
// ============================================================================

// ── Owner: full access to all actions in the organization ────────────────

@id("role-owner-full-access")
permit (
    principal is MIP::User,
    action,
    resource
)
when {
    principal in MIP::Role::"owner"
};

// ── Admin: full access (equivalent to owner) ─────────────────────────────

@id("role-admin-full-access")
permit (
    principal is MIP::User,
    action,
    resource
)
when {
    principal in MIP::Role::"admin"
};

// ── Member: standard operational access ──────────────────────────────────

@id("role-member-standard-access")
permit (
    principal is MIP::User,
    action in [
        MIP::Action::"credentials:issue",
        MIP::Action::"credentials:revoke",
        MIP::Action::"credentials:read",
        MIP::Action::"credentials:verify",
        MIP::Action::"flows:read",
        MIP::Action::"flows:write",
        MIP::Action::"flows:execute",
        MIP::Action::"applications:read",
        MIP::Action::"applications:write",
        MIP::Action::"applications:approve",
        MIP::Action::"applications:reject",
        MIP::Action::"trust:read",
        MIP::Action::"trust:write",
        MIP::Action::"compliance:read",
        MIP::Action::"compliance:write",
        MIP::Action::"templates:read",
        MIP::Action::"templates:write",
        MIP::Action::"webhooks:read",
        MIP::Action::"webhooks:write",
        MIP::Action::"integrations:read",
        MIP::Action::"integrations:write",
        MIP::Action::"notifications:read",
        MIP::Action::"notifications:send",
        MIP::Action::"audit:read",
        MIP::Action::"deployment:read",
        MIP::Action::"users:read",
        MIP::Action::"roles:read",
        MIP::Action::"keys:read",
        MIP::Action::"policy_sets:read"
    ],
    resource
)
when {
    principal in MIP::Role::"member"
};

// ── Viewer: read-only access ─────────────────────────────────────────────

@id("role-viewer-read-only")
permit (
    principal is MIP::User,
    action in [
        MIP::Action::"credentials:read",
        MIP::Action::"flows:read",
        MIP::Action::"applications:read",
        MIP::Action::"trust:read",
        MIP::Action::"compliance:read",
        MIP::Action::"templates:read",
        MIP::Action::"webhooks:read",
        MIP::Action::"integrations:read",
        MIP::Action::"notifications:read",
        MIP::Action::"audit:read",
        MIP::Action::"deployment:read",
        MIP::Action::"users:read",
        MIP::Action::"roles:read",
        MIP::Action::"keys:read",
        MIP::Action::"policy_sets:read"
    ],
    resource
)
when {
    principal in MIP::Role::"viewer"
};

// ── API key: organization-scoped access ──────────────────────────────────

@id("org-apikey-full-access")
permit (
    principal is MIP::ApiKey,
    action,
    resource
)
when {
    principal.scope_type == "ORGANIZATION" &&
    principal.enabled
};

// ── Forbid: disabled API keys ────────────────────────────────────────────

@id("deny-disabled-apikeys")
forbid (
    principal is MIP::ApiKey,
    action,
    resource
)
when {
    !principal.enabled
};

// ── Forbid: suspended or deactivated users ───────────────────────────────

@id("deny-suspended-users")
forbid (
    principal is MIP::User,
    action,
    resource
)
when {
    principal.status == "SUSPENDED" ||
    principal.status == "DEACTIVATED"
};
