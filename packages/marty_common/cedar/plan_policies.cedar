// ============================================================================
// MIP Plan-Tier Feature Gates — Cedar Forbid Policies
// ============================================================================
//
// These forbid policies restrict access to plan-gated features based on the
// organization's plan tier. They run alongside the RBAC permit policies in
// gateway_policies.cedar. Because Cedar is deny-by-default with forbid
// overriding permit, a matching forbid here blocks the action regardless
// of the user's role.
//
// Plan matrix (from plans.py):
//   free:         no webhooks, no audit_logs, no custom_cedar_policies
//   starter:      + webhooks, + audit_logs
//   professional: + custom_cedar_policies, + device_registration, + multi_environment
//   enterprise:   everything
// ============================================================================

// ── Webhooks: blocked on Free tier ──────────────────────────────────────

@id("plan-deny-webhooks-free")
forbid (
    principal,
    action in [MIP::Action::"webhooks:read", MIP::Action::"webhooks:write"],
    resource
)
when {
    context.plan_tier == "free"
};

// ── Audit logs: blocked on Free tier ────────────────────────────────────

@id("plan-deny-audit-free")
forbid (
    principal,
    action == MIP::Action::"audit:read",
    resource
)
when {
    context.plan_tier == "free"
};

// ── Deployment writes (multi-environment): blocked on Free + Starter ────

@id("plan-deny-deployment-write-low-tier")
forbid (
    principal,
    action == MIP::Action::"deployment:write",
    resource
)
when {
    context.plan_tier == "free" || context.plan_tier == "starter"
};
